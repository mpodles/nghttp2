/*
 * nghttp2 - HTTP/2 C Library
 *
 * Copyright (c) 2012 Tatsuhiro Tsujikawa
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
#include "shrpx_http2_upstream.h"

#include <netinet/tcp.h>
#include <assert.h>
#include <cerrno>

#include "shrpx_client_handler.h"
#include "shrpx_https_upstream.h"
#include "shrpx_downstream.h"
#include "shrpx_downstream_connection.h"
#include "shrpx_config.h"
#include "shrpx_http.h"
#include "shrpx_worker.h"
#include "shrpx_http2_session.h"
#include "shrpx_http2_downstream_connection.h"
#include "shrpx_log.h"
#include "shrpx_zcopy_stats.h"
#include "shrpx_xlio.h"
#ifdef HAVE_MRUBY
#  include "shrpx_mruby.h"
#endif // defined(HAVE_MRUBY)
#include "http2.h"
#include "util.h"
#include "base64.h"
#include "app_helper.h"
#include "template.h"

using namespace nghttp2;

namespace shrpx {

// MAX_BUFFER_SIZE is the pacing limit for the on_write loop: nghttp2 stops
// producing new frames when wb_ >= MAX_BUFFER_SIZE.  It is also the hard PAUSE
// threshold in downstream_data_read_callback (only triggered when buffer is
// already at capacity, not based on the remaining headroom before adding a frame).
// Previously this constant also capped DATA frame size via:
//   nread = min(nread, MAX_BUFFER_SIZE - 9 - wb_->rleft())
// That cap is removed (see downstream_data_read_callback) because with
// NGHTTP2_DATA_FLAG_NO_COPY the payload enters wb_ in send_data_callback, not
// in read_callback.  The old calculation double-counted wb_ occupancy and
// shrunk frames to ~8 KB under heavy concurrency (400 streams → avg_length 8260).
constexpr size_t MAX_BUFFER_SIZE = 32_k;

namespace {
int on_stream_close_callback(nghttp2_session *session, int32_t stream_id,
                             uint32_t error_code, void *user_data) {
  auto upstream = static_cast<Http2Upstream *>(user_data);
  if (log_enabled(INFO)) {
    Log{INFO, upstream} << "Stream stream_id=" << stream_id
                        << " is being closed";
  }

  auto downstream = static_cast<Downstream *>(
    nghttp2_session_get_stream_user_data(session, stream_id));

  if (!downstream) {
    return 0;
  }

  auto &req = downstream->request();

  upstream->consume(stream_id, req.unconsumed_body_length);

  req.unconsumed_body_length = 0;

  if (downstream->get_request_state() == DownstreamState::CONNECT_FAIL) {
    upstream->remove_downstream(downstream);
    // downstream was deleted

    return 0;
  }

  if (downstream->can_detach_downstream_connection()) {
    // Keep-alive
    downstream->detach_downstream_connection();
  }

  downstream->set_request_state(DownstreamState::STREAM_CLOSED);

  // At this point, downstream read may be paused.

  // If shrpx_downstream::push_request_headers() failed, the
  // error is handled here.
  upstream->remove_downstream(downstream);
  // downstream was deleted

  // How to test this case? Request sufficient large download
  // and make client send RST_STREAM after it gets first DATA
  // frame chunk.

  return 0;
}
} // namespace

std::expected<void, Error>
Http2Upstream::upgrade_upstream(HttpsUpstream *http) {
  int rv;

  auto &balloc = http->get_downstream()->get_block_allocator();

  auto http2_settings = http->get_downstream()->get_http2_settings();
  http2_settings = util::to_base64(balloc, http2_settings);

  auto settings_payload = base64::decode(balloc, http2_settings);

  rv = nghttp2_session_upgrade2(
    session_, settings_payload.data(), settings_payload.size(),
    http->get_downstream()->request().method == HTTP_HEAD, nullptr);
  if (rv != 0) {
    if (log_enabled(INFO)) {
      Log{INFO, this} << "nghttp2_session_upgrade() returned error: "
                      << nghttp2_strerror(rv);
    }
    return std::unexpected{Error::HTTP2};
  }
  pre_upstream_.reset(http);
  auto downstream = http->pop_downstream();
  downstream->reset_upstream(this);
  downstream->set_stream_id(1);
  downstream->reset_upstream_rtimer();
  downstream->set_stream_id(1);

  auto ptr = downstream.get();

  nghttp2_session_set_stream_user_data(session_, 1, ptr);
  downstream_queue_.add_pending(std::move(downstream));
  downstream_queue_.mark_active(ptr);

  // TODO This might not be necessary
  handler_->stop_read_timer();

  if (log_enabled(INFO)) {
    Log{INFO, this} << "Connection upgraded to HTTP/2";
  }

  return {};
}

void Http2Upstream::start_settings_timer() {
  ev_timer_start(handler_->get_loop(), &settings_timer_);
}

void Http2Upstream::stop_settings_timer() {
  ev_timer_stop(handler_->get_loop(), &settings_timer_);
}

namespace {
int on_header_callback2(nghttp2_session *session, const nghttp2_frame *frame,
                        nghttp2_rcbuf *name, nghttp2_rcbuf *value,
                        uint8_t flags, void *user_data) {
  auto namebuf = nghttp2_rcbuf_get_buf(name);
  auto valuebuf = nghttp2_rcbuf_get_buf(value);
  auto config = get_config();

  if (config->http2.upstream.debug.frame_debug) {
    verbose_on_header_callback(session, frame, namebuf.base, namebuf.len,
                               valuebuf.base, valuebuf.len, flags, user_data);
  }
  if (frame->hd.type != NGHTTP2_HEADERS) {
    return 0;
  }
  auto upstream = static_cast<Http2Upstream *>(user_data);
  auto downstream = static_cast<Downstream *>(
    nghttp2_session_get_stream_user_data(session, frame->hd.stream_id));
  if (!downstream) {
    return 0;
  }

  auto &req = downstream->request();

  auto &httpconf = config->http;

  if (req.fs.buffer_size() + namebuf.len + valuebuf.len >
        httpconf.request_header_field_buffer ||
      req.fs.num_fields() >= httpconf.max_request_header_fields) {
    if (downstream->get_response_state() == DownstreamState::MSG_COMPLETE) {
      return 0;
    }

    if (log_enabled(INFO)) {
      Log{INFO, upstream} << "Too large or many header field size="
                          << req.fs.buffer_size() + namebuf.len + valuebuf.len
                          << ", num=" << req.fs.num_fields() + 1;
    }

    // just ignore header fields if this is trailer part.
    if (frame->headers.cat == NGHTTP2_HCAT_HEADERS) {
      return 0;
    }

    if (!upstream->error_reply(downstream, 431)) {
      return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
    }

    return 0;
  }

  auto nameref = as_string_view(namebuf.base, namebuf.len);
  auto valueref = as_string_view(valuebuf.base, valuebuf.len);
  auto token = http2::lookup_token(nameref);
  auto no_index = flags & NGHTTP2_NV_FLAG_NO_INDEX;

  downstream->add_rcbuf(name);
  downstream->add_rcbuf(value);

  if (frame->headers.cat == NGHTTP2_HCAT_HEADERS) {
    // just store header fields for trailer part
    req.fs.add_trailer_token(nameref, valueref, no_index, token);
    return 0;
  }

  req.fs.add_header_token(nameref, valueref, no_index, token);
  return 0;
}
} // namespace

namespace {
int on_begin_headers_callback(nghttp2_session *session,
                              const nghttp2_frame *frame, void *user_data) {
  auto upstream = static_cast<Http2Upstream *>(user_data);

  if (frame->headers.cat != NGHTTP2_HCAT_REQUEST) {
    return 0;
  }
  if (log_enabled(INFO)) {
    Log{INFO, upstream} << "Received upstream request HEADERS stream_id="
                        << frame->hd.stream_id;
  }

  upstream->on_start_request(frame);

  return 0;
}
} // namespace

void Http2Upstream::on_start_request(const nghttp2_frame *frame) {
  auto downstream = std::make_unique<Downstream>(this, handler_->get_mcpool(),
                                                 frame->hd.stream_id);
  nghttp2_session_set_stream_user_data(session_, frame->hd.stream_id,
                                       downstream.get());

  downstream->reset_upstream_rtimer();

  auto config = get_config();
  auto &httpconf = config->http;

  handler_->reset_upstream_read_timeout(httpconf.timeout.header);

  auto &req = downstream->request();

  // Although, we deprecated minor version from HTTP/2, we supply
  // minor version 0 to use via header field in a conventional way.
  req.http_major = 2;
  req.http_minor = 0;

  add_pending_downstream(std::move(downstream));

  ++num_requests_;

  if (httpconf.max_requests <= num_requests_) {
    start_graceful_shutdown();
  }
}

std::expected<void, Error>
Http2Upstream::on_request_headers(Downstream *downstream,
                                  const nghttp2_frame *frame) {
  auto lgconf = log_config();
  lgconf->update_tstamp(std::chrono::system_clock::now());
  auto &req = downstream->request();
  req.tstamp = lgconf->tstamp;

  if (downstream->get_response_state() == DownstreamState::MSG_COMPLETE) {
    return {};
  }

  auto &nva = req.fs.headers();

  if (log_enabled(INFO)) {
    std::string ss;
    for (auto &nv : nva) {
      if (nv.name == "authorization"sv) {
        ss += tty_http_hd();
        ss += nv.name;
        ss += tty_rst();
        ss += ": <redacted>\n";
        continue;
      }
      ss += tty_http_hd();
      ss += nv.name;
      ss += tty_rst();
      ss += ": ";
      ss += nv.value;
      ss += '\n';
    }
    Log{INFO, this} << "HTTP request headers. stream_id="
                    << downstream->get_stream_id() << "\n"
                    << ss;
  }

  auto config = get_config();
  auto &dump = config->http2.upstream.debug.dump;

  if (dump.request_header) {
    http2::dump_nv(dump.request_header, nva);
  }

  auto content_length = req.fs.header(http2::HD_CONTENT_LENGTH);
  if (content_length) {
    // libnghttp2 guarantees this can be parsed
    req.fs.content_length =
      static_cast<int64_t>(*util::parse_uint(content_length->value));
  }

  // presence of mandatory header fields are guaranteed by libnghttp2.
  auto authority = req.fs.header(http2::HD__AUTHORITY);
  auto path = req.fs.header(http2::HD__PATH);
  auto method = req.fs.header(http2::HD__METHOD);
  auto scheme = req.fs.header(http2::HD__SCHEME);

  auto method_token = http2::lookup_method_token(method->value);
  if (method_token == -1) {
    return error_reply(downstream, 501);
  }

  auto faddr = handler_->get_upstream_addr();

  // For HTTP/2 proxy, we require :authority.
  if (method_token != HTTP_CONNECT && config->http2_proxy &&
      faddr->alt_mode == UpstreamAltMode::NONE && !authority) {
    rst_stream(downstream, NGHTTP2_PROTOCOL_ERROR);
    return {};
  }

  req.method = method_token;
  if (scheme) {
    req.scheme = scheme->value;
  }

  // nghttp2 library guarantees either :authority or host exist
  if (!authority) {
    req.no_authority = true;
    authority = req.fs.header(http2::HD_HOST);
  }

  if (authority) {
    req.authority = authority->value;
  }

  if (path) {
    if (method_token == HTTP_OPTIONS && path->value == "*"sv) {
      // Server-wide OPTIONS request.  Path is empty.
    } else if (config->http2_proxy &&
               faddr->alt_mode == UpstreamAltMode::NONE) {
      req.path = path->value;
    } else {
      req.path = http2::rewrite_clean_path(downstream->get_block_allocator(),
                                           path->value);
    }
  }

  auto connect_proto = req.fs.header(http2::HD__PROTOCOL);
  if (connect_proto) {
    if (connect_proto->value != "websocket"sv) {
      return error_reply(downstream, 400);
    }
    req.connect_proto = ConnectProto::WEBSOCKET;
  }

  if (!(frame->hd.flags & NGHTTP2_FLAG_END_STREAM)) {
    req.http2_expect_body = true;
  } else if (req.fs.content_length == -1) {
    // If END_STREAM flag is set to HEADERS frame, we are sure that
    // content-length is 0.
    req.fs.content_length = 0;
  }

  downstream->inspect_http2_request();

  downstream->set_request_state(DownstreamState::HEADER_COMPLETE);

  if (config->http.require_http_scheme &&
      !http::check_http_scheme(req.scheme, handler_->get_ssl() != nullptr)) {
    return error_reply(downstream, 400);
  }

#ifdef HAVE_MRUBY
  auto worker = handler_->get_worker();
  auto mruby_ctx = worker->get_mruby_context();

  if (!mruby_ctx->run_on_request_proc(downstream)) {
    return error_reply(downstream, 500);
  }
#endif // defined(HAVE_MRUBY)

  if (frame->hd.flags & NGHTTP2_FLAG_END_STREAM) {
    downstream->disable_upstream_rtimer();

    downstream->set_request_state(DownstreamState::MSG_COMPLETE);
  }

  if (downstream->get_response_state() == DownstreamState::MSG_COMPLETE) {
    return {};
  }

  start_downstream(downstream);

  return {};
}

void Http2Upstream::start_downstream(Downstream *downstream) {
  if (downstream_queue_.can_activate(downstream->request().authority)) {
    initiate_downstream(downstream);
    return;
  }

  downstream_queue_.mark_blocked(downstream);
}

void Http2Upstream::initiate_downstream(Downstream *downstream) {
#ifdef HAVE_MRUBY
  DownstreamConnection *dconn_ptr;
#endif // defined(HAVE_MRUBY)

  for (;;) {
    auto maybe_dconn = handler_->get_downstream_connection(downstream);
    if (!maybe_dconn) {
      if (!(maybe_dconn.error() == Error::TLS_REQUIRED
              ? redirect_to_https(downstream)
              : error_reply(downstream, 502))) {
        rst_stream(downstream, NGHTTP2_INTERNAL_ERROR);
      }

      downstream->set_request_state(DownstreamState::CONNECT_FAIL);
      downstream_queue_.mark_failure(downstream);

      return;
    }

    auto dconn = std::move(*maybe_dconn);

#ifdef HAVE_MRUBY
    dconn_ptr = dconn.get();
#endif // defined(HAVE_MRUBY)
    if (downstream->attach_downstream_connection(std::move(dconn))) {
      break;
    }
  }

#ifdef HAVE_MRUBY
  const auto &group = dconn_ptr->get_downstream_addr_group();
  if (group) {
    const auto &mruby_ctx = group->shared_addr->mruby_ctx;
    if (!mruby_ctx->run_on_request_proc(downstream)) {
      if (!error_reply(downstream, 500)) {
        rst_stream(downstream, NGHTTP2_INTERNAL_ERROR);
      }

      downstream_queue_.mark_failure(downstream);

      return;
    }

    if (downstream->get_response_state() == DownstreamState::MSG_COMPLETE) {
      return;
    }
  }
#endif // defined(HAVE_MRUBY)

  if (!downstream->push_request_headers()) {
    if (!error_reply(downstream, 502)) {
      rst_stream(downstream, NGHTTP2_INTERNAL_ERROR);
    }

    downstream_queue_.mark_failure(downstream);

    return;
  }

  downstream_queue_.mark_active(downstream);

  auto &req = downstream->request();
  if (!req.http2_expect_body && !downstream->end_upload_data()) {
    rst_stream(downstream, NGHTTP2_INTERNAL_ERROR);
  }

  return;
}

namespace {
int on_frame_recv_callback(nghttp2_session *session, const nghttp2_frame *frame,
                           void *user_data) {
  if (get_config()->http2.upstream.debug.frame_debug) {
    verbose_on_frame_recv_callback(session, frame, user_data);
  }
  auto upstream = static_cast<Http2Upstream *>(user_data);
  auto handler = upstream->get_client_handler();

  switch (frame->hd.type) {
  case NGHTTP2_DATA: {
    auto downstream = static_cast<Downstream *>(
      nghttp2_session_get_stream_user_data(session, frame->hd.stream_id));
    if (!downstream) {
      return 0;
    }

    if (frame->hd.flags & NGHTTP2_FLAG_END_STREAM) {
      downstream->disable_upstream_rtimer();

      if (!downstream->end_upload_data() &&
          downstream->get_response_state() != DownstreamState::MSG_COMPLETE) {
        upstream->rst_stream(downstream, NGHTTP2_INTERNAL_ERROR);
      }

      downstream->set_request_state(DownstreamState::MSG_COMPLETE);
    }

    return 0;
  }
  case NGHTTP2_HEADERS: {
    auto downstream = static_cast<Downstream *>(
      nghttp2_session_get_stream_user_data(session, frame->hd.stream_id));
    if (!downstream) {
      return 0;
    }

    if (frame->headers.cat == NGHTTP2_HCAT_REQUEST) {
      downstream->reset_upstream_rtimer();

      handler->stop_read_timer();

      if (!upstream->on_request_headers(downstream, frame)) {
        return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
      }

      return 0;
    }

    if (frame->hd.flags & NGHTTP2_FLAG_END_STREAM) {
      downstream->disable_upstream_rtimer();

      if (!downstream->end_upload_data() &&
          downstream->get_response_state() != DownstreamState::MSG_COMPLETE) {
        upstream->rst_stream(downstream, NGHTTP2_INTERNAL_ERROR);
      }

      downstream->set_request_state(DownstreamState::MSG_COMPLETE);
    }

    return 0;
  }
  case NGHTTP2_SETTINGS:
    if ((frame->hd.flags & NGHTTP2_FLAG_ACK) == 0) {
      return 0;
    }
    upstream->stop_settings_timer();
    return 0;
  case NGHTTP2_GOAWAY:
    if (log_enabled(INFO)) {
      auto debug_data = util::ascii_dump(frame->goaway.opaque_data,
                                         frame->goaway.opaque_data_len);

      Log{INFO, upstream} << "GOAWAY received: last-stream-id="
                          << frame->goaway.last_stream_id
                          << ", error_code=" << frame->goaway.error_code
                          << ", debug_data=" << debug_data;
    }
    return 0;
  default:
    return 0;
  }
}
} // namespace

namespace {
int on_data_chunk_recv_callback(nghttp2_session *session, uint8_t flags,
                                int32_t stream_id, const uint8_t *data,
                                size_t len, void *user_data) {
  auto upstream = static_cast<Http2Upstream *>(user_data);
  auto downstream = static_cast<Downstream *>(
    nghttp2_session_get_stream_user_data(session, stream_id));

  if (!downstream) {
    if (!upstream->consume(stream_id, len)) {
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    }

    return 0;
  }

  downstream->reset_upstream_rtimer();

  if (!downstream->push_upload_data_chunk({data, len})) {
    if (downstream->get_response_state() != DownstreamState::MSG_COMPLETE) {
      upstream->rst_stream(downstream, NGHTTP2_INTERNAL_ERROR);
    }

    if (!upstream->consume(stream_id, len)) {
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    }

    return 0;
  }

  return 0;
}
} // namespace

namespace {
int on_frame_send_callback(nghttp2_session *session, const nghttp2_frame *frame,
                           void *user_data) {
  if (get_config()->http2.upstream.debug.frame_debug) {
    verbose_on_frame_send_callback(session, frame, user_data);
  }
  auto upstream = static_cast<Http2Upstream *>(user_data);
  auto handler = upstream->get_client_handler();

  switch (frame->hd.type) {
  case NGHTTP2_DATA:
  case NGHTTP2_HEADERS: {
    if ((frame->hd.flags & NGHTTP2_FLAG_END_STREAM) == 0) {
      return 0;
    }
    // RST_STREAM if request is still incomplete.
    auto stream_id = frame->hd.stream_id;
    auto downstream = static_cast<Downstream *>(
      nghttp2_session_get_stream_user_data(session, stream_id));

    if (!downstream) {
      return 0;
    }

    // For tunneling, issue RST_STREAM to finish the stream.
    if (downstream->get_upgraded() ||
        nghttp2_session_get_stream_remote_close(session, stream_id) == 0) {
      if (log_enabled(INFO)) {
        Log{INFO, upstream}
          << "Send RST_STREAM to "
          << (downstream->get_upgraded() ? "tunneled " : "")
          << "stream stream_id=" << downstream->get_stream_id()
          << " to finish off incomplete request";
      }

      upstream->rst_stream(downstream, NGHTTP2_NO_ERROR);
    }

    return 0;
  }
  case NGHTTP2_SETTINGS:
    if ((frame->hd.flags & NGHTTP2_FLAG_ACK) == 0) {
      upstream->start_settings_timer();
    }
    return 0;
  case NGHTTP2_PUSH_PROMISE: {
    auto promised_stream_id = frame->push_promise.promised_stream_id;

    if (nghttp2_session_get_stream_user_data(session, promised_stream_id)) {
      // In case of push from backend, downstream object was already
      // created.
      return 0;
    }

    auto promised_downstream = std::make_unique<Downstream>(
      upstream, handler->get_mcpool(), promised_stream_id);
    auto &req = promised_downstream->request();

    // As long as we use nghttp2_session_mem_send2(), setting stream
    // user data here should not fail.  This is because this callback
    // is called just after frame was serialized.  So no worries about
    // hanging Downstream.
    nghttp2_session_set_stream_user_data(session, promised_stream_id,
                                         promised_downstream.get());

    promised_downstream->set_assoc_stream_id(frame->hd.stream_id);
    promised_downstream->disable_upstream_rtimer();

    req.http_major = 2;
    req.http_minor = 0;

    req.fs.content_length = 0;
    req.http2_expect_body = false;

    auto &promised_balloc = promised_downstream->get_block_allocator();

    for (size_t i = 0; i < frame->push_promise.nvlen; ++i) {
      auto &nv = frame->push_promise.nva[i];

      auto name =
        make_string_ref(promised_balloc, as_string_view(nv.name, nv.namelen));
      auto value =
        make_string_ref(promised_balloc, as_string_view(nv.value, nv.valuelen));

      auto token = http2::lookup_token(name);
      switch (token) {
      case http2::HD__METHOD:
        req.method = http2::lookup_method_token(value);
        break;
      case http2::HD__SCHEME:
        req.scheme = value;
        break;
      case http2::HD__AUTHORITY:
        req.authority = value;
        break;
      case http2::HD__PATH:
        req.path = http2::rewrite_clean_path(promised_balloc, value);
        break;
      }
      req.fs.add_header_token(name, value, nv.flags & NGHTTP2_NV_FLAG_NO_INDEX,
                              token);
    }

    promised_downstream->inspect_http2_request();

    promised_downstream->set_request_state(DownstreamState::MSG_COMPLETE);

    // a bit weird but start_downstream() expects that given
    // downstream is in pending queue.
    auto ptr = promised_downstream.get();
    upstream->add_pending_downstream(std::move(promised_downstream));

#ifdef HAVE_MRUBY
    auto worker = handler->get_worker();
    auto mruby_ctx = worker->get_mruby_context();

    if (!mruby_ctx->run_on_request_proc(ptr)) {
      if (!upstream->error_reply(ptr, 500)) {
        upstream->rst_stream(ptr, NGHTTP2_INTERNAL_ERROR);
        return 0;
      }
      return 0;
    }
#endif // defined(HAVE_MRUBY)

    upstream->start_downstream(ptr);

    return 0;
  }
  case NGHTTP2_GOAWAY:
    if (log_enabled(INFO)) {
      auto debug_data = util::ascii_dump(frame->goaway.opaque_data,
                                         frame->goaway.opaque_data_len);

      Log{INFO, upstream} << "Sending GOAWAY: last-stream-id="
                          << frame->goaway.last_stream_id
                          << ", error_code=" << frame->goaway.error_code
                          << ", debug_data=" << debug_data;
    }
    return 0;
  default:
    return 0;
  }
}
} // namespace

namespace {
int on_frame_not_send_callback(nghttp2_session *session,
                               const nghttp2_frame *frame, int lib_error_code,
                               void *user_data) {
  auto upstream = static_cast<Http2Upstream *>(user_data);
  if (log_enabled(INFO)) {
    Log{INFO, upstream} << "Failed to send control frame type="
                        << static_cast<uint32_t>(frame->hd.type)
                        << ", lib_error_code=" << lib_error_code << ":"
                        << nghttp2_strerror(lib_error_code);
  }
  if (frame->hd.type == NGHTTP2_HEADERS &&
      lib_error_code != NGHTTP2_ERR_STREAM_CLOSED &&
      lib_error_code != NGHTTP2_ERR_STREAM_CLOSING) {
    // To avoid stream hanging around, issue RST_STREAM.
    auto downstream = static_cast<Downstream *>(
      nghttp2_session_get_stream_user_data(session, frame->hd.stream_id));
    if (downstream) {
      upstream->rst_stream(downstream, NGHTTP2_INTERNAL_ERROR);
    }
  }
  return 0;
}
} // namespace

constexpr auto PADDING = std::array<uint8_t, 256>{};

namespace {
// [XLIO-ZC] Single source of truth for "can this backend response body be
// relayed to the client via zero-copy?" Both the decision to queue a chunk
// into zc_body_queue_ (on_downstream_body) and the decision to actually
// send it that way (send_data_callback) must agree on this, or nghttp2
// commits to a DATA frame length that the eligible-vs-not-eligible split
// then can't consistently deliver — the truncated/corrupted-frame bug this
// guards against. Eligible only if the frontend has a usable Ultra TX
// socket AND it shares a protection domain with the backend connection
// that produced the buffer (sendv_zc() can't DMA-send a buffer registered
// under a different PD).
bool zc_relay_eligible(Http2Upstream *upstream, Http2Session *backend) {
  if (!backend) return false;
  auto &xa    = XlioAdapter::get();
  auto  csock = upstream->get_client_handler()->get_connection()->xlio_sock;
  if (!csock || !xa.has_ultra_tx()) return false;
  auto  backend_sock = xa.socket_from_fd(backend->get_fd());
  auto *csock_pd      = xa.get_pd(csock);
  auto *backend_pd    = xa.get_pd(backend_sock);
  bool  eligible      = backend_pd && backend_pd == csock_pd;
  if (!eligible) {
    // [XLIO-ZC] Breaks down *why* eligibility failed: backend_sock==0 means
    // xlio_socket_from_fd() itself failed for the backend fd (per its
    // contract in sock-extra.cpp, only if the fd isn't XLIO-managed or isn't
    // a sockinfo_tcp — shouldn't happen for a live backend connection);
    // backend_sock!=0 but backend_pd==nullptr means the handle was obtained
    // but its ib_ctx_handler/ibv_pd isn't set up; both non-null but unequal
    // means frontend and backend are genuinely on different rings/devices.
    PROBNIK_LOG(PROBNIK_DEBUG, "zc-trace",
                "zc_relay_eligible FALSE: backend_fd=%d backend_sock=%d"
                " backend_pd=%p csock=%d csock_pd=%p",
                backend->get_fd(), static_cast<bool>(backend_sock),
                (void *)backend_pd, static_cast<bool>(csock), (void *)csock_pd);
  }
  return eligible;
}
} // namespace

namespace {
int send_data_callback(nghttp2_session *session, nghttp2_frame *frame,
                       const uint8_t *framehd, size_t length,
                       nghttp2_data_source *source, void *user_data) {
  auto downstream = static_cast<Downstream *>(source->ptr);
  auto upstream = static_cast<Http2Upstream *>(downstream->get_upstream());
  auto body = downstream->get_response_buf();

  auto wb = upstream->get_response_buf();

  size_t padlen = 0;

  // [XLIO-ZC] Hardware zero-copy DATA frame send path.
  //
  // Conditions: ZC body is queued, no padding (simplifies accounting), and
  // the client has an XLIO Ultra socket.
  //
  // Strategy (preserves HTTP/2 byte-stream order):
  //   1. flush_response_buf() — send all preceding frames (HEADERS, SETTINGS)
  //      from wb_ to the TLS socket NOW, before touching the DATA frame.
  //   2. sendv_inline(header, MSG_MORE) — send 9-byte DATA frame header
  //      directly via XLIO, deferring flush until step 3.
  //   3. sendv_zc(payload, flush) — send ZC payload; NIC reads from DMA and
  //      re-encrypts.  ZcRxOwner::put() fires on TCP ACK to free the buffer.
  //
  // wb_ is completely bypassed for the DATA frame itself (no copy).
  if (!downstream->zc_body_empty() && frame->data.padlen == 0) {
    auto &xa    = XlioAdapter::get();
    auto  csock = upstream->get_client_handler()->get_connection()->xlio_sock;

    // [XLIO-ZC] Deliberately NOT re-deriving backend/PD eligibility here via
    // zc_relay_eligible(): by the time send_data_callback runs, nghttp2 may
    // have already detached this Downstream's DownstreamConnection back into
    // the backend pool (happens as soon as the backend response is fully
    // read, well before all DATA frames finish sending to the client) —
    // downstream->get_downstream_connection() can be null here even though
    // everything currently in zc_body_queue_ was correctly vetted against
    // the backend's PD at queue time (on_downstream_body, before the
    // connection could be detached). Re-checking against a possibly-gone
    // backend here produced false negatives (queued-eligible chunks
    // reported ineligible at send time, every time, once the backend
    // detached first) — found live 2026-09-07. Only the frontend side can
    // actually change between queue and send time, so only check that.
    bool eligible = csock && xa.has_ultra_tx();

    if (!eligible) {
      // [XLIO-ZC] Falling through to the copy path below drains `body`
      // (downstream->get_response_buf()), NOT zc_body_queue_, so if this
      // frame's bytes were only ever queued in zc_body_queue_, they're lost:
      // a corrupted/truncated DATA frame. Should be rare — only a frontend
      // connection that lost its Ultra socket between queue and send time.
      PROBNIK_LOG(PROBNIK_ERROR, "tls-resume",
                  "[XLIO-ZC] send_data_callback INELIGIBLE-AT-SEND stream=%d"
                  " frame_len=%zu zc_queue=%zu body_rleft=%zu csock=%d"
                  " has_ultra_tx=%d — falling through to copy path, which"
                  " will NOT send the queued ZC bytes if body is empty"
                  " (frame may be truncated/corrupted)",
                  frame->hd.stream_id, length, downstream->get_zc_body_rleft(),
                  body->rleft(), static_cast<bool>(csock), xa.has_ultra_tx());
    }
    if (eligible) {

      // 1. Flush wb_ (HEADERS frames) to the TLS socket BEFORE the DATA frame.
      if (!upstream->flush_response_buf()) {
        Log{INFO, upstream}
            << "[XLIO-ZC] send_data_callback: flush_response_buf EAGAIN/err"
               " — aborting ZC for this frame (connection will close)";
        return NGHTTP2_ERR_CALLBACK_FAILURE;
      }

      // 2. Send the 9-byte HTTP/2 DATA frame header inline (MSG_MORE: not
      //    flushed yet, waits for the ZC payload to form the same TCP segment).
      {
        struct iovec hdr_iov{const_cast<uint8_t *>(framehd), 9};
        int hrc = xa.sendv_inline(csock, &hdr_iov, 1, /*flush=*/false);
        if (hrc < 0) {
          Log{INFO, upstream}
              << "[XLIO-ZC] send_data_callback: header sendv_inline failed rc="
              << hrc;
          return NGHTTP2_ERR_CALLBACK_FAILURE;
        }
      }

      // 3. Send ZC payload — NIC reads from DMA buffer, TLS encrypts.
      //    buf ownership transfers to ZcRxOwner; freed on TCP ACK.
      auto ref = downstream->pop_zc_body();

      // Correctness check: length (from downstream_data_read_callback) must
      // equal ref.len (the ZcBodyRef we're about to send).  A mismatch means
      // the DATA frame header would claim N bytes but only M bytes follow on
      // the wire, corrupting the HTTP/2 stream.
      if (log_enabled(INFO)) {
        Log{INFO, upstream}
            << "[XLIO-ZC] send_data_cb pre-send:"
            << " stream=" << frame->hd.stream_id
            << " nghttp2_len=" << length
            << " ref_len=" << ref.len
            << " zc_rleft_after=" << downstream->get_zc_body_rleft()
            << (length == ref.len ? " [MATCH ✓]" : " [MISMATCH ✗ — frame corrupted!]");
      }

      struct iovec iov{const_cast<uint8_t *>(ref.data), ref.len};
      int rc = xa.sendv_zc(csock, &iov, 1, ref.buf, /*flush=*/true);

      if (log_enabled(INFO)) {
        Log{INFO, upstream}
            << "[XLIO-ZC] ZC DATA frame sent:"
            << " stream=" << frame->hd.stream_id
            << " len=" << ref.len
            << " mkey=" << xa.buf_get_mkey(ref.buf)
            << " rc=" << rc
            << (rc >= 0 ? " [buf → ZcRxOwner, freed on TCP ACK]"
                        : " [sendv_zc FAILED — buf released by ZcRxOwner]");
      }

      if (rc < 0) {
        return NGHTTP2_ERR_CALLBACK_FAILURE;
      }

      {
        auto &zs = zcopy_stats();
        zs.send_zc_frames.fetch_add(1, std::memory_order_relaxed);
        zs.send_zc_bytes.fetch_add(static_cast<uint64_t>(ref.len),
                                   std::memory_order_relaxed);
      }

      // Bookkeeping (same as copy path).
      if (downstream->zc_body_empty() && body->rleft() == 0) {
        downstream->disable_upstream_wtimer();
      } else {
        downstream->reset_upstream_wtimer();
      }
      if (length > 0 && !downstream->resume_read(SHRPX_NO_BUFFER, length)) {
        return NGHTTP2_ERR_CALLBACK_FAILURE;
      }
      downstream->response_sent_body_length += length;
      return 0;
    }
  }

  // Copy path (ZC conditions not met or no XLIO socket).
  if (log_enabled(INFO)) {
    Log{INFO, upstream}
        << "[XLIO-ZC] COPY DATA frame: stream=" << frame->hd.stream_id
        << " len=" << length
        << " body_rleft=" << body->rleft()
        << " zc_queue=" << downstream->get_zc_body_rleft();
  }
  wb->append(framehd, 9);
  if (frame->data.padlen > 0) {
    padlen = frame->data.padlen - 1;
    wb->append(static_cast<char>(padlen));
  }

#ifdef SHRPX_ZC_BODY
  // [SHRPX_ZC_BODY] Zero-copy send path (Copy #3 elimination):
  // remove_zc splices full 16 KB Memchunks from body into wb by pointer
  // manipulation (zero bytes copied per full chunk).  Only the final partial
  // chunk is byte-copied.  Both body and wb are DefaultMemchunks from the
  // same worker pool, satisfying the pool-same-owner precondition.
  {
    // Diagnostic: record call-site shape before the splice.
    auto &zs = zcopy_stats();
    auto head_mlen   = body->head ? body->head->len() : 0u;
    auto body_rleft  = body->rleft();
    // Query the actual remote stream window nghttp2 sees right now.
    // If avg_remote_win ≈ avg_length → window is the binding constraint.
    // If avg_remote_win ≫ avg_length → something inside nghttpx caps frame size.
    auto rwin = nghttp2_session_get_stream_remote_window_size(
        session, frame->hd.stream_id);
    zs.send_cb_count.fetch_add(1, std::memory_order_relaxed);
    zs.send_cb_length_total.fetch_add(length, std::memory_order_relaxed);
    zs.send_cb_head_mlen_total.fetch_add(head_mlen, std::memory_order_relaxed);
    if (rwin > 0) {
      zs.send_cb_remote_win_total.fetch_add(static_cast<uint64_t>(rwin),
                                            std::memory_order_relaxed);
    }
    // body_drained: length consumed all (or more than) what body currently holds,
    // meaning body—not flow control—was the binding constraint on frame size.
    if (length >= body_rleft) {
      zs.send_cb_body_drained.fetch_add(1, std::memory_order_relaxed);
    }

    size_t tail_copied = 0;
    auto moved = body->remove_zc(*wb, length, &tail_copied);
    // spliced = zero-copy bytes (phase 1), tail_copied = memcpy bytes (phase 2)
    auto spliced = moved - tail_copied;
    if (spliced > 0) {
      zs.send_spliced_bytes.fetch_add(spliced, std::memory_order_relaxed);
    }
    if (tail_copied > 0) {
      zs.send_tail_bytes.fetch_add(tail_copied, std::memory_order_relaxed);
    }
    if (spliced == 0) {
      zs.send_cb_zero_splice.fetch_add(1, std::memory_order_relaxed);
    }
    if (tail_copied == 0) {
      zs.send_cb_full_splice.fetch_add(1, std::memory_order_relaxed);
    }
  }
#else
  body->remove(*wb, length);
#endif

  wb->append(PADDING.data(), padlen);

  if (body->rleft() == 0 && downstream->zc_body_empty()) {
    downstream->disable_upstream_wtimer();
  } else {
    downstream->reset_upstream_wtimer();
  }

  if (length > 0 && !downstream->resume_read(SHRPX_NO_BUFFER, length)) {
    return NGHTTP2_ERR_CALLBACK_FAILURE;
  }

  // We have to add length here, so that we can log this amount of
  // data transferred.
  downstream->response_sent_body_length += length;

  auto max_buffer_size = upstream->get_max_buffer_size();

  return wb->rleft() >= max_buffer_size ? NGHTTP2_ERR_PAUSE : 0;
}
} // namespace

namespace {
uint32_t infer_upstream_rst_stream_error_code(uint32_t downstream_error_code) {
  // NGHTTP2_REFUSED_STREAM is important because it tells upstream
  // client to retry.
  switch (downstream_error_code) {
  case NGHTTP2_NO_ERROR:
  case NGHTTP2_REFUSED_STREAM:
    return downstream_error_code;
  default:
    return NGHTTP2_INTERNAL_ERROR;
  }
}
} // namespace

namespace {
void settings_timeout_cb(struct ev_loop *loop, ev_timer *w, int revents) {
  auto upstream = static_cast<Http2Upstream *>(w->data);
  auto handler = upstream->get_client_handler();
  Log{INFO, upstream} << "SETTINGS timeout";
  if (!upstream->terminate_session(NGHTTP2_SETTINGS_TIMEOUT)) {
    delete handler;
    return;
  }
  handler->signal_write();
}
} // namespace

namespace {
void shutdown_timeout_cb(struct ev_loop *loop, ev_timer *w, int revents) {
  auto upstream = static_cast<Http2Upstream *>(w->data);
  auto handler = upstream->get_client_handler();
  upstream->submit_goaway();
  handler->signal_write();
}
} // namespace

namespace {
void prepare_cb(struct ev_loop *loop, ev_prepare *w, int revents) {
  auto upstream = static_cast<Http2Upstream *>(w->data);
  upstream->check_shutdown();
}
} // namespace

void Http2Upstream::submit_goaway() {
  auto last_stream_id = nghttp2_session_get_last_proc_stream_id(session_);
  nghttp2_submit_goaway(session_, NGHTTP2_FLAG_NONE, last_stream_id,
                        NGHTTP2_NO_ERROR, nullptr, 0);
}

void Http2Upstream::check_shutdown() {
  auto worker = handler_->get_worker();

  if (!worker->get_graceful_shutdown()) {
    return;
  }

  ev_prepare_stop(handler_->get_loop(), &prep_);

  start_graceful_shutdown();
}

void Http2Upstream::start_graceful_shutdown() {
  int rv;
  if (ev_is_active(&shutdown_timer_)) {
    return;
  }

  rv = nghttp2_submit_shutdown_notice(session_);
  if (rv != 0) {
    Log{FATAL, this} << "nghttp2_submit_shutdown_notice() failed: "
                     << nghttp2_strerror(rv);
    return;
  }

  handler_->signal_write();

  ev_timer_start(handler_->get_loop(), &shutdown_timer_);
}

nghttp2_session_callbacks *create_http2_upstream_callbacks() {
  int rv;
  nghttp2_session_callbacks *callbacks;

  rv = nghttp2_session_callbacks_new(&callbacks);

  if (rv != 0) {
    return nullptr;
  }

  nghttp2_session_callbacks_set_on_stream_close_callback(
    callbacks, on_stream_close_callback);

  nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks,
                                                       on_frame_recv_callback);

  nghttp2_session_callbacks_set_on_data_chunk_recv_callback(
    callbacks, on_data_chunk_recv_callback);

  nghttp2_session_callbacks_set_on_frame_send_callback(callbacks,
                                                       on_frame_send_callback);

  nghttp2_session_callbacks_set_on_frame_not_send_callback(
    callbacks, on_frame_not_send_callback);

  nghttp2_session_callbacks_set_on_header_callback2(callbacks,
                                                    on_header_callback2);

  nghttp2_session_callbacks_set_on_begin_headers_callback(
    callbacks, on_begin_headers_callback);

  nghttp2_session_callbacks_set_send_data_callback(callbacks,
                                                   send_data_callback);

  auto config = get_config();

  if (config->padding) {
    nghttp2_session_callbacks_set_select_padding_callback2(
      callbacks, http::select_padding_callback);
  }

  if (config->http2.upstream.debug.frame_debug) {
    nghttp2_session_callbacks_set_error_callback2(callbacks,
                                                  verbose_error_callback);
  }

  nghttp2_session_callbacks_set_rand_callback(callbacks, util::secure_random);

  return callbacks;
}

namespace {
size_t downstream_queue_size(Worker *worker) {
  auto &downstreamconf = *worker->get_downstream_config();

  if (get_config()->http2_proxy) {
    return downstreamconf.connections_per_host;
  }

  return downstreamconf.connections_per_frontend;
}
} // namespace

Http2Upstream::Http2Upstream(ClientHandler *handler)
  : wb_(handler->get_worker()->get_mcpool()),
    downstream_queue_(downstream_queue_size(handler->get_worker()),
                      !get_config()->http2_proxy),
    handler_(handler),
    session_(nullptr),
    max_buffer_size_(MAX_BUFFER_SIZE),
    num_requests_(0) {
  int rv;

  auto config = get_config();
  auto &http2conf = config->http2;

  auto faddr = handler_->get_upstream_addr();

  rv =
    nghttp2_session_server_new2(&session_, http2conf.upstream.callbacks, this,
                                faddr->alt_mode != UpstreamAltMode::NONE
                                  ? http2conf.upstream.alt_mode_option
                                  : http2conf.upstream.option);

  assert(rv == 0);

  flow_control_ = true;

  // TODO Maybe call from outside?
  std::array<nghttp2_settings_entry, 5> entry;
  size_t nentry = 3;

  entry[0].settings_id = NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS;
  entry[0].value =
    static_cast<uint32_t>(http2conf.upstream.max_concurrent_streams);

  entry[1].settings_id = NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE;
  if (faddr->alt_mode != UpstreamAltMode::NONE) {
    entry[1].value = (1u << 31) - 1;
  } else {
    entry[1].value = as_unsigned(http2conf.upstream.window_size);
  }

  entry[2].settings_id = NGHTTP2_SETTINGS_NO_RFC7540_PRIORITIES;
  entry[2].value = 1;

  if (!config->http2_proxy) {
    entry[nentry].settings_id = NGHTTP2_SETTINGS_ENABLE_CONNECT_PROTOCOL;
    entry[nentry].value = 1;
    ++nentry;
  }

  if (http2conf.upstream.decoder_dynamic_table_size !=
      NGHTTP2_DEFAULT_HEADER_TABLE_SIZE) {
    entry[nentry].settings_id = NGHTTP2_SETTINGS_HEADER_TABLE_SIZE;
    entry[nentry].value =
      static_cast<uint32_t>(http2conf.upstream.decoder_dynamic_table_size);
    ++nentry;
  }

  rv =
    nghttp2_submit_settings(session_, NGHTTP2_FLAG_NONE, entry.data(), nentry);
  if (rv != 0) {
    Log{ERROR, this} << "nghttp2_submit_settings() returned error: "
                     << nghttp2_strerror(rv);
  }

  auto window_size = faddr->alt_mode != UpstreamAltMode::NONE
                       ? std::numeric_limits<int32_t>::max()
                     : http2conf.upstream.optimize_window_size
                       ? std::min(http2conf.upstream.connection_window_size,
                                  NGHTTP2_INITIAL_CONNECTION_WINDOW_SIZE)
                       : http2conf.upstream.connection_window_size;

  rv = nghttp2_session_set_local_window_size(session_, NGHTTP2_FLAG_NONE, 0,
                                             window_size);

  if (rv != 0) {
    Log{ERROR, this}
      << "nghttp2_session_set_local_window_size() returned error: "
      << nghttp2_strerror(rv);
  }

  // We wait for SETTINGS ACK at least 10 seconds.
  ev_timer_init(&settings_timer_, settings_timeout_cb,
                http2conf.upstream.timeout.settings, 0.);

  settings_timer_.data = this;

  // timer for 2nd GOAWAY.  HTTP/2 spec recommend 1 RTT.  We wait for
  // 2 seconds.
  ev_timer_init(&shutdown_timer_, shutdown_timeout_cb, 2., 0);
  shutdown_timer_.data = this;

  ev_prepare_init(&prep_, prepare_cb);
  prep_.data = this;
  ev_prepare_start(handler_->get_loop(), &prep_);

#if defined(TCP_INFO) && defined(TCP_NOTSENT_LOWAT)
  if (http2conf.upstream.optimize_write_buffer_size) {
    auto conn = handler_->get_connection();
    conn->tls_dyn_rec_warmup_threshold = 0;

    uint32_t pollout_thres = 1;
    rv = setsockopt(conn->fd, IPPROTO_TCP, TCP_NOTSENT_LOWAT, &pollout_thres,
                    static_cast<socklen_t>(sizeof(pollout_thres)));

    if (rv != 0) {
      if (log_enabled(INFO)) {
        auto error = errno;
        Log{INFO} << "setsockopt(TCP_NOTSENT_LOWAT, " << pollout_thres
                  << ") failed: errno=" << error;
      }
    }
  }
#endif // defined(TCP_INFO) && defined(TCP_NOTSENT_LOWAT)

  handler_->reset_upstream_read_timeout(
    config->conn.upstream.timeout.http2_idle);

  handler_->signal_write();
}

Http2Upstream::~Http2Upstream() {
  nghttp2_session_del(session_);
  ev_prepare_stop(handler_->get_loop(), &prep_);
  ev_timer_stop(handler_->get_loop(), &shutdown_timer_);
  ev_timer_stop(handler_->get_loop(), &settings_timer_);
}

std::expected<void, Error> Http2Upstream::on_read() {
  auto rb = handler_->get_rb();
  auto rlimit = handler_->get_rlimit();

  if (rb->rleft()) {
    auto rv = nghttp2_session_mem_recv2(session_, rb->pos(), rb->rleft());
    if (rv < 0) {
      if (rv != NGHTTP2_ERR_BAD_CLIENT_MAGIC) {
        Log{ERROR, this} << "nghttp2_session_mem_recv2() returned error: "
                         << nghttp2_strerror(static_cast<int>(rv));
      }
      return std::unexpected{Error::HTTP2};
    }

    // nghttp2_session_mem_recv2 should consume all input bytes on
    // success.
    assert(static_cast<size_t>(rv) == rb->rleft());
    rb->reset();
    rlimit->startw();
  }

  if (nghttp2_session_want_read(session_) == 0 &&
      nghttp2_session_want_write(session_) == 0 && wb_.rleft() == 0) {
    if (log_enabled(INFO)) {
      Log{INFO, this} << "No more read/write for this HTTP2 session";
    }
    return std::unexpected{Error::DONE};
  }

  handler_->signal_write();
  return {};
}

// After this function call, downstream may be deleted.
std::expected<void, Error> Http2Upstream::on_write() {
  int rv;
  auto config = get_config();
  auto &http2conf = config->http2;

  if ((http2conf.upstream.optimize_write_buffer_size ||
       http2conf.upstream.optimize_window_size) &&
      handler_->get_ssl()) {
    auto conn = handler_->get_connection();
    auto maybe_hint = conn->get_tcp_hint();
    if (maybe_hint) {
      const auto &hint = *maybe_hint;

      if (http2conf.upstream.optimize_write_buffer_size) {
        max_buffer_size_ = std::min(MAX_BUFFER_SIZE, hint.write_buffer_size);
      }

      if (http2conf.upstream.optimize_window_size) {
        auto faddr = handler_->get_upstream_addr();
        if (faddr->alt_mode == UpstreamAltMode::NONE) {
          auto window_size = std::min(http2conf.upstream.connection_window_size,
                                      static_cast<int32_t>(hint.rwin * 2));

          rv = nghttp2_session_set_local_window_size(
            session_, NGHTTP2_FLAG_NONE, 0, window_size);
          if (rv != 0) {
            if (log_enabled(INFO)) {
              Log{INFO, this}
                << "nghttp2_session_set_local_window_size() with window_size="
                << window_size << " failed: " << nghttp2_strerror(rv);
            }
          }
        }
      }
    }
  }

  for (;;) {
    if (wb_.rleft() >= max_buffer_size_) {
      return {};
    }

    const uint8_t *data;
    auto datalen = nghttp2_session_mem_send2(session_, &data);

    if (datalen < 0) {
      Log{ERROR, this} << "nghttp2_session_mem_send2() returned error: "
                       << nghttp2_strerror(static_cast<int>(datalen));
      return std::unexpected{Error::HTTP2};
    }
    if (datalen == 0) {
      break;
    }
    wb_.append(data, as_unsigned(datalen));
  }

  if (nghttp2_session_want_read(session_) == 0 &&
      nghttp2_session_want_write(session_) == 0 && wb_.rleft() == 0) {
    if (log_enabled(INFO)) {
      Log{INFO, this} << "No more read/write for this HTTP2 session";
    }
    return std::unexpected{Error::DONE};
  }

  return {};
}

ClientHandler *Http2Upstream::get_client_handler() const { return handler_; }

std::expected<void, Error>
Http2Upstream::downstream_read(DownstreamConnection *dconn) {
  auto downstream = dconn->get_downstream();

  if (downstream->get_response_state() == DownstreamState::MSG_RESET) {
    // The downstream stream was reset (canceled). In this case,
    // RST_STREAM to the upstream and delete downstream connection
    // here. Deleting downstream will be taken place at
    // on_stream_close_callback.
    rst_stream(downstream, infer_upstream_rst_stream_error_code(
                             downstream->get_response_rst_stream_error_code()));
    downstream->pop_downstream_connection();
    // dconn was deleted
    dconn = nullptr;
  } else if (downstream->get_response_state() ==
             DownstreamState::MSG_BAD_HEADER) {
    if (auto rv = error_reply(downstream, 502); !rv) {
      return rv;
    }
    downstream->pop_downstream_connection();
    // dconn was deleted
    dconn = nullptr;
  } else {
    auto rv = downstream->on_read();
    if (!rv) {
      if (rv.error() == Error::RECV_EOF) {
        if (downstream->get_request_header_sent()) {
          return downstream_eof(dconn);
        }
        return std::unexpected{Error::DCONN_RETRY};
      }
      if (rv.error() == Error::DCONN_CANCELED) {
        downstream->pop_downstream_connection();
        handler_->signal_write();
        return {};
      }
      if (rv.error() != Error::NETWORK) {
        if (log_enabled(INFO)) {
          Log{INFO, dconn} << "HTTP parser failure";
        }
      }
      return downstream_error(dconn, Downstream::EVENT_ERROR);
    }

    if (downstream->can_detach_downstream_connection()) {
      // Keep-alive
      downstream->detach_downstream_connection();
    }
  }

  handler_->signal_write();

  // At this point, downstream may be deleted.

  return {};
}

std::expected<void, Error>
Http2Upstream::downstream_write(DownstreamConnection *dconn) {
  auto rv = dconn->on_write();
  if (!rv) {
    if (rv.error() == Error::NETWORK) {
      return downstream_error(dconn, Downstream::EVENT_ERROR);
    }

    return rv;
  }

  return {};
}

std::expected<void, Error>
Http2Upstream::downstream_eof(DownstreamConnection *dconn) {
  auto downstream = dconn->get_downstream();

  if (log_enabled(INFO)) {
    Log{INFO, dconn} << "EOF. stream_id=" << downstream->get_stream_id();
  }

  // Delete downstream connection. If we don't delete it here, it will
  // be pooled in on_stream_close_callback.
  downstream->pop_downstream_connection();
  // dconn was deleted
  dconn = nullptr;
  // downstream will be deleted in on_stream_close_callback.
  if (downstream->get_response_state() == DownstreamState::HEADER_COMPLETE) {
    // Server may indicate the end of the request by EOF
    if (log_enabled(INFO)) {
      Log{INFO, this} << "Downstream body was ended by EOF";
    }
    downstream->set_response_state(DownstreamState::MSG_COMPLETE);

    // For tunneled connection, MSG_COMPLETE signals
    // downstream_data_read_callback to send RST_STREAM after pending
    // response body is sent. This is needed to ensure that RST_STREAM
    // is sent after all pending data are sent.
    on_downstream_body_complete(downstream);
  } else if (downstream->get_response_state() !=
             DownstreamState::MSG_COMPLETE) {
    // If stream was not closed, then we set MSG_COMPLETE and let
    // on_stream_close_callback delete downstream.
    if (auto rv = error_reply(downstream, 502); !rv) {
      return rv;
    }
  }
  handler_->signal_write();
  // At this point, downstream may be deleted.
  return {};
}

std::expected<void, Error>
Http2Upstream::downstream_error(DownstreamConnection *dconn, int events) {
  auto downstream = dconn->get_downstream();

  if (log_enabled(INFO)) {
    if (events & Downstream::EVENT_ERROR) {
      Log{INFO, dconn} << "Downstream network/general error";
    } else {
      Log{INFO, dconn} << "Timeout";
    }
    if (downstream->get_upgraded()) {
      Log{INFO, dconn} << "Note: this is tunnel connection";
    }
  }

  // Delete downstream connection. If we don't delete it here, it will
  // be pooled in on_stream_close_callback.
  downstream->pop_downstream_connection();
  // dconn was deleted
  dconn = nullptr;

  if (downstream->get_response_state() == DownstreamState::MSG_COMPLETE) {
    // For SSL tunneling, we issue RST_STREAM. For other types of
    // stream, we don't have to do anything since response was
    // complete.
    if (downstream->get_upgraded()) {
      rst_stream(downstream, NGHTTP2_NO_ERROR);
    }
  } else {
    if (downstream->get_response_state() == DownstreamState::HEADER_COMPLETE) {
      if (downstream->get_upgraded()) {
        on_downstream_body_complete(downstream);
      } else {
        rst_stream(downstream, NGHTTP2_INTERNAL_ERROR);
      }
    } else {
      unsigned int status;
      if (events & Downstream::EVENT_TIMEOUT) {
        if (downstream->get_request_header_sent()) {
          status = 504;
        } else {
          status = 408;
        }
      } else {
        status = 502;
      }
      if (auto rv = error_reply(downstream, status); !rv) {
        return rv;
      }
    }
    downstream->set_response_state(DownstreamState::MSG_COMPLETE);
  }
  handler_->signal_write();
  // At this point, downstream may be deleted.
  return {};
}

std::expected<void, Error> Http2Upstream::rst_stream(Downstream *downstream,
                                                     uint32_t error_code) {
  if (log_enabled(INFO)) {
    Log{INFO, this} << "RST_STREAM stream_id=" << downstream->get_stream_id()
                    << " with error_code=" << error_code;
  }
  int rv;
  rv = nghttp2_submit_rst_stream(
    session_, NGHTTP2_FLAG_NONE,
    static_cast<int32_t>(downstream->get_stream_id()), error_code);
  if (rv < NGHTTP2_ERR_FATAL) {
    Log{FATAL, this} << "nghttp2_submit_rst_stream() failed: "
                     << nghttp2_strerror(rv);
    return std::unexpected{Error::HTTP2};
  }
  return {};
}

std::expected<void, Error>
Http2Upstream::terminate_session(uint32_t error_code) {
  int rv;
  rv = nghttp2_session_terminate_session(session_, error_code);
  if (rv != 0) {
    return std::unexpected{Error::HTTP2};
  }
  return {};
}

namespace {
nghttp2_ssize downstream_data_read_callback(nghttp2_session *session,
                                            int32_t stream_id, uint8_t *buf,
                                            size_t length, uint32_t *data_flags,
                                            nghttp2_data_source *source,
                                            void *user_data) {
  int rv;
  auto downstream = static_cast<Downstream *>(source->ptr);
  auto body = downstream->get_response_buf();
  assert(body);
  auto upstream = static_cast<Http2Upstream *>(user_data);

  const auto &resp = downstream->response();

  // [XLIO-ZC] Report readable data for this DATA frame.
  //
  // IMPORTANT: when ZC body is queued, report only the FRONT entry's length,
  // not the sum of all queued refs.  Each ZcBodyRef maps to exactly one
  // send_data_callback invocation.  Returning total_rleft (e.g. 16330+54)
  // would make nghttp2 create a 16384-byte DATA frame header but send_data_callback
  // would only pop the first 16330-byte ref, producing a malformed frame.
  //
  // With this fix, nghttp2 creates one DATA frame per ZcBodyRef boundary:
  //   frame1: header(len=16330) + 16330 ZC bytes  ← matches exactly
  //   frame2: header(len=54)    + 54 ZC bytes     ← matches exactly
  std::size_t avail;
  if (!downstream->zc_body_empty()) {
    // ZC path: one frame = one ZcBodyRef (the front one).
    avail = downstream->get_zc_front_len();
  } else {
    // Copy path: all bytes in response_buf_.
    avail = body->rleft();
  }
  auto total_rleft = body->rleft() + downstream->get_zc_body_rleft(); // for body_empty
  auto nread = std::min(avail, length);

  // [XLIO-ZC] Bookkeeping trace: log every invocation so we can see the frame
  // sizing.  Format: [read_cb] tells nghttp2 to send nread bytes.
  //   avail  = what we report (front ZcBodyRef or body->rleft())
  //   total  = all data available (sum of all ZcBodyRefs + body)
  //   queue  = number of ZcBodyRefs waiting
  //   length = flow-control cap from nghttp2
  if (log_enabled(INFO)) {
    Log{INFO, upstream}
        << "[XLIO-ZC] data_read_cb: stream=" << stream_id
        << " avail=" << avail
        << " total=" << total_rleft
        << " nread=" << nread
        << " zc_queue=" << downstream->get_zc_body_rleft()
        << " body=" << body->rleft()
        << " fc_cap=" << length;
  }

  auto max_buffer_size = upstream->get_max_buffer_size();

  auto buffer = upstream->get_response_buf();

  // With NGHTTP2_DATA_FLAG_NO_COPY the frame payload is NOT copied into wb_
  // here — it only enters wb_ later inside send_data_callback.  Capping nread
  // by (max_buffer_size - 9 - buffer->rleft()) at this point double-counts the
  // buffer occupancy: it measures wb_ BEFORE our frame lands, then under-sizes
  // nread to "fit", yielding avg_length ≈ 8260 even when flow-control windows
  // are 1 GB.  The on_write loop guard (wb_.rleft() >= max_buffer_size → return)
  // already provides pacing for this connection.  We only need to PAUSE here
  // when the buffer is already at or over the hard limit, preventing run-away
  // queuing in extreme backpressure scenarios.
  if (buffer->rleft() >= max_buffer_size) {
    if (log_enabled(INFO)) {
      Log{INFO, upstream} << "Buffer is full.  Skip write DATA";
    }
    return NGHTTP2_ERR_PAUSE;
  }

  // nread is bounded only by body->rleft() and the nghttp2 flow-control cap
  // (length = min(stream_window, connection_window, MAX_FRAME_SIZE) = 16384).
  // This lets send_data_callback see full-frame lengths, enabling remove_zc to
  // splice whole 16 KB Memchunks rather than partial fragments.

  auto body_empty = total_rleft == nread;

  *data_flags |= NGHTTP2_DATA_FLAG_NO_COPY;

  if (body_empty &&
      downstream->get_response_state() == DownstreamState::MSG_COMPLETE) {
    *data_flags |= NGHTTP2_DATA_FLAG_EOF;

    if (!downstream->get_upgraded()) {
      const auto &trailers = resp.fs.trailers();
      if (!trailers.empty()) {
        std::vector<nghttp2_nv> nva;
        nva.reserve(trailers.size());
        http2::copy_headers_to_nva_nocopy(nva, trailers, http2::HDOP_STRIP_ALL);
        if (!nva.empty()) {
          rv =
            nghttp2_submit_trailer(session, stream_id, nva.data(), nva.size());
          if (rv != 0) {
            if (nghttp2_is_fatal(rv)) {
              return NGHTTP2_ERR_CALLBACK_FAILURE;
            }
          } else {
            *data_flags |= NGHTTP2_DATA_FLAG_NO_END_STREAM;
          }
        }
      }
    }
  }

  if (avail == 0 && ((*data_flags) & NGHTTP2_DATA_FLAG_EOF) == 0) {
    if (log_enabled(INFO)) {
      Log{INFO, upstream}
          << "[XLIO-ZC] data_read_cb DEFERRED: stream=" << stream_id
          << " body=" << body->rleft()
          << " zc_queue=" << downstream->get_zc_body_rleft()
          << " resp_state=" << (int)downstream->get_response_state();
    }
    downstream->disable_upstream_wtimer();
    return NGHTTP2_ERR_DEFERRED;
  }

  return as_signed(nread);
}
} // namespace

std::expected<void, Error>
Http2Upstream::send_reply(Downstream *downstream,
                          std::span<const uint8_t> body) {
  int rv;

  nghttp2_data_provider2 data_prd, *data_prd_ptr = nullptr;

  const auto &req = downstream->request();

  if (req.method != HTTP_HEAD && !body.empty()) {
    data_prd.source.ptr = downstream;
    data_prd.read_callback = downstream_data_read_callback;
    data_prd_ptr = &data_prd;

    auto buf = downstream->get_response_buf();

    buf->append(body);
  }

  const auto &resp = downstream->response();
  auto config = get_config();
  auto &httpconf = config->http;

  auto &balloc = downstream->get_block_allocator();

  const auto &headers = resp.fs.headers();
  auto nva = std::vector<nghttp2_nv>();
  // 2 for :status and server
  nva.reserve(2 + headers.size() + httpconf.add_response_headers.size());

  auto response_status = http2::stringify_status(balloc, resp.http_status);

  nva.push_back(http2::make_field(":status"sv, response_status));

  for (auto &kv : headers) {
    if (kv.name.empty() || kv.name[0] == ':') {
      continue;
    }
    switch (kv.token) {
    case http2::HD_CONNECTION:
    case http2::HD_KEEP_ALIVE:
    case http2::HD_PROXY_CONNECTION:
    case http2::HD_TE:
    case http2::HD_TRANSFER_ENCODING:
    case http2::HD_UPGRADE:
      continue;
    }
    nva.push_back(
      http2::make_field(kv.name, kv.value, http2::no_index(kv.no_index)));
  }

  if (!resp.fs.header(http2::HD_SERVER)) {
    nva.push_back(http2::make_field("server"sv, config->http.server_name));
  }

  for (auto &p : httpconf.add_response_headers) {
    nva.push_back(http2::make_field(p.name, p.value));
  }

  rv = nghttp2_submit_response2(
    session_, static_cast<int32_t>(downstream->get_stream_id()), nva.data(),
    nva.size(), data_prd_ptr);
  if (nghttp2_is_fatal(rv)) {
    Log{FATAL, this} << "nghttp2_submit_response2() failed: "
                     << nghttp2_strerror(rv);
    return std::unexpected{Error::HTTP2};
  }

  downstream->set_response_state(DownstreamState::MSG_COMPLETE);

  if (data_prd_ptr) {
    downstream->reset_upstream_wtimer();
  }

  return {};
}

std::expected<void, Error>
Http2Upstream::error_reply(Downstream *downstream, unsigned int status_code) {
  int rv;
  auto &resp = downstream->response();

  auto &balloc = downstream->get_block_allocator();

  auto html = http::create_error_html(balloc, status_code);
  resp.http_status = status_code;

  nghttp2_data_provider2 data_prd, *data_prd_ptr = nullptr;

  const auto &req = downstream->request();

  if (req.method != HTTP_HEAD) {
    data_prd.source.ptr = downstream;
    data_prd.read_callback = downstream_data_read_callback;
    data_prd_ptr = &data_prd;

    auto body = downstream->get_response_buf();

    body->append(html);
  }

  downstream->set_response_state(DownstreamState::MSG_COMPLETE);

  auto lgconf = log_config();
  lgconf->update_tstamp(std::chrono::system_clock::now());

  auto response_status = http2::stringify_status(balloc, status_code);
  auto content_length = util::make_string_ref_uint(balloc, html.size());
  auto date = make_string_ref(balloc, lgconf->tstamp->time_http);

  auto nva = std::to_array(
    {http2::make_field(":status"sv, response_status),
     http2::make_field("content-type"sv, "text/html; charset=UTF-8"sv),
     http2::make_field("server"sv, get_config()->http.server_name),
     http2::make_field("content-length"sv, content_length),
     http2::make_field("date"sv, date)});

  rv = nghttp2_submit_response2(
    session_, static_cast<int32_t>(downstream->get_stream_id()), nva.data(),
    nva.size(), data_prd_ptr);
  if (rv < NGHTTP2_ERR_FATAL) {
    Log{FATAL, this} << "nghttp2_submit_response2() failed: "
                     << nghttp2_strerror(rv);
    return std::unexpected{Error::HTTP2};
  }

  downstream->reset_upstream_wtimer();

  return {};
}

void Http2Upstream::add_pending_downstream(
  std::unique_ptr<Downstream> downstream) {
  downstream_queue_.add_pending(std::move(downstream));
}

void Http2Upstream::remove_downstream(Downstream *downstream) {
  if (downstream->accesslog_ready()) {
    handler_->write_accesslog(downstream);
  }

  nghttp2_session_set_stream_user_data(
    session_, static_cast<int32_t>(downstream->get_stream_id()), nullptr);

  auto next_downstream = downstream_queue_.remove_and_get_blocked(downstream);

  if (next_downstream) {
    initiate_downstream(next_downstream);
  }

  if (downstream_queue_.get_downstreams() == nullptr) {
    // There is no downstream at the moment.  Start idle timer now.
    auto config = get_config();
    auto &upstreamconf = config->conn.upstream;

    handler_->reset_upstream_read_timeout(upstreamconf.timeout.http2_idle);
  }
}

// WARNING: Never call directly or indirectly nghttp2_session_send or
// nghttp2_session_recv. These calls may delete downstream.
std::expected<void, Error>
Http2Upstream::on_downstream_header_complete(Downstream *downstream) {
  int rv;

  const auto &req = downstream->request();
  auto &resp = downstream->response();

  auto &balloc = downstream->get_block_allocator();

  if (log_enabled(INFO)) {
    if (downstream->get_non_final_response()) {
      Log{INFO, downstream} << "HTTP non-final response header";
    } else {
      Log{INFO, downstream} << "HTTP response header completed";
    }
  }

  auto config = get_config();
  auto &httpconf = config->http;

  if (!config->http2_proxy && !httpconf.no_location_rewrite) {
    downstream->rewrite_location_response_header(req.scheme);
  }

#ifdef HAVE_MRUBY
  if (!downstream->get_non_final_response()) {
    auto dconn = downstream->get_downstream_connection();
    const auto &group = dconn->get_downstream_addr_group();
    if (group) {
      const auto &dmruby_ctx = group->shared_addr->mruby_ctx;

      if (auto rv = dmruby_ctx->run_on_response_proc(downstream); !rv) {
        if (auto rv = error_reply(downstream, 500); !rv) {
          return rv;
        }
        // Returning an error will signal deletion of dconn.
        return rv;
      }

      if (downstream->get_response_state() == DownstreamState::MSG_COMPLETE) {
        return std::unexpected{Error::INTERNAL};
      }
    }

    auto worker = handler_->get_worker();
    auto mruby_ctx = worker->get_mruby_context();

    if (auto rv = mruby_ctx->run_on_response_proc(downstream); !rv) {
      if (auto rv = error_reply(downstream, 500); !rv) {
        return rv;
      }
      // Returning an error will signal deletion of dconn.
      return rv;
    }

    if (downstream->get_response_state() == DownstreamState::MSG_COMPLETE) {
      return std::unexpected{Error::INTERNAL};
    }
  }
#endif // defined(HAVE_MRUBY)

  auto &http2conf = config->http2;

  // We need some conditions that must be fulfilled to initiate server
  // push.
  //
  // * Server push is disabled for http2 proxy or client proxy, since
  //   incoming headers are mixed origins.  We don't know how to
  //   reliably determine the authority yet.
  //
  // * We need non-final response or 200 response code for associated
  //   resource.  This is too restrictive, we will review this later.
  //
  // * We requires GET or POST for associated resource.  Probably we
  //   don't want to push for HEAD request.  Not sure other methods
  //   are also eligible for push.
  if (!http2conf.no_server_push &&
      nghttp2_session_get_remote_settings(session_,
                                          NGHTTP2_SETTINGS_ENABLE_PUSH) == 1 &&
      !config->http2_proxy && (downstream->get_stream_id() % 2) &&
      resp.fs.header(http2::HD_LINK) &&
      (downstream->get_non_final_response() || resp.http_status == 200) &&
      (req.method == HTTP_GET || req.method == HTTP_POST)) {
    if (!prepare_push_promise(downstream)) {
      // Continue to send response even if push was failed.
    }
  }

  auto nva = std::vector<nghttp2_nv>();
  // 6 means :status and possible server, via, x-http2-push, alt-svc,
  // and set-cookie (for affinity cookie) header field.
  nva.reserve(resp.fs.headers().size() + 6 +
              httpconf.add_response_headers.size());

  if (downstream->get_non_final_response()) {
    auto response_status = http2::stringify_status(balloc, resp.http_status);

    nva.push_back(http2::make_field(":status"sv, response_status));

    http2::copy_headers_to_nva_nocopy(nva, resp.fs.headers(),
                                      http2::HDOP_STRIP_ALL);

    if (log_enabled(INFO)) {
      log_response_headers(downstream, nva);
    }

    rv =
      nghttp2_submit_headers(session_, NGHTTP2_FLAG_NONE,
                             static_cast<int32_t>(downstream->get_stream_id()),
                             nullptr, nva.data(), nva.size(), nullptr);

    resp.fs.clear_headers();

    if (rv != 0) {
      Log{FATAL, this} << "nghttp2_submit_headers() failed";
      return std::unexpected{Error::HTTP2};
    }

    return {};
  }

  auto striphd_flags =
    static_cast<uint32_t>(http2::HDOP_STRIP_ALL & ~http2::HDOP_STRIP_VIA);
  std::string_view response_status;

  if (req.connect_proto == ConnectProto::WEBSOCKET && resp.http_status == 101) {
    response_status = http2::stringify_status(balloc, 200);
    striphd_flags |= http2::HDOP_STRIP_SEC_WEBSOCKET_ACCEPT;
  } else {
    response_status = http2::stringify_status(balloc, resp.http_status);
  }

  nva.push_back(http2::make_field(":status"sv, response_status));

  http2::copy_headers_to_nva_nocopy(nva, resp.fs.headers(), striphd_flags);

  if (!config->http2_proxy && !httpconf.no_server_rewrite) {
    nva.push_back(http2::make_field("server"sv, httpconf.server_name));
  } else {
    auto server = resp.fs.header(http2::HD_SERVER);
    if (server) {
      nva.push_back(http2::make_field("server"sv, (*server).value));
    }
  }

  if (!req.regular_connect_method() || !downstream->get_upgraded()) {
    auto affinity_cookie = downstream->get_affinity_cookie_to_send();
    if (affinity_cookie) {
      auto dconn = downstream->get_downstream_connection();
      assert(dconn);
      auto &group = dconn->get_downstream_addr_group();
      auto &shared_addr = group->shared_addr;
      auto &cookieconf = shared_addr->affinity.cookie;
      auto secure =
        http::require_cookie_secure_attribute(cookieconf.secure, req.scheme);
      auto cookie_str = http::create_affinity_cookie(
        balloc, cookieconf.name, affinity_cookie, cookieconf.path, secure);
      nva.push_back(http2::make_field("set-cookie"sv, cookie_str));
    }
  }

  if (!resp.fs.header(http2::HD_ALT_SVC)) {
    // We won't change or alter alt-svc from backend for now
    if (!httpconf.http2_altsvc_header_value.empty()) {
      nva.push_back(
        http2::make_field("alt-svc"sv, httpconf.http2_altsvc_header_value));
    }
  }

  auto via = resp.fs.header(http2::HD_VIA);
  if (httpconf.no_via) {
    if (via) {
      nva.push_back(http2::make_field("via"sv, (*via).value));
    }
  } else {
    // we don't create more than 16 bytes in
    // http::create_via_header_value.
    size_t len = 16;
    if (via) {
      len += via->value.size() + 2;
    }

    auto iov = make_byte_ref(balloc, len + 1);
    auto p = std::ranges::begin(iov);
    if (via) {
      p = std::ranges::copy(via->value, p).out;
      p = std::ranges::copy(", "sv, p).out;
    }
    p = http::create_via_header_value(p, resp.http_major, resp.http_minor);
    *p = '\0';

    nva.push_back(
      http2::make_field("via"sv, as_string_view(std::ranges::begin(iov), p)));
  }

  for (auto &p : httpconf.add_response_headers) {
    nva.push_back(http2::make_field(p.name, p.value));
  }

  if (downstream->get_stream_id() % 2 == 0) {
    // This header field is basically for human on client side to
    // figure out that the resource is pushed.
    nva.push_back(http2::make_field("x-http2-push"sv, "1"sv));
  }

  if (log_enabled(INFO)) {
    log_response_headers(downstream, nva);
  }

  if (http2conf.upstream.debug.dump.response_header) {
    http2::dump_nv(http2conf.upstream.debug.dump.response_header, nva.data(),
                   nva.size());
  }

  auto priority = resp.fs.header(http2::HD_PRIORITY);
  if (priority) {
    nghttp2_extpri extpri;

    if (nghttp2_session_get_extpri_stream_priority(
          session_, &extpri,
          static_cast<int32_t>(downstream->get_stream_id())) == 0 &&
        nghttp2_extpri_parse_priority(
          &extpri, reinterpret_cast<const uint8_t *>(priority->value.data()),
          priority->value.size()) == 0) {
      rv = nghttp2_session_change_extpri_stream_priority(
        session_, static_cast<int32_t>(downstream->get_stream_id()), &extpri,
        /* ignore_client_signal = */ 1);
      if (rv != 0) {
        Log{ERROR, this} << "nghttp2_session_change_extpri_stream_priority: "
                         << nghttp2_strerror(rv);
      }
    }
  }

  nghttp2_data_provider2 data_prd;
  data_prd.source.ptr = downstream;
  data_prd.read_callback = downstream_data_read_callback;

  nghttp2_data_provider2 *data_prdptr;

  if (downstream->expect_response_body() ||
      downstream->expect_response_trailer()) {
    data_prdptr = &data_prd;
  } else {
    data_prdptr = nullptr;
  }

  rv = nghttp2_submit_response2(
    session_, static_cast<int32_t>(downstream->get_stream_id()), nva.data(),
    nva.size(), data_prdptr);
  if (rv != 0) {
    Log{FATAL, this} << "nghttp2_submit_response2() failed";
    return std::unexpected{Error::HTTP2};
  }

  if (data_prdptr) {
    downstream->reset_upstream_wtimer();
  }

  return {};
}

// WARNING: Never call directly or indirectly nghttp2_session_send or
// nghttp2_session_recv. These calls may delete downstream.
std::expected<void, Error>
Http2Upstream::on_downstream_body(Downstream *downstream,
                                  std::span<const uint8_t> data, bool flush) {
  auto body = downstream->get_response_buf();

  // [XLIO-ZC] Hardware zero-copy path: if the data span is within the current
  // pending ZC-RX DMA buffer, claim it and enqueue a ZcBodyRef instead of
  // copying bytes.  send_data_callback() will send it via sendv_zc().
  {
    auto *dconn = dynamic_cast<Http2DownstreamConnection *>(
        downstream->get_downstream_connection());
    if (dconn) {
      if (auto *http2session = dconn->get_http2session()) {
        // Only claim the ZC buffer if the frontend can actually relay it
        // (see zc_relay_eligible()) — otherwise fall through to the normal
        // copy path below exactly as if try_claim_zc_buf() had failed. This
        // is what send_data_callback()'s eligibility check depends on: it
        // must never see a queued chunk it can't actually send.
        if (auto *buf = zc_relay_eligible(this, http2session)
                            ? http2session->try_claim_zc_buf(data.data())
                            : nullptr) {
          downstream->push_zc_body(data.data(), data.size(), buf);
          {
            auto &zs = zcopy_stats();
            zs.zc_queued_bytes.fetch_add(data.size(),
                                         std::memory_order_relaxed);
            zs.zc_queued_count.fetch_add(1, std::memory_order_relaxed);
          }
          PROBNIK_LOG(PROBNIK_DEBUG, "zc-trace",
             "ZC body queued: len=%ld stream=%ld buf=%p total_zc_rleft=%ld",
              data.size(), downstream->get_stream_id(), static_cast<void *>(buf),
              downstream->get_zc_body_rleft());
          // Skip the copy path and fall through to resume / timer below.
          goto body_queued;
        } else if (!data.empty()) {
          // ZC claim failed: no XLIO ZC socket on this connection, or data
          // pointer is outside the current segment range.
          zcopy_stats().copy_queued_bytes.fetch_add(data.size(),
                                                    std::memory_order_relaxed);

          PROBNIK_LOG(PROBNIK_DEBUG, "zc-trace",
             "COPY body appended: len=%ld stream=%ld body_rleft_before=%ld",
              data.size(), downstream->get_stream_id(), body->rleft());
        }
      }
    }
  }

#ifdef SHRPX_ZC_BODY
  /*
   * [SHRPX_ZC_BODY] Software zero-copy fast path: if the data span points
   * into the Http2Session's current pending_rx_chunk_, steal that chunk
   * directly into response_buf_, eliminating Copy #5.
   */
  {
    bool stolen = false;
    if (auto *dconn =
          dynamic_cast<Http2DownstreamConnection *>(
            downstream->get_downstream_connection())) {
      if (auto *http2session = dconn->get_http2session()) {
        if (auto *chunk = http2session->try_claim_rx_chunk(data.data())) {
          body->steal_chunk(chunk,
                            const_cast<uint8_t *>(data.data()),
                            const_cast<uint8_t *>(data.data()) + data.size());
          stolen = true;
          zcopy_stats().body_steal_hit.fetch_add(1, std::memory_order_relaxed);
        }
      }
    }
    if (!stolen) {
      body->append(data);
      zcopy_stats().body_steal_miss.fetch_add(1, std::memory_order_relaxed);
    }
  }
#else
  body->append(data);
#endif

body_queued:

  // Always resume the nghttp2 DATA provider and ensure the write timer is
  // running.  If the stream was deferred (downstream_data_read_callback
  // returned NGHTTP2_ERR_DEFERRED because both queues were momentarily empty
  // between recv_zc batches), this wakes it up so the freshly-queued bytes
  // are sent.  nghttp2_session_resume_data is a no-op when not deferred.
  if (!data.empty() || flush) {
    nghttp2_session_resume_data(
      session_, static_cast<int32_t>(downstream->get_stream_id()));
    downstream->ensure_upstream_wtimer();
  }

  return {};
}

// WARNING: Never call directly or indirectly nghttp2_session_send or
// nghttp2_session_recv. These calls may delete downstream.
std::expected<void, Error>
Http2Upstream::on_downstream_body_complete(Downstream *downstream) {
  if (log_enabled(INFO)) {
    Log{INFO, downstream} << "HTTP response completed";
  }

  auto &resp = downstream->response();

  if (!downstream->validate_response_recv_body_length()) {
    rst_stream(downstream, NGHTTP2_PROTOCOL_ERROR);
    resp.connection_close = true;
    return {};
  }

  nghttp2_session_resume_data(
    session_, static_cast<int32_t>(downstream->get_stream_id()));
  downstream->ensure_upstream_wtimer();

  return {};
}

bool Http2Upstream::get_flow_control() const { return flow_control_; }

void Http2Upstream::pause_read(IOCtrlReason reason) {}

std::expected<void, Error> Http2Upstream::resume_read(IOCtrlReason reason,
                                                      Downstream *downstream,
                                                      size_t consumed) {
  if (get_flow_control()) {
    if (auto rv =
          consume(static_cast<int32_t>(downstream->get_stream_id()), consumed);
        !rv) {
      return rv;
    }

    auto &req = downstream->request();

    req.consume(consumed);
  }

  handler_->signal_write();
  return {};
}

std::expected<void, Error>
Http2Upstream::on_downstream_abort_request(Downstream *downstream,
                                           unsigned int status_code) {
  if (auto rv = error_reply(downstream, status_code); !rv) {
    return rv;
  }

  handler_->signal_write();
  return {};
}

std::expected<void, Error>
Http2Upstream::on_downstream_abort_request_with_https_redirect(
  Downstream *downstream) {
  if (auto rv = redirect_to_https(downstream); !rv) {
    return rv;
  }

  handler_->signal_write();
  return {};
}

std::expected<void, Error>
Http2Upstream::redirect_to_https(Downstream *downstream) {
  auto &req = downstream->request();
  if (req.regular_connect_method() || req.scheme != "http"sv) {
    return error_reply(downstream, 400);
  }

  auto maybe_authority = util::extract_host(req.authority);
  if (!maybe_authority) {
    return error_reply(downstream, 400);
  }

  auto &balloc = downstream->get_block_allocator();
  auto config = get_config();
  auto &httpconf = config->http;

  std::string_view loc;
  if (httpconf.redirect_https_port == "443"sv) {
    loc = concat_string_ref(balloc, "https://"sv, *maybe_authority, req.path);
  } else {
    loc = concat_string_ref(balloc, "https://"sv, *maybe_authority, ":"sv,
                            httpconf.redirect_https_port, req.path);
  }

  auto &resp = downstream->response();
  resp.http_status = 308;
  resp.fs.add_header_token("location"sv, loc, false, http2::HD_LOCATION);

  return send_reply(downstream, {});
}

std::expected<void, Error> Http2Upstream::consume(int32_t stream_id,
                                                  size_t len) {
  int rv;

  auto faddr = handler_->get_upstream_addr();

  if (faddr->alt_mode != UpstreamAltMode::NONE) {
    return {};
  }

  rv = nghttp2_session_consume(session_, stream_id, len);

  if (rv != 0) {
    Log{WARN, this} << "nghttp2_session_consume() returned error: "
                    << nghttp2_strerror(rv);
    return std::unexpected{Error::HTTP2};
  }

  return {};
}

namespace {
std::string format_nva(std::span<const nghttp2_nv> nva) {
  std::string s;

  for (auto &nv : nva) {
    s += tty_http_hd();
    s += as_string_view(nv.name, nv.namelen);
    s += tty_rst();
    s += ": ";
    s += as_string_view(nv.value, nv.valuelen);
    s += '\n';
  }

  return s;
}
} // namespace

void Http2Upstream::log_response_headers(
  Downstream *downstream, const std::vector<nghttp2_nv> &nva) const {
  Log{INFO, this} << "HTTP response headers. stream_id="
                  << downstream->get_stream_id() << "\n"
                  << format_nva(nva);
}

std::expected<void, Error> Http2Upstream::on_timeout(Downstream *downstream) {
  if (log_enabled(INFO)) {
    Log{INFO, this} << "Stream timeout stream_id="
                    << downstream->get_stream_id();
  }

  rst_stream(downstream, NGHTTP2_INTERNAL_ERROR);
  handler_->signal_write();

  return {};
}

void Http2Upstream::on_handler_delete() {
  for (auto d = downstream_queue_.get_downstreams(); d; d = d->dlnext) {
    if (d->get_dispatch_state() == DispatchState::ACTIVE &&
        d->accesslog_ready()) {
      handler_->write_accesslog(d);
    }
  }
}

std::expected<void, Error>
Http2Upstream::on_downstream_reset(Downstream *downstream, bool no_retry) {
  if (downstream->get_dispatch_state() != DispatchState::ACTIVE) {
    // This is error condition when we failed push_request_headers()
    // in initiate_downstream().  Otherwise, we have
    // DispatchState::ACTIVE state, or we did not set
    // DownstreamConnection.
    downstream->pop_downstream_connection();
    handler_->signal_write();

    return {};
  }

  if (!downstream->request_submission_ready()) {
    if (log_enabled(INFO)) {
      Log{INFO, downstream}
          << "[XLIO-ZC-DIAG] on_downstream_reset: response_state="
          << static_cast<int>(downstream->get_response_state())
          << " zc_body_rleft=" << downstream->get_zc_body_rleft()
          << " body_rleft=" << downstream->get_response_buf()->rleft();
    }
    if (downstream->get_response_state() == DownstreamState::MSG_COMPLETE) {
      // We have got all response body already.  Send it off.
      downstream->pop_downstream_connection();
      return {};
    }
    // pushed stream is handled here
    rst_stream(downstream, NGHTTP2_INTERNAL_ERROR);
    downstream->pop_downstream_connection();

    handler_->signal_write();

    return {};
  }

  downstream->pop_downstream_connection();

  downstream->add_retry();

  std::unique_ptr<DownstreamConnection> dconn;

  auto err = Error::INTERNAL;

  if (no_retry || downstream->no_more_retry()) {
    goto fail;
  }

  // downstream connection is clean; we can retry with new
  // downstream connection.

  for (;;) {
    auto maybe_dconn = handler_->get_downstream_connection(downstream);
    if (!maybe_dconn) {
      err = maybe_dconn.error();
      goto fail;
    }

    if (downstream->attach_downstream_connection(std::move(*maybe_dconn))) {
      break;
    }
  }

  if (auto rv = downstream->push_request_headers(); !rv) {
    err = rv.error();
    goto fail;
  }

  return {};

fail:
  if (!(err == Error::TLS_REQUIRED
          ? on_downstream_abort_request_with_https_redirect(downstream)
          : on_downstream_abort_request(downstream, 502))) {
    rst_stream(downstream, NGHTTP2_INTERNAL_ERROR);
  }
  downstream->pop_downstream_connection();

  handler_->signal_write();

  return {};
}

std::expected<void, Error>
Http2Upstream::prepare_push_promise(Downstream *downstream) {
  const auto &req = downstream->request();
  auto &resp = downstream->response();

  auto base = http2::get_pure_path_component(req.path);
  if (base.empty()) {
    return {};
  }

  auto &balloc = downstream->get_block_allocator();

  for (auto &kv : resp.fs.headers()) {
    if (kv.token != http2::HD_LINK) {
      continue;
    }
    for (auto &link : http2::parse_link_header(kv.value)) {
      auto maybe_push_comp =
        http2::construct_push_component(balloc, base, link.uri);
      if (!maybe_push_comp) {
        continue;
      }

      auto push_comp = *maybe_push_comp;

      if (push_comp.scheme.empty()) {
        push_comp.scheme = req.scheme;
      }

      if (push_comp.authority.empty()) {
        push_comp.authority = req.authority;
      }

      if (resp.is_resource_pushed(push_comp.scheme, push_comp.authority,
                                  push_comp.path)) {
        continue;
      }

      if (auto rv = submit_push_promise(push_comp.scheme, push_comp.authority,
                                        push_comp.path, downstream);
          !rv) {
        return rv;
      }

      resp.resource_pushed(push_comp.scheme, push_comp.authority,
                           push_comp.path);
    }
  }
  return {};
}

std::expected<void, Error> Http2Upstream::submit_push_promise(
  std::string_view scheme, std::string_view authority, std::string_view path,
  Downstream *downstream) {
  const auto &req = downstream->request();

  std::vector<nghttp2_nv> nva;
  // 4 for :method, :scheme, :path and :authority
  nva.reserve(4 + req.fs.headers().size());

  // just use "GET" for now
  nva.push_back(http2::make_field(":method"sv, "GET"sv));
  nva.push_back(http2::make_field(":scheme"sv, scheme));
  nva.push_back(http2::make_field(":path"sv, path));
  nva.push_back(http2::make_field(":authority"sv, authority));

  for (auto &kv : req.fs.headers()) {
    switch (kv.token) {
    // TODO generate referer
    case http2::HD__AUTHORITY:
    case http2::HD__SCHEME:
    case http2::HD__METHOD:
    case http2::HD__PATH:
      continue;
    case http2::HD_ACCEPT_ENCODING:
    case http2::HD_ACCEPT_LANGUAGE:
    case http2::HD_CACHE_CONTROL:
    case http2::HD_HOST:
    case http2::HD_USER_AGENT:
      nva.push_back(
        http2::make_field(kv.name, kv.value, http2::no_index(kv.no_index)));
      break;
    }
  }

  auto promised_stream_id = nghttp2_submit_push_promise(
    session_, NGHTTP2_FLAG_NONE,
    static_cast<int32_t>(downstream->get_stream_id()), nva.data(), nva.size(),
    nullptr);

  if (promised_stream_id < 0) {
    if (log_enabled(INFO)) {
      Log{INFO, this} << "nghttp2_submit_push_promise() failed: "
                      << nghttp2_strerror(promised_stream_id);
    }
    if (nghttp2_is_fatal(promised_stream_id)) {
      return std::unexpected{Error::HTTP2};
    }
    return {};
  }

  if (log_enabled(INFO)) {
    Log{INFO, this} << "HTTP push request headers. promised_stream_id="
                    << promised_stream_id << "\n"
                    << format_nva(nva);
  }

  return {};
}

bool Http2Upstream::push_enabled() const {
  auto config = get_config();
  return !(config->http2.no_server_push ||
           nghttp2_session_get_remote_settings(
             session_, NGHTTP2_SETTINGS_ENABLE_PUSH) == 0 ||
           config->http2_proxy);
}

std::expected<void, Error> Http2Upstream::initiate_push(Downstream *downstream,
                                                        std::string_view uri) {
  if (uri.empty() || !push_enabled() ||
      (downstream->get_stream_id() % 2) == 0) {
    return {};
  }

  const auto &req = downstream->request();

  auto base = http2::get_pure_path_component(req.path);
  if (base.empty()) {
    return std::unexpected{Error::INTERNAL};
  }

  auto &balloc = downstream->get_block_allocator();

  auto maybe_push_comp = http2::construct_push_component(balloc, base, uri);
  if (!maybe_push_comp) {
    return std::unexpected{maybe_push_comp.error()};
  }

  auto push_comp = *maybe_push_comp;

  if (push_comp.scheme.empty()) {
    push_comp.scheme = req.scheme;
  }

  if (push_comp.authority.empty()) {
    push_comp.authority = req.authority;
  }

  auto &resp = downstream->response();

  if (resp.is_resource_pushed(push_comp.scheme, push_comp.authority,
                              push_comp.path)) {
    return {};
  }

  if (auto rv = submit_push_promise(push_comp.scheme, push_comp.authority,
                                    push_comp.path, downstream);
      !rv) {
    return rv;
  }

  resp.resource_pushed(push_comp.scheme, push_comp.authority, push_comp.path);

  return {};
}

std::span<struct iovec>
Http2Upstream::response_riovec(std::span<struct iovec> iov) const {
  return wb_.riovec(iov);
}

std::span<const uint8_t> Http2Upstream::response_peek() const {
  return wb_.peek();
}

void Http2Upstream::response_drain(size_t n) { wb_.drain(n); }

bool Http2Upstream::response_empty() const { return wb_.rleft() == 0; }

bool Http2Upstream::flush_response_buf() {
  auto conn = handler_->get_connection();
  while (wb_.rleft() > 0) {
    auto data = wb_.peek();
    if (data.empty()) break;
    auto maybe_nwrite = conn->write_tls(data);
    if (!maybe_nwrite) {
      if (log_enabled(INFO)) {
        Log{INFO, this} << "[XLIO-ZC] flush_response_buf: write_tls error";
      }
      return false;
    }
    auto nwrite = *maybe_nwrite;
    if (nwrite == 0) {
      if (log_enabled(INFO)) {
        Log{INFO, this} << "[XLIO-ZC] flush_response_buf: EAGAIN ("
                        << wb_.rleft() << " bytes remain)";
      }
      return false;
    }
    wb_.drain(nwrite);
  }
  return true;
}

DefaultMemchunks *Http2Upstream::get_response_buf() { return &wb_; }

Downstream *
Http2Upstream::on_downstream_push_promise(Downstream *downstream,
                                          int32_t promised_stream_id) {
  // promised_stream_id is for backend HTTP/2 session, not for
  // frontend.
  auto promised_downstream =
    std::make_unique<Downstream>(this, handler_->get_mcpool(), 0);
  auto &promised_req = promised_downstream->request();

  promised_downstream->set_downstream_stream_id(promised_stream_id);
  // Set associated stream in frontend
  promised_downstream->set_assoc_stream_id(downstream->get_stream_id());

  promised_downstream->disable_upstream_rtimer();

  promised_req.http_major = 2;
  promised_req.http_minor = 0;

  promised_req.fs.content_length = 0;
  promised_req.http2_expect_body = false;

  auto ptr = promised_downstream.get();
  add_pending_downstream(std::move(promised_downstream));
  downstream_queue_.mark_active(ptr);

  return ptr;
}

std::expected<void, Error> Http2Upstream::on_downstream_push_promise_complete(
  Downstream *downstream, Downstream *promised_downstream) {
  std::vector<nghttp2_nv> nva;

  const auto &promised_req = promised_downstream->request();
  const auto &headers = promised_req.fs.headers();

  nva.reserve(headers.size());

  for (auto &kv : headers) {
    nva.push_back(
      http2::make_field_nv(kv.name, kv.value, http2::no_index(kv.no_index)));
  }

  auto promised_stream_id = nghttp2_submit_push_promise(
    session_, NGHTTP2_FLAG_NONE,
    static_cast<int32_t>(downstream->get_stream_id()), nva.data(), nva.size(),
    promised_downstream);
  if (promised_stream_id < 0) {
    return std::unexpected{Error::HTTP2};
  }

  promised_downstream->set_stream_id(promised_stream_id);

  return {};
}

void Http2Upstream::cancel_premature_downstream(
  Downstream *promised_downstream) {
  if (log_enabled(INFO)) {
    Log{INFO, this} << "Remove premature promised stream "
                    << promised_downstream;
  }
  downstream_queue_.remove_and_get_blocked(promised_downstream, false);
}

size_t Http2Upstream::get_max_buffer_size() const { return max_buffer_size_; }

} // namespace shrpx
