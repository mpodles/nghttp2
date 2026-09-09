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
#ifndef SHRPX_HTTP2_SESSION_H
#define SHRPX_HTTP2_SESSION_H

#include "shrpx.h"

#include <unordered_set>
#include <memory>
#include <expected>

#include "ssl_compat.h"

#ifdef NGHTTP2_OPENSSL_IS_WOLFSSL
#  include <wolfssl/options.h>
#  include <wolfssl/openssl/ssl.h>
#else // !defined(NGHTTP2_OPENSSL_IS_WOLFSSL)
#  include <openssl/ssl.h>
#endif // !defined(NGHTTP2_OPENSSL_IS_WOLFSSL)

#include <ev.h>

#include <nghttp2/nghttp2.h>

#include "llhttp.h"

#include "shrpx_connection.h"
#include "buffer.h"
#include "memchunk.h"
#include "template.h"
#include "errors.h"

using namespace nghttp2;

// Forward declaration for XLIO zero-copy receive buffer handle.
struct xlio_buf_opaque;
// Forward declaration for the ZC segment descriptor from shrpx_xlio.h.
struct shrpx_xlio_zc_seg;

namespace shrpx {

class Http2DownstreamConnection;
class Worker;
class Downstream;
struct DownstreamAddrGroup;
struct DownstreamAddr;
struct DNSQuery;

struct StreamData {
  StreamData *dlnext, *dlprev;
  Http2DownstreamConnection *dconn;
};

enum class FreelistZone {
  // Http2Session object is not linked in any freelist.
  NONE,
  // Http2Session object is linked in address scope
  // http2_extra_freelist.
  EXTRA,
  // Http2Session object is about to be deleted, and it does not
  // belong to any linked list.
  GONE
};

enum class Http2SessionState {
  // Disconnected
  DISCONNECTED,
  // Connecting proxy and making CONNECT request
  PROXY_CONNECTING,
  // Tunnel is established with proxy
  PROXY_CONNECTED,
  // Establishing tunnel is failed
  PROXY_FAILED,
  // Connecting to downstream and/or performing SSL/TLS handshake
  CONNECTING,
  // Connected to downstream
  CONNECTED,
  // Connection is started to fail
  CONNECT_FAILING,
  // Resolving host name
  RESOLVING_NAME,
};

enum class ConnectionCheck {
  // Connection checking is not required
  NONE,
  // Connection checking is required
  REQUIRED,
  // Connection checking has been started
  STARTED,
};

class Http2Session {
public:
  Http2Session(struct ev_loop *loop, SSL_CTX *ssl_ctx, Worker *worker,
               const std::shared_ptr<DownstreamAddrGroup> &group,
               DownstreamAddr *addr);
  ~Http2Session();

  // If hard is true, all pending requests are abandoned and
  // associated ClientHandlers will be deleted.
  void disconnect(bool hard = false);
  std::expected<void, Error> initiate_connection();
  std::expected<void, Error> resolve_name();

  void add_downstream_connection(Http2DownstreamConnection *dconn);
  void remove_downstream_connection(Http2DownstreamConnection *dconn);

  void remove_stream_data(StreamData *sd);

  std::expected<void, Error>
  submit_request(Http2DownstreamConnection *dconn, const nghttp2_nv *nva,
                 size_t nvlen, const nghttp2_data_provider2 *data_prd);

  std::expected<void, Error> submit_rst_stream(int32_t stream_id,
                                               uint32_t error_code);

  std::expected<void, Error> terminate_session(uint32_t error_code);

  nghttp2_session *get_session() const;

  // Raw fd of the downstream connection, for callers that need to query
  // XLIO state (e.g. protection-domain checks for cross-socket zero-copy
  // relay) without going through the full read/write path.
  int get_fd() const { return conn_.fd; }

  std::expected<void, Error> resume_data(Http2DownstreamConnection *dconn);

  std::expected<void, Error> connection_made();

  std::expected<void, Error> do_read();
  std::expected<void, Error> do_write();

  std::expected<void, Error> on_read(std::span<const uint8_t> data);
  std::expected<void, Error> on_write();

  std::expected<void, Error> connected();
  std::expected<void, Error> read_clear();
  std::expected<void, Error> write_clear();
  std::expected<void, Error> tls_handshake();
  std::expected<void, Error> read_tls();
  /**
   * Zero-copy read path used when XLIO UTLS-RX is active.
   *
   * Feeds buffers directly from XLIO's DMA memory into nghttp2 without an
   * intermediate SSL_read copy.  Falls back to read_tls() for non-data TLS
   * records (alerts, key-updates) and on any ENOTSUP.
   */
  std::expected<void, Error> read_tls_zcopy();
  std::expected<void, Error> write_tls();
  // This is a special write function which just stop write event
  // watcher.
  std::expected<void, Error> write_void();

  std::expected<void, Error>
  downstream_read_proxy(std::span<const uint8_t> data);
  std::expected<void, Error> downstream_connect_proxy();

  std::expected<void, Error> downstream_read(std::span<const uint8_t> data);
  std::expected<void, Error> downstream_write();

  std::expected<void, Error> noop() { return {}; }
  std::expected<void, Error> read_noop(std::span<const uint8_t> data) {
    return {};
  }
  std::expected<void, Error> write_noop() { return {}; }

  void signal_write();

  struct ev_loop *get_loop() const;

  ev_io *get_wev();

  Http2SessionState get_state() const;
  void set_state(Http2SessionState state);

  void start_settings_timer();
  void stop_settings_timer();

  SSL *get_ssl() const;

  std::expected<void, Error> consume(int32_t stream_id, size_t len);

  // Returns true if request can be issued on downstream connection.
  bool can_push_request(const Downstream *downstream) const;
  // Initiates the connection checking if downstream connection has
  // been established and connection checking is required.
  void start_checking_connection();
  // Resets connection check timer to timeout |t|.  After timeout, we
  // require connection checking.  If connection checking is already
  // enabled, this timeout is for PING ACK timeout.
  void reset_connection_check_timer(ev_tstamp t);
  void reset_connection_check_timer_if_not_checking();
  // Signals that connection is alive.  Internally
  // reset_connection_check_timer() is called.
  void connection_alive();
  // Change connection check state.
  void set_connection_check_state(ConnectionCheck state);
  ConnectionCheck get_connection_check_state() const;

  bool should_hard_fail() const;

  void submit_pending_requests();

  DownstreamAddr *get_addr() const;

  const std::shared_ptr<DownstreamAddrGroup> &get_downstream_addr_group() const;

  std::expected<void, Error>
  handle_downstream_push_promise(Downstream *downstream,
                                 int32_t promised_stream_id);
  std::expected<void, Error>
  handle_downstream_push_promise_complete(Downstream *downstream,
                                          Downstream *promised_downstream);

  // Returns number of downstream connections, including pushed
  // streams.
  size_t get_num_dconns() const;

  // Adds to group scope http2_avail_freelist.
  void add_to_avail_freelist();
  // Adds to address scope http2_extra_freelist.
  void add_to_extra_freelist();

  // Removes this object from any freelist.  If this object is not
  // linked from any freelist, this function does nothing.
  void remove_from_freelist();

  // Removes this object form any freelist, and marks this object as
  // not schedulable.
  void exclude_from_scheduling();

  // Returns true if the maximum concurrency is reached.  In other
  // words, the number of currently participated streams in this
  // session is equal or greater than the max concurrent streams limit
  // advertised by server.  If |extra| is nonzero, it is added to the
  // number of current concurrent streams when comparing against
  // server initiated concurrency limit.
  bool max_concurrency_reached(size_t extra = 0) const;

  DefaultMemchunks *get_request_buf();

  void on_timeout();

  // This is called periodically using ev_prepare watcher, and if
  // group_ is retired (backend has been replaced), send GOAWAY to
  // shutdown the connection.
  void check_retire();

  // Returns address used to connect to backend.  Could be nullptr.
  const Address *get_raddr() const;

  // This is called when SETTINGS frame without ACK flag set is
  // received.
  void on_settings_received(const nghttp2_frame *frame);

  bool get_allow_connect_proto() const;

  // [XLIO-ZC] True if this session is using the zero-copy RX path.
  bool is_xlio_zcopy_rx() const { return xlio_zcopy_rx_; }

  // [XLIO-ZC] Multi-claim zero-copy buffer accessor.
  //
  // Returns the xlio_buf handle if |data| points anywhere inside the current
  // pending ZC segment, allowing multiple HTTP/2 DATA frame bodies within the
  // same TLS record (DMA buffer) to each get their own ZcBodyRef.
  //
  // Ownership rules:
  //   First claim  — consumes the single ref that xlio_recv_zc_fd() granted.
  //   2nd+ claims  — each calls XlioAdapter::buf_add_ref() to acquire an
  //                  additional ref so ZcRxOwner::put() can independently
  //                  free it on TCP ACK without racing with other sends.
  //
  // pending_zc_seg_ is NOT cleared here; it stays alive for the entire
  // on_read() call and is reset to nullptr by read_tls_zcopy() afterward.
  // The caller (on_downstream_body) must NOT call release_zc() for claimed bufs.
  xlio_buf_opaque *try_claim_zc_buf(const uint8_t *data) {
    if (!pending_zc_seg_) return nullptr;
    const auto *base = static_cast<const uint8_t *>(pending_zc_seg_->data);
    if (data < base || data >= base + pending_zc_seg_->len) return nullptr;
    auto *buf = pending_zc_seg_->buf;
    if (zc_claim_count_ > 0) {
      // Additional claim: need an extra lwip pbuf ref so this ZcBodyRef has
      // its own lifetime independent of all other claims on the same buffer.
      XlioAdapter::get().buf_add_ref(buf);
    }
    ++zc_claim_count_;
    return buf;
  }

  // If |data| points into the current pending_rx_chunk_, return and
  // relinquish that chunk (caller takes ownership).  Otherwise return
  // nullptr.  Used by Http2Upstream::on_downstream_body to avoid a copy.
  Memchunk16K *try_claim_rx_chunk(const uint8_t *data) {
    auto *chunk = pending_rx_chunk_;
    if (!chunk) {
      return nullptr;
    }
    auto *base = chunk->buf.data();
    if (data < base || data >= base + Memchunk16K::size) {
      return nullptr;
    }
    pending_rx_chunk_ = nullptr;
    return chunk;
  }

  using ReadBuf = Buffer<8_k>;

  Http2Session *dlnext, *dlprev;

private:
  Connection conn_;
  DefaultMemchunks wb_;
  ev_timer settings_timer_;
  // This timer has 2 purpose: when it first timeout, set
  // connection_check_state_ = ConnectionCheck::REQUIRED.  After
  // connection check has started, this timer is started again and
  // traps PING ACK timeout.
  ev_timer connchk_timer_;
  // timer to initiate connection.  usually, this fires immediately.
  ev_timer initiate_connection_timer_;
  ev_prepare prep_;
  DList<Http2DownstreamConnection> dconns_;
  DList<StreamData> streams_;
  std::function<std::expected<void, Error>(Http2Session &)> read_, write_;
  std::function<std::expected<void, Error>(Http2Session &,
                                           std::span<const uint8_t>)>
    on_read_;
  std::function<std::expected<void, Error>(Http2Session &)> on_write_;
  // Used to parse the response from HTTP proxy
  std::unique_ptr<llhttp_t> proxy_htp_;
  Worker *worker_;
  // NULL if no TLS is configured
  SSL_CTX *ssl_ctx_;
  std::shared_ptr<DownstreamAddrGroup> group_;
  // Address of remote endpoint
  DownstreamAddr *addr_;
  nghttp2_session *session_;
  // Actual remote address used to contact backend.  This is initially
  // nullptr, and may point to either &addr_->addr,
  // resolved_addr_.get(), or HTTP proxy's address structure.
  const Address *raddr_;
  // Resolved IP address if dns parameter is used
  std::unique_ptr<Address> resolved_addr_;
  std::unique_ptr<DNSQuery> dns_query_;
  Http2SessionState state_;
  ConnectionCheck connection_check_state_;
  FreelistZone freelist_zone_;
  // true if SETTINGS without ACK is received from peer.
  bool settings_recved_;
  // true if peer enables RFC 8441 CONNECT protocol.
  bool allow_connect_proto_;
  /*
   * True when the backend TLS connection completed with UTLS-RX hardware
   * offload AND the XLIO zero-copy receive API is available at runtime.
   * When set, read_ is pointed at read_tls_zcopy() instead of read_tls().
   */
  bool xlio_zcopy_rx_;
  // Set after the first INFO log in read_tls_zcopy() to avoid log spam.
  bool xlio_zc_first_seg_logged_;

  /*
   * Pool chunk used as the SSL_read destination in the current read_tls()
   * iteration.  A pointer into this chunk is valid as long as we remain
   * inside the nghttp2_session_mem_recv2() call that consumes it.
   *
   * on_downstream_body() checks whether the data span it receives points
   * into this chunk and, if so, steals it directly into response_buf_
   * (zero-copy).  After nghttp2_session_mem_recv2() returns the chunk is
   * either already owned by a response_buf_ or recycled back to the pool.
   */
  Memchunk16K *pending_rx_chunk_;

  /*
   * [XLIO-ZC] Non-null during a read_tls_zcopy() segment processing cycle.
   * Points to the current xlio ZC segment (DMA buffer + length).
   * try_claim_zc_buf() records each DATA-body claim in zc_claim_count_.
   * After on_read() returns:
   *   zc_claim_count_ == 0  → no DATA in this segment; read_tls_zcopy calls
   *                           release_zc() to free the recv_zc ref.
   *   zc_claim_count_ > 0   → each ZcBodyRef holds its own ref (1st claim
   *                           uses the recv_zc ref, subsequent ones add a ref
   *                           via XlioAdapter::buf_add_ref).  release_zc NOT
   *                           called; every ZcRxOwner::put() fires on ACK.
   */
  const shrpx_xlio_zc_seg *pending_zc_seg_;
  int                       zc_claim_count_; // number of ZcBodyRefs for current seg
};

nghttp2_session_callbacks *create_http2_downstream_callbacks();

} // namespace shrpx

#endif // !defined(SHRPX_HTTP2_SESSION_H)
