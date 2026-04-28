/*
 * shrpx_zcopy_stats.h — lightweight zero-copy telemetry for nghttpx
 *
 * All counters are relaxed atomics: a single locked INC instruction on x86,
 * no barriers, no cache-line bouncing between threads.  Hot-path overhead is
 * ~1-3 CPU cycles per increment.
 *
 * Reading the stats:
 *   kill -USR1 $(pidof nghttpx)    # prints alongside log-reopen (see shrpx.cc)
 *   kill -HUP  $(pidof nghttpx)    # also prints on config reload
 *
 * Counter semantics:
 *   body_steal_hit       Copy #5 eliminated: response body chunk moved by
 *                        pointer swap (steal_chunk) instead of memcpy.
 *   body_steal_miss      Copy #5 fallback: steal_chunk precondition not met
 *                        (non-H2 downstream, pointer mismatch, etc.).
 *   send_spliced_bytes   Copy #3 eliminated: bytes moved from response_buf_ to
 *                        wb_ by pointer splice (remove_zc phase 1, no memcpy).
 *   send_tail_bytes      Copy #3 residual: bytes in the final partial chunk
 *                        that still required a memcpy (remove_zc phase 2).
 *   recv_zc_segs         XLIO recv_zc segments consumed (Copy #4 path, only
 *                        active when xlio_recv_zc_fd is found by dlsym).
 *
 * Diagnostic counters (understanding remove_zc efficiency):
 *   send_cb_count        Total calls to send_data_callback.
 *   send_cb_length_total Sum of all `length` arguments → avg = total/count.
 *                        If avg ≪ 16384, flow control windows are too small.
 *   send_cb_head_mlen_total Sum of body->head->len() before remove_zc →
 *                        avg head chunk size entering the splice loop.
 *   send_cb_zero_splice  Calls where remove_zc transferred 0 bytes in phase 1
 *                        (head chunk too large for count; everything memcpy'd).
 *   send_cb_full_splice  Calls where remove_zc had zero tail bytes copied
 *                        (entire request satisfied by full-chunk splices).
 *   send_cb_remote_win_total Sum of nghttp2_session_get_stream_remote_window_size()
 *                        at callback time → avg = total/count tells us the actual
 *                        stream window available.  If avg ≈ length → window-limited.
 *                        If avg >> length → something internal to nghttpx limits it.
 *   send_cb_body_drained Calls where length == body->rleft() before remove_zc:
 *                        body had ≤ length bytes, meaning the body buffer was
 *                        the binding constraint (not flow control).
 *                        If this ≈ send_cb_count → body underruns dominate.
 *                        If this ≈ 0 → flow control windows are still too small.
 */
#pragma once

#include <atomic>
#include <cstdint>
#include <cstdio>

namespace shrpx {

struct ZcopyStats {
  alignas(64) std::atomic<uint64_t> body_steal_hit{0};
  alignas(64) std::atomic<uint64_t> body_steal_miss{0};
  alignas(64) std::atomic<uint64_t> send_spliced_bytes{0};
  alignas(64) std::atomic<uint64_t> send_tail_bytes{0};
  alignas(64) std::atomic<uint64_t> recv_zc_segs{0};
  // Diagnostic: remove_zc call-site shape
  alignas(64) std::atomic<uint64_t> send_cb_count{0};
  alignas(64) std::atomic<uint64_t> send_cb_length_total{0};
  alignas(64) std::atomic<uint64_t> send_cb_head_mlen_total{0};
  alignas(64) std::atomic<uint64_t> send_cb_zero_splice{0};
  alignas(64) std::atomic<uint64_t> send_cb_full_splice{0};
  alignas(64) std::atomic<uint64_t> send_cb_remote_win_total{0};
  alignas(64) std::atomic<uint64_t> send_cb_body_drained{0};
};

inline ZcopyStats &zcopy_stats() {
  static ZcopyStats s;
  return s;
}

inline void zcopy_stats_print(FILE *out = stderr) {
  auto &s = zcopy_stats();
  auto steal_hit      = s.body_steal_hit.load(std::memory_order_relaxed);
  auto steal_miss     = s.body_steal_miss.load(std::memory_order_relaxed);
  auto spliced        = s.send_spliced_bytes.load(std::memory_order_relaxed);
  auto tail_bytes     = s.send_tail_bytes.load(std::memory_order_relaxed);
  auto recv_zc        = s.recv_zc_segs.load(std::memory_order_relaxed);
  auto cb_count       = s.send_cb_count.load(std::memory_order_relaxed);
  auto cb_len_total   = s.send_cb_length_total.load(std::memory_order_relaxed);
  auto cb_mlen_total  = s.send_cb_head_mlen_total.load(std::memory_order_relaxed);
  auto zero_splice    = s.send_cb_zero_splice.load(std::memory_order_relaxed);
  auto full_splice    = s.send_cb_full_splice.load(std::memory_order_relaxed);
  auto remote_win_tot = s.send_cb_remote_win_total.load(std::memory_order_relaxed);
  auto body_drained   = s.send_cb_body_drained.load(std::memory_order_relaxed);

  uint64_t total_body = steal_hit + steal_miss;
  uint64_t total_send = spliced + tail_bytes;

  double avg_length     = cb_count > 0 ? (double)cb_len_total    / cb_count : 0.0;
  double avg_mlen       = cb_count > 0 ? (double)cb_mlen_total   / cb_count : 0.0;
  double avg_remote_win = cb_count > 0 ? (double)remote_win_tot  / cb_count : 0.0;

  fprintf(out,
    "[zcopy-stats]\n"
    "  body_steal_hit      = %10lu  (Copy#5 zero-copy, %.1f%%)\n"
    "  body_steal_miss     = %10lu  (Copy#5 fallback memcpy)\n"
    "  send_spliced_bytes  = %10lu  (Copy#3 zero-copy bytes, %.1f%%)\n"
    "  send_tail_bytes     = %10lu  (Copy#3 memcpy bytes, partial tail)\n"
    "  recv_zc_segs        = %10lu  (XLIO recv_zc, Copy#4 zero-copy)\n"
    "  --- remove_zc diagnostics ---\n"
    "  send_cb_count       = %10lu  (total send_data_callback calls)\n"
    "  avg_length          = %10.1f  (avg bytes requested per call; 16384=full frame)\n"
    "  avg_remote_win      = %10.1f  (avg stream remote window at callback time)\n"
    "    → if avg_remote_win≈avg_length: window IS the bottleneck\n"
    "    → if avg_remote_win≫avg_length: something inside nghttpx limits frame size\n"
    "  avg_head_mlen       = %10.1f  (avg body head-chunk size on entry)\n"
    "  zero_splice_calls   = %10lu  (%.1f%% of calls: head chunk > length, 0 spliced)\n"
    "  full_splice_calls   = %10lu  (%.1f%% of calls: tail_copied==0, perfect splice)\n"
    "  body_drained_calls  = %10lu  (%.1f%% of calls: length>=body->rleft(), body underrun)\n"
    "    → if body_drained≈100%%: body too small (backend pacing), or MAX_BUFFER_SIZE capping\n"
    "    → if body_drained≈0%%:   something else caps length (check avg_remote_win vs avg_length)\n",
    steal_hit,
    total_body > 0 ? steal_hit * 100.0 / total_body : 0.0,
    steal_miss,
    spliced,
    total_send > 0 ? spliced * 100.0 / total_send : 0.0,
    tail_bytes,
    recv_zc,
    cb_count,
    avg_length,
    avg_remote_win,
    avg_mlen,
    zero_splice,
    cb_count > 0 ? zero_splice * 100.0 / cb_count : 0.0,
    full_splice,
    cb_count > 0 ? full_splice * 100.0 / cb_count : 0.0,
    body_drained,
    cb_count > 0 ? body_drained * 100.0 / cb_count : 0.0);
}

} // namespace shrpx
