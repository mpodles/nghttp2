/*
 * XLIO adapter for nghttpx — zero-copy receive via xlio_recv_zc_fd().
 *
 * Self-contained: does NOT include any XLIO headers.  The types needed are
 * defined locally (they must match the layout in xlio_types.h / xlio_extra.h).
 * Detection is purely at runtime via dlsym, so the binary compiles and runs
 * correctly whether or not XLIO is present.
 *
 * Usage
 * -----
 *   XlioAdapter &xa = XlioAdapter::get();
 *   if (xa.has_recv_zc()) {
 *       shrpx_xlio_zc_seg segs[SHRPX_XLIO_MAX_SEGS];
 *       int n = xa.recv_zc(fd, segs, SHRPX_XLIO_MAX_SEGS);
 *       if (n > 0) { ... xa.release_zc(segs[i].buf); }
 *   }
 */

#pragma once

#include <dlfcn.h>
#include <cerrno>
#include <cstddef>
#include <cstdint>

namespace shrpx {

/** Maximum number of zero-copy segments to request in a single call. */
static constexpr int SHRPX_XLIO_MAX_SEGS = 64;

/*
 * Opaque handle for an XLIO receive buffer.  Must be released via
 * XlioAdapter::release_zc() when the application is done reading from it.
 * Layout does not matter here — we only ever pass it by pointer.
 */
struct xlio_buf_opaque;

/*
 * Descriptor for one zero-copy receive segment.
 * Layout must match struct xlio_zc_seg in xlio_types.h.
 */
struct shrpx_xlio_zc_seg {
    void             *data;      /* plaintext start; valid until release_zc() */
    std::size_t       len;       /* byte count */
    xlio_buf_opaque  *buf;       /* release handle */
    std::uint8_t      tls_type;  /* TLS record type; 0x17 = application data */
};

/*
 * XlioAdapter — singleton wrapper around XLIO's zero-copy recv extension.
 *
 * Provides:
 *   has_recv_zc()  — true if xlio_recv_zc_fd is available at runtime.
 *   recv_zc()      — thin forward to xlio_recv_zc_fd().
 *   release_zc()   — thin forward to xlio_recv_zc_release().
 *
 * Thread safety: get() is safe after the first call.  The singleton is
 * initialised inside a static-local (C++11 magic statics).
 */
class XlioAdapter {
public:
    static XlioAdapter &get()
    {
        static XlioAdapter instance;
        return instance;
    }

    /** True if XLIO's zero-copy receive extension is available at runtime. */
    bool has_recv_zc() const { return recv_zc_ != nullptr; }

    /**
     * Drain up to max_segs receive segments from fd into segs[].
     *
     * Returns segment count (>= 1) or -1:
     *   errno == EAGAIN   — no data yet.
     *   errno == ENODATA  — next buffer is a non-data TLS record; fall back.
     *   errno == ENOTSUP  — not an XLIO/UTLS-RX socket; fall back permanently.
     */
    int recv_zc(int fd, shrpx_xlio_zc_seg *segs, int max_segs) const
    {
        return recv_zc_(fd, segs, max_segs);
    }

    /**
     * Release one buffer returned by recv_zc().
     * Call after nghttp2_session_mem_recv2() returns (it is synchronous).
     */
    void release_zc(xlio_buf_opaque *buf) const
    {
        release_zc_(buf);
    }

private:
    using recv_zc_fn_t    = int  (*)(int, shrpx_xlio_zc_seg *, int);
    using release_zc_fn_t = void (*)(xlio_buf_opaque *);

    recv_zc_fn_t    recv_zc_    {nullptr};
    release_zc_fn_t release_zc_ {nullptr};

    XlioAdapter()
    {
        /*
         * Locate the XLIO zero-copy functions directly by symbol name.
         * Works with both LD_PRELOAD and direct linking.  If either symbol is
         * absent the adapter stays in no-op mode (has_recv_zc() == false).
         *
         * We do NOT use xlio_get_api() here to avoid needing any XLIO
         * headers at compile time.
         */
        recv_zc_    = reinterpret_cast<recv_zc_fn_t>(
            ::dlsym(RTLD_DEFAULT, "xlio_recv_zc_fd"));
        release_zc_ = reinterpret_cast<release_zc_fn_t>(
            ::dlsym(RTLD_DEFAULT, "xlio_recv_zc_release"));

        /* Both must be present; clear if only one resolved. */
        if (!recv_zc_ || !release_zc_) {
            recv_zc_    = nullptr;
            release_zc_ = nullptr;
        }
    }

    XlioAdapter(const XlioAdapter &) = delete;
    XlioAdapter &operator=(const XlioAdapter &) = delete;
};

}  // namespace shrpx
