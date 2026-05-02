/*
 * XLIO adapter for nghttpx.
 *
 * Covers two capabilities:
 *
 *   RX zero-copy (XLIO_EXTRA_API_RECV_ZC)
 *   ──────────────────────────────────────
 *   xlio_recv_zc_fd / xlio_recv_zc_release — expose XLIO DMA receive buffers
 *   directly to the HTTP/2 parser, eliminating the copy inside SSL_read.
 *   Used by Http2Session::read_tls_zcopy().
 *
 *   Ultra API TX (XLIO_EXTRA_API_SOCKET_FROM_FD + XLIO_EXTRA_API_XLIO_ULTRA)
 *   ──────────────────────────────────────────────────────────────────────────
 *   xlio_socket_from_fd — convert an existing fd to an xlio_socket_t handle
 *   without disrupting the connection (no recv callback changes).  Used after
 *   the TLS handshake to obtain the handle for Ultra API sends.
 *
 *   xlio_socket_sendv (INLINE flag) — send data via the Ultra API on cleartext
 *   connections.  For UTLS_TX sockets SSL_write must still be used because
 *   tcp_tx_express_inline bypasses sockinfo_tcp_ops_tls::tcp_tx which adds
 *   the TLS record headers before NIC encryption.
 *
 *   xlio_poll_group_create / _poll / _destroy / _flush — one poll-group per
 *   Worker thread drives TX completions and feeds the spin loop.
 *
 * Detection strategy
 * ──────────────────
 * Ultra API functions (xlio_poll_group_create, xlio_socket_sendv, …) are NOT
 * exported as dynamic symbols in libxlio — they are accessed via the
 * xlio_api_t struct returned by getsockopt(-2, SOL_SOCKET, SO_XLIO_GET_API).
 * Only a few extension functions (xlio_recv_zc_fd, xlio_socket_from_fd) carry
 * EXPORT_SYMBOL and are reachable through dlsym.
 *
 * When <mellanox/xlio_extra.h> is available at compile time the XlioAdapter
 * constructor calls xlio_get_api() and extracts all function pointers from the
 * returned struct.  If the header is absent the constructor falls back to dlsym
 * for the exported-symbol functions only; Ultra API functions stay null and
 * has_ultra_tx() returns false.
 *
 * The binary always compiles and runs correctly whether or not XLIO is
 * present at runtime.
 */

#pragma once

#include <dlfcn.h>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <sys/uio.h>
#include <sys/socket.h>

/* Conditionally pull in the system XLIO header. */
#if __has_include(<mellanox/xlio_extra.h>)
#  include <mellanox/xlio_extra.h>
#  define SHRPX_HAVE_XLIO_EXTRA_H 1
#endif

namespace shrpx {

/** Maximum number of zero-copy segments to request in a single call. */
static constexpr int SHRPX_XLIO_MAX_SEGS = 64;

/*
 * Opaque handle for an XLIO receive buffer.  Must be released via
 * XlioAdapter::release_zc() when the application is done reading from it.
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
 * Socket and poll-group handle types.
 * When xlio_extra.h is available these are aliases to the real XLIO types
 * (both are uintptr_t under the hood so the ABI is identical either way).
 */
#ifdef SHRPX_HAVE_XLIO_EXTRA_H
using shrpx_xlio_socket_t     = xlio_socket_t;
using shrpx_xlio_poll_group_t = xlio_poll_group_t;
#else
using shrpx_xlio_socket_t     = std::uintptr_t;
using shrpx_xlio_poll_group_t = std::uintptr_t;
#endif

/*
 * Polling group attributes passed to poll_group_create().
 *
 * Layout must match struct xlio_poll_group_attr in xlio_types.h:
 *   unsigned flags
 *   xlio_socket_event_cb_t  socket_event_cb   (required)
 *   xlio_socket_comp_cb_t   socket_comp_cb    (optional, null for now)
 *   xlio_socket_rx_cb_t     socket_rx_cb      (optional, null for now)
 *   xlio_socket_accept_cb_t socket_accept_cb  (optional, null for now)
 *
 * When xlio_extra.h is included we just pass a real xlio_poll_group_attr;
 * this local struct is kept for documentation and fallback mode.
 */
struct shrpx_xlio_poll_group_attr {
    unsigned  flags;
    /* event: (sock, userdata_sq, event, value) */
    void    (*socket_event_cb)(shrpx_xlio_socket_t, std::uintptr_t, int, int);
    /* comp: (sock, userdata_sq, userdata_op) */
    void    (*socket_comp_cb)(shrpx_xlio_socket_t, std::uintptr_t,
                               std::uintptr_t);
    /* rx: (sock, userdata_sq, data, len, buf) */
    void    (*socket_rx_cb)(shrpx_xlio_socket_t, std::uintptr_t, void *,
                             std::size_t, xlio_buf_opaque *);
    /* accept: (sock, parent, parent_userdata_sq) */
    void    (*socket_accept_cb)(shrpx_xlio_socket_t, shrpx_xlio_socket_t,
                                 std::uintptr_t);
};

/*
 * Minimal send-attribute struct.  Layout must match xlio_socket_send_attr.
 * Flags: XLIO_SOCKET_SEND_FLAG_INLINE = 0x1, FLUSH = 0x2.
 */
struct shrpx_xlio_send_attr {
    std::uint32_t  flags;
    std::uint32_t  mkey;
    std::uintptr_t userdata_op;
};

static constexpr std::uint32_t SHRPX_XLIO_SEND_FLAG_INLINE = 0x1u;
static constexpr std::uint32_t SHRPX_XLIO_SEND_FLAG_FLUSH  = 0x2u;

/*
 * XlioAdapter — singleton wrapping XLIO's RX zero-copy and Ultra TX API.
 *
 * All methods are no-ops (returning sensible defaults) when XLIO is absent.
 * Thread safety: get() is safe after the first call (C++11 magic statics).
 */
class XlioAdapter {
public:
    static XlioAdapter &get()
    {
        static XlioAdapter instance;
        return instance;
    }

    /* ------------------------------------------------------------------ */
    /* RX zero-copy                                                        */
    /* ------------------------------------------------------------------ */

    /** True if XLIO's zero-copy receive extension is available at runtime. */
    bool has_recv_zc() const { return recv_zc_ != nullptr; }

    /**
     * Drain up to max_segs receive segments from fd into segs[].
     * Returns segment count (>= 1) or -1 on error/no-data.
     */
    int recv_zc(int fd, shrpx_xlio_zc_seg *segs, int max_segs) const
    {
        return recv_zc_(fd, segs, max_segs);
    }

    /** Release one buffer returned by recv_zc(). */
    void release_zc(xlio_buf_opaque *buf) const { release_zc_(buf); }

    /**
     * Increment the reference count of a buffer returned by recv_zc().
     * Call once for each additional sendv_zc() that will reference this
     * buffer beyond the first (the first sendv_zc consumes the recv_zc ref).
     * Each ref is released by ZcRxOwner::put() on TCP ACK.
     */
    void buf_add_ref(xlio_buf_opaque *buf) const
    {
        if (buf_addref_ && buf) buf_addref_(buf);
    }

    /* ------------------------------------------------------------------ */
    /* Ultra API: socket handle                                            */
    /* ------------------------------------------------------------------ */

    /**
     * True if xlio_socket_from_fd and xlio_socket_sendv are available.
     *
     * NOTE: For connections with UTLS_TX active, xlio_socket_sendv(INLINE)
     * bypasses sockinfo_tcp_ops_tls::tcp_tx and therefore does NOT add TLS
     * record headers.  Use write_tls (SSL_write) for TLS sends until a
     * TLS-aware express send path is added to sockinfo_tcp_ops_tls.
     */
    bool has_ultra_tx() const { return socket_from_fd_ != nullptr; }

    /**
     * Obtain an xlio_socket_t for an existing fd without disrupting the
     * connection.  Returns 0 if the fd is not an XLIO-managed TCP socket.
     */
    shrpx_xlio_socket_t socket_from_fd(int fd) const
    {
        return socket_from_fd_(fd);
    }

    /* ------------------------------------------------------------------ */
    /* Ultra API: send                                                     */
    /* ------------------------------------------------------------------ */

    /**
     * Send data inline (copied into XLIO's internal buffers).
     * Safe for cleartext connections.
     * Returns 0 on success, -1 on error.
     */
    int sendv_inline(shrpx_xlio_socket_t sock, const struct iovec *iov,
                     unsigned iovcnt, bool flush = true) const
    {
        shrpx_xlio_send_attr attr{};
        attr.flags = SHRPX_XLIO_SEND_FLAG_INLINE;
        if (flush) attr.flags |= SHRPX_XLIO_SEND_FLAG_FLUSH;
        return socket_sendv_(sock, iov, iovcnt, &attr);
    }

    /**
     * [TEST-ZC] Get the HCA lkey for an xlio_buf (works for ZC-RX buffers).
     * Returns 0 if unavailable.
     */
    std::uint32_t buf_get_mkey(xlio_buf_opaque *buf) const
    {
        if (!buf_get_mkey_ || !buf) return 0u;
        return buf_get_mkey_(buf);
    }

    /**
     * [TEST-ZC] Level-2 zero-copy send: iov points into xlio_buf's DMA memory.
     *
     * Do NOT call release_zc(buf) after a successful call — ownership of buf
     * is transferred to the XLIO TLS record layer, which releases it on TCP
     * ACK via ZcRxOwner::put() → xlio_buf_free().
     *
     * On failure the internal ZcRxOwner::put() still frees buf; caller must
     * likewise not call release_zc() in either case.
     *
     * Returns bytes written (>= 0) on success, -1 on error.
     */
    int sendv_zc(shrpx_xlio_socket_t sock, const struct iovec *iov,
                 unsigned iovcnt, xlio_buf_opaque *buf, bool flush = true) const
    {
        shrpx_xlio_send_attr attr{};
        if (flush) attr.flags |= SHRPX_XLIO_SEND_FLAG_FLUSH;
        /* mkey=0 is fine for TLS ZC path; get_lkey comes from ZcRxOwner. */
        attr.userdata_op = reinterpret_cast<std::uintptr_t>(buf);
        return socket_sendv_(sock, iov, iovcnt, &attr);
    }

    /** Flush any buffered data for sock. */
    void socket_flush(shrpx_xlio_socket_t sock) const
    {
        if (socket_flush_) socket_flush_(sock);
    }

    /* ------------------------------------------------------------------ */
    /* Ultra API: poll group                                               */
    /* ------------------------------------------------------------------ */

    /**
     * Create a poll group.  attr->socket_event_cb must be non-null.
     * Returns 0 and sets *group_out on success.
     */
    int poll_group_create(const shrpx_xlio_poll_group_attr *attr,
                          shrpx_xlio_poll_group_t *group_out) const
    {
        if (!poll_group_create_) { errno = ENOTSUP; return -1; }
        return poll_group_create_(attr, group_out);
    }

    /** Destroy a poll group created with poll_group_create(). */
    void poll_group_destroy(shrpx_xlio_poll_group_t grp) const
    {
        if (poll_group_destroy_) poll_group_destroy_(grp);
    }

    /**
     * Process pending XLIO events for grp.  Call as often as possible
     * (typically in a tight spin loop or an ev_prepare callback).
     */
    void poll_group_poll(shrpx_xlio_poll_group_t grp) const
    {
        if (poll_group_poll_) poll_group_poll_(grp);
    }

    /** Flush all pending TX for all sockets in grp. */
    void poll_group_flush(shrpx_xlio_poll_group_t grp) const
    {
        if (poll_group_flush_) poll_group_flush_(grp);
    }

private:
    /* RX zero-copy — these are exported symbols, dlsym works. */
    using recv_zc_fn_t    = int  (*)(int, shrpx_xlio_zc_seg *, int);
    using release_zc_fn_t = void (*)(xlio_buf_opaque *);
    using buf_addref_fn_t = void (*)(xlio_buf_opaque *);

    /* Ultra TX */
    using socket_from_fd_fn_t  = shrpx_xlio_socket_t (*)(int);
    using socket_sendv_fn_t    = int  (*)(shrpx_xlio_socket_t,
                                          const struct iovec *, unsigned,
                                          const shrpx_xlio_send_attr *);
    using socket_flush_fn_t    = void (*)(shrpx_xlio_socket_t);
    using buf_get_mkey_fn_t    = std::uint32_t (*)(xlio_buf_opaque *);

    /* Poll group */
    using poll_group_create_fn_t  = int  (*)(const shrpx_xlio_poll_group_attr *,
                                              shrpx_xlio_poll_group_t *);
    using poll_group_destroy_fn_t = void (*)(shrpx_xlio_poll_group_t);
    using poll_group_poll_fn_t    = void (*)(shrpx_xlio_poll_group_t);
    using poll_group_flush_fn_t   = void (*)(shrpx_xlio_poll_group_t);

    recv_zc_fn_t          recv_zc_            {nullptr};
    release_zc_fn_t       release_zc_         {nullptr};
    buf_addref_fn_t       buf_addref_         {nullptr};

    socket_from_fd_fn_t   socket_from_fd_     {nullptr};
    socket_sendv_fn_t     socket_sendv_       {nullptr};
    socket_flush_fn_t     socket_flush_       {nullptr};
    buf_get_mkey_fn_t     buf_get_mkey_       {nullptr};

    poll_group_create_fn_t  poll_group_create_  {nullptr};
    poll_group_destroy_fn_t poll_group_destroy_ {nullptr};
    poll_group_poll_fn_t    poll_group_poll_    {nullptr};
    poll_group_flush_fn_t   poll_group_flush_   {nullptr};

    XlioAdapter()
    {
        /*
         * Zero-copy receive: xlio_recv_zc_fd and xlio_recv_zc_release are
         * explicitly exported symbols (EXPORT_SYMBOL), so dlsym finds them.
         */
        recv_zc_    = reinterpret_cast<recv_zc_fn_t>(
            ::dlsym(RTLD_DEFAULT, "xlio_recv_zc_fd"));
        release_zc_ = reinterpret_cast<release_zc_fn_t>(
            ::dlsym(RTLD_DEFAULT, "xlio_recv_zc_release"));
        if (!recv_zc_ || !release_zc_) {
            recv_zc_    = nullptr;
            release_zc_ = nullptr;
        }
        /* xlio_buf_addref is co-located with the RX ZC symbols in sock-extra. */
        buf_addref_ = reinterpret_cast<buf_addref_fn_t>(
            ::dlsym(RTLD_DEFAULT, "xlio_buf_addref"));

        /*
         * xlio_socket_from_fd is also exported (EXPORT_SYMBOL), dlsym works.
         */
        socket_from_fd_ = reinterpret_cast<socket_from_fd_fn_t>(
            ::dlsym(RTLD_DEFAULT, "xlio_socket_from_fd"));

        /*
         * Ultra API functions are NOT exported as dynamic symbols — they are
         * only accessible via the xlio_api_t struct returned by
         * getsockopt(-2, SOL_SOCKET, SO_XLIO_GET_API).
         *
         * When xlio_extra.h is available at compile time we call xlio_get_api()
         * directly for type-safe struct access.  Otherwise (no header) the
         * Ultra API stays disabled.
         */
#ifdef SHRPX_HAVE_XLIO_EXTRA_H
        struct xlio_api_t *api = xlio_get_api();
        if (api && (api->cap_mask & XLIO_EXTRA_API_XLIO_ULTRA)) {
            poll_group_create_  = reinterpret_cast<poll_group_create_fn_t>(
                api->xlio_poll_group_create);
            poll_group_destroy_ = reinterpret_cast<poll_group_destroy_fn_t>(
                api->xlio_poll_group_destroy);
            poll_group_poll_    = reinterpret_cast<poll_group_poll_fn_t>(
                api->xlio_poll_group_poll);
            poll_group_flush_   = reinterpret_cast<poll_group_flush_fn_t>(
                api->xlio_poll_group_flush);
            socket_sendv_       = reinterpret_cast<socket_sendv_fn_t>(
                api->xlio_socket_sendv);
            socket_flush_       = reinterpret_cast<socket_flush_fn_t>(
                api->xlio_socket_flush);
            buf_get_mkey_       = reinterpret_cast<buf_get_mkey_fn_t>(
                api->xlio_socket_buf_get_mkey);

            /* Require sendv for Ultra TX to be considered available. */
            if (!socket_sendv_) {
                poll_group_create_  = nullptr;
                poll_group_destroy_ = nullptr;
                poll_group_poll_    = nullptr;
                poll_group_flush_   = nullptr;
                socket_flush_       = nullptr;
            }
        }

        /*
         * xlio_socket_from_fd may also be in the api struct (for the case
         * where the library is newer but dlsym didn't find it for some reason).
         * Only override if dlsym didn't already resolve it.
         */
        if (!socket_from_fd_ && api &&
            (api->cap_mask & XLIO_EXTRA_API_SOCKET_FROM_FD)) {
            socket_from_fd_ = reinterpret_cast<socket_from_fd_fn_t>(
                api->xlio_socket_from_fd);
        }
#endif /* SHRPX_HAVE_XLIO_EXTRA_H */
    }

    XlioAdapter(const XlioAdapter &) = delete;
    XlioAdapter &operator=(const XlioAdapter &) = delete;
};

}  // namespace shrpx
