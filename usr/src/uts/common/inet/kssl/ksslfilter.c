/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <sys/systm.h>
#include <sys/cmn_err.h>
#include <sys/stropts.h>
#include <sys/strsun.h>
#include <sys/socketvar.h>
#include <sys/sockfilter.h>
#include <inet/kssl/ksslapi.h>
#include <sys/note.h>
#include <sys/taskq.h>

/*
 * Name of the KSSL filter
 */
#define	KSSL_FILNAME	"ksslf"

static struct modlmisc ksslf_modlmisc = {
	&mod_miscops,
	"Kernel SSL socket filter"
};

static struct modlinkage ksslf_modlinkage = {
	MODREV_1,
	&ksslf_modlmisc,
	NULL
};

/*
 * kssl filter cookie
 */
typedef struct ksslf {
	boolean_t	ksslf_pending;		/* waiting for 1st SSL rec. */
	boolean_t	ksslf_inhandshake;	/* during SSL handshake */
	kssl_ent_t	ksslf_ent;		/* SSL table entry */
	kssl_ctx_t	ksslf_ctx;		/* SSL session */
	kssl_endpt_type_t ksslf_type;		/* is proxy/is proxied/none */
	struct sockaddr_in6 ksslf_laddr;	/* local address */
	socklen_t	ksslf_laddrlen;
	struct ksslf	*ksslf_listener;
} ksslf_t;

static void kssl_input_callback(void *, mblk_t *, kssl_cmd_t);

/*
 * Allocate kssl state
 */
sof_rval_t
kssl_attach_passive_cb(sof_handle_t handle, sof_handle_t ph,
    void *parg, struct sockaddr *laddr, socklen_t laddrlen,
    struct sockaddr *faddr, socklen_t faddrlen, void **cookiep)
{
	ksslf_t *listener = (ksslf_t *)parg;
	ksslf_t *new;

	_NOTE(ARGUNUSED(handle, ph, faddrlen, laddr, laddrlen));

	if (listener == NULL || listener->ksslf_ent == NULL)
		return (SOF_RVAL_DETACH);
	/*
	 * Only way for a fallback listener to receive connections is when
	 * a handshake fails and socket is moved from the proxy to the fallback.
	 * Connections that come in directly on the fallback are denied.
	 */
	if (listener->ksslf_type == KSSL_HAS_PROXY)
		return (SOF_RVAL_EACCES);

	/* Allocate the SSL context for the new connection */
	new = kmem_zalloc(sizeof (ksslf_t), KM_NOSLEEP);
	if (new == NULL)
		return (SOF_RVAL_ENOMEM);

	/*
	 * The mss is initialized to SSL3_MAX_RECORD_LEN, but might be
	 * updated by the mblk_prop callback.
	 */
	if (kssl_init_context(listener->ksslf_ent, faddr, SSL3_MAX_RECORD_LEN,
	    &new->ksslf_ctx) != KSSL_STS_OK)
		return (SOF_RVAL_ENOMEM);

	new->ksslf_pending = B_TRUE;
	new->ksslf_inhandshake = B_TRUE;
	ASSERT(laddrlen <= sizeof (new->ksslf_laddr));
	new->ksslf_laddrlen = laddrlen;
	bcopy(laddr, &new->ksslf_laddr, laddrlen);
	new->ksslf_laddr.sin6_port = listener->ksslf_laddr.sin6_port;
	new->ksslf_listener = listener;

	*cookiep = new;
	/*
	 * We are in handshake, defer the notification of this connection
	 * until it is completed.
	 */
	return (SOF_RVAL_DEFER);
}

void
kssl_detach_cb(sof_handle_t handle, void *cookie, cred_t *cr)
{
	ksslf_t *kssl = (ksslf_t *)cookie;

	_NOTE(ARGUNUSED(handle, cr));

	if (kssl == NULL)
		return;

	if (kssl->ksslf_ent != NULL) {
		kssl_release_ent(kssl->ksslf_ent, handle, kssl->ksslf_type);
		kssl->ksslf_ent = NULL;
	}
	if (kssl->ksslf_ctx != NULL) {
		kssl_release_ctx(kssl->ksslf_ctx);
		kssl->ksslf_ctx = NULL;
	}

	kmem_free(kssl, sizeof (ksslf_t));
}

sof_rval_t
kssl_bind_cb(sof_handle_t handle, void *cookie, struct sockaddr *name,
    socklen_t *namelen, cred_t *cr)
{
	kssl_ent_t ent;
	kssl_endpt_type_t type;
	ksslf_t *kssl;
	in_port_t origport;

	_NOTE(ARGUNUSED(cr));

	if (cookie != NULL)
		return (SOF_RVAL_EINVAL);

	if (*namelen < sizeof (struct sockaddr_in)) {
		sof_bypass(handle);
		return (SOF_RVAL_CONTINUE);
	}

	origport = ((struct sockaddr_in *)name)->sin_port;
	/* Check if KSSL has been configured for this address */
	type = kssl_check_proxy(name, *namelen, handle, &ent);

	switch (type) {
	case KSSL_NO_PROXY:
		sof_bypass(handle);
		break;
	case KSSL_HAS_PROXY:
	case KSSL_IS_PROXY:
		kssl = kmem_zalloc(sizeof (ksslf_t), KM_SLEEP);
		kssl->ksslf_type = type;
		kssl->ksslf_ent = ent;

		/*
		 * In the unlikely event that there are multiple simultaneous
		 * bind requests, and the cookie was already swapped out, then
		 * just drop this cookie and let the bind continue unmodified.
		 */
		if (sof_cas_cookie(handle, cookie, kssl) != cookie) {
			kssl_release_ent(ent, handle, type);
			kmem_free(kssl, sizeof (ksslf_t));
			((struct sockaddr_in *)name)->sin_port = origport;
			break;
		}

		kssl->ksslf_laddrlen = *namelen;
		bcopy(name, &kssl->ksslf_laddr, kssl->ksslf_laddrlen);
		kssl->ksslf_laddr.sin6_port = origport;
		/*
		 * kssl_check_proxy updated the sockaddr, so just
		 * pass it along to the protocol.
		 */
		return ((type == KSSL_HAS_PROXY) ? SOF_RVAL_RETURN :
		    SOF_RVAL_CONTINUE);
	}
	return (SOF_RVAL_CONTINUE);
}

sof_rval_t
kssl_listen_cb(sof_handle_t handle, void *cookie, int *backlog, cred_t *cr)
{
	ksslf_t *kssl = (ksslf_t *)cookie;

	_NOTE(ARGUNUSED(backlog, cr));

	/*
	 * The cookie can be NULL in the unlikely event of an application doing
	 * listen() without binding to an address. Those listeners are of no
	 * interest.
	 */
	if (kssl == NULL) {
		sof_bypass(handle);
		return (SOF_RVAL_CONTINUE);
	}

	return (SOF_RVAL_CONTINUE);

}

/*
 * Outgoing connections are not of interest, so just bypass the filter.
 */
sof_rval_t
kssl_connect_cb(sof_handle_t handle, void *cookie, struct sockaddr *name,
    socklen_t *namelen, cred_t *cr)
{
	_NOTE(ARGUNUSED(cookie, name, namelen, cr));

	sof_bypass(handle);
	return (SOF_RVAL_CONTINUE);
}

static void
kssl_mblk_prop_cb(sof_handle_t handle, void *cookie, ssize_t *maxblk,
    ushort_t *wroff, ushort_t *tail)
{
	ksslf_t *kssl = (ksslf_t *)cookie;

	_NOTE(ARGUNUSED(handle));

	/* only care about passively opened sockets */
	if (kssl == NULL || !kssl->ksslf_pending)
		return;
	/*
	 * If this is endpoint is handling SSL, then reserve extra
	 * offset and space at the end. Also have sockfs allocate
	 * SSL3_MAX_RECORD_LEN packets, overriding the previous setting.
	 * The extra cost of signing and encrypting multiple MSS-size
	 * records (12 of them with Ethernet), instead of a single
	 * contiguous one by the stream head largely outweighs the
	 * statistical reduction of ACKs, when applicable. The peer
	 * will also save on decryption and verification costs.
	 */
	if (*maxblk == INFPSZ || *maxblk > SSL3_MAX_RECORD_LEN)
		*maxblk = SSL3_MAX_RECORD_LEN;
	else
		kssl_set_mss(kssl->ksslf_ctx, *maxblk);
	*wroff += SSL3_WROFFSET;
	*tail += SSL3_MAX_TAIL_LEN;
}

sof_rval_t
kssl_getsockname_cb(sof_handle_t handle, void *cookie, struct sockaddr *addr,
    socklen_t *addrlen, cred_t *cr)
{
	ksslf_t *kssl = (ksslf_t *)cookie;

	_NOTE(ARGUNUSED(handle, cr));

	if (kssl == NULL)
		return (SOF_RVAL_CONTINUE);

	if (*addrlen < kssl->ksslf_laddrlen)
		return (SOF_RVAL_EINVAL);

	*addrlen = kssl->ksslf_laddrlen;
	bcopy(&kssl->ksslf_laddr, addr, kssl->ksslf_laddrlen);

	return (SOF_RVAL_RETURN);
}

/*
 * Called for every packet sent to the protocol.
 * If the message is successfully processed, then it is returned.
 */
mblk_t *
kssl_data_out_cb(sof_handle_t handle, void *cookie, mblk_t *mp,
    struct nmsghdr *msg, cred_t *cr, sof_rval_t *rv)
{
	ksslf_t *kssl = (ksslf_t *)cookie;
	mblk_t *recmp;

	_NOTE(ARGUNUSED(handle, msg, cr));

	*rv = SOF_RVAL_CONTINUE;
	if (kssl == NULL || kssl->ksslf_ctx == NULL)
		return (mp);

	if ((recmp = kssl_build_record(kssl->ksslf_ctx, mp)) == NULL) {
		freemsg(mp);
		*rv = SOF_RVAL_EINVAL;
		return (NULL);
	}
	return (recmp);
}

/*
 * Called from shutdown() processing. This will produce close_notify message
 * to indicate the end of data to the client.
 */
sof_rval_t
kssl_shutdown_cb(sof_handle_t handle, void *cookie, int *howp, cred_t *cr)
{
	ksslf_t *kssl = (ksslf_t *)cookie;
	mblk_t *outmp;
	boolean_t flowctrld;
	struct nmsghdr msg;

	_NOTE(ARGUNUSED(cr));

	if (kssl == NULL || kssl->ksslf_ctx == NULL)
		return (SOF_RVAL_CONTINUE);

	/*
	 * We only want to send close_notify when doing SHUT_WR/SHUT_RDWR
	 * because it signals that server is done writing data.
	 */
	if (*howp == SHUT_RD)
		return (SOF_RVAL_CONTINUE);

	/* Go on if we fail to build the record. */
	if ((outmp = kssl_build_record(kssl->ksslf_ctx, NULL)) == NULL)
		return (SOF_RVAL_CONTINUE);

	bzero(&msg, sizeof (msg));
	(void) sof_inject_data_out(handle, outmp, &msg,
	    &flowctrld);

	return (SOF_RVAL_CONTINUE);
}

/*
 * Called for each incoming segment.
 *
 * A packet may carry multiple SSL records, so the function calls
 * kssl_input() in a loop, until all records are handled.
 */
mblk_t *
kssl_data_in_cb(sof_handle_t handle, void *cookie, mblk_t *mp, int flags,
    size_t *lenp)
{
	ksslf_t		*kssl = cookie;
	kssl_cmd_t	kssl_cmd;
	mblk_t		*outmp, *retmp = NULL, **tail = &retmp;
	boolean_t	more = B_FALSE;
	boolean_t	flowctrld;

	_NOTE(ARGUNUSED(flags));

	if (kssl == NULL || kssl->ksslf_ctx == NULL) {
		sof_bypass(handle);
		return (mp);
	}

	*lenp = 0;
	do {
		kssl_cmd = kssl_input(kssl->ksslf_ctx, mp, &outmp,
		    &more, kssl_input_callback, (void *)handle);

		switch (kssl_cmd) {
		case KSSL_CMD_SEND: {
			struct nmsghdr msg;

			DTRACE_PROBE(kssl_cmd_send);
			bzero(&msg, sizeof (msg));
			(void) sof_inject_data_out(handle, outmp, &msg,
			    &flowctrld);
		}
		/* FALLTHROUGH */
		case KSSL_CMD_NONE:
			DTRACE_PROBE(kssl_cmd_none);
			if (kssl->ksslf_pending) {
				kssl->ksslf_pending = B_FALSE;
				sof_newconn_ready(handle);
			}
			break;

		case KSSL_CMD_QUEUED:
			DTRACE_PROBE(kssl_cmd_queued);
			break;

		case KSSL_CMD_DELIVER_PROXY:
		case KSSL_CMD_DELIVER_SSL:
			DTRACE_PROBE(kssl_cmd_proxy__ssl);
			/*
			 * We're at a phase where records are sent upstreams,
			 * past the handshake
			 */
			kssl->ksslf_inhandshake = B_FALSE;

			*tail = outmp;
			*lenp += MBLKL(outmp);
			while (outmp->b_cont != NULL) {
				outmp = outmp->b_cont;
				*lenp += MBLKL(outmp);
			}
			tail = &outmp->b_cont;
			break;

		case KSSL_CMD_NOT_SUPPORTED: {
			ksslf_t *listener = kssl->ksslf_listener;
			sof_handle_t fallback;

			DTRACE_PROBE(kssl_cmd_not_supported);
			/*
			 * Stop the SSL processing by the proxy, and
			 * switch to the userland SSL
			 */
			if (kssl->ksslf_pending) {
				kssl->ksslf_pending = B_FALSE;

				DTRACE_PROBE1(kssl_no_can_do, sof_handle_t,
				    handle);

				sof_bypass(handle);

				ASSERT(listener->ksslf_ent != NULL);
				fallback =
				    kssl_find_fallback(listener->ksslf_ent);
				/*
				 * No fallback: the remote will timeout and
				 * disconnect.
				 */
				if (fallback != NULL &&
				    sof_newconn_move(handle, fallback))
					sof_newconn_ready(handle);
			}
			if (mp != NULL) {
				*tail = mp;
				*lenp += MBLKL(mp);
				while (mp->b_cont != NULL) {
					mp = mp->b_cont;
					*lenp += MBLKL(mp);
				}
				tail = &mp->b_cont;
			}
			break;
		}
		}
		mp = NULL;
	} while (more);

	return (retmp);
}

/*
 * Process queued data before it's copied by the user.
 *
 * If the message is successfully processed, then it is returned.
 * A failed message will be freed.
 */
mblk_t *
kssl_data_in_proc_cb(sof_handle_t handle, void *cookie, mblk_t *mp,
    cred_t *cr, size_t *lenp)
{
	ksslf_t *kssl = (ksslf_t *)cookie;
	kssl_cmd_t kssl_cmd;
	mblk_t *out;

	_NOTE(ARGUNUSED(cr));

	if (kssl == NULL || kssl->ksslf_ctx)
		return (mp);

	*lenp = 0;

	kssl_cmd = kssl_handle_mblk(kssl->ksslf_ctx, &mp, &out);

	switch (kssl_cmd) {
	case KSSL_CMD_NONE:
		return (NULL);
	case KSSL_CMD_DELIVER_PROXY:
		*lenp = msgdsize(mp);
		return (mp);
	case KSSL_CMD_SEND: {
		struct nmsghdr msg;
		boolean_t flowctrld;

		ASSERT(out != NULL);
		bzero(&msg, sizeof (msg));

		(void) sof_inject_data_out(handle, out, &msg,
		    &flowctrld);
		return (NULL);
	}
	default:
		/* transient error. */
		return (NULL);
	}
}

/*
 * Continue processing the incoming flow after an asynchronous callback.
 */
static void
kssl_input_asynch(void *arg)
{
	sof_handle_t handle = (sof_handle_t)arg;
	ksslf_t *kssl = (ksslf_t *)sof_get_cookie(handle);
	size_t len = 0;
	boolean_t flowctrld;
	mblk_t *mp;

	if ((mp = kssl_data_in_cb(handle, kssl, NULL, 0, &len)) != NULL) {
		ASSERT(len != 0);
		(void) sof_inject_data_in(handle, mp, len, 0, &flowctrld);
	}
	kssl_async_done(kssl->ksslf_ctx);
}

/*
 * Callback function for the cases kssl_input() had to submit an asynchronous
 * job and need to come back when done to carry on the input processing.
 * This routine follows the conentions of timeout and interrupt handlers.
 * (no blocking, ...)
 */
static void
kssl_input_callback(void *arg, mblk_t *mp, kssl_cmd_t kssl_cmd)
{
	sof_handle_t handle = (sof_handle_t)arg;
	ksslf_t *kssl = (ksslf_t *)sof_get_cookie(handle);
	boolean_t flowctrld;

	ASSERT(kssl != NULL);

	switch (kssl_cmd) {
	case KSSL_CMD_SEND: {
		struct nmsghdr msg;

		if (mp == NULL)
			break;
		bzero(&msg, sizeof (msg));

		(void) sof_inject_data_out(handle, mp, &msg, &flowctrld);
	}
	/* FALLTHROUGH */
	case KSSL_CMD_NONE:
		break;

	case KSSL_CMD_DELIVER_PROXY:
	case KSSL_CMD_DELIVER_SSL:
		(void) sof_inject_data_in(handle, mp, msgdsize(mp), 0,
		    &flowctrld);
		break;

	case KSSL_CMD_NOT_SUPPORTED:
		/* Stop the SSL processing */
		sof_bypass(handle);
	}
	/*
	 * Process any input that may have accumulated while we're waiting for
	 * the call-back. This must be done by a taskq because kssl_input might
	 * block when handling client_finish messages.
	 */
	if (taskq_dispatch(system_taskq, kssl_input_asynch, handle,
	    TQ_NOSLEEP) == TASKQID_INVALID) {
		DTRACE_PROBE(kssl_err__taskq_dispatch_failed);
		kssl_async_done(kssl->ksslf_ctx);
	}
}

sof_ops_t ksslf_ops = {
	.sofop_attach_passive = kssl_attach_passive_cb,
	.sofop_detach = kssl_detach_cb,
	.sofop_bind = kssl_bind_cb,
	.sofop_connect = kssl_connect_cb,
	.sofop_listen = kssl_listen_cb,
	.sofop_data_in = kssl_data_in_cb,
	.sofop_data_in_proc = kssl_data_in_proc_cb,
	.sofop_data_out = kssl_data_out_cb,
	.sofop_mblk_prop = kssl_mblk_prop_cb,
	.sofop_getsockname = kssl_getsockname_cb,
	.sofop_shutdown = kssl_shutdown_cb,
};

int
_init(void)
{
	int error;

	if ((error = sof_register(SOF_VERSION, KSSL_FILNAME,
	    &ksslf_ops, 0)) != 0)
		return (error);
	if ((error = mod_install(&ksslf_modlinkage)) != 0)
		(void) sof_unregister(KSSL_FILNAME);

	return (error);
}

int
_fini(void)
{
	int error;

	if ((error = sof_unregister(KSSL_FILNAME)) != 0)
		return (error);

	return (mod_remove(&ksslf_modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&ksslf_modlinkage, modinfop));
}
