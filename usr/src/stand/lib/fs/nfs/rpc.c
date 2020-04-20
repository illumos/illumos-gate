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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * This file contains a simple implementation of RPC. Standard XDR is
 * used.
 */

#include <sys/sysmacros.h>
#include <rpc/types.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "socket_inet.h"
#include "ipv4.h"
#include <rpc/xdr.h>
#include <rpc/auth.h>
#include <rpc/auth_sys.h>
#include <rpc/rpc_msg.h>
#include <sys/t_lock.h>
#include <netdb.h>
#include "clnt.h"
#include <rpc/rpc.h>
#include "brpc.h"
#include "auth_inet.h"
#include "pmap.h"
#include <sys/promif.h>
#include "nfs_inet.h"
#include <rpcsvc/nfs_prot.h>
#include <rpc/auth_unix.h>
#include <sys/salib.h>
#include "mac.h"
#include <sys/bootdebug.h>

#define	dprintf	if (boothowto & RB_DEBUG) printf

static struct in_addr cached_destination;

void
rpc_disperr(struct rpc_err *stat)
{
	if (boothowto & RB_DEBUG) {
		switch (stat->re_status) {
		case RPC_CANTENCODEARGS:
			printf("RPC: Can't encode arguments.\n");
			break;
		case RPC_CANTDECODERES:
			printf("RPC: Can't decode result.\n");
			break;
		case RPC_CANTSEND:
			printf("RPC: Unable to send (%s).\n",
			    strerror(errno));
			break;
		case RPC_CANTRECV:
			printf("RPC: Unable to receive (%s).\n",
			    strerror(errno));
			break;
		case RPC_TIMEDOUT:
			printf("RPC: Timed out.\n");
			break;
		case RPC_VERSMISMATCH:
			printf("RPC: Incompatible versions of RPC.\n");
			break;
		case RPC_AUTHERROR:
			printf("RPC: Authentication error:\n");
			switch (stat->re_why) {
			case AUTH_BADCRED:
				printf("remote: bogus credentials "
				    "(seal broken).\n");
				break;
			case AUTH_REJECTEDCRED:
				printf("remote: client should begin new "
				    "session.\n");
				break;
			case AUTH_BADVERF:
				printf("remote: bogus verifier "
				    "(seal broken).\n");
				break;
			case AUTH_REJECTEDVERF:
				printf("remote: verifier expired or was "
				    "replayed.\n");
				break;
			case AUTH_TOOWEAK:
				printf("remote: rejected due to security "
				    "reasons.\n");
				break;
			case AUTH_INVALIDRESP:
				printf("local: bogus response verifier.\n");
				break;
			case AUTH_FAILED:
				/* FALLTHRU */
			default:
				printf("local: unknown error.\n");
				break;
			}
			break;
		case RPC_PROGUNAVAIL:
			printf("RPC: Program unavailable.\n");
			break;
		case RPC_PROGVERSMISMATCH:
			printf("RPC: Program/version mismatch.\n");
			break;
		case RPC_PROCUNAVAIL:
			printf("RPC: Procedure unavailable.\n");
			break;
		case RPC_CANTDECODEARGS:
			printf("RPC: Server can't decode arguments.\n");
			break;
		case RPC_SYSTEMERROR:
			printf("RPC: Remote system error.\n");
			break;
		case RPC_UNKNOWNHOST:
			printf("RPC: Unknown host.\n");
			break;
		case RPC_UNKNOWNPROTO:
			printf("RPC: Unknown protocol.\n");
			break;
		case RPC_PMAPFAILURE:
			printf("RPC: Port mapper failure.\n");
			break;
		case RPC_PROGNOTREGISTERED:
			printf("RPC: Program not registered.\n");
			break;
		case RPC_FAILED:
			printf("RPC: Failed (unspecified error).\n");
			break;
		default:
			printf("RPC: (unknown error code).\n");
			break;
		}
	}
}

/*
 * rpc_hdr: sets the fields in the rpc msg header.
 *
 * Returns: TRUE on success, FALSE if failure.
 */
/*ARGSUSED*/
static bool_t
rpc_hdr(XDR *xdrs, uint_t xid, rpcprog_t prog, rpcvers_t vers, rpcproc_t proc)
{
	struct rpc_msg call_msg;

	/* setup header */
	call_msg.rm_xid = xid;
	call_msg.rm_direction = CALL;
	call_msg.rm_call.cb_rpcvers = (rpcvers_t)RPC_MSG_VERSION;
	call_msg.rm_call.cb_prog = prog;
	call_msg.rm_call.cb_vers = vers;

	/* xdr the header. */
	if (xdr_callhdr(xdrs, &call_msg) == FALSE)
		return (FALSE);
	else
		return (TRUE);
}

/*
 * our version of brpc_call(). We cache in portnumber in to->sin_port for
 * your convenience. to and from addresses are taken and received in network
 * order.
 */
enum clnt_stat
brpc_call(
	rpcprog_t	prog,		/* rpc program number to call. */
	rpcvers_t	vers,		/* rpc program version */
	rpcproc_t	proc,		/* rpc procedure to call */
	xdrproc_t	in_xdr,		/* routine to serialize arguments */
	caddr_t		args,		/* arg vector for remote call */
	xdrproc_t	out_xdr,	/* routine to deserialize results */
	caddr_t		ret,		/* addr of buf to place results in */
	int		rexmit,		/* retransmission interval (secs) */
	int		wait_time,	/* how long (secs) to wait (resp) */
	struct sockaddr_in 	*to,		/* destination */
	struct sockaddr_in	*from_who,	/* responder's port/address */
	uint_t			auth)		/* type of auth wanted. */
{
	int s;
	char hostname[MAXHOSTNAMELEN];
	struct sockaddr_in from;	/* us. */
	socklen_t from_len;
	XDR xmit_xdrs, rcv_xdrs;	/* xdr memory */
	AUTH *xmit_auth;		/* our chosen auth cookie */
	gid_t fake_gids = 1;		/* fake gids list for auth_unix */
	caddr_t trm_msg, rcv_msg;	/* outgoing/incoming rpc mesgs */
	struct rpc_msg reply;		/* our reply msg header */
	int trm_len, rcv_len;
	struct rpc_err rpc_error;	/* to store RPC errors in on rcv. */
	static uint_t xid;		/* current xid */
	uint_t xmit_len;		/* How much of the buffer we used */
	int nrefreshes = 2;		/* # of times to refresh cred */
	int flags = 0;			/* send flags */
	uint_t xdelay;
	int errors, preserve_errno;
	uint32_t timeout;
	socklen_t optlen;

	xmit_auth = NULL;

	trm_len = mac_get_mtu();
	trm_msg = bkmem_alloc(trm_len);
	rcv_msg = bkmem_alloc(NFSBUF_SIZE);

	if (trm_msg == NULL || rcv_msg == NULL) {
		errno = ENOMEM;
		rpc_error.re_status = RPC_CANTSEND;
		goto gt_error;
	}

	if ((s = socket(PF_INET, SOCK_DGRAM, 0)) < 0) {
		rpc_error.re_status = RPC_CANTSEND;
		goto gt_error;
	}

	if (dontroute) {
		(void) setsockopt(s, SOL_SOCKET, SO_DONTROUTE,
		    (const void *)&dontroute, sizeof (dontroute));
	}

	if (to->sin_addr.s_addr == cached_destination.s_addr) {
		optlen = sizeof (timeout);
		(void) getsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (void *)&timeout,
		    &optlen);
	} else {
		cached_destination.s_addr = htonl(INADDR_ANY);
	}

	/* Bind our endpoint. */
	from.sin_family = AF_INET;
	ipv4_getipaddr(&from.sin_addr);
	from.sin_addr.s_addr = htonl(from.sin_addr.s_addr);
	from.sin_port = get_source_port(B_TRUE);

	if (bind(s, (struct sockaddr *)&from, sizeof (from)) < 0) {
		rpc_error.re_status = RPC_CANTSEND;
		goto gt_error;
	}

	bzero((caddr_t)&rpc_error, sizeof (struct rpc_err));

	/* initialize reply's rpc_msg struct, so we can decode later. */
	reply.acpted_rply.ar_verf = _null_auth;	/* struct copy */
	reply.acpted_rply.ar_results.where = ret;
	reply.acpted_rply.ar_results.proc = out_xdr;

	if (ntohs(to->sin_port) == 0) {
		/* snag the udp port we need. */
		if ((to->sin_port = (in_port_t)bpmap_getport(prog, vers,
		    &(rpc_error.re_status), to, NULL)) == 0)
			goto gt_error;
		to->sin_port = htons(to->sin_port);
	}

	/* generate xid - increment */
	if (xid == 0)
		xid = (uint_t)(prom_gettime() / 1000) + 1;
	else
		xid++;

	/* set up outgoing pkt as xdr modified. */
	xdrmem_create(&xmit_xdrs, trm_msg, trm_len, XDR_ENCODE);

	/* setup rpc header */
	if (rpc_hdr(&xmit_xdrs, xid, prog, vers, proc) != TRUE) {
		dprintf("brpc_call: cannot setup rpc header.\n");
		rpc_error.re_status = RPC_FAILED;
		goto gt_error;
	}

	/* setup authentication */
	switch (auth) {
	case AUTH_NONE:
		xmit_auth = authnone_create();
		break;
	case AUTH_UNIX:
		/*
		 * Assumes we've configured the stack and thus know our
		 * IP address/hostname, either by using DHCP or rarp/bootparams.
		 */
		(void) gethostname(hostname, sizeof (hostname));
		xmit_auth = authunix_create(hostname, 0, 1, 1, &fake_gids);
		break;
	default:
		dprintf("brpc_call: Unsupported authentication type: %d\n",
		    auth);
		rpc_error.re_status = RPC_AUTHERROR;
		goto gt_error;
	/*NOTREACHED*/
	}

	/*
	 * rpc_hdr puts everything in the xmit buffer for the header
	 * EXCEPT the proc. Put it, and our authentication info into
	 * it now, serializing as we go. We will be at the place where
	 * we left off.
	 */
	xmit_xdrs.x_op = XDR_ENCODE;
	if ((XDR_PUTINT32(&xmit_xdrs, (int32_t *)&proc) == FALSE) ||
	    (AUTH_MARSHALL(xmit_auth, &xmit_xdrs, NULL) == FALSE) ||
	    ((*in_xdr)(&xmit_xdrs, args) == FALSE)) {
		rpc_error.re_status = RPC_CANTENCODEARGS;
		goto gt_error;
	} else
		xmit_len = (int)XDR_GETPOS(&xmit_xdrs); /* for sendto */

	/*
	 * Right now the outgoing packet should be all serialized and
	 * ready to go... Set up timers.
	 */

	xdelay = (rexmit == 0) ? RPC_REXMIT_MSEC : (rexmit * 1000);
	(void) setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (void *)&xdelay,
	    sizeof (xdelay));
	wait_time = (wait_time == 0) ? RPC_RCVWAIT_MSEC : (wait_time * 1000);

	wait_time += prom_gettime();

	/*
	 * send out the request. The first item in the receive buffer will
	 * be the xid. Check if it is correct.
	 */
	errors = 0;
	rpc_error.re_status = RPC_TIMEDOUT;
	do {
		if (sendto(s, trm_msg, xmit_len, flags, (struct sockaddr *)to,
		    sizeof (struct sockaddr_in)) < 0) {
			/*
			 * If errno is set to ETIMEDOUT, return
			 * with RPC status as RPC_TIMEDOUT. Calling
			 * funciton will take care of this error by
			 * retrying the RPC call.
			 */
			if (errno == ETIMEDOUT) {
				rpc_error.re_status = RPC_TIMEDOUT;
			} else {
				rpc_error.re_status = RPC_CANTSEND;
			}
			goto gt_error;
		}

		from_len = sizeof (struct sockaddr_in);
		while ((rcv_len = recvfrom(s, rcv_msg, NFSBUF_SIZE,
		    MSG_DONTWAIT, (struct sockaddr *)from_who,
		    &from_len)) > 0 || errors < RPC_ALLOWABLE_ERRORS) {
			if (rcv_len < 0) {
				if (errno == EWOULDBLOCK ||
				    errno == ETIMEDOUT) {
					break; /* timeout */
				}
				rpc_error.re_status = RPC_CANTRECV;
				goto gt_error;
			}
			if (ntohl(*((uint32_t *)(rcv_msg))) != xid) {
				dprintf("brpc_call: xid: 0x%x != 0x%x\n",
				    *(uint32_t *)(rcv_msg), xid);
				continue;
			}
			/*
			 * Let's deserialize the data into our 'ret' buffer.
			 */
			xdrmem_create(&rcv_xdrs, rcv_msg, rcv_len, XDR_DECODE);
			if (xdr_replymsg(&rcv_xdrs, &reply) == FALSE) {
				rpc_error.re_status = RPC_CANTDECODERES;
				goto gt_error;
			}
			_seterr_reply(&reply, &rpc_error);
			switch (rpc_error.re_status) {
			case RPC_SUCCESS:
				/*
				 * XXX - validate for unix and none
				 * always return true.
				 */
				if (AUTH_VALIDATE(xmit_auth,
				    &reply.acpted_rply.ar_verf) == FALSE) {
					rpc_error.re_status = RPC_AUTHERROR;
					rpc_error.re_why = AUTH_INVALIDRESP;
					errors++;
				}
				if (reply.acpted_rply.ar_verf.oa_base !=
				    0) {
					xmit_xdrs.x_op = XDR_FREE;
					(void) xdr_opaque_auth(
					    &xmit_xdrs,
					    &reply.acpted_rply.ar_verf);
				}
				break;

			case RPC_AUTHERROR:
				/*
				 * Let's see if our credentials need
				 * refreshing
				 */
				if (nrefreshes > 0 && AUTH_REFRESH(xmit_auth,
				    NULL, NULL)) {
					nrefreshes--;
				}
				errors++;
				break;

			case RPC_PROCUNAVAIL:
				/*
				 * Might be a silly portmapper implementation
				 * erroneously responding to our rpc broadcast
				 * indirect portmapper call. For this
				 * particular case, we don't increment the
				 * error counter because we want to keep
				 * sifting for successful replies...
				 */
				if (to->sin_addr.s_addr !=
				    ntohl(INADDR_BROADCAST))
					errors++;
				break;

			case RPC_PROGVERSMISMATCH:
				/*
				 * Successfully talked to server, but they
				 * don't speak our lingo.
				 */
				goto gt_error;

			default:
				/* Just keep trying till there's no data... */
				errors++;
				break;
			}

			if (rpc_error.re_status != RPC_SUCCESS) {
				dprintf("brpc_call: from: %s, error: ",
				    inet_ntoa(from_who->sin_addr));
				rpc_disperr(&rpc_error);
			} else
				break;
		}

		/*
		 * If we're having trouble reassembling datagrams, let the
		 * application know ASAP so that it can take the appropriate
		 * actions.
		 */

	} while (rpc_error.re_status != RPC_SUCCESS && errno != ETIMEDOUT &&
	    prom_gettime() < wait_time);

gt_error:
	if (xmit_auth != NULL)
		AUTH_DESTROY(xmit_auth);

	if (trm_msg != NULL)
		bkmem_free(trm_msg, trm_len);
	if (rcv_msg != NULL)
		bkmem_free(rcv_msg, NFSBUF_SIZE);

	if (rpc_error.re_status != RPC_SUCCESS)
		rpc_disperr(&rpc_error);

	/*
	 * socket calls reset errno. Since we want to hold onto the errno
	 * value if it is ETIMEDOUT to communicate to our caller that this
	 * RPC_TIMEDOUT situation is due to a stack problem (we're getting
	 * a reply, but the stack simply can't assemble it.), we need to
	 * preserve errno's value over the socket_close().
	 */
	preserve_errno = (errno == ETIMEDOUT) ? errno : 0;
	(void) socket_close(s);
	errno = preserve_errno;

	return (rpc_error.re_status);
}
