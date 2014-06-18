/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2014 Gary Mills
 * Copyright 2001 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */

/*
 * Miscellaneous support routines for kernel implentation of AUTH_DES
 */

/*
 *  rtime - get time from remote machine
 *
 *  sets time, obtaining value from host
 *  on the udp/time socket.  Since timeserver returns
 *  with time of day in seconds since Jan 1, 1900,  must
 *  subtract 86400(365*70 + 17) to get time
 *  since Jan 1, 1970, which is what get/settimeofday
 *  uses.
 */
#include <sys/param.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/systm.h>
#include <sys/errno.h>
#include <sys/proc.h>
#include <sys/user.h>
#include <sys/socket.h>
#include <sys/sysmacros.h>
#include <netinet/in.h>
#include <rpc/rpc.h>
#include <sys/stream.h>
#include <sys/strsubr.h>
#include <sys/cred.h>
#include <sys/utsname.h>
#include <sys/vnode.h>
#include <sys/file.h>
#include <sys/uio.h>
#include <sys/systeminfo.h>
#include <rpc/rpcb_prot.h>
#include <sys/cmn_err.h>

#define	TOFFSET ((uint32_t)86400 * (365 * 70 + (70 / 4)))
#define	WRITTEN ((uint32_t)86400 * (365 * 86 + (86 / 4)))

#define	NC_INET	"inet"		/* XXX */

int
rtime(struct knetconfig *synconfig, struct netbuf *addrp, int calltype,
	struct timeval *timep, struct timeval *wait)
{
	int			error;
	int			timo;
	time_t			thetime;
	int32_t			srvtime;
	uint32_t		dummy;
	struct t_kunitdata	*unitdata;
	struct t_call		*server;
	TIUSER			*tiptr;
	int			type;
	int			uderr;
	int			i;
	int			retries;
	mblk_t			*mp;
	mblk_t			*mp2;

	retries = 5;
	if (calltype == 0) {
again:
		RPCLOG0(8, "rtime: using old method\n");
		if ((error = t_kopen(NULL, synconfig->knc_rdev,
		    FREAD|FWRITE, &tiptr, CRED())) != 0) {
			RPCLOG(1, "rtime: t_kopen %d\n", error);
			return (-1);
		}

		if ((error = t_kbind(tiptr, NULL, NULL)) != 0) {
			(void) t_kclose(tiptr, 1);
			RPCLOG(1, "rtime: t_kbind %d\n", error);
			return (-1);
		}

		if (synconfig->knc_semantics == NC_TPI_CLTS) {
			if ((error = t_kalloc(tiptr, T_UNITDATA,
			    T_UDATA|T_ADDR, (char **)&unitdata)) != 0) {
				RPCLOG(1, "rtime: t_kalloc %d\n", error);
				(void) t_kclose(tiptr, 1);
				return (-1);
			}

			unitdata->addr.len = addrp->len;
			bcopy(addrp->buf, unitdata->addr.buf,
			    unitdata->addr.len);

			dummy = 0;
			unitdata->udata.buf = (caddr_t)&dummy;
			unitdata->udata.len = sizeof (dummy);

			if ((error = t_ksndudata(tiptr, unitdata, NULL)) !=
			    0) {
				RPCLOG(1, "rtime: t_ksndudata %d\n", error);
				(void) t_kfree(tiptr, (char *)unitdata,
				    T_UNITDATA);
				(void) t_kclose(tiptr, 1);
				return (-1);
			}

			timo = TIMEVAL_TO_TICK(wait);

			RPCLOG(8, "rtime: timo %x\n", timo);
			if ((error = t_kspoll(tiptr, timo, READWAIT,
			    &type)) != 0) {
				RPCLOG(1, "rtime: t_kspoll %d\n", error);
				(void) t_kfree(tiptr, (char *)unitdata,
				    T_UNITDATA);
				(void) t_kclose(tiptr, 1);
				return (-1);
			}

			if (type == 0) {
				RPCLOG0(1, "rtime: t_kspoll timed out\n");
				(void) t_kfree(tiptr, (char *)unitdata,
				    T_UNITDATA);
				(void) t_kclose(tiptr, 1);
				return (-1);
			}

			error = t_krcvudata(tiptr, unitdata, &type, &uderr);
			if (error != 0) {
				RPCLOG(1, "rtime: t_krcvudata %d\n", error);
				(void) t_kfree(tiptr, (char *)unitdata,
				    T_UNITDATA);
				(void) t_kclose(tiptr, 1);
				if (error == EBADMSG && retries-- > 0)
					goto again;
				return (-1);
			}

			if (type == T_UDERR) {
				if (bcmp(addrp->buf, unitdata->addr.buf,
				    unitdata->addr.len) != 0) {
				/*
				 * Response comes from some other
				 * destination:
				 * ignore it since it's not related to the
				 * request we just sent out.
				 */
					(void) t_kfree(tiptr, (char *)unitdata,
					    T_UNITDATA);
					(void) t_kclose(tiptr, 1);
					goto again;
				}
			}

			if (type != T_DATA) {
				RPCLOG(1,
				    "rtime: t_krcvudata returned type %d\n",
				    type);
				(void) t_kfree(tiptr, (char *)unitdata,
				    T_UNITDATA);
				(void) t_kclose(tiptr, 1);
				if (retries-- == 0)
					return (-1);
				goto again;
			}

			if (unitdata->udata.len < sizeof (uint32_t)) {
				RPCLOG(1, "rtime: bad rcvd length %d\n",
				    unitdata->udata.len);
				(void) t_kfree(tiptr, (char *)unitdata,
				    T_UNITDATA);
				(void) t_kclose(tiptr, 1);
				if (retries-- == 0)
					return (-1);
				goto again;
			}

			thetime = (time_t)ntohl(
			    /* LINTED pointer alignment */
			    *(uint32_t *)unitdata->udata.buf);
			(void) t_kfree(tiptr, (char *)unitdata, T_UNITDATA);

		} else {

			if ((error = t_kalloc(tiptr, T_CALL, T_ADDR,
			    (char **)&server)) != 0) {
				RPCLOG(1, "rtime: t_kalloc %d\n", error);
				(void) t_kclose(tiptr, 1);
				return (-1);
			}

			server->addr.len = addrp->len;
			bcopy(addrp->buf, server->addr.buf, server->addr.len);

			if ((error = t_kconnect(tiptr, server, NULL)) != 0) {
				RPCLOG(1, "rtime: t_kconnect %d\n", error);
				(void) t_kfree(tiptr, (char *)server, T_CALL);
				(void) t_kclose(tiptr, 1);
				return (-1);
			}
			(void) t_kfree(tiptr, (char *)server, T_CALL);

			timo = TIMEVAL_TO_TICK(wait);

			RPCLOG(8, "rtime: timo %x\n", timo);

			i = 0;
			dummy = 0;

			/* now read up to 4 bytes from the TIME server */
			while (i < sizeof (dummy)) {

				error = t_kspoll(tiptr, timo, READWAIT, &type);
				if (error != 0) {
					RPCLOG(1, "rtime: t_kspoll %d\n",
					    error);
					(void) t_kclose(tiptr, 1);
					return (-1);
				}

				if (type == 0) {
					RPCLOG0(1,
					    "rtime: t_kspoll timed out\n");
					(void) t_kclose(tiptr, 1);
					return (-1);
				}

				error = tli_recv(tiptr, &mp,
				    tiptr->fp->f_flag);
				if (error != 0) {
					RPCLOG(1, "rtime: tli_recv %d\n",
					    error);
					(void) t_kclose(tiptr, 1);
					return (-1);
				}

				if (mp->b_datap->db_type != M_DATA) {
					RPCLOG(1, "rtime: wrong msg type %d\n",
					    mp->b_datap->db_type);
					RPCLOG(1,
					    "rtime: wrong msg type: read %d"
					    " bytes\n", i);
					(void) t_kclose(tiptr, 1);
					freemsg(mp);
					return (-1);
				}

				mp2 = mp;

				/*
				 * The outer loop iterates until we reach the
				 * end of the mblk chain.
				 */
				while (mp2 != NULL) {

					/*
					 * The inner loop iterates until
					 * we've gotten 4 bytes or until
					 * the mblk is exhausted.
					 */
					while (i < sizeof (dummy) &&
					    mp2->b_rptr < mp2->b_wptr) {

						i++;

					/*
					 * We avoid big-endian/little-endian
					 * issues by serializing the result
					 * one byte at a time.
					 */
						dummy <<= 8;
						dummy += ((*mp2->b_rptr) &
						    0xFF);

						mp2->b_rptr++;
					}

					mp2 = mp2->b_cont;
				}

			freemsg(mp);
			}

			thetime = (time_t)dummy;
		}

		(void) t_kclose(tiptr, 1);

	} else {
		CLIENT			*client;
		struct timeval		timout;

		RPCLOG0(8, "rtime: using new method\n");

new_again:
		/*
		 *	We talk to rpcbind.
		 */
		error = clnt_tli_kcreate(synconfig, addrp, (rpcprog_t)RPCBPROG,
		    (rpcvers_t)RPCBVERS, 0, retries, CRED(), &client);

		if (error != 0) {
			RPCLOG(1,
			    "rtime: clnt_tli_kcreate returned %d\n", error);
			return (-1);
		}
		timout.tv_sec = 60;
		timout.tv_usec = 0;
		error = clnt_call(client, RPCBPROC_GETTIME, (xdrproc_t)xdr_void,
		    NULL, (xdrproc_t)xdr_u_int,
		    (caddr_t)&srvtime, timout);
		thetime = srvtime;
		auth_destroy(client->cl_auth);
		clnt_destroy(client);
		if (error == RPC_UDERROR) {
			if (retries-- > 0)
				goto new_again;
		}
		if (error != RPC_SUCCESS) {
			RPCLOG(1, "rtime: time sync clnt_call returned %d\n",
			    error);
			error = EIO;
			return (-1);
		}
	}

	if (calltype != 0)
		thetime += TOFFSET;

	RPCLOG(8, "rtime: thetime = %lx\n", thetime);

	if (thetime < WRITTEN) {
		RPCLOG(1, "rtime: time returned is too far in past %lx",
		    thetime);
		RPCLOG(1, "rtime: WRITTEN %x", WRITTEN);
		return (-1);
	}
	thetime -= TOFFSET;

	timep->tv_sec = thetime;
	RPCLOG(8, "rtime: timep->tv_sec = %lx\n", timep->tv_sec);
	RPCLOG(8, "rtime: machine time  = %lx\n", gethrestime_sec());
	timep->tv_usec = 0;
	RPCLOG0(8, "rtime: returning success\n");
	return (0);
}

/*
 * What is my network name?
 * WARNING: this gets the network name in sun unix format.
 * Other operating systems (non-unix) are free to put something else
 * here.
 *
 * Return 0 on success
 * Return RPC errors (non-zero values) if failed.
 */
enum clnt_stat
kgetnetname(char *netname)
{
	return (key_getnetname(netname, CRED()));
}
