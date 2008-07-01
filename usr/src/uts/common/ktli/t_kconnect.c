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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Kernel TLI-like function to allow a trasnport endpoint to initiate a
 * connection to another transport endpoint.  This function will wait for
 * an ack and a T_CONN_CON before returning.
 *
 * Returns:
 * 	0 on success, and if rcvcall is non-NULL it shall be
 * 	filled with the connection confirm data.
 * 	Otherwise a positive error code.
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/file.h>
#include <sys/vnode.h>
#include <sys/errno.h>
#include <sys/stream.h>
#include <sys/ioctl.h>
#include <sys/stropts.h>
#include <sys/tihdr.h>
#include <sys/timod.h>
#include <sys/tiuser.h>
#include <sys/t_kuser.h>
#include <sys/strsubr.h>
#include <sys/sysmacros.h>
#include <sys/strsun.h>


int
t_kconnect(TIUSER *tiptr, struct t_call *sndcall, struct t_call *rcvcall)
{
	int			len;
	int			msgsz;
	size_t			hdrsz;
	struct T_conn_req	*creq;
	union T_primitives	*pptr;
	mblk_t			*nbp;
	file_t			*fp;
	mblk_t			*bp;
	int			error;
	int			flag;

	error = 0;

	fp = tiptr->fp;
	msgsz = (int)TCONNREQSZ;
	while (!(bp = allocb(msgsz + sndcall->addr.len + sndcall->opt.len,
	    BPRI_LO))) {
		if (strwaitbuf(msgsz + sndcall->addr.len + sndcall->opt.len,
		    BPRI_LO))
			return (ENOSR);
	}

	/* LINTED pointer alignment */
	creq = (struct T_conn_req *)bp->b_wptr;
	creq->PRIM_type = T_CONN_REQ;
	creq->DEST_length = (t_scalar_t)sndcall->addr.len;
	creq->OPT_length = (t_scalar_t)sndcall->opt.len;

	if (sndcall->addr.len) {
		bcopy(sndcall->addr.buf, (bp->b_wptr+msgsz), sndcall->addr.len);
		creq->DEST_offset = (t_scalar_t)msgsz;
		msgsz += sndcall->addr.len;
	} else
		creq->DEST_offset = (t_scalar_t)0;

	if (sndcall->opt.len) {
		bcopy(sndcall->opt.buf, (bp->b_wptr+msgsz), sndcall->opt.len);
		creq->OPT_offset = (t_scalar_t)msgsz;
		msgsz += sndcall->opt.len;
	} else
		creq->OPT_offset = (t_scalar_t)0;

	bp->b_datap->db_type = M_PROTO;
	bp->b_wptr += msgsz;

	/*
	 * copy the users data, if any.
	 */
	if (sndcall->udata.len) {
		/*
		 * if CO then we would allocate a data block and
		 * put the users connect data into it.
		 */
		KTLILOG(1,
		    "Attempt to send connectionless data on T_CONN_REQ\n", 0);
		freemsg(bp);
		return (EPROTO);
	}

	flag = fp->f_flag;

	/*
	 * send it
	 */
	if ((error = tli_send(tiptr, bp, flag)) != 0)
		return (error);

	/*
	 * wait for acknowledgment
	 */
	if ((error = get_ok_ack(tiptr, T_CONN_REQ, flag)) != 0)
		return (error);

	bp = NULL;
	/*
	 * wait for CONfirm
	 */
	if ((error = tli_recv(tiptr, &bp, flag)) != 0)
		return (error);

	if (bp->b_datap->db_type != M_PROTO) {
		freemsg(bp);
		return (EPROTO);
	}

	/* LINTED pointer alignment */
	pptr = (union T_primitives *)bp->b_rptr;
	switch (pptr->type) {
	case T_CONN_CON:
		hdrsz = MBLKL(bp);

		/*
		 * check everything for consistency
		 */
		if (hdrsz < TCONNCONSZ ||
		    hdrsz < (pptr->conn_con.OPT_length +
		    pptr->conn_con.OPT_offset) ||
		    hdrsz < (pptr->conn_con.RES_length +
		    pptr->conn_con.RES_offset)) {
			error = EPROTO;
			freemsg(bp);
			break;
		}

		if (rcvcall != NULL) {
			/*
			 * okay, so now we copy them
			 */
			len = MIN(pptr->conn_con.RES_length,
			    rcvcall->addr.maxlen);
			bcopy(bp->b_rptr + pptr->conn_con.RES_offset,
			    rcvcall->addr.buf, len);
			rcvcall->addr.len = len;

			len = MIN(pptr->conn_con.OPT_length,
			    rcvcall->opt.maxlen);
			bcopy(bp->b_rptr + pptr->conn_con.OPT_offset,
			    rcvcall->opt.buf, len);
			rcvcall->opt.len = len;

			if (bp->b_cont) {
				nbp = bp;
				bp = bp->b_cont;
				msgsz = (int)MBLKL(bp);
				len = MIN(msgsz, rcvcall->udata.maxlen);
				bcopy(bp->b_rptr, rcvcall->udata.buf, len);
				rcvcall->udata.len = len;
				freemsg(nbp);
			}
		} else {
			freemsg(bp);
		}
		break;

	default:
		error = EPROTO;
		freemsg(bp);
		break;
	}
	return (error);
}
