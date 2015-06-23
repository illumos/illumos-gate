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
 * Copyright 2014 Gary Mills
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

/*
 * Kernel TLI-like function to read a datagram off of a
 * transport endpoints stream head.
 *
 * Returns:
 * 	0	On success or positive error code.
 * 		On sucess, type is set to:
 * 	T_DATA		If normal data has been received
 * 	T_UDERR		If an error indication has been received,
 * 			in which case uderr contains the unitdata
 * 			error number.
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/file.h>
#include <sys/errno.h>
#include <sys/stream.h>
#include <sys/strsubr.h>
#include <sys/vnode.h>
#include <sys/ioctl.h>
#include <sys/stropts.h>
#include <sys/tihdr.h>
#include <sys/timod.h>
#include <sys/tiuser.h>
#include <sys/t_kuser.h>
#include <sys/sysmacros.h>
#include <sys/strsun.h>


int
t_krcvudata(TIUSER *tiptr, struct t_kunitdata *unitdata, int *type, int *uderr)
{
	int			len;
	size_t			hdrsz;
	union T_primitives	*pptr;
	struct file		*fp;
	mblk_t			*bp;
	mblk_t			*nbp;
	mblk_t			*mp;
	mblk_t			*tmp;
	int			error;
	int			flag;

	fp = tiptr->fp;

	if (type == NULL || uderr == NULL)
		return (EINVAL);

	error = 0;
	unitdata->udata.buf = NULL;

	if (unitdata->udata.udata_mp) {
		KTLILOG(2, "t_krcvudata: freeing existing message block\n", 0);
		freemsg(unitdata->udata.udata_mp);
		unitdata->udata.udata_mp = NULL;
	}

	/*
	 * XXX	Grabbing a mutex to do an atomic operation seems pointless
	 */
	mutex_enter(&fp->f_tlock);
	flag = fp->f_flag;
	mutex_exit(&fp->f_tlock);

	if ((error = tli_recv(tiptr, &bp, flag)) != 0)
		return (error);

	/*
	 * Got something
	 */
	switch (bp->b_datap->db_type) {
	case M_PROTO:
		/* LINTED pointer alignment */
		pptr = (union T_primitives *)bp->b_rptr;
		switch (pptr->type) {
		case T_UNITDATA_IND:
			KTLILOG(2, "t_krcvudata: Got T_UNITDATA_IND\n", 0);
			hdrsz = MBLKL(bp);

			/*
			 * check everything for consistency
			 */
			if (hdrsz < TUNITDATAINDSZ ||
			    hdrsz < (pptr->unitdata_ind.OPT_length +
			    pptr->unitdata_ind.OPT_offset) ||
			    hdrsz < (pptr->unitdata_ind.SRC_length +
			    pptr->unitdata_ind.SRC_offset)) {
				error = EPROTO;
				freemsg(bp);
				break;
			}

			/*
			 * okay, so now we copy them
			 */
			len = MIN(pptr->unitdata_ind.SRC_length,
			    unitdata->addr.maxlen);
			bcopy(bp->b_rptr + pptr->unitdata_ind.SRC_offset,
			    unitdata->addr.buf, len);
			unitdata->addr.len = len;

			len = MIN(pptr->unitdata_ind.OPT_length,
			    unitdata->opt.maxlen);
			bcopy(bp->b_rptr + pptr->unitdata_ind.OPT_offset,
			    unitdata->opt.buf, len);
			unitdata->opt.len = len;

			bp->b_rptr += hdrsz;

			/*
			 * we assume that the client knows how to deal
			 * with a set of linked mblks, so all we do is
			 * make a pass and remove any that are zero
			 * length.
			 */
			nbp = NULL;
			mp = bp;
			while (mp) {
				if (bp->b_wptr == bp->b_rptr) {
					KTLILOG(2,
					    "t_krcvudata: zero length block\n",
					    0);
					tmp = mp->b_cont;
					if (nbp)
						nbp->b_cont = tmp;
					else
						bp = tmp;

					freeb(mp);
					mp = tmp;
				} else {
					nbp = mp;
					mp = mp->b_cont;
				}
			}
#ifdef KTLIDEBUG
{
	mblk_t *tp;

	tp = bp;
	while (tp) {
		struct datab *dbp = tp->b_datap;
		frtn_t *frp = dbp->db_frtnp;

		KTLILOG(2, "t_krcvudata: bp %x, ", tp);
		KTLILOG(2, "db_size %x, ", dbp->db_lim - dbp->db_base);
		KTLILOG(2, "db_ref %x", dbp->db_ref);

		if (frp != NULL)
			KTLILOG(2, ", func: %x", frp->free_func);
			KTLILOG(2, ", arg %x\n", frp->free_arg);
		} else
			KTLILOG(2, "\n", 0);
		tp = tp->b_cont;
	}
}
#endif /* KTLIDEBUG */
			/*
			 * now just point the users mblk
			 * pointer to what we received.
			 */
			if (bp == NULL) {
				KTLILOG(2, "t_krcvudata: No data\n", 0);
				error = EPROTO;
				break;
			}
			if (bp->b_wptr != bp->b_rptr) {
			    if (!IS_P2ALIGNED(bp->b_rptr, sizeof (uint32_t)))
					if (!pullupmsg(bp, MBLKL(bp))) {
						KTLILOG(1,
					"t_krcvudata:  pullupmsg failed\n", 0);
						error = EIO;
						freemsg(bp);
						break;
					}
				unitdata->udata.buf = (char *)bp->b_rptr;
				unitdata->udata.len = (uint_t)MBLKL(bp);

				KTLILOG(2, "t_krcvudata: got %d bytes\n",
				    unitdata->udata.len);
				unitdata->udata.udata_mp = bp;
			} else {
				KTLILOG(2,
				    "t_krcvudata: 0 length data message\n", 0);
				freemsg(bp);
				unitdata->udata.len = 0;
			}
			*type = T_DATA;
			break;

		case T_UDERROR_IND:
			KTLILOG(2, "t_krcvudata: Got T_UDERROR_IND\n", 0);
			hdrsz = MBLKL(bp);

			/*
			 * check everything for consistency
			 */
			if (hdrsz < TUDERRORINDSZ ||
			    hdrsz < (pptr->uderror_ind.OPT_length +
			    pptr->uderror_ind.OPT_offset) ||
			    hdrsz < (pptr->uderror_ind.DEST_length +
			    pptr->uderror_ind.DEST_offset)) {
				error = EPROTO;
				freemsg(bp);
				break;
			}

			if (pptr->uderror_ind.DEST_length >
			    (int)unitdata->addr.maxlen ||
			    pptr->uderror_ind.OPT_length >
			    (int)unitdata->opt.maxlen) {
				error = EMSGSIZE;
				freemsg(bp);
				break;
			}

			/*
			 * okay, so now we copy them
			 */
			bcopy(bp->b_rptr + pptr->uderror_ind.DEST_offset,
			    unitdata->addr.buf,
			    (size_t)pptr->uderror_ind.DEST_length);
			unitdata->addr.len = pptr->uderror_ind.DEST_length;

			bcopy(bp->b_rptr + pptr->uderror_ind.OPT_offset,
			    unitdata->opt.buf,
			    (size_t)pptr->uderror_ind.OPT_length);
			unitdata->opt.len = pptr->uderror_ind.OPT_length;

			*uderr = pptr->uderror_ind.ERROR_type;

			unitdata->udata.buf = NULL;
			unitdata->udata.udata_mp = NULL;
			unitdata->udata.len = 0;

			freemsg(bp);

			*type = T_UDERR;
			break;

		default:
			KTLILOG(1,
			    "t_krcvudata: Unknown transport primitive %d\n",
			    pptr->type);
			error = EPROTO;
			freemsg(bp);
			break;
		}
		break;

	case M_FLUSH:
		KTLILOG(1, "t_krcvudata: tli_recv returned M_FLUSH\n", 0);
		freemsg(bp);
		error = EBADMSG;
		break;

	default:
		KTLILOG(1, "t_krcvudata: unknown message type %x\n",
		    bp->b_datap->db_type);
		freemsg(bp);
		error = EBADMSG;
		break;
	}

	return (error);
}
