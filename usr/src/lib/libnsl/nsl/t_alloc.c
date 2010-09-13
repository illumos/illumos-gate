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

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include "mt.h"
#include <stdlib.h>
#include <unistd.h>
#include <stropts.h>
#include <sys/stream.h>
#define	_SUN_TPI_VERSION 2
#include <sys/tihdr.h>
#include <sys/timod.h>
#include <xti.h>
#include <stdio.h>
#include <errno.h>
#include <ucred.h>
#include <signal.h>
#include "tx.h"

/*
 * Function protoypes
 */
static int _alloc_buf(struct netbuf *buf, t_scalar_t n, int fields,
    int api_semantics, boolean_t option);

char *
_tx_alloc(int fd, int struct_type, int fields, int api_semantics)
{
	struct strioctl strioc;
	struct T_info_ack info;
	union structptrs {
		char	*caddr;
		struct t_bind *bind;
		struct t_call *call;
		struct t_discon *dis;
		struct t_optmgmt *opt;
		struct t_unitdata *udata;
		struct t_uderr *uderr;
		struct t_info *info;
	} p;
	unsigned int dsize;
	struct _ti_user *tiptr;
	int retval, sv_errno;
	t_scalar_t optsize;

	if ((tiptr = _t_checkfd(fd, 0, api_semantics)) == NULL)
		return (NULL);
	sig_mutex_lock(&tiptr->ti_lock);

	/*
	 * Get size info for T_ADDR, T_OPT, and T_UDATA fields
	 */
	info.PRIM_type = T_INFO_REQ;
	strioc.ic_cmd = TI_GETINFO;
	strioc.ic_timout = -1;
	strioc.ic_len = (int)sizeof (struct T_info_req);
	strioc.ic_dp = (char *)&info;
	do {
		retval = ioctl(fd, I_STR, &strioc);
	} while (retval < 0 && errno == EINTR);

	if (retval < 0) {
		sv_errno = errno;
		sig_mutex_unlock(&tiptr->ti_lock);
		t_errno = TSYSERR;
		errno = sv_errno;
		return (NULL);
	}

	if (strioc.ic_len != (int)sizeof (struct T_info_ack)) {
		t_errno = TSYSERR;
		sig_mutex_unlock(&tiptr->ti_lock);
		errno = EIO;
		return (NULL);
	}


	/*
	 * Malloc appropriate structure and the specified
	 * fields within each structure.  Initialize the
	 * 'buf' and 'maxlen' fields of each.
	 */
	switch (struct_type) {

	case T_BIND:
		if ((p.bind = calloc(1, sizeof (struct t_bind))) == NULL)
			goto errout;
		if (fields & T_ADDR) {
			if (_alloc_buf(&p.bind->addr,
			    info.ADDR_size,
			    fields, api_semantics, B_FALSE) < 0)
				goto errout;
		}
		sig_mutex_unlock(&tiptr->ti_lock);
		return ((char *)p.bind);

	case T_CALL:
		if ((p.call = calloc(1, sizeof (struct t_call))) == NULL)
			goto errout;
		if (fields & T_ADDR) {
			if (_alloc_buf(&p.call->addr,
			    info.ADDR_size,
			    fields, api_semantics, B_FALSE) < 0)
				goto errout;
		}
		if (fields & T_OPT) {
			if (info.OPT_size >= 0 && _T_IS_XTI(api_semantics))
				/* compensate for XTI level options */
				optsize = info.OPT_size +
				    TX_XTI_LEVEL_MAX_OPTBUF;
			else
				optsize = info.OPT_size;
			if (_alloc_buf(&p.call->opt, optsize,
			    fields, api_semantics, B_TRUE) < 0)
				goto errout;
		}
		if (fields & T_UDATA) {
			dsize = _T_MAX((int)info.CDATA_size,
			    (int)info.DDATA_size);
			if (_alloc_buf(&p.call->udata, (t_scalar_t)dsize,
			    fields, api_semantics, B_FALSE) < 0)
				goto errout;
		}
		sig_mutex_unlock(&tiptr->ti_lock);
		return ((char *)p.call);

	case T_OPTMGMT:
		if ((p.opt = calloc(1, sizeof (struct t_optmgmt))) == NULL)
			goto errout;
		if (fields & T_OPT) {
			if (info.OPT_size >= 0 && _T_IS_XTI(api_semantics))
				/* compensate for XTI level options */
				optsize = info.OPT_size +
				    TX_XTI_LEVEL_MAX_OPTBUF;
			else
				optsize = info.OPT_size;
			if (_alloc_buf(&p.opt->opt, optsize,
			    fields, api_semantics, B_TRUE) < 0)
				goto errout;
		}
		sig_mutex_unlock(&tiptr->ti_lock);
		return ((char *)p.opt);

	case T_DIS:
		if ((p.dis = calloc(1, sizeof (struct t_discon))) == NULL)
			goto errout;
		if (fields & T_UDATA) {
			if (_alloc_buf(&p.dis->udata, info.DDATA_size,
			    fields, api_semantics, B_FALSE) < 0)
				goto errout;
		}
		sig_mutex_unlock(&tiptr->ti_lock);
		return ((char *)p.dis);

	case T_UNITDATA:
		if ((p.udata = calloc(1, sizeof (struct t_unitdata))) == NULL)
			goto errout;
		if (fields & T_ADDR) {
			if (_alloc_buf(&p.udata->addr, info.ADDR_size,
			    fields, api_semantics, B_FALSE) < 0)
				goto errout;
		}
		if (fields & T_OPT) {
			if (info.OPT_size >= 0 && _T_IS_XTI(api_semantics))
				/* compensate for XTI level options */
				optsize = info.OPT_size +
				    TX_XTI_LEVEL_MAX_OPTBUF;
			else
				optsize = info.OPT_size;
			if (_alloc_buf(&p.udata->opt, optsize,
			    fields, api_semantics, B_TRUE) < 0)
				goto errout;
		}
		if (fields & T_UDATA) {
			if (_alloc_buf(&p.udata->udata, info.TSDU_size,
			    fields, api_semantics, B_FALSE) < 0)
				goto errout;
		}
		sig_mutex_unlock(&tiptr->ti_lock);
		return ((char *)p.udata);

	case T_UDERROR:
		if ((p.uderr = calloc(1, sizeof (struct t_uderr))) == NULL)
			goto errout;
		if (fields & T_ADDR) {
			if (_alloc_buf(&p.uderr->addr, info.ADDR_size,
			    fields, api_semantics, B_FALSE) < 0)
				goto errout;
		}
		if (fields & T_OPT) {
			if (info.OPT_size >= 0 && _T_IS_XTI(api_semantics))
				/* compensate for XTI level options */
				optsize = info.OPT_size +
				    TX_XTI_LEVEL_MAX_OPTBUF;
			else
				optsize = info.OPT_size;
			if (_alloc_buf(&p.uderr->opt, optsize,
			    fields, api_semantics, B_FALSE) < 0)
				goto errout;
		}
		sig_mutex_unlock(&tiptr->ti_lock);
		return ((char *)p.uderr);

	case T_INFO:
		if ((p.info = calloc(1, sizeof (struct t_info))) == NULL)
			goto errout;
		sig_mutex_unlock(&tiptr->ti_lock);
		return ((char *)p.info);

	default:
		if (_T_IS_XTI(api_semantics)) {
			t_errno = TNOSTRUCTYPE;
			sig_mutex_unlock(&tiptr->ti_lock);
		} else {	/* TX_TLI_API */
			t_errno = TSYSERR;
			sig_mutex_unlock(&tiptr->ti_lock);
			errno = EINVAL;
		}
		return (NULL);
	}

	/*
	 * Clean up. Set t_errno to TSYSERR.
	 * If it is because memory could not be allocated
	 * then errno already should have been set to
	 * ENOMEM
	 */
errout:
	if (p.caddr)
		(void) t_free(p.caddr, struct_type);

	t_errno = TSYSERR;
	sig_mutex_unlock(&tiptr->ti_lock);
	return (NULL);
}

static int
_alloc_buf(struct netbuf *buf, t_scalar_t n, int fields, int api_semantics,
    boolean_t option)
{
	switch (n) {
	case T_INFINITE /* -1 */:
		if (_T_IS_XTI(api_semantics)) {
			buf->buf = NULL;
			buf->maxlen = 0;
			if (fields != T_ALL) {
				/*
				 * Do not return error
				 * if T_ALL is used.
				 */
				errno = EINVAL;
				return (-1);
			}
		} else if (option) { /* TX_TLI_API */
			static size_t infalloc;

			/*
			 * retain TLI behavior; ucred_t can vary in size,
			 * we need to make sure that we can receive one.
			 */
			if (infalloc == 0) {
				size_t uc = ucred_size();
				if (uc < 1024/2)
					infalloc = 1024;
				else
					infalloc = uc + 1024/2;
			}
			if ((buf->buf = calloc(1, infalloc)) == NULL) {
				errno = ENOMEM;
				return (-1);
			} else
				buf->maxlen = infalloc;
		} else {	/* TX_TLI_API */
			/*
			 * retain TLI behavior
			 */
			if ((buf->buf = calloc(1, 1024)) == NULL) {
				errno = ENOMEM;
				return (-1);
			} else
				buf->maxlen = 1024;
		}
		break;

	case 0:
		buf->buf = NULL;
		buf->maxlen = 0;
		break;

	case T_INVALID /* -2 */:
		if (_T_IS_XTI(api_semantics)) {
			buf->buf = NULL;
			buf->maxlen = 0;
			if (fields != T_ALL) {
				/*
				 * Do not return error
				 * if T_ALL is used.
				 */
				errno = EINVAL;
				return (-1);
			}
		} else {	/* TX_TLI_API */
			/*
			 * retain TLI behavior
			 */
			buf->buf = NULL;
			buf->maxlen = 0;
		}
		break;

	default:
		if ((buf->buf = calloc(1, (size_t)n)) == NULL) {
			errno = ENOMEM;
			return (-1);
		} else
			buf->maxlen = n;
		break;
	}
	return (0);
}
