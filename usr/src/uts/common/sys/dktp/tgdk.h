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

#ifndef _SYS_DKTP_TGDK_H
#define	_SYS_DKTP_TGDK_H

#ifdef	__cplusplus
extern "C" {
#endif

struct	tgdk_ext {
	unsigned	tg_rmb	: 1;
	unsigned	tg_rdonly  : 1;
	unsigned	tg_flag    : 6;
	char		*tg_nodetype;
	char		tg_ctype;
};

struct	tgdk_obj {
	opaque_t		tg_data;
	struct tgdk_objops	*tg_ops;
	struct tgdk_ext		*tg_ext;
	struct tgdk_ext		tg_extblk;	/* extended blk defined	*/
						/* for easy of alloc	*/
};

struct	tgdk_iob {
	struct	buf *b_bp;
	daddr_t	b_lblk;
	ssize_t	b_xfer;
	daddr_t	b_psec;
	ssize_t	b_pbytecnt;
	short	b_pbyteoff;
	short	b_flag;
};
typedef struct tgdk_iob *tgdk_iob_handle;
#define	IOB_BPALLOC	0x0001
#define	IOB_BPBUFALLOC	0x0002

struct	tgdk_geom {
	int	g_cyl;
	int	g_acyl;
	int	g_head;
	int	g_sec;
	int	g_secsiz;
	diskaddr_t 	g_cap;
};

struct	tgdk_objops {
	int  (*tg_init)(opaque_t, opaque_t, opaque_t, opaque_t, opaque_t,
	    void *);
	int  (*tg_free)(struct tgdk_obj *);
	int  (*tg_probe)(opaque_t, int);
	int  (*tg_attach)(opaque_t);
	int  (*tg_open)(opaque_t, int);
	int  (*tg_close)(opaque_t);
	int  (*tg_ioctl)(opaque_t, dev_t, int, intptr_t, int, cred_t *, int *);
	int  (*tg_strategy)(opaque_t, struct buf *);
	int  (*tg_setgeom)(opaque_t, struct tgdk_geom *);
	int  (*tg_getgeom)(opaque_t, struct tgdk_geom *);
	tgdk_iob_handle	(*tg_iob_alloc)(opaque_t, daddr_t, ssize_t, int);
	int  (*tg_iob_free)(opaque_t, struct tgdk_iob *);
	caddr_t	(*tg_iob_htoc)(opaque_t, struct tgdk_iob *);
	caddr_t	(*tg_iob_xfer)(opaque_t, struct tgdk_iob *, int);
	int  (*tg_dump)(opaque_t, struct buf *);
	int  (*tg_getphygeom)(opaque_t, struct tgdk_geom *);
	int  (*tg_set_bbhobj)(opaque_t, opaque_t);
	int  (*tg_check_media)(opaque_t, int *);
	int  (*tg_inquiry)(opaque_t, opaque_t *);
	void (*tg_cleanup)(struct tgdk_obj *);
	void *tg_resv[1];
};

struct tgdk_obj *dadk_create();

#define	TGDK_GETNODETYPE(X) (((struct tgdk_obj *)(X))->tg_ext->tg_nodetype)
#define	TGDK_SETNODETYPE(X, Y) \
	(((struct tgdk_obj *)(X))->tg_ext->tg_nodetype = (char *)(Y))
#define	TGDK_RMB(X) 	(((struct tgdk_obj *)(X))->tg_ext->tg_rmb)
#define	TGDK_RDONLY(X) 	(((struct tgdk_obj *)(X))->tg_ext->tg_rdonly)
#define	TGDK_GETCTYPE(X) (((struct tgdk_obj *)(X))->tg_ext->tg_ctype)


#define	TGDK_INIT(X, devp, flcobjp, queobjp, bbhobjp, lkarg) \
	(*((struct tgdk_obj *)(X))->tg_ops->tg_init) \
		(((struct tgdk_obj *)(X))->tg_data, (devp), (flcobjp), \
		(queobjp), (bbhobjp), (lkarg))
#define	TGDK_INIT_X(X, devp, flcobjp, queobjp, bbhobjp, lkarg, cbfunc, cbarg) \
	(*((struct tgdk_obj *)(X))->tg_ops->tg_init) \
		(((struct tgdk_obj *)(X))->tg_data, (devp), (flcobjp), \
		(queobjp), (bbhobjp), (lkarg), (cbfunc), (cbarg))
#define	TGDK_FREE(X) (*((struct tgdk_obj *)(X))->tg_ops->tg_free) ((X))
#define	TGDK_PROBE(X, WAIT) (*((struct tgdk_obj *)(X))->tg_ops->tg_probe) \
	(((struct tgdk_obj *)(X))->tg_data, (WAIT))
#define	TGDK_ATTACH(X) (*((struct tgdk_obj *)(X))->tg_ops->tg_attach) \
	(((struct tgdk_obj *)(X))->tg_data)
#define	TGDK_OPEN(X, flag) (*((struct tgdk_obj *)(X))->tg_ops->tg_open) \
	(((struct tgdk_obj *)(X))->tg_data, (flag))
#define	TGDK_CLOSE(X) (*((struct tgdk_obj *)(X))->tg_ops->tg_close) \
	(((struct tgdk_obj *)(X))->tg_data)
#define	TGDK_IOCTL(X, dev, cmd, arg, flag, cred_p, rval_p) \
	(*((struct tgdk_obj *)(X))->tg_ops->tg_ioctl) \
	(((struct tgdk_obj *)(X))->tg_data, (dev), (cmd), (arg), (flag), \
		(cred_p), (rval_p))
#define	TGDK_STRATEGY(X, bp) (*((struct tgdk_obj *)(X))->tg_ops->tg_strategy) \
	(((struct tgdk_obj *)(X))->tg_data, (bp))
#define	TGDK_GETGEOM(X, datap) (*((struct tgdk_obj *)(X))->tg_ops->tg_getgeom) \
	(((struct tgdk_obj *)(X))->tg_data, (datap))
#define	TGDK_SETGEOM(X, datap) (*((struct tgdk_obj *)(X))->tg_ops->tg_setgeom) \
	(((struct tgdk_obj *)(X))->tg_data, (datap))
#define	TGDK_IOB_ALLOC(X, logblk, xfer, sleep) \
	(*((struct tgdk_obj *)(X))->tg_ops->tg_iob_alloc) \
	(((struct tgdk_obj *)(X))->tg_data, (logblk), (xfer), (sleep))
#define	TGDK_IOB_FREE(X, datap) \
	(*((struct tgdk_obj *)(X))->tg_ops->tg_iob_free) \
	(((struct tgdk_obj *)(X))->tg_data, (datap))
#define	TGDK_IOB_HTOC(X, handle) \
	(*((struct tgdk_obj *)(X))->tg_ops->tg_iob_htoc) \
	(((struct tgdk_obj *)(X))->tg_data, (handle))
#define	TGDK_IOB_RD(X, handle) \
	(*((struct tgdk_obj *)(X))->tg_ops->tg_iob_xfer) \
	(((struct tgdk_obj *)(X))->tg_data, (handle), B_READ)
#define	TGDK_IOB_WR(X, handle) \
	(*((struct tgdk_obj *)(X))->tg_ops->tg_iob_xfer) \
	(((struct tgdk_obj *)(X))->tg_data, (handle), B_WRITE)
#define	TGDK_DUMP(X, bp) (*((struct tgdk_obj *)(X))->tg_ops->tg_dump) \
	(((struct tgdk_obj *)(X))->tg_data, (bp))
#define	TGDK_GETPHYGEOM(X, datap) \
	(*((struct tgdk_obj *)(X))->tg_ops->tg_getphygeom) \
	(((struct tgdk_obj *)(X))->tg_data, (datap))
#define	TGDK_SET_BBHOBJ(X, objp) \
	(*((struct tgdk_obj *)(X))->tg_ops->tg_set_bbhobj) \
	(((struct tgdk_obj *)(X))->tg_data, (objp))
#define	TGDK_CHECK_MEDIA(X, state) \
	(*((struct tgdk_obj *)(X))->tg_ops->tg_check_media) \
	(((struct tgdk_obj *)(X))->tg_data, (state))
#define	TGDK_INQUIRY(X, inqpp) \
	(*((struct tgdk_obj *)(X))->tg_ops->tg_inquiry) \
	(((struct tgdk_obj *)(X))->tg_data, (inqpp))
#define	TGDK_CLEANUP(X) (*((struct tgdk_obj *)(X))->tg_ops->tg_cleanup) ((X))

#define	LBLK2SEC(BLK, SHF) (daddr_t)((BLK) >> (SHF))

#define	SETBPERR	bioerror

#define	DK_MAXRECSIZE	(256<<10)	/* maximum io record size 	*/

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_DKTP_TGDK_H */
