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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_DKTP_BBH_H
#define	_SYS_DKTP_BBH_H

#include <sys/scsi/scsi_types.h>

#ifdef	__cplusplus
extern "C" {
#endif

struct	bbh_cookie {
	lldaddr_t	_ck_sector;	/* sector # on device (union) 	*/
	long		ck_seclen;	/* number of contiguous sec	*/
};
#define	ck_lsector	_ck_sector._f
#define	ck_sector	_ck_sector._p._l
typedef	struct  bbh_cookie *bbh_cookie_t;

struct	bbh_handle {
	int	h_totck;
	int	h_idx;
	struct	bbh_cookie *h_cktab;
};

struct	bbh_obj {
	opaque_t		bbh_data;
	struct bbh_objops	*bbh_ops;
};

struct	bbh_objops {
	int		(*bbh_init)(opaque_t);
	int		(*bbh_free)(struct bbh_obj *);
	opaque_t 	(*bbh_gethandle)(opaque_t, struct buf *);
	bbh_cookie_t	(*bbh_htoc)(opaque_t, opaque_t);
	void 		(*bbh_freehandle)(opaque_t, opaque_t);
	void 		*bbh_resv[2];
};

#define	BBH_GETCK_SECTOR(X, ckp) ((ckp)->ck_sector)
#define	BBH_GETCK_SECLEN(X, ckp) ((ckp)->ck_seclen)

#define	BBH_INIT(X) (*((struct bbh_obj *)(X))->bbh_ops->bbh_init)\
	(((struct bbh_obj *)(X))->bbh_data)
#define	BBH_FREE(X) (*((struct bbh_obj *)(X))->bbh_ops->bbh_free) ((X))
#define	BBH_GETHANDLE(X, bp) (*((struct bbh_obj *)(X))->bbh_ops->bbh_gethandle)\
	(((struct bbh_obj *)(X))->bbh_data, (bp))
#define	BBH_HTOC(X, handle) (*((struct bbh_obj *)(X))->bbh_ops->bbh_htoc) \
	(((struct bbh_obj *)(X))->bbh_data, (handle))
#define	BBH_FREEHANDLE(X, handle) \
	(*((struct bbh_obj *)(X))->bbh_ops->bbh_freehandle) \
	(((struct bbh_obj *)(X))->bbh_data, (handle))

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_DKTP_BBH_H */
