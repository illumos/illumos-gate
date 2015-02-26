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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
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

#ifndef	_VM_PVN_H
#define	_VM_PVN_H

#include <sys/buf.h>
#include <vm/seg.h>

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef	_KERNEL

/*
 * VM - paged vnode.
 *
 * The VM system manages memory as a cache of paged vnodes.
 * This file desribes the interfaces to common subroutines
 * used to help implement the VM/file system routines.
 */

struct page	*pvn_read_kluster(struct vnode *vp, u_offset_t off,
			struct seg *seg, caddr_t addr, u_offset_t *offp,
			size_t *lenp, u_offset_t vp_off, size_t vp_len,
			int isra);
struct page	*pvn_write_kluster(struct vnode *vp, struct page *pp,
			u_offset_t *offp, size_t *lenp, u_offset_t vp_off,
			size_t vp_len, int flags);
void		pvn_read_done(struct page *plist, int flags);
void		pvn_write_done(struct page *plist, int flags);
void		pvn_io_done(struct page *plist);
int		pvn_vplist_dirty(struct vnode *vp, u_offset_t off,
			int (*putapage)(vnode_t *, struct page *, u_offset_t *,
				size_t *, int, cred_t *),
			int flags, struct cred *cred);
void		pvn_vplist_setdirty(vnode_t *vp, int (*page_check)(page_t *));
int		pvn_getdirty(struct page *pp, int flags);
void		pvn_vpzero(struct vnode *vp, u_offset_t vplen, size_t zbytes);
int		pvn_getpages(
			int (*getpage)(vnode_t *, u_offset_t, size_t, uint_t *,
				struct page *[], size_t, struct seg *,
				caddr_t, enum seg_rw, cred_t *),
			struct vnode *vp, u_offset_t off, size_t len,
			uint_t *protp, struct page **pl, size_t plsz,
			struct seg *seg, caddr_t addr, enum seg_rw rw,
			struct cred *cred);
void		pvn_plist_init(struct page *pp, struct page **pl, size_t plsz,
			u_offset_t off, size_t io_len, enum seg_rw rw);
void		pvn_init(void);

/*
 * The value is put in p_hash to identify marker pages. It is safe to
 * test p_hash ==(!=) PVN_VPLIST_HASH_TAG even without holding p_selock.
 */
#define	PVN_VPLIST_HASH_TAG	((page_t *)-1)

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _VM_PVN_H */
