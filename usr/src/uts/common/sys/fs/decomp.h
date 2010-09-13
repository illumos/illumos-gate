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

#ifndef	_SYS_DECOMP_H
#define	_SYS_DECOMP_H

#ifdef	__cplusplus
extern "C" {
#endif

#define	CH_MAGIC_ZLIB	0x5a636d70	/* ZLIB compression */
#define	CH_MAGIC_GZIP	0x8B1F		/* GZIP compression */

#define	CH_VERSION	1

#define	CH_ALG_ZLIB	1

struct comphdr {
	uint64_t	ch_magic;
	uint64_t	ch_version;
	uint64_t	ch_algorithm;
	uint64_t	ch_fsize;
	uint64_t	ch_blksize;
	uint64_t	ch_blkmap[1];
};

#define	ZMAXBUF(n)	((n) + ((n) / 1000) + 12)

#ifdef	_KERNEL

struct dcnode {
	struct vnode	*dc_vp;
	struct vnode	*dc_subvp;
	struct kmem_cache *dc_bufcache;
	kmutex_t	dc_lock;
	struct dcnode	*dc_hash;
	struct dcnode	*dc_lrunext;
	struct dcnode	*dc_lruprev;
	struct comphdr	*dc_hdr;
	size_t		dc_hdrsize;
	size_t		dc_zmax;
	int		dc_mapcnt;
};

#define	VTODC(vp)	((struct dcnode *)(vp)->v_data)
#define	DCTOV(dp)	((dp)->dc_vp)

struct vnode	*decompvp(struct vnode *, struct cred *, caller_context_t *);

#endif

#ifdef	__cplusplus
}
#endif
#endif	/* _SYS_DECOMP_H */
