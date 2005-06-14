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
 * Copyright (c) 1996-1998 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _SYS_FS_CACHEFS_FILEGRP_H
#define	_SYS_FS_CACHEFS_FILEGRP_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

struct cachefs_metadata;

/*
 * filegrp structure represents a group of front files.
 */
struct filegrp {
	uint_t			 fg_flags;	/* CFS_FS_* flags */
	int			 fg_count;	/* cnodes in group */
	cfs_cid_t		 fg_id;		/* starting id in group */
	struct fscache		*fg_fscp;	/* back ptr to fscache */

	struct cnode		*fg_cnodelist;	/* list of cnodes */

	struct filegrp		*fg_next;	/* pointer to next */
	struct vnode		*fg_dirvp;	/* filegrp directory vp */
	struct vnode		*fg_attrvp;	/* attrcache vp */
	struct attrcache_header	*fg_header;	/* Attrcache header */
	struct attrcache_index	*fg_offsets;	/* ptr to indexes in header */
	uchar_t			*fg_alloclist;	/* allocation bitmap */

	int			 fg_headersize;	/* attrcache header size */
	int			 fg_filesize;	/* size of attrcache file */
	kmutex_t		 fg_mutex;	/* filegrp contents/ac lock */
	kmutex_t		 fg_cnodelock;	/* cnode list lock */
};
typedef struct filegrp filegrp_t;

extern struct kmem_cache *cachefs_filegrp_cache;

/* fg_flags values */
#define	CFS_FG_NOCACHE		0x1	/* no cache mode */
#define	CFS_FG_ALLOC_ATTR	0x2	/* no attrcache file yet */
#define	CFS_FG_UPDATED		0x4	/* attrcache modified */
#define	CFS_FG_ALLOC_FILE	0x10	/* no front file dir yet */
#define	CFS_FG_RL		0x20	/* no longer used */
#define	CFS_FG_READ		0x40	/* attrcache can be read */
#define	CFS_FG_WRITE		0x80	/* attrcache can be written */

int filegrp_cache_create(void *, void *, int);
void filegrp_cache_destroy(void *, void *);
filegrp_t *filegrp_create(struct fscache *fscp, cfs_cid_t *cidp);
void filegrp_destroy(filegrp_t *fgp);
int filegrp_allocattr(filegrp_t *fgp);
int filegrpdir_create(filegrp_t *fgp);
int filegrpdir_find(filegrp_t *fgp);
void filegrp_hold(filegrp_t *fgp);
void filegrp_rele(filegrp_t *fgp);
int filegrp_ffhold(filegrp_t *fgp);
void filegrp_ffrele(filegrp_t *fgp);

int filegrp_sync(filegrp_t *fgp);
int filegrp_read_metadata(filegrp_t *fgp, cfs_cid_t *cidp,
    struct cachefs_metadata *mdp);
int filegrp_create_metadata(filegrp_t *fgp, struct cachefs_metadata *md,
    cfs_cid_t *cidp);
int filegrp_write_metadata(filegrp_t *fgp, cfs_cid_t *cidp,
    struct cachefs_metadata *mdp);
int filegrp_destroy_metadata(filegrp_t *fgp, cfs_cid_t *cidp);
int filegrp_cid_to_slot(filegrp_t *fgp, cfs_cid_t *cidp);

filegrp_t *filegrp_list_find(struct fscache *fscp, cfs_cid_t *cidp);
void filegrp_list_add(struct fscache *fscp, filegrp_t *fgp);
void filegrp_list_remove(struct fscache *fscp, filegrp_t *fgp);
void filegrp_list_gc(struct fscache *fscp);
void filegrp_list_enable_caching_ro(struct fscache *fscp);
void filegrp_list_enable_caching_rw(struct fscache *fscp);

#ifdef __cplusplus
}
#endif

#endif /* _SYS_FS_CACHEFS_FILEGRP_H */
