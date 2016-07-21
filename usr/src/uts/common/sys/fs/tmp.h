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
 * Copyright 2007 Sun Microsystems, Inc.
 * All rights reserved.  Use is subject to license terms.
 */
/*
 * Copyright 2016 Joyent, Inc.
 */

#ifndef	_SYS_FS_TMP_H
#define	_SYS_FS_TMP_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * tmpfs per-mount data structure.
 *
 * All fields are protected by tm_contents.
 * File renames on a particular file system are protected tm_renamelck.
 */
struct tmount {
	struct vfs	*tm_vfsp;	/* filesystem's vfs struct */
	struct tmpnode	*tm_rootnode;	/* root tmpnode */
	char 		*tm_mntpath;	/* name of tmpfs mount point */
	size_t		tm_anonmax;	/* file system max anon reservation */
	size_t		tm_anonmem;	/* bytes of reserved anon memory */
					/* and allocated kmem for the fs */
	dev_t		tm_dev;		/* unique dev # of mounted `device' */
	uint_t		tm_gen;		/* pseudo generation number for files */
	kmutex_t	tm_contents;	/* lock for tmount structure */
	kmutex_t	tm_renamelck;	/* rename lock for this mount */
};

/*
 * File system independent to tmpfs conversion macros
 */
#define	VFSTOTM(vfsp)		((struct tmount *)(vfsp)->vfs_data)
#define	VTOTM(vp)		((struct tmount *)(vp)->v_vfsp->vfs_data)
#define	VTOTN(vp)		((struct tmpnode *)(vp)->v_data)
#define	TNTOV(tp)		((tp)->tn_vnode)
#define	TNTOTM(tp)		(VTOTM(TNTOV(tp)))
#define	tmpnode_hold(tp)	VN_HOLD(TNTOV(tp))
#define	tmpnode_rele(tp)	VN_RELE(TNTOV(tp))

/*
 * enums
 */
enum de_op	{ DE_CREATE, DE_MKDIR, DE_LINK, DE_RENAME }; /* direnter ops */
enum dr_op	{ DR_REMOVE, DR_RMDIR, DR_RENAME };	/* dirremove ops */

/*
 * tmpfs_minfree is the amount (in pages) of anonymous memory that tmpfs
 * leaves free for the rest of the system.  In antiquity, this number could be
 * relevant on a system-wide basis, as physical DRAM was routinely exhausted;
 * however, in more modern times, the relative growth of DRAM with respect to
 * application footprint means that this number is only likely to become
 * factor in a virtualized OS environment (e.g., a zone) -- and even then only
 * when DRAM and swap have both been capped low to allow for maximum tenancy.
 * TMPMINFREE -- the value from which tmpfs_minfree is derived -- should
 * therefore be configured to a value that is roughly the smallest practical
 * value for memory + swap minus the largest reasonable size for tmpfs in such
 * a configuration.  As of this writing, the smallest practical memory + swap
 * configuration is 128MB, and it seems reasonable to allow tmpfs to consume
 * no more than seven-eighths of this, yielding a TMPMINFREE of 16MB.  Care
 * should be exercised in changing this:  tuning this value too high will
 * result in spurious ENOSPC errors in tmpfs in small zones (a problem that
 * can induce cascading failure surprisingly often); tuning this value too low
 * will result in tmpfs consumption alone to alone induce application-level
 * memory allocation failure.
 */
#define	TMPMINFREE	16 * 1024 * 1024	/* 16 Megabytes */

extern size_t	tmpfs_minfree;		/* Anonymous memory in pages */

extern	void	tmpnode_init(struct tmount *, struct tmpnode *,
	struct vattr *, struct cred *);
extern	void	tmpnode_cleanup(struct tmpnode *tp);
extern	int	tmpnode_trunc(struct tmount *, struct tmpnode *, ulong_t);
extern	void	tmpnode_growmap(struct tmpnode *, ulong_t);
extern	int	tdirlookup(struct tmpnode *, char *, struct tmpnode **,
    struct cred *);
extern	int	tdirdelete(struct tmpnode *, struct tmpnode *, char *,
	enum dr_op, struct cred *);
extern	int	tdirinit(struct tmpnode *, struct tmpnode *);
extern	void	tdirtrunc(struct tmpnode *);
extern	int	tmp_resv(struct tmount *, struct tmpnode *, size_t, int);
extern	int	tmp_taccess(void *, int, struct cred *);
extern	int	tmp_sticky_remove_access(struct tmpnode *, struct tmpnode *,
	struct cred *);
extern	int	tmp_convnum(char *, size_t *);
extern	int	tmp_convmode(char *, mode_t *);
extern	int	tdirenter(struct tmount *, struct tmpnode *, char *,
	enum de_op, struct tmpnode *, struct tmpnode *, struct vattr *,
	struct tmpnode **, struct cred *, caller_context_t *);

extern void	*tmp_kmem_zalloc(struct tmount *, size_t, int);
extern void	tmp_kmem_free(struct tmount *, void *, size_t);

#define	TMP_MUSTHAVE	0x01

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_FS_TMP_H */
