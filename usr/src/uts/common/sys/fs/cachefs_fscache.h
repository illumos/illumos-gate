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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_FS_CACHEFS_FSCACHE_H
#define	_SYS_FS_CACHEFS_FSCACHE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#define	CFS_FS_FGP_BUCKET_SIZE	64	/* must be a power of 2 */
#define	CFS_FS_MAXIDLE 100

enum cachefs_connected {
	CFS_CD_CONNECTED = 0x801,	/* connected to back fs */
	CFS_CD_DISCONNECTED,		/* disconnected from back fs */
	CFS_CD_RECONNECTING		/* rolling log to back fs */
};

typedef struct cachefs_stats {
	uint_t	st_hits;
	uint_t	st_misses;
	uint_t	st_passes;
	uint_t	st_fails;
	uint_t	st_modifies;
	uint_t	st_gc_count;
	cfs_time_t	st_gc_time;
	cfs_time_t	st_gc_before_atime;
	cfs_time_t	st_gc_after_atime;
} cachefs_stats_t;

/* file system persistant state */
struct cachefs_fsinfo {
	uint_t		fi_mntflags;		/* mount flags */
	int		fi_popsize;		/* cache population size */
	ino64_t		fi_root;		/* inode # of root of fs */
	uint_t		fi_resettimes;		/* when to reset local times */
	uint_t		fi_resetfileno;		/* when to reset local fileno */
	ino64_t		fi_localfileno;		/* next local fileno to use */
	int		fi_fgsize;		/* filegrp size, default 256 */
	uint_t		fi_pad[1];		/* pad field */
};
typedef struct cachefs_fsinfo cachefs_fsinfo_t;

/*
 * used to translate the server's idea of inode numbers into the
 * client's idea, after a reconnect, in a directory entry a la
 * readdir()
 */

typedef struct cachefs_inum_trans {
	ino64_t cit_real;
	ino64_t cit_fake;
} cachefs_inum_trans_t;

extern int cachefs_hash_sizes[];

/*
 * fscache structure contains per-filesystem information, both filesystem
 * cache directory information and mount-specific information.
 */
struct fscache {
	ino64_t			 fs_cfsid;	/* File system ID */
	int			 fs_flags;
	struct vnode		*fs_fscdirvp;	/* vp to fs cache dir */
	struct vnode		*fs_fsattrdir;	/* vp to attrcache dir */
	struct vnode		*fs_infovp;	/* vp to fsinfo file */
	struct cachefscache	*fs_cache;	/* back ptr to cache struct */
	cachefs_fsinfo_t	 fs_info;	/* fs persistant state */
	struct vfs		*fs_cfsvfsp;	/* cfs vfsp */
	struct vfs		*fs_backvfsp;	/* back file system vfsp */
	struct vnode		*fs_rootvp;	/* root vnode ptr */
	offset_t		 fs_offmax;	/* maximum offset if backvp */
	int			 fs_ref;	/* ref count on fscache */
	int			 fs_cnodecnt;	/* cnt of cnodes on fscache */
	int			 fs_consttype;	/* type of consistency check */
	struct cachefsops	*fs_cfsops;	/* cfsops vector pointer */
	uint_t			 fs_acregmin;	/* same as nfs values */
	uint_t			 fs_acregmax;
	uint_t			 fs_acdirmin;
	uint_t			 fs_acdirmax;
	struct fscache		*fs_next;	/* ptr to next fscache */
	struct cachefs_workq	 fs_workq;	/* async thread work queue */

	kmutex_t		 fs_fslock;	/* contents lock */

	struct vnode		*fs_dlogfile;	/* log file */
	off_t			 fs_dlogoff;	/* offset into log file */
	uint_t			 fs_dlogseq;	/* sequence number */
	struct vnode		*fs_dmapfile;	/* map file */
	off_t			 fs_dmapoff;	/* offset into map file */
	off_t			 fs_dmapsize;	/* size of map file */
	kmutex_t		 fs_dlock;	/* protects d* variables */

	kmutex_t		 fs_idlelock;	/* idle* lock */
	int			 fs_idlecnt;	/* number of idle cnodes */
	int			 fs_idleclean;	/* cleaning idle list */
	struct cnode		*fs_idlefront;	/* front of idle list */

	/* related to connected or disconnected (cd) */
	kmutex_t		 fs_cdlock;	/* protects fs_cd* variables */
	kcondvar_t		 fs_cdwaitcv;	/* signal state transitions */
	enum cachefs_connected	 fs_cdconnected; /* how connected to backfs */
	int			 fs_cdtransition; /* 1 transitioning, 0 not */
	pid_t			 fs_cddaemonid;	/* pid of cachefsd */
	int			 fs_cdrefcnt;	/* # threads in cachefs */

	struct cnode		*fs_idleback;	/* back of idle list */

	cachefs_inum_trans_t	*fs_inum_trans;	/* real->fake inums */
	int			 fs_inum_size;	/* # fs_inum_trans alloced */

	/* list of fgps */
	struct filegrp		*fs_filegrp[CFS_FS_FGP_BUCKET_SIZE];

	timestruc_t		 fs_cod_time;	/* time of CoD event */
	int			 fs_kstat_id;
	cachefs_stats_t		 fs_stats;
	char			 *fs_mntpt;
	char			 *fs_hostname;
	char			 *fs_backfsname;
};
typedef struct fscache fscache_t;

extern struct kmem_cache *cachefs_fscache_cache;

/* valid fscache flags */
#define	CFS_FS_MOUNTED		0x01	/* fscache is mounted */
#define	CFS_FS_READ		0x02	/* fscache can be read */
#define	CFS_FS_WRITE		0x04	/* fscache can be written */
#define	CFS_FS_ROOTFS		0x08	/* fscache is / */
#define	CFS_FS_DIRTYINFO	0x10	/* fs_info needs to be written */
#define	CFS_FS_HASHPRINT	0x20	/* hash warning already printed once */

/* types of consistency checking */
#define	CFS_FS_CONST_STRICT	11	/* strict consistency */
#define	CFS_FS_CONST_NOCONST	12	/* no consistency */
#define	CFS_FS_CONST_CODCONST	13	/* consistency on demand */

#define	CFSOP_INIT_COBJECT(FSCP, CP, VAP, CR)	\
	(*(FSCP)->fs_cfsops->co_init_cobject)(FSCP, CP, VAP, CR)
#define	CFSOP_CHECK_COBJECT(FSCP, CP, WHAT, CR)	\
	(*(FSCP)->fs_cfsops->co_check_cobject)(FSCP, CP, WHAT, CR)
#define	CFSOP_MODIFY_COBJECT(FSCP, CP, CR)	\
	(*(FSCP)->fs_cfsops->co_modify_cobject)(FSCP, CP, CR)
#define	CFSOP_INVALIDATE_COBJECT(FSCP, CP, CR)	\
	(*(FSCP)->fs_cfsops->co_invalidate_cobject)(FSCP, CP, CR)
#define	CFSOP_CONVERT_COBJECT(FSCP, CP, CR)	\
	(*(FSCP)->fs_cfsops->co_convert_cobject)(FSCP, CP, CR)

#define	CFS_ISFS_SNR(FSCP) \
	((FSCP)->fs_info.fi_mntflags & CFS_DISCONNECTABLE)
#define	CFS_ISFS_SOFT(FSCP) \
	((FSCP)->fs_info.fi_mntflags & CFS_SOFT)

#define	CFS_ISFS_WRITE_AROUND(FSCP) \
	((FSCP)->fs_info.fi_mntflags & CFS_WRITE_AROUND)
#define	CFS_ISFS_NONSHARED(FSCP) \
	((FSCP)->fs_info.fi_mntflags & CFS_NONSHARED)

#define	CFS_ISFS_STRICT(FSCP) \
	(((FSCP)->fs_info.fi_mntflags & CFS_WRITE_AROUND) && \
	(((FSCP)->fs_info.fi_mntflags & \
		(CFS_NOCONST_MODE | CFS_CODCONST_MODE)) == 0))
#define	CFS_ISFS_NOCONST(FSCP) \
	((FSCP)->fs_info.fi_mntflags & CFS_NOCONST_MODE)
#define	CFS_ISFS_CODCONST(FSCP) \
	((FSCP)->fs_info.fi_mntflags & CFS_CODCONST_MODE)

#define	CFS_ISFS_LLOCK(FSCP) \
	((FSCP)->fs_info.fi_mntflags & CFS_LLOCK)
#define	CFS_ISFS_BACKFS_NFSV4(FSCP) \
	((FSCP)->fs_info.fi_mntflags & CFS_BACKFS_NFSV4)

fscache_t *fscache_create(cachefscache_t *cachep);
void fscache_destory(fscache_t *fscp);
int fscache_activate(fscache_t *fscp, ino64_t fsid, char *namep,
	struct cachefsoptions *optp, ino64_t backfileno);
int fscache_enable(fscache_t *fscp, ino64_t fsid, char *namep,
	struct cachefsoptions *optp, ino64_t backfileno);
void fscache_activate_rw(fscache_t *fscp);
void fscache_hold(fscache_t *fscp);
void fscache_rele(fscache_t *fscp);
int fscache_cnodecnt(fscache_t *fscp, int cnt);
int fscache_mounted(fscache_t *fscp, struct vfs *cfsvfsp, struct vfs *backvfsp);
int fscache_compare_options(fscache_t *fscp, struct cachefsoptions *opnewp);
void fscache_sync(fscache_t *fscp);
void fscache_acset(fscache_t *fscp,
	uint_t acregmin, uint_t acregmax, uint_t acdirmin, uint_t acdirmax);

fscache_t *fscache_list_find(cachefscache_t *cachep, ino64_t fsid);
void fscache_list_add(cachefscache_t *cachep, fscache_t *fscp);
void fscache_list_remove(cachefscache_t *cachep, fscache_t *fscp);
void fscache_list_gc(cachefscache_t *cachep);
int fscache_list_mounted(cachefscache_t *cachep);

int fscache_name_to_fsid(cachefscache_t *cachep, char *namep, ino64_t *fsidp);

int cachefs_cd_access(fscache_t *fscp, int waitconnected, int writing);
int cachefs_cd_access_miss(fscache_t *fscp);
void cachefs_cd_release(fscache_t *fscp);
void cachefs_cd_timedout(fscache_t *fscp);

#ifdef __cplusplus
}
#endif

#endif /* _SYS_FS_CACHEFS_FSCACHE_H */
