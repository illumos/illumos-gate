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
 * Copyright 1996-1998,2001-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_FS_CACHEFS_IOCTL_H
#define	_SYS_FS_CACHEFS_IOCTL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

/* set of subcommands to CACHEFSIO_DCMD */
enum cfsdcmd_cmds {
	CFSDCMD_DAEMONID, CFSDCMD_STATEGET, CFSDCMD_STATESET,
	CFSDCMD_XWAIT, CFSDCMD_EXISTS, CFSDCMD_LOSTFOUND, CFSDCMD_GETINFO,
	CFSDCMD_CIDTOFID, CFSDCMD_GETATTRFID, CFSDCMD_GETATTRNAME,
	CFSDCMD_GETSTATS, CFSDCMD_ROOTFID,
	CFSDCMD_CREATE, CFSDCMD_REMOVE, CFSDCMD_LINK, CFSDCMD_RENAME,
	CFSDCMD_MKDIR, CFSDCMD_RMDIR, CFSDCMD_SYMLINK, CFSDCMD_SETATTR,
	CFSDCMD_SETSECATTR, CFSDCMD_PUSHBACK
};
typedef enum cfsdcmd_cmds cfsdcmd_cmds_t;

/* file system states passed to stateset, returned from stateget */
#define	CFS_FS_CONNECTED	0x00	/* fscache connected to backfs */
#define	CFS_FS_DISCONNECTED	0x01	/* fscache disconnected from backfs */
#define	CFS_FS_RECONNECTING	0x02	/* fscache is reconnecting to backfs */

/* bits returned by packinfo */
#define	CACHEFS_PACKED_FILE	1	/* file is marked as packed */
#define	CACHEFS_PACKED_DATA	2	/* file data is in the cache */
#define	CACHEFS_PACKED_NOCACHE	4	/* file marked as not for caching */

struct cachefsio_pack {
	char		p_name[MAXNAMELEN];	/* name of file */
	int		p_status;		/* status of operation */
};
typedef struct cachefsio_pack cachefsio_pack_t;

struct cachefsio_dcmd {
	cfsdcmd_cmds_t	 d_cmd;			/* cmd to execute */
	void		*d_sdata;		/* data for command */
	int		 d_slen;		/* len of data */
	void		*d_rdata;		/* data to return */
	int		 d_rlen;		/* len of data */
};
typedef struct cachefsio_dcmd cachefsio_dcmd_t;

struct cachefsio_getinfo {
	cfs_cid_t	gi_cid;			/* entry to lookup */
	int		gi_modified;		/* returns if modified data */
	cfs_vattr_t	gi_attr;		/* return file attributes */
	cfs_cid_t	gi_pcid;		/* returns the parent dir */
	uint_t		gi_seq;			/* sequence number */
	char		gi_name[MAXNAMELEN];	/* returns name of file */
};
typedef struct cachefsio_getinfo cachefsio_getinfo_t;

struct cachefsio_lostfound_arg {
	cfs_cid_t	lf_cid;			/* file to move */
	char		lf_name[MAXNAMELEN];	/* suggested name */
};
typedef struct cachefsio_lostfound_arg cachefsio_lostfound_arg_t;

struct cachefsio_lostfound_return {
	char		lf_name[MAXNAMELEN];	/* returns actual name */
};
typedef struct cachefsio_lostfound_return cachefsio_lostfound_return_t;

struct cachefsio_getattrfid {
	cfs_fid_t	cg_backfid;	/* backfs fid of file */
	dl_cred_t	cg_cred;	/* creds */
	gid_t	cg_groups[NGROUPS_MAX_DEFAULT-1];
};
typedef struct cachefsio_getattrfid cachefsio_getattrfid_t;

struct cachefsio_getattrname_arg {
	cfs_fid_t	cg_dir;			/* backfs fid of directory */
	char	cg_name[MAXNAMELEN];	/* name of file in directory cg_dir */
	dl_cred_t	cg_cred;	/* creds */
	gid_t	cg_groups[NGROUPS_MAX_DEFAULT-1];
};
typedef	struct cachefsio_getattrname_arg cachefsio_getattrname_arg_t;

struct cachefsio_getattrname_return {
	cfs_vattr_t	cg_attr;		/* returns attributes of file */
	cfs_fid_t	cg_fid;			/* returns fid of file */
};
typedef	struct cachefsio_getattrname_return cachefsio_getattrname_return_t;

struct cachefsio_getstats {
	int		gs_total;		/* total blocks */
	int		gs_gc;			/* number of gc blocks */
	int		gs_active;		/* number of active blocks */
	int		gs_packed;		/* number of packed blocks */
	int		gs_free;		/* number of free blocks */
	cfs_time_t	gs_gctime;		/* atime of front of gc list */
};
typedef struct cachefsio_getstats cachefsio_getstats_t;

struct cachefsio_create_arg {
	cfs_fid_t	cr_backfid;		/* backfs fid of directory */
	char		cr_name[MAXNAMELEN];	/* name of file to create */
	cfs_cid_t	cr_cid;			/* cid of file being created */
	cfs_vattr_t	cr_va;			/* attributes for create */
	int		cr_exclusive;		/* exclusive create or not */
	int		cr_mode;		/* mode */
	dl_cred_t	cr_cred;		/* creds */
	gid_t		cr_groups[NGROUPS_MAX_DEFAULT-1];
};
typedef struct cachefsio_create_arg cachefsio_create_arg_t;

struct cachefsio_create_return {
	cfs_fid_t	cr_newfid;		/* returns fid of new file */
	cfs_timestruc_t	cr_ctime;		/* returns new ctime */
	cfs_timestruc_t	cr_mtime;		/* returns new mtime */
};
typedef struct cachefsio_create_return cachefsio_create_return_t;

struct cachefsio_pushback_arg {
	cfs_cid_t	pb_cid;			/* file to push back */
	cfs_fid_t	pb_fid;			/* back fs fid to push to */
	dl_cred_t	pb_cred;		/* creds */
	gid_t		pb_groups[NGROUPS_MAX_DEFAULT-1];
};
typedef struct cachefsio_pushback_arg cachefsio_pushback_arg_t;

struct cachefsio_pushback_return {
	cfs_timestruc_t	pb_ctime;		/* returns new ctime */
	cfs_timestruc_t	pb_mtime;		/* returns new mtime */
};
typedef struct cachefsio_pushback_return cachefsio_pushback_return_t;

struct cachefsio_remove {
	cfs_cid_t	rm_cid;			/* cid of deleted file */
	cfs_fid_t	rm_fid;			/* fid of parent directory */
	char		rm_name[MAXNAMELEN];	/* name of file to remove */
	int		rm_getctime;		/* 1 means return new ctime */
	dl_cred_t	rm_cred;		/* creds */
	gid_t		rm_groups[NGROUPS_MAX_DEFAULT-1];
};
typedef struct cachefsio_remove cachefsio_remove_t;

struct cachefsio_link {
	cfs_fid_t	ln_dirfid;		/* backfid of parent dir */
	char		ln_name[MAXNAMELEN];	/* name of new link */
	cfs_fid_t	ln_filefid;		/* backfid of file to link to */
	cfs_cid_t	ln_cid;			/* cid of link */
	dl_cred_t	ln_cred;		/* creds */
	gid_t		ln_groups[NGROUPS_MAX_DEFAULT-1];
};
typedef struct cachefsio_link cachefsio_link_t;

struct cachefsio_rename_arg {
	cfs_fid_t	rn_olddir;		/* backfs fid of old dir */
	char		rn_oldname[MAXNAMELEN];	/* old name of file */
	cfs_fid_t	rn_newdir;		/* backfs fid of new dir */
	char		rn_newname[MAXNAMELEN];	/* new name of file */
	cfs_cid_t	rn_cid;			/* cid of renamed file */
	int		rn_del_getctime;	/* 1 means fill in del_ctime */
	cfs_cid_t	rn_del_cid;		/* cid of deleted file */
	dl_cred_t	rn_cred;		/* creds */
	gid_t		rn_groups[NGROUPS_MAX_DEFAULT-1];
};
typedef struct cachefsio_rename_arg cachefsio_rename_arg_t;

struct cachefsio_rename_return {
	cfs_timestruc_t	rn_ctime;		/* returns new file ctime */
	cfs_timestruc_t	rn_del_ctime;		/* returns new del file ctime */
};
typedef struct cachefsio_rename_return cachefsio_rename_return_t;

struct cachefsio_mkdir {
	cfs_fid_t	md_dirfid;		/* backfs fid of dir */
	char		md_name[MAXNAMELEN];	/* name of the new dir */
	cfs_cid_t	md_cid;			/* cid of dir being created */
	cfs_vattr_t	md_vattr;		/* attributes */
	dl_cred_t	md_cred;		/* creds */
	gid_t		md_groups[NGROUPS_MAX_DEFAULT-1];
};
typedef struct cachefsio_mkdir cachefsio_mkdir_t;

struct cachefsio_rmdir {
	cfs_fid_t	rd_dirfid;		/* backfs fid of dir */
	char		rd_name[MAXNAMELEN];	/* name of the dir to delete */
	dl_cred_t	rd_cred;		/* creds */
	gid_t		rd_groups[NGROUPS_MAX_DEFAULT-1];
};
typedef struct cachefsio_rmdir cachefsio_rmdir_t;

struct cachefsio_symlink_arg {
	cfs_fid_t	sy_dirfid;		/* backfs fid of dir */
	char		sy_name[MAXNAMELEN];	/* name of symlink to create */
	cfs_cid_t	sy_cid;			/* cid of symlink */
	char		sy_link[MAXPATHLEN];	/* contents of the symlink */
	cfs_vattr_t	sy_vattr;		/* attributes */
	dl_cred_t	sy_cred;		/* creds */
	gid_t		sy_groups[NGROUPS_MAX_DEFAULT-1];
};
typedef struct cachefsio_symlink_arg cachefsio_symlink_arg_t;

struct cachefsio_symlink_return {
	cfs_fid_t	sy_newfid;		/* returns fid of symlink */
	cfs_timestruc_t	sy_ctime;		/* returns new ctime */
	cfs_timestruc_t	sy_mtime;		/* returns new mtime */
};
typedef struct cachefsio_symlink_return cachefsio_symlink_return_t;

struct cachefsio_setattr_arg {
	cfs_fid_t	sa_backfid;		/* backfs fid of file */
	cfs_cid_t	sa_cid;			/* cid of file */
	cfs_vattr_t	sa_vattr;		/* attributes */
	int		sa_flags;		/* flags */
	dl_cred_t	sa_cred;		/* creds */
	gid_t		sa_groups[NGROUPS_MAX_DEFAULT-1];
};
typedef struct cachefsio_setattr_arg cachefsio_setattr_arg_t;

struct cachefsio_setattr_return {
	cfs_timestruc_t	sa_ctime;		/* returns new ctime */
	cfs_timestruc_t	sa_mtime;		/* returns new mtime */
};
typedef struct cachefsio_setattr_return cachefsio_setattr_return_t;

struct cachefsio_setsecattr_arg {
	cfs_fid_t	sc_backfid;		/* backfs fid of file */
	cfs_cid_t	sc_cid;			/* cid of file */
	uint_t		sc_mask;		/* mask for setsec */
	int		sc_aclcnt;		/* count of ACLs */
	int		sc_dfaclcnt;		/* count of default ACLs */
	aclent_t	sc_acl[MAX_ACL_ENTRIES]; /* ACLs */
	dl_cred_t	sc_cred;		/* creds */
	gid_t		sc_groups[NGROUPS_MAX_DEFAULT-1];
};
typedef struct cachefsio_setsecattr_arg cachefsio_setsecattr_arg_t;

struct cachefsio_setsecattr_return {
	cfs_timestruc_t	sc_ctime;		/* returns new ctime */
	cfs_timestruc_t	sc_mtime;		/* returns new mtime */
};
typedef struct cachefsio_setsecattr_return cachefsio_setsecattr_return_t;

#ifdef _SYSCALL32

/*
 * Solaris 64 - the following structs are used for user/kernel communication.
 */

struct cachefsio_dcmd32 {
	cfsdcmd_cmds_t	 d_cmd;			/* cmd to execute */
	caddr32_t	 d_sdata;		/* data for command */
	int32_t		 d_slen;		/* len of data */
	caddr32_t	 d_rdata;		/* data to return */
	int32_t		 d_rlen;		/* len of data */
};
typedef struct cachefsio_dcmd32 cachefsio_dcmd32_t;

#endif /* _SYSCALL32 */

int cachefs_pack(vnode_t *, char *, cred_t *);
int cachefs_unpack(vnode_t *, char *, cred_t *);
int cachefs_packinfo(vnode_t *dvp, char *name, int *statusp, cred_t *cr);
int cachefs_unpackall(vnode_t *);

int cachefs_io_daemonid(vnode_t *vp, void *dinp, void *doutp);
int cachefs_io_stateget(vnode_t *vp, void *dinp, void *doutp);
int cachefs_io_stateset(vnode_t *vp, void *dinp, void *doutp);
int cachefs_io_xwait(vnode_t *vp, void *dinp, void *doutp);
int cachefs_io_exists(vnode_t *vp, void *dinp, void *doutp);
int cachefs_io_lostfound(vnode_t *vp, void *dinp, void *doutp);
int cachefs_io_getinfo(vnode_t *vp, void *dinp, void *doutp);
int cachefs_io_cidtofid(vnode_t *vp, void *dinp, void *doutp);
int cachefs_io_getattrfid(vnode_t *vp, void *dinp, void *doutp);
int cachefs_io_getattrname(vnode_t *vp, void *dinp, void *doutp);
int cachefs_io_getstats(vnode_t *vp, void *dinp, void *doutp);
int cachefs_io_rootfid(vnode_t *vp, void *dinp, void *doutp);
int cachefs_io_create(vnode_t *vp, void *dinp, void *doutp);
int cachefs_io_remove(vnode_t *vp, void *dinp, void *doutp);
int cachefs_io_link(vnode_t *vp, void *dinp, void *doutp);
int cachefs_io_rename(vnode_t *vp, void *dinp, void *doutp);
int cachefs_io_mkdir(vnode_t *vp, void *dinp, void *doutp);
int cachefs_io_rmdir(vnode_t *vp, void *dinp, void *doutp);
int cachefs_io_symlink(vnode_t *vp, void *dinp, void *doutp);
int cachefs_io_setattr(vnode_t *vp, void *dinp, void *doutp);
int cachefs_io_setsecattr(vnode_t *vp, void *dinp, void *doutp);
int cachefs_io_pushback(vnode_t *vp, void *dinp, void *doutp);

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_FS_CACHEFS_IOCTL_H */
