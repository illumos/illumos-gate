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
 * Copyright 2014 Garrett D'Amore <garrett@damore.org>
 *
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_FS_CACHEFS_DLOG_H
#define	_SYS_FS_CACHEFS_DLOG_H

#include <sys/vfs.h>
#include <sys/acl.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Version number of log file format.
 * Put in an int at the start of the file.
 * Large Files: Increment VER by 1.
 */
#define	CFS_DLOG_VERSION 1001

/* valid types of dlog records */
enum cfs_dlog_op {
	CFS_DLOG_CREATE = 0x100,
	CFS_DLOG_REMOVE,
	CFS_DLOG_LINK,
	CFS_DLOG_RENAME,
	CFS_DLOG_MKDIR,
	CFS_DLOG_RMDIR,
	CFS_DLOG_SYMLINK,
	CFS_DLOG_SETATTR,
	CFS_DLOG_SETSECATTR,
	CFS_DLOG_MODIFIED,
	CFS_DLOG_MAPFID,
	CFS_DLOG_TRAILER
};
typedef enum cfs_dlog_op cfs_dlog_op_t;

/* validity of records */
enum cfs_dlog_val {
	CFS_DLOG_VAL_CRASH = 0x200,	/* crash during record creation */
	CFS_DLOG_VAL_COMMITTED,		/* valid record */
	CFS_DLOG_VAL_ERROR,		/* error, operation not performed */
	CFS_DLOG_VAL_PROCESSED		/* record processed */
};
typedef enum cfs_dlog_val cfs_dlog_val_t;

/* number of bytes for groups appended to a cred structure */
#define	CFS_DLOG_BUFSIZE (sizeof (gid_t) * (NGROUPS_MAX_DEFAULT - 1))

/* the old kernel credential; ossified on disk so we're stuck with this. */
typedef struct dl_cred {
	uint_t	__ign1;			/* ignore (was ref count) */
	uid_t	cr_uid;			/* effective user id */
	gid_t	cr_gid;			/* effective group id */
	uid_t	cr_ruid;		/* real user id */
	gid_t	cr_rgid;		/* real group id */
	uid_t	cr_suid;		/* "saved" user id (from exec) */
	gid_t	cr_sgid;		/* "saved" group id (from exec) */
	uint_t	cr_ngroups;		/* number of groups in cr_groups */
	gid_t	cr_groups[1];		/* supplementary group list */
} dl_cred_t;

/*
 * cfs_dlog_mapping_space is stored on disk, so it needs to be the same
 * 32-bit vs. 64-bit. The other structures below are also stored on disk,
 * but they do not contain any 64-bit elements.
 */

#if _LONG_LONG_ALIGNMENT == 8 && _LONG_LONG_ALIGNMENT_32 == 4
#pragma pack(4)
#endif

/* the basic elements in the mapping file */
struct cfs_dlog_mapping_space {
	cfs_cid_t	ms_cid;		/* mapping key */
	off_t		ms_fid;		/* offset to fid */
	off_t		ms_times;	/* offset to timestamps */
};

#if _LONG_LONG_ALIGNMENT == 8 && _LONG_LONG_ALIGNMENT_32 == 4
#pragma pack()
#endif

/*
 * XX64: For now we use the old time_t defs. In the next version the logs
 * and on-disk structs may change to 64-bit. The structs here are used
 * for the data log.
 */
/* mtime and ctime stamps */
struct cfs_dlog_tm {
	cfs_timestruc_t	tm_mtime;	/* cached mtime on file */
	cfs_timestruc_t	tm_ctime;	/* cached ctime on file */
};
typedef struct cfs_dlog_tm cfs_dlog_tm_t;

/* structure populated for setattr */
struct cfs_dlog_setattr {
	cfs_vattr_t	dl_attrs;	/* attrs to set file to */
	int		dl_flags;	/* flags used with setattr */
	cfs_cid_t	dl_cid;		/* cid of the file to setattr */
	cfs_dlog_tm_t	dl_times;	/* ctime and mtime on file */
	dl_cred_t	dl_cred;	/* creds used */
	char		dl_buffer[CFS_DLOG_BUFSIZE];	/* groups */
};

/* structure for setsecattr (aka setting an ACL) */
/* n.b. data for this can exceed sizeof this struct, due to 24k ACLs! */
struct cfs_dlog_setsecattr {
	cfs_cid_t	dl_cid;		/* cid of file to setsecattr */
	cfs_dlog_tm_t	dl_times;	/* ctime and mtime on file */
	uint_t		dl_mask;	/* mask field in vsecattr_t */
	int		dl_aclcnt;	/* count of ACLs */
	int		dl_dfaclcnt;	/* count of default ACLs */
	dl_cred_t	dl_cred;	/* creds used */
	char		dl_buffer[CFS_DLOG_BUFSIZE]; /* groups + ACLs */
};

/* structure populated for creates */
struct cfs_dlog_create {
	cfs_cid_t	dl_parent_cid;	/* parent directory cid */
	cfs_cid_t	dl_new_cid;	/* cid of the created file */
	cfs_vattr_t	dl_attrs;	/* attrs to create with */
	int		dl_excl;	/* exclusive mode flag */
	int		dl_mode;	/* mode bits for created file */
	int		dl_exists;	/* does file already exist? */
	cfs_dlog_tm_t	dl_times;	/* ctime and mtime on file */
	cfs_fid_t	dl_fid;		/* blank fid */
	dl_cred_t	dl_cred;	/* user credentials */
	char		dl_buffer[CFS_DLOG_BUFSIZE + MAXNAMELEN];
};

/* struct used for remove */
struct cfs_dlog_remove {
	cfs_cid_t	dl_parent_cid;	/* parent directory cid */
	cfs_cid_t	dl_child_cid;	/* cid of entry that was removed */
	cfs_dlog_tm_t	dl_times;	/* ctime and mtime on file */
	dl_cred_t	dl_cred;	/* credentials to use */
	char		dl_buffer[CFS_DLOG_BUFSIZE + MAXNAMELEN];
};

/* struct used for rmdir */
struct cfs_dlog_rmdir {
	cfs_cid_t	dl_parent_cid;	/* parent directory cid */
	dl_cred_t	dl_cred;	/* credentials to use */
	char		dl_buffer[CFS_DLOG_BUFSIZE + MAXNAMELEN];
};

/* struct used for mkdir */
struct cfs_dlog_mkdir {
	cfs_cid_t	dl_parent_cid;	/* parent directory cid */
	cfs_cid_t	dl_child_cid;	/* cid of created entry */
	cfs_vattr_t	dl_attrs;	/* attrs to insert with */
	cfs_fid_t	dl_fid;		/* blank fid */
	dl_cred_t	dl_cred;	/* credentials to use */
	char		dl_buffer[CFS_DLOG_BUFSIZE + MAXNAMELEN];
};

/* struct used for link */
struct cfs_dlog_link {
	cfs_cid_t	dl_parent_cid;	/* parent directory cid */
	cfs_cid_t	dl_child_cid;	/* cid of created entry */
	cfs_dlog_tm_t	dl_times;	/* ctime and mtime on file */
	dl_cred_t	dl_cred;	/* credentials to use */
	char		dl_buffer[CFS_DLOG_BUFSIZE + MAXNAMELEN];
};

/* struct used for symlink */
struct cfs_dlog_symlink {
	cfs_cid_t	dl_parent_cid;	/* parent directory cid */
	cfs_cid_t	dl_child_cid;	/* cid of created entry */
	cfs_vattr_t	dl_attrs;	/* attrs to insert with */
	cfs_dlog_tm_t	dl_times;	/* ctime and mtime on file */
	cfs_fid_t	dl_fid;		/* blank fid */
	dl_cred_t	dl_cred;	/* credentials to use */
	char		dl_buffer[CFS_DLOG_BUFSIZE + MAXNAMELEN + MAXPATHLEN];
};

struct cfs_dlog_rename {
	cfs_cid_t	dl_oparent_cid; /* cid of the original parent dir */
	cfs_cid_t	dl_nparent_cid;	/* cid of the new parent dir */
	cfs_cid_t	dl_child_cid;	/* cid of renamed file */
	cfs_dlog_tm_t	dl_times;	/* ctime and mtime on file */
	cfs_cid_t	dl_del_cid;	/* cid of deleted file */
	cfs_dlog_tm_t	dl_del_times;	/* ctime and mtime on deleted file */
	dl_cred_t	dl_cred;	/* credentials to use */
	char		dl_buffer[CFS_DLOG_BUFSIZE + (2 * MAXNAMELEN)];
};

struct cfs_dlog_modify {
	cfs_cid_t	dl_cid;		/* cid of modified file */
	cfs_dlog_tm_t	dl_times;	/* ctime and mtime on file */
	off32_t		dl_next;	/* daemon links modifies together */
	dl_cred_t	dl_cred;	/* credentials to use */
	char		dl_buffer[CFS_DLOG_BUFSIZE];	/* groups */
};

struct cfs_dlog_mapfid {
	cfs_cid_t	dl_cid;		/* cid of file */
	cfs_fid_t	dl_fid;		/* fid of file */
};

#define	COMMON_RECORD_HDR()  						\
	int		dl_len;		/* length of this record */	\
	cfs_dlog_op_t 	dl_op;		/* operation */			\
	cfs_dlog_val_t 	dl_valid;	/* validity of operation */	\
	uint_t		dl_seq;		/* sequence number */

/*
 * The trailer record must look just like the beginning of a record.
 * This allows the cachefs daemon to throw it away(not process the record)
 * with very little additional code.
 */
struct cfs_dlog_trailer {
	COMMON_RECORD_HDR()
};

struct cfs_dlog_entry {
	COMMON_RECORD_HDR()

	union cfs_dlog_entry_items {
		struct cfs_dlog_setattr		dl_setattr;
		struct cfs_dlog_setsecattr	dl_setsecattr;
		struct cfs_dlog_create		dl_create;
		struct cfs_dlog_remove		dl_remove;
		struct cfs_dlog_rmdir		dl_rmdir;
		struct cfs_dlog_mkdir		dl_mkdir;
		struct cfs_dlog_link		dl_link;
		struct cfs_dlog_symlink		dl_symlink;
		struct cfs_dlog_rename		dl_rename;
		struct cfs_dlog_modify		dl_modify;
		struct cfs_dlog_mapfid		dl_mapfid;
	} dl_u;

	struct cfs_dlog_trailer dl_trailer;
};
typedef struct cfs_dlog_entry cfs_dlog_entry_t;

/*
 * XXXX the maxsize calculation below will give wrong answer if
 * the total size of struct cfs_dlog_setsecattr + max aclsize is less than
 * the size of the union above. This is currently true, but to be on the safe
 * side, use struct size plus acl size (minus trailer because it's not
 * not counted in the length field).
 */
#define	CFS_DLOG_SECATTR_MAXSIZE (sizeof (struct cfs_dlog_setsecattr) + \
	(sizeof (aclent_t) * MAX_ACL_ENTRIES))

#ifndef MAX
#define	MAX(a, b)	(((a) > (b)) ? (a) : (b))
#endif /* MAX */

#define	CFS_DLOG_ENTRY_MAXSIZE	\
	MAX(offsetof(struct cfs_dlog_entry, dl_trailer),		\
	    offsetof(struct cfs_dlog_entry, dl_u.dl_setsecattr) +	\
	    CFS_DLOG_SECATTR_MAXSIZE)

#if defined(_KERNEL)
int cachefs_dlog_setup(fscache_t *fscp, int createfile);
void cachefs_dlog_teardown(fscache_t *fscp);
int cachefs_dlog_commit(fscache_t *fscp, off_t offset, int error);
int cachefs_dlog_cidmap(fscache_t *fscp);
off_t cachefs_dlog_setattr(fscache_t *fscp, struct vattr *vap, int flags,
    cnode_t *cp, cred_t *cr);
off_t
cachefs_dlog_setsecattr(fscache_t *fscp, vsecattr_t *vsec, int flags,
    cnode_t *cp, cred_t *cr);
off_t cachefs_dlog_create(fscache_t *fscp, cnode_t *pcp, char *nm,
    vattr_t *vap, int excl, int mode, cnode_t *cp, int exists, cred_t *cr);
off_t cachefs_dlog_remove(fscache_t *fscp, cnode_t *pcp, char *nm, cnode_t *cp,
    cred_t *cr);
off_t cachefs_dlog_link(fscache_t *fscp, cnode_t *pcp, char *nm, cnode_t *cp,
    cred_t *cr);
off_t cachefs_dlog_rename(fscache_t *fscp, cnode_t *odcp, char *onm,
    cnode_t *ndcp, char *nnm, cred_t *cr, cnode_t *cp, cnode_t *delcp);
off_t cachefs_dlog_mkdir(fscache_t *fscp, cnode_t *pcp, cnode_t *cp, char *nm,
    vattr_t *vap, cred_t *cr);
off_t cachefs_dlog_rmdir(fscache_t *fscp, cnode_t *pcp, char *nm, cnode_t *cp,
    cred_t *cr);
off_t cachefs_dlog_symlink(fscache_t *fscp, cnode_t *pcp, cnode_t *cp,
    char *lnm, vattr_t *vap, char *tnm, cred_t *cr);
off_t cachefs_dlog_modify(fscache_t *fscp, cnode_t *cp, cred_t *cr,
    uint_t *seqp);
int cachefs_dlog_mapfid(fscache_t *fscp, cnode_t *cp);
uint_t cachefs_dlog_seqnext(fscache_t *fscp);
#endif

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_FS_CACHEFS_DLOG_H */
