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

#ifndef _NFS4_ATTR_H
#define	_NFS4_ATTR_H

#ifdef	__cplusplus
extern "C" {
#endif

#define	FATTR4_WORD0	32
#define	FATTR4_WORD1	0

/*
 * Attributes
 */
#define	FATTR4_SUPPORTED_ATTRS_MASK	(1ULL << (FATTR4_WORD0 + 0))
#define	FATTR4_TYPE_MASK		(1ULL << (FATTR4_WORD0 + 1))
#define	FATTR4_FH_EXPIRE_TYPE_MASK	(1ULL << (FATTR4_WORD0 + 2))
#define	FATTR4_CHANGE_MASK		(1ULL << (FATTR4_WORD0 + 3))
#define	FATTR4_SIZE_MASK		(1ULL << (FATTR4_WORD0 + 4))
#define	FATTR4_LINK_SUPPORT_MASK	(1ULL << (FATTR4_WORD0 + 5))
#define	FATTR4_SYMLINK_SUPPORT_MASK	(1ULL << (FATTR4_WORD0 + 6))
#define	FATTR4_NAMED_ATTR_MASK		(1ULL << (FATTR4_WORD0 + 7))
#define	FATTR4_FSID_MASK		(1ULL << (FATTR4_WORD0 + 8))
#define	FATTR4_UNIQUE_HANDLES_MASK	(1ULL << (FATTR4_WORD0 + 9))
#define	FATTR4_LEASE_TIME_MASK		(1ULL << (FATTR4_WORD0 + 10))
#define	FATTR4_RDATTR_ERROR_MASK	(1ULL << (FATTR4_WORD0 + 11))
#define	FATTR4_ACL_MASK			(1ULL << (FATTR4_WORD0 + 12))
#define	FATTR4_ACLSUPPORT_MASK		(1ULL << (FATTR4_WORD0 + 13))
#define	FATTR4_ARCHIVE_MASK		(1ULL << (FATTR4_WORD0 + 14))
#define	FATTR4_CANSETTIME_MASK		(1ULL << (FATTR4_WORD0 + 15))
#define	FATTR4_CASE_INSENSITIVE_MASK	(1ULL << (FATTR4_WORD0 + 16))
#define	FATTR4_CASE_PRESERVING_MASK	(1ULL << (FATTR4_WORD0 + 17))
#define	FATTR4_CHOWN_RESTRICTED_MASK	(1ULL << (FATTR4_WORD0 + 18))
#define	FATTR4_FILEHANDLE_MASK		(1ULL << (FATTR4_WORD0 + 19))
#define	FATTR4_FILEID_MASK		(1ULL << (FATTR4_WORD0 + 20))
#define	FATTR4_FILES_AVAIL_MASK		(1ULL << (FATTR4_WORD0 + 21))
#define	FATTR4_FILES_FREE_MASK		(1ULL << (FATTR4_WORD0 + 22))
#define	FATTR4_FILES_TOTAL_MASK		(1ULL << (FATTR4_WORD0 + 23))
#define	FATTR4_FS_LOCATIONS_MASK	(1ULL << (FATTR4_WORD0 + 24))
#define	FATTR4_HIDDEN_MASK		(1ULL << (FATTR4_WORD0 + 25))
#define	FATTR4_HOMOGENEOUS_MASK		(1ULL << (FATTR4_WORD0 + 26))
#define	FATTR4_MAXFILESIZE_MASK		(1ULL << (FATTR4_WORD0 + 27))
#define	FATTR4_MAXLINK_MASK		(1ULL << (FATTR4_WORD0 + 28))
#define	FATTR4_MAXNAME_MASK		(1ULL << (FATTR4_WORD0 + 29))
#define	FATTR4_MAXREAD_MASK		(1ULL << (FATTR4_WORD0 + 30))
#define	FATTR4_MAXWRITE_MASK		(1ULL << (FATTR4_WORD0 + 31))

#define	FATTR4_MIMETYPE_MASK		(1ULL << (FATTR4_WORD1 + 0))
#define	FATTR4_MODE_MASK		(1ULL << (FATTR4_WORD1 + 1))
#define	FATTR4_NO_TRUNC_MASK		(1ULL << (FATTR4_WORD1 + 2))
#define	FATTR4_NUMLINKS_MASK		(1ULL << (FATTR4_WORD1 + 3))
#define	FATTR4_OWNER_MASK		(1ULL << (FATTR4_WORD1 + 4))
#define	FATTR4_OWNER_GROUP_MASK		(1ULL << (FATTR4_WORD1 + 5))
#define	FATTR4_QUOTA_AVAIL_HARD_MASK	(1ULL << (FATTR4_WORD1 + 6))
#define	FATTR4_QUOTA_AVAIL_SOFT_MASK	(1ULL << (FATTR4_WORD1 + 7))
#define	FATTR4_QUOTA_USED_MASK		(1ULL << (FATTR4_WORD1 + 8))
#define	FATTR4_RAWDEV_MASK		(1ULL << (FATTR4_WORD1 + 9))
#define	FATTR4_SPACE_AVAIL_MASK		(1ULL << (FATTR4_WORD1 + 10))
#define	FATTR4_SPACE_FREE_MASK		(1ULL << (FATTR4_WORD1 + 11))
#define	FATTR4_SPACE_TOTAL_MASK		(1ULL << (FATTR4_WORD1 + 12))
#define	FATTR4_SPACE_USED_MASK		(1ULL << (FATTR4_WORD1 + 13))
#define	FATTR4_SYSTEM_MASK		(1ULL << (FATTR4_WORD1 + 14))
#define	FATTR4_TIME_ACCESS_MASK		(1ULL << (FATTR4_WORD1 + 15))
#define	FATTR4_TIME_ACCESS_SET_MASK	(1ULL << (FATTR4_WORD1 + 16))
#define	FATTR4_TIME_BACKUP_MASK		(1ULL << (FATTR4_WORD1 + 17))
#define	FATTR4_TIME_CREATE_MASK		(1ULL << (FATTR4_WORD1 + 18))
#define	FATTR4_TIME_DELTA_MASK		(1ULL << (FATTR4_WORD1 + 19))
#define	FATTR4_TIME_METADATA_MASK	(1ULL << (FATTR4_WORD1 + 20))
#define	FATTR4_TIME_MODIFY_MASK		(1ULL << (FATTR4_WORD1 + 21))
#define	FATTR4_TIME_MODIFY_SET_MASK	(1ULL << (FATTR4_WORD1 + 22))
#define	FATTR4_MOUNTED_ON_FILEID_MASK	(1ULL << (FATTR4_WORD1 + 23))

/*
 * Common bitmap4 of file attributes to be gathered
 */
#define	NFS4_NTOV_ATTR_MASK (		\
	FATTR4_TYPE_MASK |		\
	FATTR4_CHANGE_MASK |		\
	FATTR4_SIZE_MASK |		\
	FATTR4_FSID_MASK |		\
	FATTR4_FILEID_MASK |		\
	FATTR4_MODE_MASK |		\
	FATTR4_OWNER_MASK |		\
	FATTR4_OWNER_GROUP_MASK |	\
	FATTR4_NUMLINKS_MASK |		\
	FATTR4_TIME_ACCESS_MASK |	\
	FATTR4_TIME_MODIFY_MASK |	\
	FATTR4_TIME_METADATA_MASK |	\
	FATTR4_RAWDEV_MASK |		\
	FATTR4_SPACE_USED_MASK |	\
	FATTR4_MOUNTED_ON_FILEID_MASK)

#define	NFS4_VATTR_MASK (		\
	FATTR4_TYPE_MASK |		\
	FATTR4_CHANGE_MASK |		\
	FATTR4_SIZE_MASK |		\
	FATTR4_FSID_MASK |		\
	FATTR4_FILEID_MASK |		\
	FATTR4_MODE_MASK |		\
	FATTR4_OWNER_MASK |		\
	FATTR4_OWNER_GROUP_MASK |	\
	FATTR4_NUMLINKS_MASK |		\
	FATTR4_TIME_ACCESS_MASK |	\
	FATTR4_TIME_MODIFY_MASK |	\
	FATTR4_TIME_METADATA_MASK |	\
	FATTR4_RAWDEV_MASK |		\
	FATTR4_SPACE_USED_MASK |	\
	FATTR4_MOUNTED_ON_FILEID_MASK)

#define	NFS4_PATHCONF_MASK (		\
	NFS4_VATTR_MASK |		\
	FATTR4_NO_TRUNC_MASK |		\
	FATTR4_CHOWN_RESTRICTED_MASK |	\
	FATTR4_CASE_INSENSITIVE_MASK |	\
	FATTR4_CASE_PRESERVING_MASK |	\
	FATTR4_NAMED_ATTR_MASK |	\
	FATTR4_LINK_SUPPORT_MASK |	\
	FATTR4_SYMLINK_SUPPORT_MASK |	\
	FATTR4_UNIQUE_HANDLES_MASK |	\
	FATTR4_CANSETTIME_MASK |	\
	FATTR4_HOMOGENEOUS_MASK |	\
	FATTR4_MAXLINK_MASK |		\
	FATTR4_MAXNAME_MASK |		\
	FATTR4_MAXFILESIZE_MASK)

/*
 * The corresponding AT_MASK
 */
#define	NFS4_NTOV_ATTR_AT_MASK (	\
	AT_TYPE |			\
	AT_SIZE |			\
	AT_FSID |			\
	AT_NODEID |			\
	AT_MODE |			\
	AT_UID |			\
	AT_GID |			\
	AT_NLINK |			\
	AT_ATIME |			\
	AT_MTIME |			\
	AT_CTIME |			\
	AT_RDEV |			\
	AT_NBLOCKS)

/*
 * Common bitmap4 of filesystem attributes to be gathered
 */
#define	NFS4_FS_ATTR_MASK (		\
	FATTR4_FILES_AVAIL_MASK |	\
	FATTR4_FILES_FREE_MASK |	\
	FATTR4_FILES_TOTAL_MASK |	\
	FATTR4_SPACE_AVAIL_MASK |	\
	FATTR4_SPACE_FREE_MASK |	\
	FATTR4_SPACE_TOTAL_MASK)

#define	NFS4_STATFS_ATTR_MASK (		\
	FATTR4_FILES_AVAIL_MASK |	\
	FATTR4_FILES_FREE_MASK |	\
	FATTR4_FILES_TOTAL_MASK |	\
	FATTR4_SPACE_AVAIL_MASK |	\
	FATTR4_SPACE_FREE_MASK |	\
	FATTR4_SPACE_TOTAL_MASK |	\
	FATTR4_MAXNAME_MASK)

/*
 * The corresponding AT_MASK
 */
#define	NFS4_FS_ATTR_AT_MASK	0

/*
 * Common bitmap4 to gather attr cache state
 */
#define	NFS4_NTOV_ATTR_CACHE_MASK (	\
	FATTR4_TIME_METADATA_MASK |	\
	FATTR4_TIME_MODIFY_MASK |	\
	FATTR4_SIZE_MASK)

/*
 * The corresponding AT_MASK
 */
#define	NFS4_NTOV_ATTR_CACHE_AT_MASK (	\
	AT_CTIME |			\
	AT_MTIME |			\
	AT_SIZE)

#define	NFS4_VTON_ATTR_MASK (		\
	AT_TYPE |			\
	AT_MODE |			\
	AT_UID |			\
	AT_GID |			\
	AT_NODEID |			\
	AT_SIZE |			\
	AT_NLINK |			\
	AT_ATIME |			\
	AT_MTIME |			\
	AT_CTIME |			\
	AT_RDEV |			\
	AT_NBLOCKS |			\
	AT_FSID)

#define	NFS4_VTON_ATTR_MASK_SET (	\
	AT_MODE |			\
	AT_UID |			\
	AT_GID |			\
	AT_SIZE |			\
	AT_ATIME |			\
	AT_MTIME)

/* solaris-supported, non-vattr_t per-vnode scoped attrs */
#define	NFS4_VP_ATTR_MASK (		\
	FATTR4_CHANGE_MASK |		\
	FATTR4_CHOWN_RESTRICTED_MASK |	\
	FATTR4_FILEHANDLE_MASK |	\
	FATTR4_MAXFILESIZE_MASK |	\
	FATTR4_MAXLINK_MASK |		\
	FATTR4_MAXNAME_MASK |		\
	FATTR4_MOUNTED_ON_FILEID_MASK)

#define	FATTR4_FSINFO_MASK (		\
	FATTR4_SUPPORTED_ATTRS_MASK |	\
	FATTR4_TYPE_MASK |		\
	FATTR4_FH_EXPIRE_TYPE_MASK |	\
	FATTR4_LINK_SUPPORT_MASK |	\
	FATTR4_SYMLINK_SUPPORT_MASK |	\
	FATTR4_FSID_MASK |		\
	FATTR4_MAXFILESIZE_MASK |	\
	FATTR4_MAXREAD_MASK |		\
	FATTR4_MAXWRITE_MASK)

/*
 * These are the support attributes for the NFSv4 server
 */
#define	NFS4_SRV_RDDIR_SUPPORTED_ATTRS (	\
	FATTR4_SUPPORTED_ATTRS_MASK |	\
	FATTR4_TYPE_MASK |		\
	FATTR4_FH_EXPIRE_TYPE_MASK |	\
	FATTR4_CHANGE_MASK |		\
	FATTR4_SIZE_MASK |		\
	FATTR4_LINK_SUPPORT_MASK |	\
	FATTR4_SYMLINK_SUPPORT_MASK |	\
	FATTR4_NAMED_ATTR_MASK |	\
	FATTR4_FSID_MASK |		\
	FATTR4_UNIQUE_HANDLES_MASK |	\
	FATTR4_LEASE_TIME_MASK |	\
	FATTR4_RDATTR_ERROR_MASK |	\
	FATTR4_CANSETTIME_MASK |	\
	FATTR4_CASE_INSENSITIVE_MASK |	\
	FATTR4_CASE_PRESERVING_MASK |	\
	FATTR4_CHOWN_RESTRICTED_MASK |	\
	FATTR4_FILEHANDLE_MASK |	\
	FATTR4_FILEID_MASK |		\
	FATTR4_FILES_AVAIL_MASK |	\
	FATTR4_FILES_FREE_MASK |	\
	FATTR4_FILES_TOTAL_MASK |	\
	FATTR4_FS_LOCATIONS_MASK |	\
	FATTR4_HOMOGENEOUS_MASK |	\
	FATTR4_MAXFILESIZE_MASK |	\
	FATTR4_MAXLINK_MASK |		\
	FATTR4_MAXNAME_MASK |		\
	FATTR4_MAXREAD_MASK |		\
	FATTR4_MAXWRITE_MASK |		\
	FATTR4_MODE_MASK |		\
	FATTR4_NO_TRUNC_MASK |		\
	FATTR4_NUMLINKS_MASK |		\
	FATTR4_OWNER_MASK |		\
	FATTR4_OWNER_GROUP_MASK |	\
	FATTR4_RAWDEV_MASK |		\
	FATTR4_SPACE_AVAIL_MASK |	\
	FATTR4_SPACE_FREE_MASK |	\
	FATTR4_SPACE_TOTAL_MASK |	\
	FATTR4_SPACE_USED_MASK |	\
	FATTR4_TIME_ACCESS_MASK |	\
	FATTR4_TIME_DELTA_MASK |	\
	FATTR4_TIME_METADATA_MASK |	\
	FATTR4_TIME_MODIFY_MASK |	\
	FATTR4_MOUNTED_ON_FILEID_MASK	\
)


#define	FATTR4_FSID_EQ(a, b)	\
	((a)->major == (b)->major && (a)->minor == (b)->minor)

#define	NFS4_MAXNUM_BITWORDS	2
#define	NFS4_MAXNUM_ATTRS	56

union nfs4_attr_u {
	fattr4_supported_attrs		supported_attrs;
	fattr4_type			type;
	fattr4_fh_expire_type		fh_expire_type;
	fattr4_change			change;
	fattr4_size			size;
	fattr4_link_support		link_support;
	fattr4_symlink_support		symlink_support;
	fattr4_named_attr		named_attr;
	fattr4_fsid			fsid;
	fattr4_unique_handles		unique_handles;
	fattr4_lease_time		lease_time;
	fattr4_rdattr_error		rdattr_error;
	fattr4_acl			acl;
	fattr4_aclsupport		aclsupport;
	fattr4_archive			archive;
	fattr4_cansettime		cansettime;
	fattr4_case_insensitive		case_insensitive;
	fattr4_case_preserving		case_preserving;
	fattr4_chown_restricted		chown_restricted;
	fattr4_fileid			fileid;
	fattr4_files_avail		files_avail;
	fattr4_filehandle		filehandle;
	fattr4_files_free		files_free;
	fattr4_files_total		files_total;
	fattr4_fs_locations		fs_locations;
	fattr4_hidden			hidden;
	fattr4_homogeneous		homogeneous;
	fattr4_maxfilesize		maxfilesize;
	fattr4_maxlink			maxlink;
	fattr4_maxname			maxname;
	fattr4_maxread			maxread;
	fattr4_maxwrite			maxwrite;
	fattr4_mimetype			mimetype;
	fattr4_mode			mode;
	fattr4_no_trunc			no_trunc;
	fattr4_numlinks			numlinks;
	fattr4_owner			owner;
	fattr4_owner_group		owner_group;
	fattr4_quota_avail_hard		quota_avail_hard;
	fattr4_quota_avail_soft		quota_avail_soft;
	fattr4_quota_used		quota_used;
	fattr4_rawdev			rawdev;
	fattr4_space_avail		space_avail;
	fattr4_space_free		space_free;
	fattr4_space_total		space_total;
	fattr4_space_used		space_used;
	fattr4_system			system;
	fattr4_time_access		time_access;
	fattr4_time_access_set		time_access_set;
	fattr4_time_backup		time_backup;
	fattr4_time_create		time_create;
	fattr4_time_delta		time_delta;
	fattr4_time_metadata		time_metadata;
	fattr4_time_modify		time_modify;
	fattr4_time_modify_set		time_modify_set;
	fattr4_mounted_on_fileid	mounted_on_fileid;
};

/*
 * Error details when processing the getattr response.
 */
#define	NFS4_GETATTR_OP_OK		0
#define	NFS4_GETATTR_STATUS_ERR		1
#define	NFS4_GETATTR_MANDATTR_ERR	2
#define	NFS4_GETATTR_BITMAP_ERR		3
#define	NFS4_GETATTR_ATSIZE_ERR		4
#define	NFS4_GETATTR_ATUID_ERR		5
#define	NFS4_GETATTR_ATGID_ERR		6
#define	NFS4_GETATTR_ATATIME_ERR	7
#define	NFS4_GETATTR_ATMTIME_ERR	8
#define	NFS4_GETATTR_ATCTIME_ERR	9
#define	NFS4_GETATTR_RAWDEV_ERR		10
#define	NFS4_GETATTR_ATNBLOCK_ERR	11
#define	NFS4_GETATTR_MAXFILESIZE_ERR	12
#define	NFS4_GETATTR_FHANDLE_ERR	13
#define	NFS4_GETATTR_MAXREAD_ERR	14
#define	NFS4_GETATTR_MAXWRITE_ERR	15
#define	NFS4_GETATTR_NOCACHE_OK		16

typedef struct nfs4_pathconf_info {
	unsigned pc4_cache_valid:1;	/* When in rnode4, is data valid? */
	unsigned pc4_no_trunc:1;
	unsigned pc4_chown_restricted:1;
	unsigned pc4_case_insensitive:1;
	unsigned pc4_case_preserving:1;
	unsigned pc4_xattr_valid:1;
	unsigned pc4_xattr_exists:1;
	unsigned pc4_link_support:1;
	unsigned pc4_symlink_support:1;
	unsigned pc4_unique_handles:1;
	unsigned pc4_cansettime:1;
	unsigned pc4_homogeneous:1;
	uint_t	pc4_link_max;
	uint_t	pc4_name_max;
	uint_t	pc4_filesizebits;
} nfs4_pathconf_info_t;

/*
 * Used for client only to process incoming getattr results.
 */
typedef struct nfs4_ga_ext_res {
	bitmap4				n4g_suppattrs;
	nfsstat4			n4g_rdattr_error;
	fattr4_fh_expire_type		n4g_fet;
	fattr4_lease_time		n4g_leasetime;
	uint64_t			n4g_maxfilesize;
	uint64_t			n4g_maxread;
	uint64_t			n4g_maxwrite;
	nfstime4			n4g_delta;
	nfs4_pathconf_info_t		n4g_pc4;
	struct statvfs64		n4g_sb;
	union {
		nfs_fh4 n4g_fh;
		struct {
			uint_t len;
			char *val;
			char data[NFS4_FHSIZE];
		} nfs_fh4_alt;
	} n4g_fh_u;
	/*
	 * Bitmask with valid fields being:
	 * ACL4_SUPPORT_ALLOW_ACL
	 * ACL4_SUPPORT_DENY_ACL
	 * ACL4_SUPPORT_AUDIT_ACL
	 * ACL4_SUPPORT_ALARM_ACL
	 */
	fattr4_aclsupport		n4g_aclsupport;
	fattr4_fs_locations		n4g_fslocations;
} nfs4_ga_ext_res_t;

extern bitmap4 rfs4_supported_attrs;

#ifdef	__cplusplus
}
#endif

#endif /* _NFS4_ATTR_H */
