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
 * Copyright 2015 Nexenta Systems, Inc.  All rights reserved.
 * Copyright 2020 RackTop Systems, Inc.
 */

/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _NFS4_KPROT_H
#define	_NFS4_KPROT_H

/*
 * Kernel specific version.
 * NFS Version 4 protocol definitions.  From nfs4_prot.x RFC 5662
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <rpc/rpc.h>
#ifdef _KERNEL
#include <rpc/rpc_rdma.h>
#endif
#include <sys/stream.h>

#include <rpc/auth_sys.h>
typedef struct authsys_parms authsys_parms;

#define	NFS4_FHSIZE 128
#define	NFS4_VERIFIER_SIZE 8
#define	NFS4_OTHER_SIZE 12

/*
 * Reasonable upper bounds to catch badly behaving partners
 */
#define	NFS4_OPAQUE_LIMIT	1024
#define	NFS4_COMPOUND_LIMIT	2048
#define	NFS4_FS_LOCATIONS_LIMIT	65536
#define	NFS4_ACL_LIMIT		65536
#define	NFS4_SECINFO_LIMIT	65536
#define	NFS4_FATTR4_LIMIT	1048576
#define	NFS4_DATA_LIMIT		134217728

#define	NFS4_SESSIONID_SIZE	16

enum nfs_ftype4 {
	NF4REG = 1,
	NF4DIR = 2,
	NF4BLK = 3,
	NF4CHR = 4,
	NF4LNK = 5,
	NF4SOCK = 6,
	NF4FIFO = 7,
	NF4ATTRDIR = 8,
	NF4NAMEDATTR = 9
};
typedef enum nfs_ftype4 nfs_ftype4;

enum nfsstat4 {
	NFS4_OK = 0,
	NFS4ERR_PERM = 1,
	NFS4ERR_NOENT = 2,
	NFS4ERR_IO = 5,
	NFS4ERR_NXIO = 6,
	NFS4ERR_ACCESS = 13,
	NFS4ERR_EXIST = 17,
	NFS4ERR_XDEV = 18,
	NFS4ERR_NOTDIR = 20,
	NFS4ERR_ISDIR = 21,
	NFS4ERR_INVAL = 22,
	NFS4ERR_FBIG = 27,
	NFS4ERR_NOSPC = 28,
	NFS4ERR_ROFS = 30,
	NFS4ERR_MLINK = 31,
	NFS4ERR_NAMETOOLONG = 63,
	NFS4ERR_NOTEMPTY = 66,
	NFS4ERR_DQUOT = 69,
	NFS4ERR_STALE = 70,
	NFS4ERR_BADHANDLE = 10001,
	NFS4ERR_BAD_COOKIE = 10003,
	NFS4ERR_NOTSUPP = 10004,
	NFS4ERR_TOOSMALL = 10005,
	NFS4ERR_SERVERFAULT = 10006,
	NFS4ERR_BADTYPE = 10007,
	NFS4ERR_DELAY = 10008,
	NFS4ERR_SAME = 10009,
	NFS4ERR_DENIED = 10010,
	NFS4ERR_EXPIRED = 10011,
	NFS4ERR_LOCKED = 10012,
	NFS4ERR_GRACE = 10013,
	NFS4ERR_FHEXPIRED = 10014,
	NFS4ERR_SHARE_DENIED = 10015,
	NFS4ERR_WRONGSEC = 10016,
	NFS4ERR_CLID_INUSE = 10017,
	NFS4ERR_RESOURCE = 10018,
	NFS4ERR_MOVED = 10019,
	NFS4ERR_NOFILEHANDLE = 10020,
	NFS4ERR_MINOR_VERS_MISMATCH = 10021,
	NFS4ERR_STALE_CLIENTID = 10022,
	NFS4ERR_STALE_STATEID = 10023,
	NFS4ERR_OLD_STATEID = 10024,
	NFS4ERR_BAD_STATEID = 10025,
	NFS4ERR_BAD_SEQID = 10026,
	NFS4ERR_NOT_SAME = 10027,
	NFS4ERR_LOCK_RANGE = 10028,
	NFS4ERR_SYMLINK = 10029,
	NFS4ERR_RESTOREFH = 10030,
	NFS4ERR_LEASE_MOVED = 10031,
	NFS4ERR_ATTRNOTSUPP = 10032,
	NFS4ERR_NO_GRACE = 10033,
	NFS4ERR_RECLAIM_BAD = 10034,
	NFS4ERR_RECLAIM_CONFLICT = 10035,
	NFS4ERR_BADXDR = 10036,
	NFS4ERR_LOCKS_HELD = 10037,
	NFS4ERR_OPENMODE = 10038,
	NFS4ERR_BADOWNER = 10039,
	NFS4ERR_BADCHAR = 10040,
	NFS4ERR_BADNAME = 10041,
	NFS4ERR_BAD_RANGE = 10042,
	NFS4ERR_LOCK_NOTSUPP = 10043,
	NFS4ERR_OP_ILLEGAL = 10044,
	NFS4ERR_DEADLOCK = 10045,
	NFS4ERR_FILE_OPEN = 10046,
	NFS4ERR_ADMIN_REVOKED = 10047,
	NFS4ERR_CB_PATH_DOWN = 10048,
	NFS4ERR_BADIOMODE = 10049,	/*  nfsv4.1 */
	NFS4ERR_BADLAYOUT = 10050,
	NFS4ERR_BAD_SESSION_DIGEST = 10051,
	NFS4ERR_BADSESSION = 10052,
	NFS4ERR_BADSLOT = 10053,
	NFS4ERR_COMPLETE_ALREADY = 10054,
	NFS4ERR_CONN_NOT_BOUND_TO_SESSION = 10055,
	NFS4ERR_DELEG_ALREADY_WANTED = 10056,
	NFS4ERR_BACK_CHAN_BUSY = 10057,
	NFS4ERR_LAYOUTTRYLATER = 10058,
	NFS4ERR_LAYOUTUNAVAILABLE = 10059,
	NFS4ERR_NOMATCHING_LAYOUT = 10060,
	NFS4ERR_RECALLCONFLICT = 10061,
	NFS4ERR_UNKNOWN_LAYOUTTYPE = 10062,
	NFS4ERR_SEQ_MISORDERED = 10063,
	NFS4ERR_SEQUENCE_POS = 10064,
	NFS4ERR_REQ_TOO_BIG = 10065,
	NFS4ERR_REP_TOO_BIG = 10066,
	NFS4ERR_REP_TOO_BIG_TO_CACHE = 10067,
	NFS4ERR_RETRY_UNCACHED_REP = 10068,
	NFS4ERR_UNSAFE_COMPOUND = 10069,
	NFS4ERR_TOO_MANY_OPS = 10070,
	NFS4ERR_OP_NOT_IN_SESSION = 10071,
	NFS4ERR_HASH_ALG_UNSUPP = 10072,
	NFS4ERR_CLIENTID_BUSY = 10074,
	NFS4ERR_PNFS_IO_HOLE = 10075,
	NFS4ERR_SEQ_FALSE_RETRY = 10076,
	NFS4ERR_BAD_HIGH_SLOT = 10077,
	NFS4ERR_DEADSESSION = 10078,
	NFS4ERR_ENCR_ALG_UNSUPP = 10079,
	NFS4ERR_PNFS_NO_LAYOUT = 10080,
	NFS4ERR_NOT_ONLY_OP = 10081,
	NFS4ERR_WRONG_CRED = 10082,
	NFS4ERR_WRONG_TYPE = 10083,
	NFS4ERR_DIRDELEG_UNAVAIL = 10084,
	NFS4ERR_REJECT_DELEG = 10085,
	NFS4ERR_RETURNCONFLICT = 10086,
	NFS4ERR_DELEG_REVOKED = 10087,

	/* for internal use */
	NFS4ERR_REPLAY_CACHE = 30000
};
typedef enum nfsstat4 nfsstat4;

/*
 * A bitmap can only be 56 bits, treat it as a uint64_t for now
 */
typedef uint64_t bitmap4;

typedef struct {
	uint_t attrlist4_len;
	char *attrlist4_val;
} attrlist4;

typedef uint64_t offset4;

typedef uint32_t count4;

typedef uint64_t length4;

typedef uint64_t clientid4;

typedef uint32_t nfs_lease4;

typedef uint32_t seqid4;

typedef uint32_t sequenceid4;

typedef char sessionid4[NFS4_SESSIONID_SIZE];

typedef uint32_t slotid4;

typedef struct {
	uint_t utf8string_len;
	char *utf8string_val;
} utf8string;

typedef utf8string component4;

typedef utf8string utf8str_cis;

typedef utf8string utf8str_cs;

typedef utf8string utf8str_mixed;

typedef struct {
	uint_t pathname4_len;
	component4 *pathname4_val;
} pathname4;

typedef uint64_t nfs_cookie4;

typedef struct {
	uint_t linktext4_len;
	char *linktext4_val;
} linktext4;

typedef utf8string ascii_REQUIRED4;

typedef struct {
	uint_t sec_oid4_len;
	char *sec_oid4_val;
} sec_oid4;

typedef uint32_t qop4;

typedef uint32_t mode4;

typedef uint64_t changeid4;

typedef uint64_t verifier4;

struct nfstime4 {
	int64_t seconds;
	uint32_t nseconds;
};
typedef struct nfstime4 nfstime4;

enum time_how4 {
	SET_TO_SERVER_TIME4 = 0,
	SET_TO_CLIENT_TIME4 = 1
};
typedef enum time_how4 time_how4;

struct settime4 {
	time_how4 set_it;
	nfstime4 time;
};
typedef struct settime4 settime4;

typedef struct {
	uint_t nfs_fh4_len;
	char *nfs_fh4_val;
} nfs_fh4;

struct fsid4 {
	uint64_t major;
	uint64_t minor;
};
typedef struct fsid4 fsid4;

struct change_policy4 {
	uint64_t cp_major;
	uint64_t cp_minor;
};
typedef struct change_policy4 change_policy4;

struct fs_location4 {
	uint_t server_len;
	utf8string *server_val;
	pathname4 rootpath;
};
typedef struct fs_location4 fs_location4;

struct fs_locations4 {
	pathname4 fs_root;
	uint_t locations_len;
	fs_location4 *locations_val;
};
typedef struct fs_locations4 fs_locations4;

/*
 * This structure is declared in nfs4.h
 */
struct nfs_fsl_info;

/*
 * ACL support
 */

#define	ACL4_SUPPORT_ALLOW_ACL 0x00000001
#define	ACL4_SUPPORT_DENY_ACL 0x00000002
#define	ACL4_SUPPORT_AUDIT_ACL 0x00000004
#define	ACL4_SUPPORT_ALARM_ACL 0x00000008

typedef uint32_t acetype4;
#define	ACE4_ACCESS_ALLOWED_ACE_TYPE 0x00000000
#define	ACE4_ACCESS_DENIED_ACE_TYPE 0x00000001
#define	ACE4_SYSTEM_AUDIT_ACE_TYPE 0x00000002
#define	ACE4_SYSTEM_ALARM_ACE_TYPE 0x00000003

typedef uint32_t aceflag4;
#define	ACE4_FILE_INHERIT_ACE 0x00000001
#define	ACE4_DIRECTORY_INHERIT_ACE 0x00000002
#define	ACE4_NO_PROPAGATE_INHERIT_ACE 0x00000004
#define	ACE4_INHERIT_ONLY_ACE 0x00000008
#define	ACE4_SUCCESSFUL_ACCESS_ACE_FLAG 0x00000010
#define	ACE4_FAILED_ACCESS_ACE_FLAG 0x00000020
#define	ACE4_IDENTIFIER_GROUP 0x00000040
#define	ACE4_INHERITED_ACE 0x00000080

/*
 * This defines all valid flag bits, as defined by RFC 7530.  If
 * any additional flag bits are deemed part of the NFSv4 spec,
 * you must also add them to the definition below.
 */
#define	ACE4_VALID_FLAG_BITS (\
    ACE4_FILE_INHERIT_ACE | \
    ACE4_DIRECTORY_INHERIT_ACE | \
    ACE4_NO_PROPAGATE_INHERIT_ACE | \
    ACE4_INHERIT_ONLY_ACE | \
    ACE4_SUCCESSFUL_ACCESS_ACE_FLAG | \
    ACE4_FAILED_ACCESS_ACE_FLAG | \
    ACE4_IDENTIFIER_GROUP)

typedef uint32_t acemask4;
#define	ACE4_READ_DATA 0x00000001
#define	ACE4_LIST_DIRECTORY 0x00000001
#define	ACE4_WRITE_DATA 0x00000002
#define	ACE4_ADD_FILE 0x00000002
#define	ACE4_APPEND_DATA 0x00000004
#define	ACE4_ADD_SUBDIRECTORY 0x00000004
#define	ACE4_READ_NAMED_ATTRS 0x00000008
#define	ACE4_WRITE_NAMED_ATTRS 0x00000010
#define	ACE4_EXECUTE 0x00000020
#define	ACE4_DELETE_CHILD 0x00000040
#define	ACE4_READ_ATTRIBUTES 0x00000080
#define	ACE4_WRITE_ATTRIBUTES 0x00000100
#define	ACE4_WRITE_RETENTION 0x00000200
#define	ACE4_WRITE_RETENTION_HOLD 0x00000400
#define	ACE4_DELETE 0x00010000
#define	ACE4_READ_ACL 0x00020000
#define	ACE4_WRITE_ACL 0x00040000
#define	ACE4_WRITE_OWNER 0x00080000
#define	ACE4_SYNCHRONIZE 0x00100000
#define	ACE4_GENERIC_READ 0x00120081
#define	ACE4_GENERIC_WRITE 0x00160106
#define	ACE4_GENERIC_EXECUTE 0x001200A0
/*
 * This defines all valid access mask bits, as defined by RFC 7530.  If
 * any additional access mask bits are deemed part of the NFSv4 spec,
 * you must also add them to the definition below.
 */
#define	ACE4_VALID_MASK_BITS (\
    ACE4_READ_DATA | \
    ACE4_LIST_DIRECTORY | \
    ACE4_WRITE_DATA | \
    ACE4_ADD_FILE | \
    ACE4_APPEND_DATA | \
    ACE4_ADD_SUBDIRECTORY | \
    ACE4_READ_NAMED_ATTRS | \
    ACE4_WRITE_NAMED_ATTRS | \
    ACE4_EXECUTE | \
    ACE4_DELETE_CHILD | \
    ACE4_READ_ATTRIBUTES | \
    ACE4_WRITE_ATTRIBUTES | \
    ACE4_DELETE | \
    ACE4_READ_ACL | \
    ACE4_WRITE_ACL | \
    ACE4_WRITE_OWNER | \
    ACE4_SYNCHRONIZE)

/* Used to signify an undefined value for an acemask4 */
#define	ACE4_MASK_UNDEFINED 0x80000000

#define	ACE4_WHO_OWNER		"OWNER@"
#define	ACE4_WHO_GROUP		"GROUP@"
#define	ACE4_WHO_EVERYONE	"EVERYONE@"

struct nfsace4 {
	acetype4 type;
	aceflag4 flag;
	acemask4 access_mask;
	utf8string who;
};
typedef struct nfsace4 nfsace4;

typedef uint32_t aclflag4;		/* 4.1 */
#define	ACL4_AUTO_INHERIT 0x00000001
#define	ACL4_PROTECTED 0x00000002
#define	ACL4_DEFAULTED 0x00000004

struct nfsacl41 {			/* 4.1 */
	aclflag4 na41_flag;
	struct {
		uint_t na41_aces_len;
		nfsace4 *na41_aces_val;
	} na41_aces;
};
typedef struct nfsacl41 nfsacl41;

#define	MODE4_SUID 0x800
#define	MODE4_SGID 0x400
#define	MODE4_SVTX 0x200
#define	MODE4_RUSR 0x100
#define	MODE4_WUSR 0x080
#define	MODE4_XUSR 0x040
#define	MODE4_RGRP 0x020
#define	MODE4_WGRP 0x010
#define	MODE4_XGRP 0x008
#define	MODE4_ROTH 0x004
#define	MODE4_WOTH 0x002
#define	MODE4_XOTH 0x001

struct mode_masked4 {			/* 4.1 */
	mode4 mm_value_to_set;
	mode4 mm_mask_bits;
};
typedef struct mode_masked4 mode_masked4;

/*
 * ACL conversion helpers
 */

typedef enum {
	ace4_unused,
	ace4_user_obj,
	ace4_user,
	ace4_group, /* includes GROUP and GROUP_OBJ */
	ace4_other_obj
} ace4_to_aent_state_t;

typedef struct ace4vals {
	utf8string *key; /* NB: not allocated here; points to existing utf8 */
	avl_node_t avl;
	acemask4 mask;
	acemask4 allowed;
	acemask4 denied;
	int aent_type;
} ace4vals_t;

typedef struct ace4_list {
	ace4vals_t user_obj;
	avl_tree_t user;
	int numusers;
	ace4vals_t group_obj;
	avl_tree_t group;
	int numgroups;
	ace4vals_t other_obj;
	acemask4 acl_mask;
	int hasmask;
	int dfacl_flag;
	ace4_to_aent_state_t state;
	int seen; /* bitmask of all aclent_t a_type values seen */
} ace4_list_t;

struct specdata4 {
	uint32_t specdata1;
	uint32_t specdata2;
};
typedef struct specdata4 specdata4;
#define	FH4_PERSISTENT 0x00000000
#define	FH4_NOEXPIRE_WITH_OPEN 0x00000001
#define	FH4_VOLATILE_ANY 0x00000002
#define	FH4_VOL_MIGRATION 0x00000004
#define	FH4_VOL_RENAME 0x00000008

/*
 * nfsv4.1
 */
struct netaddr4 {
	char *na_r_netid;
	char *na_r_addr;
};
typedef struct netaddr4 netaddr4;

struct nfs_impl_id4 {
	utf8str_cis nii_domain;
	utf8str_cs nii_name;
	nfstime4 nii_date;
};
typedef struct nfs_impl_id4 nfs_impl_id4;

struct stateid4 {
	uint32_t seqid;
	char other[NFS4_OTHER_SIZE];
};
typedef struct stateid4 stateid4;

enum layouttype4 {
	LAYOUT4_NFSV4_1_FILES = 0x1,
	LAYOUT4_OSD2_OBJECTS = 0x2,
	LAYOUT4_BLOCK_VOLUME = 0x3
};
typedef enum layouttype4 layouttype4;

struct layout_content4 {
	layouttype4 loc_type;
	struct {
		uint_t loc_body_len;
		char *loc_body_val;
	} loc_body;
};
typedef struct layout_content4 layout_content4;

/*
 * LAYOUT4_OSD2_OBJECTS loc_body description
 * is in a separate .x file
 */

/*
 * LAYOUT4_BLOCK_VOLUME loc_body description
 * is in a separate .x file
 */

struct layouthint4 {
	layouttype4 loh_type;
	struct {
		uint_t loh_body_len;
		char *loh_body_val;
	} loh_body;
};
typedef struct layouthint4 layouthint4;

enum layoutiomode4 {
	LAYOUTIOMODE4_READ = 1,
	LAYOUTIOMODE4_RW = 2,
	LAYOUTIOMODE4_ANY = 3
};
typedef enum layoutiomode4 layoutiomode4;

struct layout4 {
	offset4 lo_offset;
	length4 lo_length;
	layoutiomode4 lo_iomode;
	layout_content4 lo_content;
};
typedef struct layout4 layout4;
#define	NFS4_DEVICEID4_SIZE 16

typedef char deviceid4[NFS4_DEVICEID4_SIZE];

struct device_addr4 {
	layouttype4 da_layout_type;
	struct {
		uint_t da_addr_body_len;
		char *da_addr_body_val;
	} da_addr_body;
};
typedef struct device_addr4 device_addr4;

struct layoutupdate4 {
	layouttype4 lou_type;
	struct {
		uint_t lou_body_len;
		char *lou_body_val;
	} lou_body;
};
typedef struct layoutupdate4 layoutupdate4;

#define	LAYOUT4_RET_REC_FILE 1
#define	LAYOUT4_RET_REC_FSID 2
#define	LAYOUT4_RET_REC_ALL 3

enum layoutreturn_type4 {
	LAYOUTRETURN4_FILE = LAYOUT4_RET_REC_FILE,
	LAYOUTRETURN4_FSID = LAYOUT4_RET_REC_FSID,
	LAYOUTRETURN4_ALL = LAYOUT4_RET_REC_ALL
};
typedef enum layoutreturn_type4 layoutreturn_type4;

/* layouttype4 specific data */

struct layoutreturn_file4 {
	offset4 lrf_offset;
	length4 lrf_length;
	stateid4 lrf_stateid;
	struct {
		uint_t lrf_body_len;
		char *lrf_body_val;
	} lrf_body;
};
typedef struct layoutreturn_file4 layoutreturn_file4;

struct layoutreturn4 {
	layoutreturn_type4 lr_returntype;
	union {
		layoutreturn_file4 lr_layout;
	} layoutreturn4_u;
};
typedef struct layoutreturn4 layoutreturn4;

enum fs4_status_type {
	STATUS4_FIXED = 1,
	STATUS4_UPDATED = 2,
	STATUS4_VERSIONED = 3,
	STATUS4_WRITABLE = 4,
	STATUS4_REFERRAL = 5
};
typedef enum fs4_status_type fs4_status_type;

struct fs4_status {
	bool_t fss_absent;
	fs4_status_type fss_type;
	utf8str_cs fss_source;
	utf8str_cs fss_current;
	int32_t fss_age;
	nfstime4 fss_version;
};
typedef struct fs4_status fs4_status;

#define	TH4_READ_SIZE 0
#define	TH4_WRITE_SIZE 1
#define	TH4_READ_IOSIZE 2
#define	TH4_WRITE_IOSIZE 3

typedef length4 threshold4_read_size;

typedef length4 threshold4_write_size;

typedef length4 threshold4_read_iosize;

typedef length4 threshold4_write_iosize;

struct threshold_item4 {
	layouttype4 thi_layout_type;
	bitmap4 thi_hintset;
	struct {
		uint_t thi_hintlist_len;
		char *thi_hintlist_val;
	} thi_hintlist;
};
typedef struct threshold_item4 threshold_item4;

struct mdsthreshold4 {
	struct {
		uint_t mth_hints_len;
		threshold_item4 *mth_hints_val;
	} mth_hints;
};
typedef struct mdsthreshold4 mdsthreshold4;
#define	RET4_DURATION_INFINITE 0xffffffffffffffff

struct retention_get4 {
	uint64_t rg_duration;
	struct {
		uint_t rg_begin_time_len;
		nfstime4 *rg_begin_time_val;
	} rg_begin_time;
};
typedef struct retention_get4 retention_get4;

struct retention_set4 {
	bool_t rs_enable;
	struct {
		uint_t rs_duration_len;
		uint64_t *rs_duration_val;
	} rs_duration;
};
typedef struct retention_set4 retention_set4;
#define	FSCHARSET_CAP4_CONTAINS_NON_UTF8 0x1
#define	FSCHARSET_CAP4_ALLOWS_ONLY_UTF8 0x2

typedef uint32_t fs_charset_cap4;

/* nfsv4.1 end */

typedef bitmap4 fattr4_supported_attrs;

typedef nfs_ftype4 fattr4_type;

typedef uint32_t fattr4_fh_expire_type;

typedef changeid4 fattr4_change;

typedef uint64_t fattr4_size;

typedef bool_t fattr4_link_support;

typedef bool_t fattr4_symlink_support;

typedef bool_t fattr4_named_attr;

typedef fsid4 fattr4_fsid;

typedef bool_t fattr4_unique_handles;

typedef nfs_lease4 fattr4_lease_time;

typedef nfsstat4 fattr4_rdattr_error;

typedef struct {
	uint_t fattr4_acl_len;
	nfsace4 *fattr4_acl_val;
} fattr4_acl;

typedef uint32_t fattr4_aclsupport;

typedef bool_t fattr4_archive;

typedef bool_t fattr4_cansettime;

typedef bool_t fattr4_case_insensitive;

typedef bool_t fattr4_case_preserving;

typedef bool_t fattr4_chown_restricted;

typedef uint64_t fattr4_fileid;

typedef uint64_t fattr4_files_avail;

typedef nfs_fh4 fattr4_filehandle;

typedef uint64_t fattr4_files_free;

typedef uint64_t fattr4_files_total;

typedef fs_locations4 fattr4_fs_locations;

typedef bool_t fattr4_hidden;

typedef bool_t fattr4_homogeneous;

typedef uint64_t fattr4_maxfilesize;

typedef uint32_t fattr4_maxlink;

typedef uint32_t fattr4_maxname;

typedef uint64_t fattr4_maxread;

typedef uint64_t fattr4_maxwrite;

typedef ascii_REQUIRED4 fattr4_mimetype;

typedef mode4 fattr4_mode;

typedef mode_masked4 fattr4_mode_set_masked;

typedef uint64_t fattr4_mounted_on_fileid;

typedef bool_t fattr4_no_trunc;

typedef uint32_t fattr4_numlinks;

typedef utf8string fattr4_owner;

typedef utf8string fattr4_owner_group;

typedef uint64_t fattr4_quota_avail_hard;

typedef uint64_t fattr4_quota_avail_soft;

typedef uint64_t fattr4_quota_used;

typedef specdata4 fattr4_rawdev;

typedef uint64_t fattr4_space_avail;

typedef uint64_t fattr4_space_free;

typedef uint64_t fattr4_space_total;

typedef uint64_t fattr4_space_used;

typedef bool_t fattr4_system;

typedef nfstime4 fattr4_time_access;

typedef settime4 fattr4_time_access_set;

typedef nfstime4 fattr4_time_backup;

typedef nfstime4 fattr4_time_create;

typedef nfstime4 fattr4_time_delta;

typedef nfstime4 fattr4_time_metadata;

typedef nfstime4 fattr4_time_modify;

typedef settime4 fattr4_time_modify_set;

/* nfsv4.1 */
typedef bitmap4 fattr4_suppattr_exclcreat;

typedef nfstime4 fattr4_dir_notif_delay;

typedef nfstime4 fattr4_dirent_notif_delay;

typedef struct {
	uint_t fattr4_fs_layout_types_len;
	layouttype4 *fattr4_fs_layout_types_val;
} fattr4_fs_layout_types;

typedef fs4_status fattr4_fs_status;

typedef fs_charset_cap4 fattr4_fs_charset_cap;

typedef uint32_t fattr4_layout_alignment;

typedef uint32_t fattr4_layout_blksize;

typedef layouthint4 fattr4_layout_hint;

typedef struct {
	uint_t fattr4_layout_types_len;
	layouttype4 *fattr4_layout_types_val;
} fattr4_layout_types;

typedef mdsthreshold4 fattr4_mdsthreshold;

typedef retention_get4 fattr4_retention_get;

typedef retention_set4 fattr4_retention_set;

typedef retention_get4 fattr4_retentevt_get;

typedef retention_set4 fattr4_retentevt_set;

typedef uint64_t fattr4_retention_hold;

typedef nfsacl41 fattr4_dacl;

typedef nfsacl41 fattr4_sacl;

typedef change_policy4 fattr4_change_policy;

/* nfsv4.1 end */

/*
 * REQUIRED Attributes
 */
#define	FATTR4_SUPPORTED_ATTRS 0
#define	FATTR4_TYPE 1
#define	FATTR4_FH_EXPIRE_TYPE 2
#define	FATTR4_CHANGE 3
#define	FATTR4_SIZE 4
#define	FATTR4_LINK_SUPPORT 5
#define	FATTR4_SYMLINK_SUPPORT 6
#define	FATTR4_NAMED_ATTR 7
#define	FATTR4_FSID 8
#define	FATTR4_UNIQUE_HANDLES 9
#define	FATTR4_LEASE_TIME 10
#define	FATTR4_RDATTR_ERROR 11
#define	FATTR4_FILEHANDLE 19
/* new to NFSV4.1 */
#define	FATTR4_SUPPATTR_EXCLCREAT 75

/*
 * RECOMMENDED Attributes
 */
#define	FATTR4_ACL 12
#define	FATTR4_ACLSUPPORT 13
#define	FATTR4_ARCHIVE 14
#define	FATTR4_CANSETTIME 15
#define	FATTR4_CASE_INSENSITIVE 16
#define	FATTR4_CASE_PRESERVING 17
#define	FATTR4_CHOWN_RESTRICTED 18
#define	FATTR4_FILEID 20
#define	FATTR4_FILES_AVAIL 21
#define	FATTR4_FILES_FREE 22
#define	FATTR4_FILES_TOTAL 23
#define	FATTR4_FS_LOCATIONS 24
#define	FATTR4_HIDDEN 25
#define	FATTR4_HOMOGENEOUS 26
#define	FATTR4_MAXFILESIZE 27
#define	FATTR4_MAXLINK 28
#define	FATTR4_MAXNAME 29
#define	FATTR4_MAXREAD 30
#define	FATTR4_MAXWRITE 31
#define	FATTR4_MIMETYPE 32
#define	FATTR4_MODE 33
#define	FATTR4_NO_TRUNC 34
#define	FATTR4_NUMLINKS 35
#define	FATTR4_OWNER 36
#define	FATTR4_OWNER_GROUP 37
#define	FATTR4_QUOTA_AVAIL_HARD 38
#define	FATTR4_QUOTA_AVAIL_SOFT 39
#define	FATTR4_QUOTA_USED 40
#define	FATTR4_RAWDEV 41
#define	FATTR4_SPACE_AVAIL 42
#define	FATTR4_SPACE_FREE 43
#define	FATTR4_SPACE_TOTAL 44
#define	FATTR4_SPACE_USED 45
#define	FATTR4_SYSTEM 46
#define	FATTR4_TIME_ACCESS 47
#define	FATTR4_TIME_ACCESS_SET 48
#define	FATTR4_TIME_BACKUP 49
#define	FATTR4_TIME_CREATE 50
#define	FATTR4_TIME_DELTA 51
#define	FATTR4_TIME_METADATA 52
#define	FATTR4_TIME_MODIFY 53
#define	FATTR4_TIME_MODIFY_SET 54
#define	FATTR4_MOUNTED_ON_FILEID 55

/* new to NFSV4.1 */
#define	FATTR4_DIR_NOTIF_DELAY 56
#define	FATTR4_DIRENT_NOTIF_DELAY 57
#define	FATTR4_DACL 58
#define	FATTR4_SACL 59
#define	FATTR4_CHANGE_POLICY 60
#define	FATTR4_FS_STATUS 61
#define	FATTR4_FS_LAYOUT_TYPES 62
#define	FATTR4_LAYOUT_HINT 63
#define	FATTR4_LAYOUT_TYPES 64
#define	FATTR4_LAYOUT_BLKSIZE 65
#define	FATTR4_LAYOUT_ALIGNMENT 66
#define	FATTR4_FS_LOCATIONS_INFO 67
#define	FATTR4_MDSTHRESHOLD 68
#define	FATTR4_RETENTION_GET 69
#define	FATTR4_RETENTION_SET 70
#define	FATTR4_RETENTEVT_GET 71
#define	FATTR4_RETENTEVT_SET 72
#define	FATTR4_RETENTION_HOLD 73
#define	FATTR4_MODE_SET_MASKED 74
#define	FATTR4_SUPPATTR_EXCLCREAT 75
#define	FATTR4_FS_CHARSET_CAP 76

/* new to NFSv4.2 */
#define	FATTR4_SEC_LABEL 80

struct fattr4 {
	bitmap4 attrmask;
	char *attrlist4;
	uint_t attrlist4_len;
};
typedef struct fattr4 fattr4;

struct change_info4 {
	bool_t atomic;
	changeid4 before;
	changeid4 after;
};
typedef struct change_info4 change_info4;

struct clientaddr4 {
	char *r_netid;
	char *r_addr;
};
typedef struct clientaddr4 clientaddr4;

struct cb_client4 {
	uint_t cb_program;
	clientaddr4 cb_location;
};
typedef struct cb_client4 cb_client4;

struct nfs_client_id4 {
	verifier4 verifier;
	uint_t id_len;
	char *id_val;
	struct sockaddr *cl_addr;
};
typedef struct nfs_client_id4 nfs_client_id4;

struct client_owner4 {
	verifier4 co_verifier;
	struct {
		uint_t co_ownerid_len;
		char *co_ownerid_val;
	} co_ownerid;
};
typedef struct client_owner4 client_owner4;

struct server_owner4 {
	uint64_t so_minor_id;
	struct {
		uint_t so_major_id_len;
		char *so_major_id_val;
	} so_major_id;
};
typedef struct server_owner4 server_owner4;

struct state_owner4 {
	clientid4 clientid;
	struct {
		uint_t owner_len;
		char *owner_val;
	} owner;
};
typedef struct state_owner4 state_owner4;

struct open_owner4 {
	clientid4 clientid;
	uint_t owner_len;
	char *owner_val;
};
typedef struct open_owner4 open_owner4;

struct lock_owner4 {
	clientid4 clientid;
	uint_t owner_len;
	char *owner_val;
};
typedef struct lock_owner4 lock_owner4;

enum nfs_lock_type4 {
	READ_LT = 1,
	WRITE_LT = 2,
	READW_LT = 3,
	WRITEW_LT = 4
};
typedef enum nfs_lock_type4 nfs_lock_type4;

/*
 * nfsv4.1
 */

/* Input for computing subkeys */

enum ssv_subkey4 {
	SSV4_SUBKEY_MIC_I2T = 1,
	SSV4_SUBKEY_MIC_T2I = 2,
	SSV4_SUBKEY_SEAL_I2T = 3,
	SSV4_SUBKEY_SEAL_T2I = 4
};
typedef enum ssv_subkey4 ssv_subkey4;

/* Input for computing smt_hmac */

struct ssv_mic_plain_tkn4 {
	uint32_t smpt_ssv_seq;
	struct {
		uint_t smpt_orig_plain_len;
		char *smpt_orig_plain_val;
	} smpt_orig_plain;
};
typedef struct ssv_mic_plain_tkn4 ssv_mic_plain_tkn4;

/* SSV GSS PerMsgToken token */

struct ssv_mic_tkn4 {
	uint32_t smt_ssv_seq;
	struct {
		uint_t smt_hmac_len;
		char *smt_hmac_val;
	} smt_hmac;
};
typedef struct ssv_mic_tkn4 ssv_mic_tkn4;

/* Input for computing ssct_encr_data and ssct_hmac */

struct ssv_seal_plain_tkn4 {
	struct {
		uint_t sspt_confounder_len;
		char *sspt_confounder_val;
	} sspt_confounder;
	uint32_t sspt_ssv_seq;
	struct {
		uint_t sspt_orig_plain_len;
		char *sspt_orig_plain_val;
	} sspt_orig_plain;
	struct {
		uint_t sspt_pad_len;
		char *sspt_pad_val;
	} sspt_pad;
};
typedef struct ssv_seal_plain_tkn4 ssv_seal_plain_tkn4;

/* SSV GSS SealedMessage token */

struct ssv_seal_cipher_tkn4 {
	uint32_t ssct_ssv_seq;
	struct {
		uint_t ssct_iv_len;
		char *ssct_iv_val;
	} ssct_iv;
	struct {
		uint_t ssct_encr_data_len;
		char *ssct_encr_data_val;
	} ssct_encr_data;
	struct {
		uint_t ssct_hmac_len;
		char *ssct_hmac_val;
	} ssct_hmac;
};
typedef struct ssv_seal_cipher_tkn4 ssv_seal_cipher_tkn4;

struct fs_locations_server4 {
	int32_t fls_currency;
	struct {
		uint_t fls_info_len;
		char *fls_info_val;
	} fls_info;
	utf8str_cis fls_server;
};
typedef struct fs_locations_server4 fs_locations_server4;
#define	FSLI4BX_GFLAGS 0
#define	FSLI4BX_TFLAGS 1
#define	FSLI4BX_CLSIMUL 2
#define	FSLI4BX_CLHANDLE 3
#define	FSLI4BX_CLFILEID 4
#define	FSLI4BX_CLWRITEVER 5
#define	FSLI4BX_CLCHANGE 6
#define	FSLI4BX_CLREADDIR 7
#define	FSLI4BX_READRANK 8
#define	FSLI4BX_WRITERANK 9
#define	FSLI4BX_READORDER 10
#define	FSLI4BX_WRITEORDER 11
#define	FSLI4GF_WRITABLE 0x01
#define	FSLI4GF_CUR_REQ 0x02
#define	FSLI4GF_ABSENT 0x04
#define	FSLI4GF_GOING 0x08
#define	FSLI4GF_SPLIT 0x10
#define	FSLI4TF_RDMA 0x01

struct fs_locations_item4 {
	struct {
		uint_t fli_entries_len;
		fs_locations_server4 *fli_entries_val;
	} fli_entries;
	pathname4 fli_rootpath;
};
typedef struct fs_locations_item4 fs_locations_item4;

struct fs_locations_info4 {
	uint32_t fli_flags;
	int32_t fli_valid_for;
	pathname4 fli_fs_root;
	struct {
		uint_t fli_items_len;
		fs_locations_item4 *fli_items_val;
	} fli_items;
};
typedef struct fs_locations_info4 fs_locations_info4;
#define	FSLI4IF_VAR_SUB 0x00000001

typedef fs_locations_info4 fattr4_fs_locations_info;
#define	NFL4_UFLG_MASK			0x0000003F
#define	NFL4_UFLG_DENSE			0x00000001
#define	NFL4_UFLG_COMMIT_THRU_MDS	0x00000002
#define	NFL4_UFLG_STRIPE_UNIT_SIZE_MASK	0xFFFFFFC0

typedef uint32_t nfl_util4;

enum filelayout_hint_care4 {
	NFLH4_CARE_DENSE = NFL4_UFLG_DENSE,
	NFLH4_CARE_COMMIT_THRU_MDS = NFL4_UFLG_COMMIT_THRU_MDS,
	NFLH4_CARE_STRIPE_UNIT_SIZE = 0x00000040,
	NFLH4_CARE_STRIPE_COUNT = 0x00000080
};
typedef enum filelayout_hint_care4 filelayout_hint_care4;

/* Encoded in the loh_body field of data type layouthint4: */

struct nfsv4_1_file_layouthint4 {
	uint32_t nflh_care;
	nfl_util4 nflh_util;
	count4 nflh_stripe_count;
};
typedef struct nfsv4_1_file_layouthint4 nfsv4_1_file_layouthint4;

typedef struct {
	uint_t multipath_list4_len;
	netaddr4 *multipath_list4_val;
} multipath_list4;

/*
 * Encoded in the da_addr_body field of
 * data type device_addr4:
 */

struct nfsv4_1_file_layout_ds_addr4 {
	struct {
		uint_t nflda_stripe_indices_len;
		uint32_t *nflda_stripe_indices_val;
	} nflda_stripe_indices;
	struct {
		uint_t nflda_multipath_ds_list_len;
		multipath_list4 *nflda_multipath_ds_list_val;
	} nflda_multipath_ds_list;
};
typedef struct nfsv4_1_file_layout_ds_addr4 nfsv4_1_file_layout_ds_addr4;

/*
 * Encoded in the loc_body field of
 * data type layout_content4:
 */

struct nfsv4_1_file_layout4 {
	deviceid4 nfl_deviceid;
	nfl_util4 nfl_util;
	uint32_t nfl_first_stripe_index;
	offset4 nfl_pattern_offset;
	struct {
		uint_t nfl_fh_list_len;
		nfs_fh4 *nfl_fh_list_val;
	} nfl_fh_list;
};
typedef struct nfsv4_1_file_layout4 nfsv4_1_file_layout4;

/*
 * Encoded in the lou_body field of data type layoutupdate4:
 *      Nothing. lou_body is a zero length array of bytes.
 */

/*
 * Encoded in the lrf_body field of
 * data type layoutreturn_file4:
 *      Nothing. lrf_body is a zero length array of bytes.
 */

/* nfsv4.1 end */

#define	ACCESS4_READ 0x00000001
#define	ACCESS4_LOOKUP 0x00000002
#define	ACCESS4_MODIFY 0x00000004
#define	ACCESS4_EXTEND 0x00000008
#define	ACCESS4_DELETE 0x00000010
#define	ACCESS4_EXECUTE 0x00000020

struct ACCESS4args {
	uint32_t access;
};
typedef struct ACCESS4args ACCESS4args;

struct ACCESS4res {
	nfsstat4 status;
	uint32_t supported;
	uint32_t access;
};
typedef struct ACCESS4res ACCESS4res;

struct CLOSE4args {
	seqid4 seqid;
	stateid4 open_stateid;
};
typedef struct CLOSE4args CLOSE4args;

struct CLOSE4res {
	nfsstat4 status;
	stateid4 open_stateid;
};
typedef struct CLOSE4res CLOSE4res;

struct COMMIT4args {
	offset4 offset;
	count4 count;
};
typedef struct COMMIT4args COMMIT4args;

struct COMMIT4res {
	nfsstat4 status;
	verifier4 writeverf;
};
typedef struct COMMIT4res COMMIT4res;

struct CREATE4args {
	nfs_ftype4 type;
	union {
		linktext4 linkdata;
		specdata4 devdata;
	} ftype4_u;
	component4 objname;
	fattr4 createattrs;
};
typedef struct CREATE4args CREATE4args;

struct CREATE4cargs {
	nfs_ftype4 type;
	union {
		char *clinkdata;
		specdata4 devdata;
	} ftype4_u;
	char *cname;
	fattr4 createattrs;
};
typedef struct CREATE4cargs CREATE4cargs;

struct CREATE4res {
	nfsstat4 status;
	change_info4 cinfo;
	bitmap4 attrset;
};
typedef struct CREATE4res CREATE4res;

struct DELEGPURGE4args {
	clientid4 clientid;
};
typedef struct DELEGPURGE4args DELEGPURGE4args;

struct DELEGPURGE4res {
	nfsstat4 status;
};
typedef struct DELEGPURGE4res DELEGPURGE4res;

struct DELEGRETURN4args {
	stateid4 deleg_stateid;
};
typedef struct DELEGRETURN4args DELEGRETURN4args;

struct DELEGRETURN4res {
	nfsstat4 status;
};
typedef struct DELEGRETURN4res DELEGRETURN4res;

struct mntinfo4;

struct GETATTR4args {
	bitmap4 attr_request;
	struct mntinfo4 *mi;
};
typedef struct GETATTR4args GETATTR4args;

struct nfs4_ga_ext_res;

struct nfs4_ga_res {
	vattr_t				n4g_va;
	unsigned			n4g_change_valid:1;
	unsigned			n4g_mon_fid_valid:1;
	unsigned			n4g_fsid_valid:1;
	uint_t				n4g_attrerr;
	uint_t				n4g_attrwhy;
	bitmap4				n4g_resbmap;
	fattr4_change			n4g_change;
	fattr4_fsid			n4g_fsid;
	fattr4_mounted_on_fileid	n4g_mon_fid;
	struct nfs4_ga_ext_res		*n4g_ext_res;
	vsecattr_t			n4g_vsa;
};
typedef struct nfs4_ga_res nfs4_ga_res_t;

struct GETATTR4res {
	nfsstat4 status;
	fattr4 obj_attributes;
	nfsstat4	ga_status;
	struct nfs4_ga_res ga_res;
};
typedef struct GETATTR4res GETATTR4res;

struct GETFH4res {
	nfsstat4 status;
	nfs_fh4 object;
};
typedef struct GETFH4res GETFH4res;

struct LINK4args {
	component4 newname;
};
typedef struct LINK4args LINK4args;

struct LINK4cargs {
	char *cnewname;
};
typedef struct LINK4cargs LINK4cargs;

struct LINK4res {
	nfsstat4 status;
	change_info4 cinfo;
};
typedef struct LINK4res LINK4res;

struct open_to_lock_owner4 {
	seqid4 open_seqid;
	stateid4 open_stateid;
	seqid4 lock_seqid;
	lock_owner4 lock_owner;
};
typedef struct open_to_lock_owner4 open_to_lock_owner4;

struct exist_lock_owner4 {
	stateid4 lock_stateid;
	seqid4 lock_seqid;
};
typedef struct exist_lock_owner4 exist_lock_owner4;

struct locker4 {
	bool_t new_lock_owner;
	union {
		open_to_lock_owner4 open_owner;
		exist_lock_owner4 lock_owner;
	} locker4_u;
};
typedef struct locker4 locker4;

struct LOCK4args {
	nfs_lock_type4 locktype;
	bool_t reclaim;
	offset4 offset;
	length4 length;
	locker4 locker;
};
typedef struct LOCK4args LOCK4args;

struct LOCK4denied {
	offset4 offset;
	length4 length;
	nfs_lock_type4 locktype;
	lock_owner4 owner;
};
typedef struct LOCK4denied LOCK4denied;

struct LOCK4res {
	nfsstat4 status;
	union {
		stateid4 lock_stateid;
		LOCK4denied denied;
	} LOCK4res_u;
};
typedef struct LOCK4res LOCK4res;

struct LOCKT4args {
	nfs_lock_type4 locktype;
	offset4 offset;
	length4 length;
	lock_owner4 owner;
};
typedef struct LOCKT4args LOCKT4args;

struct LOCKT4res {
	nfsstat4 status;
	LOCK4denied denied;
};
typedef struct LOCKT4res LOCKT4res;

struct LOCKU4args {
	nfs_lock_type4 locktype;
	seqid4 seqid;
	stateid4 lock_stateid;
	offset4 offset;
	length4 length;
};
typedef struct LOCKU4args LOCKU4args;

struct LOCKU4res {
	nfsstat4 status;
	stateid4 lock_stateid;
};
typedef struct LOCKU4res LOCKU4res;

struct LOOKUP4args {
	component4 objname;
};
typedef struct LOOKUP4args LOOKUP4args;

struct LOOKUP4cargs {
	char *cname;
};
typedef struct LOOKUP4cargs LOOKUP4cargs;

struct LOOKUP4res {
	nfsstat4 status;
};
typedef struct LOOKUP4res LOOKUP4res;

struct LOOKUPP4res {
	nfsstat4 status;
};
typedef struct LOOKUPP4res LOOKUPP4res;

struct NVERIFY4args {
	fattr4 obj_attributes;
};
typedef struct NVERIFY4args NVERIFY4args;

struct NVERIFY4res {
	nfsstat4 status;
};
typedef struct NVERIFY4res NVERIFY4res;

enum createmode4 {
	UNCHECKED4 = 0,
	GUARDED4 = 1,
	EXCLUSIVE4 = 2,
	EXCLUSIVE4_1 = 3
};
typedef enum createmode4 createmode4;

struct creatverfattr {
	verifier4 cva_verf;
	fattr4 cva_attrs;
};
typedef struct creatverfattr creatverfattr;

struct createhow4 {
	createmode4 mode;
	union {
		fattr4 createattrs;
		verifier4 createverf;
		creatverfattr ch_createboth;
	} createhow4_u;
};
typedef struct createhow4 createhow4;

enum opentype4 {
	OPEN4_NOCREATE = 0,
	OPEN4_CREATE = 1
};
typedef enum opentype4 opentype4;

struct openflag4 {
	opentype4 opentype;
	union {
		createhow4 how;
	} openflag4_u;
};
typedef struct openflag4 openflag4;

enum limit_by4 {
	NFS_LIMIT_SIZE = 1,
	NFS_LIMIT_BLOCKS = 2
};
typedef enum limit_by4 limit_by4;

struct nfs_modified_limit4 {
	uint32_t num_blocks;
	uint32_t bytes_per_block;
};
typedef struct nfs_modified_limit4 nfs_modified_limit4;

struct nfs_space_limit4 {
	limit_by4 limitby;
	union {
		uint64_t filesize;
		nfs_modified_limit4 mod_blocks;
	} nfs_space_limit4_u;
};
typedef struct nfs_space_limit4 nfs_space_limit4;

#define	OPEN4_SHARE_ACCESS_MASK 0x00FF
#define	OPEN4_SHARE_ACCESS_READ 0x00000001
#define	OPEN4_SHARE_ACCESS_WRITE 0x00000002
#define	OPEN4_SHARE_ACCESS_BOTH 0x00000003
#define	OPEN4_SHARE_DENY_NONE 0x00000000
#define	OPEN4_SHARE_DENY_READ 0x00000001
#define	OPEN4_SHARE_DENY_WRITE 0x00000002
#define	OPEN4_SHARE_DENY_BOTH 0x00000003
/* nfsv4.1 */
#define	OPEN4_SHARE_WANT_MASK		0xFF00
#define	OPEN4_SHARE_WANT_NO_PREFERENCE	0x0000
#define	OPEN4_SHARE_WANT_READ_DELEG	0x0100
#define	OPEN4_SHARE_WANT_WRITE_DELEG	0x0200
#define	OPEN4_SHARE_WANT_ANY_DELEG	0x0300
#define	OPEN4_SHARE_WANT_NO_DELEG	0x0400
#define	OPEN4_SHARE_WANT_CANCEL		0x0500

#define	OPEN4_SHARE_WHEN_MASK			  0xF0000
#define	OPEN4_SHARE_SIGNAL_DELEG_WHEN_RESRC_AVAIL 0x10000
#define	OPEN4_SHARE_PUSH_DELEG_WHEN_UNCONTENDED   0x20000

enum open_delegation_type4 {
	OPEN_DELEGATE_NONE = 0,
	OPEN_DELEGATE_READ = 1,
	OPEN_DELEGATE_WRITE = 2,
	OPEN_DELEGATE_NONE_EXT = 3
};
typedef enum open_delegation_type4 open_delegation_type4;

enum open_claim_type4 {
	CLAIM_NULL = 0,
	CLAIM_PREVIOUS = 1,
	CLAIM_DELEGATE_CUR = 2,
	CLAIM_DELEGATE_PREV = 3,
	CLAIM_FH = 4,
	CLAIM_DELEG_CUR_FH = 5,
	CLAIM_DELEG_PREV_FH = 6
};
typedef enum open_claim_type4 open_claim_type4;

struct open_claim_delegate_cur4 {
	stateid4 delegate_stateid;
	component4 file;
};
typedef struct open_claim_delegate_cur4 open_claim_delegate_cur4;

struct copen_claim_delegate_cur4 {
	stateid4 delegate_stateid;
	char *cfile;
};
typedef struct copen_claim_delegate_cur4 copen_claim_delegate_cur4;

struct open_claim4 {
	open_claim_type4 claim;
	union {
		component4 file;
		open_delegation_type4 delegate_type;
		open_claim_delegate_cur4 delegate_cur_info;
		component4 file_delegate_prev;
		stateid4 oc_delegate_stateid;
	} open_claim4_u;
};
typedef struct open_claim4 open_claim4;

struct OPEN4args {
	seqid4 seqid;
	uint32_t share_access;
	uint32_t deleg_want;	/* nfsv4.1 */
	uint32_t share_deny;
	open_owner4 owner;
	opentype4 opentype;
	createmode4 mode;
	union {
		fattr4 createattrs;
		verifier4 createverf;
		creatverfattr ch_createboth; /* for nfsv4.1 */
	} createhow4_u;
	open_claim4 claim;
};
typedef struct OPEN4args OPEN4args;

struct OPEN4cargs {
	seqid4 seqid;
	uint32_t share_access;
	uint32_t share_deny;
	open_owner4 owner;
	opentype4 opentype;
	createmode4 mode;
	union {
		fattr4 createattrs;
		verifier4 createverf;
	} createhow4_u;
	open_claim_type4 claim;
	union {
		char *cfile;
		open_delegation_type4 delegate_type;
		copen_claim_delegate_cur4 delegate_cur_info;
		char *cfile_delegate_prev;
	} open_claim4_u;
};
typedef struct OPEN4cargs OPEN4cargs;

struct open_read_delegation4 {
	stateid4 stateid;
	bool_t recall;
	nfsace4 permissions;
};
typedef struct open_read_delegation4 open_read_delegation4;

struct open_write_delegation4 {
	stateid4 stateid;
	bool_t recall;
	nfs_space_limit4 space_limit;
	nfsace4 permissions;
};
typedef struct open_write_delegation4 open_write_delegation4;

/* nfsv4.1 */
enum why_no_delegation4 {
	WND4_NOT_WANTED = 0,
	WND4_CONTENTION = 1,
	WND4_RESOURCE = 2,
	WND4_NOT_SUPP_FTYPE = 3,
	WND4_WRITE_DELEG_NOT_SUPP_FTYPE = 4,
	WND4_NOT_SUPP_UPGRADE = 5,
	WND4_NOT_SUPP_DOWNGRADE = 6,
	WND4_CANCELLED = 7,
	WND4_IS_DIR = 8
};
typedef enum why_no_delegation4 why_no_delegation4;

struct open_none_delegation4 {
	why_no_delegation4 ond_why;
	union {
		bool_t ond_server_will_push_deleg;
		bool_t ond_server_will_signal_avail;
	} open_none_delegation4_u;
};
typedef struct open_none_delegation4 open_none_delegation4;

/* nfsv4.1 end */

struct open_delegation4 {
	open_delegation_type4 delegation_type;
	union {
		open_read_delegation4 read;
		open_write_delegation4 write;
		open_none_delegation4 od_whynone; /* nfsv4.1 */
	} open_delegation4_u;
};
typedef struct open_delegation4 open_delegation4;
#define	OPEN4_RESULT_CONFIRM 0x00000002
#define	OPEN4_RESULT_LOCKTYPE_POSIX 0x00000004
#define	OPEN4_RESULT_PRESERVE_UNLINKED 0x00000008 /* nfsv4.1 */
#define	OPEN4_RESULT_MAY_NOTIFY_LOCK 0x00000020	  /* nfsv4.1 */

struct OPEN4res {
	nfsstat4 status;
	stateid4 stateid;
	change_info4 cinfo;
	uint32_t rflags;
	bitmap4 attrset;
	open_delegation4 delegation;
};
typedef struct OPEN4res OPEN4res;

struct OPENATTR4args {
	bool_t createdir;
};
typedef struct OPENATTR4args OPENATTR4args;

struct OPENATTR4res {
	nfsstat4 status;
};
typedef struct OPENATTR4res OPENATTR4res;

struct OPEN_CONFIRM4args {
	stateid4 open_stateid;
	seqid4 seqid;
};
typedef struct OPEN_CONFIRM4args OPEN_CONFIRM4args;

struct OPEN_CONFIRM4res {
	nfsstat4 status;
	stateid4 open_stateid;
};
typedef struct OPEN_CONFIRM4res OPEN_CONFIRM4res;

struct OPEN_DOWNGRADE4args {
	stateid4 open_stateid;
	seqid4 seqid;
	uint32_t share_access;
	uint32_t deleg_want;	/* nfsv4.1 */
	uint32_t share_deny;
};
typedef struct OPEN_DOWNGRADE4args OPEN_DOWNGRADE4args;

struct OPEN_DOWNGRADE4res {
	nfsstat4 status;
	stateid4 open_stateid;
};
typedef struct OPEN_DOWNGRADE4res OPEN_DOWNGRADE4res;

struct PUTFH4args {
	nfs_fh4 object;
};
typedef struct PUTFH4args PUTFH4args;

/*
 * Client only side PUTFH arguments
 * This is really a nfs4_sharedfh_t * but the forward declaration
 * is problematic;
 */
struct PUTFH4cargs {
	void *sfh;
};
typedef struct PUTFH4cargs PUTFH4cargs;

struct PUTFH4res {
	nfsstat4 status;
};
typedef struct PUTFH4res PUTFH4res;

struct PUTPUBFH4res {
	nfsstat4 status;
};
typedef struct PUTPUBFH4res PUTPUBFH4res;

struct PUTROOTFH4res {
	nfsstat4 status;
};
typedef struct PUTROOTFH4res PUTROOTFH4res;

struct READ4args {
	stateid4 stateid;
	offset4 offset;
	count4 count;
	/* The following are used for the XDR decode path */
	char *res_data_val_alt;
	mblk_t *res_mblk;
	struct uio *res_uiop;
	uint_t res_maxsize;
#ifdef _KERNEL
	struct clist *wlist;
	CONN *conn;
#endif
};
typedef struct READ4args READ4args;

struct READ4res {
	nfsstat4 status;
	bool_t eof;
	uint_t data_len;
	char *data_val;
	mblk_t *mblk;
#ifdef _KERNEL
	struct clist *wlist;
	uint_t wlist_len;
#endif
};
typedef struct READ4res READ4res;

struct rddir4_cache;

struct READDIR4args {
	nfs_cookie4 cookie;
	verifier4 cookieverf;
	count4 dircount;
	count4 maxcount;
	bitmap4 attr_request;
	vnode_t *dvp;
	struct mntinfo4 *mi;
	cred_t *cr;
	struct rddir4_cache *rdc;
	hrtime_t t;
};
typedef struct READDIR4args READDIR4args;

struct READDIR4res_clnt {
	nfsstat4 status;
	verifier4 cookieverf;
	bool_t eof;
	struct dirent64 *dotp, *dotdotp;
	struct rddir4_cache *rdc;
};
typedef struct READDIR4res_clnt READDIR4res_clnt;

struct READDIR4res {
	nfsstat4 status;
	verifier4 cookieverf;
	mblk_t *mblk;
	uint_t data_len;
};
typedef struct READDIR4res READDIR4res;

struct READLINK4res {
	nfsstat4 status;
	linktext4 link;
};
typedef struct READLINK4res READLINK4res;

struct REMOVE4args {
	component4 target;
};
typedef struct REMOVE4args REMOVE4args;

struct REMOVE4cargs {
	char *ctarget;
};
typedef struct REMOVE4cargs REMOVE4cargs;

struct REMOVE4res {
	nfsstat4 status;
	change_info4 cinfo;
};
typedef struct REMOVE4res REMOVE4res;

struct RENAME4args {
	component4 oldname;
	component4 newname;
};
typedef struct RENAME4args RENAME4args;

struct RENAME4cargs {
	char *coldname;
	char *cnewname;
};
typedef struct RENAME4cargs RENAME4cargs;

struct RENAME4res {
	nfsstat4 status;
	change_info4 source_cinfo;
	change_info4 target_cinfo;
};
typedef struct RENAME4res RENAME4res;

struct RENEW4args {
	clientid4 clientid;
};
typedef struct RENEW4args RENEW4args;

struct RENEW4res {
	nfsstat4 status;
};
typedef struct RENEW4res RENEW4res;

struct RESTOREFH4res {
	nfsstat4 status;
};
typedef struct RESTOREFH4res RESTOREFH4res;

struct SAVEFH4res {
	nfsstat4 status;
};
typedef struct SAVEFH4res SAVEFH4res;

struct SECINFO4args {
	component4 name;
};
typedef struct SECINFO4args SECINFO4args;

struct SECINFO4cargs {
	char *cname;
};
typedef struct SECINFO4cargs SECINFO4cargs;

enum rpc_gss_svc_t {
	RPC_GSS_SVC_NONE = 1,
	RPC_GSS_SVC_INTEGRITY = 2,
	RPC_GSS_SVC_PRIVACY = 3
};
typedef enum rpc_gss_svc_t rpc_gss_svc_t;

struct rpcsec_gss_info {
	sec_oid4 oid;
	qop4 qop;
	rpc_gss_svc_t service;
};
typedef struct rpcsec_gss_info rpcsec_gss_info;

struct secinfo4 {
	uint32_t flavor;
	rpcsec_gss_info flavor_info;
};
typedef struct secinfo4 secinfo4;

struct SECINFO4res {
	nfsstat4 status;
	uint_t SECINFO4resok_len;
	secinfo4 *SECINFO4resok_val;
};
typedef struct SECINFO4res SECINFO4res;

struct SETATTR4args {
	stateid4 stateid;
	fattr4 obj_attributes;
};
typedef struct SETATTR4args SETATTR4args;

struct SETATTR4res {
	nfsstat4 status;
	bitmap4 attrsset;
};
typedef struct SETATTR4res SETATTR4res;

struct SETCLIENTID4args {
	nfs_client_id4 client;
	cb_client4 callback;
	uint32_t callback_ident;
};
typedef struct SETCLIENTID4args SETCLIENTID4args;

struct SETCLIENTID4resok {
	clientid4 clientid;
	verifier4 setclientid_confirm;
};
typedef struct SETCLIENTID4resok SETCLIENTID4resok;

struct SETCLIENTID4res {
	nfsstat4 status;
	union {
		SETCLIENTID4resok resok4;
		clientaddr4 client_using;
	} SETCLIENTID4res_u;
};
typedef struct SETCLIENTID4res SETCLIENTID4res;

struct SETCLIENTID_CONFIRM4args {
	clientid4 clientid;
	verifier4 setclientid_confirm;
};
typedef struct SETCLIENTID_CONFIRM4args SETCLIENTID_CONFIRM4args;

struct SETCLIENTID_CONFIRM4res {
	nfsstat4 status;
};
typedef struct SETCLIENTID_CONFIRM4res SETCLIENTID_CONFIRM4res;

struct VERIFY4args {
	fattr4 obj_attributes;
};
typedef struct VERIFY4args VERIFY4args;

struct VERIFY4res {
	nfsstat4 status;
};
typedef struct VERIFY4res VERIFY4res;

enum stable_how4 {
	UNSTABLE4 = 0,
	DATA_SYNC4 = 1,
	FILE_SYNC4 = 2
};
typedef enum stable_how4 stable_how4;

/*
 * mblk doesn't go over the wire.  If non-NULL, it points to an mblk chain
 * for the write data.
 */

struct WRITE4args {
	stateid4 stateid;
	offset4 offset;
	stable_how4 stable;
	uint_t data_len;
	char *data_val;
	mblk_t *mblk;
#ifdef _KERNEL
	struct clist *rlist;
	CONN *conn;
#endif
};
typedef struct WRITE4args WRITE4args;

struct WRITE4res {
	nfsstat4 status;
	count4 count;
	stable_how4 committed;
	verifier4 writeverf;
};
typedef struct WRITE4res WRITE4res;

struct RELEASE_LOCKOWNER4args {
	lock_owner4 lock_owner;
};
typedef struct RELEASE_LOCKOWNER4args RELEASE_LOCKOWNER4args;

struct RELEASE_LOCKOWNER4res {
	nfsstat4 status;
};
typedef struct RELEASE_LOCKOWNER4res RELEASE_LOCKOWNER4res;

struct ILLEGAL4res {
	nfsstat4 status;
};
typedef struct ILLEGAL4res ILLEGAL4res;

/*
 * New operations for nfsv4.1
 */
typedef struct {
	uint_t gsshandle4_t_len;
	char *gsshandle4_t_val;
} gsshandle4_t;

struct gss_cb_handles4 {
	rpc_gss_svc_t gcbp_service;
	gsshandle4_t gcbp_handle_from_server;
	gsshandle4_t gcbp_handle_from_client;
};
typedef struct gss_cb_handles4 gss_cb_handles4;

struct callback_sec_parms4 {
	uint32_t cb_secflavor;
	union {
		authsys_parms cbsp_sys_cred;
		gss_cb_handles4 cbsp_gss_handles;
	} callback_sec_parms4_u;
};
typedef struct callback_sec_parms4 callback_sec_parms4;

struct BACKCHANNEL_CTL4args {
	uint32_t bca_cb_program;
	struct {
		uint_t bca_sec_parms_len;
		callback_sec_parms4 *bca_sec_parms_val;
	} bca_sec_parms;
};
typedef struct BACKCHANNEL_CTL4args BACKCHANNEL_CTL4args;

struct BACKCHANNEL_CTL4res {
	nfsstat4 bcr_status;
};
typedef struct BACKCHANNEL_CTL4res BACKCHANNEL_CTL4res;

enum channel_dir_from_client4 {
	CDFC4_FORE = 0x1,
	CDFC4_BACK = 0x2,
	CDFC4_FORE_OR_BOTH = 0x3,
	CDFC4_BACK_OR_BOTH = 0x7
};
typedef enum channel_dir_from_client4 channel_dir_from_client4;

struct BIND_CONN_TO_SESSION4args {
	sessionid4 bctsa_sessid;
	channel_dir_from_client4 bctsa_dir;
	bool_t bctsa_use_conn_in_rdma_mode;
};
typedef struct BIND_CONN_TO_SESSION4args BIND_CONN_TO_SESSION4args;

enum channel_dir_from_server4 {
	CDFS4_FORE = 0x1,
	CDFS4_BACK = 0x2,
	CDFS4_BOTH = 0x3
};
typedef enum channel_dir_from_server4 channel_dir_from_server4;

struct BIND_CONN_TO_SESSION4resok {
	sessionid4 bctsr_sessid;
	channel_dir_from_server4 bctsr_dir;
	bool_t bctsr_use_conn_in_rdma_mode;
};
typedef struct BIND_CONN_TO_SESSION4resok BIND_CONN_TO_SESSION4resok;

struct BIND_CONN_TO_SESSION4res {
	nfsstat4 bctsr_status;
	union {
		BIND_CONN_TO_SESSION4resok bctsr_resok4;
	} BIND_CONN_TO_SESSION4res_u;
};
typedef struct BIND_CONN_TO_SESSION4res BIND_CONN_TO_SESSION4res;

#define	EXCHGID4_FLAG_SUPP_MOVED_REFER	  0x00000001
#define	EXCHGID4_FLAG_SUPP_MOVED_MIGR	  0x00000002
#define	EXCHGID4_FLAG_BIND_PRINC_STATEID  0x00000100

#define	EXCHGID4_FLAG_USE_NON_PNFS	  0x00010000
#define	EXCHGID4_FLAG_USE_PNFS_MDS	  0x00020000
#define	EXCHGID4_FLAG_USE_PNFS_DS	  0x00040000
#define	EXCHGID4_FLAG_MASK_PNFS		  0x00070000

#define	EXCHGID4_FLAG_UPD_CONFIRMED_REC_A 0x40000000
#define	EXCHGID4_FLAG_CONFIRMED_R	  0x80000000

#define	EXID4_FLAG_MASK		0x40070103

struct state_protect_ops4 {
	bitmap4 spo_must_enforce;
	bitmap4 spo_must_allow;
};
typedef struct state_protect_ops4 state_protect_ops4;

struct ssv_sp_parms4 {
	state_protect_ops4 ssp_ops;
	struct {
		uint_t ssp_hash_algs_len;
		sec_oid4 *ssp_hash_algs_val;
	} ssp_hash_algs;
	struct {
		uint_t ssp_encr_algs_len;
		sec_oid4 *ssp_encr_algs_val;
	} ssp_encr_algs;
	uint32_t ssp_window;
	uint32_t ssp_num_gss_handles;
};
typedef struct ssv_sp_parms4 ssv_sp_parms4;

enum state_protect_how4 {
	SP4_NONE = 0,
	SP4_MACH_CRED = 1,
	SP4_SSV = 2
};
typedef enum state_protect_how4 state_protect_how4;

struct state_protect4_a {
	state_protect_how4 spa_how;
	union {
		state_protect_ops4 spa_mach_ops;
		ssv_sp_parms4 spa_ssv_parms;
	} state_protect4_a_u;
};
typedef struct state_protect4_a state_protect4_a;

struct EXCHANGE_ID4args {
	client_owner4 eia_clientowner;
	uint32_t eia_flags;
	state_protect4_a eia_state_protect;
	struct {
		uint_t eia_client_impl_id_len;
		nfs_impl_id4 *eia_client_impl_id_val;
	} eia_client_impl_id;
};
typedef struct EXCHANGE_ID4args EXCHANGE_ID4args;

struct ssv_prot_info4 {
	state_protect_ops4 spi_ops;
	uint32_t spi_hash_alg;
	uint32_t spi_encr_alg;
	uint32_t spi_ssv_len;
	uint32_t spi_window;
	struct {
		uint_t spi_handles_len;
		gsshandle4_t *spi_handles_val;
	} spi_handles;
};
typedef struct ssv_prot_info4 ssv_prot_info4;

struct state_protect4_r {
	state_protect_how4 spr_how;
	union {
		state_protect_ops4 spr_mach_ops;
		ssv_prot_info4 spr_ssv_info;
	} state_protect4_r_u;
};
typedef struct state_protect4_r state_protect4_r;

struct EXCHANGE_ID4resok {
	clientid4 eir_clientid;
	sequenceid4 eir_sequenceid;
	uint32_t eir_flags;
	state_protect4_r eir_state_protect;
	server_owner4 eir_server_owner;
	struct eir_server_scope {
		uint_t eir_server_scope_len;
		char *eir_server_scope_val;
	} eir_server_scope;
	struct {
		uint_t eir_server_impl_id_len;
		nfs_impl_id4 *eir_server_impl_id_val;
	} eir_server_impl_id;
};
typedef struct EXCHANGE_ID4resok EXCHANGE_ID4resok;

struct EXCHANGE_ID4res {
	nfsstat4 eir_status;
	union {
		EXCHANGE_ID4resok eir_resok4;
	} EXCHANGE_ID4res_u;
};
typedef struct EXCHANGE_ID4res EXCHANGE_ID4res;

struct channel_attrs4 {
	count4 ca_headerpadsize;
	count4 ca_maxrequestsize;
	count4 ca_maxresponsesize;
	count4 ca_maxresponsesize_cached;
	count4 ca_maxoperations;
	count4 ca_maxrequests;
	struct {
		uint_t ca_rdma_ird_len;
		uint32_t *ca_rdma_ird_val;
	} ca_rdma_ird;
};
typedef struct channel_attrs4 channel_attrs4;

#define	CREATE_SESSION4_FLAG_PERSIST 0x00000001
#define	CREATE_SESSION4_FLAG_CONN_BACK_CHAN 0x00000002
#define	CREATE_SESSION4_FLAG_CONN_RDMA 0x00000004

#define	CREATE_SESSION4_FLAG_MASK 0x07

struct CREATE_SESSION4args {
	clientid4 csa_clientid;
	sequenceid4 csa_sequence;
	uint32_t csa_flags;
	channel_attrs4 csa_fore_chan_attrs;
	channel_attrs4 csa_back_chan_attrs;
	uint32_t csa_cb_program;
	struct {
		uint_t csa_sec_parms_len;
		callback_sec_parms4 *csa_sec_parms_val;
	} csa_sec_parms;
};
typedef struct CREATE_SESSION4args CREATE_SESSION4args;

struct CREATE_SESSION4resok {
	sessionid4 csr_sessionid;
	sequenceid4 csr_sequence;
	uint32_t csr_flags;
	channel_attrs4 csr_fore_chan_attrs;
	channel_attrs4 csr_back_chan_attrs;
};
typedef struct CREATE_SESSION4resok CREATE_SESSION4resok;

struct CREATE_SESSION4res {
	nfsstat4 csr_status;
	union {
		CREATE_SESSION4resok csr_resok4;
	} CREATE_SESSION4res_u;
};
typedef struct CREATE_SESSION4res CREATE_SESSION4res;

struct DESTROY_SESSION4args {
	sessionid4 dsa_sessionid;
};
typedef struct DESTROY_SESSION4args DESTROY_SESSION4args;

struct DESTROY_SESSION4res {
	nfsstat4 dsr_status;
};
typedef struct DESTROY_SESSION4res DESTROY_SESSION4res;

struct FREE_STATEID4args {
	stateid4 fsa_stateid;
};
typedef struct FREE_STATEID4args FREE_STATEID4args;

struct FREE_STATEID4res {
	nfsstat4 fsr_status;
};
typedef struct FREE_STATEID4res FREE_STATEID4res;

typedef nfstime4 attr_notice4;

struct GET_DIR_DELEGATION4args {
	bool_t gdda_signal_deleg_avail;
	bitmap4 gdda_notification_types;
	attr_notice4 gdda_child_attr_delay;
	attr_notice4 gdda_dir_attr_delay;
	bitmap4 gdda_child_attributes;
	bitmap4 gdda_dir_attributes;
};
typedef struct GET_DIR_DELEGATION4args GET_DIR_DELEGATION4args;

struct GET_DIR_DELEGATION4resok {
	verifier4 gddr_cookieverf;
	stateid4 gddr_stateid;
	bitmap4 gddr_notification;
	bitmap4 gddr_child_attributes;
	bitmap4 gddr_dir_attributes;
};
typedef struct GET_DIR_DELEGATION4resok GET_DIR_DELEGATION4resok;

enum gddrnf4_status {
	GDD4_OK = 0,
	GDD4_UNAVAIL = 1
};
typedef enum gddrnf4_status gddrnf4_status;

struct GET_DIR_DELEGATION4res_non_fatal {
	gddrnf4_status gddrnf_status;
	union {
		GET_DIR_DELEGATION4resok gddrnf_resok4;
		bool_t gddrnf_will_signal_deleg_avail;
	} GET_DIR_DELEGATION4res_non_fatal_u;
};
typedef struct GET_DIR_DELEGATION4res_non_fatal
    GET_DIR_DELEGATION4res_non_fatal;

struct GET_DIR_DELEGATION4res {
	nfsstat4 gddr_status;
	union {
		GET_DIR_DELEGATION4res_non_fatal gddr_res_non_fatal4;
	} GET_DIR_DELEGATION4res_u;
};
typedef struct GET_DIR_DELEGATION4res GET_DIR_DELEGATION4res;

struct GETDEVICEINFO4args {
	deviceid4 gdia_device_id;
	layouttype4 gdia_layout_type;
	count4 gdia_maxcount;
	bitmap4 gdia_notify_types;
};
typedef struct GETDEVICEINFO4args GETDEVICEINFO4args;

struct GETDEVICEINFO4resok {
	device_addr4 gdir_device_addr;
	bitmap4 gdir_notification;
};
typedef struct GETDEVICEINFO4resok GETDEVICEINFO4resok;

struct GETDEVICEINFO4res {
	nfsstat4 gdir_status;
	union {
		GETDEVICEINFO4resok gdir_resok4;
		count4 gdir_mincount;
	} GETDEVICEINFO4res_u;
};
typedef struct GETDEVICEINFO4res GETDEVICEINFO4res;

struct GETDEVICELIST4args {
	layouttype4 gdla_layout_type;
	count4 gdla_maxdevices;
	nfs_cookie4 gdla_cookie;
	verifier4 gdla_cookieverf;
};
typedef struct GETDEVICELIST4args GETDEVICELIST4args;

struct GETDEVICELIST4resok {
	nfs_cookie4 gdlr_cookie;
	verifier4 gdlr_cookieverf;
	struct {
		uint_t gdlr_deviceid_list_len;
		deviceid4 *gdlr_deviceid_list_val;
	} gdlr_deviceid_list;
	bool_t gdlr_eof;
};
typedef struct GETDEVICELIST4resok GETDEVICELIST4resok;

struct GETDEVICELIST4res {
	nfsstat4 gdlr_status;
	union {
		GETDEVICELIST4resok gdlr_resok4;
	} GETDEVICELIST4res_u;
};
typedef struct GETDEVICELIST4res GETDEVICELIST4res;

struct newtime4 {
	bool_t nt_timechanged;
	union {
		nfstime4 nt_time;
	} newtime4_u;
};
typedef struct newtime4 newtime4;

struct newoffset4 {
	bool_t no_newoffset;
	union {
		offset4 no_offset;
	} newoffset4_u;
};
typedef struct newoffset4 newoffset4;

struct LAYOUTCOMMIT4args {
	offset4 loca_offset;
	length4 loca_length;
	bool_t loca_reclaim;
	stateid4 loca_stateid;
	newoffset4 loca_last_write_offset;
	newtime4 loca_time_modify;
	layoutupdate4 loca_layoutupdate;
};
typedef struct LAYOUTCOMMIT4args LAYOUTCOMMIT4args;

struct newsize4 {
	bool_t ns_sizechanged;
	union {
		length4 ns_size;
	} newsize4_u;
};
typedef struct newsize4 newsize4;

struct LAYOUTCOMMIT4resok {
	newsize4 locr_newsize;
};
typedef struct LAYOUTCOMMIT4resok LAYOUTCOMMIT4resok;

struct LAYOUTCOMMIT4res {
	nfsstat4 locr_status;
	union {
		LAYOUTCOMMIT4resok locr_resok4;
	} LAYOUTCOMMIT4res_u;
};
typedef struct LAYOUTCOMMIT4res LAYOUTCOMMIT4res;

struct LAYOUTGET4args {
	bool_t loga_signal_layout_avail;
	layouttype4 loga_layout_type;
	layoutiomode4 loga_iomode;
	offset4 loga_offset;
	length4 loga_length;
	length4 loga_minlength;
	stateid4 loga_stateid;
	count4 loga_maxcount;
};
typedef struct LAYOUTGET4args LAYOUTGET4args;

struct LAYOUTGET4resok {
	bool_t logr_return_on_close;
	stateid4 logr_stateid;
	struct {
		uint_t logr_layout_len;
		layout4 *logr_layout_val;
	} logr_layout;
};
typedef struct LAYOUTGET4resok LAYOUTGET4resok;

struct LAYOUTGET4res {
	nfsstat4 logr_status;
	union {
		LAYOUTGET4resok logr_resok4;
		bool_t logr_will_signal_layout_avail;
	} LAYOUTGET4res_u;
};
typedef struct LAYOUTGET4res LAYOUTGET4res;

struct LAYOUTRETURN4args {
	bool_t lora_reclaim;
	layouttype4 lora_layout_type;
	layoutiomode4 lora_iomode;
	layoutreturn4 lora_layoutreturn;
};
typedef struct LAYOUTRETURN4args LAYOUTRETURN4args;

struct layoutreturn_stateid {
	bool_t lrs_present;
	union {
		stateid4 lrs_stateid;
	} layoutreturn_stateid_u;
};
typedef struct layoutreturn_stateid layoutreturn_stateid;

struct LAYOUTRETURN4res {
	nfsstat4 lorr_status;
	union {
		layoutreturn_stateid lorr_stateid;
	} LAYOUTRETURN4res_u;
};
typedef struct LAYOUTRETURN4res LAYOUTRETURN4res;

enum secinfo_style4 {
	SECINFO_STYLE4_CURRENT_FH = 0,
	SECINFO_STYLE4_PARENT = 1
};
typedef enum secinfo_style4 secinfo_style4;

typedef secinfo_style4 SECINFO_NO_NAME4args;

typedef SECINFO4res SECINFO_NO_NAME4res;

struct SEQUENCE4args {
	sessionid4 sa_sessionid;
	sequenceid4 sa_sequenceid;
	slotid4 sa_slotid;
	slotid4 sa_highest_slotid;
	bool_t sa_cachethis;
};
typedef struct SEQUENCE4args SEQUENCE4args;
#define	SEQ4_STATUS_CB_PATH_DOWN 0x00000001
#define	SEQ4_STATUS_CB_GSS_CONTEXTS_EXPIRING 0x00000002
#define	SEQ4_STATUS_CB_GSS_CONTEXTS_EXPIRED 0x00000004
#define	SEQ4_STATUS_EXPIRED_ALL_STATE_REVOKED 0x00000008
#define	SEQ4_STATUS_EXPIRED_SOME_STATE_REVOKED 0x00000010
#define	SEQ4_STATUS_ADMIN_STATE_REVOKED 0x00000020
#define	SEQ4_STATUS_RECALLABLE_STATE_REVOKED 0x00000040
#define	SEQ4_STATUS_LEASE_MOVED 0x00000080
#define	SEQ4_STATUS_RESTART_RECLAIM_NEEDED 0x00000100
#define	SEQ4_STATUS_CB_PATH_DOWN_SESSION 0x00000200
#define	SEQ4_STATUS_BACKCHANNEL_FAULT 0x00000400
#define	SEQ4_STATUS_DEVID_CHANGED 0x00000800
#define	SEQ4_STATUS_DEVID_DELETED 0x00001000
#define	SEQ4_HIGH_BIT SEQ4_STATUS_DEVID_DELETED /* highest defined flag */

struct SEQUENCE4resok {
	sessionid4 sr_sessionid;
	sequenceid4 sr_sequenceid;
	slotid4 sr_slotid;
	slotid4 sr_highest_slotid;
	slotid4 sr_target_highest_slotid;
	uint32_t sr_status_flags;
};
typedef struct SEQUENCE4resok SEQUENCE4resok;

struct SEQUENCE4res {
	nfsstat4 sr_status;
	union {
		SEQUENCE4resok sr_resok4;
	} SEQUENCE4res_u;
};
typedef struct SEQUENCE4res SEQUENCE4res;

struct ssa_digest_input4 {
	SEQUENCE4args sdi_seqargs;
};
typedef struct ssa_digest_input4 ssa_digest_input4;

struct SET_SSV4args {
	struct {
		uint_t ssa_ssv_len;
		char *ssa_ssv_val;
	} ssa_ssv;
	struct {
		uint_t ssa_digest_len;
		char *ssa_digest_val;
	} ssa_digest;
};
typedef struct SET_SSV4args SET_SSV4args;

struct ssr_digest_input4 {
	SEQUENCE4res sdi_seqres;
};
typedef struct ssr_digest_input4 ssr_digest_input4;

struct SET_SSV4resok {
	struct {
		uint_t ssr_digest_len;
		char *ssr_digest_val;
	} ssr_digest;
};
typedef struct SET_SSV4resok SET_SSV4resok;

struct SET_SSV4res {
	nfsstat4 ssr_status;
	union {
		SET_SSV4resok ssr_resok4;
	} SET_SSV4res_u;
};
typedef struct SET_SSV4res SET_SSV4res;

struct TEST_STATEID4args {
	struct {
		uint_t ts_stateids_len;
		stateid4 *ts_stateids_val;
	} ts_stateids;
};
typedef struct TEST_STATEID4args TEST_STATEID4args;

struct TEST_STATEID4resok {
	struct {
		uint_t tsr_status_codes_len;
		nfsstat4 *tsr_status_codes_val;
	} tsr_status_codes;
};
typedef struct TEST_STATEID4resok TEST_STATEID4resok;

struct TEST_STATEID4res {
	nfsstat4 tsr_status;
	union {
		TEST_STATEID4resok tsr_resok4;
	} TEST_STATEID4res_u;
};
typedef struct TEST_STATEID4res TEST_STATEID4res;

struct deleg_claim4 {
	open_claim_type4 dc_claim;
	union {
		open_delegation_type4 dc_delegate_type;
	} deleg_claim4_u;
};
typedef struct deleg_claim4 deleg_claim4;

struct WANT_DELEGATION4args {
	uint32_t wda_want;
	deleg_claim4 wda_claim;
};
typedef struct WANT_DELEGATION4args WANT_DELEGATION4args;

struct WANT_DELEGATION4res {
	nfsstat4 wdr_status;
	union {
		open_delegation4 wdr_resok4;
	} WANT_DELEGATION4res_u;
};
typedef struct WANT_DELEGATION4res WANT_DELEGATION4res;

struct DESTROY_CLIENTID4args {
	clientid4 dca_clientid;
};
typedef struct DESTROY_CLIENTID4args DESTROY_CLIENTID4args;

struct DESTROY_CLIENTID4res {
	nfsstat4 dcr_status;
};
typedef struct DESTROY_CLIENTID4res DESTROY_CLIENTID4res;

struct RECLAIM_COMPLETE4args {
	bool_t rca_one_fs;
};
typedef struct RECLAIM_COMPLETE4args RECLAIM_COMPLETE4args;

struct RECLAIM_COMPLETE4res {
	nfsstat4 rcr_status;
};
typedef struct RECLAIM_COMPLETE4res RECLAIM_COMPLETE4res;

/* new operations for NFSv4.1 end */

enum nfs_opnum4 {
	OP_ACCESS = 3,
	OP_CLOSE = 4,
	OP_COMMIT = 5,
	OP_CREATE = 6,
	OP_DELEGPURGE = 7,
	OP_DELEGRETURN = 8,
	OP_GETATTR = 9,
	OP_GETFH = 10,
	OP_LINK = 11,
	OP_LOCK = 12,
	OP_LOCKT = 13,
	OP_LOCKU = 14,
	OP_LOOKUP = 15,
	OP_LOOKUPP = 16,
	OP_NVERIFY = 17,
	OP_OPEN = 18,
	OP_OPENATTR = 19,
	OP_OPEN_CONFIRM = 20,
	OP_OPEN_DOWNGRADE = 21,
	OP_PUTFH = 22,
	OP_PUTPUBFH = 23,
	OP_PUTROOTFH = 24,
	OP_READ = 25,
	OP_READDIR = 26,
	OP_READLINK = 27,
	OP_REMOVE = 28,
	OP_RENAME = 29,
	OP_RENEW = 30,
	OP_RESTOREFH = 31,
	OP_SAVEFH = 32,
	OP_SECINFO = 33,
	OP_SETATTR = 34,
	OP_SETCLIENTID = 35,
	OP_SETCLIENTID_CONFIRM = 36,
	OP_VERIFY = 37,
	OP_WRITE = 38,
	OP_RELEASE_LOCKOWNER = 39,

	/* nfsv4.1 */
	OP_BACKCHANNEL_CTL = 40,
	OP_BIND_CONN_TO_SESSION = 41,
	OP_EXCHANGE_ID = 42,
	OP_CREATE_SESSION = 43,
	OP_DESTROY_SESSION = 44,
	OP_FREE_STATEID = 45,
	OP_GET_DIR_DELEGATION = 46,
	OP_GETDEVICEINFO = 47,
	OP_GETDEVICELIST = 48,
	OP_LAYOUTCOMMIT = 49,
	OP_LAYOUTGET = 50,
	OP_LAYOUTRETURN = 51,
	OP_SECINFO_NO_NAME = 52,
	OP_SEQUENCE = 53,
	OP_SET_SSV = 54,
	OP_TEST_STATEID = 55,
	OP_WANT_DELEGATION = 56,
	OP_DESTROY_CLIENTID = 57,
	OP_RECLAIM_COMPLETE = 58,

	OP_ILLEGAL = 10044,
/*
 * These are internal client pseudo ops that *MUST* never go over the wire
 */
#define	SUNW_PRIVATE_OP	0x10000000
#define	REAL_OP4(op)	((op) & ~SUNW_PRIVATE_OP)
	OP_CCREATE = OP_CREATE | SUNW_PRIVATE_OP,
	OP_CLINK = OP_LINK | SUNW_PRIVATE_OP,
	OP_CLOOKUP = OP_LOOKUP | SUNW_PRIVATE_OP,
	OP_COPEN = OP_OPEN | SUNW_PRIVATE_OP,
	OP_CPUTFH = OP_PUTFH | SUNW_PRIVATE_OP,
	OP_CREMOVE = OP_REMOVE | SUNW_PRIVATE_OP,
	OP_CRENAME = OP_RENAME | SUNW_PRIVATE_OP,
	OP_CSECINFO = OP_SECINFO | SUNW_PRIVATE_OP
};
typedef enum nfs_opnum4 nfs_opnum4;

struct nfs_argop4 {
	nfs_opnum4 argop;
	union {
		ACCESS4args opaccess;
		CLOSE4args opclose;
		COMMIT4args opcommit;
		CREATE4args opcreate;
		CREATE4cargs opccreate;
		DELEGPURGE4args opdelegpurge;
		DELEGRETURN4args opdelegreturn;
		GETATTR4args opgetattr;
		LINK4args oplink;
		LINK4cargs opclink;
		LOCK4args oplock;
		LOCKT4args oplockt;
		LOCKU4args oplocku;
		LOOKUP4args oplookup;
		LOOKUP4cargs opclookup;
		NVERIFY4args opnverify;
		OPEN4args opopen;
		OPEN4cargs opcopen;
		OPENATTR4args opopenattr;
		OPEN_CONFIRM4args opopen_confirm;
		OPEN_DOWNGRADE4args opopen_downgrade;
		PUTFH4args opputfh;
		PUTFH4cargs opcputfh;
		READ4args opread;
		READDIR4args opreaddir;
		REMOVE4args opremove;
		REMOVE4cargs opcremove;
		RENAME4args oprename;
		RENAME4cargs opcrename;
		RENEW4args oprenew;
		SECINFO4args opsecinfo;
		SECINFO4cargs opcsecinfo;
		SETATTR4args opsetattr;
		SETCLIENTID4args opsetclientid;
		SETCLIENTID_CONFIRM4args opsetclientid_confirm;
		VERIFY4args opverify;
		WRITE4args opwrite;
		RELEASE_LOCKOWNER4args oprelease_lockowner;
		BACKCHANNEL_CTL4args opbackchannel_ctl;		/* nfsv4.1 */
		BIND_CONN_TO_SESSION4args opbind_conn_to_session;
		EXCHANGE_ID4args opexchange_id;
		CREATE_SESSION4args opcreate_session;
		DESTROY_SESSION4args opdestroy_session;
		FREE_STATEID4args opfree_stateid;
		GET_DIR_DELEGATION4args opget_dir_delegation;
		GETDEVICEINFO4args opgetdeviceinfo;
		GETDEVICELIST4args opgetdevicelist;
		LAYOUTCOMMIT4args oplayoutcommit;
		LAYOUTGET4args oplayoutget;
		LAYOUTRETURN4args oplayoutreturn;
		SECINFO_NO_NAME4args opsecinfo_no_name;
		SEQUENCE4args opsequence;
		SET_SSV4args opset_ssv;
		TEST_STATEID4args optest_stateid;
		WANT_DELEGATION4args opwant_delegation;
		DESTROY_CLIENTID4args opdestroy_clientid;
		RECLAIM_COMPLETE4args opreclaim_complete;
	} nfs_argop4_u;
};
typedef struct nfs_argop4 nfs_argop4;

struct nfs_resop4 {
	nfs_opnum4 resop;
	union {
		ACCESS4res opaccess;
		CLOSE4res opclose;
		COMMIT4res opcommit;
		CREATE4res opcreate;
		DELEGPURGE4res opdelegpurge;
		DELEGRETURN4res opdelegreturn;
		GETATTR4res opgetattr;
		GETFH4res opgetfh;
		LINK4res oplink;
		LOCK4res oplock;
		LOCKT4res oplockt;
		LOCKU4res oplocku;
		LOOKUP4res oplookup;
		LOOKUPP4res oplookupp;
		NVERIFY4res opnverify;
		OPEN4res opopen;
		OPENATTR4res opopenattr;
		OPEN_CONFIRM4res opopen_confirm;
		OPEN_DOWNGRADE4res opopen_downgrade;
		PUTFH4res opputfh;
		PUTPUBFH4res opputpubfh;
		PUTROOTFH4res opputrootfh;
		READ4res opread;
		READDIR4res opreaddir;
		READDIR4res_clnt opreaddirclnt;
		READLINK4res opreadlink;
		REMOVE4res opremove;
		RENAME4res oprename;
		RENEW4res oprenew;
		RESTOREFH4res oprestorefh;
		SAVEFH4res opsavefh;
		SECINFO4res opsecinfo;
		SETATTR4res opsetattr;
		SETCLIENTID4res opsetclientid;
		SETCLIENTID_CONFIRM4res opsetclientid_confirm;
		VERIFY4res opverify;
		WRITE4res opwrite;
		RELEASE_LOCKOWNER4res oprelease_lockowner;
		BACKCHANNEL_CTL4res opbackchannel_ctl;		/* nfsv4.1 */
		BIND_CONN_TO_SESSION4res opbind_conn_to_session;
		EXCHANGE_ID4res opexchange_id;
		CREATE_SESSION4res opcreate_session;
		DESTROY_SESSION4res opdestroy_session;
		FREE_STATEID4res opfree_stateid;
		GET_DIR_DELEGATION4res opget_dir_delegation;
		GETDEVICEINFO4res opgetdeviceinfo;
		GETDEVICELIST4res opgetdevicelist;
		LAYOUTCOMMIT4res oplayoutcommit;
		LAYOUTGET4res oplayoutget;
		LAYOUTRETURN4res oplayoutreturn;
		SECINFO_NO_NAME4res opsecinfo_no_name;
		SEQUENCE4res opsequence;
		SET_SSV4res opset_ssv;
		TEST_STATEID4res optest_stateid;
		WANT_DELEGATION4res opwant_delegation;
		DESTROY_CLIENTID4res opdestroy_clientid;
		RECLAIM_COMPLETE4res opreclaim_complete;
		ILLEGAL4res opillegal;
	} nfs_resop4_u;
};
typedef struct nfs_resop4 nfs_resop4;

/*
 * Fixed size tag string for easy client encoding
 */
struct _ctag {
	int ct_type;
	char *ct_str;
	uint32_t ct_tag[3];
};
typedef struct _ctag ctag_t;

/*
 * Client-only encode-only version
 */
struct COMPOUND4args_clnt {
	int ctag;
	uint_t array_len;
	nfs_argop4 *array;
};
typedef struct COMPOUND4args_clnt COMPOUND4args_clnt;

struct COMPOUND4args {
	utf8string tag;
	uint32_t minorversion;
	uint_t array_len;
	nfs_argop4 *array;
};
typedef struct COMPOUND4args COMPOUND4args;

struct COMPOUND4res_clnt {
	nfsstat4 status;
	uint_t array_len;
	uint_t decode_len;
	nfs_resop4 *array;
	COMPOUND4args_clnt *argsp;
};
typedef struct COMPOUND4res_clnt COMPOUND4res_clnt;

struct COMPOUND4res {
	nfsstat4 status;
	utf8string tag;
	uint_t array_len;
	nfs_resop4 *array;
};
typedef struct COMPOUND4res COMPOUND4res;

struct CB_GETATTR4args {
	nfs_fh4 fh;
	bitmap4 attr_request;
};
typedef struct CB_GETATTR4args CB_GETATTR4args;

struct CB_GETATTR4res {
	nfsstat4 status;
	fattr4 obj_attributes;
};
typedef struct CB_GETATTR4res CB_GETATTR4res;

struct CB_RECALL4args {
	stateid4 stateid;
	bool_t truncate;
	nfs_fh4 fh;
};
typedef struct CB_RECALL4args CB_RECALL4args;

struct CB_RECALL4res {
	nfsstat4 status;
};
typedef struct CB_RECALL4res CB_RECALL4res;

struct CB_ILLEGAL4res {
	nfsstat4 status;
};
typedef struct CB_ILLEGAL4res CB_ILLEGAL4res;

/*
 * New to nfsv4.1
 */
enum layoutrecall_type4 {
	LAYOUTRECALL4_FILE = LAYOUT4_RET_REC_FILE,
	LAYOUTRECALL4_FSID = LAYOUT4_RET_REC_FSID,
	LAYOUTRECALL4_ALL = LAYOUT4_RET_REC_ALL
};
typedef enum layoutrecall_type4 layoutrecall_type4;

struct layoutrecall_file4 {
	nfs_fh4 lor_fh;
	offset4 lor_offset;
	length4 lor_length;
	stateid4 lor_stateid;
};
typedef struct layoutrecall_file4 layoutrecall_file4;

struct layoutrecall4 {
	layoutrecall_type4 lor_recalltype;
	union {
		layoutrecall_file4 lor_layout;
		fsid4 lor_fsid;
	} layoutrecall4_u;
};
typedef struct layoutrecall4 layoutrecall4;

struct CB_LAYOUTRECALL4args {
	layouttype4 clora_type;
	layoutiomode4 clora_iomode;
	bool_t clora_changed;
	layoutrecall4 clora_recall;
};
typedef struct CB_LAYOUTRECALL4args CB_LAYOUTRECALL4args;

struct CB_LAYOUTRECALL4res {
	nfsstat4 clorr_status;
};
typedef struct CB_LAYOUTRECALL4res CB_LAYOUTRECALL4res;

enum notify_type4 {
	NOTIFY4_CHANGE_CHILD_ATTRS = 0,
	NOTIFY4_CHANGE_DIR_ATTRS = 1,
	NOTIFY4_REMOVE_ENTRY = 2,
	NOTIFY4_ADD_ENTRY = 3,
	NOTIFY4_RENAME_ENTRY = 4,
	NOTIFY4_CHANGE_COOKIE_VERIFIER = 5
};
typedef enum notify_type4 notify_type4;

struct notify_entry4 {
	component4 ne_file;
	fattr4 ne_attrs;
};
typedef struct notify_entry4 notify_entry4;

struct prev_entry4 {
	notify_entry4 pe_prev_entry;
	nfs_cookie4 pe_prev_entry_cookie;
};
typedef struct prev_entry4 prev_entry4;

struct notify_remove4 {
	notify_entry4 nrm_old_entry;
	nfs_cookie4 nrm_old_entry_cookie;
};
typedef struct notify_remove4 notify_remove4;

struct notify_add4 {
	struct {
		uint_t nad_old_entry_len;
		notify_remove4 *nad_old_entry_val;
	} nad_old_entry;
	notify_entry4 nad_new_entry;
	struct {
		uint_t nad_new_entry_cookie_len;
		nfs_cookie4 *nad_new_entry_cookie_val;
} nad_new_entry_cookie;
	struct {
		uint_t nad_prev_entry_len;
		prev_entry4 *nad_prev_entry_val;
	} nad_prev_entry;
	bool_t nad_last_entry;
};
typedef struct notify_add4 notify_add4;

struct notify_attr4 {
	notify_entry4 na_changed_entry;
};
typedef struct notify_attr4 notify_attr4;

struct notify_rename4 {
	notify_remove4 nrn_old_entry;
	notify_add4 nrn_new_entry;
};
typedef struct notify_rename4 notify_rename4;

struct notify_verifier4 {
	verifier4 nv_old_cookieverf;
	verifier4 nv_new_cookieverf;
};
typedef struct notify_verifier4 notify_verifier4;

typedef struct {
	uint_t notifylist4_len;
	char *notifylist4_val;
} notifylist4;

struct notify4 {
	bitmap4 notify_mask;
	notifylist4 notify_vals;
};
typedef struct notify4 notify4;

struct CB_NOTIFY4args {
	stateid4 cna_stateid;
	nfs_fh4 cna_fh;
	struct {
		uint_t cna_changes_len;
		notify4 *cna_changes_val;
	} cna_changes;
};
typedef struct CB_NOTIFY4args CB_NOTIFY4args;

struct CB_NOTIFY4res {
	nfsstat4 cnr_status;
};
typedef struct CB_NOTIFY4res CB_NOTIFY4res;

struct CB_PUSH_DELEG4args {
	nfs_fh4 cpda_fh;
	open_delegation4 cpda_delegation;
};
typedef struct CB_PUSH_DELEG4args CB_PUSH_DELEG4args;

struct CB_PUSH_DELEG4res {
	nfsstat4 cpdr_status;
};
typedef struct CB_PUSH_DELEG4res CB_PUSH_DELEG4res;
#define	RCA4_TYPE_MASK_RDATA_DLG 0
#define	RCA4_TYPE_MASK_WDATA_DLG 1
#define	RCA4_TYPE_MASK_DIR_DLG 2
#define	RCA4_TYPE_MASK_FILE_LAYOUT 3
#define	RCA4_TYPE_MASK_BLK_LAYOUT 4
#define	RCA4_TYPE_MASK_OBJ_LAYOUT_MIN 8
#define	RCA4_TYPE_MASK_OBJ_LAYOUT_MAX 9
#define	RCA4_TYPE_MASK_OTHER_LAYOUT_MIN 12
#define	RCA4_TYPE_MASK_OTHER_LAYOUT_MAX 15

struct CB_RECALL_ANY4args {
	uint32_t craa_objects_to_keep;
	bitmap4 craa_type_mask;
};
typedef struct CB_RECALL_ANY4args CB_RECALL_ANY4args;

struct CB_RECALL_ANY4res {
	nfsstat4 crar_status;
};
typedef struct CB_RECALL_ANY4res CB_RECALL_ANY4res;

typedef CB_RECALL_ANY4args CB_RECALLABLE_OBJ_AVAIL4args;

struct CB_RECALLABLE_OBJ_AVAIL4res {
	nfsstat4 croa_status;
};
typedef struct CB_RECALLABLE_OBJ_AVAIL4res CB_RECALLABLE_OBJ_AVAIL4res;

struct CB_RECALL_SLOT4args {
	slotid4 rsa_target_highest_slotid;
};
typedef struct CB_RECALL_SLOT4args CB_RECALL_SLOT4args;

struct CB_RECALL_SLOT4res {
	nfsstat4 rsr_status;
};
typedef struct CB_RECALL_SLOT4res CB_RECALL_SLOT4res;

struct referring_call4 {
	sequenceid4 rc_sequenceid;
	slotid4 rc_slotid;
};
typedef struct referring_call4 referring_call4;

struct referring_call_list4 {
	sessionid4 rcl_sessionid;
	struct {
		uint_t rcl_referring_calls_len;
		referring_call4 *rcl_referring_calls_val;
	} rcl_referring_calls;
};
typedef struct referring_call_list4 referring_call_list4;

struct CB_SEQUENCE4args {
	sessionid4 csa_sessionid;
	sequenceid4 csa_sequenceid;
	slotid4 csa_slotid;
	slotid4 csa_highest_slotid;
	bool_t csa_cachethis;
	struct {
		uint_t csa_referring_call_lists_len;
		referring_call_list4 *csa_referring_call_lists_val;
	} csa_referring_call_lists;
};
typedef struct CB_SEQUENCE4args CB_SEQUENCE4args;

struct CB_SEQUENCE4resok {
	sessionid4 csr_sessionid;
	sequenceid4 csr_sequenceid;
	slotid4 csr_slotid;
	slotid4 csr_highest_slotid;
	slotid4 csr_target_highest_slotid;
};
typedef struct CB_SEQUENCE4resok CB_SEQUENCE4resok;

struct CB_SEQUENCE4res {
	nfsstat4 csr_status;
	union {
		CB_SEQUENCE4resok csr_resok4;
	} CB_SEQUENCE4res_u;
};
typedef struct CB_SEQUENCE4res CB_SEQUENCE4res;

struct CB_WANTS_CANCELLED4args {
	bool_t cwca_contended_wants_cancelled;
	bool_t cwca_resourced_wants_cancelled;
};
typedef struct CB_WANTS_CANCELLED4args CB_WANTS_CANCELLED4args;

struct CB_WANTS_CANCELLED4res {
	nfsstat4 cwcr_status;
};
typedef struct CB_WANTS_CANCELLED4res CB_WANTS_CANCELLED4res;

struct CB_NOTIFY_LOCK4args {
	nfs_fh4 cnla_fh;
	lock_owner4 cnla_lock_owner;
};
typedef struct CB_NOTIFY_LOCK4args CB_NOTIFY_LOCK4args;

struct CB_NOTIFY_LOCK4res {
	nfsstat4 cnlr_status;
};
typedef struct CB_NOTIFY_LOCK4res CB_NOTIFY_LOCK4res;

enum notify_deviceid_type4 {
	NOTIFY_DEVICEID4_CHANGE = 1,
	NOTIFY_DEVICEID4_DELETE = 2
};
typedef enum notify_deviceid_type4 notify_deviceid_type4;

struct notify_deviceid_delete4 {
	layouttype4 ndd_layouttype;
	deviceid4 ndd_deviceid;
};
typedef struct notify_deviceid_delete4 notify_deviceid_delete4;

struct notify_deviceid_change4 {
	layouttype4 ndc_layouttype;
	deviceid4 ndc_deviceid;
	bool_t ndc_immediate;
};
typedef struct notify_deviceid_change4 notify_deviceid_change4;

struct CB_NOTIFY_DEVICEID4args {
	struct {
		uint_t cnda_changes_len;
		notify4 *cnda_changes_val;
	} cnda_changes;
};
typedef struct CB_NOTIFY_DEVICEID4args CB_NOTIFY_DEVICEID4args;

struct CB_NOTIFY_DEVICEID4res {
	nfsstat4 cndr_status;
};
typedef struct CB_NOTIFY_DEVICEID4res CB_NOTIFY_DEVICEID4res;

/* Callback operations new to NFSv4.1 */

enum nfs_cb_opnum4 {
	OP_CB_GETATTR = 3,
	OP_CB_RECALL = 4,
	OP_CB_LAYOUTRECALL = 5,
	OP_CB_NOTIFY = 6,
	OP_CB_PUSH_DELEG = 7,
	OP_CB_RECALL_ANY = 8,
	OP_CB_RECALLABLE_OBJ_AVAIL = 9,
	OP_CB_RECALL_SLOT = 10,
	OP_CB_SEQUENCE = 11,
	OP_CB_WANTS_CANCELLED = 12,
	OP_CB_NOTIFY_LOCK = 13,
	OP_CB_NOTIFY_DEVICEID = 14,
	OP_CB_ILLEGAL = 10044
};
typedef enum nfs_cb_opnum4 nfs_cb_opnum4;

struct nfs_cb_argop4 {
	uint_t argop;
	union {
		CB_GETATTR4args opcbgetattr;
		CB_RECALL4args opcbrecall;
		CB_LAYOUTRECALL4args opcblayoutrecall;
		CB_NOTIFY4args opcbnotify;
		CB_PUSH_DELEG4args opcbpush_deleg;
		CB_RECALL_ANY4args opcbrecall_any;
		CB_RECALLABLE_OBJ_AVAIL4args opcbrecallable_obj_avail;
		CB_RECALL_SLOT4args opcbrecall_slot;
		CB_SEQUENCE4args opcbsequence;
		CB_WANTS_CANCELLED4args opcbwants_cancelled;
		CB_NOTIFY_LOCK4args opcbnotify_lock;
		CB_NOTIFY_DEVICEID4args opcbnotify_deviceid;
	} nfs_cb_argop4_u;
};
typedef struct nfs_cb_argop4 nfs_cb_argop4;

struct nfs_cb_resop4 {
	uint_t resop;
	union {
		CB_GETATTR4res opcbgetattr;
		CB_RECALL4res opcbrecall;
		CB_LAYOUTRECALL4res opcblayoutrecall;
		CB_NOTIFY4res opcbnotify;
		CB_PUSH_DELEG4res opcbpush_deleg;
		CB_RECALL_ANY4res opcbrecall_any;
		CB_RECALLABLE_OBJ_AVAIL4res opcbrecallable_obj_avail;
		CB_RECALL_SLOT4res opcbrecall_slot;
		CB_SEQUENCE4res opcbsequence;
		CB_WANTS_CANCELLED4res opcbwants_cancelled;
		CB_NOTIFY_LOCK4res opcbnotify_lock;
		CB_NOTIFY_DEVICEID4res opcbnotify_deviceid;
		CB_ILLEGAL4res opcbillegal;
	} nfs_cb_resop4_u;
};
typedef struct nfs_cb_resop4 nfs_cb_resop4;

struct CB_COMPOUND4args {
	utf8string tag;
	uint32_t minorversion;
	uint32_t callback_ident;
	uint_t array_len;
	nfs_cb_argop4 *array;
};
typedef struct CB_COMPOUND4args CB_COMPOUND4args;

struct CB_COMPOUND4res {
	nfsstat4 status;
	utf8string tag;
	uint_t array_len;
	nfs_cb_resop4 *array;
};
typedef struct CB_COMPOUND4res CB_COMPOUND4res;

#define	NFS4_PROGRAM		100003
#define	NFS_V4			4
#define	NFSPROC4_NULL		0
#define	NFSPROC4_COMPOUND	1

#define	NFS4_CALLBACK		0x40000000
#define	NFS_CB			1
#define	CB_NULL			0
#define	CB_COMPOUND		1

extern  bool_t xdr_bitmap4(XDR *, bitmap4 *);
extern  bool_t xdr_utf8string(XDR *, utf8string *);
extern  bool_t xdr_nfs_fh4(XDR *, nfs_fh4 *);
extern  bool_t xdr_fattr4_fsid(XDR *, fattr4_fsid *);
extern  bool_t xdr_fattr4_acl(XDR *, fattr4_acl *);
extern  bool_t xdr_fattr4_fs_locations(XDR *, fattr4_fs_locations *);
extern  bool_t xdr_fattr4_rawdev(XDR *, fattr4_rawdev *);
extern  bool_t xdr_nfstime4(XDR *, nfstime4 *);
extern  bool_t xdr_settime4(XDR *, settime4 *);
extern  bool_t xdr_COMPOUND4args_clnt(XDR *, COMPOUND4args_clnt *);
extern  bool_t xdr_COMPOUND4args_srv(XDR *, COMPOUND4args *);
extern  bool_t xdr_COMPOUND4res_clnt(XDR *, COMPOUND4res_clnt *);
extern  bool_t xdr_COMPOUND4res_srv(XDR *, COMPOUND4res *);
extern  bool_t xdr_CB_COMPOUND4args_clnt(XDR *, CB_COMPOUND4args *);
extern  bool_t xdr_CB_COMPOUND4args_srv(XDR *, CB_COMPOUND4args *);
extern  bool_t xdr_CB_COMPOUND4res(XDR *, CB_COMPOUND4res *);

/* New XDR to nfsv4.1 */
extern  bool_t xdr_nfs_ftype4(XDR *, nfs_ftype4*);
extern  bool_t xdr_nfsstat4(XDR *, nfsstat4*);
extern  bool_t xdr_attrlist4(XDR *, attrlist4*);
extern  bool_t xdr_bitmap4(XDR *, bitmap4*);
extern  bool_t xdr_changeid4(XDR *, changeid4*);
extern  bool_t xdr_clientid4(XDR *, clientid4*);
extern  bool_t xdr_count4(XDR *, count4*);
extern  bool_t xdr_length4(XDR *, length4*);
extern  bool_t xdr_mode4(XDR *, mode4*);
extern  bool_t xdr_nfs_cookie4(XDR *, nfs_cookie4*);
extern  bool_t xdr_nfs_fh4(XDR *, nfs_fh4*);
extern  bool_t xdr_offset4(XDR *, offset4*);
extern  bool_t xdr_qop4(XDR *, qop4*);
extern  bool_t xdr_sec_oid4(XDR *, sec_oid4*);
extern  bool_t xdr_sequenceid4(XDR *, sequenceid4*);
extern  bool_t xdr_seqid4(XDR *, seqid4*);
extern  bool_t xdr_sessionid4(XDR *, sessionid4);
extern  bool_t xdr_slotid4(XDR *, slotid4*);
extern  bool_t xdr_utf8string(XDR *, utf8string*);
extern  bool_t xdr_utf8str_cis(XDR *, utf8str_cis*);
extern  bool_t xdr_utf8str_cs(XDR *, utf8str_cs*);
extern  bool_t xdr_utf8str_mixed(XDR *, utf8str_mixed*);
extern  bool_t xdr_component4(XDR *, component4*);
extern  bool_t xdr_linktext4(XDR *, linktext4*);
extern  bool_t xdr_pathname4(XDR *, pathname4*);
extern  bool_t xdr_verifier4(XDR *, verifier4*);
extern  bool_t xdr_nfstime4(XDR *, nfstime4*);
extern  bool_t xdr_time_how4(XDR *, time_how4*);
extern  bool_t xdr_settime4(XDR *, settime4*);
extern  bool_t xdr_nfs_lease4(XDR *, nfs_lease4*);
extern  bool_t xdr_fsid4(XDR *, fsid4*);
extern  bool_t xdr_change_policy4(XDR *, change_policy4*);
extern  bool_t xdr_fs_locations4(XDR *, fs_locations4*);
extern  bool_t xdr_acetype4(XDR *, acetype4*);
extern  bool_t xdr_aceflag4(XDR *, aceflag4*);
extern  bool_t xdr_acemask4(XDR *, acemask4*);
extern  bool_t xdr_nfsace4(XDR *, nfsace4*);
extern  bool_t xdr_aclflag4(XDR *, aclflag4*);
extern  bool_t xdr_nfsacl41(XDR *, nfsacl41*);
extern  bool_t xdr_mode_masked4(XDR *, mode_masked4*);
extern  bool_t xdr_specdata4(XDR *, specdata4*);
extern  bool_t xdr_netaddr4(XDR *, netaddr4*);
extern  bool_t xdr_nfs_impl_id4(XDR *, nfs_impl_id4*);
extern  bool_t xdr_stateid4(XDR *, stateid4*);
extern  bool_t xdr_layouttype4(XDR *, layouttype4*);
extern  bool_t xdr_layout_content4(XDR *, layout_content4*);
extern  bool_t xdr_layouthint4(XDR *, layouthint4*);
extern  bool_t xdr_layoutiomode4(XDR *, layoutiomode4*);
extern  bool_t xdr_layout4(XDR *, layout4*);
extern  bool_t xdr_deviceid4(XDR *, deviceid4);
extern  bool_t xdr_device_addr4(XDR *, device_addr4*);
extern  bool_t xdr_layoutupdate4(XDR *, layoutupdate4*);
extern  bool_t xdr_layoutreturn_type4(XDR *, layoutreturn_type4*);
extern  bool_t xdr_layoutreturn_file4(XDR *, layoutreturn_file4*);
extern  bool_t xdr_layoutreturn4(XDR *, layoutreturn4*);
extern  bool_t xdr_fs4_status_type(XDR *, fs4_status_type*);
extern  bool_t xdr_fs4_status(XDR *, fs4_status*);
extern  bool_t xdr_threshold4_read_size(XDR *, threshold4_read_size*);
extern  bool_t xdr_threshold4_write_size(XDR *, threshold4_write_size*);
extern  bool_t xdr_threshold4_read_iosize(XDR *, threshold4_read_iosize*);
extern  bool_t xdr_threshold4_write_iosize(XDR *, threshold4_write_iosize*);
extern  bool_t xdr_threshold_item4(XDR *, threshold_item4*);
extern  bool_t xdr_mdsthreshold4(XDR *, mdsthreshold4*);
extern  bool_t xdr_retention_get4(XDR *, retention_get4*);
extern  bool_t xdr_retention_set4(XDR *, retention_set4*);
extern  bool_t xdr_fs_charset_cap4(XDR *, fs_charset_cap4*);
extern  bool_t xdr_fattr4_supported_attrs(XDR *, fattr4_supported_attrs*);
extern  bool_t xdr_fattr4_type(XDR *, fattr4_type*);
extern  bool_t xdr_fattr4_fh_expire_type(XDR *, fattr4_fh_expire_type*);
extern  bool_t xdr_fattr4_change(XDR *, fattr4_change*);
extern  bool_t xdr_fattr4_size(XDR *, fattr4_size*);
extern  bool_t xdr_fattr4_link_support(XDR *, fattr4_link_support*);
extern  bool_t xdr_fattr4_symlink_support(XDR *, fattr4_symlink_support*);
extern  bool_t xdr_fattr4_named_attr(XDR *, fattr4_named_attr*);
extern  bool_t xdr_fattr4_fsid(XDR *, fattr4_fsid*);
extern  bool_t xdr_fattr4_unique_handles(XDR *, fattr4_unique_handles*);
extern  bool_t xdr_fattr4_lease_time(XDR *, fattr4_lease_time*);
extern  bool_t xdr_fattr4_rdattr_error(XDR *, fattr4_rdattr_error*);
extern  bool_t xdr_fattr4_acl(XDR *, fattr4_acl*);
extern  bool_t xdr_fattr4_aclsupport(XDR *, fattr4_aclsupport*);
extern  bool_t xdr_fattr4_archive(XDR *, fattr4_archive*);
extern  bool_t xdr_fattr4_cansettime(XDR *, fattr4_cansettime*);
extern  bool_t xdr_fattr4_case_insensitive(XDR *, fattr4_case_insensitive*);
extern  bool_t xdr_fattr4_case_preserving(XDR *, fattr4_case_preserving*);
extern  bool_t xdr_fattr4_chown_restricted(XDR *, fattr4_chown_restricted*);
extern  bool_t xdr_fattr4_fileid(XDR *, fattr4_fileid*);
extern  bool_t xdr_fattr4_files_avail(XDR *, fattr4_files_avail*);
extern  bool_t xdr_fattr4_filehandle(XDR *, fattr4_filehandle*);
extern  bool_t xdr_fattr4_files_free(XDR *, fattr4_files_free*);
extern  bool_t xdr_fattr4_files_total(XDR *, fattr4_files_total*);
extern  bool_t xdr_fattr4_fs_locations(XDR *, fattr4_fs_locations*);
extern  bool_t xdr_fattr4_hidden(XDR *, fattr4_hidden*);
extern  bool_t xdr_fattr4_homogeneous(XDR *, fattr4_homogeneous*);
extern  bool_t xdr_fattr4_maxfilesize(XDR *, fattr4_maxfilesize*);
extern  bool_t xdr_fattr4_maxlink(XDR *, fattr4_maxlink*);
extern  bool_t xdr_fattr4_maxname(XDR *, fattr4_maxname*);
extern  bool_t xdr_fattr4_maxread(XDR *, fattr4_maxread*);
extern  bool_t xdr_fattr4_maxwrite(XDR *, fattr4_maxwrite*);
extern  bool_t xdr_fattr4_mimetype(XDR *, fattr4_mimetype*);
extern  bool_t xdr_fattr4_mode(XDR *, fattr4_mode*);
extern  bool_t xdr_fattr4_mode_set_masked(XDR *, fattr4_mode_set_masked*);
extern  bool_t xdr_fattr4_mounted_on_fileid(XDR *, fattr4_mounted_on_fileid*);
extern  bool_t xdr_fattr4_no_trunc(XDR *, fattr4_no_trunc*);
extern  bool_t xdr_fattr4_numlinks(XDR *, fattr4_numlinks*);
extern  bool_t xdr_fattr4_owner(XDR *, fattr4_owner*);
extern  bool_t xdr_fattr4_owner_group(XDR *, fattr4_owner_group*);
extern  bool_t xdr_fattr4_quota_avail_hard(XDR *, fattr4_quota_avail_hard*);
extern  bool_t xdr_fattr4_quota_avail_soft(XDR *, fattr4_quota_avail_soft*);
extern  bool_t xdr_fattr4_quota_used(XDR *, fattr4_quota_used*);
extern  bool_t xdr_fattr4_rawdev(XDR *, fattr4_rawdev*);
extern  bool_t xdr_fattr4_space_avail(XDR *, fattr4_space_avail*);
extern  bool_t xdr_fattr4_space_free(XDR *, fattr4_space_free*);
extern  bool_t xdr_fattr4_space_total(XDR *, fattr4_space_total*);
extern  bool_t xdr_fattr4_space_used(XDR *, fattr4_space_used*);
extern  bool_t xdr_fattr4_system(XDR *, fattr4_system*);
extern  bool_t xdr_fattr4_time_access(XDR *, fattr4_time_access*);
extern  bool_t xdr_fattr4_time_access_set(XDR *, fattr4_time_access_set*);
extern  bool_t xdr_fattr4_time_backup(XDR *, fattr4_time_backup*);
extern  bool_t xdr_fattr4_time_create(XDR *, fattr4_time_create*);
extern  bool_t xdr_fattr4_time_delta(XDR *, fattr4_time_delta*);
extern  bool_t xdr_fattr4_time_metadata(XDR *, fattr4_time_metadata*);
extern  bool_t xdr_fattr4_time_modify(XDR *, fattr4_time_modify*);
extern  bool_t xdr_fattr4_time_modify_set(XDR *, fattr4_time_modify_set*);
extern  bool_t xdr_fattr4_suppattr_exclcreat(XDR *, fattr4_suppattr_exclcreat*);
extern  bool_t xdr_fattr4_dir_notif_delay(XDR *, fattr4_dir_notif_delay*);
extern  bool_t xdr_fattr4_dirent_notif_delay(XDR *, fattr4_dirent_notif_delay*);
extern  bool_t xdr_fattr4_fs_layout_types(XDR *, fattr4_fs_layout_types*);
extern  bool_t xdr_fattr4_fs_status(XDR *, fattr4_fs_status*);
extern  bool_t xdr_fattr4_fs_charset_cap(XDR *, fattr4_fs_charset_cap*);
extern  bool_t xdr_fattr4_layout_alignment(XDR *, fattr4_layout_alignment*);
extern  bool_t xdr_fattr4_layout_blksize(XDR *, fattr4_layout_blksize*);
extern  bool_t xdr_fattr4_layout_hint(XDR *, fattr4_layout_hint*);
extern  bool_t xdr_fattr4_layout_types(XDR *, fattr4_layout_types*);
extern  bool_t xdr_fattr4_mdsthreshold(XDR *, fattr4_mdsthreshold*);
extern  bool_t xdr_fattr4_retention_get(XDR *, fattr4_retention_get*);
extern  bool_t xdr_fattr4_retention_set(XDR *, fattr4_retention_set*);
extern  bool_t xdr_fattr4_retentevt_get(XDR *, fattr4_retentevt_get*);
extern  bool_t xdr_fattr4_retentevt_set(XDR *, fattr4_retentevt_set*);
extern  bool_t xdr_fattr4_retention_hold(XDR *, fattr4_retention_hold*);
extern  bool_t xdr_fattr4_dacl(XDR *, fattr4_dacl*);
extern  bool_t xdr_fattr4_sacl(XDR *, fattr4_sacl*);
extern  bool_t xdr_fattr4_change_policy(XDR *, fattr4_change_policy*);
extern  bool_t xdr_fattr4(XDR *, fattr4*);
extern  bool_t xdr_change_info4(XDR *, change_info4*);
extern  bool_t xdr_clientaddr4(XDR *, clientaddr4*);
extern  bool_t xdr_cb_client4(XDR *, cb_client4*);
extern  bool_t xdr_nfs_client_id4(XDR *, nfs_client_id4*);
extern  bool_t xdr_client_owner4(XDR *, client_owner4*);
extern  bool_t xdr_server_owner4(XDR *, server_owner4*);
extern  bool_t xdr_state_owner4(XDR *, state_owner4*);
extern  bool_t xdr_open_owner4(XDR *, open_owner4*);
extern  bool_t xdr_lock_owner4(XDR *, lock_owner4*);
extern  bool_t xdr_nfs_lock_type4(XDR *, nfs_lock_type4*);
extern  bool_t xdr_ssv_subkey4(XDR *, ssv_subkey4*);
extern  bool_t xdr_ssv_mic_plain_tkn4(XDR *, ssv_mic_plain_tkn4*);
extern  bool_t xdr_ssv_mic_tkn4(XDR *, ssv_mic_tkn4*);
extern  bool_t xdr_ssv_seal_plain_tkn4(XDR *, ssv_seal_plain_tkn4*);
extern  bool_t xdr_ssv_seal_cipher_tkn4(XDR *, ssv_seal_cipher_tkn4*);
extern  bool_t xdr_fs_locations_server4(XDR *, fs_locations_server4*);
extern  bool_t xdr_fs_locations_item4(XDR *, fs_locations_item4*);
extern  bool_t xdr_fs_locations_info4(XDR *, fs_locations_info4*);
extern  bool_t xdr_fattr4_fs_locations_info(XDR *, fattr4_fs_locations_info*);
extern  bool_t xdr_nfl_util4(XDR *, nfl_util4*);
extern  bool_t xdr_filelayout_hint_care4(XDR *, filelayout_hint_care4*);
extern  bool_t xdr_nfsv4_1_file_layouthint4(XDR *, nfsv4_1_file_layouthint4*);
extern  bool_t xdr_multipath_list4(XDR *, multipath_list4*);
extern  bool_t xdr_nfsv4_1_file_layout_ds_addr4(XDR *,
	nfsv4_1_file_layout_ds_addr4*);
extern  bool_t xdr_nfsv4_1_file_layout4(XDR *, nfsv4_1_file_layout4*);
extern  bool_t xdr_ACCESS4args(XDR *, ACCESS4args*);
extern  bool_t xdr_COMMIT4args(XDR *, COMMIT4args*);
extern  bool_t xdr_COMMIT4res(XDR *, COMMIT4res*);
extern  bool_t xdr_DELEGPURGE4args(XDR *, DELEGPURGE4args*);
extern  bool_t xdr_DELEGPURGE4res(XDR *, DELEGPURGE4res*);
extern  bool_t xdr_DELEGRETURN4args(XDR *, DELEGRETURN4args*);
extern  bool_t xdr_DELEGRETURN4res(XDR *, DELEGRETURN4res*);
extern  bool_t xdr_GETATTR4args(XDR *, GETATTR4args*);
extern  bool_t xdr_GETATTR4res(XDR *, GETATTR4res*);
extern  bool_t xdr_GETFH4res(XDR *, GETFH4res*);
extern  bool_t xdr_open_to_lock_owner4(XDR *, open_to_lock_owner4*);
extern  bool_t xdr_exist_lock_owner4(XDR *, exist_lock_owner4*);
extern  bool_t xdr_locker4(XDR *, locker4*);
extern  bool_t xdr_LOCK4denied(XDR *, LOCK4denied*);
extern  bool_t xdr_LOOKUP4args(XDR *, LOOKUP4args*);
extern  bool_t xdr_LOOKUP4res(XDR *, LOOKUP4res*);
extern  bool_t xdr_LOOKUPP4res(XDR *, LOOKUPP4res*);
extern  bool_t xdr_NVERIFY4args(XDR *, NVERIFY4args*);
extern  bool_t xdr_NVERIFY4res(XDR *, NVERIFY4res*);
extern  bool_t xdr_createmode4(XDR *, createmode4*);
extern  bool_t xdr_creatverfattr(XDR *, creatverfattr*);
extern  bool_t xdr_createhow4(XDR *, createhow4*);
extern  bool_t xdr_opentype4(XDR *, opentype4*);
extern  bool_t xdr_openflag4(XDR *, openflag4*);
extern  bool_t xdr_limit_by4(XDR *, limit_by4*);
extern  bool_t xdr_nfs_modified_limit4(XDR *, nfs_modified_limit4*);
extern  bool_t xdr_nfs_space_limit4(XDR *, nfs_space_limit4*);
extern  bool_t xdr_open_delegation_type4(XDR *, open_delegation_type4*);
extern  bool_t xdr_open_claim_type4(XDR *, open_claim_type4*);
extern  bool_t xdr_open_claim_delegate_cur4(XDR *, open_claim_delegate_cur4*);
extern  bool_t xdr_open_claim4(XDR *, open_claim4*);
extern  bool_t xdr_open_read_delegation4(XDR *, open_read_delegation4*);
extern  bool_t xdr_open_write_delegation4(XDR *, open_write_delegation4*);
extern  bool_t xdr_why_no_delegation4(XDR *, why_no_delegation4*);
extern  bool_t xdr_open_none_delegation4(XDR *, open_none_delegation4*);
extern  bool_t xdr_open_delegation4(XDR *, open_delegation4*);
extern  bool_t xdr_PUTFH4args(XDR *, PUTFH4args*);
extern  bool_t xdr_PUTFH4res(XDR *, PUTFH4res*);
extern  bool_t xdr_PUTPUBFH4res(XDR *, PUTPUBFH4res*);
extern  bool_t xdr_PUTROOTFH4res(XDR *, PUTROOTFH4res*);
extern  bool_t xdr_RENEW4args(XDR *, RENEW4args*);
extern  bool_t xdr_RENEW4res(XDR *, RENEW4res*);
extern  bool_t xdr_RESTOREFH4res(XDR *, RESTOREFH4res*);
extern  bool_t xdr_SAVEFH4res(XDR *, SAVEFH4res*);
extern  bool_t xdr_SECINFO4args(XDR *, SECINFO4args*);
extern  bool_t xdr_rpc_gss_svc_t(XDR *, rpc_gss_svc_t *);
extern  bool_t xdr_rpcsec_gss_info(XDR *, rpcsec_gss_info*);
extern  bool_t xdr_SECINFO4res(XDR *, SECINFO4res*);
extern  bool_t xdr_SETATTR4args(XDR *, SETATTR4args*);
extern  bool_t xdr_SETATTR4res(XDR *, SETATTR4res*);
extern  bool_t xdr_SETCLIENTID_CONFIRM4args(XDR *, SETCLIENTID_CONFIRM4args*);
extern  bool_t xdr_SETCLIENTID_CONFIRM4res(XDR *, SETCLIENTID_CONFIRM4res*);
extern  bool_t xdr_VERIFY4args(XDR *, VERIFY4args*);
extern  bool_t xdr_VERIFY4res(XDR *, VERIFY4res*);
extern  bool_t xdr_stable_how4(XDR *, stable_how4*);
extern  bool_t xdr_RELEASE_LOCKOWNER4args(XDR *, RELEASE_LOCKOWNER4args*);
extern  bool_t xdr_RELEASE_LOCKOWNER4res(XDR *, RELEASE_LOCKOWNER4res*);
extern  bool_t xdr_ILLEGAL4res(XDR *, ILLEGAL4res*);
extern  bool_t xdr_gsshandle4_t(XDR *, gsshandle4_t *);
extern  bool_t xdr_gss_cb_handles4(XDR *, gss_cb_handles4*);
extern  bool_t xdr_callback_sec_parms4(XDR *, callback_sec_parms4*);
extern  bool_t xdr_BACKCHANNEL_CTL4args(XDR *, BACKCHANNEL_CTL4args*);
extern  bool_t xdr_BACKCHANNEL_CTL4res(XDR *, BACKCHANNEL_CTL4res*);
extern  bool_t xdr_channel_dir_from_client4(XDR *, channel_dir_from_client4*);
extern  bool_t xdr_BIND_CONN_TO_SESSION4args(XDR *, BIND_CONN_TO_SESSION4args*);
extern  bool_t xdr_channel_dir_from_server4(XDR *, channel_dir_from_server4*);
extern  bool_t xdr_BIND_CONN_TO_SESSION4resok(XDR *,
	BIND_CONN_TO_SESSION4resok*);
extern  bool_t xdr_BIND_CONN_TO_SESSION4res(XDR *, BIND_CONN_TO_SESSION4res*);
extern  bool_t xdr_state_protect_ops4(XDR *, state_protect_ops4*);
extern  bool_t xdr_ssv_sp_parms4(XDR *, ssv_sp_parms4*);
extern  bool_t xdr_state_protect_how4(XDR *, state_protect_how4*);
extern  bool_t xdr_state_protect4_a(XDR *, state_protect4_a*);
extern  bool_t xdr_EXCHANGE_ID4args(XDR *, EXCHANGE_ID4args*);
extern  bool_t xdr_ssv_prot_info4(XDR *, ssv_prot_info4*);
extern  bool_t xdr_state_protect4_r(XDR *, state_protect4_r*);
extern  bool_t xdr_EXCHANGE_ID4resok(XDR *, EXCHANGE_ID4resok*);
extern  bool_t xdr_EXCHANGE_ID4res(XDR *, EXCHANGE_ID4res*);
extern  bool_t xdr_channel_attrs4(XDR *, channel_attrs4*);
extern  bool_t xdr_CREATE_SESSION4args(XDR *, CREATE_SESSION4args*);
extern  bool_t xdr_CREATE_SESSION4resok(XDR *, CREATE_SESSION4resok*);
extern  bool_t xdr_CREATE_SESSION4res(XDR *, CREATE_SESSION4res*);
extern  bool_t xdr_DESTROY_SESSION4args(XDR *, DESTROY_SESSION4args*);
extern  bool_t xdr_DESTROY_SESSION4res(XDR *, DESTROY_SESSION4res*);
extern  bool_t xdr_FREE_STATEID4args(XDR *, FREE_STATEID4args*);
extern  bool_t xdr_FREE_STATEID4res(XDR *, FREE_STATEID4res*);
extern  bool_t xdr_attr_notice4(XDR *, attr_notice4*);
extern  bool_t xdr_GET_DIR_DELEGATION4args(XDR *, GET_DIR_DELEGATION4args*);
extern  bool_t xdr_GET_DIR_DELEGATION4resok(XDR *, GET_DIR_DELEGATION4resok*);
extern  bool_t xdr_gddrnf4_status(XDR *, gddrnf4_status*);
extern  bool_t xdr_GET_DIR_DELEGATION4res_non_fatal(XDR *,
	GET_DIR_DELEGATION4res_non_fatal*);
extern  bool_t xdr_GET_DIR_DELEGATION4res(XDR *, GET_DIR_DELEGATION4res*);
extern  bool_t xdr_GETDEVICEINFO4args(XDR *, GETDEVICEINFO4args*);
extern  bool_t xdr_GETDEVICEINFO4resok(XDR *, GETDEVICEINFO4resok*);
extern  bool_t xdr_GETDEVICEINFO4res(XDR *, GETDEVICEINFO4res*);
extern  bool_t xdr_GETDEVICELIST4args(XDR *, GETDEVICELIST4args*);
extern  bool_t xdr_GETDEVICELIST4resok(XDR *, GETDEVICELIST4resok*);
extern  bool_t xdr_GETDEVICELIST4res(XDR *, GETDEVICELIST4res*);
extern  bool_t xdr_newtime4(XDR *, newtime4*);
extern  bool_t xdr_newoffset4(XDR *, newoffset4*);
extern  bool_t xdr_LAYOUTCOMMIT4args(XDR *, LAYOUTCOMMIT4args*);
extern  bool_t xdr_newsize4(XDR *, newsize4*);
extern  bool_t xdr_LAYOUTCOMMIT4resok(XDR *, LAYOUTCOMMIT4resok*);
extern  bool_t xdr_LAYOUTCOMMIT4res(XDR *, LAYOUTCOMMIT4res*);
extern  bool_t xdr_LAYOUTGET4args(XDR *, LAYOUTGET4args*);
extern  bool_t xdr_LAYOUTGET4resok(XDR *, LAYOUTGET4resok*);
extern  bool_t xdr_LAYOUTGET4res(XDR *, LAYOUTGET4res*);
extern  bool_t xdr_LAYOUTRETURN4args(XDR *, LAYOUTRETURN4args*);
extern  bool_t xdr_layoutreturn_stateid(XDR *, layoutreturn_stateid*);
extern  bool_t xdr_LAYOUTRETURN4res(XDR *, LAYOUTRETURN4res*);
extern  bool_t xdr_secinfo_style4(XDR *, secinfo_style4*);
extern  bool_t xdr_SECINFO_NO_NAME4args(XDR *, SECINFO_NO_NAME4args*);
extern  bool_t xdr_SECINFO_NO_NAME4res(XDR *, SECINFO_NO_NAME4res*);
extern  bool_t xdr_SEQUENCE4args(XDR *, SEQUENCE4args*);
extern  bool_t xdr_SEQUENCE4resok(XDR *, SEQUENCE4resok*);
extern  bool_t xdr_SEQUENCE4res(XDR *, SEQUENCE4res*);
extern  bool_t xdr_ssa_digest_input4(XDR *, ssa_digest_input4*);
extern  bool_t xdr_SET_SSV4args(XDR *, SET_SSV4args*);
extern  bool_t xdr_ssr_digest_input4(XDR *, ssr_digest_input4*);
extern  bool_t xdr_SET_SSV4resok(XDR *, SET_SSV4resok*);
extern  bool_t xdr_SET_SSV4res(XDR *, SET_SSV4res*);
extern  bool_t xdr_TEST_STATEID4args(XDR *, TEST_STATEID4args*);
extern  bool_t xdr_TEST_STATEID4resok(XDR *, TEST_STATEID4resok*);
extern  bool_t xdr_TEST_STATEID4res(XDR *, TEST_STATEID4res*);
extern  bool_t xdr_deleg_claim4(XDR *, deleg_claim4*);
extern  bool_t xdr_WANT_DELEGATION4args(XDR *, WANT_DELEGATION4args*);
extern  bool_t xdr_WANT_DELEGATION4res(XDR *, WANT_DELEGATION4res*);
extern  bool_t xdr_DESTROY_CLIENTID4args(XDR *, DESTROY_CLIENTID4args*);
extern  bool_t xdr_DESTROY_CLIENTID4res(XDR *, DESTROY_CLIENTID4res*);
extern  bool_t xdr_RECLAIM_COMPLETE4args(XDR *, RECLAIM_COMPLETE4args*);
extern  bool_t xdr_RECLAIM_COMPLETE4res(XDR *, RECLAIM_COMPLETE4res*);
extern  bool_t xdr_nfs_opnum4(XDR *, nfs_opnum4*);
extern  bool_t xdr_COMPOUND4args(XDR *, COMPOUND4args*);
extern  bool_t xdr_COMPOUND4res(XDR *, COMPOUND4res*);
extern  bool_t xdr_CB_GETATTR4args(XDR *, CB_GETATTR4args*);
extern  bool_t xdr_CB_GETATTR4res(XDR *, CB_GETATTR4res*);
extern  bool_t xdr_CB_RECALL4args(XDR *, CB_RECALL4args*);
extern  bool_t xdr_CB_RECALL4res(XDR *, CB_RECALL4res*);
extern  bool_t xdr_CB_ILLEGAL4res(XDR *, CB_ILLEGAL4res*);
extern  bool_t xdr_layoutrecall_type4(XDR *, layoutrecall_type4*);
extern  bool_t xdr_layoutrecall_file4(XDR *, layoutrecall_file4*);
extern  bool_t xdr_layoutrecall4(XDR *, layoutrecall4*);
extern  bool_t xdr_CB_LAYOUTRECALL4args(XDR *, CB_LAYOUTRECALL4args*);
extern  bool_t xdr_CB_LAYOUTRECALL4res(XDR *, CB_LAYOUTRECALL4res*);
extern  bool_t xdr_notify_type4(XDR *, notify_type4*);
extern  bool_t xdr_notify_entry4(XDR *, notify_entry4*);
extern  bool_t xdr_prev_entry4(XDR *, prev_entry4*);
extern  bool_t xdr_notify_remove4(XDR *, notify_remove4*);
extern  bool_t xdr_notify_add4(XDR *, notify_add4*);
extern  bool_t xdr_notify_attr4(XDR *, notify_attr4*);
extern  bool_t xdr_notify_rename4(XDR *, notify_rename4*);
extern  bool_t xdr_notify_verifier4(XDR *, notify_verifier4*);
extern  bool_t xdr_notifylist4(XDR *, notifylist4*);
extern  bool_t xdr_notify4(XDR *, notify4*);
extern  bool_t xdr_CB_NOTIFY4args(XDR *, CB_NOTIFY4args*);
extern  bool_t xdr_CB_NOTIFY4res(XDR *, CB_NOTIFY4res*);
extern  bool_t xdr_CB_PUSH_DELEG4args(XDR *, CB_PUSH_DELEG4args*);
extern  bool_t xdr_CB_PUSH_DELEG4res(XDR *, CB_PUSH_DELEG4res*);
extern  bool_t xdr_CB_RECALL_ANY4args(XDR *, CB_RECALL_ANY4args*);
extern  bool_t xdr_CB_RECALL_ANY4res(XDR *, CB_RECALL_ANY4res*);
extern  bool_t xdr_CB_RECALLABLE_OBJ_AVAIL4args(XDR *,
	CB_RECALLABLE_OBJ_AVAIL4args*);
extern  bool_t xdr_CB_RECALLABLE_OBJ_AVAIL4res(XDR *,
	CB_RECALLABLE_OBJ_AVAIL4res*);
extern  bool_t xdr_CB_RECALL_SLOT4args(XDR *, CB_RECALL_SLOT4args*);
extern  bool_t xdr_CB_RECALL_SLOT4res(XDR *, CB_RECALL_SLOT4res*);
extern  bool_t xdr_referring_call4(XDR *, referring_call4*);
extern  bool_t xdr_referring_call_list4(XDR *, referring_call_list4*);
extern  bool_t xdr_CB_SEQUENCE4args(XDR *, CB_SEQUENCE4args*);
extern  bool_t xdr_CB_SEQUENCE4resok(XDR *, CB_SEQUENCE4resok*);
extern  bool_t xdr_CB_SEQUENCE4res(XDR *, CB_SEQUENCE4res*);
extern  bool_t xdr_CB_WANTS_CANCELLED4args(XDR *, CB_WANTS_CANCELLED4args*);
extern  bool_t xdr_CB_WANTS_CANCELLED4res(XDR *, CB_WANTS_CANCELLED4res*);
extern  bool_t xdr_CB_NOTIFY_LOCK4args(XDR *, CB_NOTIFY_LOCK4args*);
extern  bool_t xdr_CB_NOTIFY_LOCK4res(XDR *, CB_NOTIFY_LOCK4res*);
extern  bool_t xdr_notify_deviceid_type4(XDR *, notify_deviceid_type4*);
extern  bool_t xdr_notify_deviceid_delete4(XDR *, notify_deviceid_delete4*);
extern  bool_t xdr_notify_deviceid_change4(XDR *, notify_deviceid_change4*);
extern  bool_t xdr_CB_NOTIFY_DEVICEID4args(XDR *, CB_NOTIFY_DEVICEID4args*);
extern  bool_t xdr_CB_NOTIFY_DEVICEID4res(XDR *, CB_NOTIFY_DEVICEID4res*);
extern  bool_t xdr_nfs_cb_opnum4(XDR *, nfs_cb_opnum4*);
extern  bool_t xdr_nfs_cb_argop4(XDR *, nfs_cb_argop4*);
extern  bool_t xdr_nfs_cb_resop4(XDR *, nfs_cb_resop4*);
extern  bool_t xdr_CB_COMPOUND4args(XDR *, CB_COMPOUND4args*);
extern  bool_t xdr_CB_COMPOUND4res(XDR *, CB_COMPOUND4res*);
/*  nfsv4.1 end */

/* nfsv4.2 */
struct sec_label4 {
	uint_t slai_len;
	char  *slai_val;
};

typedef struct sec_label4 sec_label4;
typedef sec_label4 fattr4_sec_label;

extern  bool_t xdr_fattr4_sec_label(XDR *xdrs, fattr4_sec_label *objp);
/* nfsv4.2 end */

/* NFSv4.x xdr */
extern bool_t xdr_nfs4x_argop4(XDR *xdrs, nfs_argop4 *objp);
extern bool_t xdr_nfs4x_resop4(XDR *xdrs, nfs_resop4 *objp);

/*
 * xdr for referrrals upcall
 */
extern	bool_t xdr_knetconfig(XDR *, struct knetconfig *);
extern	bool_t xdr_nfs_fsl_info(XDR *, struct nfs_fsl_info *);


#ifdef __cplusplus
}
#endif

#endif /* _NFS4_KPROT_H */
