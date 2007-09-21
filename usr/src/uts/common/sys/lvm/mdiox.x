%/*
% * CDDL HEADER START
% *
% * The contents of this file are subject to the terms of the
% * Common Development and Distribution License (the "License").
% * You may not use this file except in compliance with the License.
% *
% * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
% * or http://www.opensolaris.org/os/licensing.
% * See the License for the specific language governing permissions
% * and limitations under the License.
% *
% * When distributing Covered Code, include this CDDL HEADER in each
% * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
% * If applicable, add the following below this CDDL HEADER, with the
% * fields enclosed by brackets "[]" replaced with your own identifying
% * information: Portions Copyright [yyyy] [name of copyright owner]
% *
% * CDDL HEADER END
% */
%
%/*
% * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
% * Use is subject to license terms.
% */
%
%#pragma ident	"%Z%%M%	%I%	%E% SMI"
%
%/*
% *	MDD interface definitions
% */

%/* pick up multihost ioctl definitions */
%#include <sys/lvm/md_mhdx.h>
%/* get the basic XDR types */
%#include <sys/lvm/md_basic.h>
%/* pick up device id information */
%#include <sys/dditypes.h>

%#if _LONG_LONG_ALIGNMENT == 8 && _LONG_LONG_ALIGNMENT_32 == 4
%/*
% * NOTE: can't change these structures so make sure they are packed
% * in the kernel.
% */
%#pragma pack(4)
%#endif
%
%/*
% * fundamental types
% */
%
%/*
% *
% * NOTE: THESE ARE ON-DISK VALUES DO NOT CHANGE THE ORDER
% */
enum mddb_type_t {
	MDDB_ALL,
	MDDB_NM_HDR,
	MDDB_NM,
	MDDB_SHR_NM,
	MDDB_VTOC,
	MDDB_USER,
	MDDB_DID_NM_HDR,
	MDDB_DID_NM,
	MDDB_DID_SHR_NM,
	MDDB_EFILABEL,
	MDDB_FIRST_MODID = 1000
};

%
%/*
% * Configuration commands.
% */
enum mddb_cfgcmd_t {
	MDDB_USEDEV,
	MDDB_NEWDEV,
	MDDB_DELDEV,
	MDDB_GETDEV,
	MDDB_ENDDEV,
	MDDB_GETDRVRNAME,
	MDDB_RELEASESET,
	MDDB_NEWSIDE,
	MDDB_DELSIDE,
	MDDB_SETDID,
	MDDB_LBINITTIME
};

%
%/*
% * Return codes from DB record operations.
% */
enum mddb_recstatus_t {
	MDDB_NORECORD,
	MDDB_NODATA,
	MDDB_OK,
	MDDB_STALE
};

%
%/*
% * Commands for DB accesses from user land.
% */
enum mddb_usercmd_t {
	MD_DB_GETNEXTREC,
	MD_DB_COMMIT_ONE,
	MD_DB_COMMIT_MANY,
	MD_DB_GETDATA,
	MD_DB_DELETE,
	MD_DB_CREATE,
	MD_DB_GETSTATUS,
	MD_DB_GETSIZE,
	MD_DB_SETDATA,
	MD_DB_MAKEID
};

%
%/*
% * MDDB_USER record subtypes, set records and drive records.
% * Node records (NR) used for Multinode Disksets.
% * The MDDB_UR_SR record subtype is associated with the structures
% * md_set_record and md_mnset_record.
% * The MDDB_UR_DR record subtype is associated with the structure
% * md_drive_record.
% * The MDDB_NR_DR record subtype is associated with the structure
% * md_mnnode_record.
% * The MDDB_UR_LR record subtype is associated with the structure
% * md_mn_changelog_record_t
% */
enum mddb_userrec_t {
	MDDB_UR_ALL,
	MDDB_UR_SR,
	MDDB_UR_DR,
	MDDB_UR_NR,
	MDDB_UR_LR
};

%
%/*
% * MDDB_USER record get commands.
% */
enum md_ur_get_cmd_t {
	MD_UR_GET_NEXT,
	MD_UR_GET_WKEY
};

%
%/*
% * These are the options for mddb_createrec()
% */
enum md_create_rec_option_t {
	MD_CRO_NOOPT		= 0x000,
	MD_CRO_OPTIMIZE		= 0x001,
	MD_CRO_32BIT		= 0x002,
	MD_CRO_64BIT		= 0x004,
	MD_CRO_STRIPE		= 0x008,
	MD_CRO_MIRROR		= 0x010,
	MD_CRO_RAID		= 0x020,
	MD_CRO_SOFTPART		= 0x040,
	MD_CRO_TRANS_MASTER	= 0x080,
	MD_CRO_TRANS_LOG	= 0x100,
	MD_CRO_HOTSPARE		= 0x200,
	MD_CRO_HOTSPARE_POOL	= 0x400,
	MD_CRO_CHANGELOG	= 0x800,
	MD_CRO_FN		= 0x1000
};

%
%/*
% * This SKEW value is used to skew the sideno of
% * the share device names that are put into each
% * local set's namespace.  This will prevent the
% * wrong name to be picked up via a devno, when
% * we really wanted a local device name.
% */
const	SKEW = 1;

#ifdef	RPC_XDR
%
%/* Start - Avoid duplicate definitions, but get the xdr calls right */
%#if 0
#include "meta_arr.x"
%#endif	/* 0 */
%/* End   - Avoid duplicate definitions, but get the xdr calls right */
%
#endif	/* RPC_XDR */

const	MD_DRIVE_RECORD_REVISION = 0x00010000;

#ifdef RPC_HDR
%
%#define	MD_DR_ADD		0x00000001U
%#define	MD_DR_DEL		0x00000002U
%#define	MD_DR_FIX_MB_DID	0x10000000U /* Fix MB */
%#define	MD_DR_FIX_LB_NM_DID	0x20000000U /* Fix LB and namespaces */
%#define	MD_DR_UNRSLV_REPLICATED	0x40000000U
%#define	MD_DR_OK		0x80000000U
#endif	/* RPC_HDR */

#if !defined(_KERNEL)
struct md_drive_record {
	u_int			dr_revision;	/* revision level */
	u_int			dr_flags;	/* state flags */
	mddb_recid_t		dr_selfid;	/* db record id */
	md_timeval32_t		dr_ctime;	/* creation timestamp */
	u_long			dr_genid;	/* generation id */
	md_drive_record		*dr_next;	/* next ptr (Incore) */
	mddb_recid_t		dr_nextrec;	/* next record id */
	int			dr_dbcnt;	/* # of replica's */
	int			dr_dbsize;	/* replica size */
	mdkey_t			dr_key;		/* namespace key */
};
#else /* _KERNEL */
struct md_drive_record {
	u_int			dr_revision;	/* revision level */
	u_int			dr_flags;	/* state flags */
	mddb_recid_t		dr_selfid;	/* db record id */
	md_timeval32_t		dr_ctime;	/* creation timestamp */
	u_int			dr_genid;	/* generation id */
	u_int			dr_next;	/* next ptr (Incore) */
	mddb_recid_t		dr_nextrec;	/* next record id */
	int			dr_dbcnt;	/* # of replica's */
	int			dr_dbsize;	/* replica size */
	mdkey_t			dr_key;		/* namespace key */
};
#endif /* !_KERNEL */

#ifdef RPC_HDR
%/*
% * Actions that can be taken on a node record.
% * Used with routine upd_nr_flags.
% */
%
%#define	MD_NR_JOIN	0x00000001U	/* Turn on JOIN flag */
%#define	MD_NR_WITHDRAW	0x00000002U	/* Turn off JOIN flag */
%#define	MD_NR_SET	0x00000004U	/* Set node flags in nodelist */
%#define	MD_NR_DEL	0x00000008U	/* reset OK flag, set DEL */
%#define	MD_NR_OK	0x80000000U	/* set OK flag; reset ADD */
#endif	/* RPC_HDR */

struct md_mnnode_record {
	u_int			nr_revision;	/* revision level */
	u_int			nr_flags;	/* state flags */
	mddb_recid_t		nr_selfid;	/* db record id */
	md_timeval32_t		nr_ctime;	/* creation timestamp */
	u_long			nr_genid;	/* generation id */
	md_mnnode_record	*nr_next;	/* next ptr (Incore) */
	mddb_recid_t		nr_nextrec;	/* next node rec id */
	u_int			nr_nodeid;	/* node id */
	md_node_nm_t		nr_nodename;	/* node name */

};

const	MD_MNNODE_RECORD_REVISION = 0x00000100;

const	MD_SET_RECORD_REVISION = 0x00010000;

#ifdef RPC_HDR
%
%#define	MD_SR_ADD		0x00000001U
%#define	MD_SR_DEL		0x00000002U
%#define	MD_SR_CHECK		0x00000004U
%#define	MD_SR_CVT		0x00000008U
%#define	MD_SR_LOCAL		0x00000010U
%#define	MD_SR_UNRSLV_REPLICATED	0x08000000U
%#define	MD_SR_MB_DEVID		0x10000000U
%#define	MD_SR_AUTO_TAKE		0x20000000U
%#define	MD_SR_MN		0x40000000U
%#define	MD_SR_OK		0x80000000U
%#define	MD_SR_STATE_FLAGS (MD_SR_ADD | \
%				   MD_SR_DEL | \
%				   MD_SR_CHECK | \
%				   MD_SR_CVT | \
%				   MD_SR_UNRSLV_REPLICATED | \
%				   MD_SR_OK)
#endif	/* RPC_HDR */

#if !defined(_KERNEL)
struct md_set_record {
	u_int			sr_revision;		/* revision level */
	u_int			sr_flags;		/* state flags */
	mddb_recid_t		sr_selfid;		/* db record id */
#ifdef RPC_HDR
	md_set_record		*sr_next;		/* next ptr (Incore) */
#endif	/* RPC_HDR */
	set_t			sr_setno;		/* set number */
	md_set_nm_t		sr_setname;		/* setname */
	md_timeval32_t		sr_ctime;		/* creation timestamp */
	u_long			sr_genid;		/* generation id */
	md_node_nm_arr_t	sr_nodes;		/* array of nodenames */
	md_drive_record		*sr_drivechain;		/* dr list (Incore) */
	mddb_recid_t		sr_driverec;		/* first dr record id */
	mhd_mhiargs_t		sr_mhiargs;		/* MH ioctl timeouts */
	md_h_arr_t		sr_med;			/* Mediator hosts */
};
#else /* _KERNEL */
struct md_set_record {
	u_int			sr_revision;		/* revision level */
	u_int			sr_flags;		/* state flags */
	mddb_recid_t		sr_selfid;		/* db record id */
#ifdef RPC_HDR
	u_int			sr_next;		/* next ptr (Incore) */
#endif  /* RPC_HDR */
	set_t			sr_setno;		/* set number */
	md_set_nm_t		sr_setname;		/* setname */
	md_timeval32_t		sr_ctime;		/* creation timestamp */
	u_int			sr_genid;		/* generation id */
	md_node_nm_arr_t	sr_nodes;		/* array of nodenames */
	u_int			sr_drivechain;		/* dr list (Incore) */
	mddb_recid_t		sr_driverec;		/* first dr record id */
	mhd_mhiargs_t		sr_mhiargs;		/* MH ioctl timeouts */
	md_h_arr_t		sr_med;			/* Mediator hosts */
};
#endif /* !_KERNEL */

struct md_mnset_record {
	u_int			sr_revision;		/* revision level */
	u_int			sr_flags;		/* state flags */
	mddb_recid_t		sr_selfid;		/* db record id */
#ifdef RPC_HDR
	md_set_record		*sr_next;		/* next ptr (Incore) */
#endif	/* RPC_HDR */
	set_t			sr_setno;		/* set number */
	md_set_nm_t		sr_setname;		/* setname */
	md_timeval32_t		sr_ctime;		/* creation timestamp */
	u_long			sr_genid;		/* generation id */
	md_node_nm_arr_t	sr_nodes_bw_compat;	/* for compat with */
							/* md_set_record, */
							/* first node always */
							/* this node */
	md_drive_record		*sr_drivechain;		/* dr list (Incore) */
	mddb_recid_t		sr_driverec;		/* first dr record id */
	mhd_mhiargs_t		sr_mhiargs;		/* MH ioctl timeouts */
	md_h_arr_t		sr_med;			/* Mediator hosts */
	md_mnnode_record	*sr_nodechain;		/* node list (incore) */
	mddb_recid_t		sr_noderec;		/* first node rec id */
	md_node_nm_t		sr_master_nodenm;	/* Master nm (incore) */
	u_int			sr_master_nodeid;	/* Master id (incore) */
	u_int			sr_mddb_min_size;	/* min size of mddb */
};

#ifdef RPC_HDR
%
%#define	MD_SETOWNER_NO		0
%#define	MD_SETOWNER_YES		1
%#define	MD_SETOWNER_NONE	2
#endif	/* RPC_HDR */

%
%/* Gate key type */
struct	md_setkey_t {
	string			sk_host<>;
	set_t			sk_setno;
	string			sk_setname<>;
	md_timeval32_t		sk_key;
#ifdef	RPC_HDR
	struct md_setkey_t	*sk_next;
#endif	/* RPC_HDR */
};

%
%/* metadevice ID */
typedef	minor_t		unit_t;

%
%/* component ID */
struct comp_t {
	minor_t		mnum;		/* associated metadevice */
	md_dev64_t	dev;
};

%
%/* hotspare pool ID */
typedef	u_int		hsp_t;

#ifdef RPC_HDR
%
%#define	MD_HSP_NONE	((hsp_t)~0U)
#endif	/* RPC_HDR */

%
%/* hotspare ID */
struct hs_t {
	hsp_t		hsp;		/* associated hotspare pool */
	md_dev64_t	dev;		/* device ID */
};

%
%/* mnum or hsp */
typedef	u_int	minor_or_hsp_t;

%
%/*
% * name service stuff
% */
const	MD_MAXPREFIX = 127;
%
%#define	MD_MAX_CTDLEN	64

struct md_name_prefix {
	u_char		pre_len;
	char		pre_data[MD_MAXPREFIX];
};

const	MD_MAXSUFFIX = 40;
%
struct md_name_suffix {
	u_char		suf_prefix;
	u_char		suf_len;
	char		suf_data[MD_MAXSUFFIX];
};

struct md_splitname {
	md_name_prefix	sn_prefix;
	md_name_suffix	sn_suffix;
};

#ifdef RPC_HDR
%
%#define	SPN_PREFIX(spn)	((spn)->sn_prefix)
%#define	SPN_SUFFIX(spn)	((spn)->sn_suffix)
#endif	/* RPC_HDR */

%
%/*
% * Number of bits to represent a setno
% * this gives us all info to define masks and shifts ...
% * Also used for minor #, hsp id, recid mask and shifts.
% */
const	MD_BITSSET =	5;
const	MD_DEFAULTSETS =	4;
%
#ifdef RPC_HDR
%
%#define	MD_MAXSETS	(1 << MD_BITSSET)
%#define	MD_SETMASK	(MD_MAXSETS - 1)
#endif	/* RPC_HDR */

%
%/*
% * Define a file descriptor for lockfd
% * when the lock is not held.
% */
const	MD_NO_LOCK = -2;

%
%/*
% * accumulated setname
% */
struct mdsetname_t {
	string			setname<>;	/* logical name */
	set_t			setno;		/* set number */
#ifdef RPC_HDR
	struct md_set_desc	*setdesc;	/* Cache set/drive desc */
	int			lockfd;		/* used by meta_lock_* */
#endif /* RPC_HDR */
};

struct mdsetnamelist_t {
	mdsetnamelist_t	*next;
	mdsetname_t	*sp;
};

%
%/*
% * device name
% */
#ifdef RPC_HDR
%#define	MD_FULLNAME_ONLY	0x0
%#define	MD_BASICNAME_OK	0x1
%#define	MD_BYPASS_DAEMON	0x2
%
%#define	MD_SLICE0		0
%#define	MD_SLICE6		6
%#define	MD_SLICE7		7
%
%#define	MD_MAX_PARTS		17
#endif	/* RPC_HDR */

struct mdname_t {
#ifdef RPC_HDR
	struct mddrivename_t *drivenamep; /* back pointer to drive */
#endif /* RPC_HDR */
	string		cname<>;	/* cannonical name */
	string		bname<>;	/* block name */
	string		rname<>;	/* raw name */
	string		devicesname<>;	/* /devices name (or NULL) */
	string		minor_name<>;	/* minor name with respect to devid */
	md_dev64_t	dev;		/* major/minor (or NODEV64) */
#ifdef RPC_HDR
	mdkey_t		key;		/* namespace key (or MD_KEYBAD) */
#endif /* RPC_HDR */
	diskaddr_t	end_blk;	/* end of database replicas (or -1) */
	diskaddr_t	start_blk;	/* usable start block (or -1) */
};

%/* name structure (old style) */
struct o_mdname_t {
#ifdef RPC_HDR
	struct o_mddrivename_t *drivenamep; /* back pointer to drive */
#endif /* RPC_HDR */
	string		cname<>;	/* cannonical name */
	string		bname<>;	/* block name */
	string		rname<>;	/* raw name */
	string		devicesname<>;	/* /devices name (or NULL) */
	dev_t		dev;		/* major/minor (or NODEV64) */
#ifdef RPC_HDR
	mdkey_t		key;		/* namespace key (or MD_KEYBAD) */
#endif /* RPC_HDR */
	daddr_t		end_blk;	/* end of database replicas (or -1) */
	daddr_t		start_blk;	/* usable start block (or -1) */
};

struct mdnamelist_t {
	mdnamelist_t	*next;
	mdname_t	*namep;
};

%
%/*
% * drive name
% */
%/* name types */
enum mdnmtype_t {
	MDT_UNKNOWN = 0,		/* unknown type */
	MDT_ACCES,			/* could not access device */
	MDT_META,			/* metadevice name */
	MDT_COMP,			/* regular device name */
	MDT_FAST_META,			/* metadevice name (partial) */
	MDT_FAST_COMP			/* regular device name (partial) */
};

%/* metadevice types */
enum md_types_t {
	MD_UNDEFINED = 0,
	MD_DEVICE,
	MD_METAMIRROR,
	MD_METATRANS,
	MD_METARAID,
	MD_METASP
};

%/* SVM general device types
% *
% * META_DEVICE refers to any SVM metadevice
% * LOGICAL_DEVICE refers to any underlying physical device
% * HSP_DEVICE refers to a hotspare pool
% *
% * In the past, the device type can be determined via
% * the device name (such as d10, c1t1d1s1).  With
% * the friendly name implementation, it is not possible
% * to determine from the device name.  In the code,
% * whereever the device type is obvious that type will be
% * used explicitly otherwise 'UNKNOWN' will be used and
% * specific SVM lookup routines will be called to determine
% * the device type associated with the name.
% */
enum meta_device_type_t {
	UNKNOWN = 0,
	META_DEVICE,
	HSP_DEVICE,
	LOGICAL_DEVICE
}; 

#ifdef RPC_HDR
%
%/* misc module names */
%/* When modifying this list also update meta_names in md_names.c */
%#define	MD_STRIPE	"md_stripe"
%#define	MD_MIRROR	"md_mirror"
%#define	MD_TRANS	"md_trans"
%#define	MD_HOTSPARES	"md_hotspares"
%#define	MD_RAID		"md_raid"
%#define	MD_VERIFY	"md_verify"
%#define	MD_SP		"md_sp"
%#define	MD_NOTIFY	"md_notify"
#endif	/* RPC_HDR */

%/* generic device info */
struct mdgeom_t {
	u_int		ncyl;
	u_int		nhead;
	u_int		nsect;
	u_int		rpm;
	u_int		write_reinstruct;
	u_int		read_reinstruct;
	u_int		blk_sz;
};

%/* generic device info (old style) */
struct o_mdgeom_t {
	u_int		ncyl;
	u_int		nhead;
	u_int		nsect;
	u_int		rpm;
	u_int		write_reinstruct;
	u_int		read_reinstruct;
};

struct mdcinfo_t {
	char		cname[16];	/* controller driver name */
	mhd_ctlrtype_t	ctype;		/* controller type */
	u_int		cnum;		/* controller instance */
	u_int		tray;		/* SSA100 tray */
	u_int		bus;		/* SSA100 bus */
	u_longlong_t	wwn;		/* SSA100 World Wide Name */
	char		dname[16];	/* disk driver name */
	u_int		unit;		/* disk instance */
	u_int		maxtransfer;	/* max I/O size (in blocks) */
};

struct mdpart_t {
	diskaddr_t	start;		/* start block */
	diskaddr_t	size;		/* size of partition (in blocks) */
	u_short		tag;		/* ID tag of partition */
	u_short		flag;		/* permission flags */
	diskaddr_t	label;		/* size of disk label (or 0) */
};

%/* partition information (old style) */
struct o_mdpart_t {
	daddr_t		start;		/* start block */
	daddr_t		size;		/* size of partition (in blocks) */
	u_short		tag;		/* ID tag of partition */
	u_short		flag;		/* permission flags */
	daddr_t		label;		/* size of disk label (or 0) */
};

struct mdvtoc_t {
	u_int		nparts;
	diskaddr_t	first_lba;	/* for efi devices only */
	diskaddr_t	last_lba;	/* for efi devices only */
	diskaddr_t	lbasize;	/* for efi devices only */
	mdpart_t	parts[MD_MAX_PARTS];	/* room for i386 too */
	char		*typename;	/* disk type (or NULL) */
};

%/* vtoc information (old style) */
struct o_mdvtoc_t {
	char		*typename;	/* disk type (or NULL) */
	u_int		nparts;
	o_mdpart_t	parts[16];	/* room for i386 too */
};
%
%/*
% * List of drivename cnames per side,
% * also the driver name, mnum (for slice 7).
% */
struct mdsidenames_t {
	mdsidenames_t	*next;
	side_t		sideno;
	minor_t		mnum;
	string		dname<>;
	string		cname<>;
};

struct mddrivename_t {
#ifdef RPC_HDR
	/*
	 * the following string is not used but is left in place so that
	 * it is not necessary to version the rpc interface that passes
	 * this structure.
	 */
	string		not_used<>;
#endif	/* RPC_HDR */
	string		cname<>;	/* canonical drive name */
	string		rname<>;	/* raw name */
	mdnmtype_t	type;		/* type of drive */
	string		devid<>;	/* Device Id of the drive */
	int		errnum;		/* errno for type == MDT_ACCES */
	mdgeom_t	geom;		/* disk geometry */
	mdcinfo_t	cinfo;		/* controller info */
	mdvtoc_t	vtoc;		/* volume table of contents info */
	mdname_t	parts<>;	/* partitions in drive */
	mdsidenames_t	*side_names;	/* list of names per side */
	mdkey_t		side_names_key;	/* key used to store the side names*/

	string		miscname<>;	/* metadevice misc name */
#ifdef RPC_HDR
	struct md_common_t *unitp;	/* metadevice unit structure */
#endif	/* RPC_HDR */
};

%/*
% * old version of mddrivename_t that contains an old version of mdgeom_t,
% * mdvtoc_t and mdname_t (prefixed _o).
% */
struct o_mddrivename_t {
#ifdef RPC_HDR
	string		cachenm<>;	/* name used for cache lookups */
#endif	/* RPC_HDR */
	string		cname<>;	/* canonical drive name */
	string		rname<>;	/* raw name */
	mdnmtype_t	type;		/* type of drive */
	int		errnum;		/* errno for type == MDT_ACCES */
	o_mdgeom_t	geom;		/* disk geometry (old style) */
	mdcinfo_t	cinfo;		/* controller info */
	o_mdvtoc_t	vtoc;		/* vtoc info (old style) */
	o_mdname_t	parts<>;	/* partitions in drive (old style) */
	mdsidenames_t	*side_names;	/* list of names per side */
	mdkey_t		side_names_key;	/* key used to store the side names*/

	string		miscname<>;	/* metadevice misc name */
#ifdef RPC_HDR
	struct md_common_t *unitp;	/* metadevice unit structure */
#endif	/* RPC_HDR */
};
struct mddrivenamelist_t {
	mddrivenamelist_t *next;
	mddrivename_t	*drivenamep;
};

%
%/*
% * replica struct
% */
typedef	u_int	replica_flags_t;
#ifdef RPC_HDR
%
%#define	MDDB_F_EREAD	0x00001	/* a read error occurred */
%#define	MDDB_F_TOOSMALL	0x00002	/* replica is too small to hold db */
%#define	MDDB_F_EFMT	0x00004	/* something is wrong with the data */
%#define	MDDB_F_EDATA	0x00008	/* error in data blocks */
%#define	MDDB_F_EMASTER	0x00010	/* error in master block(s) */
%#define	MDDB_F_ACTIVE	0x00020	/* this replica is currently in use */
%#define	MDDB_F_EWRITE	0x00040	/* a write error occurred */
%#define	MDDB_F_MASTER	0x00080	/* the copy which was used as input */
%#define	MDDB_F_SUSPECT	0x00100	/* replica write ability is suspect */
%#define	MDDB_F_PTCHED	0x00400	/* db location was patched in kernel */
%#define	MDDB_F_IOCTL	0x00800	/* db location passed in from ioctl */
%#define	MDDB_F_GOTTEN	0x01000	/* getdev has been done on this dev */
%#define	MDDB_F_LOCACC	0x02000	/* the locator has been accessed */
%#define	MDDB_F_UP2DATE	0x04000	/* this copy of db is up to date */
%#define	MDDB_F_OLDACT	0x08000	/* this copy was active previously */
%#define	MDDB_F_DELETED	0x10000 /* place holder in empty slot */
%#define	MDDB_F_TAGDATA	0x20000 /* Data is tagged */
%#define	MDDB_F_BADTAG	0x40000 /* Data tag was not valid */
%#define	MDDB_F_NODEVID	0x80000 /* No devid associated with replica */
%
%/*
% * These are used in de_flags only
% * Do not change these values, they are stored on-disk
% */
%#define	MDDB_F_STRIPE		0x00001 /* record is a stripe record */
%#define	MDDB_F_MIRROR		0x00002 /* record is a mirror record */
%#define	MDDB_F_RAID		0x00004 /* record is a raid record */
%#define	MDDB_F_SOFTPART		0x00008 /* record is a sp record */
%#define	MDDB_F_TRANS_MASTER	0x00010 /* trans master record */
%#define	MDDB_F_TRANS_LOG	0x00020 /* trans log record */
%#define	MDDB_F_HOTSPARE		0x00040 /* hotspare record */
%#define	MDDB_F_HOTSPARE_POOL	0x00080 /* hotspare record */
%#define	MDDB_F_OPT		0x00200 /* optimization record */
%#define	MDDB_F_CHANGELOG	0x00400 /* change log record */

%/* used by metadb(1m) for printing */
%#define	MDDB_FLAGS_STRING	"RSFDMaWm  pc luo tBr"
%#define	MDDB_FLAGS_LEN		(strlen(MDDB_FLAGS_STRING))
%
%/*
% * See meta_prbits() in SUNWmd/lib/libmeta/meta_print.c for a description of
% * the way this is used
% */
%#define	MDDB_F_BITNAMES	"\020\001EREAD\002TOOSMALL\003EFMT\004EDATA" \
%				"\005EMASTER\006ACTIVE\007EWRITE\010MASTER" \
%				"\011SUSPECT\012OPT\013PTCHED\014IOCTL" \
%				"\015GOTTEN\016LOCACC\017UP2DATE\020OLDACT" \
%				"\021DELETED\022TAGDATA\023BADTAG\024NORELOC"
%
#endif	/* RPC_HDR */

/*
 * Refering to r_blkno and r_nblk:
 * A replica will always be smaller than 1 Terabyte, so no need to
 * change the ondisk structure to 64 bits.
 */
struct md_replica_t {
	mdname_t		*r_namep;
	replica_flags_t		r_flags;
	daddr_t			r_blkno;
	daddr_t			r_nblk;
	ddi_devid_t		r_devid;
	char			r_driver_name[MD_MAXDRVNM];
	char			r_minor_name[MDDB_MINOR_NAME_MAX];
};

struct md_replica_recerr_t {
	int			r_li;
	int			r_flags;
	daddr32_t		r_blkno;
	minor_t			r_mnum;
	char			r_driver_name[MD_MAXDRVNM];
};

struct md_replicalist_t {
	md_replicalist_t	*rl_next;
	md_replica_t		*rl_repp;
};

%
%/*
% * set/drive structs exposed by the library routines
% */
struct md_drive_desc {
	md_timeval32_t		dd_ctime;		/* creation time */
	u_long			dd_genid;		/* generation id */
	u_int			dd_flags;		/* state flags */
	md_drive_desc		*dd_next;		/* next drive */
	mddrivename_t		*dd_dnp;		/* drive name ptr */
	int			dd_dbcnt;		/* # of replicas */
	int			dd_dbsize;		/* size of replica */
};

%
%/*
% * set/drive structs exposed by the library routines (old style)
% */
struct o_md_drive_desc {
	md_timeval32_t		dd_ctime;		/* creation time */
	u_long			dd_genid;		/* generation id */
	u_int			dd_flags;		/* state flags */
	o_md_drive_desc		*dd_next;		/* next drive */
	o_mddrivename_t		*dd_dnp;		/* drive name ptr */
	int			dd_dbcnt;		/* # of replicas */
	int			dd_dbsize;		/* size of replica */
};

struct md_mnnode_desc {
	md_timeval32_t		nd_ctime;		/* creation time */
	u_long			nd_genid;		/* generation id */
	u_int			nd_flags;		/* state flags */
	md_mnnode_desc		*nd_next;		/* next node */
	md_mnnode_nm_t		nd_nodename;		/* name of node */
	u_int			nd_nodeid;		/* id of node */
	md_mnnode_nm_t		nd_priv_ic;		/* priv interconnect */
							/* nodename */
};

struct md_set_desc {
	md_timeval32_t		sd_ctime;		/* creation time */
	u_long			sd_genid;		/* generation id */
	set_t			sd_setno;		/* set number */
	u_int			sd_flags;		/* state flags */
	md_node_nm_arr_t	sd_nodes;		/* array of nodenames */
							/* for !MN_disksets */
	int			sd_isown[MD_MAXSIDES];	/* bool for is owner? */
	md_h_arr_t		sd_med;			/* Mediator hosts */
	md_drive_desc		*sd_drvs;		/* drive list */
	u_int			sd_mn_am_i_master;
	u_int			sd_mn_numnodes;		/* # of nodes in list */
	md_mnnode_desc		*sd_nodelist;		/* MN node list */
							/* for MN_disksets */
	md_node_nm_t		sd_mn_master_nodenm;	/* Master node name */
	u_int			sd_mn_master_nodeid;	/* Master node id */
	md_mnnode_desc		*sd_mn_mynode;		/* shortcut to me */
	md_mnnode_desc		*sd_mn_masternode;	/* shortcut to master */
};

%/*
% * Defines to determine if diskset is a Multinode diskset.
% * The sd_flags field in the md_set_desc structure is never manipulated
% * directly but is always a copy of the set record's sr_flags field, so
% * the same define (MD_SR_MN) can be used for both sd_flags and sr_flags.
% * The set record is of the structure type md_set_record if a regular diskset
% * or type md_mnset_record for a Multinode diskset.
%*/
%#define	MD_MNSET_DESC(sd)	(((sd)->sd_flags & MD_SR_MN) ? 1 : 0)
%#define	MD_MNSET_REC(sr)	(((sr)->sr_flags & MD_SR_MN) ? 1 : 0)
%#define	MD_MNDR_REC(dr)		(((dr)->dr_flags & MD_DR_MN) ? 1 : 0)

%/*
% * Define to determine if diskset is a Auto-Take diskset.
%*/
%#define	MD_ATSET_DESC(sd) (((sd)->sd_flags & MD_SR_AUTO_TAKE) ? 1 : 0)

%/*
% * Define to set the alive flag for a node.  A node is alive if it
% * is in the multi_node membership list.
% */
%#define	MD_MN_NODE_ALIVE	0x0001

%/*
% * Define to set the own flag for a node.  A node is an owner of the diskset
% * if that node has snarf'd in the mddb.
% */
%#define	MD_MN_NODE_OWN		0x0002

%/*
% * Defines to set the add, delete and ok states of a node.  The add state is
% * set at the beginning of the addition of a node to a diskset.   The
% * delete state is set at the beginning of a deletion of a node from a diskset.
% * The OK state is set (and the add state reset) when that node is
% * functional in the diskset.
% * Rollback join flag is used on an error condition when deleting the last
% * disk from a diskset. rpc.metad should never see this flag.
% * NOSET flag is used on an error condition during a reconfig cycle when
% * the set has been removed from this node.  rpc.metad should just ignore
% * this flag.
% */
%#define	MD_MN_NODE_ADD		0x0004
%#define	MD_MN_NODE_DEL		0x0008
%#define	MD_MN_NODE_OK		0x0010
%#define	MD_MN_NODE_RB_JOIN	0x0020
%#define	MD_MN_NODE_NOSET	0x0040

%/*
% * Define for invalid node id.   Used specifically to set mn set record
% * master nodeid to invalid when no master can be determined.
% */
%#define	MD_MN_INVALID_NID	0xfffffffful	/* invalid node id */

%
%/*
% * set description (old style)
% */
struct o_md_set_desc {
	md_timeval32_t		sd_ctime;		/* creation time */
	u_long			sd_genid;		/* generation id */
	set_t			sd_setno;		/* set number */
	u_int			sd_flags;		/* state flags */
	md_node_nm_arr_t	sd_nodes;		/* array of nodenames */
	int			sd_isown[MD_MAXSIDES];	/* bool for is owner? */
	md_h_arr_t		sd_med;			/* Mediator hosts */
	o_md_drive_desc		*sd_drvs;		/* drive list */
};

%
%/*
% * hotspare pool name
% */
struct mdhspname_t {
	string		hspname<>;	/* hotspare pool name */
	hsp_t		hsp;		/* number */

#ifdef RPC_HDR
	struct md_hsp_t	*unitp;		/* hotspare pool unit structure */
#endif	/* RPC_HDR */
};

struct mdhspnamelist_t {
	mdhspnamelist_t	*next;
	mdhspname_t	*hspnamep;
};

%
%/*
% *	generic metadevice descriptions for status and init
% */
%

%/*
% * following used with un_status
% * bottom 16 bits are global definitions
% * top 16 bits are defined by sub device
% */
typedef	u_int	md_status_t;
#ifdef RPC_HDR
%
%#define	MD_UN_GROW_PENDING	0x0008	/* grow mirror pending */
%#define	MD_UN_BEING_RESET	0x0040	/* reset at snarf time */
#endif	/* RPC_HDR */
%
%/*
% * following are used with un_parent
% *	MD_NO_PARENT	- Not a sub-device.
% *	MD_MULTI_PARENT	- A sub-device with one or more parents, like a log.
% *	other		- A sub-device with only one parent, like a submirror.
% *			  The number is the parent's unit number.
% */
typedef	unit_t	md_parent_t;
#ifdef RPC_HDR
%
%#define	MD_NO_PARENT		0xffffffffu
%#define	MD_MULTI_PARENT		0xfffffffeu
%#define	MD_HAS_PARENT(p)	((p) != MD_NO_PARENT)
#endif	/* RPC_HDR */

typedef	u_int	md_stackcap_t;
#ifdef RPC_HDR
%
%#define	MD_CANT_PARENT		0x00	/* cannot have a parent */
%#define	MD_CAN_PARENT		0x01	/* can have a parent */
%#define	MD_CAN_SUB_MIRROR	0x02	/* can be a sub-mirror */
%#define	MD_CAN_META_CHILD	0x04	/* can have metadev. children */
%#define	MD_CAN_SP		0x08	/* can be soft partitioned */

#endif	/* RPC_HDR */

/* common to all metadevices */
struct md_common_t {
	mdname_t	*namep;
	md_types_t	type;
	md_status_t	state;
	md_stackcap_t	capabilities;
	md_parent_t	parent;
	diskaddr_t	size;
	u_long		user_flags;
	u_longlong_t	revision;
};

%
%/*
% *	stripe
% */
/*
 * ioctl stuff
 */
struct ms_params_t {
	int		change_hsp_id;
	hsp_t		hsp_id;
};

/*
 * unit structure
 */
typedef u_int	comp_state_t;
#ifdef RPC_HDR
%
%#define	CS_OKAY		0x0001
%#define	CS_ERRED	0x0002
%#define	CS_RESYNC	0x0004
%#define	CS_LAST_ERRED	0x0008
%
%/* interlace values (in bytes) */
%#define	MININTERLACE	(16 * 512)
%#define	MAXINTERLACE	(100 * 1024 * 1024)
#endif	/* RPC_HDR */

struct md_comp_t {
	mdname_t	*compnamep;
	mdname_t	*hsnamep;
	comp_state_t	state;
	u_int		lasterrcnt;
	md_timeval32_t	timestamp;
};

struct md_row_t {
	diskaddr_t	interlace;
	diskaddr_t	row_size;
	md_comp_t	comps<>;
};

struct md_stripe_t {
	md_common_t	common;
	mdhspname_t	*hspnamep;
	md_row_t	rows<>;
};

%
%/*
% *	soft partition
% */
typedef uint64_t	xsp_offset_t;
typedef uint64_t	xsp_length_t;
typedef u_int		xsp_status_t;
%
%#define	SP_INIT		0x0001
%#define	SP_OK		0x0002
%#define	SP_LASTERR	0x0004
%
/*
 * unit structure
 */

struct md_sp_ext_t {
	xsp_offset_t	voff;
	xsp_offset_t	poff;
	xsp_length_t	len;
};

struct md_sp_t {
	md_common_t	common;
	mdname_t	*compnamep;	/* name of this component */
	xsp_status_t	status;		/* state of this soft partition */
	md_sp_ext_t	ext<>;
};

%
%/*
% *	mirror
% */
/*
 * ioctl stuff
 */
enum mm_wr_opt_t {
	WR_PARALLEL = 0,	/* write submirrors in parallel */
	WR_SERIAL		/* write submirrors one at a time */
};

enum mm_rd_opt_t {
	RD_LOAD_BAL = 0,	/* read submirrors roundrobin */
	RD_GEOMETRY,		/* read submirrors geometrically */
	RD_FIRST		/* read first submirror */
};

typedef	short	mm_pass_num_t;
const	MD_PASS_DEFAULT = 1;
const	MD_PASS_MAX = 9;

struct mm_params_t {
	int		change_read_option;
	mm_rd_opt_t	read_option;
	int		change_write_option;
	mm_wr_opt_t	write_option;
	int		change_pass_num;
	mm_pass_num_t	pass_num;
};

/*
 * unit structure
 */
typedef	u_int	sm_state_t;
#ifdef RPC_HDR
%
%#define	SMS_UNUSED		0x0000
%#define	SMS_RUNNING		0x0001
%#define	SMS_COMP_ERRED		0x0002
%#define	SMS_COMP_RESYNC		0x0004
%#define	SMS_ATTACHED		0x0008
%#define	SMS_ATTACHED_RESYNC	0x0010
%#define	SMS_OFFLINE		0x0020
%#define	SMS_OFFLINE_RESYNC	0x0040
%#define	SMS_ALL_ERRED		0x0080
%#define	SMS_INUSE		(0xffff)
%#define	SMS_LIMPING		(SMS_COMP_ERRED | SMS_COMP_RESYNC)
%#define	SMS_IGNORE		0x4000
#endif	/* RPC_HDR */

typedef	u_int	sm_flags_t;
#ifdef RPC_HDR
%
%#define	MD_SM_RESYNC_TARGET	0x0001
%#define	MD_SM_FAILFAST		0x0002
#endif	/* RPC_HDR */

struct md_submirror_t {
	mdname_t	*submirnamep;
	sm_state_t	state;
	sm_flags_t	flags;
	md_timeval32_t	timestamp;
};

#ifdef RPC_HDR
%
%#define	MD_UN_RESYNC_ACTIVE	0x00010000
%#define	MD_UN_WAR		0x00020000
%#define	MD_UN_OFFLINE_SM	0x00040000
%#define	MD_UN_OPT_NOT_DONE	0x00080000
%#define	MD_UN_KEEP_DIRTY	(MD_UN_OFFLINE_SM | MD_UN_OPT_NOT_DONE)
%#define	MD_UN_RESYNC_CANCEL	0x00100000
%#define	MD_UN_REPLAYED		0x00200000
%#define	MD_UN_RENAMING		0x00400000
%#define	MD_UN_MOD_INPROGRESS	(MD_UN_RESYNC_ACTIVE	|	\
%					 MD_UN_OPT_NOT_DONE	|	\
%					 MD_UN_RENAMING)
#endif	/* RPC_HDR */

const	NMIRROR = 4;
struct md_mirror_t {
	md_common_t	common;
	mm_rd_opt_t	read_option;
	mm_wr_opt_t	write_option;
	mm_pass_num_t	pass_num;
	int		percent_done;
	int		percent_dirty;
	md_submirror_t	submirrors[NMIRROR];
};


%
%/*
% *	trans
% */
%/*
% * unit structure
% */
typedef	u_int	mt_flags_t;
#ifdef RPC_HDR
%
%#define	TRANS_NEED_OPEN		0x0001	/* subdevs are unopened */
%#define	TRANS_OPENED		0x0002	/* open at snarf succeeded */
%#define	TRANS_DETACHING		0x0004	/* detaching the log */
%#define	TRANS_DETACHED		0x0008	/* log successfully detached */
%#define	TRANS_DETACH_SKIP	0x0010	/* already processed; skip */
%#define	TRANS_ATTACHING		0x0020	/* attaching the log */
%#define	TRANS_ROLL_ON_WRITE	0x0040	/* roll on physio write */
%#define	TRANS_NEED_SCANROLL	0x0080	/* roll on physio write */
#endif	/* RPC_HDR */

typedef	u_int	mt_l_error_t;
#ifdef RPC_HDR
%
%#define	LDL_ERROR	0x0001	/* error state */
%#define	LDL_HERROR	0x0002	/* hard error state */
%#define	LDL_ANYERROR	0x0003	/* any error state */
%#define	LDL_NOERROR	0x0004	/* dont error transition during scan */
%#define	LDL_SAVERROR	0x0008	/* transition to error after scan */
#endif	/* RPC_HDR */

typedef	u_int	mt_debug_t;	/* values in md_trans.h */

struct md_trans_t {
	md_common_t	common;
	mdname_t	*masternamep;
	mdname_t	*lognamep;
	mt_flags_t	flags;
	md_timeval32_t	timestamp;
	mt_l_error_t	log_error;
	md_timeval32_t log_timestamp;
	daddr_t		log_size;
	mt_debug_t	debug;
};



%
%/*
% *	RAID
% */
/*
 * ioctl stuff
 */
struct mr_params_t {
	int		change_hsp_id;
	hsp_t		hsp_id;
};

/*
 * unit structure
 */
enum rcs_state_t {
	RCS_UNUSED = 0x0,
	RCS_INIT = 0x1,
	RCS_OKAY = 0x2,
	RCS_ERRED = 0x4,
	RCS_LAST_ERRED = 0x8,
	RCS_RESYNC = 0x10,
	RCS_INIT_ERRED = 0x20,
	RCS_REGEN = 0x40
};

typedef	u_int	rcs_flags_t;
#ifdef RPC_HDR
%
%#define	MD_RAID_DEV_ISOPEN	0x00001
%#define	MD_RAID_ALT_ISOPEN	0x00002
%#define	MD_RAID_RESYNC		0x00004
%#define	MD_RAID_RESYNC_ERRED	0x00008
%#define	MD_RAID_FORCE_REPLACE	0x00010
%#define	MD_RAID_WRITE_ALT	0x00020
%#define	MD_RAID_DEV_ERRED	0x00040
%#define	MD_RAID_COPY_RESYNC	0x00080
%#define	MD_RAID_REGEN_RESYNC	0x00100
%#define	MD_RAID_DEV_PROBEOPEN	0x00200
%#define	MD_RAID_HAS_LABEL	0x40000
#endif	/* RPC_HDR */

struct md_raidcol_t {
	mdname_t	*colnamep;
	mdname_t	*hsnamep;
	rcs_state_t	state;
	rcs_flags_t	flags;
	md_timeval32_t	timestamp;
};

enum rus_state_t {
	RUS_UNUSED = 0x0,
	RUS_INIT = 0x1,
	RUS_OKAY = 0x2,
	RUS_ERRED = 0x4,
	RUS_LAST_ERRED = 0x8,
	RUS_DOI = 0x10,
	RUS_REGEN = 0x20
};

typedef	u_int	md_riflags_t;
#ifdef RPC_HDR
%
%#define	MD_RI_INPROGRESS		0x0001
%#define	MD_GROW_INPROGRESS		0x0002
%#define	MD_RI_BLOCK			0x0004
%#define	MD_RI_UNBLOCK			0x0008
%#define	MD_RI_KILL			0x0010
%#define	MD_RI_BLOCK_OWNER		0x0020
%#define	MD_RI_SHUTDOWN			0x0040
%#define	MD_RI_NO_WAIT			0x0080
%#define	MD_RI_RESYNC_FORCE_MNSTART	0x0100
#endif	/* RPC_HDR */

const	MD_RAID_MIN = 3;
struct md_raid_t {
	md_common_t	common;
	rus_state_t	state;
	md_timeval32_t	timestamp;
	diskaddr_t	interlace;
	diskaddr_t	column_size;
	size_t		orig_ncol;
	mdhspname_t	*hspnamep;
	md_riflags_t	resync_flags;
	int		percent_dirty;
	int		percent_done;
	int		pw_count;
	md_raidcol_t	cols<>;
};

%
%/*
% *	shared
% */
/*
 * unit structure
 */
struct md_shared_t {
	md_common_t	common;
};

%
%/*
% *	hotspare
% */
/*
 * ioctl stuff
 */
enum hotspare_states_t {
	HSS_UNUSED, HSS_AVAILABLE, HSS_RESERVED, HSS_BROKEN
};

/*
 * unit structure
 */
struct md_hs_t {
	mdname_t	*hsnamep;
	hotspare_states_t state;
	diskaddr_t	size;
	md_timeval32_t	timestamp;
	u_longlong_t	revision;
};

struct md_hsp_t {
	mdhspname_t	*hspnamep;
	u_int		refcount;
	md_hs_t		hotspares<>;
};

%
%/*
% * specific error info
% */
%
%/*
% * simple errors
% */
enum md_void_errno_t {
	MDE_NONE = 0,
	MDE_UNIT_NOT_FOUND,
	MDE_DUPDRIVE,
	MDE_INVAL_HSOP,
	MDE_NO_SET,		/* no such set */
	MDE_SET_DIFF,		/* setname changed on command line */
	MDE_BAD_RD_OPT,		/* bad mirror read option */
	MDE_BAD_WR_OPT,		/* bad mirror write option */
	MDE_BAD_PASS_NUM,	/* bad mirror pass number */
	MDE_BAD_INTERLACE,	/* bad stripe interlace */
	MDE_NO_HSPS,		/* couldn't find any hotspare pools */
	MDE_NOTENOUGH_DB,	/* Too few replicas */
	MDE_DELDB_NOTALLOWED,	/* last replica in ds cannot be del in metadb */
	MDE_DEL_VALIDDB_NOTALLOWED,	/* last valid replica cannot be del */
	MDE_SYSTEM_FILE,	/* /etc/system file error */
	MDE_MDDB_FILE,		/* /etc/lvm/mddb.cf file error */
	MDE_MDDB_CKSUM,		/* /etc/lvm/mddb.cf checksum error */
	MDE_VFSTAB_FILE,	/* /etc/vfstab file error */
	MDE_NOSLICE,		/* metaslicename() with sliceno to big */
	MDE_SYNTAX,		/* metainit syntax error */
	MDE_OPTION,		/* metainit options error */
	MDE_TAKE_OWN,		/* take ownership failed */
	MDE_NOT_DRIVENAME,	/* not in drivename syntax */
	MDE_RESERVED,		/* device is reserved by another host */
	MDE_DVERSION,		/* driver version out of sync */
	MDE_MVERSION,		/* MDDB version out of sync */
	MDE_TESTERROR,		/* Test Error Message */
	MDE_BAD_ORIG_NCOL,	/* bad RAID original column count */
	MDE_RAID_INVALID,	/* attempt to use -k on invalid device */
	MDE_MED_ERROR,		/* mediator error */
	MDE_TOOMANYMED,		/* Too many mediators specified */
	MDE_NOMED,		/* No mediators */
	MDE_ONLYNODENAME,	/* Only the nodename is needed */
	MDE_RAID_BAD_PW_CNT,	/* bad prewrite count specified */
	MDE_DEVID_TOOBIG,	/* Devid size is greater than allowed */
	MDE_NOPERM,		/* No permission - not root */
	MDE_NODEVID,		/* No device id for given devt */
	MDE_NOROOT,		/* No root in /etc/mnttab */
	MDE_EOF_TRANS,		/* trans logging eof'd */
	MDE_BAD_RESYNC_OPT,	/* bad mirror resync option */
	MDE_NOT_MN,		/* option only valid within a multi-node set */
	MDE_ABR_SET,		/* invalid operation for ABR mirror */
	MDE_INVAL_MNOP,		/* Invalid operation on MN diskset */
	MDE_MNSET_NOTRANS,	/* Trans metadevice not supported in MN set */
	MDE_MNSET_NORAID,	/* RAID metadevice not supported in MN set */
	MDE_FORCE_DEL_ALL_DRV,	/* Must use -f flag to delete all drives */
	MDE_STRIPE_TRUNC_SINGLE,	/* single component stripe truncation */
	MDE_STRIPE_TRUNC_MULTIPLE,	/* multiple component stripe trun */
	MDE_SMF_FAIL,		/* service management facility error */
	MDE_SMF_NO_SERVICE,	/* service not enabled in SMF */
	MDE_AMBIGUOUS_DEV,	/* Ambiguous device specified */
	MDE_NAME_IN_USE,	/* Friendly name already in use.  For */
				/* instance name desired for hot spare pool */
				/* is being used for a metadevice. */
	MDE_ZONE_ADMIN,		/* in a zone & no admin device */
	MDE_NAME_ILLEGAL,	/* illegal syntax for metadevice or hsp name */
	MDE_MISSING_DEVID_DISK	/* unable to find disk using devid */
};

struct md_void_error_t {
	md_void_errno_t		errnum;
};

%
%/*
% * system errors
% */
struct md_sys_error_t {
	int			errnum;
};

%
%/*
% * RPC errors
% */
struct md_rpc_error_t {
	enum clnt_stat		errnum;
};

%
%/*
% * device errors
% */
enum md_dev_errno_t {
	MDE_INVAL_HS = 1,
	MDE_FIX_INVAL_STATE,
	MDE_FIX_INVAL_HS_STATE,
	MDE_NOT_META,
	MDE_IS_META,
	MDE_IS_SWAPPED,
	MDE_NAME_SPACE,
	MDE_IN_SHARED_SET,
	MDE_NOT_IN_SET,
	MDE_NOT_DISK,
	MDE_CANT_CONFIRM,
	MDE_INVALID_PART,
	MDE_HAS_MDDB,
	MDE_NO_DB,		/* Replica not on device given */
	MDE_CANTVERIFY_VTOC,
	MDE_NOT_LOCAL,
	MDE_DEVICES_NAME,
	MDE_REPCOMP_INVAL,	/* replica slice not allowed in "set" metadevs */
	MDE_REPCOMP_ONLY,	/* only replica slice diskset replicas */
	MDE_INV_ROOT,		/* Invalid root device for this operation */
	MDE_MULTNM,		/* Multiple entries for device in namespace */
	MDE_TOO_MANY_PARTS,	/* dev has more than MD_MAX_PARTS partitions */
	MDE_REPART_REPLICA,	/* replica slice would move with repartitioning */
	MDE_IS_DUMP,		/* device already in use as dump device */
	MDE_DISKNAMETOOLONG	/* devid's not in use and diskname too long */
};

struct md_dev_error_t {
	md_dev_errno_t		errnum;
	md_dev64_t		dev;	/* 64 bit fixed size */
};

%
%/*
% * overlap errors
% */
enum md_overlap_errno_t {
	MDE_OVERLAP_MOUNTED = 1,
	MDE_OVERLAP_SWAP,
	MDE_OVERLAP_DUMP
};

%

#if !defined(_KERNEL)
struct md_overlap_error_t {
	md_overlap_errno_t	errnum;
	string			where<>;
	string			overlap<>;
};
#else
struct md_overlap_error_t {
	md_overlap_errno_t	errnum;
	u_int			xwhere;
	u_int			xoverlap;
};
#endif /* !_KERNEL */

%
%/*
% * use errors
% */
enum md_use_errno_t {
	MDE_IS_MOUNTED = 1,
	MDE_ALREADY,
	MDE_OVERLAP,
	MDE_SAME_DEVID
};

%
#if !defined(_KERNEL)
struct md_use_error_t {
	md_use_errno_t		errnum;
	md_dev64_t		dev;
	string			where<>;
};
#else
struct md_use_error_t {
	md_use_errno_t		errnum;
	md_dev64_t		dev;
	u_int			xwhere;
};
#endif

%
%/*
% * metadevice errors
% */
enum md_md_errno_t {
	MDE_INVAL_UNIT = 1,
	MDE_UNIT_NOT_SETUP,
	MDE_UNIT_ALREADY_SETUP,
	MDE_NOT_MM,
	MDE_NOT_ENOUGH_DBS,
	MDE_IS_SM,
	MDE_IS_OPEN,
	MDE_C_WITH_INVAL_SM,
	MDE_RESYNC_ACTIVE,
	MDE_LAST_SM_RE,
	MDE_MIRROR_FULL,
	MDE_IN_USE,
	MDE_SM_TOO_SMALL,
	MDE_NO_LABELED_SM,
	MDE_SM_OPEN_ERR,
	MDE_CANT_FIND_SM,
	MDE_LAST_SM,
	MDE_NO_READABLE_SM,
	MDE_SM_FAILED_COMPS,
	MDE_ILLEGAL_SM_STATE,
	MDE_RR_ALLOC_ERROR,
	MDE_MIRROR_OPEN_FAILURE,
	MDE_MIRROR_THREAD_FAILURE,
	MDE_GROW_DELAYED,
	MDE_NOT_MT,
	MDE_HS_IN_USE,
	MDE_HAS_LOG,
	MDE_UNKNOWN_TYPE,
	MDE_NOT_STRIPE,
	MDE_NOT_RAID,
	MDE_NROWS,
	MDE_NCOMPS,
	MDE_NSUBMIRS,
	MDE_BAD_STRIPE,
	MDE_BAD_MIRROR,
	MDE_BAD_TRANS,
	MDE_BAD_RAID,
	MDE_RAID_OPEN_FAILURE,
	MDE_RAID_THREAD_FAILURE,
	MDE_RAID_NEED_FORCE,
	MDE_NO_LOG,
	MDE_RAID_DOI,
	MDE_RAID_LAST_ERRED,
	MDE_RAID_NOT_OKAY,
	MDE_RENAME_BUSY,
	MDE_RENAME_SOURCE_BAD,
	MDE_RENAME_TARGET_BAD,
	MDE_RENAME_TARGET_UNRELATED,
	MDE_RENAME_CONFIG_ERROR,
	MDE_RENAME_ORDER,
	MDE_RECOVER_FAILED,
	MDE_NOT_SP,
	MDE_SP_NOSPACE,
	MDE_SP_BADWMREAD,
	MDE_SP_BADWMWRITE,
	MDE_SP_BADWMMAGIC,
	MDE_SP_BADWMCRC,
	MDE_SP_OVERLAP,
	MDE_SP_BAD_LENGTH,
	MDE_UNIT_TOO_LARGE,
	MDE_LOG_TOO_LARGE,
	MDE_SP_NOSP,
	MDE_IN_UNAVAIL_STATE
};

struct md_md_error_t {
	md_md_errno_t		errnum;
	minor_t			mnum;
};

%
%/*
% * component errors
% */
enum md_comp_errno_t {
	MDE_CANT_FIND_COMP = 1,
	MDE_REPL_INVAL_STATE,
	MDE_COMP_TOO_SMALL,
	MDE_COMP_OPEN_ERR,
	MDE_RAID_COMP_ERRED,
	MDE_MAXIO,
	MDE_SP_COMP_OPEN_ERR
};

struct md_comp_error_t {
	md_comp_errno_t		errnum;
	comp_t			comp;
};

%
%/*
% * hotspare pool errors
% */
enum md_hsp_errno_t {
	MDE_HSP_CREATE_FAILURE = 1,
	MDE_HSP_IN_USE,
	MDE_INVAL_HSP,
	MDE_HSP_BUSY,
	MDE_HSP_REF,
	MDE_HSP_ALREADY_SETUP,
	MDE_BAD_HSP,
	MDE_HSP_UNIT_TOO_LARGE
};

struct md_hsp_error_t {
	md_hsp_errno_t		errnum;
	hsp_t			hsp;
};

%
%/*
% * hotspare errors
% */
enum md_hs_errno_t {
	MDE_HS_RESVD = 1,
	MDE_HS_CREATE_FAILURE,
	MDE_HS_INUSE,
	MDE_HS_UNIT_TOO_LARGE
};

struct md_hs_error_t {
	md_hs_errno_t		errnum;
	hs_t			hs;
};

%
%/*
% * MDDB errors
% */
enum md_mddb_errno_t {
	MDE_TOOMANY_REPLICAS = 1,
	MDE_REPLICA_TOOSMALL,
	MDE_NOTVERIFIED,
	MDE_DB_INVALID,
	MDE_DB_EXISTS,
	MDE_DB_MASTER,
	MDE_DB_TOOSMALL,
	MDE_DB_NORECORD,
	MDE_DB_NOSPACE,
	MDE_DB_NOTNOW,
	MDE_DB_NODB,
	MDE_DB_NOTOWNER,
	MDE_DB_STALE,
	MDE_DB_TOOFEW,
	MDE_DB_TAGDATA,
	MDE_DB_ACCOK,
	MDE_DB_NTAGDATA,
	MDE_DB_ACCNOTOK,
	MDE_DB_NOLOCBLK,
	MDE_DB_NOLOCNMS,
	MDE_DB_NODIRBLK,
	MDE_DB_NOTAGREC,
	MDE_DB_NOTAG,
	MDE_DB_BLKRANGE
};

%
struct md_mddb_error_t {
	md_mddb_errno_t		errnum;
	minor_t			mnum;		/* associated metadevice */
	set_t			setno;
	u_int			size;
};

%
%/*
% * diskset (ds) errors
% */
enum md_ds_errno_t {
	MDE_DS_DUPHOST = 1,
	MDE_DS_NOTNODENAME,
	MDE_DS_SELFNOTIN,
	MDE_DS_NODEHASSET,
	MDE_DS_NODENOSET,
	MDE_DS_NOOWNER,
	MDE_DS_NOTOWNER,
	MDE_DS_NODEISNOTOWNER,
	MDE_DS_NODEINSET,
	MDE_DS_NODENOTINSET,
	MDE_DS_SETNUMBUSY,
	MDE_DS_SETNUMNOTAVAIL,
	MDE_DS_SETNAMEBUSY,
	MDE_DS_DRIVENOTCOMMON,
	MDE_DS_DRIVEINSET,
	MDE_DS_DRIVENOTINSET,
	MDE_DS_DRIVEINUSE,
	MDE_DS_DUPDRIVE,
	MDE_DS_INVALIDSETNAME,
	MDE_DS_HASDRIVES,
	MDE_DS_SIDENUMNOTAVAIL,
	MDE_DS_SETNAMETOOLONG,
	MDE_DS_NODENAMETOOLONG,
	MDE_DS_OHACANTDELSELF,
	MDE_DS_HOSTNOSIDE,
	MDE_DS_SETLOCKED,
	MDE_DS_ULKSBADKEY,
	MDE_DS_LKSBADKEY,
	MDE_DS_WRITEWITHSULK,
	MDE_DS_SETCLEANUP,
	MDE_DS_CANTDELSELF,
	MDE_DS_HASMED,
	MDE_DS_TOOMANYALIAS,
	MDE_DS_ISMED,
	MDE_DS_ISNOTMED,
	MDE_DS_INVALIDMEDNAME,
	MDE_DS_ALIASNOMATCH,
	MDE_DS_NOMEDONHOST,
	MDE_DS_CANTDELMASTER,
	MDE_DS_NOTINMEMBERLIST,
	MDE_DS_MNCANTDELSELF,
	MDE_DS_RPCVERSMISMATCH,
	MDE_DS_WITHDRAWMASTER,
	MDE_DS_COMMDCTL_SUSPEND_NYD,
	MDE_DS_COMMDCTL_SUSPEND_FAIL,
	MDE_DS_COMMDCTL_REINIT_FAIL,
	MDE_DS_COMMDCTL_RESUME_FAIL,
	MDE_DS_NOTNOW_RECONFIG,
	MDE_DS_NOTNOW_CMD,
	MDE_DS_COMMD_SEND_FAIL,
	MDE_DS_MASTER_ONLY,
	MDE_DS_DRIVENOTONHOST,
	MDE_DS_CANTRESNARF,
	MDE_DS_INSUFQUORUM,
	MDE_DS_EXTENDEDNM,
	MDE_DS_PARTIALSET,
	MDE_DS_SINGLEHOST,
	MDE_DS_AUTONOTSET,
	MDE_DS_INVALIDDEVID,
	MDE_DS_SETNOTIMP,
	MDE_DS_NOTSELFIDENTIFY
};

%
#if !defined(_KERNEL)
struct md_ds_error_t {
	md_ds_errno_t		errnum;
	set_t			setno;
	string			node<>;
	string			drive<>;
};
#else /* _KERNEL */
struct md_ds_error_t {
	md_ds_errno_t		errnum;
	set_t			setno;
	u_int			xnode;
	u_int			xdrive;
};
#endif /* !_KERNEL */

%
%/*
% * fundamental error type
% */
enum md_errclass_t {
	MDEC_VOID = 0,	/* simple error */
	MDEC_SYS,	/* system errno */
	MDEC_RPC,	/* RPC errno */
	MDEC_DEV,	/* device error */
	MDEC_USE,	/* use error */
	MDEC_MD,	/* metadevice error */
	MDEC_COMP,	/* component error */
	MDEC_HSP,	/* hotspare pool error */
	MDEC_HS,	/* hotspare error */
	MDEC_MDDB,	/* metadevice database error */
	MDEC_DS,	/* diskset error */
	MDEC_OVERLAP	/* overlap error */
};

%
%/*
% * error info
% */
union md_error_info_t
switch (md_errclass_t	errclass) {
case MDEC_VOID:
	md_void_error_t		void_error;
case MDEC_SYS:
	md_sys_error_t		sys_error;
case MDEC_RPC:
	md_rpc_error_t		rpc_error;
case MDEC_DEV:
	md_dev_error_t		dev_error;
case MDEC_USE:
	md_use_error_t		use_error;
case MDEC_MD:
	md_md_error_t		md_error;
case MDEC_COMP:
	md_comp_error_t		comp_error;
case MDEC_HSP:
	md_hsp_error_t		hsp_error;
case MDEC_HS:
	md_hs_error_t		hs_error;
case MDEC_MDDB:
	md_mddb_error_t		mddb_error;
case MDEC_DS:
	md_ds_error_t		ds_error;
case MDEC_OVERLAP:
	md_overlap_error_t	overlap_error;
};

%
#if !defined(_KERNEL)
struct md_error_t {
	md_error_info_t		info;		/* specific info */
	string			host<>;		/* hostname */
	string			extra<>;	/* extra context info */
	string			name<>;		/* file or device name */
};
#else /* _KERNEL */
struct md_error_t {
	md_error_info_t		info;		/* specific info */
	u_int			xhost;		/* hostname */
	u_int			xextra;	/* extra context info */
	u_int			xname;		/* file or device name */
};
#endif /* !_KERNEL */
%#if _LONG_LONG_ALIGNMENT == 8 && _LONG_LONG_ALIGNMENT_32 == 4
%#pragma pack()
%#endif

#ifdef	RPC_HDR
%
%/*
% * Null error constant
% */
%#define	MDNULLERROR		{{MDEC_VOID}, NULL, NULL, NULL}
#endif	/* RPC_HDR */

#ifdef RPC_XDR
%/*
% * Constant null error struct.
% */
%const		md_error_t		mdnullerror = MDNULLERROR;
#endif	/* RPC_XDR */

#ifdef RPC_HDR
%
%/*
% * External reference to constant null error struct. (declared in mdiox_xdr.c)
% */
%extern	const	md_error_t		mdnullerror;
%
%/*
% * External declarations
% */
%extern	void	mdclrerror(md_error_t *ep);	/* clear error */
%extern	int	mdstealerror(md_error_t *to, md_error_t *from);
%
%#define	mdiserror(ep, num)	(((ep)->info.errclass == MDEC_VOID) &&\
%	((ep)->info.md_error_info_t_u.void_error.errnum == (num)))
%#define	mdisok(ep)	mdiserror(ep, MDE_NONE)
%
%#define	mdissyserror(ep, num)	(((ep)->info.errclass == MDEC_SYS) && \
%	((ep)->info.md_error_info_t_u.sys_error.errnum == (num)))
%#define	mdisrpcerror(ep, num)	(((ep)->info.errclass == MDEC_RPC) && \
%	((ep)->info.md_error_info_t_u.rpc_error.errnum == (num)))
%#define	mdisdeverror(ep, num)	(((ep)->info.errclass == MDEC_DEV) && \
%	((ep)->info.md_error_info_t_u.dev_error.errnum == (num)))
%#define	mdisuseerror(ep, num)	(((ep)->info.errclass == MDEC_USE) && \
%	((ep)->info.md_error_info_t_u.use_error.errnum == (num)))
%#define	mdismderror(ep, num)	(((ep)->info.errclass == MDEC_MD) && \
%	((ep)->info.md_error_info_t_u.md_error.errnum == (num)))
%#define	mdiscomperror(ep, num)	(((ep)->info.errclass == MDEC_COMP) &&\
%	((ep)->info.md_error_info_t_u.comp_error.errnum == (num)))
%#define	mdishsperror(ep, num)	(((ep)->info.errclass == MDEC_HSP) && \
%	((ep)->info.md_error_info_t_u.hsp_error.errnum == (num)))
%#define	mdishserror(ep, num)	(((ep)->info.errclass == MDEC_HS) && \
%	((ep)->info.md_error_info_t_u.hs_error.errnum == (num)))
%#define	mdismddberror(ep, num)	(((ep)->info.errclass == MDEC_MDDB) &&\
%	((ep)->info.md_error_info_t_u.mddb_error.errnum == (num)))
%#define	mdisdserror(ep, num)	(((ep)->info.errclass == MDEC_DS) && \
%	((ep)->info.md_error_info_t_u.ds_error.errnum == (num)))
%#define	mdisoverlaperror(ep, num) \
%	(((ep)->info.errclass == MDEC_OVERLAP) && \
%	((ep)->info.md_error_info_t_u.ds_error.errnum == (num)))
%
%#define	mdanysyserror(ep)	((ep)->info.errclass == MDEC_SYS)
%#define	mdanyrpcerror(ep)	((ep)->info.errclass == MDEC_RPC)
%#define	mdanydeverror(ep)	((ep)->info.errclass == MDEC_DEV)
%#define	mdanyuseerror(ep)	((ep)->info.errclass == MDEC_USE)
%#define	mdanymderror(ep)	((ep)->info.errclass == MDEC_MD)
%#define	mdanycomperror(ep)	((ep)->info.errclass == MDEC_COMP)
%#define	mdanyhsperror(ep)	((ep)->info.errclass == MDEC_HSP)
%#define	mdanyhserror(ep)	((ep)->info.errclass == MDEC_HS)
%#define	mdanymddberror(ep)	((ep)->info.errclass == MDEC_MDDB)
%#define	mdanydserror(ep)	((ep)->info.errclass == MDEC_DS)
%#define	mdanyoverlaperror(ep)	((ep)->info.errclass == MDEC_OVERLAP)
%
#ifdef	_KERNEL
%
%extern	int	mderror(md_error_t *ep, md_void_errno_t errnum);
%extern	int	mdsyserror(md_error_t *ep, int errnum);
%extern	int	mddeverror(md_error_t *ep, md_dev_errno_t errnum,
%		    md_dev64_t dev);
%extern	int	mdmderror(md_error_t *ep, md_md_errno_t errnum, minor_t mnum);
%extern	int	mdcomperror(md_error_t *ep, md_comp_errno_t errnum,
%		    minor_t mnum, md_dev64_t dev);
%extern	int	mdhsperror(md_error_t *ep, md_hsp_errno_t errnum, hsp_t hsp);
%extern	int	mdhserror(md_error_t *ep, md_hs_errno_t errnum,
%		    hsp_t hsp, md_dev64_t dev);
%extern	int	mdmddberror(md_error_t *ep, md_mddb_errno_t errnum,
%		    minor_t mnum, set_t setno);
%extern	int	mddbstatus2error(md_error_t *ep, int status, minor_t mnum,
%		    set_t setno);
%
#else	/* ! _KERNEL */
%
%extern	int	mderror(md_error_t *ep, md_void_errno_t errnum, char *name);
%extern	int	mdsyserror(md_error_t *ep, int errnum, char *name);
%extern	int	mdrpcerror(md_error_t *ep, CLIENT *clntp, char *host,
%		    char *extra);
%extern	int	mdrpccreateerror(md_error_t *ep, char *host, char *extra);
%extern	int	mddeverror(md_error_t *ep, md_dev_errno_t errnum,
%		    md_dev64_t dev, char *name);
%extern	int	mduseerror(md_error_t *ep, md_use_errno_t errnum,
%		    md_dev64_t dev, char *where, char *name);
%extern	int	mdmderror(md_error_t *ep, md_md_errno_t errnum, minor_t mnum,
%		    char *name);
%extern	int	mdcomperror(md_error_t *ep, md_comp_errno_t errnum,
%		    minor_t mnum, md_dev64_t dev, char *name);
%extern	int	mdhsperror(md_error_t *ep, md_hsp_errno_t errnum, hsp_t hsp,
%		    char *name);
%extern	int	mdhserror(md_error_t *ep, md_hs_errno_t errnum,
%		    hsp_t hsp, md_dev64_t dev, char *name);
%extern	int	mdmddberror(md_error_t *ep, md_mddb_errno_t errnum,
%		    minor_t mnum, set_t setno, size_t size, char *name);
%extern	int	mddserror(md_error_t *ep, md_ds_errno_t errnum, set_t setno,
%		    char *node, char *drive, char *name);
%extern	int	mdoverlaperror(md_error_t *ep, md_overlap_errno_t errnum,
%		    char *overlap, char *where, char *name);
%
%extern	void	mderrorextra(md_error_t *ep, char *extra);
%
#endif	/* ! _KERNEL */
#endif	/* RPC_HDR */

/*
 * common unit structure
 */
struct mdc_unit {
	u_longlong_t	un_revision;	/* revision # (keep this a longlong) */
	md_types_t	un_type;	/* type of record */
	md_status_t	un_status;	/* status flags */
	int		un_parent_res; /* parent reserve index */
	int		un_child_res;	/* child reserve index */
	minor_t		un_self_id;	/* metadevice unit number */
	mddb_recid_t	un_record_id;	/* db record id */
	uint_t		un_size;	/* db record size for unit structure */
	ushort_t	un_flag;	/* configuration info */
	diskaddr_t	un_total_blocks; /* external # blocks in metadevice */
	diskaddr_t	un_actual_tb;	/* actual # blocks in metadevice */
	uint_t		un_nhead;	/* saved value of # heads */
	uint_t		un_nsect;	/* saved value of # sectors */
	ushort_t	un_rpm;		/* saved value of rpm's */
	ushort_t	un_wr_reinstruct; /* worse case write reinstruct */
	ushort_t	un_rd_reinstruct; /* worse case read reinstruct */
	mddb_recid_t	un_vtoc_id;	/* vtoc db record id */
	md_stackcap_t	un_capabilities; /* subdevice capabilities */
	md_parent_t	un_parent;	/* -1 none, -2 many, positive unit # */
	uint_t		un_user_flags;	/* provided for userland */
};
typedef struct mdc_unit mdc_unit_t;

/*
 * For old 32 bit format use only
 */
%#if _LONG_LONG_ALIGNMENT == 8 && _LONG_LONG_ALIGNMENT_32 == 4
%#pragma pack(4)
%#endif
struct mdc_unit32_od {
	u_longlong_t	un_revision;
	md_types_t	un_type;
	md_status_t	un_status;
	int		un_parent_res;
	int		un_child_res;
	minor_t		un_self_id;
	mddb_recid_t	un_record_id;
	uint_t		un_size;
	ushort_t	un_flag;
	daddr32_t	un_total_blocks; /* external # blocks in metadevice */
	daddr32_t	un_actual_tb;	/* actual # blocks in metadevice */
	ushort_t	un_nhead;
	ushort_t	un_nsect;
	ushort_t	un_rpm;
	ushort_t	un_wr_reinstruct;
	ushort_t	un_rd_reinstruct;
	mddb_recid_t	un_vtoc_id;
	md_stackcap_t	un_capabilities;
	md_parent_t	un_parent;
	uint_t		un_user_flags;
};
typedef struct mdc_unit32_od mdc_unit32_od_t;

struct md_unit {
	mdc_unit_t	c;	/* common stuff */
};
typedef struct md_unit md_unit_t;

enum sp_status_t {
	MD_SP_CREATEPEND,	/* soft partition creation in progress */
	MD_SP_GROWPEND,		/* attach operation in progress */
	MD_SP_DELPEND,		/* delete operation in progress */
	MD_SP_OK,		/* soft partition is stable */
	MD_SP_ERR,		/* soft partition is errored */
	MD_SP_RECOVER,		/* recovery operation in progess */
	MD_SP_LAST		/* always the last entry */
};

/* soft partition offsets and lengths are specified in sectors */
typedef u_longlong_t	sp_ext_offset_t;
typedef u_longlong_t	sp_ext_length_t;
struct mp_ext {
	sp_ext_offset_t un_voff;	/* virtual offset */
	sp_ext_offset_t un_poff;	/* physical offset */
	sp_ext_length_t un_len;		/* length of extent */
};
typedef struct mp_ext mp_ext_t;

/*
 * mp_unit32_od is for old 32 bit format only
 */
struct mp_unit32_od {
	mdc_unit32_od_t	c;		/* common unit structure */
	mdkey_t		un_key;		/* namespace key */
	dev32_t		un_dev;		/* device number */
	sp_ext_offset_t un_start_blk;	/* start block, incl reserved space */
	sp_status_t	un_status;	/* sp status */
	uint_t		un_numexts;	/* number of extents */
	sp_ext_length_t un_length;	/* total length (in sectors) */
	/* extent array.  NOTE: sized dynamically! */
	mp_ext_t un_ext[1];
};
typedef struct mp_unit32_od mp_unit32_od_t;

/*
 * softpart unit structure
 */
struct mp_unit {
	mdc_unit_t	c;		/* common unit structure */
	mdkey_t		un_key;		/* namespace key */
	md_dev64_t	un_dev;		/* device number, 64 bit */
	sp_ext_offset_t	un_start_blk;	/* start block, incl reserved space */
	sp_status_t	un_status;	/* sp status */
	uint_t		un_numexts;	/* number of extents */
	sp_ext_length_t	un_length;	/* total length (in sectors) */
	/* extent array.  NOTE: sized dynamically! */
	mp_ext_t un_ext[1];
};
typedef struct mp_unit mp_unit_t;

/*
 * ioctl structures used when passing ioctls via rpc.mdcommd
 */
struct md_driver {
	char	md_drivername[MD_MAXDRVNM];
	set_t	md_setno;
};
typedef struct md_driver md_driver_t;

%#define	MD_DRIVER md_driver_t md_driver;
#define	MD_DRIVER md_driver_t md_driver;

struct md_set_params {
	MD_DRIVER
	md_error_t	mde;
	minor_t		mnum;
	md_types_t	type;
	uint_t		size;
	int		options;
	uint64_t	mdp;	/* Contains pointer */
};
typedef struct md_set_params md_set_params_t;
%#if _LONG_LONG_ALIGNMENT == 8 && _LONG_LONG_ALIGNMENT_32 == 4
%#pragma pack()
%#endif


