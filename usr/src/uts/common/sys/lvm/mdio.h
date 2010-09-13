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

#ifndef	_SYS__MDIO_H
#define	_SYS__MDIO_H

#include <sys/debug.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/int_types.h>
#include <sys/dditypes.h>
#ifdef _KERNEL
#include <sys/lvm/md_mdiox.h>
#else /* !_KERNEL */
#include <mdiox.h>
#endif
#include <sys/ddipropdefs.h>
#include <sys/hwconf.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * driver version number
 */
#define	MD_DVERSION	0x00040003	/* major.minor */
#define	MD_SET_SHIFT	(NBITSMINOR32 - MD_BITSSET)
#define	MD_MAXUNITS	(1 << MD_SET_SHIFT)
#define	MD_UNIT_MASK	(MD_MAXUNITS - 1)

#define	MD_MIN2UNIT(m)	((m) & MD_UNIT_MASK)
#define	MD_MIN2SET(m)	((m) >> MD_SET_SHIFT)
#define	MD_SID(u)	((u)->c.un_self_id)
#define	MD_RECID(u)	((u)->c.un_record_id)
#define	MD_STATUS(u)	((u)->c.un_status)
#define	MD_PARENT(u)	((u)->c.un_parent)
#define	MD_CAPAB(u)	((u)->c.un_capabilities)
#define	MD_UN2SET(u)	MD_MIN2SET(MD_SID(u))
#define	MD_UL2SET(l)	MD_MIN2SET(MAXMIN32 & ((l)->un_dev))

#define	MD_MKMIN(s, u)	((((s) & MD_SETMASK) << MD_SET_SHIFT) | \
			((u) & MD_UNIT_MASK))

#define	HSP_BITSID	31
#define	HSP_SET_SHIFT	(HSP_BITSID - MD_BITSSET)
#define	HSP_SET_MASK	(MD_SETMASK << HSP_SET_SHIFT)
#define	HSP_SET(hspid)	(((hspid) & HSP_SET_MASK) >> HSP_SET_SHIFT)
#define	HSP_ID(hspid)	((hspid) & ~HSP_SET_MASK)
#define	MAKE_HSP_ID(setno, id)  (((setno) << HSP_SET_SHIFT) | (id))

/*
 * The following macros were added to support friendly names for hot spare
 * pools.  Before the addition of friendly names the hsp_self_id was merely
 * the conbination of the set number and the hot spare pool number.  With
 * friendly names a NM record is created to hold the hot spare pool name.
 * The hsp_self_id now becomes the set number shifted left plus the NM
 * record key plus 1000.  The number 1000 is used to collision between
 * traditional hsp_self_ids and friendly name self ids.  In traditional hot
 * spare pool the hot spare pool number could never be grater than 999.
 *
 * HSP_ID_IS_FN(hspid)	returns TRUE if the hot spare pool ID is the ID of
 * 			a friendly named hsp.  Will return FALSE otherwise.
 * 			hspid may contain the set bits, since HSP_ID_IS_FN
 * 			will call HSP_ID as part of doing its work.
 *
 * KEY_TO_HSP_ID(setno, reckey)	constructs a hot spare pool ID (hsp_t) from
 * 			a set number and a NM record key.  The result is
 * 			suitable for storing in the hsp_self_id member of a
 * 			hot_spare_pool struct.
 *
 * HSP_ID_TO_KEY(hspid)	returns the NM key that is encoded in the hot spare
 * 			pool ID.  MD_KEYBAD will be returned if hspid does
 * 			not represent a friendly named hsp.  hspid may
 * 			contain the set bits, since HSP_ID_TO_KEY will call
 * 			HSP_ID as part of doing its work.
 *
 * HSP_KEY_OK(reckey)	Insures that the NM record key is not so large as
 * 			to interfere with the set number bits in a hot
 * 			spare pool self id.  This macro will probably only
 * 			be used in meta_hs_add.
 */
#define	HSP_FN_BASE	(1000)
#define	HSP_ID_IS_FN(hspid) (HSP_ID(hspid) > HSP_FN_BASE)
#define	KEY_TO_HSP_ID(setno, key) ((setno << HSP_SET_SHIFT) | \
					(key + HSP_FN_BASE))
#define	HSP_ID_TO_KEY(hspid) ((HSP_ID_IS_FN(hspid)) ? \
				(HSP_ID(hspid) - HSP_FN_BASE) : MD_KEYBAD)
#define	HSP_KEY_OK(key)	(((key + HSP_FN_BASE) & HSP_SET_MASK) == 0)

/*
 * for did stat ioctl
 */
#define	MD_FIND_INVDID	0x01
#define	MD_GET_INVDID	0x02

/*
 * for setting the un_revision, hsp_revision and hs_revision
 */
#define	MD_64BIT_META_DEV	0x01
#define	MD_FN_META_DEV		0x02	/* Friendly named metadevice */

/*
 * for trans EOF error messages
 */
#define	MD_EOF_TRANS_MSG	"Trans logging has been replaced by UFS" \
	" Logging.\nSee mount_ufs(1M). Operation failed.\n"

#define	MD_SHORT_EOF_TRANS_MSG	"#Trans logging has been replaced by UFS" \
	" Logging.\n#See mount_ufs(1M). Operation failed.\n"

#define	MD_EOF_TRANS_WARNING	"Existing Trans devices are not logging; they" \
	"\npass data directly to the underlying device.\n"

#define	MD_SHORT_EOF_TRANS_WARNING	"#Existing Trans devices are not " \
	"logging; they\n#pass data directly to the underlying device.\n"

/*
 * for importing of disksets (IMP_LOAD)
 */
#define	MD_IMP_STALE_SET	1

/*
 * miscname stuff
 */

#define	MD_DRIVERNAMELEN	16
#define	MD_SETDRIVERNAME(to, from, setno) \
	if ((from) != NULL) \
		(void) strcpy((to)->md_driver.md_drivername, (from)); \
	(to)->md_driver.md_setno = (setno);


#define	MD_GETDRIVERNAME(to, from) \
	(void) strcpy((to), (from)->md_driver.md_drivername);

#define	MD_PNTDRIVERNAME(from) \
	((from)->md_driver.md_drivername)

/*
 * ioctl parameter structures
 */

#if _LONG_LONG_ALIGNMENT == 8 && _LONG_LONG_ALIGNMENT_32 == 4
#pragma pack(4)
#endif
typedef struct md_i_driverinfo {
	MD_DRIVER
	md_error_t	mde;
	minor_t		mnum;
} md_i_driverinfo_t;

typedef struct md_i_getnext {
	MD_DRIVER
	md_error_t	mde;
	minor_or_hsp_t	id;
} md_i_getnext_t;

typedef struct md_i_getnum {
	MD_DRIVER
	md_error_t	mde;
	int		start;
	int		size;
	uint64_t	minors;	/* Pointer to minor #'s */
} md_i_getnum_t;

typedef struct md_i_get {
	MD_DRIVER
	md_error_t	mde;
	minor_or_hsp_t	id;
	int		size;
	uint64_t	mdp;	/* Contains pointer */
} md_i_get_t;

typedef struct md_i_reset {
	MD_DRIVER
	md_error_t	mde;
	minor_t		mnum;		/* Unit to clear */
	int		force;
} md_i_reset_t;

/* soft partition reset parameters */
typedef struct md_sp_reset {
	MD_DRIVER
	md_error_t	mde;		/* Error return */
	minor_t		mnum;		/* Unit to clear */
	int		force;		/* Force reset */
	md_parent_t	new_parent;	/* New parent for child component */
} md_sp_reset_t;

/* soft partition status change parameters */
typedef struct md_sp_statusset {
	MD_DRIVER
	md_error_t	mde;		/* Error return */
	int		num_units;	/* Number of units */
	int		new_status;	/* New status */
	int		size;		/* Array size */
	uint64_t	minors;		/* Pointer to array of minor numbers */
} md_sp_statusset_t;

typedef struct md_sp_update_wm {
	MD_DRIVER
	md_error_t	mde;		/* Error return */
	minor_t		mnum;		/* Unit to update */
	uint_t		count;		/* Number of watermarks */
	uint64_t	wmp;		/* Pointer to array of watermarks */
	uint64_t	osp;		/* Pointer to array of offsets */
} md_sp_update_wm_t;

typedef struct md_sp_read_wm {
	MD_DRIVER
	md_error_t	mde;		/* Error return */
	md_dev64_t	rdev;		/* Device from which to read */
	uint64_t	wmp;		/* Pointer to wm buffer */
	xsp_offset_t	offset;		/* Offset of wm */
} md_sp_read_wm_t;

typedef struct md_set_userflags {
	MD_DRIVER
	md_error_t	mde;
	minor_t		mnum;
	uint_t		userflags;
} md_set_userflags_t;

typedef struct md_stripe_params {
	MD_DRIVER
	md_error_t	mde;		/* Error return */
	minor_t		mnum;
	ms_params_t	params;
} md_stripe_params_t;

typedef struct md_raid_params {
	MD_DRIVER
	md_error_t	mde;		/* Error return */
	minor_t		mnum;
	mr_params_t	params;
} md_raid_params_t;

typedef struct md_mirror_params {
	MD_DRIVER
	md_error_t	mde;		/* Error return */
	minor_t		mnum;
	mm_params_t	params;
} md_mirror_params_t;

typedef struct md_grow_params {
	MD_DRIVER
	md_error_t	mde;	/* Error return */
	minor_t		mnum;	/* Unit to grow */
	int		options; /* create a 64 or 32 bit device */
	uint64_t	mdp;	/* Optional - pointer to new unit struct */
	int		size;	/* Optional - size of new unit struct */
	int		nrows;	/* Optional - original number of rows */
	int		npar;	/* Optional - number of parents to lock */
	uint64_t	par;	/* Optional - pointer to parent units */
} md_grow_params_t;

/* if the didstat struct changes you will need to change the following macro */
typedef struct md_i_didstat {
	md_error_t	mde;	/* Error return */
	set_t		setno;	/* which set to use */
	side_t		side;	/* which side to use */
	int		mode;	/* find or get ? */
	int		cnt;	/* return number of invalid devid's found */
	int		maxsz;	/* return max size of invalid device id */
	uint64_t	ctdp;	/* pointer to structure to fill with ctds */
} md_i_didstat_t;

typedef struct mdnm_params {
	md_error_t	mde;		/* Error return */
	char		drvnm[MD_MAXDRVNM];  /* drvnm for get/set/rem nm */
	major_t		major;		/* major #, (alternative) for get nm */
	minor_t		mnum;		/* minor #, for get/set/rem nm */
	uint_t		devname_len;	/* Length of device name, for set nm */
	uint64_t	devname;	/* Address of device name for set/get */
	set_t		setno;		/* Which namespace set to use */
	side_t		side;		/* -1 == current side, >0 specified */
	mdkey_t		key;		/* 0 == alloc one, else use this key */
	mdkey_t		retkey;		/* return key here! */
	ushort_t	devid_size;	/* 0 == ret size, else use this one */
	uint64_t	devid;		/* pointer to devid, supplied by user */
	uint_t		pathname_len;	/* length of pathname */
	uint64_t	pathname;	/* address of pathname for update */
	md_dev64_t	devt;		/* devt for updating namespace */
	ushort_t	minorname_len;	/* length of minor name */
	uint64_t	minorname;	/* address of minor name */
	uint_t		ref_count;	/* returned n_count */
	int		imp_flag;	/* used by metaimport */
} mdnm_params_t;

typedef struct mdhspnm_params {
	md_error_t	mde;		/* Error return */
	char		drvnm[MD_MAXDRVNM];  /* drvnm for get/set/rem nm */
	uint_t		hspname_len;	/* Length of device name, for set nm */
	uint64_t	hspname;	/* Address of device name for set/get */
	set_t		setno;		/* Which namespace set to use */
	side_t		side;		/* -1 == current side, >0 specified */
	hsp_t		hspid;		/* 0 == alloc one, else use this key */
	hsp_t		ret_hspid;	/* return key here! */
	uint_t		ref_count;	/* returned n_count */
} mdhspnm_params_t;

typedef struct md_getdevs_params {
	MD_DRIVER
	md_error_t	mde;
	minor_t		mnum;
	int		cnt;
	uint64_t	devs;	/* Pointer to devs */
} md_getdevs_params_t;


typedef struct md_i_get_tstate {
	minor_or_hsp_t	id;
	uint_t		tstate;		/* Transient state */
	md_error_t	mde;
} md_i_get_tstate_t;

typedef struct md_set_state_params {
	MD_DRIVER
	md_error_t	mde;
	minor_t		mnum;
	uint_t		sm;
	uint_t		comp;
	uint_t		state;
	mddb_recid_t	hs_id;
} md_set_state_params_t;

typedef struct md_alloc_hotsp_params {
	MD_DRIVER
	md_error_t	mde;
	minor_t		mnum;
	uint_t		sm;
	uint_t		comp;
	mddb_recid_t	hs_id;
} md_alloc_hotsp_params_t;

typedef struct md_suspend_wr_params {
	MD_DRIVER
	md_error_t	mde;
	minor_t		mnum;
} md_suspend_wr_params_t;

typedef struct md_mn_req_owner {
	minor_t		mnum;		/* Mirror metadevice */
	uint_t		flags;		/* Flags (see below) */
	md_mn_nodeid_t	owner;		/* New owner of Mirror  */
} md_mn_req_owner_t;

#define	MD_MN_MM_PREVENT_CHANGE	0x0001	/* Disallow further ownership change */
#define	MD_MN_MM_ALLOW_CHANGE	0x0002	/* Allow ownership change */
#define	MD_MN_MM_SPAWN_THREAD	0x0004
#define	MD_MN_MM_CHOOSE_OWNER	0x0008	/* Choose a resync owner */

#define	MD_MN_MM_RESULT		0x80000000	/* Result contained in LSB */
#define	MD_MN_MM_RESULT_MASK	0xFFFF		/* Mask for result code	   */
#define	MD_MN_MM_RES_OK		0		/* Success */
#define	MD_MN_MM_RES_FAIL	1		/* Failure */

typedef struct md_set_mmown_params {
	MD_DRIVER
	md_error_t		mde;
	md_mn_req_owner_t	d;	/* New owner */
} md_set_mmown_params_t;

typedef struct md_mn_own_status {
	MD_DRIVER
	md_error_t		mde;
	minor_t			mnum;
	uint_t			flags;	/* See above *_MM_RESULT flags */
} md_mn_own_status_t;

typedef struct md_mn_poke_hotspares {
	MD_DRIVER
	md_error_t		mde;
} md_mn_poke_hotspares_t;

typedef struct md_mn_rs_params {
	MD_DRIVER
	md_error_t	mde;
	int		msg_type;	/* Type of message */
	minor_t		mnum;		/* Mirror metadevice */
	uint_t		rs_type;	/* Type of resync */
	diskaddr_t	rs_start;	/* 1st block of resync range */
	diskaddr_t	rs_size;	/* size of resync range */
	diskaddr_t	rs_done;	/* amount of resync done so far */
	diskaddr_t	rs_2_do;	/* amount still to be done */
	md_mn_nodeid_t	rs_originator;	/* Originator of resync message */
	char		rs_flags;	/* flags */
	char		rs_first_time;	/* set if first resync-next message */
	sm_state_t	rs_sm_state[NMIRROR];	/* Submirror state */
	sm_flags_t	rs_sm_flags[NMIRROR];	/* Submirror flags */
} md_mn_rs_params_t;

/* flag values for rs_flags */
#define	MD_MN_RS_ERR			0x01 /* Resync err */
#define	MD_MN_RS_CLEAR_OPT_NOT_DONE	0x02 /* Optimized resync done */
#define	MD_MN_RS_FIRST_RESYNC_NEXT	0x04 /* First RESYNC_NEXT message */

typedef struct md_mn_setcap_params {
	MD_DRIVER
	md_error_t	mde;
	minor_t		mnum;
	uint_t		sc_set;		/* Capability settings */
} md_mn_setcap_params_t;

typedef struct md_mkdev_params {
	MD_DRIVER
	md_error_t	mde;		/* Error return */
	unit_t		un;
} md_mkdev_params_t;

#define	MDMN_RR_CLEAN_PARAMS_DATA(x)	((unsigned char *)(x) + \
	    sizeof (md_mn_rr_clean_params_t))
#define	MDMN_RR_CLEAN_PARAMS_SIZE(x)	(sizeof (md_mn_rr_clean_params_t) + \
	    MDMN_RR_CLEAN_PARAMS_DATA_BYTES(x))
#define	MDMN_RR_CLEAN_PARAMS_START_BIT(x)	((x)->rr_start_size >> 16)
#define	MDMN_RR_CLEAN_PARAMS_DATA_BYTES(x)	((x)->rr_start_size & 0xffff)

typedef struct md_mn_rr_clean_params {
	MD_DRIVER
	md_error_t	mde;
	md_mn_nodeid_t	rr_nodeid;
	minor_t		rr_mnum;
	unsigned int	rr_start_size;	/* start_bit (16b) | data_bytes (16b) */
	/* actual data goes here */
} md_mn_rr_clean_params_t;

typedef struct md_mn_rr_dirty_params {
	MD_DRIVER
	md_error_t	mde;
	minor_t		rr_mnum;
	md_mn_nodeid_t	rr_nodeid;
	ushort_t	rr_start;	/* First RR region to mark */
	ushort_t	rr_end;		/* Last RR region to mark */
} md_mn_rr_dirty_params_t;

/*
 * Flags to coordinate sending device id between kernel and user space.
 * To get devid from kernel:
 *   User calls ioctl with l_devid_flags set to GETSZ flag to get size of
 *   devid which is returned in the l_devid_sz field if the SZ flag is set.
 *   Then user allocs that size and sends same ioctl with SPACE flag set
 *   and l_devid_sz set to alloc'd size.  Kernel either sets the NOSPACE
 *   flag (if alloc'd space is not big enough) or sets the VALID flag and
 *   fills in the devid.
 *
 * To send devid to kernel:
 *   User alloc's space for devid, fills in devid, sets (SPACE|VALID|SZ) flags
 *   and sets size of devid into l_devid_sz field.
 *
 * If MDDB_DEVID_SPACE is set, MDDB_DEVID_GETSZ is ignored.
 * If no flags are set, devid information is ignored.
 */
#define	MDDB_DEVID_SPACE	0x0001	/* l_devid_sz bytes of space alloc'd */
#define	MDDB_DEVID_VALID	0x0002	/* kernel has filled in devid */
#define	MDDB_DEVID_NOSPACE	0x0004	/* not enough alloc'd space for devid */
#define	MDDB_DEVID_GETSZ	0x0008	/* fill in l_devid_sz with devid size */
#define	MDDB_DEVID_SZ		0x0010	/* l_devid_sz filled in with devid sz */



/*
 * Maximum number of replicas (or number of locator blocks) in set.
 */
#define	MDDB_NLB		50

/*
 * maximum size of allowable bootlist property string - only used to
 * read in and write out boolist property strings to conf files.
 */
#define	MDDB_BOOTLIST_MAX_LEN	MAX_HWC_LINESIZE

/*
 * Percentage of free space left in replica during conversion of non-devid
 * style replica to devid style replica.
 */
#define	MDDB_DEVID_CONV_PERC	5

typedef struct mddb_cfg_loc {
	dev32_t		l_dev;
	daddr32_t	l_blkno;
	int		l_flags;
	char		l_driver[MD_MAXDRVNM];
	minor_t		l_mnum;
	int		l_devid_flags;
	uint64_t	l_devid;	/* pointer to devid */
	int		l_devid_sz;
	uint64_t	l_old_devid;
	int		l_old_devid_sz;
	char		l_minor_name[MDDB_MINOR_NAME_MAX];
	char		l_devname[MAXPATHLEN];	/* device name */
} mddb_cfg_loc_t;

typedef struct mddb_dtag {
	md_timeval32_t	dt_tv;
	int		dt_id;
	set_t		dt_setno;
	char		dt_sn[MDDB_SN_LEN];
	char		dt_hn[MD_MAX_NODENAME_PLUS_1];
} mddb_dtag_t;

typedef struct mddb_dtag_lst {
	struct mddb_dtag_lst	*dtl_nx;
	mddb_dtag_t		dtl_dt;
} mddb_dtag_lst_t;

typedef struct mddb_dtag_get_parm {
	set_t		dtgp_setno;
	mddb_dtag_t	dtgp_dt;
	md_error_t	dtgp_mde;
} mddb_dtag_get_parm_t;

typedef struct mddb_dtag_use_parm {
	int		dtup_id;
	set_t		dtup_setno;
	md_error_t	dtup_mde;
} mddb_dtag_use_parm_t;

typedef struct mddb_accept_parm {
	set_t		accp_setno;
	md_error_t	accp_mde;
} mddb_accept_parm_t;

typedef struct mddb_med_parm {
	set_t		med_setno;
	md_hi_arr_t	med;
	md_error_t	med_mde;		/* error return */
} mddb_med_parm_t;

typedef struct mddb_med_upd_parm {
	set_t		med_setno;
	md_error_t	med_mde;		/* error return */
} mddb_med_upd_parm_t;

#define	MED_TE_NM_LEN	64

typedef struct mddb_med_t_ent {
	char		med_te_nm[MED_TE_NM_LEN];
	md_dev64_t	med_te_dev;		/* fixed size dev_t */
} mddb_med_t_ent_t;

typedef struct mddb_med_t_parm {
	md_error_t		med_tp_mde;		/* error return */
	int			med_tp_nents;		/* number of entries */
	int			med_tp_setup;		/* setup flag */
	mddb_med_t_ent_t	med_tp_ents[1];		/* Var. sized array */
} mddb_med_t_parm_t;

#define	MDDB_SETMASTER_MAGIC	0x53544d41	/* Ascii for STMA */
typedef struct mddb_setmaster_config {
	md_error_t	c_mde;
	set_t		c_setno;
	int		c_magic;		/* used to verify ioctl */
	int		c_current_host_master;
} mddb_setmaster_config_t;

/*
 * Structure used to set/reset/get flags in set structure.
 */
#define	MDDB_SETFLAGS_MAGIC	0x5354464c	/* ascii for STFL */
typedef struct mddb_setflags_config {
	md_error_t	sf_mde;
	set_t		sf_setno;
	int		sf_magic;	/* used to verify ioctl */
	int		sf_flags;	/* Control flags set/reset/get */
	int		sf_setflags;	/* Flag values */
} mddb_setflags_config_t;

typedef struct mddb_set_node_params {
	md_error_t	sn_mde;
	set_t		sn_setno;
	md_mn_nodeid_t	sn_nodeid;
} mddb_set_node_params_t;

typedef struct mddb_block_parm {
	md_error_t	c_mde;
	set_t		c_setno;
	int		c_blk_flags;
} mddb_block_parm_t;

typedef struct mddb_parse_parm {
	md_error_t	c_mde;
	set_t		c_setno;
	int		c_parse_flags;
	int		c_lb_flags[MDDB_NLB];
} mddb_parse_parm_t;

typedef struct mddb_optrec_parm {
	md_error_t		c_mde;
	set_t			c_setno;
	md_replica_recerr_t	c_recerr[2];
} mddb_optrec_parm_t;

typedef struct mddb_config {
	md_error_t	c_mde;			/* error return */
	int		c_id;			/* used with getnext locator */
	md_splitname	c_devname;		/* contains name or keys */
	int		c_dbcnt;		/* number of dbs */
	int		c_dbmax;		/* maximum number of dbs */
	int		c_flags;
	int		c_dbend;		/* size of database */
	set_t		c_setno;		/* set number of replica */
	int		c_multi_node;		/* set if multi_node set */
	side_t		c_sideno;		/* side number of replica */
	md_timeval32_t	c_timestamp;		/* creation of set */
						/* setname */
	char		c_setname[MD_MAX_SETNAME_PLUS_1];
	md_hi_arr_t	c_med;			/* Mediator host information */
	int		c_spare[14];		/* unused must be zero */
	md_dev64_t	c_devt;			/* devt to get/set */
	mddb_cfg_loc_t	c_locator;		/* device specific info */
} mddb_config_t;

#define	c_subcmd	c_spare[0]
/*
 * Subcommands.
 */
#define	MDDB_CONFIG_ABS	1		/* treat c_id as abs index */

typedef	struct mddb_optloc {
	int	recid;	/* really mddb_recid_t */
	int	li[2];
} mddb_optloc_t;

typedef struct md_gs_stat_parm {
	set_t		gs_setno;
	uint_t		gs_status;
	md_error_t	gs_mde;
} md_gs_stat_parm_t;

typedef struct {
	int	setno;
	int	owns_set;
} mddb_ownset_t;

typedef enum md_rename_operation_t {
	MDRNOP_UNK = 0, MDRNOP_RENAME, MDRNOP_EXCHANGE
} md_renop_t;

typedef struct md_rename {
	md_error_t	mde;
	md_renop_t	op;
	int		revision;
	uint_t		flags;
	struct {
		minor_t	mnum;
		key_t	key;
	} from, to;
} md_rename_t;

typedef struct md_regen_param {
	MD_DRIVER
	md_error_t	mde;
	minor_t		mnum;   /* Unit to regenerate parity for */
} md_regen_param_t;

/* Base ioctl's defined here */
#define	MDIOC		('V' << 8)
#define	ISMDIOC(c)	(((c) >> 8) == 'V')

#define	MD_IOCSET	(MDIOC|0)	/* set config    (metainit) */
#define	MD_IOCRESET	(MDIOC|1)	/* reset config  (metaclear) */
#define	MD_IOCGET	(MDIOC|2)	/* get config    (metastat) */
#define	MD_IOCGROW	(MDIOC|3)	/* grow config   (dyn concat) */
#define	MD_IOCCHANGE	(MDIOC|4)	/* change config (metaparam) */
#define	MD_IOCSET_NM	(MDIOC|5)	/* set device name */
#define	MD_IOCGET_NM	(MDIOC|6)	/* get device name */
#define	MD_IOCREM_NM	(MDIOC|7)	/* remove device name */
#define	MD_IOCGET_DRVNM	(MDIOC|8)	/* get driver name */
#define	MD_IOCGET_NEXT	(MDIOC|9)	/* get next unit id */
#define	MD_IOCGET_DEVS	(MDIOC|10)	/* get device list */
#define	MD_DB_NEWDEV	(MDIOC|11)	/* add a db replica */
#define	MD_DB_USEDEV	(MDIOC|12)	/* patch in a db location */
#define	MD_DB_GETDEV	(MDIOC|13)	/* get a db replica */
#define	MD_DB_DELDEV	(MDIOC|14)	/* remove a db replica */
#define	MD_DB_ENDDEV	(MDIOC|15)	/* get db replica and size */
#define	MD_DB_GETDRVNM	(MDIOC|16)	/* get db replica driver name */
#define	MD_HALT		(MDIOC|17)	/* halt driver   (metahalt) */
#define	MD_GRAB_SET	(MDIOC|18)
#define	MD_RELEASE_SET	(MDIOC|20)	/* release a set */
#define	MD_IOCSETSYNC	(MDIOC|21)
#define	MD_IOCGETSYNC	(MDIOC|22)
#define	MD_IOCOFFLINE	(MDIOC|23)
#define	MD_IOCONLINE	(MDIOC|24)
#define	MD_IOCATTACH	(MDIOC|25)
#define	MD_IOCDETACH	(MDIOC|26)
#define	MD_IOCREPLACE	(MDIOC|27)
#define	MD_DB_USERREQ	(MDIOC|28)
#define	MD_DB_GETOPTLOC	(MDIOC|29)	/* get locators for opt resync rec. */
#define	MD_DB_OWNSET	(MDIOC|30)	/* Does caller own the set */
#define	MD_IOCGETNSET	(MDIOC|31)	/* Get the config'd number sets */
#define	MD_IOCNXTKEY_NM	(MDIOC|32)	/* get next key from namespace */
#define	MD_DB_NEWSIDE	(MDIOC|33)	/* add another side to the db replica */
#define	MD_DB_DELSIDE	(MDIOC|34)	/* delete a side from the db replica */
#define	MD_IOCGVERSION	(MDIOC|35)	/* get the driver version */
#define	MD_IOCSET_FLAGS	(MDIOC|36)	/* set the userflags of a metadevice */
#define	MD_IOCGETNUNITS	(MDIOC|37)	/* Get the config'd number units */
#define	MD_IOCNOTIFY	(MDIOC|38)	/* notification */
#define	MD_IOCRENAME	(MDIOC|39)	/* (Ex)Change/Rename unit identities */
#define	MD_IOCISOPEN	(MDIOC|40)	/* Is metadevice open? */
#define	MD_IOCSETREGEN	(MDIOC|41)	/* regen ioctl for raid */
#define	MD_MED_GET_LST	(MDIOC|42)	/* Get the mediator list */
#define	MD_MED_SET_LST	(MDIOC|43)	/* Set the mediator list */
#define	MD_MED_UPD_MED	(MDIOC|44)	/* Have the kernel push mediator data */
#define	MD_MED_GET_NMED	(MDIOC|45)	/* Get the max number of mediators */
#define	MD_MED_GET_TLEN	(MDIOC|46)	/* Get the mediator transport tbl len */
#define	MD_MED_GET_T	(MDIOC|47)	/* Get the mediator transport tbl */
#define	MD_MED_SET_T	(MDIOC|48)	/* Set the mediator transport tbl */
#define	MD_MED_GET_TAG	(MDIOC|49)	/* Get the list of data tags */
#define	MD_MED_USE_TAG	(MDIOC|50)	/* Use one of the data tags */
#define	MD_MED_ACCEPT	(MDIOC|51)	/* Accept 1/2 n 1/2 */
#define	MD_GET_SETSTAT	(MDIOC|52)	/* Get the s_status for a set */
#define	MD_SET_SETSTAT	(MDIOC|53)	/* Set the s_status for a set */
#define	MD_IOCPROBE_DEV (MDIOC|54)	/* Force pseudo opens for metadevices */
#define	MD_IOCGET_DID	(MDIOC|55)	/* Get device id */
#define	MD_IOCUPD_NM	(MDIOC|56)	/* Update namespace */
#define	MD_DB_SETDID	(MDIOC|57)	/* Set device id for a locator block */
#define	MD_IOCUPD_LOCNM	(MDIOC|58)	/* update locator namespace */
#define	MD_SETNMDID	(MDIOC|59)	/* update namespace devid */
#define	MD_IOCDID_STAT	(MDIOC|60)	/* get invalid device id's */
#define	MD_UPGRADE_STAT	(MDIOC|61)	/* get upgrade status information */
#define	MD_IOCGET_NUM	(MDIOC|62)	/* get number of devs and devs */
#define	MD_IOCGET_TSTATE (MDIOC|63)	/* get ui_tstate for metastat */
#define	MD_SETMASTER	(MDIOC|64)
#define	MD_MN_SET_DOORH		(MDIOC|65) /* MN: set the doorhandle */
#define	MD_MN_OPEN_TEST		(MDIOC|66) /* MN: check / (un)lock a md */
#define	MD_MN_SET_MM_OWNER	(MDIOC|67) /* Set mirror owner */
#define	MD_MN_SET_NODEID	(MDIOC|68) /* Set this node's id */
#define	MD_MN_SET_STATE		(MDIOC|69) /* Set mirror state */
#define	MD_MN_SUSPEND_WRITES	(MDIOC|70) /* Blocks writes */
#define	MD_MN_GET_MM_OWNER	(MDIOC|71) /* Get mirror owner */
#define	MD_IOCGUNIQMSGID	(MDIOC|72) /* create a unique message ID */
#define	MD_MN_MM_OWNER_STATUS 	(MDIOC|73) /* Return status of SET_MM_OWNER */
#define	MD_MN_ALLOCATE_HOTSPARE (MDIOC|74) /* Allocate hotspare */
#define	MD_MN_SUBMIRROR_STATE 	(MDIOC|75) /* Submirror state change */
#define	MD_MN_RESYNC		(MDIOC|76) /* Resync ioctl */
#define	MD_MN_SUSPEND_SET	(MDIOC|77) /* suspend IO's for a MN diskset */
#define	MD_MN_RESUME_SET	(MDIOC|78) /* resume IO's for a MN diskset */
#define	MD_MN_MDDB_PARSE	(MDIOC|79) /* Re-parse portion of MNset mddb */
#define	MD_MN_MDDB_BLOCK	(MDIOC|80) /* Block parse or record changes */
#define	MD_MN_MDDB_OPTRECFIX	(MDIOC|81) /* Fix optimized record failure */
#define	MD_MN_SET_CAP		(MDIOC|82) /* set capability, eg ABR, DMR */
#define	MD_MN_CHK_WRT_MDDB	(MDIOC|83) /* New master checks/writes mddb */
#define	MD_MN_SET_SETFLAGS	(MDIOC|84) /* Set/reset set flags */
#define	MD_MN_GET_SETFLAGS	(MDIOC|85) /* Gets set flags */
#define	MD_IOCGET_DIDMIN	(MDIOC|94) /* get the minor name for a devid */
#define	MD_IOCIMP_LOAD		(MDIOC|95) /* load the import replicas */
#define	MD_IOCSET_DID		(MDIOC|96) /* set the devid of a disk */
#define	MD_MN_GET_MIRROR_STATE	(MDIOC|97) /* Get the mirror state MN only */
#define	MD_MN_DB_USERREQ	(MDIOC|98) /* MN MT-version of USERREQ */
#define	MD_IOCMAKE_DEV		(MDIOC|99) /* create device node for unit */
#define	MD_MN_SET_COMMD_RUNNING	(MDIOC|100) /* Commd running or exiting */
#define	MD_MN_COMMD_ERR		(MDIOC|101) /* get a message out */
#define	MD_MN_SETSYNC		(MDIOC|102) /* multi-threaded MD_IOCSETSYNC */
#define	MD_MN_POKE_HOTSPARES	(MDIOC|103) /* poke hotspares */
#define	MD_DB_LBINITTIME	(MDIOC|104) /* get the lb_inittime */
#define	MD_IOCGET_HSP_NM	(MDIOC|105) /* get hsp entry from namespace */
#define	MD_IOCREM_DEV		(MDIOC|106) /* remove device node for unit */
#define	MD_IOCUPDATE_NM_RR_DID	(MDIOC|107) /* update remotely repl did in NM */
#define	MD_MN_RR_DIRTY		(MDIOC|108) /* Mark RR range as dirty */
#define	MD_MN_RR_CLEAN		(MDIOC|109) /* Clean RR bits from bitmap */

#define	MDIOC_MISC	(MDIOC|128)	/* misc module base */
/* Used in DEBUG_TEST code */
#define	MD_MN_CHECK_DOOR1 (MDIOC|126)	/* MN: test door to master */
#define	MD_MN_CHECK_DOOR2 (MDIOC|127)	/* MN: test door master-broadcast */

#define	NODBNEEDED(c)	((c) == MD_IOCNOTIFY)

typedef struct md_resync_ioctl {
	MD_DRIVER
	md_error_t	mde;
	minor_t		ri_mnum;	    /* mirror to sync */
	diskaddr_t	ri_copysize;	    /* The size of the copy buffer */
	int		ri_zerofill;	    /* Zerofill on lec read error */
	int		ri_percent_done;    /* percent done current phase */
	int		ri_percent_dirty;
	md_riflags_t	ri_flags;
} md_resync_ioctl_t;

typedef struct md_rrsize {
	MD_DRIVER
	md_error_t	mde;		/* error return */
	minor_t		mnum;		/* unit # to get */
	ulong_t		rr_num;		/* Number of resync regions */
	ulong_t		rr_blksize;	/* Blocksize of regions */
} md_rrsize_t;

typedef	enum replace_cmd {
	REPLACE_COMP, ENABLE_COMP, FORCE_REPLACE_COMP, FORCE_ENABLE_COMP
} replace_cmd_t;

typedef struct replace_params {
	MD_DRIVER
	md_error_t	mde;
	replace_cmd_t	cmd;		/* what to do */
	minor_t		mnum;		/* mirror to act upon */
	md_dev64_t	old_dev;	/* enable/replace use this */
	md_dev64_t	new_dev;	/* replace only uses this */
	mdkey_t		new_key;	/* replace only uses this */
	diskaddr_t	start_blk;	/* start block of new device */
	int		has_label;	/* has label flag of new device */
	diskaddr_t	number_blks;	/* # of blocks of new device */
	uint_t		options;	/* misc options, see MDIOCTL_* below */
} replace_params_t;

typedef struct md_i_off_on {
	MD_DRIVER
	md_error_t	mde;
	minor_t		mnum;
	md_dev64_t	submirror;
	int		force_offline;
} md_i_off_on_t;

typedef struct md_att_struct {
	MD_DRIVER
	md_error_t	mde;		/* Normal error */
	minor_t		mnum;
	mdkey_t		key;		/* namespace key of sm */
	md_dev64_t	submirror;	/* The device  to attach */
	uint_t		options;	/* passed in from the command */
} md_att_struct_t;

/* possible values for options above */
#define	MDIOCTL_DRYRUN		0x0001	/* Only check if operation possible */
#define	MDIOCTL_NO_RESYNC_RAID	0x0002	/* if cluster replace we don't */
					/*    want to resync */

typedef struct md_detach_params {
	MD_DRIVER
	md_error_t	mde;
	minor_t		mnum;		/* mirror to act upon */
	md_dev64_t	submirror;
	int		force_detach;
} md_detach_params_t;

/*
 * Structure for accessing the DB from user land.
 */
typedef struct mddb_userreq {
	md_error_t		ur_mde;
	mddb_usercmd_t		ur_cmd;
	set_t			ur_setno;
	mddb_type_t		ur_type;
	uint_t			ur_type2;
	mddb_recid_t		ur_recid;
	mddb_recstatus_t	ur_recstat;
	int			ur_size;
	uint64_t		ur_data;	/* Pointer to user data */
} mddb_userreq_t;

/*
 * Ioctl structure for MD_IOCISOPEN
 */
typedef struct md_isopen {
	md_error_t	mde;
	md_dev64_t	dev;
	int		isopen;
} md_isopen_t;

/*
 * Ioctl structure for MD_MN_OPEN_TEST
 * md_clu_open stands for md check/lock/unlock
 * Can't use MD_IOCISOPEN, because it's a contracted inteface.
 */
typedef struct md_clu_open {
	md_error_t	clu_mde;
	md_dev64_t	clu_dev;
	enum {	MD_MN_LCU_CHECK = 0,
		MD_MN_LCU_LOCK,
		MD_MN_LCU_UNLOCK } clu_cmd;
	int		clu_isopen;
} md_clu_open_t;

/*
 * Structure to push the message out from commd
 * MAXPATHLEN macro is being overloaded to represent
 * the line size of 1024 characters. i.e. no path
 * is being passed.
 */
typedef struct md_mn_commd_err {
	int size;
	uint64_t md_message; /* pointer to array of chars */
} md_mn_commd_err_t;

/*
 * Ioctl structure for MD_IOCPROBE_DEV
 */

#define	TESTNAME_LEN 32

#define	PROBE_SEMA(p)	p->probe_sema
#define	PROBE_MX(p)	p->probe_mx

/*
 * To categorize user/kernel structures md_probedev is split into two,
 * one used by user and the other by kernel, thereby hiding the semaphore
 * /mutex pointer members from user, which should be the appropriate one.
 */

typedef struct md_probedev {
	MD_DRIVER
	md_error_t	mde;		/* return error status */
	int		nmdevs;		/* number of metadevices */
	char		test_name[TESTNAME_LEN];
	uint64_t	mnum_list;	/* pointer to array of minor numbers */
} md_probedev_t;

typedef struct md_probedev_impl {
	ksema_t		*probe_sema;
	kmutex_t	*probe_mx;
	md_probedev_t	probe;
} md_probedev_impl_t;

/*
 * Ioctl structure for MD_MN_GET_MIRROR_STATE
 */
typedef struct md_mn_get_mir_state {
	MD_DRIVER
	minor_t		mnum;		/* Unit to obtain submirror info from */
} md_mn_get_mir_state_t;

#if _LONG_LONG_ALIGNMENT == 8 && _LONG_LONG_ALIGNMENT_32 == 4
#pragma pack()
#endif
/*
 * Per set flags, stored in md_set[n].s_status
 */
#define	MD_SET_HALTED		0x00000001  /* Set is shut down */
#define	MD_SET_SNARFED		0x00000002  /* incores built for set db recs */
#define	MD_SET_SNARFING		0x00000004  /* incores being built for set */
#define	MD_SET_STALE		0x00000008  /* set database not correct */
#define	MD_SET_NM_LOADED	0x00000010  /* set namespace is loaded */
#define	MD_SET_TAGDATA		0x00000020  /* tagged data detected */
#define	MD_SET_ACCOK		0x00000040  /* Accept data is possible */
#define	MD_SET_TOOFEW		0x00000080  /* not enough replicas */
#define	MD_SET_USETAG		0x00000100  /* A tag is selected, use it */
#define	MD_SET_ACCEPT		0x00000200  /* User chose accept 50/50 mode */
#define	MD_SET_OWNERSHIP	0x00000400  /* Set is owned */
#define	MD_SET_BADTAG		0x00000800  /* DT is not valid */
#define	MD_SET_CLRTAG		0x00001000  /* Clear the tags */
#define	MD_SET_KEEPTAG		0x00002000  /* Keep the tag */
#define	MD_SET_PUSHLB		0x00004000  /* Indicate a LB push is needed */
#define	MD_SET_MNSET		0x00008000  /* Set is a multinode diskset */
#define	MD_SET_DIDCLUP		0x00010000  /* Set has cleaned up devids */
#define	MD_SET_MNPARSE_BLK	0x00020000  /* Do not send parse msgs */
#define	MD_SET_MN_NEWMAS_RC	0x00040000  /* Is new master during reconfig */
#define	MD_SET_MN_START_RC	0x00080000  /* Start step executed for set */
#define	MD_SET_IMPORT		0x00100000  /* Indicate set is importing */
#define	MD_SET_MN_MIR_STATE_RC	0x00200000  /* Mirror state gotten for set */
#define	MD_SET_HOLD		0x00400000  /* Hold set during release */
#define	MD_SET_REPLICATED_IMPORT	0x00800000  /* Set importing RC disk */

#define	MD_MNSET_SETNO(setno)	(md_set[setno].s_status & MD_SET_MNSET)

/*
 * See meta_prbits() in SUNWmd/lib/libmeta/meta_print.c for a description of
 * the way this is used
 */
#define	MD_SET_STAT_BITS "\020\001HALTED\002SNARFED\003SNARFING\004STALE" \
			    "\005NM_LOADED\006TAGDATA\007ACCOK\010TOOFEW" \
			    "\011USETAG\012ACCEPT\013OWNERSHIP\014BADTAG" \
			    "\015CLRTAG\016KEEPTAG\017PUSHLB\020MNSET" \
			    "\021DIDCLUP\022MNPARSE_BLK\023MN_NEWMAS_RC" \
			    "\024MN_START_RC\025IMPORT\026MIR_STATE_RC" \
			    "\027HOLD\030REPLICATED_IMPORT"


#ifdef	__cplusplus
}
#endif

#endif	/* _SYS__MDIO_H */
