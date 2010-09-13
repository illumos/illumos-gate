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

#ifndef	_DSW_H
#define	_DSW_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Miscellaneous defines
 */

#define	DSW_BITS	8	/* # of bits in a byte */
#define	DSW_SIZE	64	/* fba's in a DSW chunk */


/*
 * Ioctl definitions
 */

#define	_D_(x)			(('D'<<16)|('W'<<8)|(x))

#define	DSWIOC_ENABLE		_D_(1)	/* Configure DSW pair */
#define	DSWIOC_RESUME		_D_(2)	/* Resume a DSW pair */
#define	DSWIOC_SUSPEND		_D_(3)	/* Suspend a DSW pair */
#define	DSWIOC_COPY		_D_(4)	/* Copy DSW volume over its pair */
#define	DSWIOC_BITMAP		_D_(5)	/* Get bitmap */
#define	DSWIOC_STAT		_D_(6)	/* Get state of shadow */
#define	DSWIOC_DISABLE		_D_(7)	/* Deconfigure DSW pair */
#define	DSWIOC_SHUTDOWN		_D_(8)	/* Suspend all DSW pairs */
#define	DSWIOC_ABORT		_D_(9)	/* Abort Copy of DSW pair */
#define	DSWIOC_VERSION		_D_(10)	/* DataShadow version */
#define	DSWIOC_RESET		_D_(11)	/* Reset DataShadow set */
#define	DSWIOC_OFFLINE		_D_(12)	/* Offline volumes */
#define	DSWIOC_WAIT		_D_(13)	/* Wait for copy to complete */
#define	DSWIOC_LIST		_D_(14)	/* List current kernel shadow groups */
#define	DSWIOC_ACOPY		_D_(15)	/* Copy DSW volumes over their pairs */
#define	DSWIOC_EXPORT		_D_(16)	/* Export the shadow volume */
#define	DSWIOC_IMPORT		_D_(17)	/* Import shadow volume */
#define	DSWIOC_JOIN		_D_(18)	/* Rejoin previously exported shadow */
#define	DSWIOC_COPYP		_D_(19)	/* Set and get copy parameters */
#define	DSWIOC_OCREAT		_D_(20)	/* Create overflow volume */
#define	DSWIOC_OATTACH		_D_(21)	/* Attach overflow volume */
#define	DSWIOC_ODETACH		_D_(22)	/* Detach overflow volume */
#define	DSWIOC_OLIST		_D_(23)	/* List overflow volumes */
#define	DSWIOC_OSTAT		_D_(24)	/* Stat overflow volume */
#define	DSWIOC_SBITSSET		_D_(25)	/* Get # of bits set in shadow bitmap */
#define	DSWIOC_CBITSSET		_D_(26)	/* Get # of bits set in copy bitmap */
#define	DSWIOC_LISTLEN		_D_(27)	/* length of DSWIOC_LIST data */
#define	DSWIOC_OLISTLEN		_D_(28)	/* length of DSWIOC_OLIST data */
#define	DSWIOC_SEGMENT		_D_(29) /* Get segemented bitmaps */
#define	DSWIOC_MOVEGRP		_D_(30)	/* Move set from one group to another */
#define	DSWIOC_CLIST		_D_(31) /* get list of resource groups */
#define	DSWIOC_GLIST		_D_(32)	/* get list of groups */
#define	DSWIOC_CHANGETAG	_D_(33)	/* change the cluster tag of a set */
#define	DSWIOC_OSTAT2		_D_(34) /* Stat overflow volume enhanced */

/*
 * Config and status flags
 */

#define	DSW_GOLDEN	0x0001		/* the set is independent */

#define	DSW_COPYINGP	0x0100		/* Copy in progress */
#define	DSW_COPYINGM	0x0200		/* Copying master to shadow */
#define	DSW_COPYINGS	0x0400		/* Copying shadow to master */
#define	DSW_COPYING	0x0600		/* Copying, may be in progress */
#define	DSW_COPY_FLAGS	0x0700		/* Copy flags */
#define	DSW_COPYINGX	0x0800		/* Copy exit requested */
#define	DSW_OFFLINE	0xf000		/* An underlying volume offline */
#define	DSW_BMPOFFLINE	0x1000		/* Bitmap volume offline */
#define	DSW_SHDOFFLINE	0x2000		/* Shadow volume offline */
#define	DSW_MSTOFFLINE	0x4000		/* Master volume offline */
#define	DSW_OVROFFLINE	0x8000		/* Overflow volume offline */
#define	DSW_TREEMAP	0x10000		/* Shadow volume accessed by an index */
#define	DSW_OVERFLOW	0x20000		/* Shadow volume has overflowed */
#define	DSW_SHDEXPORT	0x40000		/* Shadow volume has been exported */
#define	DSW_SHDIMPORT	0x80000		/* Shadow volume has been imported */
#define	DSW_VOVERFLOW	0x100000	/* Shadow volume using overflow vol */
#define	DSW_HANGING	0x200000	/* Hanging master structure  */
#define	DSW_CFGOFFLINE	0x400000	/* config db is offline */
#define	DSW_OVRHDRDRTY	0x800000	/* Overflow header dirty */
#define	DSW_RESIZED	0x1000000	/* mst_size != shd_size */
#define	DSW_FRECLAIM	0x2000000	/* force the reclaim of an ovr vol */

/*
 * used for SNMP trap only.
 * These flags help distinguish between enable and resume,
 * suspend and disable.
 * Note that DSW_HANGING is set for both suspend and disable
 */
#define	DSW_SNMP_CLR		0	/* no flag is set	*/
#define	DSW_SNMP_DISABLE	1	/* Set is disabled	*/
#define	DSW_SNMP_SUSPEND	2	/* Set is suspended	*/
#define	DSW_SNMP_ENABLE		3	/* Set is enabled	*/
#define	DSW_SNMP_RESUME		4	/* Set is resumed	*/
#define	DSW_SNMP_OVER_ATTACH	5	/* overflow attached	*/
#define	DSW_SNMP_OVER_DETACH	6	/* overflow detached	*/
#define	DSW_SNMP_UPDATE		7	/* update operation	*/
#define	DSW_SNMP_COPIED		8	/* copy operation	*/

	/* Overflow volume flags */
#define	IIO_OFFLINE	0x0001		/* Volume is offline */
#define	IIO_HDR_WRTN	0x0002		/* Header written */
#define	IIO_CNTR_INVLD	0x0004		/* Overflow counters invalid */
#define	IIO_VOL_UPDATE	0x0008		/* Performing group update */

#define	DSW_NAMELEN	64		/* NSC_MAXPATH - don't change without */
					/* amending header version number */

#define	DSWDEV		"/dev/ii"
#define	II_IMPORTED_SHADOW "<imported_shadow>"

/*
 * Configuration parameter defines
 * ii_bitmap, ii_throttle_unit, ii_throttle_delay
 */
#define	II_KMEM		0	/* Load/store on resume/suspend, in memory */
#define	II_WTHRU	1	/* Read/write bitmap thru to bitmap volume */
#define	II_FWC		2	/* Read/write bitmap to FWC, else WTHRU */

#define	MIN_THROTTLE_UNIT	100	/* Min. number of units to transfer */
#define	MAX_THROTTLE_UNIT	60000	/* Max. number of units to transfer */
#define	MIN_THROTTLE_DELAY	2	/* Min. delay between unit transfer */
#define	MAX_THROTTLE_DELAY	10000	/* Max. delay between unit transfer */

/*
 * DSW user config structure
 */

typedef struct dsw_config_s {
	spcs_s_info_t status;
	char master_vol[DSW_NAMELEN];
	char shadow_vol[DSW_NAMELEN];
	char bitmap_vol[DSW_NAMELEN];
	char cluster_tag[DSW_NAMELEN];
	char group_name[DSW_NAMELEN];
	int flag;
} dsw_config_t;

/*
 * DSW segmented bitmap I/O structure
 */
typedef struct dsw_segment_s {
	spcs_s_info_t status;
	char shadow_vol[DSW_NAMELEN];
	unsigned seg_number;		/* 32KB Segment number to start at */
	unsigned char   *shd_bitmap;		/* pointer to shadow bitmap */
	int	shd_size;			/* size of shadow bitmap */
	unsigned char   *cpy_bitmap;		/* pointer to copy bitmap */
	int	cpy_size;			/* size of copy bitmap */
	unsigned char	*idx_bitmap;		/* pointer to index table */
	int	idx_size;			/* size of index table */
} dsw_segment_t;

/*
 * DSW user bitmap structure
 */

typedef struct dsw_bitmap_s {
	spcs_s_info_t status;
	char shadow_vol[DSW_NAMELEN];
	unsigned char	*shd_bitmap;		/* pointer to shadow bitmap */
	uint64_t shd_size;			/* size of shadow bitmap */
	uint64_t copy_size;			/* size of copy bitmap */
	unsigned char	*copy_bitmap;		/* pointer to copy bitmap */
} dsw_bitmap_t;


/*
 * DSW general ioctl structure
 */

typedef struct dsw_ioctl_s {
	spcs_s_info_t status;
	char shadow_vol[DSW_NAMELEN];
	int flags;
	pid_t pid;
} dsw_ioctl_t;


/*
 * DSW general atomic ioctl structure operating on several Image sets
 */

typedef struct dsw_aioctl_s {
	spcs_s_info_t status;
	int flags;
	int count;
	pid_t pid;
	char shadow_vol[DSW_NAMELEN];	/* start of list of image sets */
} dsw_aioctl_t;


/*
 * DSW stat ioctl structure
 */

typedef struct dsw_stat_s {
	spcs_s_info_t status;
	char shadow_vol[DSW_NAMELEN];
	int stat;
	uint64_t size;
	char overflow_vol[DSW_NAMELEN];
	uint64_t shdsize;
	uint64_t shdused;
	char group_name[DSW_NAMELEN];
	char cluster_tag[DSW_NAMELEN];
	uint64_t mtime;
} dsw_stat_t;


/*
 * DSW version ioctl structure
 */

typedef struct dsw_version_s {
	spcs_s_info_t status;
	int major;			/* Major release number */
	int minor;			/* Minor release number */
	int micro;			/* Micro release number */
	int baseline;			/* Baseline revision number */
} dsw_version_t;

/*
 * DSW get bits set in bitmap structure
 */

typedef struct dsw_bitsset_s {
	spcs_s_info_t status;
	char	shadow_vol[DSW_NAMELEN];
	uint64_t tot_size;		/* total number of bits in map */
	uint64_t tot_set;		/* number of bitmap bits set */
} dsw_bitsset_t;


/*
 * DSW list ioctl structure
 */

typedef struct dsw_list_s {
	spcs_s_info_t status;
	int list_size;			/* number of elements in list */
	int list_used;			/* number of elements returned */
	dsw_config_t *list;
} dsw_list_t;

/*
 * DSW copy parameter structure
 */

typedef struct dsw_copyp_s {
	spcs_s_info_t status;
	char shadow_vol[DSW_NAMELEN];
	int copy_unit;
	int copy_delay;
} dsw_copyp_t;

/*
 * DSW ostat ioctl structure
 */

typedef struct dsw_ostat_s {
	spcs_s_info_t status;
	char overflow_vol[DSW_NAMELEN];
	int drefcnt;
	uint64_t used;
	uint64_t unused;
	uint64_t nchunks;
	int crefcnt;
	int flags;
	int hversion;
	int hmagic;
} dsw_ostat_t;

/*
 * DSW move group structure
 */

typedef struct dsw_movegrp_s {
	spcs_s_info_t status;
	char shadow_vol[DSW_NAMELEN];
	char new_group[DSW_NAMELEN];
} dsw_movegrp_t;

/*
 * II_PIT_PROPS structure
 */
typedef struct pit_props_s {
	int iirc;
	int mstid;
	int shdid;
	int bmpid;
	int ovrid;
	char group[DSW_NAMELEN];
	char cluster[DSW_NAMELEN];
	int  has_overflow;
	int  flags;
	uint64_t  size;
	int64_t  shdchks;
	int64_t  copybits;
	int64_t  shdbits;
} pit_props_t;

/*
 * II_PIT_UPDATE structure
 */
typedef struct pit_update_s {
	int iirc;
	char direction;
} pit_update_t;

#ifdef _KERNEL
/*
 * 32 bit versions of ioctl structures
 */

typedef struct dsw_config32_s {
	spcs_s_info32_t status;
	char master_vol[DSW_NAMELEN];
	char shadow_vol[DSW_NAMELEN];
	char bitmap_vol[DSW_NAMELEN];
	char cluster_tag[DSW_NAMELEN];
	char group_name[DSW_NAMELEN];
	int flag;
} dsw_config32_t;

/*
 * DSW segmented bitmap I/O structure
 */
typedef struct dsw_segment32_s {
	spcs_s_info32_t status;
	char shadow_vol[DSW_NAMELEN];
	uint32_t seg_number;
	uint32_t shd_bitmap;
	int	 shd_size;
	uint32_t cpy_bitmap;
	int	 cpy_size;
	uint32_t idx_bitmap;
	int	 idx_size;
} dsw_segment32_t;

/*
 * DSW user bitmap structure
 */

typedef struct dsw_bitmap32_s {
	spcs_s_info32_t status;
	char shadow_vol[DSW_NAMELEN];
	uint32_t shd_bitmap;		/* 32 bit pointer value */
	uint64_t shd_size;
	uint64_t copy_size;
	uint32_t copy_bitmap;		/* 32 bit pointer value */
} dsw_bitmap32_t;

typedef struct dsw_ioctl32_s {
	spcs_s_info32_t status;
	char shadow_vol[DSW_NAMELEN];
	int flags;
	pid_t pid;
} dsw_ioctl32_t;

typedef struct dsw_stat32_s {
	spcs_s_info32_t status;
	char shadow_vol[DSW_NAMELEN];
	int stat;
	uint64_t size;
	char overflow_vol[DSW_NAMELEN];
	uint64_t shdsize;
	uint64_t shdused;
	char group_name[DSW_NAMELEN];
	char cluster_tag[DSW_NAMELEN];
	uint64_t mtime;
} dsw_stat32_t;

typedef struct dsw_version32_s {
	spcs_s_info32_t status;
	int major;			/* Major release number */
	int minor;			/* Minor release number */
	int micro;			/* Micro release number */
	int baseline;			/* Baseline revision number */
} dsw_version32_t;

typedef struct dsw_bitsset32_s {
	spcs_s_info32_t status;
	char	shadow_vol[DSW_NAMELEN];
	uint64_t	tot_size;	/* total number of bits in map */
	uint64_t	tot_set;	/* number of bitmap bits set */
} dsw_bitsset32_t;

typedef struct dsw_list32_s {
	spcs_s_info32_t status;
	int list_size;
	int list_used;
	uint32_t list;
} dsw_list32_t;

typedef struct dsw_aioctl32_s {
	spcs_s_info32_t status;
	int flags;
	int count;
	pid_t pid;
	char shadow_vol[DSW_NAMELEN];	/* start of list of image sets */
} dsw_aioctl32_t;

typedef struct dsw_copyp32_s {
	spcs_s_info32_t status;
	char shadow_vol[DSW_NAMELEN];
	int copy_unit;
	int copy_delay;
} dsw_copyp32_t;

typedef struct dsw_ostat32_s {
	spcs_s_info32_t status;
	char overflow_vol[DSW_NAMELEN];
	int drefcnt;
	uint64_t used;
	uint64_t unused;
	uint64_t nchunks;
	int crefcnt;
	int flags;
	int hversion;
	int hmagic;
} dsw_ostat32_t;

/*
 * DSW move group structure
 */

typedef struct dsw_movegrp32_s {
	spcs_s_info32_t status;
	char shadow_vol[DSW_NAMELEN];
	char new_group[DSW_NAMELEN];
} dsw_movegrp32_t;

#endif	/* _KERNEL */

/* dsw_copy dsw_ioctl_t flag bits */
#define	CV_BMP_ONLY	0x00000001	/* copy only chunks flagged by bitmap */
#define	CV_SHD2MST	0x00000002	/* copy shadow to master */
#define	CV_LOCK_PID	0x00000004	/* On copy/update, lock PIT by PID */
#define	CV_CLR_BMP	0x00000010	/* clear bits in bit map during copy */
#define	CV_IS_CLUSTER	0x00000020	/* struct refers to cluster */
#define	CV_IS_GROUP	0x00000040	/* struct refers to group (cpy/upd) */
#define	CV_SIBLING	0x00010000	/* internal copy_on_write flag */

/* nsc_control commands */

#define	II_CONTROL(x)	('I' << 24 | 'I' << 16 | (x))	/* 0x49490000 */

#define	II_PIT_COPY	II_CONTROL(1)	/* Perform an II Copy */
#define	II_PIT_UPDATE	II_CONTROL(2)	/* Perform an II Update */
#define	II_PIT_ABORT	II_CONTROL(3)	/* Perform an II Abort */
#define	II_PIT_WAIT	II_CONTROL(4)	/* Perform an II Wait */
#define	II_PIT_PROPS	II_CONTROL(5)	/* Perform an II Properties */

#ifdef __cplusplus
}
#endif

#endif	/* _DSW_H */
