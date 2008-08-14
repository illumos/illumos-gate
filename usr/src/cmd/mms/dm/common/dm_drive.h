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
 *
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */



#ifndef	__DM_DRIVE_H
#define	__DM_DRIVE_H


#include <sys/scsi/impl/uscsi.h>
#include <mms_dmd.h>
#include <mms_sym.h>
#include <mms_list.h>
#include <mms_scsi.h>
#include <sys/mtio.h>
#include <mms_trace.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	DRV_LOAD_TUR			600	/* Try this many TURs before */
						/* Issueing the load command */
#define	DMNAME	(drv->drv_dmname)
#define	DRVNAME	(drv->drv_drvname)

/*
 * an MTIOCTOP/MTIOCLTOP request
 */
typedef	struct	drv_req	{
	uint16_t	drv_op;
	int64_t		drv_count;
}	drv_req_t;


/*
 * For DRIVECARTRIDGEACCESS object
 */
typedef	struct	drv_cart_access {
	int		dca_flags;
	char		*dca_side_name;
	char		*dca_part_name;
	char		*dca_app_name;
	char		*dca_cart_id;
	char		*dca_mounted_last;
	char		*dca_cart_shape_name;
	char		*dca_drv_shape_name;
	char		*dca_pcl;
	int64_t		dca_bytes_read;		/* uncompressed bytes read */
						/* by app */
	int64_t		dca_bytes_read_med;	/* compressed bytes read */
						/* from medium */
	int64_t		dca_bytes_written;	/* uncompressed bytes written */
						/* by app */
	int64_t		dca_bytes_written_med;	/* compressed bytes written */
						/* on medium */
	int		dca_read_err;
	int		dca_rcvd_read_err;
	int		dca_write_err;
	int		dca_rcvd_write_err;
}	drv_cart_access_t;

#define	DRV_DCA_VALID	1			/* DCA has valid info */

/*
 * Hold dm mount request attributes
 */
typedef	struct	drv_mount {
	uint64_t	mnt_flags;		/* yes/no option flags */
	uint32_t	mnt_tm;			/* tapemark processing option */
	int		mnt_blksize;		/* blocksize in mount cmd */
	int		mnt_dflt_blksize;	/* default blksize */
	int		mnt_lbl_type;		/* label type - al, sl, nl */
	int		mnt_fseq;
	int		mnt_retention;
	/*
	 * Don't free the following
	 */
	mms_sym_t		*mnt_bitformat;
	mms_sym_t		*mnt_density;
	/*
	 * End of don't free
	 */
	/*
	 * Must free the following from here to ...
	 */
	char		*mnt_volumename;
	char		*mnt_vid;
	char		*mnt_pcl;
	char		*mnt_fname;		 /* filename */
	char		*mnt_user;
	char		*mnt_dencode;
	char		*mnt_shape;		/* cartridge shape */
	/*
	 * End of must free
	 */
}	drv_mount_t;

#define	MNT_FIXED		(1LL << 0)	/* fixed block */
#define	MNT_VARIABLE		(1LL << 1)	/* variable block */
#define	MNT_MMS		(1LL << 2)	/* MMS mode or raw mode */
#define	MNT_NOT_USED		(1LL << 3)
#define	MNT_NOREWIND		(1LL << 4)	/* rewind/norewind at close */
#define	MNT_AVAIL_0		(1LL << 5)
#define	MNT_COMPRESSION		(1LL << 6)	/* Turn compression on */
#define	MNT_AVAIL_1		(1LL << 7)
#define	MNT_LOW			(1LL << 8)	/* Low density */
#define	MNT_MEDIUM		(1LL << 9)	/* Medium density */
#define	MNT_HIGH		(1LL << 10)	/* High density */
#define	MNT_ULTRA		(1LL << 11)	/* Ultra density */
#define	MNT_AUTO_DEN		(1LL << 12)	/* Use auto den */
#define	MNT_BSD			(1LL << 13)	/* Use Solaris BSD mode */
#define	MNT_NOBSD		(1LL << 14)	/* Use Solaris NOBSD */
#define	MNT_MMS_TM		(1LL << 15)	/* Use MMS TM behavior */
#define	MNT_NOLOAD		(1LL << 16)	/* don't issue load command */
#define	MNT_PRIVILEGED		(1LL << 17)	/* From a privileged client */
#define	MNT_VALIDATE_VID	(1LL << 18)
#define	MNT_NO_VALIDATE_VID	(1LL << 19)
#define	MNT_VALIDATE_XDATE	(1LL << 20)
#define	MNT_NO_VALIDATE_XDATE	(1LL << 21)
#define	MNT_VALIDATE_FNAME	(1LL << 22)
#define	MNT_NO_VALIDATE_FNAME	(1LL << 23)
#define	MNT_PREEMPT_RSV		(1LL << 24)
#define	MNT_ASK_PREEMPT_RSV	(1LL << 25)
#define	MNT_NO_PREEMPT_RSV	(1LL << 26)
#define	MNT_SWITCH_LBL		(1LL << 27)
#define	MNT_ASK_SWITCH_LBL	(1LL << 28)
#define	MNT_NO_SWITCH_LBL	(1LL << 29)
#define	MNT_WRITEOVER		(1LL << 30)
#define	MNT_ASK_WRITEOVER	(1LL << 31)
#define	MNT_NO_WRITEOVER	(1LL << 32)
#define	MNT_READONLY		(1LL << 33)	/* readonly */
#define	MNT_READWRITE		(1LL << 34)	/* readwrite */
#define	MNT_OLD			(1LL << 35)
#define	MNT_CREAT		(1LL << 36)

#define	DRV_IOBUF_LEN		10240
#define	DRV_LBN_LEN		17
#define	DRV_SENSE_LEN		255		/* sense buf size */
#define	DRV_INQ_LEN		64		/* inquiry data buf size */
#define	DRV_LOGICAL_CROSS_TM	1		/* Cross TM */


/*
 * Uscsi request
 */
typedef	struct	drv_scsi_err {
	int		se_flags;
	uchar_t		se_cdb[MMS_MAX_CDB_LEN];	/* save cdb if error */
	int		se_cdblen;
	union {
		uchar_t	se_senbytes[DRV_SENSE_LEN];
		struct	scsi_extended_sense se_xsense;
	}		se_u_sense;
	int		se_senlen;
	uchar_t		se_errcl;			/* error class */
	drm_mtget_t	se_mtget;
	int		se_errno;
	char		*se_err_text;
}	drv_scsi_err_t;

#define	DRV_SE_USCSI		0x01		/* A uscsi error */
#define	DRV_SE_SEN_VALID	0x02		/* sense is valid */
#define	DRV_SE_ILI		0x04		/* Ilegal length */

#define	se_sense		se_u_sense.se_senbytes
#define	se_extsen		se_u_sense.se_xsense
#define	se_cmd			se_cdb[0]
#define	se_asc			se_sense[12]
#define	se_ascq			se_sense[13]
#define	se_type			se_mtget.drm_type
#define	se_dsreg		se_mtget.drm_dsreg
#define	se_erreg		se_mtget.drm_erreg
#define	se_status		se_dsreg
#define	se_senkey		se_erreg
#define	se_resid		se_mtget.drm_resid
#define	se_fileno		se_mtget.drm_fileno
#define	se_blkno		se_mtget.drm_blkno
#define	se_mt_flags		se_mtget.drm_mt_flags
#define	se_mt_bf		se_mtget.drm_mt_bf

/*
 * Define error class
 */
typedef	enum	{
	DRV_EC_ERROR = 1,
	DRV_EC_NOT_READY,
	DRV_EC_NO_SENSE,
	DRV_EC_TM,
	DRV_EC_EOD,
	DRV_EC_EOM,
	DRV_EC_BOM,
	DRV_EC_NEEDS_CLEANING,
	DRV_EC_FORMAT,
	DRV_EC_INTER_REQ,
	DRV_EC_RESET,
	DRV_EC_UNIT_ATTN,
	DRV_EC_LOST_PRSV,
	DRV_EC_RCVD_ERR,
	DRV_EC_MEDIUM_ERR,
	DRV_EC_HW_ERR,
	DRV_EC_ILLEGAL_REQ,
	DRV_EC_DATA_PROTECT,
	DRV_EC_BLANK_CHECK,
	DRV_EC_VENDOR,
	DRV_EC_COPY_ABORTED,
	DRV_EC_ABORTED,
	DRV_EC_VOL_OVERFLOW,
	DRV_EC_MISCOMPARE,
	DRV_EC_NREADY_TO_READY,

	/* Add additional erorr classes before this line */
	DRV_EC_UNKNOWN_ERR			/* End of table */
}	drv_err_class_t;

typedef	struct	drv_skaa {
	uchar_t		drv_senkey;
	uchar_t		drv_asc;
	uchar_t		drv_ascq;
	drv_err_class_t drv_ec;		/* error class */
	char		*drv_text;
}	drv_skaa_t;



#define	DRV_IMPID	"SUNMICRO MMS "
#define	DRV_IMPID2	"SUNMICRO SMMS"
#define	DRV_IMPID_LEN	(sizeof (((drv_vol1_t *)0)->vol1_impid))


typedef	struct	drv_vol1 {
	char	vol1_id[4];			/* Label ID */
	char	vol1_vid[6];			/* Vol ID */
	char	vol1_acc;			/* Accessability */
	char	vol1_reserved[13];
	char	vol1_impid[13];			/* implemenation ID */
	char	vol1_owner[14];			/* Owner */
	char	vol1_reserved2[28];
	char	vol1_ver;			/* Standard Version (4) */
}	drv_vol1_t;

#define	VOL1_ID		"VOL1"
#define	VOL1_OWNER	"SUNMICROSYSTEM"
#define	VOL1_VER	"4   "


typedef	struct	drv_hdr1 {
	char	hdr1_id[4];			/* Label ID */
	char	hdr1_fid[17];			/* File ID */
	char	hdr1_fsid[6];			/* File set ID */
	char	hdr1_fsnum[4];			/* File section number */
	char	hdr1_fseq[4];			/* File sequence number */
	char	hdr1_gnum[4];			/* Generation number */
	char	hdr1_gver[2];			/* Generation version */
	char	hdr1_cdate[6];			/* Creation date */
	char	hdr1_xdate[6];			/* Expiration date */
	char	hdr1_acc;			/* File accessability */
	char	hdr1_bcount[6];			/* Block count */
	char	hdr1_impid[13];			/* Implementation ID */
	char	hdr1_reserved[7];
}	drv_hdr1_t;

#define	HDR1_ID		"HDR1"

typedef	struct	drv_hdr2 {
	char	hdr2_id[4];
	char	hdr2_rformat;
	char	hdr2_blklen[5];
	char	hdr2_rcdlen[5];
	union	{
		char	hdr2_impuse[35];	/* for use by implimentation */
		char	hdr2_blksize_u[10];	/* blocksize */
	}	hdr2_impuse_u;
	char	hdr2_off[2];
	char	hdr2_reserved[28];
}	drv_hdr2_t;

#define	hdr2_blksize	hdr2_impuse_u.hdr2_blksize_u

#define	HDR2_ID		"HDR2"

typedef	struct	drv_eof1 {
	char	eof1_id[4];			/* Label ID */
	char	eof1_fid[17];			/* File ID */
	char	eof1_fsid[6];			/* File set ID */
	char	eof1_fsnum[4];			/* File section number */
	char	eof1_fseq[4];			/* File sequence number */
	char	eof1_gnum[4];			/* Generation number */
	char	eof1_gver[2];			/* Generation version */
	char	eof1_cdate[6];			/* Creation date */
	char	eof1_xdate[6];			/* Expiration date */
	char	eof1_acc;			/* File accessability */
	char	eof1_bcount[6];			/* Block count */
	char	eof1_impid[13];			/* Implementation ID */
	char	eof1_reserved[7];
}	drv_eof1_t;

#define	EOF1_ID		"EOF1"

typedef	struct	drv_eof2 {
	char	eof2_id[4];
	char	eof2_rformat;
	char	eof2_blklen[5];
	char	eof2_rcdlen[5];
	union	{
		char	eof2_impuse[35];	/* for use by implimentation */
		char	eof2_blksize_u[10];	/* blocksize */
	}	eof2_impuse_u;
	char	eof2_off[2];
	char	eof2_reserved[28];
}	drv_eof2_t;

#define	eof2_blksize	eof2_impuse_u.eof2_blksize_u

#define	EOF2_ID		"EOF2"


typedef	struct	drv_eov1 {
	char	eov1_id[4];			/* Label ID */
	char	eov1_fid[17];			/* File ID */
	char	eov1_fsid[6];			/* File set ID */
	char	eov1_fsnum[4];			/* File section number */
	char	eov1_fseq[4];			/* File sequence number */
	char	eov1_gnum[4];			/* Generation number */
	char	eov1_gver[2];			/* Generation version */
	char	eov1_cdate[6];			/* Creation date */
	char	eov1_xdate[6];			/* Expiration date */
	char	eov1_acc;			/* File accessability */
	char	eov1_bcount[6];			/* Block count */
	char	eov1_impid[13];			/* Implementation ID */
	char	eov1_reserved[7];
}	drv_eov1_t;

#define	EOV1_ID		"EOV1"

typedef	struct	drv_eov2 {
	char	eov2_id[4];
	char	eov2_rformat;
	char	eov2_blklen[5];
	char	eov2_rcdlen[5];
	union	{
		char	eov2_impuse[35];	/* for use by implimentation */
		char	eov2_blksize_u[10];	/* blocksize */
	}	eov2_impuse_u;
	char	eov2_off[2];
	char	eov2_reserved[28];
}	drv_eov2_t;

#define	eov2_blksize	eov2_impuse_u.eov2_blksize_u

#define	EOV2_ID		"EOV2"

typedef	struct	drv_timeout {
	short	drv_long_timeout;		/* For really long commands */
	short	drv_timeout;			/* Normal commands */
	short	drv_short_timeout;		/* short commands */
}	drv_timeout_t;

/*
 * Define a structure that specifies which density can be written on a shape
 */
typedef	struct	drv_shape_density {
	char	*drv_shape;			/* shape name */
	char	*drv_bit;			/* density on cartridge */
	char	*drv_den;			/* write density */
}	drv_shape_density_t;

/*
 * drv_drive - states of drive with volume mounted
 */
typedef	struct	drv_drive {
	uint64_t	drv_flags;
	char		drv_typename[65];
	char		drv_vend[9];
	char		drv_prod[17];
	mms_capacity_t	drv_cap;		/* Capacity of tape */
	int		drv_fd;			/* file descriptor of drive */
	int		drv_numopens;		/* num. of opens since loaded */
	int		drv_fseq;
	int		drv_lbl_type;		/* label type */
	int		drv_file_blksize;	/* block size of file */
	int		drv_cur_blksize;	/* current blocksize */
	int		drv_lbl_blksize;	/* block size on the label */
	int		drv_dflt_blksize;
	int		drv_retention;
	int		drv_xdate;		/* expiration date */
	int		drv_disk_mount_timeout;
	drv_vol1_t	drv_vol1;
	drv_hdr1_t	drv_hdr1;
	drv_hdr2_t	drv_hdr2;
	drv_eof1_t	drv_eof1;
	drv_eof2_t	drv_eof2;
	drv_eov1_t	drv_eov1;
	drv_eov2_t	drv_eov2;
	uint32_t	drv_oflags;
	tapepos_t	drv_bof_pos;
	tapepos_t	drv_eof_pos;
	tapepos_t	drv_cur_pos;
	drm_mtget_t	drv_mtget;
	daddr_t		drv_rdbytes;
	daddr_t		drv_wrbytes;
	int		drv_cur_den;
	mms_sym_t	*drv_density;
	char		**drv_shape;
	drv_shape_density_t *drv_shape_den;
	char		**drv_mounted;
	char		*drv_dmname;
	char		*drv_drvname;
	char		*drv_dev_dir;
	char		*drv_drive_type;		/* drive type */
	uchar_t		*drv_iobuf;
	drv_timeout_t	*drv_timeout;
	drv_skaa_t	*drv_skaa_tab;
	char		drv_vid[10];
	char		drv_fid[18];
	char		drv_serial_num[MMS_SER_NUM_LEN + 1];
	char		drv_sernum[MMS_SER_NUM_LEN + 1];
						/* serial num from DRIVE obj */
	uchar_t		drv_prsv_key[8];
	int		drv_mtee_stat_len;		/* mtee status len */
	int		drv_num_sen_bytes;
	int		*drv_disallowed_cmds;
	int		*drv_num_disallowed_cmds;
	int		*drv_disallowed_ioctls;
	int		*drv_num_disallowed_ioctls;
	int		*drv_prsv_supported;
}	drv_drive_t;

/*
 * Drive Flags
 */
#define	DRV_LOADED		(1LL << 0)
#define	DRV_IDENTIFIED		(1LL << 1)
#define	DRV_MMS_LBL		(1LL << 2)
#define	DRV_VALIDATED_FNAME	(1LL << 3)
#define	DRV_VOL1		(1LL << 4)	/* vol has VOL1 label */
#define	DRV_HDR1		(1LL << 5)	/* vol has HDR1 label */
#define	DRV_HDR2		(1LL << 6)	/* vol has HDR2 label */
#define	DRV_TERM_FILE		(1LL << 7)	/* Need to terminate file */
#define	DRV_OPENED		(1LL << 8)	/* User opened file */
#define	DRV_UDATA		(1LL << 9)	/* vol in user data */
#define	DRV_FATAL		(1LL << 10)	/* a fatal error occurred */
#define	DRV_ENABLED		(1LL << 11)	/* DM is enabled */
#define	DRV_BOF			(1LL << 12)	/* at BOF */
#define	DRV_EOF			(1LL << 13)	/* at EOF */
#define	DRV_TM			(1LL << 14)	/* hit a tapemark */
#define	DRV_BLANK		(1LL << 15)	/* A blank tape */
#define	DRV_ATTACHED		(1LL << 16)	/* drive attached */
#define	DRV_BOM			(1LL << 17)	/* at BOM */
#define	DRV_EOM			(1LL << 18)	/* at EOM */
#define	DRV_FIXED		(1LL << 19)	/* Fixed format */
#define	DRV_VARIABLE		(1LL << 20)	/* Variable format */
#define	DRV_EOF1		(1LL << 21)	/* Has EOF1 label */
#define	DRV_EOF2		(1LL << 22)	/* Has EOF2 label */
#define	DRV_VALID_BOF_POS	(1LL << 23)	/* BOF position is valid */
#define	DRV_LOST_POS		(1LL << 24)	/* DM lost position of drive */
#define	DRV_VALID_STAT		(1LL << 25)	/* Drive status is valid */
#define	DRV_VALID_EOF_POS	(1LL << 26)	/* EOF position is valid */
#define	DRV_UPDATE_EOF_POS	(1LL << 27)	/* Must update eof at close */
#define	DRV_UPDATE_CAPACITY	(1LL << 28)	/* Update capacity at close */
#define	DRV_READONLY		(1LL << 29)	/* Readonly cartridge */
#define	DRV_RESERVED		(1LL << 30)	/* Drive reserved */
#define	DRV_WRITEOVER		(1LL << 31)	/* Writeover silently */
#define	DRV_ASK_WRITEOVER	(1LL << 32)	/* Ask writeover */
#define	DRV_SWITCH_LBL		(1LL << 33)	/* Do label switch silently */
#define	DRV_ASK_SWITCH_LBL	(1LL << 34)	/* Ask label switch */
#define	DRV_VALIDATE_FNAME	(1LL << 35)	/* Validate filename */
#define	DRV_VALIDATE_VID	(1LL << 36)	/* Validate VID */
#define	DRV_VALIDATE_XDATE	(1LL << 37)	/* Validate expiration date */
#define	DRV_WRITEPROTECTED	(1LL << 38)	/* Cart is writeprotected */
#define	DRV_CREAT		(1LL << 39)	/* Create new file */
#define	DRV_APPEND		(1LL << 40)	/* append file */

#define	drv_capacity		drv_cap.mms_max
#define	drv_avail		drv_cap.mms_avail
#define	drv_pc_avail		drv_cap.mms_pc_avail

#define	DRV_MOVE_FLAGS		(DRV_BOM | DRV_BOF | DRV_TM | DRV_EOF | DRV_EOM)

#define	DRV_SAVE_STAT		1

/*
 * Define label type
 */
#define	DRV_AL		1
#define	DRV_SL		2
#define	DRV_NL		3
#define	DRV_BLP		4

typedef void		(drv_init_dev_t)(void);
drv_init_dev_t		drv_init_dev;
typedef minor_t		(drv_get_targ_t)(minor_t);
drv_get_targ_t		drv_get_targ;
typedef int		(drv_set_blksize_t)(uint64_t);
drv_set_blksize_t	drv_set_blksize;
typedef int		(drv_get_blksize_t)(uint64_t *);
drv_get_blksize_t	drv_get_blksize;
typedef	int		(drv_get_density_t)(int *, int *);
drv_get_density_t	drv_get_density;
typedef	int		(drv_set_density_t)(int);
drv_set_density_t	drv_set_density;
typedef int		(drv_read_t)(char *, int);
drv_read_t		drv_read;
typedef int		(drv_write_t)(char *, int);
drv_write_t		drv_write;
typedef int		(drv_get_capacity_t)(mms_capacity_t *);
drv_get_capacity_t	drv_get_capacity;
typedef int64_t		(drv_get_avail_capacity_t)(void);
drv_get_avail_capacity_t	drv_get_avail_capacity;
typedef int		(drv_clrerr_t)(void);
drv_clrerr_t		drv_clrerr;
typedef void		(drv_proc_error_t)(void);
drv_proc_error_t	drv_proc_error;
typedef int		(drv_inquiry_t)(void);
drv_inquiry_t		drv_inquiry;
typedef int		(drv_req_sense_t)(int);
drv_req_sense_t		drv_req_sense;
typedef int		(drv_wtm_t)(uint64_t);
drv_wtm_t		drv_wtm;
typedef int		(drv_tur_t)(void);
drv_tur_t		drv_tur;
typedef int		(drv_load_t)(void);
drv_load_t		drv_load;
typedef int		(drv_unload_t)(void);
drv_unload_t		drv_unload;
typedef int		(drv_rewind_t)(void);
drv_rewind_t		drv_rewind;
typedef int		(drv_mode_sense_t)(int, int, int);
drv_mode_sense_t	drv_mode_sense;
typedef int		(drv_mode_select_t)(int, int);
drv_mode_select_t	drv_mode_select;
typedef	int		(drv_seek_t)(uint64_t);
drv_seek_t		drv_seek;
typedef	int		(drv_tell_t)(uint64_t *);
drv_tell_t		drv_tell;
typedef int		(drv_fsf_t)(uint64_t);
drv_fsf_t		drv_fsf;
typedef int		(drv_bsf_t)(uint64_t);
drv_bsf_t		drv_bsf;
typedef int		(drv_fsb_t)(uint64_t, int);
drv_fsb_t		drv_fsb;
typedef int		(drv_bsb_t)(uint64_t, int);
drv_bsb_t		drv_bsb;
typedef int		(drv_eom_t)(void);
drv_eom_t		drv_eom;
typedef int		(drv_get_pos_t)(tapepos_t *);
drv_get_pos_t		drv_get_pos;
typedef int		(drv_mtgetpos_t)(tapepos_t *);
drv_mtgetpos_t		drv_mtgettpos;
typedef int		(drv_mtrestpos_t)(tapepos_t *);
drv_mtrestpos_t		drv_mtrestpos;
typedef int		(drv_get_statistics_t)(void);
drv_get_statistics_t	drv_get_statistics;
typedef int		(drv_locate_t)(tapepos_t *);
drv_locate_t		drv_locate;
typedef int		(drv_log_sense_t)(uchar_t *, int, int, int);
drv_log_sense_t		drv_log_sense;
typedef int		(drv_blk_limit_t)(mms_blk_limit_t *);
drv_blk_limit_t		drv_blk_limit;
typedef int		(drv_reserve_t)(void);
drv_reserve_t		drv_reserve;
typedef int		(drv_release_t)(void);
drv_release_t		drv_release;
typedef int		(drv_get_serial_num_t)(char *);
drv_get_serial_num_t	drv_get_serial_num;
typedef int		(drv_get_write_protect_t)(int *);
drv_get_write_protect_t	drv_get_write_protect;
typedef int		(drv_prsv_register_t)(void);
drv_prsv_register_t	drv_prsv_register;
typedef int		(drv_prsv_reserve_t)(void);
drv_prsv_reserve_t	drv_prsv_reserve;
typedef int		(drv_prsv_release_t)(void);
drv_prsv_release_t	drv_prsv_release;
typedef int		(drv_prsv_clear_t)(void);
drv_prsv_clear_t	drv_prsv_clear;
typedef int		(drv_prsv_preempt_t)(char *);
drv_prsv_preempt_t	drv_prsv_preempt;
typedef int		(drv_prsv_read_keys_t)(char *, int);
drv_prsv_read_keys_t	drv_prsv_read_keys;
typedef int		(drv_prsv_read_rsv_t)(char *, int);
drv_prsv_read_rsv_t	drv_prsv_read_rsv;
typedef int		(drv_set_compression_t)(int);
drv_set_compression_t	drv_set_compression;

typedef	char **		(drv_get_mounted_t)(void);
drv_get_mounted_t	drv_get_mounted;
typedef	int		(drv_get_drivetype_t)(void);
drv_get_drivetype_t	drv_get_drivetype;
typedef	int		(drv_rebind_target_t)(void);
drv_rebind_target_t	drv_rebind_target;
typedef	void		(drv_mk_prsv_key_t)(void);
drv_mk_prsv_key_t	drv_mk_prsv_key;
typedef	void		(drv_disallowed_t)(void);
drv_disallowed_t	drv_disallowed;
typedef	int		(drv_bind_raw_dev_t)(int);
drv_bind_raw_dev_t	drv_bind_raw_dev;

typedef	struct	drv_jtab {
	drv_init_dev_t		*drv_init_dev;
	drv_bind_raw_dev_t	*drv_bind_raw_dev;
	drv_disallowed_t	*drv_disallowed;
	drv_mk_prsv_key_t	*drv_mk_prsv_key;
	drv_rebind_target_t	*drv_rebind_target;
	drv_get_mounted_t	*drv_get_mounted;
	drv_get_drivetype_t	*drv_get_drivetype;
	drv_get_targ_t		*drv_get_targ;
	drv_set_blksize_t	*drv_set_blksize;
	drv_get_blksize_t	*drv_get_blksize;
	drv_get_density_t	*drv_get_density;
	drv_set_density_t	*drv_set_density;
	drv_read_t		*drv_read;
	drv_write_t		*drv_write;
	drv_get_capacity_t	*drv_get_capacity;
	drv_get_avail_capacity_t *drv_get_avail_capacity;
	drv_get_statistics_t	*drv_get_statistics;

	drv_clrerr_t		*drv_clrerr;
	drv_proc_error_t	*drv_proc_error;
	drv_inquiry_t		*drv_inquiry;
	drv_req_sense_t		*drv_req_sense;
	drv_wtm_t		*drv_wtm;
	drv_tur_t		*drv_tur;
	drv_load_t		*drv_load;
	drv_unload_t		*drv_unload;
	drv_rewind_t		*drv_rewind;
	drv_mode_sense_t	*drv_mode_sense;
	drv_mode_select_t	*drv_mode_select;
	drv_seek_t		*drv_seek;
	drv_tell_t		*drv_tell;
	drv_fsf_t		*drv_fsf;
	drv_bsf_t		*drv_bsf;
	drv_fsb_t		*drv_fsb;
	drv_bsb_t		*drv_bsb;
	drv_eom_t		*drv_eom;
	drv_get_pos_t		*drv_get_pos;
	drv_mtgetpos_t		*drv_mtgetpos;
	drv_mtrestpos_t		*drv_mtrestpos;
	drv_locate_t		*drv_locate;
	drv_log_sense_t		*drv_log_sense;
	drv_blk_limit_t		*drv_blk_limit;
	drv_reserve_t		*drv_reserve;
	drv_release_t		*drv_release;
	drv_get_serial_num_t	*drv_get_serial_num;
	drv_get_write_protect_t	*drv_get_write_protect;
	drv_prsv_register_t	*drv_prsv_register;
	drv_prsv_reserve_t	*drv_prsv_reserve;
	drv_prsv_release_t	*drv_prsv_release;
	drv_prsv_clear_t	*drv_prsv_clear;
	drv_prsv_preempt_t	*drv_prsv_preempt;
	drv_prsv_read_keys_t	*drv_prsv_read_keys;
	drv_prsv_read_keys_t	*drv_prsv_read_rsv;
	drv_set_compression_t	*drv_set_compression;
}	drv_jtab_t;


extern	drv_jtab_t	*jtab;
extern	drv_mount_t	*mnt;
extern	drv_drive_t	*drv;
extern	drv_scsi_err_t	*serr;
extern	drv_cart_access_t *dca;

int dm_uscsi(struct uscsi_cmd *us);
int dm_mtiocltop(drv_req_t *op);
int dm_ioctl(int cmd, void *arg);
void dm_get_mtstat(int);
void dm_err_trace(void);
void dm_disallowed(void);
void dm_mk_prsv_key(void);
int dm_rebind_target(void);
int dm_bind_raw_dev(int);
void dm_get_mt_error(int err);
int dm_get_log_sense_parm(uchar_t *page, int code, uint64_t *val);
int dm_send_clean_request(void);
void int32_to_char(int32_t val, uchar_t *start, int len);
void int64_to_char(int64_t val, uchar_t *start, int len);
void char_to_int32(signed char *start, int len, int32_t *val);
void char_to_uint32(uchar_t *start, int len, uint32_t *val);
void char_to_int64(signed char *start, int len, int64_t *val);
void char_to_uint64(uchar_t *start, int len, uint64_t *val);
int dm_send_error(void);
int dm_send_drive_broken(void);
int dm_send_cartridge_media_error(void);

#define	CONF_TASK		"$taskid$"
#define	CONF_DMNAME		"$dmname$"
#define	CONF_SHAPE		"$shape$"
#define	CONF_SHAPE_RW		"$shape_rw$"
#define	CONF_SHAPE_RO		"$shape_ro$"
#define	CONF_DENSITY_RW		"$density_rw$"
#define	CONF_DENSITY_RO		"$density_ro$"
#define	CONF_DENSITY_WO		"$density_wo$"
#define	CONF_DRIVE_SPEC		"$drivespec$"
#define	CONF_DRIVE_TYPE		"$drivetype$"
#define	CONF_BITFORMAT		"$bitformat$"
#define	CONF_BITFORMAT_RW	"$bitformat_rw$"
#define	CONF_BITFORMAT_RO	"$bitformat_ro$"
#define	CONF_BITFORMAT_WO	"$bitformat_writeover$"
#define	CONF_BIT_CLAUSE		"$bitformat_clause$"
#define	CONF_SHAPE_PRIORITY	"$shape_priority$"
#define	CONF_DEN_PRIORITY	"$den_priority$"
#define	CUR_SHAPE_RW		"$cur_shape_rw$"
#define	CUR_DENSITY_RW		"$cur_density_rw$"
#define	CUR_DENSITY_RO		"$cur_density_ro$"
#define	CUR_BITFORMAT_RW	"$cur_bitformat_rw$"
#define	CUR_BITFORMAT_WO	"$cur_bitformat_wo$"
#define	CONF_CAP_READWRITE	"$conf_cap_readwrite$"
#define	CONF_CAP_DENSITY_CLAUSE	"$conf_cap_density_clause$"
#define	CONF_MOUNT_POINT	"$conf_mount_point$"


#define	DRV_CAP_WRITEOVER ""						\
	/*								\
	 * Device that uses specific densities				\
	 * to overwrite existing density				\
	 */								\
									\
	"cap ['writeover-"						\
	CONF_DMNAME"-"CUR_SHAPE_RW"-"CUR_BITFORMAT_RW"-"CUR_DENSITY_RW"' " \
	"	caplist [ 'mms' \n"					\
	"	'*nocompression' 'compression' \n"			\
	"	'*default_tm' 'mms_tm' 'st_bsd' 'st_nobsd' \n"		\
	"	'variable' 'block' 'fixed' \n"				\
	"	'*load' 'noload'\n"					\
	"	'*auto_drive' "	CONF_DRIVE_SPEC "'" CONF_DRIVE_TYPE "'\n" \
	"	'*oflag' 'creat' 'old' 'trunc' 'append' \n"		\
	"	'*default_lbl' 'al' 'sl' 'nl' 'blp' \n"			\
	"	'*rewind' 'norewind' \n"				\
	"	'*dflt_vldt_filename' 'validate_filename' "		\
	"	'no_validate_filename' \n"				\
	"	'*dflt_vldt_vid' 'validate_vid' 'no_validate_vid' \n"	\
	"	'*dflt_vldt_xdate' 'validate_xdate' 'no_validate_xdate'\n" \
	"	'*dflt_switch_lbl' 'switch_lbl' 'ask_switch_lbl' "	\
	"	'no_switch_lbl'\n"					\
	"	'*dflt_writeover' 'writeover' 'ask_writeover' "		\
	"	'no_writeover'\n"					\
	"	'*dflt_preempt_rsv' 'preempt_rsv' 'ask_preempt_rsv' "	\
	"	'no_preempt_rsv'\n"					\
	"	'*readwrite' 'readwrite' \n"				\
	"	'" CUR_DENSITY_RW "'\n"					\
	"	'*bit_unknown' '" CUR_BITFORMAT_WO "'\n"		\
	"	'" CUR_SHAPE_RW "'\n"					\
	"	]] \n"

#define	DRV_CAP_READWRITE ""						\
	/*								\
	 * Device that uses specific densities				\
	 * for readwrite						\
	 */								\
									\
	"cap ['readwrite-"						\
	CONF_DMNAME"-"CUR_SHAPE_RW"-"CUR_BITFORMAT_RW"-"CUR_DENSITY_RW"' " \
	"	caplist [ 'mms' \n"					\
	"	'*nocompression' 'compression' \n"			\
	"	'*default_tm' 'mms_tm' 'st_bsd' 'st_nobsd' \n"		\
	"	'variable' 'block' 'fixed' \n"				\
	"	'*load' 'noload'\n"					\
	"	'*auto_drive' "	CONF_DRIVE_SPEC "'" CONF_DRIVE_TYPE "'\n" \
	"	'*oflag' 'creat' 'old' 'trunc' 'append' \n"		\
	"	'*default_lbl' 'al' 'sl' 'nl' 'blp' \n"			\
	"	'*rewind' 'norewind' \n"				\
	"	'*dflt_vldt_filename' 'validate_filename' "		\
	"	'no_validate_filename' \n"				\
	"	'*dflt_vldt_vid' 'validate_vid' 'no_validate_vid' \n"	\
	"	'*dflt_vldt_xdate' 'validate_xdate' 'no_validate_xdate'\n" \
	"	'*dflt_switch_lbl' 'switch_lbl' 'ask_switch_lbl' "	\
	"	'no_switch_lbl'\n"					\
	"	'*dflt_writeover' 'writeover' 'ask_writeover' "		\
	"	'no_writeover'\n"					\
	"	'*dflt_preempt_rsv' 'preempt_rsv' 'ask_preempt_rsv' "	\
	"	'no_preempt_rsv'\n"					\
	"	'*readwrite' 'readwrite' \n"				\
	"	'" CUR_DENSITY_RW "'\n"					\
	"	'" CUR_BITFORMAT_RW "'\n"				\
	"	'" CUR_SHAPE_RW "'\n"					\
	"	]] \n"



/*
 * format of config command
 * Default capabilities that begin with '*' are default capabilities which
 * are meant to be hidden from the user and should not be documented in user
 * manuals.
 */
#define	DRV_CONFIG	""						\
	"config task ['" CONF_TASK "'] scope [full]\n"			\
									\
	"group ['st-device' 'interchange' "				\
	"'*nocompression' 'compression' 'high' 'low' 'medium' 'ultra' ] \n" \
									\
	"group ['specific-density' 'interchange' "			\
	"'*auto_density' "						\
	CONF_DENSITY_RW CONF_DENSITY_RO "] \n"				\
									\
	"group ['bitformat-list' 'interchange' "			\
	"'*bit_unknown' " CONF_BITFORMAT "]\n"				\
									\
	"group ['data-block-format' 'access' "				\
	"'variable' 'block' 'fixed']\n"					\
									\
	"group ['shape' 'access' "					\
	CONF_SHAPE_RW CONF_SHAPE_RO " ] \n"				\
									\
	"group ['do-load' 'access' "					\
	"'*load' 'noload']\n"						\
									\
	"group ['tm-behavor' 'access' "					\
	"'*default_tm' 'mms_tm' 'st_nobsd' 'st_bsd' ]\n"		\
									\
	"group ['specific-drive' 'access' "				\
	"'*auto_drive' " CONF_DRIVE_SPEC "'" CONF_DRIVE_TYPE "']\n"	\
									\
	"group ['file-disposition' 'access' "				\
	"'*oflag' 'old' 'creat' 'new' 'trunc' 'append'] \n"		\
									\
	"group ['operation-mode' 'access' "				\
	"'mms' 'raw'] \n"						\
									\
	"group ['lable-type' 'access' "					\
	"'*default_lbl' 'al' 'nl' 'sl' 'blp'] \n"			\
									\
	"group ['readwrite-mode' 'access' "				\
	"'*readwrite' 'readwrite' 'readonly'] \n"			\
									\
	"group ['rewind-at-close' 'access' "				\
	"'*rewind' 'norewind' ] \n"					\
									\
	"group ['filename-validation' 'access' "			\
	"'*dflt_vldt_filename' 'validate_filename' 'no_validate_filename'] \n" \
									\
	"group ['vid-validation' 'access' "				\
	"'*dflt_vldt_vid' 'validate_vid' 'no_validate_vid' ]\n"		\
									\
	"group ['xdate-validation' 'access' "				\
	"'*dflt_vldt_xdate' 'validate_xdate' 'no_validate_xdate' ]\n"	\
									\
	"group ['switch-label' 'access' "				\
	"'*dflt_switch_lbl' 'switch_lbl' 'ask_switch_lbl' "		\
	"'no_switch_lbl' ]\n"						\
									\
	"group ['write-over' 'access' "					\
	"'*dflt_writeover' 'writeover' 'ask_writeover' 'no_writeover' ]\n" \
									\
	"group ['preempt-reservation' 'access' "			\
	"'*dflt_preempt_rsv' 'preempt_rsv' 'ask_preempt_rsv' "		\
	"'no_preempt_rsv' ]\n"						\
									\
	CONF_BIT_CLAUSE "\n"						\
									\
			/*						\
			 * Raw devices - readwrite			\
			 */						\
	"cap ['raw-rw-" CONF_DMNAME "' caplist [ \n"			\
	"	'raw' \n"						\
	"	'*nocompression' 'compression' "			\
	"	'high' 'low' 'medium' 'ultra' \n"			\
	"	'*auto_density' \n"					\
	"	'variable' \n"						\
	"	'*default_tm' 'st_bsd' 'st_nobsd' \n"			\
	"	'*load' \n"						\
	"	'*auto_drive' " CONF_DRIVE_SPEC "'" CONF_DRIVE_TYPE "'\n" \
	"	'*oflag' \n"						\
	"	'*default_lbl' \n"					\
	"	'*rewind' 'norewind' \n"				\
	"	'*dflt_vldt_filename' \n"				\
	"	'*dflt_vldt_vid' \n"					\
	"	'*dflt_vldt_xdate' \n"					\
	"	'*dflt_switch_lbl' \n"					\
	"	'*dflt_writeover' \n"					\
	"	'*dflt_preempt_rsv' 'preempt_rsv' 'ask_preempt_rsv' \n"	\
	"	'*readwrite' 'readwrite' \n"				\
	"	'*bit_unknown' " CONF_BITFORMAT_RW CONF_BITFORMAT_WO	\
	"	" CONF_SHAPE_RW "\n"					\
	"	]] \n"							\
									\
			/*						\
			 * Raw devices - readonly			\
			 */						\
	"cap ['raw-ro-" CONF_DMNAME "' caplist [ \n"			\
	"	'raw' \n"						\
	"	'*nocompression' 'compression' "			\
	"	'high' 'low' 'medium' 'ultra' \n"			\
	"	'*auto_density' \n"					\
	"	'variable' \n"						\
	"	'*default_tm' 'st_bsd' \n"				\
	"	'*load' \n"						\
	"	'*auto_drive' " CONF_DRIVE_SPEC "'" CONF_DRIVE_TYPE "'\n" \
	"	'*oflag' \n"						\
	"	'*default_lbl' \n"					\
	"	'*rewind' 'norewind' \n"				\
	"	'*dflt_vldt_filename' \n"				\
	"	'*dflt_vldt_vid' \n"					\
	"	'*dflt_vldt_xdate' \n"					\
	"	'*dflt_switch_lbl' \n"					\
	"	'*dflt_writeover' \n"					\
	"	'*dflt_preempt_rsv' 'preempt_rsv' 'ask_preempt_rsv' \n"	\
	"	'readonly' \n"						\
	"	'*bit_unknown' " CONF_BITFORMAT_RW CONF_BITFORMAT_RO "\n" \
	"	" CONF_SHAPE_RW CONF_SHAPE_RO "\n"			\
	"	]] \n"							\
									\
			/*						\
			 * MMS device that uses st densities		\
			 * for readwrite				\
			 */						\
									\
	"cap ['mms-readwrite" CONF_DMNAME "' caplist [ \n"		\
	"	'mms' \n"						\
	"	'*nocompression' 'compression' "			\
	"	'low' 'medium' 'high' 'ultra' \n"			\
	"	'*default_tm' 'mms_tm' 'st_bsd' 'st_nobsd' \n"		\
	"	'variable' 'block' 'fixed' \n"				\
	"	'*load' 'noload'\n"					\
	"	'*auto_drive' " CONF_DRIVE_SPEC "'" CONF_DRIVE_TYPE "'\n" \
	"	'*oflag' 'old' 'trunc' 'append' \n"			\
	"	'*default_lbl' 'al' 'sl' 'nl' 'blp' \n"			\
	"	'*rewind' 'norewind' \n"				\
	"	'*dflt_vldt_filename' 'validate_filename' "		\
	"	'no_validate_filename' \n"				\
	"	'*dflt_vldt_vid' 'validate_vid' 'no_validate_vid' \n"	\
	"	'*dflt_vldt_xdate' 'validate_xdate' 'no_validate_xdate'\n" \
	"	'*dflt_switch_lbl' 'switch_lbl' 'ask_switch_lbl' "	\
	"	'no_switch_lbl'\n"					\
	"	'*dflt_writeover' 'writeover' 'ask_writeover' "		\
	"	'no_writeover'\n"					\
	"	'*dflt_preempt_rsv' 'preempt_rsv' 'ask_preempt_rsv' "	\
	"	'no_preempt_rsv'\n"					\
	"	'*readwrite' 'readwrite' \n"				\
	"	'*auto_density' \n"					\
	"	'*bit_unknown' "					\
	"	" CONF_BITFORMAT_RW "\n"				\
	"	" CONF_SHAPE_RW "\n"					\
	"	]]\n"							\
									\
	"cap ['mms-writeover-" CONF_DMNAME "' caplist [ \n"		\
	"	'mms' \n"						\
	"	'*nocompression' 'compression' "			\
	"	'low' 'medium' 'high' 'ultra' \n"			\
	"	'*default_tm' 'mms_tm' 'st_bsd' 'st_nobsd' \n"		\
	"	'variable' 'block' 'fixed' \n"				\
	"	'*load' 'noload'\n"					\
	"	'*auto_drive' " CONF_DRIVE_SPEC "'" CONF_DRIVE_TYPE "'\n" \
	"	'creat' \n"						\
	"	'*default_lbl' 'al' 'sl' 'nl' 'blp' \n"			\
	"	'*rewind' 'norewind' \n"				\
	"	'*dflt_vldt_filename' 'validate_filename' "		\
	"	'no_validate_filename' \n"				\
	"	'*dflt_vldt_vid' 'validate_vid' 'no_validate_vid' \n"	\
	"	'*dflt_vldt_xdate' 'validate_xdate' 'no_validate_xdate'\n" \
	"	'*dflt_switch_lbl' 'switch_lbl' 'ask_switch_lbl' "	\
	"	'no_switch_lbl'\n"					\
	"	'*dflt_writeover' 'writeover' 'ask_writeover' "		\
	"	'no_writeover'\n"					\
	"	'*dflt_preempt_rsv' 'preempt_rsv' 'ask_preempt_rsv' "	\
	"	'no_preempt_rsv'\n"					\
	"	'*readwrite' 'readwrite' \n"				\
	"	'*auto_density' \n"					\
	"	'*bit_unknown' "					\
	"	" CONF_BITFORMAT_RW CONF_BITFORMAT_WO "\n"		\
	"	" CONF_SHAPE_RW "\n"					\
	"	]]\n"							\
									\
			/*						\
			 * MMS device that uses st densities		\
			 * for readonly bitformat			\
			 */						\
									\
	"cap ['mms-readonly-" CONF_DMNAME "' caplist [ \n"		\
	"	'mms' \n"						\
	"	'*nocompression' 'compression' "			\
	"	'low' 'medium' 'high' 'ultra' \n"			\
	"	'*default_tm' 'mms_tm' 'st_bsd' 'st_nobsd' \n"		\
	"	'variable' 'block' 'fixed' \n"				\
	"	'*load' 'noload'\n"					\
	"	'*auto_drive' " CONF_DRIVE_SPEC "'" CONF_DRIVE_TYPE "'\n" \
	"	'*oflag' 'old' \n"					\
	"	'*default_lbl' 'al' 'sl' 'nl' 'blp' \n"			\
	"	'*rewind' 'norewind' \n"				\
	"	'*dflt_vldt_filename' 'validate_filename' "		\
	"	'no_validate_filename' \n"				\
	"	'*dflt_vldt_vid' 'validate_vid' 'no_validate_vid' \n"	\
	"	'*dflt_vldt_xdate' 'validate_xdate' 'no_validate_xdate'\n" \
	"	'*dflt_switch_lbl'"					\
	"	'no_switch_lbl'\n"					\
	"	'*dflt_writeover'"					\
	"	'*dflt_preempt_rsv' 'preempt_rsv' 'ask_preempt_rsv' "	\
	"	'no_preempt_rsv'\n"					\
	"	'readonly' \n"						\
	"	'*auto_density' \n"					\
	"	'*bit_unknown' "					\
	"	" CONF_BITFORMAT_RW "\n"				\
	"	" CONF_SHAPE_RW "\n"					\
	"	]]\n"							\
									\
	CONF_CAP_DENSITY_CLAUSE						\
									\
			/*						\
			 * Device that uses specific densities		\
			 * for readonly					\
			 */						\
									\
	"cap ['readonly-" CONF_DMNAME "' caplist [ \n"			\
	"	'mms' \n"						\
	"	'*nocompression' 'compression' \n"			\
	"	'*default_tm' 'mms_tm' 'st_bsd' 'st_nobsd' \n"		\
	"	'variable' 'block' 'fixed' \n"				\
	"	'*load' 'noload'\n"					\
	"	'*auto_drive' " CONF_DRIVE_SPEC "'"CONF_DRIVE_TYPE "'\n" \
	"	'*oflag' 'old' \n"					\
	"	'*default_lbl' 'al' 'sl' 'nl' 'blp' \n"			\
	"	'*rewind' 'norewind' \n"				\
	"	'*dflt_vldt_filename' 'validate_filename' "		\
	"	'no_validate_filename' \n"				\
	"	'*dflt_vldt_vid' 'validate_vid' 'no_validate_vid' \n"	\
	"	'*dflt_vldt_xdate' 'validate_xdate' 'no_validate_xdate'\n" \
	"	'*dflt_switch_lbl' 'switch_lbl' 'ask_switch_lbl' "	\
	"	'no_switch_lbl'\n"					\
	"	'*dflt_writeover' 'writeover' 'ask_writeover' "		\
	"	'no_writeover'\n"					\
	"	'*dflt_preempt_rsv' 'preempt_rsv' 'ask_preempt_rsv' "	\
	"	'no_preempt_rsv'\n"					\
	"	'readonly' \n"						\
	"	" CONF_DENSITY_RW CONF_DENSITY_RO "\n"			\
	"	'*bit_unknown' "					\
	"	" CONF_BITFORMAT_RW CONF_BITFORMAT_RO "\n"		\
	"	" CONF_SHAPE_RW CONF_SHAPE_RO "\n"			\
	"	]] \n"							\
									\
	"	shapepriority [ " CONF_SHAPE " ]\n"			\
	"	densitypriority [ "					\
	"	" CONF_BITFORMAT_RW CONF_BITFORMAT_RO			\
	"	]\n"							\
	"	mountpoint [ " CONF_MOUNT_POINT " ]\n"			\
	"	;"

#ifdef	DM_MEM_DEBUG

#define	malloc(size)	dm_mem_malloc((size), __FILE__, __LINE__)
#define	strdup(str)	dm_mem_strdup((str), __FILE__, __LINE__)
#define	free(ptr)	dm_mem_free((ptr), __FILE__, __LINE__)


char *
dm_mem_malloc(size_t size, char *filename, int line);
char *
dm_mem_strdup(char *str, char *filename, int line);
void
dm_mem_free(void *ptr, char *filename, int line);


#endif

#define	DRV_TAPE_DIR	"/dev/rmt"
#define	DRV_DIR_TAB_SIZE	20

int dm_trace(mms_trace_sev_t severity, char *file, int line, char *fmt, ...);
#define	TRACE(args)		(void) (dm_silent() || dm_trace args)
int dm_silent(void);

#define	DRV_CALL(func, arg)						\
	((void) dm_trace(MMS_DEBUG, "Calling %s", #func), (*(jtab->func))arg)

#define	DRV_PRSV_KEY		(drv->drv_prsv_key)
#define	DRV_PRSV_KEY_PFX	"_MMS"

#ifdef	__cplusplus
}
#endif

#ifdef	MMS_MEM_DEBUG

#include <mms_mem_debug.h>

#endif

#endif	/* __DM_DRIVE_H */
