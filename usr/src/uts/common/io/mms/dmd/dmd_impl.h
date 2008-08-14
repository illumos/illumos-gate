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


#ifndef	__DMD_IMPL_H
#define	__DMD_IMPL_H


#include <sys/scsi/targets/stdef.h>

#ifdef	__cplusplus
extern "C" {
#endif

#include <mms_dmd.h>

/* Begin: 32-bit align copyin() structs for amd64 only due to 32-bit x86 ABI */
#if _LONG_LONG_ALIGNMENT == 8 && _LONG_LONG_ALIGNMENT_32 == 4
#pragma pack(8)
#endif

#define	DMD_DISALLOWED_MASK_SIZE (256 / 8) /* num of bytes for masks */

#define	DMD_SET_MASK(mask, flag)			\
	((mask)[(flag) / 8] |= (1 << ((flag) % 8)))
#define	DMD_UNSET_MASK(mask, flag)			\
	((mask)[(flag) / 8] &= ~(1 << ((flag) % 8)))
#define	DMD_MASK_SET(mask, flag)			\
	((mask)[(flag) / 8] & (1 << ((flag) % 8)))
#define	DMD_MASK_NOT_SET(mask, flag)	(! DMD_MASK_SET(mask, flag))
#define	DMD_DEBUG(x)	{ if (dmd_debug) cmn_err x; }

#define	DMD_WAIT_DM_GET_SEC	30		/* seconds to wait for DM */

typedef	struct	drm_blksize {
	uint64_t	drm_fixed;		/* 1 - fixed; 0 - variable */
	uint64_t	drm_blksize;
}	drm_blksize_t;

typedef	struct	drm_target {
	uint64_t	drm_targ_oflags;
	uint64_t	drm_targ_major;
	uint64_t	drm_targ_minor;
}	drm_target_t;

typedef	struct	drm_open {
	uint64_t	drm_open_flags;
	uint64_t	drm_open_type;
	uint64_t	drm_open_minor;
}	drm_open_t;

typedef	struct	drm_err {
	uint64_t		drm_errno;
	int64_t			drm_resid;
}	drm_err_t;

typedef	struct	drm_mtop {
	/*
	 * This is the fixed length (32 and 64 bits) version of
	 * struct mtop used by the st driver.
	 */
	uint64_t	drm_op;
	int64_t		drm_count;
}	drm_mtop_t;

typedef	struct	drm_request {
	uint64_t	drm_req_rdbytes;
	uint64_t	drm_req_wrbytes;
	uint64_t	drm_req_blkcnt;
	uint64_t	drm_req_type;
	uint64_t	drm_req_flags;
	uint64_t	drm_req_pid;
	uint64_t	drm_req_uid;
	union	{
		uint64_t	drm_den;
		drm_open_t	drm_open;
		drm_err_t	drm_err;
		drm_mtop_t	drm_mtop;
		mms_pos_t	drm_pos;
		tapepos_t	drm_mtpos;	/* define in stdef.h */
	}	drm_req_u;
}	drm_request_t;

#define	drm_den_req	drm_req_u.drm_den
#define	drm_open_req	drm_req_u.drm_open
#define	drm_err_req	drm_req_u.drm_err
#define	drm_mtop_req	drm_req_u.drm_mtop
#define	drm_pos_req	drm_req_u.drm_pos
#define	drm_mtpos_req	drm_req_u.drm_mtpos

#define	DRM_REQ_NEW_STAT	0x01		/* Read new status */
#define	DRM_REQ_MOVED		0x02		/* tape moved */
#define	DRM_REQ_NOTIFY_READ	0x04		/* Notify read in effect */
#define	DRM_REQ_NOTIFY_WRITE	0x08		/* Notify write in effect */

#define	DRM_REQ_NONE		0		/* No request to drm */
#define	DRM_REQ_OPEN		1
#define	DRM_REQ_CLOSE		3
#define	DRM_REQ_WRITE		4
#define	DRM_REQ_READ		5
#define	DRM_REQ_READ_TM		6
#define	DRM_REQ_READ_ERR	7
#define	DRM_REQ_WRITEERR	8
#define	DRM_REQ_MTIOCTOP	9
#define	DRM_REQ_MTGET		10
#define	DRM_REQ_WRITE0		11
#define	DRM_REQ_WRITE_ERR	12
#define	DRM_REQ_CLRERR		13
#define	DRM_REQ_BLK_LIMIT	14
#define	DRM_REQ_GET_POS		15
#define	DRM_REQ_LOCATE		16
#define	DRM_REQ_MOUNT_OPT	17
#define	DRM_REQ_GET_CAPACITY	18
#define	DRM_REQ_UPT_CAPACITY	19
#define	DRM_REQ_GET_DENSITY	20
#define	DRM_REQ_SET_DENSITY	21
#define	DRM_REQ_MTGETPOS	22
#define	DRM_REQ_MTRESTPOS	23
#define	DRM_REQ_MTIOCLTOP	24


typedef	struct	drm_mtget {
	/*
	 * This is the fixed length (32 and 64 bits) version of
	 * struct mtget used by the st driver.
	 */
	int64_t		drm_type;	/* type of magtape device */
	/* the following two registers are grossly device dependent */
	int64_t		drm_dsreg;	/* ``drive status'' register */
	int64_t		drm_erreg;	/* ``error'' register */
	/* optional error info. */
	uint64_t	drm_resid;	/* residual count */
	uint64_t	drm_fileno;	/* file number of current position */
	uint64_t	drm_blkno;	/* block number of current position */
	uint64_t	drm_blkno_dir;	/* direction */
	uint64_t	drm_mt_flags;
	int64_t		drm_mt_bf;		/* optimum blocking factor */
}	drm_mtget_t;

#define	DRM_BLKNO_DIR_MASK	((uint64_t)1 << (sizeof (daddr_t) * 8 - 1))

typedef	struct	drm_reply {
	uint64_t	drm_rep_flags;
	uint64_t	drm_rep_rc;
	union	{
		uint64_t	drm_den;
		drm_mtget_t	drm_mtget;
		drm_mtop_t	drm_mtop;
		mms_blk_limit_t drm_blk_limit;
		mms_pos_t	drm_pos;
		mms_capacity_t	drm_cap;
		tapepos_t	drm_mtpos;	/* define in stdef.h */
	}	drm_rep_u;
}	drm_reply_t;

#define	drm_den_rep		drm_rep_u.drm_den
#define	drm_mtget_rep		drm_rep_u.drm_mtget
#define	drm_mtop_rep		drm_rep_u.drm_mtop
#define	drm_blk_limit_rep	drm_rep_u.drm_blk_limit
#define	drm_pos_rep		drm_rep_u.drm_pos
#define	drm_mtpos_rep		drm_rep_u.drm_mtpos
#define	drm_cap_rep		drm_rep_u.drm_cap

#define	DRM_REP_NOTIFY_WRITE	0x01
#define	DRM_REP_NOTIFY_READ	0x02
#define	DRM_REP_EOF		0x04
#define	DRM_REP_FATAL		0x08


/*
 * IOCTL to the watcher
 */
#define	WCR_IOC		(('W' << 24) | ('C' << 16) | ('R' << 8))
#define	WCR_ADD_DEV	(WCR_IOC | 1)		/* Add a new device */

/*
 * IOCTL to the drive manager
 */

#if defined(_SYSCALL32)

typedef	struct	drm_allowed_cmds32 {
	uint64_t	drm_num;		/* number of allowed cmds */
	caddr32_t	drm_cmds;		/* pointer to cmd array */
}	drm_allowed_cmds32_t;

#define	dmd_allowed_cmds_to_allowed_cmds32(ac, ac32) {			\
		(ac32)->drm_num = (ac)->drm_num;			\
		(ac32)->drm_cmds = (caddr32_t)(uintptr_t)(ac)->drm_cmds; \
	}

#define	dmd_allowed_cmds32_to_allowed_cmds(ac32, ac) {			\
		(ac)->drm_num = (ac32)->drm_num;			\
		(ac)->drm_cmds = (caddr_t)(uintptr_t)(ac32)->drm_cmds;	\
	}

#endif	/* _SYSCALL32 */

#define	DRM_IOC		(('D' << 24) | ('R' << 16) | ('M' << 8))
typedef	enum	drm_cmd {
	DRM_BIND_DEV = DRM_IOC + 1,		/* Bind pseudo to real dev */
	DRM_REQUEST,				/* Get request from driver */
	DRM_RESUME,				/* Resume the user */
	DRM_MMS_MODE,				/* Set/unset MMS mode */
	DRM_BLKSIZE,				/* Set max blksize */
	DRM_TARG_MINOR,				/* Set target minor */
	DRM_DM_READY,				/* Rebind a device */
	DRM_REBIND_DEV,				/* Rebind a device */
	DRM_PRSV_KEY,				/* Set prsv key */
	DRM_DISALLOWED_CMDS,			/* Set disallowed scsi cmds */
	DRM_DISALLOWED_IOCTLS,			/* Set disallowed scsi ioctls */
	DRM_PROBE_DEV,				/* Probing this device */
	DRM_TDV_PID				/* Get tdv's pid */
}	drm_cmd_t;



/*
 * Struct for DRM_SET_INO
 */
typedef	struct	drm_probe_dev {
	uint64_t	drm_dev;
}	drm_probe_dev_t;



#define	DMD_FIRST_DM_MINOR	2
#define	DMD_NOT_READY		0
#define	DMD_READY		1

#define	DMD_STATE(s)		(dmd_state == (s))

#define	DMD_FIRST_DEV_ORDINAL	1


#define	DRM_DEVNAME(ordinal, devname)			\
	sprintf(devname, "%d%s", ordinal, DMD_DRM_NAME)

#define	DRM_MINOR_MASK		0xff

#define	DMD_WCR_NAME		"watcher"
#define	DMD_STAT_NAME		"stat"
#define	DMD_DRM_NAME		"drm"
#define	DMD_TDV_NAME		"tdv"

#define	DMD_WCR(inst)	(inst == 0)
#define	DMD_STAT(inst)	(inst == 1)
#define	DMD_DRM(inst)	(inst >= 2 && (inst & 1) == 0)
#define	DMD_TDV(inst)	(inst > 2 && (inst & 1) == 1)

#define	DMD_MAX_STAT	20				/* Max stat opens */

typedef	struct	dmd_stat_dev {
	uint64_t	stat_flags;
	uint64_t	stat_pid;			/* pid if opened */
	uint64_t	stat_inst;			/* instance */
	uint64_t	stat_targ_major;		/* major of target */
	uint64_t	stat_targ_minor;		/* minor of target */
	uint64_t	stat_busy_pid;			/* pid using this */
	uint64_t	stat_targ_drv;			/* target driver */
}	dmd_stat_dev_t;

/*
 * stat_flags
 */
#define	STAT_OPENED		0x01
#define	STAT_LDI_OPENED		0x02
#define	STAT_WCR		0x04
#define	STAT_DRM		0x08
#define	STAT_TDV		0x10
#define	STAT_STAT		0x20
#define	STAT_WAIT_RESUME	0x40



typedef	struct	dmd_stat_info {
	uint64_t	stat_num;			/* number of devs */
	uint64_t	stat_dmd_busy;
	dmd_stat_dev_t	stat_dev[1];			/* device status arr */
	/*
	 * When using DMD_STAT_INFO ioctl to get info, the amount of
	 * memory for the array must be large enough to hold the number
	 * of devices specified in stat_num.
	 * malloc(sizeof(dmd_stat_info_t) +
	 *	(stat_num - 1) * sizeof(dmd_stat_dev_t));
	 */
}	dmd_stat_info_t;
/*
 * DMD stat ioctl
 */
#define	DMD_STAT_INFO		1			/* get device info */
#define	DMD_STAT_CLEAR		2			/* clear all devs */
#define	DMD_STAT_NDEV		3			/* return num of dev */

/* End: 32-bit align copyin() structs for amd64 only due to 32-bit x86 ABI */
#if _LONG_LONG_ALIGNMENT == 8 && _LONG_LONG_ALIGNMENT_32 == 4
#pragma pack()
#endif

#ifdef	_KERNEL

typedef	struct	dmd_wcr {
	uint32_t	wcr_flags;
	int		wcr_inst;
	dev_info_t	*wcr_dip;		/* dev_info pointer */
	pid_t		wcr_pid;		/* pid of process that opens */
	void		*wcr_proc_ref;		/* proc_ref for dm signal */
	kmutex_t	wcr_mutex;
	pid_t		wcr_cur_pid;
}	dmd_wcr_t;

typedef	struct	dmd_stat {
	uint32_t	stat_flags;
	int		stat_inst;
	dev_info_t	*stat_dip;		/* dev_info pointer */
	void		*stat_proc_ref;		/* proc_ref for dm signal */
	kmutex_t	stat_mutex;
	int		stat_opens;		/* num of dev's opened */
	kcondvar_t	stat_opens0_cv;		/* wait opens 0 */
	pid_t		stat_pid;
	pid_t		stat_cur_pid;
}	dmd_stat_t;

typedef	struct	drm_share {
	/*
	 * Data share with tdv
	 */
	uint32_t	drm_share_flgs;
	pid_t		drm_share_pid;		/* pid of process that opens */
	ldi_ident_t	drm_share_li;		/* layered driver ident */
	ldi_handle_t	drm_share_lhdl;		/* layered driver handle */
	void		*drm_share_proc_ref;	/* proc_ref for dm signal */
	kcondvar_t	drm_share_res_cv;	/* wait for drm resume */
	int		drm_share_oflags;	/* Open flags */
	cred_t		*drm_share_cred;
	int		drm_share_otyp;		/* Open types */
	drm_request_t	drm_share_request;	/* request to drive mgr */
	drm_reply_t	drm_share_reply;	/* reply from drm */
	kmutex_t	drm_share_mutex;
	uint32_t	drm_share_max_blksize;	/* max blocksize */
	pid_t		drm_share_tdv_pid;	/* pid of tdv */
}	drm_share_t;

#define	DRM_SHR_WAIT_RESUME	0x01		/* waiting for resume */
#define	DRM_SHR_REQ_VALID	0x02		/* request is valid */
#define	DRM_SHR_OPEN_FAILED	0x04		/* Tell DM - open failed */
#define	DRM_SHR_FIXED		0x08		/* fixed format read/write */
#define	DRM_SHR_WAIT_TDV_CLOSE	0x10		/* wait for tdv to close */

typedef	struct	dmd_drm {
	uint32_t	drm_flags;
	int		drm_inst;
	dev_info_t	*drm_dip;		/* dev_info pointer */
	struct dmd_tdv	*drm_tdv;		/* target's state */
	dev_t		drm_targ_dev;		/* target's dev_t */
	pid_t		drm_busy;		/* device is busy */
	kcondvar_t	drm_busy_cv;		/* wait for not busy */
	kmutex_t	drm_mutex;
	drm_share_t	drm_share;		/* data share with tdv */
	int		drm_ioctl_mode;
	cred_t		*drm_ioctl_credp;
	pid_t		drm_cur_pid;
	uint64_t	drm_probe_dev;		/* dev being probed */
						/* must hold drm_sync_mutex */
						/* to change this field */
	struct uscsi_cmd drm_uscsi;
	char		drm_prsv_buf[24];
	char		drm_prsv_key[8];
}	dmd_drm_t;

#define	DRM_READY		0x02
#define	DRM_DEV_ADDED		0x04

#define	drm_shr_flags		drm_share.drm_share_flgs
#define	drm_shr_mutex		drm_share.drm_share_mutex
#define	drm_shr_pid		drm_share.drm_share_pid
#define	drm_shr_li		drm_share.drm_share_li
#define	drm_shr_lhdl		drm_share.drm_share_lhdl
#define	drm_shr_proc_ref	drm_share.drm_share_proc_ref
#define	drm_shr_res_cv		drm_share.drm_share_res_cv
#define	drm_shr_oflags		drm_share.drm_share_oflags
#define	drm_shr_cred		drm_share.drm_share_cred
#define	drm_shr_otyp		drm_share.drm_share_otyp
#define	drm_shr_req		drm_share.drm_share_request
#define	drm_shr_rep		drm_share.drm_share_reply
#define	drm_shr_max_blksize	drm_share.drm_share_max_blksize
#define	drm_shr_tdv_pid		drm_share.drm_share_tdv_pid


typedef	struct	dmd_tdv {
	uint32_t	tdv_flags;
	uint64_t	tdv_rdbytes;		/* Bytes read */
	uint64_t	tdv_wrbytes;		/* Bytes written */
	uint64_t	tdv_blkcnt;		/* blks written/read */
	int		tdv_inst;
	minor_t		tdv_minor;		/* target device minor */
	dev_info_t	*tdv_dip;		/* dev_info pointer */
	dmd_drm_t	*tdv_drm;		/* dm's state */
	uid_t		tdv_uid;		/* user's uid */
	uint64_t	tdv_max_blksize;	/* max blksize */
	pid_t		tdv_busy;		/* device is busy */
	kcondvar_t	tdv_busy_cv;		/* wait for not busy */
	kmutex_t	tdv_mutex;
	pid_t		tdv_cur_pid;
	uchar_t		tdv_disallowed_cmds[DMD_DISALLOWED_MASK_SIZE];
	uchar_t		tdv_disallowed_ioctls[DMD_DISALLOWED_MASK_SIZE];
}	dmd_tdv_t;

#define	TDV_BOUND		0x0002
#define	TDV_NOTIFY_WRITE	0x0004
#define	TDV_NOTIFY_READ		0x0008
#define	TDV_MMS_MODE		0x0010
#define	TDV_EOF			0x0020
#define	TDV_MOVED		0x0040		/* Tape moved since last */
						/* signaled DRM */
#define	TDV_FATAL		0x0080		/* Fatal, no movement cmd */

typedef	union	dmd_soft_state {
	dmd_wcr_t	ss_wcr;
	dmd_stat_t	ss_stat;
	dmd_drm_t	ss_drm;
	dmd_tdv_t	ss_tdv;
}	dmd_soft_state_t;


#define	DMD_BUSY()	{			\
		mutex_enter(&dmd_busy_mutex);	\
		dmd_busy++;			\
		mutex_exit(&dmd_busy_mutex);	\
	}

#define	DMD_UNBUSY()	{				\
		mutex_enter(&dmd_busy_mutex);		\
		dmd_busy--;				\
		mutex_exit(&dmd_busy_mutex);		\
	}

#define	DMD_INC_OPENS()	DMD_BUSY()
#define	DMD_DEC_OPENS()	DMD_UNBUSY()

#define	DRM_BUSY(drm) {							\
		mutex_enter(&(drm)->drm_mutex);				\
		while ((drm)->drm_busy) {	/* dev is busy */	\
			cmn_err(CE_NOTE, "DRM_BUSY: cv_wait for busy");	\
			cv_wait(&(drm)->drm_busy_cv, &(drm)->drm_mutex); \
			cmn_err(CE_NOTE, "back from cv_wait busy");	\
		}							\
		(drm)->drm_busy = ddi_get_pid();			\
		mutex_exit(&(drm)->drm_mutex);				\
	}

#define	DRM_UNBUSY(drm) {				\
		mutex_enter(&(drm)->drm_mutex);		\
		(drm)->drm_busy = 0;			\
		cv_broadcast(&(drm)->drm_busy_cv);	\
		mutex_exit(&(drm)->drm_mutex);		\
	}

#define	TDV_BUSY(tdv) {							\
		mutex_enter(&(tdv)->tdv_mutex);				\
		while ((tdv)->tdv_busy) {	/* dev is busy */	\
			cmn_err(CE_NOTE, "TDV_BUSY: cv_wait for busy");	\
			cv_wait(&(tdv)->tdv_busy_cv, &(tdv)->tdv_mutex); \
			cmn_err(CE_NOTE, "back from cv_wait busy");	\
		}							\
		(tdv)->tdv_busy = ddi_get_pid();			\
		mutex_exit(&(tdv)->tdv_mutex);				\
	}

#define	TDV_UNBUSY(tdv) {				\
		mutex_enter(&(tdv)->tdv_mutex);		\
		(tdv)->tdv_busy = 0;			\
		cv_broadcast(&(tdv)->tdv_busy_cv);	\
		mutex_exit(&(tdv)->tdv_mutex);		\
	}


#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* __DMD_IMPL_H */
