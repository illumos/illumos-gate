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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
 */

#ifndef _SATA_H
#define	_SATA_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Generic SATA Host Adapter Implementation
 */

#include <sys/types.h>
#include <sys/scsi/scsi.h>
#include <sys/scsi/impl/services.h>
#include <sys/sata/sata_defs.h>
#include <sys/sata/sata_hba.h>

/* Common flags specifying current state of a port or an attached drive. */
#define	SATA_STATE_PROBING		0x000001
#define	SATA_STATE_PROBED		0x000002

/* Statistics counters */
struct sata_port_stats {
	uint64_t	link_lost;		/* event counter */
	uint64_t	link_established;	/* event counter */
	uint64_t	device_attached;	/* event counter */
	uint64_t	device_detached;	/* event counter */
	uint64_t	port_reset;		/* event counter */
	uint64_t	port_pwr_changed;	/* event counter */
};

typedef struct sata_port_stats sata_port_stats_t;

struct sata_drive_stats {
	uint64_t	media_error;		/* available ??? */
	uint64_t	drive_reset;		/* event counter */
} sata_drv_stats_t;

typedef struct sata_drive_stats sata_drive_stats_t;

struct sata_ctrl_stats {
	uint64_t	ctrl_reset;		/* event counter */
	uint64_t	ctrl_pwr_change;	/* event counter */
};

typedef struct sata_ctrl_stats sata_ctrl_stats_t;


/*
 * SATA HBA instance info structure
 */
struct sata_hba_inst {
	dev_info_t		*satahba_dip;	/* this HBA instance devinfo */
	struct sata_hba_inst	*satahba_next;	/* ptr to next sata_hba_inst */
	struct sata_hba_inst	*satahba_prev;	/* ptr to prev sata_hba_inst */
	struct scsi_hba_tran	*satahba_scsi_tran; /* scsi_hba_tran */
	struct sata_hba_tran	*satahba_tran;	/* sata_hba_tran */
	kmutex_t		satahba_mutex;	/* sata hba cntrl mutex */
	struct taskq		*satahba_taskq;	/* cmd completion task queue */

						/*
						 * HBA event flags:
						 * SATA_EVNT_MAIN
						 * SATA_EVNT_PWR_LEVEL_CHANGED
						 * SATA_EVNT_SKIP
						 */
	uint_t			satahba_event_flags;

	struct sata_cport_info	*satahba_dev_port[SATA_MAX_CPORTS];

						/*
						 * DEVCTL open flag:
						 * SATA_DEVCTL_SOPENED
						 * SATA_DEVCTL_EXOPENED
						 */
	uint_t			satahba_open_flag; /* shared open flag */
	struct sata_ctrl_stats	satahba_stats;	/* HBA cntrl statistics */

	uint_t			satahba_attached; /* HBA attaching: */
						/* 0 - not completed */
						/* 1 - completed */
};

typedef struct sata_hba_inst	sata_hba_inst_t;

/*
 * SATA controller's device port info and state.
 * This structure is pointed to by the sata_hba_inst.satahba_dev_port[x]
 * where x is a device port number.
 * cport_state holds port state flags, defined in sata_hba.h file.
 * cport_event_flags holds SATA_EVNT_* flags defined in this file and in
 * sata_hba.h file.
 * cport_dev_type holds SATA_DTYPE_* types defined in sata_hba.h file.
 */
struct sata_cport_info {
	sata_address_t		cport_addr;	/* this port SATA address */
	kmutex_t		cport_mutex;	/* port mutex */

						/*
						 * Port state flags
						 * SATA_STATE_UNKNOWN
						 * SATA_STATE_PROBING
						 * SATA_STATE_PROBED
						 * SATA_STATE_READY
						 * SATA_PSTATE_PWRON
						 * SATA_PSTATE_PWROFF
						 * SATA_PSTATE_SHUTDOWN
						 * SATA_PSTATE_FAILED
						 */
	uint32_t		cport_state;

						/*
						 * Port event flags:
						 * SATA_EVNT_DEVICE_ATTACHED
						 * SATA_EVNT_DEVICE_DETACHED
						 * SATA_EVNT_LINK_LOST
						 * SATA_EVNT_LINK_ESTABLISHED
						 * SATA_EVNT_PORT_FAILED
						 * SATA_EVNT_PWR_LEVEL_CHANGED
						 */
	uint32_t		cport_event_flags;

	struct sata_port_scr	cport_scr;	/* Port status and ctrl regs */

						/*
						 * Attached device type:
						 * SATA_DTYPE_NONE
						 * SATA_DTYPE_ATADISK
						 * SATA_DTYPE_ATAPICD
						 * SATA_DTYPE_ATAPITAPE
						 * SATA_DTYPE_ATAPIDISK
						 * SATA_DTYPE_PMULT
						 * SATA_DTYPE_UNKNOWN
						 * SATA_DTYPE_ATAPIPROC
						 */
	uint32_t		cport_dev_type;
	union {
	    struct sata_drive_info *cport_sata_drive; /* Attached drive info */
	    struct sata_pmult_info *cport_sata_pmult; /* Attached Port Mult */
	} 			cport_devp;
						/* lbolt value at link lost */
	clock_t			cport_link_lost_time;
						/* lbolt value @ dev attached */
	clock_t			cport_dev_attach_time;

	struct sata_port_stats	cport_stats;	/* Port statistics */

	boolean_t		cport_tgtnode_clean; /* Target node usable */
};

typedef struct sata_cport_info sata_cport_info_t;

/*
 * Attached SATA drive info and state.
 * This structure is pointed to by sata_cport_info's cport_sata_drive field
 * when a drive is attached directly to a controller device port.
 */
struct sata_drive_info {
	sata_address_t	satadrv_addr;		/* this drive SATA address */

						/*
						 * Drive state flags
						 * SATA_STATE_UNKNOWN
						 * SATA_STATE_PROBING
						 * SATA_STATE_PROBED
						 * SATA_STATE_READY
						 * SATA_DSTATE_PWR_ACTIVE
						 * SATA_DSTATE_PWR_IDLE
						 * SATA_DSTATE_RESET
						 * SATA_DSTATE_FAILED
						 */
	uint32_t	satadrv_state;

						/*
						 * drive event flags:
						 * SATA_EVNT_DRIVE_RESET
						 */
	uint32_t	satadrv_event_flags;
						/*
						 * lbolt value @ start of
						 * device reset processing
						 */
	clock_t		satadrv_reset_time;
						/*
						 * Attached device type:
						 * SATA_DTYPE_ATADISK
						 * SATA_DTYPE_ATAPICD
						 * SATA_DTYPE_ATAPITAPE
						 * SATA_DTYPE_ATAPIDISK
						 * SATA_DTYPE_ATAPIPROC
						 */
	uint32_t	satadrv_type;

	uint32_t	satadrv_status_reg;	/* drive status reg */
	uint32_t	satadrv_error_reg;	/* drive error reg */
	uint16_t	satadrv_features_support; /* drive features support */
	uint16_t	satadrv_queue_depth;    /* drive queue depth */
	uint16_t	satadrv_atapi_cdb_len;	/* atapi supported cdb length */
	uint16_t	satadrv_atapi_trans_ver; /* atapi transport version */
	uint16_t	satadrv_settings;	/* drive settings flags */
	uint16_t	satadrv_features_enabled; /* drive features enabled */
	uint64_t	satadrv_capacity;	/* drive capacity */
	uint64_t	satadrv_max_queue_depth; /* maximum queue depth */
	sata_id_t	satadrv_id;		/* Device Identify Data */
	struct sata_drive_stats satadrv_stats;	/* drive statistics */

	/*
	 * saved standby timer
	 * [0] - [3] = high - low
	 */
	uint8_t		satadrv_standby_timer[4];
	uint8_t		satadrv_power_level; /* saved power level */
};

typedef struct sata_drive_info sata_drive_info_t;

_NOTE(SCHEME_PROTECTS_DATA("unshared data", sata_drive_info))


/* Port Multiplier & host port info and state */
struct sata_pmult_info {
	sata_address_t	pmult_addr;		/* this PMult SATA Address */
						/*
						 * PMult state flags
						 * SATA_STATE_UNKNOWN
						 * SATA_STATE_PROBING
						 * SATA_STATE_PROBED
						 * SATA_STATE_READY
						 * SATA_PSTATE_FAILED
						 */
	uint32_t	pmult_state;
	uint32_t	pmult_event_flags;	/* Undefined for now */
	struct sata_pmult_gscr pmult_gscr;	/* PMult GSCR block */
	uint32_t	pmult_num_dev_ports; 	/* Number of data ports */
	struct sata_pmport_info	*pmult_dev_port[SATA_MAX_PMPORTS - 1];
};

typedef	struct sata_pmult_info sata_pmult_info_t;

_NOTE(SCHEME_PROTECTS_DATA("unshared data", sata_pmult_info))
_NOTE(MUTEX_PROTECTS_DATA(sata_cport_info::cport_mutex, \
    sata_pmult_info::pmult_dev_port))

/* Port Multiplier's device port info & state */
struct sata_pmport_info {
	sata_address_t	pmport_addr;		/* this SATA port address */
	kmutex_t	pmport_mutex;		/* pmult device port mutex */

						/*
						 * Port state flags
						 * SATA_STATE_UNKNOWN
						 * SATA_STATE_PROBING
						 * SATA_STATE_PROBED
						 * SATA_STATE_READY
						 * SATA_PSTATE_PWRON
						 * SATA_PSTATE_PWROFF
						 * SATA_PSTATE_SHUTDOWN
						 * SATA_PSTATE_FAILED
						 */
	uint32_t	pmport_state;

						/*
						 * Port event flags:
						 * SATA_EVNT_DEVICE_ATTACHED
						 * SATA_EVNT_DEVICE_DETACHED
						 * SATA_EVNT_LINK_LOST
						 * SATA_EVNT_LINK_ESTABLISHED
						 * SATA_EVNT_PORT_FAILED
						 * SATA_EVNT_PWR_LEVEL_CHANGED
						 */
	uint32_t	pmport_event_flags;

	struct sata_port_scr pmport_scr;	/* PMult device port scr */

						/*
						 * Attached device type:
						 * SATA_DTYPE_NONE
						 * SATA_DTYPE_ATADISK
						 * SATA_DTYPE_ATAPICD
						 * SATA_DTYPE_ATAPITAPE
						 * SATA_DTYPE_ATAPIDISK
						 * SATA_DTYPE_UNKNOWN
						 * SATA_DTYPE_ATAPIPROC
						 */
	uint32_t	pmport_dev_type;

	struct sata_drive_info	*pmport_sata_drive; /* Attached drive info */

						/* lbolt value at link lost */
	clock_t		pmport_link_lost_time;
						/* lbolt value @ dev attached */
	clock_t		pmport_dev_attach_time;

	struct sata_port_stats	pmport_stats;	/* Port statistics */

	boolean_t	pmport_tgtnode_clean;	/* Target node usable */
};

typedef	struct sata_pmport_info sata_pmport_info_t;

/*
 * sata drive's power level
 * default value is active
 */
#define	SATA_POWER_ACTIVE	0x00
#define	SATA_POWER_IDLE		0x01
#define	SATA_POWER_STANDBY	0x02
#define	SATA_POWER_STOPPED	0x03

/*
 * pm-capable value definition according to PSARC 2009/310
 */
#define	SATA_CAP_POWER_CONDITON	PM_CAPABLE_SPC4
#define	SATA_CAP_SMART_PAGE	PM_CAPABLE_SMART_LOG
#define	SATA_CAP_LOG_SENSE	PM_CAPABLE_LOG_SUPPORTED

/*
 * Port SSTATUS register (sata_port_scr sport_sstatus field).
 * Link bits are valid only in port active state.
 */
#define	SATA_PORT_DEVLINK_UP	0x00000103	/* Link with dev established */
#define	SATA_PORT_DEVLINK_UP_MASK 0x0000010F	/* Mask for link bits */

/*
 * Port state clear mask (cport_state and pmport_state fields).
 * SATA_PSTATE_SHUTDOWN and power state are preserved.
 */
#define	SATA_PORT_STATE_CLEAR_MASK	(~(SATA_PSTATE_SHUTDOWN))

/*
 * Valid i.e.supported device types mask (cport_dev_type, satadrv_type,
 * pmult_dev_type fields).
 * ATA disks and ATAPI CD/DVD now.
 */
#define	SATA_VALID_DEV_TYPE	(SATA_DTYPE_ATADISK | \
				SATA_DTYPE_ATAPICD | \
				SATA_DTYPE_ATAPITAPE | \
				SATA_DTYPE_ATAPIDISK)

/*
 * Device feature_support (satadrv_features_support)
 */
#define	SATA_DEV_F_DMA			0x01
#define	SATA_DEV_F_LBA28		0x02
#define	SATA_DEV_F_LBA48		0x04
#define	SATA_DEV_F_NCQ			0x08
#define	SATA_DEV_F_SATA1		0x10
#define	SATA_DEV_F_SATA2		0x20
#define	SATA_DEV_F_TCQ			0x40	/* Non NCQ tagged queuing */
#define	SATA_DEV_F_SATA3		0x80

/*
 * Device features enabled (satadrv_features_enabled)
 */
#define	SATA_DEV_F_E_TAGGED_QING	0x01	/* Tagged queuing enabled */
#define	SATA_DEV_F_E_UNTAGGED_QING	0x02	/* Untagged queuing enabled */

/*
 * Drive settings flags (satdrv_settings)
 */
#define	SATA_DEV_READ_AHEAD		0x0001	/* Read Ahead enabled */
#define	SATA_DEV_WRITE_CACHE		0x0002	/* Write cache ON */
#define	SATA_DEV_DMA			0x0004	/* DMA selected */
#define	SATA_DEV_SERIAL_FEATURES 	0x8000	/* Serial ATA feat. enabled */
#define	SATA_DEV_ASYNCH_NOTIFY		0x2000	/* Asynch-event enabled */
#define	SATA_DEV_RMSN			0x0100	/* Rem Media Stat Notfc enbl */

/*
 * Internal event and flags.
 * These flags are set in the *_event_flags fields of various structures.
 * Events and lock flags defined below are used internally by the
 * SATA framework (they are not reported by SATA HBA drivers).
 */
#define	SATA_EVNT_MAIN			0x80000000
#define	SATA_EVNT_SKIP			0x40000000
#define	SATA_EVNT_INPROC_DEVICE_RESET	0x08000000
#define	SATA_EVNT_CLEAR_DEVICE_RESET	0x04000000
#define	SATA_EVNT_TARGET_NODE_CLEANUP	0x00000100
#define	SATA_EVNT_AUTOONLINE_DEVICE	0x00000200

/*
 * Lock flags - used to serialize configuration operations
 * on ports and devices.
 * SATA_EVNT_LOCK_PORT_BUSY is set by event daemon to prevent
 * simultaneous cfgadm operations.
 * SATA_APCTL_LOCK_PORT_BUSY is set by cfgadm ioctls to prevent
 * simultaneous event processing.
 */
#define	SATA_EVNT_LOCK_PORT_BUSY	0x00800000
#define	SATA_APCTL_LOCK_PORT_BUSY	0x00400000

/* Mask for port events */
#define	SATA_EVNT_PORT_EVENTS		(SATA_EVNT_DEVICE_ATTACHED | \
					SATA_EVNT_DEVICE_DETACHED | \
					SATA_EVNT_LINK_LOST | \
					SATA_EVNT_LINK_ESTABLISHED | \
					SATA_EVNT_PMULT_LINK_CHANGED | \
					SATA_EVNT_PORT_FAILED | \
					SATA_EVNT_TARGET_NODE_CLEANUP | \
					SATA_EVNT_AUTOONLINE_DEVICE)
/* Mask for drive events */
#define	SATA_EVNT_DRIVE_EVENTS		(SATA_EVNT_DEVICE_RESET | \
					SATA_EVNT_INPROC_DEVICE_RESET)
#define	SATA_EVNT_CONTROLLER_EVENTS	SATA_EVNT_PWR_LEVEL_CHANGED

/* Delays and timeout duration definitions */
#define	SATA_EVNT_DAEMON_SLEEP_TIME	50000	/* 50 ms */
#define	SATA_EVNT_DAEMON_TERM_TIMEOUT	100000	/* 100 ms */
#define	SATA_EVNT_DAEMON_TERM_WAIT	60000000 /* 60 s */
#define	SATA_EVNT_LINK_LOST_TIMEOUT	1000000	/* 1 s */

#define	SATA_DEV_IDENTIFY_TIMEOUT	60000000 /* 60 s, device enumeration */
#define	SATA_DEV_REPROBE_TIMEOUT	30000000  /* 30 s, dev resp after rst */
#define	SATA_DEV_RETRY_DLY		10000	/* 10 ms */

/* DEVICE IDENTIFY and device initialization retry delay */
#define	SATA_DEV_IDENTIFY_RETRY		1
#define	SATA_DEV_IDENTIFY_NORETRY	0

/*
 * sata_scsi's hba_open_flag: field indicating open devctl instance.
 *	0 = closed, 1 = shared open, 2 = exclusive open.
 */
#define	SATA_DEVCTL_CLOSED	0
#define	SATA_DEVCTL_SOPENED	1
#define	SATA_DEVCTL_EXOPENED	2

/*
 * sata_pkt_txlate structure contains info about resources allocated
 * for the packet
 * Address of this structure is stored in scsi_pkt.pkt_ha_private and
 * in sata_pkt.sata_hba_private fields, so all three strucures are
 * cross-linked, with sata_pkt_txlate as a centerpiece.
 */

typedef struct sata_pkt_txlate {
	struct sata_hba_inst	*txlt_sata_hba_inst;
	struct scsi_pkt		*txlt_scsi_pkt;
	struct sata_pkt		*txlt_sata_pkt;
	ddi_dma_handle_t	txlt_buf_dma_handle;
	uint_t			txlt_flags;	/* data-in / data-out */
	uint_t			txlt_num_dma_win; /* number of DMA windows */
	uint_t			txlt_cur_dma_win; /* current DMA window */

				/* cookies in the current DMA window */
	uint_t			txlt_curwin_num_dma_cookies;

				/* processed dma cookies in current DMA win */
	uint_t			txlt_curwin_processed_dma_cookies;
	size_t			txlt_total_residue;
	ddi_dma_cookie_t	txlt_dma_cookie; /* default dma cookie */
	int			txlt_dma_cookie_list_len; /* alloc list len */
	ddi_dma_cookie_t 	*txlt_dma_cookie_list; /* dma cookie list */
	int			txlt_num_dma_cookies; /* dma cookies in list */

				/* temporary buffer access handle */
	ddi_acc_handle_t	txlt_tmp_buf_handle;
	caddr_t			txlt_tmp_buf;	/* temp buffer address */
} sata_pkt_txlate_t;

_NOTE(SCHEME_PROTECTS_DATA("unshared data", sata_pkt_txlate))
_NOTE(SCHEME_PROTECTS_DATA("unshared data", scsi_pkt))

/* Length of largest sense buffer used by sata */
#define	SATA_MAX_SENSE_LEN	MAX(sizeof (struct scsi_arq_status), \
    sizeof (struct scsi_arq_status) - sizeof (struct scsi_extended_sense) + \
    sizeof (struct scsi_descr_sense_hdr) + \
    MAX(sizeof (struct scsi_cmd_specific_sense_descr), \
    sizeof (struct scsi_ata_status_ret_sense_descr)))

/*
 * Sense Data structure for ATA Pass Through
 * This is the entire sense data block passed back up to scsi.  It is
 * effectively the scsi_arq_status structure for ATA Sense Return descriptor
 * format sense data.
 */
struct sata_apt_sense_data {
	struct scsi_status				apt_status;
	struct scsi_status				apt_rqpkt_status;
	uchar_t						apt_rqpkt_reason;
	uchar_t						apt_rqpkt_resid;
	uint_t						apt_rqpkt_state;
	uint_t						apt_rqpkt_statistics;
	struct scsi_descr_sense_hdr			apt_sd_hdr;
	struct scsi_ata_status_ret_sense_descr		apt_sd_sense;
};


/*
 * Additional scsi sense code definitions.
 * These definition should eventually be moved to scsi header file
 * usr/src/uts/common/sys/scsi/generic/sense.h
 */
#define	SD_SCSI_ASC_NO_ADD_SENSE			0x00
#define	SD_SCSI_ASC_ATP_INFO_AVAIL			0x00
#define	SD_SCSI_ASC_LU_NOT_READY			0x04
#define	SD_SCSI_ASC_LU_NOT_RESPONSE			0x05
#define	SD_SCSI_ASC_WRITE_ERR				0x0c
#define	SD_SCSI_ASC_UNREC_READ_ERR			0x11
#define	SD_SCSI_ASC_INVALID_COMMAND_CODE		0x20
#define	SD_SCSI_ASC_LBA_OUT_OF_RANGE			0x21
#define	SD_SCSI_ASC_INVALID_FIELD_IN_CDB		0x24
#define	SD_SCSI_ASC_INVALID_FIELD_IN_PARAMS_LIST	0x26
#define	SD_SCSI_ASC_WRITE_PROTECTED			0x27
#define	SD_SCSI_ASC_MEDIUM_MAY_HAVE_CHANGED		0x28
#define	SD_SCSI_ASC_RESET				0x29
#define	SD_SCSI_ASC_CMD_SEQUENCE_ERR			0x2c
#define	SD_SCSI_ASC_MEDIUM_NOT_PRESENT			0x3a
#define	SD_SCSI_ASC_SAVING_PARAMS_NOT_SUPPORTED		0x39
#define	SD_SCSI_ASC_INTERNAL_TARGET_FAILURE		0x44
#define	SD_SCSI_ASC_INFO_UNIT_IUCRC_ERR			0x47
#define	SD_SCSI_ASC_OP_MEDIUM_REM_REQ			0x5a
#define	SD_SCSI_ASC_LOW_POWER_CONDITION_ON		0x5e


/* SCSI defs missing from scsi headers */
/* Missing from sys/scsi/generic/commands.h */
#define	SCMD_SYNCHRONIZE_CACHE_G1		0x91
/*
 * Missing from sys/scsi/impl/mode.h, although defined
 * in sys/scsi/targets/sddefs.h as MODEPAGE_ERR_RECOV
 */
#define	MODEPAGE_RW_ERRRECOV			0x01 /* read/write recovery */
/* Missing from sys/scsi/impl/commands.h */
#define	SCSI_READ_CAPACITY16_MAX_LBA		0xfffffffffffffffe

/*
 * medium access command
 */
#define	SATA_IS_MEDIUM_ACCESS_CMD(cmd) \
	(((cmd) == SCMD_READ) || ((cmd) == SCMD_WRITE) || \
	((cmd) == SCMD_READ_G1) || ((cmd) == SCMD_WRITE_G1) || \
	((cmd) == SCMD_READ_G4) || ((cmd) == SCMD_WRITE_G4) || \
	((cmd) == SCMD_READ_G5) || ((cmd) == SCMD_WRITE_G5) || \
	((cmd) == SCMD_VERIFY) || ((cmd) == SCMD_VERIFY_G4) || \
	((cmd) == SCMD_VERIFY_G5) || ((cmd) == 0x7f) /* VERIFY(32) */|| \
	((cmd) == SCMD_SYNCHRONIZE_CACHE) || ((cmd) == SCMD_SPACE_G4) || \
	((cmd) == SCMD_READ_POSITION) || \
	((cmd) == 0x90) /* PRE-FETCH(16) */ || \
	((cmd) == SCMD_READ_DEFECT_LIST) || \
	((cmd) == 0xb7) /* READ DEFECT DATA */ || \
	((cmd) == SCMD_READ_LONG) || ((cmd) == SCMD_SVC_ACTION_IN_G4) || \
	((cmd) == SCMD_WRITE_LONG) || ((cmd) == SCMD_SVC_ACTION_OUT_G4) || \
	((cmd) == 0x41) || ((cmd) == 0x93) || /* WRITE SAME */ \
	((cmd) == 0x52) || ((cmd) == 0x50) || /* XDREAD & XDWRITE */ \
	((cmd) == 0x53) || ((cmd) == 0x51) || /* XDWRITEREAD & XPWRITE */ \
	((cmd) == 0x7f))

/*
 * Macros for accessing various structure fields
 */

#define	SATA_TRAN(sata_hba_inst) \
	sata_hba_inst->satahba_tran

#define	SATA_DIP(sata_hba_inst) \
	sata_hba_inst->satahba_dip

#define	SATA_NUM_CPORTS(sata_hba_inst) \
	sata_hba_inst->satahba_tran->sata_tran_hba_num_cports

#define	SATA_QDEPTH(sata_hba_inst) \
	sata_hba_inst->satahba_tran->sata_tran_hba_qdepth

#define	SATA_FEATURES(sata_hba_inst) \
	sata_hba_inst->satahba_tran->sata_tran_hba_features_support

#define	SATA_DMA_ATTR(sata_hba_inst) \
	sata_hba_inst->satahba_tran->sata_tran_hba_dma_attr

#define	SATA_START_FUNC(sata_hba_inst) \
	sata_hba_inst->satahba_tran->sata_tran_start

#define	SATA_ABORT_FUNC(sata_hba_inst) \
	sata_hba_inst->satahba_tran->sata_tran_abort

#define	SATA_RESET_DPORT_FUNC(sata_hba_inst) \
	sata_hba_inst->satahba_tran->sata_tran_reset_dport

#define	SATA_PORT_DEACTIVATE_FUNC(sata_hba_inst) \
	(sata_hba_inst->satahba_tran->sata_tran_hotplug_ops == NULL ? \
	NULL : \
	sata_hba_inst->satahba_tran->sata_tran_hotplug_ops->\
	sata_tran_port_deactivate)

#define	SATA_PORT_ACTIVATE_FUNC(sata_hba_inst) \
	(sata_hba_inst->satahba_tran->sata_tran_hotplug_ops == NULL ? \
	NULL : \
	sata_hba_inst->satahba_tran->sata_tran_hotplug_ops->\
	sata_tran_port_activate)

#define	SATA_PROBE_PORT_FUNC(sata_hba_inst) \
	sata_hba_inst->satahba_tran->sata_tran_probe_port

#define	SATA_SELFTEST_FUNC(sata_hba_inst) \
	sata_hba_inst->satahba_tran->sata_tran_selftest

#define	SATA_CPORT_MUTEX(sata_hba_inst, cport) \
	sata_hba_inst->satahba_dev_port[cport]->cport_mutex

#define	SATA_CPORT_INFO(sata_hba_inst, cport) \
	sata_hba_inst->satahba_dev_port[cport]

#define	SATA_CPORT_STATE(sata_hba_inst, cport) \
	sata_hba_inst->satahba_dev_port[cport]->cport_state

#define	SATA_CPORT_EVENT_FLAGS(sata_hba_inst, cport) \
	sata_hba_inst->satahba_dev_port[cport]->cport_event_flags

#define	SATA_CPORT_SCR(sata_hba_inst, cport) \
	sata_hba_inst->satahba_dev_port[cport]->cport_scr

#define	SATA_CPORT_DEV_TYPE(sata_hba_inst, cport) \
	sata_hba_inst->satahba_dev_port[cport]->cport_dev_type

#define	SATA_CPORT_DRV_INFO(sata_hba_inst, cport) \
	sata_hba_inst->satahba_dev_port[cport]->cport_devp.cport_sata_drive

#define	SATA_CPORTINFO_DRV_TYPE(cportinfo) \
	cportinfo->cport_dev_type

#define	SATA_CPORTINFO_DRV_INFO(cportinfo) \
	cportinfo->cport_devp.cport_sata_drive

#define	SATA_CPORTINFO_PMULT_INFO(cportinfo) \
	cportinfo->cport_devp.cport_sata_pmult

#define	SATA_PMULT_INFO(sata_hba_inst, cport) \
	sata_hba_inst->satahba_dev_port[cport]->cport_devp.cport_sata_pmult

#define	SATA_NUM_PMPORTS(sata_hba_inst, cport) \
	sata_hba_inst->satahba_dev_port[cport]->\
	cport_devp.cport_sata_pmult->pmult_num_dev_ports

#define	SATA_PMPORT_MUTEX(sata_hba_inst, cport, pmport) \
	sata_hba_inst->satahba_dev_port[cport]->\
	cport_devp.cport_sata_pmult->pmult_dev_port[pmport]->pmport_mutex

#define	SATA_PMPORT_INFO(sata_hba_inst, cport, pmport) \
	sata_hba_inst->satahba_dev_port[cport]->\
	cport_devp.cport_sata_pmult->pmult_dev_port[pmport]

#define	SATA_PMPORT_DRV_INFO(sata_hba_inst, cport, pmport) \
	sata_hba_inst->satahba_dev_port[cport]->\
	cport_devp.cport_sata_pmult->pmult_dev_port[pmport]->\
	pmport_sata_drive

#define	SATA_PMPORT_STATE(sata_hba_inst, cport, pmport) \
	sata_hba_inst->satahba_dev_port[cport]->\
	cport_devp.cport_sata_pmult->pmult_dev_port[pmport]->pmport_state

#define	SATA_PMPORT_SCR(sata_hba_inst, cport, pmport) \
	sata_hba_inst->satahba_dev_port[cport]->\
	cport_devp.cport_sata_pmult->pmult_dev_port[pmport]->pmport_scr

#define	SATA_PMPORT_DEV_TYPE(sata_hba_inst, cport, pmport) \
	sata_hba_inst->satahba_dev_port[cport]->\
	cport_devp.cport_sata_pmult->pmult_dev_port[pmport]->pmport_dev_type

#define	SATA_PMPORT_EVENT_FLAGS(sata_hba_inst, cport, pmport) \
	sata_hba_inst->satahba_dev_port[cport]->\
	cport_devp.cport_sata_pmult->pmult_dev_port[pmport]->\
	pmport_event_flags

#define	SATA_PMPORTINFO_DRV_TYPE(pmportinfo) \
	pmportinfo->pmport_dev_type

#define	SATA_PMPORTINFO_DRV_INFO(pmportinfo) \
	pmportinfo->pmport_sata_drive

#define	SATA_TXLT_HBA_INST(spx) \
	spx->txlt_sata_hba_inst

#define	SATA_TXLT_CPORT(spx) \
	spx->txlt_sata_pkt->satapkt_device.satadev_addr.cport

#define	SATA_TXLT_PMPORT(spx) \
	spx->txlt_sata_pkt->satapkt_device.satadev_addr.pmport

#define	SATA_TXLT_QUAL(spx) \
	spx->txlt_sata_pkt->satapkt_device.satadev_addr.qual

#define	SATA_TXLT_CPORT_MUTEX(spx) \
	spx->txlt_sata_hba_inst->\
	satahba_dev_port[spx->txlt_sata_pkt->\
	satapkt_device.satadev_addr.cport]->cport_mutex

#define	SATA_TXLT_TASKQ(spx) \
	spx->txlt_sata_hba_inst->\
	satahba_taskq

/*
 * Minor number construction for devctl and attachment point nodes.
 * All necessary information has to be encoded in NBITSMINOR32 bits.
 *
 * Devctl node minor number:
 * ((controller_instance << SATA_CNTRL_INSTANCE_SHIFT) | SATA_DEVCTL_NODE)
 *
 * Attachment point node minor number has to include controller
 * instance (7 bits), controller port number (5 bits) and port multiplier
 * device port number (4 bits) and port multiplier device port
 * indicator (1 bit).  Additionally, a single bit is used to
 * differentiate between attachment point node and device control node.
 *
 * Attachment point minor number:
 * ((controller_instance << SATA_CNTRL_INSTANCE_SHIFT) | SATA_AP_NODE |
 * [(port_multiplier_device_port << SATA_PMULT_PORT_SHIFT) | SATA_PMULT_AP] |
 * (controller_port))
 *
 * 17 bits are used (if 64 instances of controllers are expected)
 * bit 18 is reserved for future use.
 *
 *   --------------------------------------------------------
 *   |17|16|15|14|13|12|11|10 |09|08|07|06|05|04|03|02|01|00|
 *   --------------------------------------------------------
 *   | R| c| c| c| c| c| c|a/d|pm|pp|pp|pp|pp|cp|cp|cp|cp|cp|
 *   --------------------------------------------------------
 * Where:
 * cp  - device port number on the HBA SATA controller
 * pp  - device port number on the port multiplier
 * pm  - 0 - target attached to controller device port
 *       1 - target attached to port multiplier's device port
 * a/d - 0 - devctl node
 *       1 - attachment point node
 * c   - controller number
 * R   - reserved bit
 */

#define	SATA_AP_NODE		0x400		/* Attachment Point node */
#define	SATA_DEVCTL_NODE	0x000		/* DEVCTL node */
#define	SATA_PMULT_AP		0x200		/* device on PMult port */
#define	SATA_PMULT_PORT_SHIFT	5
#define	SATA_CNTRL_INSTANCE_SHIFT 11
#define	SATA_CPORT_MASK		0x1f		/* 32 device ports */
#define	SATA_PMULT_PORT_MASK	0xf		/* 15 device ports */
#define	SATA_CNTRL_INSTANCE_MASK 0x03F		/* 64 controllers */

/* Macro for creating devctl node minor number */
#define	SATA_MAKE_DEVCTL_MINOR(controller_instance) \
	((controller_instance << SATA_CNTRL_INSTANCE_SHIFT) | \
	SATA_DEVCTL_NODE)

/* Macro for creating an attachment point node minor number */
#define	SATA_MAKE_AP_MINOR(cntrl_instance, cport, pmport, qual) \
	(qual & (SATA_ADDR_PMPORT | SATA_ADDR_DPMPORT) ? \
	(((cntrl_instance) << SATA_CNTRL_INSTANCE_SHIFT) | \
	SATA_AP_NODE | SATA_PMULT_AP | \
	(pmport << SATA_PMULT_PORT_SHIFT) | cport) : \
	(((cntrl_instance) << SATA_CNTRL_INSTANCE_SHIFT) | \
	SATA_AP_NODE | cport))

/* Macro retrieving controller number from a minor number */
#define	SATA_MINOR2INSTANCE(minor) \
	((minor >> SATA_CNTRL_INSTANCE_SHIFT) & SATA_CNTRL_INSTANCE_MASK)

/*
 * Macro for creating an attachment point number from sata address.
 * Address qualifier has to be one of:
 * SATA_ADDR_DCPORT, SATA_ADDR_DPMPORT, SATA_ADDR_CPORT or SATA_ADDR_PMPORT
 */
#define	SATA_MAKE_AP_NUMBER(cport, pmport, qual) \
	((qual & (SATA_ADDR_PMPORT | SATA_ADDR_DPMPORT)) ? \
	(SATA_PMULT_AP | (pmport << SATA_PMULT_PORT_SHIFT) | cport) : \
	(cport))

/*
 * SCSI target number format
 *
 *   -------------------------------
 *   | 9| 8| 7| 6| 5| 4| 3| 2| 1| 0|    Bit number
 *   -------------------------------
 *   |pm|pp|pp|pp|pp|cp|cp|cp|cp|cp|
 *   -------------------------------
 * Where:
 * cp  - device port number on the HBA SATA controller
 * pp  - device port number on the port multiplier
 * pm  - 0 - target attached to controller device port
 *       1 - target attached to port multiplier's device port
 */

/* SATA ports to SCSI target number translation */

#define	SATA_TO_SCSI_TARGET(cport, pmport, qual) \
	(qual == SATA_ADDR_DCPORT ? cport : \
	(cport | (pmport << SATA_PMULT_PORT_SHIFT) | SATA_PMULT_AP))

/* SCSI target number to SATA cntrl/pmport/cport translations */
#define	SCSI_TO_SATA_CPORT(scsi_target) \
	(scsi_target & SATA_CPORT_MASK)

#define	SCSI_TO_SATA_PMPORT(scsi_target) \
	((scsi_target >> SATA_PMULT_PORT_SHIFT) & SATA_PMULT_PORT_MASK)

#define	SCSI_TO_SATA_ADDR_QUAL(scsi_target) \
	((scsi_target & SATA_PMULT_AP) ? SATA_ADDR_DPMPORT : \
	SATA_ADDR_DCPORT)


/* Debug flags */
#if	DEBUG

#define	SATA_DEBUG
#define	SATA_DBG_SCSI_IF	1
#define	SATA_DBG_HBA_IF		2
#define	SATA_DBG_NODES		4
#define	SATA_DBG_IOCTL_IF	8
#define	SATA_DBG_EVENTS		0x10
#define	SATA_DBG_EVENTS_PROC	0x20
#define	SATA_DBG_EVENTS_PROCPST	0x40
#define	SATA_DBG_EVENTS_CNTRL	0x80
#define	SATA_DBG_EVENTS_DAEMON	0x100
#define	SATA_DBG_DMA_SETUP	0x400
#define	SATA_DBG_DEV_SETTINGS	0x800
#define	SATA_DBG_ATAPI		0x1000
#define	SATA_DBG_ATAPI_PACKET	0x8000
#define	SATA_DBG_INTR_CTX	0x10000
#define	SATA_DBG_PMULT		0x20000

typedef struct sata_atapi_cmd {
	uint8_t acdb[SATA_ATAPI_MAX_CDB_LEN];
	uint8_t arqs[SATA_ATAPI_RQSENSE_LEN];
	uint_t sata_pkt_reason;
	uint_t scsi_pkt_reason;
} sata_atapi_cmd_t;

/* Debug macros */
#define	SATADBG1(flag, sata, format, arg1) \
	if (sata_debug_flags & (flag)) { \
		sata_log(sata, CE_CONT, format, arg1); \
	}

#define	SATADBG2(flag, sata, format, arg1, arg2) \
	if (sata_debug_flags & (flag)) { \
		sata_log(sata, CE_CONT, format, arg1, arg2); \
	}

#define	SATADBG3(flag, sata, format, arg1, arg2, arg3) \
	if (sata_debug_flags & (flag)) { \
		sata_log(sata, CE_CONT, format, arg1, arg2, arg3); \
	}
#else

#define	SATADBG1(flag, dip, frmt, arg1)
#define	SATADBG2(flag, dip, frmt, arg1, arg2)
#define	SATADBG3(flag, dip, frmt, arg1, arg2, arg3)

#endif

/* sata_rev_tag 1.46 */

#ifdef	__cplusplus
}
#endif

#endif /* _SATA_H */
