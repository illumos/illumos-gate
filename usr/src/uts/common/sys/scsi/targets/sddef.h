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
 * Copyright (c) 1990, 2010, Oracle and/or its affiliates. All rights reserved.
 */
/*
 * Copyright 2011 cyril.galibern@opensvc.com
 * Copyright 2015 Nexenta Systems, Inc.  All rights reserved.
 */

#ifndef	_SYS_SCSI_TARGETS_SDDEF_H
#define	_SYS_SCSI_TARGETS_SDDEF_H

#include <sys/dktp/fdisk.h>
#include <sys/note.h>
#include <sys/mhd.h>
#include <sys/cmlb.h>

#ifdef	__cplusplus
extern "C" {
#endif


#if defined(_KERNEL) || defined(_KMEMUSER)


#define	SD_SUCCESS		0
#define	SD_FAILURE		(-1)

#if defined(TRUE)
#undef TRUE
#endif

#if defined(FALSE)
#undef FALSE
#endif

#define	TRUE			1
#define	FALSE			0

#if defined(VERBOSE)
#undef VERBOSE
#endif

#if defined(SILENT)
#undef SILENT
#endif


/*
 *  Fault Injection Flag for Inclusion of Code
 *
 *  This should only be defined when SDDEBUG is defined
 * #if DEBUG || lint
 * #define	SD_FAULT_INJECTION
 * #endif
 */

#if DEBUG || lint
#define	SD_FAULT_INJECTION
#endif
#define	VERBOSE			1
#define	SILENT			0

/*
 * Structures for recording whether a device is fully open or closed.
 * Assumptions:
 *
 *	+ There are only 8 (sparc) or 16 (x86) disk slices possible.
 *	+ BLK, MNT, CHR, SWP don't change in some future release!
 */

#if defined(_SUNOS_VTOC_8)

#define	SDUNIT_SHIFT	3
#define	SDPART_MASK	7
#define	NSDMAP		NDKMAP

#elif defined(_SUNOS_VTOC_16)

/*
 * XXX - NSDMAP has multiple definitions, one more in cmlb_impl.h
 * If they are coalesced into one, this definition will follow suit.
 * FDISK partitions - 4 primary and MAX_EXT_PARTS number of Extended
 * Partitions.
 */
#define	FDISK_PARTS		(FD_NUMPART + MAX_EXT_PARTS)

#define	SDUNIT_SHIFT	6
#define	SDPART_MASK	63
#define	NSDMAP		(NDKMAP + FDISK_PARTS + 1)

#else
#error "No VTOC format defined."
#endif


#define	SDUNIT(dev)	(getminor((dev)) >> SDUNIT_SHIFT)
#define	SDPART(dev)	(getminor((dev)) &  SDPART_MASK)

/*
 * maximum number of partitions the driver keeps track of; with
 * EFI this can be larger than the number of partitions accessible
 * through the minor nodes.  It won't be used for keeping track
 * of open counts, partition kstats, etc.
 */
#define	MAXPART		(NSDMAP + 1)

/*
 * Macro to retrieve the DDI instance number from the given buf struct.
 * The instance number is encoded in the minor device number.
 */
#define	SD_GET_INSTANCE_FROM_BUF(bp)				\
	(getminor((bp)->b_edev) >> SDUNIT_SHIFT)



struct ocinfo {
	/*
	 * Types BLK, MNT, CHR, SWP,
	 * assumed to be types 0-3.
	 */
	uint64_t  lyr_open[NSDMAP];
	uint64_t  reg_open[OTYPCNT - 1];
};

#define	OCSIZE  sizeof (struct ocinfo)

union ocmap {
	uchar_t chkd[OCSIZE];
	struct ocinfo rinfo;
};

#define	lyropen rinfo.lyr_open
#define	regopen rinfo.reg_open


#define	SD_CDB_GROUP0		0
#define	SD_CDB_GROUP1		1
#define	SD_CDB_GROUP5		2
#define	SD_CDB_GROUP4		3

struct sd_cdbinfo {
	uchar_t	 sc_grpcode;	/* CDB group code */
	uchar_t  sc_grpmask;	/* CDB group code mask (for cmd opcode) */
	uint64_t sc_maxlba;	/* Maximum logical block addr. supported */
	uint32_t sc_maxlen;	/* Maximum transfer length supported */
};



/*
 * The following declaration are for Non-512 byte block support for the
 * removable devices. (ex - DVD RAM, MO).
 * wm_state: This is an enumeration for the different states for
 * manipalating write range list during the read-modify-write-operation.
 */
typedef enum {
	SD_WM_CHK_LIST,		/* Check list for overlapping writes */
	SD_WM_WAIT_MAP,		/* Wait for an overlapping I/O to complete */
	SD_WM_LOCK_RANGE,	/* Lock the range of lba to be written */
	SD_WM_DONE		/* I/O complete */
} wm_state;

/*
 * sd_w_map: Every write I/O will get one w_map allocated for it which will tell
 * the range on the media which is being written for that request.
 */
struct sd_w_map {
	uint_t		wm_start;	/* Write start location */
	uint_t		wm_end;		/* Write end location */
	ushort_t	wm_flags;	/* State of the wmap */
	ushort_t	wm_wanted_count; /* # of threads waiting for region */
	void		*wm_private;	/* Used to store bp->b_private */
	struct buf	*wm_bufp;	/* to store buf pointer */
	struct sd_w_map	*wm_next;	/* Forward pointed to sd_w_map */
	struct sd_w_map	*wm_prev;	/* Back pointer to sd_w_map */
	kcondvar_t	wm_avail;	/* Sleep on this, while not available */
};

_NOTE(MUTEX_PROTECTS_DATA(scsi_device::sd_mutex, sd_w_map::wm_flags))


/*
 * This is the struct for the layer-private data area for the
 * mapblocksize layer.
 */

struct sd_mapblocksize_info {
	void		*mbs_oprivate;	/* saved value of xb_private */
	struct buf	*mbs_orig_bp;	/* ptr to original bp */
	struct sd_w_map	*mbs_wmp;	/* ptr to write-map struct for RMW */
	ssize_t		mbs_copy_offset;
	int		mbs_layer_index;	/* chain index for RMW */
};

_NOTE(SCHEME_PROTECTS_DATA("unshared data", sd_mapblocksize_info))


/*
 * sd_lun: The main data structure for a scsi logical unit.
 * Stored as the softstate structure for each device.
 */

struct sd_lun {

	/* Back ptr to the SCSA scsi_device struct for this LUN */
	struct scsi_device	*un_sd;

	/*
	 * Support for Auto-Request sense capability
	 */
	struct buf	*un_rqs_bp;	/* ptr to request sense bp */
	struct scsi_pkt	*un_rqs_pktp;	/* ptr to request sense scsi_pkt */
	int	un_sense_isbusy;	/* Busy flag for RQS buf */

	/*
	 * These specify the layering chains to use with this instance. These
	 * are initialized according to the values in the sd_chain_index_map[]
	 * array. See the description of sd_chain_index_map[] for details.
	 */
	int un_buf_chain_type;
	int un_uscsi_chain_type;
	int un_direct_chain_type;
	int un_priority_chain_type;

	/* Head & tail ptrs to the queue of bufs awaiting transport */
	struct buf	*un_waitq_headp;
	struct buf	*un_waitq_tailp;

	/* Ptr to the buf currently being retried (NULL if none) */
	struct buf	*un_retry_bp;

	/* This tracks the last kstat update for the un_retry_bp buf */
	void		(*un_retry_statp)(kstat_io_t *);

	void		*un_xbuf_attr;	/* xbuf attribute struct */


	/* System logical block size, in bytes. (defaults to DEV_BSIZE.) */
	uint32_t	un_sys_blocksize;

	/* The size of a logical block on the target, in bytes. */
	uint32_t	un_tgt_blocksize;

	/* The size of a physical block on the target, in bytes. */
	uint32_t	un_phy_blocksize;

	/*
	 * The number of logical blocks on the target. This is adjusted
	 * to be in terms of the block size specified by un_sys_blocksize
	 * (ie, the system block size).
	 */
	uint64_t	un_blockcount;

	/*
	 * Various configuration data
	 */
	uchar_t	un_ctype;		/* Controller type */
	char 	*un_node_type;		/* minor node type */
	uchar_t	un_interconnect_type;	/* Interconnect for underlying HBA */

	uint_t	un_notready_retry_count; /* Per disk notready retry count */
	uint_t	un_busy_retry_count;	/* Per disk BUSY retry count */

	uint_t	un_retry_count;		/* Per disk retry count */
	uint_t	un_victim_retry_count;	/* Per disk victim retry count */

	/* (4356701, 4367306) */
	uint_t	un_reset_retry_count; /* max io retries before issuing reset */
	ushort_t un_reserve_release_time; /* reservation release timeout */

	uchar_t	un_reservation_type;	/* SCSI-3 or SCSI-2 */
	uint_t	un_max_xfer_size;	/* Maximum DMA transfer size */
	int	un_partial_dma_supported;
	int	un_buf_breakup_supported;

	int	un_mincdb;		/* Smallest CDB to use */
	int	un_maxcdb;		/* Largest CDB to use */
	int	un_max_hba_cdb;		/* Largest CDB supported by HBA */
	int	un_status_len;
	int	un_pkt_flags;

	/*
	 * Note: un_uscsi_timeout is a "mirror" of un_cmd_timeout, adjusted
	 * for ISCD().  Any updates to un_cmd_timeout MUST be reflected
	 * in un_uscsi_timeout as well!
	 */
	ushort_t un_cmd_timeout;	/* Timeout for completion */
	ushort_t un_uscsi_timeout;	/* Timeout for USCSI completion */
	ushort_t un_busy_timeout;	/* Timeout for busy retry */

	/*
	 * Info on current states, statuses, etc. (Updated frequently)
	 */
	uchar_t	un_state;		/* current state */
	uchar_t	un_last_state;		/* last state */
	uchar_t	un_last_pkt_reason;	/* used to suppress multiple msgs */
	int	un_tagflags;		/* Pkt Flags for Tagged Queueing  */
	short	un_resvd_status;	/* Reservation Status */
	ulong_t	un_detach_count;	/* !0 if executing detach routine */
	ulong_t	un_layer_count;		/* Current total # of layered opens */
	ulong_t un_opens_in_progress;	/* Current # of threads in sdopen */

	ksema_t	un_semoclose;		/* serialize opens/closes */

	/*
	 * Control & status info for command throttling
	 */
	long	un_ncmds_in_driver;	/* number of cmds in driver */
	short	un_ncmds_in_transport;	/* number of cmds in transport */
	short	un_throttle;		/* max #cmds allowed in transport */
	short	un_saved_throttle;	/* saved value of un_throttle */
	short	un_busy_throttle;	/* saved un_throttle for BUSY */
	short	un_min_throttle;	/* min value of un_throttle */
	timeout_id_t	un_reset_throttle_timeid; /* timeout(9F) handle */

	/*
	 * Multi-host (clustering) support
	 */
	opaque_t	un_mhd_token;		/* scsi watch request */
	timeout_id_t	un_resvd_timeid;	/* for resvd recover */

	/* Event callback resources (photon) */
	ddi_eventcookie_t un_insert_event;	/* insert event */
	ddi_callback_id_t un_insert_cb_id;	/* insert callback */
	ddi_eventcookie_t un_remove_event;	/* remove event */
	ddi_callback_id_t un_remove_cb_id;	/* remove callback */

	uint_t		un_start_stop_cycle_page;	/* Saves start/stop */
							/* cycle page */
	timeout_id_t	un_dcvb_timeid;		/* dlyd cv broadcast */

	/*
	 * Data structures for open counts, partition info, VTOC,
	 * stats, and other such bookkeeping info.
	 */
	union	ocmap	un_ocmap;		/* open partition map */
	struct	kstat	*un_pstats[NSDMAP];	/* partition statistics */
	struct	kstat	*un_stats;		/* disk statistics */
	kstat_t		*un_errstats;		/* for error statistics */
	uint64_t	un_exclopen;		/* exclusive open bitmask */
	ddi_devid_t	un_devid;		/* device id */
	uint_t		un_vpd_page_mask;	/* Supported VPD pages */

	/*
	 * Bit fields for various configuration/state/status info.
	 * Comments indicate the condition if the value of the
	 * variable is TRUE (nonzero).
	 */
	uint32_t
	    un_f_arq_enabled		:1,	/* Auto request sense is */
						/* currently enabled */
	    un_f_blockcount_is_valid	:1,	/* The un_blockcount */
						/* value is currently valid */
	    un_f_tgt_blocksize_is_valid	:1,	/* The un_tgt_blocksize */
						/* value is currently valid */
	    un_f_allow_bus_device_reset	:1,	/* Driver may issue a BDR as */
						/* a part of error recovery. */
	    un_f_is_fibre		:1,	/* The device supports fibre */
						/* channel */
	    un_f_sync_cache_supported	:1,	/* sync cache cmd supported */
						/* supported */
	    un_f_format_in_progress	:1,	/* The device is currently */
						/* executing a FORMAT cmd. */
	    un_f_opt_queueing		:1,	/* Enable Command Queuing to */
						/* Host Adapter */
	    un_f_opt_fab_devid		:1,	/* Disk has no valid/unique */
						/* serial number.  */
	    un_f_opt_disable_cache	:1,	/* Read/Write disk cache is */
						/* disabled.  */
	    un_f_cfg_is_atapi		:1,	/* This is an ATAPI device.  */
	    un_f_write_cache_enabled	:1,	/* device return success on */
						/* writes before transfer to */
						/* physical media complete */
	    un_f_cfg_playmsf_bcd	:1,	/* Play Audio, BCD params. */
	    un_f_cfg_readsub_bcd	:1,	/* READ SUBCHANNEL BCD resp. */
	    un_f_cfg_read_toc_trk_bcd	:1,	/* track # is BCD */
	    un_f_cfg_read_toc_addr_bcd	:1,	/* address is BCD */
	    un_f_cfg_no_read_header	:1,	/* READ HEADER not supported */
	    un_f_cfg_read_cd_xd4	:1,	/* READ CD opcode is 0xd4 */
	    un_f_mmc_cap		:1,	/* Device is MMC compliant */
	    un_f_mmc_writable_media	:1,	/* writable media in device */
	    un_f_dvdram_writable_device	:1,	/* DVDRAM device is writable */
	    un_f_cfg_cdda		:1,	/* READ CDDA supported */
	    un_f_cfg_tur_check		:1,	/* verify un_ncmds before tur */

	    un_f_use_adaptive_throttle	:1,	/* enable/disable adaptive */
						/* throttling */
	    un_f_pm_is_enabled		:1,	/* PM is enabled on this */
						/* instance */
	    un_f_watcht_stopped		:1,	/* media watch thread flag */
	    un_f_pkstats_enabled	:1,	/* Flag to determine if */
						/* partition kstats are */
						/* enabled. */
	    un_f_disksort_disabled	:1,	/* Flag to disable disksort */
	    un_f_lun_reset_enabled	:1,	/* Set if target supports */
						/* SCSI Logical Unit Reset */
	    un_f_doorlock_supported	:1,	/* Device supports Doorlock */
	    un_f_start_stop_supported	:1,	/* device has motor */
	    un_f_reserved1		:1;

	uint32_t
	    un_f_mboot_supported	:1,	/* mboot supported */
	    un_f_is_hotpluggable	:1,	/* hotpluggable */
	    un_f_has_removable_media	:1,	/* has removable media */
	    un_f_non_devbsize_supported	:1,	/* non-512 blocksize */
	    un_f_devid_supported	:1,	/* device ID supported */
	    un_f_eject_media_supported	:1,	/* media can be ejected */
	    un_f_chk_wp_open		:1,	/* check if write-protected */
						/* when being opened */
	    un_f_descr_format_supported	:1,	/* support descriptor format */
						/* for sense data */
	    un_f_check_start_stop	:1,	/* needs to check if */
						/* START-STOP command is */
						/* supported by hardware */
						/* before issuing it */
	    un_f_monitor_media_state	:1,	/* need a watch thread to */
						/* monitor device state */
	    un_f_attach_spinup		:1,	/* spin up once the */
						/* device is attached */
	    un_f_log_sense_supported	:1,	/* support log sense */
	    un_f_pm_supported		:1, 	/* support power-management */
	    un_f_cfg_is_lsi		:1,	/* Is LSI device, */
						/* default to NO */
	    un_f_wcc_inprog		:1,	/* write cache change in */
						/* progress */
	    un_f_ejecting		:1,	/* media is ejecting */
	    un_f_suppress_cache_flush	:1,	/* supress flush on */
						/* write cache */
	    un_f_sync_nv_supported	:1,	/* SYNC_NV */
						/* bit is supported */
	    un_f_sync_cache_required	:1,	/* flag to check if */
						/* SYNC CACHE needs to be */
						/* sent in sdclose */
	    un_f_devid_transport_defined :1,	/* devid defined by transport */
	    un_f_rmw_type		 :2,	/* RMW type */
	    un_f_power_condition_disabled :1,	/* power condition disabled */
						/* through sd configuration */
	    un_f_power_condition_supported :1,	/* support power condition */
						/* field by hardware */
	    un_f_pm_log_sense_smart	:1,	/* log sense support SMART */
						/* feature attribute */
	    un_f_is_solid_state		:1,	/* has solid state media */
	    un_f_mmc_gesn_polling	:1,	/* use GET EVENT STATUS */
						/* NOTIFICATION for polling */
	    un_f_enable_rmw		:1,	/* Force RMW in sd driver */
	    un_f_expnevent		:1,
	    un_f_cache_mode_changeable	:1,	/* can change cache mode */
	    un_f_reserved		:2;

	/* Ptr to table of strings for ASC/ASCQ error message printing */
	struct scsi_asq_key_strings	*un_additional_codes;

	/*
	 * Power Management support.
	 *
	 * un_pm_mutex protects, un_pm_count, un_pm_timeid, un_pm_busy,
	 * un_pm_busy_cv, and un_pm_idle_timeid.
	 * It's not required that SD_MUTEX be acquired before acquiring
	 * un_pm_mutex, however if they must both be held
	 * then acquire SD_MUTEX first.
	 *
	 * un_pm_count is used to indicate PM state as follows:
	 *	less than 0 the device is powered down,
	 *	transition from 0 ==> 1, mark the device as busy via DDI
	 *	transition from 1 ==> 0, mark the device as idle via DDI
	 */
	kmutex_t	un_pm_mutex;
	int		un_pm_count;		/* indicates pm state */
	timeout_id_t	un_pm_timeid;		/* timeout id for pm */
	uint_t		un_pm_busy;
	kcondvar_t	un_pm_busy_cv;
	short		un_power_level;		/* Power Level */
	uchar_t		un_save_state;
	kcondvar_t	un_suspend_cv;		/* power management */
	kcondvar_t	un_disk_busy_cv;	/* wait for IO completion */

	/* Resources used for media change callback support */
	kcondvar_t	un_state_cv;		/* Cond Var on mediastate */
	enum dkio_state un_mediastate;		/* current media state */
	enum dkio_state un_specified_mediastate; /* expected state */
	opaque_t	un_swr_token;		/* scsi_watch request token */

	/* Non-512 byte block support */
	struct kmem_cache *un_wm_cache;	/* fast alloc in non-512 write case */
	uint_t		un_rmw_count;	/* count of read-modify-writes */
	struct sd_w_map	*un_wm;		/* head of sd_w_map chain */
	uint64_t	un_rmw_incre_count;	/* count I/O */
	timeout_id_t	un_rmw_msg_timeid;	/* for RMW message control */

	/* For timeout callback to issue a START STOP UNIT command */
	timeout_id_t	un_startstop_timeid;

	/* Timeout callback handle for SD_PATH_DIRECT_PRIORITY cmd restarts */
	timeout_id_t	un_direct_priority_timeid;

	/* TRAN_FATAL_ERROR count. Cleared by TRAN_ACCEPT from scsi_transport */
	ulong_t		un_tran_fatal_count;

	timeout_id_t	un_retry_timeid;

	hrtime_t	un_pm_idle_time;
	timeout_id_t	un_pm_idle_timeid;

	/*
	 * Count to determine if a Sonoma controller is in the process of
	 * failing over, and how many I/O's are failed with the 05/94/01
	 * sense code.
	 */
	uint_t		un_sonoma_failure_count;

	/*
	 * Support for failfast operation.
	 */
	struct buf	*un_failfast_bp;
	struct buf	*un_failfast_headp;
	struct buf	*un_failfast_tailp;
	uint32_t	un_failfast_state;
	/* Callback routine active counter */
	short		un_in_callback;

	kcondvar_t	un_wcc_cv;	/* synchronize changes to */
					/* un_f_write_cache_enabled */

#ifdef SD_FAULT_INJECTION
	/* SD Fault Injection */
#define	SD_FI_MAX_BUF 65536
#define	SD_FI_MAX_ERROR 1024
	kmutex_t			un_fi_mutex;
	uint_t				sd_fi_buf_len;
	char				sd_fi_log[SD_FI_MAX_BUF];
	struct sd_fi_pkt	*sd_fi_fifo_pkt[SD_FI_MAX_ERROR];
	struct sd_fi_xb		*sd_fi_fifo_xb[SD_FI_MAX_ERROR];
	struct sd_fi_un		*sd_fi_fifo_un[SD_FI_MAX_ERROR];
	struct sd_fi_arq	*sd_fi_fifo_arq[SD_FI_MAX_ERROR];
	uint_t				sd_fi_fifo_start;
	uint_t				sd_fi_fifo_end;
	uint_t				sd_injection_mask;

#endif

	cmlb_handle_t	un_cmlbhandle;

	/*
	 * Pointer to internal struct sd_fm_internal in which
	 * will pass necessary information for FMA ereport posting.
	 */
	void		*un_fm_private;
};

#define	SD_IS_VALID_LABEL(un)  (cmlb_is_valid(un->un_cmlbhandle))

/*
 * Macros for conversions between "target" and "system" block sizes, and
 * for conversion between block counts and byte counts.  As used here,
 * "system" block size refers to the block size used by the kernel/
 * filesystem (this includes the disk label). The "target" block size
 * is the block size returned by the SCSI READ CAPACITY command.
 *
 * Note: These macros will round up to the next largest blocksize to accomodate
 * the number of blocks specified.
 */

/* Convert a byte count to a number of target blocks */
#define	SD_BYTES2TGTBLOCKS(un, bytecount)				\
	((bytecount + (un->un_tgt_blocksize - 1))/un->un_tgt_blocksize)

/* Convert a byte count to a number of physical blocks */
#define	SD_BYTES2PHYBLOCKS(un, bytecount)				\
	((bytecount + (un->un_phy_blocksize - 1))/un->un_phy_blocksize)

/* Convert a target block count to a number of bytes */
#define	SD_TGTBLOCKS2BYTES(un, blockcount)				\
	(blockcount * (un)->un_tgt_blocksize)

/* Convert a byte count to a number of system blocks */
#define	SD_BYTES2SYSBLOCKS(bytecount)				\
	((bytecount + (DEV_BSIZE - 1))/DEV_BSIZE)

/* Convert a system block count to a number of bytes */
#define	SD_SYSBLOCKS2BYTES(blockcount)				\
	(blockcount * DEV_BSIZE)

/*
 * Calculate the number of bytes needed to hold the requested number of bytes
 * based upon the native target sector/block size
 */
#define	SD_REQBYTES2TGTBYTES(un, bytecount)				\
	(SD_BYTES2TGTBLOCKS(un, bytecount) * (un)->un_tgt_blocksize)

/*
 * Calculate the byte offset from the beginning of the target block
 * to the system block location.
 */
#define	SD_TGTBYTEOFFSET(un, sysblk, tgtblk)				\
	(SD_SYSBLOCKS2BYTES(sysblk) - SD_TGTBLOCKS2BYTES(un, tgtblk))

/*
 * Calculate the target block location from the system block location
 */
#define	SD_SYS2TGTBLOCK(un, blockcnt)					\
	(blockcnt / ((un)->un_tgt_blocksize / DEV_BSIZE))

/*
 * Calculate the target block location from the system block location
 */
#define	SD_TGT2SYSBLOCK(un, blockcnt)					\
	(blockcnt * ((un)->un_tgt_blocksize / DEV_BSIZE))

/*
 * SD_DEFAULT_MAX_XFER_SIZE is the default value to bound the max xfer
 * for physio, for devices without tagged queuing enabled.
 * The default for devices with tagged queuing enabled is SD_MAX_XFER_SIZE
 */
#if defined(__i386) || defined(__amd64)
#define	SD_DEFAULT_MAX_XFER_SIZE	(256 * 1024)
#endif
#define	SD_MAX_XFER_SIZE		(1024 * 1024)

/*
 * Warlock annotations
 */
_NOTE(MUTEX_PROTECTS_DATA(scsi_device::sd_mutex, sd_lun))
_NOTE(READ_ONLY_DATA(sd_lun::un_sd))
_NOTE(DATA_READABLE_WITHOUT_LOCK(sd_lun::un_reservation_type))
_NOTE(DATA_READABLE_WITHOUT_LOCK(sd_lun::un_mincdb))
_NOTE(DATA_READABLE_WITHOUT_LOCK(sd_lun::un_maxcdb))
_NOTE(DATA_READABLE_WITHOUT_LOCK(sd_lun::un_max_hba_cdb))
_NOTE(DATA_READABLE_WITHOUT_LOCK(sd_lun::un_status_len))
_NOTE(DATA_READABLE_WITHOUT_LOCK(sd_lun::un_f_arq_enabled))
_NOTE(DATA_READABLE_WITHOUT_LOCK(sd_lun::un_ctype))
_NOTE(DATA_READABLE_WITHOUT_LOCK(sd_lun::un_cmlbhandle))
_NOTE(DATA_READABLE_WITHOUT_LOCK(sd_lun::un_fm_private))


_NOTE(SCHEME_PROTECTS_DATA("safe sharing",
	sd_lun::un_mhd_token
	sd_lun::un_state
	sd_lun::un_tagflags
	sd_lun::un_f_format_in_progress
	sd_lun::un_resvd_timeid
	sd_lun::un_reset_throttle_timeid
	sd_lun::un_startstop_timeid
	sd_lun::un_dcvb_timeid
	sd_lun::un_f_allow_bus_device_reset
	sd_lun::un_sys_blocksize
	sd_lun::un_tgt_blocksize
	sd_lun::un_phy_blocksize
	sd_lun::un_additional_codes))

_NOTE(SCHEME_PROTECTS_DATA("stable data",
	sd_lun::un_reserve_release_time
	sd_lun::un_max_xfer_size
	sd_lun::un_partial_dma_supported
	sd_lun::un_buf_breakup_supported
	sd_lun::un_f_is_fibre
	sd_lun::un_node_type
	sd_lun::un_buf_chain_type
	sd_lun::un_uscsi_chain_type
	sd_lun::un_direct_chain_type
	sd_lun::un_priority_chain_type
	sd_lun::un_xbuf_attr
	sd_lun::un_cmd_timeout
	sd_lun::un_pkt_flags))

_NOTE(SCHEME_PROTECTS_DATA("Unshared data",
	block_descriptor
	buf
	cdrom_subchnl
	cdrom_tocentry
	cdrom_tochdr
	cdrom_read
	dk_cinfo
	dk_devid
	dk_label
	dk_map
	dk_temperature
	mhioc_inkeys
	mhioc_inresvs
	mode_caching
	mode_header
	mode_speed
	scsi_cdb
	scsi_arq_status
	scsi_extended_sense
	scsi_inquiry
	scsi_pkt
	uio
	uscsi_cmd))


_NOTE(SCHEME_PROTECTS_DATA("stable data", scsi_device dk_cinfo))
_NOTE(SCHEME_PROTECTS_DATA("unique per pkt", scsi_status scsi_cdb))

_NOTE(MUTEX_PROTECTS_DATA(sd_lun::un_pm_mutex, sd_lun::un_pm_count
	sd_lun::un_pm_timeid sd_lun::un_pm_busy sd_lun::un_pm_busy_cv
	sd_lun::un_pm_idle_timeid))

#ifdef SD_FAULT_INJECTION
_NOTE(MUTEX_PROTECTS_DATA(sd_lun::un_fi_mutex,
	sd_lun::sd_fi_buf_len sd_lun::sd_fi_log))
#endif

/* _NOTE(LOCK_ORDER(sd_lun::un_sd.sd_mutex sd_lun::un_pm_mutex)) */



/*
 * Referenced for frequently-accessed members of the unit structure
 */
#define	SD_SCSI_DEVP(un)	((un)->un_sd)
#define	SD_DEVINFO(un)		((un)->un_sd->sd_dev)
#define	SD_INQUIRY(un)		((un)->un_sd->sd_inq)
#define	SD_MUTEX(un)		(&((un)->un_sd->sd_mutex))
#define	SD_ADDRESS(un)		(&((un)->un_sd->sd_address))
#define	SD_GET_DEV(un)		(sd_make_device(SD_DEVINFO(un)))
#define	SD_FM_LOG(un)		(((struct sd_fm_internal *)\
				((un)->un_fm_private))->fm_log_level)


/*
 * Values for un_ctype
 */
#define	CTYPE_CDROM		0
#define	CTYPE_MD21		1	/* Obsolete! */
#define	CTYPE_CCS		2
#define	CTYPE_ROD		3
#define	CTYPE_PXRE		4	/* Obsolete! */

#define	ISCD(un)		((un)->un_ctype == CTYPE_CDROM)
#define	ISROD(un)		((un)->un_ctype == CTYPE_ROD)
#define	ISPXRE(un)		((un)->un_ctype == CTYPE_PXRE)

/*
 * This macro checks the vendor of the device to see if it is LSI. Because
 * LSI has some devices out there that return 'Symbios' or 'SYMBIOS', we
 * need to check for those also.
 *
 * This is used in some vendor specific checks.
 */
#define	SD_IS_LSI(un)	((un)->un_f_cfg_is_lsi == TRUE)

/*
 * Macros to check if the lun is a Sun T3 or a T4
 */
#define	SD_IS_T3(un) \
	((bcmp(SD_INQUIRY(un)->inq_vid, "SUN", 3) == 0) && \
	(bcmp(SD_INQUIRY(un)->inq_pid, "T3", 2) == 0))

#define	SD_IS_T4(un) \
	((bcmp(SD_INQUIRY(un)->inq_vid, "SUN", 3) == 0) && \
	(bcmp(SD_INQUIRY(un)->inq_pid, "T4", 2) == 0))

/*
 * Macros for non-512 byte writes to removable devices.
 */
#define	NOT_DEVBSIZE(un)	\
	((un)->un_tgt_blocksize != (un)->un_sys_blocksize)

/*
 * Check that a write map, used for locking lba ranges for writes, is in
 * the linked list.
 */
#define	ONLIST(un, wmp)		\
	(((un)->un_wm == (wmp)) || ((wmp)->wm_prev != NULL))

/*
 * Free a write map which is on list. Basically make sure that nobody is
 * sleeping on it before freeing it.
 */
#define	FREE_ONLIST_WMAP(un, wmp)				\
	if (!(wmp)->wm_wanted_count) {				\
		sd_free_inlist_wmap((un), (wmp));		\
		(wmp) = NULL;					\
	}

#define	CHK_N_FREEWMP(un, wmp)					\
	if (!ONLIST((un), (wmp))) {				\
		kmem_cache_free((un)->un_wm_cache, (wmp));	\
		(wmp) = NULL;					\
	} else {						\
		FREE_ONLIST_WMAP((un), (wmp));			\
	}

/*
 * Values used to in wm_flags field of sd_w_map.
 */
#define	SD_WTYPE_SIMPLE	0x001	/* Write aligned at blksize boundary */
#define	SD_WTYPE_RMW	0x002	/* Write requires read-modify-write */
#define	SD_WM_BUSY		0x100	/* write-map is busy */

/*
 * RMW type
 */
#define	SD_RMW_TYPE_DEFAULT	0	/* do rmw with warning message */
#define	SD_RMW_TYPE_NO_WARNING	1	/* do rmw without warning message */
#define	SD_RMW_TYPE_RETURN_ERROR	2	/* rmw disabled */

/* Device error kstats */
struct sd_errstats {
	struct kstat_named	sd_softerrs;
	struct kstat_named	sd_harderrs;
	struct kstat_named	sd_transerrs;
	struct kstat_named	sd_vid;
	struct kstat_named	sd_pid;
	struct kstat_named	sd_revision;
	struct kstat_named	sd_serial;
	struct kstat_named	sd_capacity;
	struct kstat_named	sd_rq_media_err;
	struct kstat_named	sd_rq_ntrdy_err;
	struct kstat_named	sd_rq_nodev_err;
	struct kstat_named	sd_rq_recov_err;
	struct kstat_named	sd_rq_illrq_err;
	struct kstat_named	sd_rq_pfa_err;
};


/*
 * Structs and definitions for SCSI-3 Persistent Reservation
 */
typedef struct sd_prin_readkeys {
	uint32_t	generation;
	uint32_t	len;
	mhioc_resv_key_t *keylist;
} sd_prin_readkeys_t;

typedef struct sd_readresv_desc {
	mhioc_resv_key_t	resvkey;
	uint32_t		scope_specific_addr;
	uint8_t			reserved_1;
#if defined(_BIT_FIELDS_LTOH)
	uint8_t			type:4,
				scope:4;
#elif defined(_BIT_FIELDS_HTOL)
	uint8_t			scope:4,
				type:4;
#else
#error	One of _BIT_FIELDS_LTOH or _BIT_FIELDS_HTOL must be defined
#endif	/* _BIT_FIELDS_LTOH */
	uint8_t			reserved_2;
	uint8_t			reserved_3;
} sd_readresv_desc_t;

typedef struct sd_prin_readresv {
	uint32_t		generation;
	uint32_t		len;
	sd_readresv_desc_t	*readresv_desc;
} sd_prin_readresv_t;

typedef struct sd_prout {
	uchar_t		res_key[MHIOC_RESV_KEY_SIZE];
	uchar_t		service_key[MHIOC_RESV_KEY_SIZE];
	uint32_t	scope_address;
#if defined(_BIT_FIELDS_LTOH)
	uchar_t		aptpl:1,
			reserved:7;
#elif defined(_BIT_FIELDS_HTOL)
	uchar_t		reserved:7,
			aptpl:1;
#else
#error	One of _BIT_FIELDS_LTOH or _BIT_FIELDS_HTOL must be defined
#endif	/* _BIT_FIELDS_LTOH */
	uchar_t		reserved_1;
	uint16_t	ext_len;
} sd_prout_t;

#define	SD_READ_KEYS			0x00
#define	SD_READ_RESV			0x01

#define	SD_SCSI3_REGISTER		0x00
#define	SD_SCSI3_RESERVE		0x01
#define	SD_SCSI3_RELEASE		0x02
#define	SD_SCSI3_CLEAR			0x03
#define	SD_SCSI3_PREEMPTANDABORT	0x05
#define	SD_SCSI3_REGISTERANDIGNOREKEY	0x06

/*
 * Note: The default init of un_reservation_type is to the value of '0'
 * (from the ddi_softs_state_zalloc) which means it is defaulting to SCSI-3
 * reservation type. This is ok because during attach we use a SCSI-3
 * PRIORITY RESERVE IN command to determine the reservation type, and set
 * un_reservation_type for all cases.
 */
#define	SD_SCSI3_RESERVATION		0x0
#define	SD_SCSI2_RESERVATION		0x1
#define	SCSI3_RESV_DESC_LEN		16

/*
 * Reservation Status's
 */
#define	SD_RELEASE			0x0000
#define	SD_RESERVE			0x0001
#define	SD_TKOWN			0x0002
#define	SD_LOST_RESERVE			0x0004
#define	SD_FAILFAST			0x0080
#define	SD_WANT_RESERVE			0x0100
#define	SD_RESERVATION_CONFLICT		0x0200
#define	SD_PRIORITY_RESERVE		0x0400

#define	SD_TARGET_IS_UNRESERVED		0
#define	SD_TARGET_IS_RESERVED		1

/*
 * Save page in mode_select
 */
#define	SD_DONTSAVE_PAGE		0
#define	SD_SAVE_PAGE			1

/*
 * Delay before reclaiming reservation is 6 seconds, in units of micro seconds
 */
#define	SD_REINSTATE_RESV_DELAY		6000000

#define	SD_MODE2_BLKSIZE		2336	/* bytes */

/*
 * Solid State Drive default sector size
 */
#define	SSD_SECSIZE			4096

/*
 * Resource type definitions for multi host control operations. Specifically,
 * queue and request definitions for reservation request handling between the
 * scsi facility callback function (sd_mhd_watch_cb) and the reservation
 * reclaim thread (sd_resv_reclaim_thread)
 */
struct sd_thr_request {
	dev_t	dev;
	struct	sd_thr_request	*sd_thr_req_next;
};

struct sd_resv_reclaim_request {
	kthread_t		*srq_resv_reclaim_thread;
	struct	sd_thr_request	*srq_thr_req_head;
	struct	sd_thr_request	*srq_thr_cur_req;
	kcondvar_t		srq_inprocess_cv;
	kmutex_t		srq_resv_reclaim_mutex;
	kcondvar_t		srq_resv_reclaim_cv;
};

_NOTE(MUTEX_PROTECTS_DATA(sd_resv_reclaim_request::srq_resv_reclaim_mutex,
    sd_resv_reclaim_request))
_NOTE(SCHEME_PROTECTS_DATA("unshared data", sd_thr_request))
_NOTE(SCHEME_PROTECTS_DATA("Unshared data", sd_prout))



/*
 * Driver Logging Components
 *
 * These components cover the functional entry points and areas of the
 * driver.  A component value is used for the entry point and utility
 * functions used by the entry point. The common component value is used
 * in those routines that are called from many areas of the driver.
 *
 * This can be done by adding the following two lines to /etc/system:
 * set sd:sd_component_mask=0x00080000
 * set sd:sd_level_mask=0x00000008
 */
#define	SD_LOG_PROBE			0x00000001
#define	SD_LOG_ATTACH_DETACH		0x00000002
#define	SD_LOG_OPEN_CLOSE		0x00000004
#define	SD_LOG_READ_WRITE		0x00000008
#define	SD_LOG_POWER			0x00000010
#define	SD_LOG_IOCTL			0x00000020
#define	SD_LOG_IOCTL_MHD		0x00000040
#define	SD_LOG_IOCTL_RMMEDIA		0x00000080
#define	SD_LOG_IOCTL_DKIO		0x00000100
#define	SD_LOG_IO			0x00000200
#define	SD_LOG_IO_CORE			0x00000400
#define	SD_LOG_IO_DISKSORT		0x00000800
#define	SD_LOG_IO_PARTITION		0x00001000
#define	SD_LOG_IO_RMMEDIA		0x00002000
#define	SD_LOG_IO_CHKSUM		0x00004000
#define	SD_LOG_IO_SDIOCTL		0x00008000
#define	SD_LOG_IO_PM			0x00010000
#define	SD_LOG_ERROR			0x00020000
#define	SD_LOG_DUMP			0x00040000
#define	SD_LOG_COMMON			0x00080000
#define	SD_LOG_SDTEST			0x00100000
#define	SD_LOG_IOERR			0x00200000
#define	SD_LOG_IO_FAILFAST		0x00400000

/* Driver Logging Levels */
#define	SD_LOGMASK_ERROR		0x00000001
#define	SD_LOGMASK_DUMP_MEM		0x00000002
#define	SD_LOGMASK_INFO			0x00000004
#define	SD_LOGMASK_TRACE		0x00000008
#define	SD_LOGMASK_DIAG			0x00000010

/* Driver Logging Formats */
#define	SD_LOG_HEX			0x00000001
#define	SD_LOG_CHAR			0x00000002

/*
 * The following macros should be used to log driver debug information
 * only. The output is filtered according to the component and level mask
 * values. Non-debug information, such as driver warnings intended for
 * the user should be logged via the scsi_log facility to ensure that
 * they are not filtered.
 */
#if DEBUG || lint
#define	SDDEBUG

/* SD_ERROR is called to log driver error conditions */
#define	SD_ERROR	sd_log_err

/* SD_TRACE is called to log driver trace conditions (function entry/exit) */
#define	SD_TRACE	sd_log_trace

/* SD_INFO is called to log general purpose driver info */
#define	SD_INFO		sd_log_info

/* SD_DUMP_MEMORY is called to dump a data buffer to the log */
#define	SD_DUMP_MEMORY	sd_dump_memory

/* RESET/ABORTS testing ioctls */
#define	DKIOCRESET	(DKIOC|14)
#define	DKIOCABORT	(DKIOC|15)

#ifdef SD_FAULT_INJECTION
/*
 * sd_fi_pkt replicates the variables that are exposed through pkt
 *
 * sd_fi_xb replicates the variables that are exposed through xb
 *
 * sd_fi_un replicates the variables that are exposed through un
 *
 * sd_fi_arq replicates the variables that are
 *           exposed for Auto-Reqeust-Sense
 *
 */
struct sd_fi_pkt {
	uint_t  pkt_flags;			/* flags */
	uchar_t pkt_scbp;			/* pointer to status block */
	uchar_t pkt_cdbp;			/* pointer to command block */
	uint_t  pkt_state;			/* state of command */
	uint_t  pkt_statistics;		/* statistics */
	uchar_t pkt_reason;			/* reason completion called */
};

struct sd_fi_xb {
	daddr_t xb_blkno;
	ssize_t xb_dma_resid;
	short	xb_retry_count;
	short	xb_victim_retry_count;
	uchar_t xb_sense_status;
	uint_t  xb_sense_state;
	ssize_t xb_sense_resid;
	uchar_t xb_sense_data[SENSE_LENGTH];
	uchar_t es_code;
	uchar_t es_key;
	uchar_t es_add_code;
	uchar_t es_qual_code;
};

struct sd_fi_un {
	uchar_t inq_rmb;
	uchar_t un_ctype;
	uint_t  un_notready_retry_count;
	uint_t  un_reset_retry_count;
	uchar_t un_reservation_type;
	ushort_t un_notrdy_delay;
	short   un_resvd_status;
	uint32_t
		un_f_arq_enabled,
		un_f_allow_bus_device_reset,
		un_f_opt_queueing;
	timeout_id_t    un_restart_timeid;
};

struct sd_fi_arq {
	struct scsi_status	sts_status;
	struct scsi_status	sts_rqpkt_status;
	uchar_t				sts_rqpkt_reason;
	uchar_t				sts_rqpkt_resid;
	uint_t				sts_rqpkt_state;
	uint_t				sts_rqpkt_statistics;
	struct scsi_extended_sense	sts_sensedata;
};

/*
 * Conditional set def
 */
#define	SD_CONDSET(a, b, c, d)			\
	{ \
	a->c = ((fi_ ## b)->c);			\
	SD_INFO(SD_LOG_IOERR, un,		\
			"sd_fault_injection:"	\
			"setting %s to %d\n", 	\
			d, ((fi_ ## b)->c)); 	\
	}

/* SD FaultInjection ioctls */
#define	SDIOC			('T'<<8)
#define	SDIOCSTART		(SDIOC|1)
#define	SDIOCSTOP		(SDIOC|2)
#define	SDIOCINSERTPKT	(SDIOC|3)
#define	SDIOCINSERTXB	(SDIOC|4)
#define	SDIOCINSERTUN	(SDIOC|5)
#define	SDIOCINSERTARQ	(SDIOC|6)
#define	SDIOCPUSH		(SDIOC|7)
#define	SDIOCRETRIEVE	(SDIOC|8)
#define	SDIOCRUN		(SDIOC|9)
#endif

#else

#undef	SDDEBUG
#define	SD_ERROR	{ if (0) sd_log_err; }
#define	SD_TRACE	{ if (0) sd_log_trace; }
#define	SD_INFO		{ if (0) sd_log_info; }
#define	SD_DUMP_MEMORY	{ if (0) sd_dump_memory; }
#endif


/*
 * Miscellaneous macros
 */

#define	SD_USECTOHZ(x)			(drv_usectohz((x)*1000000))
#define	SD_GET_PKT_STATUS(pktp)		((*(pktp)->pkt_scbp) & STATUS_MASK)

#define	SD_BIOERROR(bp, errcode)					\
	if ((bp)->b_resid == 0) {					\
		(bp)->b_resid = (bp)->b_bcount;				\
	}								\
	if ((bp)->b_error == 0) {					\
		bioerror(bp, errcode);					\
	}								\
	(bp)->b_flags |= B_ERROR;

#define	SD_FILL_SCSI1_LUN_CDB(lunp, cdbp)				\
	if (! (lunp)->un_f_is_fibre &&					\
	    SD_INQUIRY((lunp))->inq_ansi == 0x01) {			\
		int _lun = ddi_prop_get_int(DDI_DEV_T_ANY,		\
		    SD_DEVINFO((lunp)), DDI_PROP_DONTPASS,		\
		    SCSI_ADDR_PROP_LUN, 0);				\
		if (_lun > 0) {						\
			(cdbp)->scc_lun = _lun;				\
		}							\
	}

#define	SD_FILL_SCSI1_LUN(lunp, pktp)					\
	SD_FILL_SCSI1_LUN_CDB((lunp), (union scsi_cdb *)(pktp)->pkt_cdbp)

/*
 * Disk driver states
 */

#define	SD_STATE_NORMAL		0
#define	SD_STATE_OFFLINE	1
#define	SD_STATE_RWAIT		2
#define	SD_STATE_DUMPING	3
#define	SD_STATE_SUSPENDED	4
#define	SD_STATE_PM_CHANGING	5

/*
 * The table is to be interpreted as follows: The rows lists all the states
 * and each column is a state that a state in each row *can* reach. The entries
 * in the table list the event that cause that transition to take place.
 * For e.g.: To go from state RWAIT to SUSPENDED, event (d)-- which is the
 * invocation of DDI_SUSPEND-- has to take place. Note the same event could
 * cause the transition from one state to two different states. e.g., from
 * state SUSPENDED, when we get a DDI_RESUME, we just go back to the *last
 * state* whatever that might be. (NORMAL or OFFLINE).
 *
 *
 * State Transition Table:
 *
 *                    NORMAL  OFFLINE  RWAIT  DUMPING  SUSPENDED  PM_SUSPENDED
 *
 *   NORMAL              -      (a)      (b)     (c)      (d)       (h)
 *
 *   OFFLINE            (e)      -       (e)     (c)      (d)       NP
 *
 *   RWAIT              (f)     NP        -      (c)      (d)       (h)
 *
 *   DUMPING            NP      NP        NP      -        NP       NP
 *
 *   SUSPENDED          (g)     (g)       (b)     NP*      -        NP
 *
 *   PM_SUSPENDED       (i)     NP        (b)    (c)      (d)       -
 *
 *   NP :       Not Possible.
 *   (a):       Disk does not respond.
 *   (b):       Packet Allocation Fails
 *   (c):       Panic - Crash dump
 *   (d):       DDI_SUSPEND is called.
 *   (e):       Disk has a successful I/O completed.
 *   (f):       sdrunout() calls sdstart() which sets it NORMAL
 *   (g):       DDI_RESUME is called.
 *   (h):	Device threshold exceeded pm framework called power
 *		entry point or pm_lower_power called in detach.
 *   (i):	When new I/O come in.
 *    * :       When suspended, we dont change state during panic dump
 */


#define	SD_MAX_THROTTLE		256
#define	SD_MIN_THROTTLE		8
/*
 * Lowest valid max. and min. throttle value.
 * This is set to 2 because if un_min_throttle were allowed to be 1 then
 * un_throttle would never get set to a value less than un_min_throttle
 * (0 is a special case) which means it would never get set back to
 * un_saved_throttle in routine sd_restore_throttle().
 */
#define	SD_LOWEST_VALID_THROTTLE	2



/* Return codes for sd_send_polled_cmd() and sd_scsi_poll() */
#define	SD_CMD_SUCCESS			0
#define	SD_CMD_FAILURE			1
#define	SD_CMD_RESERVATION_CONFLICT	2
#define	SD_CMD_ILLEGAL_REQUEST		3
#define	SD_CMD_BECOMING_READY		4
#define	SD_CMD_CHECK_CONDITION		5

/* Return codes for sd_ready_and_valid */
#define	SD_READY_VALID			0
#define	SD_NOT_READY_VALID		1
#define	SD_RESERVED_BY_OTHERS		2

#define	SD_PATH_STANDARD		0
#define	SD_PATH_DIRECT			1
#define	SD_PATH_DIRECT_PRIORITY		2

#define	SD_UNIT_ATTENTION_RETRY		40

/*
 * The following three are bit flags passed into sd_send_scsi_TEST_UNIT_READY
 * to control specific behavior.
 */
#define	SD_CHECK_FOR_MEDIA		0x01
#define	SD_DONT_RETRY_TUR		0x02
#define	SD_BYPASS_PM			0x04

#define	SD_GROUP0_MAX_ADDRESS	(0x1fffff)
#define	SD_GROUP0_MAXCOUNT	(0xff)
#define	SD_GROUP1_MAX_ADDRESS	(0xffffffff)
#define	SD_GROUP1_MAXCOUNT	(0xffff)

#define	SD_BECOMING_ACTIVE	0x01
#define	SD_REMOVAL_ALLOW	0
#define	SD_REMOVAL_PREVENT	1

#define	SD_GET_PKT_OPCODE(pktp)	\
	(((union scsi_cdb *)((pktp)->pkt_cdbp))->cdb_un.cmd)


#define	SD_NO_RETRY_ISSUED		0
#define	SD_DELAYED_RETRY_ISSUED		1
#define	SD_IMMEDIATE_RETRY_ISSUED	2

#if defined(__i386) || defined(__amd64)
#define	SD_UPDATE_B_RESID(bp, pktp)	\
	((bp)->b_resid += (pktp)->pkt_resid + (SD_GET_XBUF(bp)->xb_dma_resid))
#else
#define	SD_UPDATE_B_RESID(bp, pktp)	\
	((bp)->b_resid += (pktp)->pkt_resid)
#endif


#define	SD_RETRIES_MASK		0x00FF
#define	SD_RETRIES_NOCHECK	0x0000
#define	SD_RETRIES_STANDARD	0x0001
#define	SD_RETRIES_VICTIM	0x0002
#define	SD_RETRIES_BUSY		0x0003
#define	SD_RETRIES_UA		0x0004
#define	SD_RETRIES_ISOLATE	0x8000
#define	SD_RETRIES_FAILFAST	0x4000

#define	SD_UPDATE_RESERVATION_STATUS(un, pktp)				\
if (((pktp)->pkt_reason == CMD_RESET) ||				\
	((pktp)->pkt_statistics & (STAT_BUS_RESET | STAT_DEV_RESET))) { \
	if (((un)->un_resvd_status & SD_RESERVE) == SD_RESERVE) {	\
		(un)->un_resvd_status |=				\
		    (SD_LOST_RESERVE | SD_WANT_RESERVE);		\
	}								\
}

#define	SD_SENSE_DATA_IS_VALID		0
#define	SD_SENSE_DATA_IS_INVALID	1

/*
 * Delay (in seconds) before restoring the "throttle limit" back
 * to its maximum value.
 * 60 seconds is what we will wait for to reset the
 * throttle back to it SD_MAX_THROTTLE for TRAN_BUSY.
 * 10 seconds for STATUS_QFULL because QFULL will incrementally
 * increase the throttle limit until it reaches max value.
 */
#define	SD_RESET_THROTTLE_TIMEOUT	60
#define	SD_QFULL_THROTTLE_TIMEOUT	10

#define	SD_THROTTLE_TRAN_BUSY		0
#define	SD_THROTTLE_QFULL		1

#define	SD_THROTTLE_RESET_INTERVAL	\
	(sd_reset_throttle_timeout * drv_usectohz(1000000))

#define	SD_QFULL_THROTTLE_RESET_INTERVAL	\
	(sd_qfull_throttle_timeout * drv_usectohz(1000000))


/*
 * xb_pkt_flags defines
 * SD_XB_DMA_FREED indicates the scsi_pkt has had its DMA resources freed
 * by a call to scsi_dmafree(9F). The resources must be reallocated before
 *   before a call to scsi_transport can be made again.
 * SD_XB_USCSICMD indicates the scsi request is a uscsi request
 * SD_XB_INITPKT_MASK: since this field is also used to store flags for
 *   a scsi_init_pkt(9F) call, we need a mask to make sure that we don't
 *   pass any unintended bits to scsi_init_pkt(9F) (ugly hack).
 */
#define	SD_XB_DMA_FREED		0x20000000
#define	SD_XB_USCSICMD		0x40000000
#define	SD_XB_INITPKT_MASK	(PKT_CONSISTENT | PKT_DMA_PARTIAL)

/*
 * Extension for the buf(9s) struct that we receive from a higher
 * layer. Located by b_private in the buf(9S).  (The previous contents
 * of b_private are saved & restored before calling biodone(9F).)
 */
struct sd_xbuf {

	struct sd_lun	*xb_un;		/* Ptr to associated sd_lun */
	struct scsi_pkt	*xb_pktp;	/* Ptr to associated scsi_pkt */

	/*
	 * xb_pktinfo points to any optional data that may be needed
	 * by the initpkt and/or destroypkt functions.  Typical
	 * use might be to point to a struct uscsi_cmd.
	 */
	void	*xb_pktinfo;

	/*
	 * Layer-private data area. This may be used by any layer to store
	 * layer-specific data on a per-IO basis. Typical usage is for an
	 * iostart routine to save some info here for later use by its
	 * partner iodone routine.  This area may be used to hold data or
	 * a pointer to a data block that is allocated/freed by the layer's
	 * iostart/iodone routines. Allocation & management policy for the
	 * layer-private area is defined & implemented by each specific
	 * layer as required.
	 *
	 * IMPORTANT: Since a higher layer may depend on the value in the
	 * xb_private field, each layer must ensure that it returns the
	 * buf/xbuf to the next higher layer (via SD_NEXT_IODONE()) with
	 * the SAME VALUE in xb_private as when the buf/xbuf was first
	 * received by the layer's iostart routine. Typically this is done
	 * by the iostart routine saving the contents of xb_private into
	 * a place in the layer-private data area, and the iodone routine
	 * restoring the value of xb_private before deallocating the
	 * layer-private data block and calling SD_NEXT_IODONE(). Of course,
	 * if a layer never modifies xb_private in a buf/xbuf from a higher
	 * layer, there will be no need to restore the value.
	 *
	 * Note that in the case where a layer _creates_ a buf/xbuf (such as
	 * by calling sd_shadow_buf_alloc()) to pass to a lower layer, it is
	 * not necessary to preserve the contents of xb_private as there is
	 * no higher layer dependency on the value of xb_private. Such a
	 * buf/xbuf must be deallocated by the layer that allocated it and
	 * must *NEVER* be passed up to a higher layer.
	 */
	void	*xb_private;	/* Layer-private data block */

	/*
	 * We do not use the b_blkno provided in the buf(9S), as we need to
	 * make adjustments to it in the driver, but it is not a field that
	 * the driver owns or is free to modify.
	 */
	daddr_t	xb_blkno;		/* Absolute block # on target */
	uint64_t xb_ena;		/* ena for a specific SCSI command */

	int	xb_chain_iostart;	/* iostart side index */
	int	xb_chain_iodone;	/* iodone side index */
	int	xb_pkt_flags;		/* Flags for scsi_init_pkt() */
	ssize_t	xb_dma_resid;
	short	xb_retry_count;
	short	xb_victim_retry_count;
	short	xb_ua_retry_count;	/* unit_attention retry counter */
	short	xb_nr_retry_count;	/* not ready retry counter */

	/*
	 * Various status and data used when a RQS command is run on
	 * the behalf of this command.
	 */
	struct buf	*xb_sense_bp;	/* back ptr to buf, for RQS */
	uint_t	xb_sense_state;		/* scsi_pkt state of RQS command */
	ssize_t	xb_sense_resid;		/* residual of RQS command */
	uchar_t	xb_sense_status;	/* scsi status byte of RQS command */
	uchar_t	xb_sense_data[SENSE_LENGTH];	/* sense data from RQS cmd */
	/*
	 * Extra sense larger than SENSE_LENGTH will be allocated
	 * right after xb_sense_data[SENSE_LENGTH]. Please do not
	 * add any new field after it.
	 */
};

_NOTE(SCHEME_PROTECTS_DATA("unique per pkt", sd_xbuf))

#define	SD_PKT_ALLOC_SUCCESS			0
#define	SD_PKT_ALLOC_FAILURE			1
#define	SD_PKT_ALLOC_FAILURE_NO_DMA		2
#define	SD_PKT_ALLOC_FAILURE_PKT_TOO_SMALL	3
#define	SD_PKT_ALLOC_FAILURE_CDB_TOO_SMALL	4

#define	SD_GET_XBUF(bp)		((struct sd_xbuf *)((bp)->b_private))
#define	SD_GET_UN(bp)		((SD_GET_XBUF(bp))->xb_un)
#define	SD_GET_PKTP(bp)		((SD_GET_XBUF(bp))->xb_pktp)
#define	SD_GET_BLKNO(bp)	((SD_GET_XBUF(bp))->xb_blkno)

/*
 * Special-purpose struct for sd_send_scsi_cmd() to pass command-specific
 * data through the layering chains to sd_initpkt_for_uscsi().
 */
struct sd_uscsi_info {
	int			ui_flags;
	struct uscsi_cmd	*ui_cmdp;
	/*
	 * ui_dkc is used by sd_send_scsi_SYNCHRONIZE_CACHE() to allow
	 * for async completion notification.
	 */
	struct dk_callback	ui_dkc;
	/*
	 * The following fields are to be used for FMA ereport generation.
	 */
	uchar_t			ui_pkt_reason;
	uint32_t		ui_pkt_state;
	uint32_t		ui_pkt_statistics;
	uint64_t		ui_lba;
	uint64_t		ui_ena;
};

_NOTE(SCHEME_PROTECTS_DATA("Unshared data", sd_uscsi_info))

/*
 * This structure is used to issue 'internal' command sequences from the
 * driver's attach(9E)/open(9E)/etc entry points. It provides a common context
 * for issuing command sequences, with the ability to issue a command
 * and provide expected/unexpected assessment of results at any code
 * level within the sd_ssc_t scope and preserve the information needed
 * produce telemetry for the problem, when needed, from a single
 * outer-most-scope point.
 *
 * The sd_ssc_t abstraction should result in well-structured code where
 * the basic code structure is not jeprodized by future localized improvement.
 *
 *   o  Scope for a sequence of commands.
 *   o  Within a scoped sequence of commands, provides a single top-level
 *      location for initiating telementry generation from captured data.
 *   o  Provide a common place to capture command execution data and driver
 *      assessment information for delivery to telemetry generation point.
 *   o  Mechanism to get device-as-detector (dad) and transport telemetry
 *      information from interrupt context (sdintr) back to the internal
 *      command 'driver-assessment' code.
 *   o  Ability to record assessment, and return information back to
 *      top-level telemetry generation code when an unexpected condition
 *      occurs.
 *   o  For code paths were an command itself was successful but
 *      the data returned looks suspect, the ability to record
 *      'unexpected data' conditions.
 *   o  Record assessment of issuing the command and interpreting
 *      the returned data for consumption by top-level ereport telemetry
 *      generation code.
 *   o  All data required to produce telemetry available off single data
 *      structure.
 */
typedef struct {
	struct sd_lun		*ssc_un;
	struct uscsi_cmd	*ssc_uscsi_cmd;
	struct sd_uscsi_info	*ssc_uscsi_info;
	int			ssc_flags; /* Bits for flags */
	char			ssc_info[1024]; /* Buffer holding for info */
} sd_ssc_t;

_NOTE(SCHEME_PROTECTS_DATA("Unshared data", sd_ssc_t))

/*
 * This struct switch different 'type-of-assessment'
 * as an input argument for sd_ssc_assessment
 *
 *
 * in sd_send_scsi_XXX or upper-level
 *
 * - SD_FMT_IGNORE
 *   when send uscsi command failed, and
 *   the following code check sense data properly.
 *   we use 'ignore' to let sd_ssc_assessment
 *   trust current and do not do additional
 *   checking for the uscsi command.
 *
 * - SD_FMT_IGNORE_COMPROMISE
 *   when send uscsi command failed, and
 *   the code does not check sense data or we don't
 *   think the checking is 100% coverage. We mark it
 *   as 'compromise' to indicate that we need to
 *   enhance current code in the future.
 *
 * - SD_FMT_STATUS_CHECK
 *   when send uscsi command failed and cause sd entries
 *   failed finally, we need to send out real reason against
 *   status of uscsi command no matter if there is sense back
 *   or not.
 *
 * - SD_FMT_STANDARD
 *   when send uscsi command succeeded, and
 *   the code does not check sense data, we need to check
 *   it to make sure there is no 'fault'.
 */
enum sd_type_assessment {
	SD_FMT_IGNORE = 0,
	SD_FMT_IGNORE_COMPROMISE,
	SD_FMT_STATUS_CHECK,
	SD_FMT_STANDARD
};

/*
 * The following declaration are used as hints of severities when posting
 * SCSI FMA ereport.
 * - SD_FM_DRV_FATAL
 *   When posting ereport with SD_FM_DRV_FATAL, the payload
 *   "driver-assessment" will be "fail" or "fatal" depending on the
 *   sense-key value. If driver-assessment is "fail", it will be
 *   propagated to an upset, otherwise, a fault will be propagated.
 * - SD_FM_DRV_RETRY
 *   When posting ereport with SD_FM_DRV_RETRY, the payload
 *   "driver-assessment" will be "retry", and it will be propagated to an
 *   upset.
 * - SD_FM_DRV_RECOVERY
 *   When posting ereport with SD_FM_DRV_RECOVERY, the payload
 *   "driver-assessment" will be "recovered", and it will be propagated to
 *   an upset.
 * - SD_FM_DRV_NOTICE
 *   When posting ereport with SD_FM_DRV_NOTICE, the payload
 *   "driver-assessment" will be "info", and it will be propagated to an
 *   upset.
 */
enum sd_driver_assessment {
	SD_FM_DRV_FATAL = 0,
	SD_FM_DRV_RETRY,
	SD_FM_DRV_RECOVERY,
	SD_FM_DRV_NOTICE
};

/*
 * The following structure is used as a buffer when posting SCSI FMA
 * ereport for raw i/o. It will be allocated per sd_lun when entering
 * sd_unit_attach and will be deallocated when entering sd_unit_detach.
 */
struct sd_fm_internal {
	sd_ssc_t fm_ssc;
	struct uscsi_cmd fm_ucmd;
	struct sd_uscsi_info fm_uinfo;
	int fm_log_level;
};

/*
 * Bits in ssc_flags
 * sd_ssc_init will mark ssc_flags = SSC_FLAGS_UNKNOWN
 * sd_ssc_send will mark ssc_flags = SSC_FLAGS_CMD_ISSUED &
 *                                   SSC_FLAGS_NEED_ASSESSMENT
 * sd_ssc_assessment will clear SSC_FLAGS_CMD_ISSUED and
 * SSC_FLAGS_NEED_ASSESSMENT bits of ssc_flags.
 * SSC_FLAGS_CMD_ISSUED is to indicate whether the SCSI command has been
 * sent out.
 * SSC_FLAGS_NEED_ASSESSMENT is to guarantee we will not miss any
 * assessment point.
 */
#define		SSC_FLAGS_UNKNOWN		0x00000000
#define		SSC_FLAGS_CMD_ISSUED		0x00000001
#define		SSC_FLAGS_NEED_ASSESSMENT	0x00000002
#define		SSC_FLAGS_TRAN_ABORT		0x00000004

/*
 * The following bits in ssc_flags are for detecting unexpected data.
 */
#define		SSC_FLAGS_INVALID_PKT_REASON	0x00000010
#define		SSC_FLAGS_INVALID_STATUS	0x00000020
#define		SSC_FLAGS_INVALID_SENSE		0x00000040
#define		SSC_FLAGS_INVALID_DATA		0x00000080

/*
 * The following are the values available for sd_fm_internal::fm_log_level.
 * SD_FM_LOG_NSUP	The driver will log things in traditional way as if
 * 			the SCSI FMA feature is unavailable.
 * SD_FM_LOG_SILENT	The driver will not print out syslog for FMA error
 * 			telemetry, all the error telemetries will go into
 * 			FMA error log.
 * SD_FM_LOG_EREPORT	The driver will both print the FMA error telemetry
 * 			and post the error report, but the traditional
 * 			syslog for error telemetry will be suppressed.
 */
#define		SD_FM_LOG_NSUP		0
#define		SD_FM_LOG_SILENT	1
#define		SD_FM_LOG_EREPORT	2

/*
 * Macros and definitions for driver kstats and errstats
 *
 * Some third-party layered drivers (they know who they are) do not maintain
 * their open/close counts correctly which causes our kstat reporting to get
 * messed up & results in panics. These macros will update the driver kstats
 * only if the counts are valid.
 */
#define	SD_UPDATE_COMMON_KSTATS(kstat_function, kstatp)			\
	if ((kstat_function)  == kstat_runq_exit ||			\
	    ((kstat_function) == kstat_runq_back_to_waitq)) { 		\
		if (((kstat_io_t *)(kstatp))->rcnt) {			\
			kstat_function((kstatp));			\
		} else {						\
			cmn_err(CE_WARN,				\
		"kstat rcnt == 0 when exiting runq, please check\n");	\
		}							\
	} else if ((kstat_function) == kstat_waitq_exit ||		\
	    ((kstat_function) == kstat_waitq_to_runq)) {		\
		if (((kstat_io_t *)(kstatp))->wcnt) {			\
			kstat_function(kstatp);				\
		} else {						\
			cmn_err(CE_WARN,				\
		"kstat wcnt == 0 when exiting waitq, please check\n");	\
		}							\
	} else {							\
		kstat_function(kstatp);					\
	}

#define	SD_UPDATE_KSTATS(un, kstat_function, bp)			\
	ASSERT(SD_GET_XBUF(bp) != NULL);				\
	if (SD_IS_BUFIO(SD_GET_XBUF(bp))) {				\
		struct kstat *pksp =					\
			(un)->un_pstats[SDPART((bp)->b_edev)];		\
		ASSERT(mutex_owned(SD_MUTEX(un)));			\
		if ((un)->un_stats != NULL) {				\
			kstat_io_t *kip = KSTAT_IO_PTR((un)->un_stats);	\
			SD_UPDATE_COMMON_KSTATS(kstat_function, kip);	\
		}							\
		if (pksp != NULL) {					\
			kstat_io_t *kip = KSTAT_IO_PTR(pksp);		\
			SD_UPDATE_COMMON_KSTATS(kstat_function, kip);	\
		}							\
	}

#define	SD_UPDATE_ERRSTATS(un, x)					\
	if ((un)->un_errstats != NULL) {				\
		struct sd_errstats *stp;				\
		ASSERT(mutex_owned(SD_MUTEX(un)));			\
		stp = (struct sd_errstats *)(un)->un_errstats->ks_data;	\
		stp->x.value.ui32++;					\
	}

#define	SD_UPDATE_RDWR_STATS(un, bp)					\
	if ((un)->un_stats != NULL) {					\
		kstat_io_t *kip = KSTAT_IO_PTR((un)->un_stats);		\
		size_t n_done = (bp)->b_bcount - (bp)->b_resid;		\
		if ((bp)->b_flags & B_READ) {				\
			kip->reads++;					\
			kip->nread += n_done;				\
		} else {						\
			kip->writes++;					\
			kip->nwritten += n_done;			\
		}							\
	}

#define	SD_UPDATE_PARTITION_STATS(un, bp)				\
{									\
	struct kstat *pksp = (un)->un_pstats[SDPART((bp)->b_edev)];	\
	if (pksp != NULL) {						\
		kstat_io_t *kip = KSTAT_IO_PTR(pksp);			\
		size_t n_done = (bp)->b_bcount - (bp)->b_resid;		\
		if ((bp)->b_flags & B_READ) {				\
			kip->reads++;					\
			kip->nread += n_done;				\
		} else {						\
			kip->writes++;					\
			kip->nwritten += n_done;			\
		}							\
	}								\
}


#endif	/* defined(_KERNEL) || defined(_KMEMUSER) */


/*
 * 60 seconds is a *very* reasonable amount of time for most slow CD
 * operations.
 */
#define	SD_IO_TIME			60

/*
 * 2 hours is an excessively reasonable amount of time for format operations.
 */
#define	SD_FMT_TIME			(120 * 60)

/*
 * 5 seconds is what we'll wait if we get a Busy Status back
 */
#define	SD_BSY_TIMEOUT			(drv_usectohz(5 * 1000000))

/*
 * 100 msec. is what we'll wait if we get Unit Attention.
 */
#define	SD_UA_RETRY_DELAY		(drv_usectohz((clock_t)100000))

/*
 * 100 msec. is what we'll wait for restarted commands.
 */
#define	SD_RESTART_TIMEOUT		(drv_usectohz((clock_t)100000))

/*
 * 10s misaligned I/O warning message interval
 */
#define	SD_RMW_MSG_PRINT_TIMEOUT	(drv_usectohz((clock_t)10000000))

/*
 * 100 msec. is what we'll wait for certain retries for fibre channel
 * targets, 0 msec for parallel SCSI.
 */
#if defined(__fibre)
#define	SD_RETRY_DELAY			(drv_usectohz(100000))
#else
#define	SD_RETRY_DELAY			((clock_t)0)
#endif

/*
 * 60 seconds is what we will wait for to reset the
 * throttle back to it SD_MAX_THROTTLE.
 */
#define	SD_RESET_THROTTLE_TIMEOUT	60

/*
 * Number of times we'll retry a normal operation.
 *
 * This includes retries due to transport failure
 * (need to distinguish between Target and Transport failure)
 *
 */
#if defined(__fibre)
#define	SD_RETRY_COUNT			3
#else
#define	SD_RETRY_COUNT			5
#endif

/*
 * Number of times we will retry for unit attention.
 */
#define	SD_UA_RETRY_COUNT		600

#define	SD_VICTIM_RETRY_COUNT(un)	(un->un_victim_retry_count)
#define	CD_NOT_READY_RETRY_COUNT(un)	(un->un_retry_count * 2)
#define	DISK_NOT_READY_RETRY_COUNT(un)	(un->un_retry_count / 2)


/*
 * Maximum number of units we can support
 * (controlled by room in minor device byte)
 *
 * Note: this value is out of date.
 */
#define	SD_MAXUNIT			32

/*
 * 30 seconds is what we will wait for the IO to finish
 * before we fail the DDI_SUSPEND
 */
#define	SD_WAIT_CMDS_COMPLETE		30

/*
 * Prevent/allow media removal flags
 */
#define	SD_REMOVAL_ALLOW		0
#define	SD_REMOVAL_PREVENT		1


/*
 * Drive Types (and characteristics)
 */
#define	VIDMAX				8
#define	PIDMAX				16


/*
 * The following #defines and type definitions for the property
 * processing component of the sd driver.
 */


/* Miscellaneous Definitions */
#define	SD_CONF_VERSION_1		1
#define	SD_CONF_NOT_USED		32

/*
 * "pm-capable" property values and macros
 */
#define	SD_PM_CAPABLE_UNDEFINED		-1

#define	SD_PM_CAPABLE_IS_UNDEFINED(pm_cap)	\
	(pm_cap == SD_PM_CAPABLE_UNDEFINED)

#define	SD_PM_CAPABLE_IS_FALSE(pm_cap)	\
	((pm_cap & PM_CAPABLE_PM_MASK) == 0)

#define	SD_PM_CAPABLE_IS_TRUE(pm_cap)	\
	(!SD_PM_CAPABLE_IS_UNDEFINED(pm_cap) && \
	    ((pm_cap & PM_CAPABLE_PM_MASK) > 0))

#define	SD_PM_CAPABLE_IS_SPC_4(pm_cap)	\
	((pm_cap & PM_CAPABLE_PM_MASK) == PM_CAPABLE_SPC4)

#define	SD_PM_CAP_LOG_SUPPORTED(pm_cap)	\
	((pm_cap & PM_CAPABLE_LOG_SUPPORTED) ? TRUE : FALSE)

#define	SD_PM_CAP_SMART_LOG(pm_cap)	\
	((pm_cap & PM_CAPABLE_SMART_LOG) ? TRUE : FALSE)

/*
 * Property data values used in static configuration table
 * These are all based on device characteristics.
 * For fibre channel devices, the throttle value is usually
 * derived from the devices cmd Q depth divided by the number
 * of supported initiators.
 */
#define	ELITE_THROTTLE_VALUE		10
#define	SEAGATE_THROTTLE_VALUE		15
#define	IBM_THROTTLE_VALUE		15
#define	ST31200N_THROTTLE_VALUE		8
#define	FUJITSU_THROTTLE_VALUE		15
#define	SYMBIOS_THROTTLE_VALUE		16
#define	SYMBIOS_NOTREADY_RETRIES	24
#define	LSI_THROTTLE_VALUE		16
#define	LSI_NOTREADY_RETRIES		24
#define	LSI_OEM_NOTREADY_RETRIES	36
#define	PURPLE_THROTTLE_VALUE		64
#define	PURPLE_BUSY_RETRIES		60
#define	PURPLE_RESET_RETRY_COUNT	36
#define	PURPLE_RESERVE_RELEASE_TIME	60
#define	SVE_BUSY_RETRIES		60
#define	SVE_RESET_RETRY_COUNT		36
#define	SVE_RESERVE_RELEASE_TIME	60
#define	SVE_THROTTLE_VALUE		10
#define	SVE_MIN_THROTTLE_VALUE		2
#define	SVE_DISKSORT_DISABLED_FLAG	1
#define	MASERATI_DISKSORT_DISABLED_FLAG	1
#define	MASERATI_LUN_RESET_ENABLED_FLAG	1
#define	PIRUS_THROTTLE_VALUE		64
#define	PIRUS_NRR_COUNT			60
#define	PIRUS_BUSY_RETRIES		60
#define	PIRUS_RESET_RETRY_COUNT		36
#define	PIRUS_MIN_THROTTLE_VALUE	16
#define	PIRUS_DISKSORT_DISABLED_FLAG	0
#define	PIRUS_LUN_RESET_ENABLED_FLAG	1

/*
 * Driver Property Bit Flag definitions
 *
 * Unfortunately, for historical reasons, the bit-flag definitions are
 * different on SPARC, INTEL, & FIBRE platforms.
 */

/*
 * Bit flag telling driver to set throttle from sd.conf sd-config-list
 * and driver table.
 *
 * The max throttle (q-depth) property implementation is for support of
 * fibre channel devices that can drop an i/o request when a queue fills
 * up. The number of commands sent to the disk from this driver is
 * regulated such that queue overflows are avoided.
 */
#define	SD_CONF_SET_THROTTLE		0
#define	SD_CONF_BSET_THROTTLE		(1 << SD_CONF_SET_THROTTLE)

/*
 * Bit flag telling driver to set the controller type from sd.conf
 * sd-config-list and driver table.
 */
#if defined(__i386) || defined(__amd64)
#define	SD_CONF_SET_CTYPE		1
#elif defined(__fibre)
#define	SD_CONF_SET_CTYPE		5
#else
#define	SD_CONF_SET_CTYPE		1
#endif
#define	SD_CONF_BSET_CTYPE		(1 << SD_CONF_SET_CTYPE)

/*
 * Bit flag telling driver to set the not ready retry count for a device from
 * sd.conf sd-config-list and driver table.
 */
#if defined(__i386) || defined(__amd64)
#define	SD_CONF_SET_NOTREADY_RETRIES	10
#elif defined(__fibre)
#define	SD_CONF_SET_NOTREADY_RETRIES	1
#else
#define	SD_CONF_SET_NOTREADY_RETRIES	2
#endif
#define	SD_CONF_BSET_NRR_COUNT		(1 << SD_CONF_SET_NOTREADY_RETRIES)

/*
 * Bit flag telling driver to set SCSI status BUSY Retries from sd.conf
 * sd-config-list and driver table.
 */
#if defined(__i386) || defined(__amd64)
#define	SD_CONF_SET_BUSY_RETRIES 	11
#elif defined(__fibre)
#define	SD_CONF_SET_BUSY_RETRIES 	2
#else
#define	SD_CONF_SET_BUSY_RETRIES 	5
#endif
#define	SD_CONF_BSET_BSY_RETRY_COUNT	(1 << SD_CONF_SET_BUSY_RETRIES)

/*
 * Bit flag telling driver that device does not have a valid/unique serial
 * number.
 */
#if defined(__i386) || defined(__amd64)
#define	SD_CONF_SET_FAB_DEVID		2
#else
#define	SD_CONF_SET_FAB_DEVID		3
#endif
#define	SD_CONF_BSET_FAB_DEVID   	(1 << SD_CONF_SET_FAB_DEVID)

/*
 * Bit flag telling driver to disable all caching for disk device.
 */
#if defined(__i386) || defined(__amd64)
#define	SD_CONF_SET_NOCACHE		3
#else
#define	SD_CONF_SET_NOCACHE		4
#endif
#define	SD_CONF_BSET_NOCACHE		(1 << SD_CONF_SET_NOCACHE)

/*
 * Bit flag telling driver that the PLAY AUDIO command requires parms in BCD
 * format rather than binary.
 */
#if defined(__i386) || defined(__amd64)
#define	SD_CONF_SET_PLAYMSF_BCD		4
#else
#define	SD_CONF_SET_PLAYMSF_BCD		6
#endif
#define	SD_CONF_BSET_PLAYMSF_BCD    	(1 << SD_CONF_SET_PLAYMSF_BCD)

/*
 * Bit flag telling driver that the response from the READ SUBCHANNEL command
 * has BCD fields rather than binary.
 */
#if defined(__i386) || defined(__amd64)
#define	SD_CONF_SET_READSUB_BCD		5
#else
#define	SD_CONF_SET_READSUB_BCD		7
#endif
#define	SD_CONF_BSET_READSUB_BCD	(1 << SD_CONF_SET_READSUB_BCD)

/*
 * Bit in flags telling driver that the track number fields in the READ TOC
 * request and respone are in BCD rather than binary.
 */
#if defined(__i386) || defined(__amd64)
#define	SD_CONF_SET_READ_TOC_TRK_BCD	6
#else
#define	SD_CONF_SET_READ_TOC_TRK_BCD	8
#endif
#define	SD_CONF_BSET_READ_TOC_TRK_BCD	(1 << SD_CONF_SET_READ_TOC_TRK_BCD)

/*
 * Bit flag telling driver that the address fields in the READ TOC request and
 * respone are in BCD rather than binary.
 */
#if defined(__i386) || defined(__amd64)
#define	SD_CONF_SET_READ_TOC_ADDR_BCD	7
#else
#define	SD_CONF_SET_READ_TOC_ADDR_BCD	9
#endif
#define	SD_CONF_BSET_READ_TOC_ADDR_BCD	(1 << SD_CONF_SET_READ_TOC_ADDR_BCD)

/*
 * Bit flag telling the driver that the device doesn't support the READ HEADER
 * command.
 */
#if defined(__i386) || defined(__amd64)
#define	SD_CONF_SET_NO_READ_HEADER	8
#else
#define	SD_CONF_SET_NO_READ_HEADER	10
#endif
#define	SD_CONF_BSET_NO_READ_HEADER 	(1 << SD_CONF_SET_NO_READ_HEADER)

/*
 * Bit flag telling the driver that for the READ CD command the device uses
 * opcode 0xd4 rather than 0xbe.
 */
#if defined(__i386) || defined(__amd64)
#define	SD_CONF_SET_READ_CD_XD4		9
#else
#define	SD_CONF_SET_READ_CD_XD4 	11
#endif
#define	SD_CONF_BSET_READ_CD_XD4	(1 << SD_CONF_SET_READ_CD_XD4)

/*
 * Bit flag telling the driver to set SCSI status Reset Retries
 * (un_reset_retry_count) from sd.conf sd-config-list and driver table (4356701)
 */
#define	SD_CONF_SET_RST_RETRIES		12
#define	SD_CONF_BSET_RST_RETRIES	(1 << SD_CONF_SET_RST_RETRIES)

/*
 * Bit flag telling the driver to set the reservation release timeout value
 * from sd.conf sd-config-list and driver table. (4367306)
 */
#define	SD_CONF_SET_RSV_REL_TIME	13
#define	SD_CONF_BSET_RSV_REL_TIME	(1 << SD_CONF_SET_RSV_REL_TIME)

/*
 * Bit flag telling the driver to verify that no commands are pending for a
 * device before issuing a Test Unit Ready. This is a fw workaround for Seagate
 * eliteI drives. (4392016)
 */
#define	SD_CONF_SET_TUR_CHECK		14
#define	SD_CONF_BSET_TUR_CHECK		(1 << SD_CONF_SET_TUR_CHECK)

/*
 * Bit in flags telling driver to set min. throttle from ssd.conf
 * ssd-config-list and driver table.
 */
#define	SD_CONF_SET_MIN_THROTTLE	15
#define	SD_CONF_BSET_MIN_THROTTLE	(1 << SD_CONF_SET_MIN_THROTTLE)

/*
 * Bit in flags telling driver to set disksort disable flag from ssd.conf
 * ssd-config-list and driver table.
 */
#define	SD_CONF_SET_DISKSORT_DISABLED	16
#define	SD_CONF_BSET_DISKSORT_DISABLED	(1 << SD_CONF_SET_DISKSORT_DISABLED)

/*
 * Bit in flags telling driver to set LUN Reset enable flag from [s]sd.conf
 * [s]sd-config-list and driver table.
 */
#define	SD_CONF_SET_LUN_RESET_ENABLED	17
#define	SD_CONF_BSET_LUN_RESET_ENABLED	(1 << SD_CONF_SET_LUN_RESET_ENABLED)

/*
 * Bit in flags telling driver that the write cache on the device is
 * non-volatile.
 */
#define	SD_CONF_SET_CACHE_IS_NV	18
#define	SD_CONF_BSET_CACHE_IS_NV	(1 << SD_CONF_SET_CACHE_IS_NV)

/*
 * Bit in flags telling driver that the power condition flag from [s]sd.conf
 * [s]sd-config-list and driver table.
 */
#define	SD_CONF_SET_PC_DISABLED	19
#define	SD_CONF_BSET_PC_DISABLED	(1 << SD_CONF_SET_PC_DISABLED)

/*
 * This is the number of items currently settable in the sd.conf
 * sd-config-list.  The mask value is defined for parameter checking. The
 * item count and mask should be updated when new properties are added.
 */
#define	SD_CONF_MAX_ITEMS		19
#define	SD_CONF_BIT_MASK		0x0007FFFF

typedef struct {
	int sdt_throttle;
	int sdt_ctype;
	int sdt_not_rdy_retries;
	int sdt_busy_retries;
	int sdt_reset_retries;
	int sdt_reserv_rel_time;
	int sdt_min_throttle;
	int sdt_disk_sort_dis;
	int sdt_lun_reset_enable;
	int sdt_suppress_cache_flush;
	int sdt_power_condition_dis;
} sd_tunables;

/* Type definition for static configuration table entries */
typedef struct sd_disk_config {
	char	device_id[25];
	uint_t	flags;
	sd_tunables *properties;
} sd_disk_config_t;

/*
 * first 2 bits of byte 4 options for 1bh command
 */
#define	SD_TARGET_STOP			0x00
#define	SD_TARGET_START			0x01
#define	SD_TARGET_EJECT			0x02
#define	SD_TARGET_CLOSE			0x03

/*
 * power condition of byte 4 for 1bh command
 */
#define	SD_TARGET_START_VALID		0x00
#define	SD_TARGET_ACTIVE		0x01
#define	SD_TARGET_IDLE			0x02
#define	SD_TARGET_STANDBY		0x03


#define	SD_MODE_SENSE_PAGE3_CODE	0x03
#define	SD_MODE_SENSE_PAGE4_CODE	0x04

#define	SD_MODE_SENSE_PAGE3_LENGTH					\
	(sizeof (struct mode_format) + MODE_PARAM_LENGTH)
#define	SD_MODE_SENSE_PAGE4_LENGTH					\
	(sizeof (struct mode_geometry) + MODE_PARAM_LENGTH)

/*
 * These command codes need to be moved to sys/scsi/generic/commands.h
 */

/* Both versions of the Read CD command */

/* the official SCMD_READ_CD now comes from cdio.h */
#define	SCMD_READ_CDD4		0xd4	/* the one used by some first */
					/* generation ATAPI CD drives */

/* expected sector type filter values for Play and Read CD CDBs */
#define	CDROM_SECTOR_TYPE_CDDA		(1<<2)	/* IEC 908:1987 (CDDA) */
#define	CDROM_SECTOR_TYPE_MODE1		(2<<2)	/* Yellow book 2048 bytes */
#define	CDROM_SECTOR_TYPE_MODE2		(3<<2)	/* Yellow book 2335 bytes */
#define	CDROM_SECTOR_TYPE_MODE2_FORM1	(4<<2)	/* 2048 bytes */
#define	CDROM_SECTOR_TYPE_MODE2_FORM2	(5<<2)	/* 2324 bytes */

/* READ CD filter bits (cdb[9]) */
#define	CDROM_READ_CD_SYNC	0x80	/* read sync field */
#define	CDROM_READ_CD_HDR	0x20	/* read four byte header */
#define	CDROM_READ_CD_SUBHDR	0x40	/* read sub-header */
#define	CDROM_READ_CD_ALLHDRS	0x60	/* read header and sub-header */
#define	CDROM_READ_CD_USERDATA	0x10	/* read user data */
#define	CDROM_READ_CD_EDC_ECC	0x08	/* read EDC and ECC field */
#define	CDROM_READ_CD_C2	0x02	/* read C2 error data */
#define	CDROM_READ_CD_C2_BEB	0x04	/* read C2 and Block Error Bits */


/*
 * These belong in sys/scsi/generic/mode.h
 */

/*
 * Mode Sense/Select Header response for Group 2 CDB.
 */

struct mode_header_grp2 {
	uchar_t length_msb;		/* MSB - number of bytes following */
	uchar_t length_lsb;
	uchar_t medium_type;		/* device specific */
	uchar_t device_specific;	/* device specfic parameters */
	uchar_t resv[2];		/* reserved */
	uchar_t bdesc_length_hi;	/* length of block descriptor(s) */
					/* (if any) */
	uchar_t bdesc_length_lo;
};

_NOTE(SCHEME_PROTECTS_DATA("Unshared data", mode_header_grp2))

/*
 * Length of the Mode Parameter Header for the Group 2 Mode Select command
 */
#define	MODE_HEADER_LENGTH_GRP2	(sizeof (struct mode_header_grp2))
#define	MODE_PARAM_LENGTH_GRP2 (MODE_HEADER_LENGTH_GRP2 + MODE_BLK_DESC_LENGTH)

/*
 * Mode Page 1 - Error Recovery Page
 */
#define	MODEPAGE_ERR_RECOVER		1

/*
 * The following buffer length define is 8 bytes for the Group 2 mode page
 * header, 8 bytes for the block descriptor and 26 bytes for the cdrom
 * capabilities page (per MMC-2)
 */
#define	MODEPAGE_CDROM_CAP		0x2A
#define	MODEPAGE_CDROM_CAP_LEN		26
#define	BUFLEN_MODE_CDROM_CAP		(MODEPAGE_CDROM_CAP_LEN + \
	MODE_HEADER_LENGTH_GRP2 + MODE_BLK_DESC_LENGTH)


/*
 * Power management defines
 */
#define	SD_SPINDLE_UNINIT	(-1)
#define	SD_SPINDLE_OFF		0
#define	SD_SPINDLE_ON		1
#define	SD_SPINDLE_STOPPED	0
#define	SD_SPINDLE_STANDBY	1
#define	SD_SPINDLE_IDLE		2
#define	SD_SPINDLE_ACTIVE	3
#define	SD_PM_NOT_SUPPORTED	4

/*
 * Power method flag
 */
#define	SD_START_STOP		0
#define	SD_POWER_CONDITION	1


/*
 * Number of power level for start stop or power condition
 */
#define	SD_PM_NUM_LEVEL_SSU_SS	2
#define	SD_PM_NUM_LEVEL_SSU_PC	4

/*
 * SD internal power state change flag
 */
#define	SD_PM_STATE_CHANGE	0
#define	SD_PM_STATE_ROLLBACK	1

/*
 * Power attribute table
 */
typedef struct disk_power_attr_ss {
	char *pm_comp[SD_PM_NUM_LEVEL_SSU_SS + 2];	/* pm component */
	int ran_perf[SD_PM_NUM_LEVEL_SSU_SS];		/* random performance */
	int pwr_saving[SD_PM_NUM_LEVEL_SSU_SS];		/* power saving */
	int latency[SD_PM_NUM_LEVEL_SSU_SS];		/* latency */
}sd_power_attr_ss;

typedef struct disk_power_attr_pc {
	char *pm_comp[SD_PM_NUM_LEVEL_SSU_PC + 2];	/* pm component */
	int ran_perf[SD_PM_NUM_LEVEL_SSU_PC];		/* random performance */
	int pwr_saving[SD_PM_NUM_LEVEL_SSU_PC];		/* power saving */
	int latency[SD_PM_NUM_LEVEL_SSU_PC];		/* latency */
}sd_power_attr_pc;


/*
 * No Need to resume if already in PM_SUSPEND state because the thread
 * was suspended in sdpower. It will be resumed when sdpower is invoked to make
 * the device active.
 * When the thread is suspended, the watch thread is terminated and
 * the token is NULLed so check for this condition.
 * If there's a thread that can be resumed, ie. token is not NULL, then
 * it can be resumed.
 */
#define	SD_OK_TO_RESUME_SCSI_WATCHER(un)	(un->un_swr_token != NULL)
/*
 * No Need to resume if already in PM_SUSPEND state because the thread
 * was suspended in sdpower. It will be resumed when sdpower is invoked to make
 * the device active.
 * When the thread is suspended, the watch thread is terminated and
 * the token is NULLed so check for this condition.
 */
#define	SD_OK_TO_SUSPEND_SCSI_WATCHER(un)	(un->un_swr_token != NULL)
#define	SD_DEVICE_IS_IN_LOW_POWER(un)		((un->un_f_pm_is_enabled) && \
						    (un->un_pm_count < 0))
#define	SD_PM_STATE_ACTIVE(un)				\
		(un->un_f_power_condition_supported ?	\
		SD_SPINDLE_ACTIVE : SD_SPINDLE_ON)
#define	SD_PM_STATE_STOPPED(un)				\
		(un->un_f_power_condition_supported ?	\
		SD_SPINDLE_STOPPED : SD_SPINDLE_OFF)
#define	SD_PM_IS_LEVEL_VALID(un, level)			\
		((un->un_f_power_condition_supported &&	\
		level >= SD_SPINDLE_STOPPED &&		\
		level <= SD_SPINDLE_ACTIVE) ||		\
		(!un->un_f_power_condition_supported &&	\
		level >= SD_SPINDLE_OFF &&		\
		level <= SD_SPINDLE_ON))
#define	SD_PM_IS_IO_CAPABLE(un, level)			\
		((un->un_f_power_condition_supported &&	\
		sd_pwr_pc.ran_perf[level] > 0) ||	\
		(!un->un_f_power_condition_supported &&	\
		sd_pwr_ss.ran_perf[level] > 0))
#define	SD_PM_STOP_MOTOR_NEEDED(un, level)		\
		((un->un_f_power_condition_supported &&	\
		level <= SD_SPINDLE_STANDBY) ||		\
		(!un->un_f_power_condition_supported &&	\
		level == SD_SPINDLE_OFF))

/*
 * Could move this define to some thing like log sense.h in SCSA headers
 * But for now let it live here.
 */
#define	START_STOP_CYCLE_COUNTER_PAGE_SIZE	0x28
#define	START_STOP_CYCLE_PAGE			0x0E
#define	START_STOP_CYCLE_VU_PAGE		0x31

/* CD-ROM Error Recovery Parameters page (0x01) */
#define	MODEPAGE_ERR_RECOV	0x1
#define	BUFLEN_CHG_BLK_MODE	MODE_HEADER_LENGTH + MODE_BLK_DESC_LENGTH

/*
 * Vendor Specific (Toshiba) CD-ROM Speed page (0x31)
 *
 * The following buffer length define is 4 bytes for the Group 0 mode page
 * header, 8 bytes for the block descriptor and 4 bytes for the mode speed page.
 */
#define	MODEPAGE_CDROM_SPEED_LEN	4
#define	BUFLEN_MODE_CDROM_SPEED		MODEPAGE_CDROM_SPEED_LEN +\
					MODE_HEADER_LENGTH +\
					MODE_BLK_DESC_LENGTH
#define	SD_SPEED_1X			176

/* CD-ROM Audio Control Parameters page (0x0E) */
#define	MODEPAGE_AUDIO_CTRL		0x0E
#define	MODEPAGE_AUDIO_CTRL_LEN		16

/* CD-ROM Sony Read Offset Defines */
#define	SONY_SESSION_OFFSET_LEN		12
#define	SONY_SESSION_OFFSET_KEY		0x40
#define	SONY_SESSION_OFFSET_VALID	0x0a

/*
 * CD-ROM Write Protect Defines
 *
 * Bit 7 of the device specific field of the mode page header is the write
 * protect bit.
 */
#define	WRITE_PROTECT 0x80

/*
 * Define for the length of a profile header returned in response to the
 * GET CONFIGURATION command
 */
#define	SD_PROFILE_HEADER_LEN		8	/* bytes */

/*
 * Define the length of the data in response to the GET CONFIGURATION
 * command.  The 3rd byte of the feature descriptor contains the
 * current feature field that is of interest.  This field begins
 * after the feature header which is 8 bytes.  This variable length
 * was increased in size from 11 to 24 because some devices became
 * unresponsive with the smaller size.
 */
#define	SD_CURRENT_FEATURE_LEN		24	/* bytes */

/*
 * Feature codes associated with GET CONFIGURATION command for supported
 * devices.
 */
#define	RANDOM_WRITABLE			0x20
#define	HARDWARE_DEFECT_MANAGEMENT	0x24

/*
 * Could move this define to some thing like log sense.h in SCSA headers
 * But for now let it live here.
 */
#define	TEMPERATURE_PAGE			0x0D
#define	TEMPERATURE_PAGE_SIZE			16	/* bytes */

/* delay time used for sd_media_watch_cb delayed cv broadcast */
#define	MEDIA_ACCESS_DELAY 2000000


/* SCSI power on or bus device reset additional sense code */
#define	SD_SCSI_RESET_SENSE_CODE	0x29

/*
 * These defines are for the Vital Product Data Pages in the inquiry command.
 * They are the bits in the un_vpd_page mask, telling the supported pages.
 */
#define	SD_VPD_SUPPORTED_PG	0x01	/* 0x00 - Supported VPD pages */
#define	SD_VPD_UNIT_SERIAL_PG	0x02	/* 0x80 - Unit Serial Number */
#define	SD_VPD_OPERATING_PG	0x04	/* 0x81 - Implemented Op Defs */
#define	SD_VPD_ASCII_OP_PG	0x08	/* 0x82 - ASCII Op Defs */
#define	SD_VPD_DEVID_WWN_PG	0x10	/* 0x83 - Device Identification */
#define	SD_VPD_EXTENDED_DATA_PG	0x80	/* 0x86 - Extended data about the lun */
#define	SD_VPD_DEV_CHARACTER_PG	0x400	/* 0xB1 - Device Characteristics */

/*
 * Non-volatile cache support
 *
 * Bit 1 of the byte 6 in the Extended INQUIRY data VPD page
 * is NV_SUP bit: An NV_SUP bit set to one indicates that
 * the device server supports a non-volatile cache.  An
 * NV_SUP bit set to zero indicates that the device
 * server may or may not support a non-volatile cache.
 *
 * Bit 2 of the byte 1 in the SYNC CACHE command is SYNC_NV
 * bit: The SYNC_NV bit specifies whether the device server
 * is required to synchronize volatile and non-volatile
 * caches.
 */
#define	SD_VPD_NV_SUP	0x02
#define	SD_SYNC_NV_BIT 0x04

/*
 * Addition from sddef.intel.h
 */
#if defined(__i386) || defined(__amd64)

#define	P0_RAW_DISK	(NDKMAP)
#define	FDISK_P1	(NDKMAP+1)
#define	FDISK_P2	(NDKMAP+2)
#define	FDISK_P3	(NDKMAP+3)
#define	FDISK_P4	(NDKMAP+4)

#endif	/* __i386 || __amd64 */

#ifdef	__cplusplus
}
#endif


#endif	/* _SYS_SCSI_TARGETS_SDDEF_H */
