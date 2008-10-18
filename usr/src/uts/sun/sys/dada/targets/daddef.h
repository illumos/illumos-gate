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
#ifndef	_SYS_DADA_TARGETS_DADDF_H
#define	_SYS_DADA_TARGETS_DADDF_H

#include <sys/note.h>
#include <sys/cmlb.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Defines for SCSI direct access devices
 */

#define	FIXEDFIRMWARE	/* fixed firmware for volume control */

#if	defined(_KERNEL) || defined(_KMEMUSER)


/*
 * Local definitions, for clarity of code
 */
#define	DCD_DCD_DEVP	(un->un_dcd)
#define	DCD_DEVINFO	(DCD_DCD_DEVP->dcd_dev)
#define	DCD_IDENTIFY	(DCD_DCD_DEVP->dcd_ident)
#define	DCD_MUTEX	(&DCD_DCD_DEVP->dcd_mutex)
#define	ROUTE		(DCD_DCD_DEVP->dcd_address)
#define	SECDIV		(un->un_secdiv)
#define	SECSIZE		(un->un_secsize)
#define	SCBP(pkt)	((struct dcd_status *)(pkt)->pkt_scbp)
#define	SCBP_C(pkt)	((*(pkt)->pkt_scbp) & STATUS_ATA_MASK)
#define	CDBP(pkt)	((union scsi_cdb *)(pkt)->pkt_cdbp)
#define	NO_PKT_ALLOCATED ((struct buf *)0)
#define	ALLOCATING_PKT	((struct buf *)-1)
#define	BP_PKT(bp)	((struct dcd_pkt *)bp->av_back)
#define	BP_HAS_NO_PKT(bp) (bp->av_back == NO_PKT_ALLOCATED)
#define	MAX_ATA_XFER_SIZE (256*DEV_BSIZE)

#define	STATUS_SCBP_C(statusp)	(*(uchar_t *)(statusp) & STATUS_ATA_MASK)

#define	Tgt(devp)	(devp->dcd_address->da_target)
#define	Lun(devp)	(devp->dcd_address->da_lun)

#define	New_state(un, s)	\
	(un)->un_last_state = (un)->un_state,  (un)->un_state = (s)
#define	Restore_state(un)	\
	{ uchar_t tmp = (un)->un_last_state; New_state((un), tmp); }


#define	CTYPE_DISK	 2
/*
 * Structure for recording whether a device is fully open or closed.
 * Assumptions:
 *
 *	+ There are only 8 partitions possible.
 *	+ BLK, MNT, CHR, SWP don't change in some future release!
 *
 */

#define	DCDUNIT_SHIFT	3
#define	DCDPART_MASK	7
#define	DCDUNIT(dev)	(getminor((dev))>>DCDUNIT_SHIFT)
#define	DCDPART(dev)	(getminor((dev)) & DCDPART_MASK)

struct ocinfo {
	/*
	 * Types BLK, MNT, CHR, SWP,
	 * assumed to be types 0-3.
	 */
	ulong_t  lyr_open[NDKMAP];
	uchar_t  reg_open[OTYPCNT - 1];
};
#define	OCSIZE  sizeof (struct ocinfo)
union ocmap {
	uchar_t chkd[OCSIZE];
	struct ocinfo rinfo;
};
#define	lyropen rinfo.lyr_open
#define	regopen rinfo.reg_open

/*
 * Private info for dcd disks.
 *
 * Pointed to by the un_private pointer
 * of one of the dcd_device structures.
 */

struct dcd_disk {
	struct dcd_device *un_dcd;	/* back pointer to dcd_device */
	struct dcd_drivetype *un_dp;	/* drive type table */
	struct	buf *un_sbufp;		/* for use in special io */
	char		*un_srqbufp;	/* sense buffer for special io */
	kcondvar_t	un_sbuf_cv;	/* Conditional Variable on sbufp */
	kcondvar_t	un_state_cv;	/* Conditional variable for state */
	union	ocmap un_ocmap;		/* open partition map, block && char */
	uchar_t	un_last_pkt_reason;	/* used for suppressing multiple msgs */
	struct	diskhd un_utab;		/* for queuing */
	struct	kstat *un_stats;	/* for statistics */
	struct	kstat *un_pstats[NDKMAP]; /* for partition statistics */
	ksema_t	un_semoclose;		/* lock for serializing opens/closes */
	uint_t	un_err_blkno;		/* disk block where error occurred */
	int	un_diskcapacity;	/* capacity as returned by drive */
	int	un_lbasize;		/* logical (i.e. device) block size */
	int	un_lbadiv;		/* log2 of lbasize */
	int	un_blknoshift;		/* log2 of multiple of DEV_BSIZE */
					/* blocks making up a logical block */
	int	un_secsize;		/* sector size (allow request on */
					/* this boundry) */
	int	un_secdiv;		/* log2 of secsize */
	uchar_t	un_exclopen;		/* exclusive open bits */
	uchar_t	un_mediastate;		/* Is it really needed  XXX */
	uchar_t	un_state;		/* current state */
	uchar_t	un_last_state;		/* last state */
	uchar_t	un_format_in_progress;	/* disk is formatting currently */
	uchar_t un_flush_not_supported;	/* disk doesn't support flush cmd */
	uchar_t	un_write_cache_enabled;	/* disk has write caching enabled */
	clock_t un_timestamp;		/* Time of last device access */
	short	un_ncmds;		/* number of cmds in transport */
	short	un_throttle;		/* This is used for throttling if */
					/* HBA has queuing		  */
	short	un_sbuf_busy;		/* Busy wait flag for the sbuf */
	int	un_cmd_flags;		/* cache some frequently used values */
	int	un_cmd_stat_size;	/* in make_sd_cmd */
	int	un_dcvb_timeid;		/* timeout id for dlyd cv broadcast */
	void 	*un_devid;		/* device id */
	uint_t	un_max_xfer_size;	/* max transfer size */
	uchar_t	un_bus_master;		/* Indicates that the HBA  enables  */
					/* Bus master capability */
	timeout_id_t	un_reissued_timeid;
					/* This is used in busy handler */
	kstat_t	*un_errstats;		/* For Error statsistics */
	kcondvar_t	un_suspend_cv;	/* Cond Var on power management */
	kcondvar_t	un_disk_busy_cv; /* Cond var to wait for IO */
	short	un_power_level;		/* Power Level */
	short	un_save_state;		/* Save the state for suspend/resume */
	cmlb_handle_t   un_dklbhandle;  /* Handle for disk label */
	tg_attribute_t un_tgattribute;
};

/*
 * device error statistics
 */
struct dcd_errstats {
	struct kstat_named	dcd_softerrs;	/* Collecting Softerrs */
	struct kstat_named	dcd_harderrs;	/* Collecting harderrs */
	struct kstat_named	dcd_transerrs;	/* Collecting Transfer errs */
	struct kstat_named	dcd_model;	/* model # of the disk */
	struct kstat_named	dcd_revision;	/* The disk revision */
	struct kstat_named	dcd_serial;	/* The disk serial number */
	struct kstat_named	dcd_capacity;	/* Capacity of the disk */
	struct kstat_named	dcd_rq_media_err; /* Any media err seen */
	struct kstat_named	dcd_rq_ntrdy_err; /* Not ready errs */
	struct kstat_named	dcd_rq_nodev_err; /* No device errs */
	struct kstat_named	dcd_rq_recov_err; /* Recovered errs */
	struct kstat_named	dcd_rq_illrq_err; /* Illegal requests */
};
#define	DCD_MAX_XFER_SIZE	(1 * 512)

_NOTE(MUTEX_PROTECTS_DATA(dcd_device::dcd_mutex, dcd_disk))
_NOTE(READ_ONLY_DATA(dcd_disk::un_dcd))
_NOTE(READ_ONLY_DATA(dcd_disk::un_cmd_stat_size))
_NOTE(SCHEME_PROTECTS_DATA("Save Sharing",
	dcd_disk::un_state
	dcd_disk::un_dklbhandle
	dcd_disk::un_format_in_progress))

_NOTE(SCHEME_PROTECTS_DATA("stable data",
	dcd_disk::un_max_xfer_size
	dcd_disk::un_secdiv
	dcd_disk::un_secsize
	dcd_disk::un_cmd_flags
	dcd_disk::un_cmd_stat_size))

_NOTE(SCHEME_PROTECTS_DATA("cv",
	dcd_disk::un_sbufp
	dcd_disk::un_srqbufp
	dcd_disk::un_sbuf_busy))

_NOTE(SCHEME_PROTECTS_DATA("Unshared data",
	dk_cinfo
	uio
	buf
	dcd_pkt
	udcd_cmd
	dcd_capacity
	dcd_cmd
	dk_label
	dk_map32))

_NOTE(SCHEME_PROTECTS_DATA("stable data", dcd_device))
_NOTE(SCHEME_PROTECTS_DATA("unique per pkt", dcd_cmd))

#endif	/* defined(_KERNEL) || defined(_KMEMUSER) */


/*
 * Disk driver states
 */

#define	DCD_STATE_NORMAL	0
#define	DCD_STATE_OFFLINE	1
#define	DCD_STATE_RWAIT		2
#define	DCD_STATE_DUMPING	3
#define	DCD_STATE_SUSPENDED	4
#define	DCD_STATE_FATAL		5
#define	DCD_STATE_PM_SUSPENDED	6

/*
 * Disk power levels.
 */
#define	DCD_DEVICE_ACTIVE	0x2
#define	DCD_DEVICE_IDLE		0x1
#define	DCD_DEVICE_STANDBY	0x0

/*
 * Macros used in obtaining the device ID for the disk.
 */
#define	DCD_SERIAL_NUMBER_LENGTH	20
#define	DCD_MODEL_NUMBER_LENGTH		40

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
 *			NORMAL  OFFLINE  RWAIT  DUMPING  SUSPENDED
 *
 *	NORMAL		-	(a)	(b)	(c)	(d)
 *
 *	OFFLINE		(e)	-	(e)	(c)	(d)
 *
 *	RWAIT		(f)	NP	-	(c)	(d)
 *
 *	DUMPING		NP	NP	NP	-	NP
 *
 *	SUSPENDED	(g)	(g)	(b)	NP*	-
 *
 *
 *	NP:	Not Possible.
 *	(a):	Disk does not respond.
 *	(b):	Packet Allocation Fails
 *	(c):	Panic - Crash dump
 *	(d):	DDI_SUSPEND is called.
 *	(e):	Disk has a successful I/O completed.
 *	(f):	sdrunout() calls sdstart() which sets it NORMAL
 *	(g):	DDI_RESUME is called.
 *	* :	When suspended, we dont change state during panic dump
 */


/*
 * Error levels
 */

#define	DCDERR_ALL		0
#define	DCDERR_UNKNOWN		1
#define	DCDERR_INFORMATIONAL	2
#define	DCDERR_RECOVERED	3
#define	DCDERR_RETRYABLE	4
#define	DCDERR_FATAL		5

/*
 * Parameters
 */

/*
 * 60 seconds is a *very* reasonable amount of time for most slow CD
 * operations.
 */

#define	DCD_IO_TIME	60

/*
 * Timeout value for ATA_FLUSH_CACHE used in DKIOCFLUSHWRITECACHE
 */
#define	DCD_FLUSH_TIME	60

/*
 * 2 hours is an excessively reasonable amount of time for format operations.
 */

#define	DCD_FMT_TIME	120*60

/*
 * 5 seconds is what we'll wait if we get a Busy Status back
 */

#define	DCD_BSY_TIMEOUT		(drv_usectohz(5 * 1000000))

/*
 * Number of times we'll retry a normal operation.
 *
 * This includes retries due to transport failure
 * (need to distinguish between Target and Transport failure)
 */

#define	DCD_RETRY_COUNT		5


/*
 * Maximum number of units we can support
 * (controlled by room in minor device byte)
 * XXX: this is out of date!
 */
#define	DCD_MAXUNIT		32

/*
 * 30 seconds is what we will wait for the IO to finish
 * before we fail the DDI_SUSPEND
 */
#define	DCD_WAIT_CMDS_COMPLETE	30

/*
 * dcdintr action codes
 */

#define	COMMAND_DONE		0
#define	COMMAND_DONE_ERROR	1
#define	QUE_COMMAND		2
#define	QUE_SENSE		3
#define	JUST_RETURN		4

/*
 * Indicator for Soft and hard errors
 */
#define	COMMAND_SOFT_ERROR	1
#define	COMMAND_HARD_ERROR	2

/*
 * Drive Types (and characteristics)
 */
#define	VIDMAX 8
#define	PIDMAX 16

struct dcd_drivetype {
	char 	*name;		/* for debug purposes */
	char	ctype;		/* controller type */
	char	options;	/* drive options */
	ushort_t block_factor;	/* Block mode factor */
	char	pio_mode;	/* This the Pio mode number */
	char 	dma_mode;	/* Multi word dma mode */
};

/*
 * The options values
 */
#define	DMA_SUPPORTTED	0x01
#define	BLOCK_MODE	0x02

#ifndef	LOG_EMERG
#define	LOG_WARNING	CE_NOTE
#define	LOG_NOTICE	CE_NOTE
#define	LOG_CRIT	CE_WARN
#define	LOG_ERR		CE_WARN
#define	LOG_INFO	CE_NOTE
#define	log	cmn_err
#endif

/*
 * Some internal error codes for driver functions.
 */
#define	DCD_EACCES	1

/*
 * Error returns from sd_validate_geometry()
 */
#define	DCD_BAD_LABEL		-1
#define	DCD_NO_MEM_FOR_LABEL	-2

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_DADA_TARGETS_DADDF_H */
