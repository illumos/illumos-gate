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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_VDC_H
#define	_VDC_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Virtual disk client implementation definitions
 */

#include <sys/sysmacros.h>
#include <sys/note.h>

#include <sys/ldc.h>
#include <sys/vio_mailbox.h>
#include <sys/vdsk_mailbox.h>
#include <sys/vdsk_common.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	VDC_DRIVER_NAME		"vdc"

/*
 * Bit-field values to indicate if parts of the vdc driver are initialised.
 */
#define	VDC_SOFT_STATE	0x0001
#define	VDC_LOCKS	0x0002
#define	VDC_MINOR	0x0004
#define	VDC_THREAD	0x0008
#define	VDC_LDC		0x0010
#define	VDC_LDC_INIT	0x0020
#define	VDC_LDC_CB	0x0040
#define	VDC_LDC_OPEN	0x0080
#define	VDC_DRING_INIT	0x0100	/* The DRing was created */
#define	VDC_DRING_BOUND	0x0200	/* The DRing was bound to an LDC channel */
#define	VDC_DRING_LOCAL	0x0400	/* The local private DRing was allocated */
#define	VDC_DRING_ENTRY	0x0800	/* At least one DRing entry was initialised */
#define	VDC_DRING	(VDC_DRING_INIT | VDC_DRING_BOUND |	\
				VDC_DRING_LOCAL | VDC_DRING_ENTRY)
#define	VDC_HANDSHAKE	0x1000	/* Indicates if a handshake is in progress */
#define	VDC_HANDSHAKE_STOP	0x2000	/* stop further handshakes */

/*
 * Definitions of strings to be used to create device node properties.
 * (vdc uses the capitalised versions of these properties as they are 64-bit)
 */
#define	VDC_NBLOCKS_PROP_NAME		"Nblocks"
#define	VDC_SIZE_PROP_NAME		"Size"

/*
 * Definitions of MD nodes/properties.
 */
#define	VDC_MD_CHAN_NAME		"channel-endpoint"
#define	VDC_MD_VDEV_NAME		"virtual-device"
#define	VDC_MD_PORT_NAME		"virtual-device-port"
#define	VDC_MD_DISK_NAME		"disk"
#define	VDC_MD_CFG_HDL			"cfg-handle"
#define	VDC_MD_TIMEOUT			"vdc-timeout"
#define	VDC_MD_ID			"id"

/*
 * Definition of actions to be carried out when processing the sequence ID
 * of a message received from the vDisk server. The function verifying the
 * sequence number checks the 'seq_num_xxx' fields in the soft state and
 * returns whether the message should be processed (VDC_SEQ_NUM_TODO) or
 * whether it was it was previously processed (VDC_SEQ_NUM_SKIP).
 */
#define	VDC_SEQ_NUM_INVALID		-1	/* Error */
#define	VDC_SEQ_NUM_SKIP		0	/* Request already processed */
#define	VDC_SEQ_NUM_TODO		1	/* Request needs processing */

/*
 * Macros to get UNIT and PART number
 */
#define	VDCUNIT_SHIFT	3
#define	VDCPART_MASK	7

#define	VDCUNIT(dev)	(getminor((dev)) >> VDCUNIT_SHIFT)
#define	VDCPART(dev)	(getminor((dev)) &  VDCPART_MASK)

/*
 * Scheme to store the instance number and the slice number in the minor number.
 * (NOTE: Uses the same format and definitions as the sd(7D) driver)
 */
#define	VD_MAKE_DEV(instance, minor)	((instance << VDCUNIT_SHIFT) | minor)

/*
 * variables controlling how long to wait before timing out and how many
 * retries to attempt before giving up when communicating with vds.
 *
 * These values need to be sufficiently large so that a guest can survive
 * the reboot of the service domain.
 */
#define	VDC_RETRIES	10

#define	VDC_USEC_TIMEOUT_MIN	(30 * MICROSEC)		/* 30 sec */

/*
 * This macro returns the number of Hz that the vdc driver should wait before
 * a timeout is triggered. The 'timeout' parameter specifiecs the wait
 * time in Hz. The 'mul' parameter allows for a multiplier to be
 * specified allowing for a backoff to be implemented (e.g. using the
 * retry number as a multiplier) where the wait time will get longer if
 * there is no response on the previous retry.
 */
#define	VD_GET_TIMEOUT_HZ(timeout, mul)	\
	(ddi_get_lbolt() + ((timeout) * MAX(1, (mul))))

/*
 * Macros to manipulate Descriptor Ring variables in the soft state
 * structure.
 */
#define	VDC_GET_NEXT_REQ_ID(vdc)	((vdc)->req_id++)

#define	VDC_GET_DRING_ENTRY_PTR(vdc, idx)	\
		(vd_dring_entry_t *)(uintptr_t)((vdc)->dring_mem_info.vaddr + \
			(idx * (vdc)->dring_entry_size))

#define	VDC_MARK_DRING_ENTRY_FREE(vdc, idx)			\
	{ \
		vd_dring_entry_t *dep = NULL;				\
		ASSERT(vdc != NULL);					\
		ASSERT(idx < vdc->dring_len);		\
		ASSERT(vdc->dring_mem_info.vaddr != NULL);		\
		dep = (vd_dring_entry_t *)(uintptr_t)			\
			(vdc->dring_mem_info.vaddr +	\
			(idx * vdc->dring_entry_size));			\
		ASSERT(dep != NULL);					\
		dep->hdr.dstate = VIO_DESC_FREE;			\
	}

/* Initialise the Session ID and Sequence Num in the DRing msg */
#define	VDC_INIT_DRING_DATA_MSG_IDS(dmsg, vdc)		\
		ASSERT(vdc != NULL);			\
		dmsg.tag.vio_sid = vdc->session_id;	\
		dmsg.seq_num = vdc->seq_num;

/*
 * The states that the read thread can be in.
 */
typedef enum vdc_rd_state {
	VDC_READ_IDLE,			/* idling - conn is not up */
	VDC_READ_WAITING,		/* waiting for data */
	VDC_READ_PENDING,		/* pending data avail for read */
	VDC_READ_RESET			/* channel was reset - stop reads */
} vdc_rd_state_t;

/*
 * The states that the vdc-vds connection can be in.
 */
typedef enum vdc_state {
	VDC_STATE_INIT,			/* device is initialized */
	VDC_STATE_INIT_WAITING,		/* waiting for ldc connection */
	VDC_STATE_NEGOTIATE,		/* doing handshake negotiation */
	VDC_STATE_HANDLE_PENDING,	/* handle requests in backup dring */
	VDC_STATE_RUNNING,		/* running and accepting requests */
	VDC_STATE_DETACH,		/* detaching */
	VDC_STATE_RESETTING		/* resetting connection with vds */
} vdc_state_t;

/*
 * The states that the vdc instance can be in.
 */
typedef enum vdc_lc_state {
	VDC_LC_ATTACHING,	/* driver is attaching */
	VDC_LC_ONLINE,		/* driver is attached and online */
	VDC_LC_DETACHING	/* driver is detaching */
} vdc_lc_state_t;

/*
 * Local Descriptor Ring entry
 *
 * vdc creates a Local (private) descriptor ring the same size as the
 * public descriptor ring it exports to vds.
 */

typedef enum {
	VIO_read_dir,		/* read data from server */
	VIO_write_dir,		/* write data to server */
	VIO_both_dir		/* transfer both in and out in same buffer */
} vio_desc_direction_t;

typedef enum {
	CB_STRATEGY,		/* non-blocking strategy call */
	CB_SYNC			/* synchronous operation */
} vio_cb_type_t;

typedef struct vdc_local_desc {
	boolean_t		is_free;	/* local state - inuse or not */

	int			operation;	/* VD_OP_xxx to be performed */
	caddr_t			addr;		/* addr passed in by consumer */
	int			slice;
	diskaddr_t		offset;		/* disk offset */
	size_t			nbytes;
	vio_cb_type_t		cb_type;	/* operation type blk/nonblk */
	void			*cb_arg;	/* buf passed to strategy() */
	vio_desc_direction_t	dir;		/* direction of transfer */

	caddr_t			align_addr;	/* used if addr non-aligned */
	ldc_mem_handle_t	desc_mhdl;	/* Mem handle of buf */
	vd_dring_entry_t	*dep;		/* public Dring Entry Pointer */

} vdc_local_desc_t;

/*
 * vdc soft state structure
 */
typedef struct vdc {

	kmutex_t	lock;		/* protects next 2 sections of vars */
	kcondvar_t	running_cv;	/* signal when upper layers can send */
	kcondvar_t	initwait_cv;	/* signal when ldc conn is up */
	kcondvar_t	dring_free_cv;	/* signal when desc is avail */
	kcondvar_t	membind_cv;	/* signal when mem can be bound */
	boolean_t	self_reset;

	int		initialized;	/* keeps track of what's init'ed */
	vdc_lc_state_t	lifecycle;	/* Current state of the vdc instance */

	int		hshake_cnt;	/* number of failed handshakes */
	uint8_t		open[OTYPCNT];	/* mask of opened slices */
	uint8_t		open_excl;	/* mask of exclusively opened slices */
	ulong_t		open_lyr[V_NUMPAR]; /* number of layered opens */
	int		dkio_flush_pending; /* # outstanding DKIO flushes */
	int		validate_pending; /* # outstanding validate request */
	vd_disk_label_t vdisk_label; 	/* label type of device/disk imported */
	struct vtoc	*vtoc;		/* structure to store VTOC data */
	struct dk_geom	*geom;		/* structure to store geometry data */

	kthread_t	*msg_proc_thr;	/* main msg processing thread */

	kmutex_t	read_lock;	/* lock to protect read */
	kcondvar_t	read_cv;	/* cv to wait for READ events */
	vdc_rd_state_t	read_state;	/* current read state */

	uint32_t	sync_op_cnt;	/* num of active sync operations */
	boolean_t	sync_op_pending; /* sync operation is pending */
	boolean_t	sync_op_blocked; /* blocked waiting to do sync op */
	uint32_t	sync_op_status;	/* status of sync operation */
	kcondvar_t	sync_pending_cv; /* cv wait for sync op to finish */
	kcondvar_t	sync_blocked_cv; /* cv wait for other syncs to finish */

	uint64_t	session_id;	/* common ID sent with all messages */
	uint64_t	seq_num;	/* most recent sequence num generated */
	uint64_t	seq_num_reply;	/* Last seq num ACK/NACK'ed by vds */
	uint64_t	req_id;		/* Most recent Request ID generated */
	uint64_t	req_id_proc;	/* Last request ID processed by vdc */
	vdc_state_t	state;		/* Current disk client-server state */

	dev_info_t	*dip;		/* device info pointer */
	int		instance;	/* driver instance number */

	vio_ver_t	ver;		/* version number agreed with server */
	vd_disk_type_t	vdisk_type;	/* type of device/disk being imported */
	uint32_t	vdisk_media;	/* physical media type of vDisk */
	uint64_t	vdisk_size;	/* device size in blocks */
	uint64_t	max_xfer_sz;	/* maximum block size of a descriptor */
	uint64_t	block_size;	/* device block size used */
	uint64_t	operations;	/* bitmask of ops. server supports */
	struct dk_cinfo	*cinfo;		/* structure to store DKIOCINFO data */
	struct dk_minfo	*minfo;		/* structure for DKIOCGMEDIAINFO data */
	ddi_devid_t	devid;		/* device id */
	uint64_t	ctimeout;	/* connection timeout in seconds */
	boolean_t	ctimeout_reached; /* connection timeout has expired */

	ldc_mem_info_t		dring_mem_info;		/* dring information */
	uint_t			dring_curr_idx;		/* current index */
	uint32_t		dring_len;		/* dring length */
	uint32_t		dring_max_cookies;	/* dring max cookies */
	uint32_t		dring_cookie_count;	/* num cookies */
	uint32_t		dring_entry_size;	/* descriptor size */
	ldc_mem_cookie_t 	*dring_cookie;		/* dring cookies */
	uint64_t		dring_ident;		/* dring ident */

	uint64_t		threads_pending; 	/* num of threads */

	vdc_local_desc_t	*local_dring;		/* local dring */
	vdc_local_desc_t	*local_dring_backup;	/* local dring backup */
	int			local_dring_backup_tail; /* backup dring tail */
	int			local_dring_backup_len;	/* backup dring len */

	uint64_t		ldc_id;			/* LDC channel id */
	ldc_status_t		ldc_state;		/* LDC channel state */
	ldc_handle_t		ldc_handle;		/* LDC handle */
	ldc_dring_handle_t	ldc_dring_hdl;		/* LDC dring handle */
} vdc_t;

/*
 * Debugging macros
 */
#ifdef DEBUG
extern int	vdc_msglevel;
extern uint64_t	vdc_matchinst;

#define	DMSG(_vdc, err_level, format, ...)				\
	do {								\
		if (vdc_msglevel > err_level &&				\
		(vdc_matchinst & (1ull << (_vdc)->instance)))		\
			cmn_err(CE_CONT, "?[%d,t@%p] %s: "format,	\
			(_vdc)->instance, (void *)curthread,		\
			__func__, __VA_ARGS__);				\
		_NOTE(CONSTANTCONDITION)				\
	} while (0);

#define	DMSGX(err_level, format, ...)					\
	do {								\
		if (vdc_msglevel > err_level)				\
			cmn_err(CE_CONT, "?%s: "format, __func__, __VA_ARGS__);\
		_NOTE(CONSTANTCONDITION)				\
	} while (0);

#define	VDC_DUMP_DRING_MSG(dmsgp)					\
		DMSGX(0, "sq:%lu start:%d end:%d ident:%lu\n",		\
			dmsgp->seq_num, dmsgp->start_idx,		\
			dmsgp->end_idx, dmsgp->dring_ident);

#else	/* !DEBUG */
#define	DMSG(err_level, ...)
#define	DMSGX(err_level, format, ...)
#define	VDC_DUMP_DRING_MSG(dmsgp)

#endif	/* !DEBUG */

#ifdef	__cplusplus
}
#endif

#endif	/* _VDC_H */
