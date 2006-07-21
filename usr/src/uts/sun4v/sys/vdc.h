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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
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
#define	VDC_MD_DISK_NAME		"disk"
#define	VDC_MD_CFG_HDL			"cfg-handle"
#define	VDC_ID_PROP			"id"

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
 * Scheme to store the instance number and the slice number in the minor number.
 * (Uses the same format and definitions as the sd(7D) driver)
 */
#define	VD_MAKE_DEV(instance, minor)	((instance << SDUNIT_SHIFT) | minor)

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
		(vd_dring_entry_t *)((vdc)->dring_mem_info.vaddr +	\
			(idx * (vdc)->dring_entry_size))

#define	VDC_MARK_DRING_ENTRY_FREE(vdc, idx)			\
	{ \
		vd_dring_entry_t *dep = NULL;				\
		ASSERT(vdc != NULL);					\
		ASSERT((idx >= 0) && (idx < vdc->dring_len));		\
		ASSERT(vdc->dring_mem_info.vaddr != NULL);		\
		dep = (vd_dring_entry_t *)(vdc->dring_mem_info.vaddr +	\
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
 * The states the message processing thread can be in.
 */
typedef enum vdc_thr_state {
	VDC_THR_RUNNING,	/* thread is running & ready to process */
	VDC_THR_STOP,		/* The detach func signals the thread to stop */
	VDC_THR_DONE		/* Thread has exited */
} vdc_thr_state_t;

/*
 * Local Descriptor Ring entry
 *
 * vdc creates a Local (private) descriptor ring the same size as the
 * public descriptor ring it exports to vds.
 */
typedef struct vdc_local_desc {
	kmutex_t		lock;		/* protects all fields */
	kcondvar_t		cv;		/* indicate processing done */
	int			flags;		/* Dring entry state, etc */
	int			operation;	/* VD_OP_xxx to be performed */
	caddr_t			addr;		/* addr passed in by consumer */
	caddr_t			align_addr;	/* used if addr non-aligned */
	struct buf 		*buf;		/* buf passed to strategy() */
	ldc_mem_handle_t	desc_mhdl;	/* Mem handle of buf */
	vd_dring_entry_t	*dep;		/* public Dring Entry Pointer */
} vdc_local_desc_t;

/*
 * vdc soft state structure
 */
typedef struct vdc {
	kmutex_t	attach_lock;	/* used by CV which waits in attach */
	kcondvar_t	attach_cv;	/* signal when attach can finish */

	kmutex_t	lock;		/* protects next 2 sections of vars */
	kcondvar_t	cv;		/* signal when upper layers can send */

	int		initialized;	/* keeps track of what's init'ed */
	int		hshake_cnt;	/* number of failed handshakes */
	int		open;		/* count of outstanding opens */
	int		dkio_flush_pending;	/* # outstanding DKIO flushes */

	uint64_t	session_id;	/* common ID sent with all messages */
	uint64_t	seq_num;	/* most recent sequence num generated */
	uint64_t	seq_num_reply;	/* Last seq num ACK/NACK'ed by vds */
	uint64_t	req_id;		/* Most recent Request ID generated */
	uint64_t	req_id_proc;	/* Last request ID processed by vdc */
	vd_state_t	state;		/* Current handshake state */

	dev_info_t	*dip;		/* device info pointer */
	int		instance;	/* driver instance number */
	vio_ver_t	ver;		/* version number agreed with server */
	vd_disk_type_t	vdisk_type;	/* type of device/disk being imported */
	uint64_t	vdisk_size;	/* device size in bytes */
	uint64_t	max_xfer_sz;	/* maximum block size of a descriptor */
	uint64_t	block_size;	/* device block size used */
	struct dk_label	*label;		/* structure to store disk label */
	struct dk_cinfo	*cinfo;		/* structure to store DKIOCINFO data */
	struct dk_minfo	*minfo;		/* structure for DKIOCGMEDIAINFO data */
	struct vtoc	*vtoc;		/* structure to store VTOC data */

	/*
	 * The mutex 'msg_proc_lock' protects the following group of fields.
	 *
	 * The callback function checks to see if LDC triggered it due to
	 * there being data available and the callback will signal to
	 * the message processing thread waiting on 'msg_proc_cv'.
	 */
	kmutex_t		msg_proc_lock;
	kcondvar_t		msg_proc_cv;
	boolean_t		msg_pending;
	vdc_thr_state_t		msg_proc_thr_state;
	kthread_t		*msg_proc_thr_id;

	/*
	 * The mutex 'dring_lock'  protects the following group of fields.
	 */
	kmutex_t		dring_lock;
	ldc_mem_info_t		dring_mem_info;
	uint_t			dring_curr_idx;
	uint_t			dring_proc_idx;
	uint32_t		dring_len;
	uint32_t		dring_max_cookies;
	uint32_t		dring_cookie_count;
	uint32_t		dring_entry_size;
	boolean_t		dring_notify_server;
	ldc_mem_cookie_t	*dring_cookie;
	uint64_t		dring_ident;

	vdc_local_desc_t	*local_dring;

	uint64_t		ldc_id;
	ldc_status_t		ldc_state;
	ldc_handle_t		ldc_handle;
	ldc_dring_handle_t	ldc_dring_hdl;
} vdc_t;

/*
 * Debugging macros
 */
#ifdef DEBUG
extern int	vdc_msglevel;

#define	DMSG(err_level, format, ...)					\
	do {								\
		if (vdc_msglevel > err_level)				\
			cmn_err(CE_CONT, "?%s"format, __func__, __VA_ARGS__);\
		_NOTE(CONSTANTCONDITION)				\
	} while (0);

#define	VDC_DUMP_DRING_MSG(dmsgp)					\
		DMSG(0, "sq:%lu start:%d end:%d ident:%lu\n",		\
			dmsgp->seq_num, dmsgp->start_idx,		\
			dmsgp->end_idx, dmsgp->dring_ident);

#else	/* !DEBUG */
#define	DMSG(err_level, ...)
#define	VDC_DUMP_DRING_MSG(dmsgp)

#endif	/* !DEBUG */

#ifdef	__cplusplus
}
#endif

#endif	/* _VDC_H */
