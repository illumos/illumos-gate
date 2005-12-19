/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_SCSI_ADAPTERS_EMUL64VAR_H
#define	_SYS_SCSI_ADAPTERS_EMUL64VAR_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/avl.h>
#include <sys/note.h>
#include <sys/emul64.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Convenient short hand defines
 */
#define	TRUE			 1
#define	FALSE			 0
#define	UNDEFINED		-1

#define	CNUM(emul64)		(ddi_get_instance(emul64->emul64_tran.tran_dev))

#define	EMUL64_RETRY_DELAY		5
#define	EMUL64_RETRIES		0	/* retry of selections */
#define	EMUL64_INITIAL_SOFT_SPACE	5 /* Used for the softstate_init func */

#define	MSW(x)			(int16_t)(((int32_t)x >> 16) & 0xFFFF)
#define	LSW(x)			(int16_t)((int32_t)x & 0xFFFF)

#define	TGT(sp)			(CMD2PKT(sp)->pkt_address.a_target)
#define	LUN(sp)			(CMD2PKT(sp)->pkt_address.a_lun)

#define	HW_REV(val)		(((val) >>8) & 0xff)
#define	FW_REV(val)		((val) & 0xff)

/*
 * max number of LUNs per target
 */
#define	EMUL64_NLUNS_PER_TARGET	32

/*
 * Default emul64 scsi-options
 */
#define	EMUL64_DEFAULT_SCSI_OPTIONS					\
					SCSI_OPTIONS_PARITY	|	\
					SCSI_OPTIONS_DR		|	\
					SCSI_OPTIONS_SYNC	|	\
					SCSI_OPTIONS_TAG	|	\
					SCSI_OPTIONS_FAST	|	\
					SCSI_OPTIONS_WIDE

/*
 *	Tag reject
 */
#define	TAG_REJECT	28
/*
 * Interrupt actions returned by emul64_i_flag_event()
 */
#define	ACTION_CONTINUE		0	/* Continue */
#define	ACTION_RETURN		1	/* Exit */
#define	ACTION_IGNORE		2	/* Ignore */

/*
 * Reset actions for emul64_i_reset_interface()
 */
#define	EMUL64_RESET_BUS_IF_BUSY	0x01 /* reset scsi bus if it is busy */
#define	EMUL64_FORCE_RESET_BUS	0x02	/* reset scsi bus on error reco */


/*
 * extracting period and offset from emul64_synch
 */
#define	PERIOD_MASK(val)	((val) & 0xff)
#define	OFFSET_MASK(val)	(((val) >>8) & 0xff)

/*
 * timeout values
 */
#define	EMUL64_GRACE		10	/* Timeout margin (sec.) */
#define	EMUL64_TIMEOUT_DELAY(secs, delay)	(secs * (1000000 / delay))

/*
 * delay time for polling loops
 */
#define	EMUL64_NOINTR_POLL_DELAY_TIME		1000	/* usecs */

/*
 * busy wait delay time after chip reset
 */
#define	EMUL64_CHIP_RESET_BUSY_WAIT_TIME		100	/* usecs */

/*
 * timeout for EMUL64 coming out of reset
 */
#define	EMUL64_RESET_WAIT				1000	/* ms */
#define	EMUL64_SOFT_RESET_TIME			1	/* second */

/*
 * emul64_softstate flags for introducing hot plug
 */
#define	EMUL64_SS_OPEN		0x01
#define	EMUL64_SS_DRAINING		0x02
#define	EMUL64_SS_QUIESCED		0x04
#define	EMUL64_SS_DRAIN_ERROR	0x08

/*
 * ioctl command definitions
 */
#ifndef	EMUL64_RESET_TARGET
#define	EMUL64_RESET_TARGET		(('i' << 8) | 0x03)
#endif


/*
 * Debugging macros
 */
#define	EMUL64_DEBUG	if (emul64debug) emul64_i_log
#define	EMUL64_DEBUG2	if (emul64debug > 1) emul64_i_log


#define	REQ_TGT_LUN(tgt, lun)			(((tgt) << 8) | (lun))


#define	RESP_CQ_FLAGS(resp)	((resp->resp_header.cq_flags_seq) & 0xff)


#define	EMUL64_NDATASEGS		4


/*
 * translate scsi_pkt flags into EMUL64 request packet flags
 * It would be illegal if two flags are set; the driver does not
 * check for this. Setting NODISCON and a tag flag is harmless.
 */
#define	EMUL64_SET_PKT_FLAGS(scsa_flags, emul64_flags) {		\
	emul64_flags = (scsa_flags >> 11) & 0xe; /* tags */		\
	emul64_flags |= (scsa_flags >> 1) & 0x1; /* no disconnect */	\
}

/*
 * throttle values for EMUL64 request queue
 */
#define	SHUTDOWN_THROTTLE	-1	/* do not submit any requests */
#define	CLEAR_THROTTLE		(EMUL64_MAX_REQUESTS -1)


#define	EMUL64_GET_PKT_STATE(state)	((uint32_t)(state >> 8))
#define	EMUL64_GET_PKT_STATS(stats)	((uint32_t)(stats))

#define	EMUL64_STAT_NEGOTIATE	0x0080

#define	EMUL64_SET_REASON(sp, reason) { \
	if ((sp) && CMD2PKT(sp)->pkt_reason == CMD_CMPLT) \
		CMD2PKT(sp)->pkt_reason = (reason); \
}

/*
 * mutex short hands
 */
#define	EMUL64_REQ_MUTEX(emul64)	(&emul64->emul64_request_mutex)
#define	EMUL64_RESP_MUTEX(emul64)	(&emul64->emul64_response_mutex)
#define	EMUL64_HOTPLUG_MUTEX(emul64)	(&emul64->emul64_hotplug_mutex)


#define	EMUL64_MUTEX_ENTER(emul64) mutex_enter(EMUL64_RESP_MUTEX(emul64)), \
				mutex_enter(EMUL64_REQ_MUTEX(emul64))
#define	EMUL64_MUTEX_EXIT(emul64)	mutex_exit(EMUL64_RESP_MUTEX(emul64)), \
				mutex_exit(EMUL64_REQ_MUTEX(emul64))

#define	EMUL64_CV(emul64)			(&(emul64)->emul64_cv)

/*
 * HBA interface macros
 */
#define	SDEV2TRAN(sd)		((sd)->sd_address.a_hba_tran)
#define	SDEV2ADDR(sd)		(&((sd)->sd_address))
#define	PKT2TRAN(pkt)		((pkt)->pkt_address.a_hba_tran)
#define	ADDR2TRAN(ap)		((ap)->a_hba_tran)

#define	TRAN2EMUL64(tran)	((struct emul64 *)(tran)->tran_hba_private)
#define	SDEV2EMUL64(sd)		(TRAN2EMUL64(SDEV2TRAN(sd)))
#define	PKT2EMUL64(pkt)		(TRAN2EMUL64(PKT2TRAN(pkt)))
#define	ADDR2EMUL64(ap)		(TRAN2EMUL64(ADDR2TRAN(ap)))

#define	CMD2ADDR(cmd)		(&CMD2PKT(cmd)->pkt_address)
#define	CMD2TRAN(cmd)		(CMD2PKT(cmd)->pkt_address.a_hba_tran)
#define	CMD2EMUL64(cmd)		(TRAN2EMUL64(CMD2TRAN(cmd)))

/*
 * Results of checking for range overlap.
 */
typedef enum emul64_rng_overlap {
	O_NONE,			/* No overlap */
	O_SAME,			/* Ranges are identical */
	O_SUBSET,		/* Blocks are contained in range */
	O_OVERLAP		/* Ranges overlap. */
} emul64_rng_overlap_t;

/*
 * Rather than keep the entire image of the disk, we only keep
 * the blocks which have been written with non-zeros.  As the
 * purpose of this driver is to exercise format and perhaps other
 * large-disk management tools, only recording the label for
 * i/o is sufficient
 */
typedef struct blklist {
	diskaddr_t	bl_blkno;	/* Disk address of the data */
	uchar_t		*bl_data;	/* Pointer to the data */
	avl_node_t	bl_node;	/* Our linkage in AVL tree */
} blklist_t;

/*
 * Structure to track a range of blocks where writes are to be ignored.
 */
typedef struct emul64_nowrite {
	struct emul64_nowrite	*emul64_nwnext;	/* next item in list */
	emul64_range_t		emul64_blocked;	/* range to ignore writes */
} emul64_nowrite_t;

typedef struct emul64_tgt {
	struct scsi_address	emul64_tgt_saddr;
	struct emul64_tgt	*emul64_tgt_next;	/* Next tgt on ctlr */
	emul64_nowrite_t	*emul64_tgt_nowrite;	/* List of regions to */
							/* skip writes */
	diskaddr_t		emul64_tgt_sectors;	/* # sectors in dev */
	char 			emul64_tgt_inq[8+16];
	uint_t			emul64_tgt_dtype;
	uint_t			emul64_tgt_ncyls;	/* # cylinders in dev */
	uint_t			emul64_tgt_nheads;	/* # disk heads */
	uint_t			emul64_tgt_nsect;	/* # sectors */
	uint64_t		emul64_list_length;	/* # data blks */
	avl_tree_t		emul64_tgt_data;	/* Tree of data blks */
	kmutex_t		emul64_tgt_blk_lock;	/* Protect data blks */
	krwlock_t		emul64_tgt_nw_lock;	/* Guard tgt_nowrite */
	/* Fields for error injection */
	ushort_t		emul64_einj_state;
	ushort_t		emul64_einj_sense_length;
	uint_t			emul64_einj_pkt_state;
	uint_t			emul64_einj_pkt_reason;
	struct scsi_status	emul64_einj_scsi_status;
	uint8_t			*emul64_einj_sense_data;
} emul64_tgt_t;

/*
 * emul64 softstate structure
 */

/*
 * deadline slot structure for timeout handling
 */
struct emul64_slot {
	struct emul64_cmd	*slot_cmd;
	clock_t		slot_deadline;
};


/*
 * Record the reset notification requests from target drivers.
 */
struct emul64_reset_notify_entry {
	struct scsi_address		*ap;
	void				(*callback)(caddr_t);
	caddr_t				arg;
	struct emul64_reset_notify_entry	*next;
};


struct emul64 {

	/*
	 * Transport structure for this instance of the hba
	 */
	scsi_hba_tran_t		*emul64_tran;

	/*
	 * dev_info_t reference can be found in the transport structure
	 */
	dev_info_t		*emul64_dip;

	/*
	 * Interrupt block cookie
	 */
	ddi_iblock_cookie_t	emul64_iblock;

	/*
	 * Firmware revision number
	 */
	uint16_t		emul64_major_rev;
	uint16_t		emul64_minor_rev;

	/*
	 * timeout id
	 */
	timeout_id_t		emul64_timeout_id;

	/*
	 * scsi options, scsi_tag_age_limit  per emul64
	 */
	int			emul64_scsi_options;
	int			emul64_target_scsi_options[NTARGETS_WIDE];
	int			emul64_scsi_tag_age_limit;

	/*
	 * scsi_reset_delay per emul64
	 */
	clock_t			emul64_scsi_reset_delay;

	/*
	 * current host ID
	 */
	uint8_t			emul64_initiator_id;

	/*
	 * suspended flag for power management
	 */
	uint8_t			emul64_suspended;

	/*
	 * Host adapter capabilities and offset/period values per target
	 */
	uint16_t		emul64_cap[NTARGETS_WIDE];
	int16_t			emul64_synch[NTARGETS_WIDE];

	/*
	 * EMUL64 Hardware register pointer.
	 */
	struct emul64regs		*emul64_reg;


	kmutex_t		emul64_request_mutex;
	kmutex_t		emul64_response_mutex;

	/*
	 * for keeping track of the max LUNs per target on this bus
	 */
	uchar_t			emul64_max_lun[NTARGETS_WIDE];

	/*
	 * for keeping track of each target/lun
	 */
	int	nt_total_sectors[NTARGETS_WIDE][EMUL64_NLUNS_PER_TARGET];

	struct emul64_reset_notify_entry	*emul64_reset_notify_listf;

	ushort_t		emul64_backoff;
	uint_t			emul64_softstate; /* flags for hotplug */
	int			emul64_hotplug_waiting;
	kcondvar_t		emul64_cv; /* cv for bus quiesce/unquiesce */
	kmutex_t		emul64_hotplug_mutex; /* Mutex for hotplug */
	taskq_t			*emul64_taskq;
	emul64_tgt_t		*emul64_tgt;
};

_NOTE(MUTEX_PROTECTS_DATA(emul64::emul64_request_mutex,
				emul64::emul64_queue_space))
_NOTE(MUTEX_PROTECTS_DATA(emul64::emul64_request_mutex,
				emul64::emul64_request_in))
_NOTE(MUTEX_PROTECTS_DATA(emul64::emul64_request_mutex,
				emul64::emul64_request_out))
_NOTE(MUTEX_PROTECTS_DATA(emul64::emul64_request_mutex,
				emul64::emul64_request_ptr))
_NOTE(MUTEX_PROTECTS_DATA(emul64::emul64_request_mutex,
				emul64::emul64_mbox))
_NOTE(MUTEX_PROTECTS_DATA(emul64::emul64_request_mutex,
				emul64::emul64_slots))

_NOTE(MUTEX_PROTECTS_DATA(emul64::emul64_response_mutex,
				emul64::emul64_response_in))
_NOTE(MUTEX_PROTECTS_DATA(emul64::emul64_response_mutex,
				emul64::emul64_response_out))
_NOTE(MUTEX_PROTECTS_DATA(emul64::emul64_response_mutex,
				emul64::emul64_response_ptr))

extern void emul64_bsd_init();
extern void emul64_bsd_fini();
extern void emul64_bsd_get_props(dev_info_t *);

extern emul64_rng_overlap_t emul64_overlap(emul64_range_t *,
						diskaddr_t, size_t);
extern int emul64_bsd_blkcompare(const void *, const void *);
extern int emul64debug;
extern long emul64_nowrite_count;
extern kmutex_t emul64_stats_mutex;
extern int emul64_collect_stats;
extern uint64_t emul64_taskq_max;
extern int emul64_max_task;
extern int emul64_task_nthreads;

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_SCSI_ADAPTERS_EMUL64VAR_H */
