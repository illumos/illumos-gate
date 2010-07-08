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
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 */
#ifndef	_PMCS_DEF_H
#define	_PMCS_DEF_H
#ifdef	__cplusplus
extern "C" {
#endif

typedef enum {
	NOTHING,	/* nothing connected here */
	SATA,		/* SATA connection */
	SAS,		/* direct or indirect SAS connection */
	EXPANDER,	/* connection to an expander */
	NEW		/* Brand new device (pending state) */
} pmcs_dtype_t;

/*
 * This structure defines a PHY device that represents what we
 * are connected to.
 *
 * The eight real physical PHYs that are in the PMC8X6G are represented
 * as an array of eight of these structures which define what these
 * real PHYs are connected to.
 *
 * Depending upon what is actually connected to each PHY, the
 * type set will define what we're connected to. If it is
 * a direct SATA connection, the phy will describe a SATA endpoint
 * If it is a direct SAS connection, it will describe a SAS
 * endpoint.
 *
 * If it is an EXPANDER, this will describe the edge of an expander.
 * As we perform discovery on what is in an EXPANDER we define an
 * additional list of phys that represent what the Expander is connected to.
 */
#define	PMCS_HW_MIN_LINK_RATE	SAS_LINK_RATE_1_5GBIT
#define	PMCS_HW_MAX_LINK_RATE	SAS_LINK_RATE_6GBIT

#define	PMCS_INVALID_DEVICE_ID		0xffffffff
#define	PMCS_DEVICE_ID_MASK		0xffff
#define	PMCS_PHY_INVALID_PORT_ID	0xf

#define	PMCS_PM_MAX_NAMELEN	16
#define	PMCS_MAX_REENUMERATE	2	/* Maximum re-enumeration attempts */

/*
 * Number of usecs to wait after last noted activate/deactivate callback
 * before possibly restarting discovery
 */
#define	PMCS_REDISCOVERY_DELAY	(5 * MICROSEC)

struct pmcs_phy {
	pmcs_phy_t	*sibling;	/* sibling phy */
	pmcs_phy_t 	*parent;	/* parent phy */
	pmcs_phy_t 	*children;	/* head of list of children */
	pmcs_phy_t 	*dead_next;	/* dead PHY list link */
	list_node_t	list_node;	/* list element */
	uint32_t	device_id;	/* PMC8X6G device handle */
	uint32_t
		ncphy 		: 8,	/* # of contained phys for expander */
		hw_event_ack	: 24;	/* XXX: first level phy event acked */
	uint8_t		phynum;		/* phy number on parent expander */
	uint8_t		width;		/* how many phys wide */
	uint8_t		ds_recovery_retries; /* # error retry attempts */
	uint8_t		ds_prev_good_recoveries; /* # successful recoveries */
	clock_t		prev_recovery;	/* previous successful recovery */
	clock_t		last_good_recovery; /* oldest successful recovery */
			/* within PMCS_MAX_DS_RECOVERY_TIME time frame */
	pmcs_dtype_t	dtype;		/* current dtype of the phy */
	pmcs_dtype_t	pend_dtype;	/* new dtype (pending change) */
	uint32_t
		level		: 8,	/* level in expander tree */
		tolerates_sas2	: 1,	/* tolerates SAS2 SMP */
		spinup_hold	: 1,	/* spinup hold needs releasing */
		atdt		: 3,	/* attached device type */
		portid		: 4,	/* PMC8X6G port context */
		link_rate   	: 4,	/* current supported speeds */
		valid_device_id	: 1,	/* device id is valid */
		abort_sent	: 1,	/* we've sent an abort */
		abort_pending	: 1,	/* we have an abort pending */
		need_rl_ext	: 1,	/* need SATA RL_EXT recocvery */
		subsidiary	: 1,	/* this is part of a wide phy */
		configured	: 1,	/* is configured */
		dead		: 1,	/* dead */
		changed		: 1,	/* this phy is changing */
		reenumerate	: 1,	/* attempt re-enumeration */
		virtual		: 1,	/* This is a virtual PHY */
		deregister_wait : 1;	/* phy waiting to get deregistered */
	clock_t		config_stop;	/* When config attempts will stop */
	hrtime_t	abort_all_start;
	kcondvar_t	abort_all_cv;	/* Wait for ABORT_ALL completion */
	kmutex_t	phy_lock;
	volatile uint32_t ref_count;	/* Targets & work on this PHY */
	uint32_t	enum_attempts;	/* # of enumeration attempts */
	uint8_t 	sas_address[8];	/* SAS address for this PHY */
	struct {
	uint32_t
		prog_min_rate	:4,
		hw_min_rate	:4,
		prog_max_rate	:4,
		hw_max_rate	:4,
		reserved	:16;
	} state;
	char		path[32];	/* path name for this phy */
	pmcs_hw_t	*pwp;		/* back ptr to hba struct */
	pmcs_iport_t	*iport;		/* back ptr to the iport handle */
	pmcs_iport_t	*last_iport;	/* last iport this PHY was on */
	pmcs_xscsi_t	*target;	/* back ptr to current target */
	pmcs_xscsi_t	**target_addr;	/* address of real target pointer */
	kstat_t		*phy_stats;	/* kstats for this phy */
	/*
	 * Attached port phy mask and target port phymask.  With 16 bytes
	 * we can represent a phymask for anything with up to 64 ports
	 */
	uint64_t	att_port_pm;		/* att port pm for this PHY */
	uint64_t	att_port_pm_tmp;	/* Temp area for wide-ports */
	char		att_port_pm_str[PMCS_PM_MAX_NAMELEN + 1];
	uint64_t	tgt_port_pm;		/* tgt port pm for this PHY */
	uint64_t	tgt_port_pm_tmp;	/* Temp area for wide-ports */
	char		tgt_port_pm_str[PMCS_PM_MAX_NAMELEN + 1];
	smp_routing_attr_t routing_attr; /* Routing attr. from discover resp. */
	smp_routing_attr_t routing_method; /* Actual routing method used. */
	smp_report_general_resp_t rg_resp;	/* Response to REPORT_GENERAL */
	smp_discover_resp_t disc_resp;		/* Response to DISCOVER */
};

/* maximum number of ds recovery retries (ds_recovery_retries) */
#define	PMCS_MAX_DS_RECOVERY_RETRIES	10

/* max time allowed for successful recovery */
#define	PMCS_MAX_DS_RECOVERY_TIME	(60 * 1000000) /* 60 seconds */

/* ds recovery on same same phy is not allowed within this interval */
#define	PMCS_DS_RECOVERY_INTERVAL	(1000000) /* 1 second */


/*
 * Inbound and Outbound Queue Related Definitions.
 *
 * The PMC8X6G has a programmable number of inbound and outbound circular
 * queues for use in message passing between the host and the PMC8X6G
 * (up to 64 queues for the Rev C Chip). This driver does not use all
 * possible queues.
 *
 * Each Queue is given 4K of consistent memory and we set a 64 byte size for
 * the queue entry size (this gives us 256 queue entries per queue).
 *
 * This allocation then continues up a further PMCS_SCRATCH_SIZE bytes
 * that the driver uses as a temporary scratch area for things like
 * SMP discovery.
 *
 * This control area looks like this:
 *
 * Offset			What
 * ------------------------------------------------
 * 0					IQ 0 Consumer Index
 * 4					IQ 1 Consumer Index
 * 8..255				...
 * 252..255				IQ 63 Consumer Index
 * 256					OQ 0 Producer Index
 * 260					OQ 1 Producer Index
 * 264..259				....
 * 508..511				OQ 63 Producer Index
 * 512..512+PMCS_SCRATCH_SIZE-1		Scratch area.
 */
#define	IQCI_BASE_OFFSET	0
#define	IQ_OFFSET(qnum)		(IQCI_BASE_OFFSET + (qnum << 2))
#define	OQPI_BASE_OFFSET	256
#define	OQ_OFFSET(qnum)		(OQPI_BASE_OFFSET + (qnum << 2))

/*
 * Work related structures. Each one of these structures is paired
 * with *any* command that is fed to the PMC8X6G via one of the
 * Inbound Queues. The work structure has a tag to compare with
 * the message that comes back out of an Outbound Queue. The
 * work structure also points to the phy which this command is
 * tied to. It also has a pointer a callback function (if defined).
 * See that TAG Architecture below for the various kinds of
 * dispositions of a work structure.
 */

/*
 * Work Structure States
 *
 * NIL			->	READY
 * READY		->	NIL
 * READY		->	ONCHIP
 * ONCHIP		->	INTR
 * INTR			->	READY
 * INTR			->	NIL
 * INTR			->	ABORTED
 * INTR			->	TIMED_OUT
 * ABORTED		->	NIL
 * TIMED_OUT		->	NIL
 */
typedef enum {
	PMCS_WORK_STATE_NIL = 0,
	PMCS_WORK_STATE_READY,
	PMCS_WORK_STATE_ONCHIP,
	PMCS_WORK_STATE_INTR,
	PMCS_WORK_STATE_IOCOMPQ,
	PMCS_WORK_STATE_ABORTED,
	PMCS_WORK_STATE_TIMED_OUT
} pmcs_work_state_t;

struct pmcwork {
	STAILQ_ENTRY(pmcwork)	next;
	kmutex_t		lock;
	kcondvar_t		sleep_cv;
	void			*ptr;	/* linkage or callback function */
	void 			*arg;	/* command specific data */
	pmcs_phy_t 		*phy;	/* phy who owns this command */
	pmcs_xscsi_t		*xp;	/* Back pointer to xscsi struct */
	volatile uint32_t	htag;	/* tag for this structure */
	uint32_t		abt_htag; /* Tag of command to be aborted */
	uint32_t
			timer	:	27,
			onwire	:	1,
			dead	:	1,
			state	:	3;
	hrtime_t		start;	/* timestamp start */
	uint32_t		ssp_event; /* ssp event */
	pmcs_dtype_t		dtype;	/* stash, incase phy gets cleared */

	void			*last_ptr;
	void			*last_arg;
	pmcs_phy_t		*last_phy;
	pmcs_xscsi_t		*last_xp;
	uint32_t		last_htag;
	pmcs_work_state_t	last_state;
	hrtime_t		finish;
};
#define	PMCS_ABT_HTAG_ALL	0xffffffff

#define	PMCS_REC_EVENT	0xffffffff	/* event recovery */

/*
 * This structure defines a PMC-Sierra defined firmware header.
 */
#pragma	pack(4)
typedef struct {
	char 		vendor_id[8];
	uint8_t		product_id;
	uint8_t		hwrev;
	uint8_t		destination_partition;
	uint8_t		reserved0;
	uint8_t		fwrev[4];
	uint32_t	firmware_length;
	uint32_t	crc;
	uint32_t	start_address;
	uint8_t		data[];
} pmcs_fw_hdr_t;
#pragma	pack()

/*
 * Offlevel work as a bit pattern.
 */
#define	PMCS_WORK_DISCOVER		0
#define	PMCS_WORK_ABORT_HANDLE		3
#define	PMCS_WORK_SPINUP_RELEASE	4
#define	PMCS_WORK_SAS_HW_ACK		5
#define	PMCS_WORK_SATA_RUN		6
#define	PMCS_WORK_RUN_QUEUES		7
#define	PMCS_WORK_ADD_DMA_CHUNKS	8
#define	PMCS_WORK_DS_ERR_RECOVERY	9
#define	PMCS_WORK_SSP_EVT_RECOVERY	10
#define	PMCS_WORK_DEREGISTER_DEV	11
#define	PMCS_WORK_DUMP_REGS		12

/*
 * The actual values as they appear in work_flags
 */
#define	PMCS_WORK_FLAG_DISCOVER		(1 << 0)
#define	PMCS_WORK_FLAG_ABORT_HANDLE	(1 << 3)
#define	PMCS_WORK_FLAG_SPINUP_RELEASE	(1 << 4)
#define	PMCS_WORK_FLAG_SAS_HW_ACK	(1 << 5)
#define	PMCS_WORK_FLAG_SATA_RUN		(1 << 6)
#define	PMCS_WORK_FLAG_RUN_QUEUES	(1 << 7)
#define	PMCS_WORK_FLAG_ADD_DMA_CHUNKS	(1 << 8)
#define	PMCS_WORK_FLAG_DS_ERR_RECOVERY	(1 << 9)
#define	PMCS_WORK_FLAG_SSP_EVT_RECOVERY (1 << 10)
#define	PMCS_WORK_FLAG_DEREGISTER_DEV   (1 << 11)
#define	PMCS_WORK_FLAG_DUMP_REGS	(1 << 12)

/*
 * This structure is used by this function to test MPI (and interrupts)
 * after MPI has been started to make sure it's working reliably.
 */
typedef struct {
	uint32_t signature;
	uint32_t count;
	uint32_t *ptr;
} echo_test_t;
#define	ECHO_SIGNATURE	0xbebebeef

/*
 * Tag Architecture. The PMC has 32 bit tags for MPI messages.
 * We use this tag this way.
 *
 * bits		what
 * ------------------------
 * 31		done bit
 * 30		non-io cmd bit
 * 29..28	tag type
 * 27..12	rolling serial number
 * 11..0	index into work area to get pmcwork structure
 *
 * A tag type of NONE means that nobody is waiting on any results,
 * so the interrupt code frees the work structure that has this
 * tag.
 *
 * A tag type of CBACK means that the the interrupt handler
 * takes the tag 'arg' in the work structure to be a callback
 * function pointer (see pmcs_cb_t). The callee is responsible
 * for freeing the work structure that has this tag.
 *
 * A tag type of WAIT means that the issuer of the work needs
 * be woken up from interrupt level when the command completes
 * (or times out). If work structure tag 'arg' is non-null,
 * up to 2*PMCS_QENTRY_SIZE bits of data from the Outbound Queue
 * entry may be copied to the area pointed to by 'arg'. This
 * allows issuers to get directly at the results of the command
 * they issed. The synchronization point for the issuer and the
 * interrupt code for command done notification is the setting
 * of the 'DONE' bit in the tag as stored in the work structure.
 */
#define	PMCS_TAG_TYPE_FREE	0
#define	PMCS_TAG_TYPE_NONE	1
#define	PMCS_TAG_TYPE_CBACK  	2
#define	PMCS_TAG_TYPE_WAIT	3
#define	PMCS_TAG_TYPE_SHIFT	28
#define	PMCS_TAG_SERNO_SHIFT	12
#define	PMCS_TAG_INDEX_SHIFT	0
#define	PMCS_TAG_TYPE_MASK	0x30000000
#define	PMCS_TAG_NONIO_CMD	0x40000000
#define	PMCS_TAG_DONE		0x80000000
#define	PMCS_TAG_SERNO_MASK	0x0ffff000
#define	PMCS_TAG_INDEX_MASK	0x00000fff
#define	PMCS_TAG_TYPE(x)		\
	(((x) & PMCS_TAG_TYPE_MASK) >> PMCS_TAG_TYPE_SHIFT)
#define	PMCS_TAG_SERNO(x)	\
	(((x) & PMCS_TAG_SERNO_MASK) >> PMCS_TAG_SERNO_SHIFT)
#define	PMCS_TAG_INDEX(x)	\
	(((x) & PMCS_TAG_INDEX_MASK) >> PMCS_TAG_INDEX_SHIFT)
#define	PMCS_TAG_FREE		0
#define	PMCS_COMMAND_DONE(x)	\
	(((x)->htag == PMCS_TAG_FREE) || (((x)->htag & PMCS_TAG_DONE) != 0))
#define	PMCS_COMMAND_ACTIVE(x)	\
	((x)->htag != PMCS_TAG_FREE && (x)->state == PMCS_WORK_STATE_ONCHIP)

/*
 * Miscellaneous Definitions
 */
#define	CLEAN_MESSAGE(m, x)	{	\
	int _j = x;			\
	while (_j < PMCS_MSG_SIZE) {	\
		m[_j++] = 0;		\
	}				\
}

#define	COPY_MESSAGE(t, f, a)	{	\
	int _j;				\
	for (_j = 0; _j < a; _j++) {	\
		t[_j] = f[_j];		\
	}				\
	while (_j < PMCS_MSG_SIZE) {	\
		t[_j++] = 0;		\
	}				\
}

#define	PMCS_PHY_ADDRESSABLE(pp)			\
	((pp)->level == 0 && (pp)->dtype == SATA &&	\
	    ((pp)->sas_address[0] >> 4) != 5)

#define	RESTART_DISCOVERY(pwp)				\
	ASSERT(!mutex_owned(&pwp->config_lock));	\
	mutex_enter(&pwp->config_lock);			\
	pwp->config_changed = B_TRUE;			\
	mutex_exit(&pwp->config_lock);			\
	SCHEDULE_WORK(pwp, PMCS_WORK_DISCOVER);

#define	RESTART_DISCOVERY_LOCKED(pwp)			\
	ASSERT(mutex_owned(&pwp->config_lock));		\
	pwp->config_changed = B_TRUE;			\
	SCHEDULE_WORK(pwp, PMCS_WORK_DISCOVER);

#define	PHY_CHANGED(pwp, p)						\
	pmcs_prt(pwp, PMCS_PRT_DEBUG_CONFIG, p, NULL, "%s changed in "  \
	    "%s line %d", p->path, __func__, __LINE__); 		\
	p->changed = 1;							\
	p->enum_attempts = 0

#define	PHY_CHANGED_AT_LOCATION(pwp, p, func, line)			\
	pmcs_prt(pwp, PMCS_PRT_DEBUG_CONFIG, p, NULL, "%s changed in "  \
	    "%s line %d", p->path, func, line);				\
	p->changed = 1;							\
	p->enum_attempts = 0

#define	PHY_TYPE(pptr)					\
	(((pptr)->dtype == NOTHING)?  "NOTHING" :	\
	(((pptr)->dtype == SATA)? "SATA" :		\
	(((pptr)->dtype == SAS)? "SAS" : "EXPANDER")))

#define	IS_ROOT_PHY(pptr)	(pptr->parent == NULL)

#define	PMCS_HIPRI(pwp, oq, c)				\
	(pwp->hipri_queue & (1 << PMCS_IQ_OTHER)) ?	\
	(PMCS_IOMB_HIPRI | PMCS_IOMB_IN_SAS(oq, c)) :	\
	(PMCS_IOMB_IN_SAS(oq, c))

#define	SCHEDULE_WORK(hwp, wrk)		\
	(void) atomic_set_long_excl(&hwp->work_flags, wrk)

/*
 * Check to see if the requested work bit is set.  Either way, the bit will
 * be cleared upon return.
 */
#define	WORK_SCHEDULED(hwp, wrk)	\
	(atomic_clear_long_excl(&hwp->work_flags, wrk) == 0)

/*
 * Check to see if the requested work bit is set.  The value will not be
 * changed in this case.  The atomic_xx_nv operations can be quite expensive
 * so this should not be used in non-DEBUG code.
 */
#define	WORK_IS_SCHEDULED(hwp, wrk)	\
	((atomic_and_ulong_nv(&hwp->work_flags, (ulong_t)-1) & (1 << wrk)) != 0)

#define	WAIT_FOR(p, t, r)					\
	clock_t	_lb = ddi_get_lbolt();				\
	r = 0;							\
	while (!PMCS_COMMAND_DONE(p)) {				\
		clock_t _ret = cv_timedwait(&p->sleep_cv,	\
		    &p->lock, _lb + drv_usectohz(t * 1000));	\
		if (!PMCS_COMMAND_DONE(p) && _ret < 0) {		\
			r = 1;					\
			break;					\
		}						\
	}

/*
 * Signal the next I/O completion thread to start running.
 */

#define	PMCS_CQ_RUN_LOCKED(hwp)						\
	if (!STAILQ_EMPTY(&hwp->cq) || hwp->iocomp_cb_head) {		\
		pmcs_cq_thr_info_t *cqti;				\
		cqti = &hwp->cq_info.cq_thr_info			\
		    [hwp->cq_info.cq_next_disp_thr];			\
		hwp->cq_info.cq_next_disp_thr++;			\
		if (hwp->cq_info.cq_next_disp_thr ==			\
		    hwp->cq_info.cq_threads) {				\
			hwp->cq_info.cq_next_disp_thr = 0;		\
		}							\
		mutex_enter(&cqti->cq_thr_lock);			\
		cv_signal(&cqti->cq_cv);				\
		mutex_exit(&cqti->cq_thr_lock);				\
	}

#define	PMCS_CQ_RUN(hwp)						\
	mutex_enter(&hwp->cq_lock);					\
	PMCS_CQ_RUN_LOCKED(hwp);					\
	mutex_exit(&hwp->cq_lock);


/*
 * Watchdog/SCSA timer definitions
 */
/* usecs to SCSA watchdog ticks */
#define	US2WT(x)	(x)/10

/*
 * More misc
 */
#define	BYTE0(x)	(((x) >>  0) & 0xff)
#define	BYTE1(x)	(((x) >>  8) & 0xff)
#define	BYTE2(x)	(((x) >> 16) & 0xff)
#define	BYTE3(x)	(((x) >> 24) & 0xff)
#define	BYTE4(x)	(((x) >> 32) & 0xff)
#define	BYTE5(x)	(((x) >> 40) & 0xff)
#define	BYTE6(x)	(((x) >> 48) & 0xff)
#define	BYTE7(x)	(((x) >> 56) & 0xff)
#define	WORD0(x)	(((x) >>  0) & 0xffff)
#define	WORD1(x)	(((x) >> 16) & 0xffff)
#define	WORD2(x)	(((x) >> 32) & 0xffff)
#define	WORD3(x)	(((x) >> 48) & 0xffff)
#define	DWORD0(x)	((uint32_t)(x))
#define	DWORD1(x)	((uint32_t)(((uint64_t)x) >> 32))

#define	SAS_ADDR_FMT	"0x%02x%02x%02x%02x%02x%02x%02x%02x"
#define	SAS_ADDR_PRT(x)	x[0], x[1], x[2], x[3], x[4], x[5], x[6], x[7]

#define	PMCS_VALID_LINK_RATE(r) \
	((r == SAS_LINK_RATE_1_5GBIT) || (r == SAS_LINK_RATE_3GBIT) || \
	(r == SAS_LINK_RATE_6GBIT))

/*
 * This is here to avoid inclusion of <sys/ctype.h> which is not lint clean.
 */
#define	HEXDIGIT(x)	(((x) >= '0' && (x) <= '9') || \
	((x) >= 'a' && (x) <= 'f') || ((x) >= 'A' && (x) <= 'F'))

#define	NSECS_PER_SEC	1000000000UL


typedef void (*pmcs_cb_t) (pmcs_hw_t *, pmcwork_t *, uint32_t *);

/*
 * Defines and structure used for tracing/logging information
 */

#define	PMCS_TBUF_ELEM_SIZE	120
#define	PMCS_TBUF_NUM_ELEMS_DEF	100000

#define	PMCS_TBUF_UA_MAX_SIZE	32
typedef struct {
	/* Target-specific data */
	uint16_t	target_num;
	char		target_ua[PMCS_TBUF_UA_MAX_SIZE];
	/* PHY-specific data */
	uint8_t 	phy_sas_address[8];
	char		phy_path[32];
	pmcs_dtype_t	phy_dtype;
	/* Log data */
	timespec_t	timestamp;
	uint64_t	fw_timestamp;
	char		buf[PMCS_TBUF_ELEM_SIZE];
} pmcs_tbuf_t;

/*
 * Firmware event log header format
 */
typedef struct pmcs_fw_event_hdr_s {
	uint32_t	fw_el_signature;
	uint32_t	fw_el_entry_start_offset;
	uint32_t	fw_el_rsvd1;
	uint32_t	fw_el_buf_size;
	uint32_t	fw_el_rsvd2;
	uint32_t	fw_el_oldest_idx;
	uint32_t	fw_el_latest_idx;
	uint32_t	fw_el_entry_size;
} pmcs_fw_event_hdr_t;

/*
 * Firmware event log entry format
 */
typedef struct pmcs_fw_event_entry_s {
	uint32_t	num_words : 3,
			reserved : 25,
			severity: 4;
	uint32_t	ts_upper;
	uint32_t	ts_lower;
	uint32_t	seq_num;
	uint32_t	logw0;
	uint32_t	logw1;
	uint32_t	logw2;
	uint32_t	logw3;
} pmcs_fw_event_entry_t;

#define	PMCS_FWLOG_TIMER_DIV	8	/* fw timer has 8ns granularity */
#define	PMCS_FWLOG_AAP1_SIG	0x1234AAAA
#define	PMCS_FWLOG_IOP_SIG	0x5678CCCC

/*
 * Receptacle information
 */
#define	PMCS_NUM_RECEPTACLES	2

#define	PMCS_RECEPT_LABEL_0	"SAS0"
#define	PMCS_RECEPT_LABEL_1	"SAS1"

#define	PMCS_RECEPT_PM_0	"f0"
#define	PMCS_RECEPT_PM_1	"f"

#ifdef	__cplusplus
}
#endif
#endif	/* _PMCS_DEF_H */
