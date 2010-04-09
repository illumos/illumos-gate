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
/*
 * This file is the principle header file for the PMCS driver
 */
#ifndef _PMCS_H
#define	_PMCS_H
#ifdef	__cplusplus
extern "C" {
#endif


#include <sys/cpuvar.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/modctl.h>
#include <sys/pci.h>
#include <sys/pcie.h>
#include <sys/file.h>
#include <sys/isa_defs.h>
#include <sys/sunmdi.h>
#include <sys/mdi_impldefs.h>
#include <sys/scsi/scsi.h>
#include <sys/scsi/impl/scsi_reset_notify.h>
#include <sys/scsi/impl/scsi_sas.h>
#include <sys/scsi/impl/smp_transport.h>
#include <sys/scsi/generic/sas.h>
#include <sys/scsi/generic/smp_frames.h>
#include <sys/atomic.h>
#include <sys/byteorder.h>
#include <sys/sysmacros.h>
#include <sys/bitmap.h>
#include <sys/queue.h>
#include <sys/sdt.h>
#include <sys/ddifm.h>
#include <sys/fm/protocol.h>
#include <sys/fm/util.h>
#include <sys/fm/io/ddi.h>
#include <sys/scsi/impl/spc3_types.h>

typedef struct pmcs_hw pmcs_hw_t;
typedef struct pmcs_iport pmcs_iport_t;
typedef struct pmcs_phy pmcs_phy_t;
typedef struct lsas_cmd lsas_cmd_t;
typedef struct lsas_result lsas_result_t;
typedef struct lsata_cmd lsata_cmd_t;
typedef struct lsata_result lsata_result_t;
typedef struct pmcwork pmcwork_t;
typedef struct pmcs_cmd pmcs_cmd_t;
typedef	struct pmcs_xscsi pmcs_xscsi_t;
typedef	struct pmcs_lun pmcs_lun_t;
typedef struct pmcs_chunk pmcs_chunk_t;

#include <sys/scsi/adapters/pmcs/pmcs_param.h>
#include <sys/scsi/adapters/pmcs/pmcs_reg.h>
#include <sys/scsi/adapters/pmcs/pmcs_mpi.h>
#include <sys/scsi/adapters/pmcs/pmcs_iomb.h>
#include <sys/scsi/adapters/pmcs/pmcs_sgl.h>

#include <sys/scsi/adapters/pmcs/ata.h>
#include <sys/scsi/adapters/pmcs/pmcs_def.h>
#include <sys/scsi/adapters/pmcs/pmcs_proto.h>
#include <sys/scsi/adapters/pmcs/pmcs_scsa.h>
#include <sys/scsi/adapters/pmcs/pmcs_smhba.h>

#define	PMCS_MAX_UA_SIZE	32

struct pmcs_xscsi {
	uint32_t
		ca		:	1,		/* SATA specific */
		ncq		:	1,		/* SATA specific */
		pio		:	1,		/* SATA specific */
		special_needed	:	1,		/* SATA specific */
		special_running	:	1,		/* SATA specific */
		reset_success	:	1,		/* last reset ok */
		reset_wait	:	1,		/* wait for reset */
		resetting	:	1,		/* now resetting */
		recover_wait	:	1,		/* wait for recovery */
		recovering	:	1,		/* now recovering */
		event_recovery	:	1,		/* event recovery */
		draining	:	1,
		new		:	1,
		assigned	:	1,
		dev_gone	:	1,
		phy_addressable	:	1,		/* Direct attach SATA */
		dev_state	:	4;
	uint16_t			maxdepth;
	uint16_t			qdepth;
	uint16_t			actv_cnt;	/* Pkts ON CHIP */
	uint16_t			actv_pkts;	/* Pkts in driver */
	uint16_t			target_num;
	/* statlock protects both target stats and the special queue (sq) */
	kmutex_t			statlock;
	int32_t				ref_count;
	dev_info_t 			*dip;	/* Solaris device dip */
	pmcs_phy_t			*phy;
	STAILQ_HEAD(wqh, pmcs_cmd)	wq;
	pmcs_cmd_t			*wq_recovery_tail;	/* See below */
	kmutex_t			wqlock;
	STAILQ_HEAD(aqh, pmcs_cmd)	aq;
	kmutex_t			aqlock;
	STAILQ_HEAD(sqh, pmcs_cmd)	sq;		/* SATA specific */
	uint32_t			tagmap;		/* SATA specific */
	pmcs_hw_t			*pwp;
	ddi_soft_state_bystr		*lun_sstate;
	uint64_t			capacity;	/* SATA specific */
	char				unit_address[PMCS_MAX_UA_SIZE];
	kcondvar_t			reset_cv;
	kcondvar_t			abort_cv;
	char				*ua;
	pmcs_dtype_t			dtype;
	list_t				lun_list;	/* list of LUNs */
	struct smp_device		*smpd;		/* Ptr to smp_device */
};

/*
 * wq_recovery_tail in the pmcs_xscsi structure is a pointer to a command in
 * the wait queue (wq).  That pointer is the last command in the wait queue
 * that needs to be reissued after device state recovery is complete.  Commands
 * that need to be retried are reinserted into the wq after wq_recovery_tail
 * to maintain the order in which the commands were originally submitted.
 */

#define	PMCS_INVALID_TARGET_NUM		(uint16_t)-1

#define	PMCS_TGT_WAIT_QUEUE		0x01
#define	PMCS_TGT_ACTIVE_QUEUE		0x02
#define	PMCS_TGT_SPECIAL_QUEUE		0x04
#define	PMCS_TGT_ALL_QUEUES		0xff

/*
 * LUN representation.  Just a LUN (number) and pointer to the target
 * structure (pmcs_xscsi).
 */

struct pmcs_lun {
	list_node_t		lun_list_next;
	pmcs_xscsi_t		*target;
	struct scsi_device	*sd;
	uint64_t		lun_num;	/* lun64 */
	scsi_lun_t		scsi_lun;	/* Wire format */
	char			unit_address[PMCS_MAX_UA_SIZE];
};

/*
 * Interrupt coalescing values
 */
#define	PMCS_MAX_IO_COMPS_PER_INTR	12
#define	PMCS_MAX_IO_COMPS_HIWAT_SHIFT	6
#define	PMCS_MAX_IO_COMPS_LOWAT_SHIFT	10
#define	PMCS_QUANTUM_TIME_USECS		(1000000 / 10)	/* 1/10th sec. */
#define	PMCS_MAX_COAL_TIMER		0x200	/* Don't set > than this */
#define	PMCS_MAX_CQ_THREADS		4
#define	PMCS_COAL_TIMER_GRAN		2	/* Go up/down by 2 usecs */
#define	PMCS_INTR_THRESHOLD(x)		((x) * 6 / 10)

/*
 * This structure is used to maintain state with regard to I/O interrupt
 * coalescing.
 */

typedef struct pmcs_io_intr_coal_s {
	hrtime_t	nsecs_between_intrs;
	hrtime_t	last_io_comp;
	clock_t		quantum;
	uint32_t	num_io_completions;
	uint32_t	num_intrs;
	uint32_t	max_io_completions;
	uint32_t	intr_latency;
	uint32_t	intr_threshold;
	uint16_t	intr_coal_timer;
	boolean_t	timer_on;
	boolean_t	stop_thread;
	boolean_t	int_cleared;
} pmcs_io_intr_coal_t;

typedef struct pmcs_cq_thr_info_s {
	kthread_t	*cq_thread;
	kmutex_t	cq_thr_lock;
	kcondvar_t	cq_cv;
	pmcs_hw_t	*cq_pwp;
} pmcs_cq_thr_info_t;

typedef struct pmcs_cq_info_s {
	uint32_t		cq_threads;
	uint32_t		cq_next_disp_thr;
	boolean_t		cq_stop;
	pmcs_cq_thr_info_t	*cq_thr_info;
} pmcs_cq_info_t;

typedef struct pmcs_iocomp_cb_s {
	pmcwork_t		*pwrk;
	char			iomb[PMCS_QENTRY_SIZE << 1];
	struct pmcs_iocomp_cb_s	*next;
} pmcs_iocomp_cb_t;

typedef struct pmcs_iqp_trace_s {
	char		*head;
	char		*curpos;
	uint32_t	size_left;
} pmcs_iqp_trace_t;

/*
 * Used by string-based softstate as hint to possible size.
 */

#define	PMCS_TGT_SSTATE_SZ		64
#define	PMCS_LUN_SSTATE_SZ		4

/*
 * HBA iport node softstate
 */
#define	PMCS_IPORT_INVALID_PORT_ID	0xf

struct pmcs_iport {
	kmutex_t	lock;		/* iport lock */
	list_node_t	list_node;	/* list node for pwp->iports list_t */
	kmutex_t	refcnt_lock;	/* refcnt lock */
	kcondvar_t	refcnt_cv;	/* refcnt cv */
	int		refcnt;		/* refcnt for this iport */
	dev_info_t	*dip;		/* iport dip */
	pmcs_hw_t	*pwp;		/* back pointer to HBA state */
	pmcs_phy_t	*pptr;		/* pointer to this port's primary phy */
	enum {				/* unit address state in the phymap */
		UA_INACTIVE,
		UA_PEND_ACTIVATE,
		UA_ACTIVE,
		UA_PEND_DEACTIVATE
	} ua_state;
	char		*ua;		/* unit address (phy mask) */
	int		portid;		/* portid */
	int		report_skip;	/* skip or report during discovery */
	list_t		phys;		/* list of phys on this port */
	int		nphy;		/* number of phys in this port */
	scsi_hba_tgtmap_t	*iss_tgtmap;	/* tgtmap */
	ddi_soft_state_bystr	*tgt_sstate;	/* tgt softstate */
	/* SMP serialization */
	kmutex_t	smp_lock;
	kcondvar_t	smp_cv;
	boolean_t	smp_active;
	kthread_t	*smp_active_thread;
};

struct pmcs_chunk {
	pmcs_chunk_t		*next;
	ddi_acc_handle_t	acc_handle;
	ddi_dma_handle_t	dma_handle;
	uint8_t			*addrp;
	uint64_t		dma_addr;
};

/*
 * HBA node (i.e. non-iport) softstate
 */
struct pmcs_hw {
	/*
	 * Identity
	 */
	dev_info_t	*dip;

	/*
	 * 16 possible initiator PHY WWNs
	 */
	uint64_t	sas_wwns[PMCS_MAX_PORTS];

	/*
	 * Card State
	 */
	enum pwpstate {
		STATE_NIL,
		STATE_PROBING,
		STATE_RUNNING,
		STATE_UNPROBING,
		STATE_IN_RESET,
		STATE_DEAD
	} state;

	/*
	 * Last reason for a soft reset
	 */
	enum pwp_last_reset_reason {
		PMCS_LAST_RST_UNINIT,
		PMCS_LAST_RST_ATTACH,
		PMCS_LAST_RST_FW_UPGRADE,
		PMCS_LAST_RST_FATAL_ERROR,
		PMCS_LAST_RST_STALL,
		PMCS_LAST_RST_QUIESCE,
		PMCS_LAST_RST_DETACH
	} last_reset_reason;

	uint32_t
		fw_disable_update	: 1,
		fw_force_update		: 1,
		blocked			: 1,
		stuck			: 1,
		locks_initted		: 1,
		mpi_table_setup		: 1,
		hba_attached		: 1,
		iports_attached		: 1,
		suspended		: 1,
		separate_ports		: 1,
		fwlog			: 4,
		phymode			: 3,
		physpeed		: 3,
		resource_limited	: 1,
		configuring		: 1,
		ds_err_recovering	: 1,
		quiesced		: 1,
		fwlog_file		: 1,
		fw_active_img		: 1;	/* 1='A', 0='B' */

	/*
	 * This HBA instance's iportmap and list of iport states.
	 * Note: iports_lock protects iports, iports_attached, and
	 * num_iports on the HBA softstate.
	 */
	krwlock_t		iports_lock;
	scsi_hba_iportmap_t	*hss_iportmap;
	list_t			iports;
	int			num_iports;

	sas_phymap_t		*hss_phymap;
	int			phymap_active;

	/*
	 * Locks
	 */
	kmutex_t	lock;
	kmutex_t	dma_lock;
	kmutex_t	axil_lock;
	kcondvar_t	drain_cv;

	/*
	 * FMA Capabilities
	 */
	int		fm_capabilities;

	/*
	 * Register Access Handles
	 */
	ddi_device_acc_attr_t 	dev_acc_attr;
	ddi_device_acc_attr_t	reg_acc_attr;
	ddi_acc_handle_t 	pci_acc_handle;
	ddi_acc_handle_t 	msg_acc_handle;
	ddi_acc_handle_t 	top_acc_handle;
	ddi_acc_handle_t	mpi_acc_handle;
	ddi_acc_handle_t	gsm_acc_handle;
	ddi_acc_handle_t	iqp_acchdls[PMCS_MAX_IQ];
	ddi_acc_handle_t	oqp_acchdls[PMCS_MAX_IQ];
	ddi_acc_handle_t	cip_acchdls;
	ddi_acc_handle_t	fwlog_acchdl;
	ddi_acc_handle_t	regdump_acchdl;

	/*
	 * DMA Handles
	 */
	ddi_dma_attr_t		iqp_dma_attr;
	ddi_dma_attr_t		oqp_dma_attr;
	ddi_dma_attr_t		cip_dma_attr;
	ddi_dma_attr_t		fwlog_dma_attr;
	ddi_dma_attr_t		regdump_dma_attr;
	ddi_dma_handle_t 	iqp_handles[PMCS_MAX_IQ];
	ddi_dma_handle_t 	oqp_handles[PMCS_MAX_OQ];
	ddi_dma_handle_t	cip_handles;
	ddi_dma_handle_t	fwlog_hndl;
	ddi_dma_handle_t	regdump_hndl;

	/*
	 * Register Pointers
	 */
	uint32_t	*msg_regs;	/* message unit registers */
	uint32_t	*top_regs;	/* top unit registers */
	uint32_t	*mpi_regs;	/* message passing unit registers */
	uint32_t	*gsm_regs;	/* GSM registers */

	/*
	 * Message Passing and other offsets.
	 *
	 * mpi_offset is the offset within the fourth register set (mpi_regs)
	 * that contains the base of the MPI structures. Since this is actually
	 * set by the card firmware, it can change from startup to startup.
	 *
	 * The other offsets (gst, iqc, oqc) are for similar tables in
	 * MPI space, typically only accessed during setup.
	 */
	uint32_t	mpi_offset;
	uint32_t	mpi_gst_offset;
	uint32_t	mpi_iqc_offset;
	uint32_t	mpi_oqc_offset;

	/*
	 * Inbound and outbound queue depth
	 */
	uint32_t	ioq_depth;

	/*
	 * Kernel addresses and offsets for Inbound Queue Producer Indices
	 *
	 * See comments in pmcs_iomb.h about Inbound Queues. Since it
	 * is relatively expensive to go across the PCIe bus to read or
	 * write inside the card, we maintain shadow copies in kernel
	 * memory and update the card as needed.
	 */
	uint32_t	shadow_iqpi[PMCS_MAX_IQ];
	uint32_t	iqpi_offset[PMCS_MAX_IQ];
	uint32_t	last_iqci[PMCS_MAX_IQ];
	uint32_t	last_htag[PMCS_MAX_IQ];
	uint32_t	*iqp[PMCS_MAX_IQ];
	kmutex_t	iqp_lock[PMCS_NIQ];

	pmcs_iqp_trace_t	*iqpt;

	/*
	 * Kernel addresses and offsets for Outbound Queue Consumer Indices
	 */
	uint32_t	*oqp[PMCS_MAX_OQ];
	uint32_t	oqci_offset[PMCS_MAX_OQ];

	/*
	 * Driver's copy of the outbound queue indices
	 */

	uint32_t	oqci[PMCS_NOQ];
	uint32_t	oqpi[PMCS_NOQ];

	/*
	 * DMA addresses for both Inbound and Outbound queues.
	 */
	uint64_t	oqaddr[PMCS_MAX_OQ];
	uint64_t	iqaddr[PMCS_MAX_IQ];

	/*
	 * Producer/Queue Host Memory Pointers and scratch areas,
	 * as well as DMA scatter/gather chunk areas.
	 *
	 * See discussion in pmcs_def.h about how this is laid out.
	 */
	uint8_t		*cip;
	uint64_t	ciaddr;

	/*
	 * Scratch area pointer and DMA addrress for SATA and SMP operations.
	 */
	void			*scratch;
	uint64_t		scratch_dma;
	volatile uint8_t	scratch_locked;	/* Scratch area ownership */

	/*
	 * Firmware info
	 *
	 * fwlogp: Pointer to block of memory mapped for the event logs
	 * fwlogp_aap1: Pointer to the beginning of the AAP1 event log
	 * fwlogp_iop: Pointer to the beginning of the IOP event log
	 * fwaddr: The physical address of fwlogp
	 *
	 * fwlogfile_aap1/iop: Path to the saved AAP1/IOP event logs
	 * fwlog_max_entries_aap1/iop: Max # of entries in each log
	 * fwlog_oldest_idx_aap1/iop: Index of oldest entry in each log
	 * fwlog_latest_idx_aap1/iop: Index of newest entry in each log
	 * fwlog_threshold_aap1/iop: % full at which we save the event log
	 * fwlog_findex_aap1/iop: Suffix to each event log's next filename
	 *
	 * Firmware event logs are written out to the filenames specified in
	 * fwlogp_aap1/iop when the number of entries in the in-memory copy
	 * reaches or exceeds the threshold value.  The filenames are suffixed
	 * with .X where X is an integer ranging from 0 to 4.  This allows us
	 * to save up to 5MB of event log data for each log.
	 */
	uint32_t	*fwlogp;
	pmcs_fw_event_hdr_t *fwlogp_aap1;
	pmcs_fw_event_hdr_t *fwlogp_iop;
	uint64_t	fwaddr;
	char		fwlogfile_aap1[MAXPATHLEN + 1];
	uint32_t	fwlog_max_entries_aap1;
	uint32_t	fwlog_oldest_idx_aap1;
	uint32_t	fwlog_latest_idx_aap1;
	uint32_t	fwlog_threshold_aap1;
	uint32_t	fwlog_findex_aap1;
	char		fwlogfile_iop[MAXPATHLEN + 1];
	uint32_t	fwlog_max_entries_iop;
	uint32_t	fwlog_oldest_idx_iop;
	uint32_t	fwlog_latest_idx_iop;
	uint32_t	fwlog_threshold_iop;
	uint32_t	fwlog_findex_iop;

	/*
	 * Internal register dump region and flash chunk DMA info
	 */

	caddr_t		regdumpp;
	uint32_t	*flash_chunkp;
	uint64_t	flash_chunk_addr;

	/*
	 * Copies of the last read MSGU and IOP heartbeats.
	 */
	uint32_t	last_msgu_tick;
	uint32_t	last_iop_tick;

	/*
	 * Card information, some determined during MPI setup
	 */
	uint32_t	fw;		/* firmware version */
	uint32_t	ila_ver;	/* ILA version */
	uint8_t		max_iq;		/* maximum inbound queues this card */
	uint8_t 	max_oq;		/* "" outbound "" */
	uint8_t		nphy;		/* number of phys this card */
	uint8_t		chiprev;	/* chip revision */
	uint16_t	max_cmd;	/* max number of commands supported */
	uint16_t	max_dev;	/* max number of devices supported */
	uint16_t	last_wq_dev;	/* last dev whose wq was serviced */

	/*
	 * Counter for the number of times watchdog fires.  We can use this
	 * to throttle events which fire off of the watchdog, such as the
	 * forward progress detection routine.
	 */
	uint8_t		watchdog_count;

	/*
	 * Interrupt Setup stuff.
	 *
	 * int_type defines the kind of interrupt we're using with this card.
	 * oqvec defines the relationship between an Outbound Queue Number and
	 * a MSI-X vector.
	 */
	enum {
		PMCS_INT_NONE,
		PMCS_INT_TIMER,
		PMCS_INT_MSI,
		PMCS_INT_MSIX,
		PMCS_INT_FIXED
	} int_type;
	uint8_t			oqvec[PMCS_NOQ];

	/*
	 * Interrupt handle table and size
	 */
	ddi_intr_handle_t	*ih_table;
	size_t			ih_table_size;

	timeout_id_t		wdhandle;
	uint32_t		intr_mask;
	int			intr_cnt;
	int			intr_cap;
	uint32_t		odb_auto_clear;

	/*
	 * DMA S/G chunk list
	 */
	int		nchunks;
	pmcs_chunk_t	*dma_chunklist;

	/*
	 * Front of the DMA S/G chunk freelist
	 */
	pmcs_dmachunk_t	*dma_freelist;

	/*
	 * PHY and Discovery Related Stuff
	 *
	 * The PMC chip can have up to 16 local phys. We build a level-first
	 * traversal tree of phys starting with the physical phys on the
	 * chip itself (i.e., treating the chip as if it were an expander).
	 *
	 * Our discovery process goes through a level and discovers what
	 * each entity is (and it's phy number within that expander's
	 * address space). It then configures each non-empty item (SAS,
	 * SATA/STP, EXPANDER). For expanders, it then performs
	 * discover on that expander itself via REPORT GENERAL and
	 * DISCOVERY SMP commands, attaching the discovered entities
	 * to the next level. Then we step down a level and continue
	 * (and so on).
	 *
	 * The PMC chip maintains an I_T_NEXUS notion based upon our
	 * registering each new device found (getting back a device handle).
	 *
	 * Like with the number of physical PHYS being a maximum of 16,
	 * there are a maximum number of PORTS also being 16. Some
	 * events apply to PORTS entirely, so we track PORTS as well.
	 */
	pmcs_phy_t		*root_phys;	/* HBA PHYs (level 0) */
	pmcs_phy_t		*ports[PMCS_MAX_PORTS];
	kmutex_t		dead_phylist_lock;	/* Protects dead_phys */
	pmcs_phy_t		*dead_phys;	/* PHYs waiting to be freed */

	kmem_cache_t		*phy_cache;

	/*
	 * Discovery-related items.
	 * config_lock: Protects config_changed and should never be held
	 * outside of getting or setting the value of config_changed or
	 * configuring.
	 * config_changed: Boolean indicating whether discovery needs to
	 * be restarted.
	 * configuring: 1 = discovery is running, 0 = discovery not running.
	 * NOTE: configuring is now in the bitfield above.
	 * config_restart_time is set by the tgtmap_[de]activate callbacks each
	 * time we decide we want SCSA to retry enumeration on some device.
	 * The watchdog timer will not fire discovery unless it has reached
	 * config_restart_time and config_restart is TRUE.  This ensures that
	 * we don't ask SCSA to retry enumerating devices while it is still
	 * running.
	 * config_cv can be used by any thread waiting on the configuring
	 * bit to clear.
	 */
	kmutex_t		config_lock;
	volatile boolean_t	config_changed;
	boolean_t		config_restart;
	clock_t			config_restart_time;
	kcondvar_t		config_cv;

	/*
	 * Work Related Stuff
	 *
	 * Each command given to the PMC chip has an associated work structure.
	 * See the discussion in pmcs_def.h about work structures.
	 */
	pmcwork_t	*work;		/* pool of work structures */
	STAILQ_HEAD(wfh, pmcwork) wf;	/* current freelist */
	STAILQ_HEAD(pfh, pmcwork) pf;	/* current pending freelist */
	uint16_t	wserno;		/* rolling serial number */
	kmutex_t	wfree_lock;	/* freelist/actvlist/wserno lock */
	kmutex_t	pfree_lock;	/* freelist/actvlist/wserno lock */

	/*
	 * Solaris/SCSA items.
	 */
	scsi_hba_tran_t		*tran;
	smp_hba_tran_t		*smp_tran;
	struct scsi_reset_notify_entry	*reset_notify_listf;

	/*
	 * Thread Level stuff.
	 *
	 * A number of tasks are done off worker thread taskq.
	 */
	ddi_taskq_t 		*tq;		/* For the worker thread */
	volatile ulong_t	work_flags;

	/*
	 * Solaris target representation.
	 * targets = array of pointers to xscsi structures
	 * allocated by ssoftstate.
	 */
	pmcs_xscsi_t			**targets;

	STAILQ_HEAD(dqh, pmcs_cmd)	dq;	/* dead commands */
	STAILQ_HEAD(cqh, pmcs_cmd)	cq;	/* completed commands */
	kmutex_t			cq_lock;
	kmem_cache_t			*iocomp_cb_cache;
	pmcs_iocomp_cb_t		*iocomp_cb_head;
	pmcs_iocomp_cb_t		*iocomp_cb_tail;

	uint16_t			debug_mask;
	uint16_t			phyid_block_mask;
	uint16_t			phys_started;
	uint16_t			open_retry_interval;
	uint32_t			hipri_queue;
	uint32_t			mpibar;
	uint32_t			intr_pri;

	pmcs_io_intr_coal_t		io_intr_coal;
	pmcs_cq_info_t			cq_info;
	kmutex_t			ict_lock;
	kcondvar_t			ict_cv;
	kthread_t			*ict_thread;

	/*
	 * Receptacle information - FMA
	 */
	char				*recept_labels[PMCS_NUM_RECEPTACLES];
	char				*recept_pm[PMCS_NUM_RECEPTACLES];

	/*
	 * fw_timestamp: Firmware timestamp taken after PHYs are started
	 * sys_timestamp: System timestamp taken at roughly the same time
	 * hrtimestamp is the hrtime at roughly the same time
	 * All of these are protected by the global pmcs_trace_lock.
	 */
	uint64_t	fw_timestamp;
	timespec_t	sys_timestamp;
	hrtime_t	hrtimestamp;

#ifdef	DEBUG
	kmutex_t	dbglock;
	uint32_t	ltags[256];
	uint32_t	ftags[256];
	hrtime_t	ltime[256];
	hrtime_t	ftime[256];
	uint16_t	ftag_lines[256];
	uint8_t		lti;			/* last tag index */
	uint8_t		fti;			/* first tag index */
#endif
};

extern void 		*pmcs_softc_state;
extern void 		*pmcs_iport_softstate;

/*
 * Some miscellaneous, oft used strings
 */
extern const char pmcs_nowrk[];
extern const char pmcs_nomsg[];
extern const char pmcs_timeo[];

/*
 * Other externs
 */
extern int modrootloaded;

#ifdef	__cplusplus
}
#endif
#endif	/* _PMCS_H */
