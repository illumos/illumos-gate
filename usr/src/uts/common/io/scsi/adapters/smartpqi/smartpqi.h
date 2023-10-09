/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2023 Tintri by DDN, Inc. All rights reserved.
 * Copyright 2021 RackTop Systems, Inc.
 */

#ifndef _SMARTPQI_H
#define	_SMARTPQI_H

#ifdef __cplusplus
extern "C" {
#endif

/* ---- Standard header files. ---- */
#include <sys/note.h>
#include <sys/byteorder.h>
#include <sys/scsi/scsi.h>
#include <sys/pci.h>
#include <sys/file.h>
#include <sys/policy.h>
#include <sys/model.h>
#include <sys/sysevent.h>
#include <sys/sysevent/eventdefs.h>
#include <sys/sysevent/dr.h>
#include <sys/sata/sata_defs.h>
#include <sys/sata/sata_hba.h>
#include <sys/scsi/generic/sas.h>
#include <sys/scsi/impl/scsi_sas.h>
#include <sys/scsi/impl/scsi_reset_notify.h>
#include <sys/sdt.h>
#include <sys/mdi_impldefs.h>
#include <sys/fs/dv_node.h>
#include <sys/sysmacros.h>
#include <sys/systm.h>
#include <smartpqi_hw.h>

/* ---- Hint for ddi_soft_state_init() on amount of structs to alloc ---- */
#define	SMARTPQI_INITIAL_SOFT_SPACE	1

#define	SMARTPQI_MOD_STRING	"smartpqi RT-20210716"

/* ---- Handy constants ---- */
#define	UNDEFINED				-1
#define	MAX_NAME_PROP_SIZE			256
#define	LUN_PROP				"lun"
#define	LUN64_PROP				"lun64"
#define	MDI_GUID				"wwn"
#define	NDI_GUID				"guid"
#define	TARGET_PROP				"target"
#define	LUN_PROP				"lun"
#define	COMPAT_PROP				"compatible"
#define	NAME_DISK				"disk"
#define	NAME_ENCLOSURE				"enclosure"

#define	CMD_TIMEOUT_SCAN_SECS			10
#define	SYNC_CMDS_TIMEOUT_SECS			5
#define	IO_SPACE				1
#define	PQI_MAXTGTS				256

#define	PQI_MIN_MSIX_VECTORS			1
#define	PQI_MAX_MSIX_VECTORS			16
#define	PQI_DEFAULT_QUEUE_GROUP			0
#define	PQI_MAX_QUEUE_GROUPS			PQI_MAX_MSIX_VECTORS
#define	PQI_MIN_OPERATIONAL_QUEUE_ID		1
#define	PQI_NGENS				16
#define	PQI_MAX_IO_SLOTS			(1 << 12)
#define	PQI_SLOT_INDEX_MASK			0xfff
#define	PQI_GENSHIFT				12
/*
 * Generate and extract fields from a 16 bit io request id.
 * We generate a request id by combining a 12 bit slot index with a
 * 4 bit generation count.
 */
#define	PQI_MAKE_REQID(index, gen) (((gen) << PQI_GENSHIFT) | (index))
#define	PQI_REQID_GEN(id)	((id) >> PQI_GENSHIFT)
#define	PQI_REQID_INDEX(id)	((id) & PQI_SLOT_INDEX_MASK)

/* ---- Size of structure scsi_arq_status without sense data. ---- */
#define	PQI_ARQ_STATUS_NOSENSE_LEN	(sizeof (struct scsi_arq_status) - \
    sizeof (struct scsi_extended_sense))

/* ---- macros to return various addresses ---- */
#define	ADDR2TRAN(ap)	((ap)->a_hba_tran)
#define	TRAN2PQI(hba)	((pqi_state_t *)(hba)->tran_hba_private)
#define	ADDR2PQI(ap)	(TRAN2PQI(ADDR2TRAN(ap)))
#define	PKT2CMD(pkt)	((pqi_cmd_t *)(pkt)->pkt_ha_private)
#define	CMD2PKT(cmd)	((struct scsi_pkt *)(cmd)->pc_pkt)

/* ---- PQI configuration ---- */
#define	PQI_MAX_OUTSTANDING_REQUESTS		32
#define	PQI_ERROR_BUFFER_ELEMENT_LENGTH sizeof (struct pqi_raid_error_info)
#define	PQI_CREATE_ADMIN_QUEUE_PAIR		1
#define	PQI_DELETE_ADMIN_QUEUE_PAIR		2
#define	PQI_MAX_TRANSFER_SIZE			(4 * 1024U * 1024U)
#define	PQI_MAX_RESET_XFER_SIZE			(512 * 1024)
#define	PQI_NUM_SUPPORTED_EVENTS		7
#define	PQI_RESERVED_IO_SLOTS_LUN_RESET		1
#define	PQI_RESERVED_IO_SLOTS_EVENT_ACK	PQI_NUM_SUPPORTED_EVENTS
#define	PQI_RESERVED_IO_SLOTS_SYNCHRONOUS_REQUESTS	3
#define	PQI_RESERVED_IO_SLOTS \
	(PQI_RESERVED_IO_SLOTS_LUN_RESET + PQI_RESERVED_IO_SLOTS_EVENT_ACK + \
	PQI_RESERVED_IO_SLOTS_SYNCHRONOUS_REQUESTS)
#define	PQI_MAX_SCATTER_GATHER			0x200

/* ---- SIS constants ---- */
#define	SIS_BASE_STRUCT_ALIGNMENT		16

/* ---- Once every 10 seconds ---- */
#define	WATCHDOG (10 * MICROSEC)

/* ---- Update HBA time of day clock once a day ---- */
#define	MINUTE		60
#define	HOUR		(60 * MINUTE)
#define	DAY		(24 * HOUR)

#define	HBA_IS_QUIESCED(s)	(((s)->s_flags & PQI_HBA_QUIESCED) != 0)
#define	HBA_QUIESCED_PENDING(s)	\
	(((s)->s_flags & PQI_HBA_QUIESCED_PENDING) != 0 && \
	((s)->s_cmd_queue_len == 0))

/*
 * The PQIALIGN_TYPED() does round up to produce aligned value,
 * and is built to support pointers.
 * We could use P2ROUNDUP_TYPED from sysmacros.h, but unfortunately,
 * P2ROUNDUP_TYPED does not work with pointer types.
 */
#define	PQIALIGN_TYPED(addr, align, type) \
	(type)(((uintptr_t)(addr) + align - 1) & ~(align - 1))

/* ---- Handy macros to get/set device registers ---- */
#define	G8(state, __reg__) \
    ddi_get8(state->s_datap, &state->s_reg->__reg__)
#define	G16(state, __reg__) \
    ddi_get16(state->s_datap, &state->s_reg->__reg__)
#define	G32(state, __reg__) \
    ddi_get32(state->s_datap, &state->s_reg->__reg__)
#define	S8(state, __reg__, val) \
    ddi_put8(state->s_datap, &state->s_reg->__reg__, val)
#define	S32(state, __reg__, val) \
    ddi_put32(state->s_datap, &state->s_reg->__reg__, val)
#define	S64(state, __reg__, val) \
    ddi_put64(state->s_datap, &state->s_reg->__reg__, val)
#define	G64(state, __reg__) \
    ddi_get64(state->s_datap, &state->s_reg->__reg__)

/*
 * Yuck! Internal knowledge of MPxIO, but since this variable is required
 * to use MPxIO and there's no public API it must be declared here. Both
 * the iSCSI Initiator and MPT SAS drivers do the same thing.
 */
extern dev_info_t *scsi_vhci_dip;

typedef enum pqi_io_path {
	RAID_PATH = 0,
	AIO_PATH = 1
} pqi_path_t;

typedef struct dma_overhead {
	ddi_dma_handle_t	handle;
	ddi_acc_handle_t	acc;
	caddr_t			alloc_memory;
	size_t			len_to_alloc;
	size_t			allocated_len;
	uint64_t		dma_addr;
	uint_t			cookie_count;
	ddi_dma_cookie_t	second;
} pqi_dma_overhead_t;

typedef struct pqi_admin_queues {
	caddr_t			iq_element_array;
	caddr_t			oq_element_array;
	volatile pqi_index_t	*iq_ci;
	pqi_index_t		*oq_pi;
	uint64_t		iq_element_array_bus_addr;
	uint64_t		oq_element_array_bus_addr;
	uint64_t		iq_ci_bus_addr;
	uint64_t		oq_pi_bus_addr;
	uint32_t		*iq_pi;
	pqi_index_t		iq_pi_copy;
	uint32_t		*oq_ci;
	pqi_index_t		oq_ci_copy;
	struct task_struct	*task;
	uint16_t		int_msg_num;
} pqi_admin_queues_t;

typedef struct pqi_event_queue {
	uint16_t		oq_id;
	uint16_t		int_msg_num;
	void			*oq_element_array;
	pqi_index_t		*oq_pi;		/* In s_queue_dma space */
	uint64_t		oq_element_array_bus_addr;
	uint64_t		oq_pi_bus_addr;
	uint32_t		*oq_ci;		/* In s_reg space */
	pqi_index_t		oq_ci_copy;
} pqi_event_queue_t;

typedef struct pqi_queue_group {
	struct pqi_state	*qg_softc;	/* backpointer */
	uint16_t		iq_id[2];
	uint16_t		oq_id;
	uint16_t		int_msg_num;
	caddr_t			iq_element_array[2];
	caddr_t			oq_element_array;
	uint64_t		iq_element_array_bus_addr[2];
	uint64_t		oq_element_array_bus_addr;
	pqi_index_t		iq_pi_copy[2];
	pqi_index_t		oq_ci_copy;
	/* ---- In s_reg space ---- */
	uint32_t		*iq_pi[2];
	uint32_t		*oq_ci;

	/* ---- In s_queue_dma space ---- */
	pqi_index_t		*iq_ci[2];
	pqi_index_t		*oq_pi;

	uint64_t		iq_ci_bus_addr[2];
	uint64_t		oq_pi_bus_addr;

	kmutex_t		submit_lock[2]; /* protect submission queue */
	list_t			request_list[2];
	int			submit_count;
	int			cmplt_count;
	boolean_t		qg_active;
} pqi_queue_group_t;

typedef struct pqi_io_request {
	kmutex_t		io_lock; /* protect generation/serviced flag */
	uint32_t		io_refcount;
	uint16_t		io_index;
	void			(*io_cb)(struct pqi_io_request *, void *);
	void			*io_context;
	uint8_t			io_raid_bypass : 1;
	uint8_t			io_gen;
	boolean_t		io_serviced;
	int			io_status;
	pqi_queue_group_t	*io_queue_group;
	int			io_queue_path;
	struct pqi_cmd		*io_cmd;
	void			*io_error_info;
	pqi_dma_overhead_t	*io_sg_chain_dma;
	void			*io_iu;
	list_node_t		io_list_node;

	/* ---- Debug aids ---- */
	pqi_index_t		io_pi;
	int			io_iu_type;

	struct pqi_state	*io_softc;
} pqi_io_request_t;

typedef struct pqi_event {
	boolean_t		ev_pending;
	uint8_t			ev_type;
	uint16_t		ev_id;
	uint32_t		ev_additional;
} pqi_event_t;

/* ---- Flags used in pqi_state ---- */
#define	PQI_HBA_DRIVER_SHUTDOWN			0x0001
#define	PQI_HBA_QUIESCED			0x0002
#define	PQI_HBA_QUIESCED_PENDING		0x0004
#define	PQI_HBA_AUTO_REQUEST_SENSE		0x0008
#define	PQI_HBA_LUN_RESET_CAP			0x0010

/* ---- Debug flags, example debug=0x10; in .conf file ---- */
#define	DBG_LVL_CDB				0x0001
#define	DBG_LVL_RQST				0x0002
#define	DBG_LVL_STATE				0x0004
#define	DBG_LVL_RAW_RQST			0x0008

typedef struct pqi_device {
	list_node_t		pd_list;
	kmutex_t		pd_mutex;

	/* ---- Protected by pd_mutex ---- */
	list_t			pd_cmd_list;
	int			pd_flags;

	int			pd_active_cmds;
	int			pd_target;
	int			pd_lun;

	/* ---- Only one will be valid, MPxIO uses s_pip ---- */
	dev_info_t		*pd_dip;
	mdi_pathinfo_t		*pd_pip;
	mdi_pathinfo_t		*pd_pip_offlined;

	dev_info_t		*pd_parent;
	int			pd_devtype;
	int			pd_online : 1;
	int			pd_scanned : 1;
	int			pd_phys_dev : 1;
	int			pd_external_raid : 1;
	int			pd_aio_enabled : 1;
	uint32_t		pd_aio_handle;
	char			pd_scsi3addr[8];
	uint64_t		pd_wwid;
	char			*pd_guid;
	uint8_t			pd_volume_id[16];
	char			pd_vendor[8];	/* From INQUIRY */
	char			pd_model[16];	/* From INQUIRY */
	char			pd_unit_address[32];

	/* ---- Debug stats ---- */
	uint32_t		pd_killed;
	uint32_t		pd_posted;
	uint32_t		pd_timedout;
	uint32_t		pd_sense_errors;
} pqi_device_t;

typedef struct pqi_state {
	int			s_instance;
	dev_info_t		*s_dip;
	int			s_flags;
	kmutex_t		s_mutex;
	kmutex_t		s_intr_mutex;
	kcondvar_t		s_quiescedvar;
	uint32_t		s_next_target;

	/* ---- Used for serialized commands through driver ---- */
	struct pqi_device	s_special_device;

	boolean_t		s_intr_ready;
	boolean_t		s_offline;
	boolean_t		s_disable_mpxio;
	kmem_cache_t		*s_cmd_cache;
	ddi_taskq_t		*s_events_taskq;
	ddi_taskq_t		*s_complete_taskq;
	timeout_id_t		s_time_of_day;
	timeout_id_t		s_cmd_timeout;

	/* ---- Debug related state ---- */
	int			s_debug_level;

	/* ---- State for watchdog ---- */
	timeout_id_t		s_watchdog;
	uint32_t		s_last_intr_count;
	uint32_t		s_last_heartbeat_count;
	uint32_t		s_intr_count;

	/* ---- Interrupt related fields ---- */
	int			s_intr_type;	/* Type of interrupt used */
	int			s_intr_cnt;	/* # of interrupts */
	uint_t			s_intr_pri;	/* Interrupt priority */
	int			s_intr_cap;	/* Interrupt capabilities */
	int			s_intr_size;	/* Size of s_htable */
	ddi_intr_handle_t	*s_itable;	/* Interrupt table */

	scsi_hba_tran_t		*s_tran;
	ddi_dma_attr_t		s_msg_dma_attr;	/* Used for message frames */

	/* ---- list of reset notification requests ---- */
	struct scsi_reset_notify_entry	*s_reset_notify_listf;

	pqi_ctrl_regs_t		*s_reg;
	ddi_device_acc_attr_t	s_reg_acc_attr;
	/* ---- operating regs data access handle ---- */
	ddi_acc_handle_t	s_datap;

	list_t			s_devnodes;
	volatile uint32_t	s_cmd_queue_len;

	/* ---- SIS capabilities from controller ---- */
	uint32_t		s_max_sg_entries;
	uint32_t		s_max_xfer_size;
	uint32_t		s_max_outstanding_requests;
	uint32_t		s_config_table_offset;
	uint32_t		s_config_table_len;

	/* ---- PQI capabilities from controller ---- */
	uint32_t		*s_heartbeat_counter;
	uint16_t		s_max_inbound_queues;
	uint16_t		s_max_elements_per_iq;
	uint16_t		s_max_iq_element_length;
	uint16_t		s_max_outbound_queues;
	uint16_t		s_max_elements_per_oq;
	uint16_t		s_max_oq_element_length;
	uint16_t		s_max_inbound_iu_length_per_firmware;
	uint8_t			s_inbound_spanning_supported : 1,
				s_outbound_spanning_supported:1,
				s_pqi_mode_enabled : 1;
	char			s_firmware_version[11];

	/* ---- Computed values from config ---- */
	uint32_t		s_max_sg_per_iu;
	uint32_t		s_num_elements_per_iq;
	uint32_t		s_num_elements_per_oq;
	uint32_t		s_max_inbound_iu_length;
	uint32_t		s_num_queue_groups;
	uint32_t		s_max_io_slots;
	uint32_t		s_sg_chain_buf_length;
	uint32_t		s_max_sectors;

	/* ---- allocation/free is protected by s_io_mutex ---- */
	kmutex_t		s_io_mutex;
	kcondvar_t		s_io_condvar;
	pqi_io_request_t	*s_io_rqst_pool;
	int			s_io_wait_cnt;
	int			s_next_io_slot;
	uint32_t		s_io_need;
	uint32_t		s_io_had2wait;
	uint32_t		s_io_sig;

	pqi_dma_overhead_t	*s_error_dma;
	pqi_dma_overhead_t	*s_adminq_dma;
	pqi_admin_queues_t	s_admin_queues;
	pqi_dma_overhead_t	*s_queue_dma;
	pqi_queue_group_t	s_queue_groups[PQI_MAX_QUEUE_GROUPS];
	pqi_event_queue_t	s_event_queue;
	struct pqi_event	s_events[PQI_NUM_SUPPORTED_EVENTS];
} pqi_state_t;

/* ---- Flags used in pqi_cmd_t ---- */
#define	PQI_FLAG_ABORTED	0x0001
#define	PQI_FLAG_TIMED_OUT	0x0002
#define	PQI_FLAG_RESET		0x0004
#define	PQI_FLAG_IO_IOPB	0x0040
#define	PQI_FLAG_DMA_VALID	0x0100
#define	PQI_FLAG_CDB_EXT	0x0200
#define	PQI_FLAG_SCB_EXT	0x0400
#define	PQI_FLAG_PRIV_EXT	0x0800
#define	PQI_FLAG_IO_READ	0x1000
#define	PQI_FLAG_IO_BOUNCE	0x2000
#define	PQI_FLAG_FINISHING	0x4000

typedef enum pqi_cmd_action {
	PQI_CMD_UNINIT,
	PQI_CMD_QUEUE,
	PQI_CMD_START,
	PQI_CMD_CMPLT,
	PQI_CMD_TIMEOUT,
	PQI_CMD_FAIL
} pqi_cmd_action_t;

#define	PQI_FLAGS_PERSISTENT	\
	(PQI_FLAG_DMA_VALID	|\
	PQI_FLAG_IO_IOPB)

#define	PQI_FLAGS_NON_HW_COMPLETION \
	(PQI_FLAG_ABORTED	|\
	PQI_FLAG_TIMED_OUT	|\
	PQI_FLAG_RESET)

typedef struct pqi_cmd {
	list_node_t		pc_list;
	kmutex_t		pc_mutex;	// protects pc_cmd_state

	pqi_cmd_action_t	pc_cur_action;
	pqi_cmd_action_t	pc_last_action;

	struct scsi_pkt		*pc_pkt;
	pqi_state_t		*pc_softc;
	pqi_device_t		*pc_device;
	ksema_t			*pc_poll;
	uint8_t			pc_cdb[SCSI_CDB_SIZE];
	struct scsi_arq_status	pc_cmd_scb;

	uint64_t		pc_tgt_priv[2];
	int			pc_dma_count;	/* bytes to transfer */

	/*
	 * Setting/clearing/testing of ABORT and FINISHING are
	 * protected by pqi_device->pd_mutex. The other bits in
	 * this flag are set during init_pkt and read only during
	 * cleanup.
	 */
	int			pc_flags;

	int			pc_tgtlen;
	int			pc_statuslen;
	int			pc_cmdlen;
	hrtime_t		pc_expiration;
	hrtime_t		pc_start_time;

	/* ---- For partial DMA transfers ---- */
	uint_t			pc_nwin;
	uint_t			pc_winidx;
	off_t			pc_dma_offset;
	size_t			pc_dma_len;

	/* ---- Valid after call to pqi_transport_command ---- */
	pqi_io_request_t	*pc_io_rqst;

	ddi_dma_handle_t	pc_dmahdl;
	ddi_dma_cookie_t	pc_dmac;
	uint_t			pc_dmaccount;	/* cookie count */
	struct scsi_pkt		pc_cached_pkt;
	ddi_dma_cookie_t	pc_cached_cookies[PQI_MAX_SCATTER_GATHER];
} pqi_cmd_t;

/* ---- configuration table section IDs ---- */
#define	PQI_CONFIG_TABLE_SECTION_GENERAL_INFO		0
#define	PQI_CONFIG_TABLE_SECTION_FIRMWARE_FEATURES	1
#define	PQI_CONFIG_TABLE_SECTION_FIRMWARE_ERRATA	2
#define	PQI_CONFIG_TABLE_SECTION_DEBUG			3
#define	PQI_CONFIG_TABLE_SECTION_HEARTBEAT		4

/* ---- manifest constants for the flags field of pqi_sg_descriptor ---- */
#define	CISS_SG_NORMAL				0x00000000
#define	CISS_SG_LAST				0x40000000
#define	CISS_SG_CHAIN				0x80000000

/*
 * According to the PQI spec, the IU header is only the first 4 bytes of our
 * pqi_iu_header structure.
 */
#define	PQI_REQUEST_HEADER_LENGTH			4
#define	PQI_REQUEST_IU_TASK_MANAGEMENT			0x13
#define	PQI_REQUEST_IU_RAID_PATH_IO			0x14
#define	PQI_REQUEST_IU_AIO_PATH_IO			0x15
#define	PQI_REQUEST_IU_GENERAL_ADMIN			0x60
#define	PQI_REQUEST_IU_REPORT_VENDOR_EVENT_CONFIG	0x72
#define	PQI_REQUEST_IU_SET_VENDOR_EVENT_CONFIG		0x73
#define	PQI_REQUEST_IU_ACKNOWLEDGE_VENDOR_EVENT		0xf6

#define	MASKED_DEVICE(lunid)				((lunid)[3] & 0xc0)

#define	MEMP(args...) (void) snprintf(m.mem + strlen(m.mem), \
	m.len - strlen(m.mem), args)

typedef struct mem_len_pair {
	caddr_t	mem;
	int	len;
} mem_len_pair_t;

/* ---- Defines for PQI mode ---- */
#define	IRQ_MODE_NONE			0x00
#define	VPD_PAGE			(1 << 8)

/* ---- Defines for use in Legacy mode ---- */
#define	SIS_CTRL_KERNEL_UP		0x080
#define	SIS_CTRL_KERNEL_PANIC		0x100
#define	SIS_MODE			0x0
#define	PQI_MODE			0x1

/* ---- smartpqi_main.c ---- */
extern void *pqi_state;
extern int pqi_do_scan;
extern int pqi_do_ctrl;

/* ---- smartpqi_intr.c ---- */
int smartpqi_register_intrs(pqi_state_t *);
void smartpqi_unregister_intrs(pqi_state_t *);
void pqi_process_io_intr(pqi_state_t *s, pqi_queue_group_t *qg);

/* ---- smartpqi_sis.c ---- */
boolean_t sis_reenable_mode(pqi_state_t *s);
void sis_write_scratch(pqi_state_t *s, int mode);
uint32_t sis_read_scratch(pqi_state_t *s);
boolean_t sis_wait_for_ctrl_ready(pqi_state_t *s);
boolean_t sis_get_ctrl_props(pqi_state_t *s);
boolean_t sis_init_base_struct_addr(pqi_state_t *s);
boolean_t sis_get_pqi_capabilities(pqi_state_t *s);

/* ---- smartpqi_init.c ---- */
void pqi_free_io_resource(pqi_state_t *s);
boolean_t pqi_scsi_inquiry(pqi_state_t *s, pqi_device_t *dev, int vpd,
    struct scsi_inquiry *inq, int len);
void pqi_rescan_devices(pqi_state_t *s);
boolean_t pqi_check_firmware(pqi_state_t *s);
boolean_t pqi_prep_full(pqi_state_t *s);
boolean_t pqi_reset_ctl(pqi_state_t *s);
boolean_t pqi_hba_reset(pqi_state_t *s);

/* ---- smartpqi_hba.c ---- */
boolean_t smartpqi_register_hba(pqi_state_t *);
void smartpqi_unregister_hba(pqi_state_t *);
pqi_device_t *pqi_find_target_ua(pqi_state_t *s, char *);
int pqi_cache_constructor(void *buf, void *un, int flags);
void pqi_cache_destructor(void *buf, void *un);
int pqi_config_all(dev_info_t *pdip, pqi_state_t *s);
void pqi_quiesced_notify(pqi_state_t *s);

/* ---- smartpqi_hw.c ---- */
void pqi_start_io(pqi_state_t *s, pqi_queue_group_t *qg, pqi_path_t path,
    pqi_io_request_t *io);
int pqi_transport_command(pqi_state_t *s, pqi_cmd_t *cmd);
pqi_cmd_action_t pqi_fail_cmd(pqi_cmd_t *cmd, uchar_t reason, uint_t stats);
void pqi_fail_drive_cmds(pqi_device_t *devp, uchar_t reason);
void pqi_watchdog(void *v);
void pqi_do_rescan(void *v);
void pqi_event_worker(void *v);
uint32_t pqi_disable_intr(pqi_state_t *s);
void pqi_enable_intr(pqi_state_t *s, uint32_t old_state);
void pqi_lun_reset(pqi_state_t *s, pqi_device_t *d);

/* ---- smartpqi_util.c ---- */
pqi_dma_overhead_t *pqi_alloc_single(pqi_state_t *s, size_t len);
void pqi_free_single(pqi_state_t *s, pqi_dma_overhead_t *d);
pqi_io_request_t *pqi_alloc_io(pqi_state_t *s);
void pqi_free_io(pqi_io_request_t *io);
boolean_t pqi_timeout_io(pqi_io_request_t *io);
boolean_t pqi_service_io(pqi_io_request_t *io, uint8_t generation);
void pqi_dump_io(pqi_io_request_t *io);
pqi_cmd_action_t pqi_cmd_action(pqi_cmd_t *cmd, pqi_cmd_action_t a);
pqi_cmd_action_t pqi_cmd_action_nolock(pqi_cmd_t *cmd, pqi_cmd_action_t a);
char *pqi_event_to_str(uint8_t event);
int pqi_map_event(uint8_t event);
boolean_t pqi_supported_event(uint8_t event_type);
char *bool_to_str(int v);
char *dtype_to_str(int t);
void pqi_free_mem_len(mem_len_pair_t *m);
mem_len_pair_t pqi_alloc_mem_len(int len);
mem_len_pair_t build_cdb_str(uint8_t *cdb);
boolean_t pqi_is_offline(pqi_state_t *s);
void pqi_show_dev_state(pqi_state_t *s);
char *cdb_to_str(uint8_t scsi_cmd);
char *io_status_to_str(int val);
char *scsi_status_to_str(uint8_t val);
char *iu_type_to_str(int val);

#ifdef __cplusplus
}
#endif

#endif /* _SMARTPQI_H */
