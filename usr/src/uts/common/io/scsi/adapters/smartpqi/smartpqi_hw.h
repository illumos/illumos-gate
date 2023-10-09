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
 * Copyright 2018 Nexenta Systems, Inc.
 */

#ifndef _SMARTPQI_HW_H
#define	_SMARTPQI_HW_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/ccompile.h>

/* ---- for submission of legacy SIS commands ---- */
#define	SIS_REENABLE_SIS_MODE			0x1
#define	SIS_ENABLE_MSIX				0x40
#define	SIS_ENABLE_INTX				0x80
#define	SIS_SOFT_RESET				0x100
#define	SIS_TRIGGER_SHUTDOWN			0x800000
#define	SIS_CMD_READY				0x200
#define	SIS_CMD_COMPLETE			0x1000
#define	SIS_CLEAR_CTRL_TO_HOST_DOORBELL		0x1000
#define	SIS_CMD_STATUS_SUCCESS			0x1
#define	SIS_CMD_COMPLETE_TIMEOUT_SECS		30
#define	SIS_CMD_COMPLETE_POLL_INTERVAL_MSECS	10

/* ---- SOP data direction flags ---- */
#define	SOP_NO_DIRECTION_FLAG	0
#define	SOP_WRITE_FLAG		1	/* host writes data to Data-Out */
					/* buffer */
#define	SOP_READ_FLAG		2	/* host receives data from Data-In */
					/* buffer */
#define	SOP_BIDIRECTIONAL	3	/* data is transferred from the */
					/* Data-Out buffer and data is */
					/* transferred to the Data-In buffer */

#define	SOP_TASK_ATTRIBUTE_SIMPLE		0
#define	SOP_TASK_ATTRIBUTE_HEAD_OF_QUEUE	1
#define	SOP_TASK_ATTRIBUTE_ORDERED		2
#define	SOP_TASK_ATTRIBUTE_ACA			4

#define	SOP_TMF_COMPLETE		0x0
#define	SOP_TMF_FUNCTION_SUCCEEDED	0x8

#define	SOP_TASK_MANAGEMENT_LUN_RESET	0x08

/* ---- CISS commands ---- */
#define	CISS_READ				0xc0
#define	CISS_REPORT_LOG				0xc2
#define	CISS_REPORT_PHYS			0xc3
#define	CISS_GET_RAID_MAP			0xc8

/* constants for CISS_REPORT_LOG/CISS_REPORT_PHYS commands */
#define	CISS_REPORT_LOG_EXTENDED		0x1
#define	CISS_REPORT_PHYS_EXTENDED		0x2

/* BMIC commands */
#define	BMIC_IDENTIFY_CONTROLLER		0x11
#define	BMIC_IDENTIFY_PHYSICAL_DEVICE		0x15
#define	BMIC_READ				0x26
#define	BMIC_WRITE				0x27
#define	BMIC_SENSE_CONTROLLER_PARAMETERS	0x64
#define	BMIC_SENSE_SUBSYSTEM_INFORMATION	0x66
#define	BMIC_WRITE_HOST_WELLNESS		0xa5
#define	BMIC_CACHE_FLUSH			0xc2

#define	PQI_DATA_IN_OUT_GOOD					0x0
#define	PQI_DATA_IN_OUT_UNDERFLOW				0x1
#define	PQI_DATA_IN_OUT_BUFFER_ERROR				0x40
#define	PQI_DATA_IN_OUT_BUFFER_OVERFLOW				0x41
#define	PQI_DATA_IN_OUT_BUFFER_OVERFLOW_DESCRIPTOR_AREA		0x42
#define	PQI_DATA_IN_OUT_BUFFER_OVERFLOW_BRIDGE			0x43
#define	PQI_DATA_IN_OUT_PCIE_FABRIC_ERROR			0x60
#define	PQI_DATA_IN_OUT_PCIE_COMPLETION_TIMEOUT			0x61
#define	PQI_DATA_IN_OUT_PCIE_COMPLETER_ABORT_RECEIVED		0x62
#define	PQI_DATA_IN_OUT_PCIE_UNSUPPORTED_REQUEST_RECEIVED	0x63
#define	PQI_DATA_IN_OUT_PCIE_ECRC_CHECK_FAILED			0x64
#define	PQI_DATA_IN_OUT_PCIE_UNSUPPORTED_REQUEST		0x65
#define	PQI_DATA_IN_OUT_PCIE_ACS_VIOLATION			0x66
#define	PQI_DATA_IN_OUT_PCIE_TLP_PREFIX_BLOCKED			0x67
#define	PQI_DATA_IN_OUT_PCIE_POISONED_MEMORY_READ		0x6F
#define	PQI_DATA_IN_OUT_ERROR					0xf0
#define	PQI_DATA_IN_OUT_PROTOCOL_ERROR				0xf1
#define	PQI_DATA_IN_OUT_HARDWARE_ERROR				0xf2
#define	PQI_DATA_IN_OUT_UNSOLICITED_ABORT			0xf3
#define	PQI_DATA_IN_OUT_ABORTED					0xf4
#define	PQI_DATA_IN_OUT_TIMEOUT					0xf5

/* ---- additional CDB bytes usage field codes ---- */
#define	SOP_ADDITIONAL_CDB_BYTES_0	0	/* 16-byte CDB */
#define	SOP_ADDITIONAL_CDB_BYTES_4	1	/* 20-byte CDB */
#define	SOP_ADDITIONAL_CDB_BYTES_8	2	/* 24-byte CDB */
#define	SOP_ADDITIONAL_CDB_BYTES_12	3	/* 28-byte CDB */
#define	SOP_ADDITIONAL_CDB_BYTES_16	4	/* 32-byte CDB */

/* ---- These values are defined by the PQI spec ---- */
#define	PQI_MAX_NUM_ELEMENTS_ADMIN_QUEUE		255
#define	PQI_MAX_NUM_ELEMENTS_OPERATIONAL_QUEUE		65535
#define	PQI_QUEUE_ELEMENT_ARRAY_ALIGNMENT		64
#define	PQI_QUEUE_ELEMENT_LENGTH_ALIGNMENT		16
#define	PQI_ADMIN_INDEX_ALIGNMENT			64
#define	PQI_OPERATIONAL_INDEX_ALIGNMENT			4

/* ---- These values are based on our implementation ---- */
#define	PQI_ADMIN_IQ_NUM_ELEMENTS			8
#define	PQI_ADMIN_OQ_NUM_ELEMENTS			20
#define	PQI_ADMIN_IQ_ELEMENT_LENGTH			64
#define	PQI_ADMIN_OQ_ELEMENT_LENGTH			64

#define	PQI_OPERATIONAL_IQ_ELEMENT_LENGTH		128
#define	PQI_OPERATIONAL_OQ_ELEMENT_LENGTH		16

#define	PQI_NUM_EVENT_QUEUE_ELEMENTS			32
#define	PQI_EVENT_OQ_ELEMENT_LENGTH	sizeof (struct pqi_event_response)

#define	PQI_MAX_EMBEDDED_SG_DESCRIPTORS			4

#define	PQI_EXTRA_SGL_MEMORY	(12 * sizeof (pqi_sg_entry_t))

typedef uint32_t	pqi_index_t;

/*
 * The purpose of this structure is to obtain proper alignment of objects in
 * an admin queue pair.
 * NOTE: Make sure to not move this structure to within the
 *    #pragma pack(1)
 * directives below. Those directives will override the __aligned directives
 * which in turn will cause the driver to fail.
 */
typedef struct pqi_admin_queues_aligned {
	__aligned(PQI_QUEUE_ELEMENT_ARRAY_ALIGNMENT)
	uint8_t	iq_element_array[PQI_ADMIN_IQ_NUM_ELEMENTS]
	    [PQI_ADMIN_IQ_ELEMENT_LENGTH];
	__aligned(PQI_QUEUE_ELEMENT_ARRAY_ALIGNMENT)
	uint8_t	oq_element_array[PQI_ADMIN_OQ_NUM_ELEMENTS]
	    [PQI_ADMIN_OQ_ELEMENT_LENGTH];
	__aligned(PQI_ADMIN_INDEX_ALIGNMENT) pqi_index_t iq_ci;
	__aligned(PQI_ADMIN_INDEX_ALIGNMENT) pqi_index_t oq_pi;
} pqi_admin_queues_aligned_t;

/*
 * NOTE:
 * From here to the end of the file #pragma pack(1) is set to maintain
 * the structure alignment required by the hardware. Don't change that.
 */
#pragma pack(1)
/* ---- This structure is defined by the PQI specification. ---- */
struct pqi_device_registers {
	uint64_t	signature;
	uint64_t	function_and_status_code;
	uint8_t		max_admin_iq_elements;
	uint8_t		max_admin_oq_elements;
	uint8_t		admin_iq_element_length; /* in 16-byte units */
	uint8_t		admin_oq_element_length; /* in 16-byte units */
	uint16_t	max_reset_timeout;	/* in 100-millisecond units */
	uint8_t		reserved1[2];
	uint32_t	legacy_intx_status;
	uint32_t	legacy_intx_mask_set;
	uint32_t	legacy_intx_mask_clear;
	uint8_t		reserved2[28];
	uint32_t	device_status;
	uint8_t		reserved3[4];
	uint64_t	admin_iq_pi_offset;
	uint64_t	admin_oq_ci_offset;
	uint64_t	admin_iq_element_array_addr;
	uint64_t	admin_oq_element_array_addr;
	uint64_t	admin_iq_ci_addr;
	uint64_t	admin_oq_pi_addr;
	/*
	 * byte 0 -- iq number of elements
	 * byte 1 -- oq number of elements
	 * byte 2 -- interrupt message number (IMN)
	 * byte 3 -- 3 upper bits for IMN and MSIX disable bit
	 */
	uint32_t	admin_queue_params;
	uint8_t		reserved4[4];
	uint32_t	device_error;
	uint8_t		reserved5[4];
	uint64_t	error_details;
	uint32_t	device_reset;
	uint32_t	power_action;
	uint8_t		reserved6[104];
};

/*
 * controller registers
 *
 * These are defined by the Microsemi implementation.
 *
 * Some registers (those named sis_*) are only used when in
 * legacy SIS mode before we transition the controller into
 * PQI mode.  There are a number of other SIS mode registers,
 * but we don't use them, so only the SIS registers that we
 * care about are defined here.  The offsets mentioned in the
 * comments are the offsets from the PCIe BAR 0.
 */
typedef struct pqi_ctrl_registers {
	uint8_t		reserved[0x20];
	uint32_t	sis_host_to_ctrl_doorbell;		/* 20h */
	uint8_t		reserved1[0x34 - (0x20 + sizeof (uint32_t))];
	uint32_t	sis_interrupt_mask;			/* 34h */
	uint8_t		reserved2[0x9c - (0x34 + sizeof (uint32_t))];
	uint32_t	sis_ctrl_to_host_doorbell;		/* 9Ch */
	/* uint8_t	reserved3[0xa0 - (0x9c + sizeof (uint32_t))]; */
	uint32_t	sis_ctrl_to_host_doorbell_clear;	/* A0h */
	uint8_t		reserved4[0xb0 - (0xa0 + sizeof (uint32_t))];
	uint32_t	sis_driver_scratch;			/* B0h */
	uint8_t		reserved5[0xbc - (0xb0 + sizeof (uint32_t))];
	uint32_t	sis_firmware_status;			/* BCh */
	uint8_t		reserved6[0x1000 - (0xbc + sizeof (uint32_t))];
	uint32_t	sis_mailbox[8];				/* 1000h */
	uint8_t		reserved7[0x4000 - (0x1000 + (sizeof (uint32_t) * 8))];

	/*
	 * The PQI spec states that the PQI registers should be at
	 * offset 0 from the PCIe BAR 0.  However, we can't map
	 * them at offset 0 because that would break compatibility
	 * with the SIS registers.  So we map them at offset 4000h.
	 */
	struct pqi_device_registers pqi_registers;		/* 4000h */
} pqi_ctrl_regs_t;
#define	PQI_DEVICE_REGISTERS_OFFSET	0x4000

typedef struct pqi_iu_header {
	uint8_t		iu_type;
	uint8_t		reserved;

	/* in bytes - does not include the length of this header */
	uint16_t	iu_length;

	/* specifies the OQ where the response IU is to be delivered */
	uint16_t	iu_id;

	uint8_t		work_area[2];	/* reserved for driver use */
} pqi_iu_header_t;

typedef struct pqi_sg_entry {
	uint64_t  sg_addr;
	uint32_t  sg_len;
	uint32_t  sg_flags;
} pqi_sg_entry_t;

typedef struct pqi_raid_path_request {
	pqi_iu_header_t	header;
	uint16_t	rp_id;
	uint16_t	rp_nexus_id;
	uint32_t	rp_data_len;
	uint8_t		rp_lun[8];
	uint16_t	protocol_specific;
	uint8_t		rp_data_dir : 2;
	uint8_t		rp_partial : 1;
	uint8_t		reserved1 : 4;
	uint8_t		rp_fence : 1;
	uint16_t	rp_error_index;
	uint8_t		reserved2;
	uint8_t		rp_task_attr : 3;
	uint8_t		rp_pri : 4;
	uint8_t		reserved3 : 1;
	uint8_t		reserved4 : 2;
	uint8_t		rp_additional_cdb : 3;
	uint8_t		reserved5 : 3;
	uint8_t		rp_cdb[32];
	pqi_sg_entry_t	rp_sglist[PQI_MAX_EMBEDDED_SG_DESCRIPTORS];
} pqi_raid_path_request_t;

typedef struct pqi_aio_path_request {
	pqi_iu_header_t	header;
	uint16_t	request_id;
	uint8_t		reserved1[2];
	uint32_t	nexus_id;
	uint32_t	buffer_length;
	uint8_t		data_direction : 2;
	uint8_t		partial : 1;
	uint8_t		memory_type : 1;
	uint8_t		fence : 1;
	uint8_t		encryption_enable : 1;
	uint8_t		reserved2 : 2;
	uint8_t		task_attribute : 3;
	uint8_t		command_priority : 4;
	uint8_t		reserved3 : 1;
	uint16_t	data_encryption_key_index;
	uint32_t	encrypt_tweak_lower;
	uint32_t	encrypt_tweak_upper;
	uint8_t		cdb[16];
	uint16_t	error_index;
	uint8_t		num_sg_descriptors;
	uint8_t		cdb_length;
	uint8_t		lun_number[8];
	uint8_t		reserved4[4];
	pqi_sg_entry_t	ap_sglist[PQI_MAX_EMBEDDED_SG_DESCRIPTORS];
} pqi_aio_path_request_t;

typedef struct pqi_io_response {
	pqi_iu_header_t	header;
	uint16_t	request_id;
	uint16_t	error_index;
	uint8_t		reserved2[4];
} pqi_io_response_t;

typedef struct pqi_raid_error_info {
	uint8_t		data_in_result;
	uint8_t		data_out_result;
	uint8_t		reserved[3];
	uint8_t		status;
	uint16_t	status_qualifier;
	uint16_t	sense_data_length;
	uint16_t	response_data_length;
	uint32_t	data_in_transferred;
	uint32_t	data_out_transferred;
	uint8_t		data[256];
} *pqi_raid_error_info_t;

#define	PQI_GENERAL_ADMIN_FUNCTION_REPORT_DEVICE_CAPABILITY	0x0
#define	PQI_GENERAL_ADMIN_FUNCTION_CREATE_IQ			0x10
#define	PQI_GENERAL_ADMIN_FUNCTION_CREATE_OQ			0x11
#define	PQI_GENERAL_ADMIN_FUNCTION_DELETE_IQ			0x12
#define	PQI_GENERAL_ADMIN_FUNCTION_DELETE_OQ			0x13
#define	PQI_GENERAL_ADMIN_FUNCTION_CHANGE_IQ_PROPERTY		0x14

#define	PQI_GENERAL_ADMIN_STATUS_SUCCESS	0x0
#define	PQI_GENERAL_ADMIN_IU_LENGTH		0x3c
#define	PQI_PROTOCOL_SOP			0x0

#define	PQI_IQ_PROPERTY_IS_AIO_QUEUE		0x1

typedef struct pqi_iu_layer_descriptor {
	uint8_t		inbound_spanning_supported : 1;
	uint8_t		reserved : 7;
	uint8_t		reserved1[5];
	uint16_t	max_inbound_iu_length;
	uint8_t		outbound_spanning_supported : 1;
	uint8_t		reserved2 : 7;
	uint8_t		reserved3[5];
	uint16_t	max_outbound_iu_length;
} pqi_iu_layer_descriptor_t;

typedef struct pqi_device_capability {
	uint16_t	data_length;
	uint8_t		reserved[6];
	uint8_t		iq_arbitration_priority_support_bitmask;
	uint8_t		maximum_aw_a;
	uint8_t		maximum_aw_b;
	uint8_t		maximum_aw_c;
	uint8_t		max_arbitration_burst : 3;
	uint8_t		reserved1 : 4;
	uint8_t		iqa : 1;
	uint8_t		reserved2[2];
	uint8_t		iq_freeze : 1;
	uint8_t		reserved3 : 7;
	uint16_t	max_inbound_queues;
	uint16_t	max_elements_per_iq;
	uint8_t		reserved4[4];
	uint16_t	max_iq_element_length;
	uint16_t	min_iq_element_length;
	uint8_t		reserved5[2];
	uint16_t	max_outbound_queues;
	uint16_t	max_elements_per_oq;
	uint16_t	intr_coalescing_time_granularity;
	uint16_t	max_oq_element_length;
	uint16_t	min_oq_element_length;
	uint8_t		reserved6[24];
	pqi_iu_layer_descriptor_t iu_layer_descriptors[32];
} pqi_device_capability_t;

typedef struct pqi_general_management_request {
	pqi_iu_header_t	header;
	uint16_t  request_id;
	union {
		struct {
			uint8_t		reserved[2];
			uint32_t	buffer_length;
			pqi_sg_entry_t	sg_descriptors[3];
		} report_event_configuration;

		struct {
			uint16_t	global_event_oq_id;
			uint32_t	buffer_length;
			pqi_sg_entry_t	sg_descriptors[3];
		} set_event_configuration;
	} data;
} pqi_general_mgmt_rqst_t;

#define	RAID_CTLR_LUNID		"\0\0\0\0\0\0\0\0"

typedef struct pqi_config_table {
	uint8_t		signature[8];		/* "CFGTABLE" */
	/* offset in bytes from the base address of this table to the */
	/* first section */
	uint32_t	first_section_offset;
} pqi_config_table_t;

typedef struct pqi_config_table_section_header {
	/* as defined by the PQI_CONFIG_TABLE_SECTION_* manifest */
	/* constants above */
	uint16_t	section_id;

	/* offset in bytes from base address of the table of the */
	/* next section or 0 if last entry */
	uint16_t	next_section_offset;
} pqi_config_table_section_header_t;

struct pqi_config_table_general_info {
	pqi_config_table_section_header_t	header;

	/* size of this section in bytes including the section header */
	uint32_t	section_length;

	/* max. outstanding commands supported by the controller */
	uint32_t	max_outstanding_requests;

	/* max. transfer size of a single command */
	uint32_t	max_sg_size;

	/* max. number of scatter-gather entries supported in a single cmd */
	uint32_t	max_sg_per_request;
};

typedef struct pqi_config_table_heartbeat {
	pqi_config_table_section_header_t	header;
	uint32_t				heartbeat_counter;
} pqi_config_table_heartbeat_t;

typedef struct pqi_general_admin_request {
	pqi_iu_header_t	header;
	uint16_t	request_id;
	uint8_t		function_code;
	union {
		struct {
			uint8_t		reserved[33];
			uint32_t	buffer_length;
			pqi_sg_entry_t	sg_descriptor;
		} report_device_capability;

		struct {
			uint8_t		reserved;
			uint16_t	queue_id;
			uint8_t		reserved1[2];
			uint64_t	element_array_addr;
			uint64_t	ci_addr;
			uint16_t	num_elements;
			uint16_t	element_length;
			uint8_t		queue_protocol;
			uint8_t		reserved2[23];
			uint32_t	vendor_specific;
		} create_operational_iq;

		struct {
			uint8_t		reserved;
			uint16_t	queue_id;
			uint8_t		reserved1[2];
			uint64_t	element_array_addr;
			uint64_t	pi_addr;
			uint16_t	num_elements;
			uint16_t	element_length;
			uint8_t		queue_protocol;
			uint8_t		reserved2[3];
			uint16_t	int_msg_num;
			uint16_t	coalescing_count;
			uint32_t	min_coalescing_time;
			uint32_t	max_coalescing_time;
			uint8_t		reserved3[8];
			uint32_t	vendor_specific;
		} create_operational_oq;

		struct {
			uint8_t		reserved;
			uint16_t	queue_id;
			uint8_t		reserved1[50];
		} delete_operational_queue;

		struct {
			uint8_t		reserved;
			uint16_t	queue_id;
			uint8_t		reserved1[46];
			uint32_t	vendor_specific;
		} change_operational_iq_properties;

	} data;
} pqi_general_admin_request_t;

#define	PQI_RESPONSE_IU_GENERAL_MANAGEMENT		0x81
#define	PQI_RESPONSE_IU_TASK_MANAGEMENT			0x93
#define	PQI_RESPONSE_IU_GENERAL_ADMIN			0xe0
#define	PQI_RESPONSE_IU_RAID_PATH_IO_SUCCESS		0xf0
#define	PQI_RESPONSE_IU_AIO_PATH_IO_SUCCESS		0xf1
#define	PQI_RESPONSE_IU_RAID_PATH_IO_ERROR		0xf2
#define	PQI_RESPONSE_IU_AIO_PATH_IO_ERROR		0xf3
#define	PQI_RESPONSE_IU_AIO_PATH_DISABLED		0xf4
#define	PQI_RESPONSE_IU_VENDOR_EVENT			0xf5

typedef struct pqi_general_admin_response {
	pqi_iu_header_t header;
	uint16_t	request_id;
	uint8_t		function_code;
	uint8_t		status;
	union {
		struct {
			uint8_t		status_descriptor[4];
			uint64_t	iq_pi_offset;
			uint8_t		reserved[40];
		} create_operational_iq;

		struct {
			uint8_t		status_descriptor[4];
			uint64_t	oq_ci_offset;
			uint8_t		reserved[40];
		} create_operational_oq;
	} data;
} pqi_general_admin_response_t;

typedef struct pqi_task_management_rqst {
	pqi_iu_header_t	header;
	uint16_t	request_id;
	uint16_t	nexus_id;
	uint8_t		reserved[4];
	uint8_t		lun_number[8];
	uint16_t	protocol_specific;
	uint16_t	outbound_queue_id_to_manage;
	uint16_t	request_id_to_manage;
	uint8_t		task_management_function;
	uint8_t		reserved2 : 7;
	uint8_t		fence : 1;
} pqi_task_management_rqst_t;

/* ---- Support event types ---- */
#define	PQI_EVENT_TYPE_HOTPLUG			0x1
#define	PQI_EVENT_TYPE_HARDWARE			0x2
#define	PQI_EVENT_TYPE_PHYSICAL_DEVICE		0x4
#define	PQI_EVENT_TYPE_LOGICAL_DEVICE		0x5
#define	PQI_EVENT_TYPE_AIO_STATE_CHANGE		0xfd
#define	PQI_EVENT_TYPE_AIO_CONFIG_CHANGE		0xfe
#define	PQI_EVENT_TYPE_HEARTBEAT			0xff

typedef struct pqi_event_response {
	pqi_iu_header_t	header;
	uint8_t		event_type;
	uint8_t		reserved2 : 7;
	uint8_t		request_acknowlege : 1;
	uint16_t	event_id;
	uint32_t	additional_event_id;
	uint8_t		data[16];
} pqi_event_response_t;

typedef struct pqi_event_acknowledge_request {
	pqi_iu_header_t	header;
	uint8_t		event_type;
	uint8_t		reserved2;
	uint16_t	event_id;
	uint32_t	additional_event_id;
} pqi_event_acknowledge_request_t;

typedef struct pqi_event_descriptor {
	uint8_t		event_type;
	uint8_t		reserved;
	uint16_t	oq_id;
} pqi_event_descriptor_t;

typedef struct pqi_event_config {
	uint8_t			reserved[2];
	uint8_t			num_event_descriptors;
	uint8_t			reserved1;
	pqi_event_descriptor_t	descriptors[1];
} pqi_event_config_t;

typedef struct bmic_identify_controller {
	uint8_t		configured_logical_drive_count;
	uint32_t	configuration_signature;
	uint8_t		firmware_version[4];
	uint8_t		reserved[145];
	uint16_t	extended_logical_unit_count;
	uint8_t		reserved1[34];
	uint16_t	firmware_build_number;
	uint8_t		reserved2[100];
	uint8_t		controller_mode;
	uint8_t		reserved3[32];
} bmic_identify_controller_t;

#define	CISS_GET_LEVEL_2_BUS(lunid)		((lunid)[7] & 0x3f)
#define	CISS_GET_LEVEL_2_TARGET(lunid)		((lunid)[6])
#define	CISS_GET_DRIVE_NUMBER(lunid)		\
	(((CISS_GET_LEVEL_2_BUS((lunid)) - 1) << 8) + \
	CISS_GET_LEVEL_2_TARGET((lunid)))

typedef struct bmic_identify_physical_device {
	uint8_t		scsi_bus;	/* SCSI Bus number on controller */
	uint8_t		scsi_id;	/* SCSI ID on this bus */
	uint16_t	block_size;	/* sector size in bytes */
	uint32_t	total_blocks;	/* number for sectors on drive */
	uint32_t	reserved_blocks;	/* controller reserved (RIS) */
	uint8_t		model[40];	/* Physical Drive Model */
	uint8_t		serial_number[40];	/* Drive Serial Number */
	uint8_t		firmware_revision[8];	/* drive firmware revision */
	uint8_t		scsi_inquiry_bits;	/* inquiry byte 7 bits */
	uint8_t		compaq_drive_stamp;	/* 0 means drive not stamped */
	uint8_t		last_failure_reason;
	uint8_t		flags;
	uint8_t		more_flags;
	uint8_t		scsi_lun;	/* SCSI LUN for phys drive */
	uint8_t		yet_more_flags;
	uint8_t		even_more_flags;
	uint32_t	spi_speed_rules;
	uint8_t		phys_connector[2]; /* connector number on controller */
	uint8_t		phys_box_on_bus; /* phys enclosure this drive resides */
	uint8_t		phys_bay_in_box; /* phys drv bay this drive resides */
	uint32_t	rpm;		/* drive rotational speed in RPM */
	uint8_t		device_type;	/* type of drive */
	uint8_t		sata_version;	/* only valid when device_type = */
	/* BMIC_DEVICE_TYPE_SATA */
	uint64_t	big_total_block_count;
	uint64_t	ris_starting_lba;
	uint32_t	ris_size;
	uint8_t		wwid[20];
	uint8_t		controller_phy_map[32];
	uint16_t	phy_count;
	uint8_t		phy_connected_dev_type[256];
	uint8_t		phy_to_drive_bay_num[256];
	uint16_t	phy_to_attached_dev_index[256];
	uint8_t		box_index;
	uint8_t		reserved;
	uint16_t	extra_physical_drive_flags;
	uint8_t		negotiated_link_rate[256];
	uint8_t		phy_to_phy_map[256];
	uint8_t		redundant_path_present_map;
	uint8_t		redundant_path_failure_map;
	uint8_t		active_path_number;
	uint16_t	alternate_paths_phys_connector[8];
	uint8_t		alternate_paths_phys_box_on_port[8];
	uint8_t		multi_lun_device_lun_count;
	uint8_t		minimum_good_fw_revision[8];
	uint8_t		unique_inquiry_bytes[20];
	uint8_t		current_temperature_degrees;
	uint8_t		temperature_threshold_degrees;
	uint8_t		max_temperature_degrees;
	uint8_t		logical_blocks_per_phys_block_exp;
	uint16_t	current_queue_depth_limit;
	uint8_t		switch_name[10];
	uint16_t	switch_port;
	uint8_t		alternate_paths_switch_name[40];
	uint8_t		alternate_paths_switch_port[8];
	uint16_t	power_on_hours;
	uint16_t	percent_endurance_used;
	uint8_t		drive_authentication;
	uint8_t		smart_carrier_authentication;
	uint8_t		smart_carrier_app_fw_version;
	uint8_t		smart_carrier_bootloader_fw_version;
	uint8_t		sanitize_flags;
	uint8_t		encryption_key_flags;
	uint8_t		encryption_key_name[64];
	uint32_t	misc_drive_flags;
	uint16_t	dek_index;
	uint16_t	hba_drive_encryption_flags;
	uint16_t	max_overwrite_time;
	uint16_t	max_block_erase_time;
	uint16_t	max_crypto_erase_time;
	uint8_t		connector_info[5];
	uint8_t		connector_name[8][8];
	uint8_t		page_83_identifier[16];
	uint8_t		maximum_link_rate[256];
	uint8_t		negotiated_physical_link_rate[256];
	uint8_t		box_connector_name[8];
	uint8_t	padding_to_multiple_of_512[9];
} bmic_identify_physical_device_t;

typedef struct bmic_host_wellness_driver_version {
	uint8_t		start_tag[4];
	uint8_t		drv_tag[2];
	uint16_t	driver_version_length;
	char		driver_version[32];
	uint8_t		end_tag[2];
} bmic_host_wellness_driver_version_t;

typedef struct bmic_host_wellness_time {
	uint8_t		start_tag[4];
	uint8_t		time_tag[2];
	uint16_t	time_length;
	uint8_t		time[8];
	uint8_t		dont_write_tag[2];
	uint8_t		end_tag[2];
} bmic_host_wellness_time_t;

#define	PQI_MAX_EVENT_DESCRIPTORS	255

typedef struct report_lun_header {
	uint32_t	list_length;
	uint8_t		extended_response;
	uint8_t		reserved[3];
} report_lun_header_t;

typedef struct report_log_lun_extended_entry {
	uint8_t		lunid[8];
	uint8_t		volume_id[16];
} report_log_lun_extended_entry_t;

typedef struct report_log_lun_extended {
	report_lun_header_t		header;
	report_log_lun_extended_entry_t	lun_entries[1];
} report_log_lun_extended_t;

typedef struct report_phys_lun_extended_entry {
	uint8_t		lunid[8];
	uint64_t	wwid;
	uint8_t		device_type;
	uint8_t		device_flags;
	uint8_t		lun_count; /* number of LUNs in a multi-LUN device */
	uint8_t		redundant_paths;
	uint32_t	aio_handle;
} report_phys_lun_extended_entry_t;

/* ---- Zoned Block Device ---- */
#define	TYPE_ZBC	0x14

/* for device_flags field of struct report_phys_lun_extended_entry */
#define	REPORT_PHYS_LUN_DEV_FLAG_AIO_ENABLED	0x8

typedef struct report_phys_lun_extended {
	report_lun_header_t			header;
	report_phys_lun_extended_entry_t	lun_entries[1];
} report_phys_lun_extended_t;
#pragma pack()

#ifdef __cplusplus
}
#endif

#endif /* _SMARTPQI_HW_H */
