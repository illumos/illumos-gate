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
 * Copyright (C) 2013 Hewlett-Packard Development Company, L.P.
 * Copyright (c) 2017 Joyent, Inc.
 */

#ifndef	_SMRT_SCSI_H
#define	_SMRT_SCSI_H

#include <sys/types.h>

#include <sys/scsi/adapters/smrt/smrt_ciss.h>

#ifdef	__cplusplus
extern "C" {
#endif

/* CISS LUN Addressing MODEs */
#define	PERIPHERIAL_DEV_ADDR 			0x0
#define	LOGICAL_VOL_ADDR 			0x1
#define	MASK_PERIPHERIAL_DEV_ADDR 		0x3
#define	CISS_PHYS_MODE 				0x0

/*
 * Vendor-specific SCSI Commands
 *
 * These command opcodes are for use in the opcode byte of the CDB in a request
 * of type CISS_TYPE_CMD.  They are custom SCSI commands, using the
 * vendor-specific part of the opcode space; i.e., 0xC0 through 0xFF.
 */
#define	CISS_SCMD_READ				0xC0
#define	CISS_SCMD_WRITE				0xC1
#define	CISS_SCMD_REPORT_LOGICAL_LUNS		0xC2
#define	CISS_SCMD_REPORT_PHYSICAL_LUNS		0xC3

/*
 * These command opcodes are _not_ in the usual vendor-specific space, but are
 * nonetheless vendor-specific.  They allow BMIC commands to be written to and
 * read from the controller.  If a command transfers no data, the specification
 * suggests that BMIC_WRITE (0x27) is appropriate.
 */
#define	CISS_SCMD_BMIC_READ			0x26
#define	CISS_SCMD_BMIC_WRITE			0x27

/*
 * CISS Messages
 *
 * The CISS specification describes several directives that do not behave like
 * SCSI commands.  They are sent in requests of type CISS_TYPE_MSG.
 *
 * The Abort, Reset, and Nop, messages are defined in "8. Messages" in the CISS
 * Specification.
 */
#define	CISS_MSG_ABORT				0x0
#define	CISS_ABORT_TASK				0x0
#define	CISS_ABORT_TASKSET			0x1

#define	CISS_MSG_RESET				0x1
#define	CISS_RESET_CTLR				0x0
#define	CISS_RESET_BUS				0x1
#define	CISS_RESET_TGT				0x3
#define	CISS_RESET_LUN				0x4

#define	CISS_MSG_NOP				0x3

/*
 * BMIC Commands
 *
 * These commands allow for the use of non-standard facilities specific to the
 * Smart Array firmware.  They are sent to the controller through a specially
 * constructed CDB with the CISS_SCMD_BMIC_READ or CISS_SCMD_BMIC_WRITE opcode.
 */
#define	CISS_BMIC_IDENTIFY_CONTROLLER		0x11
#define	CISS_BMIC_IDENTIFY_PHYSICAL_DEVICE	0x15
#define	CISS_BMIC_NOTIFY_ON_EVENT		0xD0
#define	CISS_BMIC_NOTIFY_ON_EVENT_CANCEL	0xD1

/*
 * Device and Phy type codes.  These are used across many commands, including
 * IDENTIFY PHYSICAL DEVICE and the REPORT PHYSICAL LUN extended reporting.
 */
#define	SMRT_DTYPE_PSCSI			0x00
#define	SMRT_DTYPE_SATA				0x01
#define	SMRT_DTYPE_SAS				0x02
#define	SMRT_DTYPE_SATA_BW			0x03
#define	SMRT_DTYPE_SAS_BW			0x04
#define	SMRT_DTYPE_EXPANDER			0x05
#define	SMRT_DTYPE_SES				0x06
#define	SMRT_DTYPE_CONTROLLER			0x07
#define	SMRT_DTYPE_SGPIO			0x08
#define	SMRT_DTYPE_NVME				0x09
#define	SMRT_DTYPE_NOPHY			0xFF

/*
 * The following packed structures are used to ease the manipulation of SCSI
 * and BMIC commands sent to, and status information returned from, the
 * controller.
 */
#pragma pack(1)

typedef struct smrt_report_logical_lun_ent {
	LogDevAddr_t smrle_addr;
} smrt_report_logical_lun_ent_t;

typedef struct smrt_report_logical_lun_extent {
	LogDevAddr_t smrle_addr;
	uint8_t smrle_wwn[16];
} smrt_report_logical_lun_extent_t;

typedef struct smrt_report_logical_lun {
	uint32_t smrll_datasize; /* Big Endian */
	uint8_t smrll_extflag;
	uint8_t smrll_reserved1[3];
	union {
		smrt_report_logical_lun_ent_t ents[SMRT_MAX_LOGDRV];
		smrt_report_logical_lun_extent_t extents[SMRT_MAX_LOGDRV];
	} smrll_data;
} smrt_report_logical_lun_t;

typedef struct smrt_report_logical_lun_req {
	uint8_t smrllr_opcode;
	uint8_t smrllr_extflag;
	uint8_t smrllr_reserved1[4];
	uint32_t smrllr_datasize; /* Big Endian */
	uint8_t smrllr_reserved2;
	uint8_t smrllr_control;
} smrt_report_logical_lun_req_t;

typedef struct smrt_report_physical_lun_ent {
	PhysDevAddr_t srple_addr;
} smrt_report_physical_lun_ent_t;

/*
 * This structure represents the 'physical node identifier' extended option for
 * REPORT PHYSICAL LUNS.  This is triggered when the extended flags is set to
 * 0x1.  Note that for SAS the other structure should always be used.
 */
typedef struct smrt_report_physical_pnid {
	uint8_t srpp_node[8];
	uint8_t srpp_port[8];
} smrt_report_physical_pnid_t;

/*
 * This structure represents the 'other physical device info' extended option
 * for report physical luns.  This is triggered when the extended flags is set
 * to 0x2.
 */
typedef struct smrt_report_physical_opdi {
	uint8_t srpo_wwid[8];
	uint8_t srpo_dtype;
	uint8_t srpo_flags;
	uint8_t srpo_multilun;
	uint8_t srpo_paths;
	uint32_t srpo_iohdl;
} smrt_report_physical_opdi_t;

typedef struct smrt_report_physical_lun_extent {
	PhysDevAddr_t srple_addr;
	union {
		smrt_report_physical_pnid_t srple_pnid;
		smrt_report_physical_opdi_t srple_opdi;
	} srple_extdata;
} smrt_report_physical_lun_extent_t;

/*
 * Values that can be ORed together into smrllr_extflag. smprl_extflag indicates
 * if any extended processing was done or not.
 */
#define	SMRT_REPORT_PHYSICAL_LUN_EXT_NONE	0x00
#define	SMRT_REPORT_PHYSICAL_LUN_EXT_PNID	0x01
#define	SMRT_REPORT_PHYSICAL_LUN_EXT_OPDI	0x02
#define	SMRT_REPORT_PHYSICAL_LUN_EXT_MASK	0x0f
#define	SMRT_REPORT_PHYSICAL_LUN_CTRL_ONLY	(1 << 6)
#define	SMRT_REPORT_PHYSICAL_LUN_ALL_PATHS	(1 << 7)

typedef struct smrt_report_physical_lun {
	uint32_t smrpl_datasize; /* Big Endian */
	uint8_t smrpl_extflag;
	uint8_t smrpl_reserved1[3];
	union {
		smrt_report_physical_lun_ent_t ents[SMRT_MAX_PHYSDEV];
		smrt_report_physical_lun_extent_t extents[SMRT_MAX_PHYSDEV];
	} smrpl_data;
} smrt_report_physical_lun_t;


typedef struct smrt_report_physical_lun_req {
	uint8_t smrplr_opcode;
	uint8_t smrplr_extflag;
	uint8_t smrplr_reserved[1];
	uint32_t smrplr_datasize; /* Big Endian */
	uint8_t smrplr_reserved2;
	uint8_t smrplr_control;
} smrt_report_physical_lun_req_t;

/*
 * Request structure for the BMIC command IDENTIFY CONTROLLER.  This structure
 * is written into the CDB with the CISS_SCMD_BMIC_READ SCSI opcode.  Reserved
 * fields should be filled with zeroes.
 */
typedef struct smrt_identify_controller_req {
	uint8_t smicr_opcode;
	uint8_t smicr_lun;
	uint8_t smicr_reserved1[4];
	uint8_t smicr_command;
	uint8_t smicr_reserved2[2];
	uint8_t smicr_reserved3[1];
	uint8_t smicr_reserved4[6];
} smrt_identify_controller_req_t;

/*
 * Response structure for IDENTIFY CONTROLLER.  This structure is used to
 * interpret the response the controller will write into the data buffer.
 */
typedef struct smrt_identify_controller {
	uint8_t smic_logical_drive_count;
	uint32_t smic_config_signature;
	uint8_t smic_firmware_rev[4];
	uint8_t smic_recovery_rev[4];
	uint8_t smic_hardware_version;
	uint8_t smic_bootblock_rev[4];

	/*
	 * These are obsolete for SAS controllers:
	 */
	uint32_t smic_drive_present_map;
	uint32_t smic_external_drive_map;

	uint32_t smic_board_id;
} smrt_identify_controller_t;

/*
 * Request structure for IDENTIFY PHYSICAL DEVICE.  This structure is written
 * into the CDB with the CISS_SCMD_BMIC_READ SCSI opcode.  Reserved fields
 * should be filled with zeroes.  Note, the lower 8 bits of the BMIC ID are in
 * index1, whereas the upper 8 bites are in index2; however, the controller may
 * only support 8 bits worth of devices (and this driver does not support that
 * many devices).
 */
typedef struct smrt_identify_physical_drive_req {
	uint8_t sipdr_opcode;
	uint8_t sipdr_lun;
	uint8_t	sipdr_bmic_index1;
	uint8_t sipdr_reserved1[3];
	uint8_t sipdr_command;
	uint8_t sipdr_reserved2[2];
	uint8_t sipdr_bmic_index2;
	uint8_t sipdr_reserved4[6];
} smrt_identify_physical_drive_req_t;

/*
 * Relevant values for the sipd_more_flags member.
 */
#define	SMRT_MORE_FLAGS_LOGVOL	(1 << 5)
#define	SMRT_MORE_FLAGS_SPARE	(1 << 6)

/*
 * Response structure for IDENTIFY PHYSICAL DEVICE.  This structure is used to
 * describe aspects of a physical drive. Note, not all fields are valid in all
 * firmware revisions.
 */
typedef struct smrt_identify_physical_drive {
	uint8_t		sipd_scsi_bus;	/* Invalid for SAS */
	uint8_t		sipd_scsi_id;	/* Invalid for SAS */
	uint16_t	sipd_lblk_size;
	uint32_t	sipd_nblocks;
	uint32_t	sipd_rsrvd_blocsk;
	uint8_t		sipd_model[40];
	uint8_t		sipd_serial[40];
	uint8_t		sipd_firmware[8];
	uint8_t		sipd_scsi_inquiry;
	uint8_t		sipd_compaq_stamp;
	uint8_t		sipd_last_failure;
	uint8_t		sipd_flags;
	uint8_t		sipd_more_flags;
	uint8_t		sipd_scsi_lun;	/* Invalid for SAS */
	uint8_t		sipd_yet_more_flags;
	uint8_t		sipd_even_more_flags;
	uint32_t	sipd_spi_speed_rules;
	uint8_t		sipd_phys_connector[2];
	uint8_t		sipd_phys_box_on_bus;
	uint8_t		sipd_phys_bay_in_box;
	uint32_t	sipd_rpm;
	uint8_t		sipd_device_type;
	uint8_t		sipd_sata_version;
	uint64_t	sipd_big_nblocks;
	uint64_t	sipd_ris_slba;
	uint32_t	sipd_ris_size;
	uint8_t		sipd_wwid[20];
	uint8_t		sipd_controller_phy_map[32];
	uint16_t	sipd_phy_count;
	uint8_t		sipd_phy_connected_dev_type[256];
	uint8_t		sipd_phy_to_drive_bay[256];
	uint16_t	sipd_phy_to_attached_dev[256];
	uint8_t		sipd_box_index;
	uint8_t		sipd_drive_support;
	uint16_t	sipd_extra_flags;
	uint8_t		sipd_neogiated_link_rate[256];
	uint8_t		sipd_phy_to_phy_map[256];
	uint8_t		sipd_pad[312];
} smrt_identify_physical_drive_t;

/*
 * Note that this structure describes the CISS version of the command. There
 * also exists a BMIC version, but it has a slightly different structure.  This
 * structure is also used for the cancellation request; however, in that case,
 * the senr_flags field is reserved.
 */
typedef struct smrt_event_notify_req {
	uint8_t		senr_opcode;
	uint8_t		senr_subcode;
	uint8_t		senr_reserved1[2];
	uint32_t	senr_flags;	/* Big Endian */
	uint32_t	senr_size;	/* Big Endian */
	uint8_t		senr_control;
} smrt_event_notify_req_t;

/*
 * When receiving event notifications, the buffer size must be 512 bytes large.
 * We make sure that we always allocate a buffer of this size, even though we
 * define a structure that is much shorter and only uses the fields that we end
 * up caring about.  This size requirement comes from the specification.
 */
#define	SMRT_EVENT_NOTIFY_BUFLEN	512

#define	SMRT_EVENT_CLASS_PROTOCOL		0
#define	SMRT_EVENT_PROTOCOL_SUBCLASS_ERROR	1

#define	SMRT_EVENT_CLASS_HOTPLUG		1
#define	SMRT_EVENT_HOTPLUG_SUBCLASS_DRIVE	0

#define	SMRT_EVENT_CLASS_HWERROR		2
#define	SMRT_EVENT_CLASS_ENVIRONMENT		3

#define	SMRT_EVENT_CLASS_PHYS			4
#define	SMRT_EVENT_PHYS_SUBCLASS_STATE		0

#define	SMRT_EVENT_CLASS_LOGVOL			5

typedef struct smrt_event_notify {
	uint32_t	sen_timestamp;
	uint16_t	sen_class;
	uint16_t	sen_subclass;
	uint16_t	sen_detail;
	uint8_t		sen_data[64];
	char		sen_message[80];
	uint32_t	sen_tag;
	uint16_t	sen_date;
	uint16_t	sen_year;
	uint32_t	sen_time;
	uint16_t	sen_pre_power_time;
	LUNAddr_t	sen_addr;
} smrt_event_notify_t;

#pragma pack()

#ifdef	__cplusplus
}
#endif

#endif	/* _SMRT_SCSI_H */
