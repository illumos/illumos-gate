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
 */

#ifndef	_CPQARY3_SCSI_H
#define	_CPQARY3_SCSI_H

#include <sys/types.h>
#include "cpqary3_ciss.h"

#ifdef	__cplusplus
extern "C" {
#endif

/* CISS LUN Addressing MODEs */
#define	PERIPHERIAL_DEV_ADDR 			0x0
#define	LOGICAL_VOL_ADDR 				0x1
#define	MASK_PERIPHERIAL_DEV_ADDR 		0x3
#define	CISS_PHYS_MODE 					0x0

/*
 * Definitions for compatibility with the old array BMIC interface
 * CISS_OPCODE_RLL IS THE OPCODE FOR THE Report Logical Luns command
 */
#define	ARRAY_READ				0x26
#define	ARRAY_WRITE				0x27
#define	CISS_NEW_READ				0xC0
#define	CISS_NEW_WRITE				0xC1
#define	CISS_OPCODE_RLL				0xC2
#define	CISS_OPCODE_RPL				0xC3
#define	CISS_NO_TIMEOUT				0x0

/*
 * BMIC commands
 */
#define	CISS_FLUSH_CACHE			0xC2
#define	BMIC_IDENTIFY_LOGICAL_DRIVE		0x10
#define	BMIC_SENSE_LOGICAL_DRIVE_STATUS		0x12

#define	CISS_MSG_ABORT				0x0
#define	CISS_ABORT_TASK				0x0
#define	CISS_ABORT_TASKSET			0x1
#define	CISS_CTLR_INIT 				0xffff0000

#define	CISS_MSG_RESET				0x1
#define	CISS_RESET_CTLR				0x0
#define	CISS_RESET_TGT				0x3

/*
 * The Controller SCSI ID is 7. Hence, when ever the OS issues a command
 * for a target with ID greater than 7, the intended Logical Drive is
 * actually one less than the issued ID.
 * So, the allignment.
 * The Mapping from OS to the HBA is as follows:
 *	OS Target IDs		HBA taret IDs
 *		0 - 6				0 - 6
 *		7					- (Controller)
 *		8 - 32				7 - 31
 */

#define	CPQARY3_TGT_ALIGNMENT			0x1
#define	CPQARY3_LEN_TAGINUSE			0x4

#define	CPQARY3_CDBLEN_12				12
#define	CPQARY3_CDBLEN_16				16

/*
 * possible values to fill in the cmdpvt_flag member
 * in the cpqary3_cmdpvt_t structure
 */
#define	CPQARY3_TIMEOUT			1
#define	CPQARY3_CV_TIMEOUT		2
#define	CPQARY3_RESET			4
#define	CPQARY3_SYNC_SUBMITTED		8
#define	CPQARY3_SYNC_TIMEOUT		16

#define	CPQARY3_INTR_ENABLE 		1
#define	CPQARY3_INTR_DISABLE 		2

#define	CPQARY3_LOCKUP_INTR_ENABLE 	1
#define	CPQARY3_LOCKUP_INTR_DISABLE 	2

#define	CPQARY3_COALESCE_DELAY		0x0
#define	CPQARY3_COALESCE_COUNT		0x00000001l

#define	CPQARY3_NO_MUTEX 		0
#define	CPQARY3_HOLD_SW_MUTEX		1

/* Completed With NO Error */
#define	CPQARY3_OSCMD_SUCCESS		0x0
#define	CPQARY3_SELFCMD_SUCCESS		0x2
#define	CPQARY3_NOECMD_SUCCESS		0x4
#define	CPQARY3_SYNCCMD_SUCCESS		0x6

/* Completed With ERROR */
#define	CPQARY3_OSCMD_FAILURE		0x1
#define	CPQARY3_SELFCMD_FAILURE		0x3
#define	CPQARY3_NOECMD_FAILURE		0x5
#define	CPQARY3_SYNCCMD_FAILURE		0x7

/* Fatal SCSI Status */
#define	SCSI_CHECK_CONDITION			0x2
#define	SCSI_COMMAND_TERMINATED			0x22

#pragma pack(1)

typedef struct flushcache {
	uint16_t	disable_flag;
	uint8_t		reserved[510];
} flushcache_buf_t;

typedef struct each_logical_lun_data {
	uint32_t	logical_id:30;
	uint32_t	mode:2;
	uint8_t		reserved[4];
} each_ll_data_t;

typedef struct rll_data {
	uint8_t			lunlist_byte3;
	uint8_t			lunlist_byte2;
	uint8_t			lunlist_byte1;
	uint8_t			lunlist_byte0;
	uint32_t		reserved;
	each_ll_data_t	ll_data[MAX_LOGDRV];
} rll_data_t;

typedef struct each_physical_lun_data {
	uint32_t	    DevID;
	uint32_t	    SecLevel;
} each_pl_data_t;

typedef struct rpl_data {
	uint8_t			lunlist_byte3;
	uint8_t			lunlist_byte2;
	uint8_t			lunlist_byte1;
	uint8_t			lunlist_byte0;
	uint32_t		reserved;
	PhysDevAddr_t	pl_data[CPQARY3_MAX_TGT];
} rpl_data_t;


/*
 * Format of the data returned for the IDENTIFY LOGICAL DRIVE Command
 */

typedef struct Identify_Logical_Drive {
	uint16_t	block_size_in_bytes;
	uint32_t	blocks_available;
	uint16_t	cylinders;
	uint8_t		heads;
	uint8_t		general[11];
	uint8_t		sectors;
	uint8_t		checksum;
	uint8_t		fault_tolerance;
	uint8_t		reserved;
	uint8_t		bios_disable_flag;
	uint8_t		reserved1;
	uint32_t	logical_drive_identifier;
	uint8_t		logical_drive_label[64];
	uint8_t		reserved3[418];
} IdLogDrive;

/* FORMAT */
typedef struct Identify_Ld_Status {
	uint8_t		status;			/* Logical Drive Status */
	uint32_t	failure_map;		/* Drive Failure Map */
	uint16_t	read_error_count[32];	/* read error count */
	uint16_t	write_error_count[32];	/* write error count */
	uint8_t		drive_error_data[256];	/* drive error data */
	uint8_t		drq_time_out_count[32];	/* drq timeout count */
	uint32_t	blocks_left_to_recover;	/* blocks yet to recover */
	uint8_t		drive_recovering;	/* drive recovering */
	uint16_t	remap_count[32];	/* remap count */
	uint32_t	replacement_drive_map;	/* replacement drive map */
	uint32_t	active_spare_map;	/* active spare map */
	uint8_t		spare_status;		/* spare status */
	uint8_t		spare_to_replace_map[32];
	uint32_t	replace_ok_map;		/* Marked ok but no rebuild */
	uint8_t		media_exchanged;	/* Media exchanged (see 0xE0) */
	uint8_t		cache_failure;		/* volume failed cache fail */
	uint8_t		expand_failure;		/* volume failed for failure */
	uint8_t		unit_flags;		/* SMART-2 only */

	/*
	 * The following fields are for firmware supporting > 7 drives per
	 * SCSI bus. The "Drives Per SCSI Bus" indicates how many bits /
	 * words (in case of remap count) correspond to each drive.
	 */
	uint16_t	big_failure_map[8];	/* Big Drive Failure Map */
	uint16_t	big_remap_cnt[128];	/* Big Drive Remap  Count */
	uint16_t	big_replace_map[8];	/* Big Replacement Drive Map */
	uint16_t	big_spare_map[8];	/* Big spare drive map */
	uint8_t		big_spare_replace_map[128]; /* Big spare replace map */
	uint16_t	big_replace_ok_map[8];	/* Big replaced marked OK map */
	uint8_t		big_drive_rebuild;	/* Drive Rebuilding - Drive # */
	uint8_t		reserved[36];
} SenseLdStatus;
/* FORMAT */

/*
 * SCSI Command Opcodes
 */
#define	SCSI_READ_6		0x08	/* READ  - 6  byte command */
#define	SCSI_READ_10		0x28	/* READ  - 10 byte command */
#define	SCSI_READ_12		0xA8	/* READ  - 12 byte command */
#define	SCSI_WRITE_6		0x0A	/* WRITE - 6  byte command */
#define	SCSI_WRITE_10		0x2A	/* WRITE - 10 byte command */
#define	SCSI_WRITE_12		0xAA	/* WRITE - 12 byte command */

/*
 * SCSI Opcodes Not supported by FW
 *
 */
#define	SCSI_LOG_SENSE			0x4D	/* LOG SENSE */
#define	SCSI_MODE_SELECT		0x15	/* LOG SENSE */
#define	SCSI_PERSISTENT_RESERVE_IN	0x5E	/* PERSISTENT RESERVE IN */

#pragma pack()

#ifdef	__cplusplus
}
#endif

#endif	/* _CPQARY3_SCSI_H */
