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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
 */

#ifndef _SATA_HBA_H
#define	_SATA_HBA_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/sata/sata_defs.h>

/*
 * SATA Host Bus Adapter (HBA) driver transport definitions
 */

#include <sys/types.h>

#ifndef	TRUE
#define	TRUE	1
#define	FALSE	0
#endif

#define	SATA_SUCCESS	0
#define	SATA_RETRY	1
#define	SATA_FAILURE	-1


/* SATA Framework definitions */

#define	SATA_MAX_CPORTS		32	/* Max number of controller ports */
					/* Multiplier (PMult) */
#define	SATA_MAX_PMPORTS	16	/* Maximum number of ports on PMult */
#define	SATA_PMULT_HOSTPORT	0xf	/* Port Multiplier host port number */


/*
 * SATA device address
 * Address qualifier flags are used to specify what is addressed (device
 * or port) and where (controller or port multiplier data port).
 */
struct sata_address {
	uint8_t		cport;		/* Controller's SATA port number */
	uint8_t 	pmport;		/* Port Multiplier SATA port number */
	uint8_t		qual;		/* Address Qualifier flags */
	uint8_t		pad;		/* Reserved */
};

typedef struct sata_address sata_address_t;

/*
 * SATA address Qualifier flags (in qual field of sata_address struct).
 * They are mutually exclusive.
 */

#define	SATA_ADDR_NULL		0x00	/* No address */
#define	SATA_ADDR_DCPORT	0x01	/* Device attched to controller port */
#define	SATA_ADDR_DPMPORT	0x02	/* Device attched to PM device port */
#define	SATA_ADDR_CPORT		0x04	/* Controller's device port */
#define	SATA_ADDR_PMPORT	0x08	/* Port Multiplier's device port */
#define	SATA_ADDR_CNTRL		0x10	/* Controller */
#define	SATA_ADDR_PMULT		0x20	/* Port Multiplier */
#define	SATA_ADDR_PMULT_SPEC	0x40	/* Port Multiplier Specific */

/*
 * SATA port status and control register block.
 * The sstatus, serror, scontrol, sactive and snotific
 * are the copies of the SATA port status and control registers.
 * (Port SStatus, SError, SControl, SActive and SNotification are
 * defined by Serial ATA r1.0a sepc and Serial ATA II spec.
 */

struct sata_port_scr
{
	uint32_t	sstatus;	/* Port SStatus register */
	uint32_t	serror;		/* Port SError register */
	uint32_t	scontrol;	/* Port SControl register */
	uint32_t	sactive;	/* Port SActive register */
	uint32_t	snotific; 	/* Port SNotification register */
};

typedef struct sata_port_scr sata_port_scr_t;

/*
 * SATA Port Multiplier general status and control register block.
 * The gscr0, gscr1, gscr2 are the copyies of the register on port multiplier.
 * GSCR[0], GSCR[1], GSCR[2] are defined in SATA defined by Port Multiplier
 * 1.0/1.1/1.2 spec.
 */
struct sata_pmult_gscr {
	uint32_t	gscr0;		/* Product Identifier register */
	uint32_t	gscr1;		/* Resrved Information register */
	uint32_t	gscr2;		/* Port Information register */
	uint32_t	gscr64;		/* Feature register */
	uint32_t	resv[4];	/* Reseved */
};

typedef struct sata_pmult_gscr sata_pmult_gscr_t;

/*
 * SATA Device Structure (rev 1)
 * Used to request/return state of the controller, port, port multiplier
 * or an attached drive:
 *  	The satadev_addr.cport, satadev_addr.pmport and satadev_addr.qual
 *  	fields are used to specify SATA address (see sata_address structure
 *  	description).
 * 	The satadev_scr structure is used to pass the content of a port
 *	status and control registers.
 *	The satadev_add_info field is used by SATA HBA driver to return an
 *	additional information, which type depends on the function using
 *	sata_device as argument. For example:
 *	- in case of sata_tran_probe_port() this field should contain
 *	a number of available Port Multiplier device ports;
 *	- in case of sata_hba_event_notify() this field may contain
 *	a value specific for a reported event.
 */
#define	SATA_DEVICE_REV_1	1
#define	SATA_DEVICE_REV		SATA_DEVICE_REV_1

struct sata_device
{
	int		satadev_rev;		/* structure  version */
	struct sata_address satadev_addr;	/* sata port/device address */
	uint32_t	satadev_state;		/* Port or device state */
	uint32_t	satadev_type;		/* Attached device type */
	struct sata_port_scr satadev_scr; 	/* Port status and ctrl regs */
	uint32_t	satadev_add_info;	/* additional information, */
						/* function specific */
};

typedef struct sata_device sata_device_t;

_NOTE(SCHEME_PROTECTS_DATA("unshared data", sata_device))


/*
 * satadev_state field of sata_device structure.
 * Common flags specifying current state of a port or an attached drive.
 * These states are mutually exclusive, obviously
 */
#define	SATA_STATE_UNKNOWN		0x000000
#define	SATA_STATE_READY		0x000010

/*
 * Attached drive specific states (satadev_state field of the sata_device
 * structure).
 * SATA_DSTATE_PWR_ACTIVE, SATA_DSTATE_PWR_IDLE and SATA_DSTATE_PWR_STANDBY
 * are mutually exclusive. All other states may be combined with each other
 * and with one of the power states.
 * These flags may be used only if the address qualifier (satadev_addr.qual) is
 * set to SATA_ADDR_DCPORT or SATA_ADDR_DPMPORT value.
 */

#define	SATA_DSTATE_PWR_ACTIVE		0x000100
#define	SATA_DSTATE_PWR_IDLE		0x000200
#define	SATA_DSTATE_PWR_STANDBY		0x000400
#define	SATA_DSTATE_RESET		0x001000
#define	SATA_DSTATE_PMULT_INIT		0x002000
#define	SATA_DSTATE_FAILED		0x008000

/* Mask for drive power states */
#define	SATA_DSTATE_PWR			(SATA_DSTATE_PWR_ACTIVE | \
					SATA_DSTATE_PWR_IDLE | \
					SATA_DSTATE_PWR_STANDBY)
/*
 * SATA Port specific states (satadev_state field of sata_device structure).
 * SATA_PSTATE_PWRON and SATA_PSTATE_PWROFF are mutually exclusive.
 * All other states may be combined with each other and with one of the power
 * level state.
 * These flags may be used only if the address qualifier (satadev_addr.qual) is
 * set to SATA_ADDR_CPORT or SATA_ADDR_PMPORT value.
 */

#define	SATA_PSTATE_PWRON		0x010000
#define	SATA_PSTATE_PWROFF		0X020000
#define	SATA_PSTATE_SHUTDOWN		0x040000
#define	SATA_PSTATE_FAILED		0x080000

/* Mask for the valid port-specific state flags */
#define	SATA_PSTATE_VALID		(SATA_PSTATE_PWRON | \
					SATA_PSTATE_PWROFF | \
					SATA_PSTATE_SHUTDOWN | \
					SATA_PSTATE_FAILED)

/* Mask for a port power states */
#define	SATA_PSTATE_PWR			(SATA_PSTATE_PWRON | \
					SATA_PSTATE_PWROFF)
/*
 * Device type (in satadev_type field of sata_device structure).
 * More device types may be added in the future.
 */

#define	SATA_DTYPE_NONE			0x00	/* No device attached */
#define	SATA_DTYPE_ATADISK		0x01	/* ATA disk */
#define	SATA_DTYPE_ATAPI		0x40	/* ATAPI device */
#define	SATA_DTYPE_ATAPICD	\
	(SATA_DTYPE_ATAPI|0x02)			/* ATAPI CD/DVD device */
#define	SATA_DTYPE_ATAPITAPE	\
	(SATA_DTYPE_ATAPI|0x04)			/* ATAPI tape */
#define	SATA_DTYPE_ATAPIDISK	\
	(SATA_DTYPE_ATAPI|0x08)			/* ATAPI disk */
#define	SATA_DTYPE_PMULT		0x10	/* Port Multiplier */
#define	SATA_DTYPE_UNKNOWN		0x20	/* Device attached, unkown */
#define	SATA_DTYPE_ATAPIPROC	\
	(SATA_DTYPE_ATAPI|0x80)			/* ATAPI processor */


/*
 * SATA cmd structure  (rev 1)
 *
 * SATA HBA framework always sets all fields except status_reg and error_reg.
 * SATA HBA driver action depends on the addressing type specified by
 * addr_type field:
 * If LBA48 addressing is indicated, SATA HBA driver has to load values from
 * satacmd_sec_count_msb_reg, satacmd_lba_low_msb_reg,
 * satacmd_lba_mid_msb_reg and satacmd_lba_hi_msb_reg
 * to appropriate registers prior to loading other registers.
 * For other addressing modes, SATA HBA driver should skip loading values
 * from satacmd_sec_count_msb_reg, satacmd_lba_low_msb_reg,
 * satacmd_lba_mid_msb_reg and satacmd_lba_hi_msb_reg
 * fields and load only remaining field values to corresponding registers.
 *
 * satacmd_sec_count_msb and satamcd_sec_count_lsb values are loaded into
 * sec_count register, satacmd_sec_count_msb loaded first (if LBA48
 * addressing is used).
 * satacmd_lba_low_msb and satacmd_lba_low_lsb values are loaded into the
 * lba_low register, satacmd_lba_low_msb loaded first (if LBA48 addressing
 * is used). The lba_low register is the newer name for the old
 * sector_number register.
 * satacmd_lba_mid_msb and satacmd_lba_mid_lsb values are loaded into lba_mid
 * register, satacmd_lba_mid_msb loaded first (if LBA48 addressing is used).
 * The lba_mid register is the newer name for the old cylinder_low register.
 * satacmd_lba_high_msb and satacmd_lba_high_lsb values are loaded into
 * the lba_high regster, satacmd_lba_high_msb loaded first (if LBA48
 * addressing is used). The lba_high register  is a newer name for the old
 * cylinder_high register.
 *
 * No addressing mode is selected when an ata command does not involve actual
 * reading/writing data from/to the media (for example IDENTIFY DEVICE or
 * SET FEATURE command), or the ATAPI PACKET command is sent.
 * If ATAPI PACKET command is sent and tagged commands are used,
 * SATA HBA driver has to provide and manage a tag value and
 * set it into the sector_count register.
 *
 * Device Control register is not specified in sata_cmd structure - SATA HBA
 * driver shall set it accordingly to current mode of operation (interrupt
 * enable/disable).
 *
 * Buffer structure's b_flags should be used to determine the
 * address type of b_un.b_addr. However, there is no need to allocate DMA
 * resources for the buffer in SATA HBA driver.
 * DMA resources for a buffer structure are allocated by the SATA HBA
 * framework. Scatter/gather list is to be used only for DMA transfers
 * and it should be based on the DMA cookies list.
 *
 * Upon completion of a command, SATA HBA driver has to update
 * satacmd_status_reg and satacmd_error_reg to reflect the contents of
 * the corresponding device status and error registers.
 * If the command completed successfully, satacmd_flags.sata_copy_xxx flags
 * specify what register fields should be updated in sata_cmd structure.
 * If the command completed with error, SATA HBA driver has to update
 * satacmd_sec_count_msb, satacmd_sec_count_lsb, satacmd_lba_low_msb,
 * satacmd_lba_low_lsb, satacmd_lba_mid_msb, satacmd_lba_mid_lsb,
 * satacmd_lba_high_msb and satacmd_lba_high_lsb to values read from the
 * corresponding device registers.
 * If an operation could not complete because of the port error, the
 * sata_pkt.satapkt_device.satadev_scr structure has to be updated.
 *
 * If ATAPI PACKET command was sent and command completed with error,
 * rqsense structure has to be filed by SATA HBA driver. The satacmd_arq_cdb
 * points to pre-set request sense cdb that may be used for issuing request
 * sense data from the device.
 *
 * The sata_max_queue_depth field specifies the maximum allowable queue depth
 * minus one, i.e. for maximum queue depth of 32, sata_max_queue_depth would
 * be set to value 0x1f.
 * If FPDMA-type command was sent and command completed with error, the HBA
 * driver may use pre-set command READ LOG EXTENDED command pointed to
 * by satacmd_rle_sata_cmd field to retrieve error data from a device.
 * Only ATA register fields of the sata_cmd are set-up for that purpose.
 *
 * If the READ MULTIPLIER command was specified in cmd_reg (command directed
 * to a port multiplier host port rather then to an attached device),
 * upon the command completion SATA HBA driver has to update_sector count
 * and lba fields of the sata_cmd structure to values returned via
 * command block registers (task file registers).
 */
#define	SATA_CMD_REV_1	1
#define	SATA_CMD_REV_2	2
#define	SATA_CMD_REV_3	3
#define	SATA_CMD_REV	SATA_CMD_REV_3

#define	SATA_ATAPI_MAX_CDB_LEN	16	/* Covers both 12 and 16 byte cdbs */
#define	SATA_ATAPI_RQSENSE_LEN	24	/* Allocated Request Sense data */
#define	SATA_ATAPI_MIN_RQSENSE_LEN 18	/* Min Fixed size Request Sense data */
#define	SATA_ATAPI_RQSENSE_CDB_LEN 6	/* Request Sense CDB length */

#define	SATA_MAX_QUEUE_DEPTH	32	/* Default max queue depth */

struct sata_cmd {
	int		satacmd_rev;		/* version */
	struct buf	*satacmd_bp;		/* ptr to buffer structure */
	struct sata_cmd_flags {
		uint32_t	sata_data_direction : 3;	 /* 0-2 */
		uint32_t	: 1;		/* reserved */	 /* 3 */
		uint32_t	sata_queue_stag : 1;		 /* 4 */
		uint32_t	sata_queue_otag : 1;		 /* 5 */
		uint32_t	: 2;		/* reserved */	 /* 6-7 */
		uint32_t	sata_queued : 1;		 /* 8 */
		uint32_t	: 3;		/* reserved */	 /* 9-11 */
		uint32_t	sata_ignore_dev_reset : 1;	 /* 12 */
		uint32_t	sata_clear_dev_reset : 1;	 /* 13 */
		uint32_t	: 2;		/* reserved */	 /* 14-15 */
		uint32_t	sata_special_regs : 1;		 /* 16 */
		uint32_t	sata_copy_out_sec_count_msb : 1; /* 17 */
		uint32_t	sata_copy_out_lba_low_msb : 1;	 /* 18 */
		uint32_t	sata_copy_out_lba_mid_msb : 1;	 /* 19 */
		uint32_t	sata_copy_out_lba_high_msb : 1;	 /* 20 */
		uint32_t	sata_copy_out_sec_count_lsb : 1; /* 21 */
		uint32_t	sata_copy_out_lba_low_lsb : 1;	 /* 22 */
		uint32_t	sata_copy_out_lba_mid_lsb : 1;	 /* 23 */
		uint32_t	sata_copy_out_lba_high_lsb : 1;	 /* 24 */
		uint32_t	sata_copy_out_device_reg : 1;	 /* 25 */
		uint32_t	sata_copy_out_error_reg : 1;	 /* 26 */
		uint32_t	sata_max_queue_depth: 5;	 /* 27-31 */
	} satacmd_flags;
	uint8_t 	satacmd_addr_type; 	/* addr type: LBA28, LBA48 */
	uint8_t		satacmd_features_reg_ext; /* features reg extended */
	uint8_t		satacmd_sec_count_msb;	/* sector count MSB (LBA48) */
	uint8_t		satacmd_lba_low_msb; 	/* LBA Low MSB (LBA48) */
	uint8_t		satacmd_lba_mid_msb;	/* LBA Mid MSB (LBA48) */
	uint8_t		satacmd_lba_high_msb;	/* LBA High MSB (LBA48) */
	uint8_t		satacmd_sec_count_lsb;	/* sector count LSB */
	uint8_t		satacmd_lba_low_lsb;	/* LBA Low LSB */
	uint8_t		satacmd_lba_mid_lsb;	/* LBA Mid LSB */
	uint8_t		satacmd_lba_high_lsb;	/* LBA High LSB */
	uint8_t		satacmd_device_reg;	/* ATA dev reg & LBA28 MSB */
	uint8_t		satacmd_cmd_reg;	/* ata command code */
	uint8_t		satacmd_features_reg;	/* ATA features register */
	uint8_t		satacmd_status_reg;	/* ATA status register */
	uint8_t		satacmd_error_reg;	/* ATA error register  */
	uint8_t		satacmd_acdb_len;	/* ATAPI cdb length */
	uint8_t		satacmd_acdb[SATA_ATAPI_MAX_CDB_LEN]; /* ATAPI cdb */

						/* kept for binary compat. */
	uint8_t		*pad1;			/* unused */

	uint8_t 	satacmd_rqsense[SATA_ATAPI_RQSENSE_LEN];
						/*
						 * Error retrieval buffer
						 * dma handle pointer
						 * (for buffer DMA syncing)
						 * Valid only in error
						 * retrieval packet!
						 */
	ddi_dma_handle_t *satacmd_err_ret_buf_handle;

	int		satacmd_num_dma_cookies; /* number of dma cookies */
						/* ptr to dma cookie list */
	ddi_dma_cookie_t *satacmd_dma_cookie_list;
};

typedef struct sata_cmd sata_cmd_t;

_NOTE(SCHEME_PROTECTS_DATA("unshared data", sata_cmd))


/* ATA address type (in satacmd_addr_type field */
#define	ATA_ADDR_LBA	0x1
#define	ATA_ADDR_LBA28	0x2
#define	ATA_ADDR_LBA48	0x4

/*
 * satacmd_flags : contain data transfer direction flags,
 * tagged queuing type flags, queued command flag, and reset state handling
 * flag.
 */

/*
 * Data transfer direction flags (satacmd_flags.sata_data_direction)
 * Direction flags are mutually exclusive.
 */
#define	SATA_DIR_NODATA_XFER	0x0001	/* No data transfer */
#define	SATA_DIR_READ		0x0002	/* Reading data from a device */
#define	SATA_DIR_WRITE		0x0004	/* Writing data to a device */

/*
 * Tagged Queuing type flags
 * 	satacmd_flags.sata_queue_stag
 * 	satacmd_flags.sata_queue_otag
 *
 * These flags indicate how the SATA command should be queued.
 *
 * sata_queue_stag
 * Simple-queue-tagged command. It may be executed out-of-order in respect
 * to other queued commands.
 * sata_queue_otag
 * Ordered-queue-tagged command. It cannot be executed out-of-order in
 * respect to other commands, i.e. it should be executed in the order of
 * being transported to the HBA.
 *
 * Translated head-of-queue-tagged scsi commands and commands that are
 * to be put at the head of the queue are treated as sata_queue_otag
 * tagged commands.
 */


/*
 * Queuing command set-up flag (satacmd_flags.sata_queued).
 * This flag indicates that sata_cmd was set-up for DMA Queued command
 * (either READ_DMA_QUEUED, READ_DMA_QUEUED_EXT, WRITE_DMA_QUEUED or
 * WRITE_DMA_QUEUED_EXT command) or one of the Native Command Queuing commands
 * (either READ_FPDMA_QUEUED or WRITE_FPDMA_QUEUED).
 * This flag will be used only if sata_tran_hba_flags indicates controller
 * support for queuing and the device for which sata_cmd is prepared supports
 * either legacy queuing (indicated by Device Identify data word 83 bit 2)
 * or NCQ (indicated by  word 76 of Device Identify data).
 */

/*
 * Reset state handling
 *	satacmd_flags.sata_ignore_dev_reset
 *	satacmd_flags.sata_clear_dev_reset
 *
 * SATA HBA device enters reset state if the device was subjected to
 * the Device Reset (may also enter this state if the device was reset
 * as a side effect of port reset). SATA HBA driver sets this state.
 * Device stays in this condition until explicit request from SATA HBA
 * framework to clear the state.
 */

/*
 * SATA Packet structure (rev 1)
 * hba_driver_private is for a private use of the SATA HBA driver;
 * satapkt_framework_private is used only by SATA HBA framework;
 * satapkt_comp is a callback function to be called when packet
 * execution is completed (for any reason) if mode of operation is not
 * synchronous (SATA_OPMODE_SYNCH);
 * satapkt_reason specifies why the packet operation was completed
 *
 * NOTE: after the packet completion callback SATA HBA driver should not
 * attempt to access any sata_pkt fields because sata_pkt is not valid anymore
 * (it could have been destroyed).
 * Since satapkt_hba_driver_private field cannot be retrieved, any hba private
 * data respources allocated per packet and accessed via this pointer should
 * either be freed before the completion callback is done, or the pointer has
 * to be saved by the HBA driver before the completion callback.
 */
#define	SATA_PKT_REV_1	1
#define	SATA_PKT_REV	SATA_PKT_REV_1

struct sata_pkt {
	int		satapkt_rev;		/* version */
	struct sata_device satapkt_device;	/* Device address/type */

						/* HBA driver private data */
	void		*satapkt_hba_driver_private;

						/* SATA framework priv data */
	void		*satapkt_framework_private;

						/* Rqsted mode of operation */
	uint32_t	satapkt_op_mode;

	struct sata_cmd	satapkt_cmd;		/* composite sata command */
	int		satapkt_time;		/* time allotted to command */
	void		(*satapkt_comp)(struct sata_pkt *); /* callback */
	int		satapkt_reason; 	/* completion reason */
};

typedef struct sata_pkt sata_pkt_t;

_NOTE(SCHEME_PROTECTS_DATA("unshared data", sata_pkt))


/*
 * Operation mode flags (in satapkt_op_mode field of sata_pkt structure).
 * Use to specify what should be a mode of operation for specified command.
 * Default (000b) means use Interrupt and Asynchronous mode to
 * perform an operation.
 * Synchronous operation menas that the packet operation has to be completed
 * before the function called to initiate the operation returns.
 */
#define	SATA_OPMODE_INTERRUPTS	0 /* Use interrupts (hint) */
#define	SATA_OPMODE_POLLING	1 /* Use polling instead of interrupts */
#define	SATA_OPMODE_ASYNCH	0 /* Return immediately after accepting pkt */
#define	SATA_OPMODE_SYNCH	4 /* Perform synchronous operation */

/*
 * satapkt_reason values:
 *
 * SATA_PKT_QUEUE_FULL - cmd not sent because of queue full (detected
 * 	by the controller). If a device reject command for this reason, it
 * 	should be reported as SATA_PKT_DEV_ERROR
 *
 * SATA_PKT_CMD_NOT_SUPPORTED - command not supported by a controller
 *	Controller is unable to send such command to a device.
 *	If device rejects a command, it should be reported as
 *	SATA_PKT_DEV_ERROR.
 *
 * SATA_PKT_DEV_ERROR - cmd failed because of device reported an error.
 *	The content of status_reg (ERROR bit has to be set) and error_reg
 *	fields of the sata_cmd structure have to be set and will be used
 *	by SATA HBA Framework to determine the error cause.
 *
 * SATA_PKT_PORT_ERROR - cmd failed because of a link or a port error.
 *	Link failed / no communication with a device / communication error
 *	or other port related error was detected by a controller.
 *	sata_pkt.satapkt_device.satadev_scr.sXXXXXXX words have to be set.
 *
 * SATA_PKT_ABORTED - cmd execution was aborted by the request from the
 *	framework. Abort mechanism is HBA driver specific.
 *
 * SATA_PKT_TIMEOUT - cmd execution has timed-out. Timeout specified by
 *	 pkt_time was exceeded. The command was terminated by the SATA HBA
 *	driver.
 *
 * SATA_PKT_COMPLETED - this is a value returned when an operation
 *	completes without errors.
 *
 * SATA_PKT_BUSY - packet was not accepted for execution because the
 *      driver was busy performing some other operation(s).
 *
 * SATA_PKT_RESET - packet execution was aborted because of device
 * reset originated by either the HBA driver or the SATA framework.
 *
 */

#define	SATA_PKT_BUSY			-1	/* Not completed, busy */
#define	SATA_PKT_COMPLETED		0	/* No error */
#define	SATA_PKT_DEV_ERROR		1	/* Device reported error */
#define	SATA_PKT_QUEUE_FULL		2	/* Not accepted, queue full */
#define	SATA_PKT_PORT_ERROR		3	/* Not completed, port error */
#define	SATA_PKT_CMD_UNSUPPORTED	4	/* Cmd unsupported */
#define	SATA_PKT_ABORTED		5	/* Aborted by request */
#define	SATA_PKT_TIMEOUT		6	/* Operation timeut */
#define	SATA_PKT_RESET			7	/* Aborted by reset request */

/*
 * Error retrieval sata packet types
 */
#define	SATA_ERR_RETR_PKT_TYPE_NCQ	1
#define	SATA_ERR_RETR_PKT_TYPE_ATAPI	2

/*
 * Read/write port multiplier packet types
 */
#define	SATA_RDWR_PMULT_PKT_TYPE_READ	1
#define	SATA_RDWR_PMULT_PKT_TYPE_WRITE	2

/*
 * Hoplug functions vector structure (rev 1)
 */
#define	SATA_TRAN_HOTPLUG_OPS_REV_1	1

struct sata_tran_hotplug_ops {
	int	sata_tran_hotplug_ops_rev; /* version */
	int	(*sata_tran_port_activate)(dev_info_t  *, sata_device_t *);
	int	(*sata_tran_port_deactivate)(dev_info_t  *, sata_device_t *);
};

typedef struct sata_tran_hotplug_ops sata_tran_hotplug_ops_t;


/*
 * Power management functions vector structure (rev 1)
 * The embedded function returns information about the controller's
 * power level.
 * Additional functions may be added in the future without changes to
 * sata_tran structure.
 */
#define	SATA_TRAN_PWRMGT_OPS_REV_1	1

struct sata_tran_pwrmgt_ops {
	int	sata_tran_pwrmgt_ops_rev; /* version */
	int	(*sata_tran_get_pwr_level)(dev_info_t  *, sata_device_t *);
};

typedef struct sata_tran_pwrmgt_ops sata_tran_pwrmgt_ops_t;


/*
 * SATA port PHY Power Level
 * These states correspond to the interface power management state as defined
 * in Serial ATA spec.
 */
#define	SATA_TRAN_PORTPWR_LEVEL1	1 /* Interface in active PM state */
#define	SATA_TRAN_PORTPWR_LEVEL2	2 /* Interface in PARTIAL PM state */
#define	SATA_TRAN_PORTPWR_LEVEL3	3 /* Interface in SLUMBER PM state */

/*
 * SATA HBA Tran structure (rev 1)
 * Registered with SATA Framework
 *
 * dma_attr is a pointer to data (buffer) dma attibutes of the controller
 * DMA engine.
 *
 * The qdepth field specifies number of commands that may be accepted by
 * the controller. Value range 1-32. A value greater than 1 indicates that
 * the controller supports queuing. Support for Native Command Queuing
 * indicated by SATA_CTLF_NCQ flag also requires qdepth set to a value
 * greater then 1.
 *
 */
#define	SATA_TRAN_HBA_REV_1	1
#define	SATA_TRAN_HBA_REV_2	2
#define	SATA_TRAN_HBA_REV_3	3
#define	SATA_TRAN_HBA_REV	SATA_TRAN_HBA_REV_3

struct sata_hba_tran {
	int		sata_tran_hba_rev;	/* version */
	dev_info_t	*sata_tran_hba_dip;	/* Controler dev info */
	ddi_dma_attr_t	*sata_tran_hba_dma_attr; /* DMA attributes */
	int		sata_tran_hba_num_cports; /* Num of HBA device ports */
	uint16_t	sata_tran_hba_features_support; /* HBA features */
	uint16_t	sata_tran_hba_qdepth;	/* HBA-supported queue depth */

	int		(*sata_tran_probe_port)(dev_info_t *, sata_device_t *);
	int		(*sata_tran_start)(dev_info_t *, sata_pkt_t *);
	int		(*sata_tran_abort)(dev_info_t *, sata_pkt_t *, int);
	int		(*sata_tran_reset_dport)(dev_info_t *,
					sata_device_t *);
	int		(*sata_tran_selftest)(dev_info_t *, sata_device_t *);

						/* Hotplug vector */
	struct sata_tran_hotplug_ops *sata_tran_hotplug_ops;

						/* Power mgt vector */
	struct sata_tran_pwrmgt_ops *sata_tran_pwrmgt_ops;

	int		(*sata_tran_ioctl)(dev_info_t *, int, intptr_t);
};

typedef struct sata_hba_tran sata_hba_tran_t;


/*
 * Controller's features support flags (sata_tran_hba_features_support).
 * Note: SATA_CTLF_NCQ indicates that SATA controller supports NCQ in addition
 * to legacy queuing commands, indicated by SATA_CTLF_QCMD flag.
 */

#define	SATA_CTLF_ATAPI			0x001 /* ATAPI support */
#define	SATA_CTLF_PORT_MULTIPLIER 	0x010 /* Port Multiplier suport */
#define	SATA_CTLF_HOTPLUG		0x020 /* Hotplug support */
#define	SATA_CTLF_ASN			0x040 /* Asynchronous Event Support */
#define	SATA_CTLF_QCMD			0x080 /* Queued commands support */
#define	SATA_CTLF_NCQ			0x100 /* NCQ support */
#define	SATA_CTLF_PMULT_FBS		0x200 /* FIS-based switching support */

/*
 * sata_tran_start() return values.
 * When pkt is not accepted, the satapkt_reason has to be updated
 * before function returns - it should reflect the same reason for not being
 * executed as the return status of above functions.
 * If pkt was accepted and executed synchronously,
 * satapk_reason should indicate a completion status.
 */
#define	SATA_TRAN_ACCEPTED		0 /* accepted */
#define	SATA_TRAN_QUEUE_FULL		1 /* not accepted, queue full */
#define	SATA_TRAN_PORT_ERROR		2 /* not accepted, port error */
#define	SATA_TRAN_CMD_UNSUPPORTED	3 /* not accepted, cmd not supported */
#define	SATA_TRAN_BUSY			4 /* not accepted, busy */


/*
 * sata_tran_abort() abort type flag
 */
#define	SATA_ABORT_PACKET		0
#define	SATA_ABORT_ALL_PACKETS		1


/*
 * Events handled by SATA HBA Framework
 * More then one event may be reported at the same time
 *
 * SATA_EVNT__DEVICE_ATTACHED
 * HBA detected the presence of a device ( electrical connection with
 * a device was detected ).
 *
 * SATA_EVNT_DEVICE_DETACHED
 * HBA detected the detachment of a device (electrical connection with
 * a device was broken)
 *
 * SATA_EVNT_LINK_LOST
 * HBA lost link with an attached device
 *
 * SATA_EVNT_LINK_ESTABLISHED
 * HBA established a link with an attached device
 *
 * SATA_EVNT_PORT_FAILED
 * HBA has determined that the port failed and is unuseable
 *
 * SATA_EVENT_DEVICE_RESET
 * SATA device was reset, causing loss of the device setting
 *
 * SATA_EVNT_PWR_LEVEL_CHANGED
 * A port or entire SATA controller power level has changed
 *
 * SATA_EVNT_PMULT_LINK_CHANGED
 * Port multiplier detect change on a link of its device port
 *
 */
#define	SATA_EVNT_DEVICE_ATTACHED	0x01
#define	SATA_EVNT_DEVICE_DETACHED	0x02
#define	SATA_EVNT_LINK_LOST		0x04
#define	SATA_EVNT_LINK_ESTABLISHED	0x08
#define	SATA_EVNT_PORT_FAILED		0x10
#define	SATA_EVNT_DEVICE_RESET		0x20
#define	SATA_EVNT_PWR_LEVEL_CHANGED	0x40
#define	SATA_EVNT_PMULT_LINK_CHANGED	0x80

/*
 * SATA Framework interface entry points
 */
int 	sata_hba_init(struct modlinkage *);
int 	sata_hba_attach(dev_info_t *, sata_hba_tran_t *, ddi_attach_cmd_t);
int 	sata_hba_detach(dev_info_t *, ddi_detach_cmd_t);
void 	sata_hba_fini(struct modlinkage *);
void 	sata_hba_event_notify(dev_info_t *, sata_device_t *, int);
sata_pkt_t *sata_get_error_retrieval_pkt(dev_info_t *, sata_device_t *, int);
void	sata_free_error_retrieval_pkt(sata_pkt_t *);
sata_pkt_t *sata_get_rdwr_pmult_pkt(dev_info_t *, sata_device_t *, uint8_t,
    uint32_t, uint32_t);
void	sata_free_rdwr_pmult_pkt(sata_pkt_t *);
void	sata_register_pmult(dev_info_t *, sata_device_t *, sata_pmult_gscr_t *);
void	sata_free_dma_resources(sata_pkt_t *);

/*
 * SATA trace ring buffer constants
 */
#define	DMSG_RING_SIZE		0x100000	/* 1MB */
#define	DMSG_BUF_SIZE		256

/*
 * SATA trace ring buffer content
 */
typedef struct sata_trace_dmsg {
	dev_info_t		*dip;
	timespec_t		timestamp;
	char			buf[DMSG_BUF_SIZE];
	struct sata_trace_dmsg	*next;
} sata_trace_dmsg_t;

/*
 * SATA trace ring buffer header
 */
typedef struct sata_trace_rbuf {
	kmutex_t		lock;		/* lock to avoid clutter */
	int			looped;		/* completed ring */
	int			allocfailed;	/* dmsg mem alloc failed */
	size_t			size;		/* current size */
	size_t			maxsize;	/* max size */
	sata_trace_dmsg_t	*dmsgh;		/* messages head */
	sata_trace_dmsg_t	*dmsgp;		/* ptr to last message */
} sata_trace_rbuf_t;

/*
 * SATA trace ring buffer interfaces
 */
void sata_trace_debug(dev_info_t *, const char *fmt, ...);
void sata_vtrace_debug(dev_info_t *, const char *fmt, va_list);

#ifdef	__cplusplus
}
#endif

#endif /* _SATA_HBA_H */
