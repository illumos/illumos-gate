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

#ifndef	_CPQARY3_IOCTL_H
#define	_CPQARY3_IOCTL_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * USED in Ioctls
 */

#define	CPQARY3_SCSI_IN		0
#define	CPQARY3_SCSI_OUT	1
#define	CPQARY3_NODATA_XFER	2
#define	SUCCESS			0
#define	FAILURE			-1

/* for SAS support */
/* BMIC Commands */
#define	HPSAS_ID_LOG_DRIVE		0x10
#define	HPSAS_ID_CONTROLLER		0x11
#define	HPSAS_SENSE_LOG_DRIVE		0x12
#define	HPSAS_ID_PHYSICAL_DRIVE		0x15
#define	HPSAS_READ			0x20
#define	HPSAS_WRITE			0x30
#define	HPSAS_WRITE_THROUGH		0x31
#define	HPSAS_SENSE_CONFIG		0x50
#define	HPSAS_SET_CONFIG		0x51
#define	HPSAS_BYPASS_VOL_STATE		0x52
#define	HPSAS_CHANGE_CONFIG		0x54
#define	HPSAS_SENSE_ORIG_CONFIG		0x55
#define	HPSAS_LABEL_LOG_DRIVE		0x57
#define	HPSAS_SENSE_BUS_PARAMS		0x65
#define	HPSAS_TAPE_INQUIRY		0x92
#define	HPSAS_RESUME_BKGND_ACTIVITY	0x99
#define	HPSAS_SENSE_MP_STAT		0xA0
#define	HPSAS_SET_MP_THRESHOLD		0xA1
#define	HPSAS_MP_PARAM_CONTROL		0xA4
#define	HPSAS_SENSE_DRV_ERR_LOG		0xA6
#define	HPSAS_FLUSH_CACHE		0xc2
#define	HPSAS_REPORT_LOGICAL_LUN	0xC2
#define	HPSAS_REPORT_PHYSICAL_LUN	0xC3
#define	HPSAS_SET_MP_VALUE		0xF3
#define	HPSAS_BMIC_CMD_LEN		16


#pragma pack(1)

typedef struct cpqary3_ioctl_request {
	uint32_t	len;		/* Data Buffer length */
	uint32_t	reserved;	/* For future enhancements */
	uint64_t	argp;		/* Data or data Buffer of the request */
} cpqary3_ioctl_request_t;

typedef struct cpqary3_drvrev {
	uint8_t		minor; 		/* Version info */
	uint8_t		major;
	uint8_t		mm;		/* Revision Date */
	uint8_t		dd;
	uint16_t	yyyy;
} cpqary3_drvrev_t;

typedef struct cpqary3_driver_info {
	int8_t		name[16];	/* Null Term. ASCII driver name */
	cpqary3_drvrev_t version;	/* Driver version and revision */
	uint32_t	num_ctlr;	/* Num of ctlrs currently handled */
	uint32_t	max_num_ctlr;	/* Max num ctlrs supported */
	int8_t		reserved[98];	/* Structure size = 128 bytes */
} cpqary3_driver_info_t;

typedef struct cpqary3_ctlr_info {
	uint16_t	state;		/* currently set to active */
	uint32_t	board_id;	/* controllers board_id */
	uint32_t	subsystem_id;	/* controllers subsystem_id */
	uint8_t		bus;		/* controllers PCI Bus number */
	uint8_t		dev : 5;	/* 5 bit device number */
	uint8_t		fun : 3;	/* 3 bit function number */
	uint16_t	slot_num;	/* physical slot number */
	uint8_t		num_of_tgts;	/* No of Logical Drives */
	uint32_t	controller_instance; /* Ap id number */
	int8_t		reserved[109];	/* Structure size = 128 bytes */
} cpqary3_ctlr_info_t;

typedef struct cpqary3_bmic_pass {
	uint8_t		lun_addr[8];	/* 8 byte LUN address */
	uint8_t		cmd;		/* BMIC command opcode */
	uint8_t		cmd_len;	/* BMIC command length */
	uint16_t	unit_number;	/* Unit number */
	uint32_t	blk_number;	/* BMIC Detail */
	uint16_t	bmic_index;	/* bmic_index */
	uint16_t	timeout;	/* timeout for command */
	uint8_t		io_direction;	/* IN(0) or OUT(1) */
	uint8_t		err_status;	/* command completion status */
	ErrorInfo_t	err_info;	/* error info */
	uint16_t	buf_len;	/* buffer/transfer length */
	uint64_t	buf;		/* buffer */
} cpqary3_bmic_pass_t;

typedef struct cpqary3_scsi_pass {
	uint8_t		lun_addr[8];	/* 8 byte LUN address */
	uint8_t		cdb[16];	/* 16 byte CDB */
	uint8_t		cdb_len;	/* SCSI CDB length */
	uint16_t	timeout;	/* timeout for command */
	uint8_t		io_direction;	/* IN(0) or OUT(1) */
	uint8_t		err_status;	/* command completion status */
	ErrorInfo_t	err_info;	/* error info */
	uint16_t	buf_len;	/* buffer/transfer length */
	uint64_t	buf;		/* buffer */
} cpqary3_scsi_pass_t;

#pragma pack()

#ifdef	__cplusplus
}
#endif

#endif	/* _CPQARY3_IOCTL_H */
