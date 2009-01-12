/*
 *
 *	  O.S	: Solaris
 *	FILE NAME  : arcmsr.h
 *	  BY	: Erich Chen
 *	Description: SCSI RAID Device Driver for
 *			ARECA RAID Host adapter
 * ***************************************************************************
 * Copyright (C) 2002,2007 Areca Technology Corporation All rights reserved.
 * Copyright (C) 2002,2007 Erich Chen
 *		Web site: www.areca.com.tw
 *		E-mail: erich@areca.com.tw
 * ***********************************************************************
 *	Redistribution and use in source and binary forms, with or without
 *	modification, are permitted provided that the following conditions
 *	are met:
 *	1. Redistributions of source code must retain the above copyright
 *	 notice, this list of conditions and the following disclaimer.
 *	2. Redistributions in binary form must reproduce the above copyright
 *	 notice, this list of conditions and the following disclaimer in the
 *	 documentation and/or other materials provided with the distribution.
 *	3. The party using or redistributing the source code and binary forms
 *	 agrees to the disclaimer below and the terms and conditions set forth
 *	 herein.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 *  ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *  ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 *  FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 *  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 *  OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 *  HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 *  LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 *  OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 *  SUCH DAMAGE.
 * *************************************************************************
 */
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

#ifndef _SYS_SCSI_ADAPTERS_ARCMSR_H
#define	_SYS_SCSI_ADAPTERS_ARCMSR_H

#ifdef	__cplusplus
	extern "C" {
#endif

#include <sys/sysmacros.h>

#ifndef	TRUE
#define	TRUE	1
#define	FALSE	0
#endif


#ifdef DEBUG
#define	ARCMSR_DEBUG	1
#endif /* DEBUG */


#define	ARCMSR_DRIVER_VERSION		"1.20.00.17Sun"
#define	ARCMSR_SCSI_INITIATOR_ID	255
#define	ARCMSR_DEV_SECTOR_SIZE		512
#define	ARCMSR_MAX_XFER_SECTORS		256
#define	ARCMSR_MAX_SG_ENTRIES		38 /* max 38 */
#define	ARCMSR_MAX_XFER_LEN		0x00200000 /* 2M */
#define	ARCMSR_MAX_TARGETID		17 /* 0-16 */
#define	ARCMSR_MAX_TARGETLUN		8 /* 0-7 */
#define	ARCMSR_MAX_DPC			16 /* defer procedure call */
#define	ARCMSR_MAX_QBUFFER		4096 /* ioctl QBUFFER */
#define	ARCMSR_MAX_ADAPTER		4 /* limitation due to pci-e slots */
#define	ARCMSR_MAX_HBB_POSTQUEUE	264 /* ARCMSR_MAX_OUTSTANDING_CMD+8 */

#define	ARCMSR_MAX_OUTSTANDING_CMD	256
#define	ARCMSR_MAX_FREECCB_NUM		320

#define	CHIP_REG_READ8(handle, a)	\
	(ddi_get8(handle, (uint8_t *)(a)))
#define	CHIP_REG_READ16(handle, a)	\
	(ddi_get16(handle, (uint16_t *)(a)))
#define	CHIP_REG_READ32(handle, a)	\
	(ddi_get32(handle, (uint32_t *)(a)))
#define	CHIP_REG_READ64(handle, a)	\
	(ddi_get64(handle, (uint64_t *)(a)))
#define	CHIP_REG_WRITE8(handle, a, d)	\
	ddi_put8(handle, (uint8_t *)(a), (uint8_t)(d))
#define	CHIP_REG_WRITE16(handle, a, d)	\
	ddi_put16(handle, (uint16_t *)(a), (uint16_t)(d))
#define	CHIP_REG_WRITE32(handle, a, d)	\
	ddi_put32(handle, (uint32_t *)(a), (uint32_t)(d))
#define	CHIP_REG_WRITE64(handle, a, d)	\
	ddi_put64(handle, (uint64_t *)(a), (uint64_t)(d))


#define	ARCOFFSET(type, member) \
	((size_t)(&((type *)0)->member))


#define	PCI_VENDOR_ID_ARECA	 0x17D3	/* Vendor ID	*/
#define	PCI_DEVICE_ID_ARECA_1110 0x1110	/* Device ID	*/
#define	PCI_DEVICE_ID_ARECA_1120 0x1120 /* Device ID	*/
#define	PCI_DEVICE_ID_ARECA_1130 0x1130 /* Device ID	*/
#define	PCI_DEVICE_ID_ARECA_1160 0x1160 /* Device ID	*/
#define	PCI_DEVICE_ID_ARECA_1170 0x1170 /* Device ID	*/
#define	PCI_DEVICE_ID_ARECA_1210 0x1210	/* Device ID	*/
#define	PCI_DEVICE_ID_ARECA_1220 0x1220 /* Device ID	*/
#define	PCI_DEVICE_ID_ARECA_1230 0x1230 /* Device ID	*/
#define	PCI_DEVICE_ID_ARECA_1260 0x1260 /* Device ID	*/
#define	PCI_DEVICE_ID_ARECA_1270 0x1270 /* Device ID	*/
#define	PCI_DEVICE_ID_ARECA_1280 0x1280 /* Device ID	*/
#define	PCI_DEVICE_ID_ARECA_1380 0x1380 /* Device ID	*/
#define	PCI_DEVICE_ID_ARECA_1381 0x1381 /* Device ID	*/
#define	PCI_DEVICE_ID_ARECA_1680 0x1680 /* Device ID	*/
#define	PCI_DEVICE_ID_ARECA_1681 0x1681 /* Device ID	*/
#define	PCI_DEVICE_ID_ARECA_1201 0x1201 /* Device ID	*/


#define	dma_addr_hi32(addr)	(uint32_t)((addr>>16)>>16)
#define	dma_addr_lo32(addr)	(uint32_t)(addr & 0xffffffff)

/*
 *	  IOCTL CONTROL CODE
 */
struct CMD_MESSAGE {
	uint32_t HeaderLength;
	uint8_t  Signature[8];
	uint32_t Timeout;
	uint32_t ControlCode;
	uint32_t ReturnCode;
	uint32_t Length;
};


#define	MSGDATABUFLEN	224
struct CMD_MESSAGE_FIELD {
	struct CMD_MESSAGE cmdmessage;	/* 28 byte ioctl header */
	uint8_t messagedatabuffer[224];	/* 1032 */
	/* areca gui program does not accept more than 1031 byte */
};

/* IOP message transfer */
#define	ARCMSR_MESSAGE_FAIL			0x0001

/* error code for StorPortLogError,ScsiPortLogError */
#define	ARCMSR_IOP_ERROR_ILLEGALPCI		0x0001
#define	ARCMSR_IOP_ERROR_VENDORID		0x0002
#define	ARCMSR_IOP_ERROR_DEVICEID		0x0002
#define	ARCMSR_IOP_ERROR_ILLEGALCDB		0x0003
#define	ARCMSR_IOP_ERROR_UNKNOW_CDBERR		0x0004
#define	ARCMSR_SYS_ERROR_MEMORY_ALLOCATE	0x0005
#define	ARCMSR_SYS_ERROR_MEMORY_CROSS4G		0x0006
#define	ARCMSR_SYS_ERROR_MEMORY_LACK		0x0007
#define	ARCMSR_SYS_ERROR_MEMORY_RANGE		0x0008
#define	ARCMSR_SYS_ERROR_DEVICE_BASE		0x0009
#define	ARCMSR_SYS_ERROR_PORT_VALIDATE		0x000A
/* DeviceType */
#define	ARECA_SATA_RAID				0x90000000
/* FunctionCode */
#define	FUNCTION_READ_RQBUFFER			0x0801
#define	FUNCTION_WRITE_WQBUFFER			0x0802
#define	FUNCTION_CLEAR_RQBUFFER			0x0803
#define	FUNCTION_CLEAR_WQBUFFER			0x0804
#define	FUNCTION_CLEAR_ALLQBUFFER		0x0805
#define	FUNCTION_REQUEST_RETURN_CODE_3F		0x0806
#define	FUNCTION_SAY_HELLO			0x0807
#define	FUNCTION_SAY_GOODBYE			0x0808
#define	FUNCTION_FLUSH_ADAPTER_CACHE		0x0809

/* ARECA IO CONTROL CODE */
#define	ARCMSR_MESSAGE_READ_RQBUFFER		 	\
	ARECA_SATA_RAID | FUNCTION_READ_RQBUFFER
#define	ARCMSR_MESSAGE_WRITE_WQBUFFER			\
	ARECA_SATA_RAID | FUNCTION_WRITE_WQBUFFER
#define	ARCMSR_MESSAGE_CLEAR_RQBUFFER			\
	ARECA_SATA_RAID | FUNCTION_CLEAR_RQBUFFER
#define	ARCMSR_MESSAGE_CLEAR_WQBUFFER			\
	ARECA_SATA_RAID | FUNCTION_CLEAR_WQBUFFER
#define	ARCMSR_MESSAGE_CLEAR_ALLQBUFFER	  	\
	ARECA_SATA_RAID | FUNCTION_CLEAR_ALLQBUFFER
#define	ARCMSR_MESSAGE_REQUEST_RETURN_CODE_3F	\
	ARECA_SATA_RAID | FUNCTION_REQUEST_RETURN_CODE_3F
#define	ARCMSR_MESSAGE_SAY_HELLO				\
	ARECA_SATA_RAID | FUNCTION_SAY_HELLO
#define	ARCMSR_MESSAGE_SAY_GOODBYE		  \
	ARECA_SATA_RAID | FUNCTION_SAY_GOODBYE
#define	ARCMSR_MESSAGE_FLUSH_ADAPTER_CACHE	\
	ARECA_SATA_RAID | FUNCTION_FLUSH_ADAPTER_CACHE

/* ARECA IOCTL ReturnCode */
#define	ARCMSR_MESSAGE_RETURNCODE_OK		0x00000001
#define	ARCMSR_MESSAGE_RETURNCODE_ERROR		0x00000006
#define	ARCMSR_MESSAGE_RETURNCODE_3F		0x0000003F

/*
 *  SPEC. for Areca HBB adapter
 */
/* ARECA HBB COMMAND for its FIRMWARE */
/* window of "instruction flags" from driver to iop */
#define	ARCMSR_DRV2IOP_DOORBELL			0x00020400
#define	ARCMSR_DRV2IOP_DOORBELL_MASK		0x00020404
/* window of "instruction flags" from iop to driver */
#define	ARCMSR_IOP2DRV_DOORBELL			0x00020408
#define	ARCMSR_IOP2DRV_DOORBELL_MASK		0x0002040C


/* ARECA FLAG LANGUAGE */
#define	ARCMSR_IOP2DRV_DATA_WRITE_OK		0x00000001 /* ioctl xfer */
#define	ARCMSR_IOP2DRV_DATA_READ_OK		0x00000002 /* ioctl xfer */
#define	ARCMSR_IOP2DRV_CDB_DONE			0x00000004
#define	ARCMSR_IOP2DRV_MESSAGE_CMD_DONE		0x00000008

#define	ARCMSR_DOORBELL_HANDLE_INT		0x0000000F
#define	ARCMSR_DOORBELL_INT_CLEAR_PATTERN	0xFF00FFF0
#define	ARCMSR_MESSAGE_INT_CLEAR_PATTERN	0xFF00FFF7

/* (ARCMSR_INBOUND_MESG0_GET_CONFIG<<16)|ARCMSR_DRV2IOP_MESSAGE_CMD_POSTED) */
#define	ARCMSR_MESSAGE_GET_CONFIG		0x00010008
/* (ARCMSR_INBOUND_MESG0_SET_CONFIG<<16)|ARCMSR_DRV2IOP_MESSAGE_CMD_POSTED) */
#define	ARCMSR_MESSAGE_SET_CONFIG		0x00020008
/* (ARCMSR_INBOUND_MESG0_ABORT_CMD<<16)|ARCMSR_DRV2IOP_MESSAGE_CMD_POSTED) */
#define	ARCMSR_MESSAGE_ABORT_CMD		0x00030008
/* (ARCMSR_INBOUND_MESG0_STOP_BGRB<<16)|ARCMSR_DRV2IOP_MESSAGE_CMD_POSTED) */
#define	ARCMSR_MESSAGE_STOP_BGRB		0x00040008
/* (ARCMSR_INBOUND_MESG0_FLUSH_CACHE<<16)|ARCMSR_DRV2IOP_MESSAGE_CMD_POSTED) */
#define	ARCMSR_MESSAGE_FLUSH_CACHE		0x00050008
/* (ARCMSR_INBOUND_MESG0_START_BGRB<<16)|ARCMSR_DRV2IOP_MESSAGE_CMD_POSTED) */
#define	ARCMSR_MESSAGE_START_BGRB		0x00060008
#define	ARCMSR_MESSAGE_START_DRIVER_MODE	0x000E0008
#define	ARCMSR_MESSAGE_SET_POST_WINDOW		0x000F0008
#define	ARCMSR_MESSAGE_ACTIVE_EOI_MODE		0x00100008
/* ARCMSR_OUTBOUND_MESG1_FIRMWARE_OK */
#define	ARCMSR_MESSAGE_FIRMWARE_OK		0x80000000

#define	ARCMSR_DRV2IOP_DATA_WRITE_OK		0x00000001 /* ioctl xfer */
#define	ARCMSR_DRV2IOP_DATA_READ_OK		0x00000002 /* ioctl xfer */
#define	ARCMSR_DRV2IOP_CDB_POSTED		0x00000004
#define	ARCMSR_DRV2IOP_MESSAGE_CMD_POSTED	0x00000008
#define	ARCMSR_DRV2IOP_END_OF_INTERRUPT		0x00000010

/* data tunnel buffer between user space program and its firmware */
/* iop msgcode_rwbuffer for message command */
#define	ARCMSR_MSGCODE_RWBUFFER			0x0000fa00
/* user space data to iop 128bytes */
#define	ARCMSR_IOCTL_WBUFFER			0x0000fe00
/* iop data to user space 128bytes */
#define	ARCMSR_IOCTL_RBUFFER			0x0000ff00
#define	ARCMSR_HBB_BASE0_OFFSET			0x00000010
#define	ARCMSR_HBB_BASE1_OFFSET			0x00000018
#define	ARCMSR_HBB_BASE0_LEN			0x00021000
#define	ARCMSR_HBB_BASE1_LEN			0x00010000

/*
 *	structure for holding DMA address data
 */
#define	IS_SG64_ADDR				0x01000000 /* bit24 */

/* 32bit Scatter-Gather list */
struct  SG32ENTRY {
	/* bit 24 = 0, high 8 bit = flag, low 24 bit = length */
	uint32_t	length;
	uint32_t	address;
};

/* 64bit Scatter-Gather list */
struct  SG64ENTRY {
	/* bit 24 = 1, high 8 bit = flag, low 24 bit = length */
	uint32_t	length;
	uint32_t	address;
	uint32_t	addresshigh;
};


struct QBUFFER {
	uint32_t	data_len;
	uint8_t		data[124];
};

/*
 *	FIRMWARE INFO
 */
#define	ARCMSR_FW_MODEL_OFFSET	0x0f
#define	ARCMSR_FW_VERS_OFFSET	0x11
#define	ARCMSR_FW_MAP_OFFSET	0x15

struct FIRMWARE_INFO {
	uint32_t	signature;
	uint32_t	request_len;
	uint32_t	numbers_queue;
	uint32_t	sdram_size;
	uint32_t	ide_channels;
	char		vendor[40];
	char		model[8];
	char		firmware_ver[16];
	char		device_map[16];
};

/*
 * ARECA FIRMWARE SPEC
 *
 * Usage of IOP331 adapter
 *
 * (All In/Out is in IOP331's view)
 *	1. Message 0 --> InitThread message and retrun code
 *	2. Doorbell is used for RS-232 emulation
 *		InDoorBell :
 *			bit0 -- data in ready (DRIVER DATA WRITE OK)
 *			bit1 -- data out has been read
 *						(DRIVER DATA READ OK)
 *		outDoorBell:
 *			bit0 -- data out ready (IOP331 DATA WRITE OK)
 *			bit1 -- data in has been read
 * 						(IOP331 DATA READ OK)
 *	3. Index Memory Usage
 *		offset 0xf00 : for RS232 out (request buffer)
 *		offset 0xe00 : for RS232 in  (scratch buffer)
 *		offset 0xa00 : for inbound message code msgcode_rwbuffer
 *				(driver send to IOP331)
 *		offset 0xa00 : for outbound message code msgcode_rwbuffer
 * 				(IOP331 send to driver)
 *	4. RS-232 emulation
 *		Currently 128 byte buffer is used:
 *		1st uint32_t : Data length (1--124)
 *			Byte 4--127 : Max 124 bytes of data
 *	5. PostQ
 *		All SCSI Command must be sent through postQ:
 *		(inbound queue port) Request frame must be 32 bytes aligned
 *			# bits 31:27 => flag for post ccb
 *		# bits 26:00 => real address (bit 31:27) of post arcmsr_cdb
 *		bit31 : 0 : 256 bytes frame
 *		1 : 512 bytes frame
 *		bit30 : 0 : normal request
 *		1 : BIOS request
 *		bit29 : reserved
 *		bit28 : reserved
 *		bit27 : reserved
 *  -----------------------------------------------------------------------
 * 		(outbount queue port)	Request reply
 *				# bits 31:27 => flag for reply
 *		# bits 26:00 => real address (bits 31:27) of reply arcmsr_cdb
 *		# bit31 : must be 0 (for this type of reply)
 *		# bit30 : reserved for BIOS handshake
 *		# bit29 : reserved
 *		# bit28 : 0 : no error, ignore AdapStatus/DevStatus/SenseData
 *			  1 : Error, see in AdapStatus/DevStatus/SenseData
 *		# bit27 : reserved
 *	6. BIOS request
 *		All BIOS request is the same with request from PostQ
 *		Except :
 *		Request frame is sent from configuration space
 *			offset: 0x78 : Request Frame (bit30 == 1)
 *			offset: 0x18 : writeonly to generate IRQ to IOP331
 *		Completion of request:
 *				(bit30 == 0, bit28==err flag)
 *	7. Definition of SGL entry (structure)
 *	8. Message1 Out - Diag Status Code (????)
 *	9. Message0 message code :
 *		0x00 : NOP
 *		0x01 : Get Config ->offset 0xa00
 *			 : for outbound message code msgcode_rwbuffer
 *			(IOP331 send to driver)
 * 		Signature 0x87974060(4)
 *		Request len		0x00000200(4)
 *		numbers of queue	0x00000100(4)
 *		SDRAM Size		0x00000100(4)-->256 MB
 *		IDE Channels	  0x00000008(4)
 *		vendor		40 bytes char
 *		model		  8 bytes char
 *		FirmVer		 16 bytes char
 *		Device Map		16 bytes char
 *
 *		FirmwareVersion DWORD
 *			<== Added for checking of new firmware capability
 *		0x02 : Set Config ->offset 0xa00
 *			:for inbound message code msgcode_rwbuffer
 *				(driver send to IOP331)
 *		Signature		 0x87974063(4)
 *		UPPER32 of Request Frame  (4)-->Driver Only
 *		0x03 : Reset (Abort all queued Command)
 *		0x04 : Stop Background Activity
 *		0x05 : Flush Cache
 *		0x06 : Start Background Activity
 *			(re-start if background is halted)
 *		0x07 : Check If Host Command Pending
 *			(Novell May Need This Function)
 *		0x08 : Set controller time ->offset 0xa00 (driver to IOP331)
 *			: for inbound message code msgcode_rwbuffer
 *		byte 0 : 0xaa <-- signature
 *		byte 1 : 0x55 <-- signature
 *		byte 2 : year (04)
 *		byte 3 : month (1..12)
 *		byte 4 : date (1..31)
 *		byte 5 : hour (0..23)
 *		byte 6 : minute (0..59)
 *		byte 7 : second (0..59)
 *
 */


/* signature of set and get firmware config */
#define	ARCMSR_SIGNATURE_GET_CONFIG			0x87974060
#define	ARCMSR_SIGNATURE_SET_CONFIG			0x87974063


/* message code of inbound message register */
#define	ARCMSR_INBOUND_MESG0_NOP			0x00000000
#define	ARCMSR_INBOUND_MESG0_GET_CONFIG			0x00000001
#define	ARCMSR_INBOUND_MESG0_SET_CONFIG			0x00000002
#define	ARCMSR_INBOUND_MESG0_ABORT_CMD			0x00000003
#define	ARCMSR_INBOUND_MESG0_STOP_BGRB			0x00000004
#define	ARCMSR_INBOUND_MESG0_FLUSH_CACHE		0x00000005
#define	ARCMSR_INBOUND_MESG0_START_BGRB			0x00000006
#define	ARCMSR_INBOUND_MESG0_CHK331PENDING		0x00000007
#define	ARCMSR_INBOUND_MESG0_SYNC_TIMER			0x00000008
/* doorbell interrupt generator */
#define	ARCMSR_INBOUND_DRIVER_DATA_WRITE_OK		0x00000001
#define	ARCMSR_INBOUND_DRIVER_DATA_READ_OK		0x00000002
#define	ARCMSR_OUTBOUND_IOP331_DATA_WRITE_OK		0x00000001
#define	ARCMSR_OUTBOUND_IOP331_DATA_READ_OK		0x00000002
/* ccb areca cdb flag */
#define	ARCMSR_CCBPOST_FLAG_SGL_BSIZE			0x80000000
#define	ARCMSR_CCBPOST_FLAG_IAM_BIOS			0x40000000
#define	ARCMSR_CCBREPLY_FLAG_IAM_BIOS			0x40000000
#define	ARCMSR_CCBREPLY_FLAG_ERROR			0x10000000
/* outbound firmware ok */
#define	ARCMSR_OUTBOUND_MESG1_FIRMWARE_OK		0x80000000

/* SBus dma burst sizes */
#ifndef BURSTSIZE
#define	BURSTSIZE
#define	BURST1			0x01
#define	BURST2			0x02
#define	BURST4			0x04
#define	BURST8			0x08
#define	BURST16			0x10
#define	BURST32			0x20
#define	BURST64			0x40
#define	BURSTSIZE_MASK		0x7f
#define	DEFAULT_BURSTSIZE	BURST16|BURST8|BURST4|BURST2|BURST1
#endif  /* BURSTSIZE */


/*
 *
 */
struct ARCMSR_CDB {
	uint8_t	Bus;		/* should be 0 */
	uint8_t	TargetID;	/* should be 0..15 */
	uint8_t	LUN;		/* should be 0..7 */
	uint8_t	Function;	/* should be 1 */

	uint8_t	CdbLength;	/* set in arcmsr_tran_init_pkt */
	uint8_t	sgcount;
	uint8_t	Flags;

	/* bit 0: 0(256) / 1(512) bytes	 */
#define	ARCMSR_CDB_FLAG_SGL_BSIZE		0x01
	/* bit 1: 0(from driver) / 1(from BIOS) */
#define	ARCMSR_CDB_FLAG_BIOS			0x02
	/* bit 2: 0(Data in) / 1(Data out)	*/
#define	ARCMSR_CDB_FLAG_WRITE			0x04
	/* bit 4/3 ,00 : simple Q,01 : head of Q,10 : ordered Q */
#define	ARCMSR_CDB_FLAG_SIMPLEQ			0x00
#define	ARCMSR_CDB_FLAG_HEADQ			0x08
#define	ARCMSR_CDB_FLAG_ORDEREDQ		0x10

	uint8_t	Reserved1;

	uint32_t	Context;	/* Address of this request */
	uint32_t	DataLength;	/* currently unused */

	uint8_t		Cdb[16];	/* SCSI CDB */
	/*
	 * Device Status : the same from SCSI bus if error occur
	 * SCSI bus status codes.
	 */
	uint8_t		DeviceStatus;

#define	SCSISTAT_GOOD				0x00
#define	SCSISTAT_CHECK_CONDITION		0x02
#define	SCSISTAT_CONDITION_MET			0x04
#define	SCSISTAT_BUSY				0x08
#define	SCSISTAT_INTERMEDIATE			0x10
#define	SCSISTAT_INTERMEDIATE_COND_MET		0x14
#define	SCSISTAT_RESERVATION_CONFLICT		0x18
#define	SCSISTAT_COMMAND_TERMINATED		0x22
#define	SCSISTAT_QUEUE_FULL			0x28
#define	ARCMSR_DEV_SELECT_TIMEOUT		0xF0
#define	ARCMSR_DEV_ABORTED			0xF1
#define	ARCMSR_DEV_INIT_FAIL			0xF2

	uint8_t		SenseData[15];

	/* Scatter gather address */
	union {
		struct SG32ENTRY	sg32entry[ARCMSR_MAX_SG_ENTRIES];
		struct SG64ENTRY	sg64entry[ARCMSR_MAX_SG_ENTRIES];
	} sgu;
};


struct HBA_msgUnit {
	uint32_t	resrved0[4];
	uint32_t	inbound_msgaddr0;
	uint32_t	inbound_msgaddr1;
	uint32_t	outbound_msgaddr0;
	uint32_t	outbound_msgaddr1;
	uint32_t	inbound_doorbell;
	uint32_t	inbound_intstatus;
	uint32_t	inbound_intmask;
	uint32_t	outbound_doorbell;
	uint32_t	outbound_intstatus;
	uint32_t	outbound_intmask;
	uint32_t	reserved1[2];
	uint32_t	inbound_queueport;
	uint32_t	outbound_queueport;
	uint32_t	reserved2[2];
	/* ......local_buffer */
	uint32_t	reserved3[492];
	uint32_t	reserved4[128];
	uint32_t	msgcode_rwbuffer[256];
	uint32_t	message_wbuffer[32];
	uint32_t	reserved5[32];
	uint32_t	message_rbuffer[32];
	uint32_t	reserved6[32];
};


struct HBB_DOORBELL {
	uint8_t		doorbell_reserved[132096];
	/*
	 * offset 0x00020400:00,01,02,03: window of "instruction flags"
	 * from driver to iop
	 */
	uint32_t	drv2iop_doorbell;
	/* 04,05,06,07: doorbell mask */
	uint32_t	drv2iop_doorbell_mask;
	/* 08,09,10,11: window of "instruction flags" from iop to driver */
	uint32_t	iop2drv_doorbell;
	/* 12,13,14,15: doorbell mask */
	uint32_t	iop2drv_doorbell_mask;
};


struct HBB_RWBUFFER {
	uint8_t		message_reserved0[64000];
	/* offset 0x0000fa00:	0..1023: message code read write 1024bytes */
	uint32_t	msgcode_rwbuffer[256];
	/* offset 0x0000fe00:1024...1151: user space data to iop 128bytes */
	uint32_t	message_wbuffer[32];
	/* 1152...1279: message reserved */
	uint32_t	message_reserved1[32];
	/* offset 0x0000ff00:1280...1407: iop data to user space 128bytes */
	uint32_t	message_rbuffer[32];
};

struct HBB_msgUnit {
	/* post queue buffer for iop */
	uint32_t	post_qbuffer[ARCMSR_MAX_HBB_POSTQUEUE];
	/* done queue buffer for iop */
	uint32_t	done_qbuffer[ARCMSR_MAX_HBB_POSTQUEUE];

	int32_t		postq_index;	/* post queue index */
	int32_t		doneq_index;	/* done queue index */
	struct HBB_DOORBELL	*hbb_doorbell;
	struct HBB_RWBUFFER	*hbb_rwbuffer;
};

struct msgUnit {
	union	{
		struct HBA_msgUnit	hbamu;
		struct HBB_msgUnit	hbbmu;
	} muu;
};


/*
 * Adapter Control Block
 */
struct ACB {
	uint32_t		adapter_type; /* A/B/C/D */

#define	ACB_ADAPTER_TYPE_A	0x00000001	/* hba (Intel) IOP */
#define	ACB_ADAPTER_TYPE_B	0x00000002	/* hbb (Marvell) IOP */
#define	ACB_ADAPTER_TYPE_C	0x00000004	/* hbc P IOP */
#define	ACB_ADAPTER_TYPE_D	0x00000008	/* hbd A IOP */

	int32_t			dma_sync_size;
	scsi_hba_tran_t		*scsi_hba_transport;
	dev_info_t		*dev_info;
	ddi_acc_handle_t	reg_mu_acc_handle0;
	ddi_acc_handle_t	reg_mu_acc_handle1;
	ddi_acc_handle_t	ccbs_acc_handle;
	ddi_dma_handle_t	ccbs_pool_handle;
	ddi_dma_cookie_t	ccb_cookie;
	ddi_device_acc_attr_t	dev_acc_attr;
	kmutex_t		acb_mutex;
	kmutex_t		postq_mutex;
	kmutex_t		workingQ_mutex;
	kmutex_t		ioctl_mutex;
	timeout_id_t		timeout_id;
	timeout_id_t		timeout_sc_id;
	ddi_taskq_t		*taskq;
	ddi_iblock_cookie_t	 iblock_cookie;
	/* Offset for arc cdb physical to virtual calculations */
	unsigned long		vir2phy_offset;
	uint32_t		outbound_int_enable;

	/* message unit ATU inbound base address0 virtual */
	struct msgUnit 	*pmu;

	uint8_t			adapter_index;
	uint8_t			irq;
	uint16_t		acb_flags;

#define	ACB_F_SCSISTOPADAPTER		0x0001
/* stop RAID background rebuild */
#define	ACB_F_MSG_STOP_BGRB		0x0002
/* stop RAID background rebuild */
#define	ACB_F_MSG_START_BGRB		0x0004
/* iop ioctl data rqbuffer overflow */
#define	ACB_F_IOPDATA_OVERFLOW		0x0008
/* ioctl clear wqbuffer */
#define	ACB_F_MESSAGE_WQBUFFER_CLEARED  0x0010
/* ioctl clear rqbuffer */
#define	ACB_F_MESSAGE_RQBUFFER_CLEARED  0x0020
/* ioctl iop wqbuffer data readed */
#define	ACB_F_MESSAGE_WQBUFFER_READ	0x0040
#define	ACB_F_BUS_RESET			0x0080
/* iop init */
#define	ACB_F_IOP_INITED		0x0100

	/* serial ccb pointer array */
	struct CCB *pccb_pool[ARCMSR_MAX_FREECCB_NUM];
	/* working ccb pointer array */
	struct CCB *ccbworkingQ[ARCMSR_MAX_FREECCB_NUM];
	/* done ccb array index */
	int32_t			workingccb_doneindex;
	/* start ccb array index  */
	int32_t			workingccb_startindex;
	int32_t			ccboutstandingcount;

	/* data collection buffer for read from 80331 */
	uint8_t			rqbuffer[ARCMSR_MAX_QBUFFER];
	/* first of read buffer  */
	int32_t			rqbuf_firstidx;
	/* last of read buffer	*/
	int32_t			rqbuf_lastidx;

	/* data collection buffer for write to 80331  */
	uint8_t			wqbuffer[ARCMSR_MAX_QBUFFER];
	/* first of write buffer */
	int32_t			wqbuf_firstidx;
	/* last of write buffer  */
	int32_t			wqbuf_lastidx;
	/* id0 ..... id15,lun0...lun7 */
	uint8_t		devstate[ARCMSR_MAX_TARGETID][ARCMSR_MAX_TARGETLUN];
#define	ARECA_RAID_GONE		0x55
#define	ARECA_RAID_GOOD		0xaa

	uint32_t		timeout_count;
	uint32_t		num_resets;
	uint32_t		num_aborts;
	uint32_t		firm_request_len;
	uint32_t		firm_numbers_queue;
	uint32_t		firm_sdram_size;
	uint32_t		firm_ide_channels;
	char			firm_model[12];
	char			firm_version[20];
	char			device_map[20];	/* 21,84-99 */
	ddi_acc_handle_t	pci_acc_handle;
	int			tgt_scsi_opts[ARCMSR_MAX_TARGETID];
	dev_info_t	*ld[ARCMSR_MAX_TARGETID-1][ARCMSR_MAX_TARGETLUN];
};


/*
 * Command Control Block (SrbExtension)
 *
 * CCB must be not cross page boundary,and the order from offset 0
 * structure describing an ATA disk request this CCB length must be
 * 32 bytes boundary
 *
 */
struct CCB
{
	struct  ARCMSR_CDB	arcmsr_cdb;
	uint32_t		cdb_shifted_phyaddr;
	uint16_t		ccb_flags;
#define	CCB_FLAG_READ		0x0000
#define	CCB_FLAG_WRITE		0x0001
#define	CCB_FLAG_ERROR		0x0002
#define	CCB_FLAG_FLUSHCACHE	0x0004
#define	CCB_FLAG_MASTER_ABORTED 0x0008
#define	CCB_FLAG_DMAVALID	0x0010
#define	CCB_FLAG_DMACONSISTENT  0x0020
#define	CCB_FLAG_DMAWRITE	0x0040
#define	CCB_FLAG_PKTBIND	0x0080
	uint16_t		startdone;
#define	ARCMSR_CCB_DONE		0x0000
#define	ARCMSR_CCB_UNBUILD 	0x0000
#define	ARCMSR_CCB_START	0x55AA
#define	ARCMSR_CCB_PENDING	0xAA55
#define	ARCMSR_CCB_RESET	0xA5A5
#define	ARCMSR_CCB_ABORTED	0x5A5A
#define	ARCMSR_CCB_ILLEGAL	0xFFFF
	struct scsi_pkt			*pkt;
	struct ACB	*acb;
	ddi_dma_cookie_t	pkt_dmacookies[ARCMSR_MAX_SG_ENTRIES];
	ddi_dma_handle_t	pkt_dma_handle;
	uint_t			pkt_cookie;
	uint_t			pkt_ncookies;
	uint_t			pkt_nwin;
	uint_t			pkt_curwin;
	off_t			pkt_dma_offset;
	size_t			pkt_dma_len;
	size_t			total_dmac_size;
	time_t			ccb_time;
	struct buf		*bp;
	ddi_dma_cookie_t	resid_dmacookie;
#ifdef _LP64
	uint32_t		reserved;
#endif
};


/* SenseData[15] */
struct SENSE_DATA {
	DECL_BITFIELD3(
	    ErrorCode		:4,	/* Vendor Unique error code */
	    ErrorClass		:3,	/* Error Class- fixed at 0x7 */
	    Valid		:1);	/* sense data is valid */

	uint8_t SegmentNumber;	/* segment number: for COPY cmd */

	DECL_BITFIELD5(
	    SenseKey		:4,	/* Sense key (see below) */
	    Reserved		:1,	/* reserved */
	    IncorrectLength	:1,	/* Incorrect Length Indicator */
	    EndOfMedia		:1,	/* End of Media */
	    FileMark		:1);	/* File Mark Detected */

	uint8_t Information[4];
	uint8_t AdditionalSenseLength;
	uint8_t CommandSpecificInformation[4];
	uint8_t AdditionalSenseCode;
	uint8_t AdditionalSenseCodeQualifier;
	uint8_t FieldReplaceableUnitCode;
};

#define	VIDLEN	8
#define	PIDLEN	16
#define	REVLEN	4
struct	SCSIInqData {
	uint8_t	DevType;	/* Periph Qualifier & Periph Dev Type */
	uint8_t	RMB_TypeMod;	/* rem media bit & Dev Type Modifier */
	uint8_t	Vers;		/* ISO, ECMA, & ANSI versions */
	uint8_t	RDF;		/* AEN, TRMIOP, & response data format */
	uint8_t	AddLen;		/* length of additional data */
	uint8_t	Res1;		/* reserved */
	uint8_t	Res2;		/* reserved */
	uint8_t	Flags; 		/* RelADr, Wbus32, Wbus16, Sync etc */
	uint8_t	VendorID[8];	/* Vendor Identification */
	uint8_t	ProductID[16]; 	/* Product Identification */
	uint8_t	ProductRev[4]; 	/* Product Revision */
};



/*
 * These definitions are the register offsets as defined in the Intel
 * IOP manuals. See (correct as of 18 January 2008)
 * http://developer.intel.com/design/iio/index.htm?iid=ncdcnav2+stor_ioproc
 * for more details
 */
#define	ARCMSR_PCI2PCI_VENDORID_REG		0x00
#define	ARCMSR_PCI2PCI_DEVICEID_REG		0x02
#define	ARCMSR_PCI2PCI_PRIMARY_COMMAND_REG	0x04
#define	PCI_DISABLE_INTERRUPT			0x0400
#define	ARCMSR_PCI2PCI_PRIMARY_STATUS_REG	0x06
#define	ARCMSR_ADAP_66MHZ			0x20
#define	ARCMSR_PCI2PCI_REVISIONID_REG		0x08
#define	ARCMSR_PCI2PCI_CLASSCODE_REG		0x09

#define	ARCMSR_PCI2PCI_PRIMARY_CACHELINESIZE_REG	0x0C
#define	ARCMSR_PCI2PCI_PRIMARY_LATENCYTIMER_REG		0x0D
#define	ARCMSR_PCI2PCI_HEADERTYPE_REG			0x0E
#define	ARCMSR_PCI2PCI_PRIMARY_BUSNUMBER_REG		0x18
#define	ARCMSR_PCI2PCI_SECONDARY_BUSNUMBER_REG		0x19
#define	ARCMSR_PCI2PCI_SUBORDINATE_BUSNUMBER_REG	0x1A
#define	ARCMSR_PCI2PCI_SECONDARY_LATENCYTIMER_REG	0x1B
#define	ARCMSR_PCI2PCI_IO_BASE_REG			0x1C
#define	ARCMSR_PCI2PCI_IO_LIMIT_REG			0x1D
#define	ARCMSR_PCI2PCI_SECONDARY_STATUS_REG		0x1E
#define	ARCMSR_PCI2PCI_NONPREFETCHABLE_MEMORY_BASE_REG  0x20
#define	ARCMSR_PCI2PCI_NONPREFETCHABLE_MEMORY_LIMIT_REG 0x22
#define	ARCMSR_PCI2PCI_PREFETCHABLE_MEMORY_BASE_REG	0x24
#define	ARCMSR_PCI2PCI_PREFETCHABLE_MEMORY_LIMIT_REG	0x26

#define	ARCMSR_PCI2PCI_PREFETCHABLE_MEMORY_BASE_UPPER32_REG	0x28
#define	ARCMSR_PCI2PCI_PREFETCHABLE_MEMORY_LIMIT_UPPER32_REG	0x2C

#define	ARCMSR_PCI2PCI_CAPABILITIES_POINTER_REG		0x34
#define	ARCMSR_PCI2PCI_PRIMARY_INTERRUPT_LINE_REG	0x3C
#define	ARCMSR_PCI2PCI_PRIMARY_INTERRUPT_PIN_REG	0x3D
#define	ARCMSR_PCI2PCI_BRIDGE_CONTROL_REG		0x3E


#define	ARCMSR_ATU_VENDOR_ID_REG		0x00
#define	ARCMSR_ATU_DEVICE_ID_REG		0x02
#define	ARCMSR_ATU_COMMAND_REG			0x04
#define	ARCMSR_ATU_STATUS_REG			0x06
#define	ARCMSR_ATU_REVISION_REG			0x08
#define	ARCMSR_ATU_CLASS_CODE_REG		0x09
#define	ARCMSR_ATU_CACHELINE_SIZE_REG		0x0C
#define	ARCMSR_ATU_LATENCY_TIMER_REG		0x0D
#define	ARCMSR_ATU_HEADER_TYPE_REG		0x0E
#define	ARCMSR_ATU_BIST_REG			0x0F
#define	ARCMSR_INBOUND_ATU_BASE_ADDRESS0_REG	0x10
#define	ARCMSR_INBOUND_ATU_MEMORY_PREFETCHABLE	0x08
#define	ARCMSR_INBOUND_ATU_MEMORY_WINDOW64	0x04

#define	ARCMSR_INBOUND_ATU_UPPER_BASE_ADDRESS0_REG	0x14
#define	ARCMSR_INBOUND_ATU_BASE_ADDRESS1_REG		0x18
#define	ARCMSR_INBOUND_ATU_UPPER_BASE_ADDRESS1_REG	0x1C
#define	ARCMSR_INBOUND_ATU_BASE_ADDRESS2_REG		0x20
#define	ARCMSR_INBOUND_ATU_UPPER_BASE_ADDRESS2_REG	0x24
#define	ARCMSR_ATU_SUBSYSTEM_VENDOR_ID_REG		0x2C
#define	ARCMSR_ATU_SUBSYSTEM_ID_REG			0x2E
#define	ARCMSR_EXPANSION_ROM_BASE_ADDRESS_REG		0x30

#define	ARCMSR_EXPANSION_ROM_ADDRESS_DECODE_ENABLE	0x01

#define	ARCMSR_ATU_CAPABILITY_PTR_REG		0x34
#define	ARCMSR_ATU_INTERRUPT_LINE_REG		0x3C
#define	ARCMSR_ATU_INTERRUPT_PIN_REG		0x3D
#define	ARCMSR_ATU_MINIMUM_GRANT_REG		0x3E
#define	ARCMSR_ATU_MAXIMUM_LATENCY_REG		0x3F
#define	ARCMSR_INBOUND_ATU_LIMIT0_REG		0x40
#define	ARCMSR_INBOUND_ATU_TRANSLATE_VALUE0_REG	0x44
#define	ARCMSR_EXPANSION_ROM_LIMIT_REG		0x48
#define	ARCMSR_EXPANSION_ROM_TRANSLATE_VALUE_REG	0x4C
#define	ARCMSR_INBOUND_ATU_LIMIT1_REG			0x50
#define	ARCMSR_INBOUND_ATU_LIMIT2_REG			0x54
#define	ARCMSR_INBOUND_ATU_TRANSLATE_VALUE2_REG		0x58
#define	ARCMSR_OUTBOUND_IO_WINDOW_TRANSLATE_VALUE_REG	0x5C

#define	ARCMSR_OUTBOUND_MEMORY_WINDOW_TRANSLATE_VALUE0_REG		0x60
#define	ARCMSR_OUTBOUND_UPPER32_MEMORY_WINDOW_TRANSLATE_VALUE0_REG	0x64
#define	ARCMSR_OUTBOUND_MEMORY_WINDOW_TRANSLATE_VALUE1_REG		0x68
#define	ARCMSR_OUTBOUND_UPPER32_MEMORY_WINDOW_TRANSLATE_VALUE1_REG	0x6C
#define	ARCMSR_OUTBOUND_UPPER32_DIRECT_WINDOW_TRANSLATE_VALUE_REG	0x78

#define	ARCMSR_ATU_CONFIGURATION_REG			0x80
#define	ARCMSR_PCI_CONFIGURATION_STATUS_REG		0x84
#define	ARCMSR_ATU_INTERRUPT_STATUS_REG			0x88
#define	ARCMSR_ATU_INTERRUPT_MASK_REG			0x8C
#define	ARCMSR_INBOUND_ATU_BASE_ADDRESS3_REG		0x90
#define	ARCMSR_INBOUND_ATU_UPPER_BASE_ADDRESS3_REG	0x94
#define	ARCMSR_INBOUND_ATU_LIMIT3_REG			0x98
#define	ARCMSR_INBOUND_ATU_TRANSLATE_VALUE3_REG		0x9C

#define	ARCMSR_OUTBOUND_CONFIGURATION_CYCLE_ADDRESS_REG		0xA4
#define	ARCMSR_OUTBOUND_CONFIGURATION_CYCLE_DATA_REG		0xAC
#define	ARCMSR_VPD_CAPABILITY_IDENTIFIER_REG			0xB8
#define	ARCMSR_VPD_NEXT_ITEM_PTR_REG				0xB9
#define	ARCMSR_VPD_ADDRESS_REG					0xBA
#define	ARCMSR_VPD_DATA_REG					0xBC
#define	ARCMSR_POWER_MANAGEMENT_CAPABILITY_IDENTIFIER_REG	0xC0
#define	ARCMSR_POWER_NEXT_ITEM_PTR_REG				0xC1
#define	ARCMSR_POWER_MANAGEMENT_CAPABILITY_REG			0xC2
#define	ARCMSR_POWER_MANAGEMENT_CONTROL_STATUS_REG		0xC4
#define	ARCMSR_PCIX_CAPABILITY_IDENTIFIER_REG			0xE0
#define	ARCMSR_PCIX_NEXT_ITEM_PTR_REG				0xE1
#define	ARCMSR_PCIX_COMMAND_REG					0xE2
#define	ARCMSR_PCIX_STATUS_REG					0xE4


#define	ARCMSR_MU_INBOUND_MESSAGE_REG0				0x10
#define	ARCMSR_MU_INBOUND_MESSAGE_REG1				0x14
#define	ARCMSR_MU_OUTBOUND_MESSAGE_REG0				0x18
#define	ARCMSR_MU_OUTBOUND_MESSAGE_REG1				0x1C
#define	ARCMSR_MU_INBOUND_DOORBELL_REG				0x20
#define	ARCMSR_MU_INBOUND_INTERRUPT_STATUS_REG			0x24
#define	ARCMSR_MU_INBOUND_INTERRUPT_MASK_REG			0x28
#define	ARCMSR_MU_OUTBOUND_DOORBELL_REG				0x2C
#define	ARCMSR_MU_OUTBOUND_INTERRUPT_STATUS_REG			0x30
#define	ARCMSR_MU_OUTBOUND_INTERRUPT_MASK_REG			0x34
#define	ARCMSR_MU_INBOUND_QUEUE_PORT_REG			0x40
#define	ARCMSR_MU_OUTBOUND_QUEUE_PORT_REG			0x44



#define	ARCMSR_MU_INBOUND_MESSAGE0_INT				0x01
#define	ARCMSR_MU_INBOUND_MESSAGE1_INT				0x02
#define	ARCMSR_MU_INBOUND_DOORBELL_INT				0x04
#define	ARCMSR_MU_INBOUND_ERROR_DOORBELL_INT			0x08
#define	ARCMSR_MU_INBOUND_POSTQUEUE_INT				0x10
#define	ARCMSR_MU_INBOUND_QUEUEFULL_INT				0x20
#define	ARCMSR_MU_INBOUND_INDEX_INT				0x40

#define	ARCMSR_MU_INBOUND_MESSAGE0_INTMASKENABLE		0x01
#define	ARCMSR_MU_INBOUND_MESSAGE1_INTMASKENABLE		0x02
#define	ARCMSR_MU_INBOUND_DOORBELL_INTMASKENABLE		0x04
#define	ARCMSR_MU_INBOUND_DOORBELL_ERROR_INTMASKENABLE		0x08
#define	ARCMSR_MU_INBOUND_POSTQUEUE_INTMASKENABLE		0x10
#define	ARCMSR_MU_INBOUND_QUEUEFULL_INTMASKENABLE		0x20
#define	ARCMSR_MU_INBOUND_INDEX_INTMASKENABLE			0x40

#define	ARCMSR_MU_OUTBOUND_MESSAGE0_INT 			0x01
#define	ARCMSR_MU_OUTBOUND_MESSAGE1_INT 			0x02
#define	ARCMSR_MU_OUTBOUND_DOORBELL_INT 			0x04
#define	ARCMSR_MU_OUTBOUND_POSTQUEUE_INT			0x08
#define	ARCMSR_MU_OUTBOUND_PCI_INT				0x10


#define	ARCMSR_MU_OUTBOUND_HANDLE_INT \
	(ARCMSR_MU_OUTBOUND_MESSAGE0_INT| \
	ARCMSR_MU_OUTBOUND_MESSAGE1_INT| \
	ARCMSR_MU_OUTBOUND_DOORBELL_INT| \
	ARCMSR_MU_OUTBOUND_POSTQUEUE_INT| \
		ARCMSR_MU_OUTBOUND_PCI_INT)

#define	ARCMSR_MU_OUTBOUND_MESSAGE0_INTMASKENABLE		0x01
#define	ARCMSR_MU_OUTBOUND_MESSAGE1_INTMASKENABLE		0x02
#define	ARCMSR_MU_OUTBOUND_DOORBELL_INTMASKENABLE		0x04
#define	ARCMSR_MU_OUTBOUND_POSTQUEUE_INTMASKENABLE		0x08
#define	ARCMSR_MU_OUTBOUND_PCI_INTMASKENABLE			0x10

#define	ARCMSR_MU_OUTBOUND_ALL_INTMASKENABLE			0x1F

#define	ARCMSR_MU_CONFIGURATION_REG				0xFFFFE350
#define	ARCMSR_MU_QUEUE_BASE_ADDRESS_REG			0xFFFFE354
#define	ARCMSR_MU_INBOUND_FREE_HEAD_PTR_REG			0xFFFFE360
#define	ARCMSR_MU_INBOUND_FREE_TAIL_PTR_REG			0xFFFFE364
#define	ARCMSR_MU_INBOUND_POST_HEAD_PTR_REG			0xFFFFE368
#define	ARCMSR_MU_INBOUND_POST_TAIL_PTR_REG			0xFFFFE36C
#define	ARCMSR_MU_LOCAL_MEMORY_INDEX_REG			0xFFFFE380

#define	ARCMSR_MU_CIRCULAR_QUEUE_ENABLE				0x0001
#define	ARCMSR_MU_CIRCULAR_QUEUE_SIZE4K				0x0002
#define	ARCMSR_MU_CIRCULAR_QUEUE_SIZE8K				0x0004
#define	ARCMSR_MU_CIRCULAR_QUEUE_SIZE16K			0x0008
#define	ARCMSR_MU_CIRCULAR_QUEUE_SIZE32K			0x0010
#define	ARCMSR_MU_CIRCULAR_QUEUE_SIZE64K			0x0020



#ifdef	__cplusplus
}
#endif
/* arcmsr.h */
#endif /* _SYS_SCSI_ADAPTERS_ARCMSR_H */
