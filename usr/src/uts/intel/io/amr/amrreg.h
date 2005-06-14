/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright (c) 1999,2000 Michael Smith
 * Copyright (c) 2000 BSDi
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * Copyright (c) 2002 Eric Moore
 * Copyright (c) 2002 LSI Logic Corporation
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The party using or redistributing the source code and binary forms
 *    agrees to the disclaimer below and the terms and conditions set forth
 *    herein.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * Note: If the structures and variables definitions can be found from the
 *	 "MegaRAID PCI SCSI Disk Array Controller F/W Technical Reference
 *	 Manual", the names defined in this documents will also be provided
 *	 by " ", and the descriptions for each variables and constants are
 *	 given as well.
 */

#ifndef _AMRREG_H
#define	_AMRREG_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#define	AMR_NSEG		26
#define	AMR_MAX_STATUS_ACK	46

#define	AMR_MAXCMD		255	/* The last CMD is used for Poll only */

#define	AMR_LIMITCMD		120	/* max count of outstanding commands */
#define	AMR_MAXLD		40

#define	AMR_MAX_CHANNELS	4
#define	AMR_MAX_TARGETS		15
#define	AMR_MAX_LUNS		7
#define	AMR_MAX_SCSI_CMDS	(AMR_MAX_CHANNELS * AMR_MAX_TARGETS)

#define	AMR_MAX_CDB_LEN		0x0a
#define	AMR_MAX_EXTCDB_LEN	0x10
#define	AMR_MAX_REQ_SENSE_LEN	0x20

#define	AMR_BLKSIZE		512	/* constant for all controllers */

/*
 * Array constraints for controllers that support 8 logic drivers
 */
#define	AMR_8LD_MAXDRIVES	8
#define	AMR_8LD_MAXCHAN		5
#define	AMR_8LD_MAXTARG		15
#define	AMR_8LD_MAXPHYSDRIVES	(AMR_8LD_MAXCHAN * AMR_8LD_MAXTARG)

/*
 * Array constraints for controllers that support 40 logic drivers
 */
#define	AMR_40LD_MAXDRIVES	40
#define	AMR_40LD_MAXCHAN	16
#define	AMR_40LD_MAXTARG	16
#define	AMR_40LD_MAXPHYSDRIVES	(AMR_40LD_MAXCHAN * AMR_40LD_MAXTARG)

/*
 * The buffer size for enquiry command
 */
#define	AMR_ENQ_BUFFER_SIZE	sizeof (union amr_enq_buffer)

/*
 * Constants used for poll command
 */
#define	AMR_POLL_COMMAND_ID		0xfe
#define	AMR_POLL_DEFAULT_NSTATUS	0xff
#define	AMR_POLL_DEFAULT_STATUS		0xff
#define	AMR_POLL_ACK			0x77

#pragma pack(1)

/*
 * The AMR mailbox. This is the main interface for
 * programming the controller. Must be aligned at
 * a 16-Byte physical address boundary.
 *
 * The first sixteen bytes are commands to the controller.
 *
 * There are two formats:
 *	1. Commands for I/O: mb_blkcount/mb_lba are used.
 *	2. Commands for I/O control: mb_channel/mb_param are used.
 *
 */

struct amr_mailbox
{
	uint8_t			mb_command;	/* "Command", OUT, the op */
						/* code of the command */
	uint8_t			mb_ident;	/* "CommandID", OUT, the */
						/* id for this command */
	union {
		uint16_t	mbu_blkcount;	/* "NoOfSectors", OUT, the */
						/* number of sectors for */
						/* this request */
		uint8_t		mbu_chparam[2];	/* "Channel" and "Param", */
						/* OUT, Channel No. and */
						/* parameters */
	} mb_un1;
	union {
		uint32_t	mbu_lba;	/* "Lba", OUT, the starting */
						/* LBA for this request */
		uint8_t		mbu_pad[4];
	} mb_un2;
	uint32_t		mb_physaddr;	/* "DataTransferAddress", OUT */
						/* physical address for a */
						/* non-s/g command or the */
						/* physical address of a s/g */
						/* list for a s/g command */
	uint8_t			mb_drive;	/* "LogicalDriveNumber", OUT, */
						/* the log-drive for which */
						/* this request is intended */
	uint8_t			mb_nsgelem;	/* "NoSGElements", OUT, */
						/* number of s/g elements */
	uint8_t			res1;
	uint8_t			mb_busy;	/* "mailboxBusy", INOUT, set */
						/* to 1 before submit the */
						/* command, firmware picks */
						/* it and makes this byte 0 */
	uint8_t			mb_nstatus;	/* "NoOfStatus", IN, the */
						/* number of status returned */
						/* by firmware */
	uint8_t			mb_status;	/* "Status", IN, status for */
						/* the IDs in mb_completed[] */
	uint8_t			mb_completed[AMR_MAX_STATUS_ACK];
						/* "CompletedIdList", IN, */
						/* finished ID list */
	uint8_t			mb_poll;	/* "Mraid_poll", IN, used for */
						/* polling/interrupt-driven */
	uint8_t			mb_ack;		/* "Mraid_ack", IN, used for */
						/* polling/interrupt-driver */
	uint8_t			res2[16];
};

/* Fields before mb_nstatus are the portions worth copying for controller */
#define	AMR_MBOX_CMDSIZE (size_t)(&((struct amr_mailbox *)(NULL))->mb_nstatus)

#define	mb_blkcount	mb_un1.mbu_blkcount
#define	mb_channel	mb_un1.mbu_chparam[0]
#define	mb_param	mb_un1.mbu_chparam[1]
#define	mb_cmdsub	mb_un1.mbu_chparam[0]
#define	mb_cmdqual	mb_un1.mbu_chparam[1]
#define	mb_lba		mb_un2.mbu_lba

/*
 * I/O commands expect the physical address of an array
 * of no more than AMR_NSEGS of scatter/gather table entries
 * in mb_physaddr.
 *
 * sg_addr is a physical address.
 */
struct amr_sgentry
{
	uint32_t	sg_addr;
	uint32_t	sg_count;
};

/*
 * Mailbox commands
 * Note: This is a subset for the command set
 */
#define	AMR_CMD_LREAD				0x01
#define	AMR_CMD_LWRITE				0x02
#define	AMR_CMD_PASS				0x03
#define	AMR_CMD_EXT_ENQUIRY			0x04
#define	AMR_CMD_ENQUIRY				0x05
#define	AMR_CMD_FLUSH				0x0a
#define	AMR_CMD_EXT_ENQUIRY2			0x0c
#define	AMR_CMD_GET_MACHINEID			0x36
#define	AMR_CMD_GET_INITIATOR			0x7d
#define	AMR_CMD_RESET_ADAPTER			0x96
#define	AMR_CMD_CONFIG				0xa1
#define	AMR_CMD_MISC_OPCODE			0xa4
#define	AMR_CMD_EXTPASS				0xe3

/*
 * Subcodes for AMR_CMD_CONFIG
 */
#define	AMR_CONFIG_PRODUCT_INFO			0x0e
#define	AMR_CONFIG_ENQ3				0x0f
#define	AMR_CONFIG_ENQ3_SOLICITED_NOTIFY	0x01
#define	AMR_CONFIG_ENQ3_SOLICITED_FULL		0x02
#define	AMR_CONFIG_ENQ3_UNSOLICITED		0x03

/*
 * Subcodes for AMR_CMD_MISC_OPCODE
 */
#define	AMR_MISC_CDB_QUERY			0x16

/*
 * Mailbox command results
 */
#define	AMR_STATUS_SUCCESS			0x00
#define	AMR_STATUS_ABORTED			0x02
#define	AMR_STATUS_FAILED			0x80

/*
 * Adapter Info structure
 */
struct amr_adapter_info
{
	uint8_t		aa_maxio;		/* "MaxConcCmds", concurrent */
						/* commands supported */
	uint8_t		aa_rebuild_rate;	/* "RbldRate", rebuild rate, */
						/* varies from 0%-100% */
	uint8_t		aa_maxtargchan;		/* "MaxTargPerChan", targets */
						/* supported per chan */
	uint8_t		aa_channels;		/* "ChanPresent", No. of */
						/* Chans present on this */
						/* adapter */
	uint8_t		aa_firmware[4];		/* "FwVer", firmware version */
	uint16_t	aa_flashage;		/* "AgeOfFlash", No. of times */
						/* FW has been downloaded */
	uint8_t		aa_chipsetvalue;	/* "ChipSetValue", contents */
						/* of 0xC0000832 */
	uint8_t		aa_memorysize;		/* "DramSize", in terms of MB */
	uint8_t		aa_cacheflush;		/* "CacheFlushInterval", in */
						/* terms of Seconds */
	uint8_t		aa_bios[4];		/* "BiosVersion", Bios ver */
	uint8_t		aa_boardtype;		/* "BoardType", board type */
	uint8_t		aa_scsisensealert;	/* "sense_alert" */
	uint8_t		aa_writeconfigcount;	/* "write_config_count", */
						/* increase with evry */
						/* configuration change */
	uint8_t		aa_driveinsertioncount;	/* "drive_inserted_count", */
						/* increase with every drive */
						/* inserted */
	uint8_t		aa_inserteddrive;	/* "inserted_drive", Chan:Id */
						/* of inserted drive */
	uint8_t		aa_batterystatus;	/* "battery_status", battery */
						/* status */
	uint8_t   	res1;			/* "dec_fault_bus_info", was */
						/* reserved */
};

/*
 * aa_batterystatus values
 */
#define	AMR_BATT_MODULE_MISSING		0x01
#define	AMR_BATT_LOW_VOLTAGE		0x02
#define	AMR_BATT_TEMP_HIGH		0x04
#define	AMR_BATT_PACK_MISSING		0x08
#define	AMR_BATT_CHARGE_MASK		0x30
#define	AMR_BATT_CHARGE_DONE		0x00
#define	AMR_BATT_CHARGE_INPROG		0x10
#define	AMR_BATT_CHARGE_FAIL		0x20
#define	AMR_BATT_CYCLES_EXCEEDED	0x40

/*
 * Logical Drive info structure
 */
struct amr_logdrive_info
{
	uint8_t		al_numdrives;		/* "NumLogDrv", No. of */
						/* configured logic drivers */
	uint8_t		res1[3];
	uint32_t	al_size[AMR_8LD_MAXDRIVES];
						/* "LDrvSize", size of each */
						/* logic driver */
	uint8_t		al_properties[AMR_8LD_MAXDRIVES];
						/* "LDrvProp", properties of */
						/* each logic driver */
	uint8_t		al_state[AMR_8LD_MAXDRIVES];
						/* "LDrvState", state of */
						/* each logic driver */
};

/*
 * Logical drive only: al_properties
 */
#define	AMR_DRV_RAID_MASK	0x0f		/* RAID level 0, 1, 3, 5, etc */
#define	AMR_DRV_WRITEBACK	0x10		/* write-back enabled */
#define	AMR_DRV_READHEAD	0x20		/* readhead policy enabled */
#define	AMR_DRV_ADAPTIVE	0x40		/* adaptive I/O enabled */

/*
 * Physical Drive info structure
 */
struct amr_physdrive_info
{
	uint8_t	ap_state[AMR_8LD_MAXPHYSDRIVES];
						/* "PDrvState", state of each */
						/* phy-driver. Low nibble is */
						/* current state, high nibble */
						/* is previous state */
	uint8_t	ap_predictivefailure;		/* "PredictiveFailure" */
};

/*
 * Physical/logical drive states
 *
 * Both logical and physical drives maintain
 * 'current' and 'previous' states in the low/high
 * nibble of the _state field.
 */
#define	AMR_DRV_CURSTATE(x)	((x) & 0x0f)
#define	AMR_DRV_PREVSTATE(x)	(((x) >> 4) & 0x0f)

/*
 * Logical drives: al_state.
 */
#define	AMR_LDRV_OFFLINE	0x00
#define	AMR_LDRV_DEGRADED	0x01
#define	AMR_LDRV_OPTIMAL	0x02

/*
 * Physical drives: ap_state.
 */
#define	AMR_PDRV_UNCNF		0x00
#define	AMR_PDRV_ONLINE		0x03
#define	AMR_PDRV_FAILED		0x04
#define	AMR_PDRV_REBUILD	0x05
#define	AMR_PDRV_HOTSPARE	0x06

/*
 * Notify structure
 */
struct amr_notify
{
	uint32_t	an_globalcounter;	/* "globalCounter", change */
						/* counter */
	uint8_t		an_paramcounter;	/* "paramCounter", parameter */
						/* change counter */
	uint8_t		an_paramid;		/* "paramId", param modified */
	uint16_t	an_paramval;		/* "paramVal", new var of */
						/* last param modified */

	uint8_t	an_writeconfigcounter;		/* "writeConfigCounter", */
						/* write config occurred */
	uint8_t	res1[3];			/* "writeConfigRsvd" */

	uint8_t	an_ldrvopcounter;		/* "ldrvOpCounter", logical */
						/* drive operation */
	uint8_t	an_ldrvopid;			/* "ldrvOpId", ldrv num */
	uint8_t	an_ldrvopcmd;			/* "ldrvOpCmd", ldrv */
						/* operations */
	uint8_t	an_ldrvopstatus;		/* "ldrvOpStatus", status of */
						/* the operation */

	uint8_t	an_ldrvstatecounter;		/* "ldrvStateCounter", change */
						/* of logical drive state */
	uint8_t	an_ldrvstateid;			/* "ldrvStateId", ldrv num */
	uint8_t	an_ldrvstatenew;		/* "ldrvStateNew", new state */
	uint8_t	an_ldrvstateold;		/* "ldrvStateOld", old state */

	uint8_t	an_pdrvstatecounter;		/* "pdrvStateCounter", change */
						/* of physical drive state */
	uint8_t	an_pdrvstateid;			/* "pdrvStateId", pdrv id */
	uint8_t	an_pdrvstatenew;		/* "pdrvStateNew", new state */
	uint8_t	an_pdrvstateold;		/* "pdrvStateOld", old state */

	uint8_t	an_pdrvfmtcounter;		/* "pdrvFmtCounter", pdrv */
						/* format started/over */
	uint8_t	an_pdrvfmtid;			/* "pdrvFmtId", pdrv id */
	uint8_t	an_pdrvfmtval;			/* "pdrvFmtVal", format */
						/* started/over */
	uint8_t	res2;				/* "pdrvFmtRsvd" */

	uint8_t	an_targxfercounter;		/* "targXferCounter", scsi */
						/* xfer rate change */
	uint8_t	an_targxferid;			/* "targXferId", pdrv id */
	uint8_t	an_targxferval;			/* "targXferVal", new Xfer */
						/* params of last pdrv */
	uint8_t	res3;				/* "targXferRsvd" */

	uint8_t	an_fcloopidcounter;		/* "fcLoopIdChgCounter", */
						/* FC/AL loop ID changed */
	uint8_t	an_fcloopidpdrvid;		/* "fcLoopIdPdrvId", pdrv id */
	uint8_t	an_fcloopid0;			/* "fcLoopId0", loopid on fc */
						/* loop 0 */
	uint8_t	an_fcloopid1;			/* "fcLoopId1", loopid on fc */
						/* loop 1 */

	uint8_t	an_fcloopstatecounter;		/* "fcLoopStateCounter", */
						/* FC/AL loop status changed */
	uint8_t	an_fcloopstate0;		/* "fcLoopState0", state of */
						/* fc loop 0 */
	uint8_t	an_fcloopstate1;		/* "fcLoopState1", state of */
						/* fc loop 1 */
	uint8_t	res4;				/* "fcLoopStateRsvd" */
	uint8_t	pad[88];
};

/*
 * an_param values
 */
#define	AMR_PARAM_REBUILD_RATE		0x01
#define	AMR_PARAM_FLUSH_INTERVAL	0x02
#define	AMR_PARAM_SENSE_ALERT		0x03
#define	AMR_PARAM_DRIVE_INSERTED	0x04
#define	AMR_PARAM_BATTERY_STATUS	0x05

/*
 * an_ldrvopcmd values
 */
#define	AMR_LDRVOP_CHECK		0x01
#define	AMR_LDRVOP_INIT			0x02
#define	AMR_LDRVOP_REBUILD		0x03

/*
 * an_ldrvopstatus: return values after issuing command
 * via an_ldrvopcmd.
 */
#define	AMR_LDRVOP_SUCCESS		0x00
#define	AMR_LDRVOP_FAILED		0x01
#define	AMR_LDRVOP_ABORTED		0x02
#define	AMR_LDRVOP_CORRECTED		0x03
#define	AMR_LDRVOP_STARTED		0x04

/*
 * an_pdrvfmtval: Formatting commands/return values
 */
#define	AMR_FORMAT_START		0x01
#define	AMR_FORMAT_COMPLETE		0x02

/*
 * Enquiry response structure for AMR_CMD_ENQUIRY, AMR_CMD_EXT_ENQUIRY and
 * AMR_CMD_EXT_ENQUIRY2.
 */
struct amr_enquiry
{
	struct amr_adapter_info		ae_adapter;
	struct amr_logdrive_info	ae_ldrv;
	struct amr_physdrive_info	ae_pdrv;
	uint8_t				ae_formatting[AMR_8LD_MAXDRIVES];
	uint8_t				res1[AMR_8LD_MAXDRIVES];
	uint32_t			ae_extlen;
	uint16_t			ae_subsystem;
	uint16_t			ae_subvendor;
	uint32_t			ae_signature;
	uint8_t				res2[844];
};

/*
 * ae_signature values
 */
#define	AMR_SIG_431			0xfffe0001
#define	AMR_SIG_438			0xfffd0002
#define	AMR_SIG_762			0xfffc0003
#define	AMR_SIG_T5			0xfffb0004
#define	AMR_SIG_466			0xfffa0005
#define	AMR_SIG_467			0xfff90006
#define	AMR_SIG_T7			0xfff80007
#define	AMR_SIG_490			0xfff70008

/*
 * Enquiry3 structure
 */
struct amr_enquiry3
{
	uint32_t	ae_datasize;		/* "dataSize", current size */
						/* in bytes(resvd excluded) */
	struct amr_notify	ae_notify;	/* "notify", event notify */
						/* structure */
	uint8_t		ae_rebuildrate;		/* "rbldRate", current */
						/* rebuild rate in % */
	uint8_t		ae_cacheflush;		/* "cacheFlushInterval", */
						/* flush interval in seconds */
	uint8_t		ae_sensealert;		/* "senseAlert" */
	uint8_t		ae_driveinsertcount;	/* "driveInsertedCount", */
						/* count of inserted drives */
	uint8_t		ae_batterystatus;	/* "batteryStatus" */
	uint8_t		ae_numldrives;		/* "numLDrv", number of logic */
						/* drivers configured */
	uint8_t		ae_reconstate[AMR_40LD_MAXDRIVES/8];
						/* "reconState", */
						/* reconstruction state */
	uint16_t	ae_opstatus[AMR_40LD_MAXDRIVES/8];
						/* "lDrvOpStatus", operation */
						/* state per logic driver */
	uint32_t	ae_drivesize[AMR_40LD_MAXDRIVES];
						/* "lDrvSize", size of each */
						/* logic driver */
	uint8_t		ae_driveprop[AMR_40LD_MAXDRIVES];
						/* "lDrvProp", properties of */
						/* each logic driver */
	uint8_t		ae_drivestate[AMR_40LD_MAXDRIVES];
						/* "lDrvState", state of */
						/* each logic driver */
	uint8_t		ae_pdrivestate[AMR_40LD_MAXPHYSDRIVES];
						/* "pDrvState", state of each */
						/* physical driver */
	uint16_t	ae_pdriveformat[AMR_40LD_MAXPHYSDRIVES/16];
						/* "physDrvFormat" */
	uint8_t		ae_targxfer[80];	/* "targXfer", physical drive */
						/* transfer rates */
	uint8_t		res1[263];		/* pad to 1024 bytes */
};

/*
 * Product Info structure. Query for this via AMR_CONFIG_PRODUCT_INFO.
 */
struct amr_prodinfo
{
	uint32_t	ap_size;		/* "DataSize", current size */
						/* in bytes */
	uint32_t	ap_configsig;		/* "ConfigSignature", default */
						/* is 0x00282008, indicating */
						/* 0x28 max logical drives, */
						/* 0x20 maximum stripes and */
						/* 0x08 maximum spans */
	uint8_t		ap_firmware[16];	/* "FwVer", firmware version */
	uint8_t		ap_bios[16];		/* "BiosVer", Bios version */
	uint8_t		ap_product[80];		/* "ProductName", prod name */
	uint8_t		ap_maxio;		/* "MaxConcCmds", max number */
						/* of concurrent commands */
	uint8_t		ap_nschan;		/* "SCSIChanPresent", number */
						/* of SCSI channels present */
	uint8_t		ap_fcloops;		/* "FCLoopPresent", number of */
						/* fibre loops present */
	uint8_t		ap_memtype;		/* "memType", memory type */
	uint32_t	ap_signature;		/* "signature" */
	uint16_t	ap_memsize;		/* "DramSize", onboard memory */
						/* in MB */
	uint16_t	ap_subsystem;		/* "subSystemID", subsystem */
						/* identifier */
	uint16_t	ap_subvendor;		/* "subSystemVendorID" */
	uint8_t		ap_numnotifyctr;	/* "numNotifyCounters", num */
						/* of notify counters */
};

/*
 * The union for used enquiry commands
 */
union amr_enq_buffer
{
	struct amr_enquiry3	aeb_enquiry3;
	struct amr_enquiry	aeb_enquiry;
	struct amr_prodinfo	aeb_prodinfo;
};

#pragma pack()

#ifdef _KERNEL

/*
 * I/O Port offsets
 */
#define	ACK_BYTE		0x08
#define	I_CMD_PORT		0x00
#define	I_ACK_PORT		0x00
#define	I_TOGGLE_PORT		0x01
#define	INTR_PORT		0x0a
#define	ENABLE_INTR_BYTE	0xc0
#define	DISABLE_INTR_BYTE  	0x00
#define	AMR_QINTR		0x0a
#define	AMR_QINTR_VALID		0x40

#define	AMR_QGET_ISTAT(sc)	pci_config_get8(sc->regsmap_handle, AMR_QINTR)
#define	AMR_QCLEAR_INTR(sc)	pci_config_put8(sc->regsmap_handle, \
				I_ACK_PORT,  ACK_BYTE)
#define	AMR_QENABLE_INTR(sc)	pci_config_put8(sc->regsmap_handle, \
				I_TOGGLE_PORT,  ENABLE_INTR_BYTE)
#define	AMR_QDISABLE_INTR(sc)	pci_config_put8(sc->regsmap_handle, \
				I_TOGGLE_PORT,  DISABLE_INTR_BYTE)
#define	AMR_CFG_SIG		0xa0	/* PCI config register for signature */
#define	AMR_SIGNATURE_1		0xCCCC	/* i960 signature (older adapters) */
#define	AMR_SIGNATURE_2		0x3344	/* i960 signature (newer adapters) */

/*
 * Doorbell registers
 */
#define	AMR_QIDB		0x20
#define	AMR_QODB		0x2c
#define	AMR_QIDB_SUBMIT		0x00000001 /* mailbox ready for work */
#define	AMR_QIDB_ACK		0x00000002 /* mailbox done */
#define	AMR_QODB_READY		0x10001234 /* work ready to be processed */

/*
 * Initialisation status
 */
#define	AMR_QINIT_SCAN		0x01	/* init scanning drives */
#define	AMR_QINIT_SCANINIT	0x02	/* init scanning initialising */
#define	AMR_QINIT_FIRMWARE	0x03	/* init firmware initing */
#define	AMR_QINIT_INPROG	0xdc	/* init in progress */
#define	AMR_QINIT_SPINUP	0x2c	/* init spinning drives */
#define	AMR_QINIT_NOMEM		0xac	/* insufficient memory */
#define	AMR_QINIT_CACHEFLUSH	0xbc	/* init flushing cache */
#define	AMR_QINIT_DONE		0x9c	/* init successfully done */

/*
 * I/O primitives
 */
#define	AMR_QPUT_IDB(sc, val)	pci_config_put32(sc->regsmap_handle, \
							AMR_QIDB, val)
#define	AMR_QGET_IDB(sc)	pci_config_get32(sc->regsmap_handle, \
							AMR_QIDB)
#define	AMR_QPUT_ODB(sc, val)	pci_config_put32(sc->regsmap_handle, \
							AMR_QODB, val)
#define	AMR_QGET_ODB(sc)	pci_config_get32(sc->regsmap_handle, \
							AMR_QODB)

/*
 * I/O registers
 */
#define	AMR_SCMD		0x10	/* command/ack register (write) */
#define	AMR_SMBOX_BUSY		0x10	/* mailbox status (read) */
#define	AMR_STOGGLE		0x11	/* interrupt enable bit here */
#define	AMR_SMBOX_0		0x14	/* mailbox physical address low byte */
#define	AMR_SMBOX_1		0x15
#define	AMR_SMBOX_2		0x16
#define	AMR_SMBOX_3		0x17	/* high byte */
#define	AMR_SMBOX_ENABLE	0x18	/* atomic mailbox address enable */
#define	AMR_SINTR		0x1a	/* interrupt status */

/*
 * I/O magic numbers
 */
#define	AMR_SCMD_POST		0x10	/* SCMD to initiate action on mailbox */
#define	AMR_SCMD_ACKINTR	0x08	/* SCMD to ack mailbox retrieved */
#define	AMR_STOGL_IENABLE	0xc0	/* in STOGGLE */
#define	AMR_SINTR_VALID		0x40	/* in SINTR */
#define	AMR_SMBOX_BUSYFLAG	0x10	/* in SMBOX_BUSY */
#define	AMR_SMBOX_ADDR		0x00	/* SMBOX_ENABLE */

/*
 * Initialisation status
 */
#define	AMR_SINIT_ABEND		0xee	/* init abnormal terminated */
#define	AMR_SINIT_NOMEM		0xca	/* insufficient memory */
#define	AMR_SINIT_CACHEFLUSH	0xbb	/* firmware flushing cache */
#define	AMR_SINIT_INPROG	0x11	/* init in progress */
#define	AMR_SINIT_SPINUP	0x22	/* firmware spinning drives */
#define	AMR_SINIT_DONE		0x99	/* init successfully done */

/*
 * I/O primitives
 */
#define	AMR_SPUT_ISTAT(sc, val)	pci_config_put8(sc->regsmap_handle, \
					AMR_SINTR, val)
#define	AMR_SGET_ISTAT(sc)	pci_config_get8(sc->regsmap_handle, AMR_SINTR)
#define	AMR_SACK_INTERRUPT(sc)	pci_config_put8(sc->regsmap_handle, \
					AMR_SCMD, AMR_SCMD_ACKINTR)
#define	AMR_SPOST_COMMAND(sc)	pci_config_put8(sc->regsmap_handle, AMR_SCMD, \
					AMR_SCMD_POST)
#define	AMR_SGET_MBSTAT(sc)	pci_config_get8(sc->regsmap_handle, \
					AMR_SMBOX_BUSY)

#define	AMR_SENABLE_INTR(sc)	\
	pci_config_put8(sc->regsmap_handle, AMR_STOGGLE, \
		pci_config_get8(sc->regsmap_handle, AMR_STOGGLE) \
		| AMR_STOGL_IENABLE)

#define	AMR_SDISABLE_INTR(sc)	\
	pci_config_put8(sc->regsmap_handle, AMR_STOGGLE, \
		pci_config_get8(sc->regsmap_handle, AMR_STOGGLE) \
		& ~AMR_STOGL_IENABLE)

#define	AMR_SBYTE_SET(sc, reg, val) pci_config_put8(sc->regsmap_handle, \
					reg, val)

#endif /* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif /* _AMRREG_H */
