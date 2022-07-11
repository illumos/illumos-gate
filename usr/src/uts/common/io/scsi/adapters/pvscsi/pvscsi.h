/*
 * Copyright (C) 2008-2014, VMware, Inc. All Rights Reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef	_PVSCSI_H_
#define	_PVSCSI_H_

#include <sys/types.h>

#define	PVSCSI_MAX_NUM_SG_ENTRIES_PER_SEGMENT 128

#define	MASK(n) ((1 << (n)) - 1)	/* make an n-bit mask */

#define	PCI_DEVICE_ID_VMWARE_PVSCSI	0x07C0

/*
 * host adapter status/error codes
 */
enum HostBusAdapterStatus {
	BTSTAT_SUCCESS		= 0x00,	/* CCB complete normally with */
					/* no errors */
	BTSTAT_LINKED_COMMAND_COMPLETED = 0x0a,
	BTSTAT_LINKED_COMMAND_COMPLETED_WITH_FLAG = 0x0b,
	BTSTAT_DATA_UNDERRUN	= 0x0c,
	BTSTAT_SELTIMEO		= 0x11,	/* SCSI selection timeout */
	BTSTAT_DATARUN		= 0x12,	/* data overrun/underrun */
	BTSTAT_BUSFREE		= 0x13,	/* unexpected bus free */
	BTSTAT_INVPHASE		= 0x14,	/* invalid bus phase or sequence */
					/* requested by target */
	BTSTAT_LUNMISMATCH	= 0x17,	/* linked CCB has different LUN from */
					/* first CCB */
	BTSTAT_INVPARAM		= 0x1a,	/* invalid parameter in CCB */
					/* or segment list */
	BTSTAT_SENSFAILED	= 0x1b,	/* auto request sense failed */
	BTSTAT_TAGREJECT	= 0x1c,	/* SCSI II tagged queueing message */
					/* rejected by target */
	BTSTAT_BADMSG		= 0x1d,	/* unsupported message received by */
					/* the host adapter */
	BTSTAT_HAHARDWARE	= 0x20,	/* host adapter hardware failed */
	BTSTAT_NORESPONSE	= 0x21,	/* target did not respond to */
					/* SCSI ATN, sent a SCSI RST */
	BTSTAT_SENTRST		= 0x22,	/* host adapter asserted a SCSI RST */
	BTSTAT_RECVRST		= 0x23,	/* other SCSI devices asserted */
					/* a SCSI RST */
	BTSTAT_DISCONNECT	= 0x24,	/* target device reconnected */
					/* improperly (w/o tag) */
	BTSTAT_BUSRESET		= 0x25,	/* host adapter issued */
					/* BUS device reset */
	BTSTAT_ABORTQUEUE	= 0x26,	/* abort queue generated */
	BTSTAT_HASOFTWARE	= 0x27,	/* host adapter software error */
	BTSTAT_HATIMEOUT	= 0x30,	/* host adapter hardware */
					/* timeout error */
	BTSTAT_SCSIPARITY	= 0x34,	/* SCSI parity error detected */
};

/*
 * SCSI device status values.
 */
enum ScsiDeviceStatus {
	SDSTAT_GOOD	= 0x00, /* No errors. */
	SDSTAT_CHECK	= 0x02, /* Check condition. */
};

/*
 * Register offsets.
 *
 * These registers are accessible both via i/o space and mm i/o.
 */

enum PVSCSIRegOffset {
	PVSCSI_REG_OFFSET_COMMAND	= 0x0,
	PVSCSI_REG_OFFSET_COMMAND_DATA	= 0x4,
	PVSCSI_REG_OFFSET_COMMAND_STATUS = 0x8,
	PVSCSI_REG_OFFSET_LAST_STS_0	= 0x100,
	PVSCSI_REG_OFFSET_LAST_STS_1	= 0x104,
	PVSCSI_REG_OFFSET_LAST_STS_2	= 0x108,
	PVSCSI_REG_OFFSET_LAST_STS_3	= 0x10c,
	PVSCSI_REG_OFFSET_INTR_STATUS	= 0x100c,
	PVSCSI_REG_OFFSET_INTR_MASK	= 0x2010,
	PVSCSI_REG_OFFSET_KICK_NON_RW_IO = 0x3014,
	PVSCSI_REG_OFFSET_DEBUG		= 0x3018,
	PVSCSI_REG_OFFSET_KICK_RW_IO	= 0x4018,
};

/*
 * Virtual h/w commands.
 */

enum PVSCSICommands {
	PVSCSI_CMD_FIRST		= 0, /* has to be first */

	PVSCSI_CMD_ADAPTER_RESET	= 1,
	PVSCSI_CMD_ISSUE_SCSI		= 2,
	PVSCSI_CMD_SETUP_RINGS		= 3,
	PVSCSI_CMD_RESET_BUS		= 4,
	PVSCSI_CMD_RESET_DEVICE		= 5,
	PVSCSI_CMD_ABORT_CMD		= 6,
	PVSCSI_CMD_CONFIG		= 7,
	PVSCSI_CMD_SETUP_MSG_RING	= 8,
	PVSCSI_CMD_DEVICE_UNPLUG	= 9,
	PVSCSI_CMD_SETUP_REQCALLTHRESHOLD = 10,

	PVSCSI_CMD_LAST			= 11  /* has to be last */
};

/*
 * Command descriptor for PVSCSI_CMD_RESET_DEVICE --
 */
#pragma pack(1)
struct PVSCSICmdDescResetDevice {
	uint32_t	target;
	uint8_t		lun[8];
};
#pragma pack()

/*
 * Command descriptor for PVSCSI_CMD_CONFIG --
 */
#pragma pack(1)
struct PVSCSICmdDescConfigCmd {
	uint64_t	cmpAddr;
	uint64_t	configPageAddress;
	uint32_t	configPageNum;
	uint32_t	_pad;
};
#pragma pack()

/*
 * Command descriptor for PVSCSI_CMD_SETUP_REQCALLTHRESHOLD --
 */
#pragma pack(1)
struct PVSCSICmdDescSetupReqCall {
	uint32_t	enable;
};
#pragma pack()

enum PVSCSIConfigPageType {
	PVSCSI_CONFIG_PAGE_CONTROLLER	= 0x1958,
	PVSCSI_CONFIG_PAGE_PHY		= 0x1959,
	PVSCSI_CONFIG_PAGE_DEVICE	= 0x195a,
};

enum PVSCSIConfigPageAddressType {
	PVSCSI_CONFIG_CONTROLLER_ADDRESS = 0x2120,
	PVSCSI_CONFIG_BUSTARGET_ADDRESS	= 0x2121,
	PVSCSI_CONFIG_PHY_ADDRESS	= 0x2122,
};

/*
 * Command descriptor for PVSCSI_CMD_ABORT_CMD --
 *
 * - currently does not support specifying the LUN.
 * - _pad should be 0.
 */

struct PVSCSICmdDescAbortCmd {
	uint64_t	context;
	uint32_t	target;
	uint32_t	_pad;
} __packed;

/*
 * Command descriptor for PVSCSI_CMD_SETUP_RINGS --
 *
 * Notes:
 * - reqRingNumPages and cmpRingNumPages need to be power of two.
 * - reqRingNumPages and cmpRingNumPages need to be different from 0,
 * - reqRingNumPages and cmpRingNumPages need to be inferior to
 *   PVSCSI_SETUP_RINGS_MAX_NUM_PAGES.
 */
#define	PVSCSI_SETUP_RINGS_MAX_NUM_PAGES 32

#pragma pack(1)
struct PVSCSICmdDescSetupRings {
	uint32_t	reqRingNumPages;
	uint32_t	cmpRingNumPages;
	uint64_t	ringsStatePPN;
	uint64_t	reqRingPPNs[PVSCSI_SETUP_RINGS_MAX_NUM_PAGES];
	uint64_t	cmpRingPPNs[PVSCSI_SETUP_RINGS_MAX_NUM_PAGES];
};
#pragma pack()

/*
 * Command descriptor for PVSCSI_CMD_SETUP_MSG_RING --
 *
 * Notes:
 * - this command was not supported in the initial revision of the h/w
 *   interface. Before using it, you need to check that it is supported by
 *   writing PVSCSI_CMD_SETUP_MSG_RING to the 'command' register, then
 *   immediately after read the 'command status' register:
 *       * a value of -1 means that the cmd is NOT supported,
 *       * a value != -1 means that the cmd IS supported.
 *   If it's supported the 'command status' register should return:
 *      sizeof(PVSCSICmdDescSetupMsgRing) / sizeof(uint32_t).
 * - this command should be issued _after_ the usual SETUP_RINGS so that the
 *   RingsState page is already setup. If not, the command is a nop.
 * - numPages needs to be a power of two,
 * - numPages needs to be different from 0,
 * - _pad should be zero.
 */
#define	PVSCSI_SETUP_MSG_RING_MAX_NUM_PAGES 16

#pragma pack(1)
struct PVSCSICmdDescSetupMsgRing {
	uint32_t	numPages;
	uint32_t	_pad;
	uint64_t	ringPPNs[PVSCSI_SETUP_MSG_RING_MAX_NUM_PAGES];
};
#pragma pack()

enum PVSCSIMsgType {
	PVSCSI_MSG_DEV_ADDED	= 0,
	PVSCSI_MSG_DEV_REMOVED	= 1,
	PVSCSI_MSG_LAST		= 2,
};

/*
 * Msg descriptor.
 *
 * sizeof(struct PVSCSIRingMsgDesc) == 128.
 *
 * - type is of type enum PVSCSIMsgType.
 * - the content of args depend on the type of event being delivered.
 */
#pragma pack(1)
struct PVSCSIRingMsgDesc {
	uint32_t	type;
	uint32_t	args[31];
};
#pragma pack()

#pragma pack(1)
struct PVSCSIMsgDescDevStatusChanged {
	uint32_t	type;  /* PVSCSI_MSG_DEV _ADDED / _REMOVED */
	uint32_t	bus;
	uint32_t	target;
	uint8_t		lun[8];
	uint32_t	pad[27];
};
#pragma pack()

/*
 * Rings state.
 *
 * - the fields:
 *    . msgProdIdx,
 *    . msgConsIdx,
 *    . msgNumEntriesLog2,
 *   .. are only used once the SETUP_MSG_RING cmd has been issued.
 * - '_pad' helps to ensure that the msg related fields are on their own
 *   cache-line.
 */
#pragma pack(1)
struct PVSCSIRingsState {
	uint32_t	reqProdIdx;
	uint32_t	reqConsIdx;
	uint32_t	reqNumEntriesLog2;

	uint32_t	cmpProdIdx;
	uint32_t	cmpConsIdx;
	uint32_t	cmpNumEntriesLog2;

	uint32_t	reqCallThreshold;

	uint8_t		_pad[100];

	uint32_t	msgProdIdx;
	uint32_t	msgConsIdx;
	uint32_t	msgNumEntriesLog2;
};
#pragma pack()

/*
 * Request descriptor.
 *
 * sizeof(RingReqDesc) = 128
 *
 * - context: is a unique identifier of a command. It could normally be any
 *   64bit value, however we currently store it in the serialNumber variable
 *   of struct SCSI_Command, so we have the following restrictions due to the
 *   way this field is handled in the vmkernel storage stack:
 *    * this value can't be 0,
 *    * the upper 32bit need to be 0 since serialNumber is as a uint32_t.
 *   Currently tracked as PR 292060.
 * - dataLen: contains the total number of bytes that need to be transferred.
 * - dataAddr:
 *   * if PVSCSI_FLAG_CMD_WITH_SG_LIST is set: dataAddr is the PA of the first
 *     s/g table segment, each s/g segment is entirely contained on a single
 *     page of physical memory,
 *   * if PVSCSI_FLAG_CMD_WITH_SG_LIST is NOT set, then dataAddr is the PA of
 *     the buffer used for the DMA transfer,
 * - flags:
 *   * PVSCSI_FLAG_CMD_WITH_SG_LIST: see dataAddr above,
 *   * PVSCSI_FLAG_CMD_DIR_NONE: no DMA involved,
 *   * PVSCSI_FLAG_CMD_DIR_TOHOST: transfer from device to main memory,
 *   * PVSCSI_FLAG_CMD_DIR_TODEVICE: transfer from main memory to device,
 *   * PVSCSI_FLAG_CMD_OUT_OF_BAND_CDB: reserved to handle CDBs larger than
 *     16bytes. To be specified.
 * - vcpuHint: vcpuId of the processor that will be most likely waiting for the
 *   completion of the i/o. For guest OSes that use lowest priority message
 *   delivery mode (such as windows), we use this "hint" to deliver the
 *   completion action to the proper vcpu. For now, we can use the vcpuId of
 *   the processor that initiated the i/o as a likely candidate for the vcpu
 *   that will be waiting for the completion..
 * - bus should be 0: we currently only support bus 0 for now.
 * - unused should be zero'd.
 */
#define	PVSCSI_FLAG_CMD_WITH_SG_LIST	(1 << 0)
#define	PVSCSI_FLAG_CMD_OUT_OF_BAND_CDB	(1 << 1)
#define	PVSCSI_FLAG_CMD_DIR_NONE	(1 << 2)
#define	PVSCSI_FLAG_CMD_DIR_TOHOST	(1 << 3)
#define	PVSCSI_FLAG_CMD_DIR_TODEVICE	(1 << 4)

#pragma pack(1)
struct PVSCSIRingReqDesc {
	uint64_t	context;
	uint64_t	dataAddr;
	uint64_t	dataLen;
	uint64_t	senseAddr;
	uint32_t	senseLen;
	uint32_t	flags;
	uint8_t		cdb[16];
	uint8_t		cdbLen;
	uint8_t		lun[8];
	uint8_t		tag;
	uint8_t		bus;
	uint8_t		target;
	uint8_t		vcpuHint;
	uint8_t		unused[59];
};
#pragma pack()

/*
 * Scatter-gather list management.
 *
 * As described above, when PVSCSI_FLAG_CMD_WITH_SG_LIST is set in the
 * RingReqDesc.flags, then RingReqDesc.dataAddr is the PA of the first s/g
 * table segment.
 *
 * - each segment of the s/g table contain a succession of struct
 *   PVSCSISGElement.
 * - each segment is entirely contained on a single physical page of memory.
 * - a "chain" s/g element has the flag PVSCSI_SGE_FLAG_CHAIN_ELEMENT set in
 *   PVSCSISGElement.flags and in this case:
 *     * addr is the PA of the next s/g segment,
 *     * length is undefined, assumed to be 0.
 */
#pragma pack(1)
struct PVSCSISGElement {
	uint64_t	addr;
	uint32_t	length;
	uint32_t	flags;
};
#pragma pack()

/*
 * Completion descriptor.
 *
 * sizeof(RingCmpDesc) = 32
 *
 * - context: identifier of the command. The same thing that was specified
 *   under "context" as part of struct RingReqDesc at initiation time,
 * - dataLen: number of bytes transferred for the actual i/o operation,
 * - senseLen: number of bytes written into the sense buffer,
 * - hostStatus: adapter status,
 * - scsiStatus: device status,
 * - _pad should be zero.
 */
#pragma pack(1)
struct PVSCSIRingCmpDesc {
	uint64_t	context;
	uint64_t	dataLen;
	uint32_t	senseLen;
	uint16_t	hostStatus;
	uint16_t	scsiStatus;
	uint32_t	_pad[2];
};
#pragma pack()

#pragma pack(1)
struct PVSCSIConfigPageHeader {
	uint32_t	pageNum;
	uint16_t	numDwords;
	uint16_t	hostStatus;
	uint16_t	scsiStatus;
	uint16_t	reserved[3];
};
#pragma pack()

#pragma pack(1)
struct PVSCSIConfigPageController {
	struct PVSCSIConfigPageHeader header;
	uint64_t	nodeWWN; /* Device name as defined in the SAS spec. */
	uint16_t	manufacturer[64];
	uint16_t	serialNumber[64];
	uint16_t	opromVersion[32];
	uint16_t	hwVersion[32];
	uint16_t	firmwareVersion[32];
	uint32_t	numPhys;
	uint8_t		useConsecutivePhyWWNs;
	uint8_t		reserved[3];
};
#pragma pack()

/*
 * Interrupt status / IRQ bits.
 */

#define	PVSCSI_INTR_CMPL_0	(1 << 0)
#define	PVSCSI_INTR_CMPL_1	(1 << 1)
#define	PVSCSI_INTR_CMPL_MASK	MASK(2)

#define	PVSCSI_INTR_MSG_0	(1 << 2)
#define	PVSCSI_INTR_MSG_1	(1 << 3)
#define	PVSCSI_INTR_MSG_MASK	(MASK(2) << 2)

#define	PVSCSI_INTR_ALL_SUPPORTED MASK(4)

/*
 * Number of MSI-X vectors supported.
 */
#define	PVSCSI_MAX_INTRS	24

/*
 * Enumeration of supported MSI-X vectors
 */
#define	PVSCSI_VECTOR_COMPLETION 0

/*
 * Misc constants for the rings.
 */

#define	PVSCSI_MAX_NUM_PAGES_REQ_RING	PVSCSI_SETUP_RINGS_MAX_NUM_PAGES
#define	PVSCSI_MAX_NUM_PAGES_CMP_RING	PVSCSI_SETUP_RINGS_MAX_NUM_PAGES
#define	PVSCSI_MAX_NUM_PAGES_MSG_RING	PVSCSI_SETUP_MSG_RING_MAX_NUM_PAGES

#define	PVSCSI_MAX_NUM_REQ_ENTRIES_PER_PAGE \
	(PAGE_SIZE / sizeof (struct PVSCSIRingReqDesc))

#define	PVSCSI_MAX_REQ_QUEUE_DEPTH \
	(PVSCSI_MAX_NUM_PAGES_REQ_RING * PVSCSI_MAX_NUM_REQ_ENTRIES_PER_PAGE)

#define	PVSCSI_MEM_SPACE_COMMAND_NUM_PAGES	1
#define	PVSCSI_MEM_SPACE_INTR_STATUS_NUM_PAGES	1
#define	PVSCSI_MEM_SPACE_MISC_NUM_PAGES		2
#define	PVSCSI_MEM_SPACE_KICK_IO_NUM_PAGES	2
#define	PVSCSI_MEM_SPACE_MSIX_NUM_PAGES		2

enum PVSCSIMemSpace {
	PVSCSI_MEM_SPACE_COMMAND_PAGE		= 0,
	PVSCSI_MEM_SPACE_INTR_STATUS_PAGE	= 1,
	PVSCSI_MEM_SPACE_MISC_PAGE		= 2,
	PVSCSI_MEM_SPACE_KICK_IO_PAGE		= 4,
	PVSCSI_MEM_SPACE_MSIX_TABLE_PAGE	= 6,
	PVSCSI_MEM_SPACE_MSIX_PBA_PAGE		= 7,
};

#define	PVSCSI_MEM_SPACE_NUM_PAGES		\
	(PVSCSI_MEM_SPACE_COMMAND_NUM_PAGES +	\
	PVSCSI_MEM_SPACE_INTR_STATUS_NUM_PAGES +\
	PVSCSI_MEM_SPACE_MISC_NUM_PAGES +	\
	PVSCSI_MEM_SPACE_KICK_IO_NUM_PAGES +	\
	PVSCSI_MEM_SPACE_MSIX_NUM_PAGES)

#define	PVSCSI_MEM_SPACE_SIZE (PVSCSI_MEM_SPACE_NUM_PAGES * PAGE_SIZE)

#endif /* _PVSCSI_H_ */
