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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright (c) 2013, Joyent, Inc. All rights reserved.
 * Copyright 2014 Nexenta Systems, Inc. All rights reserved.
 * Copyright (c) 2014, Tegile Systems Inc. All rights reserved.
 */

/*
 * Copyright (c) 2000 to 2010, LSI Corporation.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms of all code within
 * this file that is exclusively owned by LSI, with or without
 * modification, is permitted provided that, in addition to the CDDL 1.0
 * License requirements, the following conditions are met:
 *
 *    Neither the name of the author nor the names of its contributors may be
 *    used to endorse or promote products derived from this software without
 *    specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

#ifndef _MPTSAS_IOCTL_H
#define	_MPTSAS_IOCTL_H

#ifdef  __cplusplus
extern "C" {
#endif

#include <sys/types.h>

#define	MPTIOCTL			('I' << 8)
#define	MPTIOCTL_GET_ADAPTER_DATA	(MPTIOCTL | 1)
#define	MPTIOCTL_UPDATE_FLASH		(MPTIOCTL | 2)
#define	MPTIOCTL_RESET_ADAPTER		(MPTIOCTL | 3)
#define	MPTIOCTL_PASS_THRU		(MPTIOCTL | 4)
#define	MPTIOCTL_EVENT_QUERY		(MPTIOCTL | 5)
#define	MPTIOCTL_EVENT_ENABLE		(MPTIOCTL | 6)
#define	MPTIOCTL_EVENT_REPORT		(MPTIOCTL | 7)
#define	MPTIOCTL_GET_PCI_INFO		(MPTIOCTL | 8)
#define	MPTIOCTL_DIAG_ACTION		(MPTIOCTL | 9)
#define	MPTIOCTL_REG_ACCESS		(MPTIOCTL | 10)
#define	MPTIOCTL_GET_DISK_INFO		(MPTIOCTL | 11)
#define	MPTIOCTL_LED_CONTROL		(MPTIOCTL | 12)

/*
 *  The following are our ioctl() return status values.  If everything went
 *  well, we return good status.  If the buffer length sent to us is too short
 *  we return a status to tell the user.
 */
#define	MPTIOCTL_STATUS_GOOD		0
#define	MPTIOCTL_STATUS_LEN_TOO_SHORT	1

typedef struct mptsas_pci_bits
{
	union {
		struct {
			uint32_t	DeviceNumber	:5;
			uint32_t	FunctionNumber	:3;
			uint32_t	BusNumber	:24;
		} bits;
		uint32_t	AsDWORD;
	} u;
	uint32_t	PciSegmentId;
} mptsas_pci_bits_t;
/*
 *  The following is the MPTIOCTL_GET_ADAPTER_DATA data structure.  This data
 *  structure is setup so that we hopefully are properly aligned for both
 *  32-bit and 64-bit mode applications.
 *
 *  Adapter Type - Value = 4 = SCSI Protocol through SAS-2 adapter
 *                 Value = 6 = SCSI Protocol through SAS-3 adapter
 *
 *  MPI Port Number - The PCI Function number for this device
 *
 *  PCI Device HW Id - The PCI device number for this device
 *
 */
#define	MPTIOCTL_ADAPTER_TYPE_SAS2	4
#define	MPTIOCTL_ADAPTER_TYPE_SAS3	6

typedef struct mptsas_adapter_data
{
	uint32_t		StructureLength;
	uint32_t		AdapterType;
	uint32_t		MpiPortNumber;
	uint32_t		PCIDeviceHwId;
	uint32_t		PCIDeviceHwRev;
	uint32_t		SubSystemId;
	uint32_t		SubsystemVendorId;
	uint32_t		Reserved1;
	uint32_t		MpiFirmwareVersion;
	uint32_t		BiosVersion;
	uint8_t			DriverVersion[32];
	uint8_t			Reserved2;
	uint8_t			ScsiId;
	uint16_t		Reserved3;
	mptsas_pci_bits_t	PciInformation;
} mptsas_adapter_data_t;


typedef struct mptsas_update_flash
{
	uint64_t	PtrBuffer;
	uint32_t	ImageChecksum;
	uint32_t	ImageOffset;
	uint32_t	ImageSize;
	uint32_t	ImageType;
} mptsas_update_flash_t;


#define	MPTSAS_PASS_THRU_DIRECTION_NONE		0
#define	MPTSAS_PASS_THRU_DIRECTION_READ		1
#define	MPTSAS_PASS_THRU_DIRECTION_WRITE	2
#define	MPTSAS_PASS_THRU_DIRECTION_BOTH		3

typedef struct mptsas_pass_thru
{
	uint64_t	PtrRequest;
	uint64_t	PtrReply;
	uint64_t	PtrData;
	uint32_t	RequestSize;
	uint32_t	ReplySize;
	uint32_t	DataSize;
	uint32_t	DataDirection;
	uint64_t	PtrDataOut;
	uint32_t	DataOutSize;
	uint32_t	Timeout;
} mptsas_pass_thru_t;


/*
 * Event queue defines
 */
#define	MPTSAS_EVENT_QUEUE_SIZE		(50) /* Max Events stored in driver */
#define	MPTSAS_MAX_EVENT_DATA_LENGTH	(48) /* Size of each event in Dwords */

typedef struct mptsas_event_query
{
	uint16_t	Entries;
	uint16_t	Reserved;
	uint32_t	Types[4];
} mptsas_event_query_t;

typedef struct mptsas_event_enable
{
	uint32_t	Types[4];
} mptsas_event_enable_t;

/*
 * Event record entry for ioctl.
 */
typedef struct mptsas_event_entry
{
	uint32_t	Type;
	uint32_t	Number;
	uint32_t	Data[MPTSAS_MAX_EVENT_DATA_LENGTH];
} mptsas_event_entry_t;

typedef struct mptsas_event_report
{
	uint32_t		Size;
	mptsas_event_entry_t	Events[1];
} mptsas_event_report_t;


typedef struct mptsas_pci_info
{
	uint32_t	BusNumber;
	uint8_t		DeviceNumber;
	uint8_t		FunctionNumber;
	uint16_t	InterruptVector;
	uint8_t		PciHeader[256];
} mptsas_pci_info_t;


typedef struct mptsas_diag_action
{
	uint32_t	Action;
	uint32_t	Length;
	uint64_t	PtrDiagAction;
	uint32_t	ReturnCode;
} mptsas_diag_action_t;

#define	MPTSAS_FW_DIAGNOSTIC_UID_NOT_FOUND	(0xFF)

#define	MPTSAS_FW_DIAG_NEW			(0x806E6577)

#define	MPTSAS_FW_DIAG_TYPE_REGISTER		(0x00000001)
#define	MPTSAS_FW_DIAG_TYPE_UNREGISTER		(0x00000002)
#define	MPTSAS_FW_DIAG_TYPE_QUERY		(0x00000003)
#define	MPTSAS_FW_DIAG_TYPE_READ_BUFFER		(0x00000004)
#define	MPTSAS_FW_DIAG_TYPE_RELEASE		(0x00000005)

#define	MPTSAS_FW_DIAG_INVALID_UID		(0x00000000)

#define	MPTSAS_FW_DIAG_ERROR_SUCCESS		(0x00000000)
#define	MPTSAS_FW_DIAG_ERROR_FAILURE		(0x00000001)
#define	MPTSAS_FW_DIAG_ERROR_INVALID_PARAMETER	(0x00000002)
#define	MPTSAS_FW_DIAG_ERROR_POST_FAILED	(0x00000010)
#define	MPTSAS_FW_DIAG_ERROR_INVALID_UID	(0x00000011)
#define	MPTSAS_FW_DIAG_ERROR_RELEASE_FAILED	(0x00000012)
#define	MPTSAS_FW_DIAG_ERROR_NO_BUFFER		(0x00000013)
#define	MPTSAS_FW_DIAG_ERROR_ALREADY_RELEASED	(0x00000014)


typedef struct mptsas_fw_diag_register
{
	uint8_t		ExtendedType;
	uint8_t		BufferType;
	uint16_t	ApplicationFlags;
	uint32_t	DiagnosticFlags;
	uint32_t	ProductSpecific[23];
	uint32_t	RequestedBufferSize;
	uint32_t	UniqueId;
} mptsas_fw_diag_register_t;

typedef struct mptsas_fw_diag_unregister
{
	uint32_t	UniqueId;
} mptsas_fw_diag_unregister_t;

#define	MPTSAS_FW_DIAG_FLAG_APP_OWNED		(0x0001)
#define	MPTSAS_FW_DIAG_FLAG_BUFFER_VALID	(0x0002)
#define	MPTSAS_FW_DIAG_FLAG_FW_BUFFER_ACCESS	(0x0004)

typedef struct mptsas_fw_diag_query
{
	uint8_t		ExtendedType;
	uint8_t		BufferType;
	uint16_t	ApplicationFlags;
	uint32_t	DiagnosticFlags;
	uint32_t	ProductSpecific[23];
	uint32_t	TotalBufferSize;
	uint32_t	DriverAddedBufferSize;
	uint32_t	UniqueId;
} mptsas_fw_diag_query_t;

typedef struct mptsas_fw_diag_release
{
	uint32_t	UniqueId;
} mptsas_fw_diag_release_t;

#define	MPTSAS_FW_DIAG_FLAG_REREGISTER		(0x0001)
#define	MPTSAS_FW_DIAG_FLAG_FORCE_RELEASE	(0x0002)

typedef struct mptsas_diag_read_buffer
{
	uint8_t		Status;
	uint8_t		Reserved;
	uint16_t	Flags;
	uint32_t	StartingOffset;
	uint32_t	BytesToRead;
	uint32_t	UniqueId;
	uint32_t	DataBuffer[1];
} mptsas_diag_read_buffer_t;

/*
 * Register Access
 */
#define	REG_IO_READ	1
#define	REG_IO_WRITE	2
#define	REG_MEM_READ	3
#define	REG_MEM_WRITE	4

typedef struct mptsas_reg_access
{
	uint32_t	Command;
	uint32_t	RegOffset;
	uint32_t	RegData;
} mptsas_reg_access_t;

/*
 * Disk Toplogy Information
 */
typedef struct mptsas_disk_info
{
	uint64_t	SasAddress;
	uint16_t	Instance;
	uint16_t	Enclosure;
	uint16_t	Slot;
} mptsas_disk_info_t;

typedef struct mptsas_get_disk_info
{
	uint16_t		DiskCount;
	mptsas_disk_info_t	*PtrDiskInfoArray;
	uint64_t		DiskInfoArraySize;
} mptsas_get_disk_info_t;

#ifdef _KERNEL

typedef struct mptsas_get_disk_info32
{
	uint16_t		DiskCount;
	caddr32_t		PtrDiskInfoArray;
	uint64_t		DiskInfoArraySize;
} mptsas_get_disk_info32_t;

#endif /* _KERNEL */

/*
 * LED Control
 */

typedef struct mptsas_led_control
{
	uint8_t		Command;
	uint16_t	Enclosure;
	uint16_t	Slot;
	uint8_t		Led;
	uint8_t		LedStatus;
} mptsas_led_control_t;

#define	MPTSAS_LEDCTL_FLAG_SET		1
#define	MPTSAS_LEDCTL_FLAG_GET		2

#define	MPTSAS_LEDCTL_LED_IDENT		1
#define	MPTSAS_LEDCTL_LED_FAIL		2
#define	MPTSAS_LEDCTL_LED_OK2RM		3

#define	MPTSAS_LEDCTL_LED_MIN		MPTSAS_LEDCTL_LED_IDENT
#define	MPTSAS_LEDCTL_LED_MAX		MPTSAS_LEDCTL_LED_OK2RM

#ifdef  __cplusplus
}
#endif

#endif	/* _MPTSAS_IOCTL_H */
