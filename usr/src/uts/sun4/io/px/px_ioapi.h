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

#ifndef	_SYS_PX_IOAPI_H
#define	_SYS_PX_IOAPI_H

#ifdef	__cplusplus
extern "C" {
#endif

#ifndef _ASM

/*
 * SUN4V IO Data Definitions
 *
 * cpuid - A unique opaque value which represents a target cpu.
 *
 * devhandle -	Device handle. The device handle uniquely
 *		identifies a SUN4V device. It consists of the
 *		the lower 28-bits of the hi-cell of the first
 *		entry of the SUN4V device's "reg" property as defined
 *		by the SUN4V Bus Binding to Open Firmware.
 *
 * devino -	Device Interrupt Number. An unsigned integer representing
 *		an interrupt within a specific device.
 *
 * sysino -	System Interrupt Number. A 64-bit unsigned integer
 *		representing a unique interrupt within a "system".
 *
 * intr_state - A flag representing the interrupt state for a
 *		a given sysino. The state values are defined as:
 *
 *		INTR_IDLE		0
 *		INTR_RECEIVED		1
 *		INTR_DELIVERED		2
 *
 * intr_valid_state - A flag representing the 'valid' state for
 *		a given sysino. The state values are defined as:
 *
 *		INTR_NOTVALID		0  sysino not enabled
 *		INTR_VALID		1  sysino enabled
 */

typedef uint64_t devhandle_t;

typedef uint32_t cpuid_t;
typedef uint32_t devino_t;
typedef	uint64_t sysino_t;

typedef enum intr_state {
	INTR_IDLE_STATE 	= (uint32_t)0,
	INTR_RECEIVED_STATE	= (uint32_t)1,
	INTR_DELIVERED_STATE	= (uint32_t)2
} intr_state_t;

typedef enum intr_valid_state {
	INTR_NOTVALID		= (uint32_t)0,
	INTR_VALID		= (uint32_t)1
} intr_valid_state_t;

/*
 * PCI IO Data Definitions
 *
 * tsbnum -	TSB Number. Identifies which io-tsb is used.
 *		For this version of the spec, tsbnum must be zero.
 *
 * tsbindex -	TSB Index. Identifies which entry in the tsb is
 *		is used. The first entry is zero.
 *
 * tsbid -	A 64-bit aligned data structure which contains
 *		a tsbnum and a tsbindex.
 *		bits 63:32 contain the tsbnum.
 *		bits 31:00 contain the tsbindex.
 *
 * io_attributes - IO Attributes for iommu mappings.
 *		Attributes for iommu mappings. One or more of the
 *		following attribute bits stored in a 64-bit unsigned int.
 *
 *	6				    3				      0
 *	3				    1				      0
 *	00000000 00000000 00000000 00000000 BBBBBBBB DDDDDFFF 00000000 00PP0LWR
 *
 *		R: DMA data is transferred from main memory to device.
 *		W: DMA data is transferred from device to main memory.
 *		L: Requested DMA transaction can be relaxed ordered within RC.
 *		P: Value of PCI Express and PCI-X phantom function
 *		   configuration. Its encoding is identical to the
 *		   "Phantom Function Supported" field of the
 *		   "Device Capabilities Register (offset 0x4)"
 *		   in the "PCI Express Capability Structure".
 *		   The structure is part of a device's config space.
 *	      BDF: Bus, device and function number of the device
 *		   that is going to issue DMA transactions.
 *		   The BDF values are used to guarantee the mapping
 *		   only be accessed by the specified device.
 *		   If the BDF is set to all 0, RID based protection
 *		   will be turned off.
 *
 *		Relaxed Ordering (L) is advisory. Not all hardware implements a
 *		relaxed ordering attribute. If L attribute is not implemented in
 *		hardware, the implementation is permitted to ignore the L bit.
 *
 *		Bits 3, 15:6 and 63:32 are unused and must be set to zero for
 *		this version of the specification.
 *
 *		Note: For compatibility with future versions of this
 *		specification, the caller must set bits 3, 15:6 and 63:32 to
 *		zero. The implementation shall ignore these bits.
 *
 * r_addr -	64-bit Real Address.
 *
 * io_addr -	64-bit IO Address.
 *
 * pci_device - PCI device address. A PCI device address
 *		identifies a specific device on a specific PCI
 *		bus segment. A PCI device address is a 32-bit unsigned
 *		integer with the following format:
 *
 *			00000000.bbbbbbbb.dddddfff.00000000
 *
 *		Where:
 *
 *			bbbbbbbb is the 8-bit pci bus number
 *			ddddd is the 5-bit pci device number
 *			fff is the 3-bit pci function number
 *
 *			00000000 is the 8-bit literal zero.
 *
 * pci_config_offset -	PCI Configuration Space offset.
 *
 *		For conventional PCI, an unsigned integer in the range
 *		0 .. 255 representing the offset of the field in pci config
 *		space.
 *
 *		For PCI implementations with extended configuration space,
 *		an unsigned integer in the range 0 .. 4095, representing
 *		the offset of the field in configuration space. Conventional
 *		PCI config space is offset 0 .. 255. Extended config space
 *		is offset 256 .. 4095
 *
 *		Note: For pci config space accesses, the offset must be 'size'
 *		aligned.
 *
 * error_flag -	Error flag
 *
 *		A return value specifies if the action succeeded
 *		or failed, where:
 *
 *			0 - No error occurred while performing the service.
 *			non-zero - Error occurred while performing the service.
 *
 * io_sync_direction - "direction" definition for pci_dma_sync
 *
 *		A value specifying the direction for a memory/io sync
 *		operation, The direction value is a flag, one or both
 *		directions may be specified by the caller.
 *
 *			0x01 - For device (device read from memory)
 *			0x02 - For cpu (device write to memory)
 *
 * io_page_list - A list of io_page_addresses. An io_page_address
 *		is an r_addr.
 *
 * io_page_list_p - A pointer to an io_page_list.
 */
typedef uint32_t tsbnum_t;
typedef uint32_t tsbindex_t;
typedef uint64_t tsbid_t;
typedef uint64_t r_addr_t;
typedef uint64_t io_addr_t;
typedef uint64_t io_page_list_t;
typedef uint32_t pages_t;
typedef uint32_t error_flag_t;

typedef uint32_t pci_config_offset_t;
typedef uint64_t pci_device_t;

#define	PCI_TSB_INDEX		0
#define	PCI_TSB_INDEX_MASK	0xFFFFFFFF
#define	PCI_TSB_NUM		32
#define	PCI_TSB_NUM_MASK	0xFFFFFFFF

#define	PCI_TSBID(tsbnum, tsbindex) \
	((((tsbid_t)tsbnum & PCI_TSB_NUM_MASK) << PCI_TSB_NUM) | \
	(((tsbid_t)tsbindex & PCI_TSB_INDEX_MASK) << PCI_TSB_INDEX))

#define	PCI_TSBID_TO_TSBNUM(tsbid) \
	((tsbid >> PCI_TSB_NUM) & PCI_TSB_NUM_MASK)

#define	PCI_TSBID_TO_TSBINDEX(tsbid) \
	((tsbid >> PCI_TSB_INDEX) & PCI_TSB_INDEX_MASK)

typedef	uint64_t io_attributes_t;

#define	PCI_MAP_ATTR_READ	0x1ull
#define	PCI_MAP_ATTR_WRITE	0x2ull
#define	PCI_MAP_ATTR_RO		0x4ull

#define	PCI_MAP_ATTR_PHFUN	4
#define	PCI_MAP_ATTR_BDF	16

#define	PCI_MAP_ATTR_PHFUN_MASK	0x30
#define	PCI_MAP_ATTR_BDF_MASK	0xffff0000

#define	PX_ADD_ATTR_EXTNS(attr, bdf) \
	(attr | (PCIE_CHECK_VALID_BDF(bdf) ? (bdf << PCI_MAP_ATTR_BDF) : 0))

typedef enum io_sync_direction {
	IO_SYNC_DEVICE		= (uint32_t)0x01,
	IO_SYNC_CPU		= (uint32_t)0x02
} io_sync_direction_t;

/*
 *	MSI Definitions
 *
 *	MSI - Message Signaled Interrupt
 *
 *	  Message Signaled Interrupt as defined in the PCI Local Bus
 *	  Specification and the PCI Express Base Specification.
 *	  A device signals an interrupt via MSI using a posted
 *	  write cycle to an address specified by system software
 *	  using a data value specified by system software.
 *	  The MSI capability data structure contains fields for
 *	  the PCI address and data values the device uses when
 *	  sending an MSI message on the bus. MSI-X is an extended
 *	  form of MSI, but uses the same mechanism for signaling
 *	  the interrupt as MSI. For the purposes of this document,
 *	  the term "MSI" refers to MSI or MSI-X.
 *
 *	  Root complexes that support MSI define an address range
 *	  and set of data values that can be used to signal MSIs.
 *
 *	  SUN4V/pci requirements for MSI:
 *
 *		The root complex defines two address ranges. One in
 *		the 32-bit pci memory space and one in the 64-bit
 *		pci memory address space used as the target of a posted
 *		write to signal an MSI.
 *
 *		The root complex treats any write to these address
 *		ranges as signaling an MSI, however, only the data
 *		value used in the posted write signals the MSI.
 *
 *
 *	MSI EQ - MSI Event Queue
 *
 *	  The MSI Event Queue is a page-aligned main memory data
 *	  structure used to store MSI data records.
 *
 *	  Each root port supports several MSI EQs, and each EQ has a
 *	  system interrupt associated with it, and can be targeted
 *	  (individually) to any cpu. The number of MSI EQs supported
 *	  by a root complex is described by a property defined in [3].
 *	  Each MSI EQ must be large enough to contain all possible MSI
 *	  data records generated by any one PCI root port. The number
 *	  of entries in each MSI EQ is described by a property defined
 *	  in [3].
 *
 *	  Each MSI EQ is compliant with the definition of interrupt
 *	  queues described in [5], however, instead of accessing the
 *	  queue head/tail registers via ASI-based registers, an API
 *	  is provided to access the head/tail registers.
 *
 *	  The SUN4V/pci compliant root complex has the ability to
 *	  generate a system interrupt when the MSI EQ is non-empty.
 *
 *	MSI/Message/INTx Data Record format
 *
 *	  Each data record consists of 64 bytes of data, aligned
 *	  on a 64-byte boundary.
 *
 *	  The data record is defined as follows:
 *
 *
 *	6666555555555544444444443333333333222222222211111111110000000000
 *	3210987654321098765432109876543210987654321098765432109876543210
 *
 *	0x00:	VVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVxxxxxxxxxxxxxxxxxxxxxxxxTTTTTTTT
 *	0x08:	IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII
 *	0x10:	xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
 *	0x18:	SSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSS
 *	0x20:	xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxRRRRRRRRRRRRRRRR
 *	0x28:	AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
 *	0x30:	DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD
 *	0x38:	xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
 *
 *	Where,
 *
 *	  xx..xx are unused bits and must be ignored by sw.
 *
 *	  VV..VV is the version number of this data record
 *
 *		For this release of the spec, the version number
 *		field must be zero.
 *
 *	  TTTTTTTT is the data record type:
 *
 *		Upper 4 bits are reserved, and must be zero
 *
 *		0000 - Not an MSI data record - reserved for sw use.
 *		0001 - MSG
 *		0010 - MSI32
 *		0011 - MSI64
 *		0010 - Reserved
 *		...
 *		0111 - Reserved
 *		1000 - INTx
 *		1001 - Reserved
 *		...
 *		1110 - Reserved
 *		1111 - Not an MSI data record - reserved for sw use.
 *
 *		All other encodings are reserved.
 *
 *	  II..II is the sysino for INTx (sw defined value),
 *		otherwise zero.
 *
 *	  SS..SS is the message timestamp if available.
 *		If supported by the implementation, a non-zero
 *		value in this field is a copy of the %stick register
 *		at the time the message is created.
 *
 *		If unsupported, this field will contain zero.
 *
 *	  RR..RR is the requester ID of the device that initiated the MSI/MSG
 *	  and has the following format:
 *
 *		bbbbbbbb.dddddfff
 *
 *		Where bb..bb is the bus number,
 *		dd..dd is the device number
 *		and fff is the function number.
 *
 *		Note that for PCI devices or any message where
 *		the requester is unknown, this may be zero,
 *		or the device-id of an intermediate bridge.
 *
 *		For intx messages, this field should be ignored.
 *
 *	  AA..AA is the MSI address. For MSI32, the upper 32-bits must be zero.
 *	  (for data record type MSG or INTx, this field is ignored)
 *
 *	  DD..DD is the MSI/MSG data or INTx number
 *
 *		For MSI-X, bits 31..0 contain the data from the MSI packet
 *		which is the msi-number. bits 63..32 shall be zero.
 *
 *		For MSI, bits 15..0 contain the data from the MSI message
 *		which is the msi-number. bits 63..16 shall be zero
 *
 *		For MSG data, the message code and message routing code
 *		are encoded as follows:
 *
 *		63:32 - 0000.0000.0000.0000.0000.0000.GGGG.GGGG
 *		32:00 - 0000.0000.0000.0CCC.0000.0000.MMMM.MMMM
 *
 *			Where,
 *
 *			GG..GG is the target-id of the message in the
 *			following form:
 *
 *				bbbbbbbb.dddddfff
 *
 *				where bb..bb is the target bus number.
 *				ddddd is the target deviceid
 *				fff is the target function number.
 *
 *			CCC is the message routing code as defined by [4]
 *
 *			MM..MM is the message code as defined by [4]
 *
 *		For INTx data, bits 63:2 must be zero and
 *		the low order 2 bits are defined as follows:
 *
 *			00 - INTA
 *			01 - INTB
 *			10 - INTC
 *			11 - INTD
 *
 *	cpuid - A unique opaque value which represents a target cpu.
 *
 *	devhandle - Device handle. The device handle uniquely identifies a
 *	  SUN4V device. It consists of the the lower 28-bits of the hi-cell
 *	  of the first entry of the SUN4V device's "reg" property as defined
 *	  by the SUN4V Bus Binding to Open Firmware.
 *
 *	msinum	- A value defining which MSI is being used.
 *
 *	msiqhead - The index value of the current head index for a given
 *	  MSI-EQ.
 *
 *	msiqtail - The index value of the current tail index for a given
 *	  MSI-EQ.
 *
 *	msitype - Type specifier for MSI32 or MSI64
 *		0 - type is MSI32
 *		1 - type is MSI64
 *
 *	msiqid	- A number from 0 .. 'number of MSI-EQs - 1', defining
 *	  which MSI EQ within the device is being used.
 *
 *	msiqstate - An unsigned integer containing one of the
 *	  following values:
 *
 *		PCI_MSIQSTATE_IDLE		0	# idle (non-error) state
 *		PCI_MSIQSTATE_ERROR		1	# error state
 *
 *	msiqvalid - An unsigned integer containing one of the
 *		following values:
 *
 *		PCI_MSIQ_INVALID		0	# disabled/invalid
 *		PCI_MSIQ_VALID			1	# enabled/valid
 *
 *	msistate - An unsigned integer containing one of the following
 *	  values:
 *
 *		PCI_MSISTATE_IDLE		0	# idle/not enabled
 *		PCI_MSISTATE_DELIVERED		1	# MSI Delivered
 *
 *	msivalid - An unsigned integer containing one of the
 *		following values:
 *
 *		PCI_MSI_INVALID			0	# disabled/invalid
 *		PCI_MSI_VALID			1	# enabled/valid
 *
 *	msgtype	- A value defining which MSG type is being used. An unsigned
 *		integer containing one of the following values:
 *		(as per PCIe spec 1.0a)
 *
 *		PCIE_PME_MSG			0x18	PME message
 *		PCIE_PME_ACK_MSG		0x1b	PME ACK message
 *		PCIE_CORR_MSG			0x30	Correctable message
 *		PCIE_NONFATAL_MSG		0x31	Non fatal message
 *		PCIE_FATAL_MSG			0x33	Fatal message
 */

typedef uint32_t msinum_t;
typedef uint32_t msiqid_t;
typedef uint32_t msgcode_t;
typedef	uint64_t msiqhead_t;
typedef	uint64_t msiqtail_t;

/* MSIQ state */
typedef enum pci_msiq_state {
	PCI_MSIQ_STATE_IDLE 	= (uint32_t)0,	/* idle (non-error) state */
	PCI_MSIQ_STATE_ERROR 	= (uint32_t)1	/* error state */
} pci_msiq_state_t;

/* MSIQ valid */
typedef enum pci_msiq_valid_state {
	PCI_MSIQ_INVALID	= (uint32_t)0,	/* disabled/invalid */
	PCI_MSIQ_VALID		= (uint32_t)1	/* enabled/valid */
} pci_msiq_valid_state_t;

/* MSIQ Record data structure */
typedef struct msiq_rec {
	uint64_t	msiq_rec_version : 32,	/* DW 0 - 63:32 */
			msiq_rec_rsvd0 : 24,	/* DW 0 - 31:09 */
			msiq_rec_type : 8;	/* DW 0 - 07:00 */
	uint64_t	msiq_rec_intx;		/* DW 1 */
	uint64_t	msiq_rec_rsvd1;		/* DW 2 */
	uint64_t	msiq_rec_timestamp;	/* DW 3 */
	uint64_t	msiq_rec_rsvd2 : 48,	/* DW 4 - 63:16 */
			msiq_rec_rid : 16;	/* DW 4 - 15:00 */
	uint64_t	msiq_rec_msi_addr;	/* DW 5 - 63:00 */
	union {
		struct {
			uint64_t	msix_rsvd0 : 32, /* DW 6 - 63:32 */
					msix_data : 32;	/* DW 6 - 31:00 */
		} msix;
		struct {
			uint64_t	msi_rsvd0 : 48,	/* DW 6 - 63:16 */
					msi_data: 16;	/* DW 6 - 15:00 */
		} msi;
		struct {
			uint64_t	msg_rsvd0: 24,	/* DW 6 - 63:40 */
					msg_targ: 8,	/* DW 6 - 39:32 */
					msg_rsvd1: 13,	/* DW 6 - 31:19 */
					msg_route: 3,	/* DW 6 - 18:16 */
					msg_rsvd2: 8,	/* DW 6 - 15:08 */
					msg_code: 8;	/* DW 6 - 07:00 */
		} msg;
	} msiq_rec_data;
	uint64_t	msiq_rec_rsvd3;			/* DW 7 */
} msiq_rec_t;

/* MSIQ Record type */
typedef enum msiq_rec_type {
	MSG_REC			= (uint32_t)1,	/* PCIe message record */
	MSI32_REC		= (uint32_t)2,	/* MSI32 record */
	MSI64_REC		= (uint32_t)3,	/* MSI64 record */
	INTX_REC		= (uint32_t)8	/* INTx record */
} msiq_rec_type_t;

/* MSIQ Record type */
typedef enum msi_type {
	MSI32_TYPE		= (uint32_t)0,	/* MSI32 type */
	MSI64_TYPE		= (uint32_t)1	/* MSI64 type */
} msi_type_t;

/* MSI state */
typedef enum pci_msi_state {
	PCI_MSI_STATE_IDLE	= (uint32_t)0,	/* idle/not enabled */
	PCI_MSI_STATE_DELIVERED	= (uint32_t)1	/* MSI delivered */
} pci_msi_state_t;

/* MSI valid */
typedef enum pci_msi_valid_state {
	PCI_MSI_INVALID		= (uint32_t)0,  /* disabled/invalid */
	PCI_MSI_VALID		= (uint32_t)1   /* enabled/valid */
} pci_msi_valid_state_t;

/* MSG valid */
typedef enum pcie_msg_valid_state {
	PCIE_MSG_INVALID	= (uint32_t)0,  /* disabled/invalid */
	PCIE_MSG_VALID		= (uint32_t)1   /* enabled/valid */
} pcie_msg_valid_state_t;

/* PCIe MSG types */
typedef enum pcie_msg_type {
	PCIE_PME_MSG		= (uint64_t)0x18, /* PME message */
	PCIE_PME_ACK_MSG	= (uint64_t)0x1b, /* PME ACK message */
	PCIE_CORR_MSG		= (uint64_t)0x30, /* Correctable message */
	PCIE_NONFATAL_MSG	= (uint64_t)0x31, /* Non fatal message */
	PCIE_FATAL_MSG		= (uint64_t)0x33  /* Fatal message */
} pcie_msg_type_t;

#endif /* _ASM */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_PX_IOAPI_H */
