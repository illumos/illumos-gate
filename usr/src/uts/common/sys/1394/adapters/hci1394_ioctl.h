/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright (c) 1999-2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_SYS_1394_ADAPTERS_HCI1394_IOCTL_H
#define	_SYS_1394_ADAPTERS_HCI1394_IOCTL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * hci1394_ioctl.h
 *   Test ioctl's to support test/debug of the 1394 HW. hci1394_ioctl_enum_t is
 *   passed in cmd and a pointer to the appropriate structure (i.e.
 *   hci1394_ioctl_wrreg_t) is passed in arg.
 */

#ifdef __cplusplus
extern "C" {
#endif


/*
 * write_reg   - write OpenHCI register
 * read_reg    - read OpenHCI register
 * write_vreg  - write OpenHCI Vendor Specific register
 * read_vreg   - read OpenHCI Vendor Specific register
 * reset_bus   - reset the 1394 bus
 * selfid_cnt  - return the number of times we saw the selfid complete
 *		 interrupt signifying a bus reset has completed.  This does not
 *		 have to match the bus generation and probably won't.
 * busgen_cnt  - return the current bus generation
 * read_selfid - read selfid buffer
 * write_phy   - write PHY register
 * read_phy    - read PHY register
 * hba_info    - HBA vendor information
 */
#define	HCI11394_IOCTL		('f' << 8)
typedef enum {
	HCI1394_IOCTL_WRITE_REG = HCI11394_IOCTL | 0x00,
	HCI1394_IOCTL_READ_REG = HCI11394_IOCTL | 0x01,
	HCI1394_IOCTL_WRITE_VREG = HCI11394_IOCTL | 0x02,
	HCI1394_IOCTL_READ_VREG = HCI11394_IOCTL | 0x03,
	HCI1394_IOCTL_RESET_BUS = HCI11394_IOCTL | 0x04,
	HCI1394_IOCTL_SELFID_CNT = HCI11394_IOCTL | 0x05,
	HCI1394_IOCTL_BUSGEN_CNT = HCI11394_IOCTL | 0x06,
	HCI1394_IOCTL_READ_SELFID = HCI11394_IOCTL | 0x07,
	HCI1394_IOCTL_WRITE_PHY = HCI11394_IOCTL | 0x08,
	HCI1394_IOCTL_READ_PHY = HCI11394_IOCTL | 0x09,
	HCI1394_IOCTL_HBA_INFO = HCI11394_IOCTL | 0x0A
} hci1394_ioctl_enum_t;


/*
 * HCI1394_IOCTL_WRITE_REG
 *    Write OHCI register. addr is an offset into the OpenHCI register map.
 *    (i.e. addr = 0 would write to the Version Register). addr must be 32-bit
 *    aligned (i.e. 0, 4, 8, C, 10). data is the 32-bit word to write into the
 *    OpenHCI register.
 *
 *    NOTE: Writing OpenHCI registers can cause the hardware and/or SW to
 *    misbehave. Extreme care should be used when using this call.
 */
typedef struct hci1394_ioctl_wrreg_s {
	uint_t		addr;
	uint32_t	data;
} hci1394_ioctl_wrreg_t;


/*
 * HCI1394_IOCTL_READ_REG
 *    Read OHCI register. addr is an offset into the OpenHCI register map.
 *    (i.e. addr = 0 would write to the Version Register). addr must be 32-bit
 *    aligned (i.e. 0, 4, 8, C, 10). When the ioctl returns successfully, data
 *    will contain the 32-bit word read from the OHCI register.
 */
typedef struct hci1394_ioctl_rdreg_s {
	uint_t		addr;
	uint32_t	data;
} hci1394_ioctl_rdreg_t;


/*
 * HCI1394_IOCTL_WRITE_VREG
 *    Write Vendor Specific OHCI register. addr is an offset into the Vendor
 *    Specific OpenHCI register map.  (i.e. addr = 0 would write to the first
 *    Vendor Specific register. addr must be 32-bit aligned (i.e. 0, 4, 8, C,
 *    10). data is the 32-bit word to write into the Vendor Specific OpenHCI
 *    register. regset defines which vendor specific register set to write to.
 *    There will usually be one vendor specific register set so this will
 *    usually be set to 0.
 *
 *    NOTE: Writing Vendor Specific OpenHCI registers can cause the hardware
 *	    and/or SW to misbehave. Extreme care should be used when using this
 *	    call.
 */
typedef struct hci1394_ioctl_wrvreg_s {
	uint_t		regset;
	uint_t		addr;
	uint32_t	data;
} hci1394_ioctl_wrvreg_t;


/*
 * HCI1394_IOCTL_READ_VREG
 *    Read Vendor specific OHCI register. addr is an offset into the Vendor
 *    Specific OpenHCI register space. (i.e. addr = 0 is the first Vendor
 *    Specific register). addr must be 32-bit aligned (i.e. 0, 4, 8, C, 10).
 *    When the ioctl returns successfully, data will contain the 32-bit word
 *    read from the Vendor Specific OHCI register. regset defines which vendor
 *    specific register set to read from. There will usually be one vendor
 *    specific register set so this will usually be set to 0.
 */
typedef struct hci1394_ioctl_rdvreg_s {
	uint_t		regset;
	uint_t		addr;
	uint32_t	data;
} hci1394_ioctl_rdvreg_t;


/* HCI1394_IOCTL_RESET_BUS has no parameters */


/*
 * HCI1394_IOCTL_SELFID_CNT
 *    When the ioctl returns successfully, count will contain the number of
 *    times the nexus driver has seen and responded to a selfid_complete
 *    interrupt.  This interrupt signifies that the bus reset has completed
 *    and the hardware based bus enumeration has completed.  This number will
 *    most likely not be the same as the bus generation.  Everytime this
 *    increments, the bus generation count should increment by at least one.
 *
 *    NOTE: The current implementation of the nexus driver uses a uint_t for
 *	    selfid_cnt.
 */
typedef struct hci1394_ioctl_selfid_cnt_s {
	uint_t		count;
} hci1394_ioctl_selfid_cnt_t;


/*
 * HCI1394_IOCTL_BUSGEN_CNT
 *    When the ioctl returns successfully, count will contain the current 1394
 *    bus generation count.
 *
 *    NOTE: The current implementation of the nexus driver uses the OpenHCI
 *	    generation count which is an 8 bit value. Therefore, this count will
 *	    wrap over at 0xFF.
 */
typedef struct hci1394_ioctl_busgen_cnt_s {
	uint_t		count;
} hci1394_ioctl_busgen_cnt_t;


/*
 * HCI1394_IOCTL_READ_SELFID
 *    Copies the contents of the selfid buffer into a buffer pointed to by buf.
 *    Count is the number of 32-bit words to copy into buf.  The maximum size
 *    of the selfid buffer is 1024 32-bit words. The very first word is the
 *    OpenHCI selfid header.
 */
typedef struct hci1394_ioctl_read_selfid_s {
	uint32_t	*buf;
	uint_t		count;
} hci1394_ioctl_read_selfid_t;


/*
 * HCI1394_IOCTL_WRPHY
 *    Write PHY register. addr is an offset into the phy register space.
 *    (i.e. addr = 0 is the first phy register). addr is byte aligned
 *    (i.e. 0, 1, 2, 3, 4). data should contain the 8-bit value to write to the
 *    PHY register. The data should be stored as follows <0x000000dd> where dd
 *    is the byte written.
 *
 *    NOTE: Phy register 0 cannot be read or written.
 *
 *    NOTE: Writing PHY registers can cause the hardware and/or SW to misbehave.
 *	    Extreme care should be used when using this call.
 */
typedef struct hci1394_ioctl_wrphy_s {
	uint_t	addr;
	uint_t	data;
} hci1394_ioctl_wrphy_t;


/*
 * HCI1394_IOCTL_RDPHY
 *    Read PHY register. addr is an offset into the phy register space.
 *    (i.e. addr = 0 is the first phy register). addr is byte aligned
 *    (i.e. 0, 1, 2, 3, 4). When the ioctl returns successfully, data will
 *    contain the 8-bit data read from the PHY register. The data will be stored
 *    as follows <0x000000dd> where dd is the byte read.
 *
 *    NOTE: Phy register 0 cannot be read or written.
 */
typedef struct hci1394_ioctl_rdphy_s {
	uint_t	addr;
	uint_t	data;
} hci1394_ioctl_rdphy_t;


/*
 * HCI1394_IOCTL_HBA_INFO
 *    HBA Vendor Information
 *
 * Vendor Specific Info
 *    pci_vendor_id - VendorID from PCI config space (0x0-0x1)
 *    pci_device_id - DeviceID from PCI config space (0x2-0x3)
 *    pci_revision_id - RevisionID from PCI config space (0x8)
 *    ohci_version - 1394 OpenHCI Version Register (0x0)
 *    ohci_vendor_id - 1394 OpenHCI Vendor ID Register (0x40)
 *    ohci_vregset_cnt - Number of vendor specific register maps that have been
 *			 mapped by the driver. The driver will only map in
 *			 vendor specific registers for adapters it knows about.
 */
typedef struct hci1394_ioctl_hbainfo_s {
	uint_t		pci_vendor_id;
	uint_t		pci_device_id;
	uint_t		pci_revision_id;
	uint32_t	ohci_version;
	uint32_t	ohci_vendor_id;
	uint_t		ohci_vregset_cnt;
} hci1394_ioctl_hbainfo_t;


#ifdef __cplusplus
}
#endif

#endif	/* _SYS_1394_ADAPTERS_HCI1394_IOCTL_H */
