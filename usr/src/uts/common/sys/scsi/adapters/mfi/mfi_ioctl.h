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
 * Copyright 2024 Racktop Systems, Inc.
 */

#ifndef	_MFI_IOCTL_H
#define	_MFI_IOCTL_H

#include <sys/cred.h>
#include <sys/file.h>
#include <sys/types.h>
#include <sys/errno.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

#include <sys/scsi/adapters/mfi/mfi.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Definitions for the MFI ioctl interface as used by lmrc(4D) and mr_sas(4D),
 * although the latter has as of yet still its own private definitions.
 * This interface is used by closed-source utilities like storcli and thus
 * must not be changed.
 */
#define	MFI_IOCTL_DRIVER			0x12341234
#define	MFI_IOCTL_FIRMWARE			0x12345678
#define	MFI_IOCTL_AEN				0x87654321

#define	MFI_DRIVER_IOCTL_COMMON			0xF0010000
#define	MFI_DRIVER_IOCTL_DRIVER_VERSION		0xF0010100
#define	MFI_DRIVER_IOCTL_PCI_INFORMATION	0xF0010200
#define	MFI_DRIVER_IOCTL_MRRAID_STATISTICS	0xF0010300

#define	MFI_IOC_SENSE_LEN	32

#pragma pack(1)

struct mfi_drv_ver {
	uint8_t			dv_signature[12];
	uint8_t			dv_os_name[16];
	uint8_t			dv_os_ver[12];
	uint8_t			dv_drv_name[20];
	uint8_t			dv_drv_ver[32];
	uint8_t			dv_drv_rel_date[20];
};

struct mfi_pci_info {
	uint32_t		pi_bus;
	uint8_t			pi_dev;
	uint8_t			pi_func;
	uint8_t			pi_intr;
	uint8_t			pi_rsvd;
	uint8_t			pi_header[0x40];
	uint8_t			pi_cap[8];
	uint8_t			pi_rsvd2[32];
};

struct mfi_ioctl {
	uint16_t		ioc_version;
	uint16_t		ioc_controller_id;
	uint8_t			ioc_signature[8];
	uint32_t		ioc_reserved_1;
	uint32_t		ioc_control_code;
	uint32_t		ioc_reserved_2[2];
	mfi_frame_t		ioc_frame;
	mfi_sgl_t		ioc_sgl;
	uint8_t			ioc_sense[MFI_IOC_SENSE_LEN];
	uint8_t			ioc_data[0];
};

#pragma pack(0)


#ifdef __cplusplus
}
#endif

#endif	/* _MFI_IOCTL_H */
