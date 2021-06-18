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
 * Copyright 2023 Racktop Systems, Inc.
 */
#ifndef _LMRC_IOCTL_H
#define	_LMRC_IOCTL_H

#include <sys/cred.h>
#include <sys/file.h>
#include <sys/types.h>
#include <sys/errno.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

typedef struct lmrc_drv_ver	lmrc_drv_ver_t;
typedef struct lmrc_pci_info	lmrc_pci_info_t;
typedef struct lmrc_ioctl	lmrc_ioctl_t;

#include "lmrc_reg.h"

/*
 * Definitions for the lmrc ioctl interface. This has to be the same as in
 * mr_sas(4D), as the only consumers of this interface are closed-source
 * utilities like storcli which we can't change.
 */
#define	LMRC_IOCTL_DRIVER	0x12341234
#define	LMRC_IOCTL_FIRMWARE	0x12345678
#define	LMRC_IOCTL_AEN		0x87654321

#define	LMRC_DRIVER_IOCTL_COMMON		0xF0010000
#define	LMRC_DRIVER_IOCTL_DRIVER_VERSION	0xF0010100
#define	LMRC_DRIVER_IOCTL_PCI_INFORMATION	0xF0010200
#define	LMRC_DRIVER_IOCTL_MRRAID_STATISTICS	0xF0010300

#define	LMRC_IOC_SENSE_LEN	32

#pragma pack(1)

struct lmrc_drv_ver {
	uint8_t			dv_signature[12];
	uint8_t			dv_os_name[16];
	uint8_t			dv_os_ver[12];
	uint8_t			dv_drv_name[20];
	uint8_t			dv_drv_ver[32];
	uint8_t			dv_drv_rel_date[20];
};

struct lmrc_pci_info {
	uint32_t		pi_bus;
	uint8_t			pi_dev;
	uint8_t			pi_func;
	uint8_t			pi_intr;
	uint8_t			pi_rsvd;
	uint8_t			pi_header[0x40];
	uint8_t			pi_cap[8];
	uint8_t			pi_rsvd2[32];
};

struct lmrc_ioctl {
	uint16_t		ioc_version;
	uint16_t		ioc_controller_id;
	uint8_t			ioc_signature[8];
	uint32_t		ioc_reserved_1;
	uint32_t		ioc_control_code;
	uint32_t		ioc_reserved_2[2];
	lmrc_mfi_frame_t	ioc_frame;
	lmrc_mfi_sgl_t		ioc_sgl;
	uint8_t			ioc_sense[LMRC_IOC_SENSE_LEN];
	uint8_t			ioc_data[0];
};

#pragma pack(0)

int lmrc_ioctl(dev_t, int, intptr_t, int, cred_t *, int *);

#endif /* _LMRC_IOCTL_H */
