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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SATA_CFGADM_H
#define	_SATA_CFGADM_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/* SATA cfgadm plugin interface definitions */

/*
 * Sub-commands of DEVCTL_AP_CONTROL.
 */
typedef enum {
	SATA_CFGA_GET_AP_TYPE = 1,
	SATA_CFGA_GET_MODEL_INFO,
	SATA_CFGA_GET_REVFIRMWARE_INFO,
	SATA_CFGA_GET_SERIALNUMBER_INFO,
	SATA_CFGA_RESET_PORT,
	SATA_CFGA_RESET_DEVICE,
	SATA_CFGA_RESET_ALL,
	SATA_CFGA_PORT_DEACTIVATE,
	SATA_CFGA_PORT_ACTIVATE,
	SATA_CFGA_PORT_SELF_TEST,
	SATA_CFGA_GET_DEVICE_PATH
} sata_cfga_apctl_t;

/* SATA cfgadm plugin interface implementation definitions */

typedef struct sata_ioctl_data {
	uint_t		cmd;			/* one of the above commands */
	uint_t		port;			/* port */
	uint_t		get_size;		/* get size/data flag */
	caddr_t		buf;			/* data buffer */
	uint_t		bufsiz;			/* data buffer size */
	uint_t		misc_arg;		/* reserved */
} sata_ioctl_data_t;


/* For 32-bit app/64-bit kernel */
typedef struct sata_ioctl_data_32 {
	uint32_t	cmd;			/* one of the above commands */
	uint32_t	port;			/* port */
	uint32_t	get_size;		/* get size/data flag */
	caddr32_t	buf;			/* data buffer */
	uint32_t	bufsiz;			/* data buffer size */
	uint32_t	misc_arg;		/* reserved */
} sata_ioctl_data_32_t;

/*
 * Port encoding for ioctl "port" parameter - corresponds to
 * scsi target encoding for sata devices
 */
#define	SATA_CFGA_CPORT_MASK	0x1f
#define	SATA_CFGA_PMPORT_MASK	0xf
#define	SATA_CFGA_PMPORT_SHIFT	0x5
#define	SATA_CFGA_PMPORT_QUAL	0x200

#ifdef	__cplusplus
}
#endif

#endif /* _SATA_CFGADM_H */
