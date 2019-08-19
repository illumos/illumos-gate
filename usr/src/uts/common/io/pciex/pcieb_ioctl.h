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
 * Copyright 2019 Joyent, Inc.
 */

#ifndef _IO_PCIE_PCIEB_IOCTL_H
#define	_IO_PCIE_PCIEB_IOCTL_H

/*
 * These are private ioctls for PCIe bridges that are currently consumed by the
 * 'pcieb' command. These should be used until we figure out how best to
 * represent PCIe links in the traditional cfgadm and devctl frameworks.
 */

#include <sys/stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	PCIEB_IOCTL	(('p' << 24) | ('c' << 16) | ('b' << 8))

/*
 * This requests that we retrain the link that the PCIe bridge has to its
 * downstream component.
 */
#define	PCIEB_IOCTL_RETRAIN	(PCIEB_IOCTL | 0x01)

/*
 * Get and set the current target speed for a bridge. The target speed of the
 * bridge will have an impact on the values that end up being used by its
 * downstream components.
 */
#define	PCIEB_IOCTL_GET_TARGET_SPEED	(PCIEB_IOCTL | 0x02)
#define	PCIEB_IOCTL_SET_TARGET_SPEED	(PCIEB_IOCTL | 0x03)

typedef struct pcieb_ioctl_target_speed {
	uint32_t	pits_flags;
	uint32_t	pits_speed;
} pcieb_ioctl_target_speed_t;

#define	PCIEB_FLAGS_ADMIN_SET		0x01

#define	PCIEB_LINK_SPEED_UNKNOWN	0x00
#define	PCIEB_LINK_SPEED_GEN1		0x01
#define	PCIEB_LINK_SPEED_GEN2		0x02
#define	PCIEB_LINK_SPEED_GEN3		0x03
#define	PCIEB_LINK_SPEED_GEN4		0x04

#ifdef __cplusplus
}
#endif

#endif /* _IO_PCIE_PCIEB_IOCTL_H */
