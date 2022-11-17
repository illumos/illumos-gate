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
 * Copyright 2022 Oxide Computer Company
 */

#ifndef _USMN_H
#define	_USMN_H

/*
 * Private ioctls for interfacing with the usmn driver.
 */

#ifdef __cplusplus
extern "C" {
#endif

#define	USMN_IOCTL	(('u' << 24) | ('s' << 16) | ('m' << 8))

#define	USMN_READ	(USMN_IOCTL | 0x01)
#define	USMN_WRITE	(USMN_IOCTL | 0x02)

typedef struct usmn_reg {
	uint32_t usr_addr;
	uint32_t usr_data;
	uint32_t usr_size;
} usmn_reg_t;

#ifdef __cplusplus
}
#endif

#endif /* _USMN_H */
