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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Platform Power Management
 */

#ifndef	_SYS_XCALPPM_VAR_H
#define	_SYS_XCALPPM_VAR_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * External function declarations
 */
extern int	ppm_init(struct modlinkage *, size_t, char *);
extern int	ppm_open(dev_t *, int, int, cred_t *);
extern int	ppm_close(dev_t, int, int, cred_t *);
extern int	ppm_ioctl(dev_t, int, intptr_t, int, cred_t *, int *);
extern int	ppm_getinfo(dev_info_t *, ddi_info_cmd_t, void *, void **);
extern void	spm_change_schizo_speed(int);

/*
 * ppm device flags
 */
#define	XCPPMF_PCIB		0x1
#define	XCPPMF_UPA		0x2

/*
 * Defines used for verification of CPU running at lowest speed.
 */
#define	XCPPM_VCL_TRIES		5
#define	XCPPM_VCL_DELAY		10
#define	XCPPM_VCL_DIVISOR	32

/*
 * driver private data
 */
typedef struct {
	dev_info_t	*dip;		/* ptr to our dev_info node */
	struct xcppmreg	regs;		/* register accessed by ppm */
	struct xcppmhndl hndls;		/* handles */
	kmutex_t	gpio_lock;	/* protects GPIO register */
	kmutex_t	unit_lock;	/* for state, led_tid fields below */
	kmutex_t	creator_lock;	/* held to create ppm_dev_t structs */
	uint_t		state;		/* ppm internal state */
	timeout_id_t	led_tid;	/* timeout id for LED */
} xcppm_unit_t;

/*
 * Flags for the state word of ppm_unit
 */
#define	XCPPM_ST_SUSPENDED	0x00000001	/* DDI_SUSPEND received */

#define	XCPPM_GET8(handle, address)			\
	ddi_get8(handle, (uint8_t *)(address))

#define	XCPPM_SETGET8(handle, address, data)		\
	ddi_put8(handle, (uint8_t *)(address), data);	\
	data = XCPPM_GET8(handle, address)

#define	XCPPM_GET16(handle, address)			\
	ddi_get16(handle, (uint16_t *)(address))

#define	XCPPM_SETGET16(handle, address, data)		\
	ddi_put16(handle, (uint16_t *)(address), data);	\
	data = XCPPM_GET16(handle, address)

#define	XCPPM_GET32(handle, address)			\
	ddi_get32(handle, (uint32_t *)(address))

#define	XCPPM_SETGET32(handle, address, data)		\
	ddi_put32(handle, (uint32_t *)(address), data); \
	data = XCPPM_GET32(handle, address)

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_XCALPPM_VAR_H */
