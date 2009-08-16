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

#ifndef _SATA_BLACKLIST_H
#define	_SATA_BLACKLIST_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * SATA port multiplier blacklist
 *
 * The number of the device ports is indicated by GSCR2[3:0]. These port
 * multipliers got faulty values in GSCR2 (w/ pseudo port) by vendor
 * configuration.
 *
 * Following is a list of some black-listed port multipliers with the actual
 * number of device ports.
 */
struct sata_pmult_bl {
	uint32_t	bl_gscr0;
	uint32_t	bl_gscr1;
	uint32_t	bl_gscr2;
	uint32_t	bl_flags;
};

typedef struct sata_pmult_bl sata_pmult_bl_t;

sata_pmult_bl_t sata_pmult_blacklist[] = {
	{0x37261095, 0x0, 0x6, 0x5}, /* Silicon Image 3726, 5 ports. */
	{0x47261095, 0x0, 0x7, 0x5}, /* Silicon Image 4726, 5 ports. */
	{0x47231095, 0x0, 0x4, 0x2}, /* Silicon Image 4723, 2 ports. */
	NULL
};


#ifdef	__cplusplus
}
#endif

#endif /* _SATA_BLACKLIST_H */
