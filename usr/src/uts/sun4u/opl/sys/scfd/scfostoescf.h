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
 * All Rights Reserved, Copyright (c) FUJITSU LIMITED 2006
 */

#ifndef	_SCFOSTOESCF_H
#define	_SCFOSTOESCF_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/* OS to ESCF key */
#define	KEY_ESCF	('E' << 24 | 'S' << 16 | 'C' << 8 | 'F')



/*
 * External function
 */

extern int scf_service_putinfo(uint32_t, uint8_t, uint32_t, uint32_t, void *);
extern int scf_service_getinfo(uint32_t, uint8_t, uint32_t, uint32_t *, void *);
extern int scf_get_dimminfo(uint32_t boardnum, void *buf, uint32_t *bufsz);

#define	SUB_OS_SEND_PRE_FMEMA		0x10
#define	SUB_OS_SEND_CANCEL_FMEMA	0x15
#define	SUB_OS_SEND_COMPLETE_FMEMA	0x43
#define	SUB_OS_RECEIVE_DIMM_INFO	0x45

#ifdef	__cplusplus
}
#endif

#endif	/* _SCFOSTOESCF_H */
