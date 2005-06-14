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
 * Copyright (c) 1986-1996, by Sun Microsystems, Inc.
 * All Rights Reserved.
 */

#ifndef	_SYS_IDPROM_H
#define	_SYS_IDPROM_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#ifndef _ASM
/*
 * Structure declaration for ID prom in CPU and Ethernet boards
 */
typedef struct idprom {
	uint8_t	id_format;	/* format identifier */
	/*
	 * The following fields are valid only in format IDFORM_1.
	 */
	uint8_t	id_machine;	/* machine type */
	uint8_t	id_ether[6];	/* ethernet address */
	int32_t	id_date;	/* date of manufacture */
	uint32_t id_serial:24;	/* serial number */
	uint8_t	id_xsum;	/* xor checksum */
	uint8_t	id_undef[16];	/* undefined */
} idprom_t;
#endif	/* _ASM */

#define	IDFORM_1	1	/* Format number for first ID proms */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_IDPROM_H */
