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
 * Copyright 1999-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SEEPROM_IMPL_H
#define	_SEEPROM_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#define	AT24C64_ADDRSIZE	2
#define	AT24C64_MEMSIZE		8192
#define	AT24C64_PAGESIZE	32
#define	AT24C64_PAGEMASK	(AT24C64_PAGESIZE - 1)

#define	AT34C02_ADDRSIZE	1
#define	AT34C02_MEMSIZE		256
#define	AT34C02_PAGESIZE	16
#define	AT34C02_PAGEMASK	(AT34C02_PAGESIZE - 1)

#define	SEEPROM_BUSY	0x01

#define	SEEPROM_NODE_TYPE	"ddi_i2c:seeprom"

struct seepromunit {
	kmutex_t	seeprom_mutex;
	kcondvar_t	seeprom_cv;
	dev_info_t	*seeprom_dip;
	int		seeprom_flags;
	int		seeprom_oflag;
	int		seeprom_memsize;
	int		seeprom_addrsize;
	int		seeprom_pagesize;
	int		seeprom_pagemask;
	i2c_client_hdl_t seeprom_hdl;
	char		seeprom_name[20];
};

#ifdef	__cplusplus
}
#endif

#endif	/* _SEEPROM_IMPL_H */
