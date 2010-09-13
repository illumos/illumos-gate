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
 * Copyright 2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _ICS951601_IMPL_H
#define	_ICS951601_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/promif.h>
#define	ICS951601_I2C_WRITE_TRANS_SIZE	0x8
#define	ICS951601_I2C_READ_TRANS_SIZE	0x7


#define	ICS951601_CMD_TO_ACTION(x)	((x) & 0xF000)
#define	ICS951601_CMD_TO_CLOCKREG(x)	((0x0F00 & (x)) >> 8)
#define	ICS951601_CMD_TO_CLOCKBIT(x)	((x) & 0x00FF)

/*
 * Defines for debug printing
 */
#define	DPRINTF(print_flag, args)                       \
    if (ics951601_debug & (print_flag)) { prom_printf args; }


#define	ICS951601_BUSYFLAG	0x1
#define	ICS951601_MINORFLAG	0x2
#define	ICS951601_TBUFFLAG	0x4
#define	ICS951601_REGFLAG	0x8

#define	ICS951601_NODE_TYPE	"ddi_i2c:pci_clock_gen"

typedef struct ics951601_unit {
	dev_info_t		*ics951601_dip;
	i2c_transfer_t		*ics951601_transfer;
	i2c_client_hdl_t	ics951601_hdl;
	kmutex_t		ics951601_mutex;
	kcondvar_t		ics951601_cv;
	char			ics951601_name[16];
	uchar_t			ics951601_cpr_state[8];
	uint16_t		ics951601_oflag;
	uint8_t			ics951601_flags;
} ics951601_unit_t;

#ifdef	__cplusplus
}
#endif

#endif /* _ICS951601_IMPL_H */
