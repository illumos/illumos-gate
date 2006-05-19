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
 * Copyright (c) 1997,1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _SYS_DKTP_CDTYPES_H
#define	_SYS_DKTP_CDTYPES_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

struct cd_data {
	opaque_t	cd_tgpt_objp;
	ulong_t		cd_options;
};

/* cd_options values */
#define	SCCD_OPT_CDB10			0x01
#define	SCCD_OPT_PLAYMSF_BCD		0x02
#define	SCCD_OPT_READ_SUBCHANNEL_BCD	0x04
#define	SCCD_OPT_READCD			0x08

#define	TGPTOBJP(X) ((X)->cd_tgpt_objp)

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_DKTP_CDTYPES_H */
