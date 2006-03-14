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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	__CONV_DOT_H
#define	__CONV_DOT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Local include file for conversion library.
 */
#include <conv.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Some format strings differ depending on whether they are used for 32-bit
 * or 64-bit values.
 */
#if	defined(_ELF64)
#define	MSG_GBL_FMT_DEC		MSG_GBL_FMT_DEC_64
#define	MSG_GBL_FMT_DECS	MSG_GBL_FMT_DECS_64
#define	MSG_GBL_FMT_HEX		MSG_GBL_FMT_HEX_64
#define	MSG_GBL_FMT_HEXS	MSG_GBL_FMT_HEXS_64

#define	MSG_SYM_FMT_VAL		MSG_SYM_FMT_VAL_64
#else
#define	MSG_GBL_FMT_DEC		MSG_GBL_FMT_DEC_32
#define	MSG_GBL_FMT_DECS	MSG_GBL_FMT_DECS_32
#define	MSG_GBL_FMT_HEX		MSG_GBL_FMT_HEX_32
#define	MSG_GBL_FMT_HEXS	MSG_GBL_FMT_HEXS_32

#define	MSG_SYM_FMT_VAL		MSG_SYM_FMT_VAL_32
#endif

#ifdef	__cplusplus
}
#endif

#endif	/* __CONV_DOT_H */
