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
 * Copyright (c) 1995-1996 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _CS_TYPES_H
#define	_CS_TYPES_H

#pragma ident	"%W%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * PCMCIA Card Services types header file
 */

typedef uint32_t client_handle_t;
typedef	uint32_t window_handle_t;
typedef uint32_t event_t;
typedef uint8_t	cfg_regs_t;

typedef struct baseaddru_t {
	uint32_t		base;
	ddi_acc_handle_t	handle;
} baseaddru_t;

#ifdef	__cplusplus
}
#endif

#endif	/* _CS_TYPES_H */
