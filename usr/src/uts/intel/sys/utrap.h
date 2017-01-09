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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _UTRAP_H
#define	_UTRAP_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * This file contains definitions for user-level traps.
 */

#ifndef _ASM

/*
 * This architecture does not support install_utrap() (yet).
 */

#define	UTH_NOCHANGE ((utrap_handler_t)(-1))
#define	UTRAP_UTH_NOCHANGE	UTH_NOCHANGE

typedef int utrap_entry_t;
typedef void *utrap_handler_t;	/* user trap handler entry point */

#endif /* ASM */

#ifdef	__cplusplus
}
#endif

#endif	/* _UTRAP_H */
