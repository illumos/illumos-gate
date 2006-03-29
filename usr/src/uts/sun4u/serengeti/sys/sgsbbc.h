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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_SGSBBC_H
#define	_SYS_SGSBBC_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Serengeti SBBC Driver
 *
 * The Serengeti SBBC driver handles communication between the
 * System Controller Software (ScApp) and Solaris via SBBC
 * registers and IOSRAM.
 *
 */
#include <sys/serengeti.h>

/*
 * OS <-> SC Interrupt Reasons
 */
#define	SBBC_CONSOLE_IN			0x1 	/* console input available */
#define	SBBC_CONSOLE_OUT		0x2	/* console output available */
#define	SBBC_CONSOLE_BRK		0x4	/* break */
#define	SBBC_CONSOLE_SPACE_IN		0x8	/* console has in space */
#define	SBBC_CONSOLE_SPACE_OUT		0x10	/* console has out space */
#define	SBBC_MAILBOX_IN 		0x20	/* mailbox message in */
#define	SBBC_MAILBOX_OUT		0x40	/* mailbox message out */
#define	SBBC_MAILBOX_SPACE_IN		0x80	/* mailbox has in space */
#define	SBBC_MAILBOX_SPACE_OUT		0x100	/* mailbox has out space */

/*
 * SBBC needs to know what softint handlers are doing
 */
#define	SBBC_INTR_IDLE			0
#define	SBBC_INTR_RUNNING		1

typedef const char *const fn_t;

typedef uint_t (*sbbc_intrfunc_t)(caddr_t);

/* For printing out warning and panic messages */
#define	SBBC_ERR(err, msg) \
	{ prom_printf(msg); cmn_err(err, msg); }
#define	SBBC_ERR1(err, msg, arg) \
	{ prom_printf(msg, arg); cmn_err(err, msg, arg); }


#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_SGSBBC_H */
