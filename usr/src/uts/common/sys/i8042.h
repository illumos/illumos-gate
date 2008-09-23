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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_I8042_H
#define	_SYS_I8042_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Here's the interface to the virtual registers on the device.
 *
 * Normal interrupt-driven I/O:
 *
 * I8042_INT_INPUT_AVAIL
 *	Interrupt mode input bytes available?  Zero = No.
 * I8042_INT_INPUT_DATA
 *	Fetch interrupt mode input byte.
 * I8042_INT_OUTPUT_DATA
 *	Interrupt mode output byte.
 *
 * Polled I/O, used by (e.g.) kmdb, when normal system services are
 * unavailable:
 *
 * I8042_POLL_INPUT_AVAIL
 *	Polled mode input bytes available?  Zero = No.
 * I8042_POLL_INPUT_DATA
 *	Polled mode input byte.
 * I8042_POLL_OUTPUT_DATA
 *	Polled mode output byte.
 */

#define	I8042_INT_INPUT_AVAIL		0x00
#define	I8042_INT_INPUT_DATA		0x01
#define	I8042_INT_OUTPUT_DATA		0x03
#define	I8042_INT_CMD_PLUS_PARAM	0x05	/* See comment below */
#define	I8042_POLL_INPUT_AVAIL		0x10
#define	I8042_POLL_INPUT_DATA		0x11
#define	I8042_POLL_OUTPUT_DATA		0x13
#define	I8042_POLL_CMD_PLUS_PARAM	0x15	/* See comment below */

/*
 * The I8042_INT_CMD_PLUS_PARAM and I8042_POLL_CMD_PLUS_PARAM virtual
 * registers are meant to be used with i8042_rep_put8() [via
 * ddi_rep_put8 in child drivers], which is designed to allow commands
 * that have responses (or that have responses plus an option byte) to
 * execute atomically with respect to commands from other children
 * (some 8042 implementations get confused when other child devices
 * intersperse their own commands while a command to a different
 * 8042-connected device is in flight).
 */

/* Softint priority used */
#define	I8042_SOFTINT_PRI	4

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_I8042_H */
