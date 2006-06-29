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
 * Copyright (c) 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_SYS_LOMBUS_H
#define	_SYS_LOMBUS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Information for client (child) drivers:
 *
 *	Register space definitions
 *	Fault info access
 *	Fault codes
 *
 * LOMbus child regspecs are triples, in the form
 * 	<space>, <base>, <size>
 */
typedef struct {
	int lombus_space;
	int lombus_base;
	int lombus_size;
} lombus_regspec_t;

#define	LOMBUS_REGSPEC_SIZE	3	/* words/regspec */


/*
 * Register spaces
 *
 *	Space	Size	Range		Meaning
 *		(bits)
 *
 *	0	8	[0 .. 16383]	LOM virtual registers
 *	1	8	[0]		Watchdog pat (on write)
 *	2	16	[0]		Async event info (read only)
 *	All	32	[-4 .. -12]	Access handle fault info
 */
#define	LOMBUS_VREG_SPACE	(0)
#define	LOMBUS_PAT_SPACE	(1)
#define	LOMBUS_EVENT_SPACE	(2)

#define	LOMBUS_MAX_REG		(16383)		/* space 0: [0..16383]	*/
#define	LOMBUS_PAT_REG		(0)		/* space 1: [0]		*/
#define	LOMBUS_EVENT_REG	(0)		/* space 2: [0]		*/

#define	LOMBUS_FAULT_REG	(-4)		/* 32-bit only, R/W	*/
#define	LOMBUS_PROBE_REG	(-8)		/* 32-bit only, R/W	*/
#define	LOMBUS_ASYNC_REG	(-12)		/* 32-bit only, R/O	*/


/*
 * Internally-generated errors
 *
 * Note: LOM-generated errors are 0x00-0x7f and SunVTS uses 0x80-0xff,
 * so these start at 0x100
 */
enum lombus_errs {
	LOMBUS_ERR_BASE = 0x100,

	/*
	 * Errors in the way the child is accessing the virtual registers.
	 * These are programming errors and won't go away on retry!
	 */
	LOMBUS_ERR_REG_NUM,		/* register number out of range	*/
	LOMBUS_ERR_REG_RO,		/* write to read-only register	*/
	LOMBUS_ERR_REG_SIZE,		/* access with invalid size	*/

	/*
	 * Error accessing the underlying SIO hardware
	 * This is unlikely to be recoverable.
	 */
	LOMBUS_ERR_SIOHW = 0x110,

	/*
	 * Errors in the LOMbus <-> LOM firmware protocol
	 * These may or may not be recoverable, depending
	 * on the state of the LOM.
	 */
	LOMBUS_ERR_TIMEOUT = 0x120,	/* no response from LOM		*/
	LOMBUS_ERR_OFLOW,		/* rcv buf oflo - LOM babbling?	*/
	LOMBUS_ERR_SEQUENCE,		/* cmd/reply sequence mismatch	*/
	LOMBUS_ERR_BADSTATUS,		/* bad status byte in reply pkt	*/
	LOMBUS_ERR_BADERRCODE		/* invalid error code in reply	*/
};


/*
 * Time periods, in nanoseconds
 */
#define	LOMBUS_ONE_SEC		1000000000LL
#define	LOMBUS_MIN_PAT		(LOMBUS_ONE_SEC/5)
#define	LOMBUS_CMD_TIMEOUT	(LOMBUS_ONE_SEC*5)


#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_LOMBUS_H */
