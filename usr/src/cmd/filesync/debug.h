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
 * Copyright (c) 1996 Sun Microsystems, Inc.  All Rights Reserved
 *
 * module:
 *	debug.h
 *
 * purpose:
 *	definitions and declarations for special debugging features
 */

#ifndef	_DEBUG_H
#define	_DEBUG_H

#pragma ident	"%W%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#define	DBG_ERRORS	1	/* enable error simulation code	*/
#define	DBG_MAX_ERR	20	/* maximum # simulated errs	*/

/*
 * the flaglists are used by the showflags routine in order to
 * print bitmasks in a symbolic form
 */
struct flaglist {
	long fl_mask;		/* the bit in question		*/
	char *fl_name;		/* the name of that bit		*/
};

extern struct flaglist	dbgmap[], rflags[], fileflags[], diffmap[], errmap[];

char *showflags(struct flaglist *, long);	/* turn bit to a name	*/
int dbg_set_error(char *arg);			/* simulate error	*/
int dbg_chk_error(const char *name, char code);	/* check for simul err	*/

void dbg_usage();				/* debug flag usage	*/
void err_usage();				/* error simul usage	*/

#ifdef	__cplusplus
}
#endif

#endif	/* _DEBUG_H */
