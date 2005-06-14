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
 * Copyright (c) 1995-2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/* LINTLIBRARY */

/*
 * cbreak.c
 *
 * XCurses Library
 *
 * Copyright 1990, 1995 by Mortice Kern Systems Inc.  All rights reserved.
 *
 */

#if M_RCSID
#ifndef lint
static char rcsID[] =
"$Header: /team/ps/sun_xcurses/archive/local_changes/xcurses/src/lib/"
"libxcurses/src/libc/xcurses/rcs/cbreak.c 1.5 1998/06/04 19:55:47 "
"cbates Exp $";
#endif
#endif

#include <private.h>

int
cbreak(void)
{
	cur_term->_flags &= ~__TERM_HALF_DELAY;

	PTERMIOS(_prog)->c_cc[VMIN] = 1;
	PTERMIOS(_prog)->c_cc[VTIME] = 0;
	PTERMIOS(_prog)->c_lflag &= ~ICANON;

	return (__m_tty_set_prog_mode());
}

int
nocbreak(void)
{
	cur_term->_flags &= ~__TERM_HALF_DELAY;

	/*
	 * On some systems VMIN and VTIME map to VEOF and VEOL, which
	 * means we have to restore them to their original settings.
	 */
	PTERMIOS(_prog)->c_cc[VEOF] = PTERMIOS(_shell)->c_cc[VEOF];
	PTERMIOS(_prog)->c_cc[VEOL] = PTERMIOS(_shell)->c_cc[VEOL];
	PTERMIOS(_prog)->c_lflag |= ICANON;

	return (__m_tty_set_prog_mode());
}

/*
 * Set global timeout value, which overrides individual window timeout
 * values (I think believe X/Open specified this wrong).
 */
int
halfdelay(int tenths)
{
	cur_term->_flags |= __TERM_HALF_DELAY;

	PTERMIOS(_prog)->c_cc[VMIN] = 0;
	PTERMIOS(_prog)->c_cc[VTIME] = (tenths > 255) ? 255 : (cc_t)tenths;
	PTERMIOS(_prog)->c_lflag &= ~ICANON;

	return (__m_tty_set_prog_mode());
}

int
raw(void)
{
	cur_term->_flags &= ~__TERM_HALF_DELAY;

	PTERMIOS(_prog)->c_cc[VMIN] = 1;
	PTERMIOS(_prog)->c_cc[VTIME] = 0;
	PTERMIOS(_prog)->c_lflag &= ~(ICANON | ISIG);
	PTERMIOS(_prog)->c_iflag &= ~IXON;

	return (__m_tty_set_prog_mode());
}

int
noraw(void)
{
	cur_term->_flags &= ~__TERM_HALF_DELAY;

	/*
	 * On some systems VMIN and VTIME map to VEOF and VEOL, which
	 * means we have to restore them to their original settings.
	 */
	PTERMIOS(_prog)->c_cc[VEOF] = PTERMIOS(_shell)->c_cc[VEOF];
	PTERMIOS(_prog)->c_cc[VEOL] = PTERMIOS(_shell)->c_cc[VEOL];
	PTERMIOS(_prog)->c_lflag |= ICANON | ISIG;
	PTERMIOS(_prog)->c_iflag |= IXON;

	return (__m_tty_set_prog_mode());
}
