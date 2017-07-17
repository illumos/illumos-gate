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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


/* Copyright (c) 1981 Regents of the University of California */

#include "ex.h"
#include "ex_re.h"

/*
 * Routines for address parsing and assignment and checking of address bounds
 * in command mode.  The routine address is called from ex_cmds.c
 * to parse each component of a command (terminated by , ; or the beginning
 * of the command itself.  It is also called by the scanning routine
 * in ex_voperate.c from within open/visual.
 *
 * Other routines here manipulate the externals addr1 and addr2.
 * These are the first and last lines for the current command.
 *
 * The variable bigmove remembers whether a non-local glitch of . was
 * involved in an address expression, so we can set the previous context
 * mark '' when such a motion occurs.
 */

static	bool bigmove;

/*
 * Set up addr1 and addr2 for commands whose default address is dot.
 */
void
setdot(void)
{

	setdot1();
	if (bigmove)
		markDOT();
}

/*
 * Call setdot1 to set up default addresses without ever
 * setting the previous context mark.
 */
void
setdot1(void)
{

	if (addr2 == 0)
		addr1 = addr2 = dot;
	if (addr1 > addr2) {
		notempty();
		error(value(vi_TERSE) ?
			gettext("Addr1 > addr2") :
			gettext("First address exceeds second"));
	}
}

/*
 * Ex allows you to say
 *	delete 5
 * to delete 5 lines, etc.
 * Such nonsense is implemented by setcount.
 */
void
setcount(void)
{
	int cnt;

	pastwh();
	if (!isdigit(peekchar())) {
		setdot();
		return;
	}
	addr1 = addr2;
	setdot();
	cnt = getnum();
	if (cnt <= 0)
		error(value(vi_TERSE) ?
			gettext("Bad count") :
			gettext("Nonzero count required"));
	addr2 += cnt - 1;
	if (addr2 > dol)
		addr2 = dol;
	nonzero();
}

#ifdef XPG4
/*
 * setcount2():	a version of setcount() which sets addr2 based on addr1 + cnt.
 * description:
 *	this routine is responsible for setting addr1 (possibly) and addr2
 *	(always); using the [count] to compute addr2.
 *
 *	this is similar setcount(), but it differs in that setcount() sets
 *	addr1 based upon addr2; here we set addr2 based upon addr1 and the
 *	[count].
 *
 *	the reason for this is because some commands, of the form:
 *		[range] command [count]
 *	will use [count] to modify the range. E.g.:
 *		change, delete, join, list, yank.
 */
void
setcount2(void)
{
	int cnt;

	pastwh();
	if (!isdigit(peekchar())) {
		setdot();
		return;
	}
	setdot();
	cnt = getnum();
	if (cnt <= 0)
		error(value(vi_TERSE) ?
			gettext("Bad count") :
			gettext("Nonzero count required"));
	addr2 = addr1 + (cnt - 1);
	if (addr2 > dol)
		addr2 = dol;
	if (addr2 < zero) {
		addr1 = addr2 = zero;
	}
	nonzero();
}

#endif /* XPG4 */

/*
 * Parse a number out of the command input stream.
 */
int
getnum(void)
{
	int cnt;

	/*CSTYLED*/
	for (cnt = 0; isdigit(peekcd());)
		cnt = cnt * 10 + getchar() - '0';
	return (cnt);
}

/*
 * Set the default addresses for commands which use the whole
 * buffer as default, notably write.
 */
void
setall(void)
{

	if (addr2 == 0) {
		addr1 = one;
		addr2 = dol;
		if (dol == zero) {
			dot = zero;
			return;
		}
	}
	/*
	 * Don't want to set previous context mark so use setdot1().
	 */
	setdot1();
}

/*
 * No address allowed on, e.g. the file command.
 */
void
setnoaddr(void)
{

	if (addr2 != 0)
		error(value(vi_TERSE) ?
			gettext("No address allowed") :
			gettext("No address allowed on this command"));
}

/*
 * Parse an address.
 * Just about any sequence of address characters is legal.
 *
 * If you are tricky you can use this routine and the = command
 * to do simple addition and subtraction of cardinals less
 * than the number of lines in the file.
 */
line *
address(inputline)
	unsigned char *inputline;
{
	line *addr;
	int offset, c;
	short lastsign;

	bigmove = 0;
	lastsign = 0;
	offset = 0;
	addr = 0;
	for (;;) {
		if (isdigit(peekcd())) {
			if (addr == 0) {
				addr = zero;
				bigmove = 1;
			}
			loc1 = 0;
			addr += offset;
			offset = getnum();
			if (lastsign >= 0)
				addr += offset;
			else
				addr -= offset;
			lastsign = 0;
			offset = 0;
		}
		switch (c = getcd()) {

		case '?':
		case '/':
		case '$':
		case '\'':
		case '\\':
			bigmove++;
			/* FALLTHROUGH */
		case '.':
			if (addr || offset)
				error(gettext("Badly formed address"));
		}
		offset += lastsign;
		lastsign = 0;
		switch (c) {

		case ' ':
		case '\t':
			continue;
		case ':':
			while (peekchar() == ':')
				ignchar();
			continue;
		case '+':
			lastsign = 1;
			if (addr == 0)
				addr = dot;
			continue;

		case '^':
		case '-':
			lastsign = -1;
			if (addr == 0)
				addr = dot;
			continue;

		case '\\':
		case '?':
		case '/':
			c = vi_compile(c, 1);
			notempty();
			savere(&scanre);
			addr = dot;
			if (inputline && execute(0, dot)) {
				if (c == '/') {
					while (loc1 <= (char *)inputline) {
						if (loc1 == loc2)
							loc2++;
						if (!execute(1))
							goto nope;
					}
					break;
				} else if (loc1 < (char *)inputline) {
					unsigned char *last;
doques:

					do {
						last = (unsigned char *)loc1;
						if (loc1 == loc2)
							loc2++;
						if (!execute(1))
							break;
					} while (loc1 < (char *)inputline);
					loc1 = (char *)last;
					break;
				}
			}
nope:
			for (;;) {
				if (c == '/') {
					addr++;
					if (addr > dol) {
						if (value(vi_WRAPSCAN) == 0)
error(value(vi_TERSE) ?
	gettext("No match to BOTTOM") :
	gettext("Address search hit BOTTOM without matching pattern"));
						addr = zero;
					}
				} else {
					addr--;
					if (addr < zero) {
						if (value(vi_WRAPSCAN) == 0)
error(value(vi_TERSE) ?
	gettext("No match to TOP") :
	gettext("Address search hit TOP without matching pattern"));
						addr = dol;
					}
				}
				if (execute(0, addr)) {
					if (inputline && c == '?') {
						inputline = &linebuf[LBSIZE];
						goto doques;
					}
					break;
				}
				if (addr == dot)
					error(value(vi_TERSE) ?
						gettext("Fail") :
						gettext("Pattern not found"));
			}
			continue;

		case '$':
			addr = dol;
			continue;

		case '.':
			addr = dot;
			continue;

		case '\'':
			c = markreg(getchar());
			if (c == 0)
				error(gettext("Marks are ' and a-z"));
			addr = getmark(c);
			if (addr == 0)
				error(value(vi_TERSE) ?
				    gettext("Undefined mark") :
				    gettext("Undefined mark referenced"));
			break;

		default:
			ungetchar(c);
			if (offset) {
				if (addr == 0)
					addr = dot;
				addr += offset;
				loc1 = 0;
			}
			if (addr == 0) {
				bigmove = 0;
				return (0);
			}
			if (addr != zero)
				notempty();
			addr += lastsign;
			if (addr < zero)
				error(value(vi_TERSE) ?
				    gettext("Negative address") :
				    gettext("Negative address - "
					"first buffer line is 1"));
			if (addr > dol)
				error(value(vi_TERSE) ?
				    gettext("Not that many lines") :
				    gettext("Not that many lines in buffer"));
			return (addr);
		}
	}
}

/*
 * Abbreviations to make code smaller
 * Left over from squashing ex version 1.1 into
 * 11/34's and 11/40's.
 */
void
setCNL(void)
{

	setcount();
	donewline();
}

void
setNAEOL(void)
{

	setnoaddr();
	eol();
}
