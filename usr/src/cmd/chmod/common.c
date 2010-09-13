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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved						*/

/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Use of this object by a utility (so far chmod, mkdir and mkfifo use
 * it) requires that the utility implement an error-processing routine
 * named errmsg(), with a prototype as specified below.
 *
 * This is necessary because the mode-parsing code here makes use of such
 * a routine, located in chmod.c.  The error-reporting style of the
 * utilities sharing this code differs enough that it is difficult to
 * implement a common version of this routine to be used by all.
 */

/*
 *  Note that many convolutions are necessary
 *  due to the re-use of bits between locking
 *  and setgid
 */

#include <ctype.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <locale.h>
#include <string.h>	/* strerror() */
#include <stdarg.h>

#define	USER	05700	/* user's bits */
#define	GROUP	02070	/* group's bits */
#define	OTHER	00007	/* other's bits */
#define	ALL	07777	/* all */

#define	READ	00444	/* read permit */
#define	WRITE	00222	/* write permit */
#define	EXEC	00111	/* exec permit */
#define	SETID	06000	/* set[ug]id */
#define	LOCK	02000	/* lock permit */
#define	STICKY	01000	/* sticky bit */

#define	GROUP_RWX	(GROUP & (READ | WRITE | EXEC))

#define	WHO_EMPTY 0

static char *msp;

extern void
errmsg(int severity, int code, char *format, ...);

static int
what(void);

static mode_t
abs(mode_t mode, o_mode_t *group_clear_bits, o_mode_t *group_set_bits),
who(void);

mode_t
newmode_common(char *ms, mode_t new_mode, mode_t umsk, char *file, char *path,
    o_mode_t *group_clear_bits, o_mode_t *group_set_bits);

/*
 * Wrapper for newmode_common.  This function is called by mkdir and
 * mkfifo.
 */
mode_t
newmode(char *ms, mode_t new_mode, mode_t umsk, char *file, char *path)
{
	o_mode_t tmp1, tmp2;

	return (newmode_common(ms, new_mode, umsk, file, path, &tmp1, &tmp2));
}

/*
 *  We are parsing a comma-separated list of mode expressions of the form:
 *
 *			 [<who>] <op> [<perms>]
 */

/* ARGSUSED */
mode_t
newmode_common(char *ms, mode_t new_mode, mode_t umsk, char *file, char *path,
    o_mode_t *group_clear_bits, o_mode_t *group_set_bits)
{
	/*
	 * new_mode  contains the mode value constructed by parsing the
	 *			 expression pointed to by ms
	 * old_mode  contains the mode provided by the caller
	 * oper		 contains +|-|= information
	 * perms_msk contains rwx(slt) information
	 * umsk		 contains the umask value to be assumed.
	 * who_empty is non-zero if the <who> clause did not appear.
	 * who_msk   contains USER|GROUP|OTHER information
	 */

	int oper;	/* <op> */
	int lcheck;
	int scheck;
	int xcheck;
	int goon;

	int operand_empty = 0;
	int who_empty;

	mode_t who_msk;
	mode_t perms_msk;
	mode_t old_mode = new_mode;	/* save original mode */
	mode_t grp_change;

	msp = ms;

	*group_clear_bits = 0;
	*group_set_bits = 0;

	if (isdigit(*msp))
		return (abs(old_mode, group_clear_bits, group_set_bits));

	do {
		/*
		 * When <who> is empty, and <oper> == `=`, the umask is
		 * obeyed.  So we need to make note of it here, for use
		 * later.
		 */

		if ((who_msk = who()) == WHO_EMPTY) {
			who_empty = 1;
			who_msk = ALL;
		} else {
			who_empty = 0;
		}

		while (oper = what()) {
			/*
			 *  this section processes permissions
			 */

			operand_empty++;
			perms_msk = 0;
			goon = 0;
			lcheck = scheck = xcheck = 0;

			switch (*msp) {
			case 'u':
				perms_msk = (new_mode & USER) >> 6;
				goto dup;
			case 'g':
				perms_msk = (new_mode & GROUP) >> 3;
				goto dup;
			case 'o':
				perms_msk = (new_mode & OTHER);
			dup:
				perms_msk &= (READ|WRITE|EXEC);
				perms_msk |= (perms_msk << 3) |
				    (perms_msk << 6);
				msp++;
				goon = 1;
			}

			while (goon == 0) {
				switch (*msp++) {
				case 'r':
					perms_msk |= READ;
					continue;
				case 'w':
					perms_msk |= WRITE;
					continue;
				case 'x':
					perms_msk |= EXEC;
					xcheck = 1;
					continue;
				case 'X':
					if (((old_mode & S_IFMT) == S_IFDIR) ||
					    (old_mode & EXEC)) {
						perms_msk |= EXEC;
						xcheck = 1;
					}
					continue;
				case 'l':
					perms_msk |= LOCK;
					who_msk |= LOCK;
					lcheck = 1;
					continue;
				case 's':
					perms_msk |= SETID;
					scheck = 1;
					continue;
				case 't':
					perms_msk |= STICKY;
					continue;
				default:
					msp--;
					goon = 1;
				}
			}

			perms_msk &= who_msk;

			switch (oper) {
			case '+':
				if (who_empty) {
					perms_msk &= ~umsk;
				}


				/* is group execution requested? */
				if (xcheck == 1 &&
				    (perms_msk & GROUP & EXEC) ==
				    (GROUP & EXEC)) {
					/* not locking, too! */
					if (lcheck == 1 && !S_ISDIR(new_mode)) {
						errmsg(1, 3,
						    gettext("Group execution "
						    "and locking not permitted "
						    "together\n"));
					}

					/*
					 * not if the file is already
					 * lockable.
					 */
					if (((new_mode & GROUP &
					    (LOCK | EXEC)) == LOCK) &&
					    !S_ISDIR(new_mode)) {
						errmsg(2, 0,
						    gettext("%s: Group "
						    "execution not permitted "
						    "on a lockable file\n"),
						    path);
						return (old_mode);
					}
				}

				/* is setgid on execution requested? */
				if (scheck == 1 && (perms_msk & GROUP & SETID)
				    == (GROUP & SETID)) {
					/* not locking, too! */
					if (lcheck == 1 &&
					    ((perms_msk & GROUP & EXEC) ==
					    (GROUP & EXEC)) &&
					    !S_ISDIR(new_mode)) {
						errmsg(1, 4,
						    gettext("Set-group-ID and "
						    "locking not permitted "
						    "together\n"));
					}

					/*
					 * not if the file is already
					 * lockable
					 */

					if (((new_mode & GROUP &
					    (LOCK | EXEC)) == LOCK) &&
					    !S_ISDIR(new_mode)) {
						errmsg(2, 0,
						    gettext("%s: Set-group-ID "
						    "not permitted on a "
						    "lockable file\n"), path);
						return (old_mode);
					}
				}

				/* is setid on execution requested? */
				if ((scheck == 1) &&
				    ((new_mode & S_IFMT) != S_IFDIR)) {
					/*
					 * the corresponding execution must
					 * be requested or already set
					 */
					if (((new_mode | perms_msk) &
					    who_msk & EXEC & (USER | GROUP)) !=
					    (who_msk & EXEC & (USER | GROUP))) {
						errmsg(2, 0,
						    gettext("%s: Execute "
						    "permission required "
						    "for set-ID on "
						    "execution \n"),
						    path);
						return (old_mode);
					}
				}

				/* is locking requested? */
				if (lcheck == 1) {
					/*
					 * not if the file has group execution
					 * set.
					 * NOTE: this also covers files with
					 * setgid
					 */
					if ((new_mode & GROUP & EXEC) ==
					    (GROUP & EXEC) &&
					    !S_ISDIR(new_mode)) {
						errmsg(2, 0,
						    gettext("%s: Locking not "
						    "permitted on "
						    "a group executable "
						    "file\n"),
						    path);
						return (old_mode);
					}
				}

				if ((grp_change = (perms_msk & GROUP_RWX) >> 3)
				    != 0) {
					*group_clear_bits &= ~grp_change;
					*group_set_bits |= grp_change;
				}

				/* create new mode */
				new_mode |= perms_msk;
				break;

			case '-':
				if (who_empty) {
					perms_msk &= ~umsk;
				}

				/* don't turn off locking, unless it's on */
				if (lcheck == 1 && scheck == 0 &&
				    (new_mode & GROUP & (LOCK | EXEC)) !=
				    LOCK) {
					perms_msk &= ~LOCK;
				}

				/* don't turn off setgid, unless it's on */
				if (scheck == 1 &&
				    ((new_mode & S_IFMT) != S_IFDIR) &&
				    lcheck == 0 &&
				    (new_mode & GROUP & (LOCK | EXEC)) ==
				    LOCK) {
					perms_msk &= ~(GROUP & SETID);
				}

				/*
				 * if execution is being turned off and the
				 * corresponding setid is not, turn setid off,
				 * too & warn the user
				 */
				if (xcheck == 1 && scheck == 0 &&
				    ((who_msk & GROUP) == GROUP ||
				    (who_msk & USER) == USER) &&
				    (new_mode & who_msk & (SETID | EXEC)) ==
				    (who_msk & (SETID | EXEC)) &&
				    !S_ISDIR(new_mode)) {
					errmsg(2, 0,
					    gettext("%s: Corresponding set-ID "
					    "also disabled on file since "
					    "set-ID requires execute "
					    "permission\n"),
					    path);

					if ((perms_msk & USER & SETID) !=
					    (USER & SETID) && (new_mode &
					    USER & (SETID | EXEC)) ==
					    (who_msk & USER &
					    (SETID | EXEC))) {
						perms_msk |= USER & SETID;
					}
					if ((perms_msk & GROUP & SETID) !=
					    (GROUP & SETID) &&
					    (new_mode & GROUP &
					    (SETID | EXEC)) ==
					    (who_msk & GROUP &
					    (SETID | EXEC))) {
						perms_msk |= GROUP & SETID;
					}
				}

				if ((grp_change = (perms_msk & GROUP_RWX) >> 3)
				    != 0) {
					*group_clear_bits |= grp_change;
					*group_set_bits &= ~grp_change;
				}

				/* create new mode */
				new_mode &= ~perms_msk;
				break;

			case '=':
				if (who_empty) {
					perms_msk &= ~umsk;
				}
				/* is locking requested? */
				if (lcheck == 1) {
					/* not group execution, too! */
					if ((perms_msk & GROUP & EXEC) ==
					    (GROUP & EXEC) &&
					    !S_ISDIR(new_mode)) {
						errmsg(1, 3,
						    gettext("Group execution "
						    "and locking not "
						    "permitted together\n"));
					}

					/*
					 * if the file has group execution set,
					 * turn it off!
					 */
					if ((who_msk & GROUP) != GROUP) {
						new_mode &= ~(GROUP & EXEC);
					}
				}

				/*
				 * is setid on execution requested? the
				 * corresponding execution must be requested,
				 * too!
				 */
				if (scheck == 1 &&
				    (perms_msk & EXEC & (USER | GROUP)) !=
				    (who_msk & EXEC & (USER | GROUP)) &&
					!S_ISDIR(new_mode)) {
					errmsg(1, 2,
					    gettext("Execute permission "
					    "required for set-ID on "
					    "execution\n"));
				}

				/*
				 * The ISGID bit on directories will not be
				 * changed when the mode argument is a string
				 * with "=".
				 */
				if ((old_mode & S_IFMT) == S_IFDIR)
					perms_msk = (perms_msk &
					    ~S_ISGID) | (old_mode & S_ISGID);

				/*
				 * create new mode:
				 *   clear the who_msk bits
				 *   set the perms_mks bits (which have
				 *   been trimmed to fit the who_msk.
				 */

				if ((grp_change = (perms_msk & GROUP_RWX) >> 3)
				    != 0) {
					*group_clear_bits = GROUP_RWX >> 3;
					*group_set_bits = grp_change;
				}

				new_mode &= ~who_msk;
				new_mode |= perms_msk;
				break;
			}
		}
	} while (*msp++ == ',');

	if (*--msp || operand_empty == 0) {
		errmsg(1, 5, gettext("invalid mode\n"));
	}

	return (new_mode);
}

mode_t
abs(mode_t mode, o_mode_t *group_clear_bits, o_mode_t *group_set_bits)
{
	int c;
	mode_t i;

	for (i = 0; (c = *msp) >= '0' && c <= '7'; msp++)
		i = (mode_t)((i << 3) + (c - '0'));
	if (*msp)
		errmsg(1, 6, gettext("invalid mode\n"));

/*
 * The ISGID bit on directories will not be changed when the mode argument is
 * octal numeric. Only "g+s" and "g-s" arguments can change ISGID bit when
 * applied to directories.
 */
	*group_clear_bits = GROUP_RWX >> 3;
	*group_set_bits = (i & GROUP_RWX) >> 3;
	if ((mode & S_IFMT) == S_IFDIR)
		return ((i & ~S_ISGID) | (mode & S_ISGID));
	return (i);
}

static mode_t
who(void)
{
	mode_t m;

	m = WHO_EMPTY;

	for (; ; msp++) {
		switch (*msp) {
		case 'u':
			m |= USER;
			continue;
		case 'g':
			m |= GROUP;
			continue;
		case 'o':
			m |= OTHER;
			continue;
		case 'a':
			m |= ALL;
			continue;
		default:
			return (m);
		}
	}
}

static int
what(void)
{
	switch (*msp) {
	case '+':
	case '-':
	case '=':
		return (*msp++);
	}
	return (0);
}
