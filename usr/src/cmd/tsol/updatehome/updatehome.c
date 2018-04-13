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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 *	updatehome - Update the current label's $HOME copy and link files.
 *
 *		Update home reads the user's minimum label copy and link
 *	control files (.copy_files and .link_files) which contain a list
 *	of files to be copied and symbolically linked from the user's minimum
 *	label $HOME to the user's current label's $HOME.
 *
 *		This is done by the Trusted Solaris dtsession whenever a
 *	newly labeled workspace is created so that the user's favorite
 *	files are available for use.  For example the user probably
 *	wants a symlink to .profile, .login, .cshrc, .exrc, .mailrc, ~/bin,
 *	... .  updatehome provides a convient mechanism for accomplishing
 *	this.  The user may add any set of files either to be copied
 *	(.copy_files), or symbolically linked (.link_files).
 *
 *		Files should not include embedded MLDs.
 *
 *	Entry	options = c, if replace existing current label $HOME copies
 *			     (default is to ignore existing).
 *			  d, if to print debug trace msgs (internal use only).
 *			  i, if to ignore errors encountered (default is to
 *			     abort).
 *			  m, if to suppress error diagnostics -- perror
 *			     (internal use only).
 *			  r, if replace existing current label $HOME copies or
 *			     symbolic links  -- implies c and s (default is to
 *			     ignore existing).
 *			  s, if replace existing current label $HOME symbolic
 *			     links (default is to ignore existing).
 *
 *	Exit	stderr = diagnostic messages.
 *		exis status = 0, no errors noted.
 *			      1, if errors noted.
 *
 *	Calls	__setupfiles (which does all the real work).
 */


/*
 *		There is a private contract between __setupfiles in this
 *	directory and login.  Changes made to __setupfiles may need to be
 *	reflected in the source for login.
 *
 *	G.Winiger 96/11/03
 */


#include <locale.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/types.h>

#include <tsol/label.h>
#include <sys/tsol/label_macro.h>
#include <user_attr.h>

#include "setupfiles.h"

#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN	"SYS_TEST"
#endif	/* !defined(TEXT_DOMAIN) */

int
main(int argc, char **argv)
{
	int		opt;		/* option switch value */
	int		flags;		/* setupfiles flags */
	uid_t		uid;
	extern int	opterr;		/* getopt error flag */
	char		*kv_str = NULL;
	struct passwd	*pwd;		/* current user's password file entry */
	userattr_t	*userp = NULL;	/* current user's user_attr entry */
	m_label_t	*min_sl;
	m_label_t	*clearance;

	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	flags = DIAG;
	opterr = 0;	/* handle errors here */

	while ((opt = getopt(argc, argv, "cdimrs")) != EOF) {
		switch (opt) {
		case 'c':	/* replace existing copy */
			flags |= REPC;
			break;

		case 'd':	/* debug */
			flags |= DBUG;
			break;

		case 'i':	/* ignore copy/link errors */
			flags |= IGNE;
			break;

		case 'm':	/* suppress error diagnostic (perror) */
				/* prints */
			flags &= ~DIAG;
			break;

		case 'r':		/* replace existing */
			flags |= (REPC | REPL);
			break;

		case 's':	/* replace existing symbolic links */
			flags |= REPL;
			break;

		case '?':		/* switch error */
			(void) fprintf(stderr, gettext("Bad option -%c.\n"),
			    (char)optopt);
			/* FALLTHROUGH */

		default:
			(void) fprintf(stderr, gettext("usage: %s [-cirs].\n"),
			    argv[0]);
			exit(1);
			/*NOTREACHED*/
		}  /* switch (opt) */
	}  /* while ((opt = getopt()) */

	uid = getuid();

	if ((pwd = getpwuid(uid)) == (struct passwd *)0) {

		(void) fprintf(stderr,
		    gettext("Unable to get password entry for uid %d.\n"), uid);
		exit(1);
	}

	min_sl = m_label_alloc(MAC_LABEL);
	clearance = m_label_alloc(USER_CLEAR);

	if (((userp = getusernam(pwd->pw_name)) == NULL) ||
	    ((kv_str = kva_match(userp->attr, USERATTR_MINLABEL)) == NULL)) {

		if (userdefs(min_sl, clearance) == -1) {
			(void) fprintf(stderr,
			    gettext("Unable to get default user labels.\n"));
			exit(1);
		}
	}

	if (kv_str != NULL) {
		if (str_to_label(kv_str, &min_sl, MAC_LABEL, L_NO_CORRECTION,
		    NULL) == -1) {
			(void) fprintf(stderr,
			    gettext("str_to_label failure on min_label for"
			    " user %s.\n"), pwd->pw_name);
			exit(1);
		}
	}

	if (__setupfiles(pwd, min_sl, flags) != 0) {

		(void) fprintf(stderr, gettext("%s failed.\n"), argv[0]);
		exit(1);
	}

	return (0);
}  /* update home */
