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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This code is MKS code ported to Solaris originally with minimum
 * modifications so that upgrades from MKS would readily integrate.
 * The MKS basis for this modification was:
 *
 *	$Id: wordexp.c 1.22 1994/11/21 18:24:50 miked
 *
 * Additional modifications have been made to this code to make it
 * 64-bit clean.
 */

/*
 * wordexp, wordfree -- POSIX.2 D11.2 word expansion routines.
 *
 * Copyright 1985, 1992 by Mortice Kern Systems Inc.  All rights reserved.
 *
 */

#include "synonyms.h"
#include <stdio.h>
#include <unistd.h>
#include <limits.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
#include <wordexp.h>
#include <stdio.h>
#include <errno.h>

#define	INITIAL	8		/* initial pathv allocation */
#define	BUFSZ	256		/* allocation unit of the line buffer */

static int	append(wordexp_t *, char *);

extern	int __xpg4;	/* defined in _xpg4.c; 0 if not xpg4-compiled program */

/*
 * Do word expansion.
 * We just pass our arguments to shell with -E option.  Note that the
 * underlying shell must recognize the -E option, and do the right thing
 * with it.
 */
int
wordexp(const char *word, wordexp_t *wp, int flags)
{
	static char options[9] = "-";
	static char *args[4];
	const char *path;
	wordexp_t wptmp;
	size_t si;
	int i;
	pid_t pid;
	char *line, *eob, *cp;		/* word from shell */
	int rv = WRDE_ERRNO;
	int status;
	int pv[2];			/* pipe from shell stdout */
	FILE *fp;			/* pipe read stream */
	char *optendp = options+1;
	int serrno, tmpalloc;
	char *wd = NULL;

	static const char *sun_path = "/bin/ksh";
	static const char *xpg4_path = "/usr/xpg4/bin/sh";

	/*
	 * Do absolute minimum neccessary for the REUSE flag. Eventually
	 * want to be able to actually avoid excessive malloc calls.
	 */
	if (flags & WRDE_REUSE)
		wordfree(wp);

	/*
	 * Initialize wordexp_t
	 *
	 * XPG requires that the struct pointed to by wp not be modified
	 * unless wordexp() either succeeds, or fails on WRDE_NOSPACE.
	 * So we work with wptmp, and only copy wptmp to wp if one of the
	 * previously mentioned conditions is satisfied.
	 */
	wptmp = *wp;

	/*
	 * Man page says:
	 * 2. All of the calls must set WRDE_DOOFFS, or  all  must  not
	 *    set it.
	 * Therefore, if it's not set, we_offs will always be reset.
	 */
	if ((flags & WRDE_DOOFFS) == 0)
		wptmp.we_offs = 0;

	/*
	 * If we get APPEND|REUSE, how should we do?
	 * allocating buffer anyway to avoid segfault.
	 */
	tmpalloc = 0;
	if ((flags & WRDE_APPEND) == 0 || (flags & WRDE_REUSE)) {
		wptmp.we_wordc = 0;
		wptmp.we_wordn = wptmp.we_offs + INITIAL;
		wptmp.we_wordv = (char **)malloc(
					sizeof (char *) * wptmp.we_wordn);
		if (wptmp.we_wordv == NULL)
			return (WRDE_NOSPACE);
		wptmp.we_wordp = wptmp.we_wordv + wptmp.we_offs;
		for (si = 0; si < wptmp.we_offs; si++)
			wptmp.we_wordv[si] = NULL;
		tmpalloc = 1;
	}

	/*
	 * Turn flags into shell options
	 */
	*optendp++ = (char)0x05;		/* ksh -^E */
	if (flags & WRDE_UNDEF)
		*optendp++ = 'u';
	if (flags & WRDE_NOCMD)
		*optendp++ = 'N';
	*optendp = '\0';

	if (getenv("PWD") == NULL) {
		if ((wd = malloc(PATH_MAX + 4)) == NULL)
			goto cleanup;
		(void) strcpy(wd, "PWD=");
		if (getcwd(&wd[4], PATH_MAX) == NULL)
			(void) strcpy(&wd[4], "/");
	}

	/*
	 * Set up pipe from shell stdout to "fp" for us
	 */
	if (pipe(pv) < 0)
		goto cleanup;

	/*
	 * Fork/exec shell with -E word
	 */

	if ((pid = fork1()) == -1) {
		serrno = errno;
		(void) close(pv[0]);
		(void) close(pv[1]);
		errno = serrno;
		goto cleanup;
	}

	if (pid == 0) { 	/* child */
		if (wd != NULL) {
			/*
			 * fork1 handler takes care of __environ_lock.
			 * Thus we can safely call putenv().
			 */
			(void) putenv(wd);
		}

		(void) dup2(pv[1], 1);
		(void) close(pv[0]);
		(void) close(pv[1]);

		if ((flags & WRDE_SHOWERR) == 0) {
			int devnull;
			devnull = open("/dev/null", O_WRONLY);
			(void) dup2(devnull, 2);
			if (devnull != 2)
				(void) close(devnull);
		}

		path = __xpg4 ? xpg4_path : sun_path;
		args[0] = strrchr(path, '/') + 1;
		args[1] = options;
		args[2] = (char *)word;
		args[3] = NULL;

		(void) execv(path, args);
		_exit(127);
	}

	(void) close(pv[1]);

	if ((fp = fdopen(pv[0], "rb")) == NULL) {
		serrno = errno;
		(void) close(pv[0]);
		errno = serrno;
		goto wait_cleanup;
	}

	/*
	 * Read words from shell, separated with '\0'.
	 * Since there is no way to disable IFS splitting,
	 * it would be possible to separate the output with '\n'.
	 */
	cp = line = malloc(BUFSZ);
	if (line == NULL) {
		(void) fclose(fp);
		rv = WRDE_NOSPACE;
		goto wait_cleanup;
	}
	eob = line + BUFSZ;

	rv = 0;
	while ((i = getc(fp)) != EOF) {
		*cp++ = (char)i;
		if (i == '\0') {
			cp = line;
			if ((rv = append(&wptmp, cp)) != 0) {
				break;
			}
		}
		if (cp == eob) {
			size_t bs = (eob - line);
			char *nl;

			if ((nl = realloc(line, bs + BUFSZ)) == NULL) {
				rv = WRDE_NOSPACE;
				break;
			}
			line = nl;
			cp = line + bs;
			eob = cp + BUFSZ;
		}
	}

	wptmp.we_wordp[wptmp.we_wordc] = NULL;

	free(line);
	(void) fclose(fp);	/* kill shell if still writing */

wait_cleanup:
	if (waitpid(pid, &status, 0) == -1)
		rv = WRDE_ERRNO;
	else if (rv == 0)
		rv = WEXITSTATUS(status); /* shell WRDE_* status */

cleanup:
	if (rv == 0)
		*wp = wptmp;
	else {
		if (tmpalloc)
			wordfree(&wptmp);
	}

	if (wd)
		free(wd);
	/*
	 * Map ksh errors to wordexp() errors
	 */
	if (rv == 4)
		rv = WRDE_CMDSUB;
	else if (rv == 5)
		rv = WRDE_BADVAL;
	else if (rv == 6)
		rv = WRDE_SYNTAX;
	return (rv);
}

/*
 * Append a word to the wordexp_t structure, growing it as neccessary.
 */
static int
append(wordexp_t *wp, char *str)
{
	char *cp;
	char **nwp;

	/*
	 * We will be adding one entry and later adding
	 * one more NULL. So we need 2 more free slots.
	 */
	if ((wp->we_wordp + wp->we_wordc) ==
		(wp->we_wordv + wp->we_wordn - 1)) {
		nwp = realloc(wp->we_wordv,
			(wp->we_wordn + INITIAL) * sizeof (char *));
		if (nwp == NULL)
			return (WRDE_NOSPACE);
		wp->we_wordn += INITIAL;
		wp->we_wordv = nwp;
		wp->we_wordp = wp->we_wordv + wp->we_offs;
	}
	if ((cp = strdup(str)) == NULL)
		return (WRDE_NOSPACE);
	wp->we_wordp[wp->we_wordc++] = cp;
	return (0);
}

/*
 * Free all space owned by wordexp_t.
 */
void
wordfree(wordexp_t *wp)
{
	size_t i;

	if (wp->we_wordv == NULL)
		return;
	for (i = wp->we_offs; i < wp->we_offs + wp->we_wordc; i++)
		free(wp->we_wordv[i]);
	free((void *)wp->we_wordv);
	wp->we_wordc = 0;
	wp->we_wordv = NULL;
}
