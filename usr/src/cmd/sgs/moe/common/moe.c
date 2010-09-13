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

#include <dlfcn.h>
#include <link.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <libintl.h>
#include <locale.h>
#include <conv.h>
#include <msg.h>

void
locale()
{
	static int	localeinit = 0;

	/*
	 * Defer localization overhead until a localized message, is required.
	 * For successful specific (32-bit or 64-bit) commands, none of this
	 * overhead should be incurred.
	 */
	if (localeinit++)
		return;

	(void) setlocale(LC_MESSAGES, MSG_ORIG(MSG_STR_EMPTY));
	(void) textdomain(MSG_ORIG(MSG_SUNW_OST_SGS));
}

const char *
_moe_msg(Msg mid)
{
	return (gettext(MSG_ORIG(mid)));
}

/*
 * Error messages from ld.so.1 are formatted as:
 *
 *	ld.so.1: app-name: fatal: ....
 *
 * Here, we skip over these three components.  Thus the message a little less
 * hostile when displayed by moe().  Really, it would be nice to have some
 * flexibility over what ld.so.1 displays.
 */
static char *
trim_msg(char *str)
{
	char	*ptr = str;
	int	cnt = 0;

	/*
	 * Skip the first three components.
	 */
	while (*ptr) {
		if (*ptr == ':') {
			if (++cnt == 3)
				break;
		}
		ptr++;
	}
	if (*ptr == '\0')
		return (str);
	else
		return (ptr + 2);
}

#define	ONLY32	1
#define	ONLY64	2

static int
openlib(const char *prog, const char *name, int class, int silent, int verbose)
{
	void		*handle;
	const char	*modestr;

	/*
	 * If the class of object is required, localize the prefix message.
	 */
	if (class) {
		locale();
#if	defined(_LP64)
		modestr = MSG_INTL(MSG_PRE_64);
#else
		modestr = MSG_INTL(MSG_PRE_32);
#endif
	} else
		modestr = MSG_ORIG(MSG_STR_EMPTY);


	/*
	 * Open the optimal object, and determine its full name from the
	 * returned handle.  Borrow the internal mode, RTLD_CONFGEN, from
	 * crle(1).  This flag allows us to process incomplete objects, as
	 * would occur if the object couldn't find its dependencies or relocate
	 * itself.
	 */
	if ((handle = dlmopen(LM_ID_NEWLM, name,
	    (RTLD_FIRST | RTLD_CONFGEN | RTLD_LAZY))) == 0) {
		if (verbose) {
			(void) fprintf(stderr, MSG_ORIG(MSG_FMT_VERBOSE), prog,
			    modestr, trim_msg(dlerror()));
			(void) fflush(stderr);
		}
		return (1);
	}
	if (silent == 0) {
		Link_map	*lmp;

		if (dlinfo(handle, RTLD_DI_LINKMAP, &lmp) == -1) {
			if (verbose) {
				(void) fprintf(stderr,
				    MSG_ORIG(MSG_FMT_VERBOSE), prog, modestr,
				    trim_msg(dlerror()));
				(void) fflush(stderr);
			}
			return (1);
		}

		if (verbose)
			(void) printf(MSG_ORIG(MSG_FMT_VERBOSE), prog, modestr,
			    lmp->l_name);
		else
			(void) printf(MSG_ORIG(MSG_FMT_SIMPLE), modestr,
			    lmp->l_name);
		(void) fflush(stdout);
	}

	(void) dlclose(handle);
	return (0);
}

int
/* ARGSUSED2 */
main(int argc, char **argv, char **envp)
{
	int	var, verbose = 0, silent = 0, error = 0, mode = 0, class = 0;
	char	*prog;

	if ((prog = strrchr(argv[0], '/')) == 0)
		prog = argv[0];
	else
		prog++;

	opterr = 0;
	while ((var = getopt(argc, argv, MSG_ORIG(MSG_STR_OPTIONS))) != EOF) {
		switch (var) {
		case 'c':
			class++;
			break;
		case '3':
#if	!defined(_LP64)
			if ((optarg[0] == '2') && (mode == 0))
				mode = ONLY32;
			else
#endif
				error++;
			break;
		case '6':
			if ((optarg[0] == '4') && (mode == 0))
				mode = ONLY64;
			else
				error++;
			break;
		case 's':
			if (verbose == 0)
				silent++;
			else
				error++;
			break;
		case 'v':
			if (silent == 0)
				verbose++;
			else
				error++;
			break;
		case '?':
			error++;
			break;
		default:
			break;
		}
	}
	if (error || ((argc - optind) == 0)) {
		locale();
		(void) fprintf(stderr, MSG_INTL(MSG_ARG_USAGE), prog);
		return (1);
	}
	if (silent)
		class = 0;

	/*
	 * Process any 32-bit expansion.
	 */
#if	!defined(_LP64)
	if (mode != ONLY64) {
#endif
		if (openlib(prog, argv[optind], class, silent, verbose) != 0) {
			if (mode)
				error++;
		}
#if	!defined(_LP64)
	}
#endif
	if (mode == ONLY32)
		return (error);

	/*
	 * Re-exec ourselves to process any 64-bit expansion.
	 */
#if	!defined(__sparcv9) && !defined(__amd64)
	(void) conv_check_native(argv, envp);
#endif
	return (error);
}
