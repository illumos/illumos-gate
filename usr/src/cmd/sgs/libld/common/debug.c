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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include	<stdio.h>
#include	<stdarg.h>
#include	<strings.h>
#include	<dlfcn.h>
#include	<debug.h>
#include	"msg.h"

/*
 * dbg_setup() can be called a number of times.  The typical use through
 * LD_OPTIONS, results in dbg_setup() being called as the first argument to
 * ld(1).  It's also possible to pass debugging tokens through the compiler,
 * for example -Wl,-Dlibs -Wl-Ddetail, in which case multiple dbg_setup()
 * calls are made.
 *
 * A distinction is also made between diagnostics being requested before any
 * other ld(1) options are read, or whether the debugging options occur
 * between other options on the command line.  In the latter case, the
 * debugging options can be used to isolate diagnostics around one or more
 * input files.  The "phase" argument allows us to select which phase of
 * dbg_setup() processing we should isolate ourselves to.
 *
 * dbg_print() can require the output filename for use in the diagnostics
 * created.  Save the address of the output filename pointer for this use.
 */
static const char	**Name = NULL;
static int		Phase = 0;

uintptr_t
dbg_setup(const char *options, Dbg_desc *dbp, const char **name, int phase)
{
	if (Phase == 0)
		Phase = phase;
	else if (Phase != phase)
		return (0);

	Name = name;

	/*
	 * Call the debugging setup routine to initialize the mask and
	 * debug function array.
	 */
	return (Dbg_setup(options, dbp));
}

/* PRINTFLIKE2 */
void
dbg_print(Lm_list *lml, const char *format, ...)
{
	static char	*prestr = NULL;
	va_list		args;

#if	defined(lint)
	/*
	 * The lml argument is only meaningful for diagnostics sent to ld.so.1.
	 * Supress the lint error by making a dummy assignment.
	 */
	lml = NULL;
#endif
	/*
	 * Knock off any newline indicator to signify that a diagnostic has
	 * been processed.
	 */
	dbg_desc->d_extra &= ~DBG_E_STDNL;

	if (DBG_ISSNAME()) {
		/*
		 * If the debugging options have requested each diagnostic line
		 * be prepended by a name create a prefix string.
		 */
		if ((prestr == NULL) && *Name) {
			const char	*name, *cls;
			size_t		len;

			/*
			 * Select the fullname or basename of the output file
			 * being created.
			 */
			if (DBG_ISFNAME())
				name = *Name;
			else {
				if ((name =
				    strrchr(*Name, '/')) == NULL)
					name = *Name;
				else
					name++;
			}
			len = strlen(name) +
			    strlen(MSG_INTL(MSG_DBG_NAME_FMT)) + 1;

			/*
			 * Add the output file class if required.
			 */
			if (DBG_ISCLASS()) {
#if	defined(_ELF64)
				len += MSG_DBG_CLS64_FMT_SIZE;
				cls = MSG_ORIG(MSG_DBG_CLS64_FMT);
#else
				len += MSG_DBG_CLS32_FMT_SIZE;
				cls = MSG_ORIG(MSG_DBG_CLS32_FMT);
#endif
			}

			/*
			 * Allocate a string to build the prefix.
			 */
			if ((prestr = libld_malloc(len)) == NULL)
				prestr = (char *)MSG_INTL(MSG_DBG_DFLT_FMT);
			else {
				(void) snprintf(prestr, len,
				    MSG_INTL(MSG_DBG_NAME_FMT), name);
				if (DBG_ISCLASS())
					(void) strcat(prestr, cls);
			}
		}
		if (prestr)
			(void) fputs(prestr, stderr);
		else
			(void) fputs(MSG_INTL(MSG_DBG_AOUT_FMT), stderr);
	} else
		(void) fputs(MSG_INTL(MSG_DBG_DFLT_FMT), stderr);

	va_start(args, format);
	(void) vfprintf(stderr, format, args);
	(void) fprintf(stderr, MSG_ORIG(MSG_STR_NL));
	va_end(args);
}
