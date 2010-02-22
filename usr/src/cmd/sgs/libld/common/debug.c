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

#include	<stdio.h>
#include	<stdarg.h>
#include	<errno.h>
#include	<strings.h>
#include	<dlfcn.h>
#include	<debug.h>
#include	<conv.h>
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

/* Debug file output state */
static struct {
	FILE	*fptr;	/* File to send debug output */
	int	close_needed;	/* True if explicitly opened stream */
} dbg_ofile = {
	stderr,
	0
};


/*
 * If there is an explicitly opened debug file, close it and reset the state.
 */
void
dbg_cleanup(void)
{
	if (dbg_ofile.close_needed) {
		(void) fclose(dbg_ofile.fptr);
		dbg_ofile.close_needed = 0;
		dbg_ofile.fptr = stderr;
	}
}

/*
 * Process debug tokens. Returns True (1) on success, and False (0)
 * on failure.
 */
int
dbg_setup(Ofl_desc *ofl, const char *options, int phase)
{
	const char	*ofile;

	if (Phase == 0)
		Phase = phase;
	else if (Phase != phase)
		return (1);

	Name = &ofl->ofl_name;

	/*
	 * Call the debugging setup routine to initialize the mask and
	 * debug function array.
	 */
	if (Dbg_setup(DBG_CALLER_LD, options, dbg_desc, &ofile) == 0)
		return (0);

	/*
	 * If output= token was used, close the old file if necessary
	 * and open a new one if the file name is not NULL.
	 */
	if (ofile) {
		dbg_cleanup();
		if (*ofile != '\0') {
			FILE *fptr = fopen(ofile, MSG_ORIG(MSG_DBG_FOPEN_MODE));
			if (fptr == NULL) {
				int	err = errno;

				eprintf(ofl->ofl_lml, ERR_FATAL,
				    MSG_INTL(MSG_SYS_OPEN), ofile,
				    strerror(err));
				return (0);
			} else {
				dbg_ofile.fptr = fptr;
				dbg_ofile.close_needed = 1;
			}
		}
	}

	/*
	 * Now that the output file is established, identify the linker
	 * package, and generate help output if the user specified the
	 * debug help token.
	 */
	Dbg_version();
	if (dbg_desc->d_extra & DBG_E_HELP)
		Dbg_help();

	return (1);
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
		(void) fputs(prestr ? prestr : MSG_INTL(MSG_DBG_AOUT_FMT),
		    dbg_ofile.fptr);
	} else
		(void) fputs(MSG_INTL(MSG_DBG_DFLT_FMT), dbg_ofile.fptr);

	if (DBG_ISTIME()) {
		Conv_time_buf_t	buf;
		struct timeval	new;

		if (gettimeofday(&new, NULL) == 0) {
			if (DBG_ISTTIME())
				(void) fputs(conv_time(&DBG_TOTALTIME, &new,
				    &buf), stderr);
			if (DBG_ISDTIME())
				(void) fputs(conv_time(&DBG_DELTATIME, &new,
				    &buf), stderr);

			DBG_DELTATIME = new;
		}
	}

	va_start(args, format);
	(void) vfprintf(dbg_ofile.fptr, format, args);
	(void) fprintf(dbg_ofile.fptr, MSG_ORIG(MSG_STR_NL));
	va_end(args);
}
