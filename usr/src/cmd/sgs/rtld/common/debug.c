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

#include	<sys/types.h>
#include	<sys/stat.h>
#include	<sys/param.h>
#include	<stdio.h>
#include	<fcntl.h>
#include	<stdarg.h>
#include	<dlfcn.h>
#include	<unistd.h>
#include	<string.h>
#include	<thread.h>
#include	<debug.h>
#include	<conv.h>
#include	"_rtld.h"
#include	"_elf.h"
#include	"msg.h"


static int		dbg_fd;		/* debugging output file descriptor */
static dev_t		dbg_dev;
static rtld_ino_t	dbg_ino;
static int		dbg_add_pid;	/* True to add pid to debug file name */
static pid_t		pid;

/*
 * Enable diagnostic output.  All debugging functions reside in the linker
 * debugging library liblddbg.so which is lazy loaded when required.
 */
int
dbg_setup(const char *options, Dbg_desc *dbp)
{
	rtld_stat_t	status;
	const char	*ofile;

	/*
	 * If we're running secure, only allow debugging if ld.so.1 itself is
	 * owned by root and has its mode setuid.  Fail silently.
	 */
	if ((rtld_flags & RT_FL_SECURE) && (is_rtld_setuid() == 0))
		return (1);

	/*
	 * As Dbg_setup() will effectively lazy load the necessary support
	 * libraries, make sure ld.so.1 is initialized for plt relocations.
	 */
	if (elf_rtld_load() == 0)
		return (1);

	/*
	 * Call the debugging setup routine.  This function verifies the
	 * debugging tokens provided and returns a mask indicating the debugging
	 * categories selected.  The mask effectively enables calls to the
	 * debugging library.
	 */
	if (Dbg_setup(DBG_CALLER_RTLD, options, dbp, &ofile) == 0)
		return (0);

	/*
	 * Obtain the process id.
	 */
	pid = getpid();

	/*
	 * If an LD_DEBUG_OUTPUT file was specified then we need to direct all
	 * diagnostics to the specified file.  Add the process id as a file
	 * suffix so that multiple processes that inherit the same debugging
	 * environment variable don't fight over the same file.
	 *
	 * If LD_DEBUG_OUTPUT is not specified, and the output=file token
	 * was, then we direct all diagnostics to that file. Unlike
	 * LD_DEBUG_OUTPUT, we do not add the process id suffix. This
	 * is more convenient for interactive use.
	 *
	 * If neither redirection option is present, we send debugging
	 * output to stderr. Note that the caller will not be able
	 * to pipe or redirect this output at the shell level. libc
	 * has not yet initialized things to make that possible.
	 */
	if (dbg_file == NULL) {
		if (ofile && (*ofile != '\0'))
			dbg_file = ofile;
	} else {
		dbg_add_pid = 1;
	}

	if (dbg_file) {
		char 		_file[MAXPATHLEN];
		const char	*file;

		if (dbg_add_pid) {
			file = _file;
			(void) snprintf(_file, MAXPATHLEN,
			    MSG_ORIG(MSG_DBG_FILE), dbg_file, pid);
		} else {
			file = dbg_file;
		}
		dbg_fd = open(file, O_RDWR | O_CREAT | O_TRUNC, 0666);
		if (dbg_fd == -1) {
			int	err = errno;

			eprintf(&lml_rtld, ERR_FATAL, MSG_INTL(MSG_SYS_OPEN),
			    file, strerror(err));
			dbp->d_class = 0;
			return (0);
		}
	} else {
		/*
		 * The default is to direct debugging to the stderr.
		 */
		dbg_fd = 2;
	}

	/*
	 * Initialize the dev/inode pair to enable us to determine if
	 * the debugging file descriptor is still available once the
	 * application has been entered.
	 */
	(void) rtld_fstat(dbg_fd, &status);
	dbg_dev = status.st_dev;
	dbg_ino = status.st_ino;

	/*
	 * Now that the output file is established, identify the linker
	 * package, and generate help output if the user specified the
	 * debug help token.
	 */
	Dbg_version();
	if (dbp->d_extra & DBG_E_HELP)
		Dbg_help();

	return (1);
}

/*
 * Return True (1) if dbg_print() should produce output for the
 * specified link-map list, and False (0) otherwise.
 */
static int
dbg_lmid_validate(Lm_list *lml)
{
	const char	*str;
	Aliste		idx;

	/*
	 * The LDSO link-map list is a special case, requiring
	 * an explicit user request.
	 */
	if (lml->lm_flags & LML_FLG_RTLDLM)
		return ((dbg_desc->d_extra & DBG_E_LMID_LDSO) != 0);

	/*
	 * Approve special cases:
	 * -	The link-map list has no name
	 * -	lmid=all was set
	 * -	lmid=alt was set, and this is not the BASE linkmap
	 */
	if ((lml->lm_lmidstr == NULL) ||
	    ((dbg_desc->d_extra & DBG_E_LMID_ALL) != 0) ||
	    (((dbg_desc->d_extra & DBG_E_LMID_ALT) != 0) &&
	    ((lml->lm_flags & LML_FLG_BASELM) == 0)))
		return (1);

	/*
	 * If there is no list of specific link-map list names to check,
	 * then approval depends on lmid={ldso|alt} not being specified.
	 */
	if (aplist_nitems(dbg_desc->d_list) == 0)
		return ((dbg_desc->d_extra &
		    (DBG_E_LMID_LDSO | DBG_E_LMID_ALT)) == 0);

	/*
	 * Compare the link-map list name against the list of approved names
	 */
	for (APLIST_TRAVERSE(dbg_desc->d_list, idx, str))
		if (strcmp(lml->lm_lmidstr, str) == 0)
			return (1);

	/* Output for this linkmap is denied */
	return (0);
}

/*
 * All diagnostic requests are funneled to this routine.
 */
/* PRINTFLIKE2 */
void
dbg_print(Lm_list *lml, const char *format, ...)
{
	va_list		args;
	char		buffer[ERRSIZE + 1];
	pid_t		_pid;
	rtld_stat_t	status;
	Prfbuf		prf;

	/*
	 * Knock off any newline indicator to signify that a diagnostic has
	 * been processed.
	 */
	dbg_desc->d_extra &= ~DBG_E_STDNL;

	/*
	 * If debugging has been isolated to individual link-map lists,
	 * determine whether this request originates from a link-map list that
	 * is being monitored.
	 */
	if (lml && (dbg_lmid_validate(lml) == 0))
		return;

	/*
	 * If we're in the application make sure the debugging file descriptor
	 * is still available (ie, the user hasn't closed and/or reused the
	 * same descriptor).
	 */
	if (rtld_flags & RT_FL_APPLIC) {
		if ((rtld_fstat(dbg_fd, &status) == -1) ||
		    (status.st_dev != dbg_dev) ||
		    (status.st_ino != dbg_ino)) {
			if (dbg_file) {
				/*
				 * If the user specified output file has been
				 * disconnected try and reconnect to it.
				 */
				char 		_file[MAXPATHLEN];
				const char	*file;

				if (dbg_add_pid) {
					file = _file;
					(void) snprintf(_file, MAXPATHLEN,
					    MSG_ORIG(MSG_DBG_FILE), dbg_file,
					    pid);
				} else {
					file = dbg_file;
				}
				if ((dbg_fd = open(file, (O_RDWR | O_APPEND),
				    0)) == -1) {
					dbg_desc->d_class = 0;
					return;
				}
				(void) rtld_fstat(dbg_fd, &status);
				dbg_dev = status.st_dev;
				dbg_ino = status.st_ino;
			} else {
				/*
				 * If stderr has been stolen from us simply
				 * turn debugging off.
				 */
				dbg_desc->d_class = 0;
				return;
			}
		}
	}

	prf.pr_fd = dbg_fd;

	/*
	 * Obtain the process id.
	 */
	_pid = getpid();

	/*
	 * Each time ld.so.1 is entered, the diagnostic times are reset.  It is
	 * useful to convey this reset as part of our diagnostics, but only if
	 * other diagnostics will follow.  If a reset has preceded this
	 * diagnostic, print a division line.
	 */
	if (DBG_ISRESET()) {
		DBG_OFFRESET();

		prf.pr_buf = prf.pr_cur = buffer;
		prf.pr_len = ERRSIZE;

		if (lml)
			(void) bufprint(&prf, MSG_ORIG(MSG_DBG_PID), _pid);
		else
			(void) bufprint(&prf, MSG_ORIG(MSG_DBG_UNDEF));
		prf.pr_cur--;

		(void) bufprint(&prf, MSG_ORIG(MSG_DBG_RESET));
		(void) dowrite(&prf);
	}

	/*
	 * Reestablish the buffer for standard printing.
	 */
	prf.pr_buf = prf.pr_cur = buffer;
	prf.pr_len = ERRSIZE;

	/*
	 * Establish any diagnostic prefix strings.
	 */
	if (lml)
		(void) bufprint(&prf, MSG_ORIG(MSG_DBG_PID), _pid);
	else
		(void) bufprint(&prf, MSG_ORIG(MSG_DBG_UNDEF));
	prf.pr_cur--;

	if (DBG_ISLMID() && lml && lml->lm_lmidstr) {
		(void) bufprint(&prf, MSG_ORIG(MSG_DBG_LMID), lml->lm_lmidstr);
		prf.pr_cur--;
	}
	if (DBG_ISTIME()) {
		struct timeval	new;

		if (gettimeofday(&new, NULL) == 0) {
			Conv_time_buf_t	buf;

			if (DBG_ISTTIME()) {
				(void) bufprint(&prf,
				    conv_time(&DBG_TOTALTIME, &new, &buf));
				prf.pr_cur--;
			}
			if (DBG_ISDTIME()) {
				(void) bufprint(&prf,
				    conv_time(&DBG_DELTATIME, &new, &buf));
				prf.pr_cur--;
			}
			DBG_DELTATIME = new;
		}
	}
	if (rtld_flags & RT_FL_THREADS) {
		(void) bufprint(&prf, MSG_ORIG(MSG_DBG_THREAD), rt_thr_self());
		prf.pr_cur--;
	}

	/*
	 * Format the message and print it.
	 */
	va_start(args, format);
	(void) doprf(format, args, &prf);
	*(prf.pr_cur - 1) = '\n';
	(void) dowrite(&prf);
	va_end(args);
}
