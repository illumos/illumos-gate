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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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
#include	"_rtld.h"
#include	"_elf.h"
#include	"msg.h"


static int	dbg_fd;		/* debugging output file descriptor */
static dev_t	dbg_dev;
static ino_t	dbg_ino;
static pid_t	pid;

/*
 * Enable diagnostic output.  All debugging functions reside in the linker
 * debugging library liblddbg.so which is lazy loaded when required.
 */
uintptr_t
dbg_setup(const char *options, Dbg_desc *dbp)
{
	uintptr_t	ret;
	struct stat	status;

	/*
	 * If we're running secure, only allow debugging if ld.so.1 itself is
	 * owned by root and has its mode setuid.  Fail silently.
	 */
	if (rtld_flags & RT_FL_SECURE) {
		struct stat	status;

		if (stat(NAME(lml_rtld.lm_head), &status) == 0) {
			if ((status.st_uid != 0) ||
			    (!(status.st_mode & S_ISUID)))
				return (0);
		} else
			return (0);
	}

	/*
	 * As Dbg_setup() will effectively lazy load the necessary support
	 * libraries, make sure ld.so.1 is initialized for plt relocations.
	 */
	if (elf_rtld_load() == 0)
		return (0);

	/*
	 * Call the debugging setup routine.  This function verifies the
	 * debugging tokens provided and returns a mask indicating the debugging
	 * categories selected.  The mask effectively enables calls to the
	 * debugging library.
	 */
	if ((ret = Dbg_setup(options, dbp)) != (uintptr_t)1)
		return (ret);

	/*
	 * If an LD_DEBUG_OUTPUT file was specified then we need to direct all
	 * diagnostics to the specified file.  Add the process id as a file
	 * suffix so that multiple processes that inherit the same debugging
	 * environment variable don't fight over the same file.
	 */
	if (dbg_file) {
		char 	file[MAXPATHLEN];

		(void) snprintf(file, MAXPATHLEN, MSG_ORIG(MSG_DBG_FILE),
		    dbg_file, getpid());
		if ((dbg_fd = open(file, (O_RDWR | O_CREAT), 0666)) == -1) {
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
	(void) fstat(dbg_fd, &status);
	dbg_dev = status.st_dev;
	dbg_ino = status.st_ino;
	pid = getpid();

	return (ret);
}

static int
dbg_lmid(Lm_list *lml)
{
	const char	*str;
	Aliste		idx;

	for (APLIST_TRAVERSE(dbg_desc->d_list, idx, str)) {
		if (strcmp(lml->lm_lmidstr, str) == 0)
			return (1);
	}
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
	struct stat	status;
	Prfbuf		prf;

	/*
	 * Knock off any newline indicator to signify that a diagnostic has
	 * been processed.
	 */
	dbg_desc->d_extra &= ~DBG_E_STDNL;

	/*
	 * If debugging has been isolated to individual link-map lists,
	 * determine whether this request originates from a link-map list that
	 * is being monitored.  Otherwise, process all link-map list diagnostics
	 * except those that originate from ld.so.1 processing its own
	 * dependencies.
	 */
	if (dbg_desc->d_list && lml && lml->lm_lmidstr) {
		if (dbg_lmid(lml) == 0)
			return;
	} else if (lml && (lml->lm_flags & LML_FLG_RTLDLM))
		return;

	/*
	 * If we're in the application make sure the debugging file descriptor
	 * is still available (ie, the user hasn't closed and/or reused the
	 * same descriptor).
	 */
	if (rtld_flags & RT_FL_APPLIC) {
		if ((fstat(dbg_fd, &status) == -1) ||
		    (status.st_dev != dbg_dev) ||
		    (status.st_ino != dbg_ino)) {
			if (dbg_file) {
				/*
				 * If the user specified output file has been
				 * disconnected try and reconnect to it.
				 */
				char 	file[MAXPATHLEN];

				(void) snprintf(file, MAXPATHLEN,
				    MSG_ORIG(MSG_DBG_FILE), dbg_file, pid);
				if ((dbg_fd = open(file, (O_RDWR | O_APPEND),
				    0)) == -1) {
					dbg_desc->d_class = 0;
					return;
				}
				(void) fstat(dbg_fd, &status);
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

	prf.pr_buf = prf.pr_cur = buffer;
	prf.pr_len = ERRSIZE;
	prf.pr_fd = dbg_fd;

	/*
	 * The getpid() call is a 'special' interface between ld.so.1 and dbx,
	 * because of this getpid() can't be called freely until after control
	 * has been given to the user program.  Once the control has been given
	 * to the user program we know that the r_debug structure has been
	 * properly initialized for the debugger.
	 */
	if (rtld_flags & RT_FL_APPLIC)
		_pid = getpid();
	else
		_pid = pid;

	if (lml)
		(void) bufprint(&prf, MSG_ORIG(MSG_DBG_PID), _pid);
	else
		(void) bufprint(&prf, MSG_ORIG(MSG_DBG_UNDEF));
	prf.pr_cur--;

	if (DBG_ISLMID() && lml && lml->lm_lmidstr) {
		(void) bufprint(&prf, MSG_ORIG(MSG_DBG_LMID), lml->lm_lmidstr);
		prf.pr_cur--;
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
