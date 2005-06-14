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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include	"_synonyms.h"

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
#include	"debug.h"
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
uint_t
dbg_setup(const char *options)
{
	uint_t		_dbg_mask;
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
	if ((_dbg_mask = Dbg_setup(options)) == (uint_t)S_ERROR)
		return (0);

	/*
	 * If an LD_DEBUG_OUTPUT file was specified then we need to direct all
	 * diagnostics to the specified file.  Add the process id as a file
	 * suffix so that multiple processes that inherit the same debugging
	 * environment variable don't fight over the same file.
	 */
	if (dbg_file) {
		char 	file[MAXPATHLEN];

		(void) snprintf(file, MAXPATHLEN, MSG_ORIG(MSG_DBG_FMT_FILE),
		    dbg_file, (int)getpid());
		if ((dbg_fd = open(file, (O_RDWR | O_CREAT), 0666)) == -1) {
			int	err = errno;

			eprintf(ERR_FATAL, MSG_INTL(MSG_SYS_OPEN), file,
			    strerror(err));
			dbg_mask = 0;
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

	return (_dbg_mask);
}

/*
 * All diagnostic requests are funneled to this routine.
 */
/*PRINTFLIKE1*/
void
dbg_print(const char *format, ...)
{
	va_list			args;
	char			buffer[ERRSIZE + 1];
	pid_t			_pid;
	struct stat		status;
	Prfbuf			prf;

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
				    MSG_ORIG(MSG_DBG_FMT_FILE), dbg_file,
				    (int)pid);
				if ((dbg_fd = open(file, (O_RDWR | O_APPEND),
				    0)) == -1) {
					dbg_mask = 0;
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
				dbg_mask = 0;
				return;
			}
		}
	}

	/*
	 * The getpid() call is a 'special' interface between ld.so.1
	 * and dbx, because of this getpid() can't be called freely
	 * until after control has been given to the user program.
	 * Once the control has been given to the user program
	 * we know that the r_debug structure has been properly
	 * initialized for the debugger.
	 */
	if (rtld_flags & RT_FL_APPLIC)
		_pid = getpid();
	else
		_pid = pid;

	prf.pr_buf = prf.pr_cur = buffer;
	prf.pr_len = ERRSIZE;
	prf.pr_fd = dbg_fd;

	if (rtld_flags & RT_FL_THREADS)
		(void) bufprint(&prf, MSG_ORIG(MSG_DBG_FMT_THREAD), _pid,
			rt_thr_self());
	else
		(void) bufprint(&prf, MSG_ORIG(MSG_DBG_FMT_DIAG), _pid);

	/*
	 * Format the message and print it.
	 */
	va_start(args, format);
	prf.pr_cur--;
	(void) doprf(format, args, &prf);
	*(prf.pr_cur - 1) = '\n';
	(void) dowrite(&prf);
	va_end(args);
}
