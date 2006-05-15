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
 *	Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 *	Use is subject to license terms.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include	<sys/types.h>
#include	<stdio.h>
#include	<errno.h>
#include	<unistd.h>
#include	<string.h>
#include	<wait.h>
#include	<limits.h>
#include	"machdep.h"
#include	"sgs.h"
#include	"rtc.h"
#include	"conv.h"
#include	"_crle.h"
#include	"msg.h"

/*
 * Having gathered together any dependencies, dldump(3x) any necessary images.
 *
 * All dldump(3x) processing is carried out from the audit library.  The
 * temporary configuration file is read and all alternative marked files are
 * dumped.  If a -E application requires RTLD_REL_EXEC then that application
 * acts as the new process, otherwise lddstub is used.
 *
 * Besides dldump(3x)'ing any images the audit library returns the address
 * range of the images which will used to update the configuration file.
 */
int
dump(Crle_desc * crle)
{
	const char	*orgapp = (const char *)crle->c_app;
	int		fildes[2], pid;

	if (orgapp == 0)
		orgapp = conv_lddstub(M_CLASS);

	/*
	 * Set up a pipe through which the audit library will write the image
	 * address ranges.
	 */
	if (pipe(fildes) == -1) {
		int err = errno;
		(void) fprintf(stderr, MSG_INTL(MSG_SYS_PIPE),
		    crle->c_name, strerror(err));
		return (1);
	}

	/*
	 * Fork ourselves to run the application and collect its dependencies.
	 */
	if ((pid = fork()) == -1) {
		int err = errno;
		(void) fprintf(stderr, MSG_INTL(MSG_SYS_FORK),
		    crle->c_name, strerror(err));
		return (1);
	}

	if (pid) {
		/*
		 * Parent. Read memory range entries from the audit library.
		 * The read side of the pipe is attached to stdio to make
		 * obtaining the individual dependencies easier.
		 */
		int	error = 0, status;
		FILE	*fd;
		char	buffer[PATH_MAX];

		(void) close(fildes[1]);
		if ((fd = fdopen(fildes[0], MSG_ORIG(MSG_STR_READ))) != NULL) {
			char *str;
			Rtc_head *rtc = (Rtc_head *)crle->c_tempheadaddr;

			while (fgets(buffer, PATH_MAX, fd) != NULL) {
				/*
				 * Make sure we recognize the message, remove
				 * the newline (which allowed fgets() use) and
				 * register the memory range entry;
				 */
				if (strncmp(MSG_ORIG(MSG_AUD_PRF), buffer,
				    MSG_AUD_PRF_SIZE))
					continue;

				str = strrchr(buffer, '\n');
				*str = '\0';
				str = buffer + MSG_AUD_PRF_SIZE;

				if (strncmp(MSG_ORIG(MSG_AUD_RESBGN),
				    str, MSG_AUD_RESBGN_SIZE) == 0) {
					rtc->ch_resbgn =
					    strtoull(str + MSG_AUD_RESBGN_SIZE,
						(char **)NULL, 0);
				} else if (strncmp(MSG_ORIG(MSG_AUD_RESEND),
				    str, MSG_AUD_RESEND_SIZE) == 0) {
					rtc->ch_resend =
					    strtoull(str + MSG_AUD_RESEND_SIZE,
						(char **)NULL, 0);
				} else {
					continue;
				}
			}
			(void) fclose(fd);
		} else
			error = errno;

		while (wait(&status) != pid)
			;
		if (status) {
			if (WIFSIGNALED(status)) {
				(void) fprintf(stderr,
				    MSG_INTL(MSG_SYS_EXEC), crle->c_name,
				    orgapp, (WSIGMASK & status),
				    ((status & WCOREFLG) ?
				    MSG_INTL(MSG_SYS_CORE) :
				    MSG_ORIG(MSG_STR_EMPTY)));
			}
			return (status);
		}
		return (error);
	} else {
		char	efds[MSG_ENV_AUD_FD_SIZE + 10];
		char	eflg[MSG_ENV_AUD_FLAGS_SIZE + 10];
		char	ecnf[PATH_MAX];

		(void) close(fildes[0]);

		/*
		 * Child. Set up environment variables to enable and identify
		 * auditing.
		 */
		(void) snprintf(efds, (MSG_ENV_AUD_FD_SIZE + 10),
		    MSG_ORIG(MSG_ENV_AUD_FD), fildes[1]);
		(void) snprintf(eflg, (MSG_ENV_AUD_FLAGS_SIZE + 10),
		    MSG_ORIG(MSG_ENV_AUD_FLAGS), crle->c_dlflags);
		(void) snprintf(ecnf, PATH_MAX, MSG_ORIG(MSG_ENV_LD_CONFIG),
		    crle->c_tempname);

		/*
		 * Put strings in the environment for exec().
		 * NOTE, use of automatic variables for construction of the
		 * environment variables is legitimate here, as they are local
		 * to the child process and are established solely for exec().
		 */
		if ((putenv(efds) != 0) || (putenv(eflg) != 0) ||
		    (putenv(ecnf) != 0) || (putenv(crle->c_audit) != 0) ||
		    (putenv((char *)MSG_ORIG(MSG_ENV_LD_FLAGS)) != 0)) {
			int err = errno;
			(void) fprintf(stderr, MSG_INTL(MSG_SYS_PUTENV),
			    crle->c_name, strerror(err));
			return (1);
		}

		if (execlp(orgapp, orgapp, 0) == -1) {
			int err = errno;
			(void) fprintf(stderr, MSG_INTL(MSG_SYS_EXECLP),
			    crle->c_name, orgapp, strerror(err));
			_exit(err);
			/* NOTREACHED */
		}
	}
	return (0);
}
