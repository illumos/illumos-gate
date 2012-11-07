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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Stubs for basic system services otherwise unavailable to the debugger.
 */

#include <stdlib.h>
#include <unistd.h>
#include <libproc.h>
#include <sys/time.h>

#include <kmdb/kmdb_dpi.h>
#include <kmdb/kmdb_promif.h>
#include <kmdb/kmdb_io.h>
#include <mdb/mdb_debug.h>
#include <mdb/mdb_signal.h>
#include <mdb/mdb_io_impl.h>
#include <mdb/mdb.h>

/*ARGSUSED*/
char *
getenv(const char *name)
{
	/* There aren't any environment variables here */
	return (NULL);
}

char *
strerror(int errnum)
{
	static char errnostr[16];

	(void) mdb_snprintf(errnostr, sizeof (errnostr), "Error %d", errnum);

	return (errnostr);
}

pid_t
getpid(void)
{
	return (1);
}

/*
 * We're trying to isolate ourselves from the rest of the world as much as
 * possible, so we can't rely on the time in the kernel proper.  For now, we
 * just bump a counter whenever time is requested, thus guaranteeing that
 * things with timestamps can be compared according to order of occurrance.
 */
hrtime_t
gethrtime(void)
{
	static hrtime_t kmdb_timestamp;

	return (++kmdb_timestamp);
}

/*
 * Signal handling
 */

/*ARGSUSED*/
int
sigemptyset(sigset_t *set)
{
	return (0);
}

/*ARGSUSED*/
int
sigaddset(sigset_t *set, int signo)
{
	return (0);
}

/*ARGSUSED*/
int
sigfillset(sigset_t *set)
{
	return (0);
}

/*ARGSUSED*/
int
sigprocmask(int how, const sigset_t *set, sigset_t *oset)
{
	return (0);
}

/*ARGSUSED*/
int
sigaction(int sig, const struct sigaction *act, struct sigaction *oact)
{
	return (0);
}

/*ARGSUSED*/
int
kill(pid_t pid, int sig)
{
	if (sig == SIGABRT) {
		mdb_printf("Debugger aborted\n");
		exit(1);
	}

	return (0);
}

/*ARGSUSED*/
int
proc_str2flt(const char *buf, int *ptr)
{
	return (-1);
}

/*ARGSUSED*/
int
proc_str2sig(const char *buf, int *ptr)
{
	return (-1);
}

/*ARGSUSED*/
int
proc_str2sys(const char *buf, int *ptr)
{
	return (-1);
}

/*ARGSUSED*/
void
exit(int status)
{
#ifdef __sparc
	extern void kmdb_prom_exit_to_mon(void) __NORETURN;

	kmdb_prom_exit_to_mon();
#else
	extern void kmdb_dpi_reboot(void) __NORETURN;
	static int recurse = 0;

	if (!recurse) {

		recurse = 1;

		mdb_iob_printf(mdb.m_out, "Press any key to reboot\n");
		mdb_iob_flush(mdb.m_out);
		mdb_iob_clearlines(mdb.m_out);

		(void) kmdb_getchar();
	}

	kmdb_dpi_reboot();
#endif
}
