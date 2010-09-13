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
 * Copyright 1998 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "uucp.h"

static FILE	*_Lf = NULL;
static FILE	*_Cf = NULL;
static int	_Sf = -1;
static int	CurRole = MASTER;	/* Uucico's current role. */

/*
 * Make log entry
 *	text	-> ptr to text string
 *	status	-> ptr to status string
 * Returns:
 *	none
 */
void
logent(text, status)
register char	*text, *status;
{
	static	char	logfile[MAXFULLNAME];
	char		*prev;

	if (*Rmtname == NULLCHAR) /* ignore logging if Rmtname is not yet set */
		return;

	prev = _uu_setlocale(LC_ALL, "C");
	if (Nstat.t_pid == 0)
		Nstat.t_pid = getpid();

	if (_Lf != NULL
	   && strncmp(Rmtname, BASENAME(logfile, '/'), MAXBASENAME) != 0) {
		fclose(_Lf);
		_Lf = NULL;
	}

	if (_Lf == NULL) {
		sprintf(logfile, "%s/%s", Logfile, Rmtname);
		_Lf = fopen(logfile, "a");
		(void) chmod(logfile, LOGFILEMODE);
		if (_Lf == NULL) {
			(void) _uu_resetlocale(LC_ALL, prev);
			return;
		}
		setbuf(_Lf, CNULL);
	}
	(void) fseek(_Lf, 0L, 2);
	(void) fprintf(_Lf, "%s %s %s ", User, Rmtname, Jobid);
	(void) fprintf(_Lf, "(%s,%ld,%d) ", timeStamp(), (long) Nstat.t_pid, Seqn);
	(void) fprintf(_Lf, "%s (%s)\n", status, text);
	(void) _uu_resetlocale(LC_ALL, prev);
	return;
}


/*
 * Make entry for a conversation (uucico only)
 *	text	-> pointer to message string
 * Returns:
 *	none
 */
void
usyslog(text)
register char	*text;
{
	int	sbuflen;
	char	sysbuf[BUFSIZ];
	char	*prev = _uu_setlocale(LC_ALL, "C");

	(void) sprintf(sysbuf, "%s!%s %s (%s) (%c,%ld,%d) [%s] %s\n",
		Rmtname, User, CurRole == SLAVE ? "S" : "M", timeStamp(),
		Pchar, (long) getpid(), Seqn, Dc, text);
	sbuflen = strlen(sysbuf);
	if (_Sf < 0) {
		errno = 0;
		_Sf = open(SYSLOG, 1);
		if (errno == ENOENT) {
			_Sf = creat(SYSLOG, LOGFILEMODE);
			(void) chmod(SYSLOG, LOGFILEMODE);
		}
		if (_Sf < 0) {
			(void) _uu_resetlocale(LC_ALL, prev);
			return;
		}
	}
	(void) lseek(_Sf, 0L, 2);
	(void) write(_Sf, sysbuf, sbuflen);
	(void) _uu_resetlocale(LC_ALL, prev);
	return;
}

/*
 * Make entry for a command 
 *	argc	-> number of command arguments
 *	argv	-> pointer array to command arguments
 * Returns:
 *	none
 */
void
commandlog(argc,argv)
int argc;
char **argv;
{
	int	fd;
	char	*prev = _uu_setlocale(LC_ALL, "C");

	if (_Cf == NULL) {
		errno = 0;
		fd = open(CMDLOG, O_WRONLY | O_APPEND);
		if (errno == ENOENT) {
			fd = creat(CMDLOG, LOGFILEMODE);
			(void) chmod(CMDLOG, LOGFILEMODE);
		}
		if (fd < 0 || (_Cf = fdopen(fd, "a")) == NULL) {
			(void) _uu_resetlocale(LC_ALL, prev);
			return;
		}
	}
	(void) fprintf(_Cf, "%s (%s) ",User, timeStamp() );
	while (argc-- > 0) {
		(void) fprintf(_Cf, "%s%c", *argv++, (argc > 0)?' ':'\n');
	}
	(void) fflush(_Cf);
	(void) _uu_resetlocale(LC_ALL, prev);
	return;
}

/*
 * Close log files before a fork
 */
void
ucloselog()
{
	if (_Sf >= 0) {
		(void) close(_Sf);
		_Sf = -1;
	}
	if (_Lf) {
		(void) fclose(_Lf);
		_Lf = NULL;
	}
	if (_Cf) {
		(void) fclose(_Cf);
		_Cf = NULL;
	}
	return;
}

/*
 *	millitick()
 *
 *	return msec since last time called
 */
#ifdef ATTSV
#include <values.h>

time_t
millitick()
{
	struct tms	tbuf;
	time_t	now, rval;
	static time_t	past;	/* guaranteed 0 first time called */

	if (past == 0) {
		past = times(&tbuf);
		rval = 0;
	} else {
		now = times(&tbuf);
		if (now - past > MAXLONG / 1000)	/* would overflow */
			rval = (now - past) / HZ * 1000;
		else
			rval = (now - past) * 1000 / HZ;
		past = now;
	}
	return(rval);
}

#else /* !ATTSV */
time_t
millitick()
{
	struct timeb	tbuf;
	static struct timeb	tbuf1;
	static past;		/* guaranteed 0 first time called */
	time_t	rval;

	if (past == 0) {
		past++;
		rval = 0;
		ftime(&tbuf1);
	} else {
		ftime(&tbuf);
		rval = (tbuf.time - tbuf1.time) * 1000
			+ tbuf.millitm - tbuf1.millitm;
		tbuf1 = tbuf;
	}
	return(rval);
}
#endif /* ATTSV */
