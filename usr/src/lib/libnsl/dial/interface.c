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

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2014 Gary Mills
 */

/*
 * interface( label )
 *	provide alternate definitions for the I/O functions through global
 *	interfaces.
 */
#include "mt.h"
#include "uucp.h"
#include <unistd.h>

#ifdef TLI
#include <tiuser.h>
#endif /*  TLI  */

static void	sethup(int);
static int	restline(void);
static int	usetup(int, int *, int *);
static int	uteardown(int, int, int);

static ssize_t	(*Read)() = read,
	(*Write)() = write;
static int	(*Ioctl)(int, int, ...) = ioctl,
	(*Setup)() = usetup;

#ifdef TLI
static void tfaillog(int fd, const char *s);
static void show_tlook(int);
static ssize_t	tread(int, char *, unsigned);
static ssize_t	twrite(int, char *, unsigned);
static int tioctl(int, int, ...);
static int tsetup(int, int *, int *); /* TLI setup without streams module */
static int tssetup(int, int *, int *); /* TLI setup with streams module */
static int tteardown(int, int, int); /* TLI teardown, works with either setup */
#endif /*  TLI  */

/*
 *	The IN_label in Interface[] imply different caller routines:
 *	e.g. tlicall().
 *	If so, the names here and the names in callers.c must match.
 */
static struct Interface {
	const	char	*IN_label;	/* interface name */
	ssize_t	(*IN_read)();		/* read function */
	ssize_t	(*IN_write)();		/* write function */
	int	(*IN_ioctl)(int, int, ...);
	int	(*IN_setup)();		/* setup function, called before */
					/* first i/o operation */
	int	(*IN_teardown)();	/* teardown function, called after */
					/* last i/o operation */
} Interface[] = {
			/* vanilla UNIX */
		{ "UNIX", read, write, ioctl, usetup, uteardown },
#ifdef TLI
			/* AT&T Transport Interface Library WITHOUT streams */
		{ "TLI", tread, twrite, tioctl, tsetup, tteardown },
#ifdef TLIS
			/* AT&T Transport Interface Library WITH streams */
		{ "TLIS", read, write, tioctl, tssetup, uteardown },
#endif /*  TLIS  */
#endif /*  TLI  */
		{ 0, 0, 0, 0, 0, 0 }
	};


static int
interface(const char *label)
{
	int	i;

	for (i = 0;  Interface[i].IN_label;  ++i) {
		if (strcmp(Interface[i].IN_label, label) == 0) {
			Read = Interface[i].IN_read;
			Write = Interface[i].IN_write;
			Ioctl = Interface[i].IN_ioctl;
			Setup = Interface[i].IN_setup;
			DEBUG(5, "set interface %s\n", label);
			return (0);
		}
	}
	return (FAIL);
}

/*
 *	usetup - vanilla unix setup routine
 */
static int
usetup(int role, int *fdreadp, int *fdwritep)
{
	if (role == SLAVE) {
		*fdreadp = 0;
		*fdwritep = 1;
		/* 2 has been re-opened to RMTDEBUG in main() */
	}
	return (SUCCESS);
}

/*
 *	uteardown - vanilla unix teardown routine
 */
static int
uteardown(int role, int fdread, int fdwrite)
{
	char *ttyn;

	if (role == SLAVE) {
		(void) restline();
		sethup(0);
	}
	if (fdread != -1) {
		ttyn = ttyname(fdread);
		if (ttyn != NULL)
			/* can fail, but who cares? */
			(void) chmod(ttyn, Dev_mode);
		(void) close(fdread);
		(void) close(fdwrite);
	}
	return (SUCCESS);
}

#ifdef TLI
/*
 *	tread - tli read routine
 */
static ssize_t
tread(int fd, char *buf, unsigned nbytes)
{
	int		rcvflags;

	return ((ssize_t)t_rcv(fd, buf, nbytes, &rcvflags));
}

/*
 *	twrite - tli write routine
 */
#define	N_CHECK	100
static ssize_t
twrite(int fd, char *buf, unsigned nbytes)
{
	int			i, ret;
	static int		n_writ, got_info;
	static struct t_info	info;

	if (got_info == 0) {
		if (t_getinfo(fd, &info) != 0) {
			tfaillog(fd, "twrite: t_getinfo\n");
			return (FAIL);
		}
		got_info = 1;
	}

	/* on every N_CHECKth call, check that are still in DATAXFER state */
	if (++n_writ == N_CHECK) {
		n_writ = 0;
		if (t_getstate(fd) != T_DATAXFER)
			return (FAIL);
	}

	if (info.tsdu <= 0 || nbytes <= info.tsdu)
		return ((ssize_t)t_snd(fd, buf, nbytes, NULL));
	/* if get here, then there is a limit on transmit size	*/
	/* (info.tsdu > 0) and buf exceeds it			*/
	i = ret = 0;
	while (nbytes >= info.tsdu) {
		if ((ret = t_snd(fd,  &buf[i], info.tsdu, NULL)) != info.tsdu)
			return ((ssize_t)(ret >= 0 ? (i + ret) : ret));
		i += info.tsdu;
		nbytes -= info.tsdu;
	}
	if (nbytes != 0) {
		if ((ret = t_snd(fd,  &buf[i], nbytes, NULL)) != nbytes)
			return ((ssize_t)(ret >= 0 ? (i + ret) : ret));
		i += nbytes;
	}
	return ((ssize_t)i);
}

/*
 *	tioctl - stub for tli ioctl routine
 */
/* ARGSUSED */
static int
tioctl(int fd, int request, ...)
{
	return (SUCCESS);
}

/*
 *	tsetup - tli setup routine
 *	note blatant assumption that *fdreadp == *fdwritep == 0
 */
static int
tsetup(int role, int *fdreadp, int *fdwritep)
{
	if (role == SLAVE) {
		*fdreadp = 0;
		*fdwritep = 1;
		/* 2 has been re-opened to RMTDEBUG in main() */
		errno = t_errno = 0;
		if (t_sync(*fdreadp) == -1 || t_sync(*fdwritep) == -1) {
			tfaillog(*fdreadp, "tsetup: t_sync\n");
			return (FAIL);
		}
	}
	return (SUCCESS);
}

/*
 *	tteardown - tli shutdown routine
 */
/* ARGSUSED */
static int
tteardown(int role, int fdread, int fdwrite)
{
	(void) t_unbind(fdread);
	(void) t_close(fdread);
	return (SUCCESS);
}

#ifdef TLIS
/*
 *	tssetup - tli, with streams module, setup routine
 *	note blatant assumption that *fdreadp == *fdwritep
 */
static int
tssetup(int role, int *fdreadp, int *fdwritep)
{
	if (role == SLAVE) {
		*fdreadp = 0;
		*fdwritep = 1;
		/* 2 has been re-opened to RMTDEBUG in main() */
		DEBUG(5, "tssetup: SLAVE mode: leaving ok\n%s", "");
		return (SUCCESS);
	}

	DEBUG(4, "tssetup: MASTER mode: leaving ok\n%s", "");
	return (SUCCESS);
}

/*
 *	Report why a TLI call failed.
 */
static void
tfaillog(int fd, const char *s)
{
	char	fmt[ BUFSIZ ];

	if (0 < t_errno && t_errno < t_nerr) {
		(void) snprintf(fmt, sizeof (fmt), "%s: %%s\n", s);
		DEBUG(5, fmt, t_errlist[t_errno]);
		logent(s, t_errlist[t_errno]);
		if (t_errno == TSYSERR) {
			(void) strcpy(fmt, "tlicall: system error: %s\n");
			DEBUG(5, fmt, strerror(errno));
		} else if (t_errno == TLOOK) {
			show_tlook(fd);
		}
	} else {
		(void) snprintf(fmt, sizeof (fmt),
		    "unknown tli error %d", t_errno);
		logent(s, fmt);
		(void) snprintf(fmt, sizeof (fmt),
		    "%s: unknown tli error %d", s, t_errno);
		DEBUG(5, fmt, 0);
		(void) snprintf(fmt, sizeof (fmt), "%s: %%s\n", s);
		DEBUG(5, fmt, strerror(errno));
	}
}

static void
show_tlook(int fd)
{
	int reason;
	const char *msg;

/*
 * Find out the current state of the interface.
 */
	errno = t_errno = 0;
	switch (reason = t_getstate(fd)) {
	case T_UNBND:		msg = (const char *)"T_UNBIND";	break;
	case T_IDLE:		msg = (const char *)"T_IDLE";	break;
	case T_OUTCON:		msg = (const char *)"T_OUTCON";	break;
	case T_INCON:		msg = (const char *)"T_INCON";	break;
	case T_DATAXFER:	msg = (const char *)"T_DATAXFER"; break;
	case T_OUTREL:		msg = (const char *)"T_OUTREL";	break;
	case T_INREL:		msg = (const char *)"T_INREL";	break;
	default:		msg = NULL;		break;
	}
	if (msg == NULL)
		return;
	DEBUG(5, "state is %s", msg);
	switch (reason = t_look(fd)) {
	case -1:		msg = (const char *)""; break;
	case 0:			msg = (const char *)"NO ERROR"; break;
	case T_LISTEN:		msg = (const char *)"T_LISTEN"; break;
	case T_CONNECT:		msg = (const char *)"T_CONNECT"; break;
	case T_DATA:		msg = (const char *)"T_DATA";	 break;
	case T_EXDATA:		msg = (const char *)"T_EXDATA"; break;
	case T_DISCONNECT:	msg = (const char *)"T_DISCONNECT"; break;
	case T_ORDREL:		msg = (const char *)"T_ORDREL"; break;
	case T_UDERR:		msg = (const char *)"T_UDERR"; break;
	default:		msg = (const char *)"UNKNOWN ERROR"; break;
	}
	DEBUG(4, " reason is %s\n", msg);

	if (reason == T_DISCONNECT) {
		struct t_discon	*dropped;
		if (((dropped =
		    /* LINTED pointer cast */
		    (struct t_discon *)t_alloc(fd, T_DIS, T_ALL)) == 0) ||
		    (t_rcvdis(fd, dropped) == -1)) {
			if (dropped)
				(void) t_free((char *)dropped, T_DIS);
			return;
		}
		DEBUG(5, "disconnect reason #%d\n", dropped->reason);
		(void) t_free((char *)dropped, T_DIS);
	}
}
#endif /*  TLIS  */
#endif /*  TLI  */
