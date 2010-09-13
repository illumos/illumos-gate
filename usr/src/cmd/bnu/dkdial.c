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
 * Copyright 1994 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *	create a Datakit connection to a remote destination
 */
#ifndef DIAL
	static char	SCCSID[] = "@(#)dkdial.c	2.7+BNU DKHOST 87/03/09";
#endif
/*
 *	COMMKIT(TM) Software - Datakit(R) VCS Interface Release 2.0 V1
 */

#include <fcntl.h>
#include "dk.h"
#include <stdio.h>
#include <signal.h>
#define	SIGRTN	void
#include <setjmp.h>
#include <sysexits.h>
#include <errno.h>


#define DK_DEFWAIT	89	/* default time to wait for dial return */
#define	DK_MAXWAIT	600	/* maximum wait to allow the caller - 10 min */


GLOBAL unsigned int	dk_timewait = DK_DEFWAIT; /* Caller to dkdial might modify */

static char	Conn_Msg[] = "Can't connect to %s: %s\n";
static char	Resp_Msg[] = "No response from Datakit";

static SIGRTN	timout();	/* Alarm signal handler */
static void	setalarm(), usralarm();
EXTERN int	dkndial();
static int	Elapsed;	/* Alarm time elapsed during dial */
static int	Timer;		/* Current alarm setting */
static short	TimeErr;	/* Alarm clock rang */

extern char	*getenv();
EXTERN int	dk_verbose, dk_errno;

GLOBAL int
dkdial(dest)
	char *dest;
{
	return(dkndial(dest, atoi(getenv("DKINTF"))));
}

GLOBAL int
dkndial(dest, intf)
	char *dest;
{
	short		fd;		/* Channel Descriptor	*/
	SIGRTN		(*SigWas)();	/* Caller's alarm handler */
	unsigned int	TimWas;		/* Caller's alarm clock */
	char		*key;
	struct diocdial {
			struct	diocreq iocb;
			char	dialstring[128];
		}	ioreq;
	char		dial_dev[32];


	sprintf(dial_dev, "/dev/dk/dial%d", intf);

	/*
	** Clear our elapsed time and save caller's alarm stuff.
	*/

	Timer = Elapsed = 0;
	SigWas = signal(SIGALRM, timout);
	TimWas = alarm(0);

	/*
	** If requested timeout interval is unreasonable, use the default.
	*/

	if ((dk_timewait == 0)  || (dk_timewait > DK_MAXWAIT))
		dk_timewait = DK_DEFWAIT;

	/*
	** Do an alarm protected open of the dial device
	*/

	setalarm(dk_timewait);

	if ((fd = open(dial_dev, O_RDWR)) < 0) {
		setalarm(0);
		if (dk_verbose)
			fprintf(stderr, "dkdial: Can't open %s\n", dial_dev);
		usralarm(TimWas, SigWas);
		if (errno == EBUSY)
			return(dk_errno = -EX_TEMPFAIL);
		else
			return(dk_errno = -EX_OSFILE);
	}

	/*
	** If the caller has a DKKEY, use it.
	*/

	if((key = getenv("DKKEY")) != NULL && getuid() == geteuid())
		sprintf(ioreq.dialstring, "%s\n%s", dest, key);
	else
		strcpy(ioreq.dialstring, dest);

	ioreq.iocb.req_traffic = 0;
	ioreq.iocb.req_1param = 0;
	ioreq.iocb.req_2param = 0;

	/*
	** Try to dial the call.  If the alarm expires during the ioctl,
	** the ioctl will return in error.
	*/

	if (ioctl(fd, DKIODIAL, &ioreq) < 0) {
		setalarm(0);
		if (dk_verbose)
		if (TimeErr)
			fprintf(stderr, Conn_Msg, Resp_Msg, ioreq.dialstring);
		else
			fprintf(stderr, Conn_Msg, ioreq.dialstring, dkerr(ioreq.iocb.req_error));

		setalarm(2);		/* Don't wait forever on close */
		close(fd);
		usralarm(TimWas, SigWas);
		if (errno == EBUSY)
			return(-dkerrmap(dk_errno = -EX_TEMPFAIL));
		else
			return(-dkerrmap(dk_errno = ioreq.iocb.req_error));
	}
	usralarm(TimWas, SigWas);
	return (fd);
}

/*
** timout() is the alarm clock signal handling routine.  It is called
** whenever the alarm clock expires during dial processing.
*/

/* ARGSUSED */
static SIGRTN
timout(arg)
int arg;
{
	TimeErr++;
}

/*
** setalarm() is called to request an alarm at a future time.  The residual
** from the previous alarm (if any) is added to the elapsed time counter.
*/

static void
setalarm(Seconds)
{
	TimeErr = 0;
	(void) signal(SIGALRM, timout);
	Elapsed += Timer - alarm(Seconds);
	Timer = Seconds;
}

/*
** usralarm() is used to restore the alarm service for the caller.
*/

static void
usralarm(TimWas, SigWas)
	int		TimWas;		/* Caller's alarm clock */
	SIGRTN		(*SigWas)();	/* Caller's alarm handler */
{
	Elapsed += Timer - alarm(0);
	(void) signal(SIGALRM, SigWas);
	if (TimWas > 0) {
		TimWas -= Elapsed;
		if (TimWas < 2)
			TimWas = 2;
	}
	alarm(TimWas);
}
