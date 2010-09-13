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

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T
 *	  All Rights Reserved
 *
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* from SVR4 bnu:dial.c 1.3 */

/*LINTLIBRARY*/
/***************************************************************
 *      dial() returns an fd for an open tty-line connected to the
 *      specified remote.  The caller should trap all ways to
 *      terminate, and call undial(). This will release the `lock'
 *      file and return the outgoing line to the system.  This routine
 *      would prefer that the calling routine not use the `alarm()'
 *      system call, nor issue a `signal(SIGALRM, xxx)' call.
 *      If you must, then please save and restore the alarm times.
 *      The sleep() library routine is ok, though.
 *
 *	#include <sys/types.h>
 *	#include <sys/stat.h>
 *      #include "dial.h"
 *
 *      int dial(call);
 *      CALL call;
 *
 *      void undial(rlfd);
 *      int rlfd;
 *
 *      rlfd is the "remote-lne file descriptor" returned from dial.
 *
 *      The CALL structure as (defined in dial.h):
 *
 *      typedef struct {
 *              struct termio *attr;    ptr to term attribute structure
 *              int     baud;           no longer used --
 *					left in for backwards compatibility
 *              int     speed;          212A modem: low=300, high=1200
 *					negative for "Any" speed
 *              char    *line;          device name for out-going line
 *              char    *telno;         ptr to tel-no digit string
 *		int	modem		no longer used --
 *					left in for backwards compatibility
 *		char 	*device		no longer used --
 *					left in for backwards compatibility
 *		int	dev_len		no longer used --
 *					left in for backwards compatibility
 *      } CALL;
 *
 *      The error returns from dial are negative, in the range -1
 *      to -13, and their meanings are:
 *
 *              INTRPT   -1: interrupt occured
 *              D_HUNG   -2: dialer hung (no return from write)
 *              NO_ANS   -3: no answer (caller script failed)
 *              ILL_BD   -4: illegal baud-rate
 *              A_PROB   -5: acu problem (open() failure)
 *              L_PROB   -6: line problem (open() failure)
 *              NO_Ldv   -7: can't open Devices file
 *              DV_NT_A  -8: specified device not available
 *              DV_NT_K  -9: specified device not known
 *              NO_BD_A -10: no device available at requested baud-rate
 *              NO_BD_K -11: no device known at requested baud-rate
 *		DV_NT_E -12: requested speed does not match
 *		BAD_SYS -13: system not in Systems file
 *
 *      Setting attributes in the termio structure indicated in
 *      the `attr' field of the CALL structure before passing the
 *      structure to dial(), will cause those attributes to be set
 *      before the connection is made.  This can be important for
 *      some attributes such as parity and baud.
 *
 *      With an error return (negative value), there will not be
 *      any `lock-file' entry, so no need to call undial().
 ***************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <setjmp.h>
#include <sys/stat.h>
#include <sys/times.h>
#include <fcntl.h>

#include "dial.h"

#include "uucp.h"
#include "uucpdefs.c"

#include "callers.c"
#include "conn.c"
#include "getargs.c"
#include "interface.c"
#include "line.c"
#include "stoa.c"
#include "strsave.c"
#include "sysfiles.c"
#include "ulockf.c"

#ifdef DATAKIT
#include "dkbreak.c"
#include "dkerr.c"
#include "dkdial.c"
#include "dkminor.c"
#include "dtnamer.c"
#endif

static int
        rlfd;                   /* fd for remote comm line */

GLOBAL jmp_buf Sjbuf;			/*needed by connection routines*/

/*VARARGS*/
/*ARGSUSED*/
static void
assert(s1,s2,i1,s3,i2)
char *s1, *s2, *s3;
int i1, i2;
{}	/* for ASSERT in conn() */

/*ARGSUSED*/
static void
logent(s1,s2)
char *s1, *s2;
{}	/* so we can load unlockf() */

static void
cleanup(Cn) 	/*this is executed only in the parent process*/
int Cn;		/*fd for remote comm line */
{
	(void)restline();
	(void)setuid(Euid);
	if(Cn > 0) {
		(void) close(Cn);
	}


	rmlock((char*) NULL);	/*uucp routine in ulockf.c*/	
	return;		/* code=negative for signal causing disconnect*/
}

int
dial(call)
CALL call;
{
char *alt[7];
char speed[10];		/* character value of speed passed to dial */

	/* set service so we know which Sysfiles entries to use, then	*/
	/* be sure can access Devices file(s).  use "cu" entries ...	*/
	/* dial is more like cu than like uucico.			*/
	(void)strcpy(Progname,"cu");
	setservice(Progname);
	if ( sysaccess(EACCESS_DEVICES) != 0 ) {
		/* can't read Devices file(s)	*/
		return(NO_Ldv);
	}

	if (call.attr != NULL) {
		if ( call.attr->c_cflag & PARENB ) {
			Evenflag = ((call.attr->c_cflag & PARODD) ? 0 : 1);
			Oddflag = ((call.attr->c_cflag & PARODD) ? 1 : 0);
		}
		line_8bit = (call.attr->c_cflag & CS8 ? 1 : 0);
	}

	if (call.speed <= 0)
		strcpy(speed,"Any");
	else
		sprintf(speed,"%d",call.speed);

	/* Determine whether contents of "telno" is a system name. */
	if ( (call.telno != NULL) &&
	     (strlen(call.telno) != strspn(call.telno,"0123456789=-*#")) ) {
		/* use conn() for system names */
		rlfd = conn(call.telno);
	} else {
		alt[F_NAME] = "dummy";	/* to replace the Systems file fields */
		alt[F_TIME] = "Any";    /* needed for getto(); [F_TYPE] and */
		alt[F_TYPE] = "";	/* [F_PHONE] assignment below       */
		alt[F_CLASS] = speed;
		alt[F_PHONE] = "";
		alt[F_LOGIN] = "";
		alt[6] = "";

		if ( (call.telno != NULL) && (*call.telno != '\0') ) {
			/* given a phone number, use an ACU */
			alt[F_PHONE] = call.telno;
			alt[F_TYPE] = "ACU";
		} else {
			/* otherwise, use a Direct connection */
			alt[F_TYPE] = "Direct";
			/* If device name starts with "/dev/", strip it off  */
			/* since Devices file entries will also be stripped. */
			if ( (call.line != NULL) &&
				(strncmp(call.line, "/dev/", 5) == 0) )
				Myline = (call.line + 5);
			else
				Myline = call.line;
		}
	
#ifdef forfutureuse
		if (call->class != NULL)
			alt[F_TYPE] = call->class;
#endif
	
	
		rlfd = getto(alt);
	}
	if (rlfd < 0)
		switch (Uerror) {
			case SS_NO_DEVICE:	return(NO_BD_A);
			case SS_DIAL_FAILED:	return(D_HUNG);
			case SS_LOCKED_DEVICE:	return(DV_NT_A);
			case SS_BADSYSTEM:	return(BAD_SYS);
			case SS_CANT_ACCESS_DEVICE:	return(L_PROB);
			case SS_CHAT_FAILED:	return(NO_ANS);
			default:	return(-Uerror);
		}
	(void)savline();
	if ((call.attr) && ioctl(rlfd, TCSETA, call.attr) < 0) {
		perror("stty for remote");
		return(L_PROB);
	}
	Euid = geteuid();
	if(setuid(getuid()) && setgid(getgid()) < 0)
		undial(rlfd);
	return(rlfd);
}

/*
* undial(fd) 
*/
void
undial(fd)
int fd;
{
	sethup(fd);
	sleep(2);
	cleanup(fd);
}
