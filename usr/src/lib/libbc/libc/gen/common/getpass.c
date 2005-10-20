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
 * Copyright 1987 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*LINTLIBRARY*/
#include <stdio.h>
#include <signal.h>
#include <termios.h>
#include <unistd.h>

extern void setbuf();
extern int	fclose(FILE *);
extern int	fprintf(FILE *, char *, ...);
extern int	findiop();
extern int ioctl();
static int intrupt;

static void	catch(void);

#define	MAXPASSWD	8	/* max significant characters in password */

char *
getpass(char *prompt)
{
	struct termios ttyb;
	long flags;
	char *p;
	int c;
	FILE	*fi;
	static char pbuf[ MAXPASSWD + 1 ];
	struct sigvec osv, sv;

	if((fi = fopen("/dev/tty", "r")) == NULL)
#ifdef S5EMUL
		return((char*)NULL);
#else
		fi = stdin;
#endif
	else
		setbuf(fi, (char*)NULL);
	sv.sv_handler = catch;
	sv.sv_mask = 0;
	sv.sv_flags = SV_INTERRUPT;
	(void) sigvec(SIGINT, &sv, &osv);
	intrupt = 0;
	(void) ioctl(fileno(fi), TCGETS, &ttyb);
	flags = ttyb.c_lflag;
	ttyb.c_lflag &= ~(ECHO | ECHOE | ECHOK | ECHONL);
	(void) ioctl(fileno(fi), TCSETSF, &ttyb);
	(void) fputs(prompt, stderr);
	p = pbuf;
	while( !intrupt  &&
		(c = getc(fi)) != '\n'  &&  c != '\r'  &&  c != EOF ) {
		if(p < &pbuf[ MAXPASSWD ])
			*p++ = c;
	}
	*p = '\0';
	ttyb.c_lflag = flags;
	(void) ioctl(fileno(fi), TCSETSW, &ttyb);
	(void) putc('\n', stderr);
	(void) sigvec(SIGINT, &osv, (struct sigvec *)NULL);
	if(fi != stdin)
		(void) fclose(fi);
#ifdef S5EMUL	/* XXX - BOTH versions should probably do this! */
	if(intrupt)
		(void) kill(getpid(), SIGINT);
#endif
	return(pbuf);
}

static void
catch(void)
{
	++intrupt;
}
