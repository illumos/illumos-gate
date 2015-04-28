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
 * Copyright 2015 Circonus, Inc.  All rights reserved.
 */

/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Print the name of the siginfo indicated by "sig", along with the
 * supplied message
 */

#include "lint.h"
#include "_libc_gettext.h"
#include <sys/types.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <siginfo.h>

#define	strsignal(i)	(_libc_gettext(_sys_siglistp[i]))

void
psiginfo(const siginfo_t *sip, const char *s)
{
	char buf[256];
	char *c;
	const struct siginfolist *listp;

	if (sip == 0)
		return;


	if (sip->si_code <= 0) {
		(void) snprintf(buf, sizeof (buf),
		    _libc_gettext("%s : %s ( from process  %d )\n"),
		    s, strsignal(sip->si_signo), sip->si_pid);
	} else if (((listp = &_sys_siginfolist[sip->si_signo-1]) != NULL) &&
	    sip->si_code <= listp->nsiginfo) {
		c = _libc_gettext(listp->vsiginfo[sip->si_code-1]);
		switch (sip->si_signo) {
		case SIGSEGV:
		case SIGBUS:
		case SIGILL:
		case SIGFPE:
			(void) snprintf(buf, sizeof (buf),
			    _libc_gettext("%s : %s ( [%p] %s)\n"),
			    s, strsignal(sip->si_signo),
			    sip->si_addr, c);
			break;
		default:
			(void) snprintf(buf, sizeof (buf),
			    _libc_gettext("%s : %s (%s)\n"),
			    s, strsignal(sip->si_signo), c);
			break;
		}
	} else {
		(void) snprintf(buf, sizeof (buf),
		    _libc_gettext("%s : %s\n"),
		    s, strsignal(sip->si_signo));
	}
	(void) write(2, buf, strlen(buf));
}
