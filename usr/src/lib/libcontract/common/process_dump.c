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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/contract/process.h>
#include <sys/wait.h>
#include <sys/ctfs.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <limits.h>
#include <stdio.h>
#include <assert.h>
#include <signal.h>
#include <libuutil.h>
#include <libintl.h>
#include <libcontract.h>
#include <libcontract_priv.h>
#include "libcontract_impl.h"

void
event_process(FILE *file, ct_evthdl_t ev, int verbose)
{
	uint_t type;
	pid_t pid;
	char *s;

	type = ct_event_get_type(ev);
	if (ct_pr_event_get_pid(ev, &pid) != 0) {
		(void) fprintf(file, dgettext(TEXT_DOMAIN, "[bad event]\n"));
		return;
	}

	switch (type) {
	case CT_PR_EV_EMPTY:
		s = dgettext(TEXT_DOMAIN, "contract empty\n");
		break;
	case CT_PR_EV_FORK:
		s = dgettext(TEXT_DOMAIN, "process %d was created\n");
		break;
	case CT_PR_EV_EXIT:
		s = dgettext(TEXT_DOMAIN, "process %d exited\n");
		break;
	case CT_PR_EV_CORE:
		s = dgettext(TEXT_DOMAIN, "process %d dumped core\n");
		break;
	case CT_PR_EV_SIGNAL:
		s = dgettext(TEXT_DOMAIN,
		    "process %d received a fatal signal\n");
		break;
	case CT_PR_EV_HWERR:
		s = dgettext(TEXT_DOMAIN,
		    "process %d was killed by a hardware error\n");
		break;
	default:
		s = dgettext(TEXT_DOMAIN, "process %d sent an unknown event\n");
		break;
	}

	/*LINTED*/
	(void) fprintf(file, s, pid);
	if (!verbose)
		return;

	switch (type) {
		int i;
		const char *c;
		char buf[SIG2STR_MAX];
		ctid_t ctid;
	case CT_PR_EV_FORK:
		if (ct_pr_event_get_ppid(ev, &pid) == 0)
			(void) fprintf(file, dgettext(TEXT_DOMAIN,
			    "\tparent pid: %d\n"), pid);
		break;
	case CT_PR_EV_EXIT:
		if (ct_pr_event_get_exitstatus(ev, &i) != 0)
			break;
		(void) fprintf(file,
		    dgettext(TEXT_DOMAIN, "\twait status: 0x%x"), i);
		if (WIFEXITED(i)) {
			(void) fprintf(file, dgettext(TEXT_DOMAIN,
			    " (exited, code %d)\n"), WEXITSTATUS(i));
		} else if (WIFSIGNALED(i)) {
			int sig = WTERMSIG(i);
			(void) fprintf(file,
			    dgettext(TEXT_DOMAIN, " (signal %d"), sig);
			if (sig2str(sig, buf) == 0)
				(void) fprintf(file,
				    dgettext(TEXT_DOMAIN, " (SIG%s)"), buf);
			if (WCOREDUMP(i))
				(void) fprintf(file,
				    dgettext(TEXT_DOMAIN, ", core dumped)\n"));
			else
				(void) fprintf(file,
				    dgettext(TEXT_DOMAIN, ")\n"));
		} else {
			/*
			 * We really shouldn't get here.
			 */
			(void) fprintf(file, dgettext(TEXT_DOMAIN, "\n"));
		}
		break;
	case CT_PR_EV_CORE:
		if (ct_pr_event_get_pcorefile(ev, &c) == 0)
			(void) fprintf(file, dgettext(TEXT_DOMAIN,
			    "\tprocess core: %s\n"), c);
		if (ct_pr_event_get_gcorefile(ev, &c) == 0)
			(void) fprintf(file, dgettext(TEXT_DOMAIN,
			    "\tglobal core: %s\n"), c);
		if (ct_pr_event_get_zcorefile(ev, &c) == 0)
			(void) fprintf(file, dgettext(TEXT_DOMAIN,
			    "\tglobal zone core: %s\n"), c);
		break;
	case CT_PR_EV_SIGNAL:
		if (ct_pr_event_get_signal(ev, &i) == 0) {
			if (sig2str(i, buf) == -1)
				(void) fprintf(file, dgettext(TEXT_DOMAIN,
				    "\tsignal: %d\n"), i);
			else
				(void) fprintf(file, dgettext(TEXT_DOMAIN,
				    "\tsignal: %d (SIG%s)\n"), i, buf);
		}
		if (ct_pr_event_get_sender(ev, &pid) == 0)
			(void) fprintf(file, dgettext(TEXT_DOMAIN,
			    "\tsender pid: %d\n"), pid);
		if (ct_pr_event_get_senderct(ev, &ctid) == 0)
			(void) fprintf(file, dgettext(TEXT_DOMAIN,
			    "\tsender ctid: %d\n"), ctid);
		break;
	}
}
