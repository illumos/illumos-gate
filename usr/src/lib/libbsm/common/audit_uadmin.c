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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/fcntl.h>
#include <bsm/audit.h>
#include <bsm/audit_record.h>
#include <bsm/audit_uevents.h>
#include <bsm/libbsm.h>
#include <bsm/audit_private.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <netinet/in.h>
#include <generic.h>

#ifdef C2_DEBUG
#define	dprintf(x) {printf x; }
#else
#define	dprintf(x)
#endif

static char	**gargv;
static int	save_afunc();

static int audit_uadmin_generic(int);

/* ARGSUSED */
int
audit_uadmin_setup(int argc, char **argv)
{
	dprintf(("audit_uadmin_setup()\n"));

	if (cannot_audit(0)) {
		return (0);
	}
	gargv = argv;

	(void) aug_init();
	aug_save_event(AUE_uadmin_solaris);
	(void) aug_save_me();
	aug_save_afunc(save_afunc);
	return (0);
}

static int
save_afunc(int ad)
{
	if (gargv && gargv[1])
		(void) au_write(ad, au_to_text(gargv[1]));
	if (gargv && gargv[2])
		(void) au_write(ad, au_to_text(gargv[2]));
	return (0);
}

int
audit_uadmin_fail()
{
	return (audit_uadmin_generic(-1));
}

int
audit_uadmin_success()
{
	int res = 0;

	(void) audit_uadmin_generic(0);

	/*
	 * wait for audit daemon to put halt message onto audit trail
	 */
	if (!cannot_audit(0)) {
		int cond = AUC_NOAUDIT;
		int canaudit;

		(void) sleep(1);

		/* find out if audit daemon is running */
		(void) auditon(A_GETCOND, (caddr_t)&cond,
			sizeof (cond));
		canaudit = ((cond == AUC_AUDITING) || (cond == AUC_NOSPACE));

		/* turn off audit daemon and try to flush audit queue */
		if (canaudit && system("/usr/sbin/audit -t"))
			res = -1;

		/* give a chance for syslogd to do the job */
		(void) sleep(5);
	}

	return (res);
}

int
audit_uadmin_generic(sorf)
	int sorf;
{
	int r;

	dprintf(("audit_uadmin_generic(%d)\n", sorf));

	if (cannot_audit(0)) {
		return (0);
	}

	aug_save_sorf(sorf);
	r = aug_audit();

	return (r);
}
