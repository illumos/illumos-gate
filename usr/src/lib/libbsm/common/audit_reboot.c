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
 * Copyright (c) 2000, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <bsm/audit.h>
#include <bsm/audit_record.h>
#include <bsm/audit_uevents.h>
#include <bsm/libbsm.h>
#include <bsm/audit_private.h>
#include <generic.h>

#ifdef C2_DEBUG
#define	dprintf(x) { (void) printf x; }
#else
#define	dprintf(x)
#endif

static int audit_reboot_generic(int);

int
audit_reboot_setup()
{
	dprintf(("audit_reboot_setup()\n"));

	if (cannot_audit(0)) {
		return (0);
	}

	(void) aug_init();
	aug_save_event(AUE_reboot_solaris);
	(void) aug_save_me();
	return (0);
}

int
audit_reboot_fail()
{
	return (audit_reboot_generic(-1));
}

int
audit_reboot_success()
{
	int res = 0;

	(void) audit_reboot_generic(0);
	/*
	 * wait for audit daemon
	 * to put reboot message onto audit trail
	 */
	if (!cannot_audit(0)) {
		int cond = AUC_NOAUDIT;
		int canaudit;

		(void) sleep(1);

		/* find out if audit daemon is running */
		(void) auditon(A_GETCOND, (caddr_t)&cond, sizeof (cond));
		canaudit = ((cond == AUC_AUDITING) || (cond == AUC_NOSPACE));

		/* turn off audit daemon and try to flush audit queue */
		if (canaudit && system("/usr/sbin/audit -T"))
			res = -1;

		(void) sleep(5);
	}

	return (res);
}

int
audit_reboot_generic(int sorf)
{
	dprintf(("audit_reboot_generic(%d)\n", sorf));

	if (cannot_audit(0)) {
		return (0);
	}

	aug_save_sorf(sorf);
	(void) aug_audit();

	return (0);
}
