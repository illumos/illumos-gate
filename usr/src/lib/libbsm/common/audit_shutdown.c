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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/types.h>
#include <stdio.h>
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
#define	dprintf(x) { (void) printf x; }
#else
#define	dprintf(x)
#endif

static int audit_shutdown_generic(int);

/* ARGSUSED */
int
audit_shutdown_setup(int argc, char **argv)
{
	dprintf(("audit_shutdown_setup()\n"));

	if (cannot_audit(0)) {
		return (0);
	}
	(void) aug_init();
	aug_save_event(AUE_shutdown_solaris);
	(void) aug_save_me();

	return (0);
}

int
audit_shutdown_fail()
{
	return (audit_shutdown_generic(-1));
}

int
audit_shutdown_success()
{
	return (audit_shutdown_generic(0));
}

static int
audit_shutdown_generic(sorf)
	int sorf;
{
	int r;

	dprintf(("audit_shutdown_generic(%d)\n", sorf));

	if (cannot_audit(0)) {
		return (0);
	}

	aug_save_sorf(sorf);
	r = aug_audit();

	return (r);
}
