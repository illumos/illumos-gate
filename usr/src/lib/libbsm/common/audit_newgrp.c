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
#include <bsm/audit.h>
#include <bsm/audit_uevents.h>
#include <bsm/audit_private.h>
#include <stdio.h>
#include <generic.h>

#ifdef C2_DEBUG
#define	dprintf(x) {printf x; }
#else
#define	dprintf(x)
#endif


void
audit_newgrp_login(char *newgrp, int sorf)
{
	dprintf(("audit_newgrp_login(%d)\n", sorf));

	if (cannot_audit(0)) {
		return;
	}

	(void) aug_init();
	aug_save_text(newgrp);
	(void) aug_save_me();
	aug_save_event(AUE_newgrp_login);
	aug_save_sorf(sorf);

	(void) aug_audit();
}
