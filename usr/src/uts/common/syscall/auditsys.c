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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/systm.h>
#include <sys/errno.h>
#include <sys/policy.h>

#include <c2/audit.h>

/*ARGSUSED1*/
int
auditsys(struct auditcalls *uap, rval_t *rvp)
{
	int err;

	/*
	 * this ugly hack is because auditsys returns 0 for
	 * all cases except audit_active == 0 and
	 * uap->code  == BSM_AUDITCTRL || BSM_AUDITON || default)
	 */

	if (!audit_active)
		return (ENOTSUP);

	switch (uap->code) {
	case BSM_GETAUID:
	case BSM_SETAUID:
	case BSM_GETAUDIT:
	case BSM_SETAUDIT:
	case BSM_AUDIT:
		return (0);
	case BSM_AUDITCTL:
	case BSM_AUDITON:
		if ((int)uap->a1 == A_GETCOND)
			err = secpolicy_audit_getattr(CRED());
		else
			/* FALLTHROUGH */
	default:
		/* Return a different error when not privileged */
		err = secpolicy_audit_config(CRED());
		if (err == 0)
			return (EINVAL);
		else
			return (err);
	}
}
