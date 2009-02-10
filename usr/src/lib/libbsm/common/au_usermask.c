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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/types.h>
#include <stdio.h>
#include <bsm/audit.h>
#include <bsm/libbsm.h>

#define	AUDITSTRING_LEN 512

/*
 * Initialize audit preselection mask. This function should be used
 * by applications like login that set the process preselection mask
 * when a connection or a session is created.
 *
 * First, the system wide default audit flags are obtained
 *	from the audit_control(5) file.
 *
 * Next, the "always audit" flags, obtained from the audit_user(5) database,
 *	are added.
 *
 * Finally, the "never audit" flags, also obtained from the audit_user(5)
 *	database, are subtracted.
 *
 * The mask returned can be expressed as:
 *
 * (default audit flags + alway audit flags) - never audit flags
 *
 * If the lookup to audit_control(5) fails, then this function returns
 * an error.  If the lookup to audit_user(5), the function silently
 * continues.
 */
int
au_user_mask(char *username, au_mask_t *p_mask)
{
	char auditstring[AUDITSTRING_LEN];
	au_user_ent_t *p_user = NULL;
	int retval = -1;

	if (p_mask == NULL)
		return (-1);

	/*
	 * Get the system wide default audit flags out of the audit_control(5)
	 * file.
	 */
	setac();
	if (getacflg(auditstring, AUDITSTRING_LEN) == 0) {
		if (getauditflagsbin(auditstring, p_mask) == 0) {
			retval = 0;
		}
	}
	endac();

	/*
	 * If you can't get the system wide flags, return an error code
	 * now and don't bother trying to get the user specific flags.
	 */
	if (retval != 0) {
		return (-1);
	}

	/*
	 * Get the always audit flags and the never audit flags from
	 * the audit_user(5) database.
	 */
	setauuser();
	if ((p_user = getauusernam(username)) != (au_user_ent_t *)NULL) {
		/* Add always audit flags. */
		p_mask->as_success |= p_user->au_always.as_success;
		p_mask->as_failure |= p_user->au_always.as_failure;
		/* Subtract never audit flags.  */
		p_mask->as_success &= ~(p_user->au_never.as_success);
		p_mask->as_failure &= ~(p_user->au_never.as_failure);
	}
	endauuser();

	return (0);
}
