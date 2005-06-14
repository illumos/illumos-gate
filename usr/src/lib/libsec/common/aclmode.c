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
 * Copyright (c) 1993-1997 by Sun Microsystems, Inc.
 * All rights reserved
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"
/* LINTLIBRARY */

/*
 * Convert ACL to/from permission bits
 */

#include <errno.h>
#include <sys/acl.h>

int
acltomode(aclent_t *aclbufp, int nentries, mode_t *modep)
{
	aclent_t		*tp;
	unsigned long		mode;
	unsigned long		grpmode;
	unsigned long		mask;
	int			which;
	int			got_mask = 0;

	*modep = 0;
	if (aclcheck(aclbufp, nentries, &which) != 0) {
		errno = EINVAL;
		return (-1);	/* errno is set in aclcheck() */
	}
	for (tp = aclbufp; nentries--; tp++) {
		if (tp->a_type == USER_OBJ) {
			mode = tp->a_perm;
			if (mode > 07)
				return (-1);
			*modep |= (mode << 6);
			continue;
		}
		if (tp->a_type == GROUP_OBJ) {
			grpmode = tp->a_perm;
			if (grpmode > 07)
				return (-1);
			continue;
		}
		if (tp->a_type == CLASS_OBJ) {
			got_mask = 1;
			mask = tp->a_perm;
			if (mask > 07)
				return (-1);
			*modep |= (mask << 3);
			continue;
		}
		if (tp->a_type == OTHER_OBJ) {
			mode = tp->a_perm;
			if (mode > 07)
				return (-1);
			*modep |= mode;
			continue; /* we may break here if it is sorted */
		}
	}
	if (!got_mask)
		*modep |= (grpmode << 3);
	return (0);
}


int
aclfrommode(aclent_t *aclbufp, int nentries, mode_t *modep)
{
	aclent_t		*tp;
	aclent_t		*savp;
	mode_t 			mode;
	mode_t 			grpmode;
	int			which;
	int			got_mask = 0;

	if (aclcheck(aclbufp, nentries, &which) != 0) {
		errno = EINVAL;
		return (-1);	/* errno is set in aclcheck() */
	}
	for (tp = aclbufp; nentries--; tp++) {
		if (tp->a_type == USER_OBJ) {
			mode = (*modep & 0700);
			tp->a_perm = (mode >> 6);
			continue;
		}
		if (tp->a_type == GROUP_OBJ) {
			grpmode = (*modep & 070);
			savp = tp;
			continue;
		}
		if (tp->a_type == CLASS_OBJ) {
			got_mask = 1;
			mode = (*modep & 070);
			tp->a_perm = (mode >> 3);
			continue;
		}
		if (tp->a_type == OTHER_OBJ) {
			mode = (*modep & 07);
			tp->a_perm = (o_mode_t)mode;
			continue; /* we may break here if it is sorted */
		}
	}
	if (!got_mask)
		savp->a_perm = (grpmode >> 3);
	return (0);
}
