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
 * Copyright 1992-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Metadevice diskset interfaces
 */

#include "meta_lib_prv.h"
#include <sys/vfstab.h>

static 	FILE	*mfp = NULL;

FILE *
open_mnttab(void)
{
	if (mfp != NULL) {
		if (fseeko(mfp, (off_t)0L, SEEK_SET) == -1) {
			(void) fclose(mfp);
			mfp = NULL;
			return (NULL);
		}
		return (mfp);
	}

	if ((mfp = fopen(MNTTAB, "r")) == NULL)
		return (NULL);

	return (mfp);
}

int
close_mnttab(void)
{
	int	ret = -1;

	if (mfp == NULL)
		return (0);

	ret = fclose(mfp);

	mfp = NULL;

	return (ret);
}
