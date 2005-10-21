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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
/*
 * Need to include md_mddb.h for the MDDB_REV_MAJOR and MDDB_REV_MINOR
 * definitions.  The other files included are required for md_mddb.h.
 */
#ifdef _KERNEL
#include <sys/lvm/md_basic.h>
#include <sys/lvm/mdvar.h>
#else /* !_KERNEL */
#include <meta.h>
#endif /* _KERNEL */
#include <sys/lvm/md_mddb.h>


/*
 * revchk()
 * Checks the major and minor revision numbers for either an in-core or on-disk
 * directory block or record block against the currently defined major and
 * minor numbers(MDDB_REV_MAJOR and MDDB_REV_MINOR) to make sure that they are
 * compatible with this version of SVM.  For example, earlier versions of SVM
 * don't understand dummy masterblocks or deviceIDs in disksets.
 */
int
revchk(
	uint_t	my_rev,
	uint_t	data
)
{
	if ((MDDB_REV_MAJOR & my_rev) != (MDDB_REV_MAJOR & data))
		return (1);
	if ((MDDB_REV_MINOR & my_rev) < (MDDB_REV_MINOR & data))
		return (1);
	return (0);
}
