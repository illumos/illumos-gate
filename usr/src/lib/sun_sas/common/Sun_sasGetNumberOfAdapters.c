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
/*
 * Copyright 2019 Joyent, Inc.
 */

#include <sun_sas.h>

/*
 * Returns the number of HBAs supported by the library.  This returns the
 * current number of HBAs, even if this changes
 */
HBA_UINT32
Sun_sasGetNumberOfAdapters(void)
{
	int count;
	struct sun_sas_hba	*hba_ptr;

	lock(&all_hbas_lock);
	/* goes through hba list counting all the hbas found */
	for (count = 0, hba_ptr = global_hba_head;
	    hba_ptr != NULL; hba_ptr = hba_ptr->next, count++) {}

	unlock(&all_hbas_lock);

	return (count);
}
