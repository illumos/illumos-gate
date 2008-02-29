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

#include <cma.h>

#include <sys/fm/ldom.h>

#include <assert.h>
#include <errno.h>
#include <sys/mem.h>

extern ldom_hdl_t *cma_lhp;

/*
 * cma_page_cmd()
 *    Retire a page or check if it is retired.
 *    Return: 0 upon successful, -1 otherwise.
 */
int
cma_page_cmd(fmd_hdl_t *hdl, int cmd, nvlist_t *nvl)
{
	int rc;

	fmd_hdl_debug(hdl, "cma_page_cmd(%d)\n", cmd);

	switch (cmd) {
	case MEM_PAGE_FMRI_RETIRE:
		rc = ldom_fmri_retire(cma_lhp, nvl);
		break;
	case MEM_PAGE_FMRI_UNRETIRE:
		rc = ldom_fmri_unretire(cma_lhp, nvl);
		break;
	case MEM_PAGE_FMRI_ISRETIRED:
		rc = ldom_fmri_status(cma_lhp, nvl);
		break;
	default:
		errno = EINVAL;
		rc = -1;
	}

	if (rc > 0) {
		errno = rc;
		rc = -1;
	}

	return (rc);
}
