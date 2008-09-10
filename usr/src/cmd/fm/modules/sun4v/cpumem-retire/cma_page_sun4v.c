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

#include <sys/fm/ldom.h>
#include <errno.h>
#include <fm/fmd_api.h>
#include <fm/fmd_agent.h>
#include <fm/fmd_fmri.h>

extern ldom_hdl_t *cma_lhp;

/* ARGSUSED */
int
cma_fmri_page_service_state(fmd_hdl_t *hdl, nvlist_t *nvl)
{
	errno = ldom_fmri_status(cma_lhp, nvl);

	if (errno == 0 || errno == EINVAL)
		return (FMD_SERVICE_STATE_UNUSABLE);
	if (errno == EAGAIN)
		return (FMD_SERVICE_STATE_ISOLATE_PENDING);

	return (FMD_SERVICE_STATE_OK);
}

/* ARGSUSED */
int
cma_fmri_page_retire(fmd_hdl_t *hdl, nvlist_t *nvl)
{
	errno = ldom_fmri_retire(cma_lhp, nvl);

	if (errno == 0 || errno == EIO || errno == EINVAL)
		return (FMD_AGENT_RETIRE_DONE);
	if (errno == EAGAIN)
		return (FMD_AGENT_RETIRE_ASYNC);

	return (FMD_AGENT_RETIRE_FAIL);
}

/* ARGSUSED */
int
cma_fmri_page_unretire(fmd_hdl_t *hdl, nvlist_t *nvl)
{
	errno = ldom_fmri_unretire(cma_lhp, nvl);

	if (errno == 0 || errno == EIO)
		return (FMD_AGENT_RETIRE_DONE);

	return (FMD_AGENT_RETIRE_FAIL);
}
