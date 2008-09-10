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

#include <fm/fmd_api.h>
#include <fm/fmd_agent.h>
#include <fm/fmd_fmri.h>

#ifdef i386
/*
 * On x86, we call topo interfaces to invoke the retire/unretire methods in the
 * corresponding topo node.
 *
 */
int
cma_fmri_page_service_state(fmd_hdl_t *hdl, nvlist_t *nvl)
{
	return (fmd_nvl_fmri_service_state(hdl, nvl));
}

int
cma_fmri_page_retire(fmd_hdl_t *hdl, nvlist_t *nvl)
{
	return (fmd_nvl_fmri_retire(hdl, nvl));
}

int
cma_fmri_page_unretire(fmd_hdl_t *hdl, nvlist_t *nvl)
{
	return (fmd_nvl_fmri_unretire(hdl, nvl));
}
#else
/* ARGSUSED */
int
cma_fmri_page_service_state(fmd_hdl_t *hdl, nvlist_t *nvl)
{
	fmd_agent_hdl_t *fa_hdl;
	int rc = FMD_SERVICE_STATE_UNKNOWN;

	if ((fa_hdl = fmd_agent_open(FMD_AGENT_VERSION)) != NULL) {
		rc = fmd_agent_page_isretired(fa_hdl, nvl);
		if (rc == FMD_AGENT_RETIRE_DONE)
			rc = FMD_SERVICE_STATE_UNUSABLE;
		else if (rc == FMD_AGENT_RETIRE_FAIL)
			rc = FMD_SERVICE_STATE_OK;
		else if (rc == FMD_AGENT_RETIRE_ASYNC)
			rc = FMD_SERVICE_STATE_ISOLATE_PENDING;
		fmd_agent_close(fa_hdl);
	}

	return (rc);
}

/* ARGSUSED */
int
cma_fmri_page_retire(fmd_hdl_t *hdl, nvlist_t *nvl)
{
	fmd_agent_hdl_t *fa_hdl;
	int rc = FMD_AGENT_RETIRE_FAIL;

	if ((fa_hdl = fmd_agent_open(FMD_AGENT_VERSION)) != NULL) {
		rc = fmd_agent_page_retire(fa_hdl, nvl);
		fmd_agent_close(fa_hdl);
	}

	return (rc);
}

/* ARGSUSED */
int
cma_fmri_page_unretire(fmd_hdl_t *hdl, nvlist_t *nvl)
{
	fmd_agent_hdl_t *fa_hdl;
	int rc = FMD_AGENT_RETIRE_FAIL;

	if ((fa_hdl = fmd_agent_open(FMD_AGENT_VERSION)) != NULL) {
		rc = fmd_agent_page_unretire(fa_hdl, nvl);
		fmd_agent_close(fa_hdl);
	}

	return (rc);
}
#endif
