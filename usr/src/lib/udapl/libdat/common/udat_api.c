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
 * Copyright (c) 2002-2003, Network Appliance, Inc. All rights reserved.
 */

/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"


/*
 *
 * MODULE: udat_api.c
 *
 * PURPOSE: DAT Provider and Consumer registry functions.
 *
 */

#include "dat_osd.h"
#include <dat/dat_registry.h>

DAT_RETURN dat_lmr_create(
	IN	DAT_IA_HANDLE		ia_handle,
	IN	DAT_MEM_TYPE		mem_type,
	IN	DAT_REGION_DESCRIPTION	region_description,
	IN	DAT_VLEN		length,
	IN	DAT_PZ_HANDLE		pz_handle,
	IN	DAT_MEM_PRIV_FLAGS	privileges,
	OUT	DAT_LMR_HANDLE		*lmr_handle,
	OUT	DAT_LMR_CONTEXT		*lmr_context,
	OUT	DAT_RMR_CONTEXT		*rmr_context,
	OUT	DAT_VLEN 		*registered_length,
	OUT	DAT_VADDR 		*registered_address)
{
	if (DAT_BAD_HANDLE(ia_handle)) {
		return (DAT_ERROR(DAT_INVALID_HANDLE, DAT_INVALID_HANDLE_IA));
	}
	return DAT_LMR_CREATE(ia_handle,
			    mem_type,
			    region_description,
			    length,
			    pz_handle,
			    privileges,
			    lmr_handle,
			    lmr_context,
			    rmr_context,
			    registered_length,
			    registered_address);
}


DAT_RETURN dat_evd_create(
	IN	DAT_IA_HANDLE		ia_handle,
	IN	DAT_COUNT		evd_min_qlen,
	IN	DAT_CNO_HANDLE		cno_handle,
	IN	DAT_EVD_FLAGS		evd_flags,
	OUT	DAT_EVD_HANDLE		*evd_handle)
{
	if (DAT_BAD_HANDLE(ia_handle)) {
		return (DAT_ERROR(DAT_INVALID_HANDLE, DAT_INVALID_HANDLE_IA));
	}
	return DAT_EVD_CREATE(ia_handle,
			    evd_min_qlen,
			    cno_handle,
			    evd_flags,
			    evd_handle);
}


DAT_RETURN dat_evd_modify_cno(
	IN	DAT_EVD_HANDLE		evd_handle,
	IN	DAT_CNO_HANDLE		cno_handle)
{
	if (DAT_BAD_HANDLE(evd_handle)) {
		return (DAT_ERROR(DAT_INVALID_HANDLE, DAT_INVALID_HANDLE1));
	}
	return DAT_EVD_MODIFY_CNO(evd_handle,
				cno_handle);
}


DAT_RETURN dat_cno_create(
	IN 	DAT_IA_HANDLE		ia_handle,
	IN 	DAT_OS_WAIT_PROXY_AGENT agent,
	OUT	DAT_CNO_HANDLE		*cno_handle)
{
	if (DAT_BAD_HANDLE(ia_handle)) {
		return (DAT_ERROR(DAT_INVALID_HANDLE, DAT_INVALID_HANDLE_IA));
	}
	return DAT_CNO_CREATE(ia_handle,
			    agent,
			    cno_handle);
}


DAT_RETURN dat_cno_modify_agent(
	IN 	DAT_CNO_HANDLE		 cno_handle,
	IN 	DAT_OS_WAIT_PROXY_AGENT	 agent)
{
	if (DAT_BAD_HANDLE(cno_handle)) {
		return (DAT_ERROR(DAT_INVALID_HANDLE, DAT_INVALID_HANDLE_CNO));
	}
	return DAT_CNO_MODIFY_AGENT(cno_handle,
				agent);
}


DAT_RETURN dat_cno_query(
	IN	DAT_CNO_HANDLE		cno_handle,
	IN	DAT_CNO_PARAM_MASK	cno_param_mask,
	OUT	DAT_CNO_PARAM		*cno_param)
{
	if (DAT_BAD_HANDLE(cno_handle)) {
		return (DAT_ERROR(DAT_INVALID_HANDLE, DAT_INVALID_HANDLE_CNO));
	}
	return DAT_CNO_QUERY(cno_handle,
			cno_param_mask,
			cno_param);
}


DAT_RETURN dat_cno_free(
	IN DAT_CNO_HANDLE		cno_handle)
{
	if (DAT_BAD_HANDLE(cno_handle)) {
		return (DAT_ERROR(DAT_INVALID_HANDLE, DAT_INVALID_HANDLE_CNO));
	}
	return (DAT_CNO_FREE(cno_handle));
}


DAT_RETURN dat_cno_wait(
	IN  	DAT_CNO_HANDLE		cno_handle,
	IN  	DAT_TIMEOUT		timeout,
	OUT 	DAT_EVD_HANDLE		*evd_handle)
{
	if (DAT_BAD_HANDLE(cno_handle)) {
		return (DAT_ERROR(DAT_INVALID_HANDLE, DAT_INVALID_HANDLE_CNO));
	}
	return DAT_CNO_WAIT(cno_handle,
			timeout,
			evd_handle);
}


DAT_RETURN dat_evd_enable(
	IN	DAT_EVD_HANDLE		evd_handle)
{
	if (DAT_BAD_HANDLE(evd_handle)) {
		return (DAT_ERROR(DAT_INVALID_HANDLE, DAT_INVALID_HANDLE1));
	}
	return (DAT_EVD_ENABLE(evd_handle));
}


DAT_RETURN dat_evd_wait(
	IN  	DAT_EVD_HANDLE		evd_handle,
	IN  	DAT_TIMEOUT		Timeout,
	IN  	DAT_COUNT		Threshold,
	OUT 	DAT_EVENT		*event,
	OUT 	DAT_COUNT		*n_more_events)
{
	if (DAT_BAD_HANDLE(evd_handle)) {
		return (DAT_ERROR(DAT_INVALID_HANDLE, DAT_INVALID_HANDLE1));
	}
	return DAT_EVD_WAIT(evd_handle,
			Timeout,
			Threshold,
			event,
			n_more_events);
}


DAT_RETURN dat_evd_disable(
	IN	DAT_EVD_HANDLE		evd_handle)
{
	if (DAT_BAD_HANDLE(evd_handle)) {
		return (DAT_ERROR(DAT_INVALID_HANDLE, DAT_INVALID_HANDLE1));
	}
	return (DAT_EVD_DISABLE(evd_handle));
}


DAT_RETURN dat_evd_set_unwaitable(
	IN 	DAT_EVD_HANDLE		 evd_handle)
{
	if (DAT_BAD_HANDLE(evd_handle)) {
		return (DAT_ERROR(DAT_INVALID_HANDLE, DAT_INVALID_HANDLE1));
	}
	return (DAT_EVD_SET_UNWAITABLE(evd_handle));
}

DAT_RETURN dat_evd_clear_unwaitable(
	IN 	DAT_EVD_HANDLE		 evd_handle)
{
	if (DAT_BAD_HANDLE(evd_handle)) {
		return (DAT_ERROR(DAT_INVALID_HANDLE, DAT_INVALID_HANDLE1));
	}
	return (DAT_EVD_CLEAR_UNWAITABLE(evd_handle));
}

DAT_RETURN dat_cr_handoff(
	IN	DAT_CR_HANDLE		cr_handle,
	IN	DAT_CONN_QUAL		handoff)
{
	if (DAT_BAD_HANDLE(cr_handle)) {
		return (DAT_ERROR(DAT_INVALID_HANDLE, DAT_INVALID_HANDLE_CR));
	}
	return DAT_CR_HANDOFF(cr_handle,
			handoff);
}


DAT_RETURN dat_psp_create_any(
	IN	DAT_IA_HANDLE		ia_handle,
	OUT	DAT_CONN_QUAL		*conn_qual,
	IN	DAT_EVD_HANDLE		evd_handle,
	IN	DAT_PSP_FLAGS		psp_flags,
	OUT	DAT_PSP_HANDLE		*psp_handle)
{
	if (DAT_BAD_HANDLE(ia_handle)) {
		return (DAT_ERROR(DAT_INVALID_HANDLE, DAT_INVALID_HANDLE_IA));
	}
	return DAT_PSP_CREATE_ANY(ia_handle,
			    conn_qual,
			    evd_handle,
			    psp_flags,
			    psp_handle);
}


DAT_RETURN dat_ia_query(
	IN	DAT_IA_HANDLE		ia_handle,
	OUT	DAT_EVD_HANDLE		*async_evd_handle,
	IN	DAT_IA_ATTR_MASK	ia_attr_mask,
	OUT	DAT_IA_ATTR		*ia_attr,
	IN	DAT_PROVIDER_ATTR_MASK	provider_attr_mask,
	OUT	DAT_PROVIDER_ATTR 	*provider_attr)
{
	if (DAT_BAD_HANDLE(ia_handle)) {
		return (DAT_ERROR(DAT_INVALID_HANDLE, DAT_INVALID_HANDLE_IA));
	}
	return DAT_IA_QUERY(ia_handle,
			async_evd_handle,
			ia_attr_mask,
			ia_attr,
			provider_attr_mask,
			provider_attr);
}


DAT_RETURN dat_evd_query(
	IN	DAT_EVD_HANDLE		evd_handle,
	IN	DAT_EVD_PARAM_MASK	evd_param_mask,
	OUT	DAT_EVD_PARAM		*evd_param)
{
	if (DAT_BAD_HANDLE(evd_handle)) {
		return (DAT_ERROR(DAT_INVALID_HANDLE, DAT_INVALID_HANDLE1));
	}
	return DAT_EVD_QUERY(evd_handle,
			evd_param_mask,
			evd_param);
}


DAT_RETURN dat_lmr_query(
	IN	DAT_LMR_HANDLE		lmr_handle,
	IN	DAT_LMR_PARAM_MASK	lmv_param_mask,
	OUT	DAT_LMR_PARAM		*lmr_param)
{
	if (DAT_BAD_HANDLE(lmr_handle)) {
		return (DAT_ERROR(DAT_INVALID_HANDLE, DAT_INVALID_HANDLE_LMR));
	}
	return DAT_LMR_QUERY(lmr_handle,
		    lmv_param_mask,
		    lmr_param);
}
