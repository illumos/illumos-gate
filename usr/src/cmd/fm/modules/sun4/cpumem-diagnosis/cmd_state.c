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

/*
 * Case management and saved state restoration
 */

#include <cmd_state.h>
#include <cmd_cpu.h>
#include <cmd_mem.h>
#include <cmd_page.h>
#include <cmd_dimm.h>
#ifdef sun4u
#include <cmd_dp.h>
#include <cmd_dp_page.h>
#endif
#include <cmd_bank.h>
#include <cmd.h>
#ifdef sun4v
#include <cmd_branch.h>
#endif

#include <string.h>
#include <fm/fmd_api.h>

#ifdef sun4u
#include <cmd_opl.h>
#endif

/* Must be in sync with cmd_ptrsubtype_t */
static cmd_case_closer_f *const cmd_case_closers[] = {
	NULL,
	cmd_cpuerr_close,	/* CMD_PTR_CPU_ICACHE */
	cmd_cpuerr_close,	/* CMD_PTR_CPU_DCACHE */
	cmd_cpuerr_close,	/* CMD_PTR_CPU_PCACHE */
	cmd_cpuerr_close,	/* CMD_PTR_CPU_ITLB */
	cmd_cpuerr_close,	/* CMD_PTR_CPU_DTLB */
	cmd_cpuerr_close,	/* CMD_PTR_CPU_L2DATA */
	cmd_cpuerr_close,	/* CMD_PTR_CPU_L2DATA_UERETRY */
	cmd_cpuerr_close,	/* CMD_PTR_CPU_L2TAG */
	cmd_cpuerr_close,	/* CMD_PTR_CPU_L3DATA */
	cmd_cpuerr_close,	/* CMD_PTR_CPU_L3DATA_UERETRY */
	cmd_cpuerr_close,	/* CMD_PTR_CPU_L3TAG */
	cmd_dimm_close,		/* CMD_PTR_DIMM_CASE */
	cmd_bank_close,		/* CMD_PTR_BANK_CASE */
	cmd_page_close,		/* CMD_PTR_PAGE_CASE */
	cmd_cpuerr_close,	/* CMD_PTR_CPU_FPU */
	NULL,			/* CMD_PTR_CPU_XR_RETRY */
	cmd_cpuerr_close,	/* CMD_PTR_CPU_IREG */
	cmd_cpuerr_close,	/* CMD_PTR_CPU_FREG */
	cmd_cpuerr_close,	/* CMD_PTR_CPU_MAU */
	cmd_cpuerr_close,	/* CMD_PTR_CPU_L2CTL */
#ifdef sun4u
	cmd_dp_close,		/* CMD_PTR_DP_CASE */
#else
	NULL,			/* CMD_PTR_DP_CASE */
#endif
	NULL,			/* CMD_PTR_DP_PAGE_DEFER */
	cmd_cpuerr_close,	/* CMD_PTR_CPU_INV_SFSR */
	cmd_cpuerr_close,	/* CMD_PTR_CPU_UE_DET_CPU */
	cmd_cpuerr_close,	/* CMD_PTR_CPU_UE_DET_IO */
	cmd_cpuerr_close,	/* CMD_PTR_CPU_MTLB */
	cmd_cpuerr_close,	/* CMD_PTR_CPU_TLBP */
	cmd_cpuerr_close,	/* CMD_PTR_CPU_UGESR_INV_URG */
	cmd_cpuerr_close,	/* CMD_PTR_CPU_UGESR_CRE */
	cmd_cpuerr_close,	/* CMD_PTR_CPU_UGESR_TSB_CTX */
	cmd_cpuerr_close,	/* CMD_PTR_CPU_UGESR_TSBP */
	cmd_cpuerr_close,	/* CMD_PTR_CPU_UGESR_PSTATE */
	cmd_cpuerr_close,	/* CMD_PTR_CPU_UGESR_TSTATE */
	cmd_cpuerr_close,	/* CMD_PTR_CPU_UGESR_IUG_F */
	cmd_cpuerr_close,	/* CMD_PTR_CPU_UGESR_IUG_R */
	cmd_cpuerr_close,	/* CMD_PTR_CPU_UGESR_SDC */
	cmd_cpuerr_close,	/* CMD_PTR_CPU_UGESR_WDT */
	cmd_cpuerr_close,	/* CMD_PTR_CPU_UGESR_DTLB */
	cmd_cpuerr_close,	/* CMD_PTR_CPU_UGESR_ITLB */
	cmd_cpuerr_close,	/* CMD_PTR_CPU_UGESR_CORE_ERR */
	cmd_cpuerr_close,	/* CMD_PTR_CPU_UGESR_DAE */
	cmd_cpuerr_close,	/* CMD_PTR_CPU_UGESR_IAE */
	cmd_cpuerr_close,	/* CMD_PTR_CPU_UGESR_UGE */
	cmd_cpuerr_close,	/* CMD_PTR_CPU_MISC_REGS */
	cmd_cpuerr_close,	/* CMD_PTR_CPU_LFU */
#ifdef sun4v
	cmd_branch_close	/* CMD_PTR_BRANCH_CASE */
#else
	NULL
#endif
};

fmd_case_t *
cmd_case_create(fmd_hdl_t *hdl, cmd_header_t *hdr, cmd_ptrsubtype_t ptrsubtype,
    const char **uuidp)
{
	cmd_case_ptr_t ptr;
	cmd_case_closer_t *cl;
	fmd_case_t *cp;

	cl = fmd_hdl_alloc(hdl, sizeof (cmd_case_closer_t), FMD_SLEEP);
	cl->cl_func = cmd_case_closers[ptrsubtype];
	cl->cl_arg = hdr;

	cp = fmd_case_open(hdl, cl);

	ptr.ptr_type = hdr->hdr_nodetype;
	ptr.ptr_subtype = ptrsubtype;
	(void) strcpy(ptr.ptr_name, hdr->hdr_bufname);

	*uuidp = fmd_case_uuid(hdl, cp);
	fmd_buf_write(hdl, cp, *uuidp, &ptr, sizeof (cmd_case_ptr_t));

	return (cp);
}

void
cmd_case_redirect(fmd_hdl_t *hdl, fmd_case_t *cp, cmd_ptrsubtype_t newsubtype)
{
	const char *uuid = fmd_case_uuid(hdl, cp);
	cmd_case_ptr_t ptr;

	fmd_buf_read(hdl, cp, uuid, &ptr, sizeof (cmd_case_ptr_t));
	fmd_hdl_debug(hdl, "redirecting case %s from %d to %d\n", uuid,
	    ptr.ptr_subtype, newsubtype);
	ptr.ptr_subtype = newsubtype;
	fmd_buf_write(hdl, cp, uuid, &ptr, sizeof (cmd_case_ptr_t));
}

void
cmd_case_fini(fmd_hdl_t *hdl, fmd_case_t *cp, int close)
{
	const char *uuid = fmd_case_uuid(hdl, cp);
	cmd_case_closer_t *cl = fmd_case_getspecific(hdl, cp);

	if (close) {
		fmd_hdl_debug(hdl, "closing case %s\n", uuid);

		if (fmd_serd_exists(hdl, uuid))
			fmd_serd_destroy(hdl, uuid);

		if (fmd_buf_size(hdl, cp, uuid) != 0)
			fmd_buf_destroy(hdl, cp, uuid);

		fmd_case_setspecific(hdl, cp, NULL);
		fmd_case_close(hdl, cp);
	}

	if (cl != NULL)
		fmd_hdl_free(hdl, cl, sizeof (cmd_case_closer_t));
}

/* Must be in sync with cmd_nodetype_t */
static cmd_case_restorer_f *const cmd_case_restorers[] = {
	NULL,
	cmd_cpu_restore,	/* CMD_NT_CPU */
	cmd_dimm_restore,	/* CMD_NT_DIMM */
	cmd_bank_restore,	/* CMD_NT_BANK */
	cmd_page_restore,	/* CMD_NT_PAGE */
#ifdef sun4u
	cmd_dp_restore		/* CMD_NT_DP */
#endif
#ifdef sun4v
	cmd_branch_restore	/* CMD_NT_BRANCH */
#endif
};

int
cmd_state_restore(fmd_hdl_t *hdl)
{
	fmd_case_t *cp = NULL;

	while ((cp = fmd_case_next(hdl, cp)) != NULL) {
		const char *uuid = fmd_case_uuid(hdl, cp);
		cmd_case_closer_t *cl;
		cmd_case_ptr_t ptr;
		void *thing;
		size_t sz;

		if ((sz = fmd_buf_size(hdl, cp, uuid)) == 0)
			continue;
		else if (sz != sizeof (cmd_case_ptr_t))
			return (cmd_set_errno(EINVAL));

		fmd_buf_read(hdl, cp, fmd_case_uuid(hdl, cp), &ptr,
		    sizeof (cmd_case_ptr_t));

		if (ptr.ptr_type == 0 || ptr.ptr_type >
		    sizeof (cmd_case_restorers) /
		    sizeof (cmd_case_restorer_f *))
			return (cmd_set_errno(EINVAL));

		if ((thing = cmd_case_restorers[ptr.ptr_type](hdl,
		    cp, &ptr)) == NULL) {
			fmd_hdl_debug(hdl, "Unable to restore case %s\n", uuid);
			continue;
		}

		cl = fmd_hdl_alloc(hdl, sizeof (cmd_case_closer_t), FMD_SLEEP);
		cl->cl_func = cmd_case_closers[ptr.ptr_subtype];
		cl->cl_arg = thing;
		fmd_case_setspecific(hdl, cp, cl);
	}

	cmd_trw_restore(hdl);

	cmd_cpu_validate(hdl);
	cmd_bank_validate(hdl);
	cmd_dimm_validate(hdl);
#ifdef sun4u
	/*
	 * cmd_dp_page_validate() must be done before cmd_dp_validate()
	 * and cmd_page_validate()
	 */
	cmd_dp_page_validate(hdl);
	cmd_dp_validate(hdl);
#endif
	cmd_page_validate(hdl);
#ifdef sun4v
	cmd_branch_validate(hdl);
#endif

	return (0);
}

void
cmd_case_restore(fmd_hdl_t *hdl, cmd_case_t *cc, fmd_case_t *cp, char *serdnm)
{
	if (!fmd_serd_exists(hdl, serdnm)) {
		fmd_hdl_strfree(hdl, serdnm);
		serdnm = NULL;
	}

	cc->cc_cp = cp;
	cc->cc_serdnm = serdnm;
}
