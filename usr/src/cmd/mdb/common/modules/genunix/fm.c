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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/types.h>
#include <sys/time.h>
#include <sys/sysmacros.h>
#include <sys/ddifm.h>
#include <sys/nvpair.h>
#include <sys/nvpair_impl.h>
#include <sys/errorq_impl.h>
#include <sys/errorq.h>
#include <sys/fm/protocol.h>

#include <ctype.h>
#include <mdb/mdb_modapi.h>
#include <mdb/mdb_ks.h>

#include "nvpair.h"

int
ereportq_pend_walk_init(mdb_walk_state_t *wsp)
{
	errorq_t eq;
	uintptr_t addr;

	if (wsp->walk_addr == 0 &&
	    mdb_readvar(&addr, "ereport_errorq") == -1) {
		mdb_warn("failed to read ereport_errorq");
		return (WALK_ERR);
	}

	if (mdb_vread(&eq, sizeof (eq), addr) == -1) {
		mdb_warn("failed to read ereport_errorq at %p", addr);
		return (WALK_ERR);
	}

	if (!(eq.eq_flags & ERRORQ_NVLIST)) {
		mdb_warn("errorq at %p does not service ereports", addr);
		return (WALK_ERR);
	}

	wsp->walk_addr = (uintptr_t)eq.eq_pend;

	return (WALK_NEXT);
}

int
ereportq_pend_walk_step(mdb_walk_state_t *wsp)
{
	uintptr_t addr = wsp->walk_addr;
	nvlist_t nvl;
	errorq_nvelem_t eqnp;
	errorq_elem_t elem;

	if (addr == 0)
		return (WALK_DONE);

	if (mdb_vread(&elem, sizeof (elem), addr) != sizeof (elem) ||
	    mdb_vread(&eqnp, sizeof (eqnp), (uintptr_t)elem.eqe_data)
	    != sizeof (eqnp) || mdb_vread(&nvl, sizeof (nvl),
	    (uintptr_t)eqnp.eqn_nvl) != sizeof (nvl)) {
		mdb_warn("failed to read ereportq element at %p", addr);
		return (WALK_ERR);
	}

	wsp->walk_addr = (uintptr_t)elem.eqe_prev;

	return (wsp->walk_callback((uintptr_t)eqnp.eqn_nvl, &nvl,
	    wsp->walk_cbdata));
}

int
ereportq_dump_walk_init(mdb_walk_state_t *wsp)
{
	errorq_t eq;
	uintptr_t addr;

	if (wsp->walk_addr == 0 &&
	    mdb_readvar(&addr, "ereport_errorq") == -1) {
		mdb_warn("failed to read ereport_errorq");
		return (WALK_ERR);
	}

	if (mdb_vread(&eq, sizeof (eq), addr) == -1) {
		mdb_warn("failed to read ereport_errorq at %p", addr);
		return (WALK_ERR);
	}

	if (!(eq.eq_flags & ERRORQ_NVLIST)) {
		mdb_warn("errorq at %p does not service ereports", addr);
		return (WALK_ERR);
	}

	wsp->walk_addr = (uintptr_t)eq.eq_dump;

	return (WALK_NEXT);
}

int
ereportq_dump_walk_step(mdb_walk_state_t *wsp)
{
	uintptr_t addr = wsp->walk_addr;
	nvlist_t nvl;
	errorq_nvelem_t eqnp;
	errorq_elem_t elem;

	if (addr == 0)
		return (WALK_DONE);

	if (mdb_vread(&elem, sizeof (elem), addr) != sizeof (elem) ||
	    mdb_vread(&eqnp, sizeof (eqnp), (uintptr_t)elem.eqe_data)
	    != sizeof (eqnp) || mdb_vread(&nvl, sizeof (nvl),
	    (uintptr_t)eqnp.eqn_nvl) != sizeof (nvl)) {
		mdb_warn("failed to read ereportq element at %p", addr);
		return (WALK_ERR);
	}

	wsp->walk_addr = (uintptr_t)elem.eqe_dump;

	return (wsp->walk_callback((uintptr_t)eqnp.eqn_nvl, &nvl,
	    wsp->walk_cbdata));
}

/*ARGSUSED*/
int
ereport(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	int ret;
	uint_t opt_v = 0;
	char *class = NULL;
	uint64_t ena = 0;
	nvlist_t nvl;
	nvpriv_t nvpriv;
	i_nvp_t *nvcur, i_nvp;

	if (!(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	if (mdb_getopts(argc, argv, 'v', MDB_OPT_SETBITS, TRUE, &opt_v) != argc)
		return (DCMD_USAGE);

	if (mdb_vread(&nvl, sizeof (nvl), addr) == -1) {
		mdb_warn("failed to read nvlist at %p", addr);
		return (DCMD_ERR);
	}

	if (DCMD_HDRSPEC(flags) && !opt_v) {
		mdb_printf("ENA                CLASS\n");
	}

	/*
	 * The following code attempts to pretty print the ereport class
	 * and ENA.  The code uses project private macros from libnvpair
	 * that could change and break this functionality.  If we are unable
	 * to get a valid class and ENA from the nvpair list, we revert to
	 * dumping the nvlist (same as opt_v).
	 */
	if (mdb_vread(&nvpriv, sizeof (nvpriv), nvl.nvl_priv) == -1) {
		mdb_warn("failed to read nvpriv at %p", nvl.nvl_priv);
		return (DCMD_ERR);
	}

	for (nvcur = nvpriv.nvp_list; nvcur != NULL; nvcur = i_nvp.nvi_next) {
		nvpair_t *nvp, *nvpair;
		int32_t size;

		if (opt_v)
			break;

		if (mdb_vread(&i_nvp, sizeof (i_nvp), (uintptr_t)nvcur) == -1) {
			mdb_warn("failed to read i_nvp at %p", nvcur);
			return (DCMD_ERR);
		}

		nvp = &i_nvp.nvi_nvp;
		size = NVP_SIZE(nvp);
		if (size == 0) {
			mdb_warn("nvpair of size zero at %p", nvp);
			return (DCMD_OK);
		}

		/* read in the entire nvpair */
		nvpair = mdb_alloc(size, UM_SLEEP | UM_GC);
		if (mdb_vread(nvpair, size, (uintptr_t)&nvcur->nvi_nvp) == -1) {
			mdb_warn("failed to read nvpair and data at %p", nvp);
			return (DCMD_ERR);
		}

		if (strcmp(FM_CLASS, NVP_NAME(nvpair)) == 0 &&
		    NVP_TYPE(nvpair) == DATA_TYPE_STRING && class == NULL) {
			char *p = (char *)NVP_VALUE(nvpair);

			class = mdb_zalloc(strlen(p) + 1, UM_SLEEP | UM_GC);
			bcopy(p, class, strlen(p));
		} else if (strcmp(FM_EREPORT_ENA, NVP_NAME(nvpair)) == 0 &&
		    NVP_TYPE(nvpair) == DATA_TYPE_UINT64 && ena == 0) {
			bcopy(NVP_VALUE(nvpair), (char *)&ena,
			    sizeof (uint64_t));
		}

		if (class != NULL && ena != 0) {
			mdb_printf("0x%016llx %s\n", ena, class);
			return (DCMD_OK);
		}

	}

	/*
	 * Dump entire nvlist
	 */
	ret = mdb_call_dcmd("nvlist", addr, flags | DCMD_ADDRSPEC,
	    0, argv);
	mdb_printf("\n");

	return (ret);
}
