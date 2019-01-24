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

#include <mdb/mdb_modapi.h>
#include <sys/types.h>
#include <sys/contract_impl.h>

int
ct_walk_init(mdb_walk_state_t *wsp)
{
	if (wsp->walk_addr != 0) {
		wsp->walk_addr = wsp->walk_addr +
		    OFFSETOF(ct_type_t, ct_type_avl);
	} else {
		GElf_Sym sym;
		if (mdb_lookup_by_name("contract_avl", &sym)) {
			mdb_warn("failed to read contract_avl");
			return (WALK_ERR);
		}
		wsp->walk_addr = sym.st_value;
	}

	if (mdb_layered_walk("avl", wsp) == -1)
		return (WALK_ERR);

	return (WALK_NEXT);
}

int
ct_event_walk_init(mdb_walk_state_t *wsp)
{
	if (wsp->walk_addr == 0) {
		mdb_warn("ct_event walker requires ct_equeue address\n");
		return (WALK_ERR);
	}

	wsp->walk_addr = wsp->walk_addr +
	    OFFSETOF(ct_equeue_t, ctq_events);

	if (mdb_layered_walk("list", wsp) == -1)
		return (WALK_ERR);

	return (WALK_NEXT);
}

int
ct_listener_walk_init(mdb_walk_state_t *wsp)
{
	if (wsp->walk_addr == 0) {
		mdb_warn("ct_listener walker requires ct_equeue address\n");
		return (WALK_ERR);
	}

	wsp->walk_addr = wsp->walk_addr +
	    OFFSETOF(ct_equeue_t, ctq_listeners);

	if (mdb_layered_walk("list", wsp) == -1)
		return (WALK_ERR);

	return (WALK_NEXT);
}


/* ARGSUSED */
int
cmd_contract(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	contract_t ct;
	ct_type_t ctt;
	char str[32];

	if (!(flags & DCMD_ADDRSPEC)) {
		if (mdb_walk_dcmd("contract", "contract", argc, argv) == -1) {
			mdb_warn("can't walk 'contract'");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}

	if (DCMD_HDRSPEC(flags))
		mdb_printf("%<u>%?s %8s %8s %8s %?s %?s%</u>\n",
		    "ADDR", "ID", "TYPE", "STATE", "OWNER", "REGENT");

	if (mdb_vread(&ct, sizeof (ct), addr) != sizeof (ct)) {
		mdb_warn("error reading contract_t at %p", addr);
		return (DCMD_ERR);
	}
	if (mdb_vread(&ctt, sizeof (ctt), (uintptr_t)ct.ct_type) !=
	    sizeof (ctt)) {
		mdb_warn("error reading ct_type_t at %p", ct.ct_type);
		return (DCMD_ERR);
	}
	if (mdb_readstr(str, sizeof (str), (uintptr_t)ctt.ct_type_name) == -1) {
		mdb_warn("error reading contract type name at %p",
		    ctt.ct_type_name);
		return (DCMD_ERR);
	}

	mdb_printf("%0?p %8d %8s %8s %?p %?p\n", addr, ct.ct_id, str,
	    (ct.ct_state == CTS_OWNED) ? "owned" :
	    (ct.ct_state == CTS_INHERITED) ? "inherit" :
	    (ct.ct_state == CTS_ORPHAN) ? "orphan" : "dead",
	    ct.ct_owner, ct.ct_regent);

	return (DCMD_OK);
}

const mdb_bitmask_t ct_event_flags[] = {
	{ "ACK", CTE_ACK, CTE_ACK },
	{ "INFO", CTE_INFO, CTE_INFO },
	{ "NEG", CTE_NEG, CTE_NEG },
	{ NULL }
};


/* ARGSUSED */
int
cmd_ctevent(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	ct_kevent_t cte;

	if (!(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	if (DCMD_HDRSPEC(flags))
		mdb_printf("%<u>%12s %8s %12s %6s %12s %12s %s%</u>\n",
		    "ADDR", "ID", "CONTRACT", "TYPE", "DATA", "GDATA", "FLAGS");

	if (mdb_vread(&cte, sizeof (cte), addr) != sizeof (cte)) {
		mdb_warn("error reading ct_kevent_t at %p", addr);
		return (DCMD_ERR);
	}

	mdb_printf("%12p %8llu %12p %6d %12p %12p %b\n", addr, cte.cte_id,
	    cte.cte_contract, cte.cte_type, cte.cte_data, cte.cte_gdata,
	    cte.cte_flags, ct_event_flags);

	return (DCMD_OK);
}

typedef struct findct_data {
	uintptr_t fc_ctid;
	uintptr_t fc_addr;
	boolean_t fc_found;
} findct_data_t;

static int
findct(uintptr_t addr, contract_t *ct, findct_data_t *arg)
{
	if (ct->ct_id == arg->fc_ctid) {
		arg->fc_found = B_TRUE;
		arg->fc_addr = addr;
		return (WALK_DONE);
	}

	return (WALK_NEXT);
}

/* ARGSUSED */
int
cmd_ctid(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	findct_data_t fcdata;

	if (!(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	fcdata.fc_ctid = addr;
	fcdata.fc_found = B_FALSE;
	if (mdb_walk("contract", (mdb_walk_cb_t)findct, &fcdata) == -1 ||
	    !fcdata.fc_found)
		return (DCMD_ERR);

	mdb_printf("%lr", fcdata.fc_addr);

	return (DCMD_OK);
}
