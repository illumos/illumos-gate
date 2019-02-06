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

#include <sys/types.h>
#include <sys/rwlock.h>
#include <mdb/mdb_modapi.h>
#include <sys/queue.h>
#include <inet/ip.h>
#include <sys/hook.h>
#include <sys/hook_impl.h>

#define	MAX_LENGTH 64

/*
 * List pfhooks hook list information.
 */
/*ARGSUSED*/
int
hooklist(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	hook_event_int_t hr;
	hook_int_t hl, *hlp;
	char hrstr[MAX_LENGTH];
	GElf_Sym sym;
	char buf[MDB_SYM_NAMLEN + 1];
	char *hintname;
	hook_t *h;

	if (argc)
		return (DCMD_USAGE);

	if (mdb_vread((void *)&hr, sizeof (hr), (uintptr_t)addr) == -1) {
		mdb_warn("couldn't read hook register at %p", addr);
		return (DCMD_ERR);
	}

	mdb_printf("%<u>%?s %8s %20s %4s %24s %24s%</u>\n",
	    "ADDR", "FLAG", "FUNC", "HINT", "NAME", "HINTVALUE");
	h = &hl.hi_hook;
	hlp = TAILQ_FIRST(&hr.hei_head);
	while (hlp) {
		if (mdb_vread((void *)&hl, sizeof (hl),
		    (uintptr_t)hlp) == -1) {
			mdb_warn("couldn't read hook list at %p",
			    hlp);
			return (DCMD_ERR);
		}
		if (!h->h_name) {
			mdb_warn("hook list at %p has null role", h);
			return (DCMD_ERR);
		}
		if (mdb_readstr((char *)hrstr, sizeof (hrstr),
		    (uintptr_t)h->h_name) == -1) {
			mdb_warn("couldn't read list role at %p", h->h_name);
			return (DCMD_ERR);
		}
		switch (h->h_hint) {
		case HH_BEFORE :
		case HH_AFTER :
			hintname =  h->h_hintvalue ?
			    (char *)h->h_hintvalue : "";
			break;
		default :
			hintname = "";
			break;
		}
		if (mdb_lookup_by_addr((uintptr_t)h->h_func,
		    MDB_SYM_EXACT, buf, sizeof (buf), &sym) == -1)
			mdb_printf("%0?p %8x %0?p %4d %24s %24s\n",
			    hlp, h->h_flags, h->h_func,
			    h->h_hint, hrstr, hintname);
		else
			mdb_printf("%0?p %8x %20s %4d %24s %24s\n",
			    hlp, h->h_flags, buf,
			    h->h_hint, hrstr, hintname);
		hlp = TAILQ_NEXT(&hl, hi_entry);
	}
	return (DCMD_OK);
}

/*
 * List pfhooks event information.
 * List the hooks information in verbose mode as well.
 */
/*ARGSUSED*/
int
hookeventlist(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	hook_family_int_t hf;
	hook_event_int_t hr, *hrp;
	hook_event_t hp;
	char hprstr[MAX_LENGTH];

	if (argc)
		return (DCMD_USAGE);

	if (mdb_vread((void *)&hf, sizeof (hf), (uintptr_t)addr) == -1) {
		mdb_warn("couldn't read hook family at %p", addr);
		return (DCMD_ERR);
	}

	mdb_printf("%<u>%?s %10s %20s%</u>\n", "ADDR", "FLAG", "NAME");
	hrp = SLIST_FIRST(&hf.hfi_head);
	while (hrp) {
		if (mdb_vread((void *)&hr, sizeof (hr), (uintptr_t)hrp) == -1) {
			mdb_warn("couldn't read hook register at %p", hrp);
			return (DCMD_ERR);
		}
		if (!hr.hei_event) {
			mdb_warn("hook register at %p has no hook provider",
			    hrp);
			return (DCMD_ERR);
		}
		if (mdb_vread((void *)&hp, sizeof (hp),
		    (uintptr_t)hr.hei_event) == -1) {
			mdb_warn("hook provider at %p has null role",
			    hr.hei_event);
			return (DCMD_ERR);
		}
		if (!hp.he_name) {
			mdb_warn("hook provider at %p has null role",
			    hr.hei_event);
			return (DCMD_ERR);
		}
		if (mdb_readstr((char *)hprstr, sizeof (hprstr),
		    (uintptr_t)hp.he_name) == -1) {
			mdb_warn("couldn't read provider role at %p",
			    hp.he_name);
			return (DCMD_ERR);
		}
		mdb_printf("%0?p %10x %20s\n", hrp, hp.he_flags, hprstr);
		hrp = SLIST_NEXT(&hr, hei_entry);
	}

	return (DCMD_OK);
}

/*
 * List pfhooks family information.
 */
/*ARGSUSED*/
int
hookrootlist(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	struct hook_stack *hks;
	hook_family_int_head_t hfh;
	hook_family_int_t hf, *hfp;
	char hrrstr[MAX_LENGTH];

	if (argc)
		return (DCMD_USAGE);

	if (mdb_vread((void *)&hks, sizeof (hks),
	    (uintptr_t)(addr + OFFSETOF(netstack_t, netstack_hook))) == -1) {
		mdb_warn("couldn't read netstack_hook");
		return (DCMD_ERR);
	}

	if (mdb_vread((void *)&hfh, sizeof (hfh), (uintptr_t)((uintptr_t)hks +
	    OFFSETOF(hook_stack_t, hks_familylist))) == -1) {
		mdb_warn("couldn't read hook family head");
		return (DCMD_ERR);
	}

	mdb_printf("%<u>%?s %10s%</u>\n", "ADDR", "FAMILY");
	hfp = SLIST_FIRST(&hfh);
	while (hfp) {
		if (mdb_vread((void *)&hf, sizeof (hf), (uintptr_t)hfp) == -1) {
			mdb_warn("couldn't read hook family at %p", hfp);
			return (DCMD_ERR);
		}
		if (!hf.hfi_family.hf_name) {
			mdb_warn("hook root at %p has null role",
			    hf.hfi_family);
			return (DCMD_ERR);
		}
		if (mdb_readstr((char *)hrrstr, sizeof (hrrstr),
		    (uintptr_t)hf.hfi_family.hf_name) == -1) {
			mdb_warn("couldn't read root role at %p",
			    hf.hfi_family.hf_name);
			return (DCMD_ERR);
		}
		mdb_printf("%0?p %10s\n", hfp, hrrstr);
		hfp = SLIST_NEXT(&hf, hfi_entry);
	}

	return (DCMD_OK);
}


static int
hookevent_stack_walk_init(mdb_walk_state_t *wsp)
{
	hook_family_int_t hf;

	if (wsp->walk_addr == 0) {
		mdb_warn("global walk not supported\n");
		return (WALK_ERR);
	}

	if (mdb_vread((void *)&hf, sizeof (hf),
	    (uintptr_t)wsp->walk_addr) == -1) {
		mdb_warn("couldn't read hook family at %p", wsp->walk_addr);
		return (DCMD_ERR);
	}
	wsp->walk_addr = (uintptr_t)SLIST_FIRST(&hf.hfi_head);
	return (wsp->walk_callback(wsp->walk_addr, wsp->walk_data,
	    wsp->walk_cbdata));
}

static int
hookevent_stack_walk_step(mdb_walk_state_t *wsp)
{
	hook_event_int_t hr;

	if (mdb_vread((void *)&hr, sizeof (hr),
	    (uintptr_t)wsp->walk_addr) == -1) {
		mdb_warn("couldn't read hook event at %p", wsp->walk_addr);
		return (DCMD_ERR);
	}
	wsp->walk_addr = (uintptr_t)SLIST_NEXT(&hr, hei_entry);
	if (wsp->walk_addr == 0)
		return (WALK_DONE);
	return (wsp->walk_callback(wsp->walk_addr, wsp->walk_data,
	    wsp->walk_cbdata));
}

static const mdb_dcmd_t dcmds[] = {
	{ "hookrootlist", "", "display hook family information", hookrootlist },
	{ "hookeventlist", "", "display hook event information",
		hookeventlist, NULL },
	{ "hooklist", "", "display hooks", hooklist },
	{ NULL }
};

static const mdb_walker_t walkers[] = {
	{ "hookevent_stack", "walk list of hooks",
		hookevent_stack_walk_init, hookevent_stack_walk_step, NULL },
	{ NULL }
};

static const mdb_modinfo_t modinfo = { MDB_API_VERSION, dcmds, walkers };

const mdb_modinfo_t *
_mdb_init(void)
{
	return (&modinfo);
}
