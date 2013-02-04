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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright (c) 2012 by Delphix. All rights reserved.
 */

#include <mdb/mdb_modapi.h>
#include <mdb/mdb_ks.h>
#include <mdb/mdb_ctf.h>
#include <mdb/mdb_gelf.h>
#include <mdb/mdb_target_impl.h>
#include <mdb/mdb_kvm.h>
#include <mdb/mdb.h>
#include <xen/public/xen.h>
#include <xen/public/arch-x86/xen.h>
#include <errno.h>

static mdb_ctf_id_t domain_type;

/*
 * Some constants found in the non-public sched.h header file
 */
#define	MAX_EVTCHNS		NR_EVENT_CHANNELS
#define	EVTCHNS_PER_BUCKET	128
#define	NR_EVTCHN_BUCKETS	(MAX_EVTCHNS / EVTCHNS_PER_BUCKET)

/*
 * "struct domain" is an internal Xen structure.  Rather than trying to
 * keep the mdb source in sync with Xen, we use CTF to extract the
 * interesting bits from the binary, and stash them in the structure
 * defined below.
 */
typedef struct mdb_xpv_domain {
	short		domain_id;
	int		tot_pages;
	int		max_pages;
	int		xenheap_pages;
	ulong_t		domain_flags;
	char		is_hvm;
	struct vcpu	*vcpu[MAX_VIRT_CPUS];
	struct evtchn	*evtchn[NR_EVTCHN_BUCKETS];
	struct domain	*next_in_list;
} mdb_xpv_domain_t;

static uintptr_t
get_dom0_addr()
{
	GElf_Sym sym;
	uintptr_t addr;

	if ((mdb_lookup_by_obj(MDB_TGT_OBJ_EVERY, "dom0", &sym)) == 1) {
		mdb_warn("can't find symbol 'dom0'");
		return (0);
	}

	if (sym.st_size != sizeof (uintptr_t)) {
		mdb_printf("Symbol 'dom0' found, but with the wrong size\n");
		return (0);
	}

	if (mdb_vread(&addr, sym.st_size, sym.st_value) == -1) {
		mdb_warn("can't read data for symbol 'dom0'");
		return (0);
	}

	return (addr);
}

typedef struct domain_walk {
	uint_t dw_step;
} domain_walk_t;

int
domain_walk_init(mdb_walk_state_t *wsp)
{
	domain_walk_t *dwp;

	if (wsp->walk_addr == NULL)
		if ((wsp->walk_addr = get_dom0_addr()) == NULL)
			return (WALK_ERR);

	dwp = mdb_alloc(sizeof (domain_walk_t), UM_SLEEP);
	dwp->dw_step = FALSE;
	wsp->walk_data = dwp;
	return (WALK_NEXT);
}

int
domain_walk_step(mdb_walk_state_t *wsp)
{
	domain_walk_t *dwp = (domain_walk_t *)wsp->walk_data;
	mdb_xpv_domain_t dom;
	int status;

	if (wsp->walk_addr == NULL)
		return (WALK_DONE);

	status = wsp->walk_callback(wsp->walk_addr, (void *)wsp->walk_addr,
	    wsp->walk_cbdata);

	if (mdb_ctf_vread(&dom, "struct domain", "mdb_xpv_domain_t",
	    wsp->walk_addr, 0) != 0)
		return (WALK_ERR);
	wsp->walk_addr = (uintptr_t)dom.next_in_list;

	dwp->dw_step = TRUE;
	return (status);
}

void
domain_walk_fini(mdb_walk_state_t *wsp)
{
	domain_walk_t *dwp = (domain_walk_t *)wsp->walk_data;

	mdb_free(dwp, sizeof (domain_walk_t));
}

typedef struct vcpu_walk {
	uint_t vw_count;
	uint_t vw_step;
} vcpu_walk_t;

int
vcpu_walk_init(mdb_walk_state_t *wsp)
{
	vcpu_walk_t *vwp;
	uintptr_t off;

	if (wsp->walk_addr == NULL)
		if ((wsp->walk_addr = get_dom0_addr()) == NULL)
			return (WALK_ERR);

	if (mdb_ctf_offsetof(domain_type, "vcpu", &off)) {
		mdb_warn("can't find per-domain vcpu information");
		return (WALK_ERR);
	}

	wsp->walk_addr = wsp->walk_addr + (off / NBBY);
	vwp = mdb_alloc(sizeof (vcpu_walk_t), UM_SLEEP);
	vwp->vw_step = FALSE;
	vwp->vw_count = 0;
	wsp->walk_data = vwp;
	return (WALK_NEXT);
}

int
vcpu_walk_step(mdb_walk_state_t *wsp)
{
	vcpu_walk_t *vwp = (vcpu_walk_t *)wsp->walk_data;
	uintptr_t vcpu_ptr;
	int status;

	if (vwp->vw_count++ >= MAX_VIRT_CPUS)
		return (WALK_DONE);
	if ((wsp->walk_addr == NULL) ||
	    (mdb_vread(&vcpu_ptr, sizeof (uintptr_t), wsp->walk_addr) == -1) ||
	    (vcpu_ptr == 0))
		return (WALK_DONE);

	status = wsp->walk_callback(vcpu_ptr, (void *)vcpu_ptr,
	    wsp->walk_cbdata);

	wsp->walk_addr = wsp->walk_addr + sizeof (uintptr_t);
	vwp->vw_step = TRUE;
	return (status);
}

void
vcpu_walk_fini(mdb_walk_state_t *wsp)
{
	vcpu_walk_t *vwp = (vcpu_walk_t *)wsp->walk_data;

	mdb_free(vwp, sizeof (vcpu_walk_t));
}

int
domain(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	mdb_xpv_domain_t dom;
	uintptr_t off, vcpu_addr, evtchn_addr;

	if (!mdb_ctf_type_valid(domain_type)) {
		mdb_warn("Can't parse Xen domain info.\n");
		return (DCMD_ERR);
	}

	if (!(flags & DCMD_ADDRSPEC)) {
		if (mdb_walk_dcmd("domain", "domain", argc, argv) == -1) {
			mdb_warn("can't walk domains");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}

	if (DCMD_HDRSPEC(flags))
		mdb_printf("%?s %3s %8s %8s %8s %3s %?s %?s\n",
		    "ADDR", "ID", "TPAGES", "MPAGES", "FLAGS", "HVM",
		    "VCPU", "EVTCHN");

	if (mdb_ctf_vread(&dom, "struct domain", "mdb_xpv_domain_t", addr,
	    0) != 0)
		return (DCMD_ERR);

	if (mdb_ctf_offsetof(domain_type, "vcpu", &off)) {
		mdb_warn("can't find per-domain vcpu information");
		return (DCMD_ERR);
	}
	vcpu_addr = addr + (off / NBBY);
	if (mdb_ctf_offsetof(domain_type, "evtchn", &off)) {
		mdb_warn("can't find per-domain event channel information");
		return (DCMD_ERR);
	}
	evtchn_addr = addr + (off / NBBY);
	mdb_printf("%?lx %3d %8x %8x %8x %3d %?lx %?lx\n",
	    addr, dom.domain_id, dom.tot_pages, dom.max_pages, dom.domain_flags,
	    dom.is_hvm, vcpu_addr, evtchn_addr);

	return (DCMD_OK);
}

static const mdb_dcmd_t dcmds[] = {
	{ "domain", ":", "display Xen domain info", domain },
	{ NULL }
};

static const mdb_walker_t walkers[] = {
	{ "domain", "walk list of Xen domains",
		domain_walk_init, domain_walk_step, domain_walk_fini },
	{ "vcpu", "walk a Xen domain's vcpus",
		vcpu_walk_init, vcpu_walk_step, vcpu_walk_fini },
	{ NULL }
};

static const mdb_modinfo_t modinfo = { MDB_API_VERSION, dcmds, walkers };

typedef struct mdb_xpv_panic_info {
	int pi_version;
} mdb_xpv_panic_info_t;

const mdb_modinfo_t *
_mdb_init(void)
{
	uintptr_t pip;
	mdb_xpv_panic_info_t pi;

	if (mdb_readsym(&pip, sizeof (pip), "xpv_panic_info") == -1) {
		mdb_warn("failed to read xpv panic_info pointer");
		return (NULL);
	}
	if (mdb_ctf_vread(&pi, "struct panic_info", "mdb_xpv_panic_info_t",
	    pip, 0) == -1)
		return (NULL);

	if (pi.pi_version != PANIC_INFO_VERSION) {
		mdb_warn("unrecognized hypervisor panic format");
		return (NULL);
	}

	if (mdb_ctf_lookup_by_name("struct domain", &domain_type) != 0) {
		mdb_warn("Can't parse Xen domain info: "
		    "'struct domain' not found.\n");
		mdb_ctf_type_invalidate(&domain_type);
	}

	return (&modinfo);
}
