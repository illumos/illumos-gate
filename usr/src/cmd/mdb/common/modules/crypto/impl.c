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
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * mdb dcmds for selected structures from
 * usr/src/uts/common/sys/crypto/impl.h
 */
#include <stdio.h>
#include <sys/mdb_modapi.h>
#include <sys/modctl.h>
#include <sys/types.h>
#include <sys/crypto/api.h>
#include <sys/crypto/common.h>
#include <sys/crypto/impl.h>
#include "crypto_cmds.h"

static const char *prov_states[] = {
	"none",
	"KCF_PROV_ALLOCATED",
	"KCF_PROV_UNVERIFIED",
	"KCF_PROV_VERIFICATION_FAILED",
	"KCF_PROV_READY",
	"KCF_PROV_BUSY",
	"KCF_PROV_FAILED",
	"KCF_PROV_DISABLED",
	"KCF_PROV_UNREGISTERING",
	"KCF_PROV_UNREGISTERED"
};

/*ARGSUSED*/
int
kcf_provider_desc(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	kcf_provider_desc_t desc;
	kcf_provider_desc_t *ptr;
	char string[MAXNAMELEN + 1];
	int i, j;
	crypto_mech_info_t *mech_pointer;
	kcf_prov_cpu_t stats;
	uint64_t dtotal, ftotal, btotal;
	int holdcnt, jobcnt;

	if ((flags & DCMD_ADDRSPEC) != DCMD_ADDRSPEC)
		return (DCMD_USAGE);
	ptr = (kcf_provider_desc_t *)addr;

#ifdef DEBUG
	mdb_printf("DEBUG: reading kcf_provider_desc at %p\n", ptr);
#endif

	if (mdb_vread(&desc, sizeof (kcf_provider_desc_t), (uintptr_t)ptr)
	    == -1) {
		mdb_warn("cannot read at address %p", (uintptr_t)ptr);
		return (DCMD_ERR);
	}
	mdb_printf("%<b>kcf_provider_desc at %p%</b>\n", ptr);

	switch (desc.pd_prov_type) {
	case CRYPTO_HW_PROVIDER:
		mdb_printf("pd_prov_type:\t\tCRYPTO_HW_PROVIDER\n");
		break;
	case CRYPTO_SW_PROVIDER:
		mdb_printf("pd_prov_type:\t\tCRYPTO_SW_PROVIDER\n");
		break;
	case CRYPTO_LOGICAL_PROVIDER:
		mdb_printf("pd_prov_type:\t\tCRYPTO_LOGICAL_PROVIDER\n");
		break;
	default:
		mdb_printf("bad pd_prov_type:\t%d\n", desc.pd_prov_type);
	}

	mdb_printf("pd_prov_id:\t\t%u\n", desc.pd_prov_id);
	if (desc.pd_description == NULL)
		mdb_printf("pd_description:\t\tNULL\n");
	else if (mdb_readstr(string, MAXNAMELEN + 1,
	    (uintptr_t)desc.pd_description) == -1) {
		mdb_warn("cannot read %p", desc.pd_description);
	} else
		mdb_printf("pd_description:\t\t%s\n", string);

	mdb_printf("pd_sid:\t\t\t%u\n", desc.pd_sid);
	mdb_printf("pd_taskq:\t\t%p\n", desc.pd_taskq);
	mdb_printf("pd_nbins:\t\t%u\n", desc.pd_nbins);
	mdb_printf("pd_percpu_bins:\t\t%p\n", desc.pd_percpu_bins);

	dtotal = ftotal = btotal = 0;
	holdcnt = jobcnt = 0;
	for (i = 0; i < desc.pd_nbins; i++) {
		if (mdb_vread(&stats, sizeof (kcf_prov_cpu_t),
		    (uintptr_t)(desc.pd_percpu_bins + i)) == -1) {
			mdb_warn("cannot read addr %p",
			    desc.pd_percpu_bins + i);
			return (DCMD_ERR);
		}

		holdcnt += stats.kp_holdcnt;
		jobcnt += stats.kp_jobcnt;
		dtotal += stats.kp_ndispatches;
		ftotal += stats.kp_nfails;
		btotal += stats.kp_nbusy_rval;
	}
	mdb_inc_indent(4);
	mdb_printf("total kp_holdcnt:\t\t%d\n", holdcnt);
	mdb_printf("total kp_jobcnt:\t\t%u\n", jobcnt);
	mdb_printf("total kp_ndispatches:\t%llu\n", dtotal);
	mdb_printf("total kp_nfails:\t\t%llu\n", ftotal);
	mdb_printf("total kp_nbusy_rval:\t%llu\n", btotal);
	mdb_dec_indent(4);

	mdb_printf("pd_prov_handle:\t\t%p\n", desc.pd_prov_handle);
	mdb_printf("pd_kcf_prov_handle:\t%u\n", desc.pd_kcf_prov_handle);

	mdb_printf("pd_ops_vector:\t\t%p\n", desc.pd_ops_vector);
	mdb_printf("pd_mech_list_count:\t%u\n", desc.pd_mech_list_count);
	/* mechanisms */
	mdb_inc_indent(4);
	for (i = 0; i < desc.pd_mech_list_count; i++) {
		mech_pointer = desc.pd_mechanisms + i;
		mdb_call_dcmd("crypto_mech_info",
		    (uintptr_t)mech_pointer, DCMD_ADDRSPEC, 0, NULL);
	}
	mdb_dec_indent(4);
	mdb_printf("pd_mech_indx:\n");
	mdb_inc_indent(8);
	for (i = 0; i < KCF_OPS_CLASSSIZE; i++) {
		for (j = 0; j < KCF_MAXMECHTAB; j++) {
			if (desc.pd_mech_indx[i][j] == KCF_INVALID_INDX)
				mdb_printf("N ");
			else
				mdb_printf("%u ", desc.pd_mech_indx[i][j]);
		}
		mdb_printf("\n");
	}
	mdb_dec_indent(8);

	if (desc.pd_name == NULL)
		mdb_printf("pd_name:\t\t NULL\n");
	else if (mdb_readstr(string, MAXNAMELEN + 1, (uintptr_t)desc.pd_name)
	    == -1)
		mdb_warn("could not read pd_name from %X\n", desc.pd_name);
	else
		mdb_printf("pd_name:\t\t%s\n", string);

	mdb_printf("pd_instance:\t\t%u\n", desc.pd_instance);
	mdb_printf("pd_module_id:\t\t%d\n", desc.pd_module_id);
	mdb_printf("pd_mctlp:\t\t%p\n", desc.pd_mctlp);
	mdb_printf("pd_lock:\t\t%p\n", desc.pd_lock);
	if (desc.pd_state < KCF_PROV_ALLOCATED ||
	    desc.pd_state > KCF_PROV_UNREGISTERED)
		mdb_printf("pd_state is invalid:\t%d\n", desc.pd_state);
	else
		mdb_printf("pd_state:\t%s\n", prov_states[desc.pd_state]);
	mdb_printf("pd_provider_list:\t%p\n", desc.pd_provider_list);

	mdb_printf("pd_resume_cv:\t\t%hd\n", desc.pd_resume_cv._opaque);
	mdb_printf("pd_flags:\t\t%s %s %s %s %s\n",
	    (desc.pd_flags & CRYPTO_HIDE_PROVIDER) ?
	    "CRYPTO_HIDE_PROVIDER" : " ",
	    (desc.pd_flags & CRYPTO_HASH_NO_UPDATE) ?
	    "CRYPTO_HASH_NO_UPDATE" : " ",
	    (desc.pd_flags & CRYPTO_HMAC_NO_UPDATE) ?
	    "CRYPTO_HMAC_NO_UPDATE" : " ",
	    (desc.pd_flags & CRYPTO_SYNCHRONOUS) ?
	    "CRYPTO_SYNCHRONOUS" : " ",
	    (desc.pd_flags & KCF_LPROV_MEMBER) ?
	    "KCF_LPROV_MEMBER" : " ");
	if (desc.pd_flags & CRYPTO_HASH_NO_UPDATE)
		mdb_printf("pd_hash_limit:\t\t%u\n", desc.pd_hash_limit);
	if (desc.pd_flags & CRYPTO_HMAC_NO_UPDATE)
		mdb_printf("pd_hmac_limit:\t\t%u\n", desc.pd_hmac_limit);

	mdb_printf("pd_kstat:\t\t%p\n", desc.pd_kstat);

	return (DCMD_OK);
}

#define	GOT_NONE	(-2)

/*ARGSUSED*/
int
prov_tab(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	kcf_provider_desc_t **tab;
	kcf_provider_desc_t desc;
	kcf_provider_desc_t *ptr;
	uint_t prov_tab_max;
	int i;
	int gotzero = GOT_NONE;
	char string[MAXNAMELEN + 1];

	if ((flags & DCMD_ADDRSPEC) == DCMD_ADDRSPEC) {
		return (DCMD_USAGE);
	} else if (mdb_readsym(&ptr, sizeof (void *), "prov_tab")
	    == -1) {
		mdb_warn("cannot read prov_tab");
		return (DCMD_ERR);

	} else if (mdb_readvar(&prov_tab_max, "prov_tab_max") == -1) {
		mdb_warn("cannot read prov_tab_max");
		return (DCMD_ERR);
	}
	mdb_printf("%<b>prov_tab = %p%</b>\n", ptr);
	tab = mdb_zalloc(prov_tab_max * sizeof (kcf_provider_desc_t *),
	    UM_SLEEP| UM_GC);

#ifdef DEBUG
	mdb_printf("DEBUG: tab = %p, prov_tab_max = %d\n", tab, prov_tab_max);
#endif

	if (mdb_vread(tab, prov_tab_max * sizeof (kcf_provider_desc_t *),
	    (uintptr_t)ptr) == -1) {
		mdb_warn("cannot read prov_tab");
		return (DCMD_ERR);
	}
#ifdef DEBUG
	mdb_printf("DEBUG: got past mdb_vread of tab\n");
	mdb_printf("DEBUG: *tab = %p\n", *tab);
#endif
	for (i = 0;  i <  prov_tab_max; i++) {
		/* save space, only print range for long list of nulls */
		if (tab[i] == NULL) {
			if (gotzero == GOT_NONE) {
				mdb_printf("prov_tab[%d", i);
				gotzero = i;
			}
		} else {
			/* first non-null in awhile, print index of prev null */
			if (gotzero != GOT_NONE) {
				if (gotzero == (i - 1))
					mdb_printf("] = NULL\n", i - 1);
				else
					mdb_printf(" - %d] = NULL\n", i - 1);
				gotzero = GOT_NONE;
			}
			/* interesting value, print it */
			mdb_printf("prov_tab[%d] = %p ", i, tab[i]);

			if (mdb_vread(&desc, sizeof (kcf_provider_desc_t),
			    (uintptr_t)tab[i]) == -1) {
				mdb_warn("cannot read at address %p",
				    (uintptr_t)tab[i]);
				return (DCMD_ERR);
			}

			(void) mdb_readstr(string, MAXNAMELEN + 1,
			    (uintptr_t)desc.pd_name);
			mdb_printf("(%s\t%s)\n", string,
			    prov_states[desc.pd_state]);
		}
	}
	/* if we've printed the first of many nulls but left the brace open */
	if ((i > 0) && (tab[i-1] == NULL)) {
		if (gotzero == GOT_NONE)
			mdb_printf("] = NULL\n");
		else
			mdb_printf(" - %d] = NULL\n", i - 1);
	}

	return (DCMD_OK);
}

/*ARGSUSED*/
int
policy_tab(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	kcf_policy_desc_t **tab;
	kcf_policy_desc_t *ptr;
	uint_t policy_tab_max;
	int num, i;
	int gotzero = GOT_NONE;

	if ((flags & DCMD_ADDRSPEC) == DCMD_ADDRSPEC) {
		return (DCMD_USAGE);
	} else if (mdb_readsym(&ptr, sizeof (void *), "policy_tab")
	    == -1) {
		mdb_warn("cannot read policy_tab");
		return (DCMD_ERR);

	} else if (mdb_readvar(&policy_tab_max, "policy_tab_max") == -1) {
		mdb_warn("cannot read policy_tab_max");
		return (DCMD_ERR);
	}

	/* get the current number of descriptors in the table */
	if (mdb_readvar(&num, "policy_tab_num") == -1) {
		mdb_warn("cannot read policy_tab_num");
		return (DCMD_ERR);
	}
	mdb_printf("%<b>policy_tab = %p%</b> \tpolicy_tab_num = %d\n",
	    ptr, num);

	tab = mdb_zalloc(policy_tab_max * sizeof (kcf_policy_desc_t *),
	    UM_SLEEP| UM_GC);

	if (mdb_vread(tab, policy_tab_max * sizeof (kcf_policy_desc_t *),
	    (uintptr_t)ptr) == -1) {
		mdb_warn("cannot read policy_tab");
		return (DCMD_ERR);
	}
#ifdef DEBUG
	mdb_printf("DEBUG: got past mdb_vread of tab\n");
	mdb_printf("DEBUG: *tab = %p\n", *tab);
#endif
	for (i = 0;  i < policy_tab_max; i++) {
		/* save space, only print range for long list of nulls */
		if (tab[i] == NULL) {
			if (gotzero == GOT_NONE) {
				mdb_printf("policy_tab[%d", i);
				gotzero = i;
			}
		} else {
			/* first non-null in awhile, print index of prev null */
			if (gotzero != GOT_NONE) {
				if (gotzero == (i - 1))
					mdb_printf("] = NULL\n", i - 1);
				else
					mdb_printf(" - %d] = NULL\n", i - 1);
				gotzero = GOT_NONE;
			}
			/* interesting value, print it */
			mdb_printf("policy_tab[%d] = %p\n", i, tab[i]);
		}
	}
	/* if we've printed the first of many nulls but left the brace open */
	if ((i > 0) && (tab[i-1] == NULL)) {
		if (gotzero == GOT_NONE)
			mdb_printf("] = NULL\n");
		else
			mdb_printf(" - %d] = NULL\n", i - 1);
	}

	return (DCMD_OK);
}

static void
prt_mechs(int count, crypto_mech_name_t *mechs)
{
	int i;
	char name[CRYPTO_MAX_MECH_NAME + 1];
	char name2[CRYPTO_MAX_MECH_NAME + 3];

	for (i = 0; i < count; i++) {
		if (mdb_readstr(name, CRYPTO_MAX_MECH_NAME,
		    (uintptr_t)((char *)mechs)) == -1)
			continue;
		/* put in quotes */
		(void) mdb_snprintf(name2, sizeof (name2), "\"%s\"", name);
		/* yes, length is 32, but then it will wrap */
		/* this shorter size formats nicely for most cases */
		mdb_printf("mechs[%d]=%-28s", i, name2);
		mdb_printf("%s", i%2 ? "\n" : "  "); /* 2-columns */
		mechs++;
	}
}

/* ARGSUSED2 */
static int
prt_soft_conf_entry(kcf_soft_conf_entry_t *addr, kcf_soft_conf_entry_t *entry,
    void *cbdata)
{
	char name[MAXNAMELEN + 1];

	mdb_printf("\n%<b>kcf_soft_conf_entry_t at %p:%</b>\n", addr);
	mdb_printf("ce_next: %p", entry->ce_next);

	if (entry->ce_name == NULL)
		mdb_printf("\tce_name: NULL\n");
	else if (mdb_readstr(name, MAXNAMELEN, (uintptr_t)entry->ce_name)
	    == -1)
		mdb_printf("could not read ce_name from %p\n",
		    entry->ce_name);
	else
		mdb_printf("\tce_name: %s\n", name);

	mdb_printf("ce_count: %d\n", entry->ce_count);
	prt_mechs(entry->ce_count, entry->ce_mechs);
	return (WALK_NEXT);
}

int
soft_conf_walk_init(mdb_walk_state_t *wsp)
{
	uintptr_t *soft;

	if (mdb_readsym(&soft, sizeof (kcf_soft_conf_entry_t *),
	    "soft_config_list") == -1) {
		mdb_warn("failed to find 'soft_config_list'");
		return (WALK_ERR);
	}
	wsp->walk_addr = (uintptr_t)soft;
	wsp->walk_data = mdb_alloc(sizeof (kcf_soft_conf_entry_t), UM_SLEEP);
	wsp->walk_callback = (mdb_walk_cb_t)(uintptr_t)prt_soft_conf_entry;
	return (WALK_NEXT);
}

/*
 * At each step, read a kcf_soft_conf_entry_t into our private storage, then
 * invoke the callback function.  We terminate when we reach a NULL ce_next
 * pointer.
 */
int
soft_conf_walk_step(mdb_walk_state_t *wsp)
{
	int status;

	if (wsp->walk_addr == 0)	/* then we're done */
		return (WALK_DONE);
#ifdef DEBUG
	else
		mdb_printf("DEBUG: wsp->walk_addr == %p\n", wsp->walk_addr);
#endif

	if (mdb_vread(wsp->walk_data, sizeof (kcf_soft_conf_entry_t),
	    wsp->walk_addr) == -1) {
		mdb_warn("failed to read kcf_soft_conf_entry at %p",
		    wsp->walk_addr);
		return (WALK_DONE);
	}

	status = wsp->walk_callback(wsp->walk_addr, wsp->walk_data,
	    wsp->walk_cbdata);

	wsp->walk_addr =
	    (uintptr_t)(((kcf_soft_conf_entry_t *)wsp->walk_data)->ce_next);
	return (status);
}

/*
 * The walker's fini function is invoked at the end of each walk.  Since we
 * dynamically allocated a kcf_soft_conf_entry_t in soft_conf_walk_init,
 * we must free it now.
 */
void
soft_conf_walk_fini(mdb_walk_state_t *wsp)
{
#ifdef	DEBUG
	mdb_printf("...end of kcf_soft_conf_entry walk\n");
#endif
	mdb_free(wsp->walk_data, sizeof (kcf_soft_conf_entry_t));
}
/* ARGSUSED2 */
int
kcf_soft_conf_entry(uintptr_t addr, uint_t flags, int argc,
    const mdb_arg_t *argv)
{
	kcf_soft_conf_entry_t entry;
	kcf_soft_conf_entry_t *ptr;

	if ((flags & DCMD_ADDRSPEC) == DCMD_ADDRSPEC) {
		if (addr == 0)	/* not allowed with DCMD_ADDRSPEC */
			return (DCMD_USAGE);
		else
			ptr = (kcf_soft_conf_entry_t *)addr;
	} else if (mdb_readsym(&ptr, sizeof (void *), "soft_config_list")
	    == -1) {
		mdb_warn("cannot read soft_config_list");
		return (DCMD_ERR);
	} else
		mdb_printf("soft_config_list = %p\n", ptr);

	if (ptr == NULL)
		return (DCMD_OK);

	if (mdb_vread(&entry, sizeof (kcf_soft_conf_entry_t), (uintptr_t)ptr)
	    == -1) {
		mdb_warn("cannot read at address %p", (uintptr_t)ptr);
		return (DCMD_ERR);
	}

	/* this could change in the future to have more than one ret val */
	if (prt_soft_conf_entry(ptr, &entry, NULL) != WALK_ERR)
		return (DCMD_OK);
	return (DCMD_ERR);
}

/* ARGSUSED1 */
int
kcf_policy_desc(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	kcf_policy_desc_t  desc;
	char name[MAXNAMELEN + 1];


	if ((flags & DCMD_ADDRSPEC) != DCMD_ADDRSPEC)
		return (DCMD_USAGE);

	if (mdb_vread(&desc, sizeof (kcf_policy_desc_t), (uintptr_t)addr)
	    == -1) {
		mdb_warn("Could not read kcf_policy_desc_t at %p\n", addr);
		return (DCMD_ERR);
	}
	mdb_printf("pd_prov_type:  %s",
	    desc.pd_prov_type == CRYPTO_HW_PROVIDER ? "CRYPTO_HW_PROVIDER" :
	    "CRYPTO_SW_PROVIDER");

	if (desc.pd_name == NULL)
		mdb_printf("\tpd_name: NULL\n");
	else if (mdb_readstr(name, MAXNAMELEN, (uintptr_t)desc.pd_name)
	    == -1)
		mdb_printf("could not read pd_name from %p\n",
		    desc.pd_name);
	else
		mdb_printf("\tpd_name: %s\n", name);

	mdb_printf("pd_instance: %d ", desc.pd_instance);
	mdb_printf("\t\tpd_refcnt: %d\n", desc.pd_refcnt);
	mdb_printf("pd_mutex: %p", desc.pd_mutex);
	mdb_printf("\t\tpd_disabled_count: %d", desc.pd_disabled_count);
	mdb_printf("\npd_disabled_mechs:\n");
	mdb_inc_indent(4);
	prt_mechs(desc.pd_disabled_count, desc.pd_disabled_mechs);
	mdb_dec_indent(4);
	return (DCMD_OK);
}
