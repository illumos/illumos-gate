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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 */
/*
 * Copyright (c) 2010, Intel Corporation.
 * All rights reserved.
 */

#include <sys/types.h>
#include <sys/cpu_module_ms_impl.h>
#include <sys/cpuvar.h>
#include <sys/ksynch.h>
#include <sys/modctl.h>
#include <sys/x86_archext.h>
#include <sys/systm.h>
#include <sys/cmn_err.h>
#include <sys/param.h>
#include <sys/reboot.h>

/*
 * Set to prevent model-specific support from initialising.
 */
int cms_no_model_specific = 0;

/*
 * Subdirectory (relative to the module search path) in which we will
 * look for model-specific modules.
 */
#define	CPUMOD_MS_SUBDIR	"cpu"

/*
 * Cpu model-specific modules have filenames beginning with the following.
 */
#define	CPUMOD_MS_PREFIX	"cpu_ms"

#define	HDL2CMS(hdl)		cms_hdl_getcms(hdl)

#define	CMS_OPS(cms)		(cms)->cms_ops
#define	CMS_OP_PRESENT(cms, op)	((cms) && CMS_OPS(cms)->op != NULL)

struct cms_cpuid {
	const char *vendor;
	uint_t family;
	uint_t model;
	uint_t stepping;
};

#define	CMS_MATCH_VENDOR	0	/* Just match on vendor */
#define	CMS_MATCH_FAMILY	1	/* Match down to family */
#define	CMS_MATCH_MODEL		2	/* Match down to model */
#define	CMS_MATCH_STEPPING	3	/* Match down to stepping */

/*
 * Structure used to keep track of modules we have loaded.
 */
typedef struct cms {
	struct cms *cms_next;
	struct cms *cms_prev;
	const cms_ops_t *cms_ops;
	struct modctl *cms_modp;
	uint_t cms_refcnt;
} cms_t;

static cms_t *cms_list;
static kmutex_t cms_load_lock;

/*
 * We stash a cms_t and associated private data via cmi_hdl_setspecific.
 */
struct cms_ctl {
	cms_t *cs_cms;
	void *cs_cmsdata;
};

static cms_t *
cms_hdl_getcms(cmi_hdl_t hdl)
{
	struct cms_ctl *cdp = cmi_hdl_getspecific(hdl);

	return (cdp != NULL ? cdp->cs_cms : NULL);
}

void *
cms_hdl_getcmsdata(cmi_hdl_t hdl)
{
	struct cms_ctl *cdp = cmi_hdl_getspecific(hdl);

	return (cdp != NULL ? cdp->cs_cmsdata : NULL);
}

static void
cms_link(cms_t *cms)
{
	ASSERT(MUTEX_HELD(&cms_load_lock));

	cms->cms_prev = NULL;
	cms->cms_next = cms_list;
	if (cms_list != NULL)
		cms_list->cms_prev = cms;
	cms_list = cms;
}

static void
cms_unlink(cms_t *cms)
{
	ASSERT(MUTEX_HELD(&cms_load_lock));
	ASSERT(cms->cms_refcnt == 0);

	if (cms->cms_prev != NULL)
		cms->cms_prev->cms_next = cms->cms_next;

	if (cms->cms_next != NULL)
		cms->cms_next->cms_prev = cms->cms_prev;

	if (cms_list == cms)
		cms_list = cms->cms_next;
}

/*
 * Hold the module in memory.  We call to CPU modules without using the
 * stubs mechanism, so these modules must be manually held in memory.
 * The mod_ref acts as if another loaded module has a dependency on us.
 */
static void
cms_hold(cms_t *cms)
{
	ASSERT(MUTEX_HELD(&cms_load_lock));

	mutex_enter(&mod_lock);
	cms->cms_modp->mod_ref++;
	mutex_exit(&mod_lock);
	cms->cms_refcnt++;
}

static void
cms_rele(cms_t *cms)
{
	ASSERT(MUTEX_HELD(&cms_load_lock));

	mutex_enter(&mod_lock);
	cms->cms_modp->mod_ref--;
	mutex_exit(&mod_lock);

	if (--cms->cms_refcnt == 0) {
		cms_unlink(cms);
		kmem_free(cms, sizeof (cms_t));
	}
}

static cms_ops_t *
cms_getops(modctl_t *modp)
{
	cms_ops_t *ops;

	if ((ops = (cms_ops_t *)modlookup_by_modctl(modp, "_cms_ops")) ==
	    NULL) {
		cmn_err(CE_WARN, "cpu_ms module '%s' is invalid: no _cms_ops "
		    "found", modp->mod_modname);
		return (NULL);
	}

	if (ops->cms_init == NULL) {
		cmn_err(CE_WARN, "cpu_ms module '%s' is invalid: no cms_init "
		    "entry point", modp->mod_modname);
		return (NULL);
	}

	return (ops);
}

static cms_t *
cms_load_modctl(modctl_t *modp)
{
	cms_ops_t *ops;
	uintptr_t ver;
	cms_t *cms;
	cms_api_ver_t apiver;

	ASSERT(MUTEX_HELD(&cms_load_lock));

	for (cms = cms_list; cms != NULL; cms = cms->cms_next) {
		if (cms->cms_modp == modp)
			return (cms);
	}

	if ((ver = modlookup_by_modctl(modp, "_cms_api_version")) == NULL) {
		cmn_err(CE_WARN, "cpu model-specific module '%s' is invalid:  "
		    "no _cms_api_version", modp->mod_modname);
		return (NULL);
	} else {
		apiver = *((cms_api_ver_t *)ver);
		if (!CMS_API_VERSION_CHKMAGIC(apiver)) {
			cmn_err(CE_WARN, "cpu model-specific module '%s' is "
			    "invalid: _cms_api_version 0x%x has bad magic",
			    modp->mod_modname, apiver);
			return (NULL);
		}
	}

	if (apiver != CMS_API_VERSION) {
		cmn_err(CE_WARN, "cpu model-specific module '%s' has API "
		    "version %d, kernel requires API version %d",
		    modp->mod_modname, CMS_API_VERSION_TOPRINT(apiver),
		    CMS_API_VERSION_TOPRINT(CMS_API_VERSION));
	return (NULL);
	}

	if ((ops = cms_getops(modp)) == NULL)
		return (NULL);

	cms = kmem_zalloc(sizeof (cms_t), KM_SLEEP);
	cms->cms_ops = ops;
	cms->cms_modp = modp;

	cms_link(cms);

	return (cms);
}

static int
cms_cpu_match(cmi_hdl_t hdl1, cmi_hdl_t hdl2, int match)
{
	if (match >= CMS_MATCH_VENDOR &&
	    cmi_hdl_vendor(hdl1) != cmi_hdl_vendor(hdl2))
		return (0);

	if (match >= CMS_MATCH_FAMILY &&
	    cmi_hdl_family(hdl1) != cmi_hdl_family(hdl2))
		return (0);

	if (match >= CMS_MATCH_MODEL &&
	    cmi_hdl_model(hdl1) != cmi_hdl_model(hdl2))
		return (0);

	if (match >= CMS_MATCH_STEPPING &&
	    cmi_hdl_stepping(hdl1) != cmi_hdl_stepping(hdl2))
		return (0);

	return (1);
}

static int
cms_search_list_cb(cmi_hdl_t whdl, void *arg1, void *arg2, void *arg3)
{
	cmi_hdl_t thdl = (cmi_hdl_t)arg1;
	int match = *((int *)arg2);
	cmi_hdl_t *rsltp = (cmi_hdl_t *)arg3;

	if (cms_cpu_match(thdl, whdl, match)) {
		cmi_hdl_hold(whdl);	/* short-term hold */
		*rsltp = whdl;
		return (CMI_HDL_WALK_DONE);
	} else {
		return (CMI_HDL_WALK_NEXT);
	}
}

/*
 * Look to see if we've already got a module loaded for a CPU just
 * like this one.  If we do, then we'll re-use it.
 */
static cms_t *
cms_search_list(cmi_hdl_t hdl, int match)
{
	cmi_hdl_t dhdl = NULL;
	cms_t *cms = NULL;

	ASSERT(MUTEX_HELD(&cms_load_lock));

	cmi_hdl_walk(cms_search_list_cb, (void *)hdl, (void *)&match, &dhdl);
	if (dhdl) {
		cms = HDL2CMS(dhdl);
		cmi_hdl_rele(dhdl);	/* held in cms_search_list_cb */
	}

	return (cms);
}

/*
 * Try to find or load a module that offers model-specific support for
 * this vendor/family/model/stepping combination.  When attempting to load
 * a module we look in CPUMOD_MS_SUBDIR first for a match on
 * vendor/family/model/stepping, then on vendor/family/model (ignoring
 * stepping), then on vendor/family (ignoring model and stepping), then
 * on vendor alone.
 */
static cms_t *
cms_load_module(cmi_hdl_t hdl, int match, int *chosenp)
{
	modctl_t *modp;
	cms_t *cms;
	int modid;
	uint_t s[3];

	ASSERT(MUTEX_HELD(&cms_load_lock));
	ASSERT(match == CMS_MATCH_STEPPING || match == CMS_MATCH_MODEL ||
	    match == CMS_MATCH_FAMILY || match == CMS_MATCH_VENDOR);

	s[0] = cmi_hdl_family(hdl);
	s[1] = cmi_hdl_model(hdl);
	s[2] = cmi_hdl_stepping(hdl);

	/*
	 * Have we already loaded a module for a cpu with the same
	 * vendor/family/model/stepping?
	 */
	if ((cms = cms_search_list(hdl, match)) != NULL) {
		cms_hold(cms);
		return (cms);
	}

	modid = modload_qualified(CPUMOD_MS_SUBDIR, CPUMOD_MS_PREFIX,
	    cmi_hdl_vendorstr(hdl), ".", s, match, chosenp);

	if (modid == -1)
		return (NULL);

	modp = mod_hold_by_id(modid);
	cms = cms_load_modctl(modp);
	if (cms)
		cms_hold(cms);
	mod_release_mod(modp);

	return (cms);
}

static cms_t *
cms_load_specific(cmi_hdl_t hdl, void **datap)
{
	cms_t *cms;
	int err;
	int i;

	ASSERT(MUTEX_HELD(&cms_load_lock));

	for (i = CMS_MATCH_STEPPING; i >= CMS_MATCH_VENDOR; i--) {
		int suffixlevel;

		if ((cms = cms_load_module(hdl, i, &suffixlevel)) == NULL)
			return (NULL);

		/*
		 * A module has loaded and has a _cms_ops structure, and the
		 * module has been held for this instance.  Call the cms_init
		 * entry point - we expect success (0) or ENOTSUP.
		 */
		if ((err = cms->cms_ops->cms_init(hdl, datap)) == 0) {
			if (boothowto & RB_VERBOSE) {
				printf("initialized model-specific "
				    "module '%s' on chip %d core %d "
				    "strand %d\n",
				    cms->cms_modp->mod_modname,
				    cmi_hdl_chipid(hdl), cmi_hdl_coreid(hdl),
				    cmi_hdl_strandid(hdl));
			}
			return (cms);
		} else if (err != ENOTSUP) {
			cmn_err(CE_WARN, "failed to init model-specific "
			    "module '%s' on chip %d core %d strand %d: err=%d",
			    cms->cms_modp->mod_modname,
			    cmi_hdl_chipid(hdl), cmi_hdl_coreid(hdl),
			    cmi_hdl_strandid(hdl), err);
		}

		/*
		 * The module failed or declined to init, so release
		 * it and potentially change i to be equal to he number
		 * of suffices actually used in the last module path.
		 */
		cms_rele(cms);
		i = suffixlevel;
	}

	return (NULL);
}

void
cms_init(cmi_hdl_t hdl)
{
	cms_t *cms;
	void *data;

	if (cms_no_model_specific != 0)
		return;

	mutex_enter(&cms_load_lock);

	if ((cms = cms_load_specific(hdl, &data)) != NULL) {
		struct cms_ctl *cdp;

		ASSERT(cmi_hdl_getspecific(hdl) == NULL);

		cdp = kmem_alloc(sizeof (*cdp), KM_SLEEP);
		cdp->cs_cms = cms;
		cdp->cs_cmsdata = data;
		cmi_hdl_setspecific(hdl, cdp);
	}

	mutex_exit(&cms_load_lock);
}

void
cms_fini(cmi_hdl_t hdl)
{
	cms_t *cms = HDL2CMS(hdl);
	struct cms_ctl *cdp;

	if (CMS_OP_PRESENT(cms, cms_fini))
		CMS_OPS(cms)->cms_fini(hdl);

	mutex_enter(&cms_load_lock);
	cdp = (struct cms_ctl *)cmi_hdl_getspecific(hdl);
	if (cdp != NULL) {
		if (cdp->cs_cms != NULL)
			cms_rele(cdp->cs_cms);
		kmem_free(cdp, sizeof (*cdp));
	}
	mutex_exit(&cms_load_lock);
}

boolean_t
cms_present(cmi_hdl_t hdl)
{
	return (HDL2CMS(hdl) != NULL ? B_TRUE : B_FALSE);
}

void
cms_post_startup(cmi_hdl_t hdl)
{
	cms_t *cms = HDL2CMS(hdl);

	if (CMS_OP_PRESENT(cms, cms_post_startup))
		CMS_OPS(cms)->cms_post_startup(hdl);
}

void
cms_post_mpstartup(cmi_hdl_t hdl)
{
	cms_t *cms = HDL2CMS(hdl);

	if (CMS_OP_PRESENT(cms, cms_post_mpstartup))
		CMS_OPS(cms)->cms_post_mpstartup(hdl);
}

size_t
cms_logout_size(cmi_hdl_t hdl)
{
	cms_t *cms = HDL2CMS(hdl);

	if (!CMS_OP_PRESENT(cms, cms_logout_size))
		return (0);

	return (CMS_OPS(cms)->cms_logout_size(hdl));
}

uint64_t
cms_mcgctl_val(cmi_hdl_t hdl, int nbanks, uint64_t def)
{
	cms_t *cms = HDL2CMS(hdl);

	if (!CMS_OP_PRESENT(cms, cms_mcgctl_val))
		return (def);

	return (CMS_OPS(cms)->cms_mcgctl_val(hdl, nbanks, def));
}

boolean_t
cms_bankctl_skipinit(cmi_hdl_t hdl, int banknum)
{
	cms_t *cms = HDL2CMS(hdl);

	if (!CMS_OP_PRESENT(cms, cms_bankctl_skipinit))
		return (B_FALSE);

	return (CMS_OPS(cms)->cms_bankctl_skipinit(hdl, banknum));
}

uint64_t
cms_bankctl_val(cmi_hdl_t hdl, int banknum, uint64_t def)
{
	cms_t *cms = HDL2CMS(hdl);

	if (!CMS_OP_PRESENT(cms, cms_bankctl_val))
		return (def);

	return (CMS_OPS(cms)->cms_bankctl_val(hdl, banknum, def));
}

boolean_t
cms_bankstatus_skipinit(cmi_hdl_t hdl, int banknum)
{
	cms_t *cms = HDL2CMS(hdl);

	if (!CMS_OP_PRESENT(cms, cms_bankstatus_skipinit))
		return (B_FALSE);

	return (CMS_OPS(cms)->cms_bankstatus_skipinit(hdl, banknum));
}

uint64_t
cms_bankstatus_val(cmi_hdl_t hdl, int banknum, uint64_t def)
{
	cms_t *cms = HDL2CMS(hdl);

	if (!CMS_OP_PRESENT(cms, cms_bankstatus_val))
		return (def);

	return (CMS_OPS(cms)->cms_bankstatus_val(hdl, banknum, def));
}

void
cms_mca_init(cmi_hdl_t hdl, int nbanks)
{
	cms_t *cms = HDL2CMS(hdl);

	if (CMS_OP_PRESENT(cms, cms_mca_init))
		CMS_OPS(cms)->cms_mca_init(hdl, nbanks);
}

uint64_t
cms_poll_ownermask(cmi_hdl_t hdl, hrtime_t poll_interval)
{
	cms_t *cms = HDL2CMS(hdl);

	if (CMS_OP_PRESENT(cms, cms_poll_ownermask))
		return (CMS_OPS(cms)->cms_poll_ownermask(hdl, poll_interval));
	else
		return (-1ULL);		/* poll all banks by default */
}

void
cms_bank_logout(cmi_hdl_t hdl, int banknum, uint64_t status, uint64_t addr,
    uint64_t misc, void *mslogout)
{
	cms_t *cms = HDL2CMS(hdl);

	if (mslogout != NULL && CMS_OP_PRESENT(cms, cms_bank_logout))
		CMS_OPS(cms)->cms_bank_logout(hdl, banknum, status, addr,
		    misc, mslogout);
}

cms_errno_t
cms_msrinject(cmi_hdl_t hdl, uint_t msr, uint64_t val)
{
	cms_t *cms = HDL2CMS(hdl);

	if (CMS_OP_PRESENT(cms, cms_msrinject))
		return (CMS_OPS(cms)->cms_msrinject(hdl, msr, val));
	else
		return (CMSERR_NOTSUP);
}

uint32_t
cms_error_action(cmi_hdl_t hdl, int ismc, int banknum, uint64_t status,
    uint64_t addr, uint64_t misc, void *mslogout)
{
	cms_t *cms = HDL2CMS(hdl);

	if (CMS_OP_PRESENT(cms, cms_error_action))
		return (CMS_OPS(cms)->cms_error_action(hdl, ismc, banknum,
		    status, addr, misc, mslogout));
	else
		return (0);
}

cms_cookie_t
cms_disp_match(cmi_hdl_t hdl, int ismc, int banknum, uint64_t status,
    uint64_t addr, uint64_t misc, void *mslogout)
{
	cms_t *cms = HDL2CMS(hdl);

	if (CMS_OP_PRESENT(cms, cms_disp_match))
		return (CMS_OPS(cms)->cms_disp_match(hdl, ismc, banknum,
		    status, addr, misc, mslogout));
	else
		return (NULL);

}

void
cms_ereport_class(cmi_hdl_t hdl, cms_cookie_t mscookie, const char **cpuclsp,
    const char **leafclsp)
{
	cms_t *cms = HDL2CMS(hdl);

	if (cpuclsp == NULL || leafclsp == NULL)
		return;

	*cpuclsp = *leafclsp = NULL;
	if (CMS_OP_PRESENT(cms, cms_ereport_class)) {
		CMS_OPS(cms)->cms_ereport_class(hdl, mscookie, cpuclsp,
		    leafclsp);
	}
}

nvlist_t *
cms_ereport_detector(cmi_hdl_t hdl, int bankno, cms_cookie_t mscookie,
    nv_alloc_t *nva)
{
	cms_t *cms = HDL2CMS(hdl);

	if (CMS_OP_PRESENT(cms, cms_ereport_detector))
		return (CMS_OPS(cms)->cms_ereport_detector(hdl, bankno,
		    mscookie, nva));
	else
		return (NULL);

}

boolean_t
cms_ereport_includestack(cmi_hdl_t hdl, cms_cookie_t mscookie)
{
	cms_t *cms = HDL2CMS(hdl);

	if (CMS_OP_PRESENT(cms, cms_ereport_includestack)) {
		return (CMS_OPS(cms)->cms_ereport_includestack(hdl, mscookie));
	} else {
		return (B_FALSE);
	}
}

void
cms_ereport_add_logout(cmi_hdl_t hdl, nvlist_t *nvl, nv_alloc_t *nva,
    int banknum, uint64_t status, uint64_t addr, uint64_t misc, void *mslogout,
    cms_cookie_t mscookie)
{
	cms_t *cms = HDL2CMS(hdl);

	if (CMS_OP_PRESENT(cms, cms_ereport_add_logout))
		CMS_OPS(cms)->cms_ereport_add_logout(hdl, nvl, nva, banknum,
		    status, addr, misc, mslogout, mscookie);

}
