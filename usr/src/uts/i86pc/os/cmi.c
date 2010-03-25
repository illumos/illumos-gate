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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Public interface to routines implemented by CPU modules
 */

#include <sys/types.h>
#include <sys/atomic.h>
#include <sys/x86_archext.h>
#include <sys/cpu_module_impl.h>
#include <sys/cpu_module_ms.h>
#include <sys/fm/util.h>
#include <sys/reboot.h>
#include <sys/modctl.h>
#include <sys/param.h>
#include <sys/cmn_err.h>
#include <sys/systm.h>
#include <sys/fm/protocol.h>
#include <sys/pcb.h>
#include <sys/ontrap.h>
#include <sys/psw.h>
#include <sys/privregs.h>
#include <sys/machsystm.h>

/*
 * Set to force cmi_init to fail.
 */
int cmi_no_init = 0;

/*
 * Set to avoid MCA initialization.
 */
int cmi_no_mca_init = 0;

/*
 * If cleared for debugging we will not attempt to load a model-specific
 * cpu module but will load the generic cpu module instead.
 */
int cmi_force_generic = 0;

/*
 * If cleared for debugging, we will suppress panicking on fatal hardware
 * errors.  This should *only* be used for debugging; it use can and will
 * cause data corruption if actual hardware errors are detected by the system.
 */
int cmi_panic_on_uncorrectable_error = 1;

#ifndef __xpv
/*
 * Set to indicate whether we are able to enable cmci interrupt.
 */
int cmi_enable_cmci = 0;
#endif

/*
 * Subdirectory (relative to the module search path) in which we will
 * look for cpu modules.
 */
#define	CPUMOD_SUBDIR	"cpu"

/*
 * CPU modules have a filenames such as "cpu.AuthenticAMD.15" and
 * "cpu.generic" - the "cpu" prefix is specified by the following.
 */
#define	CPUMOD_PREFIX	"cpu"

/*
 * Structure used to keep track of cpu modules we have loaded and their ops
 */
typedef struct cmi {
	struct cmi *cmi_next;
	struct cmi *cmi_prev;
	const cmi_ops_t *cmi_ops;
	struct modctl *cmi_modp;
	uint_t cmi_refcnt;
} cmi_t;

static cmi_t *cmi_list;
static const cmi_mc_ops_t *cmi_mc_global_ops;
static void *cmi_mc_global_data;
static kmutex_t cmi_load_lock;

/*
 * Functions we need from cmi_hw.c that are not part of the cpu_module.h
 * interface.
 */
extern cmi_hdl_t cmi_hdl_create(enum cmi_hdl_class, uint_t, uint_t, uint_t);
extern void cmi_hdl_destroy(cmi_hdl_t ophdl);
extern void cmi_hdl_setcmi(cmi_hdl_t, void *, void *);
extern void *cmi_hdl_getcmi(cmi_hdl_t);
extern void cmi_hdl_setmc(cmi_hdl_t, const struct cmi_mc_ops *, void *);
extern void cmi_hdl_inj_begin(cmi_hdl_t);
extern void cmi_hdl_inj_end(cmi_hdl_t);
extern void cmi_read_smbios(cmi_hdl_t);

#define	HDL2CMI(hdl)		cmi_hdl_getcmi(hdl)

#define	CMI_OPS(cmi)		(cmi)->cmi_ops
#define	CMI_OP_PRESENT(cmi, op)	((cmi) && CMI_OPS(cmi)->op != NULL)

#define	CMI_MATCH_VENDOR	0	/* Just match on vendor */
#define	CMI_MATCH_FAMILY	1	/* Match down to family */
#define	CMI_MATCH_MODEL		2	/* Match down to model */
#define	CMI_MATCH_STEPPING	3	/* Match down to stepping */

static void
cmi_link(cmi_t *cmi)
{
	ASSERT(MUTEX_HELD(&cmi_load_lock));

	cmi->cmi_prev = NULL;
	cmi->cmi_next = cmi_list;
	if (cmi_list != NULL)
		cmi_list->cmi_prev = cmi;
	cmi_list = cmi;
}

static void
cmi_unlink(cmi_t *cmi)
{
	ASSERT(MUTEX_HELD(&cmi_load_lock));
	ASSERT(cmi->cmi_refcnt == 0);

	if (cmi->cmi_prev != NULL)
		cmi->cmi_prev = cmi->cmi_next;

	if (cmi->cmi_next != NULL)
		cmi->cmi_next->cmi_prev = cmi->cmi_prev;

	if (cmi_list == cmi)
		cmi_list = cmi->cmi_next;
}

/*
 * Hold the module in memory.  We call to CPU modules without using the
 * stubs mechanism, so these modules must be manually held in memory.
 * The mod_ref acts as if another loaded module has a dependency on us.
 */
static void
cmi_hold(cmi_t *cmi)
{
	ASSERT(MUTEX_HELD(&cmi_load_lock));

	mutex_enter(&mod_lock);
	cmi->cmi_modp->mod_ref++;
	mutex_exit(&mod_lock);
	cmi->cmi_refcnt++;
}

static void
cmi_rele(cmi_t *cmi)
{
	ASSERT(MUTEX_HELD(&cmi_load_lock));

	mutex_enter(&mod_lock);
	cmi->cmi_modp->mod_ref--;
	mutex_exit(&mod_lock);

	if (--cmi->cmi_refcnt == 0) {
		cmi_unlink(cmi);
		kmem_free(cmi, sizeof (cmi_t));
	}
}

static cmi_ops_t *
cmi_getops(modctl_t *modp)
{
	cmi_ops_t *ops;

	if ((ops = (cmi_ops_t *)modlookup_by_modctl(modp, "_cmi_ops")) ==
	    NULL) {
		cmn_err(CE_WARN, "cpu module '%s' is invalid: no _cmi_ops "
		    "found", modp->mod_modname);
		return (NULL);
	}

	if (ops->cmi_init == NULL) {
		cmn_err(CE_WARN, "cpu module '%s' is invalid: no cmi_init "
		    "entry point", modp->mod_modname);
		return (NULL);
	}

	return (ops);
}

static cmi_t *
cmi_load_modctl(modctl_t *modp)
{
	cmi_ops_t *ops;
	uintptr_t ver;
	cmi_t *cmi;
	cmi_api_ver_t apiver;

	ASSERT(MUTEX_HELD(&cmi_load_lock));

	for (cmi = cmi_list; cmi != NULL; cmi = cmi->cmi_next) {
		if (cmi->cmi_modp == modp)
			return (cmi);
	}

	if ((ver = modlookup_by_modctl(modp, "_cmi_api_version")) == NULL) {
		/*
		 * Apparently a cpu module before versioning was introduced -
		 * we call this version 0.
		 */
		apiver = CMI_API_VERSION_0;
	} else {
		apiver = *((cmi_api_ver_t *)ver);
		if (!CMI_API_VERSION_CHKMAGIC(apiver)) {
			cmn_err(CE_WARN, "cpu module '%s' is invalid: "
			    "_cmi_api_version 0x%x has bad magic",
			    modp->mod_modname, apiver);
			return (NULL);
		}
	}

	if (apiver != CMI_API_VERSION) {
		cmn_err(CE_WARN, "cpu module '%s' has API version %d, "
		    "kernel requires API version %d", modp->mod_modname,
		    CMI_API_VERSION_TOPRINT(apiver),
		    CMI_API_VERSION_TOPRINT(CMI_API_VERSION));
		return (NULL);
	}

	if ((ops = cmi_getops(modp)) == NULL)
		return (NULL);

	cmi = kmem_zalloc(sizeof (*cmi), KM_SLEEP);
	cmi->cmi_ops = ops;
	cmi->cmi_modp = modp;

	cmi_link(cmi);

	return (cmi);
}

static int
cmi_cpu_match(cmi_hdl_t hdl1, cmi_hdl_t hdl2, int match)
{
	if (match >= CMI_MATCH_VENDOR &&
	    cmi_hdl_vendor(hdl1) != cmi_hdl_vendor(hdl2))
		return (0);

	if (match >= CMI_MATCH_FAMILY &&
	    cmi_hdl_family(hdl1) != cmi_hdl_family(hdl2))
		return (0);

	if (match >= CMI_MATCH_MODEL &&
	    cmi_hdl_model(hdl1) != cmi_hdl_model(hdl2))
		return (0);

	if (match >= CMI_MATCH_STEPPING &&
	    cmi_hdl_stepping(hdl1) != cmi_hdl_stepping(hdl2))
		return (0);

	return (1);
}

static int
cmi_search_list_cb(cmi_hdl_t whdl, void *arg1, void *arg2, void *arg3)
{
	cmi_hdl_t thdl = (cmi_hdl_t)arg1;
	int match = *((int *)arg2);
	cmi_hdl_t *rsltp = (cmi_hdl_t *)arg3;

	if (cmi_cpu_match(thdl, whdl, match)) {
		cmi_hdl_hold(whdl);	/* short-term hold */
		*rsltp = whdl;
		return (CMI_HDL_WALK_DONE);
	} else {
		return (CMI_HDL_WALK_NEXT);
	}
}

static cmi_t *
cmi_search_list(cmi_hdl_t hdl, int match)
{
	cmi_hdl_t dhdl = NULL;
	cmi_t *cmi = NULL;

	ASSERT(MUTEX_HELD(&cmi_load_lock));

	cmi_hdl_walk(cmi_search_list_cb, (void *)hdl, (void *)&match, &dhdl);
	if (dhdl) {
		cmi = HDL2CMI(dhdl);
		cmi_hdl_rele(dhdl);	/* held in cmi_search_list_cb */
	}

	return (cmi);
}

static cmi_t *
cmi_load_module(cmi_hdl_t hdl, int match, int *chosenp)
{
	modctl_t *modp;
	cmi_t *cmi;
	int modid;
	uint_t s[3];

	ASSERT(MUTEX_HELD(&cmi_load_lock));
	ASSERT(match == CMI_MATCH_STEPPING || match == CMI_MATCH_MODEL ||
	    match == CMI_MATCH_FAMILY || match == CMI_MATCH_VENDOR);

	/*
	 * Have we already loaded a module for a cpu with the same
	 * vendor/family/model/stepping?
	 */
	if ((cmi = cmi_search_list(hdl, match)) != NULL) {
		cmi_hold(cmi);
		return (cmi);
	}

	s[0] = cmi_hdl_family(hdl);
	s[1] = cmi_hdl_model(hdl);
	s[2] = cmi_hdl_stepping(hdl);
	modid = modload_qualified(CPUMOD_SUBDIR, CPUMOD_PREFIX,
	    cmi_hdl_vendorstr(hdl), ".", s, match, chosenp);

	if (modid == -1)
		return (NULL);

	modp = mod_hold_by_id(modid);
	cmi = cmi_load_modctl(modp);
	if (cmi)
		cmi_hold(cmi);
	mod_release_mod(modp);

	return (cmi);
}

/*
 * Try to load a cpu module with specific support for this chip type.
 */
static cmi_t *
cmi_load_specific(cmi_hdl_t hdl, void **datap)
{
	cmi_t *cmi;
	int err;
	int i;

	ASSERT(MUTEX_HELD(&cmi_load_lock));

	for (i = CMI_MATCH_STEPPING; i >= CMI_MATCH_VENDOR; i--) {
		int suffixlevel;

		if ((cmi = cmi_load_module(hdl, i, &suffixlevel)) == NULL)
			return (NULL);

		/*
		 * A module has loaded and has a _cmi_ops structure, and the
		 * module has been held for this instance.  Call its cmi_init
		 * entry point - we expect success (0) or ENOTSUP.
		 */
		if ((err = cmi->cmi_ops->cmi_init(hdl, datap)) == 0) {
			if (boothowto & RB_VERBOSE) {
				printf("initialized cpu module '%s' on "
				    "chip %d core %d strand %d\n",
				    cmi->cmi_modp->mod_modname,
				    cmi_hdl_chipid(hdl), cmi_hdl_coreid(hdl),
				    cmi_hdl_strandid(hdl));
			}
			return (cmi);
		} else if (err != ENOTSUP) {
			cmn_err(CE_WARN, "failed to init cpu module '%s' on "
			    "chip %d core %d strand %d: err=%d\n",
			    cmi->cmi_modp->mod_modname,
			    cmi_hdl_chipid(hdl), cmi_hdl_coreid(hdl),
			    cmi_hdl_strandid(hdl), err);
		}

		/*
		 * The module failed or declined to init, so release
		 * it and update i to be equal to the number
		 * of suffices actually used in the last module path.
		 */
		cmi_rele(cmi);
		i = suffixlevel;
	}

	return (NULL);
}

/*
 * Load the generic IA32 MCA cpu module, which may still supplement
 * itself with model-specific support through cpu model-specific modules.
 */
static cmi_t *
cmi_load_generic(cmi_hdl_t hdl, void **datap)
{
	modctl_t *modp;
	cmi_t *cmi;
	int modid;
	int err;

	ASSERT(MUTEX_HELD(&cmi_load_lock));

	if ((modid = modload(CPUMOD_SUBDIR, CPUMOD_PREFIX ".generic")) == -1)
		return (NULL);

	modp = mod_hold_by_id(modid);
	cmi = cmi_load_modctl(modp);
	if (cmi)
		cmi_hold(cmi);
	mod_release_mod(modp);

	if (cmi == NULL)
		return (NULL);

	if ((err = cmi->cmi_ops->cmi_init(hdl, datap)) != 0) {
		if (err != ENOTSUP)
			cmn_err(CE_WARN, CPUMOD_PREFIX ".generic failed to "
			    "init: err=%d", err);
		cmi_rele(cmi);
		return (NULL);
	}

	return (cmi);
}

cmi_hdl_t
cmi_init(enum cmi_hdl_class class, uint_t chipid, uint_t coreid,
    uint_t strandid)
{
	cmi_t *cmi = NULL;
	cmi_hdl_t hdl;
	void *data;

	if (cmi_no_init) {
		cmi_no_mca_init = 1;
		return (NULL);
	}

	mutex_enter(&cmi_load_lock);

	if ((hdl = cmi_hdl_create(class, chipid, coreid, strandid)) == NULL) {
		mutex_exit(&cmi_load_lock);
		cmn_err(CE_WARN, "There will be no MCA support on chip %d "
		    "core %d strand %d (cmi_hdl_create returned NULL)\n",
		    chipid, coreid, strandid);
		return (NULL);
	}

	if (!cmi_force_generic)
		cmi = cmi_load_specific(hdl, &data);

	if (cmi == NULL && (cmi = cmi_load_generic(hdl, &data)) == NULL) {
		cmn_err(CE_WARN, "There will be no MCA support on chip %d "
		    "core %d strand %d\n", chipid, coreid, strandid);
		cmi_hdl_rele(hdl);
		mutex_exit(&cmi_load_lock);
		return (NULL);
	}

	cmi_hdl_setcmi(hdl, cmi, data);

	cms_init(hdl);

	cmi_read_smbios(hdl);

	mutex_exit(&cmi_load_lock);

	return (hdl);
}

/*
 * cmi_fini is called on DR deconfigure of a cpu resource.
 * It should not be called at simple offline of a cpu.
 */
void
cmi_fini(cmi_hdl_t hdl)
{
	cmi_t *cmi = HDL2CMI(hdl);

	if (cms_present(hdl))
		cms_fini(hdl);

	if (CMI_OP_PRESENT(cmi, cmi_fini))
		CMI_OPS(cmi)->cmi_fini(hdl);

	cmi_hdl_destroy(hdl);
}

/*
 * cmi_post_startup is called from post_startup for the boot cpu only (no
 * other cpus are started yet).
 */
void
cmi_post_startup(void)
{
	cmi_hdl_t hdl;
	cmi_t *cmi;

	if (cmi_no_mca_init != 0 ||
	    (hdl = cmi_hdl_any()) == NULL)	/* short-term hold */
		return;

	cmi = HDL2CMI(hdl);

	if (CMI_OP_PRESENT(cmi, cmi_post_startup))
		CMI_OPS(cmi)->cmi_post_startup(hdl);

	cmi_hdl_rele(hdl);
}

/*
 * Called just once from start_other_cpus when all processors are started.
 * This will not be called for each cpu, so the registered op must not
 * assume it is called as such.  We are not necessarily executing on
 * the boot cpu.
 */
void
cmi_post_mpstartup(void)
{
	cmi_hdl_t hdl;
	cmi_t *cmi;

	if (cmi_no_mca_init != 0 ||
	    (hdl = cmi_hdl_any()) == NULL)	/* short-term hold */
		return;

	cmi = HDL2CMI(hdl);

	if (CMI_OP_PRESENT(cmi, cmi_post_mpstartup))
		CMI_OPS(cmi)->cmi_post_mpstartup(hdl);

	cmi_hdl_rele(hdl);
}

void
cmi_faulted_enter(cmi_hdl_t hdl)
{
	cmi_t *cmi = HDL2CMI(hdl);

	if (cmi_no_mca_init != 0)
		return;

	if (CMI_OP_PRESENT(cmi, cmi_faulted_enter))
		CMI_OPS(cmi)->cmi_faulted_enter(hdl);
}

void
cmi_faulted_exit(cmi_hdl_t hdl)
{
	cmi_t *cmi = HDL2CMI(hdl);

	if (cmi_no_mca_init != 0)
		return;

	if (CMI_OP_PRESENT(cmi, cmi_faulted_exit))
		CMI_OPS(cmi)->cmi_faulted_exit(hdl);
}

void
cmi_mca_init(cmi_hdl_t hdl)
{
	cmi_t *cmi;

	if (cmi_no_mca_init != 0)
		return;

	cmi = HDL2CMI(hdl);

	if (CMI_OP_PRESENT(cmi, cmi_mca_init))
		CMI_OPS(cmi)->cmi_mca_init(hdl);
}

#define	CMI_RESPONSE_PANIC		0x0	/* panic must have value 0 */
#define	CMI_RESPONSE_NONE		0x1
#define	CMI_RESPONSE_CKILL		0x2
#define	CMI_RESPONSE_REBOOT		0x3	/* not implemented */
#define	CMI_RESPONSE_ONTRAP_PROT	0x4
#define	CMI_RESPONSE_LOFAULT_PROT	0x5

/*
 * Return 0 if we will panic in response to this machine check, otherwise
 * non-zero.  If the caller is cmi_mca_trap in this file then the nonzero
 * return values are to be interpreted from CMI_RESPONSE_* above.
 *
 * This function must just return what will be done without actually
 * doing anything; this includes not changing the regs.
 */
int
cmi_mce_response(struct regs *rp, uint64_t disp)
{
	int panicrsp = cmi_panic_on_uncorrectable_error ? CMI_RESPONSE_PANIC :
	    CMI_RESPONSE_NONE;
	on_trap_data_t *otp;

	ASSERT(rp != NULL);	/* don't call for polling, only on #MC */

	/*
	 * If no bits are set in the disposition then there is nothing to
	 * worry about and we do not need to trampoline to ontrap or
	 * lofault handlers.
	 */
	if (disp == 0)
		return (CMI_RESPONSE_NONE);

	/*
	 * Unconstrained errors cannot be forgiven, even by ontrap or
	 * lofault protection.  The data is not poisoned and may not
	 * even belong to the trapped context - eg a writeback of
	 * data that is found to be bad.
	 */
	if (disp & CMI_ERRDISP_UC_UNCONSTRAINED)
		return (panicrsp);

	/*
	 * ontrap OT_DATA_EC and lofault protection forgive any disposition
	 * other than unconstrained, even those normally forced fatal.
	 */
	if ((otp = curthread->t_ontrap) != NULL && otp->ot_prot & OT_DATA_EC)
		return (CMI_RESPONSE_ONTRAP_PROT);
	else if (curthread->t_lofault)
		return (CMI_RESPONSE_LOFAULT_PROT);

	/*
	 * Forced-fatal errors are terminal even in user mode.
	 */
	if (disp & CMI_ERRDISP_FORCEFATAL)
		return (panicrsp);

	/*
	 * If the trapped context is corrupt or we have no instruction pointer
	 * to resume at (and aren't trampolining to a fault handler)
	 * then in the kernel case we must panic and in usermode we
	 * kill the affected contract.
	 */
	if (disp & (CMI_ERRDISP_CURCTXBAD | CMI_ERRDISP_RIPV_INVALID))
		return (USERMODE(rp->r_cs) ?  CMI_RESPONSE_CKILL : panicrsp);

	/*
	 * Anything else is harmless
	 */
	return (CMI_RESPONSE_NONE);
}

int cma_mca_trap_panic_suppressed = 0;

static void
cmi_mca_panic(void)
{
	if (cmi_panic_on_uncorrectable_error) {
		fm_panic("Unrecoverable Machine-Check Exception");
	} else {
		cmn_err(CE_WARN, "suppressing panic from fatal #mc");
		cma_mca_trap_panic_suppressed++;
	}
}


int cma_mca_trap_contract_kills = 0;
int cma_mca_trap_ontrap_forgiven = 0;
int cma_mca_trap_lofault_forgiven = 0;

/*
 * Native #MC handler - we branch to here from mcetrap
 */
/*ARGSUSED*/
void
cmi_mca_trap(struct regs *rp)
{
#ifndef	__xpv
	cmi_hdl_t hdl = NULL;
	uint64_t disp;
	cmi_t *cmi;
	int s;

	if (cmi_no_mca_init != 0)
		return;

	/*
	 * This function can call cmn_err, and the cpu module cmi_mca_trap
	 * entry point may also elect to call cmn_err (e.g., if it can't
	 * log the error onto an errorq, say very early in boot).
	 * We need to let cprintf know that we must not block.
	 */
	s = spl8();

	if ((hdl = cmi_hdl_lookup(CMI_HDL_NATIVE, cmi_ntv_hwchipid(CPU),
	    cmi_ntv_hwcoreid(CPU), cmi_ntv_hwstrandid(CPU))) == NULL ||
	    (cmi = HDL2CMI(hdl)) == NULL ||
	    !CMI_OP_PRESENT(cmi, cmi_mca_trap)) {

		cmn_err(CE_WARN, "#MC exception on cpuid %d: %s",
		    CPU->cpu_id,
		    hdl ? "handle lookup ok but no #MC handler found" :
		    "handle lookup failed");

		if (hdl != NULL)
			cmi_hdl_rele(hdl);

		splx(s);
		return;
	}

	disp = CMI_OPS(cmi)->cmi_mca_trap(hdl, rp);

	switch (cmi_mce_response(rp, disp)) {
	default:
		cmn_err(CE_WARN, "Invalid response from cmi_mce_response");
		/*FALLTHRU*/

	case CMI_RESPONSE_PANIC:
		cmi_mca_panic();
		break;

	case CMI_RESPONSE_NONE:
		break;

	case CMI_RESPONSE_CKILL:
		ttolwp(curthread)->lwp_pcb.pcb_flags |= ASYNC_HWERR;
		aston(curthread);
		cma_mca_trap_contract_kills++;
		break;

	case CMI_RESPONSE_ONTRAP_PROT: {
		on_trap_data_t *otp = curthread->t_ontrap;
		otp->ot_trap = OT_DATA_EC;
		rp->r_pc = otp->ot_trampoline;
		cma_mca_trap_ontrap_forgiven++;
		break;
	}

	case CMI_RESPONSE_LOFAULT_PROT:
		rp->r_r0 = EFAULT;
		rp->r_pc = curthread->t_lofault;
		cma_mca_trap_lofault_forgiven++;
		break;
	}

	cmi_hdl_rele(hdl);
	splx(s);
#endif	/* __xpv */
}

void
cmi_hdl_poke(cmi_hdl_t hdl)
{
	cmi_t *cmi = HDL2CMI(hdl);

	if (!CMI_OP_PRESENT(cmi, cmi_hdl_poke))
		return;

	CMI_OPS(cmi)->cmi_hdl_poke(hdl);
}

#ifndef	__xpv
void
cmi_cmci_trap()
{
	cmi_hdl_t hdl = NULL;
	cmi_t *cmi;

	if (cmi_no_mca_init != 0)
		return;

	if ((hdl = cmi_hdl_lookup(CMI_HDL_NATIVE, cmi_ntv_hwchipid(CPU),
	    cmi_ntv_hwcoreid(CPU), cmi_ntv_hwstrandid(CPU))) == NULL ||
	    (cmi = HDL2CMI(hdl)) == NULL ||
	    !CMI_OP_PRESENT(cmi, cmi_cmci_trap)) {

		cmn_err(CE_WARN, "CMCI interrupt on cpuid %d: %s",
		    CPU->cpu_id,
		    hdl ? "handle lookup ok but no CMCI handler found" :
		    "handle lookup failed");

		if (hdl != NULL)
			cmi_hdl_rele(hdl);

		return;
	}

	CMI_OPS(cmi)->cmi_cmci_trap(hdl);

	cmi_hdl_rele(hdl);
}
#endif	/* __xpv */

void
cmi_mc_register(cmi_hdl_t hdl, const cmi_mc_ops_t *mcops, void *mcdata)
{
	if (!cmi_no_mca_init)
		cmi_hdl_setmc(hdl, mcops, mcdata);
}

cmi_errno_t
cmi_mc_register_global(const cmi_mc_ops_t *mcops, void *mcdata)
{
	if (!cmi_no_mca_init) {
		if (cmi_mc_global_ops != NULL || cmi_mc_global_data != NULL ||
		    mcops == NULL || mcops->cmi_mc_patounum == NULL ||
		    mcops->cmi_mc_unumtopa == NULL) {
			return (CMIERR_UNKNOWN);
		}
		cmi_mc_global_data = mcdata;
		cmi_mc_global_ops = mcops;
	}
	return (CMI_SUCCESS);
}

void
cmi_mc_sw_memscrub_disable(void)
{
	memscrub_disable();
}

cmi_errno_t
cmi_mc_patounum(uint64_t pa, uint8_t valid_hi, uint8_t valid_lo, uint32_t synd,
    int syndtype, mc_unum_t *up)
{
	const struct cmi_mc_ops *mcops;
	cmi_hdl_t hdl;
	cmi_errno_t rv;

	if (cmi_no_mca_init)
		return (CMIERR_MC_ABSENT);

	if (cmi_mc_global_ops != NULL) {
		if (cmi_mc_global_ops->cmi_mc_patounum == NULL)
			return (CMIERR_MC_NOTSUP);
		return (cmi_mc_global_ops->cmi_mc_patounum(cmi_mc_global_data,
		    pa, valid_hi, valid_lo, synd, syndtype, up));
	}

	if ((hdl = cmi_hdl_any()) == NULL)	/* short-term hold */
		return (CMIERR_MC_ABSENT);

	if ((mcops = cmi_hdl_getmcops(hdl)) == NULL ||
	    mcops->cmi_mc_patounum == NULL) {
		cmi_hdl_rele(hdl);
		return (CMIERR_MC_NOTSUP);
	}

	rv = mcops->cmi_mc_patounum(cmi_hdl_getmcdata(hdl), pa, valid_hi,
	    valid_lo, synd, syndtype, up);

	cmi_hdl_rele(hdl);

	return (rv);
}

cmi_errno_t
cmi_mc_unumtopa(mc_unum_t *up, nvlist_t *nvl, uint64_t *pap)
{
	const struct cmi_mc_ops *mcops;
	cmi_hdl_t hdl;
	cmi_errno_t rv;
	nvlist_t *hcsp;

	if (up != NULL && nvl != NULL)
		return (CMIERR_API);	/* convert from just one form */

	if (cmi_no_mca_init)
		return (CMIERR_MC_ABSENT);

	if (cmi_mc_global_ops != NULL) {
		if (cmi_mc_global_ops->cmi_mc_unumtopa == NULL)
			return (CMIERR_MC_NOTSUP);
		return (cmi_mc_global_ops->cmi_mc_unumtopa(cmi_mc_global_data,
		    up, nvl, pap));
	}

	if ((hdl = cmi_hdl_any()) == NULL)	/* short-term hold */
		return (CMIERR_MC_ABSENT);

	if ((mcops = cmi_hdl_getmcops(hdl)) == NULL ||
	    mcops->cmi_mc_unumtopa == NULL) {
		cmi_hdl_rele(hdl);

		if (nvl != NULL && nvlist_lookup_nvlist(nvl,
		    FM_FMRI_HC_SPECIFIC, &hcsp) == 0 &&
		    (nvlist_lookup_uint64(hcsp,
		    "asru-" FM_FMRI_HC_SPECIFIC_PHYSADDR, pap) == 0 ||
		    nvlist_lookup_uint64(hcsp, FM_FMRI_HC_SPECIFIC_PHYSADDR,
		    pap) == 0)) {
			return (CMIERR_MC_PARTIALUNUMTOPA);
		} else {
			return (mcops && mcops->cmi_mc_unumtopa == NULL ?
			    CMIERR_MC_NOTSUP : CMIERR_MC_ABSENT);
		}
	}

	rv = mcops->cmi_mc_unumtopa(cmi_hdl_getmcdata(hdl), up, nvl, pap);

	cmi_hdl_rele(hdl);

	return (rv);
}

void
cmi_mc_logout(cmi_hdl_t hdl, boolean_t ismc, boolean_t sync)
{
	const struct cmi_mc_ops *mcops;

	if (cmi_no_mca_init)
		return;

	if (cmi_mc_global_ops != NULL)
		mcops = cmi_mc_global_ops;
	else
		mcops = cmi_hdl_getmcops(hdl);

	if (mcops != NULL && mcops->cmi_mc_logout != NULL)
		mcops->cmi_mc_logout(hdl, ismc, sync);
}

cmi_errno_t
cmi_hdl_msrinject(cmi_hdl_t hdl, cmi_mca_regs_t *regs, uint_t nregs,
    int force)
{
	cmi_t *cmi = cmi_hdl_getcmi(hdl);
	cmi_errno_t rc;

	if (!CMI_OP_PRESENT(cmi, cmi_msrinject))
		return (CMIERR_NOTSUP);

	cmi_hdl_inj_begin(hdl);
	rc = CMI_OPS(cmi)->cmi_msrinject(hdl, regs, nregs, force);
	cmi_hdl_inj_end(hdl);

	return (rc);
}

boolean_t
cmi_panic_on_ue(void)
{
	return (cmi_panic_on_uncorrectable_error ? B_TRUE : B_FALSE);
}

void
cmi_panic_callback(void)
{
	cmi_hdl_t hdl;
	cmi_t *cmi;

	if (cmi_no_mca_init || (hdl = cmi_hdl_any()) == NULL)
		return;

	cmi = cmi_hdl_getcmi(hdl);
	if (CMI_OP_PRESENT(cmi, cmi_panic_callback))
		CMI_OPS(cmi)->cmi_panic_callback();

	cmi_hdl_rele(hdl);
}
