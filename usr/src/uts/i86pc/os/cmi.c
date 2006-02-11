/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Public interface to routines implemented by CPU modules
 */

#include <sys/x86_archext.h>
#include <sys/cpu_module_impl.h>
#include <sys/fm/util.h>
#include <sys/reboot.h>
#include <sys/modctl.h>
#include <sys/param.h>
#include <sys/cmn_err.h>
#include <sys/systm.h>
#include <sys/types.h>

#define	CPUMOD_SUBDIR	"cpu"
#define	CPUMOD_PREFIX	"cpu"

#define	CMI_OPS(cpu) \
	(cpu)->cpu_m.mcpu_cmi->cmi_ops
#define	CMI_DATA(cpu) \
	(cpu)->cpu_m.mcpu_cmidata

/*
 * If cleared for debugging, we will suppress panicking on fatal hardware
 * errors.  This should *only* be used for debugging; it use can and will
 * cause data corruption if actual hardware errors are detected by the system.
 */
int cmi_panic_on_uncorrectable_error = 1;

static cmi_t *cmi_list;
static kmutex_t cmi_load_lock;

static int
cmi_cpu_match(cpu_t *c1, cpu_t *c2)
{
	return (cpuid_getfamily(c1) == cpuid_getfamily(c2) &&
	    cpuid_getmodel(c1) == cpuid_getmodel(c2) &&
	    cpuid_getstep(c1) == cpuid_getstep(c2) &&
	    strcmp(cpuid_getvendorstr(c1), cpuid_getvendorstr(c2)) == 0);
}

static cmi_t *
cmi_load_modctl(modctl_t *modp)
{
	uintptr_t ops;
	cmi_t *cmi;

	ASSERT(MUTEX_HELD(&cmi_load_lock));

	for (cmi = cmi_list; cmi != NULL; cmi = cmi->cmi_next) {
		if (cmi->cmi_modp == modp)
			return (cmi);
	}

	if ((ops = modlookup_by_modctl(modp, "_cmi_ops")) == NULL) {
		cmn_err(CE_WARN, "CPU module %s is invalid: no _cmi_ops "
		    "found\n", modp->mod_modname);
		return (NULL);
	}

	/*
	 * Hold the module in memory.  We call to CPU modules without using the
	 * stubs mechanism, so these modules must be manually held in memory.
	 * The mod_ref acts as if another loaded module has a dependency on us.
	 */
	mutex_enter(&mod_lock);
	modp->mod_ref++;
	mutex_exit(&mod_lock);

	cmi = kmem_zalloc(sizeof (cmi_t), KM_SLEEP);
	cmi->cmi_ops = (const cmi_ops_t *)ops;
	cmi->cmi_modp = modp;

	cmi->cmi_next = cmi_list;
	cmi_list = cmi;

	return (cmi);
}

static cmi_t *
cmi_load_module(cpu_t *cp)
{
	modctl_t *modp;
	cmi_t *cmi;
	int i, modid;
	uint_t s[3];

	/*
	 * Look to see if we've already got a module loaded for a CPU just
	 * like this one.  If we do, then we'll re-use it.
	 */
	ASSERT(MUTEX_HELD(&cmi_load_lock));
	mutex_enter(&cpu_lock);

	for (i = 0; i < NCPU; i++) {
		cpu_t *cp2 = cpu[i];

		if (cp2 != NULL && cp2 != cp &&
		    cp2->cpu_m.mcpu_cmi != NULL && cmi_cpu_match(cp, cp2)) {
			mutex_exit(&cpu_lock);
			return (cp2->cpu_m.mcpu_cmi);
		}
	}

	mutex_exit(&cpu_lock);

	/*
	 * If we can't find a match, attempt to load the appropriate module.
	 * If that also fails, try to load the generic CPU module.
	 */
	s[0] = cpuid_getfamily(cp);
	s[1] = cpuid_getmodel(cp);
	s[2] = cpuid_getstep(cp);

	modid = modload_qualified(CPUMOD_SUBDIR, CPUMOD_PREFIX,
	    cpuid_getvendorstr(cp), ".", s, sizeof (s) / sizeof (s[0]));

	if (modid == -1)
		modid = modload(CPUMOD_SUBDIR, CPUMOD_PREFIX ".generic");

	if (modid == -1)
		return (NULL);

	modp = mod_hold_by_id(modid);
	cmi = cmi_load_modctl(modp);
	mod_release_mod(modp);

	return (cmi);
}

static cmi_t *
cmi_load_generic(void)
{
	modctl_t *modp;
	cmi_t *cmi;
	int modid;

	if ((modid = modload(CPUMOD_SUBDIR, CPUMOD_PREFIX ".generic")) == -1)
		return (NULL);

	modp = mod_hold_by_id(modid);
	cmi = cmi_load_modctl(modp);
	mod_release_mod(modp);

	return (cmi);
}

/*
 * Load a CPU module for the specified CPU, and then call its cmi_init routine.
 * If the module returns ENOTSUP, try using the generic CPU module instead.
 * If all else fails, we return -1 and the caller will panic or halt.
 */
int
cmi_load(cpu_t *cp)
{
	int err = ENOENT;
	cmi_t *cmi;
	void *data;

	mutex_enter(&cmi_load_lock);

	if ((cmi = cmi_load_module(cp)) == NULL || (
	    (err = cmi->cmi_ops->cmi_init(cp, &data)) != 0 && err != ENOTSUP)) {
		cmn_err(CE_WARN, "CPU module %s failed to init CPU %d: err=%d",
		    cmi ? cmi->cmi_modp->mod_modname : "<>", cp->cpu_id, err);
		mutex_exit(&cmi_load_lock);
		return (-1);
	}

	if (err != 0 && ((cmi = cmi_load_generic()) == NULL ||
	    (err = cmi->cmi_ops->cmi_init(cp, &data)) != 0)) {
		cmn_err(CE_WARN, "CPU module %s failed to init CPU %d: err=%d",
		    cmi ? cmi->cmi_modp->mod_modname : "<>", cp->cpu_id, err);
		mutex_exit(&cmi_load_lock);
		return (-1);
	}

	ASSERT(cp->cpu_m.mcpu_cmi == NULL);
	cp->cpu_m.mcpu_cmi = cmi;
	cp->cpu_m.mcpu_cmidata = data;

	cmi->cmi_refcnt++;
	mutex_exit(&cmi_load_lock);

	if (boothowto & RB_VERBOSE) {
		printf("cpuid %d: initialized cpumod: %s\n",
		    cp->cpu_id, cmi->cmi_modp->mod_modname);
	}

	return (0);
}

void
cmi_init(void)
{
	if (cmi_load(CPU) < 0)
		panic("failed to load module for CPU %u", CPU->cpu_id);
}

void
cmi_post_init(void)
{
	CMI_OPS(CPU)->cmi_post_init(CMI_DATA(CPU));
}

void
cmi_faulted_enter(cpu_t *cp)
{
	CMI_OPS(cp)->cmi_faulted_enter(CMI_DATA(cp));
}

void
cmi_faulted_exit(cpu_t *cp)
{
	CMI_OPS(cp)->cmi_faulted_exit(CMI_DATA(cp));
}

int
cmi_scrubber_enable(cpu_t *cp, uint64_t base, uint64_t ilen)
{
	return (CMI_OPS(cp)->cmi_scrubber_enable(CMI_DATA(cp), base, ilen));
}

void
cmi_mca_init(void)
{
	CMI_OPS(CPU)->cmi_mca_init(CMI_DATA(CPU));
}

void
cmi_mca_trap(struct regs *rp)
{
	if (CMI_OPS(CPU)->cmi_mca_trap(CMI_DATA(CPU), rp)) {
		if (cmi_panic_on_uncorrectable_error)
			fm_panic("Unrecoverable Machine-Check Exception");
		else
			cmn_err(CE_WARN, "suppressing panic from fatal #mc");
	}
}

int
cmi_mca_inject(cmi_mca_regs_t *regs, uint_t nregs)
{
	int err;

	kpreempt_disable();
	err = CMI_OPS(CPU)->cmi_mca_inject(CMI_DATA(CPU), regs, nregs);
	kpreempt_enable();

	return (err);
}

void
cmi_mca_poke(void)
{
	CMI_OPS(CPU)->cmi_mca_poke(CMI_DATA(CPU));
}

void
cmi_mc_register(cpu_t *cp, const cmi_mc_ops_t *mcops, void *mcdata)
{
	CMI_OPS(cp)->cmi_mc_register(CMI_DATA(cp), mcops, mcdata);
}

int
cmi_mc_patounum(uint64_t pa, uint32_t synd, int syndtype, mc_unum_t *up)
{
	const struct cmi_mc_ops *mcops;
	cpu_t *cp = CPU;

	if (CMI_OPS(cp) == NULL ||
	    (mcops = CMI_OPS(cp)->cmi_mc_getops(CMI_DATA(cp))) == NULL)
		return (-1);	/* not registered yet */

	return (mcops->cmi_mc_patounum(CMI_DATA(cp), pa, synd, syndtype, up));
}

int
cmi_mc_unumtopa(mc_unum_t *up, nvlist_t *nvl, uint64_t *pap)
{
	const struct cmi_mc_ops *mcops;
	cpu_t *cp = CPU;

	if (up != NULL && nvl != NULL)
		return (-1);	/* only convert from one or the other form */

	if (CMI_OPS(cp) == NULL ||
	    (mcops = CMI_OPS(cp)->cmi_mc_getops(CMI_DATA(cp))) == NULL)
		return (-1);	/* not registered yet */

	return (mcops->cmi_mc_unumtopa(CMI_DATA(cp), up, nvl, pap));
}
