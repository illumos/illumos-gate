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
#define	PSMI_1_7

#include <sys/vmem.h>
#include <vm/hat.h>
#include <sys/modctl.h>
#include <vm/seg_kmem.h>
#include <sys/psm.h>
#include <sys/psm_modctl.h>
#include <sys/smp_impldefs.h>
#include <sys/reboot.h>
#if defined(__xpv)
#include <sys/hypervisor.h>
#include <vm/kboot_mmu.h>
#include <vm/hat_pte.h>
#endif

/*
 *	External reference functions
 */
extern void *get_next_mach(void *, char *);
extern void close_mach_list(void);
extern void open_mach_list(void);

/*
 * from startup.c - kernel VA range allocator for device mappings
 */
extern void *device_arena_alloc(size_t size, int vm_flag);
extern void device_arena_free(void * vaddr, size_t size);

void psm_modloadonly(void);
void psm_install(void);

/*
 * Local Function Prototypes
 */
static struct modlinkage *psm_modlinkage_alloc(struct psm_info *infop);
static void psm_modlinkage_free(struct modlinkage *mlinkp);

static char *psm_get_impl_module(int first);

static int mod_installpsm(struct modlpsm *modl, struct modlinkage *modlp);
static int mod_removepsm(struct modlpsm *modl, struct modlinkage *modlp);
static int mod_infopsm(struct modlpsm *modl, struct modlinkage *modlp, int *p0);
struct mod_ops mod_psmops = {
	mod_installpsm, mod_removepsm, mod_infopsm
};

static struct psm_sw psm_swtab = {
	&psm_swtab, &psm_swtab, NULL, NULL
};

kmutex_t psmsw_lock;			/* lock accesses to psmsw 	*/
struct psm_sw *psmsw = &psm_swtab; 	/* start of all psm_sw		*/

static struct modlinkage *
psm_modlinkage_alloc(struct psm_info *infop)
{
	int	memsz;
	struct modlinkage *mlinkp;
	struct modlpsm *mlpsmp;
	struct psm_sw *swp;

	memsz = sizeof (struct modlinkage) + sizeof (struct modlpsm) +
	    sizeof (struct psm_sw);
	mlinkp = (struct modlinkage *)kmem_zalloc(memsz, KM_NOSLEEP);
	if (!mlinkp) {
		cmn_err(CE_WARN, "!psm_mod_init: Cannot install %s",
		    infop->p_mach_idstring);
		return (NULL);
	}
	mlpsmp = (struct modlpsm *)(mlinkp + 1);
	swp = (struct psm_sw *)(mlpsmp + 1);

	mlinkp->ml_rev = MODREV_1;
	mlinkp->ml_linkage[0] = (void *)mlpsmp;
	mlinkp->ml_linkage[1] = (void *)NULL;

	mlpsmp->psm_modops = &mod_psmops;
	mlpsmp->psm_linkinfo = infop->p_mach_desc;
	mlpsmp->psm_swp = swp;

	swp->psw_infop = infop;

	return (mlinkp);
}

static void
psm_modlinkage_free(struct modlinkage *mlinkp)
{
	if (!mlinkp)
		return;

	(void) kmem_free(mlinkp, (sizeof (struct modlinkage) +
	    sizeof (struct modlpsm) + sizeof (struct psm_sw)));
}

int
psm_mod_init(void **handlepp, struct psm_info *infop)
{
	struct modlinkage **modlpp = (struct modlinkage **)handlepp;
	int	status;
	struct modlinkage *mlinkp;

	if (!*modlpp) {
		mlinkp = psm_modlinkage_alloc(infop);
		if (!mlinkp)
			return (ENOSPC);
	} else
		mlinkp = *modlpp;

	status = mod_install(mlinkp);
	if (status) {
		psm_modlinkage_free(mlinkp);
		*modlpp = NULL;
	} else
		*modlpp = mlinkp;

	return (status);
}

/*ARGSUSED1*/
int
psm_mod_fini(void **handlepp, struct psm_info *infop)
{
	struct modlinkage **modlpp = (struct modlinkage **)handlepp;
	int	status;

	status = mod_remove(*modlpp);
	if (status == 0) {
		psm_modlinkage_free(*modlpp);
		*modlpp = NULL;
	}
	return (status);
}

int
psm_mod_info(void **handlepp, struct psm_info *infop, struct modinfo *modinfop)
{
	struct modlinkage **modlpp = (struct modlinkage **)handlepp;
	int status;
	struct modlinkage *mlinkp;

	if (!*modlpp) {
		mlinkp = psm_modlinkage_alloc(infop);
		if (!mlinkp)
			return ((int)NULL);
	} else
		mlinkp = *modlpp;

	status =  mod_info(mlinkp, modinfop);

	if (!status) {
		psm_modlinkage_free(mlinkp);
		*modlpp = NULL;
	} else
		*modlpp = mlinkp;

	return (status);
}

int
psm_add_intr(int lvl, avfunc xxintr, char *name, int vect, caddr_t arg)
{
	return (add_avintr((void *)NULL, lvl, xxintr, name, vect,
	    arg, NULL, NULL, NULL));
}

int
psm_add_nmintr(int lvl, avfunc xxintr, char *name, caddr_t arg)
{
	return (add_nmintr(lvl, xxintr, name, arg));
}

processorid_t
psm_get_cpu_id(void)
{
	return (CPU->cpu_id);
}

caddr_t
psm_map_phys_new(paddr_t addr, size_t len, int prot)
{
	uint_t pgoffset;
	paddr_t base;
	pgcnt_t npages;
	caddr_t cvaddr;

	if (len == 0)
		return (0);

	pgoffset = addr & MMU_PAGEOFFSET;
#ifdef __xpv
	/*
	 * If we're dom0, we're starting from a MA. translate that to a PA
	 * XXPV - what about driver domains???
	 */
	if (DOMAIN_IS_INITDOMAIN(xen_info)) {
		base = pfn_to_pa(xen_assign_pfn(mmu_btop(addr))) |
		    (addr & MMU_PAGEOFFSET);
	} else {
		base = addr;
	}
#else
	base = addr;
#endif
	npages = mmu_btopr(len + pgoffset);
	cvaddr = device_arena_alloc(ptob(npages), VM_NOSLEEP);
	if (cvaddr == NULL)
		return (0);
	hat_devload(kas.a_hat, cvaddr, mmu_ptob(npages), mmu_btop(base),
	    prot, HAT_LOAD_LOCK);
	return (cvaddr + pgoffset);
}

void
psm_unmap_phys(caddr_t addr, size_t len)
{
	uint_t pgoffset;
	caddr_t base;
	pgcnt_t npages;

	if (len == 0)
		return;

	pgoffset = (uintptr_t)addr & MMU_PAGEOFFSET;
	base = addr - pgoffset;
	npages = mmu_btopr(len + pgoffset);
	hat_unload(kas.a_hat, base, ptob(npages), HAT_UNLOAD_UNLOCK);
	device_arena_free(base, ptob(npages));
}

caddr_t
psm_map_new(paddr_t addr, size_t len, int prot)
{
	int phys_prot = PROT_READ;

	ASSERT(prot == (prot & (PSM_PROT_WRITE | PSM_PROT_READ)));
	if (prot & PSM_PROT_WRITE)
		phys_prot |= PROT_WRITE;

	return (psm_map_phys(addr, len, phys_prot));
}

#undef psm_map_phys
#undef psm_map

caddr_t
psm_map_phys(uint32_t addr, size_t len, int prot)
{
	return (psm_map_phys_new((paddr_t)(addr & 0xffffffff), len, prot));
}

caddr_t
psm_map(uint32_t addr, size_t len, int prot)
{
	return (psm_map_new((paddr_t)(addr & 0xffffffff), len, prot));
}

void
psm_unmap(caddr_t addr, size_t len)
{
	uint_t pgoffset;
	caddr_t base;
	pgcnt_t npages;

	if (len == 0)
		return;

	pgoffset = (uintptr_t)addr & MMU_PAGEOFFSET;
	base = addr - pgoffset;
	npages = mmu_btopr(len + pgoffset);
	hat_unload(kas.a_hat, base, ptob(npages), HAT_UNLOAD_UNLOCK);
	device_arena_free(base, ptob(npages));
}

/*ARGSUSED1*/
static int
mod_installpsm(struct modlpsm *modl, struct modlinkage *modlp)
{
	struct psm_sw *swp;

	swp = modl->psm_swp;
	mutex_enter(&psmsw_lock);
	psmsw->psw_back->psw_forw = swp;
	swp->psw_back = psmsw->psw_back;
	swp->psw_forw = psmsw;
	psmsw->psw_back = swp;
	swp->psw_flag |= PSM_MOD_INSTALL;
	mutex_exit(&psmsw_lock);
	return (0);
}

/*ARGSUSED1*/
static int
mod_removepsm(struct modlpsm *modl, struct modlinkage *modlp)
{
	struct psm_sw *swp;

	swp = modl->psm_swp;
	mutex_enter(&psmsw_lock);
	if (swp->psw_flag & PSM_MOD_IDENTIFY) {
		mutex_exit(&psmsw_lock);
		return (EBUSY);
	}
	if (!(swp->psw_flag & PSM_MOD_INSTALL)) {
		mutex_exit(&psmsw_lock);
		return (0);
	}

	swp->psw_back->psw_forw = swp->psw_forw;
	swp->psw_forw->psw_back = swp->psw_back;
	mutex_exit(&psmsw_lock);
	return (0);
}

/*ARGSUSED1*/
static int
mod_infopsm(struct modlpsm *modl, struct modlinkage *modlp, int *p0)
{
	*p0 = (int)modl->psm_swp->psw_infop->p_owner;
	return (0);
}

#if defined(__xpv)
#define	DEFAULT_PSM_MODULE	"xpv_uppc"
#else
#define	DEFAULT_PSM_MODULE	"uppc"
#endif

static char *
psm_get_impl_module(int first)
{
	static char **pnamep;
	static char *psm_impl_module_list[] = {
		DEFAULT_PSM_MODULE,
		(char *)0
	};
	static void *mhdl = NULL;
	static char machname[MAXNAMELEN];

	if (first)
		pnamep = psm_impl_module_list;

	if (*pnamep != (char *)0)
		return (*pnamep++);

	mhdl = get_next_mach(mhdl, machname);
	if (mhdl)
		return (machname);
	return ((char *)0);
}

void
psm_modload(void)
{
	char *this;

	mutex_init(&psmsw_lock, NULL, MUTEX_DEFAULT, NULL);
	open_mach_list();

	for (this = psm_get_impl_module(1); this != (char *)NULL;
	    this = psm_get_impl_module(0)) {
		if (modload("mach", this) == -1)
			cmn_err(CE_CONT, "!Skipping psm: %s\n", this);
	}
	close_mach_list();
}

#if defined(__xpv)
#define	NOTSUP_MSG "This version of Solaris xVM does not support this hardware"
#else
#define	NOTSUP_MSG "This version of Solaris does not support this hardware"
#endif	/* __xpv */

void
psm_install(void)
{
	struct psm_sw *swp, *cswp;
	struct psm_ops *opsp;
	char machstring[15];
	int err, psmcnt = 0;

	mutex_enter(&psmsw_lock);
	for (swp = psmsw->psw_forw; swp != psmsw; ) {
		opsp = swp->psw_infop->p_ops;
		if (opsp->psm_probe) {
			if ((*opsp->psm_probe)() == PSM_SUCCESS) {
				psmcnt++;
				swp->psw_flag |= PSM_MOD_IDENTIFY;
				swp = swp->psw_forw;
				continue;
			}
		}
		/* remove the unsuccessful psm modules */
		cswp = swp;
		swp = swp->psw_forw;

		mutex_exit(&psmsw_lock);
		(void) strcpy(&machstring[0], cswp->psw_infop->p_mach_idstring);
		err = mod_remove_by_name(cswp->psw_infop->p_mach_idstring);
		if (err)
			cmn_err(CE_WARN, "!%s: mod_remove_by_name failed %d",
			    &machstring[0], err);
		mutex_enter(&psmsw_lock);
	}
	mutex_exit(&psmsw_lock);
	if (psmcnt == 0)
		halt(NOTSUP_MSG);
	(*psminitf)();
}

/*
 * Return 1 if kernel debugger is present, and 0 if not.
 */
int
psm_debugger(void)
{
	return ((boothowto & RB_DEBUG) != 0);
}
