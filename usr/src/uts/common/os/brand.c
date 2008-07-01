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

#include <sys/kmem.h>
#include <sys/errno.h>
#include <sys/systm.h>
#include <sys/cmn_err.h>
#include <sys/brand.h>
#include <sys/machbrand.h>
#include <sys/modctl.h>
#include <sys/rwlock.h>
#include <sys/zone.h>

#define	SUPPORTED_BRAND_VERSION BRAND_VER_1

#if defined(__sparcv9)
/* sparcv9 uses system wide brand interposition hooks */
static void brand_plat_interposition_enable(void);
static void brand_plat_interposition_disable(void);

struct brand_mach_ops native_mach_ops  = {
		NULL, NULL
};
#else /* !__sparcv9 */
struct brand_mach_ops native_mach_ops  = {
		NULL, NULL, NULL, NULL, NULL, NULL
};
#endif /* !__sparcv9 */

brand_t native_brand = {
		BRAND_VER_1,
		"native",
		NULL,
		&native_mach_ops
};

/*
 * Used to maintain a list of all the brands currently loaded into the
 * kernel.
 */
struct brand_list {
	int			bl_refcnt;
	struct brand_list	*bl_next;
	brand_t			*bl_brand;
};

static struct brand_list *brand_list = NULL;

/*
 * This lock protects the integrity of the brand list.
 */
static kmutex_t brand_list_lock;

void
brand_init()
{
	mutex_init(&brand_list_lock, NULL, MUTEX_DEFAULT, NULL);
	p0.p_brand = &native_brand;
}

int
brand_register(brand_t *brand)
{
	struct brand_list *list, *scan;

	if (brand == NULL)
		return (EINVAL);

	if (is_system_labeled()) {
		cmn_err(CE_WARN,
		    "Branded zones are not allowed on labeled systems.");
		return (EINVAL);
	}

	if (brand->b_version != SUPPORTED_BRAND_VERSION) {
		if (brand->b_version < SUPPORTED_BRAND_VERSION) {
			cmn_err(CE_WARN,
			    "brand '%s' was built to run on older versions "
			    "of Solaris.",
			    brand->b_name);
		} else {
			cmn_err(CE_WARN,
			    "brand '%s' was built to run on a newer version "
			    "of Solaris.",
			    brand->b_name);
		}
		return (EINVAL);
	}

	/* Sanity checks */
	if (brand->b_name == NULL || brand->b_ops == NULL ||
	    brand->b_ops->b_brandsys == NULL) {
		cmn_err(CE_WARN, "Malformed brand");
		return (EINVAL);
	}

	list = kmem_alloc(sizeof (struct brand_list), KM_SLEEP);

	/* Add the brand to the list of loaded brands. */
	mutex_enter(&brand_list_lock);

	/*
	 * Check to be sure we haven't already registered this brand.
	 */
	for (scan = brand_list; scan != NULL; scan = scan->bl_next) {
		if (strcmp(brand->b_name, scan->bl_brand->b_name) == 0) {
			cmn_err(CE_WARN,
			    "Invalid attempt to load a second instance of "
			    "brand %s", brand->b_name);
			mutex_exit(&brand_list_lock);
			kmem_free(list, sizeof (struct brand_list));
			return (EINVAL);
		}
	}

#if defined(__sparcv9)
	/* sparcv9 uses system wide brand interposition hooks */
	if (brand_list == NULL)
		brand_plat_interposition_enable();
#endif /* __sparcv9 */

	list->bl_brand = brand;
	list->bl_refcnt = 0;
	list->bl_next = brand_list;
	brand_list = list;

	mutex_exit(&brand_list_lock);

	return (0);
}

/*
 * The kernel module implementing this brand is being unloaded, so remove
 * it from the list of active brands.
 */
int
brand_unregister(brand_t *brand)
{
	struct brand_list *list, *prev;

	/* Sanity checks */
	if (brand == NULL || brand->b_name == NULL) {
		cmn_err(CE_WARN, "Malformed brand");
		return (EINVAL);
	}

	prev = NULL;
	mutex_enter(&brand_list_lock);

	for (list = brand_list; list != NULL; list = list->bl_next) {
		if (list->bl_brand == brand)
			break;
		prev = list;
	}

	if (list == NULL) {
		cmn_err(CE_WARN, "Brand %s wasn't registered", brand->b_name);
		mutex_exit(&brand_list_lock);
		return (EINVAL);
	}

	if (list->bl_refcnt > 0) {
		cmn_err(CE_WARN, "Unregistering brand %s which is still in use",
		    brand->b_name);
		mutex_exit(&brand_list_lock);
		return (EBUSY);
	}

	/* Remove brand from the list */
	if (prev != NULL)
		prev->bl_next = list->bl_next;
	else
		brand_list = list->bl_next;

#if defined(__sparcv9)
	/* sparcv9 uses system wide brand interposition hooks */
	if (brand_list == NULL)
		brand_plat_interposition_disable();
#endif /* __sparcv9 */

	mutex_exit(&brand_list_lock);

	kmem_free(list, sizeof (struct brand_list));

	return (0);
}

/*
 * Record that a zone of this brand has been instantiated.  If the kernel
 * module implementing this brand's functionality is not present, this
 * routine attempts to load the module as a side effect.
 */
brand_t *
brand_register_zone(struct brand_attr *attr)
{
	struct brand_list *l = NULL;
	ddi_modhandle_t	hdl = NULL;
	char *modname;
	int err = 0;

	if (is_system_labeled()) {
		cmn_err(CE_WARN,
		    "Branded zones are not allowed on labeled systems.");
		return (NULL);
	}

	/*
	 * We make at most two passes through this loop.  The first time
	 * through, we're looking to see if this is a new user of an
	 * already loaded brand.  If the brand hasn't been loaded, we
	 * call ddi_modopen() to force it to be loaded and then make a
	 * second pass through the list of brands.  If we don't find the
	 * brand the second time through it means that the modname
	 * specified in the brand_attr structure doesn't provide the brand
	 * specified in the brandname field.  This would suggest a bug in
	 * the brand's config.xml file.  We close the module and return
	 * 'NULL' to the caller.
	 */
	for (;;) {
		/*
		 * Search list of loaded brands
		 */
		mutex_enter(&brand_list_lock);
		for (l = brand_list; l != NULL; l = l->bl_next)
			if (strcmp(attr->ba_brandname,
			    l->bl_brand->b_name) == 0)
				break;
		if ((l != NULL) || (hdl != NULL))
			break;
		mutex_exit(&brand_list_lock);

		/*
		 * We didn't find that the requested brand has been loaded
		 * yet, so we trigger the load of the appropriate kernel
		 * module and search the list again.
		 */
		modname = kmem_alloc(MAXPATHLEN, KM_SLEEP);
		(void) strcpy(modname, "brand/");
		(void) strcat(modname, attr->ba_modname);
		hdl = ddi_modopen(modname, KRTLD_MODE_FIRST, &err);
		kmem_free(modname, MAXPATHLEN);

		if (err != 0)
			return (NULL);
	}

	/*
	 * If we found the matching brand, bump its reference count.
	 */
	if (l != NULL)
		l->bl_refcnt++;

	mutex_exit(&brand_list_lock);

	if (hdl != NULL)
		(void) ddi_modclose(hdl);

	return ((l != NULL) ? l->bl_brand : NULL);
}

/*
 * Return the number of zones currently using this brand.
 */
int
brand_zone_count(struct brand *bp)
{
	struct brand_list *l;
	int cnt = 0;

	mutex_enter(&brand_list_lock);
	for (l = brand_list; l != NULL; l = l->bl_next)
		if (l->bl_brand == bp) {
			cnt = l->bl_refcnt;
			break;
		}
	mutex_exit(&brand_list_lock);

	return (cnt);
}

void
brand_unregister_zone(struct brand *bp)
{
	struct brand_list *list;

	mutex_enter(&brand_list_lock);
	for (list = brand_list; list != NULL; list = list->bl_next) {
		if (list->bl_brand == bp) {
			ASSERT(list->bl_refcnt > 0);
			list->bl_refcnt--;
			break;
		}
	}
	mutex_exit(&brand_list_lock);
}

void
brand_setbrand(proc_t *p)
{
	brand_t *bp = p->p_zone->zone_brand;

	ASSERT(bp != NULL);
	ASSERT(p->p_brand == &native_brand);

	/*
	 * We should only be called from exec(), when we know the process
	 * is single-threaded.
	 */
	ASSERT(p->p_tlist == p->p_tlist->t_forw);

	p->p_brand = bp;
	ASSERT(PROC_IS_BRANDED(p));
	BROP(p)->b_setbrand(p);
}

void
brand_clearbrand(proc_t *p)
{
	brand_t *bp = p->p_zone->zone_brand;
	ASSERT(bp != NULL);

	/*
	 * We should only be called from exec_common() or proc_exit(),
	 * when we know the process is single-threaded.
	 */
	ASSERT(p->p_tlist == p->p_tlist->t_forw);

	ASSERT(PROC_IS_BRANDED(p));
	BROP(p)->b_proc_exit(p, p->p_tlist->t_lwp);
	p->p_brand = &native_brand;
}

#if defined(__sparcv9)
/*
 * Currently, only sparc has system level brand syscall interposition.
 * On x86 we're able to enable syscall interposition on a per-cpu basis
 * when a branded thread is scheduled to run on a cpu.
 */

/* Local variables needed for dynamic syscall interposition support */
static uint32_t	syscall_trap_patch_instr_orig;
static uint32_t	syscall_trap32_patch_instr_orig;

/* Trap Table syscall entry hot patch points */
extern void	syscall_trap_patch_point(void);
extern void	syscall_trap32_patch_point(void);

/* Alternate syscall entry handlers used when branded zones are running */
extern void	syscall_wrapper(void);
extern void	syscall_wrapper32(void);

/* Macros used to facilitate sparcv9 instruction generation */
#define	BA_A_INSTR	0x30800000	/* ba,a addr */
#define	DISP22(from, to) \
	((((uintptr_t)(to) - (uintptr_t)(from)) >> 2) & 0x3fffff)

/*ARGSUSED*/
static void
brand_plat_interposition_enable(void)
{
	ASSERT(MUTEX_HELD(&brand_list_lock));

	/*
	 * Before we hot patch the kernel save the current instructions
	 * so that we can restore them later.
	 */
	syscall_trap_patch_instr_orig =
	    *(uint32_t *)syscall_trap_patch_point;
	syscall_trap32_patch_instr_orig =
	    *(uint32_t *)syscall_trap32_patch_point;

	/*
	 * Modify the trap table at the patch points.
	 *
	 * We basically replace the first instruction at the patch
	 * point with a ba,a instruction that will transfer control
	 * to syscall_wrapper or syscall_wrapper32 for 64-bit and
	 * 32-bit syscalls respectively.  It's important to note that
	 * the annul bit is set in the branch so we don't execute
	 * the instruction directly following the one we're patching
	 * during the branch's delay slot.
	 *
	 * It also doesn't matter that we're not atomically updating both
	 * the 64 and 32 bit syscall paths at the same time since there's
	 * no actual branded processes running on the system yet.
	 */
	hot_patch_kernel_text((caddr_t)syscall_trap_patch_point,
	    BA_A_INSTR | DISP22(syscall_trap_patch_point, syscall_wrapper),
	    4);
	hot_patch_kernel_text((caddr_t)syscall_trap32_patch_point,
	    BA_A_INSTR | DISP22(syscall_trap32_patch_point, syscall_wrapper32),
	    4);
}

/*ARGSUSED*/
static void
brand_plat_interposition_disable(void)
{
	ASSERT(MUTEX_HELD(&brand_list_lock));

	/*
	 * Restore the original instructions at the trap table syscall
	 * patch points to disable the brand syscall interposition
	 * mechanism.
	 */
	hot_patch_kernel_text((caddr_t)syscall_trap_patch_point,
	    syscall_trap_patch_instr_orig, 4);
	hot_patch_kernel_text((caddr_t)syscall_trap32_patch_point,
	    syscall_trap32_patch_instr_orig, 4);
}
#endif /* __sparcv9 */
