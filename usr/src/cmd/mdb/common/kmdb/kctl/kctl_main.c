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

#include <kmdb/kctl/kctl.h>
#include <kmdb/kctl/kctl_wr.h>
#include <kmdb/kmdb_kctl.h>
#include <kmdb/kmdb_kdi.h>
#include <kmdb/kmdb_auxv.h>
#include <mdb/mdb_errno.h>

#include <sys/sysmacros.h>
#include <sys/reboot.h>
#include <sys/atomic.h>
#include <sys/bootconf.h>
#include <sys/kmdb.h>
#include <sys/kobj.h>
#include <sys/kobj_impl.h>
#include <sys/promimpl.h>
#include <sys/kdi_impl.h>
#include <sys/ctf_api.h>
#include <vm/seg_kmem.h>
#include <vm/hat.h>

kctl_t kctl;

#define	KCTL_EXECNAME		"/kernel/drv/kmdb"

#if defined(_LP64)
#define	KCTL_MEM_GOALSZ		(20 * 1024 * 1024)
#else
#define	KCTL_MEM_GOALSZ		(10 * 1024 * 1024)
#endif

/*
 * kmdb will call its own copies of the promif routines during
 * initialization.  As these routines are intended to be used when the
 * world is stopped, they don't attempt to grab the PROM lock.  Very
 * Bad Things could happen if kmdb called a prom routine while someone
 * else was calling the kernel's copy of another prom routine, so we
 * grab the PROM lock ourselves before we start initialization.
 */
#ifdef __sparc
#define	KCTL_PROM_LOCK		promif_preprom()
#define	KCTL_PROM_UNLOCK	promif_postprom()
#else
#define	KCTL_PROM_LOCK
#define	KCTL_PROM_UNLOCK
#endif

static int
kctl_init(void)
{
	if (kobj_kdi.kdi_version != KDI_VERSION) {
		kctl_warn("kmdb/kernel version mismatch (expected %d, "
		    "found %d)", KDI_VERSION, kobj_kdi.kdi_version);
		return (-1);
	}

	sema_init(&kctl.kctl_wr_avail_sem, 0, NULL, SEMA_DRIVER, NULL);
	mutex_init(&kctl.kctl_wr_lock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&kctl.kctl_wr_cv, NULL, CV_DRIVER, NULL);
	mutex_init(&kctl.kctl_lock, NULL, MUTEX_DRIVER, NULL);

	kctl.kctl_execname = KCTL_EXECNAME; /* XXX get from modctl? */

	kctl.kctl_state = KCTL_ST_INACTIVE;

	kctl.kctl_dseg = kctl.kctl_mrbase = NULL;
	kctl.kctl_dseg_size = kctl.kctl_mrsize = 0;

	kctl_dmod_init();

	return (0);
}

static void
kctl_fini(void)
{
	kctl_dmod_fini();

	mutex_destroy(&kctl.kctl_lock);
	cv_destroy(&kctl.kctl_wr_cv);
	mutex_destroy(&kctl.kctl_wr_lock);
	sema_destroy(&kctl.kctl_wr_avail_sem);
}

static uint_t
kctl_set_state(uint_t state)
{
	uint_t ostate = kctl.kctl_state;

	/* forward progess only, please */
	if (state > ostate) {
		kctl_dprintf("new kctl state: %d", state);
		kctl.kctl_state = state;
	}

	return (ostate);
}

static int
kctl_boot_dseg_alloc(caddr_t dsegaddr, size_t dsegsz)
{
	/*
	 * The Intel boot memory allocator will cleverly map us onto a 4M
	 * page if we request the whole 4M Intel segment at once.  This
	 * will break physical memory r/w, so we break the request into
	 * chunks.  The allocator isn't smart enough to combine requests,
	 * so it'll give us a bunch of 4k pages.
	 */
	while (dsegsz >= 1024*1024) {
		size_t sz = MIN(dsegsz, 1024*1024);

		if (BOP_ALLOC(kctl.kctl_boot_ops, dsegaddr, sz, BO_NO_ALIGN) !=
		    dsegaddr)
			return (-1);

		dsegaddr += sz;
		dsegsz -= sz;
	}

	return (0);
}

static int
kctl_dseg_alloc(caddr_t addr, size_t sz)
{
	ASSERT(((uintptr_t)addr & PAGEOFFSET) == 0);

	/* make sure there isn't something there already (like kadb) */
	if (hat_getpfnum(kas.a_hat, addr) != PFN_INVALID)
		return (EAGAIN);

	/* Set HAT_ATTR_TEXT to override soft execute mode */
	if (segkmem_xalloc(NULL, addr, sz, VM_NOSLEEP, HAT_ATTR_TEXT,
	    segkmem_page_create, NULL) == NULL)
		return (ENOMEM);

	return (0);
}

static void
kctl_dseg_free(caddr_t addr, size_t sz)
{
	ASSERT(((uintptr_t)addr & PAGEOFFSET) == 0);

	segkmem_free(NULL, addr, sz);
}

static void
kctl_memavail(void)
{
	size_t needed;
	caddr_t base;

	/*
	 * We're now free to allocate the non-fixed portion of the debugger's
	 * memory region.
	 */

	needed = P2ROUNDUP(kctl.kctl_memgoalsz <= kctl.kctl_dseg_size ? 0 :
	    kctl.kctl_memgoalsz - kctl.kctl_dseg_size, PAGESIZE);

	if (needed == 0)
		return;

	if ((base = kmem_zalloc(needed, KM_NOSLEEP)) == NULL) {
		/*
		 * If we're going to wedge the machine during debugger startup,
		 * at least let them know why it's going to wedge.
		 */
		cmn_err(CE_WARN, "retrying of kmdb allocation of 0x%lx bytes",
		    (ulong_t)needed);

		base = kmem_zalloc(needed, KM_SLEEP);
	}

	kdi_dvec->dv_memavail(base, needed);
	kctl.kctl_mrbase = base;
	kctl.kctl_mrsize = needed;
}

void
kctl_cleanup(void)
{
	uint_t state = kctl_set_state(KCTL_ST_DEACTIVATING);

	kctl_dprintf("cleaning up from state %d", state);

	ASSERT(kctl.kctl_boot_loaded == 0);

	switch (state) {
	case KCTL_ST_ACTIVE:
		boothowto &= ~RB_DEBUG;
		/* XXX there's a race here */
		kdi_dvec = NULL;
		/*FALLTHROUGH*/

	case KCTL_ST_DBG_ACTIVATED:
		KCTL_PROM_LOCK;
		kmdb_deactivate();
		KCTL_PROM_UNLOCK;
		/*FALLTHROUGH*/

	case KCTL_ST_THREAD_STARTED:
		if (curthread != kctl.kctl_wr_thr) {
			kctl_wr_thr_stop();
			kctl_wr_thr_join();
		}
		/*FALLTHROUGH*/

	case KCTL_ST_MOD_NOTIFIERS:
		kctl_mod_notify_unreg();
		/*FALLTHROUGH*/

	case KCTL_ST_KCTL_PREACTIVATED:
		kctl_depreactivate_isadep();
		/*FALLTHROUGH*/

	case KCTL_ST_INITIALIZED:
		/* There's no kmdb_fini */
	case KCTL_ST_DSEG_ALLOCED:
		kctl_dseg_free(kctl.kctl_dseg, kctl.kctl_dseg_size);

		if (kctl.kctl_mrbase != NULL)
			kmem_free(kctl.kctl_mrbase, kctl.kctl_mrsize);
		/*FALLTHROUGH*/
	}

	kctl.kctl_state = KCTL_ST_INACTIVE;
}

static void
kctl_startup_modules(void)
{
	struct modctl *modp;

	/*
	 * Normal module load and unload is now available.  Prior to this point,
	 * we could only load modules, and that only when the debugger was being
	 * initialized.
	 *
	 * We'll need to prepare the modules we've already loaded (if any) for
	 * the brave new world in which boot is unmapped.
	 */
	kctl_dmod_sync();

	/*
	 * Process any outstanding loads or unloads and prepare for automatic
	 * module loading and unloading.
	 */
	(void) kctl_wr_process();

	kctl_mod_notify_reg();

	(void) kctl_set_state(KCTL_ST_MOD_NOTIFIERS);

	modp = &modules;
	do {
		kctl_mod_loaded(modp);
	} while ((modp = modp->mod_next) != &modules);
}

static void
kctl_startup_thread(void)
{
	/*
	 * Create the worker thread, which will handle future requests from the
	 * debugger.
	 */
	kctl_wr_thr_start();

	(void) kctl_set_state(KCTL_ST_THREAD_STARTED);
}

static int
kctl_startup_boot(void)
{
	struct modctl_list *lp, **lpp;
	int rc;

	if (kctl_wr_process() < 0) {
		kctl_warn("kmdb: failed to load modules");
		return (-1);
	}

	mutex_enter(&mod_lock);

	for (lpp = kobj_linkmaps; *lpp != NULL; lpp++) {
		for (lp = *lpp; lp != NULL; lp = lp->modl_next) {
			if ((rc = kctl_mod_decompress(lp->modl_modp)) != 0) {
				kctl_warn("kmdb: failed to decompress CTF data "
				    "for %s: %s", lp->modl_modp->mod_modname,
				    ctf_errmsg(rc));
			}
		}
	}

	mutex_exit(&mod_lock);

	return (0);
}

static int
kctl_startup_preactivate(void *romp, const char *cfg, const char **argv)
{
	kmdb_auxv_t kav;
	int rc;

	kctl_auxv_init(&kav, cfg, argv, romp);
	KCTL_PROM_LOCK;
	rc = kmdb_init(kctl.kctl_execname, &kav);
	KCTL_PROM_UNLOCK;
	kctl_auxv_fini(&kav);

	if (rc < 0)
		return (EMDB_KNOLOAD);

	(void) kctl_set_state(KCTL_ST_INITIALIZED);

	if (kctl_preactivate_isadep() != 0)
		return (EIO);

	(void) kctl_set_state(KCTL_ST_KCTL_PREACTIVATED);

	return (0);
}

static int
kctl_startup_activate(uint_t flags)
{
	kdi_debugvec_t *dvec;

	KCTL_PROM_LOCK;
	kmdb_activate(&dvec, flags);
	KCTL_PROM_UNLOCK;

	(void) kctl_set_state(KCTL_ST_DBG_ACTIVATED);

	/*
	 * fill in a few remaining debugvec entries.
	 */
	dvec->dv_kctl_modavail = kctl_startup_modules;
	dvec->dv_kctl_thravail = kctl_startup_thread;
	dvec->dv_kctl_memavail = kctl_memavail;

	kctl_activate_isadep(dvec);

	kdi_dvec = dvec;
	membar_producer();

	boothowto |= RB_DEBUG;

	(void) kctl_set_state(KCTL_ST_ACTIVE);

	return (0);
}

static int
kctl_state_check(uint_t state, uint_t ok_state)
{
	if (state == ok_state)
		return (0);

	if (state == KCTL_ST_INACTIVE)
		return (EMDB_KINACTIVE);
	else if (kctl.kctl_state > KCTL_ST_INACTIVE &&
	    kctl.kctl_state < KCTL_ST_ACTIVE)
		return (EMDB_KACTIVATING);
	else if (kctl.kctl_state == KCTL_ST_ACTIVE)
		return (EMDB_KACTIVE);
	else if (kctl.kctl_state == KCTL_ST_DEACTIVATING)
		return (EMDB_KDEACTIVATING);
	else
		return (EINVAL);
}

int
kctl_deactivate(void)
{
	int rc;

	mutex_enter(&kctl.kctl_lock);

	if (kctl.kctl_boot_loaded) {
		rc = EMDB_KNOUNLOAD;
		goto deactivate_done;
	}

	if ((rc = kctl_state_check(kctl.kctl_state, KCTL_ST_ACTIVE)) != 0)
		goto deactivate_done;

	kmdb_kdi_set_unload_request();
	kmdb_kdi_kmdb_enter();

	/*
	 * The debugger will pass the request to the work thread, which will
	 * stop itself.
	 */
	kctl_wr_thr_join();

deactivate_done:
	mutex_exit(&kctl.kctl_lock);

	return (rc);
}

/*
 * Called from krtld, this indicates that the user loaded kmdb at boot.  We
 * track activation states, but we don't attempt to clean up if activation
 * fails, because boot debugger load failures are fatal.
 *
 * Further complicating matters, various kernel routines, such as bcopy and
 * mutex_enter, assume the presence of some basic state.  On SPARC, it's the
 * presence of a valid curthread pointer.  On AMD64, it's a valid curcpu
 * pointer in GSBASE.  We set up temporary versions of these before beginning
 * activation, and tear them down when we're done.
 */
int
kctl_boot_activate(struct bootops *ops, void *romp, size_t memsz,
    const char **argv)
{
	void *old;

#ifdef __lint
	{
	/*
	 * krtld does a name-based symbol lookup to find this routine.  It then
	 * casts the address it gets, calling the result.  We want to make sure
	 * that the call in krtld stays in sync with the prototype for this
	 * function, so we define a type (kctl_boot_activate_f) that matches the
	 * current prototype.  The following assignment ensures that the type
	 * still matches the declaration, with lint as the enforcer.
	 */
	kctl_boot_activate_f *kba = kctl_boot_activate;
	if (kba == NULL)	/* Make lint think kba is actually used */
		return (0);
	}
#endif

	old = kctl_boot_tmpinit();	/* Set up temporary state */

	ASSERT(ops != NULL);
	kctl.kctl_boot_ops = ops;	/* must be set before kctl_init */

	if (kctl_init() < 0)
		return (-1);

	kctl.kctl_boot_loaded = 1;

	kctl_dprintf("beginning kmdb initialization");

	if (memsz == 0)
		memsz = KCTL_MEM_GOALSZ;

	kctl.kctl_dseg = kdi_segdebugbase;
	kctl.kctl_dseg_size =
	    memsz > kdi_segdebugsize ? kdi_segdebugsize : memsz;
	kctl.kctl_memgoalsz = memsz;

	if (kctl_boot_dseg_alloc(kctl.kctl_dseg, kctl.kctl_dseg_size) < 0) {
		kctl_warn("kmdb: failed to allocate %lu-byte debugger area at "
		    "%p", kctl.kctl_dseg_size, (void *)kctl.kctl_dseg);
		return (-1);
	}

	(void) kctl_set_state(KCTL_ST_DSEG_ALLOCED);

	if (kctl_startup_preactivate(romp, NULL, argv) != 0 ||
	    kctl_startup_activate(KMDB_ACT_F_BOOT)) {
		kctl_warn("kmdb: failed to activate");
		return (-1);
	}

	if (kctl_startup_boot() < 0)
		return (-1);

	kctl_dprintf("finished with kmdb initialization");

	kctl_boot_tmpfini(old);

	kctl.kctl_boot_ops = NULL;

	return (0);
}

int
kctl_modload_activate(size_t memsz, const char *cfg, uint_t flags)
{
	int rc;

	mutex_enter(&kctl.kctl_lock);

	if ((rc = kctl_state_check(kctl.kctl_state, KCTL_ST_INACTIVE)) != 0) {
		if ((flags & KMDB_F_AUTO_ENTRY) && rc == EMDB_KACTIVE) {
			kmdb_kdi_kmdb_enter();
			rc = 0;
		}

		mutex_exit(&kctl.kctl_lock);
		return (rc);
	}

	kctl.kctl_flags = flags;

	if (memsz == 0)
		memsz = KCTL_MEM_GOALSZ;

	kctl.kctl_dseg = kdi_segdebugbase;
	kctl.kctl_dseg_size =
	    memsz > kdi_segdebugsize ? kdi_segdebugsize : memsz;
	kctl.kctl_memgoalsz = memsz;

	if ((rc = kctl_dseg_alloc(kctl.kctl_dseg, kctl.kctl_dseg_size)) != 0)
		goto activate_fail;

	(void) kctl_set_state(KCTL_ST_DSEG_ALLOCED);

	if ((rc = kctl_startup_preactivate(NULL, cfg, NULL)) != 0)
		goto activate_fail;

	kctl_startup_modules();
	kctl_startup_thread();

	if ((rc = kctl_startup_activate(0)) != 0)
		goto activate_fail;

	kctl_memavail();	/* Must be after kdi_dvec is set */

	if (kctl.kctl_flags & KMDB_F_AUTO_ENTRY)
		kmdb_kdi_kmdb_enter();

	mutex_exit(&kctl.kctl_lock);
	return (0);

activate_fail:
	kctl_cleanup();
	mutex_exit(&kctl.kctl_lock);
	return (rc);
}

/*
 * This interface will be called when drv/kmdb loads.  When we get the call, one
 * of two things will have happened:
 *
 *  1. The debugger was loaded at boot.  We've progressed far enough into boot
 *     as to allow drv/kmdb to be loaded as a non-primary.  Invocation of this
 *     interface is the signal to the debugger that it can start allowing things
 *     like dmod loading and automatic CTF decompression - things which require
 *     the system services that have now been started.
 *
 *  2. The debugger was loaded after boot.  mdb opened /dev/kmdb, causing
 *     drv/kmdb to load, followed by misc/kmdb.  Nothing has been set up yet,
 *     so we need to initialize.  Activation will occur separately, so we don't
 *     have to worry about that.
 */
int
kctl_attach(dev_info_t *dip)
{
	kctl.kctl_drv_dip = dip;

	return (0);
}

int
kctl_detach(void)
{
	return (kctl.kctl_state == KCTL_ST_INACTIVE ? 0 : EBUSY);
}

static struct modlmisc modlmisc = {
	&mod_miscops,
	KMDB_VERSION
};

static struct modlinkage modlinkage = {
	MODREV_1,
	(void *)&modlmisc,
	NULL
};

/*
 * Invoked only when debugger is loaded via modload - not invoked when debugger
 * is loaded at boot.  kctl_boot_activate needs to call anything (aside from
 * mod_install) this function does.
 */
int
_init(void)
{
	if (kctl_init() < 0)
		return (EINVAL);

	return (mod_install(&modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

int
_fini(void)
{
	kctl_fini();

	return (mod_remove(&modlinkage));
}
