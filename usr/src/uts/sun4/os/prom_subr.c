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
#include <sys/param.h>
#include <sys/cmn_err.h>
#include <sys/mutex.h>
#include <sys/systm.h>
#include <sys/sysmacros.h>
#include <sys/machsystm.h>
#include <sys/archsystm.h>
#include <sys/x_call.h>
#include <sys/promif.h>
#include <sys/prom_isa.h>
#include <sys/privregs.h>
#include <sys/vmem.h>
#include <sys/atomic.h>
#include <sys/panic.h>
#include <sys/rwlock.h>
#include <sys/reboot.h>
#include <sys/kdi.h>
#include <sys/kdi_machimpl.h>

/*
 * We are called with a pointer to a cell-sized argument array.
 * The service name (the first element of the argument array) is
 * the name of the callback being invoked.  When called, we are
 * running on the firmwares trap table as a trusted subroutine
 * of the firmware.
 *
 * We define entry points to allow callback handlers to be dynamically
 * added and removed, to support obpsym, which is a separate module
 * and can be dynamically loaded and unloaded and registers its
 * callback handlers dynamically.
 *
 * Note: The actual callback handler we register, is the assembly lang.
 * glue, callback_handler, which takes care of switching from a 64
 * bit stack and environment to a 32 bit stack and environment, and
 * back again, if the callback handler returns. callback_handler calls
 * vx_handler to process the callback.
 */

static kmutex_t vx_cmd_lock;	/* protect vx_cmd table */

#define	VX_CMD_MAX	10
#define	ENDADDR(a)	&a[sizeof (a) / sizeof (a[0])]
#define	vx_cmd_end	((struct vx_cmd *)(ENDADDR(vx_cmd)))

static struct vx_cmd {
	char	*service;	/* Service name */
	int	take_tba;	/* If Non-zero we take over the tba */
	void	(*func)(cell_t *argument_array);
} vx_cmd[VX_CMD_MAX+1];

void
init_vx_handler(void)
{
	extern int callback_handler(cell_t *arg_array);

	/*
	 * initialize the lock protecting additions and deletions from
	 * the vx_cmd table.  At callback time we don't need to grab
	 * this lock.  Callback handlers do not need to modify the
	 * callback handler table.
	 */
	mutex_init(&vx_cmd_lock, NULL, MUTEX_DEFAULT, NULL);

	/*
	 * Tell OBP about our callback handler.
	 */
	(void) prom_set_callback((void *)callback_handler);
}

/*
 * Add a kernel callback handler to the kernel's list.
 * The table is static, so if you add a callback handler, increase
 * the value of VX_CMD_MAX. Find the first empty slot and use it.
 */
void
add_vx_handler(char *name, int flag, void (*func)(cell_t *))
{
	struct vx_cmd *vp;

	mutex_enter(&vx_cmd_lock);
	for (vp = vx_cmd; vp < vx_cmd_end; vp++) {
		if (vp->service == NULL) {
			vp->service = name;
			vp->take_tba = flag;
			vp->func = func;
			mutex_exit(&vx_cmd_lock);
			return;
		}
	}
	mutex_exit(&vx_cmd_lock);

#ifdef	DEBUG

	/*
	 * There must be enough entries to handle all callback entries.
	 * Increase VX_CMD_MAX if this happens. This shouldn't happen.
	 */
	cmn_err(CE_PANIC, "add_vx_handler <%s>", name);
	/* NOTREACHED */

#else	/* DEBUG */

	cmn_err(CE_WARN, "add_vx_handler: Can't add callback hander <%s>",
	    name);

#endif	/* DEBUG */

}

/*
 * Remove a vx_handler function -- find the name string in the table,
 * and clear it.
 */
void
remove_vx_handler(char *name)
{
	struct vx_cmd *vp;

	mutex_enter(&vx_cmd_lock);
	for (vp = vx_cmd; vp < vx_cmd_end; vp++) {
		if (vp->service == NULL)
			continue;
		if (strcmp(vp->service, name) != 0)
			continue;
		vp->service = 0;
		vp->take_tba = 0;
		vp->func = 0;
		mutex_exit(&vx_cmd_lock);
		return;
	}
	mutex_exit(&vx_cmd_lock);
	cmn_err(CE_WARN, "remove_vx_handler: <%s> not found", name);
}

int
vx_handler(cell_t *argument_array)
{
	char *name;
	struct vx_cmd *vp;
	void *old_tba;

	name = p1275_cell2ptr(*argument_array);

	for (vp = vx_cmd; vp < vx_cmd_end; vp++) {
		if (vp->service == (char *)0)
			continue;
		if (strcmp(vp->service, name) != 0)
			continue;
		if (vp->take_tba != 0)  {
			reestablish_curthread();
			if (tba_taken_over != 0)
				old_tba = set_tba((void *)&trap_table);
		}
		vp->func(argument_array);
		if ((vp->take_tba != 0) && (tba_taken_over != 0))
			(void) set_tba(old_tba);
		return (0);	/* Service name was known */
	}

	return (-1);		/* Service name unknown */
}

/*
 * PROM Locking Primitives
 *
 * These routines are called immediately before and immediately after calling
 * into the firmware.  The firmware is single-threaded and assumes that the
 * kernel will implement locking to prevent simultaneous service calls.  In
 * addition, some service calls (particularly character rendering) can be
 * slow, so we would like to sleep if we cannot acquire the lock to allow the
 * caller's CPU to continue to perform useful work in the interim.  Service
 * routines may also be called early in boot as part of slave CPU startup
 * when mutexes and cvs are not yet available (i.e. they are still running on
 * the prom's TLB handlers and cannot touch curthread).  Therefore, these
 * routines must reduce to a simple compare-and-swap spin lock when necessary.
 * Finally, kernel code may wish to acquire the firmware lock before executing
 * a block of code that includes service calls, so we also allow the firmware
 * lock to be acquired recursively by the owning CPU after disabling preemption.
 *
 * To meet these constraints, the lock itself is implemented as a compare-and-
 * swap spin lock on the global prom_cpu pointer.  We implement recursion by
 * atomically incrementing the integer prom_holdcnt after acquiring the lock.
 * If the current CPU is an "adult" (determined by testing cpu_m.mutex_ready),
 * we disable preemption before acquiring the lock and leave it disabled once
 * the lock is held.  The kern_postprom() routine then enables preemption if
 * we drop the lock and prom_holdcnt returns to zero.  If the current CPU is
 * an adult and the lock is held by another adult CPU, we can safely sleep
 * until the lock is released.  To do so, we acquire the adaptive prom_mutex
 * and then sleep on prom_cv.  Therefore, service routines must not be called
 * from above LOCK_LEVEL on any adult CPU.  Finally, if recursive entry is
 * attempted on an adult CPU, we must also verify that curthread matches the
 * saved prom_thread (the original owner) to ensure that low-level interrupt
 * threads do not step on other threads running on the same CPU.
 */

static cpu_t *volatile prom_cpu;
static kthread_t *volatile prom_thread;
static uint32_t prom_holdcnt;
static kmutex_t prom_mutex;
static kcondvar_t prom_cv;

/*
 * The debugger uses PROM services, and is thus unable to run if any of the
 * CPUs on the system are executing in the PROM at the time of debugger entry.
 * If a CPU is determined to be in the PROM when the debugger is entered,
 * prom_return_enter_debugger will be set, thus triggering a programmed debugger
 * entry when the given CPU returns from the PROM.  That CPU is then released by
 * the debugger, and is allowed to complete PROM-related work.
 */
int prom_exit_enter_debugger;

void
kern_preprom(void)
{
	for (;;) {
		/*
		 * Load the current CPU pointer and examine the mutex_ready bit.
		 * It doesn't matter if we are preempted here because we are
		 * only trying to determine if we are in the *set* of mutex
		 * ready CPUs.  We cannot disable preemption until we confirm
		 * that we are running on a CPU in this set, since a call to
		 * kpreempt_disable() requires access to curthread.
		 */
		processorid_t cpuid = getprocessorid();
		cpu_t *cp = cpu[cpuid];
		cpu_t *prcp;

		if (panicstr)
			return; /* just return if we are currently panicking */

		if (CPU_IN_SET(cpu_ready_set, cpuid) && cp->cpu_m.mutex_ready) {
			/*
			 * Disable premption, and reload the current CPU.  We
			 * can't move from a mutex_ready cpu to a non-ready cpu
			 * so we don't need to re-check cp->cpu_m.mutex_ready.
			 */
			kpreempt_disable();
			cp = CPU;
			ASSERT(cp->cpu_m.mutex_ready);

			/*
			 * Try the lock.  If we don't get the lock, re-enable
			 * preemption and see if we should sleep.  If we are
			 * already the lock holder, remove the effect of the
			 * previous kpreempt_disable() before returning since
			 * preemption was disabled by an earlier kern_preprom.
			 */
			prcp = atomic_cas_ptr((void *)&prom_cpu, NULL, cp);
			if (prcp == NULL ||
			    (prcp == cp && prom_thread == curthread)) {
				if (prcp == cp)
					kpreempt_enable();
				break;
			}

			kpreempt_enable();

			/*
			 * We have to be very careful here since both prom_cpu
			 * and prcp->cpu_m.mutex_ready can be changed at any
			 * time by a non mutex_ready cpu holding the lock.
			 * If the owner is mutex_ready, holding prom_mutex
			 * prevents kern_postprom() from completing.  If the
			 * owner isn't mutex_ready, we only know it will clear
			 * prom_cpu before changing cpu_m.mutex_ready, so we
			 * issue a membar after checking mutex_ready and then
			 * re-verify that prom_cpu is still held by the same
			 * cpu before actually proceeding to cv_wait().
			 */
			mutex_enter(&prom_mutex);
			prcp = prom_cpu;
			if (prcp != NULL && prcp->cpu_m.mutex_ready != 0) {
				membar_consumer();
				if (prcp == prom_cpu)
					cv_wait(&prom_cv, &prom_mutex);
			}
			mutex_exit(&prom_mutex);

		} else {
			/*
			 * If we are not yet mutex_ready, just attempt to grab
			 * the lock.  If we get it or already hold it, break.
			 */
			ASSERT(getpil() == PIL_MAX);
			prcp = atomic_cas_ptr((void *)&prom_cpu, NULL, cp);
			if (prcp == NULL || prcp == cp)
				break;
		}
	}

	/*
	 * We now hold the prom_cpu lock.  Increment the hold count by one
	 * and assert our current state before returning to the caller.
	 */
	atomic_inc_32(&prom_holdcnt);
	ASSERT(prom_holdcnt >= 1);
	prom_thread = curthread;
}

/*
 * Drop the prom lock if it is held by the current CPU.  If the lock is held
 * recursively, return without clearing prom_cpu.  If the hold count is now
 * zero, clear prom_cpu and cv_signal any waiting CPU.
 */
void
kern_postprom(void)
{
	processorid_t cpuid = getprocessorid();
	cpu_t *cp = cpu[cpuid];

	if (panicstr)
		return; /* do not modify lock further if we have panicked */

	if (prom_cpu != cp)
		panic("kern_postprom: not owner, cp=%p owner=%p",
		    (void *)cp, (void *)prom_cpu);

	if (prom_holdcnt == 0)
		panic("kern_postprom: prom_holdcnt == 0, owner=%p",
		    (void *)prom_cpu);

	if (atomic_dec_32_nv(&prom_holdcnt) != 0)
		return; /* prom lock is held recursively by this CPU */

	if ((boothowto & RB_DEBUG) && prom_exit_enter_debugger)
		kmdb_enter();

	prom_thread = NULL;
	membar_producer();

	prom_cpu = NULL;
	membar_producer();

	if (CPU_IN_SET(cpu_ready_set, cpuid) && cp->cpu_m.mutex_ready) {
		mutex_enter(&prom_mutex);
		cv_signal(&prom_cv);
		mutex_exit(&prom_mutex);
		kpreempt_enable();
	}
}

/*
 * If the frame buffer device is busy, briefly capture the other CPUs so that
 * another CPU executing code to manipulate the device does not execute at the
 * same time we are rendering characters.  Refer to the comments and code in
 * common/os/console.c for more information on these callbacks.
 *
 * Notice that we explicitly acquire the PROM lock using kern_preprom() prior
 * to idling other CPUs.  The idling mechanism will cross-trap the other CPUs
 * and have them spin at MAX(%pil, XCALL_PIL), so we must be sure that none of
 * them are holding the PROM lock before we idle them and then call into the
 * PROM routines that render characters to the frame buffer.
 */
int
console_enter(int busy)
{
	int s = 0;

	if (busy && panicstr == NULL) {
		kern_preprom();
		s = splhi();
		idle_other_cpus();
	}

	return (s);
}

void
console_exit(int busy, int spl)
{
	if (busy && panicstr == NULL) {
		resume_other_cpus();
		splx(spl);
		kern_postprom();
	}
}

/*
 * This routine is a special form of pause_cpus().  It ensures that
 * prom functions are callable while the cpus are paused.
 */
void
promsafe_pause_cpus(void)
{
	pause_cpus(NULL, NULL);

	/* If some other cpu is entering or is in the prom, spin */
	while (prom_cpu || mutex_owner(&prom_mutex)) {

		start_cpus();
		mutex_enter(&prom_mutex);

		/* Wait for other cpu to exit prom */
		while (prom_cpu)
			cv_wait(&prom_cv, &prom_mutex);

		mutex_exit(&prom_mutex);
		pause_cpus(NULL, NULL);
	}

	/* At this point all cpus are paused and none are in the prom */
}

/*
 * This routine is a special form of xc_attention().  It ensures that
 * prom functions are callable while the cpus are at attention.
 */
void
promsafe_xc_attention(cpuset_t cpuset)
{
	xc_attention(cpuset);

	/* If some other cpu is entering or is in the prom, spin */
	while (prom_cpu || mutex_owner(&prom_mutex)) {

		xc_dismissed(cpuset);
		mutex_enter(&prom_mutex);

		/* Wait for other cpu to exit prom */
		while (prom_cpu)
			cv_wait(&prom_cv, &prom_mutex);

		mutex_exit(&prom_mutex);
		xc_attention(cpuset);
	}

	/* At this point all cpus are paused and none are in the prom */
}


#if defined(PROM_32BIT_ADDRS)

#include <sys/promimpl.h>
#include <vm/seg_kmem.h>
#include <sys/kmem.h>
#include <sys/bootconf.h>

/*
 * These routines are only used to workaround "poor feature interaction"
 * in OBP.  See bug 4115680 for details.
 *
 * Many of the promif routines need to allocate temporary buffers
 * with 32-bit addresses to pass in/out of the CIF.  The lifetime
 * of the buffers is extremely short, they are allocated and freed
 * around the CIF call.  We use vmem_alloc() to cache 32-bit memory.
 *
 * Note the code in promplat_free() to prevent exhausting the 32 bit
 * heap during boot.
 */
static void *promplat_last_free = NULL;
static size_t promplat_last_size;
static vmem_t *promplat_arena;
static kmutex_t promplat_lock;  /* protect arena, last_free, and last_size */

void *
promplat_alloc(size_t size)
{

	mutex_enter(&promplat_lock);
	if (promplat_arena == NULL) {
		promplat_arena = vmem_create("promplat", NULL, 0, 8,
		    segkmem_alloc, segkmem_free, heap32_arena, 0, VM_SLEEP);
	}
	mutex_exit(&promplat_lock);

	return (vmem_alloc(promplat_arena, size, VM_NOSLEEP));
}

/*
 * Delaying the free() of small allocations gets more mileage
 * from pages during boot, otherwise a cycle of allocate/free
 * calls could burn through available heap32 space too quickly.
 */
void
promplat_free(void *p, size_t size)
{
	void *p2 = NULL;
	size_t s2;

	/*
	 * If VM is initialized, clean up any delayed free().
	 */
	if (kvseg.s_base != 0 && promplat_last_free != NULL) {
		mutex_enter(&promplat_lock);
		p2 = promplat_last_free;
		s2 = promplat_last_size;
		promplat_last_free = NULL;
		promplat_last_size = 0;
		mutex_exit(&promplat_lock);
		if (p2 != NULL) {
			vmem_free(promplat_arena, p2, s2);
			p2 = NULL;
		}
	}

	/*
	 * Do the free if VM is initialized or it's a large allocation.
	 */
	if (kvseg.s_base != 0 || size >= PAGESIZE) {
		vmem_free(promplat_arena, p, size);
		return;
	}

	/*
	 * Otherwise, do the last free request and delay this one.
	 */
	mutex_enter(&promplat_lock);
	if (promplat_last_free != NULL) {
		p2 = promplat_last_free;
		s2 = promplat_last_size;
	}
	promplat_last_free = p;
	promplat_last_size = size;
	mutex_exit(&promplat_lock);

	if (p2 != NULL)
		vmem_free(promplat_arena, p2, s2);
}

void
promplat_bcopy(const void *src, void *dst, size_t count)
{
	bcopy(src, dst, count);
}

#endif /* PROM_32BIT_ADDRS */

static prom_generation_cookie_t prom_tree_gen;
static krwlock_t prom_tree_lock;

int
prom_tree_access(int (*callback)(void *arg, int has_changed), void *arg,
    prom_generation_cookie_t *ckp)
{
	int chg, rv;

	rw_enter(&prom_tree_lock, RW_READER);
	/*
	 * If the tree has changed since the caller last accessed it
	 * pass 1 as the second argument to the callback function,
	 * otherwise 0.
	 */
	if (ckp != NULL && *ckp != prom_tree_gen) {
		*ckp = prom_tree_gen;
		chg = 1;
	} else
		chg = 0;
	rv = callback(arg, chg);
	rw_exit(&prom_tree_lock);
	return (rv);
}

int
prom_tree_update(int (*callback)(void *arg), void *arg)
{
	int rv;

	rw_enter(&prom_tree_lock, RW_WRITER);
	prom_tree_gen++;
	rv = callback(arg);
	rw_exit(&prom_tree_lock);
	return (rv);
}
