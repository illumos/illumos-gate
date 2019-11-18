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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/* derived from netbsd's xen_machdep.c 1.1.2.1 */

/*
 *
 * Copyright (c) 2004 Christian Limpach.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. This section intentionally left blank.
 * 4. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
/*
 * Section 3 of the above license was updated in response to bug 6379571.
 */

#include <sys/xpv_user.h>

/* XXX 3.3. TODO remove this include */
#include <xen/public/arch-x86/xen-mca.h>

#include <sys/ctype.h>
#include <sys/types.h>
#include <sys/cmn_err.h>
#include <sys/trap.h>
#include <sys/segments.h>
#include <sys/hypervisor.h>
#include <sys/xen_mmu.h>
#include <sys/machsystm.h>
#include <sys/promif.h>
#include <sys/bootconf.h>
#include <sys/bootinfo.h>
#include <sys/cpr.h>
#include <sys/taskq.h>
#include <sys/uadmin.h>
#include <sys/evtchn_impl.h>
#include <sys/archsystm.h>
#include <xen/sys/xenbus_impl.h>
#include <sys/mach_mmu.h>
#include <vm/hat_i86.h>
#include <sys/gnttab.h>
#include <sys/reboot.h>
#include <sys/stack.h>
#include <sys/clock.h>
#include <sys/bitmap.h>
#include <sys/processor.h>
#include <sys/xen_errno.h>
#include <sys/xpv_panic.h>
#include <sys/smp_impldefs.h>
#include <sys/cpu.h>
#include <sys/balloon_impl.h>
#include <sys/ddi.h>

#ifdef DEBUG
#define	SUSPEND_DEBUG if (xen_suspend_debug) xen_printf
#else
#define	SUSPEND_DEBUG(...)
#endif

int cpr_debug;
cpuset_t cpu_suspend_lost_set;
static int xen_suspend_debug;

uint_t xen_phys_ncpus;
xen_mc_logical_cpu_t *xen_phys_cpus;
int xen_physinfo_debug = 0;

/*
 * Determine helpful version information.
 *
 * (And leave copies in the data segment so we can look at them later
 * with e.g. kmdb.)
 */

typedef enum xen_version {
	XENVER_BOOT_IDX,
	XENVER_CURRENT_IDX
} xen_version_t;

struct xenver {
	ulong_t xv_major;
	ulong_t xv_minor;
	ulong_t xv_revision;
	xen_extraversion_t xv_ver;
	ulong_t xv_is_xvm;
	xen_changeset_info_t xv_chgset;
	xen_compile_info_t xv_build;
	xen_capabilities_info_t xv_caps;
} xenver[2];

#define	XENVER_BOOT(m)	(xenver[XENVER_BOOT_IDX].m)
#define	XENVER_CURRENT(m)	(xenver[XENVER_CURRENT_IDX].m)

/*
 * Update the xenver data. We maintain two copies, boot and
 * current. If we are setting the boot, then also set current.
 */
static void
xen_set_version(xen_version_t idx)
{
	ulong_t ver;

	bzero(&xenver[idx], sizeof (xenver[idx]));

	ver = HYPERVISOR_xen_version(XENVER_version, 0);

	xenver[idx].xv_major = BITX(ver, 31, 16);
	xenver[idx].xv_minor = BITX(ver, 15, 0);

	(void) HYPERVISOR_xen_version(XENVER_extraversion, &xenver[idx].xv_ver);

	/*
	 * The revision is buried in the extraversion information that is
	 * maintained by the hypervisor. For our purposes we expect that
	 * the revision number is:
	 *	- the second character in the extraversion information
	 *	- one character long
	 *	- numeric digit
	 * If it isn't then we can't extract the revision and we leave it
	 * set to 0.
	 */
	if (strlen(xenver[idx].xv_ver) > 1 && isdigit(xenver[idx].xv_ver[1]))
		xenver[idx].xv_revision = xenver[idx].xv_ver[1] - '0';
	else
		cmn_err(CE_WARN, "Cannot extract revision on this hypervisor "
		    "version: v%s, unexpected version format",
		    xenver[idx].xv_ver);

	xenver[idx].xv_is_xvm = 0;

	if (strstr(xenver[idx].xv_ver, "-xvm") != NULL)
		xenver[idx].xv_is_xvm = 1;

	(void) HYPERVISOR_xen_version(XENVER_changeset,
	    &xenver[idx].xv_chgset);

	(void) HYPERVISOR_xen_version(XENVER_compile_info,
	    &xenver[idx].xv_build);
	/*
	 * Capabilities are a set of space separated ascii strings
	 * e.g. 'xen-3.1-x86_32p' or 'hvm-3.2-x86_64'
	 */
	(void) HYPERVISOR_xen_version(XENVER_capabilities,
	    &xenver[idx].xv_caps);

	cmn_err(CE_CONT, "?v%lu.%lu%s chgset '%s'\n", xenver[idx].xv_major,
	    xenver[idx].xv_minor, xenver[idx].xv_ver, xenver[idx].xv_chgset);

	if (idx == XENVER_BOOT_IDX)
		bcopy(&xenver[XENVER_BOOT_IDX], &xenver[XENVER_CURRENT_IDX],
		    sizeof (xenver[XENVER_BOOT_IDX]));
}

typedef enum xen_hypervisor_check {
	XEN_RUN_CHECK,
	XEN_SUSPEND_CHECK
} xen_hypervisor_check_t;

/*
 * To run the hypervisor must be 3.0.4 or better. To suspend/resume
 * we need 3.0.4 or better and if it is 3.0.4. then it must be provided
 * by the Solaris xVM project.
 * Checking can be disabled for testing purposes by setting the
 * xen_suspend_debug variable.
 */
static int
xen_hypervisor_supports_solaris(xen_hypervisor_check_t check)
{
	if (xen_suspend_debug == 1)
		return (1);
	if (XENVER_CURRENT(xv_major) < 3)
		return (0);
	if (XENVER_CURRENT(xv_major) > 3)
		return (1);
	if (XENVER_CURRENT(xv_minor) > 0)
		return (1);
	if (XENVER_CURRENT(xv_revision) < 4)
		return (0);
	if (check == XEN_SUSPEND_CHECK && XENVER_CURRENT(xv_revision) == 4 &&
	    !XENVER_CURRENT(xv_is_xvm))
		return (0);

	return (1);
}

/*
 * If the hypervisor is -xvm, or 3.1.2 or higher, we don't need the
 * workaround.
 */
static void
xen_pte_workaround(void)
{
#if defined(__amd64)
	extern int pt_kern;

	if (XENVER_CURRENT(xv_major) != 3)
		return;
	if (XENVER_CURRENT(xv_minor) > 1)
		return;
	if (XENVER_CURRENT(xv_minor) == 1 &&
	    XENVER_CURRENT(xv_revision) > 1)
		return;
	if (XENVER_CURRENT(xv_is_xvm))
		return;

	pt_kern = PT_USER;
#endif
}

void
xen_set_callback(void (*func)(void), uint_t type, uint_t flags)
{
	struct callback_register cb;

	bzero(&cb, sizeof (cb));
#if defined(__amd64)
	cb.address = (ulong_t)func;
#elif defined(__i386)
	cb.address.cs = KCS_SEL;
	cb.address.eip = (ulong_t)func;
#endif
	cb.type = type;
	cb.flags = flags;

	/*
	 * XXPV always ignore return value for NMI
	 */
	if (HYPERVISOR_callback_op(CALLBACKOP_register, &cb) != 0 &&
	    type != CALLBACKTYPE_nmi)
		panic("HYPERVISOR_callback_op failed");
}

void
xen_init_callbacks(void)
{
	/*
	 * register event (interrupt) handler.
	 */
	xen_set_callback(xen_callback, CALLBACKTYPE_event, 0);

	/*
	 * failsafe handler.
	 */
	xen_set_callback(xen_failsafe_callback, CALLBACKTYPE_failsafe,
	    CALLBACKF_mask_events);

	/*
	 * NMI handler.
	 */
	xen_set_callback(nmiint, CALLBACKTYPE_nmi, 0);

	/*
	 * system call handler
	 * XXPV move to init_cpu_syscall?
	 */
#if defined(__amd64)
	xen_set_callback(sys_syscall, CALLBACKTYPE_syscall,
	    CALLBACKF_mask_events);
#endif	/* __amd64 */
}


/*
 * cmn_err() followed by a 1/4 second delay; this gives the
 * logging service a chance to flush messages and helps avoid
 * intermixing output from prom_printf().
 * XXPV: doesn't exactly help us on UP though.
 */
/*PRINTFLIKE2*/
void
cpr_err(int ce, const char *fmt, ...)
{
	va_list adx;

	va_start(adx, fmt);
	vcmn_err(ce, fmt, adx);
	va_end(adx);
	drv_usecwait(MICROSEC >> 2);
}

void
xen_suspend_devices(void)
{
	int rc;

	SUSPEND_DEBUG("xen_suspend_devices\n");

	if ((rc = cpr_suspend_devices(ddi_root_node())) != 0)
		panic("failed to suspend devices: %d", rc);
}

void
xen_resume_devices(void)
{
	int rc;

	SUSPEND_DEBUG("xen_resume_devices\n");

	if ((rc = cpr_resume_devices(ddi_root_node(), 0)) != 0)
		panic("failed to resume devices: %d", rc);
}

/*
 * The list of mfn pages is out of date.  Recompute it.
 */
static void
rebuild_mfn_list(void)
{
	int i = 0;
	size_t sz;
	size_t off;
	pfn_t pfn;

	SUSPEND_DEBUG("rebuild_mfn_list\n");

	sz = ((mfn_count * sizeof (mfn_t)) + MMU_PAGEOFFSET) & MMU_PAGEMASK;

	for (off = 0; off < sz; off += MMU_PAGESIZE) {
		size_t j = mmu_btop(off);
		if (((j * sizeof (mfn_t)) & MMU_PAGEOFFSET) == 0) {
			pfn = hat_getpfnum(kas.a_hat,
			    (caddr_t)&mfn_list_pages[j]);
			mfn_list_pages_page[i++] = pfn_to_mfn(pfn);
		}

		pfn = hat_getpfnum(kas.a_hat, (caddr_t)mfn_list + off);
		mfn_list_pages[j] = pfn_to_mfn(pfn);
	}

	pfn = hat_getpfnum(kas.a_hat, (caddr_t)mfn_list_pages_page);
	HYPERVISOR_shared_info->arch.pfn_to_mfn_frame_list_list
	    = pfn_to_mfn(pfn);
}

static void
suspend_cpus(void)
{
	int i;

	SUSPEND_DEBUG("suspend_cpus\n");

	mp_enter_barrier();

	for (i = 1; i < ncpus; i++) {
		if (!CPU_IN_SET(cpu_suspend_lost_set, i)) {
			SUSPEND_DEBUG("xen_vcpu_down %d\n", i);
			(void) xen_vcpu_down(i);
		}

		mach_cpucontext_reset(cpu[i]);
	}
}

static void
resume_cpus(void)
{
	int i;

	for (i = 1; i < ncpus; i++) {
		if (cpu[i] == NULL)
			continue;

		if (!CPU_IN_SET(cpu_suspend_lost_set, i)) {
			SUSPEND_DEBUG("xen_vcpu_up %d\n", i);
			mach_cpucontext_restore(cpu[i]);
			(void) xen_vcpu_up(i);
		}
	}

	mp_leave_barrier();
}

/*
 * Top level routine to direct suspend/resume of a domain.
 */
void
xen_suspend_domain(void)
{
	extern void rtcsync(void);
	extern hrtime_t hres_last_tick;
	mfn_t start_info_mfn;
	ulong_t flags;
	pfn_t pfn;
	int i;

	/*
	 * Check that we are happy to suspend on this hypervisor.
	 */
	if (xen_hypervisor_supports_solaris(XEN_SUSPEND_CHECK) == 0) {
		cpr_err(CE_WARN, "Cannot suspend on this hypervisor "
		    "version: v%lu.%lu%s, need at least version v3.0.4 or "
		    "-xvm based hypervisor", XENVER_CURRENT(xv_major),
		    XENVER_CURRENT(xv_minor), XENVER_CURRENT(xv_ver));
		return;
	}

	/*
	 * XXPV - Are we definitely OK to suspend by the time we've connected
	 * the handler?
	 */

	cpr_err(CE_NOTE, "Domain suspending for save/migrate");

	SUSPEND_DEBUG("xen_suspend_domain\n");

	/*
	 * suspend interrupts and devices
	 * XXPV - we use suspend/resume for both save/restore domains (like sun
	 * cpr) and for migration.  Would be nice to know the difference if
	 * possible.  For save/restore where down time may be a long time, we
	 * may want to do more of the things that cpr does.  (i.e. notify user
	 * processes, shrink memory footprint for faster restore, etc.)
	 */
	xen_suspend_devices();
	SUSPEND_DEBUG("xenbus_suspend\n");
	xenbus_suspend();

	pfn = hat_getpfnum(kas.a_hat, (caddr_t)xen_info);
	start_info_mfn = pfn_to_mfn(pfn);

	/*
	 * XXPV: cpu hotplug can hold this under a xenbus watch. Are we safe
	 * wrt xenbus being suspended here?
	 */
	mutex_enter(&cpu_lock);

	/*
	 * Suspend must be done on vcpu 0, as no context for other CPUs is
	 * saved.
	 *
	 * XXPV - add to taskq API ?
	 */
	thread_affinity_set(curthread, 0);
	kpreempt_disable();

	SUSPEND_DEBUG("xen_start_migrate\n");
	xen_start_migrate();
	if (ncpus > 1)
		suspend_cpus();

	/*
	 * We can grab the ec_lock as it's a spinlock with a high SPL. Hence
	 * any holder would have dropped it to get through suspend_cpus().
	 */
	mutex_enter(&ec_lock);

	/*
	 * From here on in, we can't take locks.
	 */
	SUSPEND_DEBUG("ec_suspend\n");
	ec_suspend();
	SUSPEND_DEBUG("gnttab_suspend\n");
	gnttab_suspend();

	flags = intr_clear();

	xpv_time_suspend();

	/*
	 * Currently, the hypervisor incorrectly fails to bring back
	 * powered-down VCPUs.  Thus we need to record any powered-down VCPUs
	 * to prevent any attempts to operate on them.  But we have to do this
	 * *after* the very first time we do ec_suspend().
	 */
	for (i = 1; i < ncpus; i++) {
		if (cpu[i] == NULL)
			continue;

		if (cpu_get_state(cpu[i]) == P_POWEROFF)
			CPUSET_ATOMIC_ADD(cpu_suspend_lost_set, i);
	}

	/*
	 * The dom0 save/migrate code doesn't automatically translate
	 * these into PFNs, but expects them to be, so we do it here.
	 * We don't use mfn_to_pfn() because so many OS services have
	 * been disabled at this point.
	 */
	xen_info->store_mfn = mfn_to_pfn_mapping[xen_info->store_mfn];
	xen_info->console.domU.mfn =
	    mfn_to_pfn_mapping[xen_info->console.domU.mfn];

	if (CPU->cpu_m.mcpu_vcpu_info->evtchn_upcall_mask == 0) {
		prom_printf("xen_suspend_domain(): "
		    "CPU->cpu_m.mcpu_vcpu_info->evtchn_upcall_mask not set\n");
		(void) HYPERVISOR_shutdown(SHUTDOWN_crash);
	}

	if (HYPERVISOR_update_va_mapping((uintptr_t)HYPERVISOR_shared_info,
	    0, UVMF_INVLPG)) {
		prom_printf("xen_suspend_domain(): "
		    "HYPERVISOR_update_va_mapping() failed\n");
		(void) HYPERVISOR_shutdown(SHUTDOWN_crash);
	}

	SUSPEND_DEBUG("HYPERVISOR_suspend\n");

	/*
	 * At this point we suspend and sometime later resume.
	 */
	if (HYPERVISOR_suspend(start_info_mfn)) {
		prom_printf("xen_suspend_domain(): "
		    "HYPERVISOR_suspend() failed\n");
		(void) HYPERVISOR_shutdown(SHUTDOWN_crash);
	}

	/*
	 * Point HYPERVISOR_shared_info to its new value.
	 */
	if (HYPERVISOR_update_va_mapping((uintptr_t)HYPERVISOR_shared_info,
	    xen_info->shared_info | PT_NOCONSIST | PT_VALID | PT_WRITABLE,
	    UVMF_INVLPG))
		(void) HYPERVISOR_shutdown(SHUTDOWN_crash);

	if (xen_info->nr_pages != mfn_count) {
		prom_printf("xen_suspend_domain(): number of pages"
		    " changed, was 0x%lx, now 0x%lx\n", mfn_count,
		    xen_info->nr_pages);
		(void) HYPERVISOR_shutdown(SHUTDOWN_crash);
	}

	xpv_time_resume();

	cached_max_mfn = 0;

	SUSPEND_DEBUG("gnttab_resume\n");
	gnttab_resume();

	/* XXPV: add a note that this must be lockless. */
	SUSPEND_DEBUG("ec_resume\n");
	ec_resume();

	intr_restore(flags);

	if (ncpus > 1)
		resume_cpus();

	mutex_exit(&ec_lock);
	xen_end_migrate();
	mutex_exit(&cpu_lock);

	/*
	 * Now we can take locks again.
	 */

	/*
	 * Force the tick value used for tv_nsec in hres_tick() to be up to
	 * date. rtcsync() will reset the hrestime value appropriately.
	 */
	hres_last_tick = xpv_gethrtime();

	/*
	 * XXPV: we need to have resumed the CPUs since this takes locks, but
	 * can remote CPUs see bad state? Presumably yes. Should probably nest
	 * taking of todlock inside of cpu_lock, or vice versa, then provide an
	 * unlocked version.  Probably need to call clkinitf to reset cpu freq
	 * and re-calibrate if we migrated to a different speed cpu.  Also need
	 * to make a (re)init_cpu_info call to update processor info structs
	 * and device tree info.  That remains to be written at the moment.
	 */
	rtcsync();

	rebuild_mfn_list();

	SUSPEND_DEBUG("xenbus_resume\n");
	xenbus_resume();
	SUSPEND_DEBUG("xenbus_resume_devices\n");
	xen_resume_devices();

	thread_affinity_clear(curthread);
	kpreempt_enable();

	SUSPEND_DEBUG("finished xen_suspend_domain\n");

	/*
	 * We have restarted our suspended domain, update the hypervisor
	 * details. NB: This must be done at the end of this function,
	 * since we need the domain to be completely resumed before
	 * these functions will work correctly.
	 */
	xen_set_version(XENVER_CURRENT_IDX);

	/*
	 * We can check and report a warning, but we don't stop the
	 * process.
	 */
	if (xen_hypervisor_supports_solaris(XEN_SUSPEND_CHECK) == 0)
		cmn_err(CE_WARN, "Found hypervisor version: v%lu.%lu%s "
		    "but need at least version v3.0.4",
		    XENVER_CURRENT(xv_major), XENVER_CURRENT(xv_minor),
		    XENVER_CURRENT(xv_ver));

	cmn_err(CE_NOTE, "domain restore/migrate completed");
}

uint_t
xen_debug_handler(caddr_t arg __unused, caddr_t arg1 __unused)
{
	debug_enter("External debug event received");

	/*
	 * If we've not got KMDB loaded, output some stuff difficult to capture
	 * from a domain core.
	 */
	if (!(boothowto & RB_DEBUG)) {
		shared_info_t *si = HYPERVISOR_shared_info;
		int i;

		prom_printf("evtchn_pending [ ");
		for (i = 0; i < 8; i++)
			prom_printf("%lx ", si->evtchn_pending[i]);
		prom_printf("]\nevtchn_mask [ ");
		for (i = 0; i < 8; i++)
			prom_printf("%lx ", si->evtchn_mask[i]);
		prom_printf("]\n");

		for (i = 0; i < ncpus; i++) {
			vcpu_info_t *vcpu = &si->vcpu_info[i];
			if (cpu[i] == NULL)
				continue;
			prom_printf("CPU%d pending %d mask %d sel %lx\n",
			    i, vcpu->evtchn_upcall_pending,
			    vcpu->evtchn_upcall_mask,
			    vcpu->evtchn_pending_sel);
		}
	}

	return (0);
}

/*ARGSUSED*/
static void
xen_sysrq_handler(struct xenbus_watch *watch, const char **vec,
    unsigned int len)
{
	xenbus_transaction_t xbt;
	char key = '\0';
	int ret;

retry:
	if (xenbus_transaction_start(&xbt)) {
		cmn_err(CE_WARN, "failed to start sysrq transaction");
		return;
	}

	if ((ret = xenbus_scanf(xbt, "control", "sysrq", "%c", &key)) != 0) {
		/*
		 * ENOENT happens in response to our own xenbus_rm.
		 * XXPV - this happens spuriously on boot?
		 */
		if (ret != ENOENT)
			cmn_err(CE_WARN, "failed to read sysrq: %d", ret);
		goto out;
	}

	if ((ret = xenbus_rm(xbt, "control", "sysrq")) != 0) {
		cmn_err(CE_WARN, "failed to reset sysrq: %d", ret);
		goto out;
	}

	if (xenbus_transaction_end(xbt, 0) == EAGAIN)
		goto retry;

	/*
	 * Somewhat arbitrary - on Linux this means 'reboot'. We could just
	 * accept any key, but this might increase the risk of sending a
	 * harmless sysrq to the wrong domain...
	 */
	if (key == 'b')
		(void) xen_debug_handler(NULL, NULL);
	else
		cmn_err(CE_WARN, "Ignored sysrq %c", key);
	return;

out:
	(void) xenbus_transaction_end(xbt, 1);
}

taskq_t *xen_shutdown_tq;

#define	SHUTDOWN_INVALID	-1
#define	SHUTDOWN_POWEROFF	0
#define	SHUTDOWN_REBOOT		1
#define	SHUTDOWN_SUSPEND	2
#define	SHUTDOWN_HALT		3
#define	SHUTDOWN_MAX		4

#define	SHUTDOWN_TIMEOUT_SECS (60 * 5)

static const char *cmd_strings[SHUTDOWN_MAX] = {
	"poweroff",
	"reboot",
	"suspend",
	"halt"
};

static void
xen_dirty_shutdown(void *arg)
{
	int cmd = (uintptr_t)arg;

	cmn_err(CE_WARN, "Externally requested shutdown failed or "
	    "timed out.\nShutting down.\n");

	switch (cmd) {
	case SHUTDOWN_HALT:
	case SHUTDOWN_POWEROFF:
		(void) kadmin(A_SHUTDOWN, AD_POWEROFF, NULL, kcred);
		break;
	case SHUTDOWN_REBOOT:
		(void) kadmin(A_REBOOT, AD_BOOT, NULL, kcred);
		break;
	}
}

static void
xen_shutdown(void *arg)
{
	int cmd = (uintptr_t)arg;
	proc_t *initpp;

	ASSERT(cmd > SHUTDOWN_INVALID && cmd < SHUTDOWN_MAX);

	if (cmd == SHUTDOWN_SUSPEND) {
		xen_suspend_domain();
		return;
	}

	switch (cmd) {
	case SHUTDOWN_POWEROFF:
		force_shutdown_method = AD_POWEROFF;
		break;
	case SHUTDOWN_HALT:
		force_shutdown_method = AD_HALT;
		break;
	case SHUTDOWN_REBOOT:
		force_shutdown_method = AD_BOOT;
		break;
	}

	/*
	 * If we're still booting and init(1) isn't set up yet, simply halt.
	 */
	mutex_enter(&pidlock);
	initpp = prfind(P_INITPID);
	mutex_exit(&pidlock);
	if (initpp == NULL) {
		extern void halt(char *);
		halt("Power off the System");   /* just in case */
	}

	/*
	 * else, graceful shutdown with inittab and all getting involved
	 */
	psignal(initpp, SIGPWR);

	(void) timeout(xen_dirty_shutdown, arg,
	    SHUTDOWN_TIMEOUT_SECS * drv_usectohz(MICROSEC));
}

/*ARGSUSED*/
static void
xen_shutdown_handler(struct xenbus_watch *watch, const char **vec,
    unsigned int len)
{
	char *str;
	xenbus_transaction_t xbt;
	int err, shutdown_code = SHUTDOWN_INVALID;
	unsigned int slen;

again:
	err = xenbus_transaction_start(&xbt);
	if (err)
		return;
	if (xenbus_read(xbt, "control", "shutdown", (void *)&str, &slen)) {
		(void) xenbus_transaction_end(xbt, 1);
		return;
	}

	SUSPEND_DEBUG("%d: xen_shutdown_handler: \"%s\"\n", CPU->cpu_id, str);

	/*
	 * If this is a watch fired from our write below, check out early to
	 * avoid an infinite loop.
	 */
	if (strcmp(str, "") == 0) {
		(void) xenbus_transaction_end(xbt, 0);
		kmem_free(str, slen);
		return;
	} else if (strcmp(str, "poweroff") == 0) {
		shutdown_code = SHUTDOWN_POWEROFF;
	} else if (strcmp(str, "reboot") == 0) {
		shutdown_code = SHUTDOWN_REBOOT;
	} else if (strcmp(str, "suspend") == 0) {
		shutdown_code = SHUTDOWN_SUSPEND;
	} else if (strcmp(str, "halt") == 0) {
		shutdown_code = SHUTDOWN_HALT;
	} else {
		printf("Ignoring shutdown request: %s\n", str);
	}

	/*
	 * XXPV	Should we check the value of xenbus_write() too, or are all
	 *	errors automatically folded into xenbus_transaction_end() ??
	 */
	(void) xenbus_write(xbt, "control", "shutdown", "");
	err = xenbus_transaction_end(xbt, 0);
	if (err == EAGAIN) {
		SUSPEND_DEBUG("%d: trying again\n", CPU->cpu_id);
		kmem_free(str, slen);
		goto again;
	}

	kmem_free(str, slen);
	if (shutdown_code != SHUTDOWN_INVALID) {
		(void) taskq_dispatch(xen_shutdown_tq, xen_shutdown,
		    (void *)(intptr_t)shutdown_code, 0);
	}
}

static struct xenbus_watch shutdown_watch;
static struct xenbus_watch sysrq_watch;

void
xen_late_startup(void)
{
	if (!DOMAIN_IS_INITDOMAIN(xen_info)) {
		xen_shutdown_tq = taskq_create("shutdown_taskq", 1,
		    maxclsyspri - 1, 1, 1, TASKQ_PREPOPULATE);
		shutdown_watch.node = "control/shutdown";
		shutdown_watch.callback = xen_shutdown_handler;
		if (register_xenbus_watch(&shutdown_watch))
			cmn_err(CE_WARN, "Failed to set shutdown watcher");

		sysrq_watch.node = "control/sysrq";
		sysrq_watch.callback = xen_sysrq_handler;
		if (register_xenbus_watch(&sysrq_watch))
			cmn_err(CE_WARN, "Failed to set sysrq watcher");
	}
	balloon_init(xen_info->nr_pages);
}

#ifdef DEBUG
#define	XEN_PRINTF_BUFSIZE	1024

char xen_printf_buffer[XEN_PRINTF_BUFSIZE];

/*
 * Printf function that calls hypervisor directly.  For DomU it only
 * works when running on a xen hypervisor built with debug on.  Works
 * always since no I/O ring interaction is needed.
 */
/*PRINTFLIKE1*/
void
xen_printf(const char *fmt, ...)
{
	va_list	ap;

	va_start(ap, fmt);
	(void) vsnprintf(xen_printf_buffer, XEN_PRINTF_BUFSIZE, fmt, ap);
	va_end(ap);

	(void) HYPERVISOR_console_io(CONSOLEIO_write,
	    strlen(xen_printf_buffer), xen_printf_buffer);
}
#else
void
xen_printf(const char *fmt, ...)
{
}
#endif	/* DEBUG */

void
startup_xen_version(void)
{
	xen_set_version(XENVER_BOOT_IDX);
	if (xen_hypervisor_supports_solaris(XEN_RUN_CHECK) == 0)
		cmn_err(CE_WARN, "Found hypervisor version: v%lu.%lu%s "
		    "but need at least version v3.0.4",
		    XENVER_CURRENT(xv_major), XENVER_CURRENT(xv_minor),
		    XENVER_CURRENT(xv_ver));
	xen_pte_workaround();
}

int xen_mca_simulate_mc_physinfo_failure = 0;

void
startup_xen_mca(void)
{
	if (!DOMAIN_IS_INITDOMAIN(xen_info))
		return;

	xen_phys_ncpus = 0;
	xen_phys_cpus = NULL;

	if (xen_mca_simulate_mc_physinfo_failure ||
	    xen_get_mc_physcpuinfo(NULL, &xen_phys_ncpus) != 0) {
		cmn_err(CE_WARN,
		    "%sxen_get_mc_physinfo failure during xen MCA startup: "
		    "there will be no machine check support",
		    xen_mca_simulate_mc_physinfo_failure ? "(simulated) " : "");
		return;
	}

	xen_phys_cpus = kmem_alloc(xen_phys_ncpus *
	    sizeof (xen_mc_logical_cpu_t), KM_NOSLEEP);

	if (xen_phys_cpus == NULL) {
		cmn_err(CE_WARN,
		    "xen_get_mc_physinfo failure: can't allocate CPU array");
		return;
	}

	if (xen_get_mc_physcpuinfo(xen_phys_cpus, &xen_phys_ncpus) != 0) {
		cmn_err(CE_WARN, "xen_get_mc_physinfo failure: no "
		    "physical CPU info");
		kmem_free(xen_phys_cpus,
		    xen_phys_ncpus * sizeof (xen_mc_logical_cpu_t));
		xen_phys_ncpus = 0;
		xen_phys_cpus = NULL;
	}

	if (xen_physinfo_debug) {
		xen_mc_logical_cpu_t *xcp;
		unsigned i;

		cmn_err(CE_NOTE, "xvm mca: %u physical cpus:\n",
		    xen_phys_ncpus);
		for (i = 0; i < xen_phys_ncpus; i++) {
			xcp = &xen_phys_cpus[i];
			cmn_err(CE_NOTE, "cpu%u: (%u, %u, %u) apid %u",
			    xcp->mc_cpunr, xcp->mc_chipid, xcp->mc_coreid,
			    xcp->mc_threadid, xcp->mc_apicid);
		}
	}
}

/*
 * Miscellaneous hypercall wrappers with slightly more verbose diagnostics.
 */

void
xen_set_gdt(ulong_t *frame_list, int entries)
{
	int err;
	if ((err = HYPERVISOR_set_gdt(frame_list, entries)) != 0) {
		/*
		 * X_EINVAL:	reserved entry or bad frames
		 * X_EFAULT:	bad address
		 */
		panic("xen_set_gdt(%p, %d): error %d",
		    (void *)frame_list, entries, -(int)err);
	}
}

void
xen_set_ldt(user_desc_t *ldt, uint_t nsels)
{
	struct mmuext_op	op;
	long			err;

	op.cmd = MMUEXT_SET_LDT;
	op.arg1.linear_addr = (uintptr_t)ldt;
	op.arg2.nr_ents = nsels;

	if ((err = HYPERVISOR_mmuext_op(&op, 1, NULL, DOMID_SELF)) != 0) {
		panic("xen_set_ldt(%p, %d): error %d",
		    (void *)ldt, nsels, -(int)err);
	}
}

void
xen_stack_switch(ulong_t ss, ulong_t esp)
{
	long err;

	if ((err = HYPERVISOR_stack_switch(ss, esp)) != 0) {
		/*
		 * X_EPERM:	bad selector
		 */
		panic("xen_stack_switch(%lx, %lx): error %d", ss, esp,
		    -(int)err);
	}
}

long
xen_set_trap_table(trap_info_t *table)
{
	long err;

	if ((err = HYPERVISOR_set_trap_table(table)) != 0) {
		/*
		 * X_EFAULT:	bad address
		 * X_EPERM:	bad selector
		 */
		panic("xen_set_trap_table(%p): error %d", (void *)table,
		    -(int)err);
	}
	return (err);
}

#if defined(__amd64)
void
xen_set_segment_base(int reg, ulong_t value)
{
	long err;

	if ((err = HYPERVISOR_set_segment_base(reg, value)) != 0) {
		/*
		 * X_EFAULT:	bad address
		 * X_EINVAL:	bad type
		 */
		panic("xen_set_segment_base(%d, %lx): error %d",
		    reg, value, -(int)err);
	}
}
#endif	/* __amd64 */

/*
 * Translate a hypervisor errcode to a Solaris error code.
 */
int
xen_xlate_errcode(int error)
{
	switch (-error) {

	/*
	 * Translate hypervisor errno's into native errno's
	 */

#define	CASE(num)	case X_##num: error = num; break

	CASE(EPERM);	CASE(ENOENT);	CASE(ESRCH);
	CASE(EINTR);	CASE(EIO);	CASE(ENXIO);
	CASE(E2BIG);	CASE(ENOMEM);	CASE(EACCES);
	CASE(EFAULT);	CASE(EBUSY);	CASE(EEXIST);
	CASE(ENODEV);	CASE(EISDIR);	CASE(EINVAL);
	CASE(ENOSPC);	CASE(ESPIPE);	CASE(EROFS);
	CASE(ENOSYS);	CASE(ENOTEMPTY); CASE(EISCONN);
	CASE(ENODATA);	CASE(EAGAIN);

#undef CASE

	default:
		panic("xen_xlate_errcode: unknown error %d", error);
	}

	return (error);
}

/*
 * Raise PS_IOPL on current vcpu to user level.
 * Caller responsible for preventing kernel preemption.
 */
void
xen_enable_user_iopl(void)
{
	physdev_set_iopl_t set_iopl;
	set_iopl.iopl = 3;		/* user ring 3 */
	(void) HYPERVISOR_physdev_op(PHYSDEVOP_set_iopl, &set_iopl);
}

/*
 * Drop PS_IOPL on current vcpu to kernel level
 */
void
xen_disable_user_iopl(void)
{
	physdev_set_iopl_t set_iopl;
	set_iopl.iopl = 1;		/* kernel pseudo ring 1 */
	(void) HYPERVISOR_physdev_op(PHYSDEVOP_set_iopl, &set_iopl);
}

int
xen_gdt_setprot(cpu_t *cp, uint_t prot)
{
	int err;
#if defined(__amd64)
	int pt_bits = PT_VALID;
	if (prot & PROT_WRITE)
		pt_bits |= PT_WRITABLE;
#endif

	if ((err = as_setprot(&kas, (caddr_t)cp->cpu_gdt,
	    MMU_PAGESIZE, prot)) != 0)
		goto done;

#if defined(__amd64)
	err = xen_kpm_page(mmu_btop(cp->cpu_m.mcpu_gdtpa), pt_bits);
#endif

done:
	if (err) {
		cmn_err(CE_WARN, "cpu%d: xen_gdt_setprot(%s) failed: error %d",
		    cp->cpu_id, (prot & PROT_WRITE) ? "writable" : "read-only",
		    err);
	}

	return (err);
}

int
xen_ldt_setprot(user_desc_t *ldt, size_t lsize, uint_t prot)
{
	int err;
	caddr_t	lva = (caddr_t)ldt;
#if defined(__amd64)
	int pt_bits = PT_VALID;
	pgcnt_t npgs;
	if (prot & PROT_WRITE)
		pt_bits |= PT_WRITABLE;
#endif	/* __amd64 */

	if ((err = as_setprot(&kas, (caddr_t)ldt, lsize, prot)) != 0)
		goto done;

#if defined(__amd64)

	ASSERT(IS_P2ALIGNED(lsize, PAGESIZE));
	npgs = mmu_btop(lsize);
	while (npgs--) {
		if ((err = xen_kpm_page(hat_getpfnum(kas.a_hat, lva),
		    pt_bits)) != 0)
			break;
		lva += PAGESIZE;
	}
#endif	/* __amd64 */

done:
	if (err) {
		cmn_err(CE_WARN, "xen_ldt_setprot(%p, %s) failed: error %d",
		    (void *)lva,
		    (prot & PROT_WRITE) ? "writable" : "read-only", err);
	}

	return (err);
}

int
xen_get_mc_physcpuinfo(xen_mc_logical_cpu_t *log_cpus, uint_t *ncpus)
{
	xen_mc_t xmc;
	struct xen_mc_physcpuinfo *cpi = &xmc.u.mc_physcpuinfo;

	cpi->ncpus = *ncpus;
	/*LINTED: constant in conditional context*/
	set_xen_guest_handle(cpi->info, log_cpus);

	if (HYPERVISOR_mca(XEN_MC_physcpuinfo, &xmc) != 0)
		return (-1);

	*ncpus = cpi->ncpus;
	return (0);
}

void
print_panic(const char *str)
{
	xen_printf(str);
}

/*
 * Interfaces to iterate over real cpu information, but only that info
 * which we choose to expose here.  These are of interest to dom0
 * only (and the backing hypercall should not work for domu).
 */

xen_mc_lcpu_cookie_t
xen_physcpu_next(xen_mc_lcpu_cookie_t cookie)
{
	xen_mc_logical_cpu_t *xcp = (xen_mc_logical_cpu_t *)cookie;

	if (!DOMAIN_IS_INITDOMAIN(xen_info))
		return (NULL);

	if (cookie == NULL)
		return ((xen_mc_lcpu_cookie_t)xen_phys_cpus);

	if (xcp == xen_phys_cpus + xen_phys_ncpus - 1)
		return (NULL);
	else
		return ((xen_mc_lcpu_cookie_t)++xcp);
}

#define	COOKIE2XCP(c) ((xen_mc_logical_cpu_t *)(c))

const char *
xen_physcpu_vendorstr(xen_mc_lcpu_cookie_t cookie)
{
	xen_mc_logical_cpu_t *xcp = COOKIE2XCP(cookie);

	return ((const char *)&xcp->mc_vendorid[0]);
}

int
xen_physcpu_family(xen_mc_lcpu_cookie_t cookie)
{
	return (COOKIE2XCP(cookie)->mc_family);
}

int
xen_physcpu_model(xen_mc_lcpu_cookie_t cookie)
{
	return (COOKIE2XCP(cookie)->mc_model);
}

int
xen_physcpu_stepping(xen_mc_lcpu_cookie_t cookie)
{
	return (COOKIE2XCP(cookie)->mc_step);
}

id_t
xen_physcpu_chipid(xen_mc_lcpu_cookie_t cookie)
{
	return (COOKIE2XCP(cookie)->mc_chipid);
}

id_t
xen_physcpu_coreid(xen_mc_lcpu_cookie_t cookie)
{
	return (COOKIE2XCP(cookie)->mc_coreid);
}

id_t
xen_physcpu_strandid(xen_mc_lcpu_cookie_t cookie)
{
	return (COOKIE2XCP(cookie)->mc_threadid);
}

id_t
xen_physcpu_initial_apicid(xen_mc_lcpu_cookie_t cookie)
{
	return (COOKIE2XCP(cookie)->mc_clusterid);
}

id_t
xen_physcpu_logical_id(xen_mc_lcpu_cookie_t cookie)
{
	return (COOKIE2XCP(cookie)->mc_cpunr);
}

boolean_t
xen_physcpu_is_cmt(xen_mc_lcpu_cookie_t cookie)
{
	return (COOKIE2XCP(cookie)->mc_nthreads > 1);
}

uint64_t
xen_physcpu_mcg_cap(xen_mc_lcpu_cookie_t cookie)
{
	xen_mc_logical_cpu_t *xcp = COOKIE2XCP(cookie);

	/*
	 * Need to #define the indices, or search through the array.
	 */
	return (xcp->mc_msrvalues[0].value);
}

int
xen_map_gref(uint_t cmd, gnttab_map_grant_ref_t *mapop, uint_t count,
    boolean_t uvaddr)
{
	long rc;
	uint_t i;

	ASSERT(cmd == GNTTABOP_map_grant_ref);

#if !defined(_BOOT)
	if (uvaddr == B_FALSE) {
		for (i = 0; i < count; ++i) {
			mapop[i].flags |= (PT_FOREIGN <<_GNTMAP_guest_avail0);
		}
	}
#endif

	rc = HYPERVISOR_grant_table_op(cmd, mapop, count);

	return (rc);
}

static int
xpv_get_physinfo(xen_sysctl_physinfo_t *pi)
{
	xen_sysctl_t op;
	struct sp { void *p; } *sp = (struct sp *)&op.u.physinfo.cpu_to_node;
	int ret;

	bzero(&op, sizeof (op));
	op.cmd = XEN_SYSCTL_physinfo;
	op.interface_version = XEN_SYSCTL_INTERFACE_VERSION;
	/*LINTED: constant in conditional context*/
	set_xen_guest_handle(*sp, NULL);

	ret = HYPERVISOR_sysctl(&op);

	if (ret != 0)
		return (xen_xlate_errcode(ret));

	bcopy(&op.u.physinfo, pi, sizeof (op.u.physinfo));
	return (0);
}

/*
 * On dom0, we can determine the number of physical cpus on the machine.
 * This number is important when figuring out what workarounds are
 * appropriate, so compute it now.
 */
uint_t
xpv_nr_phys_cpus(void)
{
	static uint_t nphyscpus = 0;

	ASSERT(DOMAIN_IS_INITDOMAIN(xen_info));

	if (nphyscpus == 0) {
		xen_sysctl_physinfo_t pi;
		int ret;

		if ((ret = xpv_get_physinfo(&pi)) != 0)
			panic("xpv_get_physinfo() failed: %d\n", ret);
		nphyscpus = pi.nr_cpus;
	}
	return (nphyscpus);
}

pgcnt_t
xpv_nr_phys_pages(void)
{
	xen_sysctl_physinfo_t pi;
	int ret;

	ASSERT(DOMAIN_IS_INITDOMAIN(xen_info));

	if ((ret = xpv_get_physinfo(&pi)) != 0)
		panic("xpv_get_physinfo() failed: %d\n", ret);

	return ((pgcnt_t)pi.total_pages);
}

uint64_t
xpv_cpu_khz(void)
{
	xen_sysctl_physinfo_t pi;
	int ret;

	ASSERT(DOMAIN_IS_INITDOMAIN(xen_info));

	if ((ret = xpv_get_physinfo(&pi)) != 0)
		panic("xpv_get_physinfo() failed: %d\n", ret);
	return ((uint64_t)pi.cpu_khz);
}
