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
 * Copyright (c) 2014, Joyent, Inc. All rights reserved.
 */

#include <sys/types.h>
#include <sys/kmem.h>
#include <sys/errno.h>
#include <sys/thread.h>
#include <sys/systm.h>
#include <sys/syscall.h>
#include <sys/proc.h>
#include <sys/modctl.h>
#include <sys/cmn_err.h>
#include <sys/model.h>
#include <sys/exec.h>
#include <sys/lx_impl.h>
#include <sys/machbrand.h>
#include <sys/lx_syscalls.h>
#include <sys/lx_pid.h>
#include <sys/lx_futex.h>
#include <sys/lx_brand.h>
#include <sys/termios.h>
#include <sys/sunddi.h>
#include <sys/ddi.h>
#include <sys/vnode.h>
#include <sys/pathname.h>
#include <sys/auxv.h>
#include <sys/priv.h>
#include <sys/regset.h>
#include <sys/privregs.h>
#include <sys/archsystm.h>
#include <sys/zone.h>
#include <sys/brand.h>
#include <sys/sdt.h>
#include <lx_signum.h>

int	lx_debug = 0;

void	lx_init_brand_data(zone_t *);
void	lx_free_brand_data(zone_t *);
void	lx_setbrand(proc_t *);
int	lx_getattr(zone_t *, int, void *, size_t *);
int	lx_setattr(zone_t *, int, void *, size_t);
int	lx_brandsys(int, int64_t *, uintptr_t, uintptr_t, uintptr_t,
		uintptr_t, uintptr_t, uintptr_t);
void	lx_set_kern_version(zone_t *, char *);
void	lx_copy_procdata(proc_t *, proc_t *);

extern int getsetcontext(int, void *);

extern void lx_setrval(klwp_t *, int, int);
extern void lx_proc_exit(proc_t *, klwp_t *);
extern void lx_exec();
extern int lx_initlwp(klwp_t *);
extern void lx_forklwp(klwp_t *, klwp_t *);
extern void lx_exitlwp(klwp_t *);
extern void lx_freelwp(klwp_t *);
extern void lx_exit_with_sig(proc_t *, sigqueue_t *, void *);
static void lx_psig_to_proc(proc_t *, kthread_t *, int);
extern boolean_t lx_wait_filter(proc_t *, proc_t *);
extern greg_t lx_fixsegreg(greg_t, model_t);
extern int lx_sched_affinity(int, uintptr_t, int, uintptr_t, int64_t *);

int lx_systrace_brand_enabled;

lx_systrace_f *lx_systrace_entry_ptr;
lx_systrace_f *lx_systrace_return_ptr;

static int lx_systrace_enabled;

static int lx_elfexec(struct vnode *vp, struct execa *uap, struct uarg *args,
    struct intpdata *idata, int level, long *execsz, int setid,
    caddr_t exec_file, struct cred *cred, int brand_action);

static boolean_t lx_native_exec(uint8_t, const char **);

/* lx brand */
struct brand_ops lx_brops = {
	lx_init_brand_data,
	lx_free_brand_data,
	lx_brandsys,
	lx_setbrand,
	lx_getattr,
	lx_setattr,
	lx_copy_procdata,
	lx_proc_exit,
	lx_exec,
	lx_setrval,
	lx_initlwp,
	lx_forklwp,
	lx_freelwp,
	lx_exitlwp,
	lx_elfexec,
	NULL,
	NULL,
	lx_psig_to_proc,
	NSIG,
	lx_exit_with_sig,
	lx_wait_filter,
	lx_native_exec
};

struct brand_mach_ops lx_mops = {
	NULL,
	lx_brand_int80_callback,	/* 32-bit Linux entry point */
	NULL,
	lx_brand_syscall_callback,	/* 64-bit common entry point */
	NULL,
	lx_fixsegreg,
};

struct brand lx_brand = {
	BRAND_VER_1,
	"lx",
	&lx_brops,
	&lx_mops,
	sizeof (struct lx_proc_data)
};

static struct modlbrand modlbrand = {
	&mod_brandops, "lx brand", &lx_brand
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modlbrand, NULL
};

void
lx_proc_exit(proc_t *p, klwp_t *lwp)
{
	zone_t *z = p->p_zone;
	int sig = ptolxproc(p)->l_signal;

	ASSERT(p->p_brand != NULL);
	ASSERT(p->p_brand_data != NULL);

	/*
	 * If init is dying and we aren't explicitly shutting down the zone
	 * or the system, then Solaris is about to restart init.  The Linux
	 * init is not designed to handle a restart, which it interprets as
	 * a reboot.  To give it a sane environment in which to run, we
	 * reboot the zone.
	 */
	if (p->p_pid == z->zone_proc_initpid) {
		if (z->zone_boot_err == 0 &&
		    z->zone_restart_init &&
		    zone_status_get(z) < ZONE_IS_SHUTTING_DOWN &&
		    zone_status_get(global_zone) < ZONE_IS_SHUTTING_DOWN)
			(void) zone_kadmin(A_REBOOT, 0, NULL, CRED());
	}

	/*
	 * We might get here if fork failed (e.g. ENOMEM) so we don't always
	 * have an lwp (see brand_clearbrand).
	 */
	if (lwp != NULL)
		lx_exitlwp(lwp);
	p->p_exit_data = sig;
}

void
lx_setbrand(proc_t *p)
{
	kthread_t *t = p->p_tlist;
	int err;

	ASSERT(p->p_brand_data == NULL);
	ASSERT(ttolxlwp(curthread) == NULL);

	p->p_brand_data = kmem_zalloc(sizeof (struct lx_proc_data), KM_SLEEP);
	ptolxproc(p)->l_signal = stol_signo[SIGCHLD];

	/*
	 * This routine can only be called for single-threaded processes.
	 * Since lx_initlwp() can only fail if we run out of PIDs for
	 * multithreaded processes, we know that this can never fail.
	 */
	err = lx_initlwp(t->t_lwp);
	ASSERT(err == 0);
}

/* ARGSUSED */
int
lx_setattr(zone_t *zone, int attr, void *buf, size_t bufsize)
{
	boolean_t val;
	char vers[LX_VERS_MAX];

	if (attr == LX_ATTR_RESTART_INIT) {
		if (bufsize > sizeof (boolean_t))
			return (ERANGE);
		if (copyin(buf, &val, sizeof (val)) != 0)
			return (EFAULT);
		if (val != B_TRUE && val != B_FALSE)
			return (EINVAL);
		zone->zone_restart_init = val;
		return (0);
	} else if (attr == LX_KERN_VERSION_NUM) {
		if (bufsize > (LX_VERS_MAX - 1))
			return (ERANGE);
		bzero(vers, LX_VERS_MAX);
		if (copyin(buf, &vers, bufsize) != 0)
			return (EFAULT);
		lx_set_kern_version(zone, vers);
		return (0);
	}
	return (EINVAL);
}

/* ARGSUSED */
int
lx_getattr(zone_t *zone, int attr, void *buf, size_t *bufsize)
{
	if (attr == LX_ATTR_RESTART_INIT) {
		if (*bufsize < sizeof (boolean_t))
			return (ERANGE);
		if (copyout(&zone->zone_restart_init, buf,
		    sizeof (boolean_t)) != 0)
			return (EFAULT);
		*bufsize = sizeof (boolean_t);
		return (0);
	} else if (attr == LX_KERN_VERSION_NUM) {
		if (*bufsize < LX_VERS_MAX)
			return (ERANGE);
		if (copyout(lx_get_zone_kern_version(curzone), buf,
		    LX_VERS_MAX) != 0)
			return (EFAULT);
		*bufsize = LX_VERS_MAX;
		return (0);
	}
	return (-EINVAL);
}

/*
 * Enable ptrace system call tracing for the given LWP. This is done by
 * both setting the flag in that LWP's brand data (in the kernel) and setting
 * the process-wide trace flag (in the brand library of the traced process).
 */
static int
lx_ptrace_syscall_set(pid_t pid, id_t lwpid, int set)
{
	proc_t *p;
	kthread_t *t;
	klwp_t *lwp;
	lx_proc_data_t *lpdp;
	lx_lwp_data_t *lldp;
	uintptr_t addr;
	int ret, flag = 1;

	if ((p = sprlock(pid)) == NULL)
		return (ESRCH);

	if (priv_proc_cred_perm(curproc->p_cred, p, NULL, VWRITE) != 0) {
		sprunlock(p);
		return (EPERM);
	}

	if ((t = idtot(p, lwpid)) == NULL || (lwp = ttolwp(t)) == NULL) {
		sprunlock(p);
		return (ESRCH);
	}

	if ((lpdp = p->p_brand_data) == NULL ||
	    (lldp = lwp->lwp_brand) == NULL) {
		sprunlock(p);
		return (ESRCH);
	}

	if (set) {
		/*
		 * Enable the ptrace flag for this LWP and this process. Note
		 * that we will turn off the LWP's ptrace flag, but we don't
		 * turn off the process's ptrace flag.
		 */
		lldp->br_ptrace = 1;
		lpdp->l_ptrace = 1;

		addr = lpdp->l_traceflag;

		mutex_exit(&p->p_lock);

		/*
		 * This can fail only in some rare corner cases where the
		 * process is exiting or we're completely out of memory. In
		 * these cases, it's sufficient to return an error to the ptrace
		 * consumer and leave the process-wide flag set.
		 */
		ret = uwrite(p, &flag, sizeof (flag), addr);

		mutex_enter(&p->p_lock);

		/*
		 * If we couldn't set the trace flag, unset the LWP's ptrace
		 * flag as there ptrace consumer won't expect this LWP to stop.
		 */
		if (ret != 0)
			lldp->br_ptrace = 0;
	} else {
		lldp->br_ptrace = 0;
		ret = 0;
	}

	sprunlock(p);

	if (ret != 0)
		ret = EIO;

	return (ret);
}

static void
lx_ptrace_fire(void)
{
	kthread_t *t = curthread;
	klwp_t *lwp = ttolwp(t);
	lx_lwp_data_t *lldp = lwp->lwp_brand;

	/*
	 * The ptrace flag only applies until the next event is encountered
	 * for the given LWP. If it's set, turn off the flag and poke the
	 * controlling process by raising a signal.
	 */
	if (lldp->br_ptrace) {
		lldp->br_ptrace = 0;
		tsignal(t, SIGTRAP);
	}
}

/*
 * Supports Linux PTRACE_SETOPTIONS handling which is similar to PTRACE_TRACEME
 * but return an event in the second byte of si_status.
 */
static int
lx_ptrace_ext_opts(int cmd, pid_t pid, uintptr_t val, int64_t *rval)
{
	proc_t *p;
	lx_proc_data_t *lpdp;
	uint_t ret;

	if (cmd != B_PTRACE_EXT_OPTS_SET && cmd != B_PTRACE_EXT_OPTS_GET &&
	    cmd != B_PTRACE_EXT_OPTS_EVT)
		return (set_errno(EINVAL));

	if ((p = sprlock(pid)) == NULL)
		return (ESRCH);

	if (priv_proc_cred_perm(curproc->p_cred, p, NULL, VWRITE) != 0) {
		sprunlock(p);
		return (EPERM);
	}

	if ((lpdp = p->p_brand_data) == NULL) {
		sprunlock(p);
		return (ESRCH);
	}

	if (cmd == B_PTRACE_EXT_OPTS_SET) {
		lpdp->l_ptrace_opts = (uint_t)val;

	} else if (cmd == B_PTRACE_EXT_OPTS_GET) {
		ret = lpdp->l_ptrace_opts;

	} else /* B_PTRACE_EXT_OPTS_EVT */ {
		ret = lpdp->l_ptrace_event;
		lpdp->l_ptrace_event = 0;
	}

	sprunlock(p);

	if (cmd != B_PTRACE_EXT_OPTS_SET) {
		if (copyout(&ret, (void *)val, sizeof (uint_t)) != 0)
			return (EFAULT);
	}

	*rval = 0;
	return (0);
}

/*
 * Used to support Linux PTRACE_SETOPTIONS handling and similar to
 * PTRACE_TRACEME. We signal ourselves to stop on return from this syscall and
 * setup the event reason so the emulation can pull this out when someone
 * 'waits' on this process.
 */
static void
lx_ptrace_stop_for_option(int option)
{
	proc_t *p = ttoproc(curthread);
	sigqueue_t *sqp;
	lx_proc_data_t *lpdp;

	if ((lpdp = p->p_brand_data) == NULL) {
		/* this should never happen but just to be safe */
		return;
	}

	/* Track the event as the reason for stopping */
	switch (option) {
	case LX_PTRACE_O_TRACEFORK:
		lpdp->l_ptrace_event = LX_PTRACE_EVENT_FORK;
		break;
	case LX_PTRACE_O_TRACEVFORK:
		lpdp->l_ptrace_event = LX_PTRACE_EVENT_VFORK;
		break;
	case LX_PTRACE_O_TRACECLONE:
		lpdp->l_ptrace_event = LX_PTRACE_EVENT_CLONE;
		break;
	case LX_PTRACE_O_TRACEEXEC:
		lpdp->l_ptrace_event = LX_PTRACE_EVENT_EXEC;
		break;
	case LX_PTRACE_O_TRACEVFORKDONE:
		lpdp->l_ptrace_event = LX_PTRACE_EVENT_VFORK_DONE;
		break;
	case LX_PTRACE_O_TRACEEXIT:
		lpdp->l_ptrace_event = LX_PTRACE_EVENT_EXIT;
		break;
	case LX_PTRACE_O_TRACESECCOMP:
		lpdp->l_ptrace_event = LX_PTRACE_EVENT_SECCOMP;
		break;
	}

	/* Post the required signal to ourselves so that we stop. */
	psignal(p, SIGTRAP);

	/*
	 * Since we're stopping, we need to post the SIGCHLD to the parent.
	 * The code in sigcld expects the following two process values to be
	 * setup specifically before it can send the signal, so do that here.
	 */
	sqp = kmem_zalloc(sizeof (sigqueue_t), KM_SLEEP);
	mutex_enter(&pidlock);
	p->p_wdata = SIGTRAP;
	p->p_wcode = CLD_STOPPED;
	sigcld(p, sqp);
	mutex_exit(&pidlock);

	/*
	 * If (p_proc_flag & P_PR_PTRACE) were set, then in stop() we would set:
	 *	p->p_wcode = CLD_TRAPPED
	 *	p->p_wdata = SIGTRAP
	 * However, when using the extended ptrace options we disable
	 * P_PR_PTRACE so that we don't stop twice on exec when
	 * LX_PTRACE_O_TRACEEXEC is set. We could ensure P_PR_PTRACE is set
	 * when using extended options but then we would stop on exec even when
	 * LX_PTRACE_O_TRACEEXEC is not set, so that is clearly broken. Thus,
	 * we have to set p_wcode and p_wdata ourselves so that waitid will
	 * do the right thing for this process. We still rely on stop() to do
	 * all of the other processing needed for our signal.
	 */
	p->p_wcode = CLD_TRAPPED;
}

void
lx_brand_systrace_enable(void)
{
	extern void lx_brand_int80_enable(void);

	ASSERT(!lx_systrace_enabled);

#if defined(__amd64)
	/* enable the trace points for both 32-bit and 64-bit lx calls */
	extern void lx_brand_syscall_enable(void);
	lx_brand_syscall_enable();
	lx_brand_int80_enable();
#else
	lx_brand_int80_enable();
#endif

	lx_systrace_enabled = 1;
}

void
lx_brand_systrace_disable(void)
{
	extern void lx_brand_int80_disable(void);

	ASSERT(lx_systrace_enabled);

#if defined(__amd64)
	/* disable the trace points for both 32-bit and 64-bit lx calls */
	extern void lx_brand_syscall_disable(void);
	lx_brand_syscall_disable();
	lx_brand_int80_disable();
#else
	lx_brand_int80_disable();
#endif

	lx_systrace_enabled = 0;
}

/*
 * Posting a signal to a proc/thread, switch to native syscall mode.
 * See the comment on lwp_segregs_save() for how we handle the user-land
 * registers when we come into the kernel and see update_sregs() for how we
 * restore.
 */
/*ARGSUSED*/
static void
lx_psig_to_proc(proc_t *p, kthread_t *t, int sig)
{
	lx_lwp_data_t *lwpd = ttolxlwp(t);
#if defined(__amd64)
	klwp_t *lwp = ttolwp(t);
	model_t datamodel;
	struct regs *rp;

	datamodel = lwp_getdatamodel(lwp);
	if (datamodel == DATAMODEL_NATIVE) {
		rp = lwptoregs(lwp);

		if (rp->r_gs != 0)
			cmn_err(CE_WARN, "lx_psig_to_proc: non-zero %%gs");

		/*
		 * XXX sometimes pcb_gs?
		 */
		rp->r_gs = lwpd->br_libc_syscall;
	}
#endif

	lwpd->br_libc_syscall = 1;
}

void
lx_init_brand_data(zone_t *zone)
{
	lx_zone_data_t *data;
	ASSERT(zone->zone_brand == &lx_brand);
	ASSERT(zone->zone_brand_data == NULL);
	data = (lx_zone_data_t *)kmem_zalloc(sizeof (lx_zone_data_t), KM_SLEEP);
	/*
	 * Set the default lxzd_kernel_version to 2.4.
	 * This can be changed by a call to setattr() during zone boot.
	 */
	(void) strlcpy(data->lxzd_kernel_version, "2.4.21", LX_VERS_MAX);
	data->lxzd_max_syscall = LX_NSYSCALLS;
	zone->zone_brand_data = data;
}

void
lx_free_brand_data(zone_t *zone)
{
	kmem_free(zone->zone_brand_data, sizeof (lx_zone_data_t));
}

void
lx_unsupported(char *dmsg)
{
	DTRACE_PROBE1(brand__lx__unsupported, char *, dmsg);
}

/*
 * Get the addresses of the user-space system call handler and attach it to
 * the proc structure. Returning 0 indicates success; the value returned
 * by the system call is the value stored in rval. Returning a non-zero
 * value indicates a failure; the value returned is used to set errno, -1
 * is returned from the syscall and the contents of rval are ignored. To
 * set errno and have the syscall return a value other than -1 we can
 * manually set errno and rval and return 0.
 */
int
lx_brandsys(int cmd, int64_t *rval, uintptr_t arg1, uintptr_t arg2,
    uintptr_t arg3, uintptr_t arg4, uintptr_t arg5, uintptr_t arg6)
{
	kthread_t *t = curthread;
	proc_t *p = ttoproc(t);
	lx_proc_data_t *pd;
	int ike_call;
	struct termios *termios;
	uint_t termios_len;
	int error;
	lx_brand_registration_t reg;
	lx_lwp_data_t *lwpd;

	/*
	 * There is one operation that is suppored for non-branded
	 * process.  B_EXEC_BRAND.  This is the equilivant of an
	 * exec call, but the new process that is created will be
	 * a branded process.
	 */
	if (cmd == B_EXEC_BRAND) {
		ASSERT(p->p_zone != NULL);
		ASSERT(p->p_zone->zone_brand == &lx_brand);
		return (exec_common(
		    (char *)arg1, (const char **)arg2, (const char **)arg3,
		    EBA_BRAND));
	}

	/* For all other operations this must be a branded process. */
	if (p->p_brand == NULL)
		return (set_errno(ENOSYS));

	ASSERT(p->p_brand == &lx_brand);
	ASSERT(p->p_brand_data != NULL);

	switch (cmd) {
	case B_REGISTER:
		if (p->p_model == DATAMODEL_NATIVE) {
			if (copyin((void *)arg1, &reg, sizeof (reg)) != 0) {
				lx_print("Failed to copyin brand registration "
				    "at 0x%p\n", (void *)arg1);
				return (EFAULT);
			}
		}
#ifdef _LP64
		else {
			/* 32-bit userland on 64-bit kernel */
			lx_brand_registration32_t reg32;

			if (copyin((void *)arg1, &reg32, sizeof (reg32)) != 0) {
				lx_print("Failed to copyin brand registration "
				    "at 0x%p\n", (void *)arg1);
				return (EFAULT);
			}

			reg.lxbr_version = (uint_t)reg32.lxbr_version;
			reg.lxbr_handler =
			    (void *)(uintptr_t)reg32.lxbr_handler;
			reg.lxbr_tracehandler =
			    (void *)(uintptr_t)reg32.lxbr_tracehandler;
			reg.lxbr_traceflag =
			    (void *)(uintptr_t)reg32.lxbr_traceflag;
		}
#endif

		if (reg.lxbr_version != LX_VERSION_1) {
			lx_print("Invalid brand library version (%u)\n",
			    reg.lxbr_version);
			return (EINVAL);
		}

		lx_print("Assigning brand 0x%p and handler 0x%p to proc 0x%p\n",
		    (void *)&lx_brand, (void *)reg.lxbr_handler, (void *)p);
		pd = p->p_brand_data;
		pd->l_handler = (uintptr_t)reg.lxbr_handler;
		pd->l_tracehandler = (uintptr_t)reg.lxbr_tracehandler;
		pd->l_traceflag = (uintptr_t)reg.lxbr_traceflag;

		/*
		 * When we register, start with native syscalls enabled so that
		 * lx_init can finish initialization before switch to Linux
		 * syscall mode.
		 */
		lwpd = ttolxlwp(t);
		lwpd->br_libc_syscall = 1;

		*rval = 0;
		return (0);
	case B_TTYMODES:
		/* This is necessary for emulating TCGETS ioctls. */
		if (ddi_prop_lookup_byte_array(DDI_DEV_T_ANY, ddi_root_node(),
		    DDI_PROP_NOTPROM, "ttymodes", (uchar_t **)&termios,
		    &termios_len) != DDI_SUCCESS)
			return (EIO);

		ASSERT(termios_len == sizeof (*termios));

		if (copyout(&termios, (void *)arg1, sizeof (termios)) != 0) {
			ddi_prop_free(termios);
			return (EFAULT);
		}

		ddi_prop_free(termios);
		*rval = 0;
		return (0);

	case B_ELFDATA:
		pd = curproc->p_brand_data;
		if (get_udatamodel() == DATAMODEL_NATIVE) {
			if (copyout(&pd->l_elf_data, (void *)arg1,
			    sizeof (lx_elf_data_t)) != 0) {
				(void) set_errno(EFAULT);
				return (*rval = -1);
			}
		}
#if defined(_LP64)
		else {
			/* 32-bit userland on 64-bit kernel */
			lx_elf_data32_t led32;

			led32.ed_phdr = (int)pd->l_elf_data.ed_phdr;
			led32.ed_phent = (int)pd->l_elf_data.ed_phent;
			led32.ed_phnum = (int)pd->l_elf_data.ed_phnum;
			led32.ed_entry = (int)pd->l_elf_data.ed_entry;
			led32.ed_base = (int)pd->l_elf_data.ed_base;
			led32.ed_ldentry = (int)pd->l_elf_data.ed_ldentry;

			if (copyout(&led32, (void *)arg1,
			    sizeof (led32)) != 0) {
				(void) set_errno(EFAULT);
				return (*rval = -1);
			}
		}
#endif
		*rval = 0;
		return (0);

	case B_EXEC_NATIVE:
		error = exec_common(
		    (char *)arg1, (const char **)arg2, (const char **)arg3,
		    EBA_NATIVE);
		if (error) {
			(void) set_errno(error);
			return (*rval = -1);
		}
		return (*rval = 0);

	/*
	 * The B_TRUSS_POINT subcommand is used so that we can make a no-op
	 * syscall for debugging purposes (dtracing) from within the user-level
	 * emulation.
	 */
	case B_TRUSS_POINT:
		*rval = 0;
		return (0);

	case B_LPID_TO_SPAIR:
		/*
		 * Given a Linux pid as arg1, return the Solaris pid in arg2 and
		 * the Solaris LWP in arg3.  We also translate pid 1 (which is
		 * hardcoded in many applications) to the zone's init process.
		 */
		{
			pid_t s_pid;
			id_t s_tid;

			if ((pid_t)arg1 == 1) {
				s_pid = p->p_zone->zone_proc_initpid;
				/* handle the dead/missing init(1M) case */
				if (s_pid == -1)
					s_pid = 1;
				s_tid = 1;
			} else if (lx_lpid_to_spair((pid_t)arg1, &s_pid,
			    &s_tid) < 0)
				return (ESRCH);

			if (copyout(&s_pid, (void *)arg2,
			    sizeof (s_pid)) != 0 ||
			    copyout(&s_tid, (void *)arg3, sizeof (s_tid)) != 0)
				return (EFAULT);

			*rval = 0;
			return (0);
		}

	case B_PTRACE_SYSCALL:
		*rval = lx_ptrace_syscall_set((pid_t)arg1, (id_t)arg2,
		    (int)arg3);
		return (0);

	case B_SYSENTRY:
		if (lx_systrace_enabled) {
			uintptr_t args[6];

			ASSERT(lx_systrace_entry_ptr != NULL);

			if (copyin((void *)arg2, args, sizeof (args)) != 0)
				return (EFAULT);

			(*lx_systrace_entry_ptr)(arg1, args[0], args[1],
			    args[2], args[3], args[4], args[5]);
		}

		lx_ptrace_fire();

		pd = p->p_brand_data;

		/*
		 * If neither DTrace not ptrace are interested in tracing
		 * this process any more, turn off the trace flag.
		 */
		if (!lx_systrace_enabled && !pd->l_ptrace)
			(void) suword32((void *)pd->l_traceflag, 0);

		*rval = 0;
		return (0);

	case B_SYSRETURN:
		if (lx_systrace_enabled) {
			ASSERT(lx_systrace_return_ptr != NULL);

			(*lx_systrace_return_ptr)(arg1, arg2, arg2, 0, 0, 0, 0);
		}

		lx_ptrace_fire();

		pd = p->p_brand_data;

		/*
		 * If neither DTrace not ptrace are interested in tracing
		 * this process any more, turn off the trace flag.
		 */
		if (!lx_systrace_enabled && !pd->l_ptrace)
			(void) suword32((void *)pd->l_traceflag, 0);

		*rval = 0;
		return (0);

	case B_SET_AFFINITY_MASK:
	case B_GET_AFFINITY_MASK:
		/*
		 * Retrieve or store the CPU affinity mask for the
		 * requested linux pid.
		 *
		 * arg1 is a linux PID (0 means curthread).
		 * arg2 is the size of the given mask.
		 * arg3 is the address of the affinity mask.
		 */
		return (lx_sched_affinity(cmd, arg1, arg2, arg3, rval));

	case B_PTRACE_EXT_OPTS:
		/*
		 * Set or get the ptrace extended options or get the event
		 * reason for the stop.
		 */
		return (lx_ptrace_ext_opts((int)arg1, (pid_t)arg2, arg3, rval));

	case B_PTRACE_STOP_FOR_OPT:
		lx_ptrace_stop_for_option((int)arg1);
		return (0);

	case B_UNSUPPORTED:
		{
		char dmsg[256];

		if (copyin((void *)arg1, &dmsg, sizeof (dmsg)) != 0) {
			lx_print("Failed to copyin unsupported msg "
			    "at 0x%p\n", (void *)arg1);
			return (EFAULT);
		}
		dmsg[255] = '\0';
		lx_unsupported(dmsg);
		}

		return (0);

	case B_STORE_ARGS:
		/*
		 * B_STORE_ARGS subcommand
		 * arg1 = address of struct to be copied in
		 * arg2 = size of the struct being copied in
		 * arg3-arg6 ignored
		 * rval = the amount of data copied.
		 */
		{
			int err;
			void *buf;

			lwpd = ttolxlwp(curthread);
			/* only have upper limit because arg2 is unsigned */
			if (arg2 > LX_BR_ARGS_SIZE_MAX) {
				return (EINVAL);
			}

			buf = kmem_alloc(arg2, KM_SLEEP);
			if ((err = copyin((void *)arg1, buf, arg2)) != 0) {
				lx_print("Failed to copyin scall arg at 0x%p\n",
				    (void *) arg1);
				kmem_free(buf, arg2);
				/*
				 * Purposely not setting br_scall_args to NULL
				 * to preserve data for debugging.
				 */
				return (EFAULT);
			}

			if (lwpd->br_scall_args != NULL) {
				ASSERT(lwpd->br_args_size > 0);
				kmem_free(lwpd->br_scall_args,
				    lwpd->br_args_size);
			}

			lwpd->br_scall_args = buf;
			lwpd->br_args_size = arg2;
			*rval = arg2;
			return (0);
		}

	case B_CLR_NTV_SYSC_FLAG:
		lwpd = ttolxlwp(curthread);
		lwpd->br_libc_syscall = 0;
		return (0);

	case B_SIGNAL_RETURN:
		/*
		 * Set the syscall mode and do the setcontext syscall.
		 * arg1 = mode
		 * arg2 = ucontext_t pointer
		 */
		lwpd = ttolxlwp(curthread);
		lwpd->br_libc_syscall = arg1;
		return (getsetcontext(SETCONTEXT, (void *)arg2));

	default:
		ike_call = cmd - B_IKE_SYSCALL;
		if (ike_call > 0 && ike_call <= LX_N_IKE_FUNCS) {
			*rval = lx_emulate_syscall(ike_call, arg1, arg2,
			    arg3, arg4, arg5, arg6);
			return (0);
		}
	}

	return (EINVAL);
}

char *
lx_get_zone_kern_version(zone_t *zone)
{
	return (((lx_zone_data_t *)zone->zone_brand_data)->lxzd_kernel_version);
}

void
lx_set_kern_version(zone_t *zone, char *vers)
{
	lx_zone_data_t *lxzd = (lx_zone_data_t *)zone->zone_brand_data;

	(void) strlcpy(lxzd->lxzd_kernel_version, vers, LX_VERS_MAX);
}

/*
 * Copy the per-process brand data from a parent proc to a child.
 */
void
lx_copy_procdata(proc_t *child, proc_t *parent)
{
	lx_proc_data_t *cpd, *ppd;

	ppd = parent->p_brand_data;

	ASSERT(ppd != NULL);

	cpd = kmem_alloc(sizeof (lx_proc_data_t), KM_SLEEP);
	*cpd = *ppd;

	child->p_brand_data = cpd;
}

#if defined(_LP64)
static void
Ehdr32to64(Elf32_Ehdr *src, Ehdr *dst)
{
	bcopy(src->e_ident, dst->e_ident, sizeof (src->e_ident));
	dst->e_type =		src->e_type;
	dst->e_machine =	src->e_machine;
	dst->e_version =	src->e_version;
	dst->e_entry =		src->e_entry;
	dst->e_phoff =		src->e_phoff;
	dst->e_shoff =		src->e_shoff;
	dst->e_flags =		src->e_flags;
	dst->e_ehsize =		src->e_ehsize;
	dst->e_phentsize =	src->e_phentsize;
	dst->e_phnum =		src->e_phnum;
	dst->e_shentsize =	src->e_shentsize;
	dst->e_shnum =		src->e_shnum;
	dst->e_shstrndx =	src->e_shstrndx;
}
#endif /* _LP64 */

static void
restoreexecenv(struct execenv *ep, stack_t *sp)
{
	klwp_t *lwp = ttolwp(curthread);

	setexecenv(ep);
	lwp->lwp_sigaltstack.ss_sp = sp->ss_sp;
	lwp->lwp_sigaltstack.ss_size = sp->ss_size;
	lwp->lwp_sigaltstack.ss_flags = sp->ss_flags;
}

extern int elfexec(vnode_t *, execa_t *, uarg_t *, intpdata_t *, int,
    long *, int, caddr_t, cred_t *, int);

extern int elf32exec(struct vnode *, execa_t *, uarg_t *, intpdata_t *, int,
    long *, int, caddr_t, cred_t *, int);

/*
 * Exec routine called by elfexec() to load either 32-bit or 64-bit Linux
 * binaries.
 */
static int
lx_elfexec(struct vnode *vp, struct execa *uap, struct uarg *args,
    struct intpdata *idata, int level, long *execsz, int setid,
    caddr_t exec_file, struct cred *cred, int brand_action)
{
	int		error;
	vnode_t		*nvp;
	Ehdr		ehdr;
	Addr		uphdr_vaddr;
	intptr_t	voffset;
	int		interp;
	uintptr_t	ldaddr = NULL;
	int		i;
	proc_t		*p = ttoproc(curthread);
	klwp_t		*lwp = ttolwp(curthread);
	struct execenv	env;
	struct execenv	origenv;
	stack_t		orig_sigaltstack;
	struct user	*up = PTOU(ttoproc(curthread));
	lx_elf_data_t	*edp =
	    &((lx_proc_data_t *)ttoproc(curthread)->p_brand_data)->l_elf_data;
	char		*lib_path = NULL;
	char		*lx_linker_path = NULL;

	ASSERT(ttoproc(curthread)->p_brand == &lx_brand);
	ASSERT(ttoproc(curthread)->p_brand_data != NULL);

	if (args->to_model == DATAMODEL_NATIVE) {
		lib_path = LX_LIB_PATH;
		lx_linker_path = LX_LINKER;
	}
#if defined(_LP64)
	else {
		lib_path = LX_LIB_PATH32;
		lx_linker_path = LX_LINKER32;
	}
#endif

	/*
	 * Set the brandname and library name for the new process so that
	 * elfexec() puts them onto the stack.
	 */
	args->brandname = LX_BRANDNAME;
	args->emulator = lib_path;

	/*
	 * We will first exec the brand library, then map in the linux
	 * executable and the linux linker.
	 */
	if ((error = lookupname(lib_path, UIO_SYSSPACE, FOLLOW, NULLVPP,
	    &nvp))) {
		uprintf("%s: not found.", lib_path);
		return (error);
	}

	/*
	 * We will eventually set the p_exec member to be the vnode for the new
	 * executable when we call setexecenv(). However, if we get an error
	 * before that call we need to restore the execenv to its original
	 * values so that when we return to the caller fop_close() works
	 * properly while cleaning up from the failed exec().  Restoring the
	 * original value will also properly decrement the 2nd VN_RELE that we
	 * took on the brand library.
	 */
	origenv.ex_bssbase = p->p_bssbase;
	origenv.ex_brkbase = p->p_brkbase;
	origenv.ex_brksize = p->p_brksize;
	origenv.ex_vp = p->p_exec;
	orig_sigaltstack.ss_sp = lwp->lwp_sigaltstack.ss_sp;
	orig_sigaltstack.ss_size = lwp->lwp_sigaltstack.ss_size;
	orig_sigaltstack.ss_flags = lwp->lwp_sigaltstack.ss_flags;

	if (args->to_model == DATAMODEL_NATIVE) {
		error = elfexec(nvp, uap, args, idata, level + 1, execsz,
		    setid, exec_file, cred, brand_action);
	}
#if defined(_LP64)
	else {
		error = elf32exec(nvp, uap, args, idata, level + 1, execsz,
		    setid, exec_file, cred, brand_action);
	}
#endif
	VN_RELE(nvp);
	if (error != 0) {
		restoreexecenv(&origenv, &orig_sigaltstack);
		return (error);
	}

	/*
	 * exec-ed in the brand library above.
	 * The u_auxv vectors are now setup by elfexec to point to the
	 * brand emulation library and its linker.
	 */

	bzero(&env, sizeof (env));

	/*
	 * map in the the Linux executable
	 */
	if (args->to_model == DATAMODEL_NATIVE) {
		error = mapexec_brand(vp, args, &ehdr, &uphdr_vaddr,
		    &voffset, exec_file, &interp, &env.ex_bssbase,
		    &env.ex_brkbase, &env.ex_brksize, NULL, NULL);
	}
#if defined(_LP64)
	else {
		Elf32_Ehdr	ehdr32;
		Elf32_Addr	uphdr_vaddr32;

		error = mapexec32_brand(vp, args, &ehdr32, &uphdr_vaddr32,
		    &voffset, exec_file, &interp, &env.ex_bssbase,
		    &env.ex_brkbase, &env.ex_brksize, NULL, NULL);

		Ehdr32to64(&ehdr32, &ehdr);

		if (uphdr_vaddr32 == (Elf32_Addr)-1)
			uphdr_vaddr = (Addr)-1;
		else
			uphdr_vaddr = uphdr_vaddr32;
	}
#endif
	if (error != 0) {
		restoreexecenv(&origenv, &orig_sigaltstack);
		return (error);
	}

	/*
	 * Save off the important properties of the lx executable. The brand
	 * library will ask us for this data later, when it is ready to set
	 * things up for the lx executable.
	 */
	edp->ed_phdr = (uphdr_vaddr == -1) ? voffset + ehdr.e_phoff :
	    voffset + uphdr_vaddr;
	edp->ed_entry = voffset + ehdr.e_entry;
	edp->ed_phent = ehdr.e_phentsize;
	edp->ed_phnum = ehdr.e_phnum;

	if (interp) {
		if (ehdr.e_type == ET_DYN) {
			/*
			 * This is a shared object executable, so we need to
			 * pick a reasonable place to put the heap. Just don't
			 * use the first page.
			 */
			env.ex_brkbase = (caddr_t)PAGESIZE;
			env.ex_bssbase = (caddr_t)PAGESIZE;
		}

		/*
		 * If the program needs an interpreter (most do), map it in and
		 * store relevant information about it in the aux vector, where
		 * the brand library can find it.
		 */
		if ((error = lookupname(lx_linker_path, UIO_SYSSPACE, FOLLOW,
		    NULLVPP, &nvp))) {
			uprintf("%s: not found.", lx_linker_path);
			restoreexecenv(&origenv, &orig_sigaltstack);
			return (error);
		}

		/*
		 * map in the Linux linker
		 */
		if (args->to_model == DATAMODEL_NATIVE) {
			error = mapexec_brand(nvp, args, &ehdr,
			    &uphdr_vaddr, &voffset, exec_file, &interp, NULL,
			    NULL, NULL, NULL, &ldaddr);
		}
#if defined(_LP64)
		else {
			Elf32_Ehdr	ehdr32;
			Elf32_Addr	uphdr_vaddr32;

			error = mapexec32_brand(nvp, args, &ehdr32,
			    &uphdr_vaddr32, &voffset, exec_file, &interp, NULL,
			    NULL, NULL, NULL, &ldaddr);

			Ehdr32to64(&ehdr32, &ehdr);

			if (uphdr_vaddr32 == (Elf32_Addr)-1)
				uphdr_vaddr = (Addr)-1;
			else
				uphdr_vaddr = uphdr_vaddr32;
		}
#endif

		VN_RELE(nvp);
		if (error != 0) {
			restoreexecenv(&origenv, &orig_sigaltstack);
			return (error);
		}

		/*
		 * Now that we know the base address of the brand's linker,
		 * we also save this for later use by the brand library.
		 */
		edp->ed_base = voffset;
		edp->ed_ldentry = voffset + ehdr.e_entry;
	} else {
		/*
		 * This program has no interpreter. The lx brand library will
		 * jump to the address in the AT_SUN_BRAND_LDENTRY aux vector,
		 * so in this case, put the entry point of the main executable
		 * there.
		 */
		if (ehdr.e_type == ET_EXEC) {
			/*
			 * An executable with no interpreter, this must be a
			 * statically linked executable, which means we loaded
			 * it at the address specified in the elf header, in
			 * which case the e_entry field of the elf header is an
			 * absolute address.
			 */
			edp->ed_ldentry = ehdr.e_entry;
			edp->ed_entry = ehdr.e_entry;
		} else {
			/*
			 * A shared object with no interpreter, we use the
			 * calculated address from above.
			 */
			edp->ed_ldentry = edp->ed_entry;

			/*
			 * In all situations except an ET_DYN elf object with no
			 * interpreter, we want to leave the brk and base
			 * values set by mapexec_brand alone. Normally when
			 * running ET_DYN objects on Solaris (most likely
			 * /lib/ld.so.1) the kernel sets brk and base to 0 since
			 * it doesn't know where to put the heap, and later the
			 * linker will call brk() to initialize the heap in:
			 *	usr/src/cmd/sgs/rtld/common/setup.c:setup()
			 * after it has determined where to put it.  (This
			 * decision is made after the linker loads and inspects
			 * elf properties of the target executable being run.)
			 *
			 * So for ET_DYN Linux executables, we also don't know
			 * where the heap should go, so we'll set the brk and
			 * base to 0.  But in this case the Solaris linker will
			 * not initialize the heap, so when the Linux linker
			 * starts running there is no heap allocated.  This
			 * seems to be ok on Linux 2.4 based systems because the
			 * Linux linker/libc fall back to using mmap() to
			 * allocate memory. But on 2.6 systems, running
			 * applications by specifying them as command line
			 * arguments to the linker results in segfaults for an
			 * as yet undetermined reason (which seems to indicatej
			 * that a more permanent fix for heap initalization in
			 * these cases may be necessary).
			 */
			if (ehdr.e_type == ET_DYN) {
				env.ex_bssbase = (caddr_t)0;
				env.ex_brkbase = (caddr_t)0;
				env.ex_brksize = 0;
			}
		}

	}

	env.ex_vp = vp;
	setexecenv(&env);

	/*
	 * We don't need to copy this stuff out. It is only used by our
	 * tools to locate the lx linker's debug section. But we should at
	 * least try to keep /proc's view of the aux vector consistent with
	 * what's on the process stack.
	 */
	if (args->to_model == DATAMODEL_NATIVE) {
		auxv_t phdr_auxv[3] = {
		    { AT_SUN_BRAND_LX_PHDR, 0 },
		    { AT_SUN_BRAND_LX_INTERP, 0 },
		    { AT_SUN_BRAND_AUX3, 0 }
		};
		phdr_auxv[0].a_un.a_val = edp->ed_phdr;
		phdr_auxv[1].a_un.a_val = ldaddr;
		phdr_auxv[2].a_type = AT_CLKTCK;
		phdr_auxv[2].a_un.a_val = hz;

		if (copyout(&phdr_auxv, args->auxp_brand,
		    sizeof (phdr_auxv)) == -1)
			return (EFAULT);
	}
#if defined(_LP64)
	else {
		auxv32_t phdr_auxv32[3] = {
		    { AT_SUN_BRAND_LX_PHDR, 0 },
		    { AT_SUN_BRAND_LX_INTERP, 0 },
		    { AT_SUN_BRAND_AUX3, 0 }
		};
		phdr_auxv32[0].a_un.a_val = edp->ed_phdr;
		phdr_auxv32[1].a_un.a_val = ldaddr;
		phdr_auxv32[2].a_type = AT_CLKTCK;
		phdr_auxv32[2].a_un.a_val = hz;

		if (copyout(&phdr_auxv32, args->auxp_brand,
		    sizeof (phdr_auxv32)) == -1)
			return (EFAULT);
	}
#endif

	/*
	 * /proc uses the AT_ENTRY aux vector entry to deduce
	 * the location of the executable in the address space. The user
	 * structure contains a copy of the aux vector that needs to have those
	 * entries patched with the values of the real lx executable (they
	 * currently contain the values from the lx brand library that was
	 * elfexec'd, above).
	 *
	 * For live processes, AT_BASE is used to locate the linker segment,
	 * which /proc and friends will later use to find Solaris symbols
	 * (such as rtld_db_preinit). However, for core files, /proc uses
	 * AT_ENTRY to find the right segment to label as the executable.
	 * So we set AT_ENTRY to be the entry point of the linux executable,
	 * but leave AT_BASE to be the address of the Solaris linker.
	 */
	for (i = 0; i < __KERN_NAUXV_IMPL; i++) {
		switch (up->u_auxv[i].a_type) {
		case AT_ENTRY:
			up->u_auxv[i].a_un.a_val = edp->ed_entry;
			break;

		case AT_SUN_BRAND_LX_PHDR:
			up->u_auxv[i].a_un.a_val = edp->ed_phdr;
			break;

		case AT_SUN_BRAND_LX_INTERP:
			up->u_auxv[i].a_un.a_val = ldaddr;
			break;

		default:
			break;
		}
	}

	return (0);
}

boolean_t
lx_native_exec(uint8_t osabi, const char **interp)
{
	if (osabi != ELFOSABI_SOLARIS)
		return (B_FALSE);

	*interp = "/native";
	return (B_TRUE);
}

int
_init(void)
{
	int err = 0;

	/* pid/tid conversion hash tables */
	lx_pid_init();

	/* for lx_futex() */
	lx_futex_init();

	err = mod_install(&modlinkage);
	if (err != 0) {
		cmn_err(CE_WARN, "Couldn't install lx brand module");

		/*
		 * This looks drastic, but it should never happen.  These
		 * two data structures should be completely free-able until
		 * they are used by Linux processes.  Since the brand
		 * wasn't loaded there should be no Linux processes, and
		 * thus no way for these data structures to be modified.
		 */
		lx_pid_fini();
		if (lx_futex_fini())
			panic("lx brand module cannot be loaded or unloaded.");
	}
	return (err);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

int
_fini(void)
{
	int err;
	int futex_done = 0;

	/*
	 * If there are any zones using this brand, we can't allow it to be
	 * unloaded.
	 */
	if (brand_zone_count(&lx_brand))
		return (EBUSY);

	lx_pid_fini();

	if ((err = lx_futex_fini()) != 0)
		goto done;
	futex_done = 1;

	err = mod_remove(&modlinkage);

done:
	if (err) {
		/*
		 * If we can't unload the module, then we have to get it
		 * back into a sane state.
		 */
		lx_pid_init();

		if (futex_done)
			lx_futex_init();

	}

	return (err);
}
