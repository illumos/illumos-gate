/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* from SVr4.0 1.31 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/sysmacros.h>
#include <sys/pcb.h>
#include <sys/systm.h>
#include <sys/signal.h>
#include <sys/cred.h>
#include <sys/user.h>
#include <sys/vfs.h>
#include <sys/vnode.h>
#include <sys/proc.h>
#include <sys/time.h>
#include <sys/file.h>
#include <sys/priocntl.h>
#include <sys/procset.h>
#include <sys/var.h>
#include <sys/disp.h>
#include <sys/callo.h>
#include <sys/callb.h>
#include <sys/debug.h>
#include <sys/conf.h>
#include <sys/bootconf.h>
#include <sys/utsname.h>
#include <sys/cmn_err.h>
#include <sys/vmparam.h>
#include <sys/modctl.h>
#include <sys/vm.h>
#include <sys/callb.h>
#include <sys/kmem.h>
#include <sys/vmem.h>
#include <sys/cpuvar.h>
#include <sys/cladm.h>
#include <sys/corectl.h>
#include <sys/exec.h>
#include <sys/syscall.h>
#include <sys/reboot.h>
#include <sys/task.h>
#include <sys/exacct.h>
#include <sys/autoconf.h>
#include <sys/errorq.h>
#include <sys/class.h>
#include <sys/stack.h>

#include <vm/as.h>
#include <vm/seg_kmem.h>
#include <sys/dc_ki.h>

#include <c2/audit.h>

/* well known processes */
proc_t *proc_sched;		/* memory scheduler */
proc_t *proc_init;		/* init */
proc_t *proc_pageout;		/* pageout daemon */
proc_t *proc_fsflush;		/* fsflush daemon */

pgcnt_t	maxmem;		/* Maximum available memory in pages.	*/
pgcnt_t	freemem;	/* Current available memory in pages.	*/
int	audit_active;
int	interrupts_unleashed;	/* set when we do the first spl0() */

kmem_cache_t *process_cache;	/* kmem cache for proc structures */

/*
 * Process 0's lwp directory and lwpid hash table.
 */
lwpdir_t p0_lwpdir[2];
lwpdir_t *p0_tidhash[2];
lwpent_t p0_lep;

/*
 * Machine-independent initialization code
 * Called from cold start routine as
 * soon as a stack and segmentation
 * have been established.
 * Functions:
 *	clear and free user core
 *	turn on clock
 *	hand craft 0th process
 *	call all initialization routines
 *	fork	- process 0 to schedule
 *		- process 1 execute bootstrap
 *		- process 2 to page out
 *	create system threads
 */

int cluster_bootflags = 0;

void
cluster_wrapper(void)
{
	cluster();
	panic("cluster()  returned");
}

char initname[INITNAME_SZ] = "/sbin/init";
char initargs[INITARGS_SZ] = "";

/*
 * Start the initial user process.
 * The program [initname] may be invoked with one argument
 * containing the boot flags.
 *
 * It must be a 32-bit program.
 */
void
icode(void)
{
	proc_t *p = ttoproc(curthread);

	ASSERT_STACK_ALIGNED();

	/*
	 * Allocate user address space and stack segment
	 */
	proc_init = p;
	zone0.zone_proc_initpid = proc_init->p_pid;

	p->p_cstime = p->p_stime = p->p_cutime = p->p_utime = 0;
	p->p_usrstack = (caddr_t)USRSTACK32;
	p->p_model = DATAMODEL_ILP32;
	p->p_stkprot = PROT_ZFOD & ~PROT_EXEC;
	p->p_datprot = PROT_ZFOD & ~PROT_EXEC;
	p->p_stk_ctl = INT32_MAX;

	p->p_as = as_alloc();
	p->p_as->a_userlimit = (caddr_t)USERLIMIT32;
	(void) hat_setup(p->p_as->a_hat, HAT_INIT);
	init_core();

	init_mstate(curthread, LMS_SYSTEM);

	if (exec_init(initname, 1, initargs[0] == '\0' ? NULL : initargs) != 0)
		halt("Could not start init");

	lwp_rtt();
}

int
exec_init(const char *initpath, int useboothowto, const char *args)
{
	char *ucp;
	caddr32_t *uap;
	char *argv[4];				/* backwards */
	int argc = 0;
	int error = 0, len, count = 0, i;
	proc_t *p = ttoproc(curthread);
	klwp_t *lwp = ttolwp(curthread);

	/*
	 * Construct the exec arguments in userland.  That is, make an array
	 * of pointers to the argument strings, just like for execv().  This
	 * is done backwards.
	 */
	ucp = p->p_usrstack;

	argv[0] = NULL;				/* argv terminator */

	if (args != NULL) {
		len = strlen(args) + 1;
		ucp -= len;
		error |= copyoutstr(args, ucp, len, NULL);
		argv[++argc] = ucp;
	}

	if (useboothowto &&
	    boothowto & (RB_SINGLE|RB_RECONFIG|RB_VERBOSE)) {
		error |= subyte(--ucp, '\0');		/* trailing null byte */

		if (boothowto & RB_SINGLE)
			error |= subyte(--ucp, 's');
		if (boothowto & RB_RECONFIG)
			error |= subyte(--ucp, 'r');
		if (boothowto & RB_VERBOSE)
			error |= subyte(--ucp, 'v');
		error |= subyte(--ucp, '-');	/* leading hyphen */

		argv[++argc] = ucp;
	}

	len = strlen(initpath) + 1;
	ucp -= len;
	error |= copyoutstr(initpath, ucp, len, NULL);
	argv[++argc] = ucp;

	/*
	 * Move out the arg pointers.
	 */
	uap = (caddr32_t *)P2ALIGN((uintptr_t)ucp, sizeof (caddr32_t));
	for (i = 0; i < argc + 1; ++i)
		error |= suword32(--uap, (uint32_t)(uintptr_t)argv[i]);

	if (error != 0) {
		zcmn_err(p->p_zone->zone_id, CE_WARN,
		    "Could not construct stack for init.\n");
		return (EFAULT);
	}

	/*
	 * Point at the arguments.
	 */
	lwp->lwp_ap = lwp->lwp_arg;
	lwp->lwp_arg[0] = (uintptr_t)argv[argc];
	lwp->lwp_arg[1] = (uintptr_t)uap;
	lwp->lwp_arg[2] = NULL;
	curthread->t_post_sys = 1;
	curthread->t_sysnum = SYS_execve;

again:
	error = exec_common((const char *)argv[argc], (const char **)uap, NULL);

	/*
	 * Normally we would just set lwp_argsaved and t_post_sys and
	 * let post_syscall reset lwp_ap for us.  Unfortunately,
	 * exec_init isn't always called from a system call.  Instead
	 * of making a mess of trap_cleanup, we just reset the args
	 * pointer here.
	 */
	reset_syscall_args();

	switch (error) {
	case 0:
		return (0);

	case ENOENT:
		zcmn_err(p->p_zone->zone_id, CE_WARN,
		    "exec(%s) failed (file not found).\n", initpath);
		return (ENOENT);

	case EAGAIN:
	case EINTR:
		++count;
		if (count < 5) {
			zcmn_err(p->p_zone->zone_id, CE_WARN,
			    "exec(%s) failed with errno %d.  Retrying...\n",
			    initpath, error);
			goto again;
		}
	}

	zcmn_err(p->p_zone->zone_id, CE_WARN,
	    "exec(%s) failed with errno %d.", initpath, error);
	return (error);
}

void
main(void)
{
	proc_t		*p = ttoproc(curthread);	/* &p0 */
	int		(**initptr)();
	extern void	sched();
	extern void	fsflush();
	extern void	thread_reaper();
	extern int	(*init_tbl[])();
	extern int	(*mp_init_tbl[])();
	extern id_t	syscid, defaultcid;
	extern int	swaploaded;
	extern int	netboot;
	extern void	vm_init(void);
	extern void	cbe_init(void);
	extern void	clock_init(void);
	extern void	physio_bufs_init(void);
	extern void	pm_cfb_setup_intr(void);
	extern int	pm_adjust_timestamps(dev_info_t *, void *);
	extern void	start_other_cpus(int);
	extern void	sysevent_evc_thrinit();
	extern void	lgrp_main_init(void);
	extern void	lgrp_main_mp_init(void);

	/*
	 * In the horrible world of x86 in-lines, you can't get symbolic
	 * structure offsets a la genassym.  This assertion is here so
	 * that the next poor slob who innocently changes the offset of
	 * cpu_thread doesn't waste as much time as I just did finding
	 * out that it's hard-coded in i86/ml/i86.il.  Similarly for
	 * curcpup.  You're welcome.
	 */
	ASSERT(CPU == CPU->cpu_self);
	ASSERT(curthread == CPU->cpu_thread);
	ASSERT_STACK_ALIGNED();

	/*
	 * Setup the first lgroup, and home t0
	 */
	lgrp_setup();

	startup();
	segkmem_gc();
	callb_init();
	callout_init();	/* callout table MUST be init'd before clock starts */
	cbe_init();
	clock_init();

	/*
	 * May need to probe to determine latencies from CPU 0 after
	 * gethrtime() comes alive in cbe_init() and before enabling interrupts
	 */
	lgrp_plat_probe();

	/*
	 * Call all system initialization functions.
	 */
	for (initptr = &init_tbl[0]; *initptr; initptr++)
		(**initptr)();

	/*
	 * initialize vm related stuff.
	 */
	vm_init();

	/*
	 * initialize buffer pool for raw I/O requests
	 */
	physio_bufs_init();

	ttolwp(curthread)->lwp_error = 0; /* XXX kludge for SCSI driver */

	/*
	 * Drop the interrupt level and allow interrupts.  At this point
	 * the DDI guarantees that interrupts are enabled.
	 */
	(void) spl0();
	interrupts_unleashed = 1;

	vfs_mountroot();	/* Mount the root file system */
	errorq_init();		/* after vfs_mountroot() so DDI root is ready */
	cpu_kstat_init(CPU);	/* after vfs_mountroot() so TOD is valid */
	ddi_walk_devs(ddi_root_node(), pm_adjust_timestamps, NULL);
				/* after vfs_mountroot() so hrestime is valid */

	post_startup();
	swaploaded = 1;

	/*
	 * Initial C2 audit system
	 */
#ifdef C2_AUDIT
	audit_init();	/* C2 hook */
#endif

	/*
	 * Plumb the protocol modules and drivers only if we are not
	 * networked booted, in this case we already did it in rootconf().
	 */
	if (netboot == 0)
		(void) strplumb();

	gethrestime(&u.u_start);
	curthread->t_start = u.u_start.tv_sec;
	p->p_mstart = gethrtime();

	/*
	 * Perform setup functions that can only be done after root
	 * and swap have been set up.
	 */
	consconfig();
#if defined(__i386) || defined(__amd64)
	release_bootstrap();
#endif
	/*
	 * attach drivers with ddi-forceattach prop
	 * This must be done after consconfig() to prevent usb key/mouse
	 * from attaching before the upper console stream is plumbed.
	 * It must be done early enough to load hotplug drivers (e.g.
	 * pcmcia nexus) so that devices enumerated via hotplug is
	 * available before I/O subsystem is fully initialized.
	 */
	i_ddi_forceattach_drivers();

	/*
	 * Set the scan rate and other parameters of the paging subsystem.
	 */
	setupclock(0);

	/*
	 * Create kmem cache for proc structures
	 */
	process_cache = kmem_cache_create("process_cache", sizeof (proc_t),
	    0, NULL, NULL, NULL, NULL, NULL, 0);

	/*
	 * Initialize process 0's lwp directory and lwpid hash table.
	 */
	p->p_lwpdir = p->p_lwpfree = p0_lwpdir;
	p->p_lwpdir->ld_next = p->p_lwpdir + 1;
	p->p_lwpdir_sz = 2;
	p->p_tidhash = p0_tidhash;
	p->p_tidhash_sz = 2;
	p0_lep.le_thread = curthread;
	p0_lep.le_lwpid = curthread->t_tid;
	p0_lep.le_start = curthread->t_start;
	lwp_hash_in(p, &p0_lep);

	/*
	 * Initialize extended accounting.
	 */
	exacct_init();

	/*
	 * Initialize threads of sysevent event channels
	 */
	sysevent_evc_thrinit();

	/*
	 * main lgroup initialization
	 * This must be done after post_startup(), but before
	 * start_other_cpus()
	 */
	lgrp_main_init();

	/*
	 * Perform MP initialization, if any.
	 */
	start_other_cpus(0);

	/*
	 * Finish lgrp initialization after all CPUS are brought online.
	 */
	lgrp_main_mp_init();

	/*
	 * After mp_init(), number of cpus are known (this is
	 * true for the time being, when there are actually
	 * hot pluggable cpus then this scheme  would not do).
	 * Any per cpu initialization is done here.
	 */
	kmem_mp_init();
	vmem_update(NULL);

	for (initptr = &mp_init_tbl[0]; *initptr; initptr++)
		(**initptr)();

	/*
	 * This must be called after start_other_cpus
	 */
	pm_cfb_setup_intr();

	/*
	 * Make init process; enter scheduling loop with system process.
	 */

	/* create init process */
	if (newproc(icode, NULL, defaultcid, 59, NULL))
		panic("main: unable to fork init.");

	/* create pageout daemon */
	if (newproc(pageout, NULL, syscid, maxclsyspri - 1, NULL))
		panic("main: unable to fork pageout()");

	/* create fsflush daemon */
	if (newproc(fsflush, NULL, syscid, minclsyspri, NULL))
		panic("main: unable to fork fsflush()");

	/* create cluster process if we're a member of one */
	if (cluster_bootflags & CLUSTER_BOOTED) {
		if (newproc(cluster_wrapper, NULL, syscid, minclsyspri, NULL))
			panic("main: unable to fork cluster()");
	}

	/*
	 * Create system threads (threads are associated with p0)
	 */

	/* create thread_reaper daemon */
	(void) thread_create(NULL, 0, (void (*)())thread_reaper,
	    NULL, 0, &p0, TS_RUN, minclsyspri);

	/* create module uninstall daemon */
	/* BugID 1132273. If swapping over NFS need a bigger stack */
	(void) thread_create(NULL, 0, (void (*)())mod_uninstall_daemon,
	    NULL, 0, &p0, TS_RUN, minclsyspri);

	(void) thread_create(NULL, 0, seg_pasync_thread,
	    NULL, 0, &p0, TS_RUN, minclsyspri);

	pid_setmin();

	bcopy("sched", u.u_psargs, 6);
	bcopy("sched", u.u_comm, 5);
	sched();
	/* NOTREACHED */
}
