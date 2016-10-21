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

#include <sys/types.h>
#include <sys/systm.h>
#include <sys/archsystm.h>
#include <sys/machsystm.h>
#include <sys/disp.h>
#include <sys/autoconf.h>
#include <sys/promif.h>
#include <sys/prom_plat.h>
#include <sys/promimpl.h>
#include <sys/platform_module.h>
#include <sys/clock.h>
#include <sys/pte.h>
#include <sys/scb.h>
#include <sys/cpu.h>
#include <sys/stack.h>
#include <sys/intreg.h>
#include <sys/ivintr.h>
#include <vm/as.h>
#include <vm/hat_sfmmu.h>
#include <sys/reboot.h>
#include <sys/sysmacros.h>
#include <sys/vtrace.h>
#include <sys/trap.h>
#include <sys/machtrap.h>
#include <sys/privregs.h>
#include <sys/machpcb.h>
#include <sys/proc.h>
#include <sys/cpupart.h>
#include <sys/pset.h>
#include <sys/cpu_module.h>
#include <sys/copyops.h>
#include <sys/panic.h>
#include <sys/bootconf.h>	/* for bootops */
#include <sys/pg.h>
#include <sys/kdi.h>
#include <sys/fpras.h>

#include <sys/prom_debug.h>
#include <sys/debug.h>

#include <sys/sunddi.h>
#include <sys/lgrp.h>
#include <sys/traptrace.h>

#include <sys/kobj_impl.h>
#include <sys/kdi_machimpl.h>

/*
 * External Routines:
 */
extern void map_wellknown_devices(void);
extern void hsvc_setup(void);
extern void mach_descrip_startup_init(void);
extern void mach_soft_state_init(void);

int	dcache_size;
int	dcache_linesize;
int	icache_size;
int	icache_linesize;
int	ecache_size;
int	ecache_alignsize;
int	ecache_associativity;
int	ecache_setsize;			/* max possible e$ setsize */
int	cpu_setsize;			/* max e$ setsize of configured cpus */
int	dcache_line_mask;		/* spitfire only */
int	vac_size;			/* cache size in bytes */
uint_t	vac_mask;			/* VAC alignment consistency mask */
int	vac_shift;			/* log2(vac_size) for ppmapout() */
int	vac = 0;	/* virtual address cache type (none == 0) */

/*
 * fpRAS.  An individual sun4* machine class (or perhaps subclass,
 * eg sun4u/cheetah) must set fpras_implemented to indicate that it implements
 * the fpRAS feature.  The feature can be suppressed by setting fpras_disable
 * or the mechanism can be disabled for individual copy operations with
 * fpras_disableids.  All these are checked in post_startup() code so
 * fpras_disable and fpras_disableids can be set in /etc/system.
 * If/when fpRAS is implemented on non-sun4 architectures these
 * definitions will need to move up to the common level.
 */
int	fpras_implemented;
int	fpras_disable;
int	fpras_disableids;

/*
 * Static Routines:
 */
static void kern_splr_preprom(void);
static void kern_splx_postprom(void);

/*
 * Setup routine called right before main(). Interposing this function
 * before main() allows us to call it in a machine-independent fashion.
 */

void
mlsetup(struct regs *rp, kfpu_t *fp)
{
	struct machpcb *mpcb;

	extern char t0stack[];
	extern struct classfuncs sys_classfuncs;
	extern disp_t cpu0_disp;
	unsigned long long pa;

#ifdef TRAPTRACE
	TRAP_TRACE_CTL *ctlp;
#endif /* TRAPTRACE */

	/* drop into kmdb on boot -d */
	if (boothowto & RB_DEBUGENTER)
		kmdb_enter();

	/*
	 * initialize cpu_self
	 */
	cpu0.cpu_self = &cpu0;

	/*
	 * initialize t0
	 */
	t0.t_stk = (caddr_t)rp - REGOFF;
	/* Can't use va_to_pa here - wait until prom_ initialized */
	t0.t_stkbase = t0stack;
	t0.t_pri = maxclsyspri - 3;
	t0.t_schedflag = TS_LOAD | TS_DONT_SWAP;
	t0.t_procp = &p0;
	t0.t_plockp = &p0lock.pl_lock;
	t0.t_lwp = &lwp0;
	t0.t_forw = &t0;
	t0.t_back = &t0;
	t0.t_next = &t0;
	t0.t_prev = &t0;
	t0.t_cpu = &cpu0;			/* loaded by _start */
	t0.t_disp_queue = &cpu0_disp;
	t0.t_bind_cpu = PBIND_NONE;
	t0.t_bind_pset = PS_NONE;
	t0.t_bindflag = (uchar_t)default_binding_mode;
	t0.t_cpupart = &cp_default;
	t0.t_clfuncs = &sys_classfuncs.thread;
	t0.t_copyops = NULL;
	THREAD_ONPROC(&t0, CPU);

	lwp0.lwp_thread = &t0;
	lwp0.lwp_procp = &p0;
	lwp0.lwp_regs = (void *)rp;
	t0.t_tid = p0.p_lwpcnt = p0.p_lwprcnt = p0.p_lwpid = 1;

	mpcb = lwptompcb(&lwp0);
	mpcb->mpcb_fpu = fp;
	mpcb->mpcb_fpu->fpu_q = mpcb->mpcb_fpu_q;
	mpcb->mpcb_thread = &t0;
	lwp0.lwp_fpu = (void *)mpcb->mpcb_fpu;

	p0.p_exec = NULL;
	p0.p_stat = SRUN;
	p0.p_flag = SSYS;
	p0.p_tlist = &t0;
	p0.p_stksize = 2*PAGESIZE;
	p0.p_stkpageszc = 0;
	p0.p_as = &kas;
	p0.p_lockp = &p0lock;
	p0.p_utraps = NULL;
	p0.p_brkpageszc = 0;
	p0.p_t1_lgrpid = LGRP_NONE;
	p0.p_tr_lgrpid = LGRP_NONE;
	psecflags_default(&p0.p_secflags);
	sigorset(&p0.p_ignore, &ignoredefault);


	CPU->cpu_thread = &t0;
	CPU->cpu_dispthread = &t0;
	bzero(&cpu0_disp, sizeof (disp_t));
	CPU->cpu_disp = &cpu0_disp;
	CPU->cpu_disp->disp_cpu = CPU;
	CPU->cpu_idle_thread = &t0;
	CPU->cpu_flags = CPU_RUNNING;
	CPU->cpu_id = getprocessorid();
	CPU->cpu_dispatch_pri = t0.t_pri;

	/*
	 * Initialize thread/cpu microstate accounting
	 */
	init_mstate(&t0, LMS_SYSTEM);
	init_cpu_mstate(CPU, CMS_SYSTEM);

	/*
	 * Initialize lists of available and active CPUs.
	 */
	cpu_list_init(CPU);

	cpu_vm_data_init(CPU);

	pg_cpu_bootstrap(CPU);

	(void) prom_set_preprom(kern_splr_preprom);
	(void) prom_set_postprom(kern_splx_postprom);
	PRM_INFO("mlsetup: now ok to call prom_printf");

	mpcb->mpcb_pa = va_to_pa(t0.t_stk);

	/*
	 * Claim the physical and virtual resources used by panicbuf,
	 * then map panicbuf.  This operation removes the phys and
	 * virtual addresses from the free lists.
	 */
	if (prom_claim_virt(PANICBUFSIZE, panicbuf) != panicbuf)
		prom_panic("Can't claim panicbuf virtual address");

	if (prom_retain("panicbuf", PANICBUFSIZE, MMU_PAGESIZE, &pa) != 0)
		prom_panic("Can't allocate retained panicbuf physical address");

	if (prom_map_phys(-1, PANICBUFSIZE, panicbuf, pa) != 0)
		prom_panic("Can't map panicbuf");

	PRM_DEBUG(panicbuf);
	PRM_DEBUG(pa);

	/*
	 * Negotiate hypervisor services, if any
	 */
	hsvc_setup();
	mach_soft_state_init();

#ifdef TRAPTRACE
	/*
	 * initialize the trap trace buffer for the boot cpu
	 * XXX todo, dynamically allocate this buffer too
	 */
	ctlp = &trap_trace_ctl[CPU->cpu_id];
	ctlp->d.vaddr_base = trap_tr0;
	ctlp->d.offset = ctlp->d.last_offset = 0;
	ctlp->d.limit = TRAP_TSIZE;		/* XXX dynamic someday */
	ctlp->d.paddr_base = va_to_pa(trap_tr0);
#endif /* TRAPTRACE */

	/*
	 * Initialize the Machine Description kernel framework
	 */

	mach_descrip_startup_init();

	/*
	 * initialize HV trap trace buffer for the boot cpu
	 */
	mach_htraptrace_setup(CPU->cpu_id);
	mach_htraptrace_configure(CPU->cpu_id);

	/*
	 * lgroup framework initialization. This must be done prior
	 * to devices being mapped.
	 */
	lgrp_init(LGRP_INIT_STAGE1);

	cpu_setup();

	if (boothowto & RB_HALT) {
		prom_printf("unix: kernel halted by -h flag\n");
		prom_enter_mon();
	}

	setcputype();
	map_wellknown_devices();
	setcpudelay();
}

/*
 * These routines are called immediately before and
 * immediately after calling into the firmware.  The
 * firmware is significantly confused by preemption -
 * particularly on MP machines - but also on UP's too.
 */

static int saved_spl;

static void
kern_splr_preprom(void)
{
	saved_spl = spl7();
}

static void
kern_splx_postprom(void)
{
	splx(saved_spl);
}


/*
 * WARNING
 * The code fom here to the end of mlsetup.c runs before krtld has
 * knitted unix and genunix together.  It can call routines in unix,
 * but calls into genunix will fail spectacularly.  More specifically,
 * calls to prom_*, bop_* and str* will work, everything else is
 * caveat emptor.
 *
 * Also note that while #ifdef sun4u is generally a bad idea, they
 * exist here to concentrate the dangerous code into a single file.
 */

static char *
getcpulist(void)
{
	pnode_t node;
	/* big enough for OBP_NAME and for a reasonably sized OBP_COMPATIBLE. */
	static char cpubuf[5 * OBP_MAXDRVNAME];
	int nlen, clen, i;
#ifdef	sun4u
	char dname[OBP_MAXDRVNAME];
#endif

	node = prom_findnode_bydevtype(prom_rootnode(), OBP_CPU);
	if (node != OBP_NONODE && node != OBP_BADNODE) {
		if ((nlen = prom_getproplen(node, OBP_NAME)) <= 0 ||
		    nlen > sizeof (cpubuf) ||
		    prom_getprop(node, OBP_NAME, cpubuf) <= 0)
			prom_panic("no name in cpu node");

		/* nlen includes the terminating null character */
#ifdef	sun4v
		if ((clen = prom_getproplen(node, OBP_COMPATIBLE)) > 0) {
#else	/* sun4u */
		/*
		 * For the CMT case, need check the parent "core"
		 * node for the compatible property.
		 */
		if ((clen = prom_getproplen(node, OBP_COMPATIBLE)) > 0 ||
		    ((node = prom_parentnode(node)) != OBP_NONODE &&
		    node != OBP_BADNODE &&
		    (clen = prom_getproplen(node, OBP_COMPATIBLE)) > 0 &&
		    prom_getprop(node, OBP_DEVICETYPE, dname) > 0 &&
		    strcmp(dname, "core") == 0)) {
#endif
			if ((clen + nlen) > sizeof (cpubuf))
				prom_panic("cpu node \"compatible\" too long");
			/* read in compatible, leaving space for ':' */
			if (prom_getprop(node, OBP_COMPATIBLE,
			    &cpubuf[nlen]) != clen)
				prom_panic("cpu node \"compatible\" error");
			clen += nlen;	/* total length */
			/* convert all null characters to ':' */
			clen--;	/* except the final one... */
			for (i = 0; i < clen; i++)
				if (cpubuf[i] == '\0')
					cpubuf[i] = ':';
		}
#ifdef	sun4u
		/*
		 * Some PROMs return SUNW,UltraSPARC when they actually have
		 * SUNW,UltraSPARC-II cpus. SInce we're now filtering out all
		 * SUNW,UltraSPARC systems during the boot phase, we can safely
		 * point the auxv CPU value at SUNW,UltraSPARC-II.
		 */
		if (strcmp("SUNW,UltraSPARC", cpubuf) == 0)
			(void) strcpy(cpubuf, "SUNW,UltraSPARC-II");
#endif
		return (cpubuf);
	} else
		return (NULL);
}

/*
 * called immediately from _start to stich the
 * primary modules together
 */
void
kobj_start(void *cif)
{
	Ehdr *ehdr;
	Phdr *phdr;
	uint32_t eadr, padr;
	val_t bootaux[BA_NUM];
	int i;

	prom_init("kernel", cif);
	bop_init();
#ifdef	DEBUG
	if (bop_getproplen("stop-me") != -1)
		prom_enter_mon();
#endif

	if (bop_getprop("elfheader-address", (caddr_t)&eadr) == -1)
		prom_panic("no ELF image");
	ehdr = (Ehdr *)(uintptr_t)eadr;
	for (i = 0; i < BA_NUM; i++)
		bootaux[i].ba_val = NULL;
	bootaux[BA_PHNUM].ba_val = ehdr->e_phnum;
	bootaux[BA_PHENT].ba_val = ehdr->e_phentsize;
	bootaux[BA_LDNAME].ba_ptr = NULL;

	padr = eadr + ehdr->e_phoff;
	bootaux[BA_PHDR].ba_ptr = (void *)(uintptr_t)padr;
	for (i = 0; i < ehdr->e_phnum; i++) {
		phdr = (Phdr *)((uintptr_t)padr + i * ehdr->e_phentsize);
		if (phdr->p_type == PT_DYNAMIC) {
			bootaux[BA_DYNAMIC].ba_ptr = (void *)phdr->p_vaddr;
			break;
		}
	}

	bootaux[BA_LPAGESZ].ba_val = MMU_PAGESIZE4M;
	bootaux[BA_PAGESZ].ba_val = MMU_PAGESIZE;
	bootaux[BA_IFLUSH].ba_val = 1;
	bootaux[BA_CPU].ba_ptr = getcpulist();
	bootaux[BA_MMU].ba_ptr = NULL;

	kobj_init(cif, NULL, bootops, bootaux);

	/* kernel stitched together; we can now test #pragma's */
	if (&plat_setprop_enter != NULL) {
		prom_setprop_enter = &plat_setprop_enter;
		prom_setprop_exit = &plat_setprop_exit;
		ASSERT(prom_setprop_exit != NULL);
	}

}

/*
 * Create modpath from kernel name.
 * If we booted:
 *  /platform/`uname -i`/kernel/sparcv9/unix
 *   or
 *  /platform/`uname -m`/kernel/sparcv9/unix
 *
 * then make the modpath:
 *  /platform/`uname -i`/kernel /platform/`uname -m`/kernel
 *
 * otherwise, make the modpath the dir the kernel was
 * loaded from, minus any sparcv9 extension
 *
 * note the sparcv9 dir is optional since a unix -> sparcv9/unix
 * symlink is available as a shortcut.
 */
void
mach_modpath(char *path, const char *fname)
{
	char *p;
	int len, compat;
	const char prefix[] = "/platform/";
	char platname[MAXPATHLEN];
#ifdef	sun4u
	char defname[] = "sun4u";
#else
	char defname[] = "sun4v";
#endif
	const char suffix[] = "/kernel";
	const char isastr[] = "/sparcv9";

	/*
	 * check for /platform
	 */
	p = (char *)fname;
	if (strncmp(p, prefix, sizeof (prefix) - 1) != 0)
		goto nopath;
	p += sizeof (prefix) - 1;

	/*
	 * check for the default name or the platform name.
	 * also see if we used the 'compatible' name
	 * (platname == default)
	 */
	(void) bop_getprop("impl-arch-name", platname);
	compat = strcmp(platname, defname) == 0;
	len = strlen(platname);
	if (strncmp(p, platname, len) == 0)
		p += len;
	else if (strncmp(p, defname, sizeof (defname) - 1) == 0)
		p += sizeof (defname) - 1;
	else
		goto nopath;

	/*
	 * check for /kernel/sparcv9 or just /kernel
	 */
	if (strncmp(p, suffix, sizeof (suffix) - 1) != 0)
		goto nopath;
	p += sizeof (suffix) - 1;
	if (strncmp(p, isastr, sizeof (isastr) - 1) == 0)
		p += sizeof (isastr) - 1;

	/*
	 * check we're at the last component
	 */
	if (p != strrchr(fname, '/'))
		goto nopath;

	/*
	 * everything is kosher; setup modpath
	 */
	(void) strcpy(path, "/platform/");
	(void) strcat(path, platname);
	(void) strcat(path, "/kernel");
	if (!compat) {
		(void) strcat(path, " /platform/");
		(void) strcat(path, defname);
		(void) strcat(path, "/kernel");
	}
	return;

nopath:
	/*
	 * Construct the directory path from the filename.
	 */
	if ((p = strrchr(fname, '/')) == NULL)
		return;

	while (p > fname && *(p - 1) == '/')
		p--;	/* remove trailing '/' characters */
	if (p == fname)
		p++;	/* so "/" -is- the modpath in this case */

	/*
	 * Remove optional isa-dependent directory name - the module
	 * subsystem will put this back again (!)
	 */
	len = p - fname;
	if (len > sizeof (isastr) - 1 &&
	    strncmp(&fname[len - (sizeof (isastr) - 1)], isastr,
	    sizeof (isastr) - 1) == 0)
		p -= sizeof (isastr) - 1;
	(void) strncpy(path, fname, p - fname);
}
