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

#include <sys/types.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/fpu/fpusystm.h>
#include <sys/sysmacros.h>
#include <sys/signal.h>
#include <sys/cred.h>
#include <sys/user.h>
#include <sys/errno.h>
#include <sys/vnode.h>
#include <sys/mman.h>
#include <sys/kmem.h>
#include <sys/proc.h>
#include <sys/pathname.h>
#include <sys/cmn_err.h>
#include <sys/debug.h>
#include <sys/exec.h>
#include <sys/exechdr.h>
#include <sys/auxv.h>
#include <sys/core.h>
#include <sys/vmparam.h>
#include <sys/archsystm.h>
#include <sys/fs/swapnode.h>
#include <sys/modctl.h>
#include <vm/anon.h>
#include <vm/as.h>
#include <vm/seg.h>

static int aoutexec(vnode_t *vp, execa_t *uap, uarg_t *args,
    intpdata_t *idatap, int level, long *execsz, int setid,
    caddr_t exec_file, cred_t *cred, int brand_action);
static int get_aout_head(struct vnode **vpp, struct exdata *edp, long *execsz,
    int *isdyn);
static int aoutcore(vnode_t *vp, proc_t *pp, cred_t *credp,
    rlim64_t rlimit, int sig, core_content_t content);
extern int elf32exec(vnode_t *, execa_t *, uarg_t *, intpdata_t *, int,
    long *, int, caddr_t, cred_t *, int);
extern int elf32core(vnode_t *, proc_t *, cred_t *, rlim64_t, int,
    core_content_t);

char _depends_on[] = "exec/elfexec";

static struct execsw nesw = {
	aout_nmagicstr,
	2,
	2,
	aoutexec,
	aoutcore
};

static struct execsw zesw = {
	aout_zmagicstr,
	2,
	2,
	aoutexec,
	aoutcore
};

static struct execsw oesw = {
	aout_omagicstr,
	2,
	2,
	aoutexec,
	aoutcore
};

/*
 * Module linkage information for the kernel.
 */
static struct modlexec nexec = {
	&mod_execops, "exec for NMAGIC", &nesw
};

static struct modlexec zexec = {
	&mod_execops, "exec for ZMAGIC", &zesw
};

static struct modlexec oexec = {
	&mod_execops, "exec for OMAGIC", &oesw
};

static struct modlinkage modlinkage = {
	MODREV_1, &nexec, &zexec, &oexec, NULL
};

int
_init(void)
{
	return (mod_install(&modlinkage));
}

int
_fini(void)
{
	return (mod_remove(&modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}


/*ARGSUSED*/
static int
aoutexec(vnode_t *vp, struct execa *uap, struct uarg *args,
    struct intpdata *idatap, int level, long *execsz, int setid,
    caddr_t exec_file, cred_t *cred, int brand_action)
{
	auxv32_t auxflags_auxv32;
	int error;
	struct exdata edp, edpout;
	struct execenv exenv;
	proc_t *pp = ttoproc(curthread);
	struct vnode *nvp;
	int pagetext, pagedata;
	int dataprot = PROT_ALL;
	int textprot = PROT_ALL & ~PROT_WRITE;
	int isdyn;


	args->to_model = DATAMODEL_ILP32;
	*execsz = btopr(SINCR) + btopr(SSIZE) + btopr(NCARGS32-1);

	/*
	 * Read in and validate the file header.
	 */
	if (error = get_aout_head(&vp, &edp, execsz, &isdyn))
		return (error);

	if (error = chkaout(&edp))
		return (error);

	/*
	 * Take a quick look to see if it looks like we will have
	 * enough swap space for the program to get started.  This
	 * is not a guarantee that we will succeed, but it is definitely
	 * better than finding this out after we are committed to the
	 * new memory image.  Maybe what is needed is a way to "prereserve"
	 * swap space for some segment mappings here.
	 *
	 * But with shared libraries the process can make it through
	 * the exec only to have ld.so fail to get the program going
	 * because its mmap's will not be able to succeed if the system
	 * is running low on swap space.  In fact this is a far more
	 * common failure mode, but we cannot do much about this here
	 * other than add some slop to our anonymous memory resources
	 * requirements estimate based on some guess since we cannot know
	 * what else the program will really need to get to a useful state.
	 *
	 * XXX - The stack size (clrnd(SSIZE + btopr(nargc))) should also
	 * be used when checking for swap space.  This requires some work
	 * since nargc is actually determined in exec_args() which is done
	 * after this check and hence we punt for now.
	 *
	 * nargc = SA(nc + (na + 4) * NBPW) + sizeof (struct rwindow);
	 */
	if (CURRENT_TOTAL_AVAILABLE_SWAP < btopr(edp.ux_dsize) + btopr(SSIZE))
		return (ENOMEM);

	/*
	 * Load the trap 0 interpreter.
	 */
	if (error = lookupname("/usr/4lib/sbcp", UIO_SYSSPACE, FOLLOW,
	    NULLVPP, &nvp)) {
		goto done;
	}
	if (error = elf32exec(nvp, uap, args, idatap, level, execsz,
	    setid, exec_file, cred, brand_action)) {
		VN_RELE(nvp);
		return (error);
	}
	VN_RELE(nvp);

	/*
	 * Determine the a.out's characteristics.
	 */
	getexinfo(&edp, &edpout, &pagetext, &pagedata);

	/*
	 * Load the a.out's text and data.
	 */
	if (error = execmap(edp.vp, edp.ux_txtorg, edp.ux_tsize,
	    (size_t)0, edp.ux_toffset, textprot, pagetext, 0))
		goto done;
	if (error = execmap(edp.vp, edp.ux_datorg, edp.ux_dsize,
	    edp.ux_bsize, edp.ux_doffset, dataprot, pagedata, 0))
		goto done;

	exenv.ex_bssbase = (caddr_t)edp.ux_datorg;
	exenv.ex_brkbase = (caddr_t)edp.ux_datorg;
	exenv.ex_brksize = edp.ux_dsize + edp.ux_bsize;
	exenv.ex_magic = edp.ux_mag;
	exenv.ex_vp = edp.vp;
	setexecenv(&exenv);

	/*
	 * It's time to manipulate the process aux vectors.
	 * We need to update the AT_SUN_AUXFLAGS aux vector to set
	 * the AF_SUN_NOPLM flag.
	 */
	if (copyin(args->auxp_auxflags, &auxflags_auxv32,
	    sizeof (auxflags_auxv32)) != 0)
		return (EFAULT);

	ASSERT(auxflags_auxv32.a_type == AT_SUN_AUXFLAGS);
	auxflags_auxv32.a_un.a_val |= AF_SUN_NOPLM;
	if (copyout(&auxflags_auxv32, args->auxp_auxflags,
	    sizeof (auxflags_auxv32)) != 0)
		return (EFAULT);

done:
	if (error != 0)
		psignal(pp, SIGKILL);
	else {
		/*
		 * Ensure that the max fds do not exceed 256 (this is
		 * applicable to 4.x binaries, which is why we only
		 * do it on a.out files).
		 */
		struct rlimit64 fdno_rlim;
		rctl_alloc_gp_t *gp = rctl_rlimit_set_prealloc(1);

		mutex_enter(&curproc->p_lock);
		(void) rctl_rlimit_get(rctlproc_legacy[RLIMIT_NOFILE], curproc,
		    &fdno_rlim);
		if (fdno_rlim.rlim_cur > 256) {
			fdno_rlim.rlim_cur = fdno_rlim.rlim_max = 256;
			(void) rctl_rlimit_set(rctlproc_legacy[RLIMIT_NOFILE],
			    curproc, &fdno_rlim, gp,
			    rctlproc_flags[RLIMIT_NOFILE],
			    rctlproc_signals[RLIMIT_NOFILE], CRED());
		} else if (fdno_rlim.rlim_max > 256) {
			fdno_rlim.rlim_max = 256;
			(void) rctl_rlimit_set(rctlproc_legacy[RLIMIT_NOFILE],
			    curproc, &fdno_rlim, gp,
			    rctlproc_flags[RLIMIT_NOFILE],
			    rctlproc_signals[RLIMIT_NOFILE], CRED());
		}
		mutex_exit(&curproc->p_lock);

		rctl_prealloc_destroy(gp);
	}

	return (error);
}

/*
 * Read in and validate the file header.
 */
static int
get_aout_head(struct vnode **vpp, struct exdata *edp, long *execsz, int *isdyn)
{
	struct vnode *vp = *vpp;
	struct exec filhdr;
	int error;
	ssize_t resid;
	rlim64_t limit;
	rlim64_t roundlimit;

	if (error = vn_rdwr(UIO_READ, vp, (caddr_t)&filhdr,
	    (ssize_t)sizeof (filhdr), (offset_t)0, UIO_SYSSPACE, 0,
	    (rlim64_t)0, CRED(), &resid))
		return (error);

	if (resid != 0)
		return (ENOEXEC);

	switch (filhdr.a_magic) {
	case OMAGIC:
		filhdr.a_data += filhdr.a_text;
		filhdr.a_text = 0;
		break;
	case ZMAGIC:
	case NMAGIC:
		break;
	default:
		return (ENOEXEC);
	}

	/*
	 * Check total memory requirements (in pages) for a new process
	 * against the available memory or upper limit of memory allowed.
	 *
	 * For the 64-bit kernel, the limit can be set large enough so that
	 * rounding it up to a page can overflow, so we check for btopr()
	 * overflowing here by comparing it with the unrounded limit in pages.
	 */
	*execsz += btopr(filhdr.a_text + filhdr.a_data);
	limit = btop(curproc->p_vmem_ctl);
	roundlimit = btopr(curproc->p_vmem_ctl);
	if ((roundlimit > limit && *execsz > roundlimit) ||
	    (roundlimit < limit && *execsz > limit)) {
		mutex_enter(&curproc->p_lock);
		(void) rctl_action(rctlproc_legacy[RLIMIT_VMEM],
		    curproc->p_rctls, curproc, RCA_SAFE);
		mutex_exit(&curproc->p_lock);
		return (ENOMEM);
	}

	edp->ux_mach = filhdr.a_machtype;
	edp->ux_tsize = filhdr.a_text;
	edp->ux_dsize = filhdr.a_data;
	edp->ux_bsize = filhdr.a_bss;
	edp->ux_mag = filhdr.a_magic;
	edp->ux_toffset = gettfile(&filhdr);
	edp->ux_doffset = getdfile(&filhdr);
	edp->ux_txtorg = gettmem(&filhdr);
	edp->ux_datorg = getdmem(&filhdr);
	edp->ux_entloc = (caddr_t)(uintptr_t)filhdr.a_entry;
	edp->vp = vp;
	*isdyn = filhdr.a_dynamic;

	return (0);
}

static int
aoutcore(vnode_t *vp, proc_t *pp, struct cred *credp, rlim64_t rlimit, int sig,
    core_content_t content)
{
	return (elf32core(vp, pp, credp, rlimit, sig, content));
}
