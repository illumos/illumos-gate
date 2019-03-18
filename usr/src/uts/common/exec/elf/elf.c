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
 * Copyright (c) 1989, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	   All Rights Reserved	*/
/*
 * Copyright (c) 2019, Joyent, Inc.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/thread.h>
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
#include <sys/policy.h>
#include <sys/cmn_err.h>
#include <sys/systm.h>
#include <sys/elf.h>
#include <sys/vmsystm.h>
#include <sys/debug.h>
#include <sys/auxv.h>
#include <sys/exec.h>
#include <sys/prsystm.h>
#include <vm/as.h>
#include <vm/rm.h>
#include <vm/seg.h>
#include <vm/seg_vn.h>
#include <sys/modctl.h>
#include <sys/systeminfo.h>
#include <sys/vmparam.h>
#include <sys/machelf.h>
#include <sys/shm_impl.h>
#include <sys/archsystm.h>
#include <sys/fasttrap.h>
#include <sys/brand.h>
#include "elf_impl.h"
#include <sys/sdt.h>
#include <sys/siginfo.h>
#include <sys/random.h>

#if defined(__x86)
#include <sys/comm_page_util.h>
#include <sys/fp.h>
#endif /* defined(__x86) */


extern int at_flags;
extern volatile size_t aslr_max_brk_skew;

#define	ORIGIN_STR	"ORIGIN"
#define	ORIGIN_STR_SIZE	6

static int getelfhead(vnode_t *, cred_t *, Ehdr *, uint_t *, uint_t *,
    uint_t *);
static int getelfphdr(vnode_t *, cred_t *, const Ehdr *, uint_t, caddr_t *,
    size_t *);
static int getelfshdr(vnode_t *, cred_t *, const Ehdr *, uint_t, uint_t,
    caddr_t *, size_t *, caddr_t *, size_t *);
static size_t elfsize(const Ehdr *, uint_t, const caddr_t, uintptr_t *);
static int mapelfexec(vnode_t *, Ehdr *, uint_t, caddr_t, Phdr **, Phdr **,
    Phdr **, Phdr **, Phdr *, caddr_t *, caddr_t *, intptr_t *, uintptr_t *,
    size_t, size_t *, size_t *);

#ifdef _ELF32_COMPAT
/* Link against the non-compat instances when compiling the 32-bit version. */
extern size_t elf_datasz_max;
extern void elf_ctx_resize_scratch(elf_core_ctx_t *, size_t);
extern uint_t elf_nphdr_max;
extern uint_t elf_nshdr_max;
extern size_t elf_shstrtab_max;
#else
size_t elf_datasz_max = 1 * 1024 * 1024;
uint_t elf_nphdr_max = 1000;
uint_t elf_nshdr_max = 10000;
size_t elf_shstrtab_max = 100 * 1024;
#endif



typedef enum {
	STR_CTF,
	STR_SYMTAB,
	STR_DYNSYM,
	STR_STRTAB,
	STR_DYNSTR,
	STR_SHSTRTAB,
	STR_NUM
} shstrtype_t;

static const char *shstrtab_data[] = {
	".SUNW_ctf",
	".symtab",
	".dynsym",
	".strtab",
	".dynstr",
	".shstrtab"
};

typedef struct shstrtab {
	uint_t	sst_ndx[STR_NUM];
	uint_t	sst_cur;
} shstrtab_t;

static void
shstrtab_init(shstrtab_t *s)
{
	bzero(&s->sst_ndx, sizeof (s->sst_ndx));
	s->sst_cur = 1;
}

static uint_t
shstrtab_ndx(shstrtab_t *s, shstrtype_t type)
{
	uint_t ret;

	if ((ret = s->sst_ndx[type]) != 0)
		return (ret);

	ret = s->sst_ndx[type] = s->sst_cur;
	s->sst_cur += strlen(shstrtab_data[type]) + 1;

	return (ret);
}

static size_t
shstrtab_size(const shstrtab_t *s)
{
	return (s->sst_cur);
}

static void
shstrtab_dump(const shstrtab_t *s, char *buf)
{
	uint_t i, ndx;

	*buf = '\0';
	for (i = 0; i < STR_NUM; i++) {
		if ((ndx = s->sst_ndx[i]) != 0)
			(void) strcpy(buf + ndx, shstrtab_data[i]);
	}
}

static int
dtrace_safe_phdr(Phdr *phdrp, struct uarg *args, uintptr_t base)
{
	ASSERT(phdrp->p_type == PT_SUNWDTRACE);

	/*
	 * See the comment in fasttrap.h for information on how to safely
	 * update this program header.
	 */
	if (phdrp->p_memsz < PT_SUNWDTRACE_SIZE ||
	    (phdrp->p_flags & (PF_R | PF_W | PF_X)) != (PF_R | PF_W | PF_X))
		return (-1);

	args->thrptr = phdrp->p_vaddr + base;

	return (0);
}

static int
handle_secflag_dt(proc_t *p, uint_t dt, uint_t val)
{
	uint_t flag;

	switch (dt) {
	case DT_SUNW_ASLR:
		flag = PROC_SEC_ASLR;
		break;
	default:
		return (EINVAL);
	}

	if (val == 0) {
		if (secflag_isset(p->p_secflags.psf_lower, flag))
			return (EPERM);
		if ((secpolicy_psecflags(CRED(), p, p) != 0) &&
		    secflag_isset(p->p_secflags.psf_inherit, flag))
			return (EPERM);

		secflag_clear(&p->p_secflags.psf_effective, flag);
	} else {
		if (!secflag_isset(p->p_secflags.psf_upper, flag))
			return (EPERM);

		if ((secpolicy_psecflags(CRED(), p, p) != 0) &&
		    !secflag_isset(p->p_secflags.psf_inherit, flag))
			return (EPERM);

		secflag_set(&p->p_secflags.psf_effective, flag);
	}

	return (0);
}


#ifndef _ELF32_COMPAT
void
elf_ctx_resize_scratch(elf_core_ctx_t *ctx, size_t sz)
{
	size_t target = MIN(sz, elf_datasz_max);

	if (target > ctx->ecc_bufsz) {
		if (ctx->ecc_buf != NULL) {
			kmem_free(ctx->ecc_buf, ctx->ecc_bufsz);
		}
		ctx->ecc_buf = kmem_alloc(target, KM_SLEEP);
		ctx->ecc_bufsz = target;
	}
}
#endif /* _ELF32_COMPAT */

/*
 * Map in the executable pointed to by vp. Returns 0 on success.  Note that
 * this function currently has the maximum number of arguments allowed by
 * modstubs on x86 (MAXNARG)!  Do _not_ add to this function signature without
 * adding to MAXNARG.  (Better yet, do not add to this monster of a function
 * signature!)
 */
int
mapexec_brand(vnode_t *vp, uarg_t *args, Ehdr *ehdr, Addr *uphdr_vaddr,
    intptr_t *voffset, caddr_t exec_file, char **interpp, caddr_t *bssbase,
    caddr_t *brkbase, size_t *brksize, uintptr_t *lddatap, uintptr_t *minaddrp)
{
	size_t		len, phdrsize;
	struct vattr	vat;
	caddr_t		phdrbase = NULL;
	uint_t		nshdrs, shstrndx, nphdrs;
	int		error = 0;
	Phdr		*uphdr = NULL;
	Phdr		*junk = NULL;
	Phdr		*dynphdr = NULL;
	Phdr		*dtrphdr = NULL;
	char		*interp = NULL;
	uintptr_t	lddata, minaddr;
	size_t		execsz;

	if (lddatap != NULL)
		*lddatap = NULL;

	if (minaddrp != NULL)
		*minaddrp = NULL;

	if (error = execpermissions(vp, &vat, args)) {
		uprintf("%s: Cannot execute %s\n", exec_file, args->pathname);
		return (error);
	}

	if ((error = getelfhead(vp, CRED(), ehdr, &nshdrs, &shstrndx,
	    &nphdrs)) != 0 ||
	    (error = getelfphdr(vp, CRED(), ehdr, nphdrs, &phdrbase,
	    &phdrsize)) != 0) {
		uprintf("%s: Cannot read %s\n", exec_file, args->pathname);
		return (error);
	}

	if ((len = elfsize(ehdr, nphdrs, phdrbase, &lddata)) == 0) {
		uprintf("%s: Nothing to load in %s", exec_file, args->pathname);
		kmem_free(phdrbase, phdrsize);
		return (ENOEXEC);
	}
	if (lddatap != NULL)
		*lddatap = lddata;

	if (error = mapelfexec(vp, ehdr, nphdrs, phdrbase, &uphdr, &dynphdr,
	    &junk, &dtrphdr, NULL, bssbase, brkbase, voffset, &minaddr,
	    len, &execsz, brksize)) {
		uprintf("%s: Cannot map %s\n", exec_file, args->pathname);
		if (uphdr != NULL && uphdr->p_flags == 0)
			kmem_free(uphdr, sizeof (Phdr));
		kmem_free(phdrbase, phdrsize);
		return (error);
	}

	if (minaddrp != NULL)
		*minaddrp = minaddr;

	/*
	 * If the executable requires an interpreter, determine its name.
	 */
	if (dynphdr != NULL) {
		ssize_t	resid;

		if (dynphdr->p_filesz > MAXPATHLEN || dynphdr->p_filesz == 0) {
			uprintf("%s: Invalid interpreter\n", exec_file);
			kmem_free(phdrbase, phdrsize);
			return (ENOEXEC);
		}

		interp = kmem_alloc(MAXPATHLEN, KM_SLEEP);

		if ((error = vn_rdwr(UIO_READ, vp, interp,
		    (ssize_t)dynphdr->p_filesz,
		    (offset_t)dynphdr->p_offset, UIO_SYSSPACE, 0,
		    (rlim64_t)0, CRED(), &resid)) != 0 || resid != 0 ||
		    interp[dynphdr->p_filesz - 1] != '\0') {
			uprintf("%s: Cannot obtain interpreter pathname\n",
			    exec_file);
			kmem_free(interp, MAXPATHLEN);
			kmem_free(phdrbase, phdrsize);
			return (error != 0 ? error : ENOEXEC);
		}
	}

	/*
	 * If this is a statically linked executable, voffset should indicate
	 * the address of the executable itself (it normally holds the address
	 * of the interpreter).
	 */
	if (ehdr->e_type == ET_EXEC && interp == NULL)
		*voffset = minaddr;

	/*
	 * If the caller has asked for the interpreter name, return it (it's
	 * up to the caller to free it); if the caller hasn't asked for it,
	 * free it ourselves.
	 */
	if (interpp != NULL) {
		*interpp = interp;
	} else if (interp != NULL) {
		kmem_free(interp, MAXPATHLEN);
	}

	if (uphdr != NULL) {
		*uphdr_vaddr = uphdr->p_vaddr;

		if (uphdr->p_flags == 0)
			kmem_free(uphdr, sizeof (Phdr));
	} else if (ehdr->e_type == ET_DYN) {
		/*
		 * If we don't have a uphdr, we'll apply the logic found
		 * in mapelfexec() and use the p_vaddr of the first PT_LOAD
		 * section as the base address of the object.
		 */
		const Phdr *phdr = (Phdr *)phdrbase;
		const uint_t hsize = ehdr->e_phentsize;
		uint_t i;

		for (i = nphdrs; i > 0; i--) {
			if (phdr->p_type == PT_LOAD) {
				*uphdr_vaddr = (uintptr_t)phdr->p_vaddr +
				    ehdr->e_phoff;
				break;
			}

			phdr = (Phdr *)((caddr_t)phdr + hsize);
		}

		/*
		 * If we don't have a PT_LOAD segment, we should have returned
		 * ENOEXEC when elfsize() returned 0, above.
		 */
		VERIFY(i > 0);
	} else {
		*uphdr_vaddr = (Addr)-1;
	}

	kmem_free(phdrbase, phdrsize);
	return (error);
}

/*ARGSUSED*/
int
elfexec(vnode_t *vp, execa_t *uap, uarg_t *args, intpdata_t *idatap,
    int level, size_t *execsz, int setid, caddr_t exec_file, cred_t *cred,
    int *brand_action)
{
	caddr_t		phdrbase = NULL;
	caddr_t		bssbase = 0;
	caddr_t		brkbase = 0;
	size_t		brksize = 0;
	size_t		dlnsize, nsize = 0;
	aux_entry_t	*aux;
	int		error;
	ssize_t		resid;
	int		fd = -1;
	intptr_t	voffset;
	Phdr		*intphdr = NULL;
	Phdr		*dynamicphdr = NULL;
	Phdr		*stphdr = NULL;
	Phdr		*uphdr = NULL;
	Phdr		*junk = NULL;
	size_t		len;
	size_t		postfixsize = 0;
	size_t		i;
	Phdr		*phdrp;
	Phdr		*dataphdrp = NULL;
	Phdr		*dtrphdr;
	Phdr		*capphdr = NULL;
	Cap		*cap = NULL;
	size_t		capsize;
	int		hasu = 0;
	int		hasauxv = 0;
	int		hasintp = 0;
	int		branded = 0;
	int		dynuphdr = 0;

	struct proc *p = ttoproc(curthread);
	struct user *up = PTOU(p);
	struct bigwad {
		Ehdr	ehdr;
		aux_entry_t	elfargs[__KERN_NAUXV_IMPL];
		char		dl_name[MAXPATHLEN];
		char		pathbuf[MAXPATHLEN];
		struct vattr	vattr;
		struct execenv	exenv;
	} *bigwad;	/* kmem_alloc this behemoth so we don't blow stack */
	Ehdr		*ehdrp;
	uint_t		nshdrs, shstrndx, nphdrs;
	size_t		phdrsize;
	char		*dlnp;
	char		*pathbufp;
	rlim64_t	limit;
	rlim64_t	roundlimit;

	ASSERT(p->p_model == DATAMODEL_ILP32 || p->p_model == DATAMODEL_LP64);

	bigwad = kmem_alloc(sizeof (struct bigwad), KM_SLEEP);
	ehdrp = &bigwad->ehdr;
	dlnp = bigwad->dl_name;
	pathbufp = bigwad->pathbuf;

	/*
	 * Obtain ELF and program header information.
	 */
	if ((error = getelfhead(vp, CRED(), ehdrp, &nshdrs, &shstrndx,
	    &nphdrs)) != 0 ||
	    (error = getelfphdr(vp, CRED(), ehdrp, nphdrs, &phdrbase,
	    &phdrsize)) != 0)
		goto out;

	/*
	 * Prevent executing an ELF file that has no entry point.
	 */
	if (ehdrp->e_entry == 0) {
		uprintf("%s: Bad entry point\n", exec_file);
		goto bad;
	}

	/*
	 * Put data model that we're exec-ing to into the args passed to
	 * exec_args(), so it will know what it is copying to on new stack.
	 * Now that we know whether we are exec-ing a 32-bit or 64-bit
	 * executable, we can set execsz with the appropriate NCARGS.
	 */
#ifdef	_LP64
	if (ehdrp->e_ident[EI_CLASS] == ELFCLASS32) {
		args->to_model = DATAMODEL_ILP32;
		*execsz = btopr(SINCR) + btopr(SSIZE) + btopr(NCARGS32-1);
	} else {
		args->to_model = DATAMODEL_LP64;
		if (!args->stk_prot_override) {
			args->stk_prot &= ~PROT_EXEC;
		}
#if defined(__i386) || defined(__amd64)
		args->dat_prot &= ~PROT_EXEC;
#endif
		*execsz = btopr(SINCR) + btopr(SSIZE) + btopr(NCARGS64-1);
	}
#else	/* _LP64 */
	args->to_model = DATAMODEL_ILP32;
	*execsz = btopr(SINCR) + btopr(SSIZE) + btopr(NCARGS-1);
#endif	/* _LP64 */

	/*
	 * We delay invoking the brand callback until we've figured out what
	 * kind of elf binary we're trying to run, 32-bit or 64-bit.  We do this
	 * because now the brand library can just check args->to_model to see if
	 * the target is 32-bit or 64-bit without having do duplicate all the
	 * code above.
	 *
	 * We also give the brand a chance to indicate that based on the ELF
	 * OSABI of the target binary it should become unbranded and optionally
	 * indicate that it should be treated as existing in a specific prefix.
	 *
	 * Note that if a brand opts to go down this route it does not actually
	 * end up being debranded. In other words, future programs that exec
	 * will still be considered for branding unless this escape hatch is
	 * used. Consider the case of lx brand for example. If a user runs
	 * /native/usr/sbin/dtrace -c /bin/ls, the isaexec and normal executable
	 * of DTrace that's in /native will take this escape hatch and be run
	 * and interpreted using the normal system call table; however, the
	 * execution of a non-illumos binary in the form of /bin/ls will still
	 * be branded and be subject to all of the normal actions of the brand.
	 *
	 * The level checks associated with brand handling below are used to
	 * prevent a loop since the brand elfexec function typically comes back
	 * through this function. We must check <= here since the nested
	 * handling in the #! interpreter code will increment the level before
	 * calling gexec to run the final elfexec interpreter.
	 */
	if ((level <= INTP_MAXDEPTH) && (*brand_action != EBA_NATIVE) &&
	    (PROC_IS_BRANDED(p)) && (BROP(p)->b_native_exec != NULL)) {
		if (BROP(p)->b_native_exec(ehdrp->e_ident[EI_OSABI],
		    &args->brand_nroot) == B_TRUE) {
			ASSERT(ehdrp->e_ident[EI_OSABI]);
			*brand_action = EBA_NATIVE;
			/* Add one for the trailing '/' in the path */
			if (args->brand_nroot != NULL)
				nsize = strlen(args->brand_nroot) + 1;
		}
	}

	if ((level <= INTP_MAXDEPTH) &&
	    (*brand_action != EBA_NATIVE) && (PROC_IS_BRANDED(p))) {
		error = BROP(p)->b_elfexec(vp, uap, args,
		    idatap, level + 1, execsz, setid, exec_file, cred,
		    brand_action);
		goto out;
	}

	/*
	 * Determine aux size now so that stack can be built
	 * in one shot (except actual copyout of aux image),
	 * determine any non-default stack protections,
	 * and still have this code be machine independent.
	 */
	const uint_t hsize = ehdrp->e_phentsize;
	phdrp = (Phdr *)phdrbase;
	for (i = nphdrs; i > 0; i--) {
		switch (phdrp->p_type) {
		case PT_INTERP:
			hasauxv = hasintp = 1;
			break;
		case PT_PHDR:
			hasu = 1;
			break;
		case PT_SUNWSTACK:
			args->stk_prot = PROT_USER;
			if (phdrp->p_flags & PF_R)
				args->stk_prot |= PROT_READ;
			if (phdrp->p_flags & PF_W)
				args->stk_prot |= PROT_WRITE;
			if (phdrp->p_flags & PF_X)
				args->stk_prot |= PROT_EXEC;
			break;
		case PT_LOAD:
			dataphdrp = phdrp;
			break;
		case PT_SUNWCAP:
			capphdr = phdrp;
			break;
		case PT_DYNAMIC:
			dynamicphdr = phdrp;
			break;
		}
		phdrp = (Phdr *)((caddr_t)phdrp + hsize);
	}

	if (ehdrp->e_type != ET_EXEC) {
		dataphdrp = NULL;
		hasauxv = 1;
	}

	/* Copy BSS permissions to args->dat_prot */
	if (dataphdrp != NULL) {
		args->dat_prot = PROT_USER;
		if (dataphdrp->p_flags & PF_R)
			args->dat_prot |= PROT_READ;
		if (dataphdrp->p_flags & PF_W)
			args->dat_prot |= PROT_WRITE;
		if (dataphdrp->p_flags & PF_X)
			args->dat_prot |= PROT_EXEC;
	}

	/*
	 * If a auxvector will be required - reserve the space for
	 * it now.  This may be increased by exec_args if there are
	 * ISA-specific types (included in __KERN_NAUXV_IMPL).
	 */
	if (hasauxv) {
		/*
		 * If a AUX vector is being built - the base AUX
		 * entries are:
		 *
		 *	AT_BASE
		 *	AT_FLAGS
		 *	AT_PAGESZ
		 *	AT_RANDOM	(added in stk_copyout)
		 *	AT_SUN_AUXFLAGS
		 *	AT_SUN_HWCAP
		 *	AT_SUN_HWCAP2
		 *	AT_SUN_PLATFORM	(added in stk_copyout)
		 *	AT_SUN_EXECNAME	(added in stk_copyout)
		 *	AT_NULL
		 *
		 * total == 10
		 */
		if (hasintp && hasu) {
			/*
			 * Has PT_INTERP & PT_PHDR - the auxvectors that
			 * will be built are:
			 *
			 *	AT_PHDR
			 *	AT_PHENT
			 *	AT_PHNUM
			 *	AT_ENTRY
			 *	AT_LDDATA
			 *
			 * total = 5
			 */
			args->auxsize = (10 + 5) * sizeof (aux_entry_t);
		} else if (hasintp) {
			/*
			 * Has PT_INTERP but no PT_PHDR
			 *
			 *	AT_EXECFD
			 *	AT_LDDATA
			 *
			 * total = 2
			 */
			args->auxsize = (10 + 2) * sizeof (aux_entry_t);
		} else {
			args->auxsize = 10 * sizeof (aux_entry_t);
		}
	} else {
		args->auxsize = 0;
	}

	/*
	 * If this binary is using an emulator, we need to add an
	 * AT_SUN_EMULATOR aux entry.
	 */
	if (args->emulator != NULL)
		args->auxsize += sizeof (aux_entry_t);

	/*
	 * If this is a native binary that's been given a modified interpreter
	 * root, inform it that the native system exists at that root.
	 */
	if (args->brand_nroot != NULL) {
		args->auxsize += sizeof (aux_entry_t);
	}


	/*
	 * On supported kernels (x86_64) make room in the auxv for the
	 * AT_SUN_COMMPAGE entry.  This will go unpopulated on i86xpv systems
	 * which do not provide such functionality.
	 *
	 * Additionally cover the floating point information AT_SUN_FPSIZE and
	 * AT_SUN_FPTYPE.
	 */
#if defined(__amd64)
	args->auxsize += 3 * sizeof (aux_entry_t);
#endif /* defined(__amd64) */

	/*
	 * If we have user credentials, we'll supply the following entries:
	 *	AT_SUN_UID
	 *	AT_SUN_RUID
	 *	AT_SUN_GID
	 *	AT_SUN_RGID
	 */
	if (cred != NULL) {
		args->auxsize += 4 * sizeof (aux_entry_t);
	}

	if ((*brand_action != EBA_NATIVE) && (PROC_IS_BRANDED(p))) {
		branded = 1;
		/*
		 * We will be adding 5 entries to the aux vectors.  One for
		 * the the brandname and 4 for the brand specific aux vectors.
		 */
		args->auxsize += 5 * sizeof (aux_entry_t);
	}

	/* If the binary has an explicit ASLR flag, it must be honoured */
	if ((dynamicphdr != NULL) && (dynamicphdr->p_filesz > 0)) {
		const size_t dynfilesz = dynamicphdr->p_filesz;
		const size_t dynoffset = dynamicphdr->p_offset;
		Dyn *dyn, *dp;

		if (dynoffset > MAXOFFSET_T ||
		    dynfilesz > MAXOFFSET_T ||
		    dynoffset + dynfilesz > MAXOFFSET_T) {
			uprintf("%s: cannot read full .dynamic section\n",
			    exec_file);
			error = EINVAL;
			goto out;
		}

#define	DYN_STRIDE	100
		for (i = 0; i < dynfilesz; i += sizeof (*dyn) * DYN_STRIDE) {
			const size_t remdyns = (dynfilesz - i) / sizeof (*dyn);
			const size_t ndyns = MIN(DYN_STRIDE, remdyns);
			const size_t dynsize = ndyns * sizeof (*dyn);

			dyn = kmem_alloc(dynsize, KM_SLEEP);

			if ((error = vn_rdwr(UIO_READ, vp, (caddr_t)dyn,
			    (ssize_t)dynsize, (offset_t)(dynoffset + i),
			    UIO_SYSSPACE, 0, (rlim64_t)0,
			    CRED(), NULL)) != 0) {
				uprintf("%s: cannot read .dynamic section\n",
				    exec_file);
				goto out;
			}

			for (dp = dyn; dp < (dyn + ndyns); dp++) {
				if (dp->d_tag == DT_SUNW_ASLR) {
					if ((error = handle_secflag_dt(p,
					    DT_SUNW_ASLR,
					    dp->d_un.d_val)) != 0) {
						uprintf("%s: error setting "
						    "security-flag from "
						    "DT_SUNW_ASLR: %d\n",
						    exec_file, error);
						goto out;
					}
				}
			}

			kmem_free(dyn, dynsize);
		}
	}

	/* Hardware/Software capabilities */
	if (capphdr != NULL &&
	    (capsize = capphdr->p_filesz) > 0 &&
	    capsize <= 16 * sizeof (*cap)) {
		const uint_t ncaps = capsize / sizeof (*cap);
		Cap *cp;

		cap = kmem_alloc(capsize, KM_SLEEP);
		if ((error = vn_rdwr(UIO_READ, vp, (caddr_t)cap,
		    (ssize_t)capsize, (offset_t)capphdr->p_offset,
		    UIO_SYSSPACE, 0, (rlim64_t)0, CRED(), NULL)) != 0) {
			uprintf("%s: Cannot read capabilities section\n",
			    exec_file);
			goto out;
		}
		for (cp = cap; cp < cap + ncaps; cp++) {
			if (cp->c_tag == CA_SUNW_SF_1 &&
			    (cp->c_un.c_val & SF1_SUNW_ADDR32)) {
				if (args->to_model == DATAMODEL_LP64)
					args->addr32 = 1;
				break;
			}
		}
	}

	aux = bigwad->elfargs;
	/*
	 * Move args to the user's stack.
	 * This can fill in the AT_SUN_PLATFORM, AT_SUN_EXECNAME and AT_RANDOM
	 * aux entries.
	 */
	if ((error = exec_args(uap, args, idatap, (void **)&aux)) != 0) {
		if (error == -1) {
			error = ENOEXEC;
			goto bad;
		}
		goto out;
	}
	/* we're single threaded after this point */

	/*
	 * If this is an ET_DYN executable (shared object),
	 * determine its memory size so that mapelfexec() can load it.
	 */
	if (ehdrp->e_type == ET_DYN)
		len = elfsize(ehdrp, nphdrs, phdrbase, NULL);
	else
		len = 0;

	dtrphdr = NULL;

	error = mapelfexec(vp, ehdrp, nphdrs, phdrbase, &uphdr, &intphdr,
	    &stphdr, &dtrphdr, dataphdrp, &bssbase, &brkbase, &voffset, NULL,
	    len, execsz, &brksize);
	/*
	 * Our uphdr has been dynamically allocated if (and only if) its
	 * program header flags are clear.  To avoid leaks, this must be
	 * checked regardless of whether mapelfexec() emitted an error.
	 */
	dynuphdr = (uphdr != NULL && uphdr->p_flags == 0);

	if (error != 0) {
		goto bad;
	}

	if (uphdr != NULL && intphdr == NULL)
		goto bad;

	if (dtrphdr != NULL && dtrace_safe_phdr(dtrphdr, args, voffset) != 0) {
		uprintf("%s: Bad DTrace phdr in %s\n", exec_file, exec_file);
		goto bad;
	}

	if (intphdr != NULL) {
		size_t		len;
		uintptr_t	lddata;
		char		*p;
		struct vnode	*nvp;

		dlnsize = intphdr->p_filesz + nsize;

		/*
		 * Make sure none of the component pieces of dlnsize result in
		 * an oversized or zeroed result.
		 */
		if (intphdr->p_filesz > MAXPATHLEN || dlnsize > MAXPATHLEN ||
		    dlnsize == 0 || dlnsize < intphdr->p_filesz) {
			goto bad;
		}

		if (nsize != 0) {
			bcopy(args->brand_nroot, dlnp, nsize - 1);
			dlnp[nsize - 1] = '/';
		}

		/*
		 * Read in "interpreter" pathname.
		 */
		if ((error = vn_rdwr(UIO_READ, vp, dlnp + nsize,
		    (ssize_t)intphdr->p_filesz, (offset_t)intphdr->p_offset,
		    UIO_SYSSPACE, 0, (rlim64_t)0, CRED(), &resid)) != 0) {
			uprintf("%s: Cannot obtain interpreter pathname\n",
			    exec_file);
			goto bad;
		}

		if (resid != 0 || dlnp[dlnsize - 1] != '\0')
			goto bad;

		/*
		 * Search for '$ORIGIN' token in interpreter path.
		 * If found, expand it.
		 */
		for (p = dlnp; p = strchr(p, '$'); ) {
			uint_t	len, curlen;
			char	*_ptr;

			if (strncmp(++p, ORIGIN_STR, ORIGIN_STR_SIZE))
				continue;

			/*
			 * We don't support $ORIGIN on setid programs to close
			 * a potential attack vector.
			 */
			if ((setid & EXECSETID_SETID) != 0) {
				error = ENOEXEC;
				goto bad;
			}

			curlen = 0;
			len = p - dlnp - 1;
			if (len) {
				bcopy(dlnp, pathbufp, len);
				curlen += len;
			}
			if (_ptr = strrchr(args->pathname, '/')) {
				len = _ptr - args->pathname;
				if ((curlen + len) > MAXPATHLEN)
					break;

				bcopy(args->pathname, &pathbufp[curlen], len);
				curlen += len;
			} else {
				/*
				 * executable is a basename found in the
				 * current directory.  So - just substitue
				 * '.' for ORIGIN.
				 */
				pathbufp[curlen] = '.';
				curlen++;
			}
			p += ORIGIN_STR_SIZE;
			len = strlen(p);

			if ((curlen + len) > MAXPATHLEN)
				break;
			bcopy(p, &pathbufp[curlen], len);
			curlen += len;
			pathbufp[curlen++] = '\0';
			bcopy(pathbufp, dlnp, curlen);
		}

		/*
		 * /usr/lib/ld.so.1 is known to be a symlink to /lib/ld.so.1
		 * (and /usr/lib/64/ld.so.1 is a symlink to /lib/64/ld.so.1).
		 * Just in case /usr is not mounted, change it now.
		 */
		if (strcmp(dlnp, USR_LIB_RTLD) == 0)
			dlnp += 4;
		error = lookupname(dlnp, UIO_SYSSPACE, FOLLOW, NULLVPP, &nvp);
		if (error && dlnp != bigwad->dl_name) {
			/* new kernel, old user-level */
			error = lookupname(dlnp -= 4, UIO_SYSSPACE, FOLLOW,
			    NULLVPP, &nvp);
		}
		if (error) {
			uprintf("%s: Cannot find %s\n", exec_file, dlnp);
			goto bad;
		}

		/*
		 * Setup the "aux" vector.
		 */
		if (uphdr) {
			if (ehdrp->e_type == ET_DYN) {
				/* don't use the first page */
				bigwad->exenv.ex_brkbase = (caddr_t)PAGESIZE;
				bigwad->exenv.ex_bssbase = (caddr_t)PAGESIZE;
			} else {
				bigwad->exenv.ex_bssbase = bssbase;
				bigwad->exenv.ex_brkbase = brkbase;
			}
			bigwad->exenv.ex_brksize = brksize;
			bigwad->exenv.ex_magic = elfmagic;
			bigwad->exenv.ex_vp = vp;
			setexecenv(&bigwad->exenv);

			ADDAUX(aux, AT_PHDR, uphdr->p_vaddr + voffset)
			ADDAUX(aux, AT_PHENT, ehdrp->e_phentsize)
			ADDAUX(aux, AT_PHNUM, nphdrs)
			ADDAUX(aux, AT_ENTRY, ehdrp->e_entry + voffset)
		} else {
			if ((error = execopen(&vp, &fd)) != 0) {
				VN_RELE(nvp);
				goto bad;
			}

			ADDAUX(aux, AT_EXECFD, fd)
		}

		if ((error = execpermissions(nvp, &bigwad->vattr, args)) != 0) {
			VN_RELE(nvp);
			uprintf("%s: Cannot execute %s\n", exec_file, dlnp);
			goto bad;
		}

		/*
		 * Now obtain the ELF header along with the entire program
		 * header contained in "nvp".
		 */
		kmem_free(phdrbase, phdrsize);
		phdrbase = NULL;
		if ((error = getelfhead(nvp, CRED(), ehdrp, &nshdrs,
		    &shstrndx, &nphdrs)) != 0 ||
		    (error = getelfphdr(nvp, CRED(), ehdrp, nphdrs, &phdrbase,
		    &phdrsize)) != 0) {
			VN_RELE(nvp);
			uprintf("%s: Cannot read %s\n", exec_file, dlnp);
			goto bad;
		}

		/*
		 * Determine memory size of the "interpreter's" loadable
		 * sections.  This size is then used to obtain the virtual
		 * address of a hole, in the user's address space, large
		 * enough to map the "interpreter".
		 */
		if ((len = elfsize(ehdrp, nphdrs, phdrbase, &lddata)) == 0) {
			VN_RELE(nvp);
			uprintf("%s: Nothing to load in %s\n", exec_file, dlnp);
			goto bad;
		}

		dtrphdr = NULL;

		error = mapelfexec(nvp, ehdrp, nphdrs, phdrbase, NULL, &junk,
		    &junk, &dtrphdr, NULL, NULL, NULL, &voffset, NULL, len,
		    execsz, NULL);

		if (error || junk != NULL) {
			VN_RELE(nvp);
			uprintf("%s: Cannot map %s\n", exec_file, dlnp);
			goto bad;
		}

		/*
		 * We use the DTrace program header to initialize the
		 * architecture-specific user per-LWP location. The dtrace
		 * fasttrap provider requires ready access to per-LWP scratch
		 * space. We assume that there is only one such program header
		 * in the interpreter.
		 */
		if (dtrphdr != NULL &&
		    dtrace_safe_phdr(dtrphdr, args, voffset) != 0) {
			VN_RELE(nvp);
			uprintf("%s: Bad DTrace phdr in %s\n", exec_file, dlnp);
			goto bad;
		}

		VN_RELE(nvp);
		ADDAUX(aux, AT_SUN_LDDATA, voffset + lddata)
	}

	if (hasauxv) {
		int auxf = AF_SUN_HWCAPVERIFY;
#if defined(__amd64)
		size_t fpsize;
		int fptype;
#endif /* defined(__amd64) */

		/*
		 * Note: AT_SUN_PLATFORM, AT_SUN_EXECNAME and AT_RANDOM were
		 * filled in via exec_args()
		 */
		ADDAUX(aux, AT_BASE, voffset)
		ADDAUX(aux, AT_FLAGS, at_flags)
		ADDAUX(aux, AT_PAGESZ, PAGESIZE)
		/*
		 * Linker flags. (security)
		 * p_flag not yet set at this time.
		 * We rely on gexec() to provide us with the information.
		 * If the application is set-uid but this is not reflected
		 * in a mismatch between real/effective uids/gids, then
		 * don't treat this as a set-uid exec.  So we care about
		 * the EXECSETID_UGIDS flag but not the ...SETID flag.
		 */
		if ((setid &= ~EXECSETID_SETID) != 0)
			auxf |= AF_SUN_SETUGID;

		/*
		 * If we're running a native process from within a branded
		 * zone under pfexec then we clear the AF_SUN_SETUGID flag so
		 * that the native ld.so.1 is able to link with the native
		 * libraries instead of using the brand libraries that are
		 * installed in the zone.  We only do this for processes
		 * which we trust because we see they are already running
		 * under pfexec (where uid != euid).  This prevents a
		 * malicious user within the zone from crafting a wrapper to
		 * run native suid commands with unsecure libraries interposed.
		 */
		if ((*brand_action == EBA_NATIVE) && (PROC_IS_BRANDED(p) &&
		    (setid &= ~EXECSETID_SETID) != 0))
			auxf &= ~AF_SUN_SETUGID;

		/*
		 * Record the user addr of the auxflags aux vector entry
		 * since brands may optionally want to manipulate this field.
		 */
		args->auxp_auxflags =
		    (char *)((char *)args->stackend +
		    ((char *)&aux->a_type -
		    (char *)bigwad->elfargs));
		ADDAUX(aux, AT_SUN_AUXFLAGS, auxf);

		/*
		 * Record information about the real and effective user and
		 * group IDs.
		 */
		if (cred != NULL) {
			ADDAUX(aux, AT_SUN_UID, crgetuid(cred));
			ADDAUX(aux, AT_SUN_RUID, crgetruid(cred));
			ADDAUX(aux, AT_SUN_GID, crgetgid(cred));
			ADDAUX(aux, AT_SUN_RGID, crgetrgid(cred));
		}

		/*
		 * Hardware capability flag word (performance hints)
		 * Used for choosing faster library routines.
		 * (Potentially different between 32-bit and 64-bit ABIs)
		 */
#if defined(_LP64)
		if (args->to_model == DATAMODEL_NATIVE) {
			ADDAUX(aux, AT_SUN_HWCAP, auxv_hwcap)
			ADDAUX(aux, AT_SUN_HWCAP2, auxv_hwcap_2)
		} else {
			ADDAUX(aux, AT_SUN_HWCAP, auxv_hwcap32)
			ADDAUX(aux, AT_SUN_HWCAP2, auxv_hwcap32_2)
		}
#else
		ADDAUX(aux, AT_SUN_HWCAP, auxv_hwcap)
		ADDAUX(aux, AT_SUN_HWCAP2, auxv_hwcap_2)
#endif
		if (branded) {
			/*
			 * Reserve space for the brand-private aux vectors,
			 * and record the user addr of that space.
			 */
			args->auxp_brand =
			    (char *)((char *)args->stackend +
			    ((char *)&aux->a_type -
			    (char *)bigwad->elfargs));
			ADDAUX(aux, AT_SUN_BRAND_AUX1, 0)
			ADDAUX(aux, AT_SUN_BRAND_AUX2, 0)
			ADDAUX(aux, AT_SUN_BRAND_AUX3, 0)
			ADDAUX(aux, AT_SUN_BRAND_AUX4, 0)
		}

		/*
		 * Add the comm page auxv entry, mapping it in if needed. Also
		 * take care of the FPU entries.
		 */
#if defined(__amd64)
		if (args->commpage != NULL ||
		    (args->commpage = (uintptr_t)comm_page_mapin()) != NULL) {
			ADDAUX(aux, AT_SUN_COMMPAGE, args->commpage)
		} else {
			/*
			 * If the comm page cannot be mapped, pad out the auxv
			 * to satisfy later size checks.
			 */
			ADDAUX(aux, AT_NULL, 0)
		}

		fptype = AT_386_FPINFO_NONE;
		fpu_auxv_info(&fptype, &fpsize);
		if (fptype != AT_386_FPINFO_NONE) {
			ADDAUX(aux, AT_SUN_FPTYPE, fptype)
			ADDAUX(aux, AT_SUN_FPSIZE, fpsize)
		} else {
			ADDAUX(aux, AT_NULL, 0)
			ADDAUX(aux, AT_NULL, 0)
		}
#endif /* defined(__amd64) */

		ADDAUX(aux, AT_NULL, 0)
		postfixsize = (uintptr_t)aux - (uintptr_t)bigwad->elfargs;

		/*
		 * We make assumptions above when we determine how many aux
		 * vector entries we will be adding. However, if we have an
		 * invalid elf file, it is possible that mapelfexec might
		 * behave differently (but not return an error), in which case
		 * the number of aux entries we actually add will be different.
		 * We detect that now and error out.
		 */
		if (postfixsize != args->auxsize) {
			DTRACE_PROBE2(elfexec_badaux, size_t, postfixsize,
			    size_t, args->auxsize);
			goto bad;
		}
		ASSERT(postfixsize <= __KERN_NAUXV_IMPL * sizeof (aux_entry_t));
	}

	/*
	 * For the 64-bit kernel, the limit is big enough that rounding it up
	 * to a page can overflow the 64-bit limit, so we check for btopr()
	 * overflowing here by comparing it with the unrounded limit in pages.
	 * If it hasn't overflowed, compare the exec size with the rounded up
	 * limit in pages.  Otherwise, just compare with the unrounded limit.
	 */
	limit = btop(p->p_vmem_ctl);
	roundlimit = btopr(p->p_vmem_ctl);
	if ((roundlimit > limit && *execsz > roundlimit) ||
	    (roundlimit < limit && *execsz > limit)) {
		mutex_enter(&p->p_lock);
		(void) rctl_action(rctlproc_legacy[RLIMIT_VMEM], p->p_rctls, p,
		    RCA_SAFE);
		mutex_exit(&p->p_lock);
		error = ENOMEM;
		goto bad;
	}

	bzero(up->u_auxv, sizeof (up->u_auxv));
	up->u_commpagep = args->commpage;
	if (postfixsize) {
		size_t num_auxv;

		/*
		 * Copy the aux vector to the user stack.
		 */
		error = execpoststack(args, bigwad->elfargs, postfixsize);
		if (error)
			goto bad;

		/*
		 * Copy auxv to the process's user structure for use by /proc.
		 * If this is a branded process, the brand's exec routine will
		 * copy it's private entries to the user structure later. It
		 * relies on the fact that the blank entries are at the end.
		 */
		num_auxv = postfixsize / sizeof (aux_entry_t);
		ASSERT(num_auxv <= sizeof (up->u_auxv) / sizeof (auxv_t));
		aux = bigwad->elfargs;
		for (i = 0; i < num_auxv; i++) {
			up->u_auxv[i].a_type = aux[i].a_type;
			up->u_auxv[i].a_un.a_val = (aux_val_t)aux[i].a_un.a_val;
		}
	}

	/*
	 * Pass back the starting address so we can set the program counter.
	 */
	args->entry = (uintptr_t)(ehdrp->e_entry + voffset);

	if (!uphdr) {
		if (ehdrp->e_type == ET_DYN) {
			/*
			 * If we are executing a shared library which doesn't
			 * have a interpreter (probably ld.so.1) then
			 * we don't set the brkbase now.  Instead we
			 * delay it's setting until the first call
			 * via grow.c::brk().  This permits ld.so.1 to
			 * initialize brkbase to the tail of the executable it
			 * loads (which is where it needs to be).
			 */
			bigwad->exenv.ex_brkbase = (caddr_t)0;
			bigwad->exenv.ex_bssbase = (caddr_t)0;
			bigwad->exenv.ex_brksize = 0;
		} else {
			bigwad->exenv.ex_brkbase = brkbase;
			bigwad->exenv.ex_bssbase = bssbase;
			bigwad->exenv.ex_brksize = brksize;
		}
		bigwad->exenv.ex_magic = elfmagic;
		bigwad->exenv.ex_vp = vp;
		setexecenv(&bigwad->exenv);
	}

	ASSERT(error == 0);
	goto out;

bad:
	if (fd != -1)		/* did we open the a.out yet */
		(void) execclose(fd);

	psignal(p, SIGKILL);

	if (error == 0)
		error = ENOEXEC;
out:
	if (dynuphdr)
		kmem_free(uphdr, sizeof (Phdr));
	if (phdrbase != NULL)
		kmem_free(phdrbase, phdrsize);
	if (cap != NULL)
		kmem_free(cap, capsize);
	kmem_free(bigwad, sizeof (struct bigwad));
	return (error);
}

/*
 * Compute the memory size requirement for the ELF file.
 */
static size_t
elfsize(const Ehdr *ehdrp, uint_t nphdrs, const caddr_t phdrbase,
    uintptr_t *lddata)
{
	const Phdr *phdrp = (Phdr *)phdrbase;
	const uint_t hsize = ehdrp->e_phentsize;
	boolean_t dfirst = B_TRUE;
	uintptr_t loaddr = UINTPTR_MAX;
	uintptr_t hiaddr = 0;
	uint_t i;

	for (i = nphdrs; i > 0; i--) {
		if (phdrp->p_type == PT_LOAD) {
			const uintptr_t lo = phdrp->p_vaddr;
			const uintptr_t hi = lo + phdrp->p_memsz;

			loaddr = MIN(lo, loaddr);
			hiaddr = MAX(hi, hiaddr);

			/*
			 * save the address of the first data segment
			 * of a object - used for the AT_SUNW_LDDATA
			 * aux entry.
			 */
			if ((lddata != NULL) && dfirst &&
			    (phdrp->p_flags & PF_W)) {
				*lddata = lo;
				dfirst = B_FALSE;
			}
		}
		phdrp = (Phdr *)((caddr_t)phdrp + hsize);
	}

	if (hiaddr <= loaddr) {
		/* No non-zero PT_LOAD segment found */
		return (0);
	}

	return (roundup(hiaddr - (loaddr & PAGEMASK), PAGESIZE));
}

/*
 * Read in the ELF header and program header table.
 * SUSV3 requires:
 *	ENOEXEC	File format is not recognized
 *	EINVAL	Format recognized but execution not supported
 */
static int
getelfhead(vnode_t *vp, cred_t *credp, Ehdr *ehdr, uint_t *nshdrs,
    uint_t *shstrndx, uint_t *nphdrs)
{
	int error;
	ssize_t resid;

	/*
	 * We got here by the first two bytes in ident,
	 * now read the entire ELF header.
	 */
	if ((error = vn_rdwr(UIO_READ, vp, (caddr_t)ehdr, sizeof (Ehdr),
	    (offset_t)0, UIO_SYSSPACE, 0, (rlim64_t)0, credp, &resid)) != 0) {
		return (error);
	}

	/*
	 * Since a separate version is compiled for handling 32-bit and
	 * 64-bit ELF executables on a 64-bit kernel, the 64-bit version
	 * doesn't need to be able to deal with 32-bit ELF files.
	 */
	if (resid != 0 ||
	    ehdr->e_ident[EI_MAG2] != ELFMAG2 ||
	    ehdr->e_ident[EI_MAG3] != ELFMAG3) {
		return (ENOEXEC);
	}

	if ((ehdr->e_type != ET_EXEC && ehdr->e_type != ET_DYN) ||
#if defined(_ILP32) || defined(_ELF32_COMPAT)
	    ehdr->e_ident[EI_CLASS] != ELFCLASS32 ||
#else
	    ehdr->e_ident[EI_CLASS] != ELFCLASS64 ||
#endif
	    !elfheadcheck(ehdr->e_ident[EI_DATA], ehdr->e_machine,
	    ehdr->e_flags)) {
		return (EINVAL);
	}

	*nshdrs = ehdr->e_shnum;
	*shstrndx = ehdr->e_shstrndx;
	*nphdrs = ehdr->e_phnum;

	/*
	 * If e_shnum, e_shstrndx, or e_phnum is its sentinel value, we need
	 * to read in the section header at index zero to access the true
	 * values for those fields.
	 */
	if ((*nshdrs == 0 && ehdr->e_shoff != 0) ||
	    *shstrndx == SHN_XINDEX || *nphdrs == PN_XNUM) {
		Shdr shdr;

		if (ehdr->e_shoff == 0)
			return (EINVAL);

		if ((error = vn_rdwr(UIO_READ, vp, (caddr_t)&shdr,
		    sizeof (shdr), (offset_t)ehdr->e_shoff, UIO_SYSSPACE, 0,
		    (rlim64_t)0, credp, NULL)) != 0)
			return (error);

		if (*nshdrs == 0)
			*nshdrs = shdr.sh_size;
		if (*shstrndx == SHN_XINDEX)
			*shstrndx = shdr.sh_link;
		if (*nphdrs == PN_XNUM && shdr.sh_info != 0)
			*nphdrs = shdr.sh_info;
	}

	return (0);
}

/*
 * We use members through p_flags on 32-bit files and p_memsz on 64-bit files,
 * so e_phentsize must be at least large enough to include those members.
 */
#if !defined(_LP64) || defined(_ELF32_COMPAT)
#define	MINPHENTSZ	(offsetof(Phdr, p_flags) + \
			sizeof (((Phdr *)NULL)->p_flags))
#else
#define	MINPHENTSZ	(offsetof(Phdr, p_memsz) + \
			sizeof (((Phdr *)NULL)->p_memsz))
#endif

static int
getelfphdr(vnode_t *vp, cred_t *credp, const Ehdr *ehdr, uint_t nphdrs,
    caddr_t *phbasep, size_t *phsizep)
{
	int err;

	/*
	 * Ensure that e_phentsize is large enough for required fields to be
	 * accessible and will maintain 8-byte alignment.
	 */
	if (ehdr->e_phentsize < MINPHENTSZ || (ehdr->e_phentsize & 3))
		return (EINVAL);

	*phsizep = nphdrs * ehdr->e_phentsize;

	if (*phsizep > sizeof (Phdr) * elf_nphdr_max) {
		if ((*phbasep = kmem_alloc(*phsizep, KM_NOSLEEP)) == NULL)
			return (ENOMEM);
	} else {
		*phbasep = kmem_alloc(*phsizep, KM_SLEEP);
	}

	if ((err = vn_rdwr(UIO_READ, vp, *phbasep, (ssize_t)*phsizep,
	    (offset_t)ehdr->e_phoff, UIO_SYSSPACE, 0, (rlim64_t)0,
	    credp, NULL)) != 0) {
		kmem_free(*phbasep, *phsizep);
		*phbasep = NULL;
		return (err);
	}

	return (0);
}

#define	MINSHDRSZ	(offsetof(Shdr, sh_entsize) + \
			sizeof (((Shdr *)NULL)->sh_entsize))

static int
getelfshdr(vnode_t *vp, cred_t *credp, const Ehdr *ehdr, uint_t nshdrs,
    uint_t shstrndx, caddr_t *shbasep, size_t *shsizep, char **shstrbasep,
    size_t *shstrsizep)
{
	int err;
	Shdr *shdr;

	/*
	 * Since we're going to be using e_shentsize to iterate down the
	 * array of section headers, it must be 8-byte aligned or else
	 * a we might cause a misaligned access. We use all members through
	 * sh_entsize (on both 32- and 64-bit ELF files) so e_shentsize
	 * must be at least large enough to include that member. The index
	 * of the string table section must also be valid.
	 */
	if (ehdr->e_shentsize < MINSHDRSZ || (ehdr->e_shentsize & 3) ||
	    nshdrs == 0 || shstrndx >= nshdrs)
		return (EINVAL);

	*shsizep = nshdrs * ehdr->e_shentsize;

	if (*shsizep > sizeof (Shdr) * elf_nshdr_max) {
		if ((*shbasep = kmem_alloc(*shsizep, KM_NOSLEEP)) == NULL)
			return (ENOMEM);
	} else {
		*shbasep = kmem_alloc(*shsizep, KM_SLEEP);
	}

	if ((err = vn_rdwr(UIO_READ, vp, *shbasep, (ssize_t)*shsizep,
	    (offset_t)ehdr->e_shoff, UIO_SYSSPACE, 0, (rlim64_t)0,
	    credp, NULL)) != 0) {
		kmem_free(*shbasep, *shsizep);
		return (err);
	}

	/*
	 * Grab the section string table.  Walking through the shdrs is
	 * pointless if their names cannot be interrogated.
	 */
	shdr = (Shdr *)(*shbasep + shstrndx * ehdr->e_shentsize);
	if ((*shstrsizep = shdr->sh_size) == 0) {
		kmem_free(*shbasep, *shsizep);
		return (EINVAL);
	}

	if (*shstrsizep > elf_shstrtab_max) {
		if ((*shstrbasep = kmem_alloc(*shstrsizep,
		    KM_NOSLEEP)) == NULL) {
			kmem_free(*shbasep, *shsizep);
			return (ENOMEM);
		}
	} else {
		*shstrbasep = kmem_alloc(*shstrsizep, KM_SLEEP);
	}

	if ((err = vn_rdwr(UIO_READ, vp, *shstrbasep, (ssize_t)*shstrsizep,
	    (offset_t)shdr->sh_offset, UIO_SYSSPACE, 0, (rlim64_t)0,
	    credp, NULL)) != 0) {
		kmem_free(*shbasep, *shsizep);
		kmem_free(*shstrbasep, *shstrsizep);
		return (err);
	}

	/*
	 * Make sure the strtab is null-terminated to make sure we
	 * don't run off the end of the table.
	 */
	(*shstrbasep)[*shstrsizep - 1] = '\0';

	return (0);
}


int
elfreadhdr(vnode_t *vp, cred_t *credp, Ehdr *ehdrp, uint_t *nphdrs,
    caddr_t *phbasep, size_t *phsizep)
{
	int error;
	uint_t nshdrs, shstrndx;

	if ((error = getelfhead(vp, credp, ehdrp, &nshdrs, &shstrndx,
	    nphdrs)) != 0 ||
	    (error = getelfphdr(vp, credp, ehdrp, *nphdrs, phbasep,
	    phsizep)) != 0) {
		return (error);
	}
	return (0);
}


static int
mapelfexec(
	vnode_t *vp,
	Ehdr *ehdr,
	uint_t nphdrs,
	caddr_t phdrbase,
	Phdr **uphdr,
	Phdr **intphdr,
	Phdr **stphdr,
	Phdr **dtphdr,
	Phdr *dataphdrp,
	caddr_t *bssbase,
	caddr_t *brkbase,
	intptr_t *voffset,
	uintptr_t *minaddrp,
	size_t len,
	size_t *execsz,
	size_t *brksize)
{
	Phdr *phdr;
	int error, page, prot, lastprot = 0;
	caddr_t addr = NULL;
	caddr_t minaddr = (caddr_t)UINTPTR_MAX;
	uint_t i;
	size_t zfodsz, memsz;
	boolean_t ptload = B_FALSE;
	off_t offset;
	const uint_t hsize = ehdr->e_phentsize;
	uintptr_t lastaddr = 0;
	extern int use_brk_lpg;

	if (ehdr->e_type == ET_DYN) {
		caddr_t vaddr;
		secflagset_t flags = 0;
		/*
		 * Obtain the virtual address of a hole in the
		 * address space to map the "interpreter".
		 */
		if (secflag_enabled(curproc, PROC_SEC_ASLR))
			flags |= _MAP_RANDOMIZE;

		map_addr(&addr, len, (offset_t)0, 1, flags);
		if (addr == NULL)
			return (ENOMEM);

		/*
		 * Despite the fact that mmapobj(2) refuses to load them, we
		 * need to support executing ET_DYN objects that have a
		 * non-NULL p_vaddr.  When found in the wild, these objects
		 * are likely to be due to an old (and largely obviated) Linux
		 * facility, prelink(8), that rewrites shared objects to
		 * prefer specific (disjoint) virtual address ranges.  (Yes,
		 * this is putatively for performance -- and yes, it has
		 * limited applicability, many edge conditions and grisly
		 * failure modes; even for Linux, it's insane.)  As ELF
		 * mandates that the PT_LOAD segments be in p_vaddr order, we
		 * find the lowest p_vaddr by finding the first PT_LOAD
		 * segment.
		 */
		phdr = (Phdr *)phdrbase;
		for (i = nphdrs; i > 0; i--) {
			if (phdr->p_type == PT_LOAD) {
				addr = (caddr_t)(uintptr_t)phdr->p_vaddr;
				break;
			}
			phdr = (Phdr *)((caddr_t)phdr + hsize);
		}

		/*
		 * We have a non-zero p_vaddr in the first PT_LOAD segment --
		 * presumably because we're directly executing a prelink(8)'d
		 * ld-linux.so.  While we could correctly execute such an
		 * object without locating it at its desired p_vaddr (it is,
		 * after all, still relocatable), our inner antiquarian
		 * derives a perverse pleasure in accommodating the steampunk
		 * prelink(8) contraption -- goggles on!
		 */
		if ((vaddr = addr) != NULL) {
			if (as_gap(curproc->p_as, len, &addr, &len,
			    AH_LO, NULL) == -1 || addr != vaddr) {
				addr = NULL;
			}
		}

		if (addr == NULL) {
			/*
			 * We either have a NULL p_vaddr (the common case, by
			 * many orders of magnitude) or we have a non-NULL
			 * p_vaddr and we were unable to obtain the specified
			 * VA range (presumably because it's an illegal
			 * address).  Either way, obtain an address in which
			 * to map the interpreter.
			 */
			map_addr(&addr, len, (offset_t)0, 1, 0);
			if (addr == NULL)
				return (ENOMEM);
		}

		/*
		 * Our voffset is the difference between where we landed and
		 * where we wanted to be.
		 */
		*voffset = (uintptr_t)addr - (uintptr_t)vaddr;
	} else {
		*voffset = 0;
	}

	phdr = (Phdr *)phdrbase;
	for (i = nphdrs; i > 0; i--) {
		switch (phdr->p_type) {
		case PT_LOAD:
			ptload = B_TRUE;
			prot = PROT_USER;
			if (phdr->p_flags & PF_R)
				prot |= PROT_READ;
			if (phdr->p_flags & PF_W)
				prot |= PROT_WRITE;
			if (phdr->p_flags & PF_X)
				prot |= PROT_EXEC;

			addr = (caddr_t)((uintptr_t)phdr->p_vaddr + *voffset);

			if ((*intphdr != NULL) && uphdr != NULL &&
			    (*uphdr == NULL)) {
				/*
				 * The PT_PHDR program header is, strictly
				 * speaking, optional.  If we find that this
				 * is missing, we will determine the location
				 * of the program headers based on the address
				 * of the lowest PT_LOAD segment (namely, this
				 * one):  we subtract the p_offset to get to
				 * the ELF header and then add back the program
				 * header offset to get to the program headers.
				 * We then cons up a Phdr that corresponds to
				 * the (missing) PT_PHDR, setting the flags
				 * to 0 to denote that this is artificial and
				 * should (must) be freed by the caller.
				 */
				Phdr *cons;

				cons = kmem_zalloc(sizeof (Phdr), KM_SLEEP);

				cons->p_flags = 0;
				cons->p_type = PT_PHDR;
				cons->p_vaddr = ((uintptr_t)addr -
				    phdr->p_offset) + ehdr->e_phoff;

				*uphdr = cons;
			}

			/*
			 * The ELF spec dictates that p_filesz may not be
			 * larger than p_memsz in PT_LOAD segments.
			 */
			if (phdr->p_filesz > phdr->p_memsz) {
				error = EINVAL;
				goto bad;
			}

			/*
			 * Keep track of the segment with the lowest starting
			 * address.
			 */
			if (addr < minaddr)
				minaddr = addr;

			/*
			 * Segments need not correspond to page boundaries:
			 * they are permitted to share a page.  If two PT_LOAD
			 * segments share the same page, and the permissions
			 * of the segments differ, the behavior is historically
			 * that the permissions of the latter segment are used
			 * for the page that the two segments share.  This is
			 * also historically a non-issue:  binaries generated
			 * by most anything will make sure that two PT_LOAD
			 * segments with differing permissions don't actually
			 * share any pages.  However, there exist some crazy
			 * things out there (including at least an obscure
			 * Portuguese teaching language called G-Portugol) that
			 * actually do the wrong thing and expect it to work:
			 * they have a segment with execute permission share
			 * a page with a subsequent segment that does not
			 * have execute permissions and expect the resulting
			 * shared page to in fact be executable.  To accommodate
			 * such broken link editors, we take advantage of a
			 * latitude explicitly granted to the loader:  it is
			 * permitted to make _any_ PT_LOAD segment executable
			 * (provided that it is readable or writable).  If we
			 * see that we're sharing a page and that the previous
			 * page was executable, we will add execute permissions
			 * to our segment.
			 */
			if (btop(lastaddr) == btop((uintptr_t)addr) &&
			    (phdr->p_flags & (PF_R | PF_W)) &&
			    (lastprot & PROT_EXEC)) {
				prot |= PROT_EXEC;
			}

			lastaddr = (uintptr_t)addr + phdr->p_filesz;
			lastprot = prot;

			zfodsz = (size_t)phdr->p_memsz - phdr->p_filesz;

			offset = phdr->p_offset;
			if (((uintptr_t)offset & PAGEOFFSET) ==
			    ((uintptr_t)addr & PAGEOFFSET) &&
			    (!(vp->v_flag & VNOMAP))) {
				page = 1;
			} else {
				page = 0;
			}

			/*
			 * Set the heap pagesize for OOB when the bss size
			 * is known and use_brk_lpg is not 0.
			 */
			if (brksize != NULL && use_brk_lpg &&
			    zfodsz != 0 && phdr == dataphdrp &&
			    (prot & PROT_WRITE)) {
				const size_t tlen = P2NPHASE((uintptr_t)addr +
				    phdr->p_filesz, PAGESIZE);

				if (zfodsz > tlen) {
					const caddr_t taddr = addr +
					    phdr->p_filesz + tlen;

					/*
					 * Since a hole in the AS large enough
					 * for this object as calculated by
					 * elfsize() is available, we do not
					 * need to fear overflow for 'taddr'.
					 */
					curproc->p_brkpageszc =
					    page_szc(map_pgsz(MAPPGSZ_HEAP,
					    curproc, taddr, zfodsz - tlen, 0));
				}
			}

			if (curproc->p_brkpageszc != 0 && phdr == dataphdrp &&
			    (prot & PROT_WRITE)) {
				uint_t	szc = curproc->p_brkpageszc;
				size_t pgsz = page_get_pagesize(szc);
				caddr_t ebss = addr + phdr->p_memsz;
				/*
				 * If we need extra space to keep the BSS an
				 * integral number of pages in size, some of
				 * that space may fall beyond p_brkbase, so we
				 * need to set p_brksize to account for it
				 * being (logically) part of the brk.
				 */
				size_t extra_zfodsz;

				ASSERT(pgsz > PAGESIZE);

				extra_zfodsz = P2NPHASE((uintptr_t)ebss, pgsz);

				if (error = execmap(vp, addr, phdr->p_filesz,
				    zfodsz + extra_zfodsz, phdr->p_offset,
				    prot, page, szc))
					goto bad;
				if (brksize != NULL)
					*brksize = extra_zfodsz;
			} else {
				if (error = execmap(vp, addr, phdr->p_filesz,
				    zfodsz, phdr->p_offset, prot, page, 0))
					goto bad;
			}

			if (bssbase != NULL && addr >= *bssbase &&
			    phdr == dataphdrp) {
				*bssbase = addr + phdr->p_filesz;
			}
			if (brkbase != NULL && addr >= *brkbase) {
				*brkbase = addr + phdr->p_memsz;
			}

			memsz = btopr(phdr->p_memsz);
			if ((*execsz + memsz) < *execsz) {
				error = ENOMEM;
				goto bad;
			}
			*execsz += memsz;
			break;

		case PT_INTERP:
			/*
			 * The ELF specification is unequivocal about the
			 * PT_INTERP program header with respect to any PT_LOAD
			 * program header:  "If it is present, it must precede
			 * any loadable segment entry." Linux, however, makes
			 * no attempt to enforce this -- which has allowed some
			 * binary editing tools to get away with generating
			 * invalid ELF binaries in the respect that PT_INTERP
			 * occurs after the first PT_LOAD program header.  This
			 * is unfortunate (and of course, disappointing) but
			 * it's no worse than that: there is no reason that we
			 * can't process the PT_INTERP entry (if present) after
			 * one or more PT_LOAD entries.  We therefore
			 * deliberately do not check ptload here and always
			 * store dyphdr to be the PT_INTERP program header.
			 */
			*intphdr = phdr;
			break;

		case PT_SHLIB:
			*stphdr = phdr;
			break;

		case PT_PHDR:
			if (ptload || phdr->p_flags == 0)
				goto bad;

			if (uphdr != NULL)
				*uphdr = phdr;

			break;

		case PT_NULL:
		case PT_DYNAMIC:
		case PT_NOTE:
			break;

		case PT_SUNWDTRACE:
			if (dtphdr != NULL)
				*dtphdr = phdr;
			break;

		default:
			break;
		}
		phdr = (Phdr *)((caddr_t)phdr + hsize);
	}

	if (minaddrp != NULL) {
		ASSERT(minaddr != (caddr_t)UINTPTR_MAX);
		*minaddrp = (uintptr_t)minaddr;
	}

	if (brkbase != NULL && secflag_enabled(curproc, PROC_SEC_ASLR)) {
		size_t off;
		uintptr_t base = (uintptr_t)*brkbase;
		uintptr_t oend = base + *brksize;

		ASSERT(ISP2(aslr_max_brk_skew));

		(void) random_get_pseudo_bytes((uint8_t *)&off, sizeof (off));
		base += P2PHASE(off, aslr_max_brk_skew);
		base = P2ROUNDUP(base, PAGESIZE);
		*brkbase = (caddr_t)base;
		/*
		 * Above, we set *brksize to account for the possibility we
		 * had to grow the 'brk' in padding out the BSS to a page
		 * boundary.
		 *
		 * We now need to adjust that based on where we now are
		 * actually putting the brk.
		 */
		if (oend > base)
			*brksize = oend - base;
		else
			*brksize = 0;
	}

	return (0);
bad:
	if (error == 0)
		error = EINVAL;
	return (error);
}

int
elfnote(vnode_t *vp, offset_t *offsetp, int type, int descsz, void *desc,
    rlim64_t rlimit, cred_t *credp)
{
	Note note;
	int error;

	bzero(&note, sizeof (note));
	bcopy("CORE", note.name, 4);
	note.nhdr.n_type = type;
	/*
	 * The System V ABI states that n_namesz must be the length of the
	 * string that follows the Nhdr structure including the terminating
	 * null. The ABI also specifies that sufficient padding should be
	 * included so that the description that follows the name string
	 * begins on a 4- or 8-byte boundary for 32- and 64-bit binaries
	 * respectively. However, since this change was not made correctly
	 * at the time of the 64-bit port, both 32- and 64-bit binaries
	 * descriptions are only guaranteed to begin on a 4-byte boundary.
	 */
	note.nhdr.n_namesz = 5;
	note.nhdr.n_descsz = roundup(descsz, sizeof (Word));

	if (error = core_write(vp, UIO_SYSSPACE, *offsetp, &note,
	    sizeof (note), rlimit, credp))
		return (error);

	*offsetp += sizeof (note);

	if (error = core_write(vp, UIO_SYSSPACE, *offsetp, desc,
	    note.nhdr.n_descsz, rlimit, credp))
		return (error);

	*offsetp += note.nhdr.n_descsz;
	return (0);
}


/*
 * Copy the section data from one vnode to the section of another vnode.
 */
static void
elf_copy_scn(elf_core_ctx_t *ctx, const Shdr *src, vnode_t *src_vp, Shdr *dst)
{
	size_t n = src->sh_size;
	u_offset_t off = 0;
	const u_offset_t soff = src->sh_offset;
	const u_offset_t doff = ctx->ecc_doffset;
	void *buf = ctx->ecc_buf;
	vnode_t *dst_vp = ctx->ecc_vp;
	cred_t *credp = ctx->ecc_credp;

	/* Protect the copy loop below from overflow on the offsets */
	if (n > OFF_MAX || (n + soff) > OFF_MAX || (n + doff) > OFF_MAX ||
	    (n + soff) < n || (n + doff) < n) {
		dst->sh_size = 0;
		dst->sh_offset = 0;
		return;
	}

	while (n != 0) {
		const size_t len = MIN(ctx->ecc_bufsz, n);
		ssize_t resid;

		if (vn_rdwr(UIO_READ, src_vp, buf, (ssize_t)len,
		    (offset_t)(soff + off),
		    UIO_SYSSPACE, 0, (rlim64_t)0, credp, &resid) != 0 ||
		    resid >= len || resid < 0 ||
		    core_write(dst_vp, UIO_SYSSPACE, (offset_t)(doff + off),
		    buf, len - resid, ctx->ecc_rlimit, credp) != 0) {
			dst->sh_size = 0;
			dst->sh_offset = 0;
			return;
		}

		ASSERT(n >= len - resid);

		n -= len - resid;
		off += len - resid;
	}

	ctx->ecc_doffset += src->sh_size;
}

/*
 * Walk sections for a given ELF object, counting (or copying) those of
 * interest (CTF, symtab, strtab).
 */
static uint_t
elf_process_obj_scns(elf_core_ctx_t *ctx, vnode_t *mvp, caddr_t saddr,
    Shdr *v, uint_t idx, uint_t remain, shstrtab_t *shstrtab)
{
	Ehdr ehdr;
	const core_content_t content = ctx->ecc_content;
	cred_t *credp = ctx->ecc_credp;
	Shdr *ctf = NULL, *symtab = NULL, *strtab = NULL;
	uintptr_t off = 0;
	uint_t nshdrs, shstrndx, nphdrs, count = 0;
	u_offset_t *doffp = &ctx->ecc_doffset;
	boolean_t ctf_link = B_FALSE;
	caddr_t shbase;
	size_t shsize, shstrsize;
	char *shstrbase;

	if ((content & (CC_CONTENT_CTF | CC_CONTENT_SYMTAB)) == 0) {
		return (0);
	}

	if (getelfhead(mvp, credp, &ehdr, &nshdrs, &shstrndx, &nphdrs) != 0 ||
	    getelfshdr(mvp, credp, &ehdr, nshdrs, shstrndx, &shbase, &shsize,
	    &shstrbase, &shstrsize) != 0) {
		return (0);
	}

	/* Starting at index 1 skips SHT_NULL which is expected at index 0 */
	off = ehdr.e_shentsize;
	for (uint_t i = 1; i < nshdrs; i++, off += ehdr.e_shentsize) {
		Shdr *shdr, *symchk = NULL, *strchk;
		const char *name;

		shdr = (Shdr *)(shbase + off);
		if (shdr->sh_name >= shstrsize || shdr->sh_type == SHT_NULL)
			continue;

		name = shstrbase + shdr->sh_name;

		if (ctf == NULL &&
		    (content & CC_CONTENT_CTF) != 0 &&
		    strcmp(name, shstrtab_data[STR_CTF]) == 0) {
			ctf = shdr;
			if (ctf->sh_link != 0 && ctf->sh_link < nshdrs) {
				/* check linked symtab below */
				symchk = (Shdr *)(shbase +
				    shdr->sh_link * ehdr.e_shentsize);
				ctf_link = B_TRUE;
			} else {
				continue;
			}
		} else if (symtab == NULL &&
		    (content & CC_CONTENT_SYMTAB) != 0 &&
		    strcmp(name, shstrtab_data[STR_SYMTAB]) == 0) {
			symchk = shdr;
		} else {
			continue;
		}

		ASSERT(symchk != NULL);
		if ((symchk->sh_type != SHT_DYNSYM &&
		    symchk->sh_type != SHT_SYMTAB) ||
		    symchk->sh_link == 0 || symchk->sh_link >= nshdrs) {
			ctf_link = B_FALSE;
			continue;
		}
		strchk = (Shdr *)(shbase + symchk->sh_link * ehdr.e_shentsize);
		if (strchk->sh_type != SHT_STRTAB) {
			ctf_link = B_FALSE;
			continue;
		}
		symtab = symchk;
		strtab = strchk;

		if (symtab != NULL && ctf != NULL) {
			/* No other shdrs are of interest at this point */
			break;
		}
	}

	if (ctf != NULL)
		count += 1;
	if (symtab != NULL)
		count += 2;
	if (v == NULL || count == 0 || count > remain) {
		count = MIN(count, remain);
		goto done;
	}

	/* output CTF section */
	if (ctf != NULL) {
		elf_ctx_resize_scratch(ctx, ctf->sh_size);

		v[idx].sh_name = shstrtab_ndx(shstrtab, STR_CTF);
		v[idx].sh_addr = (Addr)(uintptr_t)saddr;
		v[idx].sh_type = SHT_PROGBITS;
		v[idx].sh_addralign = 4;
		*doffp = roundup(*doffp, v[idx].sh_addralign);
		v[idx].sh_offset = *doffp;
		v[idx].sh_size = ctf->sh_size;

		if (ctf_link) {
			/*
			 * The linked symtab (and strtab) will be output
			 * immediately after this CTF section.  Its shdr index
			 * directly follows this one.
			 */
			v[idx].sh_link = idx + 1;
			ASSERT(symtab != NULL);
		} else {
			v[idx].sh_link = 0;
		}
		elf_copy_scn(ctx, ctf, mvp, &v[idx]);
		idx++;
	}

	/* output SYMTAB/STRTAB sections */
	if (symtab != NULL) {
		uint_t symtab_name, strtab_name;

		elf_ctx_resize_scratch(ctx,
		    MAX(symtab->sh_size, strtab->sh_size));

		if (symtab->sh_type == SHT_DYNSYM) {
			symtab_name = shstrtab_ndx(shstrtab, STR_DYNSYM);
			strtab_name = shstrtab_ndx(shstrtab, STR_DYNSTR);
		} else {
			symtab_name = shstrtab_ndx(shstrtab, STR_SYMTAB);
			strtab_name = shstrtab_ndx(shstrtab, STR_STRTAB);
		}

		v[idx].sh_name = symtab_name;
		v[idx].sh_type = symtab->sh_type;
		v[idx].sh_addr = symtab->sh_addr;
		if (ehdr.e_type == ET_DYN || v[idx].sh_addr == 0)
			v[idx].sh_addr += (Addr)(uintptr_t)saddr;
		v[idx].sh_addralign = symtab->sh_addralign;
		*doffp = roundup(*doffp, v[idx].sh_addralign);
		v[idx].sh_offset = *doffp;
		v[idx].sh_size = symtab->sh_size;
		v[idx].sh_link = idx + 1;
		v[idx].sh_entsize = symtab->sh_entsize;
		v[idx].sh_info = symtab->sh_info;

		elf_copy_scn(ctx, symtab, mvp, &v[idx]);
		idx++;

		v[idx].sh_name = strtab_name;
		v[idx].sh_type = SHT_STRTAB;
		v[idx].sh_flags = SHF_STRINGS;
		v[idx].sh_addr = strtab->sh_addr;
		if (ehdr.e_type == ET_DYN || v[idx].sh_addr == 0)
			v[idx].sh_addr += (Addr)(uintptr_t)saddr;
		v[idx].sh_addralign = strtab->sh_addralign;
		*doffp = roundup(*doffp, v[idx].sh_addralign);
		v[idx].sh_offset = *doffp;
		v[idx].sh_size = strtab->sh_size;

		elf_copy_scn(ctx, strtab, mvp, &v[idx]);
		idx++;
	}

done:
	kmem_free(shstrbase, shstrsize);
	kmem_free(shbase, shsize);
	return (count);
}

/*
 * Walk mappings in process address space, examining those which correspond to
 * loaded objects.  It is called twice from elfcore: Once to simply count
 * relevant sections, and again later to copy those sections once an adequate
 * buffer has been allocated for the shdr details.
 */
static int
elf_process_scns(elf_core_ctx_t *ctx, Shdr *v, uint_t nv, uint_t *nshdrsp)
{
	vnode_t *lastvp = NULL;
	struct seg *seg;
	uint_t idx = 0, remain;
	shstrtab_t shstrtab;
	struct as *as = ctx->ecc_p->p_as;
	int error = 0;

	ASSERT(AS_WRITE_HELD(as));

	if (v != NULL) {
		ASSERT(nv != 0);

		shstrtab_init(&shstrtab);
		remain = nv;
	} else {
		ASSERT(nv == 0);

		/*
		 * The shdrs are being counted, rather than outputting them
		 * into a buffer.  Leave room for two entries: the SHT_NULL at
		 * index 0 and the shstrtab at the end.
		 */
		remain = UINT_MAX - 2;
	}

	/* Per the ELF spec, shdr index 0 is reserved. */
	idx = 1;
	for (seg = AS_SEGFIRST(as); seg != NULL; seg = AS_SEGNEXT(as, seg)) {
		vnode_t *mvp;
		void *tmp = NULL;
		caddr_t saddr = seg->s_base, naddr, eaddr;
		size_t segsize;
		uint_t count, prot;

		/*
		 * Since we're just looking for text segments of load
		 * objects, we only care about the protection bits; we don't
		 * care about the actual size of the segment so we use the
		 * reserved size. If the segment's size is zero, there's
		 * something fishy going on so we ignore this segment.
		 */
		if (seg->s_ops != &segvn_ops ||
		    SEGOP_GETVP(seg, seg->s_base, &mvp) != 0 ||
		    mvp == lastvp || mvp == NULL || mvp->v_type != VREG ||
		    (segsize = pr_getsegsize(seg, 1)) == 0)
			continue;

		eaddr = saddr + segsize;
		prot = pr_getprot(seg, 1, &tmp, &saddr, &naddr, eaddr);
		pr_getprot_done(&tmp);

		/*
		 * Skip this segment unless the protection bits look like
		 * what we'd expect for a text segment.
		 */
		if ((prot & (PROT_WRITE | PROT_EXEC)) != PROT_EXEC)
			continue;

		count = elf_process_obj_scns(ctx, mvp, saddr, v, idx, remain,
		    &shstrtab);

		ASSERT(count <= remain);
		ASSERT(v == NULL || (idx + count) < nv);

		remain -= count;
		idx += count;
		lastvp = mvp;
	}

	if (v == NULL) {
		if (idx == 1) {
			*nshdrsp = 0;
		} else {
			/* Include room for the shrstrtab at the end */
			*nshdrsp = idx + 1;
		}
		return (0);
	}

	if (idx != nv - 1) {
		cmn_err(CE_WARN, "elfcore: core dump failed for "
		    "process %d; address space is changing",
		    ctx->ecc_p->p_pid);
		return (EIO);
	}

	v[idx].sh_name = shstrtab_ndx(&shstrtab, STR_SHSTRTAB);
	v[idx].sh_size = shstrtab_size(&shstrtab);
	v[idx].sh_addralign = 1;
	v[idx].sh_offset = ctx->ecc_doffset;
	v[idx].sh_flags = SHF_STRINGS;
	v[idx].sh_type = SHT_STRTAB;

	elf_ctx_resize_scratch(ctx, v[idx].sh_size);
	VERIFY3U(ctx->ecc_bufsz, >=, v[idx].sh_size);
	shstrtab_dump(&shstrtab, ctx->ecc_buf);

	error = core_write(ctx->ecc_vp, UIO_SYSSPACE, ctx->ecc_doffset,
	    ctx->ecc_buf, v[idx].sh_size, ctx->ecc_rlimit, ctx->ecc_credp);
	if (error == 0) {
		ctx->ecc_doffset += v[idx].sh_size;
	}

	return (error);
}

int
elfcore(vnode_t *vp, proc_t *p, cred_t *credp, rlim64_t rlimit, int sig,
    core_content_t content)
{
	u_offset_t poffset, soffset, doffset;
	int error;
	uint_t i, nphdrs, nshdrs;
	struct seg *seg;
	struct as *as = p->p_as;
	void *bigwad;
	size_t bigsize, phdrsz, shdrsz;
	Ehdr *ehdr;
	Phdr *phdr;
	Shdr shdr0;
	caddr_t brkbase, stkbase;
	size_t brksize, stksize;
	boolean_t overflowed = B_FALSE, retried = B_FALSE;
	klwp_t *lwp = ttolwp(curthread);
	elf_core_ctx_t ctx = {
		.ecc_vp = vp,
		.ecc_p = p,
		.ecc_credp = credp,
		.ecc_rlimit = rlimit,
		.ecc_content = content,
		.ecc_doffset = 0,
		.ecc_buf = NULL,
		.ecc_bufsz = 0
	};

top:
	/*
	 * Make sure we have everything we need (registers, etc.).
	 * All other lwps have already stopped and are in an orderly state.
	 */
	ASSERT(p == ttoproc(curthread));
	prstop(0, 0);

	AS_LOCK_ENTER(as, RW_WRITER);
	nphdrs = prnsegs(as, 0) + 2;		/* two CORE note sections */

	/*
	 * Count the number of section headers we're going to need.
	 */
	nshdrs = 0;
	if (content & (CC_CONTENT_CTF | CC_CONTENT_SYMTAB)) {
		VERIFY0(elf_process_scns(&ctx, NULL, 0, &nshdrs));
	}
	AS_LOCK_EXIT(as);

	/*
	 * The core file contents may require zero section headers, but if
	 * we overflow the 16 bits allotted to the program header count in
	 * the ELF header, we'll need that program header at index zero.
	 */
	if (nshdrs == 0 && nphdrs >= PN_XNUM) {
		nshdrs = 1;
	}

	/*
	 * Allocate a buffer which is sized adequately to hold the ehdr, phdrs
	 * or shdrs needed to produce the core file.  It is used for the three
	 * tasks sequentially, not simultaneously, so it does not need space
	 * for all three data at once, only the largest one.
	 */
	VERIFY(nphdrs >= 2);
	phdrsz = nphdrs * sizeof (Phdr);
	shdrsz = nshdrs * sizeof (Shdr);
	bigsize = MAX(sizeof (Ehdr), MAX(phdrsz, shdrsz));
	bigwad = kmem_alloc(bigsize, KM_SLEEP);

	ehdr = (Ehdr *)bigwad;
	bzero(ehdr, sizeof (*ehdr));

	ehdr->e_ident[EI_MAG0] = ELFMAG0;
	ehdr->e_ident[EI_MAG1] = ELFMAG1;
	ehdr->e_ident[EI_MAG2] = ELFMAG2;
	ehdr->e_ident[EI_MAG3] = ELFMAG3;
	ehdr->e_ident[EI_CLASS] = ELFCLASS;
	ehdr->e_type = ET_CORE;

#if !defined(_LP64) || defined(_ELF32_COMPAT)

#if defined(__sparc)
	ehdr->e_ident[EI_DATA] = ELFDATA2MSB;
	ehdr->e_machine = EM_SPARC;
#elif defined(__i386) || defined(__i386_COMPAT)
	ehdr->e_ident[EI_DATA] = ELFDATA2LSB;
	ehdr->e_machine = EM_386;
#else
#error "no recognized machine type is defined"
#endif

#else	/* !defined(_LP64) || defined(_ELF32_COMPAT) */

#if defined(__sparc)
	ehdr->e_ident[EI_DATA] = ELFDATA2MSB;
	ehdr->e_machine = EM_SPARCV9;
#elif defined(__amd64)
	ehdr->e_ident[EI_DATA] = ELFDATA2LSB;
	ehdr->e_machine = EM_AMD64;
#else
#error "no recognized 64-bit machine type is defined"
#endif

#endif	/* !defined(_LP64) || defined(_ELF32_COMPAT) */

	poffset = sizeof (Ehdr);
	soffset = sizeof (Ehdr) + phdrsz;
	doffset = sizeof (Ehdr) + phdrsz + shdrsz;
	bzero(&shdr0, sizeof (shdr0));

	/*
	 * If the count of program headers or section headers or the index
	 * of the section string table can't fit in the mere 16 bits
	 * shortsightedly allotted to them in the ELF header, we use the
	 * extended formats and put the real values in the section header
	 * as index 0.
	 */
	if (nphdrs >= PN_XNUM) {
		ehdr->e_phnum = PN_XNUM;
		shdr0.sh_info = nphdrs;
	} else {
		ehdr->e_phnum = (unsigned short)nphdrs;
	}

	if (nshdrs > 0) {
		if (nshdrs >= SHN_LORESERVE) {
			ehdr->e_shnum = 0;
			shdr0.sh_size = nshdrs;
		} else {
			ehdr->e_shnum = (unsigned short)nshdrs;
		}

		if (nshdrs - 1 >= SHN_LORESERVE) {
			ehdr->e_shstrndx = SHN_XINDEX;
			shdr0.sh_link = nshdrs - 1;
		} else {
			ehdr->e_shstrndx = (unsigned short)(nshdrs - 1);
		}

		ehdr->e_shoff = soffset;
		ehdr->e_shentsize = sizeof (Shdr);
	}

	ehdr->e_version = EV_CURRENT;
	ehdr->e_ehsize = sizeof (Ehdr);
	ehdr->e_phoff = poffset;
	ehdr->e_phentsize = sizeof (Phdr);

	if (error = core_write(vp, UIO_SYSSPACE, (offset_t)0, ehdr,
	    sizeof (Ehdr), rlimit, credp)) {
		goto done;
	}

	phdr = (Phdr *)bigwad;
	bzero(phdr, phdrsz);

	setup_old_note_header(&phdr[0], p);
	phdr[0].p_offset = doffset = roundup(doffset, sizeof (Word));
	doffset += phdr[0].p_filesz;

	setup_note_header(&phdr[1], p);
	phdr[1].p_offset = doffset = roundup(doffset, sizeof (Word));
	doffset += phdr[1].p_filesz;

	mutex_enter(&p->p_lock);

	brkbase = p->p_brkbase;
	brksize = p->p_brksize;

	stkbase = p->p_usrstack - p->p_stksize;
	stksize = p->p_stksize;

	mutex_exit(&p->p_lock);

	AS_LOCK_ENTER(as, RW_WRITER);
	i = 2;
	for (seg = AS_SEGFIRST(as); seg != NULL; seg = AS_SEGNEXT(as, seg)) {
		caddr_t eaddr = seg->s_base + pr_getsegsize(seg, 0);
		caddr_t saddr, naddr;
		void *tmp = NULL;
		extern struct seg_ops segspt_shmops;

		if ((seg->s_flags & S_HOLE) != 0) {
			continue;
		}

		for (saddr = seg->s_base; saddr < eaddr; saddr = naddr) {
			uint_t prot;
			size_t size;
			int type;
			vnode_t *mvp;

			prot = pr_getprot(seg, 0, &tmp, &saddr, &naddr, eaddr);
			prot &= PROT_READ | PROT_WRITE | PROT_EXEC;
			if ((size = (size_t)(naddr - saddr)) == 0) {
				ASSERT(tmp == NULL);
				continue;
			} else if (i == nphdrs) {
				pr_getprot_done(&tmp);
				overflowed = B_TRUE;
				break;
			}
			phdr[i].p_type = PT_LOAD;
			phdr[i].p_vaddr = (Addr)(uintptr_t)saddr;
			phdr[i].p_memsz = size;
			if (prot & PROT_READ)
				phdr[i].p_flags |= PF_R;
			if (prot & PROT_WRITE)
				phdr[i].p_flags |= PF_W;
			if (prot & PROT_EXEC)
				phdr[i].p_flags |= PF_X;

			/*
			 * Figure out which mappings to include in the core.
			 */
			type = SEGOP_GETTYPE(seg, saddr);

			if (saddr == stkbase && size == stksize) {
				if (!(content & CC_CONTENT_STACK))
					goto exclude;

			} else if (saddr == brkbase && size == brksize) {
				if (!(content & CC_CONTENT_HEAP))
					goto exclude;

			} else if (seg->s_ops == &segspt_shmops) {
				if (type & MAP_NORESERVE) {
					if (!(content & CC_CONTENT_DISM))
						goto exclude;
				} else {
					if (!(content & CC_CONTENT_ISM))
						goto exclude;
				}

			} else if (seg->s_ops != &segvn_ops) {
				goto exclude;

			} else if (type & MAP_SHARED) {
				if (shmgetid(p, saddr) != SHMID_NONE) {
					if (!(content & CC_CONTENT_SHM))
						goto exclude;

				} else if (SEGOP_GETVP(seg, seg->s_base,
				    &mvp) != 0 || mvp == NULL ||
				    mvp->v_type != VREG) {
					if (!(content & CC_CONTENT_SHANON))
						goto exclude;

				} else {
					if (!(content & CC_CONTENT_SHFILE))
						goto exclude;
				}

			} else if (SEGOP_GETVP(seg, seg->s_base, &mvp) != 0 ||
			    mvp == NULL || mvp->v_type != VREG) {
				if (!(content & CC_CONTENT_ANON))
					goto exclude;

			} else if (prot == (PROT_READ | PROT_EXEC)) {
				if (!(content & CC_CONTENT_TEXT))
					goto exclude;

			} else if (prot == PROT_READ) {
				if (!(content & CC_CONTENT_RODATA))
					goto exclude;

			} else {
				if (!(content & CC_CONTENT_DATA))
					goto exclude;
			}

			doffset = roundup(doffset, sizeof (Word));
			phdr[i].p_offset = doffset;
			phdr[i].p_filesz = size;
			doffset += size;
exclude:
			i++;
		}
		VERIFY(tmp == NULL);
		if (overflowed)
			break;
	}
	AS_LOCK_EXIT(as);

	if (overflowed || i != nphdrs) {
		if (!retried) {
			retried = B_TRUE;
			overflowed = B_FALSE;
			kmem_free(bigwad, bigsize);
			goto top;
		}
		cmn_err(CE_WARN, "elfcore: core dump failed for "
		    "process %d; address space is changing", p->p_pid);
		error = EIO;
		goto done;
	}

	if ((error = core_write(vp, UIO_SYSSPACE, poffset,
	    phdr, phdrsz, rlimit, credp)) != 0) {
		goto done;
	}

	if ((error = write_old_elfnotes(p, sig, vp, phdr[0].p_offset, rlimit,
	    credp)) != 0) {
		goto done;
	}
	if ((error = write_elfnotes(p, sig, vp, phdr[1].p_offset, rlimit,
	    credp, content)) != 0) {
		goto done;
	}

	for (i = 2; i < nphdrs; i++) {
		prkillinfo_t killinfo;
		sigqueue_t *sq;
		int sig, j;

		if (phdr[i].p_filesz == 0)
			continue;

		/*
		 * If dumping out this segment fails, rather than failing
		 * the core dump entirely, we reset the size of the mapping
		 * to zero to indicate that the data is absent from the core
		 * file and or in the PF_SUNW_FAILURE flag to differentiate
		 * this from mappings that were excluded due to the core file
		 * content settings.
		 */
		if ((error = core_seg(p, vp, phdr[i].p_offset,
		    (caddr_t)(uintptr_t)phdr[i].p_vaddr, phdr[i].p_filesz,
		    rlimit, credp)) == 0) {
			continue;
		}

		if ((sig = lwp->lwp_cursig) == 0) {
			/*
			 * We failed due to something other than a signal.
			 * Since the space reserved for the segment is now
			 * unused, we stash the errno in the first four
			 * bytes. This undocumented interface will let us
			 * understand the nature of the failure.
			 */
			(void) core_write(vp, UIO_SYSSPACE, phdr[i].p_offset,
			    &error, sizeof (error), rlimit, credp);

			phdr[i].p_filesz = 0;
			phdr[i].p_flags |= PF_SUNW_FAILURE;
			if ((error = core_write(vp, UIO_SYSSPACE,
			    poffset + sizeof (Phdr) * i, &phdr[i],
			    sizeof (Phdr), rlimit, credp)) != 0)
				goto done;

			continue;
		}

		/*
		 * We took a signal.  We want to abort the dump entirely, but
		 * we also want to indicate what failed and why.  We therefore
		 * use the space reserved for the first failing segment to
		 * write our error (which, for purposes of compatability with
		 * older core dump readers, we set to EINTR) followed by any
		 * siginfo associated with the signal.
		 */
		bzero(&killinfo, sizeof (killinfo));
		killinfo.prk_error = EINTR;

		sq = sig == SIGKILL ? curproc->p_killsqp : lwp->lwp_curinfo;

		if (sq != NULL) {
			bcopy(&sq->sq_info, &killinfo.prk_info,
			    sizeof (sq->sq_info));
		} else {
			killinfo.prk_info.si_signo = lwp->lwp_cursig;
			killinfo.prk_info.si_code = SI_NOINFO;
		}

#if (defined(_SYSCALL32_IMPL) || defined(_LP64))
		/*
		 * If this is a 32-bit process, we need to translate from the
		 * native siginfo to the 32-bit variant.  (Core readers must
		 * always have the same data model as their target or must
		 * be aware of -- and compensate for -- data model differences.)
		 */
		if (curproc->p_model == DATAMODEL_ILP32) {
			siginfo32_t si32;

			siginfo_kto32((k_siginfo_t *)&killinfo.prk_info, &si32);
			bcopy(&si32, &killinfo.prk_info, sizeof (si32));
		}
#endif

		(void) core_write(vp, UIO_SYSSPACE, phdr[i].p_offset,
		    &killinfo, sizeof (killinfo), rlimit, credp);

		/*
		 * For the segment on which we took the signal, indicate that
		 * its data now refers to a siginfo.
		 */
		phdr[i].p_filesz = 0;
		phdr[i].p_flags |= PF_SUNW_FAILURE | PF_SUNW_KILLED |
		    PF_SUNW_SIGINFO;

		/*
		 * And for every other segment, indicate that its absence
		 * is due to a signal.
		 */
		for (j = i + 1; j < nphdrs; j++) {
			phdr[j].p_filesz = 0;
			phdr[j].p_flags |= PF_SUNW_FAILURE | PF_SUNW_KILLED;
		}

		/*
		 * Finally, write out our modified program headers.
		 */
		if ((error = core_write(vp, UIO_SYSSPACE,
		    poffset + sizeof (Phdr) * i, &phdr[i],
		    sizeof (Phdr) * (nphdrs - i), rlimit, credp)) != 0) {
			goto done;
		}

		break;
	}

	if (nshdrs > 0) {
		Shdr *shdr = (Shdr *)bigwad;

		bzero(shdr, shdrsz);
		if (nshdrs > 1) {
			ctx.ecc_doffset = doffset;
			AS_LOCK_ENTER(as, RW_WRITER);
			error = elf_process_scns(&ctx, shdr, nshdrs, NULL);
			AS_LOCK_EXIT(as);
			if (error != 0) {
				goto done;
			}
		}
		/* Copy any extended format data destined for the first shdr */
		bcopy(&shdr0, shdr, sizeof (shdr0));

		error = core_write(vp, UIO_SYSSPACE, soffset, shdr, shdrsz,
		    rlimit, credp);
	}

done:
	if (ctx.ecc_bufsz != 0) {
		kmem_free(ctx.ecc_buf, ctx.ecc_bufsz);
	}
	kmem_free(bigwad, bigsize);
	return (error);
}

#ifndef	_ELF32_COMPAT

static struct execsw esw = {
#ifdef	_LP64
	elf64magicstr,
#else	/* _LP64 */
	elf32magicstr,
#endif	/* _LP64 */
	0,
	5,
	elfexec,
	elfcore
};

static struct modlexec modlexec = {
	&mod_execops, "exec module for elf", &esw
};

#ifdef	_LP64
extern int elf32exec(vnode_t *vp, execa_t *uap, uarg_t *args,
			intpdata_t *idatap, int level, size_t *execsz,
			int setid, caddr_t exec_file, cred_t *cred,
			int *brand_action);
extern int elf32core(vnode_t *vp, proc_t *p, cred_t *credp,
			rlim64_t rlimit, int sig, core_content_t content);

static struct execsw esw32 = {
	elf32magicstr,
	0,
	5,
	elf32exec,
	elf32core
};

static struct modlexec modlexec32 = {
	&mod_execops, "32-bit exec module for elf", &esw32
};
#endif	/* _LP64 */

static struct modlinkage modlinkage = {
	MODREV_1,
	(void *)&modlexec,
#ifdef	_LP64
	(void *)&modlexec32,
#endif	/* _LP64 */
	NULL
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

#endif	/* !_ELF32_COMPAT */
