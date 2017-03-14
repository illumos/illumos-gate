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
/*	  All Rights Reserved  	*/
/*
 * Copyright 2016 Joyent, Inc.
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
#endif /* defined(__x86) */


extern int at_flags;
extern volatile size_t aslr_max_brk_skew;

#define	ORIGIN_STR	"ORIGIN"
#define	ORIGIN_STR_SIZE	6

static int getelfhead(vnode_t *, cred_t *, Ehdr *, int *, int *, int *);
static int getelfphdr(vnode_t *, cred_t *, const Ehdr *, int, caddr_t *,
    ssize_t *);
static int getelfshdr(vnode_t *, cred_t *, const Ehdr *, int, int, caddr_t *,
    ssize_t *, caddr_t *, ssize_t *);
static size_t elfsize(Ehdr *, int, caddr_t, uintptr_t *);
static int mapelfexec(vnode_t *, Ehdr *, int, caddr_t,
    Phdr **, Phdr **, Phdr **, Phdr **, Phdr *,
    caddr_t *, caddr_t *, intptr_t *, intptr_t *, size_t, long *, size_t *);

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
	int	sst_ndx[STR_NUM];
	int	sst_cur;
} shstrtab_t;

static void
shstrtab_init(shstrtab_t *s)
{
	bzero(&s->sst_ndx, sizeof (s->sst_ndx));
	s->sst_cur = 1;
}

static int
shstrtab_ndx(shstrtab_t *s, shstrtype_t type)
{
	int ret;

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
	int i, ndx;

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

/*
 * Map in the executable pointed to by vp. Returns 0 on success.
 */
int
mapexec_brand(vnode_t *vp, uarg_t *args, Ehdr *ehdr, Addr *uphdr_vaddr,
    intptr_t *voffset, caddr_t exec_file, int *interp, caddr_t *bssbase,
    caddr_t *brkbase, size_t *brksize, uintptr_t *lddatap)
{
	size_t		len;
	struct vattr	vat;
	caddr_t		phdrbase = NULL;
	ssize_t		phdrsize;
	int		nshdrs, shstrndx, nphdrs;
	int		error = 0;
	Phdr		*uphdr = NULL;
	Phdr		*junk = NULL;
	Phdr		*dynphdr = NULL;
	Phdr		*dtrphdr = NULL;
	uintptr_t	lddata;
	long		execsz;
	intptr_t	minaddr;

	if (lddatap != NULL)
		*lddatap = NULL;

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
		kmem_free(phdrbase, phdrsize);
		return (error);
	}

	/*
	 * Inform our caller if the executable needs an interpreter.
	 */
	*interp = (dynphdr == NULL) ? 0 : 1;

	/*
	 * If this is a statically linked executable, voffset should indicate
	 * the address of the executable itself (it normally holds the address
	 * of the interpreter).
	 */
	if (ehdr->e_type == ET_EXEC && *interp == 0)
		*voffset = minaddr;

	if (uphdr != NULL) {
		*uphdr_vaddr = uphdr->p_vaddr;
	} else {
		*uphdr_vaddr = (Addr)-1;
	}

	kmem_free(phdrbase, phdrsize);
	return (error);
}

/*ARGSUSED*/
int
elfexec(vnode_t *vp, execa_t *uap, uarg_t *args, intpdata_t *idatap,
    int level, long *execsz, int setid, caddr_t exec_file, cred_t *cred,
    int brand_action)
{
	caddr_t		phdrbase = NULL;
	caddr_t 	bssbase = 0;
	caddr_t 	brkbase = 0;
	size_t		brksize = 0;
	ssize_t		dlnsize;
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
	ssize_t		phdrsize;
	int		postfixsize = 0;
	int		i, hsize;
	Phdr		*phdrp;
	Phdr		*dataphdrp = NULL;
	Phdr		*dtrphdr;
	Phdr		*capphdr = NULL;
	Cap		*cap = NULL;
	ssize_t		capsize;
	Dyn		*dyn = NULL;
	int		hasu = 0;
	int		hasauxv = 0;
	int		hasintp = 0;
	int		branded = 0;

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
	int		nshdrs, shstrndx, nphdrs;
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
		args->stk_prot &= ~PROT_EXEC;
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
	 * We delay invoking the brand callback until we've figured out
	 * what kind of elf binary we're trying to run, 32-bit or 64-bit.
	 * We do this because now the brand library can just check
	 * args->to_model to see if the target is 32-bit or 64-bit without
	 * having do duplicate all the code above.
	 *
	 * The level checks associated with brand handling below are used to
	 * prevent a loop since the brand elfexec function typically comes back
	 * through this function. We must check <= here since the nested
	 * handling in the #! interpreter code will increment the level before
	 * calling gexec to run the final elfexec interpreter.
	 */
	if ((level <= INTP_MAXDEPTH) &&
	    (brand_action != EBA_NATIVE) && (PROC_IS_BRANDED(p))) {
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
	hsize = ehdrp->e_phentsize;
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
		 *	AT_SUN_AUXFLAGS
		 *	AT_SUN_HWCAP
		 *	AT_SUN_HWCAP2
		 *	AT_SUN_PLATFORM (added in stk_copyout)
		 *	AT_SUN_EXECNAME (added in stk_copyout)
		 *	AT_NULL
		 *
		 * total == 9
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
			args->auxsize = (9 + 5) * sizeof (aux_entry_t);
		} else if (hasintp) {
			/*
			 * Has PT_INTERP but no PT_PHDR
			 *
			 *	AT_EXECFD
			 *	AT_LDDATA
			 *
			 * total = 2
			 */
			args->auxsize = (9 + 2) * sizeof (aux_entry_t);
		} else {
			args->auxsize = 9 * sizeof (aux_entry_t);
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
	 * On supported kernels (x86_64) make room in the auxv for the
	 * AT_SUN_COMMPAGE entry.  This will go unpopulated on i86xpv systems
	 * which do not provide such functionality.
	 */
#if defined(__amd64)
	args->auxsize += sizeof (aux_entry_t);
#endif /* defined(__amd64) */

	if ((brand_action != EBA_NATIVE) && (PROC_IS_BRANDED(p))) {
		branded = 1;
		/*
		 * We will be adding 4 entries to the aux vectors.  One for
		 * the the brandname and 3 for the brand specific aux vectors.
		 */
		args->auxsize += 4 * sizeof (aux_entry_t);
	}

	/* If the binary has an explicit ASLR flag, it must be honoured */
	if ((dynamicphdr != NULL) &&
	    (dynamicphdr->p_filesz > 0)) {
		Dyn *dp;
		off_t i = 0;

#define	DYN_STRIDE	100
		for (i = 0; i < dynamicphdr->p_filesz;
		    i += sizeof (*dyn) * DYN_STRIDE) {
			int ndyns = (dynamicphdr->p_filesz - i) / sizeof (*dyn);
			size_t dynsize;

			ndyns = MIN(DYN_STRIDE, ndyns);
			dynsize = ndyns * sizeof (*dyn);

			dyn = kmem_alloc(dynsize, KM_SLEEP);

			if ((error = vn_rdwr(UIO_READ, vp, (caddr_t)dyn,
			    dynsize, (offset_t)(dynamicphdr->p_offset + i),
			    UIO_SYSSPACE, 0, (rlim64_t)0,
			    CRED(), &resid)) != 0) {
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
		int ncaps = capsize / sizeof (*cap);
		Cap *cp;

		cap = kmem_alloc(capsize, KM_SLEEP);
		if ((error = vn_rdwr(UIO_READ, vp, (caddr_t)cap,
		    capsize, (offset_t)capphdr->p_offset,
		    UIO_SYSSPACE, 0, (rlim64_t)0, CRED(), &resid)) != 0) {
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
	 * This can fill in the AT_SUN_PLATFORM and AT_SUN_EXECNAME aux entries.
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

	if ((error = mapelfexec(vp, ehdrp, nphdrs, phdrbase, &uphdr, &intphdr,
	    &stphdr, &dtrphdr, dataphdrp, &bssbase, &brkbase, &voffset, NULL,
	    len, execsz, &brksize)) != 0)
		goto bad;

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

		dlnsize = intphdr->p_filesz;

		if (dlnsize > MAXPATHLEN || dlnsize <= 0)
			goto bad;

		/*
		 * Read in "interpreter" pathname.
		 */
		if ((error = vn_rdwr(UIO_READ, vp, dlnp, intphdr->p_filesz,
		    (offset_t)intphdr->p_offset, UIO_SYSSPACE, 0, (rlim64_t)0,
		    CRED(), &resid)) != 0) {
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

		error = mapelfexec(nvp, ehdrp, nphdrs, phdrbase, &junk, &junk,
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

		/*
		 * Note: AT_SUN_PLATFORM and AT_SUN_EXECNAME were filled in via
		 * exec_args()
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
		if ((brand_action == EBA_NATIVE) && (PROC_IS_BRANDED(p) &&
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
		}

		/*
		 * Add the comm page auxv entry, mapping it in if needed.
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
#endif /* defined(__amd64) */

		ADDAUX(aux, AT_NULL, 0)
		postfixsize = (char *)aux - (char *)bigwad->elfargs;

		/*
		 * We make assumptions above when we determine how many aux
		 * vector entries we will be adding. However, if we have an
		 * invalid elf file, it is possible that mapelfexec might
		 * behave differently (but not return an error), in which case
		 * the number of aux entries we actually add will be different.
		 * We detect that now and error out.
		 */
		if (postfixsize != args->auxsize) {
			DTRACE_PROBE2(elfexec_badaux, int, postfixsize,
			    int, args->auxsize);
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
		int num_auxv;

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
elfsize(Ehdr *ehdrp, int nphdrs, caddr_t phdrbase, uintptr_t *lddata)
{
	size_t	len;
	Phdr	*phdrp = (Phdr *)phdrbase;
	int	hsize = ehdrp->e_phentsize;
	int	first = 1;
	int	dfirst = 1;	/* first data segment */
	uintptr_t loaddr = 0;
	uintptr_t hiaddr = 0;
	uintptr_t lo, hi;
	int	i;

	for (i = nphdrs; i > 0; i--) {
		if (phdrp->p_type == PT_LOAD) {
			lo = phdrp->p_vaddr;
			hi = lo + phdrp->p_memsz;
			if (first) {
				loaddr = lo;
				hiaddr = hi;
				first = 0;
			} else {
				if (loaddr > lo)
					loaddr = lo;
				if (hiaddr < hi)
					hiaddr = hi;
			}

			/*
			 * save the address of the first data segment
			 * of a object - used for the AT_SUNW_LDDATA
			 * aux entry.
			 */
			if ((lddata != NULL) && dfirst &&
			    (phdrp->p_flags & PF_W)) {
				*lddata = lo;
				dfirst = 0;
			}
		}
		phdrp = (Phdr *)((caddr_t)phdrp + hsize);
	}

	len = hiaddr - (loaddr & PAGEMASK);
	len = roundup(len, PAGESIZE);

	return (len);
}

/*
 * Read in the ELF header and program header table.
 * SUSV3 requires:
 *	ENOEXEC	File format is not recognized
 *	EINVAL	Format recognized but execution not supported
 */
static int
getelfhead(vnode_t *vp, cred_t *credp, Ehdr *ehdr, int *nshdrs, int *shstrndx,
    int *nphdrs)
{
	int error;
	ssize_t resid;

	/*
	 * We got here by the first two bytes in ident,
	 * now read the entire ELF header.
	 */
	if ((error = vn_rdwr(UIO_READ, vp, (caddr_t)ehdr,
	    sizeof (Ehdr), (offset_t)0, UIO_SYSSPACE, 0,
	    (rlim64_t)0, credp, &resid)) != 0)
		return (error);

	/*
	 * Since a separate version is compiled for handling 32-bit and
	 * 64-bit ELF executables on a 64-bit kernel, the 64-bit version
	 * doesn't need to be able to deal with 32-bit ELF files.
	 */
	if (resid != 0 ||
	    ehdr->e_ident[EI_MAG2] != ELFMAG2 ||
	    ehdr->e_ident[EI_MAG3] != ELFMAG3)
		return (ENOEXEC);

	if ((ehdr->e_type != ET_EXEC && ehdr->e_type != ET_DYN) ||
#if defined(_ILP32) || defined(_ELF32_COMPAT)
	    ehdr->e_ident[EI_CLASS] != ELFCLASS32 ||
#else
	    ehdr->e_ident[EI_CLASS] != ELFCLASS64 ||
#endif
	    !elfheadcheck(ehdr->e_ident[EI_DATA], ehdr->e_machine,
	    ehdr->e_flags))
		return (EINVAL);

	*nshdrs = ehdr->e_shnum;
	*shstrndx = ehdr->e_shstrndx;
	*nphdrs = ehdr->e_phnum;

	/*
	 * If e_shnum, e_shstrndx, or e_phnum is its sentinel value, we need
	 * to read in the section header at index zero to acces the true
	 * values for those fields.
	 */
	if ((*nshdrs == 0 && ehdr->e_shoff != 0) ||
	    *shstrndx == SHN_XINDEX || *nphdrs == PN_XNUM) {
		Shdr shdr;

		if (ehdr->e_shoff == 0)
			return (EINVAL);

		if ((error = vn_rdwr(UIO_READ, vp, (caddr_t)&shdr,
		    sizeof (shdr), (offset_t)ehdr->e_shoff, UIO_SYSSPACE, 0,
		    (rlim64_t)0, credp, &resid)) != 0)
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

#ifdef _ELF32_COMPAT
extern size_t elf_nphdr_max;
#else
size_t elf_nphdr_max = 1000;
#endif

static int
getelfphdr(vnode_t *vp, cred_t *credp, const Ehdr *ehdr, int nphdrs,
    caddr_t *phbasep, ssize_t *phsizep)
{
	ssize_t resid, minsize;
	int err;

	/*
	 * Since we're going to be using e_phentsize to iterate down the
	 * array of program headers, it must be 8-byte aligned or else
	 * a we might cause a misaligned access. We use all members through
	 * p_flags on 32-bit ELF files and p_memsz on 64-bit ELF files so
	 * e_phentsize must be at least large enough to include those
	 * members.
	 */
#if !defined(_LP64) || defined(_ELF32_COMPAT)
	minsize = offsetof(Phdr, p_flags) + sizeof (((Phdr *)NULL)->p_flags);
#else
	minsize = offsetof(Phdr, p_memsz) + sizeof (((Phdr *)NULL)->p_memsz);
#endif
	if (ehdr->e_phentsize < minsize || (ehdr->e_phentsize & 3))
		return (EINVAL);

	*phsizep = nphdrs * ehdr->e_phentsize;

	if (*phsizep > sizeof (Phdr) * elf_nphdr_max) {
		if ((*phbasep = kmem_alloc(*phsizep, KM_NOSLEEP)) == NULL)
			return (ENOMEM);
	} else {
		*phbasep = kmem_alloc(*phsizep, KM_SLEEP);
	}

	if ((err = vn_rdwr(UIO_READ, vp, *phbasep, *phsizep,
	    (offset_t)ehdr->e_phoff, UIO_SYSSPACE, 0, (rlim64_t)0,
	    credp, &resid)) != 0) {
		kmem_free(*phbasep, *phsizep);
		*phbasep = NULL;
		return (err);
	}

	return (0);
}

#ifdef _ELF32_COMPAT
extern size_t elf_nshdr_max;
extern size_t elf_shstrtab_max;
#else
size_t elf_nshdr_max = 10000;
size_t elf_shstrtab_max = 100 * 1024;
#endif


static int
getelfshdr(vnode_t *vp, cred_t *credp, const Ehdr *ehdr,
    int nshdrs, int shstrndx, caddr_t *shbasep, ssize_t *shsizep,
    char **shstrbasep, ssize_t *shstrsizep)
{
	ssize_t resid, minsize;
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
	minsize = offsetof(Shdr, sh_entsize) + sizeof (shdr->sh_entsize);
	if (ehdr->e_shentsize < minsize || (ehdr->e_shentsize & 3) ||
	    shstrndx >= nshdrs)
		return (EINVAL);

	*shsizep = nshdrs * ehdr->e_shentsize;

	if (*shsizep > sizeof (Shdr) * elf_nshdr_max) {
		if ((*shbasep = kmem_alloc(*shsizep, KM_NOSLEEP)) == NULL)
			return (ENOMEM);
	} else {
		*shbasep = kmem_alloc(*shsizep, KM_SLEEP);
	}

	if ((err = vn_rdwr(UIO_READ, vp, *shbasep, *shsizep,
	    (offset_t)ehdr->e_shoff, UIO_SYSSPACE, 0, (rlim64_t)0,
	    credp, &resid)) != 0) {
		kmem_free(*shbasep, *shsizep);
		return (err);
	}

	/*
	 * Pull the section string table out of the vnode; fail if the size
	 * is zero.
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

	if ((err = vn_rdwr(UIO_READ, vp, *shstrbasep, *shstrsizep,
	    (offset_t)shdr->sh_offset, UIO_SYSSPACE, 0, (rlim64_t)0,
	    credp, &resid)) != 0) {
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

static int
mapelfexec(
	vnode_t *vp,
	Ehdr *ehdr,
	int nphdrs,
	caddr_t phdrbase,
	Phdr **uphdr,
	Phdr **intphdr,
	Phdr **stphdr,
	Phdr **dtphdr,
	Phdr *dataphdrp,
	caddr_t *bssbase,
	caddr_t *brkbase,
	intptr_t *voffset,
	intptr_t *minaddr,
	size_t len,
	long *execsz,
	size_t *brksize)
{
	Phdr *phdr;
	int i, prot, error;
	caddr_t addr = NULL;
	size_t zfodsz;
	int ptload = 0;
	int page;
	off_t offset;
	int hsize = ehdr->e_phentsize;
	caddr_t mintmp = (caddr_t)-1;
	extern int use_brk_lpg;

	if (ehdr->e_type == ET_DYN) {
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
		*voffset = (intptr_t)addr;

		/*
		 * Calculate the minimum vaddr so it can be subtracted out.
		 * According to the ELF specification, since PT_LOAD sections
		 * must be sorted by increasing p_vaddr values, this is
		 * guaranteed to be the first PT_LOAD section.
		 */
		phdr = (Phdr *)phdrbase;
		for (i = nphdrs; i > 0; i--) {
			if (phdr->p_type == PT_LOAD) {
				*voffset -= (uintptr_t)phdr->p_vaddr;
				break;
			}
			phdr = (Phdr *)((caddr_t)phdr + hsize);
		}

	} else {
		*voffset = 0;
	}
	phdr = (Phdr *)phdrbase;
	for (i = nphdrs; i > 0; i--) {
		switch (phdr->p_type) {
		case PT_LOAD:
			if ((*intphdr != NULL) && (*uphdr == NULL))
				return (0);

			ptload = 1;
			prot = PROT_USER;
			if (phdr->p_flags & PF_R)
				prot |= PROT_READ;
			if (phdr->p_flags & PF_W)
				prot |= PROT_WRITE;
			if (phdr->p_flags & PF_X)
				prot |= PROT_EXEC;

			addr = (caddr_t)((uintptr_t)phdr->p_vaddr + *voffset);

			/*
			 * Keep track of the segment with the lowest starting
			 * address.
			 */
			if (addr < mintmp)
				mintmp = addr;

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
				size_t tlen = P2NPHASE((uintptr_t)addr +
				    phdr->p_filesz, PAGESIZE);

				if (zfodsz > tlen) {
					curproc->p_brkpageszc =
					    page_szc(map_pgsz(MAPPGSZ_HEAP,
					    curproc, addr + phdr->p_filesz +
					    tlen, zfodsz - tlen, 0));
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

			*execsz += btopr(phdr->p_memsz);
			break;

		case PT_INTERP:
			if (ptload)
				goto bad;
			*intphdr = phdr;
			break;

		case PT_SHLIB:
			*stphdr = phdr;
			break;

		case PT_PHDR:
			if (ptload)
				goto bad;
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

	if (minaddr != NULL) {
		ASSERT(mintmp != (caddr_t)-1);
		*minaddr = (intptr_t)mintmp;
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
copy_scn(Shdr *src, vnode_t *src_vp, Shdr *dst, vnode_t *dst_vp, Off *doffset,
    void *buf, size_t size, cred_t *credp, rlim64_t rlimit)
{
	ssize_t resid;
	size_t len, n = src->sh_size;
	offset_t off = 0;

	while (n != 0) {
		len = MIN(size, n);
		if (vn_rdwr(UIO_READ, src_vp, buf, len, src->sh_offset + off,
		    UIO_SYSSPACE, 0, (rlim64_t)0, credp, &resid) != 0 ||
		    resid >= len ||
		    core_write(dst_vp, UIO_SYSSPACE, *doffset + off,
		    buf, len - resid, rlimit, credp) != 0) {
			dst->sh_size = 0;
			dst->sh_offset = 0;
			return;
		}

		ASSERT(n >= len - resid);

		n -= len - resid;
		off += len - resid;
	}

	*doffset += src->sh_size;
}

#ifdef _ELF32_COMPAT
extern size_t elf_datasz_max;
#else
size_t elf_datasz_max = 1 * 1024 * 1024;
#endif

/*
 * This function processes mappings that correspond to load objects to
 * examine their respective sections for elfcore(). It's called once with
 * v set to NULL to count the number of sections that we're going to need
 * and then again with v set to some allocated buffer that we fill in with
 * all the section data.
 */
static int
process_scns(core_content_t content, proc_t *p, cred_t *credp, vnode_t *vp,
    Shdr *v, int nv, rlim64_t rlimit, Off *doffsetp, int *nshdrsp)
{
	vnode_t *lastvp = NULL;
	struct seg *seg;
	int i, j;
	void *data = NULL;
	size_t datasz = 0;
	shstrtab_t shstrtab;
	struct as *as = p->p_as;
	int error = 0;

	if (v != NULL)
		shstrtab_init(&shstrtab);

	i = 1;
	for (seg = AS_SEGFIRST(as); seg != NULL; seg = AS_SEGNEXT(as, seg)) {
		uint_t prot;
		vnode_t *mvp;
		void *tmp = NULL;
		caddr_t saddr = seg->s_base;
		caddr_t naddr;
		caddr_t eaddr;
		size_t segsize;

		Ehdr ehdr;
		int nshdrs, shstrndx, nphdrs;
		caddr_t shbase;
		ssize_t shsize;
		char *shstrbase;
		ssize_t shstrsize;

		Shdr *shdr;
		const char *name;
		size_t sz;
		uintptr_t off;

		int ctf_ndx = 0;
		int symtab_ndx = 0;

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

		if (getelfhead(mvp, credp, &ehdr, &nshdrs, &shstrndx,
		    &nphdrs) != 0 ||
		    getelfshdr(mvp, credp, &ehdr, nshdrs, shstrndx,
		    &shbase, &shsize, &shstrbase, &shstrsize) != 0)
			continue;

		off = ehdr.e_shentsize;
		for (j = 1; j < nshdrs; j++, off += ehdr.e_shentsize) {
			Shdr *symtab = NULL, *strtab;

			shdr = (Shdr *)(shbase + off);

			if (shdr->sh_name >= shstrsize)
				continue;

			name = shstrbase + shdr->sh_name;

			if (strcmp(name, shstrtab_data[STR_CTF]) == 0) {
				if ((content & CC_CONTENT_CTF) == 0 ||
				    ctf_ndx != 0)
					continue;

				if (shdr->sh_link > 0 &&
				    shdr->sh_link < nshdrs) {
					symtab = (Shdr *)(shbase +
					    shdr->sh_link * ehdr.e_shentsize);
				}

				if (v != NULL && i < nv - 1) {
					if (shdr->sh_size > datasz &&
					    shdr->sh_size <= elf_datasz_max) {
						if (data != NULL)
							kmem_free(data, datasz);

						datasz = shdr->sh_size;
						data = kmem_alloc(datasz,
						    KM_SLEEP);
					}

					v[i].sh_name = shstrtab_ndx(&shstrtab,
					    STR_CTF);
					v[i].sh_addr = (Addr)(uintptr_t)saddr;
					v[i].sh_type = SHT_PROGBITS;
					v[i].sh_addralign = 4;
					*doffsetp = roundup(*doffsetp,
					    v[i].sh_addralign);
					v[i].sh_offset = *doffsetp;
					v[i].sh_size = shdr->sh_size;
					if (symtab == NULL)  {
						v[i].sh_link = 0;
					} else if (symtab->sh_type ==
					    SHT_SYMTAB &&
					    symtab_ndx != 0) {
						v[i].sh_link =
						    symtab_ndx;
					} else {
						v[i].sh_link = i + 1;
					}

					copy_scn(shdr, mvp, &v[i], vp,
					    doffsetp, data, datasz, credp,
					    rlimit);
				}

				ctf_ndx = i++;

				/*
				 * We've already dumped the symtab.
				 */
				if (symtab != NULL &&
				    symtab->sh_type == SHT_SYMTAB &&
				    symtab_ndx != 0)
					continue;

			} else if (strcmp(name,
			    shstrtab_data[STR_SYMTAB]) == 0) {
				if ((content & CC_CONTENT_SYMTAB) == 0 ||
				    symtab != 0)
					continue;

				symtab = shdr;
			}

			if (symtab != NULL) {
				if ((symtab->sh_type != SHT_DYNSYM &&
				    symtab->sh_type != SHT_SYMTAB) ||
				    symtab->sh_link == 0 ||
				    symtab->sh_link >= nshdrs)
					continue;

				strtab = (Shdr *)(shbase +
				    symtab->sh_link * ehdr.e_shentsize);

				if (strtab->sh_type != SHT_STRTAB)
					continue;

				if (v != NULL && i < nv - 2) {
					sz = MAX(symtab->sh_size,
					    strtab->sh_size);
					if (sz > datasz &&
					    sz <= elf_datasz_max) {
						if (data != NULL)
							kmem_free(data, datasz);

						datasz = sz;
						data = kmem_alloc(datasz,
						    KM_SLEEP);
					}

					if (symtab->sh_type == SHT_DYNSYM) {
						v[i].sh_name = shstrtab_ndx(
						    &shstrtab, STR_DYNSYM);
						v[i + 1].sh_name = shstrtab_ndx(
						    &shstrtab, STR_DYNSTR);
					} else {
						v[i].sh_name = shstrtab_ndx(
						    &shstrtab, STR_SYMTAB);
						v[i + 1].sh_name = shstrtab_ndx(
						    &shstrtab, STR_STRTAB);
					}

					v[i].sh_type = symtab->sh_type;
					v[i].sh_addr = symtab->sh_addr;
					if (ehdr.e_type == ET_DYN ||
					    v[i].sh_addr == 0)
						v[i].sh_addr +=
						    (Addr)(uintptr_t)saddr;
					v[i].sh_addralign =
					    symtab->sh_addralign;
					*doffsetp = roundup(*doffsetp,
					    v[i].sh_addralign);
					v[i].sh_offset = *doffsetp;
					v[i].sh_size = symtab->sh_size;
					v[i].sh_link = i + 1;
					v[i].sh_entsize = symtab->sh_entsize;
					v[i].sh_info = symtab->sh_info;

					copy_scn(symtab, mvp, &v[i], vp,
					    doffsetp, data, datasz, credp,
					    rlimit);

					v[i + 1].sh_type = SHT_STRTAB;
					v[i + 1].sh_flags = SHF_STRINGS;
					v[i + 1].sh_addr = symtab->sh_addr;
					if (ehdr.e_type == ET_DYN ||
					    v[i + 1].sh_addr == 0)
						v[i + 1].sh_addr +=
						    (Addr)(uintptr_t)saddr;
					v[i + 1].sh_addralign =
					    strtab->sh_addralign;
					*doffsetp = roundup(*doffsetp,
					    v[i + 1].sh_addralign);
					v[i + 1].sh_offset = *doffsetp;
					v[i + 1].sh_size = strtab->sh_size;

					copy_scn(strtab, mvp, &v[i + 1], vp,
					    doffsetp, data, datasz, credp,
					    rlimit);
				}

				if (symtab->sh_type == SHT_SYMTAB)
					symtab_ndx = i;
				i += 2;
			}
		}

		kmem_free(shstrbase, shstrsize);
		kmem_free(shbase, shsize);

		lastvp = mvp;
	}

	if (v == NULL) {
		if (i == 1)
			*nshdrsp = 0;
		else
			*nshdrsp = i + 1;
		goto done;
	}

	if (i != nv - 1) {
		cmn_err(CE_WARN, "elfcore: core dump failed for "
		    "process %d; address space is changing", p->p_pid);
		error = EIO;
		goto done;
	}

	v[i].sh_name = shstrtab_ndx(&shstrtab, STR_SHSTRTAB);
	v[i].sh_size = shstrtab_size(&shstrtab);
	v[i].sh_addralign = 1;
	*doffsetp = roundup(*doffsetp, v[i].sh_addralign);
	v[i].sh_offset = *doffsetp;
	v[i].sh_flags = SHF_STRINGS;
	v[i].sh_type = SHT_STRTAB;

	if (v[i].sh_size > datasz) {
		if (data != NULL)
			kmem_free(data, datasz);

		datasz = v[i].sh_size;
		data = kmem_alloc(datasz,
		    KM_SLEEP);
	}

	shstrtab_dump(&shstrtab, data);

	if ((error = core_write(vp, UIO_SYSSPACE, *doffsetp,
	    data, v[i].sh_size, rlimit, credp)) != 0)
		goto done;

	*doffsetp += v[i].sh_size;

done:
	if (data != NULL)
		kmem_free(data, datasz);

	return (error);
}

int
elfcore(vnode_t *vp, proc_t *p, cred_t *credp, rlim64_t rlimit, int sig,
    core_content_t content)
{
	offset_t poffset, soffset;
	Off doffset;
	int error, i, nphdrs, nshdrs;
	int overflow = 0;
	struct seg *seg;
	struct as *as = p->p_as;
	union {
		Ehdr ehdr;
		Phdr phdr[1];
		Shdr shdr[1];
	} *bigwad;
	size_t bigsize;
	size_t phdrsz, shdrsz;
	Ehdr *ehdr;
	Phdr *v;
	caddr_t brkbase;
	size_t brksize;
	caddr_t stkbase;
	size_t stksize;
	int ntries = 0;
	klwp_t *lwp = ttolwp(curthread);

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
		(void) process_scns(content, p, credp, NULL, NULL, NULL, 0,
		    NULL, &nshdrs);
	}
	AS_LOCK_EXIT(as);

	ASSERT(nshdrs == 0 || nshdrs > 1);

	/*
	 * The core file contents may required zero section headers, but if
	 * we overflow the 16 bits allotted to the program header count in
	 * the ELF header, we'll need that program header at index zero.
	 */
	if (nshdrs == 0 && nphdrs >= PN_XNUM)
		nshdrs = 1;

	phdrsz = nphdrs * sizeof (Phdr);
	shdrsz = nshdrs * sizeof (Shdr);

	bigsize = MAX(sizeof (*bigwad), MAX(phdrsz, shdrsz));
	bigwad = kmem_alloc(bigsize, KM_SLEEP);

	ehdr = &bigwad->ehdr;
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

	/*
	 * If the count of program headers or section headers or the index
	 * of the section string table can't fit in the mere 16 bits
	 * shortsightedly allotted to them in the ELF header, we use the
	 * extended formats and put the real values in the section header
	 * as index 0.
	 */
	ehdr->e_version = EV_CURRENT;
	ehdr->e_ehsize = sizeof (Ehdr);

	if (nphdrs >= PN_XNUM)
		ehdr->e_phnum = PN_XNUM;
	else
		ehdr->e_phnum = (unsigned short)nphdrs;

	ehdr->e_phoff = sizeof (Ehdr);
	ehdr->e_phentsize = sizeof (Phdr);

	if (nshdrs > 0) {
		if (nshdrs >= SHN_LORESERVE)
			ehdr->e_shnum = 0;
		else
			ehdr->e_shnum = (unsigned short)nshdrs;

		if (nshdrs - 1 >= SHN_LORESERVE)
			ehdr->e_shstrndx = SHN_XINDEX;
		else
			ehdr->e_shstrndx = (unsigned short)(nshdrs - 1);

		ehdr->e_shoff = ehdr->e_phoff + ehdr->e_phentsize * nphdrs;
		ehdr->e_shentsize = sizeof (Shdr);
	}

	if (error = core_write(vp, UIO_SYSSPACE, (offset_t)0, ehdr,
	    sizeof (Ehdr), rlimit, credp))
		goto done;

	poffset = sizeof (Ehdr);
	soffset = sizeof (Ehdr) + phdrsz;
	doffset = sizeof (Ehdr) + phdrsz + shdrsz;

	v = &bigwad->phdr[0];
	bzero(v, phdrsz);

	setup_old_note_header(&v[0], p);
	v[0].p_offset = doffset = roundup(doffset, sizeof (Word));
	doffset += v[0].p_filesz;

	setup_note_header(&v[1], p);
	v[1].p_offset = doffset = roundup(doffset, sizeof (Word));
	doffset += v[1].p_filesz;

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

		for (saddr = seg->s_base; saddr < eaddr; saddr = naddr) {
			uint_t prot;
			size_t size;
			int type;
			vnode_t *mvp;

			prot = pr_getprot(seg, 0, &tmp, &saddr, &naddr, eaddr);
			prot &= PROT_READ | PROT_WRITE | PROT_EXEC;
			if ((size = (size_t)(naddr - saddr)) == 0)
				continue;
			if (i == nphdrs) {
				overflow++;
				continue;
			}
			v[i].p_type = PT_LOAD;
			v[i].p_vaddr = (Addr)(uintptr_t)saddr;
			v[i].p_memsz = size;
			if (prot & PROT_READ)
				v[i].p_flags |= PF_R;
			if (prot & PROT_WRITE)
				v[i].p_flags |= PF_W;
			if (prot & PROT_EXEC)
				v[i].p_flags |= PF_X;

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
			v[i].p_offset = doffset;
			v[i].p_filesz = size;
			doffset += size;
exclude:
			i++;
		}
		ASSERT(tmp == NULL);
	}
	AS_LOCK_EXIT(as);

	if (overflow || i != nphdrs) {
		if (ntries++ == 0) {
			kmem_free(bigwad, bigsize);
			overflow = 0;
			goto top;
		}
		cmn_err(CE_WARN, "elfcore: core dump failed for "
		    "process %d; address space is changing", p->p_pid);
		error = EIO;
		goto done;
	}

	if ((error = core_write(vp, UIO_SYSSPACE, poffset,
	    v, phdrsz, rlimit, credp)) != 0)
		goto done;

	if ((error = write_old_elfnotes(p, sig, vp, v[0].p_offset, rlimit,
	    credp)) != 0)
		goto done;

	if ((error = write_elfnotes(p, sig, vp, v[1].p_offset, rlimit,
	    credp, content)) != 0)
		goto done;

	for (i = 2; i < nphdrs; i++) {
		prkillinfo_t killinfo;
		sigqueue_t *sq;
		int sig, j;

		if (v[i].p_filesz == 0)
			continue;

		/*
		 * If dumping out this segment fails, rather than failing
		 * the core dump entirely, we reset the size of the mapping
		 * to zero to indicate that the data is absent from the core
		 * file and or in the PF_SUNW_FAILURE flag to differentiate
		 * this from mappings that were excluded due to the core file
		 * content settings.
		 */
		if ((error = core_seg(p, vp, v[i].p_offset,
		    (caddr_t)(uintptr_t)v[i].p_vaddr, v[i].p_filesz,
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
			(void) core_write(vp, UIO_SYSSPACE, v[i].p_offset,
			    &error, sizeof (error), rlimit, credp);

			v[i].p_filesz = 0;
			v[i].p_flags |= PF_SUNW_FAILURE;
			if ((error = core_write(vp, UIO_SYSSPACE,
			    poffset + sizeof (v[i]) * i, &v[i], sizeof (v[i]),
			    rlimit, credp)) != 0)
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

		(void) core_write(vp, UIO_SYSSPACE, v[i].p_offset,
		    &killinfo, sizeof (killinfo), rlimit, credp);

		/*
		 * For the segment on which we took the signal, indicate that
		 * its data now refers to a siginfo.
		 */
		v[i].p_filesz = 0;
		v[i].p_flags |= PF_SUNW_FAILURE | PF_SUNW_KILLED |
		    PF_SUNW_SIGINFO;

		/*
		 * And for every other segment, indicate that its absence
		 * is due to a signal.
		 */
		for (j = i + 1; j < nphdrs; j++) {
			v[j].p_filesz = 0;
			v[j].p_flags |= PF_SUNW_FAILURE | PF_SUNW_KILLED;
		}

		/*
		 * Finally, write out our modified program headers.
		 */
		if ((error = core_write(vp, UIO_SYSSPACE,
		    poffset + sizeof (v[i]) * i, &v[i],
		    sizeof (v[i]) * (nphdrs - i), rlimit, credp)) != 0)
			goto done;

		break;
	}

	if (nshdrs > 0) {
		bzero(&bigwad->shdr[0], shdrsz);

		if (nshdrs >= SHN_LORESERVE)
			bigwad->shdr[0].sh_size = nshdrs;

		if (nshdrs - 1 >= SHN_LORESERVE)
			bigwad->shdr[0].sh_link = nshdrs - 1;

		if (nphdrs >= PN_XNUM)
			bigwad->shdr[0].sh_info = nphdrs;

		if (nshdrs > 1) {
			AS_LOCK_ENTER(as, RW_WRITER);
			if ((error = process_scns(content, p, credp, vp,
			    &bigwad->shdr[0], nshdrs, rlimit, &doffset,
			    NULL)) != 0) {
				AS_LOCK_EXIT(as);
				goto done;
			}
			AS_LOCK_EXIT(as);
		}

		if ((error = core_write(vp, UIO_SYSSPACE, soffset,
		    &bigwad->shdr[0], shdrsz, rlimit, credp)) != 0)
			goto done;
	}

done:
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
			intpdata_t *idatap, int level, long *execsz,
			int setid, caddr_t exec_file, cred_t *cred,
			int brand_action);
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
