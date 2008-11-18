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

/*
 *	Copyright (c) 1988 AT&T
 *	  All Rights Reserved
 */

/*
 * Object file dependent support for ELF objects.
 */

#include	<stdio.h>
#include	<sys/procfs.h>
#include	<sys/mman.h>
#include	<sys/debug.h>
#include	<string.h>
#include	<limits.h>
#include	<dlfcn.h>
#include	<debug.h>
#include	<conv.h>
#include	"_rtld.h"
#include	"_audit.h"
#include	"_elf.h"
#include	"msg.h"

/*
 * Default and secure dependency search paths.
 */
static Pnode		elf_dflt_dirs[] = {
#if	defined(_ELF64)
#ifndef	SGS_PRE_UNIFIED_PROCESS
	{ MSG_ORIG(MSG_PTH_LIB_64),		0,	MSG_PTH_LIB_64_SIZE,
		LA_SER_DEFAULT,			0,	&elf_dflt_dirs[1] },
#endif
	{ MSG_ORIG(MSG_PTH_USRLIB_64),		0,	MSG_PTH_USRLIB_64_SIZE,
		LA_SER_DEFAULT,			0, 0 }
#else
#ifndef	SGS_PRE_UNIFIED_PROCESS
	{ MSG_ORIG(MSG_PTH_LIB),		0,	MSG_PTH_LIB_SIZE,
		LA_SER_DEFAULT,			0,	&elf_dflt_dirs[1] },
#endif
	{ MSG_ORIG(MSG_PTH_USRLIB),		0,	MSG_PTH_USRLIB_SIZE,
		LA_SER_DEFAULT,			0, 0 }
#endif
};

static Pnode		elf_secure_dirs[] = {
#if	defined(_ELF64)
#ifndef	SGS_PRE_UNIFIED_PROCESS
	{ MSG_ORIG(MSG_PTH_LIBSE_64),		0,	MSG_PTH_LIBSE_64_SIZE,
		LA_SER_SECURE,			0,	&elf_secure_dirs[1] },
#endif
	{ MSG_ORIG(MSG_PTH_USRLIBSE_64),	0,
		MSG_PTH_USRLIBSE_64_SIZE,
		LA_SER_SECURE,			0, 0 }
#else
#ifndef	SGS_PRE_UNIFIED_PROCESS
	{ MSG_ORIG(MSG_PTH_LIBSE),		0,	MSG_PTH_LIBSE_SIZE,
		LA_SER_SECURE,			0,	&elf_secure_dirs[1] },
#endif
	{ MSG_ORIG(MSG_PTH_USRLIBSE),		0,	MSG_PTH_USRLIBSE_SIZE,
		LA_SER_SECURE,			0, 0 }
#endif
};

/*
 * Defines for local functions.
 */
static Pnode	*elf_fix_name(const char *, Rt_map *, uint_t);
static int	elf_are_u(Rej_desc *);
static void	elf_dladdr(ulong_t, Rt_map *, Dl_info *, void **, int);
static ulong_t	elf_entry_pt(void);
static char	*elf_get_so(const char *, const char *);
static Rt_map	*elf_map_so(Lm_list *, Aliste, const char *, const char *,
		    int, int *);
static int	elf_needed(Lm_list *, Aliste, Rt_map *, int *);
static void	elf_unmap_so(Rt_map *);
static int	elf_verify_vers(const char *, Rt_map *, Rt_map *);

/*
 * Functions and data accessed through indirect pointers.
 */
Fct elf_fct = {
	elf_are_u,
	elf_entry_pt,
	elf_map_so,
	elf_unmap_so,
	elf_needed,
	lookup_sym,
	elf_reloc,
	elf_dflt_dirs,
	elf_secure_dirs,
	elf_fix_name,
	elf_get_so,
	elf_dladdr,
	dlsym_handle,
	elf_verify_vers,
	elf_set_prot
};


/*
 * Redefine NEEDED name if necessary.
 */
static Pnode *
elf_fix_name(const char *name, Rt_map *clmp, uint_t orig)
{
	/*
	 * For ABI compliance, if we are asked for ld.so.1, then really give
	 * them libsys.so.1 (the SONAME of libsys.so.1 is ld.so.1).
	 */
	if (((*name == '/') &&
	/* BEGIN CSTYLED */
#if	defined(_ELF64)
	    (strcmp(name, MSG_ORIG(MSG_PTH_RTLD_64)) == 0)) ||
#else
	    (strcmp(name, MSG_ORIG(MSG_PTH_RTLD)) == 0)) ||
#endif
	    (strcmp(name, MSG_ORIG(MSG_FIL_RTLD)) == 0)) {
		/* END CSTYLED */
		Pnode	*pnp;

		DBG_CALL(Dbg_file_fixname(LIST(clmp), name,
		    MSG_ORIG(MSG_PTH_LIBSYS)));
		if (((pnp = calloc(sizeof (Pnode), 1)) == 0) ||
		    ((pnp->p_name = strdup(MSG_ORIG(MSG_PTH_LIBSYS))) == 0)) {
			if (pnp)
				free(pnp);
			return (0);
		}
		pnp->p_len = MSG_PTH_LIBSYS_SIZE;
		return (pnp);
	}

	return (expand_paths(clmp, name, orig, 0));
}

/*
 * Determine if we have been given an ELF file and if so determine if the file
 * is compatible.  Returns 1 if true, else 0 and sets the reject descriptor
 * with associated error information.
 */
static int
elf_are_u(Rej_desc *rej)
{
	Ehdr	*ehdr;

	/*
	 * Determine if we're an elf file.  If not simply return, we don't set
	 * any rejection information as this test allows use to scroll through
	 * the objects we support (ELF, AOUT).
	 */
	if (fmap->fm_fsize < sizeof (Ehdr) ||
	    fmap->fm_maddr[EI_MAG0] != ELFMAG0 ||
	    fmap->fm_maddr[EI_MAG1] != ELFMAG1 ||
	    fmap->fm_maddr[EI_MAG2] != ELFMAG2 ||
	    fmap->fm_maddr[EI_MAG3] != ELFMAG3) {
		return (0);
	}

	/*
	 * Check class and encoding.
	 */
	/* LINTED */
	ehdr = (Ehdr *)fmap->fm_maddr;
	if (ehdr->e_ident[EI_CLASS] != M_CLASS) {
		rej->rej_type = SGS_REJ_CLASS;
		rej->rej_info = (uint_t)ehdr->e_ident[EI_CLASS];
		return (0);
	}
	if (ehdr->e_ident[EI_DATA] != M_DATA) {
		rej->rej_type = SGS_REJ_DATA;
		rej->rej_info = (uint_t)ehdr->e_ident[EI_DATA];
		return (0);
	}
	if ((ehdr->e_type != ET_REL) && (ehdr->e_type != ET_EXEC) &&
	    (ehdr->e_type != ET_DYN)) {
		rej->rej_type = SGS_REJ_TYPE;
		rej->rej_info = (uint_t)ehdr->e_type;
		return (0);
	}

	/*
	 * Verify machine specific flags, and hardware capability requirements.
	 */
	if ((elf_mach_flags_check(rej, ehdr) == 0) ||
	    (cap_check(rej, ehdr) == 0))
		return (0);

	/*
	 * Verify ELF version.  ??? is this too restrictive ???
	 */
	if (ehdr->e_version > EV_CURRENT) {
		rej->rej_type = SGS_REJ_VERSION;
		rej->rej_info = (uint_t)ehdr->e_version;
		return (0);
	}
	return (1);
}

/*
 * The runtime linker employs lazy loading to provide the libraries needed for
 * debugging, preloading .o's and dldump().  As these are seldom used, the
 * standard startup of ld.so.1 doesn't initialize all the information necessary
 * to perform plt relocation on ld.so.1's link-map.  The first time lazy loading
 * is called we get here to perform these initializations:
 *
 *  o	elf_needed() is called to set up the DYNINFO() indexes for each lazy
 *	dependency.  Typically, for all other objects, this is called during
 *	analyze_so(), but as ld.so.1 is set-contained we skip this processing.
 *
 *  o	For intel, ld.so.1's JMPSLOT relocations need relative updates. These
 *	are by default skipped thus delaying all relative relocation processing
 * 	on every invocation of ld.so.1.
 */
int
elf_rtld_load()
{
	Lm_list	*lml = &lml_rtld;
	Rt_map	*lmp = lml->lm_head;

	if (lml->lm_flags & LML_FLG_PLTREL)
		return (1);

	/*
	 * As we need to refer to the DYNINFO() information, insure that it has
	 * been initialized.
	 */
	if (elf_needed(lml, ALIST_OFF_DATA, lmp, NULL) == 0)
		return (0);

#if	defined(__i386)
	/*
	 * This is a kludge to give ld.so.1 a performance benefit on i386.
	 * It's based around two factors.
	 *
	 *  o	JMPSLOT relocations (PLT's) actually need a relative relocation
	 *	applied to the GOT entry so that they can find PLT0.
	 *
	 *  o	ld.so.1 does not exercise *any* PLT's before it has made a call
	 *	to elf_lazy_load().  This is because all dynamic dependencies
	 * 	are recorded as lazy dependencies.
	 */
	(void) elf_reloc_relacount((ulong_t)JMPREL(lmp),
	    (ulong_t)(PLTRELSZ(lmp) / RELENT(lmp)), (ulong_t)RELENT(lmp),
	    (ulong_t)ADDR(lmp));
#endif

	lml->lm_flags |= LML_FLG_PLTREL;
	return (1);
}

/*
 * Lazy load an object.
 */
Rt_map *
elf_lazy_load(Rt_map *clmp, Slookup *slp, uint_t ndx, const char *sym,
    int *in_nfavl)
{
	Rt_map		*nlmp, *hlmp;
	Dyninfo		*dip = &DYNINFO(clmp)[ndx], *pdip;
	uint_t		flags = 0;
	Pnode		*pnp;
	const char	*name;
	Lm_list		*lml = LIST(clmp);
	Lm_cntl		*lmc;
	Aliste		lmco;

	/*
	 * If this dependency has already been processed, we're done.
	 */
	if (((nlmp = (Rt_map *)dip->di_info) != 0) ||
	    (dip->di_flags & FLG_DI_LDD_DONE))
		return (nlmp);

	/*
	 * If we're running under ldd(1), indicate that this dependency has been
	 * processed (see test above).  It doesn't matter whether the object is
	 * successfully loaded or not, this flag simply ensures that we don't
	 * repeatedly attempt to load an object that has already failed to load.
	 * To do so would create multiple failure diagnostics for the same
	 * object under ldd(1).
	 */
	if (lml->lm_flags & LML_FLG_TRC_ENABLE)
		dip->di_flags |= FLG_DI_LDD_DONE;

	/*
	 * Determine the initial dependency name.
	 */
	name = STRTAB(clmp) + DYN(clmp)[ndx].d_un.d_val;
	DBG_CALL(Dbg_file_lazyload(clmp, name, sym));

	/*
	 * If this object needs to establish its own group, make sure a handle
	 * is created.
	 */
	if (dip->di_flags & FLG_DI_GROUP)
		flags |= (FLG_RT_SETGROUP | FLG_RT_HANDLE);

	/*
	 * Lazy dependencies are identified as DT_NEEDED entries with a
	 * DF_P1_LAZYLOAD flag in the previous DT_POSFLAG_1 element.  The
	 * dynamic information element that corresponds to the DT_POSFLAG_1
	 * entry is free, and thus used to store the present entrance
	 * identifier.  This identifier is used to prevent multiple attempts to
	 * load a failed lazy loadable dependency within the same runtime linker
	 * operation.  However, future attempts to reload this dependency are
	 * still possible.
	 */
	if (ndx && (pdip = dip - 1) && (pdip->di_flags & FLG_DI_POSFLAG1))
		pdip->di_info = (void *)slp->sl_id;

	/*
	 * Expand the requested name if necessary.
	 */
	if ((pnp = elf_fix_name(name, clmp, 0)) == 0)
		return (0);

	/*
	 * Provided the object on the head of the link-map has completed its
	 * relocation, create a new link-map control list for this request.
	 */
	hlmp = lml->lm_head;
	if (FLAGS(hlmp) & FLG_RT_RELOCED) {
		if ((lmc = alist_append(&lml->lm_lists, 0, sizeof (Lm_cntl),
		    AL_CNT_LMLISTS)) == 0) {
			remove_pnode(pnp);
			return (0);
		}
		lmco = (Aliste)((char *)lmc - (char *)lml->lm_lists);
	} else {
		lmc = 0;
		lmco = ALIST_OFF_DATA;
	}

	/*
	 * Load the associated object.
	 */
	dip->di_info = nlmp =
	    load_one(lml, lmco, pnp, clmp, MODE(clmp), flags, 0, in_nfavl);

	/*
	 * Remove any expanded pathname infrastructure.  Reduce the pending lazy
	 * dependency count of the caller, together with the link-map lists
	 * count of objects that still have lazy dependencies pending.
	 */
	remove_pnode(pnp);
	if (--LAZY(clmp) == 0)
		LIST(clmp)->lm_lazy--;

	/*
	 * Finish processing the objects associated with this request, and
	 * create an association between the caller and this dependency.
	 */
	if (nlmp && ((bind_one(clmp, nlmp, BND_NEEDED) == 0) ||
	    (analyze_lmc(lml, lmco, nlmp, in_nfavl) == 0) ||
	    (relocate_lmc(lml, lmco, clmp, nlmp, in_nfavl) == 0)))
		dip->di_info = nlmp = 0;

	/*
	 * If this lazyload has failed, and we've created a new link-map
	 * control list to which this request has added objects, then remove
	 * all the objects that have been associated to this request.
	 */
	if ((nlmp == 0) && lmc && lmc->lc_head)
		remove_lmc(lml, clmp, lmc, lmco, name);

	/*
	 * Finally, remove any link-map control list that was created.
	 */
	if (lmc)
		remove_cntl(lml, lmco);

	/*
	 * If this lazy loading failed, record the fact, and bump the lazy
	 * counts.
	 */
	if (nlmp == 0) {
		dip->di_flags |= FLG_DI_LAZYFAIL;
		if (LAZY(clmp)++ == 0)
			LIST(clmp)->lm_lazy++;
	}

	return (nlmp);
}

/*
 * Return the entry point of the ELF executable.
 */
static ulong_t
elf_entry_pt(void)
{
	return (ENTRY(lml_main.lm_head));
}

/*
 * Unmap a given ELF shared object from the address space.
 */
static void
elf_unmap_so(Rt_map *lmp)
{
	caddr_t	addr;
	size_t	size;
	Mmap	*mmaps;

	/*
	 * If this link map represents a relocatable object concatenation, then
	 * the image was simply generated in allocated memory.  Free the memory.
	 *
	 * Note: the memory was originally allocated in the libelf:_elf_outmap
	 * routine and would normally have been free'd in elf_outsync(), but
	 * because we 'interpose' on that routine the memory  wasn't free'd at
	 * that time.
	 */
	if (FLAGS(lmp) & FLG_RT_IMGALLOC) {
		free((void *)ADDR(lmp));
		return;
	}

	/*
	 * If padding was enabled via rtld_db, then we have at least one page
	 * in front of the image - and possibly a trailing page.
	 * Unmap the front page first:
	 */
	if (PADSTART(lmp) != ADDR(lmp)) {
		addr = (caddr_t)M_PTRUNC(PADSTART(lmp));
		size = ADDR(lmp) - (ulong_t)addr;
		(void) munmap(addr, size);
	}

	/*
	 * Unmap any trailing padding.
	 */
	if (M_PROUND((PADSTART(lmp) + PADIMLEN(lmp))) >
	    M_PROUND(ADDR(lmp) + MSIZE(lmp))) {
		addr = (caddr_t)M_PROUND(ADDR(lmp) + MSIZE(lmp));
		size = M_PROUND(PADSTART(lmp) + PADIMLEN(lmp)) - (ulong_t)addr;
		(void) munmap(addr, size);
	}

	/*
	 * Unmmap all mapped segments.
	 */
	for (mmaps = MMAPS(lmp); mmaps->m_vaddr; mmaps++)
		(void) munmap(mmaps->m_vaddr, mmaps->m_msize);
}

/*
 * Determine if a dependency requires a particular version and if so verify
 * that the version exists in the dependency.
 */
static int
elf_verify_vers(const char *name, Rt_map *clmp, Rt_map *nlmp)
{
	Verneed		*vnd = VERNEED(clmp);
	int		_num, num = VERNEEDNUM(clmp);
	char		*cstrs = (char *)STRTAB(clmp);
	Lm_list		*lml = LIST(clmp);

	/*
	 * Traverse the callers version needed information and determine if any
	 * specific versions are required from the dependency.
	 */
	DBG_CALL(Dbg_ver_need_title(LIST(clmp), NAME(clmp)));
	for (_num = 1; _num <= num; _num++,
	    vnd = (Verneed *)((Xword)vnd + vnd->vn_next)) {
		Half		cnt = vnd->vn_cnt;
		Vernaux		*vnap;
		char		*nstrs, *need;

		/*
		 * Determine if a needed entry matches this dependency.
		 */
		need = (char *)(cstrs + vnd->vn_file);
		if (strcmp(name, need) != 0)
			continue;

		if ((lml->lm_flags & LML_FLG_TRC_VERBOSE) &&
		    ((FLAGS1(clmp) & FL1_RT_LDDSTUB) == 0))
			(void) printf(MSG_INTL(MSG_LDD_VER_FIND), name);

		/*
		 * Validate that each version required actually exists in the
		 * dependency.
		 */
		nstrs = (char *)STRTAB(nlmp);

		for (vnap = (Vernaux *)((Xword)vnd + vnd->vn_aux); cnt;
		    cnt--, vnap = (Vernaux *)((Xword)vnap + vnap->vna_next)) {
			char		*version, *define;
			Verdef		*vdf = VERDEF(nlmp);
			ulong_t		_num, num = VERDEFNUM(nlmp);
			int		found = 0;

			/*
			 * Skip validation of versions that are marked
			 * INFO. This optimization is used for versions
			 * that are inherited by another version. Verification
			 * of the inheriting version is sufficient.
			 *
			 * Such versions are recorded in the object for the
			 * benefit of VERSYM entries that refer to them. This
			 * provides a purely diagnositic benefit.
			 */
			if (vnap->vna_flags & VER_FLG_INFO)
				continue;

			version = (char *)(cstrs + vnap->vna_name);
			DBG_CALL(Dbg_ver_need_entry(lml, 0, need, version));

			for (_num = 1; _num <= num; _num++,
			    vdf = (Verdef *)((Xword)vdf + vdf->vd_next)) {
				Verdaux		*vdap;

				if (vnap->vna_hash != vdf->vd_hash)
					continue;

				vdap = (Verdaux *)((Xword)vdf + vdf->vd_aux);
				define = (char *)(nstrs + vdap->vda_name);
				if (strcmp(version, define) != 0)
					continue;

				found++;
				break;
			}

			/*
			 * If we're being traced print out any matched version
			 * when the verbose (-v) option is in effect.  Always
			 * print any unmatched versions.
			 */
			if (lml->lm_flags & LML_FLG_TRC_ENABLE) {
				/* BEGIN CSTYLED */
				if (found) {
				    if (!(lml->lm_flags & LML_FLG_TRC_VERBOSE))
					continue;

				    (void) printf(MSG_ORIG(MSG_LDD_VER_FOUND),
					need, version, NAME(nlmp));
				} else {
				    if (rtld_flags & RT_FL_SILENCERR)
					continue;

				    (void) printf(MSG_INTL(MSG_LDD_VER_NFOUND),
					need, version);
				}
				/* END CSTYLED */
				continue;
			}

			/*
			 * If the version hasn't been found then this is a
			 * candidate for a fatal error condition.  Weak
			 * version definition requirements are silently
			 * ignored.  Also, if the image inspected for a version
			 * definition has no versioning recorded at all then
			 * silently ignore this (this provides better backward
			 * compatibility to old images created prior to
			 * versioning being available).  Both of these skipped
			 * diagnostics are available under tracing (see above).
			 */
			if ((found == 0) && (num != 0) &&
			    (!(vnap->vna_flags & VER_FLG_WEAK))) {
				eprintf(lml, ERR_FATAL,
				    MSG_INTL(MSG_VER_NFOUND), need, version,
				    NAME(clmp));
				return (0);
			}
		}
	}
	DBG_CALL(Dbg_util_nl(lml, DBG_NL_STD));
	return (1);
}

/*
 * Search through the dynamic section for DT_NEEDED entries and perform one
 * of two functions.  If only the first argument is specified then load the
 * defined shared object, otherwise add the link map representing the defined
 * link map the the dlopen list.
 */
static int
elf_needed(Lm_list *lml, Aliste lmco, Rt_map *clmp, int *in_nfavl)
{
	Dyn		*dyn, *pdyn;
	ulong_t		ndx = 0;
	uint_t		lazy, flags;
	Word		lmflags = lml->lm_flags;
	Word		lmtflags = lml->lm_tflags;

	/*
	 * Process each shared object on needed list.
	 */
	if (DYN(clmp) == 0)
		return (1);

	for (dyn = (Dyn *)DYN(clmp), pdyn = NULL; dyn->d_tag != DT_NULL;
	    pdyn = dyn++, ndx++) {
		Dyninfo	*dip = &DYNINFO(clmp)[ndx];
		Rt_map	*nlmp = 0;
		char	*name;
		int	silent = 0;
		Pnode	*pnp;

		switch (dyn->d_tag) {
		case DT_POSFLAG_1:
			dip->di_flags |= FLG_DI_POSFLAG1;
			continue;
		case DT_NEEDED:
		case DT_USED:
			lazy = flags = 0;
			dip->di_flags |= FLG_DI_NEEDED;

			if (pdyn && (pdyn->d_tag == DT_POSFLAG_1)) {
				if ((pdyn->d_un.d_val & DF_P1_LAZYLOAD) &&
				    ((lmtflags & LML_TFLG_NOLAZYLD) == 0)) {
					dip->di_flags |= FLG_DI_LAZY;
					lazy = 1;
				}
				if (pdyn->d_un.d_val & DF_P1_GROUPPERM) {
					dip->di_flags |= FLG_DI_GROUP;
					flags =
					    (FLG_RT_SETGROUP | FLG_RT_HANDLE);
				}
			}

			name = (char *)STRTAB(clmp) + dyn->d_un.d_val;

			/*
			 * NOTE, libc.so.1 can't be lazy loaded.  Although a
			 * lazy position flag won't be produced when a RTLDINFO
			 * .dynamic entry is found (introduced with the UPM in
			 * Solaris 10), it was possible to mark libc for lazy
			 * loading on previous releases.  To reduce the overhead
			 * of testing for this occurrence, only carry out this
			 * check for the first object on the link-map list
			 * (there aren't many applications built without libc).
			 */
			if (lazy && (lml->lm_head == clmp) &&
			    (strcmp(name, MSG_ORIG(MSG_FIL_LIBC)) == 0))
				lazy = 0;

			/*
			 * Don't bring in lazy loaded objects yet unless we've
			 * been asked to attempt to load all available objects
			 * (crle(1) sets LD_FLAGS=loadavail).  Even under
			 * RTLD_NOW we don't process this - RTLD_NOW will cause
			 * relocation processing which in turn might trigger
			 * lazy loading, but its possible that the object has a
			 * lazy loaded file with no bindings (i.e., it should
			 * never have been a dependency in the first place).
			 */
			if (lazy) {
				if ((lmflags & LML_FLG_LOADAVAIL) == 0) {
					LAZY(clmp)++;
					lazy = flags = 0;
					continue;
				}

				/*
				 * Silence any error messages - see description
				 * under elf_lookup_filtee().
				 */
				if ((rtld_flags & RT_FL_SILENCERR) == 0) {
					rtld_flags |= RT_FL_SILENCERR;
					silent = 1;
				}
			}
			break;
		case DT_AUXILIARY:
			dip->di_flags |= FLG_DI_AUXFLTR;
			continue;
		case DT_SUNW_AUXILIARY:
			dip->di_flags |= (FLG_DI_AUXFLTR | FLG_DI_SYMFLTR);
			continue;
		case DT_FILTER:
			dip->di_flags |= FLG_DI_STDFLTR;
			continue;
		case DT_SUNW_FILTER:
			dip->di_flags |= (FLG_DI_STDFLTR | FLG_DI_SYMFLTR);
			continue;
		default:
			continue;
		}

		DBG_CALL(Dbg_file_needed(clmp, name));

		/*
		 * If we're running under ldd(1), indicate that this dependency
		 * has been processed.  It doesn't matter whether the object is
		 * successfully loaded or not, this flag simply ensures that we
		 * don't repeatedly attempt to load an object that has already
		 * failed to load.  To do so would create multiple failure
		 * diagnostics for the same object under ldd(1).
		 */
		if (lml->lm_flags & LML_FLG_TRC_ENABLE)
			dip->di_flags |= FLG_DI_LDD_DONE;

		/*
		 * Establish the objects name, load it and establish a binding
		 * with the caller.
		 */
		if (((pnp = elf_fix_name(name, clmp, 0)) == 0) || ((nlmp =
		    load_one(lml, lmco, pnp, clmp, MODE(clmp), flags, 0,
		    in_nfavl)) == 0) || (bind_one(clmp, nlmp, BND_NEEDED) == 0))
			nlmp = 0;

		/*
		 * Clean up any infrastructure, including the removal of the
		 * error suppression state, if it had been previously set in
		 * this routine.
		 */
		if (pnp)
			remove_pnode(pnp);
		if (silent)
			rtld_flags &= ~RT_FL_SILENCERR;

		if ((dip->di_info = (void *)nlmp) == 0) {
			/*
			 * If the object could not be mapped, continue if error
			 * suppression is established or we're here with ldd(1).
			 */
			if ((MODE(clmp) & RTLD_CONFGEN) || (lmflags &
			    (LML_FLG_LOADAVAIL | LML_FLG_TRC_ENABLE)))
				continue;
			else
				return (0);
		}
	}

	if (LAZY(clmp))
		lml->lm_lazy++;

	return (1);
}

static int
elf_map_check(Lm_list *lml, const char *name, caddr_t vaddr, Off size)
{
	prmap_t		*maps, *_maps;
	int		pfd, num, _num;
	caddr_t		eaddr = vaddr + size;
	int		err;

	/*
	 * If memory reservations have been established for alternative objects
	 * determine if this object falls within the reservation, if it does no
	 * further checking is required.
	 */
	if (rtld_flags & RT_FL_MEMRESV) {
		Rtc_head	*head = (Rtc_head *)config->c_bgn;

		if ((vaddr >= (caddr_t)(uintptr_t)head->ch_resbgn) &&
		    (eaddr <= (caddr_t)(uintptr_t)head->ch_resend))
			return (0);
	}

	/*
	 * Determine the mappings presently in use by this process.
	 */
	if ((pfd = pr_open(lml)) == FD_UNAVAIL)
		return (1);

	if (ioctl(pfd, PIOCNMAP, (void *)&num) == -1) {
		err = errno;
		eprintf(lml, ERR_FATAL, MSG_INTL(MSG_SYS_PROC), name,
		    strerror(err));
		return (1);
	}

	if ((maps = malloc((num + 1) * sizeof (prmap_t))) == 0)
		return (1);

	if (ioctl(pfd, PIOCMAP, (void *)maps) == -1) {
		err = errno;
		eprintf(lml, ERR_FATAL, MSG_INTL(MSG_SYS_PROC), name,
		    strerror(err));
		free(maps);
		return (1);
	}

	/*
	 * Determine if the supplied address clashes with any of the present
	 * process mappings.
	 */
	for (_num = 0, _maps = maps; _num < num; _num++, _maps++) {
		caddr_t		_eaddr = _maps->pr_vaddr + _maps->pr_size;
		Rt_map		*lmp;
		const char	*str;

		if ((eaddr < _maps->pr_vaddr) || (vaddr >= _eaddr))
			continue;

		/*
		 * We have a memory clash.  See if one of the known dynamic
		 * dependency mappings represents this space so as to provide
		 * the user a more meaningful message.
		 */
		if ((lmp = _caller(vaddr, 0)) != 0)
			str = NAME(lmp);
		else
			str = MSG_INTL(MSG_STR_UNKNOWN);

		eprintf(lml, ERR_FATAL, MSG_INTL(MSG_GEN_MAPINUSE), name,
		    EC_NATPTR(vaddr), EC_OFF(size), str);
		return (1);
	}
	free(maps);
	return (0);
}

/*
 * Obtain a memory reservation.  On newer systems, both MAP_ANON and MAP_ALIGN
 * are used to obtained an aligned reservation from anonymous memory.  If
 * MAP_ANON isn't available, then MAP_ALIGN isn't either, so obtain a standard
 * reservation using the file as backing.
 */
static Am_ret
elf_map_reserve(Lm_list *lml, const char *name, caddr_t *maddr, Off msize,
    int mperm, int fd, Xword align)
{
	Am_ret	amret;
	int	mflag = MAP_PRIVATE | MAP_NORESERVE;

#if defined(MAP_ALIGN)
	if ((rtld_flags2 & RT_FL2_NOMALIGN) == 0) {
		mflag |= MAP_ALIGN;
		*maddr = (caddr_t)align;
	}
#endif
	if ((amret = anon_map(lml, maddr, msize, PROT_NONE, mflag)) == AM_ERROR)
		return (amret);

	if (amret == AM_OK)
		return (AM_OK);

	/*
	 * If an anonymous memory request failed (which should only be the
	 * case if it is unsupported on the system we're running on), establish
	 * the initial mapping directly from the file.
	 */
	*maddr = 0;
	if ((*maddr = mmap(*maddr, msize, mperm, MAP_PRIVATE,
	    fd, 0)) == MAP_FAILED) {
		int	err = errno;
		eprintf(lml, ERR_FATAL, MSG_INTL(MSG_SYS_MMAP), name,
		    strerror(err));
		return (AM_ERROR);
	}
	return (AM_NOSUP);
}

static void *
elf_map_textdata(caddr_t addr, Off flen, int mperm, int phdr_mperm, int mflag,
    int fd, Off foff)
{
#if	defined(MAP_TEXT) && defined(MAP_INITDATA)
	static int	notd = 0;

	/*
	 * If MAP_TEXT and MAP_INITDATA are available, select the appropriate
	 * flag.
	 */
	if (notd == 0) {
		if ((phdr_mperm & (PROT_WRITE | PROT_EXEC)) == PROT_EXEC)
			mflag |= MAP_TEXT;
		else
			mflag |= MAP_INITDATA;
	}
#endif
	if (mmap((caddr_t)addr, flen, mperm, mflag, fd, foff) != MAP_FAILED)
		return (0);

#if	defined(MAP_TEXT) && defined(MAP_INITDATA)
	if ((notd == 0) && (errno == EINVAL)) {
		/*
		 * MAP_TEXT and MAP_INITDATA may not be supported on this
		 * platform, try again without.
		 */
		notd = 1;
		mflag &= ~(MAP_TEXT | MAP_INITDATA);

		return (mmap((caddr_t)addr, flen, mperm, mflag, fd, foff));
	}
#endif
	return (MAP_FAILED);
}

/*
 * Map in a file.
 */
static caddr_t
elf_map_it(
	Lm_list		*lml,		/* link-map list */
	const char	*name,		/* actual name stored for pathname */
	Off		fsize,		/* total mapping claim of the file */
	Ehdr		*ehdr,		/* ELF header of file */
	Phdr		*fphdr,		/* first loadable Phdr */
	Phdr		*lphdr,		/* last loadable Phdr */
	Phdr		**rrphdr,	/* return first Phdr in reservation */
	caddr_t		*rraddr,	/* return start of reservation */
	Off		*rrsize,	/* return total size of reservation */
	int		fixed,		/* image is resolved to a fixed addr */
	int		fd,		/* images file descriptor */
	Xword		align,		/* image segments maximum alignment */
	Mmap		*mmaps,		/* mmap information array and */
	uint_t		*mmapcnt)	/* 	mapping count */
{
	caddr_t		raddr;		/* reservation address */
	Off		rsize;		/* reservation size */
	Phdr		*phdr;		/* working program header poiner */
	caddr_t		maddr;		/* working mmap address */
	caddr_t		faddr;		/* working file address */
	size_t		padsize;	/* object padding requirement */
	size_t		padpsize = 0;	/* padding size rounded to next page */
	size_t		padmsize = 0;	/* padding size rounded for alignment */
	int		skipfseg;	/* skip mapping first segment */
	int		mperm;		/* segment permissions */
	Am_ret		amret = AM_NOSUP;

	/*
	 * If padding is required extend both the front and rear of the image.
	 * To insure the image itself is mapped at the correct alignment the
	 * initial padding is rounded up to the nearest page.  Once the image is
	 * mapped the excess can be pruned to the nearest page required for the
	 * actual padding itself.
	 */
	if ((padsize = r_debug.rtd_objpad) != 0) {
		padpsize = M_PROUND(padsize);
		if (fixed)
			padmsize = padpsize;
		else
			padmsize = S_ROUND(padsize, align);
	}

	/*
	 * Determine the initial permissions used to map in the first segment.
	 * If this segments memsz is greater that its filesz then the difference
	 * must be zeroed.  Make sure this segment is writable.
	 */
	mperm = 0;
	if (fphdr->p_flags & PF_R)
		mperm |= PROT_READ;
	if (fphdr->p_flags & PF_X)
		mperm |= PROT_EXEC;
	if ((fphdr->p_flags & PF_W) || (fphdr->p_memsz > fphdr->p_filesz))
		mperm |= PROT_WRITE;

	/*
	 * Determine whether or not to let system reserve address space based on
	 * whether this is a dynamic executable (addresses in object are fixed)
	 * or a shared object (addresses in object are relative to the objects'
	 * base).
	 */
	if (fixed) {
		/*
		 * Determine the reservation address and size, and insure that
		 * this reservation isn't already in use.
		 */
		faddr = maddr = (caddr_t)M_PTRUNC((ulong_t)fphdr->p_vaddr);
		raddr = maddr - padpsize;
		rsize = fsize + padpsize + padsize;

		if (lml_main.lm_head) {
			if (elf_map_check(lml, name, raddr, rsize) != 0)
				return (0);
		}

		/*
		 * As this is a fixed image, all segments must be individually
		 * mapped.
		 */
		skipfseg = 0;

	} else {
		size_t	esize;

		/*
		 * If this isn't a fixed image, reserve enough address space for
		 * the entire image to be mapped.  The amount of reservation is
		 * the range between the beginning of the first, and end of the
		 * last loadable segment, together with any padding, plus the
		 * alignment of the first segment.
		 *
		 * The optimal reservation is made as a no-reserve mapping from
		 * anonymous memory.  Each segment is then mapped into this
		 * reservation.  If the anonymous mapping capability isn't
		 * available, the reservation is obtained from the file itself.
		 * In this case the first segment of the image is mapped as part
		 * of the reservation, thus only the following segments need to
		 * be remapped.
		 */
		rsize = fsize + padmsize + padsize;
		if ((amret = elf_map_reserve(lml, name, &raddr, rsize, mperm,
		    fd, align)) == AM_ERROR)
			return (0);
		maddr = raddr + padmsize;
		faddr = (caddr_t)S_ROUND((Off)maddr, align);

		/*
		 * If this reservation has been obtained from anonymous memory,
		 * then all segments must be individually mapped.  Otherwise,
		 * the first segment heads the reservation.
		 */
		if (amret == AM_OK)
			skipfseg = 0;
		else
			skipfseg = 1;

		/*
		 * For backward compatibility (where MAP_ALIGN isn't available),
		 * insure the alignment of the reservation is adequate for this
		 * object, and if not remap the object to obtain the correct
		 * alignment.
		 */
		if (faddr != maddr) {
			(void) munmap(raddr, rsize);

			rsize += align;
			if ((amret = elf_map_reserve(lml, name, &raddr, rsize,
			    mperm, fd, align)) == AM_ERROR)
				return (0);

			maddr = faddr = (caddr_t)S_ROUND((Off)(raddr +
			    padpsize), align);

			esize = maddr - raddr + padpsize;

			/*
			 * As ths image has been realigned, the first segment
			 * of the file needs to be remapped to its correct
			 * location.
			 */
			skipfseg = 0;
		} else
			esize = padmsize - padpsize;

		/*
		 * If this reservation included padding, remove any excess for
		 * the start of the image (the padding was adjusted to insure
		 * the image was aligned appropriately).
		 */
		if (esize) {
			(void) munmap(raddr, esize);
			raddr += esize;
			rsize -= esize;
		}
	}

	/*
	 * At this point we know the initial location of the image, and its
	 * size.  Pass these back to the caller for inclusion in the link-map
	 * that will eventually be created.
	 */
	*rraddr = raddr;
	*rrsize = rsize;

	/*
	 * The first loadable segment is now pointed to by maddr.  This segment
	 * will eventually contain the elf header and program headers, so reset
	 * the program header.  Pass this  back to the caller for inclusion in
	 * the link-map so it can be used for later unmapping operations.
	 */
	/* LINTED */
	*rrphdr = (Phdr *)((char *)maddr + ehdr->e_phoff);

	/*
	 * If padding is required at the front of the image, obtain that now.
	 * Note, if we've already obtained a reservation from anonymous memory
	 * then this reservation will already include suitable padding.
	 * Otherwise this reservation is backed by the file, or in the case of
	 * a fixed image, doesn't yet exist.  Map the padding so that it is
	 * suitably protected (PROT_NONE), and insure the first segment of the
	 * file is mapped to its correct location.
	 */
	if (padsize) {
		if (amret == AM_NOSUP) {
			if (dz_map(lml, raddr, padpsize, PROT_NONE,
			    (MAP_PRIVATE | MAP_FIXED | MAP_NORESERVE)) ==
			    MAP_FAILED)
				return (0);

			skipfseg = 0;
		}
		rsize -= padpsize;
	}

	/*
	 * Map individual segments.  For a fixed image, these will each be
	 * unique mappings.  For a reservation these will fill in the
	 * reservation.
	 */
	for (phdr = fphdr; phdr <= lphdr;
	    phdr = (Phdr *)((Off)phdr + ehdr->e_phentsize)) {
		caddr_t	addr;
		Off	mlen, flen;
		size_t	size;

		/*
		 * Skip non-loadable segments or segments that don't occupy
		 * any memory.
		 */
		if (((phdr->p_type != PT_LOAD) &&
		    (phdr->p_type != PT_SUNWBSS)) || (phdr->p_memsz == 0))
			continue;

		/*
		 * Establish this segments address relative to our base.
		 */
		addr = (caddr_t)M_PTRUNC((ulong_t)(phdr->p_vaddr +
		    (fixed ? 0 : faddr)));

		/*
		 * Determine the mapping protection from the segment attributes.
		 * Also determine the etext address from the last loadable
		 * segment which has permissions but no write access.
		 */
		mperm = 0;
		if (phdr->p_flags) {
			if (phdr->p_flags & PF_R)
				mperm |= PROT_READ;
			if (phdr->p_flags & PF_X)
				mperm |= PROT_EXEC;
			if (phdr->p_flags & PF_W)
				mperm |= PROT_WRITE;
			else
				fmap->fm_etext = phdr->p_vaddr + phdr->p_memsz +
				    (ulong_t)(fixed ? 0 : faddr);
		}

		/*
		 * Determine the type of mapping required.
		 */
		if (phdr->p_type == PT_SUNWBSS) {
			/*
			 * Potentially, we can defer the loading of any SUNWBSS
			 * segment, depending on whether the symbols it provides
			 * have been bound to.  In this manner, large segments
			 * that are interposed upon between shared libraries
			 * may not require mapping.  Note, that the mapping
			 * information is recorded in our mapping descriptor at
			 * this time.
			 */
			mlen = phdr->p_memsz;
			flen = 0;

		} else if ((phdr->p_filesz == 0) && (phdr->p_flags == 0)) {
			/*
			 * If this segment has no backing file and no flags
			 * specified, then it defines a reservation.  At this
			 * point all standard loadable segments will have been
			 * processed.  The segment reservation is mapped
			 * directly from /dev/null.
			 */
			if (nu_map(lml, (caddr_t)addr, phdr->p_memsz, PROT_NONE,
			    MAP_FIXED | MAP_PRIVATE) == MAP_FAILED)
				return (0);

			mlen = phdr->p_memsz;
			flen = 0;

		} else if (phdr->p_filesz == 0) {
			/*
			 * If this segment has no backing file then it defines a
			 * nobits segment and is mapped directly from /dev/zero.
			 */
			if (dz_map(lml, (caddr_t)addr, phdr->p_memsz, mperm,
			    MAP_FIXED | MAP_PRIVATE) == MAP_FAILED)
				return (0);

			mlen = phdr->p_memsz;
			flen = 0;

		} else {
			Off	foff;

			/*
			 * This mapping originates from the file.  Determine the
			 * file offset to which the mapping will be directed
			 * (must be aligned) and how much to map (might be more
			 * than the file in the case of .bss).
			 */
			foff = M_PTRUNC((ulong_t)phdr->p_offset);
			mlen = phdr->p_memsz + (phdr->p_offset - foff);
			flen = phdr->p_filesz + (phdr->p_offset - foff);

			/*
			 * If this is a non-fixed, non-anonymous mapping, and no
			 * padding is involved, then the first loadable segment
			 * is already part of the initial reservation.  In this
			 * case there is no need to remap this segment.
			 */
			if ((skipfseg == 0) || (phdr != fphdr)) {
				int phdr_mperm = mperm;
				/*
				 * If this segments memsz is greater that its
				 * filesz then the difference must be zeroed.
				 * Make sure this segment is writable.
				 */
				if (phdr->p_memsz > phdr->p_filesz)
					mperm |= PROT_WRITE;

				if (elf_map_textdata((caddr_t)addr, flen,
				    mperm, phdr_mperm,
				    (MAP_FIXED | MAP_PRIVATE), fd, foff) ==
				    MAP_FAILED) {
					int	err = errno;
					eprintf(lml, ERR_FATAL,
					    MSG_INTL(MSG_SYS_MMAP), name,
					    strerror(err));
					return (0);
				}
			}

			/*
			 * If the memory occupancy of the segment overflows the
			 * definition in the file, we need to "zero out" the end
			 * of the mapping we've established, and if necessary,
			 * map some more space from /dev/zero.  Note, zero'ed
			 * memory must end on a double word boundary to satisfy
			 * zero().
			 */
			if (phdr->p_memsz > phdr->p_filesz) {
				caddr_t	zaddr;
				size_t	zlen, zplen;
				Off	fend;

				foff = (Off)(phdr->p_vaddr + phdr->p_filesz +
				    (fixed ? 0 : faddr));
				zaddr = (caddr_t)M_PROUND(foff);
				zplen = (size_t)(zaddr - foff);

				fend = (Off)S_DROUND((size_t)(phdr->p_vaddr +
				    phdr->p_memsz + (fixed ? 0 : faddr)));
				zlen = (size_t)(fend - foff);

				/*
				 * Determine whether the number of bytes that
				 * must be zero'ed overflow to the next page.
				 * If not, simply clear the exact bytes
				 * (filesz to memsz) from this page.  Otherwise,
				 * clear the remaining bytes of this page, and
				 * map an following pages from /dev/zero.
				 */
				if (zlen < zplen)
					zero((caddr_t)foff, (long)zlen);
				else {
					zero((caddr_t)foff, (long)zplen);

					if ((zlen = (fend - (Off)zaddr)) > 0) {
						if (dz_map(lml, zaddr, zlen,
						    mperm,
						    MAP_FIXED | MAP_PRIVATE) ==
						    MAP_FAILED)
							return (0);
					}
				}
			}
		}

		/*
		 * Unmap anything from the last mapping address to this one and
		 * update the mapping claim pointer.
		 */
		if ((fixed == 0) && ((size = addr - maddr) != 0)) {
			(void) munmap(maddr, size);
			rsize -= size;
		}

		/*
		 * Retain this segments mapping information.
		 */
		mmaps[*mmapcnt].m_vaddr = addr;
		mmaps[*mmapcnt].m_msize = mlen;
		mmaps[*mmapcnt].m_fsize = flen;
		mmaps[*mmapcnt].m_perm = mperm;
		(*mmapcnt)++;

		maddr = addr + M_PROUND(mlen);
		rsize -= M_PROUND(mlen);
	}

	/*
	 * If padding is required at the end of the image, obtain that now.
	 * Note, if we've already obtained a reservation from anonymous memory
	 * then this reservation will already include suitable padding.
	 */
	if (padsize) {
		if (amret == AM_NOSUP) {
			/*
			 * maddr is currently page aligned from the last segment
			 * mapping.
			 */
			if (dz_map(lml, maddr, padsize, PROT_NONE,
			    (MAP_PRIVATE | MAP_FIXED | MAP_NORESERVE)) ==
			    MAP_FAILED)
				return (0);
		}
		maddr += padsize;
		rsize -= padsize;
	}

	/*
	 * Unmap any final reservation.
	 */
	if ((fixed == 0) && (rsize != 0))
		(void) munmap(maddr, rsize);

	return (faddr);
}

/*
 * A null symbol interpretor.  Used if a filter has no associated filtees.
 */
/* ARGSUSED0 */
static Sym *
elf_null_find_sym(Slookup *slp, Rt_map **dlmp, uint_t *binfo, int *in_nfavl)
{
	return ((Sym *)0);
}

/*
 * Disable filtee use.
 */
static void
elf_disable_filtee(Rt_map *lmp, Dyninfo *dip)
{
	dip->di_info = 0;

	if ((dip->di_flags & FLG_DI_SYMFLTR) == 0) {
		/*
		 * If this is an object filter, free the filtee's duplication.
		 */
		if (OBJFLTRNDX(lmp) != FLTR_DISABLED) {
			free(REFNAME(lmp));
			REFNAME(lmp) = (char *)0;
			OBJFLTRNDX(lmp) = FLTR_DISABLED;

			/*
			 * Indicate that this filtee is no longer available.
			 */
			if (dip->di_flags & FLG_DI_STDFLTR)
				SYMINTP(lmp) = elf_null_find_sym;

		}
	} else if (dip->di_flags & FLG_DI_STDFLTR) {
		/*
		 * Indicate that this standard filtee is no longer available.
		 */
		if (SYMSFLTRCNT(lmp))
			SYMSFLTRCNT(lmp)--;
	} else {
		/*
		 * Indicate that this auxiliary filtee is no longer available.
		 */
		if (SYMAFLTRCNT(lmp))
			SYMAFLTRCNT(lmp)--;
	}
	dip->di_flags &= ~MSK_DI_FILTER;
}

/*
 * Find symbol interpreter - filters.
 * This function is called when the symbols from a shared object should
 * be resolved from the shared objects filtees instead of from within itself.
 *
 * A symbol name of 0 is used to trigger filtee loading.
 */
static Sym *
_elf_lookup_filtee(Slookup *slp, Rt_map **dlmp, uint_t *binfo, uint_t ndx,
    int *in_nfavl)
{
	const char	*name = slp->sl_name, *filtees;
	Rt_map		*clmp = slp->sl_cmap;
	Rt_map		*ilmp = slp->sl_imap;
	Pnode		*pnp, **pnpp;
	int		any;
	Dyninfo		*dip = &DYNINFO(ilmp)[ndx];
	Lm_list		*lml = LIST(ilmp);

	/*
	 * Indicate that the filter has been used.  If a binding already exists
	 * to the caller, indicate that this object is referenced.  This insures
	 * we don't generate false unreferenced diagnostics from ldd -u/U or
	 * debugging.  Don't create a binding regardless, as this filter may
	 * have been dlopen()'ed.
	 */
	if (name && (ilmp != clmp)) {
		Word	tracing = (LIST(clmp)->lm_flags &
		    (LML_FLG_TRC_UNREF | LML_FLG_TRC_UNUSED));

		if (tracing || DBG_ENABLED) {
			Bnd_desc 	*bdp;
			Aliste		idx;

			FLAGS1(ilmp) |= FL1_RT_USED;

			if ((tracing & LML_FLG_TRC_UNREF) || DBG_ENABLED) {
				for (APLIST_TRAVERSE(CALLERS(ilmp), idx, bdp)) {
					if (bdp->b_caller == clmp) {
						bdp->b_flags |= BND_REFER;
						break;
					}
				}
			}
		}
	}

	/*
	 * If this is the first call to process this filter, establish the
	 * filtee list.  If a configuration file exists, determine if any
	 * filtee associations for this filter, and its filtee reference, are
	 * defined.  Otherwise, process the filtee reference.  Any token
	 * expansion is also completed at this point (i.e., $PLATFORM).
	 */
	filtees = (char *)STRTAB(ilmp) + DYN(ilmp)[ndx].d_un.d_val;
	if (dip->di_info == 0) {
		if (rtld_flags2 & RT_FL2_FLTCFG)
			dip->di_info = elf_config_flt(lml, PATHNAME(ilmp),
			    filtees);

		if (dip->di_info == 0) {
			DBG_CALL(Dbg_file_filter(lml, NAME(ilmp), filtees, 0));
			if ((lml->lm_flags &
			    (LML_FLG_TRC_VERBOSE | LML_FLG_TRC_SEARCH)) &&
			    ((FLAGS1(ilmp) & FL1_RT_LDDSTUB) == 0))
				(void) printf(MSG_INTL(MSG_LDD_FIL_FILTER),
				    NAME(ilmp), filtees);

			if ((dip->di_info = (void *)expand_paths(ilmp,
			    filtees, 0, 0)) == 0) {
				elf_disable_filtee(ilmp, dip);
				return ((Sym *)0);
			}
		}
	}

	/*
	 * Traverse the filtee list, dlopen()'ing any objects specified and
	 * using their group handle to lookup the symbol.
	 */
	for (any = 0, pnpp = (Pnode **)&(dip->di_info), pnp = *pnpp; pnp;
	    pnpp = &pnp->p_next, pnp = *pnpp) {
		int	mode;
		Grp_hdl	*ghp;
		Rt_map	*nlmp = 0;

		if (pnp->p_len == 0)
			continue;

		/*
		 * Establish the mode of the filtee from the filter.  As filtees
		 * are loaded via a dlopen(), make sure that RTLD_GROUP is set
		 * and the filtees aren't global.  It would be nice to have
		 * RTLD_FIRST used here also, but as filters got out long before
		 * RTLD_FIRST was introduced it's a little too late now.
		 */
		mode = MODE(ilmp) | RTLD_GROUP;
		mode &= ~RTLD_GLOBAL;

		/*
		 * Insure that any auxiliary filter can locate symbols from its
		 * caller.
		 */
		if (dip->di_flags & FLG_DI_AUXFLTR)
			mode |= RTLD_PARENT;

		/*
		 * Process any hardware capability directory.  Establish a new
		 * link-map control list from which to analyze any newly added
		 * objects.
		 */
		if ((pnp->p_info == 0) && (pnp->p_orig & PN_TKN_HWCAP)) {
			Lm_cntl	*lmc;
			Aliste	lmco;

			if (FLAGS(lml->lm_head) & FLG_RT_RELOCED) {
				if ((lmc = alist_append(&lml->lm_lists, 0,
				    sizeof (Lm_cntl), AL_CNT_LMLISTS)) == 0)
					return ((Sym *)0);
				lmco = (Aliste)((char *)lmc -
				    (char *)lml->lm_lists);
			} else {
				lmc = 0;
				lmco = ALIST_OFF_DATA;
			}

			pnp = hwcap_filtees(pnpp, lmco, lmc, dip, ilmp, filtees,
			    mode, (FLG_RT_HANDLE | FLG_RT_HWCAP), in_nfavl);

			/*
			 * Now that any hardware capability objects have been
			 * processed, remove any link-map control list.
			 */
			if (lmc)
				remove_cntl(lml, lmco);
		}

		if (pnp->p_len == 0)
			continue;

		/*
		 * Process an individual filtee.
		 */
		if (pnp->p_info == 0) {
			const char	*filtee = pnp->p_name;
			int		audit = 0;

			DBG_CALL(Dbg_file_filtee(lml, NAME(ilmp), filtee, 0));

			ghp = 0;

			/*
			 * Determine if the reference link map is already
			 * loaded.  As an optimization compare the filtee with
			 * our interpretor.  The most common filter is
			 * libdl.so.1, which is a filter on ld.so.1.
			 */
#if	defined(_ELF64)
			if (strcmp(filtee, MSG_ORIG(MSG_PTH_RTLD_64)) == 0) {
#else
			if (strcmp(filtee, MSG_ORIG(MSG_PTH_RTLD)) == 0) {
#endif
				/*
				 * Create an association between ld.so.1 and the
				 * filter.  As an optimization, a handle for
				 * ld.so.1 itself (required for the dlopen()
				 * family filtering mechanism) shouldn't search
				 * any dependencies of ld.so.1.  Omitting
				 * GPD_ADDEPS prevents the addition of any
				 * ld.so.1 dependencies to this handle.
				 */
				nlmp = lml_rtld.lm_head;
				if ((ghp = hdl_create(&lml_rtld, nlmp, ilmp,
				    (GPH_LDSO | GPH_FIRST | GPH_FILTEE),
				    (GPD_DLSYM | GPD_RELOC), GPD_PARENT)) == 0)
					nlmp = 0;

				/*
				 * Establish the filter handle to prevent any
				 * recursion.
				 */
				if (nlmp && ghp)
					pnp->p_info = (void *)ghp;

				/*
				 * Audit the filter/filtee established.  Ignore
				 * any return from the auditor, as we can't
				 * allow ignore filtering to ld.so.1, otherwise
				 * nothing is going to work.
				 */
				if (nlmp && ((lml->lm_tflags | FLAGS1(ilmp)) &
				    LML_TFLG_AUD_OBJFILTER))
					(void) audit_objfilter(ilmp, filtees,
					    nlmp, 0);

			} else {
				Rej_desc	rej = { 0 };
				Lm_cntl		*lmc;
				Aliste		lmco;

				/*
				 * Establish a new link-map control list from
				 * which to analyze any newly added objects.
				 */
				if (FLAGS(lml->lm_head) & FLG_RT_RELOCED) {
					if ((lmc =
					    alist_append(&lml->lm_lists, 0,
					    sizeof (Lm_cntl),
					    AL_CNT_LMLISTS)) == 0)
						return ((Sym *)0);
					lmco = (Aliste)((char *)lmc -
					    (char *)lml->lm_lists);
				} else {
					lmc = 0;
					lmco = ALIST_OFF_DATA;
				}

				/*
				 * Load the filtee.  Note, an auditor can
				 * provide an alternative name.
				 */
				if ((nlmp = load_path(lml, lmco, &(pnp->p_name),
				    ilmp, mode, FLG_RT_HANDLE, &ghp, 0,
				    &rej, in_nfavl)) == 0) {
					file_notfound(LIST(ilmp), filtee, ilmp,
					    FLG_RT_HANDLE, &rej);
					remove_rej(&rej);
				}
				filtee = pnp->p_name;

				/*
				 * Establish the filter handle to prevent any
				 * recursion.
				 */
				if (nlmp && ghp) {
					ghp->gh_flags |= GPH_FILTEE;
					pnp->p_info = (void *)ghp;

					FLAGS1(nlmp) |= FL1_RT_USED;
				}

				/*
				 * Audit the filter/filtee established.  A
				 * return of 0 indicates the auditor wishes to
				 * ignore this filtee.
				 */
				if (nlmp && ((lml->lm_tflags | FLAGS1(ilmp)) &
				    LML_TFLG_AUD_OBJFILTER)) {
					if (audit_objfilter(ilmp, filtees,
					    nlmp, 0) == 0) {
						audit = 1;
						nlmp = 0;
					}
				}

				/*
				 * Finish processing the objects associated with
				 * this request.  Create an association between
				 * this object and the originating filter to
				 * provide sufficient information to tear down
				 * this filtee if necessary.
				 */
				if (nlmp && ghp && ((analyze_lmc(lml, lmco,
				    nlmp, in_nfavl) == 0) || (relocate_lmc(lml,
				    lmco, ilmp, nlmp, in_nfavl) == 0)))
					nlmp = 0;

				/*
				 * If the filtee has been successfully
				 * processed, then create an association
				 * between the filter and filtee.  This
				 * association provides sufficient information
				 * to tear down the filter and filtee if
				 * necessary.
				 */
				DBG_CALL(Dbg_file_hdl_title(DBG_HDL_ADD));
				if (nlmp && ghp &&
				    (hdl_add(ghp, ilmp, GPD_FILTER) == 0))
					nlmp = 0;

				/*
				 * If this filtee loading has failed, and we've
				 * created a new link-map control list to which
				 * this request has added objects, then remove
				 * all the objects that have been associated to
				 * this request.
				 */
				if ((nlmp == 0) && lmc && lmc->lc_head)
					remove_lmc(lml, clmp, lmc, lmco, name);

				/*
				 * Remove any link-map control list that was
				 * created.
				 */
				if (lmc)
					remove_cntl(lml, lmco);
			}

			/*
			 * Generate a diagnostic if the filtee couldn't be
			 * loaded, null out the pnode entry, and continue
			 * the search.  Otherwise, retain this group handle
			 * for future symbol searches.
			 */
			if (nlmp == 0) {
				DBG_CALL(Dbg_file_filtee(lml, 0, filtee,
				    audit));

				pnp->p_info = 0;
				pnp->p_len = 0;
				continue;
			}
		}

		ghp = (Grp_hdl *)pnp->p_info;

		/*
		 * If we're just here to trigger filtee loading skip the symbol
		 * lookup so we'll continue looking for additional filtees.
		 */
		if (name) {
			Grp_desc	*gdp;
			Sym		*sym = 0;
			Aliste		idx;
			Slookup		sl = *slp;

			sl.sl_flags |= LKUP_FIRST;
			any++;

			/*
			 * Look for the symbol in the handles dependencies.
			 */
			for (ALIST_TRAVERSE(ghp->gh_depends, idx, gdp)) {
				if ((gdp->gd_flags & GPD_DLSYM) == 0)
					continue;

				/*
				 * If our parent is a dependency don't look at
				 * it (otherwise we are in a recursive loop).
				 * This situation can occur with auxiliary
				 * filters if the filtee has a dependency on the
				 * filter.  This dependency isn't necessary as
				 * auxiliary filters are opened RTLD_PARENT, but
				 * users may still unknowingly add an explicit
				 * dependency to the parent.
				 */
				if ((sl.sl_imap = gdp->gd_depend) == ilmp)
					continue;

				if (((sym = SYMINTP(sl.sl_imap)(&sl, dlmp,
				    binfo, in_nfavl)) != 0) ||
				    (ghp->gh_flags & GPH_FIRST))
					break;
			}

			/*
			 * If a symbol has been found, indicate the binding
			 * and return the symbol.
			 */
			if (sym) {
				*binfo |= DBG_BINFO_FILTEE;
				return (sym);
			}
		}

		/*
		 * If this object is tagged to terminate filtee processing we're
		 * done.
		 */
		if (FLAGS1(ghp->gh_ownlmp) & FL1_RT_ENDFILTE)
			break;
	}

	/*
	 * If we're just here to trigger filtee loading then we're done.
	 */
	if (name == 0)
		return ((Sym *)0);

	/*
	 * If no filtees have been found for a filter, clean up any Pnode
	 * structures and disable their search completely.  For auxiliary
	 * filters we can reselect the symbol search function so that we never
	 * enter this routine again for this object.  For standard filters we
	 * use the null symbol routine.
	 */
	if (any == 0) {
		remove_pnode((Pnode *)dip->di_info);
		elf_disable_filtee(ilmp, dip);
		return ((Sym *)0);
	}

	return ((Sym *)0);
}

/*
 * Focal point for disabling error messages for auxiliary filters.  As an
 * auxiliary filter allows for filtee use, but provides a fallback should a
 * filtee not exist (or fail to load), any errors generated as a consequence of
 * trying to load the filtees are typically suppressed.  Setting RT_FL_SILENCERR
 * suppresses errors generated by eprint(), but insures a debug diagnostic is
 * produced.  ldd(1) employs printf(), and here, the selection of whether to
 * print a diagnostic in regards to auxiliary filters is a little more complex.
 *
 *   .	The determination of whether to produce an ldd message, or a fatal
 *	error message is driven by LML_FLG_TRC_ENABLE.
 *   .	More detailed ldd messages may also be driven off of LML_FLG_TRC_WARN,
 *	(ldd -d/-r), LML_FLG_TRC_VERBOSE (ldd -v), LML_FLG_TRC_SEARCH (ldd -s),
 *	and LML_FLG_TRC_UNREF/LML_FLG_TRC_UNUSED (ldd -U/-u).
 *
 *   .	If the calling object is lddstub, then several classes of message are
 *	suppressed.  The user isn't trying to diagnose lddstub, this is simply
 *	a stub executable employed to preload a user specified library against.
 *
 *   .	If RT_FL_SILENCERR is in effect then any generic ldd() messages should
 *	be suppressed.  All detailed ldd messages should still be produced.
 */
Sym *
elf_lookup_filtee(Slookup *slp, Rt_map **dlmp, uint_t *binfo, uint_t ndx,
    int *in_nfavl)
{
	Sym	*sym;
	Dyninfo	*dip = &DYNINFO(slp->sl_imap)[ndx];
	int	silent = 0;

	/*
	 * Make sure this entry is still acting as a filter.  We may have tried
	 * to process this previously, and disabled it if the filtee couldn't
	 * be processed.  However, other entries may provide different filtees
	 * that are yet to be completed.
	 */
	if (dip->di_flags == 0)
		return ((Sym *)0);

	/*
	 * Indicate whether an error message is required should this filtee not
	 * be found, based on the type of filter.
	 */
	if ((dip->di_flags & FLG_DI_AUXFLTR) &&
	    ((rtld_flags & (RT_FL_WARNFLTR | RT_FL_SILENCERR)) == 0)) {
		rtld_flags |= RT_FL_SILENCERR;
		silent = 1;
	}

	sym = _elf_lookup_filtee(slp, dlmp, binfo, ndx, in_nfavl);

	if (silent)
		rtld_flags &= ~RT_FL_SILENCERR;

	return (sym);
}

/*
 * Compute the elf hash value (as defined in the ELF access library).
 * The form of the hash table is:
 *
 *	|--------------|
 *	| # of buckets |
 *	|--------------|
 *	| # of chains  |
 *	|--------------|
 *	|   bucket[]   |
 *	|--------------|
 *	|   chain[]    |
 *	|--------------|
 */
ulong_t
elf_hash(const char *name)
{
	uint_t	hval = 0;

	while (*name) {
		uint_t	g;
		hval = (hval << 4) + *name++;
		if ((g = (hval & 0xf0000000)) != 0)
			hval ^= g >> 24;
		hval &= ~g;
	}
	return ((ulong_t)hval);
}

/*
 * If flag argument has LKUP_SPEC set, we treat undefined symbols of type
 * function specially in the executable - if they have a value, even though
 * undefined, we use that value.  This allows us to associate all references
 * to a function's address to a single place in the process: the plt entry
 * for that function in the executable.  Calls to lookup from plt binding
 * routines do NOT set LKUP_SPEC in the flag.
 */
Sym *
elf_find_sym(Slookup *slp, Rt_map **dlmp, uint_t *binfo, int *in_nfavl)
{
	const char	*name = slp->sl_name;
	Rt_map		*ilmp = slp->sl_imap;
	ulong_t		hash = slp->sl_hash;
	uint_t		ndx, htmp, buckets, *chainptr;
	Sym		*sym, *symtabptr;
	char		*strtabptr, *strtabname;
	uint_t		flags1;
	Syminfo		*sip;

	/*
	 * If we're only here to establish a symbols index, skip the diagnostic
	 * used to trace a symbol search.
	 */
	if ((slp->sl_flags & LKUP_SYMNDX) == 0)
		DBG_CALL(Dbg_syms_lookup(ilmp, name, MSG_ORIG(MSG_STR_ELF)));

	if (HASH(ilmp) == 0)
		return ((Sym *)0);

	buckets = HASH(ilmp)[0];
	/* LINTED */
	htmp = (uint_t)hash % buckets;

	/*
	 * Get the first symbol on hash chain and initialize the string
	 * and symbol table pointers.
	 */
	if ((ndx = HASH(ilmp)[htmp + 2]) == 0)
		return ((Sym *)0);

	chainptr = HASH(ilmp) + 2 + buckets;
	strtabptr = STRTAB(ilmp);
	symtabptr = SYMTAB(ilmp);

	while (ndx) {
		sym = symtabptr + ndx;
		strtabname = strtabptr + sym->st_name;

		/*
		 * Compare the symbol found with the name required.  If the
		 * names don't match continue with the next hash entry.
		 */
		if ((*strtabname++ != *name) || strcmp(strtabname, &name[1])) {
			if ((ndx = chainptr[ndx]) != 0)
				continue;
			return ((Sym *)0);
		}

		/*
		 * The Solaris ld does not put DT_VERSYM in the dynamic
		 * section, but the GNU ld does. The GNU runtime linker
		 * interprets the top bit of the 16-bit Versym value
		 * (0x8000) as the "hidden" bit. If this bit is set,
		 * the linker is supposed to act as if that symbol does
		 * not exist. The hidden bit supports their versioning
		 * scheme, which allows multiple incompatible functions
		 * with the same name to exist at different versions
		 * within an object. The Solaris linker does not support this
		 * mechanism, or the model of interface evolution that
		 * it allows, but we honor the hidden bit in GNU ld
		 * produced objects in order to interoperate with them.
		 */
		if ((VERSYM(ilmp) != NULL) &&
		    ((VERSYM(ilmp)[ndx] & 0x8000) != 0)) {
			DBG_CALL(Dbg_syms_ignore_gnuver(ilmp, name,
			    ndx, VERSYM(ilmp)[ndx]));
			if ((ndx = chainptr[ndx]) != 0)
				continue;
			return ((Sym *)0);
		}

		/*
		 * If we're only here to establish a symbols index, we're done.
		 */
		if (slp->sl_flags & LKUP_SYMNDX)
			return (sym);

		/*
		 * If we find a match and the symbol is defined, return the
		 * symbol pointer and the link map in which it was found.
		 */
		if (sym->st_shndx != SHN_UNDEF) {
			*dlmp = ilmp;
			*binfo |= DBG_BINFO_FOUND;
			if ((FLAGS(ilmp) & FLG_RT_OBJINTPO) ||
			    ((FLAGS(ilmp) & FLG_RT_SYMINTPO) &&
			    is_sym_interposer(ilmp, sym)))
				*binfo |= DBG_BINFO_INTERPOSE;
			break;

		/*
		 * If we find a match and the symbol is undefined, the
		 * symbol type is a function, and the value of the symbol
		 * is non zero, then this is a special case.  This allows
		 * the resolution of a function address to the plt[] entry.
		 * See SPARC ABI, Dynamic Linking, Function Addresses for
		 * more details.
		 */
		} else if ((slp->sl_flags & LKUP_SPEC) &&
		    (FLAGS(ilmp) & FLG_RT_ISMAIN) && (sym->st_value != 0) &&
		    (ELF_ST_TYPE(sym->st_info) == STT_FUNC)) {
			*dlmp = ilmp;
			*binfo |= (DBG_BINFO_FOUND | DBG_BINFO_PLTADDR);
			if ((FLAGS(ilmp) & FLG_RT_OBJINTPO) ||
			    ((FLAGS(ilmp) & FLG_RT_SYMINTPO) &&
			    is_sym_interposer(ilmp, sym)))
				*binfo |= DBG_BINFO_INTERPOSE;
			return (sym);
		}

		/*
		 * Undefined symbol.
		 */
		return ((Sym *)0);
	}

	/*
	 * We've found a match.  Determine if the defining object contains
	 * symbol binding information.
	 */
	if ((sip = SYMINFO(ilmp)) != 0)
		sip += ndx;

	/*
	 * If this definition is a singleton, and we haven't followed a default
	 * symbol search knowing that we're looking for a singleton (presumably
	 * because the symbol definition has been changed since the referring
	 * object was built), then reject this binding so that the caller can
	 * fall back to a standard symbol search.
	 */
	if ((ELF_ST_VISIBILITY(sym->st_other) == STV_SINGLETON) &&
	    (((slp->sl_flags & LKUP_STANDARD) == 0) ||
	    (((slp->sl_flags & LKUP_SINGLETON) == 0) &&
	    (LIST(ilmp)->lm_flags & LML_FLG_GROUPSEXIST)))) {
		DBG_CALL(Dbg_bind_reject(slp->sl_cmap, ilmp, name,
		    DBG_BNDREJ_SINGLE));
		*binfo |= BINFO_REJSINGLE;
		*binfo &= ~DBG_BINFO_MSK;
		return ((Sym *)0);
	}

	/*
	 * If this is a direct binding request, but the symbol definition has
	 * disabled directly binding to it (presumably because the symbol
	 * definition has been changed since the referring object was built),
	 * indicate this failure so that the caller can fall back to a standard
	 * symbol search.
	 */
	if (sip && (slp->sl_flags & LKUP_DIRECT) &&
	    (sip->si_flags & SYMINFO_FLG_NOEXTDIRECT)) {
		DBG_CALL(Dbg_bind_reject(slp->sl_cmap, ilmp, name,
		    DBG_BNDREJ_NODIR));
		*binfo |= BINFO_REJDIRECT;
		*binfo &= ~DBG_BINFO_MSK;
		return ((Sym *)0);
	}

	/*
	 * Determine whether this object is acting as a filter.
	 */
	if (((flags1 = FLAGS1(ilmp)) & MSK_RT_FILTER) == 0)
		return (sym);

	/*
	 * Determine if this object offers per-symbol filtering, and if so,
	 * whether this symbol references a filtee.
	 */
	if (sip && (flags1 & (FL1_RT_SYMSFLTR | FL1_RT_SYMAFLTR))) {
		/*
		 * If this is a standard filter reference, and no standard
		 * filtees remain to be inspected, we're done.  If this is an
		 * auxiliary filter reference, and no auxiliary filtees remain,
		 * we'll fall through in case any object filtering is available.
		 */
		if ((sip->si_flags & SYMINFO_FLG_FILTER) &&
		    (SYMSFLTRCNT(ilmp) == 0))
			return ((Sym *)0);

		if ((sip->si_flags & SYMINFO_FLG_FILTER) ||
		    ((sip->si_flags & SYMINFO_FLG_AUXILIARY) &&
		    SYMAFLTRCNT(ilmp))) {
			Sym	*fsym;

			/*
			 * This symbol has an associated filtee.  Lookup the
			 * symbol in the filtee, and if it is found return it.
			 * If the symbol doesn't exist, and this is a standard
			 * filter, return an error, otherwise fall through to
			 * catch any object filtering that may be available.
			 */
			if ((fsym = elf_lookup_filtee(slp, dlmp, binfo,
			    sip->si_boundto, in_nfavl)) != 0)
				return (fsym);
			if (sip->si_flags & SYMINFO_FLG_FILTER)
				return ((Sym *)0);
		}
	}

	/*
	 * Determine if this object provides global filtering.
	 */
	if (flags1 & (FL1_RT_OBJSFLTR | FL1_RT_OBJAFLTR)) {
		Sym	*fsym;

		if (OBJFLTRNDX(ilmp) != FLTR_DISABLED) {
			/*
			 * This object has an associated filtee.  Lookup the
			 * symbol in the filtee, and if it is found return it.
			 * If the symbol doesn't exist, and this is a standard
			 * filter, return and error, otherwise return the symbol
			 * within the filter itself.
			 */
			if ((fsym = elf_lookup_filtee(slp, dlmp, binfo,
			    OBJFLTRNDX(ilmp), in_nfavl)) != 0)
				return (fsym);
		}

		if (flags1 & FL1_RT_OBJSFLTR)
			return ((Sym *)0);
	}
	return (sym);
}

/*
 * Create a new Rt_map structure for an ELF object and initialize
 * all values.
 */
Rt_map *
elf_new_lm(Lm_list *lml, const char *pname, const char *oname, Dyn *ld,
    ulong_t addr, ulong_t etext, Aliste lmco, ulong_t msize, ulong_t entry,
    ulong_t paddr, ulong_t padimsize, Mmap *mmaps, uint_t mmapcnt,
    int *in_nfavl)
{
	Rt_map		*lmp;
	ulong_t		base, fltr = 0, audit = 0, cfile = 0, crle = 0;
	Xword		rpath = 0;
	Ehdr		*ehdr = (Ehdr *)addr;

	DBG_CALL(Dbg_file_elf(lml, pname, (ulong_t)ld, addr, msize, entry,
	    lml->lm_lmidstr, lmco));

	/*
	 * Allocate space for the link-map and private elf information.  Once
	 * these are allocated and initialized, we can use remove_so(0, lmp) to
	 * tear down the link-map should any failures occur.
	 */
	if ((lmp = calloc(sizeof (Rt_map), 1)) == 0)
		return (0);
	if ((ELFPRV(lmp) = calloc(sizeof (Rt_elfp), 1)) == 0) {
		free(lmp);
		return (0);
	}

	/*
	 * All fields not filled in were set to 0 by calloc.
	 */
	ORIGNAME(lmp) = PATHNAME(lmp) = NAME(lmp) = (char *)pname;
	DYN(lmp) = ld;
	ADDR(lmp) = addr;
	MSIZE(lmp) = msize;
	ENTRY(lmp) = (Addr)entry;
	SYMINTP(lmp) = elf_find_sym;
	ETEXT(lmp) = etext;
	FCT(lmp) = &elf_fct;
	LIST(lmp) = lml;
	PADSTART(lmp) = paddr;
	PADIMLEN(lmp) = padimsize;
	THREADID(lmp) = rt_thr_self();
	OBJFLTRNDX(lmp) = FLTR_DISABLED;
	SORTVAL(lmp) = -1;

	MMAPS(lmp) = mmaps;
	MMAPCNT(lmp) = mmapcnt;
	ASSERT(mmapcnt != 0);

	/*
	 * If this is a shared object, add the base address to each address.
	 * if this is an executable, use address as is.
	 */
	if (ehdr->e_type == ET_EXEC) {
		base = 0;
		FLAGS(lmp) |= FLG_RT_FIXED;
	} else
		base = addr;

	/*
	 * Fill in rest of the link map entries with information from the file's
	 * dynamic structure.
	 */
	if (ld) {
		uint_t		dynndx = 0;
		Xword		pltpadsz = 0;
		Rti_desc	*rti;

		/* CSTYLED */
		for ( ; ld->d_tag != DT_NULL; ++ld, dynndx++) {
			switch ((Xword)ld->d_tag) {
			case DT_SYMTAB:
				SYMTAB(lmp) = (void *)(ld->d_un.d_ptr + base);
				break;
			case DT_SUNW_SYMTAB:
				SUNWSYMTAB(lmp) =
				    (void *)(ld->d_un.d_ptr + base);
				break;
			case DT_SUNW_SYMSZ:
				SUNWSYMSZ(lmp) = ld->d_un.d_val;
				break;
			case DT_STRTAB:
				STRTAB(lmp) = (void *)(ld->d_un.d_ptr + base);
				break;
			case DT_SYMENT:
				SYMENT(lmp) = ld->d_un.d_val;
				break;
			case DT_FEATURE_1:
				ld->d_un.d_val |= DTF_1_PARINIT;
				if (ld->d_un.d_val & DTF_1_CONFEXP)
					crle = 1;
				break;
			case DT_MOVESZ:
				MOVESZ(lmp) = ld->d_un.d_val;
				FLAGS(lmp) |= FLG_RT_MOVE;
				break;
			case DT_MOVEENT:
				MOVEENT(lmp) = ld->d_un.d_val;
				break;
			case DT_MOVETAB:
				MOVETAB(lmp) = (void *)(ld->d_un.d_ptr + base);
				break;
			case DT_REL:
			case DT_RELA:
				/*
				 * At this time, ld.so. can only handle one
				 * type of relocation per object.
				 */
				REL(lmp) = (void *)(ld->d_un.d_ptr + base);
				break;
			case DT_RELSZ:
			case DT_RELASZ:
				RELSZ(lmp) = ld->d_un.d_val;
				break;
			case DT_RELENT:
			case DT_RELAENT:
				RELENT(lmp) = ld->d_un.d_val;
				break;
			case DT_RELCOUNT:
			case DT_RELACOUNT:
				RELACOUNT(lmp) = (uint_t)ld->d_un.d_val;
				break;
			case DT_TEXTREL:
				FLAGS1(lmp) |= FL1_RT_TEXTREL;
				break;
			case DT_HASH:
				HASH(lmp) = (uint_t *)(ld->d_un.d_ptr + base);
				break;
			case DT_PLTGOT:
				PLTGOT(lmp) = (uint_t *)(ld->d_un.d_ptr + base);
				break;
			case DT_PLTRELSZ:
				PLTRELSZ(lmp) = ld->d_un.d_val;
				break;
			case DT_JMPREL:
				JMPREL(lmp) = (void *)(ld->d_un.d_ptr + base);
				break;
			case DT_INIT:
				if (ld->d_un.d_ptr != NULL)
					INIT(lmp) =
					    (void (*)())(ld->d_un.d_ptr + base);
				break;
			case DT_FINI:
				if (ld->d_un.d_ptr != NULL)
					FINI(lmp) =
					    (void (*)())(ld->d_un.d_ptr + base);
				break;
			case DT_INIT_ARRAY:
				INITARRAY(lmp) = (Addr *)(ld->d_un.d_ptr +
				    base);
				break;
			case DT_INIT_ARRAYSZ:
				INITARRAYSZ(lmp) = (uint_t)ld->d_un.d_val;
				break;
			case DT_FINI_ARRAY:
				FINIARRAY(lmp) = (Addr *)(ld->d_un.d_ptr +
				    base);
				break;
			case DT_FINI_ARRAYSZ:
				FINIARRAYSZ(lmp) = (uint_t)ld->d_un.d_val;
				break;
			case DT_PREINIT_ARRAY:
				PREINITARRAY(lmp) = (Addr *)(ld->d_un.d_ptr +
				    base);
				break;
			case DT_PREINIT_ARRAYSZ:
				PREINITARRAYSZ(lmp) = (uint_t)ld->d_un.d_val;
				break;
			case DT_RPATH:
			case DT_RUNPATH:
				rpath = ld->d_un.d_val;
				break;
			case DT_FILTER:
				fltr = ld->d_un.d_val;
				OBJFLTRNDX(lmp) = dynndx;
				FLAGS1(lmp) |= FL1_RT_OBJSFLTR;
				break;
			case DT_AUXILIARY:
				if (!(rtld_flags & RT_FL_NOAUXFLTR)) {
					fltr = ld->d_un.d_val;
					OBJFLTRNDX(lmp) = dynndx;
				}
				FLAGS1(lmp) |= FL1_RT_OBJAFLTR;
				break;
			case DT_SUNW_FILTER:
				SYMSFLTRCNT(lmp)++;
				FLAGS1(lmp) |= FL1_RT_SYMSFLTR;
				break;
			case DT_SUNW_AUXILIARY:
				if (!(rtld_flags & RT_FL_NOAUXFLTR)) {
					SYMAFLTRCNT(lmp)++;
				}
				FLAGS1(lmp) |= FL1_RT_SYMAFLTR;
				break;
			case DT_DEPAUDIT:
				if (!(rtld_flags & RT_FL_NOAUDIT))
					audit = ld->d_un.d_val;
				break;
			case DT_CONFIG:
				cfile = ld->d_un.d_val;
				break;
			case DT_DEBUG:
				/*
				 * DT_DEBUG entries are only created in
				 * dynamic objects that require an interpretor
				 * (ie. all dynamic executables and some shared
				 * objects), and provide for a hand-shake with
				 * debuggers.  This entry is initialized to
				 * zero by the link-editor.  If a debugger has
				 * us and updated this entry set the debugger
				 * flag, and finish initializing the debugging
				 * structure (see setup() also).  Switch off any
				 * configuration object use as most debuggers
				 * can't handle fixed dynamic executables as
				 * dependencies, and we can't handle requests
				 * like object padding for alternative objects.
				 */
				if (ld->d_un.d_ptr)
					rtld_flags |=
					    (RT_FL_DEBUGGER | RT_FL_NOOBJALT);
				ld->d_un.d_ptr = (Addr)&r_debug;
				break;
			case DT_VERNEED:
				VERNEED(lmp) = (Verneed *)(ld->d_un.d_ptr +
				    base);
				break;
			case DT_VERNEEDNUM:
				/* LINTED */
				VERNEEDNUM(lmp) = (int)ld->d_un.d_val;
				break;
			case DT_VERDEF:
				VERDEF(lmp) = (Verdef *)(ld->d_un.d_ptr + base);
				break;
			case DT_VERDEFNUM:
				/* LINTED */
				VERDEFNUM(lmp) = (int)ld->d_un.d_val;
				break;
			case DT_VERSYM:
				/*
				 * The Solaris ld does not produce DT_VERSYM,
				 * but the GNU ld does, in order to support
				 * their style of versioning, which differs
				 * from ours in some ways, while using the
				 * same data structures. The presence of
				 * DT_VERSYM therefore means that GNU
				 * versioning rules apply to the given file.
				 * If DT_VERSYM is not present, then Solaris
				 * versioning rules apply.
				 */
				VERSYM(lmp) = (Versym *)(ld->d_un.d_ptr + base);
				break;
			case DT_BIND_NOW:
				if ((rtld_flags2 & RT_FL2_BINDLAZY) == 0) {
					MODE(lmp) |= RTLD_NOW;
					MODE(lmp) &= ~RTLD_LAZY;
				}
				break;
			case DT_FLAGS:
				FLAGS2(lmp) |= FL2_RT_DTFLAGS;
				if (ld->d_un.d_val & DF_SYMBOLIC)
					FLAGS1(lmp) |= FL1_RT_SYMBOLIC;
				if (ld->d_un.d_val & DF_TEXTREL)
					FLAGS1(lmp) |= FL1_RT_TEXTREL;
				if ((ld->d_un.d_val & DF_BIND_NOW) &&
				    ((rtld_flags2 & RT_FL2_BINDLAZY) == 0)) {
					MODE(lmp) |= RTLD_NOW;
					MODE(lmp) &= ~RTLD_LAZY;
				}
				/*
				 * Capture any static TLS use, and enforce that
				 * this object be non-deletable.
				 */
				if (ld->d_un.d_val & DF_STATIC_TLS) {
					FLAGS1(lmp) |= FL1_RT_TLSSTAT;
					MODE(lmp) |= RTLD_NODELETE;
				}
				break;
			case DT_FLAGS_1:
				if (ld->d_un.d_val & DF_1_DISPRELPND)
					FLAGS1(lmp) |= FL1_RT_DISPREL;
				if (ld->d_un.d_val & DF_1_GROUP)
					FLAGS(lmp) |=
					    (FLG_RT_SETGROUP | FLG_RT_HANDLE);
				if ((ld->d_un.d_val & DF_1_NOW) &&
				    ((rtld_flags2 & RT_FL2_BINDLAZY) == 0)) {
					MODE(lmp) |= RTLD_NOW;
					MODE(lmp) &= ~RTLD_LAZY;
				}
				if (ld->d_un.d_val & DF_1_NODELETE)
					MODE(lmp) |= RTLD_NODELETE;
				if (ld->d_un.d_val & DF_1_INITFIRST)
					FLAGS(lmp) |= FLG_RT_INITFRST;
				if (ld->d_un.d_val & DF_1_NOOPEN)
					FLAGS(lmp) |= FLG_RT_NOOPEN;
				if (ld->d_un.d_val & DF_1_LOADFLTR)
					FLAGS(lmp) |= FLG_RT_LOADFLTR;
				if (ld->d_un.d_val & DF_1_NODUMP)
					FLAGS(lmp) |= FLG_RT_NODUMP;
				if (ld->d_un.d_val & DF_1_CONFALT)
					crle = 1;
				if (ld->d_un.d_val & DF_1_DIRECT)
					FLAGS1(lmp) |= FL1_RT_DIRECT;
				if (ld->d_un.d_val & DF_1_NODEFLIB)
					FLAGS1(lmp) |= FL1_RT_NODEFLIB;
				if (ld->d_un.d_val & DF_1_ENDFILTEE)
					FLAGS1(lmp) |= FL1_RT_ENDFILTE;
				if (ld->d_un.d_val & DF_1_TRANS)
					FLAGS(lmp) |= FLG_RT_TRANS;
#ifndef	EXPAND_RELATIVE
				if (ld->d_un.d_val & DF_1_ORIGIN)
					FLAGS1(lmp) |= FL1_RT_RELATIVE;
#endif
				/*
				 * Global auditing is only meaningful when
				 * specified by the initiating object of the
				 * process - typically the dynamic executable.
				 * If this is the initiaiting object, its link-
				 * map will not yet have been added to the
				 * link-map list, and consequently the link-map
				 * list is empty.  (see setup()).
				 */
				if (ld->d_un.d_val & DF_1_GLOBAUDIT) {
					if (lml_main.lm_head == 0)
						FLAGS1(lmp) |= FL1_RT_GLOBAUD;
					else
						DBG_CALL(Dbg_audit_ignore(lmp));
				}

				/*
				 * If this object identifies itself as an
				 * interposer, but relocation processing has
				 * already started, then demote it.  It's too
				 * late to guarantee complete interposition.
				 */
				/* BEGIN CSTYLED */
				if (ld->d_un.d_val &
				    (DF_1_INTERPOSE | DF_1_SYMINTPOSE)) {
				    if (lml->lm_flags & LML_FLG_STARTREL) {
					DBG_CALL(Dbg_util_intoolate(lmp));
					if (lml->lm_flags & LML_FLG_TRC_ENABLE)
					    (void) printf(
						MSG_INTL(MSG_LDD_REL_ERR2),
						NAME(lmp));
				    } else if (ld->d_un.d_val & DF_1_INTERPOSE)
					FLAGS(lmp) |= FLG_RT_OBJINTPO;
				    else
					FLAGS(lmp) |= FLG_RT_SYMINTPO;
				}
				/* END CSTYLED */
				break;
			case DT_SYMINFO:
				SYMINFO(lmp) = (Syminfo *)(ld->d_un.d_ptr +
				    base);
				break;
			case DT_SYMINENT:
				SYMINENT(lmp) = ld->d_un.d_val;
				break;
			case DT_PLTPAD:
				PLTPAD(lmp) = (void *)(ld->d_un.d_ptr + base);
				break;
			case DT_PLTPADSZ:
				pltpadsz = ld->d_un.d_val;
				break;
			case DT_SUNW_RTLDINF:
				/*
				 * Maintain a list of RTLDINFO structures.
				 * Typically, libc is the only supplier, and
				 * only one structure is provided.  However,
				 * multiple suppliers and multiple structures
				 * are supported.  For example, one structure
				 * may provide thread_init, and another
				 * structure may provide atexit reservations.
				 */
				if ((rti = alist_append(&lml->lm_rti, 0,
				    sizeof (Rti_desc), AL_CNT_RTLDINFO)) == 0) {
					remove_so(0, lmp);
					return (0);
				}
				rti->rti_lmp = lmp;
				rti->rti_info = (void *)(ld->d_un.d_ptr + base);
				break;
			case DT_SUNW_SORTENT:
				SUNWSORTENT(lmp) = ld->d_un.d_val;
				break;
			case DT_SUNW_SYMSORT:
				SUNWSYMSORT(lmp) =
				    (void *)(ld->d_un.d_ptr + base);
				break;
			case DT_SUNW_SYMSORTSZ:
				SUNWSYMSORTSZ(lmp) = ld->d_un.d_val;
				break;
			case DT_DEPRECATED_SPARC_REGISTER:
			case M_DT_REGISTER:
				FLAGS(lmp) |= FLG_RT_REGSYMS;
				break;
			}
		}

		if (PLTPAD(lmp)) {
			if (pltpadsz == (Xword)0)
				PLTPAD(lmp) = 0;
			else
				PLTPADEND(lmp) = (void *)((Addr)PLTPAD(lmp) +
				    pltpadsz);
		}

		/*
		 * Allocate a Dynamic Info structure.
		 */
		if ((DYNINFO(lmp) = calloc((size_t)dynndx,
		    sizeof (Dyninfo))) == 0) {
			remove_so(0, lmp);
			return (0);
		}
		DYNINFOCNT(lmp) = dynndx;
	}

	/*
	 * A dynsym contains only global functions. We want to have
	 * a version of it that also includes local functions, so that
	 * dladdr() will be able to report names for local functions
	 * when used to generate a stack trace for a stripped file.
	 * This version of the dynsym is provided via DT_SUNW_SYMTAB.
	 *
	 * In producing DT_SUNW_SYMTAB, ld uses a non-obvious trick
	 * in order to avoid having to have two copies of the global
	 * symbols held in DT_SYMTAB: The local symbols are placed in
	 * a separate section than the globals in the dynsym, but the
	 * linker conspires to put the data for these two sections adjacent
	 * to each other. DT_SUNW_SYMTAB points at the top of the local
	 * symbols, and DT_SUNW_SYMSZ is the combined length of both tables.
	 *
	 * If the two sections are not adjacent, then something went wrong
	 * at link time. We use ASSERT to kill the process if this is
	 * a debug build. In a production build, we will silently ignore
	 * the presence of the .ldynsym and proceed. We can detect this
	 * situation by checking to see that DT_SYMTAB lies in
	 * the range given by DT_SUNW_SYMTAB/DT_SUNW_SYMSZ.
	 */
	if ((SUNWSYMTAB(lmp) != NULL) &&
	    (((char *)SYMTAB(lmp) <= (char *)SUNWSYMTAB(lmp)) ||
	    (((char *)SYMTAB(lmp) >=
	    (SUNWSYMSZ(lmp) + (char *)SUNWSYMTAB(lmp)))))) {
		ASSERT(0);
		SUNWSYMTAB(lmp) = NULL;
		SUNWSYMSZ(lmp) = 0;
	}

	/*
	 * If configuration file use hasn't been disabled, and a configuration
	 * file hasn't already been set via an environment variable, see if any
	 * application specific configuration file is specified.  An LD_CONFIG
	 * setting is used first, but if this image was generated via crle(1)
	 * then a default configuration file is a fall-back.
	 */
	if ((!(rtld_flags & RT_FL_NOCFG)) && (config->c_name == 0)) {
		if (cfile)
			config->c_name = (const char *)(cfile +
			    (char *)STRTAB(lmp));
		else if (crle) {
			rtld_flags |= RT_FL_CONFAPP;
#ifndef	EXPAND_RELATIVE
			FLAGS1(lmp) |= FL1_RT_RELATIVE;
#endif
		}
	}

	if (rpath)
		RPATH(lmp) = (char *)(rpath + (char *)STRTAB(lmp));
	if (fltr) {
		/*
		 * If this object is a global filter, duplicate the filtee
		 * string name(s) so that REFNAME() is available in core files.
		 * This cludge was useful for debuggers at one point, but only
		 * when the filtee name was an individual full path.
		 */
		if ((REFNAME(lmp) = strdup(fltr + (char *)STRTAB(lmp))) == 0) {
			remove_so(0, lmp);
			return (0);
		}
	}

	if (rtld_flags & RT_FL_RELATIVE)
		FLAGS1(lmp) |= FL1_RT_RELATIVE;

	/*
	 * For Intel ABI compatibility.  It's possible that a JMPREL can be
	 * specified without any other relocations (e.g. a dynamic executable
	 * normally only contains .plt relocations).  If this is the case then
	 * no REL, RELSZ or RELENT will have been created.  For us to be able
	 * to traverse the .plt relocations under LD_BIND_NOW we need to know
	 * the RELENT for these relocations.  Refer to elf_reloc() for more
	 * details.
	 */
	if (!RELENT(lmp) && JMPREL(lmp))
		RELENT(lmp) = sizeof (Rel);

	/*
	 * Establish any per-object auditing.  If we're establishing `main's
	 * link-map its too early to go searching for audit objects so just
	 * hold the object name for later (see setup()).
	 */
	if (audit) {
		char	*cp = audit + (char *)STRTAB(lmp);

		if (*cp) {
			if (((AUDITORS(lmp) =
			    calloc(1, sizeof (Audit_desc))) == 0) ||
			    ((AUDITORS(lmp)->ad_name = strdup(cp)) == 0)) {
				remove_so(0, lmp);
				return (0);
			}
			if (lml_main.lm_head) {
				if (audit_setup(lmp, AUDITORS(lmp), 0,
				    in_nfavl) == 0) {
					remove_so(0, lmp);
					return (0);
				}
				FLAGS1(lmp) |= AUDITORS(lmp)->ad_flags;
				lml->lm_flags |= LML_FLG_LOCAUDIT;
			}
		}
	}

	if ((CONDVAR(lmp) = rt_cond_create()) == 0) {
		remove_so(0, lmp);
		return (0);
	}
	if (oname && ((append_alias(lmp, oname, 0)) == 0)) {
		remove_so(0, lmp);
		return (0);
	}

	/*
	 * Add the mapped object to the end of the link map list.
	 */
	lm_append(lml, lmco, lmp);
	return (lmp);
}

/*
 * Assign hardware/software capabilities.
 */
void
cap_assign(Cap *cap, Rt_map *lmp)
{
	while (cap->c_tag != CA_SUNW_NULL) {
		switch (cap->c_tag) {
		case CA_SUNW_HW_1:
			HWCAP(lmp) = cap->c_un.c_val;
			break;
		case CA_SUNW_SF_1:
			SFCAP(lmp) = cap->c_un.c_val;
		}
		cap++;
	}
}

/*
 * Map in an ELF object.
 * Takes an open file descriptor for the object to map and its pathname; returns
 * a pointer to a Rt_map structure for this object, or 0 on error.
 */
static Rt_map *
elf_map_so(Lm_list *lml, Aliste lmco, const char *pname, const char *oname,
    int fd, int *in_nfavl)
{
	int		i; 		/* general temporary */
	Off		memsize = 0;	/* total memory size of pathname */
	Off		mentry;		/* entry point */
	Ehdr		*ehdr;		/* ELF header of ld.so */
	Phdr		*phdr;		/* first Phdr in file */
	Phdr		*phdr0;		/* Saved first Phdr in file */
	Phdr		*pptr;		/* working Phdr */
	Phdr		*fph = 0;	/* first loadable Phdr */
	Phdr		*lph;		/* last loadable Phdr */
	Phdr		*lfph = 0;	/* last loadable (filesz != 0) Phdr */
	Phdr		*lmph = 0;	/* last loadable (memsz != 0) Phdr */
	Phdr		*swph = 0;	/* program header for SUNWBSS */
	Phdr		*tlph = 0;	/* program header for PT_TLS */
	Phdr		*unwindph = 0;	/* program header for PT_SUNW_UNWIND */
	Cap		*cap = 0;	/* program header for SUNWCAP */
	Dyn		*mld = 0;	/* DYNAMIC structure for pathname */
	size_t		size;		/* size of elf and program headers */
	caddr_t		faddr = 0;	/* mapping address of pathname */
	Rt_map		*lmp;		/* link map created */
	caddr_t		paddr;		/* start of padded image */
	Off		plen;		/* size of image including padding */
	Half		etype;
	int		fixed;
	Mmap		*mmaps;
	uint_t		mmapcnt = 0;
	Xword		align = 0;

	/* LINTED */
	ehdr = (Ehdr *)fmap->fm_maddr;

	/*
	 * If this a relocatable object then special processing is required.
	 */
	if ((etype = ehdr->e_type) == ET_REL)
		return (elf_obj_file(lml, lmco, pname, fd));

	/*
	 * If this isn't a dynamic executable or shared object we can't process
	 * it.  If this is a dynamic executable then all addresses are fixed.
	 */
	if (etype == ET_EXEC) {
		fixed = 1;
	} else if (etype == ET_DYN) {
		fixed = 0;
	} else {
		Conv_inv_buf_t inv_buf;

		eprintf(lml, ERR_ELF, MSG_INTL(MSG_GEN_BADTYPE), pname,
		    conv_ehdr_type(etype, 0, &inv_buf));
		return (0);
	}

	/*
	 * If our original mapped page was not large enough to hold all the
	 * program headers remap them.
	 */
	size = (size_t)((char *)ehdr->e_phoff +
	    (ehdr->e_phnum * ehdr->e_phentsize));
	if (size > fmap->fm_fsize) {
		eprintf(lml, ERR_FATAL, MSG_INTL(MSG_GEN_CORTRUNC), pname);
		return (0);
	}
	if (size > fmap->fm_msize) {
		fmap_setup();
		if ((fmap->fm_maddr = mmap(fmap->fm_maddr, size, PROT_READ,
		    fmap->fm_mflags, fd, 0)) == MAP_FAILED) {
			int	err = errno;
			eprintf(lml, ERR_FATAL, MSG_INTL(MSG_SYS_MMAP), pname,
			    strerror(err));
			return (0);
		}
		fmap->fm_msize = size;
		/* LINTED */
		ehdr = (Ehdr *)fmap->fm_maddr;
	}
	/* LINTED */
	phdr0 = phdr = (Phdr *)((char *)ehdr + ehdr->e_ehsize);

	/*
	 * Get entry point.
	 */
	mentry = ehdr->e_entry;

	/*
	 * Point at program headers and perform some basic validation.
	 */
	for (i = 0, pptr = phdr; i < (int)ehdr->e_phnum; i++,
	    pptr = (Phdr *)((Off)pptr + ehdr->e_phentsize)) {
		if ((pptr->p_type == PT_LOAD) ||
		    (pptr->p_type == PT_SUNWBSS)) {

			if (fph == 0) {
				fph = pptr;
			/* LINTED argument lph is initialized in first pass */
			} else if (pptr->p_vaddr <= lph->p_vaddr) {
				eprintf(lml, ERR_ELF,
				    MSG_INTL(MSG_GEN_INVPRGHDR), pname);
				return (0);
			}

			lph = pptr;

			if (pptr->p_memsz)
				lmph = pptr;
			if (pptr->p_filesz)
				lfph = pptr;
			if (pptr->p_type == PT_SUNWBSS)
				swph = pptr;
			if (pptr->p_align > align)
				align = pptr->p_align;

		} else if (pptr->p_type == PT_DYNAMIC) {
			mld = (Dyn *)(pptr->p_vaddr);
		} else if ((pptr->p_type == PT_TLS) && pptr->p_memsz) {
			tlph = pptr;
		} else if (pptr->p_type == PT_SUNWCAP) {
			cap = (Cap *)(pptr->p_vaddr);
		} else if (pptr->p_type == PT_SUNW_UNWIND) {
			unwindph = pptr;
		}
	}

#if defined(MAP_ALIGN)
	/*
	 * Make sure the maximum page alignment is a power of 2 >= the default
	 * segment alignment, for use with MAP_ALIGN.
	 */
	align = S_ROUND(align, M_SEGM_ALIGN);
#endif

	/*
	 * We'd better have at least one loadable segment, together with some
	 * specified file and memory size.
	 */
	if ((fph == 0) || (lmph == 0) || (lfph == 0)) {
		eprintf(lml, ERR_ELF, MSG_INTL(MSG_GEN_NOLOADSEG), pname);
		return (0);
	}

	/*
	 * Check that the files size accounts for the loadable sections
	 * we're going to map in (failure to do this may cause spurious
	 * bus errors if we're given a truncated file).
	 */
	if (fmap->fm_fsize < ((size_t)lfph->p_offset + lfph->p_filesz)) {
		eprintf(lml, ERR_FATAL, MSG_INTL(MSG_GEN_CORTRUNC), pname);
		return (0);
	}

	/*
	 * Memsize must be page rounded so that if we add object padding
	 * at the end it will start at the beginning of a page.
	 */
	plen = memsize = M_PROUND((lmph->p_vaddr + lmph->p_memsz) -
	    M_PTRUNC((ulong_t)fph->p_vaddr));

	/*
	 * Determine if an existing mapping is acceptable.
	 */
	if (interp && (lml->lm_flags & LML_FLG_BASELM) &&
	    (strcmp(pname, interp->i_name) == 0)) {
		/*
		 * If this is the interpreter then it has already been mapped
		 * and we have the address so don't map it again.  Note that
		 * the common occurrence of a reference to the interpretor
		 * (libdl -> ld.so.1) will have been caught during filter
		 * initialization (see elf_lookup_filtee()).  However, some
		 * ELF implementations are known to record libc.so.1 as the
		 * interpretor, and thus this test catches this behavior.
		 */
		paddr = faddr = interp->i_faddr;

	} else if ((fixed == 0) && (r_debug.rtd_objpad == 0) &&
	    (memsize <= fmap->fm_msize) && ((fph->p_flags & PF_W) == 0) &&
	    (fph == lph) && (fph->p_filesz == fph->p_memsz) &&
	    (((Xword)fmap->fm_maddr % align) == 0)) {
		size_t	rsize;

		/*
		 * If the file contains a single segment, and the mapping
		 * required has already been established from the initial fmap
		 * mapping, then we don't need to do anything more.  Reset the
		 * fmap address so that any later files start a new fmap.  This
		 * is really an optimization for filters, such as libdl.so,
		 * libthread, etc. that are constructed to be a single text
		 * segment.
		 */
		paddr = faddr = fmap->fm_maddr;

		/*
		 * Free any unused mapping by assigning the fmap buffer to the
		 * unused region.  fmap_setup() will unmap this area and
		 * establish defaults for future mappings.
		 */
		rsize = M_PROUND(fph->p_filesz);
		fmap->fm_maddr += rsize;
		fmap->fm_msize -= rsize;
		fmap_setup();
	}

	/*
	 * Allocate a mapping array to retain mapped segment information.
	 */
	if ((mmaps = calloc(ehdr->e_phnum, sizeof (Mmap))) == 0)
		return (0);

	/*
	 * If we're reusing an existing mapping determine the objects etext
	 * address.  Otherwise map the file (which will calculate the etext
	 * address as part of the mapping process).
	 */
	if (faddr) {
		caddr_t	base;

		if (fixed)
			base = 0;
		else
			base = faddr;

		/* LINTED */
		phdr0 = phdr = (Phdr *)((char *)faddr + ehdr->e_ehsize);

		for (i = 0, pptr = phdr; i < (int)ehdr->e_phnum; i++,
		    pptr = (Phdr *)((Off)pptr + ehdr->e_phentsize)) {
			if (pptr->p_type != PT_LOAD)
				continue;

			mmaps[mmapcnt].m_vaddr = (pptr->p_vaddr + base);
			mmaps[mmapcnt].m_msize = pptr->p_memsz;
			mmaps[mmapcnt].m_fsize = pptr->p_filesz;
			mmaps[mmapcnt].m_perm = (PROT_READ | PROT_EXEC);
			mmapcnt++;

			if (!(pptr->p_flags & PF_W)) {
				fmap->fm_etext = (ulong_t)pptr->p_vaddr +
				    (ulong_t)pptr->p_memsz +
				    (ulong_t)(fixed ? 0 : faddr);
			}
		}
	} else {
		/*
		 * Map the file.
		 */
		if (!(faddr = elf_map_it(lml, pname, memsize, ehdr, fph, lph,
		    &phdr, &paddr, &plen, fixed, fd, align, mmaps, &mmapcnt)))
			return (0);
	}

	/*
	 * Calculate absolute base addresses and entry points.
	 */
	if (!fixed) {
		if (mld)
			/* LINTED */
			mld = (Dyn *)((Off)mld + faddr);
		if (cap)
			/* LINTED */
			cap = (Cap *)((Off)cap + faddr);
		mentry += (Off)faddr;
	}

	/*
	 * Create new link map structure for newly mapped shared object.
	 */
	if (!(lmp = elf_new_lm(lml, pname, oname, mld, (ulong_t)faddr,
	    fmap->fm_etext, lmco, memsize, mentry, (ulong_t)paddr, plen, mmaps,
	    mmapcnt, in_nfavl))) {
		(void) munmap((caddr_t)faddr, memsize);
		return (0);
	}

	/*
	 * Start the system loading in the ELF information we'll be processing.
	 */
	if (REL(lmp)) {
		(void) madvise((void *)ADDR(lmp), (uintptr_t)REL(lmp) +
		    (uintptr_t)RELSZ(lmp) - (uintptr_t)ADDR(lmp),
		    MADV_WILLNEED);
	}

	/*
	 * If this shared object contains any special segments, record them.
	 */
	if (swph) {
		FLAGS(lmp) |= FLG_RT_SUNWBSS;
		SUNWBSS(lmp) = phdr + (swph - phdr0);
	}
	if (tlph && (tls_assign(lml, lmp, (phdr + (tlph - phdr0))) == 0)) {
		remove_so(lml, lmp);
		return (0);
	}

	if (unwindph)
		PTUNWIND(lmp) = phdr + (unwindph - phdr0);

	if (cap)
		cap_assign(cap, lmp);

	return (lmp);
}

/*
 * Function to correct protection settings.  Segments are all mapped initially
 * with permissions as given in the segment header.  We need to turn on write
 * permissions on a text segment if there are any relocations against that
 * segment, and them turn write permission back off again before returning
 * control to the user.  This function turns the permission on or off depending
 * on the value of the argument.
 */
int
elf_set_prot(Rt_map *lmp, int permission)
{
	Mmap	*mmaps;

	/*
	 * If this is an allocated image (ie. a relocatable object) we can't
	 * mprotect() anything.
	 */
	if (FLAGS(lmp) & FLG_RT_IMGALLOC)
		return (1);

	DBG_CALL(Dbg_file_prot(lmp, permission));

	for (mmaps = MMAPS(lmp); mmaps->m_vaddr; mmaps++) {
		if (mmaps->m_perm & PROT_WRITE)
			continue;

		if (mprotect(mmaps->m_vaddr, mmaps->m_msize,
		    (mmaps->m_perm | permission)) == -1) {
			int	err = errno;
			eprintf(LIST(lmp), ERR_FATAL, MSG_INTL(MSG_SYS_MPROT),
			    NAME(lmp), strerror(err));
			return (0);
		}
	}
	return (1);
}

/*
 * Build full pathname of shared object from given directory name and filename.
 */
static char *
elf_get_so(const char *dir, const char *file)
{
	static char	pname[PATH_MAX];

	(void) snprintf(pname, PATH_MAX, MSG_ORIG(MSG_FMT_PATH), dir, file);
	return (pname);
}

/*
 * The copy relocation is recorded in a copy structure which will be applied
 * after all other relocations are carried out.  This provides for copying data
 * that must be relocated itself (ie. pointers in shared objects).  This
 * structure also provides a means of binding RTLD_GROUP dependencies to any
 * copy relocations that have been taken from any group members.
 *
 * If the size of the .bss area available for the copy information is not the
 * same as the source of the data inform the user if we're under ldd(1) control
 * (this checking was only established in 5.3, so by only issuing an error via
 * ldd(1) we maintain the standard set by previous releases).
 */
int
elf_copy_reloc(char *name, Sym *rsym, Rt_map *rlmp, void *radd, Sym *dsym,
    Rt_map *dlmp, const void *dadd)
{
	Rel_copy	rc;
	Lm_list		*lml = LIST(rlmp);

	rc.r_name = name;
	rc.r_rsym = rsym;		/* the new reference symbol and its */
	rc.r_rlmp = rlmp;		/*	associated link-map */
	rc.r_dlmp = dlmp;		/* the defining link-map */
	rc.r_dsym = dsym;		/* the original definition */
	rc.r_radd = radd;
	rc.r_dadd = dadd;

	if (rsym->st_size > dsym->st_size)
		rc.r_size = (size_t)dsym->st_size;
	else
		rc.r_size = (size_t)rsym->st_size;

	if (alist_append(&COPY_R(dlmp), &rc, sizeof (Rel_copy),
	    AL_CNT_COPYREL) == 0) {
		if (!(lml->lm_flags & LML_FLG_TRC_WARN))
			return (0);
		else
			return (1);
	}
	if (!(FLAGS1(dlmp) & FL1_RT_COPYTOOK)) {
		if (aplist_append(&COPY_S(rlmp), dlmp,
		    AL_CNT_COPYREL) == NULL) {
			if (!(lml->lm_flags & LML_FLG_TRC_WARN))
				return (0);
			else
				return (1);
		}
		FLAGS1(dlmp) |= FL1_RT_COPYTOOK;
	}

	/*
	 * If we are tracing (ldd), warn the user if
	 *	1) the size from the reference symbol differs from the
	 *	   copy definition. We can only copy as much data as the
	 *	   reference (dynamic executables) entry allows.
	 *	2) the copy definition has STV_PROTECTED visibility.
	 */
	if (lml->lm_flags & LML_FLG_TRC_WARN) {
		if (rsym->st_size != dsym->st_size) {
			(void) printf(MSG_INTL(MSG_LDD_CPY_SIZDIF),
			    _conv_reloc_type(M_R_COPY), demangle(name),
			    NAME(rlmp), EC_XWORD(rsym->st_size),
			    NAME(dlmp), EC_XWORD(dsym->st_size));
			if (rsym->st_size > dsym->st_size)
				(void) printf(MSG_INTL(MSG_LDD_CPY_INSDATA),
				    NAME(dlmp));
			else
				(void) printf(MSG_INTL(MSG_LDD_CPY_DATRUNC),
				    NAME(rlmp));
		}

		if (ELF_ST_VISIBILITY(dsym->st_other) == STV_PROTECTED) {
			(void) printf(MSG_INTL(MSG_LDD_CPY_PROT),
			    _conv_reloc_type(M_R_COPY), demangle(name),
			    NAME(dlmp));
		}
	}

	DBG_CALL(Dbg_reloc_apply_val(lml, ELF_DBG_RTLD, (Xword)radd,
	    (Xword)rc.r_size));
	return (1);
}

/*
 * Determine the symbol location of an address within a link-map.  Look for
 * the nearest symbol (whose value is less than or equal to the required
 * address).  This is the object specific part of dladdr().
 */
static void
elf_dladdr(ulong_t addr, Rt_map *lmp, Dl_info *dlip, void **info, int flags)
{
	ulong_t		ndx, cnt, base, _value;
	Sym		*sym, *_sym = NULL;
	const char	*str;
	int		_flags;
	uint_t		*dynaddr_ndx;
	uint_t		dynaddr_n = 0;
	ulong_t		value;

	/*
	 * If SUNWSYMTAB() is non-NULL, then it sees a special version of
	 * the dynsym that starts with any local function symbols that exist in
	 * the library and then moves to the data held in SYMTAB(). In this
	 * case, SUNWSYMSZ tells us how long the symbol table is. The
	 * availability of local function symbols will enhance the results
	 * we can provide.
	 *
	 * If SUNWSYMTAB() is non-NULL, then there might also be a
	 * SUNWSYMSORT() vector associated with it. SUNWSYMSORT() contains
	 * an array of indices into SUNWSYMTAB, sorted by increasing
	 * address. We can use this to do an O(log N) search instead of a
	 * brute force search.
	 *
	 * If SUNWSYMTAB() is NULL, then SYMTAB() references a dynsym that
	 * contains only global symbols. In that case, the length of
	 * the symbol table comes from the nchain field of the related
	 * symbol lookup hash table.
	 */
	str = STRTAB(lmp);
	if (SUNWSYMSZ(lmp) == NULL) {
		sym = SYMTAB(lmp);
		/*
		 * If we don't have a .hash table there are no symbols
		 * to look at.
		 */
		if (HASH(lmp) == 0)
			return;
		cnt = HASH(lmp)[1];
	} else {
		sym = SUNWSYMTAB(lmp);
		cnt = SUNWSYMSZ(lmp) / SYMENT(lmp);
		dynaddr_ndx = SUNWSYMSORT(lmp);
		if (dynaddr_ndx != NULL)
			dynaddr_n = SUNWSYMSORTSZ(lmp) / SUNWSORTENT(lmp);
	}

	if (FLAGS(lmp) & FLG_RT_FIXED)
		base = 0;
	else
		base = ADDR(lmp);

	if (dynaddr_n > 0) {		/* Binary search */
		long	low = 0, low_bnd;
		long	high = dynaddr_n - 1, high_bnd;
		long	mid;
		Sym	*mid_sym;

		/*
		 * Note that SUNWSYMSORT only contains symbols types that
		 * supply memory addresses, so there's no need to check and
		 * filter out any other types.
		 */
		low_bnd = low;
		high_bnd = high;
		while (low <= high) {
			mid = (low + high) / 2;
			mid_sym = &sym[dynaddr_ndx[mid]];
			value = mid_sym->st_value + base;
			if (addr < value) {
				if ((sym[dynaddr_ndx[high]].st_value + base) >=
				    addr)
					high_bnd = high;
				high = mid - 1;
			} else if (addr > value) {
				if ((sym[dynaddr_ndx[low]].st_value + base) <=
				    addr)
					low_bnd = low;
				low = mid + 1;
			} else {
				_sym = mid_sym;
				_value = value;
				break;
			}
		}
		/*
		 * If the above didn't find it exactly, then we must
		 * return the closest symbol with a value that doesn't
		 * exceed the one we are looking for. If that symbol exists,
		 * it will lie in the range bounded by low_bnd and
		 * high_bnd. This is a linear search, but a short one.
		 */
		if (_sym == NULL) {
			for (mid = low_bnd; mid <= high_bnd; mid++) {
				mid_sym = &sym[dynaddr_ndx[mid]];
				value = mid_sym->st_value + base;
				if (addr >= value) {
					_sym = mid_sym;
					_value = value;
				} else {
					break;
				}
			}
		}
	} else {			/* Linear search */
		for (_value = 0, sym++, ndx = 1; ndx < cnt; ndx++, sym++) {
			/*
			 * Skip expected symbol types that are not functions
			 * or data:
			 *	- A symbol table starts with an undefined symbol
			 *		in slot 0. If we are using SUNWSYMTAB(),
			 *		there will be a second undefined symbol
			 *		right before the globals.
			 *	- The local part of SUNWSYMTAB() contains a
			 *		series of function symbols. Each section
			 *		starts with an initial STT_FILE symbol.
			 */
			if ((sym->st_shndx == SHN_UNDEF) ||
			    (ELF_ST_TYPE(sym->st_info) == STT_FILE))
				continue;

			value = sym->st_value + base;
			if (value > addr)
				continue;
			if (value < _value)
				continue;

			_sym = sym;
			_value = value;

			/*
			 * Note, because we accept local and global symbols
			 * we could find a section symbol that matches the
			 * associated address, which means that the symbol
			 * name will be null.  In this case continue the
			 * search in case we can find a global symbol of
			 * the same value.
			 */
			if ((value == addr) &&
			    (ELF_ST_TYPE(sym->st_info) != STT_SECTION))
				break;
		}
	}

	_flags = flags & RTLD_DL_MASK;
	if (_sym) {
		if (_flags == RTLD_DL_SYMENT)
			*info = (void *)_sym;
		else if (_flags == RTLD_DL_LINKMAP)
			*info = (void *)lmp;

		dlip->dli_sname = str + _sym->st_name;
		dlip->dli_saddr = (void *)_value;
	} else {
		/*
		 * addr lies between the beginning of the mapped segment and
		 * the first global symbol. We have no symbol to return
		 * and the caller requires one. We use _START_, the base
		 * address of the mapping.
		 */

		if (_flags == RTLD_DL_SYMENT) {
			/*
			 * An actual symbol struct is needed, so we
			 * construct one for _START_. To do this in a
			 * fully accurate way requires a different symbol
			 * for each mapped segment. This requires the
			 * use of dynamic memory and a mutex. That's too much
			 * plumbing for a fringe case of limited importance.
			 *
			 * Fortunately, we can simplify:
			 *    - Only the st_size and st_info fields are useful
			 *	outside of the linker internals. The others
			 *	reference things that outside code cannot see,
			 *	and can be set to 0.
			 *    - It's just a label and there is no size
			 *	to report. So, the size should be 0.
			 * This means that only st_info needs a non-zero
			 * (constant) value. A static struct will suffice.
			 * It must be const (readonly) so the caller can't
			 * change its meaning for subsequent callers.
			 */
			static const Sym fsym = { 0, 0, 0,
				ELF_ST_INFO(STB_LOCAL, STT_OBJECT) };
			*info = (void *) &fsym;
		}

		dlip->dli_sname = MSG_ORIG(MSG_SYM_START);
		dlip->dli_saddr = (void *) ADDR(lmp);
	}
}

static void
elf_lazy_cleanup(APlist *alp)
{
	Rt_map	*lmp;
	Aliste	idx;

	/*
	 * Cleanup any link-maps added to this dynamic list and free it.
	 */
	for (APLIST_TRAVERSE(alp, idx, lmp))
		FLAGS(lmp) &= ~FLG_RT_TMPLIST;
	free(alp);
}

/*
 * This routine is called as a last fall-back to search for a symbol from a
 * standard relocation.  To maintain lazy loadings goal of reducing the number
 * of objects mapped, any symbol search is first carried out using the objects
 * that already exist in the process (either on a link-map list or handle).
 * If a symbol can't be found, and lazy dependencies are still pending, this
 * routine loads the dependencies in an attempt to locate the symbol.
 *
 * Only new objects are inspected as we will have already inspected presently
 * loaded objects before calling this routine.  However, a new object may not
 * be new - although the di_lmp might be zero, the object may have been mapped
 * as someone elses dependency.  Thus there's a possibility of some symbol
 * search duplication.
 */
Sym *
elf_lazy_find_sym(Slookup *slp, Rt_map **_lmp, uint_t *binfo, int *in_nfavl)
{
	Sym		*sym = 0;
	APlist		*alist = NULL;
	Aliste		idx;
	Rt_map		*lmp1, *lmp = slp->sl_imap;
	const char	*name = slp->sl_name;

	/*
	 * Generate a local list of new objects to process.  This list can grow
	 * as each object supplies its own lazy dependencies.
	 */
	if (aplist_append(&alist, lmp, AL_CNT_LAZYFIND) == NULL)
		return (NULL);
	FLAGS(lmp) |= FLG_RT_TMPLIST;

	for (APLIST_TRAVERSE(alist, idx, lmp1)) {
		uint_t	cnt = 0;
		Slookup	sl = *slp;
		Dyninfo	*dip, *pdip;

		/*
		 * Discard any relocation index from further symbol searches.
		 * This index will have already been used to trigger any
		 * necessary lazy-loads, and it might be because one of these
		 * lazy loads have failed that we're here performing this
		 * fallback.  By removing the relocation index we don't try
		 * and perform the same failed lazy loading activity again.
		 */
		sl.sl_rsymndx = 0;

		/*
		 * Loop through the lazy DT_NEEDED entries examining each object
		 * for the required symbol.  If the symbol is not found, the
		 * object is in turn added to the local alist, so that the
		 * objects lazy DT_NEEDED entries can be examined.
		 */
		lmp = lmp1;
		for (dip = DYNINFO(lmp), pdip = NULL; cnt < DYNINFOCNT(lmp);
		    cnt++, pdip = dip++) {
			Rt_map *nlmp;

			if (((dip->di_flags & FLG_DI_LAZY) == 0) ||
			    dip->di_info)
				continue;

			/*
			 * If this object has already failed to lazy load, and
			 * we're still processing the same runtime linker
			 * operation that produced the failure, don't bother
			 * to try and load the object again.
			 */
			if ((dip->di_flags & FLG_DI_LAZYFAIL) && pdip &&
			    (pdip->di_flags & FLG_DI_POSFLAG1)) {
				if (pdip->di_info == (void *)ld_entry_cnt)
					continue;

				dip->di_flags &= ~FLG_DI_LAZYFAIL;
				pdip->di_info = NULL;
			}

			/*
			 * Try loading this lazy dependency.  If the object
			 * can't be loaded, consider this non-fatal and continue
			 * the search.  Lazy loaded dependencies need not exist
			 * and their loading should only turn out to be fatal
			 * if they are required to satisfy a relocation.
			 *
			 * If the file is already loaded and relocated we must
			 * still inspect it for symbols, even though it might
			 * have already been searched.  This lazy load operation
			 * might have promoted the permissions of the object,
			 * and thus made the object applicable for this symbol
			 * search, whereas before the object might have been
			 * skipped.
			 */
			if ((nlmp = elf_lazy_load(lmp, &sl, cnt,
			    name, in_nfavl)) == 0)
				continue;

			/*
			 * If this object isn't yet a part of the dynamic list
			 * then inspect it for the symbol.  If the symbol isn't
			 * found add the object to the dynamic list so that we
			 * can inspect its dependencies.
			 */
			if (FLAGS(nlmp) & FLG_RT_TMPLIST)
				continue;

			sl.sl_imap = nlmp;
			if (sym = LM_LOOKUP_SYM(sl.sl_cmap)(&sl, _lmp,
			    binfo, in_nfavl))
				break;

			/*
			 * Some dlsym() operations are already traversing a
			 * link-map (dlopen(0)), and thus there's no need to
			 * build our own dynamic dependency list.
			 */
			if ((sl.sl_flags & LKUP_NODESCENT) == 0) {
				if (aplist_append(&alist, nlmp,
				    AL_CNT_LAZYFIND) == 0) {
					elf_lazy_cleanup(alist);
					return (0);
				}
				FLAGS(nlmp) |= FLG_RT_TMPLIST;
			}
		}
		if (sym)
			break;
	}

	elf_lazy_cleanup(alist);
	return (sym);
}

/*
 * Warning message for bad r_offset.
 */
void
elf_reloc_bad(Rt_map *lmp, void *rel, uchar_t rtype, ulong_t roffset,
    ulong_t rsymndx)
{
	const char	*name = (char *)0;
	Lm_list		*lml = LIST(lmp);
	int		trace;

	if ((lml->lm_flags & LML_FLG_TRC_ENABLE) &&
	    (((rtld_flags & RT_FL_SILENCERR) == 0) ||
	    (lml->lm_flags & LML_FLG_TRC_VERBOSE)))
		trace = 1;
	else
		trace = 0;

	if ((trace == 0) && (DBG_ENABLED == 0))
		return;

	if (rsymndx) {
		Sym	*symref = (Sym *)((ulong_t)SYMTAB(lmp) +
		    (rsymndx * SYMENT(lmp)));

		if (ELF_ST_BIND(symref->st_info) != STB_LOCAL)
			name = (char *)(STRTAB(lmp) + symref->st_name);
	}

	if (name == 0)
		name = MSG_ORIG(MSG_STR_EMPTY);

	if (trace) {
		const char *rstr;

		rstr = _conv_reloc_type((uint_t)rtype);
		(void) printf(MSG_INTL(MSG_LDD_REL_ERR1), rstr, name,
		    EC_ADDR(roffset));
		return;
	}

	Dbg_reloc_error(lml, ELF_DBG_RTLD, M_MACH, M_REL_SHT_TYPE, rel, name);
}

/*
 * Resolve a static TLS relocation.
 */
long
elf_static_tls(Rt_map *lmp, Sym *sym, void *rel, uchar_t rtype, char *name,
    ulong_t roffset, long value)
{
	Lm_list	*lml = LIST(lmp);

	/*
	 * Relocations against a static TLS block have limited support once
	 * process initialization has completed.  Any error condition should be
	 * discovered by testing for DF_STATIC_TLS as part of loading an object,
	 * however individual relocations are tested in case the dynamic flag
	 * had not been set when this object was built.
	 */
	if (PTTLS(lmp) == 0) {
		DBG_CALL(Dbg_reloc_in(lml, ELF_DBG_RTLD, M_MACH,
		    M_REL_SHT_TYPE, rel, NULL, name));
		eprintf(lml, ERR_FATAL, MSG_INTL(MSG_REL_BADTLS),
		    _conv_reloc_type((uint_t)rtype), NAME(lmp),
		    name ? demangle(name) : MSG_INTL(MSG_STR_UNKNOWN));
		return (0);
	}

	/*
	 * If no static TLS has been set aside for this object, determine if
	 * any can be obtained.  Enforce that any object using static TLS is
	 * non-deletable.
	 */
	if (TLSSTATOFF(lmp) == 0) {
		FLAGS1(lmp) |= FL1_RT_TLSSTAT;
		MODE(lmp) |= RTLD_NODELETE;

		if (tls_assign(lml, lmp, PTTLS(lmp)) == 0) {
			DBG_CALL(Dbg_reloc_in(lml, ELF_DBG_RTLD, M_MACH,
			    M_REL_SHT_TYPE, rel, NULL, name));
			eprintf(lml, ERR_FATAL, MSG_INTL(MSG_REL_BADTLS),
			    _conv_reloc_type((uint_t)rtype), NAME(lmp),
			    name ? demangle(name) : MSG_INTL(MSG_STR_UNKNOWN));
			return (0);
		}
	}

	/*
	 * Typically, a static TLS offset is maintained as a symbols value.
	 * For local symbols that are not apart of the dynamic symbol table,
	 * the TLS relocation points to a section symbol, and the static TLS
	 * offset was deposited in the associated GOT table.  Make sure the GOT
	 * is cleared, so that the value isn't reused in do_reloc().
	 */
	if (ELF_ST_BIND(sym->st_info) == STB_LOCAL) {
		if ((ELF_ST_TYPE(sym->st_info) == STT_SECTION)) {
			value = *(long *)roffset;
			*(long *)roffset = 0;
		} else {
			value = sym->st_value;
		}
	}
	return (-(TLSSTATOFF(lmp) - value));
}

/*
 * If the symbol is not found and the reference was not to a weak symbol, report
 * an error.  Weak references may be unresolved.
 */
int
elf_reloc_error(Rt_map *lmp, const char *name, void *rel, uint_t binfo)
{
	Lm_list	*lml = LIST(lmp);

	/*
	 * Under crle(1), relocation failures are ignored.
	 */
	if (lml->lm_flags & LML_FLG_IGNRELERR)
		return (1);

	/*
	 * Under ldd(1), unresolved references are reported.  However, if the
	 * original reference is EXTERN or PARENT these references are ignored
	 * unless ldd's -p option is in effect.
	 */
	if (lml->lm_flags & LML_FLG_TRC_WARN) {
		if (((binfo & DBG_BINFO_REF_MSK) == 0) ||
		    ((lml->lm_flags & LML_FLG_TRC_NOPAREXT) != 0)) {
			(void) printf(MSG_INTL(MSG_LDD_SYM_NFOUND),
			    demangle(name), NAME(lmp));
		}
		return (1);
	}

	/*
	 * Otherwise, the unresolved references is fatal.
	 */
	DBG_CALL(Dbg_reloc_in(lml, ELF_DBG_RTLD, M_MACH, M_REL_SHT_TYPE, rel,
	    NULL, name));
	eprintf(lml, ERR_FATAL, MSG_INTL(MSG_REL_NOSYM), NAME(lmp),
	    demangle(name));

	return (0);
}
