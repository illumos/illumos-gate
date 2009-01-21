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
#include	"_inline.h"
#include	"msg.h"

/*
 * Default and secure dependency search paths.
 */
static Spath_defn _elf_def_dirs[] = {
#if	defined(_ELF64)
	{ MSG_ORIG(MSG_PTH_LIB_64),		MSG_PTH_LIB_64_SIZE },
	{ MSG_ORIG(MSG_PTH_USRLIB_64),		MSG_PTH_USRLIB_64_SIZE },
#else
	{ MSG_ORIG(MSG_PTH_LIB),		MSG_PTH_LIB_SIZE },
	{ MSG_ORIG(MSG_PTH_USRLIB),		MSG_PTH_USRLIB_SIZE },
#endif
	{ 0, 0 }
};

static Spath_defn _elf_sec_dirs[] = {
#if	defined(_ELF64)
	{ MSG_ORIG(MSG_PTH_LIBSE_64),		MSG_PTH_LIBSE_64_SIZE },
	{ MSG_ORIG(MSG_PTH_USRLIBSE_64),	MSG_PTH_USRLIBSE_64_SIZE },
#else
	{ MSG_ORIG(MSG_PTH_LIBSE),		MSG_PTH_LIBSE_SIZE },
	{ MSG_ORIG(MSG_PTH_USRLIBSE),		MSG_PTH_USRLIBSE_SIZE },
#endif
	{ 0, 0 }
};

Alist	*elf_def_dirs = NULL;
Alist	*elf_sec_dirs = NULL;

/*
 * Defines for local functions.
 */
static void	elf_dladdr(ulong_t, Rt_map *, Dl_info *, void **, int);
static Addr	elf_entry_point(void);
static int	elf_fix_name(const char *, Rt_map *, Alist **, Aliste, uint_t);
static Alist	**elf_get_def_dirs(void);
static Alist	**elf_get_sec_dirs(void);
static char	*elf_get_so(const char *, const char *, size_t, size_t);
static int	elf_needed(Lm_list *, Aliste, Rt_map *, int *);

/*
 * Functions and data accessed through indirect pointers.
 */
Fct elf_fct = {
	elf_verify,
	elf_new_lmp,
	elf_entry_point,
	elf_needed,
	lookup_sym,
	elf_reloc,
	elf_get_def_dirs,
	elf_get_sec_dirs,
	elf_fix_name,
	elf_get_so,
	elf_dladdr,
	dlsym_handle
};

/*
 * Default and secure dependency search paths.
 */
static Alist **
elf_get_def_dirs()
{
	if (elf_def_dirs == NULL)
		set_dirs(&elf_def_dirs, _elf_def_dirs, LA_SER_DEFAULT);
	return (&elf_def_dirs);
}

static Alist **
elf_get_sec_dirs()
{
	if (elf_sec_dirs == NULL)
		set_dirs(&elf_sec_dirs, _elf_sec_dirs, LA_SER_SECURE);
	return (&elf_sec_dirs);
}

/*
 * Redefine NEEDED name if necessary.
 */
static int
elf_fix_name(const char *name, Rt_map *clmp, Alist **alpp, Aliste alni,
    uint_t orig)
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
		Pdesc	*pdp;

		DBG_CALL(Dbg_file_fixname(LIST(clmp), name,
		    MSG_ORIG(MSG_PTH_LIBSYS)));
		if ((pdp = alist_append(alpp, 0, sizeof (Pdesc), alni)) == NULL)
			return (0);

		pdp->pd_pname = (char *)MSG_ORIG(MSG_PTH_LIBSYS);
		pdp->pd_plen = MSG_PTH_LIBSYS_SIZE;
		pdp->pd_flags = PD_FLG_PNSLASH;

		return (1);
	}

	return (expand_paths(clmp, name, alpp, alni, orig, 0));
}

/*
 * Determine whether this object requires any hardware or software capabilities.
 */
static int
elf_cap_check(Fdesc *fdp, Ehdr *ehdr, Rej_desc *rej)
{
	Phdr	*phdr;
	int	cnt;

	/* LINTED */
	phdr = (Phdr *)((char *)ehdr + ehdr->e_phoff);
	for (cnt = 0; cnt < ehdr->e_phnum; cnt++, phdr++) {
		Cap	*cptr;

		if (phdr->p_type != PT_SUNWCAP)
			continue;

		/* LINTED */
		cptr = (Cap *)((char *)ehdr + phdr->p_offset);
		while (cptr->c_tag != CA_SUNW_NULL) {
			if (cptr->c_tag == CA_SUNW_HW_1) {
				/*
				 * Verify the hardware capabilities.
				 */
				if (hwcap_check(cptr->c_un.c_val, rej) == 0)
					return (0);

				/*
				 * Retain this hardware capabilities value for
				 * possible later inspection should this object
				 * be processed as a filtee.
				 */
				fdp->fd_hwcap = cptr->c_un.c_val;
			}
			if (cptr->c_tag == CA_SUNW_SF_1) {
				/*
				 * Verify the software capabilities.
				 */
				if (sfcap_check(cptr->c_un.c_val, rej) == 0)
					return (0);
			}
			cptr++;
		}
	}
	return (1);
}

/*
 * Determine if we have been given an ELF file and if so determine if the file
 * is compatible.  Returns 1 if true, else 0 and sets the reject descriptor
 * with associated error information.
 */
Fct *
elf_verify(caddr_t addr, size_t size, Fdesc *fdp, const char *name,
    Rej_desc *rej)
{
	Ehdr	*ehdr;
	char	*caddr = (char *)addr;

	/*
	 * Determine if we're an elf file.  If not simply return, we don't set
	 * any rejection information as this test allows use to scroll through
	 * the objects we support (ELF, AOUT).
	 */
	if (size < sizeof (Ehdr) ||
	    caddr[EI_MAG0] != ELFMAG0 ||
	    caddr[EI_MAG1] != ELFMAG1 ||
	    caddr[EI_MAG2] != ELFMAG2 ||
	    caddr[EI_MAG3] != ELFMAG3) {
		return (NULL);
	}

	/*
	 * Check class and encoding.
	 */
	/* LINTED */
	ehdr = (Ehdr *)addr;
	if (ehdr->e_ident[EI_CLASS] != M_CLASS) {
		rej->rej_type = SGS_REJ_CLASS;
		rej->rej_info = (uint_t)ehdr->e_ident[EI_CLASS];
		return (NULL);
	}
	if (ehdr->e_ident[EI_DATA] != M_DATA) {
		rej->rej_type = SGS_REJ_DATA;
		rej->rej_info = (uint_t)ehdr->e_ident[EI_DATA];
		return (NULL);
	}
	if ((ehdr->e_type != ET_REL) && (ehdr->e_type != ET_EXEC) &&
	    (ehdr->e_type != ET_DYN)) {
		rej->rej_type = SGS_REJ_TYPE;
		rej->rej_info = (uint_t)ehdr->e_type;
		return (NULL);
	}

	/*
	 * Verify ELF version.
	 */
	if (ehdr->e_version > EV_CURRENT) {
		rej->rej_type = SGS_REJ_VERSION;
		rej->rej_info = (uint_t)ehdr->e_version;
		return (NULL);
	}

	/*
	 * Verify machine specific flags.
	 */
	if (elf_mach_flags_check(rej, ehdr) == 0)
		return (NULL);

	/*
	 * Verify any hardware/software capability requirements.  Note, if this
	 * object is an explicitly defined shared object under inspection by
	 * ldd(1), and contains an incompatible hardware capabilities
	 * requirement, then inform the user, but continue processing.
	 */
	if (elf_cap_check(fdp, ehdr, rej) == 0) {
		Rt_map	*lmp = lml_main.lm_head;

		if ((lml_main.lm_flags & LML_FLG_TRC_LDDSTUB) &&
		    (lmp != NULL) && (FLAGS1(lmp) & FL1_RT_LDDSTUB) &&
		    (NEXT(lmp) == NULL)) {
			const char	*fmt;

			if (rej->rej_type == SGS_REJ_HWCAP_1)
				fmt = MSG_INTL(MSG_LDD_GEN_HWCAP_1);
			else
				fmt = MSG_INTL(MSG_LDD_GEN_SFCAP_1);
			(void) printf(fmt, name, rej->rej_str);
			return (&elf_fct);
		}
		return (NULL);
	}
	return (&elf_fct);
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
	(void) elf_reloc_relative_count((ulong_t)JMPREL(lmp),
	    (ulong_t)(PLTRELSZ(lmp) / RELENT(lmp)), (ulong_t)RELENT(lmp),
	    (ulong_t)ADDR(lmp), lmp, NULL);
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
	Alist		*palp = NULL;
	Rt_map		*nlmp, *hlmp;
	Dyninfo		*dip = &DYNINFO(clmp)[ndx], *pdip;
	uint_t		flags = 0;
	const char	*name;
	Lm_list		*lml = LIST(clmp);
	Lm_cntl		*lmc;
	Aliste		lmco;

	/*
	 * If this dependency has already been processed, we're done.
	 */
	if (((nlmp = (Rt_map *)dip->di_info) != NULL) ||
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
	if (elf_fix_name(name, clmp, &palp, AL_CNT_NEEDED, 0) == 0)
		return (NULL);

	/*
	 * Provided the object on the head of the link-map has completed its
	 * relocation, create a new link-map control list for this request.
	 */
	hlmp = lml->lm_head;
	if (FLAGS(hlmp) & FLG_RT_RELOCED) {
		if ((lmc = alist_append(&lml->lm_lists, 0, sizeof (Lm_cntl),
		    AL_CNT_LMLISTS)) == NULL) {
			remove_plist(&palp, 1);
			return (NULL);
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
	    load_one(lml, lmco, palp, clmp, MODE(clmp), flags, 0, in_nfavl);

	/*
	 * Remove any expanded pathname infrastructure.  Reduce the pending lazy
	 * dependency count of the caller, together with the link-map lists
	 * count of objects that still have lazy dependencies pending.
	 */
	remove_plist(&palp, 1);
	if (--LAZY(clmp) == 0)
		LIST(clmp)->lm_lazy--;

	/*
	 * Finish processing the objects associated with this request, and
	 * create an association between the caller and this dependency.
	 */
	if (nlmp && ((bind_one(clmp, nlmp, BND_NEEDED) == 0) ||
	    ((nlmp = analyze_lmc(lml, lmco, nlmp, in_nfavl)) == NULL) ||
	    (relocate_lmc(lml, lmco, clmp, nlmp, in_nfavl) == 0)))
		dip->di_info = nlmp = NULL;

	/*
	 * If this lazyload has failed, and we've created a new link-map
	 * control list to which this request has added objects, then remove
	 * all the objects that have been associated to this request.
	 */
	if ((nlmp == NULL) && lmc && lmc->lc_head)
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
	if (nlmp == NULL) {
		dip->di_flags |= FLG_DI_LAZYFAIL;
		if (LAZY(clmp)++ == 0)
			LIST(clmp)->lm_lazy++;
	}

	return (nlmp);
}

/*
 * Return the entry point of the ELF executable.
 */
static Addr
elf_entry_point(void)
{
	Rt_map	*lmp = lml_main.lm_head;
	Ehdr	*ehdr = (Ehdr *)ADDR(lmp);
	Addr	addr = (Addr)(ehdr->e_entry);

	if ((FLAGS(lmp) & FLG_RT_FIXED) == 0)
		addr += ADDR(lmp);

	return (addr);
}

/*
 * Determine if a dependency requires a particular version and if so verify
 * that the version exists in the dependency.
 */
int
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
	Alist		*palp = NULL;
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
		if ((elf_fix_name(name, clmp, &palp, AL_CNT_NEEDED, 0) == 0) ||
		    ((nlmp = load_one(lml, lmco, palp, clmp, MODE(clmp),
		    flags, 0, in_nfavl)) == NULL) ||
		    (bind_one(clmp, nlmp, BND_NEEDED) == 0))
			nlmp = 0;

		/*
		 * Clean up any infrastructure, including the removal of the
		 * error suppression state, if it had been previously set in
		 * this routine.
		 */
		remove_plist(&palp, 0);

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
			else {
				remove_plist(&palp, 1);
				return (0);
			}
		}
	}

	if (LAZY(clmp))
		lml->lm_lazy++;

	remove_plist(&palp, 1);
	return (1);
}

/*
 * A null symbol interpretor.  Used if a filter has no associated filtees.
 */
/* ARGSUSED0 */
static Sym *
elf_null_find_sym(Slookup *slp, Rt_map **dlmp, uint_t *binfo, int *in_nfavl)
{
	return (NULL);
}

/*
 * Disable filtee use.
 */
static void
elf_disable_filtee(Rt_map *lmp, Dyninfo *dip)
{
	if ((dip->di_flags & FLG_DI_SYMFLTR) == 0) {
		/*
		 * If this is an object filter, null out the reference name.
		 */
		if (OBJFLTRNDX(lmp) != FLTR_DISABLED) {
			REFNAME(lmp) = NULL;
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
	Pdesc		*pdp;
	int		any;
	Dyninfo		*dip = &DYNINFO(ilmp)[ndx];
	Lm_list		*lml = LIST(ilmp);
	Aliste		idx;

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
			elf_config_flt(lml, PATHNAME(ilmp), filtees,
			    (Alist **)&dip->di_info, AL_CNT_FILTEES);

		if (dip->di_info == 0) {
			DBG_CALL(Dbg_file_filter(lml, NAME(ilmp), filtees, 0));
			if ((lml->lm_flags &
			    (LML_FLG_TRC_VERBOSE | LML_FLG_TRC_SEARCH)) &&
			    ((FLAGS1(ilmp) & FL1_RT_LDDSTUB) == 0))
				(void) printf(MSG_INTL(MSG_LDD_FIL_FILTER),
				    NAME(ilmp), filtees);

			if (expand_paths(ilmp, filtees, (Alist **)&dip->di_info,
			    AL_CNT_FILTEES, 0, 0) == 0) {
				elf_disable_filtee(ilmp, dip);
				return (NULL);
			}
		}
	}

	/*
	 * Traverse the filtee list, dlopen()'ing any objects specified and
	 * using their group handle to lookup the symbol.
	 */
	any = 0;
	for (ALIST_TRAVERSE((Alist *)dip->di_info, idx, pdp)) {
		int	mode;
		Grp_hdl	*ghp;
		Rt_map	*nlmp = 0;

		if (pdp->pd_plen == 0)
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
		if ((pdp->pd_info == 0) && (pdp->pd_flags & PD_TKN_HWCAP)) {
			const char	*dir = pdp->pd_pname;
			Lm_cntl		*lmc;
			Aliste		lmco;

			if (FLAGS(lml->lm_head) & FLG_RT_RELOCED) {
				if ((lmc = alist_append(&lml->lm_lists, 0,
				    sizeof (Lm_cntl), AL_CNT_LMLISTS)) == NULL)
					return (NULL);
				lmco = (Aliste)((char *)lmc -
				    (char *)lml->lm_lists);
			} else {
				lmc = 0;
				lmco = ALIST_OFF_DATA;
			}

			/*
			 * Determine the hardware capability filtees.  If none
			 * can be found, provide suitable diagnostics.
			 */
			DBG_CALL(Dbg_cap_hw_filter(lml, dir, ilmp));
			if (hwcap_filtees((Alist **)&dip->di_info, idx, dir,
			    lmco, lmc, ilmp, filtees, mode,
			    (FLG_RT_HANDLE | FLG_RT_HWCAP), in_nfavl) == 0) {
				if ((lml->lm_flags & LML_FLG_TRC_ENABLE) &&
				    (dip->di_flags & FLG_DI_AUXFLTR) &&
				    (rtld_flags & RT_FL_WARNFLTR)) {
					(void) printf(
					    MSG_INTL(MSG_LDD_HWCAP_NFOUND),
					    dir);
				}
				DBG_CALL(Dbg_cap_hw_filter(lml, dir, 0));
			}

			/*
			 * Re-establish the originating path name descriptor, as
			 * the expansion of hardware capabilities filtees may
			 * have re-allocated the controlling Alist.  Mark this
			 * original pathname descriptor as unused so that the
			 * descriptor isn't revisited for processing.  Any real
			 * hardware capabilities filtees have been added as new
			 * pathname descriptors following this descriptor.
			 */
			pdp = alist_item((Alist *)dip->di_info, idx);
			pdp->pd_flags &= ~PD_TKN_HWCAP;
			pdp->pd_plen = 0;

			/*
			 * Now that any hardware capability objects have been
			 * processed, remove any link-map control list.
			 */
			if (lmc)
				remove_cntl(lml, lmco);
		}

		if (pdp->pd_plen == 0)
			continue;

		/*
		 * Process an individual filtee.
		 */
		if (pdp->pd_info == 0) {
			const char	*filtee = pdp->pd_pname;
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
					pdp->pd_info = (void *)ghp;

				/*
				 * Audit the filter/filtee established.  Ignore
				 * any return from the auditor, as we can't
				 * allow ignore filtering to ld.so.1, otherwise
				 * nothing is going to work.
				 */
				if (nlmp && ((lml->lm_tflags | AFLAGS(ilmp)) &
				    LML_TFLG_AUD_OBJFILTER))
					(void) audit_objfilter(ilmp, filtees,
					    nlmp, 0);

			} else {
				Rej_desc	rej = { 0 };
				Fdesc		fd = { 0 };
				Lm_cntl		*lmc;
				Aliste		lmco;

				/*
				 * Trace the inspection of this file, determine
				 * any auditor substitution, and seed the file
				 * descriptor with the originating name.
				 */
				if (load_trace(lml, pdp, clmp, &fd) == NULL)
					continue;

				/*
				 * Establish a new link-map control list from
				 * which to analyze any newly added objects.
				 */
				if (FLAGS(lml->lm_head) & FLG_RT_RELOCED) {
					if ((lmc =
					    alist_append(&lml->lm_lists, 0,
					    sizeof (Lm_cntl),
					    AL_CNT_LMLISTS)) == NULL)
						return (NULL);
					lmco = (Aliste)((char *)lmc -
					    (char *)lml->lm_lists);
				} else {
					lmc = 0;
					lmco = ALIST_OFF_DATA;
				}

				/*
				 * Locate and load the filtee.
				 */
				if ((nlmp = load_path(lml, lmco, ilmp, mode,
				    FLG_RT_HANDLE, &ghp, &fd, &rej,
				    in_nfavl)) == NULL)
					file_notfound(LIST(ilmp), filtee, ilmp,
					    FLG_RT_HANDLE, &rej);

				filtee = pdp->pd_pname;

				/*
				 * Establish the filter handle to prevent any
				 * recursion.
				 */
				if (nlmp && ghp) {
					ghp->gh_flags |= GPH_FILTEE;
					pdp->pd_info = (void *)ghp;

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
				if (nlmp && ghp && (((nlmp = analyze_lmc(lml,
				    lmco, nlmp, in_nfavl)) == NULL) ||
				    (relocate_lmc(lml, lmco, ilmp, nlmp,
				    in_nfavl) == 0)))
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
				 * Generate a diagnostic if the filtee couldn't
				 * be loaded.
				 */
				if (nlmp == 0)
					DBG_CALL(Dbg_file_filtee(lml, 0, filtee,
					    audit));

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
			 * If the filtee couldn't be loaded, null out the
			 * path name descriptor entry, and continue the search.
			 * Otherwise, the group handle is retained for future
			 * symbol searches.
			 */
			if (nlmp == 0) {
				pdp->pd_info = NULL;
				pdp->pd_plen = 0;
				continue;
			}
		}

		ghp = (Grp_hdl *)pdp->pd_info;

		/*
		 * If we're just here to trigger filtee loading skip the symbol
		 * lookup so we'll continue looking for additional filtees.
		 */
		if (name) {
			Grp_desc	*gdp;
			Sym		*sym = NULL;
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
		return (NULL);

	/*
	 * If no filtees have been found for a filter, clean up any path name
	 * descriptors and disable their search completely.  For auxiliary
	 * filters we can reselect the symbol search function so that we never
	 * enter this routine again for this object.  For standard filters we
	 * use the null symbol routine.
	 */
	if (any == 0) {
		remove_plist((Alist **)&(dip->di_info), 1);
		elf_disable_filtee(ilmp, dip);
		return (NULL);
	}

	return (NULL);
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
		return (NULL);

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
		return (NULL);

	buckets = HASH(ilmp)[0];
	/* LINTED */
	htmp = (uint_t)hash % buckets;

	/*
	 * Get the first symbol on hash chain and initialize the string
	 * and symbol table pointers.
	 */
	if ((ndx = HASH(ilmp)[htmp + 2]) == 0)
		return (NULL);

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
			return (NULL);
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
			return (NULL);
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
		return (NULL);
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
		return (NULL);
	}

	/*
	 * If this is a direct binding request, but the symbol definition has
	 * disabled directly binding to it (presumably because the symbol
	 * definition has been changed since the referring object was built),
	 * reject this binding so that the caller can fall back to a standard
	 * symbol search.
	 */
	if (sip && (slp->sl_flags & LKUP_DIRECT) &&
	    (sip->si_flags & SYMINFO_FLG_NOEXTDIRECT)) {
		DBG_CALL(Dbg_bind_reject(slp->sl_cmap, ilmp, name,
		    DBG_BNDREJ_DIRECT));
		*binfo |= BINFO_REJDIRECT;
		*binfo &= ~DBG_BINFO_MSK;
		return (NULL);
	}

	/*
	 * If this is a binding request within an RTLD_GROUP family, and the
	 * symbol has disabled directly binding to it, reject this binding so
	 * that the caller can fall back to a standard symbol search.
	 *
	 * Effectively, an RTLD_GROUP family achieves what can now be
	 * established with direct bindings.  However, various symbols have
	 * been tagged as inappropriate for direct binding to (ie. libc:malloc).
	 *
	 * A symbol marked as no-direct cannot be used within a group without
	 * first ensuring that the symbol has not been interposed upon outside
	 * of the group.  A common example occurs when users implement their own
	 * version of malloc() in the executable.  Such a malloc() interposes on
	 * the libc:malloc, and this interposition must be honored within the
	 * group as well.
	 *
	 * Following any rejection, LKUP_WORLD is established as a means of
	 * overriding this test as we return to a standard search.
	 */
	if (sip && (sip->si_flags & SYMINFO_FLG_NOEXTDIRECT) &&
	    ((MODE(slp->sl_cmap) & (RTLD_GROUP | RTLD_WORLD)) == RTLD_GROUP) &&
	    ((slp->sl_flags & LKUP_WORLD) == 0)) {
		DBG_CALL(Dbg_bind_reject(slp->sl_cmap, ilmp, name,
		    DBG_BNDREJ_GROUP));
		*binfo |= BINFO_REJGROUP;
		*binfo &= ~DBG_BINFO_MSK;
		return (NULL);
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
			return (NULL);

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
				return (NULL);
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
			return (NULL);
	}
	return (sym);
}

/*
 * Create a new Rt_map structure for an ELF object and initialize
 * all values.
 */
Rt_map *
elf_new_lmp(Lm_list *lml, Aliste lmco, Fdesc *fdp, Addr addr, size_t msize,
    void *odyn, int *in_nfavl)
{
	const char	*name = fdp->fd_nname;
	Rt_map		*lmp;
	Ehdr		*ehdr = (Ehdr *)addr;
	Phdr		*phdr, *tphdr = NULL, *dphdr = NULL, *uphdr = NULL;
	Dyn		*dyn = (Dyn *)odyn;
	Cap		*cap = NULL;
	int		ndx;
	Addr		base, fltr = 0, audit = 0, cfile = 0, crle = 0;
	Xword		rpath = 0;
	size_t		lmsz, rtsz, epsz, dynsz = 0;
	uint_t		dyncnt = 0;

	DBG_CALL(Dbg_file_elf(lml, name, addr, msize, lml->lm_lmidstr, lmco));

	/*
	 * If this is a shared object, the base address of the shared object is
	 * added to all address values defined within the object.  Otherwise, if
	 * this is an executable, all object addresses are used as is.
	 */
	if (ehdr->e_type == ET_EXEC)
		base = 0;
	else
		base = addr;

	/*
	 * Traverse the program header table, picking off required items.  This
	 * traversal also provides for the sizing of the PT_DYNAMIC section.
	 */
	phdr = (Phdr *)((uintptr_t)ehdr + ehdr->e_phoff);
	for (ndx = 0; ndx < (int)ehdr->e_phnum; ndx++,
	    phdr = (Phdr *)((uintptr_t)phdr + ehdr->e_phentsize)) {
		switch (phdr->p_type) {
		case PT_DYNAMIC:
			dphdr = phdr;
			dyn = (Dyn *)((uintptr_t)phdr->p_vaddr + base);
			break;
		case PT_TLS:
			tphdr = phdr;
			break;
		case PT_SUNWCAP:
			cap = (Cap *)((uintptr_t)phdr->p_vaddr + base);
			break;
		case PT_SUNW_UNWIND:
			uphdr = phdr;
			break;
		default:
			break;
		}
	}

	/*
	 * Determine the number of PT_DYNAMIC entries for the DYNINFO()
	 * allocation.  Sadly, this is a little larger than we really need,
	 * as there are typically padding DT_NULL entries.  However, adding
	 * this data to the initial link-map allocation is a win.
	 */
	if (dyn) {
		dyncnt = dphdr->p_filesz / sizeof (Dyn);
		dynsz = dyncnt * sizeof (Dyninfo);
	}

	/*
	 * Allocate space for the link-map, private elf information, and
	 * DYNINFO() data.  Once these are allocated and initialized,
	 * remove_so(0, lmp) can be used to tear down the link-map allocation
	 * should any failures occur.
	 */
	rtsz = S_DROUND(sizeof (Rt_map));
	epsz = S_DROUND(sizeof (Rt_elfp));
	lmsz = rtsz + epsz + dynsz;
	if ((lmp = calloc(lmsz, 1)) == NULL)
		return (NULL);
	ELFPRV(lmp) = (void *)((uintptr_t)lmp + rtsz);
	DYNINFO(lmp) = (Dyninfo *)((uintptr_t)lmp + rtsz + epsz);
	LMSIZE(lmp) = lmsz;

	/*
	 * All fields not filled in were set to 0 by calloc.
	 */
	NAME(lmp) = (char *)name;
	ADDR(lmp) = addr;
	MSIZE(lmp) = msize;
	SYMINTP(lmp) = elf_find_sym;
	FCT(lmp) = &elf_fct;
	LIST(lmp) = lml;
	OBJFLTRNDX(lmp) = FLTR_DISABLED;
	SORTVAL(lmp) = -1;
	DYN(lmp) = dyn;
	DYNINFOCNT(lmp) = dyncnt;
	PTUNWIND(lmp) = uphdr;

	if (ehdr->e_type == ET_EXEC)
		FLAGS(lmp) |= FLG_RT_FIXED;

	/*
	 * Fill in rest of the link map entries with information from the file's
	 * dynamic structure.
	 */
	if (dyn) {
		uint_t		dynndx = 0;
		Xword		pltpadsz = 0;
		Rti_desc	*rti;

		/* CSTYLED */
		for ( ; dyn->d_tag != DT_NULL; ++dyn, dynndx++) {
			switch ((Xword)dyn->d_tag) {
			case DT_SYMTAB:
				SYMTAB(lmp) = (void *)(dyn->d_un.d_ptr + base);
				break;
			case DT_SUNW_SYMTAB:
				SUNWSYMTAB(lmp) =
				    (void *)(dyn->d_un.d_ptr + base);
				break;
			case DT_SUNW_SYMSZ:
				SUNWSYMSZ(lmp) = dyn->d_un.d_val;
				break;
			case DT_STRTAB:
				STRTAB(lmp) = (void *)(dyn->d_un.d_ptr + base);
				break;
			case DT_SYMENT:
				SYMENT(lmp) = dyn->d_un.d_val;
				break;
			case DT_FEATURE_1:
				dyn->d_un.d_val |= DTF_1_PARINIT;
				if (dyn->d_un.d_val & DTF_1_CONFEXP)
					crle = 1;
				break;
			case DT_MOVESZ:
				MOVESZ(lmp) = dyn->d_un.d_val;
				FLAGS(lmp) |= FLG_RT_MOVE;
				break;
			case DT_MOVEENT:
				MOVEENT(lmp) = dyn->d_un.d_val;
				break;
			case DT_MOVETAB:
				MOVETAB(lmp) = (void *)(dyn->d_un.d_ptr + base);
				break;
			case DT_REL:
			case DT_RELA:
				/*
				 * At this time, ld.so. can only handle one
				 * type of relocation per object.
				 */
				REL(lmp) = (void *)(dyn->d_un.d_ptr + base);
				break;
			case DT_RELSZ:
			case DT_RELASZ:
				RELSZ(lmp) = dyn->d_un.d_val;
				break;
			case DT_RELENT:
			case DT_RELAENT:
				RELENT(lmp) = dyn->d_un.d_val;
				break;
			case DT_RELCOUNT:
			case DT_RELACOUNT:
				RELACOUNT(lmp) = (uint_t)dyn->d_un.d_val;
				break;
			case DT_HASH:
				HASH(lmp) = (uint_t *)(dyn->d_un.d_ptr + base);
				break;
			case DT_PLTGOT:
				PLTGOT(lmp) =
				    (uint_t *)(dyn->d_un.d_ptr + base);
				break;
			case DT_PLTRELSZ:
				PLTRELSZ(lmp) = dyn->d_un.d_val;
				break;
			case DT_JMPREL:
				JMPREL(lmp) = (void *)(dyn->d_un.d_ptr + base);
				break;
			case DT_INIT:
				if (dyn->d_un.d_ptr != NULL)
					INIT(lmp) =
					    (void (*)())(dyn->d_un.d_ptr +
					    base);
				break;
			case DT_FINI:
				if (dyn->d_un.d_ptr != NULL)
					FINI(lmp) =
					    (void (*)())(dyn->d_un.d_ptr +
					    base);
				break;
			case DT_INIT_ARRAY:
				INITARRAY(lmp) = (Addr *)(dyn->d_un.d_ptr +
				    base);
				break;
			case DT_INIT_ARRAYSZ:
				INITARRAYSZ(lmp) = (uint_t)dyn->d_un.d_val;
				break;
			case DT_FINI_ARRAY:
				FINIARRAY(lmp) = (Addr *)(dyn->d_un.d_ptr +
				    base);
				break;
			case DT_FINI_ARRAYSZ:
				FINIARRAYSZ(lmp) = (uint_t)dyn->d_un.d_val;
				break;
			case DT_PREINIT_ARRAY:
				PREINITARRAY(lmp) = (Addr *)(dyn->d_un.d_ptr +
				    base);
				break;
			case DT_PREINIT_ARRAYSZ:
				PREINITARRAYSZ(lmp) = (uint_t)dyn->d_un.d_val;
				break;
			case DT_RPATH:
			case DT_RUNPATH:
				rpath = dyn->d_un.d_val;
				break;
			case DT_FILTER:
				fltr = dyn->d_un.d_val;
				OBJFLTRNDX(lmp) = dynndx;
				FLAGS1(lmp) |= FL1_RT_OBJSFLTR;
				break;
			case DT_AUXILIARY:
				if (!(rtld_flags & RT_FL_NOAUXFLTR)) {
					fltr = dyn->d_un.d_val;
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
					audit = dyn->d_un.d_val;
				break;
			case DT_CONFIG:
				cfile = dyn->d_un.d_val;
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
				if (dyn->d_un.d_ptr)
					rtld_flags |=
					    (RT_FL_DEBUGGER | RT_FL_NOOBJALT);
				dyn->d_un.d_ptr = (Addr)&r_debug;
				break;
			case DT_VERNEED:
				VERNEED(lmp) = (Verneed *)(dyn->d_un.d_ptr +
				    base);
				break;
			case DT_VERNEEDNUM:
				/* LINTED */
				VERNEEDNUM(lmp) = (int)dyn->d_un.d_val;
				break;
			case DT_VERDEF:
				VERDEF(lmp) = (Verdef *)(dyn->d_un.d_ptr +
				    base);
				break;
			case DT_VERDEFNUM:
				/* LINTED */
				VERDEFNUM(lmp) = (int)dyn->d_un.d_val;
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
				VERSYM(lmp) = (Versym *)(dyn->d_un.d_ptr +
				    base);
				break;
			case DT_BIND_NOW:
				if ((dyn->d_un.d_val & DF_BIND_NOW) &&
				    ((rtld_flags2 & RT_FL2_BINDLAZY) == 0)) {
					MODE(lmp) |= RTLD_NOW;
					MODE(lmp) &= ~RTLD_LAZY;
				}
				break;
			case DT_FLAGS:
				FLAGS1(lmp) |= FL1_RT_DTFLAGS;
				if (dyn->d_un.d_val & DF_SYMBOLIC)
					FLAGS1(lmp) |= FL1_RT_SYMBOLIC;
				if ((dyn->d_un.d_val & DF_BIND_NOW) &&
				    ((rtld_flags2 & RT_FL2_BINDLAZY) == 0)) {
					MODE(lmp) |= RTLD_NOW;
					MODE(lmp) &= ~RTLD_LAZY;
				}
				/*
				 * Capture any static TLS use, and enforce that
				 * this object be non-deletable.
				 */
				if (dyn->d_un.d_val & DF_STATIC_TLS) {
					FLAGS1(lmp) |= FL1_RT_TLSSTAT;
					MODE(lmp) |= RTLD_NODELETE;
				}
				break;
			case DT_FLAGS_1:
				if (dyn->d_un.d_val & DF_1_DISPRELPND)
					FLAGS1(lmp) |= FL1_RT_DISPREL;
				if (dyn->d_un.d_val & DF_1_GROUP)
					FLAGS(lmp) |=
					    (FLG_RT_SETGROUP | FLG_RT_HANDLE);
				if ((dyn->d_un.d_val & DF_1_NOW) &&
				    ((rtld_flags2 & RT_FL2_BINDLAZY) == 0)) {
					MODE(lmp) |= RTLD_NOW;
					MODE(lmp) &= ~RTLD_LAZY;
				}
				if (dyn->d_un.d_val & DF_1_NODELETE)
					MODE(lmp) |= RTLD_NODELETE;
				if (dyn->d_un.d_val & DF_1_INITFIRST)
					FLAGS(lmp) |= FLG_RT_INITFRST;
				if (dyn->d_un.d_val & DF_1_NOOPEN)
					FLAGS(lmp) |= FLG_RT_NOOPEN;
				if (dyn->d_un.d_val & DF_1_LOADFLTR)
					FLAGS(lmp) |= FLG_RT_LOADFLTR;
				if (dyn->d_un.d_val & DF_1_NODUMP)
					FLAGS(lmp) |= FLG_RT_NODUMP;
				if (dyn->d_un.d_val & DF_1_CONFALT)
					crle = 1;
				if (dyn->d_un.d_val & DF_1_DIRECT)
					FLAGS1(lmp) |= FL1_RT_DIRECT;
				if (dyn->d_un.d_val & DF_1_NODEFLIB)
					FLAGS1(lmp) |= FL1_RT_NODEFLIB;
				if (dyn->d_un.d_val & DF_1_ENDFILTEE)
					FLAGS1(lmp) |= FL1_RT_ENDFILTE;
				if (dyn->d_un.d_val & DF_1_TRANS)
					FLAGS(lmp) |= FLG_RT_TRANS;

				/*
				 * Global auditing is only meaningful when
				 * specified by the initiating object of the
				 * process - typically the dynamic executable.
				 * If this is the initiaiting object, its link-
				 * map will not yet have been added to the
				 * link-map list, and consequently the link-map
				 * list is empty.  (see setup()).
				 */
				if (dyn->d_un.d_val & DF_1_GLOBAUDIT) {
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
				if (dyn->d_un.d_val &
				    (DF_1_INTERPOSE | DF_1_SYMINTPOSE)) {
				    if (lml->lm_flags & LML_FLG_STARTREL) {
					DBG_CALL(Dbg_util_intoolate(lmp));
					if (lml->lm_flags & LML_FLG_TRC_ENABLE)
					    (void) printf(
						MSG_INTL(MSG_LDD_REL_ERR2),
						NAME(lmp));
				    } else if (dyn->d_un.d_val & DF_1_INTERPOSE)
					FLAGS(lmp) |= FLG_RT_OBJINTPO;
				    else
					FLAGS(lmp) |= FLG_RT_SYMINTPO;
				}
				/* END CSTYLED */
				break;
			case DT_SYMINFO:
				SYMINFO(lmp) = (Syminfo *)(dyn->d_un.d_ptr +
				    base);
				break;
			case DT_SYMINENT:
				SYMINENT(lmp) = dyn->d_un.d_val;
				break;
			case DT_PLTPAD:
				PLTPAD(lmp) = (void *)(dyn->d_un.d_ptr + base);
				break;
			case DT_PLTPADSZ:
				pltpadsz = dyn->d_un.d_val;
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
				    sizeof (Rti_desc),
				    AL_CNT_RTLDINFO)) == NULL) {
					remove_so(0, lmp);
					return (NULL);
				}
				rti->rti_lmp = lmp;
				rti->rti_info = (void *)(dyn->d_un.d_ptr +
				    base);
				break;
			case DT_SUNW_SORTENT:
				SUNWSORTENT(lmp) = dyn->d_un.d_val;
				break;
			case DT_SUNW_SYMSORT:
				SUNWSYMSORT(lmp) =
				    (void *)(dyn->d_un.d_ptr + base);
				break;
			case DT_SUNW_SYMSORTSZ:
				SUNWSYMSORTSZ(lmp) = dyn->d_un.d_val;
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
		else if (crle)
			rtld_flags |= RT_FL_CONFAPP;
	}

	if (rpath)
		RPATH(lmp) = (char *)(rpath + (char *)STRTAB(lmp));
	if (fltr)
		REFNAME(lmp) = (char *)(fltr + (char *)STRTAB(lmp));

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
		RELENT(lmp) = sizeof (M_RELOC);

	/*
	 * Establish any per-object auditing.  If we're establishing `main's
	 * link-map its too early to go searching for audit objects so just
	 * hold the object name for later (see setup()).
	 */
	if (audit) {
		char	*cp = audit + (char *)STRTAB(lmp);

		if (*cp) {
			if (((AUDITORS(lmp) =
			    calloc(1, sizeof (Audit_desc))) == NULL) ||
			    ((AUDITORS(lmp)->ad_name = strdup(cp)) == NULL)) {
				remove_so(0, lmp);
				return (NULL);
			}
			if (lml_main.lm_head) {
				if (audit_setup(lmp, AUDITORS(lmp), 0,
				    in_nfavl) == 0) {
					remove_so(0, lmp);
					return (NULL);
				}
				AFLAGS(lmp) |= AUDITORS(lmp)->ad_flags;
				lml->lm_flags |= LML_FLG_LOCAUDIT;
			}
		}
	}

	if (tphdr && (tls_assign(lml, lmp, tphdr) == 0)) {
		remove_so(0, lmp);
		return (NULL);
	}

	if (cap)
		cap_assign(cap, lmp);

	/*
	 * Add the mapped object to the end of the link map list.
	 */
	lm_append(lml, lmco, lmp);

	/*
	 * Start the system loading in the ELF information we'll be processing.
	 */
	if (REL(lmp)) {
		(void) madvise((void *)ADDR(lmp), (uintptr_t)REL(lmp) +
		    (uintptr_t)RELSZ(lmp) - (uintptr_t)ADDR(lmp),
		    MADV_WILLNEED);
	}
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
 * Build full pathname of shared object from given directory name and filename.
 */
static char *
elf_get_so(const char *dir, const char *file, size_t dlen, size_t flen)
{
	static char	pname[PATH_MAX];

	(void) strncpy(pname, dir, dlen);
	pname[dlen++] = '/';
	(void) strncpy(&pname[dlen], file, flen + 1);
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
	    AL_CNT_COPYREL) == NULL) {
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
	Sym		*sym = NULL;
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
				    AL_CNT_LAZYFIND) == NULL) {
					elf_lazy_cleanup(alist);
					return (NULL);
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
	const char	*name = NULL;
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
		name = MSG_INTL(MSG_STR_UNKNOWN);

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

/*
 * Generic relative relocation function.
 */
inline static ulong_t
_elf_reloc_relative(ulong_t rbgn, ulong_t base, Rt_map *lmp, APlist **textrel)
{
	mmapobj_result_t	*mpp;
	ulong_t			roffset;

	roffset = ((M_RELOC *)rbgn)->r_offset;
	roffset += base;

	/*
	 * If this relocation is against an address that is not associated with
	 * a mapped segment, fall back to the generic relocation loop to
	 * collect the associated error.
	 */
	if ((mpp = find_segment((caddr_t)roffset, lmp)) == NULL)
		return (0);

	/*
	 * If this relocation is against a segment that does not provide write
	 * access, set the write permission for all non-writable mappings.
	 */
	if (((mpp->mr_prot & PROT_WRITE) == 0) && textrel &&
	    ((set_prot(lmp, mpp, 1) == 0) ||
	    (aplist_append(textrel, mpp, AL_CNT_TEXTREL) == NULL)))
		return (0);

	/*
	 * Perform the actual relocation.  Note, for backward compatibility,
	 * SPARC relocations are added to the offset contents (there was a time
	 * when the offset was used to contain the addend, rather than using
	 * the addend itself).
	 */
#if	defined(__sparc)
	*((ulong_t *)roffset) += base + ((M_RELOC *)rbgn)->r_addend;
#elif	defined(__amd64)
	*((ulong_t *)roffset) = base + ((M_RELOC *)rbgn)->r_addend;
#else
	*((ulong_t *)roffset) += base;
#endif
	return (1);
}

/*
 * When a generic relocation loop realizes that it's dealing with relative
 * relocations, but no DT_RELCOUNT .dynamic tag is present, this tighter loop
 * is entered as an optimization.
 */
ulong_t
elf_reloc_relative(ulong_t rbgn, ulong_t rend, ulong_t rsize, ulong_t base,
    Rt_map *lmp, APlist **textrel)
{
	char	rtype;

	do {
		if (_elf_reloc_relative(rbgn, base, lmp, textrel) == 0)
			break;

		rbgn += rsize;
		if (rbgn >= rend)
			break;

		/*
		 * Make sure the next type is a relative relocation.
		 */
		rtype = ELF_R_TYPE(((M_RELOC *)rbgn)->r_info, M_MACH);

	} while (rtype == M_R_RELATIVE);

	return (rbgn);
}

/*
 * This is the tightest loop for RELATIVE relocations for those objects built
 * with the DT_RELACOUNT .dynamic entry.
 */
ulong_t
elf_reloc_relative_count(ulong_t rbgn, ulong_t rcount, ulong_t rsize,
    ulong_t base, Rt_map *lmp, APlist **textrel)
{
	for (; rcount; rcount--) {
		if (_elf_reloc_relative(rbgn, base, lmp, textrel) == 0)
			break;

		rbgn += rsize;
	}
	return (rbgn);
}
