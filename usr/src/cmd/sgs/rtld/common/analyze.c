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
 *	Copyright (c) 1988 AT&T
 *	  All Rights Reserved
 *
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include	"_synonyms.h"

#include	<string.h>
#include	<stdio.h>
#include	<unistd.h>
#include	<sys/stat.h>
#include	<sys/mman.h>
#include	<fcntl.h>
#include	<limits.h>
#include	<dlfcn.h>
#include	<errno.h>
#include	<link.h>
#include	<debug.h>
#include	<conv.h>
#include	"_rtld.h"
#include	"_audit.h"
#include	"_elf.h"
#include	"msg.h"

static Fct *	vector[] = {
	&elf_fct,
#ifdef A_OUT
	&aout_fct,
#endif
	0
};

/*
 * If a load filter flag is in effect, and this object is a filter, trigger the
 * loading of all its filtees.  The load filter flag is in effect when creating
 * configuration files, or when under the control of ldd(1), or the LD_LOADFLTR
 * environment variable is set, or this object was built with the -zloadfltr
 * flag.  Otherwise, filtee loading is deferred until triggered by a relocation.
 */
static void
load_filtees(Rt_map *lmp)
{
	if ((FLAGS1(lmp) & MSK_RT_FILTER) &&
	    ((FLAGS(lmp) & FLG_RT_LOADFLTR) ||
	    (LIST(lmp)->lm_tflags & LML_TFLG_LOADFLTR))) {
		Dyninfo		*dip =  DYNINFO(lmp);
		uint_t		cnt, max = DYNINFOCNT(lmp);
		Slookup		sl;

		/*
		 * Initialize the symbol lookup data structure.
		 */
		SLOOKUP_INIT(sl, 0, lmp, lmp, ld_entry_cnt, 0, 0, 0, 0, 0);

		for (cnt = 0; cnt < max; cnt++, dip++) {
			if (((dip->di_flags & MSK_DI_FILTER) == 0) ||
			    ((dip->di_flags & FLG_DI_AUXFLTR) &&
			    (rtld_flags & RT_FL_NOAUXFLTR)))
				continue;
			(void) elf_lookup_filtee(&sl, 0, 0, cnt);
		}
	}
}

/*
 * Analyze one or more link-maps of a link map control list.  This routine is
 * called at startup to continue the processing of the main executable.  It is
 * also called each time a new set of objects are loaded, ie. from filters,
 * lazy-loaded objects, or dlopen().
 *
 * In each instance we traverse the link-map control list starting with the
 * initial object.  As dependencies are analyzed they are added to the link-map
 * control list.  Thus the list grows as we traverse it - this results in the
 * breadth first ordering of all needed objects.
 */
int
analyze_lmc(Lm_list *lml, Aliste nlmco, Rt_map *nlmp)
{
	Rt_map	*lmp = nlmp;
	Lm_cntl	*nlmc;
	int	ret = 1;

	/*
	 * If this link-map control list is being analyzed, return.  The object
	 * that has just been added will be picked up by the existing analysis
	 * thread.  Note, this is only really meaningful during process init-
	 * ialization, as objects are added to the main link-map control list.
	 * Following this initialization, each family of objects that are loaded
	 * are added to a new link-map control list.
	 */
	/* LINTED */
	nlmc = (Lm_cntl *)alist_item_by_offset(lml->lm_lists, nlmco);
	if (nlmc->lc_flags & LMC_FLG_ANALYZING)
		return (1);

	/*
	 * If this object doesn't belong to the present link-map control list
	 * then it must already have been analyzed, or it is in the process of
	 * being analyzed prior to us recursing into this analysis.  In either
	 * case, ignore the object as it's already being taken care of.
	 */
	if (nlmco != CNTL(nlmp))
		return (1);

	nlmc->lc_flags |= LMC_FLG_ANALYZING;

	for (; lmp; lmp = (Rt_map *)NEXT(lmp)) {
		if (FLAGS(lmp) &
		    (FLG_RT_ANALZING | FLG_RT_ANALYZED | FLG_RT_DELETE))
			continue;

		/*
		 * Indicate that analyzing is under way.
		 */
		FLAGS(lmp) |= FLG_RT_ANALZING;

		/*
		 * If this link map represents a relocatable object, then we
		 * need to finish the link-editing of the object at this point.
		 */
		if (FLAGS(lmp) & FLG_RT_OBJECT) {
			if (elf_obj_fini(lml, lmp) == 0) {
				if (lml->lm_flags & LML_FLG_TRC_ENABLE)
					continue;
				ret = 0;
				break;
			}
		}

		DBG_CALL(Dbg_file_analyze(lmp));

		/*
		 * Establish any dependencies this object requires.
		 */
		if (LM_NEEDED(lmp)(lml, nlmco, lmp) == 0) {
			if (lml->lm_flags & LML_FLG_TRC_ENABLE)
				continue;
			ret = 0;
			break;
		}

		FLAGS(lmp) &= ~FLG_RT_ANALZING;
		FLAGS(lmp) |= FLG_RT_ANALYZED;

		/*
		 * If we're building a configuration file, determine if this
		 * object is a filter and if so load its filtees.  This
		 * traversal is only necessary for crle(1), as typical use of
		 * an object will load filters as part of relocation processing.
		 */
		if (MODE(nlmp) & RTLD_CONFGEN)
			load_filtees(lmp);

		/*
		 * If an interposer has been added, it will have been inserted
		 * in the link-map before the link we're presently analyzing.
		 * Break out of this analysis loop and return to the head of
		 * the link-map control list to analyze the interposer.  Note
		 * that this rescan preserves the breadth first loading of
		 * dependencies.
		 */
		/* LINTED */
		nlmc = (Lm_cntl *)alist_item_by_offset(lml->lm_lists, nlmco);
		if (nlmc->lc_flags & LMC_FLG_REANALYZE) {
			nlmc->lc_flags &= ~LMC_FLG_REANALYZE;
			lmp = nlmc->lc_head;
		}
	}

	/* LINTED */
	nlmc = (Lm_cntl *)alist_item_by_offset(lml->lm_lists, nlmco);
	nlmc->lc_flags &= ~LMC_FLG_ANALYZING;

	return (ret);
}

/*
 * Copy relocation test.  If the symbol definition is within .bss, then it's
 * zero filled, and as the destination is within .bss, we can skip copying
 * zero's to zero's.  However, if the destination object has a MOVE table, it's
 * .bss might contain non-zero data, in which case copy it regardless.
 */
static int
copy_zerobits(Rt_map *dlmp, Sym *dsym)
{
	if ((FLAGS(dlmp) & FLG_RT_MOVE) == 0) {
		Mmap	*mmaps;
		caddr_t	daddr = (caddr_t)dsym->st_value;

		if ((FLAGS(dlmp) & FLG_RT_FIXED) == 0)
			daddr += ADDR(dlmp);

		for (mmaps = MMAPS(dlmp); mmaps->m_vaddr; mmaps++) {
			if ((mmaps->m_fsize != mmaps->m_msize) &&
			    (daddr >= (mmaps->m_vaddr + mmaps->m_fsize)) &&
			    (daddr < (mmaps->m_vaddr + mmaps->m_msize)))
				return (1);
		}
	}
	return (0);
}

/*
 * Relocate an individual object.
 */
static int
relocate_so(Lm_list *lml, Rt_map *lmp, int *relocated, int now)
{
	/*
	 * If we're running under ldd(1), and haven't been asked to trace any
	 * warnings, skip any actual relocation processing.
	 */
	if (((lml->lm_flags & LML_FLG_TRC_ENABLE) == 0) ||
	    (lml->lm_flags & LML_FLG_TRC_WARN)) {

		if (relocated)
			(*relocated)++;

		if ((LM_RELOC(lmp)(lmp, now) == 0) &&
		    ((lml->lm_flags & LML_FLG_TRC_ENABLE) == 0))
			return (0);
	}
	return (1);
}

/*
 * Relocate the objects on a link-map control list.
 */
static int
_relocate_lmc(Lm_list *lml, Rt_map *nlmp, int *relocated)
{
	Rt_map	*lmp;

	for (lmp = nlmp; lmp; lmp = (Rt_map *)NEXT(lmp)) {
		/*
		 * If this object has already been relocated, we're done.  If
		 * this object is being deleted, skip it, there's probably a
		 * relocation error somewhere that's causing this deletion.
		 */
		if (FLAGS(lmp) &
		    (FLG_RT_RELOCING | FLG_RT_RELOCED | FLG_RT_DELETE))
			continue;

		/*
		 * Indicate that relocation processing is under way.
		 */
		FLAGS(lmp) |= FLG_RT_RELOCING;

		/*
		 * Relocate the object.
		 */
		if (relocate_so(lml, lmp, relocated, 0) == 0)
			return (0);

		/*
		 * Indicate that the objects relocation is complete.
		 */
		FLAGS(lmp) &= ~FLG_RT_RELOCING;
		FLAGS(lmp) |= FLG_RT_RELOCED;

		/*
		 * Mark this object's init is available for harvesting.  Under
		 * ldd(1) this marking is necessary for -i (tsort) gathering.
		 */
		lml->lm_init++;
		lml->lm_flags |= LML_FLG_OBJADDED;

		/*
		 * Process any move data (not necessary under ldd()).
		 */
		if ((FLAGS(lmp) & FLG_RT_MOVE) &&
		    ((lml->lm_flags & LML_FLG_TRC_ENABLE) == 0))
			move_data(lmp);

		/*
		 * Determine if this object is a filter, and if a load filter
		 * flag is in effect, trigger the loading of all its filtees.
		 */
		load_filtees(lmp);
	}

	/*
	 * Perform special copy relocations.  These are only meaningful for
	 * dynamic executables (fixed and head of their link-map list).  If
	 * this ever has to change then the infrastructure of COPY() has to
	 * change. Presently, a given link map can only have a receiver or
	 * supplier of copy data, so a union is used to overlap the storage
	 * for the COPY_R() and COPY_S() lists. These lists would need to
	 * be separated.
	 */
	if ((FLAGS(nlmp) & FLG_RT_FIXED) && (nlmp == LIST(nlmp)->lm_head) &&
	    (((lml->lm_flags & LML_FLG_TRC_ENABLE) == 0) ||
	    (lml->lm_flags & LML_FLG_TRC_WARN))) {
		Rt_map		*lmp;
		Aliste		idx1;
		Word		tracing;

#if	defined(__i386)
		if (elf_copy_gen(nlmp) == 0)
			return (0);
#endif
		if (COPY_S(nlmp) == NULL)
			return (1);

		if ((LIST(nlmp)->lm_flags & LML_FLG_TRC_ENABLE) &&
		    (((rtld_flags & RT_FL_SILENCERR) == 0) ||
		    (LIST(nlmp)->lm_flags & LML_FLG_TRC_VERBOSE)))
			tracing = 1;
		else
			tracing = 0;

		DBG_CALL(Dbg_util_nl(lml, DBG_NL_STD));

		for (APLIST_TRAVERSE(COPY_S(nlmp), idx1, lmp)) {
			Rel_copy *	rcp;
			Aliste		idx2;

			for (ALIST_TRAVERSE(COPY_R(lmp), idx2, rcp)) {
				int zero;

				/*
				 * Only copy the bits if it's from non-zero
				 * filled memory.
				 */
				zero = copy_zerobits(rcp->r_dlmp, rcp->r_dsym);
				DBG_CALL(Dbg_reloc_copy(rcp->r_dlmp, nlmp,
				    rcp->r_name, zero));
				if (zero)
					continue;

				(void) memcpy(rcp->r_radd, rcp->r_dadd,
				    rcp->r_size);

				if ((tracing == 0) || ((FLAGS1(rcp->r_dlmp) &
				    FL1_RT_DISPREL) == 0))
					continue;

				(void) printf(MSG_INTL(MSG_LDD_REL_CPYDISP),
				    demangle(rcp->r_name), NAME(rcp->r_dlmp));
			}
		}

		DBG_CALL(Dbg_util_nl(lml, DBG_NL_STD));

		free(COPY_S(nlmp));
		COPY_S(nlmp) = 0;
	}
	return (1);
}

int
relocate_lmc(Lm_list *lml, Aliste nlmco, Rt_map *clmp, Rt_map *nlmp)
{
	int	lret = 1, pret = 1;
	APlist	*alp;
	Aliste	plmco;
	Lm_cntl	*plmc, *nlmc;

	/*
	 * If this link-map control list is being relocated, return.  The object
	 * that has just been added will be picked up by the existing relocation
	 * thread.  Note, this is only really meaningful during process init-
	 * ialization, as objects are added to the main link-map control list.
	 * Following this initialization, each family of objects that are loaded
	 * are added to a new link-map control list.
	 */
	/* LINTED */
	nlmc = (Lm_cntl *)alist_item_by_offset(lml->lm_lists, nlmco);

	if (nlmc->lc_flags & LMC_FLG_RELOCATING)
		return (1);

	nlmc->lc_flags |= LMC_FLG_RELOCATING;

	/*
	 * Relocate one or more link-maps of a link map control list.  If this
	 * object doesn't belong to the present link-map control list then it
	 * must already have been relocated, or it is in the process of being
	 * relocated prior to us recursing into this relocation.  In either
	 * case, ignore the object as it's already being taken care of, however,
	 * fall through and capture any relocation promotions that might have
	 * been established from the reference mode of this object.
	 *
	 * If we're generating a configuration file using crle(1), two passes
	 * may be involved.  Under the first pass, RTLD_CONFGEN is set.  Under
	 * this pass, crle() loads objects into the process address space.  No
	 * relocation is necessary at this point, we simply need to analyze the
	 * objects to insure any directly bound dependencies, filtees, etc.
	 * get loaded. Although we skip the relocation, fall through to insure
	 * any control lists are maintained appropriately.
	 *
	 * If objects are to be dldump(3c)'ed, crle(1) makes a second pass,
	 * using RTLD_NOW and RTLD_CONFGEN.  The RTLD_NOW effectively carries
	 * out the relocations of all loaded objects.
	 */
	if ((nlmco == CNTL(nlmp)) &&
	    ((MODE(nlmp) & (RTLD_NOW | RTLD_CONFGEN)) != RTLD_CONFGEN)) {
		int	relocated = 0;

		/*
		 * Determine whether the initial link-map control list has
		 * started relocation.  From this point, should any interposing
		 * objects be added to this link-map control list, the objects
		 * are demoted to standard objects.  Their interposition can't
		 * be guaranteed once relocations have been carried out.
		 */
		if (nlmco == ALIST_OFF_DATA)
			lml->lm_flags |= LML_FLG_STARTREL;

		/*
		 * Relocate the link-map control list.  Should this relocation
		 * fail, clean up this link-map list.  Relocations within this
		 * list may have required relocation promotions on other lists,
		 * so before acting upon these, and possibly adding more objects
		 * to the present link-map control list, try and clean up any
		 * failed objects now.
		 */
		lret = _relocate_lmc(lml, nlmp, &relocated);
		if ((lret == 0) && (nlmco != ALIST_OFF_DATA))
			remove_lmc(lml, clmp, nlmc, nlmco, NAME(nlmp));
	}

	/*
	 * Determine the new, and previous link-map control lists.
	 */
	/* LINTED */
	nlmc = (Lm_cntl *)alist_item_by_offset(lml->lm_lists, nlmco);
	if (nlmco == ALIST_OFF_DATA) {
		plmco = nlmco;
		plmc = nlmc;
	} else {
		plmco = nlmco - lml->lm_lists->al_size;
		/* LINTED */
		plmc = (Lm_cntl *)alist_item_by_offset(lml->lm_lists, plmco);
	}

	/*
	 * Having completed this control list of objects, they can now be bound
	 * to from other objects.  Move this control list to the control list
	 * that precedes it.  Although this control list may have only bound to
	 * controls lists much higher up the control list stack, it must only
	 * be moved up one control list so as to preserve the link-map order
	 * that may have already been traversed in search of symbols.
	 */
	if (lret && (nlmco != ALIST_OFF_DATA) && nlmc->lc_head)
		lm_move(lml, nlmco, plmco, nlmc, plmc);

	/*
	 * Determine whether existing objects that have already been relocated,
	 * need any additional relocations performed.  This can occur when new
	 * objects are loaded with RTLD_NOW, and these new objects have
	 * dependencies on objects that are already loaded.  Note, that we peel
	 * any relocation promotions off of one control list at a time.  This
	 * prevents relocations from being bound to objects that might yet fail
	 * to relocate themselves.
	 */
	while ((alp = plmc->lc_now) != NULL) {
		Aliste	idx;
		Rt_map	*lmp;

		/*
		 * Remove the relocation promotion list, as performing more
		 * relocations may result in discovering more objects that need
		 * promotion.
		 */
		plmc->lc_now = NULL;

		for (APLIST_TRAVERSE(alp, idx, lmp)) {
			/*
			 * If the original relocation of the link-map control
			 * list failed, or one of the relocation promotions of
			 * this loop has failed, demote any pending objects
			 * relocation mode.
			 */
			if ((lret == 0) || (pret == 0)) {
				MODE(lmp) &= ~RTLD_NOW;
				MODE(lmp) |= RTLD_LAZY;
				continue;
			}

			/*
			 * If a relocation fails, save the error condition.
			 * It's possible that all new objects on the original
			 * link-map control list have been relocated
			 * successfully, but if the user request requires
			 * promoting objects that have already been loaded, we
			 * have to indicate that this operation couldn't be
			 * performed.  The unrelocated objects are in use on
			 * another control list, and may continue to be used.
			 * If the .plt that resulted in the error is called,
			 * then the process will receive a fatal error at that
			 * time.  But, the .plt may never be called.
			 */
			if (relocate_so(lml, lmp, 0, 1) == 0)
				pret = 0;
		}

		/*
		 * Having promoted any objects, determine whether additional
		 * dependencies were added, and if so move them to the previous
		 * link-map control list.
		 */
		/* LINTED */
		nlmc = (Lm_cntl *)alist_item_by_offset(lml->lm_lists, nlmco);
		/* LINTED */
		plmc = (Lm_cntl *)alist_item_by_offset(lml->lm_lists, plmco);
		if ((nlmco != ALIST_OFF_DATA) && nlmc->lc_head)
			lm_move(lml, nlmco, plmco, nlmc, plmc);
		free(alp);
	}

	/*
	 * If relocations have been successful, indicate that relocations are
	 * no longer active for this control list.  Otherwise, leave the
	 * relocation flag, as this flag is used to determine the style of
	 * cleanup (see remove_lmc()).
	 */
	if (lret && pret) {
		/* LINTED */
		nlmc = (Lm_cntl *)alist_item_by_offset(lml->lm_lists, nlmco);
		nlmc->lc_flags &= ~LMC_FLG_RELOCATING;

		return (1);
	}

	return (0);
}

/*
 * Inherit the first rejection message for possible later diagnostics.
 *
 * Any attempt to process a file that is unsuccessful, should be accompanied
 * with an error diagnostic.  However, some operations like searching for a
 * simple filename, involve trying numerous paths, and an error message for each
 * lookup is not required.  Although a multiple search can fail, it's possible
 * that a file was found, but was rejected because it was the wrong type.
 * To satisfy these possibilities, the first failure is recorded as a rejection
 * message, and this message is used later for a more specific diagnostic.
 *
 * File searches are focused at load_one(), and from here a rejection descriptor
 * is passed down to various child routines.  If these child routines can
 * process multiple files, then they will maintain their own rejection desc-
 * riptor.  This is filled in for any failures, and a diagnostic produced to
 * reflect the failure.  The child routines then employ rejection_inherit() to
 * pass the first rejection message back to load_one().
 *
 * Note that the name, and rejection string must be duplicated, as the name
 * buffer and error string buffer (see conv_ routines) may be reused for
 * additional processing or rejection messages.
 */
void
rejection_inherit(Rej_desc *rej1, Rej_desc *rej2)
{
	if (rej2->rej_type && (rej1->rej_type == 0)) {
		rej1->rej_type = rej2->rej_type;
		rej1->rej_info = rej2->rej_info;
		rej1->rej_flag = rej2->rej_flag;
		if (rej2->rej_name)
			rej1->rej_name = strdup(rej2->rej_name);
		if (rej2->rej_str) {
			if ((rej1->rej_str = strdup(rej2->rej_str)) == NULL)
				rej1->rej_str = MSG_ORIG(MSG_EMG_ENOMEM);
		}
	}
}

/*
 * Determine the object type of a file.
 */
Fct *
are_u_this(Rej_desc *rej, int fd, struct stat *status, const char *name)
{
	int	i;
	char	*maddr = 0;

	fmap->fm_fsize = status->st_size;

	/*
	 * If this is a directory (which can't be mmap()'ed) generate a precise
	 * error message.
	 */
	if ((status->st_mode & S_IFMT) == S_IFDIR) {
		rej->rej_type = SGS_REJ_STR;
		rej->rej_str = strerror(EISDIR);
		return (0);
	}

	/*
	 * Map in the first page of the file.  When this buffer is first used,
	 * the mapping is a single system page.  This is typically enough to
	 * inspect the ehdr and phdrs of the file, and can be reused for each
	 * file that get loaded.  If a larger mapping is required to read the
	 * ehdr and phdrs, a new mapping is created (see elf_map_it()).  This
	 * new mapping is again used for each new file loaded.  Some objects,
	 * such as filters, only take up one page, and in this case this mapping
	 * will suffice for the file.
	 */
	maddr = mmap(fmap->fm_maddr, fmap->fm_msize, (PROT_READ | PROT_EXEC),
	    fmap->fm_mflags, fd, 0);
#if defined(MAP_ALIGN)
	if ((maddr == MAP_FAILED) && (errno == EINVAL)) {
		/*
		 * If the mapping failed, and we used MAP_ALIGN, assume we're
		 * on a system that doesn't support this option.  Try again
		 * without MAP_ALIGN.
		 */
		if (fmap->fm_mflags & MAP_ALIGN) {
			rtld_flags2 |= RT_FL2_NOMALIGN;
			fmap_setup();

			maddr = (char *)mmap(fmap->fm_maddr, fmap->fm_msize,
			    (PROT_READ | PROT_EXEC), fmap->fm_mflags, fd, 0);
		}
	}
#endif
	if (maddr == MAP_FAILED) {
		rej->rej_type = SGS_REJ_STR;
		rej->rej_str = strerror(errno);
		return (0);
	}

	/*
	 * From now on we will re-use fmap->fm_maddr as the mapping address
	 * so we augment the flags with MAP_FIXED and drop any MAP_ALIGN.
	 */
	fmap->fm_maddr = maddr;
	fmap->fm_mflags |= MAP_FIXED;
#if defined(MAP_ALIGN)
	fmap->fm_mflags &= ~MAP_ALIGN;
#endif

	/*
	 * Search through the object vectors to determine what kind of
	 * object we have.
	 */
	for (i = 0; vector[i]; i++) {
		if ((vector[i]->fct_are_u_this)(rej))
			return (vector[i]);
		else if (rej->rej_type) {
			Rt_map	*lmp;

			/*
			 * If this object is an explicitly defined shared
			 * object under inspection by ldd, and contains a
			 * incompatible hardware capabilities requirement, then
			 * inform the user, but continue processing.
			 *
			 * XXXX - ldd -v for any rej failure.
			 */
			if ((rej->rej_type == SGS_REJ_HWCAP_1) &&
			    (lml_main.lm_flags & LML_FLG_TRC_LDDSTUB) &&
			    ((lmp = lml_main.lm_head) != 0) &&
			    (FLAGS1(lmp) & FL1_RT_LDDSTUB) &&
			    (NEXT(lmp) == 0)) {
				(void) printf(MSG_INTL(MSG_LDD_GEN_HWCAP_1),
				    name, rej->rej_str);
				return (vector[i]);
			}
			return (0);
		}
	}

	/*
	 * Unknown file type.
	 */
	rej->rej_type = SGS_REJ_UNKFILE;
	return (0);
}

/*
 * Helper routine for is_so_matched() that consolidates matching a path name,
 * or file name component of a link-map name.
 */
static int
_is_so_matched(const char *name, const char *str, int path)
{
	const char	*_str;

	if ((path == 0) && ((_str = strrchr(str, '/')) != NULL))
		_str++;
	else
		_str = str;

	return (strcmp(name, _str));
}

/*
 * Determine whether a search name matches one of the names associated with a
 * link-map.  A link-map contains several names:
 *
 *  .	a NAME() - typically the full pathname of an object that has been
 *	loaded.  For example, when looking for the dependency "libc.so.1", a
 * 	search path is applied, with the eventual NAME() being "/lib/ld.so.1".
 *	The name of the executable is typically a simple filename, such as
 *	"main", as this is the name passed to exec() to start the process.
 *
 *  .	a PATHNAME() - this is maintained if the resolved NAME() is different
 * 	to NAME(), ie. the original name is a symbolic link.  This is also
 * 	the resolved full pathname for a dynamic executable.
 *
 *  .	a list of ALIAS() names - these are alternative names by which the
 *	object has been found, ie. when dependencies are loaded through a
 * 	variety of different symbolic links.
 *
 * The name pattern matching can differ depending on whether we are looking
 * for a full path name (path != 0), or a simple file name (path == 0).  Full
 * path names typically match NAME() or PATHNAME() entries, so these link-map
 * names are inspected first when a full path name is being searched for.
 * Simple file names typically match ALIAS() names, so these link-map names are
 * inspected first when a simple file name is being searched for.
 *
 * For all full path name searches, the link-map names are taken as is.  For
 * simple file name searches, only the file name component of any link-map
 * names are used for comparison.
 */
static Rt_map *
is_so_matched(Rt_map *lmp, const char *name, int path)
{
	Aliste		idx;
	const char	*cp;

	/*
	 * A pathname is typically going to match a NAME() or PATHNAME(), so
	 * check these first.
	 */
	if (path) {
		if (strcmp(name, NAME(lmp)) == 0)
			return (lmp);

		if (PATHNAME(lmp) != NAME(lmp)) {
			if (strcmp(name, PATHNAME(lmp)) == 0)
				return (lmp);
		}
	}

	/*
	 * Typically, dependencies are specified as simple file names
	 * (DT_NEEDED == libc.so.1), which are expanded to full pathnames to
	 * open the file.  The full pathname is NAME(), and the original name
	 * is maintained on the ALIAS() list.
	 *
	 * If this is a simple filename, or a pathname has failed to match the
	 * NAME() and PATHNAME() check above, look through the ALIAS() list.
	 */
	for (APLIST_TRAVERSE(ALIAS(lmp), idx, cp)) {
		/*
		 * If we're looking for a simple filename, _is_so_matched()
		 * will reduce the ALIAS name to its simple name.
		 */
		if (_is_so_matched(name, cp, path) == 0)
			return (lmp);
	}

	/*
	 * Finally, if this is a simple file name, and any ALIAS() search has
	 * been completed, match the simple file name of NAME() and PATHNAME().
	 */
	if (path == 0) {
		if (_is_so_matched(name, NAME(lmp), 0) == 0)
			return (lmp);

		if (PATHNAME(lmp) != NAME(lmp)) {
			if (_is_so_matched(name, PATHNAME(lmp), 0) == 0)
				return (lmp);
		}
	}

	return (0);
}

/*
 * Files are opened by ld.so.1 to satisfy dependencies, filtees and dlopen()
 * requests.  Each request investigates the file based upon the callers
 * environment, and once a full path name has been established a check is made
 * against the FullpathNode AVL tree and a device/inode check, to ensure the
 * same file isn't mapped multiple times.  See file_open().
 *
 * However, there are one of two cases where a test for an existing file name
 * needs to be carried out, such as dlopen(NOLOAD) requests, dldump() requests,
 * and as a final fallback to dependency loading.  These requests are handled
 * by is_so_loaded().
 *
 * A traversal through the callers link-map list is carried out, and from each
 * link-map, a comparison is made against all of the various names by which the
 * object has been referenced.  The subroutine, is_so_matched() compares the
 * link-map names against the name being searched for.  Whether the search name
 * is a full path name or a simple file name, governs what comparisons are made.
 *
 * A full path name, which is a fully resolved path name that starts with a "/"
 * character, or a relative path name that includes a "/" character, must match
 * the link-map names explicitly.  A simple file name, which is any name *not*
 * containing a "/" character, are matched against the file name component of
 * any link-map names.
 */
Rt_map *
is_so_loaded(Lm_list *lml, const char *name)
{
	Rt_map		*lmp;
	avl_index_t	where;
	Lm_cntl		*lmc;
	Aliste		idx;
	int		path = 0;

	/*
	 * If the name is a full path name, first determine if the path name is
	 * registered in the FullpathNode AVL tree.
	 */
	if ((name[0] == '/') &&
	    ((lmp = fpavl_loaded(lml, name, &where)) != NULL) &&
	    ((FLAGS(lmp) & (FLG_RT_OBJECT | FLG_RT_DELETE)) == 0))
		return (lmp);

	/*
	 * Determine whether the name is a simple file name, or a path name.
	 */
	if (strchr(name, '/'))
		path++;

	/*
	 * Loop through the callers link-map lists.
	 */
	for (ALIST_TRAVERSE(lml->lm_lists, idx, lmc)) {
		for (lmp = lmc->lc_head; lmp; lmp = (Rt_map *)NEXT(lmp)) {
			if (FLAGS(lmp) & (FLG_RT_OBJECT | FLG_RT_DELETE))
				continue;

			if (is_so_matched(lmp, name, path))
				return (lmp);
		}
	}
	return ((Rt_map *)0);
}

/*
 * Tracing is enabled by the LD_TRACE_LOADED_OPTIONS environment variable which
 * is normally set from ldd(1).  For each link map we load, print the load name
 * and the full pathname of the shared object.
 */
/* ARGSUSED4 */
static void
trace_so(Rt_map *clmp, Rej_desc *rej, const char *name, const char *path,
    int alter, const char *nfound)
{
	const char	*str = MSG_ORIG(MSG_STR_EMPTY);
	const char	*reject = MSG_ORIG(MSG_STR_EMPTY);
	char		_reject[PATH_MAX];

	/*
	 * The first time through trace_so() will only have lddstub on the
	 * link-map list and the preloaded shared object is supplied as "path".
	 * As we don't want to print this shared object as a dependency, but
	 * instead inspect *its* dependencies, return.
	 */
	if (FLAGS1(clmp) & FL1_RT_LDDSTUB)
		return;

	/*
	 * Without any rejection info, this is a supplied not-found condition.
	 */
	if (rej && (rej->rej_type == 0)) {
		(void) printf(nfound, name);
		return;
	}

	/*
	 * If rejection information exists then establish what object was
	 * found and the reason for its rejection.
	 */
	if (rej) {
		Conv_reject_desc_buf_t rej_buf;

		/* LINTED */
		(void) snprintf(_reject, PATH_MAX,
		    MSG_INTL(ldd_reject[rej->rej_type]),
		    conv_reject_desc(rej, &rej_buf));
		if (rej->rej_name)
			path = rej->rej_name;
		reject = (char *)_reject;

		/*
		 * Was an alternative pathname defined (from a configuration
		 * file).
		 */
		if (rej->rej_flag & FLG_FD_ALTER)
			str = MSG_INTL(MSG_LDD_FIL_ALTER);
	} else {
		if (alter)
			str = MSG_INTL(MSG_LDD_FIL_ALTER);
	}

	/*
	 * If the load name isn't a full pathname print its associated pathname
	 * together with all the other information we've gathered.
	 */
	if (*name == '/')
		(void) printf(MSG_ORIG(MSG_LDD_FIL_PATH), path, str, reject);
	else
		(void) printf(MSG_ORIG(MSG_LDD_FIL_EQUIV), name, path, str,
		    reject);
}


/*
 * Establish a link-map mode, initializing it if it has just been loaded, or
 * potentially updating it if it already exists.
 */
int
update_mode(Rt_map *lmp, int omode, int nmode)
{
	Lm_list	*lml = LIST(lmp);
	int	pmode = 0;

	/*
	 * A newly loaded object hasn't had its mode set yet.  Modes are used to
	 * load dependencies, so don't propagate any parent or no-load flags, as
	 * these would adversely affect this objects ability to load any of its
	 * dependencies that aren't already loaded.  RTLD_FIRST is applicable to
	 * this objects handle creation only, and should not be propagated.
	 */
	if ((FLAGS(lmp) & FLG_RT_MODESET) == 0) {
		MODE(lmp) |= nmode & ~(RTLD_PARENT | RTLD_NOLOAD | RTLD_FIRST);
		FLAGS(lmp) |= FLG_RT_MODESET;
		return (1);
	}

	/*
	 * Establish any new overriding modes.  RTLD_LAZY and RTLD_NOW should be
	 * represented individually (this is historic, as these two flags were
	 * the only flags originally available to dlopen()).  Other flags are
	 * accumulative, but have a hierarchy of preference.
	 */
	if ((omode & RTLD_LAZY) && (nmode & RTLD_NOW)) {
		MODE(lmp) &= ~RTLD_LAZY;
		pmode |= RTLD_NOW;
	}

	pmode |= ((~omode & nmode) &
	    (RTLD_GLOBAL | RTLD_WORLD | RTLD_NODELETE));
	if (pmode) {
		DBG_CALL(Dbg_file_mode_promote(lmp, pmode));
		MODE(lmp) |= pmode;
	}

	/*
	 * If this load is an RTLD_NOW request and the object has already been
	 * loaded non-RTLD_NOW, append this object to the relocation-now list
	 * of the objects associated control list.  Note, if the object hasn't
	 * yet been relocated, setting its MODE() to RTLD_NOW will establish
	 * full relocation processing when it eventually gets relocated.
	 */
	if ((pmode & RTLD_NOW) &&
	    (FLAGS(lmp) & (FLG_RT_RELOCED | FLG_RT_RELOCING))) {
		Lm_cntl	*lmc;

		/* LINTED */
		lmc = (Lm_cntl *)alist_item_by_offset(LIST(lmp)->lm_lists,
		    CNTL(lmp));
		(void) aplist_append(&lmc->lc_now, lmp, AL_CNT_LMNOW);
	}

#ifdef	SIEBEL_DISABLE
	/*
	 * For patch backward compatibility the following .init collection
	 * is disabled.
	 */
	if (rtld_flags & RT_FL_DISFIX_1)
		return (pmode);
#endif

	/*
	 * If this objects .init has been collected but has not yet been called,
	 * it may be necessary to reevaluate the object using tsort().  For
	 * example, a new dlopen() hierarchy may bind to uninitialized objects
	 * that are already loaded, or a dlopen(RTLD_NOW) can establish new
	 * bindings between already loaded objects that require the tsort()
	 * information be recomputed.  If however, no new objects have been
	 * added to the process, and this object hasn't been promoted, don't
	 * bother reevaluating the .init.  The present tsort() information is
	 * probably as accurate as necessary, and by not establishing a parallel
	 * tsort() we can help reduce the amount of recursion possible between
	 * .inits.
	 */
	if (((FLAGS(lmp) &
	    (FLG_RT_INITCLCT | FLG_RT_INITCALL)) == FLG_RT_INITCLCT) &&
	    ((lml->lm_flags & LML_FLG_OBJADDED) || ((pmode & RTLD_NOW) &&
	    (FLAGS(lmp) & (FLG_RT_RELOCED | FLG_RT_RELOCING))))) {
		FLAGS(lmp) &= ~FLG_RT_INITCLCT;
		LIST(lmp)->lm_init++;
		LIST(lmp)->lm_flags |= LML_FLG_OBJREEVAL;
	}

	return (pmode);
}

/*
 * Determine whether an alias name already exists, and if not create one.  This
 * is typically used to retain dependency names, such as "libc.so.1", which
 * would have been expanded to full path names when they were loaded.  The
 * full path names (NAME() and possibly PATHNAME()) are maintained as Fullpath
 * AVL nodes, and thus would have been matched by fpavl_loaded() during
 * file_open().
 */
int
append_alias(Rt_map *lmp, const char *str, int *added)
{
	Aliste	idx;
	char	*cp;

	/*
	 * Determine if this filename is already on the alias list.
	 */
	for (APLIST_TRAVERSE(ALIAS(lmp), idx, cp)) {
		if (strcmp(cp, str) == 0)
			return (1);
	}

	/*
	 * This is a new alias, append it to the alias list.
	 */
	if ((cp = strdup(str)) == NULL)
		return (0);

	if (aplist_append(&ALIAS(lmp), cp, AL_CNT_ALIAS) == NULL) {
		free(cp);
		return (0);
	}
	if (added)
		*added = 1;
	return (1);
}

/*
 * Determine whether a file is already loaded by comparing device and inode
 * values.
 */
static Rt_map *
is_devinode_loaded(struct stat *status, Lm_list *lml, const char *name,
    uint_t flags)
{
	Lm_cntl	*lmc;
	Aliste	idx;

	/*
	 * If this is an auditor, it will have been opened on a new link-map.
	 * To prevent multiple occurrences of the same auditor on multiple
	 * link-maps, search the head of each link-map list and see if this
	 * object is already loaded as an auditor.
	 */
	if (flags & FLG_RT_AUDIT) {
		Lm_list *	lml;
		Listnode *	lnp;

		for (LIST_TRAVERSE(&dynlm_list, lnp, lml)) {
			Rt_map	*nlmp = lml->lm_head;

			if (nlmp && ((FLAGS(nlmp) &
			    (FLG_RT_AUDIT | FLG_RT_DELETE)) == FLG_RT_AUDIT) &&
			    (STDEV(nlmp) == status->st_dev) &&
			    (STINO(nlmp) == status->st_ino))
				return (nlmp);
		}
		return ((Rt_map *)0);
	}

	/*
	 * If the file has been found determine from the new files status
	 * information if this file is actually linked to one we already have
	 * mapped.  This catches symlink names not caught by is_so_loaded().
	 */
	for (ALIST_TRAVERSE(lml->lm_lists, idx, lmc)) {
		Rt_map	*nlmp;

		for (nlmp = lmc->lc_head; nlmp; nlmp = (Rt_map *)NEXT(nlmp)) {
			if ((FLAGS(nlmp) & FLG_RT_DELETE) ||
			    (FLAGS1(nlmp) & FL1_RT_LDDSTUB))
				continue;

			if ((STDEV(nlmp) != status->st_dev) ||
			    (STINO(nlmp) != status->st_ino))
				continue;

			if (lml->lm_flags & LML_FLG_TRC_VERBOSE) {
				/* BEGIN CSTYLED */
				if (*name == '/')
				    (void) printf(MSG_ORIG(MSG_LDD_FIL_PATH),
					name, MSG_ORIG(MSG_STR_EMPTY),
					MSG_ORIG(MSG_STR_EMPTY));
				else
				    (void) printf(MSG_ORIG(MSG_LDD_FIL_EQUIV),
					name, NAME(nlmp),
					MSG_ORIG(MSG_STR_EMPTY),
					MSG_ORIG(MSG_STR_EMPTY));
				/* END CSTYLED */
			}
			return (nlmp);
		}
	}
	return ((Rt_map *)0);
}

/*
 * Generate any error messages indicating a file could not be found.  When
 * preloading or auditing a secure application, it can be a little more helpful
 * to indicate that a search of secure directories has failed, so adjust the
 * messages accordingly.
 */
void
file_notfound(Lm_list *lml, const char *name, Rt_map *clmp, uint_t flags,
    Rej_desc * rej)
{
	int	secure = 0;

	if ((rtld_flags & RT_FL_SECURE) &&
	    (flags & (FLG_RT_PRELOAD | FLG_RT_AUDIT)))
		secure++;

	if (lml->lm_flags & LML_FLG_TRC_ENABLE) {
		/*
		 * Under ldd(1), auxiliary filtees that can't be loaded are
		 * ignored, unless verbose errors are requested.
		 */
		if ((rtld_flags & RT_FL_SILENCERR) &&
		    ((lml->lm_flags & LML_FLG_TRC_VERBOSE) == 0))
			return;

		if (secure)
			trace_so(clmp, rej, name, 0, 0,
			    MSG_INTL(MSG_LDD_SEC_NFOUND));
		else
			trace_so(clmp, rej, name, 0, 0,
			    MSG_INTL(MSG_LDD_FIL_NFOUND));
		return;
	}

	if (rej->rej_type) {
		Conv_reject_desc_buf_t rej_buf;

		eprintf(lml, ERR_FATAL, MSG_INTL(err_reject[rej->rej_type]),
		    rej->rej_name ? rej->rej_name : MSG_INTL(MSG_STR_UNKNOWN),
		    conv_reject_desc(rej, &rej_buf));
		return;
	}

	if (secure)
		eprintf(lml, ERR_FATAL, MSG_INTL(MSG_SEC_OPEN), name);
	else
		eprintf(lml, ERR_FATAL, MSG_INTL(MSG_SYS_OPEN), name,
		    strerror(ENOENT));
}

static int
file_open(int err, Lm_list *lml, const char *oname, const char *nname,
    Rt_map *clmp, uint_t flags, Fdesc *fdesc, Rej_desc *rej)
{
	struct stat	status;
	Rt_map		*nlmp;
	int		resolved = 0;

	fdesc->fd_oname = oname;

	if ((err == 0) && (fdesc->fd_flags & FLG_FD_ALTER))
		DBG_CALL(Dbg_file_config_obj(lml, oname, 0, nname));

	/*
	 * If we're dealing with a full pathname, determine whether this
	 * pathname is already known.  Other pathnames fall through to the
	 * dev/inode check, as even though the pathname may look the same as
	 * one previously used, the process may have changed directory.
	 */
	if ((err == 0) && (nname[0] == '/')) {
		if ((nlmp = fpavl_loaded(lml, nname,
		    &(fdesc->fd_avlwhere))) != NULL) {
			fdesc->fd_nname = nname;
			fdesc->fd_lmp = nlmp;
			return (1);
		}
	}

	if ((err == 0) && ((stat(nname, &status)) != -1)) {
		char	path[PATH_MAX];
		int	fd, size, added;

		/*
		 * If this path has been constructed as part of expanding a
		 * HWCAP directory, ignore any subdirectories.  As this is a
		 * silent failure, where no rejection message is created, free
		 * the original name to simplify the life of the caller.  For
		 * any other reference that expands to a directory, fall through
		 * to construct a meaningful rejection message.
		 */
		if ((flags & FLG_RT_HWCAP) &&
		    ((status.st_mode & S_IFMT) == S_IFDIR)) {
			free((void *)nname);
			return (0);
		}

		/*
		 * Resolve the filename and determine whether the resolved name
		 * is already known.  Typically, the previous fpavl_loaded()
		 * will have caught this, as both NAME() and PATHNAME() for a
		 * link-map are recorded in the FullNode AVL tree.  However,
		 * instances exist where a file can be replaced (loop-back
		 * mounts, bfu, etc.), and reference is made to the original
		 * file through a symbolic link.  By checking the pathname here,
		 * we don't fall through to the dev/inode check and conclude
		 * that a new file should be loaded.
		 */
		if ((nname[0] == '/') && (rtld_flags & RT_FL_EXECNAME) &&
		    ((size = resolvepath(nname, path, (PATH_MAX - 1))) > 0)) {
			path[size] = '\0';

			if (strcmp(nname, path)) {
				if ((nlmp =
				    fpavl_loaded(lml, path, 0)) != NULL) {
					added = 0;

					if (append_alias(nlmp, nname,
					    &added) == 0)
						return (0);
					/* BEGIN CSTYLED */
					if (added)
					    DBG_CALL(Dbg_file_skip(LIST(clmp),
						NAME(nlmp), nname));
					/* END CSTYLED */
					fdesc->fd_nname = nname;
					fdesc->fd_lmp = nlmp;
					return (1);
				}

				/*
				 * If this pathname hasn't been loaded, save
				 * the resolved pathname so that it doesn't
				 * have to be recomputed as part of fullpath()
				 * processing.
				 */
				if ((fdesc->fd_pname = strdup(path)) == NULL)
					return (0);
				resolved = 1;
			} else {
				/*
				 * If the resolved name doesn't differ from the
				 * original, save it without duplication.
				 * Having fd_pname set indicates that no further
				 * resolvepath processing is necessary.
				 */
				fdesc->fd_pname = nname;
			}
		}

		if (nlmp = is_devinode_loaded(&status, lml, nname, flags)) {
			if (flags & FLG_RT_AUDIT) {
				/*
				 * If we've been requested to load an auditor,
				 * and an auditor of the same name already
				 * exists, then the original auditor is used.
				 */
				DBG_CALL(Dbg_audit_skip(LIST(clmp),
				    NAME(nlmp), LIST(nlmp)->lm_lmidstr));
			} else {
				/*
				 * Otherwise, if an alternatively named file
				 * has been found for the same dev/inode, add
				 * a new name alias, and insert any alias full
				 * pathname in the link-map lists AVL tree.
				 */
				added = 0;

				if (append_alias(nlmp, nname, &added) == 0)
					return (0);
				if (added) {
					if ((nname[0] == '/') &&
					    (fpavl_insert(lml, nlmp,
					    nname, 0) == 0))
						return (0);
					DBG_CALL(Dbg_file_skip(LIST(clmp),
					    NAME(nlmp), nname));
				}
			}

			/*
			 * Record in the file descriptor the existing object
			 * that satisfies this open request.
			 */
			fdesc->fd_nname = nname;
			fdesc->fd_lmp = nlmp;
			return (1);
		}

		if ((fd = open(nname, O_RDONLY, 0)) == -1) {
			/*
			 * As the file must exist for the previous stat() to
			 * have succeeded, record the error condition.
			 */
			rej->rej_type = SGS_REJ_STR;
			rej->rej_str = strerror(errno);
		} else {
			Fct	*ftp;

			if ((ftp = are_u_this(rej, fd, &status, nname)) != 0) {
				fdesc->fd_nname = nname;
				fdesc->fd_ftp = ftp;
				fdesc->fd_dev = status.st_dev;
				fdesc->fd_ino = status.st_ino;
				fdesc->fd_fd = fd;

				/*
				 * Trace that this open has succeeded.
				 */
				if (lml->lm_flags & LML_FLG_TRC_ENABLE) {
					trace_so(clmp, 0, oname, nname,
					    (fdesc->fd_flags & FLG_FD_ALTER),
					    0);
				}
				return (1);
			}
			(void) close(fd);
		}

	} else if (errno != ENOENT) {
		/*
		 * If the open() failed for anything other than the file not
		 * existing, record the error condition.
		 */
		rej->rej_type = SGS_REJ_STR;
		rej->rej_str = strerror(errno);
	}

	/*
	 * Indicate any rejection.
	 */
	if (rej->rej_type) {
		/*
		 * If this pathname was resolved and duplicated, remove the
		 * allocated name to simplify the cleanup of the callers.
		 */
		if (resolved) {
			free((void *)fdesc->fd_pname);
			fdesc->fd_pname = NULL;
		}
		rej->rej_name = nname;
		rej->rej_flag = (fdesc->fd_flags & FLG_FD_ALTER);
		DBG_CALL(Dbg_file_rejected(lml, rej));
	}
	return (0);
}

/*
 * Find a full pathname (it contains a "/").
 */
int
find_path(Lm_list *lml, const char *oname, Rt_map *clmp, uint_t flags,
    Fdesc *fdesc, Rej_desc *rej)
{
	int	err = 0;

	/*
	 * If directory configuration exists determine if this path is known.
	 */
	if (rtld_flags & RT_FL_DIRCFG) {
		Rtc_obj		*obj;
		const char	*aname;

		if ((obj = elf_config_ent(oname, (Word)elf_hash(oname),
		    0, &aname)) != 0) {
			/*
			 * If the configuration file states that this path is a
			 * directory, or the path is explicitly defined as
			 * non-existent (ie. a unused platform specific
			 * library), then go no further.
			 */
			if (obj->co_flags & RTC_OBJ_DIRENT) {
				err = EISDIR;
			} else if ((obj->co_flags &
			    (RTC_OBJ_NOEXIST | RTC_OBJ_ALTER)) ==
			    RTC_OBJ_NOEXIST) {
				err = ENOENT;
			} else if ((obj->co_flags & RTC_OBJ_ALTER) &&
			    (rtld_flags & RT_FL_OBJALT) && (lml == &lml_main)) {
				int	ret;

				fdesc->fd_flags |= FLG_FD_ALTER;
				/*
				 * Attempt to open the alternative path.  If
				 * this fails, and the alternative is flagged
				 * as optional, fall through to open the
				 * original path.
				 */
				DBG_CALL(Dbg_libs_found(lml, aname,
				    FLG_FD_ALTER));
				if (((ret = file_open(0, lml, oname, aname,
				    clmp, flags, fdesc, rej)) != 0) ||
				    ((obj->co_flags & RTC_OBJ_OPTINAL) == 0))
					return (ret);

				fdesc->fd_flags &= ~FLG_FD_ALTER;
			}
		}
	}
	DBG_CALL(Dbg_libs_found(lml, oname, 0));
	return (file_open(err, lml, oname, oname, clmp, flags, fdesc, rej));
}

/*
 * Find a simple filename (it doesn't contain a "/").
 */
static int
_find_file(Lm_list *lml, const char *oname, const char *nname, Rt_map *clmp,
    uint_t flags, Fdesc *fdesc, Rej_desc *rej, Pnode *dir, int aflag)
{
	DBG_CALL(Dbg_libs_found(lml, nname, aflag));
	if ((lml->lm_flags & LML_FLG_TRC_SEARCH) &&
	    ((FLAGS1(clmp) & FL1_RT_LDDSTUB) == 0)) {
		(void) printf(MSG_INTL(MSG_LDD_PTH_TRYING), nname, aflag ?
		    MSG_INTL(MSG_LDD_FIL_ALTER) : MSG_ORIG(MSG_STR_EMPTY));
	}

	/*
	 * If we're being audited tell the audit library of the file we're about
	 * to go search for.  The audit library may offer an alternative
	 * dependency, or indicate that this dependency should be ignored.
	 */
	if ((lml->lm_tflags | FLAGS1(clmp)) & LML_TFLG_AUD_OBJSEARCH) {
		char	*aname = audit_objsearch(clmp, nname, dir->p_orig);

		if (aname == 0) {
			DBG_CALL(Dbg_audit_terminate(lml, nname));
			return (0);
		}

		/*
		 * Protect ourselves from auditor mischief, by copying any
		 * alternative name over the present name (the present name is
		 * maintained in a static buffer - see elf_get_so());
		 */
		if (nname != aname)
			(void) strncpy((char *)nname, aname, PATH_MAX);
	}
	return (file_open(0, lml, oname, nname, clmp, flags, fdesc, rej));
}

static int
find_file(Lm_list *lml, const char *oname, Rt_map *clmp, uint_t flags,
    Fdesc *fdesc, Rej_desc *rej, Pnode *dir, Word * strhash, size_t olen)
{
	static Rtc_obj	Obj = { 0 };
	Rtc_obj *	dobj;
	const char	*nname = oname;

	if (dir->p_name == 0)
		return (0);
	if (dir->p_info) {
		dobj = (Rtc_obj *)dir->p_info;
		if ((dobj->co_flags &
		    (RTC_OBJ_NOEXIST | RTC_OBJ_ALTER)) == RTC_OBJ_NOEXIST)
			return (0);
	} else
		dobj = 0;

	/*
	 * If configuration information exists see if this directory/file
	 * combination exists.
	 */
	if ((rtld_flags & RT_FL_DIRCFG) &&
	    ((dobj == 0) || (dobj->co_id != 0))) {
		Rtc_obj		*fobj;
		const char	*alt = 0;

		/*
		 * If this pnode has not yet been searched for in the
		 * configuration file go find it.
		 */
		if (dobj == 0) {
			dobj = elf_config_ent(dir->p_name,
			    (Word)elf_hash(dir->p_name), 0, 0);
			if (dobj == 0)
				dobj = &Obj;
			dir->p_info = (void *)dobj;

			if ((dobj->co_flags & (RTC_OBJ_NOEXIST |
			    RTC_OBJ_ALTER)) == RTC_OBJ_NOEXIST)
				return (0);
		}

		/*
		 * If we found a directory search for the file.
		 */
		if (dobj->co_id != 0) {
			if (*strhash == 0)
				*strhash = (Word)elf_hash(nname);
			fobj = elf_config_ent(nname, *strhash,
			    dobj->co_id, &alt);

			/*
			 * If this object specifically does not exist, or the
			 * object can't be found in a know-all-entries
			 * directory, continue looking.  If the object does
			 * exist determine if an alternative object exists.
			 */
			if (fobj == 0) {
				if (dobj->co_flags & RTC_OBJ_ALLENTS)
					return (0);
			} else {
				if ((fobj->co_flags & (RTC_OBJ_NOEXIST |
				    RTC_OBJ_ALTER)) == RTC_OBJ_NOEXIST)
					return (0);

				if ((fobj->co_flags & RTC_OBJ_ALTER) &&
				    (rtld_flags & RT_FL_OBJALT) &&
				    (lml == &lml_main)) {
					int	ret;

					fdesc->fd_flags |= FLG_FD_ALTER;
					/*
					 * Attempt to open the alternative path.
					 * If this fails, and the alternative is
					 * flagged as optional, fall through to
					 * open the original path.
					 */
					ret = _find_file(lml, oname, alt, clmp,
					    flags, fdesc, rej, dir, 1);
					if (ret || ((fobj->co_flags &
					    RTC_OBJ_OPTINAL) == 0))
						return (ret);

					fdesc->fd_flags &= ~FLG_FD_ALTER;
				}
			}
		}
	}

	/*
	 * Protect ourselves from building an invalid pathname.
	 */
	if ((olen + dir->p_len + 1) >= PATH_MAX) {
		eprintf(lml, ERR_FATAL, MSG_INTL(MSG_SYS_OPEN), nname,
		    strerror(ENAMETOOLONG));
			return (0);
	}
	if ((nname = (LM_GET_SO(clmp)(dir->p_name, nname))) == 0)
		return (0);

	return (_find_file(lml, oname, nname, clmp, flags, fdesc, rej, dir, 0));
}

/*
 * A unique file has been opened.  Create a link-map to represent it, and
 * process the various names by which it can be referenced.
 */
static Rt_map *
load_file(Lm_list *lml, Aliste lmco, Fdesc *fdesc)
{
	const char	*oname = fdesc->fd_oname;
	const char	*nname = fdesc->fd_nname;
	Rt_map		*nlmp;

	/*
	 * Typically we call fct_map_so() with the full pathname of the opened
	 * file (nname) and the name that started the search (oname), thus for
	 * a typical dependency on libc this would be /usr/lib/libc.so.1 and
	 * libc.so.1 (DT_NEEDED).  The original name is maintained on an ALIAS
	 * list for comparison when bringing in new dependencies.  If the user
	 * specified name as a full path (from a dlopen() for example) then
	 * there's no need to create an ALIAS.
	 */
	if (strcmp(oname, nname) == 0)
		oname = 0;

	/*
	 * A new file has been opened, now map it into the process.  Close the
	 * original file so as not to accumulate file descriptors.
	 */
	nlmp = ((fdesc->fd_ftp)->fct_map_so)(lml, lmco, nname, oname,
	    fdesc->fd_fd);
	(void) close(fdesc->fd_fd);
	fdesc->fd_fd = 0;

	if (nlmp == 0)
		return (0);

	/*
	 * Save the dev/inode information for later comparisons.
	 */
	STDEV(nlmp) = fdesc->fd_dev;
	STINO(nlmp) = fdesc->fd_ino;

	/*
	 * Insert the names of this link-map into the FullpathNode AVL tree.
	 * Save both the NAME() and PATHNAME() is they differ.
	 *
	 * If this is an OBJECT file, don't insert it yet as this is only a
	 * temporary link-map.  During elf_obj_fini() the final link-map is
	 * created, and its names will be inserted in the FullpathNode AVL
	 * tree at that time.
	 */
	if ((FLAGS(nlmp) & FLG_RT_OBJECT) == 0) {
		/*
		 * Update the objects full path information if necessary.
		 * Note, with pathname expansion in effect, the fd_pname will
		 * be used as PATHNAME().  This allocated string will be freed
		 * should this object be deleted.  However, without pathname
		 * expansion, the fd_name should be freed now, as it is no
		 * longer referenced.
		 */
		if (FLAGS1(nlmp) & FL1_RT_RELATIVE)
			(void) fullpath(nlmp, fdesc->fd_pname);
		else if (fdesc->fd_pname != fdesc->fd_nname)
			free((void *)fdesc->fd_pname);
		fdesc->fd_pname = 0;

		if ((NAME(nlmp)[0] == '/') && (fpavl_insert(lml, nlmp,
		    NAME(nlmp), fdesc->fd_avlwhere) == 0)) {
			remove_so(lml, nlmp);
			return (0);
		}
		if (((NAME(nlmp)[0] != '/') ||
		    (NAME(nlmp) != PATHNAME(nlmp))) &&
		    (fpavl_insert(lml, nlmp, PATHNAME(nlmp), 0) == 0)) {
			remove_so(lml, nlmp);
			return (0);
		}
	}

	/*
	 * If we're processing an alternative object reset the original name
	 * for possible $ORIGIN processing.
	 */
	if (fdesc->fd_flags & FLG_FD_ALTER) {
		const char	*odir;
		char		*ndir;
		size_t		olen;

		FLAGS(nlmp) |= FLG_RT_ALTER;

		/*
		 * If we were given a pathname containing a slash then the
		 * original name is still in oname.  Otherwise the original
		 * directory is in dir->p_name (which is all we need for
		 * $ORIGIN).
		 */
		if (fdesc->fd_flags & FLG_FD_SLASH) {
			char	*ofil;

			odir = oname;
			ofil = strrchr(oname, '/');
			olen = ofil - odir + 1;
		} else {
			odir = fdesc->fd_odir;
			olen = strlen(odir) + 1;
		}

		if ((ndir = (char *)malloc(olen)) == 0) {
			remove_so(lml, nlmp);
			return (0);
		}
		(void) strncpy(ndir, odir, olen);
		ndir[--olen] = '\0';

		ORIGNAME(nlmp) = ndir;
		DIRSZ(nlmp) = olen;
	}

	/*
	 * Identify this as a new object.
	 */
	FLAGS(nlmp) |= FLG_RT_NEWLOAD;

	return (nlmp);
}

/*
 * This function loads the named file and returns a pointer to its link map.
 * It is assumed that the caller has already checked that the file is not
 * already loaded before calling this function (refer is_so_loaded()).
 * Find and open the file, map it into memory, add it to the end of the list
 * of link maps and return a pointer to the new link map.  Return 0 on error.
 */
static Rt_map *
load_so(Lm_list *lml, Aliste lmco, const char *oname, Rt_map *clmp,
    uint_t flags, Fdesc *nfdp, Rej_desc *rej)
{
	char		*name;
	uint_t		slash = 0;
	size_t		olen;
	Fdesc		fdesc = { 0 };
	Pnode		*dir;

	/*
	 * If the file is the run time linker then it's already loaded.
	 */
	if (interp && (strcmp(oname, NAME(lml_rtld.lm_head)) == 0))
		return (lml_rtld.lm_head);

	/*
	 * If this isn't a hardware capabilities pathname, which is already a
	 * full, duplicated pathname, determine whether the pathname contains
	 * a slash, and if not determine the input filename (for max path
	 * length verification).
	 */
	if ((flags & FLG_RT_HWCAP) == 0) {
		const char	*str;

		for (str = oname; *str; str++) {
			if (*str == '/') {
				slash++;
				break;
			}
		}
		if (slash == 0)
			olen = (str - oname) + 1;
	}

	/*
	 * If we are passed a 'null' link-map this means that this is the first
	 * object to be loaded on this link-map list.  In that case we set the
	 * link-map to ld.so.1's link-map.
	 *
	 * This link-map is referenced to determine what lookup rules to use
	 * when searching for files.  By using ld.so.1's we are defaulting to
	 * ELF look-up rules.
	 *
	 * Note: This case happens when loading the first object onto
	 *	 the plt_tracing link-map.
	 */
	if (clmp == 0)
		clmp = lml_rtld.lm_head;

	/*
	 * If this path resulted from a $HWCAP specification, then the best
	 * hardware capability object has already been establish, and is
	 * available in the calling file descriptor.  Perform some minor book-
	 * keeping so that we can fall through into common code.
	 */
	if (flags & FLG_RT_HWCAP) {
		/*
		 * If this object is already loaded, we're done.
		 */
		if (nfdp->fd_lmp)
			return (nfdp->fd_lmp);

		/*
		 * Obtain the avl index for this object.
		 */
		(void) fpavl_loaded(lml, nfdp->fd_nname, &(nfdp->fd_avlwhere));

		/*
		 * If the name and resolved pathname differ, duplicate the path
		 * name once more to provide for generic cleanup by the caller.
		 */
		if (nfdp->fd_pname && (nfdp->fd_nname != nfdp->fd_pname)) {
			char	*pname;

			if ((pname = strdup(nfdp->fd_pname)) == NULL)
				return (0);
			nfdp->fd_pname = pname;
		}
	} else if (slash) {
		Rej_desc	_rej = { 0 };

		*nfdp = fdesc;
		nfdp->fd_flags = FLG_FD_SLASH;

		if (find_path(lml, oname, clmp, flags, nfdp, &_rej) == 0) {
			rejection_inherit(rej, &_rej);
			return (0);
		}

		/*
		 * If this object is already loaded, we're done.
		 */
		if (nfdp->fd_lmp)
			return (nfdp->fd_lmp);

	} else {
		/*
		 * No '/' - for each directory on list, make a pathname using
		 * that directory and filename and try to open that file.
		 */
		Pnode		*dirlist = (Pnode *)0;
		Word		strhash = 0;
#if	!defined(ISSOLOAD_BASENAME_DISABLED)
		Rt_map		*nlmp;
#endif
		DBG_CALL(Dbg_libs_find(lml, oname));

#if	!defined(ISSOLOAD_BASENAME_DISABLED)
		if ((nlmp = is_so_loaded(lml, oname)))
			return (nlmp);
#endif
		/*
		 * Make sure we clear the file descriptor new name in case the
		 * following directory search doesn't provide any directories
		 * (odd, but this can be forced with a -znodefaultlib test).
		 */
		*nfdp = fdesc;
		for (dir = get_next_dir(&dirlist, clmp, flags); dir;
		    dir = get_next_dir(&dirlist, clmp, flags)) {
			Rej_desc	_rej = { 0 };

			*nfdp = fdesc;

			/*
			 * Try and locate this file.  Make sure to clean up
			 * any rejection information should the file have
			 * been found, but not appropriate.
			 */
			if (find_file(lml, oname, clmp, flags, nfdp, &_rej,
			    dir, &strhash, olen) == 0) {
				rejection_inherit(rej, &_rej);
				continue;
			}

			/*
			 * If this object is already loaded, we're done.
			 */
			if (nfdp->fd_lmp)
				return (nfdp->fd_lmp);

			nfdp->fd_odir = dir->p_name;
			break;
		}

		/*
		 * If the file couldn't be loaded, do another comparison of
		 * loaded files using just the basename.  This catches folks
		 * who may have loaded multiple full pathname files (possibly
		 * from setxid applications) to satisfy dependency relationships
		 * (i.e., a file might have a dependency on foo.so.1 which has
		 * already been opened using its full pathname).
		 */
		if (nfdp->fd_nname == NULL)
			return (is_so_loaded(lml, oname));
	}

	/*
	 * Duplicate the file name so that NAME() is available in core files.
	 * Note, that hardware capability names are already duplicated, but
	 * they get duplicated once more to insure consistent cleanup in the
	 * event of an error condition.
	 */
	if ((name = strdup(nfdp->fd_nname)) == NULL)
		return (0);

	if (nfdp->fd_nname == nfdp->fd_pname)
		nfdp->fd_nname = nfdp->fd_pname = name;
	else
		nfdp->fd_nname = name;

	/*
	 * Finish mapping the file and return the link-map descriptor.  Note,
	 * if this request originated from a HWCAP request, re-establish the
	 * fdesc information.  For single paged objects, such as filters, the
	 * original mapping may have been sufficient to capture the file, thus
	 * this mapping needs to be reset to insure it doesn't mistakenly get
	 * unmapped as part of HWCAP cleanup.
	 */
	return (load_file(lml, lmco, nfdp));
}

/*
 * Trace an attempt to load an object.
 */
int
load_trace(Lm_list *lml, const char **oname, Rt_map *clmp)
{
	const char	*name = *oname;

	/*
	 * First generate any ldd(1) diagnostics.
	 */
	if ((lml->lm_flags & (LML_FLG_TRC_VERBOSE | LML_FLG_TRC_SEARCH)) &&
	    ((FLAGS1(clmp) & FL1_RT_LDDSTUB) == 0))
		(void) printf(MSG_INTL(MSG_LDD_FIL_FIND), name, NAME(clmp));

	/*
	 * If we're being audited tell the audit library of the file we're
	 * about to go search for.
	 */
	if (((lml->lm_tflags | FLAGS1(clmp)) & LML_TFLG_AUD_ACTIVITY) &&
	    (lml == LIST(clmp)))
		audit_activity(clmp, LA_ACT_ADD);

	if ((lml->lm_tflags | FLAGS1(clmp)) & LML_TFLG_AUD_OBJSEARCH) {
		char	*aname = audit_objsearch(clmp, name, LA_SER_ORIG);

		/*
		 * The auditor can indicate that this object should be ignored.
		 */
		if (aname == NULL) {
			DBG_CALL(Dbg_audit_terminate(lml, name));
			return (0);
		}

		/*
		 * Protect ourselves from auditor mischief, by duplicating any
		 * alternative name.  The original name has been allocated from
		 * expand(), so free this allocation before using the audit
		 * alternative.
		 */
		if (name != aname) {
			if ((aname = strdup(aname)) == NULL) {
				eprintf(lml, ERR_FATAL,
				    MSG_INTL(MSG_GEN_AUDITERM), name);
				return (0);
			}
			free((void *)*oname);
			*oname = aname;
		}
	}
	return (1);
}

/*
 * Having loaded an object and created a link-map to describe it, finish
 * processing this stage, including verifying any versioning requirements,
 * updating the objects mode, creating a handle if necessary, and adding this
 * object to existing handles if required.
 */
static int
load_finish(Lm_list *lml, const char *name, Rt_map *clmp, int nmode,
    uint_t flags, Grp_hdl **hdl, Rt_map *nlmp)
{
	Aliste		idx;
	Grp_hdl		*ghp;
	int		promote;

	/*
	 * If this dependency is associated with a required version insure that
	 * the version is present in the loaded file.
	 */
	if (((rtld_flags & RT_FL_NOVERSION) == 0) &&
	    (FCT(clmp) == &elf_fct) && VERNEED(clmp) &&
	    (LM_VERIFY_VERS(clmp)(name, clmp, nlmp) == 0))
		return (0);

	/*
	 * If this object has indicated that it should be isolated as a group
	 * (DT_FLAGS_1 contains DF_1_GROUP - object was built with -B group),
	 * or if the callers direct bindings indicate it should be isolated as
	 * a group (DYNINFO flags contains FLG_DI_GROUP - dependency followed
	 * -zgroupperm), establish the appropriate mode.
	 *
	 * The intent of an object defining itself as a group is to isolate the
	 * relocation of the group within its own members, however, unless
	 * opened through dlopen(), in which case we assume dlsym() will be used
	 * to located symbols in the new object, we still need to associate it
	 * with the caller for it to be bound with.  This is equivalent to a
	 * dlopen(RTLD_GROUP) and dlsym() using the returned handle.
	 */
	if ((FLAGS(nlmp) | flags) & FLG_RT_SETGROUP) {
		nmode &= ~RTLD_WORLD;
		nmode |= RTLD_GROUP;

		/*
		 * If the object wasn't explicitly dlopen()'ed associate it with
		 * the parent.
		 */
		if ((flags & FLG_RT_HANDLE) == 0)
			nmode |= RTLD_PARENT;
	}

	/*
	 * Establish new mode and flags.
	 *
	 * For patch backward compatibility, the following use of update_mode()
	 * is disabled.
	 */
#ifdef	SIEBEL_DISABLE
	if (rtld_flags & RT_FL_DISFIX_1)
		promote = MODE(nlmp) |=
		    (nmode & ~(RTLD_PARENT | RTLD_NOLOAD | RTLD_FIRST));
	else
#endif
		promote = update_mode(nlmp, MODE(nlmp), nmode);

	FLAGS(nlmp) |= flags;

	/*
	 * If this is a global object, ensure the associated link-map list can
	 * be rescanned for global, lazy dependencies.
	 */
	if (MODE(nlmp) & RTLD_GLOBAL)
		LIST(nlmp)->lm_flags &= ~LML_FLG_NOPENDGLBLAZY;

	/*
	 * If we've been asked to establish a handle create one for this object.
	 * Or, if this object has already been analyzed, but this reference
	 * requires that the mode of the object be promoted, also create a
	 * handle to propagate the new modes to all this objects dependencies.
	 */
	if (((FLAGS(nlmp) | flags) & FLG_RT_HANDLE) || (promote &&
	    (FLAGS(nlmp) & FLG_RT_ANALYZED))) {
		uint_t	oflags, hflags = 0, cdflags;

		/*
		 * Establish any flags for the handle (Grp_hdl).
		 *
		 *  .	Use of the RTLD_FIRST flag indicates that only the first
		 *	dependency on the handle (the new object) can be used
		 *	to satisfy dlsym() requests.
		 */
		if (nmode & RTLD_FIRST)
			hflags = GPH_FIRST;

		/*
		 * Establish the flags for this callers dependency descriptor
		 * (Grp_desc).
		 *
		 *  .	The creation of a handle associated a descriptor for the
		 *	new object and descriptor for the parent (caller).
		 *	Typically, the handle is created for dlopen() or for
		 *	filtering.  A handle may also be created to promote
		 *	the callers modes (RTLD_NOW) to the new object.  In this
		 *	latter case, the handle/descriptor are torn down once
		 *	the mode propagation has occurred.
		 *
		 *  .	Use of the RTLD_PARENT flag indicates that the parent
		 *	can be relocated against.
		 */
		if (((FLAGS(nlmp) | flags) & FLG_RT_HANDLE) == 0)
			cdflags = GPD_PROMOTE;
		else
			cdflags = GPD_PARENT;
		if (nmode & RTLD_PARENT)
			cdflags |= GPD_RELOC;

		/*
		 * Now that a handle is being created, remove this state from
		 * the object so that it doesn't mistakenly get inherited by
		 * a dependency.
		 */
		oflags = FLAGS(nlmp);
		FLAGS(nlmp) &= ~FLG_RT_HANDLE;

		DBG_CALL(Dbg_file_hdl_title(DBG_HDL_ADD));
		if ((ghp = hdl_create(lml, nlmp, clmp, hflags,
		    (GPD_DLSYM | GPD_RELOC | GPD_ADDEPS), cdflags)) == 0)
			return (0);

		/*
		 * Add any dependencies that are already loaded, to the handle.
		 */
		if (hdl_initialize(ghp, nlmp, nmode, promote) == 0)
			return (0);

		if (hdl)
			*hdl = ghp;

		/*
		 * If we were asked to create a handle, we're done.
		 */
		if ((oflags | flags) & FLG_RT_HANDLE)
			return (1);

		/*
		 * If the handle was created to promote modes from the parent
		 * (caller) to the new object, then this relationship needs to
		 * be removed to ensure the handle doesn't prevent the new
		 * objects from being deleted if required.  If the parent is
		 * the only dependency on the handle, then the handle can be
		 * completely removed.  However, the handle may have already
		 * existed, in which case only the parent descriptor can be
		 * deleted from the handle, or at least the GPD_PROMOTE flag
		 * removed from the descriptor.
		 *
		 * Fall through to carry out any group processing.
		 */
		free_hdl(ghp, clmp, GPD_PROMOTE);
	}

	/*
	 * If the caller isn't part of a group we're done.
	 */
	if (GROUPS(clmp) == NULL)
		return (1);

	/*
	 * Determine if our caller is already associated with a handle, if so
	 * we need to add this object to any handles that already exist.
	 * Traverse the list of groups our caller is a member of and add this
	 * new link-map to those groups.
	 */
	DBG_CALL(Dbg_file_hdl_title(DBG_HDL_ADD));
	for (APLIST_TRAVERSE(GROUPS(clmp), idx, ghp)) {
		Aliste		idx1;
		Grp_desc	*gdp;
		int		exist;
		Rt_map		*dlmp1;
		APlist		*lmalp = NULL;

		/*
		 * If the caller doesn't indicate that its dependencies should
		 * be added to a handle, ignore it.  This case identifies a
		 * parent of a dlopen(RTLD_PARENT) request.
		 */
		for (ALIST_TRAVERSE(ghp->gh_depends, idx1, gdp)) {
			if (gdp->gd_depend == clmp)
				break;
		}
		if ((gdp->gd_flags & GPD_ADDEPS) == 0)
			continue;

		if ((exist = hdl_add(ghp, nlmp,
		    (GPD_DLSYM | GPD_RELOC | GPD_ADDEPS))) == 0)
			return (0);

		/*
		 * If this member already exists then its dependencies will
		 * have already been processed.
		 */
		if (exist == ALE_EXISTS)
			continue;

		/*
		 * If the object we've added has just been opened, it will not
		 * yet have been processed for its dependencies, these will be
		 * added on later calls to load_one().  If it doesn't have any
		 * dependencies we're also done.
		 */
		if (((FLAGS(nlmp) & FLG_RT_ANALYZED) == 0) ||
		    (DEPENDS(nlmp) == NULL))
			continue;

		/*
		 * Otherwise, this object exists and has dependencies, so add
		 * all of its dependencies to the handle were operating on.
		 */
		if (aplist_append(&lmalp, nlmp, AL_CNT_DEPCLCT) == 0)
			return (0);

		for (APLIST_TRAVERSE(lmalp, idx1, dlmp1)) {
			Aliste		idx2;
			Bnd_desc 	*bdp;

			/*
			 * Add any dependencies of this dependency to the
			 * dynamic dependency list so they can be further
			 * processed.
			 */
			for (APLIST_TRAVERSE(DEPENDS(dlmp1), idx2, bdp)) {
				Rt_map *	dlmp2 = bdp->b_depend;

				if ((bdp->b_flags & BND_NEEDED) == 0)
					continue;

				if (aplist_test(&lmalp, dlmp2,
				    AL_CNT_DEPCLCT) == 0) {
					free(lmalp);
					return (0);
				}
			}

			if (nlmp == dlmp1)
				continue;

			if ((exist = hdl_add(ghp, dlmp1,
			    (GPD_DLSYM | GPD_RELOC | GPD_ADDEPS))) != 0) {
				if (exist == ALE_CREATE) {
					(void) update_mode(dlmp1, MODE(dlmp1),
					    nmode);
				}
				continue;
			}
			free(lmalp);
			return (0);
		}
		free(lmalp);
	}
	return (1);
}

/*
 * The central routine for loading shared objects.  Insures ldd() diagnostics,
 * handles and any other related additions are all done in one place.
 */
static Rt_map *
_load_path(Lm_list *lml, Aliste lmco, const char **oname, Rt_map *clmp,
    int nmode, uint_t flags, Grp_hdl ** hdl, Fdesc *nfdp, Rej_desc *rej)
{
	Rt_map		*nlmp;
	const char	*name = *oname;

	if ((nmode & RTLD_NOLOAD) == 0) {
		/*
		 * If this isn't a noload request attempt to load the file.
		 * Note, the name of the file may be changed by an auditor.
		 */
		if ((load_trace(lml, oname, clmp)) == 0)
			return (0);

		name = *oname;

		if ((nlmp = load_so(lml, lmco, name, clmp, flags,
		    nfdp, rej)) == 0)
			return (0);

		/*
		 * If we've loaded a library which identifies itself as not
		 * being dlopen()'able catch it here.  Let non-dlopen()'able
		 * objects through under RTLD_CONFGEN as they're only being
		 * mapped to be dldump()'ed.
		 */
		if ((rtld_flags & RT_FL_APPLIC) && ((FLAGS(nlmp) &
		    (FLG_RT_NOOPEN | FLG_RT_RELOCED)) == FLG_RT_NOOPEN) &&
		    ((nmode & RTLD_CONFGEN) == 0)) {
			Rej_desc	_rej = { 0 };

			_rej.rej_name = name;
			_rej.rej_type = SGS_REJ_STR;
			_rej.rej_str = MSG_INTL(MSG_GEN_NOOPEN);
			DBG_CALL(Dbg_file_rejected(lml, &_rej));
			rejection_inherit(rej, &_rej);
			remove_so(lml, nlmp);
			return (0);
		}
	} else {
		/*
		 * If it's a NOLOAD request - check to see if the object
		 * has already been loaded.
		 */
		/* LINTED */
		if (nlmp = is_so_loaded(lml, name)) {
			if ((lml->lm_flags & LML_FLG_TRC_VERBOSE) &&
			    ((FLAGS1(clmp) & FL1_RT_LDDSTUB) == 0)) {
				(void) printf(MSG_INTL(MSG_LDD_FIL_FIND), name,
				    NAME(clmp));
				/* BEGIN CSTYLED */
				if (*name == '/')
				    (void) printf(MSG_ORIG(MSG_LDD_FIL_PATH),
					name, MSG_ORIG(MSG_STR_EMPTY),
					MSG_ORIG(MSG_STR_EMPTY));
				else
				    (void) printf(MSG_ORIG(MSG_LDD_FIL_EQUIV),
					name, NAME(nlmp),
					MSG_ORIG(MSG_STR_EMPTY),
					MSG_ORIG(MSG_STR_EMPTY));
				/* END CSTYLED */
			}
		} else {
			Rej_desc	_rej = { 0 };

			_rej.rej_name = name;
			_rej.rej_type = SGS_REJ_STR;
			_rej.rej_str = strerror(ENOENT);
			DBG_CALL(Dbg_file_rejected(lml, &_rej));
			rejection_inherit(rej, &_rej);
			return (0);
		}
	}

	/*
	 * Finish processing this loaded object.
	 */
	if (load_finish(lml, name, clmp, nmode, flags, hdl, nlmp) == 0) {
		FLAGS(nlmp) &= ~FLG_RT_NEWLOAD;

		/*
		 * If this object has already been analyzed, then it is in use,
		 * so even though this operation has failed, it should not be
		 * torn down.
		 */
		if ((FLAGS(nlmp) & FLG_RT_ANALYZED) == 0)
			remove_so(lml, nlmp);
		return (0);
	}

	/*
	 * If this object is new, and we're being audited, tell the audit
	 * library of the file we've just opened.  Note, if the new link-map
	 * requires local auditing of its dependencies we also register its
	 * opening.
	 */
	if (FLAGS(nlmp) & FLG_RT_NEWLOAD) {
		FLAGS(nlmp) &= ~FLG_RT_NEWLOAD;

		if (((lml->lm_tflags | FLAGS1(clmp) | FLAGS1(nlmp)) &
		    LML_TFLG_AUD_MASK) && (((lml->lm_flags |
		    LIST(clmp)->lm_flags) & LML_FLG_NOAUDIT) == 0)) {
			if (audit_objopen(clmp, nlmp) == 0) {
				remove_so(lml, nlmp);
				return (0);
			}
		}
	}
	return (nlmp);
}

Rt_map *
load_path(Lm_list *lml, Aliste lmco, const char **name, Rt_map *clmp,
    int nmode, uint_t flags, Grp_hdl **hdl, Fdesc *cfdp, Rej_desc *rej)
{
	Rt_map	*lmp;
	Fdesc	nfdp = { 0 };

	/*
	 * If this path resulted from a $HWCAP specification, then the best
	 * hardware capability object has already been establish, and is
	 * available in the calling file descriptor.
	 */
	if (flags & FLG_RT_HWCAP) {
		if (cfdp->fd_lmp == 0) {
			/*
			 * If this object hasn't yet been mapped, re-establish
			 * the file descriptor structure to reflect this objects
			 * original initial page mapping.  Make sure any present
			 * file descriptor mapping is removed before overwriting
			 * the structure.
			 */
#if	defined(MAP_ALIGN)
			if (fmap->fm_maddr &&
			    ((fmap->fm_mflags & MAP_ALIGN) == 0))
#else
			if (fmap->fm_maddr)
#endif
				(void) munmap(fmap->fm_maddr, fmap->fm_msize);

			*fmap = cfdp->fd_fmap;
		}
		nfdp = *cfdp;
	}

	lmp = _load_path(lml, lmco, name, clmp, nmode, flags, hdl, &nfdp, rej);

	/*
	 * If this path originated from a $HWCAP specification, re-establish the
	 * fdesc information.  For single paged objects, such as filters, the
	 * original mapping may have been sufficient to capture the file, thus
	 * this mapping needs to be reset to insure it doesn't mistakenly get
	 * unmapped as part of HWCAP cleanup.
	 */
	if ((flags & FLG_RT_HWCAP) && (cfdp->fd_lmp == 0)) {
		cfdp->fd_fmap.fm_maddr = fmap->fm_maddr;
		cfdp->fd_fmap.fm_mflags = fmap->fm_mflags;
		cfdp->fd_fd = nfdp.fd_fd;
	}

	return (lmp);
}

/*
 * Load one object from a possible list of objects.  Typically, for requests
 * such as NEEDED's, only one object is specified.  However, this object could
 * be specified using $ISALIST or $HWCAP, in which case only the first object
 * that can be loaded is used (ie. the best).
 */
Rt_map *
load_one(Lm_list *lml, Aliste lmco, Pnode *pnp, Rt_map *clmp, int mode,
    uint_t flags, Grp_hdl ** hdl)
{
	Rej_desc	rej = { 0 };
	Pnode   	*tpnp;
	const char	*name;

	for (tpnp = pnp; tpnp && tpnp->p_name; tpnp = tpnp->p_next) {
		Rt_map	*tlmp;

		/*
		 * A Hardware capabilities requirement can itself expand into
		 * a number of candidates.
		 */
		if (tpnp->p_orig & PN_TKN_HWCAP) {
			if ((tlmp = load_hwcap(lml, lmco, tpnp->p_name, clmp,
			    mode, (flags | FLG_RT_HWCAP), hdl, &rej)) != 0) {
				remove_rej(&rej);
				return (tlmp);
			}
		} else {
			if ((tlmp = load_path(lml, lmco, &tpnp->p_name, clmp,
			    mode, flags, hdl, 0, &rej)) != 0) {
				remove_rej(&rej);
				return (tlmp);
			}
		}
	}

	/*
	 * If this pathname originated from an expanded token, use the original
	 * for any diagnostic output.
	 */
	if ((name = pnp->p_oname) == 0)
		name = pnp->p_name;

	file_notfound(lml, name, clmp, flags, &rej);
	remove_rej(&rej);
	return (0);
}

/*
 * Determine whether a symbol is defined as an interposer.
 */
int
is_sym_interposer(Rt_map *lmp, Sym *sym)
{
	Syminfo	*sip = SYMINFO(lmp);

	if (sip) {
		ulong_t	ndx;

		ndx = (((ulong_t)sym - (ulong_t)SYMTAB(lmp)) / SYMENT(lmp));
		/* LINTED */
		sip = (Syminfo *)((char *)sip + (ndx * SYMINENT(lmp)));
		if (sip->si_flags & SYMINFO_FLG_INTERPOSE)
			return (1);
	}
	return (0);
}

/*
 * While processing direct or group bindings, determine whether the object to
 * which we've bound can be interposed upon.  In this context, copy relocations
 * are a form of interposition.
 */
static Sym *
lookup_sym_interpose(Slookup *slp, Rt_map **dlmp, uint_t *binfo, Lm_list *lml,
    Sym *sym)
{
	Rt_map		*lmp;
	Slookup		sl;

	/*
	 * If we've bound to a copy relocation definition then we need to assign
	 * this binding to the original copy reference.  Fabricate an inter-
	 * position diagnostic, as this is a legitimate form of interposition.
	 */
	if (FLAGS1(*dlmp) & FL1_RT_COPYTOOK) {
		Rel_copy	*rcp;
		Aliste		idx;

		for (ALIST_TRAVERSE(COPY_R(*dlmp), idx, rcp)) {
			if ((sym == rcp->r_dsym) || (sym->st_value &&
			    (sym->st_value == rcp->r_dsym->st_value))) {
				*dlmp = rcp->r_rlmp;
				*binfo |=
				    (DBG_BINFO_INTERPOSE | DBG_BINFO_COPYREF);
				return (rcp->r_rsym);
			}
		}
	}

	if ((lml->lm_flags & LML_FLG_INTRPOSE) == 0)
		return ((Sym *)0);

	/*
	 * Traverse the list of known interposers to determine whether any
	 * offer the same symbol.  Note, the head of the link-map could be
	 * identified as an interposer.  If it is, make sure we only look for
	 * symbol definitions.  Otherwise, skip the head of the link-map, so
	 * that we don't bind to any .plt references, or copy-relocations
	 * unintentionally.
	 */
	lmp = lml->lm_head;
	sl = *slp;
	if (((FLAGS(lmp) & MSK_RT_INTPOSE) == 0) || (sl.sl_flags & LKUP_COPY))
		lmp = (Rt_map *)NEXT(lmp);
	else
		sl.sl_flags &= ~LKUP_SPEC;

	for (; lmp; lmp = (Rt_map *)NEXT(lmp)) {
		if (FLAGS(lmp) & FLG_RT_DELETE)
			continue;
		if ((FLAGS(lmp) & MSK_RT_INTPOSE) == 0)
			break;

		if (callable(lmp, *dlmp, 0, sl.sl_flags)) {
			Rt_map	*ilmp;

			sl.sl_imap = lmp;
			if (sym = SYMINTP(lmp)(&sl, &ilmp, binfo)) {
				/*
				 * If this object provides individual symbol
				 * interposers, make sure that the symbol we
				 * have found is tagged as an interposer.
				 */
				if ((FLAGS(ilmp) & FLG_RT_SYMINTPO) &&
				    (is_sym_interposer(ilmp, sym) == 0))
					continue;

				/*
				 * Indicate this binding has occurred to an
				 * interposer, and return the symbol.
				 */
				*binfo |= DBG_BINFO_INTERPOSE;
				*dlmp = ilmp;
				return (sym);
			}
		}
	}
	return ((Sym *)0);
}

/*
 * If an object specifies direct bindings (it contains a syminfo structure
 * describing where each binding was established during link-editing, and the
 * object was built -Bdirect), then look for the symbol in the specific object.
 */
static Sym *
lookup_sym_direct(Slookup *slp, Rt_map **dlmp, uint_t *binfo, Syminfo *sip,
    Rt_map *lmp)
{
	Rt_map	*clmp = slp->sl_cmap;
	Sym	*sym;
	Slookup	sl;

	/*
	 * If a direct binding resolves to the definition of a copy relocated
	 * variable, it must be redirected to the copy (in the executable) that
	 * will eventually be made.  Typically, this redirection occurs in
	 * lookup_sym_interpose().  But, there's an edge condition.  If a
	 * directly bound executable contains pic code, there may be a
	 * reference to a definition that will eventually have a copy made.
	 * However, this copy relocation may not yet have occurred, because
	 * the relocation making this reference comes before the relocation
	 * that will create the copy.
	 * Under direct bindings, the syminfo indicates that a copy will be
	 * taken (SYMINFO_FLG_COPY).  This can only be set in an executable.
	 * Thus, the caller must be the executable, so bind to the destination
	 * of the copy within the executable.
	 */
	if (((slp->sl_flags & LKUP_COPY) == 0) &&
	    (sip->si_flags & SYMINFO_FLG_COPY)) {

		slp->sl_imap = LIST(clmp)->lm_head;
		if (sym = SYMINTP(clmp)(slp, dlmp, binfo))
			*binfo |= (DBG_BINFO_DIRECT | DBG_BINFO_COPYREF);
		return (sym);
	}

	/*
	 * If we need to directly bind to our parent, start looking in each
	 * callers link map.
	 */
	sl = *slp;
	sl.sl_flags |= LKUP_DIRECT;
	sym = 0;

	if (sip->si_boundto == SYMINFO_BT_PARENT) {
		Aliste		idx1;
		Bnd_desc	*bdp;
		Grp_hdl		*ghp;

		/*
		 * Determine the parent of this explicit dependency from its
		 * CALLERS()'s list.
		 */
		for (APLIST_TRAVERSE(CALLERS(clmp), idx1, bdp)) {
			sl.sl_imap = lmp = bdp->b_caller;
			if ((sym = SYMINTP(lmp)(&sl, dlmp, binfo)) != 0)
				goto found;
		}

		/*
		 * A caller can also be defined as the parent of a dlopen()
		 * call.  Determine whether this object has any handles.  The
		 * dependencies maintained with the handle represent the
		 * explicit dependencies of the dlopen()'ed object, and the
		 * calling parent.
		 */
		for (APLIST_TRAVERSE(HANDLES(clmp), idx1, ghp)) {
			Grp_desc	*gdp;
			Aliste		idx2;

			for (ALIST_TRAVERSE(ghp->gh_depends, idx2, gdp)) {
				if ((gdp->gd_flags & GPD_PARENT) == 0)
					continue;
				sl.sl_imap = lmp = gdp->gd_depend;
				if ((sym = SYMINTP(lmp)(&sl, dlmp, binfo)) != 0)
					goto found;
			}
		}
	} else {
		/*
		 * If we need to direct bind to anything else look in the
		 * link map associated with this symbol reference.
		 */
		if (sip->si_boundto == SYMINFO_BT_SELF)
			sl.sl_imap = lmp = clmp;
		else
			sl.sl_imap = lmp;

		if (lmp)
			sym = SYMINTP(lmp)(&sl, dlmp, binfo);
	}
found:
	if (sym)
		*binfo |= DBG_BINFO_DIRECT;

	/*
	 * If we've bound to an object, determine whether that object can be
	 * interposed upon for this symbol.
	 */
	if (sym && (LIST(*dlmp)->lm_head != *dlmp) &&
	    (LIST(*dlmp) == LIST(clmp))) {
		Sym *	isym;

		if ((isym = lookup_sym_interpose(slp, dlmp, binfo,
		    LIST(*dlmp), sym)) != 0)
			return (isym);
	}

	return (sym);
}

static Sym *
core_lookup_sym(Rt_map *ilmp, Slookup *slp, Rt_map **dlmp, uint_t *binfo,
    Aliste off)
{
	Rt_map	*lmp;

	/*
	 * Copy relocations should start their search after the head of the
	 * main link-map control list.
	 */
	if ((off == ALIST_OFF_DATA) && (slp->sl_flags & LKUP_COPY) && ilmp)
		lmp = (Rt_map *)NEXT(ilmp);
	else
		lmp = ilmp;

	for (; lmp; lmp = (Rt_map *)NEXT(lmp)) {
		if (callable(slp->sl_cmap, lmp, 0, slp->sl_flags)) {
			Sym	*sym;

			slp->sl_imap = lmp;
			if (((sym = SYMINTP(lmp)(slp, dlmp, binfo)) != 0) ||
			    (*binfo & BINFO_REJSINGLE))
				return (sym);
		}
	}
	return (0);
}

static Sym *
_lazy_find_sym(Rt_map *ilmp, Slookup *slp, Rt_map **dlmp, uint_t *binfo)
{
	Rt_map	*lmp;

	for (lmp = ilmp; lmp; lmp = (Rt_map *)NEXT(lmp)) {
		if (LAZY(lmp) == 0)
			continue;
		if (callable(slp->sl_cmap, lmp, 0, slp->sl_flags)) {
			Sym	*sym;

			slp->sl_imap = lmp;
			if ((sym = elf_lazy_find_sym(slp, dlmp, binfo)) != 0)
				return (sym);
		}
	}
	return (0);
}

static Sym *
_lookup_sym(Slookup *slp, Rt_map **dlmp, uint_t *binfo)
{
	const char	*name = slp->sl_name;
	Rt_map		*clmp = slp->sl_cmap;
	Rt_map		*ilmp = slp->sl_imap, *lmp;
	ulong_t		rsymndx;
	Sym		*sym;
	Syminfo		*sip;
	Slookup		sl;

	/*
	 * Search the initial link map for the required symbol (this category is
	 * selected by dlsym(), where individual link maps are searched for a
	 * required symbol.  Therefore, we know we have permission to look at
	 * the link map).
	 */
	if (slp->sl_flags & LKUP_FIRST)
		return (SYMINTP(ilmp)(slp, dlmp, binfo));

	/*
	 * Determine whether this lookup can be satisfied by an objects direct,
	 * or lazy binding information.  This is triggered by a relocation from
	 * the object (hence rsymndx is set).
	 */
	if (((rsymndx = slp->sl_rsymndx) != 0) &&
	    ((sip = SYMINFO(clmp)) != 0)) {
		/*
		 * Find the corresponding Syminfo entry for the original
		 * referencing symbol.
		 */
		/* LINTED */
		sip = (Syminfo *)((char *)sip + (rsymndx * SYMINENT(clmp)));

		/*
		 * If the symbol information indicates a direct binding,
		 * determine the link map that is required to satisfy the
		 * binding.  Note, if the dependency can not be found, but a
		 * direct binding isn't required, we will still fall through
		 * to perform any default symbol search.
		 */
		if (sip->si_flags & SYMINFO_FLG_DIRECT) {
			uint_t	bound = sip->si_boundto;

			lmp = 0;
			if (bound < SYMINFO_BT_LOWRESERVE)
				lmp = elf_lazy_load(clmp, slp, bound, name);

			/*
			 * If direct bindings have been disabled, and this isn't
			 * a translator, skip any direct binding now that we've
			 * ensured the resolving object has been loaded.
			 *
			 * If we need to direct bind to anything, we look in
			 * ourselves, our parent, or in the link map we've just
			 * loaded.  Otherwise, even though we may have lazily
			 * loaded an object we still continue to search for
			 * symbols from the head of the link map list.
			 */
			if (((FLAGS(clmp) & FLG_RT_TRANS) ||
			    ((!(LIST(clmp)->lm_tflags & LML_TFLG_NODIRECT)) &&
			    (!(slp->sl_flags & LKUP_SINGLETON)))) &&
			    ((FLAGS1(clmp) & FL1_RT_DIRECT) ||
			    (sip->si_flags & SYMINFO_FLG_DIRECTBIND))) {
				sym = lookup_sym_direct(slp, dlmp, binfo,
				    sip, lmp);

				/*
				 * Determine whether this direct binding has
				 * been rejected.  If we've bound to a singleton
				 * without following a singleton search, then
				 * return.  The caller detects this condition
				 * and will trigger a new singleton search.
				 *
				 * For any other rejection (such as binding to
				 * a symbol labeled as nodirect - presumably
				 * because the symbol definition has been
				 * changed since the referring object was last
				 * built), fall through to a standard symbol
				 * search.
				 */
				if (((*binfo & BINFO_REJECTED) == 0) ||
				    (*binfo & BINFO_REJSINGLE))
					return (sym);

				*binfo &= ~BINFO_REJECTED;
			}
		}
	}

	/*
	 * Duplicate the lookup information, as we'll need to modify this
	 * information for some of the following searches.
	 */
	sl = *slp;

	/*
	 * If the referencing object has the DF_SYMBOLIC flag set, look in the
	 * referencing object for the symbol first.  Failing that, fall back to
	 * our generic search.
	 */
	if ((FLAGS1(clmp) & FL1_RT_SYMBOLIC) &&
	    ((sl.sl_flags & LKUP_SINGLETON) == 0)) {
		sl.sl_imap = clmp;
		if (sym = SYMINTP(clmp)(&sl, dlmp, binfo)) {
			ulong_t	dsymndx = (((ulong_t)sym -
			    (ulong_t)SYMTAB(*dlmp)) / SYMENT(*dlmp));

			/*
			 * Make sure this symbol hasn't explicitly been defined
			 * as nodirect.
			 */
			if (((sip = SYMINFO(*dlmp)) == 0) ||
			    /* LINTED */
			    ((sip = (Syminfo *)((char *)sip +
			    (dsymndx * SYMINENT(*dlmp)))) == 0) ||
			    ((sip->si_flags & SYMINFO_FLG_NOEXTDIRECT) == 0))
				return (sym);
		}
	}

	sl.sl_flags |= LKUP_STANDARD;

	/*
	 * If this lookup originates from a standard relocation, then traverse
	 * all link-map control lists, inspecting any object that is available
	 * to this caller.  Otherwise, traverse the link-map control list
	 * associated with the caller.
	 */
	if (sl.sl_flags & LKUP_STDRELOC) {
		Aliste	off;
		Lm_cntl	*lmc;

		sym = NULL;

		for (ALIST_TRAVERSE_BY_OFFSET(LIST(clmp)->lm_lists, off, lmc)) {
			if (((sym = core_lookup_sym(lmc->lc_head, &sl, dlmp,
			    binfo, off)) != NULL) ||
			    (*binfo & BINFO_REJSINGLE))
				break;
		}
	} else
		sym = core_lookup_sym(ilmp, &sl, dlmp, binfo, ALIST_OFF_DATA);

	/*
	 * If a symbol binding was rejected, because a binding occurred to a
	 * singleton without following the default symbol search, return so
	 * that the search can be repreated.
	 */
	if (*binfo & BINFO_REJSINGLE)
		return (sym);

	/*
	 * To allow transitioning into a world of lazy loading dependencies see
	 * if this link map contains objects that have lazy dependencies still
	 * outstanding.  If so, and we haven't been able to locate a non-weak
	 * symbol reference, start bringing in any lazy dependencies to see if
	 * the reference can be satisfied.  Use of dlsym(RTLD_PROBE) sets the
	 * LKUP_NOFALLBACK flag, and this flag disables this fall back.
	 */
	if ((sym == NULL) && ((sl.sl_flags & LKUP_NOFALLBACK) == 0)) {
		if ((lmp = ilmp) == 0)
			lmp = LIST(clmp)->lm_head;

		if ((sl.sl_flags & LKUP_WEAK) || (LIST(lmp)->lm_lazy == 0))
			return ((Sym *)0);

		DBG_CALL(Dbg_syms_lazy_rescan(LIST(clmp), name));

		/*
		 * If this request originated from a dlsym(RTLD_NEXT) then start
		 * looking for dependencies from the caller, otherwise use the
		 * initial link-map.
		 */
		if (sl.sl_flags & LKUP_NEXT)
			sym = _lazy_find_sym(clmp, &sl, dlmp, binfo);
		else {
			Aliste	idx;
			Lm_cntl	*lmc;

			for (ALIST_TRAVERSE(LIST(clmp)->lm_lists, idx, lmc)) {
				sl.sl_flags |= LKUP_NOFALLBACK;
				if ((sym = _lazy_find_sym(lmc->lc_head, &sl,
				    dlmp, binfo)) != 0)
					break;
			}
		}
	}
	return (sym);
}

/*
 * Symbol lookup routine.  Takes an ELF symbol name, and a list of link maps to
 * search.  If successful, return a pointer to the symbol table entry, a
 * pointer to the link map of the enclosing object, and information relating
 * to the type of binding.  Else return a null pointer.
 *
 * To improve elf performance, we first compute the elf hash value and pass
 * it to each find_sym() routine.  The elf function will use this value to
 * locate the symbol, the a.out function will simply ignore it.
 */
Sym *
lookup_sym(Slookup *slp, Rt_map **dlmp, uint_t *binfo)
{
	Rt_map		*clmp = slp->sl_cmap;
	Sym		*rsym = slp->sl_rsym, *sym = 0;
	uchar_t		rtype = slp->sl_rtype;

	if (slp->sl_hash == 0)
		slp->sl_hash = elf_hash(slp->sl_name);
	*binfo = 0;

	/*
	 * Establish any state that might be associated with a symbol reference.
	 */
	if (rsym) {
		if ((slp->sl_flags & LKUP_STDRELOC) &&
		    (ELF_ST_BIND(rsym->st_info) == STB_WEAK))
			slp->sl_flags |= LKUP_WEAK;

		if (ELF_ST_VISIBILITY(rsym->st_other) == STV_SINGLETON)
			slp->sl_flags |= LKUP_SINGLETON;
	}

	/*
	 * Establish any lookup state required for this type of relocation.
	 */
	if ((slp->sl_flags & LKUP_STDRELOC) && rtype) {
		if (rtype == M_R_COPY)
			slp->sl_flags |= LKUP_COPY;

		if (rtype != M_R_JMP_SLOT)
			slp->sl_flags |= LKUP_SPEC;
	}

	/*
	 * Under ldd -w, any unresolved weak references are diagnosed.  Set the
	 * symbol binding as global to trigger a relocation error if the symbol
	 * can not be found.
	 */
	if (rsym) {
		if (LIST(slp->sl_cmap)->lm_flags & LML_FLG_TRC_NOUNRESWEAK)
			slp->sl_bind = STB_GLOBAL;
		else if ((slp->sl_bind = ELF_ST_BIND(rsym->st_info)) ==
		    STB_WEAK)
			slp->sl_flags |= LKUP_WEAK;
	}

	/*
	 * Carry out an initial symbol search.  This search takes into account
	 * all the modes of the requested search.
	 */
	if (((sym = _lookup_sym(slp, dlmp, binfo)) == NULL) &&
	    (*binfo & BINFO_REJSINGLE)) {
		Slookup	sl = *slp;

		/*
		 * If a binding has been rejected because of binding to a
		 * singleton without going through a singleton search, then
		 * reset the lookup data, and try again.
		 */
		sl.sl_imap = LIST(sl.sl_cmap)->lm_head;
		sl.sl_flags &= ~(LKUP_FIRST | LKUP_SELF | LKUP_NEXT);
		sl.sl_flags |= LKUP_SINGLETON;
		sl.sl_rsymndx = 0;
		*binfo &= ~BINFO_REJECTED;
		sym = _lookup_sym(&sl, dlmp, binfo);
	}

	/*
	 * If the caller is restricted to a symbol search within its group,
	 * determine if it is necessary to follow a binding from outside of
	 * the group.
	 */
	if (sym && ((MODE(clmp) & (RTLD_GROUP | RTLD_WORLD)) == RTLD_GROUP)) {
		Sym *	isym;

		if ((isym = lookup_sym_interpose(slp, dlmp, binfo, LIST(*dlmp),
		    sym)) != 0)
			return (isym);
	}
	return (sym);
}

/*
 * Associate a binding descriptor with a caller and its dependency, or update
 * an existing descriptor.
 */
int
bind_one(Rt_map *clmp, Rt_map *dlmp, uint_t flags)
{
	Bnd_desc	*bdp;
	Aliste		idx;
	int		found = ALE_CREATE;

	/*
	 * Determine whether a binding descriptor already exists between the
	 * two objects.
	 */
	for (APLIST_TRAVERSE(DEPENDS(clmp), idx, bdp)) {
		if (bdp->b_depend == dlmp) {
			found = ALE_EXISTS;
			break;
		}
	}

	if (found == ALE_CREATE) {
		/*
		 * Create a new binding descriptor.
		 */
		if ((bdp = malloc(sizeof (Bnd_desc))) == 0)
			return (0);

		bdp->b_caller = clmp;
		bdp->b_depend = dlmp;
		bdp->b_flags = 0;

		/*
		 * Append the binding descriptor to the caller and the
		 * dependency.
		 */
		if (aplist_append(&DEPENDS(clmp), bdp, AL_CNT_DEPENDS) == 0)
			return (0);

		if (aplist_append(&CALLERS(dlmp), bdp, AL_CNT_CALLERS) == 0)
			return (0);
	}

	if ((found == ALE_CREATE) || ((bdp->b_flags & flags) != flags)) {
		bdp->b_flags |= flags;

		if (flags & BND_REFER)
			FLAGS1(dlmp) |= FL1_RT_USED;

		DBG_CALL(Dbg_file_bind_entry(LIST(clmp), bdp));
	}
	return (found);
}

/*
 * Cleanup after relocation processing.
 */
int
relocate_finish(Rt_map *lmp, APlist *bound, int textrel, int ret)
{
	DBG_CALL(Dbg_reloc_run(lmp, 0, ret, DBG_REL_FINISH));

	/*
	 * Establish bindings to all objects that have been bound to.
	 */
	if (bound) {
		Aliste	idx;
		Rt_map	*_lmp;

		if (ret) {
			for (APLIST_TRAVERSE(bound, idx, _lmp)) {
				if (bind_one(lmp, _lmp, BND_REFER) == 0) {
					ret = 0;
					break;
				}
			}
		}
		free(bound);
	}

	/*
	 * If we write enabled the text segment to perform these relocations
	 * re-protect by disabling writes.
	 */
	if (textrel)
		(void) LM_SET_PROT(lmp)(lmp, 0);

	return (ret);
}
