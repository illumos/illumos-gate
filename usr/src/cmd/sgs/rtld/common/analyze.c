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
 * Copyright (c) 1990, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2014, Joyent, Inc. All rights reserved.
 */

/*
 *	Copyright (c) 1988 AT&T
 *	  All Rights Reserved
 */

#include	<string.h>
#include	<stdio.h>
#include	<unistd.h>
#include	<sys/stat.h>
#include	<sys/mman.h>
#include	<sys/debug.h>
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
#include	"_a.out.h"
#include	"_inline_gen.h"
#include	"msg.h"

/*
 * If a load filter flag is in effect, and this object is a filter, trigger the
 * loading of all its filtees.  The load filter flag is in effect when creating
 * configuration files, or when under the control of ldd(1), or the LD_LOADFLTR
 * environment variable is set, or this object was built with the -zloadfltr
 * flag.  Otherwise, filtee loading is deferred until triggered by a relocation.
 */
static void
load_filtees(Rt_map *lmp, int *in_nfavl)
{
	if ((FLAGS1(lmp) & MSK_RT_FILTER) &&
	    ((FLAGS(lmp) & FLG_RT_LOADFLTR) ||
	    (LIST(lmp)->lm_tflags & LML_TFLG_LOADFLTR))) {
		Dyninfo		*dip =  DYNINFO(lmp);
		uint_t		cnt, max = DYNINFOCNT(lmp);
		Slookup		sl;

		/*
		 * Initialize the symbol lookup data structure.  Note, no symbol
		 * name is supplied.  This NULL name causes filters to be loaded
		 * but no symbol to be searched for.
		 */
		SLOOKUP_INIT(sl, 0, lmp, lmp, ld_entry_cnt, 0, 0, 0, 0, 0);

		for (cnt = 0; cnt < max; cnt++, dip++) {
			uint_t	binfo;
			Sresult	sr;

			SRESULT_INIT(sr, NULL);

			if (((dip->di_flags & MSK_DI_FILTER) == 0) ||
			    ((dip->di_flags & FLG_DI_AUXFLTR) &&
			    (rtld_flags & RT_FL_NOAUXFLTR)))
				continue;
			(void) elf_lookup_filtee(&sl, &sr, &binfo, cnt,
			    in_nfavl);
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
 *
 * Return the initial link-map from which analysis starts for relocate_lmc().
 */
Rt_map *
analyze_lmc(Lm_list *lml, Aliste nlmco, Rt_map *nlmp, Rt_map *clmp,
    int *in_nfavl)
{
	Rt_map	*lmp;
	Lm_cntl	*nlmc;

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
		return (nlmp);

	/*
	 * If this object doesn't belong to the present link-map control list
	 * then it must already have been analyzed, or it is in the process of
	 * being analyzed prior to us recursing into this analysis.  In either
	 * case, ignore the object as it's already being taken care of.
	 */
	if (nlmco != CNTL(nlmp))
		return (nlmp);

	nlmc->lc_flags |= LMC_FLG_ANALYZING;

	for (lmp = nlmp; lmp; lmp = NEXT_RT_MAP(lmp)) {
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
			Rt_map	*olmp;

			if ((olmp = elf_obj_fini(lml, lmp, clmp,
			    in_nfavl)) == NULL) {
				if (lml->lm_flags & LML_FLG_TRC_ENABLE)
					continue;
				nlmp = NULL;
				break;
			}

			/*
			 * The original link-map that captured a relocatable
			 * object is a temporary link-map, that basically acts
			 * as a place holder in the link-map list.  On
			 * completion of relocatable object processing, a new
			 * link-map is created, and switched with the place
			 * holder.  Therefore, reassign both the present
			 * link-map pointer and the return link-map pointer.
			 * The former resets this routines link-map processing,
			 * while the latter provides for later functions, like
			 * relocate_lmc(), to start processing from this new
			 * link-map.
			 */
			if (nlmp == lmp)
				nlmp = olmp;
			lmp = olmp;
		}

		DBG_CALL(Dbg_file_analyze(lmp));

		/*
		 * Establish any dependencies this object requires.
		 */
		if (LM_NEEDED(lmp)(lml, nlmco, lmp, in_nfavl) == 0) {
			if (lml->lm_flags & LML_FLG_TRC_ENABLE)
				continue;
			nlmp = NULL;
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
			load_filtees(lmp, in_nfavl);

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

	return (nlmp);
}

/*
 * Determine whether a symbol represents zero, .bss, bits.  Most commonly this
 * function is used to determine whether the data for a copy relocation refers
 * to initialized data or .bss.  If the data definition is within .bss, then the
 * data is zero filled, and as the copy destination within the executable is
 * .bss, we can skip copying zero's to zero's.
 *
 * However, if the defining object has MOVE data, it's .bss might contain
 * non-zero data, in which case copy the definition regardless.
 *
 * For backward compatibility copy relocation processing, this routine can be
 * used to determine precisely if a copy destination is a move record recipient.
 */
static int
are_bits_zero(Rt_map *dlmp, Sym *dsym, int dest)
{
	mmapobj_result_t	*mpp;
	caddr_t			daddr = (caddr_t)dsym->st_value;

	if ((FLAGS(dlmp) & FLG_RT_FIXED) == 0)
		daddr += ADDR(dlmp);

	/*
	 * Determine the segment that contains the copy definition.  Given that
	 * the copy relocation records have already been captured and verified,
	 * a segment must be found (but we add an escape clause never the less).
	 */
	if ((mpp = find_segment(daddr, dlmp)) == NULL)
		return (1);

	/*
	 * If the definition is not within .bss, indicate this is not zero data.
	 */
	if (daddr < (mpp->mr_addr + mpp->mr_offset + mpp->mr_fsize))
		return (0);

	/*
	 * If the definition is within .bss, make sure the definition isn't the
	 * recipient of a move record.  Note, we don't precisely analyze whether
	 * the address is a move record recipient, as the infrastructure to
	 * prepare for, and carry out this analysis, is probably more costly
	 * than just copying the bytes regardless.
	 */
	if ((FLAGS(dlmp) & FLG_RT_MOVE) == 0)
		return (1);

	/*
	 * However, for backward compatibility copy relocation processing, we
	 * can afford to work a little harder.  Here, determine precisely
	 * whether the destination in the executable is a move record recipient.
	 * See comments in lookup_sym_interpose(), below.
	 */
	if (dest && is_move_data(daddr))
		return (0);

	return (1);
}

/*
 * Relocate an individual object.
 */
static int
relocate_so(Lm_list *lml, Rt_map *lmp, int *relocated, int now, int *in_nfavl)
{
	APlist	*textrel = NULL;
	int	ret = 1;

	/*
	 * If we're running under ldd(1), and haven't been asked to trace any
	 * warnings, skip any actual relocation processing.
	 */
	if (((lml->lm_flags & LML_FLG_TRC_ENABLE) == 0) ||
	    (lml->lm_flags & LML_FLG_TRC_WARN)) {

		if (relocated)
			(*relocated)++;

		if ((LM_RELOC(lmp)(lmp, now, in_nfavl, &textrel) == 0) &&
		    ((lml->lm_flags & LML_FLG_TRC_ENABLE) == 0))
			ret = 0;

		/*
		 * Finally process any move data.  Note, this is carried out
		 * with ldd(1) under relocation processing too, as it can flush
		 * out move errors, and enables lari(1) to provide a true
		 * representation of the runtime bindings.
		 */
		if ((FLAGS(lmp) & FLG_RT_MOVE) &&
		    (move_data(lmp, &textrel) == 0) &&
		    ((lml->lm_flags & LML_FLG_TRC_ENABLE) == 0))
			ret = 0;
	}

	/*
	 * If a text segment was write enabled to perform any relocations or
	 * move records, then re-protect the segment by disabling writes.
	 */
	if (textrel) {
		mmapobj_result_t	*mpp;
		Aliste			idx;

		for (APLIST_TRAVERSE(textrel, idx, mpp))
			(void) set_prot(lmp, mpp, 0);
		free(textrel);
	}

	return (ret);
}

/*
 * Relocate the objects on a link-map control list.
 */
static int
_relocate_lmc(Lm_list *lml, Aliste lmco, Rt_map *nlmp, int *relocated,
    int *in_nfavl)
{
	Rt_map	*lmp;

	for (lmp = nlmp; lmp; lmp = NEXT_RT_MAP(lmp)) {
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
		if (relocate_so(lml, lmp, relocated, 0, in_nfavl) == 0)
			return (0);

		/*
		 * Indicate that the objects relocation is complete.
		 */
		FLAGS(lmp) &= ~FLG_RT_RELOCING;
		FLAGS(lmp) |= FLG_RT_RELOCED;

		/*
		 * If this object is being relocated on the main link-map list
		 * indicate that this object's init is available for harvesting.
		 * Objects that are being collected on other link-map lists
		 * will have there init availability tagged when the objects
		 * are move to the main link-map list (ie, after we know they,
		 * and their dependencies, are fully relocated and ready for
		 * use).
		 *
		 * Note, even under ldd(1) this init identification is necessary
		 * for -i (tsort) gathering.
		 */
		if (lmco == ALIST_OFF_DATA) {
			lml->lm_init++;
			lml->lm_flags |= LML_FLG_OBJADDED;
		}

		/*
		 * Determine if this object is a filter, and if a load filter
		 * flag is in effect, trigger the loading of all its filtees.
		 */
		load_filtees(lmp, in_nfavl);
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
			Rel_copy	*rcp;
			Aliste		idx2;

			for (ALIST_TRAVERSE(COPY_R(lmp), idx2, rcp)) {
				int zero;

				/*
				 * Only copy the data if the data is from
				 * a non-zero definition (ie. not .bss).
				 */
				zero = are_bits_zero(rcp->r_dlmp,
				    rcp->r_dsym, 0);
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
		COPY_S(nlmp) = NULL;
	}
	return (1);
}

int
relocate_lmc(Lm_list *lml, Aliste nlmco, Rt_map *clmp, Rt_map *nlmp,
    int *in_nfavl)
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
	 * objects to ensure any directly bound dependencies, filtees, etc.
	 * get loaded.  Although we skip the relocation, fall through to ensure
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
		lret = _relocate_lmc(lml, nlmco, nlmp, &relocated, in_nfavl);
		if ((lret == 0) && (nlmco != ALIST_OFF_DATA))
			remove_lmc(lml, clmp, nlmco, NAME(nlmp));
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
			if (relocate_so(lml, lmp, 0, 1, in_nfavl) == 0)
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
		rej1->rej_flags = rej2->rej_flags;
		if (rej2->rej_name)
			rej1->rej_name = stravl_insert(rej2->rej_name, 0, 0, 0);
		if ((rej2->rej_str) && ((rej1->rej_str =
		    stravl_insert(rej2->rej_str, 0, 0, 0)) == NULL))
			rej1->rej_str = MSG_ORIG(MSG_EMG_ENOMEM);
	}
}

/*
 * Helper routine for is_so_matched() that consolidates matching a path name,
 * or file name component of a link-map name.
 */
inline static int
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
 *  -	a NAME() - this is the basename of the dynamic executable that started
 *	the process, and the path name of any dependencies used by the process.
 *	Most executables are received as full path names, as exec() prepends a
 *	search $PATH to locate the executable.  However, simple file names can
 *	be received from exec() if the file is executed from the present working
 *	directory.  Regardless, ld.so.1 maintains NAME() as the basename, as
 *	this has always been the name used in diagnostics and error messages.
 *	Most dependencies are full path names, as the typical search for a
 *	dependency, say "libx.so.1", results in search paths being prepended to
 *	the name, which eventually open "/lib/libx.so.1".  However, relative
 *	path names can be supplied as dependencies, e.g. dlopen("../libx.so.1").
 *
 *  -	a PATHNAME() - this is the fully resolved path name of the object.  This
 * 	name will differ from NAME() for all dynamic executables, and may differ
 *	from the NAME() of dependencies, if the dependency is not a full path
 * 	name, or the dependency resolves to a symbolic link.
 *
 *  -	an ALIAS() name - these are alternative names by which the object has
 *	been found, ie. when dependencies are loaded through a variety of
 *	different symbolic links.
 *
 * The name pattern matching can differ depending on whether we are looking
 * for a full path name (path != 0), or a simple file name (path == 0).  Full
 * path names typically match NAME() or PATHNAME() entries.
 *
 * For all full path name searches, the link-map names are taken as is.  For
 * simple file name searches, only the file name component of any link-map
 * names are used for comparison.
 */
inline static Rt_map *
is_so_matched(Rt_map *lmp, const char *name, int path)
{
	Aliste		idx;
	const char	*cp;

	if (_is_so_matched(name, NAME(lmp), path) == 0)
		return (lmp);

	if (PATHNAME(lmp) != NAME(lmp)) {
		if (_is_so_matched(name, PATHNAME(lmp), path) == 0)
			return (lmp);
	}

	for (APLIST_TRAVERSE(ALIAS(lmp), idx, cp)) {
		if (_is_so_matched(name, cp, path) == 0)
			return (lmp);
	}

	return (NULL);
}

/*
 * Files are opened by ld.so.1 to satisfy dependencies, filtees and dlopen()
 * requests.  Each request investigates the file based upon the callers
 * environment.  Once a full path name has been established, the following
 * checks are made:
 *
 *  -	does the path exist in the link-map lists FullPathNode AVL tree?  if
 *	so, the file is already loaded, and its associated link-map pointer
 *	is returned.
 *  -	does the path exist in the not-found AVL tree?  if so, this path has
 *	already been determined to not exist, and a failure is returned.
 *  -	a device/inode check, to ensure the same file isn't mapped multiple
 *	times through different paths.  See file_open().
 *
 * However, there are cases where a test for an existing file name needs to be
 * carried out, such as dlopen(NOLOAD) requests, dldump() requests, and as a
 * final fallback to dependency loading.  These requests are handled by
 * is_so_loaded().
 *
 * A traversal through the callers link-map list is carried out, and from each
 * link-map, a comparison is made against all of the various names by which the
 * object has been referenced.  is_so_matched() is used to compare the link-map
 * names against the name being searched for.  Whether the search name is a full
 * path name or a simple file name, governs what comparisons are made.
 *
 * A full path name, which is a fully resolved path name that starts with a "/"
 * character, or a relative path name that includes a "/" character, must match
 * the link-map names exactly.  A simple file name, which is any name *not*
 * containing a "/" character, are matched against the file name component of
 * any link-map names.
 */
Rt_map *
is_so_loaded(Lm_list *lml, const char *name, int *in_nfavl)
{
	Rt_map		*lmp;
	avl_index_t	where;
	Lm_cntl		*lmc;
	Aliste		idx;
	int		path = 0;

	/*
	 * If the name is a full path name, first determine if the path name is
	 * registered on the FullPathNode AVL, or not-found AVL trees.
	 */
	if (name[0] == '/') {
		uint_t	hash = sgs_str_hash(name);

		if (((lmp = fpavl_recorded(lml, name, hash, &where)) != NULL) &&
		    ((FLAGS(lmp) & (FLG_RT_OBJECT | FLG_RT_DELETE)) == 0))
			return (lmp);

		if (pnavl_recorded(&nfavl, name, hash, NULL)) {
			/*
			 * For dlopen() and dlsym() fall backs, indicate that
			 * a registered not-found path has indicated that this
			 * object does not exist.
			 */
			if (in_nfavl)
				(*in_nfavl)++;
			return (NULL);
		}
	}

	/*
	 * Determine whether the name is a simple file name, or a path name.
	 */
	if (strchr(name, '/'))
		path++;

	/*
	 * Loop through the callers link-map lists.
	 */
	for (ALIST_TRAVERSE(lml->lm_lists, idx, lmc)) {
		for (lmp = lmc->lc_head; lmp; lmp = NEXT_RT_MAP(lmp)) {
			if (FLAGS(lmp) & (FLG_RT_OBJECT | FLG_RT_DELETE))
				continue;

			if (is_so_matched(lmp, name, path))
				return (lmp);
		}
	}
	return (NULL);
}

/*
 * Walk the toxic path list and determine if the object in question has violated
 * the toxic path. When evaluating the toxic path we need to ensure that we
 * match any path that's a subdirectory of a listed entry. In other words if
 * /foo/bar is toxic, something in /foo/bar/baz/ is no good. However, we need to
 * ensure that we don't mark /foo/barbaz/ as bad.
 */
static int
is_load_toxic(Lm_list *lml, Rt_map *nlmp)
{
	const char	*fpath = PATHNAME(nlmp);
	size_t		flen = strlen(fpath);
	Pdesc 		*pdp;
	Aliste 		idx;

	for (ALIST_TRAVERSE(rpl_toxdirs, idx, pdp)) {
		if (pdp->pd_plen == 0)
			continue;

		if (strncmp(pdp->pd_pname, fpath, pdp->pd_plen) == 0) {
			if (pdp->pd_pname[pdp->pd_plen-1] != '/') {
				/*
				 * Path didn't end in a /, make sure
				 * we're at a directory boundary
				 * nonetheless.
				 */
				if (flen > pdp->pd_plen &&
				    fpath[pdp->pd_plen] == '/')
					return (1);
				continue;
			}
			return (1);
		}
	}

	return (0);
}

/*
 * Tracing is enabled by the LD_TRACE_LOADED_OPTIONS environment variable which
 * is normally set from ldd(1).  For each link map we load, print the load name
 * and the full pathname of the associated object.
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
		    conv_reject_desc(rej, &rej_buf, M_MACH));
		if (rej->rej_name)
			path = rej->rej_name;
		reject = (char *)_reject;

		/*
		 * Was an alternative pathname defined (from a configuration
		 * file).
		 */
		if (rej->rej_flags & FLG_REJ_ALTER)
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
 * full path names (NAME() and possibly PATHNAME()) are maintained on the
 * FullPathNode AVL tree, and thus would have been matched by fpavl_loaded()
 * during file_open().
 */
int
append_alias(Rt_map *lmp, const char *str, int *added)
{
	const char	*cp;
	Aliste		idx;

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
	if (((cp = stravl_insert(str, 0, 0, 0)) == NULL) ||
	    (aplist_append(&ALIAS(lmp), cp, AL_CNT_ALIAS) == NULL))
		return (0);

	if (added)
		*added = 1;
	return (1);
}

/*
 * Determine whether a file is already loaded by comparing device and inode
 * values.
 */
static Rt_map *
is_devinode_loaded(rtld_stat_t *status, Lm_list *lml, const char *name,
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
		Lm_list	*lml;

		for (APLIST_TRAVERSE(dynlm_list, idx, lml)) {
			Rt_map	*nlmp = lml->lm_head;

			if (nlmp && ((FLAGS(nlmp) &
			    (FLG_RT_AUDIT | FLG_RT_DELETE)) == FLG_RT_AUDIT) &&
			    (STDEV(nlmp) == status->st_dev) &&
			    (STINO(nlmp) == status->st_ino))
				return (nlmp);
		}
		return (NULL);
	}

	/*
	 * If the file has been found determine from the new files status
	 * information if this file is actually linked to one we already have
	 * mapped.  This catches symlink names not caught by is_so_loaded().
	 */
	for (ALIST_TRAVERSE(lml->lm_lists, idx, lmc)) {
		Rt_map	*nlmp;

		for (nlmp = lmc->lc_head; nlmp; nlmp = NEXT_RT_MAP(nlmp)) {
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
	return (NULL);
}

/*
 * Generate any error messages indicating a file could not be found.  When
 * preloading or auditing a secure application, it can be a little more helpful
 * to indicate that a search of secure directories has failed, so adjust the
 * messages accordingly.
 */
void
file_notfound(Lm_list *lml, const char *name, Rt_map *clmp, uint_t flags,
    Rej_desc *rej)
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
		    conv_reject_desc(rej, &rej_buf, M_MACH));
		return;
	}

	if (secure)
		eprintf(lml, ERR_FATAL, MSG_INTL(MSG_SEC_OPEN), name);
	else
		eprintf(lml, ERR_FATAL, MSG_INTL(MSG_SYS_OPEN), name,
		    strerror(ENOENT));
}

static int
file_open(int err, Lm_list *lml, Rt_map *clmp, uint_t flags, Fdesc *fdp,
    Rej_desc *rej, int *in_nfavl)
{
	rtld_stat_t	status;
	Rt_map		*nlmp;
	avl_index_t	nfavlwhere = 0;
	const char	*oname = fdp->fd_oname, *nname = fdp->fd_nname;
	uint_t		hash = sgs_str_hash(nname);


	if ((nname = stravl_insert(fdp->fd_nname, hash, 0, 0)) == NULL)
		return (0);
	fdp->fd_nname = nname;

	if ((err == 0) && (fdp->fd_flags & FLG_FD_ALTER))
		DBG_CALL(Dbg_file_config_obj(lml, oname, 0, nname));

	/*
	 * If we're dealing with a full pathname, determine whether this
	 * pathname is already known.  Other pathnames fall through to the
	 * dev/inode check, as even though the pathname may look the same as
	 * one previously used, the process may have changed directory.
	 */
	if ((err == 0) && (nname[0] == '/')) {
		if ((nlmp = fpavl_recorded(lml, nname, hash,
		    &(fdp->fd_avlwhere))) != NULL) {
			fdp->fd_lmp = nlmp;
			return (1);
		}
		if (pnavl_recorded(&nfavl, nname, hash, &nfavlwhere)) {
			/*
			 * For dlopen() and dlsym() fall backs, indicate that
			 * a registered not-found path has indicated that this
			 * object does not exist.  If this path has been
			 * constructed as part of expanding a CAPABILITY
			 * directory, this is a silent failure, where no
			 * rejection message is created.
			 */
			if (in_nfavl)
				(*in_nfavl)++;
			return (0);
		}
	}

	if ((err == 0) && ((rtld_stat(nname, &status)) != -1)) {
		char	path[PATH_MAX];
		int	fd, size, added;

		/*
		 * If this path has been constructed as part of expanding a
		 * CAPABILITY directory, ignore any subdirectories.  As this
		 * is a silent failure, no rejection message is created.  For
		 * any other reference that expands to a directory, fall
		 * through to construct a meaningful rejection message.
		 */
		if ((flags & FLG_RT_CAP) &&
		    ((status.st_mode & S_IFMT) == S_IFDIR))
			return (0);

		/*
		 * If this is a directory (which can't be mmap()'ed) generate a
		 * precise error message.
		 */
		if ((status.st_mode & S_IFMT) == S_IFDIR) {
			rej->rej_name = nname;
			if (fdp->fd_flags & FLG_FD_ALTER)
				rej->rej_flags = FLG_REJ_ALTER;
			rej->rej_type = SGS_REJ_STR;
			rej->rej_str = strerror(EISDIR);
			DBG_CALL(Dbg_file_rejected(lml, rej, M_MACH));
			return (0);
		}

		/*
		 * Resolve the filename and determine whether the resolved name
		 * is already known.  Typically, the previous fpavl_loaded()
		 * will have caught this, as both NAME() and PATHNAME() for a
		 * link-map are recorded in the FullPathNode AVL tree.  However,
		 * instances exist where a file can be replaced (loop-back
		 * mounts, bfu, etc.), and reference is made to the original
		 * file through a symbolic link.  By checking the pathname here,
		 * we don't fall through to the dev/inode check and conclude
		 * that a new file should be loaded.
		 */
		if ((nname[0] == '/') &&
		    ((size = resolvepath(nname, path, (PATH_MAX - 1))) > 0)) {
			path[size] = '\0';

			fdp->fd_flags |= FLG_FD_RESOLVED;

			if (strcmp(nname, path)) {
				if ((nlmp =
				    fpavl_recorded(lml, path, 0, 0)) != NULL) {
					added = 0;

					if (append_alias(nlmp, nname,
					    &added) == 0)
						return (0);
					/* BEGIN CSTYLED */
					if (added)
					    DBG_CALL(Dbg_file_skip(LIST(clmp),
						NAME(nlmp), nname));
					/* END CSTYLED */
					fdp->fd_lmp = nlmp;
					return (1);
				}

				/*
				 * If this pathname hasn't been loaded, save
				 * the resolved pathname so that it doesn't
				 * have to be recomputed as part of fullpath()
				 * processing.
				 */
				if ((fdp->fd_pname = stravl_insert(path, 0,
				    (size + 1), 0)) == NULL)
					return (0);
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
				 * a new name alias.  Insert any alias full path
				 * name in the FullPathNode AVL tree.
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
			fdp->fd_lmp = nlmp;
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
			/*
			 * Map the object.  A successful return indicates that
			 * the object is appropriate for ld.so.1 processing.
			 */
			fdp->fd_ftp = map_obj(lml, fdp, status.st_size, nname,
			    fd, rej);
			(void) close(fd);

			if (fdp->fd_ftp != NULL) {
				fdp->fd_dev = status.st_dev;
				fdp->fd_ino = status.st_ino;
				return (1);
			}
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
	 * Regardless of error, duplicate and record any full path names that
	 * can't be used on the "not-found" AVL tree.
	 */
	if (nname[0] == '/')
		nfavl_insert(nname, nfavlwhere);

	/*
	 * Indicate any rejection.
	 */
	if (rej->rej_type) {
		rej->rej_name = nname;
		if (fdp->fd_flags & FLG_FD_ALTER)
			rej->rej_flags = FLG_REJ_ALTER;
		DBG_CALL(Dbg_file_rejected(lml, rej, M_MACH));
	}
	return (0);
}

/*
 * Find a full pathname (it contains a "/").
 */
int
find_path(Lm_list *lml, Rt_map *clmp, uint_t flags, Fdesc *fdp, Rej_desc *rej,
    int *in_nfavl)
{
	const char	*oname = fdp->fd_oname;
	int		err = 0;

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

				fdp->fd_flags |= FLG_FD_ALTER;
				fdp->fd_nname = aname;

				/*
				 * Attempt to open the alternative path.  If
				 * this fails, and the alternative is flagged
				 * as optional, fall through to open the
				 * original path.
				 */
				DBG_CALL(Dbg_libs_found(lml, aname,
				    FLG_FD_ALTER));
				ret = file_open(0, lml, clmp, flags, fdp,
				    rej, in_nfavl);
				if (ret || ((obj->co_flags &
				    RTC_OBJ_OPTINAL) == 0))
					return (ret);

				fdp->fd_flags &= ~FLG_FD_ALTER;
			}
		}
	}
	DBG_CALL(Dbg_libs_found(lml, oname, 0));
	fdp->fd_nname = oname;
	return (file_open(err, lml, clmp, flags, fdp, rej, in_nfavl));
}

/*
 * Find a simple filename (it doesn't contain a "/").
 */
static int
_find_file(Lm_list *lml, Rt_map *clmp, uint_t flags, Fdesc *fdp, Rej_desc *rej,
    Pdesc *pdp, int aflag, int *in_nfavl)
{
	const char	*nname = fdp->fd_nname;

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
	if ((lml->lm_tflags | AFLAGS(clmp)) & LML_TFLG_AUD_OBJSEARCH) {
		char	*aname;

		if ((aname = audit_objsearch(clmp, nname,
		    (pdp->pd_flags & LA_SER_MASK))) == NULL) {
			DBG_CALL(Dbg_audit_terminate(lml, nname));
			return (0);
		}

		if (aname != nname) {
			fdp->fd_flags &= ~FLG_FD_SLASH;
			fdp->fd_nname = aname;
		}
	}
	return (file_open(0, lml, clmp, flags, fdp, rej, in_nfavl));
}

static int
find_file(Lm_list *lml, Rt_map *clmp, uint_t flags, Fdesc *fdp, Rej_desc *rej,
    Pdesc *pdp, Word *strhash, int *in_nfavl)
{
	static Rtc_obj	Obj = { 0 };
	Rtc_obj		*dobj;
	const char	*oname = fdp->fd_oname;
	size_t		olen = strlen(oname);

	if (pdp->pd_pname == NULL)
		return (0);
	if (pdp->pd_info) {
		dobj = (Rtc_obj *)pdp->pd_info;
		if ((dobj->co_flags &
		    (RTC_OBJ_NOEXIST | RTC_OBJ_ALTER)) == RTC_OBJ_NOEXIST)
			return (0);
	} else
		dobj = NULL;

	/*
	 * If configuration information exists see if this directory/file
	 * combination exists.
	 */
	if ((rtld_flags & RT_FL_DIRCFG) &&
	    ((dobj == NULL) || (dobj->co_id != 0))) {
		Rtc_obj		*fobj;
		const char	*aname = NULL;

		/*
		 * If this object descriptor has not yet been searched for in
		 * the configuration file go find it.
		 */
		if (dobj == NULL) {
			dobj = elf_config_ent(pdp->pd_pname,
			    (Word)elf_hash(pdp->pd_pname), 0, 0);
			if (dobj == NULL)
				dobj = &Obj;
			pdp->pd_info = (void *)dobj;

			if ((dobj->co_flags & (RTC_OBJ_NOEXIST |
			    RTC_OBJ_ALTER)) == RTC_OBJ_NOEXIST)
				return (0);
		}

		/*
		 * If we found a directory search for the file.
		 */
		if (dobj->co_id != 0) {
			if (*strhash == NULL)
				*strhash = (Word)elf_hash(oname);
			fobj = elf_config_ent(oname, *strhash,
			    dobj->co_id, &aname);

			/*
			 * If this object specifically does not exist, or the
			 * object can't be found in a know-all-entries
			 * directory, continue looking.  If the object does
			 * exist determine if an alternative object exists.
			 */
			if (fobj == NULL) {
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

					fdp->fd_flags |= FLG_FD_ALTER;
					fdp->fd_nname = aname;

					/*
					 * Attempt to open the alternative path.
					 * If this fails, and the alternative is
					 * flagged as optional, fall through to
					 * open the original path.
					 */
					ret = _find_file(lml, clmp, flags, fdp,
					    rej, pdp, 1, in_nfavl);
					if (ret || ((fobj->co_flags &
					    RTC_OBJ_OPTINAL) == 0))
						return (ret);

					fdp->fd_flags &= ~FLG_FD_ALTER;
				}
			}
		}
	}

	/*
	 * Protect ourselves from building an invalid pathname.
	 */
	if ((olen + pdp->pd_plen + 1) >= PATH_MAX) {
		eprintf(lml, ERR_FATAL, MSG_INTL(MSG_SYS_OPEN), oname,
		    strerror(ENAMETOOLONG));
			return (0);
	}
	if ((fdp->fd_nname = (LM_GET_SO(clmp)(pdp->pd_pname, oname,
	    pdp->pd_plen, olen))) == NULL)
		return (0);

	return (_find_file(lml, clmp, flags, fdp, rej, pdp, 0, in_nfavl));
}

static Fct	*Vector[] = {
	&elf_fct,
#ifdef	A_OUT
	&aout_fct,
#endif
	0
};

/*
 * Remap the first page of a file to provide a better diagnostic as to why
 * an mmapobj(2) operation on this file failed.  Sadly, mmapobj(), and all
 * system calls for that matter, only pass back a generic failure in errno.
 * Hopefully one day this will be improved, but in the mean time we repeat
 * the kernels ELF verification to try and provide more detailed information.
 */
static int
map_fail(Fdesc *fdp, size_t fsize, const char *name, int fd, Rej_desc *rej)
{
	caddr_t	addr;
	int	vnum;
	size_t	size;

	/*
	 * Use the original file size to determine what to map, and catch the
	 * obvious error of a zero sized file.
	 */
	if (fsize == 0) {
		rej->rej_type = SGS_REJ_UNKFILE;
		return (1);
	} else if (fsize < syspagsz)
		size = fsize;
	else
		size = syspagsz;

	if ((addr = mmap(0, size, PROT_READ, MAP_PRIVATE, fd, 0)) == MAP_FAILED)
		return (0);

	rej->rej_type = 0;

	/*
	 * Validate the file against each supported file type.  Should a
	 * characteristic of the file be found invalid for this platform, a
	 * rejection message will have been recorded.
	 */
	for (vnum = 0; Vector[vnum]; vnum++) {
		if (((Vector[vnum]->fct_verify_file)(addr, size,
		    fdp, name, rej) == 0) && rej->rej_type)
			break;
	}

	/*
	 * If no rejection message has been recorded, then this is simply an
	 * unknown file type.
	 */
	if (rej->rej_type == 0)
		rej->rej_type = SGS_REJ_UNKFILE;

	(void) munmap(addr, size);
	return (1);
}

/*
 * Unmap a file.
 */
void
unmap_obj(mmapobj_result_t *mpp, uint_t mapnum)
{
	uint_t	num;

	for (num = 0; num < mapnum; num++) {
		/* LINTED */
		(void) munmap((void *)(uintptr_t)mpp[num].mr_addr,
		    mpp[num].mr_msize);
	}
	cnt_unmap++;
}

/*
 * Map a file.
 */
Fct *
map_obj(Lm_list *lml, Fdesc *fdp, size_t fsize, const char *name, int fd,
    Rej_desc *rej)
{
	static mmapobj_result_t	*smpp = NULL;
	static uint_t		smapnum;
	mmapobj_result_t	*mpp;
	uint_t			mnum, mapnum, mflags;
	void			*padding;

	/*
	 * Allocate an initial mapping array.  The initial size should be large
	 * enough to handle the normal ELF objects we come across.
	 */
	if (smpp == NULL) {
		smpp = malloc(sizeof (mmapobj_result_t) * MMAPFD_NUM);
		if (smpp == NULL)
			return (NULL);
		smapnum = MMAPFD_NUM;
	}

	/*
	 * If object padding is required, set the necessary flags.
	 */
	if (r_debug.rtd_objpad) {
		mflags = MMOBJ_INTERPRET | MMOBJ_PADDING;
		padding = &r_debug.rtd_objpad;
	} else {
		mflags = MMOBJ_INTERPRET;
		padding = NULL;
	}

	/*
	 * Map the file.  If the number of mappings required by this file
	 * exceeds the present mapping structure, an error indicating the
	 * return data is too big is returned.  Bail on any other error.
	 */
	mapnum = smapnum;
	if (mmapobj(fd, mflags, smpp, &mapnum, padding) == -1) {
		if (errno != E2BIG) {
			int	err = errno;

			/*
			 * An unsupported error indicates that there's something
			 * incompatible with this ELF file, and the process that
			 * is already running.  Map the first page of the file
			 * and see if we can generate a better error message.
			 */
			if ((errno == ENOTSUP) && map_fail(fdp, fsize, name,
			    fd, rej))
				return (NULL);

			rej->rej_type = SGS_REJ_STR;
			rej->rej_str = strerror(err);
			return (NULL);
		}

		/*
		 * The mapping requirement exceeds the present mapping
		 * structure, however the number of mapping required is
		 * available in the mapping number.
		 */
		free((void *)smpp);
		if ((smpp = malloc(sizeof (mmapobj_result_t) * mapnum)) == NULL)
			return (NULL);
		smapnum = mapnum;

		/*
		 * With the appropriate mapping structure, try the mapping
		 * request again.
		 */
		if (mmapobj(fd, mflags, smpp, &mapnum, padding) == -1) {
			rej->rej_type = SGS_REJ_STR;
			rej->rej_str = strerror(errno);
			return (NULL);
		}
	}
	ASSERT(mapnum != 0);

	/*
	 * Traverse the mappings in search of a file type ld.so.1 can process.
	 * If the file type is verified as one ld.so.1 can process, retain the
	 * mapping information, and the number of mappings this object uses,
	 * and clear the static mapping pointer for the next map_obj() use of
	 * mmapobj().
	 */
	DBG_CALL(Dbg_file_mmapobj(lml, name, smpp, mapnum));
	cnt_map++;

	for (mnum = 0, mpp = smpp; mnum < mapnum; mnum++, mpp++) {
		uint_t	flags = (mpp->mr_flags & MR_TYPE_MASK);
		Fct	*fptr = NULL;

		if (flags == MR_HDR_ELF) {
			fptr = elf_verify((mpp->mr_addr + mpp->mr_offset),
			    mpp->mr_fsize, fdp, name, rej);
		}
#ifdef	A_OUT
		if (flags == MR_HDR_AOUT) {
			fptr = aout_verify((mpp->mr_addr + mpp->mr_offset),
			    mpp->mr_fsize, fdp, name, rej);
		}
#endif
		if (fptr) {
			fdp->fd_mapn = mapnum;
			fdp->fd_mapp = smpp;

			smpp = NULL;

			return (fptr);
		}
	}

	/*
	 * If the mapped file is inappropriate, indicate that the file type is
	 * unknown, and free the mapping.
	 */
	if (rej->rej_type == 0)
		rej->rej_type = SGS_REJ_UNKFILE;
	unmap_obj(smpp, mapnum);

	return (NULL);
}

/*
 * A unique file has been opened.  Create a link-map to represent it, and
 * process the various names by which it can be referenced.
 */
Rt_map *
load_file(Lm_list *lml, Aliste lmco, Rt_map *clmp, Fdesc *fdp, int *in_nfavl)
{
	mmapobj_result_t	*fpmpp = NULL, *fmpp = NULL, *lpmpp, *lmpp;
	mmapobj_result_t	*hmpp, *mpp, *ompp = fdp->fd_mapp;
	uint_t			mnum, omapnum = fdp->fd_mapn;
	const char		*nname = fdp->fd_nname;
	Rt_map			*nlmp;
	Ehdr			*ehdr = NULL;

	/*
	 * Traverse the mappings for the input file to capture generic mapping
	 * information, and create a link-map to represent the file.
	 */
	for (mnum = 0, mpp = ompp; mnum < omapnum; mnum++, mpp++) {
		uint_t	flags = (mpp->mr_flags & MR_TYPE_MASK);

		/*
		 * Keep track of the first and last mappings that may include
		 * padding.
		 */
		if (fpmpp == NULL)
			fpmpp = mpp;
		lpmpp = mpp;

		/*
		 * Keep track of the first and last mappings that do not include
		 * padding.
		 */
		if (flags != MR_PADDING) {
			if (fmpp == NULL)
				fmpp = mpp;
			lmpp = mpp;
		}
		if (flags == MR_HDR_ELF) {
			/* LINTED */
			ehdr = (Ehdr *)(mpp->mr_addr + mpp->mr_offset);
			hmpp = mpp;
		} else if (flags == MR_HDR_AOUT)
			hmpp = mpp;
	}

	/*
	 * The only ELF files we can handle are ET_EXEC, ET_DYN, and ET_REL.
	 *
	 * ET_REL must be processed by ld(1) to create an in-memory ET_DYN.
	 * The initial processing carried out by elf_obj_file() creates a
	 * temporary link-map, that acts as a place holder, until the objects
	 * processing is finished with elf_obj_fini().
	 */
	if (ehdr && (ehdr->e_type == ET_REL)) {
		if ((nlmp = elf_obj_file(lml, lmco, clmp, nname, hmpp, ompp,
		    omapnum)) == NULL)
			return (nlmp);
	} else {
		Addr	addr;
		size_t	msize;

		/*
		 * The size of the total reservation, and the padding range,
		 * are a historic artifact required by debuggers.  Although
		 * these values express the range of the associated mappings,
		 * there can be holes between segments (in which small objects
		 * could be mapped).  Anyone who needs to verify offsets
		 * against segments should analyze all the object mappings,
		 * rather than relying on these address ranges.
		 */
		addr = (Addr)(hmpp->mr_addr + hmpp->mr_offset);
		msize = lmpp->mr_addr + lmpp->mr_msize - fmpp->mr_addr;

		if ((nlmp = ((fdp->fd_ftp)->fct_new_lmp)(lml, lmco, fdp, addr,
		    msize, NULL, clmp, in_nfavl)) == NULL)
			return (NULL);

		/*
		 * Save generic mapping information.
		 */
		MMAPS(nlmp) = ompp;
		MMAPCNT(nlmp) = omapnum;
		PADSTART(nlmp) = (ulong_t)fpmpp->mr_addr;
		PADIMLEN(nlmp) = lpmpp->mr_addr + lpmpp->mr_msize -
		    fpmpp->mr_addr;
	}

	/*
	 * Save the dev/inode information for later comparisons, and identify
	 * this as a new object.
	 */
	STDEV(nlmp) = fdp->fd_dev;
	STINO(nlmp) = fdp->fd_ino;
	FLAGS(nlmp) |= FLG_RT_NEWLOAD;

	/*
	 * If this is ELF relocatable object, we're done for now.
	 */
	if (ehdr && (ehdr->e_type == ET_REL))
		return (nlmp);

	/*
	 * Insert the names of this link-map into the FullPathNode AVL tree.
	 * Save both the NAME() and PATHNAME() if the names differ.
	 */
	(void) fullpath(nlmp, fdp);

	if ((NAME(nlmp)[0] == '/') && (fpavl_insert(lml, nlmp, NAME(nlmp),
	    fdp->fd_avlwhere) == 0)) {
		remove_so(lml, nlmp, clmp);
		return (NULL);
	}
	if (((NAME(nlmp)[0] != '/') || (NAME(nlmp) != PATHNAME(nlmp))) &&
	    (fpavl_insert(lml, nlmp, PATHNAME(nlmp), 0) == 0)) {
		remove_so(lml, nlmp, clmp);
		return (NULL);
	}

	/*
	 * If this is a secure application, record any full path name directory
	 * in which this dependency has been found.  This directory can be
	 * deemed safe (as we've already found a dependency here).  This
	 * recording provides a fall-back should another objects $ORIGIN
	 * definition expands to this directory, an expansion that would
	 * ordinarily be deemed insecure.
	 */
	if (rtld_flags & RT_FL_SECURE) {
		if (NAME(nlmp)[0] == '/')
			spavl_insert(NAME(nlmp));
		if ((NAME(nlmp) != PATHNAME(nlmp)) &&
		    (PATHNAME(nlmp)[0] == '/'))
			spavl_insert(PATHNAME(nlmp));
	}

	/*
	 * If we're processing an alternative object reset the original name
	 * for possible $ORIGIN processing.
	 */
	if (fdp->fd_flags & FLG_FD_ALTER) {
		const char	*odir, *ndir;
		size_t		olen;

		FLAGS(nlmp) |= FLG_RT_ALTER;

		/*
		 * If we were given a pathname containing a slash then the
		 * original name is still in oname.  Otherwise the original
		 * directory is in dir->p_name (which is all we need for
		 * $ORIGIN).
		 */
		if (fdp->fd_flags & FLG_FD_SLASH) {
			char	*ofil;

			odir = fdp->fd_oname;
			ofil = strrchr(fdp->fd_oname, '/');
			olen = ofil - odir + 1;
		} else {
			odir = fdp->fd_odir;
			olen = strlen(odir) + 1;
		}
		if ((ndir = stravl_insert(odir, 0, olen, 1)) == NULL) {
			remove_so(lml, nlmp, clmp);
			return (NULL);
		}
		ORIGNAME(nlmp) = ndir;
		DIRSZ(nlmp) = --olen;
	}

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
load_so(Lm_list *lml, Aliste lmco, Rt_map *clmp, uint_t flags,
    Fdesc *fdp, Rej_desc *rej, int *in_nfavl)
{
	const char	*oname = fdp->fd_oname;
	Pdesc		*pdp;

	/*
	 * If this path name hasn't already been identified as containing a
	 * slash, check the path name.  Most paths have been constructed
	 * through appending a file name to a search path, and/or have been
	 * inspected by expand(), and thus have a slash.  However, we can
	 * receive path names via auditors or configuration files, and thus
	 * an evaluation here catches these instances.
	 */
	if ((fdp->fd_flags & FLG_FD_SLASH) == 0) {
		const char	*str;

		for (str = oname; *str; str++) {
			if (*str == '/') {
				fdp->fd_flags |= FLG_FD_SLASH;
				break;
			}
		}
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
	 * If this path resulted from a $CAPABILITY specification, then the
	 * best capability object has already been establish, and is available
	 * in the calling file descriptor.  Perform some minor book-keeping so
	 * that we can fall through into common code.
	 */
	if (flags & FLG_RT_CAP) {
		/*
		 * If this object is already loaded, we're done.
		 */
		if (fdp->fd_lmp)
			return (fdp->fd_lmp);

		/*
		 * Obtain the avl index for this object.
		 */
		(void) fpavl_recorded(lml, fdp->fd_nname, 0,
		    &(fdp->fd_avlwhere));

	} else if (fdp->fd_flags & FLG_FD_SLASH) {
		Rej_desc	_rej = { 0 };

		if (find_path(lml, clmp, flags, fdp, &_rej, in_nfavl) == 0) {
			rejection_inherit(rej, &_rej);
			return (NULL);
		}

		/*
		 * If this object is already loaded, we're done.
		 */
		if (fdp->fd_lmp)
			return (fdp->fd_lmp);

	} else {
		/*
		 * No '/' - for each directory on list, make a pathname using
		 * that directory and filename and try to open that file.
		 */
		Spath_desc	sd = { search_rules, NULL, 0 };
		Word		strhash = 0;
		int		found = 0;

		/*
		 * Traverse the search path lists, creating full pathnames and
		 * attempt to load each path.
		 */
		for (pdp = get_next_dir(&sd, clmp, flags); pdp;
		    pdp = get_next_dir(&sd, clmp, flags)) {
			Rej_desc	_rej = { 0 };
			Fdesc		fd = { 0 };

			/*
			 * Under debugging, duplicate path name entries are
			 * tagged but remain part of the search path list so
			 * that they can be diagnosed under "unused" processing.
			 * Skip these entries, as this path would have already
			 * been attempted.
			 */
			if (pdp->pd_flags & PD_FLG_DUPLICAT)
				continue;

			fd = *fdp;

			/*
			 * Try and locate this file.  Make sure to clean up
			 * any rejection information should the file have
			 * been found, but not appropriate.
			 */
			if (find_file(lml, clmp, flags, &fd, &_rej, pdp,
			    &strhash, in_nfavl) == 0) {
				rejection_inherit(rej, &_rej);
				continue;
			}

			/*
			 * Indicate that this search path has been used.  If
			 * this is an LD_LIBRARY_PATH setting, ignore any use
			 * by ld.so.1 itself.
			 */
			if (((pdp->pd_flags & LA_SER_LIBPATH) == 0) ||
			    ((lml->lm_flags & LML_FLG_RTLDLM) == 0))
				pdp->pd_flags |= PD_FLG_USED;

			/*
			 * If this object is already loaded, we're done.
			 */
			*fdp = fd;
			if (fdp->fd_lmp)
				return (fdp->fd_lmp);

			fdp->fd_odir = pdp->pd_pname;
			found = 1;
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
		if (found == 0)
			return (is_so_loaded(lml, oname, in_nfavl));
	}

	/*
	 * Trace that this successfully opened file is about to be processed.
	 * Note, as part of processing a family of hardware capabilities filtees
	 * a number of candidates may have been opened and mapped to determine
	 * their capability requirements.  At this point we've decided which
	 * of the candidates to use.
	 */
	if (lml->lm_flags & LML_FLG_TRC_ENABLE) {
		trace_so(clmp, 0, fdp->fd_oname, fdp->fd_nname,
		    (fdp->fd_flags & FLG_FD_ALTER), 0);
	}

	/*
	 * Finish mapping the file and return the link-map descriptor.
	 */
	return (load_file(lml, lmco, clmp, fdp, in_nfavl));
}

/*
 * Trace an attempt to load an object, and seed the originating name.
 */
const char *
load_trace(Lm_list *lml, Pdesc *pdp, Rt_map *clmp, Fdesc *fdp)
{
	const char	*name = pdp->pd_pname;

	DBG_CALL(Dbg_libs_find(lml, name));

	/*
	 * First generate any ldd(1) diagnostics.
	 */
	if ((lml->lm_flags & (LML_FLG_TRC_VERBOSE | LML_FLG_TRC_SEARCH)) &&
	    ((FLAGS1(clmp) & FL1_RT_LDDSTUB) == 0))
		(void) printf(MSG_INTL(MSG_LDD_FIL_FIND), name, NAME(clmp));

	/*
	 * Propagate any knowledge of a slash within the path name.
	 */
	if (pdp->pd_flags & PD_FLG_PNSLASH)
		fdp->fd_flags |= FLG_FD_SLASH;

	/*
	 * If we're being audited tell any audit libraries of the file we're
	 * about to go search for.
	 */
	if (aud_activity ||
	    ((lml->lm_tflags | AFLAGS(clmp)) & LML_TFLG_AUD_ACTIVITY))
		audit_activity(clmp, LA_ACT_ADD);

	if ((lml->lm_tflags | AFLAGS(clmp)) & LML_TFLG_AUD_OBJSEARCH) {
		char	*aname;

		/*
		 * The auditor can indicate that this object should be ignored.
		 */
		if ((aname =
		    audit_objsearch(clmp, name, LA_SER_ORIG)) == NULL) {
			DBG_CALL(Dbg_audit_terminate(lml, name));
			return (NULL);
		}

		if (name != aname) {
			fdp->fd_flags &= ~FLG_FD_SLASH;
			name = aname;
		}
	}
	fdp->fd_oname = name;
	return (name);
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
	Aliste		idx1;
	Grp_hdl		*ghp;
	int		promote;
	uint_t		rdflags;

	/*
	 * If this dependency is associated with a toxic path, then we must
	 * honor the user's request to die.
	 */
	if (is_load_toxic(lml, nlmp) != 0) {
		eprintf(lml, ERR_FATAL, MSG_INTL(MSG_TOXIC_FILE),
		    PATHNAME(nlmp));
		rtldexit(lml, 1);

	}

	/*
	 * If this dependency is associated with a required version ensure that
	 * the version is present in the loaded file.
	 */
	if (((rtld_flags & RT_FL_NOVERSION) == 0) && THIS_IS_ELF(clmp) &&
	    VERNEED(clmp) && (elf_verify_vers(name, clmp, nlmp) == 0))
		return (0);

	/*
	 * If this object has indicated that it should be isolated as a group
	 * (DT_FLAGS_1 contains DF_1_GROUP - object was built with -B group),
	 * or if the callers direct bindings indicate it should be isolated as
	 * a group (DYNINFO flags contains FLG_DI_GROUP - dependency following
	 * -zgroupperm), establish the appropriate mode.
	 *
	 * The intent of an object defining itself as a group is to isolate the
	 * relocation of the group within its own members, however, unless
	 * opened through dlopen(), in which case we assume dlsym() will be used
	 * to locate symbols in the new object, we still need to associate the
	 * new object with the caller so that the caller can bind to this new
	 * object.  This is equivalent to a dlopen(RTLD_GROUP) and dlsym()
	 * using the returned handle.
	 */
	if ((FLAGS(nlmp) | flags) & FLG_RT_SETGROUP) {
		nmode &= ~RTLD_WORLD;
		nmode |= RTLD_GROUP;

		/*
		 * If the object wasn't explicitly dlopen()'ed, in which case a
		 * handle would have been requested, associate the object with
		 * the parent.
		 */
		if ((flags & FLG_RT_PUBHDL) == 0)
			nmode |= RTLD_PARENT;
	}

	/*
	 * Establish new mode and flags.
	 */
	promote = update_mode(nlmp, MODE(nlmp), nmode);
	FLAGS(nlmp) |= flags;

	/*
	 * Establish the flags for any referenced dependency descriptors
	 * (Grp_desc).
	 *
	 *  -	The referenced object is available for dlsym().
	 *  -	The referenced object is available to relocate against.
	 *  -	The referenced object should have it's dependencies
	 *	added to this handle
	 */
	rdflags = (GPD_DLSYM | GPD_RELOC | GPD_ADDEPS);

	/*
	 * If we've been asked to establish a handle create one for this object.
	 * Or, if this object has already been analyzed, but this reference
	 * requires that the mode of the object be promoted, create a private
	 * handle to propagate the new modes to all this objects dependencies.
	 */
	if ((FLAGS(nlmp) & (FLG_RT_PUBHDL | FLG_RT_PRIHDL)) ||
	    (promote && (FLAGS(nlmp) & FLG_RT_ANALYZED))) {
		uint_t	oflags, hflags, cdflags = 0;

		/*
		 * Establish any flags for the handle (Grp_hdl).
		 *
		 *  -	Public handles establish dependencies between objects
		 *	that must be taken into account when dlclose()'ing
		 *	objects.  Private handles provide for collecting
		 *	dependencies, but do not affect dlclose().  Note that
		 *	a handle may already exist, but the public/private
		 *	state is set to trigger the required propagation of the
		 *	handle's flags and any dependency gathering.
		 *  -	Use of the RTLD_FIRST flag indicates that only the first
		 *	dependency on the handle (the new object) can be used
		 *	to satisfy dlsym() requests.
		 */
		if (FLAGS(nlmp) & FLG_RT_PUBHDL)
			hflags = GPH_PUBLIC;
		else
			hflags = GPH_PRIVATE;

		if (nmode & RTLD_FIRST)
			hflags |= GPH_FIRST;

		/*
		 * Establish the flags for this callers dependency descriptor
		 * (Grp_desc).
		 *
		 *  -	The creation of a public handle creates a descriptor
		 *	for the referenced object and the caller (parent).
		 *	Typically, the handle is created for dlopen() or for
		 *	filtering.  A private handle does not need to maintain
		 *	a descriptor to the parent.
		 *  -	Use of the RTLD_PARENT flag indicates that the parent
		 *	can be relocated against.
		 */
		if (FLAGS(nlmp) & FLG_RT_PUBHDL) {
			cdflags |= GPD_PARENT;
			if (nmode & RTLD_PARENT)
				cdflags |= GPD_RELOC;
		}

		/*
		 * Now that the handle flags have been established, remove any
		 * handle definition from the referenced object so that the
		 * definitions don't mistakenly get inherited by a dependency.
		 */
		oflags = FLAGS(nlmp);
		FLAGS(nlmp) &= ~(FLG_RT_PUBHDL | FLG_RT_PRIHDL);

		DBG_CALL(Dbg_file_hdl_title(DBG_HDL_ADD));
		if ((ghp = hdl_create(lml, nlmp, clmp, hflags, rdflags,
		    cdflags)) == NULL)
			return (0);

		/*
		 * Add any dependencies that are already loaded, to the handle.
		 */
		if (hdl_initialize(ghp, nlmp, nmode, promote) == 0)
			return (0);

		if (hdl)
			*hdl = ghp;

		/*
		 * If we were asked to create a public handle, we're done.
		 *
		 * If this is a private handle request, then the handle is left
		 * intact with a GPH_PRIVATE identifier.  This handle is a
		 * convenience for processing the dependencies of this object,
		 * but does not affect how this object might be dlclose()'d.
		 * For a private handle, fall through to carry out any group
		 * processing.
		 */
		if (oflags & FLG_RT_PUBHDL)
			return (1);
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
	for (APLIST_TRAVERSE(GROUPS(clmp), idx1, ghp)) {
		Aliste		idx2;
		Grp_desc	*gdp;
		int		ale;
		Rt_map		*dlmp1;
		APlist		*lmalp = NULL;

		DBG_CALL(Dbg_file_hdl_title(DBG_HDL_ADD));

		/*
		 * If the caller doesn't indicate that its dependencies should
		 * be added to a handle, ignore it.  This case identifies a
		 * parent of a dlopen(RTLD_PARENT) request.
		 */
		for (ALIST_TRAVERSE(ghp->gh_depends, idx2, gdp)) {
			if (gdp->gd_depend == clmp)
				break;
		}
		if ((gdp->gd_flags & GPD_ADDEPS) == 0)
			continue;

		if ((gdp = hdl_add(ghp, nlmp, rdflags, &ale)) == NULL)
			return (0);

		/*
		 * If this member already exists then its dependencies will
		 * have already been processed.
		 */
		if (ale == ALE_EXISTS)
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
		if (aplist_append(&lmalp, nlmp, AL_CNT_DEPCLCT) == NULL)
			return (0);

		for (APLIST_TRAVERSE(lmalp, idx2, dlmp1)) {
			Aliste		idx3;
			Bnd_desc 	*bdp;

			/*
			 * Add any dependencies of this dependency to the
			 * dynamic dependency list so they can be further
			 * processed.
			 */
			for (APLIST_TRAVERSE(DEPENDS(dlmp1), idx3, bdp)) {
				Rt_map	*dlmp2 = bdp->b_depend;

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

			if ((gdp =
			    hdl_add(ghp, dlmp1, rdflags, &ale)) == NULL) {
				free(lmalp);
				return (0);
			}

			if (ale == ALE_CREATE)
				(void) update_mode(dlmp1, MODE(dlmp1), nmode);
		}
		free(lmalp);
	}
	return (1);
}

/*
 * The central routine for loading shared objects.  Insures ldd() diagnostics,
 * handle creation, and any other related additions are all done in one place.
 */
Rt_map *
load_path(Lm_list *lml, Aliste lmco, Rt_map *clmp, int nmode, uint_t flags,
    Grp_hdl **hdl, Fdesc *fdp, Rej_desc *rej, int *in_nfavl)
{
	const char	*name = fdp->fd_oname;
	Rt_map		*nlmp;

	if ((nmode & RTLD_NOLOAD) == 0) {
		int	oin_nfavl;

		/*
		 * Keep track of the number of not-found loads.
		 */
		if (in_nfavl)
			oin_nfavl = *in_nfavl;

		/*
		 * If this isn't a noload request attempt to load the file.
		 */
		if ((nlmp = load_so(lml, lmco, clmp, flags, fdp, rej,
		    in_nfavl)) == NULL)
			return (NULL);

		/*
		 * If this file has been found, reset the not-found load count.
		 * Although a search for this file might have inspected a number
		 * of non-existent path names, the file has been found so there
		 * is no need to accumulate a non-found count, as this may
		 * trigger unnecessary fall back (retry) processing.
		 */
		if (in_nfavl)
			*in_nfavl = oin_nfavl;

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
			DBG_CALL(Dbg_file_rejected(lml, &_rej, M_MACH));
			rejection_inherit(rej, &_rej);
			remove_so(lml, nlmp, clmp);
			return (NULL);
		}
	} else {
		/*
		 * If it's a NOLOAD request - check to see if the object
		 * has already been loaded.
		 */
		/* LINTED */
		if (nlmp = is_so_loaded(lml, name, in_nfavl)) {
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
			DBG_CALL(Dbg_file_rejected(lml, &_rej, M_MACH));
			rejection_inherit(rej, &_rej);
			return (NULL);
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
			remove_so(lml, nlmp, clmp);
		return (NULL);
	}

	/*
	 * If this object is new, and we're being audited, tell the audit
	 * libraries of the file we've just opened.  Note, if the new link-map
	 * requires local auditing of its dependencies we also register its
	 * opening.
	 */
	if (FLAGS(nlmp) & FLG_RT_NEWLOAD) {
		FLAGS(nlmp) &= ~FLG_RT_NEWLOAD;

		if ((lml->lm_tflags | AFLAGS(clmp) | AFLAGS(nlmp)) &
		    LML_TFLG_AUD_MASK) {
			if (audit_objopen(clmp, nlmp) == 0) {
				remove_so(lml, nlmp, clmp);
				return (NULL);
			}
		}
	}
	return (nlmp);
}

/*
 * Load one object from a possible list of objects.  Typically, for requests
 * such as NEEDED's, only one object is specified.  However, this object could
 * be specified using $ISALIST or $CAPABILITY, in which case only the first
 * object that can be loaded is used (ie. the best).
 */
Rt_map *
load_one(Lm_list *lml, Aliste lmco, Alist *palp, Rt_map *clmp, int mode,
    uint_t flags, Grp_hdl **hdl, int *in_nfavl)
{
	Rej_desc	rej = { 0 };
	Aliste		idx;
	Pdesc   	*pdp;
	const char	*name;

	for (ALIST_TRAVERSE(palp, idx, pdp)) {
		Rt_map	*lmp = NULL;

		/*
		 * A $CAPABILITY/$HWCAP requirement can expand into a number of
		 * candidates.
		 */
		if (pdp->pd_flags & PD_TKN_CAP) {
			lmp = load_cap(lml, lmco, pdp->pd_pname, clmp,
			    mode, (flags | FLG_RT_CAP), hdl, &rej, in_nfavl);
		} else {
			Fdesc	fd = { 0 };

			/*
			 * Trace the inspection of this file, determine any
			 * auditor substitution, and seed the file descriptor
			 * with the originating name.
			 */
			if (load_trace(lml, pdp, clmp, &fd) == NULL)
				continue;

			/*
			 * Locate and load the file.
			 */
			lmp = load_path(lml, lmco, clmp, mode, flags, hdl, &fd,
			    &rej, in_nfavl);
		}
		if (lmp)
			return (lmp);
	}

	/*
	 * If no objects can be found, use the first path name from the Alist
	 * to provide a diagnostic.  If this pathname originated from an
	 * expanded token, use the original name for any diagnostic output.
	 */
	pdp = alist_item(palp, 0);

	if ((name = pdp->pd_oname) == 0)
		name = pdp->pd_pname;

	file_notfound(lml, name, clmp, flags, &rej);
	return (NULL);
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
static int
lookup_sym_interpose(Slookup *slp, Sresult *srp, uint_t *binfo, int *in_nfavl)
{
	Rt_map		*lmp, *clmp, *dlmp = srp->sr_dmap;
	Sym		*osym = srp->sr_sym;
	Slookup		sl;
	Lm_list		*lml;

	/*
	 * If we've bound to a copy relocation definition then we need to assign
	 * this binding to the original copy reference.  Fabricate an inter-
	 * position diagnostic, as this is a legitimate form of interposition.
	 */
	if (osym && (FLAGS1(dlmp) & FL1_RT_COPYTOOK)) {
		Rel_copy	*rcp;
		Aliste		idx;

		for (ALIST_TRAVERSE(COPY_R(dlmp), idx, rcp)) {
			if ((osym == rcp->r_dsym) || (osym->st_value &&
			    (osym->st_value == rcp->r_dsym->st_value))) {
				srp->sr_dmap = rcp->r_rlmp;
				srp->sr_sym = rcp->r_rsym;
				*binfo |=
				    (DBG_BINFO_INTERPOSE | DBG_BINFO_COPYREF);
				return (1);
			}
		}
	}

	/*
	 * If a symbol binding has been established, inspect the link-map list
	 * of the destination object, otherwise use the link-map list of the
	 * original caller.
	 */
	if (osym)
		clmp = dlmp;
	else
		clmp = slp->sl_cmap;

	lml = LIST(clmp);
	lmp = lml->lm_head;

	/*
	 * Prior to Solaris 8, external references from an executable that were
	 * bound to an uninitialized variable (.bss) within a shared object did
	 * not establish a copy relocation.  This was thought to be an
	 * optimization, to prevent copying zero's to zero's.  Typically,
	 * interposition took its course, with the shared object binding to the
	 * executables data definition.
	 *
	 * This scenario can be broken when this old executable runs against a
	 * new shared object that is directly bound.  With no copy-relocation
	 * record, ld.so.1 has no data to trigger the normal vectoring of the
	 * binding to the executable.
	 *
	 * Starting with Solaris 8, a DT_FLAGS entry is written to all objects,
	 * regardless of there being any DF_ flags entries.  Therefore, an
	 * object without this dynamic tag is susceptible to the copy relocation
	 * issue.  If the executable has no DT_FLAGS tag, and contains the same
	 * .bss symbol definition as has been directly bound to, redirect the
	 * binding to the executables data definition.
	 */
	if (osym && ((FLAGS1(lmp) & FL1_RT_DTFLAGS) == 0) &&
	    (FCT(lmp) == &elf_fct) &&
	    (ELF_ST_TYPE(osym->st_info) != STT_FUNC) &&
	    are_bits_zero(dlmp, osym, 0)) {
		Sresult	sr;

		/*
		 * Initialize a local symbol result descriptor, using the
		 * original symbol name.  Initialize a local symbol lookup
		 * descriptor, using the original lookup information, and a
		 * new initial link-map.
		 */
		SRESULT_INIT(sr, slp->sl_name);
		sl = *slp;
		sl.sl_imap = lmp;

		/*
		 * Determine whether the same symbol name exists within the
		 * executable, that the size and type of symbol are the same,
		 * and that the symbol is also associated with .bss.
		 */
		if (SYMINTP(lmp)(&sl, &sr, binfo, in_nfavl)) {
			Sym	*isym = sr.sr_sym;

			if ((isym->st_size == osym->st_size) &&
			    (isym->st_info == osym->st_info) &&
			    are_bits_zero(lmp, isym, 1)) {
				*srp = sr;
				*binfo |=
				    (DBG_BINFO_INTERPOSE | DBG_BINFO_COPYREF);
				return (1);
			}
		}
	}

	if ((lml->lm_flags & LML_FLG_INTRPOSE) == 0)
		return (NULL);

	/*
	 * Traverse the list of known interposers to determine whether any
	 * offer the same symbol.  Note, the head of the link-map could be
	 * identified as an interposer.  Otherwise, skip the head of the
	 * link-map, so that we don't bind to any .plt references, or
	 * copy-relocation destinations unintentionally.
	 */
	lmp = lml->lm_head;
	sl = *slp;

	if (((FLAGS(lmp) & MSK_RT_INTPOSE) == 0) || (sl.sl_flags & LKUP_COPY))
		lmp = NEXT_RT_MAP(lmp);

	for (; lmp; lmp = NEXT_RT_MAP(lmp)) {
		if (FLAGS(lmp) & FLG_RT_DELETE)
			continue;
		if ((FLAGS(lmp) & MSK_RT_INTPOSE) == 0)
			break;

		/*
		 * If we had already bound to this object, there's no point in
		 * searching it again, we're done.
		 */
		if (lmp == dlmp)
			break;

		/*
		 * If this interposer can be inspected by the caller, look for
		 * the symbol within the interposer.
		 */
		if (callable(clmp, lmp, 0, sl.sl_flags)) {
			Sresult		sr;

			/*
			 * Initialize a local symbol result descriptor, using
			 * the original symbol name.  Initialize a local symbol
			 * lookup descriptor, using the original lookup
			 * information, and a new initial link-map.
			 */
			SRESULT_INIT(sr, slp->sl_name);
			sl.sl_imap = lmp;

			if (SYMINTP(lmp)(&sl, &sr, binfo, in_nfavl)) {
				Sym	*isym = sr.sr_sym;
				Rt_map	*ilmp = sr.sr_dmap;

				/*
				 * If this object provides individual symbol
				 * interposers, make sure that the symbol we
				 * have found is tagged as an interposer.
				 */
				if ((FLAGS(ilmp) & FLG_RT_SYMINTPO) &&
				    (is_sym_interposer(ilmp, isym) == 0))
					continue;

				/*
				 * Indicate this binding has occurred to an
				 * interposer, and return the symbol.
				 */
				*srp = sr;
				*binfo |= DBG_BINFO_INTERPOSE;
				return (1);
			}
		}
	}
	return (0);
}

/*
 * If an object specifies direct bindings (it contains a syminfo structure
 * describing where each binding was established during link-editing, and the
 * object was built -Bdirect), then look for the symbol in the specific object.
 */
static int
lookup_sym_direct(Slookup *slp, Sresult *srp, uint_t *binfo, Syminfo *sip,
    Rt_map *lmp, int *in_nfavl)
{
	Rt_map	*dlmp, *clmp = slp->sl_cmap;
	int	ret;
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

		if (ret = SYMINTP(clmp)(slp, srp, binfo, in_nfavl))
			*binfo |= (DBG_BINFO_DIRECT | DBG_BINFO_COPYREF);
		return (ret);
	}

	/*
	 * If we need to directly bind to our parent, start looking in each
	 * callers link map.
	 */
	sl = *slp;
	sl.sl_flags |= LKUP_DIRECT;
	ret = 0;

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
			if (ret = SYMINTP(lmp)(&sl, srp, binfo, in_nfavl))
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
				if (ret = SYMINTP(lmp)(&sl, srp, binfo,
				    in_nfavl))
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
			ret = SYMINTP(lmp)(&sl, srp, binfo, in_nfavl);
	}
found:
	if (ret)
		*binfo |= DBG_BINFO_DIRECT;

	/*
	 * If a reference to a directly bound symbol can't be satisfied, then
	 * determine whether an interposer can provide the missing symbol.  If
	 * a reference to a directly bound symbol is satisfied, then determine
	 * whether that object can be interposed upon for this symbol.
	 */
	dlmp = srp->sr_dmap;
	if ((ret == 0) || (dlmp && (LIST(dlmp)->lm_head != dlmp) &&
	    (LIST(dlmp) == LIST(clmp)))) {
		if (lookup_sym_interpose(slp, srp, binfo, in_nfavl))
			return (1);
	}

	return (ret);
}

static int
core_lookup_sym(Rt_map *ilmp, Slookup *slp, Sresult *srp, uint_t *binfo,
    Aliste off, int *in_nfavl)
{
	Rt_map	*lmp;

	/*
	 * Copy relocations should start their search after the head of the
	 * main link-map control list.
	 */
	if ((off == ALIST_OFF_DATA) && (slp->sl_flags & LKUP_COPY) && ilmp)
		lmp = NEXT_RT_MAP(ilmp);
	else
		lmp = ilmp;

	for (; lmp; lmp = NEXT_RT_MAP(lmp)) {
		if (callable(slp->sl_cmap, lmp, 0, slp->sl_flags)) {

			slp->sl_imap = lmp;
			if ((SYMINTP(lmp)(slp, srp, binfo, in_nfavl)) ||
			    (*binfo & BINFO_MSK_TRYAGAIN))
				return (1);
		}
	}
	return (0);
}

static int
rescan_lazy_find_sym(Rt_map *ilmp, Slookup *slp, Sresult *srp, uint_t *binfo,
    int *in_nfavl)
{
	Rt_map	*lmp;

	for (lmp = ilmp; lmp; lmp = NEXT_RT_MAP(lmp)) {
		if (LAZY(lmp) == 0)
			continue;
		if (callable(slp->sl_cmap, lmp, 0, slp->sl_flags)) {

			slp->sl_imap = lmp;
			if (elf_lazy_find_sym(slp, srp, binfo, in_nfavl))
				return (1);
		}
	}
	return (0);
}

static int
_lookup_sym(Slookup *slp, Sresult *srp, uint_t *binfo, int *in_nfavl)
{
	const char	*name = slp->sl_name;
	Rt_map		*clmp = slp->sl_cmap;
	Lm_list		*lml = LIST(clmp);
	Rt_map		*ilmp = slp->sl_imap, *lmp;
	ulong_t		rsymndx;
	int		ret;
	Syminfo		*sip;
	Slookup		sl;

	/*
	 * Search the initial link map for the required symbol (this category is
	 * selected by dlsym(), where individual link maps are searched for a
	 * required symbol.  Therefore, we know we have permission to look at
	 * the link map).
	 */
	if (slp->sl_flags & LKUP_FIRST)
		return (SYMINTP(ilmp)(slp, srp, binfo, in_nfavl));

	/*
	 * Determine whether this lookup can be satisfied by an objects direct,
	 * or lazy binding information.  This is triggered by a relocation from
	 * the object (hence rsymndx is set).
	 */
	if (((rsymndx = slp->sl_rsymndx) != 0) &&
	    ((sip = SYMINFO(clmp)) != NULL)) {
		uint_t	bound;

		/*
		 * Find the corresponding Syminfo entry for the original
		 * referencing symbol.
		 */
		/* LINTED */
		sip = (Syminfo *)((char *)sip + (rsymndx * SYMINENT(clmp)));
		bound = sip->si_boundto;

		/*
		 * Identify any EXTERN or PARENT references for ldd(1).
		 */
		if ((lml->lm_flags & LML_FLG_TRC_WARN) &&
		    (bound > SYMINFO_BT_LOWRESERVE)) {
			if (bound == SYMINFO_BT_PARENT)
				*binfo |= DBG_BINFO_REF_PARENT;
			if (bound == SYMINFO_BT_EXTERN)
				*binfo |= DBG_BINFO_REF_EXTERN;
		}

		/*
		 * If the symbol information indicates a direct binding,
		 * determine the link map that is required to satisfy the
		 * binding.  Note, if the dependency can not be found, but a
		 * direct binding isn't required, we will still fall through
		 * to perform any default symbol search.
		 */
		if (sip->si_flags & SYMINFO_FLG_DIRECT) {

			lmp = 0;
			if (bound < SYMINFO_BT_LOWRESERVE)
				lmp = elf_lazy_load(clmp, slp, bound,
				    name, 0, NULL, in_nfavl);

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
			    (((lml->lm_tflags & LML_TFLG_NODIRECT) == 0) &&
			    ((slp->sl_flags & LKUP_SINGLETON) == 0))) &&
			    ((FLAGS1(clmp) & FL1_RT_DIRECT) ||
			    (sip->si_flags & SYMINFO_FLG_DIRECTBIND))) {
				ret = lookup_sym_direct(slp, srp, binfo,
				    sip, lmp, in_nfavl);

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
				if (((*binfo & BINFO_MSK_REJECTED) == 0) ||
				    (*binfo & BINFO_MSK_TRYAGAIN))
					return (ret);

				*binfo &= ~BINFO_MSK_REJECTED;
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
		if (SYMINTP(clmp)(&sl, srp, binfo, in_nfavl)) {
			Rt_map	*dlmp = srp->sr_dmap;
			ulong_t	dsymndx = (((ulong_t)srp->sr_sym -
			    (ulong_t)SYMTAB(dlmp)) / SYMENT(dlmp));

			/*
			 * Make sure this symbol hasn't explicitly been defined
			 * as nodirect.
			 */
			if (((sip = SYMINFO(dlmp)) == 0) ||
			    /* LINTED */
			    ((sip = (Syminfo *)((char *)sip +
			    (dsymndx * SYMINENT(dlmp)))) == 0) ||
			    ((sip->si_flags & SYMINFO_FLG_NOEXTDIRECT) == 0))
				return (1);
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

		ret = 0;

		for (ALIST_TRAVERSE_BY_OFFSET(lml->lm_lists, off, lmc)) {
			if (((ret = core_lookup_sym(lmc->lc_head, &sl, srp,
			    binfo, off, in_nfavl)) != 0) ||
			    (*binfo & BINFO_MSK_TRYAGAIN))
				break;
		}
	} else
		ret = core_lookup_sym(ilmp, &sl, srp, binfo, ALIST_OFF_DATA,
		    in_nfavl);

	/*
	 * If a symbol binding should be retried, return so that the search can
	 * be repeated.
	 */
	if (*binfo & BINFO_MSK_TRYAGAIN)
		return (0);

	/*
	 * To allow transitioning into a world of lazy loading dependencies see
	 * if this link map contains objects that have lazy dependencies still
	 * outstanding.  If so, and we haven't been able to locate a non-weak
	 * symbol reference, start bringing in any lazy dependencies to see if
	 * the reference can be satisfied.  Use of dlsym(RTLD_PROBE) sets the
	 * LKUP_NOFALLBACK flag, and this flag disables this fall back.
	 */
	if ((ret == 0) && ((sl.sl_flags & LKUP_NOFALLBACK) == 0)) {
		if ((lmp = ilmp) == 0)
			lmp = LIST(clmp)->lm_head;

		lml = LIST(lmp);
		if ((sl.sl_flags & LKUP_WEAK) || (lml->lm_lazy == 0))
			return (NULL);

		DBG_CALL(Dbg_syms_lazy_rescan(lml, name));

		/*
		 * If this request originated from a dlsym(RTLD_NEXT) then start
		 * looking for dependencies from the caller, otherwise use the
		 * initial link-map.
		 */
		if (sl.sl_flags & LKUP_NEXT)
			ret = rescan_lazy_find_sym(clmp, &sl, srp, binfo,
			    in_nfavl);
		else {
			Aliste	idx;
			Lm_cntl	*lmc;

			for (ALIST_TRAVERSE(lml->lm_lists, idx, lmc)) {
				sl.sl_flags |= LKUP_NOFALLBACK;
				if (ret = rescan_lazy_find_sym(lmc->lc_head,
				    &sl, srp, binfo, in_nfavl))
					break;
			}
		}
	}
	return (ret);
}

/*
 * Symbol lookup routine.  Takes an ELF symbol name, and a list of link maps to
 * search.  If successful, return a pointer to the symbol table entry, a
 * pointer to the link map of the enclosing object, and information relating
 * to the type of binding.  Else return a null pointer.
 *
 * To improve ELF performance, we first compute the ELF hash value and pass
 * it to each _lookup_sym() routine.  The ELF function will use this value to
 * locate the symbol, the a.out function will simply ignore it.
 */
int
lookup_sym(Slookup *slp, Sresult *srp, uint_t *binfo, int *in_nfavl)
{
	Rt_map		*clmp = slp->sl_cmap;
	Sym		*rsym = slp->sl_rsym;
	uchar_t		rtype = slp->sl_rtype, vis;
	int		ret, mode;

	if (slp->sl_hash == 0)
		slp->sl_hash = elf_hash(slp->sl_name);
	*binfo = 0;

	if (rsym) {
		vis = ELF_ST_VISIBILITY(rsym->st_other);

		/*
		 * Symbols that are defined as protected, or hidden, within an
		 * object usually have any relocation references from within
		 * the same object bound at link-edit time.  Therefore, ld.so.1
		 * is not involved.  However, if a reference is to a
		 * capabilities symbol, this reference must be resolved at
		 * runtime.  In this case look directly within the calling
		 * object, and only within the calling object, for these
		 * symbols.  Note, an object may still use dlsym() to search
		 * externally for a symbol which is defined as protected within
		 * the same object.
		 */
		if ((rsym->st_shndx != SHN_UNDEF) &&
		    ((slp->sl_flags & LKUP_DLSYM) == 0) &&
		    ((vis == STV_PROTECTED) || (vis == STV_HIDDEN))) {
			slp->sl_imap = clmp;
			return (SYMINTP(clmp)(slp, srp, binfo, in_nfavl));
		}

		/*
		 * Establish any state that might be associated with a symbol
		 * reference.
		 */
		if ((slp->sl_flags & LKUP_STDRELOC) &&
		    (ELF_ST_BIND(rsym->st_info) == STB_WEAK))
			slp->sl_flags |= LKUP_WEAK;

		if (vis == STV_SINGLETON)
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
	 * Save the callers MODE().
	 */
	mode = MODE(clmp);

	/*
	 * Carry out an initial symbol search.  This search takes into account
	 * all the modes of the requested search.
	 */
	if (((ret = _lookup_sym(slp, srp, binfo, in_nfavl)) == 0) &&
	    (*binfo & BINFO_MSK_TRYAGAIN)) {
		Slookup	sl = *slp;

		/*
		 * Try the symbol search again.  This retry can be necessary if:
		 *
		 *  -	a binding has been rejected because of binding to a
		 *	singleton without going through a singleton search.
		 *  -	a group binding has resulted in binding to a symbol
		 *	that indicates no-direct binding.
		 *
		 * Reset the lookup data, and try again.
		 */
		sl.sl_imap = LIST(sl.sl_cmap)->lm_head;
		sl.sl_flags &= ~(LKUP_FIRST | LKUP_SELF | LKUP_NEXT);
		sl.sl_rsymndx = 0;

		if (*binfo & BINFO_REJSINGLE)
			sl.sl_flags |= LKUP_SINGLETON;
		if (*binfo & BINFO_REJGROUP) {
			sl.sl_flags |= LKUP_WORLD;
			mode |= RTLD_WORLD;
		}
		*binfo &= ~BINFO_MSK_REJECTED;

		ret = _lookup_sym(&sl, srp, binfo, in_nfavl);
	}

	/*
	 * If the caller is restricted to a symbol search within its group,
	 * determine if it is necessary to follow a binding from outside of
	 * the group.
	 */
	if (((mode & (RTLD_GROUP | RTLD_WORLD)) == RTLD_GROUP) &&
	    (lookup_sym_interpose(slp, srp, binfo, in_nfavl)))
		return (1);

	return (ret);
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
		if ((bdp = malloc(sizeof (Bnd_desc))) == NULL)
			return (0);

		bdp->b_caller = clmp;
		bdp->b_depend = dlmp;
		bdp->b_flags = 0;

		/*
		 * Append the binding descriptor to the caller and the
		 * dependency.
		 */
		if (aplist_append(&DEPENDS(clmp), bdp, AL_CNT_DEPENDS) == NULL)
			return (0);

		if (aplist_append(&CALLERS(dlmp), bdp, AL_CNT_CALLERS) == NULL)
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
relocate_finish(Rt_map *lmp, APlist *bound, int ret)
{
	DBG_CALL(Dbg_reloc_run(lmp, 0, ret, DBG_REL_FINISH));

	/*
	 * Establish bindings to all objects that have been bound to.
	 */
	if (bound) {
		Rt_map	*_lmp;
		Word	used;

		/*
		 * Only create bindings if the callers relocation was
		 * successful (ret != 0), otherwise the object will eventually
		 * be torn down.  Create these bindings if running under ldd(1)
		 * with the -U/-u options regardless of relocation errors, as
		 * the unused processing needs to traverse these bindings to
		 * diagnose unused objects.
		 */
		used = LIST(lmp)->lm_flags &
		    (LML_FLG_TRC_UNREF | LML_FLG_TRC_UNUSED);

		if (ret || used) {
			Aliste	idx;

			for (APLIST_TRAVERSE(bound, idx, _lmp)) {
				if (bind_one(lmp, _lmp, BND_REFER) || used)
					continue;

				ret = 0;
				break;
			}
		}
		free(bound);
	}

	return (ret);
}

/*
 * Function to correct protection settings.  Segments are all mapped initially
 * with permissions as given in the segment header.  We need to turn on write
 * permissions on a text segment if there are any relocations against that
 * segment, and then turn write permission back off again before returning
 * control to the caller.  This function turns the permission on or off
 * depending on the value of the permission argument.
 */
int
set_prot(Rt_map *lmp, mmapobj_result_t *mpp, int perm)
{
	int	prot;

	/*
	 * If this is an allocated image (ie. a relocatable object) we can't
	 * mprotect() anything.
	 */
	if (FLAGS(lmp) & FLG_RT_IMGALLOC)
		return (1);

	DBG_CALL(Dbg_file_prot(lmp, perm));

	if (perm)
		prot = mpp->mr_prot | PROT_WRITE;
	else
		prot = mpp->mr_prot & ~PROT_WRITE;

	if (mprotect((void *)(uintptr_t)mpp->mr_addr,
	    mpp->mr_msize, prot) == -1) {
		int	err = errno;
		eprintf(LIST(lmp), ERR_FATAL, MSG_INTL(MSG_SYS_MPROT),
		    NAME(lmp), strerror(err));
		return (0);
	}
	mpp->mr_prot = prot;
	return (1);
}
