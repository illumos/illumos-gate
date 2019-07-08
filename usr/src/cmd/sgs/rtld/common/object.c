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
 * Copyright (c) 1992, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * Object file dependent suport for ELF objects.
 */

#include	<sys/mman.h>
#include	<stdio.h>
#include	<unistd.h>
#include	<libelf.h>
#include	<string.h>
#include	<dlfcn.h>
#include	<debug.h>
#include	<libld.h>
#include	"_rtld.h"
#include	"_audit.h"
#include	"_elf.h"

static Rt_map	*olmp = NULL;
static Alist	*mpalp = NULL;

static Ehdr	dehdr = { { ELFMAG0, ELFMAG1, ELFMAG2, ELFMAG3,
			    M_CLASS, M_DATA }, 0, M_MACH, EV_CURRENT };

/*
 * Process a relocatable object.  The static object link map pointer is used as
 * a flag to determine whether a concatenation is already in progress (ie. an
 * LD_PRELOAD may specify a list of objects).  The link map returned simply
 * specifies an `object' flag which the caller can interpret and thus call
 * elf_obj_fini() to complete the concatenation.
 */
static Rt_map *
elf_obj_init(Lm_list *lml, Aliste lmco, const char *oname)
{
	Ofl_desc	*ofl;
	const char	*name;
	size_t		lmsz;

	/*
	 * Allocate the name of this object, as the original name may be
	 * associated with a data buffer that can be reused to load the
	 * dependencies needed to processes this object.
	 */
	if ((name = stravl_insert(oname, 0, 0, 0)) == NULL)
		return (NULL);

	/*
	 * Initialize an output file descriptor and the entrance criteria.
	 */
	if ((ofl = calloc(sizeof (Ofl_desc), 1)) == NULL)
		return (NULL);

	ofl->ofl_dehdr = &dehdr;

	ofl->ofl_flags = (FLG_OF_DYNAMIC | FLG_OF_SHAROBJ | FLG_OF_STRIP);
	ofl->ofl_flags1 = (FLG_OF1_RELDYN | FLG_OF1_TEXTOFF | FLG_OF1_MEMORY);
	ofl->ofl_lml = lml;

	/*
	 * As ent_setup() will effectively lazy load the necessary support
	 * libraries, make sure ld.so.1 is initialized for plt relocations.
	 * Then configure libld.so to process objects of the desired target
	 * type (this is the first call to libld.so, which will effectively
	 * lazyload it).
	 */
	if ((elf_rtld_load() == 0) || (ld_init_target(lml, M_MACH) != 0)) {
		free(ofl);
		return (NULL);
	}

	/*
	 * Obtain a generic set of entrance criteria, and generate a link map
	 * place holder and use the ELFPRV() element to maintain the output
	 * file descriptor.
	 */
	lmsz = S_DROUND(sizeof (Rt_map)) + sizeof (Rt_elfp);
	if ((ld_ent_setup(ofl, syspagsz) == S_ERROR) ||
	    ((olmp = calloc(lmsz, 1)) == NULL)) {
		free(ofl);
		return (NULL);
	}

	DBG_CALL(Dbg_file_elf(lml, name, 0, 0, lml->lm_lmidstr, lmco));
	FLAGS(olmp) |= FLG_RT_OBJECT;
	ELFPRV(olmp) = (void *)ofl;

	/*
	 * Initialize string tables.
	 */
	if (ld_init_strings(ofl) == S_ERROR) {
		free(ofl);
		free(olmp);
		olmp = NULL;
		return (NULL);
	}

	/*
	 * Assign the output file name to be the initial object that got us
	 * here.  This name is being used for diagnostic purposes only as we
	 * don't actually generate an output file unless debugging is enabled.
	 */
	ofl->ofl_name = name;
	NAME(olmp) = (char *)name;
	LIST(olmp) = lml;

	lm_append(lml, lmco, olmp);
	return (olmp);
}

/*
 * Define a structure to retain the mapping information of the original
 * relocatable object.  Typically, mmapobj(2) maps a relocatable object into one
 * mapping.  However, if padding has been enabled by a debugger, then additional
 * padding segments may have been added.  elf_obj_file() needs to know which
 * segment is the relocatable objects data, and retain the initial segment and
 * the associated segment number for unmapping this object later (see
 * elf_obj_fini()).  Note, even if padding is enabled, the final shared object
 * that is created by the link-editor for this relocatable object will have no
 * associated padding, as ld(1) has no capabilities to provide padding.
 */
typedef struct {
	mmapobj_result_t	*md_mpp;
	uint_t			md_mnum;
} Mmap_desc;

/*
 * Initial processing of a relocatable object.  If this is the first object
 * encountered we need to initialize some structures, then simply call the
 * link-edit functionality to provide the initial processing of the file (ie.
 * reads in sections and symbols, performs symbol resolution if more that one
 * object file have been specified, and assigns input sections to output
 * sections).
 */
Rt_map *
elf_obj_file(Lm_list *lml, Aliste lmco, Rt_map *clmp, const char *name,
    mmapobj_result_t *hmpp, mmapobj_result_t *mpp, uint_t mnum)
{
	Rej_desc	rej;
	Mmap_desc	md;

	/*
	 * If this is the first relocatable object (LD_PRELOAD could provide a
	 * list of objects), initialize an input file descriptor and a link map.
	 */
	if ((olmp == NULL) && ((olmp = elf_obj_init(lml, lmco, name)) == NULL))
		return (NULL);

	DBG_CALL(Dbg_util_nl(lml, DBG_NL_STD));

	/*
	 * Keep track of the input image, as this must be free'd after all ELF
	 * processing is completed.
	 */
	md.md_mpp = mpp;
	md.md_mnum = mnum;
	if (alist_append(&mpalp, &md, sizeof (Mmap_desc),
	    AL_CNT_MPOBJS) == NULL) {
		remove_so(lml, olmp, clmp);
		return (NULL);
	}

	/*
	 * Pass the object mapping to the link-editor to commence processing the
	 * file.
	 */
	if (ld_process_mem(name, name, hmpp->mr_addr, hmpp->mr_msize,
	    (Ofl_desc *)ELFPRV(olmp), &rej) == (Ifl_desc *)S_ERROR) {
		remove_so(lml, olmp, clmp);
		return (NULL);
	}

	return (olmp);
}

/*
 * Ensure any platform or machine capability names are valid.
 */
inline static int
check_plat_names(Syscapset *scapset, Alist *caps, Rej_desc *rej)
{
	Capstr	*capstr;
	Aliste	idx;

	for (ALIST_TRAVERSE(caps, idx, capstr)) {
		if (platcap_check(scapset, capstr->cs_str, rej) == 1)
			return (1);
	}
	return (0);
}

inline static int
check_mach_names(Syscapset *scapset, Alist *caps, Rej_desc *rej)
{
	Capstr	*capstr;
	Aliste	idx;

	for (ALIST_TRAVERSE(caps, idx, capstr)) {
		if (machcap_check(scapset, capstr->cs_str, rej) == 1)
			return (1);
	}
	return (0);
}

/*
 * Finish relocatable object processing.  Having already initially processed one
 * or more objects, complete the generation of a shared object image by calling
 * the appropriate link-edit functionality (refer to sgs/ld/common/main.c).
 */
Rt_map *
elf_obj_fini(Lm_list *lml, Rt_map *lmp, Rt_map *clmp, int *in_nfavl)
{
	Ofl_desc		*ofl = (Ofl_desc *)ELFPRV(lmp);
	Rt_map			*nlmp, *tlmp;
	Ehdr			*ehdr;
	Phdr			*phdr;
	mmapobj_result_t	*mpp, *hmpp;
	uint_t			phnum;
	int			mnum;
	Lm_cntl			*lmc;
	Aliste			idx1;
	Mmap_desc		*mdp;
	Fdesc			fd = { 0 };
	Grp_hdl			*ghp;
	Rej_desc		rej = { 0 };
	Syscapset		*scapset;
	elfcap_mask_t		omsk;
	Alist			*oalp;

	DBG_CALL(Dbg_util_nl(lml, DBG_NL_STD));

	if (ld_reloc_init(ofl) == S_ERROR)
		return (NULL);
	if (ld_sym_validate(ofl) == S_ERROR)
		return (NULL);

	/*
	 * At this point, all input section processing is complete.  If any
	 * capabilities have been established, ensure that they are appropriate
	 * for this system.
	 */
	if (pnavl_recorded(&capavl, ofl->ofl_name, 0, NULL))
		scapset = alt_scapset;
	else
		scapset = org_scapset;

	if ((((omsk = ofl->ofl_ocapset.oc_hw_1.cm_val) != 0) &&
	    (hwcap1_check(scapset, omsk, &rej) == 0)) ||
	    (((omsk = ofl->ofl_ocapset.oc_sf_1.cm_val) != 0) &&
	    (sfcap1_check(scapset, omsk, &rej) == 0)) ||
	    (((omsk = ofl->ofl_ocapset.oc_hw_2.cm_val) != 0) &&
	    (hwcap2_check(scapset, omsk, &rej) == 0)) ||
	    (((oalp = ofl->ofl_ocapset.oc_plat.cl_val) != NULL) &&
	    (check_plat_names(scapset, oalp, &rej) == 0)) ||
	    (((oalp = ofl->ofl_ocapset.oc_mach.cl_val) != NULL) &&
	    (check_mach_names(scapset, oalp, &rej) == 0))) {
		if ((lml_main.lm_flags & LML_FLG_TRC_LDDSTUB) && lmp &&
		    (FLAGS1(lmp) & FL1_RT_LDDSTUB) && (NEXT(lmp) == NULL)) {
			/* LINTED */
			(void) printf(MSG_INTL(ldd_reject[rej.rej_type]),
			    ofl->ofl_name, rej.rej_str);
		}
		return (NULL);
	}

	/*
	 * Finish creating the output file.
	 */
	if (ld_make_sections(ofl) == S_ERROR)
		return (NULL);
	if (ld_create_outfile(ofl) == S_ERROR)
		return (NULL);
	if (ld_update_outfile(ofl) == S_ERROR)
		return (NULL);
	if (ld_reloc_process(ofl) == S_ERROR)
		return (NULL);

	/*
	 * At this point we have a memory image of the shared object.  The link
	 * editor would normally simply write this to the required output file.
	 * If we're debugging generate a standard temporary output file.
	 */
	DBG_CALL(Dbg_file_output(ofl));

	/*
	 * Allocate a mapping array to retain mapped segment information.
	 */
	ehdr = ofl->ofl_nehdr;
	phdr = ofl->ofl_phdr;

	if ((mpp = hmpp = calloc(ehdr->e_phnum,
	    sizeof (mmapobj_result_t))) == NULL)
		return (NULL);
	for (mnum = 0, phnum = 0; phnum < ehdr->e_phnum; phnum++) {
		if (phdr[phnum].p_type != PT_LOAD)
			continue;

		mpp[mnum].mr_addr = (caddr_t)((uintptr_t)phdr[phnum].p_vaddr +
		    (uintptr_t)ehdr);
		mpp[mnum].mr_msize = phdr[phnum].p_memsz;
		mpp[mnum].mr_fsize = phdr[phnum].p_filesz;
		mpp[mnum].mr_prot = (PROT_READ | PROT_WRITE | PROT_EXEC);
		mnum++;
	}

	/*
	 * Generate a new link map representing the memory image created.
	 */
	fd.fd_nname = ofl->ofl_name;
	if ((nlmp = elf_new_lmp(lml, CNTL(olmp), &fd, (Addr)hmpp->mr_addr,
	    ofl->ofl_size, NULL, clmp, in_nfavl)) == NULL)
		return (NULL);

	MMAPS(nlmp) = hmpp;
	MMAPCNT(nlmp) = mnum;
	PADSTART(nlmp) = (ulong_t)hmpp->mr_addr;
	PADIMLEN(nlmp) = mpp->mr_addr + mpp->mr_msize - hmpp->mr_addr;

	/*
	 * Replace the original (temporary) link map with the new link map.
	 */
	/* LINTED */
	lmc = (Lm_cntl *)alist_item_by_offset(lml->lm_lists, CNTL(nlmp));
	lml->lm_obj--;

	if ((tlmp = PREV_RT_MAP(nlmp)) == olmp)
		tlmp = nlmp;

	if (PREV(olmp)) {
		NEXT(PREV_RT_MAP(olmp)) = (Link_map *)nlmp;
		PREV(nlmp) = PREV(olmp);
	} else {
		PREV(nlmp) = NULL;
		lmc->lc_head = nlmp;
		if (CNTL(nlmp) == ALIST_OFF_DATA)
			lml->lm_head = nlmp;
	}

	if (NEXT(olmp) != (Link_map *)nlmp) {
		NEXT(nlmp) = NEXT(olmp);
		PREV(NEXT_RT_MAP(olmp)) = (Link_map *)nlmp;
	}

	NEXT(tlmp) = NULL;

	lmc->lc_tail = tlmp;
	if (CNTL(nlmp) == ALIST_OFF_DATA)
		lml->lm_tail = tlmp;

	HANDLES(nlmp) = HANDLES(olmp);
	GROUPS(nlmp) = GROUPS(olmp);
	STDEV(nlmp) = STDEV(olmp);
	STINO(nlmp) = STINO(olmp);

	FLAGS(nlmp) |= ((FLAGS(olmp) & ~FLG_RT_OBJECT) | FLG_RT_IMGALLOC);
	FLAGS1(nlmp) |= FLAGS1(olmp);
	MODE(nlmp) |= MODE(olmp);

	NAME(nlmp) = NAME(olmp);

	/*
	 * Reassign any original handles to the new link-map.
	 */
	for (APLIST_TRAVERSE(HANDLES(nlmp), idx1, ghp)) {
		Grp_desc	*gdp;
		Aliste		idx2;

		ghp->gh_ownlmp = nlmp;

		for (ALIST_TRAVERSE(ghp->gh_depends, idx2, gdp)) {
			if (gdp->gd_depend == olmp) {
				gdp->gd_depend = nlmp;
				break;
			}
		}
	}

	ld_ofl_cleanup(ofl);
	free(ELFPRV(olmp));
	free(olmp);
	olmp = 0;

	/*
	 * Unmap the original relocatable object.
	 */
	for (ALIST_TRAVERSE(mpalp, idx1, mdp)) {
		unmap_obj(mdp->md_mpp, mdp->md_mnum);
		free(mdp->md_mpp);
	}
	free(mpalp);
	mpalp = NULL;

	/*
	 * Now that we've allocated our permanent link map structure, expand the
	 * PATHNAME() and insert this path name into the FullPathNode AVL tree.
	 */
	(void) fullpath(nlmp, 0);
	if (fpavl_insert(lml, nlmp, PATHNAME(nlmp), 0) == 0)
		return (NULL);

	/*
	 * If we're being audited tell the audit library of the file we've just
	 * opened.
	 */
	if ((lml->lm_tflags | AFLAGS(nlmp)) & LML_TFLG_AUD_MASK) {
		if (audit_objopen(nlmp, nlmp) == 0)
			return (NULL);
	}
	return (nlmp);
}
