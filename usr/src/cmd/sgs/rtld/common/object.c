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

/*
 * Object file dependent suport for ELF objects.
 */
#include	"_synonyms.h"

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

static Rt_map	*olmp = 0;

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
elf_obj_init(Lm_list *lml, Aliste lmco, const char *name)
{
	Ofl_desc *	ofl;

	/*
	 * Initialize an output file descriptor and the entrance criteria.
	 */
	if ((ofl = (Ofl_desc *)calloc(sizeof (Ofl_desc), 1)) == 0)
		return (0);

	ofl->ofl_dehdr = &dehdr;

	ofl->ofl_flags = (FLG_OF_DYNAMIC | FLG_OF_SHAROBJ | FLG_OF_STRIP);
	ofl->ofl_flags1 = (FLG_OF1_RELDYN | FLG_OF1_TEXTOFF | FLG_OF1_MEMORY);
	ofl->ofl_lml = lml;

	/*
	 * As ent_setup() will effectively lazy load the necessary support
	 * libraries, make sure ld.so.1 is initialized for plt relocations.
	 */
	if (elf_rtld_load() == 0)
		return (0);

	/*
	 * Configure libld.so to process objects of the desired target
	 * type (this is the first call to libld.so, which will effectively
	 * lazyload it).
	 */
	if (ld_init_target(lml, M_MACH) != 0)
		return (0);

	/*
	 * Obtain a generic set of entrance criteria
	 */
	if (ld_ent_setup(ofl, syspagsz) == S_ERROR)
		return (0);

	/*
	 * Generate a link map place holder and use the `rt_priv' element to
	 * maintain the output file descriptor.
	 */
	if ((olmp = (Rt_map *)calloc(sizeof (Rt_map), 1)) == 0)
		return (0);

	DBG_CALL(Dbg_file_elf(lml, name, 0, 0, 0, 0, lml->lm_lmidstr, lmco));
	FLAGS(olmp) |= FLG_RT_OBJECT;
	olmp->rt_priv = (void *)ofl;

	/*
	 * Initialize string tables.
	 */
	if (ld_init_strings(ofl) == S_ERROR)
		return (0);

	/*
	 * Assign the output file name to be the initial object that got us
	 * here.  This name is being used for diagnostic purposes only as we
	 * don't actually generate an output file unless debugging is enabled.
	 */
	ofl->ofl_name = name;
	ORIGNAME(olmp) = PATHNAME(olmp) = NAME(olmp) = (char *)name;
	LIST(olmp) = lml;

	lm_append(lml, lmco, olmp);
	return (olmp);
}

/*
 * Initial processing of a relocatable object.  If this is the first object
 * encountered we need to initialize some structures, then simply call the
 * link-edit functionality to provide the initial processing of the file (ie.
 * reads in sections and symbols, performs symbol resolution if more that one
 * object file have been specified, and assigns input sections to output
 * sections).
 */
Rt_map *
elf_obj_file(Lm_list *lml, Aliste lmco, const char *name, int fd)
{
	Rej_desc	rej;

	/*
	 * If this is the first relocatable object (LD_PRELOAD could provide a
	 * list of objects), initialize an input file descriptor and a link map.
	 */
	if (!olmp) {
		/*
		 * Load the link-editor library.
		 */
		if ((olmp = elf_obj_init(lml, lmco, name)) == 0)
			return (0);
	}

	/*
	 * Proceed to process the input file.
	 */
	DBG_CALL(Dbg_util_nl(lml, DBG_NL_STD));
	if (ld_process_open(name, name, &fd, (Ofl_desc *)olmp->rt_priv,
	    NULL, &rej) == (Ifl_desc *)S_ERROR)
		return (0);
	return (olmp);
}

/*
 * Finish relocatable object processing.  Having already initially processed one
 * or more objects, complete the generation of a shared object image by calling
 * the appropriate link-edit functionality (refer to sgs/ld/common/main.c).
 */
Rt_map *
elf_obj_fini(Lm_list *lml, Rt_map *lmp)
{
	Ofl_desc	*ofl = (Ofl_desc *)lmp->rt_priv;
	Rt_map		*nlmp;
	Addr		etext;
	Ehdr		*ehdr;
	Phdr		*phdr;
	Mmap		*mmaps;
	uint_t		phnum, mmapcnt;
	Lm_cntl 	*lmc;

	DBG_CALL(Dbg_util_nl(lml, DBG_NL_STD));

	if (ld_reloc_init(ofl) == S_ERROR)
		return (0);
	if (ld_sym_validate(ofl) == S_ERROR)
		return (0);
	if (ld_make_sections(ofl) == S_ERROR)
		return (0);
	if (ld_create_outfile(ofl) == S_ERROR)
		return (0);
	if ((etext = ld_update_outfile(ofl)) == (Addr)S_ERROR)
		return (0);
	if (ld_reloc_process(ofl) == S_ERROR)
		return (0);

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
	if ((mmaps = calloc(ehdr->e_phnum, sizeof (Mmap))) == 0)
		return (0);
	for (mmapcnt = 0, phnum = 0; phnum < ehdr->e_phnum; phnum++) {
		if (phdr[phnum].p_type != PT_LOAD)
			continue;

		mmaps[mmapcnt].m_vaddr = (caddr_t)
		    (phdr[phnum].p_vaddr + (ulong_t)ehdr);
		mmaps[mmapcnt].m_msize = phdr[phnum].p_memsz;
		mmaps[mmapcnt].m_fsize = phdr[phnum].p_filesz;
		mmaps[mmapcnt].m_perm = (PROT_READ | PROT_WRITE | PROT_EXEC);
		mmapcnt++;
	}

	/*
	 * Generate a new link map representing the memory image created.
	 */
	if ((nlmp = elf_new_lm(lml, ofl->ofl_name, ofl->ofl_name,
	    ofl->ofl_osdynamic->os_outdata->d_buf, (ulong_t)ehdr,
	    (ulong_t)ehdr + etext, CNTL(olmp), (ulong_t)ofl->ofl_size,
	    0, 0, 0, mmaps, mmapcnt)) == 0)
		return (0);

	/*
	 * Remove this link map from the end of the link map list and copy its
	 * contents into the link map originally created for this file (we copy
	 * the contents rather than manipulate the link map pointers as parts
	 * of the dlopen code have remembered the original link map address).
	 */
	NEXT((Rt_map *)PREV(nlmp)) = 0;
	/* LINTED */
	lmc = (Lm_cntl *)alist_item_by_offset(lml->lm_lists, CNTL(nlmp));
	lmc->lc_tail = (Rt_map *)PREV(nlmp);
	if (CNTL(nlmp) == ALIST_OFF_DATA)
		lml->lm_tail = (Rt_map *)PREV(nlmp);
	lml->lm_obj--;

	PREV(nlmp) = PREV(olmp);
	NEXT(nlmp) = NEXT(olmp);
	HANDLES(nlmp) = HANDLES(olmp);
	GROUPS(nlmp) = GROUPS(olmp);
	STDEV(nlmp) = STDEV(olmp);
	STINO(nlmp) = STINO(olmp);

	FLAGS(nlmp) |= ((FLAGS(olmp) & ~FLG_RT_OBJECT) | FLG_RT_IMGALLOC);
	FLAGS1(nlmp) |= FLAGS1(olmp);
	MODE(nlmp) |= MODE(olmp);

	NAME(nlmp) = NAME(olmp);
	PATHNAME(nlmp) = PATHNAME(olmp);
	ORIGNAME(nlmp) = ORIGNAME(olmp);
	DIRSZ(nlmp) = DIRSZ(olmp);

	ld_ofl_cleanup(ofl);
	free(olmp->rt_priv);
	(void) memcpy(olmp, nlmp, sizeof (Rt_map));
	free(nlmp);
	nlmp = olmp;
	olmp = 0;

	/*
	 * Now that we've allocated our permanent Rt_map structure, expand the
	 * PATHNAME() and insert it into the FullpathNode AVL tree
	 */
	if (FLAGS1(nlmp) & FL1_RT_RELATIVE)
		(void) fullpath(nlmp, 0);
	if (fpavl_insert(lml, nlmp, PATHNAME(nlmp), 0) == 0)
		return (0);

	/*
	 * If we're being audited tell the audit library of the file we've just
	 * opened.
	 */
	if ((lml->lm_tflags | FLAGS1(nlmp)) & LML_TFLG_AUD_MASK) {
		if (audit_objopen(lmp, lmp) == 0)
			return (0);
	}
	return (nlmp);
}
