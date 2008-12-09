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

/*
 * Processing of relocatable objects and shared objects.
 */

/*
 * ld -- link/editor main program
 */
#include	<sys/types.h>
#include	<sys/mman.h>
#include	<string.h>
#include	<stdio.h>
#include	<locale.h>
#include	<stdarg.h>
#include	<debug.h>
#include	"msg.h"
#include	"_libld.h"

/*
 * All target specific code is referenced via this global variable, which
 * is initialized in ld_main(). This allows the linker to function as
 * a cross linker, by vectoring to the target-specific code for the
 * current target machine.
 */
Target		ld_targ;

/*
 * A default library search path is used if one was not supplied on the command
 * line.  Note: these strings can not use MSG_ORIG() since they are modified as
 * part of the path processing.
 */
#if	defined(_ELF64)
static char	def_Plibpath[] = "/lib/64:/usr/lib/64";
#else
static char	def_Plibpath[] = "/usr/ccs/lib:/lib:/usr/lib";
#endif

/*
 * A default elf header provides for simplifying diagnostic processing.
 */
static Ehdr	def_ehdr = { { ELFMAG0, ELFMAG1, ELFMAG2, ELFMAG3,
			    ELFCLASSNONE, ELFDATANONE }, 0, EM_NONE,
			    EV_CURRENT };

/*
 * Establish the global state necessary to link the desired machine
 * target, as reflected by the ld_targ global variable.
 */
int
ld_init_target(Lm_list *lml, Half mach)
{
	switch (mach) {
	case EM_386:
	case EM_AMD64:
		ld_targ = *ld_targ_init_x86();
		break;

	case EM_SPARC:
	case EM_SPARC32PLUS:
	case EM_SPARCV9:
		ld_targ = *ld_targ_init_sparc();
		break;

	default:
		{
			Conv_inv_buf_t	inv_buf;

			eprintf(lml, ERR_FATAL, MSG_INTL(MSG_TARG_UNSUPPORTED),
			    conv_ehdr_mach(mach, 0, &inv_buf));
			return (1);
		}
	}

	return (0);
}


/*
 * The main program
 */
int
ld_main(int argc, char **argv, Half mach)
{
	char		*sgs_support;	/* SGS_SUPPORT environment string */
	Half		etype;
	Ofl_desc	*ofl;

	/*
	 * Initialize signal handlers, and output file variables.  Establish a
	 * default output ELF header to satisfy diagnostic requirements.
	 */
	if ((ofl = libld_calloc(1, sizeof (Ofl_desc))) == 0)
		return (1);

	/* Initilize target state */
	if (ld_init_target(NULL, mach) != 0)
		return (1);

	/*
	 * Set up the output ELF header, and initialize the machine
	 * and class details.
	 */
	ofl->ofl_dehdr = &def_ehdr;
	def_ehdr.e_ident[EI_CLASS] = ld_targ.t_m.m_class;
	def_ehdr.e_ident[EI_DATA] = ld_targ.t_m.m_data;
	def_ehdr.e_machine = ld_targ.t_m.m_mach;

	ld_init(ofl);

	/*
	 * Build up linker version string
	 */
	if ((ofl->ofl_sgsid = (char *)libld_calloc(MSG_SGS_ID_SIZE +
	    strlen(link_ver_string) + 1, 1)) == NULL)
		return (1);
	(void) strcpy(ofl->ofl_sgsid, MSG_ORIG(MSG_SGS_ID));
	(void) strcat(ofl->ofl_sgsid, link_ver_string);

	/*
	 * Argument pass one.  Get all the input flags (skip any files) and
	 * check for consistency.  After this point any map file processing
	 * would have been completed and the entrance criteria and segment
	 * descriptor lists will be complete.
	 */
	if (ld_process_flags(ofl, argc, argv) == S_ERROR)
		return (1);
	if (ofl->ofl_flags & FLG_OF_FATAL) {
		eprintf(ofl->ofl_lml, ERR_FATAL, MSG_INTL(MSG_ARG_FLAGS));
		return (1);
	}

	/*
	 * At this point a call such as ld -V is considered complete.
	 */
	if (ofl->ofl_flags1 & FLG_OF1_DONE)
		return (0);

	/*
	 * Determine whether any support libraries should be loaded,
	 * (either through the SGS_SUPPORT environment variable and/or
	 * through the -S option).
	 */
#if	defined(_LP64)
	if ((sgs_support = getenv(MSG_ORIG(MSG_SGS_SUPPORT_64))) == NULL)
#else
	if ((sgs_support = getenv(MSG_ORIG(MSG_SGS_SUPPORT_32))) == NULL)
#endif
		sgs_support = getenv(MSG_ORIG(MSG_SGS_SUPPORT));

	if (sgs_support && (*sgs_support != '\0')) {
		const char	*sep = MSG_ORIG(MSG_STR_COLON);
		char		*lib;
		char		*lasts;

		DBG_CALL(Dbg_support_req(ofl->ofl_lml, sgs_support,
		    DBG_SUP_ENVIRON));
		if ((lib = strtok_r(sgs_support, sep, &lasts)) != NULL) {
			do {
				if (ld_sup_loadso(ofl, lib) == S_ERROR)
					return (ld_exit(ofl));

			} while ((lib = strtok_r(NULL, sep, &lasts)) != NULL);
		}
		DBG_CALL(Dbg_util_nl(ofl->ofl_lml, DBG_NL_STD));
	}
	if (lib_support.head) {
		Listnode	*lnp;
		char		*lib;

		for (LIST_TRAVERSE(&lib_support, lnp, lib)) {
			DBG_CALL(Dbg_support_req(ofl->ofl_lml, lib,
			    DBG_SUP_CMDLINE));
			if (ld_sup_loadso(ofl, lib) == S_ERROR)
				return (ld_exit(ofl));
		}
	}
	DBG_CALL(Dbg_util_nl(ofl->ofl_lml, DBG_NL_STD));

	DBG_CALL(Dbg_ent_print(ofl->ofl_lml, ofl->ofl_dehdr->e_machine,
	    &ofl->ofl_ents, (ofl->ofl_flags & FLG_OF_DYNAMIC) != 0));
	DBG_CALL(Dbg_seg_list(ofl->ofl_lml, ofl->ofl_dehdr->e_machine,
	    &ofl->ofl_segs));

	/*
	 * The objscnt and soscnt variables were used to estimate the expected
	 * input files, and size the symbol hash buckets accordingly.  Reset
	 * these values now, so as to gain an accurate count from pass two, for
	 * later statistics diagnostics.
	 */
	ofl->ofl_objscnt = ofl->ofl_soscnt = 0;

	/*
	 * Determine whether we can create the file before going any further.
	 */
	if (ld_open_outfile(ofl) == S_ERROR)
		return (ld_exit(ofl));

	/*
	 * If the user didn't supply a library path supply a default.  And, if
	 * no run-path has been specified (-R), see if the environment variable
	 * is in use (historic).  Also assign a default starting address.
	 * Don't use MSG_ORIG() for these strings, they're written to later.
	 */
	if (Plibpath == NULL)
		Plibpath = def_Plibpath;

	if (ofl->ofl_rpath == NULL) {
		char *rpath;
		if (((rpath = getenv(MSG_ORIG(MSG_LD_RUN_PATH))) != NULL) &&
		    (strcmp((const char *)rpath, MSG_ORIG(MSG_STR_EMPTY))))
			ofl->ofl_rpath = rpath;
	}
	if (ofl->ofl_flags & FLG_OF_EXEC)
		ofl->ofl_segorigin = ld_targ.t_m.m_segm_origin;

	/*
	 * Argument pass two.  Input all libraries and objects.
	 */
	if (ld_lib_setup(ofl) == S_ERROR)
		return (ld_exit(ofl));

	/*
	 * Call ld_start() with the etype of our output file and the
	 * output file name.
	 */
	if (ofl->ofl_flags & FLG_OF_SHAROBJ)
		etype = ET_DYN;
	else if (ofl->ofl_flags & FLG_OF_RELOBJ)
		etype = ET_REL;
	else
		etype = ET_EXEC;

	ld_sup_start(ofl, etype, argv[0]);

	/*
	 * Process all input files.
	 */
	if (ld_process_files(ofl, argc, argv) == S_ERROR)
		return (ld_exit(ofl));
	if (ofl->ofl_flags & FLG_OF_FATAL) {
		eprintf(ofl->ofl_lml, ERR_FATAL, MSG_INTL(MSG_ARG_FILES),
		    ofl->ofl_name);
		return (ld_exit(ofl));
	}

	ld_sup_input_done(ofl);

	/*
	 * If there were any partially initialized symbol,
	 * do preparation works.
	 */
	if (ofl->ofl_ismove.head != 0) {
		if (ld_sunwmove_preprocess(ofl) == S_ERROR)
			return (ld_exit(ofl));
	}

	/*
	 * Before validating all symbols count the number of relocation entries.
	 * If copy relocations exist, COMMON symbols must be generated which are
	 * assigned to the executables .bss.  During sym_validate() the actual
	 * size and alignment of the .bss is calculated.  Doing things in this
	 * order reduces the number of symbol table traversals required (however
	 * it does take a little longer for the user to be told of any undefined
	 * symbol errors).
	 */
	if (ld_reloc_init(ofl) == S_ERROR)
		return (ld_exit(ofl));

	/*
	 * Now that all symbol processing is complete see if any undefined
	 * references still remain.  If we observed undefined symbols the
	 * FLG_OF_FATAL bit will be set:  If creating a static executable, or a
	 * dynamic executable or shared object with the -zdefs flag set, this
	 * condition is fatal.  If creating a shared object with the -Bsymbolic
	 * flag set, this condition is simply a warning.
	 */
	if (ld_sym_validate(ofl) == S_ERROR)
		return (ld_exit(ofl));

	if (ofl->ofl_flags1 & FLG_OF1_OVRFLW) {
		eprintf(ofl->ofl_lml, ERR_FATAL, MSG_INTL(MSG_ARG_FILES),
		    ofl->ofl_name);
		return (ld_exit(ofl));
	} else if (ofl->ofl_flags & FLG_OF_FATAL) {
		eprintf(ofl->ofl_lml, ERR_FATAL, MSG_INTL(MSG_ARG_SYM_FATAL),
		    ofl->ofl_name);
		return (ld_exit(ofl));
	} else if (ofl->ofl_flags & FLG_OF_WARN)
		eprintf(ofl->ofl_lml, ERR_WARNING, MSG_INTL(MSG_ARG_SYM_WARN));

	/*
	 * Generate any necessary sections.
	 */
	if (ld_make_sections(ofl) == S_ERROR)
		return (ld_exit(ofl));

	/*
	 * Now that all sections have been added to the output file, determine
	 * whether any mapfile section ordering was specified, and verify that
	 * all mapfile ordering directives have been matched.  Issue a warning
	 * for any directives that have not been matched.
	 * Also, if SHF_ORDERED sections exist, set up sort key values.
	 */
	if (ofl->ofl_flags & (FLG_OF_SECORDER | FLG_OF_KEY))
		ld_sec_validate(ofl);

	/*
	 * Having collected all the input data create the initial output file
	 * image, assign virtual addresses to the image, and generate a load
	 * map if the user requested one.
	 */
	if (ld_create_outfile(ofl) == S_ERROR)
		return (ld_exit(ofl));

	if (ld_update_outfile(ofl) == S_ERROR)
		return (ld_exit(ofl));
	if (ofl->ofl_flags & FLG_OF_GENMAP)
		ld_map_out(ofl);

	/*
	 * Build relocation sections and perform any relocation updates.
	 */
	if (ld_reloc_process(ofl) == S_ERROR)
		return (ld_exit(ofl));

#if	defined(_ELF64)
	/*
	 * Fill in contents for Unwind Header
	 */
	if ((ld_targ.t_uw.uw_populate_unwindhdr != NULL) &&
	    ((*ld_targ.t_uw.uw_populate_unwindhdr)(ofl) == S_ERROR))
		return (ld_exit(ofl));
#endif

	/*
	 * Finally create the files elf checksum.
	 */
	if (ofl->ofl_checksum)
		*ofl->ofl_checksum = (Xword)elf_checksum(ofl->ofl_elf);

	/*
	 * If this is a cross link to a target with a different byte
	 * order than the linker, swap the data to the target byte order.
	 */
	if (((ofl->ofl_flags1 & FLG_OF1_ENCDIFF) != 0) &&
	    (_elf_swap_wrimage(ofl->ofl_elf) != 0)) {
		eprintf(ofl->ofl_lml, ERR_ELF, MSG_INTL(MSG_ELF_SWAP_WRIMAGE),
		    ofl->ofl_name);
		return (ld_exit(ofl));
	}

	/*
	 * We're done, so make sure the updates are flushed to the output file.
	 */
	if ((ofl->ofl_size = elf_update(ofl->ofl_welf, ELF_C_WRITE)) == 0) {
		eprintf(ofl->ofl_lml, ERR_ELF, MSG_INTL(MSG_ELF_UPDATE),
		    ofl->ofl_name);
		return (ld_exit(ofl));
	}

	ld_sup_atexit(ofl, 0);

	DBG_CALL(Dbg_statistics_ld(ofl));

	/*
	 * For performance reasons we don't actually free up the memory we've
	 * allocated, it will be freed when we exit.
	 *
	 * But the below line can be uncommented if/when we want to measure how
	 * our memory consumption and freeing are doing.  We should be able to
	 * free all the memory that has been allocated as part of the link-edit
	 * process.
	 *
	 * ofl_cleanup(ofl);
	 */
	return (0);
}

/*
 * Cleanup an Ifl_desc.
 */
static void
ifl_list_cleanup(List *ifl_list)
{
	Listnode	*lnp;
	Ifl_desc	*ifl;

	for (LIST_TRAVERSE(ifl_list, lnp, ifl))
		if (ifl->ifl_elf)
			(void) elf_end(ifl->ifl_elf);
	ifl_list->head = 0;
	ifl_list->tail = 0;
}

/*
 * Cleanup all memory that has been dynamically allocated during libld
 * processing and elf_end() all Elf descriptors that are still open.
 */
void
ld_ofl_cleanup(Ofl_desc *ofl)
{
	Ld_heap		*chp, *php;
	Ar_desc		*adp;
	Listnode	*lnp;

	ifl_list_cleanup(&ofl->ofl_objs);
	ifl_list_cleanup(&ofl->ofl_sos);

	for (LIST_TRAVERSE(&ofl->ofl_ars, lnp, adp)) {
		Ar_aux		*aup;
		Elf_Arsym	*arsym;

		for (arsym = adp->ad_start, aup = adp->ad_aux;
		    arsym->as_name; ++arsym, ++aup) {
			if ((aup->au_mem) && (aup->au_mem != FLG_ARMEM_PROC)) {
				(void) elf_end(aup->au_mem->am_elf);

				/*
				 * Null out all entries to this member so
				 * that we don't attempt to elf_end() it again.
				 */
				ld_ar_member(adp, arsym, aup, 0);
			}
		}
		(void) elf_end(adp->ad_elf);
	}

	(void) elf_end(ofl->ofl_elf);
	(void) elf_end(ofl->ofl_welf);

	for (chp = ld_heap, php = 0; chp; php = chp, chp = chp->lh_next) {
		if (php)
			(void) munmap((void *)php,
			    (size_t)php->lh_end - (size_t)php);
	}
	if (php)
		(void) munmap((void *)php, (size_t)php->lh_end - (size_t)php);

	ld_heap = 0;
}
