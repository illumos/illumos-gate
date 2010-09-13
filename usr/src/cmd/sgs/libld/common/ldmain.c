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
 * Copyright (c) 1989, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * Processing of relocatable objects and shared objects.
 */

/*
 * ld -- link/editor main program
 */
#include	<sys/types.h>
#include	<sys/time.h>
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
 * ld-centric wrapper on top of veprintf():
 * - Accepts output descriptor rather than linkmap list
 * - Sets the FLG_OF_FATAL/FLG_OF_WARN flags as necessary
 */
void
ld_eprintf(Ofl_desc *ofl, Error error, const char *format, ...)
{
	va_list	args;

	/* Set flag indicating type of error being issued */
	switch (error) {
	case ERR_NONE:
	case ERR_WARNING_NF:
		break;
	case ERR_WARNING:
		ofl->ofl_flags |= FLG_OF_WARN;
		break;
	case ERR_GUIDANCE:
		if ((ofl->ofl_guideflags & FLG_OFG_ENABLE) == 0)
			return;
		ofl->ofl_guideflags |= FLG_OFG_ISSUED;
		ofl->ofl_flags |= FLG_OF_WARN;
		break;
	default:
		ofl->ofl_flags |= FLG_OF_FATAL;
	}

	/* Issue the error */
	va_start(args, format);
	veprintf(ofl->ofl_lml, error, format, args);
	va_end(args);
}

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
	ofl_flag_t	save_flg_of_warn;

	/*
	 * Establish a base time.  Total time diagnostics are relative to
	 * entering the link-editor here.
	 */
	(void) gettimeofday(&DBG_TOTALTIME, NULL);
	DBG_DELTATIME = DBG_TOTALTIME;

	/* Output file descriptor */
	if ((ofl = libld_calloc(1, sizeof (Ofl_desc))) == 0)
		return (1);

	/* Initialize target state */
	if (ld_init_target(NULL, mach) != 0)
		return (1);

	/*
	 * Set up the default output ELF header to satisfy diagnostic
	 * requirements, and initialize the machine and class details.
	 */
	ofl->ofl_dehdr = &def_ehdr;
	def_ehdr.e_ident[EI_CLASS] = ld_targ.t_m.m_class;
	def_ehdr.e_ident[EI_DATA] = ld_targ.t_m.m_data;
	def_ehdr.e_machine = ld_targ.t_m.m_mach;

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
	 * check for consistency.  Return from ld_process_flags() marks the
	 * end of mapfile processing.  The entrance criteria and segment
	 * descriptors are complete and in their final form.
	 */
	if (ld_process_flags(ofl, argc, argv) == S_ERROR) {
		/* If any ERR_GUIDANCE messages were issued, add a summary */
		if (ofl->ofl_guideflags & FLG_OFG_ISSUED)
			ld_eprintf(ofl, ERR_GUIDANCE,
			    MSG_INTL(MSG_GUIDE_SUMMARY));
		return (1);
	}
	if (ofl->ofl_flags & FLG_OF_FATAL) {
		ld_eprintf(ofl, ERR_FATAL, MSG_INTL(MSG_ARG_FLAGS));
		/* If any ERR_GUIDANCE messages were issued, add a summary */
		if (ofl->ofl_guideflags & FLG_OFG_ISSUED)
			ld_eprintf(ofl, ERR_GUIDANCE,
			    MSG_INTL(MSG_GUIDE_SUMMARY));
		return (1);
	}

	/*
	 * At this point a call such as ld -V is considered complete.
	 */
	if (ofl->ofl_flags1 & FLG_OF1_DONE)
		return (0);

	/* Initialize signal handler */
	ld_init_sighandler(ofl);

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

	if (sgs_support && sgs_support[0]) {
		const char	*sep = MSG_ORIG(MSG_STR_COLON);
		char		*lib;
		char		*lasts;

		DBG_CALL(Dbg_support_req(ofl->ofl_lml, sgs_support,
		    DBG_SUP_ENVIRON));
		if ((lib = strtok_r(sgs_support, sep, &lasts)) != NULL) {
			do {
				if (ld_sup_loadso(ofl, lib) == S_ERROR)
					return (ld_exit(ofl));
				DBG_CALL(Dbg_util_nl(ofl->ofl_lml, DBG_NL_STD));

			} while ((lib = strtok_r(NULL, sep, &lasts)) != NULL);
		}
	}
	if (lib_support) {
		Aliste	idx;
		char	*lib;

		for (APLIST_TRAVERSE(lib_support, idx, lib)) {
			DBG_CALL(Dbg_support_req(ofl->ofl_lml, lib,
			    DBG_SUP_CMDLINE));
			if (ld_sup_loadso(ofl, lib) == S_ERROR)
				return (ld_exit(ofl));
			DBG_CALL(Dbg_util_nl(ofl->ofl_lml, DBG_NL_STD));
		}
	}

	DBG_CALL(Dbg_ent_print(ofl->ofl_lml,
	    ofl->ofl_dehdr->e_ident[EI_OSABI], ofl->ofl_dehdr->e_machine,
	    ofl->ofl_ents));
	DBG_CALL(Dbg_seg_list(ofl->ofl_lml,
	    ofl->ofl_dehdr->e_ident[EI_OSABI], ofl->ofl_dehdr->e_machine,
	    ofl->ofl_segs));

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
	 * is in use (historic).
	 */
	if (Plibpath == NULL)
		Plibpath = def_Plibpath;

	if (ofl->ofl_rpath == NULL) {
		char	*rpath;

		if (((rpath = getenv(MSG_ORIG(MSG_LD_RUN_PATH))) != NULL) &&
		    rpath[0])
			ofl->ofl_rpath = rpath;
	}

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
		ld_eprintf(ofl, ERR_FATAL, MSG_INTL(MSG_ARG_FILES),
		    ofl->ofl_name);
		return (ld_exit(ofl));
	}

	ld_sup_input_done(ofl);

	/*
	 * Now that all input section processing is complete, validate and
	 * process any SHT_SUNW_move sections.
	 */
	if (ofl->ofl_ismove && (ld_process_move(ofl) == S_ERROR))
		return (ld_exit(ofl));

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
	 * We need to know if FLG_OF_WARN is currently set, in case
	 * we need to honor a -z fatal-warnings request. However, we also
	 * need to know if a warning due to symbol validation results from
	 * the upcoming call to ld_sym_validate() in order to issue the
	 * appropriate message for it. So we save the current value,
	 * and clear the main flag.
	 */
	save_flg_of_warn = ofl->ofl_flags & FLG_OF_WARN;
	ofl->ofl_flags &= ~FLG_OF_WARN;

	if (ld_sym_validate(ofl) == S_ERROR)
		return (ld_exit(ofl));

	/*
	 * Now that all symbol processing is complete see if any undefined
	 * references still remain.  If we observed undefined symbols the
	 * FLG_OF_FATAL bit will be set:  If creating a static executable, or a
	 * dynamic executable or shared object with the -zdefs flag set, this
	 * condition is fatal.  If creating a shared object with the -Bsymbolic
	 * flag set, this condition is simply a warning.
	 */
	if (ofl->ofl_flags & FLG_OF_FATAL)
		ld_eprintf(ofl, ERR_FATAL, MSG_INTL(MSG_ARG_SYM_FATAL),
		    ofl->ofl_name);
	else if (ofl->ofl_flags & FLG_OF_WARN)
		ld_eprintf(ofl, ERR_WARNING, MSG_INTL(MSG_ARG_SYM_WARN));

	/*
	 * Guidance: Use -z defs|nodefs when building shared objects.
	 *
	 * ld_sym_validate() will mask this guidance message out unless we are
	 * intended to send it here, so all we need to do is use OFL_GUIDANCE()
	 * to decide whether to issue it or not.
	 */
	if (OFL_GUIDANCE(ofl, FLG_OFG_NO_DEFS))
		ld_eprintf(ofl, ERR_GUIDANCE, MSG_INTL(MSG_GUIDE_DEFS));

	/*
	 * Symbol processing was the final step before we start producing the
	 * output object. At this time, if we've seen warnings and the
	 * -z fatal-warnings option is specified, promote them to fatal, which
	 * will cause us to exit without creating an object.
	 *
	 * We didn't do this as the warnings were reported in order to
	 * maximize the number of problems a given link-editor invocation
	 * can diagnose. This is safe, since warnings are by definition events
	 * one can choose to ignore.
	 */
	if (((ofl->ofl_flags | save_flg_of_warn) &
	    (FLG_OF_WARN | FLG_OF_FATWARN)) ==
	    (FLG_OF_WARN | FLG_OF_FATWARN))
		ofl->ofl_flags |= FLG_OF_FATAL;

	/*
	 * If fatal errors occurred in symbol processing, or due to warnings
	 * promoted by -z fatal-warnings, this is the end of the line.
	 */
	if (ofl->ofl_flags & FLG_OF_FATAL)
		return (ld_exit(ofl));

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
	if (ofl->ofl_flags & (FLG_OF_OS_ORDER | FLG_OF_KEY))
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

	/*
	 * Fill in contents for unwind header (.eh_frame_hdr)
	 */
	if (ld_unwind_populate_hdr(ofl) == S_ERROR)
		return (ld_exit(ofl));

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
		ld_eprintf(ofl, ERR_ELF, MSG_INTL(MSG_ELF_SWAP_WRIMAGE),
		    ofl->ofl_name);
		return (ld_exit(ofl));
	}

	/*
	 * We're done, so make sure the updates are flushed to the output file.
	 */
	if ((ofl->ofl_size = elf_update(ofl->ofl_welf, ELF_C_WRITE)) == 0) {
		ld_eprintf(ofl, ERR_ELF, MSG_INTL(MSG_ELF_UPDATE),
		    ofl->ofl_name);
		return (ld_exit(ofl));
	}

	ld_sup_atexit(ofl, 0);

	DBG_CALL(Dbg_statistics_ld(ofl));
	DBG_CALL(Dbg_basic_finish(ofl->ofl_lml));

	/*
	 * Wrap up debug output file if one is open
	 */
	dbg_cleanup();

	/* If any ERR_GUIDANCE messages were issued, add a summary */
	if (ofl->ofl_guideflags & FLG_OFG_ISSUED)
		ld_eprintf(ofl, ERR_GUIDANCE, MSG_INTL(MSG_GUIDE_SUMMARY));

	/*
	 * For performance reasons we don't actually free up the memory we've
	 * allocated, it will be freed when we exit.
	 *
	 * But the below line can be uncommented if/when we want to measure how
	 * our memory consumption and freeing are doing.  We should be able to
	 * free all the memory that has been allocated as part of the link-edit
	 * process.
	 */
	/* ld_ofl_cleanup(ofl); */
	return (0);
}

/*
 * Cleanup an Ifl_desc.
 */
static void
ifl_list_cleanup(APlist *apl)
{
	Aliste		idx;
	Ifl_desc	*ifl;

	for (APLIST_TRAVERSE(apl, idx, ifl)) {
		if (ifl->ifl_elf)
			(void) elf_end(ifl->ifl_elf);
	}
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
	Aliste		idx;

	ifl_list_cleanup(ofl->ofl_objs);
	ofl->ofl_objs = NULL;
	ifl_list_cleanup(ofl->ofl_sos);
	ofl->ofl_sos = NULL;

	for (APLIST_TRAVERSE(ofl->ofl_ars, idx, adp)) {
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
	ofl->ofl_ars = NULL;

	(void) elf_end(ofl->ofl_elf);
	(void) elf_end(ofl->ofl_welf);

	for (chp = ld_heap, php = NULL; chp; php = chp, chp = chp->lh_next) {
		if (php)
			(void) munmap((void *)php,
			    (size_t)php->lh_end - (size_t)php);
	}
	if (php)
		(void) munmap((void *)php, (size_t)php->lh_end - (size_t)php);

	ld_heap = NULL;
}
