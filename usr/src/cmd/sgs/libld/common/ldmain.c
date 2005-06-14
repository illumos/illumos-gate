/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 *
 *	Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 *	Use is subject to license terms.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * ld -- link/editor main program
 */
#include	<string.h>
#include	<stdio.h>
#include	<unistd.h>
#include	<locale.h>
#include	<stdarg.h>
#include	"debug.h"
#include	"msg.h"
#include	"_libld.h"

/*
 * default library search path used if one was not supplied
 * on the command line.  Note:   These strings can not
 * use MSG_ORIG() since they are modified as part of the
 * path processing.
 */
#ifdef _ELF64
static char	def_Plibpath[] = "/lib/64:/usr/lib/64";
#else
static char	def_Plibpath[] = "/usr/ccs/lib:/lib:/usr/lib";
#endif

/*
 * The main program
 */
int
ld_main(int argc, char ** argv)
{
	char		*sgs_support;	/* SGS_SUPPORT environment string */
	Ofl_desc	*ofl = &Ofl;	/* Output file descriptor */
	Half		etype;
	uint_t		stflags;
	int		suplib = 0;

	/*
	 * Initialize signal handlers, and output file variables.
	 */
	init();
	ofl->ofl_libver = EV_CURRENT;
	ofl->ofl_e_machine = M_MACH;
	ofl->ofl_e_flags = 0;

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
	if (process_flags(ofl, argc, argv) == S_ERROR)
		return (1);
	if (ofl->ofl_flags & FLG_OF_FATAL) {
		eprintf(ERR_FATAL, MSG_INTL(MSG_ARG_FLAGS));
		return (1);
	}

	/*
	 * At this point a call such as ld -V is considered complete.
	 */
	if (ofl->ofl_flags1 & FLG_OF1_DONE)
		return (0);

	/*
	 * Initialize string tables, by default we compress the
	 * stringtables.
	 */
	if (ofl->ofl_flags1 & FLG_OF1_NCSTTAB)
		stflags = 0;
	else
		stflags = FLG_STNEW_COMPRESS;

	if ((ofl->ofl_shdrsttab = st_new(stflags)) == 0)
		return (1);
	if ((ofl->ofl_strtab = st_new(stflags)) == 0)
		return (1);
	if ((ofl->ofl_dynstrtab = st_new(stflags)) == 0)
		return (1);

	/*
	 * Determine whether any support libraries been loaded (either through
	 * the SGS_SUPPORT environment variable and/or through the -S option).
	 * By default the support library libldstab.so.1 is loaded provided the
	 * user hasn't specified their own -S libraries.
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

		DBG_CALL(Dbg_support_req(sgs_support, DBG_SUP_ENVIRON));
		if ((lib = strtok_r(sgs_support, sep, &lasts)) != NULL) {
			do {
				if (strcmp(lib,
				    MSG_ORIG(MSG_FIL_LIBSTAB)) == 0) {
					if (suplib++)
						continue;
				}
				if (ld_support_loadso(lib) == S_ERROR)
					return (ldexit());

			} while ((lib = strtok_r(NULL, sep, &lasts)) != NULL);
		}
	}
	if (lib_support.head) {
		Listnode	*lnp;
		char		*lib;

		for (LIST_TRAVERSE(&lib_support, lnp, lib)) {
			DBG_CALL(Dbg_support_req(lib, DBG_SUP_CMDLINE));
			if (ld_support_loadso(lib) == S_ERROR)
				return (ldexit());
		}
	} else {
		if (suplib == 0) {
			DBG_CALL(Dbg_support_req(MSG_ORIG(MSG_FIL_LIBSTAB),
			    DBG_SUP_DEFAULT));
			if (ld_support_loadso(MSG_ORIG(MSG_FIL_LIBSTAB)) ==
			    S_ERROR)
				return (ldexit());
		}
	}

	DBG_CALL(Dbg_ent_print(ofl->ofl_e_machine, &ofl->ofl_ents,
		(ofl->ofl_flags & FLG_OF_DYNAMIC)));
	DBG_CALL(Dbg_seg_list(ofl->ofl_e_machine, &ofl->ofl_segs));

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
	if (open_outfile(ofl) == S_ERROR)
		return (ldexit());

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
		ofl->ofl_segorigin = M_SEGM_ORIGIN;

	/*
	 * Argument pass two.  Input all libraries and objects.
	 */
	if (lib_setup(ofl) == S_ERROR)
		return (ldexit());

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

	lds_start(ofl->ofl_name, etype, argv[0]);

	/*
	 * Process all input files.
	 */
	if (process_files(ofl, argc, argv) == S_ERROR)
		return (ldexit());
	if (ofl->ofl_flags & FLG_OF_FATAL) {
		eprintf(ERR_FATAL, MSG_INTL(MSG_ARG_FILES), ofl->ofl_name);
		return (ldexit());
	}

	lds_input_done();

	/*
	 * If there were any partially initialized symbol,
	 * do preparation works.
	 */
	if (ofl->ofl_ismove.head != 0) {
		if (sunwmove_preprocess(ofl) == S_ERROR)
			return (ldexit());
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
	if (reloc_init(ofl) == S_ERROR)
		return (ldexit());

	/*
	 * Now that all symbol processing is complete see if any undefined
	 * references still remain.  If we observed undefined symbols the
	 * FLG_OF_FATAL bit will be set:  If creating a static executable, or a
	 * dynamic executable or shared object with the -zdefs flag set, this
	 * condition is fatal.  If creating a shared object with the -Bsymbolic
	 * flag set, this condition is simply a warning.
	 */
	if (sym_validate(ofl) == S_ERROR)
		return (ldexit());

	if (ofl->ofl_flags1 & FLG_OF1_OVRFLW) {
		eprintf(ERR_FATAL, MSG_INTL(MSG_ARG_FILES), ofl->ofl_name);
		return (ldexit());
	} else if (ofl->ofl_flags & FLG_OF_FATAL) {
		eprintf(ERR_FATAL, MSG_INTL(MSG_ARG_SYM_FATAL), ofl->ofl_name);
		return (ldexit());
	} else if (ofl->ofl_flags & FLG_OF_WARN)
		eprintf(ERR_WARNING, MSG_INTL(MSG_ARG_SYM_WARN));

	/*
	 * Generate any necessary sections.
	 */
	if (make_sections(ofl) == S_ERROR)
		return (ldexit());

	/*
	 * Now that all sections have been added to the output file, check to
	 * see if any section ordering was specified and if so give a warning
	 * if any ordering directives were not matched.
	 * Also, if SHF_ORDERED sections exist, set up sort key values.
	 */
	sec_validate(ofl);

	/*
	 * Having collected all the input data create the initial output file
	 * image, assign virtual addresses to the image, and generate a load
	 * map if the user requested one.
	 */
	if (create_outfile(ofl) == S_ERROR)
		return (ldexit());

	if (update_outfile(ofl) == S_ERROR)
		return (ldexit());
	if (ofl->ofl_flags & FLG_OF_GENMAP)
		ldmap_out(ofl);

	/*
	 * Build relocation sections and perform any relocation updates.
	 */
	if (reloc_process(ofl) == S_ERROR)
		return (ldexit());


#if defined(__x86) && defined(_ELF64)
	/*
	 * Fill in contents for Unwind Header
	 */
	if (populate_amd64_unwindhdr(ofl) == S_ERROR)
		return (ldexit());
#endif
	/*
	 * Finally create the files elf checksum.
	 */
	if (ofl->ofl_checksum)
		*ofl->ofl_checksum = (Xword)elf_checksum(ofl->ofl_elf);

	/*
	 * We're done, so make sure the updates are flushed to the output file.
	 */
	if ((ofl->ofl_size = elf_update(ofl->ofl_welf, ELF_C_WRITE)) == 0) {
		eprintf(ERR_ELF, MSG_INTL(MSG_ELF_UPDATE), ofl->ofl_name);
		return (ldexit());
	}

	lds_atexit(0);

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

/* VARARGS1 */
void
dbg_print(const char *format, ...)
{
	static char	*prestr = 0;
	va_list		args;

	if (dbg_mask & DBG_G_SNAME) {
		/*
		 * If the debugging options have requested each diagnostic line
		 * be prepended by a name create a prefix string.
		 */
		if ((prestr == 0) && Ofl.ofl_name) {
			const char	*name, *cls;
			size_t		len;

			/*
			 * Select the fullname or basename of the output file
			 * being created.
			 */
			if (dbg_mask & DBG_G_FNAME)
				name = Ofl.ofl_name;
			else {
				if ((name = strrchr(Ofl.ofl_name, '/')) == 0)
					name = Ofl.ofl_name;
				else
					name++;
			}
			len = strlen(name) +
			    strlen(MSG_INTL(MSG_DBG_NAME_FMT)) + 1;

			/*
			 * Add the output file class if required.
			 */
			if (dbg_mask & DBG_G_CLASS) {
#if	defined(_ELF64)
				len += MSG_DBG_CLS64_FMT_SIZE;
				cls = MSG_ORIG(MSG_DBG_CLS64_FMT);
#else
				len += MSG_DBG_CLS32_FMT_SIZE;
				cls = MSG_ORIG(MSG_DBG_CLS32_FMT);
#endif
			}

			/*
			 * Allocate a string to build the prefix.
			 */
			if ((prestr = libld_malloc(len)) == 0)
				prestr = (char *)MSG_INTL(MSG_DBG_DFLT_FMT);
			else {
				(void) snprintf(prestr, len,
				    MSG_INTL(MSG_DBG_NAME_FMT), name);
				if (dbg_mask & DBG_G_CLASS)
					(void) strcat(prestr, cls);
			}
		}
		if (prestr)
			(void) fputs(prestr, stderr);
		else
			(void) fputs(MSG_INTL(MSG_DBG_AOUT_FMT), stderr);
	} else
		(void) fputs(MSG_INTL(MSG_DBG_DFLT_FMT), stderr);

	va_start(args, format);
	(void) vfprintf(stderr, format, args);
	(void) fprintf(stderr, MSG_ORIG(MSG_STR_NL));
	va_end(args);
}
