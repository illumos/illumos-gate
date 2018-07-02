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
 * Copyright (c) 1994, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include	<stdio.h>
#include	<dlfcn.h>
#include	<libelf.h>
#include	<link.h>
#include	<debug.h>
#include	"msg.h"
#include	"_libld.h"

/*
 * Table which defines the default functions to be called by the library
 * SUPPORT (-S <libname>).  These functions can be redefined by the
 * ld_support_loadso() routine.
 */
static Support_list support[LDS_NUM] = {
	{MSG_ORIG(MSG_SUP_VERSION),	NULL},	/* LDS_VERSION */
	{MSG_ORIG(MSG_SUP_INPUT_DONE),	NULL},	/* LDS_INPUT_DONE */
#if	defined(_ELF64)
	{MSG_ORIG(MSG_SUP_START_64),	NULL},	/* LDS_START */
	{MSG_ORIG(MSG_SUP_ATEXIT_64),	NULL},	/* LDS_ATEXIT */
	{MSG_ORIG(MSG_SUP_OPEN_64),	NULL},	/* LDS_OPEN */
	{MSG_ORIG(MSG_SUP_FILE_64),	NULL},	/* LDS_FILE */
	{MSG_ORIG(MSG_SUP_INSEC_64),	NULL},	/* LDS_INSEC */
	{MSG_ORIG(MSG_SUP_SEC_64),	NULL}	/* LDS_SEC */
#else	/* Elf32 */
	{MSG_ORIG(MSG_SUP_START),	NULL},	/* LDS_START */
	{MSG_ORIG(MSG_SUP_ATEXIT),	NULL},	/* LDS_ATEXIT */
	{MSG_ORIG(MSG_SUP_OPEN),	NULL},	/* LDS_OPEN */
	{MSG_ORIG(MSG_SUP_FILE),	NULL},	/* LDS_FILE */
	{MSG_ORIG(MSG_SUP_INSEC),	NULL},	/* LDS_INSEC */
	{MSG_ORIG(MSG_SUP_SEC),		NULL}	/* LDS_SEC */
#endif
};

/*
 * Loads in a support shared object specified using the SGS_SUPPORT environment
 * variable or the -S ld option, and determines which interface functions are
 * provided by that object.
 */
uintptr_t
ld_sup_loadso(Ofl_desc *ofl, const char *obj)
{
	void	*handle, *fptr;
	uint_t	interface, version = LD_SUP_VERSION1;

	/*
	 * Load the required support library.  If we are unable to load it fail
	 * with a fatal error.
	 */
	if ((handle = dlopen(obj, (RTLD_LAZY | RTLD_FIRST))) == NULL) {
		ld_eprintf(ofl, ERR_FATAL, MSG_INTL(MSG_SUP_NOLOAD),
		    obj, dlerror());
		return (S_ERROR);
	}

	for (interface = 0; interface < LDS_NUM; interface++) {
		Func_list	fl;

		if ((fptr = dlsym(handle, support[interface].sup_name)) == NULL)
			continue;

		DBG_CALL(Dbg_support_load(ofl->ofl_lml, obj,
		    support[interface].sup_name));

		if (interface == LDS_VERSION) {
			DBG_CALL(Dbg_support_action(ofl->ofl_lml, obj,
			    support[LDS_VERSION].sup_name, LDS_VERSION, 0));

			version = ((uint_t(*)())fptr)(LD_SUP_VCURRENT);

			/*
			 * If version is LD_SUP_VNONE, unload the support
			 * library and act as if it was never requested.
			 * This provides the support library with a mechanism
			 * for opting out of the process.
			 *
			 * Note that this depends on LDS_VERSION being the
			 * first item in support[]. If this were not true,
			 * then other functions from the library might be
			 * entered into the function lists, and unloading
			 * the object would cause corruption.
			 */
			assert(LDS_VERSION == 0);
			if (version == LD_SUP_VNONE) {
				DBG_CALL(Dbg_support_vnone(ofl->ofl_lml,
				    obj));
				(void) dlclose(handle);
				return (1);
			}

			/*
			 * If the support library has a version higher
			 * than we support, we are unable to accept it.
			 */
			if (version > LD_SUP_VCURRENT) {
				ld_eprintf(ofl, ERR_FATAL,
				    MSG_INTL(MSG_SUP_BADVERSION), obj,
				    LD_SUP_VCURRENT, version);
				(void) dlclose(handle);
				return (S_ERROR);
			}
		}

		fl.fl_obj = obj;
		fl.fl_fptr = fptr;
		fl.fl_version = version;
		if (alist_append(&support[interface].sup_funcs, &fl,
		    sizeof (Func_list), AL_CNT_SUPPORT) == NULL)
			return (S_ERROR);
	}
	return (1);
}

/*
 * Wrapper routines for the ld support library calls.
 */
void
ld_sup_start(Ofl_desc *ofl, const Half etype, const char *caller)
{
	Func_list	*flp;
	Aliste		idx;

	for (ALIST_TRAVERSE(support[LDS_START].sup_funcs, idx, flp)) {
		DBG_CALL(Dbg_support_action(ofl->ofl_lml, flp->fl_obj,
		    support[LDS_START].sup_name, LDS_START, ofl->ofl_name));
		(*flp->fl_fptr)(ofl->ofl_name, etype, caller);
	}
}

void
ld_sup_atexit(Ofl_desc *ofl, int ecode)
{
	Func_list	*flp;
	Aliste		idx;

	for (ALIST_TRAVERSE(support[LDS_ATEXIT].sup_funcs, idx, flp)) {
		DBG_CALL(Dbg_support_action(ofl->ofl_lml, flp->fl_obj,
		    support[LDS_ATEXIT].sup_name, LDS_ATEXIT, 0));
		(*flp->fl_fptr)(ecode);
	}
}

void
ld_sup_open(Ofl_desc *ofl, const char **opath, const char **ofile, int *ofd,
    int flags, Elf **oelf, Elf *ref, size_t off, const Elf_Kind ekind)
{
	Func_list	*flp;
	Aliste		idx;

	for (ALIST_TRAVERSE(support[LDS_OPEN].sup_funcs, idx, flp)) {
		const char	*npath = *opath;
		const char	*nfile = *ofile;
		Elf		*nelf = *oelf;
		int		nfd = *ofd;
		int		_flags = 0;

		/*
		 * This interface was introduced in VERSION3.  Only call this
		 * function for libraries reporting support for version 3 or
		 * above.
		 */
		if (flp->fl_version < LD_SUP_VERSION3)
			continue;

		if (!(flags & FLG_IF_CMDLINE))
			_flags |= LD_SUP_DERIVED;
		if (!(flags & FLG_IF_NEEDED))
			_flags |= LD_SUP_INHERITED;
		if (flags & FLG_IF_EXTRACT)
			_flags |= LD_SUP_EXTRACTED;

		/*
		 * If the present object is an extracted archive member, make
		 * sure the archive offset is reset so that the caller can
		 * obtain an ELF descriptor to the same member (an elf_begin()
		 * moves the offset to the next member).
		 */
		if (flags & FLG_IF_EXTRACT)
			(void) elf_rand(ref, off);

		DBG_CALL(Dbg_support_action(ofl->ofl_lml, flp->fl_obj,
		    support[LDS_OPEN].sup_name, LDS_OPEN, *opath));
		(*flp->fl_fptr)(&npath, &nfile, &nfd, _flags, &nelf, ref, off,
		    ekind);

		/*
		 * If the file descriptor, ELF descriptor, or file names have
		 * been modified, then diagnose the differences and return the
		 * new data.  As a basic test, make sure the support library
		 * hasn't nulled out data ld(1) will try and dereference.
		 */
		if ((npath != *opath) || (nfd != *ofd) || (nelf != *oelf)) {
			DBG_CALL(Dbg_file_modified(ofl->ofl_lml, flp->fl_obj,
			    *opath, npath, *ofd, nfd, *oelf, nelf));
			if (npath)
				*opath = npath;
			if (nfile)
				*ofile = nfile;
			*ofd = nfd;
			*oelf = nelf;
		}
	}
}

void
ld_sup_file(Ofl_desc *ofl, const char *ifile, const Elf_Kind ekind, int flags,
    Elf *elf)
{
	Func_list	*flp;
	Aliste		idx;

	for (ALIST_TRAVERSE(support[LDS_FILE].sup_funcs, idx, flp)) {
		int	_flags = 0;

		if (!(flags & FLG_IF_CMDLINE))
			_flags |= LD_SUP_DERIVED;
		if (!(flags & FLG_IF_NEEDED))
			_flags |= LD_SUP_INHERITED;
		if (flags & FLG_IF_EXTRACT)
			_flags |= LD_SUP_EXTRACTED;

		DBG_CALL(Dbg_support_action(ofl->ofl_lml, flp->fl_obj,
		    support[LDS_FILE].sup_name, LDS_FILE, ifile));
		(*flp->fl_fptr)(ifile, ekind, _flags, elf);
	}
}

uintptr_t
ld_sup_input_section(Ofl_desc *ofl, Ifl_desc *ifl, const char *sname,
    Shdr **oshdr, Word ndx, Elf_Scn *scn, Elf *elf)
{
	Func_list	*flp;
	Aliste		idx;
	uint_t		flags = 0;
	Elf_Data	*data = NULL;

	for (ALIST_TRAVERSE(support[LDS_INSEC].sup_funcs, idx, flp)) {
		Shdr	*nshdr = *oshdr;

		/*
		 * This interface was introduced in VERSION2.  Only call this
		 * function for libraries reporting support for version 2 or
		 * above.
		 */
		if (flp->fl_version < LD_SUP_VERSION2)
			continue;

		if ((data == NULL) &&
		    ((data = elf_getdata(scn, NULL)) == NULL)) {
			ld_eprintf(ofl, ERR_ELF, MSG_INTL(MSG_ELF_GETDATA),
			    ifl->ifl_name);
			return (S_ERROR);
		}

		DBG_CALL(Dbg_support_action(ofl->ofl_lml, flp->fl_obj,
		    support[LDS_INSEC].sup_name, LDS_INSEC, sname));
		(*flp->fl_fptr)(sname, &nshdr, ndx, data, elf, &flags);

		/*
		 * If the section header has been re-allocated (known to occur
		 * with libCCexcept.so), then diagnose the section header
		 * difference and return the new section header.
		 */
		if (nshdr != *oshdr) {
			Ehdr	*ehdr = ifl->ifl_ehdr;

			DBG_CALL(Dbg_shdr_modified(ofl->ofl_lml, flp->fl_obj,
			    ehdr->e_ident[EI_OSABI], ehdr->e_machine, ndx,
			    *oshdr, nshdr, sname));
			*oshdr = nshdr;
		}
	}
	return (0);
}

void
ld_sup_section(Ofl_desc *ofl, const char *scn, Shdr *shdr, Word ndx,
    Elf_Data *data, Elf *elf)
{
	Func_list	*flp;
	Aliste		idx;

	for (ALIST_TRAVERSE(support[LDS_SEC].sup_funcs, idx, flp)) {
		DBG_CALL(Dbg_support_action(ofl->ofl_lml, flp->fl_obj,
		    support[LDS_SEC].sup_name, LDS_SEC, scn));
		(*flp->fl_fptr)(scn, shdr, ndx, data, elf);
	}
}

void
ld_sup_input_done(Ofl_desc *ofl)
{
	Func_list	*flp;
	Aliste		idx;
	uint_t		flags = 0;

	for (ALIST_TRAVERSE(support[LDS_INPUT_DONE].sup_funcs, idx, flp)) {
		/*
		 * This interface was introduced in VERSION2.  Only call this
		 * function for libraries reporting support for version 2 or
		 * above.
		 */
		if (flp->fl_version < LD_SUP_VERSION2)
			continue;

		DBG_CALL(Dbg_support_action(ofl->ofl_lml, flp->fl_obj,
		    support[LDS_INPUT_DONE].sup_name, LDS_INPUT_DONE, 0));
		(*flp->fl_fptr)(&flags);
	}
}
