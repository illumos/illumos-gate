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
 * Copyright (c) 1994, by Sun Microsytems, Inc.
 */

/*
 * Routines that
 *	- return an address for a symbol name
 *	- return a symbol name for an address
 */

#ifndef DEBUG
#define	NDEBUG	1
#endif

#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/procfs.h>
#include <sys/stat.h>
#include <assert.h>

#include "tnfctl_int.h"
#include "dbg.h"


/*
 * Typedefs
 */

typedef struct sym_args {
	char		*sa_name;
	uintptr_t	sa_addr;
} sym_args_t;

/*
 * Declarations
 */

static tnfctl_errcode_t sym_findname_in_obj(int objfd, uintptr_t baseaddr,
	uintptr_t symaddr, char **symname);

static tnfctl_errcode_t sym_match(char *name, uintptr_t addr, void *sym_entry,
	tnfctl_elf_search_t *search_info_p);

static tnfctl_errcode_t sym_matchname(char *name, uintptr_t addr,
	void *sym_entry,
	tnfctl_elf_search_t *search_info_p);


/* ---------------------------------------------------------------- */
/* ----------------------- Public Functions ----------------------- */
/* ---------------------------------------------------------------- */

/*
 * _tnfctl_sym_find_in_obj() - determines the virtual address of the supplied
 * symbol in the object file specified by fd.
 */
tnfctl_errcode_t
_tnfctl_sym_find_in_obj(int objfd, uintptr_t baseaddr, const char *symname,
		uintptr_t *symaddr)
{
	tnfctl_errcode_t	prexstat = TNFCTL_ERR_NONE;
	sym_args_t		symargs;
	tnfctl_elf_search_t	search_info;

	DBG_TNF_PROBE_1(_tnfctl_sym_find_in_obj_1, "libtnfctl",
			"sunw%verbosity 3",
			tnf_string, searching_for, symname);

	symargs.sa_name = (char *) symname;
	/* clear output argument in advance */
	symargs.sa_addr = 0;

	search_info.section_func = _tnfctl_traverse_dynsym;
	search_info.record_func = sym_match;
	search_info.record_data = &symargs;

	prexstat = _tnfctl_traverse_object(objfd, baseaddr, &search_info);
	if (prexstat)
		return (prexstat);

	/* check if we found symbol address */
	if (symargs.sa_addr == 0) {
		return (TNFCTL_ERR_BADARG);
	}

	*symaddr = symargs.sa_addr;
	return (TNFCTL_ERR_NONE);
}


/*
 * _tnfctl_sym_find() - determines the virtual address of the supplied symbol
 * in the process.
 */
tnfctl_errcode_t
_tnfctl_sym_find(tnfctl_handle_t *hndl, const char *symname, uintptr_t *symaddr)
{
	boolean_t	release_lock;
	tnfctl_errcode_t	prexstat = TNFCTL_ERR_NONE;
	objlist_t	*obj;

	DBG_TNF_PROBE_1(_tnfctl_sym_find_start, "libtnfctl",
			"start _tnfctl_sym_find; sunw%verbosity 3",
			tnf_string, searching_for, symname);

	/*LINTED statement has no consequent: else*/
	LOCK(hndl, prexstat, release_lock);

	/* for every object in list, search for symbol */
	for (obj = hndl->objlist; obj; obj = obj->next) {
		if (obj->old == B_TRUE)
			continue;	/* don't examine dlclose'd libs */

		/* return value of TNFCTL_ERR_BADARG means symbol not found */
		prexstat = _tnfctl_sym_find_in_obj(obj->objfd,
			obj->baseaddr, symname, symaddr);
		if (prexstat == TNFCTL_ERR_NONE)
			/* symbol found */
			break;
		else if (prexstat != TNFCTL_ERR_BADARG)
			/* error condition */
			break;
		/* continue loop on TNFCTL_ERR_BADARG */
	}

	/*LINTED statement has no consequent: else*/
	UNLOCK(hndl, release_lock);

	DBG_TNF_PROBE_0(_tnfctl_sym_find_end, "libtnfctl",
			"end _tnfctl_sym_find; sunw%verbosity 3");

	return (prexstat);
}

/*
 * _tnfctl_sym_obj_find() - determines the virtual address of the supplied
 *	symbol in the object specified by base name
 */
tnfctl_errcode_t
_tnfctl_sym_obj_find(tnfctl_handle_t *hndl, const char *lib_base_name,
	const char *symname, uintptr_t *symaddr)
{
	tnfctl_errcode_t	prexstat = TNFCTL_ERR_NONE;
	objlist_t	*obj, *found_obj;
	const char *str_ptr;

	assert((hndl->mode == INTERNAL_MODE) ?
		(MUTEX_HELD(&_tnfctl_lmap_lock)) : 1);

	DBG_TNF_PROBE_1(_tnfctl_sym_obj_find_start, "libtnfctl",
			"start _tnfctl_sym_obj_find; sunw%verbosity 3",
			tnf_string, searching_for, symname);

	found_obj = NULL;
	/* for every object in list ... */
	for (obj = hndl->objlist; obj; obj = obj->next) {
		if (obj->old == B_TRUE)
			continue;	/* don't examine dlclose'd libs */

		if (obj->objname == NULL)
			continue;

		/* find the last occurrence of / in the name */
		str_ptr = strrchr(obj->objname, '/');
		if (str_ptr == NULL) {
			str_ptr = obj->objname;
		} else {
			str_ptr++;	/* bump up past '/' */
		}

		/* XXX - use strcoll ? */
		if (strcmp(str_ptr, lib_base_name) == 0) {
			found_obj = obj;
			break;
		}
	}
	/* return value of TNFCTL_ERR_BADARG means symbol not found */
	if (found_obj == NULL)
		return (TNFCTL_ERR_BADARG);

	prexstat = _tnfctl_sym_find_in_obj(found_obj->objfd,
			found_obj->baseaddr, symname, symaddr);

	DBG_TNF_PROBE_0(_tnfctl_sym_obj_find_end, "libtnfctl",
			"end _tnfctl_sym_obj_find; sunw%verbosity 3");

	return (prexstat);
}

/*
 * _tnfctl_sym_findname() - determines the name of a function from its address.
 */
tnfctl_errcode_t
_tnfctl_sym_findname(tnfctl_handle_t *hndl, uintptr_t symaddr,
	char **symname)
{
	boolean_t	release_lock;
	tnfctl_errcode_t	prexstat = TNFCTL_ERR_NONE;
	objlist_t	*obj;

	DBG_TNF_PROBE_1(_tnfctl_sym_findname_start, "libtnfctl",
			"start _tnfctl_sym_findname; sunw%verbosity 3",
			tnf_opaque, searching_for, symaddr);

	/*LINTED statement has no consequent: else*/
	LOCK(hndl, prexstat, release_lock);

	/* for every object in list, search for name */
	for (obj = hndl->objlist; obj; obj = obj->next) {
		if (obj->old == B_TRUE)
			continue;	/* don't examine dlclose'd libs */
		/* return value of TNFCTL_ERR_BADARG means symbol not found */
		prexstat = sym_findname_in_obj(obj->objfd,
			obj->baseaddr, symaddr, symname);
		if (prexstat == TNFCTL_ERR_NONE)
			/* symbol found */
			break;
		else if (prexstat != TNFCTL_ERR_BADARG)
			/* error condition */
			break;
		/* continue loop on TNFCTL_ERR_BADARG */
	}

	/*LINTED statement has no consequent: else*/
	UNLOCK(hndl, release_lock);

	DBG_TNF_PROBE_0(_tnfctl_sym_findname_end, "libtnfctl",
			"end _tnfctl_sym_findname; sunw%verbosity 3");

	return (prexstat);
}


/* ---------------------------------------------------------------- */
/* ----------------------- Private Functions ---------------------- */
/* ---------------------------------------------------------------- */

/*
 * sym_findname_in_obj() - determines the name of the supplied
 * address in the specified object file.
 */
static tnfctl_errcode_t
sym_findname_in_obj(int objfd, uintptr_t baseaddr, uintptr_t symaddr,
	char **symname)
{
	tnfctl_errcode_t	prexstat = TNFCTL_ERR_NONE;
	sym_args_t	symargs;
	tnfctl_elf_search_t	search_info;

	DBG_TNF_PROBE_1(sym_findname_in_obj_1, "libtnfctl",
			"sunw%verbosity 3",
			tnf_opaque, searching_for, symaddr);

	/* clear output argument in advance */
	symargs.sa_name = NULL;
	symargs.sa_addr = symaddr;

	search_info.section_func = _tnfctl_traverse_dynsym;
	search_info.record_func = sym_matchname;
	search_info.record_data = &symargs;

	prexstat = _tnfctl_traverse_object(objfd, baseaddr, &search_info);
	if (prexstat)
		return (prexstat);

	/* check if we found symbol address */
	if (symargs.sa_name == NULL) {
		return (TNFCTL_ERR_BADARG);
	}

	*symname = symargs.sa_name;
	return (TNFCTL_ERR_NONE);
}

/*
 * sym_match() - function to be called on each symbol in a dynsym section.
 *		Used to find the address of a symbol.
 */
static tnfctl_errcode_t
sym_match(char *name, uintptr_t addr, void *sym_entry,
	tnfctl_elf_search_t *search_info_p)
{
	sym_args_t	*symargs_p = (sym_args_t *) search_info_p->record_data;
	Elf3264_Sym	*sym = (Elf3264_Sym *) sym_entry;
#if 0
	printf("enter sym_match: \n");
	if (symargs_p->sa_name != 0)
		printf("(symargs_p->sa_name) = %s\n", symargs_p->sa_name);
	else
		printf("symargs_p->sa_name = 0\n");
	if (name != 0)
		printf("(name) = %s\n", name);
	else
		printf("name = 0\n");
#endif

#ifdef VERYVERBOSE
	(void) fprintf(stderr, "sym_match: checking \"%s\"\n", name);
#endif

	if ((sym->st_shndx != SHN_UNDEF) &&
			(strcmp(name, symargs_p->sa_name) == 0)) {

		DBG_TNF_PROBE_2(sym_match_1, "libtnfctl",
			"sunw%verbosity 2; sunw%debug '\tMatched Symbol'",
			tnf_string, symbol, name,
			tnf_opaque, address_found, addr);

		symargs_p->sa_addr = addr;
	}
#if 0
	printf("leaving sym_match\n");
#endif
	return (TNFCTL_ERR_NONE);
}


/*
 * sym_matchname() - function to be called on each symbol in a dynsym
 * section. Used to find the name of a symbol whose address is known.
 */
static tnfctl_errcode_t
sym_matchname(char *name, uintptr_t addr, void *sym_entry,
	tnfctl_elf_search_t * search_info_p)
{
	sym_args_t	*symargs_p = (sym_args_t *) search_info_p->record_data;
	Elf3264_Sym	*sym = (Elf3264_Sym *) sym_entry;

#ifdef VERYVERBOSE
	(void) fprintf(stderr, "sym_matchname: checking \"%s\"\n", name);
#endif

	if ((sym->st_shndx != SHN_UNDEF) &&
			symargs_p->sa_addr == addr) {

		DBG_TNF_PROBE_2(sym_matchname_1, "libtnfctl",
			"sunw%verbosity 2; sunw%debug '\tMatched Name'",
			tnf_string, symbol_found, name,
			tnf_opaque, address, addr);

		symargs_p->sa_name = strdup(name);
	}

	return (TNFCTL_ERR_NONE);
}
