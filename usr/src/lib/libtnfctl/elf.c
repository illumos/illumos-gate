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
 * Interfaces for searching for elf specific information
 */

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <link.h>
#include <sys/procfs.h>

#include "tnfctl_int.h"
#include "dbg.h"


/*
 * Declarations
 */

static tnfctl_errcode_t dynsec_num(tnfctl_handle_t *hndl, uintptr_t baseaddr,
					int objfd, int *num_dyn);
static tnfctl_errcode_t elf_dynmatch(Elf *elf, char *strs, Elf_Scn *dyn_scn,
	GElf_Shdr *dyn_shdr, Elf_Data *dyn_data,
	uintptr_t baseaddr, tnfctl_elf_search_t * search_info_p);
static tnfctl_errcode_t dyn_findtag(
	Elf3264_Dyn 	*start,		/* start of dynam table read in */
	Elf3264_Sword 	tag, 		/* tag to search for */
	uintptr_t 	dynam_addr,	/* address of _DYNAMIC in target */
	int 		limit, 		/* number of entries in table */
	uintptr_t 	*dentry_address);	/* return value */


/* ---------------------------------------------------------------- */
/* ----------------------- Public Functions ----------------------- */
/* ---------------------------------------------------------------- */

/*
 * _tnfctl_elf_dbgent() - this function finds the address of the
 * debug struct (DT_DEBUG) in the target process.  _DYNAMIC is a symbol
 * present in every object.  The one in the main executable references
 * an array that is tagged with the kind of each member.  We search
 * for the tag of DT_DEBUG which is where the run time linker maintains
 * a structure that references the shared object linked list.
 *
 * A side effect of searching for DT_DEBUG ensures that the executable is
 * a dynamic executable - tracing only works on dynamic executables because
 * static executables don't have relocation tables.
 */
tnfctl_errcode_t
_tnfctl_elf_dbgent(tnfctl_handle_t *hndl, uintptr_t * entaddr_p)
{
	tnfctl_errcode_t	prexstat = TNFCTL_ERR_NONE;
	prb_status_t	prbstat = PRB_STATUS_OK;
	int		miscstat;
	int		objfd;
	int		num_dynentries = 0;
	uintptr_t	dynamic_addr;
	uintptr_t	baseaddr;
	uintptr_t	dentry_addr;
	Elf3264_Dyn	*dynam_tab = NULL;
	long		dynam_tab_size;

	*entaddr_p = 0;

	prbstat = prb_mainobj_get(hndl->proc_p, &objfd, &baseaddr);
	if (prbstat)
		return (_tnfctl_map_to_errcode(prbstat));

	/* find the address of the symbol _DYNAMIC */
	prexstat = _tnfctl_sym_find_in_obj(objfd, baseaddr, "_DYNAMIC",
			&dynamic_addr);
	if (prexstat) {
		prexstat = TNFCTL_ERR_NOTDYNAMIC;
		goto Cleanup;
	}

	/* find the number of entries in the .dynamic section */
	prexstat = dynsec_num(hndl, baseaddr, objfd, &num_dynentries);
	if (prexstat)
		goto Cleanup;

	DBG_TNF_PROBE_2(_tnfctl_elf_dbgent_1, "libtnfctl", "sunw%verbosity 2",
		tnf_long, num_of_dynentries, num_dynentries,
		tnf_opaque, DYNAMIC_address, dynamic_addr);

	/* read in the dynamic table from the image of the process */
	dynam_tab_size = num_dynentries * sizeof (Elf3264_Dyn);
	dynam_tab = malloc(dynam_tab_size);
	if (!dynam_tab) {
		close(objfd);
		return (TNFCTL_ERR_ALLOCFAIL);
	}
	miscstat = hndl->p_read(hndl->proc_p, dynamic_addr, dynam_tab,
							dynam_tab_size);
	if (miscstat) {
		prexstat = TNFCTL_ERR_INTERNAL;
		goto Cleanup;
	}

	prexstat = dyn_findtag(dynam_tab, DT_DEBUG, dynamic_addr,
		num_dynentries, &dentry_addr);
	if (prexstat) {
		goto Cleanup;
	}
	*entaddr_p = dentry_addr;

Cleanup:
	close(objfd);
	if (dynam_tab)
		free(dynam_tab);
	return (prexstat);

}


/* ---------------------------------------------------------------- */
/* ----------------------- Private Functions ---------------------- */
/* ---------------------------------------------------------------- */

/*
 * dyn_findtag() - searches tags in _DYNAMIC table
 */
static tnfctl_errcode_t
dyn_findtag(Elf3264_Dyn * start,	/* start of dynam table read in */
		Elf3264_Sword tag,	/* tag to search for */
		uintptr_t dynam_addr,	/* base address of _DYNAMIC in target */
		int limit, /* number of entries in table */
		uintptr_t * dentry_address)
{				/* return value */
	Elf3264_Dyn	  *dp;

	for (dp = start; dp->d_tag != DT_NULL; dp++) {

		DBG_TNF_PROBE_1(dyn_findtag_1, "libtnfctl",
			"sunw%verbosity 3; sunw%debug 'in loop'",
			tnf_long, tag, dp->d_tag);

		if (dp->d_tag == tag) {
			*dentry_address = dynam_addr +
				(dp - start) * sizeof (Elf3264_Dyn);
			return (TNFCTL_ERR_NONE);
		}
		if (--limit <= 0) {
			DBG((void) fprintf(stderr,
				"dyn_findtag: exceeded limit of table\n"));
			return (TNFCTL_ERR_INTERNAL);
		}
	}

	DBG((void) fprintf(stderr,
		"dyn_findtag: couldn't find tag, last tag=%d\n",
		(int) dp->d_tag));
	return (TNFCTL_ERR_INTERNAL);
}


/*
 * dynsec_num() - find the number of entries in the .dynamic section
 */
/*ARGSUSED*/
static tnfctl_errcode_t
dynsec_num(tnfctl_handle_t *hndl, uintptr_t baseaddr,
	int objfd, int *num_dyn)
{
	int		num_ent = 0;
	tnfctl_errcode_t	prexstat;
	tnfctl_elf_search_t search_info;

	DBG_TNF_PROBE_0(dynsec_num_1, "libtnfctl",
		"sunw%verbosity 2;"
		"sunw%debug 'counting number of entries in .dynamic section'");

	search_info.section_func = elf_dynmatch;
	search_info.section_data = &num_ent;

	prexstat = _tnfctl_traverse_object(objfd, baseaddr, &search_info);
	if (prexstat)
		return (prexstat);

	if (num_ent == 0)
		return (TNFCTL_ERR_NOTDYNAMIC);

	*num_dyn = num_ent;

	return (TNFCTL_ERR_NONE);
}


/*
 * elf_dynmatch() - this function searches for the .dynamic section and
 * returns the number of entries in it.
 */
/*ARGSUSED*/
static tnfctl_errcode_t
elf_dynmatch(Elf * elf,
	char *strs,
	Elf_Scn * dyn_scn,
	GElf_Shdr * dyn_shdr,
	Elf_Data * dyn_data,
	uintptr_t baseaddr,
	tnfctl_elf_search_t *search_info_p)
{
	char	*scn_name;
	int	*ret = (int *) search_info_p->section_data;

	/* bail if this isn't a .dynamic section */
	scn_name = strs + dyn_shdr->sh_name;
	if (strcmp(scn_name, ".dynamic") != 0)
		return (TNFCTL_ERR_NONE);

	if (dyn_shdr->sh_entsize == 0) {	/* no dynamic section */
		*ret = 0;
	} else {
		*ret = (int) (dyn_shdr->sh_size / dyn_shdr->sh_entsize);
	}
	return (TNFCTL_ERR_NONE);
}
