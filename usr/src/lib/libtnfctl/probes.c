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
 * Load object and probe discovery in target process.  This file is
 * not exercised for kernel probes.
 */

#ifndef DEBUG
#define	NDEBUG	1
#endif

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stddef.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <assert.h>

#include "tnfctl_int.h"
#include "kernel_int.h"
#include "dbg.h"

/*
 * Defines - Project private interfaces
 */

#define	PROBE_SYMBOL	"__tnf_probe_version_1"

/*
 * Typedefs
 */

typedef struct link_args {
	char		*la_probename;
	int		ret_val;
} link_args_t;

typedef struct link_args2 {
	tnfctl_handle_t	*la_hndl;
	char		*la_probename;
	objlist_t	*la_obj;
	ulong_t		la_index;
	ulong_t		la_base;
} link_args2_t;

static int per_loadobj(void *, const tnfctl_ind_obj_info_t *, void *);
static objlist_t *loadobj_find(tnfctl_handle_t *,
			const tnfctl_ind_obj_info_t *);
static tnfctl_errcode_t get_num_probes(tnfctl_handle_t *, objlist_t *, int *);
static tnfctl_errcode_t read_probes_in_obj(tnfctl_handle_t *, objlist_t *,
		ulong_t, ulong_t);
static void free_obj_fields(objlist_t *);
static tnfctl_errcode_t count_probes(char *, uintptr_t, void *,
					tnfctl_elf_search_t *);
static tnfctl_errcode_t read_a_probe(char *, uintptr_t, void *,
					tnfctl_elf_search_t *);
static tnfctl_errcode_t link_targ_obj_probes(tnfctl_handle_t *, objlist_t *);
static tnfctl_errcode_t unlink_targ_obj_probes(tnfctl_handle_t *, objlist_t *);

/*
 * sync up our library list with that of the run time linker's
 * Returns an event indicating if a dlopen or dlclose happened.
 */
tnfctl_errcode_t
_tnfctl_lmap_update(tnfctl_handle_t *hndl, boolean_t *lmap_ok,
				enum event_op_t *dl_evt)
{
	int		miscstat;
	objlist_t	*cur_obj;

	*lmap_ok = B_TRUE;

	/* reset old and new of current objects */
	for (cur_obj = hndl->objlist; cur_obj; cur_obj = cur_obj->next) {
		cur_obj->old = B_TRUE;
		cur_obj->new = B_FALSE;
	}

	/* read in object list */
	miscstat = hndl->p_obj_iter(hndl->proc_p, per_loadobj, hndl);
	/* reset libs_changed global var to indicated sync up done */
	_tnfctl_libs_changed = B_FALSE;
	if (miscstat) {
		/*
		 * for INDIRECT_MODE or INTERNAL_MODE, we should never get
		 * called when linkmaps are not consistent, so this is a real
		 * error - return without setting lmap_ok.
		 */
		if ((hndl->mode == INDIRECT_MODE) ||
				(hndl->mode == INTERNAL_MODE))
			return (TNFCTL_ERR_INTERNAL);

		assert(hndl->mode == DIRECT_MODE);
		/*
		 * in DIRECT_MODE:
		 * caller needs to call tnfctl_continue on BADLMAPSTATE
		 * XXXX - the cast from int to prb_status_t is ok as
		 * we know we are in DIRECT_MODE and we are calling our
		 * own loadobject iterator function.
		 */
		if ((prb_status_t) miscstat == PRB_STATUS_BADLMAPSTATE)
			*lmap_ok = B_FALSE;
		return (_tnfctl_map_to_errcode((prb_status_t) miscstat));
	}

	/*
	 * find out about dlopens or dlcloses - In direct mode, there
	 * can only be one since we monitor all dl activity.  The dl_evt
	 * field is only used by tnfctl_continue().  In proc_service
	 * mode or internal mode, the new_probe member indicates new probes
	 * correctly.
	 */
	*dl_evt = EVT_NONE;
	for (cur_obj = hndl->objlist; cur_obj; cur_obj = cur_obj->next) {
		if (cur_obj->old == B_TRUE) {
			*dl_evt = EVT_CLOSE;
			break;
		}
		if (cur_obj->new == B_TRUE) {
			*dl_evt = EVT_OPEN;
			break;
		}
	}

	/*
	 * reset new_probe field only if there was a dlopen or dlclose
	 */
	if (*dl_evt != EVT_NONE) {
		for (cur_obj = hndl->objlist; cur_obj;
				cur_obj = cur_obj->next) {
			cur_obj->new_probe = cur_obj->new;
		}
	}

	return (TNFCTL_ERR_NONE);
}


/*
 * search through all libraries and discover all probes in target
 * This function assumes all objects have been found and marked as
 * appropriate (new, old, or neither)
 */
tnfctl_errcode_t
_tnfctl_find_all_probes(tnfctl_handle_t *hndl)
{
	tnfctl_errcode_t	prexstat;
	int		num_probes, j;
	objlist_t	*cur_obj, *prev_obj, *tmp_obj;
	boolean_t	saw_new_probes = B_FALSE;

	prev_obj = NULL;
	cur_obj = hndl->objlist;
	while (cur_obj) {
		if (cur_obj->old == B_TRUE) {
			/* dlclosed library : stitch out probes in target */

			DBG_TNF_PROBE_3(_tnfctl_find_all_probes_1, "libtnfctl",
				"sunw%verbosity 1; sunw%debug 'lib dlclosed'",
				tnf_opaque, lib_baseaddr, cur_obj->baseaddr,
				tnf_string, lib_name, cur_obj->objname,
				tnf_long, lib_fd, cur_obj->objfd);

			prexstat = unlink_targ_obj_probes(hndl, cur_obj);
			if (prexstat)
				return (prexstat);
			free_obj_fields(cur_obj);
			/* remove this object from linked list */
			tmp_obj = cur_obj;
			cur_obj = cur_obj->next;
			if (prev_obj == NULL)
				hndl->objlist = cur_obj;
			else
				prev_obj->next = cur_obj;
			free(tmp_obj);
			continue;
		}

		if (cur_obj->new == B_TRUE) {
			/* dlopened library : read in probes */
			prexstat = get_num_probes(hndl, cur_obj, &num_probes);
			if (prexstat)
				return (prexstat);
			if (num_probes) {
				saw_new_probes = B_TRUE;
				cur_obj->probes = malloc(num_probes *
					sizeof (prbctlref_t));
				if (cur_obj->probes == NULL)
					return (TNFCTL_ERR_ALLOCFAIL);
				prexstat = read_probes_in_obj(hndl, cur_obj,
					num_probes, hndl->num_probes);
				if (prexstat)
					return (prexstat);
				cur_obj->min_probe_num = hndl->num_probes;
				/* increment num_probes */
				hndl->num_probes += num_probes;
				cur_obj->probecnt = num_probes;
				prexstat = link_targ_obj_probes(hndl, cur_obj);
				if (prexstat)
					return (prexstat);
			}
		}
		prev_obj = cur_obj;
		cur_obj = cur_obj->next;
	}

#if 0
	for (cur_obj = hndl->objlist; cur_obj; cur_obj = cur_obj->next) {
			(void) fprintf(stderr, "%s 0x%08x %s fd=%d\n",
				(cur_obj->new) ? "*" : " ",
				cur_obj->baseaddr, cur_obj->objname,
				cur_obj->objfd);
	}
#endif

	/* call create_func for client data if we saw new probes */
	if (saw_new_probes && hndl->create_func) {
		for (cur_obj = hndl->objlist; cur_obj;
						cur_obj = cur_obj->next) {
			tnfctl_probe_t *probe_handle;

			if (cur_obj->new == B_FALSE)
				continue;
			/* new object */
			for (j = 0; j < cur_obj->probecnt; j++) {
				probe_handle = cur_obj->probes[j].probe_handle;
				probe_handle->client_registered_data =
					hndl->create_func(hndl, probe_handle);
			}
		}
	}

	return (TNFCTL_ERR_NONE);
}

/*
 * _tnfctl_free_objs_and_probes() - cleans up objects and probes
 */
void
_tnfctl_free_objs_and_probes(tnfctl_handle_t *hndl)
{
	objlist_t *obj, *tmp;

	obj = hndl->objlist;
	while (obj) {
		free_obj_fields(obj);
		tmp = obj;
		obj = obj->next;
		free(tmp);
	}
	hndl->objlist = NULL;
}

/*
 * Free members of objlist_t
 */
static void
free_obj_fields(objlist_t *obj)
{
	int i;
	prbctlref_t *probe_p;

	for (i = 0; i < obj->probecnt; i++) {
		probe_p = &(obj->probes[i]);
		if (probe_p->attr_string)
			free(probe_p->attr_string);
		if (probe_p->probe_handle)
			probe_p->probe_handle->valid = B_FALSE;
	}
	if (obj->probes)
		free(obj->probes);
	obj->probecnt = 0;
	if (obj->objname)
		free(obj->objname);
	if (obj->objfd != -1)
		close(obj->objfd);
}

/*
 * _tnfctl_probes_traverse() - iterate over all probes by calling the
 * callback function supplied.
 */
tnfctl_errcode_t
_tnfctl_probes_traverse(tnfctl_handle_t *hndl,
	_tnfctl_traverse_probe_func_t func_p, void *calldata_p)
{
	tnfctl_errcode_t	prexstat;
	boolean_t	release_lock;
	objlist_t	*obj;
	int		j;

	/*LINTED statement has no consequent: else*/
	LOCK_SYNC(hndl, prexstat, release_lock);

	for (obj = hndl->objlist; obj; obj = obj->next) {
		for (j = 0; j < obj->probecnt; j++) {
			prexstat = (*func_p) (hndl, &(obj->probes[j]),
							calldata_p);
			if (prexstat) {
				/*LINTED statement has no consequent: else*/
				UNLOCK(hndl, release_lock);
				return (prexstat);
			}
		}
	}

	/*LINTED statement has no consequent: else*/
	UNLOCK(hndl, release_lock);

	return (TNFCTL_ERR_NONE);
}

/*
 * function that is called by loadobject iterator function for every
 * loadobject.  If a new loadobject, add it to to our list.
 */
static int
per_loadobj(void *proc_p, const tnfctl_ind_obj_info_t *obj, void *cd)
{
	tnfctl_handle_t	*hndl = cd;
	objlist_t	*entry_p, *cur_p, *next_p;

	if (entry_p = loadobj_find(hndl, obj)) {
		/* loadobject already exists */
		entry_p->old = B_FALSE;
		/* no need to close the objfd because iterator func will */

		/* successful return */
		return (0);
	}

	/* add new loadobject */
	entry_p = calloc(1, sizeof (objlist_t));

	entry_p->old = B_FALSE;
	entry_p->new = B_TRUE;
	entry_p->new_probe = B_TRUE;
	entry_p->objname = strdup(obj->objname);
	if (entry_p->objname == NULL)
		return (1);
	entry_p->baseaddr = obj->text_base;
	/* may have to actually open the fd */
	if (obj->objfd == -1) {
		entry_p->objfd = open(obj->objname, O_RDONLY);
		if (entry_p->objfd == -1)
			return (1);
	} else {
		/* dup the fd because iterator function will close it */
		entry_p->objfd = dup(obj->objfd);
		if (entry_p->objfd == -1)
			return (1);
	}

	entry_p->min_probe_num = 0;
	entry_p->probecnt = 0;
	entry_p->probes = NULL;
	entry_p->next = NULL;

	if (hndl->objlist == NULL) {
		hndl->objlist = entry_p;
	} else {
		/* add to end of list */
		next_p = hndl->objlist;
		while (next_p) {
			cur_p = next_p;
			next_p = next_p->next;
		}
		/* cur_p now points to last element on list */
		cur_p->next = entry_p;
	}

	return (0);
}

/*
 * check if this loadobject already exists in our linked list.
 */
static objlist_t *
loadobj_find(tnfctl_handle_t *hndl, const tnfctl_ind_obj_info_t *this_obj)
{
	objlist_t *obj;

	for (obj = hndl->objlist; obj; obj = obj->next) {
		if (obj->baseaddr == this_obj->text_base)
			return (obj);
	}
	return (NULL);
}

/*
 * find the number of probes in a loadobject
 */
static tnfctl_errcode_t
get_num_probes(tnfctl_handle_t *hndl, objlist_t *obj, int *num_probes)
{
	tnfctl_errcode_t	prexstat;
	link_args_t	largs;
	tnfctl_elf_search_t search_info;

	DBG_TNF_PROBE_0(get_num_probes_1, "libtnfctl", "sunw%verbosity 1");

	largs.la_probename = PROBE_SYMBOL;
	largs.ret_val = 0;

	search_info.section_func = _tnfctl_traverse_rela;
	search_info.record_func = count_probes;
	search_info.record_data = &largs;

	prexstat = _tnfctl_traverse_object(obj->objfd, obj->baseaddr,
						&search_info);
	if (prexstat)
		return (prexstat);

	DBG_TNF_PROBE_2(get_num_probes_2, "libtnfctl", "sunw%verbosity 1",
			tnf_long, num_probes, largs.ret_val,
			tnf_string, obj_name, obj->objname);

	*num_probes = largs.ret_val;
	return (TNFCTL_ERR_NONE);
}

/*
 * discover all probes in a loadobject and read it into our array.
 */
static tnfctl_errcode_t
read_probes_in_obj(tnfctl_handle_t *hndl, objlist_t *obj, ulong_t num_probes,
			ulong_t probe_base_num)
{
	tnfctl_errcode_t	prexstat;
	link_args2_t	largs2;
	tnfctl_elf_search_t search_info;

	DBG_TNF_PROBE_0(read_probes_in_obj_1, "libtnfctl", "sunw%verbosity 2");

	largs2.la_hndl = hndl;
	largs2.la_probename = PROBE_SYMBOL;
	largs2.la_obj = obj;
	largs2.la_index = 0;
	largs2.la_base = probe_base_num;

	search_info.section_func = _tnfctl_traverse_rela;
	search_info.record_func = read_a_probe;
	search_info.record_data = &largs2;

	prexstat = _tnfctl_traverse_object(obj->objfd, obj->baseaddr,
						&search_info);
	if (prexstat)
		return (prexstat);

	return (TNFCTL_ERR_NONE);
}

/*
 * checks if this relocation entry is a probe and if so,
 * increments a counter for every probe seen
 */
/*ARGSUSED*/
static tnfctl_errcode_t
count_probes(char *name, uintptr_t addr, void *rel_entry,
	tnfctl_elf_search_t * search_info_p)
{
	link_args_t	*largs_p = (link_args_t *) search_info_p->record_data;

	if (strcmp(name, largs_p->la_probename) == 0) {
		largs_p->ret_val++;
	}
	return (TNFCTL_ERR_NONE);
}

/*
 * checks if this relocation entry is a probe and if so, reads in info
 * on this probe
 */
/*ARGSUSED*/
static tnfctl_errcode_t
read_a_probe(char *name, uintptr_t addr, void *rel_entry,
	tnfctl_elf_search_t * search_info_p)
{
	link_args2_t	*largs2_p = (link_args2_t *) search_info_p->record_data;
	ulong_t		index = largs2_p->la_index;
	prbctlref_t	*prbctl_p;
	tnfctl_handle_t	*hndl = largs2_p->la_hndl;
	tnfctl_errcode_t	prexstat;
	int		miscstat;
	uintptr_t	attrs;

	assert((hndl->mode == INTERNAL_MODE) ?
		(MUTEX_HELD(&_tnfctl_lmap_lock)) : 1);

	if (strcmp(name, largs2_p->la_probename) != 0)
		return (TNFCTL_ERR_NONE);

	/* found a probe */
	prbctl_p = &(largs2_p->la_obj->probes[index]);
	prbctl_p->addr = addr;
	prbctl_p->probe_id = largs2_p->la_base + index;
	prbctl_p->obj = largs2_p->la_obj;
	largs2_p->la_index++;

	/* read in probe structure */
	miscstat = hndl->p_read(hndl->proc_p, addr,
		&prbctl_p->wrkprbctl, sizeof (prbctl_p->wrkprbctl));
	if (miscstat) {
		DBG((void) fprintf(stderr,
			"read_a_probe: read from target failed: %d\n",
			miscstat));
		return (TNFCTL_ERR_INTERNAL);
	}

	/*
	 * dereference the attrs (read it into our address space only for
	 * working copy)
	 */
	attrs = (uintptr_t) prbctl_p->wrkprbctl.attrs;
	prexstat = _tnfctl_readstr_targ(hndl, attrs, &prbctl_p->attr_string);
	if (prexstat) {
		DBG((void) fprintf(stderr,
		    "read_a_probe: _tnfctl_readstr_targ (attrs) failed: %s\n",
				tnfctl_strerror(prexstat)));
		return (prexstat);
	}

	DBG_TNF_PROBE_1(read_a_probe_2, "libtnfctl",
		"sunw%verbosity 1; sunw%debug 'found a probe'",
		tnf_string, probe, prbctl_p->attr_string);

	/* create probe handle */
	prbctl_p->probe_handle = calloc(1, sizeof (tnfctl_probe_t));
	if (prbctl_p->probe_handle == NULL)
		return (TNFCTL_ERR_ALLOCFAIL);
	prbctl_p->probe_handle->valid = B_TRUE;
	prbctl_p->probe_handle->probe_p = prbctl_p;
	/* link in probe handle into chain off tnfctl_handle_t */
	prbctl_p->probe_handle->next = hndl->probe_handle_list_head;
	hndl->probe_handle_list_head = prbctl_p->probe_handle;

	/*
	 * if this is a "virgin" probe, set up probe to initial state
	 * REMIND: Could defer this target write till we link the probes
	 * together in target process in link_targ_obj_probes() i.e.
	 * do the "write" only once.
	 */
	if (prbctl_p->wrkprbctl.commit_func == NULL) {
		prbctl_p->wrkprbctl.probe_func =
				(tnf_probe_func_t) hndl->endfunc;
		prbctl_p->wrkprbctl.commit_func =
				(tnf_probe_func_t) hndl->commitfunc;
		prbctl_p->wrkprbctl.alloc_func =
				(tnf_probe_alloc_func_t) hndl->allocfunc;
		/*
		 * update the probe in target to its initial state
		 * Since the probe is disabled, it is ok to write it one
		 * write command as opposed to updating each word individually
		 */
		miscstat = hndl->p_write(hndl->proc_p, addr,
			&prbctl_p->wrkprbctl, sizeof (prbctl_p->wrkprbctl));
		if (miscstat)
			return (TNFCTL_ERR_INTERNAL);
	}

	return (TNFCTL_ERR_NONE);
}

/*
 * Link all the probes in a linked list in the target image in specified
 * object.  Also, link probes from previous object and next object into
 * this list.  The only
 * reason this is needed is because internally in the process,
 * tnf_probe_notify() that is called from libthread walks through all
 * probes substituting the test function
 * REMIND: find a way that we don't have to walk through probes internally.
 */
static tnfctl_errcode_t
link_targ_obj_probes(tnfctl_handle_t *hndl, objlist_t *cur)
{
	int i;
	prbctlref_t *probe_p;
	tnf_probe_control_t *next_probe;
	int miscstat;
	objlist_t *cur_tmp, *prev_w_probes, *next_w_probes;
	uintptr_t next_addr;

	/* find previous object that has probes */
	prev_w_probes = NULL;
	cur_tmp = hndl->objlist;
	while (cur_tmp != cur) {
		if (cur_tmp->probecnt != 0)
			prev_w_probes = cur_tmp;
		cur_tmp = cur_tmp->next;
	}

	/* find next object with probes */
	next_w_probes = NULL;
	cur_tmp = cur->next;
	while (cur_tmp != NULL) {
		if (cur_tmp->probecnt != 0)
			next_w_probes = cur_tmp;
		cur_tmp = cur_tmp->next;
	}

	/* link probes (except for last one) in order */
	for (i = 0; i < (cur->probecnt - 1); i++) {
		probe_p = &(cur->probes[i]);
		next_probe = (tnf_probe_control_t *) cur->probes[i+1].addr;
		probe_p->wrkprbctl.next = next_probe;
		miscstat = hndl->p_write(hndl->proc_p, probe_p->addr +
				offsetof(struct tnf_probe_control, next),
				&next_probe, sizeof (next_probe));
		if (miscstat)
			return (TNFCTL_ERR_INTERNAL);
	}

	next_probe = (tnf_probe_control_t *) cur->probes[0].addr;
	if (prev_w_probes == NULL) {
		/* adding as first object in list */
		next_addr = hndl->probelist_head;
	} else {
		probe_p = &(prev_w_probes->probes[prev_w_probes->probecnt - 1]);
		probe_p->wrkprbctl.next = next_probe;
		next_addr = probe_p->addr +
				offsetof(struct tnf_probe_control, next);
	}

	/* point next_addr to first probe in this object */
	miscstat = hndl->p_write(hndl->proc_p, next_addr,
			&next_probe, sizeof (next_probe));
	if (miscstat)
		return (TNFCTL_ERR_INTERNAL);

	/* link last probe in object */
	if (next_w_probes == NULL)
		next_probe = NULL;
	else {
		next_probe = (tnf_probe_control_t *)
				next_w_probes->probes[0].addr;
	}
	probe_p = &(cur->probes[cur->probecnt - 1]);
	probe_p->wrkprbctl.next = next_probe;
	miscstat = hndl->p_write(hndl->proc_p, probe_p->addr +
			offsetof(struct tnf_probe_control, next),
			&next_probe, sizeof (next_probe));
	if (miscstat)
		return (TNFCTL_ERR_INTERNAL);
	return (TNFCTL_ERR_NONE);
}

/*
 * An object has been closed.  Stitch probes around this object in
 * target image.
 */
static tnfctl_errcode_t
unlink_targ_obj_probes(tnfctl_handle_t *hndl, objlist_t *cur)
{
	prbctlref_t *probe_p;
	tnf_probe_control_t *next_probe;
	int miscstat;
	objlist_t *cur_tmp, *prev_w_probes, *next_w_probes;
	uintptr_t next_addr;

	/* find previous object that has probes */
	prev_w_probes = NULL;
	cur_tmp = hndl->objlist;
	while (cur_tmp != cur) {
		if (cur_tmp->probecnt != 0)
			prev_w_probes = cur_tmp;
		cur_tmp = cur_tmp->next;
	}

	/* find next object with probes */
	next_w_probes = NULL;
	cur_tmp = cur->next;
	while (cur_tmp != NULL) {
		if (cur_tmp->probecnt != 0)
			next_w_probes = cur_tmp;
		cur_tmp = cur_tmp->next;
	}

	if (next_w_probes == NULL)
		next_probe = NULL;
	else {
		next_probe = (tnf_probe_control_t *)
				next_w_probes->probes[0].addr;
	}

	if (prev_w_probes == NULL) {
		/* removing first object in list */
		next_addr = hndl->probelist_head;
	} else {
		probe_p = &(prev_w_probes->probes[prev_w_probes->probecnt - 1]);
		probe_p->wrkprbctl.next = next_probe;
		next_addr = probe_p->addr +
				offsetof(struct tnf_probe_control, next);
	}

	/* point next_addr to next_probe */
	miscstat = hndl->p_write(hndl->proc_p, next_addr,
			&next_probe, sizeof (next_probe));
	if (miscstat)
		return (TNFCTL_ERR_INTERNAL);
	return (TNFCTL_ERR_NONE);
}

/*
 * _tnfctl_flush_a_probe() - write a changed probe into the target process'
 * address space.
 */
tnfctl_errcode_t
_tnfctl_flush_a_probe(tnfctl_handle_t *hndl, prbctlref_t *ref_p, size_t offset,
			size_t size)
{
	tnfctl_errcode_t	prexstat;
	int			miscstat;

	/*
	 * For internal control:
	 * There is *no race* for finding the test function (between the time
	 * we call find_test_func() and the time we assign it to a probe),
	 * because tnfctl_internal_open() cannot be called from an init section
	 * (look at man page of tnfctl_internal_open()).  And, after the init
	 * section of libthread has run, we will always use the MT test
	 * function.
	 */

	if (hndl->mode == KERNEL_MODE) {
		prexstat = _tnfctl_prbk_flush(hndl, ref_p);
		if (prexstat)
			return (prexstat);
	} else {
		miscstat = hndl->p_write(hndl->proc_p,
			ref_p->addr + offset,
			((char *)&(ref_p->wrkprbctl)) + offset, size);
		if (miscstat)
			return (TNFCTL_ERR_INTERNAL);
	}

	return (TNFCTL_ERR_NONE);
}
