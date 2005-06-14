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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Published interfaces for probe control.
 */

#ifndef DEBUG
#define	NDEBUG	1
#endif

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <stddef.h>

#include "tnfctl_int.h"
#include "kernel_int.h"
#include "dbg.h"

struct pr_func_args {
	tnfctl_probe_op_t	func_p;
	void			*calldata;
};

tnfctl_errcode_t _tnfctl_destructor_wrapper(tnfctl_handle_t *,
			prbctlref_t *, void *);
tnfctl_errcode_t _tnfctl_creator_wrapper(tnfctl_handle_t *,
			prbctlref_t *, void *);
static tnfctl_errcode_t apply_func(tnfctl_handle_t *, prbctlref_t *, void *);
static tnfctl_errcode_t check_operation(tnfctl_handle_t *, tnfctl_probe_t *);

tnfctl_errcode_t
tnfctl_register_funcs(tnfctl_handle_t *hndl,
	void *(*create_func)(tnfctl_handle_t *, tnfctl_probe_t *),
	void (*destroy_func)(void *))
{
	tnfctl_errcode_t prexstat;

	if (hndl->destroy_func) {
		/*
		 * not the first time the register_funcs() is being called
		 * First call currently registered destroy_func on all
		 * probes
		 */
		prexstat = _tnfctl_probes_traverse(hndl,
				_tnfctl_destructor_wrapper, NULL);
		if (prexstat)
			return (prexstat);
	}

	/* set up new creator and destructor functions */
	hndl->create_func = create_func;
	hndl->destroy_func = destroy_func;

	/* call new creator function for all current probes */
	if (create_func) {
		prexstat = _tnfctl_probes_traverse(hndl,
					_tnfctl_creator_wrapper, NULL);
		if (prexstat)
			return (prexstat);
	}

	return (TNFCTL_ERR_NONE);
}

tnfctl_errcode_t
_tnfctl_destructor_wrapper(tnfctl_handle_t *hndl, prbctlref_t *probe, void *cd)
{
	assert(hndl->destroy_func);
	hndl->destroy_func(probe->probe_handle->client_registered_data);

	return (TNFCTL_ERR_NONE);
}

tnfctl_errcode_t
_tnfctl_creator_wrapper(tnfctl_handle_t *hndl, prbctlref_t *probe, void *cd)
{
	tnfctl_probe_t *p_handle;

	assert(hndl->create_func);
	p_handle = probe->probe_handle;
	p_handle->client_registered_data = hndl->create_func(hndl, p_handle);

	return (TNFCTL_ERR_NONE);
}

tnfctl_errcode_t
tnfctl_probe_apply(tnfctl_handle_t *hndl, tnfctl_probe_op_t func_p,
			void *calldata)
{
	struct pr_func_args	pr_args;
	tnfctl_errcode_t		prexstat;

	pr_args.func_p = func_p;
	pr_args.calldata = calldata;
	prexstat = _tnfctl_probes_traverse(hndl, apply_func, &pr_args);
	return (prexstat);
}

tnfctl_errcode_t
tnfctl_probe_apply_ids(tnfctl_handle_t *hndl, ulong_t probe_count,
		ulong_t *probe_ids, tnfctl_probe_op_t func_p,
		void *calldata)
{
	ulong_t		*id_p;
	ulong_t		i, pos;
	objlist_t	*obj_p;
	prbctlref_t	*probe;
	tnfctl_errcode_t	prexstat = TNFCTL_ERR_NONE;
	boolean_t		release_lock;

	/*LINTED statement has no consequent: else*/
	LOCK_SYNC(hndl, prexstat, release_lock);

	/* select probes based on numbers */
	id_p = probe_ids;
	for (i = 0; i < probe_count; i++, id_p++) {
		obj_p = hndl->objlist;
		while (obj_p) {
			if ((*id_p >= obj_p->min_probe_num) &&
				(*id_p < (obj_p->min_probe_num +
					obj_p->probecnt))) {
				break;
			}
			obj_p = obj_p->next;
		}
		if (obj_p == NULL) {
			prexstat = TNFCTL_ERR_INVALIDPROBE;
			goto end_of_func;
		}
		pos = *id_p - obj_p->min_probe_num;
		probe = &(obj_p->probes[pos]);
		prexstat = func_p(hndl, probe->probe_handle, calldata);
		if (prexstat)
			goto end_of_func;
	}

end_of_func:
	/*LINTED statement has no consequent: else*/
	UNLOCK(hndl, release_lock);
	return (prexstat);
}

tnfctl_errcode_t
tnfctl_probe_state_get(tnfctl_handle_t *hndl, tnfctl_probe_t *probe_hndl,
			tnfctl_probe_state_t *state_p)
{
	tnf_probe_control_t 	*prbctl_p;
	boolean_t		release_lock;
	tnfctl_errcode_t 	prexstat = TNFCTL_ERR_NONE;
	char			**func_names;
	uintptr_t		*func_addrs;

	if (hndl->mode == KERNEL_MODE) {
		prexstat = _tnfctl_refresh_kernel(hndl);
		if (prexstat)
			return (prexstat);
	}

	/*LINTED statement has no consequent: else*/
	LOCK_SYNC(hndl, prexstat, release_lock);

	if (probe_hndl->valid == B_FALSE) {
		prexstat = TNFCTL_ERR_INVALIDPROBE;
		goto end_of_func;
	}

	state_p->id = probe_hndl->probe_p->probe_id;
	state_p->attr_string = probe_hndl->probe_p->attr_string;

	prbctl_p = &probe_hndl->probe_p->wrkprbctl;
	state_p->enabled = (prbctl_p->test_func) ? B_TRUE : B_FALSE;
	state_p->traced = (prbctl_p->commit_func ==
			(tnf_probe_func_t) hndl->commitfunc) ? B_TRUE : B_FALSE;
	state_p->new_probe = probe_hndl->probe_p->obj->new_probe;
	state_p->obj_name = probe_hndl->probe_p->obj->objname;
	state_p->client_registered_data = probe_hndl->client_registered_data;

	if (hndl->mode == KERNEL_MODE) {
		state_p->func_names = NULL;
		state_p->func_addrs = NULL;
		/* skip code upto label */
		goto end_of_func;
	}

	/* process mode - get the probe functions */
	prexstat = _tnfctl_comb_decode(hndl, (uintptr_t) prbctl_p->probe_func,
			&func_names, &func_addrs);
	if (prexstat)
		goto end_of_func;

	/* if there are any probe functions */
	if (func_names[0] != NULL) {
		state_p->func_names = (const char * const *) func_names;
		state_p->func_addrs = func_addrs;
	} else {
		state_p->func_names = NULL;
		state_p->func_addrs = NULL;
	}

end_of_func:
	/*LINTED statement has no consequent: else*/
	UNLOCK(hndl, release_lock);
	return (prexstat);
}

static tnfctl_errcode_t
check_operation(tnfctl_handle_t *hndl, tnfctl_probe_t *probe_hndl)
{
	tnfctl_errcode_t	prexstat;

	if (hndl->mode == KERNEL_MODE) {
		prexstat = _tnfctl_refresh_kernel(hndl);
		if (prexstat)
			return (prexstat);
	} else if (hndl->trace_buf_state == TNFCTL_BUF_NONE) {
		/* process tracing */
		return (TNFCTL_ERR_NOBUF);
	}

	if (hndl->trace_buf_state == TNFCTL_BUF_BROKEN)
		return (TNFCTL_ERR_BUFBROKEN);

	if (probe_hndl->valid == B_FALSE) {
		return (TNFCTL_ERR_INVALIDPROBE);
	}

	return (TNFCTL_ERR_NONE);
}

tnfctl_errcode_t
tnfctl_probe_enable(tnfctl_handle_t *hndl, tnfctl_probe_t *probe_hndl, void *cd)
{
	tnf_probe_control_t	*prbctl_p;
	boolean_t		release_lock;
	tnfctl_errcode_t 	prexstat;

	/*LINTED statement has no consequent: else*/
	LOCK_SYNC(hndl, prexstat, release_lock);

	prexstat = check_operation(hndl, probe_hndl);
	if (prexstat)
		goto end_of_func;

	prbctl_p = &probe_hndl->probe_p->wrkprbctl;
	prbctl_p->test_func = (tnf_probe_test_func_t) hndl->testfunc;
	prexstat = _tnfctl_flush_a_probe(hndl, probe_hndl->probe_p,
			offsetof(struct tnf_probe_control, test_func),
			sizeof (tnf_probe_test_func_t));
end_of_func:
	/*LINTED statement has no consequent: else*/
	UNLOCK(hndl, release_lock);
	return (prexstat);
}

tnfctl_errcode_t
tnfctl_probe_disable(tnfctl_handle_t *hndl, tnfctl_probe_t *probe_hndl,
		void *cd)
{
	tnf_probe_control_t	*prbctl_p;
	boolean_t		release_lock;
	tnfctl_errcode_t 	prexstat;

	/*LINTED statement has no consequent: else*/
	LOCK_SYNC(hndl, prexstat, release_lock);

	prexstat = check_operation(hndl, probe_hndl);
	if (prexstat)
		goto end_of_func;

	prbctl_p = &probe_hndl->probe_p->wrkprbctl;
	prbctl_p->test_func = (tnf_probe_test_func_t) NULL;
	prexstat = _tnfctl_flush_a_probe(hndl, probe_hndl->probe_p,
			offsetof(struct tnf_probe_control, test_func),
			sizeof (tnf_probe_test_func_t));
end_of_func:
	/*LINTED statement has no consequent: else*/
	UNLOCK(hndl, release_lock);
	return (prexstat);
}

tnfctl_errcode_t
tnfctl_probe_trace(tnfctl_handle_t *hndl, tnfctl_probe_t *probe_hndl, void *cd)
{
	tnf_probe_control_t	*prbctl_p;
	boolean_t		release_lock;
	tnfctl_errcode_t 	prexstat;

	/*LINTED statement has no consequent: else*/
	LOCK_SYNC(hndl, prexstat, release_lock);

	prexstat = check_operation(hndl, probe_hndl);
	if (prexstat)
		goto end_of_func;

	prbctl_p = &probe_hndl->probe_p->wrkprbctl;
	prbctl_p->commit_func = (tnf_probe_func_t) hndl->commitfunc;
	prexstat = _tnfctl_flush_a_probe(hndl, probe_hndl->probe_p,
			offsetof(struct tnf_probe_control, commit_func),
			sizeof (tnf_probe_func_t));

end_of_func:
	/*LINTED statement has no consequent: else*/
	UNLOCK(hndl, release_lock);
	return (prexstat);
}

tnfctl_errcode_t
tnfctl_probe_untrace(tnfctl_handle_t *hndl, tnfctl_probe_t *probe_hndl,
		void *cd)
{
	tnf_probe_control_t	*prbctl_p;
	boolean_t		release_lock;
	tnfctl_errcode_t 	prexstat;

	/*LINTED statement has no consequent: else*/
	LOCK_SYNC(hndl, prexstat, release_lock);

	prexstat = check_operation(hndl, probe_hndl);
	if (prexstat)
		goto end_of_func;

	prbctl_p = &probe_hndl->probe_p->wrkprbctl;
	prbctl_p->commit_func = (tnf_probe_func_t) hndl->rollbackfunc;
	prexstat = _tnfctl_flush_a_probe(hndl, probe_hndl->probe_p,
			offsetof(struct tnf_probe_control, commit_func),
			sizeof (tnf_probe_func_t));

end_of_func:
	/*LINTED statement has no consequent: else*/
	UNLOCK(hndl, release_lock);
	return (prexstat);
}

tnfctl_errcode_t
tnfctl_probe_connect(tnfctl_handle_t *hndl, tnfctl_probe_t *probe_hndl,
			const char *lib_base_name, const char *func)
{
	tnf_probe_control_t	*prbctl_p;
	boolean_t		release_lock;
	tnfctl_errcode_t 	prexstat;
	uintptr_t		func_addr;
	uintptr_t		comb;

	if (hndl->mode == KERNEL_MODE)
		return (TNFCTL_ERR_BADARG);

	/*LINTED statement has no consequent: else*/
	LOCK_SYNC(hndl, prexstat, release_lock);

	prexstat = check_operation(hndl, probe_hndl);
	if (prexstat)
		goto end_of_func;

	if (func == NULL) {
		prexstat = TNFCTL_ERR_NONE;
		goto end_of_func;
	}

	if (lib_base_name) {
		prexstat = _tnfctl_sym_obj_find(hndl, lib_base_name, func,
					&func_addr);
	} else {
		prexstat = _tnfctl_sym_find(hndl, func, &func_addr);
	}
	/* check if function address was found */
	if (prexstat)
		goto end_of_func;

	prbctl_p = &probe_hndl->probe_p->wrkprbctl;
	prexstat = _tnfctl_comb_build(hndl, PRB_COMB_CHAIN,
			func_addr, (uintptr_t) prbctl_p->probe_func,
			&comb);
	if (prexstat)
		goto end_of_func;
	prbctl_p->probe_func = (tnf_probe_func_t) comb;
	prexstat = _tnfctl_flush_a_probe(hndl, probe_hndl->probe_p,
			offsetof(struct tnf_probe_control, probe_func),
			sizeof (tnf_probe_func_t));

end_of_func:
	/*LINTED statement has no consequent: else*/
	UNLOCK(hndl, release_lock);
	return (prexstat);
}

tnfctl_errcode_t
tnfctl_probe_disconnect_all(tnfctl_handle_t *hndl, tnfctl_probe_t *probe_hndl,
			void *cd)
{
	tnf_probe_control_t	*prbctl_p;
	boolean_t		release_lock;
	tnfctl_errcode_t 	prexstat;

	if (hndl->mode == KERNEL_MODE)
		return (TNFCTL_ERR_BADARG);

	/*LINTED statement has no consequent: else*/
	LOCK_SYNC(hndl, prexstat, release_lock);

	prexstat = check_operation(hndl, probe_hndl);
	if (prexstat)
		goto end_of_func;

	prbctl_p = &probe_hndl->probe_p->wrkprbctl;
	prbctl_p->probe_func = (tnf_probe_func_t) hndl->endfunc;
	prexstat = _tnfctl_flush_a_probe(hndl, probe_hndl->probe_p,
			offsetof(struct tnf_probe_control, probe_func),
			sizeof (tnf_probe_func_t));

end_of_func:
	/*LINTED statement has no consequent: else*/
	UNLOCK(hndl, release_lock);
	return (prexstat);
}

/*
 * Important that this function be tail recursive to minimize depth
 * of call chain that is called for every probe
 */
static tnfctl_errcode_t
apply_func(tnfctl_handle_t *hndl, prbctlref_t *probe, void *cd)
{
	struct pr_func_args *args = cd;
	tnfctl_errcode_t	prexstat;

	/* Call function only if match_func returns true */
	prexstat = (*(args->func_p))(hndl, probe->probe_handle, args->calldata);
	return (prexstat);
}
