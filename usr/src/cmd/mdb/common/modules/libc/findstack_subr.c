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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <mdb/mdb_modapi.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/avl.h>
#include <sys/lwp.h>
#include <thr_uberdata.h>
#include <stddef.h>
#include "findstack.h"

#if defined(__i386) || defined(__amd64)
struct rwindow {
	uintptr_t rw_fp;
	uintptr_t rw_rtn;
};
#endif

#ifndef STACK_BIAS
#define	STACK_BIAS	0
#endif

#ifdef __amd64
#define	STACKS_REGS_FP	"rbp"
#define	STACKS_REGS_RC	"rip"
#else
#ifdef __i386
#define	STACKS_REGS_FP	"ebp"
#define	STACKS_REGS_RC	"eip"
#else
#define	STACKS_REGS_FP	"fp"
#define	STACKS_REGS_RC	"pc"
#endif
#endif

#define	STACKS_SOBJ_MX	(uintptr_t)"MX"
#define	STACKS_SOBJ_CV	(uintptr_t)"CV"

int
thread_text_to_state(const char *state, uint_t *out)
{
	if (strcmp(state, "PARKED") == 0) {
		*out = B_TRUE;
	} else if (strcmp(state, "UNPARKED") == 0) {
		*out = B_FALSE;
	} else if (strcmp(state, "FREE") == 0) {
		/*
		 * When run with "-i", ::stacks filters out "FREE" threads.
		 * We therefore need to recognize "FREE", and set it to a
		 * value that will never match fsi_tstate.
		 */
		*out = UINT_MAX;
	} else {
		return (-1);
	}

	return (0);
}

void
thread_state_to_text(uint_t state, char *out, size_t out_sz)
{
	(void) snprintf(out, out_sz, state ? "PARKED" : "UNPARKED");
}

int
sobj_text_to_ops(const char *name, uintptr_t *sobj_ops_out)
{
	if (strcmp(name, "MX") == 0) {
		*sobj_ops_out = STACKS_SOBJ_MX;
	} else if (strcmp(name, "CV") == 0) {
		*sobj_ops_out = STACKS_SOBJ_CV;
	} else {
		mdb_warn("sobj \"%s\" not recognized\n", name);
		return (-1);
	}

	return (0);
}

void
sobj_ops_to_text(uintptr_t addr, char *out, size_t sz)
{
	(void) snprintf(out, sz, "%s", addr == 0 ? "<none>" : (char *)addr);
}

static int
stacks_module_callback(mdb_object_t *obj, void *arg)
{
	stacks_module_t *smp = arg;
	boolean_t match = (strcmp(obj->obj_name, smp->sm_name) == 0);
	char *suffix = ".so";
	const char *s, *next;
	size_t len;

	if (smp->sm_size != 0)
		return (0);

	/*
	 * It doesn't match the name, but -- for convenience -- we want to
	 * allow matches before ".so.[suffix]".  An aside:  why doesn't
	 * strrstr() exist?  (Don't google that.  I'm serious, don't do it.
	 * If you do, and you read the thread of "why doesn't strrstr() exist?"
	 * circa 2005 you will see things that you will NEVER be able to unsee!)
	 */
	if (!match && (s = strstr(obj->obj_name, suffix)) != NULL) {
		while ((next = strstr(s + 1, suffix)) != NULL) {
			s = next;
			continue;
		}

		len = s - obj->obj_name;

		match = (strncmp(smp->sm_name, obj->obj_name, len) == 0 &&
		    smp->sm_name[len] == '\0');
	}

	/*
	 * If we have a library that has the libc directory in the path, we
	 * want to match against anything that would match libc.so.1.  (This
	 * is necessary to be able to easily deal with libc implementations
	 * that have alternate hardware capabilities.)
	 */
	if (!match && strstr(obj->obj_fullname, "/libc/") != NULL) {
		mdb_object_t libc = *obj;

		libc.obj_name = "libc.so.1";
		libc.obj_fullname = "";

		return (stacks_module_callback(&libc, arg));
	}

	if (match) {
		smp->sm_text = obj->obj_base;
		smp->sm_size = obj->obj_size;
	}

	return (0);
}

int
stacks_module(stacks_module_t *smp)
{
	if (mdb_object_iter(stacks_module_callback, smp) != 0)
		return (-1);

	return (0);
}

typedef struct stacks_ulwp {
	avl_node_t sulwp_node;
	lwpid_t sulwp_id;
	uintptr_t sulwp_addr;
} stacks_ulwp_t;

boolean_t stacks_ulwp_initialized;
avl_tree_t stacks_ulwp_byid;

/*ARGSUSED*/
int
stacks_ulwp_walk(uintptr_t addr, ulwp_t *ulwp, void *ignored)
{
	stacks_ulwp_t *sulwp = mdb_alloc(sizeof (stacks_ulwp_t), UM_SLEEP);

	sulwp->sulwp_id = ulwp->ul_lwpid;
	sulwp->sulwp_addr = addr;

	if (avl_find(&stacks_ulwp_byid, sulwp, NULL) != NULL) {
		mdb_warn("found multiple LWPs with ID %d!", ulwp->ul_lwpid);
		return (WALK_ERR);
	}

	avl_add(&stacks_ulwp_byid, sulwp);

	return (WALK_NEXT);
}

static int
stacks_ulwp_compare(const void *l, const void *r)
{
	const stacks_ulwp_t *lhs = l;
	const stacks_ulwp_t *rhs = r;

	if (lhs->sulwp_id > rhs->sulwp_id)
		return (1);

	if (lhs->sulwp_id < rhs->sulwp_id)
		return (-1);

	return (0);
}

/*ARGSUSED*/
int
stacks_findstack(uintptr_t addr, findstack_info_t *fsip, uint_t print_warnings)
{
	mdb_reg_t reg;
	uintptr_t fp;
	struct rwindow frame;
	avl_tree_t *tree = &stacks_ulwp_byid;
	stacks_ulwp_t *sulwp, cmp;
	ulwp_t ulwp;

	fsip->fsi_failed = 0;
	fsip->fsi_pc = 0;
	fsip->fsi_sp = 0;
	fsip->fsi_depth = 0;
	fsip->fsi_overflow = 0;

	if (!stacks_ulwp_initialized) {
		avl_create(tree, stacks_ulwp_compare, sizeof (stacks_ulwp_t),
		    offsetof(stacks_ulwp_t, sulwp_node));

		if (mdb_walk("ulwp",
		    (mdb_walk_cb_t)stacks_ulwp_walk, NULL) != 0) {
			mdb_warn("couldn't walk 'ulwp'");
			return (-1);
		}

		stacks_ulwp_initialized = B_TRUE;
	}

	bzero(&cmp, sizeof (cmp));
	cmp.sulwp_id = (lwpid_t)addr;

	if ((sulwp = avl_find(tree, &cmp, NULL)) == NULL) {
		mdb_warn("couldn't find ulwp_t for tid %d\n", cmp.sulwp_id);
		return (-1);
	}

	if (mdb_vread(&ulwp, sizeof (ulwp), sulwp->sulwp_addr) == -1) {
		mdb_warn("couldn't read ulwp_t for tid %d at %p",
		    cmp.sulwp_id, sulwp->sulwp_addr);
		return (-1);
	}

	fsip->fsi_tstate = ulwp.ul_sleepq != NULL;
	fsip->fsi_sobj_ops = (uintptr_t)(ulwp.ul_sleepq == NULL ? 0 :
	    (ulwp.ul_qtype == MX ? STACKS_SOBJ_MX : STACKS_SOBJ_CV));

	if (mdb_getareg(addr, STACKS_REGS_FP, &reg) != 0) {
		mdb_warn("couldn't read frame pointer for thread 0x%p", addr);
		return (-1);
	}

	fsip->fsi_sp = fp = (uintptr_t)reg;

#if !defined(__i386)
	if (mdb_getareg(addr, STACKS_REGS_RC, &reg) != 0) {
		mdb_warn("couldn't read program counter for thread 0x%p", addr);
		return (-1);
	}

	fsip->fsi_pc = (uintptr_t)reg;
#endif

	while (fp != 0) {
		if (mdb_vread(&frame, sizeof (frame), fp) == -1) {
			mdb_warn("couldn't read frame for thread 0x%p at %p",
			    addr, fp);
			return (-1);
		}

		if (frame.rw_rtn == 0)
			break;

		if (fsip->fsi_depth < fsip->fsi_max_depth) {
			fsip->fsi_stack[fsip->fsi_depth++] = frame.rw_rtn;
		} else {
			fsip->fsi_overflow = 1;
			break;
		}

		fp = frame.rw_fp + STACK_BIAS;
	}

	return (0);
}

void
stacks_findstack_cleanup()
{
	avl_tree_t *tree = &stacks_ulwp_byid;
	void *cookie = NULL;
	stacks_ulwp_t *sulwp;

	if (!stacks_ulwp_initialized)
		return;

	while ((sulwp = avl_destroy_nodes(tree, &cookie)) != NULL)
		mdb_free(sulwp, sizeof (stacks_ulwp_t));

	bzero(tree, sizeof (*tree));
	stacks_ulwp_initialized = B_FALSE;
}

void
stacks_help(void)
{
	mdb_printf(
"::stacks processes all of the thread stacks in the process, grouping\n"
"together threads which have the same:\n"
"\n"
"  * Thread state,\n"
"  * Sync object type, and\n"
"  * PCs in their stack trace.\n"
"\n"
"The default output (no address or options) is just a dump of the thread\n"
"groups in the process.  For a view of active threads, use \"::stacks -i\",\n"
"which filters out threads sleeping on a CV.  More general filtering options\n"
"are described below, in the \"FILTERS\" section.\n"
"\n"
"::stacks can be used in a pipeline.  The input to ::stacks is one or more\n"
"thread IDs.  When output into a pipe, ::stacks prints all of the threads \n"
"input, filtered by the given filtering options.  This means that multiple\n"
"::stacks invocations can be piped together to achieve more complicated\n"
"filters.  For example, to get threads which have both '__door_return' and\n"
"'mutex_lock' in their stack trace, you could do:\n"
"\n"
"  ::stacks -c __door_return | ::stacks -c mutex_lock\n"
"\n"
"To get the full list of threads in each group, use the '-a' flag:\n"
"\n"
"  ::stacks -a\n"
"\n");
	mdb_dec_indent(2);
	mdb_printf("%<b>OPTIONS%</b>\n");
	mdb_inc_indent(2);
	mdb_printf("%s",
"  -a    Print all of the grouped threads, instead of just a count.\n"
"  -f    Force a re-run of the thread stack gathering.\n"
"  -v    Be verbose about thread stack gathering.\n"
"\n");
	mdb_dec_indent(2);
	mdb_printf("%<b>FILTERS%</b>\n");
	mdb_inc_indent(2);
	mdb_printf("%s",
"  -i    Show active threads; equivalent to '-S CV'.\n"
"  -c func[+offset]\n"
"        Only print threads whose stacks contain func/func+offset.\n"
"  -C func[+offset]\n"
"        Only print threads whose stacks do not contain func/func+offset.\n"
"  -m module\n"
"        Only print threads whose stacks contain functions from module.\n"
"  -M module\n"
"        Only print threads whose stacks do not contain functions from\n"
"        module.\n"
"  -s {type | ALL}\n"
"        Only print threads which are on a 'type' synchronization object\n"
"        (SOBJ).\n"
"  -S {type | ALL}\n"
"        Only print threads which are not on a 'type' SOBJ.\n"
"  -t tstate\n"
"        Only print threads which are in thread state 'tstate'.\n"
"  -T tstate\n"
"        Only print threads which are not in thread state 'tstate'.\n"
"\n");
}
