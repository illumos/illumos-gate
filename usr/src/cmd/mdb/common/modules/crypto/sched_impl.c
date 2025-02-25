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
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2025 Oxide Computer Company
 */

#include <stdio.h>
#include <sys/mdb_modapi.h>
#include <sys/modctl.h>
#include <sys/types.h>
#include <sys/crypto/api.h>
#include <sys/crypto/common.h>
#include <sys/crypto/api.h>
#include <sys/crypto/sched_impl.h>
#include "crypto_cmds.h"

static void
prt_an_state(int state)
{
	switch (state) {
		case REQ_ALLOCATED:
			mdb_printf("REQ_ALLOCATED  ");
			break;
		case REQ_WAITING:
			mdb_printf("REQ_WAITING    ");
			break;
		case REQ_INPROGRESS:
			mdb_printf("REQ_INPROGRESS ");
			break;
		case REQ_DONE:
			mdb_printf("REQ_DONE       ");
			break;
		case REQ_CANCELED:
			mdb_printf("REQ_CANCELED   ");
			break;
		default:
			mdb_printf("? %d ??        ", state);
			break;
	}
}


static const mdb_bitmask_t call_flags[] = {
	{ "CRYPTO_ALWAYS_QUEUE", CRYPTO_ALWAYS_QUEUE, CRYPTO_ALWAYS_QUEUE },
	{ "CRYPTO_NOTIFY_OPDONE", CRYPTO_NOTIFY_OPDONE, CRYPTO_NOTIFY_OPDONE },
	{ "CRYPTO_SKIP_REQID", CRYPTO_SKIP_REQID, CRYPTO_SKIP_REQID },
	{ NULL, 0, 0 }
};

/*ARGSUSED*/
static int
kcf_areq_node_simple(kcf_areq_node_t *areqn)
{
	mdb_printf("\nan_type: ");
	if (areqn->an_type != CRYPTO_ASYNCH)
		mdb_printf("%-8d    ", areqn->an_type);
	else
		mdb_printf("CRYPTO_ASYNCH");

	mdb_printf("\nan_state: ");
	prt_an_state(areqn->an_state);

	mdb_printf("\nan_context: %-16p\t", areqn->an_context);
	mdb_printf("an_is_my_turn: %s\t     ", areqn->an_is_my_turn == B_FALSE ?
	    "B_FALSE" : "B_TRUE");

	mdb_printf("\ncr_reqid: %lx\n", areqn->an_reqarg.cr_reqid);
	return (DCMD_OK);
}
/*
 * Verbose print of kcf_areq_node_t
 */
static int
v_kcf_areq_node(kcf_areq_node_t *areqn)
{

	/* contents only -- the address is printed elsewhere */
	/* First column */

	mdb_printf("\n%16s:  ", "an_type");
	if (areqn->an_type != CRYPTO_ASYNCH)
		mdb_printf("%-8d    ", areqn->an_type);
	else
		mdb_printf("CRYPTO_ASYNCH");

	/* Second column */
	mdb_printf("\t\t%16s:  %p\n", "an_lock", areqn->an_lock);

	/* First column */
	mdb_printf("%16s:  ", "an_state");
	prt_an_state(areqn->an_state);

	/* Second column */
	mdb_printf("%14s:  next 4 items\n", "an_reqarg");

	/* First column again */
	mdb_printf("%16s: '%16b'", "cr_flag", areqn->an_reqarg.cr_flag,
	    call_flags);

	/* Second column */
	mdb_printf("\t%16s:  %p\n", "cr_callback_func",
	    areqn->an_reqarg.cr_callback_func);

	/* First column again */
	mdb_printf("%16s:  %-16p", "cr_callback_arg",
	    areqn->an_reqarg.cr_callback_arg);

	/* Second column */
	mdb_printf("\t%16s:  %lx\n", "cr_reqid",
	    (ulong_t)areqn->an_reqarg.cr_reqid);

	/* First column again */
	mdb_printf("%16s:  %d", "an_params.rp_opgrp",
	    areqn->an_params.rp_opgrp);

	/* Second column */
	mdb_printf("\t%16s:  %d\n", "an_params.rp_optype",
	    areqn->an_params.rp_optype);

	/* First column again */
	mdb_printf("%16s:  %-16p", "an_context",
	    areqn->an_context);

	/* Second column */
	mdb_printf("\t%16s:  %p\n", "an_ctxchain_next",
	    areqn->an_ctxchain_next);

	/* First column again */
	mdb_printf("%16s:  %s", "an_is_my_turn",
	    areqn->an_is_my_turn == B_FALSE ? "B_FALSE" : "B_TRUE");

	/* Second column */
	mdb_printf("\t\t%16s:  %s\n", "an_isdual",
	    areqn->an_isdual == B_FALSE ? "B_FALSE" : "B_TRUE");

	/* First column again */
	mdb_printf("%16s:  %p", "an_next",
	    areqn->an_next);

	/* Second column */
	mdb_printf("\t\t%16s:  %p\n", "an_prev", areqn->an_prev);

	/* First column again */
	mdb_printf("%16s:  %p", "an_provider",
	    areqn->an_provider);

	/* Second column */
	mdb_printf("\t\t%16s:  %p\n", "an_idnext", areqn->an_idnext);

	/* First column again */
	mdb_printf("%16s:  %p", "an_idprev",
	    areqn->an_idprev);

	/* Second column */
	mdb_printf("\t\t%16s:  %hx\n", "an_done", areqn->an_done);

	/* First column again */
	mdb_printf("%16s:  %d\n", "an_refcnt",
	    areqn->an_refcnt);

	return (DCMD_OK);
}
/*ARGSUSED*/
int
kcf_areq_node(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	kcf_areq_node_t areqn;
	uint_t opt_v = FALSE;


	if (mdb_getopts(argc, argv, 'v', MDB_OPT_SETBITS, TRUE, &opt_v,
	    NULL) != argc)
			return (DCMD_USAGE);

	/*
	 * read even if we're looping, because the cbdata design does not
	 * apply to mdb_pwalk_dcmd
	 */
	if (mdb_vread(&areqn, sizeof (kcf_areq_node_t), addr) == -1) {
		mdb_warn("cannot read %p", addr);
		return (DCMD_ERR);
	}
	if (opt_v)	/* verbose */
		return (v_kcf_areq_node(&areqn));
	else
		return (kcf_areq_node_simple(&areqn));
}

/*ARGSUSED*/
int
kcf_global_swq(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	kcf_global_swq_t swq;
	kcf_global_swq_t *ptr;

	if (!(flags & DCMD_ADDRSPEC)) {
		if (mdb_readsym(&ptr, sizeof (uintptr_t), "gswq")
		    == -1) {
			mdb_warn("cannot read gswq");
			return (DCMD_ERR);
		}
	}
	else
		ptr = (kcf_global_swq_t *)addr;

	if (mdb_vread(&swq, sizeof (kcf_global_swq_t), (uintptr_t)ptr) == -1) {
		mdb_warn("cannot read %p", ptr);
		return (DCMD_ERR);
	}
	mdb_printf("gs_lock (mutex):\t%p\n", swq.gs_lock);
	mdb_printf("gs_cv:\t%hx\n", swq.gs_cv._opaque);
	mdb_printf("gs_njobs:\t%u\n", swq.gs_njobs);
	mdb_printf("gs_maxjobs:\t%u\n", swq.gs_maxjobs);
	mdb_printf("gs_first:\t%p\n", swq.gs_first);
	mdb_printf("gs_last:\t%p\n", swq.gs_last);
	return (mdb_pwalk_dcmd("an_next", "kcf_areq_node", argc,
	    argv, (uintptr_t)swq.gs_first));
}

static int
areq_walk_init_common(mdb_walk_state_t *wsp, boolean_t use_first)
{
	kcf_global_swq_t gswq_copy;
	uintptr_t gswq_ptr;

	if (mdb_readsym(&gswq_ptr, sizeof (gswq_ptr), "gswq") == -1) {
		mdb_warn("failed to read 'gswq'");
		return (WALK_ERR);
	}
	if (mdb_vread(&gswq_copy, sizeof (gswq_copy), gswq_ptr) == -1) {
		mdb_warn("cannot read %p", gswq_ptr);
		return (WALK_ERR);
	}
	if ((wsp->walk_addr = (use_first ? (uintptr_t)gswq_copy.gs_first :
	    (uintptr_t)gswq_copy.gs_last)) == 0) {
		mdb_printf("Global swq is empty\n");
		return (WALK_DONE);
	}
	wsp->walk_data = mdb_alloc(sizeof (kcf_areq_node_t), UM_SLEEP);
	return (WALK_NEXT);
}

int
areq_first_walk_init(mdb_walk_state_t *wsp)
{
	return (areq_walk_init_common(wsp, B_TRUE));
}

int
areq_last_walk_init(mdb_walk_state_t *wsp)
{
	return (areq_walk_init_common(wsp, B_FALSE));
}

typedef enum idwalk_type {
	IDNEXT,		/* an_idnext */
	IDPREV,		/* an_idprev */
	CTXCHAIN	/* an_ctxchain_next */
} idwalk_type_t;

static int
an_id_walk_init(mdb_walk_state_t *wsp, idwalk_type_t type)
{
	kcf_areq_node_t *adn;

	if (wsp->walk_addr == 0) {
		mdb_warn("must give kcf_areq_node address\n");
		return (WALK_ERR);
	}
	adn = wsp->walk_data = mdb_alloc(sizeof (kcf_areq_node_t), UM_SLEEP);

	if (mdb_vread(adn, sizeof (kcf_areq_node_t), wsp->walk_addr) == -1) {
		mdb_warn("cannot read %p", wsp->walk_addr);
		return (WALK_ERR);
	}

	switch (type) {
		case IDNEXT:
			wsp->walk_addr = (uintptr_t)adn->an_idnext;
			break;
		case IDPREV:
			wsp->walk_addr = (uintptr_t)adn->an_idprev;
			break;
		case CTXCHAIN:
			wsp->walk_addr = (uintptr_t)adn->an_ctxchain_next;
			break;
		default:
			mdb_warn("Bad structure member in walk_init\n");
			return (WALK_ERR);
	}
	return (WALK_NEXT);
}
int
an_idnext_walk_init(mdb_walk_state_t *wsp)
{
	return (an_id_walk_init(wsp, IDNEXT));
}
int
an_idprev_walk_init(mdb_walk_state_t *wsp)
{
	return (an_id_walk_init(wsp, IDPREV));
}
int
an_ctxchain_walk_init(mdb_walk_state_t *wsp)
{
	return (an_id_walk_init(wsp, CTXCHAIN));
}
/*
 * At each step, read a kcf_areq_node_t into our private storage, then invoke
 * the callback function.  We terminate when we reach a NULL type pointer.
 */
static int
an_id_walk_step(mdb_walk_state_t *wsp, idwalk_type_t type)
{
	int status;
	kcf_areq_node_t *ptr;

	if (wsp->walk_addr == 0)	/* then we're done */
		return (WALK_DONE);

	ptr = wsp->walk_data;

	if (mdb_vread(wsp->walk_data, sizeof (kcf_areq_node_t),
	    wsp->walk_addr) == -1) {
		mdb_warn("cannot read %p", wsp->walk_addr);
		return (WALK_ERR);
	}

	status = wsp->walk_callback(wsp->walk_addr, wsp->walk_data,
	    wsp->walk_cbdata);

	switch (type) {
		case IDNEXT:
			if ((wsp->walk_addr =
			    (uintptr_t)ptr->an_idnext) == 0)
				return (WALK_DONE);
			break;

		case IDPREV:
			if ((wsp->walk_addr =
			    (uintptr_t)ptr->an_idprev) == 0)
				return (WALK_DONE);
			break;

		case CTXCHAIN:
			if ((wsp->walk_addr =
			    (uintptr_t)ptr->an_ctxchain_next) == 0)
				return (WALK_DONE);
			break;

		default:
			mdb_warn("Bad structure member in walk_step\n");
			return (WALK_ERR);
	}
	return (status);
}
int
an_idnext_walk_step(mdb_walk_state_t *wsp)
{
	return (an_id_walk_step(wsp, IDNEXT));
}
int
an_idprev_walk_step(mdb_walk_state_t *wsp)
{
	return (an_id_walk_step(wsp, IDPREV));
}
int
an_ctxchain_walk_step(mdb_walk_state_t *wsp)
{
	return (an_id_walk_step(wsp, CTXCHAIN));
}

/*
 * The walker's fini function is invoked at the end of each walk.  Since we
 * dynamically allocated a kcf_areq_node_t in areq_walk_init,
 * we must free it now.
 */
void
areq_walk_fini(mdb_walk_state_t *wsp)
{
#ifdef	DEBUG
	mdb_printf("...end of kcf_areq_node walk\n");
#endif
	mdb_free(wsp->walk_data, sizeof (kcf_areq_node_t));
}

/*
 * At each step, read a kcf_areq_node_t into our private storage, then invoke
 * the callback function.  We terminate when we reach a NULL an_next pointer
 * or a NULL an_prev pointer. use_next flag indicates which one to check.
 */
static int
an_walk_step_common(mdb_walk_state_t *wsp, boolean_t use_next)
{
	int status;
	kcf_areq_node_t *ptr;

	ptr = (kcf_areq_node_t *)wsp->walk_data;

	if (mdb_vread(wsp->walk_data, sizeof (kcf_areq_node_t),
	    wsp->walk_addr) == -1) {
		mdb_warn("failed to read kcf_areq_node at %p", wsp->walk_addr);
		return (WALK_DONE);
	}
	status = wsp->walk_callback(wsp->walk_addr, wsp->walk_data,
	    wsp->walk_cbdata);

	if ((wsp->walk_addr = (use_next ? (uintptr_t)ptr->an_next :
	    (uintptr_t)ptr->an_prev)) == 0)
		return (WALK_DONE);

	return (status);
}

int
an_next_walk_step(mdb_walk_state_t *wsp)
{
	return (an_walk_step_common(wsp, B_TRUE));
}

int
an_prev_walk_step(mdb_walk_state_t *wsp)
{
	return (an_walk_step_common(wsp, B_FALSE));
}

/*
 * Walker data for reqid_table walking
 */
typedef	struct reqid_data {
	kcf_reqid_table_t rd_table;
	kcf_reqid_table_t *rd_tbl_ptrs[REQID_TABLES];
	int		rd_cur_index;
} reqid_data_t;

typedef struct reqid_cb_data {
	crypto_req_id_t cb_reqid;
	int verbose;
	int found;
} reqid_cb_data_t;

extern int crypto_pr_reqid(uintptr_t, reqid_data_t *, reqid_cb_data_t *);


int
reqid_table_walk_init(mdb_walk_state_t *wsp)
{
	reqid_data_t *wdata;
	reqid_cb_data_t *cbdata;

	wsp->walk_callback = (mdb_walk_cb_t)crypto_pr_reqid;

	wsp->walk_data = mdb_alloc(sizeof (reqid_data_t), UM_SLEEP);

	/* see if the walker was called from the command line or mdb_pwalk */
	if (wsp->walk_cbdata == NULL) {		/* command line */
		if ((wsp->walk_cbdata = mdb_zalloc(sizeof (reqid_cb_data_t),
		    UM_SLEEP)) == NULL) {
			mdb_warn("couldn't get cb memory for "
			    "reqid_table_walker");
			return (WALK_ERR);
		}
		/* initialize for a simple walk, as opposed to a reqid search */
		cbdata = wsp->walk_cbdata;
		cbdata->verbose = TRUE;
		cbdata->cb_reqid = 0;
	}

	wdata = (reqid_data_t *)wsp->walk_data;

	if (mdb_readsym(wdata->rd_tbl_ptrs, sizeof (wdata->rd_tbl_ptrs),
	    "kcf_reqid_table") == -1) {
		mdb_warn("failed to read 'kcf_reqid_table'");
		return (WALK_ERR);

	}
	wdata->rd_cur_index = 0;
	wsp->walk_addr = (uintptr_t)wdata->rd_tbl_ptrs[wdata->rd_cur_index];


	return (WALK_NEXT);
}

/*
 * At each step, read a kcf_reqid_table_t into our private storage, then invoke
 * the callback function.  We terminate when we reach a
 */
int
reqid_table_walk_step(mdb_walk_state_t *wsp)
{
	int status;
	reqid_data_t *wdata;


	wdata = wsp->walk_data;
	wsp->walk_addr = (uintptr_t)wdata->rd_tbl_ptrs[wdata->rd_cur_index];

#ifdef DEBUG
	mdb_printf(
	    "DEBUG: kcf_reqid_table at %p, sizeof kcf_reqid_table_t = %d\n",
	    wsp->walk_addr, sizeof (kcf_reqid_table_t));
#endif

	status = wsp->walk_callback(wsp->walk_addr, wsp->walk_data,
	    wsp->walk_cbdata);

	/* get ready for next call */
	wdata->rd_cur_index++;
	if (wdata->rd_cur_index >= REQID_TABLES)
		return (WALK_DONE);
	return (status);
}

/*
 * The walker's fini function is invoked at the end of each walk.  Since we
 * dynamically allocated a reqid_data_t in areq_walk_init,
 * we must free it now.
 */
void
reqid_table_walk_fini(mdb_walk_state_t *wsp)
{
#ifdef DEBUG
	mdb_printf("...end of kcf_reqid walk\n");
#endif
	mdb_free(wsp->walk_data, sizeof (reqid_data_t));
}

/*
 * If there's an argument beyond -v, then we're looking for a specific
 * reqid, otherwise, print any non-null kcf_areq things we run across.
 */

int
crypto_pr_reqid(uintptr_t addr, reqid_data_t *data, reqid_cb_data_t *cbdata)
{
	kcf_areq_node_t node;
	int i;
	int needhdr = TRUE;

	if (addr == 0) {
		mdb_printf("kcf_reqid_table[%d] = NULL\n", data->rd_cur_index);
		return (WALK_NEXT);
	}

	if (mdb_vread(&(data->rd_table), sizeof (kcf_reqid_table_t),
	    addr) == -1) {
		mdb_warn("failed to read kcf_reqid_table at %p",
		    addr);
		return (WALK_ERR);
	}

	/* Loop over all rt_idhash's */
	for (i = 0; i < REQID_BUCKETS; i++) {
	    uint_t number_in_chain = 0;
	    uintptr_t node_addr;

	    /* follow the an_idnext chains for each bucket */
	    do {
		/* read kcf_areq_node */
		if (number_in_chain == 0)
		    node_addr = (uintptr_t)data->rd_table.rt_idhash[i];
		else
		    /*LINTED*/
		    node_addr = (uintptr_t)node.an_idnext;
#ifdef DEBUG
		mdb_printf("DEBUG: node_addr = %p\n", node_addr);
#endif

		if (node_addr == 0)
			break;  /* skip */

		if (mdb_vread(&node, sizeof (kcf_areq_node_t), node_addr)
		    == -1) {
			if (cbdata->verbose == TRUE)
			    mdb_printf(
				"cannot read rt_idhash %d an_idnext %d\n",
				i, number_in_chain);
			break;
		}
		/* see if we want to print it */
		if ((cbdata->cb_reqid == 0) ||
		    (node.an_reqarg.cr_reqid == cbdata->cb_reqid)) {
			cbdata->found = TRUE;  /* printed if false || reqid */
			/* is this the first rd_idhash found for this table? */
			if (needhdr == TRUE) {
			    /* print both indices in bold */
			    mdb_printf("%<b>kcf_reqid_table[%lu] at %p:%</b>\n",
				data->rd_cur_index, addr);
			    mdb_printf("\trt_lock:  %p\trt_curid: %llx\n",
				data->rd_table.rt_lock,
				data->rd_table.rt_curid);
			    needhdr = FALSE;
			}
			/* print kcf_areq_node */
			if (number_in_chain < 1)
			    mdb_printf(
				"    %<b>rt_idhash[%lu%]%</b> = %<b>%p:%</b>\n",
				i, node_addr);
			else
			    mdb_printf(
				"    rt_idhash[%lu%]"
					" an_idnext %d  = %<b>%p:%</b>\n",
					i, number_in_chain, node_addr);
			mdb_inc_indent(8);

			/* if we're looking for one and only one reqid */
			/* do it REALLY verbose */
			if ((node.an_reqarg.cr_reqid == cbdata->cb_reqid) &&
			    (cbdata->cb_reqid != 0))
				v_kcf_areq_node(&node);
			else if (cbdata->verbose == TRUE)
			/*
			 * verbose for this walker means non-verbose for
			 * the kcf_areq_node details
			 */
			    kcf_areq_node_simple(&node);
			mdb_dec_indent(8);
		}
		/* if we only wanted one reqid, quit now */
		if (node.an_reqarg.cr_reqid == cbdata->cb_reqid) {
			return (WALK_DONE);
		}

		number_in_chain++;

	    } while (node.an_idnext != NULL); /* follow chain in same bucket */

	}  /* for each REQID_BUCKETS */

	if ((needhdr == TRUE) && (cbdata->cb_reqid == 0)) {
	    mdb_printf("%kcf_reqid_table[%lu]: %p\n",
		data->rd_cur_index, addr);
	}
	return (WALK_NEXT);
}

/*ARGSUSED*/
int
crypto_find_reqid(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	const mdb_arg_t *argp = NULL;
	reqid_cb_data_t cbdata;
	int i, status;

	cbdata.cb_reqid = 0L;
	cbdata.verbose = FALSE;
	cbdata.found = FALSE;

	if (flags & DCMD_ADDRSPEC) {
		mdb_printf("use addr ::kcf_reqid_table\n");
		return (DCMD_USAGE);
	}
	if ((i = mdb_getopts(argc, argv, 'v', MDB_OPT_SETBITS, TRUE,
	    &cbdata.verbose, NULL)) != argc) {
		if (argc - i > 1)
			return (DCMD_USAGE);
	}

	if (argc > i)
		argp = &argv[i];

	if ((argp != NULL))
		cbdata.cb_reqid = (crypto_req_id_t)mdb_argtoull(argp);
	status = mdb_pwalk("kcf_reqid_table", (mdb_walk_cb_t)crypto_pr_reqid,
	    &cbdata, addr);

	if ((cbdata.cb_reqid != 0L) && (cbdata.found == FALSE))
		mdb_printf("ID 0x%lx not found\n", cbdata.cb_reqid);
#ifdef DEBUG
	else
		mdb_printf("DEBUG: cbdata.db_reqid = %lx, cbdata.found = %d\n",
		    cbdata.cb_reqid, cbdata.found);
#endif

	return (status);
}

int
kcf_reqid_table_dcmd(uintptr_t addr, uint_t flags, int argc,
    const mdb_arg_t *argv)
{
	reqid_data_t wdata;
	reqid_cb_data_t cbdata;

	if (!(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	memset(&wdata, 0, sizeof (wdata));
	memset(&cbdata, 0, sizeof (cbdata));

	if ((mdb_getopts(argc, argv, 'v', MDB_OPT_SETBITS, TRUE,
	    &cbdata.verbose, NULL)) != argc) {
			return (DCMD_USAGE);
	}
	crypto_pr_reqid(addr, &wdata, &cbdata);
	return (DCMD_OK);
}
