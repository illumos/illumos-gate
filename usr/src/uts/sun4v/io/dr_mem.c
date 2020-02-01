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
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * sun4v Memory DR Module
 */


#include <sys/types.h>
#include <sys/cmn_err.h>
#include <sys/vmem.h>
#include <sys/kmem.h>
#include <sys/systm.h>
#include <sys/machsystm.h>	/* for page_freelist_coalesce() */
#include <sys/errno.h>
#include <sys/memnode.h>
#include <sys/memlist.h>
#include <sys/memlist_impl.h>
#include <sys/tuneable.h>
#include <sys/proc.h>
#include <sys/disp.h>
#include <sys/debug.h>
#include <sys/vm.h>
#include <sys/callb.h>
#include <sys/memlist_plat.h>	/* for installed_top_size() */
#include <sys/condvar_impl.h>	/* for CV_HAS_WAITERS() */
#include <sys/dumphdr.h>	/* for dump_resize() */
#include <sys/atomic.h>		/* for use in stats collection */
#include <sys/rwlock.h>
#include <vm/seg_kmem.h>
#include <vm/seg_kpm.h>
#include <vm/page.h>
#include <vm/vm_dep.h>
#define	SUNDDI_IMPL		/* so sunddi.h will not redefine splx() et al */
#include <sys/sunddi.h>
#include <sys/mem_config.h>
#include <sys/mem_cage.h>
#include <sys/lgrp.h>
#include <sys/ddi.h>

#include <sys/modctl.h>
#include <sys/sysevent/dr.h>
#include <sys/mach_descrip.h>
#include <sys/mdesc.h>
#include <sys/ds.h>
#include <sys/drctl.h>
#include <sys/dr_util.h>
#include <sys/dr_mem.h>
#include <sys/suspend.h>


/*
 * DR operations are subject to Memory Alignment restrictions
 * for both address and the size of the request.
 */
#define	MA_ADDR	0x10000000	/* addr alignment 256M */
#define	MA_SIZE	0x10000000	/* size alignment 256M */

#define	MBLK_IS_VALID(m) \
	(IS_P2ALIGNED((m)->addr, MA_ADDR) && IS_P2ALIGNED((m)->size, MA_SIZE))

static memhandle_t dr_mh;	/* memory handle for delete */

static struct modlmisc modlmisc = {
	&mod_miscops,
	"sun4v memory DR"
};

static struct modlinkage modlinkage = {
	MODREV_1,
	(void *)&modlmisc,
	NULL
};

static int dr_mem_allow_unload = 0;

typedef int (*fn_t)(dr_mem_blk_t *, int *);

/*
 * Global Domain Services (DS) Handle
 */
static ds_svc_hdl_t ds_handle;

/*
 * Supported DS Capability Versions
 */
static ds_ver_t		dr_mem_vers[] = { { 1, 0 } };
#define	DR_MEM_NVERS	(sizeof (dr_mem_vers) / sizeof (dr_mem_vers[0]))

/*
 * DS Capability Description
 */
static ds_capability_t dr_mem_cap = {
	DR_MEM_DS_ID,		/* svc_id */
	dr_mem_vers,		/* vers */
	DR_MEM_NVERS		/* nvers */
};

/*
 * DS Callbacks
 */
static void dr_mem_reg_handler(ds_cb_arg_t, ds_ver_t *, ds_svc_hdl_t);
static void dr_mem_unreg_handler(ds_cb_arg_t arg);
static void dr_mem_data_handler(ds_cb_arg_t arg, void *buf, size_t buflen);

/*
 * DS Client Ops Vector
 */
static ds_clnt_ops_t dr_mem_ops = {
	dr_mem_reg_handler,	/* ds_reg_cb */
	dr_mem_unreg_handler,	/* ds_unreg_cb */
	dr_mem_data_handler,	/* ds_data_cb */
	NULL			/* cb_arg */
};

/*
 * Operation Results
 *
 * Used internally to gather results while an operation on a
 * list of mblks is in progress. In particular, it is used to
 * keep track of which mblks have already failed so that they are
 * not processed further, and the manner in which they failed.
 */
typedef struct {
	uint64_t	addr;
	uint64_t	size;
	uint32_t	result;
	uint32_t	status;
	char		*string;
} dr_mem_res_t;

static char *
dr_mem_estr[] = {
	"operation succeeded",		/* DR_MEM_RES_OK */
	"operation failed",		/* DR_MEM_RES_FAILURE */
	"operation was blocked",	/* DR_MEM_RES_BLOCKED */
	"memory not defined in MD",	/* DR_MEM_RES_NOT_IN_MD */
	"memory already in use",	/* DR_MEM_RES_ESPAN */
	"memory access test failed",	/* DR_MEM_RES_EFAULT */
	"resource not available",	/* DR_MEM_RES_ERESOURCE */
	"permanent pages in span",	/* DR_MEM_RES_PERM */
	"memory span busy",		/* DR_MEM_RES_EBUSY */
	"VM viability test failed",	/* DR_MEM_RES_ENOTVIABLE */
	"no pages to unconfigure",	/* DR_MEM_RES_ENOWORK */
	"operation cancelled",		/* DR_MEM_RES_ECANCELLED */
	"operation refused",		/* DR_MEM_RES_EREFUSED */
	"memory span duplicate",	/* DR_MEM_RES_EDUP */
	"invalid argument"		/* DR_MEM_RES_EINVAL */
};

static char *
dr_mem_estr_detail[] = {
	"",					/* DR_MEM_SRES_NONE */
	"memory DR disabled after migration"	/* DR_MEM_SRES_OS_SUSPENDED */
};

typedef struct {
	kcondvar_t cond;
	kmutex_t lock;
	int error;
	int done;
} mem_sync_t;

/*
 * Internal Functions
 */
static int dr_mem_init(void);
static int dr_mem_fini(void);

static int dr_mem_list_wrk(dr_mem_hdr_t *, dr_mem_hdr_t **, int *);
static int dr_mem_list_query(dr_mem_hdr_t *, dr_mem_hdr_t **, int *);
static int dr_mem_del_stat(dr_mem_hdr_t *, dr_mem_hdr_t **, int *);
static int dr_mem_del_cancel(dr_mem_hdr_t *, dr_mem_hdr_t **, int *);

static int dr_mem_unconfigure(dr_mem_blk_t *, int *);
static int dr_mem_configure(dr_mem_blk_t *, int *);
static void dr_mem_query(dr_mem_blk_t *, dr_mem_query_t *);

static dr_mem_res_t *dr_mem_res_array_init(dr_mem_hdr_t *, drctl_rsrc_t *, int);
static void dr_mem_res_array_fini(dr_mem_res_t *res, int nres);
static size_t dr_mem_pack_response(dr_mem_hdr_t *req, dr_mem_res_t *res,
    dr_mem_hdr_t **respp);

static int dr_mem_find(dr_mem_blk_t *mbp);
static mde_cookie_t dr_mem_find_node_md(dr_mem_blk_t *, md_t *, mde_cookie_t *);

static int mem_add(pfn_t, pgcnt_t);
static int mem_del(pfn_t, pgcnt_t);

extern int kphysm_add_memory_dynamic(pfn_t, pgcnt_t);

int
_init(void)
{
	int	status;

	/* check that Memory DR is enabled */
	if (dr_is_disabled(DR_TYPE_MEM))
		return (ENOTSUP);

	if ((status = dr_mem_init()) != 0) {
		cmn_err(CE_NOTE, "Memory DR initialization failed");
		return (status);
	}

	if ((status = mod_install(&modlinkage)) != 0) {
		(void) dr_mem_fini();
	}

	return (status);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

int
_fini(void)
{
	int	status;

	if (dr_mem_allow_unload == 0)
		return (EBUSY);

	if ((status = mod_remove(&modlinkage)) == 0) {
		(void) dr_mem_fini();
	}

	return (status);
}

static int
dr_mem_init(void)
{
	int rv;

	if ((rv = ds_cap_init(&dr_mem_cap, &dr_mem_ops)) != 0) {
		cmn_err(CE_NOTE, "dr_mem: ds_cap_init failed: %d", rv);
		return (rv);
	}

	return (0);
}

static int
dr_mem_fini(void)
{
	int rv;

	if ((rv = ds_cap_fini(&dr_mem_cap)) != 0) {
		cmn_err(CE_NOTE, "dr_mem: ds_cap_fini failed: %d", rv);
	}

	return (rv);
}

static void
dr_mem_reg_handler(ds_cb_arg_t arg, ds_ver_t *ver, ds_svc_hdl_t hdl)
{
	DR_DBG_MEM("reg_handler: arg=0x%p, ver=%d.%d, hdl=0x%lx\n", arg,
	    ver->major, ver->minor, hdl);

	ds_handle = hdl;
}

static void
dr_mem_unreg_handler(ds_cb_arg_t arg)
{
	DR_DBG_MEM("unreg_handler: arg=0x%p\n", arg);

	ds_handle = DS_INVALID_HDL;
}

/*ARGSUSED*/
static void
dr_mem_data_handler(ds_cb_arg_t arg, void *buf, size_t buflen)
{
	dr_mem_hdr_t	*req = buf;
	dr_mem_hdr_t	err_resp;
	dr_mem_hdr_t	*resp = &err_resp;
	int		resp_len = 0;
	int		rv = EINVAL;

	/*
	 * Sanity check the message
	 */
	if (buflen < sizeof (dr_mem_hdr_t)) {
		DR_DBG_MEM("incoming message short: expected at least %ld "
		    "bytes, received %ld\n", sizeof (dr_mem_hdr_t), buflen);
		goto done;
	}

	if (req == NULL) {
		DR_DBG_MEM("empty message: expected at least %ld bytes\n",
		    sizeof (dr_mem_hdr_t));
		goto done;
	}

	DR_DBG_MEM("incoming request:\n");
	DR_DBG_DUMP_MSG(buf, buflen);

	/*
	 * Process the command
	 */
	switch (req->msg_type) {
	case DR_MEM_CONFIGURE:
	case DR_MEM_UNCONFIGURE:
		if (req->msg_arg == 0) {
			DR_DBG_MEM("No mblks specified for operation\n");
			goto done;
		}
		if ((rv = dr_mem_list_wrk(req, &resp, &resp_len)) != 0) {
			DR_DBG_MEM("%s failed (%d)\n",
			    (req->msg_type == DR_MEM_CONFIGURE) ?
			    "Memory configure" : "Memory unconfigure", rv);
		}
		break;

	case DR_MEM_UNCONF_STATUS:
		if ((rv = dr_mem_del_stat(req, &resp, &resp_len)) != 0)
			DR_DBG_MEM("Memory delete status failed (%d)\n", rv);
		break;

	case DR_MEM_UNCONF_CANCEL:
		if ((rv = dr_mem_del_cancel(req, &resp, &resp_len)) != 0)
			DR_DBG_MEM("Memory delete cancel failed (%d)\n", rv);
		break;

	case DR_MEM_QUERY:
		if (req->msg_arg == 0) {
			DR_DBG_MEM("No mblks specified for operation\n");
			goto done;
		}
		if ((rv = dr_mem_list_query(req, &resp, &resp_len)) != 0)
			DR_DBG_MEM("Memory query failed (%d)\n", rv);
		break;

	default:
		cmn_err(CE_NOTE, "unsupported memory DR operation (%d)",
		    req->msg_type);
		break;
	}

done:
	/* check if an error occurred */
	if (resp == &err_resp) {
		resp->req_num = (req) ? req->req_num : 0;
		resp->msg_type = DR_MEM_ERROR;
		resp->msg_arg = rv;
		resp_len = sizeof (dr_mem_hdr_t);
	}

	DR_DBG_MEM("outgoing response:\n");
	DR_DBG_DUMP_MSG(resp, resp_len);

	/* send back the response */
	if (ds_cap_send(ds_handle, resp, resp_len) != 0) {
		DR_DBG_MEM("ds_send failed\n");
	}

	/* free any allocated memory */
	if (resp != &err_resp) {
		kmem_free(resp, resp_len);
	}
}

static char *
dr_mem_get_errstr(int result, int subresult)
{
	size_t len;
	char *errstr;
	const char *separator = ": ";

	if (subresult == DR_MEM_SRES_NONE)
		return (i_ddi_strdup(dr_mem_estr[result], KM_SLEEP));

	len = snprintf(NULL, 0, "%s%s%s", dr_mem_estr[result],
	    separator, dr_mem_estr_detail[subresult]) + 1;

	errstr = kmem_alloc(len, KM_SLEEP);

	(void) snprintf(errstr, len, "%s%s%s", dr_mem_estr[result],
	    separator, dr_mem_estr_detail[subresult]);

	return (errstr);
}

/*
 * Common routine to config or unconfig multiple mblks.
 *
 * Note: Do not modify result buffer or length on error.
 */
static int
dr_mem_list_wrk(dr_mem_hdr_t *req, dr_mem_hdr_t **resp, int *resp_len)
{
	int		rv;
	int		idx;
	int		count;
	int		result;
	int		subresult;
	int		status;
	boolean_t	suspend_allows_dr;
	fn_t		dr_fn;
	int		se_hint;
	dr_mem_blk_t	*req_mblks;
	dr_mem_res_t	*res;
	int		drctl_cmd;
	int		drctl_flags = 0;
	drctl_rsrc_t	*drctl_req;
	size_t		drctl_req_len;
	drctl_resp_t	*drctl_resp;
	drctl_rsrc_t	*drctl_rsrc;
	size_t		drctl_resp_len = 0;
	drctl_cookie_t	drctl_res_ck;

	ASSERT((req != NULL) && (req->msg_arg != 0));

	count = req->msg_arg;

	/*
	 * Extract all information that is specific
	 * to the various types of operations.
	 */
	switch (req->msg_type) {
	case DR_MEM_CONFIGURE:
		dr_fn = dr_mem_configure;
		drctl_cmd = DRCTL_MEM_CONFIG_REQUEST;
		se_hint = SE_HINT_INSERT;
		break;
	case DR_MEM_UNCONFIGURE:
		dr_fn = dr_mem_unconfigure;
		drctl_cmd = DRCTL_MEM_UNCONFIG_REQUEST;
		se_hint = SE_HINT_REMOVE;
		break;
	default:
		/* Programming error if we reach this. */
		cmn_err(CE_NOTE, "%s: bad msg_type %d\n",
		    __func__, req->msg_type);
		ASSERT(0);
		return (-1);
	}

	/* the incoming array of mblks to operate on */
	req_mblks = DR_MEM_CMD_MBLKS(req);

	/* allocate drctl request msg based on incoming resource count */
	drctl_req_len = sizeof (drctl_rsrc_t) * count;
	drctl_req = kmem_zalloc(drctl_req_len, KM_SLEEP);

	/* copy the size for the drctl call from the incoming request msg */
	for (idx = 0; idx < count; idx++) {
		drctl_req[idx].res_mem_addr = req_mblks[idx].addr;
		drctl_req[idx].res_mem_size = req_mblks[idx].size;
	}

	rv = drctl_config_init(drctl_cmd, drctl_flags, drctl_req,
	    count, &drctl_resp, &drctl_resp_len, &drctl_res_ck);

	ASSERT((drctl_resp != NULL) && (drctl_resp_len != 0));

	if (rv != 0) {
		DR_DBG_MEM("%s: drctl_config_init returned: %d\n",
		    __func__, rv);
		kmem_free(drctl_resp, drctl_resp_len);
		kmem_free(drctl_req, drctl_req_len);
		return (rv);
	}

	ASSERT(drctl_resp->resp_type == DRCTL_RESP_OK);

	drctl_rsrc = drctl_resp->resp_resources;

	/* create the result scratch array */
	res = dr_mem_res_array_init(req, drctl_rsrc, count);

	/*
	 * Memory DR operations are not safe if we have been suspended and
	 * resumed. Until this limitation is lifted, check to see if memory
	 * DR operations are permitted at this time by the suspend subsystem.
	 */
	if ((suspend_allows_dr = suspend_memdr_allowed()) == B_FALSE) {
		result = DR_MEM_RES_BLOCKED;
		subresult = DR_MEM_SRES_OS_SUSPENDED;
	} else {
		subresult = DR_MEM_SRES_NONE;
	}

	/* perform the specified operation on each of the mblks */
	for (idx = 0; idx < count; idx++) {
		/*
		 * If no action will be taken against the current
		 * mblk, update the drctl resource information to
		 * ensure that it gets recovered properly during
		 * the drctl fini() call.
		 */
		if (res[idx].result != DR_MEM_RES_OK) {
			drctl_req[idx].status = DRCTL_STATUS_CONFIG_FAILURE;
			continue;
		}

		/*
		 * If memory DR operations are permitted at this time by
		 * the suspend subsystem, call the function to perform the
		 * operation, otherwise return a result indicating that the
		 * operation was blocked.
		 */
		if (suspend_allows_dr)
			result = (*dr_fn)(&req_mblks[idx], &status);

		/* save off results of the operation */
		res[idx].result = result;
		res[idx].status = status;
		res[idx].addr = req_mblks[idx].addr;	/* for partial case */
		res[idx].size = req_mblks[idx].size;	/* for partial case */
		res[idx].string = dr_mem_get_errstr(result, subresult);

		/* save result for drctl fini() reusing init() msg memory */
		drctl_req[idx].status = (result != DR_MEM_RES_OK) ?
		    DRCTL_STATUS_CONFIG_FAILURE : DRCTL_STATUS_CONFIG_SUCCESS;

		DR_DBG_MEM("%s: mblk 0x%lx.0x%lx stat %d result %d off '%s'\n",
		    __func__, req_mblks[idx].addr, req_mblks[idx].size,
		    drctl_req[idx].status, result,
		    (res[idx].string) ? res[idx].string : "");
	}

	if ((rv = drctl_config_fini(&drctl_res_ck, drctl_req, count)) != 0)
		DR_DBG_MEM("%s: drctl_config_fini returned: %d\n",
		    __func__, rv);

	/*
	 * Operation completed without any fatal errors.
	 * Pack the response for transmission.
	 */
	*resp_len = dr_mem_pack_response(req, res, resp);

	/* notify interested parties about the operation */
	dr_generate_event(DR_TYPE_MEM, se_hint);

	/*
	 * Deallocate any scratch memory.
	 */
	kmem_free(drctl_resp, drctl_resp_len);
	kmem_free(drctl_req, drctl_req_len);

	dr_mem_res_array_fini(res, count);

	return (0);
}

/*
 * Allocate and initialize a result array based on the initial
 * drctl operation. A valid result array is always returned.
 */
static dr_mem_res_t *
dr_mem_res_array_init(dr_mem_hdr_t *req, drctl_rsrc_t *rsrc, int nrsrc)
{
	int		idx;
	dr_mem_res_t	*res;
	char		*err_str;
	size_t		err_len;

	/* allocate zero filled buffer to initialize fields */
	res = kmem_zalloc(nrsrc * sizeof (dr_mem_res_t), KM_SLEEP);

	/*
	 * Fill in the result information for each resource.
	 */
	for (idx = 0; idx < nrsrc; idx++) {
		res[idx].addr = rsrc[idx].res_mem_addr;
		res[idx].size = rsrc[idx].res_mem_size;
		res[idx].result = DR_MEM_RES_OK;

		if (rsrc[idx].status == DRCTL_STATUS_ALLOW)
			continue;

		/*
		 * Update the state information for this mblk.
		 */
		res[idx].result = DR_MEM_RES_BLOCKED;
		res[idx].status = (req->msg_type == DR_MEM_CONFIGURE) ?
		    DR_MEM_STAT_UNCONFIGURED : DR_MEM_STAT_CONFIGURED;

		/*
		 * If an error string exists, copy it out of the
		 * message buffer. This eliminates any dependency
		 * on the memory allocated for the message buffer
		 * itself.
		 */
		if (rsrc[idx].offset != 0) {
			err_str = (char *)rsrc + rsrc[idx].offset;
			err_len = strlen(err_str) + 1;

			res[idx].string = kmem_alloc(err_len, KM_SLEEP);
			bcopy(err_str, res[idx].string, err_len);
		}
	}

	return (res);
}

static void
dr_mem_res_array_fini(dr_mem_res_t *res, int nres)
{
	int	idx;
	size_t	str_len;

	for (idx = 0; idx < nres; idx++) {
		/* deallocate the error string if present */
		if (res[idx].string) {
			str_len = strlen(res[idx].string) + 1;
			kmem_free(res[idx].string, str_len);
		}
	}

	/* deallocate the result array itself */
	kmem_free(res, sizeof (dr_mem_res_t) * nres);
}

/*
 * Allocate and pack a response message for transmission based
 * on the specified result array. A valid response message and
 * valid size information is always returned.
 */
static size_t
dr_mem_pack_response(dr_mem_hdr_t *req, dr_mem_res_t *res, dr_mem_hdr_t **respp)
{
	int		idx;
	dr_mem_hdr_t	*resp;
	dr_mem_stat_t	*resp_stat;
	size_t		resp_len;
	uint32_t	curr_off;
	caddr_t		curr_str;
	size_t		str_len;
	size_t		stat_len;
	int		nstat = req->msg_arg;

	/*
	 * Calculate the size of the response message
	 * and allocate an appropriately sized buffer.
	 */
	resp_len = sizeof (dr_mem_hdr_t);

	/* add the stat array size */
	stat_len = sizeof (dr_mem_stat_t) * nstat;
	resp_len += stat_len;

	/* add the size of any error strings */
	for (idx = 0; idx < nstat; idx++) {
		if (res[idx].string != NULL) {
			resp_len += strlen(res[idx].string) + 1;
		}
	}

	/* allocate the message buffer */
	resp = kmem_zalloc(resp_len, KM_SLEEP);

	/*
	 * Fill in the header information.
	 */
	resp->req_num = req->req_num;
	resp->msg_type = DR_MEM_OK;
	resp->msg_arg = nstat;

	/*
	 * Fill in the stat information.
	 */
	resp_stat = DR_MEM_RESP_STATS(resp);

	/* string offsets start immediately after stat array */
	curr_off = sizeof (dr_mem_hdr_t) + stat_len;
	curr_str = (char *)resp_stat + stat_len;

	for (idx = 0; idx < nstat; idx++) {
		resp_stat[idx].addr = res[idx].addr;
		resp_stat[idx].size = res[idx].size;
		resp_stat[idx].result = res[idx].result;
		resp_stat[idx].status = res[idx].status;

		if (res[idx].string != NULL) {
			/* copy over the error string */
			str_len = strlen(res[idx].string) + 1;
			bcopy(res[idx].string, curr_str, str_len);
			resp_stat[idx].string_off = curr_off;

			curr_off += str_len;
			curr_str += str_len;
		}
	}

	/* buffer should be exactly filled */
	ASSERT(curr_off == resp_len);

	*respp = resp;
	return (resp_len);
}

static void
dr_mem_query(dr_mem_blk_t *mbp, dr_mem_query_t *mqp)
{
	memquery_t mq;

	DR_DBG_MEM("dr_mem_query...\n");


	(void) kphysm_del_span_query(btop(mbp->addr), btop(mbp->size), &mq);

	if (!mq.phys_pages)
		return;

	mqp->addr = mbp->addr;
	mqp->mq.phys_pages = ptob(mq.phys_pages);
	mqp->mq.managed = ptob(mq.managed);
	mqp->mq.nonrelocatable = ptob(mq.nonrelocatable);
	mqp->mq.first_nonrelocatable = ptob(mq.first_nonrelocatable);
	mqp->mq.last_nonrelocatable = ptob(mq.last_nonrelocatable);
	/*
	 * Set to the max byte offset within the page.
	 */
	if (mqp->mq.nonrelocatable)
		mqp->mq.last_nonrelocatable += PAGESIZE - 1;
}

/*
 * Do not modify result buffer or length on error.
 */
static int
dr_mem_list_query(dr_mem_hdr_t *req, dr_mem_hdr_t **resp, int *resp_len)
{
	int		idx;
	int		rlen;
	int		nml;
	struct memlist	*ml;
	struct memlist	*phys_copy = NULL;
	dr_mem_blk_t	*req_mblks, mb;
	dr_mem_hdr_t	*rp;
	dr_mem_query_t	*stat;

	drctl_block();

	/* the incoming array of req_mblks to configure */
	req_mblks = DR_MEM_CMD_MBLKS(req);

	/* allocate a response message, should be freed by caller */
	nml = 0;
	rlen = sizeof (dr_mem_hdr_t);
	if (req_mblks->addr == 0 && req_mblks->size == 0) {
		/*
		 * Request is for domain's full view of it's memory.
		 * place a copy in phys_copy then release the memlist lock.
		 */
		memlist_read_lock();
		phys_copy = dr_memlist_dup(phys_install);
		memlist_read_unlock();

		for (ml = phys_copy; ml; ml = ml->ml_next)
			nml++;

		rlen += nml * sizeof (dr_mem_query_t);
	} else {
		rlen += req->msg_arg * sizeof (dr_mem_query_t);
	}
	rp = kmem_zalloc(rlen, KM_SLEEP);

	/* fill in the known data */
	rp->req_num = req->req_num;
	rp->msg_type = DR_MEM_OK;
	rp->msg_arg = nml ? nml : req->msg_arg;

	/* stat array for the response */
	stat = DR_MEM_RESP_QUERY(rp);

	/* get the status for each of the mblocks */
	if (nml) {
		for (idx = 0, ml = phys_copy; ml; ml = ml->ml_next, idx++) {
			mb.addr = ml->ml_address;
			mb.size = ml->ml_size;
			dr_mem_query(&mb, &stat[idx]);
		}
	} else {
		for (idx = 0; idx < req->msg_arg; idx++)
			dr_mem_query(&req_mblks[idx], &stat[idx]);
	}

	*resp = rp;
	*resp_len = rlen;
	if (phys_copy != NULL) {
		dr_memlist_delete(phys_copy);
	}
	drctl_unblock();

	return (0);
}

static int
cvt_err(int err)
{
	int rv;

	switch (err) {
	case KPHYSM_OK:
		rv = DR_MEM_RES_OK;
		break;
	case KPHYSM_ESPAN:
		rv = DR_MEM_RES_ESPAN;
		break;
	case KPHYSM_EFAULT:
		rv = DR_MEM_RES_EFAULT;
		break;
	case KPHYSM_ERESOURCE:
		rv = DR_MEM_RES_ERESOURCE;
		break;
	case KPHYSM_ENOTSUP:
	case KPHYSM_ENOHANDLES:
		rv = DR_MEM_RES_FAILURE;
		break;
	case KPHYSM_ENONRELOC:
		rv = DR_MEM_RES_PERM;
		break;
	case KPHYSM_EHANDLE:
		rv = DR_MEM_RES_FAILURE;
		break;
	case KPHYSM_EBUSY:
		rv = DR_MEM_RES_EBUSY;
		break;
	case KPHYSM_ENOTVIABLE:
		rv = DR_MEM_RES_ENOTVIABLE;
		break;
	case KPHYSM_ESEQUENCE:
		rv = DR_MEM_RES_FAILURE;
		break;
	case KPHYSM_ENOWORK:
		rv = DR_MEM_RES_ENOWORK;
		break;
	case KPHYSM_ECANCELLED:
		rv = DR_MEM_RES_ECANCELLED;
		break;
	case KPHYSM_EREFUSED:
		rv = DR_MEM_RES_EREFUSED;
		break;
	case KPHYSM_ENOTFINISHED:
	case KPHYSM_ENOTRUNNING:
		rv = DR_MEM_RES_FAILURE;
		break;
	case KPHYSM_EDUP:
		rv = DR_MEM_RES_EDUP;
		break;
	default:
		rv = DR_MEM_RES_FAILURE;
		break;
	}

	return (rv);
}

static int
dr_mem_configure(dr_mem_blk_t *mbp, int *status)
{
	int rv;
	uint64_t addr, size;

	rv = 0;
	addr = mbp->addr;
	size = mbp->size;

	DR_DBG_MEM("dr_mem_configure...\n");

	if (!MBLK_IS_VALID(mbp)) {
		DR_DBG_MEM("invalid mblk 0x%lx.0x%lx\n", addr, size);
		*status = DR_MEM_STAT_UNCONFIGURED;
		rv = DR_MEM_RES_EINVAL;
	} else if (rv = dr_mem_find(mbp)) {
		DR_DBG_MEM("failed to find mblk 0x%lx.0x%lx (%d)\n",
		    addr, size, rv);
		if (rv == EINVAL) {
			*status = DR_MEM_STAT_NOT_PRESENT;
			rv = DR_MEM_RES_NOT_IN_MD;
		} else {
			*status = DR_MEM_STAT_UNCONFIGURED;
			rv = DR_MEM_RES_FAILURE;
		}
	} else {
		rv = mem_add(btop(addr), btop(size));
		DR_DBG_MEM("addr=0x%lx size=0x%lx rv=%d\n", addr, size, rv);
		if (rv) {
			*status = DR_MEM_STAT_UNCONFIGURED;
		} else {
			*status = DR_MEM_STAT_CONFIGURED;
		}
	}

	return (rv);
}

static int
dr_mem_unconfigure(dr_mem_blk_t *mbp, int *status)
{
	int rv;

	DR_DBG_MEM("dr_mem_unconfigure...\n");

	if (!MBLK_IS_VALID(mbp)) {
		DR_DBG_MEM("invalid mblk 0x%lx.0x%lx\n",
		    mbp->addr, mbp->size);
		*status = DR_MEM_STAT_CONFIGURED;
		rv = DR_MEM_RES_EINVAL;
	} else if (rv = mem_del(btop(mbp->addr), btop(mbp->size))) {
		*status = DR_MEM_STAT_CONFIGURED;
	} else {
		*status = DR_MEM_STAT_UNCONFIGURED;
		rv = DR_MEM_RES_OK;
		DR_DBG_MEM("mblk 0x%lx.0x%lx unconfigured\n",
		    mbp->addr, mbp->size);
	}
	return (rv);
}

static int
dr_mem_del_stat(dr_mem_hdr_t *req, dr_mem_hdr_t **resp, int *resp_len)
{
	int			status;
	int			rlen;
	memdelstat_t		del_stat, *stat;
	dr_mem_hdr_t		*rp;

	/*
	 * If a mem delete is in progress, get its status.
	 */
	status = (dr_mh && (kphysm_del_status(dr_mh, &del_stat) == KPHYSM_OK));

	/* allocate a response message, should be freed by caller */
	rlen = sizeof (dr_mem_hdr_t);
	rlen += status * sizeof (memdelstat_t);
	rp = kmem_zalloc(rlen, KM_SLEEP);

	/* fill in the known data */
	rp->req_num = req->req_num;
	rp->msg_type = DR_MEM_OK;
	rp->msg_arg = status;

	if (status) {
		/* stat struct for the response */
		stat = DR_MEM_RESP_DEL_STAT(rp);
		stat->phys_pages = ptob(del_stat.phys_pages);
		stat->managed = ptob(del_stat.managed);
		stat->collected = ptob(del_stat.collected);
	}

	*resp = rp;
	*resp_len = rlen;

	return (0);
}

static int
dr_mem_del_cancel(dr_mem_hdr_t *req, dr_mem_hdr_t **resp, int *resp_len)
{
	int		rlen;
	dr_mem_hdr_t	*rp;

	/* allocate a response message, should be freed by caller */
	rlen = sizeof (dr_mem_hdr_t);
	rp = kmem_zalloc(rlen, KM_SLEEP);

	/* fill in the known data */
	rp->req_num = req->req_num;
	rp->msg_type = DR_MEM_OK;
	rp->msg_arg = (dr_mh && kphysm_del_cancel(dr_mh) != KPHYSM_OK) ?
	    DR_MEM_RES_EINVAL : DR_MEM_RES_OK;

	*resp = rp;
	*resp_len = rlen;

	return (0);
}

static int
dr_mem_find(dr_mem_blk_t *mbp)
{
	md_t		*mdp = NULL;
	int		num_nodes;
	int		rv = 0;
	int		listsz;
	mde_cookie_t	*listp = NULL;
	mde_cookie_t	memnode;
	char		*found = "found";

	if ((mdp = md_get_handle()) == NULL) {
		DR_DBG_MEM("unable to initialize machine description\n");
		return (-1);
	}

	num_nodes = md_node_count(mdp);
	ASSERT(num_nodes > 0);

	listsz = num_nodes * sizeof (mde_cookie_t);
	listp = kmem_zalloc(listsz, KM_SLEEP);

	memnode = dr_mem_find_node_md(mbp, mdp, listp);

	if (memnode == MDE_INVAL_ELEM_COOKIE) {
		rv = EINVAL;
		found = "not found";
	}

	DR_DBG_MEM("mblk 0x%lx.0x%lx %s\n", mbp->addr, mbp->size, found);

	kmem_free(listp, listsz);
	(void) md_fini_handle(mdp);

	return (rv);
}

/*
 * Look up a particular mblk in the MD. Returns the mde_cookie_t
 * representing that mblk if present, and MDE_INVAL_ELEM_COOKIE
 * otherwise. It is assumed the scratch array has already been
 * allocated so that it can accommodate the worst case scenario,
 * every node in the MD.
 */
static mde_cookie_t
dr_mem_find_node_md(dr_mem_blk_t *mbp, md_t *mdp, mde_cookie_t *listp)
{
	int		idx;
	int		nnodes;
	mde_cookie_t	rootnode;
	uint64_t	base_prop;
	uint64_t	size_prop;
	mde_cookie_t	result = MDE_INVAL_ELEM_COOKIE;

	rootnode = md_root_node(mdp);
	ASSERT(rootnode != MDE_INVAL_ELEM_COOKIE);

	/*
	 * Scan the DAG for all the mem nodes
	 */
	nnodes = md_scan_dag(mdp, rootnode, md_find_name(mdp, "mblock"),
	    md_find_name(mdp, "fwd"), listp);

	if (nnodes < 0) {
		DR_DBG_MEM("Scan for mblks failed\n");
		return (result);
	}

	DR_DBG_MEM("dr_mem_find_node_md: found %d mblks in the MD\n", nnodes);

	/*
	 * Find the mblk of interest
	 */
	for (idx = 0; idx < nnodes; idx++) {

		if (md_get_prop_val(mdp, listp[idx], "base", &base_prop)) {
			DR_DBG_MEM("Missing 'base' property for mblk node %d\n",
			    idx);
			break;
		}

		if (md_get_prop_val(mdp, listp[idx], "size", &size_prop)) {
			DR_DBG_MEM("Missing 'size' property for mblk node %d\n",
			    idx);
			break;
		}

		if (base_prop <= mbp->addr &&
		    (base_prop + size_prop) >= (mbp->addr + mbp->size)) {
			/* found a match */
			DR_DBG_MEM("dr_mem_find_node_md: found mblk "
			    "0x%lx.0x%lx in MD\n", mbp->addr, mbp->size);
			result = listp[idx];
			break;
		}
	}

	if (result == MDE_INVAL_ELEM_COOKIE) {
		DR_DBG_MEM("mblk 0x%lx.0x%lx not in MD\n",
		    mbp->addr, mbp->size);
	}

	return (result);
}

static int
mem_add(pfn_t base, pgcnt_t npgs)
{
	int rv, rc;

	DR_DBG_MEM("%s: begin base=0x%lx npgs=0x%lx\n", __func__, base, npgs);

	if (npgs == 0)
		return (DR_MEM_RES_OK);

	rv = kphysm_add_memory_dynamic(base, npgs);
	DR_DBG_MEM("%s: kphysm_add(0x%lx, 0x%lx) = %d", __func__, base, npgs,
	    rv);
	if (rv == KPHYSM_OK) {
		if (rc = kcage_range_add(base, npgs, KCAGE_DOWN))
			cmn_err(CE_WARN, "kcage_range_add() = %d", rc);
	}
	rv = cvt_err(rv);
	return (rv);
}

static void
del_done(void *arg, int error)
{
	mem_sync_t *ms = arg;

	mutex_enter(&ms->lock);
	ms->error = error;
	ms->done = 1;
	cv_signal(&ms->cond);
	mutex_exit(&ms->lock);
}

static int
mem_del(pfn_t base, pgcnt_t npgs)
{
	int rv, err, del_range = 0;
	int convert = 1;
	mem_sync_t ms;
	memquery_t mq;
	memhandle_t mh;
	struct memlist *ml;
	struct memlist *d_ml = NULL;

	DR_DBG_MEM("%s: begin base=0x%lx npgs=0x%lx\n", __func__, base, npgs);

	if (npgs == 0)
		return (DR_MEM_RES_OK);

	if ((rv = kphysm_del_gethandle(&mh)) != KPHYSM_OK) {
		cmn_err(CE_WARN, "%s: del_gethandle() = %d", __func__, rv);
		rv = cvt_err(rv);
		return (rv);
	}
	if ((rv = kphysm_del_span_query(base, npgs, &mq))
	    != KPHYSM_OK) {
		cmn_err(CE_WARN, "%s: del_span_query() = %d", __func__, rv);
		goto done;
	}
	if (mq.nonrelocatable) {
		DR_DBG_MEM("%s: non-reloc pages = %ld",
		    __func__, mq.nonrelocatable);
		rv  = KPHYSM_ENONRELOC;
		goto done;
	}
	if (rv = kcage_range_delete(base, npgs)) {
		switch (rv) {
		case EBUSY:
			rv = DR_MEM_RES_ENOTVIABLE;
			break;
		default:
			rv = DR_MEM_RES_FAILURE;
			break;
		}
		convert = 0; /* conversion done */
		cmn_err(CE_WARN, "%s: del_range() = %d", __func__, rv);
		goto done;
	} else {
		del_range++;
	}
	if ((rv = kphysm_del_span(mh, base, npgs)) != KPHYSM_OK) {
		cmn_err(CE_WARN, "%s: del_span() = %d", __func__, rv);
		goto done;
	}
	if ((rv = memlist_add_span(ptob(base), ptob(npgs), &d_ml))
	    != MEML_SPANOP_OK) {
		switch (rv) {
		case MEML_SPANOP_ESPAN:
			rv = DR_MEM_RES_ESPAN;
			break;
		case MEML_SPANOP_EALLOC:
			rv = DR_MEM_RES_ERESOURCE;
			break;
		default:
			rv = DR_MEM_RES_FAILURE;
			break;
		}
		convert = 0; /* conversion done */
		cmn_err(CE_WARN, "%s: add_span() = %d", __func__, rv);
		goto done;
	}

	DR_DBG_MEM("%s: reserved=0x%lx", __func__, npgs);

	bzero((void *) &ms, sizeof (ms));

	mutex_init(&ms.lock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&ms.cond, NULL, CV_DRIVER, NULL);
	mutex_enter(&ms.lock);

	if ((rv = kphysm_del_start(mh, del_done, (void *) &ms)) == KPHYSM_OK) {
		/*
		 * Since we've called drctl_config_init, we are the only
		 * DR ctl operation in progress.  Set dr_mh to the
		 * delete memhandle for use by stat and cancel.
		 */
		ASSERT(dr_mh == NULL);
		dr_mh = mh;

		/*
		 * Wait for completion or interrupt.
		 */
		while (!ms.done) {
			if (cv_wait_sig(&ms.cond, &ms.lock) == 0) {
				/*
				 * There is a pending signal.
				 */
				(void) kphysm_del_cancel(mh);
				DR_DBG_MEM("%s: cancel", __func__);
				/*
				 * Wait for completion.
				 */
				while (!ms.done)
					cv_wait(&ms.cond, &ms.lock);
			}
		}
		dr_mh = NULL;
		rv = ms.error;
	} else {
		DR_DBG_MEM("%s: del_start() = %d", __func__, rv);
	}

	mutex_exit(&ms.lock);
	cv_destroy(&ms.cond);
	mutex_destroy(&ms.lock);

done:
	if (rv && del_range) {
		/*
		 * Add back the spans to the kcage growth list.
		 */
		for (ml = d_ml; ml; ml = ml->ml_next)
			if (err = kcage_range_add(btop(ml->ml_address),
			    btop(ml->ml_size), KCAGE_DOWN))
				cmn_err(CE_WARN, "kcage_range_add() = %d", err);
	}
	memlist_free_list(d_ml);

	if ((err = kphysm_del_release(mh)) != KPHYSM_OK)
		cmn_err(CE_WARN, "%s: del_release() = %d", __func__, err);
	if (convert)
		rv = cvt_err(rv);

	DR_DBG_MEM("%s: rv=%d", __func__, rv);

	return (rv);
}
