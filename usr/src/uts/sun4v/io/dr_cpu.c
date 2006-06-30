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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * sun4v CPU DR Module
 */

#include <sys/modctl.h>
#include <sys/processor.h>
#include <sys/cpuvar.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/note.h>
#include <sys/sysevent/dr.h>
#include <sys/hypervisor_api.h>
#include <sys/mach_descrip.h>
#include <sys/mdesc.h>
#include <sys/ds.h>
#include <sys/drctl.h>
#include <sys/dr_util.h>
#include <sys/dr_cpu.h>
#include <sys/promif.h>
#include <sys/machsystm.h>


static struct modlmisc modlmisc = {
	&mod_miscops,
	"sun4v CPU DR %I%"
};

static struct modlinkage modlinkage = {
	MODREV_1,
	(void *)&modlmisc,
	NULL
};

typedef int (*fn_t)(processorid_t, int *, boolean_t);

/*
 * Global DS Handle
 */
static ds_svc_hdl_t ds_handle;

/*
 * Supported DS Capability Versions
 */
static ds_ver_t		dr_cpu_vers[] = { { 1, 0 } };
#define	DR_CPU_NVERS	(sizeof (dr_cpu_vers) / sizeof (dr_cpu_vers[0]))

/*
 * DS Capability Description
 */
static ds_capability_t dr_cpu_cap = {
	DR_CPU_DS_ID,		/* svc_id */
	dr_cpu_vers,		/* vers */
	DR_CPU_NVERS		/* nvers */
};

/*
 * DS Callbacks
 */
static void dr_cpu_reg_handler(ds_cb_arg_t, ds_ver_t *, ds_svc_hdl_t);
static void dr_cpu_unreg_handler(ds_cb_arg_t arg);
static void dr_cpu_data_handler(ds_cb_arg_t arg, void *buf, size_t buflen);

/*
 * DS Client Ops Vector
 */
static ds_clnt_ops_t dr_cpu_ops = {
	dr_cpu_reg_handler,	/* ds_reg_cb */
	dr_cpu_unreg_handler,	/* ds_unreg_cb */
	dr_cpu_data_handler,	/* ds_data_cb */
	NULL			/* cb_arg */
};

/*
 * Internal Functions
 */
static int dr_cpu_init(void);
static int dr_cpu_fini(void);

static int dr_cpu_list_wrk(dr_cpu_hdr_t *, dr_cpu_hdr_t **, int *, fn_t);
static int dr_cpu_list_status(dr_cpu_hdr_t *, dr_cpu_hdr_t **, int *);

static int dr_cpu_unconfigure(processorid_t, int *status, boolean_t force);
static int dr_cpu_configure(processorid_t, int *status, boolean_t force);
static int dr_cpu_status(processorid_t, int *status);

static int dr_cpu_probe(processorid_t newcpuid);
static int dr_cpu_deprobe(processorid_t cpuid);

static dev_info_t *dr_cpu_find_node(processorid_t cpuid);
static mde_cookie_t dr_cpu_find_node_md(processorid_t, md_t *, mde_cookie_t *);
static void dr_cpu_check_cpus(uint32_t *cpuids, int ncpus, dr_cpu_stat_t *stat);


int
_init(void)
{
	int	status;

	/* check that CPU DR is enabled */
	if (dr_is_disabled(DR_TYPE_CPU)) {
		cmn_err(CE_CONT, "!CPU DR is disabled\n");
		return (-1);
	}

	if ((status = dr_cpu_init()) != 0) {
		cmn_err(CE_NOTE, "CPU DR initialization failed");
		return (status);
	}

	if ((status = mod_install(&modlinkage)) != 0) {
		(void) dr_cpu_fini();
	}

	return (status);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

int dr_cpu_allow_unload;

int
_fini(void)
{
	int	status;

	if (dr_cpu_allow_unload == 0)
		return (EBUSY);

	if ((status = mod_remove(&modlinkage)) == 0) {
		(void) dr_cpu_fini();
	}

	return (status);
}

static int
dr_cpu_init(void)
{
	int	rv;

	if ((rv = ds_cap_init(&dr_cpu_cap, &dr_cpu_ops)) != 0) {
		cmn_err(CE_NOTE, "ds_cap_init failed: %d", rv);
		return (-1);
	}

	return (0);
}

static int
dr_cpu_fini(void)
{
	int	rv;

	if ((rv = ds_cap_fini(&dr_cpu_cap)) != 0) {
		cmn_err(CE_NOTE, "ds_cap_fini failed: %d", rv);
		return (-1);
	}

	return (0);
}

static void
dr_cpu_reg_handler(ds_cb_arg_t arg, ds_ver_t *ver, ds_svc_hdl_t hdl)
{
	DR_DBG_CPU("reg_handler: arg=0x%p, ver=%d.%d, hdl=0x%lx\n", arg,
	    ver->major, ver->minor, hdl);

	ds_handle = hdl;
}

static void
dr_cpu_unreg_handler(ds_cb_arg_t arg)
{
	DR_DBG_CPU("unreg_handler: arg=0x%p\n", arg);

	ds_handle = DS_INVALID_HDL;
}

static void
dr_cpu_data_handler(ds_cb_arg_t arg, void *buf, size_t buflen)
{
	_NOTE(ARGUNUSED(arg))

	dr_cpu_hdr_t	*req = buf;
	dr_cpu_hdr_t	err_resp;
	dr_cpu_hdr_t	*resp = &err_resp;
	int		resp_len = 0;
	int		rv;

	/*
	 * Sanity check the message
	 */
	if (buflen < sizeof (dr_cpu_hdr_t)) {
		DR_DBG_CPU("incoming message short: expected at least %ld "
		    "bytes, received %ld\n", sizeof (dr_cpu_hdr_t), buflen);
		goto done;
	}

	if (req == NULL) {
		DR_DBG_CPU("empty message: expected at least %ld bytes\n",
		    sizeof (dr_cpu_hdr_t));
		goto done;
	}

	DR_DBG_CPU("incoming request:\n");
	DR_DBG_DUMP_MSG(buf, buflen);

	if (req->num_records > NCPU) {
		DR_DBG_CPU("CPU list too long: %d when %d is the maximum\n",
		    req->num_records, NCPU);
		goto done;
	}

	if (req->num_records == 0) {
		DR_DBG_CPU("No CPU specified for operation\n");
		goto done;
	}

	/*
	 * Process the command
	 */
	switch (req->msg_type) {
	case DR_CPU_CONFIGURE:
		rv = dr_cpu_list_wrk(req, &resp, &resp_len, dr_cpu_configure);
		if (rv != 0)
			DR_DBG_CPU("dr_cpu_list_configure failed (%d)\n", rv);
		break;

	case DR_CPU_UNCONFIGURE:
	case DR_CPU_FORCE_UNCONFIG:
		rv = dr_cpu_list_wrk(req, &resp, &resp_len, dr_cpu_unconfigure);
		if (rv != 0)
			DR_DBG_CPU("dr_cpu_list_unconfigure failed (%d)\n", rv);
		break;

	case DR_CPU_STATUS:
		if ((rv = dr_cpu_list_status(req, &resp, &resp_len)) != 0)
			DR_DBG_CPU("dr_cpu_list_status failed (%d)\n", rv);
		break;

	default:
		cmn_err(CE_NOTE, "unsupported DR operation (%d)",
		    req->msg_type);
		break;
	}

done:
	/* check if an error occurred */
	if (resp == &err_resp) {
		resp->req_num = (req) ? req->req_num : 0;
		resp->msg_type = DR_CPU_ERROR;
		resp->num_records = 0;
		resp_len = sizeof (dr_cpu_hdr_t);
	}

	/* send back the response */
	if (ds_cap_send(ds_handle, resp, resp_len) != 0) {
		DR_DBG_CPU("ds_send failed\n");
	}

	/* free any allocated memory */
	if (resp != &err_resp) {
		kmem_free(resp, resp_len);
	}
}

/*
 * Common routine to config or unconfig multiple cpus.  The unconfig
 * case checks with the OS to see if the removal of cpus will be
 * permitted, but can be overridden by the "force" version of the
 * command.  Otherwise, the logic for both cases is identical.
 *
 * Note: Do not modify result buffer or length on error.
 */
static int
dr_cpu_list_wrk(dr_cpu_hdr_t *rq, dr_cpu_hdr_t **resp, int *resp_len, fn_t f)
{
	/* related to request message (based on cpu_hdr_t *rq function arg) */

	uint32_t	*rq_cpus;	/* address of cpuid array in request */

	/* the response message to our caller (passed back via **resp) */

	dr_cpu_hdr_t	*rs;		/* address of allocated response msg */
	size_t		rs_len;		/* length of response msg */
	dr_cpu_stat_t	*rs_stat;	/* addr. of status array in response */
	caddr_t		rs_str;		/* addr. of string area in response */
	size_t		rs_stat_len;	/* length of status area in response */
	size_t		rs_str_len;	/* length of string area in response */

	/* the request message sent to drctl_config_[init|fini] */

	drctl_rsrc_t	*dr_rq;		/* addr. of allocated msg for drctl */
	size_t		dr_rq_len;	/* length of same */

	/* the response message received from drctl_config_init */

	drctl_rsrc_t	*dr_rs;		/* &response from drctl_config_init */
	size_t		dr_rs_len = 0;	/* length of response from same */
	caddr_t		dr_rs_str;	/* &(string area) in same */
	drctl_cookie_t	dr_rs_ck;	/* the cookie from same */

	/* common temp variables */

	int		idx;
	int		cmd;
	int		result;
	int		status;
	int		count;
	int		rv;
	int		flags;
	int		force;
	int		fail_status;
	static const char me[] = "dr_cpu_list_wrk";


	ASSERT(rq != NULL && rq->num_records != 0);

	count = rq->num_records;
	flags = 0;
	force = B_FALSE;

	switch (rq->msg_type) {
	case DR_CPU_CONFIGURE:
		cmd = DRCTL_CPU_CONFIG_REQUEST;
		fail_status = DR_CPU_STAT_UNCONFIGURED;
		break;
	case DR_CPU_FORCE_UNCONFIG:
		flags = DRCTL_FLAG_FORCE;
		force = B_TRUE;
		_NOTE(FALLTHROUGH)
	case DR_CPU_UNCONFIGURE:
		cmd = DRCTL_CPU_UNCONFIG_REQUEST;
		fail_status = DR_CPU_STAT_CONFIGURED;
		break;
	default:
		/* Programming error if we reach this. */
		ASSERT(0);
		cmn_err(CE_NOTE, "%s: bad msg_type %d\n", me, rq->msg_type);
		return (-1);
	}

	/* the incoming array of cpuids to configure */
	rq_cpus = (uint32_t *)((caddr_t)rq + sizeof (dr_cpu_hdr_t));

	/* allocate drctl request msg based on incoming resource count */
	dr_rq_len = sizeof (drctl_rsrc_t) * count;
	dr_rq = kmem_zalloc(dr_rq_len, KM_SLEEP);

	/* copy the cpuids for the drctl call from the incoming request msg */
	for (idx = 0; idx < count; idx++)
		dr_rq[idx].res_cpu_id = rq_cpus[idx];

	rv = drctl_config_init(cmd,
	    flags, dr_rq, count, &dr_rs, &dr_rs_len, &dr_rs_ck);

	if (rv != 0) {
		cmn_err(CE_CONT,
		    "?%s: drctl_config_init returned: %d\n", me, rv);
		kmem_free(dr_rq, dr_rq_len);
		return (-1);
	}

	ASSERT(dr_rs != NULL && dr_rs_len != 0);

	/*
	 * Allocate a response buffer for our caller.  It consists of
	 * the header plus the (per resource) status array and a string
	 * area the size of which is equal to the size of the string
	 * area in the drctl_config_init response.  The latter is
	 * simply the size difference between the config_init request
	 * and config_init response messages (and may be zero).
	 */
	rs_stat_len =  count * sizeof (dr_cpu_stat_t);
	rs_str_len = dr_rs_len - dr_rq_len;
	rs_len = sizeof (dr_cpu_hdr_t) + rs_stat_len + rs_str_len;
	rs = kmem_zalloc(rs_len, KM_SLEEP);

	/* fill in the known data */
	rs->req_num = rq->req_num;
	rs->msg_type = DR_CPU_OK;
	rs->num_records = count;

	/* stat array for the response */
	rs_stat = (dr_cpu_stat_t *)((caddr_t)rs + sizeof (dr_cpu_hdr_t));

	if (rq->msg_type == DR_CPU_FORCE_UNCONFIG)
		dr_cpu_check_cpus(rq_cpus, count, rs_stat);

	/* [un]configure each of the CPUs */
	for (idx = 0; idx < count; idx++) {

		if (dr_rs[idx].status != DRCTL_STATUS_ALLOW ||
		    rs_stat[idx].result == DR_CPU_RES_BLOCKED) {
			result = DR_CPU_RES_FAILURE;
			status = fail_status;
		} else {
			result = (*f)(rq_cpus[idx], &status, force);
		}

		/* save off results of the configure */
		rs_stat[idx].cpuid = rq_cpus[idx];
		rs_stat[idx].result = result;
		rs_stat[idx].status = status;

		/*
		 * Convert any string offset from being relative to
		 * the start of the drctl response to being relative
		 * to the start of the response sent to our caller.
		 */
		if (dr_rs[idx].offset != 0)
			rs_stat[idx].string_off = (uint32_t)dr_rs[idx].offset -
			    dr_rq_len + (rs_len - rs_str_len);

		/* save result for _fini() reusing _init msg memory */
		dr_rq[idx].status = (status == fail_status) ?
		    DRCTL_STATUS_CONFIG_FAILURE : DRCTL_STATUS_CONFIG_SUCCESS;
		DR_DBG_CPU("%s: cpuid %d status %d result %d off %d",
		    me, rq_cpus[idx], dr_rq[idx].status,
		    result, rs_stat[idx].string_off);
	}

	/* copy the strings (if any) from drctl resp. into resp. for caller */
	dr_rs_str = (caddr_t)dr_rs + dr_rq_len;
	rs_str = (caddr_t)rs + rs_len - rs_str_len;
	bcopy(dr_rs_str, rs_str, rs_str_len);

	rv = drctl_config_fini(&dr_rs_ck, dr_rq, count);
	if (rv != 0)
		cmn_err(CE_CONT,
		    "?%s: drctl_config_fini returned: %d\n", me, rv);

	kmem_free(dr_rs, dr_rs_len);

	kmem_free(dr_rq, dr_rq_len);

	*resp = rs;
	*resp_len = rs_len;

	dr_generate_event(DR_TYPE_CPU, SE_HINT_INSERT);

	return (0);
}

static void
dr_cpu_check_cpus(uint32_t *cpuids, int ncpus, dr_cpu_stat_t *stat)
{
	int		idx;
	kthread_t	*tp;
	proc_t		*pp;

	DR_DBG_CPU("dr_cpu_check_cpus...\n");

	mutex_enter(&cpu_lock);

	/* process each cpu that is part of the request */
	for (idx = 0; idx < ncpus; idx++) {

		if (cpu_get(cpuids[idx]) == NULL)
			continue;

		mutex_enter(&pidlock);

		/*
		 * Walk the active processes, checking if each
		 * thread belonging to the process is bound.
		 */
		for (pp = practive; pp != NULL; pp = pp->p_next) {
			mutex_enter(&pp->p_lock);
			tp = pp->p_tlist;

			if (tp == NULL || (pp->p_flag & SSYS)) {
				mutex_exit(&pp->p_lock);
				continue;
			}

			do {
				if (tp->t_bind_cpu != cpuids[idx])
					continue;

				DR_DBG_CPU("thread(s) bound to cpu %d\n",
				    cpuids[idx]);

				stat[idx].cpuid = cpuids[idx];
				stat[idx].result = DR_CPU_RES_BLOCKED;
				stat[idx].status = DR_CPU_STAT_CONFIGURED;
				break;

			} while ((tp = tp->t_forw) != pp->p_tlist);
			mutex_exit(&pp->p_lock);
		}

		mutex_exit(&pidlock);
	}

	mutex_exit(&cpu_lock);
}


/*
 * Do not modify result buffer or length on error.
 */
static int
dr_cpu_list_status(dr_cpu_hdr_t *req, dr_cpu_hdr_t **resp, int *resp_len)
{
	int		idx;
	int		result;
	int		status;
	int		rlen;
	uint32_t	*cpuids;
	dr_cpu_hdr_t	*rp;
	dr_cpu_stat_t	*stat;
	md_t		*mdp = NULL;
	int		num_nodes;
	int		listsz;
	mde_cookie_t	*listp = NULL;
	mde_cookie_t	cpunode;
	boolean_t	walk_md = B_FALSE;

	/* the incoming array of cpuids to configure */
	cpuids = (uint32_t *)((caddr_t)req + sizeof (dr_cpu_hdr_t));

	/* allocate a response message */
	rlen = sizeof (dr_cpu_hdr_t);
	rlen += req->num_records * sizeof (dr_cpu_stat_t);
	rp = kmem_zalloc(rlen, KM_SLEEP);

	/* fill in the known data */
	rp->req_num = req->req_num;
	rp->msg_type = DR_CPU_STATUS;
	rp->num_records = req->num_records;

	/* stat array for the response */
	stat = (dr_cpu_stat_t *)((caddr_t)rp + sizeof (dr_cpu_hdr_t));

	/* get the status for each of the CPUs */
	for (idx = 0; idx < req->num_records; idx++) {

		result = dr_cpu_status(cpuids[idx], &status);

		if (result == DR_CPU_RES_FAILURE)
			walk_md = B_TRUE;

		/* save off results of the status */
		stat[idx].cpuid = cpuids[idx];
		stat[idx].result = result;
		stat[idx].status = status;
	}

	if (walk_md == B_FALSE)
		goto done;

	/*
	 * At least one of the cpus did not have a CPU
	 * structure. So, consult the MD to determine if
	 * they are present.
	 */

	if ((mdp = md_get_handle()) == NULL) {
		DR_DBG_CPU("unable to initialize MD\n");
		goto done;
	}

	num_nodes = md_node_count(mdp);
	ASSERT(num_nodes > 0);

	listsz = num_nodes * sizeof (mde_cookie_t);
	listp = kmem_zalloc(listsz, KM_SLEEP);

	for (idx = 0; idx < req->num_records; idx++) {

		if (stat[idx].result != DR_CPU_RES_FAILURE)
			continue;

		/* check the MD for the current cpuid */
		cpunode = dr_cpu_find_node_md(stat[idx].cpuid, mdp, listp);

		stat[idx].result = DR_CPU_RES_OK;

		if (cpunode == MDE_INVAL_ELEM_COOKIE) {
			stat[idx].status = DR_CPU_STAT_NOT_PRESENT;
		} else {
			stat[idx].status = DR_CPU_STAT_UNCONFIGURED;
		}
	}

	kmem_free(listp, listsz);

	(void) md_fini_handle(mdp);

done:
	*resp = rp;
	*resp_len = rlen;

	return (0);
}


static int
dr_cpu_configure(processorid_t cpuid, int *status, boolean_t force)
{
	 _NOTE(ARGUNUSED(force))
	struct cpu	*cp;
	int		rv = 0;

	DR_DBG_CPU("dr_cpu_configure...\n");

	/*
	 * Build device tree node for the CPU
	 */
	if ((rv = dr_cpu_probe(cpuid)) != 0) {
		DR_DBG_CPU("failed to probe CPU %d (%d)\n", cpuid, rv);
		if (rv == EINVAL) {
			*status = DR_CPU_STAT_NOT_PRESENT;
			return (DR_CPU_RES_NOT_IN_MD);
		}
		*status = DR_CPU_STAT_UNCONFIGURED;
		return (DR_CPU_RES_FAILURE);
	}

	mutex_enter(&cpu_lock);

	/*
	 * Configure the CPU
	 */
	if ((cp = cpu_get(cpuid)) == NULL) {

		if ((rv = cpu_configure(cpuid)) != 0) {
			DR_DBG_CPU("failed to configure CPU %d (%d)\n",
			    cpuid, rv);
			rv = DR_CPU_RES_FAILURE;
			*status = DR_CPU_STAT_UNCONFIGURED;
			goto done;
		}

		DR_DBG_CPU("CPU %d configured\n", cpuid);

		/* CPU struct should exist now */
		cp = cpu_get(cpuid);
	}

	ASSERT(cp);

	/*
	 * Power on the CPU. In sun4v, this brings the stopped
	 * CPU into the guest from the Hypervisor.
	 */
	if (cpu_is_poweredoff(cp)) {

		if ((rv = cpu_poweron(cp)) != 0) {
			DR_DBG_CPU("failed to power on CPU %d (%d)\n",
			    cpuid, rv);
			rv = DR_CPU_RES_FAILURE;
			*status = DR_CPU_STAT_UNCONFIGURED;
			goto done;
		}

		DR_DBG_CPU("CPU %d powered on\n", cpuid);
	}

	/*
	 * Online the CPU
	 */
	if (cpu_is_offline(cp)) {

		if ((rv = cpu_online(cp)) != 0) {
			DR_DBG_CPU("failed to online CPU %d (%d)\n",
			    cpuid, rv);
			rv = DR_CPU_RES_FAILURE;
			/* offline is still configured */
			*status = DR_CPU_STAT_CONFIGURED;
			goto done;
		}

		DR_DBG_CPU("CPU %d online\n", cpuid);
	}

	rv = DR_CPU_RES_OK;
	*status = DR_CPU_STAT_CONFIGURED;

done:
	mutex_exit(&cpu_lock);

	return (rv);
}

static int
dr_cpu_unconfigure(processorid_t cpuid, int *status, boolean_t force)
{
	struct cpu	*cp;
	int		rv = 0;
	int		cpu_flags;

	DR_DBG_CPU("dr_cpu_unconfigure%s...\n", (force) ? " (force)" : "");

	mutex_enter(&cpu_lock);

	cp = cpu_get(cpuid);

	if (cp == NULL) {

		/*
		 * The OS CPU structures are already torn down,
		 * Attempt to deprobe the CPU to make sure the
		 * device tree is up to date.
		 */
		if (dr_cpu_deprobe(cpuid) != 0) {
			DR_DBG_CPU("failed to deprobe CPU %d\n", cpuid);
			rv = DR_CPU_RES_FAILURE;
			*status = DR_CPU_STAT_UNCONFIGURED;
			goto done;
		}

		goto done;
	}

	ASSERT(cp->cpu_id == cpuid);

	/*
	 * Offline the CPU
	 */
	if (cpu_is_active(cp)) {

		/* set the force flag correctly */
		cpu_flags = (force) ? CPU_FORCED : 0;

		if ((rv = cpu_offline(cp, cpu_flags)) != 0) {
			DR_DBG_CPU("failed to offline CPU %d (%d)\n",
			    cpuid, rv);

			rv = DR_CPU_RES_FAILURE;
			*status = DR_CPU_STAT_CONFIGURED;
			goto done;
		}

		DR_DBG_CPU("CPU %d offline\n", cpuid);
	}

	/*
	 * Power off the CPU. In sun4v, this puts the running
	 * CPU into the stopped state in the Hypervisor.
	 */
	if (!cpu_is_poweredoff(cp)) {

		if ((rv = cpu_poweroff(cp)) != 0) {
			DR_DBG_CPU("failed to power off CPU %d (%d)\n",
			    cpuid, rv);
			rv = DR_CPU_RES_FAILURE;
			*status = DR_CPU_STAT_CONFIGURED;
			goto done;
		}

		DR_DBG_CPU("CPU %d powered off\n", cpuid);
	}

	/*
	 * Unconfigure the CPU
	 */
	if ((rv = cpu_unconfigure(cpuid)) != 0) {
		DR_DBG_CPU("failed to unconfigure CPU %d (%d)\n", cpuid, rv);
		rv = DR_CPU_RES_FAILURE;
		*status = DR_CPU_STAT_UNCONFIGURED;
		goto done;
	}

	DR_DBG_CPU("CPU %d unconfigured\n", cpuid);

	/*
	 * Tear down device tree.
	 */
	if ((rv = dr_cpu_deprobe(cpuid)) != 0) {
		DR_DBG_CPU("failed to deprobe CPU %d (%d)\n", cpuid, rv);
		rv = DR_CPU_RES_FAILURE;
		*status = DR_CPU_STAT_UNCONFIGURED;
		goto done;
	}

	rv = DR_CPU_RES_OK;
	*status = DR_CPU_STAT_UNCONFIGURED;

done:
	mutex_exit(&cpu_lock);

	return (rv);
}

/*
 * Determine the state of a CPU. If the CPU structure is not present,
 * it does not attempt to determine whether or not the CPU is in the
 * MD. It is more efficient to do this at the higher level for all
 * CPUs since it may not even be necessary to search the MD if all
 * the CPUs are accounted for. Returns DR_CPU_RES_OK if the CPU
 * structure is present, and DR_CPU_RES_FAILURE otherwise as a signal
 * that an MD walk is necessary.
 */
static int
dr_cpu_status(processorid_t cpuid, int *status)
{
	int		rv;
	struct cpu	*cp;

	DR_DBG_CPU("dr_cpu_status...\n");

	mutex_enter(&cpu_lock);

	if ((cp = cpu_get(cpuid)) == NULL) {
		/* need to check if cpu is in the MD */
		rv = DR_CPU_RES_FAILURE;
		goto done;
	}

	if (cpu_is_poweredoff(cp)) {
		/*
		 * The CPU is powered off, so it is considered
		 * unconfigured from the service entity point of
		 * view. The CPU is not available to the system
		 * and intervention by the service entity would
		 * be required to change that.
		 */
		*status = DR_CPU_STAT_UNCONFIGURED;
	} else {
		/*
		 * The CPU is powered on, so it is considered
		 * configured from the service entity point of
		 * view. It is available for use by the system
		 * and service entities are not concerned about
		 * the operational status (offline, online, etc.)
		 * of the CPU in terms of DR.
		 */
		*status = DR_CPU_STAT_CONFIGURED;
	}

	rv = DR_CPU_RES_OK;

done:
	mutex_exit(&cpu_lock);

	return (rv);
}

typedef struct {
	md_t		*mdp;
	mde_cookie_t	cpunode;
	dev_info_t	*dip;
} cb_arg_t;

#define	STR_ARR_LEN	5

static int
new_cpu_node(dev_info_t *new_node, void *arg, uint_t flags)
{
	_NOTE(ARGUNUSED(flags))

	char		*compat;
	uint64_t	freq;
	uint64_t	cpuid = 0;
	int		regbuf[4];
	int		len = 0;
	cb_arg_t	*cba;
	char		*str_arr[STR_ARR_LEN];
	char		*curr;
	int		idx = 0;

	DR_DBG_CPU("new_cpu_node...\n");

	cba = (cb_arg_t *)arg;

	/*
	 * Add 'name' property
	 */
	if (ndi_prop_update_string(DDI_DEV_T_NONE, new_node,
	    "name", "cpu") != DDI_SUCCESS) {
		DR_DBG_CPU("new_cpu_node: failed to create 'name' property\n");
		return (DDI_WALK_ERROR);
	}

	/*
	 * Add 'compatible' property
	 */
	if (md_get_prop_data(cba->mdp, cba->cpunode, "compatible",
	    (uint8_t **)(&compat), &len)) {
		DR_DBG_CPU("new_cpu_node: failed to read 'compatible' property "
		    "from MD\n");
		return (DDI_WALK_ERROR);
	}

	DR_DBG_CPU("'compatible' len is %d\n", len);

	/* parse the MD string array */
	curr = compat;
	while (curr < (compat + len)) {

		DR_DBG_CPU("adding '%s' to 'compatible' property\n", curr);

		str_arr[idx++] = curr;
		curr += strlen(curr) + 1;

		if (idx == STR_ARR_LEN) {
			DR_DBG_CPU("exceeded str_arr len (%d)\n", STR_ARR_LEN);
			break;
		}
	}

	if (ndi_prop_update_string_array(DDI_DEV_T_NONE, new_node,
	    "compatible", str_arr, idx) != DDI_SUCCESS) {
		DR_DBG_CPU("new_cpu_node: failed to create 'compatible' "
		    "property\n");
		return (DDI_WALK_ERROR);
	}

	/*
	 * Add 'device_type' property
	 */
	if (ndi_prop_update_string(DDI_DEV_T_NONE, new_node,
	    "device_type", "cpu") != DDI_SUCCESS) {
		DR_DBG_CPU("new_cpu_node: failed to create 'device_type' "
		    "property\n");
		return (DDI_WALK_ERROR);
	}

	/*
	 * Add 'clock-frequency' property
	 */
	if (md_get_prop_val(cba->mdp, cba->cpunode, "clock-frequency", &freq)) {
		DR_DBG_CPU("new_cpu_node: failed to read 'clock-frequency' "
		    "property from MD\n");
		return (DDI_WALK_ERROR);
	}

	if (ndi_prop_update_int(DDI_DEV_T_NONE, new_node,
	    "clock-frequency", freq) != DDI_SUCCESS) {
		DR_DBG_CPU("new_cpu_node: failed to create 'clock-frequency' "
		    "property\n");
		return (DDI_WALK_ERROR);
	}

	/*
	 * Add 'reg' (cpuid) property
	 */
	if (md_get_prop_val(cba->mdp, cba->cpunode, "id", &cpuid)) {
		DR_DBG_CPU("new_cpu_node: failed to read 'id' property "
		    "from MD\n");
		return (DDI_WALK_ERROR);
	}

	DR_DBG_CPU("new cpuid=0x%lx\n", cpuid);

	bzero(regbuf, 4 * sizeof (int));
	regbuf[0] = 0xc0000000 | cpuid;

	if (ndi_prop_update_int_array(DDI_DEV_T_NONE, new_node,
	    "reg", regbuf, 4) != DDI_SUCCESS) {
		DR_DBG_CPU("new_cpu_node: failed to create 'reg' property\n");
		return (DDI_WALK_ERROR);
	}

	cba->dip = new_node;

	return (DDI_WALK_TERMINATE);
}

static int
dr_cpu_probe(processorid_t cpuid)
{
	dev_info_t	*pdip;
	dev_info_t	*dip;
	devi_branch_t	br;
	md_t		*mdp = NULL;
	int		num_nodes;
	int		rv = 0;
	int		listsz;
	mde_cookie_t	*listp = NULL;
	cb_arg_t	cba;
	mde_cookie_t	cpunode;

	if ((dip = dr_cpu_find_node(cpuid)) != NULL) {
		/* nothing to do */
		e_ddi_branch_rele(dip);
		return (0);
	}

	if ((mdp = md_get_handle()) == NULL) {
		DR_DBG_CPU("unable to initialize machine description\n");
		return (-1);
	}

	num_nodes = md_node_count(mdp);
	ASSERT(num_nodes > 0);

	listsz = num_nodes * sizeof (mde_cookie_t);
	listp = kmem_zalloc(listsz, KM_SLEEP);

	cpunode = dr_cpu_find_node_md(cpuid, mdp, listp);

	if (cpunode == MDE_INVAL_ELEM_COOKIE) {
		rv = EINVAL;
		goto done;
	}

	/* pass in MD cookie for CPU */
	cba.mdp = mdp;
	cba.cpunode = cpunode;

	br.arg = (void *)&cba;
	br.type = DEVI_BRANCH_SID;
	br.create.sid_branch_create = new_cpu_node;
	br.devi_branch_callback = NULL;
	pdip = ddi_root_node();

	if ((rv = e_ddi_branch_create(pdip, &br, NULL, 0))) {
		DR_DBG_CPU("e_ddi_branch_create failed: %d\n", rv);
		rv = -1;
		goto done;
	}

	DR_DBG_CPU("CPU %d probed\n", cpuid);

	rv = 0;

done:
	if (listp)
		kmem_free(listp, listsz);

	if (mdp)
		(void) md_fini_handle(mdp);

	return (rv);
}

static int
dr_cpu_deprobe(processorid_t cpuid)
{
	dev_info_t	*fdip = NULL;
	dev_info_t	*dip;

	if ((dip = dr_cpu_find_node(cpuid)) == NULL) {
		DR_DBG_CPU("cpuid %d already deprobed\n", cpuid);
		return (0);
	}

	ASSERT(e_ddi_branch_held(dip));

	if (e_ddi_branch_destroy(dip, &fdip, 0)) {
		char *path = kmem_alloc(MAXPATHLEN, KM_SLEEP);

		/*
		 * If non-NULL, fdip is held and must be released.
		 */
		if (fdip != NULL) {
			(void) ddi_pathname(fdip, path);
			ddi_release_devi(fdip);
		} else {
			(void) ddi_pathname(dip, path);
		}
		cmn_err(CE_NOTE, "node removal failed: %s (%p)",
		    path, (fdip) ? (void *)fdip : (void *)dip);

		kmem_free(path, MAXPATHLEN);

		return (-1);
	}

	DR_DBG_CPU("CPU %d deprobed\n", cpuid);

	return (0);
}

typedef struct {
	processorid_t	cpuid;
	dev_info_t	*dip;
} dr_search_arg_t;

static int
dr_cpu_check_node(dev_info_t *dip, void *arg)
{
	char 		*name;
	processorid_t	cpuid;
	dr_search_arg_t	*sarg = (dr_search_arg_t *)arg;

	if (dip == ddi_root_node()) {
		return (DDI_WALK_CONTINUE);
	}

	name = ddi_node_name(dip);

	if (strcmp(name, "cpu") != 0) {
		return (DDI_WALK_PRUNECHILD);
	}

	cpuid = ddi_prop_get_int(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "reg", -1);

	cpuid = PROM_CFGHDL_TO_CPUID(cpuid);

	DR_DBG_CPU("found cpuid=0x%x, looking for 0x%x\n", cpuid, sarg->cpuid);

	if (cpuid == sarg->cpuid) {
		DR_DBG_CPU("matching node\n");

		/* matching node must be returned held */
		if (!e_ddi_branch_held(dip))
			e_ddi_branch_hold(dip);

		sarg->dip = dip;
		return (DDI_WALK_TERMINATE);
	}

	return (DDI_WALK_CONTINUE);
}

/*
 * Walk the device tree to find the dip corresponding to the cpuid
 * passed in. If present, the dip is returned held. The caller must
 * release the hold on the dip once it is no longer required. If no
 * matching node if found, NULL is returned.
 */
static dev_info_t *
dr_cpu_find_node(processorid_t cpuid)
{
	dr_search_arg_t	arg;

	DR_DBG_CPU("dr_cpu_find_node...\n");

	arg.cpuid = cpuid;
	arg.dip = NULL;

	ddi_walk_devs(ddi_root_node(), dr_cpu_check_node, &arg);

	ASSERT((arg.dip == NULL) || (e_ddi_branch_held(arg.dip)));

	return ((arg.dip) ? arg.dip : NULL);
}

/*
 * Look up a particular cpuid in the MD. Returns the mde_cookie_t
 * representing that CPU if present, and MDE_INVAL_ELEM_COOKIE
 * otherwise. It is assumed the scratch array has already been
 * allocated so that it can accommodate the worst case scenario,
 * every node in the MD.
 */
static mde_cookie_t
dr_cpu_find_node_md(processorid_t cpuid, md_t *mdp, mde_cookie_t *listp)
{
	int		idx;
	int		nnodes;
	mde_cookie_t	rootnode;
	uint64_t	cpuid_prop;
	mde_cookie_t	result = MDE_INVAL_ELEM_COOKIE;

	rootnode = md_root_node(mdp);
	ASSERT(rootnode != MDE_INVAL_ELEM_COOKIE);

	/*
	 * Scan the DAG for all the CPU nodes
	 */
	nnodes = md_scan_dag(mdp, rootnode, md_find_name(mdp, "cpu"),
	    md_find_name(mdp, "fwd"), listp);

	if (nnodes < 0) {
		DR_DBG_CPU("Scan for CPUs failed\n");
		return (result);
	}

	DR_DBG_CPU("dr_cpu_find_node_md: found %d CPUs in the MD\n", nnodes);

	/*
	 * Find the CPU of interest
	 */
	for (idx = 0; idx < nnodes; idx++) {

		if (md_get_prop_val(mdp, listp[idx], "id", &cpuid_prop)) {
			DR_DBG_CPU("Missing 'id' property for CPU node %d\n",
			    idx);
			break;
		}

		if (cpuid_prop == cpuid) {
			/* found a match */
			DR_DBG_CPU("dr_cpu_find_node_md: found CPU %d "
			    "in MD\n", cpuid);
			result = listp[idx];
			break;
		}
	}

	if (result == MDE_INVAL_ELEM_COOKIE) {
		DR_DBG_CPU("CPU %d not in MD\n", cpuid);
	}

	return (result);
}
