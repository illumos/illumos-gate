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
 * Copyright 2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/conf.h>
#include <sys/atomic.h>
#include <sys/systm.h>
#include <sys/socket.h>
#include <sys/spl.h>
#include <netinet/in.h>
#include <sys/modctl.h>
#include <sys/sunddi.h>
#include <ipp/ipp.h>
#include <ipp/ipp_config.h>
#include <inet/common.h>
#include <ipp/flowacct/flowacct_impl.h>
#include <sys/ddi.h>

#define	D_SM_COMMENT	"IPP Flow Accounting Module"

/* DDI file for flowacct ipp module */

static int flowacct_create_action(ipp_action_id_t, nvlist_t **, ipp_flags_t);
static int flowacct_modify_action(ipp_action_id_t, nvlist_t **, ipp_flags_t);
static int flowacct_destroy_action(ipp_action_id_t, ipp_flags_t);
static int flowacct_info(ipp_action_id_t, int (*)(nvlist_t *, void *), void *,
    ipp_flags_t);
static int flowacct_invoke_action(ipp_action_id_t, ipp_packet_t *);

static int update_flowacct_kstats(ipp_stat_t *, void *, int);

ipp_ops_t flowacct_ops = {
	IPPO_REV,
	flowacct_create_action,		/* ippo_action_create */
	flowacct_modify_action,		/* ippo_action_modify */
	flowacct_destroy_action,	/* ippo_action_destroy */
	flowacct_info,			/* ippo_action_info */
	flowacct_invoke_action		/* ippo_action_invoke */
};

extern struct mod_ops mod_ippops;

/*
 * Module linkage information for the kernel.
 */
static struct modlipp modlipp = {
	&mod_ippops,
	D_SM_COMMENT " 1.12",
	&flowacct_ops
};

static struct modlinkage modlinkage = {
	MODREV_1,
	(void *)&modlipp,
	NULL
};

int
_init(void)
{
	return (mod_install(&modlinkage));
}

int
_fini(void)
{
	return (mod_remove(&modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/* Update global stats */
static int
update_flowacct_kstats(ipp_stat_t *sp, void *arg, int rw)
{
	flowacct_data_t *flowacct_data = (flowacct_data_t *)arg;
	flowacct_stat_t *fl_stat  = (flowacct_stat_t *)sp->ipps_data;
	ASSERT((fl_stat != NULL) && (flowacct_data != 0));

	(void) ipp_stat_named_op(&fl_stat->nbytes, &flowacct_data->nbytes, rw);
	(void) ipp_stat_named_op(&fl_stat->tbytes, &flowacct_data->tbytes, rw);
	(void) ipp_stat_named_op(&fl_stat->nflows, &flowacct_data->nflows, rw);
	(void) ipp_stat_named_op(&fl_stat->usedmem, &flowacct_data->usedmem,
	    rw);
	(void) ipp_stat_named_op(&fl_stat->npackets, &flowacct_data->npackets,
	    rw);
	(void) ipp_stat_named_op(&fl_stat->epackets, &flowacct_data->epackets,
	    rw);
	return (0);
}

/* Initialize global stats */
static int
global_statinit(ipp_action_id_t aid, flowacct_data_t *flowacct_data)
{
	flowacct_stat_t *flacct_stat;
	int err = 0;

	if ((err = ipp_stat_create(aid, FLOWACCT_STATS_STRING,
	    FLOWACCT_STATS_COUNT, update_flowacct_kstats, flowacct_data,
	    &flowacct_data->stats)) != 0) {
		flowacct0dbg(("global_statinit: error creating flowacct "\
		    "stats\n"));
		return (err);
	}
	flacct_stat = (flowacct_stat_t *)(flowacct_data->stats)->ipps_data;
	ASSERT(flacct_stat != NULL);

	if ((err = ipp_stat_named_init(flowacct_data->stats, "bytes_in_tbl",
	    IPP_STAT_UINT64, &flacct_stat->tbytes)) != 0) {
		flowacct0dbg(("global_statinit: ipp_stat_named_init returned "\
		    "with error %d\n", err));
		return (err);
	}
	if ((err = ipp_stat_named_init(flowacct_data->stats, "nbytes",
	    IPP_STAT_UINT64, &flacct_stat->nbytes)) != 0) {
		flowacct0dbg(("global_statinit: ipp_stat_named_init returned "\
		    "with error %d\n", err));
		return (err);
	}
	if ((err = ipp_stat_named_init(flowacct_data->stats, "npackets",
	    IPP_STAT_UINT64, &flacct_stat->npackets)) != 0) {
		flowacct0dbg(("global_statinit:ipp_stat_named_init returned "\
		    "with error %d\n", err));
		return (err);
	}
	if ((err = ipp_stat_named_init(flowacct_data->stats, "usedmem",
	    IPP_STAT_UINT64, &flacct_stat->usedmem)) != 0) {
		flowacct0dbg(("global_statinit:ipp_stat_named_init returned "\
		    "with error %d\n", err));
		return (err);
	}
	if ((err = ipp_stat_named_init(flowacct_data->stats, "flows_in_tbl",
	    IPP_STAT_UINT32, &flacct_stat->nflows)) != 0) {
		flowacct0dbg(("global_statinit:ipp_stat_named_init returned "\
		    "with error %d\n", err));
		return (err);
	}
	if ((err = ipp_stat_named_init(flowacct_data->stats, "epackets",
	    IPP_STAT_UINT64, &flacct_stat->epackets)) != 0) {
		flowacct0dbg(("global_statinit:ipp_stat_named_init returned "\
		    "with error %d\n", err));
		return (err);
	}
	ipp_stat_install(flowacct_data->stats);

	return (err);
}

static int
flowacct_create_action(ipp_action_id_t aid, nvlist_t **nvlpp, ipp_flags_t flags)
{
	nvlist_t *nvlp;
	flowacct_data_t *flowacct_data;
	char *next_action;
	int rc, flow_count;
	list_head_t *head;
	uint32_t bstats;
	uint32_t timeout = FLOWACCT_DEF_TIMEOUT;
	uint32_t timer = FLOWACCT_DEF_TIMER;

	nvlp = *nvlpp;
	*nvlpp = NULL;		/* nvlist should be NULL on return */

	if ((flowacct_data = kmem_zalloc(FLOWACCT_DATA_SZ, KM_NOSLEEP))
	    == NULL) {
		nvlist_free(nvlp);
		return (ENOMEM);
	}

	/* parse next action name */
	if ((rc = nvlist_lookup_string(nvlp, FLOWACCT_NEXT_ACTION_NAME,
	    &next_action)) != 0) {
		nvlist_free(nvlp);
		kmem_free(flowacct_data, FLOWACCT_DATA_SZ);
		flowacct0dbg(("flowacct_create_action: invalid config, "\
		    "next_action missing\n"));
		return (rc);
	}
	if ((flowacct_data->next_action = ipp_action_lookup(next_action))
	    == IPP_ACTION_INVAL) {
		nvlist_free(nvlp);
		flowacct0dbg(("flowacct_create_action: invalid next_action\n"));
		kmem_free(flowacct_data, FLOWACCT_DATA_SZ);
		return (EINVAL);
	}

	if ((rc = ipp_action_name(aid, &flowacct_data->act_name)) != 0) {
		nvlist_free(nvlp);
		flowacct0dbg(("flowacct_create_action: invalid next aid\n"));
		kmem_free(flowacct_data, FLOWACCT_DATA_SZ);
		return (EINVAL);
	}

	/* parse flow timeout - in millisec, if present */
	(void) nvlist_lookup_uint32(nvlp, FLOWACCT_TIMEOUT, &timeout);

	/* Convert to FLOWACCT_MSEC_TO_NSEC */
	flowacct_data->timeout = (uint64_t)timeout * FLOWACCT_MSEC_TO_NSEC;

	/* parse flow timer - in millisec, if present  */
	(void) nvlist_lookup_uint32(nvlp, FLOWACCT_TIMER, &timer);

	/* Convert to FLOWACCT_MSEC_TO_USEC */
	flowacct_data->timer = (uint64_t)timer * FLOWACCT_MSEC_TO_USEC;

	if ((rc = nvlist_lookup_uint32(nvlp, FLOWACCT_MAX_LIMIT,
	    &flowacct_data->max_limit)) != 0) {
		nvlist_free(nvlp);
		flowacct0dbg(("flowacct_create_action: invalid config, "\
		    "max_limit missing\n"));
		kmem_free(flowacct_data, FLOWACCT_DATA_SZ);
		return (rc);
	}

	if ((rc = nvlist_lookup_uint32(nvlp, IPP_ACTION_STATS_ENABLE,
	    &bstats)) != 0) {
		flowacct_data->global_stats = B_FALSE;
	} else {
		flowacct_data->global_stats = (boolean_t)bstats;
		if (flowacct_data->global_stats) {
			if ((rc = global_statinit(aid, flowacct_data)) != 0) {
				kmem_free(flowacct_data, FLOWACCT_DATA_SZ);
				return (rc);
			}
		}
	}

	nvlist_free(nvlp);

	/* set action chain reference */
	if ((rc = ipp_action_ref(aid, flowacct_data->next_action,
	    flags)) != 0) {
		flowacct0dbg(("flowacct_create_action: ipp_action_ref " \
		    "returned with error %d\n", rc));
		if (flowacct_data->stats != NULL) {
			ipp_stat_destroy(flowacct_data->stats);
		}
		kmem_free(flowacct_data, FLOWACCT_DATA_SZ);
		return (rc);
	}

	/* Initialize locks */
	for (flow_count = 0, head = flowacct_data->flows_tbl;
	    flow_count < (FLOW_TBL_COUNT + 1); flow_count++, head++) {
		mutex_init(&head->lock, NULL, MUTEX_DEFAULT, 0);
	}

	ipp_action_set_ptr(aid, (void *)flowacct_data);
	return (0);
}

static int
flowacct_modify_action(ipp_action_id_t aid, nvlist_t **nvlpp, ipp_flags_t flags)
{
	nvlist_t *nvlp;
	int rc = 0;
	uint8_t config_type;
	char *next_action_name, *act_name;
	ipp_action_id_t next_action;
	uint32_t timeout, timer, bstats, max_limit;
	flowacct_data_t *flowacct_data;

	nvlp = *nvlpp;
	*nvlpp = NULL;		/* nvlist should be NULL when this returns */

	if ((rc = nvlist_lookup_byte(nvlp, IPP_CONFIG_TYPE, &config_type))
	    != 0) {
		nvlist_free(nvlp);
		flowacct0dbg(("flowacct_modify_action: invalid configuration "\
		    "type\n"));
		return (rc);
	}

	if (config_type != IPP_SET) {
		nvlist_free(nvlp);
		flowacct0dbg(("flowacct_modify_action: invalid configuration "\
		    "type %d\n", config_type));
		return (EINVAL);
	}

	flowacct_data = (flowacct_data_t *)ipp_action_get_ptr(aid);

	/* parse next action name, if present */
	if ((rc = nvlist_lookup_string(nvlp, FLOWACCT_NEXT_ACTION_NAME,
	    &next_action_name)) == 0) {
		/* lookup action name to get action id */
		if ((next_action = ipp_action_lookup(next_action_name))
		    == IPP_ACTION_INVAL) {
			nvlist_free(nvlp);
			flowacct0dbg(("flowacct_modify_action: next_action "\
			    "invalid\n"));
			return (EINVAL);
		}
		/* reference new action */
		if ((rc = ipp_action_ref(aid, next_action, flags)) != 0) {
			nvlist_free(nvlp);
			flowacct0dbg(("flowacct_modify_action: "\
			    "ipp_action_ref returned with error %d\n", rc));
			return (rc);
		}

		if ((rc = ipp_action_name(aid, &act_name)) != 0) {
			nvlist_free(nvlp);
			flowacct0dbg(("flowacct_modify_action: invalid next "\
			    "aid\n"));
			return (EINVAL);
		}

		/* unref old action */
		rc = ipp_action_unref(aid, flowacct_data->next_action, flags);
		ASSERT(rc == 0);
		flowacct_data->next_action = next_action;
		kmem_free(flowacct_data->act_name,
		    (strlen(flowacct_data->act_name) + 1));
		flowacct_data->act_name = act_name;
	}

	/* parse timeout, if present */
	if ((rc = nvlist_lookup_uint32(nvlp, FLOWACCT_TIMEOUT, &timeout))
	    == 0) {
		flowacct_data->timeout = (uint64_t)timeout *
		    FLOWACCT_MSEC_TO_NSEC;
	}

	/* parse timer, if present */
	if ((rc = nvlist_lookup_uint32(nvlp, FLOWACCT_TIMER, &timer)) == 0) {
		flowacct_data->timer = (uint64_t)timer * FLOWACCT_MSEC_TO_USEC;
	}

	/* parse max_flow, if present */
	if ((rc = nvlist_lookup_uint32(nvlp, FLOWACCT_MAX_LIMIT, &max_limit))
	    == 0) {
		flowacct_data->max_limit = max_limit;
	}

	/* parse gather_stats boolean, if present */
	if ((rc = nvlist_lookup_uint32(nvlp, IPP_ACTION_STATS_ENABLE, &bstats))
	    == 0) {
		boolean_t new_val = (boolean_t)bstats;

		/* Turning global stats on */
		if (new_val && !flowacct_data->global_stats) {
			rc = global_statinit(aid, flowacct_data);
			if (rc == 0) {
				flowacct_data->global_stats = new_val;
			} else {
				flowacct0dbg(("flowacct_modify_action: error "\
				    "enabling stats\n"));
			}
		} else if (!new_val && flowacct_data->global_stats) {
			flowacct_data->global_stats = new_val;
			ipp_stat_destroy(flowacct_data->stats);
		}
	}
	return (0);
}

static int
flowacct_destroy_action(ipp_action_id_t aid, ipp_flags_t flags)
{
	flowacct_data_t *flowacct_data;
	int rc, flow_count;
	list_head_t *head;

	flowacct_data = (flowacct_data_t *)ipp_action_get_ptr(aid);
	ASSERT(flowacct_data != NULL);

	while (flowacct_data->flow_tid != 0) {
		timeout_id_t tid = flowacct_data->flow_tid;
		flowacct_data->flow_tid = 0;
		(void) untimeout(tid);
	}

	if (flowacct_data->stats != NULL) {
		ipp_stat_destroy(flowacct_data->stats);
	}

	/* Dump all the flows to the file */
	flowacct_timer(FLOWACCT_PURGE_FLOW, flowacct_data);

	kmem_free(flowacct_data->act_name, (strlen(flowacct_data->act_name)
	    + 1));

	/* Destroy the locks */
	for (flow_count = 0, head = flowacct_data->flows_tbl;
	    flow_count < FLOW_TBL_COUNT; flow_count++, head++) {
		mutex_destroy(&head->lock);
	}
	/* unreference the action */
	rc = ipp_action_unref(aid, flowacct_data->next_action, flags);
	ASSERT(rc == 0);


	kmem_free(flowacct_data, FLOWACCT_DATA_SZ);
	return (0);
}

static int
flowacct_invoke_action(ipp_action_id_t aid, ipp_packet_t *packet)
{
	flowacct_data_t *flowacct_data;
	mblk_t *mp = NULL;
	int rc;

	/* get mblk from ipp_packet structure */
	mp = ipp_packet_get_data(packet);
	flowacct_data = (flowacct_data_t *)ipp_action_get_ptr(aid);
	ASSERT(flowacct_data != NULL);

	/* flowacct packet as configured */
	if ((rc = flowacct_process(&mp, flowacct_data)) != 0) {
		return (rc);
	} else {
		/* return packet with next action set */
		return (ipp_packet_next(packet, flowacct_data->next_action));
	}
}

/* ARGSUSED */
static int
flowacct_info(ipp_action_id_t aid, int (*fn)(nvlist_t *, void *), void *arg,
    ipp_flags_t flags)
{
	nvlist_t *nvlp;
	flowacct_data_t *flowacct_data;
	char *next_action;
	uint32_t param;
	int rc;

	flowacct_data = (flowacct_data_t *)ipp_action_get_ptr(aid);
	ASSERT(flowacct_data != NULL);
	ASSERT(fn != NULL);

	/* allocate nvlist to be passed back */
	if ((rc = nvlist_alloc(&nvlp, NV_UNIQUE_NAME, KM_NOSLEEP)) != 0) {
		flowacct0dbg(("flowacct_info: memory allocation failure\n"));
		return (rc);
	}

	/* look up next action with the next action id */
	if ((rc = ipp_action_name(flowacct_data->next_action,
	    &next_action)) != 0) {
		flowacct0dbg(("flowacct_info: next action not available\n"));
		nvlist_free(nvlp);
		return (rc);
	}

	/* add next action name */
	if ((rc = nvlist_add_string(nvlp, FLOWACCT_NEXT_ACTION_NAME,
	    next_action)) != 0) {
		flowacct0dbg(("flowacct_info: error adding next action\n"));
		nvlist_free(nvlp);
		kmem_free(next_action, (strlen(next_action) + 1));
		return (rc);
	}

	/* free action name */
	kmem_free(next_action, (strlen(next_action) + 1));

	/* add config type */
	if ((rc = nvlist_add_byte(nvlp, IPP_CONFIG_TYPE, IPP_SET)) != 0) {
		flowacct0dbg(("flowacct_info: error adding config type\n"));
		nvlist_free(nvlp);
		return (rc);
	}

	/* add timer */
	param = flowacct_data->timer / FLOWACCT_MSEC_TO_USEC;
	if ((rc = nvlist_add_uint32(nvlp, FLOWACCT_TIMER, param)) != 0) {
		flowacct0dbg(("flowacct_info: error adding timer info.\n"));
		nvlist_free(nvlp);
		return (rc);
	}

	/* add max_limit */
	if ((rc = nvlist_add_uint32(nvlp, FLOWACCT_MAX_LIMIT,
	    flowacct_data->max_limit)) != 0) {
		flowacct0dbg(("flowacct_info: error adding max_flow info.\n"));
		nvlist_free(nvlp);
		return (rc);
	}


	param = flowacct_data->timeout / FLOWACCT_MSEC_TO_NSEC;
	/* add timeout */
	if ((rc = nvlist_add_uint32(nvlp, FLOWACCT_TIMEOUT, param)) != 0) {
		flowacct0dbg(("flowacct_info: error adding timeout info.\n"));
		nvlist_free(nvlp);
		return (rc);
	}

	/* add global stats boolean */
	if ((rc = nvlist_add_uint32(nvlp, IPP_ACTION_STATS_ENABLE,
	    (uint32_t)flowacct_data->global_stats)) != 0) {
		flowacct0dbg(("flowacct_info: error adding global stats "\
		    "info.\n"));
		nvlist_free(nvlp);
		return (rc);
	}

	/* call back with nvlist */
	rc = fn(nvlp, arg);

	nvlist_free(nvlp);
	return (rc);
}
