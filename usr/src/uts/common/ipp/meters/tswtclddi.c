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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/types.h>
#include <sys/atomic.h>
#include <sys/systm.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/modctl.h>
#include <sys/sunddi.h>
#include <ipp/ipp.h>
#include <ipp/ipp_config.h>
#include <inet/common.h>
#include <ipp/meters/meter_impl.h>

#define	D_SM_COMMENT	"IPP Sliding Window Meter"

/* DDI file for tswtcl ipp module */

static int tswtcl_create_action(ipp_action_id_t, nvlist_t **, ipp_flags_t);
static int tswtcl_modify_action(ipp_action_id_t, nvlist_t **, ipp_flags_t);
static int tswtcl_destroy_action(ipp_action_id_t, ipp_flags_t);
static int tswtcl_info(ipp_action_id_t, int (*)(nvlist_t *, void *), void *,
    ipp_flags_t);
static int tswtcl_invoke_action(ipp_action_id_t, ipp_packet_t *);

/* Stats init function */
static int tswtcl_statinit(ipp_action_id_t, tswtcl_data_t *);

/* Stats callback function */
static int tswtcl_update_stats(ipp_stat_t *, void *, int);

ipp_ops_t tswtcl_ops = {
	IPPO_REV,
	tswtcl_create_action,	/* ippo_action_create */
	tswtcl_modify_action,	/* ippo_action_modify */
	tswtcl_destroy_action,	/* ippo_action_destroy */
	tswtcl_info,		/* ippo_action_info */
	tswtcl_invoke_action	/* ippo_action_invoke */
};

extern struct mod_ops mod_ippops;

/*
 * Module linkage information for the kernel.
 */
static struct modlipp modlipp = {
	&mod_ippops,
	D_SM_COMMENT,
	&tswtcl_ops
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

/* ARGSUSED */
static int
tswtcl_create_action(ipp_action_id_t aid, nvlist_t **nvlpp, ipp_flags_t flags)
{
	nvlist_t *nvlp;
	tswtcl_data_t *tswtcl_data;
	tswtcl_cfg_t *cfg_parms;
	char *next_action;
	uint32_t bstats;
	int rc, rc2;

	nvlp = *nvlpp;
	*nvlpp = NULL;		/* nvlist should be NULL on return */


	if ((cfg_parms = kmem_alloc(TSWTCL_CFG_SZ, KM_NOSLEEP)) == NULL) {
		nvlist_free(nvlp);
		return (ENOMEM);
	}

	/* parse red next action name */
	if ((rc = nvlist_lookup_string(nvlp, TSWTCL_RED_ACTION_NAME,
	    &next_action)) != 0) {
		nvlist_free(nvlp);
		tswtcl0dbg(("tswtcl_create_action:invalid config, red action" \
		    " name missing\n"));
		kmem_free(cfg_parms, TSWTCL_CFG_SZ);
		return (rc);
	}
	if ((cfg_parms->red_action = ipp_action_lookup(next_action))
	    == IPP_ACTION_INVAL) {
		nvlist_free(nvlp);
		tswtcl0dbg(("tswtcl_create_action: red action invalid\n"));
		kmem_free(cfg_parms, TSWTCL_CFG_SZ);
		return (EINVAL);
	}

	/* parse yellow next action name */
	if ((rc = nvlist_lookup_string(nvlp, TSWTCL_YELLOW_ACTION_NAME,
	    &next_action)) != 0) {
		nvlist_free(nvlp);
		tswtcl0dbg(("tswtcl_create_action:invalid config, yellow " \
		    "action name missing\n"));
		kmem_free(cfg_parms, TSWTCL_CFG_SZ);
		return (rc);
	}
	if ((cfg_parms->yellow_action = ipp_action_lookup(next_action))
	    == IPP_ACTION_INVAL) {
		nvlist_free(nvlp);
		tswtcl0dbg(("tswtcl_create_action: yellow action invalid\n"));
		kmem_free(cfg_parms, TSWTCL_CFG_SZ);
		return (EINVAL);
	}

	/* parse green next action name */
	if ((rc = nvlist_lookup_string(nvlp, TSWTCL_GREEN_ACTION_NAME,
	    &next_action)) != 0) {
		nvlist_free(nvlp);
		tswtcl0dbg(("tswtcl_create_action:invalid config, green " \
		    "action name missing\n"));
		kmem_free(cfg_parms, TSWTCL_CFG_SZ);
		return (rc);
	}
	if ((cfg_parms->green_action = ipp_action_lookup(next_action))
	    == IPP_ACTION_INVAL) {
		nvlist_free(nvlp);
		tswtcl0dbg(("tswtcl_create_action: green action invalid\n"));
		kmem_free(cfg_parms, TSWTCL_CFG_SZ);
		return (EINVAL);
	}

	/* parse committed rate  - in bits / sec */
	if ((rc = nvlist_lookup_uint32(nvlp, TSWTCL_COMMITTED_RATE,
	    &cfg_parms->committed_rate)) != 0) {
		nvlist_free(nvlp);
		tswtcl0dbg(("tswtcl_create_action: invalid config, "\
		    " committed rate missing\n"));
		kmem_free(cfg_parms, TSWTCL_CFG_SZ);
		return (rc);
	}

	/* parse peak rate  - in bits / sec */
	if ((rc = nvlist_lookup_uint32(nvlp, TSWTCL_PEAK_RATE,
	    &cfg_parms->peak_rate)) != 0) {
		nvlist_free(nvlp);
		tswtcl0dbg(("tswtcl_create_action: invalid config, "\
		    " peak rate missing\n"));
		kmem_free(cfg_parms, TSWTCL_CFG_SZ);
		return (rc);
	}

	if (cfg_parms->peak_rate < cfg_parms->committed_rate) {
		nvlist_free(nvlp);
		tswtcl0dbg(("tswtcl_create_action: invalid config, "\
		    " peak rate < committed rate\n"));
		kmem_free(cfg_parms, TSWTCL_CFG_SZ);
		return (EINVAL);
	}

	/* parse window - in msec */
	if ((rc = nvlist_lookup_uint32(nvlp, TSWTCL_WINDOW,
	    &cfg_parms->window)) != 0) {
		nvlist_free(nvlp);
		tswtcl0dbg(("tswtcl_create_action: invalid config, "\
		    " window missing\n"));
		kmem_free(cfg_parms, TSWTCL_CFG_SZ);
		return (rc);
	}
	/* convert to nsec */
	cfg_parms->nsecwindow = (uint64_t)cfg_parms->window *
	    METER_MSEC_TO_NSEC;

	/* parse stats */
	if ((rc = nvlist_lookup_uint32(nvlp, IPP_ACTION_STATS_ENABLE, &bstats))
	    != 0) {
		cfg_parms->stats = B_FALSE;
	} else {
		cfg_parms->stats = (boolean_t)bstats;
	}

	nvlist_free(nvlp);

	/* Initialize other stuff */
	tswtcl_data = kmem_zalloc(TSWTCL_DATA_SZ, KM_NOSLEEP);
	if (tswtcl_data == NULL) {
		kmem_free(cfg_parms, TSWTCL_CFG_SZ);
		return (ENOMEM);
	}

	if (cfg_parms->stats) {
		if ((rc = tswtcl_statinit(aid, tswtcl_data)) != 0) {
			kmem_free(cfg_parms, TSWTCL_CFG_SZ);
			kmem_free(tswtcl_data, TSWTCL_DATA_SZ);
			return (rc);
		}
	}

	/* set action chain reference */
	if ((rc = ipp_action_ref(aid, cfg_parms->red_action, flags)) != 0) {
		tswtcl0dbg(("tswtcl_create_action: ipp_action_ref " \
		    "returned with error %d", rc));
		goto cleanup;
	}
	if ((rc = ipp_action_ref(aid, cfg_parms->yellow_action, flags)) != 0) {
		tswtcl0dbg(("tswtcl_create_action: ipp_action_ref " \
		    "returned with error %d", rc));
		rc2 = ipp_action_unref(aid, cfg_parms->red_action, flags);
		ASSERT(rc2 == 0);
		goto cleanup;
	}
	if ((rc = ipp_action_ref(aid, cfg_parms->green_action, flags)) != 0) {
		tswtcl0dbg(("tswtcl_create_action: ipp_action_ref " \
		    "returned with error %d", rc));
		rc2 = ipp_action_unref(aid, cfg_parms->red_action, flags);
		ASSERT(rc2 == 0);
		rc2 = ipp_action_unref(aid, cfg_parms->yellow_action, flags);
		ASSERT(rc2 == 0);
		goto cleanup;
	}

	/* Initializations */
	cfg_parms->pminusc = cfg_parms->peak_rate - cfg_parms->committed_rate;
	tswtcl_data->cfg_parms = cfg_parms;
	tswtcl_data->avg_rate = cfg_parms->committed_rate;
	mutex_init(&tswtcl_data->tswtcl_lock, NULL, MUTEX_DEFAULT, 0);
	tswtcl_data->win_front = gethrtime();
	ipp_action_set_ptr(aid, (void *)tswtcl_data);

	return (0);

cleanup:
	if (cfg_parms->stats) {
		ipp_stat_destroy(tswtcl_data->stats);
	}
	kmem_free(cfg_parms, TSWTCL_CFG_SZ);
	kmem_free(tswtcl_data, TSWTCL_DATA_SZ);
	return (rc);

}

static int
tswtcl_modify_action(ipp_action_id_t aid, nvlist_t **nvlpp, ipp_flags_t flags)
{

	nvlist_t *nvlp;
	int err = 0, err2;
	uint8_t config_type;
	char *next_action_name;
	ipp_action_id_t next_action;
	uint32_t rate;
	tswtcl_cfg_t *cfg_parms, *old_cfg;
	tswtcl_data_t *tswtcl_data;
	uint32_t bstats;

	nvlp = *nvlpp;
	*nvlpp = NULL;		/* nvlist should be NULL when this returns */

	if ((err = nvlist_lookup_byte(nvlp, IPP_CONFIG_TYPE, &config_type))
	    != 0) {
		nvlist_free(nvlp);
		tswtcl0dbg(("tswtcl_modify_action:invalid configuration type"));
		return (err);
	}

	if (config_type != IPP_SET) {
		nvlist_free(nvlp);
		tswtcl0dbg(("tswtcl_modify_action:invalid configuration type " \
		    "%d", config_type));
		return (EINVAL);
	}

	tswtcl_data = (tswtcl_data_t *)ipp_action_get_ptr(aid);
	old_cfg = tswtcl_data->cfg_parms;

	cfg_parms = kmem_alloc(TSWTCL_CFG_SZ, KM_NOSLEEP);
	if (cfg_parms == NULL) {
		nvlist_free(nvlp);
		tswtcl0dbg(("tswtcl_modify_action:mem. allocation failure\n"));
		return (ENOMEM);
	}

	/* Just copy all and change as needed */
	bcopy(old_cfg, cfg_parms, TSWTCL_CFG_SZ);

	/* parse red action name, if present */
	if ((err = nvlist_lookup_string(nvlp, TSWTCL_RED_ACTION_NAME,
	    &next_action_name)) == 0) {
		/* Get action id */
		if ((next_action = ipp_action_lookup(next_action_name))
		    == IPP_ACTION_INVAL) {
			nvlist_free(nvlp);
			tswtcl0dbg(("tswtcl_modify_action: red next_action"\
			    " invalid\n"));
			kmem_free(cfg_parms, TSWTCL_CFG_SZ);
			return (EINVAL);
		}
		cfg_parms->red_action = next_action;
	}

	/* parse yellow action name, if present */
	if ((err = nvlist_lookup_string(nvlp, TSWTCL_YELLOW_ACTION_NAME,
	    &next_action_name)) == 0) {
		/* Get action id */
		if ((next_action = ipp_action_lookup(next_action_name))
		    == IPP_ACTION_INVAL) {
			nvlist_free(nvlp);
			tswtcl0dbg(("tswtcl_modify_action: yellow next_action"\
			    "  invalid\n"));
			kmem_free(cfg_parms, TSWTCL_CFG_SZ);
			return (EINVAL);
		}
		cfg_parms->yellow_action = next_action;
	}

	/* parse green action name, if present */
	if ((err = nvlist_lookup_string(nvlp, TSWTCL_GREEN_ACTION_NAME,
	    &next_action_name)) == 0) {
		/* Get action id */
		if ((next_action = ipp_action_lookup(next_action_name))
		    == IPP_ACTION_INVAL) {
			nvlist_free(nvlp);
			tswtcl0dbg(("tswtcl_modify_action: green next_action"\
			    " invalid\n"));
			kmem_free(cfg_parms, TSWTCL_CFG_SZ);
			return (EINVAL);
		}
		cfg_parms->green_action = next_action;
	}

	/* parse committed rate, if present */
	if ((err = nvlist_lookup_uint32(nvlp, TSWTCL_COMMITTED_RATE, &rate))
	    == 0) {
		cfg_parms->committed_rate = rate;
	}

	/* parse peak rate, if present */
	if ((err = nvlist_lookup_uint32(nvlp, TSWTCL_PEAK_RATE, &rate))
	    == 0) {
		cfg_parms->peak_rate = rate;
	}

	if (cfg_parms->peak_rate < cfg_parms->committed_rate) {
		nvlist_free(nvlp);
		tswtcl0dbg(("tswtcl_create_action: invalid config, "\
		    " peak rate < committed rate\n"));
		kmem_free(cfg_parms, TSWTCL_CFG_SZ);
		return (EINVAL);
	}

	/* parse window - in msec */
	if ((err = nvlist_lookup_uint32(nvlp, TSWTCL_WINDOW,
	    &cfg_parms->window)) != 0) {
		cfg_parms->nsecwindow = (uint64_t)cfg_parms->window *
		    METER_MSEC_TO_NSEC;
	}

	/* parse stats, if present */
	if (nvlist_lookup_uint32(nvlp, IPP_ACTION_STATS_ENABLE, &bstats) == 0) {
		cfg_parms->stats = (boolean_t)bstats;
		if (cfg_parms->stats && !old_cfg->stats) {
			if ((err = tswtcl_statinit(aid, tswtcl_data)) != 0) {
				nvlist_free(nvlp);
				kmem_free(cfg_parms, TSWTCL_CFG_SZ);
				return (err);
			}
		} else if (!cfg_parms->stats && old_cfg->stats) {
			ipp_stat_destroy(tswtcl_data->stats);
		}
	}

	/* Can we ref all the new actions? */
	if ((err = ipp_action_ref(aid, cfg_parms->red_action, flags)) != 0) {
		tswtcl0dbg(("tswtcl_modify_data: can't ref. red action\n"));
		nvlist_free(nvlp);
		kmem_free(cfg_parms, TSWTCL_CFG_SZ);
		return (err);
	}

	if ((err = ipp_action_ref(aid, cfg_parms->yellow_action, flags)) != 0) {
		tswtcl0dbg(("tswtcl_modify_data:can't ref. yellow action\n"));
		nvlist_free(nvlp);
		err2 = ipp_action_unref(aid, cfg_parms->red_action, flags);
		ASSERT(err2 == 0);
		kmem_free(cfg_parms, TSWTCL_CFG_SZ);
		return (err);
	}

	if ((err = ipp_action_ref(aid, cfg_parms->green_action, flags)) != 0) {
		tswtcl0dbg(("tswtcl_modify_data:can't ref. green action\n"));
		nvlist_free(nvlp);
		err2 = ipp_action_unref(aid, cfg_parms->red_action, flags);
		ASSERT(err2 == 0);
		err2 = ipp_action_unref(aid, cfg_parms->yellow_action, flags);
		ASSERT(err2 == 0);
		kmem_free(cfg_parms, TSWTCL_CFG_SZ);
		return (err);
	}

	/* Re-compute pminusc */
	cfg_parms->pminusc = cfg_parms->peak_rate - cfg_parms->committed_rate;

	/* Actually modify the configuration */
	mutex_enter(&tswtcl_data->tswtcl_lock);
	tswtcl_data->cfg_parms = cfg_parms;
	mutex_exit(&tswtcl_data->tswtcl_lock);

	/* Un-ref the old actions */
	err = ipp_action_unref(aid, old_cfg->red_action, flags);
	ASSERT(err == 0);
	err = ipp_action_unref(aid, old_cfg->yellow_action, flags);
	ASSERT(err == 0);
	err = ipp_action_unref(aid, old_cfg->green_action, flags);
	ASSERT(err == 0);

	/* Free the old configuration */
	kmem_free(old_cfg, TSWTCL_CFG_SZ);

	nvlist_free(nvlp);

	return (0);
}

static int
tswtcl_destroy_action(ipp_action_id_t aid, ipp_flags_t flags)
{
	tswtcl_data_t *tswtcl_data;
	tswtcl_cfg_t *cfg_parms;
	int rc;

	tswtcl_data = (tswtcl_data_t *)ipp_action_get_ptr(aid);
	ASSERT(tswtcl_data != NULL);

	cfg_parms = tswtcl_data->cfg_parms;

	if (cfg_parms->stats) {
		ipp_stat_destroy(tswtcl_data->stats);
	}

	/* unreference the action */
	rc = ipp_action_unref(aid, cfg_parms->red_action, flags);
	ASSERT(rc == 0);
	rc = ipp_action_unref(aid, cfg_parms->yellow_action, flags);
	ASSERT(rc == 0);
	rc = ipp_action_unref(aid, cfg_parms->green_action, flags);
	ASSERT(rc == 0);

	mutex_destroy(&tswtcl_data->tswtcl_lock);
	kmem_free(cfg_parms, TSWTCL_CFG_SZ);
	kmem_free(tswtcl_data, TSWTCL_DATA_SZ);
	return (0);
}

static int
tswtcl_invoke_action(ipp_action_id_t aid, ipp_packet_t *packet)
{
	tswtcl_data_t *tswtcl_data;
	ipp_action_id_t next_action;
	mblk_t *mp = NULL;
	int rc;

	/* get mblk from ipp_packet structure */
	mp = ipp_packet_get_data(packet);
	tswtcl_data = (tswtcl_data_t *)ipp_action_get_ptr(aid);
	ASSERT(tswtcl_data != NULL);

	/* tswtcl packet as configured */
	if ((rc = tswtcl_process(&mp, tswtcl_data, &next_action)) != 0) {
		return (rc);
	} else {
		return (ipp_packet_next(packet, next_action));
	}
}

static int
tswtcl_statinit(ipp_action_id_t aid, tswtcl_data_t *tswtcl_data)
{
	int rc = 0;
	meter_stat_t *statsp;

	/* install stats entry */
	if ((rc = ipp_stat_create(aid, TSWTCL_STATS_STRING, METER_STATS_COUNT,
	    tswtcl_update_stats, tswtcl_data, &tswtcl_data->stats)) != 0) {
		tswtcl0dbg(("tswtcl_statinit:ipp_stat_create failed "\
		    " with %d\n", rc));
		return (rc);
	}

	statsp = (meter_stat_t *)(tswtcl_data->stats)->ipps_data;
	ASSERT(statsp != NULL);

	if ((rc = ipp_stat_named_init(tswtcl_data->stats, "red_packets",
	    IPP_STAT_UINT64, &statsp->red_packets)) != 0) {
		tswtcl0dbg(("tswtcl_statinit:ipp_stat_create failed "\
		    " with %d\n", rc));
		return (rc);
	}
	if ((rc = ipp_stat_named_init(tswtcl_data->stats, "red_bits",
	    IPP_STAT_UINT64, &statsp->red_bits)) != 0) {
		tswtcl0dbg(("tswtcl_statinit:ipp_stat_create failed "\
		    " with %d\n", rc));
		return (rc);
	}
	if ((rc = ipp_stat_named_init(tswtcl_data->stats, "yellow_packets",
	    IPP_STAT_UINT64, &statsp->yellow_packets)) != 0) {
		tswtcl0dbg(("tswtcl_statinit:ipp_stat_named_init failed "\
		    " with %d\n", rc));
		return (rc);
	}
	if ((rc = ipp_stat_named_init(tswtcl_data->stats, "yellow_bits",
	    IPP_STAT_UINT64, &statsp->yellow_bits)) != 0) {
		tswtcl0dbg(("tswtcl_statinit:ipp_stat_create failed "\
		    " with %d\n", rc));
		return (rc);
	}
	if ((rc = ipp_stat_named_init(tswtcl_data->stats, "green_packets",
	    IPP_STAT_UINT64, &statsp->green_packets)) != 0) {
		tswtcl0dbg(("tswtcl_statinit:ipp_stat_named_init failed "\
		    " with %d\n", rc));
		return (rc);
	}
	if ((rc = ipp_stat_named_init(tswtcl_data->stats, "green_bits",
	    IPP_STAT_UINT64, &statsp->green_bits)) != 0) {
		tswtcl0dbg(("tswtcl_statinit:ipp_stat_create failed "\
		    " with %d\n", rc));
		return (rc);
	}
	if ((rc = ipp_stat_named_init(tswtcl_data->stats, "epackets",
	    IPP_STAT_UINT64, &statsp->epackets)) != 0) {
		tswtcl0dbg(("tswtcl_statinit:ipp_stat_named_init failed "\
		    " with %d\n", rc));
		return (rc);
	}
	ipp_stat_install(tswtcl_data->stats);

	return (rc);

}

static int
tswtcl_update_stats(ipp_stat_t *sp, void *args, int rw)
{
	tswtcl_data_t *tswtcl_data = (tswtcl_data_t *)args;
	meter_stat_t *stats = (meter_stat_t *)sp->ipps_data;

	ASSERT((tswtcl_data != NULL) && (stats != NULL));

	(void) ipp_stat_named_op(&stats->red_packets, &tswtcl_data->red_packets,
	    rw);
	(void) ipp_stat_named_op(&stats->yellow_packets,
	    &tswtcl_data->yellow_packets, rw);
	(void) ipp_stat_named_op(&stats->green_packets,
	    &tswtcl_data->green_packets, rw);

	(void) ipp_stat_named_op(&stats->red_bits, &tswtcl_data->red_bits, rw);
	(void) ipp_stat_named_op(&stats->yellow_bits,
	    &tswtcl_data->yellow_bits, rw);
	(void) ipp_stat_named_op(&stats->green_bits,
	    &tswtcl_data->green_bits, rw);

	(void) ipp_stat_named_op(&stats->epackets, &tswtcl_data->epackets,
	    rw);

	return (0);
}

/* ARGSUSED */
static int
tswtcl_info(ipp_action_id_t aid, int (*fn)(nvlist_t *, void *), void *arg,
    ipp_flags_t flags)
{
	nvlist_t *nvlp;
	tswtcl_data_t *tswtcl_data;
	tswtcl_cfg_t *cfg_parms;
	char *next_action;
	int rc;

	tswtcl_data = (tswtcl_data_t *)ipp_action_get_ptr(aid);
	ASSERT(tswtcl_data != NULL);

	cfg_parms = tswtcl_data->cfg_parms;

	/* allocate nvlist to be passed back */
	if ((rc = nvlist_alloc(&nvlp, NV_UNIQUE_NAME, KM_NOSLEEP)) != 0) {
		tswtcl0dbg(("tswtcl_info: memory allocation failure\n"));
		return (rc);
	}

	/* look up red next action with the next action id */
	if ((rc = ipp_action_name(cfg_parms->red_action, &next_action)) != 0) {
		tswtcl0dbg(("tswtcl_info: red action not available\n"));
		nvlist_free(nvlp);
		return (rc);
	}

	/* add next action name */
	if ((rc = nvlist_add_string(nvlp, TSWTCL_RED_ACTION_NAME,
	    next_action)) != 0) {
		tswtcl0dbg(("tswtcl_info: error adding\n"));
		nvlist_free(nvlp);
		kmem_free(next_action, (strlen(next_action) + 1));
		return (rc);
	}

	/* free action name */
	kmem_free(next_action, (strlen(next_action) + 1));

	/* look up yellow next action with the next action id */
	if ((rc = ipp_action_name(cfg_parms->yellow_action,
	    &next_action)) != 0) {
		tswtcl0dbg(("tswtcl_info: yellow action not available\n"));
		nvlist_free(nvlp);
		return (rc);
	}

	/* add next action name */
	if ((rc = nvlist_add_string(nvlp, TSWTCL_YELLOW_ACTION_NAME,
	    next_action)) != 0) {
		tswtcl0dbg(("tswtcl_info: error adding yellow action\n"));
		nvlist_free(nvlp);
		kmem_free(next_action, (strlen(next_action) + 1));
		return (rc);
	}
	/* free action name */
	kmem_free(next_action, (strlen(next_action) + 1));

	/* look up green next action with the next action id */
	if ((rc = ipp_action_name(cfg_parms->green_action,
	    &next_action)) != 0) {
		tswtcl0dbg(("tswtcl_info: green action not available\n"));
		nvlist_free(nvlp);
		return (rc);
	}

	/* add next action name */
	if ((rc = nvlist_add_string(nvlp, TSWTCL_GREEN_ACTION_NAME,
	    next_action)) != 0) {
		tswtcl0dbg(("tswtcl_info: error adding green action\n"));
		nvlist_free(nvlp);
		kmem_free(next_action, (strlen(next_action) + 1));
		return (rc);
	}

	/* free action name */
	kmem_free(next_action, (strlen(next_action) + 1));

	/* add config type */
	if ((rc = nvlist_add_byte(nvlp, IPP_CONFIG_TYPE, IPP_SET)) != 0) {
		tswtcl0dbg(("tswtcl_info: error adding config_type\n"));
		nvlist_free(nvlp);
		return (rc);
	}

	/* add committed_rate  */
	if ((rc = nvlist_add_uint32(nvlp, TSWTCL_COMMITTED_RATE,
	    cfg_parms->committed_rate)) != 0) {
		tswtcl0dbg(("tswtcl_info: error adding committed_rate\n"));
		nvlist_free(nvlp);
		return (rc);
	}

	/* add peak_rate  */
	if ((rc = nvlist_add_uint32(nvlp, TSWTCL_PEAK_RATE,
	    cfg_parms->peak_rate)) != 0) {
		tswtcl0dbg(("tswtcl_info: error adding peak_rate\n"));
		nvlist_free(nvlp);
		return (rc);
	}

	/* add window  */
	if ((rc = nvlist_add_uint32(nvlp, TSWTCL_WINDOW,
	    cfg_parms->window)) != 0) {
		tswtcl0dbg(("tswtcl_info: error adding window\n"));
		nvlist_free(nvlp);
		return (rc);
	}

	if ((rc = nvlist_add_uint32(nvlp, IPP_ACTION_STATS_ENABLE,
	    (uint32_t)(uintptr_t)tswtcl_data->stats)) != 0) {
		tswtcl0dbg(("tswtcl_info: error adding stats status\n"));
		nvlist_free(nvlp);
		return (rc);
	}

	/* call back with nvlist */
	rc = fn(nvlp, arg);

	nvlist_free(nvlp);
	return (rc);
}
