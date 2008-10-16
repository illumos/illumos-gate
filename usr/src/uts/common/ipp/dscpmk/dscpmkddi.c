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
#include <sys/systm.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/modctl.h>
#include <sys/sunddi.h>
#include <ipp/ipp.h>
#include <ipp/ipp_config.h>
#include <inet/common.h>
#include <ipp/dscpmk/dscpmk_impl.h>

#define	D_SM_COMMENT	"IPP dscpmk marker module"

/* DDI file for dscpmk ipp module */

/* default dscp map - dscp unchanged */
uint8_t default_dscp_map[DSCPMK_ARRAY_COUNT] = {
	0,	1,	2,	3,
	4,	5,	6,	7,
	8,	9,	10,	11,
	12,	13,	14,	15,
	16,	17,	18,	19,
	20,	21,	22,	23,
	24,	25,	26,	27,
	28,	29,	30,	31,
	32,	33,	34,	35,
	36,	37,	38,	39,
	40,	41,	42,	43,
	44,	45,	46,	47,
	48,	49,	50,	51,
	52,	53,	54,	55,
	56,	57,	58,	59,
	60,	61,	62,	63
};

static int dscpmk_create_action(ipp_action_id_t, nvlist_t **, ipp_flags_t);
static int dscpmk_modify_action(ipp_action_id_t, nvlist_t **, ipp_flags_t);
static int dscpmk_destroy_action(ipp_action_id_t, ipp_flags_t);
static int dscpmk_info(ipp_action_id_t, int (*)(nvlist_t *, void *), void *,
    ipp_flags_t);
static int dscpmk_invoke_action(ipp_action_id_t, ipp_packet_t *);

/* Creating and updating summary stats */
static int dscpmk_summ_statinit(ipp_action_id_t, dscpmk_data_t *);
static int dscpmk_update_stats(ipp_stat_t *, void *, int);

/* Creating and updating per-dscp stats */
static int dscpmk_det_statinit(ipp_action_id_t, dscpmk_data_t *, int);
static int dscpmk_update_det_stats(ipp_stat_t *, void *, int);

/* Entry points for this IPP module */
ipp_ops_t dscpmk_ops = {
	IPPO_REV,
	dscpmk_create_action,	/* ippo_action_create */
	dscpmk_modify_action,	/* ippo_action_modify */
	dscpmk_destroy_action,	/* ippo_action_destroy */
	dscpmk_info,		/* ippo_action_info */
	dscpmk_invoke_action	/* ippo_action_invoke */
};

extern struct mod_ops mod_ippops;

/*
 * Module linkage information for the kernel.
 */
static struct modlipp modlipp = {
	&mod_ippops,
	D_SM_COMMENT,
	&dscpmk_ops
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

static int
dscpmk_create_action(ipp_action_id_t aid, nvlist_t **nvlpp, ipp_flags_t flags)
{
	nvlist_t *nvlp;
	dscpmk_data_t *dscpmk_data;
	char *next_action;
	int err, cnt;
	int32_t *tbl;
	uint_t nelem = DSCPMK_ARRAY_COUNT;
	uint32_t bstats;

	ASSERT((nvlpp != NULL) && (*nvlpp != NULL));

	nvlp = *nvlpp;
	*nvlpp = NULL;		/* nvlist should be NULL on return */

	if ((dscpmk_data = kmem_zalloc(DSCPMK_DATA_SZ, KM_NOSLEEP)) == NULL) {
		nvlist_free(nvlp);
		return (ENOMEM);
	}

	/* parse next action name */
	if ((err = nvlist_lookup_string(nvlp, DSCPMK_NEXT_ACTION_NAME,
	    &next_action)) != 0) {
		nvlist_free(nvlp);
		dscpmk0dbg(("dscpmk_create_action: invalid config, " \
		    "next_action name missing\n"));
		kmem_free(dscpmk_data, DSCPMK_DATA_SZ);
		return (err);
	}

	if ((dscpmk_data->next_action = ipp_action_lookup(next_action))
	    == IPP_ACTION_INVAL) {
		nvlist_free(nvlp);
		dscpmk0dbg(("dscpmk_create_action: next_action "\
		    "invalid\n"));
		kmem_free(dscpmk_data, DSCPMK_DATA_SZ);
		return (EINVAL);
	}

	/* Fill in the default value */
	bcopy(default_dscp_map, dscpmk_data->dscp_map,
	    sizeof (default_dscp_map));
	/*
	 * parse dscp_map, if present. Note that the module gets
	 * the entire array with unchanged entries marked with -1.
	 */
	if ((err = nvlist_lookup_int32_array(nvlp, DSCPMK_DSCP_MAP,
	    &tbl, &nelem)) == 0) {
		for (cnt = 0; cnt < DSCPMK_ARRAY_COUNT; cnt++) {
			if ((tbl[cnt] != DSCPMK_UNCHANGED_DSCP) && (tbl[cnt] !=
			    dscpmk_data->dscp_map[cnt])) {
				dscpmk_data->dscp_map[cnt] = tbl[cnt];
			}
		}
	}


	/* parse summary_stats boolean */
	if ((err = nvlist_lookup_uint32(nvlp, IPP_ACTION_STATS_ENABLE, &bstats))
	    != 0) {
		dscpmk_data->summary_stats = B_FALSE;
	} else {
		dscpmk_data->summary_stats = (bstats != 0) ? B_TRUE : B_FALSE;
		/* If stats is needed, initialize the stats structure */
		if (dscpmk_data->summary_stats) {
			if ((err = dscpmk_summ_statinit(aid, dscpmk_data))
			    != 0) {
				nvlist_free(nvlp);
				kmem_free(dscpmk_data, DSCPMK_DATA_SZ);
				return (err);
			}
		}
	}

	/*
	 * Initialize per-dscp stats; B_FALSE in present indicates a dscp
	 * with this value (count) is not present in the map.
	 */
	for (cnt = 0; cnt < DSCPMK_ARRAY_COUNT; cnt++) {
		dscpmk_data->dscp_stats[cnt].present = B_FALSE;
		dscpmk_data->dscp_stats[cnt].npackets = 0;
	}

	/* parse detailed_stats boolean */
	if ((err = nvlist_lookup_uint32(nvlp, DSCPMK_DETAILED_STATS, &bstats))
	    != 0) {
		dscpmk_data->detailed_stats = B_FALSE;
	} else {
		dscpmk_data->detailed_stats = (bstats != 0) ? B_TRUE : B_FALSE;
		/* If stats is needed, initialize the stats structure */
		if (dscpmk_data->detailed_stats) {
			for (cnt = 0; cnt < DSCPMK_ARRAY_COUNT; cnt++) {
				int val = dscpmk_data->dscp_map[cnt];
				if (dscpmk_data->dscp_stats[val].present) {
					continue;
				}
				dscpmk_data->dscp_stats[val].present = B_TRUE;
				if ((err = dscpmk_det_statinit(aid, dscpmk_data,
				    val)) != 0) {
					nvlist_free(nvlp);
					kmem_free(dscpmk_data, DSCPMK_DATA_SZ);
					return (err);
				}
			}
		}
	}

	/* Free the nvlist */
	nvlist_free(nvlp);

	/* set action chain reference */
	if ((err = ipp_action_ref(aid, dscpmk_data->next_action, flags)) != 0) {
		dscpmk0dbg(("dscpmk_create_action: ipp_action_ref " \
		    "returned with error %d\n", err));
		if (dscpmk_data->summary_stats) {
			ipp_stat_destroy(dscpmk_data->stats);
		}
		if (dscpmk_data->detailed_stats) {
			for (cnt = 0; cnt < DSCPMK_ARRAY_COUNT; cnt++) {
				if (dscpmk_data->dscp_stats[cnt].present) {
					ipp_stat_destroy(
					    dscpmk_data->dscp_stats[cnt].stats);
				}
			}
		}
		kmem_free(dscpmk_data, DSCPMK_DATA_SZ);
		return (err);
	}

	ipp_action_set_ptr(aid, (void *)dscpmk_data);
	return (0);
}

static int
dscpmk_modify_action(ipp_action_id_t aid, nvlist_t **nvlpp, ipp_flags_t flags)
{
	nvlist_t *nvlp;
	int err = 0, cnt;
	uint8_t config_type;
	char *next_action_name;
	uint32_t bstats;
	uint_t nelem = DSCPMK_ARRAY_COUNT;
	int32_t *tbl;
	ipp_action_id_t next_action;
	dscpmk_data_t *dscpmk_data;

	ASSERT((nvlpp != NULL) && (*nvlpp != NULL));

	nvlp = *nvlpp;
	*nvlpp = NULL;		/* nvlist should be NULL when this returns */

	if ((err = nvlist_lookup_byte(nvlp, IPP_CONFIG_TYPE, &config_type))
	    != 0) {
		nvlist_free(nvlp);
		dscpmk0dbg(("dscpmk_modify_action: invalid cfg. type\n"));
		return (err);
	}

	if (config_type != IPP_SET) {
		nvlist_free(nvlp);
		dscpmk0dbg(("dscpmk_modify_action: invalid cfg. type " \
		    "%d\n", config_type));
		return (EINVAL);
	}

	dscpmk_data = (dscpmk_data_t *)ipp_action_get_ptr(aid);
	ASSERT(dscpmk_data != NULL);

	/* parse next action name, if present */
	if ((err = nvlist_lookup_string(nvlp, DSCPMK_NEXT_ACTION_NAME,
	    &next_action_name)) == 0) {
		/* lookup action name to get action id */
		if ((next_action = ipp_action_lookup(next_action_name))
		    == IPP_ACTION_INVAL) {
			nvlist_free(nvlp);
			dscpmk0dbg(("dscpmk_modify_action: next_action "\
			    "invalid\n"));
			return (EINVAL);
		}
		/* reference new action */
		if ((err = ipp_action_ref(aid, next_action, flags)) != 0) {
			nvlist_free(nvlp);
			dscpmk0dbg(("dscpmk_modify_action: ipp_action_ref " \
			    "returned with error %d\n", err));
			return (err);
		}
		/* unref old action */
		err = ipp_action_unref(aid, dscpmk_data->next_action, flags);
		ASSERT(err == 0);
		dscpmk_data->next_action = next_action;
	}

	/*
	 * parse dscp_map, if present. Note that the module gets
	 * the entire array with unchanged entries marked with -1.
	 * If this array is absent during modification, it means revert to
	 * the default table.
	 */
	if ((err = nvlist_lookup_int32_array(nvlp, DSCPMK_DSCP_MAP,
	    &tbl, &nelem)) == 0) {
		for (cnt = 0; cnt < DSCPMK_ARRAY_COUNT; cnt++) {
			if ((tbl[cnt] != DSCPMK_UNCHANGED_DSCP) && (tbl[cnt] !=
			    dscpmk_data->dscp_map[cnt])) {
				dscpmk_data->dscp_map[cnt] = tbl[cnt];
			}
		}
	} else {
		bcopy(default_dscp_map, dscpmk_data->dscp_map,
		    sizeof (default_dscp_map));
	}

	/* parse summary_stats boolean, if present */
	if ((err = nvlist_lookup_uint32(nvlp, IPP_ACTION_STATS_ENABLE, &bstats))
	    == 0) {
		boolean_t val = (bstats != 0) ? B_TRUE : B_FALSE;
		/* Turning on stats */
		if (!dscpmk_data->summary_stats && val) {
			if ((err = dscpmk_summ_statinit(aid, dscpmk_data))
			    != 0) {
				nvlist_free(nvlp);
				return (err);
			}
		/* Turning off stats */
		} else if (!val && dscpmk_data->summary_stats) {
			ipp_stat_destroy(dscpmk_data->stats);

		}
		dscpmk_data->summary_stats = val;
	}

	/* parse detailed_stats boolean */
	if ((err = nvlist_lookup_uint32(nvlp, DSCPMK_DETAILED_STATS, &bstats))
	    == 0) {
		boolean_t val = (bstats != 0) ? B_TRUE : B_FALSE;
		if (dscpmk_data->detailed_stats && !val) {
			for (cnt = 0; cnt < DSCPMK_ARRAY_COUNT; cnt++) {
				if (dscpmk_data->dscp_stats[cnt].present) {
					dscpmk_data->dscp_stats[cnt].present =
					    B_FALSE;
					ipp_stat_destroy(dscpmk_data->
					    dscp_stats[cnt].stats);
				}
			}
		}
		dscpmk_data->detailed_stats = val;
	}

	/* The map might have changed */
	if (dscpmk_data->detailed_stats) {
		for (cnt = 0; cnt < DSCPMK_ARRAY_COUNT; cnt++) {
			int val = dscpmk_data->dscp_map[cnt];
			if (!dscpmk_data->dscp_stats[val].present) {
				dscpmk_data->dscp_stats[val].present = B_TRUE;
				if ((err = dscpmk_det_statinit(aid, dscpmk_data,
				    val)) != 0) {
					nvlist_free(nvlp);
					return (err);
				}
			}
		}
	}

	/* Free the nvlist */
	nvlist_free(nvlp);
	return (0);
}

static int
dscpmk_destroy_action(ipp_action_id_t aid, ipp_flags_t flags)
{
	dscpmk_data_t *dscpmk_data;
	int err, cnt;

	dscpmk_data = (dscpmk_data_t *)ipp_action_get_ptr(aid);
	ASSERT(dscpmk_data != NULL);

	/* Destroy stats, if gathered */
	if (dscpmk_data->summary_stats) {
		ipp_stat_destroy(dscpmk_data->stats);
	}

	if (dscpmk_data->detailed_stats) {
		for (cnt = 0; cnt < DSCPMK_ARRAY_COUNT; cnt++) {
			if (dscpmk_data->dscp_stats[cnt].present) {
				ipp_stat_destroy(dscpmk_data->dscp_stats[cnt].
				    stats);
			}
		}
	}

	/* unreference the action */
	err = ipp_action_unref(aid, dscpmk_data->next_action, flags);
	ASSERT(err == 0);

	kmem_free(dscpmk_data, DSCPMK_DATA_SZ);
	return (0);
}

static int
dscpmk_invoke_action(ipp_action_id_t aid, ipp_packet_t *packet)
{
	dscpmk_data_t *dscpmk_data;
	mblk_t *mp = NULL;
	ip_priv_t *priv;
	int err;

	ASSERT(packet != NULL);

	/* get mblk from ipp_packet structure */
	mp = ipp_packet_get_data(packet);
	priv = (ip_priv_t *)ipp_packet_get_private(packet);

	dscpmk_data = (dscpmk_data_t *)ipp_action_get_ptr(aid);
	ASSERT(dscpmk_data != NULL);

	/* dscpmk packet as configured */
	if ((err = dscpmk_process(&mp, dscpmk_data, priv->proc)) != 0) {
		return (err);
	} else {
		/* return packet with next action set */
		return (ipp_packet_next(packet, dscpmk_data->next_action));
	}
}

static int
dscpmk_det_statinit(ipp_action_id_t aid, dscpmk_data_t *dscpmk_data, int val)
{
	int err = 0;
	dscpmk_dscp_stats_t *statp;
	char stats_string[15];

	(void) sprintf(stats_string, "dscpmk_dscp0x%x", val);

	/* install stats entry */
	if ((err = ipp_stat_create(aid, stats_string, DSCPMK_DSCP_STATS_COUNT,
	    dscpmk_update_det_stats, dscpmk_data,
	    &dscpmk_data->dscp_stats[val].stats)) != 0) {
		dscpmk0dbg(("dscpmk_det_statinit: ipp_stat_create returned "\
		    "with error %d\n", err));
		return (err);
	}

	statp = (dscpmk_dscp_stats_t *)
	    (dscpmk_data->dscp_stats[val].stats)->ipps_data;
	ASSERT(statp != NULL);

	if ((err = ipp_stat_named_init(dscpmk_data->dscp_stats[val].stats,
	    "dscp", IPP_STAT_UINT32, &statp->dscp)) != 0) {
		dscpmk0dbg(("dscpmk_det_statinit: ipp_stat_named_init "\
		    "returned with error %d\n", err));
		return (err);
	}

	if ((err = ipp_stat_named_init(dscpmk_data->dscp_stats[val].stats,
	    "npackets", IPP_STAT_UINT64, &statp->npackets)) != 0) {
		dscpmk0dbg(("dscpmk_det_statinit: ipp_stat_named_init "\
		    "returned with error %d\n", err));
		return (err);
	}

	ipp_stat_install(dscpmk_data->dscp_stats[val].stats);
	return (0);
}


static int
dscpmk_summ_statinit(ipp_action_id_t aid, dscpmk_data_t *dscpmk_data)
{
	int err = 0;
	dscpmk_stat_t *statp;

	/* install stats entry */
	if ((err = ipp_stat_create(aid, DSCPMK_STATS_STRING, DSCPMK_STATS_COUNT,
	    dscpmk_update_stats, dscpmk_data, &dscpmk_data->stats)) != 0) {
		dscpmk0dbg(("dscpmk_create_action: ipp_stat_create returned " \
		    "with error %d\n", err));
		return (err);
	}

	statp = (dscpmk_stat_t *)(dscpmk_data->stats)->ipps_data;
	ASSERT(statp != NULL);

	if ((err = ipp_stat_named_init(dscpmk_data->stats, "npackets",
	    IPP_STAT_UINT64, &statp->npackets)) != 0) {
		dscpmk0dbg(("dscpmk_summ_statinit: ipp_stat_named_init " \
		    "returned with error %d\n", err));
		return (err);
	}

	if ((err = ipp_stat_named_init(dscpmk_data->stats, "dscp_changed",
	    IPP_STAT_UINT64, &statp->dscp_changed)) != 0) {
		dscpmk0dbg(("dscpmk_summ_statinit: ipp_stat_named_init " \
		    "returned with error %d\n", err));
		return (err);
	}

	if ((err = ipp_stat_named_init(dscpmk_data->stats, "dscp_unchanged",
	    IPP_STAT_UINT64, &statp->dscp_unchanged)) != 0) {
		dscpmk0dbg(("dscpmk_summ_statinit: ipp_stat_named_init " \
		    "returned with error %d\n", err));
		return (err);
	}

	if ((err = ipp_stat_named_init(dscpmk_data->stats, "ipackets",
	    IPP_STAT_UINT64, &statp->ipackets)) != 0) {
		dscpmk0dbg(("dscpmk_summ_statinit: ipp_stat_named_init " \
		    "returned with error %d\n", err));
		return (err);
	}

	if ((err = ipp_stat_named_init(dscpmk_data->stats, "epackets",
	    IPP_STAT_UINT64, &statp->epackets)) != 0) {
		dscpmk0dbg(("dscpmk_summ_statinit: ipp_stat_named_init " \
		    "returned with error %d\n", err));
		return (err);
	}

	ipp_stat_install(dscpmk_data->stats);
	return (0);
}

/* ARGSUSED */
static int
dscpmk_update_det_stats(ipp_stat_t *sp, void *arg, int rw)
{
	dscpmk_data_t *dscpmk_data = (dscpmk_data_t *)arg;
	dscpmk_dscp_stats_t *statp;
	uint32_t count;

	for (count = 0; count < DSCPMK_ARRAY_COUNT; count++) {
		if (!dscpmk_data->dscp_stats[count].present)
			continue;
		statp = (dscpmk_dscp_stats_t *)
		    (dscpmk_data->dscp_stats[count].stats)->ipps_data;
		ASSERT(statp != NULL);
		(void) ipp_stat_named_op(&statp->npackets,
		    &dscpmk_data->dscp_stats[count].npackets, rw);
		(void) ipp_stat_named_op(&statp->dscp, &count, rw);
	}
	return (0);
}

static int
dscpmk_update_stats(ipp_stat_t *sp, void *arg, int rw)
{
	dscpmk_data_t *dscpmk_data = (dscpmk_data_t *)arg;
	dscpmk_stat_t *snames = (dscpmk_stat_t *)sp->ipps_data;
	ASSERT(dscpmk_data != NULL);
	ASSERT(snames != NULL);

	(void) ipp_stat_named_op(&snames->npackets, &dscpmk_data->npackets, rw);
	(void) ipp_stat_named_op(&snames->dscp_changed, &dscpmk_data->changed,
	    rw);
	(void) ipp_stat_named_op(&snames->dscp_unchanged,
	    &dscpmk_data->unchanged, rw);
	(void) ipp_stat_named_op(&snames->ipackets, &dscpmk_data->ipackets, rw);
	(void) ipp_stat_named_op(&snames->epackets, &dscpmk_data->epackets, rw);

	return (0);
}

/* ARGSUSED */
static int
dscpmk_info(ipp_action_id_t aid, int (*fn)(nvlist_t *, void *), void *arg,
    ipp_flags_t flags)
{
	nvlist_t *nvlp;
	dscpmk_data_t *dscpmk_data;
	char *next_action;
	int err, cnt;
	int32_t dscp_map[DSCPMK_ARRAY_COUNT];

	ASSERT(fn != NULL);

	dscpmk_data = (dscpmk_data_t *)ipp_action_get_ptr(aid);
	ASSERT(dscpmk_data != NULL);

	/* allocate nvlist to be passed back */
	if ((err = nvlist_alloc(&nvlp, NV_UNIQUE_NAME, KM_NOSLEEP)) != 0) {
		dscpmk0dbg(("dscpmk_info: error allocating memory\n"));
		return (err);
	}

	/* look up next action with the next action id */
	if ((err = ipp_action_name(dscpmk_data->next_action,
	    &next_action)) != 0) {
		dscpmk0dbg(("dscpmk_info: next action not available\n"));
		nvlist_free(nvlp);
		return (err);
	}

	/* add next action name */
	if ((err = nvlist_add_string(nvlp, DSCPMK_NEXT_ACTION_NAME,
	    next_action)) != 0) {
		dscpmk0dbg(("dscpmk_info: error adding next action\n"));
		nvlist_free(nvlp);
		kmem_free(next_action, (strlen(next_action) + 1));
		return (err);
	}

	/* free action name */
	kmem_free(next_action, (strlen(next_action) + 1));

	/* add config type */
	if ((err = nvlist_add_byte(nvlp, IPP_CONFIG_TYPE, IPP_SET)) != 0) {
		dscpmk0dbg(("dscpmk_info: error adding config type\n"));
		nvlist_free(nvlp);
		return (err);
	}

	/* add dscp map */
	bcopy(dscpmk_data->dscp_map, dscp_map, sizeof (dscp_map));
	for (cnt = 0; cnt < DSCPMK_ARRAY_COUNT; cnt++) {
		dscp_map[cnt] = dscpmk_data->dscp_map[cnt];
	}
	if ((err = nvlist_add_int32_array(nvlp, DSCPMK_DSCP_MAP,
	    dscp_map, DSCPMK_ARRAY_COUNT)) != 0) {
		dscpmk0dbg(("dscpmk_info: error adding dscp map\n"));
		nvlist_free(nvlp);
		return (err);
	}

	/* add summary stats boolean */
	if ((err = nvlist_add_uint32(nvlp, IPP_ACTION_STATS_ENABLE,
	    (dscpmk_data->summary_stats ? 1 : 0))) != 0) {
		dscpmk0dbg(("dscpmk_info: error adding stats status\n"));
		nvlist_free(nvlp);
		return (err);
	}

	/* add detailed stats boolean */
	if ((err = nvlist_add_uint32(nvlp, DSCPMK_DETAILED_STATS,
	    (dscpmk_data->detailed_stats ? 1 : 0))) != 0) {
		dscpmk0dbg(("dscpmk_info: error adding det stats status\n"));
		nvlist_free(nvlp);
		return (err);
	}

	/* call back with nvlist */
	err = fn(nvlp, arg);

	nvlist_free(nvlp);
	return (err);
}
