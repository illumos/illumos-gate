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
#include <ipp/dlcosmk/dlcosmk_impl.h>

#define	D_SM_COMMENT	"IPP dlcosmk marker module"

/* DDI file for dlcosmk ipp module */

static int dlcosmk_create_action(ipp_action_id_t, nvlist_t **, ipp_flags_t);
static int dlcosmk_modify_action(ipp_action_id_t, nvlist_t **, ipp_flags_t);
static int dlcosmk_destroy_action(ipp_action_id_t, ipp_flags_t);
static int dlcosmk_info(ipp_action_id_t, int (*)(nvlist_t *, void *), void *,
    ipp_flags_t);
static int dlcosmk_invoke_action(ipp_action_id_t, ipp_packet_t *);

static int dlcosmk_statinit(ipp_action_id_t, dlcosmk_data_t *);
static int dlcosmk_update_stats(ipp_stat_t *, void *, int);

/* Entry points for this IPP module */
ipp_ops_t dlcosmk_ops = {
	IPPO_REV,
	dlcosmk_create_action,	/* ippo_action_create */
	dlcosmk_modify_action,	/* ippo_action_modify */
	dlcosmk_destroy_action,	/* ippo_action_destroy */
	dlcosmk_info,		/* ippo_action_info */
	dlcosmk_invoke_action	/* ippo_action_invoke */
};

extern struct mod_ops mod_ippops;

/*
 * Module linkage information for the kernel.
 */
static struct modlipp modlipp = {
	&mod_ippops,
	D_SM_COMMENT,
	&dlcosmk_ops
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
dlcosmk_create_action(ipp_action_id_t aid, nvlist_t **nvlpp,
    ipp_flags_t flags)
{
	nvlist_t *nvlp;
	dlcosmk_data_t *dlcosmk_data;
	char *next_action;
	int err;
	uint32_t bstats, param;

	ASSERT((nvlpp != NULL) && (*nvlpp != NULL));

	nvlp = *nvlpp;
	*nvlpp = NULL;		/* nvlist should be NULL on return */

	if ((dlcosmk_data = kmem_zalloc(DLCOSMK_DATA_SZ, KM_NOSLEEP)) == NULL) {
		nvlist_free(nvlp);
		return (ENOMEM);
	}

	/* parse next action name */
	if ((err = nvlist_lookup_string(nvlp, DLCOSMK_NEXT_ACTION_NAME,
	    &next_action)) != 0) {
		nvlist_free(nvlp);
		dlcosmk0dbg(("dlcosmk_create_action: invalid config, "\
		    "next_action name missing\n"));
		kmem_free(dlcosmk_data, DLCOSMK_DATA_SZ);
		return (err);
	}
	if ((dlcosmk_data->next_action =
	    ipp_action_lookup(next_action)) == IPP_ACTION_INVAL) {
		nvlist_free(nvlp);
		dlcosmk0dbg(("dlcosmk_create_action: next_action invalid\n"));
		kmem_free(dlcosmk_data, DLCOSMK_DATA_SZ);
		return (EINVAL);
	}

	/* parse cos - from the config file */
	if ((err = nvlist_lookup_byte(nvlp, DLCOSMK_COS,
	    &dlcosmk_data->usr_pri)) != 0) {
		nvlist_free(nvlp);
		dlcosmk0dbg(("dlcosmk_create_action: invalid config, "\
		    "cos missing\n"));
		kmem_free(dlcosmk_data, DLCOSMK_DATA_SZ);
		return (err);
	}

	/* parse b_band - mapped from cos */
	if ((err = nvlist_lookup_uint32(nvlp, DLCOSMK_BAND, &param)) != 0) {
		nvlist_free(nvlp);
		dlcosmk0dbg(("dlcosmk_create_action: invalid config, "\
		    "b_band missing\n"));
		kmem_free(dlcosmk_data, DLCOSMK_DATA_SZ);
		return (err);
	}
	dlcosmk_data->b_band = param;

	/* parse dl_priority.dl_max  - mapped from cos */
	if ((err = nvlist_lookup_uint32(nvlp, DLCOSMK_PRI, &param)) != 0) {
		nvlist_free(nvlp);
		dlcosmk0dbg(("dlcosmk_create_action: invalid config, "\
		    "dl_priority missing\n"));
		kmem_free(dlcosmk_data, DLCOSMK_DATA_SZ);
		return (err);
	}
	dlcosmk_data->dl_max = param;

	/* parse gather_stats boolean */
	if ((err = nvlist_lookup_uint32(nvlp, IPP_ACTION_STATS_ENABLE, &bstats))
	    != 0) {
		dlcosmk_data->gather_stats = B_FALSE;
	} else {
		/* If stats is needed, initialize the stats structure */
		dlcosmk_data->gather_stats = (bstats != 0) ? B_TRUE : B_FALSE;
		if (dlcosmk_data->gather_stats) {
			if ((err = dlcosmk_statinit(aid, dlcosmk_data)) != 0) {
				nvlist_free(nvlp);
				kmem_free(dlcosmk_data, DLCOSMK_DATA_SZ);
				return (err);
			}
		}
	}

	/* Free the nvlist */
	nvlist_free(nvlp);

	/* set action chain reference */
	if ((err = ipp_action_ref(aid, dlcosmk_data->next_action,
	    flags)) != 0) {
		dlcosmk0dbg(("dlcosmk_create_action: ipp_action_ref " \
		    "returned with error %d\n", err));
		ipp_stat_destroy(dlcosmk_data->stats);
		kmem_free(dlcosmk_data, DLCOSMK_DATA_SZ);
		return (err);
	}

	ipp_action_set_ptr(aid, (void *)dlcosmk_data);
	return (0);
}

static int
dlcosmk_modify_action(ipp_action_id_t aid, nvlist_t **nvlpp, ipp_flags_t flags)
{
	nvlist_t *nvlp;
	int err = 0;
	uint32_t band, dlpri;
	uint8_t config_type;
	uint8_t cos;
	char *next_action_name;
	ipp_action_id_t next_action;
	dlcosmk_data_t *dlcosmk_data;
	uint32_t bstats;

	ASSERT((nvlpp != NULL) && (*nvlpp != NULL));

	nvlp = *nvlpp;
	*nvlpp = NULL;		/* nvlist should be NULL when this returns */

	if ((err = nvlist_lookup_byte(nvlp, IPP_CONFIG_TYPE, &config_type))
	    != 0) {
		nvlist_free(nvlp);
		dlcosmk0dbg(("dlcosmk_modify_action: invalid configuration "\
		    "type\n"));
		return (err);
	}

	if (config_type != IPP_SET) {
		nvlist_free(nvlp);
		dlcosmk0dbg(("dlcosmk_modify_action: invalid configuration "\
		    "type %d\n", config_type));
		return (EINVAL);
	}

	dlcosmk_data = (dlcosmk_data_t *)ipp_action_get_ptr(aid);
	ASSERT(dlcosmk_data != NULL);

	/* parse next action name, if present */
	if ((err = nvlist_lookup_string(nvlp, DLCOSMK_NEXT_ACTION_NAME,
	    &next_action_name)) == 0) {
		/* lookup action name to get action id */
		if ((next_action = ipp_action_lookup(next_action_name))
		    == IPP_ACTION_INVAL) {
			nvlist_free(nvlp);
			dlcosmk0dbg(("dlcosmk_modify_action: next_action "\
			    "invalid\n"));
			return (EINVAL);
		}
		/* reference new action */
		if ((err = ipp_action_ref(aid, next_action, flags)) != 0) {
			nvlist_free(nvlp);
			dlcosmk0dbg(("dlcosmk_modify_action: ipp_action_ref "\
			    "returned with error %d\n", err));
			return (err);
		}
		/* unref old action */
		err = ipp_action_unref(aid, dlcosmk_data->next_action, flags);
		ASSERT(err == 0);
		dlcosmk_data->next_action = next_action;
	}

	/* parse cos, if present */
	if ((err = nvlist_lookup_byte(nvlp, DLCOSMK_COS, &cos)) == 0) {

		/* parse b_band, mapped from cos */
		if ((err = nvlist_lookup_uint32(nvlp, DLCOSMK_BAND,
		    &band)) != 0) {
			nvlist_free(nvlp);
			dlcosmk0dbg(("dlcosmk_modify_action: b_band not "\
			    "provided\n"));
			return (err);
		}

		/* parse dl_priority, mapped from cos */
		if ((err = nvlist_lookup_uint32(nvlp, DLCOSMK_PRI,
		    &dlpri)) != 0) {
			nvlist_free(nvlp);
			dlcosmk0dbg(("dlcosmk_modify_action: dl_priority not "\
			    "provided\n"));
			return (err);
		}

		/* Have all the three values, change them */
		dlcosmk_data->usr_pri = cos;
		dlcosmk_data->b_band = band;
		dlcosmk_data->dl_max = dlpri;
	}


	/* parse gather_stats boolean, if present */
	if ((err = nvlist_lookup_uint32(nvlp, IPP_ACTION_STATS_ENABLE, &bstats))
	    == 0) {
		boolean_t val = (bstats != 0) ? B_TRUE : B_FALSE;
		/* Turning on stats */
		if (!dlcosmk_data->gather_stats && val) {
			if ((err = dlcosmk_statinit(aid, dlcosmk_data)) != 0) {
				nvlist_free(nvlp);
				return (err);
			}
		/* Turning off stats */
		} else if (!val && dlcosmk_data->gather_stats) {
			ipp_stat_destroy(dlcosmk_data->stats);

		}
		dlcosmk_data->gather_stats = val;
	}

	/* Free thenvlist */
	nvlist_free(nvlp);
	return (0);
}

static int
dlcosmk_destroy_action(ipp_action_id_t aid, ipp_flags_t flags)
{
	dlcosmk_data_t *dlcosmk_data;
	int err;

	dlcosmk_data = (dlcosmk_data_t *)ipp_action_get_ptr(aid);
	ASSERT(dlcosmk_data != NULL);

	/* Destroy stats, if gathered */
	if (dlcosmk_data->gather_stats) {
		ipp_stat_destroy(dlcosmk_data->stats);
	}

	/* unreference the action */
	err = ipp_action_unref(aid, dlcosmk_data->next_action, flags);
	ASSERT(err == 0);

	kmem_free(dlcosmk_data, DLCOSMK_DATA_SZ);
	return (0);
}

static int
dlcosmk_invoke_action(ipp_action_id_t aid, ipp_packet_t *packet)
{
	dlcosmk_data_t *dlcosmk_data;
	mblk_t *mp = NULL;
	int err;
	ip_priv_t *priv;

	ASSERT(packet != NULL);

	/* get mblk from ipp_packet structure */
	mp = ipp_packet_get_data(packet);
	priv = (ip_priv_t *)ipp_packet_get_private(packet);

	dlcosmk_data = (dlcosmk_data_t *)ipp_action_get_ptr(aid);
	ASSERT(dlcosmk_data != NULL);

	/* dlcosmk packet as configured */
	if ((err = dlcosmk_process(&mp, dlcosmk_data, priv->ill_index,
	    priv->proc)) != 0) {
		return (err);
	} else {
		/* return packet with next action set */
		return (ipp_packet_next(packet, dlcosmk_data->next_action));
	}
}

static int
dlcosmk_statinit(ipp_action_id_t aid, dlcosmk_data_t *dlcosmk_data)
{
	int err;
	dlcosmk_stat_t *statp;

	/* install stats entry */
	if ((err = ipp_stat_create(aid, DLCOSMK_STATS_STRING,
	    DLCOSMK_STATS_COUNT, dlcosmk_update_stats, dlcosmk_data,
	    &dlcosmk_data->stats)) != 0) {
		dlcosmk0dbg(("dlcosmk_create_action: ipp_stat_create " \
		    "returned with error %d\n", err));
		return (err);
	}

	statp = (dlcosmk_stat_t *)(dlcosmk_data->stats)->ipps_data;
	ASSERT(statp != NULL);

	if ((err = ipp_stat_named_init(dlcosmk_data->stats, "npackets",
	    IPP_STAT_UINT64, &statp->npackets)) != 0) {
		dlcosmk0dbg(("dlcosmk_create_action: ipp_stat_named_init " \
		    "returned with error %d\n", err));
		return (err);
	}

	if ((err = ipp_stat_named_init(dlcosmk_data->stats, "ipackets",
	    IPP_STAT_UINT64, &statp->ipackets)) != 0) {
		dlcosmk0dbg(("dlcosmk_create_action: ipp_stat_named_init " \
		    "returned with error %d\n", err));
		return (err);
	}

	if ((err = ipp_stat_named_init(dlcosmk_data->stats, "epackets",
	    IPP_STAT_UINT64, &statp->epackets)) != 0) {
		dlcosmk0dbg(("dlcosmk_create_action: ipp_stat_named_init " \
		    "returned with error %d\n", err));
		return (err);
	}

	if ((err = ipp_stat_named_init(dlcosmk_data->stats, "usr_pri",
	    IPP_STAT_INT32, &statp->usr_pri)) != 0) {
		dlcosmk0dbg(("dlcosmk_create_action: ipp_stat_named_init " \
		    "returned with error %d", err));
		return (err);
	}

	if ((err = ipp_stat_named_init(dlcosmk_data->stats, "b_band",
	    IPP_STAT_INT32, &statp->b_band)) != 0) {
		dlcosmk0dbg(("dlcosmk_create_action: ipp_stat_named_init " \
		    "returned with error %d\n", err));
		return (err);
	}

	if ((err = ipp_stat_named_init(dlcosmk_data->stats, "dl_max",
	    IPP_STAT_INT32, &statp->dl_max)) != 0) {
		dlcosmk0dbg(("dlcosmk_create_action: ipp_stat_named_init " \
		    "returned with error %d\n", err));
		return (err);
	}

	ipp_stat_install(dlcosmk_data->stats);
	return (0);
}

static int
dlcosmk_update_stats(ipp_stat_t *sp, void *arg, int rw)
{
	dlcosmk_data_t *dlcosmk_data = (dlcosmk_data_t *)arg;
	dlcosmk_stat_t *snames = (dlcosmk_stat_t *)sp->ipps_data;
	uint32_t upri, bband;

	ASSERT(dlcosmk_data != NULL);
	ASSERT(snames != NULL);

	upri = dlcosmk_data->usr_pri;
	bband = dlcosmk_data->b_band;

	(void) ipp_stat_named_op(&snames->npackets, &dlcosmk_data->npackets,
	    rw);
	(void) ipp_stat_named_op(&snames->ipackets, &dlcosmk_data->ipackets,
	    rw);
	(void) ipp_stat_named_op(&snames->epackets, &dlcosmk_data->epackets,
	    rw);
	(void) ipp_stat_named_op(&snames->usr_pri, &upri, rw);
	(void) ipp_stat_named_op(&snames->b_band, &bband, rw);
	(void) ipp_stat_named_op(&snames->dl_max, &dlcosmk_data->dl_max, rw);

	return (0);
}

/* ARGSUSED */
static int
dlcosmk_info(ipp_action_id_t aid, int (*fn)(nvlist_t *, void *), void *arg,
    ipp_flags_t flags)
{
	nvlist_t *nvlp;
	dlcosmk_data_t *dlcosmk_data;
	char *next_action;
	int err;

	ASSERT(fn != NULL);

	dlcosmk_data = (dlcosmk_data_t *)ipp_action_get_ptr(aid);
	ASSERT(dlcosmk_data != NULL);

	/* allocate nvlist to be passed back */
	if ((err = nvlist_alloc(&nvlp, NV_UNIQUE_NAME, KM_NOSLEEP)) != 0) {
		dlcosmk0dbg(("dlcosmk_info: error allocating memory\n"));
		return (err);
	}

	/* look up next action with the next action id */
	if ((err = ipp_action_name(dlcosmk_data->next_action,
	    &next_action)) != 0) {
		dlcosmk0dbg(("dlcosmk_info: next action not available\n"));
		nvlist_free(nvlp);
		return (err);
	}

	/* add next action name */
	if ((err = nvlist_add_string(nvlp, DLCOSMK_NEXT_ACTION_NAME,
	    next_action)) != 0) {
		dlcosmk0dbg(("dlcosmk_info: error adding next action\n"));
		nvlist_free(nvlp);
		kmem_free(next_action, (strlen(next_action) + 1));
		return (err);
	}

	/* free action name */
	kmem_free(next_action, (strlen(next_action) + 1));

	/* add config type */
	if ((err = nvlist_add_byte(nvlp, IPP_CONFIG_TYPE, IPP_SET)) != 0) {
		dlcosmk0dbg(("dlcosmk_info: error adding config. type\n"));
		nvlist_free(nvlp);
		return (err);
	}

	/* just give the cos, since that is what is provided in the config */
	if ((err = nvlist_add_byte(nvlp, DLCOSMK_COS, dlcosmk_data->usr_pri))
	    != 0) {
		dlcosmk0dbg(("dlcosmk_info: error adding cos\n"));
		nvlist_free(nvlp);
		return (err);
	}

	/* add gather stats boolean */
	if ((err = nvlist_add_uint32(nvlp, IPP_ACTION_STATS_ENABLE,
	    (dlcosmk_data->gather_stats ? 1 : 0))) != 0) {
		dlcosmk0dbg(("dlcosmk_info: error adding stats status\n"));
		nvlist_free(nvlp);
		return (err);
	}

	/* call back with nvlist */
	err = fn(nvlp, arg);

	nvlist_free(nvlp);
	return (err);
}
