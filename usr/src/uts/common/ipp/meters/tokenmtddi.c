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

#define	D_SM_COMMENT	"IPP Single-Two Rate Token Meter"

/* DDI file for tokenmt ipp module */

/* Default DSCP to colour mapping for colour-aware meter */
enum meter_colour default_dscp_to_colour[64] = {
	TOKENMT_GREEN, TOKENMT_GREEN, TOKENMT_GREEN, TOKENMT_GREEN,
	TOKENMT_GREEN, TOKENMT_GREEN, TOKENMT_GREEN, TOKENMT_GREEN,
	TOKENMT_GREEN, TOKENMT_GREEN, TOKENMT_GREEN, TOKENMT_GREEN,
	TOKENMT_YELLOW, TOKENMT_GREEN, TOKENMT_RED, TOKENMT_GREEN,
	TOKENMT_GREEN, TOKENMT_GREEN, TOKENMT_GREEN, TOKENMT_GREEN,
	TOKENMT_YELLOW, TOKENMT_GREEN, TOKENMT_RED, TOKENMT_GREEN,
	TOKENMT_GREEN, TOKENMT_GREEN, TOKENMT_GREEN, TOKENMT_GREEN,
	TOKENMT_YELLOW, TOKENMT_GREEN, TOKENMT_RED, TOKENMT_GREEN,
	TOKENMT_GREEN, TOKENMT_GREEN, TOKENMT_GREEN, TOKENMT_GREEN,
	TOKENMT_YELLOW, TOKENMT_GREEN, TOKENMT_RED, TOKENMT_GREEN,
	TOKENMT_GREEN, TOKENMT_GREEN, TOKENMT_GREEN, TOKENMT_GREEN,
	TOKENMT_GREEN, TOKENMT_GREEN, TOKENMT_GREEN, TOKENMT_GREEN,
	TOKENMT_GREEN, TOKENMT_GREEN, TOKENMT_GREEN, TOKENMT_GREEN,
	TOKENMT_GREEN, TOKENMT_GREEN, TOKENMT_GREEN, TOKENMT_GREEN,
	TOKENMT_GREEN, TOKENMT_GREEN, TOKENMT_GREEN, TOKENMT_GREEN,
	TOKENMT_GREEN, TOKENMT_GREEN, TOKENMT_GREEN, TOKENMT_GREEN
};

static int tokenmt_create_action(ipp_action_id_t, nvlist_t **, ipp_flags_t);
static int tokenmt_modify_action(ipp_action_id_t, nvlist_t **, ipp_flags_t);
static int tokenmt_destroy_action(ipp_action_id_t, ipp_flags_t);
static int tokenmt_info(ipp_action_id_t, int (*)(nvlist_t *, void *), void *,
    ipp_flags_t);
static int tokenmt_invoke_action(ipp_action_id_t, ipp_packet_t *);

/* Initialize stats */
static int tokenmt_statinit(ipp_action_id_t, tokenmt_data_t *);

/* Stats callback function */
static int tokenmt_update_stats(ipp_stat_t *, void *, int);

ipp_ops_t tokenmt_ops = {
	IPPO_REV,
	tokenmt_create_action,	/* ippo_action_create */
	tokenmt_modify_action,	/* ippo_action_modify */
	tokenmt_destroy_action,	/* ippo_action_destroy */
	tokenmt_info,		/* ippo_action_info */
	tokenmt_invoke_action	/* ippo_action_invoke */
};

extern struct mod_ops mod_ippops;

/*
 * Module linkage information for the kernel.
 */
static struct modlipp modlipp = {
	&mod_ippops,
	D_SM_COMMENT,
	&tokenmt_ops
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
tokenmt_create_action(ipp_action_id_t aid, nvlist_t **nvlpp, ipp_flags_t flags)
{
	nvlist_t *nvlp;
	tokenmt_data_t *tokenmt_data;
	char *next_action;
	tokenmt_cfg_t *cfg_parms;
	uint32_t mode;
	uint32_t bstats;
	int rc, rc2;
	int32_t *colour_tbl;
	uint_t nelem = 64;

	nvlp = *nvlpp;
	*nvlpp = NULL;		/* nvlist should be NULL on return */

	if ((cfg_parms = kmem_zalloc(TOKENMT_CFG_SZ, KM_NOSLEEP)) == NULL) {
		nvlist_free(nvlp);
		return (ENOMEM);
	}

	/* parse red next action name */
	if ((rc = nvlist_lookup_string(nvlp, TOKENMT_RED_ACTION_NAME,
	    &next_action)) != 0) {
		nvlist_free(nvlp);
		tokenmt0dbg(("tokenmt_create_action:invalid config, red "\
		    "action name missing\n"));
		kmem_free(cfg_parms, TOKENMT_CFG_SZ);
		return (rc);
	}
	if ((cfg_parms->red_action = ipp_action_lookup(next_action))
	    == IPP_ACTION_INVAL) {
		nvlist_free(nvlp);
		tokenmt0dbg(("tokenmt_create_action: red action invalid\n"));
		kmem_free(cfg_parms, TOKENMT_CFG_SZ);
		return (EINVAL);
	}

	/* parse yellow next action name, if present  this is Two Rate meter */
	if ((rc = nvlist_lookup_string(nvlp, TOKENMT_YELLOW_ACTION_NAME,
	    &next_action)) == 0) {
		if ((cfg_parms->yellow_action = ipp_action_lookup(next_action))
		    == IPP_ACTION_INVAL) {
			nvlist_free(nvlp);
			tokenmt0dbg(("tokenmt_create_action: yellow action "\
			    "invalid\n"));
			kmem_free(cfg_parms, TOKENMT_CFG_SZ);
			return (EINVAL);
		}
	} else {
		cfg_parms->yellow_action = TOKENMT_NO_ACTION;
	}

	/* parse green next action name */
	if ((rc = nvlist_lookup_string(nvlp, TOKENMT_GREEN_ACTION_NAME,
	    &next_action)) != 0) {
		nvlist_free(nvlp);
		tokenmt0dbg(("tokenmt_create_action:invalid config, green " \
		    "action name missing\n"));
		kmem_free(cfg_parms, TOKENMT_CFG_SZ);
		return (rc);
	}
	if ((cfg_parms->green_action = ipp_action_lookup(next_action))
	    == IPP_ACTION_INVAL) {
		nvlist_free(nvlp);
		tokenmt0dbg(("tokenmt_create_action: green action invalid\n"));
		kmem_free(cfg_parms, TOKENMT_CFG_SZ);
		return (EINVAL);
	}

	/* parse committed rate  - in kilo bits / sec */
	if ((rc = nvlist_lookup_uint32(nvlp, TOKENMT_COMMITTED_RATE,
	    &cfg_parms->committed_rate)) != 0) {
		nvlist_free(nvlp);
		tokenmt0dbg(("tokenmt_create_action: invalid config, "\
		    " committed rate missing\n"));
		kmem_free(cfg_parms, TOKENMT_CFG_SZ);
		return (rc);
	}
	if (cfg_parms->committed_rate == 0) {
		nvlist_free(nvlp);
		tokenmt0dbg(("tokenmt_create_action: invalid committed rate, "\
		    "%u\n", cfg_parms->committed_rate));
		kmem_free(cfg_parms, TOKENMT_CFG_SZ);
		return (EINVAL);
	}

	/* parse committed burst in bits */
	if ((rc = nvlist_lookup_uint32(nvlp, TOKENMT_COMMITTED_BURST,
	    &cfg_parms->committed_burst)) != 0) {
		nvlist_free(nvlp);
		tokenmt0dbg(("tokenmt_create_action: invalid config, "\
		    " committed burst missing\n"));
		kmem_free(cfg_parms, TOKENMT_CFG_SZ);
		return (rc);
	}


	/*
	 * If the peak burst size is specified, make sure we have the
	 * yellow action.
	 */
	if ((rc = nvlist_lookup_uint32(nvlp, TOKENMT_PEAK_BURST,
	    &cfg_parms->peak_burst)) == 0) {
		if (cfg_parms->yellow_action == TOKENMT_NO_ACTION) {
			nvlist_free(nvlp);
			tokenmt0dbg(("tokenmt_create_action: peak burst "\
			    "specified without yellow action\n"));
			kmem_free(cfg_parms, TOKENMT_CFG_SZ);
			return (EINVAL);
		}
	} else if (cfg_parms->yellow_action != TOKENMT_NO_ACTION) {
		nvlist_free(nvlp);
		tokenmt0dbg(("tokenmt_create_action: peak burst must be "\
		    "provided with yellow action\n"));
		kmem_free(cfg_parms, TOKENMT_CFG_SZ);
		return (EINVAL);
	}

	/* Check if we have a peak_rate */
	if ((rc = nvlist_lookup_uint32(nvlp, TOKENMT_PEAK_RATE,
	    &cfg_parms->peak_rate)) == 0) {
		if (cfg_parms->yellow_action == TOKENMT_NO_ACTION) {
			nvlist_free(nvlp);
			tokenmt0dbg(("tokenmt_create_action: peak rate "\
			    "specified without yellow action\n"));
			kmem_free(cfg_parms, TOKENMT_CFG_SZ);
			return (EINVAL);
		} else if ((cfg_parms->peak_rate == 0) ||
		    (cfg_parms->peak_rate < cfg_parms->committed_rate)) {
			nvlist_free(nvlp);
			tokenmt0dbg(("tokenmt_create_action: invalid "\
			    "peak rate, %u\n", cfg_parms->peak_rate));
			kmem_free(cfg_parms, TOKENMT_CFG_SZ);
			return (EINVAL);
		}
		cfg_parms->tokenmt_type = TRTCL_TOKENMT;
	} else {
		cfg_parms->tokenmt_type = SRTCL_TOKENMT;
	}

	/* Validate the committed and peak burst size */
	if (cfg_parms->tokenmt_type == SRTCL_TOKENMT) {
		if ((cfg_parms->committed_burst == 0) &&
		    (cfg_parms->peak_burst == 0)) {
			nvlist_free(nvlp);
			tokenmt0dbg(("tokenmt_create_action: at least one "\
			    "burst size must be non-zero\n"));
			kmem_free(cfg_parms, TOKENMT_CFG_SZ);
			return (EINVAL);
		}
	} else {	/* TRTCL_TOKENMT */
		if ((cfg_parms->committed_burst == 0) ||
		    (cfg_parms->peak_burst == 0)) {
			nvlist_free(nvlp);
			tokenmt0dbg(("tokenmt_create_action: both the "\
			    "burst sizes must be non-zero\n"));
			kmem_free(cfg_parms, TOKENMT_CFG_SZ);
			return (EINVAL);
		}
	}

	/* just copy default colour mapping */
	bcopy(default_dscp_to_colour, cfg_parms->dscp_to_colour,
	    sizeof (default_dscp_to_colour));

	/* parse mode, if present */
	if ((rc = nvlist_lookup_uint32(nvlp, TOKENMT_COLOUR_AWARE,
	    &mode)) != 0) {
		cfg_parms->colour_aware = B_FALSE;
	} else {
		cfg_parms->colour_aware = (mode == 0) ? B_FALSE : B_TRUE;
	}

	/* Get the dscp to colour mapping array */
	if (cfg_parms->colour_aware) {
		if ((rc = nvlist_lookup_int32_array(nvlp,
		    TOKENMT_COLOUR_MAP, &colour_tbl, &nelem)) == 0) {
			int count;
			for (count = 0; count < 64; count++) {
				if (colour_tbl[count] == -1)
					continue;
				cfg_parms->dscp_to_colour[count] =
				    colour_tbl[count];
			}
		}
	}

	/* parse stats */
	if ((rc = nvlist_lookup_uint32(nvlp, IPP_ACTION_STATS_ENABLE, &bstats))
	    != 0) {
		cfg_parms->stats = B_FALSE;
	} else {
		cfg_parms->stats = (bstats == 0) ? B_FALSE : B_TRUE;
	}

	nvlist_free(nvlp);

	/* Initialize other stuff */
	tokenmt_data = kmem_zalloc(TOKENMT_DATA_SZ, KM_NOSLEEP);
	if (tokenmt_data == NULL) {
		kmem_free(cfg_parms, TOKENMT_CFG_SZ);
		return (ENOMEM);
	}

	/* Initialize stats, if required */
	if (cfg_parms->stats) {
		if ((rc = tokenmt_statinit(aid, tokenmt_data)) != 0) {
			kmem_free(cfg_parms, TOKENMT_CFG_SZ);
			kmem_free(tokenmt_data, TOKENMT_DATA_SZ);
			return (rc);
		}
	}

	/* set action chain reference */
	if ((rc = ipp_action_ref(aid, cfg_parms->red_action, flags)) != 0) {
		tokenmt0dbg(("tokenmt_create_action: ipp_action_ref " \
		    "returned with error %d", rc));
		goto cleanup;
	}
	if ((rc = ipp_action_ref(aid, cfg_parms->green_action, flags)) != 0) {
		tokenmt0dbg(("tokenmt_create_action: ipp_action_ref " \
		    "returned with error %d", rc));
		rc2 = ipp_action_unref(aid, cfg_parms->red_action, flags);
		ASSERT(rc2 == 0);
		goto cleanup;
	}

	if (cfg_parms->yellow_action != TOKENMT_NO_ACTION) {
		if ((rc = ipp_action_ref(aid, cfg_parms->yellow_action,
		    flags)) != 0) {
			tokenmt0dbg(("tokenmt_create_action: ipp_action_ref "\
			    "returned with error %d", rc));
			rc2 = ipp_action_unref(aid, cfg_parms->red_action,
			    flags);
			ASSERT(rc2 == 0);
			rc2 = ipp_action_unref(aid, cfg_parms->green_action,
			    flags);
			ASSERT(rc2 == 0);
			goto cleanup;
		}
	}


	tokenmt_data->cfg_parms = cfg_parms;

	tokenmt_data->committed_tokens = cfg_parms->committed_burst;
	tokenmt_data->peak_tokens = cfg_parms->peak_burst;
	tokenmt_data->last_seen = gethrtime();

	mutex_init(&tokenmt_data->tokenmt_lock, NULL, MUTEX_DEFAULT, 0);
	ipp_action_set_ptr(aid, (void *)tokenmt_data);
	return (0);

cleanup:
	if (cfg_parms->stats) {
		ipp_stat_destroy(tokenmt_data->stats);
	}
	kmem_free(cfg_parms, TOKENMT_CFG_SZ);
	kmem_free(tokenmt_data, TOKENMT_DATA_SZ);
	return (rc);
}

static int
tokenmt_modify_action(ipp_action_id_t aid, nvlist_t **nvlpp, ipp_flags_t flags)
{
	nvlist_t *nvlp;
	int err = 0, err2;
	uint8_t config_type;
	char *next_action_name;
	ipp_action_id_t next_action;
	uint32_t rate, cbs, pbs;
	tokenmt_cfg_t *cfg_parms, *old_cfg;
	tokenmt_data_t *tokenmt_data;
	uint32_t bstats, mode;
	int32_t *colour_tbl;
	uint_t nelem = 64;

	nvlp = *nvlpp;
	*nvlpp = NULL;		/* nvlist should be NULL when this returns */

	if ((err = nvlist_lookup_byte(nvlp, IPP_CONFIG_TYPE, &config_type))
	    != 0) {
		nvlist_free(nvlp);
		tokenmt0dbg(("tokenmt_modify_action: invalid configuration "\
		    "type"));
		return (err);
	}

	if (config_type != IPP_SET) {
		nvlist_free(nvlp);
		tokenmt0dbg(("tokenmt_modify_action: invalid configuration "\
		    "type %d", config_type));
		return (EINVAL);
	}

	tokenmt_data = (tokenmt_data_t *)ipp_action_get_ptr(aid);
	old_cfg = tokenmt_data->cfg_parms;

	cfg_parms = kmem_zalloc(TOKENMT_CFG_SZ, KM_NOSLEEP);
	if (cfg_parms == NULL) {
		nvlist_free(nvlp);
		tokenmt0dbg(("tokenmt_modify_action: memory allocation "\
		    "failure\n"));
		return (ENOMEM);
	}

	/* Just copy all and change as needed */
	bcopy(old_cfg, cfg_parms, TOKENMT_CFG_SZ);

	/* parse red action name, if present */
	if ((err = nvlist_lookup_string(nvlp, TOKENMT_RED_ACTION_NAME,
	    &next_action_name)) == 0) {
		/* Get action id */
		if ((next_action = ipp_action_lookup(next_action_name))
		    == IPP_ACTION_INVAL) {
			nvlist_free(nvlp);
			tokenmt0dbg(("tokenmt_modify_action: next_action "\
			    "invalid"));
			kmem_free(cfg_parms, TOKENMT_CFG_SZ);
			return (EINVAL);
		}
		cfg_parms->red_action = next_action;
	}

	/* parse yellow action name, if present */
	if ((err = nvlist_lookup_string(nvlp, TOKENMT_YELLOW_ACTION_NAME,
	    &next_action_name)) == 0) {
		/* Get action id */
		if ((next_action = ipp_action_lookup(next_action_name))
		    == IPP_ACTION_INVAL) {
			nvlist_free(nvlp);
			tokenmt0dbg(("tokenmt_modify_action: next_action "\
			    "invalid"));
			kmem_free(cfg_parms, TOKENMT_CFG_SZ);
			return (EINVAL);
		}
		cfg_parms->yellow_action = next_action;
	} else {
		cfg_parms->yellow_action = TOKENMT_NO_ACTION;
	}

	/* parse green action name, if present */
	if ((err = nvlist_lookup_string(nvlp, TOKENMT_GREEN_ACTION_NAME,
	    &next_action_name)) == 0) {
		/* Get action id */
		if ((next_action = ipp_action_lookup(next_action_name))
		    == IPP_ACTION_INVAL) {
			nvlist_free(nvlp);
			tokenmt0dbg(("tokenmt_modify_action: next_action "\
			    "invalid"));
			kmem_free(cfg_parms, TOKENMT_CFG_SZ);
			return (EINVAL);
		}
		cfg_parms->green_action = next_action;
	}

	/* parse committed rate, if present */
	if ((err = nvlist_lookup_uint32(nvlp, TOKENMT_COMMITTED_RATE, &rate))
	    == 0) {
		if (rate == 0) {
			nvlist_free(nvlp);
			tokenmt0dbg(("tokenmt_modify_action: invalid "\
			    "committed rate %u\n", cfg_parms->committed_rate));
			kmem_free(cfg_parms, TOKENMT_CFG_SZ);
			return (EINVAL);
		}
		cfg_parms->committed_rate = rate;
	}

	/* parse committed burst, if present */
	if (nvlist_lookup_uint32(nvlp, TOKENMT_COMMITTED_BURST, &cbs) == 0) {
		cfg_parms->committed_burst = cbs;
	}


	if (nvlist_lookup_uint32(nvlp, TOKENMT_PEAK_BURST, &pbs) == 0) {
		cfg_parms->peak_burst = pbs;
	} else {
		cfg_parms->peak_burst = 0;
	}

	/* If the peak rate is not specified, then it means single rate meter */
	if (nvlist_lookup_uint32(nvlp, TOKENMT_PEAK_RATE, &rate) == 0) {
		cfg_parms->peak_rate = rate;
		if ((rate == 0) || (rate < cfg_parms->committed_rate)) {
			nvlist_free(nvlp);
			tokenmt0dbg(("tokenmt_modify_action: invalid "\
			    "committed rate %u\n", cfg_parms->committed_rate));
			kmem_free(cfg_parms, TOKENMT_CFG_SZ);
			return (EINVAL);
		}
		cfg_parms->tokenmt_type = TRTCL_TOKENMT;
	} else {
		cfg_parms->peak_rate = 0;
		cfg_parms->tokenmt_type = SRTCL_TOKENMT;
	}

	if (cfg_parms->yellow_action == TOKENMT_NO_ACTION) {
		if ((cfg_parms->peak_burst != 0) ||
		    (cfg_parms->tokenmt_type == TRTCL_TOKENMT)) {
			nvlist_free(nvlp);
			tokenmt0dbg(("tokenmt_modify_action: yellow action "\
			    "missing\n"));
			kmem_free(cfg_parms, TOKENMT_CFG_SZ);
			return (EINVAL);
		}
	} else {
		if ((cfg_parms->tokenmt_type != TRTCL_TOKENMT) &&
		    (cfg_parms->peak_burst == 0)) {
			nvlist_free(nvlp);
			tokenmt0dbg(("tokenmt_modify_action: peak "\
			    "burst/rate missing\n"));
			kmem_free(cfg_parms, TOKENMT_CFG_SZ);
			return (EINVAL);
		}
	}

	/* Validate the committed and peak burst size */
	if (cfg_parms->tokenmt_type == SRTCL_TOKENMT) {
		if ((cfg_parms->committed_burst == 0) &&
		    (cfg_parms->peak_burst == 0)) {
			nvlist_free(nvlp);
			tokenmt0dbg(("tokenmt_modify_action: at least one "\
			    "burst size must be non-zero\n"));
			kmem_free(cfg_parms, TOKENMT_CFG_SZ);
			return (EINVAL);
		}
	} else {	/* TRTCL_TOKENMT */
		if ((cfg_parms->committed_burst == 0) ||
		    (cfg_parms->peak_burst == 0)) {
			nvlist_free(nvlp);
			tokenmt0dbg(("tokenmt_modify_action: both the "\
			    "burst sizes must be non-zero\n"));
			kmem_free(cfg_parms, TOKENMT_CFG_SZ);
			return (EINVAL);
		}
	}

	/* parse mode */
	if (nvlist_lookup_uint32(nvlp, TOKENMT_COLOUR_AWARE, &mode) == 0) {
		cfg_parms->colour_aware = (mode == 0) ? B_FALSE : B_TRUE;
	} else {
		cfg_parms->colour_aware = B_FALSE;
	}

	if (cfg_parms->colour_aware) {
		if (nvlist_lookup_int32_array(nvlp, TOKENMT_COLOUR_MAP,
		    &colour_tbl, &nelem) == 0) {
			int count;
			for (count = 0; count < 64; count++) {
				if (colour_tbl[count] == -1)
					continue;
				cfg_parms->dscp_to_colour[count] =
				    colour_tbl[count];
			}
		} else {
			bcopy(default_dscp_to_colour, cfg_parms->dscp_to_colour,
			    sizeof (default_dscp_to_colour));
		}
	}

	/* parse stats, if present */
	if (nvlist_lookup_uint32(nvlp, IPP_ACTION_STATS_ENABLE, &bstats) == 0) {
		cfg_parms->stats = (bstats == 0) ? B_FALSE : B_TRUE;
		if (cfg_parms->stats && !old_cfg->stats) {
			if ((err = tokenmt_statinit(aid, tokenmt_data)) != 0) {
				nvlist_free(nvlp);
				kmem_free(cfg_parms, TOKENMT_CFG_SZ);
				return (err);
			}
		} else if (!cfg_parms->stats && old_cfg->stats) {
			ipp_stat_destroy(tokenmt_data->stats);
		}
	}

	/* Can we ref all the new actions? */
	if ((err = ipp_action_ref(aid, cfg_parms->red_action, flags)) != 0) {
		tokenmt0dbg(("tokenmt_modify_data: can't ref. red action\n"));
		kmem_free(cfg_parms, TOKENMT_CFG_SZ);
		return (err);
	}
	if ((err = ipp_action_ref(aid, cfg_parms->green_action, flags)) != 0) {
		tokenmt0dbg(("tokenmt_modify_data:can't ref. green action\n"));
		err2 = ipp_action_unref(aid, cfg_parms->red_action, flags);
		ASSERT(err2 == 0);
		kmem_free(cfg_parms, TOKENMT_CFG_SZ);
		return (err);
	}

	if (cfg_parms->yellow_action != TOKENMT_NO_ACTION) {
		if ((err = ipp_action_ref(aid, cfg_parms->yellow_action,
		    flags)) != 0) {
			tokenmt0dbg(("tokenmt_modify_data:can't ref. yellow "\
			    "action\n"));
			err2 = ipp_action_unref(aid, cfg_parms->red_action,
			    flags);
			ASSERT(err2 == 0);
			err2 = ipp_action_unref(aid, cfg_parms->green_action,
			    flags);
			ASSERT(err2 == 0);
			kmem_free(cfg_parms, TOKENMT_CFG_SZ);
			return (err);
		}
	}


	/* Actually modify the configuration */
	mutex_enter(&tokenmt_data->tokenmt_lock);
	tokenmt_data->cfg_parms = cfg_parms;
	mutex_exit(&tokenmt_data->tokenmt_lock);

	/* Un-ref the old actions */
	err = ipp_action_unref(aid, old_cfg->red_action, flags);
	ASSERT(err == 0);
	if (old_cfg->yellow_action != TOKENMT_NO_ACTION) {
		err = ipp_action_unref(aid, old_cfg->yellow_action, flags);
		ASSERT(err == 0);
	}
	err = ipp_action_unref(aid, old_cfg->green_action, flags);
	ASSERT(err == 0);

	/* Free the old configuration */
	kmem_free(old_cfg, TOKENMT_CFG_SZ);
	return (0);
}

static int
tokenmt_destroy_action(ipp_action_id_t aid, ipp_flags_t flags)
{
	tokenmt_data_t *tokenmt_data;
	tokenmt_cfg_t *cfg_parms;
	int rc;

	tokenmt_data = (tokenmt_data_t *)ipp_action_get_ptr(aid);
	ASSERT(tokenmt_data != NULL);

	cfg_parms = tokenmt_data->cfg_parms;

	if (cfg_parms->stats) {
		ipp_stat_destroy(tokenmt_data->stats);
	}

	/* unreference the action */
	rc = ipp_action_unref(aid, cfg_parms->red_action, flags);
	ASSERT(rc == 0);
	if (cfg_parms->yellow_action != TOKENMT_NO_ACTION) {
		rc = ipp_action_unref(aid, cfg_parms->yellow_action, flags);
		ASSERT(rc == 0);
	}
	rc = ipp_action_unref(aid, cfg_parms->green_action, flags);
	ASSERT(rc == 0);

	mutex_destroy(&tokenmt_data->tokenmt_lock);
	kmem_free(cfg_parms, TOKENMT_CFG_SZ);
	kmem_free(tokenmt_data, TOKENMT_DATA_SZ);
	return (0);
}

static int
tokenmt_invoke_action(ipp_action_id_t aid, ipp_packet_t *packet)
{
	tokenmt_data_t *tokenmt_data;
	ipp_action_id_t next_action;
	mblk_t *mp = NULL;
	int rc;

	/* get mblk from ipp_packet structure */
	mp = ipp_packet_get_data(packet);
	tokenmt_data = (tokenmt_data_t *)ipp_action_get_ptr(aid);
	ASSERT(tokenmt_data != NULL);

	/* meter packet as configured */
	if ((rc = tokenmt_process(&mp, tokenmt_data, &next_action)) != 0) {
		return (rc);
	} else {
		return (ipp_packet_next(packet, next_action));
	}
}

static int
tokenmt_statinit(ipp_action_id_t aid, tokenmt_data_t *tokenmt_data) {

	int rc = 0;
	meter_stat_t *statsp;

	/* install stats entry */
	if ((rc = ipp_stat_create(aid, TOKENMT_STATS_STRING, METER_STATS_COUNT,
	    tokenmt_update_stats, tokenmt_data, &tokenmt_data->stats)) != 0) {
		tokenmt0dbg(("tokenmt_statinit: ipp_stat_create failed "\
		    " with %d\n", rc));
		return (rc);
	}

	statsp = (meter_stat_t *)(tokenmt_data->stats)->ipps_data;
	ASSERT(statsp != NULL);

	if ((rc = ipp_stat_named_init(tokenmt_data->stats, "red_packets",
	    IPP_STAT_UINT64, &statsp->red_packets)) != 0) {
		tokenmt0dbg(("tokenmt_statinit:ipp_stat_named_init failed "\
		    " with %d\n", rc));
		return (rc);
	}
	if ((rc = ipp_stat_named_init(tokenmt_data->stats, "yellow_packets",
	    IPP_STAT_UINT64, &statsp->yellow_packets)) != 0) {
		tokenmt0dbg(("tokenmt_statinit:ipp_stat_named_init failed "\
		    " with %d\n", rc));
		return (rc);
	}
	if ((rc = ipp_stat_named_init(tokenmt_data->stats, "green_packets",
	    IPP_STAT_UINT64, &statsp->green_packets)) != 0) {
		tokenmt0dbg(("tokenmt_statinit:ipp_stat_named_init failed "\
		    " with %d\n", rc));
		return (rc);
	}
	if ((rc = ipp_stat_named_init(tokenmt_data->stats, "red_bits",
	    IPP_STAT_UINT64, &statsp->red_bits)) != 0) {
		tokenmt0dbg(("tokenmt_statinit:ipp_stat_named_init failed "\
		    " with %d\n", rc));
		return (rc);
	}
	if ((rc = ipp_stat_named_init(tokenmt_data->stats, "yellow_bits",
	    IPP_STAT_UINT64, &statsp->yellow_bits)) != 0) {
		tokenmt0dbg(("tokenmt_statinit:ipp_stat_named_init failed "\
		    " with %d\n", rc));
		return (rc);
	}
	if ((rc = ipp_stat_named_init(tokenmt_data->stats, "green_bits",
	    IPP_STAT_UINT64, &statsp->green_bits)) != 0) {
		tokenmt0dbg(("tokenmt_statinit:ipp_stat_named_init failed "\
		    " with %d\n", rc));
		return (rc);
	}
	if ((rc = ipp_stat_named_init(tokenmt_data->stats, "epackets",
	    IPP_STAT_UINT64, &statsp->epackets)) != 0) {
		tokenmt0dbg(("tokenmt_statinit:ipp_stat_named_init failed "\
		    " with %d\n", rc));
		return (rc);
	}

	ipp_stat_install(tokenmt_data->stats);

	return (rc);
}

static int
tokenmt_update_stats(ipp_stat_t *sp, void *args, int rw)
{
	tokenmt_data_t *tokenmt_data = (tokenmt_data_t *)args;
	meter_stat_t *stats = (meter_stat_t *)sp->ipps_data;

	ASSERT((tokenmt_data != NULL) && (stats != NULL));

	(void) ipp_stat_named_op(&stats->red_packets,
	    &tokenmt_data->red_packets, rw);
	(void) ipp_stat_named_op(&stats->yellow_packets,
	    &tokenmt_data->yellow_packets, rw);
	(void) ipp_stat_named_op(&stats->green_packets,
	    &tokenmt_data->green_packets, rw);
	(void) ipp_stat_named_op(&stats->red_bits,
	    &tokenmt_data->red_bits, rw);
	(void) ipp_stat_named_op(&stats->yellow_bits,
	    &tokenmt_data->yellow_bits, rw);
	(void) ipp_stat_named_op(&stats->green_bits,
	    &tokenmt_data->green_bits, rw);
	(void) ipp_stat_named_op(&stats->epackets, &tokenmt_data->epackets,
	    rw);

	return (0);
}

/* ARGSUSED */
static int
tokenmt_info(ipp_action_id_t aid, int (*fn)(nvlist_t *, void *), void *arg,
    ipp_flags_t flags)
{
	nvlist_t *nvlp;
	tokenmt_data_t *tokenmt_data;
	tokenmt_cfg_t *cfg_parms;
	char *next_action;
	int32_t dscp_to_colour[64];
	int rc;

	tokenmt_data = (tokenmt_data_t *)ipp_action_get_ptr(aid);
	ASSERT(tokenmt_data != NULL);

	cfg_parms = tokenmt_data->cfg_parms;

	/* allocate nvlist to be passed back */
	if ((rc = nvlist_alloc(&nvlp, NV_UNIQUE_NAME, KM_NOSLEEP)) != 0) {
		tokenmt0dbg(("tokenmt_info: memory allocation failure\n"));
		return (rc);
	}

	/* look up red next action with the next action id */
	if ((rc = ipp_action_name(cfg_parms->red_action, &next_action)) != 0) {
		tokenmt0dbg(("tokenmt_info: red_action not available\n"));
		nvlist_free(nvlp);
		return (rc);
	}

	/* add next action name */
	if ((rc = nvlist_add_string(nvlp, TOKENMT_RED_ACTION_NAME,
	    next_action)) != 0) {
		nvlist_free(nvlp);
		tokenmt0dbg(("tokenmt_info: error adding red_action\n"));
		kmem_free(next_action, (strlen(next_action) + 1));
		return (rc);
	}

	/* free action name */
	kmem_free(next_action, (strlen(next_action) + 1));


	/* look up yellow next action with the next action id */
	if (cfg_parms->yellow_action != TOKENMT_NO_ACTION) {
		if ((rc = ipp_action_name(cfg_parms->yellow_action,
		    &next_action)) != 0) {
			tokenmt0dbg(("tokenmt_info: yellow_action not "\
			    "available\n"));
			nvlist_free(nvlp);
			return (rc);
		}
		/* add next action name */
		if ((rc = nvlist_add_string(nvlp, TOKENMT_YELLOW_ACTION_NAME,
		    next_action)) != 0) {
			nvlist_free(nvlp);
			tokenmt0dbg(("tokenmt_info: error adding "\
			    "yellow_action\n"));
			kmem_free(next_action, (strlen(next_action) + 1));
			return (rc);
		}
		/* free action name */
		kmem_free(next_action, (strlen(next_action) + 1));
	}

	/* look up green next action with the next action id */
	if ((rc = ipp_action_name(cfg_parms->green_action,
	    &next_action)) != 0) {
		tokenmt0dbg(("tokenmt_info: green_action not available\n"));
		nvlist_free(nvlp);
		return (rc);
	}

	/* add next action name */
	if ((rc = nvlist_add_string(nvlp, TOKENMT_GREEN_ACTION_NAME,
	    next_action)) != 0) {
		nvlist_free(nvlp);
		tokenmt0dbg(("tokenmt_info: error adding green_action\n"));
		kmem_free(next_action, (strlen(next_action) + 1));
		return (rc);
	}

	/* free action name */
	kmem_free(next_action, (strlen(next_action) + 1));

	/* add config type */
	if ((rc = nvlist_add_byte(nvlp, IPP_CONFIG_TYPE, IPP_SET)) != 0) {
		tokenmt0dbg(("tokenmt_info: error adding config_type\n"));
		nvlist_free(nvlp);
		return (rc);
	}

	/* add committed_rate  */
	if ((rc = nvlist_add_uint32(nvlp, TOKENMT_COMMITTED_RATE,
	    cfg_parms->committed_rate)) != 0) {
		tokenmt0dbg(("tokenmt_info: error adding committed_rate\n"));
		nvlist_free(nvlp);
		return (rc);
	}

	if (cfg_parms->tokenmt_type == TRTCL_TOKENMT) {
		/* add peak  rate */
		if ((rc = nvlist_add_uint32(nvlp, TOKENMT_PEAK_RATE,
		    cfg_parms->peak_rate)) != 0) {
			tokenmt0dbg(("tokenmt_info: error adding peak_rate\n"));
			nvlist_free(nvlp);
			return (rc);
		}
	}

	/* add committed_burst  */
	if ((rc = nvlist_add_uint32(nvlp, TOKENMT_COMMITTED_BURST,
	    cfg_parms->committed_burst)) != 0) {
		tokenmt0dbg(("tokenmt_info: error adding committed_burst\n"));
		nvlist_free(nvlp);
		return (rc);
	}

	/* add peak_burst  */
	if (cfg_parms->peak_burst != 0) {
		if ((rc = nvlist_add_uint32(nvlp, TOKENMT_PEAK_BURST,
		    cfg_parms->peak_burst)) != 0) {
			tokenmt0dbg(("tokenmt_info: error adding peak "\
			    "burst\n"));
			nvlist_free(nvlp);
			return (rc);
		}
	}

	/* add colour aware  */
	if ((rc = nvlist_add_uint32(nvlp, TOKENMT_COLOUR_AWARE,
	    cfg_parms->colour_aware)) != 0) {
		tokenmt0dbg(("tokenmt_info: error adding mode\n"));
		nvlist_free(nvlp);
		return (rc);
	}

	if (cfg_parms->colour_aware) {
		bcopy(cfg_parms->dscp_to_colour, dscp_to_colour,
		    sizeof (cfg_parms->dscp_to_colour));
		if ((rc = nvlist_add_int32_array(nvlp, TOKENMT_COLOUR_MAP,
		    dscp_to_colour, 64)) != 0) {
			tokenmt0dbg(("tokenmt_info: error adding colour "\
			    "array\n"));
			nvlist_free(nvlp);
			return (rc);
		}
	}

	if ((rc = nvlist_add_uint32(nvlp, IPP_ACTION_STATS_ENABLE,
	    (uint32_t)cfg_parms->stats)) != 0) {
		tokenmt0dbg(("tokenmt_info: error adding stats status\n"));
		nvlist_free(nvlp);
		return (rc);
	}

	/* call back with nvlist */
	rc = fn(nvlp, arg);

	nvlist_free(nvlp);
	return (rc);
}
