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

#include <stdlib.h>
#include <locale.h>
#include <string.h>
#include "nscd_config.h"
#include "nscd_log.h"
#include "nscd_switch.h"

/*
 * Configuration data for the nscd switch functions.
 */
nscd_cfg_global_switch_t	nscd_switch_cfg_g;
nscd_cfg_switch_t		*nscd_switch_cfg;

/*
 * statistics of the nscd switch functions.
 */
nscd_cfg_stat_global_switch_t	nscd_switch_stats_g;
nscd_cfg_stat_switch_t		*nscd_switch_stats;

/*
 * cookie is set up by the verify function for passing to
 * the notify function
 */
typedef struct {
	struct __nsw_switchconfig_v1	*cfg;
	char				*cfgstr;
} nsw_cfg_cookie_t;

nscd_rc_t
_nscd_alloc_switch_cfg()
{
	nscd_switch_cfg  = calloc(NSCD_NUM_DB, sizeof (nscd_cfg_switch_t));
	if (nscd_switch_cfg == NULL)
		return (NSCD_NO_MEMORY);

	return (NSCD_SUCCESS);
}

nscd_rc_t
_nscd_alloc_switch_stats()
{

	nscd_switch_stats = calloc(NSCD_NUM_DB,
		sizeof (nscd_cfg_stat_switch_t));
	if (nscd_switch_stats == NULL)
		return (NSCD_NO_MEMORY);

	return (NSCD_SUCCESS);
}

/* ARGSUSED */
nscd_rc_t
_nscd_cfg_switch_notify(
	void				*data,
	struct nscd_cfg_param_desc	*pdesc,
	nscd_cfg_id_t			*nswdb,
	nscd_cfg_flag_t			dflag,
	nscd_cfg_error_t		**errorp,
	void				*cookie)
{

	void				*dp;
	nscd_rc_t			rc;
	nsw_cfg_cookie_t		*ck = (nsw_cfg_cookie_t *)cookie;

	if (_nscd_cfg_flag_is_set(dflag, NSCD_CFG_DFLAG_INIT) ||
		_nscd_cfg_flag_is_set(dflag, NSCD_CFG_DFLAG_GROUP)) {
		/*
		 * group data is received, copy in the
		 * entire strcture
		 */
		if (_nscd_cfg_flag_is_set(pdesc->pflag,
			NSCD_CFG_PFLAG_GLOBAL)) {
			nscd_switch_cfg_g = *(nscd_cfg_global_switch_t *)data;
		} else {
			nscd_switch_cfg[nswdb->index] =
				*(nscd_cfg_switch_t *)data;

		}
	} else {
		/*
		 * individual paramater is received: copy in the
		 * parameter value except for nsw-config-string.
		 */
		if (_nscd_cfg_flag_is_set(pdesc->pflag,
			NSCD_CFG_PFLAG_GLOBAL)) {
			dp = (char *)&nscd_switch_cfg_g + pdesc->p_offset;
			(void) memcpy(dp, data, pdesc->p_size);
		} else {
			dp = (char *)&nscd_switch_cfg[nswdb->index] +
				pdesc->p_offset;
			if (pdesc->p_offset !=
				offsetof(nscd_cfg_switch_t, nsw_config_string))
				(void) memcpy(dp, data, pdesc->p_size);
		}
	}

	/*
	 * cookie contains data for the switch policy config
	 */
	if (cookie != NULL) {
		rc = _nscd_create_sw_struct(nswdb->index, -1, nswdb->name,
			ck->cfgstr, ck->cfg, NULL);
		if (rc != NSCD_SUCCESS) {
			(void) __nsw_freeconfig_v1(ck->cfg);
			free(ck);
			return (rc);
		}
		free(ck);
	}

	if (_nscd_cfg_flag_is_not_set(dflag, NSCD_CFG_DFLAG_STATIC_DATA))
		free(data);

	return (NSCD_SUCCESS);
}

/* ARGSUSED */
nscd_rc_t
_nscd_cfg_switch_verify(
	void				*data,
	struct	nscd_cfg_param_desc	*pdesc,
	nscd_cfg_id_t			*nswdb,
	nscd_cfg_flag_t			dflag,
	nscd_cfg_error_t		**errorp,
	void				**cookie)
{
	char				*me = "_nscd_cfg_switch_verify";
	nscd_cfg_switch_t		*cfg;
	char				*nswcfgstr;
	int				size;
	struct __nsw_switchconfig_v1	*switchcfg = NULL;
	enum __nsw_parse_err		err;
	nsw_cfg_cookie_t		*ck;
	char				buf[MAX_NSSWITCH_CONFIG_STRING_SZ];
	char				msg[NSCD_CFG_MAX_ERR_MSG_LEN];

	/*
	 * global config data has nothing special to verify
	 */
	if (_nscd_cfg_flag_is_set(pdesc->pflag, NSCD_CFG_PFLAG_GLOBAL))
		return (NSCD_SUCCESS);

	*cookie = NULL;

	/*
	 * switch policy string is the one to parse and verify
	 */

	if (_nscd_cfg_flag_is_set(dflag, NSCD_CFG_DFLAG_INIT) ||
		_nscd_cfg_flag_is_set(dflag, NSCD_CFG_DFLAG_GROUP)) {

		/* get it from the group data */
		cfg = (nscd_cfg_switch_t *)data;
		nswcfgstr = cfg->nsw_config_string;
	} else {
		/* not group, and not the switch policy string, return */
		if (pdesc->p_offset != offsetof(nscd_cfg_switch_t,
			nsw_config_string))
		return (NSCD_SUCCESS);

		/* the data itself is the string */
		nswcfgstr = (char *)data;
	}

	/*
	 * convert the string into struct __nsw_switchconfig_v1
	 */
	size = MAX_NSSWITCH_CONFIG_STRING_SZ;
	if (strlcpy(buf, nswcfgstr, size) >= size) {

		(void) snprintf(msg, sizeof (msg),
	gettext("switch policy string too long (\"%s : %s\" > %d)"),
			nswdb->name, nswcfgstr, size);

		_NSCD_LOG(NSCD_LOG_CONFIG, NSCD_LOG_LEVEL_ERROR)
		(me, "%s\n", msg);

		if (*errorp)
			*errorp = _nscd_cfg_make_error(
				NSCD_CFG_SYNTAX_ERROR, msg);

		return (NSCD_CFG_SYNTAX_ERROR);
	}
	switchcfg = _nsw_getoneconfig_v1(nswdb->name, buf, &err);
	if (switchcfg == NULL) {

		(void) snprintf(msg, sizeof (msg),
		gettext("syntax error: switch policy string (%s : %s) rc = %d"),
		nswdb->name, nswcfgstr, err);

		_NSCD_LOG(NSCD_LOG_CONFIG, NSCD_LOG_LEVEL_ERROR)
		(me, "%s\n", msg);

		if (*errorp)
			*errorp = _nscd_cfg_make_error(
				NSCD_CFG_SYNTAX_ERROR, msg);

		return (NSCD_CFG_SYNTAX_ERROR);
	}

	/* save the __nsw_switchconfig_v1 for the notify function */
	ck = calloc(1, sizeof (nsw_cfg_cookie_t));
	if (ck == NULL) {
		(void) __nsw_freeconfig_v1(switchcfg);
		return (NSCD_CFG_SYNTAX_ERROR);
	}
	ck->cfg = switchcfg;
	ck->cfgstr = nswcfgstr;
	*cookie = ck;

	return (NSCD_SUCCESS);
}

/* ARGSUSED */
nscd_rc_t
_nscd_cfg_switch_get_stat(
	void				**stat,
	struct nscd_cfg_stat_desc	*sdesc,
	nscd_cfg_id_t			*nswdb,
	nscd_cfg_flag_t			*dflag,
	void				(**free_stat)(void *stat),
	nscd_cfg_error_t		**errorp)
{

	if (_nscd_cfg_flag_is_set(sdesc->sflag, NSCD_CFG_SFLAG_GLOBAL)) {
		*stat = &NSCD_SW_STATS_G;
	} else
		*stat = &NSCD_SW_STATS(nswdb->index);

	/* indicate the statistics are static, i.e., do not free */
	*dflag = _nscd_cfg_flag_set(*dflag, NSCD_CFG_DFLAG_STATIC_DATA);

	return (NSCD_SUCCESS);
}
