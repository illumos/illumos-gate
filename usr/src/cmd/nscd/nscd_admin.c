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
 * Copyright 2012 Milan Jurik. All rights reserved.
 */

#include <stdlib.h>
#include <locale.h>
#include <string.h>
#include "cache.h"
#include "nscd_door.h"
#include "nscd_log.h"
#include "nscd_admin.h"

extern nsc_ctx_t	*cache_ctx_p[];
extern char 		*cache_name[];

static nscd_admin_t	admin_c = { 0 };
static nscd_admin_mod_t	admin_mod = { 0 };
static mutex_t		mod_lock = DEFAULTMUTEX;

/*ARGSUSED*/
int
_nscd_door_getadmin(void *outbuf)
{
	int			i;
	int			data_size = NSCD_N2N_DOOR_BUF_SIZE(admin_c);
	nss_pheader_t		*phdr = (nss_pheader_t *)outbuf;
	nscd_cfg_cache_t	cfg_default = NSCD_CFG_CACHE_DEFAULTS;

	/*
	 * if size of buffer is not big enough, tell the caller to
	 * increase it to the size returned
	 */
	if (phdr->pbufsiz < data_size)
		return (sizeof (admin_c));

	NSCD_SET_STATUS_SUCCESS(phdr);
	phdr->data_off = sizeof (nss_pheader_t);
	phdr->data_len = sizeof (admin_c);

	for (i = 0; i < CACHE_CTX_COUNT; i++) {
		if (cache_ctx_p[i] != NULL) {
			(void) rw_rdlock(&cache_ctx_p[i]->cfg_rwlp);
			admin_c.cache_cfg[i] = cache_ctx_p[i]->cfg;
			(void) rw_unlock(&cache_ctx_p[i]->cfg_rwlp);

			(void) mutex_lock(&cache_ctx_p[i]->stats_mutex);
			admin_c.cache_stats[i] = cache_ctx_p[i]->stats;
			(void) mutex_unlock(&cache_ctx_p[i]->stats_mutex);
		} else {
			admin_c.cache_cfg[i] = cfg_default;
			(void) memset(&admin_c.cache_stats[i], 0,
			    sizeof (admin_c.cache_stats[0]));
		}
	}
	(void) memcpy(((char *)outbuf) + phdr->data_off,
	    &admin_c, sizeof (admin_c));

	return (0);
}

void
_nscd_client_showstats()
{
	(void) printf("nscd configuration:\n\n");
	(void) printf("%10d  server debug level\n", admin_c.debug_level);
	(void) printf("\"%s\"  is server log file\n", admin_c.logfile);

	(void) nsc_info(NULL, NULL, admin_c.cache_cfg, admin_c.cache_stats);
}

/*ARGSUSED*/
nscd_rc_t
_nscd_server_setadmin(nscd_admin_mod_t *set)
{
	nscd_rc_t		rc = NSCD_ADMIN_FAIL_TO_SET;
	nscd_cfg_handle_t	*h;
	int			i, j;
	char			*group = "param-group-cache";
	char			*dbname;
	nscd_cfg_error_t	*err = NULL;
	char			*me = "_nscd_server_setadmin";

	if (set == NULL)
		set = &admin_mod;

	/* one setadmin at a time */
	(void) mutex_lock(&mod_lock);

	_NSCD_LOG_IF(NSCD_LOG_ADMIN, NSCD_LOG_LEVEL_DEBUG) {

		_nscd_logit(me, "total_size = %d\n", set->total_size);

		_nscd_logit(me, "debug_level_set = %d, debug_level = %d\n",
		    set->debug_level_set, set->debug_level);

		_nscd_logit(me, "logfile_set = %d, logfile = %s\n",
		    set->logfile_set, *set->logfile == '\0' ?
		    "" : set->logfile);

		_nscd_logit(me, "cache_cfg_num = %d\n",
		    set->cache_cfg_num);
		_nscd_logit(me, "cache_flush_num = %d\n",
		    set->cache_flush_num);
	}

	/*
	 *  global admin stuff
	 */

	if (set->debug_level_set == nscd_true) {
		if (_nscd_set_debug_level(set->debug_level)
		    != NSCD_SUCCESS) {

			_NSCD_LOG(NSCD_LOG_ADMIN, NSCD_LOG_LEVEL_ERROR)
			(me, "unable to set debug level %d\n",
			    set->debug_level);

			goto err_exit;
		}
		admin_c.debug_level = set->debug_level;
	}

	if (set->logfile_set == nscd_true) {
		if (_nscd_set_log_file(set->logfile) != NSCD_SUCCESS) {

			_NSCD_LOG(NSCD_LOG_ADMIN, NSCD_LOG_LEVEL_ERROR)
			(me, "unable to set log file %s\n", set->logfile);

			goto err_exit;
		}
		(void) strlcpy(admin_c.logfile, set->logfile,
		    NSCD_LOGFILE_LEN);
	}

	/*
	 *  For caches to be changed
	 */
	if (set->cache_cfg_num > CACHE_CTX_COUNT) {

		_NSCD_LOG(NSCD_LOG_ADMIN, NSCD_LOG_LEVEL_ERROR)
		(me, "number of caches (%d) to change out of bound %s\n",
		    set->cache_cfg_num);

		goto err_exit;
	}

	for (i = 0; i < set->cache_cfg_num; i++) {

		nscd_cfg_cache_t *new_cfg;

		j = set->cache_cfg_set[i];
		new_cfg = &set->cache_cfg[i];
		dbname = cache_name[j];
		if (cache_ctx_p[j] == NULL) {
			_NSCD_LOG(NSCD_LOG_ADMIN, NSCD_LOG_LEVEL_ERROR)
			(me, "unable to find cache context for %s\n",
			    dbname);
		}

		rc = _nscd_cfg_get_handle(group, dbname, &h, NULL);
		if (rc != NSCD_SUCCESS) {
			_NSCD_LOG(NSCD_LOG_ADMIN, NSCD_LOG_LEVEL_ERROR)
			(me, "unable to get handle for < %s : %s >\n",
			    dbname, group);

			goto err_exit;
		}

		rc = _nscd_cfg_set(h, new_cfg, &err);
		if (rc != NSCD_SUCCESS) {
			_NSCD_LOG(NSCD_LOG_ADMIN, NSCD_LOG_LEVEL_ERROR)
			(me, "unable to set admin data for < %s : %s >\n",
			    dbname, group);

			_nscd_cfg_free_handle(h);

			goto err_exit;
		}
		_nscd_cfg_free_handle(h);
	}

	/*
	 *  For caches to be flushed
	 */
	if (set->cache_flush_num > CACHE_CTX_COUNT) {

		_NSCD_LOG(NSCD_LOG_ADMIN, NSCD_LOG_LEVEL_ERROR)
		(me, "number of caches (%d) to flush out of bound %s\n",
		    set->cache_flush_num);

		goto err_exit;
	}

	for (i = 0; i < set->cache_flush_num; i++) {
		int j;

		j = set->cache_flush_set[i];

		if (cache_ctx_p[j] == NULL) {
			_NSCD_LOG(NSCD_LOG_ADMIN, NSCD_LOG_LEVEL_ERROR)
			(me, "unable to find cache context for %s\n",
			    dbname);
		}
		nsc_invalidate(cache_ctx_p[j], NULL, NULL);
	}

	rc = NSCD_SUCCESS;
	err_exit:

	(void) mutex_unlock(&mod_lock);
	return (rc);
}


/*ARGSUSED*/
void
_nscd_door_setadmin(void *buf)
{
	nscd_rc_t	rc;
	nss_pheader_t	*phdr = (nss_pheader_t *)buf;
	char		*me = "_nscd_door_setadmin";

	rc = _nscd_server_setadmin(NSCD_N2N_DOOR_DATA(nscd_admin_mod_t, buf));
	if (rc != NSCD_SUCCESS) {
		_NSCD_LOG(NSCD_LOG_ADMIN, NSCD_LOG_LEVEL_ERROR)
		(me, "SETADMIN call failed\n");

		NSCD_SET_N2N_STATUS(phdr, NSS_NSCD_PRIV, 0, rc);
	} else {
		NSCD_SET_STATUS_SUCCESS(phdr);
	}
}

/*
 * for a database 'dbname', add config value 'val' of option 'opt'
 * to the global admin_mod structure
 */
int
_nscd_add_admin_mod(char *dbname, char opt,
	char *val, char *msg, int msglen) {
	int			i, j;
	nscd_cfg_cache_t	*cfg;
	nscd_cfg_group_info_t	gi = NSCD_CFG_GROUP_INFO_CACHE;
	char			dbn[64], *cp;

	/* set initial admin_mod size; assume no cache config to set */
	if (admin_mod.total_size == 0)
		admin_mod.total_size = sizeof (admin_mod) -
			sizeof (admin_mod.cache_cfg);

	/* global admin stuff */
	if (opt == 'l' || opt == 'd') {
		if (opt == 'l') {
			(void) strlcpy(admin_mod.logfile,
				val, NSCD_LOGFILE_LEN);
			admin_mod.logfile_set = nscd_true;
		} else {
			admin_mod.debug_level = atoi(val);
			admin_mod.debug_level_set = nscd_true;
		}
		return (0);
	}

	/* options to be processed next requires cache name */
	(void) strlcpy(dbn, dbname, sizeof (dbn));
	if ((cp = strchr(dbn, ',')) != NULL)
		*cp = '\0';
	i = get_cache_idx(dbn);
	if (i == -1) {
		(void) snprintf(msg, msglen,
			gettext("invalid cache name \"%s\""), dbn);
		return (-1);
	}

	/* flush cache ? */
	if (opt == 'i') {
		admin_mod.cache_flush_set[admin_mod.cache_flush_num++] = i;
		return (0);
	}

	/* options to be processed next requires a param value */
	if (val == NULL) {
		(void) snprintf(msg, msglen,
			gettext("value missing after \"%s\""), dbn);
		return (-1);
	}

	/* try to use an existing cache_cfg in admin_mod */
	for (j = 0; j < admin_mod.cache_cfg_num; j++) {
		if (admin_mod.cache_cfg_set[j] == i)
			break;
	}

	/* no existing one, set up another one */
	if (j == admin_mod.cache_cfg_num) {
		admin_mod.cache_cfg_set[j] = i;
		admin_mod.cache_cfg_num++;
		admin_mod.total_size += sizeof (admin_mod.cache_cfg[0]);
	}

	cfg = &admin_mod.cache_cfg[j];
	cfg->gi.num_param = gi.num_param;

	switch (opt) {

	case 'e':
		/* enable cache */

		_nscd_cfg_bitmap_set_nth(cfg->gi.bitmap, 0);
		if (strcmp(val, "yes") == 0)
		    cfg->enable = nscd_true;
		else if (strcmp(val, "no") == 0)
		    cfg->enable = nscd_false;
		else {
			(void) snprintf(msg, msglen,
	gettext("\"yes\" or \"no\" not specified after \"%s\""), dbn);
			return (-1);
		}
		break;

	case 'c':
		/* check files */

		_nscd_cfg_bitmap_set_nth(cfg->gi.bitmap, 3);
		if (strcmp(val, "yes") == 0)
		    cfg->check_files = nscd_true;
		else if (strcmp(val, "no") == 0)
		    cfg->check_files = nscd_false;
		else {
			(void) snprintf(msg, msglen,
	gettext("\"yes\" or \"no\" not specified after \"%s\""), dbn);
			return (-1);
		}
		break;

	case 'p':
		/* positive time to live */

		_nscd_cfg_bitmap_set_nth(cfg->gi.bitmap, 5);
		cfg->pos_ttl = atoi(val);
		break;

	case 'n':
		/* negative time to live */

		_nscd_cfg_bitmap_set_nth(cfg->gi.bitmap, 6);
		cfg->neg_ttl = atoi(val);
		break;

	case 'h':
		/* keep hot count */

		_nscd_cfg_bitmap_set_nth(cfg->gi.bitmap, 7);
		cfg->keephot = atoi(val);
		break;
	}

	return (0);
}

int
_nscd_client_getadmin(char opt)
{
	int		callnum;
	nss_pheader_t	phdr;

	if (opt == 'G')
		callnum = NSCD_GETPUADMIN;
	else
		callnum = NSCD_GETADMIN;

	(void) _nscd_doorcall_data(callnum, NULL, sizeof (admin_c),
	    &admin_c, sizeof (admin_c), &phdr);

	if (NSCD_STATUS_IS_NOT_OK(&phdr)) {
		return (1);
	}

	return (0);
}

int
_nscd_client_setadmin()
{
	return (_nscd_doorcall_data(NSCD_SETADMIN, &admin_mod,
	    sizeof (admin_mod), NULL, 0, NULL));
}
