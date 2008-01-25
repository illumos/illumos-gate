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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <nss_common.h>
#include <dlfcn.h>
#include <alloca.h>

#include <stdlib.h>
#include <libscf_priv.h>
#include <string.h>
#include <assert.h>
#include "nscd_switch.h"
#include "nscd_log.h"
#include "nscd_db.h"

/*
 * _nscd_nss_finders is used to replace the nss_default_finders in libc
 * to allow nscd to have more control over the dl handles when using
 * dlsym to get the address of the nss backend instance constructors
 */
static nss_backend_constr_t _nscd_per_src_lookup(void *,
	const char *, const char *, void **);
static void _nscd_per_src_delete(void *, nss_backend_constr_t);

static nss_backend_finder_t _nscd_per_src = {
	_nscd_per_src_lookup,
	_nscd_per_src_delete,
	0,
	0 };

nss_backend_finder_t *_nscd_nss_finders = &_nscd_per_src;

/*
 * nscd database for each source. It contains backend
 * info (nscd_be_info_t) for each naming database.
 * Protected by nscd_src_backend_db_lock.
 */
nscd_db_t	***nscd_src_backend_db;
int		*nscd_src_backend_db_loaded;
static		rwlock_t nscd_src_backend_db_lock = DEFAULTRWLOCK;

/*
 * nsswitch config monitored by nscd. Protected by
 * readers/writer lock nscd_nsw_config_lock
 */
nscd_nsw_config_t ***nscd_nsw_config;
static rwlock_t nscd_nsw_config_lock = DEFAULTRWLOCK;

/*
 * nsswitch source index/name array
 * (allow 32 foreign nsswitch sources/backends)
 */
#define		NSCD_NUM_SRC_FOREIGN 32
nscd_cfg_id_t	*_nscd_cfg_nsw_src_all;
int		_nscd_cfg_num_nsw_src_all;

static void
free_nscd_nsw_config(
	nscd_acc_data_t		*data)
{

	nscd_nsw_config_t	*nsw_cfg = *(nscd_nsw_config_t **)data;
	char			*me = "free_nscd_nsw_config";

	_NSCD_LOG(NSCD_LOG_CONFIG, NSCD_LOG_LEVEL_DEBUG)
	(me, "freeing nscd nsw config %p \n", nsw_cfg);
	if (nsw_cfg == NULL)
		return;

	if (nsw_cfg->db_name != NULL)
		free(nsw_cfg->db_name);
	if (nsw_cfg->nsw_cfg_str != NULL)
		free(nsw_cfg->nsw_cfg_str);
	if (nsw_cfg->nsw_config != NULL)
		(void) __nsw_freeconfig_v1(nsw_cfg->nsw_config);
	if (nsw_cfg->src_idx != NULL)
		free(nsw_cfg->src_idx);

	free(nsw_cfg);
}


void
_nscd_free_nsw_config(
	nscd_nsw_config_t *nswcfg)
{
	free_nscd_nsw_config((nscd_acc_data_t *)&nswcfg);
}

void
_nscd_free_all_nsw_config()
{

	nscd_nsw_config_t	**nsw_cfg;
	int			i;
	char			*me = "_nscd_free_all_nsw_config";

	_NSCD_LOG(NSCD_LOG_CONFIG, NSCD_LOG_LEVEL_DEBUG)
	(me, "freeing all nscd nsw config \n");

	(void) rw_wrlock(&nscd_nsw_config_lock);
	for (i = 0; i < NSCD_NUM_DB; i++) {

		if ((nsw_cfg = nscd_nsw_config[i]) == NULL)
			continue;

		nscd_nsw_config[i] = (nscd_nsw_config_t **)_nscd_set(
		    (nscd_acc_data_t *)nsw_cfg, NULL);
	}
	(void) rw_unlock(&nscd_nsw_config_lock);
}


static void
free_nsw_backend_info_db(nscd_acc_data_t *data)
{

	nscd_db_t	*db = *(nscd_db_t **)data;
	char		*me = "free_nsw_backend_info_db";

	_NSCD_LOG(NSCD_LOG_CONFIG, NSCD_LOG_LEVEL_DEBUG)
	(me, "freeing nsw backend info db %p\n", db);

	if (db == NULL)
		return;

	_nscd_free_db(db);

}

void
_nscd_free_all_nsw_backend_info_db()
{

	nscd_db_t	**db;
	int		i;
	char		*me = " _nscd_free_all_nsw_backend_info_db";

	_NSCD_LOG(NSCD_LOG_CONFIG, NSCD_LOG_LEVEL_DEBUG)
	(me, "freeing all nsw backend info db\n");

	(void) rw_wrlock(&nscd_src_backend_db_lock);
	for (i = 0; i < NSCD_NUM_SRC; i++) {

		if ((db = nscd_src_backend_db[i]) == NULL)
			continue;

		nscd_src_backend_db[i] = (nscd_db_t **)_nscd_set(
		    (nscd_acc_data_t *)db, NULL);
		nscd_src_backend_db_loaded[i] = 0;
	}
	(void) rw_unlock(&nscd_src_backend_db_lock);
}

/*
 * Populate the backend info db for the 'NSCD_NSW_SRC_NAME(srci)'
 * source.  Create one entry for each source/database pair
 * (e.g., ldap:passwd, nis:hosts, etc).
 */
static nscd_rc_t
_nscd_populate_nsw_backend_info_db(int srci)
{
	nscd_be_info_t		be_info, *bi;
	nss_backend_finder_t	*bf;
	nscd_nsw_config_t	*nsw_cfg;
	int			i, size;
	nscd_db_entry_t		*db_entry;
	char			*src = NSCD_NSW_SRC_NAME(srci);
	const char		*dbn;
	char			*me = "_nscd_populate_nsw_backend_info_db";
	void			*handle = NULL;
	nss_backend_constr_t	c;
	void			*be_version = &_nscd_be_version;

	/* get the version number of the backend (if available) */
	if (srci >= _nscd_cfg_num_nsw_src) { /* a foreign backend */
		c = _nscd_per_src_lookup(handle, NULL, src, &handle);
		if (c == NULL)
			be_version = NULL;
		else
			be_version = (void *)c;

		_NSCD_LOG(NSCD_LOG_CONFIG, NSCD_LOG_LEVEL_DEBUG)
		(me, "foreign backend: _nss_%s_version = %p ", src, be_version);
	}

	for (i = 0; i < NSCD_NUM_DB; i++) {

		if (nscd_nsw_config[i] == NULL)
			continue;

		nsw_cfg = *nscd_nsw_config[i];
		dbn = NSCD_NSW_DB_NAME(i);
		_NSCD_LOG(NSCD_LOG_CONFIG, NSCD_LOG_LEVEL_DEBUG)
		(me, "adding backend info for <%s : %s>\n", src, dbn);

		(void) memset(&be_info, 0, sizeof (be_info));

		for (bf = nsw_cfg->fe_params.finders;  bf != 0; bf = bf->next) {

			c = (*bf->lookup)(handle, dbn, src, &handle);

			if (c != 0) {
				be_info.be_constr = c;
				be_info.finder = bf;
				be_info.finder_priv = handle;
				be_info.be_version = be_version;
				break;
			}
		}
		if (be_info.be_constr == NULL) {
			/*
			 * Couldn't find the backend anywhere.
			 * This is fine, some backend just don't
			 * support certain databases.
			 */
			_NSCD_LOG(NSCD_LOG_CONFIG, NSCD_LOG_LEVEL_ERROR)
			(me, "unable to find backend info "
			    "for <%s : %s>\n", src, dbn);
		}

		size = sizeof (nscd_be_info_t);

		db_entry = _nscd_alloc_db_entry(NSCD_DATA_BACKEND_INFO,
		    dbn, size, 1, 1);

		if (db_entry == NULL) {
			_NSCD_LOG(NSCD_LOG_CONFIG, NSCD_LOG_LEVEL_ERROR)
			(me, "unable to allocate db entry for "
			    "<%s : %s>\n", src, dbn);
			return (NSCD_NO_MEMORY);
		}

		_NSCD_LOG(NSCD_LOG_CONFIG, NSCD_LOG_LEVEL_DEBUG)
		(me, "adding be db entry %p for <%s : %s> to db %p: "
		    "constr = %p\n", db_entry, src, dbn,
		    *nscd_src_backend_db[srci], be_info.be_constr);

		bi = (nscd_be_info_t *)*(db_entry->data_array);
		*bi = be_info;

		(void) _nscd_wrlock((nscd_acc_data_t *)
		    nscd_src_backend_db[srci]);
		nscd_src_backend_db_loaded[srci] = 1;
		(void) _nscd_add_db_entry(*nscd_src_backend_db[srci],
		    dbn, db_entry, NSCD_ADD_DB_ENTRY_LAST);
		(void) _nscd_rw_unlock((nscd_acc_data_t *)
		    nscd_src_backend_db[srci]);
	}

	return (NSCD_SUCCESS);
}

/*
 * create data structures (used by the switch engine) based
 * on the input switch policy configuration and database
 * name and indexes
 */
nscd_rc_t
_nscd_create_sw_struct(
	int				dbi,
	int				compat_basei,
	const char			*dbn,
	const char			*cfgstr,
	void				*swcfgv1,
	nscd_nsw_params_t		*params)
{
	char				*me = "_nscd_create_sw_struct";
	nscd_rc_t			rc = NSCD_SUCCESS;
	nscd_nsw_config_t		*nsw_cfg = NULL;
	nscd_nsw_config_t		**nsw_cfg_p = NULL;
	struct __nsw_switchconfig_v1	*swcfg = NULL;
	struct __nsw_lookup_v1		*lkp;
	enum __nsw_parse_err		err;
	int				maxsrc;
	int				*src_idx_a = NULL;
	int				j, k;

	/*
	 * if the nsw config string has been parsed into
	 * a struct __nsw_switchconfig_v1, use it. If not,
	 * create the struct.
	 */
	if (swcfgv1 != NULL)
		swcfg = (struct __nsw_switchconfig_v1 *)swcfgv1;
	else {
		char	*cstr;

		cstr = strdup(cfgstr);
		if (cstr == NULL)
			return (NSCD_NO_MEMORY);

		/*
		 * parse the nsw config string and create
		 * a struct __nsw_switchconfig_v1
		 */
		swcfg = _nsw_getoneconfig_v1(dbn, cstr, &err);
		free(cstr);
		if (swcfg == NULL) {
			rc = NSCD_CFG_SYNTAX_ERROR;
			_NSCD_LOG(NSCD_LOG_CONFIG, NSCD_LOG_LEVEL_ERROR)
			(me, "error: unable to process nsw config string\n");
			goto error_exit;
		}
	}

	/* allocate the space for a nscd_nsw_config_t */
	nsw_cfg = calloc(1, sizeof (nscd_nsw_config_t));
	if (nsw_cfg == NULL) {
		rc = NSCD_NO_MEMORY;
		_NSCD_LOG(NSCD_LOG_CONFIG, NSCD_LOG_LEVEL_ERROR)
		(me, "error: unable to allocate an nscd_nsw_config_t\n");
		goto error_exit;
	}

	/* need to know how many backends (sources) */
	maxsrc = swcfg->num_lookups;
	nsw_cfg->max_src = maxsrc;

	/*
	 * allocate an array to store the index for each
	 * backend (source)
	 */
	src_idx_a = calloc(1, maxsrc * sizeof (int));
	if (src_idx_a == NULL) {
		rc = NSCD_NO_MEMORY;
		_NSCD_LOG(NSCD_LOG_CONFIG, NSCD_LOG_LEVEL_ERROR)
		(me, "error: unable to allocate an array for source index\n");
		goto error_exit;
	}

	/*
	 * set the index for each backend (source)
	 */
	lkp = swcfg->lookups;
	for (j = 0; j < maxsrc; j++) {
		char *usrc;

		for (k = 0; k < NSCD_NUM_SRC && NSCD_NSW_SRC_NAME(k) != NULL &&
		    strcmp(lkp->service_name, NSCD_NSW_SRC_NAME(k)) != 0;
		    k++) {
			/* empty */
		}

		if (k < NSCD_NUM_SRC && nscd_src_backend_db_loaded[k] == 0) {
			_NSCD_LOG(NSCD_LOG_CONFIG, NSCD_LOG_LEVEL_DEBUG)
			(me, "unknown nsw source name %s\n", lkp->service_name);
			usrc = strdup(lkp->service_name);
			if (usrc == NULL) {
				rc = NSCD_NO_MEMORY;
				_NSCD_LOG(NSCD_LOG_CONFIG, NSCD_LOG_LEVEL_ERROR)
				(me, "unable to strdup() source name\n");
				goto error_exit;
			}
			NSCD_NSW_SRC_NAME(k) = usrc;

			rc = _nscd_populate_nsw_backend_info_db(k);
			if (rc != NSCD_SUCCESS) {
				free(usrc);
				NSCD_NSW_SRC_NAME(k) = NULL;
				goto error_exit;
			}
		} else if (NSCD_NSW_SRC_NAME(k) == NULL) {
			/*
			 * number of user-defined source exceeded
			 */
			rc = NSCD_CFG_SYNTAX_ERROR;
			_NSCD_LOG(NSCD_LOG_CONFIG, NSCD_LOG_LEVEL_ERROR)
			(me, "error: number of user_defined source exceeded\n");

			goto error_exit;
		}

		_NSCD_LOG(NSCD_LOG_CONFIG, NSCD_LOG_LEVEL_DEBUG)
		(me, "setting source index array [%d] = %d (%s)\n",
		    j, k, lkp->service_name);

		src_idx_a[j] = k;

		lkp = lkp->next;
		if (lkp == NULL) break;

		_NSCD_LOG(NSCD_LOG_CONFIG, NSCD_LOG_LEVEL_DEBUG)
		(me, "number of nsw sources = %d\n", nsw_cfg->max_src);
		_NSCD_LOG(NSCD_LOG_CONFIG, NSCD_LOG_LEVEL_DEBUG)
		(me, "next nsw source is %s\n", lkp->service_name);
	}

	/* set it up to reference count the switch policy config */
	nsw_cfg_p = (nscd_nsw_config_t **)_nscd_alloc(NSCD_DATA_NSW_CONFIG,
	    sizeof (nscd_nsw_config_t **), free_nscd_nsw_config,
	    NSCD_ALLOC_RWLOCK);

	if (nsw_cfg_p == NULL) {
		rc = NSCD_NO_MEMORY;
		_NSCD_LOG(NSCD_LOG_CONFIG, NSCD_LOG_LEVEL_ERROR)
		(me, "unable to allocate a new nsw config DB\n");
		goto error_exit;
	}
	*nsw_cfg_p = nsw_cfg;

	_NSCD_LOG(NSCD_LOG_CONFIG, NSCD_LOG_LEVEL_DEBUG)
	(me, "new nsw config DB %p allocated\n", nsw_cfg_p);

	/* save all the data in the new nscd_nsw_config_t */
	nsw_cfg->db_name = strdup(dbn);
	nsw_cfg->nsw_cfg_str = strdup(cfgstr);
	if (nsw_cfg->db_name == NULL || nsw_cfg->nsw_cfg_str == NULL) {
		rc = NSCD_NO_MEMORY;
		goto error_exit;
	}

	_NSCD_LOG(NSCD_LOG_CONFIG, NSCD_LOG_LEVEL_DEBUG)
	(me, "switch policy \"%s\" for database is \"%s\"\n",
	    nsw_cfg->db_name, nsw_cfg->nsw_cfg_str);

	nsw_cfg->nsw_config = swcfg;
	nsw_cfg->src_idx = src_idx_a;

	/*
	 * set default frontend params and if necessary call initf()
	 * to initialize or override
	 */
	nsw_cfg->fe_params.max_active_per_src = 10;
	nsw_cfg->fe_params.max_dormant_per_src = 1;
	nsw_cfg->fe_params.finders = _nscd_nss_finders;
	if (params != NULL) {
		nsw_cfg->fe_params = params->p;

		if (params->p.flags & NSS_USE_DEFAULT_CONFIG) {
			params->nswcfg = nsw_cfg_p;
			/*
			 * this nsw_cfg is not meant to last long, no need
			 * to set up the nsw state and getent bases, just
			 * exit with NSCD_SUCCESS
			 */
			nsw_cfg->nobase = 1;
			goto error_exit;
		}
	} else
		(void) (nscd_nss_db_initf[dbi])(&nsw_cfg->fe_params);

	/*
	 * activate the new nscd_nsw_config_t, the old one
	 * will either be deleted or left on the side (and be
	 * deleted eventually)
	 */
	nscd_nsw_config[dbi] = (nscd_nsw_config_t **)_nscd_set(
	    (nscd_acc_data_t *)nscd_nsw_config[dbi],
	    (nscd_acc_data_t *)nsw_cfg_p);

	/*
	 * also create a new nsw state base
	 */
	if ((rc = _nscd_init_nsw_state_base(dbi, compat_basei, 1)) !=
	    NSCD_SUCCESS) {
		_NSCD_LOG(NSCD_LOG_CONFIG, NSCD_LOG_LEVEL_ERROR)
		(me, "unable to initialize a nsw state base(%d)\n", dbi);
		goto error_exit;
	}

	_NSCD_LOG(NSCD_LOG_CONFIG, NSCD_LOG_LEVEL_DEBUG)
	(me, "new nsw state base(%d) %p created\n", dbi,
	    nscd_nsw_state_base[dbi]);

	/*
	 * also create a new getent context base
	 */
	if ((rc = _nscd_init_getent_ctx_base(dbi, 1)) != NSCD_SUCCESS) {
		_NSCD_LOG(NSCD_LOG_CONFIG, NSCD_LOG_LEVEL_ERROR)
		(me, "unable to initialize a getent context base(%d)\n", dbi);
		goto error_exit;
	}

	_NSCD_LOG(NSCD_LOG_CONFIG, NSCD_LOG_LEVEL_DEBUG)
	(me, "new getent context base(%d) %p created\n", dbi,
	    nscd_getent_ctx_base[dbi]);

	_NSCD_LOG(NSCD_LOG_CONFIG, NSCD_LOG_LEVEL_DEBUG)
	(me, "new nsw config created (database = %s, "
	"config = %s)\n", dbn, cfgstr);


	error_exit:

	if (rc != NSCD_SUCCESS) {

		if (swcfgv1 == NULL && swcfg != NULL)
			(void) __nsw_freeconfig_v1(swcfg);
		if (src_idx_a != NULL)
			free(src_idx_a);
		if (nsw_cfg_p)
			free(nsw_cfg_p);
		if (nsw_cfg != NULL) {
			if (nsw_cfg->db_name != NULL)
				free(nsw_cfg->db_name);
			if (nsw_cfg->nsw_cfg_str != NULL)
				free(nsw_cfg->nsw_cfg_str);
			free(nsw_cfg);
		}

		return (rc);
	} else
		return (NSCD_SUCCESS);
}

static nscd_rc_t
create_nsw_config(int dbi)
{

	nscd_nsw_config_t	*nsw_cfg = NULL;
	nscd_nsw_config_t	**nsw_cfg_p = NULL;
	char			*me = "create_nsw_config";

	/*
	 * if pseudo-databases (initf function not defined),
	 * don't bother now
	 */
	if (nscd_nss_db_initf[dbi] == NULL)
		return (NSCD_SUCCESS);

	/* allocate the space for a nscd_nsw_config_t */
	nsw_cfg = calloc(1, sizeof (nscd_nsw_config_t));
	if (nsw_cfg == NULL) {
		_NSCD_LOG(NSCD_LOG_CONFIG, NSCD_LOG_LEVEL_ERROR)
		(me, "unable to allocate a nsw config structure\n");
		return (NSCD_NO_MEMORY);
	}
	_NSCD_LOG(NSCD_LOG_CONFIG, NSCD_LOG_LEVEL_DEBUG)
	(me, "nsw config structure %pallocated\n", nsw_cfg);

	nsw_cfg_p = (nscd_nsw_config_t **)_nscd_alloc(NSCD_DATA_NSW_CONFIG,
	    sizeof (nscd_nsw_config_t **), free_nscd_nsw_config,
	    NSCD_ALLOC_RWLOCK);

	if (nsw_cfg_p == NULL) {
		_NSCD_LOG(NSCD_LOG_CONFIG, NSCD_LOG_LEVEL_ERROR)
		(me, "unable to allocate a pointer to nsw config structure\n");
		return (NSCD_NO_MEMORY);
	}
	_NSCD_LOG(NSCD_LOG_CONFIG, NSCD_LOG_LEVEL_DEBUG)
		(me, "nsw config pointer = %p\n", nsw_cfg_p);

	nsw_cfg->db_name = strdup(NSCD_NSW_DB_NAME(dbi));
	if (nsw_cfg->db_name == NULL) {
		_NSCD_LOG(NSCD_LOG_CONFIG, NSCD_LOG_LEVEL_ERROR)
		(me, "unable to strdup the db name\n");
		return (NSCD_NO_MEMORY);
	}

	/*
	 * set default frontend params and then call initf()
	 * to initialize or override
	 */
	nsw_cfg->fe_params.max_active_per_src = 10;
	nsw_cfg->fe_params.max_dormant_per_src = 1;
	nsw_cfg->fe_params.finders = _nscd_nss_finders;
	(void) (nscd_nss_db_initf[dbi])(&nsw_cfg->fe_params);

	/*
	 * activate the new nscd_nsw_config_t
	 */
	*nsw_cfg_p = nsw_cfg;
	nscd_nsw_config[dbi] = (nscd_nsw_config_t **)_nscd_set(
	    (nscd_acc_data_t *)nscd_nsw_config[dbi],
	    (nscd_acc_data_t *)nsw_cfg_p);

	_NSCD_LOG(NSCD_LOG_CONFIG, NSCD_LOG_LEVEL_DEBUG)
	(me, "nsw config %p activated\n", nsw_cfg);

	return (NSCD_SUCCESS);
}

nscd_rc_t
_nscd_init_all_nsw_config(void)
{
	nscd_rc_t	rc;
	int		i;
	char		*me = "_nscd_init_all_nsw_config";

	_NSCD_LOG(NSCD_LOG_CONFIG, NSCD_LOG_LEVEL_DEBUG)
	(me, "initializing all nsw config\n");

	for (i = 0; i < NSCD_NUM_DB; i++) {
		if ((rc = create_nsw_config(i)) != NSCD_SUCCESS)
			return (rc);
	}

	return (NSCD_SUCCESS);
}

static nscd_rc_t
init_nsw_be_info_db(int srci)
{
	nscd_db_t	*ret, **db_p;
	char		*me = "init_nsw_be_info_db";

	ret = _nscd_alloc_db(NSCD_DB_SIZE_SMALL);

	if (ret == NULL) {
		_NSCD_LOG(NSCD_LOG_CONFIG, NSCD_LOG_LEVEL_ERROR)
		(me, "unable to allocate a nsw be info database\n");
		return (NSCD_NO_MEMORY);
	}

	/* set up to reference count the backend info db */
	db_p = (nscd_db_t **)_nscd_alloc(NSCD_DATA_BACKEND_INFO_DB,
	    sizeof (nscd_db_t **), free_nsw_backend_info_db,
	    NSCD_ALLOC_RWLOCK);

	if (db_p == NULL) {
		_NSCD_LOG(NSCD_LOG_CONFIG, NSCD_LOG_LEVEL_ERROR)
		(me, "unable to allocate the pointer to the nsw "
		"be info database\n");
		return (NSCD_NO_MEMORY);
	}

	*db_p = ret;
	_NSCD_LOG(NSCD_LOG_CONFIG, NSCD_LOG_LEVEL_DEBUG)
	(me, "backend database (db_p = %p, db = %p)\n", db_p, *db_p);

	nscd_src_backend_db[srci] = (nscd_db_t **)_nscd_set(
	    (nscd_acc_data_t *)nscd_src_backend_db[srci],
	    (nscd_acc_data_t *)db_p);

	return (NSCD_SUCCESS);
}

nscd_rc_t
_nscd_init_all_nsw_be_info_db(void)
{

	int		i;
	nscd_rc_t	rc;
	char		*me = "_nscd_init_all_nsw_be_info_db";

	_NSCD_LOG(NSCD_LOG_CONFIG, NSCD_LOG_LEVEL_DEBUG)
	(me, "initializing all nsw be info databases\n");

	for (i = 0; i < NSCD_NUM_SRC; i++) {
		if ((rc = init_nsw_be_info_db(i)) != NSCD_SUCCESS)
			return (rc);
	}

	return (NSCD_SUCCESS);
}


nscd_rc_t
_nscd_alloc_nsw_config()
{
	nscd_nsw_config = calloc(NSCD_NUM_DB, sizeof (nscd_nsw_config_t **));
	if (nscd_nsw_config == NULL)
		return (NSCD_NO_MEMORY);

	return (NSCD_SUCCESS);
}

nscd_rc_t
_nscd_alloc_nsw_be_info_db()
{
	int	i;

	_nscd_cfg_num_nsw_src_all = _nscd_cfg_num_nsw_src +
	    NSCD_NUM_SRC_FOREIGN;
	nscd_src_backend_db = calloc(NSCD_NUM_SRC, sizeof (nscd_db_t **));
	if (nscd_src_backend_db == NULL)
		return (NSCD_NO_MEMORY);
	nscd_src_backend_db_loaded = calloc(NSCD_NUM_SRC, sizeof (int));
	if (nscd_src_backend_db_loaded == NULL) {
		free(nscd_src_backend_db);
		return (NSCD_NO_MEMORY);
	}

	/* also allocate/init the nsswitch source index/name array */
	_nscd_cfg_nsw_src_all = (nscd_cfg_id_t *)calloc(
	    _nscd_cfg_num_nsw_src_all + 1, sizeof (nscd_cfg_id_t));
	for (i = 0; i < _nscd_cfg_num_nsw_src_all + 1; i++)
		(_nscd_cfg_nsw_src_all + i)->index = -1;

	(void) memcpy(_nscd_cfg_nsw_src_all, _nscd_cfg_nsw_src,
	    _nscd_cfg_num_nsw_src * sizeof (nscd_cfg_id_t));
	return (NSCD_SUCCESS);
}

nscd_rc_t
_nscd_populate_nsw_backend_info()
{
	int		i;
	nscd_rc_t	rc;

	for (i = 0; i < NSCD_NUM_SRC; i++) {
		if (NSCD_NSW_SRC_NAME(i) == NULL)
			continue;
		rc = _nscd_populate_nsw_backend_info_db(i);
		if (rc != NSCD_SUCCESS)
		return (rc);
	}

	return (NSCD_SUCCESS);
}

/*
 * The following defines nscd's own lookup and delete functions
 * that are to be stored in nss_backend_finder_t which is used
 * by _nscd_populate_nsw_backend_info_db() to initialize the
 * various nss backend instances
 */

static const int  dlopen_version  = 1;
#ifndef NSS_DLOPEN_FORMAT
#define	NSS_DLOPEN_FORMAT "nss_%s.so.%d"
#endif
#ifndef NSS_DLSYM_FORMAT
#define	NSS_DLSYM_FORMAT   "_nss_%s_%s_constr"
#define	NSS_DLSYM_FORMAT_V "_nss_%s_version"
#endif
static const char dlopen_format[] = NSS_DLOPEN_FORMAT;
static const char dlsym_format [] = NSS_DLSYM_FORMAT;
static const char dlsym_format_v [] = NSS_DLSYM_FORMAT_V;
static const size_t  format_maxlen   = sizeof (dlsym_format);

/*ARGSUSED*/
static nss_backend_constr_t
_nscd_per_src_lookup(void *handle, const char *db_name, const char *src_name,
	void **delete_privp)
{
	char			*name;
	void			*dlhandle;
	void			*sym;
	size_t			len;
	nss_backend_constr_t	res = NULL;

	len = format_maxlen + strlen(src_name);
	if (db_name != NULL)
		len += strlen(db_name);
	name = alloca(len);
	dlhandle = handle;
	if ((dlhandle = handle) == NULL) {
		(void) sprintf(name, dlopen_format, src_name, dlopen_version);
		dlhandle = dlopen(name, RTLD_LAZY);
	}

	if (dlhandle != NULL) {
		if (db_name != NULL)
			(void) sprintf(name, dlsym_format, src_name, db_name);
		else
			(void) sprintf(name, dlsym_format_v, src_name);
		if ((sym = dlsym(dlhandle, name)) == 0) {
			if (handle == NULL)
				(void) dlclose(dlhandle);
		} else {
			*delete_privp = dlhandle;
			res = (nss_backend_constr_t)sym;
		}
	}
	return (res);
}

/*ARGSUSED*/
static void
_nscd_per_src_delete(void *delete_priv, nss_backend_constr_t dummy)
{
	(void) dlclose(delete_priv);
}
