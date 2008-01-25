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

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include "nscd_switch.h"
#include "nscd_log.h"

/*
 * nscd_nsw_state_t list for each nss database. Protected
 * by the readers/writer lock nscd_nsw_state_base_lock.
 */
nscd_nsw_state_base_t **nscd_nsw_state_base;
static rwlock_t nscd_nsw_state_base_lock = DEFAULTRWLOCK;

static void
_nscd_free_nsw_state(
	nscd_nsw_state_t	*s)
{

	int			i;
	char			*me = "_nscd_free_nsw_state";

	_NSCD_LOG(NSCD_LOG_NSW_STATE, NSCD_LOG_LEVEL_DEBUG)
	(me, "freeing nsw state = %p\n", s);

	if (s == NULL)
		return;

	if (s->nsw_cfg_p != NULL)
		/*
		 * an nsw state without base does not reference
		 * count the nsw config data (ie not using a
		 * shared one), so the one created for it should
		 * be freed
		 */
		if ((*s->nsw_cfg_p)->nobase != 1)
			_nscd_release((nscd_acc_data_t *)s->nsw_cfg_p);
		else
			(void) _nscd_set((nscd_acc_data_t *)s->nsw_cfg_p, NULL);

	if (s->be_db_pp != NULL) {
		for (i = 0; i < s->max_src; i++) {
			if (s->be_db_pp[i] == NULL)
				continue;
			_nscd_release((nscd_acc_data_t *)s->be_db_pp[i]);
			_NSCD_LOG(NSCD_LOG_NSW_STATE, NSCD_LOG_LEVEL_DEBUG)
			(me, "release db be ptr %p\n", s->be_db_pp[i]);
		}
		free(s->be_db_pp);
	}

	if (s->be != NULL) {
		for (i = 0; i < s->max_src; i++) {
			if (s->be[i] == NULL)
				continue;
			if (s->getent == 1)
				(void) NSS_INVOKE_DBOP(s->be[i],
				    NSS_DBOP_ENDENT, 0);
			(void) NSS_INVOKE_DBOP(s->be[i],
			    NSS_DBOP_DESTRUCTOR, 0);
		}
		free(s->be);
	}

	if (s->be_constr != NULL)
		free(s->be_constr);

	if (s->be_version_p != NULL)
		free(s->be_version_p);

	s->base = NULL;

	_NSCD_LOG(NSCD_LOG_NSW_STATE, NSCD_LOG_LEVEL_DEBUG)
	(me, "nsw state %p freed \n", s);

	free(s);
}

static void
_nscd_free_nsw_state_base(
	nscd_acc_data_t		*data)
{
	nscd_nsw_state_base_t	*base = (nscd_nsw_state_base_t *)data;
	nscd_nsw_state_t	*s, *ts;
	int			i;
	char			*me = "_nscd_free_nsw_state_base";

	_NSCD_LOG(NSCD_LOG_NSW_STATE | NSCD_LOG_CONFIG, NSCD_LOG_LEVEL_DEBUG)
	(me, "freeing db state base %p\n", base);

	if (base == NULL)
		return;

	for (i = 0; i < 2; i++) {
		if (i == 1)
			s = base->nsw_state.first;
		else
			s = base->nsw_state_thr.first;

		while (s != NULL) {
			ts = s->next;
			_nscd_free_nsw_state(s);
			s = ts;
		}
	}

	_NSCD_LOG(NSCD_LOG_NSW_STATE | NSCD_LOG_CONFIG, NSCD_LOG_LEVEL_DEBUG)
	(me, "nsw state base %p freed \n", base);
}

void
_nscd_free_all_nsw_state_base()
{
	nscd_nsw_state_base_t	*base;
	int			i;
	char			*me = "_nscd_free_all_nsw_state_base";

	_NSCD_LOG(NSCD_LOG_NSW_STATE | NSCD_LOG_CONFIG, NSCD_LOG_LEVEL_DEBUG)
	(me, "freeing all db state base\n");

	(void) rw_wrlock(&nscd_nsw_state_base_lock);
	for (i = 0; i < NSCD_NUM_DB; i++) {

		base = nscd_nsw_state_base[i];
		_NSCD_LOG(NSCD_LOG_NSW_STATE | NSCD_LOG_CONFIG,
		    NSCD_LOG_LEVEL_DEBUG)
		(me, "freeing db state base (%d) %p \n", i, base);

		if (base == NULL)
			continue;

		nscd_nsw_state_base[i] = (nscd_nsw_state_base_t *)
		    _nscd_set((nscd_acc_data_t *)base, NULL);
	}
	(void) rw_unlock(&nscd_nsw_state_base_lock);
}

static nscd_nsw_state_t *
_nscd_create_nsw_state(
	nscd_nsw_params_t	*params)
{
	nscd_nsw_state_t	*s;
	nscd_nsw_config_t	*nsw_cfg;
	nscd_db_t		**be_db_p, *be_db;
	int			i, nobe = 1;
	char			*me = "_nscd_create_nsw_state";


	_NSCD_LOG(NSCD_LOG_NSW_STATE, NSCD_LOG_LEVEL_DEBUG)
	(me, "creating nsw state...\n");

	s = calloc(1, sizeof (nscd_nsw_state_t));
	if (s == NULL) {
		if ((*s->nsw_cfg_p)->nobase  != 1)
			_nscd_release((nscd_acc_data_t *)params->nswcfg);
		_NSCD_LOG(NSCD_LOG_NSW_STATE, NSCD_LOG_LEVEL_ERROR)
		(me, "not able to allocate a nsw state\n");
		return (NULL);
	} else
		_NSCD_LOG(NSCD_LOG_NSW_STATE, NSCD_LOG_LEVEL_DEBUG)
		(me, "nsw state %p allocated\n", s);

	s->dbi = params->dbi;
	s->next = NULL;

	nsw_cfg = *params->nswcfg;

	s->nsw_cfg_p = params->nswcfg;
	s->config = nsw_cfg->nsw_config;
	s->max_src = nsw_cfg->max_src;
	s->p = params->p;

	s->be = calloc(s->max_src, sizeof (nss_backend_t **));
	if (s->be == NULL) {
		_NSCD_LOG(NSCD_LOG_NSW_STATE, NSCD_LOG_LEVEL_ERROR)
		(me, "not able to allocate s->be\n");

		_nscd_free_nsw_state(s);
		return (NULL);
	} else {
		_NSCD_LOG(NSCD_LOG_NSW_STATE, NSCD_LOG_LEVEL_DEBUG)
		(me, "db be array %p allocated\n", s->be);
	}

	s->be_constr = (nss_backend_constr_t *)calloc(s->max_src,
	    sizeof (nss_backend_constr_t));
	if (s->be_constr == NULL) {
		_NSCD_LOG(NSCD_LOG_NSW_STATE, NSCD_LOG_LEVEL_ERROR)
		(me, "not able to allocate s->be_constr\n");

		_nscd_free_nsw_state(s);
		return (NULL);
	} else {
		_NSCD_LOG(NSCD_LOG_NSW_STATE, NSCD_LOG_LEVEL_DEBUG)
		(me, "db be constructor array %p allocated\n", s->be_constr);
	}

	s->be_version_p = (void **)calloc(s->max_src, sizeof (void *));
	if (s->be_version_p == NULL) {
		_NSCD_LOG(NSCD_LOG_NSW_STATE, NSCD_LOG_LEVEL_ERROR)
		(me, "not able to allocate s->be_version_p\n");

		_nscd_free_nsw_state(s);
		return (NULL);
	} else {
		_NSCD_LOG(NSCD_LOG_NSW_STATE, NSCD_LOG_LEVEL_DEBUG)
		(me, "db be version ptr array %p allocated\n", s->be_version_p);
	}

	s->be_db_pp = calloc(s->max_src, sizeof (nscd_db_t ***));
	if (s->be_db_pp == NULL) {
		_NSCD_LOG(NSCD_LOG_NSW_STATE, NSCD_LOG_LEVEL_ERROR)
		(me, "not able to allocate s->be_db_pp\n");
		_nscd_free_nsw_state(s);
		return (NULL);
	} else {
		_NSCD_LOG(NSCD_LOG_NSW_STATE, NSCD_LOG_LEVEL_DEBUG)
		(me, "be_db_pp array %p allocated\n", s->be_db_pp);
	}

	/* create the source:database backends */
	for (i = 0;  i < s->max_src;  i++) {
		nss_backend_t		*be;
		int			srci;
		char			*srcn;
		const char		*dbn;
		struct __nsw_lookup_v1	*lkp;
		const nscd_db_entry_t	*dbe;
		nscd_be_info_t		*be_info;

		if (i == 0)
			lkp = s->config->lookups;
		else
			lkp = lkp->next;
		if (lkp == NULL) {
			_NSCD_LOG(NSCD_LOG_NSW_STATE, NSCD_LOG_LEVEL_ERROR)
			(me, "error: lkp is NULL\n");
			_nscd_free_nsw_state(s);
			return (NULL);
		}

		srci = nsw_cfg->src_idx[i];
		srcn = lkp->service_name;
		_NSCD_LOG(NSCD_LOG_NSW_STATE, NSCD_LOG_LEVEL_DEBUG)
		(me, "source name = %s, index = %d\n", srcn, srci);

		be_db_p = (nscd_db_t **)_nscd_get(
		    (nscd_acc_data_t *)nscd_src_backend_db[srci]);
		if (be_db_p == NULL) {
			_nscd_free_nsw_state(s);
			return (NULL);
		}
		be_db = *be_db_p;
		s->be_db_pp[i] = be_db_p;
		_NSCD_LOG(NSCD_LOG_NSW_STATE, NSCD_LOG_LEVEL_DEBUG)
		(me, "be db ptr array %p referenced\n", be_db_p);

		be_info = NULL;
		be = NULL;
		dbn = params->p.name;
		dbe = _nscd_get_db_entry(be_db, NSCD_DATA_BACKEND_INFO,
		    (const char *)dbn, NSCD_GET_FIRST_DB_ENTRY, 0);
		if (dbe != NULL)
			be_info = (nscd_be_info_t *)*(dbe->data_array);

		if (be_info == NULL || be_info->be_constr == NULL) {
			_NSCD_LOG(NSCD_LOG_NSW_STATE, NSCD_LOG_LEVEL_DEBUG)
			(me, "no backend info or be_constr is NULL "
			    "for <%s : %s>\n", NSCD_NSW_SRC_NAME(srci),
			    dbn);
		} else {
			s->be_constr[i] = be_info->be_constr;
			be = (be_info->be_constr)(dbn,
			    NSCD_NSW_SRC_NAME(srci), 0);
			if (be == NULL)
				s->recheck_be = nscd_true;
		}

		if (be == NULL) {
			_NSCD_LOG(NSCD_LOG_NSW_STATE, NSCD_LOG_LEVEL_ERROR)
			(me, "not able to init be for <%s : %s>\n",
			    NSCD_NSW_SRC_NAME(srci), dbn);

			_NSCD_LOG(NSCD_LOG_NSW_STATE, NSCD_LOG_LEVEL_DEBUG)
			(me, "releasing db be ptr %p\n", be_db_p);

			_nscd_release((nscd_acc_data_t *)be_db_p);
			s->be_db_pp[i] = NULL;

			continue;
		}

		s->be[i] = be;
		s->be_version_p[i] = be_info->be_version;
		_NSCD_LOG(NSCD_LOG_NSW_STATE, NSCD_LOG_LEVEL_DEBUG)
		(me, "backend version is %p\n", be_info->be_version);
		nobe = 0;
	}

	if (nobe == 1) {
		_NSCD_LOG(NSCD_LOG_NSW_STATE, NSCD_LOG_LEVEL_DEBUG)
		(me, "NO backend found, returning NULL\n");

		_nscd_free_nsw_state(s);
		return (NULL);
	}

	return (s);
}

/*
 * Try to initialize the backend instances one more time
 * in case the dependencies the backend libraries depend
 * on are now available
 */
static void
check_be_array(
	nscd_nsw_state_t	*s)
{
	int			i;
	char			*dbn;
	char			*srcn;
	struct __nsw_lookup_v1	*lkp;

	dbn = NSCD_NSW_DB_NAME(s->dbi);

	s->recheck_be = nscd_false;
	for (i = 0;  i < s->max_src;  i++) {

		if (i == 0)
			lkp = s->config->lookups;
		else
			lkp = lkp->next;
		if (lkp == NULL)
			return;

		srcn = lkp->service_name;

		/*
		 * it is possible that 's->be[i]' could not be
		 * initialized earlier due to a dependency not
		 * yet available (e.g., nis on domain name),
		 * try to initialize one more time
		 */
		if (s->be[i] == NULL && s->be_constr[i] != NULL) {
			s->be[i] = (s->be_constr[i])(dbn, srcn, 0);
			if (s->be[i] == NULL)
				s->recheck_be = nscd_true;
		}
	}
}

static nscd_rc_t
_get_nsw_state_int(
	nss_db_root_t		*rootp,
	nscd_nsw_params_t	*params,
	thread_t		*tid)
{

	nscd_nsw_state_t	*ret = NULL;
	nscd_nsw_config_t	**nswcfg;
	nscd_nsw_state_base_t	*base;
	nscd_state_ctrl_t	*ctrl_p;
	int			thread_only = 0, wait_cond = 0;
	char			*me = "_get_nsw_state_int";
	int			dbi;
	nscd_rc_t		rc;

	dbi = params->dbi;

	/*
	 * no nsw state will be reused, if asked to use
	 * default config. So create the new structures
	 * used by the switch engine and the new nsw state
	 */
	if (params->p.flags & NSS_USE_DEFAULT_CONFIG) {
		rc = _nscd_create_sw_struct(dbi, -1, (char *)params->p.name,
		    (char *)params->p.default_config, NULL, params);
		if (rc != NSCD_SUCCESS)
			return (rc);

		_NSCD_LOG(NSCD_LOG_NSW_STATE, NSCD_LOG_LEVEL_DEBUG)
		(me, "no base nsw config created for %s (sources: %s)\n",
		    params->p.name, params->p.default_config);

		ret = _nscd_create_nsw_state(params);
		if (ret == NULL)
			return (NSCD_CREATE_NSW_STATE_FAILED);
		rootp->s = (struct nss_db_state *)ret;
		return (NSCD_SUCCESS);
	}

	/*
	 * if getting a nsw state for a request from the compat
	 * backend, create the new switch structures if this
	 * is the first time around for a passwd, shadow, group,
	 * audit_user, or user_attr database
	 */
	if (params->compati != -1) {

		nscd_nsw_config_t	**nswcfg1;
		int			i = params->compati;

		dbi = i;

		nswcfg = (nscd_nsw_config_t **)_nscd_get(
		    (nscd_acc_data_t *)nscd_nsw_config[i]);

		/*
		 * if nsw data structures not created yet, get the
		 * config string from the passwd_compat or
		 * group_compat DB and create the structures
		 */
		if (nswcfg == NULL) {
			nswcfg1 = (nscd_nsw_config_t **)_nscd_get(
			    (nscd_acc_data_t *)nscd_nsw_config[params->cfgdbi]);
			if (nswcfg1 == NULL) {
				_NSCD_LOG(NSCD_LOG_NSW_STATE,
				    NSCD_LOG_LEVEL_ERROR)
				(me, "no nsw config for %s\n",
				    params->p.name);
				return (NSCD_CREATE_NSW_STATE_FAILED);
			}

			rc = _nscd_create_sw_struct(i, params->cfgdbi,
			    params->p.name, (*nswcfg1)->nsw_cfg_str,
			    NULL, params);
			_nscd_release((nscd_acc_data_t *)nswcfg1);
			if (rc != NSCD_SUCCESS)
				return (rc);

			_NSCD_LOG(NSCD_LOG_NSW_STATE,
			    NSCD_LOG_LEVEL_DEBUG)
				(me, "nsw config created for %s (%s)\n",
				    params->p.name, (*nswcfg1)->nsw_cfg_str);
		} else
			_nscd_release((nscd_acc_data_t *)nswcfg);
	}

	(void) rw_rdlock(&nscd_nsw_state_base_lock);
	base = nscd_nsw_state_base[dbi];
	(void) rw_unlock(&nscd_nsw_state_base_lock);
	if (base == NULL)
		assert(base != NULL);

	/*
	 * If list is not empty, return the first one on list.
	 * Otherwise, create and return a new db state if the
	 * limit is not reached. if reacehed, wait for the 'one
	 * is available' signal.
	 */
	assert(base == (nscd_nsw_state_base_t *)_nscd_mutex_lock(
	    (nscd_acc_data_t *)base));

	if (tid == NULL) {
		ctrl_p = &base->nsw_state;
	} else {
		thread_only = 1;
		ctrl_p = &base->nsw_state_thr;

		_NSCD_LOG_IF(NSCD_LOG_NSW_STATE, NSCD_LOG_LEVEL_DEBUG) {
			_nscd_logit(me, "per thread nsw state info: \n");
			_nscd_logit(me, "tid = %d\n", *tid);
			_nscd_logit(me, "tid in base = %d\n", base->tid);
			_nscd_logit(me, "number of free nsw_state = %d\n",
			    ctrl_p->free);
			_nscd_logit(me, "number of nsw state allocated = %d\n",
			    ctrl_p->allocated);
			_nscd_logit(me, "first nsw state on list = %p\n",
			    ctrl_p->first);
			_nscd_logit(me, "number of waiter = %d\n",
			    ctrl_p->waiter);

		}
	}

	if (ctrl_p->first == NULL && ctrl_p->allocated == ctrl_p->max)
		wait_cond = 1;
	else if (thread_only && base->used_by_thr && base->tid != *tid)
		wait_cond = 1;

	if (wait_cond) {

		ctrl_p->waiter++;

		while (wait_cond) {
			if (!thread_only)
				_NSCD_LOG(NSCD_LOG_NSW_STATE,
				    NSCD_LOG_LEVEL_DEBUG)
				(me, "waiting for nsw state signal\n");
			else
				_NSCD_LOG(NSCD_LOG_NSW_STATE,
				    NSCD_LOG_LEVEL_DEBUG)
				(me, "waiting for per thread "
				    "nsw state signal\n");

			if (thread_only) {
				_nscd_cond_wait((nscd_acc_data_t *)base,
				    &base->thr_cond);

				if (base->used_by_thr == 0 &&
				    ctrl_p->first != NULL)
					wait_cond = 0;
			} else {
				_nscd_cond_wait((nscd_acc_data_t *)base, NULL);

				if (ctrl_p->first != NULL)
					wait_cond = 0;
			}

			if (!thread_only)
				_NSCD_LOG(NSCD_LOG_NSW_STATE,
				    NSCD_LOG_LEVEL_DEBUG)
				(me, "woke from cond wait ...wait_cond = %d\n",
				    wait_cond);
			else

				_NSCD_LOG(NSCD_LOG_NSW_STATE,
				    NSCD_LOG_LEVEL_DEBUG)
				(me, "woke from cond wait (per thread) "
				    "...wait_cond = %d\n", wait_cond);

		}

		ctrl_p->waiter--;
	}

	if (ctrl_p->first == NULL) {
		int	geti;

		/*
		 * for lookup calls from the compat backend
		 * uses the switch policy for passwd_compat
		 * or group_compat
		 */
		if (params->compati != -1)
			geti = params->compati;
		else
			geti = params->dbi;

		params->nswcfg = (nscd_nsw_config_t **)_nscd_get(
		    (nscd_acc_data_t *)nscd_nsw_config[geti]);
		_NSCD_LOG(NSCD_LOG_NSW_STATE, NSCD_LOG_LEVEL_DEBUG)
		(me, "got a nsw config %p for index %d\n",
		    params->nswcfg, geti);

		ctrl_p->first = _nscd_create_nsw_state(params);
		if (ctrl_p->first != NULL) {
			ctrl_p->first->base = base;

			if (tid == NULL) {
				_NSCD_LOG(NSCD_LOG_NSW_STATE,
				    NSCD_LOG_LEVEL_DEBUG)
				(me, "got a new nsw_state %p\n", ctrl_p->first);
			} else {
				_NSCD_LOG(NSCD_LOG_NSW_STATE,
				    NSCD_LOG_LEVEL_DEBUG)
				(me, "got a new per thread nsw_state %p\n",
				    ctrl_p->first);
			}
			ctrl_p->allocated++;
			ctrl_p->free++;
		} else {
			_NSCD_LOG(NSCD_LOG_NSW_STATE, NSCD_LOG_LEVEL_ERROR)
				(me, "error: unable to obtain a nsw state\n");
			_nscd_mutex_unlock((nscd_acc_data_t *)base);
			return (NSCD_CREATE_NSW_STATE_FAILED);
		}
	}

	ret = ctrl_p->first;
	if (ret->recheck_be == nscd_true)
		check_be_array(ret);
	ctrl_p->first = ret->next;
	ret->next = NULL;
	ctrl_p->free--;
	if (thread_only) {
		base->tid = *tid;
		base->used_by_thr = 1;

		_NSCD_LOG_IF(NSCD_LOG_NSW_STATE, NSCD_LOG_LEVEL_DEBUG) {
			_nscd_logit(me, "\t\t\tgot a per thread nsw "
			    "state %p: \n", ret);
			_nscd_logit(me, "tid = %d\n", *tid);
			_nscd_logit(me, "tid in base = %d\n", base->tid);
			_nscd_logit(me, "number of free nsw_state = %d\n",
			    ctrl_p->free);
			_nscd_logit(me, "number od nsw state allocated = %d\n",
			    ctrl_p->allocated);
			_nscd_logit(me, "first nsw state on list = %p\n",
			    ctrl_p->first);
			_nscd_logit(me, "number of waiter = %d\n",
			    ctrl_p->waiter);
		}
	}
	else
		_NSCD_LOG(NSCD_LOG_NSW_STATE, NSCD_LOG_LEVEL_DEBUG)
		(me, "got old nsw state %p\n", ret);

	_nscd_mutex_unlock((nscd_acc_data_t *)base);

	rootp->s = (struct nss_db_state *)ret;

	return (NSCD_SUCCESS);
}

nscd_rc_t
_nscd_get_nsw_state(
	nss_db_root_t		*rootp,
	nscd_nsw_params_t	*params)
{
	return (_get_nsw_state_int(rootp, params, NULL));
}

nscd_rc_t
_nscd_get_nsw_state_thread(
	nss_db_root_t		*rootp,
	nscd_nsw_params_t	*params)
{
	thread_t	tid = thr_self();
	return (_get_nsw_state_int(rootp, params, &tid));
}


static void
_put_nsw_state_int(
	nscd_nsw_state_t	*s,
	thread_t		*tid)
{

	nscd_nsw_state_base_t	*base;
	nscd_state_ctrl_t	*ctrl_p;
	int			thread_only = 0;
	char			*me = "_put_nsw_state_int";

	_NSCD_LOG(NSCD_LOG_NSW_STATE, NSCD_LOG_LEVEL_DEBUG)
	(me, "put back a nsw state\n");

	if (s == NULL) {
		_NSCD_LOG(NSCD_LOG_NSW_STATE, NSCD_LOG_LEVEL_DEBUG)
		(me, "nsw state is NULL, nothing to put back\n");
		return;
	}

	/*
	 * no need to put back if the nsw state is not on any base
	 * but need to free the resources used
	 */
	if ((*s->nsw_cfg_p)->nobase  == 1) {
		_NSCD_LOG(NSCD_LOG_NSW_STATE, NSCD_LOG_LEVEL_DEBUG)
		(me, "no base nsw state, freeing resources ...\n");

		_nscd_free_nsw_state(s);
		return;
	}

	if (tid != NULL)
		thread_only = 1;

	base = s->base;

	if (_nscd_mutex_lock((nscd_acc_data_t *)base) == NULL) {
		/* base has been freed, free this db state */
		_NSCD_LOG(NSCD_LOG_NSW_STATE, NSCD_LOG_LEVEL_DEBUG)
		(me, "nsw state base has been freed, freeing %p\n", s);
		_nscd_free_nsw_state(s);
		return;
	}

	if (thread_only)
		ctrl_p = &base->nsw_state_thr;
	else
		ctrl_p = &base->nsw_state;

	_NSCD_LOG_IF(NSCD_LOG_NSW_STATE, NSCD_LOG_LEVEL_DEBUG) {
		_nscd_logit(me, "before returning the nsw state: \n");
		_nscd_logit(me, "tid = %d\n", (tid == NULL) ? -1 : *tid);
		_nscd_logit(me, "tid in base = %d\n", base->tid);
		_nscd_logit(me, "number of free nsw_state = %d\n",
		    ctrl_p->free);
		_nscd_logit(me, "number od nsw state allocated = %d\n",
		    ctrl_p->allocated);
		_nscd_logit(me, "first nsw state on list = %p\n",
		    ctrl_p->first);
		_nscd_logit(me, "number of waiter = %d\n", ctrl_p->waiter);
	}

	if (ctrl_p->first != NULL) {
		s->next = ctrl_p->first;
		ctrl_p->first = s;
	} else {
		ctrl_p->first = s;
		s->next = NULL;
	}
	ctrl_p->free++;

	_NSCD_LOG(NSCD_LOG_NSW_STATE, NSCD_LOG_LEVEL_DEBUG)
	(me, "signaling waiter thread_only = %d..\n", thread_only);

	if (thread_only && ctrl_p->free == ctrl_p->allocated) {
		assert(ctrl_p->first != NULL);
		base->used_by_thr = 0;
		if (ctrl_p->waiter > 0) {
			(void) cond_signal(&base->thr_cond);
		}
	}

	if (!thread_only && ctrl_p->waiter > 0) {

		_nscd_cond_signal((nscd_acc_data_t *)base);
	}

	_NSCD_LOG_IF(NSCD_LOG_NSW_STATE, NSCD_LOG_LEVEL_DEBUG) {
		_nscd_logit(me, "after the nsw state is returned: \n");
		_nscd_logit(me, "tid = %d\n", (tid == NULL) ? -1 : *tid);
		_nscd_logit(me, "tid in base = %d\n", base->tid);
		_nscd_logit(me, "number of free nsw_state = %d\n",
		    ctrl_p->free);
		_nscd_logit(me, "number od nsw state allocated = %d\n",
		    ctrl_p->allocated);
		_nscd_logit(me, "first nsw state on list = %p\n",
		    ctrl_p->first);
		_nscd_logit(me, "tnumber of waiter = %d\n", ctrl_p->waiter);
	}

	_NSCD_LOG(NSCD_LOG_NSW_STATE, NSCD_LOG_LEVEL_DEBUG)
	(me, "done putting back nsw state %p, thread_only = %d\n",
	    s, thread_only);

	_nscd_mutex_unlock((nscd_acc_data_t *)base);

}

void
_nscd_put_nsw_state(
	nscd_nsw_state_t	*s)
{
	_put_nsw_state_int(s, NULL);
}

void
_nscd_put_nsw_state_thread(
	nscd_nsw_state_t	*s)
{
	thread_t		tid = thr_self();
	_put_nsw_state_int(s, &tid);
}

nscd_rc_t
_nscd_init_nsw_state_base(
	int			dbi,
	int			compat_basei,
	int			lock)
{
	int			cfgdbi;
	nscd_nsw_state_base_t	*base = NULL;
	char			*me = "_nscd_init_nsw_state_base";

	if (lock)
		(void) rw_rdlock(&nscd_nsw_state_base_lock);

	base = (nscd_nsw_state_base_t *)_nscd_alloc(
	    NSCD_DATA_NSW_STATE_BASE,
	    sizeof (nscd_nsw_state_base_t),
	    _nscd_free_nsw_state_base,
	    NSCD_ALLOC_MUTEX | NSCD_ALLOC_COND);

	if (base == NULL) {
		_NSCD_LOG(NSCD_LOG_NSW_STATE | NSCD_LOG_CONFIG,
		    NSCD_LOG_LEVEL_ERROR)
		(me, "not able to allocate a nsw state base\n");
		if (lock)
			(void) rw_unlock(&nscd_nsw_state_base_lock);
		return (NSCD_NO_MEMORY);
	}
	_NSCD_LOG(NSCD_LOG_NSW_STATE | NSCD_LOG_CONFIG, NSCD_LOG_LEVEL_DEBUG)
		(me, "nsw state base %p allocated\n", base);

	/*
	 * initialize and activate the new nss_nsw_state base
	 */
	base->dbi = dbi;
	if (compat_basei != -1)
		cfgdbi = compat_basei;
	else
		cfgdbi = dbi;

	base->nsw_state.max = NSCD_SW_CFG(cfgdbi).max_nsw_state_per_db;
	base->nsw_state_thr.max = NSCD_SW_CFG(cfgdbi).max_nsw_state_per_thread;

	nscd_nsw_state_base[dbi] = (nscd_nsw_state_base_t *)_nscd_set(
	    (nscd_acc_data_t *)nscd_nsw_state_base[dbi],
	    (nscd_acc_data_t *)base);

	if (lock)
		(void) rw_unlock(&nscd_nsw_state_base_lock);

	return (NSCD_SUCCESS);
}

nscd_rc_t
_nscd_init_all_nsw_state_base()
{
	int			i;
	nscd_rc_t		rc;
	char			*me = "_nscd_init_all_nsw_state_base";

	(void) rw_rdlock(&nscd_nsw_state_base_lock);

	for (i = 0; i < NSCD_NUM_DB; i++) {

		rc = _nscd_init_nsw_state_base(i, -1, 0);

		if (rc != NSCD_SUCCESS) {
			_NSCD_LOG(NSCD_LOG_NSW_STATE | NSCD_LOG_CONFIG,
			    NSCD_LOG_LEVEL_ERROR)
			(me, "not able to initialize a nsw db state "
			    "base (%d)\n", i);

			(void) rw_unlock(&nscd_nsw_state_base_lock);
			return (rc);
		}
	}
	_NSCD_LOG(NSCD_LOG_NSW_STATE | NSCD_LOG_CONFIG, NSCD_LOG_LEVEL_DEBUG)
	(me, "all nsw state base initialized\n");

	(void) rw_unlock(&nscd_nsw_state_base_lock);

	return (NSCD_SUCCESS);
}

nscd_rc_t
_nscd_alloc_nsw_state_base()
{

	(void) rw_rdlock(&nscd_nsw_state_base_lock);

	nscd_nsw_state_base = calloc(NSCD_NUM_DB,
	    sizeof (nscd_nsw_state_base_t *));
	if (nscd_nsw_state_base == NULL) {
		(void) rw_unlock(&nscd_nsw_state_base_lock);
		return (NSCD_NO_MEMORY);
	}

	(void) rw_rdlock(&nscd_nsw_state_base_lock);

	return (NSCD_SUCCESS);
}
