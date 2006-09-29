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

#include <stdlib.h>	/* getenv() */
#include <assert.h>
#include <unistd.h>
#include <string.h>
#include <dlfcn.h>
#include <nss_dbdefs.h>
#include <exec_attr.h>
#include <gssapi/gssapi.h>
#include "nscd_door.h"
#include "nscd_switch.h"
#include "nscd_log.h"
#include "nscd_frontend.h"

#pragma weak nss_search = _nss_search
#define	nss_search	_nss_search

extern rwlock_t nscd_smf_service_state_lock;

/* nscd id: main, forker, or child */
extern int _whoami;

static int
retry_test(nss_status_t res, int n, struct __nsw_lookup_v1 *lkp)
{
	if (res != NSS_TRYAGAIN && res !=  NSS_NISSERVDNS_TRYAGAIN) {
		if (res == NSS_SUCCESS) {
			__NSW_UNPAUSE_ACTION(lkp->actions[__NSW_TRYAGAIN]);
			__NSW_UNPAUSE_ACTION(
				lkp->actions[__NSW_NISSERVDNS_TRYAGAIN]);
		}
		return (0);
	}

	if ((res == NSS_TRYAGAIN &&
	    lkp->actions[__NSW_TRYAGAIN] == __NSW_TRYAGAIN_FOREVER) ||
	    (res == NSS_NISSERVDNS_TRYAGAIN &&
	    lkp->actions[__NSW_NISSERVDNS_TRYAGAIN] == __NSW_TRYAGAIN_FOREVER))
		return (1);

	if (res == NSS_TRYAGAIN &&
	    lkp->actions[__NSW_TRYAGAIN] == __NSW_TRYAGAIN_NTIMES)
		if (n <= lkp->max_retries)
			return (1);
		else {
			lkp->actions[__NSW_TRYAGAIN] = __NSW_TRYAGAIN_PAUSED;
			return (0);
		}

	if (res == NSS_NISSERVDNS_TRYAGAIN &&
	    lkp->actions[__NSW_NISSERVDNS_TRYAGAIN] == __NSW_TRYAGAIN_NTIMES)
		if (n <= lkp->max_retries)
			return (1);
		else {
			lkp->actions[__NSW_NISSERVDNS_TRYAGAIN] =
			    __NSW_TRYAGAIN_PAUSED;
			return (0);
		}

	return (0);
}

static thread_key_t loopback_key;
static mutex_t loopback_key_lock = DEFAULTMUTEX;
static int loopback_key_created = 0;
typedef struct lb_key {
	int		srci;
	int		dbi;
	int		fnum;
	int		*lb_flagp;
} lb_key_t;

static int
set_loopback_key(lb_key_t *key) {

	int		rc = 0;
	lb_key_t	*k;

	if (!loopback_key_created) {
		(void) mutex_lock(&loopback_key_lock);
		if (!loopback_key_created) {
			if ((rc = thr_keycreate(&loopback_key,
					NULL)) == 0)
				loopback_key_created = 1;
		}
		(void) mutex_unlock(&loopback_key_lock);
	}
	if (rc == 0) {
		/* set key if not already set */
		if (thr_getspecific(loopback_key, (void **)&k) == 0 &&
				k == NULL) {
			rc = thr_setspecific(loopback_key, key);
		}
	}

	return (rc);
}

static lb_key_t *
get_loopback_key(void) {

	char		*me = "get_loopback_key";
	int 		rc = 0;
	lb_key_t	*k = NULL;

	if (!loopback_key_created)
		return (NULL);

	rc = thr_getspecific(loopback_key, (void **)&k);

	_NSCD_LOG(NSCD_LOG_SWITCH_ENGINE, NSCD_LOG_LEVEL_DEBUG)
	(me, "get loopback key rc= %d, key = %p\n", rc, k);

	if (rc == 0 && k != NULL)
		return (k);

	return (NULL);
}

static void
clear_loopback_key(lb_key_t *key) {

	char		*me = "clear_loopback_key";

	if (loopback_key_created && key != 0) {
		/*
		 * key->lb_flagp points to the location of the
		 * flag, check_flag, in the stack where it was
		 * first set; clearing the flag tells that
		 * stack the loopback error has been resolved
		 */
		*key->lb_flagp = 0;
		(void) thr_setspecific(loopback_key, NULL);
	}

	_NSCD_LOG(NSCD_LOG_SWITCH_ENGINE, NSCD_LOG_LEVEL_DEBUG)
	(me, "key %p cleared\n", key);
}

static thread_key_t initf_key;
static mutex_t initf_key_lock = DEFAULTMUTEX;
static int initf_key_created = 0;

static int
set_initf_key(void *pbuf) {

	int		rc = 0;

	if (!initf_key_created) {
		(void) mutex_lock(&initf_key_lock);
		if (!initf_key_created) {
			if ((rc = thr_keycreate(&initf_key, NULL)) == 0)
				initf_key_created = 1;
		}
		(void) mutex_unlock(&initf_key_lock);
	}
	if (rc == 0)
		rc = thr_setspecific(initf_key, pbuf);

	return (rc);
}

static void *
get_initf_key(void) {

	char		*me = "get_initf_key";
	void		*pbuf;
	int 		rc = 0;

	if (!initf_key_created)
		return (NULL);

	rc = thr_getspecific(initf_key, (void **)&pbuf);

	_NSCD_LOG(NSCD_LOG_SWITCH_ENGINE, NSCD_LOG_LEVEL_DEBUG)
	(me, "got initf pbuf rc= %d, key = %p\n", rc, pbuf);

	if (rc == 0 && pbuf != NULL)
		return (pbuf);

	return (NULL);
}

static void
clear_initf_key(void) {

	char		*me = "clear_initf_key";

	if (initf_key_created)
		(void) thr_setspecific(initf_key, NULL);

	_NSCD_LOG(NSCD_LOG_SWITCH_ENGINE, NSCD_LOG_LEVEL_DEBUG)
	(me, "initf pbuf cleared\n");
}

/*
 * Call the input initf function to extract the
 * NSS front end parameters and examine them to
 * determine if an NSS lookup is to be performed
 * on a regular or a pseudo (called from compat
 * backend) database. Then set the necessary
 * parameters for later data structures creation
 * and processing.
 */
static nscd_rc_t
getparams(
	int			search_fnum,
	nss_db_initf_t		initf,
	nscd_nsw_params_t	*params)
{

	nscd_rc_t	rc = NSCD_SUCCESS;
	nss_db_params_t	*p;
	int		j;
	char		*dbn;
	const char	*n;

	p = &params->p;
	(void) memset(p, 0, sizeof (*p));
	(*initf)(p);
	params->dbi = -1;
	params->cfgdbi = -1;
	params->compati = -1;
	params->dnsi = -1;

	/* map database name to index */
	n = p->name;
	for (j = 0; j < NSCD_NUM_DB; j++) {
		dbn = NSCD_NSW_DB_NAME(j);
		if (*n != *dbn)
			continue;
		if (strcmp(n, dbn) == 0) {
			params->dbi = j;
			if (*n != 'h' && *n != 'i' && *n != 's' && *n != 'a')
				break;
			if (strcmp(n, NSS_DBNAM_HOSTS) == 0 &&
				search_fnum == NSS_DBOP_HOSTS_BYNAME)
				params->dnsi = 0;
			else if (strcmp(n, NSS_DBNAM_IPNODES) == 0 &&
				search_fnum == NSS_DBOP_IPNODES_BYNAME)
				params->dnsi = 1;
			else if (strcmp(n, NSS_DBNAM_SHADOW) == 0)
				params->privdb = 1;
			else if (strcmp(n, NSS_DBNAM_AUDITUSER) == 0)
				params->privdb = 1;
			break;
		}
	}

	/*
	 * use the switch policy for passwd_compat or
	 * group_compat?
	 */
	if (p->config_name != NULL) {

		n = p->config_name;
		for (j = 0; j < NSCD_NUM_DB; j++) {
			dbn = NSCD_NSW_DB_NAME(j);
			if (*n == *dbn) {
				if (strcmp(n, dbn) == 0) {
					params->cfgdbi = j;
					break;
				}
			}
		}
	}

	/* map the database name to the pseudo database index */
	if (params->cfgdbi != -1) {
		if (strstr(p->config_name, "_compat") != NULL) {
			n = p->name;
			for (j = params->cfgdbi; j < NSCD_NUM_DB; j++) {
				dbn = NSCD_NSW_DB_NAME(j);
				if (*n == *dbn) {
					if (strcmp(n, dbn) == 0) {
						params->compati = j;
						break;
					}
				}
			}
		}
	}

	assert(params->dbi != -1);
	return (rc);
}

static void
nscd_initf(nss_db_params_t	*p)
{
	nss_pheader_t		*pbuf;
	nssuint_t		off;
	nss_dbd_t		*pdbd;
	char			*me = "nscd_initf";

	pbuf = (nss_pheader_t *)get_initf_key();
	if (pbuf == NULL) {
		_NSCD_LOG(NSCD_LOG_SWITCH_ENGINE, NSCD_LOG_LEVEL_DEBUG)
		(me, "ERROR: initf key not set\n");
		return;
	}

	if (pbuf->dbd_len <= sizeof (nss_dbd_t)) {
		_NSCD_LOG(NSCD_LOG_SWITCH_ENGINE, NSCD_LOG_LEVEL_DEBUG)
		(me, "invalid db front params data ? dbd_len = %d\n",
		pbuf->dbd_len);
		return;
	}

	off = pbuf->dbd_off;
	pdbd = (nss_dbd_t *)((void *)((char *)pbuf + off));

	p->name = (char *)pdbd + pdbd->o_name;
	p->config_name = (char *)pdbd + pdbd->o_config_name;
	p->default_config = (char *)pdbd + pdbd->o_default_config;
	p->flags = (enum nss_dbp_flags)pdbd->flags;
	(void) memcpy(&p->private, &pbuf->nscdpriv, sizeof (p->private));

	_NSCD_LOG(NSCD_LOG_SWITCH_ENGINE, NSCD_LOG_LEVEL_DEBUG)
	(me, "db frontend params: name =%s, config_name = %s, "
	"default_config = %s, flags = %x\n", p->name,
	(p->config_name && *p->config_name != '\0' ?
				p->config_name : "<NOT SPECIFIED>"),
	(p->default_config && *p->default_config != '\0' ?
				p->default_config : "<NOT SPECIFIED>"),
	p->flags);
}


static void
trace_result(
	int		dbi,
	int		srci,
	int		op,
	nss_status_t	res,
	nss_XbyY_args_t	*arg)
{
	char	*res_str;
	char	*src = "?";
	char	*db = "?";
	char	*me = "nss_search";

	switch (res) {
	case NSS_SUCCESS:
		res_str = "NSS_SUCCESS";
		break;
	case NSS_NOTFOUND:
		res_str = "NSS_NOTFOUND";
		break;
	case NSS_UNAVAIL:
		res_str = "NSS_UNAVAIL";
		break;
	case NSS_TRYAGAIN:
		res_str = "NSS_TRYAGAIN";
		break;
	case NSS_NISSERVDNS_TRYAGAIN:
		res_str = "NSS_NISSERVDNS_TRYAGAIN";
		break;
	default:
		res_str = "UNKNOWN STATUS";
		break;
	}

	if (dbi != -1)
		db = NSCD_NSW_DB_NAME(dbi);
	if (srci != -1)
		src = NSCD_NSW_SRC_NAME(srci);

	if (res == NSS_SUCCESS) {
		_nscd_logit(me,
"%s: database: %s, operation: %d, source: %s returned \"%s\", length = %d\n",
		res_str, db, op, src, arg->buf.buffer, arg->returnlen);

		return;
	}

	_nscd_logit(me,
"%s: database: %s, operation: %d, source: %s, erange= %d, errno: %s \n",
		res_str, db, op, src, arg->erange, strerror(arg->h_errno));
}

/*
 * Determine if a request should be done locally in the getXbyY caller's
 * process. Return none zero if yes, 0 otherwise.
 * This function returnis 1 if:
 *   -- the database is exec_attr and the search_flag is GET_ALL
 */
static int
try_local(
	int			dbi,
	void			*arg)
{
	struct nss_XbyY_args	*ap = (struct nss_XbyY_args *)arg;
	_priv_execattr		*ep;
	int			rc = 0;
	char			*me = "try_local";

	if (strcmp(NSCD_NSW_DB_NAME(dbi), NSS_DBNAM_EXECATTR) == 0) {
		if ((ep = ap->key.attrp) != NULL &&
				ep->search_flag == GET_ALL)
			rc = 1;
	}

	if (rc != 0) {

		_NSCD_LOG(NSCD_LOG_SWITCH_ENGINE, NSCD_LOG_LEVEL_DEBUG)
		(me, "TRYLOCAL: exec_attr:GET_ALL\n");
	}

	return (rc);
}

static nscd_rc_t
get_dns_funcs(int dnsi, void **func_p)
{
	char		*me = "get_dns_funcs";
	static void	*handle = NULL;
	static mutex_t	func_lock = DEFAULTMUTEX;
	void		*sym;
	char		*func_name[2] = { "_nss_get_dns_hosts_name",
				"_nss_get_dns_ipnodes_name" };
	static void	*func[2] = {NULL, NULL};

	if (handle != NULL && dnsi > 0 && func[dnsi] != NULL) {
		(void) memcpy(func_p, &func[dnsi], sizeof (void *));
		return (NSCD_SUCCESS);
	}

	(void) mutex_lock(&func_lock);

	/* close the handle if requested */
	if (dnsi < 0) {
		if (handle != NULL) {
			(void) dlclose(handle);
			func[0] = NULL;
			func[1] = NULL;
		}
		(void) mutex_unlock(&func_lock);
		return (NSCD_SUCCESS);
	}

	if (handle != NULL && func[dnsi] != NULL) {
		(void) memcpy(func_p, &func[dnsi], sizeof (void *));
		(void) mutex_unlock(&func_lock);
		return (NSCD_SUCCESS);
	}

	if (handle == NULL) {
		handle = dlopen("nss_dns.so.1", RTLD_LAZY);
		if (handle == NULL) {
			_NSCD_LOG(NSCD_LOG_SWITCH_ENGINE,
				NSCD_LOG_LEVEL_ERROR)
			(me, "unable to dlopen nss_dns.so.1\n");
			(void) mutex_unlock(&func_lock);
			return (NSCD_CFG_DLOPEN_ERROR);
		}
	}

	if ((sym = dlsym(handle, func_name[dnsi])) == NULL) {

		_NSCD_LOG(NSCD_LOG_SWITCH_ENGINE, NSCD_LOG_LEVEL_ERROR)
		(me, "unable to find symbol %s\n", func_name[dnsi]);
		(void) mutex_unlock(&func_lock);
		return (NSCD_CFG_DLSYM_ERROR);
	} else {
		(void) memcpy(func_p, &sym, sizeof (void *));
		(void) memcpy(&func[dnsi], &sym, sizeof (void *));
	}

	(void) mutex_unlock(&func_lock);
	return (NSCD_SUCCESS);
}

static nss_status_t
search_dns_withttl(nscd_sw_return_t *swret, char *srcname, int dnsi)
{
	nss_status_t	(*func)();
	nss_status_t	res = NSS_UNAVAIL;
	nscd_rc_t	rc;

	swret->noarg = 0;
	if (strcmp(srcname, "dns") != 0)
		return (NSS_ERROR);

	rc = get_dns_funcs(dnsi, (void **)&func);
	if (rc == NSCD_SUCCESS)
		res = (func)(NULL, &swret->pbuf, &swret->pbufsiz);
	return (res);
}

/*
 * Returns a flag to indicate if needs to fall back to the
 * main nscd when a per-user lookup failed with rc NSS_NOTFOUND.
 */
static int
set_fallback_flag(char *srcname, nss_status_t rc)
{
	char	*me = "set_fallback_flag";
	if (strcmp(srcname, "ldap") == 0 && rc == NSS_NOTFOUND) {

		_NSCD_LOG(NSCD_LOG_SWITCH_ENGINE, NSCD_LOG_LEVEL_DEBUG)
		(me, "NSS_NOTFOUND (ldap): fallback to main nscd "
		"may be needed\n");
		return (1);
	}
	return (0);
}

nss_status_t
nss_search(nss_db_root_t *rootp, nss_db_initf_t initf, int search_fnum,
	void *search_args)
{
	char			*me = "nss_search";
	nss_status_t		res = NSS_UNAVAIL;
	nscd_nsw_state_t	*s = NULL;
	int			n_src;
	unsigned int		status_vec = 0;
	int			dbi, srci = -1;
	int			check_loopback = 0;
	int			state_thr = 0;
	lb_key_t		key, *k = NULL;
	nss_db_root_t		root_db;
	nscd_nsw_params_t	params;
	nscd_sw_return_t	*swret;

	_NSCD_LOG(NSCD_LOG_SWITCH_ENGINE, NSCD_LOG_LEVEL_DEBUG)
	(me, "rootp = %p, initf = %p, search_fnum = %d, "
		"search_args = %p\n", rootp, initf,
		search_fnum, search_args);

	NSCD_SW_STATS_G.lookup_request_received_g++;
	NSCD_SW_STATS_G.lookup_request_in_progress_g++;
	NSCD_SW_STATS_G.lookup_request_queued_g++;

	/* determine db index, cfg db index, etc */
	(void) getparams(search_fnum, initf, &params);
	dbi = params.dbi;

	/* get address of the switch engine return data area */
	if (initf == nscd_initf) {
		swret = (nscd_sw_return_t *)params.p.private;
		swret->srci = -1;
	} else {
		swret = NULL;
		params.dnsi = -1;
	}

	/*
	 * for request that should be processed by the client,
	 * send it back with status NSS_TRYLOCAL
	 */
	if (try_local(dbi, search_args) == 1) {
		res = NSS_TRYLOCAL;
		goto error_exit;
	}

	NSCD_SW_STATS(dbi).lookup_request_received++;
	NSCD_SW_STATS(dbi).lookup_request_in_progress++;
	NSCD_SW_STATS(dbi).lookup_request_queued++;

	/* if lookup not enabled, return NSS_UNAVAIL  */
	if (!(NSCD_SW_CFG_G.enable_lookup_g == nscd_true &&
		NSCD_SW_CFG(dbi).enable_lookup == nscd_true)) {

		_NSCD_LOG(NSCD_LOG_SWITCH_ENGINE, NSCD_LOG_LEVEL_DEBUG)
		(me, "lookup not enabled for %s\n", NSCD_NSW_DB_NAME(dbi));

		goto error_exit;
	}

	/* determine if loopback checking is configured */
	if (NSCD_SW_CFG_G.enable_loopback_checking_g == nscd_true &&
		NSCD_SW_CFG(dbi).enable_loopback_checking == nscd_true) {
		check_loopback = 1;

		_NSCD_LOG(NSCD_LOG_SWITCH_ENGINE, NSCD_LOG_LEVEL_DEBUG)
		(me, "loopback checking enabled for %s\n",
		NSCD_NSW_DB_NAME(dbi));
	}

	if (check_loopback) {
		k = get_loopback_key();
		if (k != NULL) {
			if (k->dbi != dbi || k->fnum != search_fnum) {
				clear_loopback_key(k);
				k = NULL;
			}
		}
	}

	if (s == 0) {
		nscd_rc_t	rc;

		if (check_loopback) {
			rc = _nscd_get_nsw_state_thread(&root_db, &params);
			state_thr = 1;
		} else
			rc = _nscd_get_nsw_state(&root_db, &params);

		NSCD_SW_STATS_G.lookup_request_queued_g--;
		NSCD_SW_STATS(dbi).lookup_request_queued--;

		if (rc != NSCD_SUCCESS)
				goto error_exit;

		s = (nscd_nsw_state_t *)root_db.s;
	}

	_NSCD_LOG(NSCD_LOG_SWITCH_ENGINE, NSCD_LOG_LEVEL_DEBUG)
	(me, "database = %s, config = [ %s ]\n", NSCD_NSW_DB_NAME(dbi),
	(*s->nsw_cfg_p)->nsw_cfg_str);

	for (n_src = 0;  n_src < s->max_src;  n_src++) {
		nss_backend_t		*be;
		nss_backend_op_t	funcp;
		struct __nsw_lookup_v1	*lkp;
		int			smf_state;
		int			n_loop = 0;
		int			max_retry = 10;

		res = NSS_UNAVAIL;

		if (n_src == 0)
			lkp = s->config->lookups;
		else
			lkp = lkp->next;

		/* set the number of max. retries */
		if (lkp->actions[__NSW_TRYAGAIN] == __NSW_TRYAGAIN_NTIMES)
			max_retry = lkp->max_retries;

		srci = (*s->nsw_cfg_p)->src_idx[n_src];
		if (swret != NULL)
			swret->srci = srci;

		_NSCD_LOG(NSCD_LOG_SWITCH_ENGINE, NSCD_LOG_LEVEL_DEBUG)
		(me, "nsw source = %s\n", NSCD_NSW_SRC_NAME(srci));

		/* if no privilege to look up, skip */
		if (params.privdb == 1 && swret != NULL &&
			strcmp(NSCD_NSW_SRC_NAME(srci), "files") == 0 &&
			_nscd_get_client_euid() != 0) {
			_NSCD_LOG(NSCD_LOG_SWITCH_ENGINE,
				NSCD_LOG_LEVEL_DEBUG)
			(me, "no privilege to look up, skip source\n");

			goto next_src;
		}

		/* get state of the (backend) client service */
		smf_state = _nscd_get_smf_state(srci, dbi, 0);

		/* stop if the source is one that should be TRYLOCAL */
		if (smf_state == NSCD_SVC_STATE_UNKNOWN_SRC) {
			_NSCD_LOG(NSCD_LOG_SWITCH_ENGINE,
					NSCD_LOG_LEVEL_DEBUG)
			(me, "returning TRYLOCAL ... \n");
			res = NSS_TRYLOCAL;
			goto free_nsw_state;
		}

		if (check_loopback && k != NULL) {

			if (k->srci == srci && k->dbi == dbi)
				if (k->fnum == search_fnum) {

					_NSCD_LOG(NSCD_LOG_SWITCH_ENGINE,
						NSCD_LOG_LEVEL_DEBUG)
					(me, "loopback detected: "
					"source = %s, database = %s "
					"search fnum = %d\n",
					NSCD_NSW_SRC_NAME(srci),
					NSCD_NSW_DB_NAME(dbi), search_fnum);

				NSCD_SW_STATS_G.loopback_nsw_db_skipped_g++;
				NSCD_SW_STATS(dbi).loopback_nsw_db_skipped++;
					continue;
				}
		}

		be = s->be[n_src];
		if (be != NULL)
			funcp = NSS_LOOKUP_DBOP(be, search_fnum);

		if ((params.dnsi >= 0 && be == 0) || (params.dnsi  < 0 &&
			(be == 0 || (smf_state != NSCD_SVC_STATE_UNINITED &&
			smf_state < SCF_STATE_ONLINE) || funcp == 0))) {

			_NSCD_LOG(NSCD_LOG_SWITCH_ENGINE,
					NSCD_LOG_LEVEL_DEBUG)
			(me, "unable to look up source %s: be = %p, "
			"smf state = %d, funcp = %p\n",
			NSCD_NSW_SRC_NAME(srci), be, smf_state, funcp);

			goto next_src;
		}

		do {
			/*
			 * we can only retry max_retry times,
			 * otherwise threads may get stuck in this
			 * do-while loop forever
			 */
			if (n_loop > max_retry) {
				if (swret != NULL)
					res = NSS_TRYLOCAL;
				goto free_nsw_state;
			}

			/*
			 * set up to prevent loopback
			 */
			if (check_loopback && k == NULL) {
				key.srci = srci;
				key.dbi = dbi;
				key.fnum = search_fnum;
				key.lb_flagp = &check_loopback;
				(void) set_loopback_key(&key);
				k = &key;
			}

			_NSCD_LOG(NSCD_LOG_SWITCH_ENGINE,
					NSCD_LOG_LEVEL_DEBUG)
			(me, "looking up source = %s, loop# = %d \n",
			NSCD_NSW_SRC_NAME(srci), n_loop);

			/*
			 * search the backend, if hosts lookups,
			 * try to get the hosts data with ttl first
			 */
			if (params.dnsi >= 0) {
				res = search_dns_withttl(swret,
					NSCD_NSW_SRC_NAME(srci),
					params.dnsi);
				/*
				 * if not able to get ttl, fall back
				 * to the regular backend call
				 */
				if (res == NSS_ERROR)
					res = (*funcp)(be, search_args);
				else {
					/*
					 * status/result are in the
					 * packed buffer, not
					 * search_args
					 */
					swret->noarg = 1;
				}
			} else
				res = (*funcp)(be, search_args);
			if (swret != NULL)
				swret->errnum = errno;

			/*
			 * backend is not up, check and update the
			 * smf state table
			 */
			if (res == NSS_UNAVAIL)
				(void) _nscd_get_smf_state(srci, dbi, 1);

			/*
			 * may need to fall back to use the main nscd
			 * if per-user lookup
			 */
			if (_whoami == NSCD_CHILD && swret != NULL)
				swret->fallback = set_fallback_flag(
				NSCD_NSW_SRC_NAME(srci), res);

			_NSCD_LOG_IF(NSCD_LOG_SWITCH_ENGINE,
					NSCD_LOG_LEVEL_DEBUG) {

				/*
				 * set up to trace the result/status
				 * of the dns/ttl lookup
				 */
				if (swret != NULL && swret->noarg == 1) {
					nss_pheader_t *phdr;
					struct nss_XbyY_args *arg;
					arg = (struct nss_XbyY_args *)
						search_args;
					phdr = (nss_pheader_t *)swret->pbuf;
					arg->buf.buffer = (char *)phdr +
						phdr->data_off;
					arg->returnlen = phdr->data_len;
					if (phdr->p_errno == ERANGE)
						arg->erange = 1;
					arg->h_errno = phdr->p_herrno;
				}

				trace_result(dbi, srci, search_fnum, res,
				(nss_XbyY_args_t *)search_args);
			}

			n_loop++;
		} while (retry_test(res, n_loop, lkp));

		next_src:

		status_vec |= (1 << res);

		if (__NSW_ACTION_V1(lkp, res) == __NSW_RETURN) {
			break;
		}
	}

	free_nsw_state:

	if (state_thr == 1)
		_nscd_put_nsw_state_thread(s);
	else
		_nscd_put_nsw_state(s);
	if (check_loopback && k != NULL)
		clear_loopback_key(k);

	if (res != NSS_SUCCESS)
		goto error_exit;

	NSCD_SW_STATS_G.lookup_request_succeeded_g++;
	NSCD_SW_STATS(dbi).lookup_request_succeeded++;
	NSCD_SW_STATS_G.lookup_request_in_progress_g--;
	NSCD_SW_STATS(dbi).lookup_request_in_progress--;

	return (NSS_SUCCESS);

	error_exit:

	NSCD_SW_STATS_G.lookup_request_failed_g++;
	NSCD_SW_STATS_G.lookup_request_in_progress_g--;
	NSCD_SW_STATS(dbi).lookup_request_failed++;
	NSCD_SW_STATS(dbi).lookup_request_in_progress--;

	return (res);
}


/* ===> get/set/endent */

static void		nss_setent_u(nss_db_root_t *,
				    nss_db_initf_t,
				    nss_getent_t *);
static nss_status_t	nss_getent_u(nss_db_root_t *,
				    nss_db_initf_t,
				    nss_getent_t *,
				    void *);
static void		nss_endent_u(nss_db_root_t *,
				    nss_db_initf_t,
				    nss_getent_t *);

void
nss_setent(nss_db_root_t *rootp, nss_db_initf_t initf,
	nss_getent_t *contextpp)
{
	if (contextpp == 0)
		return;
	nss_setent_u(rootp, initf, contextpp);
}

nss_status_t
nss_getent(nss_db_root_t *rootp, nss_db_initf_t initf, nss_getent_t *contextpp,
	void *args)
{
	nss_status_t		status;

	if (contextpp == 0) {
		return (NSS_UNAVAIL);
	}
	status = nss_getent_u(rootp, initf, contextpp, args);
	return (status);
}

void
nss_endent(nss_db_root_t *rootp, nss_db_initf_t initf,
	nss_getent_t *contextpp)
{
	if (contextpp == 0)
		return;
	nss_endent_u(rootp, initf, contextpp);
}

/*ARGSUSED*/
static void
end_iter_u(nss_db_root_t *rootp, struct nss_getent_context *contextp)
{
	nscd_getent_context_t	*ctx;
	nscd_nsw_state_t	*s;
	nss_backend_t		*be;
	int			n_src;

	ctx = (nscd_getent_context_t *)contextp;
	s = ctx->nsw_state;
	n_src = ctx->n_src;
	be = ctx->be;

	if (s != 0) {
		if (n_src < s->max_src && be != 0) {
			(void) NSS_INVOKE_DBOP(be, NSS_DBOP_ENDENT, 0);
			ctx->be = 0;  /* Should be unnecessary, but hey */
		}
	}
	ctx->n_src = 0;
}

static void
nss_setent_u(nss_db_root_t *rootp, nss_db_initf_t initf,
	nss_getent_t *contextpp)
{
	char			*me = "nss_setent_u";
	nscd_nsw_state_t	*s;
	nscd_getent_context_t	*contextp;
	nscd_nsw_params_t	params;
	nss_db_root_t		root;
	nss_backend_t		*be;
	int			n_src, i;
	nscd_sw_return_t	*swret = NULL;

	_NSCD_LOG(NSCD_LOG_SWITCH_ENGINE, NSCD_LOG_LEVEL_DEBUG)
	(me, "rootp = %p, initf = %p, contextpp = %p \n",
		rootp, initf, contextpp);

	/* get the nsw db index via the initf function */
	(void) getparams(-1, initf, &params);

	/* get address of the switch engine return data area */
	if (initf == nscd_initf)
		swret = (nscd_sw_return_t *)params.p.private;

	/* if no privilege to look up, return */
	if (params.privdb == 1 && swret != NULL &&
		((nss_pheader_t *)(swret->pbuf))->p_euid != 0) {

		_NSCD_LOG(NSCD_LOG_SWITCH_ENGINE, NSCD_LOG_LEVEL_DEBUG)
		(me, "no privilege \n");
		return;
	}

	if ((contextp = (nscd_getent_context_t *)contextpp->ctx) == 0) {
		if ((_nscd_get_getent_ctx(contextpp, &params)) !=
			NSCD_SUCCESS) {
			return;
		}
		contextp = (nscd_getent_context_t *)contextpp->ctx;
	}
	s = contextp->nsw_state;

	if (s == 0) {
		if (_nscd_get_nsw_state(&root, &params) !=
				NSCD_SUCCESS) {
			return;
		}
		s = (nscd_nsw_state_t *)root.s;
		contextp->nsw_state = s;

	} else {
		s	= contextp->nsw_state;
		n_src	= contextp->n_src;
		be	= contextp->be;
		if (n_src == 0 && be != 0) {
			/*
			 * Optimization:  don't do endent, don't change
			 *   backends, just do the setent.  Look Ma, no locks
			 *   (nor any context that needs updating).
			 */
			(void) NSS_INVOKE_DBOP(be, NSS_DBOP_SETENT, 0);
			return;
		}
		if (n_src < s->max_src && be != 0) {
			(void) NSS_INVOKE_DBOP(be, NSS_DBOP_ENDENT, 0);
			contextp->be = 0;	/* Play it safe */
		}
	}
	for (n_src = 0, be = 0; n_src < s->max_src &&
		(be = s->be[n_src]) == 0; n_src++) {
		;
	}

	contextp->n_src	= n_src;
	contextp->be	= be;

	if (be == 0) {
		/* Things are broken enough that we can't do setent/getent */
		nss_endent_u(rootp, initf, contextpp);
		return;
	}

	/*
	 * make sure all the backends are supported
	 */
	for (i = 0; i < s->max_src; i++) {
		int	st, srci;

		srci = (*s->nsw_cfg_p)->src_idx[i];
		st = _nscd_get_smf_state(srci, params.dbi, 1);
		if (st == NSCD_SVC_STATE_UNKNOWN_SRC ||
				st == NSCD_SVC_STATE_UNINITED) {
			nss_endent_u(rootp, initf, contextpp);

			_NSCD_LOG(NSCD_LOG_SWITCH_ENGINE,
				NSCD_LOG_LEVEL_DEBUG)
			(me, "backend (%s) not available (state = %d)\n",
			NSCD_NSW_SRC_NAME(srci), st);

			return;
		}
	}

	(void) NSS_INVOKE_DBOP(be, NSS_DBOP_SETENT, 0);
}

nss_status_t
nss_getent_u(nss_db_root_t *rootp, nss_db_initf_t initf,
	nss_getent_t *contextpp, void *args)
{
	char			*me = "nss_getent_u";
	nscd_nsw_state_t	*s;
	nscd_getent_context_t	*contextp;
	int			n_src;
	nss_backend_t		*be;

	_NSCD_LOG(NSCD_LOG_SWITCH_ENGINE, NSCD_LOG_LEVEL_DEBUG)
	(me, "rootp = %p, initf = %p, contextpp = %p, args = %p\n",
		rootp, initf, contextpp, args);

	if ((contextp = (nscd_getent_context_t *)contextpp->ctx) == 0) {
		nss_setent_u(rootp, initf, contextpp);
		if ((contextp = (nscd_getent_context_t *)contextpp->ctx) == 0) {
			/* Give up */
			_NSCD_LOG(NSCD_LOG_SWITCH_ENGINE,
				NSCD_LOG_LEVEL_ERROR)
			(me, "not able to obtain getent context ... give up\n");

			return (NSS_UNAVAIL);
		}
	}

	s	= contextp->nsw_state;
	n_src	= contextp->n_src;
	be	= contextp->be;

	if (s == 0) {
		/*
		 * We've done an end_iter() and haven't done nss_setent()
		 * or nss_endent() since;  we should stick in this state
		 * until the caller invokes one of those two routines.
		 */
		return (NSS_SUCCESS);
	}

	while (n_src < s->max_src) {
		nss_status_t		res;
		struct __nsw_lookup_v1	*lkp = NULL;
		int			n;

		/* get the nsw config for the current source */
		lkp = s->config->lookups;
		for (n = 0; n < n_src; n++)
			lkp = lkp->next;

		if (be == 0) {
			/* If it's null it's a bug, but let's play safe */
			res = NSS_UNAVAIL;
		} else {
			_NSCD_LOG(NSCD_LOG_SWITCH_ENGINE,
					NSCD_LOG_LEVEL_DEBUG)
			(me, "database: %s, backend: %s, nsswitch config: %s\n",
				NSCD_NSW_DB_NAME(s->dbi),
				lkp->service_name,
				(*s->nsw_cfg_p)->nsw_cfg_str);

			res = NSS_INVOKE_DBOP(be, NSS_DBOP_GETENT, args);
		}

		if (__NSW_ACTION_V1(lkp, res) == __NSW_RETURN) {
			if (res != __NSW_SUCCESS) {
				end_iter_u(rootp,
					(struct nss_getent_context *)contextp);
			}
			return (res);
		}
		(void) NSS_INVOKE_DBOP(be, NSS_DBOP_ENDENT, 0);
		do {
			n_src++;
		} while (n_src < s->max_src &&
				(be = s->be[n_src]) == 0);
		if (be == 0) {
			/*
			 * This is the case where we failed to get the backend
			 * for the last source. We exhausted all sources.
			 */
			nss_endent_u(rootp, initf, contextpp);
			return (NSS_SUCCESS);
		}
		contextp->n_src	= n_src;
		contextp->be	= be;
		(void) NSS_INVOKE_DBOP(be, NSS_DBOP_SETENT, 0);
	}
	/* Got to the end of the sources without finding another entry */
	end_iter_u(rootp, (struct nss_getent_context *)contextp);
	return (NSS_SUCCESS);
	/* success is either a successful entry or end of the sources */
}

/*ARGSUSED*/
void
nss_endent_u(nss_db_root_t *rootp, nss_db_initf_t initf,
	nss_getent_t *contextpp)
{
	char			*me = "nss_endent_u";
	nscd_getent_context_t	*contextp;

	_NSCD_LOG(NSCD_LOG_SWITCH_ENGINE, NSCD_LOG_LEVEL_DEBUG)
	(me, "rootp = %p, initf = %p, contextpp = %p \n",
		rootp, initf, contextpp);

	if ((contextp = (nscd_getent_context_t *)contextpp->ctx) == 0) {
		/* nss_endent() on an unused context is a no-op */
		return;
	}
	end_iter_u(rootp, (struct nss_getent_context *)contextp);
	_nscd_put_getent_ctx(contextp);
	contextpp->ctx = NULL;
}

/*
 * _nss_db_state_destr() and nss_delete() do nothing in nscd
 * but is needed to make the caller (below nscd) happy
 */
/*ARGSUSED*/
void
_nss_db_state_destr(struct nss_db_state *s)
{
	/* nsw state in nscd is always reused, so do nothing here */
}

/*ARGSUSED*/
void
nss_delete(nss_db_root_t *rootp)
{
	/*
	 * the only resource kept tracked by the nss_db_root_t
	 * is the nsw state which is always reused and no need
	 * to be freed. So just return.
	 */
}

/*
 * Start of nss_psearch/nss_psetent()/nss_pgetent()/nss_pendent()
 * buffers switch entry points
 */

/*
 * nss_psearch opens a packed structure header, assembles a local
 * nss_XbyY_args_t structure and calls the local copy of nss_search.
 * The return data is assembled in "files native format" in the
 * return buffer location.  Status if packed back up with the buffer
 * and the whole wad is returned to the cache or the client.
 */

void
nss_psearch(void *buffer, size_t length)
{
	/* inputs */
	nss_db_initf_t		initf;
	int			dbop;
	int			rc;
	nss_XbyY_args_t		arg;
	nss_status_t		status;
	nscd_sw_return_t	swret = { 0 }, *swrp = &swret;
	nss_pheader_t		*pbuf = (nss_pheader_t *)buffer;
	char			*me = "nss_psearch";

	if (buffer == NULL || length == 0) {
		NSCD_RETURN_STATUS(pbuf, NSS_ERROR, EFAULT);
	}

	status = nss_packed_arg_init(buffer, length,
			NULL, &initf, &dbop, &arg);
	if (status != NSS_SUCCESS) {
		NSCD_RETURN_STATUS(pbuf, status, -1);
	}

	/*
	 * pass the address of the return data area
	 * for the switch engine to return its own data
	 */
	(void) memcpy(&pbuf->nscdpriv, &swrp, sizeof (swrp));
	swret.pbuf = buffer;
	swret.pbufsiz = length;

	/*
	 * use the generic nscd_initf for all database lookups
	 * (the TSD key is the pointer to the packed header)
	 */
	rc = set_initf_key(pbuf);
	if (rc != 0) {
		NSCD_RETURN_STATUS(pbuf, NSS_UNAVAIL, EINVAL);
	}
	initf = nscd_initf;

	/* Perform local search and pack results into return buffer */
	/* nscd's search ignores db_root */
	status = nss_search(NULL, initf, dbop, &arg);

	/*
	 * If status is NSS_NOTFOUND and ldap also returned
	 * NSS_NOTFOUND, it is possible that the user does
	 * not have a credential, so check and see if
	 * needs to return NSS_ALTRETRY to let the main
	 * nscd get a chance to process the lookup
	 */
	if (swret.fallback == 1 && status == NSS_NOTFOUND) {
		OM_uint32 stat;

		if (gss_inquire_cred(&stat, GSS_C_NO_CREDENTIAL,
			NULL, NULL, NULL, NULL) != GSS_S_COMPLETE) {

			_NSCD_LOG(NSCD_LOG_SWITCH_ENGINE,
				NSCD_LOG_LEVEL_DEBUG)
			(me, "NSS_ALTRETRY: fallback to main nscd needed\n");

			status = NSS_ALTRETRY;
		}
	}

	NSCD_SET_STATUS(pbuf, status, -1);
	errno = swret.errnum;

	/*
	 * move result/status from args to packed buffer only if
	 * arg was being used
	 */
	if (!swret.noarg)
		nss_packed_set_status(buffer, length, status,  &arg);

	_NSCD_LOG(NSCD_LOG_SWITCH_ENGINE, NSCD_LOG_LEVEL_DEBUG)
	(me, "switch engine result: source is %s, status %d, "
	"herrno is %d, errno is %s\n",
	(swret.srci != -1) ? NSCD_NSW_SRC_NAME(swret.srci) : "<NOTSET>",
	pbuf->p_status, pbuf->p_herrno, strerror(pbuf->p_errno));

	/* clear the TSD key used by the generic initf */
	clear_initf_key();
	pbuf->nscdpriv = 0;
}

static void
nscd_map_contextp(void *buffer, nss_getent_t *contextp,
	nssuint_t **cookie_p, nssuint_t **seqnum_p, int setent)
{
	nss_pheader_t		*pbuf = (nss_pheader_t *)buffer;
	nssuint_t		off;
	nscd_getent_context_t	*ctx;
	char			*me = "nscd_map_contextp";

	struct cookie_seqnum {
		nssuint_t	cookie;
		nssuint_t	seqnum;
	} *csp;

	if (buffer == NULL) {
		NSCD_RETURN_STATUS(pbuf, NSS_ERROR, EFAULT);
	}

	off = pbuf->key_off;
	csp = (struct cookie_seqnum *)((void *)((char *)buffer + off));
	if (seqnum_p != NULL)
		*seqnum_p = &csp->seqnum;

	/*
	 * if called by nss_psetent, and the passed in cookie is
	 * NSCD_NEW_COOKIE, then there is no cookie yet, return
	 * a pointer pointing to where the cookie will be stored.
	 * Also because there is no cookie to validate, just
	 * return success.
	 *
	 * On the other hand, if a cookie is passed in, we need
	 * to validate the cookie before returning.
	 */
	if (cookie_p != NULL)
		*cookie_p = &csp->cookie;
	if (setent == 1 && csp->cookie == NSCD_NEW_COOKIE) {
		NSCD_RETURN_STATUS_SUCCESS(pbuf);
	}

	_NSCD_LOG(NSCD_LOG_SWITCH_ENGINE, NSCD_LOG_LEVEL_DEBUG)
	(me, "cookie = %lld,  sequence number = %lld\n",
		csp->cookie, csp->seqnum);

	ctx = _nscd_is_getent_ctx(csp->cookie);

	if (ctx == NULL) {
		_NSCD_LOG(NSCD_LOG_SWITCH_ENGINE, NSCD_LOG_LEVEL_DEBUG)
		(me, "invalid cookie (%lld)\n", csp->cookie);

		NSCD_RETURN_STATUS(pbuf, NSS_ERROR, EFAULT);
	}

	if (setent == 1) {
		/* if called by nss_psetent, reset the seq number */
		ctx->seq_num = 1;
	} else if (ctx->seq_num != (nscd_seq_num_t)csp->seqnum) {
		_NSCD_LOG(NSCD_LOG_SWITCH_ENGINE, NSCD_LOG_LEVEL_DEBUG)
		(me, "invalid sequence number (%lld)\n", csp->seqnum);

		NSCD_RETURN_STATUS(pbuf, NSS_ERROR, EFAULT);
	}

	contextp->ctx = (struct nss_getent_context *)ctx;

	NSCD_RETURN_STATUS_SUCCESS(pbuf);
}

void
nss_psetent(void *buffer, size_t length, pid_t pid)
{
	/* inputs */
	nss_db_initf_t		initf;
	nss_getent_t		context = { 0 };
	nss_getent_t		*contextp = &context;
	nss_status_t		status;
	nssuint_t		*cookiep;
	nssuint_t		*seqnump;
	nscd_getent_context_t	*ctx;
	int			rc;
	nss_pheader_t		*pbuf = (nss_pheader_t *)buffer;
	nscd_sw_return_t	swret = { 0 }, *swrp = &swret;
	char			*me = "nss_psetent";

	if (buffer == NULL || length == 0) {
		NSCD_RETURN_STATUS(pbuf, NSS_ERROR, EFAULT);
	}

	/*
	 * If this is a per-user nscd, and the user does not have
	 * the necessary credential, return NSS_TRYLOCAL, so the
	 * setent/getent can be done locally in the process of the
	 * setent call
	 */
	if (_whoami == NSCD_CHILD) {
		OM_uint32 stat;

		if (gss_inquire_cred(&stat, GSS_C_NO_CREDENTIAL,
			NULL, NULL, NULL, NULL) != GSS_S_COMPLETE) {

			_NSCD_LOG(NSCD_LOG_SWITCH_ENGINE,
				NSCD_LOG_LEVEL_DEBUG)
			(me, "NSS_TRYLOCAL: fallback to caller process\n");
			NSCD_RETURN_STATUS(pbuf, NSS_TRYLOCAL, 0);
		}
	}

	status = nss_packed_context_init(buffer, length,
			NULL, &initf, &contextp, (nss_XbyY_args_t *)NULL);
	if (status != NSS_SUCCESS) {
		NSCD_RETURN_STATUS(pbuf, status, -1);
	}

	/*
	 * use the generic nscd_initf for all the setent requests
	 * (the TSD key is the pointer to the packed header)
	 */
	rc = set_initf_key(pbuf);
	if (rc != 0) {
		NSCD_RETURN_STATUS(pbuf, NSS_UNAVAIL, EINVAL);
	}
	initf = nscd_initf;

	/* get address of cookie and seqnum for later updates */
	nscd_map_contextp(buffer, contextp, &cookiep, &seqnump, 1);
	if (NSCD_STATUS_IS_NOT_OK(pbuf))
		return;
	/*
	 * pass the packed header buffer pointer to nss_setent
	 */
	(void) memcpy(&pbuf->nscdpriv, &swrp, sizeof (swrp));
	swret.pbuf = buffer;

	/* Perform local setent and set context */
	nss_setent(NULL, initf, contextp);

	/* insert cookie info into buffer and return */
	ctx = (nscd_getent_context_t *)contextp->ctx;
	if (ctx != NULL) {
		*cookiep = ctx->cookie;
		*seqnump = (nssuint_t)ctx->seq_num;
		ctx->pid = pid;
	} else {
		/*
		 * not able to allocate a getent context, the
		 * client should try the enumeration locally
		 */
		*cookiep = NSCD_LOCAL_COOKIE;
		*seqnump = 0;
	}

	_NSCD_LOG(NSCD_LOG_SWITCH_ENGINE, NSCD_LOG_LEVEL_DEBUG)
	(me, "cookie = %lld,  sequence number = %lld\n",
		*cookiep, *seqnump);

	if (ctx != NULL) {
		_NSCD_LOG(NSCD_LOG_SWITCH_ENGINE, NSCD_LOG_LEVEL_DEBUG)
		(me, "cookie = %lld,  sequence number = %lld\n",
		ctx->cookie, ctx->seq_num);
	}

	/* clear the TSD key used by the generic initf */
	clear_initf_key();

	if (*cookiep == NSCD_LOCAL_COOKIE) {
		NSCD_RETURN_STATUS(pbuf, NSS_TRYLOCAL, 0);
	} else {
		NSCD_RETURN_STATUS(pbuf, NSS_SUCCESS, 0);
	}
}

void
nss_pgetent(void *buffer, size_t length)
{
	/* inputs */
	nss_db_initf_t		initf;
	nss_getent_t		context;
	nss_getent_t		*contextp = &context;
	nss_XbyY_args_t		arg;
	nss_status_t		status;
	nssuint_t		*cookiep;
	nssuint_t		*seqnump;
	nscd_getent_context_t	*ctx;
	int			rc;
	nss_pheader_t		*pbuf = (nss_pheader_t *)buffer;
	char			*me = "nss_pgetent";

	if (buffer == NULL || length == 0) {
		NSCD_RETURN_STATUS(pbuf, NSS_ERROR, EFAULT);
	}

	status = nss_packed_context_init(buffer, length,
			NULL, &initf, &contextp, &arg);
	if (status != NSS_SUCCESS) {
		NSCD_RETURN_STATUS(pbuf, status, -1);
	}

	/*
	 * use the generic nscd_initf for all the getent requests
	 * (the TSD key is the pointer to the packed header)
	 */
	rc = set_initf_key(pbuf);
	if (rc != 0) {
		NSCD_RETURN_STATUS(pbuf, NSS_UNAVAIL, EINVAL);
	}
	initf = nscd_initf;


	/* verify the cookie passed in */
	nscd_map_contextp(buffer, contextp, &cookiep, &seqnump, 0);
	if (NSCD_STATUS_IS_NOT_OK(pbuf))
		return;

	/* Perform local search and pack results into return buffer */
	status = nss_getent(NULL, initf, contextp, &arg);
	NSCD_SET_STATUS(pbuf, status, -1);
	nss_packed_set_status(buffer, length, status,  &arg);

	/* increment sequence number in the buffer and nscd context */
	if (status == NSS_SUCCESS) {
		ctx = (nscd_getent_context_t *)contextp->ctx;
		ctx->seq_num++;
		*seqnump = ctx->seq_num;
		*cookiep = ctx->cookie;

		_NSCD_LOG(NSCD_LOG_SWITCH_ENGINE, NSCD_LOG_LEVEL_DEBUG)
		(me, "getent OK, new sequence number = %lld, len = %lld,"
		" data = [ %s ]\n", *seqnump,
		pbuf->data_len, (char *)buffer + pbuf->data_off);
	} else {
		ctx = (nscd_getent_context_t *)contextp->ctx;
		_NSCD_LOG(NSCD_LOG_SWITCH_ENGINE, NSCD_LOG_LEVEL_DEBUG)
		(me, "getent failed, status = %d, sequence number = %lld\n",
			status, *seqnump);
	}

	/* clear the TSD key used by the generic initf */
	clear_initf_key();
}

void
nss_pendent(void *buffer, size_t length)
{
	nss_getent_t		context;
	nss_getent_t		*contextp = &context;
	nssuint_t		*seqnump;
	nssuint_t		*cookiep;
	nss_pheader_t		*pbuf = (nss_pheader_t *)buffer;
	char			*me = "nss_pendent";

	if (buffer == NULL || length == 0) {
		NSCD_RETURN_STATUS(pbuf, NSS_ERROR, EFAULT);
	}

	/* map the contextp from the cookie information */
	nscd_map_contextp(buffer, contextp, &cookiep, &seqnump, 0);
	if (NSCD_STATUS_IS_NOT_OK(pbuf))
		return;

	_NSCD_LOG(NSCD_LOG_SWITCH_ENGINE, NSCD_LOG_LEVEL_DEBUG)
	(me, "endent, cookie = %lld, sequence number = %lld\n",
		*cookiep, *seqnump);

	/* Perform local endent and reset context */
	nss_endent(NULL, NULL, contextp);
	NSCD_RETURN_STATUS(pbuf, NSS_SUCCESS, 0);
}

/*ARGSUSED*/
void
nss_pdelete(void *buffer, size_t length)
{
	nss_pheader_t	*pbuf = (nss_pheader_t *)buffer;

	/* unnecessary, kept for completeness */
	NSCD_RETURN_STATUS_SUCCESS(pbuf);
}
