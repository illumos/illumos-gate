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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2012 Milan Jurik. All rights reserved.
 */

#include <stdlib.h>	/* getenv() */
#include <assert.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
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

static thread_key_t loopback_key = THR_ONCE_KEY;
typedef struct lb_key {
	int		srci;
	int		dbi;
	int		fnum;
	int		*lb_flagp;
} lb_key_t;

static int
set_loopback_key(lb_key_t *key) {

	int		rc;

	rc = thr_keycreate_once(&loopback_key, NULL);
	/* set key if not already set */
	if (rc == 0 && pthread_getspecific(loopback_key) == NULL)
		rc = thr_setspecific(loopback_key, key);

	return (rc);
}

static lb_key_t *
get_loopback_key(void) {

	char		*me = "get_loopback_key";
	lb_key_t	*k = NULL;

	k = pthread_getspecific(loopback_key);

	_NSCD_LOG(NSCD_LOG_SWITCH_ENGINE, NSCD_LOG_LEVEL_DEBUG)
	(me, "get loopback key, key = %p\n", k);

	return (k);
}

static void
clear_loopback_key(lb_key_t *key) {

	char		*me = "clear_loopback_key";

	if (loopback_key != THR_ONCE_KEY && key != NULL) {
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

static thread_key_t initf_key = THR_ONCE_KEY;

static int
set_initf_key(void *pbuf) {

	int		rc;

	rc = thr_keycreate_once(&initf_key, NULL);
	if (rc == 0)
		rc = thr_setspecific(initf_key, pbuf);

	return (rc);
}

static void *
get_initf_key(void) {

	char		*me = "get_initf_key";
	void		*pbuf;

	pbuf = pthread_getspecific(initf_key);

	_NSCD_LOG(NSCD_LOG_SWITCH_ENGINE, NSCD_LOG_LEVEL_DEBUG)
	(me, "got initf pbuf, key = %p\n", pbuf);

	return (pbuf);
}

static void
clear_initf_key(void) {

	char		*me = "clear_initf_key";

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
	char		*me = "getparams";

	p = &params->p;
	(void) memset(params, 0, sizeof (nscd_nsw_params_t));
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

	/*
	 * if unsupported database, let caller determine what to do next
	 */
	if (params->dbi == -1) {
		_NSCD_LOG(NSCD_LOG_SWITCH_ENGINE, NSCD_LOG_LEVEL_DEBUG)
		(me, "unsupported database: %s\n", p->name);
		return (NSCD_CFG_UNSUPPORTED_SWITCH_DB);
	}

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
	char	*data_str = "<NOT STRING FORMAT>";
	int	data_len = 0;
	char	*me = "trace_result";

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

	if (arg->buf.result == NULL) {
		data_str = arg->buf.buffer;
		data_len = arg->returnlen;
	}

	if (res == NSS_SUCCESS) {
		_nscd_logit(me, "%s: database: %s, operation: %d, "
		    "source: %s returned >>%s<<, length = %d\n",
		    res_str, db, op, src, data_str, data_len);
		return;
	}

	_nscd_logit(me, "%s: database: %s, operation: %d, source: %s, "
	    "erange= %d, herrno: %s (%d)\n",
	    res_str, db, op, src, arg->erange, hstrerror(arg->h_errno),
	    arg->h_errno);
}

/*
 * Determine if a request should be done locally in the getXbyY caller's
 * process. Return none zero if yes, 0 otherwise. This should be called
 * before the switch engine steps through the backends/sources.
 * This function returns 1 if:
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
		if ((ep = ap->key.attrp) != NULL && IS_GET_ALL(ep->search_flag))
			rc = 1;
	}

	if (rc != 0) {

		_NSCD_LOG(NSCD_LOG_SWITCH_ENGINE, NSCD_LOG_LEVEL_DEBUG)
		(me, "TRYLOCAL: exec_attr:GET_ALL\n");
	}

	return (rc);
}

/*
 * Determine if a request should be done locally in the getXbyY caller's
 * process. Return none zero if yes, 0 otherwise. This should be called
 * before the switch engine invokes any backend.
 * This function returns 1 if:
 *   -- the database is shadow and the source is compat
 */
static int
try_local2(
	int	dbi,
	int	srci)
{
	int	rc = 0;
	char	*me = "try_local2";

	if (*NSCD_NSW_DB_NAME(dbi) == 's' &&
	    strcmp(NSCD_NSW_DB_NAME(dbi), NSS_DBNAM_SHADOW) == 0) {
		if (strcmp(NSCD_NSW_SRC_NAME(srci), "compat") == 0)
			rc = 1;
	}

	if (rc != 0) {
		_NSCD_LOG(NSCD_LOG_SWITCH_ENGINE, NSCD_LOG_LEVEL_DEBUG)
		(me, "TRYLOCAL: database: shadow, source: %s\n",
		    NSCD_NSW_SRC_NAME(srci));
	}

	return (rc);
}

static nscd_rc_t
get_lib_func(void **handle, void **func, mutex_t *lock,
	char *lib, char *name, void **func_p)
{
	char	*me = "get_lib_func";
	void	*sym;

	if (func_p != NULL && *handle != NULL && *func != NULL) {
		*func_p = *func;
		return (NSCD_SUCCESS);
	}

	(void) mutex_lock(lock);

	/* close the handle if requested */
	if (func_p == NULL) {
		if (*handle != NULL) {
			(void) dlclose(*handle);
			*handle = NULL;
			*func = NULL;
		}
		(void) mutex_unlock(lock);
		return (NSCD_SUCCESS);
	}

	if (*handle != NULL && *func != NULL) {
		*func_p = *func;
		(void) mutex_unlock(lock);
		return (NSCD_SUCCESS);
	}

	if (*handle == NULL) {
		*handle = dlopen(lib, RTLD_LAZY);
		if (*handle == NULL) {
			_NSCD_LOG(NSCD_LOG_SWITCH_ENGINE, NSCD_LOG_LEVEL_ERROR)
			(me, "unable to dlopen %s\n", lib);
			(void) mutex_unlock(lock);
			return (NSCD_CFG_DLOPEN_ERROR);
		}
	}

	if ((sym = dlsym(*handle, name)) == NULL) {

		_NSCD_LOG(NSCD_LOG_SWITCH_ENGINE, NSCD_LOG_LEVEL_ERROR)
		(me, "unable to find symbol %s:%s\n", lib, name);
		(void) mutex_unlock(lock);
		return (NSCD_CFG_DLSYM_ERROR);
	} else {
		*func_p = sym;
		*func = sym;
	}

	(void) mutex_unlock(lock);
	return (NSCD_SUCCESS);
}

static nscd_rc_t
get_libc_nss_search(void **func_p)
{
	static void	*handle = NULL;
	static void	*func = NULL;
	static mutex_t	lock = DEFAULTMUTEX;

	return (get_lib_func(&handle, &func, &lock,
	    "libc.so", "nss_search", func_p));
}

static nscd_rc_t
get_gss_func(void **func_p)
{
	static void	*handle = NULL;
	static void	*func = NULL;
	static mutex_t	lock = DEFAULTMUTEX;

	return (get_lib_func(&handle, &func, &lock,
	    "libgss.so", "gss_inquire_cred", func_p));
}

static nscd_rc_t
get_sldap_shadow_func(void **func_p)
{
	static void	*handle = NULL;
	static void	*func = NULL;
	static mutex_t	lock = DEFAULTMUTEX;

	return (get_lib_func(&handle, &func, &lock,
	    "libsldap.so", "__ns_ldap_is_shadow_update_enabled",
	    func_p));
}

/*
 * get_dns_funcs returns pointers to gethostbyname functions in the
 * dynamically loaded nss_dns & nss_mdns modules that return host
 * lookup results along with the TTL value in the DNS resource
 * records. The dnsi parameter indicates whether the lookup database
 * is hosts(0) or ipnodes(1). The srcname parameter identifies the DNS
 * module: dns/mdns and the function returns the address of the specific
 * gethostbyname function in func_p variable.
 */
static nscd_rc_t
get_dns_funcs(int dnsi, nss_status_t (**func_p)(), const char *srcname)
{
	int		si;
	void		**funcpp;
	static void	*handle[2] = { NULL, NULL };
	static mutex_t	func_lock[2] = { DEFAULTMUTEX, DEFAULTMUTEX };
	static void 	*func[2][2] = {{NULL, NULL}, {NULL, NULL}};
	static const char	*lib[2] = { "nss_dns.so.1", "nss_mdns.so.1" };
	static const char 	*func_name[2][2] =
		{{ "_nss_get_dns_hosts_name", "_nss_get_dns_ipnodes_name" },
		{ "_nss_get_mdns_hosts_name", "_nss_get_mdns_ipnodes_name" }};

	/* source index: 0 = dns, 1 = mdns */
	if (strcmp(srcname, "dns") == 0)
		si = 0;
	else
		si = 1;

	/*
	 * function index (func[si][dnsi]):
	 * [0,0] = dns/hosts, [0,1] = dns/ipnodes,
	 * [1,0] = mdns/hosts, [1,1] = mdns/ipnodes
	 */

	if (dnsi < 0) { /* close handle */
		funcpp = NULL;
		(void) mutex_lock(&func_lock[si]);
		func[si][0] = NULL;
		func[si][1] = NULL;
		(void) mutex_unlock(&func_lock[si]);
	} else
		funcpp = (void **)func_p;

	return (get_lib_func(&handle[si], &func[si][dnsi], &func_lock[si],
	    (char *)lib[si], (char *)func_name[si][dnsi], funcpp));
}

static nss_status_t
search_dns_withttl(nscd_sw_return_t *swret, const char *srcname, int dnsi)
{
	nss_status_t	(*func)();
	nss_status_t	res = NSS_UNAVAIL;
	nscd_rc_t	rc;

	swret->noarg = 0;
	if (strcmp(srcname, "dns") != 0 && strcmp(srcname, "mdns") != 0)
		return (NSS_ERROR);

	rc = get_dns_funcs(dnsi, &func, srcname);
	if (rc == NSCD_SUCCESS) {
		/*
		 * data_len in the packed buf header may be changed
		 * by the dns or mdns backend, reset it just in
		 * case
		 */
		((nss_pheader_t *)swret->pbuf)->data_len =
		    swret->datalen;
		res = (func)(NULL, &swret->pbuf, &swret->pbufsiz);
	}
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
	if (getparams(search_fnum, initf, &params) ==
	    NSCD_CFG_UNSUPPORTED_SWITCH_DB) {
		/*
		 * if unsupported database and the request is from the
		 * the door, tell the door client to try it locally
		 */
		if (initf == nscd_initf) {
			res = NSS_TRYLOCAL;
			goto error_exit;
		} else { /* otherwise, let libc:nss_search() handle it */
			nss_status_t	(*func)();

			if (get_libc_nss_search((void **)&func) ==
			    NSCD_SUCCESS)
				return ((func)(rootp, initf, search_fnum,
				    search_args));
			else
				goto error_exit;
		}
	}
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
	 * for door request that should be processed by the client,
	 * send it back with status NSS_TRYLOCAL
	 */
	if (initf == nscd_initf && try_local(dbi, search_args) == 1) {
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
	(me, "database = %s, config = >>%s<<\n", NSCD_NSW_DB_NAME(dbi),
	    (*s->nsw_cfg_p)->nsw_cfg_str);

	for (n_src = 0;  n_src < s->max_src;  n_src++) {
		nss_backend_t		*be = NULL;
		nss_backend_op_t	funcp = NULL;
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

		/*
		 * If no privilege to look up, skip.
		 * 'files' requires PRIV_FILE_DAC_READ to read shadow(4) data,
		 * 'ldap' requires all zones privilege.
		 */
		if (params.privdb == 1 && swret != NULL) {
			boolean_t	(*is_shadow_update_enabled)();
			boolean_t	check_ldap_priv = B_FALSE;

			if (strcmp(NSCD_NSW_SRC_NAME(srci), "ldap") == 0) {
				if (get_sldap_shadow_func(
				    (void **)&is_shadow_update_enabled) ==
				    NSCD_SUCCESS &&
				    is_shadow_update_enabled()) {
					check_ldap_priv = B_TRUE;

					/*
					 * A peruser nscd doesn't have
					 * the privileges to lookup a
					 * private database, such as shadow,
					 * returns NSS_ALTRETRY to have the
					 * main nscd do the job.
					 */
					if (_whoami == NSCD_CHILD) {
						res = NSS_ALTRETRY;
						goto free_nsw_state;
					}
				}
			}

			if ((strcmp(NSCD_NSW_SRC_NAME(srci), "files") == 0 &&
			    _nscd_check_client_priv(NSCD_READ_PRIV) != 0) ||
			    (check_ldap_priv &&
			    _nscd_check_client_priv(NSCD_ALL_PRIV) != 0)) {
				_NSCD_LOG(NSCD_LOG_SWITCH_ENGINE,
				    NSCD_LOG_LEVEL_DEBUG)
				(me, "no privilege to look up, skip source\n");

				goto next_src;
			}
		}

		/* get state of the (backend) client service */
		smf_state = _nscd_get_smf_state(srci, dbi, 0);

		/* stop if the source is one that should be TRYLOCAL */
		if (initf == nscd_initf &&	/* request is from the door */
		    (smf_state == NSCD_SVC_STATE_UNSUPPORTED_SRC ||
		    (smf_state == NSCD_SVC_STATE_FOREIGN_SRC &&
		    s->be_version_p[n_src] == NULL) ||
		    (params.privdb && try_local2(dbi, srci) == 1))) {
			_NSCD_LOG(NSCD_LOG_SWITCH_ENGINE, NSCD_LOG_LEVEL_DEBUG)
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

		/* request could be from within nscd so check states again */
		if (be == NULL || (params.dnsi < 0 && (funcp == NULL ||
		    (smf_state != NSCD_SVC_STATE_UNINITED &&
		    smf_state != NSCD_SVC_STATE_UNSUPPORTED_SRC &&
		    smf_state != NSCD_SVC_STATE_FOREIGN_SRC &&
		    smf_state < SCF_STATE_ONLINE)))) {

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
				    NSCD_NSW_SRC_NAME(srci), params.dnsi);
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

	/*
	 * Get the nsw db index via the initf function. If unsupported
	 * database, no need to continue
	 */
	if (getparams(-1, initf, &params) == NSCD_CFG_UNSUPPORTED_SWITCH_DB)
		return;

	/* get address of the switch engine return data area */
	if (initf == nscd_initf)
		swret = (nscd_sw_return_t *)params.p.private;

	/* if no privilege to look up, return */
	if (params.privdb == 1 && swret != NULL &&
	    _nscd_check_client_priv(NSCD_READ_PRIV) != 0) {

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

		if (s->be[i] == NULL)
			continue;

		srci = (*s->nsw_cfg_p)->src_idx[i];
		st = _nscd_get_smf_state(srci, params.dbi, 1);
		if (st == NSCD_SVC_STATE_UNSUPPORTED_SRC ||
		    (st == NSCD_SVC_STATE_FOREIGN_SRC &&
		    s->be_version_p[i] == NULL && initf == nscd_initf) ||
		    st == NSCD_SVC_STATE_UNINITED ||
		    (params.privdb &&
		    try_local2(params.dbi, srci) == 1)) {
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
			return (NSS_NOTFOUND);
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

	if (_nscd_is_getent_ctx_in_use(contextp) == 0) {
		end_iter_u(rootp, (struct nss_getent_context *)contextp);
		_nscd_put_getent_ctx(contextp);
		contextpp->ctx = NULL;
	}
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
		NSCD_SET_STATUS(pbuf, NSS_ERROR, EFAULT);
		return;
	}

	status = nss_packed_arg_init(buffer, length,
	    NULL, &initf, &dbop, &arg);
	if (status != NSS_SUCCESS) {
		NSCD_SET_STATUS(pbuf, status, -1);
		return;
	}

	/*
	 * pass the address of the return data area
	 * for the switch engine to return its own data
	 */
	(void) memcpy(&pbuf->nscdpriv, &swrp, sizeof (swrp));
	swret.pbuf = buffer;
	swret.pbufsiz = length;
	swret.datalen = pbuf->data_len;

	/*
	 * use the generic nscd_initf for all database lookups
	 * (the TSD key is the pointer to the packed header)
	 */
	rc = set_initf_key(pbuf);
	if (rc != 0) {
		NSCD_SET_STATUS(pbuf, NSS_UNAVAIL, EINVAL);
		return;
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
		OM_uint32	(*func)();
		OM_uint32	stat;
		nscd_rc_t	rc;

		rc = get_gss_func((void **)&func);
		if (rc == NSCD_SUCCESS) {
			if (func(&stat, GSS_C_NO_CREDENTIAL,
			    NULL, NULL, NULL, NULL) != GSS_S_COMPLETE) {

				_NSCD_LOG(NSCD_LOG_SWITCH_ENGINE,
				    NSCD_LOG_LEVEL_DEBUG)
			(me, "NSS_ALTRETRY: fallback to main nscd needed\n");

				status = NSS_ALTRETRY;
			}
		}
	}

	NSCD_SET_STATUS(pbuf, status, -1);
	errno = swret.errnum;

	/*
	 * Move result/status from args to packed buffer only if
	 * arg was being used and rc from the switch engine is not
	 * NSS_TRYLOCAL.
	 */
	if (!swret.noarg && status != NSS_TRYLOCAL)
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
    nssuint_t **cookie_num_p, nssuint_t **seqnum_p, int setent)
{
	nss_pheader_t		*pbuf = (nss_pheader_t *)buffer;
	nssuint_t		off;
	nscd_getent_context_t	*ctx;
	char			*me = "nscd_map_contextp";
	nscd_getent_p1_cookie_t	*cookie;

	if (buffer == NULL) {
		NSCD_SET_STATUS(pbuf, NSS_ERROR, EFAULT);
		return;
	}

	off = pbuf->key_off;
	cookie = (nscd_getent_p1_cookie_t *)((void *)((char *)buffer + off));
	if (seqnum_p != NULL)
		*seqnum_p = &cookie->p1_seqnum;

	/*
	 * if called by nss_psetent, and the passed in cookie number
	 * is NSCD_NEW_COOKIE, then there is no cookie yet, return a
	 * pointer pointing to where the cookie number will be stored.
	 * Also because there is no cookie to validate, just return
	 * success.
	 *
	 * On the other hand, if a cookie number is passed in, we need
	 * to validate the cookie number before returning.
	 */
	if (cookie_num_p != NULL)
		*cookie_num_p = &cookie->p1_cookie_num;
	if (setent == 1 && cookie->p1_cookie_num == NSCD_NEW_COOKIE) {
		NSCD_SET_STATUS_SUCCESS(pbuf);
		return;
	}

	/*
	 * If the sequence number and start time match nscd's p0 cookie,
	 * then either setent was done twice in a row or this is the
	 * first getent after the setent, return success as well.
	 */
	if (cookie->p1_seqnum == NSCD_P0_COOKIE_SEQNUM) {
		nscd_getent_p0_cookie_t *p0c =
		    (nscd_getent_p0_cookie_t *)cookie;
		if (p0c->p0_time == _nscd_get_start_time()) {
			NSCD_SET_STATUS_SUCCESS(pbuf);
			return;
		}
	}

	_NSCD_LOG(NSCD_LOG_SWITCH_ENGINE, NSCD_LOG_LEVEL_DEBUG)
	(me, "cookie # = %lld,  sequence # = %lld\n",
	    cookie->p1_cookie_num, cookie->p1_seqnum);

	ctx = _nscd_is_getent_ctx(cookie->p1_cookie_num);

	if (ctx == NULL) {
		_NSCD_LOG(NSCD_LOG_SWITCH_ENGINE, NSCD_LOG_LEVEL_DEBUG)
		(me, "No matching context found (cookie number: %lld)\n",
		    cookie->p1_cookie_num);

		NSCD_SET_STATUS(pbuf, NSS_ERROR, EFAULT);
		return;
	}

	/* if not called by nss_psetent, verify sequence number */
	if (setent != 1 && ctx->seq_num !=
	    (nscd_seq_num_t)cookie->p1_seqnum) {
		_NSCD_LOG(NSCD_LOG_SWITCH_ENGINE, NSCD_LOG_LEVEL_DEBUG)
		(me, "invalid sequence # (%lld)\n", cookie->p1_seqnum);

		_nscd_free_ctx_if_aborted(ctx);
		NSCD_SET_STATUS(pbuf, NSS_ERROR, EFAULT);
		return;
	}

	contextp->ctx = (struct nss_getent_context *)ctx;

	NSCD_SET_STATUS_SUCCESS(pbuf);
}

void
nss_psetent(void *buffer, size_t length, pid_t pid)
{
	nss_getent_t		context = { 0 };
	nss_getent_t		*contextp = &context;
	nssuint_t		*cookie_num_p;
	nssuint_t		*seqnum_p;
	nss_pheader_t		*pbuf = (nss_pheader_t *)buffer;
	nscd_getent_p0_cookie_t *p0c;
	char			*me = "nss_psetent";

	if (buffer == NULL || length == 0) {
		NSCD_SET_STATUS(pbuf, NSS_ERROR, EFAULT);
		return;
	}

	/*
	 * If this is a per-user nscd, and the user does not have
	 * the necessary credential, return NSS_TRYLOCAL, so the
	 * setent/getent can be done locally in the process of the
	 * setent call
	 */
	if (_whoami == NSCD_CHILD) {
		OM_uint32	(*func)();
		OM_uint32	stat;
		nscd_rc_t	rc;

		rc = get_gss_func((void **)&func);
		if (rc == NSCD_SUCCESS) {
			if (func(&stat, GSS_C_NO_CREDENTIAL,
			    NULL, NULL, NULL, NULL) != GSS_S_COMPLETE) {

				_NSCD_LOG(NSCD_LOG_SWITCH_ENGINE,
				    NSCD_LOG_LEVEL_DEBUG)
			(me, "NSS_TRYLOCAL: fallback to caller process\n");
				NSCD_SET_STATUS(pbuf, NSS_TRYLOCAL, 0);
				return;
			}
		}
	}

	/* check cookie number */
	nscd_map_contextp(buffer, contextp, &cookie_num_p, &seqnum_p, 1);
	if (NSCD_STATUS_IS_NOT_OK(pbuf))
		return;

	/* set cookie number and sequence number */
	p0c = (nscd_getent_p0_cookie_t *)cookie_num_p;
	if (contextp->ctx ==  NULL) {
		/*
		 * first setent (no existing getent context),
		 * return a p0 cookie
		 */
		_NSCD_LOG(NSCD_LOG_SWITCH_ENGINE, NSCD_LOG_LEVEL_DEBUG)
		(me, "first setent, no getent context yet\n");
	} else {
		/*
		 * doing setent on an existing getent context,
		 * release resources allocated and return a
		 * p0 cookie
		 */
		_NSCD_LOG(NSCD_LOG_SWITCH_ENGINE, NSCD_LOG_LEVEL_DEBUG)
		(me, "setent resetting sequence number = %lld\n",  *seqnum_p);

		if (_nscd_is_getent_ctx_in_use((nscd_getent_context_t *)
		    contextp->ctx) == 0) {
			/*
			 * context not in use, release the backend and
			 * return the context to the pool
			 */
			end_iter_u(NULL, contextp->ctx);
			_nscd_put_getent_ctx(
			    (nscd_getent_context_t *)contextp->ctx);
			contextp->ctx = NULL;
		}
	}

	p0c->p0_pid = pid;
	p0c->p0_time = _nscd_get_start_time();
	p0c->p0_seqnum = NSCD_P0_COOKIE_SEQNUM;
	_NSCD_LOG(NSCD_LOG_SWITCH_ENGINE, NSCD_LOG_LEVEL_DEBUG)
	(me, "returning a p0 cookie: pid = %ld, time = %ld, seq #= %llx\n",
	    p0c->p0_pid, p0c->p0_time, p0c->p0_seqnum);

	NSCD_SET_STATUS(pbuf, NSS_SUCCESS, 0);
}

static void
delayed_setent(nss_pheader_t *pbuf, nss_db_initf_t initf,
	nss_getent_t *contextp, nssuint_t *cookie_num_p,
	nssuint_t *seqnum_p, pid_t pid)
{
	nscd_getent_context_t	*ctx;
	nscd_sw_return_t	swret = { 0 }, *swrp = &swret;
	char			*me = "delayed_setent";

	/*
	 * check credential
	 */
	_nscd_APP_check_cred(pbuf, &pid, "NSCD_DELAYED_SETENT",
	    NSCD_LOG_SWITCH_ENGINE, NSCD_LOG_LEVEL_ERROR);
	if (NSCD_STATUS_IS_NOT_OK(pbuf)) {
		_NSCD_LOG(NSCD_LOG_SWITCH_ENGINE, NSCD_LOG_LEVEL_DEBUG)
		(me, "invalid credential\n");
		return;
	}

	/*
	 * pass the packed header buffer pointer to nss_setent
	 */
	(void) memcpy(&pbuf->nscdpriv, &swrp, sizeof (swrp));
	swret.pbuf = pbuf;

	/* Perform local setent and set context */
	nss_setent(NULL, initf, contextp);

	/* insert cookie info into packed buffer header */
	ctx = (nscd_getent_context_t *)contextp->ctx;
	if (ctx != NULL) {
		*cookie_num_p = ctx->cookie_num;
		*seqnum_p = ctx->seq_num;
		ctx->pid = pid;
	} else {
		/*
		 * not able to allocate a getent context, the
		 * client should try the enumeration locally
		 */
		*cookie_num_p = NSCD_LOCAL_COOKIE;
		*seqnum_p = 0;

		_NSCD_LOG(NSCD_LOG_SWITCH_ENGINE, NSCD_LOG_LEVEL_DEBUG)
		(me, "NSS_TRYLOCAL: cookie # = %lld,  sequence # = %lld\n",
		    *cookie_num_p, *seqnum_p);
		NSCD_SET_STATUS(pbuf, NSS_TRYLOCAL, 0);
		return;
	}

	_NSCD_LOG(NSCD_LOG_SWITCH_ENGINE, NSCD_LOG_LEVEL_DEBUG)
	(me, "NSS_SUCCESS: cookie # = %lld,  sequence # = %lld\n",
	    ctx->cookie_num, ctx->seq_num);

	NSCD_SET_STATUS(pbuf, NSS_SUCCESS, 0);
}

void
nss_pgetent(void *buffer, size_t length)
{
	/* inputs */
	nss_db_initf_t		initf;
	nss_getent_t		context = { 0 };
	nss_getent_t		*contextp = &context;
	nss_XbyY_args_t		arg = { 0};
	nss_status_t		status;
	nssuint_t		*cookie_num_p;
	nssuint_t		*seqnum_p;
	nscd_getent_context_t	*ctx;
	int			rc;
	nss_pheader_t		*pbuf = (nss_pheader_t *)buffer;
	char			*me = "nss_pgetent";

	if (buffer == NULL || length == 0) {
		NSCD_SET_STATUS(pbuf, NSS_ERROR, EFAULT);
		return;
	}

	/* verify the cookie passed in */
	nscd_map_contextp(buffer, contextp, &cookie_num_p, &seqnum_p, 0);
	if (NSCD_STATUS_IS_NOT_OK(pbuf))
		return;

	/*
	 * use the generic nscd_initf for all the getent requests
	 * (the TSD key is the pointer to the packed header)
	 */
	rc = set_initf_key(pbuf);
	if (rc != 0) {
		NSCD_SET_STATUS(pbuf, NSS_UNAVAIL, EINVAL);
		return;
	}
	initf = nscd_initf;

	/* if no context yet, get one */
	if (contextp->ctx ==  NULL) {
		nscd_getent_p0_cookie_t *p0c =
		    (nscd_getent_p0_cookie_t *)cookie_num_p;

		delayed_setent(pbuf, initf, contextp, cookie_num_p,
		    seqnum_p, p0c->p0_pid);
		if (NSCD_STATUS_IS_NOT_OK(pbuf)) {
			clear_initf_key();
			return;
		}
	}

	status = nss_packed_context_init(buffer, length,
	    NULL, &initf, &contextp, &arg);
	if (status != NSS_SUCCESS) {
		clear_initf_key();
		_nscd_free_ctx_if_aborted(
		    (nscd_getent_context_t *)contextp->ctx);
		NSCD_SET_STATUS(pbuf, status, -1);
		return;
	}

	/* Perform local search and pack results into return buffer */
	status = nss_getent(NULL, initf, contextp, &arg);
	NSCD_SET_STATUS(pbuf, status, -1);
	nss_packed_set_status(buffer, length, status,  &arg);

	/* increment sequence number in the buffer and nscd context */
	if (status == NSS_SUCCESS) {
		ctx = (nscd_getent_context_t *)contextp->ctx;
		ctx->seq_num++;
		*seqnum_p = ctx->seq_num;
		*cookie_num_p = ctx->cookie_num;

		_NSCD_LOG(NSCD_LOG_SWITCH_ENGINE, NSCD_LOG_LEVEL_DEBUG)
		(me, "getent OK, new sequence # = %lld, len = %lld,"
		    " data = >>%s<<\n", *seqnum_p,
		    pbuf->data_len, (char *)buffer + pbuf->data_off);

		_nscd_free_ctx_if_aborted(ctx);
	} else {
		/* release the resources used */
		ctx = (nscd_getent_context_t *)contextp->ctx;
		if (ctx != NULL && _nscd_is_getent_ctx_in_use(ctx) == 0) {
			_nscd_put_getent_ctx(ctx);
			contextp->ctx = NULL;
		}
		_NSCD_LOG(NSCD_LOG_SWITCH_ENGINE, NSCD_LOG_LEVEL_DEBUG)
		(me, "getent failed, status = %d, sequence # = %lld\n",
		    status, *seqnum_p);
	}

	/* clear the TSD key used by the generic initf */
	clear_initf_key();
}

void
nss_pendent(void *buffer, size_t length)
{
	nss_getent_t		context = { 0 };
	nss_getent_t		*contextp = &context;
	nssuint_t		*seqnum_p;
	nssuint_t		*cookie_num_p;
	nss_pheader_t		*pbuf = (nss_pheader_t *)buffer;
	char			*me = "nss_pendent";

	if (buffer == NULL || length == 0) {
		NSCD_SET_STATUS(pbuf, NSS_ERROR, EFAULT);
		return;
	}

	/* map the contextp from the cookie information */
	nscd_map_contextp(buffer, contextp, &cookie_num_p, &seqnum_p, 0);
	if (NSCD_STATUS_IS_NOT_OK(pbuf))
		return;

	if (contextp->ctx == NULL)
		return;

	_NSCD_LOG(NSCD_LOG_SWITCH_ENGINE, NSCD_LOG_LEVEL_DEBUG)
	(me, "endent, cookie = %lld, sequence # = %lld\n",
	    *cookie_num_p, *seqnum_p);

	/* Perform local endent and reset context */
	nss_endent(NULL, NULL, contextp);

	NSCD_SET_STATUS(pbuf, NSS_SUCCESS, 0);
}

/*ARGSUSED*/
void
nss_pdelete(void *buffer, size_t length)
{
	nss_pheader_t	*pbuf = (nss_pheader_t *)buffer;

	/* unnecessary, kept for completeness */
	NSCD_SET_STATUS_SUCCESS(pbuf);
}
