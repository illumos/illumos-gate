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
 *
 * Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
 */

#include <malloc.h>
#include <synch.h>
#include <syslog.h>
#include <rpcsvc/ypclnt.h>
#include <rpcsvc/yp_prot.h>
#include <pthread.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <sys/stat.h>
#include <assert.h>
#include "ad_common.h"

static pthread_mutex_t	statelock = PTHREAD_MUTEX_INITIALIZER;
static nssad_state_t	state = {0};

static void
nssad_cfg_free_props(nssad_prop_t *props)
{
	if (props->domain_name != NULL) {
		free(props->domain_name);
		props->domain_name = NULL;
	}
	if (props->domain_controller != NULL) {
		free(props->domain_controller);
		props->domain_controller = NULL;
	}
}

static int
nssad_cfg_discover_props(const char *domain, ad_disc_t ad_ctx,
	nssad_prop_t *props)
{
	ad_disc_refresh(ad_ctx);
	if (ad_disc_set_DomainName(ad_ctx, domain) != 0)
		return (-1);
	if (props->domain_controller == NULL)
		props->domain_controller =
		    ad_disc_get_DomainController(ad_ctx, AD_DISC_PREFER_SITE,
		    NULL);
	return (0);
}

static int
nssad_cfg_reload_ad(nssad_prop_t *props, adutils_ad_t **ad)
{
	int		i;
	adutils_ad_t	*new;

	if (props->domain_controller == NULL ||
	    props->domain_controller[0].host[0] == '\0')
		return (0);
	if (adutils_ad_alloc(&new, props->domain_name,
	    ADUTILS_AD_DATA) != ADUTILS_SUCCESS)
		return (-1);
	for (i = 0; props->domain_controller[i].host[0] != '\0'; i++) {
		if (adutils_add_ds(new,
		    props->domain_controller[i].host,
		    props->domain_controller[i].port) != ADUTILS_SUCCESS) {
			adutils_ad_free(&new);
			return (-1);
		}
	}

	if (*ad != NULL)
		adutils_ad_free(ad);
	*ad = new;
	return (0);
}

static
int
update_dirs(ad_disc_ds_t **value, ad_disc_ds_t **new)
{
	if (*value == *new)
		return (0);

	if (*value != NULL && *new != NULL &&
	    ad_disc_compare_ds(*value, *new) == 0) {
		free(*new);
		*new = NULL;
		return (0);
	}

	if (*value)
		free(*value);
	*value = *new;
	*new = NULL;
	return (1);
}

static
int
nssad_cfg_refresh(nssad_cfg_t *cp)
{
	nssad_prop_t	props;

	(void) ad_disc_SubnetChanged(cp->ad_ctx);
	(void) memset(&props, 0, sizeof (props));
	if (nssad_cfg_discover_props(cp->props.domain_name, cp->ad_ctx,
	    &props) < 0)
		return (-1);
	if (update_dirs(&cp->props.domain_controller,
	    &props.domain_controller)) {
		if (cp->props.domain_controller != NULL &&
		    cp->props.domain_controller[0].host[0] != '\0')
			(void) nssad_cfg_reload_ad(&cp->props, &cp->ad);
	}
	return (0);
}

static void
nssad_cfg_destroy(nssad_cfg_t *cp)
{
	if (cp != NULL) {
		(void) pthread_rwlock_destroy(&cp->lock);
		ad_disc_fini(cp->ad_ctx);
		nssad_cfg_free_props(&cp->props);
		adutils_ad_free(&cp->ad);
		free(cp);
	}
}

static nssad_cfg_t *
nssad_cfg_create(const char *domain)
{
	nssad_cfg_t	*cp;

	if ((cp = calloc(1, sizeof (*cp))) == NULL)
		return (NULL);
	if (pthread_rwlock_init(&cp->lock, NULL) != 0) {
		free(cp);
		return (NULL);
	}
	if ((cp->ad_ctx = ad_disc_init()) == NULL)
		goto errout;
	if ((cp->props.domain_name = strdup(domain)) == NULL)
		goto errout;
	if (nssad_cfg_discover_props(domain, cp->ad_ctx, &cp->props) < 0)
		goto errout;
	if (nssad_cfg_reload_ad(&cp->props, &cp->ad) < 0)
		goto errout;
	return (cp);
errout:
	nssad_cfg_destroy(cp);
	return (NULL);
}

#define	hex_char(n)	"0123456789abcdef"[n & 0xf]

int
_ldap_filter_name(char *filter_name, const char *name, int filter_name_size)
{
	char *end = filter_name + filter_name_size;
	char c;

	for (; *name; name++) {
		c = *name;
		switch (c) {
			case '*':
			case '(':
			case ')':
			case '\\':
				if (end <= filter_name + 3)
					return (-1);
				*filter_name++ = '\\';
				*filter_name++ = hex_char(c >> 4);
				*filter_name++ = hex_char(c & 0xf);
				break;
			default:
				if (end <= filter_name + 1)
					return (-1);
				*filter_name++ = c;
				break;
		}
	}
	if (end <= filter_name)
		return (-1);
	*filter_name = '\0';
	return (0);
}

static
nss_status_t
map_adrc2nssrc(adutils_rc adrc)
{
	if (adrc == ADUTILS_SUCCESS)
		return ((nss_status_t)NSS_SUCCESS);
	if (adrc == ADUTILS_ERR_NOTFOUND)
		errno = 0;
	return ((nss_status_t)NSS_NOTFOUND);
}

/* ARGSUSED */
nss_status_t
_nss_ad_marshall_data(ad_backend_ptr be, nss_XbyY_args_t *argp)
{
	int	stat;

	if (argp->buf.result == NULL) {
		/*
		 * This suggests that the process (e.g. nscd) expects
		 * nssad to return the data in native file format in
		 * argp->buf.buffer i.e. no need to marshall the data.
		 */
		argp->returnval = argp->buf.buffer;
		argp->returnlen = strlen(argp->buf.buffer);
		return ((nss_status_t)NSS_STR_PARSE_SUCCESS);
	}

	if (argp->str2ent == NULL)
		return ((nss_status_t)NSS_STR_PARSE_PARSE);

	stat = (*argp->str2ent)(be->buffer, be->buflen,
	    argp->buf.result, argp->buf.buffer, argp->buf.buflen);

	if (stat == NSS_STR_PARSE_SUCCESS) {
		argp->returnval = argp->buf.result;
		argp->returnlen = 1; /* irrelevant */
	}
	return ((nss_status_t)stat);
}

nss_status_t
_nss_ad_sanitize_status(ad_backend_ptr be, nss_XbyY_args_t *argp,
		nss_status_t stat)
{
	if (be->buffer != NULL) {
		free(be->buffer);
		be->buffer = NULL;
		be->buflen = 0;
		be->db_type = NSS_AD_DB_NONE;
	}

	if (stat == NSS_STR_PARSE_SUCCESS) {
		return ((nss_status_t)NSS_SUCCESS);
	} else if (stat == NSS_STR_PARSE_PARSE) {
		argp->returnval = 0;
		return ((nss_status_t)NSS_NOTFOUND);
	} else if (stat == NSS_STR_PARSE_ERANGE) {
		argp->erange = 1;
		return ((nss_status_t)NSS_NOTFOUND);
	}
	return ((nss_status_t)NSS_UNAVAIL);
}

/* ARGSUSED */
static
nssad_cfg_t *
get_cfg(const char *domain)
{
	nssad_cfg_t	*cp, *lru, *prev;

	/*
	 * Note about the queue:
	 *
	 * The queue is used to hold our per domain
	 * configs. The queue is limited to CFG_QUEUE_MAX_SIZE.
	 * If the queue increases beyond that point we toss
	 * out the LRU entry. The entries are inserted into
	 * the queue at state.qtail and the LRU entry is
	 * removed from state.qhead. state.qnext points
	 * from the qtail to the qhead. Everytime a config
	 * is accessed it is moved to qtail.
	 */

	(void) pthread_mutex_lock(&statelock);

	for (cp = state.qtail, prev = NULL; cp != NULL;
	    prev = cp, cp = cp->qnext) {
		if (cp->props.domain_name == NULL ||
		    strcasecmp(cp->props.domain_name, domain) != 0)
			continue;

		/* Found config for the given domain. */

		if (state.qtail != cp) {
			/*
			 * Move the entry to the tail of the queue.
			 * This way the LRU entry can be found at
			 * the head of the queue.
			 */
			prev->qnext = cp->qnext;
			if (state.qhead == cp)
				state.qhead = prev;
			cp->qnext = state.qtail;
			state.qtail = cp;
		}

		if (ad_disc_get_TTL(cp->ad_ctx) == 0) {
			/*
			 * If there are expired items in the
			 * config, grab the write lock and
			 * refresh the config.
			 */
			(void) pthread_rwlock_wrlock(&cp->lock);
			if (nssad_cfg_refresh(cp) < 0) {
				(void) pthread_rwlock_unlock(&cp->lock);
				(void) pthread_mutex_unlock(&statelock);
				return (NULL);
			}
			(void) pthread_rwlock_unlock(&cp->lock);
		}

		/* Return the config found */
		(void) pthread_rwlock_rdlock(&cp->lock);
		(void) pthread_mutex_unlock(&statelock);
		return (cp);
	}

	/* Create new config entry for the domain */
	if ((cp = nssad_cfg_create(domain)) == NULL) {
		(void) pthread_mutex_unlock(&statelock);
		return (NULL);
	}

	/* Add it to the queue */
	state.qcount++;
	if (state.qtail == NULL) {
		state.qtail = state.qhead = cp;
		(void) pthread_rwlock_rdlock(&cp->lock);
		(void) pthread_mutex_unlock(&statelock);
		return (cp);
	}
	cp->qnext = state.qtail;
	state.qtail = cp;

	/* If the queue has exceeded its size, remove the LRU entry */
	if (state.qcount >= CFG_QUEUE_MAX_SIZE) {
		/* Detach the lru entry and destroy */
		lru = state.qhead;
		if (pthread_rwlock_trywrlock(&lru->lock) == 0) {
			for (prev = state.qtail; prev != NULL;
			    prev = prev->qnext) {
				if (prev->qnext != lru)
					continue;
				state.qhead = prev;
				prev->qnext = NULL;
				state.qcount--;
				(void) pthread_rwlock_unlock(&lru->lock);
				nssad_cfg_destroy(lru);
				break;
			}
			(void) assert(prev != NULL);
		}
	}

	(void) pthread_rwlock_rdlock(&cp->lock);
	(void) pthread_mutex_unlock(&statelock);
	return (cp);
}


/* ARGSUSED */
static
nss_status_t
ad_lookup(const char *filter, const char **attrs,
	const char *domain, adutils_result_t **result)
{
	int			retries = 0;
	adutils_rc		rc, brc;
	adutils_query_state_t	*qs;
	nssad_cfg_t		*cp;

retry:
	if ((cp = get_cfg(domain)) == NULL)
		return ((nss_status_t)NSS_NOTFOUND);

	rc = adutils_lookup_batch_start(cp->ad, 1, NULL, NULL, &qs);
	(void) pthread_rwlock_unlock(&cp->lock);
	if (rc != ADUTILS_SUCCESS)
		goto out;

	rc = adutils_lookup_batch_add(qs, filter, attrs, domain, result, &brc);
	if (rc != ADUTILS_SUCCESS) {
		adutils_lookup_batch_release(&qs);
		goto out;
	}

	rc = adutils_lookup_batch_end(&qs);
	if (rc != ADUTILS_SUCCESS)
		goto out;
	rc = brc;

out:
	if (rc == ADUTILS_ERR_RETRIABLE_NET_ERR &&
	    retries++ < ADUTILS_DEF_NUM_RETRIES)
		goto retry;
	return (map_adrc2nssrc(rc));
}


/* ARGSUSED */
nss_status_t
_nss_ad_lookup(ad_backend_ptr be, nss_XbyY_args_t *argp,
		const char *database, const char *searchfilter,
		const char *dname, int *try_idmap)
{
	nss_status_t	stat;

	*try_idmap = 0;

	/* Clear up results if any */
	(void) adutils_freeresult(&be->result);

	/* Lookup AD */
	stat = ad_lookup(searchfilter, be->attrs, dname, &be->result);
	if (stat != NSS_SUCCESS) {
		argp->returnval = 0;
		*try_idmap = 1;
		return (stat);
	}

	/* Map AD object(s) to string in native file format */
	stat = be->adobj2str(be, argp);
	if (stat == NSS_STR_PARSE_SUCCESS)
		stat = _nss_ad_marshall_data(be, argp);
	return (_nss_ad_sanitize_status(be, argp, stat));
}

static
void
clean_state()
{
	nssad_cfg_t	*cp, *curr;

	(void) pthread_mutex_lock(&statelock);
	for (cp = state.qtail; cp != NULL; ) {
		curr = cp;
		cp = cp->qnext;
		nssad_cfg_destroy(curr);
	}
	(void) memset(&state, 0, sizeof (state));
	(void) pthread_mutex_unlock(&statelock);
}

static
void
_clean_ad_backend(ad_backend_ptr be)
{
	if (be->tablename != NULL)
		free(be->tablename);
	if (be->buffer != NULL) {
		free(be->buffer);
		be->buffer = NULL;
	}
	free(be);
}


/*
 * _nss_ad_destr frees allocated memory before exiting this nsswitch shared
 * backend library. This function is called before returning control back to
 * nsswitch.
 */
/*ARGSUSED*/
nss_status_t
_nss_ad_destr(ad_backend_ptr be, void *a)
{
	(void) _clean_ad_backend(be);
	clean_state();
	return ((nss_status_t)NSS_SUCCESS);
}


/*ARGSUSED*/
nss_status_t
_nss_ad_setent(ad_backend_ptr be, void *a)
{
	return ((nss_status_t)NSS_UNAVAIL);
}


/*ARGSUSED*/
nss_status_t
_nss_ad_endent(ad_backend_ptr be, void *a)
{
	return ((nss_status_t)NSS_UNAVAIL);
}


/*ARGSUSED*/
nss_status_t
_nss_ad_getent(ad_backend_ptr be, void *a)
{
	return ((nss_status_t)NSS_UNAVAIL);
}


nss_backend_t *
_nss_ad_constr(ad_backend_op_t ops[], int nops, char *tablename,
		const char **attrs, fnf adobj2str)
{
	ad_backend_ptr	be;

	if ((be = (ad_backend_ptr) calloc(1, sizeof (*be))) == NULL)
		return (NULL);
	if ((be->tablename = (char *)strdup(tablename)) == NULL) {
		free(be);
		return (NULL);
	}
	be->ops = ops;
	be->nops = (nss_dbop_t)nops;
	be->attrs = attrs;
	be->adobj2str = adobj2str;
	(void) memset(&state, 0, sizeof (state));
	return ((nss_backend_t *)be);
}
