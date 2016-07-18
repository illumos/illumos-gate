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
 */

/*
 * Shared code used by the name-service-switch frontends (e.g. getpwnam_r())
 */

#include "lint.h"
#include <mtlib.h>
#include <dlfcn.h>
#include <atomic.h>

#define	__NSS_PRIVATE_INTERFACE
#include "nsswitch_priv.h"
#undef	__NSS_PRIVATE_INTERFACE

#include <nss_common.h>
#include <nss_dbdefs.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <thread.h>
#include <synch.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <errno.h>
#include "libc.h"
#include "tsd.h"

#include <getxby_door.h>

/*
 * configurable values for default buffer sizes
 */

/*
 * PSARC/2005/133 updated the buffering mechanisms to handle
 * up to 2^64 buffering.  But sets a practical limit of 512*1024.
 * The expectation is the practical limit will be dynamic from
 * nscd.  For now, set the group limit to this value.
 */

#define	NSS_BUFLEN_PRACTICAL	(512*1024)

static size_t __nss_buflen_group = NSS_BUFLEN_PRACTICAL;
static size_t __nss_buflen_default = NSS_BUFLEN_DOOR;

/*
 * policy component function interposing definitions:
 * nscd if so desired can interpose it's own switch functions over
 * the internal unlocked counterparts.  This will allow nscd to replace
 * the switch policy state engine with one that uses it's internal
 * components.
 * Only nscd can change this through it's use of nss_config.
 * The golden rule is: ptr == NULL checking is used in the switch to
 * see if a function was interposed.  But nscd is responsible for seeing
 * that mutex locking to change the values are observed when the data is
 * changed.  Especially if it happens > once.  The switch does not lock
 * the pointer with mutexs.
 */

typedef struct {
	void	*p;
#if 0
	void		(*nss_delete_fp)(nss_db_root_t *rootp);
	nss_status_t	(*nss_search_fp)(nss_db_root_t *rootp,
				nss_db_initf_t initf, int search_fnum,
				void *search_args);
	void		(*nss_setent_u_fp)(nss_db_root_t *,
				nss_db_initf_t, nss_getent_t *);
	nss_status_t	(*nss_getent_u_fp)(nss_db_root_t *,
				nss_db_initf_t, nss_getent_t *, void *);
	void		(*nss_endent_u_fp)(nss_db_root_t *,
				nss_db_initf_t, nss_getent_t *);
	void		(*end_iter_u_fp)(nss_db_root_t *rootp,
				struct nss_getent_context *contextp);
#endif
} nss_policyf_t;

static mutex_t nss_policyf_lock = DEFAULTMUTEX;
static nss_policyf_t nss_policyf_ptrs =
	{ (void *)NULL };

/*
 * nsswitch db_root state machine definitions:
 * The golden rule is:  if you hold a pointer to an nss_db_state struct and
 * you don't hold the lock, you'd better have incremented the refcount
 * while you held the lock;  otherwise, it may vanish or change
 * significantly when you least expect it.
 *
 * The pointer in nss_db_root_t is one such, so the reference count >= 1.
 * Ditto the pointer in struct nss_getent_context.
 */

/*
 * State for one nsswitch database (e.g. "passwd", "hosts")
 */
struct nss_db_state {
	nss_db_root_t		orphan_root;	/* XXX explain */
	unsigned		refcount;	/* One for the pointer in    */
						/*   nss_db_root_t, plus one */
						/*   for each active thread. */
	nss_db_params_t		p;
	struct __nsw_switchconfig_v1 *config;
	int			max_src;	/* is == config->num_lookups */
	struct nss_src_state	*src;		/* Pointer to array[max_src] */
};

/*
 * State for one of the sources (e.g. "nis", "compat") for a database
 */
struct nss_src_state {
	struct __nsw_lookup_v1	*lkp;
	int			n_active;
	int			n_dormant;
	int			n_waiting;	/* ... on wanna_be */
	cond_t			wanna_be;
	union {
		nss_backend_t	*single; /* Efficiency hack for common case */
					    /* when limit_dead_backends == 1 */
		nss_backend_t	**multi; /* array[limit_dead_backends] of */
	} dormant;			    /* pointers to dormant backends */
	nss_backend_constr_t	be_constr;
	nss_backend_finder_t	*finder;
	void			*finder_priv;
};

static struct nss_db_state	*_nss_db_state_constr(nss_db_initf_t);
void				_nss_db_state_destr(struct nss_db_state *);

/* ==== null definitions if !MTSAFE?  Ditto lock field in nss_db_root_t */

#define	NSS_ROOTLOCK(r, sp)	(cancel_safe_mutex_lock(&(r)->lock), \
				*(sp) = (r)->s)

#define	NSS_UNLOCK(r)		(cancel_safe_mutex_unlock(&(r)->lock))

#define	NSS_CHECKROOT(rp, s)	((s) != (*(rp))->s &&			\
			(cancel_safe_mutex_unlock(&(*(rp))->lock),	\
			cancel_safe_mutex_lock(&(s)->orphan_root.lock), \
			*(rp) = &(s)->orphan_root))

#define	NSS_RELOCK(rp, s)	(cancel_safe_mutex_lock(&(*(rp))->lock), \
			NSS_CHECKROOT(rp, s))

#define	NSS_STATE_REF_u(s)	(++(s)->refcount)

#define	NSS_UNREF_UNLOCK(r, s)	(--(s)->refcount != 0			\
			? ((void)NSS_UNLOCK(r))				\
			: ((void)NSS_UNLOCK(r), (void)_nss_db_state_destr(s)))

#define	NSS_LOCK_CHECK(r, f, sp)    (NSS_ROOTLOCK((r), (sp)),	\
				    *(sp) == 0 &&		\
				    (r->s = *(sp) = _nss_db_state_constr(f)))
/* === In the future, NSS_LOCK_CHECK() may also have to check that   */
/* === the config info hasn't changed (by comparing version numbers) */


/*
 * NSS_OPTIONS/NIS_OPTIONS environment varibles data definitions:
 * This remains for backwards compatibility.  But generally nscd will
 * decide if/how this gets used.
 */
static int checked_env = 0;		/* protected by "rootlock" */

	/* allowing __nss_debug_file to be set could be a security hole. */
FILE *__nss_debug_file = stdout;
int __nss_debug_eng_loop;

/* NIS_OPTIONS infrastructure (from linbsl/nis/cache/cache_api.cc) */
	/* allowing __nis_debug_file to be set could be a security hole. */
FILE *__nis_debug_file = stdout;
int __nis_debug_bind;
int __nis_debug_rpc;
int __nis_debug_calls;
char *__nis_prefsrv;
char *__nis_preftype;
char *__nis_server;   /* if set, use only this server for binding */

#define	OPT_INT 1
#define	OPT_STRING 2
#ifdef DEBUG
#define	OPT_FILE 3
#endif

struct option {
	char *name;
	int type;
	void *address;
};

static struct option nss_options[] = {
#ifdef DEBUG
	/* allowing __nss_debug_file to be set could be a security hole. */
	{ "debug_file", OPT_FILE, &__nss_debug_file },
#endif
	{ "debug_eng_loop", OPT_INT, &__nss_debug_eng_loop },
	{ 0, 0, 0 },
};

static struct option nis_options[] = {
#ifdef DEBUG
	/* allowing __nis_debug_file to be set could be a security hole. */
	{ "debug_file", OPT_FILE, &__nis_debug_file },
#endif
	{ "debug_bind", OPT_INT, &__nis_debug_bind },
	{ "debug_rpc", OPT_INT, &__nis_debug_rpc },
	{ "debug_calls", OPT_INT, &__nis_debug_calls },
	{ "server", OPT_STRING, &__nis_server },
	{ "pref_srvr", OPT_STRING, &__nis_prefsrv },
	{ "pref_type", OPT_STRING, &__nis_preftype },
	{ 0, 0, 0 },
};

/*
 * switch configuration parameter "database" definitions:
 * The switch maintains a simmple read/write parameter database
 * that nscd and the switch components can use to communicate
 * nscd data to other components for configuration or out of band
 * [IE no in the context of a getXbyY or putXbyY operation] data.
 * The data passed are pointers to a lock  data buffer and a length.
 * Use of this is treated as SunwPrivate between nscd and the switch
 * unless other wise stated.
 */

typedef struct nss_cfgparam {
	char 		*name;
	mutex_t		*lock;
	void		*buffer;
	size_t		length;
} nss_cfgparam_t;

typedef struct nss_cfglist {
	char 		*name;
	nss_cfgparam_t	*list;
	int		count;
	int		max;
} nss_cfglist_t;

#define	NSS_CFG_INCR	16

static nss_cfglist_t *nss_cfg = NULL;
static int nss_cfgcount = 0;
static int nss_cfgmax = 0;
static mutex_t nss_cfglock = DEFAULTMUTEX;

static int nss_cfg_policy_init();

/*
 * A config parameters are in the form component:parameter
 * as in: nss:parameter - switch (internal FE/policy/BE) parameter
 *	  nscd:param - nscd application parameter
 *	  ldap:param - nss_ldap BE parameter
 *	  passwd:param - get/put passwd FE parameter
 */

#define	NSS_CONFIG_BRK	':'

/*
 * The policy components initial parameter list
 */
static nss_config_t	nss_policy_params[] = {
	{ "nss:policyfunc", NSS_CONFIG_ADD, &nss_policyf_lock,
		(void *)&nss_policyf_ptrs, (size_t)sizeof (nss_policyf_t) },
	{ NULL,	NSS_CONFIG_ADD,	(mutex_t *)NULL, (void *)NULL, (size_t)0 },
};

/*
 * NSS parameter configuration routines
 */

/* compare config name (component:parameter) to a component name */
static int
nss_cfgcn_cmp(const char *cfgname, const char *compname)
{
	char *c;
	size_t len, len2;

	/* this code assumes valid pointers */
	if ((c = strchr(cfgname, NSS_CONFIG_BRK)) == NULL)
		return (-1);
	len = (size_t)(c - cfgname);
	len2 = strlen(compname);
	if (len2 != len)
		return (-1);
	return (strncmp(cfgname, compname, len));
}

/* init configuration arena */
static int
nss_cfg_init()
{
	nss_cfglist_t *cfg;
	int i;

	/* First time caller? */
	if (nss_cfg != NULL) {
		membar_consumer();
		return (0);
	}

	/* Initialize internal tables */
	lmutex_lock(&nss_cfglock);
	if (nss_cfg != NULL) {
		lmutex_unlock(&nss_cfglock);
		membar_consumer();
		return (0);
	}
	cfg = libc_malloc(NSS_CFG_INCR * sizeof (nss_cfglist_t));
	if (cfg == NULL) {
		errno = ENOMEM;
		lmutex_unlock(&nss_cfglock);
		return (-1);
	}
	for (i = 0; i < NSS_CFG_INCR; i++) {
		cfg[i].list = libc_malloc(
		    NSS_CFG_INCR * sizeof (nss_cfgparam_t));
		if (cfg[i].list == NULL) {
			while (--i >= 0)
				libc_free(cfg[i].list);
			libc_free(cfg);
			errno = ENOMEM;
			lmutex_unlock(&nss_cfglock);
			return (-1);
		}
		cfg[i].max = NSS_CFG_INCR;
	}
	nss_cfgmax = NSS_CFG_INCR;
	membar_producer();
	nss_cfg = cfg;
	lmutex_unlock(&nss_cfglock);

	/* Initialize Policy Engine values */
	if (nss_cfg_policy_init() < 0) {
		return (-1);
	}
	return (0);
}

/* find the name'd component list - create it if non-existent */
static nss_cfglist_t *
nss_cfgcomp_get(char *name, int add)
{
	nss_cfglist_t	*next;
	char	*c;
	int	i, len;
	size_t	nsize;

	/* Make sure system is init'd */
	if (nss_cfg_init() < 0)
		return ((nss_cfglist_t *)NULL);

	/* and check component:name validity */
	if (name == NULL || (c = strchr(name, NSS_CONFIG_BRK)) == NULL)
		return ((nss_cfglist_t *)NULL);

	lmutex_lock(&nss_cfglock);
	next = nss_cfg;
	for (i = 0; i < nss_cfgcount; i++) {
		if (next->name && nss_cfgcn_cmp(name, next->name) == 0) {
			lmutex_unlock(&nss_cfglock);
			return (next);
		}
		next++;
	}
	if (!add) {
		lmutex_unlock(&nss_cfglock);
		return (NULL);
	}

	/* not found, create a fresh one */
	if (nss_cfgcount >= nss_cfgmax) {
		/* realloc first */
		nsize = (nss_cfgmax + NSS_CFG_INCR) * sizeof (nss_cfgparam_t);
		next = (nss_cfglist_t *)libc_realloc(nss_cfg, nsize);
		if (next == NULL) {
			errno = ENOMEM;
			lmutex_unlock(&nss_cfglock);
			return ((nss_cfglist_t *)NULL);
		}
		(void) memset((void *)(next + nss_cfgcount), '\0',
		    NSS_CFG_INCR * sizeof (nss_cfglist_t));
		nss_cfgmax += NSS_CFG_INCR;
		nss_cfg = next;
	}
	next = nss_cfg + nss_cfgcount;
	len = (size_t)(c - name) + 1;
	if ((next->name = libc_malloc(len)) == NULL) {
		errno = ENOMEM;
		lmutex_unlock(&nss_cfglock);
		return ((nss_cfglist_t *)NULL);
	}
	nss_cfgcount++;
	(void) strlcpy(next->name, name, len);
	lmutex_unlock(&nss_cfglock);
	return (next);
}

/* find the name'd parameter - create it if non-existent */
static nss_cfgparam_t *
nss_cfgparam_get(char *name, int add)
{
	nss_cfglist_t	*comp;
	nss_cfgparam_t	*next;
	int	count, i;
	size_t	nsize;

	if ((comp = nss_cfgcomp_get(name, add)) == NULL)
		return ((nss_cfgparam_t *)NULL);
	lmutex_lock(&nss_cfglock);
	count = comp->count;
	next = comp->list;
	for (i = 0; i < count; i++) {
		if (next->name && strcmp(name, next->name) == 0) {
			lmutex_unlock(&nss_cfglock);
			return (next);
		}
		next++;
	}
	if (!add) {
		lmutex_unlock(&nss_cfglock);
		return (NULL);
	}

	/* not found, create a fresh one */
	if (count >= comp->max) {
		/* realloc first */
		nsize = (comp->max + NSS_CFG_INCR) * sizeof (nss_cfgparam_t);
		next = (nss_cfgparam_t *)libc_realloc(comp->list, nsize);
		if (next == NULL) {
			errno = ENOMEM;
			lmutex_unlock(&nss_cfglock);
			return ((nss_cfgparam_t *)NULL);
		}
		comp->max += NSS_CFG_INCR;
		comp->list = next;
	}
	next = comp->list + comp->count;
	if ((next->name = libc_strdup(name)) == NULL) {
		errno = ENOMEM;
		lmutex_unlock(&nss_cfglock);
		return ((nss_cfgparam_t *)NULL);
	}
	comp->count++;
	lmutex_unlock(&nss_cfglock);
	return (next);
}

/* find the name'd parameter - delete it if it exists */
static void
nss_cfg_del(nss_config_t *cfgp)
{
	char		*name;
	nss_cfglist_t	*comp;
	nss_cfgparam_t	*next, *cur;
	int	count, i, j;

	/* exit if component name does not already exist */
	if ((name = cfgp->name) == NULL ||
	    (comp = nss_cfgcomp_get(name, 0)) == NULL)
		return;

	/* find it */
	lmutex_lock(&nss_cfglock);
	count = comp->count;
	next = comp->list;
	for (i = 0; i < count; i++) {
		if (next->name && strcmp(name, next->name) == 0) {
			break;	/* found it... */
		}
		next++;
	}
	if (i >= count) {
		/* not found, already deleted */
		lmutex_unlock(&nss_cfglock);
		return;
	}

	/* copy down the remaining parameters, and clean up */
	/* don't try to clean up component tables */
	cur = next;
	next++;
	for (j = i+1; j < count; j++) {
		*cur = *next;
		cur++;
		next++;
	}
	/* erase the last one */
	if (cur->name) {
		libc_free(cur->name);
		cur->name = (char *)NULL;
	}
	cur->lock = (mutex_t *)NULL;
	cur->buffer = (void *)NULL;
	cur->length = 0;
	comp->count--;
	lmutex_unlock(&nss_cfglock);
}

static int
nss_cfg_get(nss_config_t *next)
{
	nss_cfgparam_t	*param;

	errno = 0;
	if ((param = nss_cfgparam_get(next->name, 0)) == NULL)
		return (-1);
	next->lock = param->lock;
	next->buffer = param->buffer;
	next->length = param->length;
	return (0);
}

static int
nss_cfg_put(nss_config_t *next, int add)
{
	nss_cfgparam_t	*param;

	errno = 0;
	if ((param = nss_cfgparam_get(next->name, add)) == NULL)
		return (-1);
	param->lock = next->lock;
	param->buffer = next->buffer;
	param->length = next->length;
	return (0);
}

/*
 * Policy engine configurator - set and get interface
 * argument is a NULL terminated list of set/get requests
 * with input/result buffers and lengths.  nss_cname is the
 * specifier of a set or get operation and the property being
 * managed.  The intent is limited functions and expandability.
 */

nss_status_t
nss_config(nss_config_t **plist, int cnt)
{
	nss_config_t	*next;
	int 	i;

	/* interface is only available to nscd */
	if (_nsc_proc_is_cache() <= 0) {
		return (NSS_UNAVAIL);
	}
	if (plist == NULL || cnt <= 0)
		return (NSS_SUCCESS);
	for (i = 0; i < cnt; i++) {
		next = plist[i];
		if (next == NULL)
			break;
		if (next->name == NULL) {
			errno = EFAULT;
			return (NSS_ERROR);
		}
		switch (next->cop) {
		case NSS_CONFIG_GET:
			/* get current lock/buffer/length fields */
			if (nss_cfg_get(next) < 0) {
				return (NSS_ERROR);
			}
			break;
		case NSS_CONFIG_PUT:
			/* set new lock/buffer/length fields */
			if (nss_cfg_put(next, 0) < 0) {
				return (NSS_ERROR);
			}
			break;
		case NSS_CONFIG_ADD:
			/* add parameter & set new lock/buffer/length fields */
			if (nss_cfg_put(next, 1) < 0) {
				return (NSS_ERROR);
			}
			break;
		case NSS_CONFIG_DELETE:
			/* delete parameter - should always work... */
			nss_cfg_del(next);
			break;
		case NSS_CONFIG_LIST:
			break;
		default:
			continue;
		}
	}
	return (NSS_SUCCESS);
}

/*
 * This routine is called immediately after nss_cfg_init but prior to
 * any commands from nscd being processed.  The intent here is to
 * initialize the nss:* parameters allowed by the policy component
 * so that nscd can then proceed and modify them if so desired.
 *
 * We know we can only get here if we are nscd so we can skip the
 * preliminaries.
 */

static int
nss_cfg_policy_init()
{
	nss_config_t	*next = &nss_policy_params[0];

	for (; next && next->name != NULL; next++) {
		if (nss_cfg_put(next, 1) < 0)
			return (-1);
	}
	return (0);
}

/*
 * NSS_OPTION & NIS_OPTION environment variable functions
 */

static
void
set_option(struct option *opt, char *name, char *val)
{
	int n;
	char *p;
#ifdef DEBUG
	FILE *fp;
#endif

	for (; opt->name; opt++) {
		if (strcmp(name, opt->name) == 0) {
			switch (opt->type) {
			case OPT_STRING:
				p = libc_strdup(val);
				*((char **)opt->address) = p;
				break;

			case OPT_INT:
				if (strcmp(val, "") == 0)
					n = 1;
				else
					n = atoi(val);
				*((int *)opt->address) = n;
				break;
#ifdef DEBUG
			case OPT_FILE:
				fp = fopen(val, "wF");
				*((FILE **)opt->address) = fp;
				break;
#endif
			}
			break;
		}
	}
}

static
void
__parse_environment(struct option *opt, char *p)
{
	char *base;
	char optname[100];
	char optval[100];

	while (*p) {
		while (isspace(*p))
			p++;
		if (*p == '\0')
			break;

		base = p;
		while (*p && *p != '=' && !isspace(*p))
			p++;
		/*
		 * play it safe and keep it simple, bail if an opt name
		 * is too long.
		 */
		if ((p-base) >= sizeof (optname))
			return;

		(void) strncpy(optname, base, p-base);
		optname[p-base] = '\0';

		if (*p == '=') {
			p++;
			base = p;
			while (*p && !isspace(*p))
				p++;
			/*
			 * play it safe and keep it simple, bail if an opt
			 * value is too long.
			 */
			if ((p-base) >= sizeof (optval))
				return;

			(void) strncpy(optval, base, p-base);
			optval[p-base] = '\0';
		} else {
			optval[0] = '\0';
		}

		set_option(opt, optname, optval);
	}
}

static
void
nss_get_environment()
{
	char *p;

/* NSS_OPTIONS is undocumented and should be used without nscd running. */
	p = getenv("NSS_OPTIONS");
	if (p == NULL)
		return;
	__parse_environment(nss_options, p);
}

/*
 * sole external routine called from libnsl/nis/cache/cache_api.cc in the
 * routines _nis_CacheInit/__nis_CacheLocalInit/__nis_CacheMgrInit_discard
 * Only after checking "checked_env" (which must be done with mutex
 * "cur_cache_lock" held) and is done once, (then "checked_env" is set)
 */
void
__nis_get_environment()
{
	char *p;

	p = getenv("NIS_OPTIONS");
	if (p == NULL)
		return;
	__parse_environment(nis_options, p);
}


/*
 * Switch policy component backend state machine functions
 */

static nss_backend_t *
nss_get_backend_u(nss_db_root_t **rootpp, struct nss_db_state *s, int n_src)
{
	struct nss_src_state	*src = &s->src[n_src];
	nss_backend_t		*be;
	int cancel_state;

	for (;;) {
		if (src->n_dormant > 0) {
			src->n_dormant--;
			src->n_active++;
			if (s->p.max_dormant_per_src == 1) {
				be = src->dormant.single;
			} else {
				be = src->dormant.multi[src->n_dormant];
			}
			break;
		}

		if (src->be_constr == 0) {
			nss_backend_finder_t	*bf;

			for (bf = s->p.finders;  bf != 0;  bf = bf->next) {
				nss_backend_constr_t c;

				c = (*bf->lookup) (bf->lookup_priv, s->p.name,
				    src->lkp->service_name, &src->finder_priv);
				if (c != 0) {
					src->be_constr = c;
					src->finder = bf;
					break;
				}
			}
			if (src->be_constr == 0) {
				/* Couldn't find the backend anywhere */
				be = 0;
				break;
			}
		}

		if (src->n_active < s->p.max_active_per_src) {
			be = (*src->be_constr)(s->p.name,
			    src->lkp->service_name, 0 /* === unimplemented */);
			if (be != 0) {
				src->n_active++;
				break;
			} else if (src->n_active == 0) {
				/* Something's wrong;  we should be */
				/*   able to create at least one    */
				/*   instance of the backend	    */
				break;
			}
			/*
			 * Else it's odd that we can't create another backend
			 *   instance, but don't sweat it;  instead, queue for
			 *   an existing backend instance.
			 */
		}

		src->n_waiting++;
		(void) pthread_setcancelstate(PTHREAD_CANCEL_DISABLE,
		    &cancel_state);
		(void) cond_wait(&src->wanna_be, &(*rootpp)->lock);
		(void) pthread_setcancelstate(cancel_state, NULL);
		NSS_CHECKROOT(rootpp, s);
		src->n_waiting--;

		/*
		 * Loop and see whether things got better for us, or whether
		 *   someone else got scheduled first and we have to try
		 *   this again.
		 *
		 * === ?? Should count iterations, assume bug if many ??
		 */
	}
	return (be);
}

static void
nss_put_backend_u(struct nss_db_state *s, int n_src, nss_backend_t *be)
{
	struct nss_src_state	*src = &s->src[n_src];

	if (be == 0) {
		return;
	}

	src->n_active--;

	if (src->n_dormant < s->p.max_dormant_per_src) {
		if (s->p.max_dormant_per_src == 1) {
			src->dormant.single = be;
			src->n_dormant++;
		} else if (src->dormant.multi != 0 ||
		    (src->dormant.multi =
		    libc_malloc(s->p.max_dormant_per_src *
		    sizeof (nss_backend_t *))) != NULL) {
			src->dormant.multi[src->n_dormant] = be;
			src->n_dormant++;
		} else {
			/* Can't store it, so toss it */
			(void) NSS_INVOKE_DBOP(be, NSS_DBOP_DESTRUCTOR, 0);
		}
	} else {
		/* We've stored as many as we want, so toss it */
		(void) NSS_INVOKE_DBOP(be, NSS_DBOP_DESTRUCTOR, 0);
	}
	if (src->n_waiting > 0) {
		(void) cond_signal(&src->wanna_be);
	}
}

static struct nss_db_state *
_nss_db_state_constr(nss_db_initf_t initf)
{
	struct nss_db_state	*s;
	struct __nsw_switchconfig_v1 *config = 0;
	struct __nsw_lookup_v1	*lkp;
	enum __nsw_parse_err	err;
	const char		*config_name;
	int			n_src;

	if ((s = libc_malloc(sizeof (*s))) == 0) {
		return (0);
	}
	(void) mutex_init(&s->orphan_root.lock, USYNC_THREAD, 0);

	s->p.max_active_per_src	= 10;
	s->p.max_dormant_per_src = 1;
	s->p.finders = nss_default_finders;
	(*initf)(&s->p);
	if (s->p.name == 0) {
		_nss_db_state_destr(s);
		return (0);
	}

	if (!checked_env) {
/* NSS_OPTIONS is undocumented and should be used without nscd running. */
		nss_get_environment();
		checked_env = 1;
	}

	config_name = s->p.config_name ? s->p.config_name : s->p.name;
	if (! (s->p.flags & NSS_USE_DEFAULT_CONFIG)) {
		config = __nsw_getconfig_v1(config_name, &err);
		/* === ? test err ? */
	}
	if (config == 0) {
		/* getconfig failed, or frontend demanded default config */

		char	*str;	/* _nsw_getoneconfig() clobbers its argument */

		if ((str = libc_strdup(s->p.default_config)) != 0) {
			config = _nsw_getoneconfig_v1(config_name, str, &err);
			libc_free(str);
		}
		if (config == 0) {
			_nss_db_state_destr(s);
			return (0);
		}
	}
	s->config = config;
	if ((s->max_src = config->num_lookups) <= 0 ||
	    (s->src = libc_malloc(s->max_src * sizeof (*s->src))) == 0) {
		_nss_db_state_destr(s);
		return (0);
	}
	for (n_src = 0, lkp = config->lookups;
	    n_src < s->max_src; n_src++, lkp = lkp->next) {
		s->src[n_src].lkp = lkp;
		(void) cond_init(&s->src[n_src].wanna_be, USYNC_THREAD, 0);
	}
	s->refcount = 1;
	return (s);
}

void
_nss_src_state_destr(struct nss_src_state *src, int max_dormant)
{
	if (max_dormant == 1) {
		if (src->n_dormant != 0) {
			(void) NSS_INVOKE_DBOP(src->dormant.single,
			    NSS_DBOP_DESTRUCTOR, 0);
		};
	} else if (src->dormant.multi != 0) {
		int	n;

		for (n = 0;  n < src->n_dormant;  n++) {
			(void) NSS_INVOKE_DBOP(src->dormant.multi[n],
			    NSS_DBOP_DESTRUCTOR, 0);
		}
		libc_free(src->dormant.multi);
	}

	/* cond_destroy(&src->wanna_be); */

	if (src->finder != 0) {
		(*src->finder->delete)(src->finder_priv, src->be_constr);
	}
}

/*
 * _nss_db_state_destr() -- used by NSS_UNREF_UNLOCK() to free the entire
 *	nss_db_state structure.
 * Assumes that s has been ref-counted down to zero (in particular,
 *	rootp->s has already been dealt with).
 *
 * Nobody else holds a pointer to *s (if they did, refcount != 0),
 *   so we can clean up state *after* we drop the lock (also, by the
 *   time we finish freeing the state structures, the lock may have
 *   ceased to exist -- if we were using the orphan_root).
 */

void
_nss_db_state_destr(struct nss_db_state *s)
{

	if (s == NULL)
		return;

	/* === mutex_destroy(&s->orphan_root.lock); */
	if (s->p.cleanup != 0) {
		(*s->p.cleanup)(&s->p);
	}
	if (s->config != 0) {
		(void) __nsw_freeconfig_v1(s->config);
	}
	if (s->src != 0) {
		int	n_src;

		for (n_src = 0;  n_src < s->max_src;  n_src++) {
			_nss_src_state_destr(&s->src[n_src],
			    s->p.max_dormant_per_src);
		}
		libc_free(s->src);
	}
	libc_free(s);
}


/*
 * _nss_status_vec() returns a bit vector of all status codes returned during
 * the most recent call to nss_search().
 * _nss_status_vec_p() returns a pointer to this bit vector, or NULL on
 * failure.
 * These functions are private.  Don't use them externally without discussing
 * it with the switch maintainers.
 */
static uint_t *
_nss_status_vec_p()
{
	return (tsdalloc(_T_NSS_STATUS_VEC, sizeof (uint_t), NULL));
}

unsigned int
_nss_status_vec(void)
{
	unsigned int *status_vec_p = _nss_status_vec_p();

	return ((status_vec_p != NULL) ? *status_vec_p : (1 << NSS_UNAVAIL));
}

static void
output_loop_diag_a(int n,
    char *dbase,
    struct __nsw_lookup_v1 *lkp)
{
	(void) fprintf(__nss_debug_file,
	    "NSS_retry(%d): '%s': trying '%s' ... ",
	    n, dbase, lkp->service_name);
	(void) fflush(__nss_debug_file);

}

static void
output_loop_diag_b(nss_status_t res,
    struct __nsw_lookup_v1 *lkp)
{
	(void) fprintf(__nss_debug_file, "result=");
	switch (res) {
	case NSS_SUCCESS:
		(void) fprintf(__nss_debug_file, "SUCCESS");
		break;
	case NSS_NOTFOUND:
		(void) fprintf(__nss_debug_file, "NOTFOUND");
		break;
	case NSS_UNAVAIL:
		(void) fprintf(__nss_debug_file, "UNAVAIL");
		break;
	case NSS_TRYAGAIN:
		(void) fprintf(__nss_debug_file, "TRYAGAIN");
		break;
	case NSS_NISSERVDNS_TRYAGAIN:
		(void) fprintf(__nss_debug_file, "NISSERVDNS_TRYAGAIN");
		break;
	default:
		(void) fprintf(__nss_debug_file, "undefined");
	}
	(void) fprintf(__nss_debug_file, ", action=");
	switch (lkp->actions[res]) {
	case __NSW_CONTINUE:
		(void) fprintf(__nss_debug_file, "CONTINUE");
		break;
	case  __NSW_RETURN:
		(void) fprintf(__nss_debug_file, "RETURN");
		break;
	case __NSW_TRYAGAIN_FOREVER:
		(void) fprintf(__nss_debug_file, "TRYAGAIN_FOREVER");
		break;
	case __NSW_TRYAGAIN_NTIMES:
		(void) fprintf(__nss_debug_file, "TRYAGAIN_NTIMES (N=%d)",
		    lkp->max_retries);
		break;
	case __NSW_TRYAGAIN_PAUSED:
		(void) fprintf(__nss_debug_file, "TRYAGAIN_PAUSED");
		break;
	default:
		(void) fprintf(__nss_debug_file, "undefined");
	}
	(void) fprintf(__nss_debug_file, "\n");
}

#define	NSS_BACKOFF(n, b, t) \
			((n) > ((b) + 3) ? t : (1 << ((n) - ((b) + 1))))

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

/*
 * Switch policy component functional interfaces
 */

void
nss_delete(nss_db_root_t *rootp)
{
	struct nss_db_state	*s;

	/* no name service cache daemon divert here */
	/* local nss_delete decrements state reference counts */
	/* and may free up opened switch resources. */

	NSS_ROOTLOCK(rootp, &s);
	if (s == 0) {
		NSS_UNLOCK(rootp);
	} else {
		rootp->s = 0;
		NSS_UNREF_UNLOCK(rootp, s);
	}
}

nss_status_t
nss_search(nss_db_root_t *rootp, nss_db_initf_t initf, int search_fnum,
    void *search_args)
{
	nss_status_t		res = NSS_UNAVAIL;
	struct nss_db_state	*s;
	int			n_src;
	unsigned int		*status_vec_p;

	/* name service cache daemon divert */
	res = _nsc_search(rootp, initf, search_fnum, search_args);
	if (res != NSS_TRYLOCAL)
		return (res);

	/* fall through - process locally */
	errno = 0;			/* just in case ... */
	res = NSS_UNAVAIL;
	status_vec_p = _nss_status_vec_p();

	if (status_vec_p == NULL) {
		return (NSS_UNAVAIL);
	}
	*status_vec_p = 0;

	NSS_LOCK_CHECK(rootp, initf, &s);
	if (s == 0) {
		NSS_UNLOCK(rootp);
		return (res);
	}
	NSS_STATE_REF_u(s);

	for (n_src = 0;  n_src < s->max_src;  n_src++) {
		nss_backend_t		*be;
		nss_backend_op_t	funcp;

		res = NSS_UNAVAIL;
		if ((be = nss_get_backend_u(&rootp, s, n_src)) != 0) {
			if ((funcp = NSS_LOOKUP_DBOP(be, search_fnum)) != 0) {
				int n_loop = 0;
				int no_backoff = 19;
				int max_backoff = 5;	/* seconds */

				do {
					/*
					 * Backend operation may take a while;
					 * drop the lock so we don't serialize
					 * more than necessary.
					 */
					NSS_UNLOCK(rootp);

					/* After several tries, backoff... */
					if (n_loop > no_backoff) {
						if (__nss_debug_eng_loop > 1)
							(void) fprintf(
							    __nss_debug_file,
							    "NSS: loop: "
							    "sleeping %d ...\n",
							    NSS_BACKOFF(n_loop,
							    no_backoff,
							    max_backoff));

						(void) sleep(NSS_BACKOFF(n_loop,
						    no_backoff, max_backoff));
					}

					if (__nss_debug_eng_loop)
						output_loop_diag_a(n_loop,
						    s->config->dbase,
						    s->src[n_src].lkp);


					res = (*funcp)(be, search_args);
					NSS_RELOCK(&rootp, s);
					n_loop++;
					if (__nss_debug_eng_loop)
						output_loop_diag_b(res,
						    s->src[n_src].lkp);
				} while (retry_test(res, n_loop,
				    s->src[n_src].lkp));
			}
			nss_put_backend_u(s, n_src, be);
		}
		*status_vec_p |= (1 << res);
		if (__NSW_ACTION_V1(s->src[n_src].lkp, res) == __NSW_RETURN) {
			if (__nss_debug_eng_loop)
				(void) fprintf(__nss_debug_file,
				    "NSS: '%s': return.\n",
				    s->config->dbase);
			break;
		} else
			if (__nss_debug_eng_loop)
				(void) fprintf(__nss_debug_file,
				    "NSS: '%s': continue ...\n",
				    s->config->dbase);
	}
	NSS_UNREF_UNLOCK(rootp, s);
	return (res);
}


/*
 * Start of nss_{setent|getent|endent}
 */

/*
 * State (here called "context") for one setent/getent.../endent sequence.
 *   In principle there could be multiple contexts active for a single
 *   database;  in practice, since Posix and UI have helpfully said that
 *   getent() state is global rather than, say, per-thread or user-supplied,
 *   we have at most one of these per nss_db_state.
 *   XXX ? Is this statement still true?
 *
 * NSS2 - a client's context is maintained as a cookie delivered by and
 * passed to nscd.  The cookie is a 64 bit (nssuint_t) unique opaque value
 * created by nscd.
 * cookie states:
 *	NSCD_NEW_COOKIE		- cookie value uninitialized
 *	NSCD_LOCAL_COOKIE	- setent is a local setent
 *	all other		- NSCD unique opaque id for this setent
 * A client's context is also associated with a seq_num.  This is a nscd
 * opaque 64 bit (nssuint_t) value passed with a cookie, and used to by nscd
 * to validate the sequencing of the context.  The client treats this as
 * a pass through value.
 *
 * XXX ??  Use Cookie as cross-check info so that we can detect an
 * nss_context that missed an nss_delete() or similar.
 */

struct nss_getent_context {
	int			n_src;	/* >= max_src ==> end of sequence */
	nss_backend_t		*be;
	struct nss_db_state	*s;
	nssuint_t		cookie;
	nssuint_t		seq_num;
	nssuint_t		cookie_setent;
	nss_db_params_t		param;
};

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
nss_setent(nss_db_root_t *rootp, nss_db_initf_t initf, nss_getent_t *contextpp)
{
	if (contextpp == 0) {
		return;
	}
	cancel_safe_mutex_lock(&contextpp->lock);
	nss_setent_u(rootp, initf, contextpp);
	cancel_safe_mutex_unlock(&contextpp->lock);
}

nss_status_t
nss_getent(nss_db_root_t *rootp, nss_db_initf_t initf, nss_getent_t *contextpp,
    void *args)
{
	nss_status_t		status;

	if (contextpp == 0) {
		return (NSS_UNAVAIL);
	}
	cancel_safe_mutex_lock(&contextpp->lock);
	status = nss_getent_u(rootp, initf, contextpp, args);
	cancel_safe_mutex_unlock(&contextpp->lock);
	return (status);
}

void
nss_endent(nss_db_root_t *rootp, nss_db_initf_t initf, nss_getent_t *contextpp)
{
	if (contextpp == 0) {
		return;
	}
	cancel_safe_mutex_lock(&contextpp->lock);
	nss_endent_u(rootp, initf, contextpp);
	cancel_safe_mutex_unlock(&contextpp->lock);
}

/*
 * Each of the _u versions of the nss interfaces assume that the context
 * lock is held.  No need to divert to nscd.  Private to local sequencing.
 */

static void
end_iter_u(nss_db_root_t *rootp, struct nss_getent_context *contextp)
{
	struct nss_db_state	*s;
	nss_backend_t		*be;
	int			n_src;

	s = contextp->s;
	n_src = contextp->n_src;
	be = contextp->be;

	if (s != 0) {
		if (n_src < s->max_src && be != 0) {
			(void) NSS_INVOKE_DBOP(be, NSS_DBOP_ENDENT, 0);
			NSS_RELOCK(&rootp, s);
			nss_put_backend_u(s, n_src, be);
			contextp->be = 0;  /* Should be unnecessary, but hey */
			NSS_UNREF_UNLOCK(rootp, s);
		}
		contextp->s = 0;
	}
}

static void
nss_setent_u(nss_db_root_t *rootp, nss_db_initf_t initf,
    nss_getent_t *contextpp)
{
	nss_status_t		status;
	struct nss_db_state	*s;
	struct nss_getent_context *contextp;
	nss_backend_t		*be;
	int			n_src;

	/* setup process wide context while locked */
	if ((contextp = contextpp->ctx) == 0) {
		if ((contextp = libc_malloc(sizeof (*contextp))) == 0) {
			return;
		}
		contextpp->ctx = contextp;
		contextp->cookie = NSCD_NEW_COOKIE;	/* cookie init */
		contextp->seq_num = 0;			/* seq_num init */
		s = 0;
	} else {
		s = contextp->s;
		if (contextp->cookie != NSCD_LOCAL_COOKIE)
			contextp->cookie = NSCD_NEW_COOKIE;
	}

	/* name service cache daemon divert */
	if (contextp->cookie == NSCD_NEW_COOKIE) {
		status = _nsc_setent_u(rootp, initf, contextpp);
		if (status != NSS_TRYLOCAL)
			return;
	}

	/* fall through - process locally */
	if (s == 0) {
		NSS_LOCK_CHECK(rootp, initf, &s);
		if (s == 0) {
			/* Couldn't set up state, so quit */
			NSS_UNLOCK(rootp);
			/* ==== is there any danger of not having done an */
			/* end_iter() here, and hence of losing backends? */
			contextpp->ctx = 0;
			libc_free(contextp);
			return;
		}
		NSS_STATE_REF_u(s);
		contextp->s = s;
	} else {
		s	= contextp->s;
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
			NSS_RELOCK(&rootp, s);
			nss_put_backend_u(s, n_src, be);
			contextp->be = 0;	/* Play it safe */
		} else {
			NSS_RELOCK(&rootp, s);
		}
	}
	for (n_src = 0, be = 0; n_src < s->max_src &&
	    (be = nss_get_backend_u(&rootp, s, n_src)) == 0; n_src++) {
		;
	}
	NSS_UNLOCK(rootp);

	contextp->n_src	= n_src;
	contextp->be	= be;

	if (be == 0) {
		/* Things are broken enough that we can't do setent/getent */
		nss_endent_u(rootp, initf, contextpp);
		return;
	}
	(void) NSS_INVOKE_DBOP(be, NSS_DBOP_SETENT, 0);
}

static nss_status_t
nss_getent_u(nss_db_root_t *rootp, nss_db_initf_t initf,
    nss_getent_t *contextpp, void *args)
{
	nss_status_t		status;
	struct nss_db_state	*s;
	struct nss_getent_context *contextp;
	int			n_src;
	nss_backend_t		*be;

	if ((contextp = contextpp->ctx) == 0) {
		nss_setent_u(rootp, initf, contextpp);
		if ((contextp = contextpp->ctx) == 0) {
			/* Give up */
			return (NSS_UNAVAIL);
		}
	}
	/* name service cache daemon divert */
	status = _nsc_getent_u(rootp, initf, contextpp, args);
	if (status != NSS_TRYLOCAL)
		return (status);

	/* fall through - process locally */
	s	= contextp->s;
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
		nss_status_t res;

		if (be == 0) {
			/* If it's null it's a bug, but let's play safe */
			res = NSS_UNAVAIL;
		} else {
			res = NSS_INVOKE_DBOP(be, NSS_DBOP_GETENT, args);
		}

		if (__NSW_ACTION_V1(s->src[n_src].lkp, res) == __NSW_RETURN) {
			if (res != __NSW_SUCCESS) {
				end_iter_u(rootp, contextp);
			}
			return (res);
		}
		(void) NSS_INVOKE_DBOP(be, NSS_DBOP_ENDENT, 0);
		NSS_RELOCK(&rootp, s);
		nss_put_backend_u(s, n_src, be);
		do {
			n_src++;
		} while (n_src < s->max_src &&
		    (be = nss_get_backend_u(&rootp, s, n_src)) == 0);
		contextp->be = be;
		if (be == 0) {
			/*
			 * This is the case where we failed to get the backend
			 * for the last source. We exhausted all sources.
			 *
			 * We need to do cleanup ourselves because end_iter_u()
			 * does not do it for be == 0.
			 */
			NSS_UNREF_UNLOCK(rootp, s);
			contextp->s = 0;
			break;
		} else {
			NSS_UNLOCK(rootp);
			contextp->n_src = n_src;
			(void) NSS_INVOKE_DBOP(be, NSS_DBOP_SETENT, 0);
		}
	}
	/* Got to the end of the sources without finding another entry */
	end_iter_u(rootp, contextp);
	return (NSS_SUCCESS);
	/* success is either a successful entry or end of the sources */
}

/*ARGSUSED*/
static void
nss_endent_u(nss_db_root_t *rootp, nss_db_initf_t initf,
    nss_getent_t *contextpp)
{
	nss_status_t		status;
	struct nss_getent_context *contextp;

	if ((contextp = contextpp->ctx) == 0) {
		/* nss_endent() on an unused context is a no-op */
		return;
	}

	/* notify name service cache daemon */
	status = _nsc_endent_u(rootp, initf, contextpp);
	if (status != NSS_TRYLOCAL) {
		/* clean up */
		libc_free(contextp);
		contextpp->ctx = 0;
		return;
	}

	/* fall through - process locally */

	/*
	 * Existing code (BSD, SunOS) works in such a way that getXXXent()
	 *   following an endXXXent() behaves as though the user had invoked
	 *   setXXXent(), i.e. it iterates properly from the beginning.
	 * We'd better not break this, so our choices are
	 *	(1) leave the context structure around, and do nss_setent or
	 *	    something equivalent,
	 *   or	(2) free the context completely, and rely on the code in
	 *	    nss_getent() that makes getXXXent() do the right thing
	 *	    even without a preceding setXXXent().
	 * The code below does (2), which frees up resources nicely but will
	 * cost more if the user then does more getXXXent() operations.
	 * Moral:  for efficiency, don't call endXXXent() prematurely.
	 */
	end_iter_u(rootp, contextp);
	libc_free(contextp);
	contextpp->ctx = 0;
}

/*
 * pack dbd data into header
 * Argment pointers assumed valid.
 * poff offset position pointer
 *   IN = starting offset for dbd header
 *   OUT = starting offset for next section
 */

static nss_status_t
nss_pack_dbd(void *buffer, size_t bufsize, nss_db_params_t *p, size_t *poff)
{
	nss_pheader_t		*pbuf = (nss_pheader_t *)buffer;
	nss_dbd_t		*pdbd;
	size_t			off = *poff;
	size_t			len, blen;
	size_t			n, nc, dc;
	char			*bptr;

	pbuf->dbd_off = (nssuint_t)off;
	bptr = (char *)buffer + off;
	blen = bufsize - off;
	len = sizeof (nss_dbd_t);

	n = nc = dc = 0;
	if (p->name == NULL) {
		errno = ERANGE;			/* actually EINVAL */
		return (NSS_ERROR);
	}

	/* if default config not specified, the flag should be reset */
	if (p->default_config == NULL) {
		p->default_config = "<NULL>";
		p->flags = p->flags & ~NSS_USE_DEFAULT_CONFIG;
	}

	n = strlen(p->name) + 1;
	dc = strlen(p->default_config) + 1;
	if (n < 2 || dc < 2) {			/* What no DB? */
		errno = ERANGE;			/* actually EINVAL */
		return (NSS_ERROR);
	}
	if (p->config_name != NULL) {
		nc = strlen(p->config_name) + 1;
	}
	if ((len + n + nc + dc) >= blen) {
		errno = ERANGE;			/* actually EINVAL */
		return (NSS_ERROR);
	}

	pdbd = (nss_dbd_t *)((void *)bptr);
	bptr += len;
	pdbd->flags = p->flags;
	pdbd->o_name = len;
	(void) strlcpy(bptr, p->name, n);
	len += n;
	bptr += n;
	if (nc == 0) {
		pdbd->o_config_name = 0;
	} else {
		pdbd->o_config_name = len;
		(void) strlcpy(bptr, p->config_name, nc);
		bptr += nc;
		len += nc;
	}
	pdbd->o_default_config = len;
	(void) strlcpy(bptr, p->default_config, dc);
	len += dc;
	pbuf->dbd_len = (nssuint_t)len;
	off += ROUND_UP(len, sizeof (nssuint_t));
	*poff = off;
	return (NSS_SUCCESS);
}

/*
 * Switch packed and _nsc (switch->nscd) interfaces
 * Return: NSS_SUCCESS (OK to proceed), NSS_ERROR, NSS_NOTFOUND
 */

/*ARGSUSED*/
nss_status_t
nss_pack(void *buffer, size_t bufsize, nss_db_root_t *rootp,
    nss_db_initf_t initf, int search_fnum, void *search_args)
{
	nss_pheader_t		*pbuf = (nss_pheader_t *)buffer;
	nss_XbyY_args_t		*in = (nss_XbyY_args_t *)search_args;
	nss_db_params_t		tparam = { 0 };
	nss_status_t		ret = NSS_ERROR;
	const char		*dbn;
	size_t			blen, len, off = 0;
	char			*bptr;
	struct nss_groupsbymem	*gbm;

	if (pbuf == NULL || in == NULL || initf == (nss_db_initf_t)NULL) {
		errno = ERANGE;			/* actually EINVAL */
		return (ret);
	}
	tparam.cleanup = NULL;
	(*initf)(&tparam);
	if ((dbn = tparam.name) == 0) {
		if (tparam.cleanup != 0)
			(tparam.cleanup)(&tparam);
		errno = ERANGE;			/* actually EINVAL */
		return (ret);
	}

	/* init buffer header */
	pbuf->pbufsiz = (nssuint_t)bufsize;
	pbuf->p_ruid = (uint32_t)getuid();
	pbuf->p_euid = (uint32_t)geteuid();
	pbuf->p_version = NSCD_HEADER_REV;
	pbuf->p_status = 0;
	pbuf->p_errno = 0;
	pbuf->p_herrno = 0;

	/* possible audituser init */
	if (strcmp(dbn, NSS_DBNAM_AUTHATTR) == 0 && in->h_errno != 0)
		pbuf->p_herrno = (uint32_t)in->h_errno;

	pbuf->libpriv = 0;

	off = sizeof (nss_pheader_t);

	/* setup getXbyY operation - database and sub function */
	pbuf->nss_dbop = (uint32_t)search_fnum;
	ret = nss_pack_dbd(buffer, bufsize, &tparam, &off);
	if (ret != NSS_SUCCESS) {
		errno = ERANGE;			/* actually EINVAL */
		return (ret);
	}
	ret = NSS_ERROR;
	/* setup request key */
	pbuf->key_off = (nssuint_t)off;
	bptr = (char *)buffer + off;
	blen = bufsize - off;
	/* use key2str if provided, else call default getXbyY packer */
	if (strcmp(dbn, NSS_DBNAM_NETGROUP) == 0) {
		/* This has to run locally due to backend knowledge */
		if (search_fnum == NSS_DBOP_NETGROUP_SET) {
			errno = 0;
			return (NSS_TRYLOCAL);
		}
		/* use default packer for known getXbyY ops */
		ret = nss_default_key2str(bptr, blen, in, dbn,
		    search_fnum, &len);
	} else if (in->key2str == NULL ||
	    (search_fnum == NSS_DBOP_GROUP_BYMEMBER &&
	    strcmp(dbn, NSS_DBNAM_GROUP) == 0)) {
		/* use default packer for known getXbyY ops */
		ret = nss_default_key2str(bptr, blen, in, dbn,
		    search_fnum, &len);
	} else {
		ret = (*in->key2str)(bptr, blen, &in->key, &len);
	}
	if (tparam.cleanup != 0)
		(tparam.cleanup)(&tparam);
	if (ret != NSS_SUCCESS) {
		errno = ERANGE;			/* actually ENOMEM */
		return (ret);
	}
	pbuf->key_len = (nssuint_t)len;
	off += ROUND_UP(len, sizeof (nssuint_t));

	pbuf->data_off = (nssuint_t)off;
	pbuf->data_len = (nssuint_t)(bufsize - off);
	/*
	 * Prime data return with first result if
	 * the first result is passed in
	 * [_getgroupsbymember oddness]
	 */
	gbm = (struct nss_groupsbymem *)search_args;
	if (search_fnum == NSS_DBOP_GROUP_BYMEMBER &&
	    strcmp(dbn, NSS_DBNAM_GROUP) == 0 && gbm->numgids == 1) {
		gid_t	*gidp;
		gidp = (gid_t *)((void *)((char *)buffer + off));
		*gidp = gbm->gid_array[0];
	}

	errno = 0;				/* just in case ... */
	return (NSS_SUCCESS);
}

/*
 * Switch packed and _nsc (switch->nscd) {set/get/end}ent interfaces
 * Return: NSS_SUCCESS (OK to proceed), NSS_ERROR, NSS_NOTFOUND
 */

/*ARGSUSED*/
nss_status_t
nss_pack_ent(void *buffer, size_t bufsize, nss_db_root_t *rootp,
    nss_db_initf_t initf, nss_getent_t *contextpp)
{
	nss_pheader_t		*pbuf = (nss_pheader_t *)buffer;
	struct nss_getent_context *contextp = contextpp->ctx;
	nss_status_t		ret = NSS_ERROR;
	size_t			blen, len = 0, off = 0;
	char			*bptr;
	nssuint_t		*nptr;

	if (pbuf == NULL || initf == (nss_db_initf_t)NULL) {
		errno = ERANGE;			/* actually EINVAL */
		return (ret);
	}

	/* init buffer header */
	pbuf->pbufsiz = (nssuint_t)bufsize;
	pbuf->p_ruid = (uint32_t)getuid();
	pbuf->p_euid = (uint32_t)geteuid();
	pbuf->p_version = NSCD_HEADER_REV;
	pbuf->p_status = 0;
	pbuf->p_errno = 0;
	pbuf->p_herrno = 0;
	pbuf->libpriv = 0;

	off = sizeof (nss_pheader_t);

	/* setup getXXXent operation - database and sub function */
	pbuf->nss_dbop = (uint32_t)0;	/* iterators have no dbop */
	ret = nss_pack_dbd(buffer, bufsize, &contextp->param, &off);
	if (ret != NSS_SUCCESS) {
		errno = ERANGE;			/* actually EINVAL */
		return (ret);
	}
	ret = NSS_ERROR;
	off += ROUND_UP(len, sizeof (nssuint_t));

	pbuf->key_off = (nssuint_t)off;
	bptr = (char *)buffer + off;
	blen = bufsize - off;
	len = (size_t)(sizeof (nssuint_t) * 2);
	if (len >= blen) {
		errno = ERANGE;			/* actually EINVAL */
		return (ret);
	}
	nptr = (nssuint_t *)((void *)bptr);
	*nptr++ = contextp->cookie;
	*nptr = contextp->seq_num;
	pbuf->key_len = (nssuint_t)len;

	off += len;
	pbuf->data_off = (nssuint_t)off;
	pbuf->data_len = (nssuint_t)(bufsize - off);
	return (NSS_SUCCESS);
}

/*
 * Unpack packed arguments buffer
 * Return: status, errnos and results from requested operation.
 *
 * NOTES: When getgroupsbymember is being processed in the NSCD backend,
 * or via the backwards compatibility interfaces then the standard
 * str2group API is used in conjunction with process_cstr.  When,
 * processing a returned buffer, in NSS2 the return results are the
 * already digested groups array.  Therefore, unpack the digested results
 * back to the return buffer.
 *
 * Note: the digested results are nssuint_t quantities.  _getgroupsbymember
 * digests int quantities.  Therefore convert.  Assume input is in nssuint_t
 * quantities.  Store in an int array... Assume gid's are <= 32 bits...
 */

/*ARGSUSED*/
nss_status_t
nss_unpack(void *buffer, size_t bufsize, nss_db_root_t *rootp,
    nss_db_initf_t initf, int search_fnum, void *search_args)
{
	nss_pheader_t		*pbuf = (nss_pheader_t *)buffer;
	nss_XbyY_args_t		*in = (nss_XbyY_args_t *)search_args;
	nss_dbd_t		*pdbd;
	char			*dbn;
	nss_status_t		status;
	char			*buf;
	int			len;
	int			ret;
	int			i;
	int			fmt_type;
	gid_t			*gidp;
	gid_t			*gptr;
	struct nss_groupsbymem	*arg;


	if (pbuf == NULL || in == NULL)
		return (-1);
	status = pbuf->p_status;
	/* Identify odd cases */
	pdbd = (nss_dbd_t *)((void *)((char *)buffer + pbuf->dbd_off));
	dbn = (char *)pdbd + pdbd->o_name;
	fmt_type = 0; /* nss_XbyY_args_t */
	if (search_fnum == NSS_DBOP_GROUP_BYMEMBER &&
	    strcmp(dbn, NSS_DBNAM_GROUP) == 0)
		fmt_type = 1; /* struct nss_groupsbymem */
	else if (search_fnum == NSS_DBOP_NETGROUP_IN &&
	    strcmp(dbn, NSS_DBNAM_NETGROUP) == 0)
		fmt_type = 2; /* struct nss_innetgr_args */

	/* if error - door's switch error */
	/* extended data could contain additional information? */
	if (status != NSS_SUCCESS) {
		if (fmt_type == 0) {
			in->h_errno = (int)pbuf->p_herrno;
			if (pbuf->p_errno == ERANGE)
				in->erange = 1;
		}
		return (status);
	}

	if (pbuf->data_off == 0 || pbuf->data_len == 0)
		return (NSS_NOTFOUND);

	buf = (char *)buffer + pbuf->data_off;
	len = pbuf->data_len;

	/* sidestep odd cases */
	if (fmt_type == 1) {
		arg = (struct nss_groupsbymem *)in;
		/* copy returned gid array from returned nscd buffer */
		i = len / sizeof (gid_t);
		/* not enough buffer */
		if (i > arg->maxgids) {
			i = arg->maxgids;
		}
		arg->numgids = i;
		gidp = arg->gid_array;
		gptr = (gid_t *)((void *)buf);
		(void) memcpy(gidp, gptr, len);
		return (NSS_SUCCESS);
	}
	if (fmt_type == 2) {
		struct nss_innetgr_args *arg = (struct nss_innetgr_args *)in;

		if (pbuf->p_status == NSS_SUCCESS) {
			arg->status = NSS_NETGR_FOUND;
			return (NSS_SUCCESS);
		} else {
			arg->status = NSS_NETGR_NO;
			return (NSS_NOTFOUND);
		}
	}

	/* process the normal cases */
	/* marshall data directly into users buffer */
	ret = (*in->str2ent)(buf, len, in->buf.result, in->buf.buffer,
	    in->buf.buflen);
	if (ret == NSS_STR_PARSE_ERANGE) {
		in->returnval = 0;
		in->returnlen = 0;
		in->erange    = 1;
		ret = NSS_NOTFOUND;
	} else if (ret == NSS_STR_PARSE_SUCCESS) {
		in->returnval = in->buf.result;
		in->returnlen =  len;
		ret = NSS_SUCCESS;
	}
	in->h_errno = (int)pbuf->p_herrno;
	return ((nss_status_t)ret);
}

/*
 * Unpack a returned packed {set,get,end}ent arguments buffer
 * Return: status, errnos, cookie info and results from requested operation.
 */

/*ARGSUSED*/
nss_status_t
nss_unpack_ent(void *buffer, size_t bufsize, nss_db_root_t *rootp,
    nss_db_initf_t initf, nss_getent_t *contextpp, void *args)
{
	nss_pheader_t		*pbuf = (nss_pheader_t *)buffer;
	nss_XbyY_args_t		*in = (nss_XbyY_args_t *)args;
	struct nss_getent_context *contextp = contextpp->ctx;
	nssuint_t		*nptr;
	nssuint_t		cookie;
	nss_status_t		status;
	char			*buf;
	int			len;
	int			ret;

	if (pbuf == NULL)
		return (-1);
	status = pbuf->p_status;
	/* if error - door's switch error */
	/* extended data could contain additional information? */
	if (status != NSS_SUCCESS)
		return (status);

	/* unpack assigned cookie from SET/GET/END request */
	if (pbuf->key_off == 0 ||
	    pbuf->key_len != (sizeof (nssuint_t) * 2))
		return (NSS_NOTFOUND);

	nptr = (nssuint_t *)((void *)((char *)buffer + pbuf->key_off));
	cookie = contextp->cookie;
	if (cookie != NSCD_NEW_COOKIE && cookie != contextp->cookie_setent &&
	    cookie != *nptr) {
		/*
		 * Should either be new, or the cookie returned by the last
		 * setent (i.e., this is the first getent after the setent)
		 * or a match, else error
		 */
		return (NSS_NOTFOUND);
	}
	/* save away for the next ent request */
	contextp->cookie = *nptr++;
	contextp->seq_num = *nptr;

	/* All done if no marshalling is expected {set,end}ent */
	if (args == NULL)
		return (NSS_SUCCESS);

	/* unmarshall the data */
	if (pbuf->data_off == 0 || pbuf->data_len == 0)
		return (NSS_NOTFOUND);
	buf = (char *)buffer + pbuf->data_off;

	len = pbuf->data_len;

	/* marshall data directly into users buffer */
	ret = (*in->str2ent)(buf, len, in->buf.result, in->buf.buffer,
	    in->buf.buflen);
	if (ret == NSS_STR_PARSE_ERANGE) {
		in->returnval = 0;
		in->returnlen = 0;
		in->erange    = 1;
	} else if (ret == NSS_STR_PARSE_SUCCESS) {
		in->returnval = in->buf.result;
		in->returnlen =  len;
	}
	in->h_errno = (int)pbuf->p_herrno;
	return ((nss_status_t)ret);
}

/*
 * Start of _nsc_{search|setent_u|getent_u|endent_u} NSCD interposition funcs
 */

nss_status_t
_nsc_search(nss_db_root_t *rootp, nss_db_initf_t initf, int search_fnum,
    void *search_args)
{
	nss_pheader_t		*pbuf;
	void			*doorptr = NULL;
	size_t			bufsize = 0;
	size_t			datasize = 0;
	nss_status_t		status;

	if (_nsc_proc_is_cache() > 0) {
		/* internal nscd call - don't use the door */
		return (NSS_TRYLOCAL);
	}

	/* standard client calls nscd code */
	if (search_args == NULL)
		return (NSS_NOTFOUND);

	/* get the door buffer  & configured size */
	bufsize = ((nss_XbyY_args_t *)search_args)->buf.buflen;
	if (_nsc_getdoorbuf(&doorptr, &bufsize) != 0)
		return (NSS_TRYLOCAL);
	if (doorptr == NULL || bufsize == 0)
		return (NSS_TRYLOCAL);

	pbuf = (nss_pheader_t *)doorptr;
	/* pack argument and request into door buffer */
	pbuf->nsc_callnumber = NSCD_SEARCH;
	/* copy relevant door request info into door buffer */
	status = nss_pack((void *)pbuf, bufsize, rootp,
	    initf, search_fnum, search_args);

	/* Packing error return error results */
	if (status != NSS_SUCCESS)
		return (status);

	/* transfer packed switch request to nscd via door */
	/* data_off can be used because it is header+dbd_len+key_len */
	datasize = pbuf->data_off;
	status = _nsc_trydoorcall_ext(&doorptr, &bufsize, &datasize);

	/* If unsuccessful fallback to standard nss logic */
	if (status != NSS_SUCCESS) {
		/*
		 * check if doors reallocated the memory underneath us
		 * if they did munmap it or suffer a memory leak
		 */
		if (doorptr != (void *)pbuf) {
			_nsc_resizedoorbuf(bufsize);
			(void) munmap((void *)doorptr, bufsize);
		}
		return (NSS_TRYLOCAL);
	}

	/* unpack and marshall data/errors to user structure */
	/* set any error conditions */
	status = nss_unpack((void *)doorptr, bufsize, rootp, initf,
	    search_fnum, search_args);
	/*
	 * check if doors reallocated the memory underneath us
	 * if they did munmap it or suffer a memory leak
	 */
	if (doorptr != (void *)pbuf) {
		_nsc_resizedoorbuf(bufsize);
		(void) munmap((void *)doorptr, bufsize);
	}
	return (status);
}

/*
 * contact nscd for a cookie or to reset an existing cookie
 * if nscd fails (NSS_TRYLOCAL) then set cookie to -1 and
 * continue diverting to local
 */
nss_status_t
_nsc_setent_u(nss_db_root_t *rootp, nss_db_initf_t initf,
    nss_getent_t *contextpp)
{
	nss_status_t		status = NSS_TRYLOCAL;
	struct nss_getent_context *contextp = contextpp->ctx;
	nss_pheader_t		*pbuf;
	void			*doorptr = NULL;
	size_t			bufsize = 0;
	size_t			datasize = 0;

	/* return if already in local mode */
	if (contextp->cookie == NSCD_LOCAL_COOKIE)
		return (NSS_TRYLOCAL);

	if (_nsc_proc_is_cache() > 0) {
		/* internal nscd call - don't try to use the door */
		contextp->cookie = NSCD_LOCAL_COOKIE;
		return (NSS_TRYLOCAL);
	}

	/* get the door buffer & configured size */
	if (_nsc_getdoorbuf(&doorptr, &bufsize) != 0) {
		contextp->cookie = NSCD_LOCAL_COOKIE;
		return (NSS_TRYLOCAL);
	}
	if (doorptr == NULL || bufsize == 0) {
		contextp->cookie = NSCD_LOCAL_COOKIE;
		return (NSS_TRYLOCAL);
	}

	pbuf = (nss_pheader_t *)doorptr;
	pbuf->nsc_callnumber = NSCD_SETENT;

	contextp->param.cleanup = NULL;
	(*initf)(&contextp->param);
	if (contextp->param.name == 0) {
		if (contextp->param.cleanup != 0)
			(contextp->param.cleanup)(&contextp->param);
		errno = ERANGE;			/* actually EINVAL */
		return (NSS_ERROR);
	}

	/* pack relevant setent request info into door buffer */
	status = nss_pack_ent((void *)pbuf, bufsize, rootp, initf, contextpp);
	if (status != NSS_SUCCESS)
		return (status);

	/* transfer packed switch request to nscd via door */
	/* data_off can be used because it is header+dbd_len+key_len */
	datasize = pbuf->data_off;
	status = _nsc_trydoorcall_ext(&doorptr, &bufsize, &datasize);

	/* If fallback to standard nss logic (door failure) if possible */
	if (status != NSS_SUCCESS) {
		if (contextp->cookie == NSCD_NEW_COOKIE) {
			contextp->cookie = NSCD_LOCAL_COOKIE;
			return (NSS_TRYLOCAL);
		}
		return (NSS_UNAVAIL);
	}
	/* unpack returned cookie stash it away */
	status = nss_unpack_ent((void *)doorptr, bufsize, rootp,
	    initf, contextpp, NULL);
	/* save the setent cookie for later use */
	contextp->cookie_setent = contextp->cookie;
	/*
	 * check if doors reallocated the memory underneath us
	 * if they did munmap it or suffer a memory leak
	 */
	if (doorptr != (void *)pbuf) {
		_nsc_resizedoorbuf(bufsize);
		(void) munmap((void *)doorptr, bufsize);
	}
	return (status);
}

nss_status_t
_nsc_getent_u(nss_db_root_t *rootp, nss_db_initf_t initf,
    nss_getent_t *contextpp, void *args)
{
	nss_status_t		status = NSS_TRYLOCAL;
	struct nss_getent_context *contextp = contextpp->ctx;
	nss_pheader_t		*pbuf;
	void			*doorptr = NULL;
	size_t			bufsize = 0;
	size_t			datasize = 0;

	/* return if already in local mode */
	if (contextp->cookie == NSCD_LOCAL_COOKIE)
		return (NSS_TRYLOCAL);

	/* _nsc_setent_u already checked for nscd local case ... proceed */
	if (args == NULL)
		return (NSS_NOTFOUND);

	/* get the door buffer  & configured size */
	bufsize = ((nss_XbyY_args_t *)args)->buf.buflen;
	if (_nsc_getdoorbuf(&doorptr, &bufsize) != 0)
		return (NSS_UNAVAIL);
	if (doorptr == NULL || bufsize == 0)
		return (NSS_UNAVAIL);

	pbuf = (nss_pheader_t *)doorptr;
	pbuf->nsc_callnumber = NSCD_GETENT;

	/* pack relevant setent request info into door buffer */
	status = nss_pack_ent((void *)pbuf, bufsize, rootp, initf, contextpp);
	if (status != NSS_SUCCESS)
		return (status);

	/* transfer packed switch request to nscd via door */
	/* data_off can be used because it is header+dbd_len+key_len */
	datasize = pbuf->data_off;
	status = _nsc_trydoorcall_ext(&doorptr, &bufsize, &datasize);

	/* If fallback to standard nss logic (door failure) if possible */
	if (status != NSS_SUCCESS) {
		if (status == NSS_TRYLOCAL ||
		    contextp->cookie == NSCD_NEW_COOKIE) {
			contextp->cookie = NSCD_LOCAL_COOKIE;

			/* init the local cookie */
			nss_setent_u(rootp, initf, contextpp);
			if (contextpp->ctx == 0)
				return (NSS_UNAVAIL);
			return (NSS_TRYLOCAL);
		}
		return (NSS_UNAVAIL);
	}
	/* check error, unpack and process results */
	status = nss_unpack_ent((void *)doorptr, bufsize, rootp,
	    initf, contextpp, args);
	/*
	 * check if doors reallocated the memory underneath us
	 * if they did munmap it or suffer a memory leak
	 */
	if (doorptr != (void *)pbuf) {
		_nsc_resizedoorbuf(bufsize);
		(void) munmap((void *)doorptr, bufsize);
	}
	return (status);
}

nss_status_t
_nsc_endent_u(nss_db_root_t *rootp, nss_db_initf_t initf,
    nss_getent_t *contextpp)
{
	nss_status_t		status = NSS_TRYLOCAL;
	struct nss_getent_context *contextp = contextpp->ctx;
	nss_pheader_t		*pbuf;
	void			*doorptr = NULL;
	size_t			bufsize = 0;
	size_t			datasize = 0;

	/* return if already in local mode */
	if (contextp->cookie == NSCD_LOCAL_COOKIE)
		return (NSS_TRYLOCAL);

	/* _nsc_setent_u already checked for nscd local case ... proceed */

	/* get the door buffer  & configured size */
	if (_nsc_getdoorbuf(&doorptr, &bufsize) != 0)
		return (NSS_UNAVAIL);
	if (doorptr == NULL || bufsize == 0)
		return (NSS_UNAVAIL);

	/* pack up a NSCD_ENDGET request passing in the cookie */
	pbuf = (nss_pheader_t *)doorptr;
	pbuf->nsc_callnumber = NSCD_ENDENT;

	/* pack relevant setent request info into door buffer */
	status = nss_pack_ent((void *)pbuf, bufsize, rootp, initf, contextpp);
	if (status != NSS_SUCCESS)
		return (status);

	/* transfer packed switch request to nscd via door */
	/* data_off can be used because it is header+dbd_len+key_len */
	datasize = pbuf->data_off;
	(void) _nsc_trydoorcall_ext(&doorptr, &bufsize, &datasize);

	/* error codes & unpacking ret values don't matter.  We're done */

	/*
	 * check if doors reallocated the memory underneath us
	 * if they did munmap it or suffer a memory leak
	 */
	if (doorptr != (void *)pbuf) {
		_nsc_resizedoorbuf(bufsize);
		(void) munmap((void *)doorptr, bufsize);
	}

	/* clean up initf setup */
	if (contextp->param.cleanup != 0)
		(contextp->param.cleanup)(&contextp->param);
	contextp->param.cleanup = NULL;

	/* clear cookie */
	contextp->cookie = NSCD_NEW_COOKIE;
	return (NSS_SUCCESS);
}

/*
 * Internal private API to return default suggested buffer sizes
 * for nsswitch API requests.
 */

size_t
_nss_get_bufsizes(int arg)
{
	switch (arg) {
	case _SC_GETGR_R_SIZE_MAX:
		return (__nss_buflen_group);
	}
	return (__nss_buflen_default);
}

void *
_nss_XbyY_fini(nss_XbyY_args_t *args)
{
	if ((args->returnval == NULL) && (args->erange != 0))
		errno = ERANGE;
	return (args->returnval);
}
