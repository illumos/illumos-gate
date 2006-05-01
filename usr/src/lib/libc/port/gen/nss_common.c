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

/*
 * Shared code used by the name-service-switch frontends (e.g. getpwnam_r())
 */

#pragma weak nss_delete = _nss_delete
#pragma weak nss_endent = _nss_endent
#pragma weak nss_getent = _nss_getent
#pragma weak nss_search = _nss_search
#pragma weak nss_setent = _nss_setent

#include "synonyms.h"
#include <mtlib.h>
#include <dlfcn.h>

#define	__NSS_PRIVATE_INTERFACE
#include "nsswitch_priv.h"
#undef	__NSS_PRIVATE_INTERFACE

#include <nss_common.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <thread.h>
#include "libc.h"
#include "tsd.h"

/*
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

#define	NSS_ROOTLOCK(r, sp)	((void) _private_mutex_lock(&(r)->lock), \
				*(sp) = (r)->s)

#define	NSS_UNLOCK(r)		((void) _private_mutex_unlock(&(r)->lock))

#define	NSS_CHECKROOT(rp, s)	((s) != (*(rp))->s &&			\
			((void) _private_mutex_unlock(&(*(rp))->lock),	\
			(void) _private_mutex_lock(&(s)->orphan_root.lock), \
			*(rp) = &(s)->orphan_root))

#define	NSS_RELOCK(rp, s)	((void) _private_mutex_lock(&(*(rp))->lock), \
			NSS_CHECKROOT(rp, s))

#define	NSS_STATE_REF_u(s)	(++(s)->refcount)

#define	NSS_UNREF_UNLOCK(r, s)	(--(s)->refcount != 0			\
			? ((void)NSS_UNLOCK(r))				\
			: (NSS_UNLOCK(r), (void)_nss_db_state_destr(s)))

#define	NSS_LOCK_CHECK(r, f, sp)    (NSS_ROOTLOCK((r), (sp)),	\
				    *(sp) == 0 &&		\
				    (r->s = *(sp) = _nss_db_state_constr(f)))
/* === In the future, NSS_LOCK_CHECK() may also have to check that   */
/* === the config info hasn't changed (by comparing version numbers) */


/* NSS_OPTIONS infrastructure BEGIN */
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
/* NSS_OPTIONS/NIS_OPTIONS infrastructure END */


static nss_backend_t *
nss_get_backend_u(nss_db_root_t **rootpp, struct nss_db_state *s, int n_src)
{
	struct nss_src_state	*src = &s->src[n_src];
	nss_backend_t		*be;

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

				c = (*bf->lookup)
					(bf->lookup_priv,
						s->p.name,
						src->lkp->service_name,
						&src->finder_priv);
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
						src->lkp->service_name,
						0 /* === unimplemented */);
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
		(void) cond_wait(&src->wanna_be, &(*rootpp)->lock);
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
	(void) _private_mutex_init(&s->orphan_root.lock, USYNC_THREAD, 0);

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
	/* === _private_mutex_destroy(&s->orphan_root.lock); */
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

void
nss_delete(nss_db_root_t *rootp)
{
	struct nss_db_state	*s;

	NSS_ROOTLOCK(rootp, &s);
	if (s == 0) {
		NSS_UNLOCK(rootp);
	} else {
		rootp->s = 0;
		NSS_UNREF_UNLOCK(rootp, s);
	}
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
output_loop_diag_a(
	int n,
	char *dbase,
	struct __nsw_lookup_v1 *lkp)

{
	(void) fprintf(__nss_debug_file,
		"NSS_retry(%d): '%s': trying '%s' ... ",
		n, dbase, lkp->service_name);
	(void) fflush(__nss_debug_file);

}

static void
output_loop_diag_b(
	nss_status_t res,
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

nss_status_t
nss_search(nss_db_root_t *rootp, nss_db_initf_t initf, int search_fnum,
	void *search_args)
{
	nss_status_t		res = NSS_UNAVAIL;
	struct nss_db_state	*s;
	int			n_src;
	unsigned int		*status_vec_p = _nss_status_vec_p();

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
						(void) fprintf(__nss_debug_file,
						"NSS: loop: sleeping %d ...\n",
						    NSS_BACKOFF(n_loop,
						    no_backoff, max_backoff));

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
 * Start of nss_setent()/nss_getent()/nss_endent()
 */

/*
 * State (here called "context") for one setent/getent.../endent sequence.
 *   In principle there could be multiple contexts active for a single
 *   database;  in practice, since Posix and UI have helpfully said that
 *   getent() state is global rather than, say, per-thread or user-supplied,
 *   we have at most one of these per nss_db_state.
 */

struct nss_getent_context {
	int			n_src;	/* >= max_src ==> end of sequence */
	nss_backend_t		*be;
	struct nss_db_state	*s;
	/*
	 * XXX ??  Should contain enough cross-check info that we can detect an
	 * nss_context that missed an nss_delete() or similar.
	 */
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
	(void) _private_mutex_lock(&contextpp->lock);
	nss_setent_u(rootp, initf, contextpp);
	(void) _private_mutex_unlock(&contextpp->lock);
}

nss_status_t
nss_getent(nss_db_root_t *rootp, nss_db_initf_t initf, nss_getent_t *contextpp,
	void *args)
{
	nss_status_t		status;

	if (contextpp == 0) {
		return (NSS_UNAVAIL);
	}
	(void) _private_mutex_lock(&contextpp->lock);
	status = nss_getent_u(rootp, initf, contextpp, args);
	(void) _private_mutex_unlock(&contextpp->lock);
	return (status);
}

void
nss_endent(nss_db_root_t *rootp, nss_db_initf_t initf, nss_getent_t *contextpp)
{
	if (contextpp == 0) {
		return;
	}
	(void) _private_mutex_lock(&contextpp->lock);
	nss_endent_u(rootp, initf, contextpp);
	(void) _private_mutex_unlock(&contextpp->lock);
}

/*
 * Each of the _u versions of the nss interfaces assume that the context
 * lock is held.
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
	struct nss_db_state	*s;
	struct nss_getent_context *contextp;
	nss_backend_t		*be;
	int			n_src;

	if ((contextp = contextpp->ctx) == 0) {
		if ((contextp = libc_malloc(sizeof (*contextp))) == 0) {
			return;
		}
		contextpp->ctx = contextp;
		s = 0;
	} else {
		s = contextp->s;
	}

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
		if (be == 0) {
			/*
			 * This is the case where we failed to get the backend
			 * for the last source. We exhausted all sources.
			 */
			NSS_UNLOCK(rootp);
			nss_endent_u(rootp, initf, contextpp);
			nss_delete(rootp);
			return (NSS_SUCCESS);
		}
		NSS_UNLOCK(rootp);
		contextp->n_src	= n_src;
		contextp->be	= be;
		(void) NSS_INVOKE_DBOP(be, NSS_DBOP_SETENT, 0);
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
	struct nss_getent_context *contextp;

	if ((contextp = contextpp->ctx) == 0) {
		/* nss_endent() on an unused context is a no-op */
		return;
	}
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
