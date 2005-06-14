/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright (c) 1992-1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

/*
 *
 * NOTE:  The interfaces documented in this file may change in a minor
 *	  release.  It is intended that in the future a stronger committment
 *	  will be made to these interface definitions which will guarantee
 *	  them across minor releases.
 */

#ifndef _NSS_COMMON_H
#define	_NSS_COMMON_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <synch.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * The name-service switch
 * -----------------------
 *
 * From nsswitch.conf(4):
 *
 *	    The operating system uses a number of ``databases'' of information
 *	    about hosts, users (passwd/shadow), groups and so forth.  Data for
 *	    these can come from a variety of ``sources'':  host-names and
 *	    -addresses, for example, may be found in /etc/hosts, NIS, NIS+ or
 *	    DNS.  One or more sources may be used for each database;  the
 *	    sources and their lookup order are specified in the
 *	    /etc/nsswitch.conf file.
 *
 * The implementation of this consists of:
 *
 *    -	a ``frontend'' for each database, which provides a programming
 *	interface for that database [for example, the "passwd" frontend
 *	consists of getpwnam_r(), getpwuid_r(), getpwent_r(), setpwent(),
 *	endpwent(), and the old MT-unsafe routines getpwnam() and getpwuid()]
 *	and is implemented by calls to...
 *
 *    -	the common core of the switch (``switch engine'');  it determines
 *	which sources to use and invokes...
 *
 *    -	A ``backend'' for each useful <database, source> pair.  Each backend
 *	consists of whatever private data it needs and a set of functions
 *	that the switch engine may invoke on behalf of the frontend
 *	[e.g. the "nis" backend for "passwd" provides routines to lookup
 *	by name and by uid, as well as set/get/end iterator routines].
 *	The set of functions, and their expected arguments and results,
 *	constitutes a (database-specific) interface between a frontend and
 *	all its backends.  The switch engine knows as little as possible
 *	about these interfaces.
 *
 *	(The term ``backend'' is used ambiguously;  it may also refer to a
 *	particular instantiation of a backend, or to the set of all backends
 *	for a particular source, e.g. "the nis backend").
 *
 * This header file defines the interface between the switch engine and the
 * frontends and backends.  Interfaces between specific frontends and
 * backends are defined elsewhere;  many are in <nss_dbdefs.h>.
 *
 *
 * Switch-engine outline
 * ---------------------
 *
 * Frontends may call the following routines in the switch engine:
 *
 *	nss_search() does getXXXbyYYY,	e.g. getpwnam_r(), getpwuid_r()
 *	nss_getent() does getXXXent,	e.g. getpwent_r()
 *	nss_setent() does setXXXent,	e.g. setpwent()
 *	nss_endent() does endXXXent,	e.g. endpwent()
 *	nss_delete() releases resources, in the style of endpwent().
 *
 * A getpwnam_r() call might proceed thus (with many details omitted):
 *
 *	(1)  getpwnam_r	fills in (getpwnam-specific) argument/result struct,
 *			calls nss_search(),
 *	(2)  nss_search	looks up configuration info, gets "passwd: files nis",
 *	(3)  nss_search	decides to try first source ("files"),
 *	 (a) nss_search	locates code for <"passwd", "files"> backend,
 *	 (b) nss_search	creates instance of backend,
 *	 (c) nss_search	calls get-by-name routine in backend,
 *	 (d) backend	searches /etc/passwd, doesn't find the name,
 *			returns "not found" status to nss_search,
 *	(4)  nss_search	examines status and config info, decides to try
 *			next source ("nis"),
 *	 (a) nss_search	locates code for <"passwd", "nis"> backend,
 *	 (b) nss_search	creates instance of backend,
 *	 (c) nss_search	calls get-by-name routine in backend,
 *	 (d) backend	searches passwd.byname, finds the desired entry,
 *			fills in the result part of the getpwnam-specific
 *			struct, returns "success" status to nss_search,
 *	(5)  nss_search	examines status and config info, decides to return
 *			to caller,
 *	(6)  getpwnam_r	extracts result from getpwnam-specific struct,
 *			returns to caller.
 *
 *
 * Data structures
 * ---------------
 *
 * Both databases and sources are represented by case-sensitive strings
 * (the same strings that appear in the configuration file).
 *
 * The switch engine maintains a per-frontend data structure so that the
 * results of steps (2), (a) and (b) can be cached.  The frontend holds a
 * handle (nss_db_root_t) to this structure and passes it in to the
 * nss_*() routines.
 *
 * The nss_setent(), nss_getent() and nss_endent() routines introduce another
 * variety of state (the current position in the enumeration process).
 * Within a single source, this information is maintained by private data
 * in the backend instance -- but, in the presence of multiple sources, the
 * switch engine must keep track of the current backend instance [e.g either
 * <"passwd", "files"> or <"passwd", "nis"> instances].  The switch engine
 * has a separate per-enumeration data structure for this;  again, the
 * frontend holds a handle (nss_getent_t) and passes it in, along with the
 * nss_db_root_t handle, to nss_setent(), nss_getent() and nss_endent().
 *
 *
 * Multithreading
 * --------------
 *
 * The switch engine takes care of locking;  frontends should be written to
 * be reentrant, and a backend instance may assume that all calls to it are
 * serialized.
 *
 * If multiple threads simultaneously want to use a particular backend, the
 * switch engine creates multiple backend instances (up to some limit
 * specified by the frontend).  Backends must of course lock any state that
 * is shared between instances, and must serialize calls to any MT-unsafe
 * code.
 *
 * The switch engine has no notion of per-thread state.
 *
 * Frontends can use the nss_getent_t handle to define the scope of the
 * enumeration (set/get/endXXXent) state:  a static handle gives global state
 * (which is what Posix has specified for the getXXXent_r routines), handles
 * in Thread-Specific Data give per-thread state, and handles on the stack
 * give per-invocation state.
 */


/*
 * Backend instances
 * -----------------
 *
 * As far as the switch engine is concerned, an instance of a backend is a
 * struct whose first two members are:
 *    -	A pointer to a vector of function pointers, one for each
 *	database-specific function,
 *    -	The length of the vector (an int), used for bounds-checking.
 * There are four well-known function slots in the vector:
 *	[0] is a destructor for the backend instance,
 *	[1] is the endXXXent routine,
 *	[2] is the setXXXent routine,
 *	[3] is the getXXXent routine.
 * Any other slots are database-specific getXXXbyYYY routines;  the frontend
 * specifies a slot-number to nss_search().
 *
 * The functions take two arguments:
 *    -	a pointer to the backend instance (like a C++ "this" pointer)
 *    -	a single (void *) pointer to the database-specific argument/result
 *	structure (the contents are opaque to the switch engine).
 * The four well-known functions ignore the (void *) pointer.
 *
 * Backend routines return one of five status codes to the switch engine:
 * SUCCESS, UNAVAIL, NOTFOUND, TRYAGAIN (these are the same codes that may
 * be specified in the config information;  see nsswitch.conf(4)), or
 * NSS_NISSERVDNS_TRYAGAIN (should only be used by the NIS backend for
 * NIS server in DNS forwarding mode to indicate DNS server non-response).
 */

typedef enum {
	NSS_SUCCESS,
	NSS_NOTFOUND,
	NSS_UNAVAIL,
	NSS_TRYAGAIN,
	NSS_NISSERVDNS_TRYAGAIN
} nss_status_t;

struct nss_backend;

#if defined(__STDC__)
typedef nss_status_t (*nss_backend_op_t)(struct nss_backend *, void *args);
#else
typedef nss_status_t (*nss_backend_op_t)();
#endif

struct nss_backend {
	nss_backend_op_t	*ops;
	int			n_ops;
};
typedef struct nss_backend	nss_backend_t;
typedef int			nss_dbop_t;

#define	NSS_DBOP_DESTRUCTOR	0
#define	NSS_DBOP_ENDENT		1
#define	NSS_DBOP_SETENT		2
#define	NSS_DBOP_GETENT		3
#define	NSS_DBOP_next_iter	(NSS_DBOP_GETENT + 1)
#define	NSS_DBOP_next_noiter	(NSS_DBOP_DESTRUCTOR + 1)
#define	NSS_DBOP_next_ipv6_iter	(NSS_DBOP_GETENT + 3)

#define	NSS_LOOKUP_DBOP(instp, n)					    \
		(((n) >= 0 && (n) < (instp)->n_ops) ? (instp)->ops[n] : 0)

#define	NSS_INVOKE_DBOP(instp, n, argp)					    (\
		((n) >= 0 && (n) < (instp)->n_ops && (instp)->ops[n] != 0) \
		? (*(instp)->ops[n])(instp, argp)			    \
		: NSS_UNAVAIL)

/*
 * Locating and instantiating backends
 * -----------------------------------
 *
 * To perform step (a), the switch consults a list of backend-finder routines,
 * passing a <database, source> pair.
 *
 * There is a standard backend-finder;  frontends may augment or replace this
 * in order to, say, indicate that some backends are "compiled in" with the
 * frontend.
 *
 * Backend-finders return a pointer to a constructor function for the backend.
 * (or NULL if they can't find the backend).  The switch engine caches these
 * function pointers;  when it needs to perform step (b), it calls the
 * constructor function, which returns a pointer to a new instance of the
 * backend, properly initialized (or returns NULL).
 */

#if defined(__STDC__)
typedef	nss_backend_t * 	(*nss_backend_constr_t)(const char *db_name,
							const char *src_name,
/* Hook for (unimplemented) args in nsswitch.conf */	const char *cfg_args);
#else
typedef	nss_backend_t * 	(*nss_backend_constr_t)();
#endif

struct nss_backend_finder {
#if defined(__STDC__)
	nss_backend_constr_t	(*lookup)
		(void *lkp_priv, const char *, const char *, void **del_privp);
	void			(*delete)
		(void *del_priv, nss_backend_constr_t);
#else
	nss_backend_constr_t	(*lookup)();
	void			(*delete)();
#endif
	struct nss_backend_finder *next;
	void			*lookup_priv;
};

typedef struct nss_backend_finder nss_backend_finder_t;

extern nss_backend_finder_t	*nss_default_finders;

/*
 * Frontend parameters
 * -------------------
 *
 * The frontend must tell the switch engine:
 *    -	the database name,
 *    -	the compiled-in default configuration entry.
 * It may also override default values for:
 *    -	the database name to use when looking up the configuration
 *	information (e.g. "shadow" uses the config entry for "passwd"),
 *    -	a limit on the number of instances of each backend that are
 *	simultaneously active,
 *    - a limit on the number of instances of each backend that are
 *	simultaneously dormant (waiting for new requests),
 *    -	a flag that tells the switch engine to use the default configuration
 *	entry and ignore any other config entry for this database,
 *    -	backend-finders (see above)
 *    - a cleanup routine that should be called when these parameters are
 *	about to be deleted.
 *
 * In order to do this, the frontend includes a pointer to an initialization
 * function (nss_db_initf_t) in every nss_*() call.  When necessary (normally
 * just on the first invocation), the switch engine allocates a parameter
 * structure (nss_db_params_t), fills in the default values, then calls
 * the initialization function, which should update the parameter structure
 * as necessary.
 *
 * (This might look more natural if we put nss_db_initf_t in nss_db_root_t,
 * or abolished nss_db_initf_t and put nss_db_params_t in nss_db_root_t.
 * It's done the way it is for shared-library efficiency, namely:
 *	- keep the unshared data (nss_db_root_t) to a minimum,
 *	- keep the symbol lookups and relocations to a minimum.
 * In particular this means that non-null pointers, e.g. strings and
 * function pointers, in global data are a bad thing).
 */

enum nss_dbp_flags {
	NSS_USE_DEFAULT_CONFIG	= 0x1
};

struct nss_db_params {
	const char 		*name;		/* Mandatory: database name */
	const char		*config_name;	/* config-file database name */
	const char		*default_config; /* Mandatory: default config */
	unsigned		max_active_per_src;
	unsigned		max_dormant_per_src;
	enum nss_dbp_flags	flags;
	nss_backend_finder_t	*finders;
	void			*private;	/* Not used by switch */
	void			(*cleanup)(struct nss_db_params *);
};

typedef struct nss_db_params nss_db_params_t;

#if defined(__STDC__)
typedef void (*nss_db_initf_t)(nss_db_params_t *);
#else
typedef void (*nss_db_initf_t)();
#endif

/*
 * These structures are defined inside the implementation of the switch
 * engine;  the interface just holds pointers to them.
 */
struct nss_db_state;
struct nss_getent_context;

/*
 * Finally, the two handles that frontends hold:
 */

struct nss_db_root {
	struct nss_db_state	*s;
	mutex_t			lock;
};
typedef struct nss_db_root nss_db_root_t;
#define	NSS_DB_ROOT_INIT		{ 0, DEFAULTMUTEX }
#define	DEFINE_NSS_DB_ROOT(name)	nss_db_root_t name = NSS_DB_ROOT_INIT


typedef struct {
	struct nss_getent_context *ctx;
	mutex_t			lock;
} nss_getent_t;

#define	NSS_GETENT_INIT			{ 0, DEFAULTMUTEX }
#define	DEFINE_NSS_GETENT(name)		nss_getent_t name = NSS_GETENT_INIT

#if defined(__STDC__)
extern nss_status_t nss_search(nss_db_root_t *, nss_db_initf_t,
			int search_fnum, void *search_args);
extern nss_status_t nss_getent(nss_db_root_t *, nss_db_initf_t, nss_getent_t *,
			void *getent_args);
extern void nss_setent(nss_db_root_t *, nss_db_initf_t, nss_getent_t *);

extern void nss_endent(nss_db_root_t *, nss_db_initf_t, nss_getent_t *);
					/* ^^ superfluous but consistent */
extern void nss_delete(nss_db_root_t *);
#else
extern nss_status_t nss_search();
extern nss_status_t nss_getent();
extern void nss_setent();
extern void nss_endent();
extern void nss_delete();
#endif

#ifdef	__cplusplus
}
#endif

#endif /* _NSS_COMMON_H */
