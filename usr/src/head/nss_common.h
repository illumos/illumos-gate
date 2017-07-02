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
 * Copyright 2014 Garrett D'Amore <garrett@damore.org>
 *
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
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
 *	    The operating system uses a number of "databases" of information
 *	    about hosts, users (passwd/shadow), groups and so forth.  Data for
 *	    these can come from a variety of "sources":  host-names and
 *	    -addresses, for example, may be found in /etc/hosts, NIS, NIS+ or
 *	    DNS.  One or more sources may be used for each database;  the
 *	    sources and their lookup order are specified in the
 *	    /etc/nsswitch.conf file.
 *
 * The implementation of this consists of:
 *
 *    -	a "frontend" for each database, which provides a programming
 *	interface for that database [for example, the "passwd" frontend
 *	consists of getpwnam_r(), getpwuid_r(), getpwent_r(), setpwent(),
 *	endpwent(), and the old MT-unsafe routines getpwnam() and getpwuid()]
 *	and is implemented by calls to...
 *
 *    -	the common core of the switch (called the "switch" or "policy" engine);
 *	that determines what sources to use and when to invoke them.  This
 *	component works in conjunction with the name service switch (nscd).
 *	Usually nscd is the policy engine for an application lookup.
 *
 *    - Old style backend interfaces follow this pointer to function interface:
 *
 *	A "backend" exists for useful <database, source> pairs.  Each backend
 *	consists of whatever private data it needs and a set of functions
 *	that the switch engine may invoke on behalf of the frontend
 *	[e.g. the "nis" backend for "passwd" provides routines to lookup
 *	by name and by uid, as well as set/get/end iterator routines].
 *	The set of functions, and their expected arguments and results,
 *	constitutes a (database-specific) interface between a frontend and
 *	all its backends.  The switch engine knows as little as possible
 *	about these interfaces.
 *
 *	(The term "backend" is used ambiguously;  it may also refer to a
 *	particular instantiation of a backend, or to the set of all backends
 *	for a particular source, e.g. "the nis backend").
 *
 * This header file defines the interface between the switch engine and the
 * frontends and backends.  Interfaces between specific frontends and
 * backends are defined elsewhere;  many are in <nss_dbdefs.h>.
 * Most of these definitions are in the form of pointer to function
 * indicies used to call specific backend APIs.
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
 *	(2)  nss_search queries the name service cache for an existing
 *			result via a call to _nsc_search().  if the cache
 *			(nscd) has a definitive answer skip to step 7
 *	(3)  nss_search	looks up configuration info, gets "passwd: files nis",
 *	(4)  nss_search	decides to try first source ("files"),
 *	 (a) nss_search	locates code for <"passwd", "files"> backend,
 *	 (b) nss_search	creates instance of backend,
 *	 (c) nss_search	calls get-by-name routine in backend,
 *			through a function pointer interface,
 *	 (d) backend	searches /etc/passwd, doesn't find the name,
 *			returns "not found" status to nss_search,
 *	(5)  nss_search	examines status and config info, decides to try
 *			next source ("nis"),
 *	 (a) nss_search	locates code for <"passwd", "nis"> backend,
 *	 (b) nss_search	creates instance of backend,
 *	 (c) nss_search	calls get-by-name routine in backend,
 *			through a function pointer interface,
 *	 (d) backend	searches passwd.byname, finds the desired entry,
 *			fills in the result part of the getpwnam-specific
 *			struct, returns "success" status to nss_search,
 *	(6)  nss_search	examines status and config info, decides to return
 *			to caller,
 *	(7)  getpwnam_r	extracts result from getpwnam-specific struct,
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
 * Backend routines return the following status codes to the switch engine:
 *
 * SUCCESS, UNAVAIL, NOTFOUND, TRYAGAIN (these are the same codes that may
 * be specified in the config information;  see nsswitch.conf(4))
 *
 * The remaining conditions/errors are internally generated and if
 * necessary are translated, as to one of the above external errors,
 * usually NOTFOUND or UNAVAIL.
 *
 * NSS_NISSERVDNS_TRYAGAIN (should only be used by the NIS backend for
 * NIS server in DNS forwarding mode to indicate DNS server non-response).
 *
 * The policy component may return NSS_TRYLOCAL which signifies that nscd
 * is not going to process the request, and it should be performed locally.
 *
 * NSS_ERROR is a catchall for internal error conditions, errno will be set
 * to a system <errno.h> error that can help track down the problem if
 * it is persistent.  This error is the result of some internal error
 * condition and should not be seen during or exposed to aan application.
 * The error may be from the application side switch component or from the
 * nscd side switch component.
 *
 * NSS_ALTRETRY and NSS_ALTRESET are internal codes used by the application
 * side policy component and nscd to direct the policy component to
 * communicate to a per-user nscd if/when per-user authentication is enabled.
 *
 * NSS_NSCD_PRIV is a catchall for internal nscd errors or status
 * conditions.  This return code is not visible to applications.  nscd
 * may use this as a status flag and maintain additional error or status
 * information elsewhere in other private nscd data.  This status value
 * is for nscd private/internal use only.
 */

typedef enum {
	NSS_SUCCESS = 0,
	NSS_NOTFOUND = 1,
	NSS_UNAVAIL = 2,
	NSS_TRYAGAIN = 3,
	NSS_NISSERVDNS_TRYAGAIN = 4,
	NSS_TRYLOCAL = 5,
	NSS_ERROR = 6,
	NSS_ALTRETRY = 7,
	NSS_ALTRESET = 8,
	NSS_NSCD_PRIV = 9
} nss_status_t;

struct nss_backend;

typedef nss_status_t (*nss_backend_op_t)(struct nss_backend *, void *args);

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

typedef	nss_backend_t		*(*nss_backend_constr_t)(const char *db_name,
							const char *src_name,
/* Hook for (unimplemented) args in nsswitch.conf */	const char *cfg_args);

struct nss_backend_finder {
	nss_backend_constr_t	(*lookup)
		(void *lkp_priv, const char *, const char *, void **del_privp);
	void			(*delete)
		(void *del_priv, nss_backend_constr_t);
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
	const char		*name;		/* Mandatory: database name */
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

typedef void (*nss_db_initf_t)(nss_db_params_t *);

/*
 * DBD param offsets in NSS2 nscd header.
 * Offsets are relative to beginning of dbd section.
 * 32 bit offsets should be sufficient, forever.
 * 0 offset == NULL
 * flags == nss_dbp_flags
 */
typedef struct nss_dbd {
	uint32_t	o_name;
	uint32_t	o_config_name;
	uint32_t	o_default_config;
	uint32_t	flags;
} nss_dbd_t;

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

/*
 * Policy Engine Configuration
 * ---------------------------
 *
 * When nscd is running it can reconfigure it's internal policy engine
 * as well as advise an application's front-end and policy engine on how
 * respond optimally to results being returned from nscd.  This is done
 * through the policy engine configuration interface.
 */

typedef enum {
	NSS_CONFIG_GET,
	NSS_CONFIG_PUT,
	NSS_CONFIG_ADD,
	NSS_CONFIG_DELETE,
	NSS_CONFIG_LIST
} nss_config_op_t;

struct nss_config {
	char		*name;
	nss_config_op_t	cop;
	mutex_t		*lock;
	void		*buffer;
	size_t		length;
};
typedef struct nss_config nss_config_t;


extern nss_status_t nss_config(nss_config_t **, int);

extern nss_status_t nss_search(nss_db_root_t *, nss_db_initf_t,
			int search_fnum, void *search_args);
extern nss_status_t nss_getent(nss_db_root_t *, nss_db_initf_t, nss_getent_t *,
			void *getent_args);
extern void nss_setent(nss_db_root_t *, nss_db_initf_t, nss_getent_t *);
extern void nss_endent(nss_db_root_t *, nss_db_initf_t, nss_getent_t *);
extern void nss_delete(nss_db_root_t *);

extern nss_status_t nss_pack(void *, size_t, nss_db_root_t *,
			nss_db_initf_t, int, void *);
extern nss_status_t nss_pack_ent(void *, size_t, nss_db_root_t *,
			nss_db_initf_t, nss_getent_t *);
extern nss_status_t nss_unpack(void *, size_t, nss_db_root_t *,
			nss_db_initf_t, int, void *);
extern nss_status_t nss_unpack_ent(void *, size_t, nss_db_root_t *,
			nss_db_initf_t, nss_getent_t *, void *);

extern nss_status_t _nsc_search(nss_db_root_t *, nss_db_initf_t,
			int search_fnum, void *search_args);
extern nss_status_t _nsc_getent_u(nss_db_root_t *, nss_db_initf_t,
			nss_getent_t *, void *getent_args);
extern nss_status_t _nsc_setent_u(nss_db_root_t *, nss_db_initf_t,
			nss_getent_t *);
extern nss_status_t _nsc_endent_u(nss_db_root_t *, nss_db_initf_t,
			nss_getent_t *);


#ifdef	__cplusplus
}
#endif

#endif /* _NSS_COMMON_H */
