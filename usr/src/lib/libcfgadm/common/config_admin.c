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

/* Portions Copyright 2005 Cyril Plisko */

/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <locale.h>
#include <langinfo.h>
#include <time.h>

#if	!defined(DEBUG)
#define	NDEBUG	1
#else
#undef	NDEBUG
#endif

#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <dlfcn.h>
#include <synch.h>
#include <sys/systeminfo.h>
#include <sys/sunddi.h>
#include <libdevinfo.h>
#include <unistd.h>
#include <stdarg.h>
#include <limits.h>
#include <ftw.h>
#include <ctype.h>

#define	CFGA_PLUGIN_LIB
#include <config_admin.h>

/* Limit size of sysinfo return */
#define	SYSINFO_LENGTH	256

/*
 * Attachment point specifier types.
 */
typedef enum {
	UNKNOWN_AP,
	LOGICAL_LINK_AP,
	LOGICAL_DRV_AP,
	PHYSICAL_AP,
	AP_TYPE
} cfga_ap_types_t;

static char *listopt_array[] = {

#define	LISTOPT_CLASS	0
	"class",
	NULL
};

typedef struct {
	int v_min;	/* Min acceptable version */
	int v_max;	/* Max acceptable version */
} vers_req_t;

#define	INVALID_VERSION		-1
#define	VALID_HSL_VERS(v)	(((v) >= CFGA_HSL_V1) && \
				((v) <= CFGA_HSL_VERS))

/*
 * Incomplete definition
 */
struct cfga_vers_ops;

/*
 * Structure that contains plugin library information.
 */
typedef struct plugin_lib {
	struct	plugin_lib *next;	/* pointer to next */
	mutex_t	lock;			/* protects refcnt */
	int	refcnt;			/* reference count */
	void	*handle;		/* handle from dlopen */
	cfga_err_t	(*cfga_change_state_p)();
	cfga_err_t	(*cfga_private_func_p)();
	cfga_err_t	(*cfga_test_p)();
	cfga_err_t	(*cfga_stat_p)();
	cfga_err_t	(*cfga_list_p)();
	cfga_err_t	(*cfga_help_p)();
	int		(*cfga_ap_id_cmp_p)();
	cfga_err_t	(*cfga_list_ext_p)();	/* For V2 plug-ins only */

	int		plugin_vers;	/* actual plugin version */
	struct cfga_vers_ops *vers_ops;	/* version dependant routines */
	char	libpath[MAXPATHLEN];	/* full pathname to lib */
} plugin_lib_t;

static plugin_lib_t plugin_list;

typedef struct lib_cache {
	struct lib_cache *lc_next;
	plugin_lib_t *lc_libp;
	char *lc_ap_id;
	char *lc_ap_physical;	/* physical ap_id */
	char *lc_ap_logical;	/* logical ap_id */
} lib_cache_t;

static lib_cache_t *lib_cache;
static mutex_t lib_cache_lock;

/*
 * Library locator data struct - used to pass down through the device
 * tree walking code.
 */
typedef struct lib_locator {
	char	ap_base[MAXPATHLEN];
	char	ap_logical[CFGA_LOG_EXT_LEN];
	char	ap_physical[CFGA_PHYS_EXT_LEN];
	char	ap_class[CFGA_CLASS_LEN];
	char	pathname[MAXPATHLEN];
	plugin_lib_t *libp;
	cfga_err_t status;
	vers_req_t vers_req;	/* plug-in version required */
} lib_loc_t;

/*
 * linked list of cfga_stat_data structs - used for
 * config_list
 */
typedef struct stat_data_list {
	struct stat_data_list	*next;
	cfga_stat_data_t	stat_data;
} stat_data_list_t;

/*
 * linked list of arrays. Each array represents a bunch
 * of list_data_t structures returned by a single call
 * to a plugin's cfga_list_ext() routine.
 */
typedef struct array_list {
	struct array_list	*next;
	cfga_list_data_t	*array;
	int			nelem;
} array_list_t;

/*
 * encapsulate config_list args to get them through the tree
 * walking code
 */
typedef struct list_stat {
	const char *opts;	/* Hardware specific options */
	char **errstr;
	cfga_flags_t flags;
	int	*countp;	/* Total number of list and stat structures */
	stat_data_list_t *sdl;	/* Linked list of stat structures */
	array_list_t *al;	/* Linked list of arrays of list structures */
	vers_req_t use_vers;	/* plugin versions to be stat'ed */
	char *shp_errstr;	/* only for shp plugin */
} list_stat_t;

/*
 * Internal operations for libcfgadm which are version dependant
 */
struct cfga_vers_ops {
	cfga_err_t (*resolve_lib)(plugin_lib_t *libp);
	cfga_err_t (*stat_plugin)(list_stat_t *, lib_loc_t *, char **errstring);
	cfga_err_t (*mklog)(di_node_t, di_minor_t, plugin_lib_t *,
	    lib_loc_t *liblocp);
	cfga_err_t (*get_cond)(lib_loc_t *, cfga_cond_t *, char **);
};


/*
 * Lock to protect list of libraries
 */
static mutex_t plugin_list_lock;

/*
 * Forward declarations
 */

static const char *__config_strerror(cfga_err_t);
static void *config_calloc_check(size_t, size_t, char **);
static cfga_err_t resolve_lib_ref(plugin_lib_t *, lib_loc_t *);
static cfga_err_t config_get_lib(const char *, lib_loc_t *, char **);
static int check_ap(di_node_t, di_minor_t, void *);
static int check_ap_hp(di_node_t, di_hp_t, void *);
static int check_ap_impl(di_node_t, di_minor_t, di_hp_t, void *);
static int check_ap_phys(di_node_t, di_minor_t, void *);
static int check_ap_phys_hp(di_node_t, di_hp_t, void *);
static int check_ap_phys_impl(di_node_t, di_minor_t, di_hp_t, void *);

static cfga_err_t find_ap_common(lib_loc_t *libloc_p, const char *rootpath,
    int (*fcn)(di_node_t node, di_minor_t minor, void *arg),
    int (*fcn_hp)(di_node_t node, di_hp_t hp, void *arg),
    char **errstring);

static plugin_lib_t *lib_in_list(char *);
static cfga_err_t find_lib(di_node_t, di_minor_t, lib_loc_t *);
static cfga_err_t find_lib_hp(di_node_t, di_hp_t, lib_loc_t *);
static cfga_err_t find_lib_impl(char *, lib_loc_t *);
static cfga_err_t load_lib(di_node_t, di_minor_t, lib_loc_t *);
static cfga_err_t load_lib_hp(di_node_t, di_hp_t, lib_loc_t *);
static cfga_err_t load_lib_impl(di_node_t, di_minor_t, di_hp_t, lib_loc_t *);
extern void bcopy(const void *, void *, size_t);
static void config_err(int, int, char **);
static void hold_lib(plugin_lib_t *);
static void rele_lib(plugin_lib_t *);

static cfga_err_t parse_listopt(char *listopts, char **classpp,
    char **errstring);

static cfga_err_t list_common(list_stat_t *lstatp, const char *class);
static int do_list_common(di_node_t node, di_minor_t minor, void *arg);
static int do_list_common_hp(di_node_t node, di_hp_t hp, void *arg);
static int do_list_common_impl(di_node_t node, di_minor_t minor,
    di_hp_t hp, void *arg);
static cfga_err_t stat_common(int num_ap_ids, char *const *ap_ids,
    const char *class, list_stat_t *lstatp);

static cfga_err_t null_resolve(plugin_lib_t *libp);
static cfga_err_t resolve_v1(plugin_lib_t *libp);
static cfga_err_t resolve_v2(plugin_lib_t *libp);

static cfga_err_t mklog_common(di_node_t node, di_minor_t minor,
    lib_loc_t *liblocp, size_t len);

static cfga_err_t null_mklog(di_node_t node, di_minor_t minor,
    plugin_lib_t *libp, lib_loc_t *liblocp);
static cfga_err_t mklog_v1(di_node_t node, di_minor_t minor,
    plugin_lib_t *libp, lib_loc_t *liblocp);
static cfga_err_t mklog_v2(di_node_t node, di_minor_t minor,
    plugin_lib_t *libp, lib_loc_t *liblocp);

static cfga_err_t null_stat_plugin(list_stat_t *lstatp, lib_loc_t *libloc_p,
    char **errstring);
static cfga_err_t stat_plugin_v2(list_stat_t *lstat, lib_loc_t *libloc_p,
    char **errstring);
static cfga_err_t stat_plugin_v1(list_stat_t *lstat, lib_loc_t *libloc_p,
    char **errstring);

static cfga_err_t null_get_cond(lib_loc_t *liblocp, cfga_cond_t *condp,
    char **errstring);
static cfga_err_t get_cond_v1(lib_loc_t *liblocp, cfga_cond_t *condp,
    char **errstring);
static cfga_err_t get_cond_v2(lib_loc_t *liblocp, cfga_cond_t *condp,
    char **errstring);

static cfga_err_t realloc_data(cfga_stat_data_t **ap_id_list,
    int *nlistp, list_stat_t *lstatp);
static cfga_err_t realloc_data_ext(cfga_list_data_t **ap_id_list,
    int *nlistp, list_stat_t *lstatp);

static void stat_to_list(cfga_list_data_t *lp, cfga_stat_data_t *statp);
static void lstat_free(list_stat_t *lstatp);
static cfga_ap_types_t find_arg_type(const char *ap_id);
static int compat_plugin(vers_req_t *reqp, int plugin_vers);

static cfga_err_t check_flags(cfga_flags_t flags, cfga_flags_t mask,
    char **errstring);
static cfga_err_t check_apids(int num_ap_ids, char *const *ap_ids,
    char **errstring);

static char *get_class(di_minor_t minor);
static cfga_err_t split_apid(char *ap_id, char **dyncompp, char **errstring);
static void append_dyn(char *buf, const char *dyncomp, size_t blen);
static int default_ap_id_cmp(const char *ap_id1, const char *ap_id2);
static void destroy_cache();

/*
 * Plugin library search path helpers
 */
#define	LIB_PATH_BASE1	"/usr/platform/"
#define	LIB_PATH_BASE2	"/usr"
#if defined(__sparcv9)
#define	LIB_PATH_MIDDLE	"/lib/cfgadm/sparcv9/"
#elif defined(__amd64)
#define	LIB_PATH_MIDDLE "/lib/cfgadm/amd64/"
#else
#define	LIB_PATH_MIDDLE	"/lib/cfgadm/"
#endif
#define	LIB_PATH_TAIL	".so.1"


#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN	"SYS_TEST"
#endif

/*
 * Defined constants
 */
#define	DEVICES_DIR		"/devices"
#define	DOT_DOT_DEVICES		"../devices"
#define	CFGA_DEV_DIR		"/dev/cfg"
#define	SLASH			"/"
#define	S_FREE(x)	(((x) != NULL) ? (free(x), (x) = NULL) : (void *)0)
#define	GET_DYN(a)	(strstr((a), CFGA_DYN_SEP))

#define	CFGA_NO_CLASS		"none"

/*
 * Error strings
 */
#define	DI_INIT_FAILED	1
#define	ALLOC_FAILED	2
#define	INVALID_ARGS	3

static char *
err_strings[] = {
	NULL,
	"Device library initialize failed",
	"Memory allocation failed",
	"Invalid argument(s)"
};

static const char err_sep[] = ": ";


/*
 * Table of version dependant routines
 */
static struct cfga_vers_ops cfga_vers_ops[CFGA_HSL_VERS + 1] = {

{null_resolve,	null_stat_plugin,	null_mklog,	null_get_cond	},
{resolve_v1,	stat_plugin_v1,		mklog_v1,	get_cond_v1	},
{resolve_v2,	stat_plugin_v2,		mklog_v2,	get_cond_v2	}

};
#define	VERS_ARRAY_SZ	(sizeof (cfga_vers_ops)/sizeof (cfga_vers_ops[0]))


/*
 * Public interfaces for libcfgadm, as documented in config_admin.3x
 */

/*
 * config_change_state
 */

cfga_err_t
config_change_state(
	cfga_cmd_t state_change_cmd,
	int num_ap_ids,
	char *const *ap_id,
	const char *options,
	struct cfga_confirm *confp,
	struct cfga_msg *msgp,
	char **errstring,
	cfga_flags_t flags)
{
	/*
	 * for each arg -
	 *  load hs library,
	 *  if force
	 *    call cfga_state_change_func
	 *    return status
	 *  else
	 *    call it's cfga_stat
	 *    check condition
	 *    call cfga_state_change_func
	 *    return status
	 */
	int i;
	lib_loc_t libloc;
	plugin_lib_t *libp;
	cfga_cond_t cond;

	cfga_err_t retval = CFGA_OK;

	/* Sanity checks */
	if (state_change_cmd == CFGA_CMD_NONE)
		return (retval);

	if ((state_change_cmd < CFGA_CMD_NONE) ||
	    (state_change_cmd > CFGA_CMD_UNCONFIGURE))
		return (CFGA_INVAL);

	if (errstring != NULL) {
		*errstring = NULL;
	}

	if (check_flags(flags, CFGA_FLAG_FORCE | CFGA_FLAG_VERBOSE, errstring)
	    != CFGA_OK) {
		return (CFGA_ERROR);
	}

	if (check_apids(num_ap_ids, ap_id, errstring) != CFGA_OK) {
		return (CFGA_ERROR);
	}

	/*
	 * operate on each ap_id
	 */
	for (i = 0; (i < num_ap_ids) && (retval == CFGA_OK); i++) {
		libloc.libp = NULL;
		if ((retval = config_get_lib(ap_id[i], &libloc, errstring)) !=
		    CFGA_OK) {
			break;
		}

		libp = libloc.libp;
		if ((flags & CFGA_FLAG_FORCE) ||
		    (state_change_cmd == CFGA_CMD_UNLOAD) ||
		    (state_change_cmd == CFGA_CMD_DISCONNECT) ||
		    (state_change_cmd == CFGA_CMD_UNCONFIGURE)) {
			errno = 0;
			retval = (*libp->cfga_change_state_p)
			    (state_change_cmd, libloc.ap_physical, options,
			    confp, msgp, errstring, flags);
		} else {
			/*
			 * Need to check condition before proceeding in
			 * the "configure direction"
			 */
			if ((retval = libp->vers_ops->get_cond(&libloc, &cond,
			    errstring)) != CFGA_OK) {
				break;
			}

			if (cond == CFGA_COND_OK || cond == CFGA_COND_UNKNOWN) {
				errno = 0;
				retval =
				    (*libp->cfga_change_state_p)(
				    state_change_cmd,
				    libloc.ap_physical, options,
				    confp, msgp, errstring,
				    flags);
			} else {
				retval = CFGA_INSUFFICENT_CONDITION;
			}
		}
		rele_lib(libp);
	}

	return (retval);
}

/*
 * config_private_func
 */

cfga_err_t
config_private_func(
	const char *function,
	int num_ap_ids,
	char *const *ap_ids,
	const char *options,
	struct cfga_confirm *confp,
	struct cfga_msg *msgp,
	char **errstring,
	cfga_flags_t flags)
{
	int i;
	lib_loc_t libloc;
	cfga_err_t retval = CFGA_OK;


	if (errstring != NULL) {
		*errstring = NULL;
	}

	if (check_flags(flags, CFGA_FLAG_FORCE | CFGA_FLAG_VERBOSE, errstring)
	    != CFGA_OK) {
		return (CFGA_ERROR);
	}

	if (check_apids(num_ap_ids, ap_ids, errstring) != CFGA_OK) {
		return (CFGA_ERROR);
	}

	/*
	 * operate on each ap_id
	 */
	for (i = 0; (i < num_ap_ids) && (retval == CFGA_OK); i++) {
		libloc.libp = NULL;
		if ((retval = config_get_lib(ap_ids[i], &libloc, errstring)) !=
		    CFGA_OK)  {
			return (retval);
		}

		errno = 0;
		retval = (*libloc.libp->cfga_private_func_p)(function,
		    libloc.ap_physical, options, confp, msgp, errstring,
		    flags);
		rele_lib(libloc.libp);
	}

	return (retval);
}


/*
 * config_test
 */

cfga_err_t
config_test(
	int num_ap_ids,
	char *const *ap_ids,
	const char *options,
	struct cfga_msg *msgp,
	char **errstring,
	cfga_flags_t flags)
{
	int i;
	lib_loc_t libloc;
	cfga_err_t retval = CFGA_OK;

	if (errstring != NULL) {
		*errstring = NULL;
	}

	if (check_flags(flags, CFGA_FLAG_FORCE | CFGA_FLAG_VERBOSE, errstring)
	    != CFGA_OK) {
		return (CFGA_ERROR);
	}

	if (check_apids(num_ap_ids, ap_ids, errstring) != CFGA_OK) {
		return (CFGA_ERROR);
	}

	/*
	 * operate on each ap_id
	 */
	for (i = 0; (i < num_ap_ids) && (retval == CFGA_OK); i++) {
		libloc.libp = NULL;
		if ((retval = config_get_lib(ap_ids[i], &libloc, errstring)) !=
		    CFGA_OK) {
			return (retval);
		}

		errno = 0;
		retval = (*libloc.libp->cfga_test_p)(libloc.ap_physical,
		    options, msgp, errstring, flags);
		rele_lib(libloc.libp);
	}

	return (retval);
}

cfga_err_t
config_stat(
	int num_ap_ids,
	char *const *ap_ids,
	struct cfga_stat_data *buf,
	const char *options,
	char **errstring)
{
	int nstat, n, i;
	list_stat_t lstat = {NULL};
	cfga_err_t rc = CFGA_OK;

	if (check_apids(num_ap_ids, ap_ids, errstring) != CFGA_OK) {
		return (CFGA_ERROR);
	}

	/*
	 * V1 entry points don't support dynamic attachment points
	 */
	for (i = 0; i < num_ap_ids; i++) {
		if (GET_DYN(ap_ids[i]) != NULL) {
			return (CFGA_APID_NOEXIST);
		}
	}


	nstat = n = 0;
	lstat.countp = &nstat;
	lstat.opts = options;
	lstat.errstr = errstring;
	lstat.shp_errstr = NULL;
	/*
	 * This is a V1 interface which can use only V1 plugins
	 */
	lstat.use_vers.v_max = lstat.use_vers.v_min = CFGA_HSL_V1;

	rc = stat_common(num_ap_ids, ap_ids, NULL, &lstat);
	if (rc == CFGA_OK) {
		assert(*lstat.countp == num_ap_ids);
		rc = realloc_data(&buf, &n, &lstat);
	}

	return (rc);
}

/*
 * config_list
 */
cfga_err_t
config_list(
	struct cfga_stat_data **ap_id_list,
	int *nlistp,
	const char *options,
	char **errstring)
{
	int nstat;
	list_stat_t lstat = {NULL};
	cfga_err_t retval = CFGA_ERROR;

	if (errstring != NULL) {
		*errstring = NULL;
	}

	nstat = 0;
	lstat.countp = &nstat;
	lstat.opts = options;
	lstat.errstr = errstring;
	lstat.shp_errstr = NULL;
	/*
	 * This is a V1 interface which can use only V1 plugins
	 */
	lstat.use_vers.v_max = lstat.use_vers.v_min = CFGA_HSL_V1;


	*ap_id_list = NULL;
	*nlistp = 0;

	/*
	 * V1 interfaces don't support prefiltering, no class
	 * specified.
	 */
	retval = list_common(&lstat, NULL);
	if (retval == CFGA_OK) {
		retval = realloc_data(ap_id_list, nlistp, &lstat);
	}

	assert((ap_id_list != NULL && *nlistp != 0) ||
	    (ap_id_list == NULL && *nlistp == 0));

	if (retval == CFGA_OK && *nlistp == 0) {
		return (CFGA_NOTSUPP);
	} else {
		return (retval);
	}
}


/*
 * config_list_ext
 */
cfga_err_t
config_list_ext(
	int num_ap_ids,
	char *const *ap_ids,
	struct cfga_list_data **ap_id_list,
	int *nlistp,
	const char *options,
	const char *listopts,
	char **errstring,
	cfga_flags_t flags)
{
	int nstat, list, prefilter;
	list_stat_t lstat = {NULL};
	char *class;

	cfga_err_t rc = CFGA_ERROR;

	*nlistp = 0;
	*ap_id_list = NULL;

	if (errstring != NULL) {
		*errstring = NULL;
	}

	if (check_flags(flags, CFGA_FLAG_LIST_ALL, errstring) != CFGA_OK) {
		return (CFGA_ERROR);
	}

	class = NULL;
	if ((rc = parse_listopt((char *)listopts, &class, errstring))
	    != CFGA_OK) {
		return (rc);
	}

	prefilter = (class == NULL) ? 0 : 1;

	nstat = 0;
	lstat.countp = &nstat;
	lstat.opts = options;
	lstat.errstr = errstring;
	lstat.shp_errstr = NULL;
	lstat.flags = flags;
	/*
	 * We support both V1 and V2 plugins through this entry
	 * point.
	 */
	lstat.use_vers.v_min = CFGA_HSL_V1;
	lstat.use_vers.v_max = CFGA_HSL_V2;

	list = 0;
	if (num_ap_ids == 0 && ap_ids == NULL) {
		/*
		 * discover and stat all attachment points
		 */
		list = 1;
		rc = list_common(&lstat, class);
	} else if (num_ap_ids > 0 && ap_ids != NULL) {
		/*
		 * Stat specified attachment points. With dynamic expansion
		 * more data may be returned than was specified by user.
		 */
		rc = stat_common(num_ap_ids, ap_ids, class, &lstat);
	} else {
		rc = CFGA_ERROR;
	}

	S_FREE(class);

	if (rc != CFGA_OK) {
		return (rc);
	}

	rc = realloc_data_ext(ap_id_list, nlistp, &lstat);

	assert((ap_id_list != NULL && *nlistp != 0) ||
	    (ap_id_list == NULL && *nlistp == 0));

	/*
	 * For the list command notify user if no attachment
	 * point is found in the system.
	 *
	 */
	if (list && rc == CFGA_OK && *nlistp == 0) {
		/*
		 * If attachment points are being prefiltered, absence of data
		 * does not imply that config. admin. is not
		 * supported by the system.
		 */
		if (prefilter) {
			/*
			 * Prefiltering: requested class is absent
			 */
			return (CFGA_APID_NOEXIST);
		} else {
			/*
			 * No attachment points in system
			 */
			return (CFGA_NOTSUPP);
		}
	} else {
		return (rc);
	}
}


/*
 * config_unload_libs
 *
 * Attempts to remove all libs on the plugin list.
 */
void
config_unload_libs()
{
	plugin_lib_t *libp, *prev = &plugin_list, *next = NULL;

	/* destroy cache entries to remove refcnt agains plugins */
	destroy_cache();

	(void) mutex_lock(&plugin_list_lock);
	for (libp = plugin_list.next; libp != NULL; libp = next) {
		next = libp->next;
		(void) mutex_lock(&libp->lock);
		if (libp->refcnt) {
			(void) mutex_unlock(&libp->lock);
			prev = libp;
			continue;
		}
		(void) mutex_unlock(&libp->lock);
		prev->next = next;
		(void) dlclose(libp->handle);
		(void) mutex_destroy(&libp->lock);
		free(libp);
	}
	(void) mutex_unlock(&plugin_list_lock);
}

/*
 * config_ap_id_cmp
 */
int
config_ap_id_cmp(
	const cfga_ap_log_id_t ap1,
	const cfga_ap_log_id_t ap2)
{
	int ret;
	lib_loc_t libloc;
	char apstat1[CFGA_PHYS_EXT_LEN];
	char apstat2[CFGA_PHYS_EXT_LEN];
	char *sep1, *sep2;

	/*
	 * Extract static ap_ids
	 */
	(void) strlcpy(apstat1, ap1, sizeof (apstat1));
	(void) strlcpy(apstat2, ap2, sizeof (apstat2));

	sep1 = GET_DYN(apstat1);
	sep2 = GET_DYN(apstat2);

	if (sep1)
		*sep1 = '\0';
	if (sep2)
		*sep2 = '\0';

	/*
	 * Use the default comparator for static ap_ids
	 */
	ret = default_ap_id_cmp(apstat1, apstat2);
	if (ret)
		return (ret);

	/*
	 * static components match. They belong to
	 * the same static ap_id. Check if both are dynamic
	 * If not, static < dynamic.
	 */
	if ((sep1 == NULL) ^ (sep2 == NULL))
		return (sep1 ? 1 : -1);

	/*
	 * If both are static, then ap1 = ap2
	 */
	if (sep1 == NULL)
		return (0);

	/*
	 * Both are dynamic and belong to same static ap_id.
	 * Use the plugin comparator
	 */
	libloc.libp = NULL;
	if (config_get_lib(ap1, &libloc, NULL) != CFGA_OK) {
		return (strncmp(sep1, sep2, CFGA_PHYS_EXT_LEN));
	}

	ret = (*libloc.libp->cfga_ap_id_cmp_p)(ap1, ap2);

	rele_lib(libloc.libp);

	return (ret);
}

/*
 * config_strerror
 */

const char *
config_strerror(cfga_err_t cfgerrnum)
{
	const char *ep = NULL;

	if ((cfgerrnum < CFGA_OK) || (cfgerrnum > CFGA_ATTR_INVAL))
		return (NULL);

	ep = __config_strerror(cfgerrnum);

	return ((ep != NULL) ? dgettext(TEXT_DOMAIN, ep) : NULL);
}

/*
 * config_help
 */
cfga_err_t
config_help(
	int num_ap_ids,
	char *const *ap_ids,
	struct cfga_msg *msgp,
	const char *options,
	cfga_flags_t flags)
{
	int i;
	lib_loc_t libloc;
	cfga_err_t retval = CFGA_OK;

	if (check_flags(flags, CFGA_FLAG_FORCE | CFGA_FLAG_VERBOSE, NULL)
	    != CFGA_OK) {
		return (CFGA_ERROR);
	}

	if (num_ap_ids < 0) {
		return (CFGA_ERROR);
	}

	if (num_ap_ids > 0 && ap_ids == NULL) {
		return (CFGA_ERROR);
	}

	/*
	 * operate on each ap_id
	 */
	for (i = 0; (i < num_ap_ids) && (retval == CFGA_OK); i++) {
		libloc.libp = NULL;
		if ((retval = config_get_lib(ap_ids[i], &libloc,
		    NULL)) != CFGA_OK) {
			return (retval);
		}

		errno = 0;
		retval = (*libloc.libp->cfga_help_p)(msgp, options, flags);
		rele_lib(libloc.libp);
	}
	return (retval);
}

/*
 * Private support routines for the public interfaces
 */

static const char *
__config_strerror(cfga_err_t cfgerrnum)
{
	const char *ep = NULL;

	switch (cfgerrnum) {
	case CFGA_OK:
		ep = "Configuration operation succeeded";
		break;
	case CFGA_NACK:
		ep = "Configuration operation cancelled";
		break;
	case CFGA_INVAL:
		ep = "Configuration operation invalid";
		break;
	case CFGA_NOTSUPP:
		ep = "Configuration administration not supported";
		break;
	case CFGA_OPNOTSUPP:
		ep = "Configuration operation not supported";
		break;
	case CFGA_PRIV:
		ep = "Insufficient privileges";
		break;
	case CFGA_BUSY:
		ep = "Component system is busy, try again";
		break;
	case CFGA_SYSTEM_BUSY:
		ep = "System is busy, try again";
		break;
	case CFGA_DATA_ERROR:
		ep = "Data error";
		break;
	case CFGA_LIB_ERROR:
		ep = "Library error";
		break;
	case CFGA_NO_LIB:
		ep = "No Library found";
		break;
	case CFGA_INSUFFICENT_CONDITION:
		ep = "Insufficient condition";
		break;
	case CFGA_ERROR:
		ep = "Hardware specific failure";
		break;
	case CFGA_APID_NOEXIST:
		ep = "Attachment point not found";
		break;
	case CFGA_ATTR_INVAL:
		ep = "No attachment point with specified attributes found";
		break;
	default:
		ep = NULL;
		break;
	}
	return (ep);
}

/*
 * listopts is a string in the getsubopt(3C) style:
 *	name1=value1,name2=value2,
 */
static cfga_err_t
parse_listopt(char *listopts, char **classpp, char **errstring)
{
	char *bufp, *optp, *val = NULL;
	cfga_err_t rc = CFGA_ERROR;

	*classpp = NULL;

	/*
	 * NULL is a legal value for listopts
	 */
	if (listopts == NULL) {
		return (CFGA_OK);
	}

	if ((bufp = config_calloc_check(1, strlen(listopts) + 1, errstring))
	    == NULL) {
		return (CFGA_LIB_ERROR);
	}
	(void) strcpy(bufp, listopts);

	optp = bufp; /* getsubopt() modifies its argument */
	while (*optp != '\0') {
		switch (getsubopt(&optp, listopt_array, &val)) {
		case LISTOPT_CLASS:
			if (val == NULL || *classpp != NULL) {
				rc = CFGA_ERROR;
				goto out;
			}
			if ((*classpp = config_calloc_check(1, strlen(val) + 1,
			    errstring)) == NULL) {
				rc = CFGA_LIB_ERROR;
				goto out;
			}
			(void) strcpy(*classpp, val);
			break;
		default:
			rc = CFGA_ERROR;
			goto out;
		}
	}

	rc = CFGA_OK;
	/*FALLTHRU*/
out:
	S_FREE(bufp);
	if (rc != CFGA_OK) {
		S_FREE(*classpp);
	}
	return (rc);
}

/*ARGSUSED*/
static cfga_err_t
null_mklog(
	di_node_t node,
	di_minor_t minor,
	plugin_lib_t *libp,
	lib_loc_t *liblocp)
{
	return (CFGA_OK);
}

static cfga_err_t
mklog_v1(
	di_node_t node,
	di_minor_t minor,
	plugin_lib_t *libp,
	lib_loc_t *liblocp)
{
	const size_t len = CFGA_AP_LOG_ID_LEN;

	assert(len <=  sizeof (liblocp->ap_logical));

	if (libp->plugin_vers != CFGA_HSL_V1) {
		return (CFGA_LIB_ERROR);
	}

	return (mklog_common(node, minor, liblocp, len));
}


/*
 * Obtain the devlink from a /devices path
 */
static int
get_link(di_devlink_t devlink, void *arg)
{
	char *linkp = (char *)arg;

	(void) snprintf(linkp, CFGA_LOG_EXT_LEN, "%s",
	    di_devlink_path(devlink));
	return (DI_WALK_TERMINATE);
}

static cfga_err_t
mklog_v2(
	di_node_t node,
	di_minor_t minor,
	plugin_lib_t *libp,
	lib_loc_t *liblocp)
{
	const size_t len = CFGA_LOG_EXT_LEN;
	di_devlink_handle_t hdl;

	assert(len <=  sizeof (liblocp->ap_logical));

	if (libp->plugin_vers != CFGA_HSL_V2) {
		return (CFGA_LIB_ERROR);
	}

	/* open devlink database */
	if ((hdl = di_devlink_init(NULL, 0)) == NULL) {
		return (CFGA_LIB_ERROR);
	}

	liblocp->ap_logical[0] = '\0';
	(void) di_devlink_walk(hdl, NULL,
	    liblocp->ap_physical + strlen(DEVICES_DIR),
	    DI_PRIMARY_LINK, (void *)liblocp->ap_logical, get_link);

	(void) di_devlink_fini(&hdl);

	if (liblocp->ap_logical[0] != '\0')
		return (CFGA_OK);
	return (mklog_common(node, minor, liblocp, len));
}

/*
 * mklog_common - make a logical name from the driver and instance
 */
static cfga_err_t
mklog_common(
	di_node_t node,
	di_minor_t minor,
	lib_loc_t *libloc_p,
	size_t len)
{
	int inst;
	char *drv, *minor_name;

	drv = di_driver_name(node);
	inst = di_instance(node);
	minor_name = di_minor_name(minor);

	errno = 0;
	if (drv != NULL && inst != -1 && minor_name != NULL &&
	    snprintf(libloc_p->ap_logical, len, "%s%d:%s", drv, inst,
	    minor_name) < len) {	/* snprintf returns strlen */
		return (CFGA_OK);
	}

	return (CFGA_LIB_ERROR);
}

/*
 * mklog_common - make a logical name from the driver and instance
 */
/*ARGSUSED*/
static cfga_err_t
mklog_hp(
	di_node_t node,
	di_hp_t hp,
	plugin_lib_t *libp,
	lib_loc_t *liblocp)
{
	const size_t len = CFGA_LOG_EXT_LEN;
	int inst;
	char *drv, *hp_name;

	drv = di_driver_name(node);
	inst = di_instance(node);
	hp_name = di_hp_name(hp);

	errno = 0;
	if (drv != NULL && inst != -1 && hp_name != NULL &&
	    snprintf(liblocp->ap_logical, len, "%s%d:%s", drv, inst,
	    hp_name) < len) {	/* snprintf returns strlen */
		return (CFGA_OK);
	}

	return (CFGA_LIB_ERROR);
}

/*
 * resolve_lib_ref - relocate to use plugin lib
 */
static cfga_err_t
resolve_lib_ref(
	plugin_lib_t *libp,
	lib_loc_t *libloc_p)
{
	void *sym;
	void *libhdlp = libp->handle;
	int plug_vers;

	if ((sym = dlsym(libhdlp, "cfga_version")) == NULL) {
		/*
		 * Version symbol not defined, must be the first version
		 */
		plug_vers = CFGA_HSL_V1;
	} else {
		plug_vers =   *((int *)sym);
	}

	/*
	 * Check if plugin version matches request.
	 */
	if (!compat_plugin(&libloc_p->vers_req, plug_vers)) {
		return (CFGA_NO_LIB);
	}

	/*
	 * Record the plugin version and setup version dependant routines
	 */
	assert(plug_vers < VERS_ARRAY_SZ);
	libp->plugin_vers = plug_vers;
	libp->vers_ops = &cfga_vers_ops[plug_vers];

	/* resolve symbols common to all versions */
	if ((sym = dlsym(libhdlp, "cfga_change_state")) == NULL) {
		perror("dlsym: cfga_change_state");
		return (CFGA_LIB_ERROR);
	} else
		libp->cfga_change_state_p = (cfga_err_t (*)(cfga_cmd_t,
		    const char *, const char *, struct cfga_confirm *,
		    struct cfga_msg *, char **, cfga_flags_t)) sym;

	if ((sym = dlsym(libhdlp, "cfga_private_func")) == NULL) {
		perror("dlsym: cfga_private_func");
		return (CFGA_LIB_ERROR);
	} else
		libp->cfga_private_func_p = (cfga_err_t (*)(const char *,
		    const char *, const char *, struct cfga_confirm *,
		    struct cfga_msg *, char **, cfga_flags_t))sym;

	if ((sym = dlsym(libhdlp, "cfga_test")) == NULL) {
		perror("dlsym: cfga_test");
		return (CFGA_LIB_ERROR);
	} else
		libp->cfga_test_p = (cfga_err_t (*)(const char *, const char *,
		    struct cfga_msg *, char **, cfga_flags_t))sym;

	if ((sym = dlsym(libhdlp, "cfga_help")) == NULL) {
		perror("dlsym: cfga_help");
		return (CFGA_LIB_ERROR);
	} else
		libp->cfga_help_p = (cfga_err_t (*)(struct cfga_msg *,
		    const char *, cfga_flags_t))sym;

	if ((sym = dlsym(libhdlp, "cfga_ap_id_cmp")) == NULL) {
		libp->cfga_ap_id_cmp_p = default_ap_id_cmp;
	} else
		libp->cfga_ap_id_cmp_p = (int (*)(const
		    cfga_ap_log_id_t, const cfga_ap_log_id_t))sym;

	/* Resolve version specific symbols */
	return (libp->vers_ops->resolve_lib(libp));
}

/*ARGSUSED*/
static cfga_err_t
null_resolve(plugin_lib_t *libp)
{
	return (CFGA_OK);
}

static cfga_err_t
resolve_v1(plugin_lib_t *libp)
{
	void *sym, *libhdlp = libp->handle;


	if (libp->plugin_vers != CFGA_HSL_V1) {
		return (CFGA_NO_LIB);
	}

	if ((sym = dlsym(libhdlp, "cfga_stat")) == NULL) {
		perror("dlsym: cfga_stat");
		return (CFGA_LIB_ERROR);
	} else
		libp->cfga_stat_p = (cfga_err_t (*)(const char *,
		    struct cfga_stat_data *, const char *,
		    char **))sym;

	if ((sym = dlsym(libhdlp, "cfga_list")) == NULL) {
		perror("dlsym: cfga_list");
		return (CFGA_LIB_ERROR);
	} else
		libp->cfga_list_p = (cfga_err_t (*)(struct cfga_stat_data **,
		    int *, const char *, char **))sym;

	return (CFGA_OK);
}

static cfga_err_t
resolve_v2(plugin_lib_t *libp)
{
	void *sym;


	if (libp->plugin_vers != CFGA_HSL_V2) {
		return (CFGA_NO_LIB);
	}

	if ((sym = dlsym(libp->handle, "cfga_list_ext")) == NULL) {
		perror("dlsym: cfga_list_ext");
		return (CFGA_LIB_ERROR);
	} else {
		libp->cfga_list_ext_p = (cfga_err_t (*)(const char *,
		    struct cfga_list_data **, int *, const char *,
		    const char *, char **, cfga_flags_t))sym;
		return (CFGA_OK);
	}
}

/*
 * config_calloc_check - perform allocation, check result and
 * set error string
 */
static void *
config_calloc_check(
	size_t nelem,
	size_t elsize,
	char **errstring)
{
	void *p;

	p = calloc(nelem, elsize);
	if (p == NULL) {
		config_err(0, ALLOC_FAILED, errstring);
	}

	return (p);
}


/*
 * config_get_lib - given an ap_id find the library name
 *	If successful, the plugin library is held.
 */
static cfga_err_t
config_get_lib(
	const char *ap_id,
	lib_loc_t *lib_loc_p,
	char **errstring)
{
	char *dyncomp, path[PATH_MAX];
	char *apdup;
	cfga_ap_types_t type = UNKNOWN_AP;
	cfga_err_t ret = CFGA_ERROR;

	if (ap_id == NULL) {
		config_err(0, INVALID_ARGS, errstring);
		return (ret);
	}

	lib_loc_p->libp = NULL;

	if ((apdup = config_calloc_check(1, strlen(ap_id) + 1, errstring))
	    == NULL) {
		return (CFGA_LIB_ERROR);
	}
	(void) strcpy(apdup, ap_id);

	/*
	 * Separate into base and dynamic components
	 */
	if ((ret = split_apid(apdup, &dyncomp, errstring)) != CFGA_OK) {
		goto out;
	}

	/*
	 * No upper limit on version
	 */
	lib_loc_p->vers_req.v_max = CFGA_HSL_VERS;
	if (dyncomp != NULL) {
		/*
		 * We need atleast version 2 of the plug-in library
		 * interface since the ap_id has a dynamic component.
		 */

		lib_loc_p->vers_req.v_min = CFGA_HSL_V2;
	} else {
		lib_loc_p->vers_req.v_min = CFGA_HSL_V1;
	}

	/*
	 * If the ap_id is a devlink in CFGA_DEV_DIR, follow link
	 * to get the physical ap_id.
	 */
	if ((type = find_arg_type(apdup)) == LOGICAL_LINK_AP) {
		(void) snprintf(lib_loc_p->ap_base, sizeof (lib_loc_p->ap_base),
		    "%s%s", CFGA_DEV_DIR SLASH, apdup);
	}

	path[sizeof (path) - 1] = '\0';
	if (type == LOGICAL_LINK_AP && realpath(lib_loc_p->ap_base, path)
	    != NULL) {
		(void) snprintf(lib_loc_p->ap_base, sizeof (lib_loc_p->ap_base),
		    "%s", path);
	} else {
		(void) snprintf(lib_loc_p->ap_base, sizeof (lib_loc_p->ap_base),
		    "%s", apdup);
	}


	/*
	 * find and load the library
	 * The base component of the ap_id is used to locate the plug-in
	 *
	 * NOTE that PCIE/PCISHPC connectors also have minor nodes &
	 * dev links created for now.
	 */
	if ((type = find_arg_type(lib_loc_p->ap_base)) == PHYSICAL_AP) {
		/*
		 * physical ap_id: Use ap_base as root for tree walk
		 * A link based apid (logical) will resolve to a physical
		 * ap_id.
		 */
		ret = find_ap_common(lib_loc_p, lib_loc_p->ap_base,
		    check_ap_phys, check_ap_phys_hp, errstring);
	} else if ((type == LOGICAL_DRV_AP) ||
	    (type == AP_TYPE && dyncomp == NULL)) {
		/*
		 * logical ap_id or ap_type: Use "/" as root for tree walk
		 * Note: an aptype cannot have a dynamic component
		 */
		ret = find_ap_common(lib_loc_p, "/", check_ap,
		    check_ap_hp, errstring);
	} else {
		ret = CFGA_APID_NOEXIST;
	}

	if (ret == CFGA_OK) {
#ifndef	NDEBUG
		/*
		 * variables used by assert() only which is disabled
		 * by defining NDEBUG (see top of this file)
		 */
		plugin_lib_t *libp;

		libp = lib_loc_p->libp;
#endif	/* NDEBUG */

		assert(strcmp(libp->libpath, lib_loc_p->pathname) == 0);
		assert(VALID_HSL_VERS(libp->plugin_vers));

		/*
		 * If a dynamic component was present, v1 plug-ins are not
		 * acceptable.
		 */
		assert(dyncomp == NULL || libp->plugin_vers >= CFGA_HSL_V2);

		/*
		 * ap_physical is passed to plugins as their ap_id argument.
		 * Append dynamic component if any.
		 */
		append_dyn(lib_loc_p->ap_physical, dyncomp,
		    sizeof (lib_loc_p->ap_physical));
	}

	/* cleanup */
	lib_loc_p->vers_req.v_min = INVALID_VERSION;
	lib_loc_p->vers_req.v_max = INVALID_VERSION;
	*lib_loc_p->ap_base = '\0';

	/*FALLTHRU*/
out:
	S_FREE(apdup);
	S_FREE(dyncomp);
	if (ret != CFGA_OK) {
		lib_loc_p->libp = NULL;
	}

	assert(ret != CFGA_OK || lib_loc_p->libp != NULL);

	return (ret);
}

/* load_lib - load library for non-SHP attachment point node */
static cfga_err_t
load_lib(
	di_node_t node,
	di_minor_t minor,
	lib_loc_t *libloc_p)
{
	return (load_lib_impl(node, minor, NULL, libloc_p));
}

/* load_lib_hp - load library for SHP attachment point node */
static cfga_err_t
load_lib_hp(
	di_node_t node,
	di_hp_t hp,
	lib_loc_t *libloc_p)
{
	return (load_lib_impl(node, NULL, hp, libloc_p));
}

/*
 * load_lib_impl - Given a library pathname, create a entry for it
 * in the library list, * if one does not already exist, and read
 * lock it to keep it there.
 */
static cfga_err_t
load_lib_impl(
	di_node_t node,
	di_minor_t minor,
	di_hp_t hp,
	lib_loc_t *libloc_p)
{
	plugin_lib_t *libp, *list_libp;
	char *devfs_path;
	char *name;

	if (minor != DI_MINOR_NIL && hp != DI_HP_NIL)
		return (CFGA_LIB_ERROR);

	if (minor != DI_MINOR_NIL)
		name = di_minor_name(minor);
	else
		name = di_hp_name(hp);

	/*
	 * lock the library list
	 */
	(void) mutex_lock(&plugin_list_lock);

	/*
	 * see if lib exist in list, if not, allocate a new one
	 */
	list_libp = lib_in_list(libloc_p->pathname);
	if (list_libp != NULL) {
		hold_lib(list_libp);
		(void) mutex_unlock(&plugin_list_lock);

		/* fill in logical and physical name in libloc_p */
		libloc_p->libp = libp = list_libp;
		if (minor != DI_MINOR_NIL) {
			if (libp->vers_ops->mklog(node, minor, libp, libloc_p)
			    != CFGA_OK) {
				rele_lib(list_libp);
				return (CFGA_LIB_ERROR);
			}
		} else {
			if (mklog_hp(node, hp, libp, libloc_p) != CFGA_OK) {
				rele_lib(list_libp);
				return (CFGA_LIB_ERROR);
			}
		}

		devfs_path = di_devfs_path(node);
		(void) snprintf(libloc_p->ap_physical, MAXPATHLEN, "%s%s:%s",
		    DEVICES_DIR, devfs_path, name);
		di_devfs_path_free(devfs_path);

		return (CFGA_OK);
	}

	/* allocate a new plugin_lib_t structure */
	libp = config_calloc_check(1, sizeof (plugin_lib_t), NULL);
	if (libp == NULL) {
		(void) mutex_unlock(&plugin_list_lock);
		return (CFGA_LIB_ERROR);
	}

	(void) snprintf(libp->libpath, sizeof (libp->libpath), "%s",
	    libloc_p->pathname);

	/*
	 * ensure that the lib is open and linked in
	 */
	libp->handle = dlopen(libp->libpath, RTLD_NOW);
	if (libp->handle == NULL) {
		(void) mutex_unlock(&plugin_list_lock);
		free(libp);
		return (CFGA_NO_LIB);
	}

	if (minor != DI_MINOR_NIL) {
		if (resolve_lib_ref(libp, libloc_p) != CFGA_OK ||
		    libp->vers_ops->mklog(node, minor, libp, libloc_p)
		    != CFGA_OK) {
			(void) mutex_unlock(&plugin_list_lock);
			(void) dlclose(libp->handle);
			free(libp);
			return (CFGA_NO_LIB);
		}
	} else {
		if (resolve_lib_ref(libp, libloc_p) != CFGA_OK ||
		    mklog_hp(node, hp, libp, libloc_p) != CFGA_OK) {
			(void) mutex_unlock(&plugin_list_lock);
			(void) dlclose(libp->handle);
			free(libp);
			return (CFGA_NO_LIB);
		}
	}

	/*
	 * link in new entry to the end of list
	 */
	list_libp = &plugin_list;
	while (list_libp->next != NULL)
		list_libp = list_libp->next;
	libp->next = list_libp->next;
	list_libp->next = libp;

	/* Initialize refcnt to 1 */
	libp->refcnt = 1;
	(void) mutex_init(&libp->lock, USYNC_THREAD, NULL);

	(void) mutex_unlock(&plugin_list_lock);

	/*
	 * record libp and physical node name in the libloc struct
	 */
	libloc_p->libp = libp;
	devfs_path = di_devfs_path(node);
	(void) snprintf(libloc_p->ap_physical, MAXPATHLEN, "%s%s:%s",
	    DEVICES_DIR, devfs_path, name);
	di_devfs_path_free(devfs_path);

	return (CFGA_OK);
}


#define	NUM_LIB_NAMES   2

/*
 * find_lib - find library for non-SHP attachment point node
 */
static cfga_err_t
find_lib(
	di_node_t node,
	di_minor_t minor,
	lib_loc_t *libloc_p)
{
	char name[NUM_LIB_NAMES][MAXPATHLEN];
	char *class = NULL, *drv = NULL;
	int i;


	/* Make sure pathname and class is null if we fail */
	*libloc_p->ap_class = *libloc_p->pathname = '\0';

	/*
	 * Initialize possible library tags.
	 */

	drv = di_driver_name(node);
	class = get_class(minor);

	if (drv == NULL || class == NULL) {
		return (CFGA_LIB_ERROR);
	}

	i = 0;
	(void) snprintf(&name[i++][0], sizeof (name[0]), "%s", drv);
	(void) snprintf(&name[i++][0], sizeof (name[0]), "%s", class);

	/*
	 * Cycle through the array of names to find the library.
	 */
	for (i = 0; i < NUM_LIB_NAMES; i++) {

		/* Attachment points may not have a class (i.e. are generic) */
		if (name[i][0] == '\0') {
			continue;
		}

		if (find_lib_impl(name[i], libloc_p) == CFGA_OK)
			goto found;
	}

	return (CFGA_NO_LIB);

found:

	/* Record class name (if any) */
	(void) snprintf(libloc_p->ap_class, sizeof (libloc_p->ap_class), "%s",
	    class);

	return (CFGA_OK);
}

/*
 * find_lib_hp - find library for SHP attachment point
 */
/*ARGSUSED*/
static cfga_err_t
find_lib_hp(
	di_node_t node,
	di_hp_t hp,
	lib_loc_t *libloc_p)
{
	char name[MAXPATHLEN];
	char *class = NULL;


	/* Make sure pathname and class is null if we fail */
	*libloc_p->ap_class = *libloc_p->pathname = '\0';

	/*
	 * Initialize possible library tags.
	 *
	 * Only support PCI class for now, this will need to be
	 * changed as other plugins are migrated to SHP plugin.
	 */
	class = "pci";
#if 0
	/*
	 * No type check for now as PCI is the only class SHP plugin
	 * supports. In the future we'll need to enable the type check
	 * and set class accordingly, when non PCI plugins are migrated
	 * to SHP. In that case we'll probably need to add an additional
	 * interface between libcfgadm and the plugins, and SHP plugin will
	 * implement this interface which will translate the bus specific
	 * strings to standard classes that libcfgadm can recognize, for
	 * all the buses it supports, e.g. for pci/pcie it will translate
	 * PCIE_NATIVE_HP_TYPE to string "pci". We'll also need to bump up
	 * SHP plugin version to 3 to use the new interface.
	 */
	class = di_hp_type(hp);
	if ((strcmp(class, PCIE_NATIVE_HP_TYPE) == 0) ||
	    (strcmp(class, PCIE_ACPI_HP_TYPE) == 0) ||
	    (strcmp(class, PCIE_PCI_HP_TYPE) == 0)) {
		class = "pci";
	} else {
		goto fail;
	}
#endif
	(void) snprintf(&name[0], sizeof (name), "%s", "shp");

	if (find_lib_impl(name, libloc_p) == CFGA_OK)
		goto found;
fail:
	return (CFGA_NO_LIB);

found:

	/* Record class name (if any) */
	(void) snprintf(libloc_p->ap_class, sizeof (libloc_p->ap_class), "%s",
	    class);

	return (CFGA_OK);
}

/*
 * find_lib_impl - Given an attachment point node find it's library
 */
static cfga_err_t
find_lib_impl(
	char *name,
	lib_loc_t *libloc_p)
{
	char lib[MAXPATHLEN];
	struct stat lib_stat;
	void *dlhandle = NULL;
	static char plat_name[SYSINFO_LENGTH];
	static char machine_name[SYSINFO_LENGTH];
	static char arch_name[SYSINFO_LENGTH];

	/*
	 * Initialize machine name and arch name
	 */
	if (strncmp("", machine_name, MAXPATHLEN) == 0) {
		if (sysinfo(SI_PLATFORM, plat_name, SYSINFO_LENGTH) == -1) {
			return (CFGA_ERROR);
		}
		if (sysinfo(SI_ARCHITECTURE, arch_name, SYSINFO_LENGTH) == -1) {
			return (CFGA_ERROR);
		}
		if (sysinfo(SI_MACHINE, machine_name, SYSINFO_LENGTH) == -1) {
			return (CFGA_ERROR);
		}
	}

	/*
	 * Try path based upon platform name
	 */
	(void) snprintf(lib, sizeof (lib), "%s%s%s%s%s",
	    LIB_PATH_BASE1, plat_name, LIB_PATH_MIDDLE,
	    name, LIB_PATH_TAIL);

	if (stat(lib, &lib_stat) == 0) {
		/* file exists, is it a lib */
		dlhandle = dlopen(lib, RTLD_LAZY);
		if (dlhandle != NULL) {
			goto found;
		}
	}

	/*
	 * Try path based upon machine name
	 */
	(void) snprintf(lib, sizeof (lib), "%s%s%s%s%s",
	    LIB_PATH_BASE1, machine_name, LIB_PATH_MIDDLE,
	    name, LIB_PATH_TAIL);


	if (stat(lib, &lib_stat) == 0) {
		/* file exists, is it a lib */
		dlhandle = dlopen(lib, RTLD_LAZY);
		if (dlhandle != NULL) {
			goto found;
		}
	}

	/*
	 * Try path based upon arch name
	 */
	(void) snprintf(lib, sizeof (lib), "%s%s%s%s%s",
	    LIB_PATH_BASE1, arch_name, LIB_PATH_MIDDLE,
	    name, LIB_PATH_TAIL);

	if (stat(lib, &lib_stat) == 0) {
		/* file exists, is it a lib */
		dlhandle = dlopen(lib, RTLD_LAZY);
		if (dlhandle != NULL) {
			goto found;
		}

	}

	/*
	 * Try generic location
	 */
	(void) snprintf(lib, sizeof (lib), "%s%s%s%s",
	    LIB_PATH_BASE2, LIB_PATH_MIDDLE, name, LIB_PATH_TAIL);

	if (stat(lib, &lib_stat) == 0) {
		/* file exists, is it a lib */
		dlhandle = dlopen(lib, RTLD_LAZY);
		if (dlhandle != NULL) {
			goto found;
		}

	}
	return (CFGA_NO_LIB);

found:
	/* we got one! */
	(void) snprintf(libloc_p->pathname, sizeof (libloc_p->pathname), "%s",
	    lib);

	(void) dlclose(dlhandle);

	return (CFGA_OK);
}

static cfga_err_t
lookup_cache(lib_loc_t *libloc_p)
{
	lib_cache_t *entry;
	(void) mutex_lock(&lib_cache_lock);
	entry = lib_cache;
	while (entry) {
		if (strcmp(entry->lc_ap_id, libloc_p->ap_base) == 0) {
			plugin_lib_t *libp = entry->lc_libp;
			libloc_p->libp = libp;
			hold_lib(libp);
			(void) strcpy(libloc_p->pathname, libp->libpath);
			(void) strcpy(libloc_p->ap_physical,
			    entry->lc_ap_physical);
			(void) strcpy(libloc_p->ap_logical,
			    entry->lc_ap_logical);
			(void) mutex_unlock(&lib_cache_lock);
			return (CFGA_OK);
		}
		entry = entry->lc_next;
	}
	(void) mutex_unlock(&lib_cache_lock);

	return (CFGA_ERROR);
}

static void
update_cache(lib_loc_t *libloc_p)
{
	lib_cache_t *entry;
	entry = config_calloc_check(1, sizeof (lib_cache_t), NULL);
	if (entry == NULL)
		return;

	entry->lc_ap_id = strdup(libloc_p->ap_base);
	entry->lc_ap_physical = strdup(libloc_p->ap_physical);
	entry->lc_ap_logical = strdup(libloc_p->ap_logical);
	if ((entry->lc_ap_id == NULL) || (entry->lc_ap_physical == NULL) ||
	    (entry->lc_ap_logical == NULL)) {
		free(entry->lc_ap_id);
		free(entry->lc_ap_physical);
		free(entry->lc_ap_logical);
		free(entry);
		return;
	}

	(void) mutex_lock(&lib_cache_lock);
	entry->lc_libp = libloc_p->libp;
	entry->lc_next = lib_cache;
	lib_cache = entry;
	hold_lib(entry->lc_libp);	/* prevent stale cache */
	(void) mutex_unlock(&lib_cache_lock);
}

static void
destroy_cache()
{
	lib_cache_t *entry, *next;
	(void) mutex_lock(&lib_cache_lock);
	entry = lib_cache;
	while (entry) {
		next = entry->lc_next;
		rele_lib(entry->lc_libp);
		free(entry->lc_ap_id);
		free(entry->lc_ap_physical);
		free(entry->lc_ap_logical);
		free(entry);
		entry = next;
	}
	(void) mutex_unlock(&lib_cache_lock);
}

/*
 * find_ap_common - locate a particular attachment point
 */
static cfga_err_t
find_ap_common(
	lib_loc_t *libloc_p,
	const char *physpath,
	int (*fcn)(di_node_t node, di_minor_t minor, void *arg),
	int (*fcn_hp)(di_node_t node, di_hp_t hp, void *arg),
	char **errstring)
{
	di_node_t rnode, wnode;
	char *cp, *rpath;
	size_t len;

	if (lookup_cache(libloc_p) == CFGA_OK)
		return (CFGA_OK);

	if ((rpath = config_calloc_check(1, strlen(physpath) + 1,
	    errstring)) == NULL) {
		return (CFGA_LIB_ERROR);
	}

	(void) strcpy(rpath, physpath);

	/* Remove devices prefix (if any) */
	len = strlen(DEVICES_DIR);
	if (strncmp(rpath, DEVICES_DIR SLASH, len + strlen(SLASH)) == 0) {
		(void) memmove(rpath, rpath + len,
		    strlen(rpath + len) + 1);
	}

	/* Remove dynamic component if any */
	if ((cp = GET_DYN(rpath)) != NULL) {
		*cp = '\0';
	}

	/* Remove minor name (if any) */
	if ((cp = strrchr(rpath, ':')) != NULL) {
		*cp = '\0';
	}

	/*
	 * begin walk of device tree
	 *
	 * Since we create minor nodes & dev links for both all PCI/PCIE
	 * connectors, but only create hp nodes for PCIE/PCISHPC connectors
	 * of the new framework, we should first match with hp nodes. If
	 * the ap_id refers to a PCIE/PCISHPC connector, we'll be able to
	 * find it here.
	 */
	rnode = di_init("/", DINFOSUBTREE | DINFOHP);
	if (rnode)
		wnode = di_lookup_node(rnode, rpath);
	else
		wnode = DI_NODE_NIL;

	if (wnode == DI_NODE_NIL) {
		if (rnode == DI_NODE_NIL) {
			S_FREE(rpath);
			config_err(errno, DI_INIT_FAILED, errstring);
			return (CFGA_LIB_ERROR);
		} else {
			/*
			 * di_lookup_node() may fail, either because the
			 * ap_id does not exist, or because the ap_id refers
			 * to a legacy PCI slot, thus we'll not able to
			 * find node using DINFOHP, try to see if we can
			 * find one using DINFOCACHE.
			 */
			di_fini(rnode);
			goto find_minor;
		}
	}

	libloc_p->libp = NULL;
	libloc_p->status = CFGA_APID_NOEXIST;

	(void) di_walk_hp(wnode, NULL, DI_HP_CONNECTOR,
	    libloc_p, fcn_hp);

	di_fini(rnode);

	/*
	 * Failed to find a matching hp node, try minor node.
	 */
	if (libloc_p->libp == NULL) {
find_minor:
		rnode = di_init("/", DINFOCACHE);
		if (rnode)
			wnode = di_lookup_node(rnode, rpath);
		else
			wnode = DI_NODE_NIL;

		if (wnode == DI_NODE_NIL) {
			if (rnode == DI_NODE_NIL) {
				S_FREE(rpath);
				config_err(errno, DI_INIT_FAILED, errstring);
				return (CFGA_LIB_ERROR);
			} else {
				/*
				 * di_lookup_node() may fail, because the
				 * ap_id does not exist.
				 */
				S_FREE(rpath);
				di_fini(rnode);
				return (CFGA_APID_NOEXIST);
			}
		}

		libloc_p->libp = NULL;
		libloc_p->status = CFGA_APID_NOEXIST;

		(void) di_walk_minor(wnode, "ddi_ctl:attachment_point",
		    DI_CHECK_ALIAS|DI_CHECK_INTERNAL_PATH,
		    libloc_p, fcn);

		di_fini(rnode);
	}

	S_FREE(rpath);

	if (libloc_p->libp != NULL) {
		update_cache(libloc_p);
		return (CFGA_OK);
	} else {
		return (libloc_p->status);
	}
}

/*
 * check_ap - called for each non-SHP attachment point found
 */
static int
check_ap(
	di_node_t node,
	di_minor_t minor,
	void *arg)
{
	return (check_ap_impl(node, minor, NULL, arg));
}

/*
 * check_ap_hp - called for each SHP attachment point found
 */
static int
check_ap_hp(
	di_node_t node,
	di_hp_t hp,
	void *arg)
{
	return (check_ap_impl(node, NULL, hp, arg));
}

/*
 * check_ap_impl - called for each attachment point found
 *
 * This is used in cases where a particular attachment point
 * or type of attachment point is specified via a logical name or ap_type.
 * Not used for physical names or in the list case with no
 * ap's specified.
 */
static int
check_ap_impl(
	di_node_t node,
	di_minor_t minor,
	di_hp_t hp,
	void *arg)
{
	char *cp = NULL;
	char aptype[MAXPATHLEN];
	char *recep_id = NULL;
	char *node_minor;
	char *drv_name;
	char inst[MAXPATHLEN];
	char inst2[MAXPATHLEN];
	lib_loc_t *libloc_p;
	int comparison_test;
	int instance;
	cfga_ap_types_t type;

	if (minor != DI_MINOR_NIL && hp != DI_HP_NIL)
		return (DI_WALK_CONTINUE);

	libloc_p = (lib_loc_t *)arg;

	(void) snprintf(aptype, sizeof (aptype), "%s", libloc_p->ap_base);

	/*
	 * This routime handles only aptypes and driver based logical apids.
	 */
	type = find_arg_type(aptype);
	if (type == LOGICAL_DRV_AP) {
		cp = strchr(aptype, ':');
		*cp = '\0';
		recep_id =  cp+1;
		cp--;
		while (isdigit(*cp) && cp != aptype)
			cp--;
		cp++;

		(void) snprintf(inst, sizeof (inst), "%s", cp);

		*cp = '\0';
	} else if (type != AP_TYPE) {
		libloc_p->status = CFGA_APID_NOEXIST;
		return (DI_WALK_CONTINUE);
	}

	if (minor != DI_MINOR_NIL)
		node_minor = di_minor_name(minor);
	else
		node_minor = di_hp_name(hp);

	drv_name = di_driver_name(node);
	instance = di_instance(node);

	if (node_minor == NULL || drv_name == NULL || instance == -1) {
		libloc_p->status = CFGA_APID_NOEXIST;
		return (DI_WALK_CONTINUE);
	}

	(void) sprintf(inst2, "%d", instance);

	/*
	 * If the base matches driver and instance try and find a lib for it,
	 * then load it. On any failure we continue the walk.
	 *
	 * driver based logical ap_ids are derived from driver name + instance.
	 * Ap_types are just partial driver names.
	 *
	 */

	comparison_test = 0;
	if (type == AP_TYPE) {
		if (strncmp(aptype, drv_name, strlen(aptype)) == 0) {
			comparison_test = 1;
		}
	} else {
		if (strcmp(aptype, drv_name) == 0 &&
		    strcmp(recep_id, node_minor) == 0 &&
		    strcmp(inst, inst2) == 0) {
			comparison_test = 1;
		}
	}

	if (comparison_test) {
		/*
		 * save the correct type of error so user does not get confused
		 */
		if (minor != DI_MINOR_NIL) {
			if (find_lib(node, minor, libloc_p) != CFGA_OK) {
				libloc_p->status = CFGA_NO_LIB;
				return (DI_WALK_CONTINUE);
			}
			if (load_lib(node, minor, libloc_p) != CFGA_OK) {
				libloc_p->status = CFGA_LIB_ERROR;
				return (DI_WALK_CONTINUE);
			}
		} else {
			if (find_lib_hp(node, hp, libloc_p) != CFGA_OK) {
				libloc_p->status = CFGA_NO_LIB;
				return (DI_WALK_CONTINUE);
			}
			if (load_lib_hp(node, hp, libloc_p) != CFGA_OK) {
				libloc_p->status = CFGA_LIB_ERROR;
				return (DI_WALK_CONTINUE);
			}
		}
		libloc_p->status = CFGA_OK;
		return (DI_WALK_TERMINATE);
	} else {
		libloc_p->status = CFGA_APID_NOEXIST;
		return (DI_WALK_CONTINUE);
	}
}


/*
 * check_ap_phys - called for each non-SHP attachment point found
 */
static int
check_ap_phys(
	di_node_t node,
	di_minor_t minor,
	void *arg)
{
	return (check_ap_phys_impl(node, minor, DI_HP_NIL, arg));
}

/*
 * check_ap_phys_hp - called for each SHP attachment point found
 */
static int
check_ap_phys_hp(
	di_node_t node,
	di_hp_t hp,
	void *arg)
{
	return (check_ap_phys_impl(node, DI_HP_NIL, hp, arg));
}

/*
 * check_ap_phys_impl - called for each attachment point found
 *
 * This is used in cases where a particular attachment point
 * is specified via a physical name. If the name matches then
 * we try and find and load the library for it.
 */
static int
check_ap_phys_impl(
	di_node_t node,
	di_minor_t minor,
	di_hp_t hp,
	void *arg)
{
	lib_loc_t *libloc_p;
	char phys_name[MAXPATHLEN];
	char *devfs_path;
	char *minor_name;

	if (minor != DI_MINOR_NIL && hp != DI_HP_NIL)
		return (DI_WALK_CONTINUE);

	libloc_p = (lib_loc_t *)arg;
	devfs_path = di_devfs_path(node);
	if (minor != DI_MINOR_NIL)
		minor_name = di_minor_name(minor);
	else
		minor_name = di_hp_name(hp);

	if (devfs_path == NULL || minor_name == NULL) {
		libloc_p->status = CFGA_APID_NOEXIST;
		return (DI_WALK_CONTINUE);
	}

	(void) snprintf(phys_name, sizeof (phys_name), "%s%s:%s",
	    DEVICES_DIR, devfs_path, minor_name);

	di_devfs_path_free(devfs_path);

	if (strcmp(phys_name, libloc_p->ap_base) == 0) {
		if (minor != DI_MINOR_NIL) {
			if (find_lib(node, minor, libloc_p) != CFGA_OK) {
				libloc_p->status = CFGA_NO_LIB;
				return (DI_WALK_CONTINUE);
			}
			if (load_lib(node, minor, libloc_p) != CFGA_OK) {
				libloc_p->status = CFGA_LIB_ERROR;
				return (DI_WALK_CONTINUE);
			}
		} else {
			if (find_lib_hp(node, hp, libloc_p) != CFGA_OK) {
				libloc_p->status = CFGA_NO_LIB;
				return (DI_WALK_CONTINUE);
			}
			if (load_lib_hp(node, hp, libloc_p) != CFGA_OK) {
				libloc_p->status = CFGA_LIB_ERROR;
				return (DI_WALK_CONTINUE);
			}
		}

		libloc_p->status = CFGA_OK;
		return (DI_WALK_TERMINATE);
	} else {
		libloc_p->status = CFGA_APID_NOEXIST;
		return (DI_WALK_CONTINUE);
	}
}

/*
 * lib_in_list
 *
 * See if library, as specified by the full pathname and controller
 * instance number is already represented in the plugin library list.
 * If the instance number is -1 it is ignored.
 */
static plugin_lib_t *
lib_in_list(char *libpath)
{
	plugin_lib_t *libp = NULL;

	for (libp = plugin_list.next; libp != NULL; libp = libp->next) {
		if (strncmp(libpath, libp->libpath, MAXPATHLEN) == 0) {
			return (libp);
		}
	}
	return (NULL);
}




/*
 * Coalesce stat and list data into single array
 */
static cfga_err_t
realloc_data_ext(
	cfga_list_data_t **ap_id_list,
	int *nlistp,
	list_stat_t *lstatp)
{
	int i, j;
	stat_data_list_t *slp;
	cfga_list_data_t *cldp;
	array_list_t *alp;
	cfga_err_t rc = CFGA_OK;


	assert(*lstatp->countp >= 0);

	if (*lstatp->countp == 0) {
		*ap_id_list = NULL;
		*nlistp = 0;
		return (CFGA_OK);
	}

	/*
	 * allocate the array
	 */
	if ((cldp = config_calloc_check(*lstatp->countp,
	    sizeof (cfga_list_data_t), lstatp->errstr)) == NULL) {
		rc = CFGA_LIB_ERROR;
		goto out;
	}

	/*
	 * copy all the stat elements (if any) into the array
	 */
	slp = lstatp->sdl;
	for (i = 0; slp != NULL; i++) {
		if (i >= *lstatp->countp) {
			rc = CFGA_LIB_ERROR;
			goto out;
		}
		stat_to_list(&cldp[i], &slp->stat_data);
		slp = slp->next;
	}

	/*
	 * copy all the list elements (if any) into the array
	 */
	alp = lstatp->al;
	for (; alp != NULL; ) {
		if (i + alp->nelem > *lstatp->countp) {
			rc = CFGA_LIB_ERROR;
			goto out;
		}

		for (j = 0; j < alp->nelem; i++, j++) {
			cldp[i] = alp->array[j];
		}
		alp = alp->next;
	}

	if (i != *lstatp->countp) {
		rc = CFGA_LIB_ERROR;
	} else {
		rc = CFGA_OK;
	}

	/*FALLTHRU*/

out:
	/* clean up */
	lstat_free(lstatp);

	if (rc == CFGA_OK) {
		*ap_id_list = cldp;
		*nlistp = *lstatp->countp;
	} else {
		S_FREE(cldp);
		*ap_id_list = NULL;
		*nlistp = 0;
	}
	return (rc);
}

/*
 * The caller of this routine may supply a buffer through
 * ap_id_list for returning data. Otherwise, this routine allocates the
 * buffer.
 */
static cfga_err_t
realloc_data(cfga_stat_data_t **ap_id_list, int *nlistp, list_stat_t *lstatp)
{
	int i;
	stat_data_list_t *slp;
	cfga_stat_data_t *csdp, *buf;
	cfga_err_t rc;


	assert(*lstatp->countp >= 0);

	if (*lstatp->countp == 0) {
		*nlistp = 0;
		return (CFGA_OK);
	}


	/*
	 * allocate the array if caller does not supply one.
	 */
	if (*ap_id_list == NULL) {
		if ((buf = config_calloc_check(*lstatp->countp,
		    sizeof (cfga_stat_data_t), lstatp->errstr)) == NULL) {
			rc = CFGA_LIB_ERROR;
			goto out;
		}
	} else {
		buf = *ap_id_list;
	}

	/*
	 * copy the stat elements into the array
	 */
	csdp = buf;
	slp = lstatp->sdl;
	for (i = 0; slp != NULL; i++) {
		if (i >= *lstatp->countp) {
			rc = CFGA_LIB_ERROR;
			goto out;
		}
		*csdp++ = slp->stat_data;
		slp = slp->next;
	}

	rc = CFGA_OK;

out:
	if (rc == CFGA_OK) {
		*nlistp = *lstatp->countp;
		*ap_id_list = buf;
	} else {
		/*
		 * Free buffer only if we allocated it.
		 */
		if (*ap_id_list == NULL) {
			free(buf);
		}
		*nlistp = 0;
	}

	assert(lstatp->al == NULL);
	lstat_free(lstatp);

	return (rc);
}


/*
 * list_common - walk the device tree and stat all attachment points.
 */
static cfga_err_t
list_common(list_stat_t *lstatp, const char *class)
{
	di_node_t rnode;
	char nodetype[MAXPATHLEN];
	const char *l_class, *l_sep;

	/*
	 * May walk a subset of all attachment points in the device tree if
	 * a class is specified
	 */
	if (class != NULL) {
		l_sep = ":";
		l_class = class;
	} else {
		l_sep = l_class = "";
	}

	(void) snprintf(nodetype, sizeof (nodetype), "%s%s%s",
	    DDI_NT_ATTACHMENT_POINT, l_sep, l_class);

	/*
	 * Walk all hp nodes
	 */
	if ((rnode = di_init("/", DINFOSUBTREE | DINFOHP)) == DI_NODE_NIL) {
		config_err(errno, DI_INIT_FAILED, lstatp->errstr);
		return (CFGA_LIB_ERROR);
	}
	/* No need to filter on class for now */
	(void) di_walk_hp(rnode, NULL, DI_HP_CONNECTOR,
	    lstatp, do_list_common_hp);

	di_fini(rnode);

	/*
	 * Walk all minor nodes
	 * but exclude PCIE/PCIESHPC connectors which have been walked above.
	 */
	if ((rnode = di_init("/", DINFOCACHE)) == DI_NODE_NIL) {
		config_err(errno, DI_INIT_FAILED, lstatp->errstr);
		return (CFGA_LIB_ERROR);
	}
	(void) di_walk_minor(rnode, nodetype,
	    DI_CHECK_ALIAS|DI_CHECK_INTERNAL_PATH, lstatp, do_list_common);

	di_fini(rnode);

	if (lstatp->shp_errstr != NULL) {
		*(lstatp->errstr) = strdup(lstatp->shp_errstr);
		free(lstatp->shp_errstr);
		lstatp->shp_errstr = NULL;
	}

	return (CFGA_OK);
}

static void
config_err(int errnum, int err_type, char **errstring)
{
	char *p = NULL, *q = NULL;
	char *syserr = NULL;
	char syserr_num[20];
	int len = 0;

	/*
	 * If errstring is null it means user in not interested in getting
	 * error status. So we don't do all the work
	 */
	if (errstring == NULL) {
		return;
	}

	if (errnum != 0) {
		syserr = strerror(errnum);
		if (syserr == NULL) {
			(void) sprintf(syserr_num, "errno=%d", errnum);
			syserr = syserr_num;
		}
	} else
		syserr = NULL;

	q = dgettext(TEXT_DOMAIN, err_strings[err_type]);

	len = strlen(q);
	if (syserr != NULL) {
		len += strlen(err_sep) + strlen(syserr);
	}

	p = malloc(len + 1);
	if (p == NULL) {
		*errstring = NULL;
		return;
	}

	(void) strcpy(p, q);
	if (syserr != NULL) {
		(void) strcat(p, err_sep);
		(void) strcat(p, syserr);
	}

	*errstring  = p;
}

/*
 * do_list_common - list non-SHP attachment point
 */
static int
do_list_common(di_node_t node, di_minor_t minor, void *arg)
{
	di_node_t rnode;
	di_hp_t hp;
	char *minor_name;
	char *phys_path;

	if ((minor_name = di_minor_name(minor)) == NULL)
		return (DI_WALK_CONTINUE);

	/*
	 * since PCIE/PCIHSHPC connectors have both hp nodes and minor nodes
	 * created for now, we need to specifically exclude these connectors
	 * during walking minor nodes.
	 */
	if ((phys_path = di_devfs_path(node)) == NULL)
		return (DI_WALK_CONTINUE);
	rnode = di_init(phys_path, DINFOSUBTREE | DINFOHP);
	di_devfs_path_free(phys_path);
	if (rnode == DI_NODE_NIL)
		return (DI_WALK_CONTINUE);

	for (hp = DI_HP_NIL; (hp = di_hp_next(rnode, hp)) != DI_HP_NIL; ) {
		if (strcmp(di_hp_name(hp), minor_name) == 0) {
			di_fini(rnode);
			return (DI_WALK_CONTINUE);
		}
	}

	di_fini(rnode);

	return (do_list_common_impl(node, minor, NULL, arg));
}

/*
 * do_list_common_hp - list SHP attachment point
 */
static int
do_list_common_hp(
	di_node_t node,
	di_hp_t hp,
	void *arg)
{
	return (do_list_common_impl(node, NULL, hp, arg));
}

/*
 * do_list_common_impl - Routine to list attachment point as part of
 * a config_list opertion. Used by both v1 and v2 interfaces.
 * This is somewhat similar to config_get_lib() and its helper routines
 * except that the ap_ids are always physical and don't have dynamic
 * components.
 */
static int
do_list_common_impl(
	di_node_t node,
	di_minor_t minor,
	di_hp_t hp,
	void *arg)
{
	lib_loc_t lib_loc;
	plugin_lib_t *libp;
	list_stat_t *lstatp = NULL;
	cfga_err_t ret = CFGA_ERROR;

	if (minor != DI_MINOR_NIL && hp != DI_HP_NIL)
		return (DI_WALK_CONTINUE);

	lstatp = (list_stat_t *)arg;

	lib_loc.libp = NULL;
	/*
	 * try and find a lib for this node
	 */
	if (minor != DI_MINOR_NIL) {
		ret = find_lib(node, minor, &lib_loc);
	} else {
		ret = find_lib_hp(node, hp, &lib_loc);
	}
	if (ret != CFGA_OK) {
		return (DI_WALK_CONTINUE);
	}

	/*
	 * Load all plugins. We will check compatibility later in this
	 * routine.
	 */
	lib_loc.vers_req.v_min = CFGA_HSL_V1;
	lib_loc.vers_req.v_max = CFGA_HSL_VERS;

	if (minor != DI_MINOR_NIL) {
		ret = load_lib(node, minor, &lib_loc);
	} else {
		ret = load_lib_hp(node, hp, &lib_loc);
	}
	if (ret != CFGA_OK) {
		return (DI_WALK_CONTINUE);
	}

	libp = lib_loc.libp;
	assert(libp != NULL);

	/*
	 * Note: For list type routines (list all attachment points in
	 * device tree) we don't pass errstring to the plugin, nor do we
	 * stop the walk if an error occurs in the plugin.
	 */
	if (compat_plugin(&lstatp->use_vers, libp->plugin_vers)) {
		if (minor != DI_MINOR_NIL) {
			(void) libp->vers_ops->stat_plugin(lstatp,
			    &lib_loc, NULL);
		} else {
			/*
			 * If the underlying hotplug daemon is not enabled,
			 * the SHP attach points will not be shown, this
			 * could confuse the uesrs. We specifically pass the
			 * errstring to SHP plugin so that it can set the
			 * errstring accordingly in this case, giving users
			 * a hint.
			 */
			ret = libp->vers_ops->stat_plugin(lstatp,
			    &lib_loc, lstatp->errstr);
			if (ret == CFGA_NOTSUPP && *(lstatp->errstr) != NULL) {
				if (lstatp->shp_errstr == NULL) {
					lstatp->shp_errstr =
					    strdup(*(lstatp->errstr));
				}
			}

			if (*(lstatp->errstr) != NULL) {
				free(*(lstatp->errstr));
				*(lstatp->errstr) = NULL;
			}
		}
	}
	rele_lib(libp);

	return (DI_WALK_CONTINUE);
}

/*
 * stat_common - stat a user specified set of attachment points.
 */
static cfga_err_t
stat_common(
	int num_ap_ids,
	char *const *ap_ids,
	const char *class,
	list_stat_t *lstatp)
{
	int i;
	lib_loc_t libloc;
	plugin_lib_t *libp;
	cfga_err_t rc = CFGA_OK;


	/*
	 * operate on each ap_id
	 */
	for (i = 0; i < num_ap_ids; i++) {
		libloc.libp = NULL;
		if ((rc = config_get_lib(ap_ids[i], &libloc,
		    lstatp->errstr)) != CFGA_OK) {
			break;
		}
		assert(libloc.libp != NULL);
		libp = libloc.libp;

		/*
		 * do pre-filtering if requested
		 */
		if (class != NULL && strcmp(libloc.ap_class, class)) {
			rele_lib(libp);
			continue;
		}

		/*
		 * Unlike list type routines, while stat'ing specific
		 * attachment points we pass errstring to the plugins
		 * and halt if an error occurs in the plugin.
		 */
		rc = libp->vers_ops->stat_plugin(lstatp, &libloc,
		    lstatp->errstr);
		rele_lib(libp);
		if (rc != CFGA_OK) {
			break;
		}
	}

	if (rc != CFGA_OK) {
		lstat_free(lstatp);
	}
	return (rc);
}

/*ARGSUSED*/
static cfga_err_t
null_stat_plugin(list_stat_t *lstatp, lib_loc_t *libloc_p, char **errstring)
{
	return (CFGA_OK);
}

/*
 * Pass errstring as a separate argument. Some higher level routines need
 * it to be NULL.
 */
static cfga_err_t
stat_plugin_v1(list_stat_t *lstatp, lib_loc_t *libloc_p, char **errstring)
{
	stat_data_list_t *slp, *slp2 = NULL;
	cfga_err_t rc;

	/*
	 * allocate stat data buffer and list element
	 */
	if ((slp = config_calloc_check(1, sizeof (stat_data_list_t),
	    errstring)) == NULL) {
		return (CFGA_LIB_ERROR);
	}

	/*
	 * Do the stat
	 */
	errno = 0;
	if ((rc = (*(libloc_p->libp->cfga_stat_p))(libloc_p->ap_physical,
	    &slp->stat_data, lstatp->opts, errstring)) != CFGA_OK) {
		S_FREE(slp);
		return (rc);
	}
	slp->next = NULL;

	/*
	 * Set up the logical and physical id's.
	 * For v1 interfaces, the generic library (libcfgadm) creates the
	 * ap_ids. mklog() is assumed to have been called in
	 * the caller of this routine.
	 */
	(void) snprintf(slp->stat_data.ap_log_id, CFGA_AP_LOG_ID_LEN, "%s",
	    libloc_p->ap_logical);

	(void) snprintf(slp->stat_data.ap_phys_id, CFGA_AP_PHYS_ID_LEN, "%s",
	    libloc_p->ap_physical);

	/*
	 * link it in
	 */
	if ((slp2 = lstatp->sdl) == NULL) {
		lstatp->sdl = slp;
	} else {
		while (slp2->next != NULL)
			slp2 = slp2->next;
		slp2->next = slp;
	}

	/* keep count */
	(*lstatp->countp)++;

	return (CFGA_OK);
}

static cfga_err_t
stat_plugin_v2(list_stat_t *lstatp, lib_loc_t *libloc_p, char **errstring)
{
	int i;
	array_list_t *alp, *alp2 = NULL;
	cfga_err_t rc;
	char *class;

	/*
	 * allocate array list
	 */
	if ((alp = config_calloc_check(1, sizeof (array_list_t),
	    errstring)) == NULL) {
		return (CFGA_LIB_ERROR);
	}

	alp->array = NULL;
	alp->nelem = 0;

	/*
	 * The listopts argument is currently unused. Use NULL
	 */
	errno = 0;
	if ((rc = (*(libloc_p->libp->cfga_list_ext_p))(
	    libloc_p->ap_physical, &alp->array, &alp->nelem, lstatp->opts, NULL,
	    errstring, lstatp->flags)) != CFGA_OK || alp->nelem <= 0) {
		S_FREE(alp);
		return (rc);
	}
	alp->next = NULL;

	/*
	 * Set up the logical and physical id's if necessary.
	 * For v2 interfaces, the generic library (libcfgadm) creates the
	 * ap_ids only if there are no dynamic attachment points and the
	 * plug-in does not create the name itself.  mklog() is
	 * assumed to have been called in the caller of this routine.
	 */
	if (alp->nelem == 1) {
		char cphys, clog;

		clog = (alp->array[0]).ap_log_id[0];
		cphys = (alp->array[0]).ap_phys_id[0];

		if (clog == '\0') {
			(void) snprintf((alp->array[0]).ap_log_id,
			    sizeof ((alp->array[0]).ap_log_id), "%s",
			    libloc_p->ap_logical);
		}

		if (cphys == '\0') {
			(void) snprintf((alp->array[0]).ap_phys_id,
			    sizeof ((alp->array[0]).ap_phys_id), "%s",
			    libloc_p->ap_physical);
		}
	}

	if (libloc_p->ap_class[0] == '\0') {
		class = CFGA_NO_CLASS;
	} else {
		class = libloc_p->ap_class;
	}

	/* Fill in the class information for all list elements */
	for (i = 0; i < alp->nelem; i++) {
		(void) snprintf((alp->array[i]).ap_class,
		    sizeof ((alp->array[i]).ap_class), "%s", class);
	}

	/*
	 * link it in
	 */
	if ((alp2 = lstatp->al) == NULL) {
		lstatp->al = alp;
	} else {
		while (alp2->next != NULL)
			alp2 = alp2->next;
		alp2->next = alp;
	}

	/* keep count */
	(*lstatp->countp) += alp->nelem;

	return (CFGA_OK);
}

/*
 * Check if a plugin version is within requested limits.
 */
static int
compat_plugin(vers_req_t *reqp, int plugin_vers)
{

	if (!VALID_HSL_VERS(reqp->v_min) || !VALID_HSL_VERS(reqp->v_max) ||
	    !VALID_HSL_VERS(plugin_vers)) {
		return (0);
	}

	if (plugin_vers < reqp->v_min || plugin_vers > reqp->v_max) {
		return (0);
	}


	return (1);
}

/*
 * find_arg_type - determine if an argument is an ap_id or an ap_type.
 * Adapted from cfgadm.c
 */
static cfga_ap_types_t
find_arg_type(const char *ap_id)
{
	struct stat sbuf;
	cfga_ap_types_t type = UNKNOWN_AP;
	char *mkr = NULL;
	size_t len;
	int size_ap = 0, size_mkr = 0, digit = 0, i = 0;
	char *cp, path[MAXPATHLEN], ap_base[MAXPATHLEN];


	/*
	 * sanity checks
	 */
	if (ap_id == NULL || *ap_id == '\0') {

		return (UNKNOWN_AP);
	}

	/*
	 * Extract the base component
	 */
	if ((cp = GET_DYN(ap_id)) != NULL) {
		len = cp - ap_id;
	} else {
		len = strlen(ap_id);
	}

	if (len >= sizeof (ap_base)) {
		return (UNKNOWN_AP);
	}

	/* Copy only the first "len" chars */
	(void) strncpy(ap_base, ap_id, len);
	ap_base[len] = '\0';

	/*
	 * If it starts with a slash and is stat-able its a physical.
	 */
	if (*ap_base == '/' && stat(ap_base, &sbuf) == 0) {
		return (PHYSICAL_AP);
	}

	/*
	 * Is this a symlink in CFGA_DEV_DIR ?
	 */
	(void) snprintf(path, sizeof (path), "%s%s",
	    CFGA_DEV_DIR SLASH, ap_base);

	if (lstat(path, &sbuf) == 0 && S_ISLNK(sbuf.st_mode) &&
	    stat(path, &sbuf) == 0) {
		return (LOGICAL_LINK_AP);
	}

	/*
	 * Check for ":" which is always present in an ap_id
	 * but not in an ap_type.
	 * we need to check that the characters right before the : are digits
	 * since an ap_id is of the form <name><instance>:<specific ap name>
	 */
	if ((mkr = strchr(ap_base, ':')) == NULL)  {
		type = AP_TYPE;
	} else {
		size_ap = strlen(ap_base);
		size_mkr = strlen(mkr);
		mkr = ap_base;

		digit = 0;
		for (i = size_ap - size_mkr - 1;  i > 0; i--) {
			if ((int)isdigit(mkr[i])) {
				digit++;
				break;
			}
		}
		if (digit == 0) {
			type = AP_TYPE;
		} else {
			type = LOGICAL_DRV_AP;
		}
	}

	return (type);
}

/*ARGSUSED*/
static cfga_err_t
null_get_cond(lib_loc_t *liblocp, cfga_cond_t *condp, char **errstring)
{
	return (CFGA_OK);
}

static cfga_err_t
get_cond_v1(lib_loc_t *liblocp, cfga_cond_t *condp, char **errstring)
{
	plugin_lib_t *libp;
	cfga_stat_data_t sdbuf;
	cfga_err_t rc;


	libp = liblocp->libp;
	if (libp->plugin_vers != CFGA_HSL_V1) {
		return (CFGA_LIB_ERROR);
	}

	errno = 0;
	if ((rc = (*liblocp->libp->cfga_stat_p)(
	    liblocp->ap_physical, &sdbuf, NULL, errstring))
	    == CFGA_OK) {
		*condp = sdbuf.ap_cond;
	} else {
		*condp = CFGA_COND_UNKNOWN;
	}

	return (rc);
}

static cfga_err_t
get_cond_v2(lib_loc_t *liblocp, cfga_cond_t *condp, char **errstring)
{
	int nelem;
	plugin_lib_t *libp;
	cfga_list_data_t *ldbufp;
	cfga_err_t rc;


	libp = liblocp->libp;
	if (libp->plugin_vers != CFGA_HSL_V2) {
		return (CFGA_LIB_ERROR);
	}

	errno = 0;
	nelem = 0;
	ldbufp = NULL;
	if ((rc = (*liblocp->libp->cfga_list_ext_p)(
	    liblocp->ap_physical, &ldbufp, &nelem, NULL, NULL,
	    errstring, 0)) == CFGA_OK) {
		assert(nelem == 1 && ldbufp != NULL);

		*condp = ldbufp->ap_cond;
		S_FREE(ldbufp);
	} else {
		*condp = CFGA_COND_UNKNOWN;
	}

	return (rc);
}

/* mask represents the flags accepted */
static cfga_err_t
check_flags(cfga_flags_t flags, cfga_flags_t mask, char **errstring)
{
	if ((flags & ~mask) != 0) {
		config_err(0, INVALID_ARGS, errstring);
		return (CFGA_ERROR);
	} else {
		return (CFGA_OK);
	}
}

static cfga_err_t
check_apids(int num_ap_ids, char *const *ap_ids, char **errstring)
{
	if (num_ap_ids <= 0 || ap_ids == NULL) {
		config_err(0, INVALID_ARGS, errstring);
		return (CFGA_ERROR);
	} else {
		return (CFGA_OK);
	}
}

/*
 * Returns the class or the empty string if attacment point has
 * no class.
 */
static char *
get_class(di_minor_t minor)
{
	char *cp, c;
	size_t len;


	if (minor == DI_MINOR_NIL) {
		return (NULL);
	}

	cp = di_minor_nodetype(minor);
	if (cp == NULL) {
		return (NULL);
	}

	len = strlen(DDI_NT_ATTACHMENT_POINT);
	if (strncmp(cp, DDI_NT_ATTACHMENT_POINT, len)) {
		return (NULL);
	}

	cp += len;

	c = *cp;
	if (c != '\0' && c != ':') {
		return (NULL);
	}

	if (c == ':') {
		cp++;
	}

	return (cp);

}

/*
 * Transform stat data to list data
 */
static void
stat_to_list(cfga_list_data_t *lp, cfga_stat_data_t *statp)
{

	(void) snprintf(lp->ap_log_id, sizeof (lp->ap_log_id), "%s",
	    statp->ap_log_id);

	(void) snprintf(lp->ap_phys_id, sizeof (lp->ap_phys_id), "%s",
	    statp->ap_phys_id);

	(void) snprintf(lp->ap_class, sizeof (lp->ap_class), "%s",
	    CFGA_NO_CLASS);

	lp->ap_r_state = statp->ap_r_state;
	lp->ap_o_state = statp->ap_o_state;
	lp->ap_cond = statp->ap_cond;
	lp->ap_busy = statp->ap_busy;
	lp->ap_status_time = statp->ap_status_time;

	(void) snprintf(lp->ap_info, sizeof (lp->ap_info), "%s",
	    statp->ap_info);
	(void) snprintf(lp->ap_type, sizeof (lp->ap_type), "%s",
	    statp->ap_type);
}

static void
lstat_free(list_stat_t *lstatp)
{
	stat_data_list_t *slp, *slp2;
	array_list_t *ap, *ap2;

	slp = lstatp->sdl;
	while (slp != NULL) {
		slp2 = slp->next;
		S_FREE(slp);
		slp = slp2;
	}

	lstatp->sdl = NULL;

	ap = lstatp->al;
	while (ap != NULL) {
		ap2 = ap->next;
		S_FREE(ap->array);
		S_FREE(ap);
		ap = ap2;
	}

	lstatp->al = NULL;
}

static cfga_err_t
split_apid(char *ap_id, char **dyncompp, char **errstring)
{
	char *cp;

	*dyncompp = NULL;

	if (ap_id == NULL) {
		return (CFGA_ERROR);
	}

	if ((cp = strstr(ap_id, CFGA_DYN_SEP)) == NULL) {
		return (CFGA_OK);
	}

	*cp = '\0';
	cp += strlen(CFGA_DYN_SEP);
	if ((*dyncompp = config_calloc_check(1, strlen(cp) + 1,
	    errstring)) == NULL) {
		return (CFGA_LIB_ERROR);
	}
	(void) strcpy(*dyncompp, cp);

	return (CFGA_OK);
}

static void
append_dyn(char *buf, const char *dyncomp, size_t blen)
{
	if (dyncomp != NULL) {
		char *cp = buf + strlen(buf);
		size_t len = blen - strlen(buf);

		(void) snprintf(cp, len, "%s%s", CFGA_DYN_SEP,
		    dyncomp);
	}
}

/*
 * Default implementation of cfga_ap_id_cmp. Works for most cases
 * except for long hex number sequences like world-wide-name.
 *
 * This function compares the ap's in a generic way.  It does so by
 * determining the place of difference between the 2 aps.  If the first
 * difference is a digit, it attempts to obtain the numbers and compare them
 * Otherwise it just compares the aps as strings
 */
static int
default_ap_id_cmp(const char *ap_id1, const char *ap_id2)
{
	int i = 0;

	/*
	 * Search for first different char
	 */
	while (ap_id1[i] == ap_id2[i] && ap_id1[i] != '\0')
		i++;

	/*
	 * If one of the char is a digit, back up to where the
	 * number started, compare the number.
	 */
	if (isdigit(ap_id1[i]) || isdigit(ap_id2[i])) {
		while ((i > 0) && isdigit(ap_id1[i - 1]))
			i--;

		if (isdigit(ap_id1[i]) && isdigit(ap_id2[i]))
			return (atoi(ap_id1 + i) - atoi(ap_id2 + i));
	}

	/* One of them isn't a number, compare the char */
	return (ap_id1[i] - ap_id2[i]);
}

static void
hold_lib(plugin_lib_t *libp)
{
	assert(libp->refcnt >= 0);
	(void) mutex_lock(&libp->lock);
	libp->refcnt++;
	(void) mutex_unlock(&libp->lock);
}

static void
rele_lib(plugin_lib_t *libp)
{
	assert(libp->refcnt > 0);
	(void) mutex_lock(&libp->lock);
	libp->refcnt--;
	(void) mutex_unlock(&libp->lock);
}
