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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <thread.h>
#include <pthread.h>
#include <synch.h>
#include <unistd.h>
#include <stropts.h>
#include <fcntl.h>
#include <note.h>
#include <errno.h>
#include <ctype.h>
#include <libintl.h>
#include <libscf.h>
#include <pool.h>
#include <signal.h>

#include <sys/pool.h>
#include <sys/priocntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include "pool_internal.h"
#include "pool_impl.h"

/*
 * libpool Interface Routines
 *
 * pool.c implements (most of) the external interface to libpool
 * users. Some of the interface is implemented in pool_internal.c for
 * reasons of internal code organisation.  The core requirements for
 * pool.c are:
 *
 * Data Abstraction
 *
 * The abstraction of the actual datastore so that no details of the
 * underlying data representation mechanism are revealed to users of
 * the library. For instance, the fact that we use the kernel or files
 * to store our configurations is completely abstracted via the
 * various libpool APIs.
 *
 * External Interaction
 *
 * libpool users manipulate configuration components via the API
 * defined in pool.h. Most functions in this file act as interceptors,
 * validating parameters before redirecting the request into a
 * specific datastore implementation for the actual work to be done.
 *
 * These main sets of requirements have driven the design so that it
 * is possible to replace the entire datastore type without having to
 * modify the external (or internal provider) APIs. It is possible to
 * modify the storage technology used by libpool by implementing a new
 * set of datastore provider operations. Simply modify the
 * pool_conf_open() routine to establish a new datastore as the
 * provider for a configuration.
 *
 * The key components in a libpool configuration are :
 * pool_conf_t - This represents a complete configuration instance
 * pool_t - A pool inside a configuration
 * pool_resource_t - A resource inside a configuration
 * pool_component_t - A component of a resource
 *
 */

/*
 * Used to control transfer setup.
 */
#define	XFER_FAIL	PO_FAIL
#define	XFER_SUCCESS	PO_SUCCESS
#define	XFER_CONTINUE	1

#define	SMF_SVC_INSTANCE	"svc:/system/pools:default"
#define	E_ERROR		1		/* Exit status for error */

#ifndef	TEXT_DOMAIN
#define	TEXT_DOMAIN	"SYS_TEST"
#endif	/* TEXT_DOMAIN */

const char pool_info_location[] =  "/dev/pool";

/*
 * Static data
 */
static const char static_location[] = "/etc/pooladm.conf";
static const char dynamic_location[] =  "/dev/poolctl";
static thread_key_t	errkey = THR_ONCE_KEY;

/*
 * libpool error code
 */
static int pool_errval = POE_OK;

/*
 * libpool version
 */
static uint_t pool_workver = POOL_VER_CURRENT;

static const char *data_type_tags[] = {
	"uint",
	"int",
	"float",
	"boolean",
	"string"
};

/*
 * static functions
 */
static int pool_elem_remove(pool_elem_t *);
static int is_valid_prop_name(const char *);
static int prop_buf_build_cb(pool_conf_t *, pool_elem_t *, const char *,
    pool_value_t *, void *);
static char *pool_base_info(const pool_elem_t *, char_buf_t *, int);
static int choose_components(pool_resource_t *, pool_resource_t *, uint64_t);
static int pool_conf_check(const pool_conf_t *);
static void free_value_list(int, pool_value_t **);
static int setup_transfer(pool_conf_t *, pool_resource_t *, pool_resource_t *,
    uint64_t, uint64_t *, uint64_t *);

/*
 * Return the "static" location string for libpool.
 */
const char *
pool_static_location(void)
{
	return (static_location);
}

/*
 * Return the "dynamic" location string for libpool.
 */
const char *
pool_dynamic_location(void)
{
	return (dynamic_location);
}

/*
 * Return the status for a configuration. If the configuration has
 * been successfully opened, then the status will be POF_VALID or
 * POF_DESTROY.  If the configuration failed to open properly or has
 * been closed or removed, then the status will be POF_INVALID.
 */
pool_conf_state_t
pool_conf_status(const pool_conf_t *conf)
{
	return (conf->pc_state);
}

/*
 * Bind idtype id to the pool name.
 */
int
pool_set_binding(const char *pool_name, idtype_t idtype, id_t id)
{
	pool_conf_t *conf;
	int result;

	if ((conf = pool_conf_alloc()) == NULL)
		return (PO_FAIL);

	if (pool_conf_open(conf, pool_dynamic_location(), PO_RDONLY) < 0) {
		pool_conf_free(conf);
		pool_seterror(POE_INVALID_CONF);
		return (PO_FAIL);
	}

	result = conf->pc_prov->pc_set_binding(conf, pool_name, idtype, id);

	(void) pool_conf_close(conf);
	pool_conf_free(conf);
	return (result);
}

/*
 * pool_get_resource_binding() returns the binding for a pid to the supplied
 * type of resource. If a binding cannot be determined, NULL is returned.
 */
char *
pool_get_resource_binding(const char *sz_type, pid_t pid)
{
	pool_conf_t *conf;
	char *result;
	pool_resource_elem_class_t type;

	if ((type = pool_resource_elem_class_from_string(sz_type)) ==
	    PREC_INVALID) {
		pool_seterror(POE_BADPARAM);
		return (NULL);
	}

	if ((conf = pool_conf_alloc()) == NULL)
		return (NULL);

	if (pool_conf_open(conf, pool_dynamic_location(), PO_RDONLY)
	    != PO_SUCCESS) {
		pool_seterror(POE_INVALID_CONF);
		pool_conf_free(conf);
		return (NULL);
	}
	result = conf->pc_prov->pc_get_resource_binding(conf, type, pid);
	(void) pool_conf_close(conf);
	pool_conf_free(conf);
	return (result);
}

/*
 * pool_get_binding() returns the binding for a pid to a pool. If a
 * binding cannot be determined, NULL is returned.
 */
char *
pool_get_binding(pid_t pid)
{
	pool_conf_t *conf;
	char *result;

	if ((conf = pool_conf_alloc()) == NULL)
		return (NULL);

	if (pool_conf_open(conf, pool_dynamic_location(), PO_RDONLY)
	    != PO_SUCCESS) {
		pool_seterror(POE_INVALID_CONF);
		pool_conf_free(conf);
		return (NULL);
	}
	result = conf->pc_prov->pc_get_binding(conf, pid);
	(void) pool_conf_close(conf);
	pool_conf_free(conf);
	return (result);
}

/*ARGSUSED*/
int
prop_buf_build_cb(pool_conf_t *UNUSED, pool_elem_t *pe, const char *name,
    pool_value_t *pval, void *user)
{
	uint64_t u;
	int64_t i;
	uchar_t bool;
	const char *str;
	double d;
	char_buf_t *cb = (char_buf_t *)user;
	int type = pool_value_get_type(pval);

	/*
	 * Ignore "type" and "<type>.name" properties as these are not
	 * to be displayed by this function
	 */
	if (strcmp(name, c_type) == 0 ||
	    strcmp(property_name_minus_ns(pe, name), c_name) == 0)
		return (PO_SUCCESS);
	if (append_char_buf(cb, "\n%s\t%s\t%s ", cb->cb_tab_buf,
	    data_type_tags[type], name) == PO_FAIL)
		return (PO_FAIL);
	switch (type) {
	case POC_UINT:
		(void) pool_value_get_uint64(pval, &u);
		if (append_char_buf(cb, "%llu", (u_longlong_t)u) == PO_FAIL)
			return (PO_FAIL);
		break;
	case POC_INT:
		(void) pool_value_get_int64(pval, &i);
		if (append_char_buf(cb, "%lld", (longlong_t)i) == PO_FAIL)
			return (PO_FAIL);
		break;
	case POC_STRING:
		(void) pool_value_get_string(pval, &str);
		if (append_char_buf(cb, "%s", str) == PO_FAIL)
			return (PO_FAIL);
		break;
	case POC_BOOL:
		(void) pool_value_get_bool(pval, &bool);
		if (bool == 0) {
			if (append_char_buf(cb, "%s", "false") == PO_FAIL)
				return (PO_FAIL);
		} else {
			if (append_char_buf(cb, "%s", "true") == PO_FAIL)
				return (PO_FAIL);
		}
		break;
	case POC_DOUBLE:
		(void) pool_value_get_double(pval, &d);
		if (append_char_buf(cb, "%g", d) == PO_FAIL)
			return (PO_FAIL);
		break;
	case POC_INVAL: /* Do nothing */
		break;
	default:
		return (PO_FAIL);
	}
	return (PO_SUCCESS);
}

/*
 * Return a buffer which describes the element
 * pe is a pointer to the element
 * deep is PO_TRUE/PO_FALSE to indicate whether children should be included
 */
char *
pool_base_info(const pool_elem_t *pe, char_buf_t *cb, int deep)
{
	const char *sres;
	uint_t i;
	uint_t nelem;

	pool_value_t val = POOL_VALUE_INITIALIZER;
	pool_resource_t **rs;
	pool_elem_t *elem;
	pool_conf_t *conf = TO_CONF(pe);

	if (cb == NULL) {
		char *ret = NULL;

		if ((cb = alloc_char_buf(CB_DEFAULT_LEN)) == NULL)
			return (NULL);

		/*
		 * Populate the buffer with element details
		 */
		(void) pool_base_info(pe, cb, deep);
		if (cb->cb_buf)
			ret = strdup(cb->cb_buf);
		free_char_buf(cb);
		return (ret);
	}

	if (append_char_buf(cb, "\n%s%s", cb->cb_tab_buf,
	    pool_elem_class_string(pe)) == PO_FAIL) {
		return (NULL);
	}

	if (pool_get_ns_property(pe, c_name, &val) == POC_STRING) {
		(void) pool_value_get_string(&val, &sres);
		if (append_char_buf(cb, " %s", sres) == PO_FAIL) {
			return (NULL);
		}
	}

	/*
	 * Add in some details about the element
	 */
	if (pool_walk_properties(conf, (pool_elem_t *)pe, cb,
	    prop_buf_build_cb) == PO_FAIL) {
		(void) append_char_buf(cb, "\n%s%s\n", cb->cb_tab_buf,
		    "Cannot access the properties of this element.");
		return (NULL);
	}
	if (append_char_buf(cb, "%s", "\n") == PO_FAIL)
		return (NULL);

	if (pe->pe_class == PEC_POOL) {
		/*
		 * A shallow display of a pool only lists the resources by name
		 */

		if ((rs = pool_query_pool_resources(conf, pool_elem_pool(pe),
		    &nelem, NULL)) == NULL) {
			return (NULL);
		}

		for (i = 0; i < nelem; i++) {
			const char *str;

			elem = TO_ELEM(rs[i]);

			if (append_char_buf(cb, "\t%s%s", cb->cb_tab_buf,
			    pool_elem_class_string(elem)) == PO_FAIL) {
				free(rs);
				return (NULL);
			}

			if (pool_get_ns_property(elem, c_name, &val) !=
			    POC_STRING) {
				free(rs);
				pool_seterror(POE_INVALID_CONF);
				return (NULL);
			}
			(void) pool_value_get_string(&val, &str);
			if (append_char_buf(cb, "\t%s\n", str) == PO_FAIL) {
				free(rs);
				return (NULL);
			}
		}
		free(rs);
	}
	if (deep == PO_TRUE) {
		pool_t **ps;
		pool_component_t **cs;

		if (strlcat(cb->cb_tab_buf, "\t", CB_TAB_BUF_SIZE)
		    >= CB_TAB_BUF_SIZE) {
			pool_seterror(POE_SYSTEM);
			return (NULL);
		}
		switch (pe->pe_class) {
		case PEC_SYSTEM:
			if ((ps = pool_query_pools(conf, &nelem, NULL)) !=
			    NULL) { /* process the pools */
				for (i = 0; i < nelem; i++) {
					elem = TO_ELEM(ps[i]);
					if (pool_base_info(elem, cb,
					    PO_FALSE) == NULL) {
						free(ps);
						return (NULL);
					}
				}
				free(ps);
			}
			if ((rs = pool_query_resources(conf, &nelem, NULL)) !=
			    NULL) {
				for (i = 0; i < nelem; i++) {
					elem = TO_ELEM(rs[i]);
					if (pool_base_info(elem, cb,
					    PO_TRUE) == NULL) {
						free(rs);
						return (NULL);
					}
				}
				free(rs);
			}
			break;
		case PEC_POOL:
			if ((rs = pool_query_pool_resources(conf,
			    pool_elem_pool(pe), &nelem, NULL)) == NULL)
				return (NULL);
			for (i = 0; i < nelem; i++) {
				elem = TO_ELEM(rs[i]);
				if (pool_base_info(elem, cb, PO_TRUE) == NULL) {
					free(rs);
					return (NULL);
				}
			}
			free(rs);
			break;
		case PEC_RES_COMP:
			if ((cs = pool_query_resource_components(conf,
			    pool_elem_res(pe), &nelem, NULL)) != NULL) {
				for (i = 0; i < nelem; i++) {
					elem = TO_ELEM(cs[i]);
					if (pool_base_info(elem, cb,
					    PO_FALSE) == NULL) {
						free(cs);
						return (NULL);
					}
				}
				free(cs);
			}
			break;
		case PEC_RES_AGG:
		case PEC_COMP:
			break;
		default:
			/*NOTREACHED*/
			break;
		}
		if (cb->cb_tab_buf[0] != 0)
			cb->cb_tab_buf[strlen(cb->cb_tab_buf) - 1] = 0;
	}
	return (cb->cb_buf);
}

/*
 * Returns	The information on the specified pool or NULL.
 *
 * Errors	If the status of the conf is INVALID or the supplied
 *		value of deep is illegal, POE_BADPARAM.
 *
 * The caller is responsible for free(3c)ing the string returned.
 */
char *
pool_info(const pool_conf_t *conf, const pool_t *pool, int deep)
{
	pool_elem_t *pe;

	pe = TO_ELEM(pool);

	if (TO_CONF(pe) != conf) {
		pool_seterror(POE_BADPARAM);
		return (NULL);
	}

	if (pool_conf_status(conf) == POF_INVALID || (deep & ~1)) {
		pool_seterror(POE_BADPARAM);
		return (NULL);
	}

	return (pool_base_info(pe, NULL, deep));
}

/*
 * Returns	The information on the specified resource or NULL.
 *
 * Errors	If the status of the conf is INVALID or the supplied
 *		value of deep is illegal, POE_BADPARAM.
 *
 * The caller is responsible for free(3c)ing the string returned.
 */
char *
pool_resource_info(const pool_conf_t *conf, const pool_resource_t *res,
    int deep)
{
	pool_elem_t *pe;

	pe = TO_ELEM(res);

	if (TO_CONF(pe) != conf) {
		pool_seterror(POE_BADPARAM);
		return (NULL);
	}

	if (pool_conf_status(conf) == POF_INVALID || (deep & ~1)) {
		pool_seterror(POE_BADPARAM);
		return (NULL);
	}

	return (pool_base_info(pe, NULL, deep));
}

/*
 * Returns	The information on the specified component or NULL.
 *
 * Errors	If the status of the conf is INVALID or the supplied
 *		value of deep is illegal, POE_BADPARAM.
 *
 * The caller is responsible for free(3c)ing the string returned.
 */
char *
pool_component_info(const pool_conf_t *conf, const pool_component_t *comp,
    int deep)
{
	pool_elem_t *pe;

	pe = TO_ELEM(comp);

	if (TO_CONF(pe) != conf) {
		pool_seterror(POE_BADPARAM);
		return (NULL);
	}

	if (pool_conf_status(conf) == POF_INVALID || (deep & ~1)) {
		pool_seterror(POE_BADPARAM);
		return (NULL);
	}

	return (pool_base_info(pe, NULL, deep));
}

/*
 * Returns	The information on the specified conf or NULL.
 *
 * Errors	If the status of the conf is INVALID or the supplied
 *		value of deep is illegal, POE_BADPARAM.
 *
 * The caller is responsible for free(3c)ing the string returned.
 */
char *
pool_conf_info(const pool_conf_t *conf, int deep)
{
	pool_elem_t *pe;

	if (pool_conf_status(conf) == POF_INVALID || (deep & ~1)) {
		pool_seterror(POE_BADPARAM);
		return (NULL);
	}
	if ((pe = pool_conf_to_elem(conf)) == NULL) {
		pool_seterror(POE_BADPARAM);
		return (NULL);
	}
	return (pool_base_info(pe, NULL, deep));
}


/*
 * Set the thread specific error value.
 */
void
pool_seterror(int errval)
{
	if (thr_main()) {
		pool_errval = errval;
		return;
	}
	(void) thr_keycreate_once(&errkey, 0);
	(void) thr_setspecific(errkey, (void *)(intptr_t)errval);
}

/*
 * Return the current value of the error code.
 * Returns: int error code
 */
int
pool_error(void)
{
	if (thr_main())
		return (pool_errval);
	if (errkey == THR_ONCE_KEY)
		return (POE_OK);
	return ((uintptr_t)pthread_getspecific(errkey));
}

/*
 * Return the text represenation for the current value of the error code.
 * Returns: const char * error string
 */
const char *
pool_strerror(int error)
{
	char *str;

	switch (error) {
	case POE_OK:
		str = dgettext(TEXT_DOMAIN, "Operation successful");
		break;
	case POE_BAD_PROP_TYPE:
		str = dgettext(TEXT_DOMAIN,
		    "Attempted to retrieve the wrong property type");
		break;
	case POE_INVALID_CONF:
		str = dgettext(TEXT_DOMAIN, "Invalid configuration");
		break;
	case POE_NOTSUP:
		str = dgettext(TEXT_DOMAIN, "Operation is not supported");
		break;
	case POE_INVALID_SEARCH:
		str = dgettext(TEXT_DOMAIN, "Invalid search");
		break;
	case POE_BADPARAM:
		str = dgettext(TEXT_DOMAIN, "Bad parameter supplied");
		break;
	case POE_PUTPROP:
		str = dgettext(TEXT_DOMAIN, "Error putting property");
		break;
	case POE_DATASTORE:
		str = dgettext(TEXT_DOMAIN, "Pools repository error");
		break;
	case POE_SYSTEM:
		str = dgettext(TEXT_DOMAIN, "System error");
		break;
	case POE_ACCESS:
		str = dgettext(TEXT_DOMAIN, "Permission denied");
		break;
	default:
		errno = ESRCH;
		str = NULL;
	}
	return (str);
}

int
pool_get_status(int *state)
{
	int fd;
	pool_status_t status;

	if ((fd = open(pool_info_location, O_RDONLY)) < 0) {
		pool_seterror(POE_SYSTEM);
		return (PO_FAIL);
	}
	if (ioctl(fd, POOL_STATUSQ, &status) < 0) {
		(void) close(fd);
		pool_seterror(POE_SYSTEM);
		return (PO_FAIL);
	}
	(void) close(fd);

	*state = status.ps_io_state;

	return (PO_SUCCESS);
}

int
pool_set_status(int state)
{
	int old_state;

	if (pool_get_status(&old_state) != PO_SUCCESS) {
		pool_seterror(POE_SYSTEM);
		return (PO_FAIL);
	}

	if (old_state != state) {
		int fd;
		pool_status_t status;
		char *fmri;

		/*
		 * Changing the status of pools is performed by enabling
		 * or disabling the pools service instance. If this
		 * function has not been invoked by startd then we simply
		 * enable/disable the service and return success.
		 *
		 * There is no way to specify that state changes must be
		 * synchronous using the library API as yet, so we use
		 * the -s option provided by svcadm.
		 */
		fmri = getenv("SMF_FMRI");
		if (fmri == NULL) {
			FILE *p;
			char *cmd;

			if (state != 0) {
				cmd = "/usr/sbin/svcadm enable -s " \
				    SMF_SVC_INSTANCE;
			} else {
				cmd = "/usr/sbin/svcadm disable -s " \
				    SMF_SVC_INSTANCE;
			}
			if ((p = popen(cmd, "wF")) == NULL || pclose(p) != 0) {
				pool_seterror(POE_SYSTEM);
				return (PO_FAIL);
			}
			return (PO_SUCCESS);
		}

		if ((fd = open(pool_dynamic_location(), O_RDWR | O_EXCL)) < 0) {
			pool_seterror(POE_SYSTEM);
			return (PO_FAIL);
		}

		/*
		 * If pools are being enabled/disabled by another smf service,
		 * enable the smf service instance.  This must be done
		 * asynchronously as one service cannot synchronously
		 * enable/disable another.
		 */
		if (strcmp(fmri, SMF_SVC_INSTANCE) != 0) {
			int res;

			if (state != 0)
				res = smf_enable_instance(SMF_SVC_INSTANCE, 0);
			else
				res = smf_disable_instance(SMF_SVC_INSTANCE, 0);

			if (res != 0) {
				(void) close(fd);
				pool_seterror(POE_SYSTEM);
				return (PO_FAIL);
			}
		}
		status.ps_io_state = state;

		if (ioctl(fd, POOL_STATUS, &status) < 0) {
			(void) close(fd);
			pool_seterror(POE_SYSTEM);
			return (PO_FAIL);
		}

		(void) close(fd);

	}
	return (PO_SUCCESS);
}

/*
 * General Data Provider Independent Access Methods
 */

/*
 * Property manipulation code.
 *
 * The pool_(get|rm|set)_property() functions consult the plugins before
 * looking at the actual configuration. This allows plugins to provide
 * "virtual" properties that may not exist in the configuration file per se,
 * but behave like regular properties. This also allows plugins to reserve
 * certain properties as read-only, non-removable, etc.
 *
 * A negative value returned from the plugin denotes error, 0 means that the
 * property request should be forwarded to the backend, and 1 means the request
 * was satisfied by the plugin and should not be processed further.
 *
 * The (get|rm|set)_property() functions bypass the plugin layer completely,
 * and hence should not be generally used.
 */

/*
 * Return true if the string passed in matches the pattern
 * [A-Za-z][A-Za-z0-9,._-]*
 */
int
is_valid_name(const char *name)
{
	int i;
	char c;

	if (name == NULL)
		return (PO_FALSE);
	if (!isalpha(name[0]))
		return (PO_FALSE);
	for (i = 1; (c = name[i]) != '\0'; i++) {
		if (!isalnum(c) && c != ',' && c != '.' && c != '_' && c != '-')
			return (PO_FALSE);
	}
	return (PO_TRUE);
}

/*
 * Return true if the string passed in matches the pattern
 * [A-Za-z_][A-Za-z0-9,._-]*
 * A property name starting with a '_' is an "invisible" property that does not
 * show up in a property walk.
 */
int
is_valid_prop_name(const char *prop_name)
{
	int i;
	char c;

	if (prop_name == NULL)
		return (PO_FALSE);
	if (!isalpha(prop_name[0]) && prop_name[0] != '_')
		return (PO_FALSE);
	for (i = 1; (c = prop_name[i]) != '\0'; i++) {
		if (!isalnum(c) && c != ',' && c != '.' && c != '_' && c != '-')
			return (PO_FALSE);
	}
	return (PO_TRUE);
}

/*
 * Return the specified property value.
 *
 * POC_INVAL is returned if an error is detected and the error code is updated
 * to indicate the cause of the error.
 */
pool_value_class_t
pool_get_property(const pool_conf_t *conf, const pool_elem_t *pe,
    const char *name, pool_value_t *val)
{
	const pool_prop_t *prop_info;

	if (pool_conf_status(conf) == POF_INVALID) {
		pool_seterror(POE_BADPARAM);
		return (POC_INVAL);
	}
	if (pool_value_set_name(val, name) != PO_SUCCESS) {
		return (POC_INVAL);
	}
	/*
	 * Check to see if this is a property we are managing. If it
	 * is and it has an interceptor installed for property
	 * retrieval, use it.
	 */
	if ((prop_info = provider_get_prop(pe, name)) != NULL &&
	    prop_info->pp_op.ppo_get_value != NULL) {
		if (prop_info->pp_op.ppo_get_value(pe, val) == PO_FAIL)
			return (POC_INVAL);
		else
			return (pool_value_get_type(val));
	}
	return (pe->pe_get_prop(pe, name, val));
}

/*
 * Return the specified property value with the namespace prepended.
 * e.g. If this function is used to get the property "name" on a pool, it will
 * attempt to retrieve "pool.name".
 *
 * POC_INVAL is returned if an error is detected and the error code is updated
 * to indicate the cause of the error.
 */
pool_value_class_t
pool_get_ns_property(const pool_elem_t *pe, const char *name, pool_value_t *val)
{
	int ret;
	char_buf_t *cb;

	if ((cb = alloc_char_buf(CB_DEFAULT_LEN)) == NULL)
		return (POC_INVAL);
	if (set_char_buf(cb, "%s.%s", pool_elem_class_string(pe), name) ==
	    PO_FAIL) {
		free_char_buf(cb);
		return (POC_INVAL);
	}
	ret = pool_get_property(TO_CONF(pe), pe, cb->cb_buf, val);
	free_char_buf(cb);
	return (ret);
}

/*
 * Update the specified property value.
 *
 * PO_FAIL is returned if an error is detected and the error code is updated
 * to indicate the cause of the error.
 */
int
pool_put_property(pool_conf_t *conf, pool_elem_t *pe, const char *name,
    const pool_value_t *val)
{
	const pool_prop_t *prop_info;

	if (pool_conf_check(conf) != PO_SUCCESS)
		return (PO_FAIL);

	if (TO_CONF(pe) != conf) {
		pool_seterror(POE_BADPARAM);
		return (PO_FAIL);
	}

	/* Don't allow (re)setting of the "temporary" property */
	if (!is_valid_prop_name(name) || strstr(name, ".temporary") != NULL) {
		pool_seterror(POE_BADPARAM);
		return (PO_FAIL);
	}

	/* Don't allow rename of temporary pools/resources */
	if (strstr(name, ".name") != NULL && elem_is_tmp(pe)) {
		boolean_t rename = B_TRUE;
		pool_value_t *pv = pool_value_alloc();

		if (pe->pe_get_prop(pe, name, pv) != POC_INVAL) {
			const char *s1 = NULL;
			const char *s2 = NULL;

			(void) pool_value_get_string(pv, &s1);
			(void) pool_value_get_string(val, &s2);
			if (s1 != NULL && s2 != NULL && strcmp(s1, s2) == 0)
				rename = B_FALSE;
		}
		pool_value_free(pv);

		if (rename) {
			pool_seterror(POE_BADPARAM);
			return (PO_FAIL);
		}
	}

	/*
	 * Check to see if this is a property we are managing. If it is,
	 * ensure that we are happy with what the user is doing.
	 */
	if ((prop_info = provider_get_prop(pe, name)) != NULL) {
		if (prop_is_readonly(prop_info) == PO_TRUE) {
			pool_seterror(POE_BADPARAM);
			return (PO_FAIL);
		}
		if (prop_info->pp_op.ppo_set_value &&
		    prop_info->pp_op.ppo_set_value(pe, val) == PO_FAIL)
			return (PO_FAIL);
	}

	return (pe->pe_put_prop(pe, name, val));
}

/*
 * Set temporary property to flag as a temporary element.
 *
 * PO_FAIL is returned if an error is detected and the error code is updated
 * to indicate the cause of the error.
 */
int
pool_set_temporary(pool_conf_t *conf, pool_elem_t *pe)
{
	int res;
	char name[128];
	pool_value_t *val;

	if (pool_conf_check(conf) != PO_SUCCESS)
		return (PO_FAIL);

	if (TO_CONF(pe) != conf) {
		pool_seterror(POE_BADPARAM);
		return (PO_FAIL);
	}

	/* create property name based on element type */
	if (snprintf(name, sizeof (name), "%s.temporary",
	    pool_elem_class_string(pe)) > sizeof (name)) {
		pool_seterror(POE_SYSTEM);
		return (PO_FAIL);
	}

	if ((val = pool_value_alloc()) == NULL)
		return (PO_FAIL);

	pool_value_set_bool(val, (uchar_t)1);

	res = pe->pe_put_prop(pe, name, val);

	pool_value_free(val);

	return (res);
}

/*
 * Update the specified property value with the namespace prepended.
 * e.g. If this function is used to update the property "name" on a pool, it
 * will attempt to update "pool.name".
 *
 * PO_FAIL is returned if an error is detected and the error code is updated
 * to indicate the cause of the error.
 */
int
pool_put_ns_property(pool_elem_t *pe, const char *name,
    const pool_value_t *val)
{
	char_buf_t *cb;
	int ret;

	if ((cb = alloc_char_buf(CB_DEFAULT_LEN)) == NULL)
		return (PO_FAIL);
	if (set_char_buf(cb, "%s.%s", pool_elem_class_string(pe), name) ==
	    PO_FAIL) {
		free_char_buf(cb);
		return (PO_FAIL);
	}
	ret = pool_put_property(TO_CONF(pe), pe, cb->cb_buf, val);
	free_char_buf(cb);
	return (ret);
}

/*
 * Update the specified property value. Do not use the property
 * protection mechanism. This function should only be used for cases
 * where the library must bypass the normal property protection
 * mechanism. The only known use is to update properties in the static
 * configuration when performing a commit.
 *
 * PO_FAIL is returned if an error is detected and the error code is
 * updated to indicate the cause of the error.
 */
int
pool_put_any_property(pool_elem_t *pe, const char *name,
    const pool_value_t *val)
{
	if (!is_valid_prop_name(name)) {
		pool_seterror(POE_BADPARAM);
		return (PO_FAIL);
	}

	return (pe->pe_put_prop(pe, name, val));
}

/*
 * Update the specified property value with the namespace prepended.
 * e.g. If this function is used to update the property "name" on a pool, it
 * will attempt to update "pool.name".
 *
 * PO_FAIL is returned if an error is detected and the error code is updated
 * to indicate the cause of the error.
 */
int
pool_put_any_ns_property(pool_elem_t *pe, const char *name,
    const pool_value_t *val)
{
	char_buf_t *cb;
	int ret;

	if ((cb = alloc_char_buf(CB_DEFAULT_LEN)) == NULL)
		return (PO_FAIL);
	if (set_char_buf(cb, "%s.%s", pool_elem_class_string(pe), name) ==
	    PO_FAIL) {
		free_char_buf(cb);
		return (PO_FAIL);
	}
	ret = pool_put_any_property(pe, cb->cb_buf, val);
	free_char_buf(cb);
	return (ret);
}

/*
 * Remove the specified property value. Note that some properties are
 * mandatory and thus failure to remove these properties is inevitable.
 * PO_FAIL is returned if an error is detected and the error code is updated
 * to indicate the cause of the error.
 */
int
pool_rm_property(pool_conf_t *conf, pool_elem_t *pe, const char *name)
{
	const pool_prop_t *prop_info;

	if (pool_conf_check(conf) != PO_SUCCESS)
		return (PO_FAIL);

	if (TO_CONF(pe) != conf) {
		pool_seterror(POE_BADPARAM);
		return (PO_FAIL);
	}

	/* Don't allow removal of the "temporary" property */
	if (strstr(name, ".temporary") != NULL) {
		pool_seterror(POE_BADPARAM);
		return (PO_FAIL);
	}

	/*
	 * Check to see if this is a property we are managing. If it is,
	 * ensure that we are happy with what the user is doing.
	 */
	if ((prop_info = provider_get_prop(pe, name)) != NULL) {
		if (prop_is_optional(prop_info) == PO_FALSE) {
			pool_seterror(POE_BADPARAM);
			return (PO_FAIL);
		}
	}
	return (pe->pe_rm_prop(pe, name));
}

/*
 * Check if the supplied name is a namespace protected property for the supplied
 * element, pe. If it is, return the prefix, otherwise just return NULL.
 */
const char *
is_ns_property(const pool_elem_t *pe, const char *name)
{
	const char *prefix;

	if ((prefix = pool_elem_class_string(pe)) != NULL) {
		if (strncmp(name, prefix, strlen(prefix)) == 0)
			return (prefix);
	}
	return (NULL);
}

/*
 * Check if the supplied name is a namespace protected property for the supplied
 * element, pe. If it is, return the property name with the namespace stripped,
 * otherwise just return the name.
 */
const char *
property_name_minus_ns(const pool_elem_t *pe, const char *name)
{
	const char *prefix;
	if ((prefix = is_ns_property(pe, name)) != NULL) {
		return (name + strlen(prefix) + 1);
	}
	return (name);
}

/*
 * Create an element to represent a pool and add it to the supplied
 * configuration.
 */
pool_t *
pool_create(pool_conf_t *conf, const char *name)
{
	pool_elem_t *pe;
	pool_value_t val = POOL_VALUE_INITIALIZER;
	const pool_prop_t *default_props;

	if (pool_conf_check(conf) != PO_SUCCESS)
		return (NULL);

	if (!is_valid_name(name) || pool_get_pool(conf, name) != NULL) {
		/*
		 * A pool with the same name exists. Reject.
		 */
		pool_seterror(POE_BADPARAM);
		return (NULL);
	}
	if ((pe = conf->pc_prov->pc_elem_create(conf, PEC_POOL, PREC_INVALID,
	    PCEC_INVALID)) == NULL) {
		pool_seterror(POE_INVALID_CONF);
		return (NULL);
	}
	if ((default_props = provider_get_props(pe)) != NULL) {
		int i;
		for (i = 0; default_props[i].pp_pname != NULL; i++) {
			if (prop_is_init(&default_props[i]) &&
			    (pool_put_any_property(pe,
			    default_props[i].pp_pname,
			    &default_props[i].pp_value) == PO_FAIL)) {
				(void) pool_destroy(conf, pool_elem_pool(pe));
				return (NULL);
			}
		}
	}
	if (pool_value_set_string(&val, name) != PO_SUCCESS) {
		(void) pool_destroy(conf, pool_elem_pool(pe));
		pool_seterror(POE_SYSTEM);
		return (NULL);
	}
	if (pool_put_property(conf, pe, "pool.name", &val) == PO_FAIL) {
		(void) pool_destroy(conf, pool_elem_pool(pe));
		pool_seterror(POE_PUTPROP);
		return (NULL);
	}

	/*
	 * If we are creating a temporary pool configuration, flag the pool.
	 */
	if (conf->pc_prov->pc_oflags & PO_TEMP) {
		if (pool_set_temporary(conf, pe) == PO_FAIL) {
			(void) pool_destroy(conf, pool_elem_pool(pe));
			return (NULL);
		}
	}

	return (pool_elem_pool(pe));
}

/*
 * Create an element to represent a res.
 */
pool_resource_t *
pool_resource_create(pool_conf_t *conf, const char *sz_type, const char *name)
{
	pool_elem_t *pe;
	pool_value_t val = POOL_VALUE_INITIALIZER;
	const pool_prop_t *default_props;
	pool_resource_t **resources;
	int is_default = 0;
	uint_t nelem;
	pool_elem_class_t elem_class;
	pool_resource_elem_class_t type;
	pool_value_t *props[] = { NULL, NULL };

	if (pool_conf_check(conf) != PO_SUCCESS)
		return (NULL);

	if ((type = pool_resource_elem_class_from_string(sz_type)) ==
	    PREC_INVALID) {
		pool_seterror(POE_BADPARAM);
		return (NULL);
	}

	if (strcmp(sz_type, "pset") != 0) {
		pool_seterror(POE_BADPARAM);
		return (NULL);
	}

	if (!is_valid_name(name) || pool_get_resource(conf, sz_type, name) !=
	    NULL) {
		/*
		 * Resources must be unique by name+type.
		 */
		pool_seterror(POE_BADPARAM);
		return (NULL);
	}

	props[0] = &val;

	if (pool_value_set_string(props[0], sz_type) != PO_SUCCESS ||
	    pool_value_set_name(props[0], c_type) != PO_SUCCESS) {
		return (NULL);
	}

	if ((resources = pool_query_resources(conf, &nelem, props)) == NULL) {
		/*
		 * This is the first representative of this type; when it's
		 * created it should be created with 'default' = 'true'.
		 */
		is_default = 1;
	} else {
		free(resources);
	}
	/*
	 * TODO: If Additional PEC_RES_COMP types are added to
	 * pool_impl.h, this would need to be extended.
	 */
	switch (type) {
	case PREC_PSET:
		elem_class = PEC_RES_COMP;
		break;
	default:
		elem_class = PEC_RES_AGG;
		break;
	}
	if ((pe = conf->pc_prov->pc_elem_create(conf, elem_class, type,
	    PCEC_INVALID)) == NULL) {
		pool_seterror(POE_INVALID_CONF);
		return (NULL);
	}

	/*
	 * The plugins contain a list of default properties and their values
	 * for resources. The resource returned, hence, is fully initialized.
	 */
	if ((default_props = provider_get_props(pe)) != NULL) {
		int i;
		for (i = 0; default_props[i].pp_pname != NULL; i++) {
			if (prop_is_init(&default_props[i]) &&
			    pool_put_any_property(pe, default_props[i].pp_pname,
			    &default_props[i].pp_value) == PO_FAIL) {
				(void) pool_resource_destroy(conf,
				    pool_elem_res(pe));
				return (NULL);
			}
		}
	}
	if (pool_value_set_string(&val, name) != PO_SUCCESS ||
	    pool_put_ns_property(pe, "name", &val) != PO_SUCCESS) {
		(void) pool_resource_destroy(conf, pool_elem_res(pe));
		return (NULL);
	}
	if (is_default) {
		pool_value_set_bool(&val, PO_TRUE);
		if (pool_put_any_ns_property(pe, "default", &val) !=
		    PO_SUCCESS) {
			(void) pool_resource_destroy(conf, pool_elem_res(pe));
			return (NULL);
		}
	}

	/*
	 * If we are creating a temporary pool configuration, flag the resource.
	 */
	if (conf->pc_prov->pc_oflags & PO_TEMP) {
		if (pool_set_temporary(conf, pe) != PO_SUCCESS) {
			(void) pool_resource_destroy(conf, pool_elem_res(pe));
			return (NULL);
		}
	}

	return (pool_elem_res(pe));
}

/*
 * Create an element to represent a resource component.
 */
pool_component_t *
pool_component_create(pool_conf_t *conf, const pool_resource_t *res,
    int64_t sys_id)
{
	pool_elem_t *pe;
	pool_value_t val = POOL_VALUE_INITIALIZER;
	const pool_prop_t *default_props;
	char refbuf[KEY_BUFFER_SIZE];

	if ((pe = conf->pc_prov->pc_elem_create(conf, PEC_COMP,
	    PREC_INVALID, PCEC_CPU)) == NULL) {
		pool_seterror(POE_INVALID_CONF);
		return (NULL);
	}
	/*
	 * TODO: If additional PEC_COMP types are added in pool_impl.h,
	 * this would need to be extended.
	 */
	pe->pe_component_class = PCEC_CPU;
	/* Now set the container for this comp */
	if (pool_set_container(TO_ELEM(res), pe) == PO_FAIL) {
		(void) pool_component_destroy(pool_elem_comp(pe));
		return (NULL);
	}
	/*
	 * The plugins contain a list of default properties and their values
	 * for resources. The resource returned, hence, is fully initialized.
	 */
	if ((default_props = provider_get_props(pe)) != NULL) {
		int i;
		for (i = 0; default_props[i].pp_pname != NULL; i++) {
			if (prop_is_init(&default_props[i]) &&
			    pool_put_any_property(pe,
			    default_props[i].pp_pname,
			    &default_props[i].pp_value) == PO_FAIL) {
				(void) pool_component_destroy(
				    pool_elem_comp(pe));
				return (NULL);
			}
		}
	}
	/*
	 * Set additional attributes/properties on component.
	 */
	pool_value_set_int64(&val, sys_id);
	if (pool_put_any_ns_property(pe, c_sys_prop, &val) != PO_SUCCESS) {
		(void) pool_component_destroy(pool_elem_comp(pe));
		return (NULL);
	}
	if (snprintf(refbuf, KEY_BUFFER_SIZE, "%s_%lld",
	    pool_elem_class_string(pe), sys_id) > KEY_BUFFER_SIZE) {
		(void) pool_component_destroy(pool_elem_comp(pe));
		return (NULL);
	}
	if (pool_value_set_string(&val, refbuf) != PO_SUCCESS) {
		(void) pool_component_destroy(pool_elem_comp(pe));
		return (NULL);
	}
	if (pool_put_any_ns_property(pe, c_ref_id, &val) != PO_SUCCESS) {
		(void) pool_component_destroy(pool_elem_comp(pe));
		return (NULL);
	}
	return (pool_elem_comp(pe));
}

/*
 * Return the location of a configuration.
 */
const char *
pool_conf_location(const pool_conf_t *conf)
{
	if (pool_conf_status(conf) == POF_INVALID) {
		pool_seterror(POE_BADPARAM);
		return (NULL);
	}
	return (conf->pc_location);
}
/*
 * Close a configuration, freeing all associated resources. Once a
 * configuration is closed, it can no longer be used.
 */
int
pool_conf_close(pool_conf_t *conf)
{
	int rv;

	if (pool_conf_status(conf) == POF_INVALID) {
		pool_seterror(POE_BADPARAM);
		return (PO_FAIL);
	}
	rv = conf->pc_prov->pc_close(conf);
	conf->pc_prov = NULL;
	free((void *)conf->pc_location);
	conf->pc_location = NULL;
	conf->pc_state = POF_INVALID;
	return (rv);
}

/*
 * Remove a configuration, freeing all associated resources. Once a
 * configuration is removed, it can no longer be accessed and is forever
 * gone.
 */
int
pool_conf_remove(pool_conf_t *conf)
{
	int rv;

	if (pool_conf_status(conf) == POF_INVALID) {
		pool_seterror(POE_BADPARAM);
		return (PO_FAIL);
	}
	rv = conf->pc_prov->pc_remove(conf);
	conf->pc_state = POF_INVALID;
	return (rv);
}

/*
 * pool_conf_alloc() allocate the resources to represent a configuration.
 */
pool_conf_t *
pool_conf_alloc(void)
{
	pool_conf_t *conf;

	if ((conf = calloc(1, sizeof (pool_conf_t))) == NULL) {
		pool_seterror(POE_SYSTEM);
		return (NULL);
	}
	conf->pc_state = POF_INVALID;
	return (conf);
}

/*
 * pool_conf_free() frees the resources associated with a configuration.
 */
void
pool_conf_free(pool_conf_t *conf)
{
	free(conf);
}

/*
 * pool_conf_open() opens a configuration, establishing all required
 * connections to the data source.
 */
int
pool_conf_open(pool_conf_t *conf, const char *location, int oflags)
{
	/*
	 * Since you can't do anything to a pool configuration without opening
	 * it, this represents a good point to intialise structures that would
	 * otherwise need to be initialised in a .init section.
	 */
	internal_init();

	if (pool_conf_status(conf) != POF_INVALID) {
		/*
		 * Already opened configuration, return PO_FAIL
		 */
		pool_seterror(POE_BADPARAM);
		return (PO_FAIL);
	}
	if (oflags & ~(PO_RDONLY | PO_RDWR | PO_CREAT | PO_DISCO | PO_UPDATE |
	    PO_TEMP)) {
		pool_seterror(POE_BADPARAM);
		return (PO_FAIL);
	}

	/*
	 * Creating a configuration implies read-write access, so make
	 * sure that PO_RDWR is set in addition if PO_CREAT is set.
	 */
	if (oflags & PO_CREAT)
		oflags |= PO_RDWR;

	/* location is ignored when creating a temporary configuration */
	if (oflags & PO_TEMP)
		location = "";

	if ((conf->pc_location = strdup(location)) == NULL) {
		pool_seterror(POE_SYSTEM);
		return (PO_FAIL);
	}
	/*
	 * This is the crossover point into the actual data provider
	 * implementation, allocate a data provider of the appropriate
	 * type for your data storage medium. In this case it's either a kernel
	 * or xml data provider. To use a different data provider, write some
	 * code to implement all the required interfaces and then change the
	 * following code to allocate a data provider which uses your new code.
	 * All data provider routines can be static, apart from the allocation
	 * routine.
	 *
	 * For temporary pools (PO_TEMP) we start with a copy of the current
	 * dynamic configuration and do all of the updates in-memory.
	 */
	if (oflags & PO_TEMP) {
		if (pool_knl_connection_alloc(conf, PO_TEMP) != PO_SUCCESS) {
			conf->pc_state = POF_INVALID;
			return (PO_FAIL);
		}
		/* set rdwr flag so we can updated the in-memory config. */
		conf->pc_prov->pc_oflags |= PO_RDWR;

	} else if (strcmp(location, pool_dynamic_location()) == 0) {
		if (pool_knl_connection_alloc(conf, oflags) != PO_SUCCESS) {
			conf->pc_state = POF_INVALID;
			return (PO_FAIL);
		}
	} else {
		if (pool_xml_connection_alloc(conf, oflags) != PO_SUCCESS) {
			conf->pc_state = POF_INVALID;
			return (PO_FAIL);
		}
	}
	return (PO_SUCCESS);
}

/*
 * Rollback a configuration. This will undo all changes to the configuration
 * since the last time pool_conf_commit was called.
 */
int
pool_conf_rollback(pool_conf_t *conf)
{
	if (pool_conf_status(conf) == POF_INVALID) {
		pool_seterror(POE_BADPARAM);
		return (PO_FAIL);
	}
	return (conf->pc_prov->pc_rollback(conf));
}

/*
 * Commit a configuration. This will apply all changes to the
 * configuration to the permanent data store. The active parameter
 * indicates whether the configuration should be used to update the
 * dynamic configuration from the supplied (static) configuration or
 * whether it should be written back to persistent store.
 */
int
pool_conf_commit(pool_conf_t *conf, int active)
{
	int retval;

	if (pool_conf_status(conf) == POF_INVALID) {
		pool_seterror(POE_BADPARAM);
		return (PO_FAIL);
	}
	if (active) {
		int oflags;

		if (conf_is_dynamic(conf) == PO_TRUE) {
			pool_seterror(POE_BADPARAM);
			return (PO_FAIL);
		}
		/*
		 * Pretend that the configuration was opened PO_RDWR
		 * so that a configuration which was opened PO_RDONLY
		 * can be committed. The original flags are preserved
		 * in oflags and restored after pool_conf_commit_sys()
		 * returns.
		 */
		oflags = conf->pc_prov->pc_oflags;
		conf->pc_prov->pc_oflags |= PO_RDWR;
		retval = pool_conf_commit_sys(conf, active);
		conf->pc_prov->pc_oflags = oflags;
	} else {
		/*
		 * Write the configuration back to the backing store.
		 */
		retval =  conf->pc_prov->pc_commit(conf);
	}
	return (retval);
}

/*
 * Export a configuration. This will export a configuration in the specified
 * format (fmt) to the specified location.
 */
int
pool_conf_export(const pool_conf_t *conf, const char *location,
    pool_export_format_t fmt)
{
	if (pool_conf_status(conf) == POF_INVALID) {
		pool_seterror(POE_BADPARAM);
		return (PO_FAIL);
	}
	return (conf->pc_prov->pc_export(conf, location, fmt));
}

/*
 * Validate a configuration. This will validate a configuration at the
 * specified level.
 */
int
pool_conf_validate(const pool_conf_t *conf, pool_valid_level_t level)
{
	if (pool_conf_status(conf) == POF_INVALID) {
		pool_seterror(POE_BADPARAM);
		return (PO_FAIL);
	}
	return (conf->pc_prov->pc_validate(conf, level));
}

/*
 * Update the snapshot of a configuration. This can only be used on a
 * dynamic configuration.
 */
int
pool_conf_update(const pool_conf_t *conf, int *changed)
{
	if (pool_conf_status(conf) == POF_INVALID ||
	    conf_is_dynamic(conf) == PO_FALSE) {
		pool_seterror(POE_BADPARAM);
		return (PO_FAIL);
	}
	/*
	 * Since this function only makes sense for dynamic
	 * configurations, just call directly into the appropriate
	 * function. This could be added into the pool_connection_t
	 * interface if it was ever required.
	 */
	if (changed)
		*changed = 0;
	return (pool_knl_update((pool_conf_t *)conf, changed));
}

/*
 * Walk the properties of the supplied elem, calling the user supplied
 * function repeatedly as long as the user function returns
 * PO_SUCCESS.
 */
int
pool_walk_properties(pool_conf_t *conf, pool_elem_t *elem, void *arg,
    int (*prop_callback)(pool_conf_t *, pool_elem_t *, const char *,
    pool_value_t *, void *))
{
	return (pool_walk_any_properties(conf, elem, arg, prop_callback, 0));
}

void
free_value_list(int npvals, pool_value_t **pvals)
{
	int j;

	for (j = 0; j < npvals; j++) {
		if (pvals[j])
			pool_value_free(pvals[j]);
	}
	free(pvals);
}

/*
 * Walk the properties of the supplied elem, calling the user supplied
 * function repeatedly as long as the user function returns
 * PO_SUCCESS.
 * The list of properties to be walked is retrieved from the element
 */
int
pool_walk_any_properties(pool_conf_t *conf, pool_elem_t *elem, void *arg,
    int (*prop_callback)(pool_conf_t *, pool_elem_t *, const char *,
    pool_value_t *, void *), int any)
{
	pool_value_t **pvals;
	int i;
	const pool_prop_t *props = provider_get_props(elem);
	uint_t npvals;

	if (pool_conf_status(conf) == POF_INVALID) {
		pool_seterror(POE_BADPARAM);
		return (PO_FAIL);
	}

	if (props == NULL) {
		pool_seterror(POE_INVALID_CONF);
		return (PO_FAIL);
	}

	if ((pvals = elem->pe_get_props(elem, &npvals)) == NULL)
		return (PO_FAIL);

	/*
	 * Now walk the managed properties. As we find managed
	 * properties removed them from the list of all properties to
	 * prevent duplication.
	 */
	for (i = 0;  props[i].pp_pname != NULL; i++) {
		int j;

		/*
		 * Special processing for type
		 */
		if (strcmp(props[i].pp_pname, c_type) == 0) {
			pool_value_t val = POOL_VALUE_INITIALIZER;

			if (pool_value_set_name(&val, props[i].pp_pname) ==
			    PO_FAIL) {
				free_value_list(npvals, pvals);
				return (PO_FAIL);
			}
			if (props[i].pp_op.ppo_get_value(elem, &val) ==
			    PO_FAIL) {
				free_value_list(npvals, pvals);
				return (PO_FAIL);
			}
			if (any == 1 || prop_is_hidden(&props[i]) == PO_FALSE) {
				if (prop_callback(conf, elem, props[i].pp_pname,
				    &val, arg) != PO_SUCCESS) {
					free_value_list(npvals, pvals);
					pool_seterror(POE_BADPARAM);
					return (PO_FAIL);
				}
			}
			continue;
		}

		for (j = 0; j < npvals; j++) {
			if (pvals[j] && strcmp(pool_value_get_name(pvals[j]),
			    props[i].pp_pname) == 0)
				break;
		}
		/*
		 * If we have found the property, then j < npvals. Process it
		 * according to our property attributes. Otherwise, it's not
		 * a managed property, so just ignore it until later.
		 */
		if (j < npvals) {
			if (any == 1 || prop_is_hidden(&props[i]) == PO_FALSE) {
				if (props[i].pp_op.ppo_get_value) {
					if (pool_value_set_name(pvals[j],
					    props[i].pp_pname) == PO_FAIL) {
						free_value_list(npvals, pvals);
						return (PO_FAIL);
					}
					if (props[i].pp_op.ppo_get_value(elem,
					    pvals[j]) == PO_FAIL) {
						free_value_list(npvals, pvals);
						return (PO_FAIL);
					}
				}
				if (prop_callback(conf, elem, props[i].pp_pname,
				    pvals[j], arg) != PO_SUCCESS) {
					free_value_list(npvals, pvals);
					pool_seterror(POE_BADPARAM);
					return (PO_FAIL);
				}
			}
			pool_value_free(pvals[j]);
			pvals[j] = NULL;
		}
	}
	for (i = 0;  i < npvals; i++) {
		if (pvals[i]) {
			const char *name = pool_value_get_name(pvals[i]);
			char *qname = strrchr(name, '.');
			if ((qname && qname[1] != '_') ||
			    (!qname && name[0] != '_')) {
				if (prop_callback(conf, elem, name, pvals[i],
				    arg) != PO_SUCCESS) {
					free_value_list(npvals, pvals);
					pool_seterror(POE_BADPARAM);
					return (PO_FAIL);
				}
			}
			pool_value_free(pvals[i]);
			pvals[i] = NULL;
		}
	}
	free(pvals);
	return (PO_SUCCESS);
}

/*
 * Return a pool, searching the supplied configuration for a pool with the
 * supplied name. The search is case sensitive.
 */
pool_t *
pool_get_pool(const pool_conf_t *conf, const char *name)
{
	pool_value_t *props[] = { NULL, NULL };
	pool_t **rs;
	pool_t *ret;
	uint_t size = 0;
	pool_value_t val = POOL_VALUE_INITIALIZER;

	props[0] = &val;

	if (pool_conf_status(conf) == POF_INVALID) {
		pool_seterror(POE_BADPARAM);
		return (NULL);
	}

	if (pool_value_set_name(props[0], "pool.name") != PO_SUCCESS ||
	    pool_value_set_string(props[0], name) != PO_SUCCESS) {
		return (NULL);
	}
	rs = pool_query_pools(conf, &size, props);
	if (rs == NULL) { /* Can't find a pool to match the name */
		return (NULL);
	}
	if (size != 1) {
		free(rs);
		pool_seterror(POE_INVALID_CONF);
		return (NULL);
	}
	ret = rs[0];
	free(rs);
	return (ret);
}

/*
 * Return a result set of pools, searching the supplied configuration
 * for pools which match the supplied property criteria. props is a null
 * terminated list of properties which will be used to match qualifying
 * pools. size is updated with the size of the pool
 */
pool_t **
pool_query_pools(const pool_conf_t *conf, uint_t *size, pool_value_t **props)
{
	pool_result_set_t *rs;
	pool_elem_t *pe;
	pool_t **result = NULL;
	int i = 0;

	if (pool_conf_status(conf) == POF_INVALID) {
		pool_seterror(POE_BADPARAM);
		return (NULL);
	}
	rs = pool_exec_query(conf, NULL, NULL, PEC_QRY_POOL, props);
	if (rs == NULL) {
		return (NULL);
	}
	if ((*size = pool_rs_count(rs)) == 0) {
		(void) pool_rs_close(rs);
		return (NULL);
	}
	if ((result = malloc(sizeof (pool_t *) * (*size + 1))) == NULL) {
		pool_seterror(POE_SYSTEM);
		(void) pool_rs_close(rs);
		return (NULL);
	}
	(void) memset(result, 0, sizeof (pool_t *) * (*size + 1));
	for (pe = rs->prs_next(rs); pe != NULL; pe = rs->prs_next(rs)) {
		if (pool_elem_class(pe) != PEC_POOL) {
			pool_seterror(POE_INVALID_CONF);
			free(result);
			(void) pool_rs_close(rs);
			return (NULL);
		}
		result[i++] = pool_elem_pool(pe);
	}
	(void) pool_rs_close(rs);
	return (result);
}

/*
 * Return an res, searching the supplied configuration for an res with the
 * supplied name. The search is case sensitive.
 */
pool_resource_t *
pool_get_resource(const pool_conf_t *conf, const char *sz_type,
    const char *name)
{
	pool_value_t *props[] = { NULL, NULL, NULL };
	pool_resource_t **rs;
	pool_resource_t *ret;
	uint_t size = 0;
	char_buf_t *cb = NULL;
	pool_value_t val0 = POOL_VALUE_INITIALIZER;
	pool_value_t val1 = POOL_VALUE_INITIALIZER;

	if (pool_conf_status(conf) == POF_INVALID) {
		pool_seterror(POE_BADPARAM);
		return (NULL);
	}

	if (sz_type == NULL) {
		pool_seterror(POE_BADPARAM);
		return (NULL);
	}

	props[0] = &val0;
	props[1] = &val1;

	if (pool_value_set_string(props[0], sz_type) != PO_SUCCESS ||
	    pool_value_set_name(props[0], c_type) != PO_SUCCESS)
		return (NULL);

	if ((cb = alloc_char_buf(CB_DEFAULT_LEN)) == NULL) {
		return (NULL);
	}
	if (set_char_buf(cb, "%s.name", sz_type) != PO_SUCCESS) {
		free_char_buf(cb);
		return (NULL);
	}
	if (pool_value_set_name(props[1], cb->cb_buf) != PO_SUCCESS) {
		free_char_buf(cb);
		return (NULL);
	}
	if (pool_value_set_string(props[1], name) != PO_SUCCESS) {
		free_char_buf(cb);
		return (NULL);
	}
	free_char_buf(cb);
	rs = pool_query_resources(conf, &size, props);
	if (rs == NULL) {
		return (NULL);
	}
	if (size != 1) {
		free(rs);
		pool_seterror(POE_INVALID_CONF);
		return (NULL);
	}
	ret = rs[0];
	free(rs);
	return (ret);
}

/*
 * Return a result set of res (actually as pool_elem_ts), searching the
 * supplied configuration for res which match the supplied property
 * criteria. props is a null terminated list of properties which will be used
 * to match qualifying res.
 */
pool_resource_t **
pool_query_resources(const pool_conf_t *conf, uint_t *size,
    pool_value_t **props)
{
	pool_result_set_t *rs;
	pool_elem_t *pe;
	pool_resource_t **result = NULL;
	int i = 0;

	if (pool_conf_status(conf) == POF_INVALID) {
		pool_seterror(POE_BADPARAM);
		return (NULL);
	}

	*size = 0;

	rs = pool_exec_query(conf, NULL, NULL, PEC_QRY_RES, props);
	if (rs == NULL) {
		return (NULL);
	}
	if ((*size = pool_rs_count(rs)) == 0) {
		(void) pool_rs_close(rs);
		return (NULL);
	}
	if ((result = malloc(sizeof (pool_resource_t *) * (*size + 1)))
	    == NULL) {
		pool_seterror(POE_SYSTEM);
		(void) pool_rs_close(rs);
		return (NULL);
	}
	(void) memset(result, 0, sizeof (pool_resource_t *) * (*size + 1));
	for (pe = rs->prs_next(rs); pe != NULL; pe = rs->prs_next(rs)) {
		if (pool_elem_class(pe) != PEC_RES_COMP &&
		    pool_elem_class(pe) != PEC_RES_AGG) {
			pool_seterror(POE_INVALID_CONF);
			free(result);
			(void) pool_rs_close(rs);
			return (NULL);
		}
		result[i++] = pool_elem_res(pe);
	}
	(void) pool_rs_close(rs);
	return (result);
}

/*
 * Return a result set of comp (actually as pool_elem_ts), searching the
 * supplied configuration for comp which match the supplied property
 * criteria. props is a null terminated list of properties which will be used
 * to match qualifying comp.
 */
pool_component_t **
pool_query_components(const pool_conf_t *conf, uint_t *size,
    pool_value_t **props)
{
	return (pool_query_resource_components(conf, NULL, size, props));
}

/*
 * Destroy a pool. If the pool cannot be found or removed an error is
 * returned. This is basically a wrapper around pool_elem_remove to ensure
 * some type safety for the pool subtype.
 */
int
pool_destroy(pool_conf_t *conf, pool_t *pp)
{
	pool_elem_t *pe;

	if (pool_conf_check(conf) != PO_SUCCESS)
		return (PO_FAIL);

	pe = TO_ELEM(pp);

	/*
	 * Cannot destroy the default pool.
	 */
	if (elem_is_default(pe) == PO_TRUE) {
		pool_seterror(POE_BADPARAM);
		return (PO_FAIL);
	}
	if (pool_elem_remove(pe) != PO_SUCCESS)
		return (PO_FAIL);
	return (PO_SUCCESS);
}

/*
 * Destroy an res. If the res cannot be found or removed an error is
 * returned. This is basically a wrapper around pool_elem_remove to ensure
 * some type safety for the res subtype.
 */
int
pool_resource_destroy(pool_conf_t *conf, pool_resource_t *prs)
{
	pool_elem_t *pe;
	pool_component_t **rl;
	uint_t res_size;
	pool_t **pl;
	uint_t npool;
	int i;

	if (pool_conf_check(conf) != PO_SUCCESS)
		return (PO_FAIL);

	pe = TO_ELEM(prs);

	if (resource_is_system(prs) == PO_TRUE) {
		pool_seterror(POE_BADPARAM);
		return (PO_FAIL);
	}
	/*
	 * Walk all the pools and dissociate any pools which are using
	 * this resource.
	 */
	if ((pl = pool_query_pools(conf, &npool, NULL)) != NULL) {
		for (i = 0; i < npool; i++) {
			pool_resource_t **rl;
			uint_t nres;
			int j;

			if ((rl = pool_query_pool_resources(conf, pl[i], &nres,
			    NULL)) != NULL) {
				for (j = 0; j < nres; j++) {
					if (rl[j] == prs) {
						if (pool_dissociate(conf, pl[i],
						    rl[j]) != PO_SUCCESS) {
							free(rl);
							free(pl);
							return (PO_FAIL);
						}
						break;
					}
				}
			free(rl);
			}
		}
		free(pl);
	}
	if (pe->pe_class == PEC_RES_COMP) {
		pool_resource_t *default_set_res;

		/*
		 * Use the xtransfer option to move comp around
		 */
		default_set_res = (pool_resource_t *)get_default_resource(prs);

		if ((rl = pool_query_resource_components(conf, prs, &res_size,
		    NULL)) != NULL) {
			int ostate = conf->pc_state;
			conf->pc_state = POF_DESTROY;
			if (pool_resource_xtransfer(conf, prs, default_set_res,
			    rl) == PO_FAIL) {
				free(rl);
				conf->pc_state = ostate;
				return (PO_FAIL);
			}
			conf->pc_state = ostate;
			free(rl);
		}
	}
	if (pool_elem_remove(pe) != PO_SUCCESS)
		return (PO_FAIL);
	return (PO_SUCCESS);
}

/*
 * Destroy a comp. If the comp cannot be found or removed an error is
 * returned. This is basically a wrapper around pool_elem_remove to ensure
 * some type safety for the comp subtype.
 */
int
pool_component_destroy(pool_component_t *pr)
{
	pool_elem_t *pe = TO_ELEM(pr);

	if (pool_elem_remove(pe) != PO_SUCCESS)
		return (PO_FAIL);
	return (PO_SUCCESS);
}

/*
 * Remove a pool_elem_t from a configuration. This has been "hidden" away as
 * a static routine since the only elements which are currently being removed
 * are pools, res & comp and the wrapper functions above provide type-safe
 * access. However, if there is a need to remove other types of elements
 * then this could be promoted to pool_impl.h or more wrappers could
 * be added to pool_impl.h.
 */
int
pool_elem_remove(pool_elem_t *pe)
{
	return (pe->pe_remove(pe));
}

/*
 * Execute a query to search for a qualifying set of elements.
 */
pool_result_set_t *
pool_exec_query(const pool_conf_t *conf, const pool_elem_t *src,
    const char *src_attr, pool_elem_class_t classes, pool_value_t **props)
{
	return (conf->pc_prov->pc_exec_query(conf, src, src_attr, classes,
	    props));
}

/*
 * Get the next result from a result set of elements.
 */
pool_elem_t *
pool_rs_next(pool_result_set_t *set)
{
	return (set->prs_next(set));
}

/*
 * Get the previous result from a result set of elements.
 */
pool_elem_t *
pool_rs_prev(pool_result_set_t *set)
{
	return (set->prs_prev(set));
}

/*
 * Get the first result from a result set of elements.
 */
pool_elem_t *
pool_rs_first(pool_result_set_t *set)
{
	return (set->prs_first(set));
}

/*
 * Get the last result from a result set of elements.
 */
pool_elem_t *
pool_rs_last(pool_result_set_t *set)
{
	return (set->prs_last(set));
}


/*
 * Get the count for a result set of elements.
 */
int
pool_rs_count(pool_result_set_t *set)
{
	return (set->prs_count(set));
}

/*
 * Get the index for a result set of elements.
 */
int
pool_rs_get_index(pool_result_set_t *set)
{
	return (set->prs_get_index(set));
}

/*
 * Set the index for a result set of elements.
 */
int
pool_rs_set_index(pool_result_set_t *set, int index)
{
	return (set->prs_set_index(set, index));
}

/*
 * Close a result set of elements, freeing all associated resources.
 */
int
pool_rs_close(pool_result_set_t *set)
{
	return (set->prs_close(set));
}

/*
 * When transferring resource components using pool_resource_transfer,
 * this function is invoked to choose which actual components will be
 * transferred.
 */
int
choose_components(pool_resource_t *src, pool_resource_t *dst, uint64_t size)
{
	pool_component_t **components = NULL, *moved[] = { NULL, NULL };
	int i;
	uint_t ncomponent;
	pool_conf_t *conf = TO_CONF(TO_ELEM(src));

	if (size == 0)
		return (PO_SUCCESS);
	/*
	 * Get the component list from our src component.
	 */
	if ((components = pool_query_resource_components(conf, src, &ncomponent,
	    NULL)) == NULL) {
		pool_seterror(POE_BADPARAM);
		return (PO_FAIL);
	}
	qsort(components, ncomponent, sizeof (pool_elem_t *),
	    qsort_elem_compare);
	/*
	 * Components that aren't specifically requested by the resource
	 * should be transferred out first.
	 */
	for (i = 0; size > 0 && components[i] != NULL; i++) {
		if (!cpu_is_requested(components[i])) {
			moved[0] = components[i];
			if (pool_resource_xtransfer(conf, src, dst, moved) ==
			    PO_SUCCESS) {
				size--;
			}
		}
	}

	/*
	 * If we couldn't find enough "un-requested" components, select random
	 * requested components.
	 */
	for (i = 0; size > 0 && components[i] != NULL; i++) {
		if (cpu_is_requested(components[i])) {
			moved[0] = components[i];
			if (pool_resource_xtransfer(conf, src, dst, moved) ==
			    PO_SUCCESS) {
				size--;
			}
		}
	}

	free(components);
	/*
	 * If we couldn't transfer out all the resources we asked for, then
	 * return error.
	 */
	return (size == 0 ? PO_SUCCESS : PO_FAIL);
}

/*
 * Common processing for a resource transfer (xfer or xxfer).
 *
 * - Return XFER_CONTINUE if the transfer should proceeed
 * - Return XFER_FAIL if the transfer should be stopped in failure
 * - Return XFER_SUCCESS if the transfer should be stopped in success
 */
int
setup_transfer(pool_conf_t *conf, pool_resource_t *src, pool_resource_t *tgt,
    uint64_t size, uint64_t *src_size, uint64_t *tgt_size)
{
	uint64_t src_min;
	uint64_t tgt_max;

	if (pool_conf_check(conf) != PO_SUCCESS)
		return (XFER_FAIL);

	/*
	 * Makes sure the two resources are of the same type
	 */
	if (pool_resource_elem_class(TO_ELEM(src)) !=
	    pool_resource_elem_class(TO_ELEM(tgt))) {
		pool_seterror(POE_BADPARAM);
		return (XFER_FAIL);
	}

	/*
	 * Transferring to yourself is a no-op
	 */
	if (src == tgt)
		return (XFER_SUCCESS);

	/*
	 * Transferring nothing is a no-op
	 */
	if (size == 0)
		return (XFER_SUCCESS);

	if (resource_get_min(src, &src_min) != PO_SUCCESS ||
	    resource_get_size(src, src_size) != PO_SUCCESS ||
	    resource_get_max(tgt, &tgt_max) != PO_SUCCESS ||
	    resource_get_size(tgt, tgt_size) != PO_SUCCESS) {
		pool_seterror(POE_BADPARAM);
		return (XFER_FAIL);
	}
	if (pool_conf_status(conf) != POF_DESTROY) {
		/*
		 * src_size - donating >= src.min
		 * size + receiving <= tgt.max (except for default)
		 */
#ifdef DEBUG
		pool_dprintf("conf is %s\n", pool_conf_location(conf));
		pool_dprintf("setup_transfer: src_size %llu\n", *src_size);
		pool_elem_dprintf(TO_ELEM(src));
		pool_dprintf("setup_transfer: tgt_size %llu\n", *tgt_size);
		pool_elem_dprintf(TO_ELEM(tgt));
#endif	/* DEBUG */
		if (*src_size - size < src_min ||
		    (resource_is_default(tgt) == PO_FALSE &&
		    *tgt_size + size > tgt_max)) {
			pool_seterror(POE_INVALID_CONF);
			return (XFER_FAIL);
		}
	}
	return (XFER_CONTINUE);
}

/*
 * Transfer resource quantities from one resource set to another.
 */
int
pool_resource_transfer(pool_conf_t *conf, pool_resource_t *src,
    pool_resource_t *tgt, uint64_t size)
{
	uint64_t src_size;
	uint64_t tgt_size;
	int ret;

	if ((ret = setup_transfer(conf, src, tgt, size, &src_size, &tgt_size))
	    != XFER_CONTINUE)
		return (ret);
	/*
	 * If this resource is a res_comp we must call move components
	 */
	if (pool_elem_class(TO_ELEM(src)) == PEC_RES_COMP)
		return (choose_components(src, tgt, size));
	/*
	 * Now do the transfer.
	 */
	ret = conf->pc_prov->pc_res_xfer(src, tgt, size);
	/*
	 * Modify the sizes of the resource sets if the process was
	 * successful
	 */
	if (ret == PO_SUCCESS) {
		pool_value_t val = POOL_VALUE_INITIALIZER;

		src_size -= size;
		tgt_size += size;
		pool_value_set_uint64(&val, src_size);
		(void) pool_put_any_ns_property(TO_ELEM(src), c_size_prop,
		    &val);
		pool_value_set_uint64(&val, tgt_size);
		(void) pool_put_any_ns_property(TO_ELEM(tgt), c_size_prop,
		    &val);
	}
	return (ret);
}

/*
 * Transfer resource components from one resource set to another.
 */
int
pool_resource_xtransfer(pool_conf_t *conf, pool_resource_t *src,
    pool_resource_t *tgt,
    pool_component_t **rl)
{
	int i;
	uint64_t src_size;
	uint64_t tgt_size;
	uint64_t size;
	int ret;

	/*
	 * Make sure the components are all contained in 'src'. This
	 * processing must be done before setup_transfer so that size
	 * is known.
	 */
	for (i = 0; rl[i] != NULL; i++) {
#ifdef DEBUG
		pool_dprintf("resource xtransfer\n");
		pool_dprintf("in conf %s\n", pool_conf_location(conf));
		pool_dprintf("transferring component\n");
		pool_elem_dprintf(TO_ELEM(rl[i]));
		pool_dprintf("from\n");
		pool_elem_dprintf(TO_ELEM(src));
		pool_dprintf("to\n");
		pool_elem_dprintf(TO_ELEM(tgt));
#endif	/* DEBUG */

		if (pool_get_owning_resource(conf, rl[i]) != src) {
			pool_seterror(POE_BADPARAM);
			return (PO_FAIL);
		}
	}

	size = (uint64_t)i;

	if ((ret = setup_transfer(conf, src, tgt, size, &src_size, &tgt_size))
	    != XFER_CONTINUE)
		return (ret);

	ret = conf->pc_prov->pc_res_xxfer(src, tgt, rl);
	/*
	 * Modify the sizes of the resource sets if the process was
	 * successful
	 */
	if (ret == PO_SUCCESS) {
		pool_value_t val = POOL_VALUE_INITIALIZER;

#ifdef DEBUG
		pool_dprintf("src_size %llu\n", src_size);
		pool_dprintf("tgt_size %llu\n", tgt_size);
		pool_dprintf("size %llu\n", size);
#endif	/* DEBUG */
		src_size -= size;
		tgt_size += size;
		pool_value_set_uint64(&val, src_size);
		(void) pool_put_any_ns_property(TO_ELEM(src), c_size_prop,
		    &val);
		pool_value_set_uint64(&val, tgt_size);
		(void) pool_put_any_ns_property(TO_ELEM(tgt), c_size_prop,
		    &val);
	}
	return (ret);
}

/*
 * Find the owning resource for a resource component.
 */
pool_resource_t *
pool_get_owning_resource(const pool_conf_t *conf, const pool_component_t *comp)
{
	if (pool_conf_status(conf) == POF_INVALID) {
		pool_seterror(POE_BADPARAM);
		return (NULL);
	}
	return (pool_elem_res(pool_get_container(TO_ELEM(comp))));
}

/*
 * pool_get_container() returns the container of pc.
 */
pool_elem_t *
pool_get_container(const pool_elem_t *pc)
{
	return (pc->pe_get_container(pc));
}

/*
 * pool_set_container() moves pc so that it is contained by pp.
 *
 * Returns PO_SUCCESS/PO_FAIL
 */
int
pool_set_container(pool_elem_t *pp, pool_elem_t *pc)
{
	return (pc->pe_set_container(pp, pc));
}

/*
 * Conversion routines for converting to and from elem and it's various
 * subtypes of system, pool, res and comp.
 */
pool_elem_t *
pool_system_elem(const pool_system_t *ph)
{
	return ((pool_elem_t *)ph);
}

pool_elem_t *
pool_conf_to_elem(const pool_conf_t *conf)
{
	pool_system_t *sys;

	if (pool_conf_status(conf) == POF_INVALID) {
		pool_seterror(POE_BADPARAM);
		return (NULL);
	}
	if ((sys = pool_conf_system(conf)) == NULL) {
		pool_seterror(POE_BADPARAM);
		return (NULL);
	}
	return (pool_system_elem(sys));
}

pool_elem_t *
pool_to_elem(const pool_conf_t *conf, const pool_t *pp)
{
	if (pool_conf_status(conf) == POF_INVALID) {
		pool_seterror(POE_BADPARAM);
		return (NULL);
	}
	return ((pool_elem_t *)pp);
}

pool_elem_t *
pool_resource_to_elem(const pool_conf_t *conf, const pool_resource_t *prs)
{
	if (pool_conf_status(conf) == POF_INVALID) {
		pool_seterror(POE_BADPARAM);
		return (NULL);
	}
	return ((pool_elem_t *)prs);
}

pool_elem_t *
pool_component_to_elem(const pool_conf_t *conf, const pool_component_t *pr)
{
	if (pool_conf_status(conf) == POF_INVALID) {
		pool_seterror(POE_BADPARAM);
		return (NULL);
	}
	return ((pool_elem_t *)pr);
}

/*
 * Walk all the pools of the configuration calling the user supplied function
 * as long as the user function continues to return PO_TRUE
 */
int
pool_walk_pools(pool_conf_t *conf, void *arg,
    int (*callback)(pool_conf_t *conf, pool_t *pool, void *arg))
{
	pool_t **rs;
	int i;
	uint_t size;
	int error = PO_SUCCESS;

	if (pool_conf_status(conf) == POF_INVALID) {
		pool_seterror(POE_BADPARAM);
		return (PO_FAIL);
	}

	if ((rs = pool_query_pools(conf, &size, NULL)) == NULL) /* None */
		return (PO_SUCCESS);
	for (i = 0; i < size; i++)
		if (callback(conf, rs[i], arg) != PO_SUCCESS) {
			error = PO_FAIL;
			break;
		}
	free(rs);
	return (error);
}

/*
 * Walk all the comp of the res calling the user supplied function
 * as long as the user function continues to return PO_TRUE
 */
int
pool_walk_components(pool_conf_t *conf, pool_resource_t *prs, void *arg,
    int (*callback)(pool_conf_t *conf, pool_component_t *pr, void *arg))
{
	pool_component_t **rs;
	int i;
	uint_t size;
	int error = PO_SUCCESS;

	if (pool_conf_status(conf) == POF_INVALID) {
		pool_seterror(POE_BADPARAM);
		return (PO_FAIL);
	}

	if ((rs = pool_query_resource_components(conf, prs, &size, NULL)) ==
	    NULL)
		return (PO_SUCCESS); /* None */
	for (i = 0; i < size; i++)
		if (callback(conf, rs[i], arg) != PO_SUCCESS) {
			error = PO_FAIL;
			break;
		}
	free(rs);
	return (error);
}

/*
 * Return an array of all matching res for the supplied pool.
 */
pool_resource_t **
pool_query_pool_resources(const pool_conf_t *conf, const pool_t *pp,
    uint_t *size, pool_value_t **props)
{
	pool_result_set_t *rs;
	pool_elem_t *pe;
	pool_resource_t **result = NULL;
	int i = 0;

	if (pool_conf_status(conf) == POF_INVALID) {
		pool_seterror(POE_BADPARAM);
		return (NULL);
	}

	pe = TO_ELEM(pp);

	rs = pool_exec_query(conf, pe, "res", PEC_QRY_RES, props);
	if (rs == NULL) {
		return (NULL);
	}
	if ((*size = pool_rs_count(rs)) == 0) {
		(void) pool_rs_close(rs);
		return (NULL);
	}
	if ((result = malloc(sizeof (pool_resource_t *) * (*size + 1)))
	    == NULL) {
		pool_seterror(POE_SYSTEM);
		(void) pool_rs_close(rs);
		return (NULL);
	}
	(void) memset(result, 0, sizeof (pool_resource_t *) * (*size + 1));
	for (pe = rs->prs_next(rs); pe != NULL; pe = rs->prs_next(rs)) {
		if (pool_elem_class(pe) != PEC_RES_COMP &&
		    pool_elem_class(pe) != PEC_RES_AGG) {
			pool_seterror(POE_INVALID_CONF);
			free(result);
			(void) pool_rs_close(rs);
			return (NULL);
		}
		result[i++] = pool_elem_res(pe);
	}
	(void) pool_rs_close(rs);
	return (result);
}

/*
 * Walk all the res of the pool calling the user supplied function
 * as long as the user function continues to return PO_TRUE
 */
int
pool_walk_resources(pool_conf_t *conf, pool_t *pp, void *arg,
    int (*callback)(pool_conf_t *, pool_resource_t *, void *))
{
	pool_resource_t **rs;
	int i;
	uint_t size;
	int error = PO_SUCCESS;

	if (pool_conf_status(conf) == POF_INVALID) {
		pool_seterror(POE_BADPARAM);
		return (PO_FAIL);
	}
	if ((rs = pool_query_pool_resources(conf, pp, &size, NULL)) == NULL)
		return (PO_SUCCESS); /* None */
	for (i = 0; i < size; i++)
		if (callback(conf, rs[i], arg) != PO_SUCCESS) {
			error = PO_FAIL;
			break;
		}
	free(rs);
	return (error);
}

/*
 * Return a result set of all comp for the supplied res.
 */
pool_component_t **
pool_query_resource_components(const pool_conf_t *conf,
    const pool_resource_t *prs, uint_t *size, pool_value_t **props)
{
	pool_result_set_t *rs;
	pool_elem_t *pe;
	pool_component_t **result = NULL;
	int i = 0;

	if (pool_conf_status(conf) == POF_INVALID) {
		pool_seterror(POE_BADPARAM);
		return (NULL);
	}
	pe = TO_ELEM(prs);

	rs = pool_exec_query(conf, pe, NULL, PEC_QRY_COMP, props);
	if (rs == NULL) {
		return (NULL);
	}
	if ((*size = pool_rs_count(rs)) == 0) {
		(void) pool_rs_close(rs);
		return (NULL);
	}
	if ((result = malloc(sizeof (pool_component_t *) * (*size + 1)))
	    == NULL) {
		pool_seterror(POE_SYSTEM);
		(void) pool_rs_close(rs);
		return (NULL);
	}
	(void) memset(result, 0, sizeof (pool_component_t *) * (*size + 1));
	for (pe = rs->prs_next(rs); pe != NULL; pe = rs->prs_next(rs)) {
		if (pool_elem_class(pe) != PEC_COMP) {
			pool_seterror(POE_INVALID_CONF);
			free(result);
			(void) pool_rs_close(rs);
			return (NULL);
		}
		result[i++] = pool_elem_comp(pe);
	}
	(void) pool_rs_close(rs);
	return (result);
}

/*
 * pool_version() returns the version of this library, depending on the supplied
 * parameter.
 *
 * Returns: library version depening on the supplied ver parameter.
 */
uint_t
pool_version(uint_t ver)
{
	switch (ver) {
	case POOL_VER_NONE:
		break;
	case POOL_VER_CURRENT:
		pool_workver = ver;
		break;
	default:
		return (POOL_VER_NONE);
	}
	return (pool_workver);
}

/*
 * pool_associate() associates the supplied resource to the supplied pool.
 *
 * Returns: PO_SUCCESS/PO_FAIL
 */
int
pool_associate(pool_conf_t *conf, pool_t *pool, const pool_resource_t *res)
{
	if (pool_conf_check(conf) != PO_SUCCESS)
		return (PO_FAIL);

	return (pool->pp_associate(pool, res));
}

/*
 * pool_dissociate() dissociates the supplied resource from the supplied pool.
 *
 * Returns: PO_SUCCESS/PO_FAIL
 */
int
pool_dissociate(pool_conf_t *conf, pool_t *pool, const pool_resource_t *res)
{
	if (pool_conf_check(conf) != PO_SUCCESS)
		return (PO_FAIL);

	if (elem_is_default(TO_ELEM(res)))
		return (PO_SUCCESS);
	return (pool->pp_dissociate(pool, res));
}

/*
 * Compare two elements for purposes of ordering.
 * Return:
 *	< 0 if e1 is "before" e2
 *	0 if e1 "equals" e2
 *	> 0 if e1 comes after e2
 */
int
pool_elem_compare_name(const pool_elem_t *e1, const pool_elem_t *e2)
{
	char *name1, *name2;
	pool_value_t val = POOL_VALUE_INITIALIZER;
	int retval;

	/*
	 * We may be asked to compare two elements from different classes.
	 * They are different so return (1).
	 */
	if (pool_elem_same_class(e1, e2) != PO_TRUE)
		return (1);

	/*
	 * If the class is PEC_SYSTEM, always match them
	 */
	if (pool_elem_class(e1) == PEC_SYSTEM)
		return (0);

	/*
	 * If we are going to compare components, then use sys_id
	 */
	if (pool_elem_class(e1) == PEC_COMP) {
		int64_t sys_id1, sys_id2;

		if (pool_get_ns_property(e1, c_sys_prop, &val) == POC_INVAL) {
			return (-1);
		}
		(void) pool_value_get_int64(&val, &sys_id1);
		if (pool_get_ns_property(e2, c_sys_prop, &val) == POC_INVAL) {
			return (-1);
		}
		(void) pool_value_get_int64(&val, &sys_id2);
		retval = (sys_id1 - sys_id2);
	} else {
		if (pool_get_ns_property(e1, "name", &val) == POC_INVAL) {
			return (-1);
		}
		(void) pool_value_get_string(&val, (const char **)&name1);
		if ((name1 = strdup(name1)) == NULL) {
			return (-1);
		}

		if (pool_get_ns_property(e2, "name", &val) == POC_INVAL) {
			return (-1);
		}

		(void) pool_value_get_string(&val, (const char **)&name2);
		retval = strcmp(name1, name2);
		free(name1);
	}
	return (retval);
}

/*
 * Compare two elements for purposes of ordering.
 * Return:
 *	< 0 if e1 is "before" e2
 *	0 if e1 "equals" e2
 *	> 0 if e1 comes after e2
 */
int
pool_elem_compare(const pool_elem_t *e1, const pool_elem_t *e2)
{
	pool_value_t val = POOL_VALUE_INITIALIZER;
	int64_t sys_id1, sys_id2;

	/*
	 * We may be asked to compare two elements from different classes.
	 * They are different so return the difference in their classes
	 */
	if (pool_elem_same_class(e1, e2) != PO_TRUE)
		return (1);

	/*
	 * If the class is PEC_SYSTEM, always match them
	 */
	if (pool_elem_class(e1) == PEC_SYSTEM)
		return (0);

	/*
	 * Compare with sys_id
	 */
	if (pool_get_ns_property(e1, c_sys_prop, &val) == POC_INVAL) {
		assert(!"no sys_id on e1\n");
	}
	(void) pool_value_get_int64(&val, &sys_id1);
	if (pool_get_ns_property(e2, c_sys_prop, &val) == POC_INVAL) {
		assert(!"no sys_id on e2\n");
	}
	(void) pool_value_get_int64(&val, &sys_id2);
	return (sys_id1 - sys_id2);
}

/*
 * Return PO_TRUE if the supplied elems are of the same class.
 */
int
pool_elem_same_class(const pool_elem_t *e1, const pool_elem_t *e2)
{
	if (pool_elem_class(e1) != pool_elem_class(e2))
		return (PO_FALSE);

	/*
	 * Check to make sure the fundamental class of the elements match
	 */
	if (pool_elem_class(e1) == PEC_RES_COMP ||
	    pool_elem_class(e1) == PEC_RES_AGG)
		if (pool_resource_elem_class(e1) !=
		    pool_resource_elem_class(e2))
			return (PO_FALSE);
	if (pool_elem_class(e1) == PEC_COMP)
		if (pool_component_elem_class(e1) !=
		    pool_component_elem_class(e2))
			return (PO_FALSE);
	return (PO_TRUE);
}

/*
 * pool_conf_check() checks that the configuration state isn't invalid
 * and that the configuration was opened for modification.
 */
int
pool_conf_check(const pool_conf_t *conf)
{
	if (pool_conf_status(conf) == POF_INVALID) {
		pool_seterror(POE_BADPARAM);
		return (PO_FAIL);
	}

	if ((conf->pc_prov->pc_oflags & PO_RDWR) == 0) {
		pool_seterror(POE_BADPARAM);
		return (PO_FAIL);
	}
	return (PO_SUCCESS);
}
