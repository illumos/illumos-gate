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
 * Routines used by inetd to read inetd's configuration from the repository,
 * to validate it and setup inetd's data structures appropriately based on
 * in.
 */

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <netdb.h>
#include <netinet/in.h>
#include <libintl.h>
#include <nss_dbdefs.h>
#include <signal.h>
#include <wait.h>
#include "inetd_impl.h"


/* method timeout used if one isn't explicitly specified */
#define	DEFAULT_METHOD_TIMEOUT	10


/* supported method properties and their attributes */
static inetd_prop_t method_props[] = {
{PR_EXEC_NAME, "", INET_TYPE_STRING, B_FALSE, IVE_UNSET, 0, B_FALSE},
{PR_ARG0_NAME, "", INET_TYPE_STRING, B_TRUE, IVE_UNSET, 0, B_FALSE},
{SCF_PROPERTY_TIMEOUT, "", INET_TYPE_COUNT, B_TRUE, IVE_UNSET, 0, B_FALSE},
{NULL},
};

/* enumeration of method properties; used to index into method_props[] */
typedef enum {
	MP_EXEC,
	MP_ARG0,
	MP_TIMEOUT
} method_prop_t;


/* handle used for repository access in read_prop() */
static scf_handle_t	*rep_handle = NULL;

/* pool used to create proto_info_t lists (generic proto info structure) */
static uu_list_pool_t	*proto_info_pool = NULL;

static void destroy_method_props(inetd_prop_t *);
static int proto_info_compare(const void *, const void *, void *);

int
config_init(void)
{
	if ((rep_handle = scf_handle_create(SCF_VERSION)) == NULL) {
		error_msg("%s: %s",
		    gettext("Failed to create repository handle"),
		    scf_strerror(scf_error()));
		return (-1);
	} else if (make_handle_bound(rep_handle) == -1) {
		/* let config_fini clean-up */
		return (-1);
	}

	if ((proto_info_pool = uu_list_pool_create("proto_info_pool",
	    sizeof (proto_info_t), offsetof(proto_info_t, link),
	    proto_info_compare, UU_LIST_POOL_DEBUG)) == NULL) {
		error_msg(gettext("Failed to create uu list pool: %s"),
		    uu_strerror(uu_error()));
		return (-1);
	}

	return (0);
}

void
config_fini(void)
{
	if (rep_handle == NULL)
		return;

	if (proto_info_pool != NULL) {
		uu_list_pool_destroy(proto_info_pool);
		proto_info_pool = NULL;
	}

	(void) scf_handle_unbind(rep_handle);
	scf_handle_destroy(rep_handle);
	rep_handle = NULL;
}

static void
destroy_method_info(method_info_t *mi)
{
	if (mi == NULL)
		return;

	if (mi->wordexp_arg0_backup != NULL) {
		/*
		 * Return the wordexp structure back to its original
		 * state so it can be consumed by wordfree.
		 */
		free(mi->exec_args_we.we_wordv[0]);
		mi->exec_args_we.we_wordv[0] =
		    (char *)mi->wordexp_arg0_backup;
	}

	free(mi->exec_path);

	wordfree(&mi->exec_args_we);

	free(mi);
}

/*
 * Transforms the properties read from the repository for a method into a
 * method_info_t and returns a pointer to it. If expansion of the exec
 * property fails, due to an invalid string or memory allocation failure,
 * NULL is returned and exec_invalid is set appropriately to indicate whether
 * it was a memory allocation failure or an invalid exec string.
 */
static method_info_t *
create_method_info(const inetd_prop_t *mprops, boolean_t *exec_invalid)
{
	method_info_t	*ret;
	int		i;

	if ((ret = calloc(1, sizeof (method_info_t))) == NULL)
		goto alloc_fail;

	/* Expand the exec string. */
	if ((i = wordexp(get_prop_value_string(mprops, PR_EXEC_NAME),
	    &ret->exec_args_we, WRDE_NOCMD|WRDE_UNDEF)) != 0) {
		if (i == WRDE_NOSPACE)
			goto alloc_fail;

		*exec_invalid = B_TRUE;
		free(ret);
		return (NULL);
	}

	if ((ret->exec_path = strdup(ret->exec_args_we.we_wordv[0])) == NULL)
		goto alloc_fail;

	if (mprops[MP_ARG0].ip_error == IVE_VALID) {	/* arg0 is set */
		/*
		 * Keep a copy of arg0 of the wordexp structure so that
		 * wordfree() gets passed what wordexp() originally returned,
		 * as documented as required in the man page.
		 */
		ret->wordexp_arg0_backup = ret->exec_args_we.we_wordv[0];
		if ((ret->exec_args_we.we_wordv[0] =
		    strdup(get_prop_value_string(mprops, PR_ARG0_NAME)))
		    == NULL)
			goto alloc_fail;
	}

	if (mprops[MP_TIMEOUT].ip_error == IVE_VALID) {
		ret->timeout = get_prop_value_count(mprops,
		    SCF_PROPERTY_TIMEOUT);
	} else {
		ret->timeout = DEFAULT_METHOD_TIMEOUT;
	}

	/* exec_invalid not set on success */

	return (ret);

alloc_fail:
	error_msg(strerror(errno));
	destroy_method_info(ret);
	*exec_invalid = B_FALSE;
	return (NULL);
}

/*
 * Returns B_TRUE if the contents of the 2 method_info_t structures are
 * equivalent, else B_FALSE.
 */
boolean_t
method_info_equal(const method_info_t *mi, const method_info_t *mi2)
{
	int		i;

	if ((mi == NULL) && (mi2 == NULL)) {
		return (B_TRUE);
	} else if (((mi == NULL) || (mi2 == NULL)) ||
	    (mi->exec_args_we.we_wordc != mi2->exec_args_we.we_wordc) ||
	    (strcmp(mi->exec_path, mi2->exec_path) != 0)) {
		return (B_FALSE);
	}

	for (i = 0; i < mi->exec_args_we.we_wordc; i++) {
		if (strcmp(mi->exec_args_we.we_wordv[i],
		    mi2->exec_args_we.we_wordv[i]) != 0) {
			return (B_FALSE);
		}
	}

	return (B_TRUE);
}

/*
 * Checks if the contents of the 2 socket_info_t structures are equivalent.
 * If 'isrpc' is false, the address components of the two structures are
 * compared for equality as part of this. If the two structures are
 * equivalent B_TRUE is returned, else B_FALSE.
 */
boolean_t
socket_info_equal(const socket_info_t *si, const socket_info_t *si2,
    boolean_t isrpc)
{
	return ((isrpc || (memcmp(&si->local_addr, &si2->local_addr,
	    sizeof (si->local_addr)) == 0)) &&
	    (si->type == si2->type));

}

/*
 * proto_info_t comparison function. Returns 0 on match, else -1, as required
 * by uu_list_find().
 */
static int
proto_info_compare(const void *lv, const void *rv, void *istlx)
{
	proto_info_t	*pi = (proto_info_t *)lv;
	proto_info_t	*pi2 = (proto_info_t *)rv;

	/* check their RPC configuration matches */
	if (pi->ri != NULL) {
		if ((pi2->ri == NULL) || !rpc_info_equal(pi->ri, pi2->ri))
			return (-1);
	} else if (pi2->ri != NULL) {
		return (-1);
	}

	if (pi->v6only != pi2->v6only)
		return (-1);

	if (*(boolean_t *)istlx) {
		if (tlx_info_equal((tlx_info_t *)lv, (tlx_info_t *)rv,
		    pi->ri != NULL))
			return (0);
	} else {
		if (socket_info_equal((socket_info_t *)lv,
		    (socket_info_t *)rv, pi->ri != NULL))
			return (0);
	}
	return (-1);
}

/*
 * Returns B_TRUE if the bind configuration of the two instance_cfg_t
 * structures are equivalent, else B_FALSE.
 */
boolean_t
bind_config_equal(const basic_cfg_t *c1, const basic_cfg_t *c2)
{
	proto_info_t	*pi;

	if ((c1->iswait != c2->iswait) ||
	    (c1->istlx != c2->istlx))
		return (B_FALSE);

	if (uu_list_numnodes(c1->proto_list) !=
	    uu_list_numnodes(c2->proto_list))
		return (B_FALSE);
	/*
	 * For each element in the first configuration's socket/tlx list,
	 * check there's a matching one in the other list.
	 */
	for (pi = uu_list_first(c1->proto_list); pi != NULL;
	    pi = uu_list_next(c1->proto_list, pi)) {
		uu_list_index_t idx;

		if (uu_list_find(c2->proto_list, pi, (void *)&c1->istlx,
		    &idx) == NULL)
			return (B_FALSE);
	}

	return (B_TRUE);
}

/*
 * Write the default values contained in 'bprops', read by
 * read_instance_props(), into 'cfg'.
 * Returns -1 if memory allocation fails, else 0.
 */
static int
populate_defaults(inetd_prop_t *bprops, basic_cfg_t *cfg)
{
	cfg->do_tcp_wrappers = get_prop_value_boolean(bprops,
	    PR_DO_TCP_WRAPPERS_NAME);
	cfg->do_tcp_trace = get_prop_value_boolean(bprops,
	    PR_DO_TCP_TRACE_NAME);
	cfg->do_tcp_keepalive = get_prop_value_boolean(bprops,
	    PR_DO_TCP_KEEPALIVE_NAME);
	cfg->inherit_env = get_prop_value_boolean(bprops, PR_INHERIT_ENV_NAME);
	cfg->wait_fail_cnt = get_prop_value_int(bprops,
	    PR_MAX_FAIL_RATE_CNT_NAME);
	cfg->wait_fail_interval =  get_prop_value_int(bprops,
	    PR_MAX_FAIL_RATE_INTVL_NAME);
	cfg->max_copies = get_prop_value_int(bprops, PR_MAX_COPIES_NAME);
	cfg->conn_rate_offline = get_prop_value_int(bprops,
	    PR_CON_RATE_OFFLINE_NAME);
	cfg->conn_rate_max = get_prop_value_int(bprops, PR_CON_RATE_MAX_NAME);
	cfg->bind_fail_interval = get_prop_value_int(bprops,
	    PR_BIND_FAIL_INTVL_NAME);
	cfg->bind_fail_max = get_prop_value_int(bprops, PR_BIND_FAIL_MAX_NAME);
	cfg->conn_backlog = get_prop_value_int(bprops,
	    PR_CONNECTION_BACKLOG_NAME);
	if ((cfg->bind_addr =
	    strdup(get_prop_value_string(bprops, PR_BIND_ADDR_NAME))) == NULL) {
		error_msg(strerror(errno));
		return (-1);
	}
	return (0);
}

void
destroy_method_infos(method_info_t **mis)
{
	int i;

	for (i = 0; i < NUM_METHODS; i++) {
		destroy_method_info(mis[i]);
		mis[i] = NULL;
	}
}

/*
 * For each method, if it was specifed convert its entry in 'mprops',
 * into an entry in 'mis'. Returns -1 if memory allocation fails or one of the
 * exec strings was invalid, else 0.
 */
static int
create_method_infos(const char *fmri, inetd_prop_t **mprops,
    method_info_t **mis)
{
	int i;

	for (i = 0; i < NUM_METHODS; i++) {
		/*
		 * Only create a method info structure if the method properties
		 * contain an exec string, which we take to mean the method
		 * is specified.
		 */
		if (mprops[i][MP_EXEC].ip_error == IVE_VALID) {
			boolean_t exec_invalid;

			if ((mis[i] = create_method_info(mprops[i],
			    &exec_invalid)) == NULL) {
				if (exec_invalid) {
					error_msg(gettext("Property %s for "
					    "method %s of instance %s is "
					    "invalid"), PR_EXEC_NAME,
					    methods[i].name, fmri);
				}
				return (-1);
			}
		}
	}
	return (0);
}

/*
 * Try and read each of the method properties for the method 'method' of
 * instance 'inst', and return a table containing all method properties. If an
 * error occurs, NULL is returned, with 'err' set to indicate the cause.
 * Otherwise, a pointer to an inetd_prop_t table is returned containing all
 * the method properties, and each of the properties is flagged according to
 * whether it was present or not, and if it was present its value is set in
 * the property's entry in the table.
 */
static inetd_prop_t *
read_method_props(const char *inst, instance_method_t method, scf_error_t *err)
{
	inetd_prop_t	*ret;
	int		i;

	if ((ret = calloc(1, sizeof (method_props))) == NULL) {
		*err = SCF_ERROR_NO_MEMORY;
		return (NULL);
	}

	(void) memcpy(ret, method_props, sizeof (method_props));
	for (i = 0; ret[i].ip_name != NULL; i++) {
		*err = read_prop(rep_handle, &ret[i], i, inst,
		    methods[method].name);
		if ((*err != 0) && (*err != SCF_ERROR_NOT_FOUND)) {
			destroy_method_props(ret);
			return (NULL);
		}
	}

	return (ret);
}

static void
destroy_method_props(inetd_prop_t *mprop)
{
	int i;

	if (mprop == NULL)
		return;

	for (i = 0; mprop[i].ip_name != NULL; i++) {
		if (mprop[i].ip_type == INET_TYPE_STRING &&
		    mprop[i].ip_error == IVE_VALID)
			free(mprop[i].ip_value.iv_string);
	}

	free(mprop);
}

/*
 * Destroy the basic and method properties returned by read_inst_props().
 */
static void
destroy_inst_props(inetd_prop_t *bprops, inetd_prop_t **mprops)
{
	int	i;

	free_instance_props(bprops);
	for (i = 0; i < NUM_METHODS; i++)
		destroy_method_props(mprops[i]);
}

/*
 * Read all the basic and method properties for instance 'inst', as inetd_prop_t
 * tables, into the spaces referenced by 'bprops' and 'mprops' respectively.
 * Each of the properties in the tables are flagged to indicate if the
 * property was present or not, and if it was the value is stored within it.
 * If an error occurs at any time -1 is returned and 'err' is set to
 * indicate the reason, else 0 is returned.
 */
static int
read_inst_props(const char *fmri, inetd_prop_t **bprops,
    inetd_prop_t **mprops, scf_error_t *err)
{
	size_t		nprops;
	int		i;

	if ((*bprops = read_instance_props(rep_handle, (char *)fmri, &nprops,
	    err)) == NULL)
		return (-1);

	for (i = 0; i < NUM_METHODS; i++) {
		if ((mprops[i] =
		    read_method_props(fmri, (instance_method_t)i, err)) ==
		    NULL) {
			for (i--; i >= 0; i--)
				destroy_method_props(mprops[i]);
			free_instance_props(*bprops);
			return (-1);
		}
	}

	return (0);
}

/*
 * Returns B_TRUE if all required properties were read from the repository
 * (whether taken from the defaults or directly from the instance), they
 * all had valid values, all the required methods were present, and they
 * each had the required properties with valid values. Else, returns B_FALSE.
 * If the function returns B_TRUE, the storage referenced by 'cfg' is set
 * to point at an allocated instance_cfg_t initialized based on the basic
 * properties (not method or defaults).
 */
static boolean_t
valid_inst_props(const char *fmri, inetd_prop_t *bprops, inetd_prop_t **mprops,
    basic_cfg_t **cfg)
{
	boolean_t	valid;
	size_t		num_bprops;
	int		i;

	valid = valid_props(bprops, fmri, cfg, proto_info_pool, conn_ind_pool);

	/*
	 * Double check we've got all necessary properties (valid_props()
	 * doesn't enforce the presence of defaults), and output error messages
	 * for each invalid/ missing property.
	 */
	(void) get_prop_table(&num_bprops);
	for (i = 0; bprops[i].ip_name != NULL; i++) {
		switch (bprops[i].ip_error) {
		case IVE_UNSET:
			if (!bprops[i].ip_default)
				continue;
			if ((i == PT_ARG0_INDEX) || (i == PT_EXEC_INDEX))
				continue;
			/* FALLTHROUGH */
		case IVE_INVALID:
			error_msg(gettext("Property '%s' of instance "
			    "%s is missing, inconsistent or invalid"),
			    bprops[i].ip_name, fmri);
			valid = B_FALSE;
		}
	}

	for (i = 0; i < NUM_METHODS; i++) {
		int	j;

		/* check if any properties are set */
		for (j = 0; mprops[i][j].ip_name != NULL; j++) {
			if (mprops[i][j].ip_error != IVE_UNSET)
				break;
		}

		if (mprops[i][j].ip_name == NULL) {
			/* an unspecified method */
			if ((instance_method_t)i == IM_START) {
				error_msg(gettext(
				    "Unspecified %s method for instance %s"),
				    START_METHOD_NAME, fmri);
				valid = B_FALSE;
			}
		} else if (mprops[i][MP_EXEC].ip_error == IVE_UNSET) {
			error_msg(gettext("Missing %s property from method %s "
			    "of instance %s"), PR_EXEC_NAME,
			    methods[(instance_method_t)i].name, fmri);
			valid = B_FALSE;
		}
	}

	if (!valid) {
		destroy_basic_cfg(*cfg);
		*cfg = NULL;
	}

	return (valid);
}

void
destroy_instance_cfg(instance_cfg_t *cfg)
{
	if (cfg != NULL) {
		destroy_basic_cfg(cfg->basic);
		destroy_method_infos(cfg->methods);
		free(cfg);
	}
}

/*
 * Returns an allocated instance_cfg_t representation of an instance's
 * configuration read from the repository. If the configuration is invalid, a
 * repository error occurred, or a memory allocation occurred returns NULL,
 * else returns a pointer to the allocated instance_cfg_t.
 */
instance_cfg_t *
read_instance_cfg(const char *fmri)
{
	uint_t		retries;
	inetd_prop_t	*bprops;
	inetd_prop_t	*mprops[NUM_METHODS];
	instance_cfg_t	*ret = NULL;
	scf_error_t	err;

	if ((ret = calloc(1, sizeof (instance_cfg_t))) == NULL)
		return (NULL);

	for (retries = 0; retries <= REP_OP_RETRIES; retries++) {
		if (make_handle_bound(rep_handle) == -1) {
			err = scf_error();
			goto read_error;
		}

		if (read_inst_props(fmri, &bprops, mprops, &err) == 0)
			break;
		if (err != SCF_ERROR_CONNECTION_BROKEN)
			goto read_error;
		(void) scf_handle_unbind(rep_handle);
	}
	if (retries > REP_OP_RETRIES)
		goto read_error;

	/*
	 * Switch off validation of the start method's exec string, since
	 * during boot the filesystem it resides on may not have been
	 * mounted yet, which would result in a false validation failure.
	 * We'll catch any real errors when the start method is first run
	 * in passes_basic_exec_checks().
	 */
	bprops[PT_EXEC_INDEX].ip_error = IVE_UNSET;

	if ((!valid_inst_props(fmri, bprops, mprops, &ret->basic)) ||
	    (populate_defaults(bprops, ret->basic) != 0) ||
	    (create_method_infos(fmri, mprops, ret->methods) != 0)) {
		destroy_instance_cfg(ret);
		ret = NULL;
	}

	destroy_inst_props(bprops, mprops);
	return (ret);

read_error:
	error_msg(gettext(
	    "Failed to read the configuration of instance %s: %s"), fmri,
	    scf_strerror(err));
	free(ret);
	return (NULL);
}

/*
 * Returns a pointer to an allocated method context for the specified method
 * of the specified instance if it could retrieve it. Else, if there were
 * errors retrieving it, NULL is returned and the pointer referenced by
 * 'errstr' is set to point at an appropriate error string.
 */
struct method_context *
read_method_context(const char *inst_fmri, const char *method, const char *path)
{
	scf_instance_t			*scf_inst = NULL;
	struct method_context		*ret;
	uint_t				retries;
	mc_error_t			*tmperr;
	char				*fail;

	fail = gettext("Failed to retrieve method context for the %s method of "
	    "instance %s : %s");
	for (retries = 0; retries <= REP_OP_RETRIES; retries++) {
		if (make_handle_bound(rep_handle) == -1)
			goto inst_failure;

		if (((scf_inst = scf_instance_create(rep_handle)) != NULL) &&
		    (scf_handle_decode_fmri(rep_handle, inst_fmri, NULL, NULL,
		    scf_inst, NULL, NULL, SCF_DECODE_FMRI_EXACT) == 0))
			break;
		if (scf_error() != SCF_ERROR_CONNECTION_BROKEN) {
			scf_instance_destroy(scf_inst);
			goto inst_failure;
		}

		(void) scf_instance_destroy(scf_inst);
		scf_inst = NULL;

		(void) scf_handle_unbind(rep_handle);
	}
	if (retries > REP_OP_RETRIES)
		goto inst_failure;

	if ((tmperr = restarter_get_method_context(
	    RESTARTER_METHOD_CONTEXT_VERSION, scf_inst, NULL, method, path,
	    &ret)) != NULL) {
		ret = NULL;
		error_msg(fail, method, inst_fmri, tmperr->msg);
		restarter_mc_error_destroy(tmperr);
	}

	scf_instance_destroy(scf_inst);
	return (ret);

inst_failure:
	/*
	 * We can rely on this string not becoming invalid
	 * since we don't call bind_textdomain_codeset() or
	 * setlocale(3C) after initialization.
	 */
	error_msg(fail, method, inst_fmri,
	    gettext("failed to get instance from repository"));
	return (NULL);
}

/*
 * Reads the value of the enabled property from the named property group
 * of the given instance.
 * If an error occurs, the SCF error code is returned. The possible errors are:
 * - SCF_ERROR_INVALID_ARGUMENT: The enabled property is not a boolean.
 * - SCF_ERROR_NONE: No value exists for the enabled property.
 * - SCF_ERROR_CONNECTION_BROKEN: Repository connection broken.
 * - SCF_ERROR_NOT_FOUND: The property wasn't found.
 * - SCF_ERROR_NO_MEMORY: allocation failure.
 * Else 0 is returned and 'enabled' set appropriately.
 */
static scf_error_t
read_enable_prop(const char *fmri, boolean_t *enabled, const char *pg)
{
	scf_simple_prop_t	*sp;
	uint8_t			*u8p;

	if ((sp = scf_simple_prop_get(rep_handle, fmri, pg,
	    SCF_PROPERTY_ENABLED)) == NULL)
		return (scf_error());

	if ((u8p = scf_simple_prop_next_boolean(sp)) == NULL) {
		scf_simple_prop_free(sp);
		return (scf_error());
	}

	*enabled = (*u8p != 0);
	scf_simple_prop_free(sp);
	return (0);
}

/*
 * Reads the enabled value for the given instance FMRI. The read value
 * is based on a merge of the 'standard' enabled property, and the temporary
 * override one; the merge involves using the latter properties value if
 * present, else resporting to the formers. If an error occurs -1 is returned,
 * else 0 is returned and 'enabled' set approriately.
 */
int
read_enable_merged(const char *fmri, boolean_t *enabled)
{
	uint_t		retries;

	for (retries = 0; retries <= REP_OP_RETRIES; retries++) {
		if (make_handle_bound(rep_handle) == -1)
			goto gen_fail;

		switch (read_enable_prop(fmri, enabled, SCF_PG_GENERAL_OVR)) {
		case 0:
			debug_msg("read %d from override", *enabled);
			return (0);
		case SCF_ERROR_CONNECTION_BROKEN:
			break;
		case SCF_ERROR_NOT_FOUND:
		case SCF_ERROR_NONE:
		case SCF_ERROR_INVALID_ARGUMENT:
			switch (read_enable_prop(fmri, enabled,
			    SCF_PG_GENERAL)) {
			case 0:
				debug_msg("read %d from non_override",
				    *enabled);
				return (0);
			case SCF_ERROR_CONNECTION_BROKEN:
				break;
			case SCF_ERROR_NOT_FOUND:
			case SCF_ERROR_NONE:
			case SCF_ERROR_INVALID_ARGUMENT:
				error_msg(gettext("Missing %s property/value "
				    "for instance %s"), SCF_PROPERTY_ENABLED,
				    fmri);
				return (-1);
			default:
				goto gen_fail;
			}
			break;
		default:
			goto gen_fail;
		}

		(void) scf_handle_unbind(rep_handle);
		continue;
	}

gen_fail:
	error_msg(gettext("Failed to read the %s property of instance %s: %s"),
	    SCF_PROPERTY_ENABLED, fmri, scf_strerror(scf_error()));
	return (-1);
}

/*
 * Refresh the value of debug property under the property group "config"
 * for network/inetd service.
 */
void
refresh_debug_flag(void)
{
	scf_simple_prop_t	*sprop;
	uint8_t			*tmp_bool;

	if ((sprop = scf_simple_prop_get(rep_handle, INETD_INSTANCE_FMRI,
	    PG_NAME_APPLICATION_CONFIG, PR_NAME_DEBUG_FLAG)) == NULL) {
		error_msg(gettext("Unable to read %s property from %s property "
		    "group. scf_simple_prop_get() failed: %s"),
		    PR_NAME_DEBUG_FLAG, PG_NAME_APPLICATION_CONFIG,
		    scf_strerror(scf_error()));
		return;
	} else if ((tmp_bool = scf_simple_prop_next_boolean(sprop)) == NULL) {
		error_msg(gettext("Unable to read %s property for %s service. "
		    "scf_simple_prop_next_boolean() failed: %s"),
		    PR_NAME_DEBUG_FLAG, INETD_INSTANCE_FMRI,
		    scf_strerror(scf_error()));
	} else {
		debug_enabled = ((*tmp_bool == 0) ? B_FALSE : B_TRUE);
	}

	scf_simple_prop_free(sprop);
}
