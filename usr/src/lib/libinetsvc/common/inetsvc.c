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
 * This library contains a set of routines that are shared amongst inetd,
 * inetadm, inetconv and the formerly internal inetd services. Amongst the
 * routines are ones for reading and validating the configuration of an
 * inetd service, a routine for requesting inetd be refreshed, ones for
 * reading, calculating and writing the hash of an inetd.conf file, and
 * numerous utility routines shared amongst the formerly internal inetd
 * services.
 */


#include <string.h>
#include <rpc/rpcent.h>
#include <netdb.h>
#include <limits.h>
#include <errno.h>
#include <inetsvc.h>
#include <stdlib.h>
#include <unistd.h>
#include <nss_dbdefs.h>
#include <stdio.h>
#include <fcntl.h>
#include <pwd.h>
#include <md5.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <signal.h>
#include <syslog.h>
#include <libintl.h>
#include <stdlib.h>
#include <assert.h>
#include <rpc/nettype.h>
#include <libuutil.h>

static inetd_prop_t inetd_properties[] = {
	{PR_SVC_NAME_NAME, PG_NAME_SERVICE_CONFIG, INET_TYPE_STRING,
	    B_FALSE, IVE_UNSET, 0, B_FALSE},
	{PR_SOCK_TYPE_NAME, PG_NAME_SERVICE_CONFIG, INET_TYPE_STRING,
	    B_FALSE, IVE_UNSET, 0, B_FALSE},
	{PR_PROTO_NAME, PG_NAME_SERVICE_CONFIG, INET_TYPE_STRING_LIST,
	    B_FALSE, IVE_UNSET, 0, B_FALSE},
	{PR_ISRPC_NAME, PG_NAME_SERVICE_CONFIG, INET_TYPE_BOOLEAN,
	    B_FALSE, IVE_UNSET, 0, B_FALSE},
	{PR_RPC_LW_VER_NAME, PG_NAME_SERVICE_CONFIG, INET_TYPE_INTEGER,
	    B_FALSE, IVE_UNSET, 0, B_FALSE},
	{PR_RPC_HI_VER_NAME, PG_NAME_SERVICE_CONFIG, INET_TYPE_INTEGER,
	    B_FALSE, IVE_UNSET, 0, B_FALSE},
	{PR_ISWAIT_NAME, PG_NAME_SERVICE_CONFIG, INET_TYPE_BOOLEAN,
	    B_FALSE, IVE_UNSET, 0, B_FALSE},
	{PR_EXEC_NAME, START_METHOD_NAME, INET_TYPE_STRING,
	    B_FALSE, IVE_UNSET, 0, B_FALSE},
	{PR_ARG0_NAME, START_METHOD_NAME, INET_TYPE_STRING,
	    B_FALSE, IVE_UNSET, 0, B_FALSE},
	{PR_USER_NAME, START_METHOD_NAME, INET_TYPE_STRING,
	    B_FALSE, IVE_UNSET, 0, B_FALSE},
	{PR_BIND_ADDR_NAME, PG_NAME_SERVICE_CONFIG, INET_TYPE_STRING,
	    B_TRUE, IVE_UNSET, 0, B_FALSE},
	{PR_BIND_FAIL_MAX_NAME, PG_NAME_SERVICE_CONFIG, INET_TYPE_INTEGER,
	    B_TRUE, IVE_UNSET, 0, B_FALSE},
	{PR_BIND_FAIL_INTVL_NAME, PG_NAME_SERVICE_CONFIG, INET_TYPE_INTEGER,
	    B_TRUE, IVE_UNSET, 0, B_FALSE},
	{PR_CON_RATE_MAX_NAME, PG_NAME_SERVICE_CONFIG, INET_TYPE_INTEGER,
	    B_TRUE, IVE_UNSET, 0, B_FALSE},
	{PR_MAX_COPIES_NAME, PG_NAME_SERVICE_CONFIG, INET_TYPE_INTEGER,
	    B_TRUE, IVE_UNSET, 0, B_FALSE},
	{PR_CON_RATE_OFFLINE_NAME, PG_NAME_SERVICE_CONFIG, INET_TYPE_INTEGER,
	    B_TRUE, IVE_UNSET, 0, B_FALSE},
	{PR_MAX_FAIL_RATE_CNT_NAME, PG_NAME_SERVICE_CONFIG, INET_TYPE_INTEGER,
	    B_TRUE, IVE_UNSET, 0, B_FALSE},
	{PR_MAX_FAIL_RATE_INTVL_NAME, PG_NAME_SERVICE_CONFIG, INET_TYPE_INTEGER,
	    B_TRUE, IVE_UNSET, 0, B_FALSE},
	{PR_INHERIT_ENV_NAME, PG_NAME_SERVICE_CONFIG, INET_TYPE_BOOLEAN,
	    B_TRUE, IVE_UNSET, 0, B_FALSE},
	{PR_DO_TCP_TRACE_NAME, PG_NAME_SERVICE_CONFIG, INET_TYPE_BOOLEAN,
	    B_TRUE, IVE_UNSET, 0, B_FALSE},
	{PR_DO_TCP_WRAPPERS_NAME, PG_NAME_SERVICE_CONFIG, INET_TYPE_BOOLEAN,
	    B_TRUE, IVE_UNSET, 0, B_FALSE},
	{PR_CONNECTION_BACKLOG_NAME, PG_NAME_SERVICE_CONFIG, INET_TYPE_INTEGER,
	    B_TRUE, IVE_UNSET, 0, B_FALSE},
	{PR_DO_TCP_KEEPALIVE_NAME, PG_NAME_SERVICE_CONFIG, INET_TYPE_BOOLEAN,
	    B_TRUE, IVE_UNSET, 0, B_FALSE},
	{NULL},
};

#define	INETSVC_SVC_BUF_MAX (NSS_BUFLEN_RPC + sizeof (struct rpcent))

#define	DIGEST_LEN	16
#define	READ_BUFSIZ	8192
#define	HASH_PG		"hash"
#define	HASH_PROP	"md5sum"

/*
 * Inactivity timer used by dg_template(). After this many seconds of network
 * inactivity dg_template will cease listening for new datagrams and return.
 */
#define	DG_INACTIVITY_TIMEOUT	60

static boolean_t v6_proto(const char *);

boolean_t
is_tlx_service(inetd_prop_t *props)
{
	return ((strcmp(SOCKTYPE_TLI_STR,
	    props[PT_SOCK_TYPE_INDEX].ip_value.iv_string) == 0) ||
	    (strcmp(SOCKTYPE_XTI_STR,
	    props[PT_SOCK_TYPE_INDEX].ip_value.iv_string) == 0));
}

/*
 * Return a reference to the property table. Number of entries in table
 * are returned in num_elements argument.
 */
inetd_prop_t *
get_prop_table(size_t *num_elements)
{
	*num_elements = sizeof (inetd_properties) / sizeof (inetd_prop_t);
	return (&inetd_properties[0]);
}

/*
 * find_prop takes an array of inetd_prop_t's, the name of an inetd
 * property, the type expected, and returns a pointer to the matching member,
 * or NULL.
 */
inetd_prop_t *
find_prop(const inetd_prop_t *prop, const char *name, inet_type_t type)
{
	int		i = 0;

	while (prop[i].ip_name != NULL && strcmp(name, prop[i].ip_name) != 0)
		i++;

	if (prop[i].ip_name == NULL)
		return (NULL);

	if (prop[i].ip_type != type)
		return (NULL);

	return ((inetd_prop_t *)prop + i);
}

/*
 * get_prop_value_int takes an array of inetd_prop_t's together with the name of
 * an inetd property and returns the value of the property.  It's expected that
 * the property exists in the searched array.
 */
int64_t
get_prop_value_int(const inetd_prop_t *prop, const char *name)
{
	inetd_prop_t	*p;

	p = find_prop(prop, name, INET_TYPE_INTEGER);
	return (p->ip_value.iv_int);
}

/*
 * get_prop_value_count takes an array of inetd_prop_t's together with the name
 * of an inetd property and returns the value of the property.  It's expected
 * that the property exists in the searched array.
 */
uint64_t
get_prop_value_count(const inetd_prop_t *prop, const char *name)
{
	inetd_prop_t	*p;

	p = find_prop(prop, name, INET_TYPE_COUNT);
	return (p->ip_value.iv_cnt);
}

/*
 * get_prop_value_boolean takes an array of inetd_prop_t's together with the
 * name of an inetd property and returns the value of the property.  It's
 * expected that the property exists in the searched array.
 */
boolean_t
get_prop_value_boolean(const inetd_prop_t *prop, const char *name)
{
	inetd_prop_t	*p;

	p = find_prop(prop, name, INET_TYPE_BOOLEAN);
	return (p->ip_value.iv_boolean);
}

/*
 * get_prop_value_string takes an array of inetd_prop_t's together with
 * the name of an inetd property and returns the value of the property.
 * It's expected that the property exists in the searched array.
 */
const char *
get_prop_value_string(const inetd_prop_t *prop, const char *name)
{
	inetd_prop_t	*p;

	p = find_prop(prop, name, INET_TYPE_STRING);
	return (p->ip_value.iv_string);
}

/*
 * get_prop_value_string_list takes an array of inetd_prop_t's together
 * with the name of an inetd property and returns the value of the property.
 * It's expected that the property exists in the searched array.
 */
const char **
get_prop_value_string_list(const inetd_prop_t *prop, const char *name)
{
	inetd_prop_t	*p;

	p = find_prop(prop, name, INET_TYPE_STRING_LIST);
	return ((const char **)p->ip_value.iv_string_list);
}

/*
 * put_prop_value_int takes an array of inetd_prop_t's, a name of an inetd
 * property, and a value.  It copies the value into the property
 * in the array.  It's expected that the property exists in the searched array.
 */
void
put_prop_value_int(inetd_prop_t *prop, const char *name, int64_t value)
{
	inetd_prop_t	*p;

	p = find_prop(prop, name, INET_TYPE_INTEGER);
	p->ip_value.iv_int = value;
	p->ip_error = IVE_VALID;
}

/*
 * put_prop_value_count takes an array of inetd_prop_t's, a name of an inetd
 * property, and a value.  It copies the value into the property
 * in the array.  It's expected that the property exists in the searched array.
 */
void
put_prop_value_count(inetd_prop_t *prop, const char *name, uint64_t value)
{
	inetd_prop_t	*p;

	p = find_prop(prop, name, INET_TYPE_COUNT);
	p->ip_value.iv_cnt = value;
	p->ip_error = IVE_VALID;
}

/*
 * put_prop_value_boolean takes an array of inetd_prop_t's, a name of an inetd
 * property, and a value.  It copies the value into the property
 * in the array.  It's expected that the property exists in the searched array.
 */
void
put_prop_value_boolean(inetd_prop_t *prop, const char *name, boolean_t value)
{
	inetd_prop_t	*p;

	p = find_prop(prop, name, INET_TYPE_BOOLEAN);
	p->ip_value.iv_boolean = value;
	p->ip_error = IVE_VALID;
}

/*
 * put_prop_value_string takes an array of inetd_prop_t's, a name of an inetd
 * property, and a value.  It duplicates the value into the property
 * in the array, and returns B_TRUE for success and B_FALSE for failure.  It's
 * expected that the property exists in the searched array.
 */
boolean_t
put_prop_value_string(inetd_prop_t *prop, const char *name, const char *value)
{
	inetd_prop_t	*p;

	if (strlen(value) >= scf_limit(SCF_LIMIT_MAX_VALUE_LENGTH)) {
		errno = E2BIG;
		return (B_FALSE);
	}
	p = find_prop(prop, name, INET_TYPE_STRING);
	if ((p->ip_value.iv_string = strdup(value)) == NULL)
		return (B_FALSE);
	p->ip_error = IVE_VALID;
	return (B_TRUE);
}

/*
 * put_prop_value_string_list takes an array of inetd_prop_t's, a name of an
 * inetd property, and a value.  It copies the value into the property
 * in the array.  It's expected that the property exists in the searched array.
 */
void
put_prop_value_string_list(inetd_prop_t *prop, const char *name, char **value)
{
	inetd_prop_t	*p;

	p = find_prop(prop, name, INET_TYPE_STRING_LIST);
	p->ip_value.iv_string_list = value;
	p->ip_error = IVE_VALID;
}

static void
destroy_rpc_info(rpc_info_t *rpc)
{
	if (rpc != NULL) {
		free(rpc->netbuf.buf);
		free(rpc->netid);
		free(rpc);
	}
}

/*
 * If 'proto' is a valid netid,  and no memory allocations fail, returns a
 * pointer to an allocated and initialized rpc_info_t, else NULL.
 */
static rpc_info_t *
create_rpc_info(const char *proto, int pnum, int low_ver, int high_ver)
{
	struct netconfig	*nconf;
	rpc_info_t		*ret;

	if ((ret = calloc(1, sizeof (rpc_info_t))) == NULL)
		return (NULL);

	ret->netbuf.maxlen = sizeof (struct sockaddr_storage);
	if ((ret->netbuf.buf = malloc(ret->netbuf.maxlen)) == NULL) {
		free(ret);
		return (NULL);
	}

	ret->prognum = pnum;
	ret->lowver = low_ver;
	ret->highver = high_ver;

	if ((ret->netid = strdup(proto)) == NULL) {
		destroy_rpc_info(ret);
		return (NULL);
	}

	/*
	 * Determine whether this is a loopback transport. If getnetconfigent()
	 * fails, we check to see whether it was the result of a v6 proto
	 * being specified and no IPv6 interface was configured on the system;
	 * if this holds, we know it must not be a loopback transport, else
	 * getnetconfigent() must be miss-behaving, so return an error.
	 */
	if ((nconf = getnetconfigent(proto)) != NULL) {
		if (strcmp(nconf->nc_protofmly, NC_LOOPBACK) == 0)
			ret->is_loopback = B_TRUE;
		freenetconfigent(nconf);
	} else if (!v6_proto(proto)) {
		destroy_rpc_info(ret);
		return (NULL);
	}

	return (ret);
}

void
destroy_tlx_info(tlx_info_t *tlx)
{
	tlx_conn_ind_t  *ci;
	void		*cookie = NULL;

	if (tlx == NULL)
		return;

	free(tlx->dev_name);

	if (tlx->conn_ind_queue != NULL) {
		/* free up conn ind queue */
		while ((ci = uu_list_teardown(tlx->conn_ind_queue, &cookie)) !=
		    NULL) {
			(void) t_free((char *)ci->call, T_CALL);
			free(ci);
		}
		uu_list_destroy(tlx->conn_ind_queue);
	}

	free(tlx->local_addr.buf);
	free(tlx);
}

/*
 * Allocate, initialize and return a pointer to a tlx_info_t structure.
 * On memory allocation failure NULL is returned.
 */
static tlx_info_t *
create_tlx_info(const char *proto, uu_list_pool_t *conn_ind_pool)
{
	size_t			sz;
	tlx_info_t		*ret;

	if ((ret = calloc(1, sizeof (tlx_info_t))) == NULL)
		return (NULL);

	ret->local_addr.maxlen = sizeof (struct sockaddr_storage);
	if ((ret->local_addr.buf = calloc(1, ret->local_addr.maxlen)) == NULL)
		goto fail;

	if ((ret->conn_ind_queue = uu_list_create(conn_ind_pool, NULL, 0)) ==
	    NULL)
		goto fail;

	ret->local_addr.len = sizeof (struct sockaddr_in);
	/* LINTED E_BAD_PTR_CAST_ALIGN */
	((struct sockaddr_in *)(ret->local_addr.buf))->sin_family = AF_INET;
	/* LINTED E_BAD_PTR_CAST_ALIGN */
	((struct sockaddr_in *)(ret->local_addr.buf))->sin_addr.s_addr =
	    htonl(INADDR_ANY);

	/* store device name, constructing if necessary */
	if (proto[0] != '/') {
		sz = strlen("/dev/") + strlen(proto) + 1;
		if ((ret->dev_name = malloc(sz)) == NULL)
			goto fail;
		(void) snprintf(ret->dev_name, sz, "/dev/%s", proto);
	} else if ((ret->dev_name = strdup(proto)) == NULL) {
			goto fail;
	}

	return (ret);

fail:
	destroy_tlx_info(ret);
	return (NULL);
}

/*
 * Returns B_TRUE if this is a v6 protocol valid for both TLI and socket
 * based services, else B_FALSE.
 */
static boolean_t
v6_proto(const char *proto)
{
	return ((strcmp(proto, SOCKET_PROTO_TCP6) == 0) ||
	    (strcmp(proto, SOCKET_PROTO_UDP6) == 0));
}

/*
 * Returns B_TRUE if this is a valid v6 protocol for a socket based service,
 * else B_FALSE.
 */
static boolean_t
v6_socket_proto(const char *proto)
{
	return ((strcmp(proto, SOCKET_PROTO_SCTP6) == 0) ||
	    v6_proto(proto));

}

static boolean_t
valid_socket_proto(const char *proto)
{
	return (v6_socket_proto(proto) ||
	    (strcmp(proto, SOCKET_PROTO_SCTP) == 0) ||
	    (strcmp(proto, SOCKET_PROTO_TCP) == 0) ||
	    (strcmp(proto, SOCKET_PROTO_UDP) == 0));
}

/*
 * Free all the memory consumed by 'pi' associated with the instance
 * with configuration 'cfg'.
 */
static void
destroy_proto_info(basic_cfg_t *cfg, proto_info_t *pi)
{
	if (pi == NULL)
		return;

	assert(pi->listen_fd == -1);

	free(pi->proto);
	if (pi->ri != NULL)
		destroy_rpc_info(pi->ri);
	if (cfg->istlx) {
		destroy_tlx_info((tlx_info_t *)pi);
	} else {
		free(pi);
	}
}

void
destroy_proto_list(basic_cfg_t *cfg)
{
	void		*cookie = NULL;
	proto_info_t	*pi;

	if (cfg->proto_list == NULL)
		return;

	while ((pi = uu_list_teardown(cfg->proto_list, &cookie)) != NULL)
		destroy_proto_info(cfg, pi);
	uu_list_destroy(cfg->proto_list);
	cfg->proto_list = NULL;
}

void
destroy_basic_cfg(basic_cfg_t *cfg)
{
	if (cfg == NULL)
		return;

	free(cfg->bind_addr);
	destroy_proto_list(cfg);
	free(cfg->svc_name);
	free(cfg);
}

/*
 * Overwrite the socket address with the address specified by the
 * bind_addr property.
 */
static int
set_bind_addr(struct sockaddr_storage *ss, char *bind_addr)
{
	struct addrinfo hints, *res;

	if (bind_addr == NULL || bind_addr[0] == '\0')
		return (0);

	(void) memset(&hints, 0, sizeof (hints));
	hints.ai_flags = AI_DEFAULT;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_family = ss->ss_family;
	if (getaddrinfo(bind_addr, "", &hints, &res) != 0) {
		return (-1);
	} else {
		void *p = res->ai_addr;
		struct sockaddr_storage *newss = p;

		(void) memcpy(SS_SINADDR(*ss), SS_SINADDR(*newss),
		    SS_ADDRLEN(*ss));
		freeaddrinfo(res);
		return (0);
	}
}

/*
 * valid_props validates all the properties in an array of inetd_prop_t's,
 * marking each property as valid or invalid.  If any properties are invalid,
 * it returns B_FALSE, otherwise it returns B_TRUE.  Note that some properties
 * are interdependent, so if one is invalid, it leaves others in an
 * indeterminate state (such as ISRPC and SVC_NAME).  In this case, the
 * indeterminate property will be marked valid.  IE, the only properties
 * marked invalid are those that are KNOWN to be invalid.
 *
 * Piggy-backed onto this validation if 'fmri' is non-NULL is the construction
 * of a structured configuration, a basic_cfg_t,  which is used by inetd.
 * If 'fmri' is set then the latter three parameters need to be set to
 * non-NULL values, and if the configuration is valid, the storage referenced
 * by cfgpp is set to point at an initialized basic_cfg_t.
 */
boolean_t
valid_props(inetd_prop_t *prop, const char *fmri, basic_cfg_t **cfgpp,
    uu_list_pool_t *proto_info_pool, uu_list_pool_t *tlx_ci_pool)
{
	char			*bufp, *cp;
	boolean_t		ret = B_TRUE;
	int			i;
	long			uidl;
	boolean_t		isrpc;
	int			sock_type_id;
	int			rpc_pnum;
	int			rpc_lv, rpc_hv;
	basic_cfg_t		*cfg;
	char			*proto = NULL;
	int			pi;
	char			**netids = NULL;
	int			ni = 0;

	if (fmri != NULL)
		assert((cfgpp != NULL) && (proto_info_pool != NULL) &&
		    (tlx_ci_pool != NULL));

	/*
	 * Set all checkable properties to valid as a baseline.  We'll be
	 * marking all invalid properties.
	 */
	for (i = 0; prop[i].ip_name != NULL; i++) {
		if (prop[i].ip_error != IVE_UNSET)
			prop[i].ip_error = IVE_VALID;
	}

	if (((cfg = calloc(1, sizeof (basic_cfg_t))) == NULL) ||
	    ((fmri != NULL) &&
	    ((cfg->proto_list = uu_list_create(proto_info_pool, NULL, 0)) ==
	    NULL))) {
		free(cfg);
		return (B_FALSE);
	}

	/* Check a service name was supplied */
	if ((prop[PT_SVC_NAME_INDEX].ip_error == IVE_UNSET) ||
	    ((cfg->svc_name =
	    strdup(prop[PT_SVC_NAME_INDEX].ip_value.iv_string)) == NULL))
		prop[PT_SVC_NAME_INDEX].ip_error = IVE_INVALID;

	/* Check that iswait and isrpc have valid boolean values */

	if ((prop[PT_ISWAIT_INDEX].ip_error == IVE_UNSET) ||
	    (((cfg->iswait = prop[PT_ISWAIT_INDEX].ip_value.iv_boolean) !=
	    B_TRUE) && (cfg->iswait != B_FALSE)))
		prop[PT_ISWAIT_INDEX].ip_error = IVE_INVALID;

	if ((prop[PT_ISRPC_INDEX].ip_error == IVE_UNSET) ||
	    (((isrpc = prop[PT_ISRPC_INDEX].ip_value.iv_boolean) != B_TRUE) &&
	    (isrpc != B_FALSE))) {
		prop[PT_ISRPC_INDEX].ip_error = IVE_INVALID;
	} else if (isrpc) {
		/*
		 * This is an RPC service, so ensure that the RPC version
		 * numbers are zero or greater, that the low version isn't
		 * greater than the high version and a valid program name
		 * is supplied.
		 */

		if ((prop[PT_RPC_LW_VER_INDEX].ip_error == IVE_UNSET) ||
		    ((rpc_lv = prop[PT_RPC_LW_VER_INDEX].ip_value.iv_int) <
		    0))
			prop[PT_RPC_LW_VER_INDEX].ip_error = IVE_INVALID;

		if ((prop[PT_RPC_HI_VER_INDEX].ip_error == IVE_UNSET) ||
		    ((rpc_hv = prop[PT_RPC_HI_VER_INDEX].ip_value.iv_int) <
		    0))
			prop[PT_RPC_HI_VER_INDEX].ip_error = IVE_INVALID;

		if ((prop[PT_RPC_LW_VER_INDEX].ip_error != IVE_INVALID) &&
		    (prop[PT_RPC_HI_VER_INDEX].ip_error != IVE_INVALID) &&
		    (rpc_lv > rpc_hv)) {
			prop[PT_RPC_LW_VER_INDEX].ip_error = IVE_INVALID;
			prop[PT_RPC_HI_VER_INDEX].ip_error = IVE_INVALID;
		}

		if ((cfg->svc_name != NULL) &&
		    ((rpc_pnum = get_rpc_prognum(cfg->svc_name)) == -1))
			prop[PT_SVC_NAME_INDEX].ip_error = IVE_INVALID;
	}

	/* Check that the socket type is one of the acceptable values. */
	cfg->istlx = B_FALSE;
	if ((prop[PT_SOCK_TYPE_INDEX].ip_error == IVE_UNSET) ||
	    ((sock_type_id = get_sock_type_id(
	    prop[PT_SOCK_TYPE_INDEX].ip_value.iv_string)) == -1) &&
	    !(cfg->istlx = is_tlx_service(prop)))
		prop[PT_SOCK_TYPE_INDEX].ip_error = IVE_INVALID;

	/* Get the bind address */
	if (!cfg->istlx && prop[PT_BIND_ADDR_INDEX].ip_error != IVE_UNSET &&
	    (cfg->bind_addr =
	    strdup(prop[PT_BIND_ADDR_INDEX].ip_value.iv_string)) == NULL)
		prop[PT_BIND_ADDR_INDEX].ip_error = IVE_INVALID;

	/*
	 * Iterate through all the different protos/netids resulting from the
	 * proto property and check that they're valid and perform checks on
	 * other fields that are tied-in with the proto.
	 */

	pi = 0;
	do {
		socket_info_t		*si = NULL;
		tlx_info_t		*ti = NULL;
		proto_info_t		*p_inf = NULL;
		boolean_t		v6only = B_FALSE;
		char			*only;
		boolean_t		invalid_proto = B_FALSE;
		char			**protos;
		struct protoent		pe;
		char			gpbuf[1024];
		struct netconfig	*nconf = NULL;

		/*
		 * If we don't know whether it's an rpc service or its
		 * endpoint type, we can't do any of the proto checks as we
		 * have no context; break out.
		 */
		if ((prop[PT_ISRPC_INDEX].ip_error != IVE_VALID) ||
		    (prop[PT_SOCK_TYPE_INDEX].ip_error != IVE_VALID))
			break;

		/* skip proto specific processing if the proto isn't set. */
		if (prop[PT_PROTO_INDEX].ip_error == IVE_UNSET) {
			invalid_proto = B_TRUE;
			goto past_proto_processing;
		}
		protos = prop[PT_PROTO_INDEX].ip_value.iv_string_list;

		/*
		 * Get the next netid/proto.
		 */

		if (!cfg->istlx || !isrpc) {
			proto = protos[pi++];
		/*
		 * This is a TLI/RPC service, so get the next netid, expanding
		 * any supplied nettype.
		 */
		} else if ((netids == NULL) ||
		    ((proto = netids[ni++]) == NULL)) {
			/*
			 * Either this is the first time around or
			 * we've exhausted the last set of netids, so
			 * try and get the next set using the currently
			 * indexed proto entry.
			 */

			if (netids != NULL) {
				destroy_strings(netids);
				netids = NULL;
			}

			if (protos[pi] != NULL) {
				if ((netids = get_netids(protos[pi++])) ==
				    NULL) {
					invalid_proto = B_TRUE;
					proto = protos[pi - 1];
				} else {
					ni = 0;
					proto = netids[ni++];
				}
			} else {
				proto = NULL;
			}
		}

		if (proto == NULL)
			break;

		if (invalid_proto)
			goto past_proto_processing;

		/* strip a trailing only to simplify further processing */
		only = proto + strlen(proto) - (sizeof ("6only") - 1);
		if ((only > proto) && (strcmp(only, "6only") == 0)) {
			*++only = '\0';
			v6only = B_TRUE;
		}

		/* validate the proto/netid */

		if (!cfg->istlx) {
			if (!valid_socket_proto(proto))
				invalid_proto = B_TRUE;
		} else {
			/*
			 * Check if we've got a valid netid. If
			 * getnetconfigent() fails, we check to see whether
			 * we've got a v6 netid that may have been rejected
			 * because no IPv6 interface was configured before
			 * flagging 'proto' as invalid. If the latter condition
			 * holds, we don't flag the proto as invalid, and
			 * leave inetd to handle the value appropriately
			 * when it tries to listen on behalf of the service.
			 */
			if (((nconf = getnetconfigent(proto)) == NULL) &&
			    !v6_proto(proto))
				invalid_proto = B_TRUE;
		}
		if (invalid_proto)
			goto past_proto_processing;

		/*
		 * dissallow datagram type nowait services
		 */
		if ((prop[PT_ISWAIT_INDEX].ip_error == IVE_VALID) &&
		    !cfg->iswait) {
			if (strncmp(proto, SOCKET_PROTO_UDP,
			    sizeof (SOCKET_PROTO_UDP) - 1) == 0) {
				invalid_proto = B_TRUE;
			} else if (cfg->istlx && (nconf != NULL) &&
			    (nconf->nc_semantics == NC_TPI_CLTS)) {
					invalid_proto = B_TRUE;
			}
			if (invalid_proto) {
				prop[PT_ISWAIT_INDEX].ip_error = IVE_INVALID;
				goto past_proto_processing;
			}
		}

		/*
		 * We're running in validate only mode. Don't bother creating
		 * any proto structures (they don't do any further validation).
		 */
		if (fmri == NULL)
			goto past_proto_processing;

		/*
		 * Create the apropriate transport info structure.
		 */
		if (cfg->istlx) {
			if ((ti = create_tlx_info(proto, tlx_ci_pool)) != NULL)
				p_inf = (proto_info_t *)ti;
		} else {
			struct sockaddr_storage *ss;

			if ((si = calloc(1, sizeof (socket_info_t))) != NULL) {
				p_inf = (proto_info_t *)si;
				si->type = sock_type_id;
				ss = &si->local_addr;

				if (v6_socket_proto(proto)) {
					ss->ss_family = AF_INET6;
					/* already in network order */
					((struct sockaddr_in6 *)ss)->sin6_addr =
					    in6addr_any;
				} else {
					ss->ss_family = AF_INET;
					((struct sockaddr_in *)ss)->sin_addr.
					    s_addr = htonl(INADDR_ANY);
				}
				if (set_bind_addr(ss, cfg->bind_addr) != 0) {
					prop[PT_BIND_ADDR_INDEX].ip_error =
					    IVE_INVALID;
				}
			}
		}
		if (p_inf == NULL) {
			invalid_proto = B_TRUE;
			goto past_proto_processing;
		}

		p_inf->v6only = v6only;

		/*
		 * Store the supplied proto string for error reporting,
		 * re-attaching the 'only' suffix if one was taken off.
		 */
		if ((p_inf->proto = malloc(strlen(proto) + 5)) == NULL) {
			invalid_proto = B_TRUE;
			goto past_proto_processing;
		} else {
			(void) strlcpy(p_inf->proto, proto, strlen(proto) + 5);
			if (v6only)
				(void) strlcat(p_inf->proto, "only",
				    strlen(proto) + 5);
		}

		/*
		 * Validate and setup RPC/non-RPC specifics.
		 */

		if (isrpc) {
			rpc_info_t *ri;

			if ((rpc_pnum != -1) && (rpc_lv != -1) &&
			    (rpc_hv != -1)) {
				if ((ri = create_rpc_info(proto, rpc_pnum,
				    rpc_lv, rpc_hv)) == NULL) {
					invalid_proto = B_TRUE;
				} else {
					p_inf->ri = ri;
				}
			}
		}

past_proto_processing:
		/* validate non-RPC service name */
		if (!isrpc && (cfg->svc_name != NULL)) {
			struct servent	se;
			char		gsbuf[NSS_BUFLEN_SERVICES];
			char		*gsproto = proto;

			if (invalid_proto) {
				/*
				 * Make getservbyname_r do its lookup without a
				 * proto.
				 */
				gsproto = NULL;
			} else if (gsproto != NULL) {
				/*
				 * Since getservbyname & getprotobyname don't
				 * support tcp6, udp6 or sctp6 take off the 6
				 * digit from protocol.
				 */
				if (v6_socket_proto(gsproto))
					gsproto[strlen(gsproto) - 1] = '\0';
			}

			if (getservbyname_r(cfg->svc_name, gsproto, &se, gsbuf,
			    sizeof (gsbuf)) == NULL) {
				if (gsproto != NULL)
					invalid_proto = B_TRUE;
				prop[PT_SVC_NAME_INDEX].ip_error = IVE_INVALID;
			} else if (cfg->istlx && (ti != NULL)) {
				/* LINTED E_BAD_PTR_CAST_ALIGN */
				SS_SETPORT(*(struct sockaddr_storage *)
				    ti->local_addr.buf, se.s_port);
			} else if (!cfg->istlx && (si != NULL)) {
				if ((gsproto != NULL) &&
				    getprotobyname_r(gsproto, &pe, gpbuf,
				    sizeof (gpbuf)) == NULL) {
					invalid_proto = B_TRUE;
				} else {
					si->protocol = pe.p_proto;
				}
				SS_SETPORT(si->local_addr, se.s_port);
			}

		}

		if (p_inf != NULL) {
			p_inf->listen_fd = -1;

			/* add new proto entry to proto_list */
			uu_list_node_init(p_inf, &p_inf->link, proto_info_pool);
			(void) uu_list_insert_after(cfg->proto_list, NULL,
			    p_inf);
		}

		if (nconf != NULL)
			freenetconfigent(nconf);
		if (invalid_proto)
			prop[PT_PROTO_INDEX].ip_error = IVE_INVALID;
	} while (proto != NULL);	/* while just processed a proto */

	/*
	 * Check that the exec string for the start method actually exists and
	 * that the user is either a valid username or uid. Note we don't
	 * mandate the setting of these fields, and don't do any checks
	 * for arg0, hence its absence.
	 */

	if (prop[PT_EXEC_INDEX].ip_error != IVE_UNSET) {
		/* Don't pass any arguments to access() */
		if ((bufp = strdup(
		    prop[PT_EXEC_INDEX].ip_value.iv_string)) == NULL) {
			prop[PT_EXEC_INDEX].ip_error = IVE_INVALID;
		} else {
			if ((cp = strpbrk(bufp, " \t")) != NULL)
				*cp = '\0';

			if ((access(bufp, F_OK) == -1) && (errno == ENOENT))
				prop[PT_EXEC_INDEX].ip_error = IVE_INVALID;
			free(bufp);
		}
	}

	if (prop[PT_USER_INDEX].ip_error != IVE_UNSET) {
		char		pw_buf[NSS_BUFLEN_PASSWD];
		struct passwd	pw;

		if (getpwnam_r(prop[PT_USER_INDEX].ip_value.iv_string, &pw,
		    pw_buf, NSS_BUFLEN_PASSWD) == NULL) {
			errno = 0;
			uidl = strtol(prop[PT_USER_INDEX].ip_value.iv_string,
			    &bufp, 10);
			if ((errno != 0) || (*bufp != '\0') ||
			    (getpwuid_r(uidl, &pw, pw_buf,
			    NSS_BUFLEN_PASSWD) == NULL))
				prop[PT_USER_INDEX].ip_error = IVE_INVALID;
		}
	}

	/*
	 * Iterate through the properties in the array verifying that any
	 * default properties are valid, and setting the return boolean
	 * according to whether any properties were marked invalid.
	 */

	for (i = 0; prop[i].ip_name != NULL; i++) {
		if (prop[i].ip_error == IVE_UNSET)
			continue;

		if (prop[i].ip_default &&
		    !valid_default_prop(prop[i].ip_name, &prop[i].ip_value))
			prop[i].ip_error = IVE_INVALID;

		if (prop[i].ip_error == IVE_INVALID)
			ret = B_FALSE;
	}

	/* pass back the basic_cfg_t if requested and it's a valid config */
	if ((cfgpp != NULL) && ret) {
		*cfgpp = cfg;
	} else {
		destroy_basic_cfg(cfg);
	}

	return (ret);
}

/*
 * validate_default_prop takes the name of an inetd property, and a value
 * for that property.  It returns B_TRUE if the property is valid, and B_FALSE
 * if the proposed value isn't valid for that property.
 */

boolean_t
valid_default_prop(const char *name, const void *value)
{
	int		i;

	for (i = 0; inetd_properties[i].ip_name != NULL; i++) {
		if (strcmp(name, inetd_properties[i].ip_name) != 0)
			continue;
		if (!inetd_properties[i].ip_default)
			return (B_FALSE);

		switch (inetd_properties[i].ip_type) {
		case INET_TYPE_INTEGER:
			if (*((int64_t *)value) >= -1)
				return (B_TRUE);
			else
				return (B_FALSE);
		case INET_TYPE_BOOLEAN:
			if ((*((boolean_t *)value) == B_FALSE) ||
			    (*((boolean_t *)value) == B_TRUE))
				return (B_TRUE);
			else
				return (B_FALSE);
		case INET_TYPE_COUNT:
		case INET_TYPE_STRING_LIST:
		case INET_TYPE_STRING:
			return (B_TRUE);
		}
	}

	return (B_FALSE);
}

/*ARGSUSED*/
scf_error_t
read_prop(scf_handle_t *h, inetd_prop_t *iprop, int index, const char *inst,
    const char *pg_name)
{
	scf_simple_prop_t	*sprop;
	uint8_t			*tmp_bool;
	int64_t			*tmp_int;
	uint64_t		*tmp_cnt;
	char			*tmp_char;

	if ((sprop = scf_simple_prop_get(h, inst, pg_name, iprop->ip_name)) ==
	    NULL)
		return (scf_error());

	switch (iprop->ip_type) {
	case INET_TYPE_STRING:
		if ((tmp_char = scf_simple_prop_next_astring(sprop)) == NULL)
			goto scf_error;
		if ((iprop->ip_value.iv_string = strdup(tmp_char)) == NULL) {
			scf_simple_prop_free(sprop);
			return (SCF_ERROR_NO_MEMORY);
		}
		break;
	case INET_TYPE_STRING_LIST:
		{
			int	j = 0;

			while ((tmp_char =
			    scf_simple_prop_next_astring(sprop)) != NULL) {
				char	**cpp;

				if ((cpp = realloc(
				    iprop->ip_value.iv_string_list,
				    (j + 2) * sizeof (char *))) == NULL) {
					scf_simple_prop_free(sprop);
					return (SCF_ERROR_NO_MEMORY);
				}
				iprop->ip_value.iv_string_list = cpp;
				if ((cpp[j] = strdup(tmp_char)) == NULL) {
					scf_simple_prop_free(sprop);
					return (SCF_ERROR_NO_MEMORY);
				}
				cpp[++j] = NULL;
			}
			if ((j == 0) || (scf_error() != SCF_ERROR_NONE))
				goto scf_error;
		}
		break;
	case INET_TYPE_BOOLEAN:
		if ((tmp_bool = scf_simple_prop_next_boolean(sprop)) == NULL)
			goto scf_error;
		iprop->ip_value.iv_boolean =
		    (*tmp_bool == 0) ? B_FALSE : B_TRUE;
		break;
	case INET_TYPE_COUNT:
		if ((tmp_cnt = scf_simple_prop_next_count(sprop)) == NULL)
			goto scf_error;
		iprop->ip_value.iv_cnt = *tmp_cnt;
		break;
	case INET_TYPE_INTEGER:
		if ((tmp_int = scf_simple_prop_next_integer(sprop)) == NULL)
			goto scf_error;
		iprop->ip_value.iv_int = *tmp_int;
		break;
	default:
		assert(0);
	}

	iprop->ip_error = IVE_VALID;
	scf_simple_prop_free(sprop);
	return (0);

scf_error:
	scf_simple_prop_free(sprop);
	if (scf_error() == SCF_ERROR_NONE)
		return (SCF_ERROR_NOT_FOUND);
	return (scf_error());
}

/*
 * read_props reads either the full set of properties for instance 'instance'
 * (including defaults - pulling them in from inetd where necessary) if
 * 'instance' is non-null, else just the defaults from inetd. The properties
 * are returned in an allocated inetd_prop_t array, which must be freed
 * using free_instance_props(). If an error occurs NULL is returned and 'err'
 * is set to indicate the cause, else a pointer to the read properties is
 * returned.
 */
static inetd_prop_t *
read_props(scf_handle_t *h, const char *instance, size_t *num_elements,
    scf_error_t *err)
{
	inetd_prop_t	*ret = NULL;
	int		i;
	boolean_t	defaults_only = (instance == NULL);

	if ((ret = malloc(sizeof (inetd_properties))) == NULL) {
		*err = SCF_ERROR_NO_MEMORY;
		return (NULL);
	}
	(void) memcpy(ret, &inetd_properties, sizeof (inetd_properties));

	if (defaults_only)
		instance = INETD_INSTANCE_FMRI;
	for (i = 0; ret[i].ip_name != NULL; i++) {
		if (defaults_only && !ret[i].ip_default)
			continue;

		switch (*err = read_prop(h, &ret[i], i, instance,
		    defaults_only ? PG_NAME_SERVICE_DEFAULTS : ret[i].ip_pg)) {
		case 0:
			break;
		case SCF_ERROR_INVALID_ARGUMENT:
			goto failure_cleanup;
		case SCF_ERROR_NOT_FOUND:
			/*
			 * In non-default-only mode where we're reading a
			 * default property, since the property wasn't
			 * found in the instance, try and read inetd's default
			 * value.
			 */
			if (!ret[i].ip_default || defaults_only)
				continue;
			switch (*err = read_prop(h, &ret[i], i,
			    INETD_INSTANCE_FMRI, PG_NAME_SERVICE_DEFAULTS)) {
			case 0:
				ret[i].from_inetd = B_TRUE;
				continue;
			case SCF_ERROR_NOT_FOUND:
				continue;
			default:
				goto failure_cleanup;
			}
		default:
			goto failure_cleanup;
		}
	}

	*num_elements = i;
	return (ret);

failure_cleanup:
	free_instance_props(ret);
	return (NULL);
}

/*
 * Read all properties applicable to 'instance' (including defaults).
 */
inetd_prop_t *
read_instance_props(scf_handle_t *h, const char *instance, size_t *num_elements,
    scf_error_t *err)
{
	return (read_props(h, instance, num_elements, err));
}

/*
 * Read the default properties from inetd's defaults property group.
 */
inetd_prop_t *
read_default_props(scf_handle_t *h, size_t *num_elements, scf_error_t *err)
{
	return (read_props(h, NULL, num_elements, err));
}

void
free_instance_props(inetd_prop_t *prop)
{
	int i;

	if (prop == NULL)
		return;

	for (i = 0; prop[i].ip_name != NULL; i++) {
		if (prop[i].ip_type == INET_TYPE_STRING) {
			free(prop[i].ip_value.iv_string);
		} else if (prop[i].ip_type == INET_TYPE_STRING_LIST) {
			destroy_strings(prop[i].ip_value.iv_string_list);
		}
	}
	free(prop);
}

int
connect_to_inetd(void)
{
	struct sockaddr_un	addr;
	int			fd;

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0)
		return (-1);

	(void) memset(&addr, 0, sizeof (addr));
	addr.sun_family = AF_UNIX;
	/* CONSTCOND */
	assert(sizeof (INETD_UDS_PATH) <= sizeof (addr.sun_path));
	(void) strlcpy(addr.sun_path, INETD_UDS_PATH,
	    sizeof (addr.sun_path));

	if (connect(fd, (struct sockaddr *)&addr, sizeof (addr)) < 0) {
		(void) close(fd);
		return (-1);
	}

	return (fd);
}

/*
 * refresh_inetd requests that inetd re-read all of the information that it's
 * monitoring.
 */

int
refresh_inetd(void)
{
	uds_request_t   req;
	int		fd;

	if ((fd = connect_to_inetd()) < 0)
		return (-1);

	req = UR_REFRESH_INETD;
	if (send(fd, &req, sizeof (req), 0) < 0) {
		(void) close(fd);
		return (-1);
	}

	(void) close(fd);
	return (0);
}

/*
 * Returns the id of the socket type 'type_str' that can be used in a call
 * to socket(). If an unknown type string is passed returns -1, else the id.
 */

int
get_sock_type_id(const char *type_str)
{
	int	ret;

	if (strcmp(SOCKTYPE_STREAM_STR, type_str) == 0) {
		ret = SOCK_STREAM;
	} else if (strcmp(SOCKTYPE_DGRAM_STR, type_str) == 0) {
		ret = SOCK_DGRAM;
	} else if (strcmp(SOCKTYPE_RAW_STR, type_str) == 0) {
		ret = SOCK_RAW;
	} else if (strcmp(SOCKTYPE_SEQPKT_STR, type_str) == 0) {
		ret = SOCK_SEQPACKET;
	} else {
		ret = -1;
	}
	return (ret);
}

/*
 * Takes either an RPC service name or number in string form as 'svc_name', and
 * returns an integer format program number for the service. If the name isn't
 * recognized as a valid RPC service name or isn't a valid number, -1 is
 * returned, else the services program number.
 */

int
get_rpc_prognum(const char *svc_name)
{
	struct rpcent	rpc;
	char		buf[INETSVC_SVC_BUF_MAX];
	int		pnum;
	char		*endptr;

	if (getrpcbyname_r(svc_name, &rpc, buf, sizeof (buf)) != NULL)
		return (rpc.r_number);

	pnum = strtol(svc_name, &endptr, 0);
	if ((pnum == 0 && errno == EINVAL) ||
	    (pnum == LONG_MAX && errno == ERANGE) ||
	    pnum < 0 || *endptr != '\0') {
		return (-1);
	}

	return (pnum);
}

/*
 * calculate_hash calculates the MD5 message-digest of the file pathname.
 * On success, hash is modified to point to the digest string and 0 is returned.
 * Otherwise, -1 is returned and errno is set to indicate the error.
 * The space for the digest string is obtained using malloc(3C) and should be
 * freed by the caller.
 */
int
calculate_hash(const char *pathname, char **hash)
{
	int fd, i, serrno;
	size_t len;
	ssize_t n;
	char *digest;
	MD5_CTX md5_context;
	unsigned char md5_digest[DIGEST_LEN];
	unsigned char buf[READ_BUFSIZ];

	do {
		fd = open(pathname, O_RDONLY);
	} while (fd == -1 && errno == EINTR);

	if (fd == -1)
		return (-1);

	/* allocate space for a 16-byte MD5 digest as a string of hex digits */
	len = 2 * sizeof (md5_digest) + 1;
	if ((digest = malloc(len)) == NULL) {
		serrno = errno;
		(void) close(fd);
		errno = serrno;
		return (-1);
	}

	MD5Init(&md5_context);

	do {
		if ((n = read(fd, buf, sizeof (buf))) > 0)
			MD5Update(&md5_context, buf, n);
	} while ((n > 0) || (n == -1 && errno == EINTR));

	serrno = errno;
	MD5Final(md5_digest, &md5_context);

	(void) close(fd);

	if (n == -1) {
		errno = serrno;
		return (-1);
	}

	for (i = 0; i < sizeof (md5_digest); i++) {
		(void) snprintf(&digest[2 * i], len - (2 * i), "%02x",
		    md5_digest[i]);
	}
	*hash = digest;
	return (0);
}

/*
 * retrieve_inetd_hash retrieves inetd's configuration file hash from the
 * repository. On success, hash is modified to point to the hash string and
 * SCF_ERROR_NONE is returned. Otherwise, the scf_error value is returned.
 * The space for the hash string is obtained using malloc(3C) and should be
 * freed by the caller.
 */
scf_error_t
retrieve_inetd_hash(char **hash)
{
	scf_simple_prop_t *sp;
	char *hashstr, *s;
	scf_error_t scf_err;

	if ((sp = scf_simple_prop_get(NULL, INETD_INSTANCE_FMRI, HASH_PG,
	    HASH_PROP)) == NULL)
		return (scf_error());

	if ((hashstr = scf_simple_prop_next_astring(sp)) == NULL) {
		scf_err = scf_error();
		scf_simple_prop_free(sp);
		return (scf_err);
	}

	if ((s = strdup(hashstr)) == NULL) {
		scf_simple_prop_free(sp);
		return (SCF_ERROR_NO_MEMORY);
	}
	*hash = s;
	scf_simple_prop_free(sp);
	return (SCF_ERROR_NONE);
}

/*
 * store_inetd_hash stores the string hash in inetd's configuration file hash
 * in the repository. On success, SCF_ERROR_NONE is returned. Otherwise, the
 * scf_error value is returned.
 */
scf_error_t
store_inetd_hash(const char *hash)
{
	int ret;
	scf_error_t rval = SCF_ERROR_NONE;
	scf_handle_t *h;
	scf_propertygroup_t *pg = NULL;
	scf_instance_t *inst = NULL;
	scf_transaction_t *tx = NULL;
	scf_transaction_entry_t *txent = NULL;
	scf_property_t *prop = NULL;
	scf_value_t *val = NULL;

	if ((h = scf_handle_create(SCF_VERSION)) == NULL ||
	    scf_handle_bind(h) == -1)
		goto error;

	if ((pg = scf_pg_create(h)) == NULL ||
	    (inst = scf_instance_create(h)) == NULL ||
	    scf_handle_decode_fmri(h, INETD_INSTANCE_FMRI, NULL, NULL, inst,
	    NULL, NULL, SCF_DECODE_FMRI_EXACT) == -1)
		goto error;

	if (scf_instance_get_pg(inst, HASH_PG, pg) == -1) {
		if (scf_error() != SCF_ERROR_NOT_FOUND ||
		    scf_instance_add_pg(inst, HASH_PG, SCF_GROUP_APPLICATION,
		    0, pg) == -1)
			goto error;
	}

	if ((tx = scf_transaction_create(h)) == NULL ||
	    (txent = scf_entry_create(h)) == NULL ||
	    (prop = scf_property_create(h)) == NULL ||
	    (val = scf_value_create(h)) == NULL)
		goto error;

	do {
		if (scf_transaction_start(tx, pg) == -1)
			goto error;

		if (scf_transaction_property_new(tx, txent, HASH_PROP,
		    SCF_TYPE_ASTRING) == -1 &&
		    scf_transaction_property_change_type(tx, txent, HASH_PROP,
		    SCF_TYPE_ASTRING) == -1)
			goto error;

		if (scf_value_set_astring(val, hash) == -1 ||
		    scf_entry_add_value(txent, val) == -1)
			goto error;

		if ((ret = scf_transaction_commit(tx)) == -1)
			goto error;

		if (ret == 0) {
			scf_transaction_reset(tx);
			if (scf_pg_update(pg) == -1)
				goto error;
		}
	} while (ret == 0);

	goto success;

error:
	rval = scf_error();

success:
	scf_value_destroy(val);
	scf_property_destroy(prop);
	scf_entry_destroy(txent);
	scf_transaction_destroy(tx);
	scf_instance_destroy(inst);
	scf_pg_destroy(pg);
	scf_handle_destroy(h);
	return (rval);
}

/*
 * This is a wrapper function for inet_ntop(). In case the af is AF_INET6
 * and the address pointed by src is a IPv4-mapped IPv6 address, it returns
 * a printable IPv4 address, not an IPv4-mapped IPv6 address. In other cases it
 * behaves just like inet_ntop().
 */
const char *
inet_ntop_native(int af, const void *addr, char *dst, size_t size)
{
	struct in_addr	v4addr;

	if ((af == AF_INET6) && IN6_IS_ADDR_V4MAPPED((struct in6_addr *)addr)) {
		IN6_V4MAPPED_TO_INADDR((struct in6_addr *)addr, &v4addr);
		return (inet_ntop(AF_INET, &v4addr, dst, size));
	} else {
		return (inet_ntop(af, addr, dst, size));
	}
}

/*
 * inetd specific setproctitle. It sets the title so that it contains
 * 'svc_name' followed by, if obtainable, the address of the remote end of
 * socket 's'.
 * NOTE: The argv manipulation in this function should be replaced when a
 * common version of setproctitle is made available.
 */
void
setproctitle(const char *svc_name, int s, char *argv[])
{
	socklen_t		size;
	struct sockaddr_storage	ss;
	char			abuf[INET6_ADDRSTRLEN];

	static char		buf[80];

	size = (socklen_t)sizeof (ss);
	if (getpeername(s, (struct sockaddr *)&ss, &size) == 0) {
		(void) snprintf(buf, sizeof (buf), "-%s [%s]", svc_name,
		    inet_ntop_native(ss.ss_family, (ss.ss_family == AF_INET6 ?
		    (void *)&((struct sockaddr_in6 *)(&ss))->sin6_addr :
		    (void *)&((struct sockaddr_in *)(&ss))->sin_addr), abuf,
		    sizeof (abuf)));
	} else {
		(void) snprintf(buf, sizeof (buf), "-%s", svc_name);
	}

	/* we set argv[0] to point at our static storage. */
	argv[0] = buf;
	argv[1] = NULL;
}

static boolean_t
inetd_builtin_srcport(in_port_t p)
{
	p = ntohs(p);

	if ((p == IPPORT_ECHO) ||
	    (p == IPPORT_DISCARD) ||
	    (p == IPPORT_DAYTIME) ||
	    (p == IPPORT_CHARGEN) ||
	    (p == IPPORT_TIMESERVER)) {
		return (B_TRUE);
	} else {
		return (B_FALSE);
	}
}

/* ARGSUSED0 */
static void
alarm_handler(int sig)
{
	exit(0);
}

/*
 * This function is a datagram service template. It acts as a datagram wait
 * type server, waiting for datagrams to come in, and when they do passing
 * their contents, as-well as the socket they came in on and the remote
 * address, in a call to the callback function 'cb'. If no datagrams are
 * received for DG_INACTIVITY_TIMEOUT seconds the function exits with code 0.
 */
void
dg_template(void (*cb)(int, const struct sockaddr *, int, const void *, size_t),
    int s, void *buf, size_t buflen)
{
	struct sockaddr_storage	sa;
	socklen_t		sa_size;
	ssize_t			i;
	char			tmp[BUFSIZ];

	(void) sigset(SIGALRM, alarm_handler);

	if (buf == NULL) {
		buf = tmp;
		buflen = sizeof (tmp);
	}
	for (;;) {
		(void) alarm(DG_INACTIVITY_TIMEOUT);
		sa_size = sizeof (sa);
		if ((i = recvfrom(s, buf, buflen, 0, (struct sockaddr *)&sa,
		    &sa_size)) < 0) {
			continue;
		} else if (inetd_builtin_srcport(
		    ((struct sockaddr_in *)(&sa))->sin_port)) {
			/* denial-of-service attack possibility - ignore it */
			syslog(LOG_WARNING,
	"Incoming datagram from internal inetd service received; ignoring.");
			continue;
		}
		(void) alarm(0);

		cb(s, (struct sockaddr *)&sa, sa_size, buf, i);
	}
}

/*
 * An extension of write() or sendto() that keeps trying until either the full
 * request has completed or a non-EINTR error occurs. If 'to' is set to a
 * non-NULL value, sendto() is extended, else write(). Returns 0 on success
 * else -1.
 */
int
safe_sendto_write(int fd, const void *buf, size_t sz, int flags,
    const struct sockaddr *to, int tolen)
{

	size_t		cnt = 0;
	ssize_t		ret;
	const char	*cp = buf;

	do {
		if (to == NULL) {
			ret = write(fd, cp + cnt, sz - cnt);
		} else {
			ret = sendto(fd, cp + cnt, sz - cnt, flags, to, tolen);
		}

		if (ret > 0)
			cnt += ret;
	} while ((cnt != sz) && (errno == EINTR));

	return ((cnt == sz) ? 0 : -1);
}

int
safe_sendto(int fd, const void *buf, size_t sz, int flags,
    const struct sockaddr *to, int tolen)
{
	return (safe_sendto_write(fd, buf, sz, flags, to, tolen));
}

int
safe_write(int fd, const void *buf, size_t sz)
{
	return (safe_sendto_write(fd, buf, sz, 0, NULL, 0));
}

/*
 * Free up the memory occupied by string array 'strs'.
 */
void
destroy_strings(char **strs)
{
	int i = 0;

	if (strs != NULL) {
		while (strs[i] != NULL)
			free(strs[i++]);
		free(strs);
	}
}

/*
 * Parse the proto list string into an allocated array of proto strings,
 * returning a pointer to this array. If one of the protos is too big
 * errno is set to E2BIG and NULL is returned; if memory allocation failure
 * occurs errno is set to ENOMEM and NULL is returned; else on success
 * a pointer the string array is returned.
 */
char **
get_protos(const char *pstr)
{
	char	*cp;
	int	i = 0;
	char	**ret = NULL;
	size_t	max_proto_len = scf_limit(SCF_LIMIT_MAX_VALUE_LENGTH);
	char	*str;

	/* copy the parameter as strtok modifies its parameters */
	if ((str = strdup(pstr)) == NULL)
		goto malloc_failure;

	for (cp = strtok(str, PROTO_DELIMITERS); cp != NULL;
	    cp = strtok(NULL, PROTO_DELIMITERS)) {
		char **cpp;

		if (strlen(cp) >= max_proto_len) {
			destroy_strings(ret);
			free(str);
			errno = E2BIG;
			return (NULL);
		}
		if ((cpp = realloc(ret, (i + 2) * sizeof (char *))) == NULL)
			goto malloc_failure;
		ret = cpp;
		if ((cpp[i] = strdup(cp)) == NULL)
			goto malloc_failure;
		cpp[++i] = NULL;
	}

	free(str);
	return (ret);

malloc_failure:
	destroy_strings(ret);
	free(str);
	errno = ENOMEM;
	return (NULL);
}

/*
 * Returns an allocated string array of netids corresponding with 'proto'. The
 * function first tries to interpret 'proto' as a nettype to get its netids.
 * If this fails it tries to interpret it as a netid. If 'proto' is neither
 * a nettype or a netid or a memory allocation failures occurs NULL is
 * returned, else a pointer to an array of netids associated with 'proto' is
 * returned.
 */
char **
get_netids(char *proto)
{
	void			*handle;
	struct netconfig	*nconf;
	char			**netids = NULL;
	char			**cpp;
	int			i = 0;

	if (strcmp(proto, "*") == 0)
		proto = "visible";

	if ((handle = __rpc_setconf(proto)) != NULL) {
		/* expand nettype */
		while ((nconf = __rpc_getconf(handle)) != NULL) {
			if ((cpp = realloc(netids,
			    (i + 2) * sizeof (char *))) == NULL)
				goto failure_cleanup;
			netids = cpp;
			if ((cpp[i] = strdup(nconf->nc_netid)) == NULL)
				goto failure_cleanup;
			cpp[++i] = NULL;
		}
		__rpc_endconf(handle);
	} else {
		if ((netids = malloc(2 * sizeof (char *))) == NULL)
			return (NULL);
		if ((netids[0] = strdup(proto)) == NULL) {
			free(netids);
			return (NULL);
		}
		netids[1] = NULL;
	}

	return (netids);

failure_cleanup:
	destroy_strings(netids);
	__rpc_endconf(handle);
	return (NULL);
}
