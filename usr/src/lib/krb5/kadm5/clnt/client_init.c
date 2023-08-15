/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */



/*
 * Copyright 1993 OpenVision Technologies, Inc., All Rights Reserved
 */

/*
 * Copyright (C) 1998 by the FundsXpress, INC.
 *
 * All rights reserved.
 *
 * Export of this software from the United States of America may require
 * a specific license from the United States Government.  It is the
 * responsibility of any person or organization contemplating export to
 * obtain such a license before exporting.
 *
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of FundsXpress. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  FundsXpress makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

#include <stdio.h>
#include <netdb.h>
#include "autoconf.h"
#ifdef HAVE_MEMORY_H
#include <memory.h>
#endif
#include <string.h>
#include <com_err.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <k5-int.h> /* for KRB5_ADM_DEFAULT_PORT */
#include <krb5.h>
#ifdef __STDC__
#include <stdlib.h>
#endif
#include <libintl.h>

#include <kadm5/admin.h>
#include <kadm5/kadm_rpc.h>
#include "client_internal.h"

#include <syslog.h>
#include <gssapi/gssapi.h>
#include <gssapi_krb5.h>
#include <gssapiP_krb5.h>
#include <rpc/clnt.h>

#include <iprop_hdr.h>
#include "iprop.h"

#define	ADM_CCACHE  "/tmp/ovsec_adm.XXXXXX"

static int old_auth_gssapi = 0;
/* connection timeout to kadmind in seconds */
#define		KADMIND_CONNECT_TIMEOUT	25

int _kadm5_check_handle();

enum init_type { INIT_PASS, INIT_SKEY, INIT_CREDS };

static kadm5_ret_t _kadm5_init_any(char *client_name,
				   enum init_type init_type,
				   char *pass,
				   krb5_ccache ccache_in,
				   char *service_name,
				   kadm5_config_params *params,
				   krb5_ui_4 struct_version,
				   krb5_ui_4 api_version,
				   char **db_args,
				   void **server_handle);

kadm5_ret_t kadm5_init_with_creds(char *client_name,
				  krb5_ccache ccache,
				  char *service_name,
				  kadm5_config_params *params,
				  krb5_ui_4 struct_version,
				  krb5_ui_4 api_version,
				  char **db_args,
				  void **server_handle)
{
     return _kadm5_init_any(client_name, INIT_CREDS, NULL, ccache,
			    service_name, params,
			    struct_version, api_version, db_args,
			    server_handle);
}


kadm5_ret_t kadm5_init_with_password(char *client_name, char *pass,
				     char *service_name,
				     kadm5_config_params *params,
				     krb5_ui_4 struct_version,
				     krb5_ui_4 api_version,
				     char **db_args,
				     void **server_handle)
{
     return _kadm5_init_any(client_name, INIT_PASS, pass, NULL,
			    service_name, params, struct_version,
			    api_version, db_args, server_handle);
}

kadm5_ret_t kadm5_init(char *client_name, char *pass,
		       char *service_name,
		       kadm5_config_params *params,
		       krb5_ui_4 struct_version,
		       krb5_ui_4 api_version,
		       char **db_args,
		       void **server_handle)
{
     return _kadm5_init_any(client_name, INIT_PASS, pass, NULL,
			    service_name, params, struct_version,
			    api_version, db_args, server_handle);
}

kadm5_ret_t kadm5_init_with_skey(char *client_name, char *keytab,
				 char *service_name,
				 kadm5_config_params *params,
				 krb5_ui_4 struct_version,
				 krb5_ui_4 api_version,
				 char **db_args,
				 void **server_handle)
{
     return _kadm5_init_any(client_name, INIT_SKEY, keytab, NULL,
			    service_name, params, struct_version,
			    api_version, db_args, server_handle);
}

krb5_error_code  kadm5_free_config_params();

static void
display_status_1(m, code, type, mech)
char *m;
OM_uint32 code;
int type;
const gss_OID mech;
{
	OM_uint32 maj_stat, min_stat;
	gss_buffer_desc msg = GSS_C_EMPTY_BUFFER;
	OM_uint32 msg_ctx;

	msg_ctx = 0;
	ADMIN_LOG(LOG_ERR, "%s\n", m);
	/* LINTED */
	while (1) {
		maj_stat = gss_display_status(&min_stat, code,
					    type, mech,
					    &msg_ctx, &msg);
		if (maj_stat != GSS_S_COMPLETE) {
			syslog(LOG_ERR,
			    dgettext(TEXT_DOMAIN,
				    "error in gss_display_status"
				    " called from <%s>\n"), m);
			break;
		} else
			syslog(LOG_ERR, dgettext(TEXT_DOMAIN,
						"GSS-API error : %s\n"),
			    m);
		syslog(LOG_ERR, dgettext(TEXT_DOMAIN,
					"GSS-API error : %s\n"),
		    (char *)msg.value);
		if (msg.length != 0)
			(void) gss_release_buffer(&min_stat, &msg);

		if (!msg_ctx)
			break;
	}
}

/*
 * Function: display_status
 *
 * Purpose: displays GSS-API messages
 *
 * Arguments:
 *
 * 	msg		a string to be displayed with the message
 * 	maj_stat	the GSS-API major status code
 * 	min_stat	the GSS-API minor status code
 *	mech		kerberos mech
 * Effects:
 *
 * The GSS-API messages associated with maj_stat and min_stat are
 * displayed on stderr, each preceeded by "GSS-API error <msg>: " and
 * followed by a newline.
 */
void
display_status(msg, maj_stat, min_stat, mech)
char *msg;
OM_uint32 maj_stat;
OM_uint32 min_stat;
char *mech;
{
	gss_OID mech_oid;

	if (!rpc_gss_mech_to_oid(mech, (rpc_gss_OID *)&mech_oid)) {
		ADMIN_LOG(LOG_ERR,
			dgettext(TEXT_DOMAIN,
				"Invalid mechanism oid <%s>"), mech);
		return;
	}

	display_status_1(msg, maj_stat, GSS_C_GSS_CODE, mech_oid);
	display_status_1(msg, min_stat, GSS_C_MECH_CODE, mech_oid);
}

/*
 * Open an fd for the given address and connect asynchronously. Wait
 * KADMIND_CONNECT_TIMEOUT seconds or till it succeeds. If it succeeds
 * change fd to blocking and return it, else return -1.
 */
static int
get_connection(struct netconfig *nconf, struct netbuf netaddr)
{
	struct t_info tinfo;
	struct t_call sndcall;
	struct t_call *rcvcall = NULL;
	int connect_time;
	int flags;
	int fd;

	(void) memset(&tinfo, 0, sizeof (tinfo));

	/* we'l open with O_NONBLOCK and avoid an fcntl */
	fd = t_open(nconf->nc_device, O_RDWR | O_NONBLOCK, &tinfo);
	if (fd == -1) {
		return (-1);
	}

	if (t_bind(fd, (struct t_bind *)NULL, (struct t_bind *)NULL) == -1) {
		(void) close(fd);
		return (-1);
	}

	/* we can't connect unless fd is in IDLE state */
	if (t_getstate(fd) != T_IDLE) {
		(void) close(fd);
		return (-1);
	}

	/* setup connect parameters */
	netaddr.len = netaddr.maxlen = __rpc_get_a_size(tinfo.addr);
	sndcall.addr = netaddr;
	sndcall.opt.len = sndcall.udata.len = 0;

	/* we wait for KADMIND_CONNECT_TIMEOUT seconds from now */
	connect_time = time(NULL) + KADMIND_CONNECT_TIMEOUT;
	if (t_connect(fd, &sndcall, rcvcall) != 0) {
		if (t_errno != TNODATA) {
			(void) close(fd);
			return (-1);
		}
	}

	/* loop till success or timeout */
	for (;;) {
		if (t_rcvconnect(fd, rcvcall) == 0)
			break;

		if (t_errno != TNODATA || time(NULL) > connect_time) {
			/* we have either timed out or caught an error */
			(void) close(fd);
			if (rcvcall != NULL)
				t_free((char *)rcvcall, T_CALL);
			return (-1);
		}
		sleep(1);
	}

	/* make the fd blocking (synchronous) */
	flags = fcntl(fd, F_GETFL, 0);
	(void) fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
	if (rcvcall != NULL)
		t_free((char *)rcvcall, T_CALL);
	return (fd);
}

/*
 * Open an RPCSEC_GSS connection and
 * get a client handle to use for future RPCSEC calls.
 *
 * This function is only used when changing passwords and
 * the kpasswd_protocol is RPCSEC_GSS
 */
static int
_kadm5_initialize_rpcsec_gss_handle(kadm5_server_handle_t handle,
				    char *client_name,
				    char *service_name)
{
	struct netbuf netaddr;
	struct hostent *hp;
	int fd;
	struct sockaddr_in addr;
	struct sockaddr_in *sin;
	struct netconfig *nconf;
	int code = 0;
	generic_ret *r;
	char *ccname_orig;
	char *iprop_svc;
	boolean_t iprop_enable = B_FALSE;
	char mech[] = "kerberos_v5";
	gss_OID mech_oid;
	gss_OID_set_desc oid_set;
	gss_name_t gss_client;
	gss_buffer_desc input_name;
	gss_cred_id_t gss_client_creds = GSS_C_NO_CREDENTIAL;
	rpc_gss_options_req_t   options_req;
	rpc_gss_options_ret_t   options_ret;
	rpc_gss_service_t service = rpc_gss_svc_privacy;
	OM_uint32 gssstat, minor_stat;
	void *handlep;
	enum clnt_stat rpc_err_code;
	char *server = handle->params.admin_server;

	/*
	 * Try to find the kpasswd_server first if this is for the changepw
	 * service.  If defined then it should be resolvable else return error.
	 */
	if (strncmp(service_name, KADM5_CHANGEPW_HOST_SERVICE,
	    strlen(KADM5_CHANGEPW_HOST_SERVICE)) == 0) {
		if (handle->params.kpasswd_server != NULL)
			server = handle->params.kpasswd_server;
	}
	hp = gethostbyname(server);
	if (hp == (struct hostent *)NULL) {
		code = KADM5_BAD_SERVER_NAME;
		ADMIN_LOGO(LOG_ERR, dgettext(TEXT_DOMAIN,
					    "bad server name\n"));
		goto cleanup;
	}

	memset(&addr, 0, sizeof (addr));
	addr.sin_family = hp->h_addrtype;
	(void) memcpy((char *)&addr.sin_addr, (char *)hp->h_addr,
		    sizeof (addr.sin_addr));
	addr.sin_port = htons((ushort_t)handle->params.kadmind_port);
	sin = &addr;
#ifdef DEBUG
	printf("kadmin_port %d\n", handle->params.kadmind_port);
	printf("addr: sin_port: %d, sin_family: %d, sin_zero %s\n",
	    addr.sin_port, addr.sin_family, addr.sin_zero);
	printf("sin_addr %d:%d\n", addr.sin_addr.S_un.S_un_w.s_w1,
	    addr.sin_addr.S_un.S_un_w.s_w2);
#endif
	if ((handlep = setnetconfig()) == (void *) NULL) {
		(void) syslog(LOG_ERR,
			    dgettext(TEXT_DOMAIN,
				    "cannot get any transport information"));
		goto error;
	}

	while (nconf = getnetconfig(handlep)) {
		if ((nconf->nc_semantics == NC_TPI_COTS_ORD) &&
		    (strcmp(nconf->nc_protofmly, NC_INET) == 0) &&
		    (strcmp(nconf->nc_proto, NC_TCP) == 0))
			break;
	}

	if (nconf == (struct netconfig *)NULL)
		goto error;

	/* Transform addr to netbuf */
	(void) memset(&netaddr, 0, sizeof (netaddr));
	netaddr.buf = (char *)sin;

	/* get an fd connected to the given address */
	fd =  get_connection(nconf, netaddr);
	if (fd == -1) {
		syslog(LOG_ERR, dgettext(TEXT_DOMAIN,
			"unable to open connection to ADMIN server "
			"(t_error %i)"), t_errno);
		code = KADM5_RPC_ERROR;
		goto error;
	}

#ifdef DEBUG
	printf("fd: %d, KADM: %d, KADMVERS %d\n", fd, KADM, KADMVERS);
	printf("nconf: nc_netid: %s, nc_semantics: %d, nc_flag: %d, "
	    "nc_protofmly: %s\n",
	    nconf->nc_netid, nconf->nc_semantics, nconf->nc_flag,
	    nconf->nc_protofmly);
	printf("nc_proto: %s, nc_device: %s, nc_nlookups: %d, nc_used: %d\n",
	    nconf->nc_proto, nconf->nc_device, nconf->nc_nlookups,
	    nconf->nc_unused);
	printf("netaddr: maxlen %d, buf: %s, len: %d\n", netaddr.maxlen,
	    netaddr.buf, netaddr.len);
#endif
 	/*
	 * Tell clnt_tli_create that given fd is already connected
	 *
	 * If the service_name and client_name are iprop-centric,
	 * we need to clnt_tli_create to the appropriate RPC prog
	 */
	iprop_svc = strdup(KIPROP_SVC_NAME);
	if (iprop_svc == NULL)
		return (ENOMEM);

	if ((strstr(service_name, iprop_svc) != NULL) &&
	    (strstr(client_name, iprop_svc) != NULL)) {
		iprop_enable = B_TRUE;
		handle->clnt = clnt_tli_create(fd, nconf, NULL,
				    KRB5_IPROP_PROG, KRB5_IPROP_VERS, 0, 0);
	}
	else
		handle->clnt = clnt_tli_create(fd, nconf, NULL,
				    KADM, KADMVERS, 0, 0);

	if (iprop_svc)
		free(iprop_svc);

	if (handle->clnt == NULL) {
		syslog(LOG_ERR, dgettext(TEXT_DOMAIN,
					"clnt_tli_create failed\n"));
		code = KADM5_RPC_ERROR;
		(void) close(fd);
		goto error;
	}
	/*
	 * The rpc-handle was created on an fd opened and connected
	 * by us, so we have to explicitly tell rpc to close it.
	 */
	if (clnt_control(handle->clnt, CLSET_FD_CLOSE, NULL) != TRUE) {
		clnt_pcreateerror("ERROR:");
		syslog(LOG_ERR, dgettext(TEXT_DOMAIN,
			"clnt_control failed to set CLSET_FD_CLOSE"));
		code = KADM5_RPC_ERROR;
		(void) close(fd);
		goto error;
	}

	handle->lhandle->clnt = handle->clnt;

	/* now that handle->clnt is set, we can check the handle */
	if (code = _kadm5_check_handle((void *) handle))
		goto error;

	/*
	 * The RPC connection is open; establish the GSS-API
	 * authentication context.
	 */
	ADMIN_LOGO(LOG_ERR, dgettext(TEXT_DOMAIN,
				    "have an rpc connection open\n"));
	/* use the kadm5 cache */
	ccname_orig = getenv("KRB5CCNAME");
	if (ccname_orig)
		ccname_orig = strdup(ccname_orig);

	(void) krb5_setenv("KRB5CCNAME", handle->cache_name, 1);

	ADMIN_LOG(LOG_ERR,
		dgettext(TEXT_DOMAIN,
			"current credential cache: %s"), handle->cache_name);
	input_name.value = client_name;
	input_name.length = strlen((char *)input_name.value) + 1;
	gssstat = gss_import_name(&minor_stat, &input_name,
				(gss_OID)gss_nt_krb5_name, &gss_client);
	if (gssstat != GSS_S_COMPLETE) {
		code = KADM5_GSS_ERROR;
		ADMIN_LOGO(LOG_ERR,
			dgettext(TEXT_DOMAIN,
				"gss_import_name failed for client name\n"));
		goto error;
	}

	if (!rpc_gss_mech_to_oid(mech, (rpc_gss_OID *)&mech_oid)) {
		ADMIN_LOG(LOG_ERR,
			dgettext(TEXT_DOMAIN,
				"Invalid mechanism oid <%s>"), mech);
		goto error;
	}

	oid_set.count = 1;
	oid_set.elements = mech_oid;

	gssstat = gss_acquire_cred(&minor_stat, gss_client, 0,
				&oid_set, GSS_C_INITIATE,
				&gss_client_creds, NULL, NULL);
	(void) gss_release_name(&minor_stat, &gss_client);
	if (gssstat != GSS_S_COMPLETE) {
		code = KADM5_GSS_ERROR;
		ADMIN_LOG(LOG_ERR,
			dgettext(TEXT_DOMAIN,
				"could not acquire credentials, "
				"major error code: %d\n"), gssstat);
		goto error;
	}
	handle->my_cred = gss_client_creds;
	options_req.my_cred = gss_client_creds;
	options_req.req_flags = GSS_C_MUTUAL_FLAG | GSS_C_REPLAY_FLAG;
	options_req.time_req = 0;
	options_req.input_channel_bindings = NULL;
#ifndef INIT_TEST
	handle->clnt->cl_auth = rpc_gss_seccreate(handle->clnt,
						service_name,
						mech,
						service,
						NULL,
						&options_req,
						&options_ret);
#endif /* ! INIT_TEST */

	if (ccname_orig) {
		(void) krb5_setenv("KRB5CCNAME", ccname_orig, 1);
		free(ccname_orig);
	} else
		(void) krb5_unsetenv("KRB5CCNAME");

	if (handle->clnt->cl_auth == NULL) {
		code = KADM5_GSS_ERROR;
		display_status(dgettext(TEXT_DOMAIN,
					"rpc_gss_seccreate failed\n"),
			    options_ret.major_status,
			    options_ret.minor_status,
			    mech);
		goto error;
	}

	/*
	 * Bypass the remainder of the code and return straightaway
	 * if the gss service requested is kiprop
	 */
	if (iprop_enable == B_TRUE) {
		code = 0;
		goto cleanup;
	}

	r = init_2(&handle->api_version, handle->clnt);
	/* Solaris Kerberos: 163 resync */
	if (r == NULL) {
		ADMIN_LOGO(LOG_ERR, dgettext(TEXT_DOMAIN,
			"error during admin api initialization\n"));
		code = KADM5_RPC_ERROR;
		goto error;
	}

	if (r->code) {
		code = r->code;
		ADMIN_LOG(LOG_ERR,
			dgettext(TEXT_DOMAIN,
				"error during admin api initialization: %d\n"),
			r->code);
		goto error;
	}
error:
cleanup:

	if (handlep != (void *) NULL)
		(void) endnetconfig(handlep);
	/*
	 * gss_client_creds is freed only when there is an error condition,
	 * given that rpc_gss_seccreate() will assign the cred pointer to the
	 * my_cred member in the auth handle's private data structure.
	 */
	if (code && (gss_client_creds != GSS_C_NO_CREDENTIAL))
		(void) gss_release_cred(&minor_stat, &gss_client_creds);

	return (code);
}

static kadm5_ret_t _kadm5_init_any(char *client_name,
				   enum init_type init_type,
				   char *pass,
				   krb5_ccache ccache_in,
				   char *service_name,
				   kadm5_config_params *params_in,
				   krb5_ui_4 struct_version,
				   krb5_ui_4 api_version,
				   char **db_args,
				   void **server_handle)
{
     int i;
     krb5_creds	creds;
     krb5_ccache ccache = NULL;
     krb5_timestamp  now;
     OM_uint32 gssstat, minor_stat;
     kadm5_server_handle_t handle;
     kadm5_config_params params_local;
     int code = 0;
     krb5_get_init_creds_opt opt;
     gss_buffer_desc input_name;
     krb5_error_code kret;
     krb5_int32 starttime;
     char *server = NULL;
     krb5_principal serverp = NULL, clientp = NULL;
     krb5_principal saved_server = NULL;
     bool_t cpw = FALSE;

	ADMIN_LOGO(LOG_ERR, dgettext(TEXT_DOMAIN,
		"entering kadm5_init_any\n"));
     if (! server_handle) {
	 return EINVAL;
     }

     if (! (handle = malloc(sizeof(*handle)))) {
	  return ENOMEM;
     }
     if (! (handle->lhandle = malloc(sizeof(*handle)))) {
	  free(handle);
	  return ENOMEM;
     }

     handle->magic_number = KADM5_SERVER_HANDLE_MAGIC;
     handle->struct_version = struct_version;
     handle->api_version = api_version;
     handle->clnt = 0;
     handle->cache_name = 0;
     handle->destroy_cache = 0;
     *handle->lhandle = *handle;
     handle->lhandle->api_version = KADM5_API_VERSION_2;
     handle->lhandle->struct_version = KADM5_STRUCT_VERSION;
     handle->lhandle->lhandle = handle->lhandle;

    kret = krb5_init_context(&handle->context);
	if (kret) {
		free(handle->lhandle);
		free(handle);
		return (kret);
	}

     if(service_name == NULL || client_name == NULL) {
	krb5_free_context(handle->context);
	free(handle->lhandle);
	free(handle);
	return EINVAL;
     }
     memset((char *) &creds, 0, sizeof(creds));

     /*
      * Verify the version numbers before proceeding; we can't use
      * CHECK_HANDLE because not all fields are set yet.
      */
     GENERIC_CHECK_HANDLE(handle, KADM5_OLD_LIB_API_VERSION,
			  KADM5_NEW_LIB_API_VERSION);

     /*
      * Acquire relevant profile entries.  In version 2, merge values
      * in params_in with values from profile, based on
      * params_in->mask.
      *
      * In version 1, we've given a realm (which may be NULL) instead
      * of params_in.  So use that realm, make params_in contain an
      * empty mask, and behave like version 2.
      */
     memset((char *) &params_local, 0, sizeof(params_local));
     if (api_version == KADM5_API_VERSION_1) {
	  if (params_in)
	       params_local.mask = KADM5_CONFIG_REALM;
	  params_in = &params_local;
	}

#define ILLEGAL_PARAMS ( \
		KADM5_CONFIG_ACL_FILE	| KADM5_CONFIG_ADB_LOCKFILE | \
		KADM5_CONFIG_DBNAME	| KADM5_CONFIG_ADBNAME | \
		KADM5_CONFIG_DICT_FILE	| KADM5_CONFIG_ADMIN_KEYTAB | \
			KADM5_CONFIG_STASH_FILE | KADM5_CONFIG_MKEY_NAME | \
			KADM5_CONFIG_ENCTYPE	| KADM5_CONFIG_MAX_LIFE	| \
			KADM5_CONFIG_MAX_RLIFE	| KADM5_CONFIG_EXPIRATION | \
			KADM5_CONFIG_FLAGS	| KADM5_CONFIG_ENCTYPES	| \
			KADM5_CONFIG_MKEY_FROM_KBD)

     if (params_in && params_in->mask & ILLEGAL_PARAMS) {
		krb5_free_context(handle->context);
		free(handle->lhandle);
	  free(handle);
		ADMIN_LOG(LOG_ERR, dgettext(TEXT_DOMAIN,
			"bad client parameters, returning %d"),
			KADM5_BAD_CLIENT_PARAMS);
	  return KADM5_BAD_CLIENT_PARAMS;
     }

     if ((code = kadm5_get_config_params(handle->context, 0,
					 params_in, &handle->params))) {
	  krb5_free_context(handle->context);
	  free(handle->lhandle);
	  free(handle);
		ADMIN_LOG(LOG_ERR, dgettext(TEXT_DOMAIN,
			"failed to get config_params, return: %d\n"), code);
	  return(code);
     }

#define REQUIRED_PARAMS (KADM5_CONFIG_REALM | \
			 KADM5_CONFIG_ADMIN_SERVER | \
			 KADM5_CONFIG_KADMIND_PORT)
#define KPW_REQUIRED_PARAMS (KADM5_CONFIG_REALM | \
			 KADM5_CONFIG_KPASSWD_SERVER | \
			 KADM5_CONFIG_KPASSWD_PORT)

     if (((handle->params.mask & REQUIRED_PARAMS) != REQUIRED_PARAMS) &&
	 ((handle->params.mask & KPW_REQUIRED_PARAMS) != KPW_REQUIRED_PARAMS)) {
		(void) kadm5_free_config_params(handle->context,
						&handle->params);
	  krb5_free_context(handle->context);
		free(handle->lhandle);
	  free(handle);
		ADMIN_LOGO(LOG_ERR, dgettext(TEXT_DOMAIN,
			"missing config parameters\n"));
	  return KADM5_MISSING_KRB5_CONF_PARAMS;
     }

	/*
	 * Acquire a service ticket for service_name@realm in the name of
	 * client_name, using password pass (which could be NULL), and
	 * create a ccache to store them in.  If INIT_CREDS, use the
	 * ccache we were provided instead.
	 */
	if ((code = krb5_parse_name(handle->context, client_name,
			    &creds.client))) {
		ADMIN_LOGO(LOG_ERR, dgettext(TEXT_DOMAIN,
			    "could not parse client name\n"));
		goto error;
	}
	clientp = creds.client;

	if (strncmp(service_name, KADM5_CHANGEPW_HOST_SERVICE,
	    strlen(KADM5_CHANGEPW_HOST_SERVICE)) == 0)
		cpw = TRUE;

	if (init_type == INIT_PASS &&
	    handle->params.kpasswd_protocol == KRB5_CHGPWD_CHANGEPW_V2 &&
	    cpw == TRUE) {
		/*
		 * The 'service_name' is constructed by the caller
		 * but its done before the parameter which determines
		 * the kpasswd_protocol is found.  The servers that
		 * support the SET/CHANGE password protocol expect
		 * a slightly different service principal than
		 * the normal SEAM kadmind so construct the correct
		 * name here and then forget it.
		 */
		char *newsvcname = NULL;
		newsvcname = malloc(strlen(KADM5_CHANGEPW_SERVICE) +
				    strlen(handle->params.realm) + 2);
		if (newsvcname == NULL) {
			ADMIN_LOGO(LOG_ERR, dgettext(TEXT_DOMAIN,
					    "could not malloc\n"));
			code = ENOMEM;
			goto error;
		}
		sprintf(newsvcname, "%s@%s", KADM5_CHANGEPW_SERVICE,
			handle->params.realm);

		if ((code = krb5_parse_name(handle->context, newsvcname,
					    &creds.server))) {
			ADMIN_LOGO(LOG_ERR, dgettext(TEXT_DOMAIN,
					    "could not parse server "
					    "name\n"));
			free(newsvcname);
			goto error;
		}
		free(newsvcname);
	} else {
		input_name.value = service_name;
		input_name.length = strlen((char *)input_name.value) + 1;
		gssstat = krb5_gss_import_name(&minor_stat,
				    &input_name,
				    (gss_OID)GSS_C_NT_HOSTBASED_SERVICE,
				    (gss_name_t *)&creds.server);

		if (gssstat != GSS_S_COMPLETE) {
			code = KADM5_GSS_ERROR;
			ADMIN_LOGO(LOG_ERR, dgettext(TEXT_DOMAIN,
				"gss_import_name failed for client name\n"));
			goto error;
		}
	}
	serverp = creds.server;

	/* XXX temporarily fix a bug in krb5_cc_get_type */
#undef krb5_cc_get_type
#define krb5_cc_get_type(context, cache) ((cache)->ops->prefix)


     if (init_type == INIT_CREDS) {
	  ccache = ccache_in;
	  handle->cache_name = (char *)
	       malloc(strlen(krb5_cc_get_type(handle->context, ccache)) +
		      strlen(krb5_cc_get_name(handle->context, ccache)) + 2);
	  if (handle->cache_name == NULL) {
	       code = ENOMEM;
	       goto error;
	  }
	  sprintf(handle->cache_name, "%s:%s",
		  krb5_cc_get_type(handle->context, ccache),
		  krb5_cc_get_name(handle->context, ccache));
     } else {
#if 0
	  handle->cache_name =
	       (char *) malloc(strlen(ADM_CCACHE)+strlen("FILE:")+1);
	  if (handle->cache_name == NULL) {
	       code = ENOMEM;
	       goto error;
	  }
	  sprintf(handle->cache_name, "FILE:%s", ADM_CCACHE);
	  mktemp(handle->cache_name + strlen("FILE:"));
#endif
	  {
	      static int counter = 0;
	      handle->cache_name = malloc(sizeof("MEMORY:kadm5_")
					  + 3*sizeof(counter));
	      sprintf(handle->cache_name, "MEMORY:kadm5_%u", counter++);
	  }

	  if ((code = krb5_cc_resolve(handle->context, handle->cache_name,
				      &ccache)))
	       goto error;

	  if ((code = krb5_cc_initialize (handle->context, ccache,
					  creds.client)))
	       goto error;

	  handle->destroy_cache = 1;
     }
     handle->lhandle->cache_name = handle->cache_name;
	ADMIN_LOG(LOG_ERR, dgettext(TEXT_DOMAIN,
		"cache created: %s\n"), handle->cache_name);

     if ((code = krb5_timeofday(handle->context, &now)))
	  goto error;

     /*
      * Get a ticket, use the method specified in init_type.
      */

     creds.times.starttime = 0; /* start timer at KDC */
     creds.times.endtime = 0; /* endtime will be limited by service */

	memset(&opt, 0, sizeof (opt));
	krb5_get_init_creds_opt_init(&opt);

	if (creds.times.endtime) {
		if (creds.times.starttime)
			starttime = creds.times.starttime;
		else
			starttime = now;

		krb5_get_init_creds_opt_set_tkt_life(&opt,
			creds.times.endtime - starttime);
	}
	code = krb5_unparse_name(handle->context, creds.server, &server);
	if (code)
		goto error;

	/*
	 * Solaris Kerberos:
	 * Save the original creds.server as krb5_get_init_creds*() always
	 * sets the realm of the server to the client realm.
	 */
	code = krb5_copy_principal(handle->context, creds.server, &saved_server);
	if (code)
		goto error;

	if (init_type == INIT_PASS) {
		code = krb5_get_init_creds_password(handle->context,
			&creds, creds.client, pass, NULL,
			NULL, creds.times.starttime,
			server, &opt);
	} else if (init_type == INIT_SKEY) {
		krb5_keytab kt = NULL;

		if (!(pass && (code = krb5_kt_resolve(handle->context,
					pass, &kt)))) {
			code = krb5_get_init_creds_keytab(
					handle->context,
					&creds, creds.client, kt,
					creds.times.starttime,
					server, &opt);

	       if (pass) krb5_kt_close(handle->context, kt);
	  }
     }

     /* Improved error messages */
     if (code == KRB5KRB_AP_ERR_BAD_INTEGRITY) code = KADM5_BAD_PASSWORD;
     if (code == KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN)
	  code = KADM5_SECURE_PRINC_MISSING;

     if (code != 0) {
		ADMIN_LOGO(LOG_ERR, dgettext(TEXT_DOMAIN,
			"failed to obtain credentials cache\n"));
		krb5_free_principal(handle->context, saved_server);
		goto error;
	}

	/*
	 * Solaris Kerberos:
	 * If the server principal had an empty realm then store that in
	 * the cred cache and not the server realm as returned by
	 * krb5_get_init_creds_{keytab|password}(). This ensures that rpcsec_gss
	 * will find the credential in the cred cache even if a "fallback"
	 * method is being used to determine the realm.
	 */
	if (init_type != INIT_CREDS) {
		krb5_free_principal(handle->context, creds.server);
	}
	creds.server = saved_server;

	/*
	 * If we got this far, save the creds in the cache.
	 */
	if (ccache) {
		code = krb5_cc_store_cred(handle->context, ccache, &creds);
	}

	ADMIN_LOGO(LOG_ERR, dgettext(TEXT_DOMAIN, "obtained credentials cache\n"));

#ifdef ZEROPASSWD
     if (pass != NULL)
	  memset(pass, 0, strlen(pass));
#endif

	if (init_type != INIT_PASS ||
	    handle->params.kpasswd_protocol == KRB5_CHGPWD_RPCSEC ||
	    cpw == FALSE) {
		code = _kadm5_initialize_rpcsec_gss_handle(handle,
					client_name, service_name);

		/*
		 * Solaris Kerberos:
		 * If _kadm5_initialize_rpcsec_gss_handle() fails it will have
		 * called krb5_gss_release_cred(). If the credential cache is a
		 * MEMORY cred cache krb5_gss_release_cred() destroys the
		 * cred cache data. Make sure that the cred-cache is closed
		 * to prevent a double free in the "error" code.
		 */
		if (code != 0) {
			if (init_type != INIT_CREDS) {
				krb5_cc_close(handle->context, ccache);
				ccache = NULL;
			}
			goto error;
		}
	}

	*server_handle = (void *) handle;

	if (init_type != INIT_CREDS)
		krb5_cc_close(handle->context, ccache);

	goto cleanup;

error:
     /*
      * Note that it is illegal for this code to execute if "handle"
      * has not been allocated and initialized.  I.e., don't use "goto
      * error" before the block of code at the top of the function
      * that allocates and initializes "handle".
      */
     if (handle->cache_name)
	 free(handle->cache_name);
     if (handle->destroy_cache && ccache)
	 krb5_cc_destroy(handle->context, ccache);
     if(handle->clnt && handle->clnt->cl_auth)
	  AUTH_DESTROY(handle->clnt->cl_auth);
     if(handle->clnt)
	  clnt_destroy(handle->clnt);
	(void) kadm5_free_config_params(handle->context, &handle->params);

cleanup:
	if (server)
		free(server);

	/*
	 * cred's server and client pointers could have been overwritten
	 * by the krb5_get_init_* functions.  If the addresses are different
	 * before and after the calls then we must free the memory that
	 * was allocated before the call.
	 */
	if (clientp && clientp != creds.client)
		krb5_free_principal(handle->context, clientp);

	if (serverp && serverp != creds.server)
		krb5_free_principal(handle->context, serverp);

     krb5_free_cred_contents(handle->context, &creds);

	/*
	 * Dont clean up the handle if the code is OK (code==0)
	 * because it is returned to the caller in the 'server_handle'
	 * ptr.
	 */
     if (code) {
		krb5_free_context(handle->context);
		free(handle->lhandle);
	  free(handle);
	}

     return code;
}

kadm5_ret_t
kadm5_destroy(void *server_handle)
{
     krb5_ccache	    ccache = NULL;
     int		    code = KADM5_OK;
     kadm5_server_handle_t	handle =
	  (kadm5_server_handle_t) server_handle;
	OM_uint32 min_stat;

     CHECK_HANDLE(server_handle);
/* SUNW14resync:
 * krb5_cc_resolve() will resolve a ccache with the same data that
 * handle->my_cred points to. If the ccache is a MEMORY ccache then
 * gss_release_cred() will free that data (it doesn't do this when ccache
 * is a FILE ccache).
 * if'ed out to avoid the double free.
 */
#if 0
     if (handle->destroy_cache && handle->cache_name) {
	 if ((code = krb5_cc_resolve(handle->context,
				     handle->cache_name, &ccache)) == 0)
	     code = krb5_cc_destroy (handle->context, ccache);
     }
#endif
     if (handle->cache_name)
	 free(handle->cache_name);
     if (handle->clnt && handle->clnt->cl_auth) {
		/*
		 * Since kadm5 doesn't use the default credentials we
		 * must clean this up manually.
		 */
		if (handle->my_cred != GSS_C_NO_CREDENTIAL)
			(void) gss_release_cred(&min_stat, &handle->my_cred);
	  AUTH_DESTROY(handle->clnt->cl_auth);
	}
     if (handle->clnt)
	  clnt_destroy(handle->clnt);
     if (handle->lhandle)
          free (handle->lhandle);

     kadm5_free_config_params(handle->context, &handle->params);
     krb5_free_context(handle->context);

     handle->magic_number = 0;
     free(handle);

     return code;
}
/* not supported on client */
kadm5_ret_t kadm5_lock(void *server_handle)
{
    return EINVAL;
}

/* not supported on client */
kadm5_ret_t kadm5_unlock(void *server_handle)
{
    return EINVAL;
}

kadm5_ret_t kadm5_flush(void *server_handle)
{
     return KADM5_OK;
}

int _kadm5_check_handle(void *handle)
{
     CHECK_HANDLE(handle);
     return 0;
}

krb5_error_code kadm5_init_krb5_context (krb5_context *ctx)
{
    return krb5_init_context(ctx);
}

/*
 * Stub function for kadmin.  It was created to eliminate the dependency on
 * libkdb's ulog functions.  The srv equivalent makes the actual calls.
 */
krb5_error_code
kadm5_init_iprop(void *handle)
{
	return (0);
}
