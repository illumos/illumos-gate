/*
 * Copyright (c) 2001, 2010, Oracle and/or its affiliates. All rights reserved.
 */


/*
 * WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING
 *
 *	Openvision retains the copyright to derivative works of
 *	this source code.  Do *NOT* create a derivative of this
 *	source code before consulting with your legal department.
 *	Do *NOT* integrate *ANY* of this source code into another
 *	product before consulting with your legal department.
 *
 *	For further information, read the top-level Openvision
 *	copyright which is contained in the top-level MIT Kerberos
 *	copyright.
 *
 * WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING
 *
 */


/*
 * Copyright 1993 OpenVision Technologies, Inc., All Rights Reserved
 *
 */

#include <kadm5/admin.h>
#include <gssapi/gssapi.h>
#include <gssapi_krb5.h>   /* for gss_nt_krb5_name */
#include <kadm5/kadm_rpc.h>
#include <kadm5/server_internal.h>
#include <kadm5/srv/server_acl.h>
#include <security/pam_appl.h>

#include <syslog.h>
#include <arpa/inet.h>  /* inet_ntoa */
#include <krb5/adm_proto.h>  /* krb5_klog_syslog */
#include <libintl.h>
#include <krb5.h>
#include "misc.h"

#define LOG_UNAUTH  gettext("Unauthorized request: %s, %s, " \
			    "client=%s, service=%s, addr=%s")
#define	LOG_DONE   gettext("Request: %s, %s, %s, client=%s, " \
			    "service=%s, addr=%s")

extern gss_name_t 			gss_changepw_name;
extern gss_name_t			gss_oldchangepw_name;
extern void *				global_server_handle;
extern short l_port;

char buf[33];

#define CHANGEPW_SERVICE(rqstp) \
	(cmp_gss_names_rel_1(acceptor_name(rqstp), gss_changepw_name) |\
	 (gss_oldchangepw_name && \
	  cmp_gss_names_rel_1(acceptor_name(rqstp), \
			gss_oldchangepw_name)))


static int gss_to_krb5_name(kadm5_server_handle_t handle,
		     gss_name_t gss_name, krb5_principal *princ);

static int gss_name_to_string(gss_name_t gss_name, gss_buffer_desc *str);

static gss_name_t acceptor_name(struct svc_req * rqstp);

kadm5_ret_t
kadm5_get_priv(void *server_handle,
    long *privs, gss_name_t clnt);

gss_name_t
get_clnt_name(struct svc_req * rqstp)
{
	OM_uint32 maj_stat, min_stat;
	gss_name_t name;
	rpc_gss_rawcred_t *raw_cred;
	void *cookie;
	gss_buffer_desc name_buff;

	rpc_gss_getcred(rqstp, &raw_cred, NULL, &cookie);
	name_buff.value = raw_cred->client_principal->name;
	name_buff.length = raw_cred->client_principal->len;
	maj_stat = gss_import_name(&min_stat, &name_buff,
	    (gss_OID) GSS_C_NT_EXPORT_NAME, &name);
	if (maj_stat != GSS_S_COMPLETE) {
		return (NULL);
	}
	return (name);
}

char *
client_addr(struct svc_req * req, char *buf)
{
	struct sockaddr *ca;
	u_char *b;
	char *frontspace = " ";

	/*
	 * Convert the caller's IP address to a dotted string
	 */
	ca = (struct sockaddr *)
	    svc_getrpccaller(req->rq_xprt)->buf;

	if (ca->sa_family == AF_INET) {
		b = (u_char *) & ((struct sockaddr_in *) ca)->sin_addr;
		(void) sprintf(buf, "%s(%d.%d.%d.%d) ", frontspace,
		    b[0] & 0xFF, b[1] & 0xFF, b[2] & 0xFF, b[3] & 0xFF);
	} else {
		/*
		 * No IP address to print. If there was a host name
		 * printed, then we print a space.
		 */
		(void) sprintf(buf, frontspace);
	}

	return (buf);
}

static int cmp_gss_names(gss_name_t n1, gss_name_t n2)
{
   OM_uint32 emaj, emin;
   int equal;

   if (GSS_ERROR(emaj = gss_compare_name(&emin, n1, n2, &equal)))
      return(0);

   return(equal);
}

/* Does a comparison of the names and then releases the first entity */
/* For use above in CHANGEPW_SERVICE */
static int cmp_gss_names_rel_1(gss_name_t n1, gss_name_t n2)
{
   OM_uint32 min_stat;
   int ret;

   ret = cmp_gss_names(n1, n2);
   if (n1) (void) gss_release_name(&min_stat, &n1);
   return ret;
}

/*
 * Function check_handle
 *
 * Purpose: Check a server handle and return a com_err code if it is
 * invalid or 0 if it is valid.
 *
 * Arguments:
 *
 * 	handle		The server handle.
 */

static int check_handle(void *handle)
{
     CHECK_HANDLE(handle);
     return 0;
}

/*
 * Function: new_server_handle
 *
 * Purpose: Constructs a server handle suitable for passing into the
 * server library API functions, by folding the client's API version
 * and calling principal into the server handle returned by
 * kadm5_init.
 *
 * Arguments:
 * 	api_version	(input) The API version specified by the client
 * 	rqstp		(input) The RPC request
 * 	handle		(output) The returned handle
 *	<return value>	(output) An error code, or 0 if no error occurred
 * 
 * Effects:
 * 	Returns a pointer to allocated storage containing the server
 * 	handle.  If an error occurs, then no allocated storage is
 *	returned, and the return value of the function will be a
 * 	non-zero com_err code.
 *      
 *      The allocated storage for the handle should be freed with
 * 	free_server_handle (see below) when it is no longer needed.
 */

static kadm5_ret_t new_server_handle(krb5_ui_4 api_version,
					  struct svc_req *rqstp,
					  kadm5_server_handle_t
					  *out_handle)
{
     kadm5_server_handle_t handle;
	gss_name_t name;
	OM_uint32 min_stat;

     if (! (handle = (kadm5_server_handle_t)
	    malloc(sizeof(*handle))))
	  return ENOMEM;

     *handle = *(kadm5_server_handle_t)global_server_handle;
     handle->api_version = api_version;

     if (!(name = get_clnt_name(rqstp))) {
	  free(handle);
	  return KADM5_FAILURE;
     }
    if (! gss_to_krb5_name(handle, name, &handle->current_caller)) {
	  free(handle);
		gss_release_name(&min_stat, &name);
	  return KADM5_FAILURE;
	}
	gss_release_name(&min_stat, &name);

     *out_handle = handle;
     return 0;
}

/*
 * Function: free_server_handle
 *
 * Purpose: Free handle memory allocated by new_server_handle
 *
 * Arguments:
 * 	handle		(input/output) The handle to free
 */
static void free_server_handle(kadm5_server_handle_t handle)
{
     krb5_free_principal(handle->context, handle->current_caller);
     free(handle);
}

/*
 * Function: setup_gss_names
 *
 * Purpose: Create printable representations of the client and server
 * names.
 *
 * Arguments:
 * 	rqstp		(r) the RPC request
 * 	client_name	(w) pointer to client_name string
 * 	server_name	(w) pointer to server_name string
 *
 * Effects:
 *
 * Unparses the client and server names into client_name and
 * server_name, both of which must be freed by the caller.  Returns 0
 * on success and -1 on failure. On failure client_name and server_name
 * will point to null.
 */
/* SUNW14resync */
int setup_gss_names(struct svc_req *rqstp,
    char **client_name, char **server_name)
{
     OM_uint32 maj_stat, min_stat;
	rpc_gss_rawcred_t *raw_cred;
	gss_buffer_desc name_buf;
	char *tmp, *val;
	size_t len;
	gss_name_t name;

	*client_name = NULL;

	rpc_gss_getcred(rqstp, &raw_cred, NULL, NULL);

	/* Return a copy of the service principal from the raw_cred */
	*server_name = strdup(raw_cred->svc_principal);

	if (*server_name == NULL)
		return (-1);

	if (!(name = get_clnt_name(rqstp))) {
		free(*server_name);
		*server_name = NULL;
		return (-1);
	}
	maj_stat = gss_display_name(&min_stat, name, &name_buf, NULL);
	if (maj_stat != GSS_S_COMPLETE) {
		free(*server_name);
		gss_release_name(&min_stat, &name);
		*server_name = NULL;
		return (-1);
	}
	gss_release_name(&min_stat, &name);

	/*
	 * Allocate space to copy the client principal. We allocate an
	 * extra byte to make the string null terminated if we need to.
	 */

	val = name_buf.value;
	len = name_buf.length + (val[name_buf.length - 1] != '\0');

	/* len is the length including the null terminating byte. */

	tmp = malloc(len);
	if (tmp) {
		memcpy(tmp, val, len - 1);
		tmp[len - 1] = '\0';
	} else {
		free(*server_name);
		*server_name = NULL;
	}

	/* Were done with the GSS buffer */
	(void) gss_release_buffer(&min_stat, &name_buf);

	*client_name = tmp;

	return (tmp ? 0 : -1);
}

static gss_name_t acceptor_name(struct svc_req * rqstp)
{
     OM_uint32 maj_stat, min_stat;
     gss_name_t name;
     rpc_gss_rawcred_t *raw_cred;
     void *cookie;
     gss_buffer_desc name_buff;

	rpc_gss_getcred(rqstp, &raw_cred, NULL, &cookie);
	name_buff.value = raw_cred->svc_principal;
	name_buff.length = strlen(raw_cred->svc_principal);
	maj_stat = gss_import_name(&min_stat, &name_buff,
	    (gss_OID) gss_nt_krb5_name, &name);
	if (maj_stat != GSS_S_COMPLETE) {
		gss_release_buffer(&min_stat, &name_buff);
		return (NULL);
	}
	maj_stat = gss_display_name(&min_stat, name, &name_buff, NULL);
    if (maj_stat != GSS_S_COMPLETE) {
		gss_release_buffer(&min_stat, &name_buff);
	  return (NULL);
	}
	gss_release_buffer(&min_stat, &name_buff);

     return name;
}
     
static int cmp_gss_krb5_name(kadm5_server_handle_t handle,
		      gss_name_t gss_name, krb5_principal princ)
{
     krb5_principal princ2;
     int status;

     if (! gss_to_krb5_name(handle, gss_name, &princ2))
	  return 0;
     status = krb5_principal_compare(handle->context, princ, princ2);
     krb5_free_principal(handle->context, princ2);
     return status;
}


/*
 * This routine primarily validates the username and password
 * of the principal to be created, if a prior acl check for
 * the 'u' privilege succeeds. Validation is done using
 * the PAM `k5migrate' service. k5migrate normally stacks
 * pam_unix_auth.so and pam_unix_account.so in its auth and
 * account stacks respectively.
 *
 * Returns 1 (true), if validation is successful,
 * else returns 0 (false).
 */ 
int verify_pam_pw(char *userdata, char *pwd) {
	pam_handle_t *pamh;
	int err = 0;
	int result = 1;
	char *user = NULL; 
	char *ptr = NULL;

	ptr = strchr(userdata, '@');
	if (ptr != NULL) {
		user = (char *)malloc(ptr - userdata + 1);
		(void) strlcpy(user, userdata, (ptr - userdata) + 1);
	} else {
		user = (char *)strdup(userdata);
	}

	err = pam_start("k5migrate", user, NULL, &pamh);
	if (err != PAM_SUCCESS) {
		syslog(LOG_ERR, "verify_pam_pw: pam_start() failed, %s\n",
				pam_strerror(pamh, err));
		if (user)
			free(user);
		return (0);
	}
	if (user)
		free(user);

	err = pam_set_item(pamh, PAM_AUTHTOK, (void *)pwd);
	if (err != PAM_SUCCESS) {
		syslog(LOG_ERR, "verify_pam_pw: pam_set_item() failed, %s\n",
				pam_strerror(pamh, err));
		(void) pam_end(pamh, err);
		return (0);
	}

	err = pam_authenticate(pamh, PAM_SILENT);
	if (err != PAM_SUCCESS) {
		syslog(LOG_ERR, "verify_pam_pw: pam_authenticate() "
				"failed, %s\n", pam_strerror(pamh, err));
		(void) pam_end(pamh, err);
		return (0);
	}

	err = pam_acct_mgmt(pamh, PAM_SILENT);
	if (err != PAM_SUCCESS) {
		syslog(LOG_ERR, "verify_pam_pw: pam_acct_mgmt() failed, %s\n",
				pam_strerror(pamh, err));
		(void) pam_end(pamh, err);
		return (0);
	}

	(void) pam_end(pamh, PAM_SUCCESS);
	return (result);
}

static int gss_to_krb5_name(kadm5_server_handle_t handle,
		     gss_name_t gss_name, krb5_principal *princ)
{
     OM_uint32 status, minor_stat;
     gss_buffer_desc gss_str;
     gss_OID gss_type;
     int success;

     status = gss_display_name(&minor_stat, gss_name, &gss_str, &gss_type);
     if ((status != GSS_S_COMPLETE) || (!g_OID_equal(gss_type, gss_nt_krb5_name)))
	  return 0;
     success = (krb5_parse_name(handle->context, gss_str.value, princ) == 0);
     gss_release_buffer(&minor_stat, &gss_str);
     return success;
}

static int
gss_name_to_string(gss_name_t gss_name, gss_buffer_desc *str)
{
     OM_uint32 status, minor_stat;
     gss_OID gss_type;

     status = gss_display_name(&minor_stat, gss_name, str, &gss_type);
     if ((status != GSS_S_COMPLETE) || (gss_type != gss_nt_krb5_name))
	  return 1;
     return 0;
}

static int
log_unauth(
    char *op,
    char *target,
    char *client,
    char *server,
    char *addr)
{
    size_t tlen, clen, slen;
    char *tdots, *cdots, *sdots;

    tlen = strlen(target);
    trunc_name(&tlen, &tdots);
    clen = strlen(client);
    trunc_name(&clen, &cdots);
    slen = strlen(server);
    trunc_name(&slen, &sdots);

    return krb5_klog_syslog(LOG_NOTICE,
			    "Unauthorized request: %s, %.*s%s, "
			    "client=%.*s%s, service=%.*s%s, addr=%s",
			    op, tlen, target, tdots,
			    clen, client, cdots,
			    slen, server, sdots,
			    addr);
}

static int
log_done(
    char *op,
    char *target,
    const char *errmsg,
    char *client,
    char *server,
    char *addr)
{
    size_t tlen, clen, slen;
    char *tdots, *cdots, *sdots;

    tlen = strlen(target);
    trunc_name(&tlen, &tdots);
    clen = strlen(client);
    trunc_name(&clen, &cdots);
    slen = strlen(server);
    trunc_name(&slen, &sdots);

    return krb5_klog_syslog(LOG_NOTICE,
			    "Request: %s, %.*s%s, %s, "
			    "client=%.*s%s, service=%.*s%s, addr=%s",
			    op, tlen, target, tdots, errmsg,
			    clen, client, cdots,
			    slen, server, sdots,
			    addr);
}

generic_ret *
create_principal_2_svc(cprinc_arg *arg, struct svc_req *rqstp)
{
    static generic_ret		ret;
    char			*prime_arg = NULL;
    char *client_name = NULL, *service_name = NULL;
    int policy_migrate = 0;

    OM_uint32			minor_stat;
    kadm5_server_handle_t	handle;
    kadm5_ret_t retval;
    restriction_t		*rp;
    const char			*errmsg = NULL;
    gss_name_t name = NULL;

    xdr_free(xdr_generic_ret, (char *) &ret);

    if ((ret.code = new_server_handle(arg->api_version, rqstp, &handle)))
	 return &ret;

    if ((ret.code = check_handle((void *)handle)))
		goto error;
    ret.api_version = handle->api_version;

    if (setup_gss_names(rqstp, &client_name, &service_name) < 0) {
	 ret.code = KADM5_FAILURE;
	goto error;
    }
    if (krb5_unparse_name(handle->context, arg->rec.principal, &prime_arg)) {
	 ret.code = KADM5_BAD_PRINCIPAL;
	 goto error;
    }
	if (!(name = get_clnt_name(rqstp))) {
		ret.code = KADM5_FAILURE;
		goto error;
	}

	if (kadm5int_acl_check(handle->context, name, ACL_MIGRATE,
	    arg->rec.principal, &rp) &&
	    verify_pam_pw(prime_arg, arg->passwd)) {
		policy_migrate = 1;
	}

    if (CHANGEPW_SERVICE(rqstp)
	|| (!kadm5int_acl_check(handle->context, name, ACL_ADD,
			arg->rec.principal, &rp) &&
		!(policy_migrate))
	|| kadm5int_acl_impose_restrictions(handle->context,
				   &arg->rec, &arg->mask, rp)) {
	 ret.code = KADM5_AUTH_ADD;

		audit_kadmind_unauth(rqstp->rq_xprt, l_port,
				    "kadm5_create_principal",
				    prime_arg, client_name);
	 log_unauth("kadm5_create_principal", prime_arg,
		client_name, service_name, client_addr(rqstp, buf));
    } else {
	ret.code = kadm5_create_principal((void *)handle,
						&arg->rec, arg->mask,
						arg->passwd);
	/* Solaris Kerberos */
	if( ret.code != 0 )
	     errmsg = krb5_get_error_message(handle ? handle->context : NULL, ret.code);

	audit_kadmind_auth(rqstp->rq_xprt, l_port,
				"kadm5_create_principal",
				prime_arg, client_name, ret.code);
	log_done("kadm5_create_principal", prime_arg,
	    errmsg ? errmsg : "success",
	    client_name, service_name, client_addr(rqstp, buf));

	if (errmsg != NULL)
		krb5_free_error_message(handle ? handle->context : NULL, errmsg);

	if (policy_migrate && (ret.code == 0)) {
		arg->rec.policy = strdup("default");
		if ((arg->mask & KADM5_PW_EXPIRATION)) {
			arg->mask = 0;
			arg->mask |= KADM5_POLICY;
			arg->mask |= KADM5_PW_EXPIRATION;
		} else {
			arg->mask = 0;
			arg->mask |= KADM5_POLICY;
		}

		retval = kadm5_modify_principal((void *)handle,
				&arg->rec, arg->mask);
		log_done("kadm5_modify_principal",
			prime_arg, ((retval == 0) ? "success" :
			error_message(retval)), client_name,
			service_name, client_addr(rqstp, buf));
	}
    }

error:
    if (name)
    	gss_release_name(&minor_stat, &name);
    free_server_handle(handle);
    if (prime_arg)
    	free(prime_arg);
    if (client_name)
    	free(client_name);
    if (service_name)
    	free(service_name);
    return (&ret);
}

generic_ret *
create_principal3_2_svc(cprinc3_arg *arg, struct svc_req *rqstp)
{
    static generic_ret		ret;
    char			*prime_arg = NULL;
    char			*client_name = NULL, *service_name = NULL;
    int				policy_migrate = 0;

    OM_uint32			minor_stat;
    kadm5_server_handle_t	handle;
    kadm5_ret_t			retval;
    restriction_t		*rp;
    const char                        *errmsg = NULL;
    gss_name_t			name = NULL;

    xdr_free(xdr_generic_ret, (char *) &ret);

    if ((ret.code = new_server_handle(arg->api_version, rqstp, &handle)))
	 return &ret;

    if ((ret.code = check_handle((void *)handle)))
	goto error;
    ret.api_version = handle->api_version;

    if (setup_gss_names(rqstp, &client_name, &service_name) < 0) {
	 ret.code = KADM5_FAILURE;
	goto error;
    }
    if (krb5_unparse_name(handle->context, arg->rec.principal, &prime_arg)) {
	 ret.code = KADM5_BAD_PRINCIPAL;
	goto error;
    }	
    if (!(name = get_clnt_name(rqstp))) {
	ret.code = KADM5_FAILURE;
	goto error;
    }

    if (kadm5int_acl_check(handle->context, name, ACL_MIGRATE,
		arg->rec.principal, &rp) &&
		verify_pam_pw(prime_arg, arg->passwd)) {
	policy_migrate = 1;
    }

    if (CHANGEPW_SERVICE(rqstp)
	|| (!kadm5int_acl_check(handle->context, name, ACL_ADD,
			arg->rec.principal, &rp) &&
	    !(policy_migrate))
	|| kadm5int_acl_impose_restrictions(handle->context,
				   &arg->rec, &arg->mask, rp)) {
	 ret.code = KADM5_AUTH_ADD;
	 log_unauth("kadm5_create_principal", prime_arg,
		    client_name, service_name, client_addr(rqstp, buf));
    } else {
	 ret.code = kadm5_create_principal_3((void *)handle,
					     &arg->rec, arg->mask,
					     arg->n_ks_tuple,
					     arg->ks_tuple,
					     arg->passwd);
	/* Solaris Kerberos */
	 if( ret.code != 0 )
	     errmsg = krb5_get_error_message(handle ? handle->context : NULL, ret.code);

	 log_done("kadm5_create_principal", prime_arg,
		  errmsg ? errmsg : "success",
		  client_name, service_name, client_addr(rqstp, buf));

	  if (errmsg != NULL)
		krb5_free_error_message(handle ? handle->context : NULL, errmsg);

	 if (policy_migrate && (ret.code == 0)) {
	 	arg->rec.policy = strdup("default");
	 	if ((arg->mask & KADM5_PW_EXPIRATION)) {
	 		arg->mask = 0;
	 		arg->mask |= KADM5_POLICY;
	 		arg->mask |= KADM5_PW_EXPIRATION;
	 	} else {
	 		arg->mask = 0;
	 		arg->mask |= KADM5_POLICY;
	 	}

		retval = kadm5_modify_principal((void *)handle,
					   &arg->rec, arg->mask);
		log_done("kadm5_modify_principal", prime_arg,
			((retval == 0) ? "success" : error_message(retval)),
			client_name, service_name, client_addr(rqstp, buf));
	 }
    }

error:
    if (name)
    	gss_release_name(&minor_stat, &name);
    free_server_handle(handle);
    if (client_name)
    	free(client_name);
    if (service_name)
    	free(service_name);
    if (prime_arg)
    	free(prime_arg);
    return &ret;
}

generic_ret *
delete_principal_2_svc(dprinc_arg *arg, struct svc_req *rqstp)
{
    static generic_ret		    ret;
    char			    *prime_arg = NULL;
    char *client_name = NULL, *service_name = NULL;
    OM_uint32			    min_stat;
    kadm5_server_handle_t	    handle;
    const char                            *errmsg = NULL;

    gss_name_t name = NULL;


    xdr_free(xdr_generic_ret, (char *) &ret);

    if ((ret.code = new_server_handle(arg->api_version, rqstp, &handle)))
	 return &ret;

    if ((ret.code = check_handle((void *)handle)))
		goto error;
    ret.api_version = handle->api_version;

    if (setup_gss_names(rqstp, &client_name, &service_name) < 0) {
	 ret.code = KADM5_FAILURE;
		goto error;
    }
    if (krb5_unparse_name(handle->context, arg->princ, &prime_arg)) {
	 ret.code = KADM5_BAD_PRINCIPAL;
		goto error;
    }
	if (!(name = get_clnt_name(rqstp))) {
		ret.code = KADM5_FAILURE;
		goto error;
	}
    
    if (CHANGEPW_SERVICE(rqstp)
	|| !kadm5int_acl_check(handle->context, name, ACL_DELETE,
		      arg->princ, NULL)) {
	 ret.code = KADM5_AUTH_DELETE;

		audit_kadmind_unauth(rqstp->rq_xprt, l_port,
				    "kadm5_delete_principal",
				    prime_arg, client_name);
	 log_unauth("kadm5_delete_principal", prime_arg, client_name,
			service_name, client_addr(rqstp, buf));
    } else {
	 ret.code = kadm5_delete_principal((void *)handle, arg->princ);
	/* Solaris Kerberos */
	 if( ret.code != 0 )
	     errmsg = krb5_get_error_message(handle ? handle->context : NULL, ret.code);

		audit_kadmind_auth(rqstp->rq_xprt, l_port,
				"kadm5_delete_principal",
				prime_arg, client_name, ret.code);
	 log_done("kadm5_delete_principal", prime_arg,
		  errmsg ? errmsg : "success",
		  client_name, service_name, client_addr(rqstp, buf));

	  if (errmsg != NULL)
		krb5_free_error_message(handle ? handle->context : NULL, errmsg);

    }

error:
    if (name)
    	gss_release_name(&min_stat, &name);
    if (prime_arg)
    	free(prime_arg);
    free_server_handle(handle);
    if (client_name)
    	free(client_name);
    if (service_name)
    	free(service_name);
    return &ret;
}

generic_ret *
modify_principal_2_svc(mprinc_arg *arg, struct svc_req *rqstp)
{
    static generic_ret		    ret;
    char *prime_arg = NULL;
    char *client_name = NULL, *service_name = NULL;
    OM_uint32 min_stat;
    kadm5_server_handle_t handle;
    restriction_t *rp;
    gss_name_t name = NULL;
    const char                            *errmsg = NULL;

    xdr_free(xdr_generic_ret, (char *) &ret);

    if ((ret.code = new_server_handle(arg->api_version, rqstp, &handle)))
	 return &ret;

    if ((ret.code = check_handle((void *)handle)))
		goto error;
   if (setup_gss_names(rqstp, &client_name, &service_name) < 0) {
	 ret.code = KADM5_FAILURE;
		goto error;
    }
    if (krb5_unparse_name(handle->context, arg->rec.principal, &prime_arg)) {
	 ret.code = KADM5_BAD_PRINCIPAL;
	 goto error;
    }
	if (!(name = get_clnt_name(rqstp))) {
		ret.code = KADM5_FAILURE;
		goto error;
	}

    if (CHANGEPW_SERVICE(rqstp)
	|| !kadm5int_acl_check(handle->context, name, ACL_MODIFY,
		      arg->rec.principal, &rp)
	|| kadm5int_acl_impose_restrictions(handle->context,
				   &arg->rec, &arg->mask, rp)) {
	 ret.code = KADM5_AUTH_MODIFY;

		audit_kadmind_unauth(rqstp->rq_xprt, l_port,
				    "kadm5_modify_principal",
				    prime_arg, client_name);
	 log_unauth("kadm5_modify_principal", prime_arg, client_name,
		    service_name, client_addr(rqstp, buf));
    } else {
	 ret.code = kadm5_modify_principal((void *)handle, &arg->rec,
						arg->mask);
	/* Solaris Kerberos */
	 if( ret.code != 0 )
	     errmsg = krb5_get_error_message(handle ? handle->context : NULL, ret.code);

		audit_kadmind_auth(rqstp->rq_xprt, l_port,
				"kadm5_modify_principal",
				prime_arg, client_name, ret.code);
	 log_done("kadm5_modify_principal", prime_arg,
		  errmsg ? errmsg : "success",
		  client_name, service_name, client_addr(rqstp, buf));

	  if (errmsg != NULL)
		krb5_free_error_message(handle ? handle->context : NULL, errmsg);
    }

error:
    if (name)
    	gss_release_name(&min_stat, &name);
    free_server_handle(handle);
    if (prime_arg)
    	free(prime_arg);
    if (client_name)
    	free(client_name);
    if (service_name)
    	free(service_name);
    return &ret;
}

generic_ret *
rename_principal_2_svc(rprinc_arg *arg, struct svc_req *rqstp)
{
    static generic_ret		ret;
    char			*prime_arg1 = NULL, *prime_arg2 = NULL;
    char prime_arg[BUFSIZ];
    char *client_name = NULL, *service_name = NULL;
    OM_uint32 min_stat;
    kadm5_server_handle_t handle;
    restriction_t *rp;
    const char                        *errmsg = NULL;
    gss_name_t name = NULL;
    size_t tlen1, tlen2, clen, slen;
    char *tdots1, *tdots2, *cdots, *sdots;

    xdr_free(xdr_generic_ret, (char *) &ret);

    if ((ret.code = new_server_handle(arg->api_version, rqstp, &handle)))
	 return &ret;

    if ((ret.code = check_handle((void *)handle)))
	 goto error;
    if (setup_gss_names(rqstp, &client_name, &service_name) < 0) {
	 ret.code = KADM5_FAILURE;
	 goto error;
    }
    if (krb5_unparse_name(handle->context, arg->src, &prime_arg1) ||
        krb5_unparse_name(handle->context, arg->dest, &prime_arg2)) {
	 ret.code = KADM5_BAD_PRINCIPAL;
	 goto error;
    }
    tlen1 = strlen(prime_arg1);
    trunc_name(&tlen1, &tdots1);
    tlen2 = strlen(prime_arg2);
    trunc_name(&tlen2, &tdots2);
    clen = strlen(client_name);
    trunc_name(&clen, &cdots);
    slen = strlen(service_name);
    trunc_name(&slen, &sdots);

    (void) snprintf(prime_arg, sizeof (prime_arg), "%.*s%s to %.*s*s",
	tlen1, prime_arg1, tdots1,
	tlen2, prime_arg2, tdots2);
    ret.code = KADM5_OK;

	if (!(name = get_clnt_name(rqstp))) {
		ret.code = KADM5_FAILURE;
		goto error;
	}

    if (! CHANGEPW_SERVICE(rqstp)) {
	 if (!kadm5int_acl_check(handle->context, name,
			ACL_DELETE, arg->src, NULL))
	      ret.code = KADM5_AUTH_DELETE;
	 /* any restrictions at all on the ADD kills the RENAME */
	 if (!kadm5int_acl_check(handle->context, name,
			ACL_ADD, arg->dest, &rp)) {
	      if (ret.code == KADM5_AUTH_DELETE)
		   ret.code = KADM5_AUTH_INSUFFICIENT;
	      else
		   ret.code = KADM5_AUTH_ADD;
	 }
    } else
	 ret.code = KADM5_AUTH_INSUFFICIENT;
    if (ret.code != KADM5_OK) {

		audit_kadmind_unauth(rqstp->rq_xprt, l_port,
				    "kadm5_rename_principal",
				    prime_arg, client_name);
		krb5_klog_syslog(LOG_NOTICE,
		    "Unauthorized request: kadm5_rename_principal, "
		    "%.*s%s to %.*s%s, "    
		    "client=%.*s%s, service=%.*s%s, addr=%s",
		    tlen1, prime_arg1, tdots1,
		    tlen2, prime_arg2, tdots2,
		    clen, client_name, cdots,
		    slen, service_name, sdots,
		    client_addr(rqstp, buf));
    } else {
	 ret.code = kadm5_rename_principal((void *)handle, arg->src,
						arg->dest);
	/* Solaris Kerberos */
	 if( ret.code != 0 )
	     errmsg = krb5_get_error_message(handle ? handle->context : NULL, ret.code);

		audit_kadmind_auth(rqstp->rq_xprt, l_port,
				"kadm5_rename_principal",
				prime_arg, client_name, ret.code);
	 krb5_klog_syslog(LOG_NOTICE,
			  "Request: kadm5_rename_principal, "
			  "%.*s%s to %.*s%s, %s, "
			  "client=%.*s%s, service=%.*s%s, addr=%s",
			  tlen1, prime_arg1, tdots1,
			  tlen2, prime_arg2, tdots2,
			  errmsg ? errmsg : "success",
			  clen, client_name, cdots,
			  slen, service_name, sdots,
			  client_addr(rqstp, buf));

	  if (errmsg != NULL)
		krb5_free_error_message(handle ? handle->context : NULL, errmsg);
    }

error:
    if (name)
    	gss_release_name(&min_stat, &name);
    free_server_handle(handle);
    if (prime_arg1)
    	free(prime_arg1);
    if (prime_arg2)
    	free(prime_arg2);
    if (client_name)
    	free(client_name);
    if (service_name)
    	free(service_name);
    return &ret;
}

gprinc_ret *
get_principal_2_svc(gprinc_arg *arg, struct svc_req *rqstp)
{
    static gprinc_ret		    ret;
    kadm5_principal_ent_t_v1	    e;
    char			    *prime_arg = NULL, *funcname;
    char *client_name = NULL, *service_name = NULL;
    OM_uint32			    min_stat;
    kadm5_server_handle_t	    handle;
    const char                            *errmsg = NULL;
    gss_name_t name = NULL;

    xdr_free(xdr_gprinc_ret, (char *) &ret);

    if ((ret.code = new_server_handle(arg->api_version, rqstp, &handle)))
	 return &ret;

    if ((ret.code = check_handle((void *)handle)))
		goto error;
    ret.api_version = handle->api_version;

    funcname = handle->api_version == KADM5_API_VERSION_1 ?
	 "kadm5_get_principal (V1)" : "kadm5_get_principal";

    if (setup_gss_names(rqstp, &client_name, &service_name) < 0) {
	 ret.code = KADM5_FAILURE;
		goto error;
    }
    if (krb5_unparse_name(handle->context, arg->princ, &prime_arg)) {
	 ret.code = KADM5_BAD_PRINCIPAL;
		goto error;
    }
	if (!(name = get_clnt_name(rqstp))) {
		ret.code = KADM5_FAILURE;
		goto error;
	}

    if (! cmp_gss_krb5_name(handle, name, arg->princ) &&
	(CHANGEPW_SERVICE(rqstp) || !kadm5int_acl_check(handle->context,
					       name,
					       ACL_INQUIRE,
					       arg->princ,
					       NULL))) {
	 ret.code = KADM5_AUTH_GET;

		audit_kadmind_unauth(rqstp->rq_xprt, l_port,
				    funcname,
				    prime_arg, client_name);
	 log_unauth(funcname, prime_arg, client_name, service_name,
		    client_addr(rqstp, buf));
    } else {
	 if (handle->api_version == KADM5_API_VERSION_1) {
	      ret.code  = kadm5_get_principal_v1((void *)handle,
						 arg->princ, &e); 
	      if(ret.code == KADM5_OK) {
		   memcpy(&ret.rec, e, sizeof(kadm5_principal_ent_rec_v1));
		   free(e);
	      }
	 } else {
	      ret.code  = kadm5_get_principal((void *)handle,
					      arg->princ, &ret.rec,
					      arg->mask);
	 }
	 
	/* Solaris Kerberos */
	 if( ret.code != 0 )
	     errmsg = krb5_get_error_message(handle ? handle->context : NULL, ret.code);

		audit_kadmind_auth(rqstp->rq_xprt, l_port,
				funcname,
				prime_arg, client_name, ret.code);
	 log_done(funcname, prime_arg, errmsg ? errmsg : "success",
		  client_name, service_name, client_addr(rqstp, buf));

	  if (errmsg != NULL)
		krb5_free_error_message(handle ? handle->context : NULL, errmsg);
    }

error:
	if (name)
    	gss_release_name(&min_stat, &name);
    free_server_handle(handle);
    if (prime_arg)
    	free(prime_arg);
    if (client_name)
    	free(client_name);
    if (service_name)
    	free(service_name);
    return &ret;
}

gprincs_ret *
get_princs_2_svc(gprincs_arg *arg, struct svc_req *rqstp)
{
    static gprincs_ret		    ret;
    char			    *prime_arg = NULL;
    char *client_name = NULL, *service_name = NULL;
    OM_uint32			    min_stat;
    kadm5_server_handle_t handle;
    gss_name_t name = NULL;
    const char                            *errmsg = NULL;

    xdr_free(xdr_gprincs_ret, (char *) &ret);

    if ((ret.code = new_server_handle(arg->api_version, rqstp, &handle)))
	 return &ret;

    if ((ret.code = check_handle((void *)handle)))
		goto error;
    ret.api_version = handle->api_version;

    if (setup_gss_names(rqstp, &client_name, &service_name) < 0) {
	 ret.code = KADM5_FAILURE;
		goto error;
    }
    prime_arg = arg->exp;
    if (prime_arg == NULL)
	 prime_arg = "*";

	if (!(name = get_clnt_name(rqstp))) {
		ret.code = KADM5_FAILURE;
		goto error;
	}

    if (CHANGEPW_SERVICE(rqstp) || !kadm5int_acl_check(handle->context,
					      name,
					      ACL_LIST,
					      NULL,
					      NULL)) {
	 ret.code = KADM5_AUTH_LIST;

		audit_kadmind_unauth(rqstp->rq_xprt, l_port,
				    "kadm5_get_principals",
				    prime_arg, client_name);
	 log_unauth("kadm5_get_principals", prime_arg, client_name,
		    service_name, client_addr(rqstp, buf));
    } else {
	 ret.code  = kadm5_get_principals((void *)handle,
					       arg->exp, &ret.princs,
					       &ret.count);
	/* Solaris Kerberos */
	 if( ret.code != 0 )
	     errmsg = krb5_get_error_message(handle ? handle->context : NULL, ret.code);

		audit_kadmind_auth(rqstp->rq_xprt, l_port,
				"kadm5_get_principals",
				prime_arg, client_name, ret.code);
	 log_done("kadm5_get_principals", prime_arg,
		  errmsg ? errmsg : "success",
		  client_name, service_name, client_addr(rqstp, buf));
		
	  if (errmsg != NULL)
		krb5_free_error_message(handle ? handle->context : NULL, errmsg);
	}

error:
	if (name)
		gss_release_name(&min_stat, &name);
	free_server_handle(handle);
	if (client_name)
		free(client_name);
	if (service_name)
		free(service_name);
	return (&ret);
}

generic_ret *
chpass_principal_2_svc(chpass_arg *arg, struct svc_req *rqstp)
{
    static generic_ret		    ret;
    char			    *prime_arg = NULL;
    char *client_name = NULL, *service_name = NULL;
    OM_uint32 min_stat;
    kadm5_server_handle_t	    handle;
    const char                            *errmsg = NULL;
    gss_name_t name = NULL;

    xdr_free(xdr_generic_ret, (char *) &ret);

    if ((ret.code = new_server_handle(arg->api_version, rqstp, &handle)))
	 return &ret;

    if ((ret.code = check_handle((void *)handle)))
		goto error;
    ret.api_version = handle->api_version;

    if (setup_gss_names(rqstp, &client_name, &service_name) < 0) {
	 ret.code = KADM5_FAILURE;
		goto error;
    }
    if (krb5_unparse_name(handle->context, arg->princ, &prime_arg)) {
	 ret.code = KADM5_BAD_PRINCIPAL;
		goto error;
	}	
	if (!(name = get_clnt_name(rqstp))) {
		ret.code = KADM5_FAILURE;
		goto error;
	}

    if (cmp_gss_krb5_name(handle, name, arg->princ)) {
	 ret.code = chpass_principal_wrapper_3((void *)handle, arg->princ,
					       FALSE, 0, NULL, arg->pass);
    } else if (!(CHANGEPW_SERVICE(rqstp)) &&
	       kadm5int_acl_check(handle->context, name,
			 ACL_CHANGEPW, arg->princ, NULL)) {
	 ret.code = kadm5_chpass_principal((void *)handle, arg->princ,
						arg->pass);
    } else {
		audit_kadmind_unauth(rqstp->rq_xprt, l_port,
				    "kadm5_chpass_principal",
				    prime_arg, client_name);
	 log_unauth("kadm5_chpass_principal", prime_arg, client_name,
		    service_name, client_addr(rqstp, buf));
	 ret.code = KADM5_AUTH_CHANGEPW;
    }

    if(ret.code != KADM5_AUTH_CHANGEPW) {
	/* Solaris Kerberos */
	 if( ret.code != 0 )
	     errmsg = krb5_get_error_message(handle ? handle->context : NULL, ret.code);

		audit_kadmind_auth(rqstp->rq_xprt, l_port,
				"kadm5_chpass_principal",
				prime_arg, client_name, ret.code);
	log_done("kadm5_chpass_principal", prime_arg,
		 errmsg ? errmsg : "success",
		 client_name, service_name, client_addr(rqstp, buf));

	  if (errmsg != NULL)
		krb5_free_error_message(handle ? handle->context : NULL, errmsg);
    }

error:
	if (name)
		gss_release_name(&min_stat, &name);
	free_server_handle(handle);
	if (prime_arg)
		free(prime_arg);
	if (client_name)
		free(client_name);
	if (service_name)
		free(service_name);
	return (&ret);
}

generic_ret *
chpass_principal3_2_svc(chpass3_arg *arg, struct svc_req *rqstp)
{
    static generic_ret		    ret;
    char			    *prime_arg = NULL;
    char       			    *client_name = NULL,
				    *service_name = NULL;
    OM_uint32			    min_stat;
    kadm5_server_handle_t	    handle;
    const char                            *errmsg = NULL;
    gss_name_t name = NULL;

    xdr_free(xdr_generic_ret, (char *) &ret);

    if ((ret.code = new_server_handle(arg->api_version, rqstp, &handle)))
	 return &ret;

    if ((ret.code = check_handle((void *)handle)))
	goto error;
    ret.api_version = handle->api_version;

    if (setup_gss_names(rqstp, &client_name, &service_name) < 0) {
	 ret.code = KADM5_FAILURE;
	goto error;
    }
    if (krb5_unparse_name(handle->context, arg->princ, &prime_arg)) {
	 ret.code = KADM5_BAD_PRINCIPAL;
	goto error;
    }	
    if (!(name = get_clnt_name(rqstp))) {
	ret.code = KADM5_FAILURE;
	goto error;
    }

    if (cmp_gss_krb5_name(handle, name, arg->princ)) {
	 ret.code = chpass_principal_wrapper_3((void *)handle, arg->princ,
					       arg->keepold,
					       arg->n_ks_tuple,
					       arg->ks_tuple,
					       arg->pass);
    } else if (!(CHANGEPW_SERVICE(rqstp)) &&
	       kadm5int_acl_check(handle->context, name,
			 ACL_CHANGEPW, arg->princ, NULL)) {
	 ret.code = kadm5_chpass_principal_3((void *)handle, arg->princ,
					     arg->keepold,
					     arg->n_ks_tuple,
					     arg->ks_tuple,
					     arg->pass);
    } else {
	 log_unauth("kadm5_chpass_principal", prime_arg,
		client_name, service_name, client_addr(rqstp, buf));
	 ret.code = KADM5_AUTH_CHANGEPW;
    }

    if(ret.code != KADM5_AUTH_CHANGEPW) {
	/* Solaris Kerberos */
	if( ret.code != 0 )
	     errmsg = krb5_get_error_message(handle ? handle->context : NULL, ret.code);

	log_done("kadm5_chpass_principal", prime_arg,
		errmsg ? errmsg : "success",
		client_name, service_name, client_addr(rqstp, buf));
 
	  if (errmsg != NULL)
		krb5_free_error_message(handle ? handle->context : NULL, errmsg);
    }

error:
    if (name)
    	gss_release_name(&min_stat, &name);
    free_server_handle(handle);
    if (client_name)
    	free(client_name);
    if (service_name)
    	free(service_name);
    if (prime_arg)
    	free(prime_arg);
    return (&ret);
}

#ifdef SUNWOFF
generic_ret *
setv4key_principal_2_svc(setv4key_arg *arg, struct svc_req *rqstp)
{
    static generic_ret		    ret;
    char			    *prime_arg = NULL;
    char 			    *client_name = NULL,
				    *service_name = NULL;
    OM_uint32			    min_stat;
    kadm5_server_handle_t	    handle;
    const char                            *errmsg = NULL;
    gss_name_t name = NULL;

    xdr_free(xdr_generic_ret, (char *) &ret);

    if ((ret.code = new_server_handle(arg->api_version, rqstp, &handle)))
	 return &ret;

    if ((ret.code = check_handle((void *)handle)))
	goto error;
    ret.api_version = handle->api_version;

    if (setup_gss_names(rqstp, &client_name, &service_name) < 0) {
	 ret.code = KADM5_FAILURE;
	goto error;
    }
    if (krb5_unparse_name(handle->context, arg->princ, &prime_arg)) {
	 ret.code = KADM5_BAD_PRINCIPAL;
	goto error;
    }	
    if (!(name = get_clnt_name(rqstp))) {
	ret.code = KADM5_FAILURE;
	goto error;
    }

    if (!(CHANGEPW_SERVICE(rqstp)) &&
	       kadm5int_acl_check(handle->context, name,
			 ACL_SETKEY, arg->princ, NULL)) {
	 ret.code = kadm5_setv4key_principal((void *)handle, arg->princ,
					     arg->keyblock);
    } else {
	 log_unauth("kadm5_setv4key_principal", prime_arg,
		client_name, service_name, client_addr(rqstp, buf));
	 ret.code = KADM5_AUTH_SETKEY;
    }

    if(ret.code != KADM5_AUTH_SETKEY) {
	/* Solaris Kerberos */
	if( ret.code != 0 )
	     errmsg = krb5_get_error_message(handle ? handle->context : NULL, ret.code);

	log_done("kadm5_setv4key_principal", prime_arg,
		 errmsg ? errmsg : "success",
		 client_name, service_name, client_addr(rqstp, buf));

	  if (errmsg != NULL)
		krb5_free_error_message(handle ? handle->context : NULL, errmsg);
    }

error:
    if (name)
	gss_release_name(&min_stat, &name);
    free_server_handle(handle);
    if (client_name)
	free(client_name);
    if (service_name)
	free(service_name);
    if (prime_arg)
	free(prime_arg);
    return (&ret);
}
#endif

generic_ret *
setkey_principal_2_svc(setkey_arg *arg, struct svc_req *rqstp)
{
    static generic_ret		    ret;
    char			    *prime_arg;
    char			    *client_name,
				    *service_name;
    OM_uint32			    min_stat;
    kadm5_server_handle_t	    handle;
    const char                            *errmsg = NULL;
    gss_name_t name;

    xdr_free(xdr_generic_ret, (char *) &ret);

    if ((ret.code = new_server_handle(arg->api_version, rqstp, &handle)))
	 return &ret;

    if ((ret.code = check_handle((void *)handle)))
	goto error;
    ret.api_version = handle->api_version;

    if (setup_gss_names(rqstp, &client_name, &service_name) < 0) {
	 ret.code = KADM5_FAILURE;
	goto error;
    }
    if (krb5_unparse_name(handle->context, arg->princ, &prime_arg)) {
	 ret.code = KADM5_BAD_PRINCIPAL;
	goto error;
    }	
    if (!(name = get_clnt_name(rqstp))) {
	 ret.code = KADM5_FAILURE;
	goto error;
    }

    if (!(CHANGEPW_SERVICE(rqstp)) &&
	       kadm5int_acl_check(handle->context, name, ACL_SETKEY, arg->princ, NULL)) {
	 ret.code = kadm5_setkey_principal((void *)handle, arg->princ,
					   arg->keyblocks, arg->n_keys);
    } else {
	 log_unauth("kadm5_setkey_principal", prime_arg,
		client_name, service_name, client_addr(rqstp, buf));
	 ret.code = KADM5_AUTH_SETKEY;
    }

    if(ret.code != KADM5_AUTH_SETKEY) {
	/* Solaris Kerberos */
	if( ret.code != 0 )
	    errmsg = krb5_get_error_message(handle ? handle->context : NULL, ret.code);

	log_done("kadm5_setkey_principal", prime_arg,
		 errmsg ? errmsg : "success",
		 client_name, service_name, client_addr(rqstp, buf));
	
	  if (errmsg != NULL)
		krb5_free_error_message(handle ? handle->context : NULL, errmsg);
    }

error:
    if (name)
	gss_release_name(&min_stat, &name);
    free_server_handle(handle);
    if (client_name)
    	free(client_name);
    if (service_name)
    	free(service_name);
    if (prime_arg)
    	free(prime_arg);
    return (&ret);
}

generic_ret *
setkey_principal3_2_svc(setkey3_arg *arg, struct svc_req *rqstp)
{
    static generic_ret		    ret;
    char			    *prime_arg = NULL;
    char			    *client_name = NULL,
				    *service_name = NULL;
    OM_uint32			    min_stat;
    kadm5_server_handle_t	    handle;
    const char                            *errmsg = NULL;
    gss_name_t name = NULL;

    xdr_free(xdr_generic_ret, (char *) &ret);

    if ((ret.code = new_server_handle(arg->api_version, rqstp, &handle)))
	 return &ret;

    if ((ret.code = check_handle((void *)handle)))
	goto error;
    ret.api_version = handle->api_version;

    if (setup_gss_names(rqstp, &client_name, &service_name) < 0) {
	 ret.code = KADM5_FAILURE;
	goto error;
    }
    if (krb5_unparse_name(handle->context, arg->princ, &prime_arg)) {
	 ret.code = KADM5_BAD_PRINCIPAL;
	goto error;
    }	
    if (!(name = get_clnt_name(rqstp))) {
	 ret.code = KADM5_FAILURE;
	goto error;
    }

    if (!(CHANGEPW_SERVICE(rqstp)) &&
	       kadm5int_acl_check(handle->context, name,
			 ACL_SETKEY, arg->princ, NULL)) {
	 ret.code = kadm5_setkey_principal_3((void *)handle, arg->princ,
					     arg->keepold,
					     arg->n_ks_tuple,
					     arg->ks_tuple,
					     arg->keyblocks, arg->n_keys);
    } else {
	 log_unauth("kadm5_setkey_principal", prime_arg,
		client_name, service_name, client_addr(rqstp, buf));
	 ret.code = KADM5_AUTH_SETKEY;
    }

    if(ret.code != KADM5_AUTH_SETKEY) {
	/* Solaris Kerberos */
	if( ret.code != 0 )
	    errmsg = krb5_get_error_message(handle ? handle->context : NULL, ret.code);

	log_done("kadm5_setkey_principal", prime_arg,
		 errmsg ? errmsg : "success",
		 client_name, service_name, client_addr(rqstp, buf));

	  if (errmsg != NULL)
		krb5_free_error_message(handle ? handle->context : NULL, errmsg);
    }

error:
    if (name)
	gss_release_name(&min_stat, &name);
    free_server_handle(handle);
    if (client_name)
	free(client_name);
    if (service_name)
    	free(service_name);
    if (prime_arg)
    	free(prime_arg);
    return &ret;
}

chrand_ret *
chrand_principal_2_svc(chrand_arg *arg, struct svc_req *rqstp)
{
    static chrand_ret		ret;
    krb5_keyblock		*k;
    int				nkeys;
    char			*prime_arg = NULL, *funcname;
    char *client_name = NULL, *service_name = NULL;
    OM_uint32			min_stat;
    kadm5_server_handle_t	handle;
    const char                        *errmsg = NULL;
    gss_name_t name = NULL;

    xdr_free(xdr_chrand_ret, (char *) &ret);

    if ((ret.code = new_server_handle(arg->api_version, rqstp, &handle)))
	 return &ret;

    if ((ret.code = check_handle((void *)handle)))
		goto error;

    ret.api_version = handle->api_version;

    funcname = handle->api_version == KADM5_API_VERSION_1 ?
	 "kadm5_randkey_principal (V1)" : "kadm5_randkey_principal";

    if (setup_gss_names(rqstp, &client_name, &service_name) < 0) {
	 ret.code = KADM5_FAILURE;
		goto error;
    }
    if (krb5_unparse_name(handle->context, arg->princ, &prime_arg)) {
	 ret.code = KADM5_BAD_PRINCIPAL;
		goto error;
    }
	if (!(name = get_clnt_name(rqstp))) {
		ret.code = KADM5_FAILURE;
		goto error;
	}

    if (cmp_gss_krb5_name(handle, name, arg->princ)) {
	 ret.code = randkey_principal_wrapper((void *)handle, arg->princ, &k,
						&nkeys);
    } else if (!(CHANGEPW_SERVICE(rqstp)) &&
	       kadm5int_acl_check(handle->context, name,
			 ACL_CHANGEPW, arg->princ, NULL)) {
	 ret.code = kadm5_randkey_principal((void *)handle, arg->princ,
					    &k, &nkeys);
    } else {
		audit_kadmind_unauth(rqstp->rq_xprt, l_port,
				    funcname, prime_arg, client_name);
	 log_unauth(funcname, prime_arg,
		client_name, service_name, client_addr(rqstp, buf));
	 ret.code = KADM5_AUTH_CHANGEPW;
    }

    if(ret.code == KADM5_OK) {
	 if (handle->api_version == KADM5_API_VERSION_1) {
	      krb5_copy_keyblock_contents(handle->context, k, &ret.key);
	      krb5_free_keyblock(handle->context, k);
	 } else {
	      ret.keys = k;
	      ret.n_keys = nkeys;
	 }
    }

    if(ret.code != KADM5_AUTH_CHANGEPW) {
	/* Solaris Kerberos */
	if( ret.code != 0 )
	    errmsg = krb5_get_error_message(handle ? handle->context : NULL, ret.code);

		audit_kadmind_auth(rqstp->rq_xprt, l_port,
				funcname, prime_arg, client_name, ret.code);
	log_done(funcname, prime_arg, errmsg ? errmsg : "success",
		 client_name, service_name, client_addr(rqstp, buf));
	
	  if (errmsg != NULL)
		krb5_free_error_message(handle ? handle->context : NULL, errmsg);
    }

error:
	if (name)
		gss_release_name(&min_stat, &name);
	free_server_handle(handle);
	if (prime_arg)
    	free(prime_arg);
    if (client_name)
    	free(client_name);
    if (service_name)
    	free(service_name);
    return &ret;
}

chrand_ret *
chrand_principal3_2_svc(chrand3_arg *arg, struct svc_req *rqstp)
{
    static chrand_ret		ret;
    krb5_keyblock		*k;
    int				nkeys;
    char			*prime_arg = NULL, *funcname;
    char			*client_name = NULL,
	    			*service_name = NULL;
    OM_uint32			min_stat;
    kadm5_server_handle_t	handle;
    const char                        *errmsg = NULL;
    gss_name_t name = NULL;

    xdr_free(xdr_chrand_ret, (char *) &ret);

    if ((ret.code = new_server_handle(arg->api_version, rqstp, &handle)))
	 return &ret;

    if ((ret.code = check_handle((void *)handle)))
	goto error;
    ret.api_version = handle->api_version;

    funcname = handle->api_version == KADM5_API_VERSION_1 ?
	 "kadm5_randkey_principal (V1)" : "kadm5_randkey_principal";

    if (setup_gss_names(rqstp, &client_name, &service_name) < 0) {
	ret.code = KADM5_FAILURE;
	goto error;
    }
    if (krb5_unparse_name(handle->context, arg->princ, &prime_arg)) {
	 ret.code = KADM5_BAD_PRINCIPAL;
	goto error;
    }	
    if (!(name = get_clnt_name(rqstp))) {
	ret.code = KADM5_FAILURE;
	goto error;
    }

    if (cmp_gss_krb5_name(handle, name, arg->princ)) {
	 ret.code = randkey_principal_wrapper_3((void *)handle, arg->princ,
						arg->keepold,
						arg->n_ks_tuple,
						arg->ks_tuple,
						&k, &nkeys);
    } else if (!(CHANGEPW_SERVICE(rqstp)) &&
	       kadm5int_acl_check(handle->context, name,
			 ACL_CHANGEPW, arg->princ, NULL)) {
	 ret.code = kadm5_randkey_principal_3((void *)handle, arg->princ,
					      arg->keepold,
					      arg->n_ks_tuple,
					      arg->ks_tuple,
					      &k, &nkeys);
    } else {
	 log_unauth(funcname, prime_arg,
		client_name, service_name, client_addr(rqstp, buf));
	 ret.code = KADM5_AUTH_CHANGEPW;
    }

    if(ret.code == KADM5_OK) {
	 if (handle->api_version == KADM5_API_VERSION_1) {
	      krb5_copy_keyblock_contents(handle->context, k, &ret.key);
	      krb5_free_keyblock(handle->context, k);
	 } else {
	      ret.keys = k;
	      ret.n_keys = nkeys;
	 }
    }

    if(ret.code != KADM5_AUTH_CHANGEPW) {
	/* Solaris Kerberos */
	if( ret.code != 0 )
	    errmsg = krb5_get_error_message(handle ? handle->context : NULL, ret.code);

	log_done(funcname, prime_arg, errmsg ? errmsg : "success",
		 client_name, service_name, client_addr(rqstp, buf));

	if (errmsg != NULL)
		krb5_free_error_message(handle ? handle->context : NULL, errmsg);
    }

error:
    if (name)
	gss_release_name(&min_stat, &name);
    free_server_handle(handle);
    if (client_name)
	free(client_name);
    if (service_name)
	free(service_name);
    if (prime_arg)
	free(prime_arg);
    return (&ret);
}

generic_ret *
create_policy_2_svc(cpol_arg *arg, struct svc_req *rqstp)
{
    static generic_ret		    ret;
    char			    *prime_arg = NULL;
    char *client_name = NULL, *service_name = NULL;
    OM_uint32			    min_stat;    
    kadm5_server_handle_t	    handle;
    const char                            *errmsg = NULL;
    gss_name_t name = NULL;

    xdr_free(xdr_generic_ret, (char *) &ret);

    if ((ret.code = new_server_handle(arg->api_version, rqstp, &handle)))
	 return &ret;

    if ((ret.code = check_handle((void *)handle)))
		goto error;

    ret.api_version = handle->api_version;

    if (setup_gss_names(rqstp, &client_name, &service_name) < 0) {
	 ret.code = KADM5_FAILURE;
		goto error;
    }
    prime_arg = arg->rec.policy;

	if (!(name = get_clnt_name(rqstp))) {
		ret.code = KADM5_FAILURE;
		goto error;
	}

    if (CHANGEPW_SERVICE(rqstp) || !kadm5int_acl_check(handle->context,
					      name,
					      ACL_ADD, NULL, NULL)) {
	 ret.code = KADM5_AUTH_ADD;

		audit_kadmind_unauth(rqstp->rq_xprt, l_port,
				    "kadm5_create_policy",
				    prime_arg, client_name);
	 log_unauth("kadm5_create_policy", prime_arg,
		 client_name, service_name, client_addr(rqstp, buf));

    } else {
	 ret.code = kadm5_create_policy((void *)handle, &arg->rec,
					     arg->mask);
	/* Solaris Kerberos */
	 if( ret.code != 0 )
	     errmsg = krb5_get_error_message(handle ? handle->context : NULL, ret.code);

		audit_kadmind_auth(rqstp->rq_xprt, l_port,
				"kadm5_create_policy",
				prime_arg, client_name, ret.code);
	 log_done("kadm5_create_policy",
		  ((prime_arg == NULL) ? "(null)" : prime_arg),
		  errmsg ? errmsg : "success",
		  client_name, service_name, client_addr(rqstp, buf));

	  if (errmsg != NULL)
		krb5_free_error_message(handle ? handle->context : NULL, errmsg);
    }

error:
	if (name)
		gss_release_name(&min_stat, &name);
    free_server_handle(handle);
    if (client_name)
    	free(client_name);
    if (service_name)
    	free(service_name);
    return &ret;
}

generic_ret *
delete_policy_2_svc(dpol_arg *arg, struct svc_req *rqstp)
{
    static generic_ret		    ret;
    char			    *prime_arg = NULL;
    char *client_name = NULL, *service_name = NULL;
    OM_uint32			    min_stat;
    kadm5_server_handle_t	    handle;
    const char                            *errmsg = NULL;
    gss_name_t name = NULL;

    xdr_free(xdr_generic_ret, (char *) &ret);

    if ((ret.code = new_server_handle(arg->api_version, rqstp, &handle)))
	 return &ret;

    if ((ret.code = check_handle((void *)handle)))
		goto error;
    ret.api_version = handle->api_version;

    if (setup_gss_names(rqstp, &client_name, &service_name) < 0) {
	 ret.code = KADM5_FAILURE;
		goto error;
    }
    prime_arg = arg->name;
    
	if (!(name = get_clnt_name(rqstp))) {
		ret.code = KADM5_FAILURE;
		goto error;
	}

    if (CHANGEPW_SERVICE(rqstp) || !kadm5int_acl_check(handle->context,
						name,
					      ACL_DELETE, NULL, NULL)) {

		audit_kadmind_unauth(rqstp->rq_xprt, l_port,
				    "kadm5_delete_policy",
				    prime_arg, client_name);
	 log_unauth("kadm5_delete_policy", prime_arg,
		client_name, service_name, client_addr(rqstp, buf));
	 ret.code = KADM5_AUTH_DELETE;
    } else {
	 ret.code = kadm5_delete_policy((void *)handle, arg->name);
	/* Solaris Kerberos */
	 if( ret.code != 0 )
	     errmsg = krb5_get_error_message(handle ? handle->context : NULL, ret.code);

		audit_kadmind_auth(rqstp->rq_xprt, l_port,
				"kadm5_delete_policy",
				prime_arg, client_name, ret.code);
	 log_done("kadm5_delete_policy",
		  ((prime_arg == NULL) ? "(null)" : prime_arg),
		 errmsg ? errmsg : "success",
		  client_name, service_name, client_addr(rqstp, buf));
	
	 if (errmsg != NULL)
		krb5_free_error_message(handle ? handle->context : NULL, errmsg);
    }

error:
	if (name)
		gss_release_name(&min_stat, &name);
    free_server_handle(handle);
    if (client_name)
    free(client_name);
    if (service_name)
    free(service_name);
    return &ret;
}

generic_ret *
modify_policy_2_svc(mpol_arg *arg, struct svc_req *rqstp)
{
    static generic_ret		    ret;
    char			    *prime_arg = NULL;
    char *client_name = NULL, *service_name = NULL;
    OM_uint32 min_stat;
    kadm5_server_handle_t	    handle;
    const char                            *errmsg = NULL;
    gss_name_t name = NULL;

    xdr_free(xdr_generic_ret, (char *) &ret);

    if ((ret.code = new_server_handle(arg->api_version, rqstp, &handle)))
	 return &ret;

    if ((ret.code = check_handle((void *)handle)))
		goto error;
    ret.api_version = handle->api_version;

    if (setup_gss_names(rqstp, &client_name, &service_name) < 0) {
	 ret.code = KADM5_FAILURE;
		goto error;
    }
    prime_arg = arg->rec.policy;

    if (!(name = get_clnt_name(rqstp))) {
	 ret.code = KADM5_FAILURE;
		goto error;
    }

    if (CHANGEPW_SERVICE(rqstp) || !kadm5int_acl_check(handle->context,
						name,
					      ACL_MODIFY, NULL, NULL)) {

		audit_kadmind_unauth(rqstp->rq_xprt, l_port,
				    "kadm5_modify_policy",
				    prime_arg, client_name);
	 log_unauth("kadm5_modify_policy", prime_arg,
		client_name, service_name, client_addr(rqstp, buf));
	 ret.code = KADM5_AUTH_MODIFY;
    } else {
	 ret.code = kadm5_modify_policy((void *)handle, &arg->rec,
					     arg->mask);
	/* Solaris Kerberos */
	 if( ret.code != 0 )
	     errmsg = krb5_get_error_message(handle ? handle->context : NULL, ret.code);

		audit_kadmind_auth(rqstp->rq_xprt, l_port,
				"kadm5_modify_policy",
				prime_arg, client_name, ret.code);
	 log_done("kadm5_modify_policy",
		  ((prime_arg == NULL) ? "(null)" : prime_arg),
		  errmsg ? errmsg : "success",
		  client_name, service_name, client_addr(rqstp, buf));

	  if (errmsg != NULL)
		krb5_free_error_message(handle ? handle->context : NULL, errmsg);
    }

error:
	if (name)
		gss_release_name(&min_stat, &name);
	free_server_handle(handle);
	if (client_name)
		free(client_name);
	if (service_name)
		free(service_name);
	return (&ret);
}

gpol_ret * 
get_policy_2_svc(gpol_arg *arg, struct svc_req *rqstp)
{
    static gpol_ret		ret;
    kadm5_ret_t		ret2;
    char *prime_arg = NULL, *funcname;
    char *client_name = NULL, *service_name = NULL;
    OM_uint32 min_stat;
    kadm5_policy_ent_t	e;
    kadm5_principal_ent_rec	caller_ent;
    krb5_principal caller;
    kadm5_server_handle_t	handle;
    const char                        *errmsg = NULL;
  gss_name_t name = NULL;

    xdr_free(xdr_gpol_ret, (char *) &ret);

    if ((ret.code = new_server_handle(arg->api_version, rqstp, &handle)))
	 return &ret;

    if ((ret.code = check_handle((void *) handle)))
		goto error;

    ret.api_version = handle->api_version;

    funcname = handle->api_version == KADM5_API_VERSION_1 ?
	 "kadm5_get_policy (V1)" : "kadm5_get_policy";

    if (setup_gss_names(rqstp, &client_name, &service_name) < 0) {
	 ret.code = KADM5_FAILURE;
		goto error;
    }
    prime_arg = arg->name;
	ret.code = KADM5_AUTH_GET;

	if (!(name = get_clnt_name(rqstp))) {
		ret.code = KADM5_FAILURE;
		goto error;
	}

    if (!CHANGEPW_SERVICE(rqstp) && kadm5int_acl_check(handle->context,
						name,
						ACL_INQUIRE, NULL, NULL))
		ret.code = KADM5_OK;
	else {
		ret.code = kadm5_get_principal(handle->lhandle,
		    handle->current_caller,
		    &caller_ent,
		    KADM5_PRINCIPAL_NORMAL_MASK);
		if (ret.code == KADM5_OK) {
			if (caller_ent.aux_attributes & KADM5_POLICY &&
			    strcmp(caller_ent.policy, arg->name) == 0) {
		   ret.code = KADM5_OK;
	      } else ret.code = KADM5_AUTH_GET;
	      ret2 = kadm5_free_principal_ent(handle->lhandle,
					      &caller_ent);
	      ret.code = ret.code ? ret.code : ret2;
	 }
    }
    
    if (ret.code == KADM5_OK) {
	 if (handle->api_version == KADM5_API_VERSION_1) {
	      ret.code  = kadm5_get_policy_v1((void *)handle, arg->name, &e);
	      if(ret.code == KADM5_OK) {
		   memcpy(&ret.rec, e, sizeof(kadm5_policy_ent_rec));
		   free(e);
	      }
	 } else {
	      ret.code = kadm5_get_policy((void *)handle, arg->name,
					  &ret.rec);
	 }
	 
	/* Solaris Kerberos */
	 if( ret.code != 0 )
	     errmsg = krb5_get_error_message(handle ? handle->context : NULL, ret.code);

		audit_kadmind_auth(rqstp->rq_xprt, l_port,
				funcname, prime_arg, client_name, ret.code);
	 log_done(funcname,
		  ((prime_arg == NULL) ? "(null)" : prime_arg),
		  errmsg ? errmsg : "success",
		  client_name, service_name, client_addr(rqstp, buf));
	  
	 if (errmsg != NULL)
		krb5_free_error_message(handle ? handle->context : NULL, errmsg);

    } else {
		audit_kadmind_unauth(rqstp->rq_xprt, l_port,
				    funcname, prime_arg, client_name);
	 log_unauth(funcname, prime_arg,
		    client_name, service_name, client_addr(rqstp, buf));
    }

error:
	if (name)
		gss_release_name(&min_stat, &name);
	free_server_handle(handle);
	if (client_name)
		free(client_name);
	if (service_name)
		free(service_name);
	return (&ret);

}

gpols_ret *
get_pols_2_svc(gpols_arg *arg, struct svc_req *rqstp)
{
    static gpols_ret		    ret;
    char			    *prime_arg = NULL;
    char *client_name = NULL, *service_name = NULL;
    OM_uint32 min_stat;
    kadm5_server_handle_t handle;
    const char                            *errmsg = NULL;
    gss_name_t name = NULL;

    xdr_free(xdr_gpols_ret, (char *) &ret);

    if ((ret.code = new_server_handle(arg->api_version, rqstp, &handle)))
	 return &ret;

    if ((ret.code = check_handle((void *)handle)))
		goto error;

    ret.api_version = handle->api_version;

    if (setup_gss_names(rqstp, &client_name, &service_name) < 0) {
	 ret.code = KADM5_FAILURE;
	goto error;
    }
    prime_arg = arg->exp;
    if (prime_arg == NULL)
	 prime_arg = "*";

	if (!(name = get_clnt_name(rqstp))) {
		ret.code = KADM5_FAILURE;
		goto error;
	}

    if (CHANGEPW_SERVICE(rqstp) || !kadm5int_acl_check(handle->context,
					      name,
					      ACL_LIST, NULL, NULL)) {
	 ret.code = KADM5_AUTH_LIST;

		audit_kadmind_unauth(rqstp->rq_xprt, l_port,
				    "kadm5_get_policies",
				    prime_arg, client_name);
	 log_unauth("kadm5_get_policies", prime_arg,
		    client_name, service_name, client_addr(rqstp, buf));
    } else {
	 ret.code  = kadm5_get_policies((void *)handle,
					       arg->exp, &ret.pols,
					       &ret.count);
	/* Solaris Kerberos */
	 if( ret.code != 0 )
	     errmsg = krb5_get_error_message(handle ? handle->context : NULL, ret.code);

		audit_kadmind_auth(rqstp->rq_xprt, l_port,
				"kadm5_get_policies",
				prime_arg, client_name, ret.code);
	 log_done("kadm5_get_policies", prime_arg,
		  errmsg ? errmsg : "success",
		  client_name, service_name, client_addr(rqstp, buf));
	
	  if (errmsg != NULL)
		krb5_free_error_message(handle ? handle->context : NULL, errmsg);
    }

error:
	if (name)
		gss_release_name(&min_stat, &name);
	free_server_handle(handle);
	if (client_name)
		free(client_name);
	if (service_name)
		free(service_name);
	return (&ret);
}

getprivs_ret * get_privs_2_svc(krb5_ui_4 *arg, struct svc_req *rqstp)
{
     static getprivs_ret	    ret;
     char *client_name = NULL, *service_name = NULL;
     OM_uint32 min_stat;
     kadm5_server_handle_t handle;
     const char                           *errmsg = NULL;
     gss_name_t name = NULL;

     xdr_free(xdr_getprivs_ret, (char *) &ret);

     if ((ret.code = new_server_handle(*arg, rqstp, &handle)))
	  return &ret;

     if ((ret.code = check_handle((void *)handle)))
		goto error;

     ret.api_version = handle->api_version;

     if (setup_gss_names(rqstp, &client_name, &service_name) < 0) {
	  ret.code = KADM5_FAILURE;
	  goto error;
     }
	if (!(name = get_clnt_name(rqstp))) {
		ret.code = KADM5_FAILURE;
		goto error;
	}

	ret.code = __kadm5_get_priv((void *) handle, &ret.privs, name);
	/* Solaris Kerberos */
     if( ret.code != 0 )
	 errmsg = krb5_get_error_message(handle ? handle->context : NULL, ret.code);

	audit_kadmind_auth(rqstp->rq_xprt, l_port,
			"kadm5_get_privs", NULL, client_name,
			ret.code);
	log_done("kadm5_get_privs", client_name,
	    errmsg ? errmsg : "success",
	    client_name, service_name, client_addr(rqstp, buf));
	
	if (errmsg != NULL)
		krb5_free_error_message(handle ? handle->context : NULL, errmsg);

error:
	if (name)
		gss_release_name(&min_stat, &name);
	free_server_handle(handle);
	if (client_name)
		free(client_name);
	if (service_name)
		free(service_name);
	return (&ret);
}

generic_ret *init_2_svc(krb5_ui_4 *arg, struct svc_req *rqstp)
{
     static generic_ret		ret;
     char *client_name, *service_name;
     kadm5_server_handle_t handle;
     const char                       *errmsg = NULL;
     size_t clen, slen;
     char *cdots, *sdots;

     xdr_free(xdr_generic_ret, (char *) &ret);

     if ((ret.code = new_server_handle(*arg, rqstp, &handle)))
	  return &ret;
     if (! (ret.code = check_handle((void *)handle))) {
	 ret.api_version = handle->api_version;
     }

     free_server_handle(handle);

     if (setup_gss_names(rqstp, &client_name, &service_name) < 0) {
	  ret.code = KADM5_FAILURE;
	  return &ret;
     }

	/* Solaris Kerberos */
     if (ret.code != 0)
	 errmsg = krb5_get_error_message(NULL, ret.code);

	audit_kadmind_auth(rqstp->rq_xprt, l_port,
			(ret.api_version == KADM5_API_VERSION_1 ?
			"kadm5_init (V1)" : "kadm5_init"),
			NULL, client_name, ret.code);

     clen = strlen(client_name);
     trunc_name(&clen, &cdots);
     slen = strlen(service_name);
     trunc_name(&slen, &sdots);
     krb5_klog_syslog(LOG_NOTICE, "Request: %s, %.*s%s, %s, "
		      "client=%.*s%s, service=%.*s%s, addr=%s, flavor=%d",
		      (ret.api_version == KADM5_API_VERSION_1 ?
		       "kadm5_init (V1)" : "kadm5_init"),
		      clen, client_name, cdots,
		      errmsg ? errmsg : "success",
		      clen, client_name, cdots,
		      slen, service_name, sdots,
		      client_addr(rqstp, buf),
		      rqstp->rq_cred.oa_flavor);
	if (errmsg != NULL)
		krb5_free_error_message(NULL, errmsg);
	free(client_name);
	free(service_name);

	return (&ret);
}
