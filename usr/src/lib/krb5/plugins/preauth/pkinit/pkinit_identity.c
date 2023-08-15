/*
 * COPYRIGHT (C) 2007
 * THE REGENTS OF THE UNIVERSITY OF MICHIGAN
 * ALL RIGHTS RESERVED
 *
 * Permission is granted to use, copy, create derivative works
 * and redistribute this software and such derivative works
 * for any purpose, so long as the name of The University of
 * Michigan is not used in any advertising or publicity
 * pertaining to the use of distribution of this software
 * without specific, written prior authorization.  If the
 * above copyright notice or any other identification of the
 * University of Michigan is included in any copy of any
 * portion of this software, then the disclaimer below must
 * also be included.
 *
 * THIS SOFTWARE IS PROVIDED AS IS, WITHOUT REPRESENTATION
 * FROM THE UNIVERSITY OF MICHIGAN AS TO ITS FITNESS FOR ANY
 * PURPOSE, AND WITHOUT WARRANTY BY THE UNIVERSITY OF
 * MICHIGAN OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING
 * WITHOUT LIMITATION THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. THE
 * REGENTS OF THE UNIVERSITY OF MICHIGAN SHALL NOT BE LIABLE
 * FOR ANY DAMAGES, INCLUDING SPECIAL, INDIRECT, INCIDENTAL, OR
 * CONSEQUENTIAL DAMAGES, WITH RESPECT TO ANY CLAIM ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OF THE SOFTWARE, EVEN
 * IF IT HAS BEEN OR IS HEREAFTER ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGES.
 */

/*
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <unistd.h>
#include <dirent.h>

#include <libintl.h>

#include "pkinit.h"

static void
free_list(char **list)
{
    int i;

    if (list == NULL)
	return;

    for (i = 0; list[i] != NULL; i++)
	free(list[i]);
     free(list);
}

static krb5_error_code
copy_list(char ***dst, char **src)
{
    int i;
    char **newlist;

    if (dst == NULL)
	return EINVAL;
    *dst = NULL;

    if (src == NULL)
	return 0;

    for (i = 0; src[i] != NULL; i++);

    newlist = calloc(1, (i + 1) * sizeof(*newlist));
    if (newlist == NULL)
	return ENOMEM;

    for (i = 0; src[i] != NULL; i++) {
	newlist[i] = strdup(src[i]);
	if (newlist[i] == NULL)
	    goto cleanup;
    }
    newlist[i] = NULL;
    *dst = newlist;
    return 0;
cleanup:
    free_list(newlist);
    return ENOMEM;
}

char *
idtype2string(int idtype)
{
/* Solaris Kerberos: Removed "break"s (lint) */
    switch(idtype) {
    case IDTYPE_FILE: return "FILE";
    case IDTYPE_DIR: return "DIR";
    case IDTYPE_PKCS11: return "PKCS11";
    case IDTYPE_PKCS12: return "PKCS12";
    case IDTYPE_ENVVAR: return "ENV";
    default: return "INVALID";
    }
}

char *
catype2string(int catype)
{
/* Solaris Kerberos: Removed "break"s (lint) */
    switch(catype) {
    case CATYPE_ANCHORS: return "ANCHORS";
    case CATYPE_INTERMEDIATES: return "INTERMEDIATES";
    case CATYPE_CRLS: return "CRLS";
    default: return "INVALID";
    }
}

krb5_error_code
pkinit_init_identity_opts(pkinit_identity_opts **idopts)
{
    pkinit_identity_opts *opts = NULL;

    *idopts = NULL;
    opts = (pkinit_identity_opts *) calloc(1, sizeof(pkinit_identity_opts));
    if (opts == NULL)
	return ENOMEM;

    opts->identity = NULL;
    opts->anchors = NULL;
    opts->intermediates = NULL;
    opts->crls = NULL;
    opts->ocsp = NULL;
    opts->dn_mapping_file = NULL;

    opts->cert_filename = NULL;
    opts->key_filename = NULL;
#ifndef WITHOUT_PKCS11
    opts->p11_module_name = NULL;
    opts->slotid = PK_NOSLOT;
    opts->token_label = NULL;
    opts->cert_id_string = NULL;
    opts->cert_label = NULL;
    opts->PIN = NULL;
#endif

    *idopts = opts;

    return 0;
}

krb5_error_code
pkinit_dup_identity_opts(pkinit_identity_opts *src_opts,
			 pkinit_identity_opts **dest_opts)
{
    pkinit_identity_opts *newopts;
    krb5_error_code retval;

    *dest_opts = NULL;
    retval = pkinit_init_identity_opts(&newopts);
    if (retval)
	return retval;

    retval = ENOMEM;

    if (src_opts->identity != NULL) {
	newopts->identity = strdup(src_opts->identity);
	if (newopts->identity == NULL)
	    goto cleanup;
    }

    retval = copy_list(&newopts->anchors, src_opts->anchors);
    if (retval)
	goto cleanup;

    retval = copy_list(&newopts->intermediates,src_opts->intermediates);
    if (retval)
	goto cleanup;

    retval = copy_list(&newopts->crls, src_opts->crls);
    if (retval)
	goto cleanup;

    if (src_opts->ocsp != NULL) {
	newopts->ocsp = strdup(src_opts->ocsp);
	if (newopts->ocsp == NULL)
	    goto cleanup;
    }

    if (src_opts->cert_filename != NULL) {
	newopts->cert_filename = strdup(src_opts->cert_filename);
	if (newopts->cert_filename == NULL)
	    goto cleanup;
    }

    if (src_opts->key_filename != NULL) {
	newopts->key_filename = strdup(src_opts->key_filename);
	if (newopts->key_filename == NULL)
	    goto cleanup;
    }

#ifndef WITHOUT_PKCS11
    if (src_opts->p11_module_name != NULL) {
	newopts->p11_module_name = strdup(src_opts->p11_module_name);
	if (newopts->p11_module_name == NULL)
	    goto cleanup;
    }

    newopts->slotid = src_opts->slotid;

    if (src_opts->token_label != NULL) {
	newopts->token_label = strdup(src_opts->token_label);
	if (newopts->token_label == NULL)
	    goto cleanup;
    }

    if (src_opts->cert_id_string != NULL) {
	newopts->cert_id_string = strdup(src_opts->cert_id_string);
	if (newopts->cert_id_string == NULL)
	    goto cleanup;
    }

    if (src_opts->cert_label != NULL) {
	newopts->cert_label = strdup(src_opts->cert_label);
	if (newopts->cert_label == NULL)
	    goto cleanup;
    }
    if (src_opts->PIN != NULL) {
	newopts->PIN = strdup(src_opts->PIN);
	if (newopts->PIN == NULL)
	    goto cleanup;
    }
#endif


    *dest_opts = newopts;
    return 0;
cleanup:
    pkinit_fini_identity_opts(newopts);
    return retval;
}

void
pkinit_fini_identity_opts(pkinit_identity_opts *idopts)
{
    if (idopts == NULL)
	return;

    if (idopts->identity != NULL)
	free(idopts->identity);
    free_list(idopts->anchors);
    free_list(idopts->intermediates);
    free_list(idopts->crls);
    free_list(idopts->identity_alt);

    if (idopts->cert_filename != NULL)
	free(idopts->cert_filename);
    if (idopts->key_filename != NULL)
	free(idopts->key_filename);
#ifndef WITHOUT_PKCS11
    if (idopts->p11_module_name != NULL)
	free(idopts->p11_module_name);
    if (idopts->token_label != NULL)
	free(idopts->token_label);
    if (idopts->cert_id_string != NULL)
	free(idopts->cert_id_string);
    if (idopts->cert_label != NULL)
	free(idopts->cert_label);
    if (idopts->PIN != NULL) {
	(void) memset(idopts->PIN, 0, strlen(idopts->PIN));
	free(idopts->PIN);
    }
#endif
    free(idopts);
}

#ifndef WITHOUT_PKCS11
/* ARGSUSED */
static krb5_error_code
parse_pkcs11_options(krb5_context context,
		     pkinit_identity_opts *idopts,
		     const char *residual)
{
    char *s, *cp, *vp;
    krb5_error_code retval = ENOMEM;

    if (residual == NULL || residual[0] == '\0')
	return 0;

    /* Split string into attr=value substrings */
    s = strdup(residual);
    if (s == NULL)
	return retval;

    for ((cp = strtok(s, ":")); cp; (cp = strtok(NULL, ":"))) {
	vp = strchr(cp, '=');

	/* If there is no "=", this is a pkcs11 module name */
	if (vp == NULL) {
	    if (idopts->p11_module_name != NULL)
		free(idopts->p11_module_name);
	    idopts->p11_module_name = strdup(cp);
	    if (idopts->p11_module_name == NULL)
		goto cleanup;
	    continue;
	}
	*vp++ = '\0';
	if (!strcmp(cp, "module_name")) {
	    if (idopts->p11_module_name != NULL)
		free(idopts->p11_module_name);
	    idopts->p11_module_name = strdup(vp);
	    if (idopts->p11_module_name == NULL)
		goto cleanup;
	} else if (!strcmp(cp, "slotid")) {
	    long slotid = strtol(vp, NULL, 10);
	    if ((slotid == LONG_MIN || slotid == LONG_MAX) && errno != 0) {
		retval = EINVAL;
		goto cleanup;
	    }
	    if ((long) (int) slotid != slotid) {
		retval = EINVAL;
		goto cleanup;
	    }
	    idopts->slotid = slotid;
	} else if (!strcmp(cp, "token")) {
	    if (idopts->token_label != NULL)
		free(idopts->token_label);
	    idopts->token_label = strdup(vp);
	    if (idopts->token_label == NULL)
		goto cleanup;
	} else if (!strcmp(cp, "certid")) {
	    if (idopts->cert_id_string != NULL)
		free(idopts->cert_id_string);
	    idopts->cert_id_string = strdup(vp);
	    if (idopts->cert_id_string == NULL)
		goto cleanup;
	} else if (!strcmp(cp, "certlabel")) {
	    if (idopts->cert_label != NULL)
		free(idopts->cert_label);
	    idopts->cert_label = strdup(vp);
	    if (idopts->cert_label == NULL)
		goto cleanup;
	}
    }
    retval = 0;
cleanup:
    free(s);
    return retval;
}
#endif

/* ARGSUSED */
static krb5_error_code
parse_fs_options(krb5_context context,
		 pkinit_identity_opts *idopts,
		 const char *residual)
{
    char *certname, *keyname;
    krb5_error_code retval = ENOMEM;

    if (residual == NULL || residual[0] == '\0')
	return 0;

    certname = strdup(residual);
    if (certname == NULL)
	goto cleanup;

    certname = strtok(certname, ",");
    keyname = strtok(NULL, ",");

    idopts->cert_filename = strdup(certname);
    if (idopts->cert_filename == NULL)
	goto cleanup;

    idopts->key_filename = strdup(keyname ? keyname : certname);
    if (idopts->key_filename == NULL)
	goto cleanup;

    retval = 0;
cleanup:
    if (certname != NULL)
	free(certname);
    return retval;
}

/* ARGSUSED */
static krb5_error_code
parse_pkcs12_options(krb5_context context,
		     pkinit_identity_opts *idopts,
		     const char *residual)
{
    krb5_error_code retval = ENOMEM;

    if (residual == NULL || residual[0] == '\0')
	return 0;

    idopts->cert_filename = strdup(residual);
    if (idopts->cert_filename == NULL)
	goto cleanup;

    idopts->key_filename = strdup(residual);
    if (idopts->key_filename == NULL)
	goto cleanup;

    pkiDebug("%s: cert_filename '%s' key_filename '%s'\n",
	     __FUNCTION__, idopts->cert_filename,
	     idopts->key_filename);
    retval = 0;
cleanup:
    return retval;
}

static krb5_error_code
process_option_identity(krb5_context context,
			pkinit_plg_crypto_context plg_cryptoctx,
			pkinit_req_crypto_context req_cryptoctx,
			pkinit_identity_opts *idopts,
			pkinit_identity_crypto_context id_cryptoctx,
			const char *value)
{
    const char *residual;
    int idtype;
    krb5_error_code retval = 0;

    pkiDebug("%s: processing value '%s'\n",
	     __FUNCTION__, value ? value : "NULL");
    if (value == NULL)
	return EINVAL;

    residual = strchr(value, ':');
    if (residual != NULL) {
	unsigned int typelen;
	residual++; /* skip past colon */
	typelen = residual - value;
	if (strncmp(value, "FILE:", typelen) == 0) {
	    idtype = IDTYPE_FILE;
#ifndef WITHOUT_PKCS11
	} else if (strncmp(value, "PKCS11:", typelen) == 0) {
	    idtype = IDTYPE_PKCS11;
#endif
	} else if (strncmp(value, "PKCS12:", typelen) == 0) {
	    idtype = IDTYPE_PKCS12;
	} else if (strncmp(value, "DIR:", typelen) == 0) {
	    idtype = IDTYPE_DIR;
	} else if (strncmp(value, "ENV:", typelen) == 0) {
	    idtype = IDTYPE_ENVVAR;
	} else {
	    pkiDebug("%s: Unsupported type while processing '%s'\n",
		     __FUNCTION__, value);
	    krb5_set_error_message(context, KRB5_PREAUTH_FAILED,
				   "Unsupported type while processing '%s'\n",
				   value);
	    return KRB5_PREAUTH_FAILED;
	}
    } else {
	idtype = IDTYPE_FILE;
	residual = value;
    }

    idopts->idtype = idtype;
    pkiDebug("%s: idtype is %s\n", __FUNCTION__, idtype2string(idopts->idtype));
    switch (idtype) {
    case IDTYPE_ENVVAR: {
	    /* Solaris Kerberos: Improved error messages */
	    char *envvar = getenv(residual);
	    if (envvar == NULL) {
		    krb5_set_error_message(context, EINVAL,
		        gettext("failed to find environmental variable \'%s\'"),
		        residual);
		    return EINVAL;
	    }
	    return process_option_identity(context, plg_cryptoctx,
				       req_cryptoctx, idopts, id_cryptoctx,
				       envvar);
	    /* Solaris Kerberos: not reached */
	}
    case IDTYPE_FILE:
	retval = parse_fs_options(context, idopts, residual);
	break;
    case IDTYPE_PKCS12:
	retval = parse_pkcs12_options(context, idopts, residual);
	break;
#ifndef WITHOUT_PKCS11
    case IDTYPE_PKCS11:
	retval = parse_pkcs11_options(context, idopts, residual);
	break;
#endif
    case IDTYPE_DIR:
	idopts->cert_filename = strdup(residual);
	if (idopts->cert_filename == NULL)
	    retval = ENOMEM;
	break;
    default:
	krb5_set_error_message(context, KRB5_PREAUTH_FAILED,
			       "Internal error parsing X509_user_identity\n");
	retval = EINVAL;
	break;
    }
    return retval;
}

static krb5_error_code
process_option_ca_crl(krb5_context context,
		      pkinit_plg_crypto_context plg_cryptoctx,
		      pkinit_req_crypto_context req_cryptoctx,
		      pkinit_identity_opts *idopts,
		      pkinit_identity_crypto_context id_cryptoctx,
		      const char *value,
		      int catype)
{
    char *residual;
    unsigned int typelen;
    int idtype;

    pkiDebug("%s: processing catype %s, value '%s'\n",
	     __FUNCTION__, catype2string(catype), value);
    residual = strchr(value, ':');
    if (residual == NULL) {
	pkiDebug("No type given for '%s'\n", value);
	return EINVAL;
    }
    residual++; /* skip past colon */
    typelen = residual - value;
    if (strncmp(value, "FILE:", typelen) == 0) {
	idtype = IDTYPE_FILE;
    } else if (strncmp(value, "DIR:", typelen) == 0) {
	idtype = IDTYPE_DIR;
    } else {
	return ENOTSUP;
    }
    return crypto_load_cas_and_crls(context,
				    plg_cryptoctx,
				    req_cryptoctx,
				    idopts, id_cryptoctx,
				    idtype, catype, residual);
}

static krb5_error_code
pkinit_identity_process_option(krb5_context context,
			       pkinit_plg_crypto_context plg_cryptoctx,
			       pkinit_req_crypto_context req_cryptoctx,
			       pkinit_identity_opts *idopts,
			       pkinit_identity_crypto_context id_cryptoctx,
			       int attr,
			       const char *value)
{
    krb5_error_code retval = 0;

    switch (attr) {
	case PKINIT_ID_OPT_USER_IDENTITY:
	    retval = process_option_identity(context, plg_cryptoctx,
					     req_cryptoctx, idopts,
					     id_cryptoctx, value);
	    break;
	case PKINIT_ID_OPT_ANCHOR_CAS:
	    retval = process_option_ca_crl(context, plg_cryptoctx,
					   req_cryptoctx, idopts,
					   id_cryptoctx, value,
					   CATYPE_ANCHORS);
	    break;
	case PKINIT_ID_OPT_INTERMEDIATE_CAS:
	    retval = process_option_ca_crl(context, plg_cryptoctx,
					   req_cryptoctx, idopts,
					   id_cryptoctx,
					   value, CATYPE_INTERMEDIATES);
	    break;
	case PKINIT_ID_OPT_CRLS:
	    retval = process_option_ca_crl(context, plg_cryptoctx,
					   req_cryptoctx, idopts,
					   id_cryptoctx,
					   value, CATYPE_CRLS);
	    break;
	case PKINIT_ID_OPT_OCSP:
	    retval = ENOTSUP;
	    break;
	default:
	    retval = EINVAL;
	    break;
    }
    return retval;
}

krb5_error_code
pkinit_identity_initialize(krb5_context context,
			   pkinit_plg_crypto_context plg_cryptoctx,
			   pkinit_req_crypto_context req_cryptoctx,
			   pkinit_identity_opts *idopts,
			   pkinit_identity_crypto_context id_cryptoctx,
			   int do_matching,
			   krb5_principal princ)
{
    krb5_error_code retval = EINVAL;
    int i;

    pkiDebug("%s: %p %p %p\n", __FUNCTION__, context, idopts, id_cryptoctx);
    if (idopts == NULL || id_cryptoctx == NULL)
	goto errout;

    /*
     * If identity was specified, use that.  (For the kdc, this
     * is specified as pkinit_identity in the kdc.conf.  For users,
     * this is specified on the command line via X509_user_identity.)
     * If a user did not specify identity on the command line,
     * then we will try alternatives which may have been specified
     * in the config file.
     */
    if (idopts->identity != NULL) {
	retval = pkinit_identity_process_option(context, plg_cryptoctx,
						req_cryptoctx, idopts,
						id_cryptoctx,
						PKINIT_ID_OPT_USER_IDENTITY,
						idopts->identity);
    } else if (idopts->identity_alt != NULL) {
	for (i = 0; retval != 0 && idopts->identity_alt[i] != NULL; i++)
		retval = pkinit_identity_process_option(context, plg_cryptoctx,
						    req_cryptoctx, idopts,
						    id_cryptoctx,
						    PKINIT_ID_OPT_USER_IDENTITY,
						    idopts->identity_alt[i]);
    } else {
	pkiDebug("%s: no user identity options specified\n", __FUNCTION__);
	goto errout;
    }
    if (retval)
	goto errout;

    retval = crypto_load_certs(context, plg_cryptoctx, req_cryptoctx,
			       idopts, id_cryptoctx, princ, do_matching);
    if (retval)
	goto errout;

    if (do_matching) {
	retval = pkinit_cert_matching(context, plg_cryptoctx, req_cryptoctx,
				      id_cryptoctx, princ, TRUE);
	if (retval) {
	    pkiDebug("%s: No matching certificate found\n", __FUNCTION__);
	    (void) crypto_free_cert_info(context, plg_cryptoctx, req_cryptoctx,
				  id_cryptoctx);
	    goto errout;
	}
    } else {
	/* Tell crypto code to use the "default" */
	retval = crypto_cert_select_default(context, plg_cryptoctx,
					    req_cryptoctx, id_cryptoctx);
	if (retval) {
	    pkiDebug("%s: Failed while selecting default certificate\n",
		     __FUNCTION__);
	    (void) crypto_free_cert_info(context, plg_cryptoctx, req_cryptoctx,
				  id_cryptoctx);
	    goto errout;
	}
    }

    retval = crypto_free_cert_info(context, plg_cryptoctx, req_cryptoctx,
				   id_cryptoctx);
    if (retval)
	    goto errout;

    for (i = 0; idopts->anchors != NULL && idopts->anchors[i] != NULL; i++) {
	retval = pkinit_identity_process_option(context, plg_cryptoctx,
						req_cryptoctx, idopts,
						id_cryptoctx,
						PKINIT_ID_OPT_ANCHOR_CAS,
						idopts->anchors[i]);
	if (retval)
	    goto errout;
    }
    for (i = 0; idopts->intermediates != NULL
		&& idopts->intermediates[i] != NULL; i++) {
	retval = pkinit_identity_process_option(context, plg_cryptoctx,
						req_cryptoctx, idopts,
						id_cryptoctx,
						PKINIT_ID_OPT_INTERMEDIATE_CAS,
						idopts->intermediates[i]);
	if (retval)
	    goto errout;
    }
    for (i = 0; idopts->crls != NULL && idopts->crls[i] != NULL; i++) {
	retval = pkinit_identity_process_option(context, plg_cryptoctx,
						req_cryptoctx, idopts,
						id_cryptoctx,
						PKINIT_ID_OPT_CRLS,
						idopts->crls[i]);
	if (retval)
	    goto errout;
    }
    if (idopts->ocsp != NULL) {
	retval = pkinit_identity_process_option(context, plg_cryptoctx,
						req_cryptoctx, idopts,
						id_cryptoctx,
						PKINIT_ID_OPT_OCSP,
						idopts->ocsp);
	if (retval)
	    goto errout;
    }

errout:
    return retval;
}

