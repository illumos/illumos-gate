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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
 */


#include <errno.h>
#include <ldap.h>
#include <sasl/sasl.h>
#include <libintl.h>
#include <strings.h>
#include <syslog.h>
#include <stdarg.h>

#include "addisc.h"
#include "libadutils.h"
#include "idmap_priv.h"
#include "ns_sldap.h"
#include "namemaps.h"

/* From adutils.c: */

/* A single DS */
struct idmap_nm_handle {
	LDAP			*ad;		/* LDAP connection */
	/* LDAP DS info */
	char			*ad_host;
	int			ad_port;

	/* hardwired to SASL GSSAPI only for now */
	char			*saslmech;
	unsigned		saslflags;
	char			*windomain;
	char			*ad_unixuser_attr;
	char			*ad_unixgroup_attr;
	char			*nldap_winname_attr;
	char			*default_domain;
	bool_t			is_nldap;
	bool_t			is_ad;
	int			direction;
	ns_cred_t		nsc;
};

/* PRINTFLIKE1 */
static
void
namemap_log(char *fmt, ...)
{
	va_list va;

	va_start(va, fmt);
	(void) vfprintf(stderr, fmt, va);
	va_end(va);
	(void) fprintf(stderr, "\n");
}

static
idmap_stat
string2auth(const char *from, ns_auth_t *na)
{
	if (from == NULL) {
		na->type = NS_LDAP_AUTH_SASL;
		na->tlstype = NS_LDAP_TLS_SASL;
		na->saslmech = NS_LDAP_SASL_GSSAPI;
		na->saslopt = NS_LDAP_SASLOPT_PRIV |
		    NS_LDAP_SASLOPT_INT;
		return (IDMAP_SUCCESS);
	}

	if (strcasecmp(from, "simple") == 0) {
		na->type = NS_LDAP_AUTH_SIMPLE;
		na->tlstype = NS_LDAP_TLS_NONE;
		na->saslmech = NS_LDAP_SASL_NONE;
		na->saslopt = NS_LDAP_SASLOPT_NONE;
	} else if (strcasecmp(from, "sasl/CRAM-MD5") == 0) {
		na->type = NS_LDAP_AUTH_SASL;
		na->tlstype = NS_LDAP_TLS_SASL;
		na->saslmech = NS_LDAP_SASL_CRAM_MD5;
		na->saslopt = NS_LDAP_SASLOPT_NONE;
	} else if (strcasecmp(from, "sasl/DIGEST-MD5") == 0) {
		na->type = NS_LDAP_AUTH_SASL;
		na->tlstype = NS_LDAP_TLS_SASL;
		na->saslmech = NS_LDAP_SASL_DIGEST_MD5;
		na->saslopt = NS_LDAP_SASLOPT_NONE;
	} else if (strcasecmp(from, "sasl/GSSAPI") == 0) {
		na->type = NS_LDAP_AUTH_SASL;
		na->tlstype = NS_LDAP_TLS_SASL;
		na->saslmech = NS_LDAP_SASL_GSSAPI;
		na->saslopt = NS_LDAP_SASLOPT_PRIV |
		    NS_LDAP_SASLOPT_INT;
	} else if (strcasecmp(from, "tls:simple") == 0) {
		na->type = NS_LDAP_AUTH_TLS;
		na->tlstype = NS_LDAP_TLS_SIMPLE;
		na->saslmech = NS_LDAP_SASL_NONE;
		na->saslopt = NS_LDAP_SASLOPT_NONE;
	} else if (strcasecmp(from, "tls:sasl/CRAM-MD5") == 0) {
		na->type = NS_LDAP_AUTH_TLS;
		na->tlstype = NS_LDAP_TLS_SASL;
		na->saslmech = NS_LDAP_SASL_CRAM_MD5;
		na->saslopt = NS_LDAP_SASLOPT_NONE;
	} else if (strcasecmp(from, "tls:sasl/DIGEST-MD5") == 0) {
		na->type = NS_LDAP_AUTH_TLS;
		na->tlstype = NS_LDAP_TLS_SASL;
		na->saslmech = NS_LDAP_SASL_DIGEST_MD5;
		na->saslopt = NS_LDAP_SASLOPT_NONE;
	} else {
		namemap_log(
		    gettext("Invalid authentication method \"%s\" specified\n"),
		    from);
		return (IDMAP_ERR_ARG);
	}

	return (IDMAP_SUCCESS);
}



static
idmap_stat
strings2cred(ns_cred_t *nsc, char *user, char *passwd, char *auth)
{
	idmap_stat rc;
	(void) memset(nsc, 0, sizeof (ns_cred_t));

	if ((rc = string2auth(auth, &nsc->auth)) != IDMAP_SUCCESS)
		return (rc);

	if (user != NULL) {
		nsc->cred.unix_cred.userID = strdup(user);
		if (nsc->cred.unix_cred.userID == NULL)
			return (IDMAP_ERR_MEMORY);
	}

	if (passwd != NULL) {
		nsc->cred.unix_cred.passwd = strdup(passwd);
		if (nsc->cred.unix_cred.passwd == NULL) {
			free(nsc->cred.unix_cred.userID);
			return (IDMAP_ERR_MEMORY);
		}
	}

	return (IDMAP_SUCCESS);
}





/*ARGSUSED*/
static int
idmap_saslcallback(LDAP *ld, unsigned flags, void *defaults, void *prompts)
{
	sasl_interact_t	*interact;

	if (prompts == NULL || flags != LDAP_SASL_INTERACTIVE)
		return (LDAP_PARAM_ERROR);

	/* There should be no extra arguemnts for SASL/GSSAPI authentication */
	for (interact = prompts; interact->id != SASL_CB_LIST_END;
	    interact++) {
		interact->result = NULL;
		interact->len = 0;
	}
	return (LDAP_SUCCESS);
}

static
idmap_stat
idmap_open_ad_conn(idmap_nm_handle_t *adh)
{
	int zero = 0;
	int timeoutms = 30 * 1000;
	int ldversion, ldap_rc;
	idmap_stat rc = IDMAP_SUCCESS;

	/* Open and bind an LDAP connection */
	adh->ad = ldap_init(adh->ad_host, adh->ad_port);
	if (adh->ad == NULL) {
		namemap_log(
		    gettext("ldap_init() to server %s port %d failed. (%s)"),
		    CHECK_NULL(adh->ad_host),
		    adh->ad_port, strerror(errno));
		rc = IDMAP_ERR_INTERNAL;
		goto out;
	}
	ldversion = LDAP_VERSION3;
	(void) ldap_set_option(adh->ad, LDAP_OPT_PROTOCOL_VERSION, &ldversion);
	(void) ldap_set_option(adh->ad, LDAP_OPT_REFERRALS, LDAP_OPT_OFF);
	(void) ldap_set_option(adh->ad, LDAP_OPT_TIMELIMIT, &zero);
	(void) ldap_set_option(adh->ad, LDAP_OPT_SIZELIMIT, &zero);
	(void) ldap_set_option(adh->ad, LDAP_X_OPT_CONNECT_TIMEOUT, &timeoutms);
	(void) ldap_set_option(adh->ad, LDAP_OPT_RESTART, LDAP_OPT_ON);
	ldap_rc = ldap_sasl_interactive_bind_s(adh->ad, "" /* binddn */,
	    adh->saslmech, NULL, NULL, adh->saslflags, &idmap_saslcallback,
	    NULL);

	if (ldap_rc != LDAP_SUCCESS) {
		(void) ldap_unbind(adh->ad);
		adh->ad = NULL;
		namemap_log(
		    gettext("ldap_sasl_interactive_bind_s() to server "
		    "%s port %d failed. (%s)"), CHECK_NULL(adh->ad_host),
		    adh->ad_port, ldap_err2string(ldap_rc));
		rc = IDMAP_ERR_INTERNAL;
	}

out:
	return (rc);
}

static
idmap_stat
idmap_init_nldap(idmap_nm_handle_t *p)
{
/*
 * For now, there is nothing to initialize in nldap. This is just to
 * make it future-proof, especially standalone libsldap-proof
 */
	p->is_nldap = TRUE;
	return (0);
}

static
idmap_stat
idmap_init_ad(idmap_nm_handle_t *p)
{
	idmap_stat	rc = IDMAP_SUCCESS;
	ad_disc_ds_t	*dc = NULL;
	ad_disc_t	ad_ctx;

	ad_ctx = ad_disc_init();
	if (ad_ctx == NULL) {
		namemap_log(
		    gettext("AD autodiscovery initialization failed"));
		return (IDMAP_ERR_INTERNAL);
	}
	ad_disc_refresh(ad_ctx);


	/* Based on the supplied or default domain, find the proper AD: */
	if (ad_disc_set_DomainName(ad_ctx, p->windomain)) {
		rc = IDMAP_ERR_INTERNAL;
		namemap_log(
		    gettext("Setting a domain name \"%s\" for autodiscovery"
		    " failed, most likely not enough memory"), p->windomain);
		goto cleanup;
	}

	dc = ad_disc_get_DomainController(ad_ctx, AD_DISC_GLOBAL, NULL);
	if (dc == NULL) {
		rc = IDMAP_ERR_ARG;
		namemap_log(
		    gettext("A domain controller for the "
		    "domain \"%s\" not found."), p->windomain);
		goto cleanup;
	}


	p->ad_port = dc->port;
	p->ad_host = strdup(dc->host);

	if (p->ad_host == NULL) {
		rc = IDMAP_ERR_MEMORY;
		goto cleanup;
	}

	p->saslflags = LDAP_SASL_INTERACTIVE;
	p->saslmech = strdup("GSSAPI");

	if (p->saslmech == NULL) {
		rc = IDMAP_ERR_MEMORY;
		goto cleanup;
	}

	rc = idmap_open_ad_conn(p);

	if (rc != IDMAP_SUCCESS)
		goto cleanup;

	p->is_ad = TRUE;

cleanup:
	ad_disc_fini(ad_ctx);
	free(dc);
	return (rc);
}

void
idmap_fini_namemaps(idmap_nm_handle_t *p)
{
	if (p == NULL)
		return;

	if (p->ad_unixgroup_attr != NULL)
		free(p->ad_unixgroup_attr);

	if (p->ad_unixuser_attr != NULL)
		free(p->ad_unixuser_attr);

	if (p->nldap_winname_attr)
		free(p->nldap_winname_attr);

	if (p->windomain != NULL)
		free(p->windomain);

	if (p->default_domain != NULL)
		free(p->default_domain);

	if (p->saslmech != NULL)
		free(p->saslmech);

	if (p->ad_host != NULL)
		free(p->ad_host);

	if (p->nsc.cred.unix_cred.userID != NULL) {
		free(p->nsc.cred.unix_cred.userID);
	}

	if (p->nsc.cred.unix_cred.passwd != NULL) {
		/* No archeology: */
		(void) memset(p->nsc.cred.unix_cred.passwd, 0,
		    strlen(p->nsc.cred.unix_cred.passwd));
		free(p->nsc.cred.unix_cred.passwd);
	}

	if (p->ad)
		(void) ldap_unbind(p->ad);
	free(p);

}



idmap_stat
idmap_init_namemaps(idmap_nm_handle_t **adh,
    char *user, char *passwd, char *auth, char *windomain,
    int direction)
{
	idmap_stat rc;
	idmap_nm_handle_t *p;

	p = (idmap_nm_handle_t *)calloc(1, sizeof (idmap_nm_handle_t));
	if (p == NULL)
		return (IDMAP_ERR_MEMORY);

	rc = idmap_get_prop_str(PROP_DEFAULT_DOMAIN,
	    &p->default_domain);
	if (rc != IDMAP_SUCCESS) {
		namemap_log(
		    gettext("Error obtaining default domain from idmapd (%s)"),
		    idmap_stat2string(rc));
		goto cleanup;
	}

	rc = idmap_get_prop_str(PROP_AD_UNIXUSER_ATTR,
	    &p->ad_unixuser_attr);
	if (rc != IDMAP_SUCCESS) {
		namemap_log(
		    gettext("Error obtaining AD unixuser attribute (%s)"),
		    idmap_stat2string(rc));
		goto cleanup;
	}

	rc = idmap_get_prop_str(PROP_AD_UNIXGROUP_ATTR,
	    &p->ad_unixgroup_attr);
	if (rc != IDMAP_SUCCESS) {
		namemap_log(
		    gettext("Error obtaining AD unixgroup attribute (%s)"),
		    idmap_stat2string(rc));
		goto cleanup;
	}


	rc = idmap_get_prop_str(PROP_NLDAP_WINNAME_ATTR,
	    &p->nldap_winname_attr);
	if (rc != IDMAP_SUCCESS) {
		namemap_log(
		    gettext("Error obtaining AD unixgroup attribute (%s)"),
		    idmap_stat2string(rc));
		goto cleanup;
	}

	if (windomain != NULL) {
		p->windomain = strdup(windomain);
		if (p->windomain == NULL) {
			rc = IDMAP_ERR_MEMORY;
			goto cleanup;
		}
	} else if (!EMPTY_STRING(p->default_domain)) {
		p->windomain = strdup(p->default_domain);
		if (p->windomain == NULL) {
			rc = IDMAP_ERR_MEMORY;
			goto cleanup;
		}
	} else if (direction == IDMAP_DIRECTION_W2U) {
		namemap_log(
		    gettext("Windows domain not given and idmapd daemon"
		    " didn't provide a default one"));
		rc = IDMAP_ERR_ARG;
		goto cleanup;
	}

	p->direction = direction;

	if ((p->ad_unixuser_attr != NULL || p->ad_unixgroup_attr != NULL) &&
	    direction != IDMAP_DIRECTION_U2W) {
		rc = idmap_init_ad(p);
		if (rc != IDMAP_SUCCESS) {
			goto cleanup;
		}
	}

	if (p->nldap_winname_attr != NULL && direction != IDMAP_DIRECTION_W2U) {
		rc = idmap_init_nldap(p);
		if (rc != IDMAP_SUCCESS) {
			goto cleanup;
		}

		rc = strings2cred(&p->nsc, user, passwd, auth);
		if (rc != IDMAP_SUCCESS) {
			goto cleanup;
		}
	}

cleanup:

	if (rc == IDMAP_SUCCESS) {
		*adh = p;
		return (IDMAP_SUCCESS);
	}

	/* There was an error: */
	idmap_fini_namemaps(*adh);
	return (rc);
}

static
char *
dns2dn(const char *dns, const char *prefix)
{
	int num_lvl = 1;
	char *buf;
	const char *it, *new_it;

	for (it = dns; it != NULL; it = strchr(it, '.')) {
		it ++;
		num_lvl ++;
	}

	buf = (char *)malloc(strlen(prefix) + strlen(dns) + 4 * num_lvl);
	(void) strcpy(buf, prefix);


	it = dns;
	for (;;) {
		new_it = strchr(it, '.');
		(void) strcat(buf, "DC=");
		if (new_it == NULL) {
			(void) strcat(buf, it);
			break;
		} else {
			(void) strncat(buf, it, new_it - it);
			(void) strcat(buf, ",");
		}

		it = new_it + 1;
	}

	return (buf);
}


static
idmap_stat
extract_attribute(idmap_nm_handle_t *p, LDAPMessage *entry, char *name,
    char **value)
{
	char	**values = NULL;
	idmap_stat rc = IDMAP_SUCCESS;
	/* No value means it is not requested */
	if (value == NULL)
		return (IDMAP_SUCCESS);

	values = ldap_get_values(p->ad, entry, name);
	if (values == NULL || values[0] == NULL)
		*value = NULL;
	else {
		*value = strdup(values[0]);
		if (*value == NULL)
			rc = IDMAP_ERR_MEMORY;
	}
errout:
	ldap_value_free(values);
	return (rc);
}


/* Split winname to its name and domain part */
static
idmap_stat
split_fqwn(char *fqwn, char **name, char **domain)
{
	char *at;

	*name = NULL;
	*domain = NULL;

	at = strchr(fqwn, '@');
	if (at == NULL) {
		at = strchr(fqwn, '\\');
	}
	if (at == NULL) {
	/* There is no domain - leave domain NULL */
		*name = strdup(fqwn);
		if (*name == NULL)
			goto errout;
		return (IDMAP_SUCCESS);
	}


	*domain = strdup(at+1);
	if (*domain == NULL)
		goto errout;
	*name = (char *)malloc(at - fqwn + 1);
	if (*name == NULL)
		goto errout;
	(void) strlcpy(*name, fqwn, at - fqwn + 1);

	if (*at == '\\') {
		char *it = *name;
		*name = *domain;
		*domain = it;
	}

	return (IDMAP_SUCCESS);


errout:
	free(*name);
	*name = NULL;
	free(*domain);
	*domain = NULL;
	return (IDMAP_ERR_MEMORY);
}

static
idmap_stat
unixname2dn(idmap_nm_handle_t *p, char *unixname, int is_user, char **dn,
    char **winname, char **windomain)
{
	idmap_stat rc = IDMAP_SUCCESS;
	int rc_ns;


	char filter[255];
	static const char *attribs[3];
	ns_ldap_result_t *res;
	ns_ldap_error_t *errorp = NULL;
	char **attrs;


	attribs[0] = p->nldap_winname_attr;
	attribs[1] = "dn";
	attribs[2] = NULL;

	(void) snprintf(filter, sizeof (filter), is_user ? "uid=%s" : "cn=%s",
	    unixname);

	rc_ns = __ns_ldap_list(is_user ? "passwd" : "group",
	    filter, NULL, attribs, NULL, 0, &res, &errorp, NULL, NULL);


	if (rc_ns == NS_LDAP_NOTFOUND) {
		namemap_log(is_user ? gettext("User %s not found.")
		    : gettext("Group %s not found."),  unixname);
		return (IDMAP_ERR_NOTFOUND);
	} else if (rc_ns != NS_LDAP_SUCCESS) {
		char *msg = "Cause unidentified";
		if (errorp != NULL) {
			(void) __ns_ldap_err2str(errorp->status, &msg);
		}
		namemap_log(gettext("Ldap list failed (%s)."), msg);
		return (IDMAP_ERR_ARG);
	}

	if (res == NULL) {
		namemap_log(gettext("User %s not found"), unixname);
		return (IDMAP_ERR_ARG);
	}

	if (winname != NULL && windomain != NULL) {
		attrs = __ns_ldap_getAttr(&res->entry[0],
		    p->nldap_winname_attr);
		if (attrs != NULL && attrs[0] != NULL) {
			rc = split_fqwn(attrs[0], winname, windomain);
		} else {
			*winname = *windomain = NULL;
		}
	}

	if (dn != NULL) {
		attrs = __ns_ldap_getAttr(&res->entry[0], "dn");
		if (attrs == NULL || attrs[0] == NULL) {
			namemap_log(gettext("dn for %s not found"),
			    unixname);
			return (IDMAP_ERR_ARG);
		}
		*dn = strdup(attrs[0]);
	}


	return (rc);

}

#define	FILTER	"(sAMAccountName=%s)"

/* Puts the values of attributes to unixuser and unixgroup, unless NULL */

static
idmap_stat
winname2dn(idmap_nm_handle_t *p, char *winname,
    int *is_wuser, char **dn, char **unixuser, char **unixgroup)
{
	idmap_stat rc = IDMAP_SUCCESS;
	char *base;
	char *filter;
	int flen;
	char *attribs[4];
	int i;
	LDAPMessage *results = NULL;
	LDAPMessage *entry;
	int ldap_rc;

	/* Query: */

	base = dns2dn(p->windomain, "");
	if (base == NULL) {
		return (IDMAP_ERR_MEMORY);
	}

	i = 0;
	attribs[i++] = "objectClass";
	if (unixuser != NULL)
		attribs[i++] = p->ad_unixuser_attr;
	if (unixgroup != NULL)
		attribs[i++] = p->ad_unixgroup_attr;
	attribs[i] = NULL;

	flen = snprintf(NULL, 0, FILTER, winname) + 1;
	if ((filter = (char *)malloc(flen)) == NULL) {
		free(base);
		return (IDMAP_ERR_MEMORY);
	}
	(void) snprintf(filter, flen, FILTER, winname);

	ldap_rc = ldap_search_s(p->ad, base, LDAP_SCOPE_SUBTREE, filter,
	    attribs, 0, &results);

	free(base);
	free(filter);

	if (ldap_rc != LDAP_SUCCESS) {
		namemap_log(
		    gettext("Ldap query to server %s port %d failed. (%s)"),
		    p->ad_host, p->ad_port, ldap_err2string(ldap_rc));
		(void) ldap_msgfree(results);
		return (IDMAP_ERR_OTHER);
	}


	for (entry = ldap_first_entry(p->ad, results), *dn = NULL;
	    entry != NULL;
	    entry = ldap_next_entry(p->ad, entry)) {
		char	**values = NULL;
		int i = 0;
		values = ldap_get_values(p->ad, entry, "objectClass");

		if (values == NULL) {
			(void) ldap_msgfree(results);
			return (IDMAP_ERR_MEMORY);
		}

		for (i = 0; i < ldap_count_values(values); i++) {
		/*
		 * is_wuser can be IDMAP_UNKNOWN, in that case we accept
		 * both User/Group
		 */
			if (*is_wuser != IDMAP_NO &&
			    strcasecmp(values[i], "User") == 0 ||
			    *is_wuser != IDMAP_YES &&
			    strcasecmp(values[i], "Group") == 0) {
				*dn = ldap_get_dn(p->ad, entry);
				if (*dn == NULL) {
					ldap_value_free(values);
					(void) ldap_msgfree(results);
					return (IDMAP_ERR_MEMORY);
				}
				*is_wuser = strcasecmp(values[i], "User") == 0
				    ? IDMAP_YES : IDMAP_NO;
				break;
			}
		}

		ldap_value_free(values);
		if (*dn != NULL)
			break;
	}

	if (*dn == NULL) {
		namemap_log(
		    *is_wuser == IDMAP_YES ? gettext("User %s@%s not found") :
		    *is_wuser == IDMAP_NO ? gettext("Group %s@%s not found") :
		    gettext("%s@%s not found"), winname, p->windomain);
		return (IDMAP_ERR_NOTFOUND);
	}

	if (unixuser != NULL)
		rc = extract_attribute(p, entry, p->ad_unixuser_attr,
		    unixuser);

	if (rc == IDMAP_SUCCESS && unixgroup != NULL)
		rc = extract_attribute(p, entry, p->ad_unixgroup_attr,
		    unixgroup);

	(void) ldap_msgfree(results);

	return (rc);
}


/* set the given attribute to the given value. If value is NULL, unset it */
static
idmap_stat
idmap_ad_set(idmap_nm_handle_t *p, char *dn, char *attr, char *value)
{
	idmap_stat rc = IDMAP_SUCCESS;
	int ldap_rc;
	char *new_values[2] = {NULL, NULL};
	LDAPMod *mods[2] = {NULL, NULL};

	mods[0] = (LDAPMod *)calloc(1, sizeof (LDAPMod));
	mods[0]->mod_type = strdup(attr);
	if (value != NULL) {
		mods[0]->mod_op = LDAP_MOD_REPLACE;
		new_values[0] = strdup(value);
		mods[0]->mod_values = new_values;
	} else {
		mods[0]->mod_op = LDAP_MOD_DELETE;
		mods[0]->mod_values = NULL;
	}

	ldap_rc = ldap_modify_s(p->ad, dn, mods);
	if (ldap_rc != LDAP_SUCCESS) {
		namemap_log(
		    gettext("Ldap modify of %s, attribute %s failed. (%s)"),
		    dn, attr, ldap_err2string(ldap_rc));
		rc = IDMAP_ERR_INTERNAL;
	}


	ldap_mods_free(mods, 0);
	return (rc);
}


/*
 * This function takes the p argument just for the beauty of the symmetry
 * with idmap_ad_set (and for future enhancements).
 */
static
idmap_stat
/* LINTED E_FUNC_ARG_UNUSED */
idmap_nldap_set(idmap_nm_handle_t *p, ns_cred_t *nsc, char *dn, char *attr,
    char *value, bool_t is_new, int is_user)
{
	int ldaprc;
	ns_ldap_error_t *errorp = NULL;
	ns_ldap_attr_t	*attrs[2];



	attrs[0] = (ns_ldap_attr_t *)malloc(sizeof (ns_ldap_attr_t));
	if (attrs == NULL)
		return (IDMAP_ERR_MEMORY);

	attrs[0]->attrname = attr;

	if (value != NULL) {
		char **newattr = (char **)calloc(2, sizeof (char *));
		if (newattr == NULL) {
			free(attrs[0]);
			return (IDMAP_ERR_MEMORY);
		}
		newattr[0] = value;
		newattr[1] = NULL;

		attrs[0]->attrvalue = newattr;
		attrs[0]->value_count = 1;
	} else {
		attrs[0]->attrvalue = NULL;
		attrs[0]->value_count = 0;
	}


	attrs[1] = NULL;

	if (value == NULL) {
		ldaprc = __ns_ldap_delAttr(
		    is_user == IDMAP_YES ? "passwd": "group",
		    dn, (const ns_ldap_attr_t * const *)attrs,
		    nsc, 0, &errorp);
	} else if (is_new)
		ldaprc = __ns_ldap_addAttr(
		    is_user == IDMAP_YES ? "passwd": "group",
		    dn, (const ns_ldap_attr_t * const *)attrs,
		    nsc, 0, &errorp);
	else
		ldaprc = __ns_ldap_repAttr(
		    is_user == IDMAP_YES ? "passwd": "group",
		    dn, (const ns_ldap_attr_t * const *)attrs,
		    nsc, 0, &errorp);

	if (ldaprc != NS_LDAP_SUCCESS) {
		char *msg = "Cause unidentified";
		if (errorp != NULL) {
			(void) __ns_ldap_err2str(errorp->status, &msg);
		}
		namemap_log(
		    gettext("__ns_ldap_addAttr/rep/delAttr failed (%s)"),
		    msg);
		return (IDMAP_ERR_ARG);
	}

	return (IDMAP_SUCCESS);
}

idmap_stat
idmap_set_namemap(idmap_nm_handle_t *p, char *winname, char *unixname,
    int is_user, int is_wuser, int direction)
{
	idmap_stat	rc = IDMAP_SUCCESS;
	char		*dn = NULL;
	char		*oldwinname = NULL;
	char		*oldwindomain = NULL;

	if (direction == IDMAP_DIRECTION_W2U) {
		if (!p->is_ad) {
			rc = IDMAP_ERR_ARG;
			namemap_log(
			    gettext("AD namemaps aren't set up."));
			goto cleanup;
		}

		rc = winname2dn(p, winname, &is_wuser,
		    &dn, NULL, NULL);
		if (rc != IDMAP_SUCCESS)
			goto cleanup;

		rc = idmap_ad_set(p, dn, is_user ? p->ad_unixuser_attr :
		    p->ad_unixgroup_attr, unixname);
		if (rc != IDMAP_SUCCESS)
			goto cleanup;

	}


	if (direction == IDMAP_DIRECTION_U2W) {
		char *fullname;

		if (!p->is_nldap) {
			rc = IDMAP_ERR_ARG;
			namemap_log(
			    gettext("Native ldap namemaps aren't set up."));
			goto cleanup;
		}


		rc = unixname2dn(p, unixname, is_user, &dn,
		    &oldwinname, &oldwindomain);
		if (rc != IDMAP_SUCCESS)
			goto cleanup;

		if (p->windomain == NULL) {
			fullname = strdup(winname);
			if (fullname == NULL)
				rc = IDMAP_ERR_MEMORY;
				goto cleanup;
		} else {
			fullname = malloc(strlen(winname) +
			    strlen(p->windomain) + 2);
			if (fullname == NULL) {
				rc = IDMAP_ERR_MEMORY;
				goto cleanup;
			}

			(void) snprintf(fullname,
			    strlen(winname) + strlen(p->windomain) + 2,
			    "%s\\%s", p->windomain, winname);
		}
		rc = idmap_nldap_set(p, &p->nsc, dn, p->nldap_winname_attr,
		    fullname, oldwinname == NULL ? TRUE : FALSE, is_user);

		free(fullname);
		free(oldwindomain);
		free(oldwinname);

		if (rc != IDMAP_SUCCESS)
			goto cleanup;

	}

cleanup:
	if (dn != NULL)
		free(dn);

	if (oldwindomain != NULL)
		free(oldwindomain);

	if (oldwinname != NULL)
		free(oldwinname);

	return (rc);

}


idmap_stat
idmap_unset_namemap(idmap_nm_handle_t *p, char *winname, char *unixname,
    int is_user, int is_wuser, int direction)
{
	idmap_stat	rc = IDMAP_SUCCESS;
	char		*dn = NULL;
	char		*oldwinname = NULL;
	char		*oldwindomain = NULL;

	if (direction == IDMAP_DIRECTION_W2U) {
		if (!p->is_ad) {
			rc = IDMAP_ERR_ARG;
			namemap_log(
			    gettext("AD namemaps aren't set up."));
			goto cleanup;
		}

		rc = winname2dn(p, winname, &is_wuser,
		    &dn, NULL, NULL);
		if (rc != IDMAP_SUCCESS)
			goto cleanup;

		rc = idmap_ad_set(p, dn, is_user ? p->ad_unixuser_attr :
		    p->ad_unixgroup_attr, unixname);
		if (rc != IDMAP_SUCCESS)
			goto cleanup;

	} else { /* direction == IDMAP_DIRECTION_U2W */
		if (!p->is_nldap) {
			rc = IDMAP_ERR_ARG;
			namemap_log(
			    gettext("Native ldap namemaps aren't set up."));
			goto cleanup;
		}

		rc = unixname2dn(p, unixname, is_user, &dn, NULL, NULL);
		if (rc != IDMAP_SUCCESS)
			goto cleanup;

		rc = idmap_nldap_set(p, &p->nsc, dn, p->nldap_winname_attr,
		    NULL, TRUE, is_user);
		if (rc != IDMAP_SUCCESS)
			goto cleanup;

	}

cleanup:
	if (oldwindomain != NULL)
		free(oldwindomain);
	if (oldwinname != NULL)
		free(oldwinname);
	if (dn != NULL)
		free(dn);
	return (rc);
}

idmap_stat
idmap_get_namemap(idmap_nm_handle_t *p, int *is_source_ad, char **winname,
    char **windomain, int *is_wuser, char **unixuser, char **unixgroup)
{
	idmap_stat	rc = IDMAP_SUCCESS;
	char		*dn = NULL;

	*is_source_ad = IDMAP_UNKNOWN;
	if (*winname != NULL) {
		*is_source_ad = IDMAP_YES;

		if (p->is_ad == NULL) {
			rc = IDMAP_ERR_ARG;
			namemap_log(
			    gettext("AD namemaps are not active."));
			goto cleanup;
			/* In future maybe resolve winname and try nldap? */
		}

		rc = winname2dn(p, *winname, is_wuser, &dn, unixuser,
		    unixgroup);
		if (rc != IDMAP_SUCCESS) {
			namemap_log(
			    gettext("Winname %s@%s not found in AD."),
			    *winname, p->windomain);
		}
	} else if (*unixuser != NULL ||	*unixgroup != NULL) {
		char *unixname;
		int is_user;

		*is_source_ad = IDMAP_NO;

		if (p->is_nldap == NULL) {
			rc = IDMAP_ERR_ARG;
			namemap_log(
			    gettext("Native ldap namemaps aren't active."));
			goto cleanup;
			/* In future maybe resolve unixname and try AD? */
		}

		if (*unixuser != NULL) {
			is_user = IDMAP_YES;
			unixname = *unixuser;
		} else if (*unixgroup != NULL) {
			is_user = IDMAP_NO;
			unixname = *unixgroup;
		}

		rc = unixname2dn(p, unixname, is_user, NULL, winname,
		    windomain);
		if (rc != IDMAP_SUCCESS) {
			namemap_log(
			    gettext("%s %s not found in native ldap."),
			    is_user == IDMAP_YES ? "UNIX user" : "UNIX group",
			    unixname);
			goto cleanup;
		}
	} else {
		rc = IDMAP_ERR_ARG;
		goto cleanup;
	}

cleanup:
	return (rc);
}
