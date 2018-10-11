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
 * Copyright (c) 1999, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2018 Nexenta Systems, Inc.  All rights reserved.
 */

#include "ldap_common.h"
#include <malloc.h>
#include <synch.h>
#include <syslog.h>
#include <rpcsvc/ypclnt.h>
#include <rpcsvc/yp_prot.h>
#include <thread.h>
#include <ctype.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/stat.h>

/* getent attributes filters */
#define	_F_GETALIASENT		"(objectClass=rfc822MailGroup)"
#define	_F_GETAUTHNAME		"(objectClass=SolarisAuthAttr)"
#define	_F_GETAUUSERNAME	"(objectClass=SolarisAuditUser)"
#define	_F_GETEXECNAME		"(objectClass=SolarisExecAttr)"
#define	_F_GETGRENT		"(objectClass=posixGroup)"
#define	_F_GETHOSTENT		"(objectClass=ipHost)"
#define	_F_GETNETENT		"(objectClass=ipNetwork)"
#define	_F_GETPROFNAME \
"(&(objectClass=SolarisProfAttr)(!(SolarisKernelSecurityPolicy=*)))"
#define	_F_GETPROTOENT		"(objectClass=ipProtocol)"
#define	_F_GETPWENT		"(objectClass=posixAccount)"
#define	_F_GETPRINTERENT	"(objectClass=sunPrinter)"
#define	_F_GETRPCENT		"(objectClass=oncRpc)"
#define	_F_GETSERVENT		"(objectClass=ipService)"
#define	_F_GETSPENT		"(objectclass=shadowAccount)"
#define	_F_GETUSERNAME		"(objectClass=SolarisUserAttr)"
#define	_F_GETPROJENT		"(objectClass=SolarisProject)"
#define	_F_GETTNRHDB		"(objectClass=ipTnetHost)"
#define	_F_GETTNRHTP		"(&(objectClass=ipTnetTemplate)"\
				"(SolarisAttrKeyValue=*))"
#define	_F_GETENT_SSD		"(%s)"

/* getent sort attributes */
#define	_A_UID			"uid"
#define	_A_GIDNUMBER		"gidnumber"
#define	_A_CN			"cn"
#define	_A_IPNETWORKNUM		"ipnetworknumber"
#define	_A_PROJECTNAM		"SolarisProjectName"
#define	_A_IPTNETNUM		"ipTnetNumber"
#define	_A_IPTNETTMPLNAM	"ipTnetTemplateName"

static struct gettablefilter {
	char *tablename;
	char *tablefilter;
	char *sortattr;
} gettablefilterent[] = {
	{(char *)_PASSWD,	(char *)_F_GETPWENT,	(char *)_A_UID},
	{(char *)_SHADOW,	(char *)_F_GETSPENT,	(char *)_A_UID},
	{(char *)_GROUP,	(char *)_F_GETGRENT,	(char *)_A_GIDNUMBER},
	{(char *)_HOSTS,	(char *)_F_GETHOSTENT,	(char *)_A_CN},
	{(char *)_NETWORKS,	(char *)_F_GETNETENT,
						(char *)_A_IPNETWORKNUM},
	{(char *)_PROTOCOLS,	(char *)_F_GETPROTOENT,	(char *)_A_CN},
	{(char *)_RPC,		(char *)_F_GETRPCENT,	(char *)_A_CN},
	{(char *)_ALIASES,	(char *)_F_GETALIASENT,	(char *)_A_CN},
	{(char *)_SERVICES,	(char *)_F_GETSERVENT,	(char *)_A_CN},
	{(char *)_AUUSER,	(char *)_F_GETAUUSERNAME,
							(char *)_A_UID},
	{(char *)_AUTHATTR,	(char *)_F_GETAUTHNAME,	(char *)_A_CN},
	{(char *)_EXECATTR,	(char *)_F_GETEXECNAME,	(char *)_A_CN},
	{(char *)_PROFATTR,	(char *)_F_GETPROFNAME,	(char *)_A_CN},
	{(char *)_USERATTR,	(char *)_F_GETUSERNAME,	(char *)_A_UID},
	{(char *)_PROJECT,	(char *)_F_GETPROJENT,	(char *)_A_PROJECTNAM},
	{(char *)_PRINTERS,	(char *)_F_GETPRINTERENT, (char *)_A_CN},
	{(char *)_TNRHDB,	(char *)_F_GETTNRHDB,	(char *)_A_IPTNETNUM},
	{(char *)_TNRHTP,	(char *)_F_GETTNRHTP,
						(char *)_A_IPTNETTMPLNAM},
	{(char *)NULL,		(char *)NULL,		(char *)NULL}
};


nss_status_t
switch_err(int rc, ns_ldap_error_t *error)
{
	switch (rc) {
	case NS_LDAP_SUCCESS:
		return (NSS_SUCCESS);

	case NS_LDAP_NOTFOUND:
		errno = 0;
		return (NSS_NOTFOUND);

	case NS_LDAP_PARTIAL:
		return (NSS_TRYAGAIN);

	case NS_LDAP_INTERNAL:
		if (error && (error->status == LDAP_SERVER_DOWN ||
		    error->status == LDAP_TIMEOUT))
			return (NSS_TRYAGAIN);
		else
			return (NSS_UNAVAIL);

	default:
		return (NSS_UNAVAIL);
	}
}
/* ARGSUSED */
nss_status_t
_nss_ldap_lookup(ldap_backend_ptr be, nss_XbyY_args_t *argp,
    char *database, char *searchfilter, char *domain,
    int (*init_filter_cb)(const ns_ldap_search_desc_t *desc,
    char **realfilter, const void *userdata),
    const void *userdata)
{
	int		callbackstat = 0;
	ns_ldap_error_t	*error = NULL;
	int		rc;

#ifdef	DEBUG
	(void) fprintf(stdout, "\n[ldap_common.c: _nss_ldap_lookup]\n");
	(void) fprintf(stdout, "\tsearchfilter: %s\n", searchfilter);
	(void) fprintf(stdout,
	    "\tuserdata: %s\n", userdata ? userdata : "NULL");
	(void) fprintf(stdout, "\tdatabase: %s\n", database);
#endif	/* DEBUG */

	(void) __ns_ldap_freeResult(&be->result);

	if ((rc = __ns_ldap_list(database, searchfilter, init_filter_cb,
	    be->attrs, NULL, 0, &be->result, &error, NULL,
	    userdata)) != NS_LDAP_SUCCESS) {
		argp->returnval = 0;
		rc = switch_err(rc, error);
		(void) __ns_ldap_freeError(&error);

		return (rc);
	}
		(void) __ns_ldap_freeError(&error);
	/* callback function */
	if ((callbackstat =
	    be->ldapobj2str(be, argp)) != NSS_STR_PARSE_SUCCESS) {
		goto error_out;
	}

	/*
	 * publickey does not have a front end marshaller and expects
	 * a string to be returned in NSS.
	 * No need to convert file format -> struct.
	 *
	 */
	if (be->db_type == NSS_LDAP_DB_PUBLICKEY) {
		argp->returnval = argp->buf.buffer;
		argp->returnlen = strlen(argp->buf.buffer);
		be->db_type = NSS_LDAP_DB_NONE;
		return (NSS_SUCCESS);
	}
	/*
	 *  Assume the switch engine wants the returned data in the file
	 *  format when argp->buf.result == NULL.
	 *  The front-end marshaller str2ether(ethers) uses
	 *  ent (argp->buf.result) and buffer (argp->buf.buffer)
	 *  for different purpose so ethers has to be treated differently.
	 */
	if (argp->buf.result != NULL ||
	    be->db_type == NSS_LDAP_DB_ETHERS) {
		/* file format -> struct */
		if (argp->str2ent == NULL) {
			callbackstat = NSS_STR_PARSE_PARSE;
			goto error_out;
		}

		callbackstat = (*argp->str2ent)(be->buffer,
		    be->buflen,
		    argp->buf.result,
		    argp->buf.buffer,
		    argp->buf.buflen);
		if (callbackstat == NSS_STR_PARSE_SUCCESS) {
			if (be->db_type == NSS_LDAP_DB_ETHERS &&
			    argp->buf.buffer != NULL) {
				argp->returnval = argp->buf.buffer;
				argp->returnlen = strlen(argp->buf.buffer);
			} else {
				argp->returnval = argp->buf.result;
				argp->returnlen = 1; /* irrelevant */
			}
			if (be->buffer != NULL) {
				free(be->buffer);
				be->buffer = NULL;
				be->buflen = 0;
				be->db_type = NSS_LDAP_DB_NONE;
			}
			return ((nss_status_t)NSS_SUCCESS);
		}
	} else {
			/* return file format in argp->buf.buffer */
			argp->returnval = argp->buf.buffer;
			argp->returnlen = strlen(argp->buf.buffer);
			return ((nss_status_t)NSS_SUCCESS);
	}

error_out:
	if (be->buffer != NULL) {
		free(be->buffer);
		be->buffer = NULL;
		be->buflen = 0;
		be->db_type = NSS_LDAP_DB_NONE;
	}
	/* error */
	if (callbackstat == NSS_STR_PARSE_PARSE) {
		argp->returnval = 0;
		return ((nss_status_t)NSS_NOTFOUND);
	}
	if (callbackstat == NSS_STR_PARSE_ERANGE) {
		argp->erange = 1;
		return ((nss_status_t)NSS_NOTFOUND);
	}
	if (callbackstat == NSS_STR_PARSE_NO_ADDR) {
		/* No IPV4 address is found */
		argp->h_errno = HOST_NOT_FOUND;
		return ((nss_status_t)NSS_NOTFOUND);
	}
	return ((nss_status_t)NSS_UNAVAIL);
}

/*
 *  This function is similar to _nss_ldap_lookup except it does not
 *  do a callback.  It is only used by getnetgrent.c
 */

/* ARGSUSED */
nss_status_t
_nss_ldap_nocb_lookup(ldap_backend_ptr be, nss_XbyY_args_t *argp,
    char *database, char *searchfilter, const char * const *attrs,
    int (*init_filter_cb)(const ns_ldap_search_desc_t *desc,
    char **realfilter, const void *userdata),
    const void *userdata)
{
	ns_ldap_error_t	*error = NULL;
	int		rc;

	if (attrs == NULL)
		attrs = be->attrs;

#ifdef	DEBUG
	(void) fprintf(stdout, "\n[ldap_common.c: _nss_ldap_nocb_lookup]\n");
	(void) fprintf(stdout, "\tsearchfilter: %s\n", searchfilter);
	(void) fprintf(stdout, "\tdatabase: %s\n", database);
	(void) fprintf(stdout,
	    "\tuserdata: %s\n", userdata ? userdata : "NULL");
#endif	/* DEBUG */

	(void) __ns_ldap_freeResult(&be->result);

	if ((rc = __ns_ldap_list(database, searchfilter, init_filter_cb,
	    attrs, NULL, 0, &be->result, &error, NULL,
	    userdata)) != NS_LDAP_SUCCESS) {
		if (argp != NULL)
			argp->returnval = 0;
		rc = switch_err(rc, error);
		(void) __ns_ldap_freeError(&error);
		return (rc);
	}

	return ((nss_status_t)NSS_SUCCESS);
}


/*
 *
 */

void
_clean_ldap_backend(ldap_backend_ptr be)
{
	ns_ldap_error_t *error;

#ifdef	DEBUG
	(void) fprintf(stdout, "\n[ldap_common.c: _clean_ldap_backend]\n");
#endif	/* DEBUG */

	if (be->tablename != NULL)
		free(be->tablename);
	if (be->result != NULL)
		(void) __ns_ldap_freeResult(&be->result);
	if (be->enumcookie != NULL)
		(void) __ns_ldap_endEntry(&be->enumcookie, &error);
	if (be->services_cookie != NULL)
		_nss_services_cookie_free((void **)&be->services_cookie);
	if (be->toglue != NULL) {
		free(be->toglue);
		be->toglue = NULL;
	}
	if (be->buffer != NULL) {
		free(be->buffer);
		be->buffer = NULL;
	}
	free(be);
}


/*
 * _nss_ldap_destr will free all smalloc'ed variable strings and structures
 * before exiting this nsswitch shared backend library. This function is
 * called before returning control back to nsswitch.
 */

/*ARGSUSED1*/
nss_status_t
_nss_ldap_destr(ldap_backend_ptr be, void *a)
{

#ifdef DEBUG
	(void) fprintf(stdout, "\n[ldap_common.c: _nss_ldap_destr]\n");
#endif /* DEBUG */

	(void) _clean_ldap_backend(be);

	return ((nss_status_t)NSS_SUCCESS);
}


/*
 * _nss_ldap_setent called before _nss_ldap_getent. This function is
 * required by POSIX.
 */

nss_status_t
_nss_ldap_setent(ldap_backend_ptr be, void *a)
{
	struct gettablefilter	*gtf;

#ifdef DEBUG
	(void) fprintf(stdout, "\n[ldap_common.c: _nss_ldap_setent]\n");
#endif /* DEBUG */

	if (be->setcalled == 1)
		(void) _nss_ldap_endent(be, a);
	be->filter = NULL;
	be->sortattr = NULL;
	for (gtf = gettablefilterent; gtf->tablename != (char *)NULL; gtf++) {
		if (strcmp(gtf->tablename, be->tablename))
			continue;
		be->filter = (char *)gtf->tablefilter;
		be->sortattr = (char *)gtf->sortattr;
		break;
	}

	be->setcalled = 1;
	be->enumcookie = NULL;
	be->result = NULL;
	be->services_cookie = NULL;
	be->buffer = NULL;
	return ((nss_status_t)NSS_SUCCESS);
}


/*
 * _nss_ldap_endent called after _nss_ldap_getent. This function is
 * required by POSIX.
 */

/*ARGSUSED1*/
nss_status_t
_nss_ldap_endent(ldap_backend_ptr be, void *a)
{
	ns_ldap_error_t	*error = NULL;

#ifdef DEBUG
	(void) fprintf(stdout, "\n[ldap_common.c: _nss_ldap_endent]\n");
#endif /* DEBUG */

	be->setcalled = 0;
	be->filter = NULL;
	be->sortattr = NULL;
	if (be->enumcookie != NULL) {
		(void) __ns_ldap_endEntry(&be->enumcookie, &error);
		(void) __ns_ldap_freeError(&error);
	}
	if (be->result != NULL) {
		(void) __ns_ldap_freeResult(&be->result);
	}
	if (be->services_cookie != NULL) {
		_nss_services_cookie_free((void **)&be->services_cookie);
	}
	if (be->buffer != NULL) {
		free(be->buffer);
		be->buffer = NULL;
	}

	return ((nss_status_t)NSS_SUCCESS);
}


/*
 *
 */

nss_status_t
_nss_ldap_getent(ldap_backend_ptr be, void *a)
{
	nss_XbyY_args_t	*argp = (nss_XbyY_args_t *)a;
	ns_ldap_error_t	*error = NULL;
	int		parsestat = 0;
	int		retcode = 0;

#ifdef	DEBUG
	(void) fprintf(stdout, "\n[ldap_common.c: _nss_ldap_getent]\n");
#endif	/* DEBUG */

	if (be->setcalled == 0)
		(void) _nss_ldap_setent(be, a);

next_entry:
	if (be->enumcookie == NULL) {
		retcode = __ns_ldap_firstEntry(be->tablename,
		    be->filter, be->sortattr, _merge_SSD_filter, be->attrs,
		    NULL, 0, &be->enumcookie,
		    &be->result, &error, _F_GETENT_SSD);
	} else {
		if (be->services_cookie == NULL) {
			retcode = __ns_ldap_nextEntry(be->enumcookie,
			    &be->result, &error);
		}
	}
	if (retcode != NS_LDAP_SUCCESS) {
		retcode = switch_err(retcode, error);
		(void) __ns_ldap_freeError(&error);
		(void) _nss_ldap_endent(be, a);
		return (retcode);
	}

	if (be->result == NULL) {
		parsestat = NSS_STR_PARSE_NO_RESULT;
		goto error_out;
	}
	/* ns_ldap_entry_t -> file format */
	if ((parsestat = be->ldapobj2str(be, argp))
	    == NSS_STR_PARSE_SUCCESS) {
		if (argp->buf.result != NULL) {
			/* file format -> struct */
			if (argp->str2ent == NULL) {
				parsestat = NSS_STR_PARSE_NO_RESULT;
				goto error_out;
			}
			parsestat = (*argp->str2ent)(be->buffer,
			    be->buflen,
			    argp->buf.result,
			    argp->buf.buffer,
			    argp->buf.buflen);
			if (parsestat == NSS_STR_PARSE_SUCCESS) {
				if (be->buffer != NULL) {
					free(be->buffer);
					be->buffer = NULL;
					be->buflen = 0;
				}
				be->result = NULL;
				argp->returnval = argp->buf.result;
				argp->returnlen = 1; /* irrevelant */
				return ((nss_status_t)NSS_SUCCESS);
			}
		} else {
			/*
			 * nscd is not caching the enumerated
			 * entries. This code path would be dormant.
			 * Keep this path for the future references.
			 */
			argp->returnval = argp->buf.buffer;
			argp->returnlen =
			    strlen(argp->buf.buffer) + 1;
		}
	}
error_out:
	if (be->buffer != NULL) {
		free(be->buffer);
		be->buffer = NULL;
		be->buflen = 0;
	}
	be->result = NULL;
	if (parsestat == NSS_STR_PARSE_NO_RESULT) {
		argp->returnval = 0;
		(void) _nss_ldap_endent(be, a);
		return ((nss_status_t)NSS_NOTFOUND);
	}

	if (parsestat == NSS_STR_PARSE_ERANGE) {
		argp->erange = 1;
		(void) _nss_ldap_endent(be, a);
		return ((nss_status_t)NSS_NOTFOUND);
	}
	if (parsestat == NSS_STR_PARSE_NO_ADDR)
		/*
		 * No IPV4 address is found in the current entry.
		 * It indicates that the entry contains IPV6 addresses
		 * only. Instead of calling _nss_ldap_endent to
		 * terminate, get next entry to continue enumeration.
		 * If it returned NSS_NOTFOUND here,
		 * gethostent() would return NULL
		 * and the enumeration would stop prematurely.
		 */
		goto next_entry;

	if (parsestat == NSS_STR_PARSE_PARSE)
		/*
		 * There has been a parse error. Most likely some
		 * mandatory attributes are missing. Ignore the error
		 * and get the next entry. If we returned an error the
		 * enumeration would stop prematurely.
		 */
		goto next_entry;

	return ((nss_status_t)NSS_SUCCESS);
}


/*
 *
 */

nss_backend_t *
_nss_ldap_constr(ldap_backend_op_t ops[], int nops, char *tablename,
    const char **attrs, fnf ldapobj2str)
{
	ldap_backend_ptr	be;

#ifdef	DEBUG
	(void) fprintf(stdout, "\n[ldap_common.c: _nss_ldap_constr]\n");
#endif	/* DEBUG */

	if ((be = (ldap_backend_ptr) calloc(1, sizeof (*be))) == 0)
		return (0);
	be->ops = ops;
	be->nops = (nss_dbop_t)nops;
	be->tablename = (char *)strdup(tablename);
	be->attrs = attrs;
	be->ldapobj2str = ldapobj2str;

	return ((nss_backend_t *)be);
}


/*
 *
 */
int
chophostdomain(char *string, char *host, char *domain)
{
	char	*dot;

	if (string == NULL)
		return (-1);

	if ((dot = strchr(string, '.')) == NULL) {
		return (0);
	}
	*dot = '\0';
	(void) strcpy(host, string);
	(void) strcpy(domain, ++dot);

	return (0);
}


/*
 *
 */
int
propersubdomain(char *domain, char *subdomain)
{
	int	domainlen, subdomainlen;

	/* sanity check */
	if (domain == NULL || subdomain == NULL)
		return (-1);

	domainlen = strlen(domain);
	subdomainlen = strlen(subdomain);

	/* is afterdot a substring of domain? */
	if ((strncasecmp(domain, subdomain, subdomainlen)) != 0)
		return (-1);

	if (domainlen == subdomainlen)
		return (1);

	if (subdomainlen > domainlen)
		return (-1);

	if (*(domain + subdomainlen) != '.')
		return (-1);

	return (1);
}
