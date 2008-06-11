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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <libintl.h>
#include <ctype.h>

#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <syslog.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netdir.h>
#include <lber.h>
#include <ldap.h>

#include "ns_sldap.h"
#include "ns_internal.h"
#include "ns_cache_door.h"

#define	UDP	"/dev/udp"
#define	MAXIFS	32

struct ifinfo {
	struct in_addr addr, netmask;
};

static ns_service_map ns_def_map[] = {
	{ "passwd",	"ou=people,",		NULL },
	{ "shadow",	"ou=people,",		"passwd" },
	{ "user_attr",	"ou=people,",		"passwd" },
	{ "audit_user",	"ou=people,",		"passwd" },
	{ "group",	"ou=group,",		NULL },
	{ "rpc",	"ou=rpc,",		NULL },
	{ "project",	"ou=projects,",		NULL },
	{ "protocols",	"ou=protocols,",	NULL },
	{ "networks",	"ou=networks,",		NULL },
	{ "netmasks",	"ou=networks,",		"networks" },
	{ "netgroup",	"ou=netgroup,",		NULL },
	{ "aliases",	"ou=aliases,",		NULL },
	{ "Hosts",	"ou=Hosts,",		NULL },
	{ "ipnodes",	"ou=Hosts,",		"hosts" },
	{ "Services",	"ou=Services,",		NULL },
	{ "bootparams",	"ou=ethers,",		"ethers" },
	{ "ethers",	"ou=ethers,",		NULL },
	{ "auth_attr",	"ou=SolarisAuthAttr,",	NULL },
	{ "prof_attr",	"ou=SolarisProfAttr,",	NULL },
	{ "exec_attr",	"ou=SolarisProfAttr,",	"prof_attr" },
	{ "profile",	"ou=profile,",		NULL },
	{ "printers",	"ou=printers,",		NULL },
	{ "automount",	"",			NULL },
	{ "tnrhtp",	"ou=ipTnet,",		NULL },
	{ "tnrhdb",	"ou=ipTnet,",		"tnrhtp" },
	{ NULL, NULL, NULL }
};


static char ** parseDN(const char *val, const char *service);
static char ** sortServerNet(char **srvlist);
static char ** sortServerPref(char **srvlist, char **preflist,
		boolean_t flag, int version, int *error);

/*
 * FUNCTION:	s_api_printResult
 *	Given a ns_ldap_result structure print it.
 */
int
__s_api_printResult(ns_ldap_result_t *result)
{

	ns_ldap_entry_t	*curEntry;
	int		i, j, k = 0;

#ifdef DEBUG
	(void) fprintf(stderr, "__s_api_printResult START\n");
#endif
	(void) printf("--------------------------------------\n");
	if (result == NULL) {
		(void) printf("No result\n");
		return (0);
	}
	(void) printf("entries_count %d\n", result->entries_count);
	curEntry = result->entry;
	for (i = 0; i < result->entries_count; i++) {

		(void) printf("entry %d has attr_count = %d \n", i,
		    curEntry->attr_count);
		for (j = 0; j < curEntry->attr_count; j++) {
			(void) printf("entry %d has attr_pair[%d] = %s \n",
			    i, j, curEntry->attr_pair[j]->attrname);
			for (k = 0; k < 20 &&
			    curEntry->attr_pair[j]->attrvalue[k]; k++)
				(void) printf("entry %d has attr_pair[%d]->"
				    "attrvalue[%d] = %s \n", i, j, k,
				    curEntry->attr_pair[j]->attrvalue[k]);
		}
		(void) printf("\n--------------------------------------\n");
		curEntry = curEntry->next;
	}
	return (1);
}

/*
 * FUNCTION:	__s_api_getSearchScope
 *
 *	Retrieve the search scope for ldap search from the config module.
 *
 * RETURN VALUES:	NS_LDAP_SUCCESS, NS_LDAP_CONFIG
 * INPUT:		NONE
 * OUTPUT:		searchScope, errorp
 */
int
__s_api_getSearchScope(
	int *searchScope,
	ns_ldap_error_t **errorp)
{

	char		errmsg[MAXERROR];
	void		**paramVal = NULL;
	int		rc = 0;
	int		scope = 0;

#ifdef DEBUG
	(void) fprintf(stderr, "__s_api_getSearchScope START\n");
#endif
	if (*searchScope == 0) {
		if ((rc = __ns_ldap_getParam(NS_LDAP_SEARCH_SCOPE_P,
		    &paramVal, errorp)) != NS_LDAP_SUCCESS) {
			return (rc);
		}
		if (paramVal && *paramVal)
			scope = * (int *)(*paramVal);
		else
			scope = NS_LDAP_SCOPE_ONELEVEL;
		(void) __ns_ldap_freeParam(&paramVal);
	} else {
		scope = *searchScope;
	}

	switch (scope) {

		case	NS_LDAP_SCOPE_ONELEVEL:
			*searchScope = LDAP_SCOPE_ONELEVEL;
			break;
		case	NS_LDAP_SCOPE_BASE:
			*searchScope = LDAP_SCOPE_BASE;
			break;
		case	NS_LDAP_SCOPE_SUBTREE:
			*searchScope = LDAP_SCOPE_SUBTREE;
			break;
		default:
			(void) snprintf(errmsg, sizeof (errmsg),
			    gettext("Invalid search scope!"));
			MKERROR(LOG_ERR, *errorp, NS_CONFIG_FILE,
			    strdup(errmsg), NS_LDAP_CONFIG);
			return (NS_LDAP_CONFIG);
	}

	return (NS_LDAP_SUCCESS);
}

/*
 * FUNCTION:	__ns_ldap_dupAuth
 *
 *	Duplicates an authentication structure.
 *
 * RETURN VALUES:	copy of authp or NULL on error
 * INPUT:		authp
 */
ns_cred_t *
__ns_ldap_dupAuth(const ns_cred_t *authp)
{
	ns_cred_t *ap;

#ifdef DEBUG
	(void) fprintf(stderr, "__ns_ldap_dupAuth START\n");
#endif
	if (authp == NULL)
		return (NULL);

	ap = (ns_cred_t *)calloc(1, sizeof (ns_cred_t));
	if (ap == NULL)
		return (NULL);

	if (authp->hostcertpath) {
		ap->hostcertpath = strdup(authp->hostcertpath);
		if (ap->hostcertpath == NULL) {
			free(ap);
			return (NULL);
		}
	}
	if (authp->cred.unix_cred.userID) {
		ap->cred.unix_cred.userID =
		    strdup(authp->cred.unix_cred.userID);
		if (ap->cred.unix_cred.userID == NULL) {
			(void) __ns_ldap_freeCred(&ap);
			return (NULL);
		}
	}
	if (authp->cred.unix_cred.passwd) {
		ap->cred.unix_cred.passwd =
		    strdup(authp->cred.unix_cred.passwd);
		if (ap->cred.unix_cred.passwd == NULL) {
			(void) __ns_ldap_freeCred(&ap);
			return (NULL);
		}
	}
	if (authp->cred.cert_cred.nickname) {
		ap->cred.cert_cred.nickname =
		    strdup(authp->cred.cert_cred.nickname);
		if (ap->cred.cert_cred.nickname == NULL) {
			(void) __ns_ldap_freeCred(&ap);
			return (NULL);
		}
	}
	ap->auth.type = authp->auth.type;
	ap->auth.tlstype = authp->auth.tlstype;
	ap->auth.saslmech = authp->auth.saslmech;
	ap->auth.saslopt = authp->auth.saslopt;
	return (ap);
}

/*
 * FUNCTION:	__ns_ldap_freeCred
 *
 *	Frees all the memory associated with a ns_cred_t structure.
 *
 * RETURN VALUES:	NS_LDAP_INVALID_PARAM, NS_LDAP_SUCCESS, NS_LDAP_CONFIG
 * INPUT:		ns_cred_t
 */
int
__ns_ldap_freeCred(ns_cred_t ** credp)
{
	ns_cred_t *ap;

#ifdef DEBUG
	(void) fprintf(stderr, "__ns_ldap_freeCred START\n");
#endif
	if (credp == NULL || *credp == NULL)
		return (NS_LDAP_INVALID_PARAM);

	ap = *credp;
	if (ap->hostcertpath) {
		(void) memset(ap->hostcertpath, 0,
		    strlen(ap->hostcertpath));
		free(ap->hostcertpath);
	}

	if (ap->cred.unix_cred.userID) {
		(void) memset(ap->cred.unix_cred.userID, 0,
		    strlen(ap->cred.unix_cred.userID));
		free(ap->cred.unix_cred.userID);
	}

	if (ap->cred.unix_cred.passwd) {
		(void) memset(ap->cred.unix_cred.passwd, 0,
		    strlen(ap->cred.unix_cred.passwd));
		free(ap->cred.unix_cred.passwd);
	}

	if (ap->cred.cert_cred.nickname) {
		(void) memset(ap->cred.cert_cred.nickname, 0,
		    strlen(ap->cred.cert_cred.nickname));
		free(ap->cred.cert_cred.nickname);
	}

	free(ap);
	*credp = NULL;
	return (NS_LDAP_SUCCESS);
}

/*
 * FUNCTION:	__s_api_is_auth_matched
 *
 *	Compare an authentication structure.
 *
 * RETURN VALUES:	B_TRUE if matched, B_FALSE otherwise.
 * INPUT:		auth1, auth2
 */
boolean_t
__s_api_is_auth_matched(const ns_cred_t *auth1,
    const ns_cred_t *auth2)
{
	if ((auth1->auth.type != auth2->auth.type) ||
	    (auth1->auth.tlstype != auth2->auth.tlstype) ||
	    (auth1->auth.saslmech != auth2->auth.saslmech) ||
	    (auth1->auth.saslopt != auth2->auth.saslopt))
		return (B_FALSE);

	if ((((auth1->auth.type == NS_LDAP_AUTH_SASL) &&
	    ((auth1->auth.saslmech == NS_LDAP_SASL_CRAM_MD5) ||
	    (auth1->auth.saslmech == NS_LDAP_SASL_DIGEST_MD5))) ||
	    (auth1->auth.type == NS_LDAP_AUTH_SIMPLE)) &&
	    ((auth1->cred.unix_cred.userID == NULL) ||
	    (auth1->cred.unix_cred.passwd == NULL) ||
	    ((strcasecmp(auth1->cred.unix_cred.userID,
	    auth2->cred.unix_cred.userID) != 0)) ||
	    ((strcmp(auth1->cred.unix_cred.passwd,
	    auth2->cred.unix_cred.passwd) != 0))))
		return (B_FALSE);

	return (B_TRUE);
}

/*
 * FUNCTION:	__s_api_getDNs
 *
 *	Retrieves the default base dn for the given
 *	service.
 *
 * RETURN VALUES:	NS_LDAP_SUCCESS, NS_LDAP_MEMORY, NS_LDAP_CONFIG
 * INPUT:		service
 * OUTPUT:		DN, error
 */
typedef int (*pf)(const char *, char **, ns_ldap_error_t **);
int
__s_api_getDNs(
	char *** DN,
	const char *service,
	ns_ldap_error_t ** error)
{

	void	**paramVal = NULL;
	char	**dns = NULL;
	int	rc = 0;
	int	i, len;
	pf	prepend_auto2dn = __s_api_prepend_automountmapname_to_dn;

#ifdef DEBUG
	(void) fprintf(stderr, "__s_api_getDNs START\n");
#endif
	if ((rc = __ns_ldap_getParam(NS_LDAP_SEARCH_BASEDN_P,
	    &paramVal, error)) != NS_LDAP_SUCCESS) {
		return (rc);
	}
	if (!paramVal) {
		char errmsg[MAXERROR];

		(void) snprintf(errmsg, sizeof (errmsg),
		    gettext("BaseDN not defined"));
		MKERROR(LOG_ERR, *error, NS_CONFIG_FILE, strdup(errmsg),
		    NS_LDAP_CONFIG);
		return (NS_LDAP_CONFIG);
	}

	dns = (char **)calloc(2, sizeof (char *));
	if (dns == NULL) {
		(void) __ns_ldap_freeParam(&paramVal);
		return (NS_LDAP_MEMORY);
	}

	if (service == NULL) {
		dns[0] = strdup((char *)*paramVal);
		if (dns[0] == NULL) {
			(void) __ns_ldap_freeParam(&paramVal);
			free(dns);
			return (NS_LDAP_MEMORY);
		}
	} else {
		for (i = 0; ns_def_map[i].service != NULL; i++) {
			if (strcasecmp(service,
			    ns_def_map[i].service) == 0) {

				len = strlen((char *)*paramVal) +
				    strlen(ns_def_map[i].rdn) + 1;
				dns[0] = (char *)
				    calloc(len, sizeof (char));
				if (dns[0] == NULL) {
					(void) __ns_ldap_freeParam(
					    &paramVal);
					free(dns);
					return (NS_LDAP_MEMORY);
				}
				(void) strcpy(dns[0],
				    ns_def_map[i].rdn);
				(void) strcat(dns[0],
				    (char *)*paramVal);
				break;
			}
		}
		if (ns_def_map[i].service == NULL) {
			char *p = (char *)*paramVal;
			char *buffer = NULL;
			int  buflen = 0;

			if (strchr(service, '=') == NULL) {
			    /* automount entries */
				if (strncasecmp(service, "auto_", 5) == 0) {
					buffer = strdup(p);
					if (!buffer) {
						free(dns);
						(void) __ns_ldap_freeParam(
						    &paramVal);
						return (NS_LDAP_MEMORY);
					}
					/* shorten name to avoid cstyle error */
					rc = prepend_auto2dn(
					    service, &buffer, error);
					if (rc != NS_LDAP_SUCCESS) {
						free(dns);
						free(buffer);
						(void) __ns_ldap_freeParam(
						    &paramVal);
						return (rc);
					}
				} else {
				/* strlen("nisMapName")+"="+","+'\0' = 13 */
					buflen = strlen(service) + strlen(p) +
					    13;
					buffer = (char *)malloc(buflen);
					if (buffer == NULL) {
						free(dns);
						(void) __ns_ldap_freeParam(
						    &paramVal);
						return (NS_LDAP_MEMORY);
					}
					(void) snprintf(buffer, buflen,
					    "nisMapName=%s,%s", service, p);
				}
			} else {
				buflen = strlen(service) + strlen(p) + 2;
				buffer = (char *)malloc(buflen);
				if (buffer == NULL) {
					free(dns);
					(void) __ns_ldap_freeParam(&paramVal);
					return (NS_LDAP_MEMORY);
				}
				(void) snprintf(buffer, buflen,
				    "%s,%s", service, p);
			}
			dns[0] = buffer;
		}
	}

	(void) __ns_ldap_freeParam(&paramVal);
	*DN = dns;
	return (NS_LDAP_SUCCESS);
}
/*
 * FUNCTION:	__s_api_get_search_DNs_v1
 *
 *	Retrieves the list of search DNS from the V1 profile for the given
 *	service.
 *
 * RETURN VALUES:	NS_LDAP_SUCCESS, NS_LDAP_MEMORY, NS_LDAP_CONFIG
 * INPUT:		service
 * OUTPUT:		DN, error
 */
int
__s_api_get_search_DNs_v1(
	char *** DN,
	const char *service,
	ns_ldap_error_t ** error)
{

	void	**paramVal = NULL;
	void	**temptr = NULL;
	char	**dns = NULL;
	int	rc = 0;

	if ((rc = __ns_ldap_getParam(NS_LDAP_SEARCH_DN_P,
	    &paramVal, error)) != NS_LDAP_SUCCESS) {
		return (rc);
	}

	if (service && paramVal) {
		for (temptr = paramVal; *temptr != NULL; temptr++) {
			dns = parseDN((const char *)(*temptr),
			    (const char *)service);
			if (dns != NULL)
				break;
		}
	}

	(void) __ns_ldap_freeParam(&paramVal);
	*DN = dns;
	return (NS_LDAP_SUCCESS);

}
/*
 * FUNCTION:	parseDN
 *
 *	Parse a special formated list(val) into an array of char *.
 *
 * RETURN VALUE:	A char * pointer to the new list of dns.
 * INPUT:		val, service
 */
static char **
parseDN(
	const char *val,
	const char *service)
{

	size_t		len = 0;
	size_t		slen = 0;
	char		**retVal = NULL;
	const char	*temptr;
	char		*temptr2;
	const char	*valend;
	int 		valNo = 0;
	int		valSize = 0;
	int		i;
	char		*SSD_service = NULL;

#ifdef DEBUG
	(void) fprintf(stderr, "parseDN START\n");
#endif
	if (val == NULL || *val == '\0')
		return (NULL);
	if (service == NULL || *service == '\0')
		return (NULL);

	len = strlen(val);
	slen = strlen(service);
	if (strncasecmp(val, service, slen) != 0) {
		/*
		 * This routine is only called
		 * to process V1 profile and
		 * for V1 profile, map service
		 * to the corresponding SSD_service
		 * which is associated with a
		 * real container in the LDAP directory
		 * tree, e.g., map "shadow" to
		 * "password". See function
		 * __s_api_get_SSD_from_SSDtoUse_service
		 * for similar service to SSD_service
		 * mapping handling for V2 profile.
		 */
		for (i = 0; ns_def_map[i].service != NULL; i++) {
			if (ns_def_map[i].SSDtoUse_service &&
			    strcasecmp(service,
			    ns_def_map[i].service) == 0) {
				SSD_service =
				    ns_def_map[i].SSDtoUse_service;
				break;
			}
		}

		if (SSD_service == NULL)
			return (NULL);

		slen = strlen(SSD_service);
		if (strncasecmp(val, SSD_service, slen) != 0)
			return (NULL);
	}

	temptr = val + slen;
	while (*temptr == SPACETOK || *temptr == TABTOK)
		temptr++;
	if (*temptr != COLONTOK)
		return (NULL);

	while (*temptr) {
		temptr2 = strchr(temptr, OPARATOK);
		if (temptr2 == NULL)
			break;
		temptr2++;
		temptr2 = strchr(temptr2, CPARATOK);
		if (temptr2 == NULL)
			break;
		valNo++;
		temptr = temptr2+1;
	}

	retVal = (char **)calloc(valNo +1, sizeof (char *));
	if (retVal == NULL)
		return (NULL);

	temptr = val;
	valend = val+len;

	for (i = 0; (i < valNo) && (temptr < valend); i++) {
		temptr = strchr(temptr, OPARATOK);
		if (temptr == NULL) {
			__s_api_free2dArray(retVal);
			return (NULL);
		}
		temptr++;
		temptr2 = strchr(temptr, CPARATOK);
		if (temptr2 == NULL) {
			__s_api_free2dArray(retVal);
			return (NULL);
		}
		valSize = temptr2 - temptr;

		retVal[i] = (char *)calloc(valSize + 1, sizeof (char));
		if (retVal[i] == NULL) {
			__s_api_free2dArray(retVal);
			return (NULL);
		}
		(void) strncpy(retVal[i], temptr, valSize);
		retVal[i][valSize] = '\0';
		temptr = temptr2 + 1;
	}

	return (retVal);
}


/*
 * __s_api_get_local_interfaces
 *
 * Returns a pointer to an array of addresses and netmasks of all interfaces
 * configured on the system.
 *
 * NOTE: This function is very IPv4 centric.
 */
static struct ifinfo *
__s_api_get_local_interfaces()
{
	struct ifconf		ifc;
	struct ifreq		ifreq, *ifr;
	struct ifinfo		*localinfo;
	struct in_addr		netmask;
	struct sockaddr_in	*sin;
	void			*buf = NULL;
	int			fd = 0;
	int			numifs = 0;
	int			i, n = 0;

	if ((fd = open(UDP, O_RDONLY)) < 0)
		return ((struct ifinfo *)NULL);

	if (ioctl(fd, SIOCGIFNUM, (char *)&numifs) < 0) {
		numifs = MAXIFS;
	}

	buf = malloc(numifs * sizeof (struct ifreq));
	if (buf == NULL) {
		(void) close(fd);
		return ((struct ifinfo *)NULL);
	}
	ifc.ifc_len = numifs * (int)sizeof (struct ifreq);
	ifc.ifc_buf = buf;
	if (ioctl(fd, SIOCGIFCONF, (char *)&ifc) < 0) {
		(void) close(fd);
		free(buf);
		buf = NULL;
		return ((struct ifinfo *)NULL);
	}
	ifr = (struct ifreq *)buf;
	numifs = ifc.ifc_len/(int)sizeof (struct ifreq);
	localinfo = (struct ifinfo *)malloc((numifs + 1) *
	    sizeof (struct ifinfo));
	if (localinfo == NULL) {
		(void) close(fd);
		free(buf);
		buf = NULL;
		return ((struct ifinfo *)NULL);
	}

	for (i = 0, n = numifs; n > 0; n--, ifr++) {
		uint_t ifrflags;

		ifreq = *ifr;
		if (ioctl(fd, SIOCGIFFLAGS, (char *)&ifreq) < 0)
			continue;

		ifrflags = ifreq.ifr_flags;
		if (((ifrflags & IFF_UP) == 0) ||
		    (ifr->ifr_addr.sa_family != AF_INET))
			continue;

		if (ioctl(fd, SIOCGIFNETMASK, (char *)&ifreq) < 0)
			continue;
		netmask = ((struct sockaddr_in *)&ifreq.ifr_addr)->sin_addr;

		if (ioctl(fd, SIOCGIFADDR, (char *)&ifreq) < 0)
			continue;

		sin = (struct sockaddr_in *)&ifreq.ifr_addr;

		localinfo[i].addr = sin->sin_addr;
		localinfo[i].netmask = netmask;
		i++;
	}
	localinfo[i].addr.s_addr = 0;

	free(buf);
	buf = NULL;
	(void) close(fd);
	return (localinfo);
}


/*
 * __s_api_samenet(char *, struct ifinfo *)
 *
 * Returns 1 if address is on the same subnet of the array of addresses
 * passed in.
 *
 * NOTE: This function is only valid for IPv4 addresses.
 */
static int
__s_api_IPv4sameNet(char *addr, struct ifinfo *ifs)
{
	int		answer = 0;

	if (addr && ifs) {
		char		*addr_raw;
		unsigned long	iaddr;
		int		i;

		if ((addr_raw = strdup(addr)) != NULL) {
			char	*s;

			/* Remove port number. */
			if ((s = strchr(addr_raw, ':')) != NULL)
				*s = '\0';

			iaddr = inet_addr(addr_raw);

			/* Loop through interface list to find match. */
			for (i = 0; ifs[i].addr.s_addr != 0; i++) {
				if ((iaddr & ifs[i].netmask.s_addr) ==
				    (ifs[i].addr.s_addr &
				    ifs[i].netmask.s_addr))
					answer++;
			}
			free(addr_raw);
		}
	}

	return (answer);
}

/*
 * FUNCTION:	__s_api_getServers
 *
 *	Retrieve a list of ldap servers from the config module.
 *
 * RETURN VALUE:	NS_LDAP_SUCCESS, NS_LDAP_CONFIG, NS_LDAP_MEMORY
 * INPUT:		NONE
 * OUTPUT:		servers, error
 */
int
__s_api_getServers(
		char *** servers,
		ns_ldap_error_t ** error)
{
	void	**paramVal = NULL;
	char	errmsg[MAXERROR];
	char	**sortServers = NULL;
	char	**netservers = NULL;
	int	rc = 0, err = NS_LDAP_CONFIG, version = 1;
	const 	char	*str, *str1;

#ifdef DEBUG
	(void) fprintf(stderr, "__s_api_getServers START\n");
#endif
	*servers = NULL;
	/* get profile version number */
	if ((rc = __ns_ldap_getParam(NS_LDAP_FILE_VERSION_P,
	    &paramVal, error)) != NS_LDAP_SUCCESS)
		return (rc);

	if (paramVal == NULL || *paramVal == NULL) {
		(void) snprintf(errmsg, sizeof (errmsg),
		    gettext("No file version"));
		MKERROR(LOG_INFO, *error, NS_CONFIG_FILE, strdup(errmsg),
		    NS_LDAP_CONFIG);
		return (NS_LDAP_CONFIG);
	}

	if (strcasecmp((char *)*paramVal, NS_LDAP_VERSION_1) == 0)
		version = 1;
	else if (strcasecmp((char *)*paramVal, NS_LDAP_VERSION_2) == 0)
		version = 2;

	(void) __ns_ldap_freeParam(&paramVal);
	paramVal = NULL;

	if ((rc = __ns_ldap_getParam(NS_LDAP_SERVERS_P,
	    &paramVal, error)) != NS_LDAP_SUCCESS)
		return (rc);

	/*
	 * For version 2, default server list could be
	 * empty.
	 */
	if ((paramVal == NULL || (char *)*paramVal == NULL) &&
	    version == 1) {
		str = NULL_OR_STR(__s_api_get_configname(NS_LDAP_SERVERS_P));
		(void) snprintf(errmsg, sizeof (errmsg),
		    gettext("Unable to retrieve the '%s' list"), str);
		MKERROR(LOG_WARNING, *error, NS_CONFIG_FILE, strdup(errmsg),
		    NS_LDAP_CONFIG);
		return (NS_LDAP_CONFIG);
	}

	/*
	 * Get server address(es) and go through them.
	 */
	*servers = (char **)paramVal;
	paramVal = NULL;

	/* Sort servers based on network. */
	if (*servers) {
		netservers = sortServerNet(*servers);
		if (netservers) {
			free(*servers);
			*servers = netservers;
		} else {
			return (NS_LDAP_MEMORY);
		}
	}

	/* Get preferred server list and sort servers based on that. */
	if ((rc = __ns_ldap_getParam(NS_LDAP_SERVER_PREF_P,
	    &paramVal, error)) != NS_LDAP_SUCCESS) {
		if (*servers)
			__s_api_free2dArray(*servers);
		*servers = NULL;
		return (rc);
	}

	if (paramVal != NULL) {
		char **prefServers;
		void **val = NULL;

		if ((rc =  __ns_ldap_getParam(NS_LDAP_PREF_ONLY_P,
		    &val, error)) != NS_LDAP_SUCCESS) {
				if (*servers)
					__s_api_free2dArray(*servers);
				*servers = NULL;
			(void) __ns_ldap_freeParam(&paramVal);
			return (rc);
		}

		prefServers = (char **)paramVal;
		paramVal = NULL;
		if (prefServers) {
			if (val != NULL && (*val) != NULL &&
			    *(int *)val[0] == 1)
				sortServers = sortServerPref(*servers,
				    prefServers, B_FALSE, version,
				    &err);
			else
				sortServers = sortServerPref(*servers,
				    prefServers, B_TRUE, version,
				    &err);
			if (sortServers) {
				if (*servers)
					free(*servers);
				*servers = NULL;
				free(prefServers);
				prefServers = NULL;
				*servers = sortServers;
			} else {
				if (*servers)
					__s_api_free2dArray(*servers);
				*servers = NULL;
				__s_api_free2dArray(prefServers);
				prefServers = NULL;
			}
		}
		(void) __ns_ldap_freeParam(&val);
	}
	(void) __ns_ldap_freeParam(&paramVal);

	if (*servers == NULL) {
		if (err == NS_LDAP_CONFIG) {
		str = NULL_OR_STR(__s_api_get_configname(
		    NS_LDAP_SERVERS_P));
		str1 = NULL_OR_STR(__s_api_get_configname(
		    NS_LDAP_SERVER_PREF_P));
			(void) snprintf(errmsg, sizeof (errmsg),
			    gettext("Unable to generate a new server list "
			    "based on '%s' and/or '%s'"), str, str1);
			MKERROR(LOG_WARNING, *error, NS_CONFIG_FILE,
			    strdup(errmsg), err);
			return (err);
		}
		return (NS_LDAP_MEMORY);
	}

	return (NS_LDAP_SUCCESS);

}

/*
 * FUNCTION:	sortServerNet
 *	Sort the serverlist based on the distance from client as long
 *	as the list only contains IPv4 addresses.  Otherwise do nothing.
 */
static char **
sortServerNet(char **srvlist)
{
	int		count = 0;
	int		all = 0;
	int		ipv4only = 1;
	struct ifinfo	*ifs = __s_api_get_local_interfaces();
	char		**tsrvs;
	char		**psrvs, **retsrvs;

	/* Sanity check. */
	if (srvlist == NULL || srvlist[0] == NULL)
		return (NULL);

	/* Count the number of servers to sort. */
	for (count = 0; srvlist[count] != NULL; count++) {
		if (!__s_api_isipv4(srvlist[count]))
			ipv4only = 0;
	}
	count++;

	/* Make room for the returned list of servers. */
	retsrvs = (char **)calloc(count, sizeof (char *));
	if (retsrvs == NULL) {
		free(ifs);
		ifs = NULL;
		return (NULL);
	}

	retsrvs[count - 1] = NULL;

	/* Make a temporary list of servers. */
	psrvs = (char **)calloc(count, sizeof (char *));
	if (psrvs == NULL) {
		free(ifs);
		ifs = NULL;
		free(retsrvs);
		retsrvs = NULL;
		return (NULL);
	}

	/* Filter servers on the same subnet */
	tsrvs = srvlist;
	while (*tsrvs) {
		if (ipv4only && __s_api_IPv4sameNet(*tsrvs, ifs)) {
			psrvs[all] = *tsrvs;
			retsrvs[all++] = *(tsrvs);
		}
		tsrvs++;
	}

	/* Filter remaining servers. */
	tsrvs = srvlist;
	while (*tsrvs) {
		char	**ttsrvs = psrvs;

		while (*ttsrvs) {
			if (strcmp(*tsrvs, *ttsrvs) == 0)
				break;
			ttsrvs++;
		}

		if (*ttsrvs == NULL)
			retsrvs[all++] = *(tsrvs);
		tsrvs++;
	}

	free(ifs);
	ifs = NULL;
	free(psrvs);
	psrvs = NULL;

	return (retsrvs);
}

/*
 * FUNCTION:	sortServerPref
 *	Sort the serverlist based on the preferred server list.
 *
 * The sorting algorithm works as follows:
 *
 * If version 1, if flag is TRUE, find all the servers in both preflist
 * and srvlist, then append other servers in srvlist to this list
 * and return the list.
 * If flag is FALSE, just return srvlist.
 * srvlist can not be empty.
 *
 * If version 2, append all the servers in srvlist
 * but not in preflist to preflist, and return the merged list.
 * If srvlist is empty, just return preflist.
 * If preflist is empty, just return srvlist.
 */
static char **
sortServerPref(char **srvlist, char **preflist,
		boolean_t flag, int version, int *error)
{
	int		i, scount = 0, pcount = 0;
	int		all = 0, dup = 0;
	char		**tsrvs;
	char		**retsrvs;
	char		**dupsrvs;

	/* Count the number of servers to sort. */
	if (srvlist && srvlist[0])
		for (i = 0; srvlist[i] != NULL; i++)
			scount++;

	/* Sanity check. */
	if (scount == 0 && version == 1) {
		*error = NS_LDAP_CONFIG;
		return (NULL);
	}

	/* Count the number of preferred servers */
	if (preflist && preflist[0])
		for (i = 0; preflist[i] != NULL; i++)
			pcount++;

	/* Sanity check. */
	if (scount == 0 && pcount == 0) {
		*error = NS_LDAP_CONFIG;
		return (NULL);
	}

	/* Make room for the returned list of servers */
	retsrvs = (char **)calloc(scount + pcount + 1, sizeof (char *));
	if (retsrvs == NULL) {
		*error = NS_LDAP_MEMORY;
		return (NULL);
	}

	/*
	 * if the preferred server list is empty,
	 * just return a copy of the server list
	 */
	if (pcount == 0) {
		tsrvs = srvlist;
		while (*tsrvs)
			retsrvs[all++] = *(tsrvs++);
		return (retsrvs);
	}
	all = 0;

	/*
	 * if the server list is empty,
	 * just return a copy of the preferred server list
	 */
	if (scount == 0) {
		tsrvs = preflist;
		while (*tsrvs)
			retsrvs[all++] = *(tsrvs++);
		return (retsrvs);
	}
	all = 0;

	/* Make room for the servers whose memory needs to be freed */
	dupsrvs = (char **)calloc(scount + pcount + 1, sizeof (char *));
	if (dupsrvs == NULL) {
		free(retsrvs);
		*error = NS_LDAP_MEMORY;
		return (NULL);
	}

	/*
	 * If version 1,
	 * throw out preferred servers not on server list.
	 * If version 2, make a copy of the preferred server list.
	 */
	if (version == 1) {
		tsrvs = preflist;
		while (*tsrvs) {
			char	**ttsrvs = srvlist;

			while (*ttsrvs) {
				if (strcmp(*tsrvs, *(ttsrvs)) == 0)
					break;
				ttsrvs++;
			}
			if (*ttsrvs != NULL)
				retsrvs[all++] = *tsrvs;
			else
				dupsrvs[dup++] = *tsrvs;
			tsrvs++;
		}
	} else {
		tsrvs = preflist;
		while (*tsrvs)
			retsrvs[all++] = *(tsrvs++);
	}
	/*
	 * If version 1,
	 * if PREF_ONLY is false, we append the non-preferred servers
	 * to bottom of list.
	 * For version 2, always append.
	 */
	if (flag == B_TRUE || version != 1) {

		tsrvs = srvlist;
		while (*tsrvs) {
			char	**ttsrvs = preflist;

			while (*ttsrvs) {
				if (strcmp(*tsrvs, *ttsrvs) == 0) {
					break;
				}
				ttsrvs++;
			}
			if (*ttsrvs == NULL)
				retsrvs[all++] = *tsrvs;
			else
				dupsrvs[dup++] = *tsrvs;
			tsrvs++;
		}
	}

	/* free memory for duplicate servers */
	if (dup) {
		for (tsrvs = dupsrvs; *tsrvs; tsrvs++)
			free(*tsrvs);
	}
	free(dupsrvs);

	return (retsrvs);
}

/*
 * FUNCTION:	__s_api_removeBadServers
 *	Contacts the ldap cache manager for marking the
 *	problem servers as down, so that the server is
 *	not contacted until the TTL expires.
 */
void
__s_api_removeBadServers(char ** Servers)
{

	char	**host;

	if (Servers == NULL)
		return;

	for (host = Servers; *host != NULL; host++) {
		if (__s_api_removeServer(*host) < 0) {
			/*
			 * Couldn't remove server from
			 * server list. Log a warning.
			 */
			syslog(LOG_WARNING, "libsldap: could "
			    "not remove %s from servers list", *host);
		}
	}
}

/*
 * FUNCTION:	__s_api_free2dArray
 */
void
__s_api_free2dArray(char ** inarray)
{

	char	**temptr;

	if (inarray == NULL)
		return;

	for (temptr = inarray; *temptr != NULL; temptr++) {
		free(*temptr);
	}
	free(inarray);
}

/*
 * FUNCTION:	__s_api_cp2dArray
 */
char **
__s_api_cp2dArray(char **inarray)
{
	char	**newarray;
	char	 **ttarray, *ret;
	int	count;

	if (inarray == NULL)
		return (NULL);

	for (count = 0; inarray[count] != NULL; count++)
		;

	newarray = (char **)calloc(count + 1, sizeof (char *));
	if (newarray == NULL)
		return (NULL);

	ttarray = newarray;
	for (; *inarray; inarray++) {
		*(ttarray++) = ret = strdup(*inarray);
		if (ret == NULL) {
			__s_api_free2dArray(newarray);
			return (NULL);
		}
	}
	return (newarray);
}

/*
 * FUNCTION:	__s_api_isCtrlSupported
 *	Determines if the passed control is supported by the LDAP sever.
 * RETURNS:	NS_LDAP_SUCCESS if yes, NS_LDAP_OP_FAIL if not.
 */
int
__s_api_isCtrlSupported(Connection *con, char *ctrlString)
{
	char		**ctrl;
	int		len;

	len = strlen(ctrlString);
	for (ctrl = con->controls; ctrl && *ctrl; ctrl++) {
		if (strncasecmp(*ctrl, ctrlString, len) == 0)
			return (NS_LDAP_SUCCESS);
	}
	return (NS_LDAP_OP_FAILED);
}

/*
 * FUNCTION:	__s_api_toFollowReferrals
 *	Determines if need to follow referral for an SLDAP API.
 * RETURN VALUES:	NS_LDAP_SUCCESS, NS_LDAP_INVALID_PARAM, or
 *			other rc from __ns_ldap_getParam()
 * INPUT:		flags
 * OUTPUT:		toFollow, errorp
 */
int
__s_api_toFollowReferrals(const int flags,
	int *toFollow,
	ns_ldap_error_t **errorp)
{
	void		**paramVal = NULL;
	int		rc = 0;
	int		iflags = 0;

#ifdef DEBUG
	(void) fprintf(stderr, "__s_api_toFollowReferrals START\n");
#endif

	/* Either NS_LDAP_NOREF or NS_LDAP_FOLLOWREF not both */
	if ((flags & (NS_LDAP_NOREF | NS_LDAP_FOLLOWREF)) ==
	    (NS_LDAP_NOREF | NS_LDAP_FOLLOWREF)) {
		return (NS_LDAP_INVALID_PARAM);
	}

	/*
	 * if the NS_LDAP_NOREF or NS_LDAP_FOLLOWREF is set
	 * this will take precendence over the values specified
	 * in the configuration file
	 */
	if (flags & (NS_LDAP_NOREF | NS_LDAP_FOLLOWREF)) {
			iflags = flags;
	} else {
		rc = __ns_ldap_getParam(NS_LDAP_SEARCH_REF_P,
		    &paramVal, errorp);
		if (rc != NS_LDAP_SUCCESS)
			return (rc);
		if (paramVal == NULL || *paramVal == NULL) {
			(void) __ns_ldap_freeParam(&paramVal);
			if (*errorp)
				(void) __ns_ldap_freeError(errorp);
			*toFollow = TRUE;
			return (NS_LDAP_SUCCESS);
		}
		iflags = (* (int *)(*paramVal));
		(void) __ns_ldap_freeParam(&paramVal);
	}

	if (iflags & NS_LDAP_NOREF)
		*toFollow = FALSE;
	else
		*toFollow = TRUE;

	return (NS_LDAP_SUCCESS);
}

/*
 * FUNCTION:	__s_api_addRefInfo
 *	Insert a referral info into a referral info list.
 * RETURN VALUES:	NS_LDAP_SUCCESS, NS_LDAP_MEMORY, NS_LDAP_OP_FAILED
 * INPUT:		LDAP URL, pointer to the referral info list,
 *                      search baseDN, search scope, search filter,
 *                      previous connection
 */
int
__s_api_addRefInfo(ns_referral_info_t **head, char *url,
			char *baseDN, int *scope,
			char *filter, LDAP *ld)
{
	char			errmsg[MAXERROR], *tmp;
	ns_referral_info_t	*ref, *tmpref;
	LDAPURLDesc		*ludp = NULL;
	int			hostlen;
	char *ld_defhost = NULL;

#ifdef DEBUG
	(void) fprintf(stderr, "__s_api_addRefInfo START\n");
#endif

	/* sanity check */
	if (head == NULL)
		return (NS_LDAP_OP_FAILED);

	/*
	 * log error and return NS_LDAP_SUCCESS
	 * if one of the following:
	 * 1. non-LDAP URL
	 * 2. LDAP URL which can not be parsed
	 */
	if (!ldap_is_ldap_url(url) ||
	    ldap_url_parse_nodn(url, &ludp) != 0) {
		(void) snprintf(errmsg, MAXERROR, "%s: %s",
		    gettext("Invalid or non-LDAP URL when"
		    " processing referrals URL"),
		    url);
		syslog(LOG_ERR, "libsldap: %s", errmsg);
		if (ludp)
				ldap_free_urldesc(ludp);
		return (NS_LDAP_SUCCESS);
	}

	ref = (ns_referral_info_t *)calloc(1,
	    sizeof (ns_referral_info_t));
	if (ref == NULL) {
		ldap_free_urldesc(ludp);
		return (NS_LDAP_MEMORY);
	}

	/*
	 * we do have a valid URL and we were able to parse it
	 * however, we still need to find out what hostport to
	 * use if none were provided in the LDAP URL
	 * (e.g., ldap:///...)
	 */
	if ((ludp->lud_port == 0) && (ludp->lud_host == NULL)) {
		if (ld == NULL) {
			(void) snprintf(errmsg, MAXERROR, "%s: %s",
			    gettext("no LDAP handle when"
			    " processing referrals URL"),
			    url);
			syslog(LOG_WARNING, "libsldap: %s", errmsg);
			ldap_free_urldesc(ludp);
			free(ref);
			return (NS_LDAP_SUCCESS);
		} else {
			(void) ldap_get_option(ld, LDAP_OPT_HOST_NAME,
			    &ld_defhost);
			if (ld_defhost == NULL) {
				(void) snprintf(errmsg, MAXERROR, "%s: %s",
				    gettext("not able to retrieve default "
				    "host when processing "
				    "referrals URL"),
				    url);
				syslog(LOG_WARNING, "libsldap: %s", errmsg);
				ldap_free_urldesc(ludp);
				free(ref);
				return (NS_LDAP_SUCCESS);
			} else {
				ref->refHost = strdup(ld_defhost);
				if (ref->refHost == NULL) {
					ldap_free_urldesc(ludp);
					free(ref);
					return (NS_LDAP_MEMORY);
				}
			}
		}
	} else {
		/*
		 * add 4 here:
		 * 1 for the last '\0'.
		 * 1 for host and prot separator ":"
		 * and "[" & "]" for possible ipV6 addressing
		 */
		hostlen = strlen(ludp->lud_host) +
		    sizeof (MAXPORTNUMBER_STR) + 4;
		ref->refHost = (char *)malloc(hostlen);
		if (ref->refHost == NULL) {
			ldap_free_urldesc(ludp);
			free(ref);
			return (NS_LDAP_MEMORY);
		}

		if (ludp->lud_port != 0) {
			/*
			 * serverAddr = host:port
			 * or
			 * if host is an IPV6 address
			 * [host]:port
			 */
			tmp = strstr(url, ludp->lud_host);
			if (tmp && (tmp > url) && *(tmp - 1) == '[') {
				(void) snprintf(ref->refHost, hostlen,
				    "[%s]:%d",
				    ludp->lud_host,
				    ludp->lud_port);
			} else {
				(void) snprintf(ref->refHost, hostlen,
				    "%s:%d",
				    ludp->lud_host,
				    ludp->lud_port);
			}
		} else {
			/* serverAddr = host */
			(void) snprintf(ref->refHost, hostlen, "%s",
			    ludp->lud_host);
		}
	}

	if (ludp->lud_dn) {
		ref->refDN = strdup(ludp->lud_dn);
		if (ref->refDN == NULL) {
			ldap_free_urldesc(ludp);
			free(ref->refHost);
			free(ref);
			return (NS_LDAP_MEMORY);
		}
	} else {
		if (baseDN) {
			ref->refDN = strdup(baseDN);
			if (ref->refDN == NULL) {
				ldap_free_urldesc(ludp);
				free(ref->refHost);
				free(ref);
				return (NS_LDAP_MEMORY);
			}
		}
	}

	if (filter)
		ref->refFilter = strdup(filter);
	else if (ludp->lud_filter)
		ref->refFilter = strdup(ludp->lud_filter);
	else
		ref->refFilter = strdup("");

	if (ref->refFilter == NULL) {
		ldap_free_urldesc(ludp);
		free(ref->refHost);
		if (ref->refDN)
			free(ref->refDN);
		free(ref);
		return (NS_LDAP_MEMORY);
	}

	if (scope)
		ref->refScope = *scope;

	ref->next = NULL;

	ldap_free_urldesc(ludp);

	/* insert the referral info */
	if (*head) {
		for (tmpref = *head; tmpref->next; tmpref = tmpref->next)
			;
		tmpref->next = ref;
	} else
		*head = ref;

	return (NS_LDAP_SUCCESS);
}

/*
 * FUNCTION:	__s_api_deleteRefInfo
 *	Delete a referral info list.
 * INPUT:		pointer to the referral info list
 */
void
__s_api_deleteRefInfo(ns_referral_info_t *head)
{
	ns_referral_info_t	*ref, *tmp;

#ifdef DEBUG
	(void) fprintf(stderr, "__s_api_deleteRefInfo START\n");
#endif

	for (ref = head; ref; ) {
		if (ref->refHost)
			free(ref->refHost);
		if (ref->refDN)
			free(ref->refDN);
		if (ref->refFilter)
			free(ref->refFilter);
		tmp = ref->next;
		free(ref);
		ref = tmp;
	}

}

/*
 * FUNCTION:	__s_api_get_SSD_from_SSDtoUse_service
 *
 *	Retrieves the Service Search Descriptors which should be used for
 *	the given service. For example, return all the "passwd" SSDs for
 *	service "shadow" if no SSD is defined for service "shadow" and
 *	no filter component is defined in all the "passwd" SSDs. This idea
 *	of sharing the SSDs defined for some other service is to reduce the
 *	configuration complexity. For a service, which does not have its own
 *	entries in the LDAP directory, SSD for it is useless, and should not
 *	be set. But since this service must share the container with at least
 *	one other service which does have it own entries, the SSD for
 *	this other service will be shared by this service.
 *	This other service is called the SSD-to-use service.
 *	The static data structure, ns_def_map[], in this file
 *	defines the SSD-to-use service for all the services supported.
 *
 * RETURN VALUES:	NS_LDAP_SUCCESS, NS_LDAP_MEMORY, NS_LDAP_INVALID_PARAM
 * INPUT:		service
 * OUTPUT:		*SSDlist, *errorp if error
 */
int
__s_api_get_SSD_from_SSDtoUse_service(const char *service,
		ns_ldap_search_desc_t ***SSDlist,
		ns_ldap_error_t **errorp)
{
	int 			i, rc;
	int 			found = FALSE;
	int 			filter_found = FALSE;
	char			*SSD_service = NULL;
	char			errmsg[MAXERROR];
	ns_ldap_search_desc_t	**sdlist;
	int			auto_service = FALSE;

#ifdef DEBUG
	(void) fprintf(stderr,
	    "__s_api_get_SSD_from_SSDtoUse_service START\n");
#endif

	if (SSDlist == NULL || errorp == NULL)
		return (NS_LDAP_INVALID_PARAM);

	*SSDlist = NULL;
	*errorp = NULL;

	if (service == NULL)
		return (NS_LDAP_SUCCESS);

	if (strncasecmp(service, "auto_", 5) == 0)
		auto_service = TRUE;

	/*
	 * First try to return the configured SSDs for the input server
	 */
	rc = __ns_ldap_getSearchDescriptors(service, SSDlist, errorp);
	if (rc != NS_LDAP_SUCCESS)
		return (rc);
	else {
		if (*SSDlist != NULL)
			return (NS_LDAP_SUCCESS);
	}

	/*
	 * If service == auto_* and SSD is not found,
	 * then try automount to see if there is an SSD
	 * for automount.
	 */

	if (auto_service) {
		rc = __ns_ldap_getSearchDescriptors(
		    "automount", SSDlist, errorp);
		if (rc != NS_LDAP_SUCCESS)
			return (rc);
		else {
			if (*SSDlist != NULL) {
				/*
				 * If SSDlist is found,
				 * prepend automountMapName to the basedn
				 * in the SSDlist
				 *
				 */
				rc = __s_api_prepend_automountmapname(
				    service,
				    SSDlist,
				    errorp);

				if (rc != NS_LDAP_SUCCESS) {
					(void) __ns_ldap_freeSearchDescriptors(
					    SSDlist);
					*SSDlist = NULL;
				}

				return (rc);
			}
		}
	}

	/*
	 * Find the SSDtoUse service.
	 * If none found, flag "found" remains FALSE.
	 */
	for (i = 0; ns_def_map[i].service != NULL; i++) {
		if (ns_def_map[i].SSDtoUse_service &&
		    strcasecmp(service,
		    ns_def_map[i].service) == 0) {
			found = TRUE;
			SSD_service = ns_def_map[i].SSDtoUse_service;
			break;
		}
	}

	if (!found)
		return (NS_LDAP_SUCCESS);

	/*
	 * return the SSDs for SSD_service only if no optional filter
	 * component is defined in the SSDs
	 */
	rc = __ns_ldap_getSearchDescriptors(SSD_service,
	    SSDlist, errorp);
	if (rc != NS_LDAP_SUCCESS) {
		return (rc);
	} else {
		if (*SSDlist == NULL)
			return (NS_LDAP_SUCCESS);

		/* check to see if filter defined in SSD */
		for (sdlist = *SSDlist; *sdlist; sdlist++) {
			if ((*sdlist)->filter &&
			    strlen((*sdlist)->filter) > 0) {
				filter_found = TRUE;
				break;
			}
		}
		if (filter_found) {
			(void) __ns_ldap_freeSearchDescriptors(SSDlist);
			*SSDlist = NULL;
			(void) snprintf(errmsg, sizeof (errmsg),
			    gettext("Service search descriptor for "
			    "service '%s' contains filter, "
			    "which can not be used for "
			    "service '%s'."),
			    SSD_service, service);
			MKERROR(LOG_WARNING, *errorp, NS_CONFIG_FILE,
			    strdup(errmsg), NS_LDAP_CONFIG);
			return (NS_LDAP_CONFIG);
		}

	}
	return (NS_LDAP_SUCCESS);
}


/*
 * verify addr is an IPv4 address with the optional [:portno]
 * RFC2373 & RFC2732 & RFC2396
 */
int
__s_api_isipv4(char *addr)
{
	int i, seg, digit, port;

	if (!addr)
		return (0);

	digit = seg = port = 0;

	for (i = 0; i < strlen(addr); i++) {
		if (isdigit(addr[i])) {
			digit++;
			continue;
		}
		if (addr[i] == '.') {
			if (digit > 3 || digit == 0)
				return (0);
			digit = 0;
			seg++;
			continue;
		}
		if (addr[i] == ':') {
			if (digit > 3)
				return (0);
			port++;
			digit = 0;
			seg++;
			continue;
		}
		return (0);
	}

	if ((seg == 3 && port == 0 && digit > 0 && digit < 4) ||
	    (seg == 4 && port == 1 && digit > 0))
		return (1);

	return (0);
}


/*
 * verify addr is an IPv6 address with the optional [IPv6]:portno
 * RFC2373 & RFC2732 & RFC2396
 */
int
__s_api_isipv6(char *addr)
{
	int i, col, digit, port, dc, tc;
	char *laddr, *c1, *s;

	if (!addr)
		return (0);

	s = addr;
	laddr = NULL;
	digit = col = port = 0;
	if (addr[0] == '[') {
		laddr = strdup(addr);
		if (!laddr)
			return (0);
		c1 = strchr(laddr, ']');
		/* only 1 ']' should be in an addr */
		if (!c1 || (strchr(c1+1, ']')))
			goto bad;
		switch (c1[1]) {
			case ':':
				port++;
				for (i = 2; i < strlen(c1); i++) {
					if (!isdigit(c1[i]))
						goto bad;
					digit++;
				}
				if (!digit)
					goto bad;
				c1[0] = '\0';
				break;
			case '\0':
				c1[0] = '\0';
				break;
			default:
				goto bad;
		}
		s = &laddr[1];
	}

	digit = dc = tc = 0;
	for (i = 0; i < strlen(s); i++) {
		if (isxdigit(s[i])) {
			if (digit == 0)
				dc = i;
			digit++;
			col = 0;
			continue;
		}
		if (s[i] == ':') {
			tc++;
			if ((col > 1) || (i && !col && !digit))
				goto bad;
			digit = 0;
			col++;
			continue;
		}
		if (s[i] == '.') {
			if (__s_api_isipv4(&s[dc]) && tc)
				goto good;
			else
				goto bad;
		}
		goto bad;
	}

good:
	free(laddr);
	return (1);
bad:
	free(laddr);
	return (0);
}


/*
 * verify addr is a valid hostname with the optional [:portno]
 * RFC2373 & RFC2732 & RFC2396
 */
int
__s_api_ishost(char *addr)
{
	int i, seg, alpha, digit, port;

	if (!addr)
		return (0);

	alpha = digit = seg = port = 0;

	/* must start with alpha character */
	if (!isalpha(addr[0]))
		return (0);

	for (i = 0; i < strlen(addr); i++) {
		if (isalpha(addr[i]) || (i && addr[i] == '-')) {
			alpha++;
			continue;
		}
		if (isdigit(addr[i])) {
			digit++;
			continue;
		}
		if (addr[i] == '.') {
			if (!alpha && !digit)
				return (0);
			alpha = digit = 0;
			seg++;
			continue;
		}
		if (addr[i] == ':') {
			if (!alpha && !digit)
				return (0);
			alpha = digit = 0;
			port++;
			seg++;
			continue;
		}
		return (0);
	}

	if ((port == 0 && (seg || alpha || digit)) ||
	    (port == 1 && alpha == 0 && digit))
		return (1);

	return (0);
}


/*
 * Prepend automountMapName=auto_xxx to the basedn
 * in the SSDlist
 */

int __s_api_prepend_automountmapname(
	const char *service,
	ns_ldap_search_desc_t ***SSDlist,
	ns_ldap_error_t **errorp)
{
	int			i, rc;
	ns_ldap_search_desc_t	** ssdlist = NULL;

	if (service == NULL || SSDlist == NULL || *SSDlist == NULL)
		return (NS_LDAP_INVALID_PARAM);

	ssdlist = *SSDlist;

	for (i = 0; ssdlist[i] != NULL; i++) {
		rc = __s_api_prepend_automountmapname_to_dn(
		    service, &ssdlist[i]->basedn, errorp);

		if (rc != NS_LDAP_SUCCESS)
			return (rc);
	}

	return (NS_LDAP_SUCCESS);
}


/*
 * Prepend automountMapName=auto_xxx to the DN
 * Construct a string of
 * "automountMapName=auto_xxx,dn"
 *
 * If automountMapName is mapped to some other attribute,
 * then use the mapping in the setup.
 *
 * If a version 1 profile is in use, use nisMapName for
 * backward compatibility (i.e. "nisMapName=auto_xxx,dn").
 */

int
__s_api_prepend_automountmapname_to_dn(
	const char *service,
	char **dn,
	ns_ldap_error_t **errorp)
{
	int rc, len_s = 0, len_d = 0, len = 0;
	char *buffer = NULL;
	char *default_automountmapname = "automountMapName";
	char *automountmapname = NULL;
	char **mappedattrs = NULL;
	char errstr[MAXERROR];
	void **paramVal = NULL;

	if (service == NULL || dn == NULL || *dn == NULL)
		return (NS_LDAP_INVALID_PARAM);

	rc = __ns_ldap_getParam(NS_LDAP_FILE_VERSION_P, &paramVal, errorp);
	if (rc != NS_LDAP_SUCCESS || !paramVal || !*paramVal) {
		if (paramVal)
			(void) __ns_ldap_freeParam(&paramVal);
		return (rc);
	}
	if (strcasecmp(*paramVal, NS_LDAP_VERSION_1) == 0) {
		automountmapname = strdup("nisMapName");
		(void) __ns_ldap_freeParam(&paramVal);
		if (automountmapname == NULL) {
			return (NS_LDAP_MEMORY);
		}
	} else {
		(void) __ns_ldap_freeParam(&paramVal);

		/* Find mapped attribute name of auto_xxx first */
		mappedattrs = __ns_ldap_getMappedAttributes(
		    service, default_automountmapname);
		/*
		 * if mapped attribute name of auto_xxx is not found,
		 * find the mapped attribute name of automount
		 */

		if (mappedattrs == NULL)
			mappedattrs = __ns_ldap_getMappedAttributes(
			"automount", default_automountmapname);

		/*
		 * if mapped attr is not found, use the default automountmapname
		 */

		if (mappedattrs == NULL) {
			automountmapname = strdup(default_automountmapname);
			if (automountmapname == NULL)
				return (NS_LDAP_MEMORY);
		} else {
			if (mappedattrs[0] != NULL) {
				/*
				 * Copy it from the mapped attr list
				 * Assume it's 1 to 1 mapping
				 * 1 to n does not make sense
				 */
				automountmapname = strdup(mappedattrs[0]);
				__s_api_free2dArray(mappedattrs);
				if (automountmapname == NULL) {
					return (NS_LDAP_MEMORY);
				}
			} else {

				/*
				 * automountmapname is mapped to an empty string
				 */

				__s_api_free2dArray(mappedattrs);

				(void) sprintf(errstr,
				    gettext(
				    "Attribute automountMapName is "
				    "mapped to an empty string.\n"));

				MKERROR(LOG_WARNING, *errorp, NS_CONFIG_SYNTAX,
				    strdup(errstr), NS_LDAP_MEMORY);

				return (NS_LDAP_CONFIG);
			}
		}
	}

	len_s = strlen(service);
	len_d  = strlen(*dn);
	/* automountMapName + "=" + service + "," + dn + '\0' */
	len = strlen(automountmapname) + 1 + len_s + 1 + len_d + 1;
	buffer = (char *)malloc(len);
	if (buffer == NULL) {
		free(automountmapname);
		return (NS_LDAP_MEMORY);
	}

	(void) snprintf(buffer, len, "%s=%s,%s",
	    automountmapname, service, *dn);

	buffer[len-1] = '\0';

	free(automountmapname);

	/* free the original dn */
	(void) free(*dn);

	*dn = buffer;

	return (NS_LDAP_SUCCESS);
}

/*
 * Map the LDAP error code and error message from LDAP server
 * to a password status used for password aging/management.
 */
ns_ldap_passwd_status_t
__s_api_set_passwd_status(int errnum, char *errmsg)
{
	if (errmsg) {
		if (errnum ==
		    LDAP_INVALID_CREDENTIALS) {
			/*
			 * case 1 (Bind):
			 * password expired
			 */
			if (strstr(errmsg,
			    NS_PWDERR_EXPIRED))
				return (NS_PASSWD_EXPIRED);
		}

		if (errnum ==
		    LDAP_UNWILLING_TO_PERFORM) {
			/*
			 * case 1.1 (Bind):
			 * password expired
			 */
			if (strstr(errmsg,
			    NS_PWDERR_EXPIRED))
				return (NS_PASSWD_EXPIRED);

			/*
			 * case 2 (Bind):
			 * Account inactivated
			 */
			if (strstr(errmsg,
			    NS_PWDERR_ACCT_INACTIVATED))
				return (NS_PASSWD_EXPIRED);


			/*
			 * case 3 (Modify passwd):
			 * the user is not allow to change
			 * password; only admin can change it
			 */
			if (strstr(errmsg,
			    NS_PWDERR_CHANGE_NOT_ALLOW))
				return (NS_PASSWD_CHANGE_NOT_ALLOWED);
		}

		if (errnum ==
		    LDAP_CONSTRAINT_VIOLATION) {
			/*
			 * case 4 (Bind):
			 * the user account is locked due to
			 * too many login failures.
			 */
			if (strstr(errmsg,
			    NS_PWDERR_MAXTRIES))
				return (NS_PASSWD_RETRY_EXCEEDED);
			/*
			 * case 5 (Modify passwd):
			 * syntax error: the new password
			 * has length less than defined
			 * minimum
			 */
			if (strstr(errmsg,
			    NS_PWDERR_INVALID_SYNTAX))
				return (NS_PASSWD_TOO_SHORT);
			/*
			 * case 6 (Modify passwd):
			 * trivial password: same valule as
			 * that of attribute cn, sn, or uid ...
			 */
			if (strstr(errmsg,
			    NS_PWDERR_TRIVIAL_PASSWD))
				return (NS_PASSWD_INVALID_SYNTAX);
			/*
			 * case 7 (Modify passwd):
			 * re-use one of the old passwords
			 * in history list
			 */
			if (strstr(errmsg,
			    NS_PWDERR_IN_HISTORY))
				return (NS_PASSWD_IN_HISTORY);
			/*
			 * case 8 (Modify passwd):
			 * password not allowed to be
			 * changed yet; within minimum
			 * age
			 */
			if (strstr(errmsg,
			    NS_PWDERR_WITHIN_MIN_AGE))
				return (NS_PASSWD_WITHIN_MIN_AGE);
		}

	}

	return (NS_PASSWD_GOOD);
}

/*
 * Determine if the input OID list contains
 * one of the password control OIDs, which are:
 * LDAP_CONTROL_PWEXPIRED: 2.16.840.1.113730.3.4.4
 * LDAP_CONTROL_PWEXPIRING: 2.16.840.1.113730.3.4.5.
 * If yes, return 1, if no, 0.
 */
int
__s_api_contain_passwd_control_oid(char **oids)
{
	char **oid;

	if (oids == NULL)
		return (0);

	for (oid = oids; *oid; oid++) {
		if (strcmp(*oid, LDAP_CONTROL_PWEXPIRED) == 0 ||
		    strcmp(*oid, LDAP_CONTROL_PWEXPIRING) == 0) {
			return (1);
		}
	}

	return (0);
}

/*
 * Determine if the input OID list contains LDAP V3 password less
 * account management control OID, which is:
 * NS_LDAP_ACCOUNT_USABLE_CONTROL:1.3.6.1.4.1.42.2.27.9.5.8
 * If yes, return 1, if no, 0.
 */
int
__s_api_contain_account_usable_control_oid(char **oids)
{
	char **oid;

	if (oids == NULL)
		return (0);

	for (oid = oids; *oid; oid++) {
		if (strcmp(*oid, NS_LDAP_ACCOUNT_USABLE_CONTROL) == 0) {
			return (1);
		}
	}

	return (0);
}

/*
 * For some databases in name switch, the name and aliases are saved
 * as "cn". When the "cn" valuse are retrieved, there is no distinction
 * which is  the name and which is(are) aliase(s).
 * This function is to parse RDN and find the value of the "cn" and
 * then find the matching value in "cn" attribute.
 * Also see RFC 2307 section 5.6.
 *
 * Input -
 *  entry:	An LDAP entry
 *  attrptr:	A attribute which value appears in RDN
 *		This should be "cn" for the name switch for now.
 *  case_ignore:    0 Case sensitive comparison on the attribute value
 *		    1 Case insensitive comparison
 *
 * Return -
 *		The value of an attrbute which is used as canonical name
 *		This is read only and the caller should not try to free it.
 *		If it's a NULL, it could be either an RDN parsing error
 *		or RDN value does not match any existing "cn" values.
 *		e.g.
 *		dn: cn=xx+ipserviceprotocol=udp,......
 *		cn: aa
 *		cn: bb
 *
 * Note:
 *  Although the name switch/ldap's  rdn is in "cn=xx" or "cn=xx+..."
 * format, this function makes no such assumption. If the DN
 * is saved as "dn: yy=...+sn=my_canocical_name, ..", then it can still work.
 * The comments use "cn" as an example only.
 *
 */
typedef int (*cmpfunc)(const char *, const char *);

char *
__s_api_get_canonical_name(ns_ldap_entry_t *entry, ns_ldap_attr_t *attrptr,
			int case_ignore) {
	uint_t			i;
	char			*token, *lasts, *value = NULL;
	char			**rdn = NULL, **attrs = NULL, **values = NULL;
	char			*rdn_attr_value = NULL;
	cmpfunc			cmp;

	if (entry == NULL || attrptr == NULL)
		return (NULL);

	/* "values" is read-only */
	if ((values = __ns_ldap_getAttr(entry, "dn")) == NULL ||
	    values[0] == NULL)
		return (NULL);

	if ((rdn = ldap_explode_dn(values[0], 0)) == NULL ||
	    rdn[0] == NULL)
		return (NULL);

	if ((attrs = ldap_explode_rdn(rdn[0], 0)) == NULL) {
		ldap_value_free(rdn);
		return (NULL);
	}
	/* Assume the rdn is normalized */
	for (i = 0; attrs[i] != NULL; i++) {
		/* parse attribute name and value, get attribute name first */
		if ((token = strtok_r(attrs[i], "=", &lasts)) == NULL) {
			goto cleanup;
		}
		if (strcasecmp(token, attrptr->attrname) == 0) {
			/* get value */
			rdn_attr_value = lasts;
			break;
		}
	}
	if (rdn_attr_value) {
		if (case_ignore)
			cmp = strcasecmp;
		else
			cmp = strcmp;
		/*
		 * After parsing RDN and find the matching attribute in RDN,
		 * match rdn value with values in "cn".
		 */
		for (i = 0; i < attrptr->value_count; i++) {
			if (attrptr->attrvalue[i] &&
			    (*cmp)(rdn_attr_value,
			    attrptr->attrvalue[i]) == 0) {
				/* RDN "cn" value matches the "cn" value */
				value = attrptr->attrvalue[i];
				break;
			}
		}
	}
cleanup:
	ldap_value_free(rdn);
	ldap_value_free(attrs);

	return (value);
}

/*
 * This function requests a server to be removed from
 * the cache manager maintained server list. This is
 * done via the door functionality.
 * Returns 0 if OK, else a negative value.
 */

int
__s_api_removeServer(const char *server)
{
	union {
		ldap_data_t	s_d;
		char		s_b[DOORBUFFERSIZE];
	} space;

	ns_server_info_t		r, *ret = &r;
	const char		*ireq;
	ldap_data_t		*sptr;
	int			ndata;
	int			adata;
	int			len;
	int			rc;
	ns_ldap_error_t		*error = NULL;

	if (server == NULL)
		return (-1);

	ireq = NS_CACHE_NORESP;

	if (__s_api_isStandalone()) {
		/*
		 * Remove 'server' from the standalone server list.
		 * __s_api_findRootDSE() is the standalone version
		 * of getldap_get_serverInfo() used in ldap_cachemgr.
		 * Request NS_CACHE_NORESP indicates 'server' should
		 * be removed.
		 */
		if (__s_api_findRootDSE(ireq,
		    server,
		    NS_CACHE_ADDR_IP,
		    NULL,
		    &error) != NS_LDAP_SUCCESS) {
			syslog(LOG_WARNING,
			    "libsldap (\"standalone\" mode): "
			    " Unable to remove %s - %s",
			    server,
			    error != NULL && error->message != NULL ?
			    error->message : " no error info");
			if (error != NULL) {
				(void) __ns_ldap_freeError(&error);
			}

			return (-1);
		}

		return (0);
	}

	(void) memset(ret, 0, sizeof (ns_server_info_t));
	(void) memset(space.s_b, 0, DOORBUFFERSIZE);

	adata = (sizeof (ldap_call_t) + strlen(ireq) +
	    strlen(NS_CACHE_ADDR_IP) + 1);
	adata += strlen(DOORLINESEP) + 1;
	adata += strlen(server) + 1;

	ndata = sizeof (space);
	space.s_d.ldap_call.ldap_callnumber = GETLDAPSERVER;
	len = sizeof (space) - sizeof (space.s_d.ldap_call.ldap_callnumber);
	if (strlcpy(space.s_d.ldap_call.ldap_u.domainname, ireq, len) >= len)
		return (-1);
	if (strlcat(space.s_d.ldap_call.ldap_u.domainname,
	    NS_CACHE_ADDR_IP, len) >= len)
		return (-1);
	if (strlcat(space.s_d.ldap_call.ldap_u.domainname, DOORLINESEP, len) >=
	    len)
		return (-1);
	if (strlcat(space.s_d.ldap_call.ldap_u.domainname, server, len) >= len)
		return (-1);
	sptr = &space.s_d;

	/* try to remove the server via the door interface */
	rc = __ns_ldap_trydoorcall(&sptr, &ndata, &adata);

	/* clean up the door call */
	if (sptr != &space.s_d) {
		(void) munmap((char *)sptr, ndata);
	}

	return (rc);
}

void
__s_api_free_server_info(ns_server_info_t *sinfo) {
	if (sinfo->server) {
		free(sinfo->server);
		sinfo->server = NULL;
	}
	if (sinfo->serverFQDN) {
		free(sinfo->serverFQDN);
		sinfo->serverFQDN = NULL;
	}
	__s_api_free2dArray(sinfo->saslMechanisms);
	sinfo->saslMechanisms = NULL;
	__s_api_free2dArray(sinfo->controls);
	sinfo->controls = NULL;
}

/*
 * Create an ns_ldap_error structure, set status to 'rc',
 * and copy in the error message 'msg'.
 */
ns_ldap_error_t *
__s_api_make_error(int rc, char *msg) {
	ns_ldap_error_t *ep;

	ep = (ns_ldap_error_t *)calloc(1, sizeof (*ep));
	if (ep == NULL)
		return (NULL);

	ep->status = rc;
	if (msg != NULL)
		ep->message =  strdup(msg); /* OK if ep->message is NULL */

	return (ep);
}

/*
 * Make a copy of the input ns_ldap_error.
 */
ns_ldap_error_t *
__s_api_copy_error(ns_ldap_error_t *errorp) {
	ns_ldap_error_t *ep;
	char		*msg;

	if (errorp == NULL)
		return (NULL);

	ep = (ns_ldap_error_t *)malloc(sizeof (*ep));
	if (ep != NULL) {
		*ep = *errorp;
		if (ep->message != NULL) {
			msg = strdup(ep->message);
			if (msg == NULL) {
				free(ep);
				ep = NULL;
			} else
				ep->message = msg;
		}
	}
	return (ep);
}
