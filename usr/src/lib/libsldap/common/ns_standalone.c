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
 * Copyright 2012 Milan Jurik. All rights reserved.
 * Copyright 2012 Nexenta Systems, Inc. All rights reserved.
 */

#define	__STANDALONE_MODULE__

#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <libintl.h>
#include <string.h>
#include <ctype.h>

#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <syslog.h>
#include <locale.h>
#include <errno.h>
#include <sys/time.h>

#include <arpa/inet.h>
#include <netdb.h>
#include <strings.h>

#include <thread.h>

#include <nsswitch.h>
#include <nss_dbdefs.h>
#include <nss.h>

#include "ns_cache_door.h"
#include "ns_internal.h"
#include "ns_connmgmt.h"

typedef enum {
	INFO_SERVER_JUST_INITED	= -1,
	INFO_SERVER_UNKNOWN	= 0,
	INFO_SERVER_CONNECTING	= 1,
	INFO_SERVER_UP		= 2,
	INFO_SERVER_ERROR 	= 3,
	INFO_SERVER_REMOVED	= 4
} dir_server_status_t;

typedef enum {
	INFO_STATUS_NEW   	= 2,
	INFO_STATUS_OLD		= 3
} dir_server_info_t;

typedef struct dir_server {
	char			*ip;
	char			**controls;
	char			**saslMech;
	dir_server_status_t	status;
	mutex_t			updateStatus;
	dir_server_info_t	info;
} dir_server_t;

typedef struct dir_server_list {
	dir_server_t	**nsServers;

	rwlock_t	listDestroyLock;
} dir_server_list_t;

struct {
	/* The local list of the directory servers' root DSEs. */
	dir_server_list_t	*list;
	/* The flag indicating if libsldap is in the 'Standalone' mode. */
	int			standalone;
	/*
	 * The mutex ensuring that only one thread performs
	 * the initialization of the list.
	 */
	mutex_t			listReplaceLock;
	/*
	 * A flag indicating that a particular thread is
	 * in the 'ldap_cachemgr' mode. It is stored by thread as
	 * a thread specific data.
	 */
	const int		initFlag;
	/*
	 * A thread specific key storing
	 * the the 'ldap_cachemgr' mode indicator.
	 */
	thread_key_t		standaloneInitKey;
} dir_servers = {NULL, 0, DEFAULTMUTEX, '1'};

typedef struct switchDatabase {
	char *conf;
	uint32_t alloced;
} switch_database_t;

static thread_key_t switchConfigKey;

#pragma init(createStandaloneKey)

#define	DONT_INCLUDE_ATTR_NAMES	0
#define	INCLUDE_ATTR_NAMES	1
#define	IS_PROFILE		1
#define	NOT_PROFILE		0
/* INET6_ADDRSTRLEN + ":" + <5-digit port> + some round-up */
#define	MAX_HOSTADDR_LEN (INET6_ADDRSTRLEN + 6 + 12)

static
void
switch_conf_disposer(void *data)
{
	switch_database_t *localData = (switch_database_t *)data;

	free(localData->conf);
	free(localData);
}

/*
 * This function initializes an indication that a thread obtaining a root DSE
 * will be switched to the 'ldap_cachemgr' mode. Within the thread libsldap
 * will not invoke the __s_api_requestServer function. Instead, the library
 * will establish a connection to the server specified by
 * the __ns_ldap_getRootDSE function.
 * Since  ldap_cachmgr can obtain a DUAProfile and root DSEs at the same time
 * and we do not want to affect a thread obtaining a DUAProfile,
 * the 'ldap_cachemgr' mode is thread private.
 * In addition, this function creates a key holding temporary configuration
 * for the "hosts" and "ipnodes" databases which is used by the "SKIPDB"
 * mechanism (__s_api_ip2hostname() & _s_api_hostname2ip()).
 */
static
void
createStandaloneKey()
{
	if (thr_keycreate(&dir_servers.standaloneInitKey, NULL) != 0) {
		syslog(LOG_ERR, gettext("libsldap: unable to create a thread "
		"key needed for sharing ldap connections"));
	}
	if (thr_keycreate(&switchConfigKey, switch_conf_disposer) != 0) {
		syslog(LOG_ERR, gettext("libsldap: unable to create a thread "
		    "key containing current nsswitch configuration"));
	}
}

/*
 * This function sets the 'ldap_cachemgr' mode indication.
 */
void
__s_api_setInitMode()
{
	(void) thr_setspecific(dir_servers.standaloneInitKey,
	    (void *) &dir_servers.initFlag);
}

/*
 * This function unset the 'ldap_cachemgr' mode indication.
 */
void
__s_api_unsetInitMode()
{
	(void) thr_setspecific(dir_servers.standaloneInitKey, NULL);
}

/*
 * This function checks if the 'ldap_cachemgr' mode indication is set.
 */
int
__s_api_isInitializing() {
	int *flag = NULL;

	(void) thr_getspecific(dir_servers.standaloneInitKey, (void **) &flag);

	return (flag != NULL && *flag == dir_servers.initFlag);
}

/*
 * This function checks if the process runs in the 'Standalone' mode.
 * In this mode libsldap will check the local, process private list of root DSEs
 * instead of requesting them via a door call to ldap_cachemgr.
 */
int
__s_api_isStandalone()
{
	int	mode;

	(void) mutex_lock(&dir_servers.listReplaceLock);
	mode = dir_servers.standalone;
	(void) mutex_unlock(&dir_servers.listReplaceLock);

	return (mode);
}


static
int
remove_ldap(char *dst, char *src, int dst_buf_len)
{
	int i = 0;

	if (strlen(src) >= dst_buf_len)
		return (0);

	while (*src != '\0') {
		/* Copy up to one space from source. */
		if (isspace(*src)) {
			dst[i++] = *src;
			while (isspace(*src))
				src++;
		}

		/* If not "ldap", just copy. */
		if (strncmp(src, "ldap", 4) != 0) {
			while (!isspace(*src)) {
				dst[i++] = *src++;
				/* At the end of string? */
				if (dst[i-1] == '\0')
					return (1);
			}
			/* Copy up to one space from source. */
			if (isspace(*src)) {
				dst[i++] = *src;
				while (isspace(*src))
					src++;
			}
			/* Copy also the criteria section */
			if (*src == '[')
				while (*src != ']') {
					dst[i++] = *src++;
					/* Shouln't happen if format is right */
					if (dst[i-1] == '\0')
						return (1);
				}
		}

		/* If next part is ldap, skip over it ... */
		if (strncmp(src, "ldap", 4) == 0) {
			if (isspace(*(src+4)) || *(src+4) == '\0') {
				src += 4;
				while (isspace(*src))
					src++;
				if (*src == '[') {
					while (*src++ != ']') {
						/*
						 * See comment above about
						 * correct format.
						 */
						if (*src == '\0') {
							dst[i++] = '\0';
							return (1);
						}
					}
				}
				while (isspace(*src))
					src++;
			}
		}
		if (*src == '\0')
			dst[i++] = '\0';
	}

	return (1);
}

static
char *
get_db(const char *db_name)
{
	char			*ptr;
	switch_database_t	*hostService = NULL;
	FILE			*fp = fopen(__NSW_CONFIG_FILE, "rF");
	char			*linep, line[NSS_BUFSIZ];

	if (fp == NULL) {
		syslog(LOG_WARNING, gettext("libsldap: can not read %s"),
		    __NSW_CONFIG_FILE);
		return (NULL);
	}

	while ((linep = fgets(line, NSS_BUFSIZ, fp)) != NULL) {
		while (isspace(*linep)) {
			++linep;
		}
		if (*linep == '#') {
			continue;
		}
		if (strncmp(linep, db_name, strlen(db_name)) != 0) {
			continue;
		}
		if ((linep = strchr(linep, ':')) != NULL) {
			if (linep[strlen(linep) - 1] == '\n') {
				linep[strlen(linep) - 1] = '\0';
			}

			while (isspace(*++linep))
				;

			if ((ptr = strchr(linep, '#')) != NULL) {
				while (--ptr >= linep && isspace(*ptr))
					;
				*(ptr + 1) = '\0';
			}

			if (strlen(linep) == 0) {
				continue;
			}
			break;
		}
	}

	(void) fclose(fp);

	if (linep == NULL) {
		syslog(LOG_WARNING,
		    gettext("libsldap: the %s database "
		    "is missing from %s"),
		    db_name,
		    __NSW_CONFIG_FILE);
		return (NULL);
	}

	(void) thr_getspecific(switchConfigKey, (void **) &hostService);
	if (hostService == NULL) {
		hostService = calloc(1, sizeof (switch_database_t));
		if (hostService == NULL) {
			return (NULL);
		}
		(void) thr_setspecific(switchConfigKey, hostService);
	}

	/*
	 * In a long-living process threads can perform several
	 * getXbyY requests. And the windows between those requests
	 * can be long. The nsswitch configuration can change from time
	 * to time. So instead of allocating/freeing memory every time
	 * the API is called, reallocate memory only when the current
	 * configuration for the database being used is longer than
	 * the previous one.
	 */
	if (strlen(linep) >= hostService->alloced) {
		ptr = (char *)realloc((void *)hostService->conf,
		    strlen(linep) + 1);
		if (ptr == NULL) {
			free((void *)hostService->conf);
			hostService->conf = NULL;
			hostService->alloced = 0;
			return (NULL);
		}
		bzero(ptr, strlen(linep) + 1);
		hostService->conf = ptr;
		hostService->alloced = strlen(linep) + 1;
	}

	if (remove_ldap(hostService->conf, linep, hostService->alloced))
		return (hostService->conf);
	else
		return (NULL);
}

static
void
_initf_ipnodes(nss_db_params_t *p)
{
	char *services = get_db("ipnodes");

	p->name = NSS_DBNAM_IPNODES;
	p->flags |= NSS_USE_DEFAULT_CONFIG;
	p->default_config = services == NULL ? "" : services;
}

static
void
_initf_hosts(nss_db_params_t *p)
{
	char *services = get_db("hosts");

	p->name = NSS_DBNAM_HOSTS;
	p->flags |= NSS_USE_DEFAULT_CONFIG;
	p->default_config = services == NULL ? "" : services;
}

/*
 * This function is an analog of the standard gethostbyaddr_r()
 * function with an exception that it removes the 'ldap' back-end
 * (if any) from the host/ipnodes nsswitch's databases and then
 * looks up using remaining back-ends.
 */
static
struct hostent *
_filter_gethostbyaddr_r(const char *addr, int len, int type,
	struct hostent *result, char *buffer, int buflen,
	int *h_errnop)
{
	DEFINE_NSS_DB_ROOT(db_root_hosts);
	DEFINE_NSS_DB_ROOT(db_root_ipnodes);
	nss_XbyY_args_t arg;
	nss_status_t    res;
	int		(*str2ent)();
	void		(*nss_initf)();
	nss_db_root_t	*nss_db_root;
	int		dbop;

	switch (type) {
	case AF_INET:
		str2ent		= str2hostent;
		nss_initf	= _initf_hosts;
		nss_db_root	= &db_root_hosts;
		dbop		= NSS_DBOP_HOSTS_BYADDR;
		break;
	case AF_INET6:
		str2ent		= str2hostent6;
		nss_initf	= _initf_ipnodes;
		nss_db_root	= &db_root_ipnodes;
		dbop		= NSS_DBOP_IPNODES_BYADDR;
		break;
	default:
		return (NULL);
	}

	NSS_XbyY_INIT(&arg, result, buffer, buflen, str2ent);

	arg.key.hostaddr.addr	= addr;
	arg.key.hostaddr.len	= len;
	arg.key.hostaddr.type	= type;
	arg.stayopen		= 0;
	arg.h_errno		= NETDB_SUCCESS;

	res = nss_search(nss_db_root, nss_initf, dbop, &arg);
	arg.status = res;
	*h_errnop = arg.h_errno;
	return (struct hostent *)NSS_XbyY_FINI(&arg);
}

/*
 * This routine is an analog of gethostbyaddr_r().
 * But in addition __s_api_hostname2ip() performs the "LDAP SKIPDB" activity
 * prior to querying the name services.
 * If the buffer is not big enough to accommodate a returning data,
 * NULL is returned and h_errnop is set to TRY_AGAIN.
 */
struct hostent *
__s_api_hostname2ip(const char *name,
	struct hostent *result, char *buffer, int buflen,
	int *h_errnop)
{
	DEFINE_NSS_DB_ROOT(db_root_ipnodes);
	DEFINE_NSS_DB_ROOT(db_root_hosts);
	nss_XbyY_args_t	arg;
	nss_status_t	res;
	struct in_addr	addr;
	struct in6_addr	addr6;

	if (inet_pton(AF_INET, name, &addr) > 0) {
		if (buflen < strlen(name) + 1 +
		    sizeof (char *) * 2 + /* The h_aliases member */
		    sizeof (struct in_addr) +
		    sizeof (struct in_addr *) * 2) {
			*h_errnop = TRY_AGAIN;
			return (NULL);
		}

		result->h_addrtype = AF_INET;
		result->h_length = sizeof (struct in_addr);
		(void) strncpy(buffer, name, buflen);

		result->h_addr_list = (char **)ROUND_UP(
		    buffer + strlen(name) + 1,
		    sizeof (char *));
		result->h_aliases = (char **)ROUND_UP(result->h_addr_list,
		    sizeof (char *));
		result->h_aliases[0] = buffer;
		result->h_aliases[1] = NULL;
		bcopy(&addr,
		    buffer + buflen - sizeof (struct in_addr),
		    sizeof (struct in_addr));
		result->h_addr_list[0] = buffer + buflen -
		    sizeof (struct in_addr);
		result->h_addr_list[1] = NULL;
		result->h_aliases = result->h_addr_list;
		result->h_name = buffer;

		*h_errnop = NETDB_SUCCESS;
		return (result);
	}
	if (inet_pton(AF_INET6, name, &addr6) > 0) {
		if (buflen < strlen(name) + 1 +
		    sizeof (char *) * 2 + /* The h_aliases member */
		    sizeof (struct in6_addr) +
		    sizeof (struct in6_addr *) * 2) {
			*h_errnop = TRY_AGAIN;
			return (NULL);
		}

		result->h_addrtype = AF_INET6;
		result->h_length = sizeof (struct in6_addr);
		(void) strncpy(buffer, name, buflen);

		result->h_addr_list = (char **)ROUND_UP(
		    buffer + strlen(name) + 1,
		    sizeof (char *));
		result->h_aliases = (char **)ROUND_UP(result->h_addr_list,
		    sizeof (char *));
		result->h_aliases[0] = buffer;
		result->h_aliases[1] = NULL;
		bcopy(&addr6,
		    buffer + buflen - sizeof (struct in6_addr),
		    sizeof (struct in6_addr));
		result->h_addr_list[0] = buffer + buflen -
		    sizeof (struct in6_addr);
		result->h_addr_list[1] = NULL;
		result->h_aliases = result->h_addr_list;
		result->h_name = buffer;

		*h_errnop = NETDB_SUCCESS;
		return (result);
	}

	NSS_XbyY_INIT(&arg, result, buffer, buflen, str2hostent);

	arg.key.name = name;
	arg.stayopen = 0;
	arg.h_errno = NETDB_SUCCESS;

	res = nss_search(&db_root_ipnodes, _initf_ipnodes,
	    NSS_DBOP_IPNODES_BYNAME, &arg);
	if (res == NSS_NOTFOUND || res == NSS_UNAVAIL) {
		arg.h_errno = NETDB_SUCCESS;
		res = nss_search(&db_root_hosts, _initf_hosts,
		    NSS_DBOP_HOSTS_BYNAME, &arg);
	}
	arg.status = res;
	*h_errnop = arg.h_errno;
	return ((struct hostent *)NSS_XbyY_FINI(&arg));
}

/*
 * Convert an IP to a host name.
 */
ns_ldap_return_code
__s_api_ip2hostname(char *ipaddr, char **hostname) {
	struct in_addr	in;
	struct in6_addr	in6;
	struct hostent	*hp = NULL, hostEnt;
	char		buffer[NSS_BUFLEN_HOSTS];
	int		buflen = NSS_BUFLEN_HOSTS;
	char		*start = NULL,
			*end = NULL,
			delim = '\0';
	char		*port = NULL,
			*addr = NULL;
	int		errorNum = 0,
			len = 0;

	if (ipaddr == NULL || hostname == NULL)
		return (NS_LDAP_INVALID_PARAM);
	*hostname = NULL;
	if ((addr = strdup(ipaddr)) == NULL)
		return (NS_LDAP_MEMORY);

	if (addr[0] == '[') {
		/*
		 * Assume it's [ipv6]:port
		 * Extract ipv6 IP
		 */
		start = &addr[1];
		if ((end = strchr(addr, ']')) != NULL) {
			*end = '\0';
			delim = ']';
			if (*(end + 1) == ':')
				/* extract port */
				port = end + 2;
		} else {
			free(addr);
			return (NS_LDAP_INVALID_PARAM);
		}
	} else if ((end = strchr(addr, ':')) != NULL) {
		/* assume it's ipv4:port */
		*end = '\0';
		delim = ':';
		start = addr;
		port = end + 1;
	} else
		/* No port */
		start = addr;


	if (inet_pton(AF_INET, start, &in) == 1) {
		/* IPv4 */
		hp = _filter_gethostbyaddr_r((char *)&in,
		    sizeof (in.s_addr),
		    AF_INET,
		    &hostEnt,
		    buffer,
		    buflen,
		    &errorNum);
		if (hp && hp->h_name) {
			/* hostname + '\0' */
			len = strlen(hp->h_name) + 1;
			if (port)
				/* ':' + port */
				len += strlen(port) + 1;
			if ((*hostname = malloc(len)) == NULL) {
				free(addr);
				return (NS_LDAP_MEMORY);
			}

			if (port)
				(void) snprintf(*hostname, len, "%s:%s",
						hp->h_name, port);
			else
				(void) strlcpy(*hostname, hp->h_name, len);

			free(addr);
			return (NS_LDAP_SUCCESS);
		} else {
			free(addr);
			return (NS_LDAP_NOTFOUND);
		}
	} else if (inet_pton(AF_INET6, start, &in6) == 1) {
		/* IPv6 */
		hp = _filter_gethostbyaddr_r((char *)&in6,
		    sizeof (in6.s6_addr),
		    AF_INET6,
		    &hostEnt,
		    buffer,
		    buflen,
		    &errorNum);
		if (hp && hp->h_name) {
			/* hostname + '\0' */
			len = strlen(hp->h_name) + 1;
			if (port)
				/* ':' + port */
				len += strlen(port) + 1;
			if ((*hostname = malloc(len)) == NULL) {
				free(addr);
				return (NS_LDAP_MEMORY);
			}

			if (port)
				(void) snprintf(*hostname, len, "%s:%s",
						hp->h_name, port);
			else
				(void) strlcpy(*hostname, hp->h_name, len);

			free(addr);
			return (NS_LDAP_SUCCESS);
		} else {
			free(addr);
			return (NS_LDAP_NOTFOUND);
		}
	} else {
		/*
		 * A hostname
		 * Return it as is
		 */
		if (end)
			*end = delim;
		*hostname = addr;
		return (NS_LDAP_SUCCESS);
	}
}

/*
 * This function obtains data returned by an LDAP search request and puts it
 * in a string in the ldap_cachmgr(1) door call format.
 *
 * INPUT:
 *     ld - a pointer to an LDAP structure used for a search operation,
 *     result_msg - a pointer to an LDAPMessage returned by the search,
 *     include_names - if set to INCLUDE_ATTR_NAMES, the output buffer will
 *                     contain attribute names.
 *                     Otherwise, only values will be return.
 *
 * OUTPUT:
 *      a buffer containing server info in the following format:
 *         [<attribute name>=]value [DOORLINESEP [<attribute name>=]value ]...]
 *      Should be free'ed by the caller.
 */
static
ns_ldap_return_code
convert_to_door_line(LDAP* ld,
		LDAPMessage *result_msg,
		int include_names,
		int is_profile,
		char **door_line)
{
	uint32_t	total_length = 0, attr_len = 0, i;
	LDAPMessage	*e;
	char		*a, **vals;
	BerElement	*ber;
	int		seen_objectclass = 0, rewind = 0;

	if (!door_line) {
		return (NS_LDAP_INVALID_PARAM);
	}
	*door_line = NULL;

	if ((e = ldap_first_entry(ld, result_msg)) == NULL) {
		return (NS_LDAP_NOTFOUND);
	}

	/* calculate length of received data */
	for (a = ldap_first_attribute(ld, e, &ber);
	    a != NULL;
	    a = ldap_next_attribute(ld, e, ber)) {

		if ((vals = ldap_get_values(ld, e, a)) != NULL) {
			for (i = 0; vals[i] != NULL; i++) {
				total_length += (include_names ?
				    strlen(a) : 0) +
				    strlen(vals[i]) +
				    strlen(DOORLINESEP) +1;
			}
			ldap_value_free(vals);
		}
		ldap_memfree(a);
	}
	if (ber != NULL) {
		ber_free(ber, 0);
	}

	if (total_length == 0) {
		return (NS_LDAP_NOTFOUND);
	}

	/* copy the data */
	/* add 1 for the last '\0' */
	*door_line  = (char *)malloc(total_length + 1);
	if (*door_line == NULL) {
		return (NS_LDAP_MEMORY);
	}

	/* make it an empty string first */
	**door_line = '\0';
	a = ldap_first_attribute(ld, e, &ber);
	while (a != NULL) {
		if (is_profile) {
			/*
			 * If we're processing DUAConfigProfile, we need to make
			 * sure we put objectclass attribute first.
			 * __s_api_create_config_door_str depends on that.
			 */
			if (seen_objectclass) {
				if (strcasecmp(a, "objectclass") == 0) {
					/* Skip objectclass now. */
					a = ldap_next_attribute(ld, e, ber);
					continue;
				}
			} else {
				if (strcasecmp(a, "objectclass") == 0) {
					seen_objectclass = 1;
					rewind = 1;
				} else {
					/* Skip all but objectclass first. */
					a = ldap_next_attribute(ld, e, ber);
					continue;
				}
			}
		}

		if ((vals = ldap_get_values(ld, e, a)) != NULL) {
			for (i = 0; vals[i] != NULL; i++) {
				if (include_names) {
					attr_len += strlen(a);
				}
				attr_len += strlen(vals[i]) +
				    strlen(DOORLINESEP) + 2;
				if (include_names) {
					(void) snprintf(*door_line +
					    strlen(*door_line),
					    attr_len,
					    "%s=%s%s",
					    a, vals[i],
					    DOORLINESEP);
				} else {
					(void) snprintf(*door_line +
					    strlen(*door_line),
					    attr_len,
					    "%s%s",
					    vals[i],
					    DOORLINESEP);
				}
			}
			ldap_value_free(vals);
		}
		ldap_memfree(a);

		/* Rewind */
		if (rewind) {
			if (ber != NULL) {
				ber_free(ber, 0);
			}
			a = ldap_first_attribute(ld, e, &ber);
			rewind = 0;
		} else {
			a = ldap_next_attribute(ld, e, ber);
		}
	}
	if (ber != NULL) {
		ber_free(ber, 0);
	}

	if (e != result_msg) {
		(void) ldap_msgfree(e);
	}

	return (NS_LDAP_SUCCESS);
}

/*
 * This function looks up the base DN of a directory serving
 * a specified domain name.
 *
 * INPUT:
 *     ld - a pointer to an LDAP structure used for the search operation,
 *     domain_name - the name of a domain.
 *
 * OUTPUT:
 *     a buffer containing a directory's base DN found.
 *     Should be free'ed by the caller.
 */
static
ns_ldap_return_code
getDirBaseDN(LDAP *ld, const char *domain_name, char **dir_base_dn)
{
	struct timeval		tv = {NS_DEFAULT_SEARCH_TIMEOUT, 0};
	char			*attrs[2], *DNlist, *rest, *ptr;
	char			filter[BUFSIZ], *a = NULL;
	int			ldap_rc;
	LDAPMessage		*resultMsg = NULL;
	ns_ldap_return_code	ret_code;

	/* Get the whole list of naming contexts residing on the server */
	attrs[0] = "namingcontexts";
	attrs[1] = NULL;
	ldap_rc = ldap_search_ext_s(ld, "", LDAP_SCOPE_BASE, "(objectclass=*)",
	    attrs, 0, NULL, NULL, &tv, 0, &resultMsg);
	switch (ldap_rc) {
		/* If successful, the root DSE was found. */
		case LDAP_SUCCESS:
			break;
		/*
		 * If the root DSE was not found, the server does
		 * not comply with the LDAP v3 protocol.
		 */
		default:
			if (resultMsg) {
				(void) ldap_msgfree(resultMsg);
				resultMsg = NULL;
			}

			return (NS_LDAP_OP_FAILED);
	}

	if ((ret_code = convert_to_door_line(ld,
	    resultMsg,
	    DONT_INCLUDE_ATTR_NAMES,
	    NOT_PROFILE,
	    &DNlist)) != NS_LDAP_SUCCESS) {
		if (resultMsg) {
			(void) ldap_msgfree(resultMsg);
			resultMsg = NULL;
		}
		return (ret_code);
	}

	if (resultMsg) {
		(void) ldap_msgfree(resultMsg);
		resultMsg = NULL;
	}

	if (DNlist == NULL ||
	    (ptr = strtok_r(DNlist, DOORLINESEP, &rest)) == NULL) {
		return (NS_LDAP_NOTFOUND);
	}
	attrs[0] = "dn";
	do {
		/*
		 * For each context try to find a NIS domain object
		 * which 'nisdomain' attribute's value matches the domain name
		 */
		(void) snprintf(filter,
		    BUFSIZ,
		    "(&(objectclass=nisDomainObject)"
		    "(nisdomain=%s))",
		    domain_name);
		ldap_rc = ldap_search_ext_s(ld,
		    ptr,
		    LDAP_SCOPE_SUBTREE,
		    filter,
		    attrs,
		    0,
		    NULL,
		    NULL,
		    &tv,
		    0,
		    &resultMsg);
		if (ldap_rc != LDAP_SUCCESS) {
			if (resultMsg) {
				(void) ldap_msgfree(resultMsg);
				resultMsg = NULL;
			}
			continue;
		}
		if ((a = ldap_get_dn(ld, resultMsg)) != NULL) {
			*dir_base_dn = strdup(a);
			ldap_memfree(a);

			if (resultMsg) {
				(void) ldap_msgfree(resultMsg);
				resultMsg = NULL;
			}

			if (!*dir_base_dn) {
				free(DNlist);
				return (NS_LDAP_MEMORY);
			}
			break;
		}

		if (resultMsg) {
			(void) ldap_msgfree(resultMsg);
			resultMsg = NULL;
		}
	} while (ptr = strtok_r(NULL, DOORLINESEP, &rest));

	free(DNlist);

	if (!*dir_base_dn) {
		return (NS_LDAP_NOTFOUND);
	}

	return (NS_LDAP_SUCCESS);
}

/*
 * This function parses the results of a search operation
 * requesting a DUAProfile.
 *
 * INPUT:
 *     ld - a pointer to an LDAP structure used for the search operation,
 *     dir_base_dn - the name of a directory's base DN,
 *     profile_name - the name of a DUAProfile to be obtained.
 *
 * OUTPUT:
 *      a buffer containing the DUAProfile in the following format:
 *        [<attribute name>=]value [DOORLINESEP [<attribute name>=]value ]...]
 *      Should be free'ed by the caller.
 */
static
ns_ldap_return_code
getDUAProfile(LDAP *ld,
		const char *dir_base_dn,
		const char *profile_name,
		char **profile)
{
	char			searchBaseDN[BUFSIZ], filter[BUFSIZ];
	LDAPMessage		*resultMsg = NULL;
	struct timeval		tv = {NS_DEFAULT_SEARCH_TIMEOUT, 0};
	int			ldap_rc;
	ns_ldap_return_code	ret_code;

	(void) snprintf(searchBaseDN, BUFSIZ, "ou=profile,%s", dir_base_dn);
	(void) snprintf(filter,
	    BUFSIZ,
	    _PROFILE_FILTER,
	    _PROFILE1_OBJECTCLASS,
	    _PROFILE2_OBJECTCLASS,
	    profile_name);
	ldap_rc = ldap_search_ext_s(ld,
	    searchBaseDN,
	    LDAP_SCOPE_SUBTREE,
	    filter,
	    NULL,
	    0,
	    NULL,
	    NULL,
	    &tv,
	    0,
	    &resultMsg);

	switch (ldap_rc) {
		/* If successful, the DUA profile was found. */
		case LDAP_SUCCESS:
			break;
		/*
		 * If the root DSE was not found, the server does
		 * not comply with the LDAP v3 protocol.
		 */
		default:
			if (resultMsg) {
				(void) ldap_msgfree(resultMsg);
				resultMsg = NULL;
			}

			return (NS_LDAP_OP_FAILED);
	}

	ret_code = convert_to_door_line(ld,
	    resultMsg,
	    INCLUDE_ATTR_NAMES,
	    IS_PROFILE,
	    profile);
	if (resultMsg) {
		(void) ldap_msgfree(resultMsg);
		resultMsg = NULL;
	}
	return (ret_code);
}

/*
 * This function derives the directory's base DN from a provided domain name.
 *
 * INPUT:
 *     domain_name - the name of a domain to be converted into a base DN,
 *     buffer - contains the derived base DN,
 *     buf_len - the length of the buffer.
 *
 * OUTPUT:
 *     The function returns the address of the buffer or NULL.
 */
static
char *
domainname2baseDN(char *domain_name, char *buffer, uint16_t buf_len)
{
	char		*nextDC, *chr;
	uint16_t	i, length;

	if (!domain_name || !buffer || buf_len == 0) {
		return (NULL);
	}

	buffer[0] = '\0';
	nextDC = chr = domain_name;
	length = strlen(domain_name);
	for (i = 0; i < length + 1; ++i, ++chr) {
		/* Simply replace dots with "dc=" */
		if (*chr != '.' && *chr != '\0') {
			continue;
		}
		*chr = '\0';
		if (strlcat(buffer, "dc=", buf_len) >= buf_len)
			return (NULL);
		if (strlcat(buffer, nextDC, buf_len) >= buf_len)
			return (NULL);
		if (i < length) {
			/*
			 * The end of the domain name
			 * has not been reached yet
			 */
			if (strlcat(buffer, ",", buf_len) >= buf_len)
				return (NULL);
			nextDC = chr + 1;
			*chr = '.';
		}
	}

	return (buffer);
}

/*
 * This function obtains the directory's base DN and a DUAProfile
 * from a specified server.
 *
 * INPUT:
 *     server - a structure describing a server to connect to and
 *              a DUAProfile to be obtained from the server,
 *     cred - credentials to be used during establishing connections to
 *            the server.
 *
 * OUTPUT:
 *     dua_profile - a buffer containing the DUAProfile in the following format:
 *        [<attribute name>=]value [DOORLINESEP [<attribute name>=]value ]...]
 *     dir_base_dn - a buffer containing the base DN,
 *     errorp - an error object describing an error, if any.
 *
 *     All the output data structures should be free'ed by the caller.
 */
ns_ldap_return_code
__ns_ldap_getConnectionInfoFromDUA(const ns_dir_server_t *server,
	const ns_cred_t *cred,
	char **dua_profile,
	char **dir_base_dn,
	ns_ldap_error_t **errorp)
{
	char			serverAddr[MAX_HOSTADDR_LEN];
	char			*dirBaseDN = NULL, *duaProfile = NULL;
	ns_cred_t		default_cred;
	ns_ldap_return_code	ret_code;

	ns_config_t		*config_struct = __s_api_create_config();
	ConnectionID		sessionId = 0;
	Connection		*session = NULL;
	char			errmsg[MAXERROR];
	char			buffer[NSS_BUFLEN_HOSTS];
	ns_conn_user_t		*cu = NULL;

	if (errorp == NULL) {
		__s_api_destroy_config(config_struct);
		return (NS_LDAP_INVALID_PARAM);
	}

	*errorp = NULL;

	if (server == NULL) {
		__s_api_destroy_config(config_struct);
		return (NS_LDAP_INVALID_PARAM);
	}

	if (config_struct == NULL) {
		return (NS_LDAP_MEMORY);
	}

	/*
	 * If no credentials are specified, try to establish a connection
	 * as anonymous.
	 */
	if (!cred) {
		default_cred.cred.unix_cred.passwd = NULL;
		default_cred.cred.unix_cred.userID = NULL;
		default_cred.auth.type = NS_LDAP_AUTH_NONE;
	}

	/* Now create a default LDAP configuration */

	(void) strncpy(buffer, server->server, sizeof (buffer));
	if (__ns_ldap_setParamValue(config_struct, NS_LDAP_SERVERS_P, buffer,
	    errorp) != NS_LDAP_SUCCESS) {
		__s_api_destroy_config(config_struct);
		return (NS_LDAP_CONFIG);
	}

	/* Put together the address and the port specified by the user app. */
	if (server->port > 0) {
		(void) snprintf(serverAddr,
		    sizeof (serverAddr),
		    "%s:%hu",
		    buffer,
		    server->port);
	} else {
		(void) strncpy(serverAddr, buffer, sizeof (serverAddr));
	}

	/*
	 * There is no default value for the 'Default Search Base DN' attribute.
	 * Derive one from the domain name to make __s_api_crosscheck() happy.
	 */
	if (domainname2baseDN(server->domainName ?
	    server->domainName : config_struct->domainName,
	    buffer, NSS_BUFLEN_HOSTS) == NULL) {
		(void) snprintf(errmsg,
		    sizeof (errmsg),
		    gettext("Can not convert %s into a base DN name"),
		    server->domainName ?
		    server->domainName : config_struct->domainName);
		MKERROR(LOG_ERR,
		    *errorp,
		    NS_LDAP_INTERNAL,
		    strdup(errmsg),
		    NS_LDAP_MEMORY);
		__s_api_destroy_config(config_struct);
		return (NS_LDAP_INTERNAL);
	}
	if (__ns_ldap_setParamValue(config_struct, NS_LDAP_SEARCH_BASEDN_P,
	    buffer, errorp) != NS_LDAP_SUCCESS) {
		__s_api_destroy_config(config_struct);
		return (NS_LDAP_CONFIG);
	}

	if (__s_api_crosscheck(config_struct, errmsg, B_FALSE) != NS_SUCCESS) {
		__s_api_destroy_config(config_struct);
		return (NS_LDAP_CONFIG);
	}

	__s_api_init_config(config_struct);

	__s_api_setInitMode();

	cu = __s_api_conn_user_init(NS_CONN_USER_SEARCH, NULL, B_FALSE);
	if (cu == NULL) {
		return (NS_LDAP_INTERNAL);
	}

	if ((ret_code = __s_api_getConnection(serverAddr,
	    NS_LDAP_NEW_CONN,
	    cred ? cred : &default_cred,
	    &sessionId,
	    &session,
	    errorp,
	    0,
	    0,
	    cu)) != NS_LDAP_SUCCESS) {
		__s_api_conn_user_free(cu);
		__s_api_unsetInitMode();
		return (ret_code);
	}

	__s_api_unsetInitMode();

	if ((ret_code = getDirBaseDN(session->ld,
	    server->domainName ?
	    server->domainName :
	    config_struct->domainName,
	    &dirBaseDN)) != NS_LDAP_SUCCESS) {
		(void) snprintf(errmsg,
		    sizeof (errmsg),
		    gettext("Can not find the "
		    "nisDomainObject for domain %s\n"),
		    server->domainName ?
		    server->domainName : config_struct->domainName);
		MKERROR(LOG_ERR,
		    *errorp,
		    ret_code,
		    strdup(errmsg),
		    NS_LDAP_MEMORY);
		__s_api_conn_user_free(cu);
		DropConnection(sessionId, NS_LDAP_NEW_CONN);
		return (ret_code);
	}

	/*
	 * And here obtain a DUAProfile which will be used
	 * as a real configuration.
	 */
	if ((ret_code = getDUAProfile(session->ld,
	    dirBaseDN,
	    server->profileName ?
	    server->profileName : "default",
	    &duaProfile)) != NS_LDAP_SUCCESS) {
		(void) snprintf(errmsg,
		    sizeof (errmsg),
		    gettext("Can not find the "
		    "%s DUAProfile\n"),
		    server->profileName ?
		    server->profileName : "default");
		MKERROR(LOG_ERR,
		    *errorp,
		    ret_code,
		    strdup(errmsg),
		    NS_LDAP_MEMORY);
		__s_api_conn_user_free(cu);
		DropConnection(sessionId, NS_LDAP_NEW_CONN);
		return (ret_code);
	}

	if (dir_base_dn) {
		*dir_base_dn = dirBaseDN;
	} else {
		free(dirBaseDN);
	}

	if (dua_profile) {
		*dua_profile = duaProfile;
	} else {
		free(duaProfile);
	}

	__s_api_conn_user_free(cu);
	DropConnection(sessionId, NS_LDAP_NEW_CONN);

	return (NS_LDAP_SUCCESS);
}

/*
 * This function obtains the root DSE from a specified server.
 *
 * INPUT:
 *     server_addr - an adress of a server to be connected to.
 *
 * OUTPUT:
 *     root_dse - a buffer containing the root DSE in the following format:
 *          [<attribute name>=]value [DOORLINESEP [<attribute name>=]value ]...]
 *        For example: ( here | used as DOORLINESEP for visual purposes)
 *          supportedControl=1.1.1.1|supportedSASLmechanisms=EXTERNAL
 *        Should be free'ed by the caller.
 */
ns_ldap_return_code
__ns_ldap_getRootDSE(const char *server_addr,
		char **root_dse,
		ns_ldap_error_t **errorp,
		int anon_fallback)
{
	char			errmsg[MAXERROR];
	ns_ldap_return_code	ret_code;

	ConnectionID		sessionId = 0;
	Connection		*session = NULL;

	struct timeval		tv = {NS_DEFAULT_SEARCH_TIMEOUT, 0};
	char			*attrs[3];
	int			ldap_rc, ldaperrno = 0;
	LDAPMessage		*resultMsg = NULL;
	void			**paramVal = NULL;

	ns_cred_t		anon;
	ns_conn_user_t		*cu = NULL;

	if (errorp == NULL) {
		return (NS_LDAP_INVALID_PARAM);
	}

	*errorp = NULL;

	if (!root_dse) {
		return (NS_LDAP_INVALID_PARAM);
	}

	if (!server_addr) {
		return (NS_LDAP_INVALID_PARAM);
	}

	__s_api_setInitMode();

	cu = __s_api_conn_user_init(NS_CONN_USER_SEARCH, NULL, B_FALSE);
	if (cu == NULL) {
		return (NS_LDAP_INTERNAL);
	}

	/*
	 * All the credentials will be taken from the current
	 * libsldap configuration.
	 */
	if ((ret_code = __s_api_getConnection(server_addr,
	    NS_LDAP_NEW_CONN,
	    NULL,
	    &sessionId,
	    &session,
	    errorp,
	    0,
	    0,
	    cu)) != NS_LDAP_SUCCESS) {
		/* Fallback to anonymous mode is disabled. Stop. */
		if (anon_fallback == 0) {
			syslog(LOG_WARNING,
			    gettext("libsldap: can not get the root DSE from "
			    " the %s server: %s. "
			    "Falling back to anonymous disabled.\n"),
			    server_addr,
			    errorp && *errorp && (*errorp)->message ?
			    (*errorp)->message : "");
			if (errorp != NULL && *errorp != NULL) {
				(void) __ns_ldap_freeError(errorp);
			}
			__s_api_unsetInitMode();
			return (ret_code);
		}

		/*
		 * Fallback to anonymous, non-SSL mode for backward
		 * compatibility reasons. This mode should only be used when
		 * this function (__ns_ldap_getRootDSE) is called from
		 * ldap_cachemgr(1M).
		 */
		syslog(LOG_WARNING,
		    gettext("libsldap: Falling back to anonymous, non-SSL"
		    " mode for __ns_ldap_getRootDSE. %s\n"),
		    errorp && *errorp && (*errorp)->message ?
		    (*errorp)->message : "");

		/* Setup the anon credential for anonymous connection. */
		(void) memset(&anon, 0, sizeof (ns_cred_t));
		anon.auth.type = NS_LDAP_AUTH_NONE;

		if (*errorp != NULL) {
			(void) __ns_ldap_freeError(errorp);
		}
		*errorp = NULL;

		ret_code = __s_api_getConnection(server_addr,
		    NS_LDAP_NEW_CONN,
		    &anon,
		    &sessionId,
		    &session,
		    errorp,
		    0,
		    0,
		    cu);

		if (ret_code != NS_LDAP_SUCCESS) {
			__s_api_conn_user_free(cu);
			__s_api_unsetInitMode();
			return (ret_code);
		}
	}

	__s_api_unsetInitMode();

	/* get search timeout value */
	(void) __ns_ldap_getParam(NS_LDAP_SEARCH_TIME_P, &paramVal, errorp);
	if (paramVal != NULL && *paramVal != NULL) {
		tv.tv_sec = **((int **)paramVal);
		(void) __ns_ldap_freeParam(&paramVal);
	}
	if (*errorp != NULL) {
		(void) __ns_ldap_freeError(errorp);
	}

	/* Get root DSE from the server specified by the caller. */
	attrs[0] = "supportedControl";
	attrs[1] = "supportedsaslmechanisms";
	attrs[2] = NULL;
	ldap_rc = ldap_search_ext_s(session->ld,
	    "",
	    LDAP_SCOPE_BASE,
	    "(objectclass=*)",
	    attrs,
	    0,
	    NULL,
	    NULL,
	    &tv,
	    0,
	    &resultMsg);

	if (ldap_rc != LDAP_SUCCESS) {
		/*
		 * If the root DSE was not found, the server does
		 * not comply with the LDAP v3 protocol.
		 */
		(void) ldap_get_option(session->ld,
		    LDAP_OPT_ERROR_NUMBER,
		    &ldaperrno);
		(void) snprintf(errmsg,
		    sizeof (errmsg),
		    gettext(ldap_err2string(ldaperrno)));
		MKERROR(LOG_ERR,
		    *errorp,
		    NS_LDAP_OP_FAILED,
		    strdup(errmsg),
		    NS_LDAP_MEMORY);

		if (resultMsg) {
			(void) ldap_msgfree(resultMsg);
			resultMsg = NULL;
		}

		__s_api_conn_user_free(cu);
		DropConnection(sessionId, NS_LDAP_NEW_CONN);
		return (NS_LDAP_OP_FAILED);
	}
	__s_api_conn_user_free(cu);

	ret_code = convert_to_door_line(session->ld,
	    resultMsg,
	    INCLUDE_ATTR_NAMES,
	    NOT_PROFILE,
	    root_dse);
	if (ret_code == NS_LDAP_NOTFOUND) {
		(void) snprintf(errmsg,
		    sizeof (errmsg),
		    gettext("No root DSE data "
		    "for server %s returned."),
		    server_addr);
		MKERROR(LOG_ERR,
		    *errorp,
		    NS_LDAP_NOTFOUND,
		    strdup(errmsg),
		    NS_LDAP_MEMORY);
	}

	if (resultMsg) {
		(void) ldap_msgfree(resultMsg);
		resultMsg = NULL;
	}

	DropConnection(sessionId, NS_LDAP_NEW_CONN);

	return (ret_code);
}

/*
 * This function destroys the local list of root DSEs. The input parameter is
 * a pointer to the list to be erased.
 * The type of the pointer passed to this function should be
 * (dir_server_list_t *).
 */
static
void *
disposeOfOldList(void *param)
{
	dir_server_list_t	*old_list = (dir_server_list_t *)param;
	long			i = 0, j;

	(void) rw_wrlock(&old_list->listDestroyLock);
	/* Destroy the old list */
	while (old_list->nsServers[i]) {
		free(old_list->nsServers[i]->ip);
		j = 0;
		while (old_list->nsServers[i]->controls &&
		    old_list->nsServers[i]->controls[j]) {
			free(old_list->nsServers[i]->controls[j]);
			++j;
		}
		free(old_list->nsServers[i]->controls);
		j = 0;
		while (old_list->nsServers[i]->saslMech &&
		    old_list->nsServers[i]->saslMech[j]) {
			free(old_list->nsServers[i]->saslMech[j]);
			++j;
		}
		free(old_list->nsServers[i]->saslMech);
		++i;
	}
	/*
	 * All the structures pointed by old_list->nsServers were allocated
	 * in one chunck. The nsServers[0] pointer points to the beginning
	 * of that chunck.
	 */
	free(old_list->nsServers[0]);
	free(old_list->nsServers);
	(void) rw_unlock(&old_list->listDestroyLock);
	(void) rwlock_destroy(&old_list->listDestroyLock);
	free(old_list);

	return (NULL);
}

/*
 * This function cancels the Standalone mode and destroys the list of root DSEs.
 */
void
__ns_ldap_cancelStandalone(void)
{
	dir_server_list_t	*old_list;

	(void) mutex_lock(&dir_servers.listReplaceLock);
	dir_servers.standalone = 0;
	if (!dir_servers.list) {
		(void) mutex_unlock(&dir_servers.listReplaceLock);
		return;
	}
	old_list = dir_servers.list;
	dir_servers.list = NULL;
	(void) mutex_unlock(&dir_servers.listReplaceLock);

	(void) disposeOfOldList(old_list);
}


static
void*
create_ns_servers_entry(void *param)
{
#define	CHUNK_SIZE 16

	dir_server_t		*server = (dir_server_t *)param;
	ns_ldap_return_code	*retCode = calloc(1,
	    sizeof (ns_ldap_return_code));
	uint32_t		sc_counter = 0, sm_counter = 0;
	uint32_t		sc_mem_blocks = 1, sm_mem_blocks = 1;
	char			*rootDSE = NULL, *attr, *val, *rest, **ptr;
	ns_ldap_error_t		*error = NULL;

	if (retCode == NULL) {
		return (NULL);
	}

	/*
	 * We call this function in non anon-fallback mode because we
	 * want the whole procedure to fail as soon as possible to
	 * indicate there are problems with connecting to the server.
	 */
	*retCode = __ns_ldap_getRootDSE(server->ip,
	    &rootDSE,
	    &error,
	    SA_ALLOW_FALLBACK);

	if (*retCode == NS_LDAP_MEMORY) {
		free(retCode);
		return (NULL);
	}

	/*
	 * If the root DSE can not be obtained, log an error and keep the
	 * server.
	 */
	if (*retCode != NS_LDAP_SUCCESS) {
		server->status = INFO_SERVER_ERROR;
		syslog(LOG_WARNING,
		    gettext("libsldap (\"standalone\" mode): "
		    "can not obtain the root DSE from %s. %s"),
		    server->ip,
		    error && error->message ? error->message : "");
		if (error) {
			(void) __ns_ldap_freeError(&error);
		}
		return (retCode);
	}

	/* Get the first attribute of the root DSE. */
	attr = strtok_r(rootDSE, DOORLINESEP, &rest);
	if (attr == NULL) {
		free(rootDSE);
		server->status = INFO_SERVER_ERROR;
		syslog(LOG_WARNING,
		    gettext("libsldap (\"standalone\" mode): "
		    "the root DSE from %s is empty or corrupted."),
		    server->ip);
		*retCode = NS_LDAP_INTERNAL;
		return (retCode);
	}

	server->controls = (char **)calloc(CHUNK_SIZE, sizeof (char *));
	server->saslMech = (char **)calloc(CHUNK_SIZE, sizeof (char *));
	if (server->controls == NULL || server->saslMech == NULL) {
		free(rootDSE);
		free(retCode);
		return (NULL);
	}

	do {
		if ((val = strchr(attr, '=')) == NULL) {
			continue;
		}
		++val;

		if (strncasecmp(attr,
		    _SASLMECHANISM,
		    _SASLMECHANISM_LEN) == 0) {
			if (sm_counter == CHUNK_SIZE * sm_mem_blocks - 1) {
				ptr = (char **)realloc(server->saslMech,
				    CHUNK_SIZE *
				    ++sm_mem_blocks *
				    sizeof (char *));
				if (ptr == NULL) {
					*retCode = NS_LDAP_MEMORY;
					break;
				}
				bzero((char *)ptr +
				    (sm_counter + 1) *
				    sizeof (char *),
				    CHUNK_SIZE *
				    sm_mem_blocks *
				    sizeof (char *) -
				    (sm_counter + 1) *
				    sizeof (char *));
				server->saslMech = ptr;
			}
			server->saslMech[sm_counter] = strdup(val);
			if (server->saslMech[sm_counter] == NULL) {
				*retCode = NS_LDAP_MEMORY;
				break;
			}
			++sm_counter;
			continue;
		}
		if (strncasecmp(attr,
		    _SUPPORTEDCONTROL,
		    _SUPPORTEDCONTROL_LEN) == 0) {
			if (sc_counter == CHUNK_SIZE * sc_mem_blocks - 1) {
				ptr = (char **)realloc(server->controls,
				    CHUNK_SIZE *
				    ++sc_mem_blocks *
				    sizeof (char *));
				if (ptr == NULL) {
					*retCode = NS_LDAP_MEMORY;
					break;
				}
				bzero((char *)ptr +
				    (sc_counter + 1) *
				    sizeof (char *),
				    CHUNK_SIZE *
				    sc_mem_blocks *
				    sizeof (char *) -
				    (sc_counter + 1) *
				    sizeof (char *));
				server->controls = ptr;
			}

			server->controls[sc_counter] = strdup(val);
			if (server->controls[sc_counter] == NULL) {
				*retCode = NS_LDAP_MEMORY;
				break;
			}
			++sc_counter;
			continue;
		}

	} while (attr = strtok_r(NULL, DOORLINESEP, &rest));

	free(rootDSE);

	if (*retCode == NS_LDAP_MEMORY) {
		free(retCode);
		return (NULL);
	}

	server->controls[sc_counter] = NULL;
	server->saslMech[sm_counter] = NULL;

	server->status = INFO_SERVER_UP;

	return (retCode);
#undef CHUNK_SIZE
}


/*
 * This function creates a new local list of root DSEs from all the servers
 * mentioned in the DUAProfile (or local NS BEC) and returns
 * a pointer to the list.
 */
static
ns_ldap_return_code
createDirServerList(dir_server_list_t **new_list,
		ns_ldap_error_t **errorp)
{
	char			**serverList;
	ns_ldap_return_code	retCode = NS_LDAP_SUCCESS;
	dir_server_t		*tmpSrvArray;
	long			srvListLength, i;
	thread_t		*thrPool, thrID;
	void			*status = NULL;

	if (errorp == NULL) {
		return (NS_LDAP_INVALID_PARAM);
	}

	*errorp = NULL;

	if (new_list == NULL) {
		return (NS_LDAP_INVALID_PARAM);
	}

	retCode = __s_api_getServers(&serverList, errorp);
	if (retCode != NS_LDAP_SUCCESS || serverList == NULL) {
		return (retCode);
	}

	for (i = 0; serverList[i]; ++i) {
		;
	}
	srvListLength = i;

	thrPool = calloc(srvListLength, sizeof (thread_t));
	if (thrPool == NULL) {
		__s_api_free2dArray(serverList);
		return (NS_LDAP_MEMORY);
	}

	*new_list = (dir_server_list_t *)calloc(1,
	    sizeof (dir_server_list_t));
	if (*new_list == NULL) {
		__s_api_free2dArray(serverList);
		free(thrPool);
		return (NS_LDAP_MEMORY);
	}
	(void) rwlock_init(&(*new_list)->listDestroyLock, USYNC_THREAD, NULL);

	(*new_list)->nsServers = (dir_server_t **)calloc(srvListLength + 1,
	    sizeof (dir_server_t *));
	if ((*new_list)->nsServers == NULL) {
		free(*new_list);
		*new_list = NULL;
		__s_api_free2dArray(serverList);
		free(thrPool);
		return (NS_LDAP_MEMORY);
	}

	/*
	 * Allocate a set of dir_server_t structures as an array,
	 * with one alloc call and then initialize the nsServers pointers
	 * with the addresses of the array's members.
	 */
	tmpSrvArray = (dir_server_t *)calloc(srvListLength,
	    sizeof (dir_server_t));
	for (i = 0; i < srvListLength; ++i) {
		(*new_list)->nsServers[i] = &tmpSrvArray[i];

		(*new_list)->nsServers[i]->info = INFO_STATUS_NEW;
		(void) mutex_init(&(*new_list)->nsServers[i]->updateStatus,
		    USYNC_THREAD,
		    NULL);

		(*new_list)->nsServers[i]->ip = strdup(serverList[i]);
		if ((*new_list)->nsServers[i]->ip == NULL) {
			retCode = NS_LDAP_MEMORY;
			break;
		}

		(*new_list)->nsServers[i]->status = INFO_SERVER_CONNECTING;

		switch (thr_create(NULL,
		    0,
		    create_ns_servers_entry,
		    (*new_list)->nsServers[i],
		    0,
		    &thrID)) {
		case EAGAIN:
			(*new_list)->nsServers[i]->status =
			    INFO_SERVER_ERROR;
			continue;
		case ENOMEM:
			(*new_list)->nsServers[i]->status =
			    INFO_SERVER_ERROR;
			continue;
		default:
			thrPool[i] = thrID;
			continue;
		}
	}

	for (i = 0; i < srvListLength; ++i) {
		if (thrPool[i] != 0 &&
		    thr_join(thrPool[i], NULL, &status) == 0) {
			if (status == NULL) {
				/*
				 * Some memory allocation problems occured. Just
				 * ignore the server and hope there will be some
				 * other good ones.
				 */
				(*new_list)->nsServers[i]->status =
				    INFO_SERVER_ERROR;
			}
			free(status);
		}
	}

	__s_api_free2dArray(serverList);
	free(thrPool);

	if (retCode == NS_LDAP_MEMORY) {
		(void) disposeOfOldList(*new_list);
		return (NS_LDAP_MEMORY);
	}

	return (NS_LDAP_SUCCESS);
}

/*
 * This functions replaces the local list of root DSEs with a new one and starts
 * a thread destroying the old list. There is no need for other threads to wait
 * until the old list will be destroyed.
 * Since it is possible that more than one thread can start creating the list,
 * this function should be protected by mutexes to be sure that only one thread
 * performs the initialization.
 */
static
ns_ldap_return_code
initGlobalList(ns_ldap_error_t **error)
{
	dir_server_list_t	*new_list, *old_list;
	ns_ldap_return_code	ret_code;
	thread_t		tid;

	ret_code = createDirServerList(&new_list, error);
	if (ret_code != NS_LDAP_SUCCESS) {
		return (ret_code);
	}

	old_list = dir_servers.list;
	dir_servers.list = new_list;

	if (old_list) {
		(void) thr_create(NULL,
		    0,
		    disposeOfOldList,
		    old_list,
		    THR_DETACHED,
		    &tid);
	}

	return (NS_LDAP_SUCCESS);
}

static
struct {
	char *authMech;
	ns_auth_t auth;
} authArray[] = {{"none", {NS_LDAP_AUTH_NONE,
			NS_LDAP_TLS_NONE,
			NS_LDAP_SASL_NONE,
			NS_LDAP_SASLOPT_NONE}},
		{"simple", {NS_LDAP_AUTH_SIMPLE,
			NS_LDAP_TLS_NONE,
			NS_LDAP_SASL_NONE,
			NS_LDAP_SASLOPT_NONE}},
		{"tls:simple", {NS_LDAP_AUTH_TLS,
			NS_LDAP_TLS_SIMPLE,
			NS_LDAP_SASL_NONE,
			NS_LDAP_SASLOPT_NONE}},
		{"tls:sasl/CRAM-MD5", {NS_LDAP_AUTH_TLS,
			NS_LDAP_TLS_SASL,
			NS_LDAP_SASL_CRAM_MD5,
			NS_LDAP_SASLOPT_NONE}},
		{"tls:sasl/DIGEST-MD5", {NS_LDAP_AUTH_TLS,
			NS_LDAP_TLS_SASL,
			NS_LDAP_SASL_DIGEST_MD5,
			NS_LDAP_SASLOPT_NONE}},
		{"sasl/CRAM-MD5", {NS_LDAP_AUTH_SASL,
			NS_LDAP_TLS_SASL,
			NS_LDAP_SASL_CRAM_MD5,
			NS_LDAP_SASLOPT_NONE}},
		{"sasl/DIGEST-MD5", {NS_LDAP_AUTH_SASL,
			NS_LDAP_TLS_SASL,
			NS_LDAP_SASL_DIGEST_MD5,
			NS_LDAP_SASLOPT_NONE}},
		{"sasl/GSSAPI", {NS_LDAP_AUTH_SASL,
			NS_LDAP_TLS_SASL,
			NS_LDAP_SASL_GSSAPI,
			NS_LDAP_SASLOPT_PRIV | NS_LDAP_SASLOPT_INT}},
		{NULL, {NS_LDAP_AUTH_NONE,
			NS_LDAP_TLS_NONE,
			NS_LDAP_SASL_NONE,
			NS_LDAP_SASLOPT_NONE}}};

ns_ldap_return_code
__ns_ldap_initAuth(const char *auth_mech,
		ns_auth_t *auth,
		ns_ldap_error_t **errorp)
{
	uint32_t	i;
	char		errmsg[MAXERROR];

	if (auth_mech == NULL) {
		(void) snprintf(errmsg,
		    sizeof (errmsg),
		    gettext("Invalid authentication method specified\n"));
		MKERROR(LOG_WARNING,
		    *errorp,
		    NS_LDAP_INTERNAL,
		    strdup(errmsg),
		    NS_LDAP_MEMORY);
		return (NS_LDAP_INTERNAL);
	}

	for (i = 0; authArray[i].authMech != NULL; ++i) {
		if (strcasecmp(auth_mech, authArray[i].authMech) == 0) {
			*auth = authArray[i].auth;
			return (NS_LDAP_SUCCESS);
		}
	}

	(void) snprintf(errmsg,
	    sizeof (errmsg),
	    gettext("Invalid authentication method specified\n"));
	MKERROR(LOG_WARNING,
	    *errorp,
	    NS_LDAP_INTERNAL,
	    strdup(errmsg),
	    NS_LDAP_MEMORY);
	return (NS_LDAP_INTERNAL);
}

/*
 * This function "informs" libsldap that a client application has specified
 * a directory to use. The function obtains a DUAProfile, credentials,
 * and naming context. During all further operations on behalf
 * of the application requested a standalone schema libsldap will use
 * the information obtained by __ns_ldap_initStandalone() instead of
 * door_call(3C)ing ldap_cachemgr(1M).
 *
 * INPUT:
 *     sa_conf - a structure describing where and in which way to obtain all
 *               the configuration describing how to communicate to
 *               a choosen LDAP directory,
 *     errorp - an error object describing an error occured.
 */
ns_ldap_return_code
__ns_ldap_initStandalone(const ns_standalone_conf_t *sa_conf,
			ns_ldap_error_t	**errorp) {

	ns_cred_t	user_cred = {{NS_LDAP_AUTH_NONE,
					NS_LDAP_TLS_NONE,
					NS_LDAP_SASL_NONE,
					NS_LDAP_SASLOPT_NONE},
					NULL,
					{NULL, NULL}};
	char		*dua_profile = NULL;
	char		errmsg[MAXERROR];
	ns_config_t 	*cfg;
	int		ret_code;

	if (sa_conf->SA_BIND_DN == NULL && sa_conf->SA_BIND_PWD != NULL ||
	    sa_conf->SA_BIND_DN != NULL && sa_conf->SA_BIND_PWD == NULL) {
		(void) snprintf(errmsg,
		    sizeof (errmsg),
		    gettext("Bind DN and bind password"
		    " must both be provided\n"));
		MKERROR(LOG_ERR,
		    *errorp,
		    NS_CONFIG_NOTLOADED,
		    strdup(errmsg),
		    NS_LDAP_MEMORY);
		return (NS_LDAP_INTERNAL);
	}

	switch (sa_conf->type) {
	case NS_LDAP_SERVER:
		if (sa_conf->SA_BIND_DN != NULL) {
			user_cred.cred.unix_cred.userID = sa_conf->SA_BIND_DN;
			user_cred.auth.type = NS_LDAP_AUTH_SIMPLE;
		}

		if (sa_conf->SA_BIND_PWD != NULL) {
			user_cred.cred.unix_cred.passwd = sa_conf->SA_BIND_PWD;
		}

		if (sa_conf->SA_AUTH != NULL) {
			user_cred.auth.type = sa_conf->SA_AUTH->type;
			user_cred.auth.tlstype = sa_conf->SA_AUTH->tlstype;
			user_cred.auth.saslmech = sa_conf->SA_AUTH->saslmech;
			user_cred.auth.saslopt = sa_conf->SA_AUTH->saslopt;
		}

		if (sa_conf->SA_CERT_PATH != NULL) {
			user_cred.hostcertpath = sa_conf->SA_CERT_PATH;
		}

		ret_code = __ns_ldap_getConnectionInfoFromDUA(
		    &sa_conf->ds_profile.server,
		    &user_cred,
		    &dua_profile,
		    NULL,
		    errorp);
		if (ret_code != NS_LDAP_SUCCESS) {
			return (ret_code);
		}

		cfg = __s_api_create_config_door_str(dua_profile, errorp);
		if (cfg == NULL) {
			free(dua_profile);
			return (NS_LDAP_CONFIG);
		}

		if (sa_conf->SA_CERT_PATH != NULL) {
			char		*certPathAttr;
			ParamIndexType	type;

			switch (cfg->version) {
			case NS_LDAP_V1:
				certPathAttr = "NS_LDAP_CERT_PATH";
				break;
			default:	/* Version 2 */
				certPathAttr = "NS_LDAP_HOST_CERTPATH";
				break;
			}

			if (__s_api_get_versiontype(cfg,
						certPathAttr,
						&type) == 0 &&
			    (ret_code = __ns_ldap_setParamValue(cfg,
						type,
						sa_conf->SA_CERT_PATH,
						errorp)) != NS_LDAP_SUCCESS) {
				__s_api_destroy_config(cfg);
				return (ret_code);
			}
		}

		if (sa_conf->SA_BIND_DN != NULL &&
		    sa_conf->SA_BIND_PWD != NULL) {
			char *authMethods;

			authMethods = __s_api_strValue(cfg, NS_LDAP_AUTH_P,
			    NS_FILE_FMT);
			if (authMethods != NULL &&
			    strstr(authMethods, "sasl/GSSAPI") != NULL) {
				/*
				 * The received DUAProfile specifies
				 * sasl/GSSAPI as an auth. mechanism.
				 * The bind DN and password will be
				 * ignored.
				 */
				syslog(LOG_INFO, gettext("sasl/GSSAPI will be "
				    "used as an authentication method. "
				    "The bind DN and password will "
				    "be ignored.\n"));
				free(authMethods);
				break;
			}

			if (authMethods != NULL)
				free(authMethods);

			if (__ns_ldap_setParamValue(cfg,
						NS_LDAP_BINDDN_P,
						sa_conf->SA_BIND_DN,
						errorp) != NS_LDAP_SUCCESS) {
				__s_api_destroy_config(cfg);
				return (NS_LDAP_CONFIG);
			}

			if (__ns_ldap_setParamValue(cfg,
			    NS_LDAP_BINDPASSWD_P,
			    sa_conf->SA_BIND_PWD,
			    errorp) != NS_LDAP_SUCCESS) {
				__s_api_destroy_config(cfg);
				return (NS_LDAP_CONFIG);
			}
		}

		break;
	default:	/* NS_CACHEMGR */
		return (NS_LDAP_SUCCESS);
	}

	__s_api_init_config(cfg);
	/* Connection management should use the new config now. */
	__s_api_reinit_conn_mgmt_new_config(cfg);
	__ns_ldap_setServer(TRUE);

	(void) mutex_lock(&dir_servers.listReplaceLock);
	if ((ret_code = initGlobalList(errorp)) != NS_SUCCESS) {
		(void) mutex_unlock(&dir_servers.listReplaceLock);
		return (ret_code);
	}
	dir_servers.standalone = 1;
	(void) mutex_unlock(&dir_servers.listReplaceLock);

	return (NS_LDAP_SUCCESS);
}

/*
 * INPUT:
 *     serverAddr is the address of a server and
 *     request is one of the following:
 *     NS_CACHE_NEW:    get a new server address, addr is ignored.
 *     NS_CACHE_NORESP: get the next one, remove addr from list.
 *     NS_CACHE_NEXT:   get the next one, keep addr on list.
 *     NS_CACHE_WRITE:  get a non-replica server, if possible, if not, same
 *                      as NS_CACHE_NEXT.
 *     addrType:
 *     NS_CACHE_ADDR_IP: return server address as is, this is default.
 *     NS_CACHE_ADDR_HOSTNAME: return server addess as FQDN format, only
 *                             self credential case requires such format.
 * OUTPUT:
 *     ret
 *
 *     a structure of type ns_server_info_t containing the server address
 *     or name, server controls and supported SASL mechanisms.
 *     NOTE: Caller should allocate space for the structure and free
 *     all the space allocated by the function for the information contained
 *     in the structure.
 *
 *     error - an error object describing an error, if any.
 */
ns_ldap_return_code
__s_api_findRootDSE(const char *request,
		const char *serverAddr,
		const char *addrType,
		ns_server_info_t *ret,
		ns_ldap_error_t	**error)
{
	dir_server_list_t	*current_list = NULL;
	ns_ldap_return_code	ret_code;
	long			i = 0;
	int			matched = FALSE;
	dir_server_t		*server = NULL;
	char			errmsg[MAXERROR];

	(void) mutex_lock(&dir_servers.listReplaceLock);
	if (dir_servers.list == NULL) {
		(void) mutex_unlock(&dir_servers.listReplaceLock);
		(void) snprintf(errmsg,
		    sizeof (errmsg),
		    gettext("The list of root DSEs is empty: "
		    "the Standalone mode was not properly initialized"));
		MKERROR(LOG_ERR,
		    *error,
		    NS_CONFIG_NOTLOADED,
		    strdup(errmsg),
		    NS_LDAP_MEMORY);
		return (NS_LDAP_INTERNAL);
	}

	current_list = dir_servers.list;
	(void) rw_rdlock(&current_list->listDestroyLock);
	(void) mutex_unlock(&dir_servers.listReplaceLock);

	/*
	 * The code below is mostly the clone of the
	 * ldap_cachemgr::cachemgr_getldap.c::getldap_get_serverInfo() function.
	 * Currently we have two different server lists: one is maintained
	 * by libsldap ('standalone' mode), the other is in ldap_cachemgr
	 * (a part of its standard functionality).
	 */

	/*
	 * If NS_CACHE_NEW, or the server info is new,
	 * starts from the beginning of the list.
	 */
	(void) mutex_lock(&current_list->nsServers[0]->updateStatus);
	if (strcmp(request, NS_CACHE_NEW) == 0 ||
	    current_list->nsServers[0]->info == INFO_STATUS_NEW) {
		matched = TRUE;
	}
	(void) mutex_unlock(&current_list->nsServers[i]->updateStatus);

	for (i = 0; current_list->nsServers[i]; ++i) {
		/*
		 * Lock the updateStatus mutex to
		 * make sure the server status stays the same
		 * while the data is being processed.
		 */
		if (matched == FALSE &&
		    strcmp(current_list->nsServers[i]->ip,
		    serverAddr) == 0) {
			matched = TRUE;
			if (strcmp(request, NS_CACHE_NORESP) == 0) {

				/*
				 * if the server has already been removed,
				 * don't bother.
				 */
				(void) mutex_lock(&current_list->
				    nsServers[i]->updateStatus);
				if (current_list->nsServers[i]->status ==
				    INFO_SERVER_REMOVED) {
					(void) mutex_unlock(&current_list->
					    nsServers[i]->
					    updateStatus);
					continue;
				}
				(void) mutex_unlock(&current_list->
				    nsServers[i]->
				    updateStatus);

				/*
				 * if the information is new,
				 * give this server one more chance.
				 */
				(void) mutex_lock(&current_list->
				    nsServers[i]->
				    updateStatus);
				if (current_list->nsServers[i]->info ==
				    INFO_STATUS_NEW &&
				    current_list->nsServers[i]->status  ==
				    INFO_SERVER_UP) {
					server = current_list->nsServers[i];
					(void) mutex_unlock(&current_list->
					    nsServers[i]->
					    updateStatus);
					break;
				} else {
					/*
					 * it is recommended that
					 * before removing the
					 * server from the list,
					 * the server should be
					 * contacted one more time
					 * to make sure that it is
					 * really unavailable.
					 * For now, just trust the client
					 * (i.e., the sldap library)
					 * that it knows what it is
					 * doing and would not try
					 * to mess up the server
					 * list.
					 */
					current_list->nsServers[i]->status =
					    INFO_SERVER_REMOVED;
					(void) mutex_unlock(&current_list->
					    nsServers[i]->
					    updateStatus);
					continue;
				}
			} else {
				/*
				 * req == NS_CACHE_NEXT or NS_CACHE_WRITE
				 */
				continue;
			}
		}

		if (matched) {
			if (strcmp(request, NS_CACHE_WRITE) == 0) {
				/*
				 * ldap_cachemgr checks here if the server
				 * is not a non-replica server (a server
				 * of type INFO_RW_WRITEABLE). But currently
				 * it considers all the servers in its list
				 * as those.
				 */
				(void) mutex_lock(&current_list->
				    nsServers[i]->
				    updateStatus);
				if (current_list->nsServers[i]->status  ==
				    INFO_SERVER_UP) {
					(void) mutex_unlock(&current_list->
					    nsServers[i]->
					    updateStatus);
					server = current_list->nsServers[i];
					break;
				}
			} else {
				(void) mutex_lock(&current_list->
				    nsServers[i]->
				    updateStatus);
				if (current_list->nsServers[i]->status ==
				    INFO_SERVER_UP) {
					(void) mutex_unlock(&current_list->
					    nsServers[i]->
					    updateStatus);
					server = current_list->nsServers[i];
					break;
				}
			}

			(void) mutex_unlock(&current_list->
			    nsServers[i]->
			    updateStatus);
		}
	}

	if (server == NULL) {
		(void) rw_unlock(&current_list->listDestroyLock);
		(void) snprintf(errmsg,
		    sizeof (errmsg),
		    gettext("No servers are available"));
		MKERROR(LOG_ERR,
		    *error,
		    NS_CONFIG_NOTLOADED,
		    strdup(errmsg),
		    NS_LDAP_MEMORY);
		return (NS_LDAP_NOTFOUND);
	}

	(void) mutex_lock(&server->updateStatus);
	server->info = INFO_STATUS_OLD;
	(void) mutex_unlock(&server->updateStatus);

	if (ret == NULL) {
		(void) rw_unlock(&current_list->listDestroyLock);
		return (NS_LDAP_SUCCESS);
	}

	if (strcmp(addrType, NS_CACHE_ADDR_HOSTNAME) == 0) {
		ret_code = __s_api_ip2hostname(server->ip, &ret->serverFQDN);
		if (ret_code != NS_LDAP_SUCCESS) {
			(void) snprintf(errmsg,
			    sizeof (errmsg),
			    gettext("The %s address "
			    "can not be resolved into "
			    "a host name. Returning "
			    "the address as it is."),
			    server->ip);
			MKERROR(LOG_ERR,
			    *error,
			    NS_CONFIG_NOTLOADED,
			    strdup(errmsg),
			    NS_LDAP_MEMORY);
			return (NS_LDAP_INTERNAL);
		}
	}

	ret->server = strdup(server->ip);

	ret->controls = __s_api_cp2dArray(server->controls);
	ret->saslMechanisms = __s_api_cp2dArray(server->saslMech);

	(void) rw_unlock(&current_list->listDestroyLock);

	return (NS_LDAP_SUCCESS);
}

/*
 * This function iterates through the list of the configured LDAP servers
 * and "pings" those which are marked as removed or if any error occurred
 * during the previous receiving of the server's root DSE. If the
 * function is able to reach such a server and get its root DSE, it
 * marks the server as on-line. Otherwise, the server's status is set
 * to "Error".
 * For each server the function tries to connect to, it fires up
 * a separate thread and then waits until all the treads finish.
 * The function returns NS_LDAP_INTERNAL if the Standalone mode was not
 * initialized or was canceled prior to an invocation of
 * __ns_ldap_pingOfflineServers().
 */
ns_ldap_return_code
__ns_ldap_pingOfflineServers(void)
{
	dir_server_list_t	*current_list = NULL;
	ns_ldap_return_code	retCode = NS_LDAP_SUCCESS;
	long			srvListLength, i = 0;
	thread_t		*thrPool, thrID;
	void			*status = NULL;

	(void) mutex_lock(&dir_servers.listReplaceLock);
	if (dir_servers.list == NULL) {
		(void) mutex_unlock(&dir_servers.listReplaceLock);
		return (NS_LDAP_INTERNAL);
	}

	current_list = dir_servers.list;
	(void) rw_wrlock(&current_list->listDestroyLock);
	(void) mutex_unlock(&dir_servers.listReplaceLock);

	while (current_list->nsServers[i] != NULL) {
		++i;
	}
	srvListLength = i;

	thrPool = calloc(srvListLength, sizeof (thread_t));
	if (thrPool == NULL) {
		(void) rw_unlock(&current_list->listDestroyLock);
		return (NS_LDAP_MEMORY);
	}

	for (i = 0; i < srvListLength; ++i) {
		if (current_list->nsServers[i]->status != INFO_SERVER_REMOVED &&
		    current_list->nsServers[i]->status != INFO_SERVER_ERROR) {
			continue;
		}
		current_list->nsServers[i]->status = INFO_SERVER_CONNECTING;
		current_list->nsServers[i]->info = INFO_STATUS_NEW;

		__s_api_free2dArray(current_list->nsServers[i]->controls);
		current_list->nsServers[i]->controls = NULL;
		__s_api_free2dArray(current_list->nsServers[i]->saslMech);
		current_list->nsServers[i]->saslMech = NULL;

		switch (thr_create(NULL,
		    0,
		    create_ns_servers_entry,
		    current_list->nsServers[i],
		    0,
		    &thrID)) {
		case EAGAIN:
			current_list->nsServers[i]->status = INFO_SERVER_ERROR;
			continue;
		case ENOMEM:
			current_list->nsServers[i]->status = INFO_SERVER_ERROR;
			retCode = NS_LDAP_MEMORY;
			break;
		default:
			thrPool[i] = thrID;
			continue;
		}
		/* A memory allocation error has occured */
		break;

	}

	for (i = 0; i < srvListLength; ++i) {
		if (thrPool[i] != 0 &&
		    thr_join(thrPool[i], NULL, &status) == 0) {
			if (status == NULL) {
				current_list->nsServers[i]->status =
				    INFO_SERVER_ERROR;
				retCode = NS_LDAP_MEMORY;
			}
			free(status);
		}
	}

	(void) rw_unlock(&current_list->listDestroyLock);

	free(thrPool);

	return (retCode);
}
