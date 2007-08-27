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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <syslog.h>
#include "ldap_common.h"

/* netgroup attributes filters */
#define	_N_TRIPLE		"nisnetgrouptriple"
#define	_N_MEMBER		"membernisnetgroup"

#define	PRINT_VAL(a)		(((a).argc == 0) || ((a).argv == NULL) || \
				    ((a).argv[0] == NULL)) ? "*" : (a).argv[0]
#define	ISNULL(a)		(a == NULL ? "<NULL>" : a)
#define	MAX_DOMAIN_LEN		1024
#define	MAX_TRIPLE_LEN		(MAXHOSTNAMELEN + LOGNAME_MAX + \
					MAX_DOMAIN_LEN + 5)

#define	_F_SETMEMBER		"(&(objectClass=nisNetGroup)(cn=%s))"
#define	_F_SETMEMBER_SSD	"(&(%%s)(cn=%s))"

#define	N_HASH		257
#define	COMMA		','

static const char *netgrent_attrs[] = {
	_N_TRIPLE,
	_N_MEMBER,
	(char *)NULL
};

typedef struct netgroup_name {
	char *name;
	struct netgroup_name *next;
	struct netgroup_name *next_hash;
} netgroup_name_t;

typedef struct {
	netgroup_name_t *hash_list[N_HASH];
	netgroup_name_t *to_do;
	netgroup_name_t *done;
} netgroup_table_t;

typedef struct {
	ns_ldap_result_t *results;
	ns_ldap_entry_t *entry;
	char **attrs;
	void *cookie;
	char *netgroup;
	netgroup_table_t tab;
} getnetgrent_cookie_t;

typedef struct {
	struct nss_innetgr_args *ia;
	const char *ssd_filter;
	const char *netgrname;
	const char *membername;
	netgroup_table_t tab;
} innetgr_cookie_t;

typedef unsigned int hash_t;

static hash_t
get_hash(const char *s)
{
	unsigned int sum = 0;
	unsigned int i;

	for (i = 0; s[i] != '\0'; i++)
		sum += ((unsigned char *)s)[i];

	return ((sum + i) % N_HASH);
}

/*
 * Adds a name to the netgroup table
 *
 * Returns
 *	0 if successfully added or already present
 *	-1 if memory allocation error
 */

static int
add_netgroup_name(const char *name, netgroup_table_t *tab)
{
	hash_t		h;
	netgroup_name_t	*ng;
	netgroup_name_t	*ng_new;

	if (tab == NULL || name == NULL || *name == '\0')
	return (NULL);

	h = get_hash(name);
	ng = tab->hash_list[h];

	while (ng != NULL) {
		if (strcmp(name, ng->name) == 0)
			break;
		ng = ng->next_hash;
	}

	if (ng == NULL) {
		ng_new = (netgroup_name_t *)
		    calloc(1, sizeof (netgroup_name_t));
		if (ng_new == NULL)
			return (-1);
		ng_new->name = strdup(name);
		if (ng_new->name == NULL) {
			free(ng_new);
			return (-1);
		}
		ng_new->next_hash = tab->hash_list[h];
		tab->hash_list[h] = ng_new;
		ng_new->next = tab->to_do;
		tab->to_do = ng_new;
	}
	return (0);
}

static netgroup_name_t *
get_next_netgroup(netgroup_table_t *tab)
{
	netgroup_name_t *ng;

	if (tab == NULL)
		return (NULL);

	ng = tab->to_do;
	if (ng != NULL) {
		tab->to_do = ng->next;
		ng->next = tab->done;
		tab->done = ng;
	}
	return (ng);
}

static void
free_netgroup_table(netgroup_table_t *tab)
{
	netgroup_name_t *ng, *next;

	if (tab == NULL)
		return;

	for (ng = tab->to_do; ng != NULL; ng = next) {
		if (ng->name != NULL)
			free(ng->name);
		next = ng->next;
		free(ng);
	}

	for (ng = tab->done; ng != NULL; ng = next) {
		if (ng->name != NULL)
			free(ng->name);
		next = ng->next;
		free(ng);
	}
	(void) memset(tab, 0, sizeof (*tab));
}

/*
 * domain comparing routine
 * 	n1: See if n1 is n2 or an ancestor of it
 * 	n2: (in string terms, n1 is a suffix of n2)
 * Returns ZERO for success, -1 for failure.
 */
static int
domcmp(const char *n1, const char *n2)
{
#define	PASS	0
#define	FAIL	-1

	size_t		l1, l2;

	if ((n1 == NULL) || (n2 == NULL))
		return (FAIL);

	l1 = strlen(n1);
	l2 = strlen(n2);

	/* Turn a blind eye to the presence or absence of trailing periods */
	if (l1 != 0 && n1[l1 - 1] == '.') {
		--l1;
	}
	if (l2 != 0 && n2[l2 - 1] == '.') {
		--l2;
	}
	if (l1 > l2) {		/* Can't be a suffix */
		return (FAIL);
	} else if (l1 == 0) {	/* Trivially a suffix; */
				/* (do we want this case?) */
		return (PASS);
	}
	/* So 0 < l1 <= l2 */
	if (l1 < l2 && n2[l2 - l1 - 1] != '.') {
		return (FAIL);
	}
	if (strncasecmp(n1, &n2[l2 - l1], l1) == 0) {
		return (PASS);
	} else {
		return (FAIL);
	}
}

static int
split_triple(char *triple, char **hostname, char **username, char **domain)
{
	int	i, syntax_err;
	char	*splittriple[3];
	char	*p = triple;

#ifdef	DEBUG
	(void) fprintf(stdout, "\n[getnetgrent.c: split_triple]\n");
#endif	/* DEBUG */

	if (triple == NULL)
		return (-1);

	p++;
	syntax_err = 0;
	for (i = 0; i < 3; i++) {
		char	*start;
		char	*limit;
		const char	*terminators = ",) \t";

		if (i == 2) {
			/* Don't allow comma */
			terminators++;
		}
		while (isspace(*p)) {
			p++;
		}
		start = p;
		limit = strpbrk(start, terminators);
		if (limit == 0) {
			syntax_err++;
			break;
		}
		p = limit;
		while (isspace(*p)) {
			p++;
		}
		if (*p == terminators[0]) {
			/*
			 * Successfully parsed this name and
			 * the separator after it (comma or
			 * right paren); leave p ready for
			 * next parse.
			 */
			p++;
			if (start == limit) {
				/* Wildcard */
				splittriple[i] = NULL;
			} else {
				*limit = '\0';
				splittriple[i] = start;
			}
		} else {
			syntax_err++;
			break;
		}
	}

	if (syntax_err != 0)
		return (-1);

	*hostname = splittriple[0];
	*username = splittriple[1];
	*domain = splittriple[2];

	return (0);
}

/*
 * Test membership in triple
 *	return 0 = no match
 *	return 1 = match
 */

static int
match_triple_entry(struct nss_innetgr_args *ia, const ns_ldap_entry_t *entry)
{
	int	ndomains;
	char	**pdomains;
	int	nhost;
	char	**phost;
	int	nusers;
	char	**pusers;
	char	**attr;
	char	triple[MAX_TRIPLE_LEN];
	char	*tuser, *thost, *tdomain;
	int	i;
	char	*current, *limit;
	int	pulen, phlen;
	char	*pusers0, *phost0;

	nhost = ia->arg[NSS_NETGR_MACHINE].argc;
	phost = (char **)ia->arg[NSS_NETGR_MACHINE].argv;
	if (phost == NULL || *phost == NULL) {
		nhost = 0;
	} else {
		phost0 = phost[0];
		phlen = strlen(phost0);
	}
	nusers = ia->arg[NSS_NETGR_USER].argc;
	pusers = (char **)ia->arg[NSS_NETGR_USER].argv;
	if (pusers == NULL || *pusers == NULL) {
		nusers = 0;
	} else {
		pusers0 = pusers[0];
		pulen = strlen(pusers0);
	}
	ndomains = ia->arg[NSS_NETGR_DOMAIN].argc;
	pdomains = (char **)ia->arg[NSS_NETGR_DOMAIN].argv;
	if (pdomains == NULL || *pdomains == NULL)
		ndomains = 0;

	attr = __ns_ldap_getAttr(entry, _N_TRIPLE);
	if (attr == NULL || *attr == NULL)
		return (0);

	/* Special cases for speedup */
	if (nusers == 1 && nhost == 0 && ndomains == 0) {
		/* Special case for finding a single user in a netgroup */
		for (; *attr; attr++) {
			/* jump to first comma and check next character */
			current = *attr;
			if ((current = strchr(current, COMMA)) == NULL)
				continue;
			current++;

			/* skip whitespaces */
			while (isspace(*current))
				current++;

			/* if user part is null, then treat as wildcard */
			if (*current == COMMA)
				return (1);

			/* compare first character */
			if (*pusers0 != *current)
				continue;

			/* limit username to COMMA */
			if ((limit = strchr(current, COMMA)) == NULL)
				continue;
			*limit = '\0';

			/* remove blanks before COMMA */
			if ((limit = strpbrk(current, " \t")) != NULL)
				*limit = '\0';

			/* compare size of username */
			if (pulen != strlen(current)) {
				continue;
			}

			/* do actual compare */
			if (strncmp(pusers0, current, pulen) == 0) {
				return (1);
			} else {
				continue;
			}
		}
	} else if (nusers == 0 && nhost == 1 && ndomains == 0) {
		/* Special case for finding a single host in a netgroup */
		for (; *attr; attr++) {

			/* jump to first character and check */
			current = *attr;
			current++;

			/* skip whitespaces */
			while (isspace(*current))
				current++;

			/* if host part is null, then treat as wildcard */
			if (*current == COMMA)
				return (1);

			/* limit hostname to COMMA */
			if ((limit = strchr(current, COMMA)) == NULL)
				continue;
			*limit = '\0';

			/* remove blanks before COMMA */
			if ((limit = strpbrk(current, " \t")) != NULL)
				*limit = '\0';

			/* compare size of hostname */
			if (phlen != strlen(current)) {
				continue;
			}

			/* do actual compare */
			if (strncasecmp(phost0, current, phlen) == 0) {
				return (1);
			} else {
				continue;
			}
		}
	} else {
		for (; *attr; attr++) {
			if (strlcpy(triple, *attr,
			    sizeof (triple)) >= sizeof (triple))
				continue;
			if (split_triple(triple, &thost, &tuser, &tdomain) != 0)
				continue;
			if (thost != NULL && *thost != '\0' && nhost != 0) {
				for (i = 0; i < nhost; i++)
					if (strcasecmp(thost, phost[i]) == 0)
						break;
				if (i == nhost)
					continue;
			}
			if (tuser != NULL && *tuser != '\0' && nusers != 0) {
				for (i = 0; i < nusers; i++)
					if (strcmp(tuser, pusers[i]) == 0)
						break;
				if (i == nusers)
					continue;
			}
			if (tdomain != NULL && *tdomain != '\0' &&
			    ndomains != 0) {
				for (i = 0; i < ndomains; i++)
					if (domcmp(tdomain, pdomains[i]) == 0)
						break;
				if (i == ndomains)
					continue;
			}
			return (1);
		}
	}

	return (0);
}

static int
match_triple(struct nss_innetgr_args *ia, ns_ldap_result_t *result)
{
	ns_ldap_entry_t	*entry;

	for (entry = result->entry; entry != NULL; entry = entry->next)
		if (match_triple_entry(ia, entry) == 1)
			return (1);

	return (0);
}

static int
add_netgroup_member_entry(ns_ldap_entry_t *entry, netgroup_table_t *tab)
{
	char		**attrs;
	char		**a;

	attrs = __ns_ldap_getAttr(entry, _N_MEMBER);
	if (attrs == NULL || *attrs == NULL)
		return (0);

	for (a = attrs; *a != NULL; a++) {}

	do {
		a--;
		if (add_netgroup_name(*a, tab) != 0)
			return (-1);
	} while (a > attrs);
	return (0);
}

static int
add_netgroup_member(ns_ldap_result_t *result, netgroup_table_t *tab)
{
	ns_ldap_entry_t	*entry;
	int		ret = 0;

	for (entry = result->entry; entry != NULL; entry = entry->next) {
		ret = add_netgroup_member_entry(entry, tab);
		if (ret != 0)
			break;
	}
	return (ret);
}

/*
 * top_down_search checks only checks the netgroup specified in netgrname
 */
static nss_status_t
top_down_search(struct nss_innetgr_args *ia, char *netgrname)
{
	char			searchfilter[SEARCHFILTERLEN];
	char			name[SEARCHFILTERLEN];
	char			userdata[SEARCHFILTERLEN];
	ns_ldap_result_t	*result = NULL;
	ns_ldap_error_t		*error = NULL;
	int			rc;
	void			*cookie = NULL;
	nss_status_t		status = NSS_NOTFOUND;
	nss_status_t		status1;
	netgroup_table_t	tab;
	netgroup_name_t		*ng;
	int			ret;

	(void) memset(&tab, 0, sizeof (tab));

	if (add_netgroup_name(netgrname, &tab) != 0)
		return ((nss_status_t)NSS_NOTFOUND);

	while ((ng = get_next_netgroup(&tab)) != NULL) {
		if (_ldap_filter_name(name, ng->name, sizeof (name)) != 0)
			break;
		ret = snprintf(searchfilter, sizeof (searchfilter),
		    _F_SETMEMBER, name);
		if (ret >= sizeof (searchfilter) || ret < 0)
			break;

		ret = snprintf(userdata, sizeof (userdata), _F_SETMEMBER_SSD,
		    name);
		if (ret >= sizeof (userdata) || ret < 0)
			break;

		rc = __ns_ldap_firstEntry(_NETGROUP, searchfilter,
		    _merge_SSD_filter, netgrent_attrs, NULL, 0, &cookie,
		    &result, &error, userdata);

		if (error != NULL) {
			status1 = switch_err(rc, error);
			if (status1 == NSS_TRYAGAIN) {
				(void) __ns_ldap_freeError(&error);
				free_netgroup_table(&tab);
				return (status1);
			}
		}

		(void) __ns_ldap_freeError(&error);
		while (rc == NS_LDAP_SUCCESS && result != NULL) {
			if (match_triple(ia, result) == 1) {
				/* We found a match */
				ia->status = NSS_NETGR_FOUND;
				status = NSS_SUCCESS;
				break;
			}

			rc = add_netgroup_member(result, &tab);
			(void) __ns_ldap_freeResult(&result);

			if (rc != NS_LDAP_SUCCESS)
				break;
			rc = __ns_ldap_nextEntry(cookie, &result, &error);
			if (error != NULL) {
				status1 = switch_err(rc, error);
				if (status1 == NSS_TRYAGAIN) {
					free_netgroup_table(&tab);
					(void) __ns_ldap_freeError(&error);
					(void) __ns_ldap_endEntry(&cookie,
					    &error);
					(void) __ns_ldap_freeError(&error);
					return (status1);
				}
			}
			(void) __ns_ldap_freeError(&error);
		}
		(void) __ns_ldap_freeResult(&result);
		(void) __ns_ldap_endEntry(&cookie, &error);
		(void) __ns_ldap_freeError(&error);

		if (status == NSS_SUCCESS ||
		    (rc != NS_LDAP_SUCCESS && rc != NS_LDAP_NOTFOUND))
		break;
	}

	(void) __ns_ldap_freeResult(&result);
	(void) __ns_ldap_endEntry(&cookie, &error);
	(void) __ns_ldap_freeError(&error);
	free_netgroup_table(&tab);
	return (status);
}

/*
 * __netgr_in checks only checks the netgroup specified in ngroup
 */
static nss_status_t
__netgr_in(void *a, char *netgrname)
{
	struct nss_innetgr_args	*ia = (struct nss_innetgr_args *)a;
	nss_status_t		status = NSS_NOTFOUND;

#ifdef DEBUG
	(void) fprintf(stdout, "\n[getnetgrent.c: netgr_in]\n");
	(void) fprintf(stdout, "\tmachine: argc[%d]='%s' user: "
	    "argc[%d]='%s',\n\tdomain:argc[%d]='%s' "
	    "netgroup: argc[%d]='%s'\n",
	    NSS_NETGR_MACHINE,
	    PRINT_VAL(ia->arg[NSS_NETGR_MACHINE]),
	    NSS_NETGR_USER,
	    PRINT_VAL(ia->arg[NSS_NETGR_USER]),
	    NSS_NETGR_DOMAIN,
	    PRINT_VAL(ia->arg[NSS_NETGR_DOMAIN]),
	    NSS_NETGR_N,
	    PRINT_VAL(ia->arg[NSS_NETGR_N]));
	(void) fprintf(stdout, "\tgroups='%s'\n", netgrname);
#endif	/* DEBUG */

	ia->status = NSS_NETGR_NO;

	if (netgrname == NULL)
		return (status);

	return (top_down_search(ia, netgrname));
}

/*ARGSUSED0*/
static nss_status_t
netgr_in(ldap_backend_ptr be, void *a)
{
	struct nss_innetgr_args	*ia = (struct nss_innetgr_args *)a;
	int	i;
	nss_status_t	rc = (nss_status_t)NSS_NOTFOUND;

	ia->status = NSS_NETGR_NO;
	for (i = 0; i < ia->groups.argc; i++) {
		rc = __netgr_in(a, ia->groups.argv[i]);
		if (ia->status == NSS_NETGR_FOUND)
			return (NSS_SUCCESS);
	}
	return (rc);
}

/*
 *
 */

static nss_status_t
getnetgr_ldap_setent(ldap_backend_ptr be, void *a)
{
	const char	*netgroup = (const char *) a;
	getnetgrent_cookie_t	*cookie;

#ifdef	DEBUG
	(void) fprintf(stdout, "\n[getnetgrent.c: getnetgr_ldap_setent]\n");
#endif	/* DEBUG */

	cookie = (getnetgrent_cookie_t *)be->netgroup_cookie;
	if (cookie != NULL && cookie->netgroup != NULL) {
		/* is this another set on the same netgroup */
		if (strcmp(cookie->netgroup, netgroup) == 0)
			return ((nss_status_t)NSS_SUCCESS);
	}

	return (NSS_NOTFOUND);
}

static void
free_getnetgrent_cookie(getnetgrent_cookie_t **cookie)
{
	ns_ldap_error_t	*error = NULL;
	getnetgrent_cookie_t *p = *cookie;

#ifdef DEBUG
	(void) fprintf(stdout, "\n[getnetgrent.c: free_getnetgrent_cookie]\n");
#endif	/* DEBUG */

	if (p == NULL)
		return;

	(void) __ns_ldap_freeResult(&p->results);
	(void) __ns_ldap_endEntry(&p->cookie, &error);
	(void) __ns_ldap_freeError(&error);
	free_netgroup_table(&p->tab);
	free(p->netgroup);
	free(p);
	*cookie = NULL;
}

/*ARGSUSED1*/
static nss_status_t
getnetgr_ldap_endent(ldap_backend_ptr be, void *a)
{

#ifdef	DEBUG
	(void) fprintf(stdout, "\n[getnetgrent.c: getnetgr_ldap_endent]\n");
#endif	/* DEBUG */

	free_getnetgrent_cookie((getnetgrent_cookie_t **)&be->netgroup_cookie);

	return ((nss_status_t)NSS_NOTFOUND);
}


/*ARGSUSED1*/
static nss_status_t
getnetgr_ldap_destr(ldap_backend_ptr be, void *a)
{

#ifdef	DEBUG
	(void) fprintf(stdout, "\n[getnetgrent.c: getnetgr_ldap_destr]\n");
#endif	/* DEBUG */

	free_getnetgrent_cookie((getnetgrent_cookie_t **)&be->netgroup_cookie);
	free(be);

	return ((nss_status_t)NSS_NOTFOUND);
}


static nss_status_t
getnetgr_ldap_getent(ldap_backend_ptr be, void *a)
{
	struct nss_getnetgrent_args	*args;
	getnetgrent_cookie_t	*p;
	char			searchfilter[SEARCHFILTERLEN];
	char			userdata[SEARCHFILTERLEN];
	char			name[SEARCHFILTERLEN];
	int			rc;
	void			*cookie = NULL;
	ns_ldap_result_t	*result = NULL;
	ns_ldap_error_t		*error = NULL;
	char			**attrs;
	char			*hostname, *username, *domain;
	char			*buffer;
	nss_status_t		status = NSS_SUCCESS;
	netgroup_name_t		*ng;
	int			ret;

#ifdef	DEBUG
	(void) fprintf(stdout, "\n[getnetgrent.c: getnetgr_ldap_getent]\n");
#endif	/* DEBUG */

	args = (struct nss_getnetgrent_args *)a;

	args->status = NSS_NETGR_NO;

	p = (getnetgrent_cookie_t *)be->netgroup_cookie;
	if (p == NULL)
		return ((nss_status_t)NSS_SUCCESS);

	for (;;) {
		while (p->cookie == NULL) {
			ng = get_next_netgroup(&p->tab);
			if (ng == NULL)	 /* no more */
				break;

			if (_ldap_filter_name(name, ng->name,
			    sizeof (name)) != 0)
				break;

			ret = snprintf(searchfilter,
			    sizeof (searchfilter),
			    _F_SETMEMBER, name);
			if (ret >= sizeof (searchfilter) || ret < 0)
				break;

			ret = snprintf(userdata, sizeof (userdata),
			    _F_SETMEMBER_SSD, name);
			if (ret >= sizeof (userdata) || ret < 0)
				break;

			result = NULL;
			rc = __ns_ldap_firstEntry(_NETGROUP,
			    searchfilter,
			    _merge_SSD_filter, netgrent_attrs,
			    NULL, 0, &cookie,
			    &result, &error, userdata);
			(void) __ns_ldap_freeError(&error);

			if (rc == NS_LDAP_SUCCESS && result != NULL) {
				p->cookie = cookie;
				p->results = result;
				break;
			}
			(void) __ns_ldap_freeResult(&result);
			(void) __ns_ldap_endEntry(&cookie, &error);
			(void) __ns_ldap_freeError(&error);
		}
		if (p->cookie == NULL)
			break;
		if (p->results == NULL) {
			result = NULL;
			rc = __ns_ldap_nextEntry(p->cookie, &result,
			    &error);
			(void) __ns_ldap_freeError(&error);
			if (rc == NS_LDAP_SUCCESS && result != NULL)
				p->results = result;
			else {
				(void) __ns_ldap_freeResult(&result);
				(void) __ns_ldap_endEntry(&p->cookie,
				    &error);
				(void) __ns_ldap_freeError(&error);
				p->cookie = NULL;
			}
		}
		if (p->results == NULL)
			continue;

		if (p->entry == NULL)
			p->entry = p->results->entry;

		if (p->entry == NULL)
			continue;

		if (p->attrs == NULL) {
			attrs = __ns_ldap_getAttr(p->entry, _N_TRIPLE);
			if (attrs != NULL && *attrs != NULL)
				p->attrs = attrs;
		}

		if (p->attrs != NULL) {
			attrs = p->attrs;
			buffer = args->buffer;

			if (strlcpy(buffer, *attrs, args->buflen) >=
			    args->buflen) {
				status = NSS_STR_PARSE_ERANGE;
				break;
			}

			rc = split_triple(buffer, &hostname, &username,
			    &domain);
			attrs++;
			if (attrs != NULL && *attrs != NULL)
				p->attrs = attrs;
			else
				p->attrs = NULL;
			if (rc == 0) {
				args->retp[NSS_NETGR_MACHINE] = hostname;
				args->retp[NSS_NETGR_USER] = username;
				args->retp[NSS_NETGR_DOMAIN] = domain;
				args->status = NSS_NETGR_FOUND;
				if (p->attrs != NULL)
					break;
			}
		}

		if (p->attrs == NULL) {
			rc = add_netgroup_member_entry(p->entry, &p->tab);
			if (rc != 0) {
				args->status = NSS_NETGR_NO;
				break;
			}

			p->entry = p->entry->next;
			if (p->entry == NULL)
				(void) __ns_ldap_freeResult(&p->results);
			if (args->status == NSS_NETGR_FOUND)
				break;
		}
	}

	return (status);
}

static ldap_backend_op_t getnetgroup_ops[] = {
	getnetgr_ldap_destr,
	getnetgr_ldap_endent,
	getnetgr_ldap_setent,
	getnetgr_ldap_getent,
};

/*
 *
 */

static nss_status_t
netgr_set(ldap_backend_ptr be, void *a)
{
	struct nss_setnetgrent_args	*args =
	    (struct nss_setnetgrent_args *)a;
	ldap_backend_ptr		get_be;
	getnetgrent_cookie_t		*p;

#ifdef DEBUG
	(void) fprintf(stdout, "\n[getnetgrent.c: netgr_set]\n");
	(void) fprintf(stdout,
	    "\targs->netgroup: %s\n", ISNULL(args->netgroup));
#endif /* DEBUG */

	if (args->netgroup == NULL)
		return ((nss_status_t)NSS_NOTFOUND);

	free_getnetgrent_cookie((getnetgrent_cookie_t **)&be->netgroup_cookie);
	p = (getnetgrent_cookie_t *)calloc(1, sizeof (getnetgrent_cookie_t));
	if (p == NULL)
		return ((nss_status_t)NSS_NOTFOUND);
	p->netgroup = strdup(args->netgroup);
	if (p->netgroup == NULL) {
		free(p);
		return ((nss_status_t)NSS_NOTFOUND);
	}
	if (add_netgroup_name(args->netgroup, &p->tab) == -1) {
		free_getnetgrent_cookie(&p);
		return ((nss_status_t)NSS_NOTFOUND);
	}

	/* now allocate and return iteration backend structure */
	if ((get_be = (ldap_backend_ptr)malloc(sizeof (*get_be))) == NULL)
		return (NSS_UNAVAIL);
	get_be->ops = getnetgroup_ops;
	get_be->nops = sizeof (getnetgroup_ops) / sizeof (getnetgroup_ops[0]);
	get_be->tablename = NULL;
	get_be->attrs = netgrent_attrs;
	get_be->result = NULL;
	get_be->ldapobj2str = NULL;
	get_be->setcalled = 1;
	get_be->filter = NULL;
	get_be->toglue = NULL;
	get_be->enumcookie = NULL;
	get_be->netgroup_cookie = p;
	args->iterator = (nss_backend_t *)get_be;

	(void) __ns_ldap_freeResult(&be->result);

	return (NSS_SUCCESS);
}


/*ARGSUSED1*/
static nss_status_t
netgr_ldap_destr(ldap_backend_ptr be, void *a)
{

#ifdef	DEBUG
	(void) fprintf(stdout, "\n[getnetgrent.c: netgr_ldap_destr]\n");
#endif	/* DEBUG */

	(void) _clean_ldap_backend(be);

	return ((nss_status_t)NSS_NOTFOUND);
}




static ldap_backend_op_t netgroup_ops[] = {
	netgr_ldap_destr,
	0,
	0,
	0,
	netgr_in,		/*	innetgr()	*/
	netgr_set		/*	setnetgrent()	*/
};


/*
 * _nss_ldap_netgroup_constr is where life begins. This function calls the
 * generic ldap constructor function to define and build the abstract data
 * types required to support ldap operations.
 */

/*ARGSUSED0*/
nss_backend_t *
_nss_ldap_netgroup_constr(const char *dummy1, const char *dummy2,
			const char *dummy3)
{

#ifdef	DEBUG
	(void) fprintf(stdout,
	    "\n[getnetgrent.c: _nss_ldap_netgroup_constr]\n");
#endif	/* DEBUG */

	return ((nss_backend_t *)_nss_ldap_constr(netgroup_ops,
	    sizeof (netgroup_ops)/sizeof (netgroup_ops[0]), _NETGROUP,
	    netgrent_attrs, NULL));
}
