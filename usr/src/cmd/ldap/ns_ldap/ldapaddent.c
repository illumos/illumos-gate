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
 * Copyright (c) 2001, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2012 Milan Jurik. All rights reserved.
 */

/*
 * ldapaddent.c
 *
 * Utility to add /etc files into LDAP.
 * Can also be used to dump entries from a ldap container in /etc format.
 */

#include <stdio.h>
#include <stdlib.h>
#include <libintl.h>
#include <strings.h>
#include <sys/param.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <locale.h>
#include <syslog.h>

#undef opaque

#include <nss_dbdefs.h>
#include <netdb.h>
#include <rpc/rpcent.h>
#include <grp.h>
#include <pwd.h>
#include <project.h>
#include <shadow.h>
#include <sys/systeminfo.h>
#include "ns_internal.h"
#include "ldapaddent.h"
#include "standalone.h"

#define	OP_ADD	0
#define	OP_DUMP	3

static struct ttypelist_t {
	char *ttype;		/* type tag */
	int (*genent)(char *, int(*)());
				/* routine to turn line into ldap entries */
	void (*dump)(ns_ldap_result_t *);
				/* routine to print ldap containers */
	int (*filedbmline)();	/* routine to turn file line into dbm line */
	char *objclass;		/* Objectclass for the servicetype */
	char *sortattr;		/* Sort attr for enumeration */
} *tt;

char	parse_err_msg [PARSE_ERR_MSG_LEN];
int	continue_onerror = 0;  /* do not exit on error */

static int get_basedn(char *service, char **basedn);
static int check_ipaddr(char *addr, char **newaddr);
static int check_projname(char *addr);

extern	int	optind;
extern	char	*optarg;

extern	char	*__nis_quote_key(const char *, char *, int);

static char	*inputbasedn = NULL;
static char	*databasetype = NULL;
static int	exit_val = 0;
static unsigned	nent_add = 0;
static FILE	*etcf = 0;
static ns_cred_t	authority;
unsigned	flags = 0;

static void
perr(ns_ldap_error_t *e)
{
	if (e)
		(void) fprintf(stderr, "%d: %s\n",
		    e->status, e->message);
}


static int
ascii_to_int(char *str)
{
	int i;
	char *c = str;

	if (c == NULL || *c == '\0')
		return (-1);

	while (*c == ' ')
		c++;
	if (*c == '\0')
		return (-1);

	for (i = 0; i < strlen(c); i++)
		if (!isdigit(c[i]))
			return (-1);

	return (atoi(c));
}

/*
 * Internet network address interpretation routine.
 * The library routines call this routine to interpret
 * network numbers.
 */
static in_addr_t
encode_network(const char *cp)
{
	in_addr_t val;
	int base;
	ptrdiff_t n;
	char c;
	in_addr_t parts[4], *pp = parts;
	int i;

again:
	val = 0; base = 10;
	if (*cp == '0') {
		if (*++cp == 'x' || *cp == 'X')
			base = 16, cp++;
		else
			base = 8;
	}
	while ((c = *cp) != NULL) {
		if (isdigit(c)) {
			if ((c - '0') >= base)
				break;
			val = (val * base) + (c - '0');
			cp++;
			continue;
		}
		if (base == 16 && isxdigit(c)) {
			val = (val << 4) + (c + 10 - (islower(c) ? 'a' : 'A'));
			cp++;
			continue;
		}
		break;
	}
	if (*cp == '.') {
		if (pp >= parts + 4)
			return ((in_addr_t)-1);
		*pp++ = val, cp++;
		goto again;
	}
	if (*cp && !isspace(*cp))
		return ((in_addr_t)-1);
	*pp++ = val;
	n = pp - parts;
	if (n > 4)
		return ((in_addr_t)-1);
	for (val = 0, i = 0; i < n; i++) {
		val <<= 8;
		val |= parts[i] & 0xff;
	}
	for (/* no init */; i < 4; i++)
		val <<= 8;
	return (val);
}

static void
replace_tab2space(char *str)
{
	int i = 0;

	while ((str) && (str[i])) {
		if (str[i] == '\t')
			str[i] = ' ';
		i++;
	}
}

static int
blankline(char *line)
{
	char *p;

	for (p = line; *p; p++)
		if (*p != ' ' && *p != '\t')
			return (0);
	return (1);
}

/*
 * check whether the token <tok> is a triplet,
 * i. e. <tok> := (<hostname>,<username>,<domainname>)
 * where <hostname>, <username>, <domainname> are IA5String
 * <tok> supposes to contain NO spaces and start with '('
 */
static int
is_triplet(char *tok)
{
	char *s;
	return (strchr(++tok, '(') == NULL &&		/* no more '(' */
	    (s = strchr(tok, ')')) != NULL &&		/* find ')' */
	    !*++s &&					/* ')' ends token */
	    (tok = strchr(tok, ',')) != NULL &&		/* host up to ',' */
	    (tok = strchr(++tok, ',')) != NULL &&	/* user up to ',' */
	    strchr(++tok, ',') == NULL);		/* no more ',' */
}

static void
line_buf_expand(struct line_buf *line)
{
	line->alloc += BUFSIZ;
	line->str = (char *)realloc(line->str, line->alloc);

	if (line->str == NULL) {
		(void) fprintf(stderr,
		    gettext("line_buf_expand: out of memory\n"));
		exit(1);
	}
}

static void
line_buf_init(struct line_buf *line)
{
	(void) memset((char *)line, 0, sizeof (*line));
	line_buf_expand(line);
}

static int
__s_add_attr(ns_ldap_entry_t *e, char *attrname, char *value)
{
	ns_ldap_attr_t	*a;
	char		*v;

	a = (ns_ldap_attr_t *)calloc(1, sizeof (ns_ldap_attr_t));
	if (a == NULL)
		return (NS_LDAP_MEMORY);
	a->attrname = strdup(attrname);
	if (a->attrname == NULL) {
		free(a);
		return (NS_LDAP_MEMORY);
	}
	a->attrvalue = (char **)calloc(1, sizeof (char **));
	if (a->attrvalue == NULL) {
		free(a->attrname);
		free(a);
		return (NS_LDAP_MEMORY);
	}
	a->value_count = 1;
	a->attrvalue[0] = NULL;
	v = strdup(value);
	if (v == NULL) {
		free(a->attrname);
		free(a->attrvalue);
		free(a);
		return (NS_LDAP_MEMORY);
	}
	a->attrvalue[0] = v;
	e->attr_pair[e->attr_count] = a;
	e->attr_count++;
	return (NS_LDAP_SUCCESS);
}

static int
__s_add_attrlist(ns_ldap_entry_t *e, char *attrname, char **argv)
{
	ns_ldap_attr_t	*a;
	char		*v;
	char		**av;
	int		i, j;

	a = (ns_ldap_attr_t *)calloc(1, sizeof (ns_ldap_attr_t));
	if (a == NULL)
		return (NS_LDAP_MEMORY);
	a->attrname = strdup(attrname);
	if (a->attrname == NULL) {
		free(a);
		return (NS_LDAP_MEMORY);
	}

	for (i = 0, av = argv; *av != NULL; av++, i++)
		;

	a->attrvalue = (char **)calloc(i, sizeof (char **));

	if (a->attrvalue == NULL) {
		free(a->attrname);
		free(a);
		return (NS_LDAP_MEMORY);
	}
	a->value_count = i;
	for (j = 0; j < i; j++) {
		v = strdup(argv[j]);
		if (v == NULL) {
			free(a->attrname);
			free(a->attrvalue);
			free(a);
			return (NS_LDAP_MEMORY);
		}
		a->attrvalue[j] = v;
	}
	e->attr_pair[e->attr_count] = a;
	e->attr_count++;
	return (NS_LDAP_SUCCESS);
}

static ns_ldap_entry_t *
__s_mk_entry(char **objclass, int max_attr)
{
	ns_ldap_entry_t *e;
	e = (ns_ldap_entry_t *)calloc(1, sizeof (ns_ldap_entry_t));
	if (e == NULL)
		return (NULL);
	e->attr_pair = (ns_ldap_attr_t **)calloc(max_attr+1,
	    sizeof (ns_ldap_attr_t *));
	if (e->attr_pair == NULL) {
		free(e);
		return (NULL);
	}
	e->attr_count = 0;
	if (__s_add_attrlist(e, "objectClass", objclass) != NS_LDAP_SUCCESS) {
		free(e->attr_pair);
		free(e);
		return (NULL);
	}
	return (e);
}

static void
ldap_freeEntry(ns_ldap_entry_t *ep)
{
	int		j, k = 0;

	if (ep == NULL)
		return;

	if (ep->attr_pair == NULL) {
		free(ep);
		return;
	}
	for (j = 0; j < ep->attr_count; j++) {
		if (ep->attr_pair[j] == NULL)
			continue;
		if (ep->attr_pair[j]->attrname)
			free(ep->attr_pair[j]->attrname);
		if (ep->attr_pair[j]->attrvalue) {
			for (k = 0; (k < ep->attr_pair[j]->value_count) &&
			    (ep->attr_pair[j]->attrvalue[k]); k++) {
				free(ep->attr_pair[j]->attrvalue[k]);
			}
			free(ep->attr_pair[j]->attrvalue);
		}
		free(ep->attr_pair[j]);
	}
	free(ep->attr_pair);
	free(ep);
}

static int
addentry(void *entry, int mod)
{
	int		 result = 0;
	ns_ldap_error_t	 *eres = NULL;
	int		rc = 1;


	/*  adds entry into the LDAP tree */
	if (mod)
		result = __ns_ldap_addTypedEntry(databasetype, inputbasedn,
		    entry, 0, &authority, NS_LDAP_FOLLOWREF | NS_LDAP_KEEP_CONN,
		    &eres);
	else
		result = __ns_ldap_addTypedEntry(databasetype, inputbasedn,
		    entry, 1, &authority, NS_LDAP_FOLLOWREF | NS_LDAP_KEEP_CONN,
		    &eres);
	/*
	 *  Return	0 on success
	 *		LDAP_ALREADY_EXISTS if entry exists already
	 *		1 for all other non-fatal errors.
	 *  Exit on fatal errors.
	 */
	switch (result) {
	case NS_LDAP_SUCCESS:
		nent_add++;
		rc = 0;
		break;

	case NS_LDAP_OP_FAILED:
		(void) fprintf(stderr, gettext("operation failed.\n"));
		rc = 1;
		break;

	case NS_LDAP_INVALID_PARAM:
		(void) fprintf(stderr,
		    gettext("invalid parameter(s) passed.\n"));
		rc = 1;
		break;

	case NS_LDAP_NOTFOUND:
		(void) fprintf(stderr, gettext("entry not found.\n"));
		rc = 1;
		break;

	case NS_LDAP_MEMORY:
		(void) fprintf(stderr,
		    gettext("internal memory allocation error.\n"));
		exit(1);
		break;

	case NS_LDAP_CONFIG:
		(void) fprintf(stderr,
		    gettext("LDAP Configuration problem.\n"));
		perr(eres);
		exit(1);
		break;

	case NS_LDAP_PARTIAL:
		(void) fprintf(stderr,
		    gettext("partial result returned\n"));
		perr(eres);
		rc = 1;
		break;

	case NS_LDAP_INTERNAL:
		if (eres->status == LDAP_ALREADY_EXISTS ||
		    eres->status == LDAP_NO_SUCH_OBJECT)
			rc = eres->status;
		else if (eres->status == LDAP_INSUFFICIENT_ACCESS) {
			(void) fprintf(stderr,
			    gettext("The user does not have permission"
			    " to add/modify entries\n"));
			perr(eres);
			exit(1);
		} else {
			rc = 1;
			perr(eres);
		}
		break;
	}

	if (eres)
		(void) __ns_ldap_freeError(&eres);
	return (rc);
}

/*
 * usage(char *msg)
 * Display usage message to STDERR.
 */
static void
usage(char *msg) {

	if (msg)
		(void) fprintf(stderr, "%s\n", msg);

	(void) fprintf(stderr, gettext(
	"usage: ldapaddent [-cpv] [-a authenticationMethod] [-b baseDN]\n"
	"-D bindDN [-w bindPassword] [-j passwdFile] [-f filename]\n"
	"database\n"
	"\n"
	"usage: ldapaddent  [-cpv] -asasl/GSSAPI [-b baseDN] [-f filename]\n"
	"database\n"
	"\n"
	"usage: ldapaddent  -d [-v] [-a authenticationMethod] [-D bindDN]\n"
	"[-w bindPassword] [-j passwdFile] database\n"
	"\n"
	"usage: ldapaddent [-cpv] -h LDAP_server[:serverPort] [-M domainName]\n"
	"[-N  profileName]  [-P certifPath]  [-a authenticationMethod]\n"
	"[-b baseDN] -D bindDN [-w bindPassword] [-f filename]\n"
	"[-j passwdFile] database\n"
	"\n"
	"usage: ldapaddent [-cpv] -h LDAP_server[:serverPort] [-M domainName]\n"
	"[-N  profileName]  [-P certifPath] -asasl/GSSAPI  [-b baseDN]\n"
	"[-f filename] database\n"
	"\n"
	"usage: ldapaddent -d [-v] -h LDAP_server[:serverPort]"
	" [-M domainName]\n"
	"[-N profileName]  [-P certifPath]  [-a authenticationMethod]\n"
	"[-b baseDN] -D bindDN [-w bindPassword] [-j passwdFile]\n"
	"database\n"));
	exit(1);
}

/*
 * Determine if the given string is an IP address (IPv4 or IPv6).
 * If so, it's converted to the preferred form (rfc2373) and
 * *newaddr will point to the new address.
 *
 * Returns	-2		: inet_ntop error
 *		-1		: not an IP address
 *		0		: unsupported IP address (future use)
 *		AF_INET		: IPv4
 *		AF_INET6	: IPv6
 */
static int
check_ipaddr(char *addr, char **newaddr) {
	ipaddr_t	addr_ipv4 = 0;
	in6_addr_t	addr_ipv6;

	/* IPv6 */
	if (inet_pton(AF_INET6, addr, &addr_ipv6) == 1) {
		if (newaddr == NULL)
			return (AF_INET6);

		/* Convert IPv4-mapped IPv6 address to IPv4 */
		if (IN6_IS_ADDR_V4MAPPED(&addr_ipv6) ||
					IN6_IS_ADDR_V4COMPAT(&addr_ipv6)) {
			IN6_V4MAPPED_TO_IPADDR(&addr_ipv6, addr_ipv4);
			if ((*newaddr = calloc(1, INET_ADDRSTRLEN)) == NULL) {
				(void) fprintf(stderr,
				    gettext("out of memory\n"));
				exit(1);
			}
			if (inet_ntop(AF_INET, &addr_ipv4, *newaddr,
			    INET_ADDRSTRLEN))
				return (AF_INET6);
			free(*newaddr);
			return (-2);
		}

		/* Processing general IPv6 addresses */
		if ((*newaddr = calloc(1, INET6_ADDRSTRLEN)) == NULL) {
			(void) fprintf(stderr, gettext("out of memory\n"));
			exit(1);
		}
		if (inet_ntop(AF_INET6, &addr_ipv6, *newaddr, INET6_ADDRSTRLEN))
			return (AF_INET6);
		free(*newaddr);
		return (-2);
	}

	/* Processing IPv4 addresses of the type d.d.d.d. */
	if (inet_pton(AF_INET, addr, &addr_ipv4) == 1) {
		if (newaddr == NULL)
			return (AF_INET);
		if ((*newaddr = calloc(1, INET_ADDRSTRLEN)) == NULL) {
			(void) fprintf(stderr, gettext("out of memory\n"));
			exit(1);
		}
		if (inet_ntop(AF_INET, &addr_ipv4, *newaddr, INET_ADDRSTRLEN))
			return (AF_INET);
		free(*newaddr);
		return (-2);
	}

	/* Processing IPv4 addresses d.d.d , d.d and d */
	if (inet_addr(addr) != (in_addr_t)-1) {
		if (newaddr == NULL)
			return (AF_INET);
		if ((*newaddr = strdup(addr)) == NULL) {
			(void) fprintf(stderr, gettext("out of memory\n"));
			exit(1);
		}
		return (AF_INET);
	}

	return (-1);
}

/*
 * Verifies that project name meets the restrictions defined by project(4).
 */
static int
check_projname(char *addr)
{
	int i;
	if (addr == NULL || *addr == '\0')
		return (-1);

	for (i = 0; i < strlen(addr); i++) {
		if (!isalpha(addr[i]) &&
		    !isdigit(addr[i]) &&
		    addr[i] != '_' &&
		    addr[i] != '-' &&
		    addr[i] != '.')
			return (-1);
	}

	return (0);
}

static int
genent_hosts(char *line, int (*cback)())
{
	char buf[BUFSIZ+1];
	char *t, *comment;
	entry_col ecol[4];
	char *cname, *pref_addr;
	int ctr = 0, retval = 1;
	int rc = GENENT_OK, af;

	struct hostent  data;
	char *alias;

	/*
	 * don't clobber our argument
	 */
	if (strlen(line) >= sizeof (buf)) {
		(void) strlcpy(parse_err_msg, gettext("line too long"),
		    PARSE_ERR_MSG_LEN);
		return (GENENT_PARSEERR);
	}
	(void) strcpy(buf, line);

	/*
	 * clear column data
	 */
	(void) memset((char *)ecol, 0, sizeof (ecol));

	/*
	 * comment (col 3)
	 * All leading spaces will be deleted from the comment
	 */
	ecol[3].ec_value.ec_value_val = "";
	ecol[3].ec_value.ec_value_len = 0;
	comment = t = strchr(buf, '#');
	if (comment) {
		do {
			++comment;
		} while (*comment != '\0' && isspace(*comment));
		if (*comment != '\0') {
			*--comment = '#';
			ecol[3].ec_value.ec_value_val = strdup(comment);
			ecol[3].ec_value.ec_value_len = strlen(comment)+1;
		}

		*t = '\0';
	}

	/*
	 * addr(col 2)
	 */
	if ((t = strtok(buf, " \t")) == 0) {
		(void) strlcpy(parse_err_msg, gettext("no host"),
		    PARSE_ERR_MSG_LEN);
		return (GENENT_PARSEERR);
	}

	af = check_ipaddr(t, &pref_addr);
	if (af == -2) {
		(void) strlcpy(parse_err_msg, gettext("Internal error"),
		    PARSE_ERR_MSG_LEN);
	} else if (af == -1) {
		(void) snprintf(parse_err_msg, sizeof (parse_err_msg),
		    gettext("Invalid IP address: %s"), t);
	} else if (flags & F_VERBOSE) {
		if ((strncasecmp(t, pref_addr, strlen(t))) != 0) {
			(void) fprintf(stdout,
			    gettext("IP address %s converted to %s\n"),
			    t, pref_addr);
		}
	}

	if (af < 0) {
		(void) fprintf(stderr, "%s\n", parse_err_msg);
		if (continue_onerror == 0)
			return (GENENT_CBERR);
		else
			return (rc);
	}

	ecol[2].ec_value.ec_value_val = pref_addr;
	ecol[2].ec_value.ec_value_len = strlen(pref_addr)+1;

	/*
	 * cname (col 0)
	 */
	if ((t = strtok(NULL, " \t")) == 0) {
		(void) strlcpy(parse_err_msg, gettext("no cname"),
		    PARSE_ERR_MSG_LEN);
		return (GENENT_PARSEERR);
	}
	ecol[0].ec_value.ec_value_val = t;
	ecol[0].ec_value.ec_value_len = strlen(t)+1;
	cname = t;


	/* build entry */
	if ((data.h_addr_list = (char **)calloc(2, sizeof (char **))) == NULL) {
		(void) fprintf(stderr, gettext("out of memory\n"));
		exit(1);
	}
	data.h_addr_list[0] = strdup(ecol[2].ec_value.ec_value_val);
	data.h_addr_list[1] = NULL;

	free(pref_addr);
	data.h_name = strdup(ecol[0].ec_value.ec_value_val);

	/*
	 * name (col 1)
	 */

	data.h_aliases = NULL;

	do {
		/*
		 * don't clobber comment in canonical entry
		 */

		/* This call to AddEntry may move out of the loop */
		/* This is because we have to call the function just once */
		if (t != cname && strcasecmp(t, cname) == 0)
			continue;
		if (strcasecmp(t, ecol[0].ec_value.ec_value_val) == 0)
			continue;

		ecol[1].ec_value.ec_value_val = t;
		ecol[1].ec_value.ec_value_len = strlen(t)+1;

		ctr++;
		alias = strdup(ecol[1].ec_value.ec_value_val);
		if ((data.h_aliases = (char **)realloc(data.h_aliases,
		    ctr * sizeof (char **))) == NULL) {
			(void) fprintf(stderr, gettext("out of memory\n"));
			exit(1);
		}
		data.h_aliases[ctr-1] = alias;
	} while (t = strtok(NULL, " \t"));

	/*
	 * End the list of all the aliases by NULL
	 * If there is some comment, it will be stored as the last entry
	 * in the list of the host aliases
	 */
	if ((data.h_aliases = (char **)realloc(data.h_aliases,
	    (ecol[3].ec_value.ec_value_len != 0 ?
	    ctr + 2 : ctr + 1) * sizeof (char **))) == NULL) {
		(void) fprintf(stderr, gettext("out of memory\n"));
		exit(1);
	}

	if (ecol[3].ec_value.ec_value_len != 0) {
		data.h_aliases[ctr++] = ecol[3].ec_value.ec_value_val;
	}
	data.h_aliases[ctr] = NULL;

	if (flags & F_VERBOSE)
		(void) fprintf(stdout,
		    gettext("Adding entry : cn=%s+ipHostNumber=%s\n"),
		    data.h_name, data.h_addr_list[0]);

	retval = (*cback)(&data, 0);

	if (ecol[3].ec_value.ec_value_len != 0) {
		free(ecol[3].ec_value.ec_value_val);
	}

	if (retval == LDAP_ALREADY_EXISTS) {
		if (continue_onerror)
			(void) fprintf(stderr,
			    gettext("Entry: cn=%s+ipHostNumber=%s "
			    "already Exists -skipping it\n"),
			    data.h_name, data.h_addr_list[0]);
		else {
			rc = GENENT_CBERR;
			(void) fprintf(stderr,
			    gettext("Entry: cn=%s+ipHostNumber=%s"
			    " already Exists\n"),
			    data.h_name, data.h_addr_list[0]);
		}
	} else if (retval)
		rc = GENENT_CBERR;

	free(data.h_name);
	free(data.h_aliases);
	free(data.h_addr_list);

	return (rc);
}



static void
dump_hosts(ns_ldap_result_t *res)
{
	ns_ldap_attr_t	*attrptr = NULL,
	    *cn = NULL,
	    *iphostnumber = NULL,
	    *desc = NULL;
	int		 i, j;
	char		*name; /* host name */

	if (res == NULL || res->entry == NULL)
		return;
	for (i = 0; i < res->entry->attr_count; i++) {
		attrptr = res->entry->attr_pair[i];
		if (strcasecmp(attrptr->attrname, "cn") == 0)
			cn = attrptr;
		else if (strcasecmp(attrptr->attrname, "iphostnumber") == 0)
			iphostnumber = attrptr;
		else if (strcasecmp(attrptr->attrname, "description") == 0) {
			desc = attrptr;
		}
	}
	/* sanity check */
	if (cn == NULL || cn->attrvalue == NULL || cn->attrvalue[0] == NULL ||
	    iphostnumber == NULL || iphostnumber->attrvalue == NULL ||
	    iphostnumber->attrvalue[0] == NULL)
		return;

	if ((name = __s_api_get_canonical_name(res->entry, cn, 1)) == NULL)
		return;

	/* ip host/ipnode number */
	if (strlen(iphostnumber->attrvalue[0]) <= INET_ADDRSTRLEN)
		/* IPV4 or IPV6 but <= NET_ADDRSTRLEN */
		(void) fprintf(stdout, "%-18s", iphostnumber->attrvalue[0]);
	else
		/* IPV6 */
		(void) fprintf(stdout, "%-48s", iphostnumber->attrvalue[0]);

	/* host/ipnode name */
	(void) fprintf(stdout, "%s ", name);

	/* aliases */
	for (j = 0; j < cn->value_count; j++) {
		if (cn->attrvalue[j]) {
			if (strcasecmp(name, cn->attrvalue[j]) == 0)
				/* skip host name */
				continue;
			(void) fprintf(stdout, "%s ", cn->attrvalue[j]);
		}
	}

	/* description */
	if (desc != NULL && desc->attrvalue != NULL &&
	    desc->attrvalue[0] != NULL) {
		(void) fprintf(stdout, "#%s", desc->attrvalue[0]);
	}

	/* end of line */
	(void) fprintf(stdout, "\n");
}

/*
 * /etc/rpc
 */

static int
genent_rpc(char *line, int (*cback)())
{
	char buf[BUFSIZ+1];
	char *t;
	entry_col ecol[4];
	char *cname;

	struct rpcent	data;
	char *alias;
	int ctr = 0;
	int retval = 1;
	int rc = GENENT_OK;

	/*
	 * don't clobber our argument
	 */
	if (strlen(line) >= sizeof (buf)) {
		(void) strlcpy(parse_err_msg, gettext("line too long"),
		    PARSE_ERR_MSG_LEN);
		return (GENENT_PARSEERR);
	}
	(void) strcpy(buf, line);

	/*
	 * clear column data
	 */
	(void) memset((char *)ecol, 0, sizeof (ecol));

	/*
	 * comment (col 3)
	 */
	t = strchr(buf, '#');
	if (t) {
		*t++ = 0;
		ecol[3].ec_value.ec_value_val = t;
		ecol[3].ec_value.ec_value_len = strlen(t)+1;
	} else {
		ecol[3].ec_value.ec_value_val = 0;
		ecol[3].ec_value.ec_value_len = 0;
	}

	/*
	 * cname(col 0)
	 */
	if ((t = strtok(buf, " \t")) == 0) {
		(void) strlcpy(parse_err_msg, gettext("no number"),
		    PARSE_ERR_MSG_LEN);
		return (GENENT_PARSEERR);
	}
	ecol[0].ec_value.ec_value_val = t;
	ecol[0].ec_value.ec_value_len = strlen(t)+1;
	cname = t;

	/*
	 * number (col 2)
	 */
	if ((t = strtok(NULL, " \t")) == 0) {
		(void) strlcpy(parse_err_msg, gettext("no number"),
		    PARSE_ERR_MSG_LEN);
		return (GENENT_PARSEERR);
	}
	ecol[2].ec_value.ec_value_val = t;
	ecol[2].ec_value.ec_value_len = strlen(t)+1;


	/*
	 * build entry
	 */

	data.r_name = strdup(ecol[0].ec_value.ec_value_val);
	if (ecol[2].ec_value.ec_value_val != NULL &&
	    ecol[2].ec_value.ec_value_val[0] != '\0') {

		data.r_number = ascii_to_int(ecol[2].ec_value.ec_value_val);
		if (data.r_number == -1) {
			(void) snprintf(parse_err_msg, sizeof (parse_err_msg),
			    gettext("invalid program number: %s"),
			    ecol[2].ec_value.ec_value_val);
		return (GENENT_PARSEERR);
		}
	} else
		data.r_number = -1;

	/*
	 * name (col 1)
	 */
	t = cname;
	data.r_aliases = NULL;
	do {

		/*
		 * don't clobber comment in canonical entry
		 */
		if (t != cname && strcasecmp(t, cname) == 0)
			continue;
		if (strcasecmp(t, ecol[0].ec_value.ec_value_val) == 0)
			continue;

		ecol[1].ec_value.ec_value_val = t;
		ecol[1].ec_value.ec_value_len = strlen(t)+1;

		ctr++;
		alias = strdup(ecol[1].ec_value.ec_value_val);
		if ((data.r_aliases = (char **)realloc(data.r_aliases,
		    ctr * sizeof (char **))) == NULL) {
			(void) fprintf(stderr, gettext("out of memory\n"));
			exit(1);
		}
		data.r_aliases[ctr-1] = alias;


		/*
		 * only put comment in canonical entry
		 */
		ecol[3].ec_value.ec_value_val = 0;
		ecol[3].ec_value.ec_value_len = 0;

	} while (t = strtok(NULL, " \t"));

	/* End the list of all the aliases by NULL */
	if ((data.r_aliases = (char **)realloc(data.r_aliases,
	    (ctr + 1) * sizeof (char **))) == NULL) {
		(void) fprintf(stderr, gettext("out of memory\n"));
		exit(1);
	}
	data.r_aliases[ctr] = NULL;

	if (flags & F_VERBOSE)
		(void) fprintf(stdout,
		    gettext("Adding entry : %s\n"), data.r_name);

	retval = (*cback)(&data, 0);

	if (retval == LDAP_ALREADY_EXISTS) {
		if (continue_onerror)
			(void) fprintf(stderr,
			    gettext("Entry: %s - already Exists,"
			    " skipping it.\n"), data.r_name);
		else {
			rc = GENENT_CBERR;
			(void) fprintf(stderr,
			    gettext("Entry: %s - already Exists\n"),
			    data.r_name);
		}
	} else if (retval)
		rc = GENENT_CBERR;

	free(data.r_name);
	free(data.r_aliases);

	return (rc);
}



static void
dump_rpc(ns_ldap_result_t *res)
{
	ns_ldap_attr_t	*attrptr = NULL, *cn = NULL, *rpcnumber = NULL;
	int		 i, j;
	char		*name; /* rpc name */

	if (res == NULL || res->entry == NULL)
		return;
	for (i = 0; i < res->entry->attr_count; i++) {
		attrptr = res->entry->attr_pair[i];
		if (strcasecmp(attrptr->attrname, "cn") == 0)
			cn = attrptr;
		else if (strcasecmp(attrptr->attrname, "oncRpcNumber") == 0)
			rpcnumber = attrptr;
	}
	/* sanity check */
	if (cn == NULL || cn->attrvalue == NULL || cn->attrvalue[0] == NULL ||
	    rpcnumber == NULL || rpcnumber->attrvalue == NULL ||
	    rpcnumber->attrvalue[0] == NULL)
		return;

	if ((name = __s_api_get_canonical_name(res->entry, cn, 1)) == NULL)
		return;

	/* rpc name */
	if (strlen(name) < 8)
		(void) fprintf(stdout, "%s\t\t", name);
	else
		(void) fprintf(stdout, "%s\t", name);

	/* rpc number */
	(void) fprintf(stdout, "%-8s", rpcnumber->attrvalue[0]);


	/* aliases */
	for (j = 0; j < cn->value_count; j++) {
		if (cn->attrvalue[j]) {
			if (strcasecmp(name, cn->attrvalue[j]) == 0)
				/* skip rpc name */
				continue;
			(void) fprintf(stdout, "%s ", cn->attrvalue[j]);
		}
	}

	/* end of line */
	(void) fprintf(stdout, "\n");

}

/*
 * /etc/protocols
 *
 */

static int
genent_protocols(char *line, int (*cback)())
{
	char buf[BUFSIZ+1];
	char *t;
	entry_col ecol[4];
	char *cname;

	struct protoent	data;
	char *alias;
	int ctr = 0;
	int retval = 1;
	int rc = GENENT_OK;

	/*
	 * don't clobber our argument
	 */
	if (strlen(line) >= sizeof (buf)) {
		(void) strlcpy(parse_err_msg, gettext("line too long"),
		    PARSE_ERR_MSG_LEN);
		return (GENENT_PARSEERR);
	}
	(void) strcpy(buf, line);

	/*
	 * clear column data
	 */
	(void) memset((char *)ecol, 0, sizeof (ecol));

	/*
	 * comment (col 3)
	 */
	t = strchr(buf, '#');
	if (t) {
		*t++ = 0;
		ecol[3].ec_value.ec_value_val = t;
		ecol[3].ec_value.ec_value_len = strlen(t)+1;
	} else {
		ecol[3].ec_value.ec_value_val = 0;
		ecol[3].ec_value.ec_value_len = 0;
	}

	/*
	 * cname(col 0)
	 */
	if ((t = strtok(buf, " \t")) == 0) {
		(void) strlcpy(parse_err_msg, gettext("no number"),
		    PARSE_ERR_MSG_LEN);
		return (GENENT_PARSEERR);
	}
	ecol[0].ec_value.ec_value_val = t;
	ecol[0].ec_value.ec_value_len = strlen(t)+1;
	cname = t;

	/*
	 * number (col 2)
	 */
	if ((t = strtok(NULL, " \t")) == 0) {
		(void) strlcpy(parse_err_msg, gettext("no number"),
		    PARSE_ERR_MSG_LEN);
		return (GENENT_PARSEERR);
	}
	ecol[2].ec_value.ec_value_val = t;
	ecol[2].ec_value.ec_value_len = strlen(t)+1;


	/*
	 * build entry
	 */
	data.p_name = strdup(ecol[0].ec_value.ec_value_val);

	if (ecol[2].ec_value.ec_value_val != NULL &&
	    ecol[2].ec_value.ec_value_val[0] != '\0') {

		data.p_proto = ascii_to_int(ecol[2].ec_value.ec_value_val);
		if (data.p_proto == -1) {
			(void) snprintf(parse_err_msg, sizeof (parse_err_msg),
			    gettext("invalid protocol number: %s"),
			    ecol[2].ec_value.ec_value_val);
		return (GENENT_PARSEERR);
		}
	} else
		data.p_proto = -1;

	/*
	 * name (col 1)
	 */
	t = cname;
	ctr = 0;
	data.p_aliases = NULL;

	do {
		/*
		 * don't clobber comment in canonical entry
		 */
		if (t != cname && strcasecmp(t, cname) == 0)
			continue;
		if (strcasecmp(t, ecol[0].ec_value.ec_value_val) == 0)
			continue;

		ecol[1].ec_value.ec_value_val = t;
		ecol[1].ec_value.ec_value_len = strlen(t)+1;

		ctr++;
		alias = strdup(ecol[1].ec_value.ec_value_val);
		if ((data.p_aliases = (char **)realloc(data.p_aliases,
		    ctr * sizeof (char **))) == NULL) {
			(void) fprintf(stderr, gettext("out of memory\n"));
			exit(1);
		}
		data.p_aliases[ctr-1] = alias;

		/*
		 * only put comment in canonical entry
		 */
		ecol[3].ec_value.ec_value_val = 0;
		ecol[3].ec_value.ec_value_len = 0;

	} while (t = strtok(NULL, " \t"));

	/* End the list of all the aliases by NULL */
	if ((data.p_aliases = (char **)realloc(data.p_aliases,
	    (ctr + 1) * sizeof (char **))) == NULL) {
		(void) fprintf(stderr, gettext("out of memory\n"));
		exit(1);
	}
	data.p_aliases[ctr] = NULL;

	if (flags & F_VERBOSE)
		(void) fprintf(stdout,
		    gettext("Adding entry : %s\n"), data.p_name);

	retval = (*cback)(&data, 0);

	if (retval == LDAP_ALREADY_EXISTS) {
		if (continue_onerror)
			(void) fprintf(stderr,
			    gettext("Entry: %s - already Exists,"
			    " skipping it.\n"), data.p_name);
		else {
			rc = GENENT_CBERR;
			(void) fprintf(stderr,
			    gettext("Entry: %s - already Exists\n"),
			    data.p_name);
		}
	} else if (retval)
		rc = GENENT_CBERR;

	free(data.p_name);
	free(data.p_aliases);

	return (rc);
}


static void
dump_protocols(ns_ldap_result_t *res)
{
	ns_ldap_attr_t	*attrptr = NULL, *cn = NULL, *protocolnumber = NULL;
	int		 i, j;
	char		*name, *cp;

	if (res == NULL || res->entry == NULL)
		return;
	for (i = 0; i < res->entry->attr_count; i++) {
		attrptr = res->entry->attr_pair[i];
		if (strcasecmp(attrptr->attrname, "cn") == 0)
			cn = attrptr;
		else if (strcasecmp(attrptr->attrname, "ipProtocolNumber")
		    == 0)
			protocolnumber = attrptr;
	}
	/* sanity check */
	if (cn == NULL || cn->attrvalue == NULL || cn->attrvalue[0] == NULL ||
	    protocolnumber == NULL || protocolnumber->attrvalue == NULL ||
	    protocolnumber->attrvalue[0] == NULL)
		return;

	if ((name = __s_api_get_canonical_name(res->entry, cn, 1)) == NULL)
		return;

	/* protocol name */
	if (strlen(name) < 8)
		(void) fprintf(stdout, "%s\t\t", name);
	else
		(void) fprintf(stdout, "%s\t", name);

	/* protocol number */
	(void) fprintf(stdout, "%-16s", protocolnumber->attrvalue[0]);

	/* aliases */
	for (j = 0; j < cn->value_count; j++) {
		if (cn->attrvalue[j]) {
			if (strcasecmp(name, cn->attrvalue[j]) == 0) {
				if (cn->value_count > 1)
					/* Do not replicate */
					continue;
				/*
				 * Replicate name in uppercase as an aliase
				 */
				for (cp = cn->attrvalue[j]; *cp; cp++)
					*cp = toupper(*cp);
			}
			(void) fprintf(stdout, "%s ", cn->attrvalue[j]);
		}
	}

	/* end of line */
	(void) fprintf(stdout, "\n");

}





/*
 * /etc/networks
 *
 */

static int
genent_networks(char *line, int (*cback)())
{
	char buf[BUFSIZ+1];
	char *t;
	entry_col ecol[4];
	char *cname;

	struct netent	data;
	char *alias;
	int ctr = 0;
	int retval = 1;
	int enet;
	int rc = GENENT_OK;

	/*
	 * don't clobber our argument
	 */
	if (strlen(line) >= sizeof (buf)) {
		(void) strlcpy(parse_err_msg, gettext("line too long"),
		    PARSE_ERR_MSG_LEN);
		return (GENENT_PARSEERR);
	}
	(void) strcpy(buf, line);

	/*
	 * clear column data
	 */
	(void) memset((char *)ecol, 0, sizeof (ecol));

	/*
	 * comment (col 3)
	 */
	t = strchr(buf, '#');
	if (t) {
		*t++ = 0;
		ecol[3].ec_value.ec_value_val = t;
		ecol[3].ec_value.ec_value_len = strlen(t)+1;
	} else {
		ecol[3].ec_value.ec_value_val = 0;
		ecol[3].ec_value.ec_value_len = 0;
	}

	/*
	 * cname(col 0)
	 */
	if ((t = strtok(buf, " \t")) == 0) {
		(void) strlcpy(parse_err_msg, gettext("no number"),
		    PARSE_ERR_MSG_LEN);
		return (GENENT_PARSEERR);
	}
	ecol[0].ec_value.ec_value_val = t;
	ecol[0].ec_value.ec_value_len = strlen(t)+1;
	cname = t;

	/*
	 * number (col 2)
	 */
	if ((t = strtok(NULL, " \t")) == 0) {
		(void) strlcpy(parse_err_msg, gettext("no number"),
		    PARSE_ERR_MSG_LEN);
		return (GENENT_PARSEERR);
	}
	ecol[2].ec_value.ec_value_val = t;
	ecol[2].ec_value.ec_value_len = strlen(t)+1;


	/*
	 * build entry
	 */

	data.n_name = strdup(ecol[0].ec_value.ec_value_val);
	/*
	 * data.n_net is an unsigned field,
	 * assign -1 to it, make no sense.
	 * Use enet here to avoid lint warning.
	 */
	enet = encode_network(ecol[2].ec_value.ec_value_val);

	if (enet == -1 && continue_onerror == 0) {
		(void) fprintf(stderr, gettext("Invalid network number\n"));
		if (continue_onerror == 0)
			return (GENENT_CBERR);
	} else
		data.n_net = enet;

	/*
	 * name (col 1)
	 */
	t = cname;
	data.n_aliases = NULL;

	do {
		/*
		 * don't clobber comment in canonical entry
		 */
		if (t != cname && strcasecmp(t, cname) == 0)
			continue;
		if (strcasecmp(t, ecol[0].ec_value.ec_value_val) == 0)
			continue;

		ecol[1].ec_value.ec_value_val = t;
		ecol[1].ec_value.ec_value_len = strlen(t)+1;

		ctr++;
		alias = strdup(ecol[1].ec_value.ec_value_val);
		if ((data.n_aliases = (char **)realloc(data.n_aliases,
		    ctr * sizeof (char **))) == NULL) {
			(void) fprintf(stderr, gettext("out of memory\n"));
			exit(1);
		}
		data.n_aliases[ctr-1] = alias;

		/*
		 * only put comment in canonical entry
		 */
		ecol[3].ec_value.ec_value_val = 0;
		ecol[3].ec_value.ec_value_len = 0;

	} while (t = strtok(NULL, " \t"));

	/* End the list of all the aliases by NULL */
	if ((data.n_aliases = (char **)realloc(data.n_aliases,
	    (ctr + 1) * sizeof (char **))) == NULL) {
		(void) fprintf(stderr, gettext("out of memory\n"));
		exit(1);
	}
	data.n_aliases[ctr] = NULL;

	if (flags & F_VERBOSE)
		(void) fprintf(stdout,
		    gettext("Adding entry : %s\n"), data.n_name);

	retval = (*cback)(&data, 0);

	if (retval == LDAP_ALREADY_EXISTS) {
		if (continue_onerror)
			(void) fprintf(stderr,
			    gettext("Entry: %s - already Exists,"
			    " skipping it.\n"), data.n_name);
		else {
			rc = GENENT_CBERR;
			(void) fprintf(stderr,
			    gettext("Entry: %s - already Exists\n"),
			    data.n_name);
		}
	} else if (retval)
		rc = GENENT_CBERR;

	free(data.n_name);
	free(data.n_aliases);

	return (rc);
}


static void
dump_networks(ns_ldap_result_t *res)
{
	ns_ldap_attr_t	*attrptr = NULL, *cn = NULL, *networknumber = NULL;
	int		 i, j;
	char		*name;

	if (res == NULL || res->entry == NULL)
		return;
	for (i = 0; i < res->entry->attr_count; i++) {
		attrptr = res->entry->attr_pair[i];
		if (strcasecmp(attrptr->attrname, "cn") == 0)
			cn = attrptr;
		else if (strcasecmp(attrptr->attrname, "ipNetworkNumber")
		    == 0)
			networknumber = attrptr;
	}
	/* sanity check */
	if (cn == NULL || cn->attrvalue == NULL || cn->attrvalue[0] == NULL ||
	    networknumber == NULL || networknumber->attrvalue == NULL ||
	    networknumber->attrvalue[0] == NULL)
		return;

	/*
	 * cn can be a MUST attribute(RFC 2307) or MAY attribute(2307bis).
	 * If the canonical name can not be found (2307bis), use the 1st
	 * value as the official name.
	 */

	/* network name */
	if ((name = __s_api_get_canonical_name(res->entry, cn, 1)) == NULL)
		name = cn->attrvalue[0];

	if (strlen(name) < 8)
		(void) fprintf(stdout, "%s\t\t", name);
	else
		(void) fprintf(stdout, "%s\t", name);

	/* network number */
	(void) fprintf(stdout, "%-16s", networknumber->attrvalue[0]);

	/* aliases */
	for (j = 0; j < cn->value_count; j++) {
		if (cn->attrvalue[j]) {
			if (strcasecmp(name, cn->attrvalue[j]) == 0)
				/* skip name */
				continue;
			(void) fprintf(stdout, "%s ", cn->attrvalue[j]);
		}
	}

	/* end of line */
	(void) fprintf(stdout, "\n");

}




/*
 * /etc/services
 *
 */

static int
genent_services(char *line, int (*cback)())
{
	char buf[BUFSIZ+1];
	char *t, *p;
	entry_col ecol[5];
	char *cname;

	struct servent	data;
	char *alias;
	int ctr = 0;
	int retval = 1;
	int rc = GENENT_OK;

	/*
	 * don't clobber our argument
	 */
	if (strlen(line) >= sizeof (buf)) {
		(void) strlcpy(parse_err_msg, gettext("line too long"),
		    PARSE_ERR_MSG_LEN);
		return (GENENT_PARSEERR);
	}
	(void) strcpy(buf, line);

	/*
	 * clear column data
	 */
	(void) memset((char *)ecol, 0, sizeof (ecol));

	/*
	 * comment (col 4)
	 */
	t = strchr(buf, '#');
	if (t) {
		*t++ = 0;
		ecol[4].ec_value.ec_value_val = t;
		ecol[4].ec_value.ec_value_len = strlen(t)+1;
	} else {
		ecol[4].ec_value.ec_value_val = 0;
		ecol[4].ec_value.ec_value_len = 0;
	}

	/*
	 * cname(col 0)
	 */
	if ((t = strtok(buf, " \t")) == 0) {
		(void) strlcpy(parse_err_msg, gettext("no port"),
		    PARSE_ERR_MSG_LEN);
		return (GENENT_PARSEERR);
	}
	ecol[0].ec_value.ec_value_val = t;
	ecol[0].ec_value.ec_value_len = strlen(t)+1;
	cname = t;

	/*
	 * port (col 3)
	 */
	if ((t = strtok(NULL, " \t")) == 0) {
		(void) strlcpy(parse_err_msg, gettext("no protocol"),
		    PARSE_ERR_MSG_LEN);
		return (GENENT_PARSEERR);
	}
	if ((p = strchr(t, '/')) == 0) {
		(void) strlcpy(parse_err_msg, gettext("bad port/proto"),
		    PARSE_ERR_MSG_LEN);
		return (GENENT_PARSEERR);
	}
	*(p++) = 0;
	ecol[3].ec_value.ec_value_val = t;
	ecol[3].ec_value.ec_value_len = strlen(t)+1;

	/*
	 * proto (col 2)
	 */
	ecol[2].ec_value.ec_value_val = p;
	ecol[2].ec_value.ec_value_len = strlen(p)+1;


	/*
	 * build entry
	 */

	data.s_name = strdup(ecol[0].ec_value.ec_value_val);
	data.s_proto = strdup(ecol[2].ec_value.ec_value_val);

	if (ecol[3].ec_value.ec_value_val != NULL &&
	    ecol[3].ec_value.ec_value_val[0] != '\0') {

		data.s_port = ascii_to_int(ecol[3].ec_value.ec_value_val);
		if (data.s_port == -1) {
			(void) snprintf(parse_err_msg, sizeof (parse_err_msg),
			    gettext("invalid port number: %s"),
			    ecol[3].ec_value.ec_value_val);
		return (GENENT_PARSEERR);
		}
	} else
		data.s_port = -1;

	/*
	 * name (col 1)
	 */
	t = cname;
	data.s_aliases = NULL;

	do {
		/*
		 * don't clobber comment in canonical entry
		 */
		if (t != cname && strcasecmp(t, cname) == 0)
			continue;
		if (strcasecmp(t, ecol[0].ec_value.ec_value_val) == 0)
			continue;

		ecol[1].ec_value.ec_value_val = t;
		ecol[1].ec_value.ec_value_len = strlen(t)+1;

		ctr++;
		alias = strdup(ecol[1].ec_value.ec_value_val);
		if ((data.s_aliases = (char **)realloc(data.s_aliases,
		    ctr * sizeof (char **))) == NULL) {
			(void) fprintf(stderr, gettext("out of memory\n"));
			exit(1);
		}
		data.s_aliases[ctr-1] = alias;

		/*
		 * only put comment in canonical entry
		 */
		ecol[4].ec_value.ec_value_val = 0;
		ecol[4].ec_value.ec_value_len = 0;

	} while (t = strtok(NULL, " \t"));

	/* End the list of all the aliases by NULL */
	if ((data.s_aliases = (char **)realloc(data.s_aliases,
	    (ctr + 1) * sizeof (char **))) == NULL) {
		(void) fprintf(stderr, gettext("out of memory\n"));
		exit(1);
	}
	data.s_aliases[ctr] = NULL;

	if (flags & F_VERBOSE)
		(void) fprintf(stdout,
		    gettext("Adding entry : %s\n"), line);

	retval = (*cback)(&data, 0);

	if (retval == LDAP_ALREADY_EXISTS) {
		if (continue_onerror)
			(void) fprintf(stderr, gettext(
			    "Entry: cn=%s+ipServiceProtocol=%s"
			    " already Exists, skipping it.\n"),
			    data.s_name, data.s_proto);
		else {
			rc = GENENT_CBERR;
			(void) fprintf(stderr,
			    gettext("Entry: cn=%s+ipServiceProtocol=%s"
			    " - already Exists\n"),
			    data.s_name, data.s_proto);
		}
	} else if (retval)
		rc = GENENT_CBERR;

	free(data.s_name);
	free(data.s_proto);
	free(data.s_aliases);

	return (rc);
}



static void
dump_services(ns_ldap_result_t *res)
{
	ns_ldap_attr_t	*attrptr = NULL, *cn = NULL, *port = NULL;
	ns_ldap_attr_t	*protocol = NULL;
	int		i, j, len;
	char		*name; /* service name */

	/*
	 * cn can have multiple values.(service name and its aliases)
	 * In order to support RFC 2307, section 5.5, ipserviceprotocol  can
	 * have multiple values too.
	 * The output format should look like
	 *
	 * test		2345/udp mytest
	 * test		2345/tcp mytest
	 */
	if (res == NULL || res->entry == NULL)
		return;
	for (i = 0; i < res->entry->attr_count; i++) {
		attrptr = res->entry->attr_pair[i];
		if (strcasecmp(attrptr->attrname, "cn") == 0)
			cn = attrptr;
		else if (strcasecmp(attrptr->attrname, "ipServicePort") == 0)
			port = attrptr;
		else if (strcasecmp(attrptr->attrname,
		    "ipServiceProtocol") == 0)
			protocol = attrptr;
	}
	/* sanity check */
	if (cn == NULL || cn->attrvalue == NULL || cn->attrvalue[0] == NULL ||
	    port == NULL || port->attrvalue == NULL ||
	    port->attrvalue[0] == NULL || protocol == NULL ||
	    protocol->attrvalue == NULL || protocol->attrvalue[0] == NULL)
		return;

	if ((name = __s_api_get_canonical_name(res->entry, cn, 1)) == NULL)
		return;
	for (i = 0; i < protocol->value_count; i++) {
		if (protocol->attrvalue[i] == NULL)
			return;
		/* service name */
		(void) fprintf(stdout, "%-16s", name);

		/* port & protocol */
		(void) fprintf(stdout, "%s/%s%n", port->attrvalue[0],
		    protocol->attrvalue[i], &len);

		if (len < 8)
			(void) fprintf(stdout, "\t\t");
		else
			(void) fprintf(stdout, "\t");

		/* aliases */
		for (j = 0; j < cn->value_count; j++) {
			if (cn->attrvalue[j]) {
				if (strcasecmp(name, cn->attrvalue[j]) == 0)
					/* skip service name */
					continue;
				(void) fprintf(stdout, "%s ", cn->attrvalue[j]);
			}
		}

		/* end of line */
		(void) fprintf(stdout, "\n");
	}
}


/*
 * /etc/group
 */

static int
genent_group(char *line, int (*cback)())
{
	char buf[BIGBUF+1];
	char *s, *t;
	entry_col ecol[5];

	struct group	data;
	int ctr = 0;
	int retval = 1;
	int rc = GENENT_OK;

	/*
	 * don't clobber our argument
	 */
	if (strlen(line) >= sizeof (buf)) {
		(void) strlcpy(parse_err_msg, gettext("line too long"),
		    PARSE_ERR_MSG_LEN);
		return (GENENT_PARSEERR);
	}
	(void) strcpy(buf, line);
	t = buf;

	/* ignore empty entries */
	if (*t == '\0')
		return (GENENT_OK);

	/*
	 * clear column data
	 */
	(void) memset((char *)ecol, 0, sizeof (ecol));

	/*
	 * name (col 0)
	 */
	if ((s = strchr(t, ':')) == 0) {
		(void) strlcpy(parse_err_msg, gettext("no passwd"),
		    PARSE_ERR_MSG_LEN);
		return (GENENT_PARSEERR);
	}
	*s++ = 0;
	ecol[0].ec_value.ec_value_val = t;
	ecol[0].ec_value.ec_value_len = strlen(t)+1;
	t = s;

	/*
	 * passwd (col 1)
	 */
	if ((s = strchr(t, ':')) == 0) {
		(void) strlcpy(parse_err_msg, gettext("no gid"),
		    PARSE_ERR_MSG_LEN);
		return (GENENT_PARSEERR);
	}
	*s++ = 0;
	ecol[1].ec_value.ec_value_val = t;
	ecol[1].ec_value.ec_value_len = strlen(t)+1;
	t = s;


	/*
	 * gid (col 2)
	 */
	if ((s = strchr(t, ':')) == 0 || s == t) {
		(void) strlcpy(parse_err_msg, gettext("no members"),
		    PARSE_ERR_MSG_LEN);
		return (GENENT_PARSEERR);
	}
	*s++ = 0;
	ecol[2].ec_value.ec_value_val = t;
	ecol[2].ec_value.ec_value_len = strlen(t)+1;
	t = s;

	/*
	 * members (col 3)
	 */
	ecol[3].ec_value.ec_value_val = t;
	ecol[3].ec_value.ec_value_len = strlen(t)+1;


	/*
	 * build entry
	 */
	data.gr_name = strdup(ecol[0].ec_value.ec_value_val);
	data.gr_passwd = strdup(ecol[1].ec_value.ec_value_val);
	if (ecol[2].ec_value.ec_value_val != NULL &&
	    ecol[2].ec_value.ec_value_val[0] != '\0') {

		data.gr_gid = ascii_to_int(ecol[2].ec_value.ec_value_val);
		if (data.gr_gid == (uid_t)-1) {
			(void) snprintf(parse_err_msg, sizeof (parse_err_msg),
			    gettext("invalid group id: %s"),
			    ecol[2].ec_value.ec_value_val);
		return (GENENT_PARSEERR);
		}
	} else
		data.gr_gid = (uid_t)-1;

	data.gr_mem = NULL;

	/* Compute maximum amount of members */
	s = t;
	while (s = strchr(s, ',')) {
		s++;
		ctr++;
	}

	/* Allocate memory for all members */
	data.gr_mem = calloc(ctr + 2, sizeof (char **));
	if (data.gr_mem == NULL) {
		(void) fprintf(stderr, gettext("out of memory\n"));
		exit(1);
	}

	ctr = 0;
	while (s = strchr(t, ',')) {

		*s++ = 0;
		ecol[3].ec_value.ec_value_val = t;
		t = s;
		/* Send to server only non empty member names */
		if (strlen(ecol[3].ec_value.ec_value_val) != 0)
			data.gr_mem[ctr++] = ecol[3].ec_value.ec_value_val;
	}

	/* Send to server only non empty member names */
	if (strlen(t) != 0)
		data.gr_mem[ctr++] = t;

	/* Array of members completed, finished by NULL, see calloc() */

	if (flags & F_VERBOSE)
		(void) fprintf(stdout,
		    gettext("Adding entry : %s\n"), data.gr_name);

	retval = (*cback)(&data, 0);

	if (retval == LDAP_ALREADY_EXISTS) {
		if (continue_onerror)
			(void) fprintf(stderr,
			    gettext("Entry: %s - already Exists,"
			    " skipping it.\n"), data.gr_name);
		else {
			rc = GENENT_CBERR;
			(void) fprintf(stderr,
			    gettext("Entry: %s - already Exists\n"),
			    data.gr_name);
		}
	} else if (retval)
		rc = GENENT_CBERR;

	free(data.gr_name);
	free(data.gr_passwd);
	free(data.gr_mem);

	return (rc);
}

static void
dump_group(ns_ldap_result_t *res)
{
	char    **value = NULL;
	char	pnam[256];
	int	attr_count = 0;

	value = __ns_ldap_getAttr(res->entry, "cn");
	if (value && value[0])
		(void) fprintf(stdout, "%s:", value[0]);
	value = __ns_ldap_getAttr(res->entry, "userPassword");
	if (value == NULL || value[0] == NULL)
		(void) fprintf(stdout, "*:");
	else {
		(void) strcpy(pnam, value[0]);
		if (strncasecmp(value[0], "{crypt}", 7) == 0)
			(void) fprintf(stdout, "%s:", (pnam+7));
		else
			(void) fprintf(stdout, "*:");
	}
	value = __ns_ldap_getAttr(res->entry, "gidNumber");
	if (value && value[0])
		(void) fprintf(stdout, "%s:", value[0]);

	value = __ns_ldap_getAttr(res->entry, "memberUid");
	if (value != NULL && value[0] != NULL) {
		while (value[attr_count] != NULL) {
			if (value[attr_count+1] == NULL)
				(void) fprintf(stdout, "%s", value[attr_count]);
			else
				(void) fprintf(stdout, "%s,",
				    value[attr_count]);
			attr_count++;
		}
		(void) fprintf(stdout, "\n");
	}
	else
		(void) fprintf(stdout, "\n");
}





/*
 * /etc/ethers
 */

static int
genent_ethers(char *line, int (*cback)())
{
	char buf[BUFSIZ+1];
	char *t;
	entry_col ecol[3];
	int retval = 1;
	struct _ns_ethers	data;
	int rc = GENENT_OK;

	/*
	 * don't clobber our argument
	 */
	if (strlen(line) >= sizeof (buf)) {
		(void) strlcpy(parse_err_msg, gettext("line too long"),
		    PARSE_ERR_MSG_LEN);
		return (GENENT_PARSEERR);
	}
	(void) strcpy(buf, line);

	/*
	 * clear column data
	 */
	(void) memset((char *)ecol, 0, sizeof (ecol));

	/*
	 * comment (col 2)
	 */
	t = strchr(buf, '#');
	if (t) {
		*t++ = 0;
		ecol[2].ec_value.ec_value_val = t;
		ecol[2].ec_value.ec_value_len = strlen(t)+1;
	} else {
		ecol[2].ec_value.ec_value_val = 0;
		ecol[2].ec_value.ec_value_len = 0;
	}

	/*
	 * addr(col 0)
	 */
	if ((t = strtok(buf, " \t")) == 0) {
		(void) strlcpy(parse_err_msg, gettext("no name"),
		    PARSE_ERR_MSG_LEN);
		return (GENENT_PARSEERR);
	}
	ecol[0].ec_value.ec_value_val = t;
	ecol[0].ec_value.ec_value_len = strlen(t)+1;

	/*
	 * name(col 1)
	 */
	if ((t = strtok(NULL, " \t")) == 0) {
		(void) strlcpy(parse_err_msg,
		    gettext("no white space allowed in name"),
		    PARSE_ERR_MSG_LEN);
		return (GENENT_PARSEERR);
	}
	ecol[1].ec_value.ec_value_val = t;
	ecol[1].ec_value.ec_value_len = strlen(t)+1;


	/*
	 * build entry
	 */

	data.ether = strdup(ecol[0].ec_value.ec_value_val);
	data.name  = strdup(ecol[1].ec_value.ec_value_val);


	if (flags & F_VERBOSE)
		(void) fprintf(stdout,
		    gettext("Adding entry : %s\n"), data.name);

	retval = (*cback)(&data, 0);

	if (retval == LDAP_ALREADY_EXISTS) {
		if (continue_onerror)
			(void) fprintf(stderr,
			    gettext("Entry: %s - already Exists,"
			    " skipping it.\n"), data.name);
		else {
			rc = GENENT_CBERR;
			(void) fprintf(stderr,
			    gettext("Entry: %s - already Exists\n"),
			    data.name);
		}
	} else if (retval)
		rc = GENENT_CBERR;

	free(data.ether);
	free(data.name);

	return (rc);
}


static void
dump_ethers(ns_ldap_result_t *res)
{
	char	**value = NULL;

	value = __ns_ldap_getAttr(res->entry, "macAddress");
	if (value && value[0])
		(void) fprintf(stdout, "%s", value[0]);
	else
		return;
	value = __ns_ldap_getAttr(res->entry, "cn");
	if (value && value[0])
		(void) fprintf(stdout, "	%s\n", value[0]);
}

static int
genent_aliases(char *line, int (*cback)())
{
	char buf[BUFSIZ+1];
	char *t, *aliases;
	char *cname;
	int ctr = 0;
	int retval = 1;
	int i;

	struct _ns_alias data;
	char *alias;
	int rc = GENENT_OK;

	/*
	 * don't clobber our argument
	 */
	if (strlen(line) >= sizeof (buf)) {
		(void) strlcpy(parse_err_msg, gettext("line too long"),
		    PARSE_ERR_MSG_LEN);
		return (GENENT_PARSEERR);
	}

	(void) strcpy(buf, line);

	if ((t = strchr(buf, ':')) == 0) {
		(void) strlcpy(parse_err_msg, gettext("no alias name"),
		    PARSE_ERR_MSG_LEN);
		return (GENENT_PARSEERR);
	}

	t[0] = '\0';
	if ((++t)[0] == '\0') {
		(void) strlcpy(parse_err_msg, gettext("no alias value"),
		    PARSE_ERR_MSG_LEN);
		return (GENENT_PARSEERR);
	}

	cname = buf;
	aliases = t;

	/* build entry */
	data.alias = strdup(cname);
	if (!data.alias) {
		(void) fprintf(stderr, gettext("out of memory\n"));
		exit(1);
	}

	data.member = NULL;
	t = strtok(aliases, ",");
	do {
		ctr++;
		while (t[0] == ' ')
			t++;
		alias = strdup(t);
		if ((alias == NULL) ||
		    ((data.member = (char **)realloc(data.member,
		    (ctr + 1) * sizeof (char **))) == NULL)) {
			(void) fprintf(stderr, gettext("out of memory\n"));
			exit(1);
		}
		data.member[ctr-1] = alias;

	} while (t = strtok(NULL, ","));

	data.member[ctr] = NULL;

	if (flags & F_VERBOSE)
		(void) fprintf(stdout,
		    gettext("Adding entry : %s\n"), data.alias);

	retval = (*cback)(&data, 0);

	if (retval == LDAP_ALREADY_EXISTS) {
		if (continue_onerror)
			(void) fprintf(stderr,
			    gettext("Entry: %s - already Exists,"
			    " skipping it.\n"), data.alias);
		else {
			rc = GENENT_CBERR;
			(void) fprintf(stderr,
			    gettext("Entry: %s - already Exists\n"),
			    data.alias);
		}
	} else if (retval)
		rc = GENENT_CBERR;

	free(data.alias);
	i = 0;
	while (data.member[i])
		free(data.member[i++]);
	free(data.member);

	return (rc);
}


static void
dump_aliases(ns_ldap_result_t *res)
{

	char	**value = NULL;
	int 		attr_count = 0;

	value = __ns_ldap_getAttr(res->entry, "mail");
	if (value && value[0])
		(void) fprintf(stdout, "%s:", value[0]);
	value = __ns_ldap_getAttr(res->entry, "mgrpRFC822MailMember");
	if (value != NULL)
		while (value[attr_count] != NULL) {
			(void) fprintf(stdout, "%s,", value[attr_count]);
			attr_count++;
		}
	(void) fprintf(stdout, "\n");

}

/*
 * /etc/publickey
 */

static char *h_errno2str(int h_errno);

static int
genent_publickey(char *line, int (*cback)())
{
	char buf[BUFSIZ+1], tmpbuf[BUFSIZ+1], cname[BUFSIZ+1];
	char *t, *p, *tmppubkey, *tmpprivkey;
	entry_col ecol[3];
	int buflen, uid, retval = 1, errnum = 0;
	struct passwd *pwd;
	char auth_type[BUFSIZ+1], *dot;
	keylen_t keylen;
	algtype_t algtype;
	struct _ns_pubkey data;
	struct hostent *hp;
	struct in_addr in;
	struct in6_addr in6;
	char abuf[INET6_ADDRSTRLEN];

	/*
	 * don't clobber our argument
	 */
	if (strlen(line) >= sizeof (buf)) {
		(void) strlcpy(parse_err_msg, gettext("line too long"),
		    PARSE_ERR_MSG_LEN);
		return (GENENT_PARSEERR);
	}
	(void) strcpy(buf, line);

	/*
	 * clear column data
	 */
	(void) memset((char *)ecol, 0, sizeof (ecol));

	if ((t = strtok(buf, " \t")) == 0) {
		(void) strlcpy(parse_err_msg, gettext("no cname"),
		    PARSE_ERR_MSG_LEN);
		return (GENENT_PARSEERR);
	}

	/*
	 * Special case:  /etc/publickey usually has an entry
	 * for principal "nobody".  We skip it.
	 */
	if (strcmp(t, "nobody") == 0)
		return (GENENT_OK);

	/*
	 * cname (col 0)
	 */
	if (strncmp(t, "unix.", 5)) {
		(void) strlcpy(parse_err_msg, gettext("bad cname"),
		    PARSE_ERR_MSG_LEN);
		return (GENENT_PARSEERR);
	}
	(void) strcpy(tmpbuf, &(t[5]));
	if ((p = strchr(tmpbuf, '@')) == 0) {
		(void) strlcpy(parse_err_msg, gettext("bad cname"),
		    PARSE_ERR_MSG_LEN);
		return (GENENT_PARSEERR);
	}
	*(p++) = 0;
	if (isdigit(*tmpbuf)) {

		uid = atoi(tmpbuf);
		/*
		 * don't generate entries for uids without passwd entries
		 */
		if ((pwd = getpwuid(uid)) == 0) {
			(void) fprintf(stderr,
			gettext("can't map uid %d to username, skipping\n"),
			    uid);
			return (GENENT_OK);
		}
		(void) strcpy(cname, pwd->pw_name);
		data.hostcred = NS_HOSTCRED_FALSE;
	} else {
		if ((hp = getipnodebyname(tmpbuf, AF_INET6,
		    AI_ALL | AI_V4MAPPED, &errnum)) == NULL) {
			(void) fprintf(stderr,
			    gettext("can't map hostname %s to hostaddress, "
			    "errnum %d %s skipping\n"), tmpbuf, errnum,
			    h_errno2str(errnum));
			return (GENENT_OK);
		}
		(void) memcpy((char *)&in6.s6_addr, hp->h_addr_list[0],
		    hp->h_length);
		if (IN6_IS_ADDR_V4MAPPED(&in6) ||
		    IN6_IS_ADDR_V4COMPAT(&in6)) {
			IN6_V4MAPPED_TO_INADDR(&in6, &in);
			if (inet_ntop(AF_INET, (const void *)&in, abuf,
			    INET6_ADDRSTRLEN) == NULL) {
				(void) fprintf(stderr,
				    gettext("can't convert IPV4 address of"
				    " hostname %s to string, "
				    "skipping\n"), tmpbuf);
					return (GENENT_OK);
			}
		} else {
			if (inet_ntop(AF_INET6, (const void *)&in6, abuf,
			    INET6_ADDRSTRLEN) == NULL) {
				(void) fprintf(stderr,
				    gettext("can't convert IPV6 address of"
				    " hostname %s to string, "
				    "skipping\n"), tmpbuf);
					return (GENENT_OK);
			}
		}
		data.hostcred = NS_HOSTCRED_TRUE;
		/*
		 * tmpbuf could be an alias, use hp->h_name instead.
		 * hp->h_name is in FQDN format, so extract 1st field.
		 */
		if ((dot = strchr(hp->h_name, '.')) != NULL)
			*dot = '\0';
		(void) snprintf(cname, sizeof (cname),
		    "%s+ipHostNumber=%s", hp->h_name, abuf);
		if (dot)
			*dot = '.';
	}

	ecol[0].ec_value.ec_value_val = cname;
	ecol[0].ec_value.ec_value_len = strlen(cname)+1;

	/*
	 * public_data (col 1)
	 */
	if ((t = strtok(NULL, " \t")) == 0) {
		(void) strlcpy(parse_err_msg, gettext("no private_data"),
		    PARSE_ERR_MSG_LEN);
		return (GENENT_PARSEERR);
	}
	if ((p = strchr(t, ':')) == 0) {
		(void) strlcpy(parse_err_msg, gettext("bad public_data"),
		    PARSE_ERR_MSG_LEN);
		return (GENENT_PARSEERR);
	}
	*(p++) = 0;
	ecol[1].ec_value.ec_value_val = t;
	ecol[1].ec_value.ec_value_len = strlen(t)+1;
	keylen = (strlen(t) / 2) * 8;

	/*
	 * private_data (col 2) and algtype extraction
	 */
	if (*p == ':')
		p++;
	t = p;
	if (!(t = strchr(t, ':'))) {
		(void) fprintf(stderr,
		    gettext("WARNING: No algorithm type data found "
		    "in publickey file, assuming 0\n"));
		algtype = 0;
	} else {
		*t = '\0';
		t++;
		algtype = atoi(t);
	}
	ecol[2].ec_value.ec_value_val = p;
	ecol[2].ec_value.ec_value_len = strlen(p)+1;

	/*
	 * auth_type (col 1)
	 */
	if (AUTH_DES_KEY(keylen, algtype))
		/*
		 * {DES} and {DH192-0} means same thing.
		 * However, nisplus uses "DES" and ldap uses "DH192-0"
		 * internally.
		 * See newkey(1M), __nis_mechalias2authtype() which is
		 * called by __nis_keyalg2authtype() and getkey_ldap_g()
		 */
		(void) strlcpy(auth_type, "DH192-0", BUFSIZ+1);
	else if (!(__nis_keyalg2authtype(keylen, algtype, auth_type,
	    MECH_MAXATNAME))) {
		(void) fprintf(stderr,
		    gettext("Could not convert algorithm type to "
		    "corresponding auth type string\n"));
		return (GENENT_ERR);
	}

	/*
	 * build entry
	 */
	data.name = strdup(ecol[0].ec_value.ec_value_val);
	if (data.name == NULL) {
		(void) fprintf(stderr, gettext("out of memory\n"));
		exit(1);
	}

	buflen = sizeof (auth_type) + strlen(ecol[1].ec_value.ec_value_val) + 3;
	if ((tmppubkey = (char *)malloc(buflen)) == NULL) {
		(void) fprintf(stderr, gettext("out of memory\n"));
		exit(1);
	}
	(void) snprintf(tmppubkey, buflen, "{%s}%s", auth_type,
	    ecol[1].ec_value.ec_value_val);
	data.pubkey = tmppubkey;

	buflen = sizeof (auth_type) + strlen(ecol[2].ec_value.ec_value_val) + 3;
	if ((tmpprivkey = (char *)malloc(buflen)) == NULL) {
		(void) fprintf(stderr, gettext("out of memory\n"));
		exit(1);
	}

	(void) snprintf(tmpprivkey, buflen, "{%s}%s", auth_type,
	    ecol[2].ec_value.ec_value_val);
	data.privkey = tmpprivkey;

	retval = (*cback)(&data, 1);
	if (retval != NS_LDAP_SUCCESS) {
		if (retval == LDAP_NO_SUCH_OBJECT) {
			if (data.hostcred == NS_HOSTCRED_TRUE)
				(void) fprintf(stdout,
				    gettext("Cannot add publickey entry"" (%s),"
				    " add host entry first\n"),
				    tmpbuf);
			else
				(void) fprintf(stdout,
				    gettext("Cannot add publickey entry (%s), "
				    "add passwd entry first\n"),
				    data.name);
		}
		if (continue_onerror == 0)
			return (GENENT_CBERR);
	}

	free(data.name);
	free(data.pubkey);
	free(data.privkey);
	return (GENENT_OK);
}

static void
dump_publickey(ns_ldap_result_t *res, char *container)
{
	char	**value = NULL;
	char	buf[BUFSIZ];
	char	domainname[BUFSIZ];
	char	*pubptr, *prvptr;

	if (res == NULL)
		return;

	if (sysinfo(SI_SRPC_DOMAIN, domainname, BUFSIZ) < 0) {
		(void) fprintf(stderr,
		    gettext("could not obtain domainname\n"));
		exit(1);
	}

	/*
	 * Retrieve all the attributes, but don't print
	 * until we have all the required ones.
	 */

	if (strcmp(container, "passwd") == 0)
		value = __ns_ldap_getAttr(res->entry, "uidNumber");
	else
		value = __ns_ldap_getAttr(res->entry, "cn");

	if (value && value[0])
		(void) snprintf(buf, sizeof (buf), "unix.%s@%s",
		    value[0], domainname);
	else
		return;

	value = __ns_ldap_getAttr(res->entry, "nisPublickey");
	if (value != NULL && value[0] != NULL) {
		if ((pubptr = strchr(value[0], '}')) == NULL)
			return;
	}

	value = __ns_ldap_getAttr(res->entry, "nisSecretkey");
	if (value != NULL && value[0] != NULL)
		if ((prvptr = strchr(value[0], '}')) == NULL)
			return;

	/* print the attributes, algorithm type is always 0 */
	(void) fprintf(stdout, "%s	%s:%s:0\n", buf, ++pubptr, ++prvptr);
}



/*
 * /etc/netmasks
 */

static int
genent_netmasks(char *line, int (*cback)())
{
	char buf[BUFSIZ+1];
	char *t;
	entry_col ecol[3];
	int retval;

	struct _ns_netmasks data;


	/*
	 * don't clobber our argument
	 */
	if (strlen(line) >= sizeof (buf)) {
		(void) strlcpy(parse_err_msg, gettext("line too long"),
		    PARSE_ERR_MSG_LEN);
		return (GENENT_PARSEERR);
	}
	(void) strcpy(buf, line);

	/*
	 * clear column data
	 */
	(void) memset((char *)ecol, 0, sizeof (ecol));

	/*
	 * comment (col 2)
	 */
	t = strchr(buf, '#');
	if (t) {
		*t++ = 0;
		ecol[2].ec_value.ec_value_val = t;
		ecol[2].ec_value.ec_value_len = strlen(t)+1;
	} else {
		ecol[2].ec_value.ec_value_val = 0;
		ecol[2].ec_value.ec_value_len = 0;
	}

	/*
	 * addr(col 0)
	 */
	if ((t = strtok(buf, " \t")) == 0) {
		(void) strlcpy(parse_err_msg, gettext("no mask"),
		    PARSE_ERR_MSG_LEN);
		return (GENENT_PARSEERR);
	}
	ecol[0].ec_value.ec_value_val = t;
	ecol[0].ec_value.ec_value_len = strlen(t)+1;

	/*
	 * mask (col 1)
	 */
	if ((t = strtok(NULL, " \t")) == 0) {
		(void) strlcpy(parse_err_msg, gettext("no mask"),
		    PARSE_ERR_MSG_LEN);
		return (GENENT_PARSEERR);
	}
	ecol[1].ec_value.ec_value_val = t;
	ecol[1].ec_value.ec_value_len = strlen(t)+1;

	/* build entry */
	data.netnumber = ecol[0].ec_value.ec_value_val;
	data.netmask = ecol[1].ec_value.ec_value_val;

	if (flags & F_VERBOSE)
		(void) fprintf(stdout,
		    gettext("Adding entry : %s\n"), data.netnumber);

	retval = (*cback)(&data, 1);
	if (retval != NS_LDAP_SUCCESS) {
		if (retval == LDAP_NO_SUCH_OBJECT)
			(void) fprintf(stdout,
			    gettext("Cannot add netmask entry (%s), "
			    "add network entry first\n"), data.netnumber);
		if (continue_onerror == 0)
			return (GENENT_CBERR);
	}

	return (GENENT_OK);
}

static void
dump_netmasks(ns_ldap_result_t *res)
{
	char	**value = NULL;

	value = __ns_ldap_getAttr(res->entry, "ipNetworkNumber");
	if (value && value[0])
		(void) fprintf(stdout, "%s", value[0]);
	value = __ns_ldap_getAttr(res->entry, "ipNetmaskNumber");
	if (value && value[0])
		(void) fprintf(stdout, "	%s\n", value[0]);
}


/*
 * /etc/netgroup
 * column data format is:
 *    col 0: netgroup name (or cname)
 *    col 1: netgroup member, if this is a triplet
 *    col 2: netgroup member, if not a triplet
 *    col 3: comment
 */

static int
genent_netgroup(char *line, int (*cback)())
{
	char buf[BIGBUF+1];    /* netgroup entries tend to be big */
	char *t;
	char *cname = NULL;
	entry_col ecol[4];
	char *netg_tmp = NULL, *triplet_tmp = NULL;
	int netgcount = 0, tripletcount = 0, retval = 1, i;
	struct _ns_netgroups data;
	int rc = GENENT_OK;

	/* don't clobber our argument */
	if (strlen(line) >= sizeof (buf)) {
		(void) strlcpy(parse_err_msg, gettext("line too long"),
		    PARSE_ERR_MSG_LEN);
		return (GENENT_PARSEERR);
	}
	(void) strcpy(buf, line);

	/* clear column data */
	(void) memset((char *)ecol, 0, sizeof (ecol));

	/*
	 * process 1st minimal entry, to validate that there is no
	 * parsing error.
	 * start with comment(col 3)
	 */
	t = strchr(buf, '#');
	if (t) {
		*t++ = 0;
		ecol[3].ec_value.ec_value_val = t;
		ecol[3].ec_value.ec_value_len = strlen(t)+1;
	} else {
		ecol[3].ec_value.ec_value_val = "";
		ecol[3].ec_value.ec_value_len = 0;
	}

	ecol[1].ec_value.ec_value_val = NULL;
	ecol[2].ec_value.ec_value_val = NULL;

	/* cname (col 0) */
	if ((t = strtok(buf, " \t")) == 0) {
		(void) strlcpy(parse_err_msg, gettext("no cname"),
		    PARSE_ERR_MSG_LEN);
		return (GENENT_PARSEERR);
	}

	ecol[0].ec_value.ec_value_val = t;
	ecol[0].ec_value.ec_value_len = strlen(t)+1;
	cname = t;

	/* addr(col 1 and 2) */
	if ((t = strtok(NULL, " \t")) == 0) {
		(void) strlcpy(parse_err_msg,
		    gettext("no members for netgroup"), PARSE_ERR_MSG_LEN);
		return (GENENT_PARSEERR);
	}

	if (*t == '(') {
		/* if token starts with '(' it must be a valid triplet */
		if (is_triplet(t)) {
			ecol[1].ec_value.ec_value_val = t;
			ecol[1].ec_value.ec_value_len = strlen(t)+1;
		} else {
			(void) strlcpy(parse_err_msg,
			    gettext("invalid triplet"), PARSE_ERR_MSG_LEN);
			return (GENENT_PARSEERR);
		}
	} else {
		ecol[2].ec_value.ec_value_val = t;
		ecol[2].ec_value.ec_value_len = strlen(t)+1;
	}

	/*
	 * now build entry.
	 * start by clearing entry data
	 */
	(void) memset((struct _ns_netgroups *)&data, 0, sizeof (data));

	data.name = strdup(ecol[0].ec_value.ec_value_val);

	if (ecol[1].ec_value.ec_value_val != NULL) {
		if ((data.triplet = calloc(1, sizeof (char **))) == NULL) {
				(void) fprintf(stderr,
				    gettext("out of memory\n"));
				exit(1);
		}
		data.triplet[tripletcount++] =
		    strdup(ecol[1].ec_value.ec_value_val);
	} else if (ecol[2].ec_value.ec_value_val != NULL) {
			if ((data.netgroup = calloc(1, sizeof (char **)))
			    == NULL) {
					(void) fprintf(stderr,
				    gettext("out of memory\n"));
					exit(1);
			}
			data.netgroup[netgcount++] =
			    strdup(ecol[2].ec_value.ec_value_val);
	}

	/*
	 * we now have a valid entry (at least 1 netgroup name and
	 * 1 netgroup member), proceed with the rest of the line
	 */
	while (rc == GENENT_OK && (t = strtok(NULL, " \t"))) {

		/* if next token is equal to netgroup name, ignore */
		if (t != cname && strcasecmp(t, cname) == 0)
			continue;
		if (strcasecmp(t, ecol[0].ec_value.ec_value_val) == 0)
			continue;

		if (*t == '(') {
			if (is_triplet(t)) {
				/* skip a triplet if it is added already */
				for (i = 0; i < tripletcount &&
				    strcmp(t, data.triplet[i]); i++)
					;
				if (i < tripletcount)
					continue;

				tripletcount++;
				triplet_tmp = strdup(t);
				if ((data.triplet = (char **)realloc(
				    data.triplet,
				    tripletcount * sizeof (char **))) == NULL) {
					(void) fprintf(stderr,
					    gettext("out of memory\n"));
					exit(1);
				}
				data.triplet[tripletcount-1] = triplet_tmp;
			} else {
				(void) strlcpy(parse_err_msg,
				    gettext("invalid triplet"),
				    PARSE_ERR_MSG_LEN);
				rc = GENENT_PARSEERR;
			}
		} else {
			/* skip a netgroup if it is added already */
			for (i = 0; i < netgcount &&
			    strcmp(t, data.netgroup[i]); i++)
				;
			if (i < netgcount)
				continue;

			netgcount++;
			netg_tmp = strdup(t);
			if ((data.netgroup = (char **)realloc(data.netgroup,
			    netgcount * sizeof (char **))) == NULL) {
				(void) fprintf(stderr,
				gettext("out of memory\n"));
				exit(1);
			}
			data.netgroup[netgcount-1] = netg_tmp;
		}
	}

	/* End the list with NULL */
	if ((data.triplet = (char **)realloc(data.triplet,
	    (tripletcount + 1) * sizeof (char **))) == NULL) {
		(void) fprintf(stderr, gettext("out of memory\n"));
		exit(1);
	}
	data.triplet[tripletcount] = NULL;
	if ((data.netgroup = (char **)realloc(data.netgroup,
	    (netgcount + 1) * sizeof (char **))) == NULL) {
		(void) fprintf(stderr, gettext("out of memory\n"));
		exit(1);
	}
	data.netgroup[netgcount] = NULL;

	if (rc == GENENT_OK) {
		if (flags & F_VERBOSE)
			(void) fprintf(stdout,
			    gettext("Adding entry : %s\n"), data.name);

		retval = (*cback)(&data, 0);

		if (retval == LDAP_ALREADY_EXISTS) {
			if (continue_onerror)
				(void) fprintf(stderr, gettext(
				    "Entry: %s - already Exists,"
				    " skipping it.\n"), data.name);
			else {
				rc = GENENT_CBERR;
				(void) fprintf(stderr,
				    gettext("Entry: %s - already Exists\n"),
				    data.name);
			}
		} else if (retval)
			rc = GENENT_CBERR;
	}

	/* release memory allocated by strdup() */
	for (i = 0; i < tripletcount; i++) {
		free(data.triplet[i]);
	}
	for (i = 0; i < netgcount; i++) {
		free(data.netgroup[i]);
	}

	free(data.name);
	free(data.triplet);
	free(data.netgroup);

	return (rc);
}

static void
dump_netgroup(ns_ldap_result_t *res)
{
	char	**value = NULL;
	int	attr_count = 0;

	value = __ns_ldap_getAttr(res->entry, "cn");
	if ((value != NULL) && (value[0] != NULL))
		(void) fprintf(stdout, "%s", value[0]);
	else
		return;
	value = __ns_ldap_getAttr(res->entry, "nisNetgroupTriple");
	if (value != NULL)
		while (value[attr_count] != NULL) {
			(void) fprintf(stdout, " %s", value[attr_count]);
			attr_count++;
		}
	attr_count = 0;
	value = __ns_ldap_getAttr(res->entry, "memberNisNetgroup");
	if (value != NULL)
		while (value[attr_count] != NULL) {
			(void) fprintf(stdout, " %s", value[attr_count]);
			attr_count++;
		}
	(void) fprintf(stdout, "\n");

}

static int
genent_automount(char *line, int (*cback)())
{
	char buf[BUFSIZ+1];
	char *t, *s;
	entry_col ecol[2];
	struct _ns_automount data;
	int retval = 1;
	int rc = GENENT_OK;

	/*
	 * don't clobber our argument
	 */
	if (strlen(line) >= sizeof (buf)) {
		(void) strlcpy(parse_err_msg, gettext("line too long"),
		    PARSE_ERR_MSG_LEN);
		return (GENENT_PARSEERR);
	}

	/* replace every tabspace with single space */
	replace_tab2space(line);
	(void) strcpy(buf, line);

	/*
	 * clear column data
	 */
	(void) memset((char *)ecol, 0, sizeof (ecol));

	/*
	 * key (col 0)
	 */
	t = buf;
	while (t[0] == ' ')
		t++;

	if ((s = strchr(t, ' ')) == 0) {
		return (GENENT_PARSEERR);
	}
	*s++ = 0;

	ecol[0].ec_value.ec_value_val = t;
	ecol[0].ec_value.ec_value_len = strlen(t)+1;
	t = s;

	while (t[0] == ' ')
		t++;

	/*
	 * mapentry (col 1)
	 */

	ecol[1].ec_value.ec_value_val = t;
	ecol[1].ec_value.ec_value_len = strlen(t)+1;

	data.mapname = strdup(databasetype);
	data.key = strdup(ecol[0].ec_value.ec_value_val);
	data.value = strdup(ecol[1].ec_value.ec_value_val);

	if (flags & F_VERBOSE)
		(void) fprintf(stdout,
		    gettext("Adding entry : %s\n"), data.key);

	retval = (*cback)(&data, 0);

	if (retval == LDAP_ALREADY_EXISTS) {
		if (continue_onerror)
			(void) fprintf(stderr,
			    gettext("Entry: %s - already Exists,"
			    " skipping it.\n"), data.key);
		else {
			rc = GENENT_CBERR;
			(void) fprintf(stderr,
			    gettext("Entry: %s - already Exists\n"),
			    data.key);
		}
	} else if (retval)
		rc = GENENT_CBERR;

	free(data.mapname);
	free(data.key);
	free(data.value);
	return (rc);
}

static void
dump_automount(ns_ldap_result_t *res)
{
	char	**value = NULL;

	if (res == NULL)
		return;

	value = __ns_ldap_getAttr(res->entry, "automountKey");
	if (value != NULL) {
		(void) fprintf(stdout, "%s", value[0]);
		value = __ns_ldap_getAttr(res->entry, "automountInformation");
		if (value != NULL)
			(void) fprintf(stdout, "	%s\n", value[0]);
		else
			(void) fprintf(stdout, "\n");
	}
}


/*
 * /etc/passwd
 *
 */

static int
genent_passwd(char *line, int (*cback)())
{
	char buf[BUFSIZ+1];
	char *s, *t;
	entry_col ecol[8];
	int retval = 1;
	char pname[BUFSIZ];

	struct passwd	data;
	int rc = GENENT_OK;


	/*
	 * don't clobber our argument
	 */
	if (strlen(line) >= sizeof (buf)) {
		(void) strlcpy(parse_err_msg, gettext("line too long"),
		    PARSE_ERR_MSG_LEN);
		return (GENENT_PARSEERR);
	}
	(void) strcpy(buf, line);
	t = buf;

	/* ignore empty entries */
	if (*t == '\0')
		return (GENENT_OK);

	/*
	 * clear column data
	 */
	(void) memset((char *)ecol, 0, sizeof (ecol));

	/*
	 * name (col 0)
	 */
	if ((s = strchr(t, ':')) == 0) {
		(void) strlcpy(parse_err_msg, gettext("no password"),
		    PARSE_ERR_MSG_LEN);
		return (GENENT_PARSEERR);
	}
	*s++ = 0;
	ecol[0].ec_value.ec_value_val = t;
	ecol[0].ec_value.ec_value_len = strlen(t)+1;
	t = s;

	/*
	 * passwd (col 1)
	 */
	if ((s = strchr(t, ':')) == 0) {
		(void) strlcpy(parse_err_msg, gettext("no uid"),
		    PARSE_ERR_MSG_LEN);
		return (GENENT_PARSEERR);
	}
	*s++ = 0;

	ecol[1].ec_value.ec_value_val = t;
	ecol[1].ec_value.ec_value_len = strlen(t)+1;

	t = s;

	/*
	 * uid (col 2)
	 */
	if ((s = strchr(t, ':')) == 0 || s == t) {
		(void) strlcpy(parse_err_msg, gettext("no gid"),
		    PARSE_ERR_MSG_LEN);
		return (GENENT_PARSEERR);
	}
	*s++ = 0;
	ecol[2].ec_value.ec_value_val = t;
	ecol[2].ec_value.ec_value_len = strlen(t)+1;
	t = s;

	/*
	 * gid (col 3)
	 */
	if ((s = strchr(t, ':')) == 0 || s == t) {
		(void) strlcpy(parse_err_msg, gettext("no gcos"),
		    PARSE_ERR_MSG_LEN);
		return (GENENT_PARSEERR);
	}
	*s++ = 0;
	ecol[3].ec_value.ec_value_val = t;
	ecol[3].ec_value.ec_value_len = strlen(t)+1;
	t = s;

	/*
	 * gcos (col 4)
	 */
	if ((s = strchr(t, ':')) == 0) {
		(void) strlcpy(parse_err_msg, gettext("no home"),
		    PARSE_ERR_MSG_LEN);
		return (GENENT_PARSEERR);
	}
	*s++ = 0;
	ecol[4].ec_value.ec_value_val = t;
	ecol[4].ec_value.ec_value_len = strlen(t)+1;
	t = s;

	/*
	 * home (col 5)
	 */
	if ((s = strchr(t, ':')) == 0) {
		(void) strlcpy(parse_err_msg, gettext("no shell"),
		    PARSE_ERR_MSG_LEN);
		return (GENENT_PARSEERR);
	}
	*s++ = 0;
	ecol[5].ec_value.ec_value_val = t;
	ecol[5].ec_value.ec_value_len = strlen(t)+1;
	t = s;

	/*
	 * shell (col 6)
	 */
	ecol[6].ec_value.ec_value_val = t;
	ecol[6].ec_value.ec_value_len = strlen(t)+1;

	/*
	 * build entry
	 */
	data.pw_name = strdup(ecol[0].ec_value.ec_value_val);

	if (flags & F_PASSWD) {
		/* Add {crypt} before passwd entry */
		(void) snprintf(pname, sizeof (pname), "{crypt}%s",
		    ecol[1].ec_value.ec_value_val);
		data.pw_passwd = strdup(pname);
	}
	else
		data.pw_passwd = NULL;

	if (ecol[2].ec_value.ec_value_val != NULL &&
	    ecol[2].ec_value.ec_value_val[0] != '\0') {
		data.pw_uid = ascii_to_int(ecol[2].ec_value.ec_value_val);
		if (data.pw_uid == (uid_t)-1) {
			(void) snprintf(parse_err_msg, sizeof (parse_err_msg),
			    gettext("invalid uid : %s"),
			    ecol[2].ec_value.ec_value_val);
		return (GENENT_PARSEERR);
		}
	} else
		data.pw_uid = (uid_t)-1;

	if (ecol[3].ec_value.ec_value_val != NULL &&
	    ecol[3].ec_value.ec_value_val[0] != '\0') {

		data.pw_gid = ascii_to_int(ecol[3].ec_value.ec_value_val);
		if (data.pw_gid == (uid_t)-1) {
			(void) snprintf(parse_err_msg, sizeof (parse_err_msg),
			    gettext("invalid gid : %s"),
			    ecol[3].ec_value.ec_value_val);
		return (GENENT_PARSEERR);
		}
	} else
		data.pw_gid = (uid_t)-1;

	data.pw_age = NULL;
	data.pw_comment = NULL;
	data.pw_gecos = strdup(ecol[4].ec_value.ec_value_val);
	data.pw_dir = strdup(ecol[5].ec_value.ec_value_val);
	data.pw_shell = strdup(ecol[6].ec_value.ec_value_val);

	if (flags & F_VERBOSE)
		(void) fprintf(stdout,
		    gettext("Adding entry : %s\n"), data.pw_name);

	retval = (*cback)(&data, 0);

	if (retval == LDAP_ALREADY_EXISTS) {
		if (continue_onerror)
			(void) fprintf(stderr,
			    gettext("Entry: %s - already Exists,"
			    " skipping it.\n"), data.pw_name);
		else {
			rc = GENENT_CBERR;
			(void) fprintf(stderr,
			    gettext("Entry: %s - already Exists\n"),
			    data.pw_name);
		}
	} else if (retval)
		rc = GENENT_CBERR;

	free(data.pw_name);
	free(data.pw_gecos);
	free(data.pw_dir);
	free(data.pw_shell);
	return (rc);
}


static void
dump_passwd(ns_ldap_result_t *res)
{
	char    **value = NULL;

	value = __ns_ldap_getAttr(res->entry, "uid");
	if (value == NULL)
		return;
	else
		(void) fprintf(stdout, "%s:", value[0]);
	value = __ns_ldap_getAttr(res->entry, "userPassword");

	/*
	 * Don't print the encrypted password, Use x to
	 * indicate it is in the shadow database.
	 */
	(void) fprintf(stdout, "x:");

	value = __ns_ldap_getAttr(res->entry, "uidNumber");
	if (value && value[0])
		(void) fprintf(stdout, "%s:", value[0]);
	value = __ns_ldap_getAttr(res->entry, "gidNumber");
	if (value && value[0])
		(void) fprintf(stdout, "%s:", value[0]);
	value = __ns_ldap_getAttr(res->entry, "gecos");
	if (value == NULL)
		(void) fprintf(stdout, ":");
	else
		(void) fprintf(stdout, "%s:", value[0]);
	value = __ns_ldap_getAttr(res->entry, "homeDirectory");
	if (value == NULL)
		(void) fprintf(stdout, ":");
	else
		(void) fprintf(stdout, "%s:", value[0]);
	value = __ns_ldap_getAttr(res->entry, "loginShell");
	if (value == NULL)
		(void) fprintf(stdout, "\n");
	else
		(void) fprintf(stdout, "%s\n", value[0]);

}

/*
 * /etc/shadow
 */

static int
genent_shadow(char *line, int (*cback)())
{
	char buf[BUFSIZ+1];
	char *s, *t;
	entry_col ecol[9];
	char pname[BUFSIZ];

	struct spwd	data;
	int spflag;
	int retval;


	/*
	 * don't clobber our argument
	 */
	if (strlen(line) >= sizeof (buf)) {
		(void) strlcpy(parse_err_msg, gettext("line too long"),
		    PARSE_ERR_MSG_LEN);
		return (GENENT_PARSEERR);
	}
	(void) strcpy(buf, line);
	t = buf;

	/* ignore empty entries */
	if (*t == '\0')
		return (GENENT_OK);

	/*
	 * clear column data
	 */
	(void) memset((char *)ecol, 0, sizeof (ecol));

	/*
	 * name (col 0)
	 */
	if ((s = strchr(t, ':')) == 0) {
		(void) strlcpy(parse_err_msg, gettext("no uid"),
		    PARSE_ERR_MSG_LEN);
		return (GENENT_PARSEERR);
	}
	*s++ = 0;
	ecol[0].ec_value.ec_value_val = t;
	ecol[0].ec_value.ec_value_len = strlen(t)+1;
	t = s;

	/*
	 * passwd (col 1)
	 */
	if ((s = strchr(t, ':')) == 0) {
		(void) strlcpy(parse_err_msg, gettext("Improper format"),
		    PARSE_ERR_MSG_LEN);
		return (GENENT_PARSEERR);
	}
	*s++ = 0;

		ecol[1].ec_value.ec_value_val = t;
		ecol[1].ec_value.ec_value_len = strlen(t)+1;

	t = s;

	/*
	 * shadow last change (col 2)
	 */
	if ((s = strchr(t, ':')) == 0) {
		(void) strlcpy(parse_err_msg, gettext("Improper format"),
		    PARSE_ERR_MSG_LEN);
		return (GENENT_PARSEERR);
	}
	*s++ = 0;
	ecol[2].ec_value.ec_value_val = t;
	ecol[2].ec_value.ec_value_len = strlen(t)+1;
	t = s;

	/*
	 * shadow min (col 3)
	 */
	if ((s = strchr(t, ':')) == 0) {
		(void) strlcpy(parse_err_msg, gettext("Improper format"),
		    PARSE_ERR_MSG_LEN);
		return (GENENT_PARSEERR);
	}
	*s++ = 0;
	ecol[3].ec_value.ec_value_val = t;
	ecol[3].ec_value.ec_value_len = strlen(t)+1;
	t = s;

	/*
	 * shadow max (col 4)
	 */
	if ((s = strchr(t, ':')) == 0) {
		(void) strlcpy(parse_err_msg, gettext("Improper format"),
		    PARSE_ERR_MSG_LEN);
		return (GENENT_PARSEERR);
	}
	*s++ = 0;
	ecol[4].ec_value.ec_value_val = t;
	ecol[4].ec_value.ec_value_len = strlen(t)+1;
	t = s;

	/*
	 * shadow warn (col 5)
	 */
	if ((s = strchr(t, ':')) == 0) {
		(void) strlcpy(parse_err_msg, gettext("Improper format"),
		    PARSE_ERR_MSG_LEN);
		return (GENENT_PARSEERR);
	}
	*s++ = 0;
	ecol[5].ec_value.ec_value_val = t;
	ecol[5].ec_value.ec_value_len = strlen(t)+1;
	t = s;

	/*
	 * shadow inactive (col 6)
	 */
	if ((s = strchr(t, ':')) != 0) {
	*s++ = 0;
	ecol[6].ec_value.ec_value_val = t;
	ecol[6].ec_value.ec_value_len = strlen(t)+1;
	t = s;
	}

	/*
	 * shadow expire  (col 7)
	 */
	if ((s = strchr(t, ':')) != 0) {
	*s++ = 0;
	ecol[7].ec_value.ec_value_val = t;
	ecol[7].ec_value.ec_value_len = strlen(t)+1;
	t = s;

	/*
	 * flag (col 8)
	 */
	ecol[8].ec_value.ec_value_val = t;
	ecol[8].ec_value.ec_value_len = strlen(t)+1;
	}

	/*
	 * build entry
	 */

	data.sp_namp = strdup(ecol[0].ec_value.ec_value_val);

	if (ecol[1].ec_value.ec_value_val != NULL &&
	    ecol[1].ec_value.ec_value_val[0] != '\0') {
		/* Add {crypt} before passwd entry */
		(void) snprintf(pname, sizeof (pname), "{crypt}%s",
		    ecol[1].ec_value.ec_value_val);
		data.sp_pwdp = strdup(pname);
	} else {
		/*
		 * no password (e.g., deleted by "passwd -d"):
		 * use the special value NS_LDAP_NO_UNIX_PASSWORD
		 * instead.
		 */
		(void) snprintf(pname, sizeof (pname), "{crypt}%s",
		    NS_LDAP_NO_UNIX_PASSWORD);
		data.sp_pwdp = strdup(pname);
	}

	if (ecol[2].ec_value.ec_value_val != NULL &&
	    ecol[2].ec_value.ec_value_val[0] != '\0') {

		data.sp_lstchg = ascii_to_int(ecol[2].ec_value.ec_value_val);
		if (data.sp_lstchg < -1) {
			(void) snprintf(parse_err_msg, sizeof (parse_err_msg),
			    gettext("invalid last changed date: %s"),
			    ecol[2].ec_value.ec_value_val);
		return (GENENT_PARSEERR);
		}
	} else
		data.sp_lstchg = -1;

	if (ecol[3].ec_value.ec_value_val != NULL &&
	    ecol[3].ec_value.ec_value_val[0] != '\0') {

		data.sp_min = ascii_to_int(ecol[3].ec_value.ec_value_val);
		if (data.sp_min < -1) {
			(void) snprintf(parse_err_msg, sizeof (parse_err_msg),
			    gettext("invalid sp_min : %s"),
			    ecol[3].ec_value.ec_value_val);
		return (GENENT_PARSEERR);
		}
	} else
		data.sp_min = -1;

	if (ecol[4].ec_value.ec_value_val != NULL &&
	    ecol[4].ec_value.ec_value_val[0] != '\0') {

		data.sp_max = ascii_to_int(ecol[4].ec_value.ec_value_val);
		if (data.sp_max < -1) {
			(void) snprintf(parse_err_msg, sizeof (parse_err_msg),
			    gettext("invalid sp_max : %s"),
			    ecol[4].ec_value.ec_value_val);
		return (GENENT_PARSEERR);
		}
	} else
		data.sp_max = -1;

	if (ecol[5].ec_value.ec_value_val != NULL &&
	    ecol[5].ec_value.ec_value_val[0] != '\0') {

		data.sp_warn = ascii_to_int(ecol[5].ec_value.ec_value_val);
		if (data.sp_warn < -1) {
			(void) snprintf(parse_err_msg, sizeof (parse_err_msg),
			    gettext("invalid sp_warn : %s"),
			    ecol[5].ec_value.ec_value_val);
		return (GENENT_PARSEERR);
		}
	} else
		data.sp_warn = -1;

	if (ecol[6].ec_value.ec_value_val != NULL &&
	    ecol[6].ec_value.ec_value_val[0] != '\0') {

		data.sp_inact = ascii_to_int(ecol[6].ec_value.ec_value_val);
		if (data.sp_inact < -1) {
			(void) snprintf(parse_err_msg, sizeof (parse_err_msg),
			    gettext("invalid sp_inact : %s"),
			    ecol[6].ec_value.ec_value_val);
		return (GENENT_PARSEERR);
		}
	} else
		data.sp_inact = -1;

	if (ecol[7].ec_value.ec_value_val != NULL &&
	    ecol[7].ec_value.ec_value_val[0] != '\0') {

		data.sp_expire = ascii_to_int(ecol[7].ec_value.ec_value_val);
		if (data.sp_expire < -1) {
			(void) snprintf(parse_err_msg, sizeof (parse_err_msg),
			    gettext("invalid login expiry date : %s"),
			    ecol[7].ec_value.ec_value_val);
		return (GENENT_PARSEERR);
		}
	} else
		data.sp_expire = -1;

	if (ecol[8].ec_value.ec_value_val != NULL &&
	    ecol[8].ec_value.ec_value_val[0] != '\0') {

		/*
		 * data.sp_flag is an unsigned int,
		 * assign -1 to it, make no sense.
		 * Use spflag here to avoid lint warning.
		 */
		spflag = ascii_to_int(ecol[8].ec_value.ec_value_val);
		if (spflag < 0) {
			(void) snprintf(parse_err_msg, sizeof (parse_err_msg),
			    gettext("invalid flag value: %s"),
			    ecol[8].ec_value.ec_value_val);
		return (GENENT_PARSEERR);
		} else
			data.sp_flag = spflag;
	} else
		data.sp_flag = 0;

	if (flags & F_VERBOSE)
		(void) fprintf(stdout,
		    gettext("Adding entry : %s\n"), data.sp_namp);

	retval = (*cback)(&data, 1);
	if (retval != NS_LDAP_SUCCESS) {
		if (retval == LDAP_NO_SUCH_OBJECT)
			(void) fprintf(stdout,
			    gettext("Cannot add shadow entry (%s), "
			    "add passwd entry first\n"), data.sp_namp);
		if (continue_onerror == 0)
			return (GENENT_CBERR);
	}

	free(data.sp_namp);
	free(data.sp_pwdp);
	return (GENENT_OK);
}

static void
dump_shadow(ns_ldap_result_t *res)
{
	char    **value = NULL;
	char   pnam[256];

	value = __ns_ldap_getAttr(res->entry, "uid");
	if (value == NULL)
		return;
	else
		(void) fprintf(stdout, "%s:", value[0]);
	value = __ns_ldap_getAttr(res->entry, "userPassword");
	if (value == NULL)
		(void) fprintf(stdout, "*:");
	else {
		(void) strcpy(pnam, value[0]);
		if (strncasecmp(value[0], "{crypt}", 7) == 0) {
			if (strcmp(pnam + 7, NS_LDAP_NO_UNIX_PASSWORD) == 0)
				(void) fprintf(stdout, ":");
			else
				(void) fprintf(stdout, "%s:", (pnam+7));
		} else
			(void) fprintf(stdout, "*:");
	}
	value = __ns_ldap_getAttr(res->entry, "shadowLastChange");
	if (value == NULL)
		(void) fprintf(stdout, ":");
	else
		(void) fprintf(stdout, "%s:", value[0]);
	value = __ns_ldap_getAttr(res->entry, "shadowMin");
	if (value == NULL)
		(void) fprintf(stdout, ":");
	else
		(void) fprintf(stdout, "%s:", value[0]);
	value = __ns_ldap_getAttr(res->entry, "shadowMax");
	if (value == NULL)
		(void) fprintf(stdout, ":");
	else
		(void) fprintf(stdout, "%s:", value[0]);

	value = __ns_ldap_getAttr(res->entry, "shadowWarning");
	if (value == NULL)
		(void) fprintf(stdout, ":");
	else
		(void) fprintf(stdout, "%s:", value[0]);

	value = __ns_ldap_getAttr(res->entry, "shadowInactive");
	if (value == NULL)
		(void) fprintf(stdout, ":");
	else
		(void) fprintf(stdout, "%s:", value[0]);

	value = __ns_ldap_getAttr(res->entry, "shadowExpire");
	if (value == NULL)
		(void) fprintf(stdout, ":");
	else
		(void) fprintf(stdout, "%s:", value[0]);

	value = __ns_ldap_getAttr(res->entry, "shadowFlag");
	if (value == NULL || value[0] == NULL || strcmp(value[0], "0") == 0)
		(void) fprintf(stdout, "\n");
	else
		(void) fprintf(stdout, "%s\n", value[0]);
}

static int
genent_bootparams(char *line, int (*cback)())
{
	char buf[BUFSIZ+1];
	char *t;
	entry_col ecol[2];
	int ctr = 0, retval = 1;

	struct _ns_bootp data;
	char *parameter;
	int rc = GENENT_OK;

	/*
	 * don't clobber our argument
	 */
	if (strlen(line) >= sizeof (buf)) {
		(void) strlcpy(parse_err_msg, gettext("line too long"),
		    PARSE_ERR_MSG_LEN);
		return (GENENT_PARSEERR);
	}
	(void) strcpy(buf, line);

	/*
	 * clear column data
	 */
	(void) memset((char *)ecol, 0, sizeof (ecol));


	/*
	 * cname (col 0)
	 */
	if ((t = strtok(buf, " \t")) == 0) {
		(void) strlcpy(parse_err_msg, gettext("no cname"),
		    PARSE_ERR_MSG_LEN);
		return (GENENT_PARSEERR);
	}
	ecol[0].ec_value.ec_value_val = t;
	ecol[0].ec_value.ec_value_len = strlen(t)+1;



	/* build entry */
	data.name = strdup(ecol[0].ec_value.ec_value_val);

	/*
	 * name (col 1)
	 */

	data.param = NULL;

	while (t = strtok(NULL, " \t"))  {

		/*
		 * don't clobber comment in canonical entry
		 */


		ecol[1].ec_value.ec_value_val = t;
		ecol[1].ec_value.ec_value_len = strlen(t)+1;

		ctr++;
		parameter = strdup(ecol[1].ec_value.ec_value_val);
		if ((data.param = (char **)realloc(data.param,
		    (ctr + 1) * sizeof (char **))) == NULL) {
			(void) fprintf(stderr, gettext("out of memory\n"));
			exit(1);
		}
		data.param[ctr-1] = parameter;

	}


	/* End the list of all the aliases by NULL */
	if ((data.param = (char **)realloc(data.param,
	    (ctr + 1) * sizeof (char **))) == NULL) {
		(void) fprintf(stderr, gettext("out of memory\n"));
		exit(1);
	}
	data.param[ctr] = NULL;

	if (flags & F_VERBOSE)
		(void) fprintf(stdout,
		    gettext("Adding entry : %s\n"), data.name);

	retval = (*cback)(&data, 0);

	if (retval == LDAP_ALREADY_EXISTS) {
		if (continue_onerror)
			(void) fprintf(stderr,
			    gettext("Entry: %s - already Exists,"
			    " skipping it.\n"), data.name);
		else {
			rc = GENENT_CBERR;
			(void) fprintf(stderr,
			    gettext("Entry: %s - already Exists\n"),
			    data.name);
		}
	} else if (retval)
		rc = GENENT_CBERR;

	free(data.name);
	free(data.param);

	return (rc);

}

/*
 * Count number of tokens in string which has tokens separated by colons.
 *
 * NULL or "" - 0 tokens
 * "foo" - 1 token
 * "foo:bar" - 2 tokens
 * ":bar" - 2 tokens, first empty
 * "::" - 3 tokens, all empty
 */
static int
count_tokens(char *string, char delim)
{
	int i = 0;
	char *s = string;

	if (string == NULL || *string == '\0')
		return (0);

	/* Count delimiters */
	while ((s = strchr(s, delim)) != NULL && *s != '\0') {
		i++;
		s++;
	}

	return (i + 1);
}

static int
genent_project(char *line, int (*cback)())
{
	char buf[BUFSIZ+1];
	char *b = buf;
	char *s;
	int rc = GENENT_OK, retval;
	int index = 0;
	struct project data;

	(void) memset(&data, 0, sizeof (struct project));

	/*
	 * don't clobber our argument
	 */
	if (strlen(line) >= sizeof (buf)) {
		(void) strlcpy(parse_err_msg, gettext("line too long"),
		    PARSE_ERR_MSG_LEN);
		return (GENENT_PARSEERR);
	}

	if (count_tokens(line, ':') != 6) {
		(void) strlcpy(parse_err_msg, gettext("Improper format"),
		    PARSE_ERR_MSG_LEN);
		return (GENENT_PARSEERR);
	}

	(void) strcpy(buf, line);

	s = strsep(&b, ":");
	while (s != NULL) {
		switch (index) {
		/* Project name */
		case 0:
			if (check_projname(s) != 0) {
				(void) strlcpy(parse_err_msg,
				    gettext("invalid project name"),
				    PARSE_ERR_MSG_LEN);
				return (GENENT_PARSEERR);
			} else {
				data.pj_name = strdup(s);
			}
			break;

		/* Project ID */
		case 1:
		{
			char *endptr = NULL;
			int projid = strtoul(s, &endptr, 10);

			if (*s == '\0' || strlen(endptr) != 0 || projid < 0 ||
			    projid > MAXPROJID) {
				(void) strlcpy(parse_err_msg,
				    gettext("invalid project id"),
				    PARSE_ERR_MSG_LEN);
				return (GENENT_PARSEERR);
			} else {
				data.pj_projid = projid;
			}
			break;
		}

		/* Project description */
		case 2:
			if (*s != '\0')
				data.pj_comment = strdup(s);
			break;

		/* Project users */
		case 3:
		{
			if (*s == '\0')
				break;

			char *usrlist = strdup(s);
			int   i = 0;
			int   usr_count = count_tokens(usrlist, ',');
			char *u = strsep(&usrlist, ",");

			if (usr_count == 0) {
				free(usrlist);
				break;
			}

			/* +1 to NULL-terminate the array */
			data.pj_users = (char **)calloc(usr_count + 1,
			    sizeof (char *));

			while (u != NULL) {
				data.pj_users[i++] = strdup(u);
				u = strsep(&usrlist, ",");
			}

			free(usrlist);
			break;
		}

		/* Project groups */
		case 4:
		{
			if (*s == '\0')
				break;

			char *grouplist = strdup(s);
			int   i = 0;
			int   grp_count = count_tokens(grouplist, ',');
			char *g = strsep(&grouplist, ",");

			if (grp_count == 0) {
				free(grouplist);
				break;
			}

			/* +1 to NULL-terminate the array */
			data.pj_groups = (char **)calloc(grp_count + 1,
			    sizeof (char *));

			while (g != NULL) {
				data.pj_groups[i++] = strdup(g);
				g = strsep(&grouplist, ",");
			}

			free(grouplist);
			break;
		}

		/* Attributes */
		case 5:
			if (*s != '\0')
				data.pj_attr = strdup(s);

			break;
		}

		/* Next token */
		s = strsep(&b, ":");
		index++;
	}

	if (flags & F_VERBOSE)
		(void) fprintf(stdout,
		    gettext("Adding entry : %s\n"), data.pj_name);

	retval = (*cback)(&data, 0);

	if (retval == LDAP_ALREADY_EXISTS) {
		if (continue_onerror)
			(void) fprintf(stderr,
			    gettext("Entry: %s - already Exists,"
			    " skipping it.\n"), data.pj_name);
		else {
			rc = GENENT_CBERR;
			(void) fprintf(stderr,
			    gettext("Entry: %s - already Exists\n"),
			    data.pj_name);
		}
	} else if (retval)
		rc = GENENT_CBERR;

	/* Clean up */
	free(data.pj_name);
	free(data.pj_attr);
	if (data.pj_users != NULL) {
		for (index = 0; data.pj_users[index] != NULL; index++)
			free(data.pj_users[index]);
		free(data.pj_users);
	}
	if (data.pj_groups != NULL) {
		for (index = 0; data.pj_groups[index] != NULL; index++)
			free(data.pj_groups[index]);
		free(data.pj_groups);
	}

	return (rc);
}

static void
dump_project(ns_ldap_result_t *res)
{
	char    **value = NULL;
	char 	*endptr = NULL;
	int 	projid;

	if (res == NULL || res->entry == NULL)
		return;

	/* Sanity checking */
	value = __ns_ldap_getAttr(res->entry, "SolarisProjectID");

	if (value[0] == NULL)
		return;

	projid = strtoul(value[0], &endptr, 10);
	if (*value[0] == '\0' || strlen(endptr) != 0 || projid < 0 ||
	    projid > MAXPROJID)
		return;

	value = __ns_ldap_getAttr(res->entry, "SolarisProjectName");
	if (value && value[0] && check_projname(value[0]) == 0)
		(void) fprintf(stdout, "%s:", value[0]);
	else
		return;

	(void) fprintf(stdout, "%d:", projid);

	value = __ns_ldap_getAttr(res->entry, "description");
	if (value && value[0])
		(void) fprintf(stdout, "%s:", value[0]);
	else
		(void) fprintf(stdout, ":");

	value = __ns_ldap_getAttr(res->entry, "memberUid");
	if (value) {
		int i;
		for (i = 0; value[i] != NULL; i++)
			if (value[i+1] != NULL)
				(void) fprintf(stdout, "%s,", value[i]);
			else
				(void) fprintf(stdout, "%s:", value[i]);
	} else {
		(void) fprintf(stdout, ":");
	}

	value = __ns_ldap_getAttr(res->entry, "memberGid");
	if (value) {
		int i;
		for (i = 0; value[i] != NULL; i++)
			if (value[i+1] != NULL)
				(void) fprintf(stdout, "%s,", value[i]);
			else
				(void) fprintf(stdout, "%s:", value[i]);
	} else {
		(void) fprintf(stdout, ":");
	}

	value = __ns_ldap_getAttr(res->entry, "SolarisProjectAttr");
	if (value && value[0])
		(void) fprintf(stdout, "%s\n", value[0]);
	else
		(void) fprintf(stdout, "\n");

}

static void
dump_bootparams(ns_ldap_result_t *res)
{
	char	**value = NULL;
	int		attr_count = 0;

	value = __ns_ldap_getAttr(res->entry, "cn");
	if (value[0] != NULL)
		(void) fprintf(stdout, "%s", value[0]);
	value = __ns_ldap_getAttr(res->entry, "bootParameter");
	if (value != NULL)
		while (value[attr_count] != NULL) {
		(void) fprintf(stdout, "\t%s", value[attr_count]);
			attr_count++;
		}
	(void) fprintf(stdout, "\n");


}

static char *
fget_line_at(struct line_buf *line, int n, FILE *fp)
{
	int c;

	line->len = n;

	for (;;) {
		c = fgetc(fp);
		if (c == -1)
			break;
		if (line->len >= line->alloc)
			line_buf_expand(line);
		line->str[line->len++] = c;

		if (c == '\n')
			break;
	}

	/* Null Terminate */
	if (line->len >= line->alloc)
		line_buf_expand(line);
	line->str[line->len++] = 0;

	/* if no characters are read, return NULL to indicate EOF */
	if (line->str[0] == '\0')
		return (0);

	return (line->str);
}

/*
 * return a line from the file, discarding comments and blank lines
 */
static int
filedbmline_comment(struct line_buf *line, FILE *etcf, int *lineno,
    struct file_loc *loc)
{
	int i, len = 0;

	loc->offset = ftell(etcf);
	for (;;) {
		if (fget_line_at(line, len, etcf) == 0)
			return (0);

		if (lineno)
			(*lineno)++;

		len = strlen(line->str);
		if (len >= 2 &&
		    line->str[0] != '#' &&
		    line->str[len-2] == '\\' && line->str[len-1] == '\n') {
			line->str[len-2] = 0;
			len -= 2;
			continue;    /* append next line at end */
		}

		if (line->str[len-1] == '\n') {
			line->str[len-1] = 0;
			len -= 1;
		}

		/*
		 * Skip lines where '#' is the first non-blank character.
		 */
		for (i = 0; i < len; i++) {
			if (line->str[i] == '#') {
				line->str[i] = '\0';
				len = i;
				break;
			}
			if (line->str[i] != ' ' && line->str[i] != '\t')
				break;
		}

		/*
		 * A line with one or more white space characters followed
		 * by a comment will now be blank. The special case of a
		 * line with '#' in the first byte will have len == 0.
		 */
		if (len > 0 && !blankline(line->str))
			break;

		len = 0;
		loc->offset = ftell(etcf);
	}

	loc->size = len;
	return (1);
}

/*
 * return a line from the file, discarding comments, blanks, and '+' lines
 */
static int
filedbmline_plus(struct line_buf *line, FILE *etcf, int *lineno,
    struct file_loc *loc)
{
	int len = 0;

	loc->offset = ftell(etcf);
	for (;;) {
		if (fget_line_at(line, len, etcf) == 0)
			return (0);

		if (lineno)
			(*lineno)++;

		len = strlen(line->str);
		if (line->str[len-1] == '\n') {
			line->str[len-1] = 0;
			len -= 1;
		}

		if (!blankline(line->str) &&
		    line->str[0] != '+' && line->str[0] != '-' &&
		    line->str[0] != '#')
			break;

		len = 0;
		loc->offset = ftell(etcf);
	}

	loc->size = len;
	return (1);
}


/* Populating the ttypelist structure */

static struct ttypelist_t ttypelist[] = {
	{ NS_LDAP_TYPE_HOSTS, genent_hosts, dump_hosts,
		filedbmline_comment, "iphost", "cn" },
	{ NS_LDAP_TYPE_IPNODES, genent_hosts, dump_hosts,
		filedbmline_comment, "iphost", "cn" },
	{ NS_LDAP_TYPE_RPC, genent_rpc, dump_rpc,
		filedbmline_comment, "oncrpc", "cn" },
	{ NS_LDAP_TYPE_PROTOCOLS, genent_protocols, dump_protocols,
		filedbmline_comment, "ipprotocol", "cn" },
	{ NS_LDAP_TYPE_NETWORKS, genent_networks, dump_networks,
		filedbmline_comment, "ipnetwork", "ipnetworknumber" },
	{ NS_LDAP_TYPE_SERVICES, genent_services, dump_services,
		filedbmline_comment, "ipservice", "cn" },
	{ NS_LDAP_TYPE_GROUP, genent_group, dump_group,
		filedbmline_plus, "posixgroup", "gidnumber" },
	{ NS_LDAP_TYPE_NETMASKS, genent_netmasks, dump_netmasks,
		filedbmline_comment, "ipnetwork", "ipnetworknumber"},
	{ NS_LDAP_TYPE_ETHERS, genent_ethers, dump_ethers,
		filedbmline_comment, "ieee802Device", "cn" },
	{ NS_LDAP_TYPE_NETGROUP, genent_netgroup, dump_netgroup,
		filedbmline_comment, "nisnetgroup", "cn" },
	{ NS_LDAP_TYPE_BOOTPARAMS, genent_bootparams, dump_bootparams,
		filedbmline_comment, "bootableDevice", "cn" },
	{ NS_LDAP_TYPE_PUBLICKEY, genent_publickey, NULL /* dump_publickey */,
		filedbmline_comment, "niskeyobject", "cn" },
	{ NS_LDAP_TYPE_PASSWD, genent_passwd, dump_passwd,
		filedbmline_plus, "posixaccount", "uid" },
	{ NS_LDAP_TYPE_SHADOW, genent_shadow, dump_shadow,
		filedbmline_plus, "shadowaccount", "uid" },
	{ NS_LDAP_TYPE_ALIASES, genent_aliases, dump_aliases,
		filedbmline_plus, "mailGroup", "cn" },
	{ NS_LDAP_TYPE_AUTOMOUNT, genent_automount, dump_automount,
		filedbmline_comment, "automount", "automountKey" },
	{ NS_LDAP_TYPE_USERATTR, genent_user_attr, dump_user_attr,
		filedbmline_comment, "SolarisUserAttr", "uid" },
	{ NS_LDAP_TYPE_PROFILE, genent_prof_attr, dump_prof_attr,
		filedbmline_comment, "SolarisProfAttr", "cn" },
	{ NS_LDAP_TYPE_EXECATTR, genent_exec_attr, dump_exec_attr,
		filedbmline_comment, "SolarisExecAttr", "cn" },
	{ NS_LDAP_TYPE_AUTHATTR, genent_auth_attr, dump_auth_attr,
		filedbmline_comment, "SolarisAuthAttr", "cn" },
	{ NS_LDAP_TYPE_TNRHDB, genent_tnrhdb, dump_tnrhdb,
		filedbmline_comment, "ipTnetHost", "ipTnetNumber" },
	{ NS_LDAP_TYPE_TNRHTP, genent_tnrhtp, dump_tnrhtp,
		filedbmline_comment, "ipTnetTemplate", "ipTnetTemplateName" },
	{ NS_LDAP_TYPE_PROJECT, genent_project, dump_project,
		filedbmline_comment, "SolarisProject", "SolarisProjectName" },
	{ 0, 0, 0, 0, 0, 0 }
};




static int lineno = 0;

static	void
addfile()
{
	struct line_buf line;
	struct file_loc loc;

	/* Initializing the Line Buffer */
	line_buf_init(&line);

	/* Loop through all the lines in the file */
	while (tt->filedbmline(&line, etcf, &lineno, &loc)) {
		switch ((*(tt->genent))(line.str, addentry)) {
		case GENENT_OK:
			break;
		case GENENT_PARSEERR:
			(void) fprintf(stderr,
			    gettext("parse error: %s (line %d)\n"),
			    parse_err_msg, lineno);
			exit_val = 1;
			break;
		case GENENT_CBERR:
			(void) fprintf(stderr,
			    gettext("Error while adding line: %s\n"),
			    line.str);
			exit_val = 2;
			free(line.str);
			return;
		case GENENT_ERR:
			(void) fprintf(stderr,
			    gettext("Internal Error while adding line: %s\n"),
			    line.str);
			exit_val = 3;
			free(line.str);
			return;
		}
	}
	free(line.str);
}

static void
dumptable(char *service)
{

	ns_ldap_result_t *eres = NULL;
	ns_ldap_error_t *err = NULL;
	int	rc = 0, success = 0;
	char	filter[BUFSIZ];
	int	done = 0;
	void	*cookie = NULL;

	/* set the appropriate filter */
	if (strcmp(tt->ttype, NS_LDAP_TYPE_PROFILE) == 0) {
		/*
		 * prof_attr entries are SolarisProfAttr
		 * without AUXILIARY SolarisExecAttr
		 */
		(void) snprintf(filter, sizeof (filter),
		    "(&(objectclass=%s)(!(objectclass=SolarisExecAttr)))",
		    tt->objclass);
	} else if (strcmp(tt->ttype, NS_LDAP_TYPE_TNRHDB) == 0) {
		/*
		 * tnrhtp entries are ipTnet entries with SolarisAttrKeyValue
		 */
		(void) snprintf(filter, sizeof (filter),
		    "(&(objectclass=%s)(SolarisAttrKeyValue=*)))",
		    tt->objclass);
	} else {
		(void) snprintf(filter, sizeof (filter),
		    "(objectclass=%s)", tt->objclass);
	}

	if (flags & F_VERBOSE)
		(void) fprintf(stdout, gettext("FILTER = %s\n"), filter);

	/* Pass cred only if supplied. Cred is not always needed for dump */
	if (authority.cred.unix_cred.userID == NULL ||
	    authority.cred.unix_cred.passwd == NULL)
		rc = __ns_ldap_firstEntry(service, filter, tt->sortattr, NULL,
		    NULL, NULL, NS_LDAP_HARD, &cookie, &eres, &err, NULL);
	else
		rc = __ns_ldap_firstEntry(service, filter, tt->sortattr, NULL,
		    NULL, &authority, NS_LDAP_HARD, &cookie, &eres, &err, NULL);

	switch (rc) {
	case NS_LDAP_SUCCESS:
		nent_add++;
		success = 1;
		if (eres != NULL) {
			if (strcmp(databasetype, "publickey") == 0)
				dump_publickey(eres, service);
			else
				(*(tt->dump))(eres);
		}
		else
			(void) fprintf(stderr, gettext("No entries found.\n"));
		break;

	case NS_LDAP_OP_FAILED:
		exit_val = 2;
		(void) fprintf(stderr, gettext("operation failed.\n"));
		break;

	case NS_LDAP_INVALID_PARAM:
		exit_val = 2;
		(void) fprintf(stderr,
		    gettext("invalid parameter(s) passed.\n"));
		break;

	case NS_LDAP_NOTFOUND:
		exit_val = 2;
		(void) fprintf(stderr, gettext("entry not found.\n"));
		break;

	case NS_LDAP_MEMORY:
		exit_val = 2;
		(void) fprintf(stderr,
		    gettext("internal memory allocation error.\n"));
		break;

	case NS_LDAP_CONFIG:
		exit_val = 2;
		(void) fprintf(stderr,
		    gettext("LDAP Configuration problem.\n"));
		perr(err);
		break;

	case NS_LDAP_PARTIAL:
		exit_val = 2;
		(void) fprintf(stderr,
		    gettext("partial result returned\n"));
		perr(err);
		break;

	case NS_LDAP_INTERNAL:
		exit_val = 2;
		(void) fprintf(stderr,
		    gettext("internal LDAP error occured.\n"));
		perr(err);
		break;
	}

	if (eres != NULL) {
		(void) __ns_ldap_freeResult(&eres);
		eres = NULL;
	}

	if (success) {
		while (!done) {
			rc = __ns_ldap_nextEntry(cookie, &eres, &err);
			if (rc != NS_LDAP_SUCCESS || eres  == NULL) {
				done = 1;
				continue;
			}

			/* Print the result */
			if (eres != NULL) {
				if (strcmp(databasetype, "publickey") == 0)
					dump_publickey(eres, service);
				else
					(*(tt->dump))(eres);
				(void) __ns_ldap_freeResult(&eres);
				eres = NULL;
			}
		}
	}
}

int
main(int argc, char **argv)
{
	char			*password;
	ns_standalone_conf_t	standalone_cfg = standaloneDefaults;
	int			c;
	int			rc;
	int			ldaprc;
	int			authstried = 0;
	int			op = OP_ADD;
	char			*ttype, *authmech = 0, *etcfile = 0;
	/* Temporary password variable */
	char			ps[LDAP_MAXNAMELEN];
	char			filter[BUFSIZ];
	void			**paramVal = NULL;
	ns_auth_t		**app;
	ns_auth_t		**authpp = NULL;
	ns_auth_t		*authp = NULL;
	ns_ldap_error_t		*errorp = NULL;
	ns_ldap_result_t	*resultp;
	ns_ldap_entry_t		*e;
	int			flag = 0;
	int			version1 = 0;

	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	openlog("ldapaddent", LOG_PID, LOG_USER);

	inputbasedn = NULL;
	authority.cred.unix_cred.passwd = NULL;
	authority.cred.unix_cred.userID = NULL;
	authority.auth.type = NS_LDAP_AUTH_SIMPLE;

	while ((c = getopt(argc, argv, "cdh:N:M:vpf:D:w:j:b:a:P:r:")) != EOF) {
		switch (c) {
		case 'd':
			if (op)
				usage(gettext(
				    "no other option should be specified"));
			op = OP_DUMP;
			break;
		case 'c':
			continue_onerror = 1;
			break;
		case 'v':
			flags |= F_VERBOSE;
			break;
		case 'p':
			flags |= F_PASSWD;
			break;
		case 'M':
			standalone_cfg.type = NS_LDAP_SERVER;
			standalone_cfg.SA_DOMAIN = optarg;
			break;
		case 'h':
			standalone_cfg.type = NS_LDAP_SERVER;
			if (separatePort(optarg,
			    &standalone_cfg.SA_SERVER,
			    &standalone_cfg.SA_PORT) > 0) {
				exit(1);
			}
			break;
		case 'P':
			standalone_cfg.type = NS_LDAP_SERVER;
			authority.hostcertpath = optarg;
			break;
		case 'N':
			standalone_cfg.type = NS_LDAP_SERVER;
			standalone_cfg.SA_PROFILE_NAME = optarg;
			break;
		case 'f':
			etcfile = optarg;
			break;
		case 'D':
			authority.cred.unix_cred.userID = strdup(optarg);
			break;
		case 'w':
			if (authority.cred.unix_cred.passwd) {
				(void) fprintf(stderr,
				    gettext("Warning: The -w option is mutually"
				    " exclusive of -j. -w is ignored.\n"));
				break;
			}

			if (optarg != NULL &&
			    optarg[0] == '-' && optarg[1] == '\0') {
				/* Ask for a password later */
				break;
			}

			authority.cred.unix_cred.passwd = strdup(optarg);
			break;
		case 'j':
			if (authority.cred.unix_cred.passwd != NULL) {
				(void) fprintf(stderr,
				    gettext("The -w option is mutually "
				    "exclusive of -j. -w is ignored.\n"));
				free(authority.cred.unix_cred.passwd);
			}
			authority.cred.unix_cred.passwd = readPwd(optarg);
			if (authority.cred.unix_cred.passwd == NULL) {
				exit(1);
			}
			break;
		case 'b':
			inputbasedn = strdup(optarg);
			break;
		case 'a':
			authmech = strdup(optarg);
			break;
		default:
			usage(gettext("Invalid option"));
		}
	}

	if (standalone_cfg.type == NS_LDAP_SERVER &&
	    standalone_cfg.SA_SERVER == NULL) {
		(void) fprintf(stderr,
		    gettext("Please specify an LDAP server you want "
		    "to connect to. \n"));
		exit(1);
	}

	if (authmech != NULL) {
		if (__ns_ldap_initAuth(authmech, &authority.auth, &errorp) !=
		    NS_LDAP_SUCCESS) {
			if (errorp) {
				(void) fprintf(stderr, "%s", errorp->message);
				(void) __ns_ldap_freeError(&errorp);
			}
			exit(1);
		}
	}

	if (authority.auth.saslmech != NS_LDAP_SASL_GSSAPI &&
	    authority.cred.unix_cred.userID == NULL &&
	    op != OP_DUMP) {
	    /* This is not an optional parameter. Exit */
		(void) fprintf(stderr,
		    gettext("DN must be specified unless SASL/GSSAPI is used."
		    " Use option -D.\n"));
		exit(1);
	}

	if (authority.auth.saslmech != NS_LDAP_SASL_GSSAPI &&
	    authority.cred.unix_cred.passwd == NULL &&
	    (op != OP_DUMP ||
	    standalone_cfg.type != NS_CACHEMGR &&
	    authority.cred.unix_cred.userID != NULL)) {
		/* If password is not specified, then prompt user for it. */
		password = getpassphrase("Enter password:");
		(void) strcpy(ps, password);
		authority.cred.unix_cred.passwd = strdup(ps);
	}

	standalone_cfg.SA_AUTH = authmech == NULL ? NULL : &authority.auth;
	standalone_cfg.SA_CERT_PATH = authority.hostcertpath;
	standalone_cfg.SA_BIND_DN = authority.cred.unix_cred.userID;
	standalone_cfg.SA_BIND_PWD = authority.cred.unix_cred.passwd;

	if (__ns_ldap_initStandalone(&standalone_cfg,
	    &errorp) != NS_LDAP_SUCCESS) {
		if (errorp) {
			(void) fprintf(stderr, "%s", errorp->message);
		}
		exit(1);
	}

	if (authmech == NULL) {
		ldaprc = __ns_ldap_getParam(NS_LDAP_AUTH_P, (void ***)&authpp,
		    &errorp);
		if (ldaprc != NS_LDAP_SUCCESS ||
		    (authpp == NULL && op != OP_DUMP)) {
			(void) fprintf(stderr,
			    gettext("No legal authentication method "
			    "configured.\n"));
			(void) fprintf(stderr,
			    gettext("Provide a legal authentication method "
			    "using -a option\n"));
			exit(1);
		}

		/* Use the first authentication method which is not none */
		for (app = authpp; *app; app++) {
			authp = *app;
			if (authp->type != NS_LDAP_AUTH_NONE) {
				authstried++;
				authority.auth.type = authp->type;
				authority.auth.tlstype = authp->tlstype;
				authority.auth.saslmech = authp->saslmech;
				authority.auth.saslopt = authp->saslopt;
				break;
			}
		}
		if (authstried == 0 && op != OP_DUMP) {
			(void) fprintf(stderr,
			    gettext("No legal authentication method configured."
			    "\nProvide a legal authentication method using "
			    "-a option"));
			exit(1);
		}
		if (authority.auth.saslmech == NS_LDAP_SASL_GSSAPI &&
		    authority.cred.unix_cred.passwd != NULL &&
		    authority.cred.unix_cred.userID != NULL) {
			/*
			 * -a is not specified and the auth method sasl/GSSAPI
			 * is defined in the configuration of the ldap profile.
			 * Even -D and -w is provided it's not valid usage.
			 * Drop them on the floor.
			 */

			(void) fprintf(stderr,
			    gettext("The default authentication is "
			    "sasl/GSSAPI.\n"
			    "The bind DN and password will be ignored.\n"));
			authority.cred.unix_cred.passwd = NULL;
			authority.cred.unix_cred.userID = NULL;
		}
	}

	ttype = argv[optind++];

	if (ttype == NULL) {
		usage(gettext("No database type specified"));
		exit(1);
	}

	if (strncasecmp(ttype, "automount", 9) == 0) {
		(void) fprintf(stderr,
		    gettext("automount is not a valid service for ldapaddent.\n"
		    "Please use auto_*.\n"
		    "e.g.  auto_home, auto_ws etc.\n "));
		exit(1);
	}

	for (tt = ttypelist; tt->ttype; tt++) {
		if (strcmp(tt->ttype, ttype) == 0)
			break;
		if (strcmp(tt->ttype, NS_LDAP_TYPE_AUTOMOUNT) == 0 &&
		    strncmp(ttype, NS_LDAP_TYPE_AUTOMOUNT,
		    sizeof (NS_LDAP_TYPE_AUTOMOUNT) - 1) == 0)
			break;
	}

	if (tt->ttype == 0) {
		(void) fprintf(stderr,
		    gettext("database %s not supported;"
		    " supported databases are:\n"), ttype);
		for (tt = ttypelist; tt->ttype; tt++)
			(void) fprintf(stderr, gettext("\t%s\n"), tt->ttype);
		exit(1);
	}

	if (flags & F_VERBOSE)
		(void) fprintf(stdout, gettext("SERVICE = %s\n"), tt->ttype);

	databasetype = ttype;

	if (strcmp(tt->ttype, NS_LDAP_TYPE_AUTOMOUNT) == 0) {
		paramVal = NULL;
		errorp = NULL;
		rc = __ns_ldap_getParam(NS_LDAP_FILE_VERSION_P, &paramVal,
		    &errorp);
		if (paramVal && *paramVal &&
		    strcasecmp(*paramVal, NS_LDAP_VERSION_1) == 0)
			version1 = 1;
		if (paramVal)
			(void) __ns_ldap_freeParam(&paramVal);
		if (errorp)
			(void) __ns_ldap_freeError(&errorp);
	}

	/* Check if the container exists in first place */
	(void) strcpy(&filter[0], "(objectclass=*)");

	rc = __ns_ldap_list(databasetype, filter, NULL, (const char **)NULL,
	    NULL, NS_LDAP_SCOPE_BASE, &resultp, &errorp, NULL, NULL);

	/* create a container for auto_* if it does not exist already */
	if ((rc == NS_LDAP_NOTFOUND) && (op == OP_ADD) &&
	    (strcmp(tt->ttype, NS_LDAP_TYPE_AUTOMOUNT) == 0)) {
		static	char *oclist[] = {NULL, "top", NULL};
		if (version1)
			oclist[0] = "nisMap";
		else
			oclist[0] = "automountMap";
		e = __s_mk_entry(oclist, 3);
		if (e == NULL) {
			(void) fprintf(stderr,
			    gettext("internal memory allocation error.\n"));
			exit(1);
		}
		if (__s_add_attr(e,
		    version1 ? "nisMapName" : "automountMapName",
		    databasetype) != NS_LDAP_SUCCESS) {
			(void) fprintf(stderr,
			    gettext("internal memory allocation error.\n"));
			ldap_freeEntry(e);
			exit(1);
		}

		if (inputbasedn == NULL) {
			if (get_basedn(databasetype, &inputbasedn) !=
			    NS_LDAP_SUCCESS) {
				(void) fprintf(stderr,
				    gettext("Could not obtain basedn\n"));
				ldap_freeEntry(e);
				exit(1);
			}
		}
		if (__ns_ldap_addEntry(databasetype, inputbasedn, e,
		    &authority, flag, &errorp) != NS_LDAP_SUCCESS) {
			(void) fprintf(stderr,
			    gettext("Could not create container for %s\n"),
			    databasetype);
			ldap_freeEntry(e);
		}
	} else if (strcmp(databasetype, "publickey") != 0) {
		if (rc == NS_LDAP_NOTFOUND) {
			(void) fprintf(stderr,
			    gettext("Container %s does not exist\n"),
			    databasetype);
			exit(1);
		}
	}

	if (op == OP_DUMP) {
		if (strcmp(databasetype, "publickey") == 0) {
			dumptable("hosts");
			dumptable("passwd");
		} else {
			dumptable(databasetype);
		}
		exit(exit_val);
	}

	if (etcfile) {
		if ((etcf = fopen(etcfile, "r")) == 0) {
			(void) fprintf(stderr,
			    gettext("can't open file %s\n"), etcfile);
			exit(1);
		}
	} else {
		etcfile = "stdin";
		etcf = stdin;
	}

	if (op == OP_ADD) {
		(void) addfile();
		(void) fprintf(stdout, gettext("%d entries added\n"), nent_add);
	}

	__ns_ldap_cancelStandalone();
	/* exit() -> return for make lint */
	return (exit_val);
}


/*
 * This is called when service == auto_*.
 * It calls __ns_ldap_getSearchDescriptors
 * to generate the dn from SSD's base dn.
 * If there is no SSD available,
 * default base dn will be used
 * Only the first baseDN in the SSD is used
 */

static int get_basedn(char *service, char **basedn) {
	int rc = NS_LDAP_SUCCESS;
	char *dn = NULL;
	ns_ldap_search_desc_t **desc = NULL;
	ns_ldap_error_t *errp = NULL;
	void		**paramVal = NULL;
	int		prepend_automountmapname = FALSE;

	/*
	 * Get auto_* SSD first
	 */

	if ((rc = __ns_ldap_getSearchDescriptors(
			(const char *) service,
			&desc, &errp))  == NS_LDAP_SUCCESS &&
		desc != NULL) {

		if (desc[0] != NULL && desc[0]->basedn != NULL) {
			dn = strdup(desc[0]->basedn);
			if (dn == NULL) {
				(void) __ns_ldap_freeSearchDescriptors
						(&desc);
				return (NS_LDAP_MEMORY);
			}
		}
	}

	/* clean up */
	if (desc) (void) __ns_ldap_freeSearchDescriptors(&desc);
	if (errp) (void) __ns_ldap_freeError(&errp);

	/*
	 * If no dn is duplicated from auto_* SSD, try automount SSD
	 */
	if (dn == NULL) {
		if ((rc = __ns_ldap_getSearchDescriptors(
				"automount", &desc, &errp))
				== NS_LDAP_SUCCESS && desc != NULL) {

			if (desc[0] != NULL && desc[0]->basedn != NULL) {
				dn = strdup(desc[0]->basedn);
				if (dn == NULL) {
					(void) __ns_ldap_freeSearchDescriptors
							(&desc);
					return (NS_LDAP_MEMORY);
				}
				prepend_automountmapname = TRUE;
			}
		}
		/* clean up */
		if (desc) (void) __ns_ldap_freeSearchDescriptors(&desc);
		if (errp) (void) __ns_ldap_freeError(&errp);
	}

	/*
	 * If no dn is duplicated from auto_* or automount SSD,
	 * use default DN
	 */

	if (dn == NULL) {
		if ((rc = __ns_ldap_getParam(NS_LDAP_SEARCH_BASEDN_P,
			&paramVal, &errp)) == NS_LDAP_SUCCESS) {
			dn = strdup((char *)paramVal[0]);
			if (dn == NULL) {
				(void) __ns_ldap_freeParam(&paramVal);
				return (NS_LDAP_MEMORY);
			}
			prepend_automountmapname = TRUE;
		}
		if (paramVal) (void) __ns_ldap_freeParam(&paramVal);
		if (errp) (void) __ns_ldap_freeError(&errp);
	}


	if (dn == NULL) {
		return (NS_LDAP_OP_FAILED);
	} else {
		/*
		 * If dn is duplicated from
		 * automount SSD basedn or
		 * default base dn
		 * then prepend automountMapName=auto_xxx
		 */
		if (prepend_automountmapname)
			rc = __s_api_prepend_automountmapname_to_dn(
				service, &dn, &errp);

		if (rc != NS_LDAP_SUCCESS) {
			(void) __ns_ldap_freeError(&errp);
			free(dn);
			return (rc);
		}

		*basedn = dn;

		return (NS_LDAP_SUCCESS);
	}
}
static char *
h_errno2str(int h_errno) {
	switch (h_errno) {
	case HOST_NOT_FOUND:
		return ("HOST_NOT_FOUND");
	case TRY_AGAIN:
		return ("TRY_AGAIN");
	case NO_RECOVERY:
		return ("NO_RECOVERY");
	case NO_DATA:
		return ("NO_DATA");
	default:
		break;
	}
	return ("UNKNOWN_ERROR");
}
