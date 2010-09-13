/*
 *
 * Copyright (c) 1998-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 *
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *  Copyright (c) 1990 Regents of the University of Michigan.
 *  All rights reserved.
 *
 *  search.c
 */

#ifndef lint
static char copyright[] = "@(#) Copyright (c) 1990 Regents of the University of Michigan.\nAll rights reserved.\n";
#endif

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h> /* free() for Solaris */

#ifdef MACOS
#include <stdlib.h>
#include "macos.h"
#endif /* MACOS */

#if defined(DOS) || defined(_WIN32)
#include "msdos.h"
#endif /* DOS */

#if !defined(MACOS) && !defined(DOS) && !defined(_WIN32)
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#endif
#include "lber.h"
#include "ldap.h"
#include "ldap-private.h"
#include "ldap-int.h"

#ifdef NEEDPROTOS
static char *find_right_paren(char *s);
static char *put_complex_filter(BerElement *ber, char *str,
	unsigned int tag, int not);
static int put_filter(BerElement *ber, char *str);
static int put_simple_filter(BerElement *ber, char *str);
static int put_substring_filter(BerElement *ber, char *type, char *str);
static int put_filter_list(BerElement *ber, char *str);
static char *star_search(char *str);
static int hex_char2int(char c);
static int decode_value(char *str);
#else
static char *find_right_paren();
static char *put_complex_filter();
static int put_filter();
static int put_simple_filter();
static int put_substring_filter();
static int put_filter_list();
static char *star_search();
static int hex_char2int();
static int decode_value();
#endif /* NEEDPROTOS */


BerElement *
ldap_build_search_req(LDAP *ld, char *base, int scope, char *filter,
		char **attrs, int attrsonly, LDAPControl ** serverctrls,
		struct timeval *timeoutp, int sizelimit)
{
	BerElement	*ber;
	int		err;
	int theSizeLimit, theTimeLimit;
	char *theFilter;

	/*
	 * Create the search request.  It looks like this:
	 *	SearchRequest := [APPLICATION 3] SEQUENCE {
	 *		baseObject	DistinguishedName,
	 *		scope		ENUMERATED {
	 *			baseObject	(0),
	 *			singleLevel	(1),
	 *			wholeSubtree	(2)
	 *		},
	 *		derefAliases	ENUMERATED {
	 *			neverDerefaliases	(0),
	 *			derefInSearching	(1),
	 *			derefFindingBaseObj	(2),
	 *			alwaysDerefAliases	(3)
	 *		},
	 *		sizelimit	INTEGER (0 .. 65535),
	 *		timelimit	INTEGER (0 .. 65535),
	 *		attrsOnly	BOOLEAN,
	 *		filter		Filter,
	 *		attributes	SEQUENCE OF AttributeType
	 *	}
	 * wrapped in an ldap message.
	 */

	if (filter == NULL || *filter == '\0') {
		ld->ld_errno = LDAP_PARAM_ERROR;
		return (NULLBER);
	}

	/* create a message to send */
	if ((ber = alloc_ber_with_options(ld)) == NULLBER) {
		return (NULLBER);
	}

	if (base == NULL) {
	    base = "";
	}

	if (timeoutp != NULL) {
		if (timeoutp->tv_sec > 0) {
			theTimeLimit = (int)(timeoutp->tv_sec +
				(timeoutp->tv_usec / 1000000));
		} else if (timeoutp->tv_usec > 0) {
			theTimeLimit = 1; /* minimum we can express in LDAP */
		} else {
			theTimeLimit = 0;  /* no limit */
		}
	} else {
		theTimeLimit = ld->ld_timelimit;
	}

#ifdef CLDAP
	if (ld->ld_sb.sb_naddr > 0) {
	    err = ber_printf(ber, "{ist{seeiib", ++ld->ld_msgid,
		ld->ld_cldapdn, LDAP_REQ_SEARCH, base, scope, ld->ld_deref,
		sizelimit == -1 ? ld->ld_sizelimit : sizelimit, theTimeLimit,
		attrsonly);
	} else {
#endif /* CLDAP */
		err = ber_printf(ber, "{it{seeiib", ++ld->ld_msgid,
		    LDAP_REQ_SEARCH, base, scope, ld->ld_deref,
		    sizelimit == -1 ? ld->ld_sizelimit : sizelimit,
		    theTimeLimit, attrsonly);
#ifdef CLDAP
	}
#endif /* CLDAP */

	if (err == -1) {
		ld->ld_errno = LDAP_ENCODING_ERROR;
		ber_free(ber, 1);
		return (NULLBER);
	}

	theFilter = filter;
	while (*theFilter == ' ') theFilter++;
	if ((*theFilter == '&') || (*theFilter == '|') || (*theFilter == '!')) {
		char *ptr = theFilter;
		theFilter = (char *)calloc(1, strlen(ptr) + 3);
		sprintf(theFilter, "(%s)", ptr);
	} else {
		theFilter = strdup(filter);
	}
	err = put_filter(ber, theFilter);
	free(theFilter);

	if (err  == -1) {
		ld->ld_errno = LDAP_FILTER_ERROR;
		ber_free(ber, 1);
		return (NULLBER);
	}

	if (ber_printf(ber, "{v}}", attrs) == -1) {
		ld->ld_errno = LDAP_ENCODING_ERROR;
		ber_free(ber, 1);
		return (NULLBER);
	}

	/* LDAPv3 */
	/* Code controls if any */
	if (serverctrls && serverctrls[0]) {
		if (ldap_controls_code(ber, serverctrls) != LDAP_SUCCESS) {
			ld->ld_errno = LDAP_ENCODING_ERROR;
			ber_free(ber, 1);
			return (NULLBER);
		}
	} else if (ld->ld_srvctrls && ld->ld_srvctrls[0]) {
		/* Otherwise, is there any global server ctrls ? */
		if (ldap_controls_code(ber, ld->ld_srvctrls) != LDAP_SUCCESS) {
			ld->ld_errno = LDAP_ENCODING_ERROR;
			ber_free(ber, 1);
			return (NULLBER);
		}
	}

	if (ber_printf(ber, "}") == -1) {
		ld->ld_errno = LDAP_ENCODING_ERROR;
		ber_free(ber, 1);
		return (NULLBER);
	}

	return (ber);
}

/*
 * ldap_search - initiate an ldap (and X.500) search operation.  Parameters:
 *
 *	ld		LDAP descriptor
 *	base		DN of the base object
 *	scope		the search scope - one of LDAP_SCOPE_BASE,
 *			    LDAP_SCOPE_ONELEVEL, LDAP_SCOPE_SUBTREE
 *	filter		a string containing the search filter
 *			(e.g., "(|(cn=bob)(sn=bob))")
 *	attrs		list of attribute types to return for matches
 *	attrsonly	1 => attributes only 0 => attributes and values
 *
 * Example:
 *	char	*attrs[] = { "mail", "title", 0 };
 *	msgid = ldap_search( ld, "c=us@o=UM", LDAP_SCOPE_SUBTREE, "cn~=bob",
 *	    attrs, attrsonly );
 */
int
ldap_search(LDAP *ld, char *base, int scope, char *filter,
	char **attrs, int attrsonly)
{
	BerElement	*ber;

#if defined(SUN) && defined(_REENTRANT)
	int rv;

	LOCK_LDAP(ld);
#endif
	Debug(LDAP_DEBUG_TRACE, catgets(slapdcat, 1, 242, "ldap_search\n"),
		0, 0, 0);

	if ((ber = ldap_build_search_req(ld, base, scope, filter, attrs,
	    attrsonly, NULL, NULL, -1)) == NULLBER) {
#if defined(SUN) && defined(_REENTRANT)
		UNLOCK_LDAP(ld);
#endif
		return (-1);
	}

#ifndef NO_CACHE
	if (ld->ld_cache != NULL) {
		if (check_cache(ld, LDAP_REQ_SEARCH, ber) == 0) {
			ber_free(ber, 1);
			ld->ld_errno = LDAP_SUCCESS;
			rv = ld->ld_msgid;
#ifdef _REENTRANT
			UNLOCK_LDAP(ld);
#endif
			return (rv);
		}
		add_request_to_cache(ld, LDAP_REQ_SEARCH, ber);
	}
#endif /* NO_CACHE */

	/* send the message */
	rv = send_initial_request(ld, LDAP_REQ_SEARCH, base, ber);
#ifdef _REENTRANT
	UNLOCK_LDAP(ld);
#endif
	return (rv);
}


static char *
find_right_paren(char *s)
{
	int	balance, escape;

	balance = 1;
	escape = 0;
	while (*s && balance) {
		if (escape == 0) {
			if (*s == '(')
				balance++;
			else if (*s == ')')
				balance--;
		}
		if (*s == '\\' && ! escape)
			escape = 1;
		else
			escape = 0;
		if (balance)
			s++;
	}

	return (*s ? s : NULL);
}

static char *
put_complex_filter(BerElement *ber, char *str, unsigned int tag, int not)
{
	char	*next;

	/*
	 * We have (x(filter)...) with str sitting on
	 * the x.  We have to find the paren matching
	 * the one before the x and put the intervening
	 * filters by calling put_filter_list().
	 */

	/* put explicit tag */
	if (ber_printf(ber, "t{", tag) == -1)
		return (NULL);
/*
	if (!not && ber_printf(ber, "{") == -1)
		return (NULL);
*/

	str++;
	if ((next = find_right_paren(str)) == NULL)
		return (NULL);

	*next = '\0';
	if (put_filter_list(ber, str) == -1)
		return (NULL);
	*next++ = ')';

	/* flush explicit tagged thang */
	if (ber_printf(ber, "}") == -1)
		return (NULL);
/*
	if (!not && ber_printf(ber, "}") == -1)
		return (NULL);
*/

	return (next);
}

static int
put_filter(BerElement *ber, char *str)
{
	char	*next, *tmp, *s, *d;
	int	parens, balance, escape;
	int multipleparen = 0;

	/*
	 * A Filter looks like this:
	 *	Filter ::= CHOICE {
	 *		and		[0]	SET OF Filter,
	 *		or		[1]	SET OF Filter,
	 *		not		[2]	Filter,
	 *		equalityMatch	[3]	AttributeValueAssertion,
	 *		substrings	[4]	SubstringFilter,
	 *		greaterOrEqual	[5]	AttributeValueAssertion,
	 *		lessOrEqual	[6]	AttributeValueAssertion,
	 *		present		[7]	AttributeType,
	 *		approxMatch	[8]	AttributeValueAssertion,
	 *		extensibleMatch	[9]	MatchingRuleAssertion
	 *	}
	 *
	 *	SubstringFilter ::= SEQUENCE {
	 *		type		AttributeType,
	 *		SEQUENCE OF CHOICE {
	 *			initial		[0] IA5String,
	 *			any		[1] IA5String,
	 *			final		[2] IA5String
	 *		}
	 *	}
	 *	MatchingRuleAssertion ::= SEQUENCE {
	 *		matchingRule	[1]	MatchingRuleId OPTIONAL,
	 *		type		[2]	AttributeDescription OPTIONAL,
	 *		matchValue	[3]	AssertionValue,
	 *		dnAttributes	[4]	BOOLEAN DEFAULT FALSE
	 *	}
	 *
	 * Note: tags in a choice are always explicit
	 */

	Debug(LDAP_DEBUG_TRACE, catgets(slapdcat, 1, 243,
		"put_filter \"%s\"\n"), str, 0, 0);

	parens = 0;
	while (*str) {
		switch (*str) {
		case '(':
			str++;
			parens++;
			switch (*str) {
			case '&':
				Debug(LDAP_DEBUG_TRACE, catgets(slapdcat, 1,
				    244, "put_filter: AND\n"), 0, 0, 0);

				if ((str = put_complex_filter(ber, str,
				    LDAP_FILTER_AND, 0)) == NULL)
					return (-1);

				parens--;
				break;

			case '|':
				Debug(LDAP_DEBUG_TRACE, catgets(slapdcat, 1,
				    245, "put_filter: OR\n"), 0, 0, 0);

				if ((str = put_complex_filter(ber, str,
				    LDAP_FILTER_OR, 0)) == NULL)
					return (-1);

				parens--;
				break;

			case '!':
				Debug(LDAP_DEBUG_TRACE, catgets(slapdcat, 1,
				    246, "put_filter: NOT\n"), 0, 0, 0);

				if ((str = put_complex_filter(ber, str,
				    LDAP_FILTER_NOT, 1)) == NULL)
					return (-1);

				parens--;
				break;

			case '(':
				Debug(LDAP_DEBUG_TRACE, catgets(slapdcat, 1,
				    402, "put_filter: Double Parentheses\n"),
				    0, 0, 0);
				multipleparen++;
				continue;

			default:
				Debug(LDAP_DEBUG_TRACE, catgets(slapdcat, 1,
				    247, "put_filter: simple\n"), 0, 0, 0);

				balance = 1;
				escape = 0;
				next = str;
				while (*next && balance) {
					if (escape == 0) {
						if (*next == '(')
							balance++;
						else if (*next == ')')
							balance--;
					}
					if (*next == '\\' && ! escape)
						escape = 1;
					else
						escape = 0;
					if (balance)
						next++;
				}
				if (balance != 0)
					return (-1);

				*next = '\0';
				if (put_simple_filter(ber, str) == -1)
					return (-1);
				*next++ = ')';
				str = next;
				parens--;
				break;
			}
			break;

		case ')':
			Debug(LDAP_DEBUG_TRACE, catgets(slapdcat, 1, 248,
			    "put_filter: end\n"), 0, 0, 0);
			if (multipleparen) {
				multipleparen--;
			} else {
				if (ber_printf(ber, "]") == -1)
					return (-1);
			}

			str++;
			parens--;
			break;

		case ' ':
			str++;
			break;

		default:	/* assume it's a simple type=value filter */
			Debug(LDAP_DEBUG_TRACE, catgets(slapdcat, 1, 249,
			    "put_filter: default\n"), 0, 0, 0);
			next = strchr(str, '\0');
			if (put_simple_filter(ber, str) == -1) {
				return (-1);
			}
			str = next;
			break;
		}
	}

	return (parens ? -1 : 0);
}

/*
 * Put a list of filters like this "(filter1)(filter2)..."
 */

static int
put_filter_list(BerElement *ber, char *str)
{
	char	*next;
	char	save;

	Debug(LDAP_DEBUG_TRACE, catgets(slapdcat, 1, 250,
	    "put_filter_list \"%s\"\n"), str, 0, 0);

	while (*str) {
		while (*str && isspace(*str))
			str++;
		if (*str == '\0')
			break;

		if ((next = find_right_paren(str + 1)) == NULL)
			return (-1);
		save = *++next;

		/* now we have "(filter)" with str pointing to it */
		*next = '\0';
		if (put_filter(ber, str) == -1)
			return (-1);
		*next = save;

		str = next;
	}

	return (0);
}

static int
put_simple_filter(BerElement *ber, char *str)
{
	char		*s;
	char		*value, savechar;
	unsigned int	ftype;
	int		rc;
	int		len;

	Debug(LDAP_DEBUG_TRACE, catgets(slapdcat, 1, 251,
	    "put_simple_filter \"%s\"\n"), str, 0, 0);

	if ((s = strchr(str, '=')) == NULL)
		return (-1);
	value = s + 1;
	*s-- = '\0';
	savechar = *s;

	switch (*s) {
	case '<':
		ftype = LDAP_FILTER_LE;
		*s = '\0';
		break;
	case '>':
		ftype = LDAP_FILTER_GE;
		*s = '\0';
		break;
	case '~':
		ftype = LDAP_FILTER_APPROX;
		*s = '\0';
		break;
	/* LDAP V3 : New extensible matching */
	case ':':
		rc = put_extensible_filter(ber, str, value);
		*(value -1) = '=';
		return (rc);
	default:
		if (star_search(value) == NULL) {
			ftype = LDAP_FILTER_EQUALITY;
		} else if (strcmp(value, "*") == 0) {
			ftype = LDAP_FILTER_PRESENT;
		} else {
			rc = put_substring_filter(ber, str, value);
			*(value-1) = '=';
			return (rc);
		}
		break;
	}

	if (*(value -1) == '=')
		return (rc);
	if (ftype == LDAP_FILTER_PRESENT) {
		rc = ber_printf(ber, "ts", ftype, str);
	} else {
		if ((len = decode_value(value)) >= 0)
			rc = ber_printf(ber, "t{so}", ftype, str, value, len);
	}

	*s = savechar;
	*(value-1) = '=';
	return (rc == -1 ? rc : 0);
}

static int
put_substring_filter(BerElement *ber, char *type, char *val)
{
	char		*nextstar, gotstar = 0;
	unsigned int	ftype;
	int		len;

	Debug(LDAP_DEBUG_TRACE, catgets(slapdcat, 1, 252,
		"put_substring_filter \"%1$s=%2$s\"\n"), type, val, 0);

	if (ber_printf(ber, "t{s{", LDAP_FILTER_SUBSTRINGS, type) == -1)
		return (-1);

	while (val != NULL) {
		if ((nextstar = star_search(val)) != NULL)
			*nextstar++ = '\0';

		if (gotstar == 0) {
			ftype = LDAP_SUBSTRING_INITIAL;
		} else if (nextstar == NULL) {
			ftype = LDAP_SUBSTRING_FINAL;
		} else {
			ftype = LDAP_SUBSTRING_ANY;
		}
		if (*val != '\0') {
			if ((len = decode_value(val)) == -1 ||
			    ber_printf(ber, "to", ftype, val, len) == -1)
				return (-1);
		}

		gotstar = 1;
		if (nextstar != NULL)
			*(nextstar-1) = '*';
		val = nextstar;
	}

	if (ber_printf(ber, "}}") == -1)
		return (-1);

	return (0);
}

static int
put_extensible_filter(BerElement *ber, char *type, char *val)
{
	char	*ptr, *ptype;
	char	*dn, *rule;
	int	len;

	Debug(LDAP_DEBUG_TRACE, catgets(slapdcat, 1, 252,
		"put_extensible_filter \"%1$s=%2$s\"\n"), type, val, 0);

	/* type is off form : attr:dn:matchingrule: or :dn:matchingrule: */
	/* type ends with ':', suppress it */
	ptr = strdup(type);
	ptype = ptr;
	while (*ptype) {
		*ptype = tolower(*ptype);
		ptype++;
	}

	len = strlen(ptr);
	if (len > 0 && ptr[len -1] == ':')
		ptr [len - 1] = '\0';
	else {
		return (-1);
	}

	ptype = ptr;
	/* Search first ':dn' */
	if ((dn = strstr(ptype, ":dn")) == NULL) {
		/* No dn */
		/* if there's a : its separating type and matching rule */
		rule = strchr(ptype, ':');
		if (rule == ptype) {
			ptype = NULL;
		}
	} else {
		if (dn == ptype) {
			ptype = NULL;
		} else {
			*dn = '\0';
		}

		rule = dn + 3;
	}

	if (rule && rule[0] == ':') {
		rule[0] = '\0';
		rule++;
	} else {
		rule = NULL;
	}

	if ((ptype == NULL || *ptype == '\0') && rule == NULL) {
		free(ptr);
		return (-1);
	}

	if (ber_printf(ber, "t{", LDAP_FILTER_EXTENSIBLE) == -1) {
		free(ptr);
		return (-1);
	}

	if (rule && *rule && (ber_printf(ber, "ts",
		LDAP_TAG_FEXT_RULE, rule) == -1)) {
		free(ptr);
		return (-1);
	}

	if (ptype && *ptype && (ber_printf(ber, "ts",
		LDAP_TAG_FEXT_TYPE, ptype) == -1)) {
		free(ptr);
		return (-1);
	}

	/* Code value */
	if ((len = decode_value(val)) == -1 ||
	    ber_printf(ber, "to", LDAP_TAG_FEXT_VAL, val, len) == -1) {
		free(ptr);
		return (-1);
	}

	if (dn && (ber_printf(ber, "tb", LDAP_TAG_FEXT_DN, 1) == -1)) {
		free(ptr);
		return (-1);
	}

	free(ptr);

	if (ber_printf(ber, "}") == -1)
		return (-1);

	return (0);
}

int
ldap_search_st(LDAP *ld, char *base, int scope, char *filter, char **attrs,
	int attrsonly, struct timeval *timeout, LDAPMessage **res)
{
	int	msgid;

	if ((msgid = ldap_search(ld, base, scope, filter, attrs, attrsonly))
	    == -1)
		return (ld->ld_errno);

	if (ldap_result(ld, msgid, 1, timeout, res) == -1)
		return (ld->ld_errno);

	if (ld->ld_errno == LDAP_TIMEOUT) {
		(void) ldap_abandon(ld, msgid);
		ld->ld_errno = LDAP_TIMEOUT;
		return (ld->ld_errno);
	}

	return (ldap_result2error(ld, *res, 0));
}

int
ldap_search_s(LDAP *ld, char *base, int scope, char *filter, char **attrs,
	int attrsonly, LDAPMessage **res)
{
	int	msgid;

	if ((msgid = ldap_search(ld, base, scope, filter, attrs, attrsonly))
	    == -1)
		return (ld->ld_errno);

	if (ldap_result(ld, msgid, 1, (struct timeval *)NULL, res) == -1)
		return (ld->ld_errno);

	return (ldap_result2error(ld, *res, 0));
}

/* LDAPv3 API EXTENSIONS */
int ldap_search_ext(LDAP *ld, char *base, int scope, char *filter,
	char **attrs, int attrsonly, LDAPControl **serverctrls,
	LDAPControl **clientctrls, struct timeval *timeoutp, int sizelimit,
	int *msgidp)
{
	BerElement	*ber;
	int rv;

	if (timeoutp != NULL && timeoutp->tv_sec == 0 &&
		timeoutp->tv_usec == 0) {
		timeoutp = NULL;
	}

#ifdef _REENTRANT
	LOCK_LDAP(ld);
#endif
	Debug(LDAP_DEBUG_TRACE, catgets(slapdcat, 1, 242,
		"ldap_search\n"), 0, 0, 0);

	if ((ber = ldap_build_search_req(ld, base, scope, filter, attrs,
	    attrsonly, serverctrls, timeoutp, sizelimit)) == NULLBER) {
		rv = ld->ld_errno;
		if (rv == LDAP_SUCCESS)
			rv = LDAP_OTHER;
#ifdef _REENTRANT
		UNLOCK_LDAP(ld);
#endif
		return (rv);
	}

#ifndef NO_CACHE
	if (ld->ld_cache != NULL) {
		if (check_cache(ld, LDAP_REQ_SEARCH, ber) == 0) {
			ber_free(ber, 1);
			ld->ld_errno = LDAP_SUCCESS;
			*msgidp = ld->ld_msgid;
#ifdef _REENTRANT
			UNLOCK_LDAP(ld);
#endif
			return (LDAP_SUCCESS);
		}
		add_request_to_cache(ld, LDAP_REQ_SEARCH, ber);
	}
#endif /* NO_CACHE */

	/* send the message */
	rv = send_initial_request(ld, LDAP_REQ_SEARCH, base, ber);
	if (rv == -1) {
		rv = ld->ld_errno;
		if (rv == LDAP_SUCCESS) {
			rv = LDAP_OTHER;
		}
#ifdef _REENTRANT
		UNLOCK_LDAP(ld);
#endif
		return (rv);
	}

	*msgidp = rv;
#if _REENTRANT
	UNLOCK_LDAP(ld);
#endif
	return (LDAP_SUCCESS);
}


int ldap_search_ext_s(LDAP *ld, char *base, int scope, char *filter,
	char **attrs, int attrsonly, LDAPControl **serverctrls,
	LDAPControl **clientctrls, struct timeval *timeoutp, int sizelimit,
	LDAPMessage **res)
{
	int msgid;
	int retcode = LDAP_SUCCESS;

	if ((retcode = ldap_search_ext(ld, base, scope, filter, attrs,
		attrsonly, serverctrls, clientctrls, timeoutp, sizelimit,
		&msgid)) != LDAP_SUCCESS)
		return (retcode);
	if (ldap_result(ld, msgid, 1, timeoutp, res) == -1)
		return (ld->ld_errno);


#if _REENTRANT
	LOCK_LDAP(ld);
#endif
	retcode = ldap_parse_result(ld, *res, &ld->ld_errno, &ld->ld_matched,
		&ld->ld_error, &ld->ld_referrals, &ld->ld_ret_ctrls, 0);
	if (retcode == LDAP_SUCCESS)
		retcode = ld->ld_errno;
#if _REENTRANT
	UNLOCK_LDAP(ld);
#endif
	return (retcode);
}

/*
 * Search string for ascii '*' (asterisk) character.
 * RFC 1960 permits an escaped asterisk to pass through.
 * RFC 2254 adds the definition of encoded characters:
 *
 *            Character       ASCII value
 *            ---------------------------
 *            *               0x2a
 *            (               0x28
 *            )               0x29
 *            \               0x5c
 *            NUL             0x00
 *
 * No distinction of escaped characters is made here.
 */
static char *
star_search(char *str)
{
	for (; *str; str++) {
		switch (*str) {
		case '*':
			return (str);
		case '\\':
			if (str[1] == '\0')
				break;	/* input string exahausted */
			++str;	/* Assume RFC 1960 escaped character */
			/* Check for RFC 2254 hex encoding */
			if (hex_char2int(str[0]) >= 0 &&
			    hex_char2int(str[1]) >= 0) {
				str++;	/* skip over RFC 2254 hex encoding */
			}
		default:
			break;
		}
	}
	return (NULL);
}

/*
 * Return integer value of hexadecimal character or (-1) if character is
 * not a hexadecimal digit [0-9A-Fa-f].
 */
static int
hex_char2int(char c)
{
	if (c >= '0' && c <= '9') {
		return (c-'0');
	} else if (c >= 'A' && c <= 'F') {
		return (c-'A'+10);
	} else if (c >= 'a' && c <= 'f') {
		return (c-'a'+10);
	}
	return (-1);
}

/*
 * Modifys passed string converting escaped hexadecimal characters as
 * per RFC 2254 and un-escapes escaped characters.  Returns length of
 * modified string as it may contain null characters as per RFC 2254.
 */
static int
decode_value(char *start)
{
	char *read, *write;
	int hn, ln;

	for (read = write = start; *read; *write++ = *read++) {
		if (*read == '\\') {
			if (*++read == '\0')
				break; /* input string exahausted */
			/*
			 * Assume *read is simple RFC 1960 escaped character.
			 * However check for RFC 2254 hex encoding.
			 */
			if ((hn = hex_char2int(read[0])) >= 0 &&
			    (ln = hex_char2int(read[1])) >= 0) {
				read++;
				*read = (hn<<4)+ln;
			}
		}
	}
	*write = '\0';
	return (write-start);
}

