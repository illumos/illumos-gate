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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2011 Nexenta Systems, Inc. All rights reserved.
 */

/*
 * native LDAP related utility routines
 */

#include "idmapd.h"
#include "idmap_priv.h"
#include "ns_sldap.h"
#include "nldaputils.h"
#include <assert.h>

/*
 * The following are format strings used to construct LDAP search filters
 * when looking up Native LDAP directory service. The _F_XXX_SSD format
 * is used by the libsldap API if a corresponding SSD is defined in
 * Native LDAP configuration. The SSD contains a string that replaces
 * the first %s in _F_XXX_SSD. If no SSD is defined then the regular
 * _F_XXX format is used.
 *
 * Note that '\\' needs to be represented as "\\5c" in LDAP filters.
 */

/* Native LDAP lookup using UNIX username */
#define	_F_GETPWNAM		"(&(objectClass=posixAccount)(uid=%s))"
#define	_F_GETPWNAM_SSD		"(&(%%s)(uid=%s))"

/*
 * Native LDAP user lookup using names of well-known SIDs
 * Note the use of 1$, 2$ in the format string which basically
 * allows snprintf to re-use its first two arguments.
 */
#define	_F_GETPWWNAMWK \
		"(&(objectClass=posixAccount)(|(%s=%s)(%1$s=BUILTIN\\5c%2$s)))"
#define	_F_GETPWWNAMWK_SSD	"(&(%%s)(|(%s=%s)(%1$s=BUILTIN\\5c%2$s)))"

/* Native LDAP user lookup using winname@windomain OR windomain\winname */
#define	_F_GETPWWNAMDOM \
	"(&(objectClass=posixAccount)(|(%s=%s@%s)(%1$s=%3$s\\5c%2$s)))"
#define	_F_GETPWWNAMDOM_SSD	"(&(%%s)(|(%s=%s@%s)(%1$s=%3$s\\5c%2$s)))"

/* Native LDAP lookup using UID */
#define	_F_GETPWUID		"(&(objectClass=posixAccount)(uidNumber=%u))"
#define	_F_GETPWUID_SSD		"(&(%%s)(uidNumber=%u))"

/* Native LDAP lookup using UNIX groupname */
#define	_F_GETGRNAM		"(&(objectClass=posixGroup)(cn=%s))"
#define	_F_GETGRNAM_SSD		"(&(%%s)(cn=%s))"

/* Native LDAP group lookup using names of well-known SIDs */
#define	_F_GETGRWNAMWK \
		"(&(objectClass=posixGroup)(|(%s=%s)(%1$s=BUILTIN\\5c%2$s)))"
#define	_F_GETGRWNAMWK_SSD	"(&(%%s)(|(%s=%s)(%1$s=BUILTIN\\5c%2$s)))"

/* Native LDAP group lookup using winname@windomain OR windomain\winname */
#define	_F_GETGRWNAMDOM \
		"(&(objectClass=posixGroup)(|(%s=%s@%s)(%1$s=%3$s\\5c%2$s)))"
#define	_F_GETGRWNAMDOM_SSD	"(&(%%s)(|(%s=%s@%s)(%1$s=%3$s\\5c%2$s)))"

/* Native LDAP lookup using GID */
#define	_F_GETGRGID		"(&(objectClass=posixGroup)(gidNumber=%u))"
#define	_F_GETGRGID_SSD		"(&(%%s)(gidNumber=%u))"

/* Native LDAP attribute names */
#define	UID			"uid"
#define	CN			"cn"
#define	UIDNUMBER		"uidnumber"
#define	GIDNUMBER		"gidnumber"
#define	DN			"dn"

#define	IS_NLDAP_RC_FATAL(x)	((x == NS_LDAP_MEMORY) ? 1 : 0)

typedef struct idmap_nldap_q {
	char			**winname;
	char			**windomain;
	char			**unixname;
	uid_t			*pid;
	char			**dn;
	char			**attr;
	char			**value;
	int			is_user;
	idmap_retcode		*rc;
	int			lrc;
	ns_ldap_result_t	*result;
	ns_ldap_error_t		*errorp;
	char			*filter;
	char			*udata;
} idmap_nldap_q_t;

typedef struct idmap_nldap_query_state {
	const char		*nldap_winname_attr;
	const char		*defdom;
	int			nqueries;
	int			qid;
	int			flag;
	ns_ldap_list_batch_t	*batch;
	idmap_nldap_q_t		queries[1];
} idmap_nldap_query_state_t;

/*
 * This routine has been copied from lib/nsswitch/ldap/common/ldap_utils.c
 * after removing the debug statements.
 *
 * This is a generic filter callback function for merging the filter
 * from service search descriptor with an existing search filter. This
 * routine expects userdata to contain a format string with a single %s
 * in it, and will use the format string with sprintf() to insert the
 * SSD filter.
 *
 * This routine and userdata are passed to the __ns_ldap_list_batch_add()
 * API.
 *
 * Consider an example that uses __ns_ldap_list_batch_add() to lookup
 * native LDAP directory using a given userid 'xy12345'. In this
 * example the userdata will contain the filter "(&(%s)(cn=xy1234))".
 * If a SSD is defined to replace the rfc2307bis specified filter
 * i.e. (objectClass=posixAccount) by a site-specific filter
 * say (department=sds) then this routine when called will produce
 * "(&(department=sds)(uid=xy1234))" as the real search filter.
 */
static
int
merge_SSD_filter(const ns_ldap_search_desc_t *desc,
	char **realfilter, const void *userdata)
{
	int	len;
	char *checker;

	if (realfilter == NULL)
		return (NS_LDAP_INVALID_PARAM);
	*realfilter = NULL;
	if (desc == NULL || desc->filter == NULL || userdata == NULL)
		return (NS_LDAP_INVALID_PARAM);

	/* Parameter check.  We only want one %s here, otherwise bail. */
	len = 0;	/* Reuse 'len' as "Number of %s hits"... */
	checker = (char *)userdata;
	do {
		checker = strchr(checker, '%');
		if (checker != NULL) {
			if (len > 0 || *(checker + 1) != 's')
				return (NS_LDAP_INVALID_PARAM);
			len++;	/* Got our %s. */
			checker += 2;
		} else if (len != 1)
			return (NS_LDAP_INVALID_PARAM);
	} while (checker != NULL);

	len = strlen(userdata) + strlen(desc->filter) + 1;
	*realfilter = (char *)malloc(len);
	if (*realfilter == NULL)
		return (NS_LDAP_MEMORY);
	(void) sprintf(*realfilter, (char *)userdata, desc->filter);
	return (NS_LDAP_SUCCESS);
}

static
char
hex_char(int n)
{
	return ("0123456789abcdef"[n & 0xf]);
}

/*
 * If the input string contains special characters that needs to be
 * escaped before the string can be used in a LDAP filter then this
 * function will return a new sanitized string. Otherwise this function
 * returns the input string (This saves us un-necessary memory allocations
 * especially when processing a batch of requests). The caller must free
 * the returned string if it isn't the input string.
 *
 * The escape mechanism for LDAP filter is described in RFC2254 basically
 * it's \hh where hh are the two hexadecimal digits representing the ASCII
 * value of the encoded character (case of hh is not significant).
 * Example: * -> \2a, ( -> \28, ) -> \29, \ -> \5c,
 *
 * outstring = sanitize_for_ldap_filter(instring);
 * if (outstring == NULL)
 *	Out of memory
 * else
 *	Use outstring
 *	if (outstring != instring)
 *		free(outstring);
 * done
 */
char *
sanitize_for_ldap_filter(const char *str)
{
	const char	*p;
	char		*q, *s_str = NULL;
	int		n;

	/* Get a count of special characters */
	for (p = str, n = 0; *p; p++)
		if (*p == '*' || *p == '(' || *p == ')' ||
		    *p == '\\' || *p == '%')
			n++;
	/* If count is zero then no need to sanitize */
	if (n == 0)
		return ((char *)str);
	/* Create output buffer that will contain the sanitized value */
	s_str = calloc(1, n * 2 + strlen(str) + 1);
	if (s_str == NULL)
		return (NULL);
	for (p = str, q = s_str; *p; p++) {
		if (*p == '*' || *p == '(' || *p == ')' ||
		    *p == '\\' || *p == '%') {
			*q++ = '\\';
			*q++ = hex_char(*p >> 4);
			*q++ = hex_char(*p & 0xf);
		} else
			*q++ = *p;
	}
	return (s_str);
}

/*
 * Map libsldap status to idmap  status
 */
static
idmap_retcode
nldaprc2retcode(int rc)
{
	switch (rc) {
	case NS_LDAP_SUCCESS:
	case NS_LDAP_SUCCESS_WITH_INFO:
		return (IDMAP_SUCCESS);
	case NS_LDAP_NOTFOUND:
		return (IDMAP_ERR_NOTFOUND);
	case NS_LDAP_MEMORY:
		return (IDMAP_ERR_MEMORY);
	case NS_LDAP_CONFIG:
		return (IDMAP_ERR_NS_LDAP_CFG);
	case NS_LDAP_OP_FAILED:
		return (IDMAP_ERR_NS_LDAP_OP_FAILED);
	case NS_LDAP_PARTIAL:
		return (IDMAP_ERR_NS_LDAP_PARTIAL);
	case NS_LDAP_INTERNAL:
		return (IDMAP_ERR_INTERNAL);
	case NS_LDAP_INVALID_PARAM:
		return (IDMAP_ERR_ARG);
	default:
		return (IDMAP_ERR_OTHER);
	}
	/*NOTREACHED*/
}

/*
 * Create a batch for native LDAP lookup.
 */
static
idmap_retcode
idmap_nldap_lookup_batch_start(int nqueries, idmap_nldap_query_state_t **qs)
{
	idmap_nldap_query_state_t	*s;

	s = calloc(1, sizeof (*s) +
	    (nqueries - 1) * sizeof (idmap_nldap_q_t));
	if (s == NULL)
		return (IDMAP_ERR_MEMORY);
	if (__ns_ldap_list_batch_start(&s->batch) != NS_LDAP_SUCCESS) {
		free(s);
		return (IDMAP_ERR_MEMORY);
	}
	s->nqueries = nqueries;
	s->flag = NS_LDAP_KEEP_CONN;
	*qs = s;
	return (IDMAP_SUCCESS);
}

/*
 * Add a lookup by winname request to the batch.
 */
static
idmap_retcode
idmap_nldap_bywinname_batch_add(idmap_nldap_query_state_t *qs,
	const char *winname, const char *windomain, int is_user,
	char **dn, char **attr, char **value,
	char **unixname, uid_t *pid, idmap_retcode *rc)
{
	idmap_nldap_q_t		*q;
	const char		*db, *filter, *udata;
	int			flen, ulen, wksid = 0;
	char			*s_winname, *s_windomain;
	const char		**attrs;
	const char		*pwd_attrs[] = {UID, UIDNUMBER, NULL, NULL};
	const char		*grp_attrs[] = {CN, GIDNUMBER, NULL, NULL};

	s_winname = s_windomain = NULL;
	q = &(qs->queries[qs->qid++]);
	q->unixname = unixname;
	q->pid = pid;
	q->rc = rc;
	q->is_user = is_user;
	q->dn = dn;
	q->attr = attr;
	q->value = value;

	if (is_user) {
		db = "passwd";
		if (lookup_wksids_name2sid(winname, NULL, NULL, NULL, NULL,
		    NULL, NULL) == IDMAP_SUCCESS) {
			filter = _F_GETPWWNAMWK;
			udata = _F_GETPWWNAMWK_SSD;
			wksid = 1;
		} else if (windomain != NULL) {
			filter = _F_GETPWWNAMDOM;
			udata = _F_GETPWWNAMDOM_SSD;
		} else {
			*q->rc = IDMAP_ERR_DOMAIN_NOTFOUND;
			goto errout;
		}
		pwd_attrs[2] = qs->nldap_winname_attr;
		attrs = pwd_attrs;
	} else {
		db = "group";
		if (lookup_wksids_name2sid(winname, NULL, NULL, NULL, NULL,
		    NULL, NULL) == IDMAP_SUCCESS) {
			filter = _F_GETGRWNAMWK;
			udata = _F_GETGRWNAMWK_SSD;
			wksid = 1;
		} else if (windomain != NULL) {
			filter = _F_GETGRWNAMDOM;
			udata = _F_GETGRWNAMDOM_SSD;
		} else {
			*q->rc = IDMAP_ERR_DOMAIN_NOTFOUND;
			goto errout;
		}
		grp_attrs[2] = qs->nldap_winname_attr;
		attrs = grp_attrs;
	}

	/*
	 * Sanitize names. No need to sanitize qs->nldap_winname_attr
	 * because if it contained any of the special characters then
	 * it would have been rejected by the function that reads it
	 * from the SMF config. LDAP attribute names can only contain
	 * letters, digits or hyphens.
	 */
	s_winname = sanitize_for_ldap_filter(winname);
	if (s_winname == NULL) {
		*q->rc = IDMAP_ERR_MEMORY;
		goto errout;
	}
	/* windomain could be NULL for names of well-known SIDs */
	if (windomain != NULL) {
		s_windomain = sanitize_for_ldap_filter(windomain);
		if (s_windomain == NULL) {
			*q->rc = IDMAP_ERR_MEMORY;
			goto errout;
		}
	}

	/* Construct the filter and udata using snprintf. */
	if (wksid) {
		flen = snprintf(NULL, 0, filter, qs->nldap_winname_attr,
		    s_winname) + 1;
		ulen = snprintf(NULL, 0, udata, qs->nldap_winname_attr,
		    s_winname) + 1;
	} else {
		flen = snprintf(NULL, 0, filter, qs->nldap_winname_attr,
		    s_winname, s_windomain) + 1;
		ulen = snprintf(NULL, 0, udata, qs->nldap_winname_attr,
		    s_winname, s_windomain) + 1;
	}

	q->filter = malloc(flen);
	if (q->filter == NULL) {
		*q->rc = IDMAP_ERR_MEMORY;
		goto errout;
	}
	q->udata = malloc(ulen);
	if (q->udata == NULL) {
		*q->rc = IDMAP_ERR_MEMORY;
		goto errout;
	}

	if (wksid) {
		(void) snprintf(q->filter, flen, filter,
		    qs->nldap_winname_attr, s_winname);
		(void) snprintf(q->udata, ulen, udata,
		    qs->nldap_winname_attr, s_winname);
	} else {
		(void) snprintf(q->filter, flen, filter,
		    qs->nldap_winname_attr, s_winname, s_windomain);
		(void) snprintf(q->udata, ulen, udata,
		    qs->nldap_winname_attr, s_winname, s_windomain);
	}

	if (s_winname != winname)
		free(s_winname);
	if (s_windomain != windomain)
		free(s_windomain);

	q->lrc = __ns_ldap_list_batch_add(qs->batch, db, q->filter,
	    merge_SSD_filter, attrs, NULL, qs->flag, &q->result,
	    &q->errorp, &q->lrc, NULL, q->udata);

	if (IS_NLDAP_RC_FATAL(q->lrc))
		return (nldaprc2retcode(q->lrc));
	return (IDMAP_SUCCESS);

errout:
	/* query q and its content will be freed by batch_release */
	if (s_winname != winname)
		free(s_winname);
	if (s_windomain != windomain)
		free(s_windomain);
	return (*q->rc);
}

/*
 * Add a lookup by uid/gid request to the batch.
 */
static
idmap_retcode
idmap_nldap_bypid_batch_add(idmap_nldap_query_state_t *qs,
	uid_t pid, int is_user, char **dn, char **attr, char **value,
	char **winname, char **windomain,
	char **unixname, idmap_retcode *rc)
{
	idmap_nldap_q_t		*q;
	const char		*db, *filter, *udata;
	int			len;
	const char		**attrs;
	const char		*pwd_attrs[] = {UID, NULL, NULL};
	const char		*grp_attrs[] = {CN, NULL, NULL};

	q = &(qs->queries[qs->qid++]);
	q->winname = winname;
	q->windomain = windomain;
	q->unixname = unixname;
	q->rc = rc;
	q->is_user = is_user;
	q->dn = dn;
	q->attr = attr;
	q->value = value;

	if (is_user) {
		db = "passwd";
		filter = _F_GETPWUID;
		udata = _F_GETPWUID_SSD;
		pwd_attrs[1] = qs->nldap_winname_attr;
		attrs = pwd_attrs;
	} else {
		db = "group";
		filter = _F_GETGRGID;
		udata = _F_GETGRGID_SSD;
		grp_attrs[1] = qs->nldap_winname_attr;
		attrs = grp_attrs;
	}

	len = snprintf(NULL, 0, filter, pid) + 1;
	q->filter = malloc(len);
	if (q->filter == NULL) {
		*q->rc = IDMAP_ERR_MEMORY;
		return (IDMAP_ERR_MEMORY);
	}
	(void) snprintf(q->filter, len, filter, pid);

	len = snprintf(NULL, 0, udata, pid) + 1;
	q->udata = malloc(len);
	if (q->udata == NULL) {
		*q->rc = IDMAP_ERR_MEMORY;
		return (IDMAP_ERR_MEMORY);
	}
	(void) snprintf(q->udata, len, udata, pid);

	q->lrc = __ns_ldap_list_batch_add(qs->batch, db, q->filter,
	    merge_SSD_filter, attrs, NULL, qs->flag, &q->result,
	    &q->errorp, &q->lrc, NULL, q->udata);

	if (IS_NLDAP_RC_FATAL(q->lrc))
		return (nldaprc2retcode(q->lrc));
	return (IDMAP_SUCCESS);
}

/*
 * Add a lookup by user/group name request to the batch.
 */
static
idmap_retcode
idmap_nldap_byunixname_batch_add(idmap_nldap_query_state_t *qs,
	const char *unixname, int is_user,
	char **dn, char **attr, char **value,
	char **winname, char **windomain, uid_t *pid, idmap_retcode *rc)
{
	idmap_nldap_q_t		*q;
	const char		*db, *filter, *udata;
	int			len;
	char			*s_unixname = NULL;
	const char		**attrs;
	const char		*pwd_attrs[] = {UIDNUMBER, NULL, NULL};
	const char		*grp_attrs[] = {GIDNUMBER, NULL, NULL};

	q = &(qs->queries[qs->qid++]);
	q->winname = winname;
	q->windomain = windomain;
	q->pid = pid;
	q->rc = rc;
	q->is_user = is_user;
	q->dn = dn;
	q->attr = attr;
	q->value = value;

	if (is_user) {
		db = "passwd";
		filter = _F_GETPWNAM;
		udata = _F_GETPWNAM_SSD;
		pwd_attrs[1] = qs->nldap_winname_attr;
		attrs = pwd_attrs;
	} else {
		db = "group";
		filter = _F_GETGRNAM;
		udata = _F_GETGRNAM_SSD;
		grp_attrs[1] = qs->nldap_winname_attr;
		attrs = grp_attrs;
	}

	s_unixname = sanitize_for_ldap_filter(unixname);
	if (s_unixname == NULL) {
		*q->rc = IDMAP_ERR_MEMORY;
		return (IDMAP_ERR_MEMORY);
	}

	len = snprintf(NULL, 0, filter, s_unixname) + 1;
	q->filter = malloc(len);
	if (q->filter == NULL) {
		if (s_unixname != unixname)
			free(s_unixname);
		*q->rc = IDMAP_ERR_MEMORY;
		return (IDMAP_ERR_MEMORY);
	}
	(void) snprintf(q->filter, len, filter, s_unixname);

	len = snprintf(NULL, 0, udata, s_unixname) + 1;
	q->udata = malloc(len);
	if (q->udata == NULL) {
		if (s_unixname != unixname)
			free(s_unixname);
		*q->rc = IDMAP_ERR_MEMORY;
		return (IDMAP_ERR_MEMORY);
	}
	(void) snprintf(q->udata, len, udata, s_unixname);

	if (s_unixname != unixname)
		free(s_unixname);

	q->lrc = __ns_ldap_list_batch_add(qs->batch, db, q->filter,
	    merge_SSD_filter, attrs, NULL, qs->flag, &q->result,
	    &q->errorp, &q->lrc, NULL, q->udata);

	if (IS_NLDAP_RC_FATAL(q->lrc))
		return (nldaprc2retcode(q->lrc));
	return (IDMAP_SUCCESS);
}

/*
 * Free the batch
 */
static
void
idmap_nldap_lookup_batch_release(idmap_nldap_query_state_t *qs)
{
	idmap_nldap_q_t		*q;
	int			i;

	if (qs->batch != NULL)
		(void) __ns_ldap_list_batch_release(qs->batch);
	for (i = 0; i < qs->qid; i++) {
		q = &(qs->queries[i]);
		free(q->filter);
		free(q->udata);
		if (q->errorp != NULL)
			(void) __ns_ldap_freeError(&q->errorp);
		if (q->result != NULL)
			(void) __ns_ldap_freeResult(&q->result);
	}
	free(qs);
}

/*
 * Process all requests added to the batch and then free the batch.
 * The results for individual requests will be accessible using the
 * pointers passed during idmap_nldap_lookup_batch_end.
 */
static
idmap_retcode
idmap_nldap_lookup_batch_end(idmap_nldap_query_state_t *qs)
{
	idmap_nldap_q_t		*q;
	int			i;
	ns_ldap_entry_t		*entry;
	char			**val, *end, *str, *name, *dom;
	idmap_retcode		rc = IDMAP_SUCCESS;

	(void) __ns_ldap_list_batch_end(qs->batch);
	qs->batch = NULL;
	for (i = 0; i < qs->qid; i++) {
		q = &(qs->queries[i]);
		*q->rc = nldaprc2retcode(q->lrc);
		if (*q->rc != IDMAP_SUCCESS)
			continue;
		if (q->result == NULL ||
		    !q->result->entries_count ||
		    (entry = q->result->entry) == NULL ||
		    !entry->attr_count) {
			*q->rc = IDMAP_ERR_NOTFOUND;
			continue;
		}
		/* Get uid/gid */
		if (q->pid != NULL) {
			val = __ns_ldap_getAttr(entry,
			    (q->is_user) ? UIDNUMBER : GIDNUMBER);
			if (val != NULL && *val != NULL)
				*q->pid = strtoul(*val, &end, 10);
		}
		/* Get unixname */
		if (q->unixname != NULL) {
			val = __ns_ldap_getAttr(entry,
			    (q->is_user) ? UID : CN);
			if (val != NULL && *val != NULL) {
				*q->unixname = strdup(*val);
				if (*q->unixname == NULL) {
					rc = *q->rc = IDMAP_ERR_MEMORY;
					goto out;
				}
			}
		}
		/* Get DN for how info */
		if (q->dn != NULL) {
			val = __ns_ldap_getAttr(entry, DN);
			if (val != NULL && *val != NULL) {
				*q->dn = strdup(*val);
				if (*q->dn == NULL) {
					rc = *q->rc = IDMAP_ERR_MEMORY;
					goto out;
				}
			}
		}
		/* Get nldap name mapping attr name for how info */
		if (q->attr != NULL) {
			*q->attr = strdup(qs->nldap_winname_attr);
			if (*q->attr == NULL) {
				rc = *q->rc = IDMAP_ERR_MEMORY;
				goto out;
			}
		}
		/* Get nldap name mapping attr value for how info */
		val =  __ns_ldap_getAttr(entry, qs->nldap_winname_attr);
		if (val == NULL || *val == NULL)
			continue;
		if (q->value != NULL) {
			*q->value = strdup(*val);
			if (*q->value == NULL) {
				rc = *q->rc = IDMAP_ERR_MEMORY;
				goto out;
			}
		}

		/* Get winname and windomain */
		if (q->winname == NULL && q->windomain == NULL)
			continue;
		/*
		 * We need to split the value into winname and
		 * windomain. The value could be either in NT4
		 * style (i.e. dom\name) or AD-style (i.e. name@dom).
		 * We choose the first '\\' if it's in NT4 style and
		 * the last '@' if it's in AD-style for the split.
		 */
		name = dom = NULL;
		if (lookup_wksids_name2sid(*val, NULL, NULL, NULL, NULL, NULL,
		    NULL) == IDMAP_SUCCESS) {
			name = *val;
			dom = NULL;
		} else if ((str = strchr(*val, '\\')) != NULL) {
			*str = '\0';
			name = str + 1;
			dom = *val;
		} else if ((str = strrchr(*val, '@')) != NULL) {
			*str = '\0';
			name = *val;
			dom = str + 1;
		} else {
			idmapdlog(LOG_INFO, "Domain-less "
			    "winname (%s) found in Native LDAP", *val);
			*q->rc = IDMAP_ERR_NS_LDAP_BAD_WINNAME;
			continue;
		}
		if (q->winname != NULL) {
			*q->winname = strdup(name);
			if (*q->winname == NULL) {
				rc = *q->rc = IDMAP_ERR_MEMORY;
				goto out;
			}
		}
		if (q->windomain != NULL && dom != NULL) {
			*q->windomain = strdup(dom);
			if (*q->windomain == NULL) {
				rc = *q->rc = IDMAP_ERR_MEMORY;
				goto out;
			}
		}
	}

out:
	(void) idmap_nldap_lookup_batch_release(qs);
	return (rc);
}

/* ARGSUSED */
idmap_retcode
nldap_lookup_batch(lookup_state_t *state, idmap_mapping_batch *batch,
		idmap_ids_res *result)
{
	idmap_retcode			retcode, rc1;
	int				i, add;
	idmap_mapping			*req;
	idmap_id_res			*res;
	idmap_nldap_query_state_t	*qs = NULL;
	idmap_how			*how;

	if (state->nldap_nqueries == 0)
		return (IDMAP_SUCCESS);

	/* Create nldap lookup batch */
	retcode = idmap_nldap_lookup_batch_start(state->nldap_nqueries, &qs);
	if (retcode != IDMAP_SUCCESS) {
		idmapdlog(LOG_ERR,
		    "Failed to create batch for native LDAP lookup");
		goto out;
	}

	qs->nldap_winname_attr = state->nldap_winname_attr;
	qs->defdom = state->defdom;

	/* Add requests to the batch */
	for (i = 0, add = 0; i < batch->idmap_mapping_batch_len; i++) {
		req = &batch->idmap_mapping_batch_val[i];
		res = &result->ids.ids_val[i];
		retcode = IDMAP_SUCCESS;

		/* Skip if not marked for nldap lookup */
		if (!(req->direction & _IDMAP_F_LOOKUP_NLDAP))
			continue;

		if (IS_ID_SID(req->id1)) {

			/* win2unix request: */

			/*
			 * When processing a win2unix request, nldap lookup
			 * is performed after AD lookup or a successful
			 * name-cache lookup. Therefore we should already
			 * have sid, winname and sidtype. Note that
			 * windomain could be NULL e.g. well-known SIDs.
			 */
			assert(req->id1name != NULL &&
			    (res->id.idtype == IDMAP_UID ||
			    res->id.idtype == IDMAP_GID));

			/* Skip if we already have pid and unixname */
			if (req->id2name != NULL &&
			    res->id.idmap_id_u.uid != IDMAP_SENTINEL_PID) {
				res->retcode = IDMAP_SUCCESS;
				continue;
			}

			/* Clear leftover value */
			free(req->id2name);
			req->id2name = NULL;

			/* Lookup nldap by winname to get pid and unixname */
			add = 1;
			idmap_how_clear(&res->info.how);
			res->info.src = IDMAP_MAP_SRC_NEW;
			how = &res->info.how;
			how->map_type = IDMAP_MAP_TYPE_DS_NLDAP;
			retcode = idmap_nldap_bywinname_batch_add(
			    qs, req->id1name, req->id1domain,
			    (res->id.idtype == IDMAP_UID) ? 1 : 0,
			    &how->idmap_how_u.nldap.dn,
			    &how->idmap_how_u.nldap.attr,
			    &how->idmap_how_u.nldap.value,
			    &req->id2name, &res->id.idmap_id_u.uid,
			    &res->retcode);

		} else if (IS_ID_UID(req->id1) || IS_ID_GID(req->id1)) {

			/* unix2win request: */

			/* Skip if we already have winname */
			if (req->id2name != NULL) {
				res->retcode = IDMAP_SUCCESS;
				continue;
			}

			/* Clear old value */
			free(req->id2domain);
			req->id2domain = NULL;

			/* Set how info */
			idmap_how_clear(&res->info.how);
			res->info.src = IDMAP_MAP_SRC_NEW;
			how = &res->info.how;
			how->map_type = IDMAP_MAP_TYPE_DS_NLDAP;

			/* Lookup nldap by pid or unixname to get winname */
			if (req->id1.idmap_id_u.uid != IDMAP_SENTINEL_PID) {
				add = 1;
				retcode = idmap_nldap_bypid_batch_add(
				    qs, req->id1.idmap_id_u.uid,
				    (req->id1.idtype == IDMAP_UID) ? 1 : 0,
				    &how->idmap_how_u.nldap.dn,
				    &how->idmap_how_u.nldap.attr,
				    &how->idmap_how_u.nldap.value,
				    &req->id2name, &req->id2domain,
				    (req->id1name == NULL) ?
				    &req->id1name : NULL,
				    &res->retcode);
			} else if (req->id1name != NULL) {
				add = 1;
				retcode = idmap_nldap_byunixname_batch_add(
				    qs, req->id1name,
				    (req->id1.idtype == IDMAP_UID) ? 1 : 0,
				    &how->idmap_how_u.nldap.dn,
				    &how->idmap_how_u.nldap.attr,
				    &how->idmap_how_u.nldap.value,
				    &req->id2name, &req->id2domain,
				    &req->id1.idmap_id_u.uid, &res->retcode);
			}

		}

		/*
		 * nldap_batch_add API returns error only on fatal failures
		 * otherwise it returns success and the actual status
		 * is stored in the individual request (res->retcode).
		 * Stop adding requests to this batch on fatal failures
		 * (i.e. if retcode != success)
		 */
		if (retcode != IDMAP_SUCCESS)
			break;
	}

	if (!add)
		idmap_nldap_lookup_batch_release(qs);
	else if (retcode != IDMAP_SUCCESS)
		idmap_nldap_lookup_batch_release(qs);
	else
		retcode = idmap_nldap_lookup_batch_end(qs);

out:
	for (i = 0; i < batch->idmap_mapping_batch_len; i++) {
		req = &batch->idmap_mapping_batch_val[i];
		res = &result->ids.ids_val[i];
		if (!(req->direction & _IDMAP_F_LOOKUP_NLDAP))
			continue;

		/* Reset nldap flag */
		req->direction &= ~(_IDMAP_F_LOOKUP_NLDAP);

		/*
		 * As noted earlier retcode != success if there were fatal
		 * errors during batch_start and batch_adds. If so then set
		 * the status of each nldap request to that error.
		 */
		if (retcode != IDMAP_SUCCESS) {
			res->retcode = retcode;
			continue;
		}
		if (!add)
			continue;

		/*
		 * If we successfully retrieved winname from nldap entry
		 * then lookup winname2sid locally. If not found locally
		 * then mark this request for AD lookup.
		 */
		if (res->retcode == IDMAP_SUCCESS &&
		    req->id2name != NULL &&
		    res->id.idmap_id_u.sid.prefix == NULL &&
		    (IS_ID_UID(req->id1) || IS_ID_GID(req->id1))) {

			rc1 = lookup_name2sid(state->cache,
			    req->id2name, req->id2domain, -1,
			    NULL, NULL,
			    &res->id.idmap_id_u.sid.prefix,
			    &res->id.idmap_id_u.sid.rid,
			    &res->id.idtype,
			    req, 1);
			if (rc1 == IDMAP_ERR_NOTFOUND) {
				req->direction |= _IDMAP_F_LOOKUP_AD;
				state->ad_nqueries++;
			} else
				res->retcode = rc1;
		}

		/*
		 * Unset non-fatal errors in individual request. This allows
		 * the next pass to process other mapping mechanisms for
		 * this request.
		 */
		if (res->retcode != IDMAP_SUCCESS &&
		    res->retcode != IDMAP_ERR_NS_LDAP_BAD_WINNAME &&
		    !(IDMAP_FATAL_ERROR(res->retcode))) {
			idmap_how_clear(&res->info.how);
			res->retcode = IDMAP_SUCCESS;
		}
	}

	state->nldap_nqueries = 0;
	return (retcode);
}
