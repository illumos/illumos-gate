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
 */


#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <errno.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <malloc.h>
#include <stdlib.h>
#include <deflt.h>
#include <limits.h>

#include "ldap_parse.h"
#include "ldap_glob.h"
#include "ldap_attr.h"
#include "ldap_util.h"
#include "ldap_map.h"
#include "ldap_ruleval.h"
#include "nis_parse_ldap_conf.h"

int yp2ldap = 0;
/*
 * List of mapping structures in original (i.e., as in config file) order.
 * Lined on the 'seqNext' field.
 */
__nis_table_mapping_t	*ldapMappingSeq = 0;

/*
 * Call the parser for the config file 'ldapConfFile', and command line
 * attribute settings per 'ldapCLA'.
 *
 * Returns
 *	0	Success
 *	-1	Config file stat/open or parse error
 *	1	No mapping should be used.
 */
int
parseConfig(char **ldapCLA, char *ldapConfFile) {
	int		ret;

	/*
	 * Establish defaults for ldapDBTableMapping, so that we have
	 * valid values even if there's no mapping config to parse.
	 */
	ldapDBTableMapping.initTtlLo = (3600-1800);
	ldapDBTableMapping.initTtlHi = (3600+1800);
	ldapDBTableMapping.ttl = 3600;
	ldapDBTableMapping.enumExpire = 0;
	ldapDBTableMapping.fromLDAP = FALSE;
	ldapDBTableMapping.toLDAP = FALSE;
	ldapDBTableMapping.expire = 0;

	ret = parse_ldap_migration((const char **)ldapCLA, ldapConfFile);

	return (ret);
}

/*
 * Convert the linked list of __nis_table_mapping_t's (produced by the
 * attribute parser) to the 'ldapMappingList', keyed on the objPath.
 *
 * Once this function has returned, the 'tlist' is invalid, and must
 * not be used in any way.
 */
int
linked2hash(__nis_table_mapping_t *tlist) {
	__nis_hash_table_mt	dbids;
	__nis_table_mapping_t	*t, *told, *x, **seqNext;
	__nis_object_dn_t	*o, *to;
	char			*myself = "linked2hash";
#ifdef	NISDB_LDAP_DEBUG
	char			*selectDbid = getenv("NISLDAPSELECTDBID");
	char			**sdi, *s;
	int			i, nsdi;
#endif	/* NISDB_LDAP_DEBUG */


	if (tlist == 0)
		return (0);

	/* proxyInfo.default_nis_domain must end in a dot */
	{
		int	len = slen(proxyInfo.default_nis_domain);

		if (len > 0 && proxyInfo.default_nis_domain[len-1] != '.') {
			char	*domain = am(myself, len+2);

			(void) memcpy(domain, proxyInfo.default_nis_domain,
					len);
			domain[len] = '.';
			domain[len+1] = '\0';
			sfree(proxyInfo.default_nis_domain);
			proxyInfo.default_nis_domain = domain;
		}
	}

#ifdef	NISDB_LDAP_DEBUG
	for (nsdi = 0, s = selectDbid; s != 0 && *s != '\0'; s++) {
		if (*s != ' ') {
			nsdi++;
			while (*s != ' ' && *s != '\0')
				s++;
			if (*s == '\0')
				break;
		}
	}
	if (nsdi > 0) {
		sdi = am(myself, nsdi * sizeof (sdi[0]));
		if (sdi == 0)
			logmsg(MSG_NOTIMECHECK, LOG_WARNING,
				"%s: Memory alloc failure for dbId selection",
				myself);
		else {
			for (i = 0, s = selectDbid; *s != '\0'; s++) {
				if (*s != ' ') {
					sdi[i++] = selectDbid;
					while (*s != ' ' && *s != '\0')
						s++;
					if (*s != '\0') {
						*s = '\0';
						s++;
					} else
						break;
					selectDbid = s;
				}
			}
		}
	}
#endif	/* NISDB_LDAP_DEBUG */

	__nis_init_hash_table(&dbids, 0);

	seqNext = &ldapMappingSeq;
	for (t = tlist; t != 0; t = told) {
		int	len;

#ifdef	NISDB_LDAP_DEBUG
		/*
		 * If the dbId doesn't match 'selectDbid', skip this
		 * mapping. Re-insert on 'tlist', in order to keep memory
		 * leak checking happy. Note that 'tlist' may end up pointing
		 * into the real mapping list, so it shouldn't be used once
		 * this routine has been called.
		 */
		if (nsdi > 0) {
			for (i = 0; i < nsdi; i++) {
				if (strcmp(sdi[i], t->dbId) == 0)
					break;
			}
			if (i >= nsdi) {
				told = t->next;
				if (tlist != t)
					t->next = tlist;
				else
					t->next = 0;
				tlist = t;
				continue;
			}
		}
#endif	/* NISDB_LDAP_DEBUG */

		told = t->next;
		t->next = 0;

		/* Make sure t->item.name is set correctly */
		if (t->item.name == 0)
			t->item.name = t->dbId;

		/* Remove leading dot in object name, if any */
		len = slen(t->objName);
		while (len > 0 && t->objName[0] == '.') {
			(void) memmove(t->objName, &t->objName[1], len);
			len -= 1;
		}

		/*
		 * Initialize the object path, which is what we'll
		 * rehash on.
		 */
		if (yp2ldap) {
			t->objPath = internal_table_name(t->objName,
				t->objPath);
			if (!t->objPath) {
				logmsg(MSG_NOTIMECHECK, LOG_ERR,
			"%s: Failed to obtain internal table name for \"%s\"",
					myself, t->objName);
				return (-1);
			}
		} else {
			t->objPath = am(myself, len + MAXPATHLEN + 1);
			if (t->objPath == 0)
				return (-1);
			if (internal_table_name(t->objName,
				t->objPath) == 0) {
				logmsg(MSG_NOTIMECHECK, LOG_ERR,
			"%s: Failed to obtain internal table name for \"%s\"",
					myself, t->objName);
				return (-1);
			}
		}

		/*
		 * Initialize the column name array.
		 */
		if (!yp2ldap) {
			if (setColumnsDuringConfig && setColumnNames(t)) {
				logmsg(MSG_NOTIMECHECK, LOG_ERR,
				"%s: Unable to find column names for \"%s\"",
					myself, NIL(t->objName));
				return (-1);
			}
		}

		/*
		 * If there are multiple mapping target containers, make
		 * each one into it's own mapping structure. They can all
		 * be minimal copies (i.e., share pointers to sub-structures
		 * other than the objectDN).
		 *
		 * If objectDN is NULL, we will never use this structure.
		 * In order to allow the rest of the mapping code to assume
		 * objectDN != NULL, skip the mapping (even if x == t).
		 */
		for (o = to = t->objectDN; o != 0; o = o->next) {
			__nis_table_mapping_t	*p;

			if (o == to) {
				x = t;
				/*
				 * Only insert the first mapping for an
				 * object on the sequential list.
				 */
				*seqNext = t;
				t->seqNext = 0;
				seqNext = (__nis_table_mapping_t **)&t->seqNext;
			} else {
				x = am(myself, sizeof (*x));
				if (x == 0) {
					/*
					 * This happens during rpc.nisd
					 * initialization, and it's an
					 * unrecoverable disaster, so don't
					 * bother cleaning up.
					 */
					return (-1);
				}
				memcpy(x, t, sizeof (*x));
				x->objectDN = o;
				x->next = 0;
			}

			/*
			 * If x->objectDN->write.base is NULL, clone it from
			 * x->objectDN->read.base.
			 */
			if (x->objectDN->write.scope != LDAP_SCOPE_UNKNOWN) {
				if (x->objectDN->write.base == 0 &&
						x->objectDN->read.base != 0) {
					x->objectDN->write.base =
						sdup(myself, T,
						x->objectDN->read.base);
					if (x->objectDN->write.base == 0)
						return (-1);
				}
				if (x->objectDN->write.attrs == 0 &&
						x->objectDN->read.attrs != 0) {
					x->objectDN->write.attrs =
						sdup(myself, T,
						x->objectDN->read.attrs);
					if (x->objectDN->write.attrs == 0)
						return (-1);
				}
			}

			if (o != to) {
				/* Insert last on the 't->next' list */
				for (p = t; p->next != 0; p = p->next);
				p->next = x;
			}
		}

		/* Insert on dbid hash list */
		if (t->objectDN != 0 && !__nis_insert_item_mt(t, &dbids, 0)) {
			logmsg(MSG_NOTIMECHECK, LOG_ERR,
			"%s: Error inserting mapping for \"%s\" on hash list",
				myself, NIL(t->objName));
#ifdef	NISDB_LDAP_DEBUG
			abort();
#endif	/* NISDB_LDAP_DEBUG */
			return (-1);
		}
	}

	/*
	 * dbids2objs() will remove the entries on 'dbids', so no need
	 * to clean up that list from this function.
	 */
	return (dbids2objs(&dbids, &ldapMappingList));
}

int
dbids2objs(__nis_hash_table_mt *dbids, __nis_hash_table_mt *objs) {
	__nis_table_mapping_t	*t, *o;
	char			*myself = "dbids2objs";


	while ((t = __nis_pop_item_mt(dbids)) != 0) {
		/* Previous entry for this object ? */
		o = __nis_find_item_mt(t->objPath, objs, -1, 0);
		if (o != 0) {
			__nis_table_mapping_t	*p = o;
			/*
			 * Mapping already exists, so this is an alternate.
			 * Find the end of the list of any previous alt's,
			 * and insert there.
			 */
			while (p->next != 0) {
				p = p->next;
			}
			p->next = t;
			if (!__nis_release_item(o, objs, -1)) {
				logmsg(MSG_NOTIMECHECK, LOG_ERR,
					"%s: __nis_release_item error",
					myself);
				return (-1);
			}
		} else {
			t->item.name = t->objPath;
			if (!__nis_insert_item_mt(t, objs, 0)) {
				logmsg(MSG_NOTIMECHECK, LOG_ERR,
					"%s: __nis_insert_item error",
					myself);
				return (-1);
			}
		}
	}

	return (0);
}

/*
 * internal_table_name()
 *
 * Removes the local domain part from a fully qualified name
 * to create the internal table name for an object. These tables are
 * stored in /var/nis/<hostname>
 *
 * Imported from rpc.nisd/nisdb.c.
 */
char *
internal_table_name(nis_name name, char *res)
{
	char		*s, *t;
	int		i, j;

	if (yp2ldap) {
		if (name == NULL)
			return (NULL);
		res = s_strndup(name, strlen(name));
		if (res == NULL)
			return (NULL);
		return (res);
	}

	if (res == NULL)
		return (NULL);
	/* pointer at the first character of the table name */
	s = relative_name(name);

	/*
	 * If s == NULL then either this is a request for a lookup
	 * in our parents namespace (ILLEGAL), or we're the root
	 * server and this is a lookup in our namespace.
	 */
	if (s) {
		return (NULL);
	}

	t = strrchr(res, '/');
	if (t)
		t++; /* Point past the slash */
	/* Strip off the quotes if they were used here. */
	if (t[0] == '"') {
		/* Check for simply a quoted quote. */
		if (t[1] != '"') {
			j = strlen(t);
			/* shift string left by one */
			for (i = 0; i < j; i++)
				t[i] = t[i+1];
			t[j-2] = '\0'; /* Trounce trailing dquote */
		}
	}
	/*
	 * OK so now we have the unique name for the table.
	 * At this point we can fix it up to match local
	 * file system conventions if we so desire. Since it
	 * is only used in this form by _this_ server we can
	 * mangle it any way we want, as long as we are consistent
	 * about it. :-)
	 */
	__make_legal(res);
	return (res);
}

/*
 * SYSTEM DEPENDENT
 *
 * This function makes the table name "legal" for the underlying file system.
 *
 * Imported from rpc.nisd/nisdb.c.
 */
void
__make_legal(char *s)
{
	while (*s) {
		if (isupper(*s))
			*s = tolower(*s);
		s++;
	}
}

/*
 * relative_name()
 * This internal function will remove from the NIS name, the domain
 * name of the current server, this will leave the unique part in
 * the name this becomes the "internal" version of the name. If this
 * function returns NULL then the name we were given to resolve is
 * bad somehow.
 *
 * A dynamically-allocated string is returned.
 *
 * Imported from rpc.nisd/nis_log_common.c
 */

nis_name
relative_name(s)
	char	*s;	/* string with the name in it. */
{
	char			*d;
	char			*buf;
	int			dl, sl;
	name_pos		p;

	if (s == NULL)
		return (NULL);

	d = __nis_rpc_domain();
	if (d == NULL)
		return (NULL);
	dl = strlen(d); 	/* _always dot terminated_   */

	buf = strdup(s);
	if (buf == NULL)
		return (NULL);
	strcpy(buf, s);		/* Make a private copy of 's'   */
	sl = strlen(buf);

	if (dl == 1) {			/* We're the '.' directory   */
		buf[sl-1] = '\0';	/* Lose the 'dot'	  */
		return (buf);
	}

	p = nis_dir_cmp(buf, d);

	/* 's' is above 'd' in the tree */
	if ((p == HIGHER_NAME) || (p == NOT_SEQUENTIAL) || (p == SAME_NAME)) {
		free(buf);
		return (NULL);
	}

	/* Insert a NUL where the domain name starts in the string */
	buf[(sl - dl) - 1] = '\0';

	/* Don't return a zero length name */
	if (buf[0] == '\0') {
		free((void *)buf);
		return (NULL);
	}

	return (buf);
}

/*
 * Wrapper for internal_table_name() that allocates a large enough
 * buffer for the internal name. Return value must be freed by caller.
 * If the input 'name' is NULL, the name of the root directory table
 * is returned.
 */
char *
internalTableName(char *name) {
	char	*buf, *res;
	char	*myself = "internalTableName";

	buf = (char *)am(myself, MAXPATHLEN + NIS_MAXNAMELEN + 1);
	if (buf == 0)
		return (0);

	if (name == 0) {
		(void) memcpy(buf, ROOTDIRFILE, slen(ROOTDIRFILE));
		return (buf);
	}

	res = internal_table_name(name, buf);
	if (res != buf) {
		sfree(buf);
		buf = 0;
	}

	return (buf);
}

/*
 * Return the object mapping for the object indicated either by the
 * internal DB name ('intNameArg'; preferred), or the FQ object name
 * 'name'. If 'asObj' is non-zero, the caller is interested in the
 * object mapping proper, not a mapping of table entries. Optionally,
 * also indicate if the object is mapped from (read) or to (write) LDAP.
 *
 * Note that there may be more than one mapping of the appropriate type.
 * Use the selectTableMapping() function in ldap_map.c to get all
 * alternatives. However, the function below works as a short-cut if:
 *
 *	You only want an indication that _a_ mapping of the desired
 *	type exists, or
 *
 *	You want the non-objectDN information for an object-mapping
 *	proper (i.e., _not_ the mapping for entries in a table).
 */
__nis_table_mapping_t *
getObjMapping(char *name, char *intNameArg, int asObj,
		int *doRead, int *doWrite) {
	__nis_table_mapping_t	*t, *x;
	char			*intName;
	int			freeIntName = 0, rd, wr;

	if (doRead != 0)
		*doRead = 0;
	if (doWrite != 0)
		*doWrite = 0;

	if (intNameArg == 0) {
		if (name == 0)
			return (0);
		intName = internalTableName(name);
		if (intName == 0)
			return (0);
		freeIntName = 1;
	} else {
		intName = intNameArg;
	}

	t = __nis_find_item_mt(intName, &ldapMappingList, 0, 0);
	if (t == 0) {
		if (freeIntName)
			sfree(intName);
		return (0);
	}

	rd = wr = 0;
	for (x = t; x != 0; x = x->next) {
		/*
		 * If we're looking for an object mapping, and this
		 * one's for entries in a table, skip it.
		 */
		if (asObj && x->objType == NIS_TABLE_OBJ &&
				x->numColumns > 0)
			continue;
		/* Check if we should read/write */
		if (x->objectDN->read.scope != LDAP_SCOPE_UNKNOWN)
			rd++;
		if (x->objectDN->write.scope != LDAP_SCOPE_UNKNOWN)
			wr++;
	}

	if (doRead != 0)
		*doRead = (rd > 0) ? 1 : 0;
	if (doWrite != 0)
		*doWrite = (wr > 0) ? 1 : 0;

	if (freeIntName)
		sfree(intName);

	return (x);
}
