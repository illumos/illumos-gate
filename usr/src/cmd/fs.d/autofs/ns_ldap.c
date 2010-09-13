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
 *	ns_ldap.c
 *
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <string.h>
#include <ctype.h>
#include <nsswitch.h>
#include <sys/param.h>
#include <sys/types.h>
#include <rpc/rpc.h>
#include <rpcsvc/nfs_prot.h>
#include <sys/errno.h>
#include <libintl.h>
#include "automount.h"
#include "../../../lib/libsldap/common/ns_sldap.h"

/*
 * LDAP schema used for automounter:
 *
 * automountMapName: mapname i.e. auto_home, etc.
 * automountKey: contains the key i.e. the mount point
 * automountInformation: contains the mount options and remote mount location
 * description: an optional description (not used by automounter)
 *
 * For example, if auto_direct has the following line of data:
 *
 * 		/work -rw,intr,nosuid,noquota hosta:/export/work
 *
 * Then this would map to the the following LDAP entry:
 *
 *	dn: automountKey=/work,automountMapName=auto_direct,...
 * 	automountKey: /work
 * 	automountInformation: -rw,intr,nosuid,noquota hosta:/export/work
 *	objectclass: top
 *	objectclass: automount
 *
 * In this container:
 *
 *	dn: automountMapName=auto_direct,...
 *	automountMapName: auto_direct
 *	objectClass: top
 *	objectClass: automountMap
 *
 * Note that the schema can be mapped and SSD's can be used to relocate
 * the default location of these entries.
 *
 */

#define	CAPCHAR '%'
#define	MAXERROR 4000

static char *automountKey = NULL;
static char *automountInformation = NULL;
static char *defaultFilter = NULL;
static int encode = 0;

static int mastermap_callback_ldap();
static int directmap_callback();
static int ldap_err(int);
static int ldap_match();
static int readdir_callback();

struct loadmaster_cbdata {
	char *ptr1;
	char **ptr2;
	char ***ptr3;
};

struct loaddirect_cbdata {
	char *ptr1;
	char *ptr2;
	char **ptr3;
	char ***ptr4;
};

struct dir_cbdata {
	struct dir_entry **list;
	struct dir_entry *last;
	int error;
};

static char *tosunds_str(char *);
static char *tounix_str(char *);

static int
isAttrMapped(char *orig, char *mapped)
{
	char **s;
	char **mappedschema = NULL;

	mappedschema = __ns_ldap_getMappedAttributes("automount", orig);
	if (mappedschema == NULL)
		return (0);
	if (strcasecmp(mappedschema[0], mapped) != 0) {
		for (s = mappedschema; *s != NULL; s++)
			free(*s);
		free(mappedschema);
		return (0);
	}
	for (s = mappedschema; *s != NULL; s++)
		free(*s);
	free(mappedschema);
	return (1);
}

static int
isObjectMapped(char *orig, char *mapped)
{
	char **s;
	char **mappedschema = NULL;

	mappedschema = __ns_ldap_getMappedObjectClass("automount", orig);
	if (mappedschema == NULL)
		return (0);
	if (strcasecmp(mappedschema[0], mapped) != 0) {
		for (s = mappedschema; *s != NULL; s++)
			free(*s);
		free(mappedschema);
		return (0);
	}
	for (s = mappedschema; *s != NULL; s++)
		free(*s);
	free(mappedschema);
	return (1);
}

void
init_ldap(char **stack, char ***stkptr)
{
	/*
	 * Check for version of the profile the client is using
	 *
	 * For version 1 profiles we do encoding of attributes
	 * and use nisMap and nisObject schema for backward compatibility.
	 *
	 * For version 2 profiles we don't do encoding and use
	 * automountMap and automount as default attributes (which can
	 * then be overridden in libsldap if schema mapping is configured
	 * in the profile).
	 *
	 * If profile version is not available, use version 2 as default
	 * and syslog message.
	 */
	int rc, v2 = 1;
	void **paramVal = NULL;
	ns_ldap_error_t *errorp = NULL;
	struct __nsw_switchconfig *conf = NULL;
	struct __nsw_lookup *lkp = NULL;
	enum __nsw_parse_err pserr;
	int	ldap_configured = 0;

#ifdef lint
	stack = stack;
	stkptr = stkptr;
#endif /* lint */

	/* get nsswitch info of "automount */
	conf = __nsw_getconfig("automount", &pserr);

	/* find out if LDAP backend is configured */
	if (conf != NULL) {
		for (lkp = conf->lookups; lkp != NULL; lkp = lkp->next) {
			if (strcmp(lkp->service_name, "ldap") == 0) {
				ldap_configured = 1;
				break;
			}
		}
		/* free conf at the end of "if"  bracket */
		(void) __nsw_freeconfig(conf);
	}

	/* if ldap is not configured, init_ldap is a no op */
	if (!ldap_configured)
		return;

	rc = __ns_ldap_getParam(NS_LDAP_FILE_VERSION_P, &paramVal, &errorp);
	if (rc != NS_LDAP_SUCCESS || !paramVal || !*paramVal) {
		syslog(LOG_ERR, "Can not determine version of LDAP profile"
		    " that is used (%d, %s).  Using version 2 profile"
		    " defaults", rc, (errorp && errorp->message ?
		    errorp->message : ""));
		(void) __ns_ldap_freeError(&errorp);
	} else {
		if (strcasecmp(*paramVal, NS_LDAP_VERSION_1) == 0)
			v2 = 0;
		(void) __ns_ldap_freeParam(&paramVal);
	}

	if (v2) {
		if (trace > 1)
			trace_prt(1, "init_ldap: setting up for version 2\n");
		automountKey = "automountKey";
		automountInformation = "automountInformation";
		defaultFilter = "(&(objectClass=automount)(automountKey=%s))";

		/* check for automountMapName mapped to nisMapName */
		if (!isAttrMapped("automountMapName", "nisMapName"))
			return;

		/* check for automountKey mapped to cn */
		if (!isAttrMapped("automountKey", "cn"))
			return;

		/* check for automountInformation mapped to nisMapEntry */
		if (!isAttrMapped("automountInformation", "nisMapEntry"))
			return;

		/* check for automountMap mapped to nisMap */
		if (!isObjectMapped("automountMap", "nisMap"))
			return;

		/* check for automount mapped to nisObject */
		if (!isObjectMapped("automount", "nisObject"))
			return;

		if (trace > 1)
			trace_prt(1, "init_ldap: encode = TRUE\n");
		encode = 1;
	} else {
		if (trace > 1) {
			trace_prt(1, "init_ldap: setting up for version 1\n");
			trace_prt(1, "init_ldap: encode = TRUE\n");
		}
		encode = 1;
		automountKey = "cn";
		automountInformation = "nisMapEntry";
		defaultFilter = "(&(objectClass=nisObject)(cn=%s))";
	}
}

/*ARGSUSED*/
int
getmapent_ldap(char *key, char *map, struct mapline *ml,
char **stack, char ***stkptr, bool_t *iswildcard, bool_t isrestricted)
{
	char *ldap_line = NULL;
	char *lp;
	int ldap_len, len;
	int nserr;

	if (trace > 1)
		trace_prt(1, "getmapent_ldap called\n");

	if (trace > 1) {
		trace_prt(1, "getmapent_ldap: key=[ %s ]\n", key);
	}

	if (iswildcard)
		*iswildcard = FALSE;
	nserr = ldap_match(map, key, &ldap_line, &ldap_len);
	if (nserr) {
		if (nserr == __NSW_NOTFOUND) {
			/* Try the default entry "*" */
			if ((nserr = ldap_match(map, "\\2a", &ldap_line,
			    &ldap_len)))
				goto done;
			else {
				if (iswildcard)
					*iswildcard = TRUE;
			}
		} else
			goto done;
	}

	/*
	 * at this point we are sure that ldap_match
	 * succeeded so massage the entry by
	 * 1. ignoring # and beyond
	 * 2. trim the trailing whitespace
	 */
	if (lp = strchr(ldap_line, '#'))
		*lp = '\0';
	len = strlen(ldap_line);
	if (len == 0) {
		nserr = __NSW_NOTFOUND;
		goto done;
	}
	lp = &ldap_line[len - 1];
	while (lp > ldap_line && isspace(*lp))
		*lp-- = '\0';
	if (lp == ldap_line) {
		nserr = __NSW_NOTFOUND;
		goto done;
	}
	(void) strncpy(ml->linebuf, ldap_line, LINESZ);
	unquote(ml->linebuf, ml->lineqbuf);
	nserr = __NSW_SUCCESS;
done:
	if (ldap_line)
		free((char *)ldap_line);

	if (trace > 1)
		trace_prt(1, "getmapent_ldap: exiting ...\n");

	return (nserr);
}

static int
ldap_match(char *map, char *key, char **ldap_line, int *ldap_len)
{
	char searchfilter[LDAP_FILT_MAXSIZ];
	int res, attr_found;
	ns_ldap_result_t *result = NULL;
	ns_ldap_error_t *errp = NULL;
	ns_ldap_entry_t *entry = NULL;
	char *ldapkey;
	int i;

	if (trace > 1) {
		trace_prt(1, "ldap_match called\n");
		trace_prt(1, "ldap_match: key =[ %s ]\n", key);
	}

	/*
	 * need to handle uppercase characters in the key because LDAP
	 * searches are case insensitive.  Note, key = attribute automountKey.
	 */
	if (encode)
		ldapkey = tosunds_str(key);
	else
		ldapkey = key;

	if (trace > 1) {
		trace_prt(1, "ldap_match: ldapkey =[ %s ]\n", ldapkey);
	}

	(void) sprintf(searchfilter, defaultFilter, ldapkey);

	if (trace > 1)
		trace_prt(1, "  ldap_match: Requesting list for %s in %s\n",
		    searchfilter, map);

	res = __ns_ldap_list(map, searchfilter, NULL,
	    NULL, NULL, 0, &result, &errp, NULL, NULL);

	if (trace > 1) {
		if (res != NS_LDAP_SUCCESS)
			trace_prt(1,
			    "  ldap_match: __ns_ldap_list FAILED (%d)\n", res);
		else
			trace_prt(1, "  ldap_match: __ns_ldap_list OK\n");
	}

	if (res != NS_LDAP_SUCCESS && res != NS_LDAP_NOTFOUND) {
		if (errp) {
			if (verbose) {
				char errstr[MAXERROR];
				(void) sprintf(errstr,
				    gettext("ldap server can't list map,"
				    " '%s': '%s' - '%d'."),
				    map, errp->message, errp->status);
				syslog(LOG_ERR, errstr);
			}
			__ns_ldap_freeError(&errp);
		} else {
			if (verbose) {
				char *errmsg;
				__ns_ldap_err2str(res, &errmsg);
				syslog(LOG_ERR, errmsg);
			}
		}
		if (result)
			__ns_ldap_freeResult(&result);
		return (ldap_err(res));
	}

	if (res == NS_LDAP_NOTFOUND || result == NULL ||
	    result->entries_count == 0 || result->entry->attr_count == 0) {
		if (trace > 1)
			trace_prt(1, "  ldap_match: no entries found\n");
		if (errp)
			__ns_ldap_freeError(&errp);
		if (result)
			__ns_ldap_freeResult(&result);
		return (__NSW_NOTFOUND);
	}

	/*
	 * get value of attribute nisMapEntry.  This attribute contains a
	 * list of mount options AND mount location for a particular mount
	 * point (key).
	 * For example:
	 *
	 * key: /work
	 *	^^^^^
	 *	(mount point)
	 *
	 * nisMapEntry: -rw,intr,nosuid,noquota hosta:/export/work
	 *		^^^^^^^^^^^^^^^^^^^^^^^ ^^^^^^^^^^^^^^^^^^
	 *		(    mount options    ) (remote mount location)
	 *
	 */
	attr_found = 0;
	entry = result->entry;
	for (i = 0; i < entry->attr_count; i++) {
		ns_ldap_attr_t *attr;

		attr = entry->attr_pair[i];
		if (strcasecmp(attr->attrname, automountInformation) == 0) {
			char *attrval;

			attr_found = 1;
			if (encode)
				attrval = tounix_str(attr->attrvalue[0]);
			else
				attrval = attr->attrvalue[0];
			*ldap_len = strlen(key) + strlen(attrval);

			/*
			 * so check for the length; it should be less than
			 * LINESZ
			 */
			if ((*ldap_len + 2) > LINESZ) {
				syslog(LOG_ERR,
				    "ldap server map %s, entry for %s"
				    " is too long %d chars (max %d)",
				    map, key, (*ldap_len + 2), LINESZ);
				__ns_ldap_freeResult(&result);
				return (__NSW_UNAVAIL);
			}
			*ldap_line = (char *)malloc(*ldap_len + 2);
			if (*ldap_line == NULL) {
				syslog(LOG_ERR, "ldap_match: malloc failed");
				__ns_ldap_freeResult(&result);
				return (__NSW_UNAVAIL);
			}

			(void) sprintf(*ldap_line, "%s", attrval);

			break;
		}
	}

	__ns_ldap_freeError(&errp);
	__ns_ldap_freeResult(&result);

	if (!attr_found)
		return (__NSW_NOTFOUND);

	if (trace > 1)
		trace_prt(1, "  ldap_match: found: %s\n", *ldap_line);

	return (__NSW_SUCCESS);
}

int
loadmaster_ldap(char *mapname, char *defopts, char **stack, char ***stkptr)
{
	char searchfilter[LDAP_FILT_MAXSIZ];
	int res;
	ns_ldap_result_t *result = NULL;
	ns_ldap_error_t *errp = NULL;
	struct loadmaster_cbdata master_cbdata;

	if (trace > 1)
		trace_prt(1, "loadmaster_ldap called\n");

	master_cbdata.ptr1 = defopts;
	master_cbdata.ptr2 = stack;
	master_cbdata.ptr3 = stkptr;

	/* filter gets all the entries for the specified mapname */
	(void) sprintf(searchfilter, defaultFilter, "*");

	if (trace > 1)
		trace_prt(1, "loadmaster_ldap: Requesting list for %s in %s\n",
		    searchfilter, mapname);

	res = __ns_ldap_list(mapname, searchfilter, NULL, NULL, NULL,
	    0, &result, &errp, mastermap_callback_ldap,
	    (void *) &master_cbdata);

	if (trace > 1)
		trace_prt(1,
		    "loadmaster_ldap: __ns_ldap_list just returned: %d\n",
		    res);

	if (res != NS_LDAP_SUCCESS) {
		if (errp) {
			char errstr[MAXERROR];
			if (verbose) {
				(void) sprintf(errstr, gettext(
				    "ldap server can't list map,"
				    "'%s': '%s' - '%d'."),
				    mapname, errp->message, errp->status);
				syslog(LOG_ERR, errstr);
			}
			__ns_ldap_freeError(&errp);
		} else {
			if (verbose) {
				char *errmsg;
				__ns_ldap_err2str(res, &errmsg);
				syslog(LOG_ERR, errmsg);
			}
		}
		if (result)
			__ns_ldap_freeResult(&result);
		return (ldap_err(res));
	}

	if (trace > 1)
		trace_prt(1,
		    "loadmaster_ldap: calling __ns_ldap_freeResult...\n");

	__ns_ldap_freeResult(&result);

	if (trace > 1)
		trace_prt(1,
		    "loadmaster_ldap: about to return __NSW_SUCCESS...\n");

	return (__NSW_SUCCESS);
}

int
loaddirect_ldap(char *nsmap, char *localmap, char *opts,
char **stack, char ***stkptr)
{
	char searchfilter[LDAP_FILT_MAXSIZ];
	int res;
	ns_ldap_result_t *result = NULL;
	ns_ldap_error_t *errp = NULL;
	struct loaddirect_cbdata direct_cbdata;

	if (trace > 1) {
		trace_prt(1, "loaddirect_ldap called\n");
	}

	direct_cbdata.ptr1 = opts;
	direct_cbdata.ptr2 = localmap;
	direct_cbdata.ptr3 = stack;
	direct_cbdata.ptr4 = stkptr;

	/* filter gets all the entries for the specified mapname */
	(void) sprintf(searchfilter, defaultFilter, "*");

	if (trace > 1)
		trace_prt(1, "loaddirect_ldap: Requesting list for %s in %s\n",
		    searchfilter, nsmap);

	res = __ns_ldap_list(nsmap, searchfilter, NULL, NULL,
	    NULL, 0, &result, &errp,
	    directmap_callback, (void *) &direct_cbdata);


	if (res != NS_LDAP_SUCCESS) {
		if (errp) {
			char errstr[MAXERROR];
			if (verbose) {
				(void) sprintf(errstr,
				    gettext("ldap server can't list map,"
				    " '%s': '%s' - '%d'."),
				    nsmap, errp->message, errp->status);
				syslog(LOG_ERR, errstr);
			}
			__ns_ldap_freeError(&errp);
		} else {
			if (verbose) {
				char *errmsg;
				__ns_ldap_err2str(res, &errmsg);
				syslog(LOG_ERR, errmsg);
			}
		}
		if (result)
			__ns_ldap_freeResult(&result);
		return (ldap_err(res));
	}

	__ns_ldap_freeResult(&result);
	return (__NSW_SUCCESS);
}

static int
ldap_err(int err)
{
	if (trace > 1)
		trace_prt(1, "ldap_err called\n");

	switch (err) {

	case NS_LDAP_SUCCESS:
		return (__NSW_SUCCESS);

	case NS_LDAP_NOTFOUND:
		return (__NSW_NOTFOUND);

	case NS_LDAP_PARTIAL:
		return (__NSW_TRYAGAIN);

	default:
		return (__NSW_UNAVAIL);
	}
}

static int
mastermap_callback_ldap(ns_ldap_entry_t *entry, void *udata)
{
	char *key, *contents, *pmap, *opts;
	char dir[LINESZ], map[LINESZ], qbuff[LINESZ];
	char cont_temp[LINESZ], key_temp[LINESZ];
	int  key_len, contents_len;
	struct loadmaster_cbdata *temp = (struct loadmaster_cbdata *)udata;
	char *defopts = temp->ptr1;
	char **stack = temp->ptr2;
	char ***stkptr = temp->ptr3;
	int i;

	if (trace > 1) {
		trace_prt(1, "mastermap_callback_ldap called\n");
		trace_prt(1, "mastermap_callback_ldap: entry=%x\n", entry);
		if (entry) {
			trace_prt(1,
			"mastermap_callback_ldap: entry->attr_count=[ %d ]\n",
			    entry->attr_count);
		}
	}

	/*
	 * For the current entry, obtain the values of the cn and the
	 * nisMapEntry attributes and the length of each value (cn=key,
	 * nisMapEntry=contents).
	 * We skip the description.  Even though LDAP allows for multiple
	 * values per attribute, we take only the 1st value for each
	 * attribute because the automount data is organized as such.
	 */
	key_len = 0;
	contents_len = 0;
	key = NULL;
	contents = NULL;
	for (i = 0; i < entry->attr_count; i++) {
		ns_ldap_attr_t *attr;

		attr = entry->attr_pair[i];
		if (trace > 1) {
			trace_prt(1,
			"mastermap_callback_ldap: attr[%d]: %s=%s\n",
			    i, attr->attrname, attr->attrvalue[0]);
		}
		if (strcasecmp(attr->attrname, automountInformation) == 0) {
			if (encode)
				(void) strncpy(cont_temp,
				    tounix_str(attr->attrvalue[0]), LINESZ);
			else
				(void) strncpy(cont_temp, attr->attrvalue[0],
				    LINESZ);
			contents = cont_temp;
			contents_len = strlen(contents);
			if (trace > 1) {
				trace_prt(1,
				    "mastermap_callback_ldap: contents=[ %s ],"
				    " contents_len=[ %d ]\n",
				    contents, contents_len);
			}
		}
		if (strcasecmp(attr->attrname, automountKey) == 0) {
			if (encode)
				(void) strncpy(key_temp,
				    tounix_str(attr->attrvalue[0]), LINESZ);
			else
				(void) strncpy(key_temp, attr->attrvalue[0],
				    LINESZ);
			key = key_temp;
			key_len = strlen(key);
			if (trace > 1) {
				trace_prt(1,
				    "mastermap_callback_ldap: key=[ %s ],"
				    " key_len=[ %d ]\n",
				    key, key_len);
			}
		}
	}

	if (key_len >= LINESZ || contents_len >= LINESZ)
		return (0);
	if (key_len < 2 || contents_len < 2)
		return (0);

	while (isspace(*contents))
		contents++;
	if (contents == NULL)
		return (0);
	if (isspace(*key) || *key == '#')
		return (0);

	(void) strncpy(dir, key, key_len);
	dir[key_len] = '\0';
	if (trace > 1)
		trace_prt(1, "mastermap_callback_ldap: dir= [ %s ]\n", dir);
	for (i = 0; i < LINESZ; i++)
		qbuff[i] = ' ';
	if (macro_expand("", dir, qbuff, sizeof (dir))) {
		syslog(LOG_ERR,
		    "%s in ldap server map: entry too long (max %d chars)",
		    dir, sizeof (dir) - 1);
		return (0);
	}
	(void) strncpy(map, contents, contents_len);
	map[contents_len] = '\0';
	if (trace > 1)
		trace_prt(1, "mastermap_callback_ldap: map= [ %s ]\n", map);
	if (macro_expand("", map, qbuff, sizeof (map))) {
		syslog(LOG_ERR,
		    "%s in ldap server map: entry too long (max %d chars)",
		    map, sizeof (map) - 1);
		return (0);
	}
	pmap = map;
	while (*pmap && isspace(*pmap))
		pmap++;		/* skip blanks in front of map */
	opts = pmap;
	while (*opts && !isspace(*opts))
		opts++;
	if (*opts) {
		*opts++ = '\0';
		while (*opts && isspace(*opts))
			opts++;
		if (*opts == '-')
			opts++;
			else
			opts = defopts;
	}
	/*
	 * Check for no embedded blanks.
	 */
	if (strcspn(opts, " 	") == strlen(opts)) {
		if (trace > 1)
			trace_prt(1,
			"mastermap_callback_ldap: dir=[ %s ], pmap=[ %s ]\n",
			    dir, pmap);
		dirinit(dir, pmap, opts, 0, stack, stkptr);
	} else {
		char *dn = NULL;

		/* get the value for the dn */
		for (i = 0; i < entry->attr_count; i++) {
			ns_ldap_attr_t *attr;

			attr = entry->attr_pair[i];
			if (strcasecmp(attr->attrname, "dn")
			    == 0) {
				dn = attr->attrvalue[0];
				break;
			}
		}
		pr_msg(
		    "Warning: invalid entry for %s in ldap server"
		    " dn: %s ignored.\n",
		    dir, dn);
	}
	if (trace > 1)
		trace_prt(1, "mastermap_callback_ldap exiting...\n");
	return (0);
}

static int
directmap_callback(ns_ldap_entry_t *entry, void *udata)
{
	char *key;
	char dir[256];
	int  key_len;
	struct loaddirect_cbdata *temp = (struct loaddirect_cbdata *)udata;
	char *opts = temp->ptr1;
	char *localmap = temp->ptr2;
	char **stack = temp->ptr3;
	char ***stkptr = temp->ptr4;
	int i;

	/*
	 * For the current entry, obtain the value and length of the cn i.e.
	 * the contents of key and its key length.
	 */
	key_len = 0;
	key = NULL;
	for (i = 0; i < entry->attr_count; i++) {
		ns_ldap_attr_t *attr;

		attr = entry->attr_pair[i];
		if (strcasecmp(attr->attrname, automountKey) == 0) {
			if (encode)
				key = tounix_str(attr->attrvalue[0]);
			else
				key = attr->attrvalue[0];
			key_len = strlen(key);
			break;
		}
	}

	if (key_len >= 100 || key_len < 2)
		return (0);

	if (isspace(*key) || *key == '#')
		return (0);
	(void) strncpy(dir, key, key_len);
	dir[key_len] = '\0';

	dirinit(dir, localmap, opts, 1, stack, stkptr);

	return (0);
}

int
getmapkeys_ldap(char *nsmap, struct dir_entry **list, int *error,
int *cache_time, char **stack, char ***stkptr)
{
	char searchfilter[LDAP_FILT_MAXSIZ];
	int res;
	ns_ldap_result_t *result = NULL;
	ns_ldap_error_t *errp = NULL;
	struct dir_cbdata readdir_cbdata;

#ifdef lint
	stack = stack;
	stkptr = stkptr;
#endif /* lint */

	if (trace > 1)
		trace_prt(1, "getmapkeys_ldap called\n");

	*cache_time = RDDIR_CACHE_TIME;
	*error = 0;
	readdir_cbdata.list = list;
	readdir_cbdata.last = NULL;

	/* filter gets all the entries for the specified mapname */
	(void) sprintf(searchfilter, defaultFilter, "*");

	if (trace > 1)
		trace_prt(1, "getmapkeys_ldap: Requesting list for %s in %s\n",
		    searchfilter, nsmap);

	res = __ns_ldap_list(nsmap, searchfilter, NULL, NULL, NULL, 0,
	    &result, &errp, readdir_callback, (void *) &readdir_cbdata);

	if (trace > 1)
		trace_prt(1, "  getmapkeys_ldap: __ns_ldap_list returned %d\n",
		    res);

	if (readdir_cbdata.error)
		*error = readdir_cbdata.error;

	if (res != NS_LDAP_SUCCESS && res != NS_LDAP_NOTFOUND) {
		if (errp) {
			if (verbose) {
				char errstr[MAXERROR];
				(void) sprintf(errstr, gettext(
				    "ldap server can't list map,"
				    " '%s': '%s' - '%d'."),
				    nsmap, errp->message, errp->status);
				syslog(LOG_ERR, errstr);
			}
			__ns_ldap_freeError(&errp);
		} else {
			if (verbose) {
				char *errmsg;
				__ns_ldap_err2str(res, &errmsg);
				syslog(LOG_ERR, errmsg);
			}
		}
		if (result)
			__ns_ldap_freeResult(&result);
		if (*error == 0)
			*error = ECOMM;
		return (ldap_err(res));
	}
	if (result)
		__ns_ldap_freeResult(&result);

	return (__NSW_SUCCESS);
}

static int
readdir_callback(const ns_ldap_entry_t *entry, const void *udata)
{
	char *key;
	int  key_len;
	struct dir_cbdata *temp = (struct dir_cbdata *)udata;
	struct dir_entry **list = temp->list;
	struct dir_entry *last = temp->last;
	int i;

	if (trace > 1)
		trace_prt(1, "readdir_callback called\n");
	/*
	 * For the current entry, obtain the value and length of the cn i.e. the
	 * contents of key and its key length.
	 */
	key_len = 0;
	key = NULL;

	if (trace > 1)
		trace_prt(1, "readdir_callback: entry->attr_count=[ %d ]\n",
		    entry->attr_count);

	for (i = 0; i < entry->attr_count; i++) {
		ns_ldap_attr_t *attr;

		attr = entry->attr_pair[i];

		if (trace > 1)
			trace_prt(1,
			"readdir_callback: attr->attrname=[ %s ]\n",
			    attr->attrname);

		if (strcasecmp(attr->attrname, automountKey) == 0) {
			if (encode)
				key = tounix_str(attr->attrvalue[0]);
			else
				key = attr->attrvalue[0];
			key_len = strlen(key);

			if (trace > 1)
				trace_prt(1,
			"readdir_callback: key=[ %s ], key_len=[ %d ]\n",
				    key, key_len);

			break;
		}
	}

	if (key_len >= 100 || key_len < 2)
		return (0);

	if (isspace(*key) || *key == '#')
		return (0);

	/*
	 * Wildcard entry should be ignored - following entries should continue
	 * to be read to corroborate with the way we search for entries in
	 * LDAP, i.e., first for an exact key match and then a wildcard
	 * if there's no exact key match.
	 */
	if (key[0] == '*' && key[1] == '\0')
		return (0);

	if (add_dir_entry(key, list, &last)) {
		temp->error = ENOMEM;
		return (1);
	}

	temp->last = last;
	temp->error = 0;

	if (trace > 1)
		trace_prt(1, "readdir_callback returning 0...\n");

	return (0);
}

/*
 * Puts CAPCHAR in front of uppercase characters or surrounds a set of
 * contiguous uppercase characters with CAPCHARS and square brackets.
 *
 * For example (assuming CAPCHAR = '%'):
 *
 * if str = Abc, it returns %Abc
 * if str = ABc, it returns %[AB]c
 * if str = AbC, it returns %Ab%C
 *
 */
static char *
tosunds_str(char *str)
{
	static char buf[BUFSIZ];
	int i, j, er = FALSE;
#ifdef NEWCAP
	int openBracket = FALSE, closeBracket = FALSE;
#endif

	(void) memset(buf, 0, BUFSIZ);

	j = 0;
	for (i = 0; i < strlen(str); i++) {
		/* Check the current element */
		if (isupper(str[i])) {
#ifdef NEWCAP
			/* check the next element */
			if (isupper(str[i+1])) {
				if (openBracket == FALSE) {
					openBracket = TRUE;
					buf[j] = CAPCHAR;
					buf[j+1] = '[';
					j += 2;
				}
			} else {
				if (openBracket == FALSE) {
					buf[j] = CAPCHAR;
					j++;
				} else {
					openBracket = FALSE;
					closeBracket = TRUE;
				}
			}
#else
			buf[j++] = CAPCHAR;
#endif
		}
		buf[j] = str[i];
		j++;

#ifdef NEWCAP
		if (closeBracket == TRUE) {
			closeBracket = FALSE;
			buf[j] = ']';
			j++;
		}
#endif
		if (j >= BUFSIZ) {
			er = TRUE;
			break;
		}
	}

	if (er) {
		syslog(LOG_ERR, "Buffer size exceeded.");
		(void) memset(buf, 0, BUFSIZ);
	} else
		buf[j] = '\0';

	return (buf);

}

/*
 * Reverses what tosunds_str() did
 */
static char *
tounix_str(char *str)
{
	static char buf[BUFSIZ];
	int i, j;
	int openBracket = FALSE;

	(void) memset(buf, 0, BUFSIZ);
	j = 0;

	for (i = 0; i < strlen(str); i++) {
		if (str[i] == '%') {
			if (isupper(str[i+1])) {
				i += 1;
			} else if ((str[i+1] == '[') && (isupper(str[i+2]))) {
				i += 2;
				openBracket = TRUE;
			}
		} else if (str[i] == ']') {
			if ((isupper(str[i-1])) && (openBracket == TRUE))
				i += 1;
			openBracket = FALSE;
		}
		buf[j] = str[i];
		j++;
	}
	return (buf);
}
