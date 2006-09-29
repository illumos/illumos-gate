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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <ctype.h>
#include <libintl.h>
#include <strings.h>
#include <stdio.h>
#include <tsol/label.h>
#include "../../../lib/libsldap/common/ns_sldap.h"


#define	SAME	0

struct mapping {
	char *database;
	char *def_type;
	char *objectclass;
	char *actual_db;
};

#define	PUBLICKEY	0

static struct mapping maplist[] = {
	{"publickey", "uidnumber", "niskeyobject", "passwd"},
	{"publickey", "cn", "niskeyobject", "host"},
	{"bootparams", "cn", "bootableDevice", NULL},
	{"ethers", "cn", "ieee802Device", NULL},
	{"group", "cn", "posixgroup", NULL},
	{"hosts", "cn", "iphost", NULL},
	{"ipnodes", "cn", "iphost", NULL},
	{"netgroup", "cn", "nisnetgroup", NULL},
	{"netmasks", "ipnetworknumber", "ipnetwork", NULL},
	{"networks", "ipnetworknumber", "ipnetwork", NULL},
	{"passwd", "uid", "posixaccount", NULL},
	{"protocols", "cn", "ipprotocol", NULL},
	{"rpc", "cn", "oncrpc", NULL},
	{"services", "cn", "ipservice", NULL},
	{"aliases", "cn", "mailGroup", NULL},
	{"project", "SolarisProjectID", "SolarisProject", NULL},
	{"printers", "printer-uri", "sunPrinter", NULL},
	{"shadow", "uid", "shadowaccount", NULL},
	{"auth_attr", "cn", "SolarisAuthAttr", NULL},
	{"prof_attr", "cn", "SolarisProfAttr", NULL},
	{"exec_attr", "cn", "SolarisExecAttr", NULL},
	{"user_attr", "uid", "SolarisUserAttr", NULL},
	{"audit_user", "uid", "SolarisAuditUser", NULL},
	{"tnrhtp", "ipTnetTemplateName", "ipTnetTemplate", NULL},
	{"tnrhdb", "ipTnetNumber", "ipTnetHost", NULL},
	{NULL, NULL, NULL, NULL}
};

#define	PROF_ATTR_FILTER \
	"(&(objectclass=SolarisProfAttr)(!(SolarisKernelSecurityPolicy=*))%s)"
#define	TNRHTP_FILTER \
	"(&(objectclass=ipTnetTemplate)(!(objectclass=ipTnetHost))%s)"
#define	OC_FILTER	"objectclass=%s"
#define	OC_FLEN		15
#define	OC_FILTER2	"(&(objectclass=%s)%s)"
#define	OC_FLEN2	22

/* Malloc and print error message in case of failure */
#define	MALLOC(ptr, len) \
	if ((ptr = (char *)malloc(len)) == NULL) { \
		(void) fprintf(stderr, gettext("out of memory\n")); \
	}

/*
 * Allocate memory for filter and user data. Set
 * error to 1 if either of the mallocs fail.
 * In addition, free the memory allocated for filter,
 * if memory allocation for user data fails.
 */
#define	MALLOC_FILTER_UDATA(ptr1, len1, ptr2, len2, error) \
	error = 0; \
	MALLOC(ptr1, len1); \
	if (!ptr1) { \
		error = 1; \
	} \
	else { \
		MALLOC(ptr2, len2); \
		if (!ptr2) { \
			error = 1; \
			free(ptr1); \
		} \
	}

void
printMapping()
{
	int	i;

	(void) fprintf(stdout,
		gettext("database       default type        objectclass\n"));
	(void) fprintf(stdout,
		gettext("=============  =================   =============\n"));
	/* first dump auto_* and automount which are not in maplist[] */
	(void) fprintf(stdout, "%-15s%-20s%s\n", "auto_*", "automountKey",
		"automount");
	(void) fprintf(stdout, "%-15s%-20s%s\n", "automount",
		"automountMapName",
		"automountMap");
	for (i = 0; maplist[i].database != NULL; i++) {
		/* skip printing shadow */
		if (strcasecmp(maplist[i].database, "shadow") == 0)
			continue;
		if (!is_system_labeled()) {
			/*
			 * do not print tnrhdb and tnrhtp if system is
			 * not configured with Trusted Extensions
			 */
			if ((strcasecmp(maplist[i].database, "tnrhdb") == 0) ||
			    (strcasecmp(maplist[i].database, "tnrhtp") == 0))
				continue;
		}
		(void) fprintf(stdout, "%-15s%-20s%s\n", maplist[i].database,
		    maplist[i].def_type, maplist[i].objectclass);
	}
}

/*
 * set_key routine to handle user specified keys.
 * A key can be of the form: attribute=value or value.
 * A filter is constructed from a set of keys specified in
 * the form (|(key1)(key2)...(keyn))
 * It returns: NULL if no keys are defined or
 *		the keyfilter as constructed above.
 */

char *
set_keys(char **key, char *attrtype)
{
	char	*keyeq = NULL;
	char	*keyfilter = NULL;
	int	len, totlen = 1; /* Terminating NULL byte */
	char	*k, **karray;
	char	*tmpptr;

	if (!key || !key[0])	/* should never contain NULL string */
		return (NULL);

	if (key[1]) {
		totlen += 3;
		/* Allocate memory for '(|)' */
		MALLOC(keyfilter, totlen);
		if (!keyfilter)
			exit(2);
		(void) snprintf(keyfilter, totlen, "(|");
	}

	karray = key;
	while ((k = *karray) != 0) {
		keyeq = strchr(k, '=');
		if (keyeq) {
			/* make enough room for (%s) */
			totlen += strlen(k) + 2;
		} else {
			/* make enough room for (%s=%s) */
			totlen += strlen(attrtype) + strlen(k) + 3;
		}

		len = keyfilter ? strlen(keyfilter) : 0;

		if (!(tmpptr = (char *)realloc(keyfilter, totlen))) {
			if (keyfilter)
				free(keyfilter);
			(void) fprintf(stderr, gettext("out of memory\n"));
			exit(2);
		}
		keyfilter = tmpptr;

		if (keyeq) {
			(void) snprintf(keyfilter + len, totlen - len,
					"(%s)", k);
		} else {
			(void) snprintf(keyfilter + len, totlen - len,
					"(%s=%s)", attrtype, k);
		}
		karray++;
	}

	if (key[1]) {
		/* We allocated memory for this earlier */
		(void) strlcat(keyfilter, ")", totlen);
	}

	return (keyfilter);
}


/*
 * A special set_key routine for to handle public keys.
 * If the key starts with a digiti, view it as a user id.
 * Otherwise, view it as a hostname.
 * It returns: -1 no keys defined, 0 key defined but none for type
 *		specified, n>0 number of matches found.
 */
int
set_keys_publickey(char **key, char *attrtype, int type, char **ret)
{
	char	*keyeq = NULL;
	char	*keyfilter = NULL;
	char	*pre_filter = NULL;
	char	*k, **karray;
	int	count = 0;
	int	len, totlen = 1; /* Terminating NULL byte */
	char	*tmpptr;

	if (!key || !key[0]) {	/* should never contain NULL string */
		*ret = NULL;
		return (-1);
	}

	karray = key;
	while ((k = *karray) != 0) {
		keyeq = strchr(k, '=');
		if (keyeq) {
			/* make enough room for (%s) */
			totlen += strlen(k) + 2;
		} else {
			if ((type == 0 && isdigit(*k)) ||
				/* user type keys */
			    (type == 1 && (!isdigit(*k)))) {
				/* hosts type keys */
				/* make enough room for (%s=%s) */
				totlen += strlen(k) + strlen(attrtype) + 3;
			} else {
				karray++;
				continue;
			}
		}

		len = pre_filter ? strlen(pre_filter) : 0;

		if (!(tmpptr = (char *)realloc(pre_filter, totlen))) {
			if (pre_filter)
				free(pre_filter);
			(void) fprintf(stderr, gettext("out of memory\n"));
			exit(2);
		}
		pre_filter = tmpptr;

		if (keyeq) {
			(void) snprintf(pre_filter + len, totlen - len,
					"(%s)", k);
		} else {
			(void) snprintf(pre_filter + len, totlen - len,
					"(%s=%s)", attrtype, k);
		}
		karray++;
		count++;
	}
	if (count > 1) {
		len = strlen(pre_filter) + 4;
		if (!(keyfilter = (char *)malloc(len))) {
			(void) fprintf(stderr, gettext("out of memory\n"));
			free(pre_filter);
			exit(2);
		}
		(void) snprintf(keyfilter, len, "(|%s)", pre_filter);
		free(pre_filter);
		*ret = keyfilter;
	} else
		*ret = pre_filter;
	return (count);
}

/*
 * publickey specific set_filter
 * type 0 -> check for user publickeys
 * type 1 -> check for hosts publickeys
 */
char *
set_filter_publickey(char **key, char *database, int type, char **udata)
{
	char 	*filter = NULL;
	char 	*userdata;
	char	*keyfilter = NULL;
	int	rc;
	int	filterlen, udatalen;
	short	nomem = 0;

	if (!database || !udata) {
		return (NULL);
	}

	if (strcasecmp(database, maplist[PUBLICKEY].database) == SAME) {
		rc = set_keys_publickey(key,
				maplist[PUBLICKEY + type].def_type, type,
				&keyfilter);
		switch (rc) {
		case -1:
			filterlen = strlen(maplist[PUBLICKEY].objectclass) + 13;
			udatalen = 3;
			MALLOC_FILTER_UDATA(filter, filterlen, userdata,
						udatalen, nomem);
			if (!nomem) {
				(void) snprintf(filter, filterlen,
					"objectclass=%s",
					maplist[PUBLICKEY].objectclass);
				(void) snprintf(userdata, udatalen, "%%s");
			}
			break;
		case 0:
			return (NULL);
		default:
			filterlen = strlen(maplist[PUBLICKEY].objectclass) +
				strlen(keyfilter) + 18;
			udatalen = strlen(keyfilter) + 8;
			MALLOC_FILTER_UDATA(filter, filterlen, userdata,
						udatalen, nomem);
			if (!nomem) {
			    (void) snprintf(filter, filterlen,
				"(&(objectclass=%s)%s)",
				maplist[PUBLICKEY].objectclass, keyfilter);
			    (void) snprintf(userdata, udatalen, "(&(%%s)%s)",
					keyfilter);
			}
		}
	} else {
		if ((keyfilter = set_keys(key, "cn")) == NULL) {
			filterlen = 14;
			udatalen = 3;
			MALLOC_FILTER_UDATA(filter, filterlen, userdata,
						udatalen, nomem);
			if (!nomem) {
				(void) snprintf(filter, filterlen,
						"objectclass=*");
				(void) snprintf(userdata, udatalen, "%%s");
			}
		} else {
			filterlen = strlen(keyfilter) + 1;
			udatalen = strlen(keyfilter) + 8;
			MALLOC_FILTER_UDATA(filter, filterlen, userdata,
						udatalen, nomem);
			if (!nomem) {
				(void) snprintf(filter, filterlen, "%s",
						keyfilter);
				(void) snprintf(userdata, udatalen,
						"(&(%%s)%s)", keyfilter);
			}
		}
	}
#ifdef DEBUG
	(void) fprintf(stdout, "set_filter: filter=\"%s\"\n", filter);
	(void) fprintf(stdout, "set_filter: userdata=\"%s\"\n", userdata);
#endif /* DEBUG */
	if (keyfilter)
		free(keyfilter);
	if (nomem)
		exit(2);
	*udata = userdata;
	return (filter);
}


/* generic set_filter, this function is not thread safe */
char *
set_filter(char **key, char *database, char **udata)
{
	char 		*filter = NULL;
	char 		*userdata = NULL;
	char		*keyfilter;
	int		i, filterlen, udatalen;
	int		rc, v2 = 1;
	int		dbpf, dbtp;
	void		**paramVal = NULL;
	ns_ldap_error_t	*errorp = NULL;
	short		nomem;

	if (!database || !udata) {
		return (NULL);
	}


	/*
	 * Check for version of the profile the client is using
	 *
	 * For version 1 profiles we do use nisMap and nisObject schema
	 * for backward compatibility with Solaris 8 clients.
	 *
	 * For version 2 profiles we use automountMap and automount as
	 * default attributes (which can then be overridden in libsldap
	 * if schema mapping is configured in the profile).
	 *
	 * If profile version is not available, use version 2 as default.
	 */
	rc = __ns_ldap_getParam(NS_LDAP_FILE_VERSION_P, &paramVal, &errorp);
	if (rc != NS_LDAP_SUCCESS || !paramVal || !*paramVal) {
		/* should print a message here: using v2 defaults */
		(void) __ns_ldap_freeError(&errorp);
	} else {
		if (strcasecmp(*paramVal, NS_LDAP_VERSION_1) == 0)
			v2 = 0;
		(void) __ns_ldap_freeParam(&paramVal);
	}

	/*
	 * starts at 2 to skip over publickey databases.
	 * These databases are handled separately.
	 */
	for (i = 2; maplist[i].database != NULL; i++) {
		if (strcasecmp(database, maplist[i].database) == SAME) {
			dbpf = 0, dbtp = 0;
			if (strcasecmp(database, "prof_attr") == 0)
				dbpf = 1;
			else if (strcasecmp(database, "tnrhtp") == 0)
				dbtp = 1;
			if ((keyfilter = set_keys(key, maplist[i].def_type))
							== NULL) {
				filterlen = strlen(maplist[i].objectclass);
				udatalen = 3;
				if (dbpf)
					filterlen += strlen(PROF_ATTR_FILTER)
							+ 1;
				else if (dbtp)
					filterlen += strlen(TNRHTP_FILTER) + 1;
				else
					filterlen += OC_FLEN;

				MALLOC_FILTER_UDATA(filter, filterlen, userdata,
						udatalen, nomem);
				if (nomem)
					goto done;
				if (dbpf)
					(void) snprintf(filter, filterlen,
						PROF_ATTR_FILTER, "");
				else if (dbtp)
					(void) snprintf(filter, filterlen,
						TNRHTP_FILTER, "");
				else
					(void) snprintf(filter, filterlen,
						OC_FILTER,
						maplist[i].objectclass);

				(void) snprintf(userdata, udatalen, "%%s");
			} else {
				filterlen = strlen(maplist[i].objectclass) +
					strlen(keyfilter);
				if (dbpf)
					filterlen += strlen(PROF_ATTR_FILTER)
							+ 1;
				else if (dbtp)
					filterlen += strlen(TNRHTP_FILTER) + 1;
				else
					filterlen += OC_FLEN2;

				udatalen = strlen(keyfilter) + 8;
				MALLOC_FILTER_UDATA(filter, filterlen, userdata,
						udatalen, nomem);
				if (nomem)
					goto done;
				if (dbpf)
					(void) snprintf(filter, filterlen,
						PROF_ATTR_FILTER, keyfilter);
				else if (dbtp)
					(void) snprintf(filter, filterlen,
						TNRHTP_FILTER, keyfilter);
				else
					(void) snprintf(filter, filterlen,
						OC_FILTER2,
						maplist[i].objectclass,
						keyfilter);

				(void) snprintf(userdata, udatalen,
					"(&(%%s)%s)", keyfilter);
			}
			goto done;
		}
	}

	/* special cases for automounter and other services */

	/* auto_* services */
	if (strncasecmp(database, "auto_", 5) == SAME) {
	    if (v2) {
		if ((keyfilter = set_keys(key, "automountKey"))
			!= NULL) {
			filterlen = strlen(keyfilter) + 27;
			udatalen = strlen(keyfilter) + 8;
			MALLOC_FILTER_UDATA(filter, filterlen, userdata,
					udatalen, nomem);
			if (!nomem) {
				(void) snprintf(filter, filterlen,
				    "(&(objectclass=automount)%s)",
					keyfilter);
				(void) snprintf(userdata, udatalen,
					"(&(%%s)%s)", keyfilter);
			}
		} else {
			filterlen = 22;
			udatalen = 3;
			MALLOC_FILTER_UDATA(filter, filterlen, userdata,
					udatalen, nomem);
			if (!nomem) {
				(void) strlcpy(filter, "objectclass=automount",
					filterlen);
				(void) strlcpy(userdata, "%s", udatalen);
			}
		}
	    } else {
		if ((keyfilter = set_keys(key, "cn")) != NULL) {
			filterlen = strlen(keyfilter) + 27;
			udatalen = strlen(keyfilter) + 8;
			MALLOC_FILTER_UDATA(filter, filterlen, userdata,
					udatalen, nomem);
			if (!nomem) {
				(void) snprintf(filter, filterlen,
				    "(&(objectclass=nisObject)%s)", keyfilter);
				(void) snprintf(userdata, udatalen,
					"(&(%%s)%s)", keyfilter);
			}
		} else {
			filterlen = 22;
			udatalen = 3;
			MALLOC_FILTER_UDATA(filter, filterlen, userdata,
					udatalen, nomem);
			if (!nomem) {
				(void) strlcpy(filter, "objectclass=nisObject",
						filterlen);
				(void) strlcpy(userdata, "%s", udatalen);
			}
		}
	    }
	    goto done;
	}

	/* automount service */
	if (strcasecmp(database, "automount") == SAME) {
	    if (v2) {
		if ((keyfilter = set_keys(key, "automountMapName"))
			!= NULL) {
			filterlen = strlen(keyfilter) + 30;
			udatalen = strlen(keyfilter) + 8;
			MALLOC_FILTER_UDATA(filter, filterlen, userdata,
					udatalen, nomem);
			if (!nomem) {
				(void) snprintf(filter, filterlen,
					"(&(objectclass=automountMap)%s)",
					keyfilter);
				(void) snprintf(userdata, udatalen,
					"(&(%%s)%s)", keyfilter);
			}
		} else {
			filterlen = 25;
			udatalen = 3;
			MALLOC_FILTER_UDATA(filter, filterlen, userdata,
					udatalen, nomem);
			if (!nomem) {
				(void) strlcpy(filter,
					"objectclass=automountMap",
					filterlen);
				(void) strlcpy(userdata, "%s", udatalen);
			}
		}
	    } else {
		if ((keyfilter = set_keys(key, "nisMapName"))
			!= NULL) {
			filterlen = strlen(keyfilter) + 24;
			udatalen = strlen(keyfilter) + 8;
			MALLOC_FILTER_UDATA(filter, filterlen, userdata,
					udatalen, nomem);
			if (!nomem) {
				(void) snprintf(filter, filterlen,
					"(&(objectclass=nisMap)%s)",
					keyfilter);
				(void) snprintf(userdata, udatalen,
					"(&(%%s)%s)", keyfilter);
			}
		} else {
			filterlen = 19;
			udatalen = 3;
			MALLOC_FILTER_UDATA(filter, filterlen, userdata,
					udatalen, nomem);
			if (!nomem) {
			    (void) strlcpy(filter, "objectclass=nisMap",
					filterlen);
			    (void) strlcpy(userdata, "%s", udatalen);
			}
		}
	    }
	    goto done;
	}

	/* other services (catch all) */
	if ((keyfilter = set_keys(key, "cn")) == NULL) {
		filterlen = 14;
		udatalen = 3;
		MALLOC_FILTER_UDATA(filter, filterlen, userdata,
				udatalen, nomem);
		if (!nomem) {
			(void) snprintf(filter, filterlen, "objectclass=*");
			(void) strlcpy(userdata, "%s", udatalen);
		}
	} else {
		filterlen = strlen(keyfilter) + 1;
		udatalen = strlen(keyfilter) + 8;
		MALLOC_FILTER_UDATA(filter, filterlen, userdata,
				udatalen, nomem);
		if (!nomem) {
			(void) snprintf(filter, filterlen, "%s", keyfilter);
			(void) snprintf(userdata, udatalen, "(&(%%s)%s)",
					keyfilter);
		}
	}

done:
#ifdef DEBUG
	(void) fprintf(stdout, "set_filter: filter=\"%s\"\n", filter);
	(void) fprintf(stdout, "set_filter: userdata=\"%s\"\n", userdata);
#endif /* DEBUG */
	if (keyfilter)
		free(keyfilter);
	if (nomem)
		exit(2);
	*udata = userdata;
	return (filter);
}
