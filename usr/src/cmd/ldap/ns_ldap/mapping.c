/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <ctype.h>
#include <libintl.h>
#include <strings.h>
#include <stdio.h>
#include "../../../lib/libsldap/common/ns_sldap.h"


#define	MAXLINE	2000
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
	{NULL, NULL, NULL, NULL}
};


void
printMapping()
{
	int	i;

	fprintf(stdout,
		gettext("database       default type        objectclass\n"));
	fprintf(stdout,
		gettext("=============  =================   =============\n"));
	/* first dump auto_* and automount which are not in maplist[] */
	fprintf(stdout, "%-15s%-20s%s\n", "auto_*", "automountKey",
		"automount");
	fprintf(stdout, "%-15s%-20s%s\n", "automount", "automountMapName",
		"automountMap");
	for (i = 0; maplist[i].database != NULL; i++) {
	/* skip printing shadow */
	if (strcasecmp(maplist[i].database, "shadow") != 0)
		fprintf(stdout, "%-15s%-20s%s\n", maplist[i].database,
			maplist[i].def_type, maplist[i].objectclass);
	}
}


char *
set_keys(char **key, char *attrtype)
{
	char	*keyeq = NULL;
	static char	keyfilter[MAXLINE];
	char	typeeq[100];
	char	buf[100];
	char	*k, **karray;

	if (!key || !key[0])	/* should never contain NULL string */
		return (NULL);

	if (attrtype) {
		strcpy(typeeq, attrtype);
		strcat(typeeq, "=");
	}

	keyfilter[0] = '\0';
	if (key[1])
		strcat(keyfilter, "(|");
	karray = key;
	while (k = *karray) {
		keyeq = strchr(k, '=');
		sprintf(buf, "(%s%s)", (keyeq ? "" : typeeq), k);
		if (strlen(buf) + strlen(keyfilter) >= MAXLINE) {
			fprintf(stdout,
				gettext("***ERROR: ldapfilter too long\n"));
			exit(2);
		}
		strcat(keyfilter, buf);
		karray++;
	}
	if (key[1])
		strcat(keyfilter, ")");
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
	static char	keyfilter[MAXLINE];
	char	pre_filter[MAXLINE];
	char	buf[100];
	char	*k, **karray;
	int	count = 0;

	if (!key || !key[0]) {	/* should never contain NULL string */
		*ret = NULL;
		return (-1);
	}

	keyfilter[0] = '\0';
	pre_filter[0] = '\0';
	karray = key;
	while (k = *karray) {
		keyeq = strchr(k, '=');
		if (keyeq)
			sprintf(buf, "(%s)", k);
		else {
			if (type == 0 && isdigit(*k)) {
				/* user type keys */
				sprintf(buf, "(%s=%s)", attrtype, k);
			} else if (type == 1 && (!isdigit(*k))) {
				/* hosts type keys */
				sprintf(buf, "(%s=%s)", attrtype, k);
			} else {
				karray++;
				continue;
			}
		}
		if (strlen(buf) + strlen(pre_filter) >= MAXLINE) {
			fprintf(stdout,
				gettext("***ERROR: ldapfilter too long\n"));
			exit(2);
		}
		strcat(pre_filter, buf);
		karray++;
		count++;
	}
	if (count > 1) {
		if (strlen(pre_filter) + 4 >= MAXLINE) {
			fprintf(stdout,
				gettext("***ERROR: ldapfilter too long\n"));
			exit(2);
		}
		strcat(keyfilter, "(|");
		strcat(keyfilter, pre_filter);
		strcat(keyfilter, ")");
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
	char 	*filter;
	char 	*userdata;
	char	*keyfilter;
	int	rc;

	if (!database) {
		return (NULL);
	}
	if (!udata) {
		return (NULL);
	}

	filter = (char *)malloc(MAXLINE);
	if (!filter) {
		return (NULL);
	}
	filter[0] = '\0';

	userdata = (char *)malloc(MAXLINE);
	if (!userdata) {
		free(filter);
		return (NULL);
	}
	userdata[0] = '\0';
	*udata = userdata;

	if (strcasecmp(database, maplist[PUBLICKEY].database) == SAME) {
		rc = set_keys_publickey(key,
				maplist[PUBLICKEY + type].def_type, type,
				&keyfilter);
		switch (rc) {
		case -1:
			sprintf(filter, "objectclass=%s",
				maplist[PUBLICKEY].objectclass);
			sprintf(userdata, "%%s");
			break;
		case 0:
			return (NULL);
		default:
			sprintf(filter, "(&(objectclass=%s)%s)",
				maplist[PUBLICKEY].objectclass, keyfilter);
			sprintf(userdata, "(&(%%s)%s)",
				keyfilter);
		}
	} else {
		if ((keyfilter = set_keys(key, "cn")) == NULL) {
			sprintf(filter, "objectclass=*");
			sprintf(userdata, "%%s");
		} else {
			sprintf(filter, "%s", keyfilter);
			sprintf(userdata, "(&(%%s)%s)", keyfilter);
		}
	}
#ifdef DEBUG
	fprintf(stdout, "set_filter: filter=\"%s\"\n", filter);
	fprintf(stdout, "set_filter: userdata=\"%s\"\n", userdata);
#endif /* DEBUG */
	return (filter);
}


/* generic set_filter, this function is not thread safe */
char *
set_filter(char **key, char *database, char **udata)
{
	char 		*filter;
	char 		*userdata;
	char		*keyfilter;
	int		i;
	int		rc, v2 = 1;
	void		**paramVal = NULL;
	ns_ldap_error_t	*errorp = NULL;

	if (!database) {
		return (NULL);
	}
	if (!udata) {
		return (NULL);
	}

	filter = (char *)malloc(MAXLINE);
	if (!filter) {
		return (NULL);
	}
	filter[0] = '\0';

	userdata = (char *)malloc(MAXLINE);
	if (!userdata) {
		free(filter);
		return (NULL);
	}
	userdata[0] = '\0';
	*udata = userdata;

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
			if ((keyfilter = set_keys(key, maplist[i].def_type))
							== NULL) {
				snprintf(filter, MAXLINE, "objectclass=%s",
					maplist[i].objectclass);
				sprintf(userdata, "%%s");
			} else {
				snprintf(filter, MAXLINE,
					"(&(objectclass=%s)%s)",
					maplist[i].objectclass, keyfilter);
				snprintf(userdata, MAXLINE, "(&(%%s)%s)",
					keyfilter);
#ifdef DEBUG
	fprintf(stdout, "set_filter: filter=\"%s\"\n", filter);
	fprintf(stdout, "set_filter: userdata=\"%s\"\n", userdata);
#endif /* DEBUG */
			}
			return (filter);
		}
	}

	/* special cases for automounter and other services */

	/* auto_* services */
	if (strncasecmp(database, "auto_", 5) == SAME) {
	    if (v2) {
		if ((keyfilter = set_keys(key, "automountKey"))
			!= NULL) {
			snprintf(filter, MAXLINE,
				"(&(objectclass=automount)%s)", keyfilter);
			snprintf(userdata, MAXLINE, "(&(%%s)%s)", keyfilter);
		} else {
			strcpy(filter, "objectclass=automount");
			strcpy(userdata, "%s");
		}
	    } else {
		if ((keyfilter = set_keys(key, "cn"))
			!= NULL) {
			snprintf(filter, MAXLINE,
				"(&(objectclass=nisObject)%s)", keyfilter);
			snprintf(userdata, MAXLINE, "(&(%%s)%s)", keyfilter);
		} else {
			strcpy(filter, "objectclass=nisObject");
			strcpy(userdata, "%s");
		}
	    }
	    goto done;
	}

	/* automount service */
	if (strcasecmp(database, "automount") == SAME) {
	    if (v2) {
		if ((keyfilter = set_keys(key, "automountMapName"))
			!= NULL) {
			snprintf(filter, MAXLINE,
				"(&(objectclass=automountMap)%s)", keyfilter);
			snprintf(userdata, MAXLINE, "(&(%%s)%s)", keyfilter);
		} else {
			strcpy(filter, "objectclass=automountMap");
			strcpy(userdata, "%s");
		}
	    } else {
		if ((keyfilter = set_keys(key, "nisMapName"))
			!= NULL) {
			snprintf(filter, MAXLINE, "(&(objectclass=nisMap)%s)",
				keyfilter);
			snprintf(userdata, MAXLINE, "(&(%%s)%s)", keyfilter);
		} else {
			strcpy(filter, "objectclass=nisMap");
			strcpy(userdata, "%s");
		}
	    }
	    goto done;
	}

	/* other services (catch all) */
	if ((keyfilter = set_keys(key, "cn")) == NULL) {
		snprintf(filter, MAXLINE, "objectclass=*");
		strcpy(userdata, "%s");
	} else {
		snprintf(filter, MAXLINE, "%s", keyfilter);
		snprintf(userdata, MAXLINE, "(&(%%s)(%s))", keyfilter);
	}

done:
#ifdef DEBUG
	fprintf(stdout, "set_filter: filter=\"%s\"\n", filter);
	fprintf(stdout, "set_filter: userdata=\"%s\"\n", userdata);
#endif /* DEBUG */
	return (filter);
}
