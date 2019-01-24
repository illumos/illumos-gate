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

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <strings.h>
#include <pwd.h>
#include <shadow.h>
#include <netdb.h>
#include <mp.h>
#include <rpcsvc/nis.h>
#include <rpc/key_prot.h>
#include <nsswitch.h>
#include <ns_sldap.h>

extern char *crypt();
extern long random();
extern char *getpassphrase();
extern char *program_name;
static const char *CRED_TABLE = "cred.org_dir";

#define	ROOTKEY_FILE	"/etc/.rootkey"

#ifndef MAXHOSTNAMELEN
#define	MAXHOSTNAMELEN 256
#endif

#define	PK_FILES	1
#define	PK_YP		2
#define	PK_LDAP		4

#define	LDAP_BINDDN_DEFAULT	"cn=Directory Manager"
#define	PROMPTGET_SUCCESS	1
#define	PROMPTGET_FAIL		-1
#define	PROMPTGET_MEMORY_FAIL	-2
#define	PASSWD_UNMATCHED	-3

#define	FREE_CREDINFO(s) \
	if ((s)) { (void) memset((s), 0, strlen((s))); }


/* ************************ switch functions *************************** */

/*	NSW_NOTSUCCESS  NSW_NOTFOUND   NSW_UNAVAIL    NSW_TRYAGAIN */
#define	DEF_ACTION {__NSW_RETURN, __NSW_RETURN, __NSW_CONTINUE, __NSW_CONTINUE}

static struct __nsw_lookup lookup_files = {"files", DEF_ACTION, NULL, NULL},
		lookup_nis = {"nis", DEF_ACTION, NULL, &lookup_files};
static struct __nsw_switchconfig publickey_default =
			{0, "publickey", 2, &lookup_nis};

static int get_ldap_bindDN(char **);
static int get_ldap_bindPassword(char **);

/*
 * Prompt the users for a ldap bind DN. If users do not enter a value but just
 * simply hit the return key, the default bindDN "cn=Directory Manager"
 * will be used.
 */
static int
get_ldap_bindDN(char **ret_bindDN)
{

	char	bindDN[BUFSIZ];
	char	prompt[BUFSIZ];
	int	blen, pos;

	/* set the initial value for bindDN buffer */
	(void) memset(bindDN, 0, BUFSIZ);

	(void) snprintf(prompt, BUFSIZ,
	"\nThe LDAP bind DN and password are required for this update.\n"
	"If you are not sure what values to enter, please contact your\n"
	"LDAP administrator.\n\nPlease enter LDAP bind DN [%s]: ",
	    LDAP_BINDDN_DEFAULT);

	printf(prompt);

	if (fgets(bindDN, sizeof (bindDN), stdin) == NULL) {
		(void) strlcpy(bindDN, LDAP_BINDDN_DEFAULT, BUFSIZ);
	}

	blen = strlen(bindDN);

	/* Check if the buffer ends with a newline */
	if ((blen > 0) && (bindDN[blen - 1] == '\n')) {
		bindDN[blen - 1] = '\0';
		blen -= 1;
	}

	/* Remove the white spaces */
	if (blen > 0) {
		for (pos = blen - 1; pos >= 0; pos--) {
			if (isspace(bindDN[pos]))
				bindDN[pos] = '\0';
			else
				break;
		}
	}

	/* Use the default bindDN, if the buffer contains no characters */
	if (strlen(bindDN) == 0)
		(void) strlcpy(bindDN, LDAP_BINDDN_DEFAULT, BUFSIZ);

	if ((*ret_bindDN = (char *)malloc(strlen(bindDN)+1)) == NULL) {
		(void) memset(bindDN, 0, BUFSIZ);
		return (PROMPTGET_MEMORY_FAIL);
	}

	(void) strlcpy(*ret_bindDN, bindDN, strlen(bindDN)+1);

	/* Clean up and erase the credential info */
	(void) memset(bindDN, 0, BUFSIZ);

	return (PROMPTGET_SUCCESS);
}


/*
 * Prompt the user for a ldap bind password.
 */
static int
get_ldap_bindPassword(char **ret_bindPass)
{

	char	bindPassword[BUFSIZ];
	char	prompt[BUFSIZ];
	char	*bindPass = NULL;

	/* set the initial value for bindPassword buffer */
	(void) memset(bindPassword, 0, BUFSIZ);
	*ret_bindPass = NULL;

	(void) snprintf(prompt, BUFSIZ,
	    "Please enter LDAP bind password: ");

	bindPass = getpassphrase(prompt);

	if (bindPass == NULL)
		return (PROMPTGET_FAIL);

	(void) strlcpy(bindPassword, bindPass, BUFSIZ);

	/* clean the static buffer returned from getpassphrase call */
	(void) memset(bindPass, 0, strlen(bindPass));
	bindPass = NULL;

	/*
	 * Re-enter the bind passowrd and compare it with the one
	 * from previous entered.
	 */
	(void) snprintf(prompt, BUFSIZ,
	    "Re-enter LDAP bind password to confirm: ");

	bindPass = getpassphrase(prompt);

	if (bindPass == NULL) {
		(void) memset(bindPassword, 0, BUFSIZ);
		return (PASSWD_UNMATCHED);
	}

	if (strcmp(bindPass, bindPassword) != 0) {
		(void) memset(bindPassword, 0, BUFSIZ);
		(void) memset(bindPass, 0, strlen(bindPass));
		return (PASSWD_UNMATCHED);
	} else {
		(void) memset(bindPass, 0, strlen(bindPass));
		if ((*ret_bindPass = (char *)malloc(strlen(bindPassword)+1))
		    == NULL) {
			(void) memset(bindPassword, 0, BUFSIZ);
			return (PROMPTGET_MEMORY_FAIL);
		}

		(void) strlcpy(*ret_bindPass, bindPassword,
		    strlen(bindPassword)+1);

		/* Clean up and erase the credential info */
		(void) memset(bindPassword, 0, BUFSIZ);

		return (PROMPTGET_SUCCESS);
	}
}



char *
switch_policy_str(struct __nsw_switchconfig *conf)
{
	struct __nsw_lookup *look;
	static char policy[256];  /* 256 is enough for (nis, files...etc) */
	int previous = 0;

	memset((char *)policy, 0, 256);

	for (look = conf->lookups; look; look = look->next) {
		if (previous)
			strcat(policy, " ");
		strcat(policy, look->service_name);
		previous = 1;
	}
	return (policy);
}

int
no_switch_policy(struct __nsw_switchconfig *conf)
{
	return (conf == NULL || conf->lookups == NULL);
}

int
is_switch_policy(struct __nsw_switchconfig *conf, char *target)
{
	return (conf &&
	    conf->lookups &&
	    strcmp(conf->lookups->service_name, target) == 0 &&
	    conf->lookups->next == NULL);
}

char *
first_and_only_switch_policy(char *policy,
    struct __nsw_switchconfig *default_conf, char *head_msg)
{
	struct __nsw_switchconfig *conf;
	enum __nsw_parse_err perr;
	int policy_correct = 1;
	char *target_service = 0;
	int use_default = 0;

	if (default_conf == 0)
		default_conf = &publickey_default;

	conf = __nsw_getconfig(policy, &perr);
	if (no_switch_policy(conf)) {
		use_default = 1;
		conf = default_conf;
	}

	target_service = conf->lookups->service_name;

	if (conf->lookups->next != NULL) {
		policy_correct = 0;
		if (use_default) {
			(void) fprintf(stderr,
			"\n%s\n There is no publickey entry in %s.\n",
			    head_msg, __NSW_CONFIG_FILE);
			(void) fprintf(stderr,
			"The default publickey policy is \"publickey: %s\".\n",
			    switch_policy_str(default_conf));
		} else
			(void) fprintf(stderr,
		"\n%s\nThe publickey entry in %s is \"publickey: %s\".\n",
			    head_msg, __NSW_CONFIG_FILE,
			    switch_policy_str(conf));
	}

	if (policy_correct == 0)
		(void) fprintf(stderr,
	"I cannot figure out which publickey database you want to update.\n");
	if (!use_default && conf)
		__nsw_freeconfig(conf);

	if (policy_correct)
		return (target_service);
	else
		return (0);
}



int
check_switch_policy(char *policy, char *target_service,
    struct __nsw_switchconfig *default_conf, char *head_msg, char *tail_msg)
{
	struct __nsw_switchconfig *conf;
	enum __nsw_parse_err perr;
	int policy_correct = 1;

	if (default_conf == 0)
		default_conf = &publickey_default;

	conf = __nsw_getconfig(policy, &perr);
	if (no_switch_policy(conf)) {
		if (!is_switch_policy(default_conf, target_service)) {
			(void) fprintf(stderr,
			    "\n%s\nThere is no publickey entry in %s.\n",
			    head_msg, __NSW_CONFIG_FILE);
			(void) fprintf(stderr,
			"The default publickey policy is \"publickey: %s\".\n",
			    switch_policy_str(default_conf));
			policy_correct = 0;
		}
	} else if (!is_switch_policy(conf, target_service)) {
		(void) fprintf(stderr,
		"\n%s\nThe publickey entry in %s is \"publickey: %s\".\n",
		    head_msg, __NSW_CONFIG_FILE,
		    switch_policy_str(conf));
		policy_correct = 0;
	}
	/* should we exit ? */
	if (policy_correct == 0)
		(void) fprintf(stderr,
		"It should be \"publickey: %s\"%s\n\n",
		    target_service, tail_msg);
	if (conf)
		__nsw_freeconfig(conf);

	return (policy_correct);
}

int
get_pk_source(char *pk_service)
{
	int db = 0, got_from_switch = 0;

	/* No service specified, try to figure out from switch */
	if (pk_service == 0) {
		pk_service = first_and_only_switch_policy("publickey", 0,
		    "ERROR:");
		if (pk_service == 0)
			return (0);
		(void) fprintf(stdout,
		    "Updating %s publickey database.\n",
		    pk_service);
		got_from_switch = 1;
	}

	if (strcmp(pk_service, "ldap") == 0)
		db = PK_LDAP;
	else if (strcmp(pk_service, "nis") == 0)
		db = PK_YP;
	else if (strcmp(pk_service, "files") == 0)
		db = PK_FILES;
	else return (0);

	/*
	 * If we didn't get service name from switch, check switch
	 * and print warning about it source of publickeys if not unique
	 */
	if (got_from_switch == 0)
		check_switch_policy("publickey", pk_service, 0, "WARNING:",
		    db == PK_FILES ? "" :
		    "; add 'files' if you want the 'nobody' key.");


	return (db); /* all passed */
}


/* ***************************** keylogin stuff *************************** */
int
keylogin(char *netname, char *secret)
{
	struct key_netstarg netst;

	netst.st_pub_key[0] = 0;
	memcpy(netst.st_priv_key, secret, HEXKEYBYTES);
	netst.st_netname = netname;

#ifdef NFS_AUTH
	nra.authtype = AUTH_DES;	/* only revoke DES creds */
	nra.uid = getuid();		/* use the real uid */
	if (_nfssys(NFS_REVAUTH, &nra) < 0) {
		perror("Warning: NFS credentials not destroyed");
		err = 1;
	}
#endif


	/* do actual key login */
	if (key_setnet(&netst) < 0) {
		(void) fprintf(stderr,
		    "Could not set %s's secret key\n", netname);
		(void) fprintf(stderr, "May be the keyserv is down?\n");
		return (0);
	}

	return (1);
}

nis_object *
init_entry()
{
	static nis_object	obj;
	static entry_col	cred_data[10];
	entry_obj		*eo;

	memset((char *)(&obj), 0, sizeof (obj));
	memset((char *)(cred_data), 0, sizeof (entry_col) * 10);

	obj.zo_name = "cred";
	obj.zo_group = "";
	obj.zo_ttl = 43200;
	obj.zo_data.zo_type = NIS_ENTRY_OBJ;
	eo = &(obj.EN_data);
	eo->en_type = "cred_tbl";
	eo->en_cols.en_cols_val = cred_data;
	eo->en_cols.en_cols_len = 5;
	cred_data[4].ec_flags |= EN_CRYPT;
	return (&obj);
}


static char	*attrFilter[] = {
	"objectclass",
	"nispublickey",
	"nissecretkey",
	(char *)NULL
};


/* Determines if there is a NisKeyObject objectclass in a given entry */
static int
ldap_keyobj_exist(ns_ldap_entry_t *entry)
{
	char		**fattrs;

	fattrs = __ns_ldap_getAttr(entry, "objectClass");

	if (fattrs == NULL)
		return (1);

	while (*fattrs) {
		if (strcasecmp("NisKeyObject", *fattrs) == 0)
			return (1);
		fattrs++;
	}

	return (0);
}


static char *keyAttrs[] = {
	"nispublickey",
	"nissecretkey",
	NULL
};

/*
 * Replace or append new attribute value(s) to an attribute.
 * Don't care about memory leaks, because program is short running.
 */

static int
ldap_attr_mod(ns_ldap_entry_t *entry, char *mechname, char *public,
    ns_ldap_attr_t **pkeyattrs, char *crypt, ns_ldap_attr_t **ckeyattrs)
{
	char		**alist[2];
	char		*keys[2];

	char		*mechfilter;
	int		mechfilterlen;
	int		q = 0;
	int		i, j;
	int		keycount[] = {0, 0};
	ns_ldap_attr_t	*attrs;

	keys[0] = public;
	keys[1] = crypt;

	mechfilter = (char *)malloc(strlen(mechname) + 3);
	if (mechfilter == NULL)
		return (0);
	sprintf(mechfilter, "{%s}", mechname);
	mechfilterlen = strlen(mechfilter);

	for (q = 0; keyAttrs[q] != NULL; q++) {
		int		found = 0;

		for (i = 0; i < entry->attr_count; i++) {
			int		rep = 0;
			ns_ldap_attr_t	*attr = entry->attr_pair[i];
			char		*name = attr->attrname;
			int		count = 0;

			if (strcasecmp(keyAttrs[q], name) == 0) {
				found++;
				count = attr->value_count;
		alist[q] = (char **)malloc(sizeof (char *) * (count + 1));
				if (alist[q] == NULL)
					return (0);
				alist[q][attr->value_count] = NULL;
				for (j = 0; j < attr->value_count; j++) {
					char	*val = attr->attrvalue[j];
					if (strncasecmp(val, mechfilter,
					    mechfilterlen) == 0) {
						/* Replace entry */
						rep++;
						alist[q][j] = keys[q];
					} else
						alist[q][j] = val;
					++keycount[q];
				}
				if (!rep) {
					/* Add entry to list */
					alist[q] = (char **)realloc(alist[q],
					    sizeof (char *) * (count + 2));
					if (alist[q] == NULL)
						return (0);
					alist[q][attr->value_count + 1] = NULL;
					alist[q][attr->value_count] = keys[q];
					++keycount[q];
				}
			}
		}
		if (!found) {
			/* Attribute does not exist, add entry anyways */
			alist[q] = (char **)malloc(sizeof (char *) * 2);
			if (alist[q] == NULL)
				return (0);
			alist[q][0] = keys[q];
			alist[q][1] = NULL;
			++keycount[q];
		}
	}
	if ((attrs = (ns_ldap_attr_t *)calloc(1,
	    sizeof (ns_ldap_attr_t))) == NULL)
		return (0);
	attrs->attrname = "nisPublicKey";
	attrs->attrvalue = alist[0];
	attrs->value_count = keycount[0];
	*pkeyattrs = attrs;

	if ((attrs = (ns_ldap_attr_t *)calloc(1,
	    sizeof (ns_ldap_attr_t))) == NULL)
		return (0);
	attrs->attrname = "nisSecretKey";
	attrs->attrvalue = alist[1];
	attrs->value_count = keycount[1];
	*ckeyattrs = attrs;
	return (1);
}


/*
 * Do the actual Add or update of attributes in attrs.
 * The parameter 'update4host' is a flag that tells the function which
 * DN and password should be used to bind to ldap. If it is an update
 * for a host (update4host > 0), the two parameters "bindDN" and
 * "bindPasswd" would be used to bind as the directory manager,
 * otherwise "dn" and "passwd" would be used to bind as an individual
 * user.
 */
static void
update_ldap_attr(const char *dn, ns_ldap_attr_t **attrs, const char *passwd,
    int add, int update4host, const char *bindDN, const char *bindPasswd)
{
	int		ldaprc;
	int		authstried = 0;
	char		*msg;
	char		*ldap_pw;
	char		**certpath = NULL;
	ns_auth_t	**app;
	ns_auth_t	**authpp = NULL;
	ns_auth_t	*authp = NULL;
	ns_cred_t	*credp;
	ns_ldap_error_t	*errorp = NULL;
	int		status;

	if ((credp = (ns_cred_t *)calloc(1, sizeof (ns_cred_t))) == NULL) {
		fprintf(stderr, "Can not allocate cred buffer.\n");
		goto out;
	}

	/*
	 * if this is an update for host, use the bindDN from the
	 * command prompt, otherwise use user's DN directly.
	 */
	if (update4host)
		credp->cred.unix_cred.userID = strdup(bindDN);
	else
		credp->cred.unix_cred.userID = strdup(dn);

	if (credp->cred.unix_cred.userID == NULL) {
		fprintf(stderr, "Memory allocation failure (userID)\n");
		goto out;
	}

	if (update4host) {
		credp->cred.unix_cred.passwd = strdup(bindPasswd);
	} else {
		if (passwd)
			credp->cred.unix_cred.passwd = strdup(passwd);
		else {
			/* Make sure a valid password is received. */
			status = get_ldap_bindPassword(&ldap_pw);

			if (status != PROMPTGET_SUCCESS) {
				if (!ldap_pw)
					free(ldap_pw);
				goto out;
			}
			credp->cred.unix_cred.passwd = ldap_pw;
		}
	}

	if (credp->cred.unix_cred.passwd == NULL) {
		fprintf(stderr, "Memory allocation failure (passwd)\n");
		goto out;
	}

	/* get host certificate path, if one is configured */
	if (__ns_ldap_getParam(NS_LDAP_HOST_CERTPATH_P,
	    (void ***)&certpath, &errorp) != NS_LDAP_SUCCESS)
		goto out;

	if (certpath && *certpath)
		credp->hostcertpath = *certpath;

	/* Load the service specific authentication method */
	if (__ns_ldap_getServiceAuthMethods("keyserv", &authpp, &errorp) !=
	    NS_LDAP_SUCCESS)
		goto out;

	/*
	 * if authpp is null, there is no serviceAuthenticationMethod
	 * try default authenticationMethod
	 */
	if (authpp == NULL) {
		if (__ns_ldap_getParam(NS_LDAP_AUTH_P, (void ***)&authpp,
		    &errorp) != NS_LDAP_SUCCESS)
			goto out;
	}

	/*
	 * if authpp is still null, then can not authenticate, log
	 * error message and return error
	 */
	if (authpp == NULL) {
		fprintf(stderr, "No LDAP authentication method configured.\n"
		    " configured.\n");
		goto out;
	}

	/*
	 * Walk the array and try all authentication methods in order except
	 * for "none".
	 */
	for (app = authpp; *app; app++) {
		authp = *app;
		/* what about disabling other mechanisms? "tls:sasl/EXTERNAL" */
		if (authp->type == NS_LDAP_AUTH_NONE)
			continue;
		authstried++;
		credp->auth.type = authp->type;
		credp->auth.tlstype = authp->tlstype;
		credp->auth.saslmech = authp->saslmech;
		credp->auth.saslopt = authp->saslopt;

		if (add == TRUE)
			ldaprc = __ns_ldap_addAttr("publickey", dn,
			    (const ns_ldap_attr_t * const *)attrs,
			    credp, 0, &errorp);
		else
			ldaprc = __ns_ldap_repAttr("publickey", dn,
			    (const ns_ldap_attr_t * const *)attrs,
			    credp, 0, &errorp);
		if (ldaprc == NS_LDAP_SUCCESS) {
			/* clean up ns_cred_t structure in memory */
			if (credp != NULL)
				(void) __ns_ldap_freeCred(&credp);
			return;
		}

		/* XXX add checking for cases of authentication errors */
		if ((ldaprc == NS_LDAP_INTERNAL) &&
		    ((errorp->status == LDAP_INAPPROPRIATE_AUTH) ||
		    (errorp->status == LDAP_INVALID_CREDENTIALS))) {
			fprintf(stderr, "LDAP authentication failed.\n");
			goto out;
		}
	}
	if (authstried == 0)
		fprintf(stderr, "No legal authentication method configured.\n");

out:
	/* clean up ns_cred_t structure in memory */
	if (credp != NULL) {
		(void) __ns_ldap_freeCred(&credp);
	}

	if (errorp) {
		__ns_ldap_err2str(errorp->status, &msg);
		fprintf(stderr, "LDAP error: %s.\n", msg);
	}
	fprintf(stderr, "%s: key-pair(s) unchanged.\n", program_name);
	exit(1);
}


/*
 * Update LDAP nisplublickey entry with new key information via SLDAP.
 * Free and clean up memory that stores credential data soon after
 * they are not used or an error comes up.
 */
int
ldap_update(char *mechname, char *netname, char *public, char *crypt,
    char *passwd)
{
	char		*netnamecpy;
	char		*id;
	char		*domain;
	char		*dn;
	char		*db;
	char		*filter;
	ns_ldap_error_t	*errorp;
	char		*pkeyatval, *ckeyatval;
	ns_ldap_result_t	*res;
	ns_ldap_attr_t	*pattrs, *cattrs;
	int		update4host = FALSE;
	char		*bindDN = NULL;
	char		*bindPasswd = NULL;
	int		status;

	/* Generate DN */
	if ((netnamecpy = strdup(netname)) == NULL)
		return (0);
	if (((id = strchr(netnamecpy, '.')) == NULL) ||
	    ((domain = strchr(netnamecpy, '@')) == NULL))
		return (0);
	else {
		*domain++ = '\0';
		*id++ = '\0';

		id = strdup(id);
		if (id == NULL) {
			free(netnamecpy);
			fprintf(stderr, "LDAP memory error (id)\n");
			return (0);
		}
		domain = strdup(domain);
		if (domain == NULL) {
			free(netnamecpy);
			free(id);
			fprintf(stderr, "LDAP memory error (domain)\n");
			return (0);
		}
		free(netnamecpy);
	}

	if (isdigit(*id)) {
		/* We be user. */
		__ns_ldap_uid2dn(id, &dn, NULL, &errorp);
		if (dn == NULL) {
			fprintf(stderr, "Could not obtain LDAP dn\n");
			fprintf(stderr, "%s: key-pair(s) unchanged.\n",
			    program_name);
			exit(1);
		}
		db = "passwd";
		filter = (char *)malloc(strlen(id) + 13);
		if (filter)
			sprintf(filter, "(uidnumber=%s)", id);
		else {
			fprintf(stderr, "Can not allocate filter buffer.\n");
			fprintf(stderr, "%s: key-pair(s) unchanged.\n",
			    program_name);
			exit(1);
		}
	} else {
		/* We be host. */
		update4host = TRUE;

		__ns_ldap_host2dn(id, NULL, &dn, NULL, &errorp);
		if (dn == NULL) {
			fprintf(stderr, "Could not obtain LDAP dn\n");
			fprintf(stderr, "%s: key-pair(s) unchanged.\n",
			    program_name);
			exit(1);
		}

		db = "hosts";
		filter = (char *)malloc(strlen(id) + 6);
		if (filter)
			sprintf(filter, "(cn=%s)", id);
		else {
			fprintf(stderr, "Can not allocate filter buffer.\n");
			fprintf(stderr, "%s: key-pair(s) unchanged.\n",
			    program_name);
			exit(1);
		}

		/* Prompt for ldap bind DN for entry udpates */
		status = get_ldap_bindDN(&bindDN);

		if (status != PROMPTGET_SUCCESS) {
			FREE_CREDINFO(bindDN);
			fprintf(stderr,
			    "Failed to get a valid LDAP bind DN.\n"
			    "%s: key-pair(s) unchanged.\n",
			    program_name);
			exit(1);
		}

		/* Prompt for ldap bind password */
		status = get_ldap_bindPassword(&bindPasswd);

		if (status != PROMPTGET_SUCCESS) {
			FREE_CREDINFO(bindPasswd);
			FREE_CREDINFO(bindDN);

			fprintf(stderr,
			    "Failed to get a valid LDAP bind password."
			    "\n%s: key-pair(s) unchanged.\n",
			    program_name);
			exit(1);
		}
	}

	/* Construct attribute values */
	pkeyatval = (char *)malloc(strlen(mechname) + strlen(public) + 3);
	if (pkeyatval == NULL) {
		FREE_CREDINFO(bindPasswd);
		FREE_CREDINFO(bindDN);
		fprintf(stderr, "LDAP memory error (pkeyatval)\n");
		fprintf(stderr, "%s: key-pair(s) unchanged.\n", program_name);
		exit(1);
	}
	sprintf(pkeyatval, "{%s}%s", mechname, public);
	ckeyatval = (char *)malloc(strlen(mechname) + strlen(crypt) + 3);
	if (ckeyatval == NULL) {
		FREE_CREDINFO(pkeyatval);
		FREE_CREDINFO(bindPasswd);
		FREE_CREDINFO(bindDN);
		fprintf(stderr, "LDAP memory error (pkeyatval)\n");
		fprintf(stderr, "%s: key-pair(s) unchanged.\n", program_name);
		exit(1);
	}
	sprintf(ckeyatval, "{%s}%s", mechname, crypt);

	/* Does entry exist? */
	if ((__ns_ldap_list(db, filter, NULL, (const char **)attrFilter,
	    NULL, 0, &res, &errorp,
	    NULL, NULL) == NS_LDAP_SUCCESS) && res == NULL) {
		FREE_CREDINFO(ckeyatval);
		FREE_CREDINFO(pkeyatval);
		FREE_CREDINFO(bindPasswd);
		FREE_CREDINFO(bindDN);
		fprintf(stderr, "LDAP entry does not exist.\n");
		fprintf(stderr, "%s: key-pair(s) unchanged.\n", program_name);
		exit(1);
	}

	/* Entry exists, modify attributes for public and secret keys */

	/* Is there a NisKeyObject in entry? */
	if (!ldap_keyobj_exist(&res->entry[0])) {
		/* Add NisKeyObject objectclass and the keys */
		char	**newattr;
		ns_ldap_attr_t	*attrs[4]; /* objectclass, pk, sk, NULL */

		/* set objectclass */
		newattr = (char **)calloc(2, sizeof (char *));
		newattr[0] = "NisKeyObject";
		newattr[1] = NULL;
		if ((attrs[0] = (ns_ldap_attr_t *)calloc(1,
		    sizeof (ns_ldap_attr_t))) == NULL) {
			FREE_CREDINFO(ckeyatval);
			FREE_CREDINFO(pkeyatval);
			FREE_CREDINFO(bindPasswd);
			FREE_CREDINFO(bindDN);
			fprintf(stderr, "Memory allocation failed\n");
			fprintf(stderr, "%s: key-pair(s) unchanged.\n",
			    program_name);
			exit(1);
		}
		attrs[0]->attrname = "objectClass";
		attrs[0]->attrvalue = newattr;
		attrs[0]->value_count = 1;

		/* set publickey */
		newattr = (char **)calloc(2, sizeof (char *));
		newattr[0] = pkeyatval;
		newattr[1] = NULL;
		if ((attrs[1] = (ns_ldap_attr_t *)calloc(1,
		    sizeof (ns_ldap_attr_t))) == NULL) {
			FREE_CREDINFO(ckeyatval);
			FREE_CREDINFO(pkeyatval);
			FREE_CREDINFO(bindPasswd);
			FREE_CREDINFO(bindDN);
			fprintf(stderr, "Memory allocation failed\n");
			fprintf(stderr, "%s: key-pair(s) unchanged.\n",
			    program_name);
			exit(1);
		}
		attrs[1]->attrname = "nisPublicKey";
		attrs[1]->attrvalue = newattr;
		attrs[1]->value_count = 1;

		/* set privatekey */
		newattr = (char **)calloc(2, sizeof (char *));
		newattr[0] = ckeyatval;
		newattr[1] = NULL;
		if ((attrs[2] = (ns_ldap_attr_t *)calloc(1,
		    sizeof (ns_ldap_attr_t))) == NULL) {
			FREE_CREDINFO(ckeyatval);
			FREE_CREDINFO(pkeyatval);
			FREE_CREDINFO(bindPasswd);
			FREE_CREDINFO(bindDN);
			fprintf(stderr, "Memory allocation failed\n");
			fprintf(stderr, "%s: key-pair(s) unchanged.\n",
			    program_name);
			exit(1);
		}
		attrs[2]->attrname = "nisSecretKey";
		attrs[2]->attrvalue = newattr;
		attrs[2]->value_count = 1;

		/* terminator */
		attrs[3] = NULL;

		update_ldap_attr(dn, attrs, passwd, TRUE, update4host,
		    bindDN, bindPasswd);
	} else {
		/* object class already exists, replace keys */
		ns_ldap_attr_t	*attrs[4]; /* objectclass, pk, sk, NULL */

		if (!ldap_attr_mod(&res->entry[0], mechname,
		    pkeyatval, &pattrs,
		    ckeyatval, &cattrs)) {
			FREE_CREDINFO(ckeyatval);
			FREE_CREDINFO(pkeyatval);
			FREE_CREDINFO(bindPasswd);
			FREE_CREDINFO(bindDN);
			fprintf(stderr,
			    "Could not generate LDAP attribute list.\n");
			fprintf(stderr,
			    "%s: key-pair(s) unchanged.\n", program_name);
			exit(1);
		}

		attrs[0] = pattrs;
		attrs[1] = cattrs;
		attrs[2] = NULL;

		update_ldap_attr(dn, attrs, passwd, FALSE, update4host,
		    bindDN, bindPasswd);
	}

	FREE_CREDINFO(ckeyatval);
	FREE_CREDINFO(pkeyatval);
	FREE_CREDINFO(bindPasswd);
	FREE_CREDINFO(bindDN);

	return (0);
}
