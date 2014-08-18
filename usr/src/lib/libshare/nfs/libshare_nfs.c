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
 * Copyright (c) 2006, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
 * Copyright (c) 2012, Joyent, Inc. All rights reserved.
 */

/*
 * NFS specific functions
 */
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <unistd.h>
#include <zone.h>
#include <errno.h>
#include <locale.h>
#include <signal.h>
#include <strings.h>
#include "libshare.h"
#include "libshare_impl.h"
#include <nfs/export.h>
#include <pwd.h>
#include <grp.h>
#include <limits.h>
#include <libscf.h>
#include <syslog.h>
#include <rpcsvc/daemon_utils.h>
#include "nfslog_config.h"
#include "nfslogtab.h"
#include "libshare_nfs.h"
#include <nfs/nfs.h>
#include <nfs/nfssys.h>
#include "smfcfg.h"

/* should really be in some global place */
#define	DEF_WIN	30000
#define	OPT_CHUNK	1024

int debug = 0;

#define	NFS_SERVER_SVC	"svc:/network/nfs/server:default"
#define	NFS_CLIENT_SVC	(char *)"svc:/network/nfs/client:default"

/* internal functions */
static int nfs_init();
static void nfs_fini();
static int nfs_enable_share(sa_share_t);
static int nfs_disable_share(sa_share_t, char *);
static int nfs_validate_property(sa_handle_t, sa_property_t, sa_optionset_t);
static int nfs_validate_security_mode(char *);
static int nfs_is_security_opt(char *);
static int nfs_parse_legacy_options(sa_group_t, char *);
static char *nfs_format_options(sa_group_t, int);
static int nfs_set_proto_prop(sa_property_t);
static sa_protocol_properties_t nfs_get_proto_set();
static char *nfs_get_status();
static char *nfs_space_alias(char *);
static uint64_t nfs_features();

/*
 * ops vector that provides the protocol specific info and operations
 * for share management.
 */

struct sa_plugin_ops sa_plugin_ops = {
	SA_PLUGIN_VERSION,
	"nfs",
	nfs_init,
	nfs_fini,
	nfs_enable_share,
	nfs_disable_share,
	nfs_validate_property,
	nfs_validate_security_mode,
	nfs_is_security_opt,
	nfs_parse_legacy_options,
	nfs_format_options,
	nfs_set_proto_prop,
	nfs_get_proto_set,
	nfs_get_status,
	nfs_space_alias,
	NULL,	/* update_legacy */
	NULL,	/* delete_legacy */
	NULL,	/* change_notify */
	NULL,	/* enable_resource */
	NULL,	/* disable_resource */
	nfs_features,
	NULL,	/* transient shares */
	NULL,	/* notify resource */
	NULL,	/* rename_resource */
	NULL,	/* run_command */
	NULL,	/* command_help */
	NULL	/* delete_proto_section */
};

/*
 * list of support services needed
 * defines should come from head/rpcsvc/daemon_utils.h
 */

static char *service_list_default[] =
	{ STATD, LOCKD, MOUNTD, NFSD, NFSMAPID, RQUOTAD, REPARSED, NULL };
static char *service_list_logging[] =
	{ STATD, LOCKD, MOUNTD, NFSD, NFSMAPID, RQUOTAD, NFSLOGD, REPARSED,
	    NULL };

/*
 * option definitions.  Make sure to keep the #define for the option
 * index just before the entry it is the index for. Changing the order
 * can cause breakage.  E.g OPT_RW is index 1 and must precede the
 * line that includes the SHOPT_RW and OPT_RW entries.
 */

struct option_defs optdefs[] = {
#define	OPT_RO		0
	{SHOPT_RO, OPT_RO, OPT_TYPE_ACCLIST},
#define	OPT_RW		1
	{SHOPT_RW, OPT_RW, OPT_TYPE_ACCLIST},
#define	OPT_ROOT	2
	{SHOPT_ROOT, OPT_ROOT, OPT_TYPE_ACCLIST},
#define	OPT_SECURE	3
	{SHOPT_SECURE, OPT_SECURE, OPT_TYPE_DEPRECATED},
#define	OPT_ANON	4
	{SHOPT_ANON, OPT_ANON, OPT_TYPE_USER},
#define	OPT_WINDOW	5
	{SHOPT_WINDOW, OPT_WINDOW, OPT_TYPE_NUMBER},
#define	OPT_NOSUID	6
	{SHOPT_NOSUID, OPT_NOSUID, OPT_TYPE_BOOLEAN},
#define	OPT_ACLOK	7
	{SHOPT_ACLOK, OPT_ACLOK, OPT_TYPE_BOOLEAN},
#define	OPT_NOSUB	8
	{SHOPT_NOSUB, OPT_NOSUB, OPT_TYPE_BOOLEAN},
#define	OPT_SEC		9
	{SHOPT_SEC, OPT_SEC, OPT_TYPE_SECURITY},
#define	OPT_PUBLIC	10
	{SHOPT_PUBLIC, OPT_PUBLIC, OPT_TYPE_BOOLEAN, OPT_SHARE_ONLY},
#define	OPT_INDEX	11
	{SHOPT_INDEX, OPT_INDEX, OPT_TYPE_FILE},
#define	OPT_LOG		12
	{SHOPT_LOG, OPT_LOG, OPT_TYPE_LOGTAG},
#define	OPT_CKSUM	13
	{SHOPT_CKSUM, OPT_CKSUM, OPT_TYPE_STRINGSET},
#define	OPT_NONE	14
	{SHOPT_NONE, OPT_NONE, OPT_TYPE_ACCLIST},
#define	OPT_ROOT_MAPPING	15
	{SHOPT_ROOT_MAPPING, OPT_ROOT_MAPPING, OPT_TYPE_USER},
#define	OPT_CHARSET_MAP	16
	{"", OPT_CHARSET_MAP, OPT_TYPE_ACCLIST},
#define	OPT_NOACLFAB	17
	{SHOPT_NOACLFAB, OPT_NOACLFAB, OPT_TYPE_BOOLEAN},
#define	OPT_UIDMAP	18
	{SHOPT_UIDMAP, OPT_UIDMAP, OPT_TYPE_MAPPING},
#define	OPT_GIDMAP	19
	{SHOPT_GIDMAP, OPT_GIDMAP, OPT_TYPE_MAPPING},
#ifdef VOLATILE_FH_TEST	/* XXX added for testing volatile fh's only */
#define	OPT_VOLFH	20
	{SHOPT_VOLFH, OPT_VOLFH},
#endif /* VOLATILE_FH_TEST */
	NULL
};

/*
 * Codesets that may need to be converted to UTF-8 for file paths.
 * Add new names here to add new property support. If we ever get a
 * way to query the kernel for character sets, this should become
 * dynamically loaded. Make sure changes here are reflected in
 * cmd/fs.d/nfs/mountd/nfscmd.c
 */

static char *legal_conv[] = {
	"euc-cn",
	"euc-jp",
	"euc-jpms",
	"euc-kr",
	"euc-tw",
	"iso8859-1",
	"iso8859-2",
	"iso8859-5",
	"iso8859-6",
	"iso8859-7",
	"iso8859-8",
	"iso8859-9",
	"iso8859-13",
	"iso8859-15",
	"koi8-r",
	NULL
};

/*
 * list of properties that are related to security flavors.
 */
static char *seclist[] = {
	SHOPT_RO,
	SHOPT_RW,
	SHOPT_ROOT,
	SHOPT_WINDOW,
	SHOPT_NONE,
	SHOPT_ROOT_MAPPING,
	SHOPT_UIDMAP,
	SHOPT_GIDMAP,
	NULL
};

/* structure for list of securities */
struct securities {
	sa_security_t security;
	struct securities *next;
};

/*
 * findcharset(charset)
 *
 * Returns B_TRUE if the charset is a legal conversion otherwise
 * B_FALSE. This will need to be rewritten to be more efficient when
 * we have a dynamic list of legal conversions.
 */

static boolean_t
findcharset(char *charset)
{
	int i;

	for (i = 0; legal_conv[i] != NULL; i++)
		if (strcmp(charset, legal_conv[i]) == 0)
			return (B_TRUE);
	return (B_FALSE);
}

/*
 * findopt(name)
 *
 * Lookup option "name" in the option table and return the table
 * index.
 */

static int
findopt(char *name)
{
	int i;
	if (name != NULL) {
		for (i = 0; optdefs[i].tag != NULL; i++) {
			if (strcmp(optdefs[i].tag, name) == 0)
				return (optdefs[i].index);
		}
		if (findcharset(name))
			return (OPT_CHARSET_MAP);
	}
	return (-1);
}

/*
 * gettype(name)
 *
 * Return the type of option "name".
 */

static int
gettype(char *name)
{
	int optdef;

	optdef = findopt(name);
	if (optdef != -1)
		return (optdefs[optdef].type);
	return (OPT_TYPE_ANY);
}

/*
 * nfs_validate_security_mode(mode)
 *
 * is the specified mode string a valid one for use with NFS?
 */

static int
nfs_validate_security_mode(char *mode)
{
	seconfig_t secinfo;
	int err;

	(void) memset(&secinfo, '\0', sizeof (secinfo));
	err = nfs_getseconfig_byname(mode, &secinfo);
	if (err == SC_NOERROR)
		return (1);
	return (0);
}

/*
 * nfs_is_security_opt(tok)
 *
 * check to see if tok represents an option that is only valid in some
 * security flavor.
 */

static int
nfs_is_security_opt(char *tok)
{
	int i;

	for (i = 0; seclist[i] != NULL; i++) {
		if (strcmp(tok, seclist[i]) == 0)
			return (1);
	}
	return (0);
}

/*
 * find_security(seclist, sec)
 *
 * Walk the current list of security flavors and return true if it is
 * present, else return false.
 */

static int
find_security(struct securities *seclist, sa_security_t sec)
{
	while (seclist != NULL) {
		if (seclist->security == sec)
			return (1);
		seclist = seclist->next;
	}
	return (0);
}

/*
 * make_security_list(group, securitymodes, proto)
 *	go through the list of securitymodes and add them to the
 *	group's list of security optionsets. We also keep a list of
 *	those optionsets so we don't have to find them later. All of
 *	these will get copies of the same properties.
 */

static struct securities *
make_security_list(sa_group_t group, char *securitymodes, char *proto)
{
	char *tok, *next = NULL;
	struct securities *curp, *headp = NULL, *prev;
	sa_security_t check;
	int freetok = 0;

	for (tok = securitymodes; tok != NULL; tok = next) {
		next = strchr(tok, ':');
		if (next != NULL)
			*next++ = '\0';
		if (strcmp(tok, "default") == 0) {
			/* resolve default into the real type */
			tok = nfs_space_alias(tok);
			freetok = 1;
		}
		check = sa_get_security(group, tok, proto);

		/* add to the security list if it isn't there already */
		if (check == NULL || !find_security(headp, check)) {
			curp = (struct securities *)calloc(1,
			    sizeof (struct securities));
			if (curp != NULL) {
				if (check == NULL) {
					curp->security = sa_create_security(
					    group, tok, proto);
				} else {
					curp->security = check;
				}
				/*
				 * note that the first time through the loop,
				 * headp will be NULL and prev will be
				 * undefined.  Since headp is NULL, we set
				 * both it and prev to the curp (first
				 * structure to be allocated).
				 *
				 * later passes through the loop will have
				 * headp not being NULL and prev will be used
				 * to allocate at the end of the list.
				 */
				if (headp == NULL) {
					headp = curp;
					prev = curp;
				} else {
					prev->next = curp;
					prev = curp;
				}
			}
		}

		if (freetok) {
			freetok = 0;
			sa_free_attr_string(tok);
		}
	}
	return (headp);
}

static void
free_security_list(struct securities *sec)
{
	struct securities *next;
	if (sec != NULL) {
		for (next = sec->next; sec != NULL; sec = next) {
			next = sec->next;
			free(sec);
		}
	}
}

/*
 * nfs_alistcat(str1, str2, sep)
 *
 * concatenate str1 and str2 into a new string using sep as a separate
 * character. If memory allocation fails, return NULL;
 */

static char *
nfs_alistcat(char *str1, char *str2, char sep)
{
	char *newstr;
	size_t len;

	len = strlen(str1) + strlen(str2) + 2;
	newstr = (char *)malloc(len);
	if (newstr != NULL)
		(void) snprintf(newstr, len, "%s%c%s", str1, sep, str2);
	return (newstr);
}

/*
 * add_security_prop(sec, name, value, persist, iszfs)
 *
 * Add the property to the securities structure. This accumulates
 * properties for as part of parsing legacy options.
 */

static int
add_security_prop(struct securities *sec, char *name, char *value,
			int persist, int iszfs)
{
	sa_property_t prop;
	int ret = SA_OK;

	for (; sec != NULL; sec = sec->next) {
		if (value == NULL) {
			if (strcmp(name, SHOPT_RW) == 0 ||
			    strcmp(name, SHOPT_RO) == 0)
				value = "*";
			else
				value = "true";
		}

		/*
		 * Get the existing property, if it exists, so we can
		 * determine what to do with it. The ro/rw/root
		 * properties can be merged if multiple instances of
		 * these properies are given. For example, if "rw"
		 * exists with a value "host1" and a later token of
		 * rw="host2" is seen, the values are merged into a
		 * single rw="host1:host2".
		 */
		prop = sa_get_property(sec->security, name);

		if (prop != NULL) {
			char *oldvalue;
			char *newvalue;

			/*
			 * The security options of ro/rw/root/uidmap/gidmap
			 * might appear multiple times.  If they do, the values
			 * need to be merged.  If it was previously empty, the
			 * new value alone is added.
			 */
			oldvalue = sa_get_property_attr(prop, "value");
			if (oldvalue != NULL) {
				char sep = ':';

				if (strcmp(name, SHOPT_UIDMAP) == 0 ||
				    strcmp(name, SHOPT_GIDMAP) == 0)
					sep = '~';

				/*
				 * The general case is to concatenate the new
				 * value onto the old value for multiple
				 * rw(ro/root/uidmap/gidmap) properties.  For
				 * rw/ro/root a special case exists when either
				 * the old or new is the "all" case.  In the
				 * special case, if both are "all", then it is
				 * "all", else if one is an access-list, that
				 * replaces the "all".
				 */
				if (strcmp(oldvalue, "*") == 0) {
					/* Replace old value with new value. */
					newvalue = strdup(value);
				} else if (strcmp(value, "*") == 0 ||
				    strcmp(oldvalue, value) == 0) {
					/*
					 * Keep old value and ignore
					 * the new value.
					 */
					newvalue = NULL;
				} else {
					/*
					 * Make a new list of old plus new
					 * access-list.
					 */
					newvalue = nfs_alistcat(oldvalue,
					    value, sep);
				}

				if (newvalue != NULL) {
					(void) sa_remove_property(prop);
					prop = sa_create_property(name,
					    newvalue);
					ret = sa_add_property(sec->security,
					    prop);
					free(newvalue);
				}

				sa_free_attr_string(oldvalue);
			}
		} else {
			prop = sa_create_property(name, value);
			ret = sa_add_property(sec->security, prop);
		}
		if (ret == SA_OK && !iszfs) {
			ret = sa_commit_properties(sec->security, !persist);
		}
	}
	return (ret);
}

/*
 * check to see if group/share is persistent.
 */
static int
is_persistent(sa_group_t group)
{
	char *type;
	int persist = 1;

	type = sa_get_group_attr(group, "type");
	if (type != NULL && strcmp(type, "persist") != 0)
		persist = 0;
	if (type != NULL)
		sa_free_attr_string(type);
	return (persist);
}

/*
 * invalid_security(options)
 *
 * search option string for any invalid sec= type.
 * return true (1) if any are not valid else false (0)
 */
static int
invalid_security(char *options)
{
	char *copy, *base, *token, *value;
	int ret = 0;

	copy = strdup(options);
	token = base = copy;
	while (token != NULL && ret == 0) {
		token = strtok(base, ",");
		base = NULL;
		if (token != NULL) {
			value = strchr(token, '=');
			if (value != NULL)
				*value++ = '\0';
			if (strcmp(token, SHOPT_SEC) == 0) {
				/* HAVE security flavors so check them */
				char *tok, *next;
				for (next = NULL, tok = value; tok != NULL;
				    tok = next) {
					next = strchr(tok, ':');
					if (next != NULL)
						*next++ = '\0';
					ret = !nfs_validate_security_mode(tok);
					if (ret)
						break;
				}
			}
		}
	}
	if (copy != NULL)
		free(copy);
	return (ret);
}

/*
 * nfs_parse_legacy_options(group, options)
 *
 * Parse the old style options into internal format and store on the
 * specified group.  Group could be a share for full legacy support.
 */

static int
nfs_parse_legacy_options(sa_group_t group, char *options)
{
	char *dup;
	char *base;
	char *token;
	sa_optionset_t optionset;
	struct securities *security_list = NULL;
	sa_property_t prop;
	int ret = SA_OK;
	int iszfs = 0;
	sa_group_t parent;
	int persist = 0;
	char *lasts;

	/* do we have an existing optionset? */
	optionset = sa_get_optionset(group, "nfs");
	if (optionset == NULL) {
		/* didn't find existing optionset so create one */
		optionset = sa_create_optionset(group, "nfs");
	} else {
		/*
		 * Have an existing optionset . Ideally, we would need
		 * to compare options in order to detect errors. For
		 * now, we assume that the first optionset is the
		 * correct one and the others will be the same. An
		 * empty optionset is the same as no optionset so we
		 * don't want to exit in that case. Getting an empty
		 * optionset can occur with ZFS property checking.
		 */
		if (sa_get_property(optionset, NULL) != NULL)
			return (ret);
	}

	if (strcmp(options, SHOPT_RW) == 0) {
		/*
		 * there is a special case of only the option "rw"
		 * being the default option. We don't have to do
		 * anything.
		 */
		return (ret);
	}

	/*
	 * check if security types are present and validate them. If
	 * any are not legal, fail.
	 */

	if (invalid_security(options)) {
		return (SA_INVALID_SECURITY);
	}

	/*
	 * in order to not attempt to change ZFS properties unless
	 * absolutely necessary, we never do it in the legacy parsing.
	 */
	if (sa_is_share(group)) {
		char *zfs;
		parent = sa_get_parent_group(group);
		if (parent != NULL) {
			zfs = sa_get_group_attr(parent, "zfs");
			if (zfs != NULL) {
				sa_free_attr_string(zfs);
				iszfs++;
			}
		}
	} else {
		iszfs = sa_group_is_zfs(group);
	}

	/* We need a copy of options for the next part. */
	dup = strdup(options);
	if (dup == NULL)
		return (SA_NO_MEMORY);

	/*
	 * we need to step through each option in the string and then
	 * add either the option or the security option as needed. If
	 * this is not a persistent share, don't commit to the
	 * repository. If there is an error, we also want to abort the
	 * processing and report it.
	 */
	persist = is_persistent(group);
	base = dup;
	token = dup;
	lasts = NULL;
	while (token != NULL && ret == SA_OK) {
		token = strtok_r(base, ",", &lasts);
		base = NULL;
		if (token != NULL) {
			char *value;
			/*
			 * if the option has a value, it will have an '=' to
			 * separate the name from the value. The following
			 * code will result in value != NULL and token
			 * pointing to just the name if there is a value.
			 */
			value = strchr(token, '=');
			if (value != NULL) {
				*value++ = '\0';
			}
			if (strcmp(token, SHOPT_SEC) == 0 ||
			    strcmp(token, SHOPT_SECURE) == 0) {
				/*
				 * Once in security parsing, we only
				 * do security. We do need to move
				 * between the security node and the
				 * toplevel. The security tag goes on
				 * the root while the following ones
				 * go on the security.
				 */
				if (security_list != NULL) {
					/*
					 * have an old list so close it and
					 * start the new
					 */
					free_security_list(security_list);
				}
				if (strcmp(token, SHOPT_SECURE) == 0) {
					value = "dh";
				} else {
					if (value == NULL) {
						ret = SA_SYNTAX_ERR;
						break;
					}
				}
				security_list = make_security_list(group,
				    value, "nfs");
			} else {
				/*
				 * Note that the "old" syntax allowed a
				 * default security model.  This must be
				 * accounted for and internally converted to
				 * "standard" security structure.
				 */
				if (nfs_is_security_opt(token)) {
					if (security_list == NULL) {
						/*
						 * need to have a
						 * security
						 * option. This will
						 * be "closed" when a
						 * defined "sec="
						 * option is
						 * seen. This is
						 * technically an
						 * error but will be
						 * allowed with
						 * warning.
						 */
						security_list =
						    make_security_list(group,
						    "default",
						    "nfs");
					}
					if (security_list != NULL) {
						ret = add_security_prop(
						    security_list, token,
						    value, persist, iszfs);
					} else {
						ret = SA_NO_MEMORY;
					}
				} else {
					/* regular options */
					if (value == NULL) {
						if (strcmp(token, SHOPT_RW) ==
						    0 || strcmp(token,
						    SHOPT_RO) == 0) {
							value = "*";
						} else {
							value = "global";
							if (strcmp(token,
							    SHOPT_LOG) != 0) {
								value = "true";
							}
						}
					}
					/*
					 * In all cases, create the
					 * property specified. If the
					 * value was NULL, the default
					 * value will have been
					 * substituted.
					 */
					prop = sa_create_property(token, value);
					ret =  sa_add_property(optionset, prop);
					if (ret != SA_OK)
						break;

					if (!iszfs) {
						ret = sa_commit_properties(
						    optionset, !persist);
					}
				}
			}
		}
	}
	if (security_list != NULL)
		free_security_list(security_list);

	free(dup);
	return (ret);
}

/*
 * is_a_number(number)
 *
 * is the string a number in one of the forms we want to use?
 */

static int
is_a_number(char *number)
{
	int ret = 1;
	int hex = 0;

	if (strncmp(number, "0x", 2) == 0) {
		number += 2;
		hex = 1;
	} else if (*number == '-') {
		number++; /* skip the minus */
	}
	while (ret == 1 && *number != '\0') {
		if (hex) {
			ret = isxdigit(*number++);
		} else {
			ret = isdigit(*number++);
		}
	}
	return (ret);
}

/*
 * Look for the specified tag in the configuration file. If it is found,
 * enable logging and set the logging configuration information for exp.
 */
static void
configlog(struct exportdata *exp, char *tag)
{
	nfsl_config_t *configlist = NULL, *configp;
	int error = 0;
	char globaltag[] = DEFAULTTAG;

	/*
	 * Sends config errors to stderr
	 */
	nfsl_errs_to_syslog = B_FALSE;

	/*
	 * get the list of configuration settings
	 */
	error = nfsl_getconfig_list(&configlist);
	if (error) {
		(void) fprintf(stderr,
		    dgettext(TEXT_DOMAIN, "Cannot get log configuration: %s\n"),
		    strerror(error));
	}

	if (tag == NULL)
		tag = globaltag;
	if ((configp = nfsl_findconfig(configlist, tag, &error)) == NULL) {
		nfsl_freeconfig_list(&configlist);
		(void) fprintf(stderr,
		    dgettext(TEXT_DOMAIN, "No tags matching \"%s\"\n"), tag);
		/* bad configuration */
		error = ENOENT;
		goto err;
	}

	if ((exp->ex_tag = strdup(tag)) == NULL) {
		error = ENOMEM;
		goto out;
	}
	if ((exp->ex_log_buffer = strdup(configp->nc_bufferpath)) == NULL) {
		error = ENOMEM;
		goto out;
	}
	exp->ex_flags |= EX_LOG;
	if (configp->nc_rpclogpath != NULL)
		exp->ex_flags |= EX_LOG_ALLOPS;
out:
	if (configlist != NULL)
		nfsl_freeconfig_list(&configlist);

err:
	if (error != 0) {
		if (exp->ex_flags != NULL)
			free(exp->ex_tag);
		if (exp->ex_log_buffer != NULL)
			free(exp->ex_log_buffer);
		(void) fprintf(stderr,
		    dgettext(TEXT_DOMAIN, "Cannot set log configuration: %s\n"),
		    strerror(error));
	}
}

/*
 * fill_export_from_optionset(export, optionset)
 *
 * In order to share, we need to set all the possible general options
 * into the export structure. Share info will be filled in by the
 * caller. Various property values get turned into structure specific
 * values.
 */

static int
fill_export_from_optionset(struct exportdata *export, sa_optionset_t optionset)
{
	sa_property_t option;
	int ret = SA_OK;

	for (option = sa_get_property(optionset, NULL);
	    option != NULL; option = sa_get_next_property(option)) {
		char *name;
		char *value;
		uint32_t val;

		/*
		 * since options may be set/reset multiple times, always do an
		 * explicit set or clear of the option. This allows defaults
		 * to be set and then the protocol specific to override.
		 */

		name = sa_get_property_attr(option, "type");
		value = sa_get_property_attr(option, "value");
		switch (findopt(name)) {
		case OPT_ANON:
			if (value != NULL && is_a_number(value)) {
				val = strtoul(value, NULL, 0);
			} else {
				struct passwd *pw;
				pw = getpwnam(value != NULL ? value : "nobody");
				if (pw != NULL) {
					val = pw->pw_uid;
				} else {
					val = UID_NOBODY;
				}
				endpwent();
			}
			export->ex_anon = val;
			break;
		case OPT_NOSUID:
			if (value != NULL && (strcasecmp(value, "true") == 0 ||
			    strcmp(value, "1") == 0))
				export->ex_flags |= EX_NOSUID;
			else
				export->ex_flags &= ~EX_NOSUID;
			break;
		case OPT_ACLOK:
			if (value != NULL && (strcasecmp(value, "true") == 0 ||
			    strcmp(value, "1") == 0))
				export->ex_flags |= EX_ACLOK;
			else
				export->ex_flags &= ~EX_ACLOK;
			break;
		case OPT_NOSUB:
			if (value != NULL && (strcasecmp(value, "true") == 0 ||
			    strcmp(value, "1") == 0))
				export->ex_flags |= EX_NOSUB;
			else
				export->ex_flags &= ~EX_NOSUB;
			break;
		case OPT_PUBLIC:
			if (value != NULL && (strcasecmp(value, "true") == 0 ||
			    strcmp(value, "1") == 0))
				export->ex_flags |= EX_PUBLIC;
			else
				export->ex_flags &= ~EX_PUBLIC;
			break;
		case OPT_INDEX:
			if (value != NULL && (strcmp(value, "..") == 0 ||
			    strchr(value, '/') != NULL)) {
				/* this is an error */
				(void) printf(dgettext(TEXT_DOMAIN,
				    "NFS: index=\"%s\" not valid;"
				    "must be a filename.\n"),
				    value);
				break;
			}
			if (value != NULL && *value != '\0' &&
			    strcmp(value, ".") != 0) {
				/* valid index file string */
				if (export->ex_index != NULL) {
					/* left over from "default" */
					free(export->ex_index);
				}
				/* remember to free */
				export->ex_index = strdup(value);
				if (export->ex_index == NULL) {
					(void) printf(dgettext(TEXT_DOMAIN,
					    "NFS: out of memory setting "
					    "index property\n"));
					break;
				}
				export->ex_flags |= EX_INDEX;
			}
			break;
		case OPT_LOG:
			if (value == NULL)
				value = strdup("global");
			if (value != NULL)
				configlog(export,
				    strlen(value) ? value : "global");
			break;
		case OPT_CHARSET_MAP:
			/*
			 * Set EX_CHARMAP when there is at least one
			 * charmap conversion property. This will get
			 * checked by the nfs server when it needs to.
			 */
			export->ex_flags |= EX_CHARMAP;
			break;
		case OPT_NOACLFAB:
			if (value != NULL && (strcasecmp(value, "true") == 0 ||
			    strcmp(value, "1") == 0))
				export->ex_flags |= EX_NOACLFAB;
			else
				export->ex_flags &= ~EX_NOACLFAB;
			break;
		default:
			/* have a syntactic error */
			(void) printf(dgettext(TEXT_DOMAIN,
			    "NFS: unrecognized option %s=%s\n"),
			    name != NULL ? name : "",
			    value != NULL ? value : "");
			break;
		}
		if (name != NULL)
			sa_free_attr_string(name);
		if (value != NULL)
			sa_free_attr_string(value);
	}
	return (ret);
}

/*
 * cleanup_export(export)
 *
 * Cleanup the allocated areas so we don't leak memory
 */

static void
cleanup_export(struct exportdata *export)
{
	int i;

	free(export->ex_index);

	for (i = 0; i < export->ex_seccnt; i++) {
		struct secinfo *s = &export->ex_secinfo[i];

		while (s->s_rootcnt > 0)
			free(s->s_rootnames[--s->s_rootcnt]);

		free(s->s_rootnames);
	}
	free(export->ex_secinfo);
}

/*
 * Given a seconfig entry and a colon-separated
 * list of names, allocate an array big enough
 * to hold the root list, then convert each name to
 * a principal name according to the security
 * info and assign it to an array element.
 * Return the array and its size.
 */
static caddr_t *
get_rootnames(seconfig_t *sec, char *list, int *count)
{
	caddr_t *a;
	int c, i;
	char *host, *p;

	/*
	 * Count the number of strings in the list.
	 * This is the number of colon separators + 1.
	 */
	c = 1;
	for (p = list; *p; p++)
		if (*p == ':')
			c++;
	*count = c;

	a = (caddr_t *)malloc(c * sizeof (char *));
	if (a == NULL) {
		(void) printf(dgettext(TEXT_DOMAIN,
		    "get_rootnames: no memory\n"));
	} else {
		for (i = 0; i < c; i++) {
			host = strtok(list, ":");
			if (!nfs_get_root_principal(sec, host, &a[i])) {
				while (i > 0)
					free(a[--i]);
				free(a);
				a = NULL;
				break;
			}
			list = NULL;
		}
	}

	return (a);
}

/*
 * fill_security_from_secopts(sp, secopts)
 *
 * Fill the secinfo structure from the secopts optionset.
 */

static int
fill_security_from_secopts(struct secinfo *sp, sa_security_t secopts)
{
	sa_property_t prop;
	char *type;
	int longform;
	int err = SC_NOERROR;
	uint32_t val;

	type = sa_get_security_attr(secopts, "sectype");
	if (type != NULL) {
		/* named security type needs secinfo to be filled in */
		err = nfs_getseconfig_byname(type, &sp->s_secinfo);
		sa_free_attr_string(type);
		if (err != SC_NOERROR)
			return (err);
	} else {
		/* default case */
		err = nfs_getseconfig_default(&sp->s_secinfo);
		if (err != SC_NOERROR)
			return (err);
	}

	err = SA_OK;
	for (prop = sa_get_property(secopts, NULL);
	    prop != NULL && err == SA_OK;
	    prop = sa_get_next_property(prop)) {
		char *name;
		char *value;

		name = sa_get_property_attr(prop, "type");
		value = sa_get_property_attr(prop, "value");

		longform = value != NULL && strcmp(value, "*") != 0;

		switch (findopt(name)) {
		case OPT_RO:
			sp->s_flags |= longform ? M_ROL : M_RO;
			break;
		case OPT_RW:
			sp->s_flags |= longform ? M_RWL : M_RW;
			break;
		case OPT_ROOT:
			sp->s_flags |= M_ROOT;
			/*
			 * if we are using AUTH_UNIX, handle like other things
			 * such as RO/RW
			 */
			if (sp->s_secinfo.sc_rpcnum == AUTH_UNIX)
				break;
			/* not AUTH_UNIX */
			if (value != NULL) {
				sp->s_rootnames = get_rootnames(&sp->s_secinfo,
				    value, &sp->s_rootcnt);
				if (sp->s_rootnames == NULL) {
					err = SA_BAD_VALUE;
					(void) fprintf(stderr,
					    dgettext(TEXT_DOMAIN,
					    "Bad root list\n"));
				}
			}
			break;
		case OPT_NONE:
			sp->s_flags |= M_NONE;
			break;
		case OPT_WINDOW:
			if (value != NULL) {
				sp->s_window = atoi(value);
				/* just in case */
				if (sp->s_window < 0)
					sp->s_window = DEF_WIN;
			}
			break;
		case OPT_ROOT_MAPPING:
			if (value != NULL && is_a_number(value)) {
				val = strtoul(value, NULL, 0);
			} else {
				struct passwd *pw;
				pw = getpwnam(value != NULL ? value : "nobody");
				if (pw != NULL) {
					val = pw->pw_uid;
				} else {
					val = UID_NOBODY;
				}
				endpwent();
			}
			sp->s_rootid = val;
			break;
		case OPT_UIDMAP:
		case OPT_GIDMAP:
			sp->s_flags |= M_MAP;
			break;
		default:
			break;
		}
		if (name != NULL)
			sa_free_attr_string(name);
		if (value != NULL)
			sa_free_attr_string(value);
	}
	/* if rw/ro options not set, use default of RW */
	if ((sp->s_flags & NFS_RWMODES) == 0)
		sp->s_flags |= M_RW;
	return (err);
}

/*
 * This is for testing only
 * It displays the export structure that
 * goes into the kernel.
 */
static void
printarg(char *path, struct exportdata *ep)
{
	int i, j;
	struct secinfo *sp;

	if (debug == 0)
		return;

	(void) printf("%s:\n", path);
	(void) printf("\tex_version = %d\n", ep->ex_version);
	(void) printf("\tex_path = %s\n", ep->ex_path);
	(void) printf("\tex_pathlen = %ld\n", (ulong_t)ep->ex_pathlen);
	(void) printf("\tex_flags: (0x%02x) ", ep->ex_flags);
	if (ep->ex_flags & EX_NOSUID)
		(void) printf("NOSUID ");
	if (ep->ex_flags & EX_ACLOK)
		(void) printf("ACLOK ");
	if (ep->ex_flags & EX_PUBLIC)
		(void) printf("PUBLIC ");
	if (ep->ex_flags & EX_NOSUB)
		(void) printf("NOSUB ");
	if (ep->ex_flags & EX_LOG)
		(void) printf("LOG ");
	if (ep->ex_flags & EX_CHARMAP)
		(void) printf("CHARMAP ");
	if (ep->ex_flags & EX_LOG_ALLOPS)
		(void) printf("LOG_ALLOPS ");
	if (ep->ex_flags == 0)
		(void) printf("(none)");
	(void) 	printf("\n");
	if (ep->ex_flags & EX_LOG) {
		(void) printf("\tex_log_buffer = %s\n",
		    (ep->ex_log_buffer ? ep->ex_log_buffer : "(NULL)"));
		(void) printf("\tex_tag = %s\n",
		    (ep->ex_tag ? ep->ex_tag : "(NULL)"));
	}
	(void) printf("\tex_anon = %d\n", ep->ex_anon);
	(void) printf("\tex_seccnt = %d\n", ep->ex_seccnt);
	(void) printf("\n");
	for (i = 0; i < ep->ex_seccnt; i++) {
		sp = &ep->ex_secinfo[i];
		(void) printf("\t\ts_secinfo = %s\n", sp->s_secinfo.sc_name);
		(void) printf("\t\ts_flags: (0x%02x) ", sp->s_flags);
		if (sp->s_flags & M_ROOT) (void) printf("M_ROOT ");
		if (sp->s_flags & M_RO) (void) printf("M_RO ");
		if (sp->s_flags & M_ROL) (void) printf("M_ROL ");
		if (sp->s_flags & M_RW) (void) printf("M_RW ");
		if (sp->s_flags & M_RWL) (void) printf("M_RWL ");
		if (sp->s_flags & M_NONE) (void) printf("M_NONE ");
		if (sp->s_flags & M_MAP) (void) printf("M_MAP ");
		if (sp->s_flags == 0) (void) printf("(none)");
		(void) printf("\n");
		(void) printf("\t\ts_window = %d\n", sp->s_window);
		(void) printf("\t\ts_rootid = %d\n", sp->s_rootid);
		(void) printf("\t\ts_rootcnt = %d ", sp->s_rootcnt);
		(void) fflush(stdout);
		for (j = 0; j < sp->s_rootcnt; j++)
			(void) printf("%s ", sp->s_rootnames[j] ?
			    sp->s_rootnames[j] : "<null>");
		(void) printf("\n\n");
	}
}

/*
 * count_security(opts)
 *
 * Count the number of security types (flavors). The optionset has
 * been populated with the security flavors as a holding mechanism.
 * We later use this number to allocate data structures.
 */

static int
count_security(sa_optionset_t opts)
{
	int count = 0;
	sa_property_t prop;
	if (opts != NULL) {
		for (prop = sa_get_property(opts, NULL); prop != NULL;
		    prop = sa_get_next_property(prop)) {
			count++;
		}
	}
	return (count);
}

/*
 * nfs_sprint_option(rbuff, rbuffsize, incr, prop, sep)
 *
 * provides a mechanism to format NFS properties into legacy output
 * format. If the buffer would overflow, it is reallocated and grown
 * as appropriate. Special cases of converting internal form of values
 * to those used by "share" are done. this function does one property
 * at a time.
 */

static int
nfs_sprint_option(char **rbuff, size_t *rbuffsize, size_t incr,
			sa_property_t prop, int sep)
{
	char *name;
	char *value;
	int curlen;
	char *buff = *rbuff;
	size_t buffsize = *rbuffsize;
	int printed = B_FALSE;

	name = sa_get_property_attr(prop, "type");
	value = sa_get_property_attr(prop, "value");
	if (buff != NULL)
		curlen = strlen(buff);
	else
		curlen = 0;
	if (name != NULL) {
		int len;
		len = strlen(name) + sep;

		/*
		 * A future RFE would be to replace this with more
		 * generic code and to possibly handle more types.
		 */
		switch (gettype(name)) {
		case OPT_TYPE_BOOLEAN:
			/*
			 * For NFS, boolean value of FALSE means it
			 * doesn't show up in the option list at all.
			 */
			if (value != NULL && strcasecmp(value, "false") == 0)
				goto skip;
			if (value != NULL) {
				sa_free_attr_string(value);
				value = NULL;
			}
			break;
		case OPT_TYPE_ACCLIST:
			if (value != NULL && strcmp(value, "*") == 0) {
				sa_free_attr_string(value);
				value = NULL;
			} else {
				if (value != NULL)
					len += 1 + strlen(value);
			}
			break;
		case OPT_TYPE_LOGTAG:
			if (value != NULL && strlen(value) == 0) {
				sa_free_attr_string(value);
				value = NULL;
			} else {
				if (value != NULL)
					len += 1 + strlen(value);
			}
			break;
		default:
			if (value != NULL)
				len += 1 + strlen(value);
			break;
		}
		while (buffsize <= (curlen + len)) {
			/* need more room */
			buffsize += incr;
			buff = realloc(buff, buffsize);
			if (buff == NULL) {
				/* realloc failed so free everything */
				if (*rbuff != NULL)
					free(*rbuff);
			}
			*rbuff = buff;
			*rbuffsize = buffsize;
			if (buff == NULL)
				goto skip;

		}

		if (buff == NULL)
			goto skip;

		if (value == NULL) {
			(void) snprintf(buff + curlen, buffsize - curlen,
			    "%s%s", sep ? "," : "", name);
		} else {
			(void) snprintf(buff + curlen, buffsize - curlen,
			    "%s%s=%s", sep ? "," : "",
			    name, value != NULL ? value : "");
		}
		printed = B_TRUE;
	}
skip:
	if (name != NULL)
		sa_free_attr_string(name);
	if (value != NULL)
		sa_free_attr_string(value);
	return (printed);
}

/*
 * nfs_format_options(group, hier)
 *
 * format all the options on the group into an old-style option
 * string. If hier is non-zero, walk up the tree to get inherited
 * options.
 */

static char *
nfs_format_options(sa_group_t group, int hier)
{
	sa_optionset_t options = NULL;
	sa_optionset_t secoptions = NULL;
	sa_property_t prop, secprop;
	sa_security_t security = NULL;
	char *buff;
	size_t buffsize;
	char *sectype = NULL;
	int sep = 0;


	buff = malloc(OPT_CHUNK);
	if (buff == NULL) {
		return (NULL);
	}

	buff[0] = '\0';
	buffsize = OPT_CHUNK;

	/*
	 * We may have a an optionset relative to this item. format
	 * these if we find them and then add any security definitions.
	 */

	options = sa_get_derived_optionset(group, "nfs", hier);

	/*
	 * do the default set first but skip any option that is also
	 * in the protocol specific optionset.
	 */
	if (options != NULL) {
		for (prop = sa_get_property(options, NULL);
		    prop != NULL; prop = sa_get_next_property(prop)) {
			/*
			 * use this one since we skipped any
			 * of these that were also in
			 * optdefault
			 */
			if (nfs_sprint_option(&buff, &buffsize, OPT_CHUNK,
			    prop, sep))
				sep = 1;
			if (buff == NULL) {
				/*
				 * buff could become NULL if there
				 * isn't enough memory for
				 * nfs_sprint_option to realloc()
				 * as necessary. We can't really
				 * do anything about it at this
				 * point so we return NULL.  The
				 * caller should handle the
				 * failure.
				 */
				if (options != NULL)
					sa_free_derived_optionset(
					    options);
				return (buff);
			}
		}
	}
	secoptions = (sa_optionset_t)sa_get_all_security_types(group,
	    "nfs", hier);
	if (secoptions != NULL) {
		for (secprop = sa_get_property(secoptions, NULL);
		    secprop != NULL;
		    secprop = sa_get_next_property(secprop)) {
			sectype = sa_get_property_attr(secprop, "type");
			security =
			    (sa_security_t)sa_get_derived_security(
			    group, sectype, "nfs", hier);
			if (security != NULL) {
				if (sectype != NULL) {
					prop = sa_create_property(
					    "sec", sectype);
					if (prop == NULL)
						goto err;
					if (nfs_sprint_option(&buff,
					    &buffsize, OPT_CHUNK, prop, sep))
						sep = 1;
					(void) sa_remove_property(prop);
					if (buff == NULL)
						goto err;
				}
				for (prop = sa_get_property(security,
				    NULL); prop != NULL;
				    prop = sa_get_next_property(prop)) {
					if (nfs_sprint_option(&buff,
					    &buffsize, OPT_CHUNK, prop, sep))
						sep = 1;
					if (buff == NULL)
						goto err;
				}
				sa_free_derived_optionset(security);
			}
			if (sectype != NULL)
				sa_free_attr_string(sectype);
		}
		sa_free_derived_optionset(secoptions);
	}

	if (options != NULL)
		sa_free_derived_optionset(options);
	return (buff);

err:
	/*
	 * If we couldn't allocate memory for option printing, we need
	 * to break out of the nested loops, cleanup and return NULL.
	 */
	if (secoptions != NULL)
		sa_free_derived_optionset(secoptions);
	if (security != NULL)
		sa_free_derived_optionset(security);
	if (sectype != NULL)
		sa_free_attr_string(sectype);
	if (options != NULL)
		sa_free_derived_optionset(options);
	return (buff);
}

/*
 * Append an entry to the nfslogtab file
 */
static int
nfslogtab_add(dir, buffer, tag)
	char *dir, *buffer, *tag;
{
	FILE *f;
	struct logtab_ent lep;
	int error = 0;

	/*
	 * Open the file for update and create it if necessary.
	 * This may leave the I/O offset at the end of the file,
	 * so rewind back to the beginning of the file.
	 */
	f = fopen(NFSLOGTAB, "a+");
	if (f == NULL) {
		error = errno;
		goto out;
	}
	rewind(f);

	if (lockf(fileno(f), F_LOCK, 0L) < 0) {
		(void) fprintf(stderr, dgettext(TEXT_DOMAIN,
		    "share complete, however failed to lock %s "
		    "for update: %s\n"), NFSLOGTAB, strerror(errno));
		error = -1;
		goto out;
	}

	if (logtab_deactivate_after_boot(f) == -1) {
		(void) fprintf(stderr, dgettext(TEXT_DOMAIN,
		    "share complete, however could not deactivate "
		    "entries in %s\n"), NFSLOGTAB);
		error = -1;
		goto out;
	}

	/*
	 * Remove entries matching buffer and sharepoint since we're
	 * going to replace it with perhaps an entry with a new tag.
	 */
	if (logtab_rement(f, buffer, dir, NULL, -1)) {
		(void) fprintf(stderr, dgettext(TEXT_DOMAIN,
		    "share complete, however could not remove matching "
		    "entries in %s\n"), NFSLOGTAB);
		error = -1;
		goto out;
	}

	/*
	 * Deactivate all active entries matching this sharepoint
	 */
	if (logtab_deactivate(f, NULL, dir, NULL)) {
		(void) fprintf(stderr, dgettext(TEXT_DOMAIN,
		    "share complete, however could not deactivate matching "
		    "entries in %s\n"), NFSLOGTAB);
		error = -1;
		goto out;
	}

	lep.le_buffer = buffer;
	lep.le_path = dir;
	lep.le_tag = tag;
	lep.le_state = LES_ACTIVE;

	/*
	 * Add new sharepoint / buffer location to nfslogtab
	 */
	if (logtab_putent(f, &lep) < 0) {
		(void) fprintf(stderr, dgettext(TEXT_DOMAIN,
		    "share complete, however could not add %s to %s\n"),
		    dir, NFSLOGTAB);
		error = -1;
	}

out:
	if (f != NULL)
		(void) fclose(f);
	return (error);
}

/*
 * Deactivate an entry from the nfslogtab file
 */
static int
nfslogtab_deactivate(path)
	char *path;
{
	FILE *f;
	int error = 0;

	f = fopen(NFSLOGTAB, "r+");
	if (f == NULL) {
		error = errno;
		goto out;
	}
	if (lockf(fileno(f), F_LOCK, 0L) < 0) {
		error = errno;
		(void)  fprintf(stderr, dgettext(TEXT_DOMAIN,
		    "share complete, however could not lock %s for "
		    "update: %s\n"), NFSLOGTAB, strerror(error));
		goto out;
	}
	if (logtab_deactivate(f, NULL, path, NULL) == -1) {
		error = -1;
		(void) fprintf(stderr,
		    dgettext(TEXT_DOMAIN,
		    "share complete, however could not "
		    "deactivate %s in %s\n"), path, NFSLOGTAB);
		goto out;
	}

out:	if (f != NULL)
		(void) fclose(f);

	return (error);
}

/*
 * check_public(group, skipshare)
 *
 * Check the group for any shares that have the public property
 * enabled. We skip "skipshare" since that is the one we are
 * working with. This is a separate function to make handling
 * subgroups simpler. Returns true if there is a share with public.
 */
static int
check_public(sa_group_t group, sa_share_t skipshare)
{
	int exists = B_FALSE;
	sa_share_t share;
	sa_optionset_t opt;
	sa_property_t prop;
	char *shared;

	for (share = sa_get_share(group, NULL); share != NULL;
	    share = sa_get_next_share(share)) {
		if (share == skipshare)
			continue;

		opt = sa_get_optionset(share, "nfs");
		if (opt == NULL)
			continue;
		prop = sa_get_property(opt, "public");
		if (prop == NULL)
			continue;
		shared = sa_get_share_attr(share, "shared");
		if (shared != NULL) {
			exists = strcmp(shared, "true") == 0;
			sa_free_attr_string(shared);
			if (exists == B_TRUE)
				break;
		}
	}

	return (exists);
}

/*
 * public_exists(handle, skipshare)
 *
 * check to see if public option is set on any other share than the
 * one specified. Need to check zfs sub-groups as well as the top
 * level groups.
 */
static int
public_exists(sa_handle_t handle, sa_share_t skipshare)
{
	sa_group_t group = NULL;

	/*
	 * If we don't have a handle, we can only do syntax check. We
	 * can't check against other shares so we assume OK and will
	 * catch the problem only when we actually try to apply it.
	 */
	if (handle == NULL)
		return (SA_OK);

	if (skipshare != NULL) {
		group = sa_get_parent_group(skipshare);
		if (group == NULL)
			return (SA_NO_SUCH_GROUP);
	}

	for (group = sa_get_group(handle, NULL); group != NULL;
	    group = sa_get_next_group(group)) {
		/* Walk any ZFS subgroups as well as all standard groups */
		if (sa_group_is_zfs(group)) {
			sa_group_t subgroup;
			for (subgroup = sa_get_sub_group(group);
			    subgroup != NULL;
			    subgroup = sa_get_next_group(subgroup)) {
				if (check_public(subgroup, skipshare))
					return (B_TRUE);
			}
		} else {
			if (check_public(group, skipshare))
				return (B_TRUE);
		}
	}
	return (B_FALSE);
}

/*
 * sa_enable_share at the protocol level, enable_share must tell the
 * implementation that it is to enable the share. This entails
 * converting the path and options into the appropriate ioctl
 * calls. It is assumed that all error checking of paths, etc. were
 * done earlier.
 */
static int
nfs_enable_share(sa_share_t share)
{
	struct exportdata export;
	sa_optionset_t secoptlist;
	struct secinfo *sp;
	int num_secinfo;
	sa_optionset_t opt;
	sa_security_t sec;
	sa_property_t prop;
	char *path;
	int err = SA_OK;
	int i;
	int iszfs;
	sa_handle_t handle;

	/* Don't drop core if the NFS module isn't loaded. */
	(void) signal(SIGSYS, SIG_IGN);

	/* get the path since it is important in several places */
	path = sa_get_share_attr(share, "path");
	if (path == NULL)
		return (SA_NO_SUCH_PATH);

	iszfs = sa_path_is_zfs(path);
	/*
	 * find the optionsets and security sets.  There may not be
	 * any or there could be one or two for each of optionset and
	 * security may have multiple, one per security type per
	 * protocol type.
	 */
	opt = sa_get_derived_optionset(share, "nfs", 1);
	secoptlist = (sa_optionset_t)sa_get_all_security_types(share, "nfs", 1);
	if (secoptlist != NULL)
		num_secinfo = MAX(1, count_security(secoptlist));
	else
		num_secinfo = 1;

	/*
	 * walk through the options and fill in the structure
	 * appropriately.
	 */

	(void) memset(&export, '\0', sizeof (export));

	/*
	 * do non-security options first since there is only one after
	 * the derived group is constructed.
	 */
	export.ex_version = EX_CURRENT_VERSION;
	export.ex_anon = UID_NOBODY; /* this is our default value */
	export.ex_index = NULL;
	export.ex_path = path;
	export.ex_pathlen = strlen(path) + 1;

	if (opt != NULL)
		err = fill_export_from_optionset(&export, opt);

	/*
	 * check to see if "public" is set. If it is, then make sure
	 * no other share has it set. If it is already used, fail.
	 */

	handle = sa_find_group_handle((sa_group_t)share);
	if (export.ex_flags & EX_PUBLIC && public_exists(handle, share)) {
		(void) printf(dgettext(TEXT_DOMAIN,
		    "NFS: Cannot share more than one file "
		    "system with 'public' property\n"));
		err = SA_NOT_ALLOWED;
		goto out;
	}

	sp = calloc(num_secinfo, sizeof (struct secinfo));
	if (sp == NULL) {
		err = SA_NO_MEMORY;
		(void) printf(dgettext(TEXT_DOMAIN,
		    "NFS: NFS: no memory for security\n"));
		goto out;
	}
	export.ex_secinfo = sp;
	/* get default secinfo */
	export.ex_seccnt = num_secinfo;
	/*
	 * since we must have one security option defined, we
	 * init to the default and then override as we find
	 * defined security options. This handles the case
	 * where we have no defined options but we need to set
	 * up one.
	 */
	sp[0].s_window = DEF_WIN;
	sp[0].s_rootnames = NULL;
	/* setup a default in case no properties defined */
	if (nfs_getseconfig_default(&sp[0].s_secinfo)) {
		(void) printf(dgettext(TEXT_DOMAIN,
		    "NFS: nfs_getseconfig_default: failed to "
		    "get default security mode\n"));
		err = SA_CONFIG_ERR;
	}
	if (secoptlist != NULL) {
		for (i = 0, prop = sa_get_property(secoptlist, NULL);
		    prop != NULL && i < num_secinfo;
		    prop = sa_get_next_property(prop), i++) {
			char *sectype;
			sectype = sa_get_property_attr(prop, "type");
			/*
			 * if sectype is NULL, we probably
			 * have a memory problem and can't get
			 * the correct values. Rather than
			 * exporting with incorrect security,
			 * don't share it.
			 */
			if (sectype == NULL) {
				err = SA_NO_MEMORY;
				(void) printf(dgettext(TEXT_DOMAIN,
				    "NFS: Cannot share %s: "
				    "no memory\n"), path);
				goto out;
			}
			sec = (sa_security_t)sa_get_derived_security(
			    share, sectype, "nfs", 1);
			sp[i].s_window = DEF_WIN;
			sp[i].s_rootcnt = 0;
			sp[i].s_rootnames = NULL;
			(void) fill_security_from_secopts(&sp[i], sec);
			if (sec != NULL)
				sa_free_derived_security(sec);
			if (sectype != NULL)
				sa_free_attr_string(sectype);
		}
	}
	/*
	 * when we get here, we can do the exportfs system call and
	 * initiate things. We probably want to enable the nfs.server
	 * service first if it isn't running within SMF.
	 */
	/* check nfs.server status and start if needed */
	/* now add the share to the internal tables */
	printarg(path, &export);
	/*
	 * call the exportfs system call which is implemented
	 * via the nfssys() call as the EXPORTFS subfunction.
	 */
	if (iszfs) {
		struct exportfs_args ea;
		share_t sh;
		char *str;
		priv_set_t *priv_effective;
		int privileged;

		/*
		 * If we aren't a privileged user
		 * and NFS server service isn't running
		 * then print out an error message
		 * and return EPERM
		 */

		priv_effective = priv_allocset();
		(void) getppriv(PRIV_EFFECTIVE, priv_effective);

		privileged = (priv_isfullset(priv_effective) == B_TRUE);
		priv_freeset(priv_effective);

		if (!privileged &&
		    (str = smf_get_state(NFS_SERVER_SVC)) != NULL) {
			err = 0;
			if (strcmp(str, SCF_STATE_STRING_ONLINE) != 0) {
				(void) printf(dgettext(TEXT_DOMAIN,
				    "NFS: Cannot share remote "
				    "filesystem: %s\n"), path);
				(void) printf(dgettext(TEXT_DOMAIN,
				    "NFS: Service needs to be enabled "
				    "by a privileged user\n"));
				err = SA_SYSTEM_ERR;
				errno = EPERM;
			}
			free(str);
		}

		if (err == 0) {
			ea.dname = path;
			ea.uex = &export;

			(void) sa_sharetab_fill_zfs(share, &sh, "nfs");
			err = sa_share_zfs(share, NULL, path, &sh,
			    &ea, ZFS_SHARE_NFS);
			if (err != SA_OK) {
				errno = err;
				err = -1;
			}
			sa_emptyshare(&sh);
		}
	} else {
		err = exportfs(path, &export);
	}

	if (err < 0) {
		err = SA_SYSTEM_ERR;
		switch (errno) {
		case EREMOTE:
			(void) printf(dgettext(TEXT_DOMAIN,
			    "NFS: Cannot share filesystems "
			    "in non-global zones: %s\n"), path);
			err = SA_NOT_SUPPORTED;
			break;
		case EPERM:
			if (getzoneid() != GLOBAL_ZONEID) {
				(void) printf(dgettext(TEXT_DOMAIN,
				    "NFS: Cannot share file systems "
				    "in non-global zones: %s\n"), path);
				err = SA_NOT_SUPPORTED;
				break;
			}
			err = SA_NO_PERMISSION;
			break;
		case EEXIST:
			err = SA_SHARE_EXISTS;
			break;
		default:
			break;
		}
	} else {
		/* update sharetab with an add/modify */
		if (!iszfs) {
			(void) sa_update_sharetab(share, "nfs");
		}
	}

	if (err == SA_OK) {
		/*
		 * enable services as needed. This should probably be
		 * done elsewhere in order to minimize the calls to
		 * check services.
		 */
		/*
		 * check to see if logging and other services need to
		 * be triggered, but only if there wasn't an
		 * error. This is probably where sharetab should be
		 * updated with the NFS specific entry.
		 */
		if (export.ex_flags & EX_LOG) {
			/* enable logging */
			if (nfslogtab_add(path, export.ex_log_buffer,
			    export.ex_tag) != 0) {
				(void) fprintf(stderr, dgettext(TEXT_DOMAIN,
				    "Could not enable logging for %s\n"),
				    path);
			}
			_check_services(service_list_logging);
		} else {
			/*
			 * don't have logging so remove it from file. It might
			 * not be thre, but that doesn't matter.
			 */
			(void) nfslogtab_deactivate(path);
			_check_services(service_list_default);
		}
	}

out:
	if (path != NULL)
		free(path);

	cleanup_export(&export);
	if (opt != NULL)
		sa_free_derived_optionset(opt);
	if (secoptlist != NULL)
		(void) sa_destroy_optionset(secoptlist);
	return (err);
}

/*
 * nfs_disable_share(share, path)
 *
 * Unshare the specified share. Note that "path" is the same path as
 * what is in the "share" object. It is passed in to avoid an
 * additional lookup. A missing "path" value makes this a no-op
 * function.
 */
static int
nfs_disable_share(sa_share_t share, char *path)
{
	int err;
	int ret = SA_OK;
	int iszfs;
	sa_group_t parent;
	sa_handle_t handle;

	if (path == NULL)
		return (ret);

	/*
	 * If the share is in a ZFS group we need to handle it
	 * differently.  Just being on a ZFS file system isn't
	 * enough since we may be in a legacy share case.
	 */
	parent = sa_get_parent_group(share);
	iszfs = sa_group_is_zfs(parent);
	if (iszfs) {
		struct exportfs_args ea;
		share_t sh = { 0 };
		ea.dname = path;
		ea.uex = NULL;
		sh.sh_path = path;
		sh.sh_fstype = "nfs";

		err = sa_share_zfs(share, NULL, path, &sh,
		    &ea, ZFS_UNSHARE_NFS);
		if (err != SA_OK) {
			errno = err;
			err = -1;
		}
	} else {
		err = exportfs(path, NULL);
	}
	if (err < 0) {
		/*
		 * TBD: only an error in some
		 * cases - need better analysis
		 */
		switch (errno) {
		case EPERM:
		case EACCES:
			ret = SA_NO_PERMISSION;
			if (getzoneid() != GLOBAL_ZONEID) {
				ret = SA_NOT_SUPPORTED;
			}
			break;
		case EINVAL:
		case ENOENT:
			ret = SA_NO_SUCH_PATH;
			break;
		default:
			ret = SA_SYSTEM_ERR;
			break;
		}
	}
	if (ret == SA_OK || ret == SA_NO_SUCH_PATH) {
		handle = sa_find_group_handle((sa_group_t)share);
		if (!iszfs)
			(void) sa_delete_sharetab(handle, path, "nfs");
		/* just in case it was logged */
		(void) nfslogtab_deactivate(path);
	}
	return (ret);
}

static int
check_user(char *value)
{
	int ret = SA_OK;

	if (!is_a_number(value)) {
		struct passwd *pw;
		/*
		 * in this case it would have to be a
		 * user name
		 */
		pw = getpwnam(value);
		if (pw == NULL)
			ret = SA_BAD_VALUE;
		endpwent();
	} else {
		uint64_t intval;
		intval = strtoull(value, NULL, 0);
		if (intval > UID_MAX && intval != -1)
			ret = SA_BAD_VALUE;
	}

	return (ret);
}

static int
check_group(char *value)
{
	int ret = SA_OK;

	if (!is_a_number(value)) {
		struct group *gr;
		/*
		 * in this case it would have to be a
		 * group name
		 */
		gr = getgrnam(value);
		if (gr == NULL)
			ret = SA_BAD_VALUE;
		endgrent();
	} else {
		uint64_t intval;
		intval = strtoull(value, NULL, 0);
		if (intval > UID_MAX && intval != -1)
			ret = SA_BAD_VALUE;
	}

	return (ret);
}

/*
 * check_rorwnone(v1, v2, v3)
 *
 * check ro vs rw vs none values.  Over time this may get beefed up.
 * for now it just does simple checks. v1 is never NULL but v2 or v3
 * could be.
 */

static int
check_rorwnone(char *v1, char *v2, char *v3)
{
	int ret = SA_OK;
	if (v2 != NULL && strcmp(v1, v2) == 0)
		ret = SA_VALUE_CONFLICT;
	else if (v3 != NULL && strcmp(v1, v3) == 0)
		ret = SA_VALUE_CONFLICT;

	return (ret);
}

/*
 * nfs_validate_property(handle, property, parent)
 *
 * Check that the property has a legitimate value for its type.
 */

static int
nfs_validate_property(sa_handle_t handle, sa_property_t property,
    sa_optionset_t parent)
{
	int ret = SA_OK;
	char *propname;
	char *other1;
	char *other2;
	int optindex;
	nfsl_config_t *configlist;
	sa_group_t parent_group;
	char *value;

	propname = sa_get_property_attr(property, "type");

	if ((optindex = findopt(propname)) < 0)
		ret = SA_NO_SUCH_PROP;

	/* need to validate value range here as well */

	if (ret == SA_OK) {
		parent_group = sa_get_parent_group((sa_share_t)parent);
		if (optdefs[optindex].share && parent_group != NULL &&
		    !sa_is_share(parent_group))
			ret = SA_PROP_SHARE_ONLY;
	}
	if (ret == SA_OK) {
		if (optdefs[optindex].index == OPT_PUBLIC) {
			/*
			 * Public is special in that only one instance can
			 * be in the repository at the same time.
			 */
			if (public_exists(handle, parent_group)) {
				sa_free_attr_string(propname);
				return (SA_VALUE_CONFLICT);
			}
		}
		value = sa_get_property_attr(property, "value");
		if (value != NULL) {
			/* first basic type checking */
			switch (optdefs[optindex].type) {

			case OPT_TYPE_NUMBER:
				/* check that the value is all digits */
				if (!is_a_number(value))
					ret = SA_BAD_VALUE;
				break;

			case OPT_TYPE_BOOLEAN:
				if (strlen(value) == 0 ||
				    strcasecmp(value, "true") == 0 ||
				    strcmp(value, "1") == 0 ||
				    strcasecmp(value, "false") == 0 ||
				    strcmp(value, "0") == 0) {
					ret = SA_OK;
				} else {
					ret = SA_BAD_VALUE;
				}
				break;

			case OPT_TYPE_USER:
				ret = check_user(value);
				break;

			case OPT_TYPE_FILE:
				if (strcmp(value, "..") == 0 ||
				    strchr(value, '/') != NULL) {
					ret = SA_BAD_VALUE;
				}
				break;

			case OPT_TYPE_ACCLIST: {
				sa_property_t oprop1;
				sa_property_t oprop2;
				char *ovalue1 = NULL;
				char *ovalue2 = NULL;

				if (parent == NULL)
					break;
				/*
				 * access list handling. Should eventually
				 * validate that all the values make sense.
				 * Also, ro and rw may have cross value
				 * conflicts.
				 */
				if (strcmp(propname, SHOPT_RO) == 0) {
					other1 = SHOPT_RW;
					other2 = SHOPT_NONE;
				} else if (strcmp(propname, SHOPT_RW) == 0) {
					other1 = SHOPT_RO;
					other2 = SHOPT_NONE;
				} else if (strcmp(propname, SHOPT_NONE) == 0) {
					other1 = SHOPT_RO;
					other2 = SHOPT_RW;
				} else {
					other1 = NULL;
					other2 = NULL;
				}
				if (other1 == NULL && other2 == NULL)
					break;

				/* compare rw(ro) with ro(rw) */

				oprop1 = sa_get_property(parent, other1);
				oprop2 = sa_get_property(parent, other2);
				if (oprop1 == NULL && oprop2 == NULL)
					break;
				/*
				 * Only potential confusion if other1
				 * or other2 exists. Check the values
				 * and run the check if there is a
				 * value other than the one we are
				 * explicitly looking at.
				 */
				ovalue1 = sa_get_property_attr(oprop1, "value");
				ovalue2 = sa_get_property_attr(oprop2, "value");
				if (ovalue1 != NULL || ovalue2 != NULL)
					ret = check_rorwnone(value, ovalue1,
					    ovalue2);

				if (ovalue1 != NULL)
					sa_free_attr_string(ovalue1);
				if (ovalue2 != NULL)
					sa_free_attr_string(ovalue2);
				break;
			}

			case OPT_TYPE_LOGTAG:
				if (nfsl_getconfig_list(&configlist) == 0) {
					int error;
					if (value == NULL ||
					    strlen(value) == 0) {
						if (value != NULL)
							sa_free_attr_string(
							    value);
						value = strdup("global");
					}
					if (value != NULL &&
					    nfsl_findconfig(configlist, value,
					    &error) == NULL) {
						ret = SA_BAD_VALUE;
					}
					/* Must always free when done */
					nfsl_freeconfig_list(&configlist);
				} else {
					ret = SA_CONFIG_ERR;
				}
				break;

			case OPT_TYPE_STRING:
				/* whatever is here should be ok */
				break;

			case OPT_TYPE_SECURITY:
				/*
				 * The "sec" property isn't used in the
				 * non-legacy parts of sharemgr. We need to
				 * reject it here. For legacy, it is pulled
				 * out well before we get here.
				 */
				ret = SA_NO_SUCH_PROP;
				break;

			case OPT_TYPE_MAPPING: {
				char *p;
				char *n;
				char *c;
				int (*f)(char *);

				sa_security_t security;

				/*
				 * mapping is only supported for sec=sys
				 */
				ret = SA_CONFIG_ERR;
				if (parent_group == NULL)
					break;

				for (security = sa_get_security(parent_group,
				    NULL, NULL); security != NULL;
				    security = sa_get_next_security(security)) {
					char *type;
					char *sectype;

					type = sa_get_security_attr(security,
					    "type");
					if (type == NULL)
						continue;

					if (strcmp(type, "nfs") != 0) {
						sa_free_attr_string(type);
						continue;
					}
					sa_free_attr_string(type);

					sectype = sa_get_security_attr(security,
					    "sectype");
					if (sectype == NULL)
						continue;

					if (strcmp(sectype, "sys") != 0) {
						sa_free_attr_string(sectype);
						ret = SA_CONFIG_ERR;
						break;
					}
					sa_free_attr_string(sectype);
					ret = SA_OK;
				}

				if (ret != SA_OK)
					break;

				assert(optindex == OPT_UIDMAP ||
				    optindex == OPT_GIDMAP);
				f = optindex == OPT_UIDMAP ? check_user :
				    check_group;


				p = strdup(value);
				if (p == NULL)
					ret = SA_BAD_VALUE;

				for (c = p; ret == SA_OK && c != NULL; c = n) {
					char *s;
					char *t;

					n = strchr(c, '~');
					if (n != NULL)
						*n++ = '\0';

					s = strchr(c, ':');
					if (s != NULL) {
						*s++ = '\0';
						t = strchr(s, ':');
						if (t != NULL)
							*t = '\0';
					}

					if (s == NULL || t == NULL)
						ret = SA_BAD_VALUE;

					if (ret == SA_OK && *c != '\0' &&
					    strcmp(c, "*") != 0)
						ret = f(c);

					if (ret == SA_OK && *s != '\0' &&
					    strcmp(s, "-1") != 0)
						ret = f(s);
				}

				free(p);

				break;
			}

			default:
				break;
			}

			if (value != NULL)
				sa_free_attr_string(value);

			if (ret == SA_OK && optdefs[optindex].check != NULL) {
				/* do the property specific check */
				ret = optdefs[optindex].check(handle, property);
			}
		}
	}

	if (propname != NULL)
		sa_free_attr_string(propname);
	return (ret);
}

/*
 * Protocol management functions
 *
 * Properties defined in the default files are defined in
 * proto_option_defs for parsing and validation. If "other" and
 * "compare" are set, then the value for this property should be
 * compared against the property specified in "other" using the
 * "compare" check (either <= or >=) in order to ensure that the
 * values are in the correct range.  E.g. setting server_versmin
 * higher than server_versmax should not be allowed.
 */

struct proto_option_defs {
	char *tag;
	char *name;	/* display name -- remove protocol identifier */
	int index;
	int type;
	union {
	    int intval;
	    char *string;
	} defvalue;
	uint32_t svcs;
	int32_t minval;
	int32_t maxval;
	char *other;
	int compare;
#define	OPT_CMP_GE	0
#define	OPT_CMP_LE	1
	int (*check)(char *);
} proto_options[] = {
#define	PROTO_OPT_NFSD_SERVERS			0
	{"nfsd_servers",
	    "servers", PROTO_OPT_NFSD_SERVERS, OPT_TYPE_NUMBER, 16, SVC_NFSD,
	    1, INT32_MAX},
#define	PROTO_OPT_LOCKD_LISTEN_BACKLOG		1
	{"lockd_listen_backlog",
	    "lockd_listen_backlog", PROTO_OPT_LOCKD_LISTEN_BACKLOG,
	    OPT_TYPE_NUMBER, 32, SVC_LOCKD, 32, INT32_MAX},
#define	PROTO_OPT_LOCKD_SERVERS			2
	{"lockd_servers",
	    "lockd_servers", PROTO_OPT_LOCKD_SERVERS, OPT_TYPE_NUMBER, 20,
	    SVC_LOCKD, 1, INT32_MAX},
#define	PROTO_OPT_LOCKD_RETRANSMIT_TIMEOUT	3
	{"lockd_retransmit_timeout",
	    "lockd_retransmit_timeout", PROTO_OPT_LOCKD_RETRANSMIT_TIMEOUT,
	    OPT_TYPE_NUMBER, 5, SVC_LOCKD, 0, INT32_MAX},
#define	PROTO_OPT_GRACE_PERIOD			4
	{"grace_period",
	    "grace_period", PROTO_OPT_GRACE_PERIOD, OPT_TYPE_NUMBER, 90,
	    SVC_LOCKD, 0, INT32_MAX},
#define	PROTO_OPT_NFS_SERVER_VERSMIN		5
	{"nfs_server_versmin",
	    "server_versmin", PROTO_OPT_NFS_SERVER_VERSMIN, OPT_TYPE_NUMBER,
	    (int)NFS_VERSMIN_DEFAULT, SVC_NFSD|SVC_MOUNTD, NFS_VERSMIN,
	    NFS_VERSMAX, "server_versmax", OPT_CMP_LE},
#define	PROTO_OPT_NFS_SERVER_VERSMAX		6
	{"nfs_server_versmax",
	    "server_versmax", PROTO_OPT_NFS_SERVER_VERSMAX, OPT_TYPE_NUMBER,
	    (int)NFS_VERSMAX_DEFAULT, SVC_NFSD|SVC_MOUNTD, NFS_VERSMIN,
	    NFS_VERSMAX, "server_versmin", OPT_CMP_GE},
#define	PROTO_OPT_NFS_CLIENT_VERSMIN		7
	{"nfs_client_versmin",
	    "client_versmin", PROTO_OPT_NFS_CLIENT_VERSMIN, OPT_TYPE_NUMBER,
	    (int)NFS_VERSMIN_DEFAULT, SVC_CLIENT, NFS_VERSMIN, NFS_VERSMAX,
	    "client_versmax", OPT_CMP_LE},
#define	PROTO_OPT_NFS_CLIENT_VERSMAX		8
	{"nfs_client_versmax",
	    "client_versmax", PROTO_OPT_NFS_CLIENT_VERSMAX, OPT_TYPE_NUMBER,
	    (int)NFS_VERSMAX_DEFAULT, SVC_CLIENT, NFS_VERSMIN, NFS_VERSMAX,
	    "client_versmin", OPT_CMP_GE},
#define	PROTO_OPT_NFS_SERVER_DELEGATION		9
	{"nfs_server_delegation",
	    "server_delegation", PROTO_OPT_NFS_SERVER_DELEGATION,
	    OPT_TYPE_ONOFF, NFS_SERVER_DELEGATION_DEFAULT, SVC_NFSD, 0, 0},
#define	PROTO_OPT_NFSMAPID_DOMAIN		10
	{"nfsmapid_domain",
	    "nfsmapid_domain", PROTO_OPT_NFSMAPID_DOMAIN, OPT_TYPE_DOMAIN,
	    NULL, SVC_NFSMAPID, 0, 0},
#define	PROTO_OPT_NFSD_MAX_CONNECTIONS		11
	{"nfsd_max_connections",
	    "max_connections", PROTO_OPT_NFSD_MAX_CONNECTIONS,
	    OPT_TYPE_NUMBER, -1, SVC_NFSD, -1, INT32_MAX},
#define	PROTO_OPT_NFSD_PROTOCOL			12
	{"nfsd_protocol",
	    "protocol", PROTO_OPT_NFSD_PROTOCOL, OPT_TYPE_PROTOCOL, 0,
	    SVC_NFSD, 0, 0},
#define	PROTO_OPT_NFSD_LISTEN_BACKLOG		13
	{"nfsd_listen_backlog",
	    "listen_backlog", PROTO_OPT_NFSD_LISTEN_BACKLOG,
	    OPT_TYPE_NUMBER, 0, SVC_NFSD, 0, INT32_MAX},
#define	PROTO_OPT_NFSD_DEVICE			14
	{"nfsd_device",
	    "device", PROTO_OPT_NFSD_DEVICE,
	    OPT_TYPE_STRING, NULL, SVC_NFSD, 0, 0},
#define	PROTO_OPT_MOUNTD_LISTEN_BACKLOG		15
	{"mountd_listen_backlog",
	    "mountd_listen_backlog", PROTO_OPT_MOUNTD_LISTEN_BACKLOG,
	    OPT_TYPE_NUMBER, 64, SVC_NFSD|SVC_MOUNTD, 1, INT32_MAX},
#define	PROTO_OPT_MOUNTD_MAX_THREADS		16
	{"mountd_max_threads",
	    "mountd_max_threads", PROTO_OPT_MOUNTD_MAX_THREADS,
	    OPT_TYPE_NUMBER, 16, SVC_NFSD|SVC_MOUNTD, 1, INT32_MAX},
	{NULL}
};

/*
 * the protoset holds the defined options so we don't have to read
 * them multiple times
 */
static sa_protocol_properties_t protoset;

static int
findprotoopt(char *name, int whichname)
{
	int i;
	for (i = 0; proto_options[i].tag != NULL; i++) {
		if (whichname == 1) {
			if (strcasecmp(proto_options[i].name, name) == 0)
			return (i);
		} else {
			if (strcasecmp(proto_options[i].tag, name) == 0)
				return (i);
		}
	}
	return (-1);
}

/*
 * fixcaselower(str)
 *
 * convert a string to lower case (inplace).
 */

static void
fixcaselower(char *str)
{
	while (*str) {
		*str = tolower(*str);
		str++;
	}
}

/*
 * skipwhitespace(str)
 *
 * Skip leading white space. It is assumed that it is called with a
 * valid pointer.
 */

static char *
skipwhitespace(char *str)
{
	while (*str && isspace(*str))
		str++;

	return (str);
}

/*
 * extractprop()
 *
 * Extract the property and value out of the line and create the
 * property in the optionset.
 */
static int
extractprop(char *name, char *value)
{
	sa_property_t prop;
	int index;
	int ret = SA_OK;
	/*
	 * Remove any leading
	 * white space.
	 */
	name = skipwhitespace(name);

	index = findprotoopt(name, 1);
	if (index >= 0) {
		fixcaselower(name);
		prop = sa_create_property(proto_options[index].name, value);
		if (prop != NULL)
			ret = sa_add_protocol_property(protoset, prop);
		else
			ret = SA_NO_MEMORY;
	}
	return (ret);
}

scf_type_t
getscftype(int type)
{
	scf_type_t ret;

	switch (type) {
	case OPT_TYPE_NUMBER:
		ret = SCF_TYPE_INTEGER;
	break;
	case OPT_TYPE_BOOLEAN:
		ret = SCF_TYPE_BOOLEAN;
	break;
	default:
		ret = SCF_TYPE_ASTRING;
	}
	return (ret);
}

char *
getsvcname(uint32_t svcs)
{
	char *service;
	switch (svcs) {
		case SVC_LOCKD:
			service = LOCKD;
			break;
		case SVC_STATD:
			service = STATD;
			break;
		case SVC_NFSD:
			service = NFSD;
			break;
		case SVC_CLIENT:
			service = NFS_CLIENT_SVC;
			break;
		case SVC_NFS4CBD:
			service = NFS4CBD;
			break;
		case SVC_NFSMAPID:
			service = NFSMAPID;
			break;
		case SVC_RQUOTAD:
			service = RQUOTAD;
			break;
		case SVC_NFSLOGD:
			service = NFSLOGD;
			break;
		case SVC_REPARSED:
			service = REPARSED;
			break;
		default:
			service = NFSD;
	}
	return (service);
}

/*
 * initprotofromsmf()
 *
 * Read NFS SMF properties and add the defined values to the
 * protoset.  Note that default values are known from the built in
 * table in case SMF doesn't have a definition. Not having
 * SMF properties is OK since we have builtin default
 * values.
 */
static int
initprotofromsmf()
{
	char name[PATH_MAX];
	char value[PATH_MAX];
	int ret = SA_OK, bufsz = 0, i;

	protoset = sa_create_protocol_properties("nfs");
	if (protoset != NULL) {
		for (i = 0; proto_options[i].tag != NULL; i++) {
			scf_type_t ptype;
			char *svc_name;

			bzero(value, PATH_MAX);
			(void) strncpy(name, proto_options[i].name, PATH_MAX);
			/* Replace NULL with the correct instance */
			ptype = getscftype(proto_options[i].type);
			svc_name = getsvcname(proto_options[i].svcs);
			bufsz = PATH_MAX;
			ret = nfs_smf_get_prop(name, value,
			    (char *)DEFAULT_INSTANCE, ptype,
			    svc_name, &bufsz);
			if (ret == SA_OK) {
				ret = extractprop(name, value);
			}
		}
	} else {
		ret = SA_NO_MEMORY;
	}

	return (ret);
}

/*
 * add_defaults()
 *
 * Add the default values for any property not defined
 * in NFS SMF repository.
 * Values are set according to their defined types.
 */

static void
add_defaults()
{
	int i;
	char number[MAXDIGITS];

	for (i = 0; proto_options[i].tag != NULL; i++) {
		sa_property_t prop;
		prop = sa_get_protocol_property(protoset,
		    proto_options[i].name);
		if (prop == NULL) {
			/* add the default value */
			switch (proto_options[i].type) {
			case OPT_TYPE_NUMBER:
				(void) snprintf(number, sizeof (number), "%d",
				    proto_options[i].defvalue.intval);
				prop = sa_create_property(proto_options[i].name,
				    number);
				break;

			case OPT_TYPE_BOOLEAN:
				prop = sa_create_property(proto_options[i].name,
				    proto_options[i].defvalue.intval ?
				    "true" : "false");
				break;

			case OPT_TYPE_ONOFF:
				prop = sa_create_property(proto_options[i].name,
				    proto_options[i].defvalue.intval ?
				    "on" : "off");
				break;

			default:
				/* treat as strings of zero length */
				prop = sa_create_property(proto_options[i].name,
				    "");
				break;
			}
			if (prop != NULL)
				(void) sa_add_protocol_property(protoset, prop);
		}
	}
}

static void
free_protoprops()
{
	if (protoset != NULL) {
		xmlFreeNode(protoset);
		protoset = NULL;
	}
}

/*
 * nfs_init()
 *
 * Initialize the NFS plugin.
 */

static int
nfs_init()
{
	int ret = SA_OK;

	if (sa_plugin_ops.sa_init != nfs_init) {
		(void) printf(dgettext(TEXT_DOMAIN,
		    "NFS plugin not properly initialized\n"));
		return (SA_CONFIG_ERR);
	}

	ret = initprotofromsmf();
	if (ret != SA_OK) {
		/*
		 * This is a workaround.  See the comment in
		 * cmd/fs.d/nfs/lib/smfcfg.c for an explanation.
		 */
		if (getzoneid() == GLOBAL_ZONEID ||
		    ret != SCF_ERROR_NOT_FOUND) {
			(void) printf(dgettext(TEXT_DOMAIN,
			    "NFS plugin problem with SMF repository: %s\n"),
			    sa_errorstr(ret));
		}
		ret = SA_OK;
	}
	add_defaults();

	return (ret);
}

/*
 * nfs_fini()
 *
 * uninitialize the NFS plugin. Want to avoid memory leaks.
 */

static void
nfs_fini()
{
	free_protoprops();
}

/*
 * nfs_get_proto_set()
 *
 * Return an optionset with all the protocol specific properties in
 * it.
 */

static sa_protocol_properties_t
nfs_get_proto_set()
{
	return (protoset);
}

/*
 * service_in_state(service, chkstate)
 *
 * Want to know if the specified service is in the desired state
 * (chkstate) or not. Return true (1) if it is and false (0) if it
 * isn't.
 */
static int
service_in_state(char *service, const char *chkstate)
{
	char *state;
	int ret = B_FALSE;

	state = smf_get_state(service);
	if (state != NULL) {
		/* got the state so get the equality for the return value */
		ret = strcmp(state, chkstate) == 0 ? B_TRUE : B_FALSE;
		free(state);
	}
	return (ret);
}

/*
 * restart_service(svcs)
 *
 * Walk through the bit mask of services that need to be restarted in
 * order to use the new property values. Some properties affect
 * multiple daemons. Should only restart a service if it is currently
 * enabled (online).
 */

static void
restart_service(uint32_t svcs)
{
	uint32_t mask;
	int ret;
	char *service;

	for (mask = 1; svcs != 0; mask <<= 1) {
		switch (svcs & mask) {
		case SVC_LOCKD:
			service = LOCKD;
			break;
		case SVC_STATD:
			service = STATD;
			break;
		case SVC_NFSD:
			service = NFSD;
			break;
		case SVC_MOUNTD:
			service = MOUNTD;
			break;
		case SVC_NFS4CBD:
			service = NFS4CBD;
			break;
		case SVC_NFSMAPID:
			service = NFSMAPID;
			break;
		case SVC_RQUOTAD:
			service = RQUOTAD;
			break;
		case SVC_NFSLOGD:
			service = NFSLOGD;
			break;
		case SVC_REPARSED:
			service = REPARSED;
			break;
		case SVC_CLIENT:
			service = NFS_CLIENT_SVC;
			break;
		default:
			continue;
		}

		/*
		 * Only attempt to restart the service if it is
		 * currently running. In the future, it may be
		 * desirable to use smf_refresh_instance if the NFS
		 * services ever implement the refresh method.
		 */
		if (service_in_state(service, SCF_STATE_STRING_ONLINE)) {
			ret = smf_restart_instance(service);
			/*
			 * There are only a few SMF errors at this point, but
			 * it is also possible that a bad value may have put
			 * the service into maintenance if there wasn't an
			 * SMF level error.
			 */
			if (ret != 0) {
				(void) fprintf(stderr,
				    dgettext(TEXT_DOMAIN,
				    "%s failed to restart: %s\n"),
				    service, scf_strerror(scf_error()));
			} else {
				/*
				 * Check whether it has gone to "maintenance"
				 * mode or not. Maintenance implies something
				 * went wrong.
				 */
				if (service_in_state(service,
				    SCF_STATE_STRING_MAINT)) {
					(void) fprintf(stderr,
					    dgettext(TEXT_DOMAIN,
					    "%s failed to restart\n"),
					    service);
				}
			}
		}
		svcs &= ~mask;
	}
}

/*
 * nfs_minmax_check(name, value)
 *
 * Verify that the value for the property specified by index is valid
 * relative to the opposite value in the case of a min/max variable.
 * Currently, server_minvers/server_maxvers and
 * client_minvers/client_maxvers are the only ones to check.
 */

static int
nfs_minmax_check(int index, int value)
{
	int val;
	char *pval;
	sa_property_t prop;
	sa_optionset_t opts;
	int ret = B_TRUE;

	if (proto_options[index].other != NULL) {
		/* have a property to compare against */
		opts = nfs_get_proto_set();
		prop = sa_get_property(opts, proto_options[index].other);
		/*
		 * If we don't find the property, assume default
		 * values which will work since the max will be at the
		 * max and the min at the min.
		 */
		if (prop != NULL) {
			pval = sa_get_property_attr(prop, "value");
			if (pval != NULL) {
				val = strtoul(pval, NULL, 0);
				if (proto_options[index].compare ==
				    OPT_CMP_LE) {
					ret = value <= val ? B_TRUE : B_FALSE;
				} else if (proto_options[index].compare ==
				    OPT_CMP_GE) {
					ret = value >= val ? B_TRUE : B_FALSE;
				}
				sa_free_attr_string(pval);
			}
		}
	}
	return (ret);
}

/*
 * nfs_validate_proto_prop(index, name, value)
 *
 * Verify that the property specified by name can take the new
 * value. This is a sanity check to prevent bad values getting into
 * the default files. All values need to be checked against what is
 * allowed by their defined type. If a type isn't explicitly defined
 * here, it is treated as a string.
 *
 * Note that OPT_TYPE_NUMBER will additionally check that the value is
 * within the range specified and potentially against another property
 * value as well as specified in the proto_options members other and
 * compare.
 */

static int
nfs_validate_proto_prop(int index, char *name, char *value)
{
	int ret = SA_OK;
	char *cp;
#ifdef lint
	name = name;
#endif
	switch (proto_options[index].type) {
	case OPT_TYPE_NUMBER:
		if (!is_a_number(value))
			ret = SA_BAD_VALUE;
		else {
			int val;
			val = strtoul(value, NULL, 0);
			if (val < proto_options[index].minval ||
			    val > proto_options[index].maxval)
				ret = SA_BAD_VALUE;
			/*
			 * For server_versmin/server_versmax and
			 * client_versmin/client_versmax, the value of the
			 * min(max) should be checked to be correct relative
			 * to the current max(min).
			 */
			if (!nfs_minmax_check(index, val)) {
				ret = SA_BAD_VALUE;
			}
		}
		break;

	case OPT_TYPE_DOMAIN:
		/*
		 * needs to be a qualified domain so will have at
		 * least one period and other characters on either
		 * side of it.  A zero length string is also allowed
		 * and is the way to turn off the override.
		 */
		if (strlen(value) == 0)
			break;
		cp = strchr(value, '.');
		if (cp == NULL || cp == value || strchr(value, '@') != NULL)
			ret = SA_BAD_VALUE;
		break;

	case OPT_TYPE_BOOLEAN:
		if (strlen(value) == 0 ||
		    strcasecmp(value, "true") == 0 ||
		    strcmp(value, "1") == 0 ||
		    strcasecmp(value, "false") == 0 ||
		    strcmp(value, "0") == 0) {
			ret = SA_OK;
		} else {
			ret = SA_BAD_VALUE;
		}
		break;

	case OPT_TYPE_ONOFF:
		if (strcasecmp(value, "on") != 0 &&
		    strcasecmp(value, "off") != 0) {
			ret = SA_BAD_VALUE;
		}
		break;

	case OPT_TYPE_PROTOCOL:
		if (strlen(value) != 0 &&
		    strcasecmp(value, "all") != 0 &&
		    strcasecmp(value, "tcp") != 0 &&
		    strcasecmp(value, "udp") != 0)
			ret = SA_BAD_VALUE;
		break;

	default:
		/* treat as a string */
		break;
	}
	return (ret);
}

/*
 * nfs_set_proto_prop(prop)
 *
 * check that prop is valid.
 */

static int
nfs_set_proto_prop(sa_property_t prop)
{
	int ret = SA_OK;
	char *name;
	char *value;

	name = sa_get_property_attr(prop, "type");
	value = sa_get_property_attr(prop, "value");
	if (name != NULL && value != NULL) {
		scf_type_t sctype;
		char *svc_name;
		char *instance = NULL;
		int index = findprotoopt(name, 1);

		ret = nfs_validate_proto_prop(index, name, value);
		if (ret == SA_OK) {
			sctype = getscftype(proto_options[index].type);
			svc_name = getsvcname(proto_options[index].svcs);
			if (sctype == SCF_TYPE_BOOLEAN) {
				if (value != NULL)
					sa_free_attr_string(value);
				if (string_to_boolean(value) == 0)
					value = strdup("0");
				else
					value = strdup("1");
			}
			ret = nfs_smf_set_prop(name, value, instance, sctype,
			    svc_name);
			if (ret == SA_OK) {
				restart_service(proto_options[index].svcs);
			} else {
				(void) printf(dgettext(TEXT_DOMAIN,
				    "Cannot restart NFS services : %s\n"),
				    sa_errorstr(ret));
			}
		}
	}
	if (name != NULL)
		sa_free_attr_string(name);
	if (value != NULL)
		sa_free_attr_string(value);
	return (ret);
}

/*
 * nfs_get_status()
 *
 * What is the current status of the nfsd? We use the SMF state here.
 * Caller must free the returned value.
 */

static char *
nfs_get_status()
{
	return (smf_get_state(NFSD));
}

/*
 * nfs_space_alias(alias)
 *
 * Lookup the space (security) name. If it is default, convert to the
 * real name.
 */

static char *
nfs_space_alias(char *space)
{
	char *name = space;
	seconfig_t secconf;

	/*
	 * Only the space named "default" is special. If it is used,
	 * the default needs to be looked up and the real name used.
	 * This is normally "sys" but could be changed.  We always
	 * change default to the real name.
	 */
	if (strcmp(space, "default") == 0 &&
	    nfs_getseconfig_default(&secconf) == 0) {
		if (nfs_getseconfig_bynumber(secconf.sc_nfsnum, &secconf) == 0)
			name = secconf.sc_name;
	}
	return (strdup(name));
}

/*
 * nfs_features()
 *
 * Return a mask of the features required.
 */

static uint64_t
nfs_features()
{
	return ((uint64_t)SA_FEATURE_DFSTAB | SA_FEATURE_SERVER);
}
