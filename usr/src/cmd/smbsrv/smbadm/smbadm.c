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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * This module contains smbadm CLI which offers smb configuration
 * functionalities.
 */
#include <errno.h>
#include <err.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <syslog.h>
#include <strings.h>
#include <limits.h>
#include <getopt.h>
#include <libintl.h>
#include <zone.h>
#include <grp.h>
#include <libgen.h>
#include <netinet/in.h>
#include <smbsrv/libsmb.h>

typedef enum {
	HELP_ADD_MEMBER,
	HELP_CREATE,
	HELP_DELETE,
	HELP_DEL_MEMBER,
	HELP_GET,
	HELP_JOIN,
	HELP_LIST,
	HELP_RENAME,
	HELP_SET,
	HELP_SHOW,
	HELP_USER_DISABLE,
	HELP_USER_ENABLE
} smbadm_help_t;

#define	SMBADM_CMDF_USER	0x01
#define	SMBADM_CMDF_GROUP	0x02
#define	SMBADM_CMDF_TYPEMASK	0x0F

#define	SMBADM_ANSBUFSIZ	64

typedef struct smbadm_cmdinfo {
	char *name;
	int (*func)(int, char **);
	smbadm_help_t usage;
	uint32_t flags;
} smbadm_cmdinfo_t;

smbadm_cmdinfo_t *curcmd;
static char *progname;

static void smbadm_usage(boolean_t);
static int smbadm_join_workgroup(const char *);
static int smbadm_join_domain(const char *, const char *);
static boolean_t smbadm_valid_domainname(const char *);
static boolean_t smbadm_valid_username(const char *);
static boolean_t smbadm_valid_workgroup(const char *);
static void smbadm_extract_domain(char *, char **, char **);

static int smbadm_join(int, char **);
static int smbadm_list(int, char **);
static int smbadm_group_create(int, char **);
static int smbadm_group_delete(int, char **);
static int smbadm_group_rename(int, char **);
static int smbadm_group_show(int, char **);
static int smbadm_group_getprop(int, char **);
static int smbadm_group_setprop(int, char **);
static int smbadm_group_addmember(int, char **);
static int smbadm_group_delmember(int, char **);
static int smbadm_user_disable(int, char **);
static int smbadm_user_enable(int, char **);

static smbadm_cmdinfo_t smbadm_cmdtable[] =
{
	{ "add-member",		smbadm_group_addmember,	HELP_ADD_MEMBER,
	SMBADM_CMDF_GROUP },
	{ "create",		smbadm_group_create,	HELP_CREATE,
	SMBADM_CMDF_GROUP },
	{ "delete",		smbadm_group_delete,	HELP_DELETE,
	SMBADM_CMDF_GROUP },
	{ "disable-user",	smbadm_user_disable,	HELP_USER_DISABLE,
	SMBADM_CMDF_USER },
	{ "enable-user",	smbadm_user_enable,	HELP_USER_ENABLE,
	SMBADM_CMDF_USER },
	{ "get",		smbadm_group_getprop,	HELP_GET,
	SMBADM_CMDF_GROUP },
	{ "join",		smbadm_join,		HELP_JOIN,	0 },
	{ "list",		smbadm_list,		HELP_LIST,	0 },
	{ "remove-member",	smbadm_group_delmember,	HELP_DEL_MEMBER,
	SMBADM_CMDF_GROUP },
	{ "rename",		smbadm_group_rename,	HELP_RENAME,
	SMBADM_CMDF_GROUP },
	{ "set",		smbadm_group_setprop,	HELP_SET,
	SMBADM_CMDF_GROUP },
	{ "show",		smbadm_group_show,	HELP_SHOW,
	SMBADM_CMDF_GROUP },
};

#define	SMBADM_NCMD	(sizeof (smbadm_cmdtable) / sizeof (smbadm_cmdtable[0]))

typedef struct smbadm_prop {
	char *p_name;
	char *p_value;
} smbadm_prop_t;

typedef struct smbadm_prop_handle {
	char *p_name;
	char *p_dispvalue;
	int (*p_setfn)(char *, smbadm_prop_t *);
	int (*p_getfn)(char *, smbadm_prop_t *);
	boolean_t (*p_chkfn)(smbadm_prop_t *);
} smbadm_prop_handle_t;

static boolean_t smbadm_prop_validate(smbadm_prop_t *prop, boolean_t chkval);
static int smbadm_prop_parse(char *arg, smbadm_prop_t *prop);
static smbadm_prop_handle_t *smbadm_prop_gethandle(char *pname);

static boolean_t smbadm_chkprop_priv(smbadm_prop_t *prop);
static int smbadm_setprop_tkowner(char *gname, smbadm_prop_t *prop);
static int smbadm_getprop_tkowner(char *gname, smbadm_prop_t *prop);
static int smbadm_setprop_backup(char *gname, smbadm_prop_t *prop);
static int smbadm_getprop_backup(char *gname, smbadm_prop_t *prop);
static int smbadm_setprop_restore(char *gname, smbadm_prop_t *prop);
static int smbadm_getprop_restore(char *gname, smbadm_prop_t *prop);
static int smbadm_setprop_desc(char *gname, smbadm_prop_t *prop);
static int smbadm_getprop_desc(char *gname, smbadm_prop_t *prop);

static smbadm_prop_handle_t smbadm_ptable[] = {
	{"backup",	"on | off", 	smbadm_setprop_backup,
	smbadm_getprop_backup,	smbadm_chkprop_priv 	},
	{"restore",	"on | off",	smbadm_setprop_restore,
	smbadm_getprop_restore,	smbadm_chkprop_priv	},
	{"take-ownership", "on | off",	smbadm_setprop_tkowner,
	smbadm_getprop_tkowner,	smbadm_chkprop_priv	},
	{"description",	"<string>",	smbadm_setprop_desc,
	smbadm_getprop_desc,	NULL			},
};

static int smbadm_init(void);
static void smbadm_fini(void);
static const char *smbadm_pwd_strerror(int error);

/*
 * Number of supported properties
 */
#define	SMBADM_NPROP	(sizeof (smbadm_ptable) / sizeof (smbadm_ptable[0]))

static void
smbadm_cmdusage(FILE *fp, smbadm_cmdinfo_t *cmd)
{
	switch (cmd->usage) {
	case HELP_ADD_MEMBER:
		(void) fprintf(fp,
		    gettext("\t%s -m member [[-m member] ...] group\n"),
		    cmd->name);
		return;

	case HELP_CREATE:
		(void) fprintf(fp, gettext("\t%s [-d description] group\n"),
		    cmd->name);
		return;

	case HELP_DELETE:
		(void) fprintf(fp, gettext("\t%s group\n"), cmd->name);
		return;

	case HELP_USER_DISABLE:
	case HELP_USER_ENABLE:
		(void) fprintf(fp, gettext("\t%s user\n"), cmd->name);
		return;

	case HELP_GET:
		(void) fprintf(fp, gettext("\t%s [[-p property] ...] group\n"),
		    cmd->name);
		return;

	case HELP_JOIN:
		(void) fprintf(fp, gettext("\t%s -u username domain\n"
		    "\t%s -w workgroup\n"), cmd->name, cmd->name);
		return;

	case HELP_LIST:
		(void) fprintf(fp, gettext("\t%s\n"), cmd->name);
		return;

	case HELP_DEL_MEMBER:
		(void) fprintf(fp,
		    gettext("\t%s -m member [[-m member] ...] group\n"),
		    cmd->name);
		return;

	case HELP_RENAME:
		(void) fprintf(fp, gettext("\t%s group new-group\n"),
		    cmd->name);
		return;

	case HELP_SET:
		(void) fprintf(fp, gettext("\t%s -p property=value "
		    "[[-p property=value] ...] group\n"), cmd->name);
		return;

	case HELP_SHOW:
		(void) fprintf(fp, gettext("\t%s [-m] [-p] [group]\n"),
		    cmd->name);
		return;

	default:
		break;
	}

	abort();
	/* NOTREACHED */
}

static void
smbadm_usage(boolean_t requested)
{
	FILE *fp = requested ? stdout : stderr;
	boolean_t show_props = B_FALSE;
	int i;

	if (curcmd == NULL) {
		(void) fprintf(fp,
		    gettext("usage: %s [-h | <command> [options]]\n"),
		    progname);
		(void) fprintf(fp,
		    gettext("where 'command' is one of the following:\n\n"));

		for (i = 0; i < SMBADM_NCMD; i++)
			smbadm_cmdusage(fp, &smbadm_cmdtable[i]);

		(void) fprintf(fp,
		    gettext("\nFor property list, run %s %s|%s\n"),
		    progname, "get", "set");

		exit(requested ? 0 : 2);
	}

	(void) fprintf(fp, gettext("usage:\n"));
	smbadm_cmdusage(fp, curcmd);

	if (strcmp(curcmd->name, "get") == 0 ||
	    strcmp(curcmd->name, "set") == 0)
		show_props = B_TRUE;

	if (show_props) {
		(void) fprintf(fp,
		    gettext("\nThe following properties are supported:\n"));

		(void) fprintf(fp, "\n\t%-16s   %s\n\n",
		    "PROPERTY", "VALUES");

		for (i = 0; i < SMBADM_NPROP; i++) {
			(void) fprintf(fp, "\t%-16s   %s\n",
			    smbadm_ptable[i].p_name,
			    smbadm_ptable[i].p_dispvalue);
		}
	}

	exit(requested ? 0 : 2);
}

/*
 * smbadm_strcasecmplist
 *
 * Find a string 's' within a list of strings.
 *
 * Returns the index of the matching string or -1 if there is no match.
 */
static int
smbadm_strcasecmplist(const char *s, ...)
{
	va_list ap;
	char *p;
	int ndx;

	va_start(ap, s);

	for (ndx = 0; ((p = va_arg(ap, char *)) != NULL); ++ndx) {
		if (strcasecmp(s, p) == 0) {
			va_end(ap);
			return (ndx);
		}
	}

	va_end(ap);
	return (-1);
}

/*
 * smbadm_answer_prompt
 *
 * Prompt for the answer to a question.  A default response must be
 * specified, which will be used if the user presses <enter> without
 * answering the question.
 */
static int
smbadm_answer_prompt(const char *prompt, char *answer, const char *dflt)
{
	char buf[SMBADM_ANSBUFSIZ];
	char *p;

	(void) printf(gettext("%s [%s]: "), prompt, dflt);

	if (fgets(buf, SMBADM_ANSBUFSIZ, stdin) == NULL)
		return (-1);

	if ((p = strchr(buf, '\n')) != NULL)
		*p = '\0';

	if (*buf == '\0')
		(void) strlcpy(answer, dflt, SMBADM_ANSBUFSIZ);
	else
		(void) strlcpy(answer, buf, SMBADM_ANSBUFSIZ);

	return (0);
}

/*
 * smbadm_confirm
 *
 * Ask a question that requires a yes/no answer.
 * A default response must be specified.
 */
static boolean_t
smbadm_confirm(const char *prompt, const char *dflt)
{
	char buf[SMBADM_ANSBUFSIZ];

	for (;;) {
		if (smbadm_answer_prompt(prompt, buf, dflt) < 0)
			return (B_FALSE);

		if (smbadm_strcasecmplist(buf, "n", "no", 0) >= 0)
			return (B_FALSE);

		if (smbadm_strcasecmplist(buf, "y", "yes", 0) >= 0)
			return (B_TRUE);

		(void) printf(gettext("Please answer yes or no.\n"));
	}
}

static boolean_t
smbadm_join_prompt(const char *domain)
{
	(void) printf(gettext("After joining %s the smb service will be "
	    "restarted automatically.\n"), domain);

	return (smbadm_confirm("Would you like to continue?", "no"));
}

static void
smbadm_restart_service(void)
{
	if (smb_smf_restart_service() != 0) {
		(void) fprintf(stderr,
		    gettext("Unable to restart smb service. "
		    "Run 'svcs -xv smb/server' for more information."));
	}
}

/*
 * smbadm_join
 *
 * Join a domain or workgroup.
 *
 * When joining a domain, we may receive the username, password and
 * domain name in any of the following combinations.  Note that the
 * password is optional on the command line: if it is not provided,
 * we will prompt for it later.
 *
 *	username+password domain
 *	domain\username+password
 *	domain/username+password
 *	username@domain
 *
 * We allow domain\name+password or domain/name+password but not
 * name+password@domain because @ is a valid password character.
 *
 * If the username and domain name are passed as separate command
 * line arguments, we process them directly.  Otherwise we separate
 * them and continue as if they were separate command line arguments.
 */
static int
smbadm_join(int argc, char **argv)
{
	char buf[MAXHOSTNAMELEN * 2];
	char *domain = NULL;
	char *username = NULL;
	uint32_t mode = 0;
	char option;

	while ((option = getopt(argc, argv, "u:w:")) != -1) {
		switch (option) {
		case 'w':
			if (mode != 0) {
				(void) fprintf(stderr,
				    gettext("-u and -w must only appear "
				    "once and are mutually exclusive\n"));
				smbadm_usage(B_FALSE);
			}

			mode = SMB_SECMODE_WORKGRP;
			domain = optarg;
			break;

		case 'u':
			if (mode != 0) {
				(void) fprintf(stderr,
				    gettext("-u and -w must only appear "
				    "once and are mutually exclusive\n"));
				smbadm_usage(B_FALSE);
			}

			mode = SMB_SECMODE_DOMAIN;
			username = optarg;

			if ((domain = argv[optind]) == NULL) {
				/*
				 * The domain was not specified as a separate
				 * argument, check for the combination forms.
				 */
				(void) strlcpy(buf, username, sizeof (buf));
				smbadm_extract_domain(buf, &username, &domain);
			}

			if ((username == NULL) || (*username == '\0')) {
				(void) fprintf(stderr,
				    gettext("missing username\n"));
				smbadm_usage(B_FALSE);
			}
			break;

		default:
			smbadm_usage(B_FALSE);
			break;
		}
	}

	if ((domain == NULL) || (*domain == '\0')) {
		(void) fprintf(stderr, gettext("missing %s name\n"),
		    (mode == SMB_SECMODE_WORKGRP) ? "workgroup" : "domain");
		smbadm_usage(B_FALSE);
	}

	if (mode == SMB_SECMODE_WORKGRP)
		return (smbadm_join_workgroup(domain));
	else
		return (smbadm_join_domain(domain, username));
}

/*
 * Workgroups comprise a collection of standalone, independently administered
 * computers that use a common workgroup name.  This is a peer-to-peer model
 * with no formal membership mechanism.
 */
static int
smbadm_join_workgroup(const char *workgroup)
{
	smb_joininfo_t jdi;
	uint32_t status;

	bzero(&jdi, sizeof (jdi));
	jdi.mode = SMB_SECMODE_WORKGRP;
	(void) strlcpy(jdi.domain_name, workgroup, sizeof (jdi.domain_name));
	(void) strtrim(jdi.domain_name, " \t\n");

	if (!smbadm_valid_workgroup(jdi.domain_name)) {
		(void) fprintf(stderr, gettext("workgroup name is invalid\n"));
		smbadm_usage(B_FALSE);
	}

	if (!smbadm_join_prompt(jdi.domain_name))
		return (0);

	if ((status = smb_join(&jdi)) != NT_STATUS_SUCCESS) {
		(void) fprintf(stderr, gettext("failed to join %s: %s\n"),
		    jdi.domain_name, xlate_nt_status(status));
		return (1);
	}

	(void) printf(gettext("Successfully joined %s\n"), jdi.domain_name);
	smbadm_restart_service();
	return (0);
}

/*
 * Domains comprise a centrally administered group of computers and accounts
 * that share a common security and administration policy and database.
 * Computers must join a domain and become domain members, which requires
 * an administrator level account name.
 *
 * The '+' character is invalid within a username.  We allow the password
 * to be appended to the username using '+' as a scripting convenience.
 */
static int
smbadm_join_domain(const char *domain, const char *username)
{
	smb_joininfo_t jdi;
	uint32_t status;
	char *prompt;
	char *p;
	int len;

	bzero(&jdi, sizeof (jdi));
	jdi.mode = SMB_SECMODE_DOMAIN;
	(void) strlcpy(jdi.domain_name, domain, sizeof (jdi.domain_name));
	(void) strtrim(jdi.domain_name, " \t\n");

	if (!smbadm_valid_domainname(jdi.domain_name)) {
		(void) fprintf(stderr, gettext("domain name is invalid\n"));
		smbadm_usage(B_FALSE);
	}

	if (!smbadm_join_prompt(jdi.domain_name))
		return (0);

	if ((p = strchr(username, '+')) != NULL) {
		++p;

		len = (int)(p - username);
		if (len > sizeof (jdi.domain_name))
			len = sizeof (jdi.domain_name);

		(void) strlcpy(jdi.domain_username, username, len);
		(void) strlcpy(jdi.domain_passwd, p,
		    sizeof (jdi.domain_passwd));
	} else {
		(void) strlcpy(jdi.domain_username, username,
		    sizeof (jdi.domain_username));
	}

	if (!smbadm_valid_username(jdi.domain_username)) {
		(void) fprintf(stderr,
		    gettext("username contains invalid characters\n"));
		smbadm_usage(B_FALSE);
	}

	if (*jdi.domain_passwd == '\0') {
		prompt = gettext("Enter domain password: ");

		if ((p = getpassphrase(prompt)) == NULL) {
			(void) fprintf(stderr, gettext("missing password\n"));
			smbadm_usage(B_FALSE);
		}

		(void) strlcpy(jdi.domain_passwd, p,
		    sizeof (jdi.domain_passwd));
	}

	(void) printf(gettext("Joining %s ... this may take a minute ...\n"),
	    jdi.domain_name);

	status = smb_join(&jdi);

	switch (status) {
	case NT_STATUS_SUCCESS:
		(void) printf(gettext("Successfully joined %s\n"),
		    jdi.domain_name);
		bzero(&jdi, sizeof (jdi));
		smbadm_restart_service();
		return (0);

	case NT_STATUS_DOMAIN_CONTROLLER_NOT_FOUND:
		(void) fprintf(stderr,
		    gettext("failed to find any domain controllers for %s\n"),
		    jdi.domain_name);
		bzero(&jdi, sizeof (jdi));
		return (1);

	default:
		(void) fprintf(stderr, gettext("failed to join %s: %s\n"),
		    jdi.domain_name, xlate_nt_status(status));
		bzero(&jdi, sizeof (jdi));
		return (1);
	}
}

/*
 * We want to process the user and domain names as separate strings.
 * Check for names of the forms below and separate the components as
 * required.
 *
 *	name@domain
 *	domain\name
 *	domain/name
 *
 * If we encounter any of the forms above in arg, the @, / or \
 * separator is replaced by \0 and the username and domain pointers
 * are changed to point to the appropriate components (in arg).
 *
 * If none of the separators are encountered, the username and domain
 * pointers remain unchanged.
 */
static void
smbadm_extract_domain(char *arg, char **username, char **domain)
{
	char *p;

	if ((p = strpbrk(arg, "/\\@")) != NULL) {
		if (*p == '@') {
			*p = '\0';
			++p;

			if (strchr(arg, '+') != NULL)
				return;

			*domain = p;
			*username = arg;
		} else {
			*p = '\0';
			++p;
			*username = p;
			*domain = arg;
		}
	}
}

/*
 * Check a domain name for RFC 1035 and 1123 compliance.  Domain names may
 * contain alphanumeric characters, hyphens and dots.  The first and last
 * character of a label must be alphanumeric.  Interior characters may be
 * alphanumeric or hypens.
 *
 * Domain names should not contain underscores but we allow them because
 * Windows names are often in non-compliance with this rule.
 */
static boolean_t
smbadm_valid_domainname(const char *domain)
{
	boolean_t new_label = B_TRUE;
	const char *p;
	char label_terminator;

	if (domain == NULL || *domain == '\0')
		return (B_FALSE);

	label_terminator = *domain;

	for (p = domain; *p != '\0'; ++p) {
		if (new_label) {
			if (!isalnum(*p))
				return (B_FALSE);
			new_label = B_FALSE;
			label_terminator = *p;
			continue;
		}

		if (*p == '.') {
			if (!isalnum(label_terminator))
				return (B_FALSE);
			new_label = B_TRUE;
			label_terminator = *p;
			continue;
		}

		label_terminator = *p;

		if (isalnum(*p) || *p == '-' || *p == '_')
			continue;

		return (B_FALSE);
	}

	if (!isalnum(label_terminator))
		return (B_FALSE);
	return (B_TRUE);
}

/*
 * Windows user names cannot contain the following characters
 * or control characters.
 *
 * " / \ [ ] < > + ; , ? * = @
 */
static boolean_t
smbadm_valid_username(const char *username)
{
	const char *invalid = "\"/\\[]<>+;,?*=@";
	const char *p;

	if (username == NULL)
		return (B_FALSE);

	if (strpbrk(username, invalid))
		return (B_FALSE);

	for (p = username; *p != '\0'; p++) {
		if (iscntrl(*p))
			return (B_FALSE);
	}

	return (B_TRUE);
}

/*
 * A workgroup name can contain 1 to 15 characters but cannot be the same
 * as the NetBIOS name.  The name must begin with a letter or number.
 *
 * The name cannot consist entirely of spaces or dots, which is covered
 * by the requirement that the name must begin with an alphanumeric
 * character.
 *
 * The name must not contain any of the following characters or control
 * characters.
 *
 * " / \ [ ] : | < > + = ; , ?
 */
static boolean_t
smbadm_valid_workgroup(const char *workgroup)
{
	char netbiosname[NETBIOS_NAME_SZ];
	const char *invalid = "\"/\\[]:|<>+=;,?";
	const char *p;

	if (workgroup == NULL || *workgroup == '\0' || (!isalnum(*workgroup)))
		return (B_FALSE);

	if (strlen(workgroup) >= NETBIOS_NAME_SZ)
		return (B_FALSE);

	if (smb_getnetbiosname(netbiosname, NETBIOS_NAME_SZ) == 0) {
		if (utf8_strcasecmp(workgroup, netbiosname) == 0)
			return (B_FALSE);
	}

	if (strpbrk(workgroup, invalid))
		return (B_FALSE);

	for (p = workgroup; *p != '\0'; p++) {
		if (iscntrl(*p))
			return (B_FALSE);
	}

	return (B_TRUE);
}

/*
 * smbadm_list
 *
 * Displays current security mode and domain/workgroup name.
 */
/*ARGSUSED*/
static int
smbadm_list(int argc, char **argv)
{
	char domain[MAXHOSTNAMELEN];
	char fqdn[MAXHOSTNAMELEN];
	char srvname[MAXHOSTNAMELEN];
	char modename[16];
	int rc;
	uint32_t srvipaddr;
	char ipstr[INET6_ADDRSTRLEN];

	rc = smb_config_getstr(SMB_CI_SECURITY, modename, sizeof (modename));
	if (rc != SMBD_SMF_OK) {
		(void) fprintf(stderr,
		    gettext("failed to get the connected mode\n"));
		return (1);
	}

	if (smb_getdomainname(domain, sizeof (domain)) != 0) {
		(void) fprintf(stderr, gettext("failed to get the %s name\n"),
		    modename);
		return (1);
	}
	if (strcmp(modename, "workgroup") == 0) {
		(void) printf(gettext("Workgroup: %s\n"), domain);
		return (0);
	}
	(void) printf(gettext("Domain: %s\n"), domain);
	if ((smb_getfqdomainname(fqdn, sizeof (fqdn)) == 0) && (*fqdn != '\0'))
		(void) printf(gettext("FQDN: %s\n"), fqdn);

	if ((smb_get_dcinfo(srvname, MAXHOSTNAMELEN, &srvipaddr)
	    == NT_STATUS_SUCCESS) && (*srvname != '\0') &&
	    (srvipaddr != 0)) {
		(void) inet_ntop(AF_INET, (const void *)&srvipaddr,
		    ipstr, sizeof (ipstr));
		(void) printf(gettext("Selected Domain Controller: %s (%s)\n"),
		    srvname, ipstr);
	}
	return (0);
}

/*
 * smbadm_group_create
 *
 * Creates a local SMB group
 */
static int
smbadm_group_create(int argc, char **argv)
{
	char *gname = NULL;
	char *desc = NULL;
	char option;
	int status;

	while ((option = getopt(argc, argv, "d:")) != -1) {
		switch (option) {
		case 'd':
			desc = optarg;
			break;

		default:
			smbadm_usage(B_FALSE);
		}
	}

	gname = argv[optind];
	if (optind >= argc || gname == NULL || *gname == '\0') {
		(void) fprintf(stderr, gettext("missing group name\n"));
		smbadm_usage(B_FALSE);
	}

	if (getgrnam(gname) == NULL) {
		(void) fprintf(stderr,
		    gettext("failed to get the Solaris group '%s'\n"), gname);
		(void) fprintf(stderr,
		    gettext("use 'groupadd' to add '%s'\n"), gname);
		return (1);
	}

	status = smb_lgrp_add(gname, desc);
	if (status != SMB_LGRP_SUCCESS) {
		(void) fprintf(stderr,
		    gettext("failed to create the group (%s)\n"),
		    smb_lgrp_strerror(status));
	} else {
		(void) printf(gettext("'%s' created.\n"),
		    gname);
	}

	return (status);
}

/*
 * smbadm_group_dump_members
 *
 * Dump group members details.
 */
static void
smbadm_group_dump_members(smb_gsid_t *members, int num)
{
	char sidstr[SMB_SID_STRSZ];
	int i;

	if (num == 0) {
		(void) printf(gettext("\tNo members\n"));
		return;
	}

	(void) printf(gettext("\tMembers:\n"));
	for (i = 0; i < num; i++) {
		*sidstr = '\0';
		if (smb_lookup_sid(members[i].gs_sid, sidstr,
		    sizeof (sidstr)) == NT_STATUS_SUCCESS)
			(void) printf(gettext("\t\t%s\n"), sidstr);
		else
			(void) printf(gettext("\t\tinvalid SID\n"));
	}
}

/*
 * smbadm_group_dump_privs
 *
 * Dump group privilege details.
 */
static void
smbadm_group_dump_privs(smb_privset_t *privs)
{
	smb_privinfo_t *pinfo;
	char *pstatus;
	int i;

	(void) printf(gettext("\tPrivileges: \n"));

	for (i = 0; i < privs->priv_cnt; i++) {
		pinfo = smb_priv_getbyvalue(privs->priv[i].luid.lo_part);
		if ((pinfo == NULL) || (pinfo->flags & PF_PRESENTABLE) == 0)
			continue;

		switch (privs->priv[i].attrs) {
		case SE_PRIVILEGE_ENABLED:
			pstatus = "On";
			break;
		case SE_PRIVILEGE_DISABLED:
			pstatus = "Off";
			break;
		default:
			pstatus = "Unknown";
			break;
		}
		(void) printf(gettext("\t\t%s: %s\n"), pinfo->name, pstatus);
	}

	if (privs->priv_cnt == 0)
		(void) printf(gettext("\t\tNo privileges\n"));
}

/*
 * smbadm_group_dump
 *
 * Dump group details.
 */
static void
smbadm_group_dump(smb_group_t *grp, boolean_t show_mem, boolean_t show_privs)
{
	char sidstr[SMB_SID_STRSZ];

	(void) printf(gettext("%s (%s)\n"), grp->sg_name, grp->sg_cmnt);

	smb_sid_tostr(grp->sg_id.gs_sid, sidstr);
	(void) printf(gettext("\tSID: %s\n"), sidstr);

	if (show_privs)
		smbadm_group_dump_privs(grp->sg_privs);

	if (show_mem)
		smbadm_group_dump_members(grp->sg_members, grp->sg_nmembers);
}

/*
 * smbadm_group_show
 *
 */
static int
smbadm_group_show(int argc, char **argv)
{
	char *gname = NULL;
	boolean_t show_privs;
	boolean_t show_members;
	char option;
	int status;
	smb_group_t grp;
	smb_giter_t gi;

	show_privs = show_members = B_FALSE;

	while ((option = getopt(argc, argv, "mp")) != -1) {
		switch (option) {
		case 'm':
			show_members = B_TRUE;
			break;
		case 'p':
			show_privs = B_TRUE;
			break;

		default:
			smbadm_usage(B_FALSE);
		}
	}

	gname = argv[optind];
	if (optind >= argc || gname == NULL || *gname == '\0')
		gname = "*";

	if (strcmp(gname, "*")) {
		status = smb_lgrp_getbyname(gname, &grp);
		if (status == SMB_LGRP_SUCCESS) {
			smbadm_group_dump(&grp, show_members, show_privs);
			smb_lgrp_free(&grp);
		} else {
			(void) fprintf(stderr,
			    gettext("failed to find %s (%s)\n"),
			    gname, smb_lgrp_strerror(status));
		}
		return (status);
	}

	if ((status = smb_lgrp_iteropen(&gi)) != SMB_LGRP_SUCCESS) {
		(void) fprintf(stderr, gettext("failed to list groups (%s)\n"),
		    smb_lgrp_strerror(status));
		return (status);
	}

	while ((status = smb_lgrp_iterate(&gi, &grp)) == SMB_LGRP_SUCCESS) {
		smbadm_group_dump(&grp, show_members, show_privs);
		smb_lgrp_free(&grp);
	}

	smb_lgrp_iterclose(&gi);

	if (status != SMB_LGRP_NO_MORE) {
		(void) fprintf(stderr,
		    gettext("failed to get all the groups (%s)\n"),
		    smb_lgrp_strerror(status));
		return (status);
	}

	return (0);
}

/*
 * smbadm_group_delete
 */
static int
smbadm_group_delete(int argc, char **argv)
{
	char *gname = NULL;
	int status;

	gname = argv[optind];
	if (optind >= argc || gname == NULL || *gname == '\0') {
		(void) fprintf(stderr, gettext("missing group name\n"));
		smbadm_usage(B_FALSE);
	}

	status = smb_lgrp_delete(gname);
	if (status != SMB_LGRP_SUCCESS) {
		(void) fprintf(stderr,
		    gettext("failed to delete %s (%s)\n"), gname,
		    smb_lgrp_strerror(status));
	} else {
		(void) printf(gettext("%s deleted.\n"), gname);
	}

	return (status);
}

/*
 * smbadm_group_rename
 */
static int
smbadm_group_rename(int argc, char **argv)
{
	char *gname = NULL;
	char *ngname = NULL;
	int status;

	gname = argv[optind];
	if (optind++ >= argc || gname == NULL || *gname == '\0') {
		(void) fprintf(stderr, gettext("missing group name\n"));
		smbadm_usage(B_FALSE);
	}

	ngname = argv[optind];
	if (optind >= argc || ngname == NULL || *ngname == '\0') {
		(void) fprintf(stderr, gettext("missing new group name\n"));
		smbadm_usage(B_FALSE);
	}

	if (getgrnam(ngname) == NULL) {
		(void) fprintf(stderr,
		    gettext("failed to get the Solaris group '%s'\n"), ngname);
		(void) fprintf(stderr,
		    gettext("use 'groupadd' to add '%s'\n"), ngname);
		return (1);
	}

	status = smb_lgrp_rename(gname, ngname);
	if (status != SMB_LGRP_SUCCESS) {
		if (status == SMB_LGRP_EXISTS)
			(void) fprintf(stderr,
			    gettext("failed to rename '%s' (%s already "
			    "exists)\n"), gname, ngname);
		else
			(void) fprintf(stderr,
			    gettext("failed to rename '%s' (%s)\n"), gname,
			    smb_lgrp_strerror(status));
	} else {
		(void) printf(gettext("'%s' renamed to '%s'\n"), gname, ngname);
	}

	return (status);
}

/*
 * smbadm_group_setprop
 *
 * Set the group properties.
 */
static int
smbadm_group_setprop(int argc, char **argv)
{
	char *gname = NULL;
	smbadm_prop_t props[SMBADM_NPROP];
	smbadm_prop_handle_t *phandle;
	char option;
	int pcnt = 0;
	int ret;
	int p;

	bzero(props, SMBADM_NPROP * sizeof (smbadm_prop_t));

	while ((option = getopt(argc, argv, "p:")) != -1) {
		switch (option) {
		case 'p':
			if (pcnt >= SMBADM_NPROP) {
				(void) fprintf(stderr,
				    gettext("exceeded number of supported"
				    " properties\n"));
				smbadm_usage(B_FALSE);
			}

			if (smbadm_prop_parse(optarg, &props[pcnt++]) != 0)
				smbadm_usage(B_FALSE);
			break;

		default:
			smbadm_usage(B_FALSE);
		}
	}

	if (pcnt == 0) {
		(void) fprintf(stderr,
		    gettext("missing property=value argument\n"));
		smbadm_usage(B_FALSE);
	}

	gname = argv[optind];
	if (optind >= argc || gname == NULL || *gname == '\0') {
		(void) fprintf(stderr, gettext("missing group name\n"));
		smbadm_usage(B_FALSE);
	}

	for (p = 0; p < pcnt; p++) {
		phandle = smbadm_prop_gethandle(props[p].p_name);
		if (phandle) {
			if (phandle->p_setfn(gname, &props[p]) != 0)
				ret = 1;
		}
	}

	return (ret);
}

/*
 * smbadm_group_getprop
 *
 * Get the group properties.
 */
static int
smbadm_group_getprop(int argc, char **argv)
{
	char *gname = NULL;
	smbadm_prop_t props[SMBADM_NPROP];
	smbadm_prop_handle_t *phandle;
	char option;
	int pcnt = 0;
	int ret;
	int p;

	bzero(props, SMBADM_NPROP * sizeof (smbadm_prop_t));

	while ((option = getopt(argc, argv, "p:")) != -1) {
		switch (option) {
		case 'p':
			if (pcnt >= SMBADM_NPROP) {
				(void) fprintf(stderr,
				    gettext("exceeded number of supported"
				    " properties\n"));
				smbadm_usage(B_FALSE);
			}

			if (smbadm_prop_parse(optarg, &props[pcnt++]) != 0)
				smbadm_usage(B_FALSE);
			break;

		default:
			smbadm_usage(B_FALSE);
		}
	}

	gname = argv[optind];
	if (optind >= argc || gname == NULL || *gname == '\0') {
		(void) fprintf(stderr, gettext("missing group name\n"));
		smbadm_usage(B_FALSE);
	}

	if (pcnt == 0) {
		/*
		 * If no property has be specified then get
		 * all the properties.
		 */
		pcnt = SMBADM_NPROP;
		for (p = 0; p < pcnt; p++)
			props[p].p_name = smbadm_ptable[p].p_name;
	}

	for (p = 0; p < pcnt; p++) {
		phandle = smbadm_prop_gethandle(props[p].p_name);
		if (phandle) {
			if (phandle->p_getfn(gname, &props[p]) != 0)
				ret = 1;
		}
	}

	return (ret);
}

/*
 * smbadm_group_addmember
 *
 */
static int
smbadm_group_addmember(int argc, char **argv)
{
	char *gname = NULL;
	char **mname;
	char option;
	smb_gsid_t msid;
	int status;
	int mcnt = 0;
	int ret = 0;
	int i;


	mname = (char **)malloc(argc * sizeof (char *));
	if (mname == NULL) {
		warn(gettext("failed to add group member"));
		return (1);
	}
	bzero(mname, argc * sizeof (char *));

	while ((option = getopt(argc, argv, "m:")) != -1) {
		switch (option) {
		case 'm':
			mname[mcnt++] = optarg;
			break;

		default:
			free(mname);
			smbadm_usage(B_FALSE);
		}
	}

	if (mcnt == 0) {
		(void) fprintf(stderr, gettext("missing member name\n"));
		free(mname);
		smbadm_usage(B_FALSE);
	}

	gname = argv[optind];
	if (optind >= argc || gname == NULL || *gname == 0) {
		(void) fprintf(stderr, gettext("missing group name\n"));
		free(mname);
		smbadm_usage(B_FALSE);
	}


	for (i = 0; i < mcnt; i++) {
		if (mname[i] == NULL)
			continue;

		if (smb_lookup_name(mname[i], &msid) != NT_STATUS_SUCCESS) {
			(void) fprintf(stderr,
			    gettext("failed to add %s: unable to obtain SID\n"),
			    mname[i]);
			continue;
		}

		status = smb_lgrp_add_member(gname, msid.gs_sid, msid.gs_type);
		free(msid.gs_sid);
		if (status != SMB_LGRP_SUCCESS) {
			(void) fprintf(stderr,
			    gettext("failed to add %s (%s)\n"),
			    mname[i], smb_lgrp_strerror(status));
			ret = 1;
		} else {
			(void) printf(gettext("'%s' is now a member of '%s'\n"),
			    mname[i], gname);
		}
	}

	free(mname);
	return (ret);
}

/*
 * smbadm_group_delmember
 */
static int
smbadm_group_delmember(int argc, char **argv)
{
	char *gname = NULL;
	char **mname;
	char option;
	smb_gsid_t msid;
	int status;
	int mcnt = 0;
	int ret = 0;
	int i;

	mname = (char **)malloc(argc * sizeof (char *));
	if (mname == NULL) {
		warn(gettext("failed to delete group member"));
		return (1);
	}
	bzero(mname, argc * sizeof (char *));

	while ((option = getopt(argc, argv, "m:")) != -1) {
		switch (option) {
		case 'm':
			mname[mcnt++] = optarg;
			break;

		default:
			free(mname);
			smbadm_usage(B_FALSE);
		}
	}

	if (mcnt == 0) {
		(void) fprintf(stderr, gettext("missing member name\n"));
		free(mname);
		smbadm_usage(B_FALSE);
	}

	gname = argv[optind];
	if (optind >= argc || gname == NULL || *gname == 0) {
		(void) fprintf(stderr, gettext("missing group name\n"));
		free(mname);
		smbadm_usage(B_FALSE);
	}


	for (i = 0; i < mcnt; i++) {
		if (mname[i] == NULL)
			continue;

		if (smb_lookup_name(mname[i], &msid) != NT_STATUS_SUCCESS) {
			(void) fprintf(stderr,
			    gettext("failed to remove %s: "
			    "unable to obtain SID\n"),
			    mname[i]);
			continue;
		}

		status = smb_lgrp_del_member(gname, msid.gs_sid, msid.gs_type);
		free(msid.gs_sid);
		if (status != SMB_LGRP_SUCCESS) {
			(void) fprintf(stderr,
			    gettext("failed to remove %s (%s)\n"),
			    mname[i], smb_lgrp_strerror(status));
			ret = 1;
		} else {
			(void) printf(
			    gettext("'%s' has been removed from %s\n"),
			    mname[i], gname);
		}
	}

	return (ret);
}

static int
smbadm_user_disable(int argc, char **argv)
{
	int error;
	char *user = NULL;

	user = argv[optind];
	if (optind >= argc || user == NULL || *user == '\0') {
		(void) fprintf(stderr, gettext("missing user name\n"));
		smbadm_usage(B_FALSE);
	}

	error = smb_pwd_setcntl(user, SMB_PWC_DISABLE);
	if (error == SMB_PWE_SUCCESS)
		(void) printf(gettext("%s is disabled.\n"), user);
	else
		(void) fprintf(stderr, "%s\n", smbadm_pwd_strerror(error));

	return (error);
}

static int
smbadm_user_enable(int argc, char **argv)
{
	int error;
	char *user = NULL;

	user = argv[optind];
	if (optind >= argc || user == NULL || *user == '\0') {
		(void) fprintf(stderr, gettext("missing user name\n"));
		smbadm_usage(B_FALSE);
	}

	error = smb_pwd_setcntl(user, SMB_PWC_ENABLE);
	if (error == SMB_PWE_SUCCESS)
		(void) printf(gettext("%s is enabled.\n"), user);
	else
		(void) fprintf(stderr, "%s\n", smbadm_pwd_strerror(error));

	return (error);
}


int
main(int argc, char **argv)
{
	int ret;
	int i;

	(void) malloc(0);	/* satisfy libumem dependency */

	progname = basename(argv[0]);

	if (getzoneid() != GLOBAL_ZONEID) {
		(void) fprintf(stderr,
		    gettext("cannot execute in non-global zone\n"));
		return (0);
	}

	if (is_system_labeled()) {
		(void) fprintf(stderr,
		    gettext("Trusted Extensions not supported\n"));
		return (0);
	}

	if (argc < 2) {
		(void) fprintf(stderr, gettext("missing command\n"));
		smbadm_usage(B_FALSE);
	}

	/*
	 * Special case "cmd --help/-?"
	 */
	if (strcmp(argv[1], "-?") == 0 ||
	    strcmp(argv[1], "--help") == 0 ||
	    strcmp(argv[1], "-h") == 0)
		smbadm_usage(B_TRUE);

	for (i = 0; i < SMBADM_NCMD; ++i) {
		curcmd = &smbadm_cmdtable[i];
		if (strcasecmp(argv[1], curcmd->name) == 0) {
			if (argc > 2) {
				/* cmd subcmd --help/-? */
				if (strcmp(argv[2], "-?") == 0 ||
				    strcmp(argv[2], "--help") == 0 ||
				    strcmp(argv[2], "-h") == 0)
					smbadm_usage(B_TRUE);
			}

			if ((ret = smbadm_init()) != 0)
				return (ret);

			ret = curcmd->func(argc - 1, &argv[1]);

			smbadm_fini();
			return (ret);
		}
	}

	curcmd = NULL;
	(void) fprintf(stderr, gettext("unknown subcommand (%s)\n"), argv[1]);
	smbadm_usage(B_FALSE);
	return (2);
}

static int
smbadm_init(void)
{
	int rc;

	switch (curcmd->flags & SMBADM_CMDF_TYPEMASK) {
	case SMBADM_CMDF_GROUP:
		if (smb_idmap_start() != 0) {
			(void) fprintf(stderr,
			    gettext("failed to contact idmap service\n"));
			return (1);
		}

		if ((rc = smb_lgrp_start()) != SMB_LGRP_SUCCESS) {
			(void) fprintf(stderr,
			    gettext("failed to initialize (%s)\n"),
			    smb_lgrp_strerror(rc));
			smb_idmap_stop();
			return (1);
		}
		break;

	case SMBADM_CMDF_USER:
		smb_pwd_init(B_FALSE);
		break;

	default:
		break;
	}

	return (0);
}

static void
smbadm_fini(void)
{
	switch (curcmd->flags & SMBADM_CMDF_TYPEMASK) {
	case SMBADM_CMDF_GROUP:
		smb_lgrp_stop();
		smb_idmap_stop();
		break;

	case SMBADM_CMDF_USER:
		smb_pwd_fini();
		break;

	default:
		break;
	}
}

static boolean_t
smbadm_prop_validate(smbadm_prop_t *prop, boolean_t chkval)
{
	smbadm_prop_handle_t *pinfo;
	int i;

	for (i = 0; i < SMBADM_NPROP; i++) {
		pinfo = &smbadm_ptable[i];
		if (strcmp(pinfo->p_name, prop->p_name) == 0) {
			if (pinfo->p_chkfn && chkval)
				return (pinfo->p_chkfn(prop));

			return (B_TRUE);
		}
	}

	(void) fprintf(stderr, gettext("unrecognized property '%s'\n"),
	    prop->p_name);

	return (B_FALSE);
}

static int
smbadm_prop_parse(char *arg, smbadm_prop_t *prop)
{
	boolean_t parse_value;
	char *equal;

	if (arg == NULL)
		return (2);

	prop->p_name = prop->p_value = NULL;

	if (strcmp(curcmd->name, "set") == 0)
		parse_value = B_TRUE;
	else
		parse_value = B_FALSE;

	prop->p_name = arg;

	if (parse_value) {
		equal = strchr(arg, '=');
		if (equal == NULL)
			return (2);

		*equal++ = '\0';
		prop->p_value = equal;
	}

	if (smbadm_prop_validate(prop, parse_value) == B_FALSE)
		return (2);

	return (0);
}

static smbadm_prop_handle_t *
smbadm_prop_gethandle(char *pname)
{
	int i;

	for (i = 0; i < SMBADM_NPROP; i++)
		if (strcmp(pname, smbadm_ptable[i].p_name) == 0)
			return (&smbadm_ptable[i]);

	return (NULL);
}

static int
smbadm_setprop_desc(char *gname, smbadm_prop_t *prop)
{
	int status;

	status = smb_lgrp_setcmnt(gname, prop->p_value);
	if (status != SMB_LGRP_SUCCESS) {
		(void) fprintf(stderr,
		    gettext("failed to modify the group description (%s)\n"),
		    smb_lgrp_strerror(status));
		return (1);
	}

	(void) printf(gettext("%s: description modified\n"), gname);
	return (0);
}

static int
smbadm_getprop_desc(char *gname, smbadm_prop_t *prop)
{
	char *cmnt = NULL;
	int status;

	status = smb_lgrp_getcmnt(gname, &cmnt);
	if (status != SMB_LGRP_SUCCESS) {
		(void) fprintf(stderr,
		    gettext("failed to get the group description (%s)\n"),
		    smb_lgrp_strerror(status));
		return (1);
	}

	(void) printf(gettext("\t%s: %s\n"), prop->p_name, cmnt);
	free(cmnt);
	return (0);
}

static int
smbadm_group_setpriv(char *gname, uint8_t priv_id, smbadm_prop_t *prop)
{
	boolean_t enable;
	int status;
	int ret;

	if (strcasecmp(prop->p_value, "on") == 0) {
		(void) printf(gettext("Enabling %s privilege "), prop->p_name);
		enable = B_TRUE;
	} else {
		(void) printf(gettext("Disabling %s privilege "), prop->p_name);
		enable = B_FALSE;
	}

	status = smb_lgrp_setpriv(gname, priv_id, enable);
	if (status == SMB_LGRP_SUCCESS) {
		(void) printf(gettext("succeeded\n"));
		ret = 0;
	} else {
		(void) printf(gettext("failed: %s\n"),
		    smb_lgrp_strerror(status));
		ret = 1;
	}

	return (ret);
}

static int
smbadm_group_getpriv(char *gname, uint8_t priv_id, smbadm_prop_t *prop)
{
	boolean_t enable;
	int status;

	status = smb_lgrp_getpriv(gname, priv_id, &enable);
	if (status != SMB_LGRP_SUCCESS) {
		(void) fprintf(stderr, gettext("failed to get %s (%s)\n"),
		    prop->p_name, smb_lgrp_strerror(status));
		return (1);
	}

	(void) printf(gettext("\t%s: %s\n"), prop->p_name,
	    (enable) ? "On" : "Off");

	return (0);
}

static int
smbadm_setprop_tkowner(char *gname, smbadm_prop_t *prop)
{
	return (smbadm_group_setpriv(gname, SE_TAKE_OWNERSHIP_LUID, prop));
}

static int
smbadm_getprop_tkowner(char *gname, smbadm_prop_t *prop)
{
	return (smbadm_group_getpriv(gname, SE_TAKE_OWNERSHIP_LUID, prop));
}

static int
smbadm_setprop_backup(char *gname, smbadm_prop_t *prop)
{
	return (smbadm_group_setpriv(gname, SE_BACKUP_LUID, prop));
}

static int
smbadm_getprop_backup(char *gname, smbadm_prop_t *prop)
{
	return (smbadm_group_getpriv(gname, SE_BACKUP_LUID, prop));
}

static int
smbadm_setprop_restore(char *gname, smbadm_prop_t *prop)
{
	return (smbadm_group_setpriv(gname, SE_RESTORE_LUID, prop));
}

static int
smbadm_getprop_restore(char *gname, smbadm_prop_t *prop)
{
	return (smbadm_group_getpriv(gname, SE_RESTORE_LUID, prop));
}

static boolean_t
smbadm_chkprop_priv(smbadm_prop_t *prop)
{
	if (prop->p_value == NULL || *prop->p_value == '\0') {
		(void) fprintf(stderr,
		    gettext("missing value for '%s'\n"), prop->p_name);
		return (B_FALSE);
	}

	if (strcasecmp(prop->p_value, "on") == 0)
		return (B_TRUE);

	if (strcasecmp(prop->p_value, "off") == 0)
		return (B_TRUE);

	(void) fprintf(stderr,
	    gettext("%s: unrecognized value for '%s' property\n"),
	    prop->p_value, prop->p_name);

	return (B_FALSE);
}

static const char *
smbadm_pwd_strerror(int error)
{
	switch (error) {
	case SMB_PWE_SUCCESS:
		return (gettext("Success."));

	case SMB_PWE_USER_UNKNOWN:
		return (gettext("User does not exist."));

	case SMB_PWE_USER_DISABLE:
		return (gettext("User is disabled."));

	case SMB_PWE_CLOSE_FAILED:
	case SMB_PWE_OPEN_FAILED:
	case SMB_PWE_WRITE_FAILED:
	case SMB_PWE_UPDATE_FAILED:
		return (gettext("Unexpected failure. "
		    "SMB password database unchanged."));

	case SMB_PWE_STAT_FAILED:
		return (gettext("stat of SMB password file failed."));

	case SMB_PWE_BUSY:
		return (gettext("SMB password database busy. "
		    "Try again later."));

	case SMB_PWE_DENIED:
		return (gettext("Operation not permitted."));

	case SMB_PWE_SYSTEM_ERROR:
		return (gettext("System error."));

	default:
		break;
	}

	return (gettext("Unknown error code."));
}

/*
 * Enable libumem debugging by default on DEBUG builds.
 */
#ifdef DEBUG
const char *
_umem_debug_init(void)
{
	return ("default,verbose"); /* $UMEM_DEBUG setting */
}

const char *
_umem_logging_init(void)
{
	return ("fail,contents"); /* $UMEM_LOGGING setting */
}
#endif
