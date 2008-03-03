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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This module contains smbadm CLI which offers smb configuration
 * functionalities.
 */
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
	HELP_UDISABLE,
	HELP_UENABLE
} smbadm_help_t;

#define	SMBADM_CMDF_GROUP	0x01

typedef struct smbadm_cmdinfo {
	char *name;
	int (*func)(int, char **);
	smbadm_help_t usage;
	uint32_t flags;
} smbadm_cmdinfo_t;

smbadm_cmdinfo_t *curcmd;
static char *progname;

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
	{ "disable-user",	smbadm_user_disable,	HELP_UDISABLE,	0 },
	{ "enable-user",	smbadm_user_enable,	HELP_UENABLE,	0 },
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

static int smbadm_grpcmd_init(void);
static void smbadm_grpcmd_fini(void);
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

	case HELP_UDISABLE:
	case HELP_UENABLE:
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
 * smbadm_join
 *
 * Join the given domain/workgroup
 */
static int
smbadm_join(int argc, char **argv)
{
	char option;
	smb_joininfo_t jdi;
	boolean_t join_w = B_FALSE;
	boolean_t join_d = B_FALSE;
	uint32_t status;
	char kdom[MAXHOSTNAMELEN];

	bzero(&jdi, sizeof (jdi));

	while ((option = getopt(argc, argv, "u:w:")) != -1) {
		switch (option) {
		case 'w':
			(void) strlcpy(jdi.domain_name, optarg,
			    sizeof (jdi.domain_name));
			jdi.mode = SMB_SECMODE_WORKGRP;
			join_w = B_TRUE;
			break;

		case 'u':
			/* admin username */
			(void) strlcpy(jdi.domain_username, optarg,
			    sizeof (jdi.domain_username));
			jdi.mode = SMB_SECMODE_DOMAIN;
			join_d = B_TRUE;
			break;

		default:
			smbadm_usage(B_FALSE);
		}
	}

	if (join_w && join_d) {
		(void) fprintf(stderr,
		    gettext("domain and workgroup "
		    "can not be specified together\n"));
		smbadm_usage(B_FALSE);
	}

	if (join_d && (argv[optind] != NULL)) {
		(void) strlcpy(jdi.domain_name, argv[optind],
		    sizeof (jdi.domain_name));
	}

	if (*jdi.domain_name == '\0') {
		(void) fprintf(stderr, gettext("missing %s name\n"),
		    (join_d) ? "domain" : "workgroup");
		smbadm_usage(B_FALSE);
	}

	if (join_d && *jdi.domain_username == '\0') {
		(void) fprintf(stderr, gettext("missing username\n"));
		smbadm_usage(B_FALSE);
	}

	if (join_w) {
		status = smb_join(&jdi);
		if (status == NT_STATUS_SUCCESS) {
			(void) printf(
			    gettext("Successfully joined workgroup '%s'\n"),
			    jdi.domain_name);
			return (0);
		}

		(void) fprintf(stderr,
		    gettext("failed to join workgroup '%s' (%s)\n"),
		    jdi.domain_name, xlate_nt_status(status));

		return (1);
	}

	if ((smb_config_getstr(SMB_CI_KPASSWD_DOMAIN, kdom, sizeof (kdom))
	    == SMBD_SMF_OK) && (*kdom != 0)) {
		if (strncasecmp(jdi.domain_name, kdom,
		    strlen(jdi.domain_name))) {
			char reply[8];

			(void) printf(gettext("The system has already "
			    "joined to a different domain %s by another "
			    "program.\nWould you like to continue [yes/no]? "),
			    kdom);
			(void) scanf("%8s", reply);
			(void) trim_whitespace(reply);
			if (strncasecmp(reply, "yes", 3) != 0)
				return (0);
		}
	}

	/* Join the domain */
	if (*jdi.domain_passwd == '\0') {
		char *p = NULL;
		char *prompt = gettext("Enter domain password: ");
		p = getpassphrase(prompt);
		if (!p) {
			(void) fprintf(stderr, gettext("missing password\n"));
			smbadm_usage(B_FALSE);
		}

		(void) strlcpy(jdi.domain_passwd, p,
		    sizeof (jdi.domain_passwd));
	}

	(void) printf(gettext("Joining '%s' ... this may take a minute ...\n"),
	    jdi.domain_name);

	status = smb_join(&jdi);

	switch (status) {
	case NT_STATUS_SUCCESS:
		(void) printf(gettext("Successfully joined domain '%s'\n"),
		    jdi.domain_name);
		return (0);

	case NT_STATUS_DOMAIN_CONTROLLER_NOT_FOUND:
		(void) fprintf(stderr, gettext("failed to find "
		    "any domain controllers for '%s'\n"),
		    jdi.domain_name);
		break;

	default:
		(void) fprintf(stderr,
		    gettext("failed to join domain '%s' (%s)\n"),
		    jdi.domain_name, xlate_nt_status(status));
	}

	return (1);
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
	char modename[16];
	int rc;

	rc = smb_config_getstr(SMB_CI_SECURITY, modename, sizeof (modename));
	if (rc != SMBD_SMF_OK) {
		(void) fprintf(stderr,
		    gettext("failed to get the security mode\n"));
		return (1);
	}

	(void) printf(gettext("security mode: %s\n"), modename);

	if (smb_getdomainname(domain, sizeof (domain)) != 0) {
		(void) fprintf(stderr, gettext("failed to get the %s name\n"),
		    modename);
		return (1);
	}

	(void) printf(gettext("%s name: %s\n"), modename, domain);
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
	char sidstr[NT_SID_FMTBUF_SIZE];
	int i;

	if (num == 0) {
		(void) printf(gettext("\tNo members\n"));
		return;
	}

	(void) printf(gettext("\tMembers:\n"));
	for (i = 0; i < num; i++) {
		(void) smb_lookup_sid(members[i].gs_sid, sidstr,
		    sizeof (sidstr));
		(void) printf(gettext("\t\t%s\n"), sidstr);
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
	char sidstr[NT_SID_FMTBUF_SIZE];

	(void) printf(gettext("%s (%s)\n"), grp->sg_name, grp->sg_cmnt);

	nt_sid_format2(grp->sg_id.gs_sid, sidstr);
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
			    gettext("failed to find '%s' (%s)\n"),
			    gname, smb_lgrp_strerror(status));
		}
		return (status);
	}

	status = smb_lgrp_iteropen(&gi);
	if (status != SMB_LGRP_SUCCESS) {
		(void) fprintf(stderr,
		    gettext("failed to list groups (%s)\n"),
		    smb_lgrp_strerror(status));
		return (status);
	}

	while (smb_lgrp_iterate(&gi, &grp) == SMB_LGRP_SUCCESS) {
		smbadm_group_dump(&grp, show_members, show_privs);
		smb_lgrp_free(&grp);
	}
	smb_lgrp_iterclose(&gi);

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
		    gettext("failed to delete the group (%s)\n"),
		    smb_lgrp_strerror(status));
	} else {
		(void) printf(gettext("'%s' deleted.\n"),
		    gname);
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
		(void) fprintf(stderr, gettext("out of memory\n"));
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
			    gettext("failed to add %s "
			    "(could not obtain the SID)\n"),
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
		(void) fprintf(stderr, gettext("out of memory\n"));
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
			    gettext("failed to remove %s "
			    "(could not obtain the SID)\n"),
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

			if ((ret = smbadm_grpcmd_init()) != 0)
				return (ret);

			ret = curcmd->func(argc - 1, &argv[1]);

			smbadm_grpcmd_fini();
			return (ret);
		}
	}

	curcmd = NULL;
	(void) fprintf(stderr, gettext("unknown subcommand (%s)\n"), argv[1]);
	smbadm_usage(B_FALSE);
	return (2);
}

static int
smbadm_grpcmd_init(void)
{
	int rc;

	if (curcmd->flags & SMBADM_CMDF_GROUP) {
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
	}

	return (0);
}

static void
smbadm_grpcmd_fini(void)
{
	if (curcmd->flags & SMBADM_CMDF_GROUP) {
		smb_lgrp_stop();
		smb_idmap_stop();
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

	(void) fprintf(stderr,
	    gettext("unrecognized property '%s'\n"), prop->p_name);

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

	(void) printf(gettext("Successfully modified "
	    "'%s' description\n"), gname);

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
		return (gettext("User is disable."));

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
