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
#include <string.h>
#include <unistd.h>
#include <strings.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <libilb.h>
#include "ilbadm.h"

static ilbadm_cmd_help_t create_sg_help = {
"[-s server=hostspec[:portspec...]] groupname"
};

static ilbadm_cmd_help_t create_rule_help = {
"[-e] [-p] -i vip=value,port=value[,protocol=value] \n"			\
"	-m lbalg=value,type=value[,proxy-src=ip-range][,pmask=mask] \n"\
"	-h hc-name=value[,hc-port=value]] \n"                           \
"	[-t [conn-drain=N][,nat-timeout=N][,persist-timeout=N]] \n"     \
"	-o servergroup=value name"
};

static ilbadm_cmd_help_t destroy_rule_help = {
"-a | name ..."
};

static ilbadm_cmd_help_t add_server_help = {
"-s server=value[,value ...] servergroup"
};

static ilbadm_cmd_help_t remove_server_help = {
"-s server=value[,value ...] servergroup"
};


static ilbadm_cmd_help_t disable_server_help = {
"server ... "
};

static ilbadm_cmd_help_t enable_server_help = {
"server ..."
};

static ilbadm_cmd_help_t enable_rule_help = {
"[name ... ]"
};

static ilbadm_cmd_help_t disable_rule_help = {
"[name ... ]"
};

static ilbadm_cmd_help_t show_server_help = {
"[[-p] -o field[,field...]] [rulename ... ]"
};

static ilbadm_cmd_help_t showstats_help = {
"[-p] -o field[,...]] [-tdAvi]\n"				\
"	[-r rulename|-s servername] [interval [count]]"
};

static ilbadm_cmd_help_t show_nat_help = {
"[count]"
};

static ilbadm_cmd_help_t show_persist_help = {
"[count]"
};

static ilbadm_cmd_help_t show_hc_help = {
"[hc-name]"
};

static ilbadm_cmd_help_t create_hc_help = {
"[-n] -h hc-test=value[,hc-timeout=value]\n"			\
"	[,hc-count=value][,hc-interval=value] hcname"
};

static ilbadm_cmd_help_t destroy_hc_help = {
"name ..."
};

static ilbadm_cmd_help_t show_hc_result_help = {
"[rule-name]"
};

static ilbadm_cmd_help_t show_rule_help = {
"[-e|-d] [-f |[-p] -o key[,key ...]] [name ...]"
};

static ilbadm_cmd_help_t destroy_servergroup_help = {
"groupname"
};

static ilbadm_cmd_help_t show_servergroup_help = {
"[[-p] -o field[,field]] [name]"
};

static ilbadm_cmd_help_t export_config_help = {
"[filename]"
};

static ilbadm_cmd_help_t import_config_help = {
"[-p] [filename]"
};
static ilbadm_cmd_desc_t ilbadm_cmds[] = {
	{"create-rule", "create-rl", ilbadm_create_rule, &create_rule_help},
	{"delete-rule", "delete-rl", ilbadm_destroy_rule, &destroy_rule_help},
	{"enable-rule", "enable-rl", ilbadm_enable_rule, &enable_rule_help},
	{"disable-rule", "disable-rl", ilbadm_disable_rule,
	    &disable_rule_help},
	{"show-rule", "show-rl", ilbadm_show_rules, &show_rule_help},

	{"create-servergroup", "create-sg", ilbadm_create_servergroup,
	    &create_sg_help},
	{"delete-servergroup", "delete-sg", ilbadm_destroy_servergroup,
	    &destroy_servergroup_help},
	{"show-servergroup", "show-sg", ilbadm_show_servergroups,
	    &show_servergroup_help},

	{"add-server", "add-srv", ilbadm_add_server_to_group,
	    &add_server_help},
	{"remove-server", "remove-srv", ilbadm_rem_server_from_group,
	    &remove_server_help},
	{"disable-server", "disable-srv", ilbadm_disable_server,
	    &disable_server_help},
	{"enable-server", "enable-srv", ilbadm_enable_server,
	    &enable_server_help},
	{"show-server", "show-srv", ilbadm_show_server,
	    &show_server_help},

	{"show-healthcheck", "show-hc", ilbadm_show_hc, &show_hc_help},
	{"create-healthcheck", "create-hc", ilbadm_create_hc, &create_hc_help},
	{"delete-healthcheck", "delete-hc", ilbadm_destroy_hc,
	    &destroy_hc_help},
	{"show-hc-result", "show-hc-res", ilbadm_show_hc_result,
	    &show_hc_result_help},

	{"export-config", "export-cf", ilbadm_export, &export_config_help},
	{"import-config", "import-cf", ilbadm_noimport, &import_config_help},

	{"show-statistics", "show-stats", ilbadm_show_stats, &showstats_help},
	{"show-nat", "show-nat", ilbadm_show_nat, &show_nat_help},
	{"show-persist", "show-pt", ilbadm_show_persist,
	    &show_persist_help},
	{"", "", NULL, NULL}
};


/* ARGSUSED */
ilbadm_status_t
ilbadm_noimport(int argc, char *argv[])
{
	ilbadm_err(ilbadm_errstr(ILBADM_NORECURSIVE));
	return (ILBADM_LIBERR);
}

static void
print_cmd_short(char *name, FILE *fp, ilbadm_cmd_desc_t *cmd)
{
	char	*h;

	while (cmd->c_name[0] != '\0') {
		if (cmd->c_help != NULL &&
		    (h = cmd->c_help->h_help) != NULL)
			(void) fprintf(fp, "%s %s|%s %s\n", name,
			    cmd->c_name, cmd->c_alias, h);
		else
			(void) fprintf(fp, "%s %s|%s\n", name, cmd->c_name,
			    cmd->c_alias);
		cmd++;
	}
}

void
print_cmdlist_short(char *name, FILE *fp)
{
	print_cmd_short(name, fp, ilbadm_cmds);
}

#define	IMPORT_FILE	0x1

static void
match_cmd(char *name, ilbadm_cmd_desc_t *cmds, cmdfunc_t *action, int flags)
{
	ilbadm_cmd_desc_t	*cmd;

	if ((flags & IMPORT_FILE) == IMPORT_FILE) {
		if (strcasecmp(name, "export-config") == 0 ||
		    strcasecmp(name, "export-cf") == 0) {
			ilbadm_err(gettext("export from import file"
			    " not allowed"));
			exit(1);
		}
	}

	for (cmd = &cmds[0]; cmd->c_name[0] != '\0'; cmd++) {
		if (strncasecmp(cmd->c_name, name, sizeof (cmd->c_name)) == 0 ||
		    strncasecmp(cmd->c_alias, name, sizeof (cmd->c_alias)) == 0)
			break;
	}
	*action = cmd->c_action;
}

/*
 * read and parse commandline
 */
static ilbadm_status_t
ilb_import_cmdline(int argc, char *argv[], int flags)
{
	ilbadm_status_t	rc = ILBADM_OK;
	cmdfunc_t	cmd;

	match_cmd(argv[0], ilbadm_cmds, &cmd, flags);

	if (*cmd != NULL) {
		rc = cmd(argc, argv);
	} else {
		rc = ILBADM_INVAL_COMMAND;
		ilbadm_err(ilbadm_errstr(rc));
	}

	return (rc);
}

#define	CHUNK	10
#define	LINESZ	1024

typedef struct {
	int	listsz;
	char	*arglist[1];
} arg_t;

static int
i_getln_to_argv(FILE *fp, arg_t **ap)
{
	static char	*linebuf = NULL;
	char	*stringp, *currp;
	char	delim[] = " \t\n";
	int	i;
	arg_t	*a = *ap;

#define	STR_DIFF(s1, s2)	(int)((char *)s2 - (char *)s1)
#define	STR_ADJ_SZ(sz, buf, s)	(sz - STR_DIFF(buf, s))

	if (linebuf == NULL)
		if ((linebuf = (char *)malloc(LINESZ)) == NULL)
			return (0);

	stringp = currp = linebuf;
	i = 0;
read_next:
	if (fgets(currp, STR_ADJ_SZ(LINESZ, linebuf, currp), fp) == NULL)
		return (i);

	/* ignore lines starting with a # character */
	if (*currp == '#')
		goto read_next;

	for (; stringp != NULL && currp != NULL; i++) {
		currp = strsep(&stringp, delim);
		/*
		 * if there's more than one adjacent delimiters ...
		 */
		if (*currp == '\0') {
			i--;
			continue;
		}
		/*
		 * if we find a '\' at the end of a line, treat
		 * it as a continuation character.
		 */
		if (*currp == '\\' && stringp == NULL) {
			stringp = currp;
			goto read_next;
		}
		if (a == NULL) {
			a = (arg_t *)malloc(sizeof (*a));
			bzero(a, sizeof (*a));
		}
		if (a->listsz <= i) {
			int	sz;

			a->listsz += CHUNK;
			sz = sizeof (*a) +
			    ((a->listsz - 1) * sizeof (a->arglist));
			a = (arg_t *)realloc(a, sz);
			*ap = a;
		}
		a->arglist[i] = currp;
	}
	return (i);
}

static ilbadm_status_t
ilb_import_file(int fd, int flags)
{
	FILE		*fp;
	arg_t		*a = NULL;
	int		argcount;
	ilbadm_status_t	rc = ILBADM_OK;

	if ((fp = fdopen(fd, "r")) == NULL) {
		ilbadm_err(gettext("cannot import file for reading"));
		exit(1);
	}

	if ((flags & ILBADM_IMPORT_PRESERVE) == 0) {
		ilb_handle_t	h = ILB_INVALID_HANDLE;
		ilb_status_t	rclib;

		rclib = ilb_open(&h);
		if (rclib == ILB_STATUS_OK)
			(void) ilb_reset_config(h);
		if (h != ILB_INVALID_HANDLE)
			(void) ilb_close(h);
	}

	while ((argcount = i_getln_to_argv(fp, &a)) > 0) {
		optind = 1;
		rc = ilb_import_cmdline(argcount, a->arglist, IMPORT_FILE);
		if (rc != ILBADM_OK)
			break;
	}

	return (rc);
}

/*
 * this is the wrapper around everything to do with importing and
 * parsing either commandline or persistent storage.
 * if (fd == -1), parse commandline, otherwise use the given fd as input.
 */
/* ARGSUSED */
ilbadm_status_t
ilbadm_import(int fd, int argc, char *argv[], int flags)
{
	ilbadm_status_t	rc;

	if (fd == -1)
		rc = ilb_import_cmdline(argc, argv, 0);
	else
		rc = ilb_import_file(fd, flags);

	return (rc);
}

ilbadm_status_t
ilbadm_export(int argc, char *argv[])
{
	ilb_handle_t	h = ILB_INVALID_HANDLE;
	ilbadm_status_t	rc = ILBADM_OK;
	ilb_status_t	rclib = ILB_STATUS_OK;
	int		fd;
	FILE		*fp;
	char		*fname = NULL;
	char		tmpfile[MAXPATHLEN];

	if (argc < 2) {
		fd = 1; 	/* stdout */
		*tmpfile = '\0';
	} else {
		fname = argv[1];
		(void) snprintf(tmpfile, sizeof (tmpfile), "%sXXXXXX", fname);
		fd = mkstemp(tmpfile);

		if (fd == -1) {
			ilbadm_err(gettext("cannot create working file"));
			exit(1);
		}
	}
	fp = fdopen(fd, "w");
	if (fp == NULL) {
		ilbadm_err(gettext("cannot open file for writing"), fd);
		exit(1);
	}

	rclib = ilb_open(&h);
	if (rclib != ILB_STATUS_OK)
		goto out;

	rc = ilbadm_export_servergroups(h, fp);
	if (rc != ILBADM_OK)
		goto out;

	rc = ilbadm_export_hc(h, fp);
	if (rc != ILBADM_OK)
		goto out;

	rc = ilbadm_export_rules(h, fp);
	if (rc != ILBADM_OK)
		goto out;

	if (fname != NULL) {
		if (rename(tmpfile, fname) == -1) {
			ilbadm_err(gettext("cannot create %s: %s"), fname,
			    strerror(errno));
			exit(1);
		}
		*tmpfile = '\0';
	}

out:
	if (h != ILB_INVALID_HANDLE)
		(void) ilb_close(h);

	if ((rc != ILBADM_OK) && (rc != ILBADM_LIBERR))
		ilbadm_err(ilbadm_errstr(rc));
	(void) fclose(fp);
	if (*tmpfile != '\0')
		(void) unlink(tmpfile);
	return (rc);
}
