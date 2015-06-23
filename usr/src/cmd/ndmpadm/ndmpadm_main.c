/*
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2015 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * BSD 3 Clause License
 *
 * Copyright (c) 2007, The Storage Networking Industry Association.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 	- Redistributions of source code must retain the above copyright
 *	  notice, this list of conditions and the following disclaimer.
 *
 * 	- Redistributions in binary form must reproduce the above copyright
 *	  notice, this list of conditions and the following disclaimer in
 *	  the documentation and/or other materials provided with the
 *	  distribution.
 *
 *	- Neither the name of The Storage Networking Industry Association (SNIA)
 *	  nor the names of its contributors may be used to endorse or promote
 *	  products derived from this software without specific prior written
 *	  permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#include <assert.h>
#include <ctype.h>
#include <libgen.h>
#include <libintl.h>
#include <locale.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <door.h>
#include <sys/mman.h>
#include <libndmp.h>
#include "ndmpadm.h"

typedef enum {
	HELP_GET_CONFIG,
	HELP_SET_CONFIG,
	HELP_SHOW_DEVICES,
	HELP_SHOW_SESSIONS,
	HELP_KILL_SESSIONS,
	HELP_ENABLE_AUTH,
	HELP_DISABLE_AUTH
} ndmp_help_t;

typedef struct ndmp_command {
	const char	*nc_name;
	int		(*func)(int argc, char **argv,
			    struct ndmp_command *cur_cmd);
	ndmp_help_t	nc_usage;
} ndmp_command_t;

static int ndmp_get_config(int, char **, ndmp_command_t *);
static int ndmp_set_config(int, char **, ndmp_command_t *);
static int ndmp_show_devices(int, char **, ndmp_command_t *);
static int ndmp_show_sessions(int, char **, ndmp_command_t *);
static int ndmp_kill_sessions(int, char **, ndmp_command_t *);
static int ndmp_enable_auth(int, char **, ndmp_command_t *);
static int ndmp_disable_auth(int, char **, ndmp_command_t *);
static void ndmp_get_config_process(char *);
static void ndmp_set_config_process(char *arg);
static int ndmp_get_password(char **);

static ndmp_command_t command_table[] = {
	{ "get",		ndmp_get_config,	HELP_GET_CONFIG	},
	{ "set",		ndmp_set_config,	HELP_SET_CONFIG	},
	{ "show-devices",	ndmp_show_devices,	HELP_SHOW_DEVICES },
	{ "show-sessions",	ndmp_show_sessions,	HELP_SHOW_SESSIONS },
	{ "kill-sessions",	ndmp_kill_sessions,	HELP_KILL_SESSIONS },
	{ "enable",		ndmp_enable_auth,	HELP_ENABLE_AUTH },
	{ "disable",		ndmp_disable_auth,	HELP_DISABLE_AUTH }
};

#define	NCOMMAND	(sizeof (command_table) / sizeof (command_table[0]))

static char *prop_table[] = {
	"debug-path",
	"dump-pathnode",
	"tar-pathnode",
	"ignore-ctime",
	"token-maxseq",
	"version",
	"dar-support",
	"tcp-port",
	"backup-quarantine",
	"restore-quarantine",
	"overwrite-quarantine",
	"zfs-force-override",
	"drive-type",
	"debug-mode"
};

#define	NDMPADM_NPROP	(sizeof (prop_table) / sizeof (prop_table[0]))

typedef struct ndmp_auth {
	const char *auth_type;
	const char *username;
	const char *password;
} ndmp_auth_t;

static ndmp_auth_t ndmp_auth_table[] = {
	{ "cram-md5", "cram-md5-username", "cram-md5-password" },
	{ "cleartext", "cleartext-username", "cleartext-password" }
};
#define	NAUTH	(sizeof (ndmp_auth_table) / sizeof (ndmp_auth_table[0]))
#define	NDMP_PASSWORD_RETRIES	3

#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN	"SYS_TEST"
#endif

static const char *
get_usage(ndmp_help_t idx)
{
	switch (idx) {
	case HELP_SET_CONFIG:
		return ("\tset [-p] <property=value> [[-p] property=value] "
		    "...\n");
	case HELP_GET_CONFIG:
		return ("\tget [-p] [property] [[-p] property] ...\n");
	case HELP_SHOW_DEVICES:
		return ("\tshow-devices\n");
	case HELP_SHOW_SESSIONS:
		return ("\tshow-sessions [-i tape,scsi,data,mover] [id] ...\n");
	case HELP_KILL_SESSIONS:
		return ("\tkill-sessions <id ...>\n");
	case HELP_ENABLE_AUTH:
		return ("\tenable <-a auth-type> <-u username>\n");
	case HELP_DISABLE_AUTH:
		return ("\tdisable <-a auth-type>\n");
	}

	return (NULL);
}

/*
 * Display usage message.  If we're inside a command, display only the usage for
 * that command.  Otherwise, iterate over the entire command table and display
 * a complete usage message.
 */
static void
usage(boolean_t requested, ndmp_command_t *current_command)
{
	int i;
	boolean_t show_properties = B_FALSE;
	FILE *fp = requested ? stdout : stderr;

	if (current_command == NULL) {
		(void) fprintf(fp,
		    gettext("Usage: ndmpadm subcommand args ...\n"));
		(void) fprintf(fp,
		    gettext("where 'command' is one of the following:\n\n"));

		for (i = 0; i < NCOMMAND; i++) {
			(void) fprintf(fp, "%s",
			    get_usage(command_table[i].nc_usage));
		}
		(void) fprintf(fp, gettext("\t\twhere %s can be either "
		    "%s or %s\n"), "'auth-type'", "'cram-md5'", "'cleartext'");
	} else {
		(void) fprintf(fp, gettext("Usage:\n"));
		(void) fprintf(fp, "%s", get_usage(current_command->nc_usage));
		if ((current_command->nc_usage == HELP_ENABLE_AUTH) ||
		    (current_command->nc_usage == HELP_DISABLE_AUTH))
			(void) fprintf(fp, gettext("\t\twhere %s can be either "
			    "%s or %s\n"),
			    "'auth-type'", "'cram-md5'", "'cleartext'");
	}

	if (current_command != NULL &&
	    (strcmp(current_command->nc_name, "set") == 0))
		show_properties = B_TRUE;

	if (show_properties) {
		(void) fprintf(fp,
		    gettext("\nThe following properties are supported:\n"));

		(void) fprintf(fp, gettext("\n\tPROPERTY"));
		(void) fprintf(fp, "\n\t%s", "-------------");
		for (i = 0; i < NDMPADM_NPROP; i++)
			(void) fprintf(fp, "\n\t%s", prop_table[i]);
		(void) fprintf(fp, "\n");
	}

	exit(requested ? 0 : 2);
}

/*ARGSUSED*/
static int
ndmp_get_config(int argc, char **argv, ndmp_command_t *cur_cmd)
{
	char *propval;
	int i, c;

	if (argc == 1) {
		/*
		 * Get all the properties and variables ndmpadm is allowed
		 * to see.
		 */
		for (i = 0; i < NDMPADM_NPROP; i++) {
			if (ndmp_get_prop(prop_table[i], &propval)) {
				(void) fprintf(stdout, "\t%s=\n",
				    prop_table[i]);
			} else {
				(void) fprintf(stdout, "\t%s=%s\n",
				    prop_table[i], propval);
				free(propval);
			}
		}
	} else if (argc > 1) {
		while ((c = getopt(argc, argv, ":p:")) != -1) {
			switch (c) {
			case 'p':
				ndmp_get_config_process(optarg);
				break;
			case ':':
				(void) fprintf(stderr, gettext("Option -%c "
				    "requires an operand\n"), optopt);
				break;
			case '?':
				(void) fprintf(stderr, gettext("Unrecognized "
				    "option: -%c\n"), optopt);
			}
		}
		/*
		 * optind is initialized to 1 if the -p option is not used,
		 * otherwise index to argv.
		 */
		argc -= optind;
		argv += optind;

		for (i = 0; i < argc; i++) {
			if (strncmp(argv[i], "-p", 2) == 0)
				continue;

			ndmp_get_config_process(argv[i]);
		}
	}
	return (0);
}

static void
ndmp_get_config_process(char *arg)
{
	int j;
	char *propval;

	for (j = 0; j < NDMPADM_NPROP; j++) {
		if (strcmp(arg, prop_table[j]) == 0) {
			if (ndmp_get_prop(arg, &propval)) {
				(void) fprintf(stdout, "\t%s=\n", arg);
			} else {
				(void) fprintf(stdout, "\t%s=%s\n",
				    arg, propval);
				free(propval);
			}
			break;
		}
	}
	if (j == NDMPADM_NPROP) {
		(void) fprintf(stdout, gettext("\t%s is invalid property "
		    "or variable\n"), arg);
	}
}

/*ARGSUSED*/
static int
ndmp_set_config(int argc, char **argv, ndmp_command_t *cur_cmd)
{
	int c, i;

	if (argc < 2) {
		(void) fprintf(stderr, gettext("Missing property=value "
		    "argument\n"));
		usage(B_FALSE, cur_cmd);
	}
	while ((c = getopt(argc, argv, ":p:")) != -1) {
		switch (c) {
		case 'p':
			ndmp_set_config_process(optarg);
			break;
		case ':':
			(void) fprintf(stderr, gettext("Option -%c "
			    "requires an operand\n"), optopt);
			break;
		case '?':
			(void) fprintf(stderr, gettext("Unrecognized "
			    "option: -%c\n"), optopt);
		}
	}
	/*
	 * optind is initialized to 1 if the -p option is not used,
	 * otherwise index to argv.
	 */
	argc -= optind;
	argv += optind;

	for (i = 0; i < argc; i++) {
		if (strncmp(argv[i], "-p", 2) == 0)
			continue;

		ndmp_set_config_process(argv[i]);
	}
	return (0);
}

static void
ndmp_set_config_process(char *propname)
{
	char *propvalue;
	int ret, j;

	if ((propvalue = strchr(propname, '=')) == NULL) {
		(void) fprintf(stderr, gettext("Missing value in "
		    "property=value argument for %s\n"), propname);
			return;
	}
	*propvalue = '\0';
	propvalue++;

	if (*propname == '\0') {
		(void) fprintf(stderr, gettext("Missing property in "
		    "property=value argument for %s\n"), propname);
			return;
	}
	for (j = 0; j < NDMPADM_NPROP; j++) {
		if (strcmp(propname, prop_table[j]) == 0)
			break;
	}
	if (j == NDMPADM_NPROP) {
		(void) fprintf(stdout, gettext("%s is invalid property or "
		    "variable\n"), propname);
		return;
	}
	ret = ndmp_set_prop(propname, propvalue);
	if (ret != -1) {
		if (!ndmp_door_status()) {
			if (ndmp_service_refresh() != 0)
				(void) fprintf(stdout, gettext("Could not "
				    "refesh property of service ndmpd\n"));
		}
	} else {
		(void) fprintf(stdout, gettext("Could not set property for "
		    "%s - %s\n"), propname, ndmp_strerror(ndmp_errno));
	}
}

/*ARGSUSED*/
static int
ndmp_show_devices(int argc, char **argv, ndmp_command_t *cur_cmd)
{
	int ret;
	ndmp_devinfo_t *dip = NULL;
	size_t size;

	if (ndmp_door_status()) {
		(void) fprintf(stdout,
		    gettext("Service ndmpd not running\n"));
		return (-1);
	}

	ret = ndmp_get_devinfo(&dip, &size);

	if (ret == -1)
		(void) fprintf(stdout,
		    gettext("Could not get device information\n"));
	else
		ndmp_devinfo_print(dip, size);

	ndmp_get_devinfo_free(dip, size);
	return (0);
}

static int
ndmp_show_sessions(int argc, char **argv, ndmp_command_t *cur_cmd)
{
	ndmp_session_info_t *sinfo = NULL;
	ndmp_session_info_t *sp = NULL;
	uint_t num;
	int c, ret, i, j;
	int statarg = 0;
	char *value;
	char *type_subopts[] = { "tape", "scsi", "data", "mover", NULL };

	if (ndmp_door_status()) {
		(void) fprintf(stdout,
		    gettext("Service ndmpd not running\n"));
		return (-1);
	}

	/* Detail output if no option is specified */
	if (argc == 1) {
		statarg = NDMP_CAT_ALL;
	} else {
		statarg = 0;
		while ((c = getopt(argc, argv, ":i:")) != -1) {
			switch (c) {
			case 'i':
				while (*optarg != '\0') {
					switch (getsubopt(&optarg, type_subopts,
					    &value)) {
					case 0:
						statarg |= NDMP_CAT_TAPE;
						break;
					case 1:
						statarg |= NDMP_CAT_SCSI;
						break;
					case 2:
						statarg |= NDMP_CAT_DATA;
						break;
					case 3:
						statarg |= NDMP_CAT_MOVER;
						break;
					default:
						(void) fprintf(stderr,
						    gettext("Invalid object "
						    "type '%s'\n"), value);
						usage(B_FALSE, cur_cmd);
					}
				}
				break;
			case ':':
				(void) fprintf(stderr,
				    gettext("Missing argument for "
				    "'%c' option\n"), optopt);
				usage(B_FALSE, cur_cmd);
				break;
			case '?':
				(void) fprintf(stderr,
				    gettext("Invalid option '%c'\n"), optopt);
				usage(B_FALSE, cur_cmd);
			}
		}
		/* if -i and its argument are not specified, display all */
		if (statarg == 0)
			statarg = NDMP_CAT_ALL;
	}
	/*
	 * optind is initialized to 1 if the -i option is not used, otherwise
	 * index to argv.
	 */
	argc -= optind;
	argv += optind;

	ret = ndmp_get_session_info(&sinfo, &num);
	if (ret == -1) {
		(void) fprintf(stdout,
		    gettext("Could not get session information\n"));
	} else {
		if (argc == 0) {
			ndmp_session_all_print(statarg, sinfo, num);
		} else {
			for (i = 0; i < argc; i++) {
				sp = sinfo;
				for (j = 0; j < num; j++, sp++) {
					if (sp->nsi_sid == atoi(argv[i])) {
						ndmp_session_print(statarg, sp);
						(void) fprintf(stdout, "\n");
						break;
					}
				}
				if (j == num) {
					(void) fprintf(stdout,
					    gettext("Session %d not "
					    "found\n"), atoi(argv[i]));
				}
			}
		}
		ndmp_get_session_info_free(sinfo, num);
	}
	return (0);
}

/*ARGSUSED*/
static int
ndmp_kill_sessions(int argc, char **argv, ndmp_command_t *cur_cmd)
{
	int ret, i;

	if (ndmp_door_status()) {
		(void) fprintf(stdout,
		    gettext("Service ndmpd not running.\n"));
		return (-1);
	}

	/* If no arg is specified, print the usage and exit */
	if (argc == 1)
		usage(B_FALSE, cur_cmd);

	for (i = 1; i < argc; i++) {
		if (atoi(argv[i]) > 0) {
			ret = ndmp_terminate_session(atoi(argv[i]));
		} else {
			(void) fprintf(stderr,
			    gettext("Invalid argument %s\n"), argv[i]);
				continue;
		}
		if (ret == -1)
			(void) fprintf(stdout,
			    gettext("Session id %d not found.\n"),
			    atoi(argv[i]));
	}
	return (0);
}

static int
ndmp_get_password(char **password)
{
	char *pw1, pw2[257];
	int i;

	for (i = 0; i < NDMP_PASSWORD_RETRIES; i++) {
		/*
		 * getpassphrase use the same buffer to return password, so
		 * copy the result in different buffer, before calling the
		 * getpassphrase again.
		 */
		if ((pw1 =
		    getpassphrase(gettext("Enter new password: "))) != NULL) {
			(void) strlcpy(pw2, pw1, sizeof (pw2));
			if ((pw1 =
			    getpassphrase(gettext("Re-enter  password: ")))
			    != NULL) {
				if (strncmp(pw1, pw2, strlen(pw1)) == 0) {
					*password = pw1;
					return (0);
				} else {
					(void) fprintf(stderr,
					    gettext("Both password did not "
					    "match.\n"));
				}
			}
		}
	}
	return (-1);
}

static int
ndmp_enable_auth(int argc, char **argv, ndmp_command_t *cur_cmd)
{
	char *auth_type, *username, *password;
	int c, i, auth_type_flag = 0;
	char *enc_password;

	/* enable <-a auth-type> <-u username> */
	if (argc != 5) {
		usage(B_FALSE, cur_cmd);
	}

	while ((c = getopt(argc, argv, ":a:u:")) != -1) {
		switch (c) {
		case 'a':
			auth_type = strdup(optarg);
			break;
		case 'u':
			username = strdup(optarg);
			break;
		case ':':
			(void) fprintf(stderr, gettext("Option -%c "
			    "requires an operand\n"), optopt);
			usage(B_FALSE, cur_cmd);
			break;
		case '?':
			(void) fprintf(stderr, gettext("Unrecognized "
			    "option: -%c\n"), optopt);
			usage(B_FALSE, cur_cmd);
		}
	}

	if ((auth_type) && (username)) {
		if (ndmp_get_password(&password)) {
			(void) fprintf(stderr, gettext("Could not get correct "
			    "password, exiting..."));
			free(auth_type);
			free(username);
			exit(-1);
		}
	} else {
		(void) fprintf(stderr, gettext("%s or %s can not be blank"),
		    "'auth-type'", "'username'");
		free(auth_type);
		free(username);
		exit(-1);
	}

	if ((enc_password = ndmp_base64_encode(password)) == NULL) {
		(void) fprintf(stdout,
		    gettext("Could not encode password - %s\n"),
		    ndmp_strerror(ndmp_errno));
		free(auth_type);
		free(username);
		exit(-1);
	}

	for (i = 0; i < NAUTH; i++) {
		if (strncmp(auth_type, ndmp_auth_table[i].auth_type,
		    strlen(ndmp_auth_table[i].auth_type)) == 0) {
			auth_type_flag = 1;
			if ((ndmp_set_prop(ndmp_auth_table[i].username,
			    username)) == -1) {
				(void) fprintf(stdout,
				    gettext("Could not set username - %s\n"),
				    ndmp_strerror(ndmp_errno));
				continue;
			}
			if ((ndmp_set_prop(ndmp_auth_table[i].password,
			    enc_password)) == -1) {
				(void) fprintf(stdout,
				    gettext("Could not set password - %s\n"),
				    ndmp_strerror(ndmp_errno));
				continue;
			}
			if (!ndmp_door_status() &&
			    (ndmp_service_refresh()) != 0) {
				(void) fprintf(stdout,
				    gettext("Could not refesh ndmpd service "
				    "properties\n"));
			}
		}
	}
	free(auth_type);
	free(username);
	free(enc_password);

	if (!auth_type_flag)
		usage(B_FALSE, cur_cmd);

	return (0);
}

static int
ndmp_disable_auth(int argc, char **argv, ndmp_command_t *cur_cmd)
{
	char *auth_type;
	int c, i, auth_type_flag = 0;

	/* disable <-a auth-type> */
	if (argc != 3) {
		usage(B_FALSE, cur_cmd);
	}

	while ((c = getopt(argc, argv, ":a:")) != -1) {
		switch (c) {
		case 'a':
			auth_type = strdup(optarg);
			break;
		case ':':
			(void) fprintf(stderr, gettext("Option -%c "
			    "requires an operand\n"), optopt);
			break;
		case '?':
			(void) fprintf(stderr, gettext("Unrecognized "
			    "option: -%c\n"), optopt);
		}
	}
	for (i = 0; i < NAUTH; i++) {
		if (strncmp(auth_type, ndmp_auth_table[i].auth_type,
		    strlen(ndmp_auth_table[i].auth_type)) == 0) {
			auth_type_flag = 1;
			if ((ndmp_set_prop(ndmp_auth_table[i].username,
			    "")) == -1) {
				(void) fprintf(stdout,
				    gettext("Could not clear username - %s\n"),
				    ndmp_strerror(ndmp_errno));
				continue;
			}
			if ((ndmp_set_prop(ndmp_auth_table[i].password,
			    "")) == -1) {
				(void) fprintf(stdout,
				    gettext("Could not clear password - %s\n"),
				    ndmp_strerror(ndmp_errno));
				continue;
			}
			if (!ndmp_door_status() &&
			    (ndmp_service_refresh()) != 0) {
				(void) fprintf(stdout, gettext("Could not "
				    "refesh ndmpd service properties\n"));
			}
		}
	}
	free(auth_type);

	if (!auth_type_flag)
		usage(B_FALSE, cur_cmd);

	return (0);
}

int
main(int argc, char **argv)
{
	int ret;
	int i;
	char *cmdname;
	ndmp_command_t	*current_command = NULL;

	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	opterr = 0;

	/* Make sure the user has specified some command. */
	if (argc < 2) {
		(void) fprintf(stderr, gettext("Missing command.\n"));
		usage(B_FALSE, current_command);
	}

	cmdname = argv[1];

	/*
	 * Special case '-?'
	 */
	if (strcmp(cmdname, "-?") == 0)
		usage(B_TRUE, current_command);

	/*
	 * Run the appropriate sub-command.
	 */
	for (i = 0; i < NCOMMAND; i++) {
		if (strcmp(cmdname, command_table[i].nc_name) == 0) {
			current_command = &command_table[i];
			ret = command_table[i].func(argc - 1, argv + 1,
			    current_command);
			break;
		}
	}

	if (i == NCOMMAND) {
		(void) fprintf(stderr, gettext("Unrecognized "
		    "command '%s'\n"), cmdname);
		usage(B_FALSE, current_command);
	}

	return (ret);
}
