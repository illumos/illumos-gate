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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <getopt.h>
#include <libgen.h>

#include "libshare.h"
#include <sharemgr.h>

#include <libintl.h>
#include <locale.h>

static int run_command(char *, int, char **, sa_handle_t);
static void sub_command_help(char *proto);

static void
global_help()
{
	(void) printf(gettext("usage: sharectl <command> [options]\n"));
	sub_command_help(NULL);
}

int
main(int argc, char *argv[])
{
	int c;
	int help = 0;
	int rval;
	char *command;
	sa_handle_t handle;

	/*
	 * make sure locale and gettext domain is setup
	 */
	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	handle = sa_init(SA_INIT_CONTROL_API);

	while ((c = getopt(argc, argv, "h?")) != EOF) {
	    switch (c) {
	    case '?':
	    case 'h':
		help = 1;
		break;
	    default:
		(void) printf(gettext("Invalid option: %c\n"), c);
	    }
	}
	if (optind == argc || help) {
	    /* no subcommand */
	    global_help();
	    exit(0);
	}
	optind = 1;

	/*
	 * now have enough to parse rest of command line
	 */
	command = argv[optind];
	rval = run_command(command, argc - optind, argv + optind, handle);

	sa_fini(handle);
	return (rval);
}

char *
sc_get_usage(sc_usage_t index)
{
	char *ret = NULL;

	switch (index) {
	case USAGE_CTL_GET:
	    ret = gettext("get [-h | -p property ...] proto");
	    break;
	case USAGE_CTL_SET:
	    ret = gettext("set [-h] -p property=value ... proto");
	    break;
	case USAGE_CTL_STATUS:
	    ret = gettext("status [-h | proto ...]");
	    break;
	}
	return (ret);
}

/*ARGSUSED*/
static int
sc_get(sa_handle_t handle, int flags, int argc, char *argv[])
{
	char *proto = NULL;
	struct options *optlist = NULL;
	int ret = SA_OK;
	int c;

	while ((c = getopt(argc, argv, "?hp:")) != EOF) {
	    switch (c) {
	    case 'p':
		ret = add_opt(&optlist, optarg, 1);
		if (ret != SA_OK) {
		    (void) printf(gettext("Problem with property: %s\n"),
						optarg);
		    return (SA_NO_MEMORY);
		}
		break;
	    default:
		(void) printf(gettext("usage: %s\n"),
				sc_get_usage(USAGE_CTL_GET));
		return (SA_SYNTAX_ERR);
	    case '?':
	    case 'h':
		(void) printf(gettext("usage: %s\n"),
				sc_get_usage(USAGE_CTL_GET));
		return (SA_OK);
		break;
	    }
	}

	if (optind >= argc) {
	    (void) printf(gettext("usage: %s\n"), sc_get_usage(USAGE_CTL_GET));
	    (void) printf(gettext("\tprotocol must be specified.\n"));
	    return (SA_INVALID_PROTOCOL);
	}

	proto = argv[optind];
	if (sa_valid_protocol(proto)) {
	    sa_protocol_properties_t propset;
	    propset = sa_proto_get_properties(proto);
	    if (propset != NULL) {
		sa_property_t prop;
		char *value;
		char *name;
		if (optlist == NULL) {
		    /* display all known properties for this protocol */
		    for (prop = sa_get_protocol_property(propset, NULL);
			prop != NULL;
			prop = sa_get_next_protocol_property(prop)) {

			/* get and display the property and value */
			name = sa_get_property_attr(prop, "type");
			if (name != NULL) {
			    value = sa_get_property_attr(prop, "value");
			    (void) printf(gettext("%s=%s\n"), name,
						value != NULL ? value : "");
			}
			if (value != NULL)
			    sa_free_attr_string(value);
			if (name != NULL)
			    sa_free_attr_string(name);
		    }
		} else {
		    struct options *opt;
		    /* list the specified option(s) */
		    for (opt = optlist; opt != NULL; opt = opt->next) {
			prop = sa_get_protocol_property(propset, opt->optname);
			if (prop != NULL) {
			    value = sa_get_property_attr(prop, "value");
			    (void) printf(gettext("%s=%s\n"), opt->optname,
					value != NULL ? value : "");
			    sa_free_attr_string(value);
			} else {
			    (void) printf(gettext("%s: not defined\n"),
						opt->optname);
			    ret = SA_NO_SUCH_PROP;
			}
		    }
		}
	    }
	} else {
	    (void) printf(gettext("Invalid protocol specified: %s\n"), proto);
	    ret = SA_INVALID_PROTOCOL;
	}
	return (ret);
}

/*ARGSUSED*/
static int
sc_set(sa_handle_t handle, int flags, int argc, char *argv[])
{
	char *proto = NULL;
	struct options *optlist = NULL;
	int ret = SA_OK;
	int c;

	while ((c = getopt(argc, argv, "?hp:")) != EOF) {
	    switch (c) {
	    case 'p':
		ret = add_opt(&optlist, optarg, 0);
		if (ret != SA_OK) {
		    (void) printf(gettext("Problem with property: %s\n"),
					optarg);
		    return (SA_NO_MEMORY);
		}
		break;
	    default:
		(void) printf(gettext("usage: %s\n"),
				sc_get_usage(USAGE_CTL_SET));
		return (SA_SYNTAX_ERR);
	    case '?':
	    case 'h':
		(void) printf(gettext("usage: %s\n"),
				sc_get_usage(USAGE_CTL_SET));
		return (SA_OK);
		break;
	    }
	}

	if (optind >= argc) {
	    (void) printf(gettext("usage: %s\n"),
				sc_get_usage(USAGE_CTL_SET));
	    (void) printf(gettext("\tprotocol must be specified.\n"));
	    return (SA_INVALID_PROTOCOL);
	}

	proto = argv[optind];
	if (sa_valid_protocol(proto)) {
	    sa_protocol_properties_t propset;
	    propset = sa_proto_get_properties(proto);
	    if (propset != NULL) {
		sa_property_t prop;
		int err;

		if (optlist == NULL) {
		    (void) printf(gettext("usage: %s\n"),
				sc_get_usage(USAGE_CTL_SET));
		    (void) printf(gettext("\tat least one property and value "
				    "must be specified\n"));
		} else {
		    struct options *opt;
		    /* list the specified option(s) */
		    for (opt = optlist; opt != NULL; opt = opt->next) {
			prop = sa_get_protocol_property(propset, opt->optname);
			if (prop != NULL) {
				/*
				 * "err" is used in order to prevent
				 * setting ret to SA_OK if there has
				 * been a real error. We want to be
				 * able to return an error status on
				 * exit in that case. Error messages
				 * are printed for each error, so we
				 * only care on exit that there was an
				 * error and not the specific error
				 * value.
				 */
			    err = sa_set_protocol_property(prop, opt->optvalue);
			    if (err != SA_OK) {
				(void) printf(gettext("Could not set property"
							" %s: %s\n"),
					opt->optname, sa_errorstr(err));
				ret = err;
			    }
			} else {
			    (void) printf(gettext("%s: not defined\n"),
						opt->optname);
			    ret = SA_NO_SUCH_PROP;
			}
		    }
		}
	    }
	} else {
	    (void) printf(gettext("Invalid protocol specified: %s\n"), proto);
	    ret = SA_INVALID_PROTOCOL;
	}
	return (ret);
}

static void
show_status(char *proto)
{
	char *status;
	status = sa_get_protocol_status(proto);
	(void) printf("%s\t%s\n", proto, status ? gettext(status) : "-");
	if (status != NULL)
	    free(status);
}

static int
valid_proto(char **protos, int num, char *proto)
{
	int i;
	for (i = 0; i < num; i++)
	    if (strcmp(protos[i], proto) == 0)
		return (1);
	return (0);
}

/*ARGSUSED*/
static int
sc_status(sa_handle_t handle, int flags, int argc, char *argv[])
{
	char **protos;
	int ret = SA_OK;
	int c;
	int i;
	int num_proto;
	int verbose = 0;

	while ((c = getopt(argc, argv, "?hv")) != EOF) {
	    switch (c) {
	    case 'v':
		verbose++;
		break;
	    case '?':
	    case 'h':
		(void) printf(gettext("usage: %s\n"),
				sc_get_usage(USAGE_CTL_STATUS));
		return (SA_OK);
	    default:
		(void) printf(gettext("usage: %s\n"),
				sc_get_usage(USAGE_CTL_STATUS));
		return (SA_SYNTAX_ERR);
	    }
	}

	num_proto = sa_get_protocols(&protos);
	if (optind == argc) {
	    /* status for all protocols */
	    for (i = 0; i < num_proto; i++) {
		show_status(protos[i]);
	    }
	} else {
	    for (i = optind; i < argc; i++) {
		if (valid_proto(protos, num_proto, argv[i])) {
		    show_status(argv[i]);
		} else {
		    (void) printf(gettext("Invalid protocol: %s\n"), argv[i]);
		    ret = SA_INVALID_PROTOCOL;
		}
	    }
	}
	if (protos != NULL)
	    free(protos);
	return (ret);
}

static sa_command_t commands[] = {
	{"get", 0, sc_get, USAGE_CTL_GET},
	{"set", 0, sc_set, USAGE_CTL_SET},
	{"status", 0, sc_status, USAGE_CTL_STATUS},
	{NULL, 0, NULL, 0},
};

/*ARGSUSED*/
void
sub_command_help(char *proto)
{
	int i;

	(void) printf("\tsub-commands:\n");
	for (i = 0; commands[i].cmdname != NULL; i++) {
		if (!(commands[i].flags & (CMD_ALIAS|CMD_NODISPLAY)))
			(void) printf("\t%s\n",
				sc_get_usage((sc_usage_t)commands[i].cmdidx));
	}
}

sa_command_t *
sa_lookup(char *cmd)
{
	int i;
	size_t len;

	len = strlen(cmd);
	for (i = 0; commands[i].cmdname != NULL; i++) {
		if (strncmp(cmd, commands[i].cmdname, len) == 0)
			return (&commands[i]);
	}
	return (NULL);
}

static int
run_command(char *command, int argc, char *argv[], sa_handle_t handle)
{
	sa_command_t *cmdvec;
	int ret;

	/*
	 * To get here, we know there should be a command due to the
	 * preprocessing done earlier.  Need to find the protocol
	 * that is being affected. If no protocol, then it is ALL
	 * protocols.
	 *
	 * ??? do we really need the protocol at this level? it may be
	 * sufficient to let the commands look it up if needed since
	 * not all commands do proto specific things
	 *
	 * Known sub-commands are handled at this level. An unknown
	 * command will be passed down to the shared object that
	 * actually implements it. We can do this since the semantics
	 * of the common sub-commands is well defined.
	 */

	cmdvec = sa_lookup(command);
	if (cmdvec == NULL) {
		(void) printf(gettext("command %s not found\n"), command);
		exit(1);
	}
	/*
	 * need to check priviledges and restrict what can be done
	 * based on least priviledge and sub-command.
	 */
	ret = cmdvec->cmdfunc(handle, NULL, argc, argv);
	return (ret);
}
