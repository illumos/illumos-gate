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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Front end CLI to metassist.  Parses command line, reads in data
 * files, provides main() entry point into metassist.  Here's the
 * complete data validation stack for the project:
 *
 * 1. Controller validates command line syntax/order of arguments.
 *
 * 2. XML parser validates XML syntax, conformance with DTD
 *
 * 3. xml_convert validates proper conversion from string to
 *    size/integer/float/boolean/etc.
 *
 * 4. devconfig_t mutators validate limits/boundaries/min/max/names of
 *    data.  References md_mdiox.h and possibly libmeta.
 *
 * 5. layout validates on remaining issues, including existence of
 *    given devices, feasibility of request, suitability of specified
 *    components, and subtle misuse of data structure (like both size
 *    and components specified).
 */

#include "metassist.h"

#include <errno.h>
#include <libintl.h>

#include <math.h>
#include <signal.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>
#include "getopt_ext.h"
#include "locale.h"
#include "volume_error.h"
#include "volume_output.h"
#include "volume_request.h"
#include "volume_defaults.h"
#include "volume_string.h"
#include "xml_convert.h"
#include "layout.h"

/*
 * Function prototypes
 */

static void clean_up();
static void interrupthandler(int x);
static int copy_arg(char *option, char *value, char **saveto);
static xmlDocPtr create_volume_request_XML();
static int handle_common_opts(int c, boolean_t *handled);
static int parse_create_opts(int argc, char *argv[]);
static int parse_opts(int argc, char *argv[]);
static int parse_tokenized_list(const char *string, dlist_t **list);
static int parse_verbose_arg(char *arg, int *verbosity);
static void print_help_create(FILE *stream);
static void print_help_main(FILE *stream);
static void print_manual_reference(FILE *stream);
static void print_usage(FILE *stream);
static void print_usage_create(FILE *stream);
static void print_usage_main(FILE *stream);
static int print_version(FILE *stream);
static int get_doc_from_file(
    char *file, char **valid_types, xmlDocPtr *doc, char **root);
static int get_volume_request_or_config(xmlDocPtr *doc, char **root);
static int handle_commands(char *commands);
static int handle_config(devconfig_t *config);
static int handle_request(request_t *request, defaults_t *defaults);
static int write_temp_file(char *text, mode_t mode, char **file);

/*
 * Data
 */

/* Holds argv[0] */
char *progname;

/* The action to take */
int action = ACTION_EXECUTE;

/* Holds the name of the temporary command file */
char *commandfile = NULL;

/* The metassist subcommand */
int subcmd = SUBCMD_NONE;

/* The volume-request XML file to read */
char *arg_inputfile = NULL;

/* The size of the requested volume */
char *arg_size = NULL;

/* The disk set to use */
char *arg_diskset = NULL;

/* The volume name to use */
char *arg_name = NULL;

/* Redundancy level */
char *arg_redundancy = NULL;

/* Number of datapaths */
char *arg_datapaths = NULL;

/* Whether to implement fault recovery */
boolean_t faultrecovery = B_FALSE;

/* Whether to output the config file */
boolean_t output_configfile = B_FALSE;

/* Whether to output the command file instead of */
boolean_t output_commandfile = B_FALSE;

/* List of available devices */
dlist_t *available = NULL;

/* List of unavailable devices */
dlist_t *unavailable = NULL;

/*
 * Functions
 */

/*
 * Frees alloc'd memory, to be called prior to exiting.
 */
static void
clean_up()
{
	/* Remove temporary command file */
	if (commandfile != NULL) {
	    /* Ignore failure */
	    unlink(commandfile);
	}

	/* Free allocated argument strings */
	if (commandfile != NULL) free(commandfile);
	if (arg_diskset != NULL) free(arg_diskset);
	if (arg_name != NULL) free(arg_name);
	if (arg_inputfile != NULL) free(arg_inputfile);

	/* Free available dlist and strings within */
	dlist_free_items(available, free);

	/* Free unavailable dlist and strings within */
	dlist_free_items(unavailable, free);

	/* Clean up XML data structures */
	cleanup_xml();
}

/*
 * Signal handler, called to exit gracefully
 */
static void
interrupthandler(
	int sig)
{
	char sigstr[SIG2STR_MAX];

	if (sig2str(sig, sigstr) != 0) {
	    sigstr[0] = '\0';
	}

	fprintf(stderr,
	    gettext("Signal %d (%s) caught -- exiting...\n"), sig, sigstr);

	/* Allow layout to cleanup on abnormal exit */
	layout_clean_up();

	clean_up();
	exit(1);
}

/*
 * Copies and saves the given argument, verifying that the argument
 * has not already been saved.
 *
 * @param       option
 *              The flag preceding or type of the argument.  Used only
 *              in the error message when an option has already been
 *              saved to *saveto.
 *
 * @param       value
 *              The argument to be copied.
 *
 * @param       saveto
 *              Changed to point to the copied data.  This must point
 *              to NULL data initially, or it will be assumed that
 *              this argument has already been set.  This memory must
 *              be free()d by the caller.
 *
 * @return      0 on success, non-zero otherwise.
 */
static int
copy_arg(
	char *option,
	char *value,
	char **saveto)
{
	int error = 0;

	/* Has this string already been set? */
	if (*saveto != NULL) {
	    volume_set_error(
		gettext("%s: option specified multiple times"), option);
	    error = -1;
	} else

	if ((*saveto = strdup(value)) == NULL) {
	    error = ENOMEM;
	}

	return (error);
}

/*
 * Generates the XML volume request corresponding to the command-line
 * parameters.  No DTD node is included in this request.
 *
 * @return      The XML request, or NULL if an error ocurred in
 *              generating the text.  This memory must be freed with
 *              XMLFree().
 */
static xmlDocPtr
create_volume_request_XML()
{
	xmlDocPtr doc;
	xmlNodePtr request, volume;

	/* Create the XML document */
	doc = xmlNewDoc((xmlChar *)"1.0");

	/* Create the root node */
	request = xmlNewDocNode(
	    doc, NULL, (xmlChar *)ELEMENT_VOLUMEREQUEST, NULL);
	xmlAddChild((xmlNodePtr) doc, (xmlNodePtr)request);

	/* diskset element */
	if (arg_diskset != NULL) {
	    xmlNodePtr node = xmlNewChild(
		request, NULL, (xmlChar *)ELEMENT_DISKSET, NULL);
	    xmlSetProp(node,
		(xmlChar *)ATTR_NAME, (xmlChar *)arg_diskset);
	}

	/* available elements */
	if (available != NULL) {
	    dlist_t *item;
	    for (item = available; item != NULL; item = item->next) {
		xmlNodePtr node = xmlNewChild(
		    request, NULL, (xmlChar *)ELEMENT_AVAILABLE, NULL);
		xmlSetProp(node,
		    (xmlChar *)ATTR_NAME, (xmlChar *)item->obj);
	    }
	}

	/* unavailable elements */
	if (unavailable != NULL) {
	    dlist_t *item;
	    for (item = unavailable; item != NULL; item = item->next) {
		xmlNodePtr node = xmlNewChild(
		    request, NULL, (xmlChar *)ELEMENT_UNAVAILABLE, NULL);
		xmlSetProp(node,
		    (xmlChar *)ATTR_NAME, (xmlChar *)item->obj);
	    }
	}

	/* volume element */
	volume = xmlNewChild(request, NULL, (xmlChar *)ELEMENT_VOLUME, NULL);

	/* Volume name - optional */
	if (arg_name != NULL) {
	    xmlSetProp(volume,
		(xmlChar *)ATTR_NAME, (xmlChar *)arg_name);
	}

	/* Volume size - required */
	xmlSetProp(volume, (xmlChar *)ATTR_SIZEINBYTES, (xmlChar *)arg_size);

	/* Volume redundancy - optional */
	if (arg_redundancy != NULL) {
	    xmlSetProp(volume,
		(xmlChar *)ATTR_VOLUME_REDUNDANCY, (xmlChar *)arg_redundancy);
	}

	/* Volume fault recovery - optional */
	if (faultrecovery == B_TRUE) {
	    xmlSetProp(volume,
		(xmlChar *)ATTR_VOLUME_FAULTRECOVERY, (xmlChar *)"TRUE");
	}

	/* Volume datapaths - optional */
	if (arg_datapaths != NULL) {
	    xmlSetProp(volume,
		(xmlChar *)ATTR_VOLUME_DATAPATHS, (xmlChar *)arg_datapaths);
	}

	if (get_max_verbosity() >= OUTPUT_DEBUG) {
	    xmlChar *text;
	    /* Get the text dump */
	    xmlDocDumpFormatMemory(doc, &text, NULL, 1);
	    oprintf(OUTPUT_DEBUG,
		gettext("Generated volume-request:\n%s"), text);
	    xmlFree(text);
	}

	return (doc);
}

/*
 * Checks the given flag for options common to all subcommands.
 *
 * @param       c
 *              The option letter.
 *
 * @param       handled
 *              RETURN: whether the given option flag was handled.
 *
 * @return      Non-zero if an error occurred or the given option was
 *              invalid or incomplete, 0 otherwise.
 */
static int
handle_common_opts(
	int c,
	boolean_t *handled)
{
	int error = 0;

	/* Level of verbosity to report */
	int verbosity;

	*handled = B_TRUE;

	switch (c) {
	    case COMMON_SHORTOPT_VERBOSITY:
		if ((error = parse_verbose_arg(optarg, &verbosity)) == 0) {
		    set_max_verbosity(verbosity, stderr);
		}
	    break;

	    case COMMON_SHORTOPT_VERSION:
		if ((error = print_version(stdout)) == 0) {
		    clean_up();
		    exit(0);
		}
	    break;

	    case GETOPT_ERR_MISSING_ARG:
		volume_set_error(
		    gettext("option missing a required argument: -%c"), optopt);
		error = -1;
	    break;

	    case GETOPT_ERR_INVALID_OPT:
		volume_set_error(gettext("invalid option: -%c"), optopt);
		error = -1;
	    break;

	    case GETOPT_ERR_INVALID_ARG:
		volume_set_error(gettext("invalid argument: %s"), optarg);
		error = -1;
	    break;

	    default:
		*handled = B_FALSE;
	}

	return (error);
}

/*
 * Parse the command line options for the create subcommand.
 *
 * @param       argc
 *              The number of arguments in the array
 *
 * @param       argv
 *              The argument array
 */
static int
parse_create_opts(
	int argc,
	char *argv[])
{
	int c;
	int error = 0;

	/*
	 * Whether a volume request is specified on the command line
	 * (vs. a inputfile)
	 */
	boolean_t request_on_command_line = B_FALSE;

	/* Examine next arg */
	while (!error && (c = getopt_ext(
		argc, argv, CREATE_SHORTOPTS)) != GETOPT_DONE_PARSING) {

	    boolean_t handled;

	    /* Check for args common to all scopes */
	    error = handle_common_opts(c, &handled);
	    if (error == 0 && handled == B_FALSE) {

		/* Check for args specific to this scope */
		switch (c) {

		    /* Help */
		    case COMMON_SHORTOPT_HELP:
			print_help_create(stdout);
			clean_up();
			exit(0);
		    break;

		    /* Config file */
		    case CREATE_SHORTOPT_CONFIGFILE:
			action &= ~ACTION_EXECUTE;
			action |= ACTION_OUTPUT_CONFIG;
		    break;

		    /* Command file */
		    case CREATE_SHORTOPT_COMMANDFILE:
			action &= ~ACTION_EXECUTE;
			action |= ACTION_OUTPUT_COMMANDS;
		    break;

		    /* Disk set */
		    case CREATE_SHORTOPT_DISKSET:
			error = copy_arg(
			    argv[optind - 2], optarg, &arg_diskset);
			request_on_command_line = B_TRUE;
		    break;

		    /* Name */
		    case CREATE_SHORTOPT_NAME:
			error = copy_arg(
			    argv[optind - 2], optarg, &arg_name);
			request_on_command_line = B_TRUE;
		    break;

		    /* Redundancy */
		    case CREATE_SHORTOPT_REDUNDANCY:
			error = copy_arg(
			    argv[optind - 2], optarg, &arg_redundancy);
			request_on_command_line = B_TRUE;
		    break;

		    /* Data paths */
		    case CREATE_SHORTOPT_DATAPATHS:
			error = copy_arg(
			    argv[optind - 2], optarg, &arg_datapaths);
			request_on_command_line = B_TRUE;
		    break;

		    /* Fault recovery */
		    case CREATE_SHORTOPT_FAULTRECOVERY:
			faultrecovery = B_TRUE;
			request_on_command_line = B_TRUE;
		    break;

		    /* Available devices */
		    case CREATE_SHORTOPT_AVAILABLE:
			error = parse_tokenized_list(optarg, &available);
			request_on_command_line = B_TRUE;
		    break;

		    /* Unavailable devices */
		    case CREATE_SHORTOPT_UNAVAILABLE:
			error = parse_tokenized_list(optarg, &unavailable);
			request_on_command_line = B_TRUE;
		    break;

		    /* Size */
		    case CREATE_SHORTOPT_SIZE:
			request_on_command_line = B_TRUE;
			error = copy_arg(
			    argv[optind - 1], optarg, &arg_size);
		    break;

		    /* Input file */
		    case CREATE_SHORTOPT_INPUTFILE:
			error = copy_arg(gettext("request/configuration file"),
			    optarg, &arg_inputfile);
		    break;

		    default:
			/* Shouldn't be here! */
			volume_set_error(
			    gettext("unexpected option: %c (%d)"), c, c);
			error = -1;
		}
	    }
	}

	/*
	 * Now that the arguments have been parsed, verify that
	 * required options were specified.
	 */
	if (!error) {
	    /* Third invocation method -- two required arguments */
	    if (request_on_command_line == B_TRUE) {
		if (arg_inputfile != NULL) {
		    volume_set_error(
			gettext("invalid option(s) specified with input file"));
		    error = -1;
		} else

		if (arg_size == NULL) {
		    volume_set_error(gettext("no size specified"));
		    error = -1;
		} else

		if (arg_diskset == NULL) {
		    volume_set_error(gettext("no disk set specified"));
		    error = -1;
		}
	    } else

	    /* First or second invocation method -- one required argument */
	    if (arg_inputfile == NULL) {
		volume_set_error(gettext("missing required arguments"));
		error = -1;
	    }

		/*
		 * The CREATE_SHORTOPT_CONFIGFILE and
		 * CREATE_SHORTOPT_COMMANDFILE arguments are mutually
		 * exclusive.  Verify that these were not both specified.
		 */
	    if (!error &&
		action & ACTION_OUTPUT_CONFIG &&
		action & ACTION_OUTPUT_COMMANDS) {
		volume_set_error(
		    gettext("-%c and -%c are mutually exclusive"),
		    CREATE_SHORTOPT_CONFIGFILE,
		    CREATE_SHORTOPT_COMMANDFILE);
		error = -1;
	    }
	}

	return (error);
}

/*
 * Parse the main command line options.
 *
 * @param       argc
 *              The number of arguments in the array
 *
 * @param       argv
 *              The argument array
 *
 * @return      0 on success, non-zero otherwise.
 */
static int
parse_opts(
	int argc,
	char *argv[])
{
	int c;
	int error = 0;

	/* Examine next arg */
	while (!error && (c = getopt_ext(
		argc, argv, MAIN_SHORTOPTS)) != GETOPT_DONE_PARSING) {

	    boolean_t handled;

	    /* Check for args common to all scopes */
	    error = handle_common_opts(c, &handled);

	    if (error == 0 && handled == B_FALSE) {

		/* Check for args specific to this scope */
		switch (c) {

		    /* Help */
		    case COMMON_SHORTOPT_HELP:
			print_help_main(stdout);
			clean_up();
			exit(0);
		    break;

		    /* Non-option arg */
		    case GETOPT_NON_OPTION_ARG:

			/* See if non-option arg is subcommand */
			if (strcmp(optarg, MAIN_SUBCMD_CREATE) == 0) {
			    subcmd = SUBCMD_CREATE;
			    error = parse_create_opts(argc, argv);
			} else {
			    /* Argument not recognized */
			    volume_set_error(
				gettext("%s: invalid argument"), optarg);
			    error = -1;
			}
		    break;

		    default:
			/* Shouldn't be here! */
			volume_set_error(
			    gettext("unexpected option: %c (%d)"), c, c);
			error = -1;
		}
	    } else

		/*
		 * Check invalid arguments to see if they are valid
		 * options out of place.
		 *
		 * NOTE: IN THE FUTURE, A CODE BLOCK SIMILAR TO THIS
		 * ONE SHOULD BE ADDED FOR EACH NEW SUBCOMMAND.
		 */
	    if (c == GETOPT_ERR_INVALID_OPT &&
		strchr(CREATE_SHORTOPTS, optopt) != NULL) {
		/* Provide a more enlightening error message */
		volume_set_error(
		    gettext("-%c specified before create subcommand"), optopt);
	    }
	}

	/* Parsing appears to be successful */
	if (!error) {

	    /* Was a subcommand specified? */
	    if (subcmd == SUBCMD_NONE) {
		volume_set_error(gettext("no subcommand specified"));
		error = -1;
	    }
	}

	return (error);
}

/*
 * Convert a string containing a comma/space-separated list into a
 * dlist.
 *
 * @param       string
 *              a comma/space-separated list
 *
 * @param       list
 *              An exisiting dlist to append to, or NULL to create a
 *              new list.
 *
 * @return      The head node of the dlist_t, whether it was newly
 *              created or passed in.  On memory allocation error,
 *              errno will be set and processing will stop.
 */
static int
parse_tokenized_list(
	const char *string,
	dlist_t **list)
{
	char *stringdup;
	char *device;
	char *dup;
	dlist_t *item;
	int error = 0;

	/* Don't let strtok alter original argument */
	if ((stringdup = strdup(string)) == NULL) {
	    error = ENOMEM;
	} else {

	    /* For each device in the string list... */
	    while ((device = strtok(stringdup, DEVICELISTDELIM)) != NULL) {

		/* Duplicate the device string */
		if ((dup = strdup(device)) == NULL) {
		    error = ENOMEM;
		    break;
		}

		/* Create new dlist_t for this device */
		if ((item = dlist_new_item((void *)dup)) == NULL) {
		    error = ENOMEM;
		    free(dup);
		    break;
		}

		/* Append item to list */
		*list = dlist_append(item, *list, B_TRUE);

		/* strtok needs NULL pointer on subsequent calls */
		stringdup = NULL;
	    }

	    free(stringdup);
	}

	return (error);
}

/*
 * Parses the given verbosity level argument string.
 *
 * @param       arg
 *              A string representation of a verbosity level
 *
 * @param       verbosity
 *              RETURN: the verbosity level
 *
 * @return      0 if the given verbosity level string cannot
 *              be interpreted, non-zero otherwise
 */
static int
parse_verbose_arg(
	char *arg,
	int *verbosity)
{
	int level;

	/* Scan for int */
	if (sscanf(arg, "%d", &level) == 1) {

	    /* Argument was an integer */
	    switch (level) {
		case OUTPUT_QUIET:
		case OUTPUT_TERSE:
		case OUTPUT_VERBOSE:
#ifdef	DEBUG
		case OUTPUT_DEBUG:
#endif

		*verbosity = level;
		return (0);
	    }
	}

	volume_set_error(gettext("%s: invalid verbosity level"), arg);
	return (-1);
}

/*
 * Print the help message for the command.
 *
 * @param       stream
 *              stdout or stderr, as appropriate.
 */
static void
print_help_create(
	FILE *stream)
{
	print_usage_create(stream);

	/* BEGIN CSTYLED */
	fprintf(stream, gettext("\
\n\
Create Solaris Volume Manager volumes.\n\
\n\
-F <inputfile>\n\
    Specify the volume request or volume configuration file to\n\
    process.\n\
\n\
-s <set>\n\
    Specify the disk set to use when creating volumes.\n\
\n\
-S <size>\n\
    Specify the size of the volume to be created.\n\
\n\
-a <device1,device2,...>\n\
    Explicitly specify the devices that can be used in the\n\
    creation of this volume.\n\
\n\
-c  Output the command script that would implement the specified or\n\
    generated volume configuration.\n\
\n\
-d  Output the volume configuration that satisfies the specified or\n\
    generated volume request.\n\
\n\
-f  Specify whether the volume should support automatic component\n\
    replacement after a fault.\n\
\n\
-n <name>\n\
    Specify the name of the new volume.\n\
\n\
-p <n>\n\
    Specify the number of required paths to the storage volume.\n\
\n\
-r <n>\n\
    Specify the redundancy level (0-4) of the data.\n\
\n\
-u <device1,device2,...>\n\
    Explicitly specify devices to exclude in the creation of this\n\
    volume.\n\
\n\
-v <value>\n\
    Specify the level of verbosity.\n\
\n\
-V  Display program version information.\n\
\n\
-?  Display help information.\n"));

	/* END CSTYLED */

	print_manual_reference(stream);
}

/*
 * Print the help message for the command.
 *
 * @param       stream
 *              stdout or stderr, as appropriate.
 */
static void
print_help_main(
	FILE *stream)
{
	print_usage_main(stream);

	/* BEGIN CSTYLED */
	fprintf(stream, gettext("\
\n\
Provide assistance, through automation, with common Solaris Volume\n\
Manager tasks.\n\
\n\
-V  Display program version information.\n\
\n\
-?  Display help information.  This option can follow <subcommand>\n\
    for subcommand-specific help.\n\
\n\
The accepted values for <subcommand> are:\n\
\n\
create          Create Solaris Volume Manager volumes.\n"));
	/* END CSTYLED */

	print_manual_reference(stream);
}

/*
 * Print the help postscript for the command.
 *
 * @param       stream
 *              stdout or stderr, as appropriate.
 */
static void
print_manual_reference(
	FILE *stream)
{
	fprintf(stream, gettext("\nFor more information, see %s(1M).\n"),
	    progname);
}

/*
 * Print the program usage to the given file stream.
 *
 * @param       stream
 *              stdout or stderr, as appropriate.
 */
static void
print_usage(
	FILE *stream)
{
	switch (subcmd) {
	    case SUBCMD_CREATE:
		print_usage_create(stream);
	    break;

	    case SUBCMD_NONE:
	    default:
		print_usage_main(stream);
	}
}

/*
 * Print the program usage to the given file stream.
 *
 * @param       stream
 *              stdout or stderr, as appropriate.
 */
static void
print_usage_create(
	FILE *stream)
{
	/* Create a blank the length of progname */
	char *blank = strdup(progname);
	memset(blank, ' ', strlen(blank) * sizeof (char));

	/* BEGIN CSTYLED */
	fprintf(stream, gettext("\
Usage: %1$s create [-v <n>] [-c] -F <configfile>\n\
       %1$s create [-v <n>] [-c|-d] -F <requestfile>\n\
       %1$s create [-v <n>] [-c|-d]\n\
       %2$s [-f] [-n <name>] [-p <datapaths>] [-r <redundancy>]\n\
       %2$s [-a <available>[,<available>,...]]\n\
       %2$s [-u <unavailable>[,<unavailable>,...]]\n\
       %2$s -s <setname> -S <size>\n\
       %1$s create -V\n\
       %1$s create -?\n"), progname, blank);
	/* END CSTYLED */

	free(blank);
}

/*
 * Print the program usage to the given file stream.
 *
 * @param       stream
 *              stdout or stderr, as appropriate.
 */
static void
print_usage_main(
	FILE *stream)
{
	/* BEGIN CSTYLED */
	fprintf(stream, gettext("\
Usage: %1$s <subcommand> [-?] [options]\n\
       %1$s -V\n\
       %1$s -?\n"), progname);
	/* END CSTYLED */
}

/*
 * Print the program version to the given file stream.
 *
 * @param       stream
 *              stdout or stderr, as appropriate.
 */
static int
print_version(
	FILE *stream)
{
	int error = 0;
	struct utsname uname_info;

	if (uname(&uname_info) < 0) {
	    error = -1;
	    volume_set_error(gettext("could not determine version"));
	} else {
	    fprintf(stream, gettext("%s %s"), progname, uname_info.version);
	}

	fprintf(stream, "\n");

	return (error);
}

/*
 * Get an xmlDocPtr by parsing the given file.
 *
 * @param       file
 *              The file to read
 *
 * @param       valid_types
 *              An array of the allowable root elements.  If the root
 *              element of the parsed XML file is not in this list, an
 *              error is returned.
 *
 * @param       doc
 *              RETURN: the XML document
 *
 * @param       root
 *              RETURN: the root element of the document
 *
 * @return      0 if the given XML file was successfully parsed,
 *              non-zero otherwise
 */
static int
get_doc_from_file(
	char *file,
	char **valid_types,
	xmlDocPtr *doc,
	char **root)
{
	int error = 0;

	*root = NULL;

	/*
	 * Create XML doc by reading the specified file using the
	 * default SAX handler (which has been modified in init_xml())
	 */
	*doc = xmlSAXParseFile((xmlSAXHandlerPtr)
	    &xmlDefaultSAXHandler, file, 0);

	if (*doc != NULL) {
	    int i;
	    xmlNodePtr root_elem = xmlDocGetRootElement(*doc);

	    /* Is this a valid root element? */
	    for (i = 0; valid_types[i] != NULL; i++) {
		if (xmlStrcmp(root_elem->name,
		    (const xmlChar *)valid_types[i]) == 0) {
		    *root = valid_types[i];
		}
	    }

	    /* Was a valid root element found? */
	    if (*root == NULL) {
		xmlFreeDoc(*doc);
	    }
	}

	/* Was a valid root element found? */
	if (*root == NULL) {
	    volume_set_error(
		gettext("%s: invalid or malformed XML file"), file);
	    error = -1;
	}

	return (error);
}

/*
 * Creates a volume-request or volume-config XML document, based on the
 * arguments passed into the command.
 *
 * @param       doc
 *              RETURN: the XML document, or NULL if no valid document
 *              could be created.
 *
 * @param       root
 *              RETURN: the root element of the document
 *
 * @return      0 if a volume-request or volume-config XML document
 *              could be read or created, non-zero otherwise
 */
static int
get_volume_request_or_config(
	xmlDocPtr *doc,
	char **root)
{
	int error = 0;

	if (arg_inputfile == NULL) {
	    /* Create a volume-request based on quality of service */
	    *doc = create_volume_request_XML();

	    if (*doc == NULL) {
		volume_set_error(gettext("error creating volume request"));
		error = -1;
		*root = NULL;
	    } else {
		*root = ELEMENT_VOLUMEREQUEST;
	    }
	} else {
	    char *valid[] = {
		ELEMENT_VOLUMEREQUEST,
		ELEMENT_VOLUMECONFIG,
		NULL
	    };

	    error = get_doc_from_file(arg_inputfile, valid, doc, root);
	}

	return (error);
}

/*
 * Handle processing of the given meta* commands.  Commands are
 * written to a file, the file is optionally executed, and optionally
 * deleted.
 *
 * @param       commands
 *              The commands to write to the command script file.
 *
 * @return      0 on success, non-zero otherwise.
 */
static int
handle_commands(
	char *commands)
{
	int error = 0;

	if (action & ACTION_OUTPUT_COMMANDS) {
	    printf("%s", commands);
	}

	if (action & ACTION_EXECUTE) {

	    /* Write a temporary file with 744 permissions */
	    if ((error = write_temp_file(commands,
		S_IRWXU | S_IRGRP | S_IROTH, &commandfile)) == 0) {

		char *command;

		/* Create command line to execute */
		if (get_max_verbosity() >= OUTPUT_VERBOSE) {
		    /* Verbose */
		    command = stralloccat(3,
			commandfile, " ", COMMAND_VERBOSE_FLAG);
		} else {
		    /* Terse */
		    command = strdup(commandfile);
		}

		if (command == NULL) {
		    volume_set_error(gettext("could not allocate memory"));
		    error = -1;
		} else {

		    oprintf(OUTPUT_VERBOSE,
			gettext("Executing command script: %s\n"), command);

		    /* Execute command */
		    switch (error = system(command)) {
			/* system() failed */
			case -1:
			    error = errno;
			break;

			/* Command succeded */
			case 0:
			break;

			/* Command failed */
			default:
			    volume_set_error(
				/* CSTYLED */
				gettext("execution of command script failed with status %d"),
				WEXITSTATUS(error));
			    error = -1;
		    }
		    free(command);
		}
	    }
	}

	return (error);
}

/*
 * Handle processing of the given volume-config devconfig_t.  The
 * devconfig_t is first converted to XML.  Then, depending
 * on user input to the command, the XML is either written to a file
 * or converted to a command script and passed on to
 * handle_commands().
 *
 * @param       config
 *              A devconfig_t representing a valid volume-config.
 *
 * @return      0 on success, non-zero otherwise.
 */
static int
handle_config(
	devconfig_t *config)
{
	int error;
	xmlDocPtr doc;

	/* Get the xml document for the config */
	if ((error = config_to_xml(config, &doc)) == 0) {

	    /* Get the text dump */
	    xmlChar *text;
	    xmlDocDumpFormatMemory(doc, &text, NULL, 1);

	    /* Should we output the config file? */
	    if (action & ACTION_OUTPUT_CONFIG) {
		printf("%s", text);
	    } else {
		oprintf(OUTPUT_DEBUG,
		    gettext("Generated volume-config:\n%s"), text);
	    }

	    xmlFree(text);

	    /* Proceed to command generation? */
	    if (action & ACTION_OUTPUT_COMMANDS ||
		action & ACTION_EXECUTE) {
		char *commands;

		/* Get command script from the file */
		if ((error = xml_to_commands(doc, &commands)) == 0) {
		    if (commands == NULL) {
			volume_set_error(
			    gettext("could not convert XML to commands"));
			error = -1;
		    } else {
			error = handle_commands(commands);
			free(commands);
		    }
		}
	    }

	    xmlFreeDoc(doc);
	}

	return (error);
}

/*
 * Handle processing of the given volume-request request_t and
 * volume-defaults defaults_t.  A layout is generated from these
 * structures and the resulting volume-config devconfig_t is passed on
 * to handle_config().
 *
 * @param       request
 *              A request_t representing a valid volume-request.
 *
 * @param       defaults
 *              A defaults_t representing a valid volume-defaults.
 *
 * @return      0 on success, non-zero otherwise.
 */
static int
handle_request(
	request_t *request,
	defaults_t *defaults)
{
	int error;

	/* Get layout for given request and system defaults */
	if ((error = get_layout(request, defaults)) == 0) {

	    /* Retrieve resulting volume config */
	    devconfig_t *config = request_get_diskset_config(request);

	    if (config != NULL) {
		error = handle_config(config);
	    }
	}

	return (error);
}

/*
 * Write the given text to a temporary file with the given
 * permissions.  If the file already exists, return an error.
 *
 * @param       text
 *              The text to write to the file.
 *
 * @param       mode
 *              The permissions to give the file, passed to chmod(2).
 *
 * @param       file
 *              RETURN: The name of the file written.  Must be
 *              free()d.
 *
 * @return      0 on success, non-zero otherwise.
 */
static int
write_temp_file(
	char *text,
	mode_t mode,
	char **file)
{
	int error = 0;

	/*
	 * Create temporary file name -- "XXXXXX" is replaced with
	 * unique char sequence by mkstemp()
	 */
	*file = stralloccat(3, "/tmp/", progname, "XXXXXX");

	if (*file == NULL) {
	    volume_set_error(gettext("out of memory"));
	    error = -1;
	} else {
	    int fildes;
	    FILE *out = NULL;

	    /* Open temp file */
	    if ((fildes = mkstemp(*file)) != -1) {
		out = fdopen(fildes, "w");
	    }

	    if (out == NULL) {
		volume_set_error(gettext(
		    "could not open file for writing: %s"), *file);
		error = -1;
	    } else {

		fprintf(out, "%s", text);
		fclose(out);

		if (mode != 0) {
		    if (chmod(*file, mode)) {
			volume_set_error(
			    gettext("could not change permissions of file: %s"),
			    *file);
			error = -1;
		    }
		}

		/* Remove file on error */
		if (error != 0) {
		    unlink(*file);
		}
	    }

	    /* Free *file on error */
	    if (error != 0) {
		free(*file);
		*file = NULL;
	    }
	}

	return (error);
}

/*
 * Main entry to metassist.  See the print_usage_* functions* for
 * usage.
 *
 * @return      0 on successful exit, non-zero otherwise
 */
int
main(
	int argc,
	char *argv[])
{
	int error = 0;
	int printusage = 0;

#ifdef DEBUG
	time_t start = time(NULL);
#endif

	/*
	 * Get the locale set up before calling any other routines
	 * with messages to ouput.  Just in case we're not in a build
	 * environment, make sure that TEXT_DOMAIN gets set to
	 * something.
	 */
#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif
	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	/* Set program name, strip directory */
	if ((progname = strrchr(argv[0], '/')) != NULL) {
	    progname++;
	} else {
	    progname = argv[0];
	}

	/* Set up signal handlers to exit gracefully */
	{
	    struct sigaction act;
	    act.sa_handler = interrupthandler;
	    sigemptyset(&act.sa_mask);
	    act.sa_flags = 0;
	    sigaction(SIGHUP, &act, (struct sigaction *)0);
	    sigaction(SIGINT, &act, (struct sigaction *)0);
	    sigaction(SIGQUIT, &act, (struct sigaction *)0);
	    sigaction(SIGTERM, &act, (struct sigaction *)0);
	}

	/* Set default verbosity level */
	set_max_verbosity(OUTPUT_TERSE, stderr);

	/* Verify we're running as root */
	if (geteuid() != 0) {
	    volume_set_error(gettext("must be run as root"));
	    error = -1;
	} else {

	    /* Disable error messages from getopt */
	    opterr = 0;

	    /* Parse command-line options */
	    if ((error = parse_opts(argc, argv)) == 0) {
		xmlDocPtr doc;
		char *root;

		/* Initialize XML defaults */
		init_xml();

		/* Read volume-request/config file */
		if ((error = get_volume_request_or_config(&doc, &root)) == 0) {

		    /* Is this a volume-config? */
		    if (strcmp(root, ELEMENT_VOLUMECONFIG) == 0) {

			/* Was the -d flag specified? */
			if (action & ACTION_OUTPUT_CONFIG) {
			    /* -d cannot be used with -F <configfile> */
			    volume_set_error(gettext(
				"-%c incompatible with -%c <configfile>"),
				CREATE_SHORTOPT_CONFIGFILE,
				CREATE_SHORTOPT_INPUTFILE);
			    error = -1;
			    printusage = 1;
			} else {
			    devconfig_t *config;
			    if ((error = xml_to_config(doc, &config)) == 0) {
				error = handle_config(config);
				free_devconfig(config);
			    }
			}
		    } else

		    /* Is this a volume-request? */
		    if (strcmp(root, ELEMENT_VOLUMEREQUEST) == 0) {
			request_t *request;

			if ((error = xml_to_request(doc, &request)) == 0) {

			    xmlDocPtr defaults_doc;
			    char *valid[] = {
				ELEMENT_VOLUMEDEFAULTS,
				NULL
			    };

			    /* Read defaults file */
			    if ((error = get_doc_from_file(VOLUME_DEFAULTS_LOC,
				valid, &defaults_doc, &root)) == 0) {

				defaults_t *defaults;

				oprintf(OUTPUT_DEBUG,
				    gettext("Using defaults file: %s\n"),
				    VOLUME_DEFAULTS_LOC);

				/* Parse defaults XML */
				if ((error = xml_to_defaults(
				    defaults_doc, &defaults)) == 0) {
				    error = handle_request(request, defaults);
				    free_defaults(defaults);
				}

				xmlFreeDoc(defaults_doc);
			    }

			    free_request(request);
			}
		    }

		    xmlFreeDoc(doc);
		}
	    } else {
		printusage = 1;
	    }
	}

	/* Handle any errors that were propogated */
	if (error != 0) {
	    char *message = get_error_string(error);

	    if (message != NULL && strlen(message)) {
		fprintf(stderr, "%s: %s\n", progname, message);

		if (printusage) {
		    fprintf(stderr, "\n");
		}
	    }

	    if (printusage) {
		print_usage(stderr);
	    }
	}

#ifdef DEBUG
	/* Print run report to stderr if METASSIST_DEBUG is set */
	if (getenv(METASSIST_DEBUG_ENV) != NULL) {
	    time_t end = time(NULL);
	    struct tm *time;
	    int i;
#define	TIMEFMT	"%8s: %.2d:%.2d:%.2d\n"

	    fprintf(stderr, " Command:");
	    for (i = 0; i < argc; i++) {
		fprintf(stderr, " %s", argv[i]);
	    }
	    fprintf(stderr, "\n");

	    fprintf(stderr, " Version: ");
	    print_version(stderr);

	    time = localtime(&start);
	    fprintf(stderr, TIMEFMT, "Start",
		time->tm_hour, time->tm_min, time->tm_sec);

	    time = localtime(&end);
	    fprintf(stderr, TIMEFMT, "End",
		time->tm_hour, time->tm_min, time->tm_sec);

	    end -= start;
	    time = gmtime(&end);
	    fprintf(stderr, TIMEFMT, "Duration",
		time->tm_hour, time->tm_min, time->tm_sec);
	}
#endif

	clean_up();

	return (error != 0);
}
