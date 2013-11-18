/*
 * Copyright 1995-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright 2013 Nexenta Systems. All rights reserved.
 */

/*
 * Test client for kwarnd.  This program is not shipped on the binary
 * release. This code was taken and modified from gssdtest.c
 */

#include <stdio.h>
#include <strings.h>
#include <ctype.h>
#include <stdlib.h>
#include "kwarnd.h"
#include <rpc/rpc.h>

#define	LOOP_COUNTER  100

#define	OCTAL_MACRO "%03.3o."
#define	MALLOC(n) malloc(n)
#define	CALLOC(n, s) calloc((n), (s))
#define	FREE(x, n) free(x)

static void instructs(void);
static void usage(void);
static int parse_input_line(char *, int *, char ***);
extern uid_t getuid(void);

static void _kwarnd_add_warning(int, char **);
static void _kwarnd_del_warning(int, char **);

static int do_kwarndtest(char *buf);

extern OM_UINT32 kwarn_add_warning();
extern OM_UINT32 kwarn_del_warning();

static int read_line(char *buf, int size)
{
	int len;

	/* read the next line. If cntl-d, return with zero char count */
	printf(gettext("\n> "));

	if (fgets(buf, size, stdin) == NULL)
		return (0);

	len = strlen(buf);
	buf[--len] = '\0';
	return (len);
}

int
main()
{
	char buf[512];
	int len, ret;

	/* Print out usage and instructions to start off the session */

	instructs();
	usage();

	/*
	 * Loop, repeatedly calling parse_input_line() to get the
	 * next line and parse it into argc and argv. Act on the
	 * arguements found on the line.
	 */

	do {
		len = read_line(buf, 512);
		if (len)
			ret = do_kwarndtest(buf);
	} while (len && !ret);

	return (0);
}

static int
do_kwarndtest(char *buf)
{
	int argc;
	char **argv, **argv_array;

	char *cmd;

	argv = 0;

	if (parse_input_line(buf, &argc, &argv) == 0) {
		printf(gettext("\n"));
		return (1);
	}

	if (argc == 0) {
		usage();
		FREE(argv, (argc+1)*sizeof (char *));
		return (0);
	}

	/*
	 * remember argv_array address, which is memory calloc'd by
	 * parse_input_line, so it can be free'd at the end of the loop.
	 */

	argv_array = argv;

	cmd = argv[0];

	argc--;
	argv++;

	if (strcmp(cmd, "kwarn_add_warning") == 0 ||
	    strcmp(cmd, "add") == 0) {
		_kwarnd_add_warning(argc, argv);
	} else if (strcmp(cmd, "kwarn_del_warning") == 0 ||
	    strcmp(cmd, "delete") == 0) {
		_kwarnd_del_warning(argc, argv);
	} else if (strcmp(cmd, "exit") == 0) {
		printf(gettext("\n"));
		FREE(argv_array, (argc+2) * sizeof (char *));
		return (1);
	} else
		usage();

	/* free argv array */

	FREE(argv_array, (argc+2) * sizeof (char *));
	return (0);
}

static void
_kwarnd_add_warning(int argc, char **argv)
{
	OM_UINT32 status;
	time_t	exptime;
	time_t	now;

	/* set up the arguments specified in the input parameters */

	if (argc == 0) {
		usage();
		return;
	}

	if (argc != 2) {
		usage();
		return;
	}

	time(&now);
	exptime = atol(argv[1]);
	exptime = now + exptime;

	status = kwarn_add_warning(argv[0], exptime);

	if (status == 0) {
		printf(gettext("\nadd of credential\n\n"));
		printf(gettext("warning message successful for \"%s\"\n\n"),
		    argv[0]);
	} else {
		printf(gettext("server ret err (octal) %o (%s)\n"),
		    status, gettext("add warning error"));
	}

	return;

}

static void
_kwarnd_del_warning(int argc, char **argv)
{
	OM_UINT32 status;

	if (argc != 1) {
		usage();
		return;
	}

	status = kwarn_del_warning(argv[0]);

	if (status == 0) {
		printf(gettext("delete of principal warning message"
		    "for %s successful"),
		    argv[0]);
	} else {
		printf(gettext("delete of principal %s unsuccessful\n\n"),
		    argv[0]);
	}
}

static void
instructs(void)
{
	fprintf(stderr,
	    gettext(
"\nThis program will test kwarnd.  kwarnd must be running as root. Enter\n"
"the desired command and the principal to be added/deleted. If adding a\n"
"principal, also include the expiration time in seconds.\n"));
}

static void
usage(void)
{
	fprintf(stderr,
	    gettext(
	    "\nusage:\t[kwarn_add_warning | add] (principal) (exptime)\n"
	    "\t[kwarn_del_warning | delete] (principal)\n"
	    "\texit\n\n"));
}

/* Copied from parse_argv(), then modified */

static int
parse_input_line(char *input_line, int *argc, char ***argv)
{
	const char nil = '\0';
	char *chptr;
	int chr_cnt;
	int arg_cnt = 0;
	int ch_was_space = 1;
	int ch_is_space;

	chr_cnt = strlen(input_line);

	/* Count the arguments in the input_line string */

	*argc = 1;

	for (chptr = &input_line[0]; *chptr != nil; chptr++) {
		ch_is_space = isspace(*chptr);
		if (ch_is_space && !ch_was_space) {
			(*argc)++;
		}
		ch_was_space = ch_is_space;
	}

	if (ch_was_space) {
		(*argc)--;
	}	/* minus trailing spaces */

	/* Now that we know how many args calloc the argv array */

	*argv = (char **)CALLOC((*argc)+1, sizeof (char *));
	chptr = (char *)(&input_line[0]);

	for (ch_was_space = 1; *chptr != nil; chptr++) {
		ch_is_space = isspace(*chptr);
		if (ch_is_space) {
			*chptr = nil;	/* replace each space with nil	*/
		} else if (ch_was_space) {	/* begining of word? */
			(*argv)[arg_cnt++] = chptr;	/* new argument ? */
		}

		ch_was_space = ch_is_space;
	}

	return (chr_cnt);
}
