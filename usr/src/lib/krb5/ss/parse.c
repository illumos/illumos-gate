/*
 * Copyright 1987, 1988 by MIT Student Information Processing Board
 *
 * For copyright info, see copyright.h.
 */

/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include "ss_internal.h"
#include "copyright.h"
#include <errno.h>

enum parse_mode { WHITESPACE, TOKEN, QUOTED_STRING };


/*
 * Solaris Kerberos:
 * ss_parse has been modified slightly from the original in two ways.
 * 1) A new parameter "quiet" has been added which is used to silence
 *    error or warning messages.
 * 2) ss_parse now returns an error status instead of argv - this is to
 *    allow an error to be distinguished from no tokens when parsing an empty
 *    string.
 * Both of these changes allow ss_parse to be used during tab-completion.
 */

/*
 * parse(line_ptr, argc_ptr)
 *
 * Function:
 *      Parses line, dividing at whitespace, into tokens, returns
 *      the "argc" and "argv" values.
 * Arguments:
 *      line_ptr (char *)
 *              Pointer to text string to be parsed.
 *      argc_ptr (int *)
 *              Where to put the "argc" (number of tokens) value.
 *      argv_ptr (char ***)
 *              Where to put the series of pointers to parsed tokens.
 * Returns:
 *      error (0 - success, non-zero on failure)
 */

#define NEW_ARGV(old,n) (char **)realloc((char *)old,\
					 (unsigned)(n+2)*sizeof(char*))

int ss_parse (sci_idx, line_ptr, argc_ptr, argv_ptr, quiet)
    int sci_idx;
    register char *line_ptr;
    int *argc_ptr;
    char ***argv_ptr;
    int quiet;
{
    register char **argv, *cp;
    register int argc;
    register enum parse_mode parse_mode;

    argv = (char **) malloc (sizeof(char *));
    if (argv == (char **)NULL) {
	if (!quiet)
	    ss_error(sci_idx, errno, "Can't allocate storage");
	*argc_ptr = 0;
	*argv_ptr = argv;
	return(ENOMEM);
    }
    *argv = (char *)NULL;

    argc = 0;

    parse_mode = WHITESPACE;	/* flushing whitespace */
    cp = line_ptr;		/* cp is for output */
    while (1) {
#ifdef DEBUG
	{
	    printf ("character `%c', mode %d\n", *line_ptr, parse_mode);
	}
#endif
	while (parse_mode == WHITESPACE) {
	    if (*line_ptr == '\0')
		goto end_of_line;
	    if (*line_ptr == ' ' || *line_ptr == '\t') {
		line_ptr++;
		continue;
	    }
	    if (*line_ptr == '"') {
		/* go to quoted-string mode */
		parse_mode = QUOTED_STRING;
		cp = line_ptr++;
		argv = NEW_ARGV (argv, argc);
		argv[argc++] = cp;
		argv[argc] = NULL;
	    }
	    else {
		/* random-token mode */
		parse_mode = TOKEN;
		cp = line_ptr;
		argv = NEW_ARGV (argv, argc);
		argv[argc++] = line_ptr;
		argv[argc] = NULL;
	    }
	}
	while (parse_mode == TOKEN) {
	    if (*line_ptr == '\0') {
		*cp++ = '\0';
		goto end_of_line;
	    }
	    else if (*line_ptr == ' ' || *line_ptr == '\t') {
		*cp++ = '\0';
		line_ptr++;
		parse_mode = WHITESPACE;
	    }
	    else if (*line_ptr == '"') {
		line_ptr++;
		parse_mode = QUOTED_STRING;
	    }
	    else {
		*cp++ = *line_ptr++;
	    }
	}
	while (parse_mode == QUOTED_STRING) {
	    if (*line_ptr == '\0') {
		if (!quiet)
		    ss_error (sci_idx, 0,
			"Unbalanced quotes in command line");
		free (argv);
		*argc_ptr = 0;
		*argv_ptr = NULL;
		return (-1);
	    }
	    else if (*line_ptr == '"') {
		if (*++line_ptr == '"') {
		    *cp++ = '"';
		    line_ptr++;
		}
		else {
		    parse_mode = TOKEN;
		}
	    }
	    else {
		*cp++ = *line_ptr++;
	    }
	}
    }
end_of_line:
    *argc_ptr = argc;
#ifdef DEBUG
    {
	int i;
	printf ("argc = %d\n", argc);
	for (i = 0; i <= argc; i++)
	    printf ("\targv[%2d] = `%s'\n", i,
		    argv[i] ? argv[i] : "<NULL>");
    }
#endif
    *argv_ptr = argv;
    return(0);
}
