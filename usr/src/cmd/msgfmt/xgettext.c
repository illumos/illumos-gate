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
 * Copyright 1991, 1999, 2001-2002 Sun Microsystems, Inc.
 * All rights reserved.
 * Use is subject to license terms.
 */

#include	<ctype.h>
#include	<stdio.h>
#include	<stdlib.h>
#include	<string.h>

#define	TRUE	1
#define	FALSE	0
#define	MAX_PATH_LEN	1024
#define	MAX_DOMAIN_LEN	1024
#define	MAX_STRING_LEN  2048

#define	USAGE	"Usage:	xgettext [-a [-x exclude-file]] [-jns]\
[-c comment-tag]\n	[-d default-domain] [-m prefix] \
[-M suffix] [-p pathname] files ...\n\
	xgettext -h\n"

#define	DEFAULT_DOMAIN	"messages"

extern char	yytext[];
extern int	yylex(void);

/*
 * Contains a list of strings to be used to store ANSI-C style string.
 * Each quoted string is stored in one node.
 */
struct strlist_st {
	char			*str;
	struct strlist_st	*next;
};

/*
 * istextdomain	: Boolean telling if this node contains textdomain call.
 * isduplicate	: Boolean telling if this node duplicate of any other msgid.
 * msgid	: contains msgid or textdomain if istextdomain is true.
 * msgstr	: contains msgstr.
 * comment	: comment extracted in case of -c option.
 * fname	: tells which file contains msgid.
 * linenum	: line number in the file.
 * next		: Next node.
 */
struct element_st {
	char			istextdomain;
	char			isduplicate;
	struct strlist_st	*msgid;
	struct strlist_st	*msgstr;
	struct strlist_st	*comment;
	char			*fname;
	int			linenum;
	struct element_st	*next;
};

/*
 * dname	   : domain name. NULL if default domain.
 * gettext_head    : Head of linked list containing [d]gettext().
 * gettext_tail    : Tail of linked list containing [d]gettext().
 * textdomain_head : Head of linked list containing textdomain().
 * textdomain_tail : Tail of linked list containing textdomain().
 * next		   : Next node.
 *
 * Each domain contains two linked list.
 *	(gettext_head,  textdomain_head)
 * If -s option is used, then textdomain_head contains all
 * textdomain() calls and no textdomain() calls are stored in gettext_head.
 * If -s option is not used, textdomain_head is empty list and
 * gettext_head contains all gettext() dgettext(), and textdomain() calls.
 */
struct domain_st {
	char			*dname;
	struct element_st	*gettext_head;
	struct element_st	*gettext_tail;
	struct element_st	*textdomain_head;
	struct element_st	*textdomain_tail;
	struct domain_st	*next;
};

/*
 * There are two domain linked lists.
 * def_dom contains default domain linked list and
 * dom_head contains all other deomain linked lists to be created by
 * dgettext() calls.
 */
static struct domain_st	*def_dom = NULL;
static struct domain_st	*dom_head = NULL;
static struct domain_st	*dom_tail = NULL;

/*
 * This linked list contains a list of strings to be excluded when
 * -x option is used.
 */
static struct exclude_st {
	struct strlist_st	*exstr;
	struct exclude_st	*next;
} *excl_head;

/*
 * All option flags and values for each option if any.
 */
static int	aflg = FALSE;
static int	cflg = FALSE;
static char	*comment_tag = NULL;
static char	*default_domain = NULL;
static int	hflg = FALSE;
static int	jflg = FALSE;
static int	mflg = FALSE;
static int	Mflg = FALSE;
static char	*suffix = NULL;
static char	*prefix = NULL;
static int	nflg = FALSE;
static int	pflg = FALSE;
static char	*pathname = NULL;
static int	sflg = FALSE;
static int	tflg = FALSE;	/* Undocumented option to extract dcgettext */
static int	xflg = FALSE;
static char	*exclude_file = NULL;

/*
 * Each variable shows the current state of parsing input file.
 *
 * in_comment    : Means inside comment block (C or C++).
 * in_cplus_comment    : Means inside C++ comment block.
 * in_gettext    : Means inside gettext call.
 * in_dgettext   : Means inside dgettext call.
 * in_dcgettext  : Means inside dcgettext call.
 * in_textdomain : Means inside textdomain call.
 * in_str	 : Means currently processing ANSI style string.
 * in_quote	 : Means currently processing double quoted string.
 * in_skippable_string	: Means currently processing double quoted string,
 *                        that occurs outside a call to gettext, dgettext,
 *                        dcgettext, textdomain, with -a not specified.
 * is_last_comment_line : Means the current line is the last line
 *			  of the comment block. This is necessary because
 *			  in_comment becomes FALSE when '* /' is encountered.
 * is_first_comma_found : This is used only for dcgettext because dcgettext()
 *			  requires 2 commas. So need to do different action
 *			  depending on which commas encountered.
 * num_nested_open_paren : This keeps track of the number of open parens to
 *			   handle dcgettext ((const char *)0,"msg",LC_TIME);
 */
static int	in_comment		= FALSE;
static int	in_cplus_comment	= FALSE;
static int	in_gettext		= FALSE;
static int	in_dgettext		= FALSE;
static int	in_dcgettext		= FALSE;
static int	in_textdomain		= FALSE;
static int	in_str			= FALSE;
static int	in_quote		= FALSE;
static int	is_last_comment_line	= FALSE;
static int	is_first_comma_found	= FALSE;
static int	in_skippable_string	= FALSE;
static int	num_nested_open_paren	= 0;

/*
 * This variable contains the first line of gettext(), dgettext(), or
 * textdomain() calls.
 * This is necessary for multiple lines of a single call to store
 * the starting line.
 */
static int	linenum_saved = 0;

int	stdin_only = FALSE;	/* Read input from stdin */

/*
 * curr_file    : Contains current file name processed.
 * curr_domain  : Contains the current domain for each dgettext().
 *		  This is NULL for gettext().
 * curr_line    : Contains the current line processed.
 * qstring_buf  : Contains the double quoted string processed.
 * curr_linenum : Line number being processed in the current input file.
 * warn_linenum : Line number of current warning message.
 */
char	curr_file[MAX_PATH_LEN];
static char	curr_domain[MAX_DOMAIN_LEN];
static char	curr_line[MAX_STRING_LEN];
static char	qstring_buf[MAX_STRING_LEN];
int	curr_linenum = 1;
int	warn_linenum = 0;

/*
 * strhead  : This list contains ANSI style string.
 *		Each node contains double quoted string.
 * strtail  : This is the tail of strhead.
 * commhead : This list contains comments string.
 *		Each node contains one line of comment.
 * commtail : This is the tail of commhead.
 */
static struct strlist_st	*strhead = NULL;
static struct strlist_st	*strtail = NULL;
static struct strlist_st	*commhead = NULL;
static struct strlist_st	*commtail = NULL;

/*
 * gargc : Same as argc. Used to pass argc to lex routine.
 * gargv : Same as argv. Used to pass argc to lex routine.
 */
int	gargc;
char	**gargv;

static void add_line_to_comment(void);
static void add_qstring_to_str(void);
static void add_str_to_element_list(int, char *);
static void copy_strlist_to_str(char *, struct strlist_st *);
static void end_ansi_string(void);
static void free_strlist(struct strlist_st *);
void handle_newline(void);
static void initialize_globals(void);
static void output_comment(FILE *, struct strlist_st *);
static void output_msgid(FILE *, struct strlist_st *, int);
static void output_textdomain(FILE *, struct element_st *);
static void print_help(void);
static void read_exclude_file(void);
static void trim_line(char *);
static void write_all_files(void);
static void write_one_file(struct domain_st *);

static void lstrcat(char *, const char *);

/*
 * Utility functions to malloc a node and initialize fields.
 */
static struct domain_st  *new_domain(void);
static struct strlist_st *new_strlist(void);
static struct element_st *new_element(void);
static struct exclude_st *new_exclude(void);

/*
 * Main program of xgettext.
 */
int
main(int argc, char **argv)
{
	int		opterr = FALSE;
	int		c;

	initialize_globals();

	while ((c = getopt(argc, argv, "jhax:nsc:d:m:M:p:t")) != EOF) {
		switch (c) {
		case 'a':
			aflg = TRUE;
			break;
		case 'c':
			cflg = TRUE;
			comment_tag = optarg;
			break;
		case 'd':
			default_domain = optarg;
			break;
		case 'h':
			hflg = TRUE;
			break;
		case 'j':
			jflg = TRUE;
			break;
		case 'M':
			Mflg = TRUE;
			suffix = optarg;
			break;
		case 'm':
			mflg = TRUE;
			prefix = optarg;
			break;
		case 'n':
			nflg = TRUE;
			break;
		case 'p':
			pflg = TRUE;
			pathname = optarg;
			break;
		case 's':
			sflg = TRUE;
			break;
		case 't':
			tflg = TRUE;
			break;
		case 'x':
			xflg = TRUE;
			exclude_file = optarg;
			break;
		case '?':
			opterr = TRUE;
			break;
		}
	}

	/* if -h is used, ignore all other options. */
	if (hflg == TRUE) {
		(void) fprintf(stderr, USAGE);
		print_help();
		exit(0);
	}

	/* -x can be used only with -a */
	if ((xflg == TRUE) && (aflg == FALSE))
		opterr = TRUE;

	/* -j cannot be used with -a */
	if ((jflg == TRUE) && (aflg == TRUE)) {
		(void) fprintf(stderr,
		"-a and -j options cannot be used together.\n");
		opterr = TRUE;
	}

	/* -j cannot be used with -s */
	if ((jflg == TRUE) && (sflg == TRUE)) {
		(void) fprintf(stderr,
		"-j and -s options cannot be used together.\n");
		opterr = TRUE;
	}

	if (opterr == TRUE) {
		(void) fprintf(stderr, USAGE);
		exit(2);
	}

	/* error, if no files are specified. */
	if (optind == argc) {
		(void) fprintf(stderr, USAGE);
		exit(2);
	}

	if (xflg == TRUE) {
		read_exclude_file();
	}

	/* If files are -, then read from stdin */
	if (argv[optind][0] == '-') {
		stdin_only = TRUE;
		optind++;
	} else {
		stdin_only = FALSE;
	}

	/* Store argc and argv to pass to yylex() */
	gargc = argc;
	gargv = argv;

#ifdef DEBUG
	(void) printf("optind=%d\n", optind);
	{
	int i = optind;
	for (; i < argc; i++) {
		(void) printf("   %d, <%s>\n", i, argv[i]);
	}
	}
#endif

	if (stdin_only == FALSE) {
		if (freopen(argv[optind], "r", stdin) == NULL) {
			(void) fprintf(stderr,
			"ERROR, can't open input file: %s\n", argv[optind]);
			exit(2);
		}
		(void) strcpy(curr_file, gargv[optind]);
		optind++;
	}

	/*
	 * Process input.
	 */
	(void) yylex();

#ifdef DEBUG
	printf("\n======= default_domain ========\n");
	print_one_domain(def_dom);
	printf("======= domain list ========\n");
	print_all_domain(dom_head);
#endif

	/*
	 * Write out all .po files.
	 */
	write_all_files();

	return (0);
} /* main */

/*
 * Prints help information for each option.
 */
static void
print_help(void)
{
	(void) fprintf(stderr, "\n");
	(void) fprintf(stderr, "-a\t\t\tfind ALL strings\n");
	(void) fprintf(stderr,
	    "-c <comment-tag>\tget comments containing <flag>\n");
	(void) fprintf(stderr,
	    "-d <default-domain>\tuse <default-domain> for default domain\n");
	(void) fprintf(stderr, "-h\t\t\tHelp\n");
	(void) fprintf(stderr,
	    "-j\t\t\tupdate existing file with the current result\n");
	(void) fprintf(stderr,
	    "-M <suffix>\t\tfill in msgstr with msgid<suffix>\n");
	(void) fprintf(stderr,
	    "-m <prefix>\t\tfill in msgstr with <prefix>msgid\n");
	(void) fprintf(stderr,
	    "-n\t\t\tline# file name and line number info in output\n");
	(void) fprintf(stderr,
	    "-p <pathname>\t\tuse <pathname> for output file directory\n");
	(void) fprintf(stderr,
	    "-s\t\t\tgenerate sorted output files\n");
	(void) fprintf(stderr, "-x <exclude-file>\texclude strings in file "
	    "<exclude-file> from output\n");
	(void) fprintf(stderr,
	    "-\t\t\tread stdin, use as a filter (input only)\n");
} /* print_help */

/*
 * Extract file name and line number information from macro line
 * and set the global variable accordingly.
 * The valid line format is
 *   1) # nnn
 *    or
 *   2) # nnn "xxxxx"
 *   where nnn is line number and xxxxx is file name.
 */
static void
extract_filename_linenumber(char *mline)
{
	int	num;
	char	*p, *q, *r;

	/*
	 * mline can contain multi newline.
	 * line number should be increased by the number of newlines.
	 */
	p = mline;
	while ((p = strchr(p, '\n')) != NULL) {
		p++;
		curr_linenum++;
	}
	p = strchr(mline, ' ');
	if (p == NULL)
		return;
	q = strchr(++p, ' ');
	if (q == NULL) {
		/* case 1 */
		if ((num = atoi(p)) > 0) {
			curr_linenum = num;
			return;
		}
	} else {
		/* case 2 */
		*q++ = 0;
		if (*q == '"') {
			q++;
			r = strchr(q, '"');
			if (r == NULL) {
				return;
			}
			*r = 0;
			if ((num = atoi(p)) > 0) {
				curr_linenum = num;
				(void) strcpy(curr_file, q);
			}
		}
	}
} /* extract_filename_linenumber */

/*
 * Handler for MACRO line which starts with #.
 */
void
handle_macro_line(void)
{
#ifdef DEBUG
	(void) printf("Macro line=<%s>\n", yytext);
#endif
	if (cflg == TRUE)
		lstrcat(curr_line, yytext);

	if (in_quote == TRUE) {
		lstrcat(qstring_buf, yytext);
	} else if (in_comment == FALSE) {
		extract_filename_linenumber(yytext);
	}

	curr_linenum--;
	handle_newline();
} /* handle_macro_line */

/*
 * Handler for C++ comments which starts with //.
 */
void
handle_cplus_comment_line(void)
{
	if (cflg == TRUE)
		lstrcat(curr_line, yytext);

	if (in_quote == TRUE) {
		lstrcat(qstring_buf, yytext);
	} else if ((in_comment == FALSE) &&
	    (in_skippable_string == FALSE)) {

		/*
		 * If already in c comments, don't do anything.
		 * Set both flags to TRUE here.
		 * Both flags will be set to FALSE when newline
		 * encounters.
		 */
		in_cplus_comment = TRUE;
		in_comment = TRUE;
	}
} /* handle_cplus_comment_line */

/*
 * Handler for the comment start (slash asterisk) in input file.
 */
void
handle_open_comment(void)
{
	if (cflg == TRUE)
		lstrcat(curr_line, yytext);

	if (in_quote == TRUE) {
		lstrcat(qstring_buf, yytext);
	} else if ((in_comment == FALSE) &&
	    (in_skippable_string == FALSE)) {

		in_comment = TRUE;
		is_last_comment_line = FALSE;
		/*
		 * If there is any comment extracted before accidently,
		 * clean it up and start the new comment again.
		 */
		free_strlist(commhead);
		commhead = commtail = NULL;
	}
}

/*
 * Handler for the comment end (asterisk slash) in input file.
 */
void
handle_close_comment(void)
{
	if (cflg == TRUE)
		lstrcat(curr_line, yytext);

	if (in_quote == TRUE) {
		lstrcat(qstring_buf, yytext);
	} else if (in_skippable_string == FALSE) {
		in_comment = FALSE;
		is_last_comment_line = TRUE;
	}
}

/*
 * Handler for "gettext" in input file.
 */
void
handle_gettext(void)
{
	/*
	 * If -t option is specified to extrct dcgettext,
	 * don't do anything for gettext().
	 */
	if (tflg == TRUE) {
		return;
	}

	num_nested_open_paren = 0;

	if (cflg == TRUE)
		lstrcat(curr_line, yytext);

	if (in_quote == TRUE) {
		lstrcat(qstring_buf, yytext);
	} else if (in_comment == FALSE) {
		in_gettext = TRUE;
		linenum_saved = curr_linenum;
		/*
		 * gettext will be put into default domain .po file
		 * curr_domain does not change for gettext.
		 */
		curr_domain[0] = '\0';
	}
} /* handle_gettext */

/*
 * Handler for "dgettext" in input file.
 */
void
handle_dgettext(void)
{
	/*
	 * If -t option is specified to extrct dcgettext,
	 * don't do anything for dgettext().
	 */
	if (tflg == TRUE) {
		return;
	}

	num_nested_open_paren = 0;

	if (cflg == TRUE)
		lstrcat(curr_line, yytext);

	if (in_quote == TRUE) {
		lstrcat(qstring_buf, yytext);
	} else if (in_comment == FALSE) {
		in_dgettext = TRUE;
		linenum_saved = curr_linenum;
		/*
		 * dgettext will be put into domain file specified.
		 * curr_domain will follow.
		 */
		curr_domain[0] = '\0';
	}
} /* handle_dgettext */

/*
 * Handler for "dcgettext" in input file.
 */
void
handle_dcgettext(void)
{
	/*
	 * dcgettext will be extracted only when -t flag is specified.
	 */
	if (tflg == FALSE) {
		return;
	}

	num_nested_open_paren = 0;

	is_first_comma_found = FALSE;

	if (cflg == TRUE)
		lstrcat(curr_line, yytext);

	if (in_quote == TRUE) {
		lstrcat(qstring_buf, yytext);
	} else if (in_comment == FALSE) {
		in_dcgettext = TRUE;
		linenum_saved = curr_linenum;
		/*
		 * dcgettext will be put into domain file specified.
		 * curr_domain will follow.
		 */
		curr_domain[0] = '\0';
	}
} /* handle_dcgettext */

/*
 * Handler for "textdomain" in input file.
 */
void
handle_textdomain(void)
{
	if (cflg == TRUE)
		lstrcat(curr_line, yytext);

	if (in_quote == TRUE) {
		lstrcat(qstring_buf, yytext);
	} else if (in_comment == FALSE) {
		in_textdomain = TRUE;
		linenum_saved = curr_linenum;
		curr_domain[0] = '\0';
	}
} /* handle_textdomain */

/*
 * Handler for '(' in input file.
 */
void
handle_open_paren(void)
{
	if (cflg == TRUE)
		lstrcat(curr_line, yytext);

	if (in_quote == TRUE) {
		lstrcat(qstring_buf, yytext);
	} else if (in_comment == FALSE) {
		if ((in_gettext == TRUE) ||
		    (in_dgettext == TRUE) ||
		    (in_dcgettext == TRUE) ||
		    (in_textdomain == TRUE)) {
			in_str = TRUE;
			num_nested_open_paren++;
		}
	}
} /* handle_open_paren */

/*
 * Handler for ')' in input file.
 */
void
handle_close_paren(void)
{
	if (cflg == TRUE)
		lstrcat(curr_line, yytext);

	if (in_quote == TRUE) {
		lstrcat(qstring_buf, yytext);
	} else if (in_comment == FALSE) {
		if ((in_gettext == TRUE) ||
		    (in_dgettext == TRUE) ||
		    (in_dcgettext == TRUE) ||
		    (in_textdomain == TRUE)) {
			/*
			 * If this is not the matching close paren with
			 * the first open paren, no action is necessary.
			 */
			if (--num_nested_open_paren > 0)
				return;
			add_str_to_element_list(in_textdomain, curr_domain);
			in_str = FALSE;
			in_gettext = FALSE;
			in_dgettext = FALSE;
			in_dcgettext = FALSE;
			in_textdomain = FALSE;
		} else if (aflg == TRUE) {
			end_ansi_string();
		}
	}
} /* handle_close_paren */

/*
 * Handler for '\\n' in input file.
 *
 * This is a '\' followed by new line.
 * This can be treated like a new line except when this is a continuation
 * of a ANSI-C string.
 * If this is a part of ANSI string, treat the current line as a double
 * quoted string and the next line is the start of the double quoted
 * string.
 */
void
handle_esc_newline(void)
{
	if (cflg == TRUE)
		lstrcat(curr_line, "\\");

	curr_linenum++;

	if (in_quote == TRUE) {
		add_qstring_to_str();
	} else if ((in_comment == TRUE) ||
	    (is_last_comment_line == TRUE)) {
		if (in_cplus_comment == FALSE) {
			add_line_to_comment();
		}
	}

	curr_line[0] = '\0';
} /* handle_esc_newline */

/*
 * Handler for '"' in input file.
 */
void
handle_quote(void)
{
	if (cflg == TRUE)
		lstrcat(curr_line, yytext);

	if (in_comment == TRUE) {
		/*EMPTY*/
	} else if ((in_gettext == TRUE) ||
	    (in_dgettext == TRUE) ||
	    (in_dcgettext == TRUE) ||
	    (in_textdomain == TRUE)) {
		if (in_str == TRUE) {
			if (in_quote == FALSE) {
				in_quote = TRUE;
			} else {
				add_qstring_to_str();
				in_quote = FALSE;
			}
		}
	} else if (aflg == TRUE) {
		/*
		 * The quote is found outside of gettext, dgetext, and
		 * textdomain. Everytime a quoted string is found,
		 * add it to the string list.
		 * in_str stays TRUE until ANSI string ends.
		 */
		if (in_str == TRUE) {
			if (in_quote == TRUE) {
				in_quote = FALSE;
				add_qstring_to_str();
			} else {
				in_quote = TRUE;
			}
		} else {
			in_str = TRUE;
			in_quote = TRUE;
			linenum_saved = curr_linenum;
		}
	} else {
		in_skippable_string = (in_skippable_string == TRUE) ?
		    FALSE : TRUE;
	}
} /* handle_quote */

/*
 * Handler for ' ' or TAB in input file.
 */
void
handle_spaces(void)
{
	if (cflg == TRUE)
		lstrcat(curr_line, yytext);

	if (in_quote == TRUE) {
		lstrcat(qstring_buf, yytext);
	}
} /* handle_spaces */

/*
 * Flattens a linked list containing ANSI string to the one string.
 */
static void
copy_strlist_to_str(char *str, struct strlist_st *strlist)
{
	struct strlist_st	*p;

	str[0] = '\0';

	if (strlist != NULL) {
		p = strlist;
		while (p != NULL) {
			if (p->str != NULL) {
				lstrcat(str, p->str);
			}
			p = p->next;
		}
	}
} /* copy_strlist_to_str */

/*
 * Handler for ',' in input file.
 */
void
handle_comma(void)
{
	if (cflg == TRUE)
		lstrcat(curr_line, yytext);

	if (in_quote == TRUE) {
		lstrcat(qstring_buf, yytext);
	} else if (in_comment == FALSE) {
		if (in_str == TRUE) {
			if (in_dgettext == TRUE) {
				copy_strlist_to_str(curr_domain, strhead);
				free_strlist(strhead);
				strhead = strtail = NULL;
			} else if (in_dcgettext == TRUE) {
				/*
				 * Ignore the second comma.
				 */
				if (is_first_comma_found == FALSE) {
					copy_strlist_to_str(curr_domain,
					    strhead);
					free_strlist(strhead);
					strhead = strtail = NULL;
					is_first_comma_found = TRUE;
				}
			} else if (aflg == TRUE) {
				end_ansi_string();
			}
		}
	}
} /* handle_comma */

/*
 * Handler for any other character that does not have special handler.
 */
void
handle_character(void)
{
	if (cflg == TRUE)
		lstrcat(curr_line, yytext);

	if (in_quote == TRUE) {
		lstrcat(qstring_buf, yytext);
	} else if (in_comment == FALSE) {
		if (in_str == TRUE) {
			if (aflg == TRUE) {
				end_ansi_string();
			}
		}
	}
} /* handle_character */

/*
 * Handler for new line in input file.
 */
void
handle_newline(void)
{
	curr_linenum++;

	/*
	 * in_quote is always FALSE here for ANSI-C code.
	 */
	if ((in_comment == TRUE) ||
	    (is_last_comment_line == TRUE)) {
		if (in_cplus_comment == TRUE) {
			in_cplus_comment = FALSE;
			in_comment = FALSE;
		} else {
			add_line_to_comment();
		}
	}

	curr_line[0] = '\0';
	/*
	 * C++ comment always ends with new line.
	 */
} /* handle_newline */

/*
 * Process ANSI string.
 */
static void
end_ansi_string(void)
{
	if ((aflg == TRUE) &&
	    (in_str == TRUE) &&
	    (in_gettext == FALSE) &&
	    (in_dgettext == FALSE) &&
	    (in_dcgettext == FALSE) &&
	    (in_textdomain == FALSE)) {
		add_str_to_element_list(FALSE, curr_domain);
		in_str = FALSE;
	}
} /* end_ansi_string */

/*
 * Initialize global variables if necessary.
 */
static void
initialize_globals(void)
{
	default_domain = strdup(DEFAULT_DOMAIN);
	curr_domain[0] = '\0';
	curr_file[0] = '\0';
	qstring_buf[0] = '\0';
} /* initialize_globals() */

/*
 * Extract only string part when read a exclude file by removing
 * keywords (e.g. msgid, msgstr, # ) and heading and trailing blanks and
 * double quotes.
 */
static void
trim_line(char *line)
{
	int	i, p, len;
	int	first = 0;
	int	last = 0;
	char	c;

	len = strlen(line);

	/*
	 * Find the position of the last non-whitespace character.
	 */
	i = len - 1;
	/*CONSTCOND*/
	while (1) {
		c = line[i--];
		if ((c != ' ') && (c != '\n') && (c != '\t')) {
			last = ++i;
			break;
		}
	}

	/*
	 * Find the position of the first non-whitespace character
	 * by skipping "msgid" initially.
	 */
	if (strncmp("msgid ", line, 6) == 0) {
		i = 5;
	} else if (strncmp("msgstr ", line, 7) == 0) {
		i = 6;
	} else if (strncmp("# ", line, 2) == 0) {
		i = 2;
	} else {
		i = 0;
	}

	/*CONSTCOND*/
	while (1) {
		c = line[i++];
		if ((c != ' ') && (c != '\n') && (c != '\t')) {
			first = --i;
			break;
		}
	}

	/*
	 * For Backward compatibility, we consider both double quoted
	 * string and non-quoted string.
	 * The double quote is removed before being stored if exists.
	 */
	if (line[first] == '"') {
		first++;
	}
	if (line[last] == '"') {
		last--;
	}

	/*
	 * Now copy the valid part of the string.
	 */
	p = first;
	for (i = 0; i <= (last-first); i++) {
		line[i] = line[p++];
	}
	line [i] = '\0';
} /* trim_line */

/*
 * Read exclude file and stores it in the global linked list.
 */
static void
read_exclude_file(void)
{
	FILE	*fp;
	struct exclude_st	*tmp_excl;
	struct strlist_st	*tail;
	int			ignore_line;
	char			line [MAX_STRING_LEN];

	if ((fp = fopen(exclude_file, "r")) == NULL) {
		(void) fprintf(stderr, "ERROR, can't open exclude file: %s\n",
		    exclude_file);
		exit(2);
	}

	ignore_line = TRUE;
	while (fgets(line, MAX_STRING_LEN, fp) != NULL) {
		/*
		 * Line starting with # is a comment line and ignored.
		 * Blank line is ignored, too.
		 */
		if ((line[0] == '\n') || (line[0] == '#')) {
			continue;
		} else if (strncmp(line, "msgstr", 6) == 0) {
			ignore_line = TRUE;
		} else if (strncmp(line, "domain", 6) == 0) {
			ignore_line = TRUE;
		} else if (strncmp(line, "msgid", 5) == 0) {
			ignore_line = FALSE;
			tmp_excl = new_exclude();
			tmp_excl->exstr = new_strlist();
			trim_line(line);
			tmp_excl->exstr->str = strdup(line);
			tail = tmp_excl->exstr;
			/*
			 * Prepend new exclude string node to the list.
			 */
			tmp_excl->next = excl_head;
			excl_head = tmp_excl;
		} else {
			/*
			 * If more than one line of string forms msgid,
			 * append it to the string linked list.
			 */
			if (ignore_line == FALSE) {
				trim_line(line);
				tail->next = new_strlist();
				tail->next->str = strdup(line);
				tail = tail->next;
			}
		}
	} /* while */

#ifdef DEBUG
	tmp_excl = excl_head;
	while (tmp_excl != NULL) {
		printf("============================\n");
		tail = tmp_excl->exstr;
		while (tail != NULL) {
			printf("%s###\n", tail->str);
			tail = tail->next;
		}
		tmp_excl = tmp_excl->next;
	}
#endif
} /* read_exclude_file */

/*
 * Get next character from the string list containing ANSI style string.
 * This function returns three valus. (p, *m, *c).
 * p is returned by return value and, *m and *c are returned by changing
 * values in the location pointed.
 *
 *  p : points node in the linked list for ANSI string.
 *	Each node contains double quoted string.
 *  m : The location of the next characters in the double quoted string
 *	as integer index in the string.
 *	When it gets to end of quoted string, the next node will be
 *	read and m starts as zero for every new node.
 *  c : Stores the value of the characterto be returned.
 */
static struct strlist_st *
get_next_ch(struct strlist_st *p, int *m, char *c)
{
	char	ch, oct, hex;
	int	value, i;

	/*
	 * From the string list, find non-null string first.
	 */

	/*CONSTCOND*/
	while (1) {
		if (p == NULL) {
			break;
		} else if (p->str == NULL)  {
			p = p->next;
		} else if (p->str[*m] == '\0') {
			p = p->next;
			*m = 0;
		} else {
			break;
		}
	}

	/*
	 * No more character is available.
	 */
	if (p == NULL) {
		*c = 0;
		return (NULL);
	}

	/*
	 * Check if the character back slash.
	 * If yes, ANSI defined escape sequence rule is used.
	 */
	if (p->str[*m] != '\\') {
		*c = p->str[*m];
		*m = *m + 1;
		return (p);
	} else {
		/*
		 * Get next character after '\'.
		 */
		*m = *m + 1;
		ch = p->str[*m];
		switch (ch) {
		case 'a':
			*c = '\a';
			break;
		case 'b':
			*c = '\b';
			break;
		case 'f':
			*c = '\f';
			break;
		case 'n':
			*c = '\n';
			break;
		case 'r':
			*c = '\r';
			break;
		case 't':
			*c = '\t';
			break;
		case 'v':
			*c = '\v';
			break;
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
			/*
			 * Get maximum of three octal digits.
			 */
			value = ch;
			for (i = 0; i < 2; i++) {
				*m = *m + 1;
				oct = p->str[*m];
				if ((oct >= '0') && (oct <= '7')) {
					value = value * 8 + (oct - '0');
				} else {
					*m = *m - 1;
					break;
				}
			}
			*c = value;
#ifdef DEBUG
			/* (void) fprintf(stderr, "octal=%d\n", value); */
#endif
			break;
		case 'x':
			value = 0;
			/*
			 * Remove all heading zeros first and
			 * get one or two valuid hexadecimal charaters.
			 */
			*m = *m + 1;
			while (p->str[*m] == '0') {
				*m = *m + 1;
			}
			value = 0;
			for (i = 0; i < 2; i++) {
				hex = p->str[*m];
				*m = *m + 1;
				if (isdigit(hex)) {
					value = value * 16 + (hex - '0');
				} else if (isxdigit(hex)) {
					hex = tolower(hex);
					value = value * 16 + (hex - 'a' + 10);
				} else {
					*m = *m - 1;
					break;
				}
			}
			*c = value;
#ifdef DEBUG
			(void) fprintf(stderr, "hex=%d\n", value);
#endif
			*m = *m - 1;
			break;
		default :
			/*
			 * Undefined by ANSI.
			 * Just ignore "\".
			 */
			*c = p->str[*m];
			break;
		}
		/*
		 * Advance pointer to point the next character to be parsed.
		 */
		*m = *m + 1;
		return (p);
	}
} /* get_next_ch */

/*
 * Compares two msgids.
 * Comparison is done by values, not by characters represented.
 * For example, '\t', '\011' and '0x9' are identical values.
 * Return values are same as in strcmp.
 *   1   if  msgid1 > msgid2
 *   0   if  msgid1 = msgid2
 *  -1   if  msgid1 < msgid2
 */
static int
msgidcmp(struct strlist_st *id1, struct strlist_st *id2)
{
	char	c1, c2;
	int	m1, m2;

	m1 = 0;
	m2 = 0;

	/*CONSTCOND*/
	while (1) {
		id1 = get_next_ch(id1, &m1, &c1);
		id2 = get_next_ch(id2, &m2, &c2);

		if ((c1 == 0) && (c2 == 0)) {
			return (0);
		}

		if (c1 > c2) {
			return (1);
		} else if (c1 < c2) {
			return (-1);
		}
	}
	/*NOTREACHED*/
} /* msgidcmp */

/*
 * Check if a ANSI string (which is a linked list itself) is a duplicate
 * of any string in the list of ANSI string.
 */
static int
isduplicate(struct element_st *list, struct strlist_st *str)
{
	struct element_st	*p;

	if (list == NULL) {
		return (FALSE);
	}

	p = list;
	while (p != NULL) {
		if (p->msgid != NULL) {
			if (msgidcmp(p->msgid, str) == 0) {
				return (TRUE);
			}
		}
		p = p->next;
	}

	return (FALSE);
} /* isduplicate */

/*
 * Extract a comment line and add to the linked list containing
 * comment block.
 * Each comment line is stored in the node.
 */
static void
add_line_to_comment(void)
{
	struct strlist_st	*tmp_str;

	tmp_str = new_strlist();
	tmp_str->str = strdup(curr_line);
	tmp_str->next = NULL;

	if (commhead == NULL) {
		/* Empty comment list */
		commhead = tmp_str;
		commtail = tmp_str;
	} else {
		/* append it to the list */
		commtail->next = tmp_str;
		commtail = commtail->next;
	}

	is_last_comment_line = FALSE;
} /* add_line_to_comment */

/*
 * Add a double quoted string to the linked list containing ANSI string.
 */
static void
add_qstring_to_str(void)
{
	struct strlist_st	*tmp_str;

	tmp_str = new_strlist();
	tmp_str->str = strdup(qstring_buf);
	tmp_str->next = NULL;

	if (strhead == NULL) {
		/* Null ANSI string */
		strhead = tmp_str;
		strtail = tmp_str;
	} else {
		/* Append it to the ANSI string linked list */
		strtail->next = tmp_str;
		strtail = strtail->next;
	}

	qstring_buf[0] = '\0';
} /* add_qstring_to_str */

/*
 * Finds the head of domain nodes given domain name.
 */
static struct domain_st *
find_domain_node(char *dname)
{
	struct domain_st	*tmp_dom, *p;

	/*
	 * If -a option is specified everything will be written to the
	 * default domain file.
	 */
	if (aflg == TRUE) {
		if (def_dom == NULL) {
			def_dom = new_domain();
		}
		return (def_dom);
	}

	if ((dname == NULL) ||
	    (dname[0] == '\0') ||
	    (strcmp(dname, default_domain) == 0)) {
		if (def_dom == NULL) {
			def_dom = new_domain();
		}
		if (strcmp(dname, default_domain) == 0) {
			(void) fprintf(stderr, "%s \"%s\" is used in dgettext "
			    "of file:%s line:%d.\n",
			    "Warning: default domain name",
			    default_domain, curr_file, curr_linenum);
		}
		return (def_dom);
	} else {
		p = dom_head;
		while (p != NULL) {
			if (strcmp(p->dname, dname) == 0) {
				return (p);
			}
			p = p->next;
		}

		tmp_dom = new_domain();
		tmp_dom->dname = strdup(dname);

		if (dom_head == NULL) {
			dom_head = tmp_dom;
			dom_tail = tmp_dom;
		} else {
			dom_tail->next = tmp_dom;
			dom_tail = dom_tail->next;
		}
		return (tmp_dom);
	}
} /* find_domain_node */

/*
 * Frees the ANSI string linked list.
 */
static void
free_strlist(struct strlist_st *ptr)
{
	struct strlist_st	*p;

	p = ptr;
	ptr = NULL;
	while (p != NULL) {
		ptr = p->next;
		free(p->str);
		free(p);
		p = ptr;
	}
} /* free_strlist */

/*
 * Finds if a ANSI string is contained in the exclude file.
 */
static int
isexcluded(struct strlist_st *strlist)
{
	struct exclude_st	*p;

	p = excl_head;
	while (p != NULL) {
		if (msgidcmp(p->exstr, strlist) == 0) {
			return (TRUE);
		}
		p = p->next;
	}
	return (FALSE);
} /* isexcluded */

/*
 * Finds if a comment block is to be extracted.
 *
 * When -c option is specified, find out if comment block contains
 * comment-tag as a token separated by blanks. If it does, this
 * comment block is associated with the next msgid encountered.
 * Comment block is a linked list where each node contains one line
 * of comments.
 */
static int
isextracted(struct strlist_st *strlist)
{
	struct strlist_st	*p;
	char			*first, *pc;


	p = strlist;
	while (p != NULL) {
		first = strdup(p->str);
		while ((first != NULL) && (first[0] != '\0')) {
			pc = first;

			/*CONSTCOND*/
			while (1) {
				if (*pc == '\0') {
					break;
				} else if ((*pc == ' ') || (*pc == '\t')) {
					*pc++ = '\0';
					break;
				}
				pc++;
			}
			if (strcmp(first, comment_tag) == 0) {
				return (TRUE);
			}
			first = pc;
		}
		p = p->next;
	} /* while */

	/*
	 * Not found.
	 */
	return (FALSE);
} /* isextracted */

/*
 * Adds ANSI string to the domain element list.
 */
static void
add_str_to_element_list(int istextdomain, char *domain_list)
{
	struct element_st	*tmp_elem;
	struct element_st	*p, *q;
	struct domain_st	*tmp_dom;
	int			result;

	/*
	 * This can happen if something like gettext(USAGE) is used
	 * and it is impossible to get msgid for this gettext.
	 * Since -x option should be used in this kind of cases,
	 * it is OK not to catch msgid.
	 */
	if (strhead == NULL) {
		return;
	}

	/*
	 * The global variable curr_domain contains either NULL
	 * for default_domain or domain name for dgettext().
	 */
	tmp_dom = find_domain_node(domain_list);

	/*
	 * If this msgid is in the exclude file,
	 * then free the linked list and return.
	 */
	if ((istextdomain == FALSE) &&
	    (isexcluded(strhead) == TRUE)) {
		free_strlist(strhead);
		strhead = strtail = NULL;
		return;
	}

	tmp_elem = new_element();
	tmp_elem->msgid = strhead;
	tmp_elem->istextdomain = istextdomain;
	/*
	 * If -c option is specified and TAG matches,
	 * then associate the comment to the next [d]gettext() calls
	 * encountered in the source code.
	 * textdomain() calls will not have any effect.
	 */
	if (istextdomain == FALSE) {
		if ((cflg == TRUE) && (commhead != NULL)) {
			if (isextracted(commhead) == TRUE) {
				tmp_elem->comment = commhead;
			} else {
				free_strlist(commhead);
			}
			commhead = commtail = NULL;
		}
	}

	tmp_elem->linenum = linenum_saved;
	tmp_elem->fname = strdup(curr_file);


	if (sflg == TRUE) {
		/*
		 * If this is textdomain() call and -s option is specified,
		 * append this node to the textdomain linked list.
		 */
		if (istextdomain == TRUE) {
			if (tmp_dom->textdomain_head == NULL) {
				tmp_dom->textdomain_head = tmp_elem;
				tmp_dom->textdomain_tail = tmp_elem;
			} else {
				tmp_dom->textdomain_tail->next = tmp_elem;
				tmp_dom->textdomain_tail = tmp_elem;
			}
			strhead = strtail = NULL;
			return;
		}

		/*
		 * Insert the node to the properly sorted position.
		 */
		q = NULL;
		p = tmp_dom->gettext_head;
		while (p != NULL) {
			result = msgidcmp(strhead, p->msgid);
			if (result == 0) {
				/*
				 * Duplicate id. Do not store.
				 */
				free_strlist(strhead);
				strhead = strtail = NULL;
				return;
			} else if (result > 0) {
				/* move to the next node */
				q = p;
				p = p->next;
			} else {
				tmp_elem->next = p;
				if (q != NULL) {
					q->next = tmp_elem;
				} else {
					tmp_dom->gettext_head = tmp_elem;
				}
				strhead = strtail = NULL;
				return;
			}
		} /* while */

		/*
		 * New msgid is the largest or empty list.
		 */
		if (q != NULL) {
			/* largest case */
			q->next = tmp_elem;
		} else {
			/* empty list */
			tmp_dom->gettext_head = tmp_elem;
		}
	} else {
		/*
		 * Check if this msgid is already in the same domain.
		 */
		if (tmp_dom != NULL) {
			if (isduplicate(tmp_dom->gettext_head,
			    tmp_elem->msgid) == TRUE) {
				tmp_elem->isduplicate = TRUE;
			}
		}
		/*
		 * If -s option is not specified, then everything
		 * is stored in gettext linked list.
		 */
		if (tmp_dom->gettext_head == NULL) {
			tmp_dom->gettext_head = tmp_elem;
			tmp_dom->gettext_tail = tmp_elem;
		} else {
			tmp_dom->gettext_tail->next = tmp_elem;
			tmp_dom->gettext_tail = tmp_elem;
		}
	}

	strhead = strtail = NULL;
} /* add_str_to_element_list */

/*
 * Write all domain linked list to the files.
 */
static void
write_all_files(void)
{
	struct domain_st	*tmp;

	/*
	 * Write out default domain file.
	 */
	write_one_file(def_dom);

	/*
	 * If dgettext() exists and -a option is not used,
	 * then there are non-empty linked list.
	 */
	tmp = dom_head;
	while (tmp != NULL) {
		write_one_file(tmp);
		tmp = tmp->next;
	}
} /* write_all_files */

/*
 * add an element_st list to the linked list.
 */
static void
add_node_to_polist(struct element_st **pohead,
    struct element_st **potail, struct element_st *elem)
{
	if (elem == NULL) {
		return;
	}

	if (*pohead == NULL) {
		*pohead = *potail = elem;
	} else {
		(*potail)->next = elem;
		*potail = (*potail)->next;
	}
} /* add_node_to_polist */

#define	INIT_STATE	0
#define	IN_MSGID	1
#define	IN_MSGSTR	2
#define	IN_COMMENT	3
/*
 * Reads existing po file into the linked list and returns the head
 * of the linked list.
 */
static struct element_st *
read_po(char *fname)
{
	struct element_st	*tmp_elem = NULL;
	struct element_st	*ehead = NULL, *etail = NULL;
	struct strlist_st	*comment_tail = NULL;
	struct strlist_st	*msgid_tail = NULL;
	struct strlist_st	*msgstr_tail = NULL;
	int			state = INIT_STATE;
	char			line [MAX_STRING_LEN];
	FILE			*fp;

	if ((fp = fopen(fname, "r")) == NULL) {
		return (NULL);
	}

	while (fgets(line, MAX_STRING_LEN, fp) != NULL) {
		/*
		 * Line starting with # is a comment line and ignored.
		 * Blank line is ignored, too.
		 */
		if (line[0] == '\n') {
			continue;
		} else if (line[0] == '#') {
			/*
			 * If tmp_elem is not NULL, there is msgid pair
			 * stored. Therefore, add it.
			 */
			if ((tmp_elem != NULL) && (state == IN_MSGSTR)) {
				add_node_to_polist(&ehead, &etail, tmp_elem);
			}

			if ((state == INIT_STATE) || (state == IN_MSGSTR)) {
				state = IN_COMMENT;
				tmp_elem = new_element();
				tmp_elem->comment = comment_tail =
				    new_strlist();
				/*
				 * remove new line and skip "# "
				 * in the beginning of the existing
				 * comment line.
				 */
				line[strlen(line)-1] = 0;
				comment_tail->str = strdup(line+2);
			} else if (state == IN_COMMENT) {
				comment_tail->next = new_strlist();
				comment_tail = comment_tail->next;
				/*
				 * remove new line and skip "# "
				 * in the beginning of the existing
				 * comment line.
				 */
				line[strlen(line)-1] = 0;
				comment_tail->str = strdup(line+2);
			}

		} else if (strncmp(line, "domain", 6) == 0) {
			/* ignore domain line */
			continue;
		} else if (strncmp(line, "msgid", 5) == 0) {
			if (state == IN_MSGSTR) {
				add_node_to_polist(&ehead, &etail, tmp_elem);
				tmp_elem = new_element();
			} else if (state == INIT_STATE) {
				tmp_elem = new_element();
			}

			state = IN_MSGID;
			trim_line(line);
			tmp_elem->msgid = msgid_tail = new_strlist();
			msgid_tail->str = strdup(line);

		} else if (strncmp(line, "msgstr", 6) == 0) {
			state = IN_MSGSTR;
			trim_line(line);
			tmp_elem->msgstr = msgstr_tail = new_strlist();
			msgstr_tail->str = strdup(line);
		} else {
			/*
			 * If more than one line of string forms msgid,
			 * append it to the string linked list.
			 */
			if (state == IN_MSGID) {
				trim_line(line);
				msgid_tail->next = new_strlist();
				msgid_tail = msgid_tail->next;
				msgid_tail->str = strdup(line);
			} else if (state == IN_MSGSTR) {
				trim_line(line);
				msgstr_tail->next = new_strlist();
				msgstr_tail = msgstr_tail->next;
				msgstr_tail->str = strdup(line);
			}
		}
	} /* while */

	/*
	 * To insert the last msgid pair.
	 */
	if (tmp_elem != NULL) {
		add_node_to_polist(&ehead, &etail, tmp_elem);
	}

#ifdef DEBUG
	{
		struct domain_st *tmp_domain = new_domain();
		char	tmpstr[256];

		sprintf(tmpstr, "existing_po file : <%s>", fname);
		tmp_domain->dname = strdup(tmpstr);
		tmp_domain->gettext_head = ehead;
		printf("======= existing po file <%s>  ========\n", fname);
		print_one_domain(tmp_domain);
	}
#endif /* DEBUG */

	(void) fclose(fp);
	return (ehead);
} /* read_po */

/*
 * This function will append the second list to the first list.
 * If the msgid in the second list contains msgid in the first list,
 * it will be marked as duplicate.
 */
static struct element_st *
append_list(struct element_st *l1, struct element_st *l2)
{
	struct element_st	*p = NULL, *q = NULL, *l1_tail = NULL;

	if (l1 == NULL)
		return (l2);
	if (l2 == NULL)
		return (l1);

	/*
	 * in this while loop, just mark isduplicate field of node in the
	 * l2 list if the same msgid exists in l1 list.
	 */
	p = l2;
	while (p != NULL) {
		q = l1;
		while (q != NULL) {
			if (msgidcmp(p->msgid, q->msgid) == 0) {
				p->isduplicate = TRUE;
				break;
			}
			q = q->next;
		}
		p = p->next;
	}

	/* Now connect two linked lists. */
	l1_tail = l1;
	while (l1_tail->next != NULL) {
		if (l1->next == NULL)
			break;
		l1_tail = l1_tail-> next;
	}
	l1_tail->next = l2;

	return (l1);
} /* append_list */

/*
 * Writes one domain list to the file.
 */
static void
write_one_file(struct domain_st *head)
{
	FILE			*fp;
	char			fname [MAX_PATH_LEN];
	char			dname [MAX_DOMAIN_LEN];
	struct element_st	*p;
	struct element_st	*existing_po_list;

	/*
	 * If head is NULL, then it still has to create .po file
	 * so that it will guarantee that the previous .po file was
	 * alwasys deleted.
	 * This is why checking NULL pointer has been moved to after
	 * creating  .po file.
	 */

	/*
	 * If domain name is NULL, it is the default domain list.
	 * The domain name is either "messages" or specified by option -d.
	 * The default domain name is contained in default_domain variable.
	 */
	dname[0] = '\0';
	if ((head != NULL) &&
	    (head->dname != NULL)) {
		(void) strcpy(dname, head->dname);
	} else {
		(void) strcpy(dname, default_domain);
	}

	/*
	 * path is the current directory if not specified by option -p.
	 */
	fname[0] = 0;
	if (pflg == TRUE) {
		(void) strcat(fname, pathname);
		(void) strcat(fname, "/");
	}
	(void) strcat(fname, dname);
	(void) strcat(fname, ".po");

	/*
	 * If -j flag is specified, read exsiting .po file and
	 * append the current list to the end of the list read from
	 * the existing .po file.
	 */
	if (jflg == TRUE) {
		/*
		 * If head is NULL, we don't have to change existing file.
		 * Therefore, just return it.
		 */
		if (head == NULL) {
			return;
		}
		existing_po_list = read_po(fname);
		head->gettext_head = append_list(existing_po_list,
		    head->gettext_head);
#ifdef DEBUG
		if (head->dname != NULL) {
			printf("===after merge (-j option): <%s>===\n",
			    head->dname);
		} else {
			printf("===after merge (-j option): <NULL>===\n");
		}
		print_one_domain(head);
#endif

	} /* if jflg */

	if ((fp = fopen(fname, "w")) == NULL) {
		(void) fprintf(stderr,
		    "ERROR, can't open output file: %s\n", fname);
		exit(2);
	}

	(void) fprintf(fp, "domain \"%s\"\n", dname);

	/* See comments above in the beginning of this function */
	if (head == NULL)
		return;

	/*
	 * There are separate storage for textdomain() calls if
	 * -s option is used (textdomain_head linked list).
	 * Otherwise, textdomain() is mixed with gettext(0 and dgettext().
	 * If mixed, the boolean varaible istextdomain is used to see
	 * if the current node contains textdomain() or [d]gettext().
	 */
	if (sflg == TRUE) {
		p = head->textdomain_head;
		while (p != NULL) {
			/*
			 * textdomain output line already contains
			 * FIle name and line number information.
			 * Therefore, does not have to check for nflg.
			 */
			output_textdomain(fp, p);
			p = p->next;
		}
	}

	p = head->gettext_head;
	while (p != NULL) {

		/*
		 * Comment is printed only if -c is used and
		 * associated with gettext or dgettext.
		 * textdomain is not associated with comments.
		 * Changes:
		 *    comments should be extracted in case of -j option
		 *    because there are read from exising file.
		 */
		if (((cflg == TRUE) || (jflg == TRUE)) &&
		    (p->istextdomain != TRUE)) {
			output_comment(fp, p->comment);
		}

		/*
		 * If -n is used, then file number and line number
		 * information is printed.
		 * In case of textdomain(), this information is redundant
		 * and is not printed.
		 * If linenum is 0, it means this information has been
		 * read from existing po file and it already contains
		 * file and line number info as a comment line. So, it
		 * should not printed in such case.
		 */
		if ((nflg == TRUE) && (p->istextdomain == FALSE) &&
		    (p->linenum > 0)) {
			(void) fprintf(fp, "# File:%s, line:%d\n",
			    p->fname, p->linenum);
		}

		/*
		 * Depending on the type of node, output textdomain comment
		 * or msgid.
		 */
		if ((sflg == FALSE) &&
		    (p->istextdomain == TRUE)) {
			output_textdomain(fp, p);
		} else {
			output_msgid(fp, p->msgid, p->isduplicate);
		}
		p = p->next;

	} /* while */

	(void) fclose(fp);
} /* write_one_file */

/*
 * Prints out textdomain call as a comment line with file name and
 * the line number information.
 */
static void
output_textdomain(FILE *fp, struct element_st *p)
{

	if (p == NULL)
		return;

	/*
	 * Write textdomain() line as a comment.
	 */
	(void) fprintf(fp, "# File:%s, line:%d, textdomain(\"%s\");\n",
	    p->fname, p->linenum,  p->msgid->str);
} /* output_textdomain */

/*
 * Prints out comments from linked list.
 */
static void
output_comment(FILE *fp, struct strlist_st *p)
{
	if (p == NULL)
		return;

	/*
	 * Write comment section.
	 */
	while (p != NULL) {
		(void) fprintf(fp, "# %s\n", p->str);
		p = p->next;
	}
} /* output_comment */

/*
 * Prints out msgid along with msgstr.
 */
static void
output_msgid(FILE *fp, struct strlist_st *p, int duplicate)
{
	struct strlist_st	*q;

	if (p == NULL)
		return;

	/*
	 * Write msgid section.
	 * If duplciate flag is ON, prepend "# " in front of every line
	 * so that they are considered as comment lines in .po file.
	 */
	if (duplicate == TRUE) {
		(void) fprintf(fp, "# ");
	}
	(void) fprintf(fp, "msgid  \"%s\"\n", p->str);
	q = p->next;
	while (q != NULL) {
		if (duplicate == TRUE) {
			(void) fprintf(fp, "# ");
		}
		(void) fprintf(fp, "       \"%s\"\n", q->str);
		q = q->next;
	}

	/*
	 * Write msgstr section.
	 * if -M option is specified, append <suffix> to msgid.
	 * if -m option is specified, prepend <prefix> to msgid.
	 */
	if (duplicate == TRUE) {
		(void) fprintf(fp, "# ");
	}
	if ((mflg == TRUE) || (Mflg == TRUE)) {
		if (mflg == TRUE) {
			/*
			 * If single line msgid, add suffix to the same line
			 */
			if ((Mflg == TRUE) && (p->next == NULL)) {
				/* -M and -m and single line case */
				(void) fprintf(fp, "msgstr \"%s%s%s\"\n",
				    prefix, p->str, suffix);
			} else {
				/* -M and -m and multi line case */
				(void) fprintf(fp, "msgstr \"%s%s\"\n",
				    prefix, p->str);
			}
		} else {
			if ((Mflg == TRUE) && (p->next == NULL)) {
				/* -M only with single line case */
				(void) fprintf(fp, "msgstr \"%s%s\"\n",
				    p->str, suffix);
			} else {
				/* -M only with multi line case */
				(void) fprintf(fp, "msgstr \"%s\"\n", p->str);
			}
		}
		q = p->next;
		while (q != NULL) {
			if (duplicate == TRUE) {
				(void) fprintf(fp, "# ");
			}
			(void) fprintf(fp, "       \"%s\"\n", q->str);
			q = q->next;
		}
		/*
		 * If multi line msgid, add suffix after the last line.
		 */
		if ((Mflg == TRUE) && (p->next != NULL) &&
		    (suffix[0] != '\0')) {
			(void) fprintf(fp, "       \"%s\"\n", suffix);
		}
	} else {
		(void) fprintf(fp, "msgstr\n");
	}
} /* output_msgid */

/*
 * Malloc a new element node and initialize fields.
 */
static struct element_st *
new_element(void)
{
	struct element_st *tmp;

	tmp = (struct element_st *)malloc(sizeof (struct element_st));
	tmp->istextdomain = FALSE;
	tmp->isduplicate = FALSE;
	tmp->msgid = NULL;
	tmp->msgstr = NULL;
	tmp->comment = NULL;
	tmp->fname = NULL;
	tmp->linenum = 0;
	tmp->next = NULL;

	return (tmp);
} /* new_element */

/*
 * Malloc a new domain node and initialize fields.
 */
static struct domain_st *
new_domain(void)
{
	struct domain_st *tmp;

	tmp = (struct domain_st *)malloc(sizeof (struct domain_st));
	tmp->dname = NULL;
	tmp->gettext_head = NULL;
	tmp->gettext_tail = NULL;
	tmp->textdomain_head = NULL;
	tmp->textdomain_tail = NULL;
	tmp->next = NULL;

	return (tmp);
} /* new_domain */

/*
 * Malloc a new string list node and initialize fields.
 */
static struct strlist_st *
new_strlist(void)
{
	struct strlist_st *tmp;

	tmp = (struct strlist_st *)malloc(sizeof (struct strlist_st));
	tmp->str = NULL;
	tmp->next = NULL;

	return (tmp);
} /* new_strlist */

/*
 * Malloc a new exclude string list node and initialize fields.
 */
static struct exclude_st *
new_exclude(void)
{
	struct exclude_st *tmp;

	tmp = (struct exclude_st *)malloc(sizeof (struct exclude_st));
	tmp->exstr = NULL;
	tmp->next = NULL;

	return (tmp);
} /* new_exclude */

/*
 * Local version of strcat to keep within maximum string size.
 */
static void
lstrcat(char *s1, const char *s2)
{
	char	*es1 = &s1[MAX_STRING_LEN];
	char	*ss1 = s1;

	while (*s1++)
		;
	--s1;
	while (*s1++ = *s2++)
		if (s1 >= es1) {
			s1[-1] = '\0';
			if ((in_comment == TRUE || in_quote == TRUE) &&
			    (warn_linenum != curr_linenum)) {
				if (stdin_only == FALSE) {
					(void) fprintf(stderr,
					    "WARNING: file %s line %d exceeds "\
					    "%d characters:  \"%15.15s\"\n",
					    curr_file, curr_linenum,
					    MAX_STRING_LEN, ss1);
				} else {
					(void) fprintf(stderr,
					    "WARNING: line %d exceeds "\
					    "%d characters:  \"%15.15s\"\n",
					    curr_linenum, MAX_STRING_LEN, ss1);
				}
				warn_linenum = curr_linenum;
			}
			break;
		}
} /* lstrcat */

#ifdef DEBUG
/*
 * Debug print routine. Compiled only with DEBUG on.
 */
void
print_element_list(struct element_st *q)
{
	struct strlist_st	*r;

	while (q != NULL) {
		printf("   istextdomain = %d\n", q->istextdomain);
		printf("   isduplicate  = %d\n", q->isduplicate);
		if ((q->msgid != NULL) && (q->msgid->str != NULL)) {
			printf("   msgid = <%s>\n", q->msgid->str);
			r = q->msgid->next;
			while (r != NULL) {
				printf("           <%s>\n", r->str);
				r = r->next;
			}
		} else {
			printf("   msgid = <NULL>\n");
		}
		if ((q->msgstr != NULL) && (q->msgstr->str != NULL)) {
			printf("   msgstr= <%s>\n", q->msgstr->str);
			r = q->msgstr->next;
			while (r != NULL) {
				printf("           <%s>\n", r->str);
				r = r->next;
			}
		} else {
			printf("   msgstr= <NULL>\n");
		}

		if (q->comment == NULL) {
			printf("   comment = <NULL>\n");
		} else {
			printf("   comment = <%s>\n", q->comment->str);
			r = q->comment->next;
			while (r != NULL) {
				printf("             <%s>\n", r->str);
				r = r->next;
			}
		}

		if (q->fname == NULL) {
			printf("   fname = <NULL>\n");
		} else {
			printf("   fname = <%s>\n", q->fname);
		}
		printf("   linenum = %d\n", q->linenum);
		printf("\n");
		q = q->next;
	}
}

/*
 * Debug print routine. Compiled only with DEBUG on.
 */
void
print_one_domain(struct domain_st *p)
{
	struct element_st	*q;

	if (p == NULL) {
		printf("domain pointer = <NULL>\n");
		return;
	} else if (p->dname == NULL) {
		printf("domain_name = <%s>\n", "<NULL>");
	} else {
		printf("domain_name = <%s>\n", p->dname);
	}
	q = p->gettext_head;
	print_element_list(q);

	q = p->textdomain_head;
	print_element_list(q);
} /* print_one_domain */

void
print_all_domain(struct domain_st *dom_list)
{
	struct domain_st	*p;
	struct element_st	*q;

	p = dom_list;
	while (p != NULL) {
		print_one_domain(p);
		p = p->next;
	} /* while */
} /* print_all_domain */
#endif
