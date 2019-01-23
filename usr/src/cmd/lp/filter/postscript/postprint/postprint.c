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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 *
 * postprint - PostScript translator for ASCII files.
 *
 * A simple program that translates ASCII files into PostScript. All it really
 * does is expand tabs and backspaces, handle character quoting, print text lines,
 * and control when pages are started based on the requested number of lines per
 * page.
 *
 * The PostScript prologue is copied from *prologue before any of the input files
 * are translated. The program expects that the following procedures are defined
 * in that file:
 *
 *	setup
 *
 *	  mark ... setup -
 *
 *	    Handles special initialization stuff that depends on how the program
 *	    was called. Expects to find a mark followed by key/value pairs on the
 *	    stack. The def operator is applied to each pair up to the mark, then
 *	    the default state is set up.
 *
 *	pagesetup
 *
 *	  page pagesetup -
 *
 *	    Does whatever is needed to set things up for the next page. Expects
 *	    to find the current page number on the stack.
 *
 *	l
 *
 *	  string l -
 *
 *	    Prints string starting in the first column and then goes to the next
 *	    line.
 *
 *	L
 *
 *	  mark string column string column ... L mark
 *
 *	    Prints each string on the stack starting at the horizontal position
 *	    selected by column. Used when tabs and spaces can be sufficiently well
 *	    compressed to make the printer overhead worthwhile. Always used when
 *	    we have to back up.
 *
 *	done
 *
 *	  done
 *
 *	    Makes sure the last page is printed. Only needed when we're printing
 *	    more than one page on each sheet of paper.
 *
 * Almost everything has been changed in this version of postprint. The program
 * is more intelligent, especially about tabs, spaces, and backspacing, and as a
 * result output files usually print faster. Output files also now conform to
 * Adobe's file structuring conventions, which is undoubtedly something I should
 * have done in the first version of the program. If the number of lines per page
 * is set to 0, which can be done using the -l option, pointsize will be used to
 * guess a reasonable value. The estimate is based on the values of LINESPP,
 * POINTSIZE, and pointsize, and assumes LINESPP lines would fit on a page if
 * we printed in size POINTSIZE. Selecting a point size using the -s option and
 * adding -l0 to the command line forces the guess to be made.
 *
 * Many default values, like the magnification and orientation, are defined in
 * the prologue, which is where they belong. If they're changed (by options), an
 * appropriate definition is made after the prologue is added to the output file.
 * The -P option passes arbitrary PostScript through to the output file. Among
 * other things it can be used to set (or change) values that can't be accessed by
 * other options.
 *
 */


#include <stdio.h>
#include <signal.h>
#include <ctype.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#include "comments.h"			/* PostScript file structuring comments */
#include "gen.h"			/* general purpose definitions */
#include "path.h"			/* for the prologue */
#include "ext.h"			/* external variable declarations */
#include "postprint.h"			/* a few special definitions */


char	*optnames = "a:c:e:f:l:m:n:o:p:r:s:t:x:y:A:C:J:L:P:R:DI";

char	*prologue = POSTPRINT;		/* default PostScript prologue */
char	*formfile = FORMFILE;		/* stuff for multiple pages per sheet */
char	*locale = NULL;

int	formsperpage = 1;		/* page images on each piece of paper */
int	copies = 1;			/* and this many copies of each sheet */

int	linespp = LINESPP;		/* number of lines per page */
int	pointsize = POINTSIZE;		/* in this point size */
int	tabstops = TABSTOPS;		/* tabs set at these columns */
int	crmode = 0;			/* carriage return mode - 0, 1, or 2 */

int	col = 1;			/* next character goes in this column */
int	line = 1;			/* on this line */

int	stringcount = 0;		/* number of strings on the stack */
int	stringstart = 1;		/* column where current one starts */

Fontmap	fontmap[] = FONTMAP;		/* for translating font names */
char	*fontname = "Courier";		/* use this PostScript font */

int	page = 0;			/* page we're working on */
int	printed = 0;			/* printed this many pages */

FILE	*fp_in = stdin;			/* read from this file */
FILE	*fp_out = stdout;		/* and write stuff here */
FILE	*fp_acct = NULL;		/* for accounting data */

static void account(void);
static void arguments(void);
static void done(void);
static void endline(void);
static void formfeed(void);
static void header(void);
static void init_signals(void);
static void newline(void);
static void options(void);
static void oput(int);
static void redirect(int);
static void setup(void);
static void spaces(int);
static void startline(void);
static void text(void);

/*****************************************************************************/


int
main(int agc, char *agv[])
{

/*
 *
 * A simple program that translates ASCII files into PostScript. If there's more
 * than one input file, each begins on a new page.
 *
 */


    argc = agc;				/* other routines may want them */
    argv = agv;

    prog_name = argv[0];		/* really just for error messages */

    init_signals();			/* sets up interrupt handling */
    header();				/* PostScript header and prologue */
    setup();				/* for PostScript */
    arguments();			/* followed by each input file */
    done();				/* print the last page etc. */
    account();				/* job accounting data */

    return (x_stat);			/* not much could be wrong */

}   /* End of main */


/*****************************************************************************/


static void
init_signals(void)
{
    void	interrupt();		/* signal handler */

/*
 *
 * Makes sure we handle interrupts.
 *
 */


    if ( signal(SIGINT, interrupt) == SIG_IGN )  {
	signal(SIGINT, SIG_IGN);
	signal(SIGQUIT, SIG_IGN);
	signal(SIGHUP, SIG_IGN);
    } else {
	signal(SIGHUP, interrupt);
	signal(SIGQUIT, interrupt);
    }   /* End else */

    signal(SIGTERM, interrupt);

}   /* End of init_signals */


/*****************************************************************************/


static void
header(void)
{
    int		ch;			/* return value from getopt() */
    int		old_optind = optind;	/* for restoring optind - should be 1 */

/*
 *
 * Scans the option list looking for things, like the prologue file, that we need
 * right away but could be changed from the default. Doing things this way is an
 * attempt to conform to Adobe's latest file structuring conventions. In particular
 * they now say there should be nothing executed in the prologue, and they have
 * added two new comments that delimit global initialization calls. Once we know
 * where things really are we write out the job header, follow it by the prologue,
 * and then add the ENDPROLOG and BEGINSETUP comments.
 *
 */


    while ( (ch = getopt(argc, argv, optnames)) != EOF )
	if ( ch == 'L' )
	    prologue = optarg;
	else if ( ch == '?' )
	    error(FATAL, "");

    optind = old_optind;		/* get ready for option scanning */

    fprintf(stdout, "%s", CONFORMING);
    fprintf(stdout, "%s %s\n", CREATOR, "%M%");
    fprintf(stdout, "%s %s\n", VERSION, "%I%");
    fprintf(stdout, "%s %s\n", DOCUMENTFONTS, ATEND);
    fprintf(stdout, "%s %s\n", PAGES, ATEND);
    fprintf(stdout, "%s", ENDCOMMENTS);

    options();				/* handle the command line options */

    if ( cat(prologue) == FALSE )
	error(FATAL, "can't read %s", prologue);

    fprintf(stdout, "%s", ENDPROLOG);
    fprintf(stdout, "%s", BEGINSETUP);
    fprintf(stdout, "mark\n");

}   /* End of header */


/*****************************************************************************/


static void
options(void)
{
    int		ch;			/* return value from getopt() */
    int		euro = 0;
    extern char *getenv(char *);


/*
 *
 * Reads and processes the command line options. Added the -P option so arbitrary
 * PostScript code can be passed through. Expect it could be useful for changing
 * definitions in the prologue for which options have not been defined.
 *
 * Although any PostScript font can be used, things will only work well for
 * constant width fonts.
 *
 */

    if  (((locale = getenv("LC_MONETARY")) != NULL) ||
         ((locale = getenv("LANG")) != NULL)) {
        char *tmp = NULL;

        /* if there is a locale specific prologue, use it as the default */
        if ((tmp = calloc(1, strlen(POSTPRINT) + strlen(locale) + 2)) != NULL) {
            sprintf(tmp, "%s-%s", POSTPRINT, locale);
            if (access(tmp, R_OK) == 0)
                    prologue = tmp;
            else
                    free(tmp);
        }

        /* if the locale has 8859-15 or euro in it, add the symbol to font */
        if ((strstr(locale, "8859-15") != NULL) ||
	    (strstr(locale, "euro") != NULL))
		euro = 1;
    }

    while ( (ch = getopt(argc, argv, optnames)) != EOF )  {
#if defined(DEBUG)
	fprintf(stderr, " Opt: %c, arg: %s\n", ch, optarg);
#endif
	switch ( ch )  {

	    case 'a':			/* aspect ratio */
		    fprintf(stdout, "/aspectratio %s def\n", optarg);
		    break;

	    case 'c':			/* copies */
		    copies = atoi(optarg);
		    fprintf(stdout, "/#copies %s store\n", optarg);
		    break;

	    case 'e':			/* should we add the euro ? */
		    euro = (strcasecmp(optarg, "on") == 0);
		    break;

	    case 'f':			/* use this PostScript font */
		    fontname = get_font(optarg);
		    fprintf(stdout, "/font /%s def\n", fontname);
		    break;

	    case 'l':			/* lines per page */
		    linespp = atoi(optarg);
		    break;

	    case 'm':			/* magnification */
		    fprintf(stdout, "/magnification %s def\n", optarg);
		    break;

	    case 'n':			/* forms per page */
		    formsperpage = atoi(optarg);

		    if (formsperpage <= 0) {
			/* set default value */
			formsperpage = 1;
		    }

		    fprintf(stdout, "/formsperpage %d def\n", formsperpage);

		    break;

	    case 'o':			/* output page list */
		    out_list(optarg);
		    break;

	    case 'p':			/* landscape or portrait mode */
		    if ( *optarg == 'l' )
			fprintf(stdout, "/landscape true def\n");
		    else fprintf(stdout, "/landscape false def\n");
		    break;

	    case 'r':			/* carriage return mode */
		    crmode = atoi(optarg);
		    break;

	    case 's':			/* point size */
		    pointsize = atoi(optarg);
		    fprintf(stdout, "/pointsize %s def\n", optarg);
		    break;

	    case 't':			/* tabstops */
		    tabstops = atoi(optarg);

		    if (tabstops <= 0) {
			/* set default */
			tabstops = TABSTOPS;
		    }

		    break;

	    case 'x':			/* shift things horizontally */
		    fprintf(stdout, "/xoffset %s def\n", optarg);
		    break;

	    case 'y':			/* and vertically on the page */
		    fprintf(stdout, "/yoffset %s def\n", optarg);
		    break;

	    case 'A':			/* force job accounting */
	    case 'J':
		    if ( (fp_acct = fopen(optarg, "a")) == NULL )
			error(FATAL, "can't open accounting file %s", optarg);
		    break;

	    case 'C':			/* copy file straight to output */
		    if ( cat(optarg) == FALSE )
			error(FATAL, "can't read %s", optarg);
		    break;

	    case 'L':			/* PostScript prologue file */
		    prologue = optarg;
		    break;

	    case 'P':			/* PostScript pass through */
		    fprintf(stdout, "%s\n", optarg);
		    break;

	    case 'R':			/* special global or page level request */
		    saverequest(optarg);
		    break;

	    case 'D':			/* debug flag */
		    debug = ON;
		    break;

	    case 'I':			/* ignore FATAL errors */
		    ignore = ON;
		    break;

	    case '?':			/* don't understand the option */
		    error(FATAL, "");
		    break;

	    default:			/* don't know what to do for ch */
		    error(FATAL, "missing case for option %c\n", ch);
		    break;

	}   /* End switch */

    }   /* End while */

    if (euro != 0)
	fprintf(stdout, "/must-add-euro-to-font true def\n");

    argc -= optind;			/* get ready for non-option args */
    argv += optind;

}   /* End of options */


/*****************************************************************************/


char *get_font(name)


    char	*name;			/* name the user asked for */


{


    int		i;			/* for looking through fontmap[] */


/*
 *
 * Called from options() to map a user's font name into a legal PostScript name.
 * If the lookup fails *name is returned to the caller. That should let you choose
 * any PostScript font, although things will only work well for constant width
 * fonts.
 *
 */


    for ( i = 0; fontmap[i].name != NULL; i++ )
	if ( strcmp(name, fontmap[i].name) == 0 )
	    return(fontmap[i].val);

    return(name);

}   /* End of get_font */


/*****************************************************************************/


static void
setup(void)
{

/*
 *
 * Handles things that must be done after the options are read but before the
 * input files are processed. linespp (lines per page) can be set using the -l
 * option. If it's not positive we calculate a reasonable value using the
 * requested point size - assuming LINESPP lines fit on a page in point size
 * POINTSIZE.
 *
 */

    writerequest(0, stdout);		/* global requests eg. manual feed */
    fprintf(stdout, "setup\n");

    if ( formsperpage > 1 )  {
	if ( cat(formfile) == FALSE )
	    error(FATAL, "can't read %s", formfile);
	fprintf(stdout, "%d setupforms\n", formsperpage);
    }	/* End if */

    fprintf(stdout, "%s", ENDSETUP);

    if ( linespp <= 0 )
	linespp = LINESPP * POINTSIZE / pointsize;

}   /* End of setup */


/*****************************************************************************/


static void
arguments(void)
{

/*
 *
 * Makes sure all the non-option command line arguments are processed. If we get
 * here and there aren't any arguments left, or if '-' is one of the input files
 * we'll translate stdin.
 *
 */

    if ( argc < 1 )
	text();
    else {				/* at least one argument is left */
	while ( argc > 0 )  {
	    if ( strcmp(*argv, "-") == 0 )
		fp_in = stdin;
	    else if ( (fp_in = fopen(*argv, "r")) == NULL )
		error(FATAL, "can't open %s", *argv);
	    text();
	    if ( fp_in != stdin )
		fclose(fp_in);
	    argc--;
	    argv++;
	}   /* End while */
    }   /* End else */

}   /* End of arguments */


/*****************************************************************************/


static void
done(void)
{

/*
 *
 * Finished with all the input files, so mark the end of the pages with a TRAILER
 * comment, make sure the last page prints, and add things like the PAGES comment
 * that can only be determined after all the input files have been read.
 *
 */
    if (printed % formsperpage != 0) {	/* pad to ENDPAGE */
	while (printed % formsperpage) {
	    printed++;

	    fprintf(stdout, "save\n");
	    fprintf(stdout, "mark\n");
	    writerequest(printed, stdout);
	    fprintf(stdout, "%d pagesetup\n", printed);

	    fprintf(stdout, "cleartomark\n");
	    fprintf(stdout, "showpage\n");
	    fprintf(stdout, "restore\n");
	}
	fprintf(stdout, "%s %d %d\n", ENDPAGE, page, printed);
    }

    fprintf(stdout, "%s", TRAILER);
    fprintf(stdout, "done\n");
    fprintf(stdout, "%s %s\n", DOCUMENTFONTS, fontname);
    fprintf(stdout, "%s %d\n", PAGES, printed);

}   /* End of done */


/*****************************************************************************/


static void
account(void)
{

/*
 *
 * Writes an accounting record to *fp_acct provided it's not NULL. Accounting is
 * requested using the -A or -J options.
 *
 */

    if ( fp_acct != NULL )
	fprintf(fp_acct, " print %d\n copies %d\n", printed, copies);

}   /* End of account */


/*****************************************************************************/


static void
text(void)
{
    int		ch;			/* next input character */

/*
 *
 * Translates *fp_in into PostScript. All we do here is handle newlines, tabs,
 * backspaces, and quoting of special characters. All other unprintable characters
 * are totally ignored. The redirect(-1) call forces the initial output to go to
 * /dev/null. It's done to force the stuff that formfeed() does at the end of
 * each page to /dev/null rather than the real output file.
 *
 */


    redirect(-1);			/* get ready for the first page */
    formfeed();				/* force PAGE comment etc. */

    while ( (ch = getc(fp_in)) != EOF )

	switch ( ch )  {

	    case '\n':
		    newline();
		    break;

	    case '\t':
	    case '\b':
	    case ' ':
		    spaces(ch);
		    break;

	    case '\014':
		    formfeed();
		    break;

	    case '\r':
		    if ( crmode == 1 )
			spaces(ch);
		    else if ( crmode == 2 )
			newline();
		    break;

	    case '(':
	    case ')':
	    case '\\':
		    startline();
		    putc('\\', fp_out);

/*
 *
 * Fall through to the default case.
 *
 */

	    default:
		    if ( isascii(ch) && isprint(ch) )
			oput(ch);
		    else {
#define isintlprint(ch)	((ch)&0x80)
#define isss(ch)	0
			if (isintlprint(ch) || isss(ch)) {
				startline();
				fprintf(fp_out, "\\%03o", 0xFF&ch);
				col++;
			}
		    }
		    break;

	}   /* End switch */

    formfeed();				/* next file starts on a new page? */

}   /* End of text */


/*****************************************************************************/


static void
formfeed(void)
{

/*
 *
 * Called whenever we've finished with the last page and want to get ready for the
 * next one. Also used at the beginning and end of each input file, so we have to
 * be careful about what's done. The first time through (up to the redirect() call)
 * output goes to /dev/null.
 *
 * Adobe now recommends that the showpage operator occur after the page level
 * restore so it can be easily redefined to have side-effects in the printer's VM.
 * Although it seems reasonable I haven't implemented it, because it makes other
 * things, like selectively setting manual feed or choosing an alternate paper
 * tray, clumsy - at least on a per page basis.
 *
 */


    if ( fp_out == stdout )		/* count the last page */
	printed++;

    endline();				/* print the last line */

    fprintf(fp_out, "cleartomark\n");
    fprintf(fp_out, "showpage\n");
    fprintf(fp_out, "restore\n");
    if (printed % formsperpage == 0)
	fprintf(fp_out, "%s %d %d\n", ENDPAGE, page, printed);

    if ( ungetc(getc(fp_in), fp_in) == EOF )
	redirect(-1);
    else redirect(++page);

    if (printed % formsperpage == 0)
	fprintf(fp_out, "%s %d %d\n", PAGE, page, printed+1);
    fprintf(fp_out, "save\n");
    fprintf(fp_out, "mark\n");
    writerequest(printed+1, fp_out);
    fprintf(fp_out, "%d pagesetup\n", printed+1);

    line = 1;

}   /* End of formfeed */


/*****************************************************************************/


static void
newline(void)
{

/*
 *
 * Called when we've read a newline character. The call to startline() ensures
 * that at least an empty string is on the stack.
 *
 */

    startline();
    endline();				/* print the current line */

    if ( ++line > linespp )		/* done with this page */
	formfeed();

}   /* End of newline */


/*****************************************************************************/


static void
spaces(int ch)
    /* next input character */
{
    int		endcol;			/* ending column */
    int		i;			/* final distance - in spaces */

/*
 *
 * Counts consecutive spaces, tabs, and backspaces and figures out where the next
 * string should start. Once that's been done we try to choose an efficient way
 * to output the required number of spaces. The choice is between using procedure
 * l with a single string on the stack and L with several string and column pairs.
 * We usually break even, in terms of the size of the output file, if we need four
 * consecutive spaces. More means using L decreases the size of the file. For now
 * if there are less than 6 consecutive spaces we just add them to the current
 * string, otherwise we end that string, follow it by its starting position, and
 * begin a new one that starts at endcol. Backspacing is always handled this way.
 *
 */


    startline();			/* so col makes sense */
    endcol = col;

    do {
	if ( ch == ' ' )
	    endcol++;
	else if ( ch == '\t' )
	    endcol += tabstops - ((endcol - 1) % tabstops);
	else if ( ch == '\b' )
	    endcol--;
	else if ( ch == '\r' )
	    endcol = 1;
	else break;
    } while ( ch = getc(fp_in) );	/* if ch is 0 we'd quit anyway */

    ungetc(ch, fp_in);			/* wasn't a space, tab, or backspace */

    if ( endcol < 1 )			/* can't move past left edge */
	endcol = 1;

    if ( (i = endcol - col) >= 0 && i < 6 )
	for ( ; i > 0; i-- )
	    oput((int)' ');
    else {
	fprintf(fp_out, ")%d(", stringstart-1);
	stringcount++;
	col = stringstart = endcol;
    }	/* End else */

}   /* End of spaces */


/*****************************************************************************/


static void
startline(void)
{

/*
 *
 * Called whenever we want to be certain we're ready to start pushing characters
 * into an open string on the stack. If stringcount is positive we've already
 * started, so there's nothing to do. The first string starts in column 1.
 *
 */


    if ( stringcount < 1 )  {
	putc('(', fp_out);
	stringstart = col = 1;
	stringcount = 1;
    }	/* End if */

}   /* End of startline */


/*****************************************************************************/


static void
endline(void)
{


/*
 *
 * Generates a call to the PostScript procedure that processes all the text on
 * the stack - provided stringcount is positive. If one string is on the stack
 * the fast procedure (ie. l) is used to print the line, otherwise the slower
 * one that processes string and column pairs is used.
 *
 */


    if ( stringcount == 1 )
	fprintf(fp_out, ")l\n");
    else if ( stringcount > 1 )
	fprintf(fp_out, ")%d L\n", stringstart-1);

    stringcount = 0;

}   /* End of endline */


/*****************************************************************************/


static void
oput(int ch)
    /* next output character */
{

/*
 *
 * Responsible for adding all printing characters from the input file to the
 * open string on top of the stack. The only other characters that end up in
 * that string are the quotes required for special characters. Some simple
 * changes here and in spaces could make line wrapping possible. Doing a good
 * job would probably force lots of printer dependent stuff into the program,
 * so I haven't bothered with it. Could also change the prologue, or perhaps
 * write a different one, that uses kshow instead of show to display strings.
 *
 */


    startline();
    putc(ch, fp_out);
    col++;

}   /* End of oput */


/*****************************************************************************/


static void
redirect(int pg)
    /* next page we're printing */
{
    static FILE	*fp_null = NULL;	/* if output is turned off */

/*
 *
 * If we're not supposed to print page pg, fp_out will be directed to /dev/null,
 * otherwise output goes to stdout.
 *
 */


    if ( pg >= 0 && in_olist(pg) == ON )
	fp_out = stdout;
    else if ( (fp_out = fp_null) == NULL )
	fp_out = fp_null = fopen("/dev/null", "w");

}   /* End of redirect */


/*****************************************************************************/


