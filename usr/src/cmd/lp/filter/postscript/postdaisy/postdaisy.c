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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *
 * postdaisy - PostScript translator for Diablo 1640 files.
 *
 * A program that translates Diablo 1640 files into PostScript. Absolutely nothing
 * is guaranteed. Quite a few things haven't been implemented, and what's been
 * done isn't well tested. Most of the documentation used to write this program
 * was taken from the 'Diablo Emulator' section of a recent Imagen manual.
 *
 * Some of document comments that are generated may not be right. Most of the test
 * files I used produced a trailing blank page. I've put a check in formfeed() that
 * won't print the last page if it doesn't contain any text, but PAGES comments may
 * not be right. The DOCUMENTFONTS comment will also be wrong if auto underline or
 * bold printing have been turned on by escape commands.
 *
 * The brute force approach used to implement horizontal and vertical tabs leaves
 * much to be desired, and may not work for very small initial hmi and vmi values.
 * At the very least I should have used malloc() to get space for the two tabstop
 * arrays after hmi and vmi are known!
 *
 * Reverse printing mode hasn't been tested at all, but what's here should be
 * close even though it's not efficient.
 *
 * The PostScript prologue is copied from *prologue before any of the input files
 * are translated. The program expects that the following PostScript procedures
 * are defined in that file:
 *
 *	setup
 *
 *	  mark ... setup -
 *
 *	    Handles special initialization stuff that depends on how this program
 *	    was called. Expects to find a mark followed by key/value pairs on the
 *	    stack. The def operator is applied to each pair up to the mark, then
 *	    the default state is set up.
 *
 *	pagesetup
 *
 *	  page pagesetup -
 *
 *	    Does whatever is needed to set things up for the next page. Expects to
 *	    find the current page number on the stack.
 *
 *	t
 *
 *	  mark str1 x1 str2 x2 ... strn xn y hmi t mark
 *
 *	    Handles all the text on the stack. Characters in the strings are
 *	    printed using hmi as the character advance, and all strings are at
 *	    vertical position y. Each string is begins at the horizontal position
 *	    that preceeds it.
 *
 *	f
 *
 *	  font f -
 *
 *	    Use font f, where f is the full PostScript font name. Only used when
 *	    we switch to auto underline (Courier-Italic) or bold (Courier-Bold)
 *	    printing.
 *
 *	done
 *
 *	  done
 *
 *	    Makes sure the last page is printed. Only needed when we're printing
 *	    more than one page on each sheet of paper.
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

#include "comments.h"			/* PostScript file structuring comments */
#include "gen.h"			/* general purpose definitions */
#include "path.h"			/* for the prologue */
#include "ext.h"			/* external variable declarations */
#include "postdaisy.h"			/* a few special definitions */


char	*optnames = "a:c:f:h:l:m:n:o:p:r:s:v:x:y:A:C:J:L:P:DI";

char	*prologue = POSTDAISY;		/* default PostScript prologue */
char	*formfile = FORMFILE;		/* stuff for multiple pages per sheet */

int	formsperpage = 1;		/* page images on each piece of paper */
int	copies = 1;			/* and this many copies of each sheet */

char	htabstops[COLUMNS];		/* horizontal */
char	vtabstops[ROWS];		/* and vertical tabs */

int	res = RES;			/* input file resolution - sort of */

int	hmi = HMI;			/* horizontal motion index - 1/120 inch */
int	vmi = VMI;			/* vertical motion index - 1/48 inch */
int	ohmi = HMI;			/* original hmi */
int	ovmi = VMI;			/* and vmi - for tabs and char size */

int	hpos = 0;			/* current horizontal */
int	vpos = 0;			/* and vertical position */

int	lastx = -1;			/* printer's last horizontal */
int	lasty = -1;			/* and vertical position */
int	lasthmi = -1;			/* hmi for current text strings */

int	lastc = -1;			/* last printed character */
int	prevx = -1;			/* at this position */

int	leftmargin = LEFTMARGIN;	/* page margins */
int	rightmargin = RIGHTMARGIN;
int	topmargin = TOPMARGIN;
int	bottommargin = BOTTOMMARGIN;

int	stringcount = 0;		/* number of strings on the stack */
int	stringstart = 1;		/* column where current one starts */
int	advance = 1;			/* -1 if in backward print mode */

int	lfiscr = OFF;			/* line feed implies carriage return */
int	crislf = OFF;			/* carriage return implies line feed */

int	linespp = 0;			/* lines per page if it's positive */
int	markedpage = FALSE;		/* helps prevent trailing blank page */
int	page = 0;			/* page we're working on */
int	printed = 0;			/* printed this many pages */

Fontmap	fontmap[] = FONTMAP;		/* for translating font names */
char	*fontname = "Courier";		/* use this PostScript font */
int	shadowprint = OFF;		/* automatic bold printing if ON */

FILE	*fp_in;				/* read from this file */
FILE	*fp_out = stdout;		/* and write stuff here */
FILE	*fp_acct = NULL;		/* for accounting data */

static void account(void);
static void arguments(void);
static void backspace(void);
static void carriage(void);
static void changefont(char *);
static void cleartabs(void);
static void endline(void);
static void endstring(void);
static void escape(void);
static void done(void);
static void formfeed(void);
static void header(void);
static void hgoto(int);
static void hmot(int);
static void htab(void);
static void inittabs(void);
static void init_signals(void);
static void linefeed(void);
static void options(void);
static void oput(int);
static void redirect(int);
static void setup(void);
static void startline(void);
static void text(void);
static void vgoto(int);
static void vmot(int);
static void vtab(void);

/*****************************************************************************/

int
main(int agc, char *agv[])
{

/*
 *
 * A simple program that translates Diablo 1640 files into PostScript. Nothing is
 * guaranteed - the program not well tested and doesn't implement everything.
 *
 */


    argc = agc;				/* other routines may want them */
    argv = agv;

    prog_name = argv[0];		/* really just for error messages */

    init_signals();			/* sets up interrupt handling */
    header();				/* PostScript header comments */
    options();				/* handle the command line options */
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
    fprintf(stdout, "%s %s\n", VERSION, PROGRAMVERSION);
    fprintf(stdout, "%s %s\n", DOCUMENTFONTS, ATEND);
    fprintf(stdout, "%s %s\n", PAGES, ATEND);
    fprintf(stdout, "%s", ENDCOMMENTS);

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
    int		n;			/* for CR and LF modes */

/*
 *
 * Reads and processes the command line options. Added the -P option so arbitrary
 * PostScript code can be passed through. Expect it could be useful for changing
 * definitions in the prologue for which options have not been defined.
 *
 * Although any PostScript font can be used, things will only work for constant
 * width fonts.
 *
 */


    while ( (ch = getopt(argc, argv, optnames)) != EOF )  {

	switch ( ch )  {

	    case 'a':			/* aspect ratio */
		    fprintf(stdout, "/aspectratio %s def\n", optarg);
		    break;

	    case 'c':			/* copies */
		    copies = atoi(optarg);
		    fprintf(stdout, "/#copies %s store\n", optarg);
		    break;

	    case 'f':			/* use this PostScript font */
		    fontname = get_font(optarg);
		    fprintf(stdout, "/font /%s def\n", fontname);
		    break;

	    case 'h':			/* default character spacing */
		    ohmi = hmi = atoi(optarg) * HSCALE;
		    fprintf(stdout, "/hmi %s def\n", optarg);
		    break;

	    case 'l':			/* lines per page */
		    linespp = atoi(optarg);
		    break;

	    case 'm':			/* magnification */
		    fprintf(stdout, "/magnification %s def\n", optarg);
		    break;

	    case 'n':			/* forms per page */
		    formsperpage = atoi(optarg);
		    fprintf(stdout, "%s %s\n", FORMSPERPAGE, optarg);
		    fprintf(stdout, "/formsperpage %s def\n", optarg);
		    break;

	    case 'o':			/* output page list */
		    out_list(optarg);
		    break;

	    case 'p':			/* landscape or portrait mode */
		    if ( *optarg == 'l' )
			fprintf(stdout, "/landscape true def\n");
		    else fprintf(stdout, "/landscape false def\n");
		    break;

	    case 'r':			/* set CR and LF modes */
		    n = atoi(optarg);
		    if ( n & 01 )
			lfiscr = ON;
		    else lfiscr = OFF;
		    if ( n & 02 )
			crislf = ON;
		    else crislf = OFF;
		    break;

	    case 's':			/* point size */
		    fprintf(stdout, "/pointsize %s def\n", optarg);
		    break;

	    case 'v':			/* default line spacing */
		    ovmi = vmi = atoi(optarg) * VSCALE;
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

    argc -= optind;			/* get ready for non-option args */
    argv += optind;

}   /* End of options */


/*****************************************************************************/


char *
get_font(char *name)
    /* name the user asked for */
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
 * input files are processed.
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

}   /* End of setup */


/*****************************************************************************/

static void
arguments(void)
{

/*
 *
 * Makes sure all the non-option command line arguments are processed. If we get
 * here and there aren't any arguments left, or if '-' is one of the input files
 * we'll process stdin.
 *
 */


    fp_in = stdin;

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
 * Finished with all the input files, so mark the end of the pages, make sure the
 * last page is printed, and restore the initial environment.
 *
 */


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
 * Writes an accounting record to *fp_acct provided it's not NULL. Accounting
 * is requested using the -A or -J options.
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
 * Translates the next input file into PostScript. The redirect(-1) call forces
 * the initial output to go to /dev/null - so the stuff formfeed() does at the
 * end of each page doesn't go to stdout.
 *
 */


    redirect(-1);			/* get ready for the first page */
    formfeed();				/* force PAGE comment etc. */
    inittabs();

    while ( (ch = getc(fp_in)) != EOF )

	switch ( ch )  {

	    case '\010':		/* backspace */
		    backspace();
		    break;

	    case '\011':		/* horizontal tab */
		    htab();
		    break;

	    case '\012':		/* new line */
		    linefeed();
		    break;

	    case '\013':		/* vertical tab */
		    vtab();
		    break;

	    case '\014':		/* form feed */
		    formfeed();
		    break;

	    case '\015':		/* carriage return */
		    carriage();
		    break;

	    case '\016':		/* extended character set - SO */
		    break;

	    case '\017':		/* extended character set - SI */
		    break;

	    case '\031':		/* next char from supplementary set */
		    break;

	    case '\033':		/* 2 or 3 byte escape sequence */
		    escape();
		    break;

	    default:
		    if ( isascii(ch) && isprint(ch) )
			oput(ch);
		    break;

	}   /* End switch */

    formfeed();				/* next file starts on a new page? */

}   /* End of text */


/*****************************************************************************/

static void
inittabs(void)
{
    int		i;			/* loop index */

/*
 *
 * Initializes the horizontal and vertical tab arrays. The way tabs are handled is
 * quite inefficient and may not work for all initial hmi or vmi values.
 *
 */


    for ( i = 0; i < ROWS; i++ )
	htabstops[i] = ((i % 8) == 0) ? ON : OFF;

    for ( i = 0; i < COLUMNS; i++ )
	vtabstops[i] = ((i * ovmi) > BOTTOMMARGIN) ? ON : OFF;

}   /* End of inittabs */


/*****************************************************************************/

static void
cleartabs(void)
{
    int		i;			/* loop index */

/*
 *
 * Clears all horizontal and vertical tab stops.
 *
 */


    for ( i = 0; i < ROWS; i++ )
	htabstops[i] = OFF;

    for ( i = 0; i < COLUMNS; i++ )
	vtabstops[i] = OFF;

}   /* End of cleartabs */


/*****************************************************************************/

static void
formfeed(void)
{

/*
 *
 * Called whenever we've finished with the last page and want to get ready for the
 * next one. Also used at the beginning and end of each input file, so we have to
 * be careful about what's done. I've added a simple test before the showpage that
 * should eliminate the extra blank page that was put out at the end of many jobs,
 * but the PAGES comments may be wrong.
 *
 */


    if ( fp_out == stdout )		/* count the last page */
	printed++;

    endline();				/* print the last line */

    fprintf(fp_out, "cleartomark\n");
    if ( feof(fp_in) == 0 || markedpage == TRUE )
	fprintf(fp_out, "showpage\n");
    fprintf(fp_out, "restore\n");
    fprintf(fp_out, "%s %d %d\n", ENDPAGE, page, printed);

    if ( ungetc(getc(fp_in), fp_in) == EOF )
	redirect(-1);
    else redirect(++page);

    fprintf(fp_out, "%s %d %d\n", PAGE, page, printed+1);
    fprintf(fp_out, "save\n");
    fprintf(fp_out, "mark\n");
    writerequest(printed+1, fp_out);
    fprintf(fp_out, "%d pagesetup\n", printed+1);

    vgoto(topmargin);
    hgoto(leftmargin);

    markedpage = FALSE;

}   /* End of formfeed */


/*****************************************************************************/

static void
linefeed(void)
{
    int		line = 0;		/* current line - based on ovmi */

/*
 *
 * Adjust our current vertical position. If we've passed the bottom of the page
 * or exceeded the number of lines per page, print it and go to the upper left
 * corner of the next page. This routine is also called from carriage() if crislf
 * is ON.
 *
 */


    vmot(vmi);

    if ( lfiscr == ON )
	hgoto(leftmargin);

    if ( linespp > 0 )			/* it means something so see where we are */
	line = vpos / ovmi + 1;

    if ( vpos > bottommargin || line > linespp )
	formfeed();

}   /* End of linefeed */


/*****************************************************************************/

static void
carriage(void)
{

/*
 *
 * Handles carriage return character. If crislf is ON we'll generate a line feed
 * every time we get a carriage return character.
 *
 */


    if ( shadowprint == ON )		/* back to normal mode */
	changefont(fontname);

    advance = 1;
    shadowprint = OFF;

    hgoto(leftmargin);

    if ( crislf == ON )
	linefeed();

}   /* End of carriage */


/*****************************************************************************/

static void
htab(void)
{
    int		col;			/* 'column' we'll be at next */
    int		i;			/* loop index */

/*
 *
 * Tries to figure out where the next tab stop is. Wasn't positive about this
 * one, since hmi can change. I'll assume columns are determined by the original
 * value of hmi. That fixes them on the page, which seems to make more sense than
 * letting them float all over the place.
 *
 */


    endline();

    col = hpos/ohmi + 1;
    for ( i = col; i < ROWS; i++ )
	if ( htabstops[i] == ON )  {
	    col = i;
	    break;
	}   /* End if */

    hgoto(col * ohmi);
    lastx = hpos;

}   /* End of htab */


/*****************************************************************************/

static void
vtab(void)
{


    int		line;			/* line we'll be at next */
    int		i;			/* loop index */


/*
 *
 * Looks for the next vertical tab stop in the vtabstops[] array and moves to that
 * line. If we don't find a tab we'll just move down one line - shouldn't happen.
 *
 */


    endline();

    line = vpos/ovmi + 1;
    for ( i = line; i < COLUMNS; i++ )
	if ( vtabstops[i] == ON )  {
	    line = i;
	    break;
	}   /* End if */

    vgoto(line * ovmi);

}   /* End of vtab */


/*****************************************************************************/

static void
backspace(void)
{

/*
 *
 * Moves backwards a distance equal to the current value of hmi provided we don't
 * go past the left margin.
 *
 */


    endline();

    if ( hpos - leftmargin >= hmi )
	hmot(-hmi);
    else hgoto(leftmargin);		/* maybe just ignore the backspace?? */

    lastx = hpos;

}   /* End of backspace */


/*****************************************************************************/

static void
escape(void)
{
    int		ch;			/* control character */

/*
 *
 * Handles special codes that are expected to follow an escape character. The
 * initial escape character is followed by one or two bytes.
 *
 */


    switch ( ch = getc(fp_in) )  {

	case 'T':			/* top margin */
		topmargin = vpos;
		break;

	case 'L':			/* bottom margin */
		bottommargin = vpos;
		break;

	case 'C':			/* clear top and bottom margins */
		bottommargin = BOTTOMMARGIN;
		topmargin = TOPMARGIN;
		break;

	case '9':			/* left margin */
		leftmargin = hpos;
		break;

	case '0':			/* right margin */
		rightmargin = hpos;
		break;

	case '1':			/* set horizontal tab */
		htabstops[hpos/ohmi] = ON;
		break;

	case '8':			/* clear horizontal tab at hpos */
		htabstops[hpos/ohmi] = OFF;
		break;

	case '-':			/* set vertical tab */
		vtabstops[vpos/ovmi] = ON;
		break;

	case '2':			/* clear all tabs */
		cleartabs();
		break;

	case '\014':			/* set lines per page */
		linespp = getc(fp_in);
		break;

	case '\037':			/* set hmi to next byte minus 1 */
		hmi = HSCALE * (getc(fp_in) - 1);
		break;

	case 'S':			/* reset hmi to default */
		hmi = ohmi;
		break;

	case '\011':			/* move to column given by next byte */
		hgoto((getc(fp_in)-1) * ohmi);
		break;

	case '?':			/* do carriage return after line feed */
		lfiscr = ON;
		break;

	case '!':			/* don't generate carriage return */
		lfiscr = OFF;
		break;

	case '5':			/* forward print mode */
		advance = 1;
		break;

	case '6':			/* backward print mode */
		advance = -1;
		break;

	case '\036':			/* set vmi to next byte minus 1 */
		vmi = VSCALE * (getc(fp_in) - 1);
		break;

	case '\013':			/* move to line given by next byte */
		vgoto((getc(fp_in)-1) * ovmi);
		break;

	case 'U':			/* positive half line feed */
		vmot(vmi/2);
		break;

	case 'D':			/* negative half line feed */
		vmot(-vmi/2);
		break;

	case '\012':			/* negative line feed */
		vmot(-vmi);
		break;

	case '\015':			/* clear all margins */
		bottommargin = BOTTOMMARGIN;
		topmargin = TOPMARGIN;
		leftmargin = BOTTOMMARGIN;
		rightmargin = RIGHTMARGIN;
		break;

	case 'E':			/* auto underscore - use italic font */
		changefont("/Courier-Oblique");
		break;

	case 'R':			/* disable auto underscore */
		changefont(fontname);
		break;

	case 'O':			/* bold/shadow printing */
	case 'W':
		changefont("/Courier-Bold");
		shadowprint = ON;
		break;

	case '&':			/* disable bold printing */
		changefont(fontname);
		shadowprint = OFF;
		break;

	case '/':			/* ignored 2 byte escapes */
	case '\\':
	case '<':
	case '>':
	case '%':
	case '=':
	case '.':
	case '4':
	case 'A':
	case 'B':
	case 'M':
	case 'N':
	case 'P':
	case 'Q':
	case 'X':
	case '\010':
		break;

	case ',':			/* ignored 3 byte escapes */
	case '\016':
	case '\021':
		getc(fp_in);
		break;

	case '3':			/* graphics mode - should quit! */
	case '7':
	case 'G':
	case 'V':
	case 'Y':
	case 'Z':
		error(FATAL, "graphics mode is not implemented");
		break;

	default:
		error(FATAL, "missing case for escape o%o\n", ch);
		break;

    }	/* End switch */

}   /* End of escape */


/*****************************************************************************/

static void
vmot(int n)
    /* move this far vertically */
{

/*
 *
 * Move vertically n units from where we are.
 *
 */


    vpos += n;

}   /* End of vmot */


/*****************************************************************************/

static void
vgoto(int n)
    /* new vertical position */
{

/*
 *
 * Moves to absolute vertical position n.
 *
 */


    vpos = n;

}   /* End of vgoto */


/*****************************************************************************/

static void
hmot(int n)
    /* move this horizontally */
{

/*
 *
 * Moves horizontally n units from our current position.
 *
 */


    hpos += n * advance;

    if ( hpos < leftmargin )
	hpos = leftmargin;

}   /* End of hmot */


/*****************************************************************************/

static void
hgoto(int n)
    /* go to this horizontal position */
{

/*
 *
 * Moves to absolute horizontal position n.
 *
 */


    hpos = n;

}   /* End of hgoto */


/*****************************************************************************/

static void
changefont(char *name)
{

/*
 *
 * Changes the current font. Used to get in and out of auto underscore and bold
 * printing.
 *
 */


    endline();
    fprintf(fp_out, "%s f\n", name);

}   /* End of changefont */


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
	stringstart = lastx = hpos;
	lasty = vpos;
	lasthmi = hmi;
	lastc = -1;
	prevx = -1;
	stringcount = 1;
    }	/* End if */

}   /* End of startline */


/*****************************************************************************/

static void
endline(void)
{

/*
 *
 * Generates a call to the PostScript procedure that processes the text on the
 * the stack - provided stringcount is positive.
 *
 */


    if ( stringcount > 0 )
	fprintf(fp_out, ")%d %d %d t\n", stringstart, lasty, lasthmi);

    stringcount = 0;

}   /* End of endline */


/*****************************************************************************/

static void
endstring(void)
{

/*
 *
 * Takes the string we've been working on and adds it to the output file. Called
 * when we need to adjust our horizontal position before starting a new string.
 * Also called from endline() when we're done with the current line.
 *
 */


    if ( stringcount > 0 )  {
	fprintf(fp_out, ")%d(", stringstart);
	lastx = stringstart = hpos;
	stringcount++;
    }	/* End if */

}   /* End of endstring */


/*****************************************************************************/

static void
oput(int ch)
    /* next output character */
{

/*
 *
 * Responsible for adding all printing characters from the input file to the
 * open string on top of the stack. The only other characters that end up in
 * that string are the quotes required for special characters. Reverse printing
 * mode hasn't been tested but it should be close. hpos and lastx should disagree
 * each time (except after startline() does something), and that should force a
 * call to endstring() for every character.
 *
 */


    if ( stringcount > 100 )		/* don't put too much on the stack */
	endline();

    if ( vpos != lasty )
	endline();

    if ( advance == -1 )		/* for reverse printing - move first */
	hmot(hmi);

    startline();

    if ( lastc != ch || hpos != prevx )  {
	if ( lastx != hpos )
	    endstring();

	if ( ch == '\\' || ch == '(' || ch == ')' )
	    putc('\\', fp_out);
	putc(ch, fp_out);

	lastc = ch;
	prevx = hpos;
	lastx += lasthmi;
    }	/* End if */

    if ( advance != -1 )
	hmot(hmi);

    markedpage = TRUE;

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

