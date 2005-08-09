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
 * postplot - PostScript translator for Unix (System V) plot files.
 *
 * Only support (currently) is for the System V version of plot. Ninth Edition
 * plot is completely different and probably will need a separate translator.
 * If character placement appears to be off a bit try changing the definitions
 * of xtextshift and ytextshift in the prologue. Didn't spend much time trying
 * to speed things up - there's undoubtedly much that could still be done.
 *
 * The program expects that the following PostScript procedures are defined in
 * the prologue:
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
 *	    Does whatever is needed to set things up for the next page. Expect
 *	    to find the current page number on the stack.
 *
 *	space
 *
 *	  height width space -
 *
 *	    Defines the height and width of the image space. Called outside page
 *	    level save/restore so the definitions are permanent. Typically called
 *	    once at the beginning of each job.
 *
 *	setupspace
 *
 *	  setupspace
 *
 *	    Finishes setting up the page coordinate system using the height and
 *	    width definitions made by space (above). Usually called at the start
 *	    of each page.
 *
 *	l
 *
 *	  x0 y0 x1 y1 l -
 *
 *	    Draws a line from (x0, y0) to (x1, y1).
 *
 *	n
 *
 *	  x y n -
 *
 *	    Adds the line segment from (hpos, vpos) to (x, y) to the current
 *	    path.
 *
 *	p
 *
 *	  x y p -
 *
 *	    Marks point (x, y) with a filled circle whose radius varies with
 *	    the linewidth.
 *
 *	c
 *
 *	  x y r c -
 *
 *	    Draws a circle of radius r centered at (x, y).
 *
 *	a
 *
 *	  x y dx1 dy1 dx2 dy2 a -
 *
 *	    Draws a counterclockwise arc centered at (x, y) through (x+dx1, y+dy1)
 *	    to (x+dx2, y+dy2).
 *
 *	t
 *
 *	  s x y t -
 *
 *	    Prints string s starting at (x, y). xtextshift and ytextshift provide
 *	    additional control over the placement of text strings.
 *
 *	f
 *
 *	  array f -
 *
 *	    Selects the line style (e.g. dotted) according to the pattern in array.
 *
 *	m
 *
 *	  x y m
 *
 *	    Starts a new path that begins at (x, y) - only used with connected
 *	    lines.
 *
 *	s
 *
 *	  s
 *
 *	    Strokes the current path - again only used with connected lines.
 *
 *	done
 *
 *	  done
 *
 *	    Makes sure the last page is printed. Only needed when we're printing
 *	    more than one page on each sheet of paper.
 *
 * The default line width is zero, which forces lines to be one pixel wide. That
 * works well on 'write to black' engines but won't be right for 'write to white'
 * engines. The line width can be changed using the -w option, or you can change
 * the initialization of linewidth in the prologue.
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
#include "postplot.h"			/* a few special definitions */

char	*optnames = "a:c:f:m:n:o:p:s:w:x:y:A:C:J:L:P:R:DI";

char	*prologue = POSTPLOT;		/* default PostScript prologue */
char	*formfile = FORMFILE;		/* stuff for multiple pages per sheet */

int	formsperpage = 1;		/* page images on each piece of paper */
int	copies = 1;			/* and this many copies of each sheet */

int	hpos;				/* current horizontal */
int	vpos;				/* and vertical position */

Styles	styles[] = STYLES;		/* recognized line styles */
int	linestyle = 0;			/* index into styles[] */

Fontmap	fontmap[] = FONTMAP;		/* for translating font names */
char	*fontname = "Courier";		/* use this PostScript font */

int	page = 0;			/* page we're working on */
int	printed = 0;			/* printed this many pages */

FILE	*fp_in = stdin;			/* read from this file */
FILE	*fp_out = stdout;		/* and write stuff here */
FILE	*fp_acct = NULL;		/* for accounting data */

static void account(void);
static void arguments(void);
static void connect(void);
static void done(void);
static void formfeed(void);
static char *get_font(char *);
static int getint(void);
static void getstring(char *);
static void header(void);
static void init_signals(void);
static void options(void);
static void plot(void);
static void redirect(int);
static void setstyle(char *);
static void setup(void);

/*****************************************************************************/

int
main(int agc, char *agv[])
{

/*
 *
 * Plot to PostScript translator for System V only.
 *
 */

    argc = agc;				/* other routines may want them */
    argv = agv;

    prog_name = argv[0];		/* really just for error messages */

    init_signals();			/* sets up interrupt handling */
    header();				/* PostScript header and prologue */
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

/*
 *
 * Reads and processes the command line options. Added the -P option so arbitrary
 * PostScript code can be passed through. Expect it could be useful for changing
 * definitions in the prologue for which options have not been defined.
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

	    case 's':			/* point size */
		    fprintf(stdout, "/size %s def\n", optarg);
		    break;

	    case 'w':			/* line width */
		    fprintf(stdout, "/linewidth %s def\n", optarg);
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

static char *
get_font(char *name)
    /* name the user asked for */
{
    int		i;			/* for looking through fontmap[] */

/*
 *
 * Called from options() to map a user's font name into a legal PostScript name.
 * If the lookup fails *name is returned to the caller. That should let you choose
 * any PostScript font.
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
 * we'll translate stdin.
 *
 */

    if ( argc < 1 )
	plot();
    else {				/* at least one argument is left */
	while ( argc > 0 )  {
	    if ( strcmp(*argv, "-") == 0 )
		fp_in = stdin;
	    else if ( (fp_in = fopen(*argv, "r")) == NULL )
		error(FATAL, "can't open %s", *argv);
	    plot();
	    if ( fp_in != stdin )
		fclose(fp_in);
	    argc--;
	    argv++;
	}   /* End while */
    }   /* End else */

}   /* End of arguments */

/*****************************************************************************/

static void
plot(void)
{

    int		c;
    char	s[256];
    int		x0,y0,x1,y1;
    int		xc, yc, r;
    int		dx0, dy0, dx1, dy1;
    int		n, i, pat[256];

/*
 *
 * Parser - borrowed directly from tplot source.
 *
 */

    redirect(-1);
    formfeed();

    while((c=getc(fp_in)) != EOF) {
	switch(c) {
	    case 'm':
		hpos = getint();
		vpos = getint();
		break;

	    case 'l':
		x0 = getint();
		y0 = getint();
		x1 = getint();
		y1 = getint();
		fprintf(fp_out, "%d %d %d %d l\n", x1, y1, x0, y0);
		hpos = x1;
		vpos = y1;
		break;

	    case 't':
		getstring(s);
		if ( *s != '\0' )
		    fprintf(fp_out, "(%s) %d %d t\n", s, hpos, vpos);
		break;

	    case 'e':
		formfeed();
		break;

	    case 'p':
		hpos = getint();
		vpos = getint();
		fprintf(fp_out, "%d %d p\n", hpos, vpos);
		break;

	    case 'n':
		ungetc(c, fp_in);
		connect();
		break;

	    case 's':
		x0 = getint();
		y0 = getint();
		x1 = getint();
		y1 = getint();
		fprintf(fp_out, "cleartomark restore\n");
		fprintf(fp_out, "%d %d space\n", x1-x0, y1-y0);
		fprintf(fp_out, "save mark\n");
		fprintf(fp_out, "setupspace\n");
		fprintf(fp_out, "%s f\n", styles[linestyle].val);
		break;

	    case 'a':
		xc = getint();
		yc = getint();
		x0 = getint();
		y0 = getint();
		x1 = getint();
		y1 = getint();
		dx0 = x0 - xc;
		dy0 = y0 - yc;
		dx1 = x1 - xc;
		dy1 = y1 - yc;
		if ( (dx0 != 0 || dy0 != 0) && (dx1 != 0 || dy1 != 0) )
		    fprintf(fp_out, "%d %d %d %d %d %d a\n", xc, yc, dx0, dy0, dx1, dy1);
		break;

	    case 'c':
		xc = getint();
		yc = getint();
		r = getint();
		fprintf(fp_out, "%d %d %d c\n", xc, yc, r);
		break;

	    case 'f':
		getstring(s);
		setstyle(s);
		break;

	    case 'd':			/* undocumented and unimplemented */
		x0 = getint();
		y0 = getint();
		dx0 = getint();
		n = getint();
		for(i=0; i<n; i++)pat[i] = getint();
		/*dot(x0,y0,dx0,n,pat);*/
		break;

	    default:
		error(FATAL, "unknown command %o\n", c);

	}   /* End switch */

    }	/* End while */

    formfeed();

}   /* End of plot */

/*****************************************************************************/

static void
connect(void)
{

    int		c;
    int		x, y;
    int		count = 0;		/* so the path doesn't get to big */

/*
 *
 * Reads consecutive connect commands from the input file. Can't let the path
 * get too big, so it's occasionally stroked.
 *
 */

    fprintf(fp_out, "%d %d m\n", hpos, vpos);

    while ( (c = getc(fp_in)) == 'n' ) {
	if ( count++ > 100 ) {
	    fprintf(fp_out, "s\n%d %d m\n", hpos, vpos);
	    count = 1;
	}   /* End if */
	x = getint();
	y = getint();
	fprintf(fp_out, "%d %d n\n", x, y);
	hpos = x;
	vpos = y;
    }	/* End while */

    fprintf(fp_out, "s\n");
    ungetc(c, fp_in);

}   /* End of connect */

/*****************************************************************************/

static void
setstyle(char *str)
{
    int		i;

/*
 *
 * Selects the line style that matches *str. No match resets the style to solid
 * (unless you've changed STYLES in postplot.h).
 *
 */

    for ( i = 0; styles[i].name != NULL; i++ )
	if ( strcmp(styles[i].name, str) == 0 )
	    break;

    if ( styles[i].val != NULL ) {
	linestyle = i;
	fprintf(fp_out, "%s f\n", styles[linestyle].val);
    }	/* End if */

}   /* End of setstyle */

/*****************************************************************************/

static int
getint(void)
{
    short	a, b;

/*
 *
 * Returns the integer stored in the next two bytes.
 *
 */

    if((b = getc(fp_in)) == EOF)
	return(EOF);
    if((a = getc(fp_in)) == EOF)
	return(EOF);

    a = a<<8;
    return(a|b);

}   /* End of getint */

/*****************************************************************************/

static void
getstring(char *s)
{

    int c;

/*
 *
 * Reads characters, up to a newline, and stores the quoted string in s.
 *
 */

    for( ; (c = getc(fp_in)) != EOF; s++) {
	if ( c == '(' || c == ')' || c == '\\' )
	    *s++ = '\\';
	if( (*s = c) == '\n' )
	    break;
    }	/* End for */

    *s = '\0';

}   /* End of getstring */

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

    fprintf(fp_out, "cleartomark\n");
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
    fprintf(fp_out, "setupspace\n");
    fprintf(fp_out, "%s f\n", styles[linestyle].val);

}   /* End of formfeed */

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
