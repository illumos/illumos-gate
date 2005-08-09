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
 * posttek - PostScript translator for tektronix 4014 files
 *
 * A program that can be used to translate tektronix 4014 files into PostScript.
 * Most of the code was borrowed from the tektronix 4014 emulator that was written
 * for DMDs. Things have been cleaned up some, but there's still plently that
 * could be done.
 *
 * The PostScript prologue is copied from *prologue before any of the input files
 * are translated. The program expects that the following PostScript procedures
 * are defined in that file:
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
 *	v
 *
 *	  mark dx1 dy1 ... dxn dyn x y v mark
 *
 *	    Draws the vector described by the numbers on the stack. The top two
 *	    numbers are the starting point. The rest are relative displacements
 *	    from the preceeding point. Must make sure we don't put too much on
 *	    the stack!
 *
 *	t
 *
 *	  x y string t -
 *
 *	    Prints the string that's on the top of the stack starting at point
 *	    (x, y).
 *
 *	p
 *
 *	  x y p -
 *
 *	    Marks the point (x, y) with a circle whose radius varies with the
 *	    current intensity setting.
 *
 *	i
 *
 *	  percent focus i -
 *
 *	    Changes the size of the circle used to mark individual points to
 *	    percent of maximum for focused mode (focus=1) or defocused mode
 *	    (focus=0). The implementation leaves much to be desired!
 *
 *	l
 *
 *	  mark array l mark
 *
 *	    Set the line drawing mode according to the description given in array.
 *	    The arrays that describe the different line styles are declared in
 *	    STYLES (file posttek.h). The array really belongs in the prologue!
 *
 *	w
 *
 *	  n w -
 *
 *	    Adjusts the line width for vector drawing. Used to select normal (n=0)
 *	    or defocused (n=1) mode.
 *
 *	f
 *
 *	  size f -
 *
 *	    Changes the size of the font that's used to print characters in alpha
 *	    mode. size is the tektronix character width and is used to choose an
 *	    appropriate point size in the current font.
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
#include <fcntl.h> 

#include "comments.h"			/* PostScript file structuring comments */
#include "gen.h"			/* general purpose definitions */
#include "path.h"			/* for the prologue */
#include "ext.h"			/* external variable definitions */
#include "posttek.h"			/* control codes and other definitions */


char	*optnames = "a:c:f:m:n:o:p:w:x:y:A:C:J:L:P:R:DI";

char	*prologue = POSTTEK;		/* default PostScript prologue */
char	*formfile = FORMFILE;		/* stuff for multiple pages per sheet */

int	formsperpage = 1;		/* page images on each piece of paper */
int	copies = 1;			/* and this many copies of each sheet */

int	charheight[] = CHARHEIGHT;	/* height */
int	charwidth[] = CHARWIDTH;	/* and width arrays for tek characters */
int	tekfont = TEKFONT;		/* index into charheight[] and charwidth[] */

char	intensity[] = INTENSITY;	/* special point intensity array */
char	*styles[] = STYLES;		/* description of line styles */
int	linestyle = 0;			/* index into styles[] */
int	linetype = 0;			/* 0 for normal, 1 for defocused */

int	dispmode = ALPHA;		/* current tektronix state */
int	points = 0;			/* points making up the current vector */
int	characters = 0;			/* characters waiting to be printed */
int	pen = UP;			/* just for point plotting */
int	margin = 0;			/* left edge - ALPHA state */

Point	cursor;				/* should be current cursor position */

Fontmap	fontmap[] = FONTMAP;		/* for translating font names */
char	*fontname = "Courier";		/* use this PostScript font */

int	page = 0;			/* page we're working on */
int	printed = 0;			/* printed this many pages */

FILE	*fp_in;				/* read from this file */
FILE	*fp_out = stdout;		/* and write stuff here */
FILE	*fp_acct = NULL;		/* for accounting data */

static void account(void);
static void alpha(void);
static void arguments(void);
static int control(int);
static int esc(void);
static void done(void);
static void draw(void);
static void formfeed(void);
static void gin(void);
static void graph(void);
static void header(void);
static void home(void);
static void incremental(void);
static void init_signals(void);
static void move(int, int);
static int nextchar(void);
static void options(void);
static void point(void);
static void redirect(int);
static void reset(void);
static void setfont(int);
static void setmode(int);
static void setup(void);
static void statemachine(FILE *);
static void text(void);


/*****************************************************************************/


int
main(int agc, char *agv[])
{

/*
 *
 * A simple program that can be used to translate tektronix 4014 files into
 * PostScript. Most of the code was taken from the DMD tektronix 4014 emulator,
 * although things have been cleaned up some.
 *
 */

    argv = agv;				/* so everyone can use them */
    argc = agc;

    prog_name = argv[0];		/* just for error messages */

    init_signals();			/* sets up interrupt handling */
    header();				/* PostScript header comments */
    options();				/* handle the command line options */
    setup();				/* for PostScript */
    arguments();			/* followed by each input file */
    done();				/* print the last page etc. */
    account();				/* job accounting data */

    return (x_stat);			/* nothing could be wrong */

}   /* End of main */


/*****************************************************************************/


static void
init_signals(void)
{
    void		interrupt();		/* signal handler */

/*
 *
 * Make sure we handle interrupts.
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
    int		ch;			/* value returned by getopt() */

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

	    case 'w':			/* line width */
		    fprintf(stdout, "/linewidth %s def\n", optarg);
		    break;

	    case 'x':			/* shift horizontally */
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

	    case '?':			/* don't know the option */
		    error(FATAL, "");
		    break;

	    default:			/* don't know what to do for ch */
		    error(FATAL, "missing case for option %c", ch);
		    break;

	}   /* End switch */

    }	/* End while */

    argc -= optind;
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
 * we'll process stdin.
 *
 */


    if ( argc < 1 )
	statemachine(fp_in = stdin);
    else  {				/* at least one argument is left */
	while ( argc > 0 )  {
	    if ( strcmp(*argv, "-") == 0 )
		fp_in = stdin;
	    else if ( (fp_in = fopen(*argv, "r")) == NULL )
		error(FATAL, "can't open %s", *argv);
	    statemachine(fp_in);
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
statemachine(FILE *fp)
    /* used to set fp_in */
{

/*
 *
 * Controls the translation of the next input file. Tektronix states (dispmode)
 * are typically changed in control() and esc().
 *
 */


    redirect(-1);			/* get ready for the first page */
    formfeed();
    dispmode = RESET;

    while ( 1 )

	switch ( dispmode )  {

	    case RESET:
		    reset();
		    break;

	    case ALPHA:
		    alpha();
		    break;

	    case GIN:
		    gin();
		    break;

	    case GRAPH:
		    graph();
		    break;

	    case POINT:
	    case SPECIALPOINT:
		    point();
		    break;

	    case INCREMENTAL:
		    incremental();
		    break;

	    case EXIT:
		    formfeed();
		    return;

	}   /* End switch */

}   /* End of statemachine */


/*****************************************************************************/


static void
reset(void)
{

/*
 *
 * Called to reset things, typically only at the beginning of each input file.
 *
 */


    tekfont = -1;
    home();
    setfont(TEKFONT);
    setmode(ALPHA);

}   /* End of reset */


/*****************************************************************************/


static void
alpha(void)
{
    int		c;			/* next character */
    int		x, y;			/* cursor will be here when we're done */

/*
 *
 * Takes care of printing characters in the current font.
 *
 */


    if ( (c = nextchar()) == OUTMODED )
	return;

    if ( (c < 040) && ((c = control(c)) <= 0) )
	return;

    x = cursor.x;			/* where the cursor is right now */
    y = cursor.y;

    switch ( c )  {

	case DEL:
		return;

	case BS:
		if ((x -= charwidth[tekfont]) < margin)
		    x = TEKXMAX - charwidth[tekfont];
		break;

	case NL:
		y -= charheight[tekfont];
		break;

	case CR:
		x = margin;
		break;

	case VT:
		if ((y += charheight[tekfont]) >= TEKYMAX)
		    y = 0;
		break;

	case HT:
	case ' ':
	default:
		if ( characters++ == 0 )
		    fprintf(fp_out, "%d %d (", cursor.x, cursor.y);
		switch ( c )  {
		    case '(':
		    case ')':
		    case '\\':
			putc('\\', fp_out);

		    default:
			putc(c, fp_out);
		}   /* End switch */
		x += charwidth[tekfont];
		move(x, y);
		break;

    }	/* End switch */

    if (x >= TEKXMAX) {
	x = margin;
	y -= charheight[tekfont];
    }	/* End if */

    if (y < 0) {
	y = TEKYMAX - charheight[tekfont];
	x -= margin;
	margin = (TEKXMAX/2) - margin;
	if ((x += margin) > TEKXMAX)
	    x -= margin;
    }	/* End if */

    if ( y != cursor.y || x != cursor.x )
	text();

    move(x, y);

}   /* End of alpha */


/*****************************************************************************/

static void
graph(void)
{
    int			c;		/* next character */
    int			b;		/* for figuring out loy */
    int			x, y;		/* next point in the vector */
    static int		hix, hiy;	/* upper */
    static int		lox, loy;	/* and lower part of the address */
    static int		extra;		/* for extended addressing */

/*
 *
 * Handles things when we're in GRAPH, POINT, or SPECIALPOINT mode.
 *
 */

    if ((c = nextchar()) < 040) {
	control(c);
	return;
    }	/* End if */

    if ((c & 0140) == 040) {		/* new hiy */
	hiy = c & 037;
	do
	    if (((c = nextchar()) < 040) && ((c = control(c)) == OUTMODED))
		return;
	while (c == 0);
    }	/* End if */

    if ((c & 0140) == 0140) {		/* new loy */
	b = c & 037;
	do
	    if (((c = nextchar()) < 040) && ((c = control(c)) == OUTMODED))
		return;
	while (c == 0);
	if ((c & 0140) == 0140) {	/* no, it was extra */
	    extra = b;
	    loy = c & 037;
	    do
		if (((c = nextchar()) < 040) && ((c = control(c)) == OUTMODED))
		    return;
	    while (c == 0);
	} else loy = b;
    }	/* End if */

    if ((c & 0140) == 040) {		/* new hix */
	hix = c & 037;
	do
	    if (((c = nextchar()) < 040) && ((c = control(c)) == OUTMODED))
		return;
	while (c == 0);
    }	/* End if */

    lox = c & 037;			/* this should be lox */
    if (extra & 020)
	margin = TEKXMAX/2;

    x = (hix<<7) | (lox<<2) | (extra & 03);
    y = (hiy<<7) | (loy<<2) | ((extra & 014)>>2);

    if ( points > 100 )  {		/* don't put too much on the stack */
	draw();
	points = 1;
    }	/* End if */

    if ( points++ )
	fprintf(fp_out, "%d %d\n", cursor.x - x, cursor.y - y);

    move(x, y);				/* adjust the cursor */

}   /* End of graph */


/*****************************************************************************/

static void
point(void)
{
    int		c;			/* next input character */

/*
 *
 * Special point mode permits gray scaling by varying the size of the stored
 * point, which is controlled by an intensity character that preceeds each point
 * address.
 *
 */


    if ( dispmode == SPECIALPOINT )  {
	if ((c = nextchar()) < 040 || c > 0175) {
		control(c);
		return;
	}

	fprintf(fp_out, "%d %d i\n", intensity[c - ' '], c & 0100);
    }	/* End if */

    graph();
    draw();

}   /* End of point */


/*****************************************************************************/

static void
incremental(void)
{


    int		c;			/* for the next few characters */
    int		x, y;			/* cursor position when we're done */


/*
 *
 * Handles incremental plot mode. It's entered after the RS control code and is
 * used to mark points relative to our current position. It's typically followed
 * by one or two bytes that set the pen state and are used to increment the
 * current position.
 *
 */


    if ( (c = nextchar()) == OUTMODED )
	return;

    if ( (c < 040) && ((c = control(c)) <= 0) )
	return;

    x = cursor.x;			/* where we are right now */
    y = cursor.y;

    if ( c & 060 )
	pen = ( c & 040 ) ? UP : DOWN;

    if ( c & 04 ) y++;
    if ( c & 010 ) y--;
    if ( c & 01 ) x++;
    if ( c & 02 ) x--;

    move(x, y);

    if ( pen == DOWN )  {
	points = 1;
	draw();
    }	/* End if */

}   /* End of incremental */


/*****************************************************************************/

static void
gin(void)
{

/*
 *
 * All we really have to do for GIN mode is make sure it's properly ended.
 *
 */


    control(nextchar());

}   /* End of gin */


/*****************************************************************************/

static int
control(int c)
    /* check this control character */
{

/*
 *
 * Checks character c and does special things, like mode changes, that depend
 * not only on the character, but also on the current state. If the mode changed
 * becuase of c, OUTMODED is returned to the caller. In all other cases the
 * return value is c or 0, if c doesn't make sense in the current mode.
 *
 */


    switch ( c )  {

	case BEL:
		return(0);

	case BS:
	case HT:
	case VT:
		return(dispmode == ALPHA ? c : 0);

	case CR:
		if ( dispmode != ALPHA )  {
		    setmode(ALPHA);
		    ungetc(c, fp_in);
		    return(OUTMODED);
		} else return(c);

	case FS:
		if ( (dispmode == ALPHA) || (dispmode == GRAPH) )  {
		    setmode(POINT);
		    return(OUTMODED);
		}   /* End if */
		return(0);

	case GS:
		if ( (dispmode == ALPHA) || (dispmode == GRAPH) )  {
		    setmode(GRAPH);
		    return(OUTMODED);
		}   /* End if */
		return(0);

	case NL:
		ungetc(CR, fp_in);
		return(dispmode == ALPHA ? c : 0);

	case RS:
		if ( dispmode != GIN )  {
		    setmode(INCREMENTAL);
		    return(OUTMODED);
		}   /* End if */
		return(0);

	case US:
		if ( dispmode == ALPHA )
		    return(0);
		setmode(ALPHA);
		return(OUTMODED);

	case ESC:
		return(esc());

	case OUTMODED:
		return(c);

	default:
		return(c < 040 ? 0 : c);

    }	/* End switch */

}   /* End of control */


/*****************************************************************************/


static int
esc(void)
{
    int		c;			/* next input character */
    int		ignore;			/* skip it if nonzero */

/*
 *
 * Handles tektronix escape code. Called from control() whenever an ESC character
 * is found in the input file.
 *
 */


    do  {
	c = nextchar();
	ignore = 0;
	switch ( c )  {

	    case CAN:
		    return(0);

	    case CR:
		    ignore = 1;
		    break;

	    case ENQ:
		    setmode(ALPHA);
		    return(OUTMODED);

	    case ETB:
		    return(0);

	    case FF:
		    formfeed();
		    setmode(ALPHA);
		    return(OUTMODED);

	    case FS:
		    if ( (dispmode == INCREMENTAL) || ( dispmode == GIN) )
			return(0);
		    setmode(SPECIALPOINT);
		    return(OUTMODED);

	    case SI:
	    case SO:
		    return(0);

	    case SUB:
		    setmode(GIN);
		    return(OUTMODED);

	    case OUTMODED:
		    return(OUTMODED);

	    case '8':
	    case '9':
	    case ':':
	    case ';':
		    setfont(c - '8');
		    return(0);

	    default:
		    if ( c == '?' && dispmode == GRAPH )
			return(DEL);
		    if ( (c<'`') || (c>'w') )
			break;
		    c -= '`';
		    if ( (c & 010) != linetype )
			fprintf(fp_out, "%d w\n", (linetype = (c & 010))/010);
		    if ( ((c + 1) & 7) >= 6 )
			break;
		    if ( (c + 1) & 7 )
			if ( (c & 7) != linestyle )  {
			    linestyle = c & 7;
			    setmode(dispmode);
			    fprintf(fp_out, "%s l\n", styles[linestyle]);
			}   /* End if */
		    return(0);
	}   /* End switch */

    } while (ignore);

    return(0);

}   /* End of esc */


/*****************************************************************************/


static void
move(int x, int y)
    /* move the cursor here */
{

/*
 *
 * Moves the cursor to the point (x, y).
 *
 */


    cursor.x = x;
    cursor.y = y;

}   /* End of move */


/*****************************************************************************/

static void
setmode(int mode)
    /* this should be the new mode */
{

/*
 *
 * Makes sure the current mode is properly ended and then sets dispmode to mode.
 *
 */


    switch ( dispmode )  {

	case ALPHA:
		text();
		break;

	case GRAPH:
		draw();
		break;

	case INCREMENTAL:
		pen = UP;
		break;

    }	/* End switch */

    dispmode = mode;

}   /* End of setmode */


/*****************************************************************************/

static void
home(void)
{

/*
 *
 * Makes sure the cursor is positioned at the upper left corner of the page.
 *
 */


    margin = 0;
    move(0, TEKYMAX);

}   /* End of home */


/*****************************************************************************/

static void
setfont(int newfont)
    /* use this font next */
{


/*
 *
 * Generates the call to the procedure that's responsible for changing the
 * tektronix font (really just the size).
 *
 */


    if ( newfont != tekfont )  {
	setmode(dispmode);
	fprintf(fp_out, "%d f\n", charwidth[newfont]);
    }	/* End if */

    tekfont = newfont;

}   /* End of setfont */


/*****************************************************************************/

static void
text(void)
{

/*
 *
 * Makes sure any text we've put on the stack is printed.
 *
 */


    if ( dispmode == ALPHA && characters > 0 )
	fprintf(fp_out, ") t\n");

    characters = 0;

}   /* End of text */


/*****************************************************************************/

static void
draw(void)
{


/*
 *
 * Called whenever we need to draw a vector or plot a point. Nothing will be
 * done if points is 0 or if it's 1 and we're in GRAPH mode.
 *
 */


    if ( points > 1 )			/* it's a vector */
	fprintf(fp_out, "%d %d v\n", cursor.x, cursor.y);
    else if ( points == 1 && dispmode != GRAPH )
	fprintf(fp_out, "%d %d p\n", cursor.x, cursor.y);

    points = 0;

}   /* End of draw */


/*****************************************************************************/

static void
formfeed(void)
{

/*
 *
 * Usually called when we've finished the last page and want to get ready for the
 * next one. Also used at the beginning and end of each input file, so we have to
 * be careful about exactly what's done.
 *
 */


    setmode(dispmode);			/* end any outstanding text or graphics */

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
    fprintf(fp_out, "%d f\n", charwidth[tekfont]);
    fprintf(fp_out, "%s l\n", styles[linestyle]);

    home();

}   /* End of formfeed */


/*****************************************************************************/


static int
nextchar(void)
{
    int		ch;			/* next input character */

/*
 *
 * Reads the next character from the current input file and returns it to the
 * caller. When we're finished with the file dispmode is set to EXIT and OUTMODED
 * is returned to the caller.
 *
 */


    if ( (ch = getc(fp_in)) == EOF )  {
	setmode(EXIT);
	ch = OUTMODED;
    }	/* End if */

    return(ch);

}   /* End of nextchar */


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
