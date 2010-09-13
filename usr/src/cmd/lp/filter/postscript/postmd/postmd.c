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
 * postmd - matrix display program for PostScript printers.
 *
 * A simple program that can be used to display a matrix as a gray scale image on
 * a PostScript printer using the image operator. Much of the code was borrowed
 * from postdmd, the bitmap display program DMD screen dumps. May help if you have
 * a large matix (of floating point numbers) and want a simple way to look for
 * patterns.
 *
 * Matrix elements are a series of floating point numbers arranged in the input
 * file in row major order. The actual matrix elements can be preceeded by a simple
 * header that sets things like the matrix dimensions, interval list, and possibly
 * a window into the matrix that we'll use for display. The dimension statement is
 * perhaps the most important. If present it determines the number of rows and
 * columns in the matrix. For example, either of the following defines a 50x50
 * matrix,
 *
 *		dimension	50
 *		dimension	50x50
 *
 * If no dimension statement appears in the input file, the matrix is assumed to
 * be square, and the number of rows (and columns) is set to the square root of
 * the number of elements in the input file.
 *
 * Each matrix element is mapped into an integer in the range 0 to 255 (actually
 * 254) and PostScript's image operator then maps that number into a gray scale
 * appropriate for the particular printer. The mapping from the floating point
 * matrix elements to integers is accomplished using an interval list that can be
 * set using the -i option. The format of the interval string is,
 *
 *		num1,num2,num3,...,numn
 *
 * where each num is a floating point number. The list must be given in increasing
 * numerical order. A list of n numbers partitions the real line into 2n+1 regions
 * given as,
 *
 *		region1		element < num1
 *		region2		element = num1
 *		region3		element < num2
 *		region4		element = num2
 *		   .
 *		   .
 *		   .
 *		region2n	element = numn
 *		region2n+1	element > numn
 *
 * Every number in a region is mapped one integer in the range 0 to 254, and that
 * number, when displayed on a printer using the image operator, prints as a square
 * filled with a gray shade that reflects the integer that was chosen. 0 maps to
 * black and 255 maps to white (which by default will not be used).
 *
 * The default gray scale gets darker as the region number increases, but can be
 * changed by supplying a gray scale list with the -g option or in the optional
 * matrix header. The color map is again a comman or space separated list that
 * looks like,
 *
 *		color1,color2, ... ,color2n+1
 *
 * where color1 applies to region 1 and color2n+1 applies to region2n+1. Each
 * number in the list should be an integer between 0 and 255. If less than 2n+1
 * colors are given default assignments will be used for missing regions.
 *
 * The size of the matrix that we can display reasonably well is a function of the
 * number of elements in the interval list, paper size, and printer resolution.
 * For example a 300dpi printer using 8.5x11 inch paper gives us an image area of
 * about 2400x2400 pixels. An interval list of two numbers generates five separate
 * regions and will therefore need that many different shades of gray. Since we're
 * not using white we'll need to partion our image area into 4x4 pixel squares,
 * and that means a 600x600 matrix is about as big as we can go. In practice that's
 * optimistic, but the argument illustrates some of the limitations.
 *
 * A submatrix can be selected to display by windowing into the matrix. The window
 * list can be given using the -w option or can be set in the optional header that
 * can preceed each matrix.  The list should be a comma or space separated list
 * that looks like,
 *
 *		lower-column, lower-row, upper-column, upper-row
 *
 * where each element in the list must be a positive integer. Rows and columns in
 * the input matrix start at 1. The dimension of the displayed window will be from
 * lower-column to upper-column and from lower-row to upper-row inclusive.
 *
 * The encoding produced by the program is essentially identical to what's done
 * by postdmd. See the comments at the beginning of that program if you need more
 * details. The prologue also shares much of the same code. 
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
 *	    Does whatever is needed to set things up for the next page. Expects
 *	    to find the current page number on the stack.
 *
 *	bitmap
 *
 *	  columns rows bitmap -
 *
 *	    Prints the image that's read as a hex string from standard input. The
 *	    image consists of rows lines, each of which includes columns elements.
 *	    Eight bits per pixel are used to encode the matrix elements.
 *
 *	labelmatrix
 *
 *	  matrixname matrixlimits labelmatrix -
 *
 *	    Prints string matrixname just below the lower left corner of the image
 *	    and prints string martixlimits near the lower right corner. Outlines
 *	    the entire image with a (one pixel wide) box and then draws tick marks
 *	    along the top and left sides of the image. One tick mark is printed
 *	    for every ten elements.
 *
 *	legend
 *
 *	  n1 ... nN N c1 m1 ... cM mM total regions legend -
 *
 *	    Prints the legend as a bar graph below the matrix image. n1 ... nN are
 *	    strings that represent the interval list. c1 m1 ... cm mM are pairs
 *	    that consist of a region's color and the statistics count. Actually
 *	    the c's are trivial procedures that just leave a one character string
 *	    on the stack when they're executed by image - which is the way the
 *	    bar graph is drawn.
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
#include "postmd.h"			/* special matrix display definitions */


char	*optnames = "a:b:c:d:g:i:m:n:o:p:w:x:y:A:C:J:L:P:R:DI";

char	*prologue = POSTMD;		/* default PostScript prologue */
char	*formfile = FORMFILE;		/* stuff for multiple pages per sheet */
char	*temp_dir = TEMPDIR;		/* temp directory for copying stdin */

int	formsperpage = 1;		/* page images on each piece of paper */
int	copies = 1;			/* and this many copies of each sheet */
int	bytespp = 6;			/* bytes per pattern - on output */

int	dostats = ON;			/* permanent statistics flag */
int	nmstat = ON;			/* and the one for the next matrix */

char	*interval = DFLTILIST;		/* string representations of the interval */
char	*colormap = NULL;		/* color map */
char	*window = NULL;			/* and window lists */
char	*matrixname = "pipe.end";	/* name for the next plot */

Ilist	ilist[128];			/* active interval list and color map */
int	next = 0;			/* one past the last element in ilist[] */
int	regions;			/* an index assigned to the last region */
int	wlist[4];			/* upper left and lower right corners */

int	page = 0;			/* last page we worked on */
int	printed = 0;			/* and the number of pages printed */

int	dfltrows = 0;			/* default rows */
int	dfltcols = 0;			/* and columns - changed by -d option */
int	rows;				/* real number of rows */
int	columns;			/* and columns in the matrix */
int	patcount = 0;			/* will be set to columns * rows */

double	element;			/* next matrix element */

char	*raster = NULL;			/* next raster line */
char	*rptr;				/* next free byte in raster */
char	*eptr;				/* one past the last byte in raster */

FILE	*fp_in = stdin;			/* read from this file */
FILE	*fp_out = stdout;		/* and write stuff here */
FILE	*fp_acct = NULL;		/* for accounting data */

static void account(void);
static void addcolormap(char *);
static void arguments(void);
static void buildilist(char *);
static void copystdin(void);
static void dimensions(void);
static void done(void);
static void getheader(void);
static void header(void);
static void init_signals(void);
static int inrange(void);
static int inwindow(void);
static void labelmatrix(void);
static int mapfloat(double);
static void matrix(void);
static void options(void);
static int patncmp(char *, int);
static void putrow(void);
static void redirect(int);
static char *savestring(char *);
static void setup(void);
static void setwindow(char *);

/*****************************************************************************/

int
main(int agc, char *agv[])
{

/*
 *
 * Bitmap display program for matrices. Only one matrix is allowed per input file,
 * and each one will be displayed on a page by itself. Input files consist of an
 * optional header followed by floating point numbers that represent the matrix
 * elements - in row major order.
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
    signal(SIGFPE, interrupt);

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

	    case 'b':			/* bytes per pattern - on output */
		    bytespp = atoi(optarg);
		    break;

	    case 'c':			/* copies */
		    copies = atoi(optarg);
		    fprintf(stdout, "/#copies %s store\n", optarg);
		    break;

	    case 'd':			/* default matrix dimensions */
		    sscanf(optarg, "%dx%d", &dfltrows, &dfltcols);
		    break;

	    case 'g':			/* set the colormap (ie. grayscale) */
		    colormap = optarg;
		    break;

	    case 'i':			/* matrix element interval list */
		    interval = optarg;
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

	    case 'w':			/* set the window */
		    window = optarg;
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
	matrix();
    else  {				/* at least one argument is left */
	while ( argc > 0 )  {
	    matrixname = *argv;
	    if ( strcmp(*argv, "-") == 0 )  {
		fp_in = stdin;
		matrixname = "pipe.end";
	    } else if ( (fp_in = fopen(*argv, "r")) == NULL )
		error(FATAL, "can't open %s", *argv);
	    matrix();
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
    fprintf(stdout, "%s %d\n", PAGES, printed);

    if ( temp_file != NULL )
	unlink(temp_file);

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
matrix(void)
{


    int		count;			/* pattern repeats this many times */
    long	total;			/* expect this many patterns */


/*
 *
 * Reads a matrix from *fp_in, translates it into a PostScript gray scale image,
 * and writes the result on stdout. For now only one matrix is allowed per input
 * file. Matrix elements are floating point numbers arranged in row major order
 * in the input file. In addition each input file may contain an optional header
 * that defines special things like the dimension of the matrix, a window into
 * the matrix that will be displayed, and an interval list.
 *
 * If we're reading from stdin we first make a copy in a temporary file so we can
 * can properly position ourselves after we've looked for the header. Originally
 * wasn't always making a copy of stdin, but I've added a few things to what's
 * accepted in the header and this simplifies the job. An alternative would be
 * to always require a header and mark the end of it by some string. Didn't like
 * that approach much - may fix things up later.
 *
 */


    if ( fp_in == stdin )		/* make a copy so we can seek etc. */
	copystdin();

    rows = dfltrows;			/* new dimensions for the next matrix */
    columns = dfltcols;

    buildilist(interval);		/* build the default ilist[] */
    addcolormap(colormap);		/* add the colormap - if not NULL */
    setwindow(window);			/* and setup the initial matrix window */
    nmstat = dostats;			/* want statistics? */
    getheader();			/* matrix dimensions at the very least */
    dimensions();			/* make sure we have the dimensions etc. */

    patcount = 0;
    total = rows * columns;

    eptr = rptr + (wlist[2] - wlist[0] + 1);

    redirect(++page);

    fprintf(fp_out, "%s %d %d\n", PAGE, page, printed+1);
    fprintf(fp_out, "save\n");
    writerequest(printed+1, fp_out);
    fprintf(fp_out, "%d %d bitmap\n", wlist[2] - wlist[0] + 1, wlist[3] - wlist[1] + 1);

    while ( patcount != total && fscanf(fp_in, "%f", &element) != EOF )  {
	if ( inwindow() ) *rptr++ = mapfloat(element);
	if ( ++patcount % columns == 0 )
	    if ( inrange() )
		putrow();
    }	/* End while */

    if ( total != patcount )
	error(FATAL, "matrix format error");

    labelmatrix();

    if ( fp_out == stdout ) printed++;

    fprintf(fp_out, "showpage\n");
    fprintf(fp_out, "restore\n");
    fprintf(fp_out, "%s %d %d\n", ENDPAGE, page, printed);

}   /* End of matrix */


/*****************************************************************************/

static void
copystdin(void)
{
    int		fd_out;			/* for the temporary file */
    int		fd_in;			/* for stdin */
    int		buf[512];		/* buffer for reads and writes */
    int		count;			/* number of bytes put in buf */

/*
 *
 * If we're reading the matrix from stdin and the matrix dimension isn't set by
 * a dimension statement at the beginning of the file we'll copy stdin to a
 * temporary file and reset *fp_in so reads come from the temp file. Simplifies
 * reading the header (if present), but is expensive.
 *
 */


    if ( temp_file != NULL )		/* been here already */
	unlink(temp_file);

    if ( (temp_file = tempnam(temp_dir, "post")) == NULL )
	error(FATAL, "can't generate temp file name");

    if ( (fd_out = creat(temp_file, 0660)) == -1 )
	error(FATAL, "can't create %s", temp_file);

    fd_in = fileno(stdin);

    while ( (count = read(fd_in, buf, sizeof(buf))) > 0 )
	if ( write(fd_out, buf, count) != count )
	    error(FATAL, "error writing to %s", temp_file);

    close(fd_out);

    if ( (fp_in = fopen(temp_file, "r")) == NULL )
	error(FATAL, "can't open %s", temp_file);

}   /* End of copystdin */


/*****************************************************************************/

static void
getheader(void)
{
    char	buf[512];		/* temporary string space */
    char	*cmap = NULL;		/* remember header colormap list */
    long	pos;			/* for seeking back to first element */

/*
 *
 * Looks for the optional header information at the beginning of the input file,
 * reads it if it's there, and sets *fp_in to be just past the header. That should
 * be the beginning of the matrix element list. The recognized header keywords are
 * dimension, interval, colormap (or grayscale), window, name, and statistics. All
 * are optional, but may be useful in a spooling environment when the user doesn't
 * doesn't actually run the translator.
 *
 * The dimension statement specifies the number of rows and columns. For example
 * either of the following two lines define a 50 by 50 element matrix,
 *
 *	dimension	50
 *	dimension	50x50
 *
 * The first integer is the number of rows and the second, if given, is the number
 * of columns. If columns are missing from the dimension statement we assume the
 * matrix is square.
 *
 * interval can be used to redefine the interval list used for mapping floating
 * point numbers into integers in the range 0 to 254. The string following the
 * interval keyword has the same format as the -i option. For example to set the
 * interval list to -1, 0, and 1 you can add the line,
 *
 *	interval	-1,0,1
 *
 * The numbers are floats given in increasing order, and separated by commas or
 * blanks. The last interval list in a header takes precedence.
 *
 * colormap can be used to redefine the grayscale list.  The string following
 * the colormap keyword has the same format as the -g option.  For example
 *
 *	colormap	0,50,100,150,200,250
 * or	grayscale	0,50,100,150,200,250
 *
 * The window keyword can be used to select a submatrix. The numbers following
 * window are the upper left and lower right matix coordinates. May not be
 * implemented yet but shouldn't be difficult. For example
 *
 *	window		10 10 40 40
 *
 * selects the submatrix with corners at (10, 10) and (40, 40). The edges of the
 * window are included in the display.
 *
 * The name keyword can be used to define the title of the display.  For example,
 *
 *	name		Plot Of Matrix 1
 *
 * prints the string "Plot Of Matrix 1" at the top of the page. Everything up to
 * the next newline is taken as the name string.
 *
 */


    pos = ftell(fp_in);

    while ( fscanf(fp_in, "%s", buf) != EOF )  {
	if ( strncmp(buf, "dimension", strlen("dimension")) == 0 )
	    fscanf(fp_in, "%dx%d", &rows, &columns);
	else if ( strncmp(buf, "window", strlen("window")) == 0 )  {
	    fgets(buf, sizeof(buf), fp_in);
	    setwindow(buf);
	} else if ( strncmp(buf, "name", strlen("name")) == 0 )  {
	    fgets(buf, sizeof(buf), fp_in);
	    matrixname = savestring(buf);
	} else if ( strncmp(buf, "colormap", strlen("colormap")) == 0 )  {
	    fgets(buf, sizeof(buf), fp_in);
	    cmap = savestring(buf);
	} else if ( strncmp(buf, "grayscale", strlen("grayscale")) == 0 )  {
	    fgets(buf, sizeof(buf), fp_in);
	    cmap = savestring(buf);
	} else if ( strncmp(buf, "interval", strlen("interval")) == 0 )  {
	    fgets(buf, sizeof(buf), fp_in);
	    buildilist(buf);
	} else if ( strncmp(buf, "statistics", strlen("statistics")) == 0 )  {
	    fscanf(fp_in, "%s", buf);
	    if ( strcmp(buf, "on") == 0 || strcmp(buf, "ON") == 0 )
		nmstat = ON;
	    else
		nmstat = OFF;
	} else break;
	pos = ftell(fp_in);
    }	/* End while */

    addcolormap(cmap);			/* must happen last */
    fseek(fp_in, pos, 0);		/* back to the start of the matrix */

}   /* End of getheader */


/*****************************************************************************/

static void
dimensions(void)
{
    char	buf[100];		/* temporary storage for the elements */
    long	count = 0;		/* number of elements in the matrix */
    long	pos;			/* matrix elements start here */

/*
 *
 * Need to know the dimensions of the matrix before we can go any farther. If
 * rows and columns are still 0 we'll read the entire input file, starting from
 * the current position, count the number of elements, take the square root of it,
 * and use it as the number of rows and columns. Then we seek back to the start
 * of the real matrix, make sure columns is set, and allocate enough memory for
 * storing each raster line. After we're certain we've got the number of rows and
 * columns we check the window coordinates, and if they're not legitimate they're
 * reset to cover the entire matrix.
 *
 */



    if ( rows == 0 )  {
	pos = ftell(fp_in);
	while ( fscanf(fp_in, "%s", buf) != EOF )
	    count++;
	rows = sqrt((double) count);
	fseek(fp_in, pos, 0);
    }	/* End if */

    if ( columns <= 0 ) columns = rows;

    if ( raster != NULL ) free(raster);

    if ( (rptr = raster = malloc(columns)) == NULL )
	error(FATAL, "no memory");

    eptr = rptr + columns;

    if ( rows <= 0 || columns <= 0 )
	error(FATAL, "bad matrix dimensions");

    if ( wlist[0] > wlist[2] || wlist[1] > wlist[3] )  {
	wlist[0] = wlist[1] = 1;
	wlist[2] = columns;
	wlist[3] = rows;
    }	/* End if */

}   /* End of dimensions */


/*****************************************************************************/

static void
buildilist(char *list)
    /* use this as the interval list */
{
    static char	*templist = NULL;	/* a working copy of the list */
    char	*ptr;			/* next number in *templist */
    int		i;			/* loop index - for checking the list */


/*
 *
 * Reads string *list and builds up the ilist[] that will be used in the next
 * matrix. Since strtok() modifies the string it's parsing we make a copy first.
 * The format of the interval list is described in detail in the comments at the
 * beginning of this program. Basically consists of a comma or space separated
 * list of floating point numbers that must be given in increasing numerical order.
 * The list determines how floating point numbers are mapped into integers in the
 * range 0 to 254.
 *
 */


    if ( templist != NULL )		/* free the space used by the last list */
	free(templist);

    while ( isascii(*list) && isspace(*list) )
	list++;

    for ( ptr = list, regions = 3; *ptr != '\0'; ptr++ )  {
	if ( *ptr == ',' || *ptr == '/' || isspace(*ptr) )
	    regions += 2;
	while ( isascii(*ptr) && isspace(*ptr) ) ptr++;
    }	/* End for */

    next = 0;
    templist = savestring(list);

    ptr = strtok(templist, ",/ \t\n");
    while ( ptr != NULL )  {
	ilist[next].count = 0;
	ilist[next++].color = 254 * (regions - 1 - next) / (regions - 1);
	ilist[next].val = atof(ptr);
	ilist[next].count = 0;
	ilist[next++].color = 254 * (regions - 1 - next) / (regions - 1);
	ptr = strtok(NULL, ",/ \t\n");
    }	/* End while */

    ilist[next].count = 0;
    ilist[next].color = 254 * (regions - 1 - next) / (regions - 1);

    if ( next == 0 )			/* make sure we have a list */
	error(FATAL, "missing interval list");

    for ( i = 3; i < next; i += 2 )	/* that's in increasing numerical order */
	if ( ilist[i].val <= ilist[i-2].val )
	    error(FATAL, "bad interval list");

}   /* End of buildilist */


/*****************************************************************************/

static void
addcolormap(char *list)
    /* use this color map */
{
    static char	*templist = NULL;	/* a working copy of the color list */
    char	*ptr;			/* next color in *templist */
    int		i = 0;			/* assigned to this region in ilist[] */

/*
 *
 * Assigns the integers in *list to the color field for the regions defined in
 * ilist[]. Assumes ilist[] has already been setup.
 *
 */


    if ( list != NULL )  {
	if ( templist != NULL )
	    free(templist);
	templist = savestring(list);

	ptr = strtok(templist, ",/ \t\n");
	while ( ptr != NULL )  {
	    ilist[i++].color = atoi(ptr) % 256;
	    ptr = strtok(NULL, ",/ \t\n");
	}   /* End while */
    }	/* End if */

}   /* End of addcolormap */


/*****************************************************************************/

static void
setwindow(char *list)
    /* corners of window into the matrix */
{
    static char	*templist = NULL;	/* a working copy of the window list */
    char	*ptr;			/* next window coordinate in *templist */
    int		i = 0;			/* assigned to this region in wlist[] */

/*
 *
 * Sets up an optional window into the matrix.
 *
 */


    wlist[0] = wlist[1] = 1;
    wlist[2] = wlist[3] = 0;

    if ( list != NULL )  {
	if ( templist != NULL )
	    free(templist);
	templist = savestring(list);

	ptr = strtok(templist, ",/ \t\n");
	while ( ptr != NULL )  {
	    wlist[i++] = atoi(ptr);
	    ptr = strtok(NULL, ",/ \t\n");
	}   /* End while */
    }	/* End if */

}   /* End of setwindow */


/*****************************************************************************/

static int
inwindow(void)
{
    int		r;			/* row of the patcount element */
    int		c;			/* column of the patcount element */

/*
 *
 * Checks if the patcount element of the matrix is in the window.
 *
 */


    r = (patcount/columns) + 1;
    c = (patcount%columns) + 1;

    return((c >= wlist[0]) && (r >= wlist[1]) && (c <= wlist[2]) && (r <= wlist[3]));

}   /* End of inwindow */


/*****************************************************************************/

static int
inrange(void)
{

/*
 *
 * Checks if the current row lies in the window. Used right before we output the
 * raster lines.
 *
 */


    return(((patcount/columns) >= wlist[1]) && ((patcount/columns) <= wlist[3]));


}   /* End of inrange */


/*****************************************************************************/

static int
mapfloat(double element)
    /* floating point matrix element */
{
    int		i;			/* loop index */

/*
 *
 * Maps element into an integer in the range 0 to 255, and returns the result to
 * the caller. Mapping is done using the color map that was saved in ilist[]. Also
 * updates the count field for the region that contains element - not good!
 *
 */


    for ( i = 1; i < next && ilist[i].val < element; i += 2 ) ;

    if ( i > next || element < ilist[i].val )
	i--;

    ilist[i].count++;
    return(ilist[i].color);

}   /* End of mapfloat */


/*****************************************************************************/

static void
putrow(void)
{
    char	*p1, *p2;		/* starting and ending columns */
    int		n;			/* set to bytes per pattern */
    int		i;			/* loop index */

/*
 *
 * Takes the scanline that's been saved in *raster, encodes it according to the
 * value that's been assigned to bytespp, and writes the result to *fp_out. Each
 * line in the output bitmap is terminated by a 0 on a line by itself.
 *
 */


    n = (bytespp <= 0) ? columns : bytespp;

    for ( p1 = raster, p2 = raster + n; p1 < eptr; p1 = p2 )
	if ( patncmp(p1, n) == TRUE )  {
	    while ( patncmp(p2, n) == TRUE ) p2 += n;
	    p2 += n;
	    fprintf(fp_out, "%d ", n);
	    for ( i = 0; i < n; i++, p1++ )
		fprintf(fp_out, "%.2X", ((int) *p1) & 0377);
	    fprintf(fp_out, " %d\n", (p2 - p1) / n);
	} else {
	    while ( p2 < eptr && patncmp(p2, n) == FALSE ) p2 += n;
	    if ( p2 > eptr ) p2 = eptr;
	    fprintf(fp_out, "%d ", p2 - p1);
	    while ( p1 < p2 )
		fprintf(fp_out, "%.2X", ((int) *p1++) & 0377);
	    fprintf(fp_out, " 0\n");
	}   /* End else */

    fprintf(fp_out, "0\n");

    rptr = raster;

}   /* End of putrow */


/*****************************************************************************/

static void
labelmatrix(void)
{
    int		total;			/* number of elements in the window */
    int		i;			/* loop index */

/*
 *
 * Responsible for generating the PostScript calls that label the matrix, generate
 * the legend, and print the matrix name.
 *
 */


    fprintf(fp_out, "(%s) ((%d, %d) to (%d, %d)) labelmatrix\n", matrixname,
			wlist[0], wlist[1], wlist[2], wlist[3]);

    total = (wlist[2] - wlist[0] + 1) * (wlist[3] - wlist[1] + 1);

    if ( nmstat == OFF )
	for ( i = 0; i < regions; i++ )
	    ilist[i].count = 0;

    for ( i = 1; i < next; i += 2 )
	fprintf(fp_out, "(%g) ", ilist[i].val);
    fprintf(fp_out, "%d ", (regions - 1) / 2);

    for ( i = regions - 1; i >= 0; i-- )
	fprintf(fp_out, "{(\\%.3o)} %d ", ilist[i].color, ilist[i].count);
    fprintf(fp_out, "%d %d legend\n", total, regions);

}   /* End of labelmatrix */


/*****************************************************************************/

static int
patncmp(char *p1, int n)
    /* p1 - first patterns starts here */
    /* n - and extends this many bytes */
{
    char	*p2;			/* address of the second pattern */

/*
 *
 * Compares the two n byte patterns *p1 and *(p1+n). FALSE if returned is they're
 * different or extend past the end of the current raster line.
 *
 */


    p2 = p1 + n;

    for ( ; n > 0; n--, p1++, p2++ )
	if ( p2 >= eptr || *p1 != *p2 )
	    return(FALSE);

    return(TRUE);

}   /* End of patncmp */


/*****************************************************************************/

static char *
savestring(char *str)
    /* save this string */
{
    char	*ptr = NULL;		/* at this address */

/*
 *
 * Copies string *str to a permanent place and returns the address to the caller.
 *
 */


    if ( str != NULL && *str != '\0' )  {
	if ( (ptr = malloc(strlen(str) + 1)) == NULL )
	    error(FATAL, "no memory available for string %s", str);
	strcpy(ptr, str);
    }	/* End if */

    return(ptr);

}   /* End of savestring */


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
