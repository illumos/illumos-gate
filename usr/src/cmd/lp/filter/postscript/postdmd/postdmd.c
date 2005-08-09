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
 * postdmd - PostScript translator for DMD bitmap files.
 *
 * A simple program that can be used to print DMD bitmaps on PostScript printers.
 * Much of the code was borrowed from abm, which was written by Guy Riddle.
 *
 * Although the program supports two different input bitmap formats, by far the
 * most important is the Eighth (and Ninth) Edition bitfile format. A bitmap in
 * the bitfile format begins with a 10 byte header with the first two bytes set to
 * zero. The next 8 bytes set the x and y coordinates of the bitmap's origin and
 * corner (ie. the upper left and lower right corners). The compressed raster data
 * follows the header and consists of control bytes followed an appropriate number
 * of data bytes. Control bytes (ie. n) less than 127 means read the next 2*n bytes 
 * of raster data directly from the input file, while if n is larger than 128 we
 * read two bytes from the input file and replicate the bytes n-128 times. After
 * each scan line is recovered it's exclusive-or'd with the preceeding line to
 * generate the real raster data.
 *
 * After each raster line is recovered postdmd encodes it in a slightly different
 * format that's designed to be unpacked by a PostScript procedure that's defined
 * in the prologue. By default no exclusive-or'ing is done and packing of pattern
 * data can be based on any number of bytes rather than just the next two bytes.
 * By default 6 byte patterns are used, but any number can be selected with the -b
 * option. A non-positive argument (eg. -b0) disables all pattern encoding. Larger
 * patterns increase the size of the output file, but reduce the work load that's
 * forced on the PostScript interpreter. The default choices I've made (ie. 6 byte
 * patterns and no exclusive-or'ing) do a decent balancing job across currently
 * available PostScript printers. Larger patterns (eg. -b16) increase the output
 * file size, but may be appropriate if you're running at a high baud rate (eg.
 * 19.2KB), while smaller patter size (eg. -b4) may help if you've got a printer
 * with a fast processor (eg. a PS-810).
 *
 * The encoding produced by the program (and decoded on the printer) looks like,
 * 
 * 	bytes patterns count
 * 
 * where bytes and count are decimal integers and patterns is a hex string. Bytes
 * is the number of bytes represented by the hex patterns and count is the number
 * of additional times the patterns should be repeated. For example,
 * 
 * 	2 FFFF 4
 * 	5 FFFFFFFFFF 1
 *     10 FFFFFFFFFFFFFFFFFFFF 0
 * 
 * all represent 10 consecutive bytes of ones. Scanlines are terminated by a 0 on
 * a line by itself.
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
 *	  v8format flip scanlength scanlines bitmap -
 *
 *	    Prints the bitmap that's read from standard input. The bitmap consists
 *	    of scanlines lines, each of which includes scanlength pixels. If
 *	    v8format is true the picture is assumed to be an Eighth Edition bitmap,
 *	    and the exclusive-or'ing will be done on the printer.
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


char	*optnames = "a:b:c:fm:n:o:p:ux:y:A:C:J:L:P:DI";

char	*prologue = POSTDMD;		/* default PostScript prologue */
char	*formfile = FORMFILE;		/* stuff for multiple pages per sheet */

int	bbox[2] = {0, 0};		/* upper right coordinates only */

int	formsperpage = 1;		/* page images on each piece of paper */
int	copies = 1;			/* and this many copies of each sheet */

int	bytespp = 6;			/* bytes per pattern - on output */
int	flip = FALSE;			/* ones complement the bitmap */
int	v8undo = TRUE;			/* xor'ing done on host if TRUE */
int	v8format = FALSE;		/* for Eighth Edition bitmaps */

int	page = 0;			/* last page we worked on */
int	printed = 0;			/* and the number of pages printed */

int	patterns;			/* 16 bit patterns per scan line */
int	scanlines;			/* lines in the bitmap */
int	patcount = 0;			/* should be patterns * scanlines */

char	*raster = NULL;			/* next raster line */
char	*prevrast = NULL;		/* and the previous one - v8format */
char	*rptr;				/* next free byte in raster */
char	*eptr;				/* one past the last byte in raster */

FILE	*fp_in = NULL;			/* read from this file */
FILE	*fp_out = stdout;		/* and write stuff here */
FILE	*fp_acct = NULL;		/* for accounting data */

static void account(void);
static void addrast(int);
static void arguments(void);
static void bitmap(FILE *);
static int dimensions(void);
static void done(void);
static int getint(void);
static void header(void);
static void init_signals(void);
static void options(void);
static int patncmp(char *, int);
static void putrast(void);
static void redirect(int);
static void setup(void);

/*****************************************************************************/

int
main(int agc, char *agv[])
{

/*
 *
 * A simple program that translates DMD bitmap files into PostScript. There can
 * be more than one bitmap per file, but none can be split across input files.
 * Each bitmap goes on a page by itself.
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

	    case 'b':			/* bytes per pattern */
		    bytespp = atoi(optarg);
		    break;

	    case 'c':			/* copies */
		    copies = atoi(optarg);
		    fprintf(stdout, "/#copies %s store\n", optarg);
		    break;

	    case 'f':			/* ones complement - sort of */
		    flip = TRUE;
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

	    case 'u':			/* don't undo Eighth Edition bitmaps */
		    v8undo = FALSE;
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

    if ( formsperpage > 1 )  {		/* followed by stuff for multiple pages */
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
    FILE	*fp;			/* next input file */

/*
 *
 * Makes sure all the non-option command line arguments are processed. If we get
 * here and there aren't any arguments left, or if '-' is one of the input files
 * we'll process stdin.
 *
 */


    if ( argc < 1 )
	bitmap(stdin);
    else  {				/* at least one argument is left */
	while ( argc > 0 )  {
	    if ( strcmp(*argv, "-") == 0 )
		fp = stdin;
	    else if ( (fp = fopen(*argv, "r")) == NULL )
		error(FATAL, "can't open %s", *argv);
	    bitmap(fp);
	    if ( fp != stdin )
		fclose(fp);
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
    fprintf(stdout, "%s 0 0 %d %d\n", BOUNDINGBOX, (bbox[0]*72+100)/100, (bbox[1]*72+100)/100);
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
bitmap(FILE *fp)
    /* next input file */
{
    int		count;			/* pattern repeats this many times */
    long	total;			/* expect this many patterns */

/*
 *
 * Reads all the bitmaps from the next input file, translates each one into
 * PostScript, and arranges to have one bitmap printed on each page. Multiple
 * bitmaps per input file work.
 *
 */


    fp_in = fp;				/* everyone reads from this file */

    while ( dimensions() == TRUE )  {
	patcount = 0;
	total = scanlines * patterns;

	bbox[0] = MAX(bbox[0], patterns*16);	/* for BoundingBox comment */
	bbox[1] = MAX(bbox[1], scanlines);

	redirect(++page);
	fprintf(fp_out, "%s %d %d\n", PAGE, page, printed+1);
	fprintf(fp_out, "save\n");
	writerequest(printed+1, fp_out);

	fprintf(fp_out, "%s ", (v8format == TRUE && v8undo == FALSE) ? "true" : "false");
	fprintf(fp_out, "%s ", (flip == TRUE) ? "true" : "false");
	fprintf(fp_out, "%d %d bitmap\n", patterns * 16, scanlines);

	while ( patcount != total && (count = getc(fp)) != EOF )  {
	    addrast(count);
	    patcount += (count & 0177);
	    if ( patcount % patterns == 0 )
		putrast();
	}   /* End while */

	if ( debug == ON )
	    fprintf(stderr, "patterns = %d, scanlines = %d, patcount = %d\n", patterns, scanlines, patcount);

	if ( total != patcount )
	    error(FATAL, "bitmap format error");

	if ( fp_out == stdout ) printed++;

	fprintf(fp_out, "showpage\n");
	fprintf(fp_out, "restore\n");
	fprintf(fp_out, "%s %d %d\n", ENDPAGE, page, printed);
    }	/* End while */

}   /* End of bitmap */


/*****************************************************************************/

static int
dimensions(void)
{
    int		ox, oy;			/* coordinates of the origin */
    int		cx, cy;			/* and right corner of the bitmap */
    int		i;			/* loop index */

/*
 *
 * Determines the dimensions and type of the next bitmap. Eighth edition bitmaps
 * have a zero in the first 16 bits. If valid dimensions are read TRUE is returned
 * to the caller. Changed so the check of whether we're done (by testing scanlines
 * or patterns) comes before the malloc().
 *
 */


    if ( (scanlines = getint()) == 0 )  {
	ox = getint();
	oy = getint();
	cx = getint();
	cy = getint();
	scanlines = cy - oy;
	patterns = (cx - ox + 15) / 16;
	v8format = TRUE;
    } else patterns = getint();

    if ( scanlines <= 0 || patterns <= 0 )	/* done - don't do the malloc() */
	return(FALSE);

    if ( raster != NULL ) free(raster);
    if ( prevrast != NULL ) free(prevrast);

    if ( (rptr = raster = (char *) malloc(patterns * 2)) == NULL )
	error(FATAL, "no memory");

    if ( (prevrast = (char *) malloc(patterns * 2)) == NULL )
	error(FATAL, "no memory");

    for ( i = 0; i < patterns * 2; i++ )
	*(prevrast+i) = 0377;

    eptr = rptr + patterns * 2;

    return(TRUE);

}   /* End of dimensions */


/*****************************************************************************/

static void
addrast(int count)
    /* repeat count for next pattern */
{
    int		size;			/* number of bytes in next pattern */
    int		l, h;			/* high and low bytes */
    int		i, j;			/* loop indices */

/*
 *
 * Reads the input file and adds the appropriate number of bytes to the output
 * raster line. If count has bit 7 on, one 16 bit pattern is read and repeated
 * count & 0177 times. If bit 7 is off, count is the number of patterns read from
 * fp_in - each one repeated once.
 *
 */


    if ( count & 0200 )  {
	size = 1;
	count &= 0177;
    } else {
	size = count;
	count = 1;
    }	/* End else */

    for ( i = size; i > 0; i-- )  {
	if ( (l = getc(fp_in)) == EOF || (h = getc(fp_in)) == EOF )
	    return;
	for ( j = count; j > 0; j-- )  {
	    *rptr++ = l;
	    *rptr++ = h;
	}   /* End for */
    }	/* End for */

}   /* End of addrast */


/*****************************************************************************/

static void
putrast(void)
{
    char	*p1, *p2;		/* starting and ending patterns */
    int		n;			/* set to bytes per pattern */
    int		i;			/* loop index */

/*
 *
 * Takes the scanline that's been saved in *raster, encodes it according to the
 * value that's been assigned to bytespp, and writes the result to *fp_out. Each
 * line in the output bitmap is terminated by a 0 on a line by itself.
 *
 */


    n = (bytespp <= 0) ? 2 * patterns : bytespp;

    if ( v8format == TRUE && v8undo == TRUE )
	for ( i = 0; i < patterns * 2; i++ )
	    *(raster+i) = (*(prevrast+i) ^= *(raster+i));

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

}   /* End of putrast */


/*****************************************************************************/

static int
patncmp(char *p1, int n)
    /* p1 - first patterns starts here */
    /* n - and extends this many bytes */
{
    char	*p2;			/* address of the second pattern */

/*
 *
 * Compares the two n byte patterns *p1 and *(p1+n). FALSE is returned if they're
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

static int
getint(void)
{
    int		h, l;			/* high and low bytes */

/*
 *
 * Reads the next two bytes from *fp_in and returns the resulting integer.
 *
 */


    if ( (l = getc(fp_in)) == EOF || (h = getc(fp_in)) == EOF )
	return(-1);

    return((h & 0377) << 8 | (l & 0377));

}   /* End of getint */


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
