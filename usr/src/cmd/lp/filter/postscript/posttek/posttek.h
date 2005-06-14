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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.1	*/

/*
 *
 * Definitions used by the PostScript translator for tektronix 4014 files.
 *
 */

#define NUL '\000'
#define SOH '\001'
#define STX '\002'
#define ETX '\003'
#define EOT '\004'
#define ENQ '\005'
#define ACK '\006'
#define BEL '\007'
#define BS  '\010'
#define HT  '\011'
#define NL  '\012'
#define VT  '\013'
#define FF  '\014'
#define CR  '\015'
#define SO  '\016'
#define SI  '\017'
#define DLE '\020'
#define DC1 '\021'
#define DC2 '\022'
#define DC3 '\023'
#define DC4 '\024'
#define NAK '\025'
#define SYN '\026'
#define ETB '\027'
#define CAN '\030'
#define EM  '\031'
#define SUB '\032'
#define ESC '\033'
#define FS  '\034'
#define GS  '\035'
#define RS  '\036'
#define US  '\037'
#define DEL '\177'

/*
 *
 * A few definitions used to classify the different tektronix states. OUTMODED
 * is returned by control() and esc(), and typically means the state has changed.
 *
 */

#define OUTMODED	-1
#define ALPHA		0
#define GIN		1
#define GRAPH		2
#define POINT		3
#define SPECIALPOINT	4
#define INCREMENTAL	5
#define RESET		6
#define EXIT		7

/*
 *
 * The pen state, either UP or DOWN, controls whether vectors are drawn.
 *
 */

#define UP		0
#define DOWN		1

/*
 *
 * Coordinates of the upper right corner of the screen - almost the real screen
 * dimensions.
 *
 */

#define TEKXMAX		4096
#define TEKYMAX		3120

/*
 *
 * The size of the spot in SPECIALPOINT mode is controlled by a non-linear
 * function that has a domain that consists of the integers from 040 to 0175.
 * The next definition is used to initialize the special point mode intensity
 * array that implements the function. Data came from table F-6 in the tektronix
 * 4014 manual.
 *
 */

#define INTENSITY							\
									\
	{								\
	    14, 16, 17, 19, 20, 22, 23, 25,				\
	    28, 31, 34, 38, 41, 44, 47, 50,				\
	    56, 62, 69, 75, 81, 88, 94,100,				\
	    56, 62, 69, 75, 81, 88, 94,100,				\
	     0,  1,  1,  1,  1,  1,  1,  2,				\
	     2,  2,  2,  2,  3,  3,  3,  3,				\
	     4,  4,  4,  5,  5,  5,  6,  6,				\
	     7,  8,  9, 10, 11, 12, 12, 13,				\
	    14, 16, 17, 19, 20, 22, 23, 25,				\
	    28, 31, 34, 38, 41, 44, 47, 50,				\
	    56, 62, 69, 75, 81, 88, 94,100,				\
	    56, 62, 69, 75, 81, 88, 94,100,				\
	}

/*
 *
 * The next two definitions give the height and width of characters in the four
 * different sizes available on tektronix terminals. TEKFONT is the default index
 * into CHARHEIGHT and CHARWIDTH.
 *
 */

#define CHARHEIGHT	{88, 82, 53, 48}
#define CHARWIDTH	{56, 51, 34, 31}
#define TEKFONT		2

/*
 *
 * The entries defined in STYLES are passed on to the PostScript operator setdash.
 * They're used to implement the different tektronix line styles. Belongs in the
 * prologue!
 *
 */

#define STYLES								\
									\
	{								\
	    "[]",							\
	    "[.5 2]",							\
	    "[.5 2 4 2]",						\
	    "[4 4]",							\
	    "[8 4]",							\
	    "[]"							\
	}

/*
 *
 * Variables of type Point are used to keep track of the cursor position.
 *
 */

typedef struct {

	int	x;
	int	y;

} Point;

/*
 *
 * An array of type Fontmap helps convert font names requested by users into
 * legitimate PostScript names. The array is initialized using FONTMAP, which must
 * end with an entry that has NULL defined as its name field.
 *
 */

typedef struct {

	char	*name;			/* user's font name */
	char	*val;			/* corresponding PostScript name */

} Fontmap;

#define FONTMAP								\
									\
	{								\
	    "R", "Courier",						\
	    "I", "Courier-Oblique",					\
	    "B", "Courier-Bold",					\
	    "CO", "Courier",						\
	    "CI", "Courier-Oblique",					\
	    "CB", "Courier-Bold",					\
	    "CW", "Courier",						\
	    "PO", "Courier",						\
	    "courier", "Courier",					\
	    "cour", "Courier",						\
	    "co", "Courier",						\
	    NULL, NULL							\
	}

/*
 *
 * Some of the non-integer valued functions in posttek.c.
 *
 */

char	*get_font();

