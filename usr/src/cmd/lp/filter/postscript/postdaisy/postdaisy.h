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
 * Definitions used by the PostScript translator for Diablo 1640 files.
 *
 * Diablo printers have horizontal and vertical resolutions of 120 and 48 dpi.
 * We'll use a single resolution of 240 dpi and let the program scale horizontal
 * and vertical positions by HSCALE and VSCALE.
 *
 */

#define RES		240
#define HSCALE		2
#define VSCALE		5

/*
 *
 * HMI is the default character spacing and VMI is the line spacing. Both values
 * are in terms of the 240 dpi resolution.
 *
 */

#define HMI		(12 * HSCALE)
#define VMI		(8 * VSCALE)

/*
 *
 * Paper dimensions don't seem to be all that important. They're just used to
 * set the right and bottom margins. Both are given in terms of the 240 dpi
 * resolution.
 *
 */

#define LEFTMARGIN	0
#define RIGHTMARGIN	3168
#define TOPMARGIN	0
#define BOTTOMMARGIN	2640

/*
 *
 * ROWS and COLUMNS set the dimensions of the horizontal and vertical tab arrays.
 * The way I've implemented both kinds of tabs leaves something to be desired, but
 * it was simple and should be good enough for now. If arrays are going to be used
 * to mark tab stops I probably should use malloc() to get enough space once the
 * initial hmi and vmi are know.
 *
 */

#define ROWS		400
#define COLUMNS		200

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
 * Some of the non-integer functions in postdaisy.c.
 *
 */

char	*get_font();

