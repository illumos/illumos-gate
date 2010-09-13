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
 * Copyright 1997 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * define unctrl codes for each character
 *
 */

/* LINTLIBRARY */
char	*_unctrl[]	= {	/* unctrl codes for ttys		*/
	"^@", "^A", "^B", "^C", "^D", "^E", "^F", "^G", "^H", "^I", "^J", "^K",
	"^L", "^M", "^N", "^O", "^P", "^Q", "^R", "^S", "^T", "^U", "^V", "^W",
	"^X", "^Y", "^Z", "^[", "^\\", "^]", "^~", "^_",
	" ", "!", "\"", "#", "$",  "%", "&", "'", "(", ")", "*", "+", ",", "-",
	".", "/", "0",  "1", "2",  "3", "4", "5", "6", "7", "8", "9", ":", ";",
	"<", "=", ">",  "?", "@",  "A", "B", "C", "D", "E", "F", "G", "H", "I",
	"J", "K", "L",  "M", "N",  "O", "P", "Q", "R", "S", "T", "U", "V", "W",
	"X", "Y", "Z",  "[", "\\", "]", "^", "_", "`", "a", "b", "c", "d", "e",
	"f", "g", "h",  "i", "j",  "k", "l", "m", "n", "o", "p", "q", "r", "s",
	"t", "u", "v",  "w", "x",  "y", "z", "{", "|", "}", "~", "^?"
#ifdef DEBUG
	,
	"M-^@", "M-^A", "M-^B", "M-^C", "M-^D", "M-^E", "M-^F", "M-^G",
	"M-^H", "M-^I", "M-^J", "M-^K", "M-^L", "M-^M", "M-^N", "M-^O",
	"M-^P", "M-^Q", "M-^R", "M-^S", "M-^T", "M-^U", "M-^V", "M-^W",
	"M-^X", "M-^Y", "M-^Z", "M-^[", "M-^\\", "M-^]", "M-^~", "M-^_",
	"M- ", "M-!", "M-\"", "M-#", "M-$", "M-%", "M-&", "M-'",
	"M-(", "M-)", "M-*", "M-+", "M-,", "M--", "M-.", "M-/",
	"M-0", "M-1", "M-2", "M-3", "M-4", "M-5", "M-6", "M-7",
	"M-8", "M-9", "M-:", "M-;", "M-<", "M-=", "M->", "M-?",
	"M-@", "M-A", "M-B", "M-C", "M-D", "M-E", "M-F", "M-G",
	"M-H", "M-I", "M-J", "M-K", "M-L", "M-M", "M-N", "M-O",
	"M-P", "M-Q", "M-R", "M-S", "M-T", "M-U", "M-V", "M-W",
	"M-X", "M-Y", "M-Z", "M-[", "M-\\", "M-]", "M-^", "M-_",
	"M-`", "M-a", "M-b", "M-c", "M-d", "M-e", "M-f", "M-g",
	"M-h", "M-i", "M-j", "M-k", "M-l", "M-m", "M-n", "M-o",
	"M-p", "M-q", "M-r", "M-s", "M-t", "M-u", "M-v", "M-w",
	"M-x", "M-y", "M-z", "M-{", "M-|", "M-}", "M-~", "M-^?"
#endif /* DEBUG */
};
