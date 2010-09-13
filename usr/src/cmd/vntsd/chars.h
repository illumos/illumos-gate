
/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _CHARS_H
#define	_CHARS_H

#ifdef __cplusplus
extern "C" {
#endif

#define	CNTRL(c) ((c)&0x37)

#define	    CR	    13
#define	    LF	    10


/* telnet protocol command support */
#define	    BEL	    7	    /* not support */
#define	    BS	    8	    /* supported */
#define	    HT	    9	    /* eoln */
#define	    VT	    11	    /* not support */
#define	    FF	    12	    /* not support */
#define	    STOP    19
#define	    START   17

#define	    SE	    240	    /* end of subnegotiation params */
#define	    NOP	    241
#define	    DM	    242	    /* Data Mark not support */
#define	    BRK	    243	    /* termial support  */
#define	    IP	    244	    /* control-C */
#define	    AO	    245	    /* abort output  not support */
#define	    AYT	    246	    /* Are you there */
#define	    EC	    247	    /* Erase character - not support */
#define	    EL	    248	    /* Erase line   - not support */
#define	    GA	    249	    /* Go ahead. */
#define	    SB	    250	    /* Subnegotiation of the indicated option */
#define	    WILL    251	    /* will do */
#define	    WONT    252	    /* refuse */
#define	    DO	    253	    /* request do */
#define	    DONT    254	    /* request do not do */
#define	    IAC	    255	    /* command */



/* telnet options */

#define	    TEL_ECHO	1
#define	    SUPRESS	3
#define	    STATUS	5
#define	    TM		6	/* timing mark - not supported */
#define	    TERM_TYPE	24	/* Terminal type -not supported */
#define	    WIN_SIZE	31	/*  window size - not supported */
#define	    TERM_SP	32	/* terminal speed - not supported */
#define	    FC		33	/* remote flow control - not supported */
#define	    LINEMODE	34	/* line mode */
#define	    ENV		36	/* environment variables */

#define	    VNTSD_DAEMON_CMD	'~'

#ifdef __cplusplus
}
#endif

#endif /* _CHARS_H */
