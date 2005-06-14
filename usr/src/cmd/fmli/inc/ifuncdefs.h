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


/*
 * Copyright  (c) 1985 AT&T
 *	All Rights Reserved
 */

#ident	"%Z%%M%	%I%	%E% SMI"       /* SVr4.0 1.1 */

/** This include file contains the indices of the internal object functions
 ** in the table of object functions.  It could also be used to make an
 ** externally defined oot more readable, since many of the internal functions
 ** could be used in such a table.
 **/

/* general operations which pertain to most objects */

#define IF_VI	0	/* viewing init function */
#define IF_SH	1	/* selection handler */
#define IF_CP	2	/* copy */
#define IF_RN	3	/* rename */
#define IF_MV	4	/* move */
#define IF_SC	5	/* scramble */
#define IF_UNSC	6	/* unscramble */
#define IF_RM	7	/* remove */
#define IF_ML	8	/* mail */
#define IF_VF	9	/* view full screen */
#define IF_UNRM	10	/* undelete */
#define IF_SP	11	/* check spelling */

/* read only functions */
#define IF_CPOF	16	/* copy to office files */
/* install functions */
#define IF_INST	18	/* install for news/info */

/* operations pertaining to directories */

#define IF_DED	21	/* directory open */
#define IF_DVI	22	/* directory viewing init */
#define IF_DSH	23	/* directory selection handler */
#define IF_DEX	24	/* directory exit function */
#define IF_DCR	25	/* directory creation function */
#define IF_DRM	26	/* directory deletion function */
#define IF_DRN	27	/* directory rename function */
#define IF_DUNRM	28	/* directory undelete function */
#define IF_DCRDIR 29	/* directory create for browse */
#define IF_DPL	30	/* directory place it here function */
#define IF_DSEL	31	/* directory selection for browsing */
#define IF_DBU	32	/* directory backup for browsing */
#define IF_DMV	33	/* directory move */
#define IF_DCP	34	/* directory copy */

/* operations which are specific to mail directories */

#define IF_MDVI 37 	/* mail directory viewing init */
#define IF_MDSH 38 	/* mail directory selection handler */
#define IF_MDEX 39 	/* mail directory exit function */

/* operations which are specific to ascii files */

#define IF_AEX	43	/* ascii exit */
#define IF_ACV  44  /* ascii convert for viewing*/
#define IF_APR	45	/* ascii print */
#define IF_AED	46	/* ascii edit */

/* operations which are specific to MAIL_IN objects */

#define IF_MICV		50	/* mail_in convert to viewable */
#define IF_MIVI		51	/* mail_in view init */
#define IF_MISH		52	/* mail_in selection handler */
#define IF_MIEX		53	/* mail_in exit function */
#define IF_MISAVE	54	/* mail_in save */
#define IF_MIFILE	55	/* mail_in file a message */
#define IF_MIPRINT	56	/* mail_in print */
#define IF_MIREPLY	57	/* mail_in reply */
#define IF_MIFORWARD	58	/* mail_in annotate and forward */
#define IF_MIDIAL	59	/* mail_in dial number */
#define IF_MIRESEND	60	/* mail_in resend message */

/* operations which are specific to XED_5.028 objects */

#define IF_XEX	64	/* exit function */
#define IF_XCV	65	/* convert for viewing */
#define IF_XED	66	/* edit */
#define IF_XPR	67	/* print */

/* operations which are specific to Structured Files */

#define IF_SEX	71	/* exit function */
#define IF_SCV	72	/* convert for viewing */
#define IF_SED	73	/* edit (modify) */
#define IF_SPR	74	/* print */

/* operations which are specific to MAIL_OUT objects */

#define IF_MOVI		78
#define IF_MOEX		79
#define IF_MOCV		80
#define IF_MOSUBJ	81
#define IF_MOADDR	82
#define IF_MOSEND	83
#define IF_MOSA		84
#define IF_MOSR		85
#define IF_MOPRINT	86
#define IF_MOEDIT	87
#define IF_MOSPELL	88
#define IF_MOBROWSE	89
#define IF_MOBCC	90

/* operations which are specific to Unknown objects */

#define IF_UCV	91	/* unknown convert to viewing*/
#define IF_UEX	92	/* unknown object exit function */

/* operations which are specific to executables */

#define IF_EED	93
#define IF_EXVI	94

/* operations specific to form objects */

#define IF_FRMOPEN	96

/* operations specific to menu objects */

#define IF_MENOPEN	97
#define IF_MENVI	98
#define IF_MENSH	99

/* operations specific to text objects */

#define IF_HLPOPEN	100

/* operations specific to ultracalc */

#define IF_ULED		101

#define IF_BADFUNC	104

#define MAX_IFUNCS 105	/* maximum number of internal functions */
