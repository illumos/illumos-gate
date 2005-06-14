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
 * 
 */

#ident	"%Z%%M%	%I%	%E% SMI"       /* SVr4.0 1.8 */

/* indices for the fcntbl[] array */

#define AR_CLOSE	(0)		/* prepare this record for destruction */
#define AR_NONCUR	(1)		/* make this record noncurrent */
#define AR_CURRENT	(2)		/* make this record current */
#define AR_REREAD	(3)		/* reread this record */
#define AR_CTL		(4)		/* change something about this record */
#define AR_ODSH		(5)		/* handle tokens */
#define AR_REINIT	(6)		/* init during checkworld */
#define AR_HELP		(7)		/* help function */
#define AR_TEMP_CUR	(8)		/* make this record temporarily current */
#define AR_NUMFCN	(9)


struct actrec {
	char	*path;
	int	serial;
	int	id;	/* menu, form, process */
	int	flags;
	int	lifetime;
	char 	*interrupt;	/* abs */
	char    *oninterrupt;	/* abs */
	struct slk	*slks;
	struct actrec	*prevrec;
	struct actrec	*nextrec;
	struct actrec	*backup;

	/* object dependent fields */

	char	*odptr;			/* any structure you want */
	int	(*fcntbl[AR_NUMFCN])();	/* any functions you want */
};

/* lifetimes */

#define AR_SHORTERM	(1)
#define AR_HELPTERM	(2)
#define AR_LONGTERM	(3)
#define AR_PERMANENT	(4)
#define AR_IMMORTAL	(5)
#define AR_INITIAL	(6)
#define AR_CLOSING	(7)	/* abs k17 */

/* flags */

#define AR_SKIP		(1)	/* don't stop here on prev/next wdw */
#define AR_ALTSLKS	(2)	/* use alternate slks by default */
#define AR_NORESHAPE	(4)	/* can't do frm-mgmt "reshape" */

/* macros for calling activation functions */

#define arf_close(X,Y)	(*(X->fcntbl[AR_CLOSE]))(Y)
#define arf_current(X,Y)	(*(X->fcntbl[AR_CURRENT]))(Y)
#define arf_temp_current(X,Y)	(*(X->fcntbl[AR_TEMP_CUR]))(Y)
#define arf_noncur(X,Y)	(*(X->fcntbl[AR_NONCUR]))(Y, TRUE)
#define arf_reread(X,Y)	(*(X->fcntbl[AR_REREAD]))(Y)
#define arf_reinit(X,Y)	(*(X->fcntbl[AR_REINIT]))(Y)
#define arf_odsh(X,Y)	(*(X->fcntbl[AR_ODSH]))(X, Y)
#define arf_help(X,Y)	(*(X->fcntbl[AR_HELP]))(Y)

/* Definitions of standard menu functions */

extern int AR_MEN_CLOSE(), AR_MEN_CURRENT(), AR_MEN_NONCUR(), AR_MEN_CTL(), 
			AR_NOHELP(), AR_NOP();

extern token AR_MEN_ODSH();
