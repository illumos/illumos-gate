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

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.5	*/

#if	!defined(_LP_FORM_H)
#define	_LP_FORM_H

/**
 ** The disk copy of the form files:
 **/

/*
 * There are 10 fields in the form configuration file.
 */
# define FO_MAX		10
# define FO_PLEN	0
# define FO_PWID	1
# define FO_NP		2
# define FO_LPI		3
# define FO_CPI		4
# define FO_CHSET	5
# define FO_RCOLOR	6
# define FO_CMT	 	7	
# define FO_ALIGN	8	
# define FO_PAPER	9	

/**
 ** The internal copy of a form as seen by the rest of the world:
 **/

typedef struct FORM {
	SCALED			plen;
	SCALED			pwid;
	SCALED			lpi;
	SCALED			cpi;
	int			np;
	char *			chset;
	short			mandatory;
	char *			rcolor;
	char *			comment;
	char *			conttype;
	char *			name;
	char *			paper;
	short			isDefault;
}			FORM;

/*
 * Default configuration values:
 */
#define DPLEN		66
#define DPWIDTH		80
#define DNP		1
#define	DLPITCH		6
#define DCPITCH		10
#define DCHSET		NAME_ANY
#define	DRCOLOR		NAME_ANY
#define DCONTYP		NAME_SIMPLE
#define ENDENV		"#ENDOF_ENV\n"
#define MANSTR		"mandatory"
#define DFTSTR		"default"

/*
 * These are the filenames that may be used for storing a form
 */
#define DESCRIBE	"describe"
#define COMMENT		"comment"
#define ALIGN_PTRN	"align_ptrn"
#define ALERTSH		"alert.sh"
#define ALERTVARS	"alert.vars"

#define err_hndlr	int (*)( int , int , int )

int		delform ( char * );
int		getform ( char * , FORM * , FALERT * , FILE ** );
int		putform ( char * , FORM * , FALERT * , FILE ** );
int		rdform ( char * , FORM * , int , err_hndlr , int * );
int		wrform ( char * , FORM * , int , err_hndlr , int * );

void		freeform ( FORM * );

#undef	err_hndlr

#endif
