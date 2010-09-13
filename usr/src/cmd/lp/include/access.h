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
 * Copyright 1993 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.7	*/

#if	!defined(_LP_ACCESS_H)
#define	_LP_ACCESS_H

#include "stdio.h"

/*
 * To speed up reading in each allow/deny file, ACC_MAX_GUESS slots
 * will be preallocated for the internal copy. If these files
 * are expected to be substantially larger than this, bump it up.
 */
#define ACC_MAX_GUESS	100

int	allow_form_printer ( char **, char * );
int	allow_user_form ( char ** , char * );
int	allow_user_printer ( char **, char * );
int	allowed ( char *, char **, char ** );
int	deny_form_printer ( char **, char * );
int	deny_user_form ( char ** , char * );
int	deny_user_printer ( char **, char * );
int	dumpaccess ( char *, char *, char *, char ***, char *** );
int	is_form_allowed_printer ( char *, char * );
int	is_user_admin ( void );
int	is_user_allowed ( char *, char ** , char ** );
int	is_user_allowed_form ( char *, char * );
int	is_user_allowed_printer ( char *, char * );
int	load_formprinter_access ( char *, char ***, char *** );
int	load_paperprinter_access(char *, char ***, char ***);
int	load_userform_access ( char *, char ***, char *** );
int	load_userprinter_access ( char *, char ***, char *** );
int	loadaccess ( char *, char *, char *, char ***, char *** );
int	bangequ ( char * , char * );
int	bang_searchlist ( char * , char ** );
int	bang_dellist ( char *** , char * );

char *	getaccessfile ( char *, char *, char *, char * );

#endif
