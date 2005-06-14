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
 * Copyright 1999 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.9	*/


#if	!defined(_LP_OAM_H)
# define	_LP_OAM_H
/*
 * Change the following lines to include the appropriate
 * standard header file when it becomes available.
 * Or change all the LP source to include it directly,
 * and get rid of the following stuff (up to the ====...==== line).
 */

char *agettxt(long msg_id, char *buf, int buflen);

void fmtmsg(char * label, int severity, char * text, char * action);

/*
 * Possible values of "severity":
 */
#define	MIN_SEVERITY	0
#define	HALT		0
#define	ERROR		1
#define	WARNING		2
#define	INFO		3
#define	MAX_SEVERITY	3

/**======================================================================
 **
 ** LP Spooler specific error message handling.
 **/

#define	MSGSIZ		512

#if	defined(WHO_AM_I)

#include "oam_def.h"

#if	WHO_AM_I == I_AM_CANCEL
static char		*who_am_i = "UX:cancel";

#elif	WHO_AM_I == I_AM_COMB
static char		*who_am_i = "UX:comb           ";
				  /* changed inside pgm */

#elif	WHO_AM_I == I_AM_LPMOVE
static char		*who_am_i = "UX:lpmove";

#elif	WHO_AM_I == I_AM_LPUSERS
static char		*who_am_i = "UX:lpusers";

#elif	WHO_AM_I == I_AM_LPNETWORK
static char		*who_am_i = "UX:lpnetwork";

#elif	WHO_AM_I == I_AM_LP
static char		*who_am_i = "UX:lp";

#elif	WHO_AM_I == I_AM_LPADMIN
static char		*who_am_i = "UX:lpadmin";

#elif	WHO_AM_I == I_AM_LPFILTER
static char		*who_am_i = "UX:lpfilter";

#elif	WHO_AM_I == I_AM_LPFORMS
static char		*who_am_i = "UX:lpforms";

#elif	WHO_AM_I == I_AM_LPPRIVATE
static char		*who_am_i = "UX:lpprivate";

#elif	WHO_AM_I == I_AM_LPSCHED
static char		*who_am_i = "UX:lpsched";

#elif	WHO_AM_I == I_AM_LPSHUT
static char		*who_am_i = "UX:lpshut";

#elif	WHO_AM_I == I_AM_LPSTAT
static char		*who_am_i = "UX:lpstat";

#elif	WHO_AM_I == I_AM_LPSYSTEM
static char		*who_am_i = "UX:lpsystem";

#else
static char		*who_am_i = "UX:mysterious";

#endif

/*
 * Simpler interfaces to the "fmtmsg()" and "agettxt()" stuff.
 */

#if	defined(lint)

#define LP_ERRMSG(C,X)			(void)printf("", C, X)
#define LP_ERRMSG1(C,X,A)		(void)printf("", C, X, A)
#define LP_ERRMSG2(C,X,A1,A2)		(void)printf("", C, X, A1, A2)
#define LP_ERRMSG3(C,X,A1,A2,A3)	(void)printf("", C, X, A1, A2, A3)

#else

#define	LP_ERRMSG(C,X) \
			fmtmsg ( \
				who_am_i, \
				C, \
				agettxt((X), _m_, MSGSIZ), \
				agettxt((X+1), _a_, MSGSIZ) \
			)
#define	LP_ERRMSG1(C,X,A) \
			fmtmsg ( \
				who_am_i, \
				C, \
				fmt1((X), A), \
				agettxt((X+1), _a_, MSGSIZ) \
			)
#define	LP_ERRMSG2(C,X,A1,A2) \
			fmtmsg ( \
				who_am_i, \
				C, \
				fmt2((X), A1, A2), \
				agettxt((X+1), _a_, MSGSIZ) \
			)
#define	LP_ERRMSG3(C,X,A1,A2,A3) \
			fmtmsg ( \
				who_am_i, \
				C, \
				fmt3((X), A1, A2, A3), \
				agettxt((X+1), _a_, MSGSIZ) \
			)


#define	vsnp		(void)snprintf

#define fmt1(X,A)	(vsnp(_m_, MSGSIZ, agettxt((X),_f_,MSGSIZ), A), _m_)
#define fmt2(X,A,B)	(vsnp(_m_, MSGSIZ, agettxt((X),_f_,MSGSIZ), A,B), _m_)
#define fmt3(X,A,B,C)	(vsnp(_m_, MSGSIZ, agettxt((X),_f_,MSGSIZ), A,B,C), _m_)

#endif	/* lint */

extern char		_m_[],
			_a_[],
			_f_[],
			*_t_;

#endif	/* WHO_AM_I */

#endif
