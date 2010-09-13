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
/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/


#ifndef _REGEXPR_H
#define	_REGEXPR_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.1.3.1 */

#ifdef	__cplusplus
extern "C" {
#endif

#define	NBRA 9
#ifdef	_REENTRANT
extern char **___braslist();
#define	braslist (___braslist())
extern char **___braelist();
#define	braelist (___braelist())
extern int *___nbra();
#define	nbra (*(___nbra()))
extern int *___regerrno();
#define	regerrno (*(___regerrno()))
extern int *___reglength();
#define	reglength (*(___reglength()))
extern char **___loc1();
#define	loc1 (*(___loc1()))
extern char **___loc2();
#define	loc2 (*(___loc2()))
extern char **___locs();
#define	locs (*(___locs()))
#else
extern char	*braslist[NBRA];
extern char	*braelist[NBRA];
extern int nbra, regerrno, reglength;
extern char *loc1, *loc2, *locs;
#endif
#ifdef	__STDC__
extern int step(const char *string, const char *expbuf);
extern int advance(const char *string, const char *expbuf);
extern char *compile(const char *instring, char *expbuf, char *endbuf);
#else
extern int step();
extern int advance();
extern char *compile();
#endif	/* __STDC__ */

#ifdef	__cplusplus
}
#endif

#endif	/* _REGEXPR_H */
