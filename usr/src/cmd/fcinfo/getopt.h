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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_GETOPT_H
#define	_GETOPT_H



#ifdef	__cplusplus
extern "C" {
#endif

extern char *optarg;

extern int optind;

extern int opterr;

extern int optopt;


struct option
{
#if defined(__STDC__) && __STDC__
	const char *name;
#else
	char *name;
#endif
	int has_arg;
	int *flag;
	int val;
};


#define	no_argument		0
#define	required_argument	1
#define	optional_argument	2

#if defined(__STDC__) && __STDC__
#if !HAVE_DECL_GETOPT
#if defined(__GNU_LIBRARY__) || defined(HAVE_DECL_GETOPT)
extern int getopt(int argc, char *const *argv, const char *shortopts);
#else
#ifndef __cplusplus
extern int getopt();
#endif /* __cplusplus */
#endif
#endif /* !HAVE_DECL_GETOPT */

extern int getopt_long(int argc, char *const *argv, const char *shortopts,
    const struct option *longopts, int *longind);
extern int getopt_long_only(int argc, char *const *argv,
    const char *shortopts, const struct option *longopts, int *longind);
extern int _getopt_internal(int argc, char *const *argv,
    const char *shortopts, const struct option *longopts, int *longind,
    int long_only);
#else /* not __STDC__ */
extern int getopt();
extern int getopt_long();
extern int getopt_long_only();

extern int _getopt_internal();
#endif /* __STDC__ */

#ifdef	__cplusplus
}
#endif

#endif	/* _GETOPT_H */
