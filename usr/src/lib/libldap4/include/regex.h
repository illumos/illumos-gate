/*
 *
 * Portions Copyright 1998 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#if defined( MACOS ) || defined( DOS ) || defined( _WIN32 ) || defined( NEED_BSDREGEX )
/*
 * Copyright (c) 1993 Regents of the University of Michigan.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that this notice is preserved and that due credit is given
 * to the University of Michigan at Ann Arbor. The name of the University
 * may not be used to endorse or promote products derived from this
 * software without specific prior written permission. This software
 * is provided ``as is'' without express or implied warranty.
 */
/*
 * regex.h -- includes for regular expression matching routines
 * 13 August 1993 Mark C Smith
 */

#ifdef __cplusplus
extern "C" {
#endif

#if !defined( NEEDPROTOS ) && defined( __STDC__ )
#define NEEDPROTOS
#endif

#ifdef NEEDPROTOS
char *re_comp( char *pat );
int re_exec( char *lp );
void re_modw( char *s );
int re_subs( char *src, char *dst );
#else /* NEEDPROTOS */
char *re_comp();
int re_exec();
void re_modw();
int re_subs();
#endif /* NEEDPROTOS */

#define re_fail( m, p )

#ifdef __cplusplus
}
#endif
#endif /* MACOS or DOS or NEED_BSDREGEX */
