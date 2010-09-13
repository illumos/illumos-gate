/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_PRIVATE_H
#define	_PRIVATE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This file is in the public domain, so clarified as of
 * June 5, 1996 by Arthur David Olson (arthur_david_olson@nih.gov).
 */

/*
 * This header is for use ONLY with the time conversion code.
 * There is no guarantee that it will remain unchanged,
 * or that it will remain at all.
 * Do NOT copy it to any system include directory.
 * Thank you!
 */

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Nested includes
 */
#include <sys/types.h>	/* for time_t */
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <limits.h>	/* for CHAR_BIT */
#include <time.h>
#include <stdlib.h>
#include <libintl.h>	/* for F_OK and R_OK */
#include <unistd.h>
#include <sys/wait.h>

/* static char	privatehid[] = "@(#)private.h	7.55"; */

#define	GRANDPARENTED	"Local time zone must be set--see zic manual page"

/* Unlike <ctype.h>'s isdigit, this also works if c < 0 | c > UCHAR_MAX.  */
#define	is_digit(c)		((unsigned)(c) - '0' <= 9)

/*
 * Private function declarations.
 */
char 	*icatalloc(char *old, const char *new);
char 	*icpyalloc(const char *string);
char 	*imalloc(int n);
void 	*irealloc(void *pointer, int size);
void	ifree(char *pointer);
const char	*scheck(const char *string, const char *format);

/*
 * Finally, some convenience items.
 */

#ifndef TRUE
#define	TRUE	1
#endif /* !defined TRUE */

#ifndef FALSE
#define	FALSE	0
#endif /* !defined FALSE */

#ifndef TYPE_BIT
#define	TYPE_BIT(type)	(sizeof (type) * CHAR_BIT)
#endif /* !defined TYPE_BIT */

#ifndef TYPE_SIGNED
#define	TYPE_SIGNED(type) (((type) -1) < 0)
#endif /* !defined TYPE_SIGNED */

/*
 * INITIALIZE(x)
 */

#ifndef INITIALIZE
#ifdef lint
#define	INITIALIZE(x)	((x) = 0)
#endif /* defined lint */
#ifndef lint
#define	INITIALIZE(x)
#endif /* !defined lint */
#endif /* !defined INITIALIZE */

#ifdef	__cplusplus
}
#endif

#endif	/* _PRIVATE_H */
