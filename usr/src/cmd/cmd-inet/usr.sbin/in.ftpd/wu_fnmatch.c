#pragma ident	"%Z%%M%	%I%	%E% SMI"

/****************************************************************************    
  Copyright (c) 1999,2000 WU-FTPD Development Group.  
  All rights reserved.
   
  Portions Copyright (c) 1980, 1985, 1988, 1989, 1990, 1991, 1993, 1994  
    The Regents of the University of California. 
  Portions Copyright (c) 1993, 1994 Washington University in Saint Louis.  
  Portions Copyright (c) 1996, 1998 Berkeley Software Design, Inc.  
  Portions Copyright (c) 1989 Massachusetts Institute of Technology.  
  Portions Copyright (c) 1998 Sendmail, Inc.  
  Portions Copyright (c) 1983, 1995, 1996, 1997 Eric P.  Allman.  
  Portions Copyright (c) 1997 by Stan Barber.  
  Portions Copyright (c) 1997 by Kent Landfield.  
  Portions Copyright (c) 1991, 1992, 1993, 1994, 1995, 1996, 1997  
    Free Software Foundation, Inc.    
   
  Use and distribution of this software and its source code are governed   
  by the terms and conditions of the WU-FTPD Software License ("LICENSE").  
   
  If you did not receive a copy of the license, it may be obtained online  
  at http://www.wu-ftpd.org/license.html.  
   
  $Id: wu_fnmatch.c,v 1.7 2000/10/25 20:18:13 wuftpd Exp $  
   
****************************************************************************/
/*
 * Function fnmatch() as specified in POSIX 1003.2-1992, section B.6.
 * Compares a filename or pathname to a pattern.
 */

#include <ctype.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

typedef int boolean;
#define FALSE 0
#define TRUE  1

#include "wu_fnmatch.h"

#define	EOS '\0'

static const char *rangematch(const char *pattern, const char *string, int flags)
{
/*
 * A bracket expression starting with an unquoted circumflex character
 * produces unspecified results (IEEE 1003.2-1992, 3.13.2).  This
 * implementation treats it like '!', for consistency with the regular
 * expression syntax.  J.T. Conklin (conklin@ngai.kaleida.com)
 */
    char test = *string;
    boolean negate = ((*pattern == '!') || (*pattern == '^'));
    boolean ok = FALSE;
    if (negate)
	++pattern;
    if (flags & FNM_CASEFOLD)
	test = tolower((unsigned char) test);
    while (*pattern != ']') {
	char c = *pattern++;
	if ((c == '\\') && !(flags & FNM_NOESCAPE))
	    c = *pattern++;
	if (c == EOS)
	    return (NULL);
	if (flags & FNM_CASEFOLD)
	    c = tolower((unsigned char) c);
	if (*pattern == '-') {
	    char c2 = pattern[1];
	    if ((c2 != EOS)
		&& (c2 != ']')) {
		pattern += 2;
		if ((c2 == '\\') && !(flags & FNM_NOESCAPE))
		    c2 = *pattern++;
		if (c2 == EOS)
		    return (NULL);
		if (flags & FNM_CASEFOLD)
		    c2 = tolower((unsigned char) c2);
		/* this is a hack */
		if ((c <= test) && (test <= c2))
		    ok = TRUE;
	    }
	    else if (c == test)
		ok = TRUE;
	}
	else if (c == test)
	    ok = TRUE;
    }
    return ((ok == negate) ? NULL : pattern+1);
}

int wu_fnmatch(const char *pattern, const char *string, int flags)
{
    const char *stringstart = string;
    if ((pattern == NULL) || (string == NULL))
	return FNM_NOMATCH;
    while (TRUE) {
	char test;
	char c = *pattern++;
	switch (c) {
	case EOS:
#ifdef FNM_LEADING_DIR
	    if ((flags & FNM_LEADING_DIR)
		&& (*string == '/'))
		return (0);
	    /*
	     * WU-FTPD extension/correction.
	     *
	     * If the pattern ended with a '/', and we're doing
	     * FNM_PATHNAME matching, consider it a match if the
	     * previous string character was a '/' and the current
	     * is not a '/'.
	     */
	    if ((flags & FNM_LEADING_DIR)
		&& (string != stringstart)
		&& (flags & FNM_PATHNAME)
		&& (*(string - 1) == '/'))
		return (0);
#endif
	    return ((*string == EOS) ? 0 : FNM_NOMATCH);
	case '?':
	    if (*string == EOS)
		return (FNM_NOMATCH);
	    if ((*string == '/')
		&& (flags & FNM_PATHNAME))
		return (FNM_NOMATCH);
	    if ((*string == '.')
		&& (flags & FNM_PERIOD)
		&& ((string == stringstart)
		    || ((flags & FNM_PATHNAME)
			&& (*(string - 1) == '/'))))
		return (FNM_NOMATCH);
	    ++string;
	    break;
	case '*':
	    c = *pattern;
	    while (c == '*')
		c = *++pattern;
	    if ((*string == '.')
		&& (flags & FNM_PERIOD)
		&& ((string == stringstart)
		    || ((flags & FNM_PATHNAME)
			&& (*(string - 1) == '/'))))
		return (FNM_NOMATCH);
	    /* Optimize for pattern with * at end or before /. */
	    if (c == EOS)
		if (flags & FNM_PATHNAME) {
#ifdef FNM_LEADING_DIR
		    if (flags & FNM_LEADING_DIR)
			return (0);
#endif
		    return ((strchr(string, '/') == NULL) ? 0 : FNM_NOMATCH);
		}
		else
		    return (0);
	    else if ((c == '/')
		     && (flags & FNM_PATHNAME)) {
		string = strchr(string, '/');
		if (string == NULL)
		    return (FNM_NOMATCH);
		break;
	    }
	    /* General case, use recursion. */
	    for (test = *string; test != EOS; test = *++string) {
		if (!wu_fnmatch(pattern, string, (flags & ~FNM_PERIOD)))
		    return (0);
		if ((test == '/')
		    && (flags & FNM_PATHNAME))
		    break;
	    }
	    return (FNM_NOMATCH);
	case '[':
	    if (*string == EOS)
		return (FNM_NOMATCH);
	    if ((*string == '/')
		&& (flags & FNM_PATHNAME))
		return (FNM_NOMATCH);
	    pattern = rangematch(pattern, string, flags);
	    if (pattern == NULL)
		return (FNM_NOMATCH);
	    ++string;
	    break;
	case '\\':
	    if (!(flags & FNM_NOESCAPE)) {
		c = *pattern++;
		if (c == EOS) {
		    c = '\\';
		    --pattern;
		}
	    }
	    /* FALLTHROUGH */
	default:
	    if (c == *string);
#ifdef FNM_CASEFOLD
	    else if ((flags & FNM_CASEFOLD)
		     && (tolower((unsigned char) c) == tolower((unsigned char) *string)));
#endif
	    else
		return (FNM_NOMATCH);
	    string++;
	    break;
	}
    }
/* NOTREACHED */
}
