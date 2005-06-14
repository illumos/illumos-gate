/*
 * Copyright (c) 1996 by Sun Microsystems, Inc.
 * All Rights Reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Define string ops: strchr strrchr memcmp memmove memset 
 */

#ifndef  _ntp_string_h
#define  _ntp_string_h

#ifdef HAVE_MEMORY_H
# include <memory.h>
#endif

#ifdef HAVE_STRING_H
# include <string.h>
#endif

#ifndef STDC_HEADERS
# ifndef HAVE_STRCHR
#  include <strings.h>
#  define strchr index
#  define strrchr rindex
# endif
# ifndef __GNUC__
char *strchr(), *strrchr();
# endif
# ifndef HAVE_MEMCPY
#  define NTP_NEED_BOPS
# endif
#endif /* STDC_HEADERS */

#ifdef NTP_NEED_BOPS
# define memcmp(a,b,c) bcmp(a,b,c)
# define memmove(t,f,c) bcopy(f,t,c)
# define memset(a,x,c) if (x == 0x00) bzero(a,c); else ntp_memset((char*)a,x,c)
void ntp_memset P((char *, int, int));

#endif /*  NTP_NEED_BOPS */

#endif /* _ntp_string_h */
