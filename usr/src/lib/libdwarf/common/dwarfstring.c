/*
Copyright (c) 2019-2019, David Anderson
All rights reserved.

Redistribution and use in source and binary forms, with
or without modification, are permitted provided that the
following conditions are met:

    Redistributions of source code must retain the above
    copyright notice, this list of conditions and the following
    disclaimer.

    Redistributions in binary form must reproduce the above
    copyright notice, this list of conditions and the following
    disclaimer in the documentation and/or other materials
    provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

/*  A lighly generalized data buffer.
    Works for more than just strings,
    but has features (such as ensuring
    data always has a NUL byte following
    the data area used) most useful for C strings.

    All these return either TRUE (the values altered)
    or FALSE (something went wrong, quite likely
    the caller presented a bad format string for the
    value).
*/

#include "config.h"
#include <stdio.h> /* for malloc */
#ifdef HAVE_STDLIB_H
#include <stdlib.h> /* for malloc */
#endif /* HAVE_STDLIB_H */
#include <string.h> /* for strlen */
#ifdef HAVE_MALLOC_H
/* Useful include for some Windows compilers. */
#include <malloc.h>
#endif /* HAVE_MALLOC_H */
#include "dwarfstring.h"
#ifndef TRUE
#define TRUE 1
#endif /* TRUE */
#ifndef FALSE
#define FALSE 0
#endif /* FALSE */

#ifdef HAVE_UNUSED_ATTRIBUTE
#define  UNUSEDARG __attribute__ ((unused))
#else
#define  UNUSEDARG
#endif


static unsigned long minimumnewlen = 30;
/*
struct dwarfstring_s {
   char *        s_data;
   unsigned long s_size;
   unsigned long s_avail;
   unsigned char s_malloc;
};
*/

int
dwarfstring_constructor(struct dwarfstring_s *g)
{
    g->s_data = "";
    g->s_size = 0;
    g->s_avail = 0;
    g->s_malloc = FALSE;
    return TRUE;
}

static int
dwarfstring_resize_to(struct dwarfstring_s *g,unsigned long newlen)
{
    char *b = 0;
    unsigned long lastpos =
        g->s_size - g->s_avail;
    unsigned long malloclen = newlen+1;

    if(malloclen < minimumnewlen) {
        malloclen = minimumnewlen;
    }
    b = malloc(malloclen);
    if (!b) {
        return FALSE;
    }
    if (lastpos > 0) {
        memcpy(b,g->s_data,lastpos);
    }
    if (g->s_malloc) {
        free(g->s_data);
        g->s_data = 0;
    }
    g->s_data = b;
    g->s_data[lastpos] = 0;
    g->s_size = newlen;
    g->s_avail = newlen - lastpos;
    g->s_malloc = TRUE;
    return TRUE;
}

int
dwarfstring_reset(struct dwarfstring_s *g)
{
    if (!g->s_size) {
        /* In initial condition, nothing to do. */
        return TRUE;
    }
    g->s_avail = g->s_size;
    g->s_data[0] = 0;
    return TRUE;
}

int
dwarfstring_constructor_fixed(struct dwarfstring_s *g,unsigned long len)
{
    int r = FALSE;

    dwarfstring_constructor(g);
    if (len == 0) {
        return TRUE;
    }
    r = dwarfstring_resize_to(g,len);
    if (!r) {
        return FALSE;
    }
    return TRUE;
}

int
dwarfstring_constructor_static(struct dwarfstring_s *g,
    char * space,
    unsigned long len)
{
    dwarfstring_constructor(g);
    g->s_data = space;
    g->s_data[0] = 0;
    g->s_size = len;
    g->s_avail = len;
    g->s_malloc = FALSE;
    return TRUE;
}

void
dwarfstring_destructor(struct dwarfstring_s *g)
{
    if (g->s_malloc) {
        free(g->s_data);
        g->s_data = 0;
        g->s_malloc = 0;
    }
    dwarfstring_constructor(g);
}

/*  For the case where one wants just the first 'len'
    characters of 'str'. NUL terminator provided
    for you in s_data.
*/
int
dwarfstring_append_length(struct dwarfstring_s *g,char *str,
    unsigned long slen)
{
    unsigned long lastpos = g->s_size - g->s_avail;
    int r = 0;

    if (!str  || slen ==0) {
        return TRUE;
    }
    if (slen >= g->s_avail) {
        unsigned long newlen = 0;

        newlen = g->s_size + slen+2;
        r = dwarfstring_resize_to(g,newlen);
        if (!r) {
            return FALSE;
        }
    }
    memcpy(g->s_data + lastpos,str,slen);
    g->s_avail -= slen;
    g->s_data[g->s_size - g->s_avail] = 0;
    return TRUE;
}

int
dwarfstring_append(struct dwarfstring_s *g,char *str)
{
    unsigned long dlen = 0;

    if(!str) {
        return TRUE;
    }
    dlen = strlen(str);
    return dwarfstring_append_length(g,str,dlen);
}

char *
dwarfstring_string(struct dwarfstring_s *g)
{
    return g->s_data;
}

unsigned long
dwarfstring_strlen(struct dwarfstring_s *g)
{
    return g->s_size - g->s_avail;
}

static int
_dwarfstring_append_spaces(dwarfstring *data,
   size_t count)
{
    int res = 0;
    char spacebuf[] = {"                                       "};
    size_t charct = sizeof(spacebuf)-1;
    size_t l = count;

    while (l > charct) {
        res = dwarfstring_append_length(data,spacebuf,charct);
        l -= charct;
        if (res != TRUE) {
            return res;
        }
    }
    /* ASSERT: l > 0 */
    res = dwarfstring_append_length(data,spacebuf,l);
    return res;
}
static int
_dwarfstring_append_zeros(dwarfstring *data, size_t l)
{
    int res = 0;
    static char zeros[] = {"0000000000000000000000000000000000000000"};
    size_t charct = sizeof(zeros)-1;

    while (l > charct) {
        res = dwarfstring_append_length(data,zeros,charct);
        l -= charct;
        if (res != TRUE) {
            return res;
        }
    }
    /* ASSERT: l > 0 */
    dwarfstring_append_length(data,zeros,l);
    return res;
}


int dwarfstring_append_printf_s(dwarfstring *data,
    char *format,char *s)
{
    size_t stringlen = strlen(s);
    size_t next = 0;
    long val = 0;
    char *endptr = 0;
    const char *numptr = 0;
    /* was %[-]fixedlen.  Zero means no len provided. */
    size_t fixedlen = 0;
    /* was %-, nonzero means left-justify */
    long leftjustify = 0;
    size_t prefixlen = 0;
    int res = 0;

    while (format[next] && format[next] != '%') {
        ++next;
        ++prefixlen;
    }
    if (prefixlen) {
        dwarfstring_append_length(data,format,prefixlen);
    }
    if (!format[next]) {
        return TRUE;
    }
    next++;
    if (format[next] == '-') {
        leftjustify++;
        next++;
    }
    numptr = format+next;
    val = strtol(numptr,&endptr,10);
    if ( endptr != numptr) {
        fixedlen = val;
    }
    next = (endptr - format);
    if (format[next] != 's') {
        return FALSE;
    }
    next++;

    if (fixedlen && (stringlen >= fixedlen)) {
        /*  Ignore  leftjustify (if any) and the stringlen
            as the actual string overrides those. */
        leftjustify = 0;
    }
    if (leftjustify) {

        dwarfstring_append_length(data,s,stringlen);
        if(fixedlen) {
            size_t trailingspaces = fixedlen - stringlen;

            _dwarfstring_append_spaces(data,trailingspaces);
        }
    } else {
        if (fixedlen && fixedlen < stringlen) {
            /*  This lets us have fixedlen < stringlen by
                taking all the chars from s*/
            dwarfstring_append_length(data,s,stringlen);
        } else {
            if(fixedlen) {
                size_t leadingspaces = fixedlen - stringlen;
                size_t k = 0;

                for ( ; k < leadingspaces; ++k) {
                    dwarfstring_append_length(data," ",1);
                }
            }
            dwarfstring_append_length(data,s,stringlen);
        }
    }
    if (!format[next]) {
        return TRUE;
    }
    {
        char * startpt = format+next;
        size_t suffixlen = strlen(startpt);

        res = dwarfstring_append_length(data,startpt,suffixlen);
    }
    return res;
}

static char v32m[] = {"-2147483648"};
static char v64m[] = {"-9223372036854775808"};
static char dtable[10] = {
'0','1','2','3','4','5','6','7','8','9'
};
static char xtable[16] = {
'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'
};
static char Xtable[16] = {
'0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'
};

/*  We deal with formats like:
    %d   %5d %05d %+d %+5d %-5d (and ld and lld too). */
int dwarfstring_append_printf_i(dwarfstring *data,
    char *format,
    dwarfstring_i v)
{
    int res = TRUE;
    size_t next = 0;
    long val = 0;
    char *endptr = 0;
    const char *numptr = 0;
    size_t fixedlen = 0;
    int leadingzero = 0;
    int minuscount = 0; /*left justify */
    int pluscount = 0;
    int lcount = 0;
    int ucount = 0;
    int dcount = 0;
    int xcount = 0;
    int Xcount = 0;
    char *ctable = dtable;
    size_t prefixlen = 0;
    int done = 0;

    while (format[next] && format[next] != '%') {
        ++next;
        ++prefixlen;
    }
    dwarfstring_append_length(data,format,prefixlen);
    if (format[next] != '%') {
        /*   No % operator found, we are done */
        return TRUE;
    }
    next++;
    if (format[next] == '-') {
        minuscount++;
        return FALSE;
    }
    if (format[next] == '+') {
        pluscount++;
        next++;
    }
    if (format[next] == '0') {
        leadingzero = 1;
        next++;
    }
    numptr = format+next;
    val = strtol(numptr,&endptr,10);
    if ( endptr != numptr) {
        fixedlen = val;
    }
    next = (endptr - format);
    /*  Following is lx lu or u or llx llu , we take
        all this to mean 64 bits, */
#if defined(_WIN32) && defined(HAVE_NONSTANDARD_PRINTF_64_FORMAT)
    if (format[next] == 'I') {
        /*lcount++;*/
        next++;
    }
    if (format[next] == '6') {
        /*lcount++;*/
        next++;
    }
    if (format[next] == '4') {
        /*lcount++;*/
        next++;
    }
#endif /* HAVE_NONSTANDARD_PRINTF_64_FORMAT */
    if (format[next] == 'l') {
        lcount++;
        next++;
    }
    if (format[next] == 'l') {
        lcount++;
        next++;
    }
    if (format[next] == 'u') {
        ucount++;
        next++;
    }
    if (format[next] == 'd') {
        dcount++;
        next++;
    }
    if (format[next] == 'x') {
        xcount++;
        next++;
    }
    if (format[next] == 'X') {
        Xcount++;
        next++;
    }
    if (format[next] == 's') {
        /* ESBERR("ESBERR_pct_scount_in_i"); */
        return FALSE;
    }
    if (xcount || Xcount) {
        /*  Use the printf_u for %x and the like
            just copying the entire format makes
            it easier for coders to understand
            nothing much was done */
        dwarfstring_append(data,format+prefixlen);
        return FALSE;
    }
    if (!dcount || (lcount >2) ||
        (Xcount+xcount+dcount+ucount) > 1) {
        /* error */
        /* ESBERR("ESBERR_xcount_etc_i"); */
        return FALSE;
    }
    if (pluscount && minuscount) {
        /* We don't allow  format +- */
        return FALSE;
    }
    {
        char digbuf[36];
        char *digptr = digbuf+sizeof(digbuf) -1;
        size_t digcharlen = 0;
        dwarfstring_i remaining = v;
        int vissigned = 0;
        dwarfstring_i divisor = 10;

        *digptr = 0;
        --digptr;
        if (v < 0) {
            vissigned = 1;
            /*  This test is for twos-complement
                machines and would be better done via
                configure with a compile-time check
                so we do not need a size test at runtime. */
            if (sizeof(v) == 8) {
                dwarfstring_u vm = 0x7fffffffffffffffULL;
                if (vm == (dwarfstring_u)~v) {
                    memcpy(digbuf,v64m,sizeof(v64m));
                    digcharlen = sizeof(v64m)-1;
                    digptr = digbuf;
                    done = 1;
                } else {
                    remaining = -v;
                }
            } else if (sizeof(v) == 4) {
                dwarfstring_u vm = 0x7fffffffL;
                if (vm == (dwarfstring_u)~v) {
                    memcpy(digbuf,v32m,sizeof(v32m));
                    digcharlen = sizeof(v32m)-1;
                    digptr = digbuf;
                    done = 1;
                } else {
                    remaining = -v;
                }
            }else {
                /* ESBERR("ESBERR_sizeof_v_i"); */
                /* error */
                return FALSE;
            }
        }
        if(!done) {
            for ( ;; ) {
                dwarfstring_u dig = 0;

                dig = remaining % divisor;
                remaining /= divisor;
                *digptr = ctable[dig];
                digcharlen++;
                if (!remaining) {
                    break;
                }
                --digptr;
            }
            if (vissigned) { /* could check minuscount instead */
                --digptr;
                digcharlen++;
                *digptr = '-';
            } else if (pluscount) {
                --digptr;
                digcharlen++;
                *digptr = '+';
            }
        }
        if (fixedlen > 0) {
            if (fixedlen <= digcharlen) {
                dwarfstring_append_length(data,digptr,digcharlen);
            } else {
                size_t prefixcount = fixedlen - digcharlen;
                if (!leadingzero) {
                    _dwarfstring_append_spaces(data,prefixcount);
                    dwarfstring_append_length(data,digptr,digcharlen);
                } else {
                    if (*digptr == '-') {
                        dwarfstring_append_length(data,"-",1);
                        _dwarfstring_append_zeros(data,prefixcount);
                        digptr++;
                        dwarfstring_append_length(data,digptr,
                            digcharlen-1);
                    } else if (*digptr == '+') {
                        dwarfstring_append_length(data,"+",1);
                        _dwarfstring_append_zeros(data,prefixcount);
                        digptr++;
                        dwarfstring_append_length(data,digptr,
                            digcharlen-1);
                    } else {
                        _dwarfstring_append_zeros(data,prefixcount);
                        dwarfstring_append_length(data,digptr,
                            digcharlen);
                    }
                }
            }
        } else {
            res = dwarfstring_append_length(data,digptr,digcharlen);
        }
    }
    if (format[next]) {
        size_t trailinglen = strlen(format+next);
        res = dwarfstring_append_length(data,format+next,trailinglen);
    }
    return res;
}

#if 0
/*  Counts hex chars. divide by two to get bytes from input
    integer. */
static unsigned
trimleadingzeros(char *ptr,unsigned digits,unsigned keepcount)
{
    char *cp = ptr;
    unsigned leadzeroscount = 0;
    unsigned trimoff = 0;

    for(; *cp; ++cp) {
        if (*cp == '0') {
            leadzeroscount++;
            continue;
        }
    }
    trimoff = keepcount - digits;
    if (trimoff&1) {
        trimoff--;
    }
    return trimoff;
}
#endif /* 0 */

/* With gcc version 5.4.0 20160609  a version using
   const char *formatp instead of format[next]
   and deleting the 'next' variable
   is a few hundredths of a second slower, repeatably.

   We deal with formats like:
   %u   %5u %05u (and ld and lld too).
   %x   %5x %05x (and ld and lld too).  */

int dwarfstring_append_printf_u(dwarfstring *data,
    char *format,
    dwarfstring_u v)
{

    size_t next = 0;
    long val = 0;
    char *endptr = 0;
    const char *numptr = 0;
    size_t fixedlen = 0;
    int leadingzero = 0;
    int lcount = 0;
    int ucount = 0;
    int dcount = 0;
    int xcount = 0;
    int Xcount = 0;
    char *ctable = 0;
    size_t divisor = 0;
    size_t prefixlen = 0;

    while (format[next] && format[next] != '%') {
        ++next;
        ++prefixlen;
    }
    dwarfstring_append_length(data,format,prefixlen);
    if (format[next] != '%') {
        /*   No % operator found, we are done */
        return TRUE;
    }
    next++;
    if (format[next] == '-') {
        /*ESBERR("ESBERR_printf_u - format not supported"); */
        next++;
    }
    if (format[next] == '0') {
        leadingzero = 1;
        next++;
    }
    numptr = format+next;
    val = strtol(numptr,&endptr,10);
    if ( endptr != numptr) {
        fixedlen = val;
    }
    next = (endptr - format);
    /*  Following is lx lu or u or llx llu , we take
        all this to mean 64 bits, */
#if defined(_WIN32) && defined(HAVE_NONSTANDARD_PRINTF_64_FORMAT)
    if (format[next] == 'I') {
        /*lcount++;*/
        next++;
    }
    if (format[next] == '6') {
        /*lcount++;*/
        next++;
    }
    if (format[next] == '4') {
        /*lcount++;*/
        next++;
    }
#endif /* HAVE_NONSTANDARD_PRINTF_64_FORMAT */
    if (format[next] == 'l') {
        lcount++;
        next++;
    }
    if (format[next] == 'l') {
        lcount++;
        next++;
    }
    if (format[next] == 'u') {
        ucount++;
        next++;
    }
    if (format[next] == 'd') {
        dcount++;
        next++;
    }
    if (format[next] == 'x') {
        xcount++;
        next++;
    }
    if (format[next] == 'X') {
        Xcount++;
        next++;
    }
    if (format[next] == 's') {
        /* ESBERR("ESBERR_pct_scount_in_u"); */
        return FALSE;
    }

    if ( (Xcount +xcount+dcount+ucount) > 1) {
        /* ESBERR("ESBERR_pct_xcount_etc_u"); */
        return FALSE;
    }
    if (lcount > 2) {
        /* ESBERR("ESBERR_pct_lcount_error_u"); */
        /* error */
        return FALSE;
    }
    if (dcount > 0) {
        /*ESBERR("ESBERR_pct_dcount_error_u");*/
        /* error */
        return FALSE;
    }
    if (ucount) {
        divisor = 10;
        ctable = dtable;
    } else {
        divisor = 16;
        if (xcount) {
            ctable = xtable;
        } else {
            ctable = Xtable;
        }
    }
    {
        char digbuf[36];
        char *digptr = 0;
        unsigned digcharlen = 0;
        dwarfstring_u remaining = v;

        if (divisor == 16) {
            digptr = digbuf+sizeof(digbuf) -1;
            for ( ;; ) {
                dwarfstring_u dig;
                dig = remaining & 0xf;
                remaining = remaining >> 4;
                *digptr = ctable[dig];
                ++digcharlen;
                if (!remaining) {
                    break;
                }
                --digptr;
            }
        } else {
            digptr = digbuf+sizeof(digbuf) -1;
            *digptr = 0;
            --digptr;
            for ( ;; ) {
                dwarfstring_u dig;
                dig = remaining % divisor;
                remaining /= divisor;
                *digptr = ctable[dig];
                ++digcharlen;
                if (!remaining) {
                    break;
                }
                --digptr;
            }
        }
        if (fixedlen <= digcharlen) {
            dwarfstring_append_length(data,digptr,digcharlen);
        } else {
            if (!leadingzero) {
                size_t justcount = fixedlen - digcharlen;
                _dwarfstring_append_spaces(data,justcount);
                dwarfstring_append_length(data,digptr,digcharlen);
            } else {
                size_t prefixcount = fixedlen - digcharlen;
                _dwarfstring_append_zeros(data,prefixcount);
                dwarfstring_append_length(data,digptr,digcharlen);
            }
        }
    }
    if (format[next]) {
        size_t trailinglen = strlen(format+next);
        dwarfstring_append_length(data,format+next,trailinglen);
    }
    return FALSE;
}
