/* $NetBSD: getopt.c,v 1.1 2009/03/22 22:33:13 joerg Exp $*/
/*  Modified by David Anderson to work with GNU/Linux and freebsd.
    Added {} for clarity.
    Switched to standard dwarfdump formatting.
    Treatment of : modified so that :: gets dwoptarg NULL
    if space follows the letter
    (the dwoptarg is set to null).
*/
/*
* Copyright (c) 1987, 1993, 1994
* The Regents of the University of California.  All rights reserved.
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions
* are met:
* 1. Redistributions of source code must retain the above copyright
*    notice, this list of conditions and the following disclaimer.
* 2. Redistributions in binary form must reproduce the above copyright
*    notice, this list of conditions and the following disclaimer in the
*    documentation and/or other materials provided with the distribution.
* 3. Neither the name of the University nor the names of its contributors
*    may be used to endorse or promote products derived from this software
*    without specific prior written permission.
*
* THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
* ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
* IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
* ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
* FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
* DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
* OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
* HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
* LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
* OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
* SUCH DAMAGE.
*/

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */
extern int  dwopterr;
extern int  dwoptind;
extern int  dwoptopt;
extern int  dwoptreset;
extern char *dwoptarg;

int dwgetopt(int nargc, char * const nargv[], const char *ostr);

/*  As of October 2017 it seems adviseable to allow
    long option names.  So based on a reading of
    'man 3 getopt' we reimplement a portion of GNU getopt_long().
    It's a wonderfully sensible design and all the credit
    should go to the original designers.
    We are not implementing all the features of GNU/Linux
    getopt_long(), just the features we wish to use.
    Specifically, we require val be 0 and flag
    be NULL and ignore those fields.
    We do not implement GNU digit_optind at all.
    Within these restrictions the interface behaves the same
    as GNU getopt_long() (or so it appears from the
    getopt documentation:
    release 4.04 of the Linux man-pages project,
    GETOPT(3),
    http://www.kernel.org/doc/man-pages/).
    */

struct dwoption {
    const char *name;
    int has_arg;
    int *flag;
    int val;
};
#define dwno_argument 0
#define dwrequired_argument 1
#define dwoptional_argument 2

int dwgetopt_long(int nargc, char *const nargv[],
    const char *ostr,
    const struct dwoption* longopts,
    int *longindex);


#ifdef __cplusplus
}
#endif /* __cplusplus */
