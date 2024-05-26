/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2011 Nexenta Systems, Inc.  All rights reserved.
 * Copyright 2024 OmniOS Community Edition (OmniOSce) Association.
 */

#ifndef	_TERMCAP_H_
#define	_TERMCAP_H_

/*
 * This declares the public functions exported by the
 * "filter" library: libtermcap.  That exports only
 * the traditional BSD-style functions and data.
 *
 * Note that the libtermcap filter library uses NODIRECT
 * linker bindings when filtering what libcurses exports
 * so that an application can link with an alternative
 * curses library providing the symbols below, and those
 * will be used instead of the ones in libcurses.
 */

#ifdef	__cplusplus
extern "C" {
#endif

extern char PC, *UP, *BC;
extern short ospeed;

/*
 * These are intentionally the same as the XPG4v2 term.h
 * declares so the compiler won't bark if that is included
 * too.
 */
extern int tgetent(char *, const char *);
extern int tgetflag(char *);
extern int tgetnum(char *);
extern char *tgetstr(char *, char **);
extern char *tgoto(char *, int, int);
extern int tputs(const char *, int, int (*)(int));

#ifdef	__cplusplus
}
#endif

#endif	/* _TERMCAP_H_ */
