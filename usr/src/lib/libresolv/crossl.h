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
 * Copyright 2015 Gary Mills
 */

#ifndef _CROSSL_H
#define	_CROSSL_H

/*
 * Definitions needed for cross-linkages between source files
 */

#ifdef __cplusplus
extern "C" {
#endif

extern int dn_comp(u_char *, u_char *, int, u_char **, u_char **);
extern int dn_expand(u_char *, u_char *, u_char *, u_char *, int);
extern int dn_skipname(u_char *, u_char *);

extern int res_init(void);
extern int res_mkquery(int, char *, int, int, char *, int, struct rrec *,
    char *, int);
extern int res_query(char *, int, int, u_char *, int);
extern int res_querydomain(char *, char *, int, int, u_char *, int);
extern int res_search(char *, int, int, u_char *, int);
extern int res_send(char *, int, char *, int);

extern void putlong(u_long, u_char *);
extern void putshort(u_short, u_char *);
extern void p_query(char *);
extern void _res_close();


#ifdef __cplusplus
}
#endif

#endif /* _CROSSL_H */
