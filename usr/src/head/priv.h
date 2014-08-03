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
 * Copyright 2014 Garrett D'Amore <garrett@damore.org>
 *
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_PRIV_H_
#define	_PRIV_H_

#include <sys/priv.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	PRIV_STR_PORT		0x00			/* portable output */
#define	PRIV_STR_LIT		0x01			/* literal output */
#define	PRIV_STR_SHORT		0x02			/* shortest output */

#define	PRIV_ALLSETS		((priv_ptype_t)0)	/* for priv_set() */

/*
 * library functions prototype.
 */

extern int setppriv(priv_op_t, priv_ptype_t, const priv_set_t *);
extern int getppriv(priv_ptype_t, priv_set_t *);
extern int setpflags(uint_t, uint_t);
extern uint_t getpflags(uint_t);
extern const priv_impl_info_t *getprivimplinfo(void);

extern int priv_set(priv_op_t, priv_ptype_t, ...);
extern boolean_t priv_ineffect(const char *);
extern priv_set_t *priv_str_to_set(const char *, const char *, const char **);
extern char *priv_set_to_str(const priv_set_t *, char, int);

extern int priv_getbyname(const char *);
extern const char *priv_getbynum(int);
extern int priv_getsetbyname(const char *);
extern const char *priv_getsetbynum(int);
extern char *priv_gettext(const char *);

extern priv_set_t *priv_allocset(void);
extern void priv_freeset(priv_set_t *);

extern void priv_emptyset(priv_set_t *);
extern void priv_basicset(priv_set_t *);
extern void priv_fillset(priv_set_t *);
extern boolean_t priv_isemptyset(const priv_set_t *);
extern boolean_t priv_isfullset(const priv_set_t *);
extern boolean_t priv_isequalset(const priv_set_t *, const priv_set_t *);
extern boolean_t priv_issubset(const priv_set_t *, const priv_set_t *);
extern void priv_intersect(const priv_set_t *, priv_set_t *);
extern void priv_union(const priv_set_t *, priv_set_t *);
extern void priv_inverse(priv_set_t *);
extern int priv_addset(priv_set_t *, const char *);
extern void priv_copyset(const priv_set_t *, priv_set_t *);
extern int priv_delset(priv_set_t *, const char *);
extern boolean_t priv_ismember(const priv_set_t *, const char *);

#ifdef	__cplusplus
}
#endif

#endif	/* _PRIV_H_ */
