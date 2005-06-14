/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_DICT_H
#define	_DICT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct dict_hdl dict_hdl_t;

/*
 * Hash functions
 */

extern uint64_t		hash_buf(const void *, size_t);
extern uint64_t		hash_str(const char *);

/*
 * Dictionary functions
 */
extern void		dict_free(dict_hdl_t **);
extern uint64_t		dict_length(dict_hdl_t *);
extern dict_hdl_t	*dict_new(int (*)(const void *, const void *),
    uint64_t (*)(const void *));

/*
 * Dictionary entry functions
 */

extern void		*dict_get(dict_hdl_t *, const void *);
extern void		*dict_put(dict_hdl_t *, const void *, void *);
extern void		*dict_remove(dict_hdl_t *, const void *);

extern void		dict_map(dict_hdl_t *,
    void (*)(const void *, void **, void *), void *);

/*
 * Dictionary conversion
 */

#ifdef	__cplusplus
}
#endif

#endif	/* _DICT_H */
