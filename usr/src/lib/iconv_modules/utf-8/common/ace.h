/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_ACE_H
#define	_ACE_H

#include <sys/isa_defs.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef  _LP64
#define ICV_LIBIDNKITPATH	"/usr/lib/64/libidnkit.so.1"
#else
#define ICV_LIBIDNKITPATH	"/usr/lib/libidnkit.so.1"
#endif

typedef struct _ace_state_t {
	void *libidnkit;
	idn_result_t (*idn_function)(int, const char *, char *, size_t);
	uchar_t *ib;
	size_t ibl;
	size_t iblconsumed;
	uchar_t *ob;
	size_t obl;
	size_t oblremaining;
} ace_state_t;

#ifdef __cplusplus
}
#endif

#endif	/* _ACE_H */
