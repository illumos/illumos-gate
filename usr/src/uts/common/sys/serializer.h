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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_SERIALIZER_H
#define	_SYS_SERIALIZER_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This file is used for building Solaris kernel. It does not provide any public
 * interface, its content is unstable and subject to change without notice at
 * any time.
 */

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef _KERNEL

#include <sys/stream.h>
#include <sys/kmem.h>

struct serializer_s;
typedef struct serializer_s serializer_t;

typedef void (srproc_t)(mblk_t *, void *);

extern void serializer_init(void);
extern serializer_t *serializer_create(int);
extern void serializer_enter(serializer_t *, srproc_t, mblk_t *, void *);
extern void serializer_wait(serializer_t *);
extern void serializer_destroy(serializer_t *);

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_SERIALIZER_H */
