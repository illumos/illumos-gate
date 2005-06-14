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
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _SYS_REFSTR_IMPL_H
#define	_SYS_REFSTR_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Strings with reference counts.
 * The refstr_t definition is private to the implementation.
 * <sys/refstr.h> just declares it as a 'struct refstr'.
 * We require there never to be an allocation larger than 4 Gbytes.
 */

struct refstr {
	uint32_t	rs_size;	/* allocation size */
	uint32_t	rs_refcnt;	/* reference count */
	char		rs_string[1];	/* constant string */
};

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_REFSTR_IMPL_H */
