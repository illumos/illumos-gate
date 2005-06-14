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

#ifndef _MDB_KREG_IMPL_H
#define	_MDB_KREG_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <mdb/mdb_kreg.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * The mdb_tgt_gregset type is opaque to callers of the target interface
 * and to our own target common code.  We now can define it explicitly.
 */
struct mdb_tgt_gregset {
	kreg_t kregs[KREG_NGREG];
};

#ifdef __cplusplus
}
#endif

#endif /* _MDB_KREG_IMPL_H */
