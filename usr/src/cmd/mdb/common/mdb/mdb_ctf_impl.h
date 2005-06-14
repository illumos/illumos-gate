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
 * Copyright (c) 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_MDB_CTF_IMPL_H
#define	_MDB_CTF_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct mdb_ctf_impl {
	ctf_file_t *mci_fp;
	ctf_id_t mci_id;
} mdb_ctf_impl_t;

extern int mdb_ctf_lookup_by_symbol(const GElf_Sym *, const mdb_syminfo_t *,
    mdb_ctf_id_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _MDB_CTF_IMPL_H */
