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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2018 Joyent, Inc.
 */

#ifndef	_VM_SEG_MF_H
#define	_VM_SEG_MF_H


#include <sys/types.h>
#include <vm/seg.h>
#include <sys/hypervisor.h>

#ifdef __cplusplus
extern "C" {
#endif

struct segmf_crargs {
	dev_t		dev;
	uchar_t		prot;
	uchar_t		maxprot;
};

extern int segmf_create(struct seg **, void *);

extern int segmf_add_mfns(struct seg *, caddr_t, mfn_t, pgcnt_t, domid_t);

/* max grefs which can be passed into segmf_add_grefs */
#define	SEGMF_MAX_GREFS		0x10

/* segmf_add_grefs flags */
#define	SEGMF_GREF_WR		0x1	/* Map gref writable */

extern int segmf_add_grefs(struct seg *, caddr_t, uint_t, grant_ref_t *,
    uint_t, domid_t);
extern int segmf_release_grefs(struct seg *, caddr_t, uint_t);
extern void segmf_add_gref_pte(struct seg *, caddr_t, uint64_t);

#ifdef __cplusplus
}
#endif

#endif /* _VM_SEG_MF_H */
