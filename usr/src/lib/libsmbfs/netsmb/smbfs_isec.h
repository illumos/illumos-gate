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
 */

#ifndef _SMBFS_ISEC_H
#define	_SMBFS_ISEC_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Internal Security Descriptor (SD)
 */

#include <netsmb/smbfs_acl.h>

/*
 * Internal form of an NT SID
 * Same as on the wire, but possibly byte-swapped.
 */
typedef struct i_ntsid {
	uint8_t	sid_revision;
	uint8_t	sid_subauthcount;
	uint8_t	sid_authority[6];
	uint32_t sid_subauthvec[1]; /* actually len=subauthcount */
} i_ntsid_t;
#define	I_SID_SIZE(sacnt)	(8 + 4 * (sacnt))

/*
 * Internal form of an NT ACE
 */
typedef struct i_ntace {
	uint8_t	ace_type;
	uint8_t	ace_flags;
	uint32_t	ace_rights; /* generic, standard, specific, etc */
	i_ntsid_t	*ace_sid;
} i_ntace_t;

/*
 * Internal form of an NT ACL (see sacl/dacl below)
 */
typedef struct i_ntacl {
	uint8_t	acl_revision;	/* 0x02 observed with W2K */
	uint16_t	acl_acecount;
	i_ntace_t	*acl_acevec[1]; /* actually, len=acecount */
} i_ntacl_t;

/*
 * Internal form of an NT Security Descriptor (SD)
 */
struct i_ntsd {
	uint8_t		sd_revision;	/* 0x01 observed between W2K */
	uint16_t	sd_flags;
	i_ntsid_t	*sd_owner;
	i_ntsid_t	*sd_group;
	i_ntacl_t	*sd_sacl;
	i_ntacl_t	*sd_dacl;
};


/*
 * Import a raw SD (mb chain) into "internal" form.
 * (like "absolute" form per. NT docs)
 * Returns allocated data in sdp
 */
int mb_get_ntsd(mbdata_t *mbp, i_ntsd_t **sdp);

/*
 * Export an "internal" SD into an raw SD (mb chain).
 * (a.k.a "self-relative" form per. NT docs)
 * Returns allocated mbchain in mbp.
 */
int mb_put_ntsd(mbdata_t *mbp, i_ntsd_t *sd);


/*
 * Get an SD via ioctl on FD (with "selector" bits),
 * stroing the raw Windows SD in the mb chain mbp.
 */
int smbfs_acl_iocget(int fd, uint32_t selector, mbdata_t *mbp);

/*
 * Set an SD via ioctl on FD (with "selector" bits),
 * with a raw Windows SD from the chain mbp.
 */
int smbfs_acl_iocset(int fd, uint32_t selector, mbdata_t *mbp);


int smbfs_sid2str(i_ntsid_t *sid,
	char *obuf, size_t olen, uint32_t *ridp);

#endif	/* _SMBFS_ISEC_H */
