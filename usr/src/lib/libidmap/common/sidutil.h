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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SIDUTIL_H
#define	_SIDUTIL_H

/*
 * Security Identifier (SID) interface definition.
 *
 * This is an extract from uts/common/smbsrv/smb_sid.h, with functions
 * renamed as part of a tentative plan for convergence.
 */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Common definition for a SID.
 */
#define	NT_SID_REVISION		1
#define	NT_SID_AUTH_MAX		6
#define	NT_SID_SUBAUTH_MAX	15

#if	!defined(ANY_SIZE_ARRAY)
#define	ANY_SIZE_ARRAY	1
#endif

/*
 * Security Identifier (SID)
 *
 * The security identifier (SID) uniquely identifies a user, group or
 * a domain. It consists of a revision number, the identifier authority,
 * and a list of sub-authorities. The revision number is currently 1.
 * The identifier authority identifies which system issued the SID. The
 * sub-authorities of a domain SID uniquely identify a domain. A user
 * or group SID consists of a domain SID with the user or group id
 * appended. The user or group id (also known as a relative id (RID)
 * uniquely identifies a user within a domain. A user or group SID
 * uniquely identifies a user or group across all domains. The SidType
 * values identify the various types of SID.
 *
 *      1   1   1   1   1   1
 *      5   4   3   2   1   0   9   8   7   6   5   4   3   2   1   0
 *   +---------------------------------------------------------------+
 *   |      SubAuthorityCount        |Reserved1 (SBZ)|   Revision    |
 *   +---------------------------------------------------------------+
 *   |                   IdentifierAuthority[0]                      |
 *   +---------------------------------------------------------------+
 *   |                   IdentifierAuthority[1]                      |
 *   +---------------------------------------------------------------+
 *   |                   IdentifierAuthority[2]                      |
 *   +---------------------------------------------------------------+
 *   |                                                               |
 *   +- -  -  -  -  -  -  -  SubAuthority[]  -  -  -  -  -  -  -  - -+
 *   |                                                               |
 *   +---------------------------------------------------------------+
 *
 */
/*
 * Note: NT defines the Identifier Authority as a separate
 * structure (SID_IDENTIFIER_AUTHORITY) containing a literal
 * definition of a 6 byte vector but the effect is the same
 * as defining it as a member value.
 */
typedef struct sid {
	uint8_t sid_revision;
	uint8_t sid_subauthcnt;
	uint8_t sid_authority[NT_SID_AUTH_MAX];
	uint32_t sid_subauth[ANY_SIZE_ARRAY];
} sid_t;

/*
 * The maximum size of a SID in string format
 */
#define	SID_STRSZ		256

/* Given a SID, return its length in bytes. */
int sid_len(sid_t *);

/* Given a dynamically allocated SID (e.g. from sid_fromstr), free it. */
void sid_free(sid_t *);

/* Translate a binary-format SID into the supplied SID_STRSZ buffer. */
void sid_tostr(sid_t *, char *);

/* Translate a text-format SID into an allocated binary-format SID. */
sid_t *sid_fromstr(char *);

/* In-place, translate a host-order SID into MS-native little endian. */
void sid_to_le(sid_t *);

/* In-place, translate a MS-native little endian SID into host order. */
void sid_from_le(sid_t *);

#ifdef __cplusplus
}
#endif


#endif /* _SIDUTIL_H */
