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
 * Copyright (c) 1999-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _AUTH_H
#define	_AUTH_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * auth.h : Data structures and prototypes used by a Mobile IP agent
 *          for authentication purposes.
 */

#ifdef __cplusplus
extern "C" {
#endif

int appendAuthExt(uint8_t *, size_t, uint8_t, MipSecAssocEntry *);

/*
 * Routines to find Security Associatios
 */
MipSecAssocEntry *findSecAssocFromIp(uint32_t, int);
MipSecAssocEntry *findSecAssocFromSPI(uint32_t, int);

/*
 * Support for the latest Challenge/Response I-D
 */
int faCheckRegReqAuth(MessageHdr *, FaVisitorEntry *, FaVisitorEntry *,
    unsigned char *, uint32_t, boolean_t *);
int faCheckRegRepAuth(MessageHdr *, FaVisitorEntry *);
int haCheckRegReqAuth(MessageHdr *, HaMobileNodeEntry **, uint32_t *,
    uint32_t *);

#define	AUTHENTICATOR_LEN	16

#define	GET_SPI(SPI, authExt)                                           \
	{                                                               \
	uint16_t SPIlo;                                                 \
	uint16_t SPIhi;                                                 \
									\
	(void) memcpy(&SPIhi, &authExt->SPIhi, sizeof (SPIhi));         \
	(void) memcpy(&SPIlo, &authExt->SPIlo, sizeof (SPIlo));         \
	SPI = ntohs(SPIhi) << AUTHENTICATOR_LEN | ntohs(SPIlo);         \
	}

/*
 * Support for the latest Challenge/Response I-D
 */
#define	GET_GEN_AUTH_SPI(SPI, genAuthExt)                               \
	{                                                               \
	uint16_t SPIlo;                                                 \
	uint16_t SPIhi;                                                 \
									\
	(void) memcpy(&SPIhi, &genAuthExt->SPIhi, sizeof (SPIhi));      \
	(void) memcpy(&SPIlo, &genAuthExt->SPIlo, sizeof (SPIlo));      \
	SPI = ntohs(SPIhi) << AUTHENTICATOR_LEN | ntohs(SPIlo);         \
	}
#ifdef __cplusplus
}
#endif

#endif /* _AUTH_H */
