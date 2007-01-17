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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _DHCP_SYMBOL_COMMON_H
#define	_DHCP_SYMBOL_COMMON_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This file contains DHCP symbol definitions that are shared between userland
 * (libdhcputil) and standalone.  The sharing is just for convenience; there's
 * no inherent relationship between the two implementations.
 *
 * NOTE: This file should never be included directly, but rather through
 *       either <dhcp_symbol.h> or <dhcp_impl.h>.
 */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Symbol category ids and strings
 */
typedef enum {
	DSYM_BAD_CAT	= -1,	/* An invalid category */
	DSYM_STANDARD	= 0,	/* Standard option */
	DSYM_EXTEND	= 1,	/* Extended Standard option */
	DSYM_VENDOR	= 2,	/* Vendor-specific option */
	DSYM_SITE	= 3,	/* Site-specific option */
	DSYM_FIELD	= 4,	/* DHCP packet fixed field option */
	DSYM_INTERNAL	= 5	/* Solaris DHCP internal option */
} dsym_category_t;

/*
 * Symbol type ids and strings
 */
typedef enum {
	DSYM_BAD_TYPE	= -1,	/* An invalid type */
	DSYM_ASCII	= 0,	/* A printable character string */
	DSYM_OCTET	= 1,	/* An array of bytes */
	DSYM_IP		= 2,	/* An IP address */
	DSYM_NUMBER	= 3,	/* A signed number */
	DSYM_BOOL	= 4,	/* No associated value */
	DSYM_INCLUDE	= 5,	/* Include macro (internal only) */
	DSYM_UNUMBER8	= 6,	/* An 8-bit unsigned integer */
	DSYM_UNUMBER16	= 7,	/* A 16-bit unsigned integer */
	DSYM_UNUMBER32	= 8,	/* A 32-bit unsigned integer */
	DSYM_UNUMBER64	= 9,	/* A 64-bit unsigned integer */
	DSYM_SNUMBER8	= 10,	/* An 8-bit signed integer */
	DSYM_SNUMBER16	= 11,	/* A 16-bit signed integer */
	DSYM_SNUMBER32	= 12,	/* A 32-bit signed integer */
	DSYM_SNUMBER64	= 13,	/* A 64-bit signed integer */
	DSYM_UNUMBER24	= 14,	/* A 24-bit unsigned integer */
	DSYM_IPV6	= 15,	/* An IPv6 address */
	DSYM_DUID	= 16,	/* A DHCP Unique Identifier */
	DSYM_DOMAIN	= 17	/* An RFC 1035-encoded domain name */
} dsym_cdtype_t;

#ifdef __cplusplus
}
#endif

#endif /* _DHCP_SYMBOL_COMMON_H */
