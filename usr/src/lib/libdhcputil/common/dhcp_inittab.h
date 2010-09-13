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

#ifndef	_DHCP_INITTAB_H
#define	_DHCP_INITTAB_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <dhcp_symbol.h>
#include <limits.h>

/*
 * dhcp_inittab.[ch] make up the interface to the inittab file, which
 * is a table of all known DHCP options.  please see `README.inittab'
 * for more background on the inittab api, and dhcp_inittab.c for details
 * on how to use the exported functions.
 */

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * On-disk inittab attributes and limits.
 */
#define	ITAB_INITTAB_PATH	"/etc/dhcp/inittab"
#define	ITAB_INITTAB6_PATH	"/etc/dhcp/inittab6"
#define	ITAB_MAX_LINE_LEN	8192 		/* bytes */
#define	ITAB_MAX_NUMBER_LEN	30		/* digits */
#define	ITAB_COMMENT_CHAR	'#'
#define	ITAB_CODE_MAX		UCHAR_MAX	/* for now */
#define	ITAB_GRAN_MAX		UCHAR_MAX
#define	ITAB_MAX_MAX		UCHAR_MAX

/*
 * Return values from the inittab API.
 */
#define	ITAB_FAILURE		0
#define	ITAB_SUCCESS		1
#define	ITAB_UNKNOWN		2

/*
 * Categories to pass to inittab functions; note that these may be
 * bitwise-OR'd to request more than one.  Note that these should
 * not be used otherwise.
 */
#define	ITAB_CAT_STANDARD	0x01
#define	ITAB_CAT_FIELD		0x02
#define	ITAB_CAT_INTERNAL	0x04
#define	ITAB_CAT_VENDOR		0x08
#define	ITAB_CAT_SITE		0x10
#define	ITAB_CAT_V6		0x20
#define	ITAB_CAT_COUNT		6

/*
 * Consumer which is using the inittab functions.
 */
#define	ITAB_CONS_INFO		'i'
#define	ITAB_CONS_SERVER	'd'
#define	ITAB_CONS_SNOOP		's'
#define	ITAB_CONS_MANAGER	'm'
#define	ITAB_CONS_COUNT		(sizeof ("idsm") - 1)

/*
 * Extended error codes, for use with inittab_{en,de}code_e().
 */
#define	ITAB_SYNTAX_ERROR	(-1)
#define	ITAB_BAD_IPADDR		(-2)
#define	ITAB_BAD_STRING		(-3)
#define	ITAB_BAD_OCTET		(-4)
#define	ITAB_BAD_NUMBER		(-5)
#define	ITAB_BAD_BOOLEAN	(-6)
#define	ITAB_NOT_ENOUGH_IP	(-7)
#define	ITAB_BAD_GRAN		(-8)
#define	ITAB_NOMEM		(-9)

extern uint8_t		inittab_type_to_size(const dhcp_symbol_t *);
extern int		inittab_verify(const dhcp_symbol_t *, dhcp_symbol_t *);
extern dhcp_symbol_t	*inittab_load(uchar_t, char, size_t *);
extern dhcp_symbol_t	*inittab_getbyname(uchar_t, char, const char *);
extern dhcp_symbol_t	*inittab_getbycode(uchar_t, char, uint16_t);
extern uchar_t		*inittab_encode(const dhcp_symbol_t *, const char *,
			    uint16_t *, boolean_t);
extern uchar_t		*inittab_encode_e(const dhcp_symbol_t *, const char *,
			    uint16_t *, boolean_t, int *);
extern char		*inittab_decode(const dhcp_symbol_t *, const uchar_t *,
			    uint16_t, boolean_t);
extern char		*inittab_decode_e(const dhcp_symbol_t *,
			    const uchar_t *, uint16_t, boolean_t, int *);

#ifdef	__cplusplus
}
#endif

#endif	/* _DHCP_INITTAB_H */
