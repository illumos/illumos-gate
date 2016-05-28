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
 * Copyright (c) 2015, Joyent, Inc.
 */

	.file	"byteorder.s"

#include "SYS.h"

	/*
	 * NOTE: htonl/ntohl are identical routines, as are htons/ntohs.
	 * As such, they could be implemented as a single routine, using
	 * multiple ALTENTRY/SET_SIZE definitions. We don't do this so
	 * that they will have unique addresses, allowing DTrace and
	 * other debuggers to tell them apart.  With the endian
	 * functions we do the same, even though it's similarly
	 * repetitive.
	 */

/	unsigned long htonl( hl )
/	unsigned long ntohl( hl )
/	long hl;
/	reverses the byte order of 'long hl'
/
	ENTRY(htonl)
	movl	4(%esp), %eax	/ %eax = hl
	bswap	%eax		/ reverses the byte order of %eax
	ret			/ return (%eax)
	SET_SIZE(htonl)

	ENTRY(ntohl)
	movl	4(%esp), %eax	/ %eax = hl
	bswap	%eax		/ reverses the byte order of %eax
	ret			/ return (%eax)
	SET_SIZE(ntohl)

/	unsigned short htons( hs )
/	short hs;
/
/	reverses the byte order in hs.
/
	ENTRY(htons)
	movl	4(%esp), %eax	/ %eax = hs
	bswap	%eax		/ reverses the byte order of %eax
	shrl	$16, %eax	/ moves high 16-bit to low 16-bit
	ret			/ return (%eax)
	SET_SIZE(htons)

	ENTRY(ntohs)
	movl	4(%esp), %eax	/ %eax = hs
	bswap	%eax		/ reverses the byte order of %eax
	shrl	$16, %eax	/ moves high 16-bit to low 16-bit
	ret			/ return (%eax)
	SET_SIZE(ntohs)

/	uint16_t htobe16(uint16_t in)
/
/	Convert in to big endian, eg. htons()
/
	ENTRY(htobe16)
	movl	4(%esp), %eax	/ %eax = hs
	bswap	%eax		/ reverses the byte order of %eax
	shrl	$16, %eax	/ moves high 16-bit to low 16-bit
	ret			/ return (%eax)
	SET_SIZE(htobe16)

/	uint32_t htobe32(uint32_t in)
/
/	Convert in to big endian, eg. htonl()
/
	ENTRY(htobe32)
	movl	4(%esp), %eax	/ %eax = hl
	bswap	%eax		/ reverses the byte order of %eax
	ret			/ return (%eax)
	SET_SIZE(htobe32)

/	uint16_t betoh16(uint16_t in)
/	uint16_t be16toh(uint16_t in)
/
/	Convert in to little endian, eg. ntohs()
/
	ENTRY(betoh16)
	movl	4(%esp), %eax	/ %eax = hs
	bswap	%eax		/ reverses the byte order of %eax
	shrl	$16, %eax	/ moves high 16-bit to low 16-bit
	ret			/ return (%eax)
	SET_SIZE(betoh16)

	ENTRY(be16toh)
	movl	4(%esp), %eax	/ %eax = hs
	bswap	%eax		/ reverses the byte order of %eax
	shrl	$16, %eax	/ moves high 16-bit to low 16-bit
	ret			/ return (%eax)
	SET_SIZE(be16toh)


/	uint32_t be32toh(uint32_t in)
/	uint32_t betoh32(uint32_t in)
/
/	Convert in to little endian, eg. ntohl()
/
	ENTRY(be32toh)
	movl	4(%esp), %eax	/ %eax = hl
	bswap	%eax		/ reverses the byte order of %eax
	ret			/ return (%eax)
	SET_SIZE(be32toh)

	ENTRY(betoh32)
	movl	4(%esp), %eax	/ %eax = hl
	bswap	%eax		/ reverses the byte order of %eax
	ret			/ return (%eax)
	SET_SIZE(betoh32)
