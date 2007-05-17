/
/ Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
/ Use is subject to license terms.
/
/ CDDL HEADER START
/
/ The contents of this file are subject to the terms of the
/ Common Development and Distribution License, Version 1.0 only
/ (the "License").  You may not use this file except in compliance
/ with the License.
/
/ You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
/ or http://www.opensolaris.org/os/licensing.
/ See the License for the specific language governing permissions
/ and limitations under the License.
/
/ When distributing Covered Code, include this CDDL HEADER in each
/ file and include the License file at usr/src/OPENSOLARIS.LICENSE.
/ If applicable, add the following below this CDDL HEADER, with the
/ fields enclosed by brackets "[]" replaced with your own identifying
/ information: Portions Copyright [yyyy] [name of copyright owner]
/
/ CDDL HEADER END
/
	.ident	"%Z%%M%	%I%	%E% SMI"

	.file	"byteorder.s"

#include <sys/asm_linkage.h>

/
/ uint32_t	htonl(uint32_t hl);
/ uint32_t	ntohl(uint32_t nl);
/
/ reverses the byte order of the argument.
/

	ENTRY(htonl)
	ENTRY(ntohl)
	movl	4(%esp), %eax	/ %eax = hl
	bswap	%eax		/ reverses the byte order of %eax
	ret			/ return (%eax)
	SET_SIZE(htonl)
	SET_SIZE(ntohl)

/
/ uint16_t	htons(uint16_t hs);
/ uint16_t	ntohs(uint16_t ns); 
/
/ reverses the byte order of the argument.
/

	ENTRY(htons)
	ENTRY(ntohs)
	movl	4(%esp), %eax	/ %eax = hs
	bswap	%eax		/ reverses the byte order of %eax
	shrl	$16, %eax	/ moves high 16-bit to low 16-bit
	ret			/ return (%eax)
	SET_SIZE(htons)
	SET_SIZE(ntohs)
