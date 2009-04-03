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

/*
 * String conversion routines for symbol attributes.
 */
#include	<stdio.h>
#include	<_machelf.h>
#include	<sys/elf_SPARC.h>
#include	<sys/elf_amd64.h>
#include	"_conv.h"
#include	"symbols_msg.h"

const char *
conv_sym_value(Half mach, uchar_t type, Addr value, Conv_inv_buf_t *inv_buf)
{
	if (((mach == EM_SPARC) || (mach == EM_SPARC32PLUS) ||
	    (mach == EM_SPARCV9)) && (type == STT_SPARC_REGISTER))
		return (conv_sym_SPARC_value(value, 0, inv_buf));

	(void) snprintf(inv_buf->buf, sizeof (inv_buf->buf),
	    MSG_ORIG(MSG_SYM_FMT_VAL), EC_ADDR(value));
	return (inv_buf->buf);
}
