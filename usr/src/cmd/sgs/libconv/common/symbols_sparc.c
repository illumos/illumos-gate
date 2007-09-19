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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include "_conv.h"
#include "symbols_sparc_msg.h"
#include <sys/elf_SPARC.h>

/*
 * SPARC specific register symbols
 */

static const Msg registers[] = { 0,
	MSG_STO_REGISTERG1,	MSG_STO_REGISTERG2, 	MSG_STO_REGISTERG3,
	MSG_STO_REGISTERG4,	MSG_STO_REGISTERG5, 	MSG_STO_REGISTERG6,
	MSG_STO_REGISTERG7
};

const char *
conv_sym_SPARC_value(Addr val, Conv_fmt_flags_t fmt_flags,
    Conv_inv_buf_t *inv_buf)
{
	if ((val < STO_SPARC_REGISTER_G1) || (val > STO_SPARC_REGISTER_G7)) {
		return (conv_invalid_val(inv_buf, val, fmt_flags));
	} else {
		return (MSG_ORIG(registers[val]));
	}
}
