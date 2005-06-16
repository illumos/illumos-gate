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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_PKTOOL_BIGINTEGER_H
#define	_PKTOOL_BIGINTEGER_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include <security/pkcs11t.h>

/*
 * NOTE:
 *
 * This is same "biginteger_t" found in both these places:
 *	usr/src/lib/pkcs11/pkcs11_softtoken/common/softObject.h
 *	usr/src/lib/pkcs11/pkcs11_kernel/common/kernelObject.h
 * The BIGNUM implementation in usr/src/common/bignum does not
 * meet the need.  It is recommended that the biginteger_t be
 * factored out of pkcs11_softtoken/pkcs11_kernel/pktool and
 * the pkcs11 libraries and moved into cryptoutil.h
 */
typedef struct biginteger {
	CK_BYTE *big_value;
	CK_ULONG big_value_len;
} biginteger_t;

#ifdef	__cplusplus
}
#endif

#endif /* _PKTOOL_BIGINTEGER_H */
