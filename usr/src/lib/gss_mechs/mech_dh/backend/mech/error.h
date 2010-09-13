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
 *	error.h
 *
 *	Copyright (c) 1997, by Sun Microsystems, Inc.
 *	All rights reserved.
 *
 */

#ifndef _ERROR_H_
#define	_ERROR_H_

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#define	EBASE 0
#define	EVAL(v) (EBASE + (v))
#define	ENUM(v) ((v) ? (v) - EBASE : 0)

#define	DH_SUCCESS 0
#define	DH_NOMEM_FAILURE EVAL(1)
#define	DH_ENCODE_FAILURE EVAL(2)
#define	DH_DECODE_FAILURE EVAL(3)
#define	DH_BADARG_FAILURE EVAL(4)
#define	DH_CIPHER_FAILURE EVAL(5)
#define	DH_VERIFIER_FAILURE EVAL(6)
#define	DH_SESSION_CIPHER_FAILURE EVAL(7)
#define	DH_NO_SECRET EVAL(8)
#define	DH_NO_PRINCIPAL EVAL(9)
#define	DH_NOT_LOCAL EVAL(10)
#define	DH_UNKNOWN_QOP EVAL(11)
#define	DH_VERIFIER_MISMATCH EVAL(12)
#define	DH_NO_SUCH_USER EVAL(13)
#define	DH_NETNAME_FAILURE EVAL(14)
#define	DH_BAD_CRED EVAL(15)
#define	DH_BAD_CONTEXT EVAL(16)
#define	DH_PROTO_MISMATCH EVAL(17)

#ifdef __cplusplus
}
#endif

#endif /* _ERROR_H_ */
