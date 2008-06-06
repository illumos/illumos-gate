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

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_DES_SYNONYMS_H
#define	_DES_SYNONYMS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "c_synonyms.h"

#ifdef __cplusplus
extern "C" {
#endif

#if !defined(__lint)

#define	crypt_close	_crypt_close
#define	des_crypt	_des_crypt
#define	des_decrypt1	_des_decrypt1
#define	des_encrypt	_des_encrypt
#define	des_encrypt1	_des_encrypt1
#define	des_setkey	_des_setkey
#define	makekey		_makekey
#define	run_crypt	_run_crypt
#define	run_setkey	_run_setkey

#endif	/* !defined(__lint) */

#ifdef __cplusplus
}
#endif

#endif	/* _DES_SYNONYMS_H */
