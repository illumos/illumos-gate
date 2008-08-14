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
 *
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


#ifndef _LIB_MIXED_MEDIA_
#define	_LIB_MIXED_MEDIA_

#define	LIB_MEDIA_TYPE_LEN		1
#define	LIB_DRIVE_TYPE_LEN		2
typedef char LIB_MEDIA_TYPE[LIB_MEDIA_TYPE_LEN + 1];
typedef char LIB_DRIVE_TYPE[LIB_DRIVE_TYPE_LEN + 1];

#define	MM_UNK_LIB_DRIVE_TYPE		0

#define	LIB_DTYPE_MIN		01
#define	LIB_DTYPE_MAX		99

#endif /* _LIB_MIXED_MEDIA_ */
