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

#ifndef	_LIBC_PORT_I18N_LOCPATH_H
#define	_LIBC_PORT_I18N_LOCPATH_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/isa_defs.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	_DFLT_LOC_PATH	"/usr/lib/locale/"

#define	_ICONV_PATH1	"/usr/lib/iconv/"
#define	_ICONV_PATH2	"%s%%%s.so"
#define	_WDMOD_PATH1	"/LC_CTYPE/"
#define	_WDMOD_PATH2	"wdresolve.so"
#define	_ENCODING_ALIAS_FILE	"alias"
#define	_ENCODING_ALIAS_PATH	_ICONV_PATH1 _ENCODING_ALIAS_FILE

#define	_GENICONVTBL_PATH1	"geniconvtbl/binarytables/%s%%%s.bt"
#define	_GENICONVTBL_INT_PATH1	"geniconvtbl.so"

#ifdef _LP64

#if defined(__sparcv9)

#define	_MACH64_NAME		"sparcv9"

#elif defined(__amd64)

#define	_MACH64_NAME		"amd64"

#else  /* !defined(__sparcv9) */

#error "Unknown architecture"

#endif /* defined(__sparcv9) */

#define	_MACH64_NAME_LEN	(sizeof (_MACH64_NAME) - 1)

#define	_ICONV_PATH	_ICONV_PATH1 _MACH64_NAME "/" _ICONV_PATH2
#define	_WDMOD_PATH	_WDMOD_PATH1 _MACH64_NAME "/" _WDMOD_PATH2
#define	_GENICONVTBL_PATH	_ICONV_PATH1 _GENICONVTBL_PATH1
#define	_GENICONVTBL_INT_PATH	_ICONV_PATH1 \
			_MACH64_NAME "/" _GENICONVTBL_INT_PATH1

#else  /* !LP64 */

#define	_ICONV_PATH	_ICONV_PATH1 _ICONV_PATH2
#define	_WDMOD_PATH	_WDMOD_PATH1 _WDMOD_PATH2
#define	_GENICONVTBL_PATH	_ICONV_PATH1 _GENICONVTBL_PATH1
#define	_GENICONVTBL_INT_PATH	_ICONV_PATH1 _GENICONVTBL_INT_PATH1

#endif /* _LP64 */

#ifdef	__cplusplus
}
#endif

#endif	/* !_LIBC_PORT_I18N_LOCPATH_H */
