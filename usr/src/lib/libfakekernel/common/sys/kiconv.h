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
 *
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
 */

#ifndef _SYS_KICONV_H
#define	_SYS_KICONV_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>

#if defined(_KERNEL) || defined(_FAKE_KERNEL)

/*
 * kiconv functions and their macros (from sunddi.h)
 */
#define	KICONV_IGNORE_NULL	(0x0001)
#define	KICONV_REPLACE_INVALID	(0x0002)

struct _iconv_info;
typedef struct _iconv_info *kiconv_t;

extern kiconv_t kiconv_open(const char *, const char *);
extern size_t kiconv(kiconv_t, char **, size_t *, char **, size_t *, int *);
extern int kiconv_close(kiconv_t);
extern size_t kiconvstr(const char *, const char *, char *, size_t *, char *,
	size_t *, int, int *);

#endif	/* _KERNEL */

#ifdef __cplusplus
}
#endif

#endif /* _SYS_KICONV_H */
