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
 * Copyright 2001 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _LIBC_PORT_GEN_ICONVP_H
#define	_LIBC_PORT_GEN_ICONVP_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

struct _iconv_fields {
	void *_icv_handle;
	size_t (*_icv_iconv)(iconv_t, const char **, size_t *, char **,
		size_t *);
	void (*_icv_close)(iconv_t);
	void *_icv_state;
};

typedef struct _iconv_fields *iconv_p;

struct _iconv_info {
	iconv_p	_conv;		/* conversion by shared object */
	size_t  bytesleft;    	/* used for premature/incomplete conversion */
};

#ifdef	__cplusplus
}
#endif

#endif	/* _LIBC_PORT_GEN_ICONVP_H */
