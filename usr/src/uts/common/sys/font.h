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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_FONT_H
#define	_SYS_FONT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

struct font {
	short	width;
	short	height;
	uchar_t	*char_ptr[256];
	void	*image_data;
};

typedef	struct  bitmap_data {
	short		width;
	short		height;
	unsigned char	*image;
	unsigned char	**encoding;
} bitmap_data_t;

struct fontlist {
	bitmap_data_t	*data;
	bitmap_data_t   *(*fontload)(char *);
};

#ifdef __cplusplus
}
#endif

#endif /* !_SYS_FONT_H */
