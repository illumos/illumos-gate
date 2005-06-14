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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _ELFCAP_DOT_H
#define	_ELFCAP_DOT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Define a capabilities descriptor.
 */
typedef	struct {
	uint64_t	c_val;
	const char	*c_str;
	size_t		c_len;
} Cap_desc;

/*
 * Define a format descriptor.
 */
typedef struct {
	const char	*f_str;
	size_t		f_len;
} Fmt_desc;

/*
 * Define valid format values.
 */
#define	CAP_FMT_SNGSPACE	0
#define	CAP_FMT_DBLSPACE	1
#define	CAP_FMT_PIPSPACE	2

#define	CAP_MAX_TYPE		CAP_FMT_PIPSPACE

/*
 * Define error return values.
 */
#define	CAP_ERR_BUFOVFL		1		/* buffer overfow */
#define	CAP_ERR_INVFMT		2		/* invalid format */
#define	CAP_ERR_UNKTAG		3		/* unknown capabilities tag */
#define	CAP_ERR_UNKMACH		4		/* unknown machine type */


extern int	cap_val2str(uint64_t, uint64_t, char *, size_t, int, ushort_t);
extern int	hwcap_1_val2str(uint64_t, char *, size_t, int, ushort_t);
extern int	sfcap_1_val2str(uint64_t, char *, size_t, int, ushort_t);
extern uint64_t	hwcap_1_str2val(const char *, ushort_t mach);
extern uint64_t	sfcap_1_str2val(const char *, ushort_t mach);

#ifdef	__cplusplus
}
#endif

#endif /* _ELFCAP_DOT_H */
