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

#ifndef _IA32_SYS_MACHTYPES_H
#define	_IA32_SYS_MACHTYPES_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Machine dependent types:
 *
 *	intel ia32 Version
 */

#if (!defined(_POSIX_C_SOURCE) && !defined(_XOPEN_SOURCE)) || \
	defined(__EXTENSIONS__)

#define	REG_LABEL_PC	0
#define	REG_LABEL_SP	1
#define	REG_LABEL_BP	2
#if defined(__amd64)
#define	REG_LABEL_RBX	3
#define	REG_LABEL_R12	4
#define	REG_LABEL_R13	5
#define	REG_LABEL_R14	6
#define	REG_LABEL_R15	7
#define	REG_LABEL_MAX	8
#else /* __amd64 */
#define	REG_LABEL_EBX	3
#define	REG_LABEL_ESI	4
#define	REG_LABEL_EDI	5
#define	REG_LABEL_MAX	6
#endif /* __amd64 */

typedef	struct _label_t { long val[REG_LABEL_MAX]; } label_t;

#endif /* !defined(_POSIX_C_SOURCE)... */

typedef	unsigned char	lock_t;		/* lock work for busy wait */

#ifdef	__cplusplus
}
#endif

#endif	/* _IA32_SYS_MACHTYPES_H */
