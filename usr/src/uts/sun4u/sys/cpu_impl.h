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

#ifndef _SYS_CPU_IMPL_H
#define	_SYS_CPU_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Definitions of UltraSparc III cpu implementations as specified
 * in version register
 */
#define	CHEETAH_IMPL			0x14
#define	IS_CHEETAH(impl)		((impl) == CHEETAH_IMPL)
#define	CHEETAH_MAJOR_VERSION(rev)	(((rev) >> 4) & 0xf)
#define	CHEETAH_MINOR_VERSION(rev)	((rev) & 0xf)

/*
 * Definitions of UltraSPARC III+ cpu implementation as specified
 * in version register
 */
#define	CHEETAH_PLUS_IMPL		0x15
#define	IS_CHEETAH_PLUS(impl)		((impl) == CHEETAH_PLUS_IMPL)
#define	CHEETAH_PLUS_MAJOR_VERSION(rev)	CHEETAH_MAJOR_VERSION(rev)
#define	CHEETAH_PLUS_MINOR_VERSION(rev)	CHEETAH_MINOR_VERSION(rev)

/*
 * Definitions of UltraSPARC IIIi cpu implementation as specified
 * in version register.  Jalapeno major and minor rev's are in
 * the same location and are the same size as Cheetah/Cheetah+.
 */
#define	JALAPENO_IMPL			0x16
#define	IS_JALAPENO(impl)		((impl) == JALAPENO_IMPL)
#define	JALAPENO_MAJOR_VERSION(rev)	CHEETAH_MAJOR_VERSION(rev)
#define	JALAPENO_MINOR_VERSION(rev)	CHEETAH_MINOR_VERSION(rev)

/*
 * Definitions of UltraSPARC IV cpu implementation as specified
 * in version register. Jaguar major and minor rev's are in
 * the same location and are the same size as Cheetah/Cheetah+.
 */
#define	JAGUAR_IMPL			0x18
#define	IS_JAGUAR(impl)			((impl) == JAGUAR_IMPL)
#define	JAGUAR_MAJOR_VERSION(rev)	CHEETAH_MAJOR_VERSION(rev)
#define	JAGUAR_MINOR_VERSION(rev)	CHEETAH_MINOR_VERSION(rev)

/*
 * Definitions of UltraSPARC IIIi+ cpu implementation as specified
 * in version register.  Serrano major and minor rev's are in
 * the same location and are the same size as Cheetah/Cheetah+.
 */
#define	SERRANO_IMPL			0x22
#define	IS_SERRANO(impl)		((impl) == SERRANO_IMPL)
#define	SERRANO_MAJOR_VERSION(rev)	CHEETAH_MAJOR_VERSION(rev)
#define	SERRANO_MINOR_VERSION(rev)	CHEETAH_MINOR_VERSION(rev)

/*
 * Definitions of UltraSPARC IV+ cpu implementation as specified
 * in version register. Panther major and minor rev's are in
 * the same location and are the same size as Cheetah/Cheetah+.
 */
#define	PANTHER_IMPL			0x19
#define	IS_PANTHER(impl)		((impl) == PANTHER_IMPL)
#define	PANTHER_MAJOR_VERSION(rev)	CHEETAH_MAJOR_VERSION(rev)
#define	PANTHER_MINOR_VERSION(rev)	CHEETAH_MINOR_VERSION(rev)


/*
 * Definitions of Olympus-C cpu implementations as specified
 * in version register
 */
#define	OLYMPUS_C_IMPL			0x6
#define	IS_OLYMPUS_C(impl)		((impl) == OLYMPUS_C_IMPL)
#define	OLYMPUS_REV_MASK(x)		(((x) >> 28) & 0x7)
#define	OLYMPUS_C_A			0

/*
 * Definitions for Jupiter cpu.
 */
#define	JUPITER_IMPL			0x7
#define	IS_JUPITER(impl)		((impl) == JUPITER_IMPL)

#define	CPU_IMPL_IS_CMP(impl)		(IS_JAGUAR(impl) || \
					IS_PANTHER(impl) || \
					IS_OLYMPUS_C(impl) || \
					IS_JUPITER(impl))

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_CPU_IMPL_H */
