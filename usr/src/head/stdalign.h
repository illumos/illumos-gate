/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2016 Joyent, Inc.
 */

#ifndef _STDALIGN_H
#define	_STDALIGN_H

/*
 * ISO/IEC C11 stdalign.h
 */
#include <sys/feature_tests.h>

#ifdef __cplusplus
extern "C" {
#endif

#if !defined(_STRICT_SYMBOLS) || defined(_STDC_C11)

#define	alignas	_Alignas
#define	alignof	_Alignof

#define	__alignas_is_defined	1
#define	__alignof_is_defined	1

#endif	/* !_STRICT_SYMBOLS || _STDC_C11 */

#ifdef __cplusplus
}
#endif

#endif /* _STDALIGN_H */
