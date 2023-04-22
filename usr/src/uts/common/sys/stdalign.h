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
 * Copyright 2023 Oxide Computer Company
 */

#ifndef _SYS_STDALIGN_H
#define	_SYS_STDALIGN_H

/*
 * ISO/IEC C11 stdalign.h. This header is meant to provide definitions for the
 * alignas and alignof 'keywords' into the underlying compiler-understood value.
 * In addition, there are two macros that are meant to define that this process
 * has happened. C++11 added alignas/alignof as keywords and including this
 * header is meant to cause us to still have the _is_defined macros, but not
 * define this overall.
 *
 * Unlike other cases we don't use any symbol guards here (other than C++) and
 * just allow the implementation to either have _Alignas and _Alignof or not
 * have it and lead to a compiler error for the user. The main justification of
 * this is that this header is only defined in C11 (and newer). It's not defined
 * in other standards and just as if you include a non-standard header, in this
 * case we don't try to stop that (same as if you included something like
 * libdevinfo.h).
 */

#ifdef __cplusplus
extern "C" {
#endif

#ifndef	__cplusplus

#define	alignas	_Alignas
/*CSTYLED*/
#define	alignof	_Alignof

#endif	/* !__cplusplus */

#define	__alignas_is_defined	1
#define	__alignof_is_defined	1

#ifdef __cplusplus
}
#endif

#endif /* _SYS_STDALIGN_H */
