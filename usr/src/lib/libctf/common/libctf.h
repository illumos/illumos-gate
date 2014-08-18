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
 * Copyright 2001-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright (c) 2014, Joyent, Inc.  All rights reserved.
 */

/*
 * This header file defines the interfaces available from the CTF debugger
 * library, libctf.  This library provides functions that a debugger can
 * use to operate on data in the Compact ANSI-C Type Format (CTF).  This
 * is NOT a public interface, although it may eventually become one in
 * the fullness of time after we gain more experience with the interfaces.
 *
 * In the meantime, be aware that any program linked with libctf in this
 * release of Solaris is almost guaranteed to break in the next release.
 *
 * In short, do not user this header file or libctf for any purpose.
 */

#ifndef	_LIBCTF_H
#define	_LIBCTF_H

#include <sys/ctf_api.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * This flag can be used to enable debug messages.
 */
extern int _libctf_debug;

typedef enum ctf_diff_flag {
	CTF_DIFF_F_IGNORE_INTNAMES = 0x01,
	CTF_DIFF_F_MASK	= 0x01
} ctf_diff_flag_t;

typedef struct ctf_diff ctf_diff_t;
typedef void (*ctf_diff_type_f)(ctf_file_t *, ctf_id_t, boolean_t, ctf_file_t *,
    ctf_id_t, void *);

extern int ctf_diff_init(ctf_file_t *, ctf_file_t *, ctf_diff_t **);
extern uint_t ctf_diff_getflags(ctf_diff_t *);
extern int ctf_diff_setflags(ctf_diff_t *, uint_t);
extern int ctf_diff_types(ctf_diff_t *, ctf_diff_type_f, void *);
extern void ctf_diff_fini(ctf_diff_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _LIBCTF_H */
