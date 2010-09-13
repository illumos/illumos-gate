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
 *      Copyright (c) 1994, by Sun Microsytems, Inc.
 */

#ifndef _TNF_ARGS_H
#define	_TNF_ARGS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <tnf/probe.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * In process interface for getting probe arguments and types and attributes
 */

#define	tnf_probe_get_int(x) 		(*((int *)(x)))
#define	tnf_probe_get_uint(x) 		(*((unsigned int *)(x)))
#define	tnf_probe_get_long(x) 		(*((long *)(x)))
#define	tnf_probe_get_ulong(x) 		(*((unsigned long *)(x)))
#define	tnf_probe_get_longlong(x) 	(*((long long *)(x)))
#define	tnf_probe_get_ulonglong(x) 	(*((unsigned long long *)(x)))
#define	tnf_probe_get_float(x) 		(*((float *)(x)))
#define	tnf_probe_get_double(x) 	(*((double *)(x)))

char * tnf_probe_get_chars(void *);

int tnf_probe_get_num_args(tnf_probe_control_t *);

void *tnf_probe_get_arg_indexed(tnf_probe_control_t *, int, void *);

tnf_arg_kind_t tnf_probe_get_type_indexed(tnf_probe_control_t *, int);

const char * tnf_probe_get_value(tnf_probe_control_t *, char *, ulong_t *);

#ifdef __cplusplus
}
#endif

#endif /* _TNF_ARGS_H */
