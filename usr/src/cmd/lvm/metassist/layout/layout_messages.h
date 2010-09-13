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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _LAYOUT_MESSAGES_H
#define	_LAYOUT_MESSAGES_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>

/*
 * Functions to print out progress, status and error messages that
 * are shared by layout_concat.c, layout_hsp.c, layout_mirror.c,
 * layout_stripe.c
 */
extern void print_layout_success_msg();
extern void print_layout_volume_msg(char *type, uint64_t nbytes);
extern void print_layout_explicit_msg(char *type);
extern void print_layout_explicit_added_msg(char *comp);
extern void print_layout_submirrors_msg(char *type, uint64_t nbytes, int nsubs);
extern void print_layout_submirrors_failed_msg(char *type, int count,
	int nsubs);

extern void print_populate_volume_msg(char *type, uint64_t nbytes);
extern void print_populate_volume_ncomps_msg(char *type, uint64_t nbytes,
	int ncomps);
extern void print_populate_success_msg();
extern void print_populate_choose_slices_msg();
extern void print_populate_no_slices_msg();

extern void print_no_hbas_msg();
extern void print_debug_failure_msg();

extern void print_insufficient_resources_msg(char *type);
extern void print_insufficient_hbas_msg(int n);
extern void print_insufficient_disks_msg(int n);
extern void print_hba_insufficient_space_msg(char *name, uint64_t nbytes);
extern void print_insufficient_capacity_msg(uint64_t nbytes);
extern void print_insufficient_components_msg(int ncomp);

#ifdef __cplusplus
}
#endif

#endif /* _LAYOUT_MESSAGES_H */
