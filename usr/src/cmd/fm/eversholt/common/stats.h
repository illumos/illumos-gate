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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * stats.h -- public definitions for stats module
 *
 */

#ifndef	_ESC_COMMON_STATS_H
#define	_ESC_COMMON_STATS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

void stats_init(int ext);
void stats_fini(void);
void stats_publish(void);
struct stats *stats_new_counter(const char *name, const char *desc, int ext);
void stats_delete(struct stats *sp);
void stats_counter_bump(struct stats *sp);
void stats_counter_add(struct stats *sp, int n);
void stats_counter_reset(struct stats *sp);
int stats_counter_value(struct stats *sp);
struct stats *stats_new_elapse(const char *name, const char *desc, int ext);
void stats_elapse_start(struct stats *sp);
void stats_elapse_stop(struct stats *sp);
struct stats *stats_new_string(const char *name, const char *desc, int ext);
void stats_string_set(struct stats *sp, const char *s);

#ifdef	__cplusplus
}
#endif

#endif	/* _ESC_COMMON_STATS_H */
