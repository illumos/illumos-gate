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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _FPS_EREPORT_H
#define	_FPS_EREPORT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#define	IS_EREPORT_INFO 0x1 /* Ereport has Info field */
#define	MAX_ARRAY_SIZE 20
#define	MAX_CPU_BRAND 40
#define	MAX_INFO_SIZE 400
#define	NO_EREPORT_INFO 0x2 /* Ereport does not have Info field */

struct fps_test_ereport
{
	int expected_size; /* Size of expected array */
	int is_valid_cpu; /* Is a supported CPU */
	int mask; /* Determines which fields are used */
	int observed_size; /* Size of observed array */
	uint32_t cpu_id;
	uint32_t test_id;
	char info[MAX_INFO_SIZE];
	uint64_t observed[MAX_ARRAY_SIZE];
	uint64_t expected[MAX_ARRAY_SIZE];
};

/* fps ereport module functions used by other objects */

int fps_generate_ereport_struct(struct fps_test_ereport *report);
void setup_fps_test_struct(int mask, struct fps_test_ereport *rep, ...);
void free_fps_test_struct(struct fps_test_ereport *free_me);
void initialize_fps_test_struct(struct fps_test_ereport *init_me);

#ifdef __cplusplus
}
#endif

#endif /* _FPS_EREPORT_H */
