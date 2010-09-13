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
 * Copyright (c) 2006, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#define	XXX_emulation_table		sn1_emulation_table
#define	XXX_brand_syscall32_callback	sn1_brand_syscall32_callback
#define XXX_brand_syscall_callback	sn1_brand_syscall_callback
#define XXX_brand_sysenter_callback	sn1_brand_sysenter_callback
#define XXX_brand_int91_callback	sn1_brand_int91_callback

#include "../common/brand_solaris.s"
