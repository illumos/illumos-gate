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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/param.h>

/*
 * In-Kernel Logical Domain Channel (LDC) Functionality
 *
 * Provides a mechanism for LDC channels to be reset when entering
 * the prom or kmdb by invoking a callback before entry.
 */

/*
 * Setting this to zero disables debug_enter/debug_exit callbacks
 * which may be useful when debugging LDC related issues.
 */
static int kldc_callback_enabled = 1;

/*
 * Callback function pointer.
 */
static void (*kldc_debug_enter_cb)(void);

void
kldc_set_debug_cb(void (*debug_enter_cb)(void))
{
	kldc_debug_enter_cb = debug_enter_cb;
}

/*
 * Called just before entering the prom or kmdb but after all other CPUs
 * have entered the idle loop.
 */
void
kldc_debug_enter(void)
{
	if (kldc_callback_enabled != 0 && kldc_debug_enter_cb != NULL) {
		(*kldc_debug_enter_cb)();
	}
}
