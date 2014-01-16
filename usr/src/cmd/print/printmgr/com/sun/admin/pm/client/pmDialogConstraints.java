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
 *
 * ident	"%Z%%M%	%I%	%E% SMI"
 *
 * Copyright(c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 *
 * pmDialogConstraints.java
 * Location constants for pmDialogs.
 */

package com.sun.admin.pm.client;

public interface pmDialogConstraints {

    /* 
     * These are offsets from origin of a pmDialog's parent frame 
     * at which to place the newly created dialog.
     */ 
    static final int xoffset = 100;
    static final int yoffset = 80;
}
