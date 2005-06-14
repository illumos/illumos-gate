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
 * ident	"%Z%%M%	%I%	%E% SMI"
 *
 * Copyright (c) 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 *
 * Solaris_ActiveUserProperties.java
 */

package com.sun.wbem.solarisprovider.srm;

/**
 * Defines property names of the Solaris_ActiveUse class and
 * the corresponding keys in the RDS protocol
 */

public interface Solaris_ActiveUserProperties {
    /** The name of the user name property */
    static final String USERNAME = "UserName";
    static final String USERNAME_KEY = "usr_name";
    /** The name of the user ID property */
    static final String USERID = "UserID";
    static final String USERID_KEY = "usr_id";
}
