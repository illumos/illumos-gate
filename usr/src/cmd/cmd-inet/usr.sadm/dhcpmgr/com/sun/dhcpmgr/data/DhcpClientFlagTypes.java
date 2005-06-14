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
 */

package com.sun.dhcpmgr.data;

/**
 * This class contains definitiion for all the valid DHCP client flags.
 */
public class DhcpClientFlagTypes {

    public static final DhcpClientFlagType BOOTP =
	new DhcpClientFlagType((byte)8, 'B', new String("BOOTP"));

    public static final DhcpClientFlagType UNUSABLE =
	new DhcpClientFlagType((byte)4, 'U', new String("UNUSABLE"));

    public static final DhcpClientFlagType MANUAL =
	new DhcpClientFlagType((byte)2, 'M', new String("MANUAL"));

    public static final DhcpClientFlagType PERMANENT =
	new DhcpClientFlagType((byte)1, 'P', new String("PERMANENT"));

    public static final DhcpClientFlagType DYNAMIC =
	new DhcpClientFlagType((byte)0, 'D', new String("DYNAMIC"));
}
