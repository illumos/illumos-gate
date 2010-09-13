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
 *
 * ident	"%Z%%M%	%I%	%E% SMI"
 *
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Comment which describes the contents of this file.
 *
 * Constants.java
 * Common constants for Printer Manager
 */

package com.sun.admin.pm.client;

/*
 * pmConstants.java
 * 	defines constants used with print manager
 */

public interface Constants
{
	// Buttons
	int OK = 1;
	int APPLY = 2;
	int RESET = 3;
	int CANCEL = 4;
	int HELP = 5;

	// Buttons for user access list
	int ADD = 6;
	int DELETE = 7;

	// Printer type to add/modify
	int ADDLOCAL = 1;
	int ADDNETWORK = 2;
	int MODIFYATTACHED = 3;
	int MODIFYREMOTE = 4;
	int MODIFYNETWORK = 5;

	// Printer connection types
	int ATTACHED = 1;
	int NETWORK = 2;

	// Useful Constants
	int MAXPNAMELEN = 20;

	// Combo Listener
	int PORT = 1;
	int TYPE = 2;
	int MAKE = 3;
	int MODEL  = 4;
	int PPD  = 5;

}
