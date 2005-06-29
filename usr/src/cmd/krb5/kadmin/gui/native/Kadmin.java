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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

public class Kadmin {

	/**
	 * Static block to load "libkadmin.so"
	 */
	static { System.loadLibrary("kadmin"); }

	/**
	 * Initialize the kadmin session with the passed arguments
	 */
	public native boolean sessionInit(String name, String password,
		String realm, String server, int port);

	/**
	 * Terminate the kadmin session gracefully
	 */
	public native void sessionExit();

	/**
	 * Get the ACL setting for the logged in principal
	 */
	public native int getPrivs();

	/**
	 * Get the complete enc type list
	 */
	public native String[] getEncList();

	/**
	 * Get the complete principal list
	 */
	public native String[] getPrincipalList();

	/**
	 * Get the complete principal list in one string
	 */
	public native String getPrincipalList2();

	/**
	 * Load the selected principal
	 */
	public native boolean loadPrincipal(String name, Principal p);

	/**
	 * Save the selected principal
	 */
	public native boolean savePrincipal(Principal p);

	/**
	 * Create a new principal
	 */
	public native boolean createPrincipal(Principal p);

	/**
	 * Delete the selected principal
	 */
	public native boolean deletePrincipal(String name);

	/**
	 * Get the complete policy list
	 */
	public native String[] getPolicyList();

	/**
	 * Load the selected policy
	 */
	public native boolean loadPolicy(String name, Policy p);

	/**
	 * Save the selected policy
	 */
	public native boolean savePolicy(Policy p);

	/**
	 * Create a new policy
	 */
	public native boolean createPolicy(Policy p);

	/**
	 * Delete the selected policy
	 */
	public native boolean deletePolicy(String name);
}
