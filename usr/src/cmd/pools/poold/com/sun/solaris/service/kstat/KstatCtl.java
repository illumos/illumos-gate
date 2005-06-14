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
 *
 * ident	"%Z%%M%	%I%	%E% SMI"
 */

package com.sun.solaris.service.kstat;

/**
 * <code>kstat</code> controlling object.  Allows kstats to be looked up
 * so they can later be sampled.
 */
public final class KstatCtl
{
	static {
		System.loadLibrary("jkstat");
		KstatCtl.init();
	}

	/**
	 * Pointer to a <code>kstat_ctl_t</code>.
	 */
	private long kctl;

	/**
	 * Invokes <code>kstat_open(3KSTAT)</code>.  The returned object
	 * should be explicitly finalized when it's no longer needed.
	 */
	public KstatCtl()
	{
		kctl = open();
		assert(kctl != 0);
	}

	/**
	 * Calls <code>kstat_close(3KSTAT)</code>.
	 */
	public void finalize()
	{
		close(kctl);
		kctl = 0;
	}

	/**
	 * Invokes <code>kstat_open(3KSTAT)</code>.
	 */
	private native long open();

	/**
	 * Invokes <code>kstat_close(3KSTAT)</code>.
	 */
	private native int close(long kctl);

	/**
	 * Invokes <code>kstat_lookup(3KSTAT)</code> and returns a Kstat
	 * for any result, or null if none is found.
	 */
	public native Kstat lookup(String module, int instance, String name);

	/**
	 * Invokes <code>kstat_chain_update(3KSTAT)</code>.
	 *
	 * @throws KstatChainUpdateException if the native function
	 * returns -1.
	 */
	public native void chainUpdate() throws KstatChainUpdateException;

	/**
	 * Initialize cached class, method, and field IDs.
	 */
	private static native void init();
}
