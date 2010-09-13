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

import com.sun.solaris.service.pools.*;

/**
 * Wraps <code>libkstat(3lib)</code>.  See
 * <code>/usr/include/sys/kstat.h</code> for details.
 */
public final class Kstat {
	/**
	 * Pointer to native <code>kstat_ctl_t</code>.
	 */
	private long kctl;

	/**
	 * Pointer to native <code>kstat_t</code>.
	 */
	private long ksp;

	Kstat(long kctl, long ksp)
	{
		this.kctl = kctl;
		this.ksp = ksp;
	}

	/**
	 * Returns the kstat's <code>ks_snaptime</code> field.
	 */
	public native HRTime getSnapTime();

	/**
	 * Returns the kstat's <code>ks_crtime</code> field.
	 */
	public native HRTime getCreationTime();

	/**
	 * Returns the named value -- the value of the named kstat, or
	 * field in a raw kstat, as applicable, and available.  Returns
	 * <i>null</i> if no such named kstat or field is available.
	 *
	 * @throws KstatTypeNotSupportedException if the raw kstat is not
	 * understood.  (Presenstly, none are.)
	 */
	public native Object getValue(String name)
	    throws KstatTypeNotSupportedException;

	/**
	 * Invokes <code>kstat_read(3kstat)</code> for tho underlying kstat.
	 * Throws KstatException if the native function returns an error.
	 */
	public native void read() throws KstatReadException;
}
