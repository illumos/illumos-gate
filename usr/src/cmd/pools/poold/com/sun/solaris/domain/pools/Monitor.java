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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 *ident	"%Z%%M%	%I%	%E% SMI"
 */

package com.sun.solaris.domain.pools;

import java.util.Map;

import com.sun.solaris.service.pools.Configuration;
import com.sun.solaris.service.pools.Resource;
import com.sun.solaris.service.pools.PoolsException;

/**
 * A monitoring class. The user of this interface can retrieve
 * monitoring information related to the configuration which is
 * examined.
 */

public interface Monitor {
	/**
	 * Initialize the monitoring object using details from the
	 * supplied configuration.
	 *
	 * @param conf The configuration to be monitored.
	 * @throws PoolsException If the initialize fails.
	 * @throws StaleMonitorException If the resource monitors
	 * cannot be accessed.
	 */
	public void initialize(Configuration conf) throws PoolsException,
	    StaleMonitorException;

	/**
	 * Return the next sample.
	 *
	 * This call is a blocking call. The sample will only be
	 * returned after pausing the invoking thread for the "sample
	 * interval".
	 *
	 * @throws StaleMonitorException If the sample fails.
	 * @throws PoolsException If there is an error manipulating the
	 * pools configuration.
	 * @throws InterruptedException If the thread is interrupted
	 * while waiting for the sampling time to arrive.  The caller
	 * may wish to check other conditions before possibly
	 * reinitiating the sample.
	 */
	public void getNext() throws StaleMonitorException, PoolsException,
	    InterruptedException;

	/**
	 * Return the number of samples taken.  This is the number of
	 * successful calls to <code>getNext()</code>.
	 */
	public int getSampleCount();

	/**
	 * Return the utilization for supplied resource.
	 *
	 * @param res The resource to be examined.
	 *
	 * @throws StaleMonitorException if the resource cannot be accessed.
	 */
	public double getUtilization(Resource res) throws StaleMonitorException;
	public boolean isValid();
	public ResourceMonitor get(Resource res) throws StaleMonitorException;
}

/**
 * Indicates that a monitor must be re-initialized. This can occur
 * for a number of reasons, including:
 *
 * <ul>
 * <li><p>
 * Resources created, modified, destroyed whilst sampling
 * </ul>
 */
class StaleMonitorException extends Exception {
}
