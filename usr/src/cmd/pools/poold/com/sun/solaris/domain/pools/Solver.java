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
 *
 */

package com.sun.solaris.domain.pools;

import java.util.Set;

import com.sun.solaris.service.pools.Configuration;
import com.sun.solaris.service.pools.Element;
import com.sun.solaris.service.pools.PoolsException;

/**
 * This interface specifies the contract between poold and the poold
 * allocation algorithms.
 */

public interface Solver {
	/**
	 * Initialize the solver.
	 *
	 * @param conf The configuration to be manipulated.
	 * @throws PoolsException If the initialization fails.
	 */
	public void initialize(Configuration conf) throws PoolsException;

	/**
	 * Evaluate whether a workload based reconfiguration is
	 * required.
	 *
	 * @param mon The monitor to be used during examination.
	 * @throws PoolsException If the examination fails.
	 * @throws StaleMonitorException If the monitor is stale.
	 */
	public boolean examine(Monitor mon) throws PoolsException,
	    StaleMonitorException;

	/**
	 * Allocate resources. Return true if a change was made.
	 *
	 * @throws Exception If the solve fails.
	 */
	public boolean solve() throws Exception;

	/**
	 * Return true if all examined resources are capable of
	 * providing statistically valid data.
	 *
	 * If any of the monitored resources have not accumulated
	 * enough data to be statistically significant, then this
	 * monitor is not ready to be used to obtain data for all
	 * resources. In this case, false is returned.
	 *
	 */
	public boolean isValid();

	/**
	 * Return a reference to the monitor which this solver is
	 * using to provide statistics about the configuration which
	 * is to be solved.
	 */
	public Monitor getMonitor();

	/**
	 * Return the set of objectives associated with the supplied
	 * element.
	 *
	 * @param elem Retrieve objectives for this element.
	 */
	public Set getObjectives(Element elem);
}
