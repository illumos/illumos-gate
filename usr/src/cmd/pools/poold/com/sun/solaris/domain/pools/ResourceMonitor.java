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

package com.sun.solaris.domain.pools;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Iterator;
import com.sun.solaris.service.pools.Component;
import com.sun.solaris.service.pools.Resource;
import com.sun.solaris.service.pools.PoolsException;
import com.sun.solaris.service.pools.UnsignedInt64;

/**
 * This represents a monitored resource and the techniques used to
 * monitor the resource.
 */
class ResourceMonitor extends HashMap
{
	/**
	 * The monitored resource.
	 */
	private Resource target;

	/**
	 * The size of the statistic buffer.
	 */
	private final int maxSize;

	/**
	 * Cached list of components to be monitored.
	 */
	private LinkedList compList;

	/**
	 * Constructor. No monitor target and a default buffer size of
	 * 50.
	 */
	public ResourceMonitor()
	{
		this(null, 50);
	}

	/**
	 * Constructor.
	 *
	 * @param target The resource to be monitored.
	 * @param maxSize The maximum number of samples to be held.
	 */
	public ResourceMonitor(Resource target, int maxSize)
	{
		super();
		this.target = target;
		this.maxSize = maxSize;
		compList = new LinkedList();

	}

	/**
	 * Initialize the resource monitor with it's list of
	 * components. Components which are off-line or powered-off
	 * cannot be monitored, so they should be removed from the
	 * list of components.
	 *
	 * @throws PoolsException if there is an error accessing the
	 * pool elements.
	 */
	public void initialize() throws PoolsException
	{
		compList.clear();
		List candidates = target.getComponents(null);
		Iterator candIt = candidates.iterator();
		while (candIt.hasNext()) {
			Component comp = (Component) candIt.next();
			String status = comp.getStringProperty("cpu.status");
			if (status.compareTo("off-line") != 0 &&
			    status.compareTo("powered-off") != 0)
				compList.add(comp);
		}
	}

	/**
	 * Get the list of components which are actively monitored by
	 * this resource.
	 */
	public List getComponents()
	{
		return ((List) compList.clone());
	}

	/**
	 * Return the maximum number of samples this monitor will
	 * hold.
	 */
	public int getMaxSampleSize()
	{
		return (maxSize);
	}

	/**
	 * Return the object which is being monitored.
	 */
	public Resource getMonitored()
	{
		return (target);
	}

	/**
	 * Set the resource to be monitored. A resource target can
	 * only be set once, if you attempt to modify it then an
	 * IllegalArgumentException is thrown.
	 *
	 * @param target The resource to be monitored.
	 * @throws IllegalArgumentException if the target has already
	 * been set.
	 */
	public void setResource(Resource target)
	{
		if (this.target != null)
			this.target = target;
		else
			throw new IllegalArgumentException("Once the target " +
			    "of a ResourceMonitor is set, it cannot be " +
			    "changed.");
	}

	/**
	 * Return the name of the monitored object.
	 *
	 * @throws PoolsException if there is an error accessing the
	 * pool element.
	 */
	public String getName() throws PoolsException
	{
		String type = target.getStringProperty("type");
		return (target.getStringProperty(type + ".name"));
	}

	/**
	 * Update the derived statistics.
	 */
	public void updateDerived()
	{
		StatisticList util = (StatisticList) get("utilization");
		AggregateStatistic stat = calcDerivedStatistic("utilization");
		if (stat != null)
			util.add(stat);
	}

	/**
	 * Get a derived statistic.
	 *
	 * @param name The name of the statistic to get.
	 */
	public AggregateStatistic getDerivedStatistic(String name)
	{
		return ((AggregateStatistic)((StatisticList)get(name)).
		    getLast());
	}

	/**
	 * Return the latest value of a derived statistic.
	 *
	 * @param name is the name of the derived statistic to be
	 * returned.
	 */
	private AggregateStatistic calcDerivedStatistic(String name)
	{
		/*
		 * The only statistic which can be obtained from this
		 * resource monitor is utilization. A utilization
		 * statistic actually represents a complex
		 * manipulation of several lower level
		 * statistics. This manipulation is performed here
		 * until a good interface can be thought through which
		 * best captures this abstraction.
		 */
		if (name.compareTo("utilization") != 0)
			throw new IllegalArgumentException("No such derived "
			    + "statistic: " + name);
		/*
		 * This statistic is based on lower level
		 * monotonically increasing numbers. The statistic can
		 * thus only be derived as an observation of the
		 * change in value over time of these values.
		 */

		StatisticList first = (StatisticList) get("idle");

		switch (first.size()) {
		case 0:
		case 1:
			return (null);
		default:
			BigInteger total = new BigInteger("0");
			double utilV = 0.0;
			double idleV = 0.0;
			LinkedList keys = new LinkedList(keySet());
			keys.remove("utilization");
			for (int i = 0; i < keys.size(); i++) {
				StatisticList sl = (StatisticList) get(keys.
				    get(i));
				AggregateStatistic sv1 = (AggregateStatistic)
				    sl.getLast();
				AggregateStatistic sv2 = (AggregateStatistic)
				    sl.get(sl.size() - 2);
				if (sl.getName().compareTo("idle") == 0)
					idleV = ((UnsignedInt64) sv1.
					    subtract(sv2).getValue()).
					    doubleValue();
				total = total.add((UnsignedInt64) sv1.
				    subtract(sv2).getValue());
			}
			utilV = 100 * ((total.doubleValue() - idleV) /
			    total.doubleValue());
			return (new DoubleStatistic(new Double(utilV),
				((AggregateStatistic)first.get(first.size() -
				2)).getStart(), ((AggregateStatistic)first.
				getLast()).getEnd()));
		}
	}

	void resetData(String name)
	{
		StatisticList sl = (StatisticList) get(name);
		sl.clear();
	}
}
