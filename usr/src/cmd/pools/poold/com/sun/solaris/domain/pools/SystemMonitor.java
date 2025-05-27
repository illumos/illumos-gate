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
 * ident	"%Z%%M%	%I%	%E% SMI"
 */

package com.sun.solaris.domain.pools;

import java.math.BigInteger;
import java.text.DecimalFormat;
import java.util.*;
import java.util.logging.*;

import com.sun.solaris.service.kstat.*;
import com.sun.solaris.service.logging.Severity;
import com.sun.solaris.domain.pools.*;
import com.sun.solaris.service.pools.*;
import com.sun.solaris.service.timer.*;

/**
 * Regularly samples the objective-related utilization statistics of
 * the resource in the pool with the given configuration.
 */
class SystemMonitor implements Monitor
{
	/**
	 * The pool configuration with resources to be monitored.
	 */
	private Configuration conf;

	/**
	 * The map of monitored resources.The map is keyed by
	 * resource, with the values being the monitorable instances.
	 */
	private Map monitored;

	/**
	 * Default sample interval (milliseconds).
	 */
	public static final int DEF_SAMPLE_INT = 15000;

	/**
	 * Sample interval (milliseconds, default 15000).
	 */
	private int interval;

	/**
	 * Sample interval property name.
	 */
	static final String SAMPLE_INTERVAL_PROP_NAME =
	    "system.poold.monitor-interval";

	/**
	 * Kstat interface for raw data
	 */
	private KstatCtl kc;

	/**
	 * Raw statistics which are sampled each interval.
	 */
	private final String stats[] = { "idle", "kernel", "wait", "user" };

	/**
	 * Timer regulating sampling frequency.
	 */
	private RecurringEventTimer timer;

	/**
	 * The number of samples taken.
	 */
	private int sampleCount = 0;

	/**
	 * Time the last sample was taken.
	 */
	private Date lastSampleTime = null;

	/**
	 * Constructs a new monitor which is not associated with a
	 * specific configuration.
	 */
	public SystemMonitor()
	{
		this(null);
	}

	/**
	 * Constructs a new Monitor for monitoring the resources in the
	 * given configuration using the given statistic source.
	 *
	 * @param conf The configuration which is monitored.
	 */
	public SystemMonitor(Configuration conf)
	{
		this.conf = conf;
		monitored = new HashMap();
		kc = new KstatCtl();
	}

	/**
	 * Initialize the monitor with the configuration which is to
	 * be monitored.
	 *
	 * @param conf The configuration which is monitored.
	 *
	 * @throws PoolsException if manipulating the configuration
	 * fails.
	 * @throws StaleMonitorException if the resource monitors
	 * cannot be set.
	 */
	public void initialize(Configuration conf) throws PoolsException,
	    StaleMonitorException
	{
		Poold.CONF_LOG.log(Severity.DEBUG, "initializing");
		this.conf = conf;
		try {
			kc.chainUpdate();
		} catch (KstatChainUpdateException kcue) {
			Poold.utility.die(Poold.CONF_LOG, kcue);
		}

		try {
			interval = (int)conf.getLongProperty(
			    SAMPLE_INTERVAL_PROP_NAME);
		} catch (PoolsException pe) {
			interval = DEF_SAMPLE_INT;
		}
		timer = new SimpleRecurringEventTimer(interval);

		setResourceMonitors("pset");
	}

	/**
	 * Add all resources of the supplied type in the monitored
	 * configuration to the set of monitored resources. Remove
	 * redundant monitors for resources which no longer exist.
	 * Don't monitor resource sets which are empty.
	 *
	 * @param type The type of the resources to be added
	 */
	private void setResourceMonitors(String type) throws PoolsException,
	    StaleMonitorException
	{
		Value val = new Value("type", type);

		List valueList = new LinkedList();
		valueList.add(val);
		Iterator resIt = conf.getResources(valueList).iterator();
		val.close();
		HashSet oldKeys = new HashSet(monitored.keySet());
		while (resIt.hasNext()) {
			Resource res = (Resource)resIt.next();
			ResourceMonitor mon = null;
			boolean activeComponents = false;

			List compList = res.getComponents(null);
			Iterator compIt = compList.iterator();
			while (compIt.hasNext()) {
				Component comp = (Component) compIt.next();
				String status = comp.getStringProperty(
				    "cpu.status");
				if (status.compareTo("off-line") != 0 &&
			    	    status.compareTo("powered-off") != 0) {
					activeComponents = true;
					break;
				}
			}
			if (activeComponents == false)
				continue;

			if (monitored.containsKey(res)) {
				mon = get(res);
				for (int i = 0; i < stats.length; i++)
					mon.resetData(stats[i]);
			} else {
				mon = new ResourceMonitor(res, 50);
				for (int i = 0; i < stats.length; i++) {
					StatisticList sl = new StatisticList(
					    stats[i], 2);
					mon.put(stats[i], sl);
				}
				mon.put("utilization", new StatisticList(
				    "utilization", mon.getMaxSampleSize(),
				    true));
				monitored.put(res, mon);
			}
			mon.initialize();
			oldKeys.remove(res);
		}
		monitored.keySet().removeAll(oldKeys);
	}

	/**
	 * Get the next sample. Before obtaining the sample, the call
	 * will block for the interval which was specified when this
	 * monitor was initialized.
	 *
	 * @throws StaleMonitorException if a statistic cannot be obtained.
	 * @throws PoolsException if there is an error manipulating the
	 * pools configuration.
	 * @throws InterruptedException if the thread is interrupted
	 * while waiting for the sampling time to arrive.  The caller
	 * may wish to check other conditions before possibly
	 * reinitiating the sample.
	 */
	public void getNext() throws StaleMonitorException, PoolsException,
	    InterruptedException
	{
		Poold.MON_LOG.log(Severity.DEBUG, "waiting sampling interval");

		Date start = lastSampleTime;
		if (start == null)
			start = new Date();

		timer.waitUntilNextFiring();
		Date end = new Date();

		Poold.MON_LOG.log(Severity.DEBUG, "sampling");
		Iterator itMon = monitored.values().iterator();
		while (itMon.hasNext()) {
			ResourceMonitor mon = (ResourceMonitor) itMon.next();
			List compList = mon.getComponents();
			Iterator itComp = compList.iterator();
			BigInteger statsv[] = new BigInteger[4];
			while (itComp.hasNext()) {
				Component cpu = (Component) itComp.next();
				Kstat kstat = kc.lookup("cpu",
				    (int) cpu.getLongProperty("cpu.sys_id"),
				    "sys");
				if (kstat == null)
					throw new StaleMonitorException();
				UnsignedInt64 value;
				try {
					kstat.read();
					for (int i = 0; i < stats.length; i++) {
						value = (UnsignedInt64) kstat.
						    getValue("cpu_ticks_" +
						    stats[i]);
						if (value == null)
							throw new
							StaleMonitorException();
						if (statsv[i] == null)
							statsv[i] = value;
						else
							statsv[i] = statsv[i].
							    add(value);
					}
				} catch (KstatException ke) {
					StaleMonitorException sme =
					    new StaleMonitorException();
					sme.initCause(ke);
					Poold.MON_LOG.log(Severity.DEBUG,
					    "configuration necessary due to "
					    + ke);
					throw(sme);
				}
			}
			if (compList.isEmpty() == false) {
				for (int i = 0; i < stats.length; i++) {
					StatisticList sl;
					sl = (StatisticList) mon.get(stats[i]);
					sl.add(new UnsignedInt64Statistic(
					    new UnsignedInt64(statsv[i].
					    divide(new BigInteger(
					    Integer.toString(
					    compList.size())))),
					    start, end));
				}
			}
			mon.updateDerived();
		}

		sampleCount++;
		lastSampleTime = end;
	}

	/**
	 * Return the number of samples taken.  This is the number of
	 * successful calls to <code>getNext()</code>.
	 */
	public int getSampleCount()
	{
		return (sampleCount);
	}

	/**
	 * Return the utilization of the supplied resource. The
	 * utilization is represented as a percentage between 0
	 * and 100.
	 *
	 * @param res A reference to a configuration resource.
	 */
	public double getUtilization(Resource res) throws StaleMonitorException
	{
		ResourceMonitor mon = get(res);
		DoubleStatistic util = null;
		try {
			util = (DoubleStatistic)mon.getDerivedStatistic(
			    "utilization");
		} catch (NoSuchElementException nsee) {
			util = new DoubleStatistic(Double.valueOf(0));
		}
		Poold.MON_LOG.log(Severity.DEBUG,
		    res + " utilization " + util.toString());
		return (((Double)util.getValue()).doubleValue());
	}

	/**
	 * Return true if the system contains enough sampled data for
	 * monitoring to be worthwhile.
	 */
	public boolean isValid()
	{
		Iterator itMon = monitored.values().iterator();
		while (itMon.hasNext()) {
			ResourceMonitor mon = (ResourceMonitor) itMon.next();

			Iterator itSL = mon.values().iterator();
			while (itSL.hasNext()) {
				StatisticList sl = (StatisticList) itSL.next();
				if (sl.getName().compareTo("utilization") ==
				    0) {
					if (sl.isValid() == false)
						return (false);
				}
			}
		}
		return (true);
	}

	/**
	 * Return the ResourceMonitor for the supplied Resource
	 *
	 * @throws StaleMonitorException if the ResourceMonitor cannot be found.
	*/
	public ResourceMonitor get(Resource res) throws StaleMonitorException
	{
		ResourceMonitor rm = (ResourceMonitor)monitored.get(res);

		if (rm == null)
			throw new StaleMonitorException();
		return (rm);
	}
}
