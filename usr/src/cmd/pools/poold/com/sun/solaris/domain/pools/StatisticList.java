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


import java.util.*;
import java.text.DecimalFormat;

import com.sun.solaris.service.logging.*;

/**
 * Contains information about statistics. An instance must only
 * contain Statistics of the same type.
 */
class StatisticList extends LinkedList
{
	/**
	 * The name of the statistic.
	 */
	private final String name;

	/**
	 * The maximum number of samples to be stored.
	 */
	private final int maxSize;

	/**
	 * The list of StatisticListeners.
	 */
	private List listeners;

	/**
	 * Statistically assess utilization.
	 */
	private StatisticOperations statisticOperations;

	/**
	 * Constructor.
	 */
	public StatisticList()
	{
		this("default", 10);
	}

	/**
	 * Constructor. Statistics will not be held for this set.
	 *
	 * @param name is the name of the contained statistics
	 * @param size is the maximum number of statistics to hold
	 */
	public StatisticList(String name, int size)
	{
		this(name, size, false);
	}

	/**
	 * Constructor.
	 *
	 * @param name is the name of the contained statistics
	 * @param size is the maximum number of statistics to hold
	 * @param doStats indicates whether or not statistics should
	 * be calculated for the data.
	 */
	public StatisticList(String name, int size, boolean doStats)
	    throws IllegalArgumentException
	{
		super();
		this.name = name;
		if (size < 1)
			throw new IllegalArgumentException("Size must be > 0");
		this.maxSize = size;
		listeners = new LinkedList();
		if (doStats) {
			statisticOperations = new StatisticOperations(this);
			addStatisticListener(statisticOperations);
		}
	}

	/**
	 * Return the name of the Statistics being sampled.
	 */
	public String getName()
	{
		return (name);
	}

	/**
	 * Return a "snapshot" which is the aggregation of all
	 * statistic records.
	 *
	 * @throws NoSuchElementException if there is an error
	 * accessing a list member.
	 */
	public AggregateStatistic getSnapshot()
	    throws NoSuchElementException
	{
		return (getSnapshotForInterval(iterator(), null, null));
	}

	/**
	 * Return a "snapshot" of the data using the supplied
	 * iterator.
	 *
	 * @param it An iterator over the contained elements to be
	 * used as the basis for the snapshot.
	 * @throws NoSuchElementException if there is an error
	 * accessing a list member.
	 */
	private AggregateStatistic getSnapshot(Iterator it)
	    throws NoSuchElementException
	{
		return (getSnapshotForInterval(it, null, null));
	}

	/**
	 * Returns the aggregated value for the StatisticList only
	 * including samples which satisfy the start and end criteria.
	 *
	 * @param start start time or null if unspecified.
	 * @param end end time or null if unspecified.
	 * @throws NoSuchElementException if there is an error
	 * accessing a list member.
	 */
	public AggregateStatistic getSnapshotForInterval(Date start,
	    Date end) throws NoSuchElementException

	{
		return (getSnapshotForInterval(iterator(), start, end));
	}

	/**
	 * Returns the aggregated value for the StatisticList only
	 * including samples which satisfy the start and end criteria.
	 *
	 * @param it An iterator over the contained elements to be
	 * used as the basis for the snapshot.
	 * @param start start time or null if unspecified.
	 * @param end end time or null if unspecified.
	 * @throws NoSuchElementException if there is an error
	 * accessing a list member.
	 */
	private AggregateStatistic getSnapshotForInterval(Iterator it,
	    Date start, Date end)
	{
		AggregateStatistic f = (AggregateStatistic) getFirst();
		return (f.getSnapshotForInterval(it, start, end));
	}

	/**
	 * Add the supplied object to the list. If the list is full,
	 * remove the first entry before adding the new entry.
	 *
	 * @param o Object to add to the list.
	 */
	public boolean add(Object o)
	{
		boolean ret;
		if (size() == maxSize)
			removeFirst();
		ret = super.add(o);
		if (ret)
			notifyStatisticAdd((AggregateStatistic) o);
		return (ret);
	}

	/**
	 * Remove the supplied object from the list.
	 *
	 * @param o Object to remove from the list.
	 */
	public boolean remove(Object o)
	{
		boolean ret;
		ret = super.remove(o);
		if (ret)
			notifyStatisticRemove((AggregateStatistic) o);
		return (ret);
	}

	/**
	 * Removes and returns the first element from this list.
	 *
	 * @return the first element from this list.
	 * @throws	  NoSuchElementException if this list is empty.
	 */
	public Object removeFirst() {
		Object first = getFirst();
		remove(first);
		return (first);
	}

	/**
	 * Add a listener for StatisticEvents.
	 *
	 * @param l Listener to add.
	 */
	public void addStatisticListener(StatisticListener l) {
		listeners.add(l);
	}

	/**
	 * Remove a listener for StatisticEvents.
	 *
	 * @param l Listener to remove.
	 */
	public void removeStatisticListener(StatisticListener l) {
		listeners.remove(l);
	}

	/**
	 * Notify all StatisticEvent listeners of a new Add event.
	 *
	 * @param s Event payload.
	 */
	private void notifyStatisticAdd(AggregateStatistic s)
	{
		StatisticEvent e = new StatisticEvent(this,
		    StatisticEvent.ADD, s);

		Iterator listIt = listeners.iterator();

		while (listIt.hasNext()) {

			StatisticListener l = (StatisticListener)listIt.next();
			l.onStatisticAdd(e);
		}
	}

	/**
	 * Notify all StatisticEvent listeners of a new Remove event.
	 *
	 * @param s Event payload.
	 */
	private void notifyStatisticRemove(AggregateStatistic s)
	{
		StatisticEvent e = new StatisticEvent(this,
		    StatisticEvent.REMOVE, s);

		Iterator listIt = listeners.iterator();

		while (listIt.hasNext()) {

			StatisticListener l = (StatisticListener)listIt.next();
			l.onStatisticRemove(e);
		}
	}

	/**
	 * Return true if the contents of the instance are
	 * statistically valid.
	 */
	boolean isValid()
	{
		return (statisticOperations.isValid());
	}

	/**
	 * Return the zone of control to which the supplied val
	 * belongs based on the target details in the supplied
	 * objective expression.
	 *
	 * @param kve Objective expression used to determine zone
	 * details.
	 * @param val The value to be assessed.
	 */
	int getZone(KVOpExpression kve, double val)
	{
		return (statisticOperations.getZone(kve, val));
	}

	/**
	 * Return the zone of control to which the supplied val
	 * belongs based on the mean of the sampled data.
	 *
	 * @param val The value to be assessed.
	 */
	int getZoneMean(double val)
	{
		return (statisticOperations.getZoneMean(val));
	}

	/**
	 * Return the difference (gap) between the target utilization
	 * expressed in the supplied objective expression and the
	 * supplied value.
	 *
	 * @param kve Objective expression used to determine target
	 * utilization details.
	 * @param val The value to be assessed.
	 */
	double getGap(KVOpExpression kve, double val)
	{
		return (statisticOperations.getGap(kve, val));
	}

	/**
	 * Clear all the data from the StatisticList and reset all the
	 * statistic counters.
	 */
	public void clear()
	{
		if (statisticOperations != null) {
			removeStatisticListener(statisticOperations);
			statisticOperations = new StatisticOperations(this);
			addStatisticListener(statisticOperations);
		}
		super.clear();
	}

	/**
	 * Return a string which describes the zones for this set of
	 * data.
	 *
	 * @param kve The expression containing objectives.
	 * @param val The value to be assessed against objectives.
	 */
	public String toZoneString(KVOpExpression kve, double val)
	{
		return (statisticOperations.toZoneString(kve, val));
	}
}

/**
 * Event class which describes modifications (Add, Remove) to a
 * StatisticList instance.
 */
final class StatisticEvent extends EventObject
{
	/**
	 * Identifier for an ADD event.
	 */
	public static final int ADD = 0x1;

	/**
	 * Identifier for a REMOVE event.
	 */
	public static final int REMOVE = 0x2;

	/**
	 * The target of the event.
	 */
	private final AggregateStatistic target;

	/**
	 * The identifier of this event.
	 */
	private final int id;

	/**
	 * Constructor.
	 *
	 * @param source The source of the event.
	 * @param id The type of the event.
	 * @param target The target of the event.
	 */
	public StatisticEvent(Object source, int id, AggregateStatistic target)
	{
		super(source);
		this.id = id;
		this.target = target;
	}

	/**
	 * Return the target of the event.
	 */
	public AggregateStatistic getTarget()
	{
		return (target);
	}

	/**
	 * Return the ID (type) of the event.
	 */
	public int getID()
	{
		return (id);
	}

	/**
	 * Return the source of the event. This is a typesafe
	 * alternative to using getSource().
	 */
	public StatisticList getStatisticList()
	{
		return ((StatisticList) source);
	}

}

/**
 * The listener interface for receiving statistic events. The class
 * that is interested in processing a statistic event implements this
 * interface, and the object created with that class is registered
 * with a component, using the component's addStatisticListener
 * method. When the statistic event occurs, the relevant method in the
 * listener object is invoked, and the StatisticEvent is passed to it.
 */
interface StatisticListener extends EventListener
{
	/**
	 * Invoked when a statistic is added to the source
	 * StatisticList.
	 *
	 * @param e The event.
	 */
	public void onStatisticAdd(StatisticEvent e);

	/**
	 * Invoked when a statistic is removed from the source
	 * StatisticList.
	 *
	 * @param e The event.
	 */
	public void onStatisticRemove(StatisticEvent e);
}

/**
 * This class performs statistical calculations on a source
 * StatisticList. Zones are regions in a set of samples which are set
 * to be at 1, 2 and 3 standard deviations from the mean. ZONEC is
 * closest to the center, with ZONEZ representing the region beyond
 * ZONEA.
 */
class StatisticOperations implements StatisticListener
{
	/**
	 * Control zone C.
	 */
	public static final int ZONEC = 0x00010;

	/**
	 * Control zone B.
	 */
	public static final int ZONEB = 0x00100;

	/**
	 * Control zone A.
	 */
	public static final int ZONEA = 0x01000;

	/**
	 * Control zone Z.
	 */
	public static final int ZONEZ = 0x10000;

	/**
	 * Direction from mean (used to test ZONELT and ZONEGT).
	 */
	public static final int ZONET = 0x00001;

	/**
	 * Less than the mean.
	 */
	public static final int ZONELT = 0x00000;

	/**
	 * Greater than the mean.
	 */
	public static final int ZONEGT = 0x00001;

	/**
	 * The raw statistical data.
	 */
	private final StatisticList statistics;

	/**
	 * The mean of the samples.
	 */
	private double mean;

	/**
	 * The standard deviation of the samples.
	 */
	private double sd;

	/**
	 * The total of the samples.
	 */
	private AggregateStatistic total;

	/**
	 * Constructs a new StatisticOperations object for working on
	 * the given statistic, whose values are in the given
	 * (modifiable) data set.
	 *
	 * @param statistics The statistics to operate on.
	 */
	public StatisticOperations(StatisticList statistics)
	{
		this.statistics = statistics;
		total = new DoubleStatistic(new Double(0.0));
	}

	/**
	 * Calculate the standard deviation for the data held in the
	 * associated StatisticsList.
	 */
	private void calc_sd()
	{
		Iterator it;

		sd = 0;
		it = statistics.iterator();
		while (it.hasNext()) {
			Double val = (Double)((DoubleStatistic)
			    ((AggregateStatistic)it.next())).getValue();

			sd += java.lang.Math.pow(val.doubleValue() - mean, 2);
		}
		sd /= statistics.size();
		sd = java.lang.Math.sqrt(sd);
	}

	/**
	 * Return a string which describes the zones for this set of
	 * data.
	 *
	 * @param kve The expression containing objectives.
	 * @param val The value to be assessed against objectives.
	 */
	public String toZoneString(KVOpExpression kve, double val)
	{
		if (isValid()) {
			DecimalFormat f = new DecimalFormat("00.00");
			double target = kve.getValue();

			if (kve.getOp() == KVOpExpression.LT) {
				target -= 3 * sd;
			} else if (kve.getOp() == KVOpExpression.GT) {
				target += 3 * sd;
			}
			StringBuffer buf = new StringBuffer();
			buf.append(kve.toString());
			buf.append("\nsample = " + statistics.size());
			buf.append("\n\ttarget: " + f.format(target));
			buf.append("\n\tvalue: " + f.format(val));
			buf.append("\n\tsd: " + f.format(sd));
			buf.append("\n\tZones:");
			buf.append("\n\t\tC:" + f.format(target - sd));
			buf.append("-" + f.format(target + sd));
			buf.append("\n\t\tB:" + f.format(target - 2 * sd));
			buf.append("-" + f.format(target + 2 * sd));
			buf.append("\n\t\tA:" + f.format(target - 3 * sd));
			buf.append("-" + f.format(target + 3 * sd));
			return (buf.toString());
		} else {
			return ("Still sampling...");
		}
	}


	/**
	 * Return a string which describes this instance.
	 */
	public String toString()
	{
		DecimalFormat f = new DecimalFormat("00.00");

		if (isValid()) {
			return ("sample = " + statistics.size() +
			    "\n\tmean: " + f.format(mean) +
			    "\n\tsd: " + f.format(sd) +
			    "\n\tZones:" +
			    "\n\t\tC:" + f.format(mean - sd) +
			    "-" + f.format(mean + sd) +
			    "\n\t\tB:" + f.format(mean - 2 * sd) +
			    "-" + f.format(mean + 2 * sd) +
			    "\n\t\tA:" + f.format(mean - 3 * sd) +
			    "-" + f.format(mean + 3 * sd));
		} else {
			return ("Still sampling...");
		}
	}

	/**
	 * Return true if the data is normally distributed. This
	 * method currently just returns true if the sample size is >=
	 * 5. It could be extended to use a test of normality, for
	 * instance "Pearson's Chi-Squared Test" or "Shapiro-Wilks W
	 * Test".
	 */
	public boolean isValid()
	{
		if (statistics.size() >= 5)
			return (true);
		return (false);
	}

	/**
	 * Calculate the statistical values for the associated
	 * samples. This method should be called when the sample
	 * population changes.
	 */
	private final void process()
	{
		mean = ((Double)((DoubleStatistic)total).getValue()).
		    doubleValue() / statistics.size();
		calc_sd();
	}

	/**
	 * Return the control zone for the supplied value using the
	 * information derived from the monitored statistics and the
	 * objective expressed in the supplied objective expression.
	 *
	 * @param kve The target utilization expression.
	 * @param val The value to be evaluated.
	 */
	public int getZone(KVOpExpression kve, double val)
	{
		if (!isValid())
			return (StatisticOperations.ZONEC);

		double target = kve.getValue();

		if (kve.getOp() == KVOpExpression.LT) {
			target -= 3 * sd;
		} else if (kve.getOp() == KVOpExpression.GT) {
			target += 3 * sd;
		}

		return (getZone(target, val));
	}

	/**
	 * Return the control zone for the supplied value using the
	 * information derived from the monitored statistics.
	 *
	 * @param val The value to be evaluated.
	 */
	public int getZoneMean(double val)
	{
		if (!isValid())
			return (StatisticOperations.ZONEC);

		return (getZone(mean, val));
	}

	/**
	 * Return the control zone for the supplied value using the
	 * information derived from the supplied target.
	 *
	 * @param val The value to be evaluated.
	 */
	private int getZone(double target, double val)
	{
		if (!isValid())
			return (StatisticOperations.ZONEC);

		return ((val < target - 3 * sd) ?
		    ZONEZ | ZONELT : (val > target + 3 * sd) ?
		    ZONEZ | ZONEGT : (val < target - 2 * sd) ?
		    ZONEA | ZONELT : (val > target + 2 * sd) ?
		    ZONEA | ZONEGT : (val < target - sd) ?
		    ZONEB | ZONELT : (val > target + sd) ?
		    ZONEB | ZONEGT : (val < target) ?
		    ZONEC | ZONELT : ZONEC | ZONEGT);
	}

	/**
	 * Return the difference (gap) between the target utilization
	 * expressed in the supplied objective expression and the
	 * supplied value.
	 *
	 * @param kve Objective expression used to determine target
	 * utilization details.
	 * @param val The value to be assessed.
	 */
	public double getGap(KVOpExpression kve, double val)
	{
		if (!isValid())
			return (0.0);

		double target = kve.getValue();

		if (kve.getOp() == KVOpExpression.LT) {
			target -= 3 * sd;
		} else if (kve.getOp() == KVOpExpression.GT) {
			target += 3 * sd;
		}
		if (val - target < -100)
			return (-100);
		else if (val - target > 100)
			return (100);
		else
			return (val - target);
	}

	/**
	 * Event handler for added statistics.
	 *
	 * @param e The event.
	 */
	public void onStatisticAdd(StatisticEvent e)
	{
		total = total.add(e.getTarget());
		process();

	}

	/**
	 * Event handler for removed statistics.
	 *
	 * @param e The event.
	 */
	public void onStatisticRemove(StatisticEvent e)
	{
		total = total.subtract(e.getTarget());
		process();
	}
}
