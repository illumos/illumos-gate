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
import java.util.Date;
import java.util.Iterator;
import java.text.*;

import com.sun.solaris.service.pools.UnsignedInt64;

/**
 * Contains the information relating to a specific statistic for an
 * object. The Statistic has no notion of the source of the data, it
 * is simply a repository for holding statistical information.
 */
interface Statistic
{
	/**
	 * Return the start of the sample period for which the
	 * statistic is representative.
	 */
	public Date getStart();

	/**
	 * Return the end of the sample period for which the
	 * statistic is representative.
	 */
	public Date getEnd();

	/**
	 * Get the value of this statistic.
	 */
	public Object getValue();

	/**
	 * Get the value of this statistic as a Long.
	 */
	public Long getLongValue();

	/**
	 * Get the value of this statistic as a Double.
	 */
	public Double getDoubleValue();

	/**
	 * Get the value of this statistic as a UnsignedInt64.
	 */
	public UnsignedInt64 getUnsignedInt64Value();
}

/**
 * An interface for Statistics which may be aggregated.
 */
interface AggregateStatistic extends Statistic
{
	/**
	 * Add the supplied statistic to this.
	 *
	 * @param o The other statistic.
	 */
	public AggregateStatistic add(AggregateStatistic o);

	/**
	 * Subtract the supplied statistic from this.
	 *
	 * @param o The other statistic.
	 */
	public AggregateStatistic subtract(AggregateStatistic o);

	/**
	 * Produce the aggregate of all objects in the supplied
	 * iterator (which must be of the same type) whose start and
	 * end dates lie within the supplied ranges. If either start
	 * or end is null, then that bound is not applied. i.e. if no
	 * start date is supplied, then start checking is disabled.
	 *
	 * @param start The start date for qualification in the snapshot.
	 * @param end The end date for qualification in the snapshot.
	 * @throws IllegalArgumentException If the iterator is empty.
	 */
	public AggregateStatistic getSnapshotForInterval(Iterator it,
	    Date start, Date end) throws IllegalArgumentException;
}

/**
 * A basic Statistic implementation which makes it easy to derive
 * concrete statistic types. This is an immutable class, the state is
 * set when the object is constructed and cannot be later changed.
 */
abstract class AbstractStatistic implements Statistic
{
	/**
	 * The value of the statistic.
	 */
	private final Object value;

	/**
	 * The start of the interval during which the statistic was
	 * captured.
	 */
	private final Date start;

	/**
	 * The end of the interval during which the statistic was
	 * captured.
	 */
	private final Date end;

	/**
	 * Formatter for the sample start time, used by toString().
	 */
	private static final DateFormat df = new SimpleDateFormat("kk:mm:ss");

	/**
	 * Constructor. This is provided as a mechanism to allow
	 * inherited classes to correctly initialize their state.
	 *
	 * @param value The value of this statistic.
	 */
	protected AbstractStatistic(Object value)
	{
		this(value, null, null);
	}

	/**
	 * Constructor. This is provided as a mechanism to allow
	 * inherited classes to correctly initialize their state.
	 *
	 * @param value The value of this statistic.
	 * @param start The start of the sample period which this
	 * statistic represents.
	 * @param end The end of the sample period which this
	 * statistic represents.
	 */
	protected AbstractStatistic(Object value, Date start, Date end)
	{
		this.value = value;
		this.start = start;
		this.end = end;
	}

	/**
	 * Return the start of the sample period for which the
	 * statistic is representative.
	 */
	public Date getStart()
	{
		return (start);
	}


	/**
	 * Return the end of the sample period for which the
	 * statistic is representative.
	 */
	public Date getEnd()
	{
		return (end);
	}

	/**
	 * Get the value of this statistic.
	 */
	public Object getValue()
	{
		return (value);
	}

	public abstract Long getLongValue();
	public abstract Double getDoubleValue();
	public abstract UnsignedInt64 getUnsignedInt64Value();

	/**
	 * Return the string representation of this statistic.
	 */
	public String toString()
	{
		StringBuffer buf = new StringBuffer();

		buf.append(value);
		if (start != null && end != null) {
			buf.append(" from ");
			buf.append(df.format(start));
			buf.append(" to ");
			buf.append(df.format(end));
		}
		return (buf.toString());
	}
}

/**
 * A statistic of type Double.
 */
final class DoubleStatistic extends AbstractStatistic
    implements AggregateStatistic
{

	/**
	 * Constructor.
	 *
	 * @param value The value of this statistic.
	 */
	public DoubleStatistic(Double value)
	{
		super(value);
	}

	/**
	 * Constructor.
	 *
	 * @param value The value of this statistic.
	 * @param start The start of the interval over which this
	 * statistic is representative.
	 * @param end The end of the interval over which this
	 * statistic is representative.
	 */
	public DoubleStatistic(Double value, Date start, Date end)
	{
		super(value, start, end);
	}

	public Double getDoubleValue()
	{
		return ((Double) getValue());
	}

	public Long getLongValue()
	{
		return (new Long(((Double) getValue()).longValue()));
	}

	public UnsignedInt64 getUnsignedInt64Value()
	{
		return (new UnsignedInt64(Long.toString(((Double) getValue()).
					      longValue())));
	}

	public AggregateStatistic add(AggregateStatistic o)
	{
		Double v1 = getDoubleValue();
		Double v2 = o.getDoubleValue();

		return (new DoubleStatistic(new Double(v1.doubleValue() +
					    v2.doubleValue()),
			getStart(), getEnd()));
	}

	public AggregateStatistic subtract(AggregateStatistic o)
	{
		Double v1 = getDoubleValue();
		Double v2 = o.getDoubleValue();

		return (new DoubleStatistic(new Double(v1.doubleValue() -
					    v2.doubleValue()),
			getStart(), getEnd()));
	}

	public AggregateStatistic getSnapshotForInterval(Iterator it,
	    Date start, Date end) throws IllegalArgumentException
	{
		double total = 0;
		int count = 0;
		Date first = start, last = end;

		while (it.hasNext()) {
			DoubleStatistic s = (DoubleStatistic) it.next();
			if (start != null) {
				if (s.getStart().compareTo(start) < 0)
					continue;
			}
			if (first == null)
				first = s.getStart();
			if (end != null) {
				if (s.getEnd().compareTo(end) > 0)
					continue;
			}
			last = s.getEnd();
			total += s.getDoubleValue().doubleValue();
			count++;
		}
		if (count == 0)
			throw new IllegalArgumentException("Cannot derive a " +
			    "snapshot from an empty iterator");
		return (new DoubleStatistic(new Double(total / count), first,
			last));
	}
}

/**
 * A statistic of type Long.
 */
final class LongStatistic extends AbstractStatistic
    implements AggregateStatistic
{

	/**
	 * Constructor.
	 *
	 * @param value The value of this statistic.
	 * @param start The start of the interval over which this
	 * statistic is representative.
	 * @param end The end of the interval over which this
	 * statistic is representative.
	 */
	public LongStatistic(Long value, Date start, Date end)
	{
		super(value, start, end);
	}

	public Double getDoubleValue()
	{
		return (new Double(((Long) getValue()).longValue()));
	}

	public Long getLongValue()
	{
		return ((Long) getValue());
	}

	public UnsignedInt64 getUnsignedInt64Value()
	{
		return (new UnsignedInt64(Long.toString(((Long) getValue()).
					      longValue())));
	}

	public AggregateStatistic add(AggregateStatistic o)
	{
		Long v1 = getLongValue();
		Long v2 = o.getLongValue();

		return (new LongStatistic(new Long(v1.longValue() +
					    v2.longValue()),
			getStart(), getEnd()));
	}

	public AggregateStatistic subtract(AggregateStatistic o)
	{
		Long v1 = getLongValue();
		Long v2 = o.getLongValue();

		return (new LongStatistic(new Long(v1.longValue() -
					    v2.longValue()),
			getStart(), getEnd()));
	}

	public AggregateStatistic getSnapshotForInterval(Iterator it,
	    Date start, Date end) throws IllegalArgumentException
	{
		long total = 0;
		int count = 0;
		Date first = start, last = end;
		while (it.hasNext()) {
			LongStatistic s = (LongStatistic) it.next();
			if (start != null) {
				if (s.getStart().compareTo(start) < 0)
					continue;
			}
			if (first == null)
				first = s.getStart();
			if (end != null) {
				if (s.getEnd().compareTo(end) > 0)
					continue;
			}
			last = s.getEnd();
			total += s.getLongValue().longValue();
			count++;
		}
		if (count == 0)
			throw new IllegalArgumentException("Cannot derive a " +
			    "snapshot from an empty iterator");
		return (new LongStatistic(new Long(total / count), first,
			last));
	}
}

/**
 * A statistic of type UnsignedInt64.
 */
final class UnsignedInt64Statistic extends AbstractStatistic
    implements AggregateStatistic
{

	/**
	 * Constructor.
	 *
	 * @param value The value of this statistic.
	 * @param start The start of the interval over which this
	 * statistic is representative.
	 * @param end The end of the interval over which this
	 * statistic is representative.
	 */
	public UnsignedInt64Statistic(UnsignedInt64 value, Date start,
	    Date end)
	{
		super(value, start, end);
	}

	public Double getDoubleValue()
	{
		return (new Double(((UnsignedInt64) getValue()).longValue()));
	}

	public Long getLongValue()
	{
		return (new Long(((UnsignedInt64) getValue()).longValue()));
	}

	public UnsignedInt64 getUnsignedInt64Value()
	{
		return ((UnsignedInt64) getValue());
	}

	public AggregateStatistic add(AggregateStatistic o)
	{
		UnsignedInt64 v1 = getUnsignedInt64Value();
		UnsignedInt64 v2 = o.getUnsignedInt64Value();

		return (new UnsignedInt64Statistic(
		    new UnsignedInt64(v1.add(v2)),
		        getStart(), getEnd()));
	}

	public AggregateStatistic subtract(AggregateStatistic o)
	{
		UnsignedInt64 v1 = getUnsignedInt64Value();
		UnsignedInt64 v2 =  o.getUnsignedInt64Value();

		return (new UnsignedInt64Statistic(
		    new UnsignedInt64(v1.subtract(v2)),
		        getStart(), getEnd()));
	}

	public AggregateStatistic getSnapshotForInterval(Iterator it,
	    Date start, Date end) throws IllegalArgumentException
	{
		BigInteger total = new BigInteger("0");
		int count = 0;
		Date first = start, last = end;
		while (it.hasNext()) {
			UnsignedInt64Statistic s = (UnsignedInt64Statistic)
			    it.next();
			if (start != null) {
				if (s.getStart().compareTo(start) < 0)
					continue;
			}
			if (first == null)
				first = s.getStart();

			if (end != null) {
				if (s.getEnd().compareTo(end) > 0)
					continue;
			}
			last = s.getEnd();
			total = total.add(s.getUnsignedInt64Value());
			count++;
		}
		if (count == 0)
			throw new IllegalArgumentException("Cannot derive a " +
			    "snapshot from an empty iterator");
		return (new UnsignedInt64Statistic(
		    new UnsignedInt64(total.divide(new BigInteger(
	            Integer.toString(count)))), first, last));
	}
}
