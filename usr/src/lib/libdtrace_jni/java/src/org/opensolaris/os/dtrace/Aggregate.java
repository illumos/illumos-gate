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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * ident	"%Z%%M%	%I%	%E% SMI"
 */
package org.opensolaris.os.dtrace;

import java.util.*;
import java.beans.*;
import java.io.*;

/**
 * A consistent snapshot of all aggregations requested by a single
 * {@link Consumer}.
 * <p>
 * Immutable.  Supports persistence using {@link java.beans.XMLEncoder}.
 *
 * @see Consumer#getAggregate()
 *
 * @author Tom Erickson
 */
public final class Aggregate implements Serializable
{
    static final long serialVersionUID = 3180340417154076628L;

    static {
	try {
	    BeanInfo info = Introspector.getBeanInfo(Aggregate.class);
	    PersistenceDelegate persistenceDelegate =
		    new DefaultPersistenceDelegate(
		    new String[] {"snaptime", "aggregations"});
	    BeanDescriptor d = info.getBeanDescriptor();
	    d.setValue("persistenceDelegate", persistenceDelegate);
	} catch (IntrospectionException e) {
	    System.out.println(e);
	}
    }

    /** @serial */
    private final long snaptime;

    // Map must not have same name as named PersistenceDelegate property
    // ("aggregations"), otherwise it gets confused for a bean property
    // and XMLDecoder calls the constructor with a Map instead of the
    // value of the getAggregations() method.

    private transient Map <String, Aggregation> map;
    private transient int recordSequence;

    /**
     * Called by native code.
     */
    private
    Aggregate(long snaptimeNanos)
    {
	snaptime = snaptimeNanos;
	map = new HashMap <String, Aggregation> ();
    }

    /**
     * Creates an aggregate with the given snaptime and aggregations.
     * Supports XML persistence.
     *
     * @param snaptimeNanos nanosecond timestamp when this aggregate was
     * snapped
     * @param aggregations unordered collection of aggregations
     * belonging to this aggregate
     * @throws NullPointerException if the given collection of
     * aggregations is {@code null}
     * @throws IllegalArgumentException if the record ordinals of the
     * given aggregations are invalid
     */
    public
    Aggregate(long snaptimeNanos, Collection <Aggregation> aggregations)
    {
	snaptime = snaptimeNanos;
	mapAggregations(aggregations);
	validate();
    }

    // assumes map is not yet created
    private void
    mapAggregations(Collection <Aggregation> aggregations)
    {
	int capacity = (int)(((float)aggregations.size() * 3.0f) / 2.0f);
	// avoid rehashing and optimize lookup; will never be modified
	map = new HashMap <String, Aggregation> (capacity, 1.0f);
	for (Aggregation a : aggregations) {
	    map.put(a.getName(), a);
	    recordSequence += a.asMap().size();
	}
    }

    private void
    validate()
    {
	int capacity = (int)(((float)recordSequence * 3.0f) / 2.0f);
	Set <Integer> ordinals = new HashSet <Integer> (capacity, 1.0f);
	int ordinal, max = 0;
	for (Aggregation a : map.values()) {
	    for (AggregationRecord r : a.asMap().values()) {
		// Allow all ordinals to be zero for backward
		// compatibility (allows XML decoding of aggregates that
		// were encoded before the ordinal property was added).
		if (!ordinals.add(ordinal = r.getOrdinal()) && (ordinal > 0)) {
		    throw new IllegalArgumentException(
			    "duplicate record ordinal: " + ordinal);
		}
		if (ordinal > max) {
		    max = ordinal;
		}
	    }
	}
	if ((max > 0) && (max != (recordSequence - 1))) {
	    throw new IllegalArgumentException(
		    "The maximum record ordinal (" + max + ") does not " +
		    "equal the number of records (" + recordSequence +
		    ") minus one.");
	}
    }

    /**
     * Gets the nanosecond timestamp of this aggregate snapshot.
     *
     * @return nanosecond timestamp of this aggregate snapshot
     */
    public long
    getSnaptime()
    {
	return snaptime;
    }

    /**
     * Gets an unordered list of all aggregations in this aggregate
     * snapshot.  The list is easily sortable using {@link
     * java.util.Collections#sort(List list, Comparator c)} provided any
     * user-defined ordering.  Modifying the returned list has no effect
     * on this aggregate.  Supports XML persistence.
     *
     * @return modifiable unordered list of all aggregations in this
     * aggregate snapshot; list is non-null and possibly empty
     */
    public List <Aggregation>
    getAggregations()
    {
	// Must return an instance of a public, mutable class in order
	// to support XML persistence.
	List <Aggregation> list = new ArrayList <Aggregation> (map.size());
	list.addAll(map.values());
	return list;
    }

    /**
     * Gets the aggregation with the given name if it exists in this
     * aggregate snapshot.
     *
     * @param name  the name of the desired aggregation, or empty string
     * to request the unnamed aggregation.  In D, the unnamed
     * aggregation is used anytime a name does not follow the
     * aggregation symbol '{@code @}', for example:
     * <pre>		{@code @ = count();}</pre> as opposed to
     * <pre>		{@code @counts = count()}</pre> resulting in an
     * {@code Aggregation} with the name "counts".
     *
     * @return {@code null} if no aggregation by the given name exists
     * in this aggregate
     * @see Aggregation#getName()
     */
    public Aggregation
    getAggregation(String name)
    {
	// This was decided March 18, 2005 in a meeting with the DTrace
	// team that calling getAggregation() with underbar should
	// return the unnamed aggregation (same as calling with empty
	// string).  Underbar is used to identify the unnamed
	// aggregation in libdtrace; in the jave API it is identifed by
	// the empty string.  The API never presents underbar but
	// accepts it as input (just converts underbar to empty string
	// everywhere it sees it).
	name = Aggregate.filterUnnamedAggregationName(name);
	return map.get(name);
    }

    /**
     * Gets an unordered list of this aggregate's records. The list is
     * sortable using {@link java.util.Collections#sort(List list,
     * Comparator c)} with any user-defined ordering. Modifying the
     * returned list has no effect on this aggregate.
     *
     * @return a newly created list that copies this aggregate's records
     * by reference in no particular order
     */
    public List <AggregationRecord>
    getRecords()
    {
	List <AggregationRecord> list =
		new ArrayList <AggregationRecord> (recordSequence);
	for (Aggregation a : map.values()) {
	    list.addAll(a.asMap().values());
	}
	return list;
    }

    /**
     * Gets an ordered list of this aggregate's records sequenced by
     * their {@link AggregationRecord#getOrdinal() ordinal} property.
     * Note that the unordered list returned by {@link #getRecords()}
     * can easily be sorted by any arbitrary criteria, for example by
     * key ascending:
     * <pre><code>
     * List <AggregationRecord> records = aggregate.getRecords();
     * Collections.sort(records, new Comparator &lt;AggregationRecord&gt; () {
     * 	public int compare(AggregationRecord r1, AggregationRecord r2) {
     * 		return r1.getTuple().compareTo(r2.getTuple());
     * 	}
     * });
     * </code></pre>
     * Use {@code getOrderedRecords()} instead of {@code getRecords()}
     * when you want to list records as they would be ordered by {@code
     * dtrace(1M)}.
     *
     * @return a newly created list of this aggregate's records
     * in the order used by the native DTrace library
     */
    public List <AggregationRecord>
    getOrderedRecords()
    {
	List <AggregationRecord> list = getRecords();
	Collections.sort(list, new Comparator <AggregationRecord> () {
	    public int compare(AggregationRecord r1, AggregationRecord r2) {
		int n1 = r1.getOrdinal();
		int n2 = r2.getOrdinal();
		return (n1 < n2 ? -1 : (n1 > n2 ? 1 : 0));
	    }
	});
	return list;
    }

    /**
     * In the native DTrace library, the unnamed aggregation {@code @}
     * is given the name {@code _} (underbar).  The Java DTrace API does
     * not expose this implementation detail but instead identifies the
     * unnamed aggregation with the empty string.  Here we convert the
     * name of the unnamed aggregation at the earliest opportunity.
     * <p>
     * Package level access.  Called by this class and PrintaRecord when
     * adding the Aggregation abstraction on top of native aggregation
     * records.
     */
    static String
    filterUnnamedAggregationName(String name)
    {
	if ((name != null) && name.equals("_")) {
	    return "";
	}
	return name;
    }

    /**
     * Gets a read-only {@code Map} view of this aggregate.
     *
     * @return a read-only {@code Map} view of this aggregate keyed by
     * aggregation name
     */
    public Map <String, Aggregation>
    asMap()
    {
	return Collections. <String, Aggregation> unmodifiableMap(map);
    }

    /**
     * Called by native code.
     *
     * @throws IllegalStateException if the aggregation with the given
     * name already has a record with the same tuple key as the given
     * record.
     */
    private void
    addRecord(String aggregationName, long aggid, AggregationRecord rec)
    {
	rec.setOrdinal(recordSequence++);
	aggregationName = Aggregate.filterUnnamedAggregationName(
		aggregationName);
	Aggregation aggregation = getAggregation(aggregationName);
	if (aggregation == null) {
	    aggregation = new Aggregation(aggregationName, aggid);
	    map.put(aggregationName, aggregation);
	}
	aggregation.addRecord(rec);
    }

    /**
     * Serialize this {@code Aggregate} instance.
     *
     * @serialData Serialized fields are emitted, followed by a {@link
     * java.util.List} of {@link Aggregation} instances.
     */
    private void
    writeObject(ObjectOutputStream s) throws IOException
    {
	s.defaultWriteObject();
	s.writeObject(getAggregations());
    }

    @SuppressWarnings("unchecked")
    private void
    readObject(ObjectInputStream s)
            throws IOException, ClassNotFoundException
    {
	s.defaultReadObject();
	// cannot cast to parametric type without compiler warning
	List <Aggregation> aggregations = (List)s.readObject();
	// load serialized form into private map as a defensive copy
	mapAggregations(aggregations);
	// check class invariants after defensive copy
	try {
	    validate();
	} catch (Exception e) {
	    InvalidObjectException x = new InvalidObjectException(
		    e.getMessage());
	    x.initCause(e);
	    throw x;
	}
    }

    /**
     * Gets a string representation of this aggregate snapshot useful
     * for logging and not intended for display.  The exact details of
     * the representation are unspecified and subject to change, but the
     * following format may be regarded as typical:
     * <pre><code>
     * class-name[property1 = value1, property2 = value2]
     * </code></pre>
     */
    public String
    toString()
    {
	StringBuilder buf = new StringBuilder();
	buf.append(Aggregate.class.getName());
	buf.append("[snaptime = ");
	buf.append(snaptime);
	buf.append(", aggregations = ");
	List <Aggregation> a = getAggregations();
	Collections.sort(a, new Comparator <Aggregation> () {
	    public int compare(Aggregation a1, Aggregation a2) {
		return a1.getName().compareTo(a2.getName());
	    }
	});
	buf.append(Arrays.toString(a.toArray()));
	buf.append(']');
	return buf.toString();
    }
}
