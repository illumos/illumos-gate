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

import java.io.*;
import java.util.*;
import java.beans.*;
import java.util.*;

/**
 * Multi-element key to a value in an {@link Aggregation}.
 * <p>
 * Tuple equality is based on the length of each tuple and the equality
 * of each corresponding element.  The natural ordering of tuples is
 * based on a lenient comparison designed not to throw exceptions when
 * corresponding elements are not mutually comparable or the number of
 * tuple elements differs.
 * <p>
 * Immutable.  Supports persistence using {@link java.beans.XMLEncoder}.
 *
 * @author Tom Erickson
 */
public final class Tuple implements Serializable, Comparable <Tuple>,
       Iterable<ValueRecord>
{
    static final long serialVersionUID = 5192674716869462720L;

    /**
     * The empty tuple has zero elements and may be used to obtain the
     * singleton {@link AggregationRecord} of a non-keyed {@link
     * Aggregation}, such as the one derived from the D statement
     * <code>&#64;a = count()</code>.  (In D, an aggregation without
     * square brackets aggregates a single value.)
     */
    public static final Tuple EMPTY = new Tuple();

    static {
	try {
	    BeanInfo info = Introspector.getBeanInfo(Tuple.class);
	    PersistenceDelegate persistenceDelegate =
		    new DefaultPersistenceDelegate(
		    new String[] {"elements"})
	    {
		/*
		 * Need to prevent DefaultPersistenceDelegate from using
		 * overridden equals() method, resulting in a
		 * StackOverFlowError.  Revert to PersistenceDelegate
		 * implementation.  See
		 * http://forum.java.sun.com/thread.jspa?threadID=
		 * 477019&tstart=135
		 */
		protected boolean
		mutatesTo(Object oldInstance, Object newInstance)
		{
		    return (newInstance != null && oldInstance != null &&
			    oldInstance.getClass() == newInstance.getClass());
		}
	    };
	    BeanDescriptor d = info.getBeanDescriptor();
	    d.setValue("persistenceDelegate", persistenceDelegate);
	} catch (IntrospectionException e) {
	    System.out.println(e);
	}
    }

    /** @serial */
    private java.util.List <ValueRecord> elements;

    private
    Tuple()
    {
	//
	// expected to be a short list (usually one to three elements)
	//
	elements = new ArrayList <ValueRecord> (4);
    }

    /**
     * Creates a tuple with the given elements in the given order.
     *
     * @param tupleElements ordered series of tuple elements
     * @throws NullPointerException if the given array or any of its
     * elements is {@code null}
     */
    public
    Tuple(ValueRecord ... tupleElements)
    {
	this();
	if (tupleElements == null) {
	    throw new NullPointerException("null array");
	}
	for (ValueRecord r : tupleElements) {
	    if (r == null) {
		throw new NullPointerException("null element");
	    }
	    elements.add(r);
	}
    }

    /**
     * Creates a tuple with the given element list in the given list
     * order.
     *
     * @param tupleElements ordered list of tuple elements
     * @throws NullPointerException if the given list or any of its
     * elements is {@code null}
     */
    public
    Tuple(List <ValueRecord> tupleElements)
    {
	this();
	if (tupleElements == null) {
	    throw new NullPointerException("element list is null");
	}
	for (ValueRecord r : tupleElements) {
	    if (r == null) {
		throw new NullPointerException("null element");
	    }
	    elements.add(r);
	}
    }

    /**
     * Called by native code.
     *
     * @throws NullPointerException if element is null
     * @throws IllegalArgumentException if element is neither a {@link
     * ValueRecord} nor one of the DTrace primitive types returned by
     * {@link ScalarRecord#getValue()}
     */
    private void
    addElement(ValueRecord element)
    {
	if (element == null) {
	    throw new NullPointerException("tuple element is null at " +
		    "index " + elements.size());
	}
	elements.add(element);
    }

    /**
     * Gets a modifiable list of this tuple's elements in the same order
     * as their corresponding variables in the original D program tuple.
     * Modifying the returned list has no effect on this tuple.
     * Supports XML persistence.
     *
     * @return a modifiable list of this tuple's elements in the same order
     * as their corresponding variables in the original D program tuple
     */
    public List <ValueRecord>
    getElements()
    {
	return new ArrayList <ValueRecord> (elements);
    }

    /**
     * Gets a read-only {@code List} view of this tuple.
     *
     * @return a read-only {@code List} view of this tuple
     */
    public List <ValueRecord>
    asList()
    {
	return Collections. <ValueRecord> unmodifiableList(elements);
    }

    /**
     * Gets the number of elements in this tuple.
     *
     * @return non-negative element count
     */
    public int
    size()
    {
	return elements.size();
    }

    /**
     * Returns {@code true} if this tuple has no elements.
     *
     * @return {@code true} if this tuple has no elements, {@code false}
     * otherwise
     * @see Tuple#EMPTY
     */
    public boolean
    isEmpty()
    {
	return elements.isEmpty();
    }

    /**
     * Gets the element at the given tuple index (starting at zero).
     *
     * @return non-null tuple element at the given zero-based index
     */
    public ValueRecord
    get(int index)
    {
	return elements.get(index);
    }

    /**
     * Gets an iterator over the elements of this tuple.
     *
     * @return an iterator over the elements of this tuple
     */
    public Iterator<ValueRecord>
    iterator()
    {
	return elements.iterator();
    }

    /**
     * Compares the specified object with this {@code Tuple} instance
     * for equality.  Defines equality as having the same elements in
     * the same order.
     *
     * @return {@code true} if and only if the specified object is of
     * type {@code Tuple} and both instances have the same size and
     * equal elements at corresponding tuple indexes
     */
    public boolean
    equals(Object o)
    {
	if (o instanceof Tuple) {
	    Tuple t = (Tuple)o;
	    return elements.equals(t.elements);
	}
	return false;
    }

    /**
     * Overridden to ensure that equals instances have equal hash codes.
     */
    public int
    hashCode()
    {
	return elements.hashCode();
    }

    // lenient sort does not throw exceptions
    @SuppressWarnings("unchecked")
    private static int
    compareObjects(Object o1, Object o2)
    {
	int cmp;

	if (o1 instanceof Comparable) {
	    Class c1 = o1.getClass();
	    Class c2 = o2.getClass();
	    if (c1.equals(c2)) {
		cmp = ProbeData.compareUnsigned(Comparable.class.cast(o1),
			Comparable.class.cast(o2));
	    } else {
		// Compare string values.
		String s1 = o1.toString();
		String s2 = o2.toString();
		cmp = s1.compareTo(s2);
	    }
	} else if (o1 instanceof byte[] && o2 instanceof byte[]) {
	    byte[] a1 = byte[].class.cast(o1);
	    byte[] a2 = byte[].class.cast(o2);
	    cmp = ProbeData.compareByteArrays(a1, a2);
	} else {
	    // Compare string values.
	    String s1 = o1.toString();
	    String s2 = o2.toString();
	    cmp = s1.compareTo(s2);
	}

	return cmp;
    }

    /**
     * Defines the natural ordering of tuples.  Uses a lenient algorithm
     * designed not to throw exceptions.  Sorts tuples by the natural
     * ordering of corresponding elements, starting with the first pair
     * of corresponding elements and comparing subsequent pairs only
     * when all previous pairs are equal (as a tie breaker).  If
     * corresponding elements are not mutually comparable, it compares
     * the string values of those elements.  If all corresponding
     * elements are equal, then the tuple with more elements sorts
     * higher than the tuple with fewer elements.
     *
     * @return a negative integer, zero, or a postive integer as this
     * tuple is less than, equal to, or greater than the given tuple
     * @see Tuple#compare(Tuple t1, Tuple t2, int pos)
     */
    public int
    compareTo(Tuple t)
    {
	int cmp = 0;
	int len = size();
	int tlen = t.size();
	for (int i = 0; (cmp == 0) && (i < len) && (i < tlen); ++i) {
	    cmp = Tuple.compare(this, t, i);
	}
	if (cmp == 0) {
	    cmp = (len < tlen ? -1 : (len > tlen ? 1 : 0));
	}
	return cmp;
    }

    /**
     * Compares corresponding tuple elements at the given zero-based
     * index. Elements are ordered as defined in the native DTrace
     * library, which treats integer values as unsigned when sorting.
     *
     * @param t1 first tuple
     * @param t2 second tuple
     * @param pos nth tuple element, starting at zero
     * @return a negative integer, zero, or a postive integer as the
     * element in the first tuple is less than, equal to, or greater
     * than the element in the second tuple
     * @throws IndexOutOfBoundsException if the given tuple index {@code
     * pos} is out of range {@code (pos < 0 || pos >= size())} for
     * either of the given tuples
     */
    public static int
    compare(Tuple t1, Tuple t2, int pos)
    {
	int cmp = 0;
	ValueRecord rec1 = t1.get(pos);
	ValueRecord rec2 = t2.get(pos);
	Object val1;
	Object val2;
	if (rec1 instanceof ScalarRecord) {
	    val1 = rec1.getValue();
	} else {
	    val1 = rec1;
	}
	if (rec2 instanceof ScalarRecord) {
	    val2 = rec2.getValue();
	} else {
	    val2 = rec2;
	}
	cmp = compareObjects(val1, val2);
	return (cmp);
    }

    private void
    readObject(ObjectInputStream s)
            throws IOException, ClassNotFoundException
    {
	s.defaultReadObject();
	// Make a defensive copy of elements
	if (elements == null) {
	    throw new InvalidObjectException("element list is null");
	}
	List <ValueRecord> copy = new ArrayList <ValueRecord>
		(elements.size());
	copy.addAll(elements);
	elements = copy;
	// check class invariants
	for (ValueRecord e : elements) {
	    if (e == null) {
		throw new InvalidObjectException("null element");
	    }
	}
    }

    /**
     * Gets a string representation of this tuple's elements in the same
     * format as that returned by {@link AbstractCollection#toString()}.
     * The representation, although specified, is subject to change.
     */
    public String
    toString()
    {
	return elements.toString();
    }
}
