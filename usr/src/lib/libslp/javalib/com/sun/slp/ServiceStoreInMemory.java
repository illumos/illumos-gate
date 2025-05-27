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
 * Copyright 2001,2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 */

//  ServiceStoreInMemory.java: An in-memory implementation
//			       of the service store.
//  Author:           James Kempf
//  Created On:       Mon Oct 20 12:36:35 1997
//  Last Modified By: James Kempf
//  Last Modified On: Tue Mar  2 15:32:23 1999
//  Update Count:     472
//

package com.sun.slp;

import java.util.*;
import java.io.*;

/**
 * The ServiceStoreInMemory class implements the ServiceStore interface
 * on in-memory data structures.
 * <details of those structures here>
 *
 * @author James Kempf
 */

class ServiceStoreInMemory extends Object implements ServiceStore {

    /**
     * The BVCollector interface allows various
     * data structures to collect stuff from the BtreeVector.
     *
     * @author James Kempf
     */

    private interface BVCollector {

	// Set the return value.

	abstract void setReturn(ServiceRecordInMemory rec);

    }

    /**
     * The ParserBVCollector class implements a BtreeVector
     * collector for the parser.
     *
     * @author James Kempf
     */

    private class ParserBVCollector extends Object implements BVCollector {

	Parser.ParserRecord prReturns = null;
	private Vector scopes = null;

	ParserBVCollector(Vector scopes) {
	    this.scopes = scopes;

	}

	public void setReturn(ServiceRecordInMemory rec) {

	    Hashtable services = prReturns.services;
	    Hashtable signatures = prReturns.signatures;
	    ServiceURL surl = rec.getServiceURL();

	    // Add if we don't already have it.

	    if (services.get(surl) == null) {
		Vector s = (Vector)rec.getScopes().clone();

		DATable.filterScopes(s, scopes, false);

		// Need to adjust lifetime to reflect the time to live. Don't
		//  set the lifetime if it has already expired.

		long lifetime =
		    (rec.getExpirationTime() -
		     System.currentTimeMillis()) / 1000;

		if (lifetime > 0) {
		    ServiceURL url =
			new ServiceURL(surl.toString(), (int)lifetime);

		    services.put(surl, s);

		    Hashtable sig = rec.getURLSignature();

		    if (sig != null) {
			signatures.put(url, sig);

		    }
		}
	    }
	}
    }

    /**
     * The AttributeBVCollector class implements a BtreeVector
     * collector for the collecting attribute values by type.
     *
     * @author James Kempf
     */

    private class AttributeBVCollector extends Object implements BVCollector {

	private Hashtable alreadySeen = new Hashtable();
						// records already seen.
	private Vector attrTags = null;	// tags to match against records
	private Hashtable ht = new Hashtable();	// for collecting attributes.
	private Vector ret = null;		// for returns.

	AttributeBVCollector(Vector attrTags, Vector ret) {
	    this.attrTags = attrTags;
	    this.ret = ret;

	}

	public void setReturn(ServiceRecordInMemory rec) {

	    // If we've got it already, then don't add again.

	    if (alreadySeen.get(rec) == null) {
		alreadySeen.put(rec, rec);

		try {
		    findMatchingAttributes(rec, attrTags, ht, ret);

		} catch (ServiceLocationException ex) {

		    Assert.slpassert(false,
				  "ssim_attrbvc_botch",
				  new Object[] {ex.getMessage()});
		}
	    }
	}
    }

    /**
     * The ScopeBVCollector class implements a BtreeVector
     * collector for the collecting records if scopes match.
     *
     * @author James Kempf
     */

    private class ScopeBVCollector extends Object implements BVCollector {

	private Hashtable alreadySeen = new Hashtable();
						// for those we've seen
	private Vector records = null;		// for returns.
	private Vector scopes = null;		// the scopes we're looking for

	ScopeBVCollector(Vector records, Vector scopes) {
	    this.records = records;
	    this.scopes = scopes;

	}

	public void setReturn(ServiceRecordInMemory rec) {

	    // If we've got it already, then don't add.

	    if (alreadySeen.get(rec) == null) {
		alreadySeen.put(rec, rec);

		if (scopes == null) {
		    records.addElement(rec);

		} else {

		    // Check scopes.

		    int i;
		    Vector rscopes = rec.getScopes();
		    int len = scopes.size();

		    for (i = 0; i < len; i++) {
			if (rscopes.contains(scopes.elementAt(i))) {
			    records.addElement(rec);
			    break;

			}
		    }
		}
	    }
	}
    }

    /**
     * The AllBVCollector class implements a BtreeVector
     * collector for collecting all records.
     *
     * @author James Kempf
     */

    private class AllBVCollector extends Object implements BVCollector {

	private Vector records = null;			// for returns.

	AllBVCollector(Vector records) {
	    this.records = records;

	}

	public void setReturn(ServiceRecordInMemory rec) {

	    // If we've got it already, then don't add.

	    if (!records.contains(rec)) {
		records.addElement(rec);

	    }
	}
    }

    /**
     * The List class implements a linked list for storing records
     * in the BtreeVector structure.
     *
     * @author James Kempf
     */

    private class List extends Object {

	ServiceRecordInMemory record = null;
	List next = null;
	List prev = null;

	// Create a new list object.

	List(ServiceRecordInMemory record) {
	    this.record = record;

	}

	// Insert a new record after this one. Return the new
	//  record.

	synchronized List insertAfter(ServiceRecordInMemory record) {
	    List newRec = new List(record);
	    newRec.next = next;
	    newRec.prev = this;

	    if (next != null) {
		next.prev = newRec;

	    }

	    this.next = newRec;

	    return newRec;

	}

	// Delete this record from the list.

	synchronized void delete() {

	    if (next != null) {
		next.prev = prev;
	    }

	    if (prev != null) {
		prev.next = next;

	    }

	    prev = null;
	    next = null;

	}
    }

    /**
     * The RegRecord class implements a record with the value for the
     * record buckets. It is used as elements in BtreeVector.
     *
     * @author James Kempf
     */

    private class RegRecord extends Object {

	Object value = null;		// the value for these registrations.
	List head = new List(null); 	// head of the list always null,
				        //  never changes.
	// Construct a new one.

	RegRecord(Object value) {
	    this.value = value;

	}

	// Add a new record to the buckets, return new element.

	List add(ServiceRecordInMemory rec) {

	    return head.insertAfter(rec);

	}

	// For every element in record's list, set the return value in the
	// returns object. Since deletions may have removed everything
	// from this record, return true only if something was there.

	boolean setReturn(BVCollector returns) {

	    boolean match = false;
	    List l = head;

	    for (l = l.next; l != null; l = l.next) {
		ServiceRecordInMemory rec = l.record;
		returns.setReturn(rec);
		match = true;

	    }

	    return match;
	}

	public String toString() {
	    return "<RegRecord value="+value+"list="+head.next+">";

	}
    }

    /**
     * The BtreeVector class stores registrations in sorted order. The
     * Quicksort algorithm is used to insert items and search for something.
     *
     * @author James Kempf
     */

    private class BtreeVector extends Object {

	// Contains the sorted vector.

	private Vector contents = new Vector();

	public String toString() {
	    return "<BtreeVector "+contents.toString()+">";

	}

	// Return the contents as a sorted vector of RegRecord.
	//  Note that this doesn't return a copy, so
	//  the vector can be side-effected.

	Vector getContents() {
	    return contents;

	}

	// Add the entire contents of the vector to the return record.

	boolean getAll(BVCollector returns) {

	    int i, n = contents.size();
	    boolean match = false;

	    for (i = 0; i < n; i++) {
		RegRecord rec = (RegRecord)contents.elementAt(i);

		match = match | rec.setReturn(returns);
	    }

	    return match;
	}

	// Add a new record to this vector. We also garbage collect any
	// records that are empty. Return the list object added.

	List add(Object value, ServiceRecordInMemory record) {
	    RegRecord rec = walkVector(value, true);  // an update...

	    // Add the record to this one.

	    return rec.add(record);

	}


	// Add only if no element in the vector matches the tag.

	boolean matchDoesNotContain(Object pattern, BVCollector returns) {

	    // Go through the vector, putting in anything that isn't equal.

	    int i, n = contents.size();
	    Vector noMatch = new Vector();
	    boolean match = false;

	    for (i = 0; i < n; i++) {
		RegRecord rec = (RegRecord)contents.elementAt(i);

		if (!compareEqual(rec.value, pattern)) {

		    // Add to prospective returns.

		    noMatch.addElement(rec);

		}

	    }

	    // If we got this far, there are some no matches.

	    n = noMatch.size();

	    for (i = 0; i < n; i++) {
		RegRecord rec = (RegRecord)noMatch.elementAt(i);

		match = match | rec.setReturn(returns);

	    }

	    return match;

	}

	boolean
	    matchEqual(Object pattern, BVCollector returns) {

	    boolean match = false;

	    // We can't walk the vector if the value is an AttributePattern,
	    //  because equals doesn't apply.

	    if (pattern instanceof AttributePattern) {
		int i, n = contents.size();

		for (i = 0; i < n; i++) {
		    RegRecord rec = (RegRecord)contents.elementAt(i);
		    AttributeString val = (AttributeString)rec.value;
		    AttributePattern pat = (AttributePattern)pattern;

		    if (pat.match(val)) {
			match = match | rec.setReturn(returns);

		    }
		}
	    } else {
		RegRecord rec = walkVector(pattern, false);
							// not an update...

		// If nothing came back, return false.

		if (rec == null) {
		    match = false;

		} else {

		    // Otherwise set returns in the vector.

		    match = rec.setReturn(returns);

		}
	    }

	    return match;
	}

	boolean
	    matchNotEqual(Object pattern, BVCollector returns) {

	    // Go through the vector, putting in anything that isn't equal.

	    int i, n = contents.size();
	    boolean match = false;

	    for (i = 0; i < n; i++) {
		RegRecord rec = (RegRecord)contents.elementAt(i);

		if (!compareEqual(rec.value, pattern)) {
		    match = match | rec.setReturn(returns);

		}
	    }

	    return match;
	}

	boolean
	    matchLessEqual(Object pattern,
			   BVCollector returns) {

	    // Go through the vector, putting in anything that is
	    // less than or equal.

	    int i, n = contents.size();
	    boolean match = false;

	    for (i = 0; i < n; i++) {
		RegRecord rec = (RegRecord)contents.elementAt(i);

		if (!compareLessEqual(rec.value, pattern)) {
		    break;

		}

		match = match | rec.setReturn(returns);
	    }

	    return match;
	}

	boolean
	    matchNotLessEqual(Object pattern,
			      BVCollector returns) {
	    // Go through the vector, putting in anything that is not
	    // less than or equal. Start at the top.

	    int i, n = contents.size();
	    boolean match = false;

	    for (i = n - 1; i >= 0; i--) {
		RegRecord rec = (RegRecord)contents.elementAt(i);

		if (compareLessEqual(rec.value, pattern)) {
		    break;

		}

		match = match | rec.setReturn(returns);
	    }

	    return match;
	}

	boolean
	    matchGreaterEqual(Object pattern,
			      BVCollector returns) {
	    // Go through the vector, putting in anything that is greater
	    // than or equal. Start at the top.

	    int i, n = contents.size();
	    boolean match = false;

	    for (i = n - 1; i >= 0; i--) {
		RegRecord rec = (RegRecord)contents.elementAt(i);

		if (!compareGreaterEqual(rec.value, pattern)) {
		    break;

		}

		match = match | rec.setReturn(returns);
	    }

	    return match;
	}

	boolean
	    matchNotGreaterEqual(Object pattern,
				 BVCollector returns) {
	    // Go through the vector, putting in anything that is not
	    // than or equal.

	    int i, n = contents.size();
	    boolean match = false;

	    for (i = 0; i < n; i++) {
		RegRecord rec = (RegRecord)contents.elementAt(i);

		if (compareGreaterEqual(rec.value, pattern)) {
		    break;

		}

		match = match | rec.setReturn(returns);
	    }

	    return match;
	}

	// Binary tree walk the vector, performing the operation. Note that
	//  we use dynamic typing heavily here to get maximum code reuse.

	private RegRecord
	    walkVector(Object pattern, boolean update) {

	    // Get the starting set of indicies.

	    int size = contents.size();
	    int middle = size / 2;
	    int top = size - 1;
	    int bottom = 0;
	    RegRecord rec = null;

	    top = (top < 0 ? 0:top);

	    while (size > 0) {

		// Get the one at the current middle.

		rec = (RegRecord)contents.elementAt(middle);

		// Garbage Collection.
		//  If it was null, then delete. But only if we're
		//  inserting. We leave it alone on lookup.

		if (update) {
		    if (rec.head.next == null) {

			contents.removeElementAt(middle);

			size = size - 1;
			middle = bottom + (size / 2);
			top = top - 1;

			top = (top < 0 ? 0:top);

			continue;
		    }
		}

		// Compare value to record, if equal, return record.
		//  code.

		if (compareEqual(rec.value, pattern)) {
		    return rec;

		} else if (compareLessEqual(pattern, rec.value)) {

		    // Recalculate index. We move left, because the value is
		    // less that the value in the vector, so an equal value
		    // must be to the left. Note that the top is not in the
		    // interval because it has already been checked and
		    // found wanting.

		    top = middle;
		    size = (top - bottom);
		    middle = top - (size / 2);
		    middle = (middle < 0 ? 0:middle);

		    if (middle == top) {

			// Neither top nor middle are in the interval,
			// so size is zero. We need to compare with bottom.

			rec = null;
			RegRecord trec = (RegRecord)contents.elementAt(bottom);

			if (update) {
			    rec = new RegRecord(pattern);

			    // If the pattern is equal to bottom, return it.
			    // If the pattern is less than or equal to bottom,
			    // we insert it at bottom. If it is greater
			    // than or equal, we insert it at middle.

			    if (compareEqual(trec.value, pattern)) {
				return trec;

			    } else if (compareLessEqual(pattern, trec.value)) {

				// Pattern is less than bottom, so insert
				// at bottom.

				contents.insertElementAt(rec, bottom);

			    } else {
				contents.insertElementAt(rec, middle);

			    }
			} else {

			    // If it equals bottom, then return bottom rec.

			    if (compareEqual(trec.value, pattern)) {
				rec = trec;

			    }
			}

			break;

		    }

		} else if (compareGreaterEqual(pattern, rec.value)) {

		    // Recalculate index. We move right, because the value is
		    // greater that the value in the vector, so an equal
		    // value must be to the right. Note that the top is not
		    // in the interval because it has already been checked
		    // and found wanting.

		    bottom = middle;
		    size = (top - bottom);
		    middle = bottom + (size / 2);

		    if (middle == bottom) {

			// Neither bottom nor middle is in the interval,
			// so size is zero. We need to compare with top.

			rec = null;
			RegRecord trec = (RegRecord)contents.elementAt(top);

			if (update) {
			    rec = new RegRecord(pattern);

			    // If the pattern is equal to the top, we
			    // return the top. If the pattern is greater
			    // then top, we insert it after top, else we
			    // insert it at top.

			    if (compareEqual(trec.value, pattern)) {
				return trec;

			    } else if (compareGreaterEqual(pattern,
							   trec.value)) {

				// Pattern is greater than top, so insert
				// after top.

				int i = top + 1;

				if (i >= contents.size()) {
				    contents.addElement(rec);

				} else {
				    contents.insertElementAt(rec, i);

				}
			    } else {

				// Pattern is less than top, so insert at
				// top, causing top to move up.

				contents.insertElementAt(rec, top);

			    }
			} else {

			    // If it equals top, then return top rec.

			    if (compareEqual(trec.value, pattern)) {
				rec = trec;

			    }
			}

			break;

		    }
		}
	    }

	    // Take care of update where vector is empty or cleaned out.

	    if (update && rec == null) {
		rec = new RegRecord(pattern);

		Assert.slpassert((contents.size() == 0),
			      "ssim_btree_botch",
			      new Object[0]);

		contents.addElement(rec);
	    }

	    return rec;
	}

	// Add any registrations that match the pattern.

	boolean
	    compareEqual(Object target, Object pattern) {

	    if (target instanceof Integer ||
		target instanceof Boolean ||
		target instanceof Opaque ||
		target instanceof Long) {
		if (pattern.equals(target)) {
		    return true;

		}

	    } else if (target instanceof AttributeString) {

		// If the pattern is an AttributePattern instead of an
		// AttributeString, the subclass method will get invoked.

		if (((AttributeString)pattern).match(
						(AttributeString)target)) {
		    return true;

		}

	    } else {
		Assert.slpassert(false,
			      "ssim_unk_qtype",
			      new Object[] {pattern.getClass().getName()});
	    }

	    return false;

	}

	// Add any registrations that are less than or equal to the pattern.

	boolean
	    compareLessEqual(Object target, Object pattern) {

	    if (target instanceof Integer) {
		if (((Integer)target).intValue() <=
		    ((Integer)pattern).intValue()) {
		    return true;

		}

	    } else if (target instanceof AttributeString) {

		if (((AttributeString)target).lessEqual(
						(AttributeString)pattern)) {
		    return true;

		}

	    } else if (target instanceof Long) {
		if (((Long)target).longValue() <=
		    ((Long)pattern).longValue()) {
		    return true;

		}

	    } else if (target instanceof Boolean ||
		       target instanceof Opaque) {
		if (target.toString().compareTo(pattern.toString()) <= 0) {
		    return true;

		}
	    } else {
		Assert.slpassert(false,
			      "ssim_unk_qtype",
			      new Object[] {target.getClass().getName()});
	    }

	    return false;

	}

	// Add any registrations that are greater than or equal to the pattern.

	boolean
	    compareGreaterEqual(Object target, Object pattern) {

	    if (target instanceof Integer) {
		if (((Integer)target).intValue() >=
		    ((Integer)pattern).intValue()) {
		    return true;

		}

	    } else if (target instanceof AttributeString) {

		if (((AttributeString)target).greaterEqual(
						(AttributeString)pattern)) {
		    return true;

		}

	    } else if (target instanceof Long) {
		if (((Long)target).longValue() >=
		    ((Long)pattern).longValue()) {
		    return true;

		}

	    } else if (target instanceof Boolean ||
		       target instanceof Opaque) {
		if (target.toString().compareTo(pattern.toString()) >= 0) {
		    return true;

		}

	    } else {
		Assert.slpassert(false,
			      "ssim_unk_qtype",
			      new Object[] {target.getClass().getName()});
	    }

	    return false;

	}
    }

    /**
     * The InMemoryEvaluator evaluates queries for ServiceStoreInMemory.
     *
     * @author James Kempf
     */

    private class InMemoryEvaluator implements Parser.QueryEvaluator {

	private Hashtable attrLevel;	// Sorted attribute table.
	private BtreeVector attrLevelNot;   // Used for universal negation.
	private Vector inScopes;            // Input scopes.
	private ParserBVCollector returns;  // For gathering results.

	InMemoryEvaluator(Hashtable ht,
			  BtreeVector btv,
			  Vector nscopes) {
	    attrLevel = ht;
	    attrLevelNot = btv;
	    inScopes = nscopes;
	    returns = new ParserBVCollector(inScopes);


	}

	// Evaluate the query by matching the attribute tag and
	//  value, using the operator. If invert is true, then
	//  return records that do NOT match.

	public boolean
	    evaluate(AttributeString tag,
		     char op,
		     Object pattern,
		     boolean invert,
		     Parser.ParserRecord prReturns)
	    throws ServiceLocationException {

	    boolean match = false;
	    returns.prReturns = prReturns;

	    // If inversion is on, then gather all from the
	    //  table of registrations that do NOT have this
	    //  attribute.

	    if (invert) {
		match = attrLevelNot.matchDoesNotContain(tag, returns);

	    }

	    // Find the table of classes v.s. sorted value vectors.

	    Hashtable ttable = (Hashtable)attrLevel.get(tag);

	    // If attribute not present, then simply return.

	    if (ttable == null) {

		return match;

	    }

	    // If operator is present, then return all.

	    if (op == Parser.PRESENT) {

		// ...but only if invert isn't on.

		if (!invert) {

		    // We use attrLevelNot to get all, because it
		    //  will also pick up keywords. There are
		    //  no keywords in attrLevel because keywords
		    //  don't have any values.

		    match = attrLevelNot.matchEqual(tag, returns);

		}

		return match;
	    }

	    // We know that the type table is fully initialized with
	    //  BtreeVectors for each type.

	    // Get the pattern's class. Pattern will not be null because
	    //  the parser has checked for it and PRESENT has been
	    //  filtered out above.

	    Class pclass = pattern.getClass();
	    String typeKey = pclass.getName();

	    // If the class is AttributePattern, then use AttributeString
	    //  instead.

	    if (pattern instanceof AttributePattern) {
		typeKey = pclass.getSuperclass().getName();

	    }

	    // If invert is on, collect those whose types don't match as
	    //  well.

	    if (invert) {
		Enumeration en = ttable.keys();

		while (en.hasMoreElements()) {
		    String key = (String)en.nextElement();

		    // Only record if the type does NOT match.

		    if (!key.equals(typeKey)) {
			BtreeVector bvec = (BtreeVector)ttable.get(key);

			match = match | bvec.getAll(returns);

		    }
		}
	    }

	    // Get the sorted value vector corresponding to the value class.

	    BtreeVector bvec = (BtreeVector)ttable.get(typeKey);

	    // Do the appropriate thing for the operator.

	    switch (op) {

	    case Parser.EQUAL:

		if (!invert) {
		    match = bvec.matchEqual(pattern, returns);

		} else {
		    match = bvec.matchNotEqual(pattern, returns);

		}
		break;

	    case Parser.LESS:

		// Note that we've filtered out Opaque, Boolean, and wildcarded
		// strings before calling this method.

		if (!invert) {
		    match = bvec.matchLessEqual(pattern, returns);

		} else {
		    match = bvec.matchNotLessEqual(pattern, returns);

		}
		break;

	    case Parser.GREATER:

		// Note that we've filtered out Opaque and Boolean
		// before calling this method.

		if (!invert) {
		    match = bvec.matchGreaterEqual(pattern, returns);

		} else {
		    match = bvec.matchNotGreaterEqual(pattern, returns);

		}
		break;

	    default:
		Assert.slpassert(false,
			      "ssim_unk_qop",
			      new Object[] {Character.valueOf((char)op)});
	    }

	    return match;
	}
    }

    /**
     * The ServiceRecordInMemory class implements the
     * ServiceStore.ServiceRecord interface on in-memory data structures.
     * Each property is implemented as an instance variable.
     *
     * @author James Kempf
     */

    private class ServiceRecordInMemory extends Object
	implements ServiceStore.ServiceRecord {

	private ServiceURL serviceURL = null;	// the service URL
	private Vector attrList = null;		// the attribute list
	private Locale locale = null;		// the locale
	private long timeToDie = 0;		// when the record should die.
	private Vector scopes = null;		// the scopes
	private Hashtable urlSig = null;
				// URL signature block list, if any.
	private Hashtable attrSig = null;
				// Attribute signature block list, if any.

	// Create a ServiceStoreInMemory record.

	ServiceRecordInMemory(ServiceURL surl, Vector alist,
			      Vector nscopes, Locale loc,
			      Hashtable nurlSig,
			      Hashtable nattrSig) {

	    // All need to be nonnull.

	    Assert.nonNullParameter(surl, "surl");
	    Assert.nonNullParameter(alist, "alist");
	    Assert.nonNullParameter(nscopes, "nscopes");
	    Assert.nonNullParameter(loc, "loc");

	    serviceURL = surl;
	    attrList = attributeVectorToServerAttribute(alist, loc);
	    scopes = nscopes;
	    locale = loc;
	    urlSig = nurlSig;
	    attrSig = nattrSig;

	    int lifetime = serviceURL.getLifetime();

	    timeToDie = lifetime * 1000 + System.currentTimeMillis();
	}

	/**
	 * Return the ServiceURL for the record.
	 *
	 * @return The record's service URL.
	 */

	public final ServiceURL getServiceURL() {
	    return serviceURL;

	}

	/**
	 * Return the Vector of ServerAttribute objects for the record.
	 *
	 * @return Vector of ServerAttribute objects for the record.
	 */

	public final Vector getAttrList() {
	    return attrList;

	}

	/**
	 * Return the locale of the registration.
	 *
	 * @return The locale of the registration.
	 */

	public final Locale getLocale() {
	    return locale;

	}

	/**
	 * Return the Vector of scopes in which the record is registered.
	 *
	 * @return Vector of strings with scope names.
	 */

	public final Vector getScopes() {
	    return scopes;

	}

	/**
	 * Return the expiration time for the record. This informs the
	 * service store when the record should expire and be removed
	 * from the table.
	 *
	 * @return The expiration time for the record.
	 */

	public long getExpirationTime() {
	    return timeToDie;

	}

	/**
	 * Return the URL signature list.
	 *
	 * @return URL signature block list.
	 */

	public Hashtable getURLSignature() {
	    return urlSig;

	}

	/**
	 * Return the attribute signature list.
	 *
	 * @return Attribute signature list.
	 */

	public Hashtable getAttrSignature() {
	    return attrSig;

	}


	//
	// Package-local methods.

	final void setAttrList(Vector newList) {
	    attrList = newList;

	}

	final void setScopes(Vector newScopes) {
	    scopes = newScopes;

	}

	final void setURLSignature(Hashtable nauth) {
	    urlSig = nauth;

	}

	final void setAttrSignature(Hashtable nauth) {
	    attrSig = nauth;

	}

	public String toString() {

	    String ret = "{";

	    ret +=
		serviceURL + ", " + locale + ", " + attrList + ", " +
		scopes + ", " + locale + ", " + urlSig + ", " + attrSig;

	    ret += "}";

	    return ret;
	}

	// Convert a vector of ServiceLocationAttribute objects to
	// ServerAttibutes.

	private Vector
	    attributeVectorToServerAttribute(Vector attrs, Locale locale) {
	    int i, n = attrs.size();
	    Vector v = new Vector();

	    for (i = 0; i < n; i++) {
		ServiceLocationAttribute attr =
		    (ServiceLocationAttribute)attrs.elementAt(i);

		v.addElement(new ServerAttribute(attr, locale));
	    }

	    return v;
	}

    }

    /**
     * A record for scopeTypeLangTable table,
     *
     * @author James Kempf
     */

    private class STLRecord extends Object {

	Hashtable attrValueSort = new Hashtable();
				// Table of attributes, sorted by value.
	BtreeVector attrSort = new BtreeVector();	// Btree of attributes.
	boolean isAbstract = false;
				// True if the record is for an abstract
				//  type.
	STLRecord(boolean isAbstract) {
	    this.isAbstract = isAbstract;

	}
    }

    //
    // ServiceStoreInMemory instance variables.
    //

    // ServiceStoreInMemory maintains an invaraint that the record for a
    //  particular URL, set of scopes, and locale is the same object
    //  (pointer-wise) regardless of where it is inserted into the table.
    //  So it can be compared with ==.

    // The scopeTypeLangTable
    //
    //  Keys for this table are scope/service type/lang tag. Values are
    //  STLRecord objects. The STLRecord.attrValueSort field is a Hashtable
    //  where all registrations *having* the attribute tag keys in the
    //  table are contained. This table is used in queries for positive
    //  logical expressions. The STLRecord.attrSort field is a BtreeVector
    //  keyed by attribute. It is used for negative queries to find all
    //  records not having a particular attribute and to find all
    //  registrations. The STLRecord.isAbstract field tells whether the record
    //  is for an abstract type name.
    //
    //  The values in the STLRecord.attrValueSort hashtable are themselves
    //  hashtables. These hashtables are keyed by one of the type keys below,
    //  with  the values being BtreeVector objects. The BtreeVector objects
    //  contain sorted lists of RegRecord objects for Integer,
    //  AttributeString, Boolean, and Opaque types. All records having
    //  values equal to the value in the RegRecord are put into a list
    //  on the RegRecord. There is no STLRecord.attrValueSort
    //  hashtable for keyword attributes because they have no values.
    //  The parser evaluator must use the STLRecord.attrSort hashtable when a
    //  present operator is encountered (the only valid operator with a
    //  keyword).
    //
    //  The values in the STLRecord.attrSort BtreeVector are RegRecord
    //  objects with all records having that attribute tag being on the
    //  RegRecord list.

    // Keys for the various types.

    private final static String INTEGER_TYPE = "java.lang.Integer";
    private final static String ATTRIBUTE_STRING_TYPE =
	"com.sun.slp.AttributeString";
    private final static String BOOLEAN_TYPE = "java.lang.Boolean";
    private final static String OPAQUE_TYPE = "com.sun.slp.Opaque";

    private Hashtable scopeTypeLangTable = new Hashtable();

    //  The urlScopeLangTable
    //
    //  Keys for this table are service url as a string. We don't use
    //  the service URL itself because the hash code depends on the
    //  current service type rather than the original, and we need
    //  to be able to distinguish for a non-service: URL if a
    //  registration comes in with a different service type from the
    //  original. Values are hashtables with key being scope name,
    //  values are hashtables with lang tag key. Ultimate values are
    //  a vector of List objects for lists in which List.record is
    //  inserted. This table is used to perform deletions and for
    //  finding the attributes associated with a particular URL.

    private Hashtable urlScopeLangTable = new Hashtable();

    //  The sstLocales Table
    //
    //  The scope/service type v.s. number of languages. Keys are
    //  the type/scope, values are a hashtable keyed by lang tag.
    //  Values in the lang tag table are Integer objects giving
    //  the number of registrations for that type/scope in the
    //  given locale.

    private Hashtable sstLocales = new Hashtable();

    // A queue of records sorted according to expiration time.

    BtreeVector ageOutQueue = new BtreeVector();

    // Constants that indicate whether there are any registrations.

    private final static int NO_REGS = 0;
    private final static int NO_REGS_IN_LOCALE = 1;
    private final static int REGS_IN_LOCALE = 2;

    // Boot time. For DAAdvert timestamps.

    private long bootTime = SLPConfig.currentSLPTime();

    //
    // ServiceStore Interface Methods.
    //

    /**
     * Return the time since the last stateless reboot
     * of the ServiceStore.
     *
     * @return A Long giving the time since the last stateless reboot,
     *         in NTP format.
     */

    public long getStateTimestamp() {

	return bootTime;

    }

    /**
     * Age out all records whose time has expired.
     *
     * @param deleted A Vector for return of ServiceStore.Service records
     *		     containing deleted services.
     * @return The time interval until another table walk must be done,
     *         in milliseconds.
     *
     */

    synchronized public long ageOut(Vector deleted) {

	// Get the ageOut queue and remove all records whose
	// time has popped.

	SLPConfig conf = SLPConfig.getSLPConfig();
	boolean traceDrop = conf.traceDrop();
	Vector queue = ageOutQueue.getContents();

	// Go through the queue, dropping records that
	//  have expired.

	int i;

	for (i = 0; i < queue.size(); i++) {
	    RegRecord qRec = (RegRecord)queue.elementAt(i);
	    long exTime = ((Long)(qRec.value)).longValue();
	    long time = System.currentTimeMillis();

	    // Break out when none expire now.

	    if (exTime > time) {
		break;

	    }

	    // Remove the element from the queue.

	    /*
	     *  Must decrement the index 'i' otherwise the next iteration
	     *  around the loop will miss the element immediately after
	     *  the element removed.
	     *
	     *  WARNING: Do not use 'i' again until the loop has
	     *           iterated as it may, after decrementing,
	     *           be negative.
	     */
	    queue.removeElementAt(i);
	    i--;

	    // Deregister all on this list. We
	    // take specific care to save the next
	    // list element before we deregister, otherwise
	    // it will be gone after the deregister.

	    List l = qRec.head.next;

	    while (l != null) {
		ServiceRecordInMemory rec = l.record;
		ServiceURL url = rec.getServiceURL();
		Vector scopes = rec.getScopes();
		Locale locale = rec.getLocale();

		if (traceDrop) {
		    conf.writeLog("ssim_ageout",
				  new Object[] {
			url,
			    rec.getAttrList(),
			    scopes,
			    locale,
			    rec.getURLSignature(),
			    rec.getAttrSignature(),
			    Long.toString(time),
			    Long.toString(exTime)});
		}

		// Save the record for the service table, in case more
		// processing needed.

		deleted.addElement(rec);

		// Save l.next NOW before deregisterInternal() removes it!

		l = l.next;

		String lang = locale.getLanguage();

		deregisterInternal(url, scopes, lang);

	    }
	}

	// Calculate the new sleep time. If there's anything in the vector,
	// then use element 0, because the vector is sorted by time
	// and that will be minimum. Otherwise, use the maximum.

	long newSleepy = Defaults.lMaxSleepTime;

	if (queue.size() > 0) {
	    RegRecord rec = (RegRecord)queue.elementAt(0);

	    newSleepy =
		((Long)(rec.value)).longValue() - System.currentTimeMillis();

	    newSleepy = (newSleepy > 0 ? newSleepy:0);
						// it will wake right up, but
						// so what?

	}

	return newSleepy;

    }

    /**
     * Create a new registration with the given parameters.
     *
     * @param url The ServiceURL.
     * @param attrs The Vector of ServiceLocationAttribute objects.
     * @param locale The Locale.
     * @param scopes Vector of scopes in which this record is registered.
     * @param urlSig auth block Hashtable for URL signature, or null if none.
     * @param attrSig auth block Hashtable for URL signature, or null if none.
     * @return True if there is an already existing registration that
     *         this one replaced.
     * @exception ServiceLocationException Thrown if any
     *			error occurs during registration or if the table
     * 			requires a network connection that failed. This
     *			includes timeout failures.
     */

    synchronized public boolean
	register(ServiceURL url, Vector attrs,
		 Vector scopes, Locale locale,
		 Hashtable urlSig, Hashtable attrSig)
	throws ServiceLocationException {

	boolean existing = false;

	String lang = locale.getLanguage();

	// Find an existing record, in any set of scopes having this language.

	ServiceRecordInMemory rec = findExistingRecord(url, null, lang);

	// Deregister from existing scopes, if there is an existing record.

	if (rec != null) {
	    if (urlSig != null) {
		// Ensure that the rereg SPI set and the record's SPI set are
		// equivalent. We need only check the URL sigs here, since
		// this operation is equivalent to a dereg followed by a reg,
		// and dereg requires only URL auth blocks.

		Enumeration spis = urlSig.keys();
		while (spis.hasMoreElements()) {
		    Object spi = spis.nextElement();
		    if (rec.urlSig.remove(spi) == null) {
			throw new ServiceLocationException(
				ServiceLocationException.AUTHENTICATION_FAILED,
				"not_all_spis_present",
				new Object[] {spi});
		    }
		}
		if (rec.urlSig.size() != 0) {
		    // not all required SPIs were present in SrvReg
		    throw new ServiceLocationException(
				ServiceLocationException.AUTHENTICATION_FAILED,
				"not_all_spis_present",
				new Object[] {rec.urlSig.keys()});
		}
	    }

	    deregisterInternal(url, rec.getScopes(), lang);
	    existing = true;

	}

	// Create a new record to register.

	rec = new ServiceRecordInMemory(url, attrs, scopes,
					locale, urlSig, attrSig);

	// Add new registration.

	registerInternal(rec);

	return existing;

    }

    /**
     * Deregister a ServiceURL from the database for every locale
     * and every scope. There will be only one record for each URL
     * and locale deregistered, regardless of the number of scopes in
     * which the URL was registered, since the attributes will be the
     * same in each scope if the locale is the same.
     *
     * @param url The ServiceURL
     * @param scopes Vector of scopes.
     * @param urlSig The URL signature, if any.
     * @exception ServiceLocationException Thrown if the
     *			ServiceStore does not contain the URL, or if any
     *			error occurs during the operation, or if the table
     * 			requires a network connection that failed. This
     *			includes timeout failures.
     */

    synchronized public void
	deregister(ServiceURL url, Vector scopes, Hashtable urlSig)
	throws ServiceLocationException {

	// Find existing record. Any locale will do.

	ServiceRecordInMemory oldRec =
	    findExistingRecord(url, scopes, null);

	// Error if none.

	if (oldRec == null) {
	    throw
		new ServiceLocationException(
				ServiceLocationException.INVALID_REGISTRATION,
				"ssim_no_rec",
				new Object[] {url});

	}

	// verify that the dereg SPI set and the record's SPI set are
	// equivalent
	if (urlSig != null) {
	    Enumeration spis = urlSig.keys();
	    while (spis.hasMoreElements()) {
		Object spi = spis.nextElement();
		if (oldRec.urlSig.remove(spi) == null) {
		    throw new ServiceLocationException(
				ServiceLocationException.AUTHENTICATION_FAILED,
				"not_all_spis_present",
				new Object[] {spi});
		}
	    }
	    if (oldRec.urlSig.size() != 0) {
		// not all required SPIs were present in SrvDereg
		throw new ServiceLocationException(
				ServiceLocationException.AUTHENTICATION_FAILED,
				"not_all_spis_present",
				new Object[] {oldRec.urlSig.keys()});
	    }
	}

	/*
	 * Deregister the URL for all locales. Use the recorded service URL
	 * because the one passed by the client is possibly incomplete e.g.
	 * lacking the service type.
	 */

	deregisterInternal(oldRec.getServiceURL(), scopes, null);

    }

    /**
     * Update the service registration with the new parameters, adding
     * attributes and updating the service URL's lifetime.
     *
     * @param url The ServiceURL.
     * @param attrs The Vector of ServiceLocationAttribute objects.
     * @param locale The Locale.
     * @param scopes Vector of scopes in which this record is registered.
     * @exception ServiceLocationException Thrown if any
     *			error occurs during registration or if the table
     * 			requires a network connection that failed. This
     *			includes timeout failures.
     */

    synchronized public void
	updateRegistration(ServiceURL url, Vector attrs,
			   Vector scopes, Locale locale)
	throws ServiceLocationException {

	String lang = locale.getLanguage();
	ServiceRecordInMemory oldRec =
	    findExistingRecord(url, scopes, lang);

	// Error if none.

	if (oldRec == null) {
	    throw
		new ServiceLocationException(
				ServiceLocationException.INVALID_UPDATE,
				"ssim_no_rec",
				new Object[] {url});

	}

	// If this is a nonServiceURL, check whether it's registered
	//  under a different service type.

	ServiceType type = url.getServiceType();

	if (!type.isServiceURL()) {
	    checkForExistingUnderOtherServiceType(url, scopes);

	}

	// Deregister the URL in this locale.

	deregisterInternal(url, scopes, lang);

	// Create a new record to update.

	ServiceRecordInMemory rec =
	    new ServiceRecordInMemory(url, attrs, scopes,
				      locale, null, null);

	// Merge old record into new.

	mergeOldRecordIntoNew(oldRec, rec);

	// Add the new record.

	registerInternal(rec);
    }

    /**
     * Delete the attributes from the ServiceURL object's table entries.
     * Delete for every locale that has the attributes and every scope.
     * Note that the attribute tags must be lower-cased in the locale of
     * the registration, not in the locale of the request.
     *
     * @param url The ServiceURL.
     * @param scopes Vector of scopes.
     * @param attrTags The Vector of String
     *			objects specifying the attribute tags of
     *			the attributes to delete.
     * @param locale Locale of the request.
     * @exception ServiceLocationException Thrown if the
     *			ServiceStore does not contain the URL or if any
     *			error occurs during the operation or if the table
     * 			requires a network connection that failed. This
     *			includes timeout failures.
     */

    synchronized public void
	deleteAttributes(ServiceURL url,
			 Vector scopes,
			 Vector attrTags,
			 Locale locale)
	throws ServiceLocationException {

	String lang = SLPConfig.localeToLangTag(locale);

	// Get the scope level from urlScopeLangTable.

	Hashtable scopeLevel =
	    (Hashtable)urlScopeLangTable.get(url.toString());

	// Error if no old record to update.

	if (scopeLevel == null) {
	    throw
		new ServiceLocationException(
				ServiceLocationException.INVALID_REGISTRATION,
				"ssim_no_rec",
				new Object[] {url});

	}

	// Check existing records to be sure that the scopes
	//  match. Attributes must be the same across
	//  scopes.

	checkScopeStatus(url,
			 scopes,
			 ServiceLocationException.INVALID_REGISTRATION);

	// Create attribute patterns for the default locale. This
	//  is an optimization. Only Turkish differs in lower
	//  case from the default. If there are any other exceptions,
	//  we need to move this into the loop.

	Vector attrPatterns =
	    stringVectorToAttributePattern(attrTags, Defaults.locale);

	// Look through the language table for this language at scope level.

	Enumeration en = scopeLevel.keys();

	Assert.slpassert(en.hasMoreElements(),
		      "ssim_empty_scope_table",
		      new Object[] {url});

	Hashtable ht = new Hashtable();
	boolean foundIt = false;

	while (en.hasMoreElements()) {
	    String scope = (String)en.nextElement();
	    Hashtable langLevel = (Hashtable)scopeLevel.get(scope);
	    Enumeration een = langLevel.keys();

	    Assert.slpassert(een.hasMoreElements(),
			  "ssim_empty_lang_table",
			  new Object[] {url});

	    // Find the list of records for this language.

	    Vector listVec = (Vector)langLevel.get(lang);

	    if (listVec == null) {
		continue;

	    }

	    foundIt = true;

	    List elem = (List)listVec.elementAt(0);
	    ServiceRecordInMemory rec = elem.record;
	    Locale loc = rec.getLocale();

	    // If we've done this one already, go on.

	    if (ht.get(rec) != null) {
		continue;

	    }

	    ht.put(rec, rec);

	    // Delete old registration.

	    deregisterInternal(url, rec.getScopes(), lang);

	    // Delete attributes from this record.

	    // If the locale is Turkish, then use the Turkish patterns.

	    if (loc.getLanguage().equals("tr")) {
		Vector turkishTags =
		    stringVectorToAttributePattern(attrTags, loc);

		deleteAttributes(rec, turkishTags);

	    } else {
		deleteAttributes(rec, attrPatterns);

	    }

	    // Reregister the record.

	    registerInternal(rec);
	}

	// If no record found, report error.

	if (!foundIt) {
	    throw
		new ServiceLocationException(
				ServiceLocationException.INVALID_REGISTRATION,
				"ssim_no_rec_locale",
				new Object[] {url, locale});

	}

    }

    /**
     * Return a Vector of String containing the service types for this
     * scope and naming authority. If there are none, an empty vector is
     * returned.
     *
     * @param namingAuthority The namingAuthority, or "*" if for all.
     * @param scopes The scope names.
     * @return A Vector of String objects that are the type names, or
     *		an empty vector if there are none.
     * @exception ServiceLocationException Thrown if any
     *			error occurs during the operation or if the table
     * 			requires a network connection that failed. This
     *			includes timeout failures.
     */

    synchronized public Vector
	findServiceTypes(String namingAuthority, Vector scopes)
	throws ServiceLocationException {

	Vector ret = new Vector();
	Enumeration keys = scopeTypeLangTable.keys();
	boolean isWildCard = namingAuthority.equals("*");
	boolean isIANA = (namingAuthority.length() <= 0);

	// Get all the keys in the table, look for scope.

	while (keys.hasMoreElements()) {
	    String sstKey = (String)keys.nextElement();

	    // Check whether this is an abstract type entry.
	    //  If so, then we ignore it, because we only
	    //  want full type names in the return.

	    if (isAbstractTypeRecord(sstKey)) {
		continue;

	    }

	    // If the scope matches then check the naming authority.

	    String keyScope = keyScope(sstKey);

	    if (scopes.contains(keyScope)) {
		String keyType = keyServiceType(sstKey);

		// If not already there, see if we should add this one to the
		//  vector.

		if (!ret.contains(keyType)) {
		    ServiceType type = new ServiceType(keyType);

		    // If wildcard, then simply add it to the vector.

		    if (isWildCard) {
			ret.addElement(type.toString());

		    } else {

			// Check naming authority.

			String na = type.getNamingAuthority();

			if (type.isNADefault() && isIANA) { // check for IANA..
			    ret.addElement(type.toString());

			} else if (namingAuthority.equals(na)) { // Not IANA..
			    ret.addElement(type.toString());

			}
		    }
		}
	    }
	}

	return ret;
    }

    /**
     * Return a Hashtable with the key FS_SERVICES matched to the
     * hashtable of ServiceURL objects as key and a vector
     * of their scopes as value, and the key FS_SIGTABLE
     * matched to a hashtable with ServiceURL objects as key
     * and the auth block Hashtable for the URL (if any) for value. The
     * returned service URLs will match the service type, scope, query,
     * and locale. If there are no signatures, the FS_SIGTABLE
     * key returns null. If there are no
     * registrations in any locale, FS_SERVICES is bound to an
     * empty table.
     *
     * @param serviceType The service type name.
     * @param scope The scope name.
     * @param query The query, with any escaped characters as yet unprocessed.
     * @param locale The locale in which to lowercase query and search.
     * @return A Hashtable with the key FS_SERVICES matched to the
     *         hashtable of ServiceURL objects as key and a vector
     *         of their scopes as value, and the key FS_SIGTABLE
     *         matched to a hashtable with ServiceURL objects as key
     *         and the auth block Hashtable for the URL (if any) for value.
     *         If there are no registrations in any locale, FS_SERVICES
     *	      is bound to an empty table.
     * @exception ServiceLocationException Thrown if a parse error occurs
     *			during query parsing or if any
     *			error occurs during the operation or if the table
     * 			requires a network connection that failed. This
     *			includes timeout failures.
     */

    synchronized public Hashtable
	findServices(String serviceType,
		     Vector scopes,
		     String query,
		     Locale locale)
	throws ServiceLocationException {

	String lang = locale.getLanguage();
	Parser.ParserRecord ret = new Parser.ParserRecord();
	Hashtable services = null;
	Hashtable signatures = null;
	int i, n = scopes.size();
	int len = 0;

	// Get the services and signatures tables.

	services = ret.services;
	signatures = ret.signatures;

	// Remove leading and trailing spaces.

	query = query.trim();
	len = query.length();

	// Check whether there are any registrations for this type/scope/
	//  language tag and, if not, whether there are others.
	//  in another language, but not this one.

	int regStatus = languageSupported(serviceType, scopes, lang);

	if (regStatus == NO_REGS_IN_LOCALE) {
	    throw
		new ServiceLocationException(
			ServiceLocationException.LANGUAGE_NOT_SUPPORTED,
			"ssim_lang_unsup",
			new Object[] {locale});

	} else if (regStatus == REGS_IN_LOCALE) {

	    // Only do query if regs exist.

	    for (i = 0; i < n; i++) {
		String scope = (String)scopes.elementAt(i);
		String sstKey =
		    makeScopeTypeLangKey(scope, serviceType, lang);
		STLRecord regRecs =
		    (STLRecord)scopeTypeLangTable.get(sstKey);

		// If no record for this combo of service type and
		//  scope, continue.

		if (regRecs == null) {
		    continue;
		}

		// Special case if the query string is empty. This
		//  indicates that all registrations should be returned.

		if (len <= 0) {
		    BtreeVector bvec = regRecs.attrSort;
		    ParserBVCollector collector =
			new ParserBVCollector(scopes);
		    collector.prReturns = ret;

		    // Use the BtreeVector.getAll() method to get all
		    //  registrations. We will end up revisiting some
		    //  list elements because there will be ones
		    //  for multiple attributes, but that will be
		    //  filtered in the BVCollector.setReturn() method.

		    bvec.getAll(collector);

		} else {

		    // Otherwise, use the LDAPv3 parser to evaluate.

		    InMemoryEvaluator ev =
			new InMemoryEvaluator(regRecs.attrValueSort,
					      regRecs.attrSort,
					      scopes);

		    Parser.parseAndEvaluateQuery(query, ev, locale, ret);

		}
	    }
	}

	// Create return hashtable.

	Hashtable ht = new Hashtable();

	// Set up return hashtable.

	ht.put(ServiceStore.FS_SERVICES, services);

	// Put in signatures if there.

	if (signatures.size() > 0) {
	    ht.put(ServiceStore.FS_SIGTABLE, signatures);

	}

	return ht;
    }

    /**
     * Return a Hashtable with key FA_ATTRIBUTES matched to the
     * vector of ServiceLocationAttribute objects and key FA_SIG
     * matched to the auth block Hashtable for the attributes (if any)
     * The attribute objects will have tags matching the tags in
     * the input parameter vector. If there are no registrations in any locale,
     * FA_ATTRIBUTES is an empty vector.
     *
     * @param url The ServiceURL for which the records should be returned.
     * @param scopes The scope names for which to search.
     * @param attrTags The Vector of String
     *			objects containing the attribute tags.
     * @param locale The locale in which to lower case tags and search.
     * @return A Hashtable with a vector of ServiceLocationAttribute objects
     *         as the key and the auth block Hashtable for the attributes
     *         (if any) as the value.
     *         If there are no registrations in any locale, FA_ATTRIBUTES
     *         is an empty vector.
     * @exception ServiceLocationException Thrown if any
     *			error occurs during the operation or if the table
     * 			requires a network connection that failed. This
     *			includes timeout failures. An error should be
     *			thrown if the tag vector is for a partial request
     *			and any of the scopes are protected.
     */

    synchronized public Hashtable
	findAttributes(ServiceURL url,
		       Vector scopes,
		       Vector attrTags,
		       Locale locale)
	throws ServiceLocationException {

	Hashtable ht = new Hashtable();
	Vector ret = new Vector();
	String lang = locale.getLanguage();
	Hashtable sig = null;

	// Check whether there are any registrations for this scope/type
	//  language and, if not, whether there are others.
	//  in another language, but not this one.

	int regStatus =
	    languageSupported(url.getServiceType().toString(), scopes, lang);

	if (regStatus == NO_REGS_IN_LOCALE) {
	    throw
		new ServiceLocationException(
			ServiceLocationException.LANGUAGE_NOT_SUPPORTED,
			"ssim_lang_unsup",
			new Object[] {locale});

	} else if (regStatus == REGS_IN_LOCALE) {

	    // Only if there are any regs at all.

	    // Process string tags into pattern objects. Note that, here,
	    //  the patterns are locale specific because the locale of
	    //  the request determines how the attribute tags are lower
	    //  cased.

	    attrTags = stringVectorToAttributePattern(attrTags, locale);

	    // Return attributes from the matching URL record.

	    Hashtable scopeLevel =
		(Hashtable)urlScopeLangTable.get(url.toString());

	    // If nothing there, then simply return. The URL isn't
	    //  registered.

	    if (scopeLevel != null) {

		// We reuse ht here for attributes.

		int i, n = scopes.size();

		for (i = 0; i < n; i++) {
		    String scope = (String)scopes.elementAt(i);
		    Hashtable langLevel =
			(Hashtable)scopeLevel.get(scope);

		    // If no registration in this scope, continue.

		    if (langLevel == null) {
			continue;
		    }

		    // Get the vector of lists.

		    Vector listVec = (Vector)langLevel.get(lang);

		    // If no registration in this locale, continue.

		    if (listVec == null) {
			continue;

		    }

		    // Get the service record.

		    List elem = (List)listVec.elementAt(0);
		    ServiceRecordInMemory rec = elem.record;

		    // Once we've found *the* URL record, we can leave the loop
		    //  because there is only one record per locale.

		    findMatchingAttributes(rec, attrTags, ht, ret);

		    // Clear out the hashtable. We reuse it for the return.

		    ht.clear();

		    // Store the return vector and the signatures, if any.

		    ht.put(ServiceStore.FA_ATTRIBUTES, ret);

		    sig = rec.getAttrSignature();

		    if (sig != null) {
			ht.put(ServiceStore.FA_SIG, sig);

		    }

		    break;

		}
	    }
	}

	// Put in the empty vector, in case there are no regs at all.

	if (ht.size() <= 0) {
	    ht.put(ServiceStore.FA_ATTRIBUTES, ret);

	}

	return ht;
    }

    /**
     * Return a Vector of ServiceLocationAttribute objects with attribute tags
     * matching the tags in the input parameter vector for all service URL's
     * of the service type. If there are no registrations
     * in any locale, an empty vector is returned.
     *
     * @param serviceType The service type name.
     * @param scopes The scope names for which to search.
     * @param attrTags The Vector of String
     *			objects containing the attribute tags.
     * @param locale The locale in which to lower case tags.
     * @return A Vector of ServiceLocationAttribute objects matching the query.
     *         If no match occurs but there are registrations
     * 	      in other locales, null is returned. If there are no registrations
     *         in any locale, an empty vector is returned.
     * @exception ServiceLocationException Thrown if any
     *		 error occurs during the operation or if the table
     * 		 requires a network connection that failed. This
     *		 includes timeout failures. An error should also be
     *            signalled if any of the scopes are protected.
     */

    synchronized public Vector
	findAttributes(String serviceType,
		       Vector scopes,
		       Vector attrTags,
		       Locale locale)
	throws ServiceLocationException {

	String lang = locale.getLanguage();
	Vector ret = new Vector();

	// Check whether there are any registrations for this type/scope/
	//  language and, if not, whether there are others.
	//  in another language, but not this one.

	int regStatus = languageSupported(serviceType, scopes, lang);

	if (regStatus == NO_REGS_IN_LOCALE) {
	    throw
		new ServiceLocationException(
			ServiceLocationException.LANGUAGE_NOT_SUPPORTED,
			"ssim_lang_unsup",
			new Object[] {locale});

	} else if (regStatus == REGS_IN_LOCALE) {

	    // Process string tags into pattern objects. Note that, here,
	    //  the patterns are locale specific because the locale of
	    //  the request determines how the attribute tags are lower
	    //  cased.

	    attrTags = stringVectorToAttributePattern(attrTags, locale);
	    int len = attrTags.size();

	    // Make a collector for accessing the BtreeVector.

	    BVCollector collector =
		new AttributeBVCollector(attrTags, ret);
	    int i, n = scopes.size();

	    for (i = 0; i < n; i++) {
		String scope = (String)scopes.elementAt(i);
		String sstKey =
		    makeScopeTypeLangKey(scope, serviceType, lang);
		STLRecord regRecs = (STLRecord)scopeTypeLangTable.get(sstKey);

		// If no service type and scope, go to next scope.

		if (regRecs == null) {
		    continue;
		}

		// Get BtreeVector with all attributes for searching.

		BtreeVector bvec = regRecs.attrSort;

		// If there are no tags, then simply return everything in
		//  the BtreeVector.

		if (len <= 0) {
		    bvec.getAll(collector);

		} else {

		    // Use Btree vector to match the attribute tag patterns,
		    //  returning matching records.

		    int j;

		    for (j = 0; j < len; j++) {
			AttributePattern pat =
			    (AttributePattern)attrTags.elementAt(j);

			bvec.matchEqual(pat, collector);

		    }
		}
	    }
	}

	return ret;
    }

    /**
     * Obtain the record matching the service URL and locale.
     *
     * @param URL The service record to match.
     * @param locale The locale of the record.
     * @return The ServiceRecord object, or null if none.
     */

    synchronized public ServiceStore.ServiceRecord
	getServiceRecord(ServiceURL URL, Locale locale) {

	if (URL == null || locale == null) {
	    return null;

	}

	// Search in all scopes.

	return findExistingRecord(URL,
				  null,
				  SLPConfig.localeToLangTag(locale));

    }

    /**
     * Obtains service records with scopes matching from vector scopes.
     * If scopes is null, then returns all records.
     *
     * @param scopes Vector of scopes to match.
     * @return Enumeration   Of ServiceRecord Objects.
     */
    synchronized public Enumeration getServiceRecordsByScope(Vector scopes) {

	// Use a scope collector.

	Vector records = new Vector();
	BVCollector collector =
	    new ScopeBVCollector(records, scopes);

	Enumeration keys = scopeTypeLangTable.keys();

	while (keys.hasMoreElements()) {
	    String sstKey = (String)keys.nextElement();
	    STLRecord regRecs = (STLRecord)scopeTypeLangTable.get(sstKey);

	    // Get all records.

	    BtreeVector bvec = regRecs.attrSort;
	    bvec.getAll(collector);

	}

	return records.elements();
    }


    /**
     * Dump the service store to the log.
     *
     */

    synchronized public void dumpServiceStore() {

	SLPConfig conf = SLPConfig.getSLPConfig();

	conf.writeLogLine("ssim_dump_start",
			  new Object[] {this});

	Enumeration keys = scopeTypeLangTable.keys();

	while (keys.hasMoreElements()) {
	    String sstKey = (String)keys.nextElement();
	    STLRecord regRec = (STLRecord)scopeTypeLangTable.get(sstKey);

	    // If the service type is abstract, then skip it. It will be
	    //  displayed when the concrete type is.

	    if (regRec.isAbstract) {
		continue;

	    }

	    // Get all records.

	    BtreeVector bvec = regRec.attrSort;
	    Vector vReturns = new Vector();
	    BVCollector collector = new AllBVCollector(vReturns);

	    bvec.getAll(collector);

	    // Now write them out.

	    int i, n = vReturns.size();

	    for (i = 0; i < n; i++) {
		ServiceRecordInMemory rec =
		    (ServiceRecordInMemory)vReturns.elementAt(i);

		writeRecordToLog(conf, rec);
	    }
	}

	conf.writeLog("ssim_dump_end",
		      new Object[] {this});
    }

    //
    // Protected/private methods.
    //

    // Register the record without any preliminaries. We assume that
    //  any old records have been removed and merged into this one,
    //  as necessary.

    private void registerInternal(ServiceRecordInMemory rec) {

	ServiceURL surl = rec.getServiceURL();
	ServiceType type = surl.getServiceType();
	String serviceType = type.toString();
	String abstractTypeName = type.getAbstractTypeName();
	Locale locale = rec.getLocale();
	String lang = locale.getLanguage();
	Vector scopes = rec.getScopes();

	// Make one age out queue entry. It will go into
	//  all scopes, but that's OK.

	List ageOutElem = addToAgeOutQueue(rec);

	// Go through all scopes.

	int i, n = scopes.size();

	for (i = 0; i < n; i++) {
	    String scope = (String)scopes.elementAt(i);

	    // Initialize the urltable list vector for this URL.

	    Vector listVec =
		initializeURLScopeLangTableVector(surl, scope, lang);

	    // Add to scope/type/lang table.

	    addRecordToScopeTypeLangTable(scope,
					  serviceType,
					  lang,
					  false,
					  rec,
					  listVec);

	    // Add a new service type/scope record for this locale.

	    addTypeLocale(serviceType, scope, lang);

	    // Add ageOut record, so that it gets deleted when
	    //  the record does.

	    listVec.addElement(ageOutElem);

	    // If the type is an abstract type, then add
	    //  separate records.

	    if (type.isAbstractType()) {
		addRecordToScopeTypeLangTable(scope,
					      abstractTypeName,
					      lang,
					      true,
					      rec,
					      listVec);
		addTypeLocale(abstractTypeName, scope, lang);

	    }
	}
    }

    // Create a urlScopeLangTable record for this URL.

    private Vector
	initializeURLScopeLangTableVector(ServiceURL url,
					  String scope,
					  String lang) {

	// Get scope level, creating if new.

	Hashtable scopeLevel =
	    (Hashtable)urlScopeLangTable.get(url.toString());

	if (scopeLevel == null) {
	    scopeLevel = new Hashtable();
	    urlScopeLangTable.put(url.toString(), scopeLevel);

	}

	// Get lang level, creating if new.

	Hashtable langLevel =
	    (Hashtable)scopeLevel.get(scope);

	if (langLevel == null) {
	    langLevel = new Hashtable();
	    scopeLevel.put(scope, langLevel);

	}

	// Check whether there's anything already there.
	//  Bug if so.

	Assert.slpassert(langLevel.get(lang) == null,
		      "ssim_url_lang_botch",
		      new Object[] {lang,
					url,
					scope});

	// Add a new list vector, and return it.

	Vector listVec = new Vector();

	langLevel.put(lang, listVec);

	return listVec;

    }

    // Add a record to the scope/type/language table.

    private void
	addRecordToScopeTypeLangTable(String scope,
				      String serviceType,
				      String lang,
				      boolean isAbstract,
				      ServiceRecordInMemory rec,
				      Vector listVec) {

	// Make key for scope/type/language table.

	String stlKey = makeScopeTypeLangKey(scope, serviceType, lang);

	// Get record for scope/type/lang.

	STLRecord trec = (STLRecord)scopeTypeLangTable.get(stlKey);

	// If it's not there, make it.

	if (trec == null) {
	    trec = new STLRecord(isAbstract);
	    scopeTypeLangTable.put(stlKey, trec);

	}

	// Otherwise, add record to all.

	addRecordToAttrValueSort(trec.attrValueSort, rec, listVec);
	addRecordToAttrSort(trec.attrSort, rec, listVec);

    }

    // Add a new record into the attr value table.

    private void
	addRecordToAttrValueSort(Hashtable table,
				 ServiceRecordInMemory rec,
				 Vector listVec) {

	Vector attrList = rec.getAttrList();
	int i, n = attrList.size();

	// Go through the attribute list.

	for (i = 0; i < n; i++) {
	    ServerAttribute attr =
		(ServerAttribute)attrList.elementAt(i);
	    AttributeString tag = attr.idPattern;
	    Vector values = attr.values;

	    // If a type table record exists, use it. Otherwise,
	    //  create a newly initialized one.

	    Hashtable ttable = (Hashtable)table.get(tag);

	    if (ttable == null) {
		ttable = makeAttrTypeTable();
		table.put(tag, ttable);

	    }

	    // Get the class of values.

	    String typeKey = null;

	    if (values == null) {

		// We're done, since there are no attributes to add.

		continue;

	    } else {
		Object val = values.elementAt(0);

		typeKey = val.getClass().getName();
	    }

	    // Get the BtreeVector.

	    BtreeVector bvec =
		(BtreeVector)ttable.get(typeKey);

	    // Insert a record for each value.

	    int j, m = values.size();

	    for (j = 0; j < m; j++) {
		List elem = bvec.add(values.elementAt(j), rec);

		// Put the element into the deletion table.

		listVec.addElement(elem);
	    }
	}
    }

    // Return a newly initialized attribute type table. It will
    //  have a hash for each allowed type, with a new BtreeVector
    //  attached.

    private Hashtable makeAttrTypeTable() {

	Hashtable ret = new Hashtable();

	ret.put(INTEGER_TYPE, new BtreeVector());
	ret.put(ATTRIBUTE_STRING_TYPE, new BtreeVector());
	ret.put(BOOLEAN_TYPE, new BtreeVector());
	ret.put(OPAQUE_TYPE, new BtreeVector());

	return ret;
    }

    // Add a new record into the attrs table.

    private void
	addRecordToAttrSort(BtreeVector table,
			    ServiceRecordInMemory rec,
			    Vector listVec) {

	Vector attrList = rec.getAttrList();
	int i, n = attrList.size();

	// If no attributes, then add with empty string as
	//  the attribute tag.

	if (n <= 0) {
	    List elem =
		table.add(new AttributeString("", rec.getLocale()), rec);

	    listVec.addElement(elem);

	    return;
	}

	// Iterate through the attribute list, adding to the
	//  BtreeVector with attribute as the sort key.

	for (i = 0; i < n; i++) {
	    ServerAttribute attr =
		(ServerAttribute)attrList.elementAt(i);

	    List elem = table.add(attr.idPattern, rec);

	    // Save for deletion.

	    listVec.addElement(elem);

	}
    }

    // Add a record to the ageOut queue.

    private List addToAgeOutQueue(ServiceRecordInMemory rec) {

	Long exTime = Long.valueOf(rec.getExpirationTime());
	return ageOutQueue.add(exTime, rec);

    }

    // Remove the URL record from the database.

    private void
	deregisterInternal(ServiceURL url, Vector scopes, String lang) {

	ServiceType type = url.getServiceType();

	// To deregister, we only need to find the Vector of List objects
	//  containing the places where this registration is hooked into
	//  lists and unhook them. Garbage collection of other structures
	//  is handled during insertion or in deregisterTypeLocale(),
	//  if there are no more registrations at all.

	// Find the scope table..

	Hashtable scopeLangTable =
	    (Hashtable)urlScopeLangTable.get(url.toString());

	// If it's not there, then maybe not registered.

	if (scopeLangTable == null) {
	    return;

	}

	// For each scope, find the lang table.

	int i, n = scopes.size();

	for (i = 0; i < n; i++) {
	    String scope = (String)scopes.elementAt(i);

	    Hashtable langTable = (Hashtable)scopeLangTable.get(scope);

	    if (langTable == null) {
		continue;
	    }

	    // If the locale is non-null, then just deregister from this
	    //  locale.

	    if (lang != null) {
		deregisterFromLocale(langTable, lang);

		// Record the deletion in the scope/type table, and
		//  also the number of regs table.

		deleteTypeLocale(type.toString(), scope, lang);

		// Check for abstract type as well.

		if (type.isAbstractType()) {
		    deleteTypeLocale(type.getAbstractTypeName(), scope, lang);

		}

	    } else {

		// Otherwise, deregister all languages.

		Enumeration en = langTable.keys();

		while (en.hasMoreElements()) {
		    lang = (String)en.nextElement();

		    deregisterFromLocale(langTable, lang);

		    // Record the deletion in the scope/type table, and
		    //  also the number of regs table.

		    deleteTypeLocale(type.toString(), scope, lang);

		    // Check for abstract type as well.

		    if (type.isAbstractType()) {
			deleteTypeLocale(type.getAbstractTypeName(),
					 scope,
					 lang);

		    }
		}
	    }

	    // If the table is empty, then remove the lang table.

	    if (langTable.size() <= 0) {
		scopeLangTable.remove(scope);

	    }
	}

	// If all languages were deleted, delete the
	//  urlScopeLangTable record. Other GC handled in
	//  deleteTypeLocale().

	if (scopeLangTable.size() <= 0) {
	    urlScopeLangTable.remove(url.toString());

	}

    }

    // Deregister a single locale from the language table.

    private void deregisterFromLocale(Hashtable langTable, String lang) {

	// Get the Vector containing the list of registrations.

	Vector regList = (Vector)langTable.get(lang);

	Assert.slpassert(regList != null,
		      "ssim_null_reg_vector",
		      new Object[] {lang});

	// Walk down the list of registrations and unhook them from
	//  their respective lists.

	int i, n = regList.size();

	for (i = 0; i < n; i++) {
	    List elem = (List)regList.elementAt(i);

	    elem.delete();

	}

	// Remove the locale record.

	langTable.remove(lang);
    }

    // Find an existing record matching the URL by searching in all scopes.
    //  The record will be the same for all scopes in the same language.
    //  If locale is null, return any. If there are none, return null.

    private ServiceRecordInMemory
	findExistingRecord(ServiceURL surl, Vector scopes, String lang) {

	ServiceRecordInMemory rec = null;

	// Look in urlScopeLangTable.

	Hashtable scopeLevel =
	    (Hashtable)urlScopeLangTable.get(surl.toString());

	if (scopeLevel != null) {

	    // If scopes is null, then perform the search for all
	    //  scopes in the table. Otherwise perform it for
	    //  all scopes incoming.

	    Enumeration en = null;

	    if (scopes == null) {
		en = scopeLevel.keys();

	    } else {
		en = scopes.elements();

	    }

	    while (en.hasMoreElements()) {
		String scope = (String)en.nextElement();
		Hashtable langLevel = (Hashtable)scopeLevel.get(scope);

		// If no langLevel table, continue searching.

		if (langLevel == null) {
		    continue;

		}

		Vector listVec = null;

		// Use lang tag if we have it, otherwise, pick arbitrary.

		if (lang != null) {
		    listVec = (Vector)langLevel.get(lang);

		} else {
		    Enumeration llen = langLevel.elements();

		    listVec = (Vector)llen.nextElement();

		}

		// If none for this locale, try the next scope.

		if (listVec == null) {
		    continue;

		}

		// Select out the record.

		List elem = (List)listVec.elementAt(0);

		rec = elem.record;
		break;

	    }
	}

	return rec;
    }

    // Find attributes matching the record and place the matching attributes
    //  into the vector. Use the hashtable for collation.

    static void
	findMatchingAttributes(ServiceRecordInMemory rec,
			       Vector attrTags,
			       Hashtable ht,
			       Vector ret)
	throws ServiceLocationException {

	int len = attrTags.size();
	Vector attrList = rec.getAttrList();

	// For each attribute, go through the tag vector If an attribute
	//  matches, merge it into the return vector.

	int i, n = attrList.size();

	for (i = 0; i < n; i++) {
	    ServerAttribute attr =
		(ServerAttribute)attrList.elementAt(i);

	    // All attributes match if the pattern vector is
	    //  empty.

	    if (len <= 0) {
		saveValueIfMatch(attr, null, ht, ret);

	    } else {

		// Check each pattern against the attribute id.

		int j;

		for (j = 0; j < len; j++) {
		    AttributePattern attrTag =
			(AttributePattern)attrTags.elementAt(j);

		    saveValueIfMatch(attr, attrTag, ht, ret);

		}
	    }
	}
    }

    // Check the attribute against the pattern. If the pattern is null,
    //  then match occurs. Merge the attribute into the vector
    //  if match.

    static private void saveValueIfMatch(ServerAttribute attr,
					 AttributePattern attrTag,
					 Hashtable ht,
					 Vector ret)
	throws ServiceLocationException {

	AttributeString id = attr.idPattern;

	// We save the attribute value if either
	//  the pattern is null or it matches the attribute id.

	if (attrTag == null || attrTag.match(id)) {

	    Vector values = attr.getValues();

	    // Create new values vector so record copy isn't
	    //  modified.

	    if (values != null) {
		values = (Vector)values.clone();

	    }

	    // Create new attribute so record copy isn't
	    //  modified.

	    ServiceLocationAttribute nattr =
		new ServiceLocationAttribute(attr.getId(), values);

	    // Merge duplicate attributes into vector.

	    ServiceLocationAttribute.mergeDuplicateAttributes(nattr,
							      ht,
							      ret,
							      true);
	}
    }

    // Check whether the incoming scopes are the same as existing
    //  scopes.

    private void
	checkScopeStatus(ServiceURL surl,
			 Vector scopes,
			 short errCode)
	throws ServiceLocationException {

	// Drill down in the urlScopeLangTable table.

	Hashtable scopeLevel =
	    (Hashtable)urlScopeLangTable.get(surl.toString());

	if (scopeLevel == null) {
	    return;  // not yet registered...

	}

	// We need to have exactly the same scopes as in
	//  the registration.

	int i, n = scopes.size();
	boolean ok = true;

	if (n != scopeLevel.size()) {
	    ok = false;

	} else {

	    for (i = 0; i < n; i++) {
		if (scopeLevel.get(scopes.elementAt(i)) == null) {
		    ok = false;
		    break;

		}
	    }
	}

	if (!ok) {
	    throw
		new ServiceLocationException(errCode,
					     "ssim_scope_mis",
					     new Object[0]);

	}
    }

    // Check whether an existing nonservice URL is registered under
    //  a different service type.

    private void checkForExistingUnderOtherServiceType(ServiceURL url,
						       Vector scopes)
	throws ServiceLocationException {

	// Drill down in the urlScopeLangTable table.

	Hashtable scopeLevel =
	    (Hashtable)urlScopeLangTable.get(url.toString());

	if (scopeLevel == null) {
	    return; // not yet registered.

	}

	// Get hashtable of locale records under scopes. Any scope
	//  will do.

	Object scope = scopes.elementAt(0);

	Hashtable localeLevel = (Hashtable)scopeLevel.get(scope);

	Assert.slpassert(localeLevel != null,
		      "ssim_null_lang_table",
		      new Object[] {scope});

	// Get a record from any locale.

	Enumeration en = localeLevel.elements();

	Assert.slpassert(en.hasMoreElements(),
		      "ssim_empty_lang_table",
		      new Object[] {scope});

	// Get vector of registrations.

	Vector vec = (Vector)en.nextElement();

	Assert.slpassert(vec.size() > 0,
		      "ssim_empty_reg_vector",
		      new Object[] {scope});

	List elem = (List)vec.elementAt(0);

	// OK, now check the registration.

	ServiceURL recURL = elem.record.getServiceURL();
	ServiceType recType = recURL.getServiceType();

	if (!recType.equals(url.getServiceType())) {
	    throw
		new ServiceLocationException(
				ServiceLocationException.INVALID_UPDATE,
				"ssim_st_already",
				new Object[0]);
	}
    }

    // Merge old record into new record.

    final private void mergeOldRecordIntoNew(ServiceRecordInMemory oldRec,
					     ServiceRecordInMemory newRec)
	throws ServiceLocationException {

	Vector newAttrs = newRec.getAttrList();
	Vector oldAttrs = oldRec.getAttrList();
	Hashtable ht = new Hashtable();

	// Charge up the hashtable with the new attributes.

	int i, n = newAttrs.size();

	for (i = 0; i < n; i++) {
	    ServerAttribute attr =
		(ServerAttribute)newAttrs.elementAt(i);

	    ht.put(attr.getId().toLowerCase(), attr);

	}

	// Merge in the old attributes.

	n = oldAttrs.size();

	for (i = 0; i < n; i++) {
	    ServerAttribute attr =
		(ServerAttribute)oldAttrs.elementAt(i);

	    if (ht.get(attr.getId().toLowerCase()) == null) {
		newAttrs.addElement(attr);

	    }
	}

	// Change the attribute vector on the rec.

	newRec.setAttrList(newAttrs);

	// Merge old scopes into new.

	Vector oldScopes = oldRec.getScopes();
	Vector newScopes = newRec.getScopes();
	int j, m = oldScopes.size();

	for (j = 0; j < m; j++) {
	    String scope = (String)oldScopes.elementAt(j);

	    if (!newScopes.contains(scope)) {
		newScopes.addElement(scope);

	    }
	}

	// Note that we don't have to merge security because there
	//  will never be an incremental update to a record
	//  in a protected scope.

	// Change the scope vector on the rec.

	newRec.setScopes(newScopes);

    }

    // Delete attributes matching attrTags.

    private void deleteAttributes(ServiceRecordInMemory rec,
				  Vector attrTags)
	throws ServiceLocationException {

	// For each attribute, go through the tag vector and put attributes
	// that do not match the tags into the new attribute vector.

	Vector attrList = rec.getAttrList();

	// If there are no attributes for this one, then simply return.

	if (attrList.size() <= 0) {
	    return;

	}

	int i, n = attrList.size();
	Vector newAttrList = new Vector();
	int len = attrTags.size();

	for (i = 0; i < n; i++) {
	    ServerAttribute attr =
		(ServerAttribute)attrList.elementAt(i);
	    AttributeString id = attr.idPattern;
	    boolean deleteIt = false;

	    int j;

	    // Now check the tags.

	    for (j = 0; j < len; j++) {
		AttributePattern attrTag =
		    (AttributePattern)attrTags.elementAt(j);

		// If there's a match, mark for deletion.

		if (attrTag.match(id)) {
		    deleteIt = true;
		    break;

		}
	    }

	    if (!deleteIt) {
		newAttrList.addElement(attr);
	    }
	}

	// Replace the attribute vector in the record.

	rec.setAttrList(newAttrList);
    }

    // Convert a vector of attribute tag strings to attribute pattern objects.

    private Vector stringVectorToAttributePattern(Vector tags, Locale locale)
	throws ServiceLocationException {

	// Takes care of findAttributes() case where no vector.

	if (tags == null) {
	    return null;

	}

	Vector v = new Vector();
	int i, n = tags.size();

	for (i = 0; i < n; i++) {
	    String value = (String)tags.elementAt(i);

	    AttributePattern tag =
		new AttributePattern(value, locale);

	    if (!v.contains(tag)) {
		v.addElement(tag);

	    }
	}

	return v;
    }

    //
    // Output of service store to log.
    //

    // Write record to config log file.

    private void
	writeRecordToLog(SLPConfig conf, ServiceStore.ServiceRecord rec) {

	Locale locale = rec.getLocale();
	ServiceURL surl = rec.getServiceURL();
	Vector scopes = rec.getScopes();
	Vector attributes = rec.getAttrList();
	long exTime = rec.getExpirationTime();
	Hashtable urlSig = rec.getURLSignature();
	Hashtable attrSig = rec.getAttrSignature();

	conf.writeLogLine("ssim_dump_entry_start", new Object[0]);
	conf.writeLogLine("ssim_dump_entry",
			  new Object[] {
	    locale,
		surl.toString(),
		Integer.toString(surl.getLifetime()),
		Long.toString(((exTime - System.currentTimeMillis())/1000)),
		surl.getServiceType(),
		scopes,
		attributes});

	if (urlSig != null) {
	    conf.writeLogLine("ssim_dump_urlsig",
			      new Object[] {urlSig});

	}

	if (attrSig != null) {
	    conf.writeLogLine("ssim_dump_attrsig",
			      new Object[] {
		attrSig});

	}
	conf.writeLogLine("ssim_entry_end", new Object[0]);
    }

    //
    // Utilities for dealing with service type/scope locale table.
    //

    // Bump up the number of registrations for this service type, scope and
    //  locale.

    private void
	addTypeLocale(String type, String scope, String lang) {

	String sstKey = makeScopeTypeKey(scope, type);

	// Get any existing record.

	Hashtable langTable = (Hashtable)sstLocales.get(sstKey);

	// Insert a new one if none there.

	if (langTable == null) {
	    langTable = new Hashtable();

	    sstLocales.put(sstKey, langTable);

	}

	// Look up locale.

	Integer numRegs = (Integer)langTable.get(lang);

	// Add a new one if none there, otherwise, bump up old.

	if (numRegs == null) {
	    numRegs = Integer.valueOf(1);

	} else {
	    numRegs = Integer.valueOf(numRegs.intValue() + 1);

	}

	// Put it back.

	langTable.put(lang, numRegs);

    }

    // Bump down the number of registrations for this service type, scope,
    //  in all locales.

    private void deleteTypeLocale(String type, String scope, String lang) {

	String sstKey = makeScopeTypeKey(scope, type);

	// Get any existing record.

	Hashtable langTable = (Hashtable)sstLocales.get(sstKey);

	// If none there, then error. But this should have been caught
	//  during deletion, so it's fatal.

	Assert.slpassert(langTable != null,
		      "ssim_ssttable_botch",
		      new Object[] {
	    type,
		scope});

	// Get the Integer object recording the number of registrations.

	Integer numRegs = (Integer)langTable.get(lang);

	Assert.slpassert(numRegs != null,
		      "ssim_ssttable_lang_botch",
		      new Object[] {
	    lang,
		type,
		scope});

	// Bump down by one, remove if zero.

	numRegs = Integer.valueOf(numRegs.intValue() - 1);

	if (numRegs.intValue() <= 0) {
	    langTable.remove(lang);

	    if (langTable.size() <= 0) {
		sstLocales.remove(sstKey);

	    }

	    // Garbage collection.

	    // Remove records from the scopeTypeLangTable,
	    //  since there are no registrations left for this
	    //  type/scope/locale.

	    String stlKey =
		makeScopeTypeLangKey(scope, type, lang);
	    scopeTypeLangTable.remove(stlKey);

	} else {

	    // Put it back.

	    langTable.put(lang, numRegs);

	}
    }

    // Return REGS if the language is supported. Supported means that the
    //  there are some registrations of this service type in it or that
    //  there are none in any locale. Return NO_REGS if there are absolutely
    //  no registrations whatsoever, in any language. Return NO_REGS_IN_LOCALE
    //  if there are no registrations in that language but there are in
    //  others.

    private int
	languageSupported(String type, Vector scopes, String lang) {

	// Look through scope vector.

	boolean otherLangRegs = false;
	boolean sameLangRegs = false;
	int i, n = scopes.size();

	for (i = 0; i < n; i++) {
	    String scope = (String)scopes.elementAt(i);
	    String sstKey = makeScopeTypeKey(scope, type);

	    // Get any existing record.

	    Hashtable langTable = (Hashtable)sstLocales.get(sstKey);

	    // If there are no regs, then check next scope.

	    if (langTable == null) {
		continue;

	    }

	    Object numRegs = langTable.get(lang);

	    // Check whether there are other language regs
	    //  or same language regs.

	    if (numRegs == null) {
		otherLangRegs = true;

	    } else {
		sameLangRegs = true;

	    }
	}

	// Return appropriate code.

	if (otherLangRegs == false &&
	    sameLangRegs == false) {
	    return NO_REGS;

	} else if (otherLangRegs == true &&
		   sameLangRegs == false) {
	    return NO_REGS_IN_LOCALE;

	} else {
	    return REGS_IN_LOCALE;

	}
    }

    //
    // Hash key calculations and hash table structuring.
    //

    // Return a key for type and scope.

    private String makeScopeTypeKey(String scope, String type) {
	return scope + "/" + type;

    }

    // Make a hash key consisting of the scope and service type.

    final private String
	makeScopeTypeLangKey(String scope,
			     String serviceType,
			     String lang) {

	return scope + "/" + serviceType + "/" + lang;
    }

    // Return the key's scope.

    final private String keyScope(String key) {
	int idx = key.indexOf('/');
	String ret = "";

	if (idx > 0) {
	    ret = key.substring(0, idx);
	}

	return ret;
    }


    // Return the key's service type/NA.

    final private String keyServiceType(String key) {
	int idx = key.indexOf('/');
	String ret = "";
	int len = key.length();

	if (idx >= 0 && idx < len - 1) {
	    ret = key.substring(idx+1, len);
	}

	// Parse off the final lang.

	idx = ret.indexOf('/');

	ret = ret.substring(0, idx);

	return ret;
    }

    // Return true if the record is for an abstract type.

    final private boolean isAbstractTypeRecord(String sstKey) {
	STLRecord rec = (STLRecord)scopeTypeLangTable.get(sstKey);

	return rec.isAbstract;

    }

}
