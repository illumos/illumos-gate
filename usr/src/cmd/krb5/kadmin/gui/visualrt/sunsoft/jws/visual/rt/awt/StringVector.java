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
 * ident	"%Z%%M%	%I%	%E% SMI"
 *
 * Copyright (c) 2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

/*
 *        Copyright (C) 1996  Active Software, Inc.
 *                  All rights reserved.
 *
 * @(#) StringVector.java 1.3 - last change made 04/25/96
 */

package sunsoft.jws.visual.rt.awt;

import java.util.Vector;
import java.util.Enumeration;

public final class StringVector {
    Vector vector;
    
    public StringVector(int initialCapacity, int capacityIncrement) {
        vector = new Vector(initialCapacity, capacityIncrement);
    }
    
    public StringVector(int initialCapacity) {
        vector = new Vector(initialCapacity);
    }
    
    public StringVector() {
        vector = new Vector();
    }
    
    public final void copyInto(String anArray[]) {
        vector.copyInto(anArray);
    }
    
    public final void trimToSize() {
        vector.trimToSize();
    }
    
    public final void ensureCapacity(int minCapacity) {
        vector.ensureCapacity(minCapacity);
    }
    
    public final void setSize(int newSize) {
        vector.setSize(newSize);
    }
    
    public final int capacity() {
        return vector.capacity();
    }
    
    public final int size() {
        return vector.size();
    }
    
    public final boolean isEmpty() {
        return vector.isEmpty();
    }
    
    public final Enumeration elements() {
        return vector.elements();
    }
    
    public final boolean contains(String elem) {
        return vector.contains(elem);
    }
    
    public final int indexOf(String elem) {
        return vector.indexOf(elem);
    }
    
    public final int indexOf(String elem, int index) {
        return vector.indexOf(elem, index);
    }
    
    public final int lastIndexOf(String elem) {
        return vector.lastIndexOf(elem);
    }
    
    public final int lastIndexOf(String elem, int index) {
        return vector.lastIndexOf(elem, index);
    }
    
    public final String elementAt(int index) {
        return (String)vector.elementAt(index);
    }
    
    public final String firstElement() {
        return (String)vector.firstElement();
    }
    
    public final String lastElement() {
        return (String)vector.lastElement();
    }
    
    public final void setElementAt(String obj, int index) {
        vector.setElementAt(obj, index);
    }
    
    public final void removeElementAt(int index) {
        vector.removeElementAt(index);
    }
    
    public final void insertElementAt(String obj, int index) {
        vector.insertElementAt(obj, index);
    }
    
    public final void addElement(String obj) {
        vector.addElement(obj);
    }
    
    public final boolean removeElement(Object obj) {
        return vector.removeElement(obj);
    }
    
    public final void removeAllElements() {
        vector.removeAllElements();
    }
    
    public synchronized Object clone() {
        try {
            StringVector v = (StringVector)super.clone();
            v.vector = (Vector)vector.clone();
            return v;
        } catch (CloneNotSupportedException e) {
            // this shouldn't happen, since we are Cloneable
            throw new InternalError();
        }
    }
    
    public String toString() {
        return vector.toString();
    }
}
