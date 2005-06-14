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
 * @(#) BaseEnumHelper.java 1.5 - last change made 07/18/96
 */

package sunsoft.jws.visual.rt.type;

import java.util.Hashtable;
import java.util.Vector;
import java.util.Enumeration;

/**
 * Keeps track of the string/int pairs in sub-classes of BaseEnum.
 * This is meant to be a class-wide member for each subclass of
 * BaseEnum.  Each subclass of BaseEnum should provide a single
 * instance of BaseEnumHelper for use by all instances of that subclass.
 *
 * @see BaseEnum
 * @version 1.5, 07/18/96
 */
public class BaseEnumHelper {
    /**
     * Ordered list of the enum names.
     */
    private Vector names = new Vector();
    
    /**
     * Pairs keyed by the description.
     */
    private Hashtable keyedByString = new Hashtable();
    
    /**
     * Pairs keyed by the integer value.
     */
    private Hashtable keyedByInteger = new Hashtable();
    
    /**
     * The default if no choice is initially specified.  Sub-classers
     * shouldn't rely on this and should call setDefaultChoice in their
     * static initializer.
     */
    private int defaultChoice = 0;
    
    /**
     * Sets the default choice for newly constructed 
     * instances of the enum.
    */
    public void setDefaultChoice(int value) {
        defaultChoice = value;
    }
    
    /**
     * Gets the default choice for newly constructed 
     * instances of the enum.
    */
    public int getDefaultChoice() {
        return (defaultChoice);
    }
    
    /**
     * Adds a new string/int pair to the internal hashtable.
     */
    public void add(int value, String name) {
        Integer I = new Integer(value);
        names.addElement(name);
        keyedByString.put(name, I);
        keyedByInteger.put(I, name);
    }
    
    /**
     * Returns true if the choice is valid for this enum type.
     */
    public boolean isValid(int choice) {
        return (keyedByInteger.containsKey(new Integer(choice)));
    }
    
    /**
     * Returns true if the choice is valid for this enum type.
     */
    public boolean isValid(String choice) {
        return (keyedByString.containsKey(choice));
    }
    
    /**
     * Returns the Integer associated with a String key.
     */
    public Integer getInteger(String key) {
        return ((Integer) keyedByString.get(key));
    }
    
    /**
     * Returns the String associated with an Integer key.
     */
    public String getString(Integer key) {
        return ((String) keyedByInteger.get(key));
    }
    
    /**
     * Returns an Enumeration of the String descriptions
     * available in this enum.
     */
    public Enumeration elements() {
        return (names.elements());
    }
    
    /**
     * Returns an array containing all of the String descriptions
     * available in this enum.
     */
    public String[] descriptions() {
        String retval[] = new String[names.size()];
        names.copyInto(retval);
        return (retval);
    }
}
