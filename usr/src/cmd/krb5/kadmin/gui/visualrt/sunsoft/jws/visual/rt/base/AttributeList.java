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
 * @(#) AttributeList.java 1.31 - last change made 07/25/97
 */

package sunsoft.jws.visual.rt.base;

import java.util.Hashtable;
import java.util.Vector;
import java.util.Enumeration;

/**
 * Class for storing information about the attributes available on a
 * particular type of GUI object.
 *
 * @version 	1.31, 07/25/97
 */
public class AttributeList implements Cloneable {
    private Hashtable table;
    private Hashtable aliasTable;
    
    public AttributeList() {
        table = new Hashtable();
        aliasTable = new Hashtable();
    }
    
    public void add(Attribute attr) {
        table.put(attr.getName(), attr);
    }
    
    public void add(String name, String type, Object defaultValue) {
        Attribute a = lookup(name);
        if (a == null)
            add(new Attribute(name, type, defaultValue, 0));
        else
            add(new Attribute(name, type, defaultValue, a.getFlags()));
    }
    
    public void add(String name, String type, Object defaultValue,
		    int flags) {
        table.put(name, (new Attribute(name, type, defaultValue,
				       flags)));
    }
    
    public void alias(String name1, String name2) {
        aliasTable.put(name1, name2);
    }
    
    public Enumeration aliasKeys() {
        return aliasTable.keys();
    }
    
    public String resolveAlias(String name) {
        String s1, s2;
        
        s1 = name;
        s2 = s1;
        while (s1 != null) {
            s2 = s1;
            s1 = (String)aliasTable.get(s1);
        }
        
        return s2;
    }
    
    public void remove(String name) {
        table.remove(name);
        aliasTable.remove(name);
    }
    
    private Attribute lookup(String name) {
        Attribute attr = (Attribute)table.get(name);
        if (attr == null) {
            name = resolveAlias(name);
            attr = (Attribute)table.get(name);
        }
        return attr;
    }
    
    public Attribute get(String name) {
        return lookup(name);
    }
    
    public boolean contains(String name) {
        return (lookup(name) != null);
    }
    
    /**
     * Returns an enumeration of attributes with the given flags.
     */
    public Enumeration attributesWithFlags(int flags) {
        Attribute s;
        Vector set = new Vector();
        for (Enumeration e = table.elements(); e.hasMoreElements(); ) {
            s = (Attribute) e.nextElement();
            if ((s.getFlags() & flags) != 0) {
                set.addElement(s);
            }
        }
        return (set.elements());
    }
    
    /**
     * Returns an enumeration of attributes that do not have
     * the given flags.
     */
    public Enumeration attributesWithoutFlags(int flags) {
        Attribute s;
        Vector set = new Vector();
        for (Enumeration e = table.elements(); e.hasMoreElements(); ) {
            s = (Attribute) e.nextElement();
            if ((s.getFlags() & flags) == 0) {
                set.addElement(s);
            }
        }
        return (set.elements());
    }
    
    /**
     * Returns an enumeration of all elements in the attribute list.
     */
    public Enumeration elements() {
        return (table.elements());
    }
    
    /**
     * Returns the number of elements in the attribute list.
     */
    public int size() {
        return (table.size());
    }
    
    /**
     * Merge the contents of the given list with this one.  New elements
     * by the same name will overwrite old ones.  Attributes are cloned
     * before merging with this list.
     */
    public void merge(AttributeList list) {
        if (list != null) {
            for (Enumeration e = list.elements(); e.hasMoreElements(); )
                
		{
		    add((Attribute) ((Attribute) e.nextElement()).clone());
		}
            for (Enumeration e = list.aliasKeys();
		 /* JSTYLED */
		 e.hasMoreElements(); ) {
		String s = (String)e.nextElement();
		alias(s, list.resolveAlias(s));
	    }
	}
    }

    /**
     * Returns an alphabetized enumeration of attributes.
     */
    public static Enumeration alphabetize(Enumeration e) {
	Vector v = new Vector();
	for (; e.hasMoreElements(); ) {
	    int i;
	    Attribute a = (Attribute) e.nextElement();
	    for (i = 0; i < v.size(); i++) {
		if (((Attribute)
		     v.elementAt(i)).getName().compareTo(a.getName()) > 0)
            
		    {
			v.insertElementAt(a, i);
			break;
		    }
	    }
	    if (i >= v.size()) {
		v.addElement(a);
	    }
	}
	return (v.elements());
    }

    /**
     * Clones the attribute list.  The attributes in the list
     * are cloned, but the attribute's value is not cloned (see
     * the comment for the clone method in Attribute).
     *
     * @see Attribute
     */
    public Object clone() {
	AttributeList retval = new AttributeList();
	retval.merge(this);
	return (retval);
    }

    public String toString() {
	StringBuffer buf = new StringBuffer();
    
	for (Enumeration e = table.keys(); e.hasMoreElements(); ) {
	    String key = (String) e.nextElement();
	    buf.append(key + /* NOI18N */"(" + ((Attribute)
				table.get(key)).getType() + /* NOI18N */") ");
	}
    
	for (Enumeration e = aliasTable.keys(); e.hasMoreElements(); ) {
	    String alias = (String) e.nextElement();
	    buf.append(/* NOI18N */"alias:" + alias + /* NOI18N */"->"
		       + (String) aliasTable.get(alias) + /* NOI18N */" ");
	}
    
	return (buf.toString());
    }
}
