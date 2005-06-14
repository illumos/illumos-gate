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
 * @(#) Attribute.java 1.25 - last change made 07/30/96
 */

package sunsoft.jws.visual.rt.base;

/**
 * Storage for a single attribute.
 *
 * @version 	1.25, 07/30/96
 */
public class Attribute implements Cloneable {
    /**
     * Name of this attribute.
     */
    private String name;
    
    /**
     * The full class name of the type of the value of this attribute.
     */
    private String type;
    
    /**
     * The actual value of this attribute.  It is of the type specified
     * by the type field.
     */
    private Object value;
    
    /**
     * The default value of this attribute.  It is of the type specified
     * by the type field.
     */
    private Object defaultValue;
    
    /**
     * Contains description flags about the nature of this attribute.
     */
    private int flags;
    
    /**
     * The constructor initializes the value for the attribute.
     * The initial value of the attribute is set to be the same
     * as the default value.  If the default value is not a simple
     * type, you
     * may want to set the value again after cloning the default value,
     * otherwise, directly setting internal members of the value will
     * change
     * the default value as well.
     */
    public Attribute(String name, String type, Object defaultValue,
		     int flags) {
        this.name = name;
        this.type = type;
        
        // throwOnBadType is commented out for performance reasons.
        // Shadow class construction is 15% faster with this
        // commented out.
        //
        // throwOnBadType(defaultValue);
        
        this.value = defaultValue;
        this.defaultValue = defaultValue;
        this.flags = flags;
    }
    
    private void throwOnBadType(Object checkee) {
        // allow null
        if (checkee == null)
            return;
        
        if (checkee.getClass().getName().equals(type))
            return; // FIX  for 4059234
        
        // type must pass "instance of" test (except for null)
        Class typeClass = null;
        try {
            typeClass = Global.util.getClassLoader().loadClass(type);
        } catch (ClassNotFoundException e) {
            throw new Error(Global.fmtMsg(
	    "sunsoft.jws.visual.rt.base.Attribute.ClassNotFound", type));
        }
        
        if (typeClass.isInstance(checkee))
            return;
        
        throw new Error(Global.fmtMsg(
		"sunsoft.jws.visual.rt.base.Attribute.IllegalAttribute",
		      name, type, checkee.getClass().getName(), checkee));
    }
    
    public String getName() {
        return (name);
    }
    
    public String getType() {
        return (type);
    }
    
    public Object getDefaultValue() {
        return (defaultValue);
    }
    
    void setDefaultValue(Object value) {
        defaultValue = value;
    }
    
    public boolean isModified() {
        if (value == null)
            return (defaultValue != null);
        else
            return (!value.equals(defaultValue));
    }
    
    /**
     * Resets the value to the default
     */
    public void reset() {
        setValue(defaultValue);
    }
    
    public Object getValue() {
        return (value);
    }
    
    /**
     * Sets the value of the attribute.
     */
    public void setValue(Object value) {
        // Commented out the "does new value equal old value"
        // check, because:
        // 1) Setting a value to "null" can cause a null pointer
        //  exception
        // 2) Some attributes may not implement equals properly
        throwOnBadType(value);
        
        
        this.value = value;
    }
    
    public int getFlags() {
        return (flags);
    }
    
    public void addFlags(int flags) {
        this.flags = (this.flags | flags);
    }
    
    public boolean flagged(int flags) {
        return ((flags & this.flags) != 0);
    }
    
    /**
     * Shallow clone for this attribute.  It's not a deep clone,
     * only the
     * references to the value and default value are cloned,
     * not the actual
     * values themselves.
     */
    public Object clone() {
        Object retval;
        try {
            retval = super.clone();
        }
        catch (CloneNotSupportedException e) {
            throw new Error(e.getMessage());
        }
        return (retval);
    }
}
