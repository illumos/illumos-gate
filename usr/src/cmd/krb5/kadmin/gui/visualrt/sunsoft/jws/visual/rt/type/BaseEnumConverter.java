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
 * @(#) BaseEnumConverter.java 1.16 - last change made 06/18/97
 */

package sunsoft.jws.visual.rt.type;

/**
 * Converts enum types to and from strings and to code.  This converter
 * can handle any sub-class of BaseEnum.
 *
 * @see BaseEnum
 * @version 	1.16, 06/18/97
 */
public class BaseEnumConverter extends Converter {
    private Class enumClass = null;
    
    public BaseEnumConverter() {
    }
    
    /**
     * Constructs an instance of this converter that can be used for the
     * given subclass of BaseEnum.
     *
     * @param type the fully qualified class name of the subclass
     */
    public BaseEnumConverter(String type) {
        setConverterType(type);
    }
    
    private BaseEnum makeEnum(String s) {
        if (enumClass == null) {
            try {
                enumClass = Class.forName(getConverterType());
            }
            catch (ClassNotFoundException e) {
                throw new Error(e.getMessage());
            }
        }
        
        try {
            BaseEnum retval = (BaseEnum) enumClass.newInstance();
            retval.set(s);
            return (retval);
        }
        catch (Exception e) {
            throw new Error(e.getMessage());
        }
    }
    
    /**
     * Returns the string representation of the enumeration 
     * selected in the
     * given BaseEnum object.
     *
     * @param obj an instance of BaseEnum or one of its subclasses
     */
    public String convertToString(Object obj) {
        return (((BaseEnum) obj).toString());
    }
    
    /**
     * Returns a new instance of BaseEnum (or subclass) for enumeration
     * value given.
     *
     * @param s string version of the enumeration choice
     */
    public Object convertFromString(String s) {
        return (makeEnum(s));
    }
    
    /**
     * Returns a block of code that creates a new BaseEnum (or subclass)
     * like the one given.
     *
     * @param the BaseEnum instance to emulate
     */
    public String convertToCode(Object obj) {
        StringBuffer buf = new StringBuffer();
        
        buf.append(/* NOI18N */"new ");
        buf.append(obj.getClass().getName());
        buf.append(/* NOI18N */"(");
        
        ListParser.quote(obj.toString(), buf, true);
        
        buf.append(/* NOI18N */")");
        
        return buf.toString();
    }
    
    /**
     * Helps signify that in an attribute editor (like the
     * one in the Desginer), an instance of BaseEnum 
     * is not viewable in a
     * textfield.  It will be displayed using a choice menu instead.
     *
     * @return false
     */
    public boolean viewableAsString() {
        return false;
    }
}
