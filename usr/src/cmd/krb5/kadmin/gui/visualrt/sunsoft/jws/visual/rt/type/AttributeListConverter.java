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
 * @(#) AttributeListConverter.java 1.29 - last change made 06/17/97
 */

package sunsoft.jws.visual.rt.type;

import sunsoft.jws.visual.rt.base.Global;

import sunsoft.jws.visual.rt.base.*;
import java.util.*;

/**
 * The class converts AttributeLists to strings and back again.
 *
 * @see AttributeList
 * @version 1.29, 06/17/97
 */
public class AttributeListConverter extends Converter {
    
    private static AttributeConverter ac = new AttributeConverter();
    
    /**
     * Returns true if the attribute is one that should be placed in a
     * save file.  Include only non-default attributes (and skip the
     * name attribute.)
     */
    private boolean shouldConvertAttribute(Attribute a) {
        return (a.isModified() && !a.getName().equals
		(/* NOI18N */"name") && !isTransient(a));
    }
    
    private boolean isTransient(Attribute a) {
        return ((a.getFlags() & (AttributeManager.TRANSIENT |
				 AttributeManager.READONLY)) != 0);
    }
    
    /**
     * Converts an AttributeList to a string.
     *
     * @param obj AttributeList to convert
     * @param buf buffer to which to add the string
     */
    public void convertToString(Object obj, StringBuffer buf) {
        if (obj != null) {
            AttributeList l = (AttributeList) obj;
            for (Enumeration e = l.elements(); e.hasMoreElements(); ) {
                Attribute a = (Attribute) e.nextElement();
                if (shouldConvertAttribute(a)) {
                    indent(buf);
                    ac.convertToString(a, buf);
                    newline(buf);
                }
            }
        }
    }
    
    /**
     * Call convertFromString that takes more arguments instead.
     *
     * @exception Error when called
     */
    public Object convertFromString(String s) {
	/* BEGIN JSTYLED */
	throw new Error(Global.getMsg("sunsoft.jws.visual.rt.type.AttributeListConverter.AttributeListConvert.12"));
	/* END JSTYLED */
    }
    
    /**
     * Converts a string to an AttributeList.
     *
     * @param version description file version
     * @param mgr AttributeManager from which the attribute list came
     * @param s string to convert
     * @return string representation of AttributeList
     * @exception ParseError when there is a problem with the string
     */
    public String convertFromString(double version,
				    AttributeManager mgr, String s) {
        String children = null;
        String type = null, key = null, value = null;
        boolean isChildren;
        
        if (s == null || mgr == null)
            return null;
        
        Enumeration e;
        if (version >= 3)
            e = ListParser.getListElements(s, 3);
        else
            e = ListParser.getListElements(s, 2);
        
        try {
            while (e.hasMoreElements()) {
                type = null;
                key = null;
                value = null;
                
                if (version >= 3) {
                    type = (String)e.nextElement();
                    key = (String)e.nextElement();
                    value = (String)e.nextElement();
                    isChildren = (type.equals(/* NOI18N */"child") &&
				  key.equals(/* NOI18N */"list"));
                } else {
                    key = (String)e.nextElement();
                    value = (String)e.nextElement();
                    isChildren = (key.equals(/* NOI18N */"children"));
                }
                
                if (isChildren)
                    children = value;
                else
                    ac.convertFromString(version, mgr, type,
					 key, value);
            }
        }
        catch (NoSuchElementException ex) {
            throw new ParseException(Global.newline() +
				     /* BEGIN JSTYLED */
				     Global.getMsg("sunsoft.jws.visual.rt.type.AttributeListConverter.________Incomplete__attri.13") +
				     /* END JSTYLED */
		     Global.newline() + /* NOI18N */"      type = " + type +
		     Global.newline() + /* NOI18N */"      key = " + key +
		     Global.newline() + /* NOI18N */"      value = " + value);
        }
        
        return children;
    }
    
    /**
     * Returns true if the attribute is one that should be placed in a
     * generated code file.  Include only non-default attributes.
     */
    private boolean shouldGenerateAttribute(Attribute a) {
        return (a.isModified() && !isTransient(a) &&
		!a.getName().equals(/* NOI18N */"operations"));
    }
    
    /**
     * Converts an AttributeManager's AttributeList to code.
     *
     * Skips the name attribute because it is generated 
     * separately in GenCode.
     * This is done because during initialization for the
     * generated root, the
     * name must be set before add is called.  All the other attributes
     * must be set after add is called.
     *
     * @param amName name of the AttributeManager
     * @param list the list to convert
     * @param indent number of spaces to indent on each line
     * @param buf buffer to which to add the code
     */
    public void convertToCodeBlock(String amName, AttributeList list,
				   int indent, StringBuffer buf) {
        Enumeration e = list.elements();
        while (e.hasMoreElements()) {
            Attribute a = (Attribute) e.nextElement();
            if (shouldGenerateAttribute(a) && (!a.getName().equals
					       (/* NOI18N */"name"))) {
                ac.convertToCodeBlock(amName, a, indent, buf);
            }
        }
    }
}
