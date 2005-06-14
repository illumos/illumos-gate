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
 * @(#) AttributeConverter.java 1.32 - last change made 08/12/97
 */

package sunsoft.jws.visual.rt.type;

import sunsoft.jws.visual.rt.base.Global;

import sunsoft.jws.visual.rt.base.*;
import java.util.Enumeration;

/**
 * This class converts Attributes to strings and back again.
 *
 * @see Attribute
 * @version 1.32, 08/12/97
 */
public class AttributeConverter extends Converter {
    
    /**
     * Converts an attribute to a string.
     *
     * @param obj Attribute instance to convert
     * @param buf buffer to which to add the string
     * @return string representation of an attribute 
     * (type, name, and value)
    */
    public void convertToString(Object obj, StringBuffer buf) {
        if (obj != null) {
            Attribute a = (Attribute) obj;
            
            String type = a.getType();
            // Special case for GBConstraints to make
            // the save file neater
            if (type.equals(/* NOI18N */
			    "sunsoft.jws.visual.rt.awt.GBConstraints"))
		type = /* NOI18N */"GBC";
            ListParser.quote(type, buf, false);
            buf.append(/* NOI18N */ ' ');
            
            ListParser.quote(a.getName(), buf, false);
            buf.append(/* NOI18N */ ' ');
            
            Converter c = getConverter(a.getType());
            if (c == null) {
                buf.append(/* NOI18N */"null");
            } else {
                ListParser.quote(c.convertToString(a.getValue()),
				 buf, false);
            }
        }
    }
    
    /**
     * Call the convertFromString method that takes additionhal
     * arguments. An AttributeManager object is needed to operate on.
     *
     * @exception Error when called
     */
    public Object convertFromString(String s) {
	/* BEGIN JSTYLED */
	throw new Error(Global.getMsg("sunsoft.jws.visual.rt.type.AttributeConverter.AttributeConverter__n.6") +
			Global.getMsg("sunsoft.jws.visual.rt.type.AttributeConverter.argument__to__operate"));
	/* END JSTYLED */
    }
    
    /**
     * Converts a string (type, name, and value) to an Attribute.
     *
     * @param version description file version
     * @param mgr object in which the attribute will be used
     * @param type type of the attribute
     * @param key name of the attribute
     * @param value value of the attribute
     * @return a new instance of Attribute
     * @exception ParseError when there is an error 
     * in one of the strings
    */
    public Object convertFromString(double version,
	    AttributeManager mgr, String type, String key, String value) {
        
        // get the targeted attribute from the shadow object
        if (!mgr.hasAttribute(key)) {
            String errMsg = Global.fmtMsg(
		  "sunsoft.jws.visual.rt.type.AttributeConverter.FMT.33",
			  key, mgr.getClass().getName(), type, key, value);
            if (java.beans.Beans.isDesignTime()) {
                DesignerAccess.reportInstantiationError(errMsg);
                return null;
            } else {
                throw new ParseException(errMsg);
            }
        }
        
        // get type of attribute and convert and set the value
        String mgrType = mgr.getType(key);
        
        if (version >= 3) {
            if (!type.equals(mgrType) &&
		!type.equals(/* NOI18N */"GBC")) {
                String errMsg = Global.fmtMsg(
		      "sunsoft.jws.visual.rt.type.AttributeConverter.FMT.35",
					      type, mgrType);
                if (java.beans.Beans.isDesignTime()) {
                    DesignerAccess.reportInstantiationError(errMsg);
                    return null;
                } else {
                    throw new ParseException(errMsg);
                }
            }
        }
        
        Converter valueConverter = getConverter(mgrType);
        if (valueConverter == null) {
            String errMsg = Global.fmtMsg(
		  "sunsoft.jws.visual.rt.type.AttributeConverter.FMT.34",
					  mgrType);
            if (java.beans.Beans.isDesignTime()) {
                DesignerAccess.reportInstantiationError(errMsg);
                return null;
            } else {
                throw new ParseException(errMsg);
            }
        }
        
        mgr.set(key, valueConverter.convertFromString(value));
        return null;
    }
    
    /**
     * Converts an attribute to the code that would set it for an
     * AttributeManager object.
     *
     * @param amName name of the AttributeManager
     * @param a attribute (which contains type, name, and value)
     * @param indent number of spaces to indent the code line(s)
     * @param buf buffer to which to add the code
     */
    public void convertToCodeBlock(String amName, Attribute a,
				   int indent, StringBuffer buf) {
        
        Converter c = getConverter(a.getType());
        c.convertToCodeBlock(amName, a, indent, buf);
    }
    
    /**
     * Call the convertToCode method that takes more arguments instead.
     *
     * @exception Error when called
     */
    public String convertToCode(Object obj) {
        throw new Error(
			/* BEGIN JSTYLED */
			Global.getMsg(
				      "sunsoft.jws.visual.rt.type.AttributeConverter.internal__error__-__") +
			Global.getMsg(
				      "sunsoft.jws.visual.rt.type.AttributeConverter.convertToCode__with__m.11")   );
	/* END JSTYLED */
    }
}
