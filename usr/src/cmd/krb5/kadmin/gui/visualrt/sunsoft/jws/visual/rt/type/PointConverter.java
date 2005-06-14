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
 * @(#) @(#) PointConverter.java 1.8 - last change made 07/25/97
 */

package sunsoft.jws.visual.rt.type;

import java.awt.Point;
import java.util.Hashtable;
import java.util.Enumeration;
import sunsoft.jws.visual.rt.base.Global;


/**
 * Converts Point objects to strings and back again.
 * An example of the string representation: "x=45;y=24".
 *
 * @version 	1.8, 07/25/97
 */
public class PointConverter extends Converter {
    public String convertToString(Object obj) {
        if (obj == null)
            return /* NOI18N */"";
        
        Point p = (Point)obj;
        return (/* NOI18N */"x=" + p.x + /* NOI18N */";y=" + p.y);
    }
    
    /**
     * Converts a string representation to a new instance of Point.
     *
     * @exception ParseException when there is a format 
     * problem with the string
    */
    public Object convertFromString(String s) {
        if (s == null || s.length() == 0)
            return null;
        
        SubFieldTokenizer sft = new SubFieldTokenizer(s);
        Hashtable table = sft.getHashtable();
        Point p = new Point(0, 0);
        
        Enumeration e = table.keys();
        while (e.hasMoreElements()) {
            String key = (String)e.nextElement();
            if (!key.equals(/* NOI18N */"x") &&
		!key.equals(/* NOI18N */"y")) {
                throw new ParseException(Global.fmtMsg(
	        "sunsoft.jws.visual.rt.type.PointConverter.IllegalPoint",
						       key));
            }
        }
        
        if (table.containsKey(/* NOI18N */"x"))
            p.x = getIntegerFromTable(table, /* NOI18N */"x");
        if (table.containsKey(/* NOI18N */"y"))
            p.y = getIntegerFromTable(table, /* NOI18N */"y");
        
        return p;
    }
    
    private int getIntegerFromTable(Hashtable table, String key) {
        String value = (String) table.get(key);
        if (value != null) {
            try {
                return Integer.valueOf(value).intValue();
            }
            catch (NumberFormatException ex) {
                throw new ParseException(Global.fmtMsg(
   	        "sunsoft.jws.visual.rt.type.PointConverter.BadFormattedValue",
						       value));
            }
        } else {
            return (0);
        }
    }
    
    public String convertToCode(Object obj) {
        if (obj == null) {
            return /* NOI18N */"new java.awt.Point(0, 0)";
        } else {
            Point p = (Point)obj;
            return (/* NOI18N */"new java.awt.Point(" + p.x
		    + /* NOI18N */", " + p.y + /* NOI18N */")");
        }
    }
}
