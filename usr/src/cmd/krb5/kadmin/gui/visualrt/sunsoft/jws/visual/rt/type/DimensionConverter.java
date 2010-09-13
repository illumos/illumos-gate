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
 * @(#) @(#) DimensionConverter.java 1.12 - last change made 07/25/97
 */

package sunsoft.jws.visual.rt.type;

import sunsoft.jws.visual.rt.base.Global;

import java.awt.Dimension;
import java.util.Hashtable;
import java.util.Enumeration;

/**
 * Converts Dimension objects to strings and back again.  The format
 * of the string representation is "width=#;height=#", where # can be
 * any non-negative number.
 *
 * @see Dimension
 * @version 1.12, 07/25/97
 */
public class DimensionConverter extends Converter {
    public String convertToString(Object obj) {
        if (obj == null)
            return /* NOI18N */"";
        
        Dimension d = (Dimension)obj;
        return (/* NOI18N */"width=" + d.width
		+ /* NOI18N */";height=" + d.height);
    }
    
    public Object convertFromString(String s) {
        if (s == null || s.length() == 0)
            return null;
        
        SubFieldTokenizer sft = new SubFieldTokenizer(s);
        Hashtable table = sft.getHashtable();
        Dimension d = new Dimension();
        
        Enumeration e = table.keys();
        while (e.hasMoreElements()) {
            String key = (String)e.nextElement();
            if (!key.equals(/* NOI18N */"width") &&
		!key.equals(/* NOI18N */"height")) {
		/* BEGIN JSTYLED */
		// throw new ParseException(/* NOI18N */"Illegal dimension value: " + key);
		throw new ParseException(Global.fmtMsg(
						       "sunsoft.jws.visual.rt.type.DimensionConverter.FMT.31",
						       Global.getMsg("sunsoft.jws.visual.rt.type.DimensionConverter.illegal__dimension__value"),
						       key));
		/* END JSTYLED */
            }
        }
        
        if (table.containsKey(/* NOI18N */"width"))
            d.width = getIntegerFromTable(table, /* NOI18N */"width");
        if (table.containsKey(/* NOI18N */"height"))
            d.height = getIntegerFromTable(table, /* NOI18N */"height");
        
        return d;
    }
    
    private int getIntegerFromTable(Hashtable table, String key) {
        String value = (String) table.get(key);
        if (value != null) {
            try {
                return Integer.valueOf(value).intValue();
            }
            catch (NumberFormatException ex) {
                /* JSTYLED */
		throw new ParseException(Global.getMsg("sunsoft.jws.visual.rt.type.DimensionConverter.Badly__formatted__dime.27") + value);
            }
        } else {
            return (0);
        }
    }
    
    public String convertToCode(Object obj) {
        if (obj == null) {
            return /* NOI18N */"new java.awt.Dimension()";
        } else {
            Dimension d = (Dimension)obj;
            return (/* NOI18N */"new java.awt.Dimension(" + d.width
		    + /* NOI18N */", " + d.height + /* NOI18N */")");
        }
    }
}
