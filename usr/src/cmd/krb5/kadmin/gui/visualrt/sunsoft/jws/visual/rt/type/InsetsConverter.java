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
 * @(#) InsetsConverter.java 1.12 - last change made 05/02/97
 */

package sunsoft.jws.visual.rt.type;

import java.awt.Insets;
import java.util.*;
import sunsoft.jws.visual.rt.base.Global;

/**
 * Converts Insets to strings and back again.
 * An example of the inset string format: "top=14;left=5;bottom=10;right=4".
 *
 * @see Insets
 * @version 	1.12, 05/02/97
 */
public class InsetsConverter extends Converter {
    
	/**
	 * Converts an instance of Insets to its string representation.
	 *
	 * @param obj an instance of Insets
	 */
	public String convertToString(Object obj) {
		if (obj == null)
			return /* NOI18N */"top=0;left=0;bottom=0;right=0;";
		String s = /* NOI18N */"";
		Insets insets = (Insets)obj;
        
        
		s = s + /* NOI18N */"top=" + insets.top + /* NOI18N */";";
        
		s = s + /* NOI18N */"left=" + insets.left + /* NOI18N */";";
        
		s = s + /* NOI18N */"bottom=" + insets.bottom
			+ /* NOI18N */";";
        
		s = s + /* NOI18N */"right=" + insets.right + /* NOI18N */";";
        
		return s;
	}
    
	private int getIntegerFromTable(Hashtable table, String key) {
		String value = (String) table.get(key);
		if (value != null) {
			try {
				return Integer.valueOf(value).intValue();
			}
			catch (NumberFormatException ex) {
				throw new ParseException(Global.fmtMsg(
			"sunsoft.jws.visual.rt.type.InsetsConverter.BadInsets",
					value));
			}
		} else {
			return (0);
		}
	}
    
	/**
	 * Returns a new instance of Insets according to the string 
	 * representation
	 * given.
	 *
	 * @exception ParseException when there is a format error in the
	 * string
	 */
	public Object convertFromString(String s) {
		if (s == null || s.length() == 0)
			return null;
        
		SubFieldTokenizer sft = new SubFieldTokenizer(s);
		Hashtable table = sft.getHashtable();
		Insets insets = new Insets(0, 0, 0, 0);
        
		Enumeration e = table.keys();
		while (e.hasMoreElements()) {
			String key = (String)e.nextElement();
			if (!key.equals(/* NOI18N */"top") && !key.equals
			    (/* NOI18N */"bottom") &&
			    !key.equals(/* NOI18N */"left") && !key.equals
			    (/* NOI18N */"right")) {
				/* JSTYLED */
				throw new ParseException(Global.fmtMsg(
		"sunsoft.jws.visual.rt.type.InsetsConverter.IllegalInsets",
		key));
			}
		}
        
		if (table.containsKey(/* NOI18N */"top"))
			insets.top = getIntegerFromTable(table,
							/* NOI18N */"top");
		if (table.containsKey(/* NOI18N */"left"))
			insets.left = getIntegerFromTable(table,
							/* NOI18N */"left");
		if (table.containsKey(/* NOI18N */"bottom"))
			insets.bottom = getIntegerFromTable(table,
						    /* NOI18N */"bottom");
		if (table.containsKey(/* NOI18N */"right"))
			insets.right = getIntegerFromTable(table,
							/* NOI18N */"right");
        
		return insets;
	}
    
	/**
	 * Returns code to create an instance of Insets like the one given.
	 *
	 * @param obj an instance of Insets
	 */
	public String convertToCode(Object obj) {
		if (obj == null) {
			return /* NOI18N */"null";
		} else {
			Insets i = (Insets)obj;
			return (/* NOI18N */"new java.awt.Insets(" +
			    i.top + /* NOI18N */", " + i.left + /* NOI18N */", "
				+ i.bottom + /* NOI18N */", " + i.right
				+ /* NOI18N */")");
            
		}
	}
}
