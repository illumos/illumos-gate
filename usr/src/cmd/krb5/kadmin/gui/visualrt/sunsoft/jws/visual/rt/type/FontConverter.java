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
 * @(#) FontConverter.java 1.14 - last change made 07/25/97
 */

package sunsoft.jws.visual.rt.type;

import sunsoft.jws.visual.rt.base.Global;

import java.awt.Font;
import java.util.Hashtable;
import java.util.StringTokenizer;

/**
 * Converts Font objects to strings and back again.  An example of the
 * string representation: "name=Helvetica;style=bold;size=14".  The
 * styles that can currently be used are "plain", "bold", and
 * "italic".
 *
 * @version 1.14, 07/25/97
 */
public class FontConverter extends Converter {
    
    private static final int styleDefault = Font.PLAIN;
    private static final int sizeDefault = 12;
    
    /**
     * Converts a Font instance to a string.
     */
    public String convertToString(Object obj) {
        if (obj == null)
            return /* NOI18N */"";
        
        Font font = (Font) obj;
        String style;
        
        switch (font.getStyle()) {
	case Font.PLAIN:
            style = /* NOI18N */"plain";
            break;
	case Font.BOLD:
            style = /* NOI18N */"bold";
            break;
	case Font.ITALIC:
            style = /* NOI18N */"italic";
            break;
	default:
            /* JSTYLED */
	    System.out.println(Global.getMsg("sunsoft.jws.visual.rt.type.FontConverter.Warning-co-__unknown__fon.29") + font.getStyle());
            style = /* NOI18N */"plain";
            break;
        }
        
        return (/* NOI18N */"name=" + font.getName()
		+ /* NOI18N */";style=" + style
		+ /* NOI18N */";size=" + font.getSize());
    }
    
    /**
     * Converts a string to a new instance of Font.
     *
     * @exception ParseException when there is a format 
     * problem with the string
    */
    public Object convertFromString(String s) {
        if (s == null || s.length() == 0)
            return null;
        
        SubFieldTokenizer sft = new SubFieldTokenizer(s);
        Hashtable table = sft.getHashtable();
        
        String name = (String) table.get(/* NOI18N */"name");
        if (name == null || name.length() <= 0)
	    /* BEGIN JSTYLED */
	    throw new ParseException(Global.getMsg("sunsoft.jws.visual.rt.type.FontConverter.Missing__font__name-co-__") + s);
	/* END JSTYLED */
	int style;
        String styleString = (String) table.get(/* NOI18N */"style");
        if (styleString != null) {
            if (styleString.equals(/* NOI18N */"italic"))
                style = Font.ITALIC;
            else if (styleString.equals(/* NOI18N */"bold"))
                style = Font.BOLD;
            else if (styleString.equals(/* NOI18N */"plain"))
                style = Font.PLAIN;
            else {
		/* BEGIN JSTYLED */
		throw new ParseException(Global.getMsg("sunsoft.jws.visual.rt.type.FontConverter.Invalid__font__style-co-__.30") + s);
		/* END JSTYLED */
            }
        } else {
            style = styleDefault;
        }
        
        int size;
        String sizeString = (String) table.get(/* NOI18N */"size");
        if (sizeString != null) {
            try {
                size = Integer.valueOf(sizeString).intValue();
            } catch (NumberFormatException e) {
		/* BEGIN JSTYLED */
		throw new ParseException(Global.getMsg("sunsoft.jws.visual.rt.type.FontConverter.Invalid__font__size-co-__") + s);
	    }
	    if (size <= 0) {
		throw new ParseException(Global.getMsg("sunsoft.jws.visual.rt.type.FontConverter.Negative__font__size-co-__.31") + s);
		/* END JSTYLED */
            }
        } else {
            size = sizeDefault;
        }
        
        return (new Font(name, style, size));
    }
}
