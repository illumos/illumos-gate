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
 * @(#) ColorConverter.java 1.16 - last change made 07/25/97
 */

package sunsoft.jws.visual.rt.type;

import sunsoft.jws.visual.rt.base.Global;

import java.awt.Color;

/**
 * Converts Color objects to strings and back again.
 *
 * @see Color
 * @version 	1.16, 07/25/97
 */
public class ColorConverter extends Converter {
    /**
     * Returns the string for a given color value.  Looks in the
     * ColorStore fisrt, for a good name for the color, or if it can't
     * find one, returns rgb hexadecimal format (e.g. #ef6caf).
     *
     * @param obj instance of Color
     * @see ColorStore
     */
    public String convertToString(Object obj) {
        Color c = (Color)obj;
        if (c == null)
            return /* NOI18N */"";
        
        // check the color store for a name
        /* JSTYLED */
	String colorName = ColorStore.getDefaultColorStore().getColorName(c);
        if (colorName != null)
            return colorName;
        
        // create a string contain the hexidecimal rgb value
        int rgb = c.getRGB();
        rgb = rgb & 0xffffff;	// RGB is 3 bytes
        StringBuffer sb = new StringBuffer(Integer.toString(rgb, 16));
        while (sb.length() < 6) {
            sb.insert(0, /* NOI18N */ '0');
        }
        return (/* NOI18N */"#" + sb.toString());
    }
    
    /**
     * Figures out the color the given string represents.
     *
     * @exception ParseException when the color can't be figured
     */
    public Object convertFromString(String s) {
        if (s == null || s.length() == 0)
            return null;
        
        Color color = ColorStore.getDefaultColorStore().getColor(s);
        if (color != null)
            return color;
        
        if (!s.startsWith(/* NOI18N */"#")) {
            /* JSTYLED */
	    throw new ParseException(Global.getMsg("sunsoft.jws.visual.rt.type.ColorConverter.Illegal__color__value-co-.18") + s);
        }
        
        Integer colorValue;
        try {
            colorValue = Integer.valueOf(s.substring(1), 16);
        }
        catch (NumberFormatException ex) {
            /* JSTYLED */
	    throw new ParseException(Global.getMsg("sunsoft.jws.visual.rt.type.ColorConverter.Badly__formatted__colo.19") + s);
        }
        
        int i = colorValue.intValue();
        color = new Color((i >> 16) & 0xFF,
			  (i >> 8) & 0xFF,
			  (i >> 0) & 0xFF);
        
        return color;
    }
}
