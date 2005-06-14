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
 * @(#) IntArrayConverter.java 1.14 - last change made 07/25/97
 */

package sunsoft.jws.visual.rt.type;

import sunsoft.jws.visual.rt.base.Attribute;
import sunsoft.jws.visual.rt.base.Global;

import java.util.Vector;
import java.util.StringTokenizer;

/**
* Converts array of int to a string and back again.
* The string representation is a single line of 
* comma-separated numbers.
*
* @version 	1.14, 07/25/97
*/
public class IntArrayConverter extends Converter {
    /**
     * Converts and array of int to a string representation.
     */
    public String convertToString(Object obj) {
        if (obj != null) {
            int[] a = (int[]) obj;
            
            StringBuffer retval = new StringBuffer();
            for (int i = 0; i < a.length; i++) {
                retval.append(a[i]);
                if (i != (a.length-1))
                    retval.append(/* NOI18N */",");
            }
            
            return (retval.toString());
        } else {
            return (/* NOI18N */"");
        }
    }
    
    /**
     * Converts a string to an array of int.
     *
     * @exception ParseException when one of the numbers 
     * is badly formatted
    */
    public Object convertFromString(String s) {
        if (s != null) {
            Vector intbuf = new Vector();
            
            StringTokenizer st = new StringTokenizer(
						     s, /* NOI18N */",");
            for (; st.hasMoreTokens(); ) {
                try {
                    s = st.nextToken().trim();
                    intbuf.addElement(Integer.valueOf(s));
                } catch (NumberFormatException e) {
                    /* JSTYLED */
		    throw new ParseException(Global.fmtMsg("sunsoft.jws.visual.rt.type.IntArrayConverter.BadFormatInteger", s));
                }
            }
            
            if (intbuf.size() > 0) {
                int retval[] = new int[intbuf.size()];
                for (int i = 0; i < intbuf.size(); i++)
                    retval[i] = ((Integer) intbuf.elementAt(i)).intValue();
                return (retval);
            }
        }
        return (null);
    }
    
    /**
     * Converts an array of int (stored in an attribute) into a block
     * of code that will create the array without using 
     * this converter at
     * runtime.
     */
    public void convertToCodeBlock(String amName, Attribute a,
				   int indent, StringBuffer buf) {
        indent(buf, indent);
        buf.append(/* NOI18N */"{");
        Global.newline(buf);
        
        indent += 2;
        indent(buf, indent);
        buf.append(/* NOI18N */"int _tmp[] = {");
        convertToString(a.getValue(), buf);
        buf.append(/* NOI18N */"};");
        Global.newline(buf);
        
        super.convertToCodeBlock(amName, a, indent, buf);
        
        indent -= 2;
        indent(buf, indent);
        buf.append(/* NOI18N */"}");
        Global.newline(buf);
    }
    
    /**
     * Use convertToCodeBlock instead.
     */
    public String convertToCode(Object obj) {
        return (/* NOI18N */"_tmp");
    }
}
