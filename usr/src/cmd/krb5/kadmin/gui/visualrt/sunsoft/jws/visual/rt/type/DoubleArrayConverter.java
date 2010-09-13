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
 * @(#) DoubleArrayConverter.java 1.15 - last change made 06/17/97
 */

package sunsoft.jws.visual.rt.type;

import sunsoft.jws.visual.rt.base.Attribute;
import sunsoft.jws.visual.rt.base.Global;

import java.util.Vector;
import java.util.StringTokenizer;

/**
* Converts array of double to a string and back again.
* The string representation is a single line of 
* comma-separated numbers.
*
* @version 	1.15, 06/17/97
*/
public class DoubleArrayConverter extends Converter {
    /**
     * Converts and array of double to a string representation.
     */
    public String convertToString(Object obj) {
        if (obj != null) {
            double[] a = (double[]) obj;
            
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
     * Converts a string to an array of double.
     *
     * @exception ParseException when one of the numbers 
     * is badly formatted
    */
    public Object convertFromString(String s) {
        if (s != null) {
            Vector doublebuf = new Vector();
            
            StringTokenizer st = new StringTokenizer(s, /* NOI18N */",");
            for (; st.hasMoreTokens(); ) {
                try {
                    s = st.nextToken().trim();
                    doublebuf.addElement(Double.valueOf(s));
                } catch (NumberFormatException e) {
                    /* JSTYLED */
		    throw new ParseException(Global.getMsg("sunsoft.jws.visual.rt.type.DoubleArrayConverter.Badly__formatted__doub.28") + s);
                }
            }
            
            if (doublebuf.size() > 0) {
                double retval[] = new double[doublebuf.size()];
                for (int i = 0; i < doublebuf.size(); i++)
                    retval[i] = ((Double) doublebuf.elementAt(i)).
			doubleValue();
                return (retval);
            }
        }
        return (null);
    }
    
    /**
     * Converts an array of double (stored in an attribute) into 
     * a block
     * of code that will create the array without using this
     * converter at
     * runtime.
     */
    public void convertToCodeBlock(String amName, Attribute a,
				   int indent, StringBuffer buf) {
        indent(buf, indent);
        buf.append(/* NOI18N */"{");
        Global.newline(buf);
        
        indent += 2;
        indent(buf, indent);
        buf.append(/* NOI18N */"double _tmp[] = {");
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
