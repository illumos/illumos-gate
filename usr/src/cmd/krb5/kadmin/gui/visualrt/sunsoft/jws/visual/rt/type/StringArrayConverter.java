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
 * @(#) StringArrayConverter.java 1.15 - last change made 07/25/97
 */

package sunsoft.jws.visual.rt.type;

import java.util.Vector;
import java.util.StringTokenizer;

/**
 * Converts array of strings to a single string and back again.  The
 * string representation is a string of comma-separated strings.
 * Commas are not (currently) allowed in the strings.
 *
 * @version 1.15, 07/25/97
 */
public class StringArrayConverter extends Converter {
    
    public String convertToString(Object obj) {
        if (obj != null) {
            String[] a = (String[]) obj;
            
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
    
    public Object convertFromString(String s) {
        if (s != null) {
            Vector strbuf = new Vector();
            
            StringTokenizer st = new StringTokenizer
		(s, /* NOI18N */",");
            for (; st.hasMoreTokens(); )
                strbuf.addElement(st.nextToken());
            
            if (strbuf.size() > 0) {
                String retval[] = new String[strbuf.size()];
                for (int i = 0; i < strbuf.size(); i++)
                    retval[i] = (String) strbuf.elementAt(i);
                return (retval);
            }
        }
        return (null);
    }
    
    public String convertToCode(Object obj) {
        StringBuffer buf = new StringBuffer();
        
        buf.append(/* NOI18N */"convert(\"[Ljava.lang.String; \", ");
        ListParser.quote(convertToString(obj), buf, true);
        buf.append(/* NOI18N */")");
        
        return buf.toString();
    }
}
