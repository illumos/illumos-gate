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
 * @(#) SubFieldTokenizer.java 1.7 - last change made 07/25/97
 */

package sunsoft.jws.visual.rt.type;

import java.util.Hashtable;
import java.util.StringTokenizer;

/* BEGIN JSTYLED */
/**
 * Separates a string into sub-field (key-value pairs.)  The 
 * syntax of the
 * string needs to be something like this:
 * <pre>
 *     name=Helvetica;style=italic;size=12;
 * </pre>
 * A hashtable of the keys->values is created, which the caller can then
 * run through to determine what values were set.  Case of field names
 * is always ignored.
 *
 * @version 	1.7, 07/25/97
*/
/* END JSTYLED */
public class SubFieldTokenizer {
    private Hashtable table;
    
    public SubFieldTokenizer(String s) {
        table = new Hashtable();
        
        StringTokenizer st = new StringTokenizer(s, /* NOI18N */";");
        while (st.hasMoreTokens()) {
            String spec = st.nextToken();
            if (spec.length() > 0) {
                int index = spec.indexOf(/* NOI18N */ '=');
                if (index != -1) {
                    String key = spec.substring(0, index).
			trim().toLowerCase();
                    String value = spec.substring(index + 1).trim();
                    if (key.length() > 0) {
                        table.put(key, value);
                    }
                }
            }
        }
    }
    
    public Hashtable getHashtable() {
        return (table);
    }
}
