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
 * @(#) OpArrayConverter.java 1.6 - last change made 07/25/97
 */

package sunsoft.jws.visual.rt.type;

import java.util.Enumeration;

/**
 * Converts an array of Op to a string and back again.
 *
 * @see Op
 * @version 	1.6, 07/25/97
 */
public class OpArrayConverter extends Converter {
    
    public void convertToString(Object obj, StringBuffer buf) {
        if (obj == null) {
            buf.append(/* NOI18N */"null");
            return;
        }
        
        Op op[] = (Op[])obj;
        
        buf.append(/* NOI18N */"{");
        newline(buf);
        incrIndent();
        
        for (int i = 0; i < op.length; i++) {
            indent(buf);
            if (op[i] != null)
                op[i].convertToString(op[i], buf);
            newline(buf);
        }
        
        decrIndent();
        indent(buf);
        buf.append(/* NOI18N */"}");
    }
    
    public Object convertFromString(String s) {
        if (s == null)
            return null;
        
        ListParser parser = new ListParser(s);
        Enumeration e = parser.elements();
        Op ops[] = new Op[parser.size()];
        int i = 0;
        
        while (e.hasMoreElements()) {
            ops[i] = new Op();
            ops[i].convertFromString((String)e.nextElement(), ops[i]);
            i++;
        }
        
        return ops;
    }
    
    /**
     * Returns true if this type should be displayed in an editor.
     *
     * For the attribute editor, a return value of false means that the
     * the textfield will be hidden.
     *
     * @return false
     */
    public boolean viewableAsString() {
        return (false);
    }
}
