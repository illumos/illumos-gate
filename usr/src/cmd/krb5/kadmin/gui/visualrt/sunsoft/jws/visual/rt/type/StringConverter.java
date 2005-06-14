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
 * @(#) StringConverter.java 1.16 - last change made 07/29/97
 */

package sunsoft.jws.visual.rt.type;

/**
 * Converts strings to strings.  This is really just a place holder
 * for the String type amoung the type converters.
 *
 * @version 1.16, 07/29/97
 */
public class StringConverter extends Converter {
    public String convertToString(Object obj) {
        if (obj != null)
            return ((String) obj);
        else
            return /* NOI18N */"<null>";
    }
    
    public Object convertFromString(String s) {
        if (!s.equals(/* NOI18N */"<null>"))
            return (s);
        else
            return null;
    }
    
    public String convertToCode(Object obj) {
        StringBuffer buf = new StringBuffer();
        ListParser.quote(convertToString(obj), buf, true);
        
        return buf.toString();
    }
    
}
