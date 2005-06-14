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
 * @(#) @(#) IntegerConverter.java 1.12 - last change made 07/25/97
 */

package sunsoft.jws.visual.rt.type;
import sunsoft.jws.visual.rt.base.Global;

/**
 * Converts Integers to strings and back again.
 *
 * @version 	1.12, 07/25/97
 */
public class IntegerConverter extends Converter {
    public String convertToString(Object obj) {
        if (obj != null)
            return (((Integer) obj).toString());
        else
            return (/* NOI18N */"0");
    }
    
    /**
     * Converts a string to a new instance of Integer.
     *
     * @exception ParseException when the string is badly formatted
     */
    public Object convertFromString(String s) {
        Integer retval = null;
        try {
            retval = new Integer(s);
        } catch (NumberFormatException e) {
            /* JSTYLED */
	    throw new ParseException(Global.fmtMsg("sunsoft.jws.visual.rt.type.IntArrayConverter.BadFormatInteger", s));
        }
        return (retval);
    }
    
    public String convertToCode(Object obj) {
        if (obj != null)
            return (/* NOI18N */"new Integer(" +
		    ((Integer) obj).toString() + /* NOI18N */")");
        else
            return (/* NOI18N */"new Integer(0)");
    }
}
