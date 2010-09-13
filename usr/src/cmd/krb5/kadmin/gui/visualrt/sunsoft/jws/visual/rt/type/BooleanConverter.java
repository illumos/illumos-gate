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
 * @(#) BooleanConverter.java 1.10 - last change made 06/17/97
 */

package sunsoft.jws.visual.rt.type;

import sunsoft.jws.visual.rt.base.Global;

/**
 * Converts Booleans to strings and back again.
 *
 * @see Boolean
 * @version 	1.10, 06/17/97
 */
public class BooleanConverter extends Converter {
    /**
     * Converts a Boolean to a string.
     *
     * @param obj an instance of Boolean
     * @return its string equivalent, "true" or "false"
     */
    public String convertToString(Object obj) {
        return (((Boolean) obj).booleanValue() ? /* NOI18N */"true"
		: /* NOI18N */"false");
    }
    
    /**
     * Converts a string to a new instance of Boolean.
     *
     * @exception ParseException when a lower-cased version 
     * of the string is not "true" or "false"
    */
    public Object convertFromString(String s) {
        if (s.toLowerCase().equals(/* NOI18N */"true")) {
            return (Boolean.TRUE);
        } else if (s.toLowerCase().equals(/* NOI18N */"false")) {
            return (Boolean.FALSE);
        } else {
	    /* BEGIN JSTYLED */
	    throw new ParseException(Global.getMsg("sunsoft.jws.visual.rt.type.BooleanConverter.Illegal__boolean__valu.17") + s);
	    /* END JSTYLED */
        }
    }
    
    /**
     * Returns a block of code representing a Boolean 
     * like the one given.
     *
     * @param obj an instance of Boolean
     */
    public String convertToCode(Object obj) {
        if (((Boolean) obj).booleanValue())
            return (/* NOI18N */"Boolean.TRUE");
        else
            return (/* NOI18N */"Boolean.FALSE");
    }
}
