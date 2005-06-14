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
 * @(#) AMRefConverter.java 1.15 - last change made 07/25/97
 */

package sunsoft.jws.visual.rt.type;

/**
 * Converts references to attribute manager objects into their
 * names and back again.
 *
 * @see AMRef
 * @version 1.15, 07/25/97
 */
public class AMRefConverter extends Converter {
    /**
     * Converts an AMRef object to a string.
     */
    public String convertToString(Object obj) {
        if (obj != null)
            return (((AMRef) obj).getName());
        else
            return (/* NOI18N */"");
    }
    
    /**
     * Converts a string into an AMRef object.
     *
     * @param s string to convert
     */
    public Object convertFromString(String s) {
        if (s != null && s.length() != 0)
            return (new AMRef(s));
        else
            return (null);
    }
    
    /**
     * Returns code for creating an AMRef object.
     *
     * @param obj AMRef object for which to generate code
     */
    public String convertToCode(Object obj) {
        return (/* NOI18N */"new AMRef(\"" + convertToString(obj)
		+ /* NOI18N */"\")");
    }
}
