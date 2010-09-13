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
 * @(#) @(#) CharacterConverter.java 1.10 - last change made 07/25/97
 */

package sunsoft.jws.visual.rt.type;

/**
 * Converts Character objects to strings and back again.
 *
 * @see Character
 * @version 	1.10, 07/25/97
 */
public class CharacterConverter extends Converter {
    /**
     * Converts a Character to a string.
     *
     * @param obj a instance of Character
     */
    public String convertToString(Object obj) {
        Character c = (Character)obj;
        if (c.charValue() == (char)0)
            return /* NOI18N */"";
        else
            return (c.toString());
    }
    
    /**
     * Converts a string into a Character.  Uses only the 
     * first letter in the
     * string.
     */
    public Object convertFromString(String s) {
        if (s == null || s.equals(/* NOI18N */"")) {
            return new Character((char)0);
        } else {
            return new Character(s.charAt(0));
        }
    }
    
    /**
     * Returns a block of code that will create a 
     * Character liek the one given.
     *
     * @param obj a instance of Character
     */
    public String convertToCode(Object obj) {
        return (/* NOI18N */"new Character('" +
		((Character) obj).toString() + /* NOI18N */"')");
    }
}
