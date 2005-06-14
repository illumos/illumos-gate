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
 * @(#) ImageRefConverter.java 1.14 - last change made 07/25/97
 */

package sunsoft.jws.visual.rt.type;

import java.net.URL;
import java.net.MalformedURLException;

/**
 * Converts Image filenames/urls (strings) to instances of ImageRef and
 * back again.
 *
 * @see ImageRef
 * @version 	1.14, 07/25/97
 */
public class ImageRefConverter extends Converter {
    /**
     * Converts an ImageRef to a string.
     * 
     * @param obj an instance of ImageRef
     */
    public String convertToString(Object obj) {
        if (obj != null)
            return (((ImageRef) obj).toString());
        else
            return (/* NOI18N */"");
    }
    
    /**
     * Converts a string to a new instance of ImageRef.
     */
    public Object convertFromString(String s) {
        if (s != null && !s.equals(/* NOI18N */""))
            return (new ImageRef(s));
        else
            return (null);
    }
    
    /**
     * Returns code that will create a new instance 
     * of an ImageRef like the one
     * given.
     *
     * @param obj an instance of ImageRef
     */
    public String convertToCode(Object obj) {
        StringBuffer buf = new StringBuffer();
        
        if (obj == null)
            buf.append(/* NOI18N */"null");
        else {
            buf.append(/* NOI18N */"new ImageRef(");
            ListParser.quote(convertToString(obj), buf, true);
            buf.append(/* NOI18N */")");
        }
        
        return buf.toString();
    }
}
