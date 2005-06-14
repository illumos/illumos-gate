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
 * @(#) UnknownTypeConverter.java 1.11 - last change made 07/25/97
 */

package sunsoft.jws.visual.rt.type;

import java.awt.Color;
import sunsoft.jws.visual.rt.base.Global;


/**
* Handles conversion of objects of unknown type to string 
* and back again.
*
* @version 	1.11, 07/25/97
*/
public class UnknownTypeConverter extends Converter {
    /**
     * Handles conversion of an unknown object type.
     *
     * @exception Error when called
     */
    public String convertToString(Object obj) {
	/* BEGIN JSTYLED */
	throw new Error(Global.fmtMsg("sunsoft.jws.visual.rt.type.UnknownTypeConverter.NoTypeConverter",
				      ((obj == null) ? /* NOI18N */"null" : obj.getClass().getName())));
	/* END JSTYLED */
    }
    
    /**
     * Handles conversion of an string type representation.
     *
     * @exception Error when called
     */
    public Object convertFromString(String s) {
        /* JSTYLED */
	throw new Error(Global.fmtMsg("sunsoft.jws.visual.rt.type.UnknownTypeConverter.CantConvert", s));
    }
}
