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
 * @(#) OrientationEnum.java 1.8 - last change made 07/25/97
 */

package sunsoft.jws.visual.rt.type;

import java.awt.Scrollbar;

/**
* A class that knows the orientation attributes of scrollbars, 
* and in an
* instantiation, can store the orientation attribute of a
* single scrollbar.
*
* @see Scrollbar
* @version 	1.8, 07/25/97
*/
public class OrientationEnum extends BaseEnum {
    private static BaseEnumHelper helper = new BaseEnumHelper();
    
    static {
        helper = new BaseEnumHelper();
        helper.add(Scrollbar.HORIZONTAL, /* NOI18N */"horizontal");
        helper.add(Scrollbar.VERTICAL, /* NOI18N */"vertical");
        helper.setDefaultChoice(Scrollbar.VERTICAL);
    }
    
    /**
     * Creates an instance with the choice set to Scrollbar.VERTICAL.
     */
    public OrientationEnum() {
        super();
    }
    
    /**
     * Creates an instance with the choice set to the given int value.
     *
     * @param choice Scrollbar.VERTICAL or Scrollbar.HORIZONTAL
     */
    public OrientationEnum(int choice) {
        super(choice);
    }
    
    /**
     * Creates an instance with the choice set to the given string.
     *
     * @param choice "vertical" or "horizontal"
     */
    public OrientationEnum(String choice) {
        super(choice);
    }
    
    protected BaseEnumHelper getHelper() {
        return (helper);
    }
}
