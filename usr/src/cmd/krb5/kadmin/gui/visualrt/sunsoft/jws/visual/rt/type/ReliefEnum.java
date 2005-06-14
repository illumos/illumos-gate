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
 * @(#) ReliefEnum.java 1.5 - last change made 07/25/97
 */

package sunsoft.jws.visual.rt.type;

import sunsoft.jws.visual.rt.base.Util;

/**
 * A class that knows the different kinds of reliefs 
 * available for panels.
 *
 * @see Util
 * @see sunsoft.jws.visual.rt.awt.VJPanel
 * @version 	1.5, 07/25/97
 */
public class ReliefEnum extends BaseEnum {
    private static BaseEnumHelper helper = new BaseEnumHelper();
    
    static {
        helper = new BaseEnumHelper();
        
        helper.add(Util.RELIEF_FLAT, /* NOI18N */"flat");
        helper.add(Util.RELIEF_RAISED, /* NOI18N */"raised");
        helper.add(Util.RELIEF_SUNKEN, /* NOI18N */"sunken");
        helper.add(Util.RELIEF_RIDGE, /* NOI18N */"ridge");
        helper.add(Util.RELIEF_GROOVE, /* NOI18N */"groove");
        helper.add(Util.WIN95_RAISED, /* NOI18N */"win95 raised");
        helper.add(Util.WIN95_SUNKEN, /* NOI18N */"win95 sunken");
        helper.add(Util.WIN95_FIELD_BORDER, /* NOI18N */
		   "win95 field border");
        helper.add(Util.WIN95_WINDOW_BORDER, /* NOI18N */
		   "win95 window border");
        
        helper.setDefaultChoice(Util.RELIEF_FLAT);
    }
    
    /**
     * Creates an instance with the choice set to Util.RELIEF_FLAT.
     */
    public ReliefEnum() {
        super();
    }
    
    /**
     * Creates an instance with the choice set to the given int value.
     *
     * @param choice Util.RELIEF_FLAT, Util.RELIEF_RAISED, 
     * Util.RELIEF_SUNKEN, Util.RELIEF_RIDGE, Util.RELIEF_GROOVE,
     * Util.WIN95_RAISED, Util.WIN95_SUNKEN, Util.WIN95_FIELD_BORDER,
     * or Util.WIN95_WINDOW_BORDER
     */
    public ReliefEnum(int choice) {
        super(choice);
    }
    
    /**
     * Creates an instance with the choice set to the given string.
     *
     * @param choice "flat", "raised", "sunken", "ridge", "groove", 
     * "win95 raised", "win95 sunken", "win95 field border", or
     * "win95 window border"
     */
    public ReliefEnum(String choice) {
        super(choice);
    }
    
    protected BaseEnumHelper getHelper() {
        return (helper);
    }
}
