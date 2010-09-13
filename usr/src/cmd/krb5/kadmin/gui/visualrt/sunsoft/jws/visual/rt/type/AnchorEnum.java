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
 * @(#) AnchorEnum.java 1.8 - last change made 06/18/97
 */

package sunsoft.jws.visual.rt.type;

import sunsoft.jws.visual.rt.awt.GBConstraints;

/**
 * A class that knows all the possible anchor attribute choices.  In an
 * instantiation, can store a single alignment selection.
 *
 * @see GBConstraints
 * @version 	1.8, 06/18/97
 */
public class AnchorEnum extends BaseEnum {
    private static BaseEnumHelper helper = new BaseEnumHelper();
    
    static {
        helper = new BaseEnumHelper();
        helper.add(GBConstraints.CENTER, /* NOI18N */"center");
        helper.add(GBConstraints.NORTH, /* NOI18N */"north");
        helper.add(GBConstraints.SOUTH, /* NOI18N */"south");
        helper.add(GBConstraints.EAST, /* NOI18N */"east");
        helper.add(GBConstraints.WEST, /* NOI18N */"west");
        helper.add(GBConstraints.NORTHWEST, /* NOI18N */"northwest");
        helper.add(GBConstraints.SOUTHWEST, /* NOI18N */"southwest");
        helper.add(GBConstraints.NORTHEAST, /* NOI18N */"northeast");
        helper.add(GBConstraints.SOUTHEAST, /* NOI18N */"southeast");
        helper.setDefaultChoice(GBConstraints.CENTER);
    }
    
    /**
     * Constructs an instance with choice set to GBConstraints.CENTER.
     */
    public AnchorEnum() {
        super();
    }
    
    /**
     * Constructs an instance from an int value.
     *
     * @param choice GBConstraints.CENTER, GBConstraints.NORTH, 
     * GBConstraints.SOUTH, GBConstraints.EAST, GBConstraints.WEST,
     * GBConstraints.NORTHWEST, GBConstraints.SOUTHWEST,
     * GBConstraints.NORTHEAST, or GBConstraints.SOUTHEAST
    */
    public AnchorEnum(int choice) {
        super(choice);
    }
    
    /**
     * Constructs an instance from a string value.
     *
     * @param choice "center", "north", "south", "east", "west", 
     * "northwest", "southwest", "northeast", or "southeast"
    */
    public AnchorEnum(String choice) {
        super(choice);
    }
    
    protected BaseEnumHelper getHelper() {
        return (helper);
    }
}
