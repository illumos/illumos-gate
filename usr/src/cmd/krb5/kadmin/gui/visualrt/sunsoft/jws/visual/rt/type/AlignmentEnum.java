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
 * @(#) AlignmentEnum.java 1.9 - last change made 06/18/97
 */

package sunsoft.jws.visual.rt.type;

import java.awt.Label;

/**
 * A class that knows the alignment attributes of labels, and in an
 * instantiation, can store a single alignment selection.
 *
 * @see Label
 * @version 	1.9, 06/18/97
 */
public class AlignmentEnum extends BaseEnum {
    private static BaseEnumHelper helper = new BaseEnumHelper();
    
    static {
        helper.add(Label.LEFT, /* NOI18N */"left");
        helper.add(Label.CENTER, /* NOI18N */"center");
        helper.add(Label.RIGHT, /* NOI18N */"right");
        helper.setDefaultChoice(Label.LEFT);
    }
    
    /**
     * Creates an instance with the choice set to LEFT.
     */
    public AlignmentEnum() {
        super();
    }
    
    /**
     * Creates an instance with the choice set to the given int value.
     *
     * @param choice Label.LEFT, Label.CENTER, or Label.RIGHT
     */
    public AlignmentEnum(int choice) {
        super(choice);
    }
    
    /**
     * Creates an instance with the choice set to the given string.
     *
     * @param choice "left", "center", or "right"
     */
    public AlignmentEnum(String choice) {
        super(choice);
    }
    
    protected BaseEnumHelper getHelper() {
        return (helper);
    }
}
