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
 * @(#) JAShadowAccess.java 1.2 - last change made 07/25/96
 */

package sunsoft.jws.visual.rt.shadow.java.awt;

import sunsoft.jws.visual.rt.base.*;

/**
 * Accessor class for use only by graphical interface builders.  Gives
 * a GUI builder access to methods in this package which are package
 * private.  The methods in this class should not be used by any other
 * application, they are for use by Visual Java only and are subject
 * to change.
 *
 * @version 1.2, 07/25/96
 */
public class JAShadowAccess {

    //
    // These instantiate methods are needed so that the ComponentShadow
    // and ContainerShadow classes can be instantiated when we are
    // generating the list of attribute names.
    //

    public static AttributeManager instantiate(String classname) {
	Class c;
	try {
	    c = Class.forName(classname);
	}
	catch (Exception ex) {
	    System.out.println(ex.toString());
	    return null;
	}
	return instantiate(c);
    }

    public static AttributeManager instantiate(Class c) {
	Object obj;
	try {
	    obj = c.newInstance();
	}
	catch (Exception ex) {
	    System.out.println(ex.toString());
	    return null;
	}

	if (obj instanceof AttributeManager)
	    return (AttributeManager)obj;
	else
	    return null;
    }

    //
    // Internal "FrameShadow" methods
    //

    public static int incrCursor(FrameShadow fs) {
	return fs.incrCursor();
    }

    public static int decrCursor(FrameShadow fs) {
	return fs.decrCursor();
    }

    public static void setPrevCursor(FrameShadow fs, int cursor) {
	fs.setPrevCursor(cursor);
    }

    public static int getPrevCursor(FrameShadow fs) {
	return fs.getPrevCursor();
    }
}
