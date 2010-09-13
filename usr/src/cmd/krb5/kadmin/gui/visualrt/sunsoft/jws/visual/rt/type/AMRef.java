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
 * @(#) AMRef.java 1.14 - last change made 07/18/96
 */

package sunsoft.jws.visual.rt.type;

import sunsoft.jws.visual.rt.base.AttributeManager;
import sunsoft.jws.visual.rt.base.Root;
import java.util.*;

/**
 * A reference to an attribute manager object.  The reference can
 * merely be the expected name of the object, if necessary.  That way
 * there will be no error until the reference is actually needed.
 * This reference can be made to serve in forward-referencing
 * situations (like file loads) when the object referred to hasn't
 * been loaded yet.
 *
 * @see AttributeManager
 * @version 1.14, 07/18/96
 */
public class AMRef {
    private String name;
    private AttributeManager mgr;
    
    // AMRef Table: a record of unresolved AMRefs created
    private static Vector refRecord = null;
    
    /**
     * Starts recording the AMRefs that are created using a name only.
     * Later a call to the stopRecording method can be used in order to
     * force the resolution of all the AMRefs created since this call
     * was made.  The Designer uses this in order to insure that all
     * AMRefs created during the loading of a file are force to resolve
     * and bind to the real AttributeManager objects to which they
     * refer.
     *
     * @see #stopRecording
     */
    public static void startRecording() {
        refRecord = new Vector();
    }
    
    /**
     * Stops recording the AMRefs that are created and resolves them.
     * Resolution occurrs within the scope of the tree given.  If scope
     * is null then stops recording, clears the list, and doesn't
     * resolve anything.
     *
     * @param scope the attribute manager tree in which to resolve names
     * @see #startRecording
     */
    public static void stopRecording(AttributeManager scope) {
        if (refRecord != null) {
            if (scope != null) {
		/* BEGIN JSTYLED */
		for (Enumeration e = refRecord.elements(); e.hasMoreElements(); ) {
				/* END JSTYLED */
		    AMRef ref = (AMRef) e.nextElement();
		    ref.getRef(scope);
		}
	    }
	    refRecord = null;
	}
    }

    /**
     * Creates a shadow reference from the name only.
     *
     * @see #getRef
     * @param name name of object to which this reference refers
     */
    public AMRef(String name) {
	this.name = name;
	if (refRecord != null)
	    refRecord.addElement(this);
    }

    /**
     * Creates an already-resolved reference.
     *
     * @param mgr the object referred to
     */
    public AMRef(AttributeManager mgr) {
	this.mgr = mgr;
    }

    /**
     * Returns the object referred to.  Resolves it from 
     * the name if necessary.
     *
     * @param scope the attribute manager tree in which
     * to resolve the name
    */
    public AttributeManager getRef(AttributeManager scope) {
	if (mgr == null) {
	    Root root = scope.getRoot();
	    if (root != null)
		mgr = root.resolve(name);
	}
    
	return (mgr);
    }

    /**
     * Returns the name of the object referred to.
     */
    public String getName() {
	if (mgr != null)
	    name = mgr.getName();
	return (name);
    }
}
