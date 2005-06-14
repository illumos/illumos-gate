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
 * Copyright (c) 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 *
 * SetUI64Prop.java
 */


package com.sun.wbem.solarisprovider.srm;

import javax.wbem.cim.*;

class SetUI64Prop extends SetProp {

    private long	v;  // value
        
    /**
     * Constructor
     * @param n - the name of this property
     */
    public SetUI64Prop(String  name) {
    	super(name);
    }
    
    /**
     * Set the property value. Depending of the action flag perform
     * the following actions:
     * CACHE: only save it in the vs variable
     * FLASH: format the value in vs variable and set it in ci instance
     * CHECK_WTHROUGH: save val in vs and check if it is deferent form 
     * the property in ci instance, if so set a new property value.
     * @param ci a cim instance
     * @param action the action to be done: CACHE, FLASH or CHECK_WTHROUGH
     * @param val the property value
     */
    public void set(CIMInstance  ci, byte action, String val)
	    throws NumberFormatException {

    	vs = val;
    	if (action != FLUSH)
	    v = Long.parseLong(val);
	switch (action) {
	    case CACHE : break;
	    case CHECK_WTHROUGH :
		if (v == ((UnsignedInt64)(ci.getProperty(n).
			getValue().getValue())).longValue())
		    break;
	    default: ci.setProperty(n, new CIMValue(Util.longToUI64(v)));
    	}
    }

} // end class SetUI64Prop
