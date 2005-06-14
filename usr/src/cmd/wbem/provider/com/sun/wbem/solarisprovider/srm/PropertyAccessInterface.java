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
 * PropertyAccessInterface.java
 */


package com.sun.wbem.solarisprovider.srm;

import javax.wbem.cim.*;


/**
 * Defines the access methods to a properties of a CIM instance.
 */
interface PropertyAccessInterface {

    static final byte CACHE		= 1;
    static final byte FLUSH		= 2;
    static final byte CHECK_WTHROUGH	= 3;

    /**
     * Set the property to the value val. The action specifies how to access
     * the property.
     * CACHE - only cache the value, don't write it to the CIM instance.
     * FLUSH - flush the cached value to the CIM instance.
     * CHECK_WTHROUGH - if the value doesn't equal the current value do nothing,
     *                  otherwise write the internal and the CIM instance value.
     * @param	ci	the CIM instance
     * @param	action	the set type (CACHE, FLUSH or CHECK_WTHROUGH)
     * @param	val	the set value
     */
    void set(CIMInstance  ci, byte action, String val)
	    throws NumberFormatException;

    /**
     * Returns the string value of this object
     */
    String toString();

    /**
     * Returns value string of this property
     */
    public String getValue();

} // end interface PropertyAccessInterface
