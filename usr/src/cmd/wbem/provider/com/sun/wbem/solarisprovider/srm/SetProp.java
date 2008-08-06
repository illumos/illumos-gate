/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright (c) 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 *
 * SetProp.java
 */


package com.sun.wbem.solarisprovider.srm;

import javax.wbem.cim.*;

/**
 * This is the base class for set property classes. Each
 * derived class can format a string into one CIM data format.
 * @author Sun Microsystems
 */
abstract class SetProp implements PropertyAccessInterface {

    protected String	n;  // the property name
    protected String	vs; // property value as a string
    
    /**
     * Constructor
     * @param n - the name of this property
     */
    public SetProp(String  name) {
	n = name;
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
    abstract public void set(CIMInstance  ci, byte action, String val);
    
    /**
     * Returns a formated name value string of this property
     * @return formated name value string of this property
     */
    public String toString() {
     	return (n + " " + vs + '\n');
    }
    
    /**
     * Returns value string of this property
     * @return value string of this property
     */
    public String getValue() {
     	return vs;
    }

} // end class SetProp
