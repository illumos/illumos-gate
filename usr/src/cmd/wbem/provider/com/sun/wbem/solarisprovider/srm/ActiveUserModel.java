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
 * ActiveUserModel.java
 */

package com.sun.wbem.solarisprovider.srm;

import javax.wbem.cim.*;

import java.util.LinkedHashMap;


/**
 * Data model of an active user that is actively running on an OperatingSystem.
 * It encapsulates a CIM instance of the Solaris_ActiveUser class.
 * @author Sun Microsystems
 */
public class ActiveUserModel extends SRMProviderDataModel
	implements SRMProviderProperties, Solaris_ActiveUserProperties {

    /**
     * Construct an active user model and set the user id property
     * to uidStr.
     * @param	uidStr the user id as a string
     */
    public ActiveUserModel(String uidStr) {
	name = uidStr;
    }

    /**
     * Returns the string value of this object
     */
    public String toString() {
	return "\nUser ID " + name + '\n' + super.toString();
    }

    protected void setCIMInstance(boolean newInstance) {
	setStrProp(newInstance, CSCREATIONCLASSNAME, SOLARIS_COMPUTERSYSTEM);
	setStrProp(newInstance, CSNAME, csName);
	setStrProp(newInstance, OSCREATIONCLASSNAME, SOLARIS_OPERATINGSYSTEM);
	setStrProp(newInstance, OSNAME, osName);
	setStrProp(newInstance, CREATIONCLASSNAME, SOLARIS_ACTIVEUSER);
    }

    protected void setOpPropertiesVector() {
	opProperties.add(new CIMProperty(CSCREATIONCLASSNAME,
	    new CIMValue(SOLARIS_COMPUTERSYSTEM)));
	opProperties.add(new CIMProperty(CSNAME, new CIMValue(csName)));
	opProperties.add(new CIMProperty(OSCREATIONCLASSNAME,
	    new CIMValue(SOLARIS_OPERATINGSYSTEM)));
	opProperties.add(new CIMProperty(OSNAME, new CIMValue(osName)));
	opProperties.add(new CIMProperty(USERID, new CIMValue(name)));
    }
    
    protected void initKeyValTable() {
	keyValTab = new LinkedHashMap(2);
	keyValTab.put(USERID_KEY, new SetUI32Prop(USERID));	  
	keyValTab.put(USERNAME_KEY, new SetStringProp(USERNAME));	  
    }

} // end class ActiveUserModel
