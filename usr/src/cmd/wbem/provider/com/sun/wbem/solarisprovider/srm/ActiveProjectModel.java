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
 * ActiveProjectModel.java
 */

package com.sun.wbem.solarisprovider.srm;

import javax.wbem.cim.*;

import java.util.LinkedHashMap;


/**
 * Data model of a Solaris project.
 * It encapsulates a CIM instance of the Solaris_ActiveProject class.
 * @author Sun Microsystems
 */

public class ActiveProjectModel extends SRMProviderDataModel
	implements SRMProviderProperties, Solaris_ActiveProjectProperties {

    /**
     * Construct an active project model and set the project name property
     * to projName.
     * @param   projName the project name
     */
    public ActiveProjectModel(String projName) {
	name = projName;
    }

    /**
     * Returns the string value of this object
     */
    public String toString() {
	return "Project: " + name + "\n" + super.toString();
    }

    protected void setOpPropertiesVector() {
	opProperties.add(new CIMProperty(CSCREATIONCLASSNAME,
	    new CIMValue(SOLARIS_COMPUTERSYSTEM)));
	opProperties.add(new CIMProperty(CSNAME, new CIMValue(csName)));
	opProperties.add(new CIMProperty(OSCREATIONCLASSNAME,
	    new CIMValue(SOLARIS_OPERATINGSYSTEM)));
	opProperties.add(new CIMProperty(OSNAME, new CIMValue(osName)));
	opProperties.add(new CIMProperty(PROJECTNAME, new CIMValue(name)));
    }

    protected void setCIMInstance(boolean newInstance) {
	setStrProp(newInstance, CSCREATIONCLASSNAME, SOLARIS_COMPUTERSYSTEM);
	setStrProp(newInstance, CSNAME, csName);
	setStrProp(newInstance, OSCREATIONCLASSNAME, SOLARIS_OPERATINGSYSTEM);
	setStrProp(newInstance, OSNAME, osName);
	setStrProp(newInstance, CREATIONCLASSNAME, SOLARIS_ACTIVEPROJECT);
    }

    protected void initKeyValTable() {
	keyValTab = new LinkedHashMap(2);
	keyValTab.put(PROJECTID_KEY, new SetUI32Prop(PROJECTID));
	keyValTab.put(PROJECTNAME_KEY, new SetStringProp(PROJECTNAME));
    }

} // end class ActiveProjectModel
