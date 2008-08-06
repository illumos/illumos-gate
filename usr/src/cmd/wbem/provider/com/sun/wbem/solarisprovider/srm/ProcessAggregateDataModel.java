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
 * ProcessAggregateDataModel.java
 */

package com.sun.wbem.solarisprovider.srm;

import javax.wbem.cim.*;


/**
 * Data model of aggregated process utilization
 * It encapsulates a CIM instance of
 * a Solaris_ProjectProcessAggregateStatisticalInformation
 * or Solaris_UserProcessAggregateStatisticalInformation class.
 * @author Sun Microsystems
 */
public class ProcessAggregateDataModel extends ProcessDataModel {


    /**
     * Construct an aggregated process utilization model and set the user id
     * or the project name propertyto uidStr.
     * @param   idStr the user id or project name
     */
    public ProcessAggregateDataModel(String idStr) {
	name = idStr;
    }

    protected void setOpPropertiesVector() {

	opProperties.add(new CIMProperty(SYSTEMNAME,
	      new CIMValue(csName)));
	
	opProperties.add(new CIMProperty(SYSTEMCREATIONCLASSNAME,
	      new CIMValue(SOLARIS_COMPUTERSYSTEM)));
	
	opProperties.add(new CIMProperty(NAME,
	      new CIMValue(name)));
    }
   
    protected void setCIMInstance(boolean newInstance) {
	super.setCIMInstance(newInstance);
	setStrProp(newInstance, CREATIONCLASSNAME,
	    SOLARIS_PROCESSAGGREGATESTATISTICALINFORMATION);
    }

    /**
     * Returns the string value of this object
     */
    public String toString() {
	return super.toString() + "Name    " + name + "\n" + super.toString();
    }

    protected void initKeyValTable() {
	super.initKeyValTable();
	keyValTab.put("id_nproc", new SetUI64Prop("NumProcs"));
    }

} // end class ProcessAggregateDataModel
