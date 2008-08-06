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
 * ProcessDataModel.java
 */

package com.sun.wbem.solarisprovider.srm;

import javax.wbem.cim.*;

import java.util.*;


/**
 * Data model of Process Utilization. It encapsulates a CIM instance of
 * a Solaris_ProcessStatisticalInformation class.
 * @author Sun Microsystems
 */
public class ProcessDataModel extends SRMProviderDataModel
	implements SRMProviderProperties,
	    Solaris_ProcessStatisticalInformationProperties {

    /**
     * Object path to the Solaris_Process instance
     */
    protected CIMObjectPath   opForProc;
    int pid;
    

    public ProcessDataModel() {
    	super();
    }

    
    public ProcessDataModel(int pid) {
    	this.pid = pid;
    }
    

    /**
     * Get a CIM object path to a Solaris_Process object.
     * @returns object path to the Solaris_Process instance.
     */
    public CIMObjectPath getCIMObjectPathForProc() {
        if (opForProc == null) {

            opForProc = new CIMObjectPath(SOLARIS_PROCESS);
	    opForProc.setNameSpace(NAMESPACE);
	    
            Vector properties = new Vector(5);
	    
            properties.add(
		new CIMProperty(CSCREATIONCLASSNAME,
		  new CIMValue(SOLARIS_COMPUTERSYSTEM)));

	    properties.add(
		new CIMProperty(CSNAME,
		  new CIMValue(csName)));

	    properties.add(
		new CIMProperty(OSCREATIONCLASSNAME,
		  new CIMValue(SOLARIS_OPERATINGSYSTEM)));

	    properties.add(
		new CIMProperty(OSNAME,
		  new CIMValue(osName)));

	    properties.add(
		new CIMProperty(HANDLE,
		  new CIMValue(Long.toString(pid))));

	    opForProc.setKeys(properties);
        }
        return opForProc;
    }

    
    public String toString() {

    	return "Name    " + pid + "\n" + super.toString();
    }

    
    protected void setOpPropertiesVector() {

        opProperties.add(
	    	new CIMProperty(CSCREATIONCLASSNAME,
		new CIMValue(SOLARIS_COMPUTERSYSTEM)));
	
        opProperties.add(
		new CIMProperty(CSNAME,
		new CIMValue(csName)));
	
        opProperties.add(
	    	new CIMProperty(OSCREATIONCLASSNAME,
	  	new CIMValue(SOLARIS_OPERATINGSYSTEM)));
	
        opProperties.add(
	    	new CIMProperty(OSNAME,
		new CIMValue(osName)));
	
        opProperties.add(
	    	new CIMProperty(NAME,
		new CIMValue(Long.toString(pid))));
    }

    
    protected void setCIMInstance(boolean newInstance) {

        setStrProp(newInstance,
		  	SYSTEMCREATIONCLASSNAME,
		  	SOLARIS_COMPUTERSYSTEM);
	
        setStrProp(newInstance,
			  SYSTEMNAME,
			  csName);
	
        setStrProp(newInstance,
			  CREATIONCLASSNAME,
			  SOLARIS_PROCESSSTATISTICALINFORMATION);
	
        setStrProp(newInstance,
			  CAPTION,
			  "");
	
        setStrProp(newInstance,
			  DESCRIPTION,
			  "");
	
        setStrProp(newInstance,
			  NAME,
			  Long.toString(pid));
    }

    
    protected void initKeyValTable() {
    	keyValTab = new LinkedHashMap(30);
	
	keyValTab.put(WAITCPUTIME_KEY,
	    new SetReal64Prop(WAITCPUTIME));	  
	keyValTab.put(USERMODETIME_KEY,
	    new SetReal64Prop(USERMODETIME));	  
	keyValTab.put(SYSTEMMODETIME_KEY,
	    new SetReal64Prop(SYSTEMMODETIME));	 
	keyValTab.put(SYSTEMTRAPTIME_KEY,
	    new SetReal64Prop(SYSTEMTRAPTIME));	 
	keyValTab.put(TEXTPAGEFAULTSLEEPTIME_KEY,
	    new SetReal64Prop(TEXTPAGEFAULTSLEEPTIME));
	keyValTab.put(DATAPAGEFAULTSLEEPTIME_KEY,
	    new SetReal64Prop(DATAPAGEFAULTSLEEPTIME));
	keyValTab.put(SYSTEMPAGEFAULTSLEEPTIME_KEY,
	    new SetReal64Prop(SYSTEMPAGEFAULTSLEEPTIME));
	keyValTab.put(USERLOCKWAITSLEEPTIME_KEY,
	    new SetReal64Prop(USERLOCKWAITSLEEPTIME));
	keyValTab.put(OTHERSLEEPTIME_KEY,
	    new SetReal64Prop(OTHERSLEEPTIME));	 
	keyValTab.put(STOPPEDTIME_KEY,
	    new SetReal64Prop(STOPPEDTIME)); 
	keyValTab.put(MINORPAGEFAULTS_KEY,
	    new SetUI64Prop(MINORPAGEFAULTS));	 
	keyValTab.put(MAJORPAGEFAULTS_KEY,
	    new SetUI64Prop(MAJORPAGEFAULTS));	 
	keyValTab.put(SWAPOPERATIONS_KEY,
	    new SetUI64Prop(SWAPOPERATIONS));	 
	keyValTab.put(BLOCKSREAD_KEY,
	    new SetUI64Prop(BLOCKSREAD));  	 
	keyValTab.put(BLOCKSWRITTEN_KEY,
	    new SetUI64Prop(BLOCKSWRITTEN));	 
	keyValTab.put(MESSAGESSENT_KEY,
	    new SetUI64Prop(MESSAGESSENT)); 	 
	keyValTab.put(MESSAGESRECEIVED_KEY,
	    new SetUI64Prop(MESSAGESRECEIVED));	 
	keyValTab.put(SIGNALSRECEIVED_KEY,
	    new SetUI64Prop(SIGNALSRECEIVED));	 
	keyValTab.put(VOLUNTARYCONTEXTSWITCHES_KEY,
	    new SetUI64Prop(VOLUNTARYCONTEXTSWITCHES));
	keyValTab.put(INVOLUNTARYCONTEXTSWITCHES_KEY,
	    new SetUI64Prop(INVOLUNTARYCONTEXTSWITCHES));
	keyValTab.put(SYSTEMCALLSMADE_KEY,
	    new SetUI64Prop(SYSTEMCALLSMADE));	 
	keyValTab.put(CHARACTERIOUSAGE_KEY,
	    new SetUI64Prop(CHARACTERIOUSAGE));	 
	keyValTab.put(PROCESSHEAPSIZE_KEY,
	    new SetUI64Prop(PROCESSHEAPSIZE));	 
	keyValTab.put(PROCESSVMSIZE_KEY,
	    new SetUI64Prop(PROCESSVMSIZE));	 
	keyValTab.put(PROCESSRESIDENTSETSIZE_KEY,
	    new SetUI64Prop(PROCESSRESIDENTSETSIZE));
	keyValTab.put(PERCENTCPUTIME_KEY,
	    new SetReal32Prop(PERCENTCPUTIME));	   
	keyValTab.put(PERCENTMEMORYSIZE_KEY,
	    new SetReal32Prop(PERCENTMEMORYSIZE));    
	keyValTab.put(USERSYSTEMMODETIME_KEY,
	    new SetUI64Prop(USERSYSTEMMODETIME));	
	keyValTab.put(NUMTHREADS_KEY,
	    new SetUI64Prop(NUMTHREADS));
	keyValTab.put(TIMESTAMP_KEY,
	    new SetUI64Prop(TIMESTAMP));
    }
}
