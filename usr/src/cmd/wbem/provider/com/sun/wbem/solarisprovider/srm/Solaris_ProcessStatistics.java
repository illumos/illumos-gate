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
 * Copyright 2001-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

package com.sun.wbem.solarisprovider.srm;

import javax.wbem.cim.*;
import javax.wbem.client.*;
import javax.wbem.provider.*;

import java.util.Enumeration;
import java.util.Iterator;
import java.util.Vector;


/**
 * Provider of the Solaris_ProcessStatistics class. This class represents
 * an association linking a Solaris_Process and its
 * Solaris_ProcessStatisticalInformation instance a raw resource utilization
 * measurements for a process.
 * @author Sun Microsystems, Inc.
 */
public class Solaris_ProcessStatistics extends SRMProvider {

    /**
     * The name of the provider implemented by this class
     */
    String providerName = SOLARIS_PROCESSSTATISTICS;

    private DataModel dm;

    
    /**
     * Get the name of the provider implemented by this class.
     * @returns String provider name
     */
    protected String getProviderName() {
	return providerName;
    }

    
    /**
     * Returns a specific instance.
     * @param op - the name of the instance to be retrieved. This must include
     * all of the keys and values for the instance.
     * @param localOnly - if true, only the local properties of the class are
     * returned, otherwise all properties are required
     * @param includeQualifiers - if true, the qualifiers are returned as part
     * of of the returned instancei, otherwise no qualifiers will be returned
     * @param includeClassOrigin - if true, the class origin of each property
     * will be returned
     * @param String[] - if null, all properties are returned, otherwise only
     * the properties specified will be returned. Any duplicate properties will
     * be ignored.
     * @param cc - the class reference
     *
     * @return	CIMInstance the retrieved instance.
     * @exception CIMException - the method getInstance throws a CIMException
     * if the CIMObjectPath is incorrect or does not exist.
     */
    public synchronized  CIMInstance getInstance(CIMObjectPath op,
				   boolean localOnly,
				   boolean includeQualifiers,
				   boolean includeClassOrigin,
				   String[] propList,
				   CIMClass cc)
	    throws CIMException {

	CIMObjectPath procstatCOP = null;
	CIMObjectPath procCOP = null;
	CIMInstance ci = null;
	CIMProperty cp = null;

	SRMDebug.trace(SRMDebug.METHOD_CALL, op.toString());		
	try {
	    Enumeration e = op.getKeys().elements();
	    while (e.hasMoreElements()) {
		cp = (CIMProperty) e.nextElement();
		if (cp.getName().equalsIgnoreCase(ELEMENT)) {
		    procCOP = (CIMObjectPath)((CIMValue)(cp.getValue())).
			getValue();
		}
		if (cp.getName().equalsIgnoreCase(STATS)) {
		    procstatCOP = (CIMObjectPath)((CIMValue)(cp.getValue())).
			getValue();
		}
	    }

	    ci = cc.newInstance();
	    ci.setProperty(ELEMENT, new CIMValue(procCOP));
	    ci.setProperty(STATS, new CIMValue(procstatCOP));

	} catch (Exception e) {
	    String msg = writeLog(LOGERROR, "SRM_1001");
	    writeLog(LOGERROR, e);
	    msg += " (" + e.getClass().toString() + ")";
	    SRMDebug.trace1(providerName, e);	
	    throw new CIMException(CIMException.CIM_ERR_FAILED, msg);
	}
    	SRMDebug.trace(SRMDebug.METHOD_RETV, ci.toString());
	return ci;

    } // end getInstance


    /**
     * Returns all instances of Solaris_ProcessStatistics.
     * @param op - the object path specifies the class to be enumerated
     * localOnly - if true, only the local properties of the class are returned,
     * otherwise all properties are required
     * @param includeQualifiers - if true, the qualifiers are returned as part
     * of of the returned instancei, otherwise no qualifiers will be returned
     * @param includeClassOrigin - if true, the class origin of each property
     * will be returned
     * @param String[] - if null, all properties are returned, otherwise only
     * the properties specified will be
     * returned. Any duplicate properties will be ignored.
     * @param cc - the class reference
     * @return An array of CIMInstance
     * @exception CIMException - if the CIMObjectPath is incorrect or does not
     * exist.
     */
    public synchronized  CIMInstance[] enumerateInstances(CIMObjectPath op,
					    boolean localOnly,
					    boolean includeQualifiers,
					    boolean includeClassOrigin,
					    String[] propList,
					    CIMClass cc)
	    throws CIMException {

	Vector installedElements = new Vector();
	ProcessDataModel pdm;
	CIMObjectPath procstatCOP;
	CIMObjectPath procCOP;
	CIMInstance ci;
    	DataModel   dm = null;
	
	SRMDebug.trace(SRMDebug.METHOD_CALL, op.toString());		
	try {
	    dm = resourceMonitor.getDataModel(false);
	    Iterator i = dm.getProcessIterator();
	    while (i.hasNext()) {
		pdm = (ProcessDataModel)i.next();
		procstatCOP  = pdm.getCIMObjectPath(
		    SOLARIS_PROCESSSTATISTICALINFORMATION);
		procCOP = pdm.getCIMObjectPathForProc();
		ci = cc.newInstance();
		ci.setProperty(ELEMENT, new CIMValue(procCOP));
		ci.setProperty(STATS, new CIMValue(procstatCOP));
		installedElements.addElement(ci);
	    }
	    dm = resourceMonitor.releaseDataModel(dm);
	} catch (Exception e) {
	    dm = resourceMonitor.releaseDataModel(dm);
            String msg = writeLog(LOGERROR, "SRM_1002");
	    writeLog(LOGERROR, e);
	    msg += " (" + e.getClass().toString() + ")";
	    SRMDebug.trace1(providerName, e);	
	    throw new CIMException(CIMException.CIM_ERR_FAILED, msg);
    	}

	CIMInstance[] ciArray = new CIMInstance[installedElements.size()];
	installedElements.toArray(ciArray);
	SRMDebug.trace(SRMDebug.METHOD_RETV, "instance[0]: "
	    + (String)(ciArray.length > 0 ? ciArray[0].toString() : "null"));
        return ciArray;

    } // end enumerateInstances

    
    /**
     * Returns the names of all Solaris_ProcessUtilizationInformation instances.
     *
     * @param op - the class name to enumerate the instances
     * @param cc - the class reference passed to the provider
     * @return an array of CIMObjectPath containing names of the enumerated
     * instances.
     * @exception CIMException - if the classname is null or does not exist.
     */
    public synchronized  CIMObjectPath[]
    	    enumerateInstanceNames(CIMObjectPath op, CIMClass cc)
	    throws CIMException {

	Vector installedElements = new Vector();
	ProcessDataModel pdm;
	CIMObjectPath procstatCOP;
	CIMObjectPath procCOP;
	CIMObjectPath cop;

	SRMDebug.trace(SRMDebug.METHOD_CALL, op.toString());		
	try {
	    dm = resourceMonitor.getDataModel(false);
	    Iterator i = dm.getProcessIterator();
	    while (i.hasNext()) {
		pdm = (ProcessDataModel) i.next();
		procstatCOP  = pdm.getCIMObjectPath(
		    SOLARIS_PROCESSSTATISTICALINFORMATION);
		procCOP = pdm.getCIMObjectPathForProc();
		cop = new CIMObjectPath(op.getObjectName(),
		op.getNameSpace());
		cop.addKey(ELEMENT, new CIMValue(procCOP));
		cop.addKey(STATS, new CIMValue(procstatCOP));
		installedElements.add(cop);
	    }
	    dm = resourceMonitor.releaseDataModel(dm);
	} catch (Exception e) {
	    dm = resourceMonitor.releaseDataModel(dm);
	    String msg = writeLog(LOGERROR, "SRM_1003");
	    writeLog(LOGERROR, e);
	    msg += " (" + e.getClass().toString() + ")";
	    SRMDebug.trace1(providerName, e);	
	    throw new CIMException(CIMException.CIM_ERR_FAILED, msg);
    	}
	
	CIMObjectPath[] copArray = new CIMObjectPath[installedElements.size()];
	installedElements.toArray(copArray);
	SRMDebug.trace(SRMDebug.METHOD_RETV, "instanceName[0]: "
	    + (String)(copArray.length > 0 ? copArray[0].toString() : "null"));
        return copArray;

    } // end enumerateInstanceNames

} // end class Solaris_ProcessStatistics
