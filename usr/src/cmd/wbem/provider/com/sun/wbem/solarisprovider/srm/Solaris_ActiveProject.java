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
 * Solaris_ActiveProject.java
 */


package com.sun.wbem.solarisprovider.srm;

import javax.wbem.cim.*;
import javax.wbem.client.*;
import javax.wbem.provider.*;
import javax.wbem.query.*;

import com.sun.wbem.solarisprovider.common.ProviderUtility;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.Vector;


/**
 * Provider of the Solaris_ActiveProject class. This class represents
 * a Project that is actively running on an OperatingSystem.
 * @author Sun Microsystems
 */
public class Solaris_ActiveProject extends SRMProvider
	implements Authorizable, Solaris_ActiveProjectProperties {

    /**
     * The name of the provider implemented by this class.
     */
    protected String providerName = SOLARIS_ACTIVEPROJECT;

    /**
     * Get the name of the provider implemented by this class.
     * @returns String provider name
     */
    protected String getProviderName() {
	return providerName;
    }


    /**
     * Returns a specific CIMInstance.
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
    public synchronized CIMInstance getInstance(CIMObjectPath op,
				   boolean localOnly,
				   boolean includeQualifiers,
				   boolean includeClassOrigin,
				   String[] propList,
				   CIMClass cc)
	    throws CIMException {


        String projName = null;
	CIMProperty cp;
	CIMInstance ci = null;
	DataModel   dm = null;
	ActiveProjectModel apm;
	
	SRMDebug.trace(SRMDebug.METHOD_CALL, op.toString());		
        try {
	    Enumeration e = op.getKeys().elements();
            while (e.hasMoreElements()) {
                cp = (CIMProperty) e.nextElement();
                if (cp.getName().equalsIgnoreCase(PROJECTNAME)) {
		    projName =
		      (String) (((CIMValue)(cp.getValue())).getValue());
                }
            }
	    dm = resourceMonitor.getDataModel(false);
	    if ((apm = dm.getProject(projName)) == null) {
	    	resourceMonitor.releaseDataModel(dm);
	    	throw notFoundEx;
	    }
	    ci = apm.getCIMInstance(cc);
	    dm = resourceMonitor.releaseDataModel(dm);
        } catch (Exception e) {
	    dm = resourceMonitor.releaseDataModel(dm);
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
     * Returns all instances of Solaris_ActiveProject.
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
    public synchronized CIMInstance[] enumerateInstances(CIMObjectPath op,
					    boolean localOnly,
					    boolean includeQualifiers,
					    boolean includeClassOrigin,
					    String[] propList,
					    CIMClass cc)
	    throws CIMException {
    	DataModel   dm = null;

	SRMDebug.trace(SRMDebug.METHOD_CALL, op.toString());		
        try {
            Vector  projInstances = new Vector();
	    CIMInstance ci;
    	    dm = resourceMonitor.getDataModel(false);
	    Iterator i = dm.getProjectIterator();

	    while (i.hasNext()) {
		ci = ((ActiveProjectModel) i.next()).getCIMInstance(cc);
		projInstances.addElement(ci);
            }
	    dm = resourceMonitor.releaseDataModel(dm);
	    CIMInstance[] ciArray = new CIMInstance[projInstances.size()];
	    projInstances.toArray(ciArray);
	    SRMDebug.trace(SRMDebug.METHOD_RETV, "instance[0]: " +
	    	    	ciArray[0].toString());
            return ciArray;
        } catch (Exception e) {
	    dm = resourceMonitor.releaseDataModel(dm);
	    String msg = writeLog(LOGERROR, "SRM_1002");
	    writeLog(LOGERROR, e);
	    msg += " (" + e.getClass().toString() + ")";
	    SRMDebug.trace1(providerName, e);	
            throw new CIMException(CIMException.CIM_ERR_FAILED, msg);
	}

    } // end enumerateInstances

    
    /**
     * Returns the names of all Solaris_ActiveProject instances,
     *
     * @param op - the class name to enumerate the instances
     * @param cc - the class reference passed to the provider
     * @return an array of CIMObjectPath containing names of the enumerated
     * instances.
     * @exception CIMException - if the classname is null or does not exist.
     */
    public synchronized CIMObjectPath[] enumerateInstanceNames(CIMObjectPath op,
						  CIMClass cc)
	    throws CIMException {

	DataModel   dm = null;

	SRMDebug.trace(SRMDebug.METHOD_CALL, op.toString());		
        try {
            ActiveProjectModel apm;
            Vector projInstances = new Vector();
	    CIMObjectPath cop;
    	    dm = resourceMonitor.getDataModel(false);
	    Iterator i = dm.getProjectIterator();
	    while (i.hasNext()) {
                apm = (ActiveProjectModel) i.next();
                cop = new CIMObjectPath(op.getObjectName(), op.getNameSpace());
                cop.addKey(PROJECTNAME, new CIMValue(apm.name));
                projInstances.addElement(cop);
            }
	    dm = resourceMonitor.releaseDataModel(dm);
	    CIMObjectPath[] copArray = new CIMObjectPath[projInstances.size()];
	    projInstances.toArray(copArray);
	    SRMDebug.trace(SRMDebug.METHOD_RETV, "instanceName[0]: "
	    	    + copArray[0].toString());
            return copArray;
        } catch (Exception e) {
	    dm = resourceMonitor.releaseDataModel(dm);
	    String msg = writeLog(LOGERROR, "SRM_1002");
	    writeLog(LOGERROR, e);
	    msg += " (" + e.getClass().toString() + ")";
	    SRMDebug.trace1(providerName, e);	
            throw new CIMException(CIMException.CIM_ERR_FAILED, msg);
	}
    
    } // end enumerateInstanceNames

    protected CIMValue getBulkData(Vector outParams) throws CIMException {
	DataModel   dm = null;
	
	try {
    	    dm = resourceMonitor.getDataModel(false);
	    Iterator i = dm.getProjectIterator();
            // Fill the array; each obj takes the bulk data for one user.
            Vector  vOutParam = new Vector();
	    while (i.hasNext()) {	    
    	    	vOutParam.addElement(((ActiveProjectModel) i.next()).
		    	toBulkData());
	    }
            // rem:  we can only return CIMValues in our outParams
            CIMDataType dtype = new CIMDataType(CIMDataType.STRING_ARRAY);
            CIMValue outVal = new CIMValue(vOutParam, dtype);
	    outParams.addElement(outVal);
	    
	    dm = resourceMonitor.releaseDataModel(dm);

	} catch (Exception e) {
	    dm = resourceMonitor.releaseDataModel(dm);
	    String msg = writeLog(LOGERROR, "SRM_1002");
	    writeLog(LOGERROR, e);
	    msg += " (" + e.getClass().toString() + ")";
	    SRMDebug.trace1(providerName, e);	
	    throw new CIMException(CIMException.CIM_ERR_FAILED, msg);
    	}

        CIMValue rv = new CIMValue(new Integer(0));
	return (rv);
    } // end getBulkData

} // end class Solaris_ActiveProject
