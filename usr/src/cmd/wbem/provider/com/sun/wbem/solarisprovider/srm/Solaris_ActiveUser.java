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
 * Solaris_ActiveUser.java
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
 * Provider of the Solaris_ActiveUser class. This class represents
 * a ActiveUser that is actively running on an OperatingSystem.
 * @author Sun Microsystems
 */
public class Solaris_ActiveUser extends SRMProvider
	implements Authorizable, Solaris_ActiveUserProperties {

    /**
     * The name of the provider implemented by this class.
     */
    protected String providerName = SOLARIS_ACTIVEUSER;

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

	String userID = null;
	CIMProperty cp;
	CIMInstance ci;
	DataModel   dm = null;
	ActiveUserModel aum;

	SRMDebug.trace(SRMDebug.METHOD_CALL, op.toString());		
	try {
	    Enumeration e = op.getKeys().elements();
	    while (e.hasMoreElements()) {
		cp = (CIMProperty) e.nextElement();		
		if (cp.getName().equalsIgnoreCase(USERID)) {
		    userID = (String) (((CIMValue) (cp.getValue())).getValue());
		}
	    }

	    dm = resourceMonitor.getDataModel(false);
	    if ((aum = dm.getUser(userID)) == null) {
	    	resourceMonitor.releaseDataModel(dm);
	    	throw notFoundEx;
	    }
	    ci = aum.getCIMInstance(cc);
	    dm = resourceMonitor.releaseDataModel(dm);
	} catch (Exception e) {
	    dm = resourceMonitor.releaseDataModel(dm);
	    String msg = writeLog(LOGERROR, "SRM_1001");
	    writeLog(LOGERROR, e);
	    SRMDebug.trace1(providerName, e);	
    	    throw new CIMException(CIMException.CIM_ERR_FAILED, msg);
    	}
    	SRMDebug.trace(SRMDebug.METHOD_RETV, ci.toString());	
	return ci;

    } // end getInstance

    
    /**
     * Returns all instances of Solaris_ActiveUser.
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
	CIMInstance ci;
	
	SRMDebug.trace(SRMDebug.METHOD_CALL, op.toString());		
	try {
	    Vector  userInstances = new Vector();
	    dm = resourceMonitor.getDataModel(false);
	    Iterator i = dm.getUserIterator();
	    while (i.hasNext()) {
		ci = ((ActiveUserModel) i.next()).getCIMInstance(cc);
		userInstances.addElement(ci);
	    }
    	    dm = resourceMonitor.releaseDataModel(dm);
	    CIMInstance[] ciArray = new CIMInstance[userInstances.size()];
	    userInstances.toArray(ciArray);
	    SRMDebug.trace(SRMDebug.METHOD_RETV, "instance[0]: " +
	    	    	ciArray[0].toString());
            return ciArray;
	} catch (Exception e) {
    	    dm = resourceMonitor.releaseDataModel(dm);
	    String msg = writeLog(LOGERROR, "SRM_1002");
	    msg += " (" + e.getClass().toString() + ")";
	    writeLog(LOGERROR, e);
	    SRMDebug.trace1(providerName, e);	
	    throw new CIMException(CIMException.CIM_ERR_FAILED, msg);
    	}

    } // end enumerateInstances

    
    /**
     * Returns the names of all Solaris_ActiveUser instances.
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
    	DataModel dm = null;

	SRMDebug.trace(SRMDebug.METHOD_CALL, op.toString());		
	try {
	    ActiveUserModel aum;
	    Vector userInstances = new Vector();
	    CIMObjectPath cop;

    	    dm = resourceMonitor.getDataModel(false);
	    Iterator i = dm.getUserIterator();
	    while (i.hasNext()) {
		aum = (ActiveUserModel) i.next();
		cop = new CIMObjectPath(op.getObjectName(), op.getNameSpace());
		cop.addKey(USERID, new CIMValue(aum.name));
		userInstances.addElement(cop);
	    }
	    dm = resourceMonitor.releaseDataModel(dm);
	    CIMObjectPath[] copArray = new CIMObjectPath[userInstances.size()];
	    userInstances.toArray(copArray);
	    SRMDebug.trace(SRMDebug.METHOD_RETV, "instanceName[0]: "
	    	    + copArray[0].toString());
            return copArray;
	} catch (Exception e) {
	    dm = resourceMonitor.releaseDataModel(dm);
	    String msg = writeLog(LOGERROR, "SRM_1003");
	    writeLog(LOGERROR, e);
	    SRMDebug.trace1(providerName, e);	
	    throw new CIMException(CIMException.CIM_ERR_FAILED, msg);
    	}

    } // end enumerateInstanceNames

    protected CIMValue getBulkData(Vector outParams) throws CIMException {
	DataModel   dm = null;
	
	try {
    	    dm = resourceMonitor.getDataModel(false);
	    Iterator i = dm.getUserIterator();
            // Fill the array; each obj takes the bulk data for one user.
            Vector  vOutParam = new Vector();
	    while (i.hasNext()) {	    
    	    	vOutParam.addElement(((ActiveUserModel) i.next()).toBulkData());
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

} // end class Solaris_ActiveUser
