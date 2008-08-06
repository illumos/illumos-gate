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
 * SRMProvider.java
 */


package com.sun.wbem.solarisprovider.srm;

import javax.wbem.cim.*;
import javax.wbem.client.*;
import javax.wbem.provider.*;
import javax.wbem.query.*;

import com.sun.wbem.utility.log.*;
import com.sun.wbem.utility.authorization.AuthorizationUtility;
import com.sun.wbem.solarisprovider.common.ProviderUtility;

import java.util.Vector;


/**
 * This is the base class for the SRM providers.
 * It contains default implementations of the WBEM provider API methods which
 * return the CIM_ERR_NOTSUPPORTED error. Each concrete user manager provider
 * subclass overrides the methods with its own implementation. This class also
 * contains several utility methods which may be useful to the individual
 * provider classes.
 * @author Sun Microsystems
 */
public abstract class SRMProvider
	implements InstanceProvider, MethodProvider, SRMProviderProperties {

    /**
     * The handle to the CIMOM.
     */
    private CIMOMHandle cimomhandle = null;

    /**
     * Handle to the log service.
     */
    LogUtil logUtil = null;

    /**
     * Some often used exception are defined here to save some memory.
     */
    protected static final CIMProviderException notFoundEx =
    	new CIMProviderException(CIMException.CIM_ERR_NOT_FOUND);
	
    protected static final CIMProviderException generalEx =
    	new CIMProviderException(CIMProviderException.GENERAL_EXCEPTION);
		
    protected static final CIMException	notSupported = 
    	new CIMException(CIMException.CIM_ERR_NOT_SUPPORTED);

    /**
     * Severity indicator 'ERROR' for logging.
     */
    protected static final int LOGERROR = LogUtil.ERROR;

    /**
     * Severity indicator 'WARNING' for logging.
     */
    protected static final int LOGWARNING = LogUtil.WARNING;

    /**
     * Severity indicator 'INFO' for logging.
     */
    protected static final int LOGINFO = LogUtil.INFO;

    /**
     * Classname of resource messages for logging.
     */
    protected static final String RESOURCEBUNDLE =
    	"com.sun.wbem.solarisprovider.srm.resources.LogMessages";
    
    /**
     * Handle to the resource monitor, which controls the access
     * into the resource data cache (DataModel).
     */
    ResourceMonitor resourceMonitor;

    /**
     * This must be implemented by each subclass to make its
     * class name visible.
     * @returns String provider class name
     */
    protected abstract String getProviderName(); 

    
    //
    // Default implementations of the WBEM Provider API methods
    //


    /**
     * Called by the CIMOM when the provider is initialized.
     *
     * @exception   CIMException    the client connection failed
     */
    public void initialize(CIMOMHandle cimomhandle)
	throws CIMException {
	
    	int updateTime = -1;
    	int rdsTimeout = -1;
    	int rdsInterval = -1;

	// Save the cimomhandle.
	this.cimomhandle = cimomhandle;

	// Establish the logging facility
	logUtil = LogUtil.getInstance(cimomhandle);
		
	try {
	    if (Util.propertyUPDATETIME != null) {
	    	updateTime = Integer.parseInt(Util.propertyUPDATETIME);
	    }
	    if (Util.propertyRDSTIMEOUT != null) {
	    	rdsTimeout = Integer.parseInt(Util.propertyRDSTIMEOUT);
	    }
	    if (Util.propertyRDSINTERVAL != null) {
	    	rdsInterval = Integer.parseInt(Util.propertyRDSINTERVAL);
	    }
	} catch (Exception e)  { };

	try {
	    resourceMonitor = ResourceMonitor.getHandle();
	    resourceMonitor.openDataModel(rdsTimeout, rdsInterval, updateTime);
	} catch (Exception e) {
	    String msg = writeLog(LOGERROR, "SRM_1000", "SRM_10000");
	    writeLog(LOGERROR, e);
	    throw new CIMException(CIMException.CIM_ERR_FAILED, msg);
	}

    } // end initialize

    /**
     * Called by the CIMOM when the provider is removed. Currently the CIMOM
     * does not remove providers, but this method is provided for future
     * versions.
     *
     * @exception CIMException	The method cleanup() throws a CIMException.
     */
    public void cleanup() throws CIMException {

	SRMDebug.trace(SRMDebug.METHOD_CALL, "closing rds data model");		
	resourceMonitor.closeDataModel();
    }

    /**
     * This method must be implemented by instance providers to create
     * the instance specified in the object path. If the instance does
     * exist, CIMInstanceException with ID CIM_ERR_ALREADY_EXISTS
     * must be thrown. The parameter should be the instance name.
     *
     * @param	op	The path of the instance to be set. The important part
     *			in this parameter is the namespace component.
     * @param	ci	The instance to be set.
     * @return	CIMObjectPath of the instance that was created.
     * @exception CIMException	This method throws a CIMException.
     */
    public synchronized CIMObjectPath createInstance(CIMObjectPath op,
					CIMInstance ci)
	    throws CIMException {

	throw notSupported;
    }

    /**
     * Retrieves the instance specified in the argument CIMObjectPath.
     *
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

	throw notSupported;
    }

    /**
     * This method must be implemented by instance providers to set
     * the instance specified in the object path. If the instance does
     * not exist, CIMInstanceException with ID CIM_ERR_NOT_FOUND
     * must be thrown. The parameter should be the instance name.
     *
     * @param	op	The path of the instance to be set. The important part
     *			in this parameter is the namespace component.
     * @param	ci	The instance to be set.
     * @exception CIMException	The setInstance method throws a CIMException.
     */
    public synchronized void setInstance(CIMObjectPath op,
			    CIMInstance ci)
	    throws CIMException {

	throw notSupported;
    }

    /**
     * This method must be implemented by instance providers to delete
     * the instance specified in the object path.
     *
     * @param	ci	The instance to be deleted.
     * @exception CIMException	The deleteInstance method throws a
     *				CIMException.
     */
    public synchronized void deleteInstance(CIMObjectPath op)
	    throws CIMException {

	throw notSupported;
    }

    /**
     * Enumerates all instances of the class which is specified by the
     * CIMObjectPath argument. The entire instances and not just the names
     * are returned.
     *
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

	throw notSupported;
    }
   
    /**
     * Enumerates all of the instances of the class which is specified by
     * the CIMObjectPath argument. Only the class name portion of the
     * CIMObjectPath argument is used, any additional information will be
     * ignored
     *
     * @param op - the class name to enumerate the instances
     * @param cc - the class reference passed to the provider
     * @return an array of CIMObjectPath containing names of the enumerated
     * instances.
     * @exception CIMException - if the classname is null or does not exist.
     */
    public synchronized CIMObjectPath[] enumerateInstanceNames(CIMObjectPath op,
						boolean deep,
						CIMClass cc)
	    throws CIMException {

	throw notSupported;
    }

    /**
     * This method must be implemented by instance providers to enumerate
     * instances of the class which is specified in op which meet the criteria
     * defined by the query string.
     *
     * @param	op	The object path specifies the class that must
     *			be enumerated.
     * @param	query	The criteria.
     * @param	ql	The CIM query.
     * @param	cc	The class reference.
     * @return CIMInstance The retrieved instance.
     * @exception CIMException	This method throws a CIMException message if the
     *				if operation is not supported.
     */
    public synchronized CIMInstance[] execQuery(CIMObjectPath op,
				   String query,
				   String ql,
				   CIMClass cc)
	    throws CIMException {

	writeLog(LOGINFO,
	  "SRM_0001",
	  "SRM_5003",
	  op.toString(), query, ql);
	
	throw notSupported;
    }

    /**
     * This method contains the implementation for the method. The CIMOM calls
     * this method when the method specified in the parameters is to be invoked.
     * @param op	 Contains the path to the instance whose method must be
     *			 invoked.
     * @param methodName The name of the method.
     * @param inParams	 This is a vector of CIMValues which are the input
     *			 parameters for the method.
     * @param outParams  This is a vector of CIMValues which are the output
     *			 parameters for the method.
     * @return CIMValue  The return value of the method. If the method has no
     *			 return value, it must return null.
     * @exception CIMException	This method throws a CIMException
     */
    public synchronized CIMValue invokeMethod(CIMObjectPath op, 
    	String methodName, Vector inParams, Vector outParams)
	throws CIMException {

	SRMDebug.trace(SRMDebug.METHOD_CALL, op.toString() + methodName);	
	if (methodName.equalsIgnoreCase("getBulkData")) {
	    return getBulkData(outParams);
	} else {
            throw new CIMMethodException(CIMMethodException.NO_SUCH_METHOD,
                methodName, op.getObjectName());
	}

    } // end invokeMethod

    /**
     * This method contains the implementation for the method. The CIMOM calls
     * this method when the method specified in the parameters is to be invoked.
     * @param op    Contains the path to the instance whose method must be
     *	    	    invoked.
     * @param methodName    The name of the method.
     * @param outParams This is a vector of CIMValues which are the output
     *      	    parameters for the method.
     * @return CIMValue The return value of the method. If the method has
     *	    	    no return value, it must return null.
     * @exception CIMException The invokeMethod method throws a CIMException.
     */
    protected CIMValue getBulkData(Vector outParams)
    	throws CIMException {
	throw notSupported;
    }

    //
    // Logging methods.
    // 
    
    /**
     * Utility logging method.
     * @return the log message.
     * @param 	severity 	the reported severity level.
     * @param 	x 		an Exception to be logged.
     */
    protected String writeLog(int severity, Exception x) {
	return writeLog(severity, x.toString());
    }

    
    /**
     * Utility logging method.
     * @return the log message.
     * @param 	severity 	the reported severity level.
     * @param 	summary 	the short summary to be logged.
     * @param 	x 		an Exception to be logged.
     */
    protected String writeLog(int severity,
      			    String summary,
                            Exception x) {
	return writeLog(severity, summary, x.toString());
    }

    
    /**
     * Utility logging method.
     * @return the log message.
     * @param 	severity 	the reported severity level.
     * @param 	summary 	the short summary to be logged.
     * @param 	detail 		the detailed message to be logged.
     * @param 	x 		an Exception to be logged.
     */
    protected String writeLog(int severity,
                            String summary,
                            String detail,
                            Exception x) {
	return writeLog(severity, summary, detail, x.toString());
    }

    
    /**
     * Utility logging method.
     * @return the log message.
     * @param 	severity 	the reported severity level.
     * @param 	summary 	the short summary to be logged.
     */
    protected String writeLog(int severity, String summary) {
	return writeLog(severity,
	  summary,
	  null,
	  null,
	  null,
	  null,
	  null);
    }


    /**
     * Utility logging method.
     * @return the log message.
     * @param 	severity 	the reported severity level.
     * @param 	summary 	the short summary to be logged.
     * @param 	detail 		the detailed message to be logged.
     */
    protected String writeLog(int severity,
      			    String summary,
      			    String detail) {
	return writeLog(severity,
	  summary,
	  detail,
	  null,
	  null,
	  null,
	  null);
    }

    
    /**
     * Utility logging method.
     * @return the log message.
     * @param 	severity 	the reported severity level.
     * @param 	summary 	the short summary to be logged.
     * @param 	detail	 	the detailed message to be logged.
     * @param 	arg1 		the first parameter to substitute
     *				into the logged message.
     */
    protected String writeLog(int severity,
      			    String summary,
      			    String detail,
      			    String arg1) {
	return writeLog(severity,
	  summary,
	  detail,
	  arg1,
	  null,
	  null,
	  null);
    }


    /**
     * Utility logging method.
     * @return the log message.
     * @param 	severity 	the reported severity level.
     * @param 	summary 	the short summary to be logged.
     * @param 	detail	 	the detailed message to be logged.
     * @param 	arg1 		the first parameter to substitute
     *				into the logged message.
     * @param 	arg2 		the second parameter to substitute
     *				into the logged message.
     */
    protected String writeLog(int severity,
      			    String summary,
      			    String detail,
      			    String arg1,
      			    String arg2) {
	return writeLog(severity,
	  summary,
	  detail,
	  arg1,
	  arg2,
	  null,
	  null);
    }

    
    /**
     * Utility logging method.
     * @return the log message.
     * @param 	severity 	the reported severity level.
     * @param 	summary 	the short summary to be logged.
     * @param 	detail	 	the detailed message to be logged.
     * @param 	arg1 		the first parameter to substitute
     *				into the logged message.
     * @param 	arg2 		the second parameter to substitute
     *				into the logged message.
     * @param 	arg3 		the third parameter to substitute
     * 				into the logged message.
     */
    protected String writeLog(int severity, String summary,
      			    String detail,
      			    String arg1,
      			    String arg2,
      			    String arg3) {
	return writeLog(severity,
	  summary,
	  detail,
	  arg1,
	  arg2,
	  arg3,
	  null);
    }

    
    /**
     * Utility logging method (bottom-level implementation).
     * @return a formatted version of the log message
     *           (<providerName>: <summaryMessage>).
     * @param severity the reported severity level.
     * @param summary the short summary to be logged.
     * @param detail the detailed message to be logged.
     * @param arg1 the first parameter to substitute into the logged message.
     * @param arg2 the second parameter to substitute into the logged message.
     * @param arg3 the third parameter to substitute into the logged message.
     * @param arg4 the fourth parameter to substitute into the logged message.
     */
    protected String writeLog(int severity,
      			    String summary,
      			    String detail,
      			    String arg1,
      			    String arg2,
      			    String arg3,
      			    String arg4) {
	String[] args = {arg1, arg2, arg3, arg4};
	String logmsg = "";

	try {
	    logUtil.writeLog(
		getProviderName(),
		  summary,
		  detail,
		  args,
		  "",
		  true, 
		  LogUtil.APPLICATION_LOG,
		  severity,
		  RESOURCEBUNDLE);
	    
	    logmsg = getProviderName() +
	      		": " +
	      		logUtil.getSummaryMesg(summary, true, RESOURCEBUNDLE);
	} catch (Exception x) {
	    System.err.println("writeLog threw " + x);
	    x.printStackTrace();
	}

	return logmsg;
    }

    protected static String getBundleName() {
	return (RESOURCEBUNDLE);
    }

} // end class SRMProvider
