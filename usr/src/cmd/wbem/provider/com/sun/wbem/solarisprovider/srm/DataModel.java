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
 * DataModel.java
 */

package com.sun.wbem.solarisprovider.srm;

import java.util.HashMap;
import java.util.Vector;
import java.util.Iterator;


/**
 * Aggregation of all users, projects, and sets metrics data.
 * Implements the singleton pattern
 * @author Sun Microsystems, Inc.
 */
class DataModel {

    private static DataModel		dm;
    private static SRMDataReader	dr;
    private static boolean		doAlive;
    /** 
     * syncObject guards the calls of SRMDataReader methods between the 
     * current data model thread and the KeepAlive thread.
     */
    private static Object		syncObject;
    /** 
     * rdsKeepAliveTimeout: how long the KeepAlive thread should keep
     * the connection opened.
     */ 
    private static int rdsKeepAliveTimeout = 30 * 60000;
    private static KeepAlive	ka;
    private static boolean	kaError;
    private static boolean  	msacct = false;

    private static final int PROCESSESHASHSIZE = 500;
    private static final int USERPROCSHASHSIZE = 200;
    private static final int PROJPROCSHASHSIZE = 100;
    private static final int USERSHASHSIZE = 200;
    private static final int PROJSHASHSIZE = 100;
    private static final int L_PRC_SI = 1;
    private static final int L_USR_SI = 2;
    private static final int L_PRJ_SI = 3;
    private static final int L_AC_USR = 4;
    private static final int L_AC_PRJ = 5;
    private static final int L_SYSTEM = 6;
    private static final int L_ALL  = 20;

    // RDS exec command
    private static final String RDSPGM = "/usr/sadm/lib/wbem/rds";
    
    private static final int	TIMEOUTIDX  = 3;
    private static final int	INTERVALIDX = 5;

    // RDS commands
    private static final String CMD_GETALL	= "-pUuJjS";
    private static final String CMD_GETPL	= "-p";
    private static final String CMD_GETUL	= "-u";
    private static final String CMD_GETAUL	= "-U";
    private static final String CMD_GETJL	= "-j";
    private static final String CMD_GETAJL	= "-J";
    private static final String CMD_GETASL	= "-S";
    private static final String CMD_ALIVE	= "alive";
    private static final String CMD_EXIT	= "exit";

    private static boolean updating; // set if udpdateing is in progress
    private static boolean running;  // set if the rds is running

    private int rdsTimeout;
    private int rdsInterval;
    private String rdsArgs[];
    protected HashMap processes	= new HashMap(PROCESSESHASHSIZE);
    protected HashMap users	= new HashMap(USERSHASHSIZE);
    protected HashMap userprocs	= new HashMap(USERPROCSHASHSIZE);
    protected HashMap projs	= new HashMap(PROJSHASHSIZE);
    protected HashMap projprocs	= new HashMap(PROJPROCSHASHSIZE);
    protected SystemDataModel sdm = new  SystemDataModel();

    /**
     * Default constructor
     */
    private DataModel() {
    }

    /**
     * Should be used to obtain the singleton instance of this class
     * @return	the singleton instance of this class
     */
    static DataModel getHandle(Object syncObj) {

    	if (dm == null) {
	    dm = new DataModel();
	    dr = new SRMDataReader(dm);
	    syncObject = syncObj;
	    try {
	    	if (Util.propertyKEEPALIVETIMEOUT != null) {
	    	    rdsKeepAliveTimeout =
		    	Integer.parseInt(Util.propertyKEEPALIVETIMEOUT);
	    	}
	    	if (Util.propertyMSACCT != null) {
	    	    msacct = Util.propertyMSACCT.equalsIgnoreCase("true");
	    	}
	    } catch (Exception e) { };
    	}
	return dm;
    }

    /**
     * Initialize the rds timeouts, the actually opening is deleted
     * until the first update call.
     */
    void open(int rdsTimeout, int rdsInterval) {
    	Vector args  = new Vector(6);
    	String dbfile = null;

	this.rdsTimeout = rdsTimeout;
	this.rdsInterval = rdsInterval;
    	args.add(RDSPGM);
    	args.add("-a");
    	args.add("-t");
    	args.add(""+rdsTimeout);
    	args.add("-i");
    	args.add(""+rdsInterval);
	if (Util.propertyRDSDATABASE != null) {
    	    args.add("-f");
    	    args.add(Util.propertyRDSDATABASE);
	}
    	if (Util.propertyMSACCT != null &&
	    Util.propertyMSACCT.equalsIgnoreCase("true")) {
    	    args.add("-m");
	}
	if (Util.propertyRDSLOGFILE != null) {
    	    args.add("-L");
    	    args.add(Util.propertyRDSLOGFILE);
	}
	rdsArgs = new String[args.size()];
	args.toArray(rdsArgs);
	
    } // end open

    /**
     * Close the rds communication pipe. 
     */
    void close() {

	if (running) {
	    doAlive = false;
	    ka.interrupt();
    	    synchronized (syncObject) {
	    	/*
		 * check again, since AliveThread could already close RDS
		 * when this thread was waiting on syncObject
		 */
	    	if (running) {
		    dr.closeRDS();
		    running = false;
		}
	    }
	}

    } // end close
    
    /**
     * Close the rds communication pipe after an error has raised. In this
     * case the rds will be shutdown instead of gently closed.
     */
    void closeONError() {
	doAlive = false;
    	ka.interrupt();
    	dr.shutdownRDS();		
    	running = false;
    }
    
    /**
     * Get a provider data model object identified by id from the list defined
     * by listt.
     * @return	the provider data model object or null if other the  list type
     *		or the provider object id are unsupported.
     */
    SRMProviderDataModel getProviderDataModel(int listt, String id) {

	try {
	    switch (listt) {
		case  L_PRC_SI : return getProcess(Integer.parseInt(id));
		case  L_USR_SI : return getUserprocs(id);
		case  L_PRJ_SI : return getProjprocs(id);
		case  L_AC_USR : return getUser(id);
		case  L_AC_PRJ : return getProject(id);
		case  L_SYSTEM : return sdm;
		default: return null;
	    }
	} catch (NumberFormatException e) {
	    return null;
	}
    }

    /**
     * Get process metrics object.
     * @param	pid the process id
     * @return	metrics object with process metrics or new empty
     *		object at first call.
     */
    ProcessDataModel getProcess(int pid) {

	ProcessDataModel pdm = null;
	Integer pidI = new Integer(pid);

	if ((pdm = (ProcessDataModel) processes.get(pidI)) == null) {
	    if (updating == false)
	    	return null;
	    pdm = new ProcessDataModel(pid);
	    processes.put(pidI, pdm);
	}
	if (updating == true)
	    pdm.setUpdated(true);

	return pdm;
    }

    /**
     * Get user metrics object.
     * @param	uid the user id
     * @return	metrics object with process metrics or new empty object at
     *		first call.
     */
    UserProcessAggregateDataModel getUserprocs(String uidStr) {

	UserProcessAggregateDataModel  padm = null;

	if ((padm = (UserProcessAggregateDataModel)
		userprocs.get(uidStr)) == null) {
	    if (updating == false)
	    	return null;
	    padm = new UserProcessAggregateDataModel(uidStr);
	    userprocs.put(uidStr, padm);
	}
	
	if (updating == true)
	    padm.setUpdated(true);

	return padm;
    }

    /**
     * Get project metrics object.
     * @return	metrics object with process metrics or new empty
     *		object at first call.
     */
    ProjectProcessAggregateDataModel getProjprocs(String name) {

	ProjectProcessAggregateDataModel  padm = null;

	if ((padm = (ProjectProcessAggregateDataModel)
		projprocs.get(name)) == null) {
	    if (updating == false)
	    	return null;
	    padm = new ProjectProcessAggregateDataModel(name);
	    projprocs.put(name, padm);
	}
	if (updating == true)
	    padm.setUpdated(true);

	return padm;
    }

    /**
     * Get active user object.
     * @param	name the user id as string
     * @return	active user object.
     */
    ActiveUserModel getUser(String name) {

	ActiveUserModel aum = null;

	if ((aum = (ActiveUserModel) users.get(name)) == null) {
	    if (updating == false)
	    	return null;
	    aum = new ActiveUserModel(name);
	    users.put(name, aum);
	}
	if (updating == true)
	    aum.setUpdated(true);

	return aum;
    }

    /**
     * Get active project object.
     * @param	name the project
     * @return	project object.
     */
    ActiveProjectModel getProject(String name) {

	ActiveProjectModel apm = null;

	if ((apm = (ActiveProjectModel) projs.get(name)) == null) {
	    if (updating == false)
	    	return null;
	    apm = new ActiveProjectModel(name);
	    projs.put(name, apm);
	}
	if (updating == true)
	    apm.setUpdated(true);

	return apm;
    }

    /**
     * Returns an iterator over the Processes.
     * @return iterator
     */
    Iterator getProcessIterator() {
	return processes.values().iterator();
    }

    /**
     * Returns an iterator over the Users.
     * @return iterator
     */
    Iterator getUserIterator() {
	return users.values().iterator();
    }

    /**
     * Returns an iterator over the Projects.
     * @return iterator
     */
    Iterator getProjectIterator() {
	return projs.values().iterator();
    }

    /**
     * Returns an iterator over the user process aggregation.
     * @return iterator
     */
    Iterator getUserprocsIterator() {
	    return userprocs.values().iterator();
    }

    /**
     * Returns an iterator over the project process aggregation.
     * @return iterator
     */
    Iterator getProjprocsIterator() {
	return projprocs.values().iterator();
    }

    /**
     * Update the metrics data.
     * @exception SRMProtocolException
     */
    void  update() throws SRMProtocolException {

	SRMProviderDataModel pdm;
	int tries = 2;

	while (tries-- > 0) {
	    if (!running) {
		dr.startRDS(rdsArgs);
		running = true;
	    	ka = new KeepAlive(rdsKeepAliveTimeout);
		ka.start();
	    }
	    try {
		synchronized (syncObject) {
		    /* check if AliveThread has set error flag */
		    if (kaError) {
		    	closeONError();
			continue;
	    	    /* 
		     * check if rds is still running, since AliveThread
		     * could already close RDS when this thread was waiting
		     * on syncObject
		     */
		    } else if (running) { 	
    	    	    	updating = true;
		    	dr.getUpdate(CMD_GETALL);
		    } else {
		    	tries = 2;
		    	continue;
		    }
		}
		ka.resetTimeout();
		updating = false;
		tries = 0;
	    } catch (SRMProtocolException e) {
	    	SRMDebug.trace(SRMDebug.TRACE_ALL, e.getMessage());	
	    	closeONError();
		if (tries == 0)
		    throw e;		    
	    }
	}
	cleanUp();

    } // end update

    /**
     * Remove all dead processes, users or projects.
     */
    private void cleanUp() {

	cleanUpList(processes);
	cleanUpList(users);
	cleanUpList(userprocs);
	cleanUpList(projs);
	cleanUpList(projprocs);
    }

    /**
     * Remove all elements that heven't been updated in last update.
     */
    private void cleanUpList(HashMap map) {
	Iterator i;
	SRMProviderDataModel pdm;

	for (i = map.values().iterator(); i.hasNext(); ) {
	    if (!((pdm = (SRMProviderDataModel) i.next()).isUpdated())) {
		i.remove();
	    } else {
		pdm.setUpdated(false);
	    }
	}
    }

    /**
     * This thread keeps the rds and the communication with it alive by
     * sending the alive message to rds.
     */
    class KeepAlive extends Thread {
    	int keepAliveTimeout, save;
	
    	/**
     	 * Constructor
     	 * @param timeout how long to run at all
     	 */
	public KeepAlive(int timeout) {
	    super("KeepAlive");
	    kaError = false;
	    keepAliveTimeout = timeout;
	    save = keepAliveTimeout;
	}
	
	synchronized public void run() {
	    int myTimeout = 0;
	    int waitTime = rdsTimeout / 2;
	    
	    doAlive = true;

	    while (doAlive) {
	    	/*
		 * the keepAliveTimeout value is set in constructor and 
		 * in the resetTimeout() method. If its value is reseted
		 * the internal timer myTimeout value will be wind up.
		 */
	    	if (keepAliveTimeout > 0) {
		    myTimeout = keepAliveTimeout;
		    keepAliveTimeout = 0;
		}
		try {
    	    	    synchronized (syncObject) {
		    	/*
			 * this thread has gained the sync object, but it
			 * also should check the doAlive flag since
			 * the dataModel thread could already removed it
			 * because of a protocol error
			 */
		    	if (doAlive) {
		    	    myTimeout -= waitTime;
    	    	    	    kaError = true;
		    	    if (myTimeout <= 0) {
		    	    	dr.closeRDS();
		    	    	running = false;
		    	    	return;
		    	    } else {
		    	    	dr.alive();
			    }
			    kaError = false;
			} else {
			    return;
			}
		    }
		    wait(waitTime);
		} catch (InterruptedException e) {
	    	    SRMDebug.trace(SRMDebug.TRACE_ALL, e.getMessage());
		    return;
    	    	} catch (SRMProtocolException e) {
	    	    SRMDebug.trace(SRMDebug.TRACE_ALL, e.getMessage());
		    return;
		}
	    }
	}
	
    	/**
     	 * Reset the absolute timeout 
     	 */
	public void resetTimeout() {
	    keepAliveTimeout = save;    
	}

    } // end class KeepAlive


    class ProjectProcessAggregateDataModel extends ProcessAggregateDataModel {
	public ProjectProcessAggregateDataModel(String id) {
	    super(id);
	}
	
	protected void setCIMInstance(boolean newInstance) {
	    super.setCIMInstance(newInstance);
	    setStrProp(newInstance, CREATIONCLASSNAME,
	      SOLARIS_PROJECTPROCESSAGGREGATESTATISTICALINFORMATION);
	    setStrProp(newInstance, NAME, name);
	}
    }

    class UserProcessAggregateDataModel extends ProcessAggregateDataModel {
	public UserProcessAggregateDataModel(String id) {
	    super(id);
	}
	
	protected void setCIMInstance(boolean newInstance) {
	    super.setCIMInstance(newInstance);
	    setStrProp(newInstance, CREATIONCLASSNAME,
	      SOLARIS_USERPROCESSAGGREGATESTATISTICALINFORMATION);
	    setStrProp(newInstance, NAME, name);
	}
    }
    
} // end class DataModel
