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
 * ResourceMonitor.java
 */


package com.sun.wbem.solarisprovider.srm;

import	java.util.HashSet;

/**
 * Mediator between data model the native interface and the client.
 * Implements the singleton pattern.
 * @author Sun Microsystems, Inc.
 */
public final class ResourceMonitor {
    /**
     * The UPDATETIME defines a time window in which a data request will
     *  be served from internal data cache instead of accessing rds, 5 sec.
     */
    private static final int UPDATETIME =  5000;
     
    /**
     * The RDSTIMEOUT defines the timeout after which the rds 
     * rds will exit, if it hasn't received command from client, 30 sec.
     */
    private static final int RDSTIMEOUT =  30000;
    /**
     * The RDSINTERVAL defines a interval in which the rds
     * will update its data, 1 sec.
     */
    private static final int RDSINTERVAL =  1000;
    
    private static ResourceMonitor	rm;
    private static DataModel	dataModel;
    private long    lastUpdateTime;
    private int     updateTime	= UPDATETIME;
    private int     rdsTimeout	= RDSTIMEOUT; 
    private int     rdsInterval = RDSINTERVAL;
    
    /**
     * threads that hold access into the data model
     */
    private int			    	activeClients;

    /**
     * Ensure that DataModel will be opened and closed once. 
     */
    private boolean ifOpened = false;

    /**
     * Default constructor
     */
    private ResourceMonitor() {
    }

    /**
     * Should be used to obtain the singleton instance of this class
     * @return the singleton instance of this class
     */
    public static synchronized  ResourceMonitor getHandle() {
    	if (rm == null) {
            rm  = new ResourceMonitor();
     	    // The provider data model used by this monitor
            dataModel  = DataModel.getHandle(rm);
    	}
    	return rm;
    }

    /**
     * Open the data model used by this monitor with the following default
     * times, timeout after which the rds rds will exit 30 sec., interval in
     * which the rds will update its data 1 sec., time in which the data model
     * will refresh its cache 5 sec.
     */
    public synchronized void openDataModel() {
	openDataModel(rdsTimeout, rdsInterval, updateTime);
    }

    /**
     * Open the data model used by this monitor.
     * @param rdsTimeout    timeout after which the rds rds will exit,
     *	    	    	    if -1 the default value 30 sec. will be used 
     * @param rdsInterval   interval in which the rds will update its data
     *	    	    	    if -1 the default value 1 sec. will be used 
     * @param updateTime    time in which the data model will refresh its cache
     *	    	    	    if -1 the default value 5 sec. will be used 
     */
    public synchronized void openDataModel(int rdsTimeout,
	    int rdsInterval, int updateTime) {

	if (ifOpened == false) {
	    if (updateTime != -1)
    	    	this.updateTime = updateTime;
	    if (rdsTimeout != -1)
	    	this.rdsTimeout = rdsTimeout;
	    if (rdsTimeout != -1)
	    	this.rdsInterval = rdsInterval;
	    dataModel.open(rdsTimeout, rdsInterval);
	    ifOpened = true;
	}

    } // end openDataModel

    /**
     * Close the data model used by this monitor.
     */
    public synchronized void closeDataModel() {

	if (ifOpened == true) {
	    dataModel.close();
	    ifOpened = false;
	}

    } // end closeDataModel

    /**
     * Get the access to the data model. The caller should invoke
     * releaseDataModel() in order to allow the refresh of the data
     * model cache after it has finished the data processing.
     * @return the data model
     * @throws com.sun.wbem.solarisprovider.srm.SRMException
     *		if the data model couldn't be updated.
     */
    public synchronized
    DataModel getDataModel(boolean forceUpdate)
    throws SRMException {

	if (ifOpened == false)
	    throw new SRMException("Resource Data Model is not opened");

	if (forceUpdate == true) {
	    update();
	} else {
	    long currentTime = System.currentTimeMillis();
	    if ((currentTime - lastUpdateTime) > updateTime) {
		lastUpdateTime = currentTime;
		update();
	    }
	}
	activeClients++;
    	SRMDebug.trace(SRMDebug.THREAD_SYNC, "srm data cache update locked by "
	    	+ activeClients + " clients");
	return dataModel;

    } // end getDataModel

    /**
     * Release the lock into the data model. This allows the refresh of the
     * data model cache.
     * @param dm the data got from getDataModel() model must not be zero
     */
    public synchronized DataModel releaseDataModel(DataModel dm) {

    	if (dm != null) {
    	    activeClients--;
    	    SRMDebug.trace(SRMDebug.THREAD_SYNC,
	    	    "srm data cache update locked by "
		    + activeClients + " clients");
    	    notifyAll();
	}
	return null;
    } // end releaseDataModel

    /**
     * Wait till all data model readers release their lock, then do the update
     */
    private void update() throws SRMException {
   
    	    beforeUpdate();
	    SRMDebug.trace(SRMDebug.THREAD_SYNC,
	    	"starting srm data cache update, at: "
	    	+System.currentTimeMillis()+"ms");
	    dataModel.update();
	    SRMDebug.trace(SRMDebug.THREAD_SYNC,
	    	"finished srm data cache update, at: "
	    	+System.currentTimeMillis()+"ms");
    }

    private static final int WAITTIME =  500;

    /**
     * Wait till all data model readers release their lock. To ensure
     * liveness only wait max. 10 * WAITTIME;
     */
    private synchronized void beforeUpdate() {
    	int tries = 10;
	
	while (activeClients > 0) {
	    try {
	    	--tries;
	    	wait(WAITTIME);
		if (tries == 0)
		    activeClients = 0;
	    } catch (InterruptedException ex) {
	    }
    	}
    }
    
} // end class ResourceMonitor
