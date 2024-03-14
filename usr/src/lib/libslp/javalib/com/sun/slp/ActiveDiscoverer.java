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
 */

//  ActiveDiscoverer.java: Object to perform active DA discovery.
//  Author:           James Kempf
//  Created On:       Thu Sep  3 08:45:21 1998
//  Last Modified By: James Kempf
//  Last Modified On: Thu Jan 28 15:45:45 1999
//  Update Count:     32
//

package com.sun.slp;

import java.util.*;
import java.net.*;

/*
 * The ActiveDiscover does active discovery DA discovery by periodically
 * sending out a SrvRqst for "service:directory-agent". Replies are
 * entered into the DA table.
 *
 * @author James Kempf
 */

class ActiveDiscoverer extends Thread {

    // Config object.

    static private SLPConfig config = null;

    // Message for active DA discovery.

    private CSrvMsg activeMsg = null;

    // Version of protocol to use for advertisements.

    private int version = 0;

    // DATable where discovered DAs are recorded.

    private ServerDATable table = null;

    // Scopes to advertise for.

    private Vector useScopes = null;

    // Address on which to advertise.

    private InetAddress address = null;

    // Create an active discoverer.

    ActiveDiscoverer(int version,
		     ServerDATable table,
		     Vector useScopes,
		     InetAddress address) {

	this.version = version;

	this.table = table;

	this.useScopes = useScopes;

	this.address = address;

	if (config == null) {
	    config = SLPConfig.getSLPConfig();

	}

    }

    // Do an initial active discovery then start a thread to
    //  do one periodically.

    public void start() {

	// Initial sleepy time.

	long sleepyTime = config.getRandomWait();

	// Create a message for active discovery.

	try {

	    activeMsg = new CSrvMsg(config.getLocale(),
				    Defaults.DA_SERVICE_TYPE,
				    useScopes,
				    "");

	} catch (ServiceLocationException ex) {
	    Assert.slpassert(false,
			  "sdat_active_err",
			  new Object[] {
		Integer.valueOf(ex.getErrorCode()),
		    ex.getMessage()});

	}

	// Initialize preconfigured DAs.

	addPreconfiguredDAs();

	// Do an initial round of active discovery, waiting for
	//  a random period first. Only do it if active
	//  discovery is on.

	if (config.getActiveDiscoveryInterval() > 0) {
	    try {
		Thread.currentThread().sleep(sleepyTime);

	    } catch (InterruptedException ex) {

	    }

	    activeDiscovery();

	} else {

	    // Report that active discovery is off.

	    config.writeLog("ad_active_off",
			    new Object[0]);

	}

	// Start the active discovery thread.

	super.start();
    }



    // Implement the Runnable interface for a thread to start.

    public void run() {

	// Set the Thread name.

	Thread.currentThread().setName("SLP Active DA Discovery");

	// Sleepy time until discovery.

	long sleepyTime = config.getActiveDiscoveryInterval() * 1000;

	// If the sleep time is zero, then active discovery is turned off.
	//  Use the service URL maximum lifetime.

	if (sleepyTime <= 0) {
	    sleepyTime = (ServiceURL.LIFETIME_MAXIMUM / 2) * 1000;

	}

	// Register ourselves at startup if we are a DA. We may not be
	//  listening for the active discovery message at startup
	//  because the listener thread goes on-line last of all.

	if (config.isDA()) {
	    Vector interfaces = config.getInterfaces();
	    int i, n = interfaces.size();

	    for (i = 0; i < n; i++) {
		InetAddress interfac = (InetAddress)interfaces.elementAt(i);
		ServiceURL url = new ServiceURL(Defaults.DA_SERVICE_TYPE +
						"://" +
						interfac.getHostAddress(),
						ServiceURL.LIFETIME_MAXIMUM);
		Vector scopes = config.getSAConfiguredScopes();
		long timestamp = 0; // later adverts will cause replacement,
				    // but noforwarding because it is to us...

		String mySPIs = System.getProperty("sun.net.slp.SPIs");
		mySPIs = mySPIs == null ? "" : mySPIs;

		table.recordNewDA(url,
				  scopes,
				  timestamp,
				  version,
				  config.getDAAttributes(),
				  mySPIs);
	    }
	}

	// Sleep, then perform active discovery or polling of preconfigured
	//  DAs when we awake.

	do {

	    try {

		sleep(sleepyTime);

		if (config.getActiveDiscoveryInterval() > 0) {
		    activeDiscovery();

		} else {
		    addPreconfiguredDAs();

		}

	    } catch (InterruptedException ex) {

	    }

	} while (true);

    }

    // Perform active DA discovery.

    synchronized private void activeDiscovery() {

	// Set the previous responders list to null. Otherwise,
	//  the previous responders from the last time we did
	//  this may interfere.

	SrvLocHeader hdr = activeMsg.getHeader();

	hdr.previousResponders.removeAllElements();


	// Perform the active discovery message transaction.

	try {
	    Transact.transactActiveAdvertRequest(Defaults.DA_SERVICE_TYPE,
						 activeMsg,
						 table);

	} catch (ServiceLocationException ex) {

	    config.writeLog("ad_multi_error",
			    new Object[] { Integer.valueOf(ex.getErrorCode()),
					       ex.getMessage() });

	}

    }

    // Add preconfigured DAs to the DA table. Note that we poll the
    // preconfigured DAs once every 9 hours to make sure they are still around.

    synchronized private void addPreconfiguredDAs() {

	Vector daAddrs = config.getPreconfiguredDAs();
	int i, n = daAddrs.size();

	// Go through the DA addresses, contacting them for their
	// information. Better not be any SLPv1 DAs there.

	for (i = 0; i < n; i++) {
	    InetAddress daAddr = (InetAddress)daAddrs.elementAt(i);

	    // Use a TCP connection. DAs must support TCP so why not?

	    SrvLocMsg reply = null;

	    try {
		reply = Transact.transactTCPMsg(daAddr, activeMsg, false);

	    } catch (ServiceLocationException ex) {

		if (config.traceDrop()) {
		    config.writeLog("ad_trans_error", new Object[] {
			Integer.valueOf(ex.getErrorCode()),
			    daAddr,
			    ex.getMessage() });
		}

		continue;
	    }

	    // Report if there's an error in configuration.

	    if (!(reply instanceof CDAAdvert)) {
		if (config.traceDrop()) {
		    config.writeLog("ad_preconfig_not_advert",
				    new Object[] { daAddr, reply });

		}

		continue;
	    }


	    CDAAdvert advert = (CDAAdvert)reply;
	    SrvLocHeader hdr = advert.getHeader();

	    // We need to make the URL long lived if active
	    // discovery is off. Otherwise, we let the DA time out like all the
	    // rest.

	    if (config.getActiveDiscoveryInterval() <= 0) {
		advert.URL =
		    new ServiceURL(advert.URL.toString(),
				   ServiceURL.LIFETIME_MAXIMUM);

	    }

	    // Add the scopes to the configured scopes. Scopes from configured
	    //  DAs count as configured scopes.

	    config.addPreconfiguredDAScopes(hdr.scopes);

	    // Record it. Note that we don't have to forward here
	    //  because it's the very beginning.

	    table.recordNewDA(advert.URL,
			      hdr.scopes,
			      advert.timestamp,
			      hdr.version,
			      advert.attrs,
			      advert.spis);

	}
    }

}
