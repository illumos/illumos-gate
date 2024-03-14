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
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 *
 */

//  ServerDATable.java: Abstract class for DA Table in the DA/SA server.
//  Author:           James Kempf
//  Created On:       Wed May 20 08:30:46 1998
//  Last Modified By: James Kempf
//  Last Modified On: Tue Mar  9 12:36:37 1999
//  Update Count:     124
//

package com.sun.slp;

import java.util.*;
import java.net.*;

/**
 * ServerDATable is an abstract class that provides the interface for DA
 * and scope discovery, storage of DA information from incoming DAAdverts,
 * and forwarding of registrations and deregistration to DAs having
 * the same scopes. A variety of implementations are possible.
 * The getServerDATable() method creates the right one from a subclass.
 * We keep separate track of the superclass DA table and the server
 * DA table so that these two classes can co-exist in the same JVM.
 * Note that the code for forwarding registrations must keep track of
 * only those registrations that were done on this host. It does this
 * by saving the registrations as they come in. The forwarding code
 * is optimized so that forwarding of a new message is fast, while
 * forwarding of a message due to discovery of a new DA is somewhat
 * slower. This helps assure that SA clients get good service.
 *
 * The ServerDATable also does active discovery for the SA server/DA,
 * in a separate thread.
 *
 * @author James Kempf
 */

abstract class ServerDATable extends DATable {

    // The active discovery object.

    protected static ActiveDiscoverer activeDiscoverer = null;

    // The table of regs to forward. Keys are the reg URL and locale, values
    //  are the SSrvReg objects.

    protected Hashtable forwardRegs = new Hashtable();

    // This acts as a guard protecting an non-initialized DA table:
    //  If the DA Table hasn't been populated by active discovery yet,
    //  other threads accessing the DA table will block on readyLock.
    private static Object readyLock = new Object();

    // Keeps track of which DAs support which SPIs. The actual mapping
    //  is DA InetAddress to LinkedList of SPI Strings. recordNewDA
    //  populates this.
    protected Hashtable daSPIsHash = new Hashtable();

    /**
     * Get the right server DA table from the subclass.
     *
     * @return Table for handling DAs in the server.
     */

    static ServerDATable getServerDATable()
	throws ServiceLocationException {

	ServerDATable table = null;

	synchronized (readyLock) {

	    // Note that we are expecting this subclass. We will get a
	    //  cast exception if somebody instantiated with a
	    //  DATable subclass.

	    if (daTable != null) {
		return (ServerDATable)daTable;

	    }

	    conf = SLPConfig.getSLPConfig();

	    // Call the superclass method to link it.

	    daTable = linkAndInstantiateFromProp();

	    table = (ServerDATable)daTable;

	    // Advertise for *all* scopes. This is because we need to
	    //  be able to support clients that do user scoping.

	    Vector useScopes = new Vector();

	    activeDiscoverer =
		new ActiveDiscoverer(Defaults.version,
				     table,
				     useScopes,
				     conf.getMulticastAddress());

	    activeDiscoverer.start();

	}	// readyLock

	return table;

    }

    /**
     * Record a new DA.
     *
     * @param URL The DAAdvert URL.
     * @param scopes The scopes.
     * @param version DA version number.
     * @param attrs Attributes of DA.
     * @param spis SPIs supported by DA
     * @return True if recorded, false if not.
     */

    abstract long
	recordNewDA(ServiceURL url,
		    Vector scopes,
		    long timestamp,
		    int version,
		    Vector attrs,
		    String spis);

    /**
     * Return a hashtable in ServiceTable.findServices() format (e.g.
     * URL's as keys, scopes as values) for DAs matching the query.
     *
     * @param query Query for DA attributes.
     */

    abstract Hashtable returnMatchingDAs(String query)
	throws ServiceLocationException;

    /**
     * Forward a registration or deregistration to all DAs that have matching
     * scopes.
     *
     * @param msg Registration or deregistration message, server side.
     * @param source The address of the source.
     */

    void forwardSAMessage(SrvLocMsg msg, InetAddress source)
	throws ServiceLocationException {

	SrvLocHeader hdr = msg.getHeader();

	// If the message is not from this host (on any interface)
	//  then don't forward it.

	if (!conf.isLocalHostSource(source)) {
	    return;

	}

	// Record it so we can forward to a new DA.

	if (msg instanceof SSrvReg || msg instanceof CSrvReg) {
	    ServiceURL url;
	    if (msg instanceof SSrvReg) {
		url = ((SSrvReg)msg).URL;
	    } else {
		url = ((CSrvReg)msg).URL;
	    }

	    String key = makeKey(url, hdr.locale); // need locale also...
	    forwardRegs.put(key, msg);  // fresh doesn't matter.

	} else {
	    SSrvDereg smsg = (SSrvDereg)msg;

	    // Only remove if tags are null. Otherwise, the updated record
	    //  will be sought.

	    if (smsg.tags == null) {
		String key = makeKey(smsg.URL, hdr.locale);
		forwardRegs.remove(key);

	    }
	}

	// We only forward registrations to v2 DAs because we are
	//  acting as an SA server here. There is no requirement
	//  for v2 SAs to communicate with v1 DAs.

	// Get a hashtable of DAs that match the scopes in the message.

	Hashtable daScopeRec = findDAScopes(hdr.scopes);

	// We are only concerned with the unicast key, since it contains
	//  the DAs to which forwarding is required.

	Vector daRecs = (Vector)daScopeRec.get(UNICAST_KEY);

	// If there are no daRecs, then simply return.

	if (daRecs == null) {
	    return;

	}

	// Otherwise, forward the registration to all DAs in the vector.

	int i, n = daRecs.size();

	for (i = 0; i < n; i++) {
	    DARecord rec = (DARecord)daRecs.elementAt(i);
	    Vector daAddresses = rec.daAddresses;

	    int j, m = daAddresses.size();

	    for (j = 0; j < m; j++) {
		InetAddress addr = (InetAddress)daAddresses.elementAt(j);

		// Don't forward if it's the host from which the registration
		//  came. Otherwise, we're hosed.

		if (!source.equals(addr)) {
		    forwardRegOrDereg(addr, msg);

		}
	    }
	}
    }

    // Make a key for the service agent message table.

    private String makeKey(ServiceURL url, Locale locale) {

	return url.toString() + "/" + locale.toString();

    }


    /**
     * Handle an incoming DAAdvert. Presence must be recorded in the
     * implementation specific server DA table and any registrations need
     * to be forwarded if the boot timestamp is different from the
     * old boot timestamp.
     *
     * @param advert Incoming DAAdvert.
     */

    void handleAdvertIn(CDAAdvert advert) {

	SrvLocHeader hdr = advert.getHeader();

	// Remove if DA is going down.

	if (advert.isGoingDown()) {

	    InetAddress addr = null;

	    try {

		addr = InetAddress.getByName(advert.URL.getHost());

	    } catch (UnknownHostException ex) {
		conf.writeLog("unknown_da_address",
			      new Object[] {advert.URL.getHost()});

		return;
	    }

	    if (removeDA(addr, hdr.scopes)) {

		if (conf.traceDATraffic()) {
		    conf.writeLog("sdat_delete_da",
				  new Object[] {
			advert.URL,
			    hdr.scopes});
		}
	    }

	} else {

	    // verify the DAAdvert
	    if (advert.authBlock != null) {
		try {
		    AuthBlock.verifyAll(advert.authBlock);
		} catch (ServiceLocationException e) {
		    if (conf.traceDrop()) {
			conf.writeLog("sdat_daadvert_vrfy_failed",
				      new Object[] {advert.URL});
		    }
		    return;
		}
	    }

	    long timestamp =
		recordNewDA(advert.URL,
			    hdr.scopes,
			    advert.timestamp,
			    hdr.version,
			    advert.attrs,
			    advert.spis);

	    // Don't forward if the advert was rejected, or if the
	    //  old timestamp greater than or equal to the new timestamp.
	    //  If the old timestamp is greater than or equal to the new,
	    //  it means that we have already forwarded to this DA.
	    //  IF the old timestamp is less, it means that
	    //  the DA has crashed and come up again since we last saw
	    //  it, so we may have missed forwarding something to it.

	    if (timestamp >= advert.timestamp) {

		if (conf.traceDATraffic()) {
		    conf.writeLog("sdat_add_da_no_forward",
				  new Object[] {
			advert.URL,
			    hdr.scopes,
			    Long.valueOf(timestamp)});
		}

		return;

	    }

	    if (conf.traceDATraffic()) {
		conf.writeLog("sdat_add_da",
			      new Object[] {
		    advert.URL,
			hdr.scopes,
			Long.valueOf(advert.timestamp)});
	    }

	    // Forward existing registrations to the new advert.

	    forwardRegistrations(advert.URL, hdr.scopes,
				 advert.timestamp, hdr.version);
	}
    }

    //
    // Private methods.
    //

    private void
	forwardRegistrations(ServiceURL url,
			     Vector scopes,
			     long timestamp,
			     int version) {

	// Wait a random amount of time before forwarding.

	try {

	    Thread.currentThread().sleep(conf.getRandomWait());

	} catch (InterruptedException ex) {

	}

	// Get the registrations to forward.

	Enumeration regs = forwardRegs.elements();

	// Get the address of the DA.

	InetAddress addr = null;
	String host = url.getHost();

	try {
	    addr = InetAddress.getByName(host);

	} catch (UnknownHostException ex) {
	    if (conf.traceDrop() || conf.traceDATraffic()) {
		conf.writeLog("sdat_drop_fwd",
			      new Object[] {
		    host});

	    }

	    return;
	}

	ServiceTable serviceTable = null;

	try {

	    serviceTable = ServiceTable.getServiceTable();

	} catch (ServiceLocationException ex) {

	    // By this time, we should have it.

	}

	// Forward the registrations. Keep track of any deleted elements.

	Vector deleted = new Vector();

	while (regs.hasMoreElements()) {
	    SrvLocMsg reg = (SrvLocMsg)regs.nextElement();

	    ServiceURL regurl;
	    if (reg instanceof SSrvReg) {
		regurl = ((SSrvReg)reg).URL;
	    } else {
		regurl = ((CSrvReg)reg).URL;
	    }

	    SrvLocHeader hdr = reg.getHeader();

	    // Get the record and modify the reg to reflect the
	    //  record. We must do this because the SA may have
	    //  changed the record since it was first registred
	    //  and we do not keep track of the changes here.

	    ServiceStore.ServiceRecord rec =
		serviceTable.getServiceRecord(regurl, hdr.locale);

	    // If the record is null, it means that the entry was
	    //  aged out.

	    if (rec == null) {
		deleted.addElement(reg);

	    } else {

		// Check that the scopes match.

		Vector sscopes = (Vector)hdr.scopes.clone();

		DATable.filterScopes(sscopes, scopes, false);

		if (sscopes.size() <= 0) {
		    continue;

		}

		if (reg instanceof SSrvReg) {
		    SSrvReg sreg = (SSrvReg)reg;

		    hdr.scopes = (Vector)hdr.scopes.clone();
		    sreg.attrList = (Vector)rec.getAttrList().clone();
		    sreg.URLSignature = rec.getURLSignature();
		    sreg.attrSignature = rec.getAttrSignature();
		}

		forwardRegOrDereg(addr, reg);
	    }

	}

	// Remove any deleted elements from the hashtable.
	//  We do this in a separate loop because enumerations
	//  aren't synchronized.

	int i, n = deleted.size();

	for (i = 0; i < n; i++) {
	    SrvLocMsg reg = (SrvLocMsg)deleted.elementAt(i);
	    SrvLocHeader hdr = reg.getHeader();
	    ServiceURL regurl;
	    if (reg instanceof SSrvReg) {
		regurl = ((SSrvReg)reg).URL;
	    } else {
		regurl = ((CSrvReg)reg).URL;
	    }

	    String key = makeKey(regurl, hdr.locale);

	    forwardRegs.remove(key);

	}

    }


    // Forward the registration or deregistration to the URL.

    private void forwardRegOrDereg(InetAddress addr, SrvLocMsg rqst) {
	SrvLocHeader hdr = rqst.getHeader();

	// Don't forward to myself! Otherwise, nasty recursion happens.

	if (conf.isLocalHostSource(addr)) {
	    return;

	}

	// If security is on, only forward if this DA can verify the authblocks
	if (conf.getHasSecurity()) {
	    LinkedList spis = (LinkedList)daSPIsHash.get(addr);
	    if (spis == null) {
		// internal error; skip this DA to be safe
		return;
	    }

	    Hashtable auths = null;
	    if (rqst instanceof SSrvReg) {
		auths = ((SSrvReg)rqst).URLSignature;
	    } else if (rqst instanceof SSrvDereg) {
		auths = ((SSrvDereg)rqst).URLSignature;
	    } else {
		// shouldn't even be forwarding this!
		return;
	    }

	    // If each authblock is equiv to at least one SPI, forward the reg
	    Enumeration abs = auths.elements();
	    while (abs.hasMoreElements()) {
		AuthBlock ab = (AuthBlock)abs.nextElement();

		// check each DA SPI
		boolean daSPImatch = false;
		for (int SPIi = 0; SPIi < spis.size(); SPIi++) {
		    if (AuthBlock.checkEquiv((String)spis.get(SPIi), ab)) {
			daSPImatch = true;
			break;
		    }
		}

		if (!daSPImatch) {
		    return;
		}
	    }
	}

	if (conf.traceDATraffic()) {
	    conf.writeLog("sdat_forward",
			  new Object[] {
		Integer.toHexString(hdr.xid),
		    addr});

	}


	// Send it via TCP. DAs should understand TCP, and it's reliable.

	SrvLocMsg rply = null;

	try {

	    // Construct the client side message, for outgoing.

	    if (rqst instanceof SSrvReg) {
		SSrvReg rrqst = (SSrvReg)rqst;
		CSrvReg msg = new CSrvReg(hdr.fresh,
					  hdr.locale,
					  rrqst.URL,
					  hdr.scopes,
					  rrqst.attrList,
					  rrqst.URLSignature,
					  rrqst.attrSignature);
		rply = msg;

	    } else if (rqst instanceof SSrvDereg) {
		SSrvDereg drqst = (SSrvDereg)rqst;
		CSrvDereg msg = new CSrvDereg(hdr.locale,
					      drqst.URL,
					      hdr.scopes,
					      drqst.tags,
					      drqst.URLSignature);
		rply = msg;

	    } else if (rqst instanceof CSrvReg) {
		rply = rqst;

	    }

	    rply = Transact.transactTCPMsg(addr, rply, false);

	} catch (ServiceLocationException ex) {

	    if (conf.traceDATraffic()) {
		conf.writeLog("sdat_forward_exception",
			      new Object[] {
		    Integer.toHexString(hdr.xid),
			addr,
			Integer.valueOf(ex.getErrorCode()),
			ex.getMessage()});

	    }
	}

	// Report any errors.

	if (rply == null ||
	    rply.getErrorCode() != ServiceLocationException.OK) {
	    if (conf.traceDATraffic()) {
		conf.writeLog("sdat_forward_err",
			      new Object[] {
		    Integer.toHexString(hdr.xid),
			addr,
			(rply == null ? "<null>":
			 Integer.toString(rply.getErrorCode()))});

	    }
	}
    }
}
