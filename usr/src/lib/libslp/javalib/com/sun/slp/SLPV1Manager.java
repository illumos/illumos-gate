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

//  SLPV1Manager.java: Manages V1 Compatibility
//  Author:           James Kempf
//  Created On:       Wed Sep  9 09:51:40 1998
//  Last Modified By: James Kempf
//  Last Modified On: Thu Mar  4 10:39:11 1999
//  Update Count:     46
//

package com.sun.slp;

import java.io.*;
import java.util.*;
import java.net.*;


/**
 * The SLPV1Manager manages access between the DA and the V1 compatibility
 * framework. The DA calls into the SLPV1Manager to initialize
 * active and passive DA advertising, and to decode an incoming V1
 * message. However, the ServiceTable does *not* call into SLPV1Manager
 * to handle an outgoing message, since each individual message type is
 * handled separately. SLPV1Manager also handles V1 defaults.
 *
 * @author James Kempf
 */

abstract class SLPV1Manager extends Object {

    // V1 Header class.

    static final String V1_HEADER_CLASS = "com.sun.slp.SLPHeaderV1";

    // V1 multicast addresses.

    static final String sGeneralSLPMCAddress = "224.0.1.22";
    static final String sDADiscSLPMCAddress  = "224.0.1.35";

    static InetAddress v1SLPGSAddr = null;
    static InetAddress v1SLPDAAddr = null;

    /**
     * The SLPV1Advertiser implements the SLPv1 DAAdvert xid incrementing
     * algorithm. In SLPv1, the xid of an unsolicited DAAdvert is only
     * 0 if it came up stateless. If it comes up with preexisting state,
     * it sets the counter to 0x100. Also, when the xid counter wraps,
     * it must wrap to 0x100 and not 0x0.
     */

    static class SLPV1Advertiser extends DAAdvertiser {

	// For implementing the V1 xid algorithm.

	private short xid = 0;

	private static final short STATEFUL_XID = 0x100;

	private static final long STATEFUL_TIME_BOUND = 300L;

	// Service table.

	private ServiceTable table = null;

	// Scopes to use. We need to map from V2, so default corresponds to
	//  the empty scope.

	Vector useScopes = new Vector();

	// Create an SLPv1 Advertiser and start it running.

	SLPV1Advertiser(InetAddress interfac,
			InetAddress maddr,
			ServiceTable table)
	    throws ServiceLocationException {
	    super();

	    this.table = table;

	    initialize();

	    //  There will be NO listener on this multicast address,
	    //  so the superclass will simply create a scoket for it.
	    //  We don't want to create a new Listener
	    //  because we are not interested in multicast requests since
	    //  only SAs answer multicast requests.

	    initializeNetworking(interfac, maddr);
	}

	// Initialize the xid for passive advertising. We need to determine
	//  whether we came up stateless or not. We do this by asking the
	//  the service store for the stateless reboot time. If the
	//  stateless reboot time is within the last 5 minutes, we
	//  assume we came up stateless. Otherwise, we're stateful.
	//  We also initialize the URL and scopes.

	private void initialize() throws ServiceLocationException {

	    // Initialize the xid.

	    ServiceStore store = ServiceTable.getServiceTable().store;
	    long timestamp = store.getStateTimestamp();
	    long currentTime = SLPConfig.currentSLPTime();

	    if ((currentTime - timestamp) > STATEFUL_TIME_BOUND) {
		xid = STATEFUL_XID;

	    }

	    // Initialize the scopes.

	    useScopes = config.getSAConfiguredScopes();

	}

	// Return the output buffer for a passive advert. We need to create
	//  the advert, rolling over the xid if necessary for the next one.

	protected byte[] getOutbuf() {

	    SDAAdvert daadvert = null;

	    try {

		SLPHeaderV1 hdr = new SLPHeaderV1();
		hdr.functionCode = SrvLocHeader.DAAdvert;
		hdr.locale = config.getLocale();

		daadvert = (SDAAdvert)table.makeDAAdvert(hdr,
							 interfac,
							 xid,
							 useScopes,
							 config);
		hdr = (SLPHeaderV1)daadvert.getHeader();

		ByteArrayOutputStream baos = new ByteArrayOutputStream();

		hdr.externalize(baos, true, false);
		byte[] outbuf = baos.toByteArray();

		bumpXid();

		return outbuf;

	    } catch (ServiceLocationException ex) {
		Assert.slpassert(false,
			      "v1_advert_error",
			      new Object[0]);

	    }

	    return null;
	}

	private void bumpXid() {

	    int newXID = (int)xid + 1;

	    if (newXID > Short.MAX_VALUE) {
		xid = STATEFUL_XID;

	    } else {
		xid = (short)newXID;

	    }
	}
    }


    // Start up listener, active and passive listeners for SLPv1.

    static public void
	start(SLPConfig config, ServerDATable table, ServiceTable stable) {

	// We do not handle SLPv1 if security is enabled, because SLPv1
	//  security is not implemented.

	if (config.getHasSecurity()) {

	    if (config.regTest() ||
		config.traceMsg() ||
		config.traceDrop() ||
		config.traceDATraffic()) {

		config.writeLog("v1_security_enabled",
				new Object[0]);
	    }

	    return;

	}

	Vector interfaces = config.getInterfaces();
	int i = 0, n = interfaces.size();
	Vector advs = new Vector();

	try {

	    InetAddress v1SLPDAAddr = null;

	    // Get address for DA discovery multicast.

	    v1SLPDAAddr = InetAddress.getByName(sDADiscSLPMCAddress);
	    v1SLPGSAddr = InetAddress.getByName(sGeneralSLPMCAddress);

	    // Add all listeners onto the SLPv1 DA multicast address and
	    //  create a DAAdvertiser on all network interfaces for the
	    //  general multicast group.

	    for (i = 0; i < n; i++) {
		InetAddress interfac = (InetAddress)interfaces.elementAt(i);

		// Listen for SLPv1 multicast DA service requests. Only DA
		//  service requests are multicast on this address.

		Listener.addListenerToMulticastGroup(interfac, v1SLPDAAddr);

		// We don't need to listen to the SLPv1 general multicast
		//  address because we never want any multicast service
		//  requests. But we do need to advertise as an SLPv1 DA.
		//  So we have a special DAAdvertiser subclass to do it.

		DAAdvertiser ad =
		    new SLPV1Advertiser(interfac, v1SLPGSAddr, stable);
		ad.start();

		advs.addElement(ad);

	    }

	    // Let admin know we are running in SLPv1 compatibility mode
	    //  if tracing is on

	    if (config.regTest() ||
		config.traceMsg() ||
		config.traceDrop() ||
		config.traceDATraffic()) {

		config.writeLog("v1_hello",
				new Object[] {config.getSAConfiguredScopes()});
	    }

	    return;

	} catch (ServiceLocationException ex) {

	    config.writeLog("v1_init_error",
			    new Object[] {ex.getMessage()});

	}  catch (UnknownHostException ex) {

	    config.writeLog("v1_init_error",
			    new Object[] {ex.getMessage()});

	}

	// Remove Listeners from multicast group, stop DAAdvertisers.
	// An error occured.

	int j;

	for (j = 0; j < i; i++) {
	    InetAddress interfac = (InetAddress)interfaces.elementAt(i);
	    DatagramSocket dss =
		Listener.returnListenerSocketOnInterface(interfac);

	    if (dss instanceof MulticastSocket) {
		MulticastSocket mss = (MulticastSocket)dss;

		try {
		    mss.leaveGroup(v1SLPDAAddr);

		} catch (IOException ex) {

		    // Ignore it.

		}

		DAAdvertiser ad = (DAAdvertiser)advs.elementAt(j);

		ad.stopThread();
	    }
	}
    }

    // Initialize CSrvReg, CSrvDereg, CSrvMsg, and SDAAdvert classes for SLPv1,
    //  also V1 header class.

    static {

	SrvLocHeader.addHeaderClass(V1_HEADER_CLASS, SLPHeaderV1.VERSION);

    }
}
