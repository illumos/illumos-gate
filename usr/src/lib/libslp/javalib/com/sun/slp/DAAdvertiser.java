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

//  DAAdvertiser.java: Advertise a DA, also handle incoming DAAdverts.
//  Author:           James Kempf
//  Created On:       Tue May 19 15:22:04 1998
//  Last Modified By: James Kempf
//  Last Modified On: Thu Mar  4 10:39:06 1999
//  Update Count:     44
//

package com.sun.slp;

import java.net.*;
import java.util.*;
import java.io.*;

/**
 * This class supplies a regular interval 'heartbeat' DAAdvertisement.
 * Implementation specific subclasses handle incoming DAAdverts and
 * forwarding of registrations and deregistrations to other DAs. The
 * implementation specific subclasses depend on how the server is
 * representing DA information internally.
 *
 * @author James Kempf, Erik Guttman
 */

class DAAdvertiser extends Thread {

    protected DatagramSocket dss = null;
    protected InetAddress castAddr = null;
    protected InetAddress interfac = null;

    // V2 advertising has the same DAAdvert every time.

    static private byte[]	 outbuf = null;

    static protected SLPConfig config = null;    // Config object.
    static protected Hashtable daadv =
	new Hashtable();	// Existing advertisers

    private Boolean done = Boolean.valueOf(false);

    // Initialize the DAAdvertiser on the designated interface.

    static void initializeDAAdvertiserOnInterface(InetAddress interfac)
	throws ServiceLocationException {

	// If we've got it, return.

	if (daadv.get(interfac) != null) {
	    return;

	}

	// Get the config object.

	if (config == null) {
	    config = SLPConfig.getSLPConfig();

	}

	// Get the SLPv2 DAADvert to send

	ServiceTable table = ServiceTable.getServiceTable();

	SLPServerHeaderV2 hdr =
	    new SLPServerHeaderV2(SrvLocHeader.DAAdvert,
				  false,
				  config.getLocale());

	SDAAdvert msg =
	    (SDAAdvert)table.makeDAAdvert(hdr,
					  interfac,
					  (short)0x0,
					  config.getSAConfiguredScopes(),
					  config);

	// Create a new DAAdvertiser for this interface, with SLPv2
	//  message to send.

	DAAdvertiser daadv = new DAAdvertiser(interfac, msg.getHeader());

	// Start thread running.

	daadv.start();

    }

    // Used by V1 subclass constructor.

    DAAdvertiser() {

	if (config == null) {
	    config = SLPConfig.getSLPConfig();

	}

    }

    // Create a new DAAdvertiser for the interface for default multicast
    //  address. Externalize the message and set the instance variable.

    DAAdvertiser(InetAddress interfac, SrvLocHeader hdr)
	throws ServiceLocationException {

	// Config may not be initialized if this was called directly from
	//  slpd.

	if (config == null) {
	    config = SLPConfig.getSLPConfig();

	}

	// Externalize the DAAdvert.

	ByteArrayOutputStream baos = new ByteArrayOutputStream();

	hdr.externalize(baos, true, false);
	outbuf = baos.toByteArray();

	// Initialize the networking for default multicast address.

	initializeNetworking(interfac, config.getMulticastAddress());

    }


    // Convert advert to bytes, initialize networking.

    protected void
	initializeNetworking(InetAddress interfac,
			     InetAddress maddr)
	throws ServiceLocationException {

	// Set the interface and multicast address on this advertiser.

	this.interfac = interfac;
	this.castAddr = maddr;

	// Get the socket from the listener object corresponding to this
	//  interface. The listener will always be started before the
	//  DAAdvertiser, otherwise, SAs may start sending registrations
	//  before anybody is listening.

	dss = Listener.returnListenerSocketOnInterface(interfac);

	// If the socket is null, then there is no listener. Open a
	//  new socket. Note that any listener opened *afterwards* will
	//  not get this socket.

	if (dss == null) {
	    dss = config.getMulticastSocketOnInterface(interfac, true);

	}
    }

    public void run() {

	// Set the thread name.

	setName("SLP DA Advertisement");

	long heartbeat = config.getAdvertHeartbeatTime() * 1000;

	while (true) {

	    // Send an advert.

	    sendAdvert();

	    // Sleep until next time.

	    try {
		sleep(heartbeat);

	    } catch (InterruptedException ie) {

		// Somebody interrupted us. If we are to exit, then do so.

		synchronized (this) {

		    if (done.booleanValue()) {
			return;

		    }
		}

	    }

	}
    }

    // Send an unsolicited DAAdvert.

    void sendAdvert() {

	byte[] buf = getOutbuf();

	DatagramPacket dp =
	    new DatagramPacket(buf,
			       buf.length,
			       castAddr,
			       Defaults.iSLPPort);
	try {

	    dss.send(dp);

	} catch (IOException ex) {
	    config.writeLog("passive_advert_exception",
			    new Object[] {ex.getMessage()});

	    // Tell the listener to refresh the socket.

	    dss = Listener.refreshSocketOnInterface(interfac);

	}
    }

    // Return the buffer for transmission.

    protected byte[] getOutbuf() {
	return outbuf;

    }

    // Stop the thread from executing.

    void stopThread() {

	synchronized (this) {
	    done = Boolean.valueOf(true);

	}

	this.interrupt();

    }
}
