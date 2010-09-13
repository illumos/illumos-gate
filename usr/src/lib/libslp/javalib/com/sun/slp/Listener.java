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

//  Listener.java:    Organize basic listening for slpd and specifically
//                    support datagram listening.
//  Author:           James Kempf
//  Created On:       Mon May 18 12:43:50 1998
//  Last Modified By: James Kempf
//  Last Modified On: Thu Jan  7 08:39:19 1999
//  Update Count:     54
//

package com.sun.slp;

import java.util.*;
import java.net.*;
import java.io.*;

/**
 * This class supplies the basic listening function for the DA
 * and SA. On creation, a StreamListener is created to listen for
 * clients that need to initiate unicast connections. The main object
 * listens on the SLP multicast address for SLP multicasts, and
 * passes the results off to the RequestHandler for direction to
 * the proper table. The RequestHandler object is executed in a different
 * thread to maximize throughput. Note that unicast datagram requests
 * may also enter through this class, since many systems don't distinguish
 * between the multicast and datagram queues for a port.
 *
 * @author James Kempf, Erik Guttman
 */

class Listener extends Thread {

    private DatagramSocket dss = null; 	    // SLP multicast/broadcast socket.
    private InetAddress interfac = null;    // Interface on which we listen.
    private int pktsize = 0;	    	    // MTU of network packet.
    private Vector groups = new Vector();   // Multicast groups monitored.

    static private SLPConfig config = null; // Config object for properties
    static private Hashtable listeners =
			new Hashtable();    // Listeners keyed by interface.

    // Initialize the complex of listener/sender objects on the interface.
    //  This includes a datagram listener, a DAAdvertiser (which shares
    //  the same socket as the datagram listener) if a DA, and a
    //  stream listener.

    static void initializeInterfaceManagers(InetAddress interfac)
	throws ServiceLocationException {

	// If we've done the intializtion, forget it.

	if (listeners.get(interfac) != null) {
	    return;

	}

	// Get config object.

	if (config == null) {
	    config = SLPConfig.getSLPConfig();

	}

	// Create a listener object for this interface.

	Listener listener = new Listener(interfac);

	// Start thread to listen for incoming datagram request.

	listener.start();

	// Create a stream listener object for this interface.

	StreamListener.initializeStreamListenerOnInterface(interfac);

	// We wait until this point to advertise ourselves as DAs. At
	//  this point, we have the listeners up to handle any messages
	//  that might come in as a result.

    }

    // Return the socket for the listener on the designated interface.
    //  DAAdvertisers and the SLPv1 codes uses this to share the
    //  same socket as the main datagram listener.

    static DatagramSocket returnListenerSocketOnInterface(
						InetAddress interfac) {

	Listener listener = (Listener)listeners.get(interfac);

	if (listener != null) {
	    return listener.dss;
	}

	return null;
    }

    // Add the listener on the interface to the multicast group.

    static void
	addListenerToMulticastGroup(InetAddress interfac, InetAddress maddr)
	throws ServiceLocationException {

	Listener listener = (Listener)listeners.get(interfac);

	// Ignore if we haven't got it.

	if (listener == null) {
	    return;

	}

	DatagramSocket dss = listener.dss;

	// Only add if we're multicast.

	if (dss instanceof MulticastSocket) {
	    MulticastSocket mss = (MulticastSocket)dss;

	    try {
		mss.joinGroup(maddr);

		// Record the groups monitored.

		listener.groups.addElement(maddr);

	    } catch (IOException ex) {
		new ServiceLocationException(
				ServiceLocationException.NETWORK_INIT_FAILED,
				"socket_initializtion_failure",
				new Object[] {maddr, ex.getMessage()});

	    }
	}
    }

    // Refresh the listener socket on the interface. If there is no
    //  listener, then simply return a new send socket.

    static DatagramSocket
	refreshSocketOnInterface(InetAddress interfac) {

	Listener listener = (Listener)listeners.get(interfac);

	if (listener == null) {
	    return config.refreshMulticastSocketOnInterface(interfac, null);

	}

	listener.dss.close();

	listener.dss =
	    config.refreshMulticastSocketOnInterface(interfac,
						     listener.groups);

	return listener.dss;

    }

    // Create a Listener for the interface.

    private Listener(InetAddress interfac) throws ServiceLocationException {

	// Get packet size.

	this.pktsize = config.getMTU();

	this.interfac = interfac;

	// Get a socket for this interface.

	this.dss = config.getMulticastSocketOnInterface(interfac, false);

	// Record here so we can use standard utility to add to multicast
	// group.

	listeners.put(interfac, this);

	// If we're multicasting, add to the default SLP group.

	addListenerToMulticastGroup(interfac, config.getMulticastAddress());

    }

    // Listen on multicast for incoming requests, spawn a RequestHandler
    //  to process the datagram.

    public void run()  {

	boolean retry = true;
	String castName = "Multicast";

	if (config.isBroadcastOnly()) {
	    castName = "Broadcast";

	}

	setName("SLP "+castName+" Datagram Listener:"+
		dss.getLocalAddress()+"/"+
		dss.getLocalPort());

	// Loop forever, receiving datagrams and spawning a request handler
	//  to handle it.

	while (true) {
	    byte[] inbuf = new byte[pktsize];
	    DatagramPacket incoming = new DatagramPacket(inbuf, pktsize);

	    // Block on datagram receive.

	    try {
		dss.receive(incoming);

		if (config.traceMsg()) {
		    config.writeLog("request_in",
				    new Object[] {incoming.getAddress(),
						      interfac});
		}

		RequestHandler rh =
		    new RequestHandler(incoming, interfac, config);
		rh.start();

	    } catch (IOException ex) {

		// Die if we can't retry.

		Assert.slpassert(retry,
			      "datagram_io_error",
			      new Object[] {dss.getLocalAddress(),
						ex.getMessage()});

		retry = false;

		config.writeLog("datagram_io_error",
				new Object[] {dss.getLocalAddress(),
						  ex.getMessage()});

		// Close cast socket, get a new one and try again.

		dss.close();
		dss = config.refreshMulticastSocketOnInterface(interfac,
							       groups);

	    }
	}
    }
}
