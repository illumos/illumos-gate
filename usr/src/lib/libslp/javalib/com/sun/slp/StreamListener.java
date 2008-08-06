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

//  StreamListener.java: Listen to stream socket, spawn request to
//			  handle incoming request.
//  Author:           James Kempf
//  Created On:       Mon May 18 13:31:40 1998
//  Last Modified By: James Kempf
//  Last Modified On: Tue Jan 12 11:03:30 1999
//  Update Count:     24
//

package com.sun.slp;

import java.util.*;
import java.net.*;
import java.io.*;

/**
 * Listen on the SLP port for clients requesting a stream connection. Spawn
 * a request handler to handle the connection.
 *
 * @author James Kempf, Erik Guttman
 */

class StreamListener extends Thread {

    private ServerSocket serverSocket = null;		// The listening socket
    private InetAddress interfac = null;		// The interface.

    static private SLPConfig config   = null;		// Config object
    static private Hashtable listeners = new Hashtable(); // Stream listeners

    // Initialize a stream (TCP) listener on an interface.

    static void initializeStreamListenerOnInterface(InetAddress interfac)
	throws ServiceLocationException {

	// If we've got it, return.

	if (listeners.get(interfac) != null) {
	    return;

	}

	// Get config object.

	if (config == null) {
	    config = SLPConfig.getSLPConfig();

	}

	// Create the new stream listener.

	StreamListener listener = new StreamListener(interfac);

	// Start it running.

	listener.start();

    }

    private StreamListener(InetAddress interfac)
	throws ServiceLocationException {

	int qn = config.getServerSocketQueueLength();

	// Create a server socket for incoming Stream connections.

	try {
	    serverSocket = new ServerSocket(Defaults.iSLPPort,
					    qn,
					    interfac);

	} catch (IOException ex) {
	    throw new ServiceLocationException(
				ServiceLocationException.NETWORK_INIT_FAILED,
				"socket_creation_failure",
				new Object[] {interfac, ex.getMessage()});
	}

	// Record.

	listeners.put(interfac, this);

	this.interfac = interfac;

    }

    // Listen to port 427, accept incoming connections, pass the socket
    //  off to a new RequestHandler to process.

    public void run() {

	setName("SLP Stream Listener");

	long lLastIOE = 0;

	// Loop, blocking on acceptence of connections.

	while (true) {

	    Socket s = null;

	    try {
		s = serverSocket.accept(); // will block here

		if (config.traceMsg() && s != null) {
		    config.writeLog("sl_incoming",
				    new Object[] {
			s.getInetAddress().toString(),
			    interfac});
		}

		// Set socket timeout in case something goes wrong.

		if (s != null) {
		    s.setSoTimeout(config.getTCPTimeout());

		}

	    } catch (SocketException ex) {
		if (config.traceMsg()) {
		    config.writeLog("sl_sock_timeout",
				    new Object[] {
			s.getInetAddress().toString(),
			    interfac,
			    ex.getMessage()});

		}

		continue;

	    } catch (IOException ex) {
		long lThisIOE = System.currentTimeMillis();

		Assert.slpassert((lThisIOE - lLastIOE >= 250),
			      "sls_repeat_failure",
			      new Object[0]);

		lLastIOE = lThisIOE;
		continue;
	    }

	    RequestHandler rh = new RequestHandler(s, interfac, config);
	    rh.start();

	}
    }
}
