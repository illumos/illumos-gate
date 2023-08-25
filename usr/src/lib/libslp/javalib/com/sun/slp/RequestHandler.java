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
 * Copyright 2001-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 */

//  RequestHandler.java: Handle an incoming request in a separate thread.
//  Author:           James Kempf
//  Created On:       Mon May 18 14:00:27 1998
//  Last Modified By: James Kempf
//  Last Modified On: Mon Mar  8 16:12:13 1999
//  Update Count:     173
//

package com.sun.slp;

import java.io.*;
import java.net.*;
import java.util.*;

/**
 * Handle an incoming request in a separate thread. The request
 * may have arrived via datagram, or it may have arrived via
 * stream.
 *
 * @author James Kempf, Erik Guttman
 */


class RequestHandler extends Thread {

    private SLPConfig config;		// Config for system properties.
    private ServerDATable daTable;	// DA table in server for reg and dereg
    private InetAddress interfac = null; // Interface on which request came in.
    private Socket sock = null;		// Socket for incoming stream request.
    private DatagramPacket packet = null; // Packet for datagram requests.
    private InetAddress clientAddr = null; // Internet address of the client.
    private int port = 0;		// Port to use.
    private ServiceTable serviceTable = null;
    private SrvLocMsg toForward = null;	 // Reg or dereg to forward.
    private InputStream inStream = null;
    private OutputStream outStream = null;

    static private Hashtable inProgress = new Hashtable();
				// Keeps track of in progress requests

    // When a request handler gets GC'd, make sure it's open socket is closed.
    //  We simply let the exception propagate, because it is ignored.

    protected void finalize() throws IOException {
	if (sock != null) sock.close();

    }

    RequestHandler(InputStream in, OutputStream out, SLPConfig config_in) {
	config = config_in;
	sock = null;
	inStream = in;
	outStream = out;
	clientAddr = config.getLoopback();
	port = 427;
	interfac = clientAddr;

	try {
	    serviceTable = ServiceTable.getServiceTable();

	} catch (ServiceLocationException ex) {

	    // Taken care of in initialization code.

	}
    }

    // Request arrived via stream. Set the incoming socket, spawn
    //  a separate thread in which to run.

    RequestHandler(Socket sock_in, InetAddress interfac, SLPConfig config_in) {

	Assert.slpassert((sock_in != null),
		      "rh_null_sock",
		      new Object[0]);
	Assert.slpassert((config_in != null),
		      "ls_null_config",
		      new Object[0]);

	config = config_in;
	sock = sock_in;
	clientAddr = sock.getInetAddress();
	port = sock.getPort();
	this.interfac = interfac;

	try {
	    serviceTable = ServiceTable.getServiceTable();

	} catch (ServiceLocationException ex) {

	    // Taken care of in initialization code.

	}
    }

    // Request arrived via datagram. Set the incoming packet, spawn
    //  a separate thread in which to run.

    RequestHandler(DatagramPacket packet_in,
		   InetAddress interfac,
		   SLPConfig config_in) {

	Assert.slpassert((packet_in != null),
		      "rh_null_packy",
		      new Object[0]);
	Assert.slpassert((config_in != null),
		      "ls_null_config",
		      new Object[0]);

	config = config_in;
	packet = packet_in;
	clientAddr = packet.getAddress();
	port = packet.getPort();
	this.interfac = interfac;

	try {
	    serviceTable = ServiceTable.getServiceTable();
	    daTable = ServerDATable.getServerDATable();

	} catch (ServiceLocationException ex) {

	    // Taken care of in initialziation code.

	}

    }

    /**
     * Return a stringified buffer, suitable for printing, for
     * debugging.
     *
     * @param bytes The byte buffer.
     * @return A string with the ASCII characters as characters, otherwise
     *         convert to escape notation.
     */

    static String stringifyBuffer(byte[] bytes) {

	StringBuffer buf = new StringBuffer();
	int i, n = bytes.length;

	for (i = 0; i < n; i++) {
	    byte b = bytes[i];

	    if ((b >= 0x21) && (b < 0x7e)) {
		buf.append((char)b);
	    } else {
		buf.append("\\"+Integer.toHexString(((int)b) & 0xFF));
	    }
	}

	return buf.toString();
    }

    // If a stream thread, then get the request first. Process the
    //  request and reply to client.

    public void run() {

	// Is this a stream or datagram thread?

	if (sock != null || inStream != null) {

	    // Label appropriately.

	    setName("Stream Request Handler "+clientAddr+":"+port);

	    if (sock != null) {
		// Set the socket to block until there are bytes to read.

		try {
		    sock.setSoTimeout(0);

		} catch (SocketException ex) {

		}

	    }

	    // get DA Table

	    try {
		daTable = ServerDATable.getServerDATable();
	    } catch (ServiceLocationException e) {

		// Taken care of in initialziation code.

	    }

	    // Stream needs to loop through until requests are completed.

	    handleStream();

	    if (sock != null) {
		try {

		    sock.close();
		    sock = null;

		} catch (IOException ex) {

		}
	    }

	} else {

	    // Label appropriately.

	    setName("Datagram Request Handler "+clientAddr+":"+port);

	    byte[] inbuf = packet.getData();

	    // Copy xid for use in hash key.

	    byte[] xidBuf = new byte[2];
	    System.arraycopy(inbuf, SrvLocHeader.XID_OFFSET, xidBuf, 0, 2);

	    // If this request is already in progress, drop new request.

	    int xid = 0;
	    xid = (int)((char)xidBuf[0] & 0xFF) << 8;
	    xid += (int)((char)xidBuf[1] & 0xFF);
	    String syncTableKey =
		(new Integer(xid)).toString() +  clientAddr.getHostAddress();
	    boolean there = false;

	    synchronized (inProgress) {

		there = (inProgress.get(syncTableKey) != null);

		if (!there) {
		    inProgress.put(syncTableKey, this);

		}
	    }

	    // Drop if we are processing it already.

	    if (there) {
		if (config.traceDrop()) {
		    config.writeLog("rh_rqst_in_progress",
				    new Object[] {clientAddr,
						      new Integer(port),
						      interfac});
		}
		return;

	    }

	    // We can simply cut to the chase and process the datagram
	    //  request.

	    DataInputStream dis =
		new DataInputStream(new ByteArrayInputStream(inbuf));
	    ByteArrayOutputStream baos = new ByteArrayOutputStream();

	    try {

		handleRequest(dis, baos, false);

		byte[] outbuf = baos.toByteArray();

		// Open a data output stream for the outgoing request. There
		//  is no buffer for reply or it is empty, the request was
		//  multicast and nothing was sent back.

		if (outbuf != null && outbuf.length > 0) {
		    sendDatagramReply(outbuf);

		}

	    } catch (IOException ex) {

		// No excuse for an EOF exception here.

		if (config.traceDrop()) {
		    config.writeLog("rh_datagram_ioe",
				    new Object[] {clientAddr,
						      new Integer(port),
						      interfac,
						      ex.getMessage()});

		}
	    }

	    // Remove the lock for this request. We do this just before the
	    //  run() method exits and the thread expires to reduce the
	    //  window in which a new copy of the request could come in.
	    //  We need to be sure that we only remove if it is this
	    //  request handler.

	    synchronized (inProgress) {
		RequestHandler rh =
		    (RequestHandler)inProgress.get(syncTableKey);

		if (rh == this) {
		    inProgress.remove(syncTableKey);

		}

	    }

	}

    }

    // Handle an incoming stream.

    private void handleStream() {

	try {

	    DataInputStream dis = null;
	    DataOutputStream dos = null;

	    if (inStream != null) {
		dis = new DataInputStream(inStream);
		dos = new DataOutputStream(outStream);
	    } else {
		// use the socket

		dis = new DataInputStream(sock.getInputStream());
		dos = new DataOutputStream(sock.getOutputStream());
	    }

	    // Loop while the client still wants to send something. But we
	    //  only read one SLP message at a time on the connection,
	    //  returning if it there are no more bytes to read. Note that
	    //  we have to use a do/while loop here so that the read hangs
	    //  until something shows up.

	    do {

		// Handle the new request.

		ByteArrayOutputStream baos = new ByteArrayOutputStream();

		boolean parseError = handleRequest(dis, baos, true);

		dos.write(baos.toByteArray(), 0, baos.size());

		// Forward reg or dereg to foreign DAs that need to know
		//  about it.

		if (toForward != null) {

		    try {
			daTable.forwardSAMessage(toForward, clientAddr);
			toForward = null;

		    } catch (ServiceLocationException ex) {
			config.writeLog("sa_forwarding_exception",
					new Object[] {
			    new Short(ex.getErrorCode()),
				Integer.toHexString(toForward.getHeader().xid),
				ex.getMessage()});
		    }
		}

		// If there was a parse error, then break out and close the
		//  stream, because it may have lingering bytes.

		if (parseError && config.traceMsg()) {

		    config.writeLog("rh_tcp_error",
				    new Object[] {clientAddr,
						      new Integer(port),
						      interfac});

		    break;

		}

	    } while (true);

	} catch (EOFException ex) {

	    if (config.traceMsg()) {
		config.writeLog("rh_socket_closed",
				new Object[] {clientAddr,
						  new Integer(port),
						  interfac});
	    }


	} catch (IOException ex) {

	    // An error occured during input.

	    if (config.traceDrop()) {
		config.writeLog("ioexception_server_stream",
				new Object[] {clientAddr,
						  new Integer(port),
						  interfac,
						  ex.getMessage()});
	    }

	}
    }

    // Send a byte buffer reply through a datagram socket.

    private void sendDatagramReply(byte[] outbuf) {

	DatagramSocket ds = null;

	try {

	    // Open the socket.

	    ds = new DatagramSocket();

	    // Format the outgoing packet.

	    DatagramPacket dpOut =
		new DatagramPacket(outbuf, outbuf.length, clientAddr, port);

	    // Send the reply.

	    ds.send(dpOut);

	    // Forward reg or dereg to foreign DAs that need to know about it.

	    if (toForward != null) {

		try {
		    daTable.forwardSAMessage(toForward, clientAddr);
		    toForward = null;

		} catch (ServiceLocationException ex) {
		    config.writeLog("sle_forward_error",
			  new Object[] {
			new Integer(ex.getErrorCode()),
			    Integer.toHexString(toForward.getHeader().xid),
			    ex.getMessage()});
		}
	    }

	} catch (SocketException ex) {

	    // Failure in reply.

	    if (config.traceDrop()) {
		config.writeLog("rh_socket_error",
				new Object[] {clientAddr,
						  new Integer(port),
						  interfac,
						  ex.getMessage()});
	    }
	} catch (IOException ex) {

	    // Failure in reply.

	    if (config.traceDrop()) {
		config.writeLog(
				"rh_ioexception_reply",
				new Object[] {clientAddr,
						  new Integer(port),
						  interfac,
						  ex.getMessage()});
	    }

	} finally {

	    if (ds != null) {
		ds.close();

	    }

	}

    }

    // Handle an incoming stream containing an SLP request.

    private boolean
	handleRequest(DataInputStream dis,
		      ByteArrayOutputStream baos,
		      boolean isTCP)
	throws IOException {

	boolean parseError = false;

	// Decode the message.

	SrvLocMsg msg = internalize(dis, isTCP);

	// If there was an error converting the request, then don't
	// process further.

	SrvLocMsg rply = msg;

	if (msg != null) {
	    SrvLocHeader hdr = msg.getHeader();

	    if (hdr.errCode == ServiceLocationException.OK) {

		if (config.traceMsg()) {
		    config.writeLog("rh_rqst_in",
				    new Object[] {Integer.toHexString(hdr.xid),
						      clientAddr,
						      new Integer(port),
						      interfac,
						      msg.getHeader()});
		}


		// Dispatch the message to the service table.

		rply = dispatch(msg);

		// If no reply, then simply return.

		if (rply == null) {

		    if (config.traceMsg()) {
			config.writeLog("rh_rply_null",
					new Object[] {
			    Integer.toHexString(hdr.xid),
				clientAddr,
				new Integer(port),
				interfac});

		    }

		    return parseError;

		}
	    } else {

		// Drop if multicast.

		if (msg.getHeader().mcast) {
		    rply = null;

		    if (config.traceDrop()) {
			config.writeLog("rh_multi_error",
					new Object[] {
			    msg.getClass().getName(),
				Integer.toHexString(hdr.xid),
				clientAddr,
				new Integer(port),
				interfac});


		    }
		} else if (isTCP) {

		    // Set the parse error flag so that the stream gets closed.
		    //  It's easier than trying to keep track of the number of
		    //  bytes read. Otherwise, the remnents of the message
		    //  hang around.

		    parseError = true;

		}
	    }
	}

	// Reply to the client if necessary. Note that if the reply is null
	//  here, there was a problem parsing the message in and so formulating
	//  a reply may be impossible (for example, the message may not
	//  be parsable beyond the function code.

	if (rply != null) {
	    SrvLocHeader hdr = rply.getHeader();
	    ServiceLocationException ex = null;

	    // Parse out the message.

	    try {
		hdr.externalize(baos, false, isTCP);
	    } catch (ServiceLocationException sle) {
		ex = sle;
	    }

	    if (config.traceMsg()) {
		config.writeLog("rh_rply_out",
				new Object[] {Integer.toHexString(hdr.xid),
						  clientAddr,
						  new Integer(port),
						  interfac,
						  rply.getHeader()});
	    }

	    if (ex != null) {
		baos.reset();
		rply = hdr.makeErrorReply(ex);

		Assert.slpassert(msg != null,
			      "rh_header_class_error",
			      new Object[] {ex.getMessage()});

		hdr = rply.getHeader();

		try {
		    hdr.externalize(baos, false, isTCP);

		} catch (ServiceLocationException exx) {

		}
	    }
	} else if (config.traceMsg()) {

	    // Print error message.

	    String xidStr = "<null message>";

	    if (msg != null) {
		SrvLocHeader hdr = msg.getHeader();
		xidStr = Integer.toHexString(hdr.xid);

	    }

	    config.writeLog("rh_rply_null",
			    new Object[] {xidStr,
					      clientAddr,
					      new Integer(port),
					      interfac});
	}

	return parseError;
    }

    /**
     * Internalize the byte array in the input stream into a SrvLocMsg
     * subclass. It will be an appropriate subclass for the SA/DA.
     *
     * @param dis The input stream containing the packet.
     * @param viaTCP True if the outgoing stream is via TCP.
     * @return The right SrvLocMsg subclass appropriate for the SA/DA.
     *		If null is returned, it means that the function code was
     *		not recognized.
     *		If any error occurs during creation, an error request is
     *		returned with the error code set.
     */

    private SrvLocMsg
	internalize(DataInputStream dis, boolean viaTCP) throws IOException {

	int ver = 0, fun = 0;

	Assert.slpassert((dis != null),
		      "rh_null_bais",
		      new Object[0]);

	try {

	    // Pull off the version number and function code.

	    byte[] b = new byte[2];

	    dis.readFully(b, 0, 2);

	    ver = (int) ((char)b[0] & 0XFF);
	    fun = (int) ((char)b[1] & 0XFF);

	} catch (IOException ex) {

	    // Print an error message, but only if not EOF.

	    if (!(ex instanceof EOFException)) {
		printInternalizeErrorMessage(ver, fun, ex);

	    }

	    // Throw the exception, so streams can terminate.

	    throw ex;

	}

	SrvLocMsg msg = null;
	SrvLocHeader hdr = null;

	try {

	    hdr = SrvLocHeader.newInstance(ver);

	    // Unrecognized version number if header not returned.
	    //  We only throw an exception if the version number
	    //  is greater than the current default version number.
	    //  otherwise, the packet is from an earlier version
	    //  of the protocol and should be ignored if we are
	    //  not operating in compatibility mode.

	    if (hdr == null) {

		if (ver > Defaults.version ||
		    (config.isV1Supported() && config.isDA())) {
							// code problem...
		    throw
			new ServiceLocationException(
				ServiceLocationException.VERSION_NOT_SUPPORTED,
				"rh_version_number_error",
				new Object[] {new Integer(ver),
						  clientAddr,
						  new Integer(port),
						  interfac});
		} else {
		    return null;

		}
	    }

	    // If we've come via TCP, clear the packet length so the
	    //  eventual reply won't be checked for overflow.

	    if (viaTCP) {
		hdr.setPacketLength(Integer.MAX_VALUE);

	    }

	    // Parse the header.

	    hdr.parseHeader(fun, dis);

	    // Parse body.

	    if ((msg = hdr.parseMsg(dis)) != null) {

		// Parse options, if any.

		hdr.parseOptions(dis);

	    }

	} catch (Exception ex) {

	    printInternalizeErrorMessage(ver, fun, ex);

	    msg = null;

	    // If this is a DAAdvert or an SAAdvert, or there's no header,
	    //  return null cause we don't need to return anything or
	    //  can't.

	    if (fun != SrvLocHeader.DAAdvert &&
		fun != SrvLocHeader.SAAdvert &&
		hdr != null) {

		// Let header create message.

		msg = hdr.makeErrorReply(ex);

	    }

	}

	return msg;
    }

    // Print an error message for errors during internalization.

    private void printInternalizeErrorMessage(int ver, int fun, Exception ex) {

	if (config.traceDrop()) {

	    StringWriter sw = new StringWriter();
	    PrintWriter pw = new PrintWriter(sw);

	    ex.printStackTrace(pw);

	    short errCode = ServiceLocationException.INTERNAL_SYSTEM_ERROR;

	    if (ex instanceof ServiceLocationException) {
		errCode = ((ServiceLocationException)ex).getErrorCode();

	    } else if (ex instanceof IllegalArgumentException) {
		errCode = ServiceLocationException.PARSE_ERROR;

	    }

	    String exMsg = "(" + errCode + "):" + ex.getMessage();

	    config.writeLog("rh_unparse_exception",
			    new Object[] {clientAddr,
					      new Integer(port),
					      interfac,
					      new Integer(ver),
					      new Integer(fun),
					      exMsg,
					      sw.toString()});
	}
    }

    /**
     * Dispatch the service request object to the service table.
     * The SA table is used for the following:
     *
     * @param rqst Service request object.
     * @return A SrvLocMsg object to reply with, or null if no reply.
     */

    SrvLocMsg dispatch(SrvLocMsg rqst) {

	SrvLocHeader hdr = rqst.getHeader();
	boolean mcast = hdr.mcast;

	// Check CDAAdvert and CSAAdvert before we check the previous
	//  responders list, because they don't have any.

	if (rqst instanceof CDAAdvert) {  // DA advert...
	    CDAAdvert msg = (CDAAdvert)rqst;

	    // For V1, V2 messages know.

	    msg.setIsUnsolicited(true);

	    // If passive detection is off, ignore it, but only if it wasn't
	    //  a signal to stop.

	    if (!config.passiveDADetection() &&
		msg.isUnsolicited() &&
		!msg.isGoingDown()) {
		if (config.traceDrop()) {
		    config.writeLog("rh_passive_drop",
				    new Object[] {msg.URL,
						      hdr.scopes});

		}

	    } else if (msg.isGoingDown() && msg.isUnsolicited() &&
		       isLocalHostURL(msg.URL) && config.isDA()) {

		// We've been asked to terminate.

		// Check scopes.

		Vector scopes = (Vector)hdr.scopes.clone();

		DATable.filterScopes(scopes,
				     config.getSAConfiguredScopes(), true);

		// If all scopes not equal, it isn't a shutdown message for us.

		if (scopes.size() > 0) {
		    daTable.handleAdvertIn(msg);

		} else {

		    Vector discoveredScopes = new Vector();

		    try {
			discoveredScopes = daTable.findScopes();

		    } catch (ServiceLocationException ex) {

			// Ignore, we're going down anyway and it's
			// just a report.

		    }

		    // It is a shutdown message for us.

		    Vector serverScopes = config.getSAConfiguredScopes();
		    Vector interfaces = config.getInterfaces();
		    Vector daAttributes = config.getDAAttributes();

		    if (config.traceAll() ||
			config.traceMsg() ||
			config.traceDrop() ||
			config.traceDATraffic()) {

			config.writeLog("goodby_da",
					new Object[] {interfaces,
							  serverScopes,
							  discoveredScopes,
							  daAttributes});
		    }


		    // We don't reply, which means that the client will
		    // time out.

		    System.exit(0);

		}
	    } else {

		// The implementation specific DA table handles this.

		daTable.handleAdvertIn(msg);

	    }

	    return null;

	} else if (rqst instanceof CSAAdvert) {// SA advert...
	    CSAAdvert msg = (CSAAdvert)rqst;

	    // We are only interested in it if we may be going down.

	    if ((hdr.xid == 0) && isLocalHostURL(msg.URL) && !config.isDA()) {

		// Check scopes.

		Vector scopes = (Vector)hdr.scopes.clone();

		DATable.filterScopes(scopes,
				     config.getSAConfiguredScopes(), true);

		// If all scopes not equal, it isn't a shutdown message for us.

		if (scopes.size() <= 0) {

		    Vector discoveredScopes = new Vector();

		    try {
			discoveredScopes = daTable.findScopes();

		    } catch (ServiceLocationException ex) {

			// Ignore, we're going down anyway and it's just a
			// report.

		    }

		    // It is a shutdown message for us.

		    Vector serverScopes = config.getSAConfiguredScopes();
		    Vector interfaces = config.getInterfaces();
		    Vector saAttributes = config.getSAAttributes();

		    if (config.traceAll() ||
			config.traceMsg() ||
			config.traceDrop() ||
			config.traceDATraffic()) {

			config.writeLog("goodby",
					new Object[] {interfaces,
							  serverScopes,
							  discoveredScopes,
							  saAttributes});
		    }

		    System.exit(0);
		}
	    }

	    // Otherwise, drop it for now.

	    if (config.traceDrop()) {
		config.writeLog("rh_client_sa_advert_drop",
				new Object[] {Integer.toHexString(hdr.xid),
						  clientAddr,
						  new Integer(port),
						  interfac});
	    }

	    return null;

	}

	if (rqst instanceof SSrvReg) { // registration...

	    return dispatchReg((SSrvReg)rqst,
			       serviceTable);

	} else if (rqst instanceof SSrvDereg) { // deregistration...

	    return dispatchDereg((SSrvDereg)rqst,
				 serviceTable);

	}


	// If we are on the previous responder list, then ignore this
	//  request.

	if (isPreviousResponder(hdr)) {

	    if (config.traceDrop()) {
		config.writeLog("rh_prev_resp",
				new Object[] {Integer.toHexString(hdr.xid),
						  clientAddr,
						  new Integer(port),
						  interfac});
	    }

	    return null;

	}

	// Now check requests with previous responders.

	if (rqst instanceof SSrvTypeMsg) {	// service types...

	    return dispatchSrvType((SSrvTypeMsg)rqst,
				   serviceTable);

	} else if (rqst instanceof SAttrMsg) { // attributes...

	    return dispatchAttr((SAttrMsg)rqst,
				serviceTable);

	} else if (rqst instanceof SSrvMsg) { // services...

	    return dispatchSrv((SSrvMsg)rqst,
			       serviceTable);

	} else {				    // error...

	    Assert.slpassert(false,
			  "rh_rqst_type_err",
			  new Object[] {rqst});

	}

	return null;

    }


    // Dispatch a service registration.

    private SrvLocMsg dispatchReg(SSrvReg rqst,
				  ServiceTable serviceTable) {

	SrvLocHeader hdr = rqst.getHeader();

	// Report error if the message was multicast.

	if (hdr.mcast && config.traceDrop()) {

	    if (config.traceDrop()) {
		config.writeLog("rh_no_multi",
				new Object[] {"SrvReg",
						  Integer.toHexString(hdr.xid),
						  clientAddr,
						  new Integer(port),
						  interfac});
	    }

	    return null;

	}

	// Register the request.

	SrvLocMsg rply = serviceTable.register(rqst);

	// Forward to foreign DAs if no error.

	if (rply != null) {
	    hdr = rply.getHeader();

	    if (hdr.errCode == ServiceLocationException.OK) {
		toForward = rqst;

	    }
	}

	return rply;
    }

    // Dispatch a service deregistration.

    private SrvLocMsg dispatchDereg(SSrvDereg rqst,
				    ServiceTable serviceTable) {

	SrvLocHeader hdr = rqst.getHeader();

	// Report error if the message was multicast.

	if (hdr.mcast && config.traceDrop()) {

	    if (config.traceDrop()) {
		config.writeLog("rh_no_multi",
				new Object[] {"SrvDereg",
						  Integer.toHexString(hdr.xid),
						  clientAddr,
						  new Integer(port),
						  interfac});
	    }

	    return null;

	}

	// If the message came from the local host, use the SA store.

	SrvLocMsg rply = serviceTable.deregister(rqst);

	// Forward to foreign DAs if no error.

	if (rply != null) {
	    hdr = rply.getHeader();

	    if (hdr.errCode == ServiceLocationException.OK) {
		toForward = rqst;

	    }
	}

	return rply;
    }

    // Dispatch a service type message.

    private SrvLocMsg dispatchSrvType(SSrvTypeMsg rqst,
				      ServiceTable serviceTable) {

	SrvLocHeader hdr = rqst.getHeader();
	boolean mcast = hdr.mcast;

	// Drop if this is a DA and the request was multicast. DAs
	//  do not respond to multicast, except for DAAdverts.

	if (mcast && config.isDA()) {

	    if (config.traceDrop()) {
		config.writeLog("rh_drop_da_multi",
				new Object[] {"SrvTypeRqst",
						  Integer.toHexString(hdr.xid),
						  clientAddr,
						  new Integer(port),
						  interfac});
	    }

	    return null;

	}

	SrvLocMsg rply = serviceTable.findServiceTypes(rqst);
	hdr = rply.getHeader();

	// Filter multicast replies to remove null and error returns.

	if (mcast &&
	    ((hdr.errCode != ServiceLocationException.OK) ||
	    (hdr.getNumReplies() == 0))) {

	    if (config.traceDrop()) {
		config.writeLog("rh_multi_error",
				new Object[] {"SrvTypeRqst",
						  Integer.toHexString(hdr.xid),
						  clientAddr,
						  new Integer(port),
						  interfac});


	    }

	    return null;

	}

	return rply;
    }

    // Dispatch an attribute request.

    private SrvLocMsg dispatchAttr(SAttrMsg rqst,
				   ServiceTable serviceTable) {

	SrvLocHeader hdr = rqst.getHeader();
	boolean mcast = hdr.mcast;

	// Drop if this is a DA and the request was multicast. DAs
	//  do not respond to multicast, except for DAAdverts.

	if (mcast && config.isDA()) {

	    if (config.traceDrop()) {
		config.writeLog("rh_drop_da_multi",
				new Object[] {"AttrRqst",
						  Integer.toHexString(hdr.xid),
						  clientAddr,
						  new Integer(port),
						  interfac});
	    }

	    return null;

	}

	SrvLocMsg rply = serviceTable.findAttributes(rqst);
	hdr = rply.getHeader();

	// Filter multicast replies to remove null and error returns.

	if (mcast &&
	    ((hdr.errCode != ServiceLocationException.OK) ||
	    (hdr.getNumReplies() == 0))) {

	    if (config.traceDrop()) {
		config.writeLog("rh_multi_error",
				new Object[] {"AttrRqst",
						  Integer.toHexString(hdr.xid),
						  clientAddr,
						  new Integer(port),
						  interfac});

	    }

	    return null;

	}

	return rply;
    }

    // Dispatch a service request.

    private SrvLocMsg dispatchSrv(SSrvMsg rqst,
				  ServiceTable serviceTable) {

	SrvLocHeader hdr = rqst.getHeader();
	boolean mcast = hdr.mcast;
	String serviceType = rqst.serviceType;
	SrvLocMsg rply = null;

	// We need to special case if this is a request for a DAAdvert
	//  and we are a DA or an SAAdvert and we are an SA only.

	if (serviceType.equals(Defaults.DA_SERVICE_TYPE.toString())) {

	    // Reply only if a DA.

	    if (config.isDA()) {


		// Return a DAAdvert for this DA.

		rply = serviceTable.makeDAAdvert(rqst,
						 interfac,
						 config);

		hdr = rply.getHeader();

		if ((hdr.errCode != ServiceLocationException.OK) &&
		    config.traceMsg()) {
		    config.writeLog("rh_advert_error",
				    new Object[] { new Integer(hdr.errCode),
						       "DAAdvert",
						       ""});

		}
	    }

	    // If there was an error and the request was multicast, drop it
	    //  by returning null.

	    if (hdr.errCode != ServiceLocationException.OK &&
		mcast) {

		if (config.traceDrop()) {

		    config.writeLog("rh_drop_srv",
				    new Object[] {
			"DA SrvRqst",
			    Integer.toHexString(hdr.xid),
			    clientAddr,
			    new Integer(port),
			    interfac});

		}

		return null;

	    }

	    return rply;

	} else if (serviceType.equals(Defaults.SA_SERVICE_TYPE.toString())) {

	    // Note that we reply if we are a DA because somebody may want
	    //  SA attributes.

	    // We report error for unicast SA service request.

	    if (!mcast) {

		if (config.traceDrop()) {

		    config.writeLog("rh_no_srv_uni",
				    new Object[] {
			"SA SrvRqst",
			    Integer.toHexString(hdr.xid),
			    clientAddr,
			    new Integer(port),
			    interfac});

		}

		return null;

	    }

	    // Return a SAAdvert for this SA.

	    try {
		rply = serviceTable.makeSAAdvert(rqst,
						 interfac,
						 config);

	    } catch (ServiceLocationException ex) {
		config.writeLog("rh_advert_error",
				new Object [] {new Integer(ex.getErrorCode()),
						   "SAAdvert",
						   ex.getMessage()});

	    }


	    if (rply == null && config.traceDrop()) {

		config.writeLog("rh_drop_srv",
				new Object[] {"SA SrvRqst",
						  Integer.toHexString(hdr.xid),
						  clientAddr,
						  new Integer(port),
						  interfac});

	    }

	    return rply;

	}

	// Drop if this is a DA and the request was multicast. DAs
	//  do not respond to multicast, except for DAAdverts.

	if (mcast && config.isDA()) {

	    if (config.traceDrop()) {
		config.writeLog("rh_drop_da_multi",
				new Object[] {"SrvRqst",
						  Integer.toHexString(hdr.xid),
						  clientAddr,
						  new Integer(port),
						  interfac});
	    }

	    return null;

	}

	SrvLocMsg smrply = serviceTable.findServices(rqst);
	hdr = smrply.getHeader();

	// Filter multicast replies to remove null and error returns.

	if (mcast &&
	    ((hdr.errCode != ServiceLocationException.OK) ||
	    (hdr.getNumReplies() == 0))) {

	    if (config.traceDrop()) {
		config.writeLog("rh_multi_error",
				new Object[] {"SrvRqst",
						  Integer.toHexString(hdr.xid),
						  clientAddr,
						  new Integer(port),
						  interfac});

	    }

	    return null;

	}

	return smrply;
    }

    // Return true if the host address matches one of the local interfaces.

    boolean isLocalHostURL(ServiceURL url) {
	String hostAddr = url.getHost();
	Vector interfaces = config.getInterfaces();
	InetAddress addr = null;

	try {
	    addr = InetAddress.getByName(hostAddr);

	} catch (UnknownHostException ex) {

	    // We simply ignore it.

	    return false;

	}

	if (interfaces.contains(addr)) {
	    return true;

	}

	return false;
    }

    /**
     * Return whether this was previous responder. Only do so if the
     * request was multicast.
     *
     * @return True if this host was a previous responder.
     */

    public boolean isPreviousResponder(SrvLocHeader hdr) {

	// If there are no previous responders, then return false,
	//  because they aren't used for this message. Also for
	//  messages that are not multicast.

	if ((hdr.previousResponders == null) ||
	    (hdr.mcast == false)) {
	    return false;

	}

	Vector previousResponders = hdr.previousResponders;
	Enumeration e = null;
	Vector interfaces = config.getInterfaces();

	// Check for matches against this address.

	for (e = previousResponders.elements(); e.hasMoreElements(); ) {
	    try {
		String sHost = ((String)e.nextElement());
		InetAddress iaHost = InetAddress.getByName(sHost);

		if (interfaces.contains(iaHost)) {
		    return true;
		}

	    } catch (UnknownHostException ex) {

	    }
	}

	return false;
    }


    // Initialize the SLPv2 header parser class when we are loaded.

    static {

	SrvLocHeader.addHeaderClass(Defaults.DEFAULT_SERVER_HEADER_CLASS,
				    Defaults.version);

    }

}
