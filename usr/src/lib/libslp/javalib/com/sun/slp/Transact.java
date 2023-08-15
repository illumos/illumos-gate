/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * ident	"%Z%%M%	%I%	%E% SMI"
 *
 * Copyright 1999-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 */

//  Transact.java:    Low level details of performing an SLP
//                    network transaction.

package com.sun.slp;

import java.util.*;
import java.net.*;
import java.io.*;

/**
 * Transact performs the low level details for transacting an SLP network
 * query. Note that, in the future, this class may spin separate threads
 * for DA requests as well.
 */

class Transact extends Object implements Runnable {

    // Cache of open TCP sockets.

    private static final Hashtable TCPSocketCache = new Hashtable();

    // SLP config object.

    protected static SLPConfig config = null;

    // Message to send.

    protected SrvLocMsg msgOut = null;

    // Vector of return values.

    protected Vector returns = null;

    // Timeout for multicast convergence. Varies if it's DA discovery or
    //  request multicast.

    protected int[] MSTimeouts;

    // Maximum results desired for multicast.

    protected int maxResults = 0;

    // Exception to throw.

    protected ServiceLocationException exErr = null;

    // Multicast address to use.

    protected InetAddress address = null;

    // If this is true, continue multicast after the first set of stuff
    //  is found. Exit when three tries have happened without finding
    //  anything.

    boolean continueAfterFound = false;

    /**
     * Perform a query to the SLP network. The multicast query is performed
     * in a separate thread for performance reasons. DAs having the
     * same scope set are queried until one answers. These DAs form
     * an equivalence class.
     *
     * @param daEquivClasses Vector of DATable.DARecord objects in the
     *			  same equivalence clase w.r.t. scopes.
     * @param uniMsg A unicast message to send.
     * @param multiMsg A multicast message to send.
     * @param address Multicast address to use.
     * @return Vector of SrvLocMsg objects with results.
     */

    static Vector
	transactUA(Vector daEquivClasses,
		   SrvLocMsg uniMsg,
		   SrvLocMsg multiMsg,
		   InetAddress address)
	throws ServiceLocationException {

	// If we need to multicast, then start the multicast thread.

	Vector ret = new Vector();
	Thread multiThread = null;
	Transact tracon = null;

	if (multiMsg != null) {

	    // Create a new Transact multicast thread.

            // The final argument to the constructor of Transact determines
            // whether to return after the first result or to continue to
            // gather more than one result.  The value to this field
            // continueAfterFound MUST be set to 'true' or else multicast
            // based discovery will find the first result, not all results,
            // as it should.
	    tracon =
		new Transact(multiMsg,
			     ret,
			     config.getMulticastTimeouts(),
			     config.getMaximumResults(),
			     address,
			     true);  // continueAfterFound

	    multiThread = new Thread(tracon);

	    // Run it.

	    multiThread.start();

	}

	// Go through the msgTable doing all the DAs.

	ServiceLocationException exx = null;

	if (daEquivClasses != null) {
	    exx =
		transactUnicastMsg(daEquivClasses,
				   uniMsg,
				   ret,
				   config.getMaximumResults());

	}

	// Wait until the TransactConverge thread is done, if necessary.

	if (multiThread != null) {

	    try {
		multiThread.join();

	    } catch (InterruptedException ex) {

	    }

	}

	// If there was a problem in either the multicast thread or in
	//  the unicast call, throw an exception, but *only* if no
	//  results came back.

	if (ret.size() <= 0) {

	    if (exx != null) {
		short err = exx.getErrorCode();

		if (err != ServiceLocationException.VERSION_NOT_SUPPORTED &&
		    err != ServiceLocationException.INTERNAL_ERROR &&
		    err != ServiceLocationException.OPTION_NOT_SUPPORTED &&
		    err != ServiceLocationException.REQUEST_NOT_SUPPORTED) {
		    throw exx;

		}

	    }

	    if (tracon != null && tracon.exErr != null) {
		short err = tracon.exErr.getErrorCode();

		if (err != ServiceLocationException.VERSION_NOT_SUPPORTED &&
		    err != ServiceLocationException.INTERNAL_ERROR &&
		    err != ServiceLocationException.OPTION_NOT_SUPPORTED &&
		    err != ServiceLocationException.REQUEST_NOT_SUPPORTED) {
		    throw tracon.exErr;

		}
	    }
	}


	// Return the result to the client.

	return ret;

    }

    /**
     * Transact a message with DAs. Put the returned SrvLocMsg
     * object into the Vector ret.
     *
     * @param daEquivClasses Vector of DATable.DARecord objects in the
     *			   same equivalence clase w.r.t. scopes.
     * @param msg SrvLocMsg Message to send.
     * @param ret Vector for returns.
     * @param maxResults Maximum results expected.
     * @return A ServiceLocationException object if an exception occured.
     * @exception ServiceLocationException
     *            If results cannot be obtained in the timeout interval
     *            specified in the 'config.' or
     *            If networking resources cannot be obtained or used
     *            effectively.
     */
    static ServiceLocationException
	transactUnicastMsg(Vector daEquivClasses,
			   SrvLocMsg msg,
			   Vector ret,
			   int maxResults) {

	// Get the config object if we need it.

	if (config == null) {
	    config = SLPConfig.getSLPConfig();

	}

	DatagramSocket ds = null;
	int i, n = daEquivClasses.size();
	ServiceLocationException exx = null;
	InetAddress addr = null;
	int numReplies = 0;
	DATable daTable = DATable.getDATable();

	try {

	    // Go through the DA address equivalence classes we need
	    //  to query.

	    for (i = 0; i < n && numReplies < maxResults; i++) {

		DATable.DARecord rec =
		    (DATable.DARecord)daEquivClasses.elementAt(i);
		Vector daAddresses = (Vector)rec.daAddresses.clone();

		// Get a new outgoing socket.

		if (ds == null) {
		    ds = new DatagramSocket();

		}

		// Go through the DA addresses until we get a reply from one.

		Enumeration en = daAddresses.elements();
		SrvLocHeader mhdr = msg.getHeader();

		while (en.hasMoreElements()) {

		    try {

			addr = (InetAddress)en.nextElement();

			if (config.traceDATraffic()) {
			    config.writeLog("sending_da_trace",
					    new Object[] {
				Integer.toHexString(mhdr.xid),
				    addr});

			}

			// Get the reply message if any.

			SrvLocMsg rply = transactDatagramMsg(ds, addr, msg);

			if (!filterRply(msg, rply, addr)) {
			    continue;

			}

			SrvLocHeader rhdr = rply.getHeader();

			if (config.traceDATraffic()) {
			    config.writeLog("reply_da_trace",
					    new Object[] {
				Integer.toHexString(rhdr.xid),
				    addr});

			}

			// If overflow, try TCP.

			if (rhdr.overflow) {
			    if (config.traceDATraffic()) {
				config.writeLog("tcp_send_da_trace",
						new Object[] {
				    Integer.toHexString(mhdr.xid),
					addr});

			    }

			    rply = transactTCPMsg(addr, msg, false);

			    if (config.traceDATraffic()) {
				config.writeLog("tcp_reply_da_trace",
						new Object[] {
				    (msg == null ? "<null>":
				     Integer.toHexString(mhdr.xid)),
					addr});

			    }

			    if (rply == null) {
				continue;

			    }

			}

			// Increment number of replies we received.

			SrvLocHeader hdr = rply.getHeader();

			numReplies += hdr.iNumReplies;

			// Add to return vector.

			ret.addElement(rply);

			// Break out of the loop, since we only need one in
			//  this equivalence class.

			break;

		    } catch (ServiceLocationException ex) {

			config.writeLog("da_exception_trace",
					new Object[] {
			    new Short(ex.getErrorCode()),
				addr,
				ex.getMessage()});

			// In case we are querying more than one DA, we
			// save th exception, returning it to the caller to
			// decide if it should be thrown. We ignore DA_BUSY,
			// though, since the DA may free up later.

			short errCode = ex.getErrorCode();

			if (errCode != ServiceLocationException.DA_BUSY) {
			    exx = ex;

			}

			// If the error code is NETWORK_TIMED_OUT, then remove
			//  this DA from the DA table. If it's just down
			//  temporarily, we'll get it next time we go to
			//  the server to get the DA addresses.

			if (errCode ==
			    ServiceLocationException.NETWORK_TIMED_OUT) {

			    if (config.traceDATraffic()) {
				config.writeLog("da_drop",
						new Object[] {
				    addr, rec.scopes});

			    }

			    daTable.removeDA(addr, rec.scopes);

			}
		    }
		}
	    }

	} catch (SocketException ex) {
	    exx =
		new ServiceLocationException(
				ServiceLocationException.NETWORK_ERROR,
				"socket_creation_failure",
				new Object[] {addr, ex.getMessage()});

	} finally {

	    // Clean up socket.

	    if (ds != null) {
		ds.close();
	    }
	}

	return exx;
    }

    /**
     * Transact a message via. UDP. Try a maximum of three times if
     * a timeout.
     *
     * @param ds The datagram socket to use.
     * @param addr The DA to contact.
     * @param msg The message to send.
     * @return The SrvLocMsg returned or null if none.
     * @exception ServiceLocationException Due to errors in parsing message.
     */

    static private SrvLocMsg
	transactDatagramMsg(DatagramSocket ds, InetAddress addr, SrvLocMsg msg)
	throws ServiceLocationException {

	SrvLocMsg rply = null;
	byte[] outbuf = getBytes(msg, false, false);
	byte[] inbuf = new byte[Defaults.iReadMaxMTU];

	// Construct the datagram packet to send.

	DatagramPacket dpReply =
	    new DatagramPacket(inbuf, inbuf.length);
	DatagramPacket dpRequest =
	    new DatagramPacket(outbuf, outbuf.length, addr, Defaults.iSLPPort);
	int[] timeouts = config.getDatagramTimeouts();

	// Resend for number of timeouts in timeout interval.

	int i;

	for (i = 0; i < timeouts.length; i++) {

	    // Catch timeout and IO errors.

	    try {

		ds.setSoTimeout(timeouts[i]);
		ds.send(dpRequest);
		ds.receive(dpReply);

		// Process result into a reply object.

		DataInputStream dis =
		    new DataInputStream(
			new ByteArrayInputStream(dpReply.getData()));

		rply = internalize(dis, addr);
		break;

	    } catch (InterruptedIOException ex) {

		// Did not get it on the first timeout, try again.

		if (config.traceDrop()|| config.traceDATraffic()) {
		    config.writeLog("udp_timeout",
				    new Object[] {addr});

		}

		continue;

	    } catch (IOException ex) {
		Object[] message = {addr, ex.getMessage()};

		if (config.traceDrop() || config.traceDATraffic()) {
		    config.writeLog("datagram_io_error",
				    message);

		}

		throw
		    new ServiceLocationException(
				ServiceLocationException.NETWORK_ERROR,
				"datagram_io_error",
				message);

	    }
	}

	// If nothing, then we've timed out. DAs with no matching
	//  info should at least return a reply.

	if (rply == null) {
	    throw
		new ServiceLocationException(
				ServiceLocationException.NETWORK_TIMED_OUT,
				"udp_timeout",
				new Object[] {addr});

	}

	return rply;
    }

    /**
     * Transact a message using TCP, since the reply was too big.
     * @parameter addr Address of the DA to contact.
     * @parameter msg  The message object to use.
     * @parameter cacheIt Cache socket, if new.
     * @return  The SrvLocMsg returned if any.
     * @exception ServiceLocationException
     *            If results cannot be obtained in the timeout interval
     *            specified in the 'config.'
     *            If networking resources cannot be obtained or used
     *            effectively.
     */

    static SrvLocMsg
	transactTCPMsg(InetAddress addr, SrvLocMsg msg, boolean cacheIt)
	throws ServiceLocationException {

	// Get the config object if we need it.

	if (config == null) {
	    config = SLPConfig.getSLPConfig();

	}

	SrvLocMsg rply = null;

	try {

	    // Transact the message, taking care of socket caching.

	    rply = transactMsg(addr, msg, cacheIt, true);

	} catch (InterruptedIOException ex) {
	    Object[] message = {addr};

	    if (config.traceDrop()|| config.traceDATraffic()) {
		config.writeLog("tcp_timeout",
				message);

	    }

	    throw
		new ServiceLocationException(
				ServiceLocationException.NETWORK_TIMED_OUT,
				"tcp_timeout",
				message);

	} catch (IOException ex) {
	    Object[] message = {addr, ex.getMessage()};

	    if (config.traceDrop() || config.traceDATraffic()) {
		config.writeLog("tcp_io_error",
				message);

	    }

	    throw
		new ServiceLocationException(
				ServiceLocationException.NETWORK_ERROR,
				"tcp_io_error",
				message);

	}

	// Filter reply for nulls, invalid xid.

	if (!filterRply(msg, rply, addr)) {
	    return null;

	}

	return rply;
    }

    // Uncache a socket.

    static private void uncacheSocket(InetAddress addr, Socket s) {

	try {

	    s.close();

	} catch (IOException ex) {

	}

	TCPSocketCache.remove(addr);

    }

    // Get a (possibly cached) TCP socket, cache it if cache is on.

    static private Socket getTCPSocket(InetAddress addr, boolean cacheIt)
	throws IOException {

	Socket s = null;

	// We use the cached socket if we've got it.

	s = (Socket)TCPSocketCache.get(addr);

	if (s == null) {
	    s = new Socket(addr, Defaults.iSLPPort);

	    // Set it so the socket will block for fixed timeout.

	    s.setSoTimeout(config.getTCPTimeout());

	}

	// We cache it if we're supposed to.

	if (cacheIt) {
	    TCPSocketCache.put(addr, s);

	}

	return s;
    }

    // Transact the message, using cached socket if necessary. Retry if
    //  flag is true.

    static private SrvLocMsg
	transactMsg(InetAddress addr,
		    SrvLocMsg msg,
		    boolean cacheIt,
		    boolean retry)
	throws InterruptedIOException, IOException, ServiceLocationException {

	Socket s = null;
	byte outbuf[] = getBytes(msg, false, true);

	try {

	    s = getTCPSocket(addr, cacheIt);

	    DataOutputStream dos = new DataOutputStream(s.getOutputStream());
	    DataInputStream dis = new DataInputStream(s.getInputStream());

	    // In case the server cuts us off...

	    try {

		// Only one thread at a time gets to use this socket, in case
		//  it was cached. Otherwise, we *may* get interleaved i/o.

		synchronized (s) {

		    // Send the request.

		    dos.write(outbuf, 0, outbuf.length);

		    // Read reply.

		    return internalize(dis, addr);

		}

	    } catch (IOException ex) {

		// Uncache it, get a new one. If that one doesn't work, we're
		//  hosed.

		uncacheSocket(addr, s);

		s = null;

		if (!retry) {
		    throw ex;

		}

		// Recursively call ourselves to take care of this, but
		//  don't retry it.

		return transactMsg(addr, msg, cacheIt, false);

	    }

	} finally {

	    if (s != null && !cacheIt) {
		uncacheSocket(addr, s);

	    }
	}
    }

    // Externalize the message into bytes.

    static protected byte[] getBytes(SrvLocMsg slm,
				     boolean isMulti,
				     boolean isTCP)
	throws ServiceLocationException {

	ByteArrayOutputStream baos = new ByteArrayOutputStream();
	SrvLocHeader hdr = slm.getHeader();

	hdr.externalize(baos, isMulti, isTCP);

	byte[] outbuf = baos.toByteArray();

	// Check if it excceds the output buffer length.

	if (hdr.overflow) {
	    throw
		new ServiceLocationException(
				ServiceLocationException.BUFFER_OVERFLOW,
				"buffer_overflow",
				new Object[] {
		    new Integer(outbuf.length),
			new Integer(config.getMTU())});
	}

	return outbuf;
    }

    // Filter the reply to make sure the xid matches and that it's not null.

    static protected boolean
	filterRply(SrvLocMsg msg, SrvLocMsg rply, InetAddress addr) {

	SrvLocHeader mhdr = msg.getHeader();
	SrvLocHeader rhdr = rply.getHeader();

	if (rply == null) {
	    if (config.traceDrop()) {
		config.writeLog("reply_unparsable",
				new Object[] {addr});

	    }

	    return false;

	}

	// Check for invalid xid.

	if (mhdr.xid != rhdr.xid) {
	    if (config.traceDrop()) {
		config.writeLog("wrong_xid",
				new Object[] {addr});

	    }
	    return false;

	}
	return true;

    }

    /**
     * Internalize the byte array in the input stream into a SrvLocMsg
     * subclass. It will be an appropriate subclass for the client agent.
     * If an exception comes out of this method, it is converted into
     * a SrvLocMsg with error code.
     *
     *
     * @param dis The input stream containing the packet.
     * @param addr The address of the replying agent (for error reporting).
     * @return The right SrvLocMsg subclass appropriate for the Client Agent.
     *		If null is returned, the function code wasn't recognized,
     *		and so it may be appropriate for another agent.
     * @exception ServiceLocationException If the character set was not valid
     *		or an error occured during parsing.
     * @exception IOException If DataInputStream throws it.
     */

    static protected SrvLocMsg internalize(DataInputStream dis,
					   InetAddress addr)
	throws ServiceLocationException {

	int ver = 0, fun = 0;
	SrvLocMsg msg = null;
	SrvLocHeader hdr = null;
	byte[] b = new byte[2];

	try {

	    dis.readFully(b, 0, 2);

	    ver = (int) ((char)b[0] & 0XFF);
	    fun = (int) ((char)b[1] & 0XFF);

	    // Unrecognized version number if header not returned.

	    if (ver != Defaults.version) {
		throw
		    new ServiceLocationException(
				ServiceLocationException.VERSION_NOT_SUPPORTED,
				"version_number_error",
				new Object[] {new Integer(ver)});

	    }

	    // Create the header. Note that we only need to create a
	    //  client side header here, because that is all that
	    //  will be expected by the client side code. Note that we
	    //  *can't* use the SrvLocHeader.newInstance() mechanism
	    //  because Transact lives in the server as well, and
	    //  SrvLocHeader can only handle one header class per
	    //  version.

	    hdr = new SLPHeaderV2();

	    // Parse header.

	    hdr.parseHeader(fun, dis);

	    // Parse body.

	    if ((msg = hdr.parseMsg(dis)) != null) {

		// Parse options, if any.

		hdr.parseOptions(dis);

	    }

	} catch (IllegalArgumentException ex) {

	    // During parsing, this can be thrown if syntax errors occur.

	    throw
		new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"passthrough_addr",
				new Object[] {ex.getMessage(), addr});

	} catch (IOException ex) {

	    // If version code is zero, then we suspect a network error,
	    //  otherwise, it is probably a parse error.

	    String fcode = (fun == 0 ? "???":Integer.toString(fun));
	    short exCode =
		(ver == 0 ? ServiceLocationException.NETWORK_ERROR:
		 ServiceLocationException.PARSE_ERROR);

	    // During parsing, this can be thrown if the message stream
	    //  is improperly formatted.

	    throw
		new ServiceLocationException(exCode,
					     "ioexception_parsing",
					     new Object[] {
		    ex, fcode, addr, ex.getMessage()});

	} catch (ServiceLocationException ex) {

	    // Add the address of the replying agent.

	    throw
		new ServiceLocationException(ex.getErrorCode(),
					     "passthrough_addr",
					     new Object[] {
		    ex.getMessage(), addr});

	}

	return msg;
    }

    // Send out the message.

    static protected void
	send(DatagramSocket ds, SrvLocMsg msg, InetAddress addr)
	throws ServiceLocationException, IOException {

	byte[] outbuf = getBytes(msg, true, false);
	DatagramPacket dpsend =
	    new DatagramPacket(outbuf, outbuf.length, addr, Defaults.iSLPPort);
	ds.send(dpsend);

    }

    // Check the response and add the previous responder if it is OK.

    static protected boolean
	addPreviousResponder(SrvLocMsg msg, InetAddress addr) {

	// Add incoming result to the vector.

	SrvLocHeader hdr = msg.getHeader();
	Vector v = hdr.previousResponders;
	String srcAddr = addr.getHostAddress();

	if (v.contains(srcAddr)) {	// the SRC ignored its PR list
	    if (config.traceDrop()) {
		config.writeLog("drop_pr",
				new Object[] {
		    srcAddr,
			Integer.toHexString(hdr.xid)});

	    }
	    return false;

	} else {
	    hdr.addPreviousResponder(addr);
	    return true;

	}
    }

    // Transact an active request for DA or SA adverts.

    static Vector transactActiveAdvertRequest(ServiceType type,
					      SrvLocMsg rqst,
					      ServerDATable daTable)
	throws ServiceLocationException {

	// Perform active advertisement.

	Vector ret = new Vector();
	Vector results = new Vector();

	// Create Transact object and start.

	Transact tran = new Transact(rqst,
				     results,
				     config.getMulticastTimeouts(),
				     Integer.MAX_VALUE, // config doesn't apply
				     config.getMulticastAddress(),
				     true);

	Thread multiThread = new Thread(tran);

	multiThread.start();

	// Wait until the TransactConverge thread is done, if necessary.

	try {
	    multiThread.join();

	} catch (InterruptedException ex) {

	}

	ServiceLocationException ex = tran.exErr;

	// Report error.

	if (ex != null && config.traceDATraffic()) {
	    config.writeLog("sdat_active_err",
			    new Object[] {new Integer(ex.getErrorCode()),
					      ex.getMessage()});

	    throw ex;

	}

	// Process the results.

	int i, n = results.size();

	for (i = 0; i < n; i++) {
	    Object msg = results.elementAt(i);

	    if ((type.equals(Defaults.DA_SERVICE_TYPE) &&
		!(msg instanceof CDAAdvert)) ||
		(type.equals(Defaults.SA_SERVICE_TYPE) &&
		!(msg instanceof CSAAdvert))) {

		if (config.traceDrop()) {
		    config.writeLog("sdat_nonadvert_err",
				    new Object[] {
			msg});

		}

		continue;
	    }

	    // Let DA table handle it if it`s a DAAdvert.

	    if (type.equals(Defaults.DA_SERVICE_TYPE)) {
		CDAAdvert advert = (CDAAdvert)msg;

		daTable.handleAdvertIn(advert);

	    } else {

		// Add scopes from the SAAdvert if not already there.

		SrvLocHeader hdr = ((SrvLocMsg)msg).getHeader();

		int j, m = hdr.scopes.size();

		for (j = 0; j < m; j++) {
		    Object o = hdr.scopes.elementAt(j);

		    if (!ret.contains(o)) {
			ret.addElement(o);

		    }
		}
	    }
	}

	return ret;
    }

    // Construct a Transact object to run a convergence transaction in
    //  a separate thread.

    Transact(SrvLocMsg msg,
	     Vector ret,
	     int[] msT,
	     int mResults,
	     InetAddress address,
	     boolean continueAfterFound) {

	msgOut = msg;
	returns = ret;
	MSTimeouts = msT;
	maxResults = mResults;
	this.address = address;
	this.continueAfterFound = continueAfterFound;
    }

    // Run the multicast convergence algorithm.

    public void run() {

	Exception xes = null;
	DatagramSocket ds = null;

	// Get the config object if we need it.

	if (config == null) {
	    config = SLPConfig.getSLPConfig();

	}

	// Set thread name.

	if (config.isBroadcastOnly()) {
	    Thread.currentThread().setName("SLP Broadcast Transact");
	    address = config.getBroadcastAddress();

	} else {
	    Thread.currentThread().setName("SLP Multicast Transact");

	}

	try {

	    // Multicast out on the default interface only.

	    ds = config.getMulticastSocketOnInterface(config.getLocalHost(),
						      true);

	    // Perform convergence.

	    transactConvergeMsg(address,
				ds,
				msgOut,
				returns,
				MSTimeouts,
				maxResults,
				continueAfterFound);

	    ds.close();

	    ds = null;

	} catch (ServiceLocationException ex) {

	    // Ignore DA_BUSY, the DA may free up later.

	    if (ex.getErrorCode() != ServiceLocationException.DA_BUSY) {
		exErr = ex;
		xes = ex;

	    }

	} catch (Exception ex) {

	    // Create new exception to be thrown.

	    xes = ex;
	    exErr = new ServiceLocationException(
				ServiceLocationException.INTERNAL_SYSTEM_ERROR,
				"passthrough",
				new Object[] {ex.getMessage()});

	} finally {

	    // Close the socket if it's been opened.

	    if (ds != null) {
		ds.close();

	    }
	}

	// Log any errors.

	if (xes != null) {
	    StringWriter sw = new StringWriter();
	    PrintWriter pw = new PrintWriter(sw);

	    xes.printStackTrace(pw);
	    pw.flush();

	    config.writeLog("multicast_error",
			    new Object[] {xes.getMessage(),
					      sw.toString()});

	}
    }

    /**
     * Send the message using multicast and use convergence to gather the
     * results. Note that this routine must be synchronized because
     * only one multicast can be active at a time; othewise, the client
     * may get back an unexpected result. However, there can be many unicast
     * requests active along with a multicast request, hence the separate
     * thread for multicast.
     *
     * The subtlety of the timing routine is that it will only resend the
     * message when one of the multicast convergence timeout intervals
     * elapses.  Further, for efficiency, it will give up after a complete
     * interval has gone by without receiving any results.  This may mean
     * that the intervals have to be extended in larger networks.  In the
     * common case, multicast convergence will complete under 3 seconds
     * as all results will arrive during the first interval (1 second long)
     * and none will arrive during the second interval.
     *
     * @param     addr  The multicast/broadcast address to send the request to.
     * @param     ds  The datagram socket to send on.
     * @param     msg The message to send.
     * @param     vResult A vector in which to put the returns.
     * @param	msTimeouts Array of timeout values for multicast convergence.
     * @param     maxResults Maximum replies desired.
     * @param	continueAfterFound If true, continue after something is
     *				   found. Try three times if nothing was
     *				   found. If false, exit at the first
     *				   timeout. DA discovery should set this
     *				   to true so as many DAs as possible are
     *				   found, otherwise, it should be false.
     * @exception ServiceLocationException
     *            If results cannot be obtained in the timeout interval
     *            specified in the 'config.' or
     *            if networking resources cannot be obtained or used
     *            effectively.
     */

    static public void
	transactConvergeMsg(InetAddress addr,
			    DatagramSocket ds,
			    SrvLocMsg   msg,
			    Vector vResult,
			    int[] msTimeouts,
			    int maxResults,
			    boolean continueAfterFound)
	throws ServiceLocationException {

	// Get the config object if we need it.

	if (config == null) {
	    config = SLPConfig.getSLPConfig();

	}

	int numReplies = 0;
	int tries = 0;
	SrvLocMsg rply = null;
	ByteArrayOutputStream baos = null;
	int multiMax = config.getMulticastMaximumWait();
	long lStartTime = System.currentTimeMillis();
	int mtu = config.getMTU();

	try {

	    // Send the request for the 1st iteration.  It will be sent again
	    //  only when the timeout intervals elapse.

	    send(ds, msg, addr);
	    tries++;

	    long lTimeSent = System.currentTimeMillis();

	    // Continue collecting results only as long as we need more for
	    //   the 'max results' configuration.

	    while (numReplies < maxResults) {

		// Set up the reply buffer.

		byte [] incoming = new byte[mtu];
		DatagramPacket dprecv =
		    new DatagramPacket(incoming, incoming.length);

		// Block on receive (no longer than max timeout - time spent).

		int iTimeout =
		    getTimeout(lStartTime, lTimeSent, multiMax, msTimeouts);

		if (iTimeout < 0) {
		    break; // we have no time left!
		}

		ds.setSoTimeout(iTimeout);

		try {
		    ds.receive(dprecv);

		} catch (InterruptedIOException ex) {

		    // We try sending at least three times, unless there was
		    // a timeout. If continueAfterFound is false, we exit
		    // after the first timeout if something was found.

		    if ((!continueAfterFound && numReplies > 0) ||
		(int)(System.currentTimeMillis() - lStartTime) > multiMax ||
			tries >= 3) {
			break;

		    }

		    // Now resend the request...

		    send(ds, msg, addr);
		    tries++;

		    lTimeSent = System.currentTimeMillis();
		    continue; // since we did not receive anything, continue...

		}

		// Data was received without timeout or fail.

		DataInputStream dis =
		    new DataInputStream(
			new ByteArrayInputStream(dprecv.getData()));

		InetAddress raddr = dprecv.getAddress();
		rply = internalize(dis, raddr);

		if (!filterRply(msg, rply, raddr)) {
		    continue;

		}

		// Add this responder to previous responders. If the message
		//  was already received but the SA resent because it isn't
		//  doing multicast convergence correctly, then ignore it.

		if (!addPreviousResponder(msg, raddr)) {
		    continue;

		}

		// Handle any overflow thru TCP.

		SrvLocHeader rhdr = rply.getHeader();

		if (rhdr.overflow) {

		    rply = transactTCPMsg(raddr, msg, false);

		    if (rply == null) {
			continue;

		    }

		    rhdr = rply.getHeader();
		}

		// Add response to list.

		if (vResult.size() < maxResults) {
		    vResult.addElement(rply);

		}

		// Increment the number of results returned.

		numReplies += rhdr.iNumReplies;

		// Exit if we should not continue.

		if (!continueAfterFound) {
		    break;

		}
	    }
	} catch (ServiceLocationException ex) {

	    // If we broke off because the previous responder's list is too
	    // long, then return, otherwise throw the exception again.

	    if (ex.getErrorCode() ==
		ServiceLocationException.PREVIOUS_RESPONDER_OVERFLOW) {
		return;

	    }

	    throw ex;

	} catch (IOException ex) {

	    throw
		new ServiceLocationException(
				ServiceLocationException.NETWORK_ERROR,
				"ioexception_conv",
				new Object[] {ex, ex.getMessage()});

	}
    }

    // Calculate the multicast timeout depending on where we are in the loop.

    static private int
	getTimeout(long lStart, long lSent, int iTimeout, int[] a_iTOs) {
	int iTotal = (int)(lSent - lStart);

	if (iTimeout < iTotal) {
	    return -1;

	}

	int iWaitTotal = 0;
	int i;

	for (i = 0; i < a_iTOs.length; i++) {
	    iWaitTotal += a_iTOs[i];

	    int iTillNext = (iWaitTotal - iTotal);

	    if (iTotal < iWaitTotal) {
		if (iTimeout < (iTotal + iTillNext)) {
		    return (iTimeout - iTotal);  // max to wait is iTimeout

		} else {
		    return iTillNext; // otherwise wait till next interval
		}
	    }
	}

	return -1; // if we get here we have waited past all of the timeouts
    }

    static {

	config = SLPConfig.getSLPConfig();

    }
}
