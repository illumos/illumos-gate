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

//  SrvLocHeader.java: Abstract superclass for SLP Headers
//  Author:           James Kempf
//  Created On:       Mon Sep 14 12:47:20 1998
//  Last Modified By: James Kempf
//  Last Modified On: Mon Nov 23 14:32:50 1998
//  Update Count:     55
//

package com.sun.slp;

import java.util.*;
import java.net.*;
import java.io.*;

/**
 * SrvLocHeader handles different versions of the SLP header. Clients
 * call the instance methods returned by newInstance(). If no version
 * specific subclass exists for the version number, null is returned
 * from newInstance. Parsing of the header and message bodies, and
 * creation of error replies are handled by the version specific
 * subclasses. We also let the SrvLocHeader serve as a SrvLocMsg object
 * to handle the SrvAck, which only has an error code.
 *
 * @author James Kempf
 */

abstract class SrvLocHeader extends Object implements SrvLocMsg, Cloneable {

    // Table of header classes. Keys are the version number.

    private static final Hashtable classTable = new Hashtable();

    // Offset to XID.

    static final int XID_OFFSET = 10;

    // Common constants and instance variables.

    // Number of bytes in the version and function fields.

    static int VERSION_FUNCTION_BYTES = 2;

    // SLP function codes. Even though SAAdvert isn't in all versions,
    //  we include it here.

    static final int SrvReq  = 1;
    static final int SrvRply = 2;
    static final int SrvReg = 3;
    static final int SrvDereg = 4;
    static final int SrvAck = 5;
    static final int AttrRqst = 6;
    static final int AttrRply = 7;
    static final int DAAdvert = 8;
    static final int SrvTypeRqst = 9;
    static final int SrvTypeRply = 10;
    static final int SAAdvert = 11;

    static final String[] functionCodeAbbr = {
	"0",
	"SrvReq",
	"SrvRply",
	"SrvReg",
	"SrvDereg",
	"SrvAck",
	"AttrRqst",
	"AttrRply",
	"DAAdvert",
	"SrvTypeRqst",
	"SrvTypeRply",
	"SAAdvert",
    };

    // Sizes of data items.

    protected static final int BYTE_SIZE = 1;
    protected static final int SHORT_SIZE = 2;
    protected static final int INT24_SIZE = 3;

    //
    // Header instance variables.
    //

    // Unprotected for less code.

    int    version = 0;			// version number
    int    functionCode = 0;		// function code
    int    length = 0;			// packet length
    short  xid = 0;			// transaction id
    short  errCode =
	ServiceLocationException.OK;	// not applicable to start
    Locale locale = Defaults.locale;	// language locale
    Vector previousResponders = null;	// list of previous responders
    Vector scopes = null;		// list of scopes
    boolean overflow = false;		// Overflow flag
    boolean fresh = false;		// Fresh flag
    boolean mcast = false;		// Mulitcast flag.
    byte[] payload = new byte[0];	// bytes of outgoing payload,
    int nbytes = 0;			// number of bytes processed
    int packetLength = 0;		// length of packet.
    int iNumReplies = 0;		// number of replies.


    protected static short uniqueXID = 0;	// outgoing transaction id.

    // Message description.

    private String msgType;
    private String msgDescription;


    SrvLocHeader() {

	packetLength = SLPConfig.getSLPConfig().getMTU();

    }

    //
    // SrvLocMsg Implementation.
    //

    public SrvLocHeader getHeader() {
	return this;

    }

    public short getErrorCode() {
	return errCode;

    }

    // Return number of replies to this message.

    public int getNumReplies() {
	return iNumReplies;

    }

    //
    // SrvLocHeader Interface.
    //

    // Register a new header class for version. Serious error, causing
    //  program termination, if we can't find it.

    static void addHeaderClass(String className, int version) {

	try {

	    Class headerClass = Class.forName(className);

	    classTable.put(new Integer(version), headerClass);

	} catch (ClassNotFoundException ex) {

	    Assert.slpassert(false,
			  "no_class",
			  new Object[] {className});

	}
    }

    // Create a version specific instance. We use a naming convention
    //  to identify the version specific classes used to create the
    //  instance.

    static SrvLocHeader newInstance(int version) {

	try {

	    // Get header class.

	    Class hdrClass = (Class)classTable.get(new Integer(version));

	    if (hdrClass == null) {
		return null;

	    }

	    SrvLocHeader hdr = (SrvLocHeader)hdrClass.newInstance();

	    return hdr;

	} catch (Exception ex) {

	    SLPConfig.getSLPConfig().writeLog("slh_creation_exception",
					      new Object[] {
		new Integer(version),
		    ex,
		    ex.getMessage()});
	    return null;

	}

    }

    // Parse the incoming stream to obtain the header.

    abstract void parseHeader(int functionCode, DataInputStream dis)
	throws ServiceLocationException, IOException, IllegalArgumentException;

    // Parse the incoming stream to obtain the message.

    abstract SrvLocMsg parseMsg(DataInputStream dis)
	throws ServiceLocationException, IOException, IllegalArgumentException;

    // Externalize the message.

    abstract void
	externalize(ByteArrayOutputStream baos,
		    boolean multicast,
		    boolean isTCP)
	throws ServiceLocationException;

    // Return the appropriately versioned DAAdvert.

    abstract SDAAdvert
	getDAAdvert(short xid,
		    long timestamp,
		    ServiceURL url,
		    Vector scopes,
		    Vector attrs)
	throws ServiceLocationException;

    //
    // Methods that some subclasses may reimplement.
    //

    // Parse any options.

    void parseOptions(DataInputStream dis)
	throws ServiceLocationException,
	       IOException,
	       IllegalArgumentException {

    }

    // Create an error reply for this message. This reply will be appropriate
    //  for the server to send back to the client. Default is to do nothing,
    //  which is the code for the client.

    SrvLocMsg makeErrorReply(Exception ex) {
	return null;

    }

    //
    //  Common utilities for all versions.
    //

    // Set the packet length to the incoming value.

    void setPacketLength(int newLength) {

	if (newLength > 0) {
	    packetLength = newLength;

	}
    }

    // Add an Internet address to the previous responders list.

    void addPreviousResponder(InetAddress addr) {

	String hostAddr = addr.getHostAddress();

	Assert.slpassert((previousResponders != null),
		      "prev_resp_reply",
		      new Object[0]);

	if (!previousResponders.contains(hostAddr)) {
	    previousResponders.addElement(hostAddr);

	}
    }

    // Get a unique transaction id.

    synchronized static short getUniqueXID() {
	if (uniqueXID == 0) {
	    Random r = new Random();
	    uniqueXID = (short)(r.nextInt() &0xFFFF);
	}
	uniqueXID++;
	return (short)(uniqueXID & 0xFFFF);
    }

    // Parse 2-byte integer, bump byte count.

    int getInt(DataInputStream dis)
	throws ServiceLocationException, IOException {

	int ret = getInteger(dis);

	nbytes += SHORT_SIZE;

	return ret;
    }


    // Parse a 2-byte integer from the input stream.

    static int getInteger(DataInputStream dis)
	throws ServiceLocationException, IOException {

	byte[] b = new byte[2];

	dis.readFully(b, 0, 2);

	int x = (int)((char)b[0] & 0xFF);
	int y = (int)((char)b[1] & 0xFF);
	int z = x << 8;
	z += y;
	return z;
    }

    // Parse 2-byte integer, bump byte count.

    void putInt(int z, ByteArrayOutputStream baos) {

	putInteger(z, baos);

	nbytes += SHORT_SIZE;

    }

    // Parse a 2-byte integer to the output stream.

    static void putInteger(int z, ByteArrayOutputStream baos) {
	baos.write((byte) ((0xFF00 & z)>>8));
	baos.write((byte) (0xFF & z));
    }


    // Parse a 3-byte integer from the byte input stream.

    protected int getInt24(DataInputStream dis)
	throws ServiceLocationException, IOException {

	byte[] b = new byte[3];

	dis.readFully(b, 0, 3);

	int w = (int)((char)b[0] & 0xFF);
	int x = (int)((char)b[1] & 0xFF);
	int y = (int)((char)b[2] & 0xFF);
	int z = w << 16;
	z += x << 8;
	z += y;
	nbytes += 3;
	return z;
    }

    // Parse a 3-byte integer to the output stream.

    protected void putInt24(int z, ByteArrayOutputStream baos) {
	baos.write((byte) ((0xFF0000 & z) >> 16));
	baos.write((byte) ((0xFF00 & z)>>8));
	baos.write((byte) (0xFF & z));

	nbytes += 3;
    }


    // Parse string, bump byte count. Use UTF8 encoding.

    byte[] getString(StringBuffer buf, DataInputStream dis)
	throws ServiceLocationException, IOException {

	byte[] ret = getStringField(buf, dis, Defaults.UTF8);

	nbytes += ret.length + SHORT_SIZE;

	return ret;
    }

    // Parse a string with an initial length from the input stream.
    //  Convert it to the proper encoding. Return the raw bytes for
    //  auth block creation.

    static byte[]
	getStringField(StringBuffer buf, DataInputStream dis, String encoding)
	throws ServiceLocationException, IOException {

	// Clear out buffer first.

	buf.setLength(0);

	// First get the length.

	int i, n = 0;

	n = getInteger(dis);

	// Now get the bytes.

	byte[] bytes = new byte[n];

	dis.readFully(bytes, 0, n);

	// Convert to string and return.

	buf.append(getBytesString(bytes, encoding));

	return bytes;

    }

    // Parse out string, bump byte count. Use UTF8 encoding.

    byte[] putString(String string, ByteArrayOutputStream baos) {

	byte[] bytes = putStringField(string, baos, Defaults.UTF8);

	nbytes += bytes.length + SHORT_SIZE;

	return bytes;

    }

    // Put a string with an initial length into the byte stream, converting
    //  into the proper encoding.

    static byte[]
	putStringField(String string,
		       ByteArrayOutputStream baos,
		       String encoding) {

	byte[] bytes = getStringBytes(string, encoding);

	// Put out the string's length in the encoding.

	putInteger(bytes.length, baos);

	// Now really write out the bytes.

	baos.write(bytes, 0, bytes.length);

	return bytes;

    }

    // Convert a Unicode string into encoded bytes.

    static byte[] getStringBytes(String string, String encoding) {

	try {
	    return string.getBytes(encoding);

	} catch (UnsupportedEncodingException ex) {
	    return  new byte[0];  // won't happen, hopefully...

	}
    }

    // Convert bytes into a Unicode string.

    static String getBytesString(byte[] bytes, String encoding) {

	try {
	    return new String(bytes, encoding);

	} catch (UnsupportedEncodingException ex) {
	    return "";  // won't happen, hopefully ...

	}

    }

    // Parse a comma separated list of strings from the vector into the
    //  output stream.

    protected byte[]
	parseCommaSeparatedListOut(Vector v,
				   ByteArrayOutputStream baos) {

	return putString(vectorToCommaSeparatedList(v), baos);

    }

    /**
     * Create a comma separated list of strings out of the vector.
     *
     * @param v A Vector of strings.
     */

    static String
	vectorToCommaSeparatedList(Vector v) {

	// Construct in a string buffer first.

	int i, n = v.size();
	StringBuffer buf = new StringBuffer();


	for (i = 0; i < n; i++) {
	    String string = (String)v.elementAt(i);

	    // Add comma for previous one if we need it.

	    if (i != 0) {
		buf.append(',');
	    }

	    buf.append(string);

	}

	// Return the bytes.

	return buf.toString();
    }

    /**
     * @parameter The string has the format = STRING *("," STRING)
     * @parameter A boolean indicating whether parens should be ignored or
     * 		used for grouping.
     * @return  A vector (of Strings) based upon the (comma delimited) string.
     */
    static Vector parseCommaSeparatedListIn(String s, boolean ignoreParens)
	throws ServiceLocationException {

	if (s == null)
	    return new Vector();
	if (s.length() == 0)
	    return new Vector();
	StringTokenizer st = new StringTokenizer(s, ",()", true);
	try {
	    int level = 0;
	    String el = "";
	    Vector v = new Vector();

	    while (st.hasMoreElements()) {
		String tok = st.nextToken();

		// It's an open paren, so begin collecting.

		if (tok.equals("(")) {

		    // Increment the level if not ignoring parens, add to token

		    if (!ignoreParens) {
			level++;

		    }

		    el += tok;

		} else if (tok.equals(")")) {

		    // Decrement level if not ignoring parens.

		    if (!ignoreParens) {
			level--;

		    }

		    el += tok;

		} else if (tok.equals(",")) {

		    // Add if collecting.

		    if (level != 0) {
			el += tok;

		    } else {

			// Check for empty token.

			if (el.length() <= 0) {
			    throw
				new ServiceLocationException(
					ServiceLocationException.PARSE_ERROR,
					"csl_syntax_error",
					new Object[] {s});
			}

			// If not collecting, then close off the element.

			v.addElement(el);
			el = "";

		    }
		} else {
		    el += tok;

		}
	    }

	    // Add last token, but check first for empty token.

	    if (el.length() <= 0) {
		throw
		    new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"csl_syntax_error",
				new Object[] {s});
	    }

	    v.addElement(el);

	    // If we're still collecting on close, then there's a syntax error.

	    if (level != 0) {
		throw
		    new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"csl_syntax_error",
				new Object[] {s});
	    }

	    return v;
	} catch (NoSuchElementException nsee) {
	    throw
		new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"csl_syntax_error",
				new Object[] {s});

	}
    }

    // Allow clients to clone the header.

    public Object clone()
	throws CloneNotSupportedException {
	SrvLocHeader hdr = (SrvLocHeader)super.clone();

	// Reinitialize some stuff. Subclasses must reimplement nbytes
	//  header size calculation.

	hdr.length = 0;
	hdr.payload = new byte[0];
	hdr.iNumReplies = 0;
	// packetlength stays the same, we may be using the same transport.

	return hdr;

    }

    // Construct a description of the header. Messages add individual
    //  descriptions to this.

    protected void constructDescription(String msgType,
					String msgDescription) {
	this.msgType = msgType;
	this.msgDescription = msgDescription;
    }

    public String getMsgType() {
	if (msgType == null) {
	    if (functionCode > 0 && functionCode < functionCodeAbbr.length) {
		return functionCodeAbbr[functionCode];
	    } else {
		return String.valueOf(functionCode);
	    }
	} else {
	    return msgType;
	}
    }

    public String getMsgDescription() {
	return (msgDescription == null) ? "" : msgDescription;
    }
}
