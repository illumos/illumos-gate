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

//  SLPHeaderV2.java:   Base class for Service Location Messages
//  Author:           James Kempf
//  Created On:       Thu Oct  9 08:50:31 1997
//  Last Modified By: James Kempf
//  Last Modified On: Wed Jan  6 15:24:26 1999
//  Update Count:     472
//

package com.sun.slp;

import java.util.*;

import java.net.*;
import java.io.*;

/**
 * The SLPHeaderV2 class serves as the header class for all SLPv2 messages.
 * It contains instance variables for SLP message header contents,
 * and implements the SLPHeaderV2 interface.
 *
 * @author James Kempf
 */

class SLPHeaderV2 extends SrvLocHeader implements Cloneable {

    // Support for options.

    private int optOff = 0;
    Hashtable optTable = new Hashtable();

    // Maximum message size (24 bits).

    private final static int MAX_MESSAGE_LENGTH = 0xffffff;

    // Location of flag byte.

    static final int FLAG_BYTE = 4;

    // Various header flags.

    protected static final int NOFLAG   = 0x00;
    static final int           OVERFLOW = 0x80;  // needed by Transact.
    protected static final int FRESH    = 0x40;
    protected static final int MCAST    = 0x20;

    // Header sizes. Note that this doesn't include the language tag,
    //  which is variable.

    protected static final int REST_HEADER_BYTES = 12;
    protected static final int HEADER_BYTES =
	VERSION_FUNCTION_BYTES + REST_HEADER_BYTES;

    // Maximum protected scopes allowed.

    protected static final int MAX_PROTECTED_SCOPES = 255;

    // Registered option classes.

    protected static Hashtable optClasses = new Hashtable();

    // Manditory option range.

    protected static int MANDATORY_OPTION_LOW = 0x4000;
    protected static int MANDATORY_OPTION_HIGH = 0x7fff;

    // Sizes of option id and extension fields (in bytes).

    protected static int OPT_ID_SIZE = 2;
    protected static int OPT_OFF_SIZE = 2;

    // Interfaces for options to use.

    interface OptionParser {

	// Parse the option from the data stream. We include the header also,
	//  in case it is needed.

	abstract SLPOption parse(SLPHeaderV2 hdr, DataInputStream dsr)
	    throws ServiceLocationException, IOException;

    }

    interface SLPOption {

	// Externalize the option to the byte array stream. We include the
	//  header also, in case it is needed.

	abstract void externalize(SLPHeaderV2 hdr, ByteArrayOutputStream baos)
	    throws ServiceLocationException;

    }

    // Register an option parsing class.

    static void registerOptionClass(int id, Class optClass) {

	Integer key = new Integer(id);

	// We should probably check if it implements SLPOption.OptionParser,
	//  but...

	optClasses.put(key, optClass);

    }

    //
    // Header instance variables.
    //

    // For the incoming message side.

    SLPHeaderV2() {
	super();

	version = Defaults.version;

    }

    // Initialize the new SLPHeaderV2 from the input stream. Version and
    //  function code have already been removed from the stream.

    void parseHeader(int functionCode, DataInputStream dis)
	throws ServiceLocationException, IOException {

	this.functionCode = functionCode;

	nbytes += 2;  // for version and function code...

	// Get length.

	length = getInt24(dis);

	// Get flags.

	byte[] b = new byte[2];

	dis.readFully(b, 0, 2);

	nbytes += 2;

	byte flags   = (byte) ((char)b[0] & 0xFF);

	overflow = ((flags & OVERFLOW) != NOFLAG);
	fresh = ((flags & FRESH) != NOFLAG);
	mcast = ((flags & MCAST) != NOFLAG);

	// We could check for null on reserved part of flags field, but
	//  in the spirit of "be liberal in what you receive" we don't.

	// Get option offset.

	optOff = getInt24(dis);

	// Check option offset for sanity.

	if (optOff > length) {
	    throw
		new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"option_error",
				new Object[] {
		    new Integer(optOff), new Integer(length)});

	}

	// Get transaction id.

	xid = (short)getInt(dis);

	// Get language code.

	StringBuffer buf = new StringBuffer();

	getString(buf, dis);

	locale = SLPConfig.langTagToLocale(buf.toString());

	// Everything went OK coming in, so set the error code.

	errCode = ServiceLocationException.OK;
    }

    // By default, the header parses the client side message. A server
    //  side subclass must replace this. We do this so that the amount of code
    //  in the client is minimized, since this class must be in both.

    SrvLocMsg parseMsg(DataInputStream dis)
	throws ServiceLocationException,
	       IOException,
	       IllegalArgumentException {

	SrvLocMsg rply = null;

	// Get the error code, if not SAAdvert.

	if (functionCode != SrvLocHeader.SAAdvert) {
	    errCode = (short)getInt(dis);

	}

	// Switch and convert according to function code.

	switch (functionCode) {

	case SrvLocHeader.SrvRply:
	    rply = new CSrvMsg(this, dis);
	    break;

	case SrvLocHeader.AttrRply:
	    rply = new CAttrMsg(this, dis);
	    break;

	case SrvLocHeader.SrvTypeRply:
	    rply = new CSrvTypeMsg(this, dis);
	    break;

	case SrvLocHeader.DAAdvert:
	    rply = new CDAAdvert(this, dis);
	    break;

	case SrvLocHeader.SrvAck:

	    // We act as a SrvAck.

	    rply = this;
	    iNumReplies = 1;
	    break;

	case SrvLocHeader.SAAdvert:
	    rply = new CSAAdvert(this, dis);
	    break;

	default:
	    throw
		new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"function_code_error",
				new Object[] {
		    new Integer(functionCode)});

	}

	// Check for size overflow.

	if (nbytes > length) {
	    throw
		new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"length_overflow",
				new Object[] {
		    new Integer(nbytes), new Integer(length)});

	}

	return rply;
    }

    // Construct a header for output. Used by the client side code to
    //  construct an initial request and the server side code to construct
    //  a reply.

    SLPHeaderV2(int functionCode, boolean fresh, Locale locale)
	throws ServiceLocationException {

	// Check for proper function code and nonnull locale.

	Assert.slpassert(((functionCode <= SAAdvert) &&
	    (functionCode >= SrvReq)),
		      "function_code_error",
		      new Object[] {new Integer(functionCode)});

	Assert.slpassert((locale != null),
		      "null_locale_error",
		      new Object[0]);

	this.version = Defaults.version;
	this.functionCode = functionCode;
	this.locale = locale;
	this.xid = getUniqueXID();  // client can change it later if they want.
	this.fresh = fresh;

	// If there's not enough for the error code (if any), then signal
	//  an error. The assumption here is that the message is going
	//  via UDP or multicast.

	byte[] ltag =
	    getStringBytes(SLPConfig.localeToLangTag(locale), Defaults.UTF8);
	int headerLen = ltag.length + HEADER_BYTES;
	int payLen =  packetLength - headerLen;

	if (payLen < SHORT_SIZE) {
	    throw
		new ServiceLocationException(
				ServiceLocationException.BUFFER_OVERFLOW,
				"buffer_overflow",
				new Object[] {
		    new Integer(headerLen + SHORT_SIZE),
			new Integer(packetLength)});
	}
    }

    // Externalize the message by converting it to bytes and writing
    //  it to the output stream.

    public void
	externalize(ByteArrayOutputStream baos, boolean mcast, boolean isTCP)
	throws ServiceLocationException {

	// Convert the locale to a tag. We need the length.

	byte[] ltagBytes =
	    getStringBytes(SLPConfig.localeToLangTag(locale), Defaults.UTF8);
	int ltagLen = ltagBytes.length;

	// Set the multicast flag.

	this.mcast = mcast;

	// We need to get stuff into another stream first, so we can correctly
	//  calculate the length.

	ByteArrayOutputStream bbaos = new ByteArrayOutputStream();

	// Need to put in the error code. There will only be an error code
	//  if error codes are applicable for this message type. Note
	//  that room for the error code was reserved in the initial
	//  calculation of the header, so there should always be room
	//  for it, even if the packet overflowed otherwise.

	if (functionCode == SrvLocHeader.SrvAck ||
	    functionCode == SrvLocHeader.SrvTypeRply ||
	    functionCode == SrvLocHeader.SrvRply ||
	    functionCode == SrvLocHeader.AttrRply ||
	    functionCode == SrvLocHeader.DAAdvert) {
	    putInt(errCode, bbaos);

	}

	// Put in the previous responders, if there are any. Note that
	//  there may be only when the error code is not put out.
	//  We check against the packet size during parsing so that
	//  we don't overflow the packet and throw a special exception
	//  if an overflow happens. We only put out the previous
	//  responders list if the request is going by multicast, but
	//  we need to put out an empty vector for unicast requests.

	int prevResLen =
	    packetLength - (payload.length + HEADER_BYTES + ltagLen);
	Vector resp = previousResponders;

	if (resp != null) {
	    resp = (mcast ? resp:new Vector());

	    parsePreviousRespondersOut(resp, bbaos, prevResLen);

	}

	// If the error code is OK, then insert the rest of the message
	//  and parse the options. If there was an error,
	//  this step is skipped because the data isn't relevant.

	if (errCode == ServiceLocationException.OK) {
	    bbaos.write(payload, 0, payload.length);

	    // Externalize any options.

	    optOff = externalizeOptions(bbaos, ltagLen);
	}

	byte[] payloadBytes = bbaos.toByteArray();

	// Set the length here to the actual length of the packet.

	length = HEADER_BYTES + ltagLen + payloadBytes.length;

	// If we exceed the 24 bit length size, we are hosed.

	if (length > MAX_MESSAGE_LENGTH) {
	    throw
		new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"max_msg_size_exceeded",
				new Object[0]);

	}

	// Truncate if necessary. We will always have room for a header
	//  and error code because we check when creating the object.
	//  Note that no URL block will be truncated because the spec
	//  says it can't be.

	if (!isTCP && (length > packetLength)) {
	    overflow = true;
	    length = packetLength;
	    byte[] newBytes = new byte[packetLength];
	    System.arraycopy(payloadBytes, 0, newBytes, 0,
			     length - (HEADER_BYTES + ltagLen));
	    payloadBytes = newBytes;

	}

	//
	// Write out the header.
	//

	// Write version and function code.

	baos.write((byte) (0xFF & version));
	baos.write((byte) (0xFF & functionCode));

	// Put length in.

	putInt24(length, baos);

	// Put in flags.

	byte flags = (byte)NOFLAG;

	if (overflow) {
	    flags = (byte)(flags | OVERFLOW);
	} else {
	    flags = (byte)(flags & ~OVERFLOW);
	}

	if (fresh) {
	    flags = (byte)((flags | FRESH) & 0xFF);
	} else {
	    flags = (byte)((flags & ~FRESH) & 0xFF);
	}

	if (mcast) {
	    flags = (byte)((flags | MCAST) & 0xFF);
	} else {
	    flags = (byte)((flags & ~MCAST) & 0xFF);
	}

	// Write out flags.

	baos.write((byte) (0xFF & flags));
	baos.write((byte)0);

	putInt24(optOff, baos);  // write option offset,  if any.

	putInt(xid, baos);  // write xid.

	putInt(ltagLen, baos);  // write lang size.
	baos.write(ltagBytes, 0, ltagBytes.length);  // write lang tag.

	//
	// Write the body.
	//

	baos.write(payloadBytes, 0, payloadBytes.length);

    }

    //
    // Option handling.
    //

    // Parse any options.

    void parseOptions(DataInputStream dsr)
	throws ServiceLocationException,
	       IOException,
	       IllegalArgumentException {

	// If no options return.

	if (optOff == 0) {
	    return;

	}

	int optNext = 0;

	// Parse any options in the data stream.

	do {

	    // Parse extension id.

	    int optId = getInt(dsr);

	    // Parse extension offset.

	    optNext = getInt(dsr);

	    // Lookup an option parser.

	    Integer key = new Integer(optId);

	    Class optClass = (Class)optClasses.get(key);

	    // May be an exception if class is null.

	    if (optClass == null) {

		// In mandatory range. Throw an exception.

		if ((optId >= MANDATORY_OPTION_LOW) &&
		    (optId <= MANDATORY_OPTION_HIGH)) {
		    throw
			new ServiceLocationException(
				ServiceLocationException.OPTION_NOT_SUPPORTED,
				"v2_unsup_option",
				new Object[] {key});

		}

		// Skip the rest of the option.

		int skipStart = length;

		if (optNext != 0) {
		    skipStart = optNext;

		}

		dsr.skipBytes(skipStart - nbytes);


	    } else {

		try {

		    // Parse the option.

		    OptionParser optParser =
			(OptionParser)optClass.newInstance();

		    SLPOption opt = optParser.parse(this, dsr);

		    // Insert option into option table.

		    optTable.put(key, opt);

		} catch (InstantiationException ex) {

		    throw
			new ServiceLocationException(
				ServiceLocationException.INTERNAL_SYSTEM_ERROR,
				"v2_option_inst",
				new Object[] {key, ex});

		} catch (IllegalAccessException ex) {

		    throw
			new ServiceLocationException(
				ServiceLocationException.INTERNAL_SYSTEM_ERROR,
				"v2_option_sec",
				new Object[] {key, ex});
		}
	    }
	} while (optNext != 0);
    }

    // Externalize any options.

    private int externalizeOptions(ByteArrayOutputStream baos, int langTagLen)
	throws ServiceLocationException {

	// Calculate offset to options, if any.

	int toOpt  = 0;

	if (optTable.size() <= 0) {
	    return toOpt;

	}

	toOpt = HEADER_BYTES + langTagLen + baos.size();

	// For all options in the table, parse them out.

	Enumeration en = optTable.keys();
	int nextOpt = toOpt;

	while (en.hasMoreElements()) {
	    Integer id = (Integer)en.nextElement();
	    SLPOption opt = (SLPOption)optTable.get(id);
	    ByteArrayOutputStream obaos = new ByteArrayOutputStream();

	    // Linearize option object.

	    opt.externalize(this, obaos);

	    // Calculate offset to next options.

	    nextOpt += obaos.size() + OPT_ID_SIZE + OPT_OFF_SIZE;

	    // Plop it into the output stream.

	    putInt(id.intValue(), baos);


	    // Check whether there are more options first. If so, then
	    //  the next offset is zero.

	    if (en.hasMoreElements()) {
		putInt(nextOpt, baos);

	    } else {
		putInt(0, baos);

	    }

	    byte[] bytes = obaos.toByteArray();

	    baos.write(bytes, 0, bytes.length);

	}

	return toOpt;
    }

    // Parse the previous responder list out, being sure to truncate
    //  so the list is syntactically correct if there is an overflow.
    //  This duplicates the comma separated list code to a certain
    //  extent.

    private void
	parsePreviousRespondersOut(Vector resp,
				   ByteArrayOutputStream baos,
				   int available)
	throws ServiceLocationException {

	ByteArrayOutputStream bbaos = new ByteArrayOutputStream();
	int i, n = resp.size();

	for (i = 0; i < n; i++) {
	    String address = (String)resp.elementAt(i);

	    // Add comma if necessary.

	    if (i > 0) {
		address = "," + address;

	    }

	    // Convert to UTF8 bytes.

	    byte[] bytes = getStringBytes(address, Defaults.UTF8);

	    // Write bytes to stream if there's room.

	    if (bytes.length <= available) {
		bbaos.write(bytes, 0, bytes.length);
		available = available - bytes.length;

	    } else {

		// Throw exception, upper layers need to break off multicast.
		//  This exception should *never* be surfaced.

		throw
		    new ServiceLocationException(
			ServiceLocationException.PREVIOUS_RESPONDER_OVERFLOW,
			"v2_prev_resp_overflow",
			new Object[] {});
	    }
	}

	// Now write to the real stream.

	byte[] out = bbaos.toByteArray();
	putInt(out.length, baos);
	baos.write(out, 0, out.length);

	nbytes += out.length;

    }

    //
    //  Utilities for parsing service URL's and attribute lists, with
    //  authentication information.
    //

    // Parse in a service URL including lifetime if necessary.

    ServiceURL
	parseServiceURLIn(DataInputStream dis,
			  Hashtable authTable,
			  short err)
	throws ServiceLocationException, IOException {

	// Ignore reserved byte.

	byte[] b = new byte[1];

	dis.readFully(b, 0, 1);

	nbytes += 1;

	// Get URL lifetime.

	int lifetime = getInt(dis);

	// Get URL.

	StringBuffer buf = new StringBuffer();

	byte[] rawBytes = getString(buf, dis);

	// Get auth block, if any.

	Hashtable auth = null;

	// Get number of auth blocks.

	b = new byte[1];

	dis.readFully(b, 0, 1);

	nbytes += 1;

	byte nauths = (byte)(b[0] & 0xFF);

	if (nauths > 0) {
	    ByteArrayOutputStream abaos = new ByteArrayOutputStream();
	    putInteger(rawBytes.length, abaos);
	    Object[] message = new Object[2];
	    message[0] = abaos.toByteArray();
	    message[1] = rawBytes;
	    auth = getCheckedAuthBlockList(message, nauths, dis);

	    lifetime = AuthBlock.getShortestLifetime(auth);

	}

	String ssurl = buf.toString();
	ServiceURL url = null;

	try {

	    url = new ServiceURL(ssurl, lifetime);

	} catch (IllegalArgumentException ex) {

	    throw
		new ServiceLocationException(err,
					     "malformed_url",
					     new Object[] {ex.getMessage()});

	}

	if (auth != null) {

	    // Put it in the auth block for this URL.

	    authTable.put(url, auth);

	}

	return url;
    }

    // Parse out a service URL, create authentication blocks if necessary.
    //  Return true if the URL was output. Check that we don't overflow
    //  packet size in the middle.

    boolean
	parseServiceURLOut(ServiceURL surl,
			   boolean urlAuth,
			   Hashtable auth,
			   ByteArrayOutputStream baos,
			   boolean checkOverflow)
	throws ServiceLocationException {

	// We need to keep track of size, so we don't overflow packet length.

	ByteArrayOutputStream bbaos = new ByteArrayOutputStream();

	int mbytes = nbytes;

	// Convert the URL to bytes.

	byte[] bytes =  getStringBytes(surl.toString(), Defaults.UTF8);

	// Parse out reserved.

	bbaos.write((byte)(0xFF & 0));

	nbytes += 1;

	// Parse out the lifetime.

	putInt(surl.getLifetime(), bbaos);

	byte bs = (byte)0;

	// Process auth block list if required.

	if (urlAuth) {

	    // Create an auth block if necessary.

	    if (auth == null) {
		ByteArrayOutputStream abaos = new ByteArrayOutputStream();
		putInteger(bytes.length, abaos);
		Object[] message = new Object[2];
		message[0] = abaos.toByteArray();
		message[1] = bytes;
		auth = getCheckedAuthBlockList(message, surl.getLifetime());

	    }

	    bs = (byte) auth.size();
	    Object[] bytesArray = AuthBlock.getContents(auth);
	    bytes = (byte[]) bytesArray[1];

	}

	// Put out the URL bytes.

	putInt(bytes.length, bbaos);
	bbaos.write(bytes, 0, bytes.length);

	nbytes += bytes.length;

	// Write auth block size.

	bbaos.write((byte)(0xFF & bs));

	nbytes += 1;

	// If there are auth blocks required, put them out now.

	if (bs > (byte)0) {
	    AuthBlock.externalizeAll(this, auth, bbaos);

	}

	// If we can, write it out.

	bytes = bbaos.toByteArray();

	if (!checkOverflow || nbytes <= packetLength) {
	    baos.write(bytes, 0, bytes.length);
	    return true; // nbytes already set...

	} else {
	    nbytes = mbytes; // truncate...
	    return false;

	}
    }

    // Parse in a potentially authenticated attribute list.

    Hashtable
	parseAuthenticatedAttributeVectorIn(Vector attrs,
					    DataInputStream dis,
					    boolean allowMultiValuedBooleans)
	throws ServiceLocationException, IOException {

	// First, parse in the attribute vector.

	byte[] rawBytes =
	    parseAttributeVectorIn(attrs, dis, allowMultiValuedBooleans);

	ByteArrayOutputStream abaos = new ByteArrayOutputStream();
	putInteger(rawBytes.length, abaos);
	Object[] message = new Object[2];
	message[0] = abaos.toByteArray();
	message[1] = rawBytes;

	// Get the attribute list signature, if necessary.

	return parseSignatureIn(message, dis);

    }

    // Parse in a list of attributes into attrs, returing raw bytes.
    //  ServiceLocationAttribute objects. Clients take care of auth blocks.

    byte[]
	parseAttributeVectorIn(Vector attrs,
			       DataInputStream dis,
			       boolean allowMultiValuedBooleans)
	throws ServiceLocationException, IOException {

	StringBuffer buf = new StringBuffer();

	byte[] rawBytes  = getString(buf, dis);

	// Parse the list into ServiceLocationAttribute objects.

	Vector attrForms = parseCommaSeparatedListIn(buf.toString(), false);

	int i, n = attrForms.size();

	for (i = 0; i < n; i++) {
	    String attrForm =
		(String)attrForms.elementAt(i);

	    attrs.addElement(
		new ServiceLocationAttribute(
			attrForm, allowMultiValuedBooleans));
	}

	return rawBytes;
    }

    // Parse out a vector of ServiceLocationAttributes. Includes escaping
    //  characters.
    byte[]
	parseAttributeVectorOut(Vector v,
				int lifetime,
				boolean attrAuth,
				Hashtable auth,
				ByteArrayOutputStream baos,
				boolean writeAuthCount)
	throws ServiceLocationException {

	byte[] bytes = null;
	int nBlocks = 0;

	// Convert attribute vector to comma separated list.

	if (!attrAuth || auth == null) {
	    Vector strings = new Vector();
	    Enumeration en = v.elements();

	    // Convert the attributes to strings, escaping characters to
	    //  escape.

	    while (en.hasMoreElements()) {
		ServiceLocationAttribute attr =
		    (ServiceLocationAttribute)en.nextElement();

		strings.addElement(attr.externalize());

	    }

	    // Create the comma separated list.

	    String clist = vectorToCommaSeparatedList(strings);
	    bytes = getStringBytes(clist, Defaults.UTF8);

	    if (attrAuth) {
		ByteArrayOutputStream abaos = new ByteArrayOutputStream();
		putInteger(bytes.length, abaos);
		Object[] message = new Object[2];
		message[0] = abaos.toByteArray();
		message[1] = bytes;
		auth = getCheckedAuthBlockList(message, lifetime);
	    }
	} else {
	    Object[] bytesArray = AuthBlock.getContents(auth);
	    bytes = (byte[]) bytesArray[1];

	}

	// Get number of blocks if authentication.

	if (auth != null) {
	    nBlocks = auth.size();

	}


	// Write out the bytes.

	putInt(bytes.length, baos);
	baos.write(bytes, 0, bytes.length);
	nbytes += bytes.length;

	// Write out number of auth blocks.

	if (writeAuthCount) {
	    baos.write((byte)(nBlocks & 0xFF));
	    nbytes += 1;
	}

	// Write out the attribute authentication blocks.

	if (attrAuth && nBlocks > 0) {
	    AuthBlock.externalizeAll(this, auth, baos);
	}

	return bytes;
    }

    // Get an auth block list, checking first for security.

    Hashtable getCheckedAuthBlockList(Object[] message, int lifetime)
	throws ServiceLocationException {

	if (!SLPConfig.getSLPConfig().getHasSecurity()) {
	    throw
		new ServiceLocationException(
				ServiceLocationException.AUTHENTICATION_ABSENT,
				"auth_classes_missing",
				new Object[0]);
	}

	return AuthBlock.makeAuthBlocks(message, lifetime);
    }

    // Get an SLPAuthBlockList, checking first if security is enabled.

    Hashtable getCheckedAuthBlockList(Object[] message,
				      byte nauth,
				      DataInputStream dis)
	throws ServiceLocationException, IOException {

	if (!SLPConfig.getSLPConfig().getHasSecurity()) {
	    throw
		new ServiceLocationException(
				ServiceLocationException.AUTHENTICATION_ABSENT,
				"auth_classes_missing",
				new Object[0]);
	}

	return AuthBlock.makeAuthBlocks(this, message, dis, nauth);
    }

    // Parse in an attribute signature.

    Hashtable parseSignatureIn(Object[] message, DataInputStream dis)
	throws ServiceLocationException, IOException {

	Hashtable auth = null;

	byte[] b = new byte[1];

	dis.readFully(b, 0, 1);
	nbytes += 1;

	byte nauths = (byte)(b[0] & 0xFF);

	if (nauths > 0) {
	    auth = getCheckedAuthBlockList(message, nauths, dis);

	}

	return auth;
    }

    //
    // Utility functions to help with verification of data.
    //

    // Escape tags, check for strings. Trim trailing, leading whitespace,
    //  since it is ignored for matching purposes and tags are only
    //  used for matching.

    void escapeTags(Vector t)
	throws ServiceLocationException {

	int i, n = t.size();

	for (i = 0; i < n; i++) {
	    Object o = t.elementAt(i);

	    if (o instanceof String) {

		// Escape tag.

		String tag =
		    ServiceLocationAttribute.escapeAttributeString((String)o,
								   false);

		t.setElementAt(tag.trim(), i);

	    } else {
		throw
		    new IllegalArgumentException(
		SLPConfig.getSLPConfig().formatMessage("nonstring_tag",
						       new Object[0]));
	    }
	}
    }

    // Unescape tags. Trim trailing and leading whitespace since it is
    //  ignored for matching purposes and tags are only used for matching.

    void unescapeTags(Vector t)
	throws ServiceLocationException {

	int i, n = t.size();

	for (i = 0; i < n; i++) {
	    String tag = (String)t.elementAt(i);

	    tag =
		ServiceLocationAttribute.unescapeAttributeString(tag, false);

	    t.setElementAt(tag.trim(), i);
	}
    }

    // Escape vector of scope strings.

    static void escapeScopeStrings(Vector scopes)
	throws ServiceLocationException {

	int i, n = scopes.size();
	Vector ret = new Vector();

	for (i = 0; i < n; i++) {
	    String scope = (String)scopes.elementAt(i);

	    scopes.setElementAt(
		ServiceLocationAttribute.escapeAttributeString(scope, false),
		i);
	}
    }

    // Unescape vector of scope strings.

    static void unescapeScopeStrings(Vector scopes)
	throws ServiceLocationException {

	int i, n = scopes.size();
	Vector ret = new Vector();

	for (i = 0; i < n; i++) {
	    String scope = (String)scopes.elementAt(i);

	    scopes.setElementAt(
		ServiceLocationAttribute.unescapeAttributeString(scope, false),
		i);
	}
    }

    // Error if somebody tries to do this client side.

    SDAAdvert
	getDAAdvert(short xid,
		    long timestamp,
		    ServiceURL url,
		    Vector scopes,
		    Vector attrs)
	throws ServiceLocationException {

	Assert.slpassert(false,
		      "v2_daadvert_client_side",
		      new Object[0]);

	return null;  // never get here...
    }

    // Reimplement clone() to get the header size right.

    public Object clone()
	throws CloneNotSupportedException {
	SLPHeaderV2 hdr = (SLPHeaderV2)super.clone();

	byte[] langBytes = getStringBytes(locale.toString(),
					  Defaults.UTF8);

	hdr.nbytes = HEADER_BYTES + langBytes.length + 2;  // for error code...

	return hdr;
    }
}
