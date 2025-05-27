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

//  SLPHeaderV1.java: SLPv1 Header.
//  Author:           James Kempf
//  Created On:       Thu Sep 10 15:12:14 1998
//  Last Modified By: James Kempf
//  Last Modified On: Wed Jan 20 15:38:07 1999
//  Update Count:     59
//

package com.sun.slp;

import java.util.*;
import java.io.*;

/**
 * The SLPHeaderV1 class models the SLPv1 server side header.
 *
 * @author James Kempf
 */

class SLPHeaderV1 extends SrvLocHeader implements Cloneable {

    // Version number.

    static int VERSION = 1;

    // Function code for message reply.

    int replyFunctionCode = SrvLocHeader.SrvAck;

    // Various header flags.

    protected static final int NOFLAG   = 0x00;
    protected static final int OVERFLOW = 0x80;
    protected static final int MONOLING = 0x40;
    protected static final int URLSIG   = 0x20;
    protected static final int ATTRSIG  = 0x10;
    protected static final int FRESH    = 0x08;

    protected static int LANG_CODE_BYTES = 2;

    protected static int HEADER_BYTES =
	VERSION_FUNCTION_BYTES + LANG_CODE_BYTES + 8;

    // Characters to escape.

    final private static String UNESCAPABLE_CHARS = ",=!></*()";
    final private static String ESCAPABLE_CHARS =
	UNESCAPABLE_CHARS + "&#;";

    String charCode = IANACharCode.UTF8;	// character encoding.
    boolean monolingual = false;		// monolingual flag.

    // Used to construct a header in SrvLocHeader.newInstance().

    SLPHeaderV1() {
	super();

	version = VERSION;

    }

    // Assign reply code based on function code type, then use superclass
    //  method to parse header.

    void parseHeader(int functionCode, DataInputStream dis)
	throws ServiceLocationException, IOException {

	this.functionCode = functionCode;

	// We ignore the error case here.

	switch (functionCode) {

	case SrvLocHeader.SrvReq:
	    replyFunctionCode = SrvLocHeader.SrvRply;
	    break;

	case SrvLocHeader.AttrRqst:
	    replyFunctionCode = SrvLocHeader.AttrRply;
	    break;

	case SrvLocHeader.SrvTypeRqst:
	    replyFunctionCode = SrvLocHeader.SrvTypeRply;
	    break;

	}

	length     = getInt(dis);
	byte flags   = (byte) ((char)dis.read() & 0xFF);
	nbytes++;

	overflow = ((flags & OVERFLOW) != 0x00);
	fresh = false; // fresh gets set on output in SLPv1
	monolingual = ((flags & MONOLING) != 0x00);
	boolean urlAuth = ((flags & URLSIG) != 0x00);
	boolean attrAuth = ((flags & ATTRSIG) != 0x00);

	// Security not handled for SLPv1.

	if (urlAuth || attrAuth) {
	    throw
		new ServiceLocationException(
				ServiceLocationException.AUTHENTICATION_FAILED,
				"v1_no_security",
				new Object[0]);
	}

	int dialect    = (int) ((char)dis.read() & 0xFF);
	nbytes++;

	// Dialect must be zero.

	if (dialect != 0) {
	    throw
		new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"v1_nonzero_dialect",
				new Object[0]);

	}

	byte a_bTemp[] = new byte[LANG_CODE_BYTES];
	a_bTemp[0] = (byte) dis.read();
	a_bTemp[1] = (byte) dis.read();
	nbytes += 2;

	try {
	    locale = new Locale(new String(a_bTemp, IANACharCode.ASCII), "");

	} catch (UnsupportedEncodingException ex) {

	}

	int intCharCode = getInt(dis);
	charCode = IANACharCode.decodeCharacterEncoding(intCharCode);

	xid     = (short)getInt(dis);

	errCode = ServiceLocationException.OK;
    }

    // Parse an incoming V1 message and return the SrvLocMsg object.

    SrvLocMsg parseMsg(DataInputStream dis)
	throws ServiceLocationException,
	       IOException,
	       IllegalArgumentException {

	SrvLocMsg msg = null;

	// If this is a *multicast* request, we reject it except for DAAdvert.
	//  Multicast requests are only taken by SA servers.

	if (mcast && (functionCode != SrvLocHeader.DAAdvert)) {
	    return null;

	}

	// Switch and convert according to function code.

	switch (functionCode) {

	case SrvLocHeader.SrvReq:
	    msg = new SLPV1SSrvMsg(this, dis);
	    break;

	case SrvLocHeader.SrvReg:
	    msg = new SLPV1SSrvReg(this, dis);
	    break;

	case SrvLocHeader.SrvDereg:
	    msg = new SLPV1SSrvDereg(this, dis);
	    break;

	case SrvLocHeader.AttrRqst:
	    msg = new SLPV1SAttrMsg(this, dis);
	    break;

	case SrvLocHeader.SrvTypeRqst:
	    msg = new SLPV1SSrvTypeMsg(this, dis);
	    break;

	case SrvLocHeader.DAAdvert:
	    msg = new SLPV1CDAAdvert(this, dis);
	    break;

	default:
	    throw
		new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"function_code_error",
				new Object[] {
		    Integer.valueOf(functionCode)});

	}

	// Check for size overflow.

	if (nbytes > length) {
	    throw
		new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"length_overflow",
				new Object[] {
		    Integer.valueOf(nbytes), Integer.valueOf(length)});

	}

	return msg;

    }

    // Externalize the message by converting it to bytes and writing
    //  it to the output stream.

    public void
	externalize(ByteArrayOutputStream baos, boolean mcast, boolean isTCP)
	throws ServiceLocationException {

	// Need to put in the error code or previous responders.

	ByteArrayOutputStream fin = new ByteArrayOutputStream();

	if (functionCode == SrvLocHeader.SrvAck ||
	    functionCode == SrvLocHeader.SrvTypeRply ||
	    functionCode == SrvLocHeader.SrvRply ||
	    functionCode == SrvLocHeader.AttrRply ||
	    functionCode == SrvLocHeader.DAAdvert) {
	    putInt(errCode, fin);

	} else {

	    // Parse out previous responders. Note there will only be some
	    //  if the error code is not put out.

	    if (previousResponders != null) {
		parseCommaSeparatedListOut(previousResponders, fin);

	    }
	}

	// Parse payload out if error code is OK and payload is nonnull.

	if (payload != null && errCode == ServiceLocationException.OK) {
	    fin.write(payload, 0, payload.length);
	}

	// Don't touch payload here, somebody may put in a previousResponder
	//  and resend the message.

	byte[] npayload = fin.toByteArray();

	// Set overflow flag if buffer is too large and this isn't going out
	//  via TCP.

	if (((npayload.length + 12) > SLPConfig.getSLPConfig().getMTU()) &&
	    !isTCP) {
	    overflow = true;

	}

	baos.write((byte) (0xFF & version));
	nbytes++;
	baos.write((byte) (0xFF & functionCode));
	nbytes++;

	length = npayload.length +12; // the 12 is the length of this header!

	putInt(length, baos);  // what about overflow???

	byte flags = 0X00;

	if (overflow) {
	    flags = (byte)(flags | OVERFLOW);
	} else {
	    flags = (byte)(flags & ~OVERFLOW);
	}

	if (monolingual) {
	    flags = (byte)(flags | MONOLING);
	} else {
	    flags = (byte)(flags & ~MONOLING);
	}

	if (fresh) {
	    flags = (byte)((flags | FRESH) & 0XFF);
	} else {
	    flags = (byte)((flags & ~FRESH) & 0XFF);
	}

	baos.write((byte) (0xFF & flags));
	nbytes++;
	baos.write((byte) (0xFF & 0)); // dialect...
	nbytes++;

	String language = locale.getLanguage();

	baos.write((byte) (0xFF & language.charAt(0)));
	baos.write((byte) (0xFF & language.charAt(1)));
	nbytes += 2;

	int intCharCode = 0;

	try {
	    intCharCode = IANACharCode.encodeCharacterEncoding(charCode);

	} catch (ServiceLocationException ex) {
	    Assert.slpassert(false,
			  "v1_unsupported_encoding",
			  new Object[] {charCode});

	}

	putInt(intCharCode, baos);
	putInt(xid, baos);

	// Write the body.

	baos.write(npayload, 0, npayload.length);
	nbytes += npayload.length;
    }

    // Create an error reply using the reply code. Calculate the
    //  error code using the exception.

    SrvLocMsg makeErrorReply(Exception ex) {

	// If this is a DAAdvert, then no error reply is returned
	//  because V1 doesn't support unicast SrvRqst for DAAdvert.

	if (functionCode == SrvLocHeader.DAAdvert) {
	    return null;

	}

	// Clone the header to make sure that everything else is the same.
	//  We don't want to use the same header because it may be tested
	//  elsewhere.

	SLPHeaderV1 hdr = null;

	try {
	    hdr = (SLPHeaderV1)this.clone();

	} catch (CloneNotSupportedException exx) {

	    // We know we support it.

	}

	hdr.fresh = false;
	hdr.overflow = false;
	hdr.mcast = false;
	hdr.functionCode = replyFunctionCode;

	// We should *not* be getting a null exception down this path!

	Assert.slpassert(ex != null,
		      "null_parameter",
		      new Object[] {ex});

	if (ex instanceof ServiceLocationException) {

	    hdr.errCode = ((ServiceLocationException)ex).getErrorCode();

	    // Handle monolingual bit here. If the exception is
	    //  LANGUAGE_NOT_SUPPORTED and the message type is
	    //  either SrvRqst or AttrRqst, then we simply return an
	    //  empty message unless the monolingual flag is on.

	    if (hdr.errCode ==
		ServiceLocationException.LANGUAGE_NOT_SUPPORTED) {

		try {

		    if (!hdr.monolingual) {

			if (hdr.functionCode == SrvLocHeader.SrvReq) {

			    return SLPV1SSrvMsg.makeEmptyReply(hdr);

			} else if (hdr.functionCode == SrvLocHeader.AttrRqst) {

			    return SLPV1SAttrMsg.makeEmptyReply(hdr);

			}
		    }

		} catch (ServiceLocationException exx) {

		    hdr.monolingual = true;
		    hdr.makeErrorReply(exx);

		}

		// Otherwise, we just ignore it.
	    }

	    // Anything over AUTHENTICATION_FAILED is an internal error in V1.

	    if (hdr.errCode > ServiceLocationException.AUTHENTICATION_FAILED) {
		hdr.errCode = ServiceLocationException.PARSE_ERROR;

	    }

	} else if (ex instanceof IllegalArgumentException ||
		   ex instanceof IOException) {
	    hdr.errCode = ServiceLocationException.PARSE_ERROR;

	} else {
	    hdr.errCode = ServiceLocationException.PARSE_ERROR;

	}

	// Construct header description.

	hdr.constructDescription("SrvLocMsg", "");

	return hdr;
    }

    // Return a reply header with flags properly set.

    SLPHeaderV1 makeReplyHeader() {

	SLPHeaderV1 hdr = null;

	try {
	    hdr = (SLPHeaderV1)this.clone();

	} catch (CloneNotSupportedException ex) {

	    // We know that we support it.
	}

	hdr.functionCode = replyFunctionCode;
	hdr.length = 0;
	hdr.previousResponders = null;
	hdr.scopes = null;
	hdr.overflow = false;
	hdr.fresh = false;
	hdr.mcast = false;
	hdr.nbytes = 0;

	return hdr;
    }

    // Return display string.

    public String toString() {
	return
	    getMsgType() + ":version=``" + version + "''\n" +
	    "       functionCode=``" + functionCode + "''\n" +
	    "       length=``" + length + "''\n" +
	    "       overflow=``" + overflow + "''\n" +
	    "       mcast = ``" + mcast + "''\n" +
	    "       fresh=``" + fresh + "''\n" +
	    "       monolingual=``" + monolingual + "''\n" +
	    "       charCode=``" + charCode + "''\n" +
	    "       locale = ``" + locale + "''\n" +
	    "       xid=``0x" + Integer.toHexString(xid) + "''\n" +
	    "       errCode=``" + errCode + "''\n" +
	    "       previousResponders=``" + previousResponders + "''\n" +
	    "       scopes=``" + scopes + "''\n" +
	    getMsgDescription();
    }

    //
    // Validation Utilities.
    //

    /**
     * Validate the scope name to be sure it doesn't contain forbidden
     * chars and isn't one of the reserved scope names.
     */

    static void validateScope(String scope)
	throws ServiceLocationException
    {
	if (scope.indexOf('/') != -1 || scope.indexOf(',') != -1 ||
	    scope.indexOf(':') != -1) {
	    throw new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"v1_scope_char_res",
				new Object[] {scope});
	}

	// Check against reserved scope names.

	if (scope.equalsIgnoreCase("local") ||
	    scope.equalsIgnoreCase("remote")) {
	    throw new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"v1_scope_name_res",
				new Object[] {scope});
	}

    }

    /**
     * Remove IANA from the service type name.
     *
     * @param serviceType The service type and naming authority.
     * @return The service type name with IANA removed.
     */

    static String removeIANA(String serviceType) {

	// Substitute null string for IANA.

	int idx = 0;

	serviceType = serviceType.toLowerCase();

	if ((idx = serviceType.indexOf("." + ServiceType.IANA)) != -1) {
	    serviceType = serviceType.substring(0, idx);

	}

	return serviceType;
    }

    // Check whether this is a vaild SLPv1 service type. Also remove
    //  IANA.

    static String checkServiceType(String stype)
	throws ServiceLocationException {

	// Check for trailing colon and remove it.

	if (!stype.endsWith(":")) {
	    throw
		new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"v1_service_type_format",
				new Object[] {stype});

	}

	String type = stype.substring(0, stype.length()-1);

	// Remove IANA.

	type = removeIANA(type);

	// Check syntax.

	ServiceType st = new ServiceType(type);

	// Reject if abstract type. SLPv1 doesn't handle
	//  abstract types.

	if (st.isAbstractType()) {
	    throw
		new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"v1_abstract_type",
				new Object[0]);

	}

	// Reject if not a service: type. SLPv1 doesn't handle
	//  nonservice: types.

	if (!st.isServiceURL()) {
	    throw
		new ServiceLocationException(
				ServiceLocationException.PARSE_ERROR,
				"v1_not_surl",
				new Object[0]);

	}

	return type;
    }

    //
    // Parsing Utilities.
    //

    // Parse string, bump byte count.

    byte[] getString(StringBuffer buf, DataInputStream dis)
	throws ServiceLocationException, IOException {

	int i, n = 0;

	// Get length.

	n = getInteger(dis);

	byte[] bytes = new byte[n];

	// Read bytes.

	dis.readFully(bytes, 0, n);

	// If the encoding type is Unicode, then figure out first
	//  whether it's big or little endian from byte header. Future
	//  calls won't have to go through this grief unless the byte header
	//  is missing.

	if (this.charCode == IANACharCode.UNICODE) {

	    this.charCode = IANACharCode.getUnicodeEndianess(bytes);

	}

	String charCode = this.charCode;

	// If we are still just Unicode by this point, then we need to
	//  add the big endian bytes to the beginning of the array.
	//  Otherwise, Java won't parse it. Note that we don't change
	//  the flag in the header, since we will need to convert the
	//  next time around as well.

	if (charCode == IANACharCode.UNICODE) {
	    charCode = IANACharCode.UNICODE_BIG;

	    bytes = IANACharCode.addBigEndianFlag(bytes);

	}

	// Convert the bytes into a string.

	buf.setLength(0);

	buf.append(getBytesString(bytes, charCode));

	return bytes;
    }

    // Parse out string, bump byte count. Use header encoding.

    byte[] putString(String string, ByteArrayOutputStream baos) {

	// If the charCode is UNICODE, arbirtarily change to big or little,
	//  while Java will parse.

	if (charCode == IANACharCode.UNICODE) {
	    charCode = IANACharCode.UNICODE_BIG;

	}

	byte[] bytes = putStringField(string, baos, charCode);

	nbytes += bytes.length;

	return bytes;

    }

    // Parse in a service URL including lifetime if necessary.

    protected ServiceURL
	parseServiceURLIn(DataInputStream dis,
			  boolean lifeTimeToo,
			  short errCode)
	throws ServiceLocationException, IOException {

	int lifetime = 0;
	StringBuffer buf = new StringBuffer();

	if (lifeTimeToo) {
	    lifetime = getInt(dis);
	}

	getString(buf, dis);

	ServiceURL url = null;

	try {

	    url = new ServiceURLV1(buf.toString(), lifetime);

	} catch (IllegalArgumentException ex) {

	    throw
		new ServiceLocationException(errCode,
					     "malformed_url",
					     new Object[] {ex});
	}

	return url;
    }

    // Parse out a service URL including lifetime if required.

    void
	parseServiceURLOut(ServiceURL surl,
			   boolean lifetimeToo,
			   ByteArrayOutputStream baos)
	throws ServiceLocationException {

	String ssurl = surl.toString();

	if (lifetimeToo) {
	    putInt(surl.getLifetime(), baos);
	}

	putString(ssurl, baos);

    }

    // Parse in a list of attributes, returing a vector of
    //  ServiceLocationAttribute objects.

    protected Vector parseAttributeVectorIn(DataInputStream dis)
	throws ServiceLocationException, IOException {

	StringBuffer buf = new StringBuffer();

	getString(buf, dis);

	SLPConfig config = SLPConfig.getSLPConfig();

	// Parse the list into ServiceLocationAttribute objects.

	Vector attrForms = parseCommaSeparatedListIn(buf.toString(), false);

	int i, n = attrForms.size();

	for (i = 0; i < n; i++) {
	    String attrForm =
		(String)attrForms.elementAt(i);

	    attrForms.setElementAt(new ServiceLocationAttributeV1(attrForm,
								  charCode,
								  false),
				   i);
	}

	return attrForms;
    }

    // Parse out a V1 attribute vector.

    void
	parseAttributeVectorOut(Vector attrs,
				ByteArrayOutputStream baos)
	throws ServiceLocationException {

	Enumeration en = attrs.elements();
	Vector strings = new Vector();

	// Convert the attributes to strings, escaping characters to
	//  escape.

	while (en.hasMoreElements()) {
	    ServiceLocationAttribute attr =
		(ServiceLocationAttribute)en.nextElement();

	    // Make an SLPv1 attribute out of it, so we can
	    //  externalize it with the v1 encoding scheme.

	    ServiceLocationAttributeV1 attrv1 =
		new ServiceLocationAttributeV1(attr);
	    attrv1.charCode = charCode;
	    String out = attrv1.externalize();

	    strings.addElement(out);

	}

	// Parse it out.

	parseCommaSeparatedListOut(strings, baos);

    }

    // Parse in previous responders.

    void parsePreviousRespondersIn(DataInputStream dis)
	throws ServiceLocationException, IOException {

	StringBuffer buf = new StringBuffer();

	getString(buf, dis);

	previousResponders =
	    parseCommaSeparatedListIn(buf.toString(), true);

    }

    // Put out a vector of strings.

    void putStringVector(Vector v, ByteArrayOutputStream baos) {

	int i, n = v.size();

	// Put out the total number of strings.

	putInt(n, baos);

	// Put out the strings.

	for (i = 0; i < n; i++) {

	    putString((String)v.elementAt(i), baos);
	}
    }

    // Return an SLPv1 DAAdvert.

    SDAAdvert
	getDAAdvert(short xid,
		    long timestamp,
		    ServiceURL url,
		    Vector scopes,
		    Vector attrs)
	throws ServiceLocationException {

	// If scopes vector is null, then return all scopes for this
	//  DA.

	if (scopes.size() <= 0) {
	    scopes = SLPConfig.getSLPConfig().getSAConfiguredScopes();

	}

	return new SLPV1SDAAdvert(this, xid, timestamp, url, scopes, attrs);

    }

    // Reimplement clone() to get the header size right.

    public Object clone()
	throws CloneNotSupportedException {
	SLPHeaderV1 hdr = (SLPHeaderV1)super.clone();

	hdr.nbytes = HEADER_BYTES + 2;  // for error code...

	return hdr;
    }
}
