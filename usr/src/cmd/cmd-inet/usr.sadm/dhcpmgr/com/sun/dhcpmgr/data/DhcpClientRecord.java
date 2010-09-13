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
 * Copyright 1998-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

package com.sun.dhcpmgr.data;

import java.util.Date;
import java.text.SimpleDateFormat;
import java.text.DateFormat;
import java.util.StringTokenizer;
import java.io.Serializable;

/**
 * This class represents a record in a DHCP network table.  It can also be used
 * to manage an associated hosts record by setting the client name; that effect
 * is not part of this class, but rather is provided by the DhcpNetMgr.
 */
public class DhcpClientRecord implements Serializable, Comparable, Cloneable {

    /**
     * Default values for class attributes.
     */
    public static final String DEFAULT_CLIENT_ID	= new String("00");
    public static final String DEFAULT_FLAGS		= new String("00");
    public static final String DEFAULT_CLIENT_NAME	= new String();
    public static final String DEFAULT_EXPIRATION	= new String("0");
    public static final String DEFAULT_SIGNATURE	= new String("0");
    public static final String DEFAULT_MACRO		= new String("UNKNOWN");
    public static final String DEFAULT_COMMENT		= new String();
    
    /**
     * Expiration special values.
     */
    private static final String EXPIRATION_ZERO		= new String("0");
    private static final String EXPIRATION_FOREVER	= new String("-1");

    private String clientId;
    private byte flags;
    private IPAddress clientIP;
    private IPAddress serverIP;
    private Date expiration;
    private String signature = DEFAULT_SIGNATURE;
    private String macro;
    private String comment;
    private String clientName = null;
    private String serverName = null;

    // Serialization id of this class
    static final long serialVersionUID = 5007310554198923085L;

    /**
     * Constructs a basic, empty client record.
     */
    public DhcpClientRecord() {
	clientId = DEFAULT_CLIENT_ID;
	macro = comment = null;
	flags = 0;
	clientIP = serverIP = null;
	expiration = null;
	signature = DEFAULT_SIGNATURE;
    }

    /**
     * Constructs a client record with a client IP.
     * @param clientIP the client IP address for the record.
     */
    public DhcpClientRecord(String clientIP) throws ValidationException {
	setDefaults();
	setClientIP(new IPAddress(clientIP));
    }
    
    /**
     * Constructs a fully specified client record
     * @param clientId Client's unique identifier
     * @param flags Status flags for the record
     * @param clientIP Client's IP address
     * @param serverIP IP address of owning server
     * @param expiration Lease expiration time in seconds since Unix epoch
     * @param macro Configuration macro associated with this record
     * @param comment User notes on this record
     */
    public DhcpClientRecord(String clientId, String flags, String clientIP,
			    String serverIP, String expiration, String macro,
			    String comment) throws ValidationException {
	
	this(clientId, flags, clientIP, serverIP, expiration, macro,
			    comment, DEFAULT_SIGNATURE);
	}

    /**
     * Constructs a fully specified client record
     * @param clientId Client's unique identifier
     * @param flags Status flags for the record
     * @param clientIP Client's IP address
     * @param serverIP IP address of owning server
     * @param expiration Lease expiration time in seconds since Unix epoch
     * @param macro Configuration macro associated with this record
     * @param comment User notes on this record
     * @param signature Opaque signature
     */
    public DhcpClientRecord(String clientId, String flags, String clientIP,
			    String serverIP, String expiration, String macro,
			    String comment, String signature)
				throws ValidationException {
	setClientId(clientId);
	this.flags = Byte.parseByte(flags);
	setClientIP(new IPAddress(clientIP));
	setServerIP(new IPAddress(serverIP));
	setExpiration(expiration);
	this.macro = macro;
	this.comment = comment;
	this.signature = signature;
    }
    
    /**
     * Make a copy of this record
     */
    public Object clone() {
	DhcpClientRecord newrec = new DhcpClientRecord();
	newrec.clientId = clientId;
	newrec.flags = flags;
	if (clientIP != null) {
	    newrec.clientIP = (IPAddress)clientIP.clone();
	}
	if (serverIP != null) {
	    newrec.serverIP = (IPAddress)serverIP.clone();
	}
	if (expiration != null) {
	    newrec.expiration = (Date)expiration.clone();
	}
	newrec.macro = macro;
	newrec.comment = comment;
	newrec.clientName = clientName;
	newrec.serverName = serverName;
	newrec.signature = signature;
	return newrec;
    }
    
    /**
     * Fully specifies the defaults for a client record
     */
    public void setDefaults()
	throws ValidationException {
	setClientId(DEFAULT_CLIENT_ID);
	setFlags(DEFAULT_FLAGS);
	setClientName(DEFAULT_CLIENT_NAME);
	setExpiration(DEFAULT_EXPIRATION);
	setMacro(DEFAULT_MACRO);
	setComment(DEFAULT_COMMENT);
    }

    /**
     * Retrieve the client ID
     * @return Client ID as a String
     */
    public String getClientId() {
	return clientId;
    }
    
    /**
     * Set the client ID.  See dhcp_network(4) for the rules about client
     * ID syntax which are implemented here.
     * @param clientId Client's unique identifier
     */
    public void setClientId(String clientId) throws ValidationException {
	if (clientId.length() > 128 || clientId.length() % 2 != 0) {
	    // Must be even number of characters, no more than 128 characters
	    String msg = ResourceStrings.getString("dcr_invalid_clientid");
	    throw new ValidationException(msg);
	}
	char [] c = clientId.toCharArray();
	for (int i = 0; i < c.length; ++i) {
	    if ((c[i] < '0' || c[i] > '9') && (c[i] < 'A' || c[i] > 'F')) {
		String msg = ResourceStrings.getString("dcr_invalid_clientid");
		throw new ValidationException(msg);
	    }
	}
	this.clientId = clientId;
	if (this.clientId.length() == 0) {
	    this.clientId = DEFAULT_CLIENT_ID;
	}
    }
    
    /**
     * Get the flags byte
     * @return A <code>byte</code> containing the record's status flags
     */
    public byte getFlags() {
	return flags;
    }
    
    /**
     * Get the flags as a string
     * @return The flag byte converted to a String
     */
    public String getFlagString() {
	return getFlagString(false);
    }
    
    public String getFlagString(boolean verbose) {

	StringBuffer b = new StringBuffer();
	if (!verbose) {
	    b.append(flags);
	    // Make sure we always have a 2-character representation.
	    if (flags < 10) {
		b.insert(0, 0);
	    }
	} 
	else {
	    if (flags == 0) {
		b.append(DhcpClientFlagTypes.DYNAMIC.getCharVal());
	    } else {
		if (isPermanent()) {
		    b.append(DhcpClientFlagTypes.PERMANENT.getCharVal());
		}
		if (isManual()) {
		    b.append(DhcpClientFlagTypes.MANUAL.getCharVal());
		}
		if (isUnusable()) {
		    b.append(DhcpClientFlagTypes.UNUSABLE.getCharVal());
		}
		if (isBootp()) {
		    b.append(DhcpClientFlagTypes.BOOTP.getCharVal());
		}
	    }
	}
	return b.toString();
    }

    /**
     * Test for setting of unusable flag
     * @return <code>true</code> if the unusable flag is set, 
     * <code>false</code> if not.
     */
    public boolean isUnusable() {
	return DhcpClientFlagTypes.UNUSABLE.isSet(flags);
    }
    
    /**
     * Set/reset the unusable flag.
     * @param state <code>true</code> if address is to be unusable
     */
    public void setUnusable(boolean state) {
	if (state) {
	    flags |= DhcpClientFlagTypes.UNUSABLE.getNumericVal();
	} else {
	    flags &= ~DhcpClientFlagTypes.UNUSABLE.getNumericVal();
	}
    }
    
    /**
     * Test for setting of bootp flag
     * @return <code>true</code> if the bootp flag is set,
     * <code>false</code> if not.
     */
    public boolean isBootp() {
	return DhcpClientFlagTypes.BOOTP.isSet(flags);
    }
    
    /**
     * Set/reset the bootp flag
     * @param state <code>true</code> if address is reserved for BOOTP clients
     */
    public void setBootp(boolean state) {
	if (state) {
	    flags |= DhcpClientFlagTypes.BOOTP.getNumericVal();
	} else {
	    flags &= ~DhcpClientFlagTypes.BOOTP.getNumericVal();
	}
    }
    
    /**
     * Test for setting of manual assignment flag
     * @return <code>true</code> if address is manually assigned,
     * <code>false</code> if not.
     */
    public boolean isManual() {
	return DhcpClientFlagTypes.MANUAL.isSet(flags);
    }
    
    /**
     * Set/reset the manual assignment flag
     * @param state <code>true</code> if the address is manually assigned
     */
    public void setManual(boolean state) {
	if (state) {
	    flags |= DhcpClientFlagTypes.MANUAL.getNumericVal();
	} else {
	    flags &= ~DhcpClientFlagTypes.MANUAL.getNumericVal();
	}
    }
    
    /**
     * Test for setting of permanent assignment flag
     * @return <code>true</code> if lease is permanent,
     * <code>false</code> if dynamic
     */
    public boolean isPermanent() {
	return DhcpClientFlagTypes.PERMANENT.isSet(flags);
    }
    
    /**
     * Set/reset the permanent assignment flag
     * @param state <code>true</code> if the address is permanently leased
     */
    public void setPermanent(boolean state) {
	if (state) {
	    flags |= DhcpClientFlagTypes.PERMANENT.getNumericVal();
	} else {
	    flags &= ~DhcpClientFlagTypes.PERMANENT.getNumericVal();
	}
    }
    
    /**
     * Set the flags as a unit
     * @param flags a <code>byte</code> setting for the flags
     */
    public void setFlags(String flags) throws ValidationException {
	if (flags.charAt(0) >= '0' && flags.charAt(0) <= '9') {
	    this.flags = Byte.parseByte(flags);
	} else {
	    this.flags = 0;
	    StringTokenizer flagTokenizer = new StringTokenizer(flags, "+");
	    while (flagTokenizer.hasMoreTokens()) {
		String keyword = flagTokenizer.nextToken();
		if (keyword.equalsIgnoreCase(
		    DhcpClientFlagTypes.DYNAMIC.getKeyword())) {
		    // nothing to do, default is Dynamic.
		} else if (keyword.equalsIgnoreCase(
		    DhcpClientFlagTypes.PERMANENT.getKeyword())) {
		    this.flags |= DhcpClientFlagTypes.PERMANENT.getNumericVal();
		} else if (keyword.equalsIgnoreCase(
		    DhcpClientFlagTypes.MANUAL.getKeyword())) {
		    this.flags |= DhcpClientFlagTypes.MANUAL.getNumericVal();
		} else if (keyword.equalsIgnoreCase(
		    DhcpClientFlagTypes.UNUSABLE.getKeyword())) {
		    this.flags |= DhcpClientFlagTypes.UNUSABLE.getNumericVal();
		} else if (keyword.equalsIgnoreCase(
		    DhcpClientFlagTypes.BOOTP.getKeyword())) {
		    this.flags |= DhcpClientFlagTypes.BOOTP.getNumericVal();
		} else {
		    String msg = ResourceStrings.getString("dcr_invalid_flags");
		    throw new ValidationException(msg);
		}
	    }
	}
    }

    /**
     * Set the flags as a unit
     * @param flags a <code>byte</code> setting for the flags
     */
    public void setFlags(byte flags) {
	this.flags = flags;
    }
    
    /**
     * Retrieve the client's IP address
     * @return the client's IP address
     */
    public IPAddress getClientIP() {
	return clientIP;
    }
    
    /**
     * Retrieve a string version of the client's IP address
     * @return A <code>String</code> containing the dotted decimal IP address.
     */
    public String getClientIPAddress() {
	if (clientIP == null) {
	    return "";
	} else {
	    return clientIP.getHostAddress();
	}
    }
    
    /**
     * Set the client's IP address
     * @param clientIP A String representation of the <code>IPAddress</code>
     * to assign from this record.
     */
    public void setClientIP(String clientIP) throws ValidationException {
	if (clientIP == null) {
	    String msg = ResourceStrings.getString("dcr_invalid_null_clientip");
	    throw new ValidationException(msg);
	}

	try {
	    setClientIP(new IPAddress(clientIP));
	} catch (Throwable e) {
	    String msg = ResourceStrings.getString("dcr_invalid_clientip");
	    throw new ValidationException(msg);
	}
    }
    
    /**
     * Set the client's IP address
     * @param clientIP An <code>IPAddress</code> to assign from this record.
     */
    public void setClientIP(IPAddress clientIP) throws ValidationException {
	if (clientIP == null) {
	    String msg = ResourceStrings.getString("dcr_invalid_null_clientip");
	    throw new ValidationException(msg);
	}
	this.clientIP = clientIP;
    }
    
    /**
     * Retrieve the IP address of the owning server.
     * @return An <code>IPAddress</code> for the server controlling this record.
     */
    public IPAddress getServerIP() {
	return serverIP;
    }
    
    /**
     * Retrieve a string version of the owning server's IP address
     * @return The server's dotted decimal IP address as a <code>String</code>
     */
    public String getServerIPAddress() {
	if (serverIP == null) {
	    return "";
	} else {
	    return serverIP.getHostAddress();
	}
    }
    
    /**
     * Set the server's IP address
     * @param serverIP A String representation of the <code>IPAddress</code>
     * to assign from this record.
     */
    public void setServerIP(String serverIP) throws ValidationException {
	if (serverIP == null) {
	    String msg = ResourceStrings.getString("dcr_invalid_null_serverip");
	    throw new ValidationException(msg);
	}

	try {
	    setServerIP(new IPAddress(serverIP));
	} catch (Throwable e) {
	    String msg = ResourceStrings.getString("dcr_invalid_serverip");
	    throw new ValidationException(msg);
	}
    }

    /**
     * Assign this address to a server denoted by its IP address
     * @param serverIP The <code>IPAddress</code> of the owning server.
     */
    public void setServerIP(IPAddress serverIP) throws ValidationException {
	if (serverIP == null) {
	    String msg = ResourceStrings.getString("dcr_invalid_null_serverip");
	    throw new ValidationException(msg);
	}
	this.serverIP = serverIP;
    }
    
    /**
     * @return The expiration time of this record's lease as a <code>Date</code>
     */
    public Date getExpiration() {
	return expiration;
    }
    
    /**
     * @return The expiration time of this record's lease in seconds
     * since the epoch, as a <code>String</code>
     */
    public String getExpirationTime() {
	if (expiration == null) {
	    return null;
	}
	if (expiration.getTime() == Long.parseLong(EXPIRATION_FOREVER)) {
	    return EXPIRATION_FOREVER;
	} else {
	    return String.valueOf((expiration.getTime()/(long)1000));
	}
    }
    
    /**
     * Set the lease expiration date.
     * @param expiration Lease expiration time in seconds since Unix epoch
     */
    public void setExpiration(String expiration) {
	this.expiration = new Date((long)(Long.parseLong(expiration)*1000));
    }
    
    /**
     * Set the lease expiration date.
     * @param expiration The <code>Date</code> when the lease expires.
     */
    public void setExpiration(Date expiration) {
	this.expiration = expiration;
    }
    
    /**
     * Set the lease expiration date by parsing a formatted string.  Also
     * provides special handling of the "0" and "-1" values.
     * @param dateFormat A DateFormat used to parse the expiration date
     * @param date Lease expiration in desired format.
     */
    public void setExpiration(DateFormat dateFormat, String date)
	throws ValidationException {

	if (date == null) {
	    setExpiration(date);
	} else if (date.equals(EXPIRATION_ZERO)) {
	    setExpiration(date);
	} else if (date.equals(EXPIRATION_FOREVER)) {
	    setExpiration(date);
	} else {
	    try {
		expiration = dateFormat.parse(date);
	    } catch (Exception ex) {
		String msg =
		    ResourceStrings.getString("dcr_invalid_expiration");
		throw new ValidationException(msg);
	    }
	}
    }
    
    /**
     * @return The name of the macro used to explicitly configure this address
     */
    public String getMacro() {
	return macro;
    }
    
    /**
     * Set the name of the macro used to explicitly configure this address
     */
    public void setMacro(String macro) {
	this.macro = macro;
    }
    
    /**
     * @return The descriptive comment for this record
     */
    public String getComment() {
	return comment;
    }
    
    /**
     * Set a descriptive comment for this record
     * @param comment The comment
     */
    public void setComment(String comment) {
	this.comment = comment;
    }
    
    /**
     * @return The signature for this record
     */
    public String getSignature() {
	return signature;
    }

    /**
     * Set the signature for this record
     * @param signature The new signature value
     */
    public void setSignature(String signature) {
	this.signature = signature;
    }

    /**
     * Perform comparisons to another DhcpClientRecord instance.  This is used
     * for sorting a network table by client address.
     * @param o A <code>DhcpClientRecord</code> to compare against.
     * @return 0 if the objects have the same address,
     * a negative number if this record has a lower IP address than the
     * supplied record, a positive number if this record has a higher IP 
     * address than the supplied record.
     */
    public int compareTo(Object o) {
	DhcpClientRecord r = (DhcpClientRecord)o;
	return (int)(getBinaryAddress() - r.getBinaryAddress());
    }
    
    /**
     * Retrieve the IP address as a number suitable for arithmetic operations.
     * We use a <code>long</code> rather than an <code>int</code> in order to 
     * be able to treat it as an unsigned value, since all Java types are
     * signed.
     * @return The IP address as a <code>long</code>.
     */
    public long getBinaryAddress() {
	return (clientIP.getBinaryAddress());
    }
    
    /**
     * @return The client's hostname
     */
    public String getClientName() {
	if (clientName == null && clientIP != null) {
		clientName = clientIP.getHostName();
	}
	return clientName;
    }

    /**
     * @param name The hostname for the client.
     */
    public void setClientName(String name) {
	clientName = name;
    }
    
    /**
     * @return The server's hostname
     */
    public String getServerName() {
	if (serverName == null && serverIP != null) {
		serverName = serverIP.getHostName();
	}
	return serverName;
    }
    
    /**
     * @param name The server's hostname
     */
    public void setServerName(String name) {
	serverName = name;
    }
    
    public String toString() {

	String server = null;
	if (serverIP != null) {
	    server = serverIP.getHostAddress();
	}

	String client = null;
	if (clientIP != null) {
	    client = clientIP.getHostAddress();
	}

	String expiration = null;
	if (this.expiration != null) {
	    expiration = this.expiration.toString();
	}

	String s = clientId + " " + String.valueOf(flags) + " "
			    + client + " " + server 
		            + " " + expiration + " " + signature 
			    + " " + macro + " " + comment;
	return s;
    }
}
