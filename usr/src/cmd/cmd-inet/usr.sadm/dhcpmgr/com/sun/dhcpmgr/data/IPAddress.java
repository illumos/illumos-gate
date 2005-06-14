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

import java.net.InetAddress;
import java.util.StringTokenizer;
import java.io.Serializable;
import java.text.MessageFormat;

/**
 * This class provides a container for holding IP Addresses.  It is different
 * from java.net.InetAddress in that it allows for constructing an arbitrary IP
 * address, rather than forcing you to use InetAddress.getByName, which can
 * generate all sorts of nasty exception conditions in applets, especially when
 * doing a configuration-type app which handles addresses which are not
 * necessarily resolvable in any nameservice.
 */
public class IPAddress implements Cloneable, Serializable {
    private byte [] bytes = new byte[] { 0, 0, 0, 0 };
    
    // Serialization id for this class
    static final long serialVersionUID = -7439646692550395242L;

    /**
     * Construct an empty address
     */
    public IPAddress() {
    }
    
    /**
     * Construct an address for the dotted-decimal <code>String</code> supplied.
     *
     */
    public IPAddress(String s) throws ValidationException {
	try {
	    // If the input looks like a valid format, try parsing it
	    char [] chars = s.toCharArray();
	    int dots = 0; // Count number of periods
	    for (int i = 0; i < chars.length; ++i) {
		if (Character.isDigit(chars[i])) {
		    continue;
		}
		if ((chars[i] == '.')) {
		    if (++dots > 3) {
			// Too many; we're done
			throwException(s);
		    }
		    continue;
		}
		/*
		 * Can't be an address, so let InetAdddress try to resolve it
		 * as a name
		 */
		InetAddress a = InetAddress.getByName(s);
		bytes = a.getAddress();
		return;
	    }
	    // Looks like an IP address; parse it
	    StringTokenizer st = new StringTokenizer(s, ".");
	    int b = 0;
	    while (st.hasMoreTokens()) {
		/*
		 * Byte won't parse anything larger than 127 since it thinks
		 * everything's signed, so use Short instead
		 */
		short shortVal = Short.parseShort(st.nextToken());
		if (shortVal > 255 || shortVal < 0) {
		    throwException(s);
		}
		bytes[b++] = (byte)shortVal;
	    }
	    if (b < 4) {
		// Not a fully specified address; don't read caller's mind
		throwException(s);
	    }
	} catch (ValidationException e) {
	    // Just re-throw it
	    throw e;
	} catch (Throwable e) {
	    // Convert other exceptions to ValidationException
	    throw new ValidationException(e.getMessage());
	}
    }
    
    /**
     * Construct an IPAddress from an InetAddress
     * @param a The InetAddress to convert
     */
    public IPAddress(InetAddress a) {
	bytes = a.getAddress();
    }
    
    /**
     * Construct an IP address from an arbitrary 32-bit value
     * @param addr The value to use
     */
    public IPAddress(int addr) {
	bytes = new byte[4];
	for (int i = 0; i < 4; ++i) {
	    // Careful; must mask to fight sign-extension
	    bytes[i] = (byte)((addr >> (8 * (3 - i))) & 0xff);
	}
    }
    
    public String toString() {
	StringBuffer b = new StringBuffer();
	for (int i = 0; i < 4; ++i) {
	    if (i != 0) {
		b.append('.');
	    }
	    // Careful; must mask to fight sign-extension
	    b.append((int)bytes[i] & 0xff);
	}
	return b.toString();
    }
    
    /**
     * Convert this address to an <code>int</code>
     * @return The address as an <code>int</code>
     */
    public int intValue() {
	int i = 0;
	for (int j = 0; j < 4; ++j) {
	    // Careful; must mask to fight sign-extension
	    i |= ((int)bytes[j] & 0xff) << (8 * (3 - j));
	}
	return i;
    }
    
    /**
     * Try to convert to a name
     * @return The hostname for this address, if one can be found.  Otherwise,
     *		dotted-decimal form of this address is returned.
     */
    public String getHostName() {
	try {
	    return InetAddress.getByName(toString()).getHostName();
	} catch (Throwable e) {
	    return toString();
	}
    }
    
    /**
     * Provide the individual bytes of the address a la InetAddress
     * @return A byte array of the address
     */
    public byte [] getAddress() {
	return bytes;
    }
    
    /**
     * @return the dotted-decimal string representing this address
     */
    public String getHostAddress() {
	return toString();
    }
    
    /**
     * Compare this IP address to either another IP address or a
     * <code>java.net.InetAddress</code>.
     * @return <code>true</code> if the addresses are the same.
     */
    public boolean equals(Object obj) {
	if (obj == null) {
	    return false;
	}
	
	byte [] ba;
	
	if (obj instanceof InetAddress) {
	    ba = ((InetAddress)obj).getAddress();
	} else if (obj instanceof IPAddress) {
	    ba = ((IPAddress)obj).getAddress();
	} else {
	    return false;
	}
	
	if (ba.length != bytes.length) {
	    return false;
	}
	
	for (int i = 0; i < bytes.length; ++i) {
	    if (ba[i] != bytes[i]) {
		return false;
	    }
	}
	
	return true;
    }

    /**
     * Make a copy of this address
     * @return a new IPAddress
     */
    public Object clone() {
	IPAddress a = new IPAddress();
	a.bytes = (byte [])bytes.clone();
	return a;
    }

    /**
     * Retrieve the IP address as a number suitable for arithmetic operations.
     * We use a <code>long</code> rather than an <code>int</code> in order to
     * be able to treat it as an unsigned value, since all Java types are
     * signed.
     * @return The IP address as a <code>long</code>.
     */
    public long getBinaryAddress() {
	byte [] bytes = getAddress();
	long result = 0;
	for (int i = 0; i < bytes.length; ++i) {
	    // Defeat sign extension with cast & mask
	    result |= ((long)bytes[i] & 0xff) << (24-(i*8));
	}
	return result;
    }

    private void throwException(String s)
	throws ValidationException {
	Object [] args = { s };
	MessageFormat form = new MessageFormat(
	    ResourceStrings.getString("invalid_ip_address"));
	String msg = form.format(args);
	throw new ValidationException(msg);
    }
}
