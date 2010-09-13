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

import java.io.Serializable;
import java.util.StringTokenizer;
import java.text.MessageFormat;

/**
 * A representation of an IP network from DHCP's point of view; we're
 * primarily interested in the address and subnet mask.
 */
public class Network implements Serializable, Comparable {
    private IPAddress address;
    private IPAddress netmask;

    // Serialization id for this class
    static final long serialVersionUID = 7221738570228102243L;
    
    /**
     * Construct an empty network object
     */
    public Network() {
	address = new IPAddress();
	netmask = new IPAddress();
    }
    
    /**
     * Construct a network with the supplied address and a default mask
     * @param addr The IP address of the network
     */
    public Network(IPAddress addr) {
	initialize(addr);
    }

    // Common initialization routine
    private void initialize(IPAddress addr) {
	address = addr;
	// Initialize a default netmask based on address class
	byte [] b = address.getAddress();
	int msb = (int)b[0] & 0xff;
	try {
	    if (msb < 128) {
		netmask = new IPAddress("255.0.0.0");
	    } else if (msb < 192) {
		netmask = new IPAddress("255.255.0.0");
	    } else {
		netmask = new IPAddress("255.255.255.0");
	    }
	} catch (ValidationException e) {
	    // This shouldn't happen, above masks are all valid IP addrs
	}
    }

    /**
     * Construct a network with the supplied address.
     * @param addr The IP address of the network.
     */
    public Network(String addr) throws ValidationException {
	try {
	    initialize(new IPAddress(addr));
	} catch (ValidationException e) {
	    Object [] args = new Object[1];
	    args[0] = addr;
	    MessageFormat form = new MessageFormat(
		ResourceStrings.getString("invalid_network"));
	    String msg = form.format(args);
	    throw new ValidationException(msg);
	}
    }
    
    /**
     * Construct a network with the supplied address and subnet mask
     * @param addr The IP address of the network as a <code>String</code>
     * @param mask The subnet mask as an <code>int</code>
     */
    public Network(String addr, int mask) throws ValidationException {
	try {
	    address = new IPAddress(addr);
	} catch (ValidationException e) {
	    Object [] args = new Object[1];
	    args[0] = addr;
	    MessageFormat form = new MessageFormat(
		ResourceStrings.getString("invalid_network"));
	    String msg = form.format(args);
	    throw new ValidationException(msg);
	}

	netmask = new IPAddress(mask);
    }
    
    /**
     * Construct a network with the supplied address and subnet mask.
     * @param addr The IP address as an <code>IPAddress</code>
     * @param mask The subnet mask as an <code>IPAddress</code>
     */
    public Network(IPAddress addr, IPAddress mask) {
	address = addr;
	netmask = mask;
    }
    
    /**
     * Construct a network with the supplied address and subnet mask.
     * @param addr The IP address as a dotted decimal <code>String</code>
     * @param mask The subnet mask as a dotted decimal <code>String</code>
     */
    public Network(String addr, String mask) throws ValidationException {
	try {
	    address = new IPAddress(addr);
	} catch (ValidationException e) {
	    Object [] args = new Object[1];
	    args[0] = addr;
	    MessageFormat form = new MessageFormat(
		ResourceStrings.getString("invalid_network"));
	    String msg = form.format(args);
	    throw new ValidationException(msg);
	}

	try {
	    netmask = new IPAddress(mask);
	} catch (ValidationException e) {
	    Object [] args = new Object[1];
	    args[0] = mask;
	    MessageFormat form = new MessageFormat(
		ResourceStrings.getString("invalid_netmask"));
	    String msg = form.format(args);
	    throw new ValidationException(msg);
	}
    }
    
    /**
     * @return The IP address of the network
     */
    public IPAddress getAddress() {
	return address;
    }
    
    /**
     * Return the actual network number, which is the product of applying
     * the subnet mask to the address supplied.
     * @return The network number as an <code>IPAddress</code>
     */
    public IPAddress getNetworkNumber() {
	// If netmask is not set then ignore it and return address raw
	if (netmask.intValue() == 0) {
	    return address;
	} else {
	    return new IPAddress(address.intValue() & netmask.intValue());
	}
    }

    /**
     * @return The subnet mask of the network
     */
    public IPAddress getMask() {
	return netmask;
    }
    
    /**
     * Set the subnet mask.
     * @param mask The subnet mask.
     */
    public void setMask(IPAddress mask) {
	netmask = mask;
    }

    /**
     * Do the math to evaluate whether an address is part of this network.
     * @param addr The IP address to evaluate
     * @return <code>true</code> if the address is on this network,
     * <code>false</code> if not.
     */
    public boolean containsAddress(IPAddress addr) {
	return ((addr.intValue() & netmask.intValue())
	    == (address.intValue() & netmask.intValue()));
    }
    
    /**
     * Compute the broadcast address for this network and return it.
     * @return a string representation of the broadcast address.
     */
    public String getBroadcastAddress() {

	byte [] netBytes = getAddress().getAddress();
	byte [] maskBytes = getMask().getAddress();
	StringBuffer buf = new StringBuffer();
	for (int i = 0; i < netBytes.length; ++i) {
	    int b = (netBytes[i] | ~maskBytes[i]) & 0xff;
	    if (buf.length() != 0) {
		buf.append('.');
	    }
	    buf.append(b);
	}

	return (buf.toString());

    } // getBroadcastAddress

    /**
     * Compare against another network object for equality.
     * @param obj The network to compare against.
     * @return <code>true</code> if the networks have the same network number
     */
    public boolean equals(Object obj) {
	// If object passed isn't of same type, always false.
	if (!(obj instanceof Network)) {
	    return false;
	}
	return getNetworkNumber().equals(((Network)obj).getNetworkNumber());
    }
    
    public String toString() {
	return getNetworkNumber().toString();
    }

    /**
     * Perform comparisons to another Network instance.  This is used
     * for sorting a list of network tables.
     * @param o A <code>Network</code> to compare against.
     * @return 0 if the objects have the same address,
     * a negative number if this record has a lower IP address than the
     * supplied record, a positive number if this record has a higher IP
     * address than the supplied record.
     */
    public int compareTo(Object o) {

	Network n = (Network)o;
	long result = getNetworkNumber().getBinaryAddress() -
            n.getNetworkNumber().getBinaryAddress();

	if (result < 0) {
	    return (-1);
	} else if (result > 0) {
	    return (1);
	} else {
	    return (0);
	}
    }

}
