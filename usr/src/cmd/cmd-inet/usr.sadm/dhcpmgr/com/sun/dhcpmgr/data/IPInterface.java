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
 * Copyright (c) 1998-1999 Sun Microsystems, Inc.
 * All rights reserved.
 */

package com.sun.dhcpmgr.data;

import java.io.Serializable;

/**
 * This class represents an IP network interface on the server.  It consists
 * of the interface's device name (short form) and the network it's attached to.
 */
public class IPInterface implements Serializable {
    private String name;
    private Network net;
    
    /**
     * Construct a new interface with the given name, address, and subnet mask.
     * @param name Interface name
     * @param addr The address
     * @param mask The subnet mask
     */
    public IPInterface(String name, IPAddress addr, IPAddress mask) {
	this.name = name;
	net = new Network(addr, mask);
    }
    
    /**
     * Construct a new interface with the given name, address, and subnet mask.
     * @param name The interface name
     * @param addr The IP address as a dotted-decimal <code>String</code>
     * @param mask The subnet mask as a dotted-decimal <code>String</code>
     */
    public IPInterface(String name, String addr, String mask)
	    throws ValidationException {
	this.name = name;
	net = new Network(addr, mask);
    }
    
    /**
     * @return Interface's device name
     */
    public String getName() {
	return name;
    }
    
    /**
     * Set the interface's device name
     * @param name Name of interface
     */
    public void setName(String name) {
	this.name = name;
    }
    
    /**
     * @return Network the device is attached to.
     */
    public Network getNetwork() {
	return net;
    }
}
