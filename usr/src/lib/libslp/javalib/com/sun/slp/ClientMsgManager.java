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

//  ClientMsgManager.java:Manages versioned client message creation in server
//  Author:           James Kempf
//  Created On:       Thu Sep 17 10:16:33 1998
//  Last Modified By: James Kempf
//  Last Modified On: Tue Oct 13 15:26:16 1998
//  Update Count:     8
//

package com.sun.slp;

import java.util.*;

/**
 * The ClientMsgManager class manages creation of client messages in the
 * slpd server. Client messages are needed for active DA advertisement
 * solicitation, and for forwarding of registrations and deregistrations
 * from the SA server to DAs. This class creates the appropriately
 * versioned message instance, based on the arguments. It also
 * sets the header variables. It is up to the caller to set the
 * instance variables in the object itself.
 *
 * @author James Kempf
 */

abstract class ClientMsgManager extends Object {

    // The class table contains classes registered for particular versions
    //  and message types.

    private static Hashtable classTable = new Hashtable();

    // Register a new message type class and version.

    static void addClientMsgClass(String className,
				  int version,
				  String keyName) {

	// Create the key.

	String key = makeClassKey(keyName, version);

	try {

	    Class headerClass = Class.forName(className);

	    classTable.put(headerClass, key);

	} catch (ClassNotFoundException ex) {

	    Assert.slpassert(false,
			  "no_class",
			  new Object[] {className});

	}
    }

    // Return the appropriately versioned object, with instance variables
    //  set in the header.

    static SrvLocMsg
	newInstance(String keyName,
		    int version,
		    boolean isTCP)
	throws ServiceLocationException {

	try {

	    // Get header class.

	    Class msgClass =
		(Class)classTable.get(makeClassKey(keyName, version));

	    if (msgClass == null) {
		throw
		    new ServiceLocationException(
				ServiceLocationException.INTERNAL_ERROR,
				"cmm_creation_error",
				new Object[] { keyName,
						   new Integer(version)});

	    }

	    SrvLocMsg msg = (SrvLocMsg)msgClass.newInstance();

	    // Set the packet length. If we've come via TCP, we don't
	    //  need to set it.

	    SrvLocHeader hdr = msg.getHeader();

	    if (!isTCP) {
		hdr.packetLength = SLPConfig.getSLPConfig().getMTU();

	    }

	    return msg;

	} catch (Exception ex) {
	    throw
		new ServiceLocationException(
				ServiceLocationException.INTERNAL_ERROR,
				"cmm_creation_exception",
				new Object[] { ex,
						   keyName,
						   new Integer(version),
						   ex.getMessage()});
	}
    }

    // Create the key for the hashtable.

    private static String makeClassKey(String className, int version) {

	return className + version;
    }

}
