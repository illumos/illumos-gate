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
 * Copyright 2001-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
package com.sun.dhcpmgr.cli.pntadm;

import com.sun.dhcpmgr.cli.common.Util;
import com.sun.dhcpmgr.data.DhcpClientRecord;
import com.sun.dhcpmgr.data.Macro;
import com.sun.dhcpmgr.data.Network;
import com.sun.dhcpmgr.bridge.BridgeException;
import com.sun.dhcpmgr.bridge.NoEntryException;

import java.lang.IllegalArgumentException;

/**
 * The main class for the "modify client" functionality of pntadm.
 */
public class ModifyClientEntry extends PntAdmFunction {

    /**
     * The valid options associated with modifying a client entry.
     */
    static final int supportedOptions[] = {
	PntAdm.NEW_IP,
	PntAdm.COMMENT,
	PntAdm.LEASE_EXPIRATION,
	PntAdm.FLAGS,
	PntAdm.CLIENTID,
	PntAdm.CONVERT_CLIENTID,
	PntAdm.MACRO_NAME,
	PntAdm.VERIFY_MACRO,
	PntAdm.SERVER,
	PntAdm.RESOURCE,
	PntAdm.RESOURCE_CONFIG,
	PntAdm.PATH
    };

    /**
     * The client entry to modify.
     */
    String clientIP;

    /**
     * Constructs a ModifyClientEntry object for the client, clientIP.
     * @param clientIP the client name or IP address.
     */
    public ModifyClientEntry(String clientIP) {

	this.clientIP = clientIP;
	validOptions = supportedOptions;

    } // constructor

    /**
     * Returns the option flag for this function.
     * @returns the option flag for this function.
     */
    public int getFunctionFlag() {
	return (PntAdm.MODIFY_CLIENT_ENTRY);
    }

    /**
     * Executes the "modify client" functionality.
     * @return PntAdm.SUCCESS, PntAdm.ENOENT, PntAdm.WARNING, or
     * PntAdm.CRITICAL
     */
    public int execute()
	throws IllegalArgumentException {

	int returnCode = PntAdm.SUCCESS;

	// Build up a DhcpClientRecord so that we can retrieve the current
	// client record from the network table.
	//
	try {
	    DhcpClientRecord oldDhcpClientRecord = new DhcpClientRecord();
	    oldDhcpClientRecord.setClientIP(clientIP);

	    // Create a Network object.
	    //
	    Network network = getNetMgr().getNetwork(networkName);
	    if (network == null) {
		printErrMessage(getString("network_name_error"));
		return (PntAdm.WARNING);
	    }

	    // Go and get the current client record from the network table.
	    //
	    oldDhcpClientRecord =
		getNetMgr().getClient(oldDhcpClientRecord, network.toString(),
		getDhcpDatastore());

	    // Build up the new DhcpClientRecord from the original and the
	    // user specified options.
	    //
	    DhcpClientRecord newDhcpClientRecord =
		(DhcpClientRecord)oldDhcpClientRecord.clone();

	    String newClientIP = options.valueOf(PntAdm.NEW_IP);
	    if (newClientIP != null) {
		newDhcpClientRecord.setClientIP(newClientIP);
	    } else {
		newDhcpClientRecord.setClientIP(clientIP);
	    }

	    String clientId = options.valueOf(PntAdm.CLIENTID);
	    boolean convertClientId = options.isSet(PntAdm.CONVERT_CLIENTID);
	    if (convertClientId) {
		if (clientId == null) {
		    String msg = getString("no_clientid_specified");
		    throw new IllegalArgumentException(msg);
		}
		clientId = Util.asciiToHex(clientId);
	    }
	    if (clientId != null) {
		newDhcpClientRecord.setClientId(clientId);
	    }

	    String flags = options.valueOf(PntAdm.FLAGS);
	    if (flags != null) {
		newDhcpClientRecord.setFlags(flags);
	    }

	    String serverIP = options.valueOf(PntAdm.SERVER);
	    if (serverIP == null) {
		serverIP = getSvcMgr().getServerName();
	    }
	    newDhcpClientRecord.setServerIP(serverIP);

	    String expiration = options.valueOf(PntAdm.LEASE_EXPIRATION);
	    if (expiration != null) {
		newDhcpClientRecord.setExpiration(shortFormat, expiration);
	    }

	    boolean verifyMacro = options.isSet(PntAdm.VERIFY_MACRO);
	    String macro = options.valueOf(PntAdm.MACRO_NAME);
	    if (verifyMacro) {
		if (macro == null) {
		    String msg = getString("no_macro_specified");
		    throw new IllegalArgumentException(msg);
		}

		// Create a Macro entry so that we can check to see if it
		// exists in the dhcptab.
		//
		try {
		    Macro existingMacro =
			getDhcptabMgr().getMacro(macro);
		}
		catch (BridgeException e) {
		    printErrMessage(getString("macro_not_found"));
		    return (PntAdm.WARNING);
		}
	    }
	    if (macro != null) {
		newDhcpClientRecord.setMacro(macro);
	    }

	    String comment =  options.valueOf(PntAdm.COMMENT);
	    if (comment != null) {
		newDhcpClientRecord.setComment(comment);
	    }

	    // Modify the client and adds host if necessary.
	    //
	    getNetMgr().modifyClient(oldDhcpClientRecord, newDhcpClientRecord,
		network.toString(), getDhcpDatastore());

	} catch (NoEntryException e) {
	    printErrMessage(getMessage(e));
	    returnCode = PntAdm.ENOENT;
	} catch (Throwable e) {
	    printErrMessage(getMessage(e));
	    returnCode = PntAdm.WARNING;
	}

	return (returnCode);

    } // execute

} // ModifyClientEntry
