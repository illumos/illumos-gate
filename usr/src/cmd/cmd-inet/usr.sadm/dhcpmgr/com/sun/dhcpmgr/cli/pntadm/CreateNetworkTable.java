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
 * Copyright (c) 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */
package com.sun.dhcpmgr.cli.pntadm;

import com.sun.dhcpmgr.data.Network;
import com.sun.dhcpmgr.bridge.TableExistsException;

import java.lang.IllegalArgumentException;

/**
 * The main class for the "create network table" functionality
 * of pntadm.
 */
public class CreateNetworkTable extends PntAdmFunction {

    /**
     * The valid options associated with creating a network table.
     */
    static final int supportedOptions[] = {
	PntAdm.RESOURCE,
	PntAdm.RESOURCE_CONFIG,
	PntAdm.PATH
    };

    /**
     * Constructs a CreateNetworkTable object.
     */
    public CreateNetworkTable() {

	validOptions = supportedOptions;

    } // constructor

    /**
     * Returns the option flag for this function.
     * @returns the option flag for this function.
     */
    public int getFunctionFlag() {
	return (PntAdm.CREATE_NETWORK_TABLE);
    }

    /**
     * Executes the "create network table" functionality.
     * @return PntAdm.SUCCESS, PntAdm.EXISTS, PntAdm.WARNING, or 
     * PntAdm.CRITICAL
     */
    public int execute()
	throws IllegalArgumentException {

	int returnCode = PntAdm.SUCCESS;

	// Create a Network object.
	//
	try {
	    Network network = getNetMgr().getNetwork(networkName);
	    if (network == null) {
		printErrMessage(getString("network_name_error"));
		return (PntAdm.WARNING);
	    }

	    getNetMgr().createNetwork(network.toString(), getDhcpDatastore());
	} catch (TableExistsException e) {
	    printErrMessage(getMessage(e));
	    returnCode = PntAdm.EXISTS;
	} catch (Throwable e) {
	    printErrMessage(getMessage(e));
	    returnCode = PntAdm.WARNING;
	}

	return (returnCode);

    } // execute

} // CreateNetworkTable
