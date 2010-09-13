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
package com.sun.dhcpmgr.cli.dhcpconfig;

import com.sun.dhcpmgr.cli.common.DhcpCliFunction;
import com.sun.dhcpmgr.data.DhcpdOptions;
import com.sun.dhcpmgr.data.ValidationException;

/**
 * The main class for the "configure BOOTP relay" functionality of dhcpconfig.
 */
public class ConfigureBootp extends DhcpCfgFunction {

    /**
     * The valid options associated with configuring a BOOTP relay agent.
     */
    static final int supportedOptions[] = {
    };

    /**
     * The addresses of servers for which to serve as a relay.
     */
    String addresses;

    /**
     * Constructs a ConfigureBootp object.
     * @param addresses the addresses of servers for which to serve as a relay.
     */
    public ConfigureBootp(String addresses) {

	validOptions = supportedOptions;
	this.addresses = addresses;

    } // constructor

    /**
     * Returns the option flag for this function.
     * @returns the option flag for this function.
     */
    public int getFunctionFlag() {
	return (DhcpCfg.CONFIGURE_BOOTP);
    }

    /**
     * Executes the "configure BOOTP relay" functionality.
     * @return DhcpCfg.SUCCESS or DhcpCfg.FAILURE
     */
    public int execute() {

	// Check to see if DHCP or BOOTP relay is already configured.
	//
	boolean isServer = false;
	boolean isRelay = false;
	try {
	    DhcpdOptions opts = getSvcMgr().readDefaults();
	    if (opts.isRelay()) {
		isRelay = true;
	    } else {
		isServer = true;
	    }
	} catch (Throwable e) {
	    // this is to be expected
	}

	if (isServer) {
	    printErrMessage(getString("config_dhcp_configured_error"));
	    return (DhcpCfg.FAILURE);
	}

	if (isRelay) {
	    printErrMessage(getString("config_bootp_configured_error"));
	    return (DhcpCfg.FAILURE);
	}

	// Write the information to the DHCP configuration file.
	//
	try {
	    IPAddressList list = new IPAddressList(addresses);
	    DhcpdOptions options = new DhcpdOptions();
	    options.setDaemonEnabled(true);
	    options.setRelay(true, list.toString());
	    getSvcMgr().writeDefaults(options);
	    printMessage(getString("config_create_conf_progress"));
	} catch (ValidationException e) {
	    printErrMessage(getMessage(e));
	    return (DhcpCfg.FAILURE);
	} catch (Throwable e) {
	    Object [] arguments = new Object[1];
	    arguments[0] = getMessage(e);
	    printErrMessage(getString("config_writing_conf_error"), arguments);
	    return (DhcpCfg.FAILURE);
	}

	// Start it up.
	//
	try {
	    getSvcMgr().startup();
	    printMessage(getString("config_startup_progress"));
	} catch (Throwable e) {
	    Object [] arguments = new Object[1];
	    arguments[0] = getMessage(e);
	    printErrMessage(getString("config_startup_error"), arguments);
	    return (DhcpCfg.FAILURE);
	}

	return (DhcpCfg.SUCCESS);

    } // execute

} // ConfigureBootp
