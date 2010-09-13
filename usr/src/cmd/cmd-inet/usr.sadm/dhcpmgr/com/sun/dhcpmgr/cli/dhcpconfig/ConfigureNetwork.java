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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
package com.sun.dhcpmgr.cli.dhcpconfig;

import com.sun.dhcpmgr.cli.common.DhcpCliFunction;
import com.sun.dhcpmgr.data.IPAddress;
import com.sun.dhcpmgr.data.Network;
import com.sun.dhcpmgr.data.ValidationException;
import com.sun.dhcpmgr.data.StandardOptions;

/**
 * The main class for the "configure network" functionality of dhcpconfig.
 */
public class ConfigureNetwork extends DhcpCfgFunction {

    /**
     * The valid options associated with configuring a network.
     */
    static final int supportedOptions[] = {
	DhcpCfg.SUBNET_MASK,
	DhcpCfg.POINT_TO_POINT,
	DhcpCfg.ROUTER_ADDRESSES,
	DhcpCfg.NIS_DOMAIN,
	DhcpCfg.NIS_ADDRESSES,
	DhcpCfg.SIGHUP
    };

    /**
     * The address of the network to configure.
     */
    String address;

    /**
     * Constructs a ConfigureNetwork object.
     * @param address the address of the network to configure
     */
    public ConfigureNetwork(String address) {

	validOptions = supportedOptions;
	this.address = address;

    } // constructor

    /**
     * Returns the option flag for this function.
     * @returns the option flag for this function.
     */
    public int getFunctionFlag() {
	return (DhcpCfg.CONFIGURE_NETWORK);
    }

    /**
     * Executes the "configure network" functionality.
     * @return DhcpCfg.SUCCESS or DhcpCfg.FAILURE
     */
    public int execute() {

	// Make sure that server is configured as a DHCP server.
	//
	if (!isServerConfigured()) {
	    return (DhcpCfg.FAILURE);
	}

	// Check the validity of the data store version.
	//
	if (!isVersionValid(false)) {
	    return (DhcpCfg.FAILURE);
	}

	// Validate the network address
	//
	Network network;
	try {
	    network = getNetMgr().getNetwork(address);
	} catch (Throwable e) {
	    Object [] arguments = new Object[1];
	    arguments[0] = address;
	    printErrMessage(getString("cfgnet_invalid_network_error"),
		arguments);
	    return (DhcpCfg.FAILURE);
	}

	// Determine/validate the subnet mask.
	//
	IPAddress netmask = null;
	String mask = options.valueOf(DhcpCfg.SUBNET_MASK);
	if (mask != null) {
	    try {
		netmask = new IPAddress(mask);
		network.setMask(netmask);
	    } catch (ValidationException e) {
		Object [] arguments = new Object[1];
		arguments[0] = address;
		printErrMessage(getString("cfgnet_invalid_ip_error"),
		    arguments);
		return (DhcpCfg.FAILURE);
	    }
	}

	boolean isLan = !options.isSet(DhcpCfg.POINT_TO_POINT);

	// Get the list of router addresses
	//
	IPAddressList routers = null;
	if (options.isSet(DhcpCfg.ROUTER_ADDRESSES)) {
	    try {
		String addrs = options.valueOf(DhcpCfg.ROUTER_ADDRESSES);
		routers = new IPAddressList(addrs);
	    } catch (ValidationException e) {
		printErrMessage(getMessage(e));
		return (DhcpCfg.FAILURE);
	    }
	}

	// Get the NIS info.
	//
	String nisDomain = options.valueOf(DhcpCfg.NIS_DOMAIN);
	String nisServers = options.valueOf(DhcpCfg.NIS_ADDRESSES);
	if ((nisDomain == null) != (nisServers == null)) {
	    String msg = getString("cfgnet_nis_error");
	    throw new IllegalArgumentException(msg);
	}

	IPAddressList nisAddresses = null;
	try {
	    if (nisDomain == null) {
		nisDomain = getSvcMgr().getStringOption(
		    StandardOptions.CD_NIS_DOMAIN, "");
	    }
	    if (nisServers != null) {
		nisAddresses = new IPAddressList(nisServers);
	    } else {
		nisAddresses = new IPAddressList(
		    getSvcMgr().getIPOption(StandardOptions.CD_NIS_SERV, ""));
	    }
	} catch (ValidationException e) {
	    Object [] arguments = new Object[1];
	    arguments[0] = getMessage(e);
	    printErrMessage(getString("cfgnet_nis_server_error"), arguments);
	    return (DhcpCfg.FAILURE);
	} catch (Throwable e) {
	    // Ignore, NIS info will not be configured in the network macro.
	}

	// Create the network macro in the dhcptab
	//
	try {
	    IPAddress[] routersArray = null;
	    if (routers != null) {
		routersArray = routers.toIPAddressArray();
	    }
	    getDhcptabMgr().createNetworkMacro(network, routersArray,
		isLan, nisDomain, nisAddresses);
	    Object [] arguments = new Object[1];
	    arguments[0] = network.toString();
	    printMessage(getString("cfgnet_network_macro_progress"),
		arguments);
	} catch (Throwable e) {
	    Object [] arguments = new Object[1];
	    arguments[0] = getMessage(e);
	    printErrMessage(getString("cfgnet_network_macro_error"),
		arguments);
	    return (DhcpCfg.FAILURE);
	}


	// Create the network table for this network
	//
	try {
	    getNetMgr().createNetwork(network.toString());
	    printMessage(getString("cfgnet_network_table_progress"));
	} catch (Throwable e) {
	    Object [] arguments = new Object[1];
	    arguments[0] = getMessage(e);
	    printErrMessage(getString("cfgnet_network_table_error"),
		arguments);
	    return (DhcpCfg.FAILURE);
	}

	// Signal the server if the user asked us to
	try {
	    if (options.isSet(DhcpCfg.SIGHUP)) {
		getSvcMgr().reload();
	    }
	} catch (Throwable e) {
	    printErrMessage(getString("sighup_failed"));
	    return (DhcpCfg.FAILURE);
	}

	return (DhcpCfg.SUCCESS);

    } // execute

} // ConfigureNetwork
