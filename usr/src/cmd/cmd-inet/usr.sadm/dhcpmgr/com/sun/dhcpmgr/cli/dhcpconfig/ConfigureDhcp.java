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
import com.sun.dhcpmgr.data.DhcpdOptions;
import com.sun.dhcpmgr.data.DhcpDatastore;
import com.sun.dhcpmgr.data.ValidationException;
import com.sun.dhcpmgr.data.StandardOptions;
import com.sun.dhcpmgr.bridge.ExistsException;
import com.sun.dhcpmgr.bridge.TableExistsException;

import java.net.InetAddress;
import java.lang.IllegalArgumentException;

/**
 * The main class for the "configure DHCP server" functionality of dhcpconfig.
 */
public class ConfigureDhcp extends DhcpCfgFunction {

    /**
     * The valid options associated with configuring a DHCP server.
     */
    static final int supportedOptions[] = {
	DhcpCfg.NON_NEGOTIABLE_LEASE,
	DhcpCfg.LEASE_LENGTH,
	DhcpCfg.DNS_ADDRESSES,
	DhcpCfg.DNS_DOMAIN,
	DhcpCfg.RESOURCE,
	DhcpCfg.RESOURCE_CONFIG,
	DhcpCfg.PATH
    };

    /**
     * Constructs a ConfigureDhcp object.
     */
    public ConfigureDhcp() {

	validOptions = supportedOptions;

    } // constructor

    /**
     * Returns the option flag for this function.
     * @returns the option flag for this function.
     */
    public int getFunctionFlag() {
	return (DhcpCfg.CONFIGURE_DHCP);
    }

    /**
     * Executes the "configure DHCP server" functionality.
     * @return DhcpCfg.SUCCESS or DhcpCfg.FAILURE
     */
    public int execute() throws IllegalArgumentException {

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

	// User must define both resource and path.
	//
	if (options.valueOf(DhcpCfg.RESOURCE) == null ||
	    options.valueOf(DhcpCfg.PATH) == null) {
	    String msg = getString("config_null_datastore_error");
	    throw new IllegalArgumentException(msg);
	}

	try {
	    setDhcpDatastore(getSvcMgr().getDataStore(
		options.valueOf(DhcpCfg.RESOURCE)));
	    getDhcpDatastore().setLocation(options.valueOf(DhcpCfg.PATH));
	    getDhcpDatastore().setConfig(
		options.valueOf(DhcpCfg.RESOURCE_CONFIG));
	} catch (Throwable e) {
	    // resource will not be valid
	}


	if (getDhcpDatastore() == null || !getDhcpDatastore().isEnabled()) {
	    Object [] arguments = new Object[1];
	    arguments[0] = getDhcpDatastore().getResource();
	    printErrMessage(getString("config_invalid_resource_error"),
		arguments);
	    return (DhcpCfg.FAILURE);
	}

	// Retrieve the leaseLength option and check its validity.
	// The default (3600*24 = 1 day) should be defined as static somewhere.
	//
	Integer leaseLength = new Integer(3600*24);
	if (options.isSet(DhcpCfg.LEASE_LENGTH)) {
	    try {
		leaseLength =
		    new Integer(options.valueOf(DhcpCfg.LEASE_LENGTH));
	    } catch (Throwable e) {
		printErrMessage(getString("config_lease_error"));
		return (DhcpCfg.FAILURE);
	    }

	    if (leaseLength.intValue() == 0) {
		printErrMessage(getString("config_lease_zero_error"));
		return (DhcpCfg.FAILURE);
	    }
	}

	// Are leases negotiable
	//
	boolean leaseNegotiable =
	    !options.isSet(DhcpCfg.NON_NEGOTIABLE_LEASE);

	// Get the DNS information.
	//
	String dnsDomain = options.valueOf(DhcpCfg.DNS_DOMAIN);
	String dnsServers = options.valueOf(DhcpCfg.DNS_ADDRESSES);
	if ((dnsDomain == null) != (dnsServers == null)) {
	    String msg = getString("config_dns_error");
	    throw new IllegalArgumentException(msg);
	}

	IPAddressList dnsAddresses = null;
	try {
	    if (dnsDomain == null) {
		dnsDomain = getSvcMgr().getStringOption(
		    StandardOptions.CD_DNSDOMAIN, "");
	    }
	    if (dnsServers != null) {
		dnsAddresses = new IPAddressList(dnsServers);
	    } else {
		dnsAddresses = new IPAddressList(
		    getSvcMgr().getIPOption(StandardOptions.CD_DNSSERV, ""));
	    }
        } catch (ValidationException e) {
	    Object [] arguments = new Object[1];
	    arguments[0] = getMessage(e);
            printErrMessage(getString("config_dns_server_error"), arguments);
            return (DhcpCfg.FAILURE);
	} catch (Throwable e) {
	    // Ignore, DNS info will not be configured in the server macro.
	}

	// Create the location if it does not exist.
	//
	try {
	    getSvcMgr().makeLocation(getDhcpDatastore());
	} catch (ExistsException e) {
	    // this is o.k.
	} catch (Throwable e) {
	    Object [] arguments = new Object[1];
	    arguments[0] = getDhcpDatastore().getLocation();
	    printErrMessage(getString("config_make_location_error"),
		arguments);
	    return (DhcpCfg.FAILURE);
	}

	// Create the DHCP configuration file
	//
	DhcpdOptions dhcpdOptions = new DhcpdOptions();
	dhcpdOptions.setDaemonEnabled(true);
	dhcpdOptions.setDhcpDatastore(getDhcpDatastore());
	try {
	    getSvcMgr().writeDefaults(dhcpdOptions);
	    printMessage(getString("config_create_conf_progress"));
	} catch (Throwable e) {
	    Object [] arguments = new Object[1];
	    arguments[0] = getMessage(e);
	    printErrMessage(getString("config_writing_conf_error"), arguments);
	    return (DhcpCfg.FAILURE);
	}

	// Create the dhcptab
	//
	try {
	    getDhcptabMgr().createDhcptab(getDhcpDatastore());
	    printMessage(getString("config_dhcptab_progress"));
	} catch (TableExistsException e) {
	    // Not an error; some data stores are shared by multiple servers
	    printMessage(getString("config_dhcptab_exists_progress"));
	} catch (Throwable e) {
	    Object [] arguments = new Object[1];
	    arguments[0] = getMessage(e);
	    printErrMessage(getString("config_dhcptab_error"), arguments);
	    return (DhcpCfg.FAILURE);
	}

	// Create the locale macro
	//
	try {
	    getDhcptabMgr().createLocaleMacro();
	    printMessage(getString("config_locale_progress"));
	} catch (ExistsException e) {
	    /*
	     * Ignore this error, if one's already there we'll assume
	     * it's correct
	     */
	} catch (Throwable e) {
	    Object [] arguments = new Object[1];
	    arguments[0] = getMessage(e);
	    printErrMessage(getString("config_locale_error"), arguments);
	    return (DhcpCfg.FAILURE);
	}

	// Create the Server macro
	//
	String svrName = null;
	try {
	    svrName = getSvcMgr().getShortServerName();
	    InetAddress svrAddress = getSvcMgr().getServerAddress();
	    getDhcptabMgr().createServerMacro(svrName, svrAddress,
		leaseLength.intValue(),	leaseNegotiable, dnsDomain,
		dnsAddresses);
	    Object [] arguments = new Object[1];
	    arguments[0] = svrName;
	    printMessage(getString("config_server_macro_progress"), arguments);
	} catch (Throwable e) {
	    // Couldn't create it; inform user because this is serious
	    Object [] arguments = new Object[2];
	    arguments[1] = svrName;
	    arguments[0] = getMessage(e);
	    printErrMessage(getString("config_server_macro_error"), arguments);
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

} // ConfigureDhcp
