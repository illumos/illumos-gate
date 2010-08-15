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
package com.sun.dhcpmgr.server;

import java.util.*;
import java.util.jar.*;
import java.net.InetAddress;
import java.net.UnknownHostException;

import com.sun.dhcpmgr.bridge.*;
import com.sun.dhcpmgr.data.*;

/**
 * This class provides the capabilities for managing the the basic service
 * parameters which are not stored in the dhcptab or per-network tables.
 */
public class DhcpServiceMgrImpl implements DhcpServiceMgr {
    private Bridge bridge;

    private String serverName;
    private String shortServerName;
    private InetAddress serverAddress;

    public DhcpServiceMgrImpl(Bridge bridge) {
	this.bridge = bridge;

	try {
	    serverAddress = InetAddress.getLocalHost();
	    serverName = serverAddress.getHostName();

	    int i = serverName.indexOf('.');
	    if (i == -1) {
		shortServerName = serverName;
	    } else {
		shortServerName = serverName.substring(0, i);
	    }
	} catch (UnknownHostException e) {
	    serverName = shortServerName = "";
	}
    }

    public String getServerName() {
	return serverName;
    }

    public String getShortServerName() {
	return shortServerName;
    }

    public InetAddress getServerAddress() {
	return serverAddress;
    }

    public void makeLocation(DhcpDatastore datastore)
	throws BridgeException {
	bridge.makeLocation(datastore);
    }

    public DhcpDatastore getDataStore(String resource) throws BridgeException {
	return bridge.getDataStore(resource);
    }

    /**
     * Retrieve the list of possible data stores for this server
     * @return an array of data store module names.
     */
    public DhcpDatastore [] getDataStores() throws BridgeException {
	return bridge.getDataStores();
    }

    /**
     * Retrieve a list of options from the DHCP inittab.
     * @return an array of options
     */
    public Option [] getInittabOptions(byte context) throws BridgeException {
	return bridge.getInittabOptions(context);
    }

    public String getDataStoreClassname(String dataStoreName)
	throws BridgeException {

	String beansDirectory = new String("/usr/sadm/admin/dhcpmgr/");
	String jarPath = beansDirectory.concat(dataStoreName).concat(".jar");
	String className = null;
	try {
	    JarFile jarFile = new JarFile(jarPath);
	    Manifest manifest = jarFile.getManifest();
	    if (manifest == null) {
		throw new BridgeException();
	    }
	    Attributes attrs = manifest.getMainAttributes();
	    if (attrs == null) {
		throw new BridgeException();
	    }
	    className = attrs.getValue("Name");
	    if (!className.endsWith(".class")) {
		throw new BridgeException();
	    }
	    className = className.substring(0, className.length() - 6);
	    className = className.replace('/', '.');
	} catch (Throwable e) {
	    throw new BridgeException();
	}

	return className;
    }

    /**
     * Retrieve the contents of the DHCP config file.
     * @return the config settings
     */
    public DhcpdOptions readDefaults() throws BridgeException {
	return bridge.readDefaults();
    }

    /**
     * Write new settings to the DHCP config file.
     * @param cfgs the new config settings
     */
    public void writeDefaults(DhcpdOptions cfgs) throws BridgeException {
	bridge.writeDefaults(cfgs);
    }

    /**
     * Remove the DHCP config file.
     */
    public void removeDefaults() throws BridgeException {
	bridge.removeDefaults();
    }

    /**
     * Start the server
     */
    public void startup() throws BridgeException {
	bridge.startup();
    }

    /**
     * Stop the server
     */
    public void shutdown() throws BridgeException {
	bridge.shutdown();
    }

    /**
     * Send the server a SIGHUP to re-read the dhcptab
     */
    public void reload() throws BridgeException {
	bridge.reload();
    }

    /**
     * Get the list of possible interfaces for the server to monitor
     * @return an array of interfaces
     */
    public IPInterface [] getInterfaces() throws BridgeException {
	return bridge.getInterfaces();
    }

    /**
     * Break up a line into a list of arguments
     * @param input line
     * @return an array of arguments
     */
    public String [] getArguments(String line) throws BridgeException {
	return bridge.getArguments(line);
    }

    /**
     * Get the default value for an option which would take a string
     * @param optionName name of the option
     * @param arg additional information needed for this code
     */
    public synchronized String getStringOption(String optionName, String arg)
	    throws BridgeException {
	Option option = OptionsTable.getTable().get(optionName);
	return bridge.getStringOption(option.getCode(), arg);
    }

    /**
     * Get the default value for an option which would take one or more IP addrs
     * @param optionName name of the option
     * @param arg additional information needed for this code
     */
    public synchronized IPAddress [] getIPOption(String optionName, String arg)
	    throws BridgeException {
	Option option = OptionsTable.getTable().get(optionName);
	return bridge.getIPOption(option.getCode(), arg);
    }

    /**
     * Get the default value for an option which would take one or more numbers
     * @param optionName name of the option
     * @param arg additional information needed for this code
     */
    public synchronized long [] getNumberOption(String optionName, String arg)
	    throws BridgeException {
	Option option = OptionsTable.getTable().get(optionName);
	return bridge.getNumberOption(option.getCode(), arg);
    }

    /**
     * Check if the datastore version is current.
     * @return true if the datastore version if current.
     */
    public boolean isVersionCurrent() throws BridgeException {
	return bridge.isVersionCurrent();
    }

    /**
     * Check if the server is currently running
     * @return true if the server process is started
     */
    public boolean isServerRunning() throws BridgeException {
	return bridge.isServerRunning();
    }
}
