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
import java.net.InetAddress;

import com.sun.dhcpmgr.bridge.*;
import com.sun.dhcpmgr.data.*;

/**
 * This class provides methods to manage the contents of the dhcptab.
 */

public class DhcptabMgrImpl implements DhcptabMgr {
    private Bridge bridge;

    /**
     * Create a new DhcptabMgr using the provided native bridge.
     * @param bridge the native bridge class which actually does the work.
     */
    public DhcptabMgrImpl(Bridge bridge) {
	this.bridge = bridge;
    }

    /**
     * Create an option.
     * @param name the name of the option.
     * @param value the value for the option in dhcptab(4) format.
     * @return the Option.
     */
    public Option createOption(String name, String value)
	throws BridgeException {
	return bridge.createOption(name, value);
    }

    /**
     * Retrieve all options currently defined in the dhcptab.
     * @return an array of Options
     */
    public Option [] getOptions() throws BridgeException {
	return getOptions(null);
    }

    /**
     * Retrieve all options currently defined in the dhcptab.
     * @param datastore user-supplied datastore attributes
     * @return an array of Options
     */
    public Option [] getOptions(DhcpDatastore datastore)
	throws BridgeException {
	return bridge.getOptions(datastore);
    }

    /**
     * Retrieve all the macros currently defined in the dhcptab.
     * @return an array of Macros
     */
    public Macro [] getMacros() throws BridgeException {
	return getMacros(null);
    }

    /**
     * Retrieve all the macros currently defined in the dhcptab.
     * @param datastore user-supplied datastore attributes
     * @return an array of Macros
     */
    public Macro [] getMacros(DhcpDatastore datastore)
	throws BridgeException {
	/*
	 * Load the vendor and site options before loading the macros
	 * so we can validate correctly, adding them to the standard options
	 * table.
	 */
	OptionsTable optionsTable = OptionsTable.getTable();
	optionsTable.add(bridge.getOptions(datastore));
	return bridge.getMacros(datastore);
    }

    /**
     * Create a given record in the dhcptab, and signal the server to
     * reload the dhcptab if so requested.
     * @param rec the record to add to the table
     * @param signalServer true if the server is to be sent a SIGHUP
     */
    public void createRecord(DhcptabRecord rec, boolean signalServer)
	    throws BridgeException {
	createRecord(rec, signalServer, null);
    }

    /**
     * Create a given record in the dhcptab, and signal the server to
     * reload the dhcptab if so requested.
     * @param rec the record to add to the table
     * @param signalServer true if the server is to be sent a SIGHUP
     * @param datastore user-supplied datastore attributes
     */
    public void createRecord(DhcptabRecord rec, boolean signalServer,
	DhcpDatastore datastore) throws BridgeException {
	bridge.createDhcptabRecord(rec, datastore);
	if (signalServer) {
	    bridge.reload();
	}
    }

    /**
     * Modify a given record in the dhcptab, and signal the server to reload
     * the dhcptab if so requested
     * @param oldRec the current record to modify
     * @param newRec the new record to be placed in the table
     * @param signalServer true if the server is to be sent a SIGHUP
     */
    public void modifyRecord(DhcptabRecord oldRec, DhcptabRecord newRec,
	    boolean signalServer) throws BridgeException {
	modifyRecord(oldRec, newRec, signalServer, null);
    }

    /**
     * Modify a given record in the dhcptab, and signal the server to reload
     * the dhcptab if so requested
     * @param oldRec the current record to modify
     * @param newRec the new record to be placed in the table
     * @param signalServer true if the server is to be sent a SIGHUP
     * @param datastore user-supplied datastore attributes
     */
    public void modifyRecord(DhcptabRecord oldRec, DhcptabRecord newRec,
	boolean signalServer, DhcpDatastore datastore)
	throws BridgeException {
	bridge.modifyDhcptabRecord(oldRec, newRec, datastore);
	if (signalServer) {
	    bridge.reload();
	}
    }

    /**
     * Delete a given record from the dhcptab, and signal the server to reload
     * the dhcptab if so requested
     * @param rec the record to delete
     * @param signalServer true if the server is to be sent a SIGHUP
     */
    public void deleteRecord(DhcptabRecord rec, boolean signalServer)
	    throws BridgeException {
	deleteRecord(rec, signalServer, null);
    }

    /**
     * Delete a given record from the dhcptab, and signal the server to reload
     * the dhcptab if so requested
     * @param rec the record to delete
     * @param signalServer true if the server is to be sent a SIGHUP
     * @param datastore user-supplied datastore attributes
     */
    public void deleteRecord(DhcptabRecord rec, boolean signalServer,
	DhcpDatastore datastore) throws BridgeException {
	bridge.deleteDhcptabRecord(rec, datastore);
	if (signalServer) {
	    bridge.reload();
	}
    }

    /**
     * Delete a record by name and type
     * @param key The key for the record
     * @param type The type of record; either MACRO or OPTION
     */
    private void deleteRecord(String name, String type) throws BridgeException {
	DhcptabRecord rec = null;
	if (type.equals(DhcptabRecord.MACRO)) {
	    rec = getMacro(name);
	} else {
	    rec = getOption(name);
	}
	deleteRecord(rec, false);
    }

    /**
     * Delete a set of records.
     * @return An array of ActionError, one error for each record not deleted
     */
    private ActionError [] deleteRecords(DhcptabRecord [] recs) {
	ArrayList errorList = new ArrayList();

	for (int i = 0; i < recs.length; ++i) {
	    try {
		deleteRecord(recs[i], false);
	    } catch (BridgeException e) {
		errorList.add(new ActionError(recs[i].getKey(), e));
	    }
	}

	return (ActionError[])errorList.toArray(new ActionError[0]);
    }

    private ActionError [] deleteAllRecords(String type)
	    throws BridgeException {
	DhcptabRecord [] recs;
	if (type.equals(DhcptabRecord.MACRO)) {
	    recs = getMacros();
	} else {
	    recs = getOptions();
	}
	return deleteRecords(recs);
    }

    /**
     * Delete all macros
     * @return An array of ActionError, one error for each macro not deleted
     */
    public ActionError [] deleteAllMacros() throws BridgeException {
    	return deleteAllRecords(DhcptabRecord.MACRO);
    }

    /**
     * Delete all options
     * @return An array of ActionError, one error for each option not deleted
     */
    public ActionError [] deleteAllOptions() throws BridgeException {
	return deleteAllRecords(DhcptabRecord.OPTION);
    }

    /**
     * Delete a list of macros identified by name
     * @param macroNames Names of the macros to delete
     * @return An array of ActionError, one element per macro not deleted
     */
    public ActionError [] deleteMacros(String [] macroNames) {
	ArrayList errorList = new ArrayList();

	for (int i = 0; i < macroNames.length; ++i) {
	    try {
		deleteRecord(macroNames[i], DhcptabRecord.MACRO);
	    } catch (BridgeException e) {
		errorList.add(new ActionError(macroNames[i], e));
	    }
	}

	return (ActionError [])errorList.toArray(new ActionError[0]);
    }

    /**
     * Delete a list of options identified by name
     * @param optionNames Names of options to delete
     * @return An array of ActionError, one element per option not deleted
     */
    public ActionError [] deleteOptions(String [] optionNames) {
	ArrayList errorList = new ArrayList();

	for (int i = 0; i < optionNames.length; ++i) {
	    try {
		deleteRecord(optionNames[i], DhcptabRecord.OPTION);
	    } catch (BridgeException e) {
		errorList.add(new ActionError(optionNames[i], e));
	    }
	}

	return (ActionError [])errorList.toArray(new ActionError[0]);
    }

    /**
     * Retrieve a given macro from the dhcptab.
     * @param key the key of the record to retrieve
     * @return the Macro for the given key
     */
    public Macro getMacro(String key)
    	throws BridgeException {
	return getMacro(key, null);
    }

    /**
     * Retrieve a given macro from the dhcptab.
     * @param key the key of the record to retrieve
     * @param datastore user-supplied datastore attributes
     * @return the Macro for the given key
     */
    public Macro getMacro(String key, DhcpDatastore datastore)
    	throws BridgeException {
	OptionsTable optionsTable = OptionsTable.getTable();
	optionsTable.add(bridge.getOptions(datastore));
	return bridge.getMacro(key, datastore);
    }

    /**
     * Retrieve a given option from the dhcptab.
     * @param key the key of the record to retrieve
     * @return the Option for the given key
     */
    public Option getOption(String key)
    	throws BridgeException {
	return getOption(key, null);
    }

    /**
     * Retrieve a given option from the dhcptab.
     * @param key the key of the record to retrieve
     * @param datastore user-supplied datastore attributes
     * @return the Option for the given key
     */
    public Option getOption(String key, DhcpDatastore datastore)
    	throws BridgeException {
	return bridge.getOption(key, datastore);
    }

    /**
     * Create a new dhcptab converting the one in the server's data store,
     * into a new data store.
     * @param datastore user-supplied datastore attributes
     */
    public void cvtDhcptab(DhcpDatastore datastore)
	throws BridgeException {
	bridge.cvtDhcptab(datastore);
    }

    /**
     * Create a new empty dhcptab in the server's data store, which must
     * already be configured.
     */
    public void createDhcptab() throws BridgeException {
	createDhcptab(null);
    }

    /**
     * Create a new empty dhcptab in the server's data store, which must
     * already be configured.
     * @param datastore user-supplied datastore attributes
     */
    public void createDhcptab(DhcpDatastore datastore)
	throws BridgeException {
	bridge.createDhcptab(datastore);
    }

    /**
     * Delete the server's dhcptab in the current data store.
     */
    public void deleteDhcptab() throws BridgeException {
	deleteDhcptab(null);
    }

    /**
     * Delete the server's dhcptab in the current data store.
     * @param datastore user-supplied datastore attributes
     */
    public void deleteDhcptab(DhcpDatastore datastore)
	throws BridgeException {
	bridge.deleteDhcptab(datastore);
    }

    public void createLocaleMacro()
	throws BridgeException, ValidationException {
	createLocaleMacro(null);
    }

    public void createLocaleMacro(DhcpDatastore datastore)
	throws BridgeException, ValidationException {

	Macro macro = new Macro();
	macro.setKey("Locale");
	macro.storeOption(StandardOptions.CD_TIMEOFFSET,
	    String.valueOf(TimeZone.getDefault().getRawOffset()/1000));

	createRecord(macro, false);
    }

    public void createServerMacro(String svrName,
	InetAddress svrAddress, int leaseLength,
	boolean leaseNegotiable, String dnsDomain, Vector dnsServs)
	throws BridgeException, ValidationException {

	createServerMacro(svrName, svrAddress, leaseLength, leaseNegotiable,
	    dnsDomain, dnsServs, null);
    }

    public void createServerMacro(String svrName,
	InetAddress svrAddress, int leaseLength,
	boolean leaseNegotiable, String dnsDomain, Vector dnsServs,
	DhcpDatastore datastore)
	throws BridgeException, ValidationException {

	Macro macro = new Macro();
	macro.setKey(svrName);
	macro.storeOption("Include", "Locale");
	macro.storeOption(StandardOptions.CD_TIMESERV, svrAddress);
	macro.storeOption(StandardOptions.CD_LEASE_TIME,
	    String.valueOf(leaseLength));
	if (leaseNegotiable) {
	    macro.storeOption(StandardOptions.CD_BOOL_LEASENEG, null);
	}
	if (dnsDomain != null && dnsDomain.length() != 0 &&
	    dnsServs != null && dnsServs.size() != 0) {
	    macro.storeOption(StandardOptions.CD_DNSDOMAIN, dnsDomain);
	    macro.storeOption(StandardOptions.CD_DNSSERV, dnsServs);
	}
	// First delete it in case it's already there
	try {
	    deleteRecord(macro, false);
	} catch (Throwable e) {
	    // Ignore any error
	}

	createRecord(macro, false);
    }

    public synchronized void createNetworkMacro(Network network,
	IPAddress [] routers, boolean isLan, String nisDomain, Vector nisServs)
	throws BridgeException, ValidationException {

	createNetworkMacro(network, routers, isLan, nisDomain, nisServs,
	    null);
    }

    public void createNetworkMacro(Network network,
	IPAddress [] routers, boolean isLan, String nisDomain, Vector nisServs,
	DhcpDatastore datastore) throws BridgeException, ValidationException {

	Macro macro = new Macro();
	macro.setKey(network.toString());
	macro.storeOption(StandardOptions.CD_SUBNETMASK, network.getMask());
	if (routers == null) {
	    macro.storeOption(StandardOptions.CD_ROUTER_DISCVRY_ON, "1");
	} else {
	    for (int i = 0; i < routers.length; i++) {
		macro.storeOption(StandardOptions.CD_ROUTER, routers[i]);
	    }
	}

	if (isLan) {
	    macro.storeOption(StandardOptions.CD_BROADCASTADDR,
		network.getBroadcastAddress());
	}

	// NIS config
	if (nisDomain != null && nisDomain.length() != 0 &&
	    nisServs != null && nisServs.size() != 0) {
	    macro.storeOption(StandardOptions.CD_NIS_DOMAIN, nisDomain);
	    macro.storeOption(StandardOptions.CD_NIS_SERV, nisServs);
	}

	createRecord(macro, false);
    }
}
