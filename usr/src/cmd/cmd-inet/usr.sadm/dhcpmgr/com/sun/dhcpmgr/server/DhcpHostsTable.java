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

import com.sun.dhcpmgr.bridge.*;
import com.sun.dhcpmgr.data.*;
import com.sun.wbem.utility.directorytable.*;

import java.net.*;

/**
 * This class provides the capabilities for managing the hosts table.
 */
public class DhcpHostsTable {

    /**
     * This is the handle to the host table as defined by the config file
     * Access to this handle is synchronized.
     */
    private static DhcpHostsTable cfgHostsTable = null;

    private DirectoryTable hostsTable;
    private int addrColumn = 0;
    private int cnameColumn = 0;
    private int aliasesColumn = 0;
    private int commentColumn = 0;

    /**
     * Create a new DhcpHostsTable of type resource in the specified domain
     * @param resource the host resource(eg., files, dns)
     * @param domain the domain (if any) for the host resource
     */
    public DhcpHostsTable(String resource, String domain)
	throws BridgeException {

	// Determine the local host name. Directory table url requires it.
	//
	String server = null;
	try {
	    server = InetAddress.getLocalHost().getHostName();
	} catch (Throwable e) {
	    throw new BridgeException(
		ResourceStrings.getString("get_host_err"));
	}

	// Build the url.
	//
	StringBuffer url = new StringBuffer();
	if (resource.equals(DhcpConfigOpts.DSVC_CV_FILES)) {
	    url.append("file");
	} else {
	    url.append(resource);
	}
	url.append(":/");
	url.append(server);
	url.append("/");
	if (resource.equals(DhcpConfigOpts.DSVC_CV_FILES)) {
	    url.append(server);
	} else {
	    url.append(domain);
	}
	try {
	    DirectoryTableFactory factory = new DirectoryTableFactory();
	    hostsTable = factory.getDirectoryTableInstance(url.toString());

	    TableDefinitions defs = hostsTable.getTableDefinitionsInstance();
	    defs.loadTableDefinitions(TableDefinitions.TN_HOSTS);
	    addrColumn =
		defs.getColumnNumber(TableDefinitions.CN_HOSTS_ADDR);
	    cnameColumn =
		defs.getColumnNumber(TableDefinitions.CN_HOSTS_CNAME);
	    aliasesColumn =
		defs.getColumnNumber(TableDefinitions.CN_HOSTS_ALIASES);
	    commentColumn =
		defs.getColumnNumber(TableDefinitions.CN_HOSTS_COMMENT);
	} catch (Throwable e) {
	    throw new BridgeException(
		ResourceStrings.getString("hosts_access_err"));
	}

    } // end constructor

    /**
     * Checks access on the host table.
     * @param requestedAccess the desired access
     * @return true if the desired access can be granted
     */
    public synchronized boolean canAccessTable(int requestedAccess)
	throws BridgeException {

	int access = DirectoryTable.NO_ACCESS;

	try {
	    access = hostsTable.access(TableDefinitions.TN_HOSTS);
	} catch (Throwable e) {
	    // No access apparently
	}

	return ((access & requestedAccess) == requestedAccess);
    } // openTable

    /**
     * Opens the host table.
     */
    public synchronized void openTable()
	throws BridgeException {

	try {
	    hostsTable.open(TableDefinitions.TN_HOSTS);
	} catch (Throwable e) {
	    throw new BridgeException(
		ResourceStrings.getString("hosts_open_err"));
	}

    } // openTable

    /**
     * Closes the host table.
     */
    public synchronized void closeTable()
	throws BridgeException {

	try {
	    hostsTable.close();
	} catch (Throwable e) {
	    throw new BridgeException(
		ResourceStrings.getString("hosts_close_err"));
	}

    } // closeTable


    /**
     * Finds a host entry by name and returns its address.
     * @param name host name
     * @return address of entry or null if entry does not exist.
     */
    public synchronized String getHostAddress(String name) {

	String address = null;
	try {
	    DirectoryRow record = hostsTable.getRowInstance();
	    record.putColumn(addrColumn, "");
	    record.putColumn(cnameColumn, name);
	    record.putColumn(aliasesColumn, "");
	    record.putColumn(commentColumn, "");

	    record = hostsTable.getFirstRow(record);

	    address = record.getColumn(addrColumn);

	} catch (Throwable e) {
	    // Nothing to do
	}

	return address;
    }

    /**
     * Finds a host entry by address and returns its name.
     * @param address host address
     * @return name of entry or null if entry does not exist.
     */
    public synchronized String getHostName(String address) {

	String name = null;
	try {
	    DirectoryRow record = hostsTable.getRowInstance();
	    record.putColumn(addrColumn, address);
	    record.putColumn(cnameColumn, "");
	    record.putColumn(aliasesColumn, "");
	    record.putColumn(commentColumn, "");

	    record = hostsTable.getFirstRow(record);

	    name = record.getColumn(cnameColumn);

	} catch (Throwable e) {
	    // Nothing to do
	}

	return name;
    }

    /**
     * Add an entry to the hosts table.
     * @param addr host address
     * @param name host name
     * @param comment comment for host entry
     */
    public synchronized void createHostsRecord(String addr, String name,
	String comment) throws BridgeException {

	if (getHostName(addr) != null) {
	    throw new HostExistsException(addr);
	}

	if (getHostAddress(name) != null) {
	    throw new HostExistsException(name);
	}

	try {
	    DirectoryRow record = hostsTable.getRowInstance();

	    record.putColumn(addrColumn, addr);
	    record.putColumn(cnameColumn, name);
	    record.putColumn(aliasesColumn, "");
	    record.putColumn(commentColumn, comment);

	    hostsTable.addRow(record);
	} catch (Throwable e) {
	    throw new BridgeException(
		ResourceStrings.getString("hosts_add_err"));
	}

    } // createHostsRecord

    /**
     * Remove an entry from the hosts table
     * @param addr host address of entry to remove
     */
    public synchronized void deleteHostsRecord(String addr)
	throws BridgeException {

	try {
	    DirectoryRow record = hostsTable.getRowInstance();
	    record.putColumn(addrColumn, addr);
	    hostsTable.deleteRow(record);
	} catch (DirectoryTableRowNotFoundException e) {
	    throw new NoHostsEntryException(addr);
	} catch (Throwable e) {
	    throw new BridgeException(
		ResourceStrings.getString("hosts_remove_err"));
	}

    } // deleteHostsRecord

    /**
     * Modify an entry on the hosts table.
     * @param oldAddr host address of entry to modify
     * @param newAddr new host address for entry
     * @param name new host name
     * @param comment new comment for host entry
     */
    public synchronized void modifyHostsRecord(String oldAddr, String newAddr,
	String name, String comment) throws BridgeException {

	if (getHostAddress(name) != null) {
	    throw new HostExistsException(name);
	}

	try {
	    DirectoryRow oldRecord = hostsTable.getRowInstance();
	    oldRecord.putColumn(addrColumn, oldAddr);

	    DirectoryRow newRecord = hostsTable.getRowInstance();
	    newRecord.putColumn(addrColumn, newAddr);
	    newRecord.putColumn(cnameColumn, name);
	    newRecord.putColumn(aliasesColumn, "");
	    newRecord.putColumn(commentColumn, comment);

	    hostsTable.modifyRow(oldRecord, newRecord);
	} catch (DirectoryTableRowNotFoundException e) {
	    throw new NoHostsEntryException(oldAddr);
	} catch (Throwable e) {
	    throw new BridgeException(
		ResourceStrings.getString("hosts_modify_err"));
	}
    } // modifyHostsRecord

    /**
     * Determines the whether or not the hosts table under a given
     * name service can be managed.
     * @param resource name service resource (files, dns)
     * @param domain the name service domain (ignored for files)
     * @return true if the user can manage the table
     */
    public static boolean isHostsValid(String resource, String domain) {

	boolean result = false;
	try {
	    DhcpHostsTable hostsTable = new DhcpHostsTable(resource, domain);
	    result = hostsTable.canAccessTable(DirectoryTable.MODIFY_ACCESS);
	} catch (Throwable e) {
	    // No access apparently
	}
	return (result);
    } // isHostsManageable

    /**
     * Constructs a DhcpHostsTable as defined by the DHCP config file.
     * This object is a singleton (only one will ever be created and will
     * be cached).
     * @param bridge the bridge object to the native library
     * @return the DhcpHostsTable
     */
    public static synchronized DhcpHostsTable getCfgHostsTable(Bridge bridge)
	throws BridgeException {

	if (cfgHostsTable == null) {
	    try {
		DhcpdOptions options = bridge.readDefaults();
		String resource = options.getHostsResource();
		if (resource != null) {
		    String domain = options.getHostsDomain();
		    cfgHostsTable = new DhcpHostsTable(resource, domain);
		}
	    } catch (Throwable e) {
		throw new BridgeException(e.getMessage());
	    }
	}
	return cfgHostsTable;

    } // getCfgHostsTable

} // DhcpHostsTable
