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
 * Copyright (c) 1998-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

package com.sun.dhcpmgr.bridge;

import java.util.Hashtable;
import com.sun.dhcpmgr.data.*;

/**
 * Bridge supplies access to the native functions in libdhcp and the
 * dhcpmgr shared object which actually interact with the data stores
 * used by DHCP.
 */

public class Bridge {
    public native DhcpDatastore getDataStore(String resource)
	throws BridgeException;
    public native DhcpDatastore [] getDataStores() throws BridgeException;
    public native Option [] getInittabOptions(byte context)
	throws BridgeException;
    public native Macro getMacro(String key, DhcpDatastore datastore)
	throws BridgeException;
    public native Option getOption(String key, DhcpDatastore datastore)
	throws BridgeException;
    public native void createDhcptabRecord(DhcptabRecord rec,
	DhcpDatastore datastore) throws BridgeException;
    public native void modifyDhcptabRecord(DhcptabRecord oldRecord,
	DhcptabRecord newRecord, DhcpDatastore datastore)
	throws BridgeException;
    public native void deleteDhcptabRecord(DhcptabRecord rec,
	DhcpDatastore datastore) throws BridgeException;
    public native void cvtDhcptab(DhcpDatastore datastore)
	throws BridgeException;
    public native Option createOption(String name, String value)
	throws BridgeException;
    public native Option [] getOptions(DhcpDatastore datastore)
	throws BridgeException;
    public native Macro [] getMacros(DhcpDatastore datastore)
	throws BridgeException;
    public native Network [] getNetworks(DhcpDatastore datastore)
	throws BridgeException;
    public native Network getNetwork(String network)
	throws BridgeException;
    public native void cvtNetwork(String table,
	DhcpDatastore datastore) throws BridgeException;
    public native DhcpClientRecord [] loadNetwork(String table,
	DhcpDatastore datastore) throws BridgeException;
    public native void createDhcpClientRecord(DhcpClientRecord rec,
	String table, DhcpDatastore datastore) throws BridgeException;
    public native void modifyDhcpClientRecord(DhcpClientRecord oldRecord,
	DhcpClientRecord newRecord, String table, DhcpDatastore datastore)
	throws BridgeException;
    public native void deleteDhcpClientRecord(DhcpClientRecord rec,
	String table, DhcpDatastore datastore) throws BridgeException;
    public native DhcpClientRecord getDhcpClientRecord(DhcpClientRecord rec,
	String table, DhcpDatastore datastore) throws BridgeException;
    public native DhcpdOptions readDefaults() throws BridgeException;
    public native void writeDefaults(DhcpdOptions defs)
	throws BridgeException;
    public native void removeDefaults() throws BridgeException;
    public native void startup() throws BridgeException;
    public native void shutdown() throws BridgeException;
    public native void reload() throws BridgeException;
    public native IPInterface [] getInterfaces() throws BridgeException;
    public native String [] getArguments(String line) throws BridgeException;
    public native String getStringOption(short code, String arg)
	throws BridgeException;
    public native IPAddress [] getIPOption(short code, String arg)
	throws BridgeException;
    public native long [] getNumberOption(short code, String arg)
	throws BridgeException;
    public native void createDhcptab(DhcpDatastore datastore)
	throws BridgeException;
    public native void deleteDhcptab(DhcpDatastore datastore)
	throws BridgeException;
    public native void createDhcpNetwork(String net, DhcpDatastore datastore)
	throws BridgeException;
    public native void deleteDhcpNetwork(String net, DhcpDatastore datastore)
	throws BridgeException;
    public native void makeLocation(DhcpDatastore datastore)
	throws BridgeException;
    public native boolean isServerRunning() throws BridgeException;
    public native boolean isVersionCurrent() throws BridgeException;
    static {
	
	System.load("/usr/sadm/admin/dhcpmgr/dhcpmgr.so.1");
    }
}
