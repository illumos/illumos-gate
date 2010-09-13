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
 * Copyright (c) 1998-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */
package com.sun.dhcpmgr.server;

import java.io.*;
import java.util.zip.*;
import java.util.*;

import com.sun.dhcpmgr.bridge.*;
import com.sun.dhcpmgr.data.*;

public class DhcpMgrImpl implements DhcpMgr {
    private Bridge bridge;
    private DhcpNetMgrImpl netMgr;
    private DhcptabMgrImpl dtMgr;
    private DhcpServiceMgrImpl srvMgr;
    // Global lock file used to ensure only one export or import is running
    private static final String LOCK_FILE = "/var/run/dhcp_import_export_lock";
    private static final File lockFile = new File(LOCK_FILE);
    private File currentlyOpenFile = null;
    private Object currentStream = null;

    public DhcpMgrImpl() {
	bridge = new Bridge();
    }

    public DhcpNetMgr getNetMgr()  {
	if (netMgr == null) {
	    netMgr = new DhcpNetMgrImpl(bridge);
	}
	return netMgr;
    }

    public DhcptabMgr getDhcptabMgr()  {
	if (dtMgr == null) {
	    dtMgr = new DhcptabMgrImpl(bridge);
	}
	return dtMgr;
    }

    public DhcpServiceMgr getDhcpServiceMgr()  {
	if (srvMgr == null) {
	    srvMgr = new DhcpServiceMgrImpl(bridge);
	}
	return srvMgr;
    }

    /**
     * Set the file which is currently open.
     */
    private synchronized File setFile(String name) throws IOException {
	// Some other file is currently listed as open; deny the request
	if (currentlyOpenFile != null) {
	    return null;
	}

	// Get system-wide lock by atomically creating lockfile
	if (!lockFile.createNewFile()) {
	    return null;
	}
	currentlyOpenFile = new File(name);
	currentStream = null;
	return currentlyOpenFile;
    }

    private synchronized void clearFile(File file) {
	// If this is truly the currently open file, then clear our reference
	if (isFileOpen(file)) {
	    currentlyOpenFile = null;
	    currentStream = null;
	    // Release system-wide lock by deleting lockfile
	    lockFile.delete();
	}
    }

    /**
     * Get the file which is currently open.
     */
    private synchronized File getFile() {
	return currentlyOpenFile;
    }

    /**
     * Test whether a file is currently open.
     */
    private synchronized boolean isFileOpen(File file) {
	return (file == currentlyOpenFile);
    }

    /**
     * Returns the fullpath to the lock file.
     * @return the fullpath to the lock file.
     */
    public String getLockPath() {
	return (LOCK_FILE);
    }

    /**
     * Opens an export file and writes a header record to it.
     * @param fileName the fullpath to the export file to create.
     * @param user the name of the user creating this file
     * @param nets an array of networks which will be exported
     * @param overwrite true if file should be forcible overwritten
     * @return a reference key for this file instance, or null if there is
     * another file already open for import or export
     */
    public Object openExportFile(String fileName, String user,
	    int recCount, Network [] nets, boolean overwrite)
	    throws ExistsException, IOException {

	// Grab the lock
	File file = setFile(fileName);

	if (file != null) {
	    // File exists and not supposed to overwrite, throw exception
	    if (!overwrite && file.exists()) {
		clearFile(file);
		throw new ExistsException(fileName);
	    }

	    try {
		// Open a stream to write on
		ObjectOutputStream export = new ObjectOutputStream(
		    new GZIPOutputStream(new FileOutputStream(file)));

		// Construct a header record, and write it
		ExportHeader header = new ExportHeader(
		    getDhcpServiceMgr().getServerName(), user, recCount, nets);
		export.writeObject(header);

		// Save stream reference
		currentStream = export;
	    } catch (IOException e) {
		// Something went wrong, release the lock and re-throw
		clearFile(file);
		throw e;
	    }
	}
	// Give caller a reference to use for writing additional data
	return file;
    } // openExportFile

    /**
     * Close an export file, delete it if need be
     * @param ref Reference to the open file, returned from openExportFile
     * @param delete true if file is to be deleted on close, false otherwise.
     */
    public void closeExportFile(Object ref, boolean delete) throws IOException {
	if (!isFileOpen((File)ref)) {
	    throw new FileNotFoundException(((File)ref).getName());
	}
	try {
	    ObjectOutputStream oos = (ObjectOutputStream)currentStream;
	    oos.flush();
	    oos.close();
	    if (delete) {
		((File)ref).delete();
	    }
	} catch (IOException e) {
	    // Just re-throw, let finally block clean up
	    throw e;
	} finally {
	    /*
	     * Always release the lock, we consider the file no longer useful
	     * no matter the outcome above.
	     */
	    clearFile((File)ref);
	}
    }

    /**
     * Open an import file
     * @param fileName Name of file to open
     * @return A reference to the opened import file, or null if another
     * export or import is already in progress.
     */
    public Object openImportFile(String fileName) throws IOException {
	File file = setFile(fileName);
	if (file != null) {
	    if (!file.exists()) {
		clearFile(file);
		throw new FileNotFoundException(fileName);
	    }

	    try {
		currentStream = new ObjectInputStream(new GZIPInputStream(
		    new FileInputStream(file)));
	    } catch (IOException e) {
		clearFile(file);
		throw e;
	    }
	}
	// Return reference caller can use to actually do the import
	return file;
    }

    /**
     * Close an import file, delete it if need be
     * @param ref Reference to the open file, returned from openImportFile
     * @param delete true if file is to be deleted on close, false otherwise.
     */
    public void closeImportFile(Object ref, boolean delete) throws IOException {
	if (!isFileOpen((File)ref)) {
	    throw new FileNotFoundException(((File)ref).getName());
	}
	try {
	    ((ObjectInputStream)currentStream).close();
	    if (delete) {
    		((File)ref).delete();
	    }
	} catch (IOException e) {
	    // Just re-throw and let finally do the cleanup
	    throw e;
	} finally {
	    clearFile((File)ref);
	}
    }

    /**
     * Retrieve the export header for the import file
     * @param ref Reference to the file we're reading from
     * @return The ExportHeader written at export time.
     */
    public ExportHeader getExportHeader(Object ref)
	    throws IOException, ClassNotFoundException {
	if (!isFileOpen((File)ref)) {
	    // No such file open; throw an exception
	    throw new FileNotFoundException(((File)ref).getName());
	} else {
	    ObjectInputStream ois = (ObjectInputStream)currentStream;
	    ExportHeader rec = (ExportHeader)ois.readObject();
	    return rec;
	}
    }

    // Get the desired records out of an array
    private ArrayList getSelectedRecs(String [] names, DhcptabRecord [] recs)
	    throws NoEntryException {
	// Grab only the ones we want
	TreeSet nameSet = new TreeSet(Arrays.asList(names));
	ArrayList recArr = new ArrayList();
	for (int i = 0; i < recs.length; ++i) {
	    if (nameSet.contains(recs[i].getKey())) {
		recArr.add(recs[i]);
		nameSet.remove(recs[i].getKey());
	    }
	}
	if (!nameSet.isEmpty()) {
	    // We didn't find one of the requested records
	    throw new NoEntryException((String)nameSet.first());
	}
	return recArr;
    }

    /**
     * Export a list of macros specified by name to a file.
     * @param ref A reference to the file, acquired from openExportFile()
     * @param allMacros true if all macros are to be exported
     * @param names names of macros to be exported if allMacros is false
     */
    public void exportMacros(Object ref, boolean allMacros, String [] names)
	    throws BridgeException, IOException {
	if (!isFileOpen((File)ref)) {
	    // throw an exception that this is a bad reference
	    throw new FileNotFoundException(((File)ref).getName());
	}

	Macro [] macros = getDhcptabMgr().getMacros();
	if (!allMacros) {
	    // Grab only the ones we want
	    ArrayList macArr = getSelectedRecs(names, macros);
	    macros = (Macro [])macArr.toArray(new Macro[0]);
	}

	ObjectOutputStream oos = (ObjectOutputStream)currentStream;
	oos.writeObject(macros);
    }

    /**
     * Export a list of options specified by name to a file.
     * @param ref A reference to the file, acquired from openExportFile()
     * @param allOptions true if all options are to be exported
     * @param names names of options to be exported if allOptions is false
     */
    public void exportOptions(Object ref, boolean allOptions, String [] names)
	    throws BridgeException, IOException {
	if (!isFileOpen((File)ref)) {
	    // throw an exception that this is a bad reference
	    throw new FileNotFoundException(((File)ref).getName());
	}

	Option [] options = getDhcptabMgr().getOptions();
	if (!allOptions) {
	    // Grab only the ones we want
	    ArrayList optArr = getSelectedRecs(names, options);
	    options = (Option [])optArr.toArray(new Option[0]);
	}

	ObjectOutputStream oos = (ObjectOutputStream)currentStream;
	oos.writeObject(options);
    }

    /**
     * Export a network and its client records to a file
     * @param ref A reference to the file, acquired from openExportFile()
     * @param net Network to be exported
     */
    public void exportNetwork(Object ref, Network net)
	    throws BridgeException, IOException {
	if (!isFileOpen((File)ref)) {
	    // throw an exception that this is a bad reference
	    throw new FileNotFoundException(((File)ref).getName());
	}

	// Get clients from database
	DhcpClientRecord [] clients =
	    getNetMgr().loadNetworkCompletely(net.toString());

	// Now write client array for this net
	ObjectOutputStream oos = (ObjectOutputStream)currentStream;
	oos.writeObject(clients);
    }

    /**
     * Import dhcptab records from an export file into the configuration.
     * @param recType The type of record to import; must be either
     * DhcptabRecord.MACRO or DhcptabRecord.OPTION
     * @param ref The file reference returned by openImportFile()
     * @param overwrite true if this data should overwrite existing data
     * @return An array of import results; empty if all records were imported.
     */
    private ActionError [] importDhcptabRecs(String recType, Object ref,
	    boolean overwrite)
	    throws IOException, OptionalDataException, ClassNotFoundException {

	ArrayList resultList = new ArrayList();
	DhcptabRecord [] recs = new DhcptabRecord[0];

	if (!isFileOpen((File)ref)) {
	    // No such file open; throw an exception
	    throw new FileNotFoundException(((File)ref).getName());
	}
	ObjectInputStream ois = (ObjectInputStream)currentStream;
	recs = (DhcptabRecord [])ois.readObject();
	// Try to cast to appropriate type to ensure data is OK.
	if (recType.equals(DhcptabRecord.MACRO)) {
	    Macro [] macros = (Macro []) recs;
	} else {
	    Option [] options = (Option []) recs;
	}

	DhcptabMgr mgr = getDhcptabMgr();
	for (int i = 0; recs != null && i < recs.length; ++i) {
	    try {
		if (overwrite) {
		    /*
		     * Hack alert!  We reset the signature to a default value
		     * that the datastores will not interpret.  This allows us
		     * to forcibly delete the record, even if it came from a
		     * previous attempt to import this record.  Without this
		     * step, the datastore may (correctly) signal an update
		     * collision and refuse to perform the delete.  An
		     * alternative that might be used is to mark the signature
		     * member of DhcptabRecord as transient; however, that would
		     * have the future undesirable effect of dropping that
		     * field when we put a remote communication method
		     * in the mix which uses serialization, such as RMI.
		     */
		    recs[i].setSignature(DhcptabRecord.DEFAULT_SIGNATURE);
		    mgr.deleteRecord(recs[i], false);
		}
	    } catch (Throwable t) {
		// Do nothing; we'll probably have an error on the create
	    }
	    try {
		mgr.createRecord(recs[i], false);
	    } catch (Exception e) {
		// Record the error, we try all of them no matter what
		resultList.add(new ActionError(recs[i].getKey(), e));
	    }
	}

	return (ActionError [])resultList.toArray(new ActionError[0]);
    }

    /**
     * Import options from an export file.
     * @param ref Reference to import file returned by openImportFile
     * @param overwrite true if existing data should be overwritten.
     * @return An array of errors in the import process; empty if all OK
     */
    public ActionError [] importOptions(Object ref, boolean overwrite)
	    throws IOException, OptionalDataException, ClassNotFoundException {
	return importDhcptabRecs(DhcptabRecord.OPTION, ref, overwrite);
    }

    /**
     * Import macros from an export file.
     * @param ref Reference to import file returned by openImportFile
     * @param overwrite true if existing data should be overwritten.
     * @return An array of errors in the import process; empty if all OK
     */
    public ActionError [] importMacros(Object ref, boolean overwrite)
	    throws IOException, OptionalDataException, ClassNotFoundException {
	return importDhcptabRecs(DhcptabRecord.MACRO, ref, overwrite);
    }



    /**
     * Import network records from an export file into the configuration.
     * @param net The network which is expected to be imported
     * @param ref The file reference returned by openImportFile()
     * @param overwrite true if this data should overwrite existing data
     * @return An array of import results; empty if all records were imported.
     */
    public ActionError [] importNetwork(Network net, Object ref,
	    boolean overwrite) throws IOException, OptionalDataException,
	    ClassNotFoundException, BridgeException {

	if (!isFileOpen((File)ref)) {
	    // No such file open; throw an exception
	    throw new FileNotFoundException(((File)ref).getName());
	}

	ArrayList resultList = new ArrayList();
	DhcpClientRecord [] clients = null;
	ObjectInputStream ois = (ObjectInputStream)currentStream;
	clients = (DhcpClientRecord [])ois.readObject();

	String networkName = net.toString();
	DhcpNetMgr mgr = getNetMgr();

	// Create the network table. It may already exist.
	boolean netExisted = false;
	try {
	    mgr.createNetwork(networkName);
	} catch (TableExistsException e) {
	    /*
	     * This is o.k. no matter whether overwrite is true or not;
	     * however, record the fact that it existed so that we don't
	     * optimize out the delete in the loop below.
	     */
	    netExisted = true;
	}

	// Add the addresses to the table and record any exceptions.
	for (int i = 0; clients != null && i < clients.length; ++i) {
	    /*
	     * If we're supposed to overwrite and the network table
	     * existed before we started, then try to delete the client
	     */
	    if (overwrite && netExisted) {
		try {
		    /*
		     * Hack alert!  We reset the signature to a default value
		     * that the datastores will not interpret.  This allows us
		     * to forcibly delete the record, even if it came from a
		     * previous attempt to import this record.  Without this
		     * step, the datastore may "correctly" signal an update
		     * collision and refuse to perform the delete.  An
		     * alternative that might be used is to mark the signature
		     * member of DhcptabRecord as transient; however, that would
		     * have the future undesirable effect of dropping that
		     * field when we put a remote communication method
		     * in the mix which uses serialization, such as RMI.
		     */
		    clients[i].setSignature(DhcpClientRecord.DEFAULT_SIGNATURE);
		    mgr.deleteClient(clients[i], networkName);
		} catch (Throwable t) {
		    // Ignore delete error, we'll probably have an error on add
		}
	    }
	    try {
		// Now add the client
		mgr.addClient(clients[i], networkName);
	    } catch (Exception e) {
		String address = clients[i].getClientIPAddress();
		resultList.add(new ActionError(address, e));
	    }
	}

	return (ActionError [])resultList.toArray(new ActionError[0]);
    }
}
