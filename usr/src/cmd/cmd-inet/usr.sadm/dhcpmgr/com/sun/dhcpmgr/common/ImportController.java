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
 * Copyright 2001-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
package com.sun.dhcpmgr.common;

import java.io.IOException;
import java.text.MessageFormat;

import com.sun.dhcpmgr.data.ExportHeader;
import com.sun.dhcpmgr.data.ActionError;
import com.sun.dhcpmgr.data.Network;
import com.sun.dhcpmgr.server.DhcpMgr;
import com.sun.dhcpmgr.bridge.BridgeException;

/**
 * ImportController contains the logic to import data from a file to the
 * server's data store.  The file must have been written using the export
 * procedure defined by ExportController.  Users of this class must implement
 * the Importer interface, which allows this class to communicate with the
 * user.
 * @see Importer
 * @see ExportController
 */
public class ImportController {
    Importer importer;
    DhcpMgr server;
    String file;
    Object ref = null;
    ExportHeader header = null;
    /*
     * The following constants are heuristics used to estimate the time
     * required to complete each step of the import process; they're used to
     * allow a GUI progress meter to pop up and behave relatively correctly.
     * We can't afford from a performance point of view to be precise as it
     * would defeat the purpose of our import architecture, so we try to
     * make sure the user gets at least some idea of where we are in the
     * process.  The *OPS constants indicate an estimate of how expensive
     * the various operations are relative to each other in a "typical"
     * import, the assumption being that there are 5 macros exported to every
     * option exported, and that there are around 150 clients per network.
     * Obviously these can vary widely, but it gets the idea across pretty well.
     */
    private static final int OPTION_OPS = 1;
    private static final int MACRO_OPS = 5;
    private static final int NET_OPS = 150;

    /**
     * Construct an ImportController with the given Importer and server
     * implementation to use for the import process.  Don't pass in "null"
     * for either argument; the implementation does not validate these inputs.
     * @param importer The importing object
     * @param server The server which will perform the work
     */
    public ImportController(Importer importer, DhcpMgr server) {
	this.importer = importer;
	this.server = server;
    }

    /**
     * Set the name of the file to be used for the import
     * @param file The name of the file.
     */
    public void setFile(String file) {
	// We can only have one file open at a time; close any currently open.
	closeFile();
	this.file = file;
    }

    /**
     * Close the file and clean up references
     */
    public void closeFile() {
	if (ref != null) {
	    try {
		// We *never* delete the file here
		server.closeImportFile(ref, false);
	    } catch (IOException e) {
	    	displayError(ResourceStrings.getString("imp_err_io"),
		    e.getMessage());
	    }
	}
	ref = null;
	header = null;
    }
    /**
     * Retrieve the header from the file.
     * @return the header record from the file
     */
    public ExportHeader getHeader()
	    throws ClassNotFoundException, IOException {
	// If header not already read, then read it
	if (header == null) {
	    // If file not yet open, then open it now
	    if (ref == null) {
		ref = server.openImportFile(file);
		if (ref == null) {
		    // Import/export lock not available, display error and abort
		    String [] args = new String[2];
		    args[0] = server.getDhcpServiceMgr().getServerName();
		    args[1] = server.getLockPath();
		    MessageFormat form = new MessageFormat(
			ResourceStrings.getString("lock_error"));
		    importer.displayError(form.format(args));
		    return null;
		}
	    }
	    header = server.getExportHeader(ref);
	}
	return header;
    }

    /**
     * Import the data, optionally overwriting any conflicting data
     * @param overwrite true if conflicting objects should be overwritten.
     * @return true if the import completed successfully, false if not
     */
    public boolean importData(boolean overwrite) {
	// Default return is that import did not complete
	boolean retval = false;
	int totalOps = 0;
	try {
	    // Ensure file is open and header has been read
	    if (getHeader() == null) {
		// Couldn't get header; abort
		return false;
	    }

	    /*
	     * Initialize progress display; recCount is number of networks + 
	     * one for macros and one for options.
	     */
	    int recCount = header.getRecCount();
	    totalOps = OPTION_OPS + MACRO_OPS + NET_OPS * (recCount - 2);
	    importer.initializeProgress(totalOps);
	    int progress = 0;

	    //  Update progress, and import the options
	    importer.updateProgress(progress,
		ResourceStrings.getString("importing_options"));
	    ActionError [] result = server.importOptions(ref, overwrite);
	    if (result.length > 0) {
		importer.displayErrors(
		    ResourceStrings.getString("imp_err_importing_options"),
		    ResourceStrings.getString("imp_option"), result);
	    }

	    // Update progress and import the macros
	    progress += OPTION_OPS;
	    importer.updateProgress(progress, 
		ResourceStrings.getString("importing_macros"));
	    result = server.importMacros(ref, overwrite);
	    if (result.length > 0) {
		importer.displayErrors(
		    ResourceStrings.getString("imp_err_importing_macros"),
		    ResourceStrings.getString("imp_macro"), result);
	    }

	    // Set up for network progress messages
	    progress += MACRO_OPS;
	    MessageFormat form = new MessageFormat(
		ResourceStrings.getString("importing_network"));
	    String [] args = new String[1];

	    /*
	     * Get list of networks from the header; ExportController never
	     * writes a null reference, always a zero-length array at worst.
	     */
	    Network [] nets = header.getNetworks();
	    for (int i = 0; i < nets.length; ++i) {
		// For each network, update progress and import it
		args[0] = nets[i].toString();
		importer.updateProgress(progress, form.format(args));
		result = server.importNetwork(nets[i], ref, overwrite);
		if (result.length > 0) {
		    MessageFormat errFmt = new MessageFormat(
			ResourceStrings.getString("imp_err_importing_net"));
		    importer.displayErrors(errFmt.format(args),
			ResourceStrings.getString("imp_address"), result);
		}
		progress += NET_OPS;
	    }
	    retval = true;
	} catch (InterruptedException e) {
	    // User asked us to stop; nothing to do but let it fall through
	} catch (ClassNotFoundException e) {
	    // Bad version of file
	    displayError(ResourceStrings.getString("imp_err_file_fmt"),
	        e.getMessage());
	} catch (Exception e) {
	    // Error reading the file
	    displayError(ResourceStrings.getString("imp_err_io"),
	        e.getMessage());
	} finally {
	    // Finish progress
	    try {
	    	importer.updateProgress(totalOps,
		    ResourceStrings.getString("import_completed"));
	    } catch (InterruptedException e) {
		// Ignore
	    }
	    // Always close import file
	    closeFile();
	}
	return retval;
    }

    private void displayError(String format, String data) {
    	MessageFormat form = new MessageFormat(format);
	String [] args = new String [] { data };
	importer.displayError(form.format(args));
    }
}
