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
 * Copyright (c) 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */
package com.sun.dhcpmgr.common;

import java.io.IOException;
import java.text.MessageFormat;
import java.util.ArrayList;

import com.sun.dhcpmgr.bridge.BridgeException;
import com.sun.dhcpmgr.bridge.ExistsException;
import com.sun.dhcpmgr.data.Network;
import com.sun.dhcpmgr.data.ActionError;
import com.sun.dhcpmgr.server.DhcpMgr;

/**
 * ExportController contains the logic to export the server's data to
 * a file for later import on either this server or some other server.
 * Users of this class must implement the Exporter interface in order
 * to provide communication.
 * @see Exporter
 * @see ImportController
 */
public class ExportController {
    Exporter exporter;
    DhcpMgr server;
    String user;
    String file;
    private boolean allNets = false, allMacros = false, allOptions = false;
    // Statics used to ensure we never have null array references
    private static final Network [] emptyNets = new Network[0];
    private static final String [] emptyMacros = new String[0];
    private static final String [] emptyOptions = new String[0];
    Network [] networks = emptyNets;
    String [] macros = emptyMacros;
    String [] options = emptyOptions;
    /*
     * The following constants are heuristics used to estimate the time
     * required to complete each step of the export process; they're used to
     * allow a GUI progress meter to pop up and behave relatively correctly.
     * We can't afford from a performance point of view to be precise as it
     * would defeat the purpose of our export architecture, so we try to
     * make sure the user gets at least some idea of where we are in the
     * process.  The *OPS constants indicate an estimate of how expensive
     * the delete operations are relative to the export operations.  YMMV.
     */
    private static final int OPTION_DELETE_OPS = 2;
    private static final int MACRO_DELETE_OPS = 2;
    private static final int NETWORK_DELETE_OPS = 2;
    private static final int DEFAULT_OPTION_COUNT = 10;
    private static final int DEFAULT_MACRO_COUNT = 50;
    private static final int DEFAULT_CLIENTS_PER_NET = 150;

    /**
     * Construct an ExportController with the given Exporter and a
     * server-side to use to perform the export.  Don't pass in "null" for
     * either argument; the implementation does not validate these inputs.
     * @param exporter The exporting object
     * @param server The server which will do the work for us.
     */
    public ExportController(Exporter exporter, DhcpMgr server) {
	this.exporter = exporter;
	this.server = server;
    }

    /**
     * Set the name of the user performing the export.  This is
     * recorded in the export file for reference at import.
     * @param user The name of the user
     */
    public void setUser(String user) {
	this.user = user;
    }

    /**
     * Set the name of the file to which to export.
     * @param file the full pathname of the file to export into
     */
    public void setFile(String file) {
	this.file = file;
    }

    /**
     * Specify that all networks are to be exported
     */
    public void setAllNetworks() {
	allNets = true;
	networks = emptyNets;
    }

    /**
     * Specify the networks to be exported.
     * @param networks An array of Network objects which should be exported
     */
    public void setNetworks(Network [] networks) {
	allNets = false;
	// Never allow networks to be null
	if (networks != null) {
	    this.networks = networks;
	} else {
	    this.networks = emptyNets;
	}
    }

    /**
     * Specify that all macros should be exported.
     */
    public void setAllMacros() {
	allMacros = true;
	macros = emptyMacros;
    }

    /**
     * Specify the macros to be exported.
     * @param macros An array of macro names
     */
    public void setMacros(String [] macros) {
	allMacros = false;
	// Never allow macros to be null
	if (macros != null) {
	    this.macros = macros;
	} else {
	    this.macros = emptyMacros;
	}
    }

    /**
     * Specify that all options should be exported
     */
    public void setAllOptions() {
	allOptions = true;
	options = emptyOptions;
    }

    /**
     * Specify the options to be exported.
     * @param options An array of option names
     */
    public void setOptions(String [] options) {
	allOptions = false;
	// Never allow options to be null
	if (options != null) {
	    this.options = options;
	} else {
	    this.options = emptyOptions;
	}
    }

    /**
     * Perform the actual export.
     * @param deleteData True if data should be deleted after a successful
     * export.
     * @param overwrite True if file should be forcibly overwritten.  An
     * ExistsException will be thrown if the file exists and overwrite is
     * false.
     * @return true if the export succeeded, false on failure.
     */
    public boolean exportData(boolean deleteData, boolean overwrite)
	    throws ExistsException {

	Object ref = null;

	// Value to return; default to false for failure
	boolean retval = false;

	// Default to deleting the file on any errors
	boolean deleteFile = true;

	if (allNets) {
	    try {
		// Load network list
		setNetworks(server.getNetMgr().getNetworks());
	    } catch (Exception e) {
		displayException(e,
		    ResourceStrings.getString("exp_err_loading_networks"));
		return false;
	    }
	}

	/*
	 * Number of records in the export file is number of networks, plus 1
	 * for options, plus 1 for macros.
	 */
	int recCount = networks.length + 2;

	// Calculate total number of estimated ops for progress
	int optionOps = allOptions ? DEFAULT_OPTION_COUNT : options.length;
	int optionDelOps = 0;
	int macroOps = allMacros ? DEFAULT_MACRO_COUNT : macros.length;
	int macroDelOps = 0;
	int netOps = DEFAULT_CLIENTS_PER_NET * networks.length;
	int netDelOps = 0;
	int totalOps = optionOps + macroOps + netOps;
	if (totalOps == 0) {
	    // Nothing to export!!!
	    exporter.displayError(ResourceStrings.getString("exp_err_no_data"));
	    return false;
	}
	// If user wants to delete, add to number of ops required
	if (deleteData) {
	    optionDelOps = optionOps * OPTION_DELETE_OPS;
	    macroDelOps = macroOps * MACRO_DELETE_OPS;
	    netDelOps = netOps * NETWORK_DELETE_OPS;
	    totalOps += optionDelOps + macroDelOps + netDelOps;
	}

	/*
	 * Open the file; catch IO errors, but if we get an ExistsException we
	 * just let that through to the caller, who's supposed to deal with it
	 * appropriately.
	 */
	try {
	    ref = server.openExportFile(file, user, recCount, networks,
		overwrite);
	    // If lock couldn't be obtained, display error and abort
	    if (ref == null) {
		String [] args = new String[2];
		args[0] = server.getDhcpServiceMgr().getServerName();
		args[1] = server.getLockPath();
		MessageFormat form = new MessageFormat(
		    ResourceStrings.getString("lock_error"));
		exporter.displayError(form.format(args));
		return false;
	    }
	} catch (IOException e) {
	    displayException(e, ResourceStrings.getString("exp_err_io"));
	    return false;
	}

	try {

	    // Initialize progress with our expected number of operations
	    exporter.initializeProgress(totalOps);
	    int progress = 0;

	    // Now export the options
	    if (optionOps != 0) {
		// Only update progress if we're actually doing something here
		exporter.updateProgress(progress,
		    ResourceStrings.getString("exp_exporting_options"));
	    }
	    try {
		server.exportOptions(ref, allOptions, options);
	    } catch (BridgeException e) {
		displayException(e,
		    ResourceStrings.getString("exp_err_exporting_options"));
		throw new InterruptedException();
	    }
	    progress += optionOps;

	    if (macroOps != 0) {
		// Only update progress if we're actually doing something here
		exporter.updateProgress(progress,
		    ResourceStrings.getString("exp_exporting_macros"));
	    }

	    // Now export the macros
	    try {
		server.exportMacros(ref, allMacros, macros);
	    } catch (BridgeException e) {
		displayException(e,
		    ResourceStrings.getString("exp_err_exporting_macros"));
		throw new InterruptedException();
	    }
	    progress += macroOps;

	    // Set up for progress messages
	    MessageFormat form = new MessageFormat(
		ResourceStrings.getString("exp_exporting_network"));
	    String [] nets = new String[1];

	    // Now export each network in turn
	    for (int i = 0; i < networks.length; ++i) {
		// Export the network
		try {
		    nets[0] = networks[i].toString();
		    exporter.updateProgress(progress, form.format(nets));
		    server.exportNetwork(ref, networks[i]);
		    progress += DEFAULT_CLIENTS_PER_NET;
		} catch (BridgeException e) {
		    MessageFormat fmt = new MessageFormat(
			ResourceStrings.getString("exp_err_exporting_network"));
		    String [] args = new String [] { nets[0], e.getMessage() };
		    exporter.displayError(fmt.format(args));
		    throw new InterruptedException();
		}
	    }

	    // Success; don't delete the file
	    deleteFile = false;

	    // If user wants data deleted, too, then do it now
	    if (deleteData) {
		ActionError [] optionErrs, macroErrs;

		// Delete options
		if (optionDelOps != 0) {
		    // Only update progress if something to delete
		    exporter.updateProgress(progress,
			ResourceStrings.getString("exp_deleting_options"));
		}
		if (allOptions) {
		    try {
			optionErrs = server.getDhcptabMgr().deleteAllOptions();
		    } catch (BridgeException e) {
			optionErrs = new ActionError[1];
			optionErrs[0] = new ActionError(
			    ResourceStrings.getString("all_options"), e);
		    }
		} else {
		    optionErrs = server.getDhcptabMgr().deleteOptions(options);
		}
		progress += optionDelOps;

		// Delete macros
		if (macroDelOps != 0) {
		    // Only update progress if something to delete
		    exporter.updateProgress(progress,
			ResourceStrings.getString("exp_deleting_macros"));
		}
		if (allMacros) {
		    try {
			macroErrs = server.getDhcptabMgr().deleteAllMacros();
		    } catch (BridgeException e) {
			macroErrs = new ActionError[1];
			macroErrs[0] = new ActionError(
			    ResourceStrings.getString("all_macros"), e);
		    }
		} else {
		    macroErrs = server.getDhcptabMgr().deleteMacros(macros);
		}
		progress += macroDelOps;

		// Delete each network in turn
		form = new MessageFormat(
		    ResourceStrings.getString("exp_deleting_network"));
		ArrayList errList = new ArrayList();
		for (int i = 0; i < networks.length; ++i) {
		    nets[0] = networks[i].toString();
		    exporter.updateProgress(progress, form.format(nets));
		    try {
			server.getNetMgr().deleteNetwork(nets[0], false);
		    } catch (BridgeException e) {
			errList.add(new ActionError(nets[0], e));
		    }
		    progress += DEFAULT_CLIENTS_PER_NET * NETWORK_DELETE_OPS;
		}

		// This update informs caller we're done
		exporter.updateProgress(progress,
		    ResourceStrings.getString("export_completed"));
		// Now display whatever errors happened during delete
		if (optionErrs != null && optionErrs.length > 0) {
		    exporter.displayErrors(
			ResourceStrings.getString("exp_err_deleting_options"),
			ResourceStrings.getString("exp_option"),
			optionErrs);
		}

		if (macroErrs != null && macroErrs.length > 0) {
		    exporter.displayErrors(
			ResourceStrings.getString("exp_err_deleting_macros"),
			ResourceStrings.getString("exp_macro"),
			macroErrs);
		}

		if (!errList.isEmpty()) {
		    exporter.displayErrors(
			ResourceStrings.getString("exp_err_deleting_networks"),
			ResourceStrings.getString("exp_network"),
			(ActionError [])errList.toArray(new ActionError[0]));
		}
	    }
	    retval = true;
	} catch (InterruptedException e) {
	    /*
	     * User wanted to cancel, or some serious failure occurred; in the
	     * former case no need to display anything, in the latter it
	     * was already displayed before we got here, so just return.
	     */
	    retval = false;
	} catch (Exception e) {
	    // I/O error of some sort.  Display it before returning.
	    displayException(e, ResourceStrings.getString("exp_err_io"));
	    retval = false;
	} finally {
	    // Always close before leaving; display any resulting errors
	    try {
		server.closeExportFile(ref, deleteFile);
	    } catch (IOException e) {
		displayException(e,
		    ResourceStrings.getString("exp_err_closing_file"));
	    }
	}
	return retval;
    }

    // Utility method to display an error message for an exception
    private void displayException(Exception e, String format) {
	MessageFormat form = new MessageFormat(format);
	String [] args = new String [] { e.getMessage() };
	exporter.displayError(form.format(args));
    }
}
