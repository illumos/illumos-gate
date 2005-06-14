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
 * Copyright 2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
package com.sun.dhcpmgr.cli.dhcpconfig;

import com.sun.dhcpmgr.cli.common.DhcpCliFunction;
import com.sun.dhcpmgr.data.DhcpdOptions;
import com.sun.dhcpmgr.data.qualifier.*;
import com.sun.dhcpmgr.server.*;
import com.sun.dhcpmgr.bridge.BridgeException;

/**
 * Functions for handling all dhcpconfig options that manage the DHCP server
 * parameters.
 */
public class ConfigureService extends DhcpCfgFunction {

    /**
     * Return codes.
     *
     * These supplement the inherited SUCCESS and FAILURE return codes.
     * Note that these values are binary!!! The next value would be 4.
     */
    public static final int ENABLED	= 1;
    public static final int DISABLED	= 0;
    public static final int RUNNING	= 2;
    public static final int STOPPED	= 0;

    /**
     * Options that this DhcpCfgFunction will accept.
     */
    static final int supportedOptions[] = {
	DhcpCfg.SERVICE_ENABLE,
	DhcpCfg.SERVICE_DISABLE,
	DhcpCfg.SERVICE_REENABLE,
	DhcpCfg.SERVICE_QUERY,
    };

    public ConfigureService() {
	validOptions = supportedOptions;
    } // constructor

    /**
     * Returns the option flag for this function.
     * @returns
     *   The option flag for this function.
     */
    public int getFunctionFlag() {
	return DhcpCfg.CONFIGURE_SERVICE;
    } // getFunctionFlag

    /**
     * Parse and execute the options for this function.
     * @return
     *   DhcpCfg.SUCCESS for success and DhcpCfg.FAILURE for failure.
     */
    public int execute() throws IllegalArgumentException {
	Action action = null;
	boolean enableOptionSet;
	boolean disableOptionSet;
	boolean reenableOptionSet;
	boolean queryOptionSet;
	boolean[] possibleOptions =  {
	    enableOptionSet = options.isSet(DhcpCfg.SERVICE_ENABLE),
	    disableOptionSet = options.isSet(DhcpCfg.SERVICE_DISABLE),
	    reenableOptionSet = options.isSet(DhcpCfg.SERVICE_REENABLE),
	    queryOptionSet = options.isSet(DhcpCfg.SERVICE_QUERY)
	};

	int numOptionsSet = 0;
	for (int index = 0; index < possibleOptions.length; index++) {
	    if (possibleOptions[index]) {
		numOptionsSet++;
	    }
	}

	if (numOptionsSet != 1) {
	    String msg = getString("config_service_bad_action_error");
	    throw new IllegalArgumentException(msg);
	}

	if (enableOptionSet) {
	    action = new ActionEnable();
	} else if (disableOptionSet) {
	    action = new ActionDisable();
	} else if (reenableOptionSet) {
	    action = new ActionReenable();
	} else {
	    action = new ActionQuery();
	}

	return action.execute();
    } // execute

    /**
     * All functions are carried out through a specific action sub-classed
     * from this class. 
     */
    private interface Action {
	/**
	 * Execute the action.
	 *
	 * @return
	 *   DhcpCfg.SUCCESS for success and DhcpCfg.FAILURE for failure.
	 */
	public int execute();
    }

    /**
     * Shared super class for actions.
     */
    private abstract class ActionImpl implements Action {
	/**
	 * Server parameters.
	 */
	protected DhcpdOptions dhcpdOptions;

	/**
	 * Service manager.
	 */
	protected DhcpServiceMgr dhcpServiceMgr;

	/**
	 * Validate and execute the action. A sub-classed action is passed
	 * execution control via the doExecute() callback method.
	 *
	 * @return
	 *   DhcpCfg.SUCCESS for success and DhcpCfg.FAILURE for failure.
	 */
	public final int execute() {
	    dhcpServiceMgr = getSvcMgr();

	    try {
		dhcpdOptions = dhcpServiceMgr.readDefaults();
	    } catch (BridgeException be) {
		printErrMessage(
			getString("config_service_failed_read_params_error"));
		return DhcpCfg.FAILURE;
	    }

	    dhcpdOptions.clearDirty();

	    int result = doExecute();

	    if (result != DhcpCfg.FAILURE) {
		if (dhcpdOptionsWrite() == DhcpCfg.FAILURE) {
		    return DhcpCfg.FAILURE;
		}
	    }

	    return result;
	} // execute

	/**
	 * Sub-classed action callback method. Once validation has been
	 * performed execution is continued in the action sub-class by calling
	 * this method.
	 *
	 * @return
	 *   DhcpCfg.SUCCESS for success, otherwise DhcpCfg.FAILURE for failure.
	 */
	protected abstract int doExecute();

	/**
	 * Ensures that changes to the parameter are written back to the data
	 * store.
	 *
	 * @return
	 *   DhcpCfg.SUCCESS for success, otherwise DhcpCfg.FAILURE for failure.
	 */
	protected int dhcpdOptionsWrite() {
	    if (dhcpdOptions.isDirty()) {
		try {
		    dhcpServiceMgr.writeDefaults(dhcpdOptions);
		} catch (BridgeException e) {
		    printErrMessage(getString(
				"config_service_failed_write_params_error"));
		    return DhcpCfg.FAILURE;
		}

		dhcpdOptions.clearDirty();
	    }

	    return DhcpCfg.SUCCESS;
	}
    }

    /**
     * Enable the DHCP service.
     */
    private class ActionEnable extends ActionImpl {
	/**
	 * Enable the DHCP service.
	 *
	 * @return
	 *   DhcpCfg.SUCCESS for success, otherwise DhcpCfg.FAILURE for failure.
	 */
	protected int doExecute() {
	    if (!dhcpdOptions.isDaemonEnabled()) {
		dhcpdOptions.setDaemonEnabled(true);
		if (dhcpdOptionsWrite() == DhcpCfg.FAILURE) {
		    return DhcpCfg.FAILURE;
		}
		printMessage(getString("config_service_state_enabled"));
	    }

	    try {
		if (!dhcpServiceMgr.isServerRunning()) {
		    dhcpServiceMgr.startup();
		    printMessage(getString("config_service_state_startup"));
		}
	    } catch (BridgeException e) {
		printErrMessage(
			getString("config_service_failed_startup_error"));
		return DhcpCfg.FAILURE;
	    }

	    return DhcpCfg.SUCCESS;
	} // doExecute
    }

    /**
     * Disable the DHCP service.
     */
    private class ActionDisable extends ActionImpl {
	/**
	 * Disable the DHCP service.
	 *
	 * @return
	 *   DhcpCfg.SUCCESS for success, otherwise DhcpCfg.FAILURE for failure.
	 */
	protected int doExecute() {
	    if (dhcpdOptions.isDaemonEnabled()) {
		dhcpdOptions.setDaemonEnabled(false);
		if (dhcpdOptionsWrite() == DhcpCfg.FAILURE) {
		    return DhcpCfg.FAILURE;
		}
		printMessage(getString("config_service_state_disabled"));
	    }

	    try {
		if (dhcpServiceMgr.isServerRunning()) {
		    dhcpServiceMgr.shutdown();
		    printMessage(getString("config_service_state_shutdown"));
		}
	    } catch (BridgeException e) {
		printErrMessage(
			getString("config_service_failed_shutdown_error"));
		return DhcpCfg.FAILURE;
	    }

	    return DhcpCfg.SUCCESS;
	} // doExecute
    }

    /**
     * Reenable the DHCP service.
     */
    private class ActionReenable extends ActionImpl {
	/**
	 * Reenable the DHCP service.
	 *
	 * @return
	 *   DhcpCfg.SUCCESS for success, otherwise DhcpCfg.FAILURE for failure.
	 */
	protected int doExecute() {
	    try {
		if (dhcpServiceMgr.isServerRunning()) {
		    dhcpServiceMgr.shutdown();
		    printMessage(getString("config_service_state_shutdown"));
		}
	    } catch (BridgeException e) {
		printErrMessage(
			getString("config_service_failed_shutdown_error"));
		return DhcpCfg.FAILURE;
	    }

	    if (!dhcpdOptions.isDaemonEnabled()) {
		dhcpdOptions.setDaemonEnabled(true);
		if (dhcpdOptionsWrite() == DhcpCfg.FAILURE) {
		    return DhcpCfg.FAILURE;
		}
		printMessage(getString("config_service_state_enabled"));
	    }

	    try {
		dhcpServiceMgr.startup();
		printMessage(getString("config_service_state_startup"));
	    } catch (BridgeException e) {
		printErrMessage(
			getString("config_service_failed_startup_error"));
		return DhcpCfg.FAILURE;
	    }

	    return DhcpCfg.SUCCESS;
	} // doExecute
    }

    /**
     * Query the DHCP service.
     */
    private class ActionQuery extends ActionImpl {
	/**
	 * Query the DHCP service.
	 *
	 * @return
	 *   DhcpCfg.SUCCESS for success, otherwise DhcpCfg.FAILURE for failure.
	 */
	protected int doExecute() {
	    int serviceState = DhcpCfg.SUCCESS;

	    if (dhcpdOptions.isDaemonEnabled()) {
		printMessage(getString("config_service_state_enabled"));
		serviceState += ENABLED;
	    } else {
		printMessage(getString("config_service_state_disabled"));
		serviceState += DISABLED;
	    }

	    try {
		if (dhcpServiceMgr.isServerRunning()) {
		    printMessage(getString("config_service_state_running"));
		    serviceState += RUNNING;
		} else {
		    printMessage(getString("config_service_state_stopped"));
		    serviceState += STOPPED;
		}
	    } catch (BridgeException e) {
		printErrMessage(getString("config_service_failed_query_error"));
		return DhcpCfg.FAILURE;
	    }

	    return serviceState;
	} // doExecute
    }


} // ConfigureService
