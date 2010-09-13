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

import java.util.List;
import java.util.ArrayList;
import java.util.Iterator;
import com.sun.dhcpmgr.cli.common.GetSubOpt;
import com.sun.dhcpmgr.cli.common.DhcpCliFunction;
import com.sun.dhcpmgr.data.DhcpdOptions;
import com.sun.dhcpmgr.data.DhcpResource;
import com.sun.dhcpmgr.data.qualifier.*;
import com.sun.dhcpmgr.bridge.BridgeException;

/**
 * Functions for handling all dhcpconfig options that manage the DHCP server
 * parameters.
 */
public class ServerParameter extends DhcpCfgFunction {

    /**
     * Options that this DhcpCfgFunction will accept.
     */
    static final int supportedOptions[] = {
    };

    /**
     * List of suboptions.
     */
    private String subOptions;

    /**
     * Simple constructor
     */
    public ServerParameter(String subOptions) {
	validOptions = supportedOptions;
	this.subOptions = subOptions;
    } // constructor

    /**
     * Returns the option flag for this function.
     * @returns
     *   The option flag for this function.
     */
    public int getFunctionFlag() {
	return DhcpCfg.CONFIGURE_SERVER_PARAMETER;
    } // getFunctionFlag

    /**
     * Parse and execute the options for this function.
     * @return
     *   DhcpCfg.SUCCESS for success and DhcpCfg.FAILURE for failure.
     */
    public int execute() throws IllegalArgumentException {
	List actions = new ArrayList();

	if (subOptions == null || subOptions.length() == 0) {	
	    actions.add(new ActionGetAll());
	} else {
	    GetSubOpt getSubOpt = new GetSubOpt(subOptions);

	    while (getSubOpt.hasMoreSubOptions()) {
		String keyword = getSubOpt.getNextSubOption();
		String value = getSubOpt.getSubOptionArg();

		boolean valueSet = (value != null);

		if (value == null) {
		    actions.add(new ActionGet(keyword));
		} else {
		    if (value.equals("")) {
			actions.add(new ActionDelete(keyword));
		    } else {
			actions.add(new ActionSet(keyword, value));
		    }
		}
	    }
	}

	DhcpdOptions dhcpdOptions;
	boolean atLeastOneActionFailed;
	Iterator iterator;

	try {
	    dhcpdOptions = getSvcMgr().readDefaults();
	} catch (BridgeException be) {
	    printErrMessage(
		    getString("server_parameter_failed_read_params_error"));
	    return DhcpCfg.FAILURE;
	}

	atLeastOneActionFailed = false;

	// Initialise the actions.
	iterator = actions.iterator();
	while (iterator.hasNext()) {
	    Action action = (Action) iterator.next();

	    if (action.init(dhcpdOptions) != DhcpCfg.SUCCESS) {
		atLeastOneActionFailed = true;
	    }
	}

	if (atLeastOneActionFailed) {
	    return DhcpCfg.FAILURE;
	}

	dhcpdOptions.clearDirty();

	atLeastOneActionFailed = false;

	// Execute the actions.
	iterator = actions.iterator();
	while (iterator.hasNext()) {
	    Action action = (Action) iterator.next();

	    if (action.execute() != DhcpCfg.SUCCESS) {
		atLeastOneActionFailed = true;
	    }
	}

	if (atLeastOneActionFailed) {
	    return DhcpCfg.FAILURE;
	}

	if (dhcpdOptions.isDirty()) {
	    try {
		getSvcMgr().writeDefaults(dhcpdOptions);
	    } catch (BridgeException e) {
		printErrMessage(
			getString(
			    "server_parameter_failed_write_params_error"));
		return DhcpCfg.FAILURE;
	    }

	    dhcpdOptions.clearDirty();
	}

	return DhcpCfg.SUCCESS;
    } // execute

    /**
     * All functions are carried out through a specific action sub-classed
     * from this class. 
     */
    private interface Action {
	/**
	 * Initialise the action.
	 *
	 * @param dhcpdOptions
	 *   The server options that an action manipulates.
	 *
	 * @return
	 *   DhcpCfg.SUCCESS for success and DhcpCfg.FAILURE for failure.
	 */
	public int init(DhcpdOptions dhcpdOptions);

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
	 * The server parameter this action works upon. Could be null.
	 */
	protected String keyword;

	/**
	 * The value this action works upon. Could be null.
	 */
	protected String value;

	/**
	 * The qualifier for the server parameter. If the keyword is null
	 * the qualifier will be null. The general rule is that if keyword is
	 * not null, qualifier must not be null. If it is then the keyword
	 * is not a recognised server parameter.
	 */
	protected Qualifier qualifier;

	/**
	 * Server parameters.
	 */
	protected DhcpdOptions dhcpdOptions;

	/**
	 * Construct an action for the given server parameter keyword and
	 * value. The constructor will find the appropriate qualifier that
	 * matches the keyword if the keyword is not null. Note that no
	 * checking on the validity of the keyword contents is made at this
	 * point.
	 *
	 * @param keyword
	 *   The server parameter this action works upon. Could be null.
	 * @param value
	 *   The value this action works upon. Could be null.
	 */
	protected ActionImpl(String keyword, String value) {
	    this.keyword = keyword;
	    this.value = value;
	} // constructor

	/**
	 * Get the keyword.
	 *
	 * @return
	 *   The keyword this action operates upon.
	 */
	public String getKeyword() {
	    return keyword;
	}

	/**
	 * Validate and initialise the action. A sub-classed action is passed
	 * execution control via the doExecute() callback method.
	 *
	 * @return
	 *   DhcpCfg.SUCCESS for success and DhcpCfg.FAILURE for failure.
	 */
	public final int init(DhcpdOptions dhcpdOptions) {
	    if (dhcpdOptions == null) {
		return DhcpCfg.FAILURE;
	    }

	    this.dhcpdOptions = dhcpdOptions;

	    if (keyword != null) {
		qualifier = dhcpdOptions.getQualifier(keyword);

		if (qualifier == null) {
		    Object[] arguments = new Object[1];
		    arguments[0] = keyword;
		    printErrMessage(
			getString(
			    "server_parameter_keyword_bad_keyword_error"),
			arguments);
		    return DhcpCfg.FAILURE;
		}
	    }

	    return doInit();
	} // execute

	/**
	 * Sub-classed action callback method. Once validation has been
	 * performed initialisation is continued in the action sub-class
	 * by calling this method.
	 *
	 * @return
	 *   DhcpCfg.SUCCESS for success, otherwise DhcpCfg.FAILURE for failure.
	 */
	protected abstract int doInit();

	/**
	 * Validate and execute the action. A sub-classed action is passed
	 * execution control via the doExecute() callback method.
	 *
	 * @return
	 *   DhcpCfg.SUCCESS for success and DhcpCfg.FAILURE for failure.
	 */
	public final int execute() {
	    if (dhcpdOptions == null) {
		return DhcpCfg.FAILURE;
	    }

	    return doExecute();
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
    }

    /**
     * Set a parameter action.
     */
    private class ActionSet extends ActionImpl {
    
	/**
	 * Construct an add action.
	 *
	 * @param keyword
	 *   The server parameter this action works upon.
	 * @param value
	 *   The value this action works upon.
	 */
	public ActionSet(String keyword, String value) {
	    super(keyword, value);
	} // constructor

	protected int doInit() {
	    if (qualifier.isReadOnly()) {
		Object[] arguments = new Object[1];
		arguments[0] = keyword;
		printErrMessage(
			getString(
			    "server_parameter_keyword_set_read_only_error"),
			arguments);
		return DhcpCfg.FAILURE;
	    }

	    QualifierType qualifierType = qualifier.getType();

	    if (qualifierType.parseValue(value) == null) {
		Object[] arguments = new Object[2];
		arguments[0] = keyword;
		arguments[1] = value;
		printErrMessage(
			getString(
			    "server_parameter_keyword_set_bad_value_error"),
			arguments);
		return DhcpCfg.FAILURE;
	    }

	    return DhcpCfg.SUCCESS;
	}

	/**
	 * Set the parameters value.
	 *
	 * @return
	 *   DhcpCfg.SUCCESS for success, otherwise DhcpCfg.FAILURE for failure.
	 */
	protected int doExecute() {
	    QualifierType qualifierType = qualifier.getType();

	    dhcpdOptions.set(keyword, qualifierType.formatValue(value));
	    dhcpdOptions.set(keyword, qualifierType.formatValue(value));

	    return DhcpCfg.SUCCESS;
	} // doExecute

    }

    /**
     * Get a parameter action.
     */
    private class ActionGet extends ActionImpl {

	/**
	 * This field controls the displaying of the keyword in addition
	 * to the keywords value. The default is to not show the keyword.
	 */
	protected boolean showKeyword = false;

	/**
	 * Construct a get action
	 *
	 * @param keyword
	 *   The server parameter this action works upon.
	 */
	public ActionGet(String keyword) {
	    super(keyword, null);
	} // constructor

	protected int doInit() {
	    if (!dhcpdOptions.isSet(keyword)) {
		Object[] arguments = new Object[1];
		arguments[0] = keyword;
		printErrMessage(
			getString("server_parameter_keyword_not_set_error"),
			arguments);

		return DhcpCfg.FAILURE;
	    }

	    return DhcpCfg.SUCCESS;
	}

	/**
	 * Get the parameters value.
	 *
	 * @return
	 *   DhcpCfg.SUCCESS for success, otherwise DhcpCfg.FAILURE for failure.
	 */
	protected int doExecute() {
	    Object[] arguments;

	    if (showKeyword) {
		arguments = new Object[2];
		arguments[0] = keyword;
		arguments[1] = dhcpdOptions.valueOf(keyword);
		printMessage(
			getString("server_parameter_get_keyword_value"),
			arguments);
	    } else {
		arguments = new Object[1];
		arguments[0] = dhcpdOptions.valueOf(keyword);
		printMessage(getString("server_parameter_get_value"),
			arguments);
	    }

	    return DhcpCfg.SUCCESS;

	} // doExecute

	/**
	 * This method controls the displaying of the keyword in addition
	 * to the keywords value.
	 *
	 * @param showKeyword
	 *   If true the keyword is shown with the value, otherwise only the
	 *   the value is shown.
	 */
	public void setShowKeyword(boolean showKeyword) {
	    this.showKeyword = showKeyword;
	}

    }

    /**
     * Get all parameters action.
     */
    private class ActionGetAll extends ActionImpl {

	protected List subActions;

	/**
	 * Construct a get all action.
	 */
	public ActionGetAll() {
	    super(null, null);
	    subActions = new ArrayList();
	} // constructor

	protected int doInit() {
	    Object[] parameters = dhcpdOptions.getAll();
	    boolean atLeastOneSubActionFailed = false;

	    for (int index = 0; index < parameters.length; index++) {
		ActionGet subAction;
		String parameter = ((DhcpResource) parameters[index]).getKey();
		qualifier = dhcpdOptions.getQualifier(parameter);

		if (qualifier == null) {
		    Object[] arguments = new Object[1];
		    arguments[0] = keyword;
		    printErrMessage(
			getString(
			    "server_parameter_keyword_bad_keyword_error"),
			arguments);
		    continue;
		}

		if (qualifier.isHidden()) {
		    continue;
		}

		subAction = new ActionGet(parameter);
		subAction.setShowKeyword(true);
		subActions.add(subAction);

		if (subAction.init(dhcpdOptions) == DhcpCfg.FAILURE) {
		    atLeastOneSubActionFailed = true;
		}
	    }

	    if (atLeastOneSubActionFailed) {
		return DhcpCfg.FAILURE;
	    } else {
		return DhcpCfg.SUCCESS;
	    }
	}

	/**
	 * Get all the parameters and their values.
	 *
	 * @return
	 *   DhcpCfg.SUCCESS for success, otherwise DhcpCfg.FAILURE for failure.
	 */
	protected int doExecute() {
	    Iterator iterator = subActions.iterator();

	    while (iterator.hasNext()) {
		ActionGet subAction = (ActionGet) iterator.next();
		String parameter = subAction.getKeyword();
		qualifier = dhcpdOptions.getQualifier(parameter);

		if (subAction.execute() == DhcpCfg.FAILURE) {
		    return DhcpCfg.FAILURE;
		}
	    }

	    return DhcpCfg.SUCCESS;
	} // doExecute

    }

    /**
     * Delete a parameter action.
     */
    private class ActionDelete extends ActionImpl {

	/**
	 * Construct a get delete action
	 *
	 * @param keyword
	 *   The server parameter this action works upon.
	 */
	public ActionDelete(String keyword) {
	    super(keyword, null);
	} // constructor

	protected int doInit() {
	    if (!dhcpdOptions.isSet(keyword)) {
		Object[] arguments = new Object[1];
		arguments[0] = keyword;
		printErrMessage(
			getString("server_parameter_keyword_not_set_error"),
			arguments);
		return DhcpCfg.FAILURE;
	    }

	    if (qualifier.isReadOnly()) {
		Object[] arguments = new Object[1];
		arguments[0] = keyword;
		printErrMessage(
			getString(
			    "server_parameter_keyword_delete_read_only_error"),
			 arguments);
		return DhcpCfg.FAILURE;
	    }

	    return DhcpCfg.SUCCESS;
	}

	/**
	 * Delete the parameter and its value.
	 *
	 * @return
	 *   DhcpCfg.SUCCESS for success, otherwise DhcpCfg.FAILURE for failure.
	 */
	protected int doExecute() {
	    dhcpdOptions.clear(keyword);

	    return DhcpCfg.SUCCESS;
	} // doExecute

    }

} // ServerParameter
