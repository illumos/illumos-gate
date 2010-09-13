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
 * Copyright 1998-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

package com.sun.dhcpmgr.data;

import java.util.*;
import java.text.MessageFormat;

/**
 * Macro is a simple data class which encapsulates a macro record in
 * the dhcptab.  See dhcptab(4) for the gory details on macros.
 * @see DhcptabRecord
 * @see Option
 */
public class Macro extends DhcptabRecord implements Cloneable {

    private boolean valueClean = false;
    private Vector options;

    // Definition for attribute limits
    public final static short MAX_NAME_SIZE = 128;

    // Value used to edit a boolean symbol of a macro
    public final static String BOOLEAN_EDIT_VALUE = "_NULL_VALUE_";

    // Serialization id for this class
    static final long serialVersionUID = -5255083189703724489L;

    public Macro() {
        super("", DhcptabRecord.MACRO, "");
	options = new Vector();
    }
    
    public Macro(String name) throws ValidationException {
	this();
	setKey(name);
    }

    public Macro(String name, String expansion) throws ValidationException {
	this(name, expansion, DhcptabRecord.DEFAULT_SIGNATURE);
    }
    
    public Macro(String name, String expansion, String signature)
	throws ValidationException {
	this();
        setKey(name);
	setValue(expansion, false, false);
	setSignature(signature);
    }
    
    public void setKey(String name) throws ValidationException {
        if (name.length() > MAX_NAME_SIZE) {
	    Object [] args = new Object[1];
	    args[0] = new Short(MAX_NAME_SIZE);
	    MessageFormat form = new MessageFormat(
		ResourceStrings.getString("macro_key_length"));
	    String msg = form.format(args);
	    throw new ValidationException(msg);
        }
        super.setKey(name);
    }

    public void setValue(String expansion, boolean edit, boolean validate)
	throws ValidationException {

	StringBuffer symbol = new StringBuffer();
	StringBuffer value = new StringBuffer();
	boolean inQuote = false;
	boolean inEscape = false;
	char c;

	// State list for parsing machine
	int START = 0;
	int NAME = 1;
	int VALUE = 2;
	int state = !edit ? START : NAME;

	for (int i = 0; i < expansion.length(); ++i) {
	    c = expansion.charAt(i);
	    if (!edit && (state == START)) {
		// Start of expansion
		if (c != ':' || expansion.length() == 1) {
		    Object [] args = new Object[1];
		    args[0] = getKey();
		    MessageFormat form = new MessageFormat(
			ResourceStrings.getString("mac_syntax_error"));
		    String msg = form.format(args);
		    throw new ValidationException(msg);
		}
		state = NAME;
	    } else if (state == NAME) {
		// Name of symbol
		if (c == '=') {
		    state = VALUE;
		} else if (!edit && (c == ':')) {
		    if (!validate) {
			storeOption(symbol.toString(), value.toString());
		    } else {
			setOption(symbol.toString(), value.toString(), false);
		    }
		    symbol.setLength(0);
		    value.setLength(0);
		    state = NAME;			
		} else {
		    symbol.append(c);
		}
	    } else if (state == VALUE) {
		// Value of symbol
		if (inEscape) {
		    value.append(c);
		    inEscape = false;
		} else if (c == '\\') {
		    inEscape = true;
		} else if (c == '"') {
		    inQuote = !inQuote;
		    value.append(c);
		} else if (inQuote) {
		    value.append(c);
		} else if (!edit && (c == ':')) {
		    if (!validate) {
			storeOption(symbol.toString(), value.toString());
		    } else {
			setOption(symbol.toString(), value.toString(), false);
		    }
		    symbol.setLength(0);
		    value.setLength(0);
		    state = NAME;
		} else {
		    value.append(c);
		}
	    }
	}

	if (edit) {
	    setOption(symbol.toString(), value.toString(), true);

	    valueClean = false;
	} else {
	    if (state != NAME) {
		Object [] args = new Object[1];
		args[0] = getKey();
		MessageFormat form = new MessageFormat(
		    ResourceStrings.getString("mac_syntax_error"));
		String msg = form.format(args);
		throw new ValidationException(msg);
	    }
	    super.setValue(expansion);
	    valueClean = true;
	}
    }

    public void editOption(String expansion)
	throws ValidationException {
	setValue(expansion, true, false);
    } 

    /**
     * Common method used to set an option value for the macro.
     * @param symbol name of the option
     * @param value the option value(if any)
     * @param edit flag indicating that this is an edit of and existing option
     */
    private void setOption(String symbol, String value, boolean edit)
	throws ValidationException {

	int index = getOptionIndex(symbol);

	if (value.length() == 0) {

	    if (edit) {
		if (index == -1) {
		    Object [] args = new Object[1];
		    args[0] = symbol;
		    MessageFormat form = new MessageFormat(
			ResourceStrings.getString("invalid_option"));
		    String msg = form.format(args);
		    throw new ValidationException(msg);
		}
		deleteOptionAt(index);
	    } else {
		OptionValue option = 
		    OptionValueFactory.newOptionValue(symbol, new String());

		if (option instanceof BogusOptionValue) {
		    Object [] args = new Object[1];
		    args[0] = symbol;
		    MessageFormat form = new MessageFormat(
			ResourceStrings.getString("invalid_option"));
		    String msg = form.format(args);
		    throw new ValidationException(msg);
		} else if (!(option instanceof BooleanOptionValue)) {
		    Object [] args = new Object[1];
		    args[0] = symbol;
		    MessageFormat form = new MessageFormat(
			ResourceStrings.getString("not_boolean_option"));
		    String msg = form.format(args);
		    throw new ValidationException(msg);
		}
	    }

	} else if (edit && value.equals(BOOLEAN_EDIT_VALUE)) {

	    OptionValue option = 
	        OptionValueFactory.newOptionValue(symbol, new String());

	    if (option instanceof BogusOptionValue) {
		Object [] args = new Object[1];
		args[0] = symbol;
		MessageFormat form = new MessageFormat(
		    ResourceStrings.getString("invalid_option"));
		String msg = form.format(args);
		throw new ValidationException(msg);
	    } else if (!(option instanceof BooleanOptionValue)) {
		Object [] args = new Object[1];
		args[0] = symbol;
		MessageFormat form = new MessageFormat(
		    ResourceStrings.getString("not_boolean_option"));
		String msg = form.format(args);
		throw new ValidationException(msg);
	    }

	    if (index == -1) {
		storeOption(option);
	    } else {
		// nothing to do - option already turned on
	    }

	} else {

	    OptionValue option = 
		OptionValueFactory.newOptionValue(symbol);
	    if (option instanceof BogusOptionValue) {
		Object [] args = new Object[1];
		args[0] = symbol;
		MessageFormat form = new MessageFormat(
		    ResourceStrings.getString("invalid_option"));
		String msg = form.format(args);
		throw new ValidationException(msg);
	    } else if (edit && option instanceof BooleanOptionValue) {
		Object [] args = new Object[1];
		args[0] = symbol;
		MessageFormat form = new MessageFormat(
		    ResourceStrings.getString("boolean_option"));
		String msg = form.format(args);
		throw new ValidationException(msg);
	    }

	    if (index == -1) {
		storeOption(option);
	    } else {
		option = getOptionAt(index);
	    }
	    option.setValue(value);

	}
    }

    public void storeOption(OptionValue option)
	    throws ValidationException {
	options.addElement(option);
    }

    public void storeOption(String option, Object value)
	    throws ValidationException {
	options.addElement(OptionValueFactory.newOptionValue(option, value));
    }
    
    // Useful for creating options when standard code values are known.
    //
    // XXX
    // NOTE!!! Do not use this method for now. We need to resolve whether or
    // not all standard options are going to have unique codes. Today, they do
    // not. We include internal options as standard and set their codes to 0.
    // 
    public void storeOption(int code, Object value) throws ValidationException {
	options.addElement(
	    OptionValueFactory.newOptionValue(StandardOptions.nameForCode(code),
	    value));
    }

    public String getValue() {
	boolean first;
	if (!valueClean) {
	    // Construct a new value
	    StringBuffer buf = new StringBuffer();
	    for (Enumeration e = options.elements(); e.hasMoreElements(); ) {
		OptionValue v = (OptionValue)e.nextElement();
		if (v == null) {
		    continue;	// Ignore an empty position
		}
		buf.append(':');
		buf.append(v.toString());
    	    }
	    buf.append(':');
	    try {
	        super.setValue(buf.toString());
	    } catch (ValidationException ex) {
		// Shouldn't happen; ignore it
	    }
	    valueClean = true;
	}
        return super.getValue();
    }
    
    public Enumeration elements() {
	return options.elements();
    }
    
    public OptionValue [] getOptions() {
	OptionValue [] optArray = new OptionValue[options.size()];
	options.copyInto(optArray);
	return optArray;
    }
    
    public OptionValue getOption(String name) {
	for (Enumeration en = options.elements(); en.hasMoreElements(); ) {
	    OptionValue v = (OptionValue)en.nextElement();
	    if (name.equals(v.getName())) {
		return v;
	    }
	}
	return null;
    }
    
    public int getOptionIndex(String name) {
	int index = -1;
	boolean found = false;

	Enumeration en = options.elements();
	while (en.hasMoreElements() && !found) {
	    index++;
	    OptionValue v = (OptionValue)en.nextElement();
	    if (name.equals(v.getName())) {
		found = true;
	    }
	}
	if (!found) {
	    index = -1;
	}

	return index;
    }
    
    public OptionValue getOptionAt(int index) {
	return (OptionValue)options.elementAt(index);
    }
    
    public void setOptionAt(OptionValue v, int index) {
	if (index >= options.size()) {
	    options.setSize(index + 1); // Grow vector if necessary
	}
	options.setElementAt(v, index);
    }	
    
    public int optionCount() {
	return options.size();
    }
    
    public void deleteOptionAt(int index) {
	if (index >= options.size()) {
	    return;
	}
	options.removeElementAt(index);
    }
    
    public void insertOptionAt(OptionValue v, int index) {
	options.insertElementAt(v, index);
    }
    
    // Make a copy of this macro
    public Object clone() {
	Macro m = new Macro();
	m.key = key;
	m.options = new Vector();
	for (Enumeration en = options.elements(); en.hasMoreElements(); ) {
	    OptionValue v = (OptionValue)en.nextElement();
	    m.options.addElement((OptionValue)v.clone());
	}
	m.signature = signature;
	return m;
    }
    
    public String toString() {
	return (getKey() + " m " + getValue());
    }
    
    // Verify that the options contained in this macro are all valid
    public void validate() throws ValidationException {
	for (Enumeration en = options.elements(); en.hasMoreElements(); ) {
	    OptionValue v = (OptionValue)en.nextElement();
	    if (!v.isValid()) {
		throw new ValidationException(v.getName());
	    }
	}
    }
}
