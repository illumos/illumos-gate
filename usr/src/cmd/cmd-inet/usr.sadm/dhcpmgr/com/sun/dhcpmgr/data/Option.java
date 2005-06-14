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
 * Copyright 1998-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

package com.sun.dhcpmgr.data;

import java.util.*;

/**
 * Option is a simple data class which encapsulates an option record in
 * the dhcptab.  See dhcptab(4) for the gory details on options (aka symbols).
 *
 * @see DhcptabRecord
 * @see Macro
 */
public class Option extends DhcptabRecord implements Cloneable {
    private byte context;
    private short code;
    private byte type;
    private int granularity;
    private int maximum;
    private Vector vendors;
    private boolean valueClean = false;
    private boolean validValue = true;

    // The Option attributes that must match their native values.

    // Definition for attribute limits
    public static short MAX_NAME_SIZE = 128;

    // Option contexts.
    public static byte STANDARD = 0;
    public static byte EXTEND = 1;
    public static byte VENDOR = 2;
    public static byte SITE = 3;
    public static byte CONTEXTS = 4;
    public static OptionContext [] ctxts = {
	new OptionContext(STANDARD, "Standard", "standard_option"),
	new OptionContext(EXTEND, "Extend", "extended_option"),
	new OptionContext(VENDOR, "Vendor=", "vendor_option"),
	new OptionContext(SITE, "Site", "site_option") };

    // Option types.
    public static byte ASCII = 0;
    public static byte OCTET = 1;
    public static byte IP = 2;
    public static byte NUMBER = 3;
    public static byte BOOLEAN = 4;
    public static byte UNUMBER8 = 5;
    public static byte UNUMBER16 = 6;
    public static byte UNUMBER32 = 7;
    public static byte UNUMBER64 = 8;
    public static byte SNUMBER8 = 9;
    public static byte SNUMBER16 = 10;
    public static byte SNUMBER32 = 11;
    public static byte SNUMBER64 = 12;
    public static byte TYPES = 13;

    public static OptionType [] types = {
	new OptionType((byte)0, "ASCII", "ascii_type"),
	new OptionType((byte)1, "OCTET", "octet_type"),
	new OptionType((byte)2, "IP", "ip_type"),
	new OptionType((byte)3, "NUMBER", "number_type"),
	new OptionType((byte)4, "BOOL", "boolean_type"),
	new OptionType((byte)6, "UNUMBER8", "unumber8_type"),
	new OptionType((byte)7, "UNUMBER16", "unumber16_type"),
	new OptionType((byte)8, "UNUMBER32", "unumber32_type"),
	new OptionType((byte)9, "UNUMBER64", "unumber64_type"),
	new OptionType((byte)10, "SNUMBER8", "snumber8_type"),
	new OptionType((byte)11, "SNUMBER16", "snumber16_type"),
	new OptionType((byte)12, "SNUMBER32", "snumber32_type"),
	new OptionType((byte)13, "SNUMBER64", "snumber64_type") };
    	
    /*
     * These need to be the same as the definitions in libdhcputil's
     * parser in dhcp_symbol.c
     */	 
    public static String DSYM_CLASS_DEL_SPACE = " ";
    public static String DSYM_CLASS_DEL = DSYM_CLASS_DEL_SPACE + "\t\n";
    public static String DSYM_CLASS_DEL_REGEXP = ".*[" + DSYM_CLASS_DEL + "].*";
    public static char DSYM_FIELD_DEL = ',';
    public static char DSYM_QUOTE = '"';


    // Serialization id for this class
    static final long serialVersionUID = 7468266817375654444L;

    /**
     * Construct an empty instance.  Default to Site option, IP type.
     */
    public Option() {
	super("", DhcptabRecord.OPTION, "");
	valueClean = false;
	vendors = new Vector();
	context = ctxts[SITE].getCode();
	type = types[IP].getCode();
	granularity = 1;
    }

    /**
     * Construct a fully defined instance. Used by the server to create
     * Options.
     * @param name the option name/key
     * @param context the option context/category code
     * @param vendors the list of vendors (if any)
     * @param code the option code
     * @param type the option type code
     * @param gran the option granularity
     * @param max the option maximum
     * @param sig the signature from the dhcptab
     * @param isValid the flag indicating option definition validity
     */
    public Option(String name, byte context, String [] vendors, short code,
	byte type, int gran, int max, String sig, boolean isValid) {

	super("", DhcptabRecord.OPTION, "");

	valueClean = false;
	validValue = isValid;

	setKey(name);
	setContext(context);
	setVendors(vendors);
	setCode(code);
	setType(type);
	setGranularity(gran);
	setMaximum(max);

	if (sig != null) {
		setSignature(sig);
	}
    }

    /**
     * Set the option name as specified.
     * @param name a string representing the option name.
     */
    public void setKey(String name) {
	try {
	        super.setKey(name);
	} catch (ValidationException e) {
		// Can't happen.
	}
    }
    
    /**
     * Get the context for this option
     * @return a byte for the option context (context codes are
     * defined by the OptionContext objects in the ctxts array).
     */
    public byte getContext() {
	return context;
    }
    
    /**
     * Set the context for this option (context codes are defined
     *  by the OptionContext objects in the ctxts array).
     */
    public void setContext(byte c) {
	context = c;
	valueClean = false;
    }
    
    /**
     * Enumerate the vendor list.
     * @return an Enumeration of the vendors, which will be empty for
     * non-vendor options.
     */
    public Enumeration getVendors() {
	return vendors.elements();
    }
    
    /**
     * Get the number of vendors for this option.
     * @return an int count of the vendors, zero for non-vendor options.
     */
    public int getVendorCount() {
	return vendors.size();
    }
    
    /**
     * Add a vendor to the list for this option.
     * @param v the vendor name as a String.
     */
    public void addVendor(String v) throws ValidationException {
	if (v.indexOf(DSYM_FIELD_DEL) != -1) {
	    throw new ValidationException(v);
	}
	vendors.addElement(v);
	valueClean = false;
    }
    
    /**
     * Empty the vendor list.
     */
    public void clearVendors() {
	vendors = new Vector();
	valueClean = false;
    }
    
    /**
     * Remove a vendor from the list.
     * @param index the position of the vendor to remove in the list of vendors
     */
    public void removeVendorAt(int index) {
	vendors.removeElementAt(index);
	valueClean = false;
    }
    
    /**
     * Get the vendor at a specified index in the vendor list.
     * @param index the index of the vendor to retrieve
     * @return the vendor name
     */
    public String getVendorAt(int index) {
	return (String)vendors.elementAt(index);
    }

    private void setVendors(String [] vendors) {

	this.vendors = new Vector();

        if (vendors == null) {
            return;
        }

        for (int i = 0; i < vendors.length; i++) {
            this.vendors.addElement(vendors[i]);
        }

    }
    
    /**
     * Set the vendor name at a specified index in the list.
     * @param vendor the vendor name
     * @param index the position in the list to set.
     */
    public void setVendorAt(String vendor, int index) {
	if (index >= vendors.size()) {
	    vendors.setSize(index+1);
	}
	vendors.setElementAt(vendor, index);
	valueClean = false;
    }
    
    /**
     * Get the option code.
     * @return the code as a short.
     */
    public short getCode() {
	return code;
    }
    
    /**
     * Set the option code.
     * @param c the code to use
     */
    public void setCode(short c) {
	code = c;
	valueClean = false;
    }
    
    /**
     * Get the type.
     * @return a byte value for the type (type codes are
     * defined by the OptionTypes objects in the type array).
     * OCTET
     */
    public byte getType() {
	return type;
    }
    
    /**
     * Set the type.
     * @param t the type code (type codes are defined by the
     * OptionTypes objects in the type array).
     * or OCTET.
     */
    public void setType(byte t) {
	type = t;
	valueClean = false;
    }
    
    /**
     * Get the granularity.  See dhcptab(4) for an explanation of granularity
     * interpretations.
     * @return the granularity as an int
     */
    public int getGranularity() {
	return granularity;
    }
    
    /**
     * Set the granularity.  See dhcptab(4) for an explanation of granularity
     * interpretations.
     * @param g the granularity as an int.
     */
    public void setGranularity(int g) {
	granularity = g;
	valueClean = false;
    }
    
    /**
     * Get the maximum.  See dhcptab(4) for an explanation of maximum.
     * @return the maximum as an int.
     */
    public int getMaximum() {
	return maximum;
    }
    
    /**
     * Set the maximum.  See dhcptab(4) for an explanation of maximum.
     * @param m the maximum as an int.
     */
    public void setMaximum(int m) {
	maximum = m;
	valueClean = false;
    }
    
    /**
     * Return validity of this option.
     * @return true if the option is correctly defined, false if not
     */
    public boolean isValid() {
    	return (validValue);
    }

    /**
     * Get the definition as a string in the format specified by dhcptab(4)
     * @return a String containing the definition
     */
    public String getValue() {
	/* The value string stored is not clean, regenerate */
	if (!valueClean) {
	    StringBuffer b = new StringBuffer();
	    // Start with context
	    b.append(getContextDhcptabString(context));
	    // Vendor context next adds the vendors, separate by blanks
	    if (context == ctxts[VENDOR].getCode()) {
		boolean first = true;
		for (Enumeration e = getVendors(); e.hasMoreElements(); ) {
		    String s = (String)e.nextElement();
		    if (!first) {
			b.append(DSYM_CLASS_DEL_SPACE);
		    } else {
			first = false;
		    }
		    // If vendor class contains whitespace, need to quote it
		    boolean needQuoting = s.matches(DSYM_CLASS_DEL_REGEXP);
		    if (needQuoting) {
			b.append(DSYM_QUOTE);
		    }
		    b.append(s);
		    if (needQuoting) {
			b.append(DSYM_QUOTE);
		    }
		}
	    }
	    b.append(DSYM_FIELD_DEL);
	    // Add the code
	    b.append(code);
	    b.append(DSYM_FIELD_DEL);
	    // Add the type
	    b.append(getTypeDhcptabString(type));
	    b.append(DSYM_FIELD_DEL);
	    // Add the granularity
	    b.append(granularity);
	    b.append(DSYM_FIELD_DEL);
	    // Add the maximum
	    b.append(maximum);
	    // Save it and note as such so we can avoid doing this again
	    try {
		super.setValue(b.toString());
	    } catch (ValidationException e) {
		// This should never happen!
	    }
	    valueClean = true;   
	}
	return super.getValue();
    }
	    
    // Make a copy of this option
    public Object clone() {
	Option o = new Option();

	o.setKey(getKey());
	o.setContext(getContext());
	o.setCode(getCode());
	o.vendors = new Vector();
	for (Enumeration en = vendors.elements(); en.hasMoreElements(); ) {
	    String s = (String)en.nextElement();
	    o.vendors.addElement(new String(s));
	}
	o.setType(getType());
	o.setGranularity(getGranularity());
	o.setMaximum(getMaximum());
	o.setSignature(getSignature());

	return o;
    }
    
    /**
     * Returns a string representation of this object.
     * @return a string representation of this object.
     */
    public String toString() {
	return (getKey() + " s " + getValue());
    }

    /**
     * Returns the context definition for the specified context.
     * @param code the context code.
     * @return the OptionContext for the context.
     */
    public static OptionContext findContext(byte code) {

	OptionContext ctxt = null;

	for (int i = 0; i < CONTEXTS; i++) {
	    if (ctxts[i].getCode() == code) {
		ctxt = ctxts[i];
		break;
	    }
	}

	return (ctxt);
    }

    /**
     * Returns the dhcptab string representation of the specified context.
     * @param code the context code.
     * @return the dhcptab string representation of the context.
     */
    public static String getContextDhcptabString(byte code) {

	OptionContext ctxt = findContext(code);

	if (ctxt == null) {
	    return ("undefined");
	} else {
	    return (ctxt.getDhcptabString());
	}
    }

    /**
     * Returns the string representation of the specified context.
     * @param code the context code.
     * @return a string representation of the context.
     */
    public static String getContextString(byte code) {

	OptionContext ctxt = findContext(code);

	if (ctxt == null) {
	    return ("undefined");
	} else {
	    return (ctxt.toString());
	}
    }

    /**
     * Returns the type definition for the specified type.
     * @param code the type code.
     * @return the OptionType for the type.
     */
    public static OptionType findType(byte code) {

	OptionType type = null;

	for (int i = 0; i < TYPES; i++) {
	    if (types[i].getCode() == code) {
		type = types[i];
		break;
	    }
	}

	return (type);
    }

    /**
     * Returns the dhcptab string representation of the specified type.
     * @param code the type code.
     * @return the dhcptab string representation of the type.
     */
    public static String getTypeDhcptabString(byte code) {

	OptionType type = findType(code);

	if (type == null) {
	    return ("undefined"); // should never happen
	} else {
	    return (type.getDhcptabString());
	}
    }

    /**
     * Returns the string representation of the specified type.
     * @param code the type code.
     * @return a string representation of the type.
     */
    public static String getTypeString(byte code) {

	OptionType type = findType(code);

	if (type == null) {
	    return ("undefined"); // should never happen
	} else {
	    return (type.toString());
	}
    }
}
