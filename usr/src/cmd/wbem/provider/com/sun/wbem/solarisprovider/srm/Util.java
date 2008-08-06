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
 * Copyright (c) 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 *
 * Util.java
 */

package com.sun.wbem.solarisprovider.srm;

import javax.wbem.cim.*;

import java.math.*;

import java.util.PropertyResourceBundle;
import java.io.InputStream;

/**
 * Utility class 
 * @author Sun Microsystems
 */
class Util {
    
    public static String propertyUPDATETIME;
    public static String propertyRDSTIMEOUT;
    public static String propertyRDSINTERVAL;
    public static String propertyRDSDATABASE;
    public static String propertyKEEPALIVETIMEOUT;
    public static String propertyMSACCT;
    public static String propertyREADTIMEOUT;
    public static String propertyRDSLOGFILE;


    /**
     * Converts a java long into CIM UnsignedInt64 object.
     * @param l the long to be converted
     * @returns a CIM UnsignedInt64 object
     */
    public static UnsignedInt64 longToUI64(long l) {
        byte a[] = new byte[9];
        
        for (int i = 8; i > 0; i--, l >>= 8) {
            a[i] = (byte)(l & 0x0ff);
        }
        a[0] = 0;
        return new UnsignedInt64(a);
    }

    /**
     * Waits some milliseconds.
     *
     * @param ms time to wait in milliseconds
     */
    public static void napms(int ms) {
	try {
	    Thread.sleep(ms);
	} catch (InterruptedException e) {}
    }
    
    private static final String classNameForResourceBundle =
    	    	"com.sun.wbem.solarisprovider.srm.Util";
    private static final String nameForResourceBundle =
    	    	"perfprovider.properties";
    private static final String nameForDebugPropertyLevel =
    	    	"ProviderDEBUGLEVEL";
    private static final String nameForDebugPropertyDevice =
    	    	"ProviderDEBUGDEVICE";
    private static final String nameForUPDATETIME =
    	    	"ProviderUPDATETIME";
    private static final String nameForRDSTIMEOUT =
    	    	"ProviderRDSTIMEOUT";
    private static final String nameForRDSINTERVAL =
    	    	"ProviderRDSINTERVAL";
    private static final String nameForRDSDATABASE =
    	    	"ProviderRDSDATABASE";
    private static final String nameForKEEPALIVETIMEOUT =
    	    	"ProviderKEEPALIVETIMEOUT";
    private static final String nameForMSACCT =
    	    	"ProviderMSACCT";
    private static final String nameForREADTIMEOUT=
    	    	"ProviderREADTIMEOUT";
    private static final String nameForRDSLOGFILE=
    	    	"ProviderRDSLOGFILE";

    // look for debug flag as a local resource
    static {
	try {
	    Class c = Class.forName(classNameForResourceBundle);

	    InputStream is = c.getResourceAsStream(nameForResourceBundle);

	    PropertyResourceBundle prb = new PropertyResourceBundle(is);

	    try {
		propertyUPDATETIME = prb.getString(nameForUPDATETIME);
	    } catch (java.util.MissingResourceException x) {
		;
	    }

	    try {
		propertyRDSTIMEOUT = prb.getString(nameForRDSTIMEOUT);
	    } catch (java.util.MissingResourceException x) {
		;
	    }

	    try {
		propertyRDSINTERVAL = prb.getString(nameForRDSINTERVAL);
	    } catch (java.util.MissingResourceException x) {
		;
	    }

	    try {
		propertyRDSDATABASE = prb.getString(nameForRDSDATABASE);
	    } catch (java.util.MissingResourceException x) {
		;
	    }

	    try {
		propertyKEEPALIVETIMEOUT =
		    prb.getString(nameForKEEPALIVETIMEOUT);
	    } catch (java.util.MissingResourceException x) {
		;
	    }

	    try {
		propertyMSACCT = prb.getString(nameForMSACCT);
	    } catch (java.util.MissingResourceException x) {
		;
	    }

	    try {
		propertyREADTIMEOUT = prb.getString(nameForREADTIMEOUT);
	    } catch (java.util.MissingResourceException x) {
		;
	    }

	    try {
		propertyRDSLOGFILE = prb.getString(nameForRDSLOGFILE);
	    } catch (java.util.MissingResourceException x) {
		;
	    }
	    String level = null;
	    String device = null;

	    try {
		level = prb.getString(nameForDebugPropertyLevel);
		device = prb.getString(nameForDebugPropertyDevice);
	    } catch (java.util.MissingResourceException x) {
		;
	    }

	    if ((device != null) && (device.equalsIgnoreCase("file"))) {
	    	device = "perfprovider";
	    }
	    SRMDebug.traceOpen(level, device);
	    SRMDebug.trace(SRMDebug.TRACE_ALL,
		"Starting SRM provider trace level = "
		+ level + ", device = " + device);

	} catch (Exception x) {
		;
	}
    }
    
}
