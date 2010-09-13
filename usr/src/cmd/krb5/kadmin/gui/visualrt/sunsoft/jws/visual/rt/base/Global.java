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
 * Copyright (c) 2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

/*
 *        Copyright (C) 1996  Active Software, Inc.
 *                  All rights reserved.
 *
 * @(#) Global.java 1.53 - last change made 08/12/97
 */

package sunsoft.jws.visual.rt.base;

import java.util.StringTokenizer;
import sunsoft.jws.visual.rt.props.MessageCatalog;

/**
 * Globals for runtime area.
 *
 * @version 	1.53, 08/12/97
 */
public class Global {
    private static final double version = 1.0;
    private static final String vendor = /* NOI18N */"SunSoft, Inc.";
    private static final char   PERIOD = /* NOI18N */ '.';
    
    /**
     * Returns the version number of this runtime package.
     */
    public static double getVersion() { return (version); }
    
    /**
     * Returns the vendor of this runtime package.
     */
    public static String getVendor() { return (vendor); }
    
    /**
     * A convenient instance of the Util class,
     * easy access to the utility
     * functions there.
     */
    public static Util util = new Util();
    
    // Which OS are we running?
    // If we know we can work-around some AWT bugs.
    private static boolean isWindows;
    private static boolean isWindows95;
    private static boolean isWindowsNT;
    private static boolean isSolaris;
    private static boolean isUnix;
    private static boolean isIrix;
    private static boolean isMotif;
    
    // What version of java are we using?
    private static double javaVersion;
    
    // What do we use for new lines (when printing, generating, etc.)
    private static String newline;
    
    // current message catalog for the current locale
    private static MessageCatalog messageCatalog;
    
    static {
        String osname = System.getProperty(/* NOI18N */"os.name");
        isWindows = osname.startsWith(/* NOI18N */"Windows");
        isWindows95 = osname.startsWith(/* NOI18N */"Windows 95");
        isWindowsNT = osname.startsWith(/* NOI18N */"Windows NT");
        isSolaris = osname.startsWith(/* NOI18N */"Solaris");
        isUnix = !osname.startsWith(/* NOI18N */"Windows");
        isIrix = osname.startsWith(/* NOI18N */"Irix");
        isMotif = isUnix;
        
        // work-around for the fact that newline character
        // sequences are different on Unix and Windows
        newline = (isWindows ? /* NOI18N */"\r\n" : /* NOI18N */"\n");
        
        initJavaVersion();
        
        // ORIGINAL CODE
        // load the msg catalog for the runtime classes for
        // the current locale
        // messageCatalog = new MessageCatalog(
        // /* NOI18N */"sunsoft.jws.visual.rt.VisualRTProperties");
        // END OFF ORIGINAL CODE
        
        // WORKAROUND
        // XXX To workaround the JDK bug 4071131,
        // which reports bogus errors,
        // we always load VisualRTProperties_en_US for the
        // Atlantis release.
        // Since we don't have localized catalogs for
        // any other locale in
        // the Atlantis release, this works for Atlantis.  For releases
        // after Atlantis, we have to undo this workaround
        // and fix the real
        // JDK problem.
        messageCatalog = new MessageCatalog(
	    /* NOI18N */"sunsoft.jws.visual.rt.props.VisualRTProperties",
					    java.util.Locale.US);
        // END OF WORKAROUND
    }
    
    private static void initJavaVersion() {
        String jv;
        int i, len;
        
        javaVersion = 0.0;
        jv = System.getProperty(/* NOI18N */"java.version");
        
        // Strip everything off starting at the first non-numeric
        // character.
        // The JWS java version will soon look like
        // this: "1.0.1ss:<date-time>"
        len = jv.length();
        for (i = 0; i < len; i++) {
            char c = jv.charAt(i);
            if (!Character.isDigit(c) && c != PERIOD)
                break;
        }
        jv = jv.substring(0, i);
        
        // JWS screws up the "java.version" property.  This will
        // be fixed soon.
        if (jv.equals(/* NOI18N */"")) {
            javaVersion = 1.01;
            return;
        }
        
        // Count up the number of dot characters.
        //  This is necessary because
        // the JDK java version looks like this: "1.0.2"
        int dotcount = 0;
        len = jv.length();
        for (i = 0; i < len; i++) {
            if (jv.charAt(i) == PERIOD)
                dotcount++;
        }
        
        // The netscape java version looks like this: "1.021"
        if (dotcount <= 1) {
            try {
                javaVersion = Double.valueOf(jv).doubleValue();
                return;
            }
            catch (NumberFormatException ex) {
            }
        }
        
        // The JDK java version looks like this: "1.0.2"
        double mult = 1;
        StringTokenizer st = new StringTokenizer(jv, /* NOI18N */".");
        while (st.hasMoreTokens()) {
            javaVersion += Integer.parseInt(st.nextToken()) * mult;
            mult *= 0.1;
        }
    }
    
    /**
     * Returns true if running on Windows 95 or NT.
     */
    public static boolean isWindows() { return isWindows; }
    
    /**
     * Returns true if running on Windows 95.
     */
    public static boolean isWindows95() { return isWindows95; }
    
    /**
     * Returns true if running on Windows NT.
     */
    public static boolean isWindowsNT() { return isWindowsNT; }
    
    /**
     * Returns true if running on Solaris.
     */
    public static boolean isSolaris() { return isSolaris; }
    
    /**
     * Returns true if running on Unix.
     */
    public static boolean isUnix() { return isUnix; }
    
    /**
     * Returns true if running on SGI Irix.
     */
    public static boolean isIrix() { return isIrix; }
    
    /**
     * Returns true if using Motif.
     */
    public static boolean isMotif() { return isMotif; }
    
    /**
     * Returns a string that can be used as a newline.
     *  This string includes
     * a carriage return if we are running on Windows.
     */
    public static String newline() { return newline; }
    
    /**
     * Appends a newline to buf.  This also appends a carriage return
     * if we are running on Windows.
     */
    public static void newline(StringBuffer buf)
    { buf.append(newline); }
    
    /**
     * Returns the version of Java we are using.
     */
    public static double javaVersion() {
        return javaVersion;
    }
    
    /**
     * Returns a msg string from the current msg catalog
     */
    public static String getMsg(String key) {
        return messageCatalog.getKeyMessage(key, null);
    }
    
    public static String fmtMsg(String key, Object arg1) {
        return messageCatalog.getFormattedKeyMessage(key, null, arg1);
    }
    
    public static String fmtMsg(String key, Object arg1, Object arg2) {
        return messageCatalog.getFormattedKeyMessage(key, null, arg1,
						     arg2);
    }
    
    public static String fmtMsg(String key, Object arg1, Object arg2,
				Object arg3) {
        return messageCatalog.getFormattedKeyMessage(key, null, arg1,
						     arg2, arg3);
    }
    
    public static String fmtMsg(String key, Object arg1, Object arg2,
				Object arg3, Object arg4)
    {
        Object [] args = { arg1, arg2, arg3, arg4 };
        return messageCatalog.getFormattedKeyMessage(key, null, args);
    }
    
    public static String fmtMsg(String key, Object arg1, Object arg2,
				Object arg3, Object arg4, Object arg5)
    {
        Object [] args = { arg1, arg2, arg3, arg4, arg5 };
        return messageCatalog.getFormattedKeyMessage(key, null, args);
    }
    
    public static String fmtMsg(String key, Object arg1, Object arg2,
				Object arg3, Object arg4, Object arg5,
				Object arg6)
    {
        Object [] args = { arg1, arg2, arg3, arg4, arg5, arg6 };
        return messageCatalog.getFormattedKeyMessage(key, null, args);
    }
    
    public static String fmtMsg(String key, Object arg1, Object arg2,
				Object arg3, Object arg4, Object arg5,
				Object arg6, Object arg7)
    {
        Object [] args = { arg1, arg2, arg3, arg4, arg5, arg6, arg7 };
        return messageCatalog.getFormattedKeyMessage(key, null, args);
    }
}
