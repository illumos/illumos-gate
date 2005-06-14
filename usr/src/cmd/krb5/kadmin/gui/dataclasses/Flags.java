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
 * Copyright (c) 1999-2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

import java.util.ResourceBundle;
import java.util.MissingResourceException;

/**
 * The Flags class stores all flags that might pertain to a
 * Principal.
 */

//XXX: Move this to a java.util.BitSet model later on.
public class Flags {

    private int flags = 0;

    private static int allOnes = 0xFFFF;

    public static final int DISALLOW_POSTDATED = 1;
    public static final int DISALLOW_FORWARDABLE = 2;
    public static final int DISALLOW_TGT_BASED = 4;
    public static final int DISALLOW_RENEWABLE = 8;
    public static final int DISALLOW_PROXIABLE = 16;
    public static final int DISALLOW_DUP_SKEY = 32;
    public static final int DISALLOW_ALL_TIX = 64;
    public static final int REQUIRE_PRE_AUTH = 128;
    public static final int REQUIRE_HW_AUTH = 256;
    public static final int REQUIRES_PWCHANGE = 512;
    public static final int DISALLOW_SVR = 4096;
    // public static final int MASK = 65535 - 1024 - 2048 - 32678;

    private static int bitfields[] = {1, 2, 4, 8, 16, 32, 64, 128, 256, 512,
  				      4096};

    private static String flagNames[] = {"Allow Postdated Tickets",
				         "Allow Forwardable Tickets",
				         "Allow TGT-Based Authentication", 
				         "Allow Renewable Tickets", 
				         "Allow Proxiable Tickets", 
				         "Allow Duplicate Authentication",
				         "Disable Account",
				         "Require Preauthentication",
				         "Require Hardware Preauthentication",
				         "Require Password Change", 
				         "Allow Service Tickets"};

    // For I18N
    private static ResourceBundle rb = 
    ResourceBundle.getBundle("GuiResource" /* NOI18N */); 
  
    /**
     * Constructor for Flags. Sets all flags to false;
     */
    // Required since non-default constructor is used.
    public Flags() {
    }
  
    /**
     * Constructor for Flags.
     * @param flags an integer where the bit positions determined by the
     * static masks determine the value of that flag.
     */
    public Flags(int flags) {
        this.flags = flags;
    }

    /**
     * Call rb.getString(), but catch exception and return English
     * key so that small spelling errors don't cripple the GUI
     *
     */
    private static final String getString(String key) {
        try {
      	    String res = rb.getString(key);
	    return res;
        } catch (MissingResourceException e) {
	    System.out.println("Missing resource "+key+", using English.");
	    return key;
        }
    }

    /**
     * Returns a label for the flag corresponding to the given
     * bitfield.
     * @param bitfield an integer chosen from the static list of masks
     *   in this class to indicate a particular flag.
     * @return a String containing the label for the flag.
     */
    public static final String getLabel(int bitfield) {
        int pos = getIndex(bitfield);
        if (pos < 0)
            return null;
        else
            return getString(flagNames[pos]);
    }

    /**
     * Returns the boolean value of the flag corresponding to the given
     * bitfield.
     * @param bitfield an integer chosen from the static list of masks
     *   in this class to indicate a particular flag.
     * @return the boolean value that the flag is currently set to.
     */
    public boolean getFlag(int bitfield) {
        return !((flags & bitfield) == 0);
    }

    /**
     * Sets the current value of one or more flags.
     * @param mask an integer mask that has all those bits set that
     * correspond to flags that need to be set.
     * @value the boolean value that the flags should be set to.
     */
    public void setFlags(int mask, boolean value) {
        if (!value) {
            mask ^= allOnes; // invert mask
            flags &= mask;   // zero out
        } else {
            flags |= mask;
        }
    }

    /**
     * Toggles the current value of one or more flags.
     * @param mask an integermask that has all those bits set that
     * correspond to flags that need to be toggled.
     */
    public void toggleFlags(int mask) {
        flags ^= mask;
    }

    /**
     * Returns a string containing all of the flags labels and their
     * corresponding boolean values.
     */
    public String toString() {
  
        StringBuffer sb = new StringBuffer();
        char ch;

        ch = (!getFlag(DISALLOW_POSTDATED)? '+':'-');
        sb.append('\t').append(ch).append(getString(flagNames[0])).append('\n');

        ch = (!getFlag(DISALLOW_FORWARDABLE)? '+':'-');
        sb.append('\t').append(ch).append(getString(flagNames[1])).append('\n');

        ch = (!getFlag(DISALLOW_TGT_BASED)? '+':'-');
        sb.append('\t').append(ch).append(getString(flagNames[2])).append('\n');

        ch = (!getFlag(DISALLOW_RENEWABLE)? '+':'-');
        sb.append('\t').append(ch).append(getString(flagNames[3])).append('\n');

        ch = (!getFlag(DISALLOW_PROXIABLE)? '+':'-');
        sb.append('\t').append(ch).append(getString(flagNames[4])).append('\n');

        ch = (!getFlag(DISALLOW_DUP_SKEY)? '+':'-');
        sb.append('\t').append(ch).append(getString(flagNames[5])).append('\n');

        ch = (getFlag(DISALLOW_ALL_TIX)? '+':'-');
        sb.append('\t').append(ch).append(getString(flagNames[6])).append('\n');

        ch = (getFlag(REQUIRE_PRE_AUTH)? '+':'-');
        sb.append('\t').append(ch).append(getString(flagNames[7])).append('\n');

        ch = (getFlag(REQUIRE_HW_AUTH)? '+':'-');
        sb.append('\t').append(ch).append(getString(flagNames[8])).append('\n');

        ch = (getFlag(REQUIRES_PWCHANGE)? '+':'-');
        sb.append('\t').append(ch).append(getString(flagNames[9])).append('\n');

        ch = (!getFlag(DISALLOW_SVR)? '+':'-');
        sb.append('\t').append(ch).append(getString(flagNames[10])).append(
            '\n');

        return sb.toString();
    }

    /**
     * Converts a bitfield with one bit set in it to an index.
     * The index can be used with bitfields or flagNames.
     * @flagBitfield an integer that has exactly one bit set in it
     * @return the index of the first bit that was found set when
     *  scanning from the lsb.
     */
    // This is not always the position of the bit in the integer's
    // internal representation.
    private static int getIndex(int flagBitfield) {
        for (int i = 0; i < flagNames.length; i++) {
            if (flagBitfield == bitfields[i])
    	        return i;
        }

        return -1;
    }

    /**
     * Returns an integer with the bits indicating the status of each of
     * the flags.
     */
    public int getBits() {
        return flags;
    }

}
