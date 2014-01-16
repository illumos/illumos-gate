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
 *
 * ident	"%Z%%M%	%I%	%E% SMI"
 *
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 *
 * pmButton.java
 *
 */

package com.sun.admin.pm.client;

import java.util.*;
import java.awt.*;
import java.awt.event.*;
import javax.swing.*;

import com.sun.admin.pm.server.*;

/*
 * strategy:
 * Keep a hashtable of root panes and their associated default buttons.
 * Note that there is at present no way to remove a root pane entry
 * from the table...
 *
 * Ideally there should be an interface to allow objects to
 * remove themselves before disappearing.
 */

public class pmButton extends JButton {

    // static JButton defaultButton = null;

    // map root panes to their true default buttons
    static Hashtable map = new Hashtable();

    public static Hashtable getHashtable() {
        return map;
    }

    /*
     * make this button the default on this root pane
     * retunrs true if success, false o/w
     */
    boolean makeDefaultButton() {
        return makeDefaultButton(this);
    }

    /*
     * make b the default on this root pane
     * returns true if success, false otherwise
     */
    boolean makeDefaultButton(JButton b) {
        JRootPane r = this.getRootPane();

        if (r == null) {
            Debug.info("BUTTON:  null root panel");
            return false;
        }

        if (b == null) {
            Debug.info("BUTTON:  makeDefaultButton null on " + r);
        }

        /*
         * Debug.info("\nBUTTON:  makeDefaultButton " +
         *	(b == null ? "null" : b.getText()) +
         *		" on " + r + "\n");
         */

        if (b != null && b.isDefaultCapable() == false) {
            Debug.info("BUTTON:  false isDefaultCapable on " + r);
            return false;
        }

        // unfocus the old default, if it's different
        JButton oldb;
        if ((oldb = r.getDefaultButton()) != null && oldb != b) {
            oldb.setFocusPainted(false);
        }

        /*
         * Debug.info("\nBUTTON:  makeDefaultButton: old button was " +
         *	(oldb == null ? "null" : oldb.getText()) + "\n");
         */

        r.setDefaultButton(b);

        return true;
    }


    public pmButton(String s) {
        super(s);

        this.addFocusListener(new FocusAdapter() {

            // upon gaining focus: make this the root pane's default
            public void focusGained(FocusEvent e) {
                if (e.isTemporary()) {
                    /*
                     * Debug.info("BUTTON:  " + getText() +
                     *		" gained temp - ignoring");
                     */
                    return;
                }

                Debug.info("BUTTON:  " + getText() + " gained");

                if (makeDefaultButton())
                    setFocusPainted(true);

            }

            // upon losing focus: make 'true' default the default
            public void focusLost(FocusEvent e) {
                if (e.isTemporary()) {
                    /*
                     * Debug.info("BUTTON:  " + getText() +
                     *		" lost temp - ignoring");
                     */
                    return;
                }

                Debug.info("BUTTON:  " + getText() + " lost");

                /*
                 * i thought it might make sense to test for the
                 * next focusable comp, but what if focus is being
                 * lost as the result of a mouse click??
                 */

                makeDefaultButton((JButton) map.get(getRootPane()));
                // setFocusPainted(false);
            }

        });
    }

    // make this the true default for this root pane
    void setAsDefaultButton() {
        setAsDefaultButton(this);
    }

    // make b the true default for this root pane
    void setAsDefaultButton(JButton b) {
        JRootPane r = getRootPane();

        /*
         * Debug.message("BUTTON:  setAsDefaultButton " +
         *	(b == null ? "null" : b.getText()) +
         *			" root = " + r);
         */

        // setting default to null removes state
        if (b == null)
            map.remove(r);
        else
            map.put(r, b);	// creates a new entry if needed
        makeDefaultButton(b);
    }


    // clean up component about to be removed
    void unreference() {
        JRootPane r = getRootPane();
        map.remove(r);
    }

    public static void unreference(JComponent c) {
        JRootPane r = c.getRootPane();
        map.remove(r);
    }

    public static void unreference(JRootPane r) {
        map.remove(r);
    }


    static boolean enableMnemonics = false;

    static void setEnableMnemonics(boolean m) {
        enableMnemonics = m;
    }

    public void setMnemonic(int mnemonic) {
        setMnemonic((char)mnemonic);
    }

    public void setMnemonic(char mnemonic) {
        if (enableMnemonics)
            super.setMnemonic(mnemonic);
    }

}
