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
 * Copyright(c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 *
 * pmLogDisplay.java
 * Command Log implementation
 */

package com.sun.admin.pm.client;

import javax.swing.*;

import java.awt.*;
import java.util.*;
import java.awt.event.*;

import com.sun.admin.pm.server.*;

public class pmLogDisplay extends pmFrame {

    pmButton helpButton = null;
    pmButton okButton = null;
    pmButton clearButton = null;
    pmTop theTop = null;
    String helpTag = null;
    JTextArea theList = null;
    String theContents = null;

    public pmLogDisplay() {
	this(null, null);
    }


    public pmLogDisplay(pmTop t, String  h) {
        super(pmUtility.getResource("SPM:Command-Line.Console"));

        theTop = t;
        helpTag = h;

        setLocation(150, 200);	// relative to parent frame

        // top panel
        JPanel p = new JPanel();
        p.setLayout(new BorderLayout());

	theContents = new String();
	theList = new JTextArea(12, 36);
	theList.setLineWrap(false);
	theList.setEditable(false);

	theList.registerKeyboardAction(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                copyPressed();
            }},
            KeyStroke.getKeyStroke(KeyEvent.VK_INSERT, Event.CTRL_MASK),
            JComponent.WHEN_IN_FOCUSED_WINDOW);

	theList.registerKeyboardAction(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                copyPressed();
            }},
            KeyStroke.getKeyStroke(KeyEvent.VK_C, Event.CTRL_MASK),
            JComponent.WHEN_IN_FOCUSED_WINDOW);


        JScrollPane scroll = new JScrollPane();
        scroll.getViewport().setView(theList);

        p.add(scroll, "Center");

        this.getContentPane().add(p, "Center");

        p = new JPanel();

        okButton = new pmButton(
	    pmUtility.getResource("Dismiss"));
        okButton.setMnemonic(
	    pmUtility.getIntResource("Dismiss.mnemonic"));
        p.add(okButton);

        clearButton = new pmButton(
	    pmUtility.getResource("Clear"));
        clearButton.setMnemonic(
	    pmUtility.getIntResource("Clear.mnemonic"));
        p.add(clearButton);

        if (theTop != null && helpTag != null) {
            helpButton = new pmButton(
		pmUtility.getResource("Help"));
            helpButton.setMnemonic(
		pmUtility.getIntResource("Help.mnemonic"));
            p.add(helpButton);
            helpButton.addActionListener(new ActionListener() {
                public void actionPerformed(ActionEvent evt) {
                    Debug.message("Help button event");
                    theTop.showHelpItem(helpTag);
		}
            });
        }

        this.getContentPane().add(p, "South");

        this.pack();

        this.addWindowListener(new WindowAdapter() {
            public void windowClosing(WindowEvent evt) {
                returnValue = JOptionPane.CLOSED_OPTION;
                pmLogDisplay.this.setVisible(false);
                if (pmLogDisplay.this.theTop != null)
		    pmLogDisplay.this.theTop.setLogOption(false);
            }
        });

        okButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent evt) {
                okPressed();
            }
        });

        clearButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent evt) {
                pmLogDisplay.this.clear();
            }
        });

        // handle Esc as dismiss in any case
        getRootPane().registerKeyboardAction(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                Debug.message("CLNT:  default cancel action");
                okPressed();
            }},
            KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0, false),
            JComponent.WHEN_IN_FOCUSED_WINDOW);

        // getRootPane().setDefaultButton(okButton);
        okButton.setAsDefaultButton();

        theList.requestFocus();

    }

    protected void copyPressed() {
	theList.copy();
    }


    protected void okPressed() {
        returnValue = JOptionPane.OK_OPTION;
        pmLogDisplay.this.setVisible(false);
	if (pmLogDisplay.this.theTop != null)
	    pmLogDisplay.this.theTop.setLogOption(false);
    }

    public int getValue() {
        // Debug.message("getValue");
        return returnValue;
    }

    // i.e. a solid line, or spaces, or...
    public void addSeparator() {
	theContents = theContents + "\n\r";
	theList.setText(theContents);
    }

    // tricky: s may have embedded newlines...
    public void addText(String s) {
	theContents = theContents + s;

	/*
	 * StringTokenizer st = new StringTokenizer(s, "\n\r", false);
	 * try {
	 *    while(st.hasMoreTokens())  {
	 *	String ss = st.nextToken();
	 *	theContents.addElement(ss);
	 *    }
	 * } catch(Exception x) {
	 *	Debug.warning("CLNT:  Log addText caught: " + x);
	 * }
	 */

        /*
         * Debug.message("Log contents len = " + theContents.size());
         * for (int i = 0; i < theContents.size(); ++i)
         *    Debug.message("\t" + i + ": " + theContents.elementAt(i));
         */

	// conveniently, this forces the last line to be scrolled to.
	theList.setText(theContents);

    }

    public void clear() {
	theContents = null;
	theContents = new String();
	theList.setText(theContents);
    }

    public void disableText(boolean d) {
        // theText.setEnabled(!d);
    }

    public static void main(String[] args) {
        JFrame f = new JFrame("Test Dialog");
        f.setSize(300, 100);

        f.addWindowListener(new WindowAdapter() {
            public void windowClosing(WindowEvent evt) {
                System.exit(0);
            }
        });

        f.setVisible(true);

        pmLogDisplay d = new pmLogDisplay();
        d.addText("A\nB\nC\nD\nE\nF\nG\nH\nI\nJ");
        d.setVisible(true);
    }


    protected int returnValue = JOptionPane.CLOSED_OPTION;
}
