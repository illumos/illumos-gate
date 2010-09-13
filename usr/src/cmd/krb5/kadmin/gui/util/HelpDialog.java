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

import java.awt.*;
import java.awt.event.*;
import java.util.StringTokenizer;
import java.util.ResourceBundle;
import java.util.MissingResourceException;

/**
 *  Dialog box for diaplaying Help
 *
 */
public class HelpDialog extends Dialog {

    protected Button b;
    protected TextArea t;
    private Frame parent;

    public static int NUM_ROWS = 10;
    public static int NUM_COLS = 45;

    // For I18N
    private static ResourceBundle rb =
    ResourceBundle.getBundle("GuiResource" /* NOI18N */); 
    
    public HelpDialog(Frame parent, String title, boolean mode) {
        this(parent, title, mode, NUM_ROWS, NUM_COLS);
    }

    public HelpDialog(Frame parent, String title, boolean mode, int numRows,
                      int numCols) {
        super(parent, title, mode);
        this.parent = parent;
        setBackground(parent.getBackground());
        setForeground(parent.getForeground());
        addButtonAndTextArea(numRows, numCols);
        addWindowListener(new WindowAdapter() {
	    public void windowClosing(WindowEvent e) {
	        quit(); 
	    }
        });
    }

    protected void quit() {
        dispose();
    }

    private void addButtonAndTextArea(int numRows, int numCols) {
        t = new TextArea(null, numRows, numCols,
                         TextArea.SCROLLBARS_VERTICAL_ONLY);
        t.setEditable(false);
        b = new Button(getString("Dismiss"));

        setLayout(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.weightx = gbc.weighty = 1;
        gbc.fill = GridBagConstraints.BOTH;
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        add(t, gbc);
        gbc.fill = GridBagConstraints.NONE;
        add(b, gbc);

        pack();
        setResizable(false);
        setLocationBesideParent(parent);
      
        b.addActionListener(new ActionListener() {
	    public void actionPerformed(ActionEvent e) {
	        quit();
	    }
        });
    }
    
    private void setLocationBesideParent(Frame parent) {
        Point p = parent.getLocationOnScreen();
        Dimension parentSize = parent.getSize();
        Dimension mySize = getSize();
        p.x += parentSize.width;
        p.y += parentSize.height/2 - mySize.height/2;
        setLocation(p.x, p.y);
    }


    public void setText(String text) {
        t.setText(text);
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

    /*
    public static void main(String args[]) {
        Frame f = new Frame();
        f.setVisible(true);
        HelpDialog hd = new HelpDialog(f, "Test HelpDialog", false);
        hd.setVisible(true);
    }
    */
}
