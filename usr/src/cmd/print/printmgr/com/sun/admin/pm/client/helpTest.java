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
 *
 * ident	"%Z%%M%	%I%	%E% SMI"
 *
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 *
 * helpTest.java
 * Test harness for help subsystem
 */

package com.sun.admin.pm.client;

import java.util.*;
import java.awt.*;
import java.awt.event.*;
import java.util.*;
import javax.swing.JPanel;
import javax.swing.border.*;
import javax.swing.event.*;
import javax.swing.*;
import com.sun.admin.pm.server.*;

class helpTest {
    static private pmHelpFrame helpFrame = null;

    public static void main(String args[]) {

        Debug.setDebugLevel(Debug.ERROR);
        
        JFrame frame = new JFrame("Help Test Tool");
        frame.addWindowListener(new WindowAdapter() {
            public void windowClosing(WindowEvent e) {System.exit(0); }
        });

        helpFrame = new pmHelpFrame();
        helpFrame.setLocation(180, 180);
        
    
        JList theList = new JList();
        theList.addMouseListener(new MouseAdapter() {
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2) {
                    JList l = (JList) e.getSource();
                    int i = l.locationToIndex(e.getPoint());
                    Debug.message("doubleclick index: " + i);
                    if (i >= 0) {
                        String s = (String) l.getModel().getElementAt(i);
                        Debug.message("doubleclick: " + s);
                        helpFrame.showHelp(s);
                    }
                }
            }
        });
                        
        JScrollPane scrollPane = new JScrollPane();
        scrollPane.getViewport().setView(theList);

	JPanel tp = new JPanel();
	tp.setLayout(new GridBagLayout());
	GridBagConstraints pc = new GridBagConstraints();
	pc.insets = new Insets(5, 5, 0, 5);
	// pc.fill = GridBagConstraints.HORIZONTAL;
	pc.weightx = 1.0;
	pc.anchor = GridBagConstraints.WEST;
	pc.gridx = 0;
	pc.gridy = GridBagConstraints.RELATIVE;

	tp.add(new JLabel("Double-click a tag to load it."), pc);
	pc.insets = new Insets(0, 5, 5, 5);
	tp.add(new JLabel(""), pc);

        JPanel p = new JPanel();
	p.setLayout(new GridBagLayout());

        GridBagConstraints c = new GridBagConstraints();
	c.insets = new Insets(5, 5, 5, 5);
        c.gridwidth = GridBagConstraints.REMAINDER;
        c.fill = GridBagConstraints.HORIZONTAL;
	c.gridheight = 1;
        c.gridx = 0;
        c.gridy = 0;
        c.weightx = 1.0;
        c.weighty = 0.0;
        
        c.anchor = GridBagConstraints.NORTH;
	p.add(tp, c);

	JPanel pp = new JPanel();
	pp.setLayout(new BorderLayout());
	pp.add(scrollPane, "Center");

	c.gridy = GridBagConstraints.RELATIVE;
	c.gridheight = 0;
	c.weighty = 1.0;
	c.weightx = 0.0;
	c.fill = GridBagConstraints.BOTH; 
	c.anchor = GridBagConstraints.EAST;

	p.add(pp, c);

	p.setBorder(BorderFactory.createEtchedBorder());
        
        frame.getContentPane().add("Center", p);

        helpTestButtonPanel bp = new helpTestButtonPanel();
        frame.getContentPane().add("South", bp);
        
        p = new JPanel();
        Vector v = new Vector();

	ResourceBundle bundle = null;
	
	try {
            bundle = ResourceBundle.getBundle(
		"com.sun.admin.pm.client.pmHelpResources");
        } catch (MissingResourceException e) {
            System.out.println("Could not load pmHelpResources file");
            System.exit(-1);
        }
        
	Enumeration e = bundle.getKeys(); 
	while (e.hasMoreElements()) {
            String key = (String) e.nextElement();
            if (key.endsWith(".tag")) {
                String tagName = null;
                try {
                    tagName = bundle.getString(key);
                } catch (MissingResourceException x) {
                    System.out.println("Unable to find tag for " + key);
                    continue;
                } 
                v.addElement(tagName);
            }
        }

        theList.setListData(v);
		theList.removeSelectionInterval(
			theList.getMinSelectionIndex(),
			theList.getMaxSelectionIndex());
		// theList.addSelectionInterval(3, 5);
		// theList.disable();

        frame.pack();
        frame.setVisible(true);
        frame.repaint();
        System.err.println("Hello from main");
     
    }

    public void showHelpItem(String tag) {
        helpFrame.showHelp(tag);
    }

}
    
    class helpTestButtonPanel extends JPanel {
        JButton dismiss;

        public helpTestButtonPanel() {
            add(dismiss = new JButton("Done"));
            dismiss.addActionListener(new ActionListener() {
                public void actionPerformed(ActionEvent e) {
                    System.exit(0);
                }
            });
        }
    }
    






