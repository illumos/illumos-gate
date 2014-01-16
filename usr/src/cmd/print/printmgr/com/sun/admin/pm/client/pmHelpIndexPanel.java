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
 * pmHelpIndexPanel.java
 * Search help titles
 */

package com.sun.admin.pm.client;

import java.awt.*;
import java.awt.event.*;
import java.util.*;
import javax.swing.JPanel;
import javax.swing.border.*;
import javax.swing.event.*;
import javax.swing.*;

import com.sun.admin.pm.server.*;


public class pmHelpIndexPanel extends JPanel {

    pmHelpController controller;
    pmHelpIndexQueryPanel queryPanel;
    pmHelpIndexResultPanel resultPanel;
    JLabel textPanels[];

    public pmHelpIndexPanel(pmHelpController ctrl) {
        controller = ctrl;

        // build subpanels
        queryPanel = new pmHelpIndexQueryPanel(this);
        resultPanel = new pmHelpIndexResultPanel(this);

        textPanels = new JLabel[4];
        textPanels[0] = new JLabel(
            pmUtility.getResource("To.search.the.index..."));
        textPanels[1] = new JLabel(
            pmUtility.getResource("type.your.query.below..."));

        // lay out top panel
        this.setLayout(new GridBagLayout());
        GridBagConstraints c = new GridBagConstraints();
        c.insets = new Insets(5, 5, 5, 5);
        c.gridwidth = GridBagConstraints.REMAINDER;

        c.gridx = 0;
        c.gridy = 0;

        c.gridheight = 1; // GridBagConstraints.REMAINDER;
        c.fill = GridBagConstraints.BOTH;
        c.weightx = 1.0;
        c.weighty = 0.0;

        JPanel p = new JPanel();
        p.setLayout(new GridBagLayout());
        GridBagConstraints pc = new GridBagConstraints();
        pc.insets = new Insets(5, 5, 0, 5);
        // pc.fill = GridBagConstraints.HORIZONTAL;
        pc.weightx = 1.0;
        pc.anchor = GridBagConstraints.WEST;
        pc.gridx = 0;
        pc.gridy = GridBagConstraints.RELATIVE;

        p.add(textPanels[0], pc);
        pc.insets = new Insets(0, 5, 5, 5);
        p.add(textPanels[1], pc);
        // p.add(textPanels[2]);

        this.add(p, c);

        p = new JPanel();
        p.setLayout(new BorderLayout());
        p.add(queryPanel, "North");
        p.add(resultPanel, "Center");
        p.setBorder(BorderFactory.createEtchedBorder());

        c.gridy = GridBagConstraints.RELATIVE;
        c.gridheight = 0;
        c.weighty = 1.0;
        c.weightx = 0.0;
        c.fill = GridBagConstraints.BOTH;
        c.anchor = GridBagConstraints.EAST;

        this.add(p, c);

        this.setBorder(BorderFactory.createEtchedBorder());


        // figure out when we are un-tabbed
        controller.outerPanel.addChangeListener(new ChangeListener() {
            public void stateChanged(ChangeEvent e) {
                JTabbedPane tp = (JTabbedPane) e.getSource();
                Debug.info("HELP:  Tab event!");
                if (!(tp.getSelectedComponent() instanceof
                    com.sun.admin.pm.client.pmHelpIndexPanel)) {
                    Debug.info("HELP:  Tab event: resetting default");
		    /*
		     * controller.frame.getRootPane().
		     *	setDefaultButton(
		     *		controller.frame.dismiss);
		     */
                } else {
                    // allow tab to retain focus
                    // queryPanel.query.requestFocus();
                }
            }
        });


    }


    // place item titles in search result panel
    public void setSearchResults(Vector items) {
        Vector v = new Vector();

        if (items.size() == 0) {
            resultPanel.setListEmpty(true);
            v.addElement(pmUtility.getResource("Nothing.matched."));
        } else {
            Enumeration e = items.elements();
            while (e.hasMoreElements()) {
                pmHelpItem i = (pmHelpItem) e.nextElement();
                v.addElement(i);
            }
            resultPanel.setListEmpty(false);
        }

        resultPanel.setResultList(v);
    }

}



class pmHelpIndexResultPanel extends JPanel {

    JList resultList = null;
    pmButton selectButton = null;
    pmHelpIndexPanel parentPanel = null;
    protected boolean listEmpty = true;


    public pmHelpIndexResultPanel(pmHelpIndexPanel p) {

        parentPanel = p;

        this.setLayout(new GridBagLayout());

        GridBagConstraints c = new GridBagConstraints();
        c.insets = new Insets(10, 10, 10, 10);
        c.fill = GridBagConstraints.NONE;
        c.weightx = c.weighty = 0.0;
        c.gridx = 0;
        c.gridy = 0;
        c.anchor = GridBagConstraints.NORTHWEST;

        JLabel promptLabel = new JLabel(
            pmUtility.getResource("Matching.entries:"));
/*
 * MNEMONIC
 *        promptLabel.setDisplayedMnemonic(
 *           pmUtility.getIntResource("Matching.entries:.mnemonic"));
 */

        this.add(promptLabel, c);

        c.gridy = 1;
        c.anchor = GridBagConstraints.WEST;

        selectButton = new pmButton(
            pmUtility.getResource("Show"));
        selectButton.setMnemonic(
            pmUtility.getIntResource("Show.mnemonic"));

        selectButton.setEnabled(false);

        this.add(selectButton, c);

        selectButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                pmHelpItem selectedItem = (pmHelpItem)
                    resultList.getSelectedValue();
                Debug.message("Selected " + selectedItem);
                parentPanel.controller.showHelpItem(selectedItem);
            }
        });

        Vector resultItems = null;
        try {
            // resultItems = pmHelpIndexQueryPanel.helpDB.getPartialMatch("");
            resultItems = pmHelpRepository.helpItemsForString("");
        } catch (pmHelpException x) {
            Debug.message("pmHelpIndexResultpanel init: " + x);
            resultItems = new Vector();
            resultItems.addElement(
                pmUtility.getResource("Nothing.matched."));
        }

        resultList = new JList(resultItems);
        JScrollPane scrollPane = new JScrollPane();
        scrollPane.getViewport().setView(resultList);
        resultList.setVisibleRowCount(8);

        promptLabel.setLabelFor(resultList);

        resultList.addListSelectionListener(new ListSelectionListener() {
            public void valueChanged(ListSelectionEvent e) {
                if (!listEmpty) {
                    selectButton.setEnabled(true);
		    /*
		     * parentPanel.controller.frame.
		     * getRootPane().setDefaultButton(selectButton);
		     */
                    selectButton.setAsDefaultButton();

                }
            }});

        resultList.addMouseListener(new MouseAdapter() {
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2) {
                    JList l = (JList) e.getSource();
                    int i = l.locationToIndex(e.getPoint());
                    Debug.message("doubleclick index: " + i);
                    if (!listEmpty && i >= 0) {
                        pmHelpItem item =
                           (pmHelpItem) l.getModel().getElementAt(i);
                        Debug.message("doubleclick: " + item.tag);
                        parentPanel.controller.showHelpItem(item);
                    }
                }
            }
        });

        c.gridwidth = 1;    // 2;
        c.gridx = 1;
        c.gridy = 0;
        c.weightx = c.weighty = 1.0;
        c.fill = GridBagConstraints.BOTH;
        c.anchor = GridBagConstraints.EAST;

        this.add(scrollPane, c);

    }

    void setResultList(Vector v) {

        resultList.setListData(v);

        resultList.setSelectedValue(v.elementAt(0), true);
    }

    void setListEmpty(boolean e) {
        listEmpty = e;
        selectButton.setEnabled(false);
	/*
	 * parentPanel.controller.frame.getRootPane().
	 *    setDefaultButton(parentPanel.controller.frame.dismiss);
	 */
        if (parentPanel.controller.frame.dismiss != null)
            parentPanel.controller.frame.dismiss.
                setAsDefaultButton();
    }

}


class pmHelpIndexQueryPanel extends JPanel {

    JTextField query;
    pmHelpIndexPanel parentPanel;

    public pmHelpIndexQueryPanel(pmHelpIndexPanel p) {

        parentPanel = p;

        this.setLayout(new GridBagLayout());

        GridBagConstraints c = new GridBagConstraints();
        c.insets = new Insets(10, 10, 10, 10);
        c.fill = GridBagConstraints.NONE;
        c.weightx = c.weighty = 0.0;
        c.anchor = GridBagConstraints.WEST;

        c.gridx = 0;
        c.gridy = 0;
        c.gridwidth = 1;
        c.gridheight = 1;
        c.insets = new Insets(10, 10, 10, 10);

        JLabel promptLabel =
            new JLabel(pmUtility.getResource("Search.help.index.for:"));
/*
 * MNEMONIC
 *    promptLabel.setDisplayedMnemonic(
 *		pmUtility.getIntResource("Search.help.index.for:.mnemonic"));
 */

        this.add(promptLabel, c);

        query = new JTextField();
        query.setEditable(true);
        query.setText("");

        promptLabel.setLabelFor(query);

        query.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                Debug.info("HELP:  Action!");
                parentPanel.resultPanel.selectButton.doClick();
            }
        });

        c.gridwidth = GridBagConstraints.REMAINDER;
        c.gridx = 1;
        c.weightx = 1.0;
        c.fill = GridBagConstraints.HORIZONTAL;
        c.anchor = GridBagConstraints.EAST;

        this.add(query, c);

        DocumentListener d = new DocumentListener() {
            public void changedUpdate(DocumentEvent e) {
                // ignore
            }

            public void insertUpdate(DocumentEvent e) {
                handleText(query.getText());
            }

            public void removeUpdate(DocumentEvent e) {
                handleText(query.getText());
            }
        };

        query.getDocument().addDocumentListener(d);
    }

    public void handleText(String txt) {

        Debug.message("Got text " + txt);

        Vector v = null;

        try {
            // v = helpDB.getPartialMatch(txt);
            v = pmHelpRepository.helpItemsForString(txt);
        } catch (pmHelpException x) {
            Debug.warning("handleText: " + x);
        }
        parentPanel.setSearchResults(v);

    }

    // belongs in controller?
    //  static pmHelpRepository helpDB = new pmHelpRepository();
}
