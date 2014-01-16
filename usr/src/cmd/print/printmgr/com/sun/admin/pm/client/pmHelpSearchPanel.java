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
 * pmHelpSearchPanel.java
 * Search help keywords
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


public class pmHelpSearchPanel extends JPanel {

    pmHelpController controller;
    pmHelpSearchQueryPanel queryPanel;
    pmHelpSearchResultPanel resultPanel;
    JLabel textPanels[];

    public pmHelpSearchPanel(pmHelpController ctrl) {
        controller = ctrl;

        // build subpanels
        queryPanel = new pmHelpSearchQueryPanel(this);
        resultPanel = new pmHelpSearchResultPanel(this);

        textPanels = new JLabel[4];
        textPanels[0] = new JLabel(
            pmUtility.getResource("To.find.help.articles..."));
        textPanels[1] = new JLabel(
            pmUtility.getResource("enter.keywords.below..."));

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
        queryPanel.setBorder(BorderFactory.createEtchedBorder());
        p.add(queryPanel, "North");
        resultPanel.setBorder(BorderFactory.createEtchedBorder());
        p.add(resultPanel, "Center");
        // p.setBorder(BorderFactory.createEtchedBorder());

        c.gridy = 1;
        // new stuff
        c.gridy = GridBagConstraints.RELATIVE;
        c.gridheight = 0;
        c.weighty = 1.0;
        c.weightx = 0.0;
        c.fill = GridBagConstraints.BOTH;
        c.anchor = GridBagConstraints.EAST;
        // end new stuff

        this.add(p, c);
        this.setBorder(BorderFactory.createEtchedBorder());


        // figure out when we are tabbed or un-tabbed
        controller.outerPanel.addChangeListener(new ChangeListener() {
            public void stateChanged(ChangeEvent e) {
                JTabbedPane tp = (JTabbedPane) e.getSource();
                Debug.info("HELP:  Tab event!");
                if (!(tp.getSelectedComponent() instanceof
                       com.sun.admin.pm.client.pmHelpSearchPanel)) {
                    Debug.info("HELP:  Tab event: resetting default");
		    /*
		     * controller.frame.getRootPane().
		     *	setDefaultButton(
		     * 		controller.frame.dismiss);
		     */
		    /*
		     * System.out.println(controller);
		     * System.out.println(controller.frame);
		     * System.out.println(controller.frame.dismiss);
		     */

                    if (controller.frame.dismiss != null)
                        controller.frame.dismiss.
                            setAsDefaultButton();
                } else {
                    // better to have the tab itself keep focus.
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



class pmHelpSearchResultPanel extends JPanel {

    JList resultList = null;
    pmButton selectButton = null;
    pmHelpSearchPanel parentPanel = null;
    protected boolean listEmpty = true;


    public pmHelpSearchResultPanel(pmHelpSearchPanel par) {

        parentPanel = par;

        this.setLayout(new GridBagLayout());

        GridBagConstraints c = new GridBagConstraints();
        c.insets = new Insets(10, 10, 10, 10);
        c.fill = GridBagConstraints.NONE;
        c.weightx = c.weighty = 0.0;
        c.gridx = 0;
        c.gridy = 0;
        c.anchor = GridBagConstraints.NORTHWEST;

        JLabel promptLabel = new JLabel(
            pmUtility.getResource("Search.Results:"));
/*
 * MNEMONIC
 *        promptLabel.setDisplayedMnemonic(
 *            pmUtility.getIntResource("Search.Results:.mnemonic"));
 */

        this.add(promptLabel, c);

        selectButton = new pmButton(
            pmUtility.getResource("Show"));
        selectButton.setMnemonic(
            pmUtility.getIntResource("Show.mnemonic"));

        selectButton.setEnabled(false);

        selectButton.addActionListener(new ActionListener() {
            // load the selected item into view panel
            public void actionPerformed(ActionEvent e) {
                pmHelpItem selectedItem = (pmHelpItem)
                    resultList.getSelectedValue();
                Debug.info("HELP:  Selected " + selectedItem);
                parentPanel.controller.showHelpItem(selectedItem);

            }
        });

        c.gridy = 1;
        c.anchor = GridBagConstraints.SOUTHWEST;
        this.add(selectButton, c);


        Vector resultItems = new Vector();

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
                    Debug.info("HELP:  doubleclick index: " + i);
                    if (!listEmpty && i >= 0) {
                        pmHelpItem item = (pmHelpItem) l.getModel().
                            getElementAt(i);
                        Debug.info("HELP:  doubleclick: " + item.tag);
                        parentPanel.controller.showHelpItem(item);
                    }
                }
            }
        });


        c.gridwidth = 2;
        c.gridx = 1;
        c.gridy = 0;
        c.weightx = c.weighty = 1.0;
        c.fill = GridBagConstraints.BOTH;
        c.anchor = GridBagConstraints.WEST;

        this.add(scrollPane, c);

    }

    public void setResultList(Vector v) {
        resultList.setListData(v);
        resultList.setSelectedValue(v.elementAt(0), true);

    }

    void setListEmpty(boolean e) {
        listEmpty = e;
        selectButton.setEnabled(false);
	/*
	 * parentPanel.controller.frame.getRootPane().
	 * setDefaultButton(parentPanel.controller.frame.dismiss);
	 */
        parentPanel.controller.frame.dismiss.setAsDefaultButton();

    }


}


class pmHelpSearchQueryPanel extends JPanel {

    JTextField query;
    pmButton search;
    pmHelpSearchPanel parentPanel = null;

    public pmHelpSearchQueryPanel(pmHelpSearchPanel par) {

        parentPanel = par;

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

        JLabel promptLabel =
            new JLabel(pmUtility.getResource("Keywords:"));
/*
 * MNEMONIC
 *     promptLabel.setDisplayedMnemonic(
 *         pmUtility.getIntResource("Keywords:.mnemonic"));
 */

        this.add(promptLabel, c);

        search = new pmButton(
            pmUtility.getResource("Find"));
        search.setMnemonic(
            pmUtility.getIntResource("Find.mnemonic"));

        search.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                // parse the keyword strings
                Vector v = null;
                StringTokenizer st = null;
                String s = query.getText();
                if (s != null) {
                    v = new Vector();
                    st = new StringTokenizer(s);
                    while (st.hasMoreTokens())
                        v.addElement(st.nextToken());
                    v = getItemsForKeywords(v);
                    parentPanel.setSearchResults(v);

                    if (v != null && v.size() != 0) {
                        Debug.info("HELP:  search vector full");
                        parentPanel.resultPanel.resultList.requestFocus();
                    } else {
                        Debug.info("HELP:  search vector empty");
                    }
                }

            }
        });

        c.fill = GridBagConstraints.NONE;
        c.gridx = 2;
	c.gridy = 0;	// GridBagConstraints.RELATIVE;
        this.add(search, c);

        query = new JTextField();
        query.setEditable(true);
        query.setText(" ");

        promptLabel.setLabelFor(query);

        query.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                Debug.info("HELP:  Action!");
                pmHelpSearchQueryPanel.this.search.doClick();
            }
        });

        query.getDocument().addDocumentListener(new DocumentListener() {
            public void changedUpdate(DocumentEvent e) {
                // ignore
            }

            public void insertUpdate(DocumentEvent e) {
                // make search the default button
                Debug.info("HELP:  search doc inserted update");
                pmHelpSearchQueryPanel.this.search.setEnabled(true);
		/*
		 * parentPanel.controller.frame.
		 * getRootPane().setDefaultButton(
		 * pmHelpSearchQueryPanel.this.search);
		 */
                if (pmHelpSearchQueryPanel.this.search != null)
                    pmHelpSearchQueryPanel.this.search.
                        setAsDefaultButton();
            }

            public void removeUpdate(DocumentEvent e) {
                Debug.info("HELP:  search doc removed update");
                // restore the default button
                if (query.getText().length() == 0) {
                    /*
                     * parentPanel.controller.frame.
                     * getRootPane().setDefaultButton(
                     * parentPanel.controller.frame.dismiss);
                     */
                    if (parentPanel.controller.frame.dismiss != null)
                        parentPanel.controller.frame.dismiss.
                            setAsDefaultButton();
                }
            }
        });



	c.gridwidth = 1;	// GridBagConstraints.REMAINDER;
        c.gridx = 1;
        c.weightx = 1.0;
        c.fill = GridBagConstraints.HORIZONTAL;
        c.anchor = GridBagConstraints.EAST;

        this.add(query, c);

    }


    Vector getItemsForKeywords(Vector keywords) {
        Vector result = new Vector();

        Debug.info("HELP:  getItemsForKeywords: " + keywords);

        Enumeration words = keywords.elements();
        while (words.hasMoreElements()) {
            String s = (String) words.nextElement();
            Vector newItems = pmHelpRepository.helpItemsForKeyword(s);
            Debug.info("HELP:  getItemsForKeywords new items: " + newItems);

            if (newItems != null) {
                Enumeration items = newItems.elements();
                while (items.hasMoreElements()) {
                    pmHelpItem i = (pmHelpItem) items.nextElement();
                    Debug.info("HELP:  getItemsForKeywords result: " + result);
                    Debug.info("HELP:  getItemsForKeywords item: " + i);

                    if (!result.contains(i))
                        result.addElement(i);
                }
            }
        }
        return result;
    }
}
