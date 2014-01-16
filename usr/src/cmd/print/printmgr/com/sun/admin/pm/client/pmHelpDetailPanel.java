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
 * Copyright(c) 1999 - 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 *
 * pmHelpDetailPanel.java
 * View a help article
 */

package com.sun.admin.pm.client;

import java.awt.*;
import java.awt.event.*;
import java.util.*;
import java.io.*;
import java.net.URL;
import javax.swing.JPanel;
import javax.swing.border.*;
import javax.swing.event.*;
import javax.swing.*;

import com.sun.admin.pm.server.*;

class pmHelpLoc {
    public pmHelpItem item;
    public Point pos;

    public pmHelpLoc(pmHelpItem i) {
        this(i, new Point(0, 0));
    }

    public pmHelpLoc(pmHelpItem i, Point p) {
        item = i;
        pos = p;
    }

    public pmHelpLoc() {
        this(null, new Point(0, 0));
    }
}

public class pmHelpDetailPanel extends JPanel {

    pmHelpController controller;
    pmHelpSeeAlsoPanel seeAlsoPanel;
    pmHelpViewPanel viewPanel;

    pmHelpLoc history[];
    int historyIndex;
    int historyLast;

    static final int MAX_HISTORY_ITEMS = 101;

    public pmHelpDetailPanel(pmHelpController ctrl) {

        controller = ctrl;

        // build subpanels
        seeAlsoPanel = new pmHelpSeeAlsoPanel(this);
        viewPanel = new pmHelpViewPanel(this);

        // lay out top panel
        this.setLayout(new GridBagLayout());
        GridBagConstraints c = new GridBagConstraints();

        c.insets = new Insets(5, 5, 5, 5);

        c.gridwidth = GridBagConstraints.REMAINDER;

        c.gridx = 0;
        c.gridy = 0;

        c.gridheight = 2;    // GridBagConstraints.REMAINDER;
        c.fill = GridBagConstraints.BOTH;
        c.weightx = 1.0;
        c.weighty = 6.0;
        c.insets = new Insets(5, 5, 0, 5);
        this.add(viewPanel, c);

        c.gridy = GridBagConstraints.RELATIVE;
        // c.gridheight = GridBagConstraints.REMAINDER;
        c.gridheight = 0;
        c.weighty = 0.0;
        c.weightx = 1.0;
        c.fill = GridBagConstraints.BOTH;
        c.anchor = GridBagConstraints.WEST;
        c.insets = new Insets(0, 5, 5, 5);
        this.add(seeAlsoPanel, c);

        this.setBorder(BorderFactory.createEtchedBorder());

        history = new pmHelpLoc[MAX_HISTORY_ITEMS];
        historyIndex = 0;
        historyLast = 0;

        // manage focus when we are tabbed or un-tabbed
        controller.outerPanel.addChangeListener(new ChangeListener() {
            public void stateChanged(ChangeEvent e) {
                JTabbedPane tp = (JTabbedPane) e.getSource();
                Debug.info("HELP:  Tab event!");
                if (!(tp.getSelectedComponent() instanceof
                       com.sun.admin.pm.client.pmHelpDetailPanel)) {
                    Debug.info("HELP:  Tab event: resetting default");
                    /*
                     * controller.frame.getRootPane().
                     * setDefaultButton(
                     *		controller.frame.dismiss);
                     */
                    if (controller.frame.dismiss != null)
                        controller.frame.dismiss.
                            setAsDefaultButton();
                }
            }
        });

        addFocusListener(new FocusAdapter() {
            public void focusGained(FocusEvent e) {
                Debug.info("HELP:  detailPanel gained focus");
                if (controller.frame.dismiss != null)
                    controller.frame.dismiss.
                        setAsDefaultButton();

            }
        });
    }

    // ask parent controller to show item
    public void showItem(String tag) {
        controller.showHelpItem(tag);
    }

    public void showHistoryBackItem() {
        Debug.message("HELP:  showHistoryBackItem: index = " +
                      historyIndex + " last = " +
                      historyLast +
                      "\n\thistory = " +
                      history);

        // assuming item already visible, preserve its position
        history[historyIndex].pos = viewPanel.getPos();

        Debug.info("back: pos is " + history[historyIndex].pos);

        if (historyIndex > 1) {
            pmHelpLoc l = history [--historyIndex];
            pmHelpItem item = l.item;
            Point p = l.pos;
            loadItem(item, p);
        }
        viewPanel.setNavButtons(historyIndex, historyLast);
    }

    public void showHistoryForwardItem() {
        Debug.message("HELP:  showHistoryForwardItem: index = " +
                      historyIndex +
                      " last = " + historyLast +
                      "\n\thistory = " + history);

        // assuming already an item visible, preserve its position
        history[historyIndex].pos = viewPanel.getPos();

        Debug.info("HELP:  fwd: pos is " + history[historyIndex].pos);

        if (historyIndex < historyLast) {
            pmHelpLoc l = history [++historyIndex];
            pmHelpItem item = l.item;
            Point p = l.pos;
            loadItem(item, p);
        }
        viewPanel.setNavButtons(historyIndex, historyLast);
    }


    /*
     * load the help item
     * internal
     */
    protected pmHelpItem loadItem(pmHelpItem item) {
        return loadItem(item, new Point(0, 0));
    }

    protected pmHelpItem loadItem(pmHelpItem item, Point pos) {
        Debug.message("HELP:  View: loadItem " + item.tag);
        seeAlsoPanel.setItems(item.seealso);

        Debug.info("loadItem: pos is " + pos);

        viewPanel.setItem(item.title, item.content);
        viewPanel.setPos(pos);
        return item;
    }


    /*
     * load the help item corresponding to the specified tag
     * external - called from helpController
     *		note that this is how see-also items are loadedes
     */
    public pmHelpItem loadItemForTag(String tag) {

        pmHelpItem item;

        if (tag == null ||
            (item = pmHelpRepository.helpItemForTag(tag)) == null) {
            Debug.warning("HELP:  View: item not found");
            loadEmptyItem(tag);
            return null;
        }

        Debug.info("loadItem(before): index = " + historyIndex +
                   ", last = " + historyLast);

        // if there's already an item visible, preserve its position
        if (historyIndex != 0 && historyLast != 0)
            history[historyIndex].pos = viewPanel.getPos();

        loadItem(item);

        Debug.info("HELP:  loadItemForTag: index = " + historyIndex +
                   " last = " + historyLast + "\n\thistory = " +
                   history);

        /*
         * make the new item the latest in history.
         * if the history length is maxed out, the new item
         * will replace the item that's currently last.
         */

        if (historyIndex < history.length - 1) {
            // init pos to 0,0
            history [++historyIndex] = new pmHelpLoc(item);
        } else {
            // replace last item
            history [historyIndex] = new pmHelpLoc(item);
        }
        historyLast = historyIndex;

        viewPanel.setNavButtons(historyIndex, historyLast);

        Debug.info("loadItem(after): index = " + historyIndex +
                   ", last = " + historyLast);
        return item;
    }

    private void loadEmptyItem(String itm) {
        String msg = new String(
            pmUtility.getResource("Item.not.found:") + itm);
        viewPanel.setItem(msg, new pmHelpContent(
            pmUtility.getResource("No.information.available.")));
        seeAlsoPanel.setItems(null);
    }

}



class pmHelpSeeAlsoPanel extends JPanel {

    pmHelpDetailPanel parentPanel = null;
    Vector seeAlsoItems = null;
    JComboBox theComboBox = null;
    pmButton selectButton = null;

    private void layoutBox() {

        JPanel p = new JPanel();
        p.setLayout(new BorderLayout(5, 0));

        p.add(new JPanel(), "North");
        p.add(new JPanel(), "South");

        p.add(new JLabel(
            pmUtility.getResource("See.also:")), "West");

        theComboBox = new JComboBox();

        Font f = theComboBox.getFont();
        Font fb = new Font(f.getName(), f.PLAIN, f.getSize());
        theComboBox.setFont(fb);

        theComboBox.setPreferredSize(
            new Dimension(200, theComboBox.getPreferredSize().height));
        theComboBox.setMinimumSize(
            new Dimension(20, theComboBox.getPreferredSize().height));
        theComboBox.setMaximumSize(
            new Dimension(300, theComboBox.getPreferredSize().height));
        theComboBox.setEnabled(false);

	/*
	 * theComboBox.addActionListener(new ActionListener() {
	 *    public void actionPerformed(ActionEvent e) {
	 *	JComboBox src = (JComboBox) e.getSource();
	 *	System.out.println("Combo: action = " +
	 *			e.getActionCommand());
	 *	System.out.println("Combo: mod = " +
	 *			e.getModifiers());
	 *	System.out.println("Combo: param = " +
	 *			e.paramString());
	 *	System.out.println("Combo: item = " +
	 *			src.getSelectedItem());
	 *    }
	 * });
	 */

        p.add(theComboBox, "Center");

        selectButton = new pmButton(
            pmUtility.getResource("Show"));
        selectButton.setMnemonic(
            pmUtility.getIntResource("Show.mnemonic"));
        selectButton.setEnabled(false);

        p.add(selectButton, "East");
        selectButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                pmHelpItem i = (pmHelpItem) theComboBox.getSelectedItem();
                Debug.message("HELP:  got button: item is " + i);
                // parentPanel.loadItemForTag(i.tag);
                parentPanel.showItem(i.tag);
            }
        });

        JPanel pp = new JPanel();
        pp.setLayout(new BorderLayout(5, 0));
        pp.add(p, "Center");

        this.setLayout(new BoxLayout(this, BoxLayout.X_AXIS));
        this.add(Box.createHorizontalStrut(10));
        this.add(pp);
        this.add(Box.createHorizontalStrut(10));
        this.add(Box.createHorizontalGlue());

    }

    public pmHelpSeeAlsoPanel(pmHelpDetailPanel p) {
        parentPanel = p;
        layoutBox();
        this.setBorder(BorderFactory.createEtchedBorder());
    }


    /*
     * set the titles of the pmHelpItems whose tags are
     * passed into see-also combo box
     */
    public void setItems(Vector tags) {
        clearItems();

        if (tags == null)
            return;

        Enumeration e = tags.elements();
        while (e.hasMoreElements()) {
            pmHelpItem i =
                pmHelpRepository.helpItemForTag((String) e.nextElement());
            if (i != null)
                theComboBox.addItem(i);
        }

        selectButton.setEnabled(true);
        theComboBox.setEnabled(true);


        // repaint();
    }


    public void clearItems() {
        if (theComboBox.getItemCount() > 0)
            theComboBox.removeAllItems();
        selectButton.setEnabled(false);
        theComboBox.setEnabled(false);
    }

}


class pmHelpViewPanel extends JPanel {
    // JTextArea helpView;
    JEditorPane helpView;
    JScrollPane scrollPane;
    pmHelpHelpOnPanel titlePanel;
    pmHelpDetailPanel parentPanel;
    pmButton backButton;
    pmButton forwardButton;

    public pmHelpViewPanel(pmHelpDetailPanel par) {
        parentPanel = par;

        // helpView = new JTextArea(10, 32);
        // helpView.setLineWrap(true);

        helpView = new JEditorPane();

        helpView.setContentType("text/html");
        helpView.setEditable(false);
        helpView.setEnabled(false);
        helpView.setDisabledTextColor(Color.blue);

        scrollPane = new JScrollPane(helpView);

        this.setLayout(new GridBagLayout());
        GridBagConstraints c = new GridBagConstraints();
        c.insets = new Insets(5, 10, 5, 10);
        c.gridwidth = GridBagConstraints.REMAINDER;

        c.gridx = 0;
        c.gridy = 0;

        c.gridheight = 1;
        c.fill = GridBagConstraints.HORIZONTAL;
        c.weightx = 1.0;
        // c.weighty = 1.0;
        c.weighty = 0.05;

        titlePanel = new pmHelpHelpOnPanel();
        this.add(titlePanel, c);

        c.gridy = 1;
        c.gridheight = 1;

        c.gridwidth = GridBagConstraints.REMAINDER;
        c.weightx = 1.0;
        c.weighty = 6.0;
        c.fill = GridBagConstraints.BOTH;
        c.insets = new Insets(5, 10, 5, 10);
        // c.insets = new Insets(5, 5, 5, 5); // NEW
        this.add(scrollPane, c);

        this.setBorder(BorderFactory.createEtchedBorder());

        /*
         */
        try {
            helpView.setPage(new URL("file:///test.html"));
        } catch (Exception x) {
            Debug.info("setPage caught: " + x);
        }
        /*
         */

        // navigation buttons
        JPanel p = new JPanel();
        p.setLayout(new GridBagLayout());
        GridBagConstraints pc = new GridBagConstraints();
        // pc.insets = new Insets(2, 2, 2, 2);
        // pc.fill = GridBagConstraints.HORIZONTAL;
        pc.weightx = 1.0;
        pc.weighty = 1.0;
        pc.gridx = 0;
        pc.anchor = GridBagConstraints.WEST;

        backButton = new pmButton(
            pmUtility.getResource("Back"));
        backButton.setMnemonic(
            pmUtility.getIntResource("Back.mnemonic"));
        p.add(backButton, pc);
        backButton.setEnabled(false);
        backButton.setDefaultCapable(false);
        backButton.addActionListener(new  ActionListener() {
            public void actionPerformed(ActionEvent e) {
                parentPanel.showHistoryBackItem();
            }
        });


        pc.gridx = 1;
        pc.anchor = GridBagConstraints.EAST;

        forwardButton = new pmButton(
            pmUtility.getResource("Forward"));
        forwardButton.setMnemonic(
            pmUtility.getIntResource("Forward.mnemonic"));
        p.add(forwardButton, pc);
        forwardButton.setEnabled(false);
        forwardButton.setDefaultCapable(false);
        forwardButton.addActionListener(new  ActionListener() {
            public void actionPerformed(ActionEvent e) {
                parentPanel.showHistoryForwardItem();
            }
        });

        c.gridy = GridBagConstraints.RELATIVE;
        c.gridheight = 1;    // GridBagConstraints.REMAINDER;
        c.gridwidth = GridBagConstraints.REMAINDER;
        c.weightx = 1.0;
        // c.weighty = 1.0;
	c.weighty = 0.05;	// NEW

        c.fill = GridBagConstraints.BOTH;
        c.insets = new Insets(0, 10, 5, 10);
        // c.insets = new Insets(0, 10, 5, 10);
        c.insets = new Insets(5, 10, 5, 10);
        // NEW

        add(p, c);

    }


    public void setItem(String title, pmHelpContent content) {
        helpView.setText(content.getText());
        // scrollPane.getViewport().setViewPosition(new Point(0, 0));
        titlePanel.helpTopic.setText(title);
    }

    public void setPos(Point p) {
        scrollPane.getViewport().setViewPosition(p);
    }

    public Point getPos() {
        return scrollPane.getViewport().getViewPosition();
    }

    public void setNavButtons(int index, int last) {
        Debug.message("HELP:  NavButtons " + index + " " + last);

        if (last > index)
            forwardButton.setEnabled(true);
        else
            forwardButton.setEnabled(false);

        if (index > 1 && last > 1)
            backButton.setEnabled(true);
        else
            backButton.setEnabled(false);
    }

}


class pmJTextField extends JTextField {
    public boolean isFocusable() {
        return false;
    }
}

class pmHelpHelpOnPanel extends JPanel {

    pmJTextField helpTopic;

    public  pmHelpHelpOnPanel() {

        helpTopic = new pmJTextField();
        helpTopic.setEditable(false);
        helpTopic.setText("Default help topic");
        helpTopic.setBackground(Color.white);

        Font f = helpTopic.getFont();
        Font fb = new Font(f.getName(), Font.BOLD, f.getSize());
        helpTopic.setFont(fb);

        this.setLayout(new BoxLayout(this, BoxLayout.X_AXIS));
        JPanel p = new JPanel();
        p.setLayout(new BorderLayout(5, 0));
        p.add(new JLabel(
            pmUtility.getResource("Help.on:")),
              "West");
        p.add(helpTopic, "Center");

        JPanel pp = new JPanel();
        pp.setLayout(new BorderLayout(0, 0));
        pp.add(p, "Center");

        // this.add(Box.createHorizontalStrut(5));
        this.add(pp);
        // this.add(Box.createHorizontalStrut(5));
        this.add(Box.createHorizontalGlue());


        // this.setBorder(BorderFactory.createEtchedBorder());

    }

}
