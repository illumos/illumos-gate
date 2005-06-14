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
 * Copyright (c) 1999-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 *
 * pmAboutBox.java
 *
 */

package com.sun.admin.pm.client;

import java.awt.*;
import java.awt.event.*;
import javax.swing.*;
import javax.swing.border.*;

import com.sun.admin.pm.server.*;


public class pmAboutBox extends pmFrame {
	public pmButton cancel = null;
	String title = pmUtility.getResource("About.Solaris.Print.Manager");
	String copyright = new String(pmUtility.getResource("info_copyright1")
			+ pmUtility.getCopyrightResource("copyright_year")
			+ pmUtility.getResource("info_copyright2"));
	String version = pmUtility.getResource("info_version");
	String appname = pmUtility.getResource("info_name");
	String contents = new String(appname + "\n" +
			version + "\n\n" +
			copyright + "\n");

	public pmAboutBox() {

	super(pmUtility.getResource("About.Solaris.Print.Manager"));

	cancel = new pmButton(pmUtility.getResource("Cancel"));
	cancel.setMnemonic(pmUtility.getIntResource("Cancel.mnemonic"));
	cancel.addActionListener(new ActionListener() {
		public void actionPerformed(ActionEvent e) {
			hideAboutBox();
		}
	});

	// Create a regular text field.
	JTextArea textArea = new JTextArea(contents);
	Font f = new pmJTextField().getFont();
	Font fb = new Font(f.getName(), f.PLAIN, f.getSize());
	textArea.setOpaque(false);
	textArea.setFont(fb);
	textArea.setLineWrap(true);
	textArea.setWrapStyleWord(true);
	textArea.setEditable(false);
	textArea.setDisabledTextColor(Color.blue);

	JPanel j1 = new JPanel();
	j1.setBorder(new EmptyBorder(10, 10, 10, 10));
	j1.setLayout(new BorderLayout());
	JScrollPane areaScrollPane = new JScrollPane(textArea);
	areaScrollPane.setPreferredSize(new Dimension(270, 175));
	j1.add(areaScrollPane, BorderLayout.CENTER);

	JPanel buttonPanel = new JPanel();
	buttonPanel.setBorder(new EmptyBorder(0, 0, 10, 10));
	buttonPanel.setLayout(new FlowLayout(FlowLayout.CENTER));
	buttonPanel.add(cancel);

	JPanel bottomPanel = new JPanel(new BorderLayout());
	bottomPanel.add(buttonPanel, BorderLayout.SOUTH);

	Container contentPane = getContentPane();
	contentPane.add(j1, BorderLayout.CENTER);
	contentPane.add(bottomPanel, BorderLayout.SOUTH);

	// default button is cancel
	cancel.setAsDefaultButton();

	// handle Esc as cancel
	getRootPane().registerKeyboardAction(new ActionListener() {
		public void actionPerformed(ActionEvent e) {
			Debug.message("HELP:  cancel action");
			hideAboutBox();
		}},
		KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0, false),
		JComponent.WHEN_IN_FOCUSED_WINDOW);

	pack();
	repaint();

	}

	public void hideAboutBox() {
		this.setVisible(false);
	}
}
