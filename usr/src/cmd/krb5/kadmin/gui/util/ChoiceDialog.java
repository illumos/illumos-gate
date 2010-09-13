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

/**
 * Returns null when the dialog box is closed through the window closing menu.
 */
public class ChoiceDialog extends java.awt.Dialog {

    private String result = null;
  
    public ChoiceDialog(Frame parent, String title,
  		        String[] messageLines, String[] buttonText,
		        int bottomLeftX, int bottomLeftY) {
        super(parent, title, true);
        addLinesAndButtons(messageLines, buttonText);
        positionDialog(bottomLeftX, bottomLeftY);
        finishDialog();
    }

    public ChoiceDialog(Frame parent, String title,
    String[] messageLines, String[] buttonText) {

        super(parent, title, true);
        addLinesAndButtons(messageLines, buttonText);
        positionDialog(parent);
        finishDialog();
    }

    public void addLinesAndButtons(String[] messageLines, String[] buttonText) {

	Panel panel = new Panel();

	panel.setLayout(new GridBagLayout());
	GridBagConstraints gbc = new GridBagConstraints();
	gbc.gridwidth = GridBagConstraints.REMAINDER;
	gbc.weightx = gbc.weighty = 1;
	gbc.gridx = gbc.gridy = 1;

	for (int i = 0; i < messageLines.length; i++) {
	    Label t = new Label(" "+messageLines[i]);
	    panel.add(t, gbc);
	    gbc.gridy++;
	}

	add(panel, "Center" /* NOI18N */);

	panel = new Panel();
	panel.setLayout(new FlowLayout(FlowLayout.CENTER, 20, 5));

	for (int i = 0; i < buttonText.length; i++) {
	    Button b = new Button(buttonText[i]);
	    b.addActionListener(new ActionListener() {
		public void actionPerformed(ActionEvent e) {
		    result = e.getActionCommand();
		    dispose();
		}
	    });
	    panel.add(b);
	}

	add(panel, "South" /* NOI18N */);
    }

    public void finishDialog() {

        Frame parent = (Frame)getParent();

	setResizable(false);

	setBackground(parent.getBackground());
	setForeground(parent.getForeground());
	addWindowListener(new WindowCloseListener());
	setVisible(true);
    }

    public void positionDialog(Frame frame) {
        Point p = frame.getLocationOnScreen();
        Dimension s1 = frame.getSize();
        pack();
        Dimension s2 = getSize();
        p.x += s1.width/2 - s2.width/2;
        p.y += s1.height/2 - s2.height/2;
        setLocation(p.x, p.y);
    }

    public void positionDialog(int bottomLeftX, int bottomLeftY) {
        Point p = new Point(bottomLeftX, bottomLeftY);
        pack();
        Dimension s = getSize();
        p.y -= s.height;
        setLocation(p.x, p.y);
    }
  
    // return the name of the selected button.
    public String getSelection() {
	return result;
    }	

    private  class WindowCloseListener extends  WindowAdapter {
        public void windowClosing(WindowEvent e) {
	    dispose();
        }
    }   

    public static void main(String[] args) {

	Frame frame = new Frame();
	frame.setVisible(true);

	String[] lines = {"line one", "line two"};
	String[] buttons = {"button one", "button two"};
	ChoiceDialog c1 = new ChoiceDialog(frame, "Hi", lines, buttons,
                                           100, 100);
	String s = c1.getSelection();
	System.out.println("Returned "+s);

	String[] warnlines = {"You are about to lose changes",
		 "Press OK to discard changes or"
		+" Cancel to continue editing."};
	String[] warnbuttons = {"OK", "Cancel"};
	c1 = new ChoiceDialog(frame, "Confirm Action",
				warnlines, warnbuttons);
	s = c1.getSelection();
	System.out.println("Returned "+s);

	System.exit(0);
    }
}
