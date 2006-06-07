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
 * pmTextField.java
 * Extension of JTextField which accepts only 8-bit-ASCII.
 */

package com.sun.admin.pm.client;

import java.awt.*;
import java.awt.event.*;
import javax.swing.*;
import javax.swing.text.*;

public class pmTextField extends JTextField {
    public pmTextField(int n) {
        this(null, n);
    }

    public pmTextField(String s) {
        this(s, 0);
    }

    public pmTextField(String s, int n) {
        super(s, n);
    }

    protected Document createDefaultModel() {
        return new pmFilterDoc();
    }

    /*
     * This doc implementation will disallow insertion of a
     * string containing any characters which are non-8-bit-ascii.
     */
    private class pmFilterDoc extends PlainDocument {
        public void insertString(int offset, String str, AttributeSet a)
            throws BadLocationException {
            int i, c;
            char[] buf = str.toCharArray();

            for (i = 0; i < buf.length; i++) {
                c = (new Character(buf[i])).charValue();
                if (c > 0x00ff)
                    break;
            }
            if (i == buf.length)
                super.insertString(offset, str, a);
            else
                Toolkit.getDefaultToolkit().beep();
    }
    }

    public static void main(String args[]) {
        JFrame f = new JFrame();
        f.getContentPane().add(new pmTextField(20));
        f.pack();
        f.setVisible(true);
        f.repaint();
    }

}
