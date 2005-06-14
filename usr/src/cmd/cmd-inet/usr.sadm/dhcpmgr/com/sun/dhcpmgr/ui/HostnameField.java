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
 * Copyright (c) 1998-1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */
package com.sun.dhcpmgr.ui;

import java.awt.*;
import java.awt.event.*;
import javax.swing.*;
import javax.swing.text.*;

/**
 * A text field which limits input to only those characters which can legally 
 * appear in a hostname as specified in RFC1123, i.e. the letters, digits
 * and '-'.
 */
public class HostnameField extends JTextField {

    /**
     * Constructs an empty field, 20 characters wide.
     */
    public HostnameField() {
	this("");
    }
    
    /**
     * Constructs a field initialized to the provided text.  Defaults to 20
     * characters wide.
     * @param text the text to display initially
     */
    public HostnameField(String text) {
	this(text, 20);
    }
    
    /**
     * Constructs a field initialized to the provided text with the requested
     * size.
     * @param text the text to display initially
     * @param length the length in characters the field should size itself to
     */
    public HostnameField(String text, int length) {
	super(text, length);
    }
    
    protected Document createDefaultModel() {
	return new HostnameDocument();
    }
    
    /* 
     * This is the recommended way to validate/filter input, as opposed to
     * trapping KeyEvents because this will catch paste operations, too.
     */
    static class HostnameDocument extends PlainDocument {
	public void insertString(int offs, String str, AttributeSet a)
		throws BadLocationException {
	    if (str != null) {
		char [] chars = str.toCharArray();
		if ((chars.length != 0) && (getLength() == 0)) {
		    // First character in field must be a letter or digit
		    if (!Character.isLetterOrDigit(chars[0])) {
			throw new BadLocationException("", offs);
		    }
		}
		// Now validate that everything we're inserting is legal
		for (int i = 0; i < chars.length; ++i) {
		    if (!Character.isLetterOrDigit(chars[i])
			    && chars[i] != '-') {
			throw new BadLocationException("", offs);
		    }
		}
	    }
	    super.insertString(offs, str, a);
	}
    }
}
