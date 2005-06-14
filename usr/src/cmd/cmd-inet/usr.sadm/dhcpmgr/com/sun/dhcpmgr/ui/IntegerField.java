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
 * A text field which limits input to only digits.
 */
public class IntegerField extends JTextField {

    /**
     * Construct an empty field
     */
    public IntegerField() {
	this("");
    }
    
    /**
     * Construct a field initialized to the specified text.  Defaults to a width
     * of 5 characters.
     * @param text The initial text to display
     */
    public IntegerField(String text) {
	this(text, 5);
    }
    
    /**
     * Construct a field initialized to the specified value.  Defaults to a
     * width of 5 characters.
     * @param value The initial value to display
     */
    public IntegerField(int value) {
	this();
	setValue(value);
    }
    
    /**
     * Construct a field initialized to the specified Integer object.
     * Defaults to a width of 5 characters.
     * @param value The initial value to display
     */
    public IntegerField(Integer value) {
	this();
	setValue(value);
    }
    
    /**
     * Construct a field initialized to the specified text and width.
     * @param text The initial text to display
     * @param width The width of the field in characters
     */
    public IntegerField(String text, int width) {
	super(text, width);
	setHorizontalAlignment(RIGHT);
    }
    
    /**
     * Set the value of the field
     * @param value An <code>int</code> value to set
     */
    public void setValue(int value) {
	setText(String.valueOf(value));
    }
    
    /**
     * Set the value of the field
     * @param value The value to set as an <code>Integer</code>
     */
    public void setValue(Integer value) {
	if (value != null) {
	    setValue(value.intValue());
	}
    }
    
    /**
     * Retrieve the entered value
     * @return The value stored in the field as an <code>int</code>
     */
    public int getValue() {
	String s = getText();
	if ((s == null) || (s.length() == 0)) {
	    return 0;
	} else {
	    return Integer.parseInt(getText());
	}
    }

    protected Document createDefaultModel() {
	return new IntegerDocument();
    }
    
    /* 
     * This is the recommended way to validate input, as opposed to trapping
     * KeyEvents because this will actually catch paste operations as well.
     */
    static class IntegerDocument extends PlainDocument {
	public void insertString(int offs, String str, AttributeSet a)
	        throws BadLocationException {
	    if (str != null) {
		char [] chars = str.toCharArray();
		for (int i = 0; i < chars.length; ++i) {
		    if (!Character.isDigit(chars[i])) {
			throw new BadLocationException("", offs);
		    }
		}
	    }
	    super.insertString(offs, str, a);
	}
    }
}
