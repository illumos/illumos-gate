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

import sunsoft.jws.visual.rt.shadow.java.awt.*;
import java.awt.*;

/**
 * This creates a text field for storing integers that implements the
 *  DCListener interface so that it can be notified to
 * increment/decrement its value. 
 */
public class DCTextField extends TextField implements DCListener {

	private int value;

	private int bigIncrementValue = 1;

    /**
     * Constructor for DCTextField.
     * @param text the text to initialize the text field with
     * @param columns the width of the text field in number of columns
     */
    public DCTextField(String text, int columns) {
	super(columns);
	setValueFromText(text);
    }

    /**
     * Sets the value of the big increment for this text field.
     */
    public void setBigIncrement(int value) {
	bigIncrementValue = value;
    }

    /**
     * Method from interface DCListener.
     */
    public void increment() {
   	increment(1);
    }

    /**
     * Method from interface DCListener.
     */
    public void decrement() {
	increment(-1);
    }

    /**
     * Method from interface DCListener.
     */
    public void bigIncrement() {
	increment(bigIncrementValue);
    }

    /**
     * Method from interface DCListener.
     */
    public void bigDecrement() {
	increment(-1*bigIncrementValue);
    }

    /**
     * Increments the value of the textfield. It does not increment it
     * if this will lead to an invalid value.
     * @param value how much to increment by.  It can be negative if one
     * desires to decrement.
     */
    protected void increment(int value) {
	setValue(getValue() + value);
    }

    /**
     * The current integer value associated with this text field.
     * @return the int value.
     */
    public int getValue() {
	return value;
    }

    /**
     * Sets the current integer value associated with this text
     * field. The text field will display this value. If the value is not
     * valid then the old value will remain in effect. 
     */
	public void setValue(int newValue) {
		if (checkValue(newValue)) {
			value = newValue;
			setText(Integer.toString(newValue));
		}
	}

    /**
     * Sets the value for this text field from the given text.
     * @param text the text that this text field shoudl contain.
     * @exception NumberFormatException Thrown when the supplied text
     * cannot be parsed in to an interger value.
     */
	public void setValueFromText(String text) throws NumberFormatException {
		Integer i = Integer.valueOf(text);
		setValue(i.intValue());
	}

    /**
     * Checks to see if the given value
     * would be valid for this text
     * field. Classes deriving form this class should override this to
     * provide whatever checks they desire.
     * @param newValue
     * @return true if it will be valid,
     * false otherwise. This class
     * returns true always for all integer values.
     */
    public boolean checkValue(int newValue) {
	return true;
    }

}
