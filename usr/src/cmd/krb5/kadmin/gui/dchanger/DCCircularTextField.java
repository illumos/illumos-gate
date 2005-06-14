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

    import java.awt.TextField;

    /**
     * This class is a DCTextField that allows values to wrap around over
     * a maximum and a minimum value.
     */
    public class DCCircularTextField extends DCTextField {
    private int maximum = 59;
    private int minimum = 0;
 
    /**
     * Constructor for DCCircularTextField.
     * @param text the text to initilize the text field with
     * @param columns the width of the text field in number of columns
     */
    public DCCircularTextField(String text, int columns) {
	super(text, columns);
    }

    /**
     * Sets the maximum allowable value for this field. If the current
     * value is greater than this maximum value, then the current value is
     * set to the maximum value.
     * @param maxValue the maximum integer value for this text field.
     */
    public void setMaximum(int maxValue) {
	maximum = maxValue;
	if (getValue() > maxValue)
	    super.setValue(maxValue);
    }
    
    /**
     * Sets the minimum allowable value for this field. If the current
     * value is less than this minimum value, then the current value is
     * set to the minimum value.
     * @param minValue the minimum integer value for this text field.
     */
    public void setMinimum(int minValue) {
	minimum = minValue;
	if (getValue() < minValue)
	    super.setValue(minValue);
    }
    
    /**
     * Increments the value of the textfield. It does a wrap around on
     * the max value and min value.
     * @param value how much to increment by. It can be negative if one
     * desires to decrement.
     */
    protected final void increment(int value) {
    
    int current = getValue();
    int next = (current + value);
    
    /*
     * Now wrap it around this way:
     */
    
    /*
     *
     * (1) Translate coordinates by 'minimum' to get the minimum to 0
     *     eg. the legal range -1..5   to   0..6
     *                      or  1..5   to   0..4
     */
    int transMax   = maximum - minimum;
    int transValue = next    - minimum;
    
    /*
     * (2) Now do circular math
     */
    transValue %= (transMax + 1); // modulo max+1 since max is permissible
    transValue = (transValue < 0)? (transValue + (transMax+1)) : transValue;
    
    /*
     * (3) Translate back to old coordinates
     */
    next = transValue + minimum;
    
    setValue(next);
    }

    /**
     * Checks to see if the given value would be 
     * valid for this text
     * field. The check looks to see if the value is less than the
     * minimum value or greater than the maximum value.
     * @param newValue
     * @return true if it will be valid, false otherwise.
     */
    public boolean checkValue(int value) {
    if (value > maximum || value < minimum)
        return false;
    else
        return true;
    }
}
