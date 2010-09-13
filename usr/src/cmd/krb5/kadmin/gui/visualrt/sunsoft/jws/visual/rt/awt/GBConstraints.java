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
 * @(#)GBConstraints.java	1.12 97/09/03 Doug Stein
 *
 * Copyright (c) 1996, 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 *
 * Permission to use, copy, modify, and distribute this software
 * and its documentation for NON-COMMERCIAL purposes and without
 * fee is hereby granted provided that this copyright notice
 * appears in all copies. Please refer to the file "copyright.html"
 * for further important copyright and licensing information.
 *
 * SUN MAKES NO REPRESENTATIONS OR WARRANTIES ABOUT THE SUITABILITY OF
 * THE SOFTWARE, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED
 * TO THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
 * PARTICULAR PURPOSE, OR NON-INFRINGEMENT. SUN SHALL NOT BE LIABLE FOR
 * ANY DAMAGES SUFFERED BY LICENSEE AS A RESULT OF USING, MODIFYING OR
 * DISTRIBUTING THIS SOFTWARE OR ITS DERIVATIVES.
 */
package sunsoft.jws.visual.rt.awt;

import sunsoft.jws.visual.rt.base.Global;

import java.awt.*;
import java.util.StringTokenizer;
import java.util.NoSuchElementException;

/**
 * GBConstraints is used to specify constraints for components
 * laid out using the GBLayout class.
 *
 * @see java.awt.GBLayout
 * @version 1.12, 06/17/97
 * @author Doug Stein
 */
public class GBConstraints implements Cloneable {
    public static final int RELATIVE = -1;
    public static final int REMAINDER = 0;
    
    public static final int NONE = 0;
    public static final int BOTH = 1;
    public static final int HORIZONTAL = 2;
    public static final int VERTICAL = 3;
    
    public static final int CENTER = 10;
    public static final int NORTH = 11;
    public static final int NORTHEAST = 12;
    public static final int EAST = 13;
    public static final int SOUTHEAST = 14;
    public static final int SOUTH = 15;
    public static final int SOUTHWEST = 16;
    public static final int WEST = 17;
    public static final int NORTHWEST = 18;
    
    public int gridx, gridy, gridwidth, gridheight;
    public double weightx, weighty;
    public int anchor, fill;
    
    // Regular insets and pads will shrink when space gets tight
    public Insets insets;
    public int ipadx, ipady;
    
    // Hard insets and pads never shrink
    public Insets hardinsets;
    public int hardipadx, hardipady;
    
    // Normally a component will not shrink below it minimum size.  Setting
    // shrinkx or shrinky to true indicates that the component may shrink
    // below its minimum size.
    public boolean shrinkx;
    public boolean shrinky;
    
    // The following variables are filled in during layout and
    // can be accessed, but should not be modified:
    public Point location;           // location of the component
    public Dimension size;           // size of the component
    public Dimension minsize;        // minimum size of the component
    
    int tempX, tempY;
    int tempWidth, tempHeight;
    int tinyWidth, tinyHeight;
    
    /**
     * Creates a set of gridbag constraints.
     */
    public GBConstraints() {
        gridx = RELATIVE;
        gridy = RELATIVE;
        gridwidth = 1;
        gridheight = 1;
        
        weightx = 0;
        weighty = 0;
        anchor = CENTER;
        fill = NONE;
        
        insets = new Insets(0, 0, 0, 0);
        ipadx = 0;
        ipady = 0;
        
        hardinsets = new Insets(0, 0, 0, 0);
        hardipadx = 0;
        hardipady = 0;
    }
    
    /**
     * Creates a set of gridbag constraints by parsing the given
     * constraints option string.  Each option has the form key=value.
     * Options are separated by semicolons (;).
     */
    public GBConstraints(String constraints) {
        this();
        parseConstraints(constraints);
    }
    
    public Object clone() {
        GBConstraints c;
        try {
            c = (GBConstraints)super.clone();
        } catch (CloneNotSupportedException e) {
            // this shouldn't happen, since we are Cloneable
            throw new InternalError();
        }
        
        if (c.insets != null)
            c.insets = (Insets)c.insets.clone();
        if (c.hardinsets != null)
            c.hardinsets = (Insets)c.hardinsets.clone();
        
        return c;
    }
    
    private void parseConstraints(String constraints) {
        StringTokenizer st = new StringTokenizer(
				 constraints, /* NOI18N */";", true);
        
        String option_string = null;
        try {
            while (st.hasMoreTokens()) {
                option_string = st.nextToken();
                if (option_string.equals(/* NOI18N */";"))
                    continue;
                
                StringTokenizer op = new StringTokenizer(option_string,
						/* NOI18N */"=", true);
                String option = op.nextToken();
                
                if (option.equals(/* NOI18N */"gridx") ||
		    option.equals(/* NOI18N */"x"))
		    gridx = convertSymbolicValue(getValueToken(op));
                else if (option.equals(/* NOI18N */"gridy") ||
			 option.equals(/* NOI18N */"y"))
		    gridy = convertSymbolicValue(getValueToken(op));
                else if (option.equals(/* NOI18N */"gridwidth") ||
			 option.equals(/* NOI18N */"width"))
		    gridwidth = convertSymbolicValue(getValueToken(
								   op));
                else if (option.equals(/* NOI18N */"gridheight") ||
			 option.equals(/* NOI18N */"height"))
		    gridheight = convertSymbolicValue(getValueToken(op));
                
                else if (option.equals(/* NOI18N */"weightx")) {
                    Double x = new Double(getValueToken(op));
                    weightx = x.doubleValue();
                } else if (option.equals(/* NOI18N */"weighty")) {
                    Double x = new Double(getValueToken(op));
                    weighty = x.doubleValue();
                } else if (option.equals(/* NOI18N */"anchor"))
                    anchor = convertSymbolicValue(getValueToken(op));
                else if (option.equals(/* NOI18N */"fill"))
                    fill = convertSymbolicValue(getValueToken(op));
                
                else if (option.equals(/* NOI18N */"insets.top"))
                    insets.top = convertSymbolicValue(getValueToken(op));
                else if (option.equals(/* NOI18N */"insets.left"))
                    insets.left = convertSymbolicValue(getValueToken(op));
                else if (option.equals(/* NOI18N */"insets.bottom"))
                    insets.bottom = convertSymbolicValue(
							 getValueToken(op));
                else if (option.equals(/* NOI18N */"insets.right"))
                    insets.right = convertSymbolicValue(getValueToken(op));
                
                else if (option.equals(/* NOI18N */"ipadx"))
                    ipadx = convertSymbolicValue(getValueToken(op));
                else if (option.equals(/* NOI18N */"ipady"))
                    ipady = convertSymbolicValue(getValueToken(op));
                
                else if (option.equals(/* NOI18N */"shrinkx")) {
                    Boolean x = new Boolean(getValueToken(op));
                    shrinkx = x.booleanValue();
                } else if (option.equals(/* NOI18N */"shrinky")) {
                    Boolean x = new Boolean(getValueToken(op));
                    shrinky = x.booleanValue();
                }
                
                else if (option.equals(/* NOI18N */"hardinsets.top"))
                    hardinsets.top = convertSymbolicValue(
							  getValueToken(op));
                else if (option.equals(/* NOI18N */"hardinsets.left"))
                    hardinsets.left = convertSymbolicValue(
							   getValueToken(op));
                else if (option.equals(/* NOI18N */"hardinsets.bottom"))
                    hardinsets.bottom = convertSymbolicValue(
							     getValueToken(op));
                else if (option.equals(/* NOI18N */"hardinsets.right"))
                    hardinsets.right = convertSymbolicValue(
							    getValueToken(op));
                
                else if (option.equals(/* NOI18N */"hardipadx"))
                    hardipadx = convertSymbolicValue(
						     getValueToken(op));
                else if (option.equals(/* NOI18N */"hardipady"))
                    hardipady = convertSymbolicValue(
						     getValueToken(op));
                
                else
                    throw new NoSuchElementException();
            }
        }
        catch (Exception e) {
            /* JSTYLED */
	    throw new Error(Global.getMsg("sunsoft.jws.visual.rt.awt.GBConstraints.-ba-r-ba-n-ba-tSyntax__error__i.3") +
			    /* NOI18N */"\t\t" + constraints + /* NOI18N */": "
			    + option_string);
        }
    }
    
    private String getValueToken(StringTokenizer op)
	throws NoSuchElementException
    {
        if (op.hasMoreTokens()) {
            String assign = op.nextToken();
            if (assign.equals(/* NOI18N */"="))
                if (op.hasMoreTokens())
		    return op.nextToken();
        }
        throw new NoSuchElementException();
    }
    
    private int convertSymbolicValue(String value) {
        if (value.equals(/* NOI18N */"relative"))
            return GBConstraints.RELATIVE;
        else if (value.equals(/* NOI18N */"remainder"))
            return GBConstraints.REMAINDER;
        else if (value.equals(/* NOI18N */"none"))
            return GBConstraints.NONE;
        else if (value.equals(/* NOI18N */"both"))
            return GBConstraints.BOTH;
        else if (value.equals(/* NOI18N */"horizontal"))
            return GBConstraints.HORIZONTAL;
        else if (value.equals(/* NOI18N */"vertical"))
            return GBConstraints.VERTICAL;
        else if (value.equals(/* NOI18N */"center"))
            return GBConstraints.CENTER;
        else if (value.equals(/* NOI18N */"north"))
            return GBConstraints.NORTH;
        else if (value.equals(/* NOI18N */"northeast"))
            return GBConstraints.NORTHEAST;
        else if (value.equals(/* NOI18N */"east"))
            return GBConstraints.EAST;
        else if (value.equals(/* NOI18N */"southeast"))
            return GBConstraints.SOUTHEAST;
        else if (value.equals(/* NOI18N */"south"))
            return GBConstraints.SOUTH;
        else if (value.equals(/* NOI18N */"southwest"))
            return GBConstraints.SOUTHWEST;
        else if (value.equals(/* NOI18N */"west"))
            return GBConstraints.WEST;
        else if (value.equals(/* NOI18N */"northwest"))
            return GBConstraints.NORTHWEST;
        
        Integer int_val = new Integer(value);
        return int_val.intValue();
    }
}
