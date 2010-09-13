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
 * Copyright (c) 2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

/*
 *        Copyright (C) 1996  Active Software, Inc.
 *                  All rights reserved.
 *
 * @(#) GBConstraintsConverter.java 1.21 - last change made 07/25/97
 */

package sunsoft.jws.visual.rt.type;

import sunsoft.jws.visual.rt.base.Global;
import sunsoft.jws.visual.rt.base.Shadow;
import sunsoft.jws.visual.rt.awt.GBConstraints;
import java.util.Hashtable;

/**
 * Converts instances of GBConstraints to strings and back again.
 *
 * @version 1.21, 07/25/97
 */
public class GBConstraintsConverter extends Converter {
    
    private static final GBConstraints constraintsDefault =
	new GBConstraints();
    
    private String constantToString(int c) {
        if (c == GBConstraints.RELATIVE)
            return (/* NOI18N */"relative");
        else if (c == GBConstraints.REMAINDER)
            return (/* NOI18N */"remainder");
        else if (c == GBConstraints.NONE)
            return (/* NOI18N */"none");
        else if (c == GBConstraints.BOTH)
            return (/* NOI18N */"both");
        else if (c == GBConstraints.HORIZONTAL)
            return (/* NOI18N */"horizontal");
        else if (c == GBConstraints.VERTICAL)
            return (/* NOI18N */"vertical");
        else if (c == GBConstraints.CENTER)
            return (/* NOI18N */"center");
        else if (c == GBConstraints.NORTH)
            return (/* NOI18N */"north");
        else if (c == GBConstraints.NORTHEAST)
            return (/* NOI18N */"northeast");
        else if (c == GBConstraints.EAST)
            return (/* NOI18N */"east");
        else if (c == GBConstraints.SOUTHEAST)
            return (/* NOI18N */"southeast");
        else if (c == GBConstraints.SOUTH)
            return (/* NOI18N */"south");
        else if (c == GBConstraints.SOUTHWEST)
            return (/* NOI18N */"southwest");
        else if (c == GBConstraints.WEST)
            return (/* NOI18N */"west");
        else if (c == GBConstraints.NORTHWEST)
            return (/* NOI18N */"northwest");
        else
	    /* BEGIN JSTYLED */
	    throw new Error(Global.fmtMsg(
					  "sunsoft.jws.visual.rt.type.GBConstraintsConverter.FMT.29",
					  Global.getMsg("sunsoft.jws.visual.rt.type.GBConstraintsConverter.unknown__constant"),
					  new Integer(c)));
	/* END JSTYLED */
    }
    
    private int stringToConstant(String s) {
        if (s.equals(/* NOI18N */"relative"))
            return GBConstraints.RELATIVE;
        else if (s.equals(/* NOI18N */"remainder"))
            return GBConstraints.REMAINDER;
        else if (s.equals(/* NOI18N */"none"))
            return GBConstraints.NONE;
        else if (s.equals(/* NOI18N */"both"))
            return GBConstraints.BOTH;
        else if (s.equals(/* NOI18N */"horizontal"))
            return GBConstraints.HORIZONTAL;
        else if (s.equals(/* NOI18N */"vertical"))
            return GBConstraints.VERTICAL;
        else if (s.equals(/* NOI18N */"center"))
            return GBConstraints.CENTER;
        else if (s.equals(/* NOI18N */"north"))
            return GBConstraints.NORTH;
        else if (s.equals(/* NOI18N */"northeast"))
            return GBConstraints.NORTHEAST;
        else if (s.equals(/* NOI18N */"east"))
            return GBConstraints.EAST;
        else if (s.equals(/* NOI18N */"southeast"))
            return GBConstraints.SOUTHEAST;
        else if (s.equals(/* NOI18N */"south"))
            return GBConstraints.SOUTH;
        else if (s.equals(/* NOI18N */"southwest"))
            return GBConstraints.SOUTHWEST;
        else if (s.equals(/* NOI18N */"west"))
            return GBConstraints.WEST;
        else if (s.equals(/* NOI18N */"northwest"))
            return GBConstraints.NORTHWEST;
        else
	    /* BEGIN JSTYLED */
	    throw new Error(Global.fmtMsg(
					  "sunsoft.jws.visual.rt.type.GBConstraintsConverter.FMT.29",
					  Global.getMsg("sunsoft.jws.visual.rt.type.GBConstraintsConverter.unknown__constant"),
					  s));
	/* END JSTYLED */
    }
    
    /**
     * Converts an instance of GBConstraints to a string representation.
     */
    public String convertToString(Object obj) {
        if (obj != null) {
            GBConstraints c = (GBConstraints) obj;
            String retval = /* NOI18N */"";
            
            if (c.gridx != constraintsDefault.gridx) {
                retval = retval + /* NOI18N */"x=" + c.gridx
		    + /* NOI18N */";";
            }
            if (c.gridy != constraintsDefault.gridy) {
                retval = retval + /* NOI18N */"y=" + c.gridy
		    + /* NOI18N */";";
            }
            if (c.gridwidth != constraintsDefault.gridwidth) {
                retval = retval + /* NOI18N */"width=" + c.gridwidth
		    + /* NOI18N */";";
            }
            if (c.gridheight != constraintsDefault.gridheight) {
                retval = retval + /* NOI18N */"height="
		    + c.gridheight + /* NOI18N */";";
            }
            if (c.weightx != constraintsDefault.weightx) {
                retval = retval + /* NOI18N */"weightx=" + c.weightx
		    + /* NOI18N */";";
            }
            if (c.weighty != constraintsDefault.weighty) {
                retval = retval + /* NOI18N */"weighty=" + c.weighty
		    + /* NOI18N */";";
            }
            if (c.fill != constraintsDefault.fill) {
                retval = retval + /* NOI18N */"fill="
		    + constantToString(c.fill) + /* NOI18N */";";
            }
            if (c.ipadx != constraintsDefault.ipadx) {
                retval = /* NOI18N */(retval + "ipadx="
				      + c.ipadx + ";");
            }
            if (c.ipady != constraintsDefault.ipady) {
                retval = /* NOI18N */(retval + "ipady="
				      + c.ipady + ";");
            }
            if (c.shrinkx != constraintsDefault.shrinkx) {
                retval = /* NOI18N */(retval + "shrinkx="
				      + c.shrinkx + ";");
            }
            if (c.shrinky != constraintsDefault.shrinky) {
                retval = /* NOI18N */(retval + "shrinky="
				      + c.shrinky + ";");
            }
            
            if (retval.length() > 0 &&
		retval.charAt(retval.length() - 1) == /* NOI18N */ ';')
		return (retval.substring(0, retval.length() - 1));
            else
                return (retval);
        } else {
            return (null);
        }
    }
    
    /**
     * Returns a code for creating a GBConstraints instance 
     * like the one given.
     *
     * @param obj an instance of GBConstraints
     */
    public String convertToCode(Object obj) {
        return (/* NOI18N */("new GBConstraints(\""
			     + convertToString(obj) + "\")"));
    }
    
    private int getIntegerFromTable(Hashtable table, String key) {
        String value = (String) table.get(key);
        if (value != null)
            return (Integer.valueOf(value).intValue());
        else
            return (0);
    }
    
    private boolean getBooleanFromTable(Hashtable table, String key) {
        String value = (String) table.get(key);
        if (value != null)
            return (Boolean.valueOf(value).booleanValue());
        else
            return (false);
    }
    
    private double getDoubleFromTable(Hashtable table, String key) {
        String value = (String) table.get(key);
        if (value != null)
            return (Double.valueOf(value).doubleValue());
        else
            return (0.0);
    }
    
    private int getConstantFromTable(Hashtable table, String key) {
        String value = (String) table.get(key);
        if (value != null)
            return (stringToConstant(value));
        else
            return (0);
    }
    
    /**
     * Converts a string into a new instance of GBConstraints.
     *
     * @exception Error when there is a problem with the string
     */
    public Object convertFromString(String s) {
        if (s != null && s.length() > 0) {
            SubFieldTokenizer sft = new SubFieldTokenizer(s);
            Hashtable table = sft.getHashtable();
            GBConstraints retval = new GBConstraints();
            
            if (table.containsKey(/* NOI18N */"x")) {
                retval.gridx = getIntegerFromTable(table, /* NOI18N */"x");
            }
            if (table.containsKey(/* NOI18N */"y")) {
                retval.gridy = getIntegerFromTable(table, /* NOI18N */"y");
            }
            if (table.containsKey(/* NOI18N */"width")) {
                retval.gridwidth = getIntegerFromTable(
					       table, /* NOI18N */"width");
            }
            if (table.containsKey(/* NOI18N */"height")) {
                retval.gridheight = getIntegerFromTable(
						table, /* NOI18N */"height");
            }
            if (table.containsKey(/* NOI18N */"weightx")) {
                retval.weightx = getDoubleFromTable(
					    table, /* NOI18N */"weightx");
            }
            if (table.containsKey(/* NOI18N */"weighty")) {
                retval.weighty = getDoubleFromTable(
					    table, /* NOI18N */"weighty");
            }
            if (table.containsKey(/* NOI18N */"fill")) {
                retval.fill = getConstantFromTable(
						   table, /* NOI18N */"fill");
            }
            if (table.containsKey(/* NOI18N */"ipadx")) {
                retval.ipadx = getIntegerFromTable(
						   table, /* NOI18N */"ipadx");
            }
            if (table.containsKey(/* NOI18N */"ipady")) {
                retval.ipady = getIntegerFromTable(
						   table, /* NOI18N */"ipady");
            }
            if (table.containsKey(/* NOI18N */"shrinkx")) {
                retval.shrinkx = getBooleanFromTable(
					     table, /* NOI18N */"shrinkx");
            }
            if (table.containsKey(/* NOI18N */"shrinky")) {
                retval.shrinky = getBooleanFromTable(
					     table, /* NOI18N */"shrinky");
            }
            
            return (retval);
        } else {
            return (null);
        }
    }
}
