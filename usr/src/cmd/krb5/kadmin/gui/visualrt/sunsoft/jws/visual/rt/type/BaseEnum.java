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
 * @(#) BaseEnum.java 1.17 - last change made 07/25/97
 */

package sunsoft.jws.visual.rt.type;

import sunsoft.jws.visual.rt.base.Global;

import java.util.Enumeration;

/* BEGIN JSTYLED */
/**
 * Base class for types that implement enumerations 
 * (in the C style) where
 * an integer signifies an important answer to a 
 * multiple-choice question.
 * Sub-classers are supposed to supply the list of strings 
 * that describe the
 * enumerations values available (and their corresponding integer values)
 * in their static initializers.  Sub-classes should set up their own
 * instance of the BaseEnumHelper class to hold their 
 * enumeration definition.
 * <p>
 * When you sub-class off of BaseEnum, Visual Java will automatically
 * recognize your type as an enumeration, and offer a choice menu in
 * the attribute editor of Visual Java for selecting the value of an
 * attribute of that type.
 * <p>
 * The AlignmentEnum, shown below, is used for setting whether the
 * text in a Label will appear on the left, center, or right.
 * <p>
 * To use the example below to create a new enumerated type, copy
 * everything and then modify the imports and static constructor to use
 * the constants and names for the choices you'd like to offer in your
 * enumeration.
 * <p>
 * The addConverter call will register your type with Visual Java's
 * type conversion interface and make it understood that this type is
 * an enumeration.  Change the
 * "sunsoft.jws.visual.rt.type.AlignmentEnum" argument to reflect the
 * package name and class of your new enumerated type.
 *
 * <pre>
 * package sunsoft.jws.visual.rt.type;
 * 
 * import sunsoft.jws.visual.rt.type.BaseEnum;
 * import sunsoft.jws.visual.rt.type.BaseEnumHelper;
 * import sunsoft.jws.visual.rt.type.Converter;
 * import java.awt.Label;
 *
 * public class AlignmentEnum extends BaseEnum {
 *   private static BaseEnumHelper helper = new BaseEnumHelper();
 *
 *   static {
 *     helper.add(Label.LEFT, "left");
 *     helper.add(Label.CENTER, "center");
 *     helper.add(Label.RIGHT, "right");
 *     helper.setDefaultChoice(Label.LEFT);
 *     Converter.addConverter("sunsoft.jws.visual.rt.type.AlignmentEnum",
 *          "sunsoft.jws.visual.rt.type.BaseEnumConverter");
 *   }
 *
 *   public AlignmentEnum() {
 *     super();
 *   }
 *
 *   public AlignmentEnum(int choice) {
 *     super(choice);
 *   }
 *
 *   public AlignmentEnum(String choice) {
 *     super(choice);
 *   }
 * 
 *   protected BaseEnumHelper getHelper() {
 *     return(helper);
 *   }
 * }
 * </pre>
 *
 * @see BaseEnumHelper
 * @see AlignmentEnum
 * @see java.awt.Label
 * @version 1.17, 07/25/97
*/

/* END JSTYLED */
public abstract class BaseEnum implements Cloneable {
    /**
     * The currently selected value from the enum.
     */
    protected Integer currentChoice;
    
    /**
     * Constructor, sets the choice to the default.
     */
    protected BaseEnum() {
        set(getHelper().getDefaultChoice());
    }
    
    /**
     * Constructor to use when integer value is available.
     *
     * @param choice enumerated value
     */
    protected BaseEnum(int choice) {
        set(choice);
    }
    
    /**
     * Constructor to use when string of choice is available.
     *
     * @param choice enumerated value
     */
    protected BaseEnum(String choice) {
        set(choice);
    }
    
    /**
     * Gets the helper class that stores the enum definition.
     *
     * Each sub-classer should override this so that a different
     * class-wide instance of BaseEnumHelper is returned.  If there
     * weren't a mechanism like this, then all sub-classers would be
     * sharing a single helper, and that would be bad.
     *
     * @return a helper use by all enumeration instances of 
     * a single class
    */
    protected abstract BaseEnumHelper getHelper();
    
    /**
     * Sets the enumeration to the given integer value.  
     * Checks validity
     * of the choice.
     *
     * @param choice enumerated value
     * @exception Error when an invalid choice is given
     */
    public void set(int choice) {
        if (getHelper().isValid(choice))
            currentChoice = new Integer(choice);
        else
            throw new ParseException(Global.fmtMsg(
			   "sunsoft.jws.visual.rt.type.BaseEnum.FMT.30",
	   Global.getMsg(
		 "sunsoft.jws.visual.rt.type.BaseEnum.invalid__int__choice__"),
						   new Integer(choice),
						   /* BEGIN JSTYLED */
						   Global.getMsg("sunsoft.jws.visual.rt.type.BaseEnum.__given__to__Enum__class.14")));
	/* END JSTYLED */
    }
    
    /**
     * Sets the enumeration to the given string value.  Checks validity
     * of the choice.
     *
     * @param choice string version of the enumerated value
     * @exception Error when an invalid choice is given
     */
    public void set(String choice) {
        if (getHelper().isValid(choice))
            currentChoice = getHelper().getInteger(choice);
        else
            throw new ParseException(Global.fmtMsg(
			   "sunsoft.jws.visual.rt.type.BaseEnum.FMT.30",
						   /* BEGIN JSTYLED */
						   Global.getMsg("sunsoft.jws.visual.rt.type.BaseEnum.invalid__string__choic.15"),
						   choice,
						   Global.getMsg("sunsoft.jws.visual.rt.type.BaseEnum.__given__to__Enum__class.16")));
	/* END JSTYLED */
    }
    
    /**
     * Returns the int value of the current selection 
     * from the enumeration.
    */
    public int intValue() {
        return (currentChoice.intValue());
    }
    
    /**
     * Returns the String description of the current selection from the
     * enumeration.
     */
    public String toString() {
        return (getHelper().getString(currentChoice));
    }
    
    /**
     * Returns a java.util.Enumeration of the String descriptions
     * available in this enum.
     */
    public Enumeration elements() {
        return (getHelper().elements());
    }
    
    /**
     * Returns an array containing all of the String descriptions
     * available in this enum.
     */
    public String[] descriptions() {
        return (getHelper().descriptions());
    }
    
    /**
     * Returns a copy of this enumeration instance.
     */
    public Object clone() {
        try {
            return super.clone();
        } catch (CloneNotSupportedException e) {
            // this shouldn't happen, since we are Cloneable
            throw new InternalError();
        }
    }
    
    /**
     * Returns true if this enumeration instance and the one given have
     * the same selection made.
     */
    public boolean equals(Object obj) {
        if (obj instanceof BaseEnum) {
            if (getClass() == obj.getClass()) {
                Integer otherChoice = ((BaseEnum)obj).currentChoice;
                if (currentChoice != null)
                    return (currentChoice.equals(otherChoice));
                else
                    return (otherChoice == null);
            }
        }
        return false;
    }
}
