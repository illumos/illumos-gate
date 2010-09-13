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
 * @(#) ChoiceShadow.java 1.13 - last change made 05/02/97
 */

package sunsoft.jws.visual.rt.shadow.java.awt;

import sunsoft.jws.visual.rt.base.Global;
import java.awt.*;

/**
 * Wraps an AWT widget.  The attributes available for this
 * class are listed below.  In the type column, type names beginning
 * with "sunsoft.jws.visual.rt" have been abbreviated to begin with "rt".
 *
 * <pre>
name            type                      default value
-----------------------------------------------------------------------
items           [Ljava.lang.String;       item1, item2
selectedItem    java.lang.String          ""
*  < /pre>
*
* selectedItem: is the item(amoung the the strings in the "items"
* attribute) that is currently showing in the choice field.  This
* attribute is not available in the attribute editor, but is instead
* expected to be used programmatically to change the setting on the
* choice as the result of a callback or some such.
*  < p>
* Check the super class for additional attributes.
*
* @see Choice
* @version 	1.13, 05/02/97
*/
public class ChoiceShadow extends ComponentShadow {
    public ChoiceShadow() {
        String items[] = { /* NOI18N */"item1", /* NOI18N */"item2"};
        // changed for bugid 4006105 -kp
        //   attributes.add("items", "[Ljava.lang.String;", items, CONSTRUCTOR);
        attributes.add(/* NOI18N */"items",
		       /* NOI18N */"[Ljava.lang.String;", items, 0);
        attributes.add(/* NOI18N */"selectedItem",
		       /* NOI18N */"java.lang.String", /* NOI18N */"", HIDDEN);
        
        // On WindowsNT, choice menus look bad because they have extra
        // space on the bottom.  Setting the insets here tries to adjust
        // for this problem.
        if (Global.isWindowsNT()) {
            attributes.add(/* NOI18N */"insets",
			   /* NOI18N */"java.awt.Insets",
			new Insets(2, 0, 0, 0));
        } else if (Global.isMotif()) {
            // Motif choice menus hang out over their bottom and right edges.
            // The problem is worse on SGI than Sun.
            if (Global.isIrix())
		attributes.add(/* NOI18N */"insets",
			       /* NOI18N */"java.awt.Insets",
			    new Insets(0, 0, 4, 12));
            else
                attributes.add(/* NOI18N */"insets",
			       /* NOI18N */"java.awt.Insets",
			       new Insets(0, 0, 2, 6));
        }
    }
    
    protected Object getOnBody(String key) {
        if (key.equals(/* NOI18N */"items")) {
            Choice choice = (Choice)body;
            int count = choice.countItems();
            String value[] = new String[count];
            
            for (int i = 0; i < count; i++)
                value[i] = choice.getItem(i);
            return value;
        } else if (key.equals(/* NOI18N */"selectedItem")) {
            Choice choice = (Choice)body;
            return choice.getSelectedItem();
        }
        else
            return (super.getOnBody(key));
    }
    
    /**
     * This makes changes to the Choice body when the user changes
     * items in it.  it updates the Choice body from the new data.
     */
    private void equalizeChoices(Object value) {
        
        String s[] = (String[])value;
        Choice choice = (Choice) body;
        int count = choice.countItems();
        // remove all the items and add the new list...
        if (count  > 0)
            choice.removeAll();
        // Motif workaround: Need to add at least one item to the choice menu
        // or else Motif will cause a core dump.
	if (s == null || s.length == 0)
            choice.addItem(/* NOI18N */"     ");
        else {
            for (int i = 0; i < s.length; i++)
                if (s[i] != null)
		    choice.addItem(s[i]);
        }
    }
    
    protected void setOnBody(String key, Object value) {
        if (key.equals(/* NOI18N */"items")) {
            
            // added -kp for bugid 4006105
            equalizeChoices(value);
            // end of addition -kp
        } else if (key.equals(/* NOI18N */"selectedItem")) {
            String str = (String)value;
            if (str == null)
                str = /* NOI18N */"";
            
            Choice choice = (Choice)body;
            boolean selected = false;
            int count = choice.countItems();
            
            for (int i = 0; i < count; i++) {
                if (choice.getItem(i).equals(str)) {
                    selected = true;
                    choice.select(i);
                    break;
                }
            }
            
            if (!selected && count != 0)
                choice.select(0);
        } else
            super.setOnBody(key, value);
    }
    
    public void createBody() {
        Choice choice = new Choice();
        body = choice;
    }
}
