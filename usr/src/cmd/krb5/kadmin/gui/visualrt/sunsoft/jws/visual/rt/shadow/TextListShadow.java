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
 * @(#) TextListShadow.java 1.11 - last change made 08/12/97
 */
        
package sunsoft.jws.visual.rt.shadow;
        
import sunsoft.jws.visual.rt.shadow.java.awt.CanvasShadow;
import sunsoft.jws.visual.rt.awt.TextList;
import sunsoft.jws.visual.rt.awt.StringVector;
import sunsoft.jws.visual.rt.base.Global;
        
import java.util.*;
import java.awt.SystemColor;
import java.awt.*;
        
/*
 * Wraps an AWT widget.  The attributes available for this
 * class are listed below.  In the type column, type names beginning
 * with "sunsoft.jws.visual.rt" have been abbreviated to begin with "rt".
 *
 * <pre>
 *        name            type                      default value
 *    -----------------------------------------------------------------------
 *    allowMultipleSelections java.lang.Boolean false
 *    items           [Ljava.lang.String;       item1, item2
 *    selectedItem    java.lang.String          null
 *    selectedItems   [Ljava.lang.String;       null
 *    visibleRows     java.lang.Integer         10
 *  < /pre>
 *
 * visibleRows: how many rows are visible in the list, changing the
 * number affects the size of the component in the vertical dimension.
 *  < p>
 * Check the super class for additional attributes.
 *
 * @see TextList
 * @see StringVector
 * @version 1.11, 08/12/97
 */
public class TextListShadow extends CanvasShadow {
    public TextListShadow() {
	attributes.add(/* NOI18N */"allowMultipleSelections",
		       /* NOI18N */"java.lang.Boolean",
		       Boolean.FALSE, 0);
	String sa[] = { /* NOI18N */"item1", /* NOI18N */"item2"};
	attributes.add(/* NOI18N */"items",
		       /* NOI18N */"[Ljava.lang.String;", sa, 0);
	attributes.add(/* NOI18N */"selectedItem",
		       /* NOI18N */"java.lang.String", null, HIDDEN);
	attributes.add(/* NOI18N */"selectedItems",
		       /* NOI18N */"[Ljava.lang.String;", null, HIDDEN);
	attributes.add(/* NOI18N */"visibleRows",
		       /* NOI18N */"java.lang.Integer",
		       new Integer(10), 0);
                
	// This is a work around for JDK color bug.
	// The defaults are not correctly set
	if (Global.isWindows())  {
	    attributes.add(/* NOI18N */"background",
			   /* NOI18N */"java.awt.Color",
			   SystemColor.window, DONTFETCH);
	}
	if (Global.isMotif())  {
	    attributes.add(/* NOI18N */"background",
			   /* NOI18N */"java.awt.Color",
			   SystemColor.text, DONTFETCH);
	    attributes.add(/* NOI18N */"foreground",
			   /* NOI18N */"java.awt.Color",
			   SystemColor.textText, DONTFETCH);
	}
    }
            
    protected Object getOnBody(String key) {
	TextList list = (TextList)body;
                
	if (key.equals(/* NOI18N */"allowMultipleSelections")) {
	    return new Boolean(list.allowsMultipleSelections());
	} else if (key.equals(/* NOI18N */"items")) {
	    return getFromTable(/* NOI18N */"items");
	} else if (key.equals(/* NOI18N */"visibleRows")) {
	    return new Integer(list.getMinimumRows());
	} else if (key.equals(/* NOI18N */"selectedItem")) {
	    return list.getSelectedItem();
	} else if (key.equals(/* NOI18N */"selectedItems")) {
	    return list.getSelectedItems();
	} else
	    return (super.getOnBody(key));
    }
            
    protected void setOnBody(String key, Object value) {
	TextList list = (TextList)body;
                
	if (key.equals(/* NOI18N */"allowMultipleSelections")) {
	    list.setMultipleSelections(
		((Boolean)value).booleanValue());
	} else if (key.equals(/* NOI18N */"items")) {
	    String names[] = (String [])value;
	    StringVector items = list.items();
	    items.removeAllElements();
                    
	    if (names != null) {
		for (int i = 0; i < names.length; i++)
		    items.addElement(names[i]);
	    }
                    
	    list.updateView();
	} else if (key.equals(/* NOI18N */"visibleRows")) {
	    list.setMinimumRows(((Integer)value).intValue());
	} else if (key.equals(/* NOI18N */"selectedItem")) {
	    int index = -1;
	    if (value != null)
		index = list.items().indexOf((String)value);
	    list.select(index);
	} else if (key.equals(/* NOI18N */"selectedItems")) {
	    String items[] = (String[])value;
	    if (list.allowsMultipleSelections()) {
		list.deselectAll();
		if (items != null) {
		    for (int i = 0; i < items.length; i++)
			list.select(items[i]);
		}
	    } else {
		if (items != null && items.length != 0)
		    list.select(items[0]);
		else
		    list.select(null);
	    }
	} else {
	    super.setOnBody(key, value);
	}
    }
            
    public void createBody() {
	body = new TextList();
    }
}
