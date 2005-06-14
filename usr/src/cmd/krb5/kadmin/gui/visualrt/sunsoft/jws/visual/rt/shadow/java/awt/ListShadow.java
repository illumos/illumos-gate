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
 * @(#) @(#) ListShadow.java 1.32 - last change made 08/12/97 
 */

package sunsoft.jws.visual.rt.shadow.java.awt;

import sunsoft.jws.visual.rt.awt.GBConstraints;
import java.awt.List;
import java.awt.SystemColor;
import sunsoft.jws.visual.rt.base.Global;

/**
 * Wraps an AWT widget.  The attributes available for this
 * class are listed below.  In the type column, type names beginning
 * with "sunsoft.jws.visual.rt" have been abbreviated to begin with "rt".
 *
 * <pre>
name            type                      default value
-----------------------------------------------------------------------
allowMultipleSelections java.lang.Boolean false
items           [Ljava.lang.String;       item1, item2
selectedItem    java.lang.String          null
selectedItems   [Ljava.lang.String;       null
visibleRows     java.lang.Integer         4
*  < /pre>
*
* selectedItem: is the item(amoung the the strings in the "items"
* attribute) that is currently showing in the list.  This attribute is
* not available in the attribute editor, but is instead expected to be
* used programmatically to change or check the setting.
*  < p>
* Check the super class for additional attributes.
*
* @see List
* @version 	1.32, 08/12/97
*/
public class ListShadow extends ComponentShadow {
    public ListShadow() {
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
		       /* NOI18N */"java.lang.Integer", new Integer(4),
		       CONSTRUCTOR);
        
        GBConstraints c = (GBConstraints)get(/* NOI18N */"GBConstraints");
        c.fill = GBConstraints.BOTH;
        attributes.add(/* NOI18N */"GBConstraints",
		       /* NOI18N */"sunsoft.jws.visual.rt.awt.GBConstraints",
		    c);
        
        // This is a work around for JDK color bug. The defaults are
        // not correctly set
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
        if (key.equals(/* NOI18N */"visibleRows"))
	    return (new Integer(((List) body).getRows()));
        else if (key.equals(/* NOI18N */"allowMultipleSelections"))
            return (new Boolean(((List) body).allowsMultipleSelections()));
        else if (key.equals(/* NOI18N */"items")) {
            if (((List) body).countItems() == 0)
		return null;
            else {
                int index;
                String[] listContents = new String[((List)body).countItems()];
                for (index = 0; index < listContents.length; index++)
                    listContents[index] = ((List)body).getItem(index);
                return listContents;
            }
        } else if (key.equals(/* NOI18N */"selectedItem")) {
            List list = (List)body;
            return list.getSelectedItem();
        } else if (key.equals(/* NOI18N */"selectedItems")) {
            return ((List)body).getSelectedItems();
        }
        else
            return (super.getOnBody(key));
    }
    
    /**
     * This efficiently makes changes to the List body when the user changes
     * items in it.  it updates the List body from the new data.
     */
    private void equalizeLists(Object value) {
        String[] newList = ((String[]) (value));
        
        int newListIndex = 0, oldListIndex = 0;
        int dummyIndex;
        
        // If the user deleted all of the entries, the newList would be null
        if (newList == null) {
            if (((List) body).countItems() > 0) {
                ((List) body).delItems(0, ((List)body).countItems()-1);
            }
        } else {
            while (newListIndex < newList.length &&
		   oldListIndex < ((List) body).countItems())
		{
		    String curOldItem = ((List) (body)).getItem(oldListIndex);
                
		    if (newList[newListIndex].equals(curOldItem)) {
			newListIndex++;
			oldListIndex++;
		    } else {
			for (dummyIndex = newListIndex;
			     dummyIndex < newList.length; dummyIndex++) {
			    if (curOldItem.equals(newList[dummyIndex])) {
				((List) body).delItem(oldListIndex);
				break;
			    }
			}
			((List) body).addItem(newList[newListIndex],
					    oldListIndex);
			newListIndex++;
			oldListIndex++;
		    }
		}
            
            if (oldListIndex < ((List) body).countItems()) {
                ((List) body).delItems(oldListIndex,
				       ((List)body).countItems()-1);
            }
            
            while (newListIndex < newList.length) {
                ((List) body).addItem(newList[newListIndex]);
                newListIndex++;
            }
        }
    }
    
    protected void setOnBody(String key, Object value) {
        if (key.equals(/* NOI18N */"allowMultipleSelections"))
		/* JSTYLED */
	    ((List) body).setMultipleSelections(((Boolean)value).booleanValue());
        else if (key.equals(/* NOI18N */"items"))
            equalizeLists(value);
        else if (key.equals(/* NOI18N */"visibleRows"))
            return;	// this must be set in constructor
        else if (key.equals(/* NOI18N */"selectedItem")) {
            List list = (List)body;
            if (list.allowsMultipleSelections())
		unselectAll(list);
            select((List)body, (String)value);
        } else if (key.equals(/* NOI18N */"selectedItems")) {
            List list = (List)body;
            String items[] = (String[])value;
            if (list.allowsMultipleSelections()) {
                unselectAll(list);
                if (items != null) {
                    for (int i = 0; i < items.length; i++)
                        select(list, items[i]);
                }
            } else {
                if (items != null && items.length != 0)
                    select(list, items[0]);
                else
                    select(list, null);
            }
        }
        else
            super.setOnBody(key, value);
    }
    
    private void select(List list, String s) {
        if (s == null) {
            int index = list.getSelectedIndex();
            if (index != -1)
                list.deselect(index);
            return;
        }
        
        int num = list.countItems();
        for (int i = 0; i < num; i++) {
            if (s.equals(list.getItem(i))) {
                list.select(i);
                break;
            }
        }
    }
    
    private void unselectAll(List list) {
        int indexes[] = list.getSelectedIndexes();
        if (indexes != null) {
            for (int i = 0; i < indexes.length; i++)
                list.deselect(indexes[i]);
        }
    }
    
    public void createBody() {
	    /* JSTYLED */
        body = new List(((Integer) getFromTable(/* NOI18N */"visibleRows")).intValue(),
			/* JSTYLED */
			((Boolean) getFromTable(/* NOI18N */"allowMultipleSelections")).booleanValue());
    }
}
