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
 * @(#) TextList.java 1.15 - last change made 11/26/96
 */

package sunsoft.jws.visual.rt.awt;

import java.awt.*;
import java.util.Vector;

/**
 * An alternate to the regular AWT List widget.
 *
 * @version 	1.15, 11/26/96
 */
public class TextList extends ScrollPanel {
    TextView view;
    private StringVector items;
    
    public TextList() {
        items = new StringVector();
        view = new TextView();
        view.items(items.vector);
        
        add(view);
    }
    
    //
    // Methods that are forwarded to the view.
    //
    public void enable(boolean value) {
        super.enable(value);
        view.enable(value);
    }
    
    public StringVector items() {
        return items;
    }
    
    public void updateView() {
        view.updateView();
        updateWindow();
    }
    
    public void setMinimumRows(int num) {
        view.setMinimumRows(num);
    }
    
    public int getMinimumRows() {
        return view.getMinimumRows();
    }
    
    public void setMinimumColumns(int num) {
        view.setMinimumColumns(num);
    }
    
    public int getMinimumColumns() {
        return view.getMinimumColumns();
    }
    
    public int getRows() {
        return view.getRows();
    }
    
    public void select(int index) {
        view.select(index);
    }
    
    public void select(String item) {
        view.select(item);
    }
    
    public void deselect(int index) {
        view.deselect(index);
    }
    
    public void deselectAll() {
        view.deselectAll();
    }
    
    public void setMultipleSelections(boolean v) {
        view.setMultipleSelections(v);
    }
    
    public boolean allowsMultipleSelections() {
        return view.allowsMultipleSelections();
    }
    
    public int getSelectedIndex() {
        return view.getSelectedIndex();
    }
    
    public int[] getSelectedIndexes() {
        return view.getSelectedIndexes();
    }
    
    public String getSelectedItem() {
        return (String)view.getSelectedItem();
    }
    
    public String[] getSelectedItems() {
        Object items[] = view.getSelectedItems();
        String str[] = new String[items.length];
        for (int i = 0; i < items.length; i++)
            str[i] = (String)items[i];
        return str;
    }
    
    public void addItem(String item) {
        items.addElement(item);
        updateView();
    }
    
    public void addItem(String item, int index) {
        if (index == -1) {
            if (items.size() == 0) {
                items.addElement(item);
            } else {
                items.insertElementAt(item, 0);
            }
        } else if (index < items.size()) {
            items.insertElementAt(item, index);
        } else {
            items.addElement(item);
        }
        updateView();
    }
    
    public void replaceItem(String newValue, int index) {
        if (index < items.size()) {
            items.setElementAt(newValue, index);
            updateView();
        }
    }
    
    public int countItems() {
        return items.size();
    }
    
    public void clear() {
        items.removeAllElements();
        updateView();
    }
    
    public void delItem(int position) {
        if (position < items.size()) {
            items.removeElementAt(position);
            updateView();
        }
    }
    
    public void delItems(int start, int end) {
        for (int index = start; index <= end; index++) {
            if (index < items.size()) {
                items.removeElementAt(start);
            }
        }
        updateView();
    }
    
    public String getItem(int index) {
        if (index < items.size()) {
            return (items.elementAt(index));
        } else return null;
    }
    
    public void makeVisible(int index) {
        updateView();
        super.makeVisible(index);
    }
    
    public int lineHeight() {
        return view.lineHeight();
    }
    
    public void menuMode(CLChoice choice) {
        view.menuMode(choice);
    }
}
