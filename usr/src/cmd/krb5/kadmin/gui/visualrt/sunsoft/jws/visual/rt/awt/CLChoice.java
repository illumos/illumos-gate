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

/**
 * Copyright 1996 Active Software Inc.
 *
 * @version @(#)CLChoice.java 1.13 97/06/18
 */

package sunsoft.jws.visual.rt.awt;

import sunsoft.jws.visual.rt.base.Global;
import java.awt.*;
import java.util.*;

public class CLChoice extends CLIconLabel
{
    public static final int APPLY = EditLine.APPLY;
    
    private Vector items = new Vector();
    private int selectedIndex = -1;
    private int itemsVisible = 12;
    private boolean allowSuffix;
    
    private boolean dragging;
    private int dragX, dragY;
    private Window menuWindow;
    private int menuWindowX, menuWindowY;
    private TextList menu;
    private boolean forwarding;
    
    public CLChoice() {
        this(null, -1, null);
    }
    
    public CLChoice(String[] items) {
        this(items, 0, null);
    }
    
    public CLChoice(String[] items, int selectedIndex) {
        this(items, selectedIndex, null);
    }
    
    public CLChoice(String[] items, String selectedItem) {
        this(items, selectedItem, null);
    }
    
    public CLChoice(String[] items, int selectedIndex, Image icon) {
        super(null, icon);
        
        if (items == null) {
            super.setText(/* NOI18N */"");
            this.selectedIndex = 0;
        } else {
            setItems(items);
            select(selectedIndex);
        }
    }
    
    public CLChoice(String[] items, String selectedItem, Image icon) {
        super(null, icon);
        
        if (items == null) {
            super.setText(/* NOI18N */"");
            this.selectedIndex = 0;
        } else {
            setItems(items);
            select(selectedItem);
        }
    }
    
    public CLChoice(String[] items, String selectedItem, Image icon,
		    boolean allowSuffix) {
        super(null, icon);
        
        this.allowSuffix = allowSuffix;
        
        if (items == null) {
            super.setText(/* NOI18N */"");
            this.selectedIndex = 0;
        } else {
            setItems(items);
            select(selectedItem);
        }
    }
    
    public void setItemsVisible(int num) {
        if (num <= 0)
            num = 1;
        itemsVisible = num;
    }
    
    public int getItemsVisible() {
        return itemsVisible;
    }
    
    public void addItem(String item) {
        items.addElement(item);
        if (menu != null)
            menu.addItem(item);
    }
    
    public int countItems() {
        return items.size();
    }
    
    public String[] getItems() {
        int length = items.size();
        String[] s = new String[length];
        for (int i = 0; i < length; i++)
            s[i] = (String)items.elementAt(i);
        return s;
    }
    
    public void setItems(String[] items) {
        this.items.removeAllElements();
        if (menu != null)
            menu.clear();
        for (int i = 0; i < items.length; i++)
            addItem(items[i]);
    }
    
    public String getItem(int index) {
        return (String)items.elementAt(index);
    }
    
    public void removeItem(String item) {
        removeItem(items.indexOf(item));
    }
    
    public void removeItem(int index) {
        if (index < 0 || index >= items.size())
            return;
        
        items.removeElementAt(index);
        if (menu != null) {
            menu.items().removeElementAt(index);
            menu.updateView();
        }
        
        int selectedIndex = getSelectedIndex();
        if (selectedIndex != -1) {
            if (selectedIndex == index)
                select(0);
            else if (selectedIndex > index)
                select(selectedIndex-1);
        }
    }
    
    public int getSelectedIndex() {
        if (items.size() == 0)
            return -1;
        else
            return selectedIndex;
    }
    
    public String getSelectedItem() {
        if (items.size() == 0)
            return null;
        else
            return (String)items.elementAt(selectedIndex);
    }
    
    public void select(int index) {
        select(index, null);
    }
    
    public void select(String item) {
        if (items == null)
            return;
        
        int index = -1;
        String selItem = null;
        
        if (item != null) {
            if (allowSuffix) {
                int length = items.size();
                for (int i = 0; i < length; i++) {
                    String thisItem = (String)items.elementAt(i);
                    if (item.startsWith(thisItem)) {
                        selItem = item;
                        index = i;
                        break;
                    }
                }
            } else {
                index = items.indexOf(item);
            }
        }
        
        select(index, selItem);
    }
    
    private void select(int index, String selItem) {
        if (index >= items.size())
            index = items.size()-1;
        if (index < 0)
            index = 0;
        
        if (index != selectedIndex) {
            selectedIndex = index;
            if (items.size() == 0) {
                super.setText(/* NOI18N */"");
            } else {
                if (selItem == null)
                    selItem = (String)items.elementAt(index);
                super.setText(selItem);
            }
        }
    }
    
    public void setText(String text, boolean update) {
        super.setText(text, update);
        select(text);
    }
    
    public String getText() {
        return getSelectedItem();
    }
    
    public void setAllowSuffix(boolean allowSuffix) {
        this.allowSuffix = allowSuffix;
    }
    
    public boolean getAllowSuffix() {
        return allowSuffix;
    }
    
    public boolean mouseDown(Event evt) {
        if (canvas == null)
            return false;
        
        if (evt.clickCount == 1 && canvas.getSelectedRow() == row &&
	    canvas.startEdit(column)) {
            showMenu();
            dragging = true;
            dragX = evt.x + canvas.columnX(column);
            dragY = evt.y + canvas.rowY(row);
            return true;
        } else {
            return false;
        }
    }
    
    void cancelEdit() {
        if (canvas != null)
            hideMenu();
    }
    
    // Events are sent here subsequent to the mouseDown.
    public boolean handleEvent(Event evt) {
        if (canvas == null)
            return false;
        
        if (evt.target == menu && evt.id == Event.LIST_SELECT) {
            dragging = false;
            String item = menu.getSelectedItem();
            hideMenu();
            canvas.postEvent(new Event(this, APPLY, item));
        } else if (dragging) {
            forwardToMenu(evt, canvas.getEditRow(),
			  canvas.getEditColumn());
            if (evt.id == Event.MOUSE_UP && dragging &&
		evt.x != -1 && evt.y != -1) {
                dragging = false;
                if (Math.abs(evt.x - dragX) +
		    Math.abs(evt.y - dragY) > 4) {
                    canvas.cancelEdit();
                }
            }
        } else {
            return false;
        }
        
        return true;
    }
    
    private void showMenu() {
        if (menu == null) {
            menu = canvas.choiceMenu;
            menuWindow = canvas.choiceMenuWindow;
            
            if (menu == null) {
                menu = new TextList();
                menu.setBackground(canvas.getParent().getBackground());
                menu.setRelief(menu.BLACK_BORDER);
                menu.setBorderWidth(1);
                menu.setMinimumColumns(0);
                menu.setMinimumRows(0);
                canvas.choiceMenu = menu;
                
                if (Global.isMotif()) {
                    menu.hide();
                    canvas.add(menu);
                } else {
                    menuWindow = new Window(findFrame(canvas));
                    canvas.choiceMenuWindow = menuWindow;
                    canvas.add(menuWindow);
                    menuWindow.add(/* NOI18N */"Center", menu);
                }
            } else {
                menu.clear();
                
                // Don't remove the menu from the canvas on Windows.  If you do,
                // you start getting spurious double-clicks!  But you do want
                // to remove it on Motif, otherwise the canvas becomes incapable
                // of getting the keyboard focus.
                if (Global.isMotif())
                    canvas.add(menu);
            }
            
            Enumeration e = items.elements();
            while (e.hasMoreElements())
                menu.addItem((String)e.nextElement());
        }
        
        if (Global.isMotif()) {
            Rectangle r = getMenuBounds(menu);
            menu.reshape(r.x, r.y, r.width, r.height);
            menu.select(selectedIndex);
            menu.validate();
            menu.makeVisible(selectedIndex);
            menu.menuMode(null);
            menu.show();
        } else {
            Rectangle r = getWindowMenuBounds(menu);
            menuWindow.reshape(r.x, r.y, r.width, r.height);
            menuWindow.validate();
            menu.select(selectedIndex);
            menu.makeVisible(selectedIndex);
            menu.menuMode(this);
            menuWindow.show();
            findFrame(canvas).requestFocus();
        }
    }
    
    private void hideMenu() {
        if (menu != null) {
            if (Global.isMotif()) {
                menu.reshape(0, 0, 0, 0);
                menu.hide();
                
                // Don't remove the menu from the canvas on Windows.  If you do,
                // you start getting spurious double-clicks!  But you do want
                // to remove it on Motif, otherwise the canvas becomes incapable
                // of getting the keyboard focus.
                if (Global.isMotif())
                    canvas.remove(menu);
                
                menu = null;
            } else {
                menuWindow.hide();
                menuWindow = null;
                menuWindowX = 0;
                menuWindowY = 0;
                menu = null;
            }
        }
    }
    
    private synchronized void forwardToMenu(Event evt, int row,
					    int column) {
        if (forwarding)
            return;
        
        Point offset = new Point(0, 0);
        
        if (Global.isMotif()) {
            Point p1 = menu.location();
            Point p2 = menu.view.location();
            offset.x = p1.x + p2.x;
            offset.y = p1.y + p2.y;
        } else {
            if (!(evt.id == Event.MOUSE_DRAG))
                return;
            
            offset.x = menuWindowX;
            offset.y = menuWindowY;
        }
        
        Event evtCopy = new Event(evt.target, evt.when, evt.id,
				  evt.x - offset.x, evt.y - offset.y, evt.key,
				  evt.modifiers, evt.arg);
        evtCopy.clickCount = evt.clickCount;
        evtCopy.evt = evt.evt;
        
        forwarding = true;
        
        // Don't set the menuDrag flag based on a forwarded event.
        boolean menuDrag = menu.view.menuDrag;
        menu.view.postEvent(evtCopy);
        if (menu != null)
            menu.view.menuDrag = menuDrag;
        
        forwarding = false;
    }
    
    private Rectangle getMenuBounds(TextList menu) {
        Rectangle r = new Rectangle(0, 0, 0, 0);
        Dimension pref = menu.preferredSize();
        Dimension size = canvas.size();
        int x = canvas.columnX(column);
        int y = canvas.rowY(row);
        
        r.x = Math.min(x, size.width - pref.width);
        r.x = Math.max(0, r.x);
        r.width = Math.min(pref.width, size.width - r.x);
        
        int numItems = Math.min(items.size(), itemsVisible);
        numItems = Math.max(numItems, 1);
        int lineHeight = menu.lineHeight();
        int hPad = 6;
        
        int prefHeight = numItems * lineHeight + hPad;
        int spaceAbove = y;
        int spaceBelow = (size.height - (y + canvas.rowHeight));
        int availableHeight;
        boolean below;
        
        if (prefHeight <= spaceBelow || spaceBelow >= spaceAbove) {
            below = true;
            availableHeight = spaceBelow;
        } else {
            below = false;
            availableHeight = spaceAbove;
        }
        
        numItems = Math.min(numItems,
			    (availableHeight - hPad) / lineHeight);
        
        r.height = numItems * lineHeight + hPad;
        if (below)
            r.y = y + canvas.rowHeight;
        else
            r.y = y - r.height;
        
        return r;
    }
    
    private Rectangle getWindowMenuBounds(TextList menu) {
        Rectangle r = new Rectangle(0, 0, 0, 0);
        Point offset = getFrameOffset(canvas);
        Dimension pref = menu.preferredSize();
        
        int numItems = Math.min(items.size(), itemsVisible);
        numItems = Math.max(numItems, 1);
        int lineHeight = menu.lineHeight();
        int hPad = 6;
        int prefHeight = numItems * lineHeight + hPad;
        
        r.x = offset.x + canvas.columnX(column);
        r.y = offset.y + canvas.rowY(row) + lineHeight;
        r.width = pref.width;
        r.height = prefHeight;
        
        // The Window instance cannot be resized narrower than 112 or shorter
        // than 27.  This is a lame AWT restriction for Windows95.
        r.width = Math.max(r.width, 112);
        r.height = Math.max(r.height, 27);
        
        Dimension screenSize = canvas.getToolkit().getScreenSize();
        // Subtract for taskbar
        screenSize.height -= 30;
        
        if ((r.x + r.width) > screenSize.width)
            r.x = screenSize.width - r.width;
        if (r.x < 0)
            r.x = 0;
        
        if ((r.y + r.height) > screenSize.height)
            r.y -= (r.height + lineHeight);
        if (r.y < 0)
            r.y = 0;
        
        menuWindowX = r.x - offset.x;
        menuWindowY = r.y - offset.y;
        
        return r;
    }
    
    private Frame findFrame(Component comp) {
        while (comp != null && !(comp instanceof Frame))
            comp = comp.getParent();
        
        return (Frame)comp;
    }
    
    private Point getFrameOffset(Component comp) {
        Point offset = new Point(0, 0);
        while (comp != null) {
            Point location = comp.location();
            offset.x += location.x;
            offset.y += location.y;
            if (comp instanceof Frame)
                break;
            comp = comp.getParent();
        }
        
        return offset;
    }
}
