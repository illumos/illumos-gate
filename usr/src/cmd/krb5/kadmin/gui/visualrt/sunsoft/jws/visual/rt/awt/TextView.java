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
 * @(#) TextView.java 1.29 - last change made 08/12/97
 */

package sunsoft.jws.visual.rt.awt;

import sunsoft.jws.visual.rt.base.Global;

import java.awt.*;
import java.util.Vector;
import java.util.Hashtable;

public class TextView extends VJCanvas implements Scrollable {
    private static final int RIGHT_MOUSE = 4;
    
    protected Vector items;
    
    protected int fontHeight, lineWidth, lineHeight;
    protected FontMetrics fontMetrics;
    protected int minrows = 10;
    protected int mincolumns = 15;
    protected int minWidth = 0;
    
    static protected final int textIndent = 6;
    static protected final int textBorder = 2;
    static protected final int viewBorder = 0;
    static protected final int viewIPad = 2;
    
    private int selected[] = new int[0];
    private int numSelected;
    
    private int scrollx = 0;
    private int scrolly = 0;
    private Image buffer;
    private boolean multipleSelections;
    private Hashtable stringWidthTable;
    
    private boolean menuMode;
    private CLChoice menuChoice;
    boolean menuDrag;
    
    private boolean gotEventInside;
    private int prevMenuY;
    
    public TextView() {
        stringWidthTable = new Hashtable();
        // why was the background hardcoded to white?
        // setBackground(Color.white);
    }
    
    //
    // Accessor methods.  These are forwarded from the TextList class.
    //
    public void setMinimumRows(int num) {
        minrows = num;
    }
    
    public int getMinimumRows() {
        return minrows;
    }
    
    public void setMinimumColumns(int num) {
        mincolumns = num;
    }
    
    public int getMinimumColumns() {
        return mincolumns;
    }
    
    public int getRows() {
        if (lineHeight == 0)
            return 0;
        
        Dimension size = size();
        int h = size.height - (viewBorder + viewIPad);
        return ((h+lineHeight-1)/lineHeight);
    }
    
    public void updateView() {
        for (int i = 0; i < numSelected; i++) {
            if (selected[i] >= items.size()) {
                shift(selected, i+1, numSelected, -1);
                numSelected--;
            }
        }
        
        cacheMinWidth();
        repaint();
    }
    
    private void shift(int[] data, int offset, int length, int shift) {
        System.arraycopy(data, offset, data, offset+shift,
			 length-offset);
    }
    
    public void select(int index) {
        if (index >= items.size())
            return;
        if (index < -1)
            return;
        
        if (!multipleSelections) {
            if (index == -1) {
                if (numSelected != 0) {
                    numSelected = 0;
                    repaint();
                }
            } else {
                if (numSelected == 0) {
                    selected = ensureCapacity(selected, numSelected, 1);
                    numSelected = 1;
                    selected[0] = -1;
                }
                if (selected[0] != index) {
                    selected[0] = index;
                    repaint();
                }
            }
        } else {
            if (index == -1)
                return;
            
            boolean inserted = false;
            for (int i = 0; i < numSelected; i++) {
                if (index == selected[i]) {
                    inserted = true;
                    break;
                } else if (index < selected[i]) {
                    inserted = true;
                    selected = ensureCapacity(selected,
					      numSelected, numSelected+1);
                    shift(selected, i, numSelected, 1);
                    selected[i] = index;
                    numSelected++;
                    repaint();
                    break;
                }
            }
            
            if (!inserted) {
                selected = ensureCapacity(selected, numSelected,
					  numSelected+1);
                selected[numSelected] = index;
                numSelected++;
                repaint();
            }
        }
    }
    
    public void select(Object item) {
        if (item != null)
            select(items.indexOf(item));
    }
    
    public void deselect(int index) {
        if (index < 0 || index >= items.size())
            return;
        
        for (int i = 0; i < numSelected; i++) {
            if (selected[i] == index) {
                shift(selected, i+1, numSelected, -1);
                numSelected--;
                repaint();
                break;
            }
        }
    }
    
    public void deselectAll() {
        if (numSelected != 0) {
            numSelected = 0;
            repaint();
        }
    }
    
    public boolean isSelected(int index) {
        for (int i = 0; i < numSelected; i++) {
            if (selected[i] == index)
                return true;
        }
        
        return false;
    }
    
    public void setMultipleSelections(boolean v) {
        multipleSelections = v;
    }
    
    public boolean allowsMultipleSelections() {
        return multipleSelections;
    }
    
    public int getSelectedIndex() {
        if (numSelected == 0)
            return -1;
        else
            return selected[0];
    }
    
    public int[] getSelectedIndexes() {
        int[] data = new int[numSelected];
        System.arraycopy(selected, 0, data, 0, numSelected);
        return data;
    }
    
    public Object getSelectedItem() {
        if (numSelected == 0)
            return null;
        else
            return items.elementAt(selected[0]);
    }
    
    public Object[] getSelectedItems() {
        Object[] data = new Object[numSelected];
        for (int i = 0; i < numSelected; i++)
            data[i] = items.elementAt(selected[i]);
        return data;
    }
    
    private int[] ensureCapacity(int[] elementData, int elementCount,
				 int minCapacity) {
        int oldCapacity = elementData.length;
        if (minCapacity > oldCapacity) {
            int oldData[] = elementData;
            int newCapacity = oldCapacity * 2;
            if (newCapacity < minCapacity) {
                newCapacity = minCapacity;
            }
            elementData = new int[newCapacity];
            System.arraycopy(oldData, 0, elementData, 0, elementCount);
        }
        
        return elementData;
    }
    
    //
    // Package private accessor methods
    //
    protected void items(Vector items) {
        this.items = items;
    }
    
    //
    // Component methods
    //
    public Dimension minimumSize() {
        int bd = getBD();
        return new Dimension(minWidth + bd, (minrows * lineHeight)
			     + bd);
    }
    
    public Dimension preferredSize() {
        return minimumSize();
    }
    
    //
    // Scrollable methods
    //
    public void scrollX(int x) {
        scrollx = x;
        repaint();
    }
    
    public void scrollY(int y) {
        scrolly = y;
        repaint();
    }
    
    public Dimension scrollSize() {
        return new Dimension(minWidth, items.size()*lineHeight);
    }
    
    public Dimension viewSize(Dimension size) {
        int bd = getBD();
        size.width -= bd;
        size.height -= bd;
        return size;
    }
    
    public int lineHeight() {
        return lineHeight;
    }
    
    private int getBD() {
        return 2 * (viewBorder + viewIPad);
    }
    
    //
    // Event handling for selections
    //
    public boolean mouseDown(Event e, int x, int y) {
        //
        // On Windows95, we sometimes get bogus
        // mouseDown events.  This happens
        // when the TextView is being used as a
        // menu for the CLChoice component.
        // The user presses the mouse over the CLChoice
        // item in the list, causing
        // the menu to be mapped.  Then, without
        // releasing the mouse, the user
        // drags the mouse into the menu.  This
        // sometimes causes a bogus
        // mouseDown event to be sent to the menu /* JSTYLED */
	// (actually to the TextView
        // inside the menu).
        //
        // The workaround is to ignore mouseDown
        // events that occur before there
        // has been either a mouseDrag or a
        // mouseMove event.  This check is only
        // made if menuChoice is not null /* JSTYLED */
	// (indicating that this TextView is being
        // used as a CLChoice menu).
        //
        if (menuChoice != null && !menuDrag)
            return true;
        
        selectY(e, true);
        
        menuMode = false;
        menuChoice = null;
        menuDrag = false;
        
        return true;
    }
    
    public boolean mouseDrag(Event e, int x, int y) {
        // Workaround for bug observed on WindowsNT
        // where you get spurious
        // mouse drag events when pressing the mouse.
        // The spurious event
        // has coordinates x=-1 and y=-1.
        if (!Global.isWindows() || e.y != -1) {
            if (menuMode) {
                menuDrag = true;
                menuEvent(e);
            } else if (!multipleSelections) {
                selectY(e, true);
            }
        }
        
        return true;
    }
    
    public boolean mouseUp(Event e, int x, int y) {
        if (menuMode)
            menuEvent(e);
        
        return true;
    }
    
    public boolean mouseMove(Event e, int x, int y) {
        if (menuMode) {
            menuDrag = true;
            menuEvent(e);
            return true;
        } else {
            return false;
        }
    }
    
    private void selectY(Event e, boolean doPost) {
        int evtX = e.x;
        int evtY = e.y + scrolly - (viewBorder + viewIPad);
        int index = evtY/lineHeight;
        int size = items.size();
        int id;
        
        if (size == 0)
            return;
        if (index >= size)
            index = size-1;
        if (index < 0)
            index = 0;
        
        if (multipleSelections) {
            if (isSelected(index)) {
                id = Event.LIST_DESELECT;
                deselect(index);
            } else {
                id = Event.LIST_SELECT;
                select(index);
            }
            
            if (doPost) {
                Event evt = new Event(getParent(), id,
				      items.elementAt(index));
                if (menuChoice != null)
                    menuChoice.handleEvent(evt);
                else
                    postEvent(evt);
            }
        } else {
            id = Event.LIST_SELECT;
            
            //
            // Ignore double-clicks on Windows because
            // they are sent spuriously.
            //
            if ((e.clickCount == 2 && !Global.isWindows()) ||
		e.modifiers == RIGHT_MOUSE) {
                id = Event.ACTION_EVENT;
            }
            
            if (!isSelected(index)) {
                select(index);
                repaint();
                if (doPost) {
                    Event evt = new Event(getParent(), id,
					  items.elementAt(index));
                    if (menuChoice != null)
                        menuChoice.handleEvent(evt);
                    else
                        postEvent(evt);
                }
            } else if (e.id == Event.MOUSE_DOWN ||
		       e.id == Event.MOUSE_UP) {
                if (doPost) {
                    Event evt = new Event(getParent(), id,
					  items.elementAt(index));
                    if (menuChoice != null)
                        menuChoice.handleEvent(evt);
                    else
                        postEvent(evt);
                }
            }
        }
    }
    
    //
    // Painting
    //
    public void reshape(int x, int y, int width, int height) {
        super.reshape(x, y, width, height);
        cacheLineWidth();
        
        if (width <= 0 || height <= 0)
            return;
        
        // Create the image used for double-buffering
        if (buffer == null ||
	    (width != buffer.getWidth(this) ||
	    height != buffer.getHeight(this)))
	    buffer = createImage(width, height);
    }
    
    public void update(Graphics g) {
        paint(g);
    }
    
    public void paint(Graphics g) {
        if (buffer == null)
            return;
        
        g = buffer.getGraphics();
        g.setFont(getFont());
        
        Dimension d = size();
        
        g.setColor(getBackground());
        g.fillRect(0, 0, d.width, d.height);
        
        if (isEnabled())
            g.setColor(getForeground());
        else
            g.setColor(getBackground().darker());
        drawItems(g);
        
        g.setColor(getBackground());
        drawBorder(g);
        
        g = getGraphics();
        g.drawImage(buffer, 0, 0, this);
    }
    
    private void drawItems(Graphics g) {
        Dimension d = size();
        int size = items.size();
        
        int viewTop, viewBottom, lineTop, lineBottom;
        int bd = viewBorder + viewIPad;
        int yoff;
        
        viewTop = scrolly;
        viewBottom = scrolly + d.height;
        
        for (int i = 0; i < size; i++) {
            lineTop = i*lineHeight;
            lineBottom = lineTop + lineHeight;
            
            if (lineTop > viewBottom || lineBottom < viewTop)
                continue;
            
            yoff = lineTop - viewTop + bd;
            drawLine(g, i, -scrollx+bd, yoff);
        }
    }
    
    protected void drawLine(Graphics g, int index, int xoff, int yoff) {
        String name = (String)items.elementAt(index);
        
        int x = textIndent;
        int y = (lineHeight + fontHeight)/2 - 1;
        
        if (isSelected(index)) {
            g.setColor(new Color(0, 0, 128));
            g.fillRect(xoff, yoff, lineWidth, lineHeight);
            g.setColor(Color.white);
        }
        
        // Useful for pixel debugging
        // g.drawRect(xoff, yoff, lineWidth-1, lineHeight-1);
        
        g.drawString(name, x+xoff, y+yoff);
        
        if (isSelected(index)) {
            g.setColor(getForeground());
        }
    }
    
    private void drawBorder(Graphics g) {
        Dimension size = size();
        
        for (int i = 0; i < viewIPad; i++)
            g.drawRect(viewBorder+i, viewBorder+i,
		       size.width-1-2*(i+viewBorder),
		       size.height-1-2*(i+viewBorder));
    }
    
    public void addNotify() {
        super.addNotify();
        cacheAll();
    }
    
    public void setFont(Font f) {
        super.setFont(f);
        
        stringWidthTable.clear();
        if (getPeer() != null)
            cacheAll();
    }
    
    private void cacheAll() {
        cacheLineHeight();
        cacheMinWidth();
    }
    
    //
    // Need to call this when the list of items
    // changes, the font changes,
    // or the mincolumns changes.  The mincolumns
    // change should be followed
    // by a call to updateView for the change
    // to take effect.  It is only
    // necessary to call updateView if addNotify
    // has not yet been called.
    //
    protected void cacheMinWidth() {
        minWidth = mincolumns * getStringWidth(/* NOI18N */"0");
        
        int count = items.size();
        for (int i = 0; i < count; i++)
            minWidth = Math.max(minWidth,
				getStringWidth((String)items.elementAt(i)));
        
        minWidth += textIndent * 2;
        cacheLineWidth();
    }
    
    protected int getStringWidth(String s) {
        if (fontMetrics == null)
            return 0;
        
        Integer val = (Integer)stringWidthTable.get(s);
        if (val == null) {
            val = new Integer(fontMetrics.stringWidth(s));
            stringWidthTable.put(s, val);
        }
        
        return val.intValue();
    }
    
    //
    // Need to call this when the size
    // changes and when the minWidth changes.
    //
    protected void cacheLineWidth() {
        Dimension size = size();
        int bd = getBD();
        lineWidth = Math.max(minWidth, size.width-bd);
    }
    
    //
    // Need to call this when the font changes.
    //
    protected void cacheLineHeight() {
        lineHeight = 0;
        Graphics g = getGraphics();
        if (g == null)
            return;
        
        Font f = getFont();
        if (f == null)
            return;
        
        fontMetrics = g.getFontMetrics(f);
        fontHeight = fontMetrics.getMaxAscent();
        
        lineHeight = fontHeight + 2*textBorder;
    }
    
    //
    // Methods used by CLChoice
    //
    
    void menuMode(CLChoice choice) {
        menuChoice = choice;
        menuMode = true;
        menuDrag = false;
        gotEventInside = false;
        prevMenuY = 0;
    }
    
    private void menuEvent(Event e) {
        if (checkBounds(e)) {
            selectY(e, (e.id == Event.MOUSE_UP));
            
            // Auto-scrolling
            int bd = getBD();
            if (e.id != Event.MOUSE_MOVE &&
		((e.y < bd && e.y < prevMenuY) ||
		 (e.y > (size().height-bd) && e.y > prevMenuY))) {
                ((TextList)getParent()).makeVisible(getSelectedIndex());
            }
            
            prevMenuY = e.y;
        }
    }
    
    private boolean checkBounds(Event e) {
        if (!gotEventInside) {
            Dimension d = size();
            int bd = getBD();
            if (e.x >= bd && e.y >= bd &&
		e.x <= (d.width-bd) && e.y <= (d.height-bd))
		gotEventInside = true;
        }
        
        return gotEventInside;
    }
}
