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
 *
 * Copyright (c) 1994-1995, 2001 by Sun Microsystems, Inc. 
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
 * DISTRIBUTING THIS SOFTWARE OR ITS DERIVATIVES
 *
 *
 *        Copyright (C) 1996  Active Software, Inc.
 *                  All rights reserved.
 *
 * @(#) WinScrollbar.java 1.13 - last change made 05/02/97
 */

package sunsoft.jws.visual.rt.awt;

import sunsoft.jws.visual.rt.base.Global;
import sunsoft.jws.visual.rt.base.Util;
import java.awt.*;


public class WinScrollbar extends Canvas implements Runnable {
    
    /**
     * The horizontal Scrollbar variable.
     */
    public static final int	HORIZONTAL = Scrollbar.HORIZONTAL;
    
    /**
     * The vertical Scrollbar variable.
     */
    public static final int	VERTICAL   = Scrollbar.VERTICAL;
    
    /**
     * The value of the Scrollbar.
     */
    int	value;
    
    /**
     * The maximum value of the Scrollbar.
     */
    int	maximum;		// doesn't include the visible area
    
    /**
     * The minimum value of the Scrollbar.
     */
    int	minimum;
    
    /**
     * The size of the visible portion of the Scrollbar.
     */
    int	sVisible;
    
    /**
     * The Scrollbar's orientation--being either horizontal or vertical.
     */
    int	orientation;
    
    /**
     * The amount by which the scrollbar value will change when going
     * up or down by a line.
     */
    int lineIncrement = 1;
    
    /**
     * The amount by which the scrollbar value will change when going
     * up or down by a page.
     */
    int pageIncrement = 10;
    
    /**
     * Are we running on WindowsNT
     */
    private boolean winNT;
    
    private static WinScrollbar threadScrollbar;
    private static Thread scrollThread;
    private WinScrollbar currentScrollbar;
    private int currentScrollAction;
    private int currentScrollPosition;
    
    private static final int SCROLL_DELAY = 250;
    private static final int SCROLL_INTERVAL = 40;
    
    /**
     * Constructs a new vertical Scrollbar.
     */
    public WinScrollbar() {
        this(VERTICAL);
    }
    
    
    /**
     * Constructs a new Scrollbar with the specified orientation.
     * @param orientation either Scrollbar.HORIZONTAL 
     * or Scrollbar.VERTICAL
     * @exception IllegalArgumentException When an
     * illegal scrollbar orientation is given.
    */
    public WinScrollbar(int orientation) {
        switch (orientation) {
	case Scrollbar.HORIZONTAL:
	case Scrollbar.VERTICAL:
            this.orientation = orientation;
            break;
            
	default:
            /* JSTYLED */
	    throw new IllegalArgumentException(Global.getMsg("sunsoft.jws.visual.rt.awt.WinScrollbar.IllegalOrientation"));
        }
        
        winNT = Global.isWindowsNT();
    }
    
    /**
     * Constructs a new Scrollbar with the specified orientation,
     * value, page size,  and minumum and maximum values.
     * @param orientation either Scrollbar.HORIZONTAL 
     * or Scrollbar.VERTICAL
     * @param value the scrollbar's value
     * @param visible the size of the visible portion of the
     * scrollable area. The scrollbar will use this value when paging up
     * or down by a page.
     * @param minimum the minimum value of the scrollbar
     * @param maximum the maximum value of the scrollbar
     */
    public WinScrollbar(int orientation, int value, int visible,
			int minimum, int maximum) {
        this(orientation);
        setValues(value, visible, minimum, maximum);
    }
    
    /**
     * Returns the orientation for this Scrollbar.
     */
    public int getOrientation() {
        return orientation;
    }
    
    /**
     * Returns the current value of this Scrollbar.
     * @see #getMinimum
     * @see #getMaximum
     */
    public int getValue() {
        return value;
    }
    
    /**
     * Sets the value of this Scrollbar to the specified value.
     * @param value the new value of the Scrollbar. If this value is
     * below the current minimum or above 
     * the current maximum, it becomes the
     * new one of those values, respectively.
     * @see #getValue
     */
    public void setValue(int value) {
        if (value < minimum) {
            value = minimum;
        }
        if (value > (maximum - sVisible)) {
            value = maximum - sVisible;
        }
        if (value != this.value) {
            this.value = value;
            if (getPeer() != null)
                peerSetValue(value);
        }
    }
    
    /**
     * Returns the minimum value of this Scrollbar.
     * @see #getMaximum
     * @see #getValue
     */
    public int getMinimum() {
        return minimum;
    }
    
    /**
     * Returns the maximum value of this Scrollbar.
     * @see #getMinimum
     * @see #getValue
     */
    public int getMaximum() {
        return maximum;
    }
    
    /**
     * Returns the visible amount of the Scrollbar.
     */
    public int getVisible() {
        return sVisible;
    }
    
    /**
     * Sets the line increment for this scrollbar. This is the value
     * that will be added (subtracted) when the user hits the line down
     * (up) gadgets.
     */
    public void setLineIncrement(int l) {
        lineIncrement = l;
        if (getPeer() != null)
            peerSetLineIncrement(l);
    }
    
    /**
     * Gets the line increment for this scrollbar.
     */
    public int getLineIncrement() {
        return lineIncrement;
    }
    
    /**
     * Sets the page increment for this scrollbar. This is the value
     * that will be added (subtracted) when the user hits the page down
     * (up) gadgets.
     */
    public void setPageIncrement(int l) {
        pageIncrement = l;
        if (getPeer() != null)
            peerSetPageIncrement(l);
    }
    
    /**
     * Gets the page increment for this scrollbar.
     */
    public int getPageIncrement() {
        return pageIncrement;
    }
    
    /**
     * Sets the values for this Scrollbar.
     * @param value is the position in the current window.
     * @param visible is the amount visible per page
     * @param minimum is the minimum value of the scrollbar
     * @param maximum is the maximum value of the scrollbar
     */
    public void setValues(int value, int visible, int minimum,
			  int maximum) {
        if (visible < 0)
            visible = 0;
        
        if (visible > maximum)
            visible = maximum;
        
        if (maximum < minimum) {
            maximum = minimum;
        }
        if (value < minimum) {
            value = minimum;
        }
        if (value > (maximum - visible)) {
            value = (maximum - visible);
        }
        
        this.value = value;
        this.sVisible = visible;
        this.minimum = minimum;
        this.maximum = maximum;
        
        if (getPeer() != null)
            peerSetValues(value, sVisible, minimum, maximum);
    }
    
    /**
     * Returns the String parameters for this Scrollbar.
     */
    protected String paramString() {
        return super.paramString() +
	    /* NOI18N */",val=" + value +
	    /* NOI18N */",vis=" + isVisible() +
	    /* NOI18N */",min=" + minimum +
	    /* NOI18N */",max=" + maximum +
	    ((orientation == VERTICAL) ? /* NOI18N */
	    ",vert" : /* NOI18N */",horz");
    }
    
    /**
     * Returns the minimum size for the scrollbar
     */
    public Dimension minimumSize() {
        if (orientation == VERTICAL)
            return new Dimension(16, 50);
        else
            return new Dimension(50, 16);
    }
    
    /**
     * Returns the preferred size for the scrollbar
     */
    public Dimension preferredSize() {
        return minimumSize();
    }
    
    
    // The rest of this code does the things
    // that the peer would normally
    // if the peer weren't so badly broken.
    
    private Image buffer;
    private int prevWidth = 0;
    private int prevHeight = 0;
    private int action = 0;
    
    private int anchorPos;
    private int anchorValue;
    private int dragSpace;
    
    private static final int UP = 10;
    private static final int DOWN = 11;
    private static final int LEFT = 12;
    private static final int RIGHT = 13;
    
    private static final int LINEUP = 20;
    private static final int LINEDOWN = 21;
    private static final int PAGEUP = 22;
    private static final int PAGEDOWN = 23;
    private static final int DRAG = 24;
    
    private void peerSetValue(int value) {
        repaint();
    }
    
    private void peerSetLineIncrement(int l) {
    }
    
    private void peerSetPageIncrement(int l) {
    }
    
    private void peerSetValues(int value, int sVisible,
			       int minimum, int maximum) {
        repaint();
    }
    
    public void reshape(int x, int y, int width, int height) {
        super.reshape(x, y, width, height);
        
        if (prevWidth != width || prevHeight != height) {
            if (width > 0 && height > 0)
                buffer = createImage(width, height);
            else
                buffer = null;
            
            prevWidth = width;
            prevHeight = height;
        }
    }
    
    public void update(Graphics g) {
        if (Global.isWindows())
            g = getGraphics();
        draw(g);
    }
    
    public void paint(Graphics g) {
        if (Global.isWindows())
            g = getGraphics();
        draw(g);
    }
    
    private void draw(Graphics g) {
        if (buffer == null)
            return;
        
        drawScrollbar();
        g.drawImage(buffer, 0, 0, null);
    }
    
    private void drawScrollbar() {
        Graphics g = buffer.getGraphics();
        Dimension size = size();
        int w = size.width;
        int h = size.height;
        
        // Erase the old version
        g.setColor(getBackground());
        g.fillRect(0, 0, size.width, size.height);
        
        drawOutline(g, w-1, h-1);
        drawEndBoxes(g, w-1, h-1);
        
        int info[] = getDragBoxInfo();
        fillPageBox(g, w, h, info);
        drawDragBox(g, w-1, h-1, info);
    }
    
    private void drawOutline(Graphics g, int w, int h) {
        g.setColor(Global.util.darker(getBackground()));
        if (orientation == VERTICAL) {
            g.drawRect(0, 0, w, w);
            g.drawRect(0, w, w, h-2*w);
            g.drawRect(0, h-w, w, w);
        } else {
            g.drawRect(0, 0, h, h);
            g.drawRect(h, 0, w-2*h, h);
            g.drawRect(w-h, 0, h, h);
        }
    }
    
    private void drawEndBoxes(Graphics g, int w, int h) {
        if (orientation == VERTICAL) {
            if (action != LINEUP) {
                drawArrow(g, 0, 0, w, w, UP);
                drawBox(g, 0, 0, w, w);
            } else {
                drawArrow(g, 1, 1, w, w, UP);
            }
            
            if (action != LINEDOWN) {
                drawArrow(g, 0, h-w, w, w, DOWN);
                drawBox(g, 0, h-w, w, w);
            } else {
                drawArrow(g, 1, h-w+1, w, w, DOWN);
            }
        } else {
            if (action != LINEUP) {
                drawArrow(g, 0, 0, h, h, LEFT);
                drawBox(g, 0, 0, h, h);
            } else {
                drawArrow(g, 1, 1, h, h, LEFT);
            }
            
            if (action != LINEDOWN) {
                drawArrow(g, w-h, 0, h, h, RIGHT);
                drawBox(g, w-h, 0, h, h);
            } else {
                drawArrow(g, w-h+1, 1, h, h, RIGHT);
            }
        }
    }
    
    private void fillPageBox(Graphics g, int w, int h, int info[]) {
        g.setColor(pageDarker(getBackground()));
        if (orientation == VERTICAL) {
            if (action == PAGEUP) {
                g.fillRect(1, w, w-2, info[0]-w);
            } else if (action == PAGEDOWN) {
                g.fillRect(1, info[0]+info[1]+1, w-2,
			   h-(w+info[0]+info[1])-1);
            }
        } else {
            if (action == PAGEUP) {
                g.fillRect(h, 1, info[0]-h, h-2);
            } else if (action == PAGEDOWN) {
                g.fillRect(info[0]+info[1]+1, 1,
			   w-(h+info[0]+info[1])-1, h-2);
            }
        }
    }
    
    private void drawDragBox(Graphics g, int w, int h, int info[]) {
        if (orientation == VERTICAL) {
            drawBox(g, 0, info[0], w, info[1]);
        } else {
            drawBox(g, info[0], 0, info[1], h);
        }
    }
    
    private int [] getDragBoxInfo() {
        int info[] = new int[2];
        int minpix;
        int deltapix;
        Dimension size = size();
        
        if (orientation == VERTICAL) {
            minpix = size.width;
            deltapix = size.height - 2 * size.width;
        } else {
            minpix = size.height;
            deltapix = size.width - 2 * size.height;
        }
        
        int deltaval = maximum - minimum;
        double d = (double)deltapix/(double)deltaval;
        double xory = minpix + (value-minimum) * d;
        double worh = sVisible * d;
        
        info[0] = (int)xory;
        info[1] = (int)worh;
        
        return info;
    }
    
    private void drawBox(Graphics g, int x, int y, int w, int h) {
        g.setColor(getBackground());
        Global.util.draw3DRect(g, x, y, w, h,
			       Util.WIN95_WINDOW_BORDER, 2);
        
        if (true)
            return;
        else {
            g.setColor(Global.util.brighter(getBackground()));
            g.drawLine(x, y, x+w-1, y);
            g.drawLine(x, y, x, y+h-1);
            
            g.setColor(Color.white);
            g.drawLine(x+1, y+1, x+w-2, y+1);
            g.drawLine(x+1, y+1, x+1, y+h-2);
            
            g.setColor(Color.black);
            g.drawLine(x+w, y, x+w, y+h);
            g.drawLine(x, y+h, x+w, y+h);
            
            g.setColor(Global.util.darker(getBackground()));
            g.drawLine(x+w-1, y+1, x+w-1, y+h-1);
            g.drawLine(x+1, y+h-1, x+w-1, y+h-1);
        }
    }
    
    private void drawArrow(Graphics g, int x, int y, int w, int h,
			   int direction) {
        Polygon p = new Polygon();
        
        // xoff=4 and yoff=4 for the default case where w=15 and y=15
        int xoff = (w-3)/3;
        int yoff = (h-3)/3;
        int bd = 2;
        
        g.setColor(Color.black);
        
        switch (direction) {
	case LEFT:
            if (winNT) {
                x -= xoff/4;
                g.fillRect(x+bd+2*xoff-1, y+bd+(5*yoff/4)-1,
			   xoff/2+1, yoff/2+1);
            }
            p.addPoint(x+bd+xoff-1, y+bd+(3*yoff/2)-1);
            p.addPoint(x+bd+2*xoff-1, y+bd+yoff-3);
            p.addPoint(x+bd+2*xoff-1, y+bd+2*yoff+1);
            break;
            
	case RIGHT:
            if (winNT) {
                x += xoff/4+1;
                g.fillRect(x+bd+(xoff/2)-1, y+bd+(5*yoff/4)-1,
			   xoff/2+2, yoff/2+1);
            }
            p.addPoint(x+bd+xoff, y+bd+yoff-3);
            p.addPoint(x+bd+xoff*2, y+bd+(3*yoff/2)-1);
            p.addPoint(x+bd+xoff, y+bd+2*yoff+1);
            break;
            
	case UP:
            if (winNT) {
                y -= yoff/4+1;
                g.fillRect(x+bd+(5*xoff/4)-1, y+bd+2*yoff,
			   xoff/2+1, yoff/2+1);
            }
            p.addPoint(x+bd+xoff-3, y+bd+2*yoff);
            p.addPoint(x+bd+(3*xoff/2)-1, y+bd+yoff);
            p.addPoint(x+bd+(3*xoff/2), y+bd+yoff);
            p.addPoint(x+bd+2*xoff+2, y+bd+2*yoff);
            break;
            
	case DOWN:
            if (winNT) {
                y += yoff/4+1;
                g.fillRect(x+bd+(5*xoff/4)-1, y+bd+(yoff/2)-1,
			   xoff/2+1, yoff/2+2);
            }
            p.addPoint(x+bd+xoff-2, y+bd+yoff);
            p.addPoint(x+bd+2*xoff+1, y+bd+yoff);
            p.addPoint(x+bd+(3*xoff/2)-1, y+bd+2*yoff);
            p.addPoint(x+bd+(3*xoff/2)-1, y+bd+2*yoff-1);
            break;
        }
        
        g.fillPolygon(p);
    }
    
    private static final double PAGE_DFACTOR = 0.8;
    
    /**
     * Returns a darker version of this color used for the paging
     * highlight color.
     */
    private Color pageDarker(Color c) {
        return new Color(Math.max((int)(c.getRed()  *PAGE_DFACTOR), 0),
			 Math.max((int)(c.getGreen()*PAGE_DFACTOR), 0),
			 Math.max((int)(c.getBlue() *PAGE_DFACTOR), 0));
    }
    
    public boolean mouseDown(Event evt, int x, int y) {
        Dimension size = size();
        int w = size.width;
        int h = size.height;
        
        if (orientation == VERTICAL) {
            if (y < w) {
                lineUp(y);
            } else if (y >= (h-w)) {
                lineDown(y);
            } else {
                int info[] = getDragBoxInfo();
                if (y >= (w+1) && y < info[0]) {
                    pageUp(y);
                } else if (y >= info[0]+info[1] && y < (h-w)) {
                    pageDown(y);
                } else if (y >= info[0] && y < info[0]+info[1]) {
                    dragStart(x, y);
                }
            }
            
        } else {
            if (x < h) {
                lineUp(x);
            } else if (x >= (w-h)) {
                lineDown(x);
            } else {
                int info[] = getDragBoxInfo();
                if (x >= (h+1) && x < info[0]) {
                    pageUp(x);
                } else if (x >= info[0]+info[1] && x < (w-h)) {
                    pageDown(x);
                } else if (x >= info[0] && x < info[0]+info[1]) {
                    dragStart(x, y);
                }
            }
        }
        
        return false;
    }
    
    public boolean mouseDrag(Event evt, int x, int y) {
        if (action == DRAG) {
            drag(x, y);
            return true;
        } else if (threadScrollbar != null &&
		   threadScrollbar.currentScrollbar == this) {
            synchronized (threadScrollbar) {
                if (orientation == VERTICAL)
                    threadScrollbar.currentScrollPosition = y;
                else
                    threadScrollbar.currentScrollPosition = x;
            }
        }
        
        return false;
    }
    
    public boolean mouseUp(Event evt, int x, int y) {
        cancelAutoScroll();
        
        if (action == DRAG) {
            dragStop(x, y);
        }
        
        action = 0;
        repaint();
        
        return false;
    }
    
    private boolean lineUp(int pos) {
        boolean status = false;
        action = LINEUP;
        initAutoScroll(action, pos);
        
        int prevValue = value;
        value = Math.max(minimum, value-lineIncrement);
        if (value != prevValue) {
            status = true;
            postEvent(new Event(this, Event.SCROLL_LINE_UP,
				new Integer(value)));
        }
        
        repaint();
        return status;
    }
    
    private boolean lineDown(int pos) {
        boolean status = false;
        action = LINEDOWN;
        initAutoScroll(action, pos);
        
        int prevValue = value;
        value = Math.min(maximum-sVisible, value+lineIncrement);
        if (value != prevValue) {
            postEvent(new Event(this, Event.SCROLL_LINE_DOWN,
				new Integer(value)));
            status = true;
        }
        
        repaint();
        return status;
    }
    
    private boolean pageUp(int pos) {
        boolean status = false;
        action = PAGEUP;
        initAutoScroll(action, pos);
        
        int prevValue = value;
        value = Math.max(minimum, value-pageIncrement);
        if (value != prevValue) {
            status = true;
            postEvent(new Event(this, Event.SCROLL_PAGE_UP,
				new Integer(value)));
        }
        
        repaint();
        return status;
    }
    
    private boolean pageDown(int pos) {
        boolean status = false;
        action = PAGEDOWN;
        initAutoScroll(action, pos);
        
        int prevValue = value;
        value = Math.min(maximum-sVisible, value+pageIncrement);
        if (value != prevValue) {
            status = true;
            postEvent(new Event(this, Event.SCROLL_PAGE_DOWN,
				new Integer(value)));
        }
        
        repaint();
        return status;
    }
    
    private void dragStart(int x, int y) {
        action = DRAG;
        
        if (orientation == VERTICAL)
            anchorPos = y;
        else
            anchorPos = x;
        
        anchorValue = value;
        
        Dimension size = size();
        int info[] = getDragBoxInfo();
        
        if (orientation == VERTICAL)
            dragSpace = size.height - size.width*2 - info[1];
        else
            dragSpace = size.width - size.height*2 - info[1];
    }
    
    private void drag(int x, int y) {
        if (orientation == VERTICAL)
            newDragValue(y);
        else
            newDragValue(x);
    }
    
    private void dragStop(int x, int y) {
        action = 0;
        drag(x, y);
    }
    
    private void newDragValue(int pos) {
        int pixelsDiff = pos - anchorPos;
        int valDiff = (pixelsDiff * (maximum-minimum) / dragSpace);
        int prevValue = value;
        
        value = anchorValue + valDiff;
        if (valDiff < 0)
            value = Math.max(value, minimum);
        else
            value = Math.min(value, maximum-sVisible);
        
        if (value != prevValue)
            postEvent(new Event(this, Event.SCROLL_ABSOLUTE,
				new Integer(value)));
        
        repaint();
    }
    
    private void initAutoScroll(int action, int pos) {
        if (Thread.currentThread() == scrollThread)
            return;
        
        if (threadScrollbar == null) {
            threadScrollbar = this;
            scrollThread = new Thread(threadScrollbar, /* NOI18N */
				      "WindowsScrollbarThread");
            scrollThread.setDaemon(true);
            scrollThread.start();
        }
        
        synchronized (threadScrollbar) {
            threadScrollbar.currentScrollbar = this;
            threadScrollbar.currentScrollAction = action;
            threadScrollbar.currentScrollPosition = pos;
            threadScrollbar.notify();
        }
    }
    
    private void cancelAutoScroll() {
        if (threadScrollbar != null) {
            synchronized (threadScrollbar) {
                threadScrollbar.currentScrollbar = null;
                threadScrollbar.currentScrollAction = -1;
                threadScrollbar.currentScrollPosition = -1;
                threadScrollbar.notify();
            }
        }
    }
    
    public synchronized void run() {
        boolean scrolling = false;
        long waitTime;
        
        while (scrollThread == Thread.currentThread()) {
            long startTime = System.currentTimeMillis();
            
            if (currentScrollbar == null) {
                waitTime = 0;
                scrolling = false;
            } else {
                if (scrolling) {
                    if (!doScroll(currentScrollbar,
				  currentScrollAction,
				  currentScrollPosition)) {
                        cancelAutoScroll();
                        waitTime = 0;
                    } else {
                        waitTime = SCROLL_INTERVAL;
                    }
                } else {
                    waitTime = SCROLL_DELAY;
                    scrolling = true;
                }
            }
            
            // Wait for "waitTime" milliseconds.
            // But if "waitTime" is zero,
            // then just wait for a notify.  If
            // the currentScrollbar changes,
            // then don't wait any longer.
            if (waitTime == 0 || currentScrollbar == null) {
                try { wait(0); }
                catch (InterruptedException ex) {}
            } else {
                WinScrollbar initScrollbar = currentScrollbar;
                long targetTime = startTime + waitTime;
                long diff = targetTime - System.currentTimeMillis();
                
                while (currentScrollbar == initScrollbar && diff > 0) {
                    try { wait(diff); }
                    catch (InterruptedException ex) {}
                    diff = targetTime - System.currentTimeMillis();
                }
                
                if (currentScrollbar != initScrollbar)
                    scrolling = false;
            }
        }
    }
    
    private boolean doScroll(WinScrollbar scrollbar,
			     int action, int pos) {
        boolean status = false;
        
        switch (action) {
	case LINEUP:
            status = scrollbar.lineUp(pos);
            break;
            
	case LINEDOWN:
            status = scrollbar.lineDown(pos);
            break;
            
	case PAGEUP:
            if (continuePaging(scrollbar, action, pos)) {
                status = scrollbar.pageUp(pos);
            } else {
                // Keep trying to scroll for the case
                // where the user drags
                // the mouse while paging.  We want to
                // track the drag position
                // in the direction of the original paging action.
                status = true;
            }
            break;
            
	case PAGEDOWN:
            if (continuePaging(scrollbar, action, pos)) {
                status = scrollbar.pageDown(pos);
            } else {
                // Keep trying to scroll for the case
                // where the user drags
                // the mouse while paging.  We want to
                // track the drag position
                // in the direction of the original paging action.
                status = true;
            }
            break;
            
	default:
            break;
        }
        
        return status;
    }
    
    private boolean continuePaging(WinScrollbar scrollbar, int action,
				   int pos) {
        boolean status = false;
        int info[] = scrollbar.getDragBoxInfo();
        
        if (pos < info[0]) {
            status = (action == PAGEUP);
        } else if (pos >= info[0]+info[1]) {
            status = (action == PAGEDOWN);
        }
        
        return status;
    }
}
