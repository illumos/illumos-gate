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
 * @version @(#)EditLine.java 1.13 97/06/18
 */


package sunsoft.jws.visual.rt.awt;

import sunsoft.jws.visual.rt.base.Global;
import java.awt.*;

/**
 * An EditLine allows for the editing of text within some other component.
 */

public class EditLine implements Runnable
{
    public static final int REPAINT = 87000;
    public static final int APPLY = 87001;
    public static final int CANCEL = 87002;
    
    public static final int BACKSPACE_KEY = 8;
    public static final int TAB_KEY = 9;
    public static final int RETURN_KEY = 10;
    public static final int ESCAPE_KEY = 27;
    public static final int DELETE_KEY = 127;
    
    private Component comp;
    private String text;
    private int textX, textY;
    private Color fg, bg;
    private Font font;
    private FontMetrics metrics;
    
    private int x, y, w, h;
    private int initWidth;
    private String initText;
    
    private boolean justStartedEditing;
    private boolean cancelApply;
    private boolean applying;
    
    private int scrollPos;
    private int cursorPos;
    private int selectPos;
    private boolean dragging;
    private Frame frame;
    
    private boolean cursorState;
    private boolean paintCursor;
    private Thread cursorThread;
    private long cursorTime;
    private static final long CURSOR_DELAY = 500;
    
    private static final int XOFF = 2;
    private static final int MINWIDTH = 12;
    static final int XPAD = 15;
    static final int YPAD = 4;
    
    public EditLine(Component comp, String text, int textX, int textY) {
        if (text == null)
            text = /* NOI18N */"";
        
        this.comp = comp;
        this.text = text;
        this.textX = textX;
        this.textY = textY;
        this.initText = text;
        
        selectPos = 0;
        cursorPos = text.length();
        scrollPos = 0;
        justStartedEditing = true;
        
        cacheDims();
        this.initWidth = w;
        mouseMove(textX, textY);
        comp.requestFocus();
        
        cursorThread = new Thread(this, /* NOI18N */"Edit Line Cursor");
        cursorThread.setDaemon(true);
        cursorTime = System.currentTimeMillis();
        cursorState = true;
        cursorThread.start();
    }
    
    public void setText(String text) {
        if (text == null)
            text = /* NOI18N */"";
        
        this.text = text;
        cursorPos = text.length();
        selectPos = cursorPos;
        scrollPos = 0;
        cacheText();
    }
    
    public String getText() {
        return text;
    }
    
    public void setSelection(int start, int end) {
        int len = text.length();
        start = Math.max(0, start);
        start = Math.min(start, len);
        end = Math.max(start, end);
        end = Math.min(end, len);
        
        selectPos = start;
        cursorPos = end;
        makeVisible(cursorPos);
        repaint();
    }
    
    public String getSelection() {
        return text.substring(selectStart(), selectEnd());
    }
    
    public void setFont(Font font) {
        this.font = font;
        cacheDims();
        comp.repaint();
    }
    
    public Font getFont() {
        if (font == null)
            return comp.getFont();
        else
            return font;
    }
    
    public void setForeground(Color fg) {
        this.fg = fg;
    }
    
    public Color getForeground() {
        if (fg == null)
            return comp.getForeground();
        else
            return fg;
    }
    
    public void setBackground(Color bg) {
        this.bg = bg;
    }
    
    public Color getBackground() {
        if (bg == null)
            return comp.getBackground();
        else
            return bg;
    }
    
    public boolean applyChanges() {
        if (!text.equals(initText)) {
            applying = true;
            cancelApply = false;
            comp.postEvent(new Event(this, APPLY, text));
            applying = false;
            return !cancelApply;
        } else {
            comp.postEvent(new Event(this, CANCEL, null));
            return true;
        }
    }
    
    public void cancelApply() {
        cancelApply = true;
    }
    
    private void cacheText() {
        int len = text.length();
        if (selectPos > len)
            selectPos = len;
        if (cursorPos > len)
            cursorPos = len;
        if (scrollPos > len)
            scrollPos = 0;
        
        Rectangle paintRect = cacheHorizontal();
        makeVisible(cursorPos);
        repaint(paintRect);
    }
    
    private void cacheDims() {
        metrics = comp.getFontMetrics(getFont());
        cacheHorizontal();
        cacheVertical();
    }
    
    private Rectangle cacheHorizontal() {
        Dimension d = comp.size();
        int prevLeft = x;
        int prevRight = x+w;
        
        x = textX - XOFF;
        w = metrics.stringWidth(text) + XPAD;
        w = Math.max(w, MINWIDTH);
        w = Math.max(w, initWidth);
        
        if (w > (d.width-x)) {
            x = d.width - w;
            if (x < 0) {
                x = 0;
                w = d.width;
            }
        }
        
        int left = x;
        int right = x+w;
        
        if (left > prevLeft && right < prevRight)
            return new Rectangle(prevLeft, y, prevRight-prevLeft, h);
        else if (left > prevLeft)
            return new Rectangle(prevLeft, y, left - prevLeft, h);
        else if (right < prevRight)
            return new Rectangle(right, y, prevRight - right, h);
        else
            return null;
    }
    
    private void cacheVertical() {
        Dimension d = comp.size();
        y = textY - (metrics.getAscent() + YPAD/2);
        h = metrics.getHeight() + YPAD;
        
        if (h > (d.height-y)) {
            y = d.height - h;
            if (y < 0) {
                y = 0;
                h = d.height;
            }
        }
    }
    
    public boolean handleEvent(Event evt) {
        if (evt.id == Event.MOUSE_DOWN) {
            if (justStartedEditing && evt.clickCount == 2) {
                justStartedEditing = false;
                comp.postEvent(new Event(this, CANCEL, null));
                return false;
            } else {
                justStartedEditing = false;
            }
        }
        
        boolean retval = false;
        
        switch (evt.id) {
	case Event.MOUSE_DOWN:
            if (inside(evt.x, evt.y)) {
                mouseDown(evt.clickCount, evt.x, evt.y);
                retval = true;
            }
            break;
            
	case Event.MOUSE_DRAG:
            if (dragging) {
                mouseDrag(evt.x, evt.y);
                retval = true;
            }
            break;
            
	case Event.MOUSE_UP:
            if (dragging) {
                mouseUp(evt.x, evt.y);
                retval = true;
            }
            break;
            
	case Event.LOST_FOCUS:
            // Don't allow the focus to get away!
            comp.requestFocus();
            // Intentional lack of break
	case Event.GOT_FOCUS:
            mouseMove(-1, -1);
            retval = true;
            break;
            
	case Event.MOUSE_MOVE:
            mouseMove(evt.x, evt.y);
            retval = true;
            break;
            
	case Event.KEY_PRESS:
	case Event.KEY_ACTION:
            keyPress(evt);
            // intentional lack of break
	case Event.KEY_RELEASE:
	case Event.KEY_ACTION_RELEASE:
            retval = true;
            break;
        }
        
        return retval;
    }
    
    private void mouseDown(int clickCount, int evtX, int evtY) {
        comp.requestFocus();
        
        switch (clickCount) {
	case 2:
            selectWord(evtX);
            break;
            
	case 3:
            selectLine();
            break;
            
	default:
            dragging = true;
            setCursorX(evtX);
            break;
        }
    }
    
    private void mouseDrag(int evtX, int evtY) {
        adjustSelection(evtX);
    }
    
    private void mouseUp(int evtX, int evtY) {
        mouseDrag(evtX, evtY);
        dragging = false;
        mouseMove(evtX, evtY);
        resetTimer();
    }
    
    private void mouseMove(int evtX, int evtY) {
        Frame f = getFrame();
        if (f == null)
            return;
        
        if (inside(evtX, evtY)) {
            if (f.getCursorType() != Frame.TEXT_CURSOR)
                f.setCursor(Frame.TEXT_CURSOR);
        } else {
            if (f.getCursorType() != Frame.DEFAULT_CURSOR)
                f.setCursor(Frame.DEFAULT_CURSOR);
        }
    }
    
    private void keyPress(Event evt) {
        boolean cacheText = false;
        boolean repaint = false;
        
        int key = evt.key;
        
        if (key == RETURN_KEY) {
            applyChanges();
            return;
        } else if (key == ESCAPE_KEY) {
            comp.postEvent(new Event(this, CANCEL, null));
            return;
        }
        
        int len = text.length();
        
        switch (key) {
	case Event.HOME:
            if (cursorPos != 0) {
                setCursorPos(0);
                repaint = true;
            }
            break;
            
	case Event.END:
            if (cursorPos != len) {
                setCursorPos(len);
                repaint = true;
            }
            break;
            
	case Event.LEFT:
            if (cursorPos != 0) {
                setCursorPos(cursorPos-1);
                repaint = true;
            }
            break;
            
	case Event.RIGHT:
            if (cursorPos != len) {
                setCursorPos(cursorPos+1);
                repaint = true;
            }
            break;
            
	case BACKSPACE_KEY:
            if (deleteSelection()) {
                cacheText = true;
            } else if (cursorPos != 0) {
                text = text.substring(0, cursorPos-1) +
		    text.substring(cursorPos);
                cursorPos--;
                selectPos--;
                cacheText = true;
            }
            break;
            
	case DELETE_KEY:
            if (deleteSelection()) {
                cacheText = true;
            } else if (cursorPos != len) {
                text = text.substring(0, cursorPos) +
		    text.substring(cursorPos+1);
                cacheText = true;
            }
            break;
            
	default:
            if ((evt.modifiers & ~Event.SHIFT_MASK) == 0 &&
		(key >= 32 && key <= 127)) {
                deleteSelection();
                text = text.substring(0, cursorPos) +
		    String.valueOf((char)key) +
		    text.substring(cursorPos);
                cursorPos++;
                selectPos++;
                cacheText = true;
            }
            break;
        }
        
        if (cacheText)
            cacheText();
        else if (repaint)
            repaint();
    }
    
    private boolean deleteSelection() {
        if (selectPos != cursorPos) {
            int start = selectStart();
            int end = selectEnd();
            text = text.substring(0, start) + text.substring(end);
            setCursorPos(start);
            return true;
        } else {
            return false;
        }
    }
    
    private void selectWord(int evtX) {
        int pos = getCursorPos(evtX);
        selectPos = getWordStart(pos);
        cursorPos = getWordEnd(pos);
        makeVisible(cursorPos);
        repaint();
    }
    
    private int getWordStart(int pos) {
        int i;
        boolean hitChar = false;
        
        for (i = (pos-1); i >= 0; i--) {
            char c = text.charAt(i);
            if (hitChar && Character.isSpace(c))
                break;
            else if (!hitChar && !Character.isSpace(c))
                hitChar = true;
        }
        
        return i+1;
    }
    
    private int getWordEnd(int pos) {
        int i;
        boolean hitSpace = false;
        int len = text.length();
        int start = Math.max(pos-1, 0);
        
        for (i = start; i < len; i++) {
            char c = text.charAt(i);
            if (hitSpace && !Character.isSpace(c))
                break;
            else if (!hitSpace && Character.isSpace(c))
                hitSpace = true;
        }
        
        return i;
    }
    
    private void selectLine() {
        selectPos = 0;
        cursorPos = text.length();
        repaint();
    }
    
    private Frame getFrame() {
        Component c = comp;
        if (frame == null) {
            while (c != null && !(c instanceof Frame))
                c = c.getParent();
            frame = (Frame)c;
        }
        return frame;
    }
    
    public Point location() {
        return new Point(x, y);
    }
    
    public Dimension size() {
        return new Dimension(w, h);
    }
    
    private void setCursorX(int evtX) {
        setCursorPos(getCursorPos(evtX));
        repaint();
    }
    
    private void setCursorPos(int pos) {
        cursorPos = pos;
        selectPos = pos;
        makeVisible(cursorPos);
        resetTimer();
    }
    
    private void adjustSelection(int evtX) {
        int pos = getCursorPos(evtX);
        if (cursorPos != pos) {
            cursorPos = pos;
            makeVisible(cursorPos);
            repaint();
        }
    }
    
    private boolean makeVisible(int pos) {
        if (pos < scrollPos) {
            scrollPos = Math.max(pos-6, 0);
            return true;
        } else if (pos > scrollPos) {
            int width = metrics.stringWidth(text.substring(
							   scrollPos, pos));
            if (width >= (w-3)) {
                int old = scrollPos;
                scrollPos = getScrollPos(pos, w-40);
                return true;
            }
        }
        
        return false;
    }
    
    private synchronized void resetTimer() {
        cursorState = true;
        cursorTime = System.currentTimeMillis();
        notify();
    }
    
    private int getCursorPos(int evtX) {
        int len = text.length();
        int beginW = metrics.stringWidth(text.substring(0, scrollPos));
        
        int xoff = evtX - x - XOFF + beginW;
        return findCursorOffset(xoff, text, len/2, 0, len);
    }
    
    private int findCursorOffset(int xoff, String str,
				 int cur, int lower, int upper) {
        if (lower == upper) {
            return lower;
        } else if (lower == (upper-1)) {
            int lw = metrics.stringWidth(str.substring(0, lower));
            int uw = metrics.stringWidth(str.substring(0, upper));
            
            if ((xoff - lw) < (uw - xoff))
                return lower;
            else
                return upper;
        }
        
        int width = metrics.stringWidth(str.substring(0, cur));
        
        if (width > xoff)
            return findCursorOffset(xoff, str, cur - (cur-lower)/2,
				    lower, cur);
        else
            return findCursorOffset(xoff, str, cur + (upper-cur)/2,
				    cur, upper);
    }
    
    private int getScrollPos(int pos, int textW) {
        String str = text.substring(scrollPos);
        int offset = pos - scrollPos;
        if (offset <= 0)
            return scrollPos;
        
        pos = findScrollOffset(textW, str, offset, offset/2, 0, offset);
        return (scrollPos + pos);
    }
    
    private int findScrollOffset(int textW, String str, int len,
				 int cur, int lower, int upper) {
        if (lower == upper) {
            return lower;
        } else if (lower == (upper-1)) {
            int lw = metrics.stringWidth(str.substring(lower, len));
            int uw = metrics.stringWidth(str.substring(upper, len));
            if ((lw-textW) < (textW-uw))
                return lower;
            else
                return upper;
        }
        
        int width = metrics.stringWidth(str.substring(cur, len));
        if (width > textW)
            return findScrollOffset(textW, str, len,
				    cur + (upper-cur)/2, cur, upper);
        else
            return findScrollOffset(textW, str, len,
				    cur - (cur-lower)/2, lower, cur);
    }
    
    private boolean inside(int evtX, int evtY) {
        return (evtX >= x && evtX <= (x+w) &&
		evtY >= y && evtY <= (y+h));
    }
    
    private int selectStart() {
        return Math.min(selectPos, cursorPos);
    }
    
    private int selectEnd() {
        return Math.max(selectPos, cursorPos);
    }
    
    public void repaint() {
        repaint(null);
    }
    
    // If "rect" is non-null, then the component is expected to repaint
    // the area define by the rectangle.  The coordinates
    // in the rectangle
    // are relative to the component's coordinate space.
    public void repaint(Rectangle rect) {
        comp.postEvent(new Event(this, REPAINT, rect));
    }
    
    public synchronized void paint(Graphics g) {
        g = g.create();
        g.translate(x, y);
        g.setFont(getFont());
        
        if (paintCursor) {
            if (cursorState)
                g.setColor(getForeground());
            else
                g.setColor(getBackground());
            
            int xoff =
		metrics.stringWidth(text.substring(scrollPos,
						   cursorPos)) + XOFF;
            g.fillRect(xoff, YPAD/2, 1, h-YPAD);
            
            paintCursor = false;
            return;
        }
        
        if (bg != null) {
            g.setColor(getBackground());
            g.fillRect(0, 0, w, h);
        } else {
            g.clearRect(0, 0, w, h);
        }
        
        g.setColor(getForeground());
        g.drawRect(0, 0, w-1, h-1);
        
        int xoff = XOFF;
        int yoff = h - YPAD/2 - metrics.getDescent();
        if (Global.isMotif())
            yoff -= 1;
        
        int start = selectStart();
        int end = selectEnd();
        
        if (start == end) {
            String str = text.substring(scrollPos);
            g.drawString(str, XOFF, yoff);
            
            if (cursorState) {
                xoff += metrics.stringWidth(text.substring(scrollPos,
							   cursorPos));
                g.fillRect(xoff, YPAD/2, 1, h-YPAD);
            }
        } else {
            
            // Draw first unselected segment
            if (start > scrollPos) {
                g.drawString(text.substring(scrollPos, start),
			     xoff, yoff);
                xoff += metrics.stringWidth(text.substring(
							   scrollPos, start));
            }
            
            // Draw selected segment
            String selectStr = text.substring(Math.max(start,
						       scrollPos), end);
            int selectW = metrics.stringWidth(selectStr);
            
            g.setColor(new Color(0, 0, 128));
            g.fillRect(xoff, YPAD/2, selectW, h-YPAD);
            g.setColor(Color.white);
            g.drawString(selectStr, xoff, yoff);
            
            if (cursorState)
                g.setColor(getForeground());
            
            if (cursorPos == end)
                xoff += selectW;
            
            // Draw the cursor
            g.fillRect(xoff, YPAD/2, 1, h-YPAD);
            
            if (cursorPos == start)
                xoff += selectW;
            
            if (!cursorState)
                g.setColor(getForeground());
            
            // Draw last unselected segment
            int length = text.length();
            if (end < length) {
                g.drawString(text.substring(end), xoff, yoff);
            }
        }
    }
    
    public synchronized void run() {
        long waitTime = CURSOR_DELAY;
        
        while (Thread.currentThread() == cursorThread) {
            try {
                wait(waitTime);
            }
            catch (InterruptedException ex) {
            }
            
            comp.requestFocus();
            
            if (dragging) {
                waitTime = 0;
            } else {
                long diff = System.currentTimeMillis() - cursorTime;
                if (diff >= CURSOR_DELAY) {
                    waitTime = CURSOR_DELAY;
                    cursorState = !cursorState;
                    cursorTime = System.currentTimeMillis();
                    paintCursor = true;
                    repaint();
                } else {
                    waitTime = CURSOR_DELAY - diff;
                }
            }
        }
    }
    
    public synchronized void destroy() {
        cursorThread = null;
        notify();
        
        Frame f = getFrame();
        if (f != null && f.getCursorType() != Frame.DEFAULT_CURSOR)
            f.setCursor(Frame.DEFAULT_CURSOR);
    }
    
    protected void finalize() {
        destroy();
    }
}
