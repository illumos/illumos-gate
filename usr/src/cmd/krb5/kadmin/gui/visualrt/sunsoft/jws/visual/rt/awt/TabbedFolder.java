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
 * @(#) TabbedFolder.java 1.20 - last change made 08/04/97
 */

package sunsoft.jws.visual.rt.awt;

import sunsoft.jws.visual.rt.base.Global;

import java.awt.*;
import java.util.*;

public class TabbedFolder extends CardPanel {
    
    public static final int CONFIRM_SWITCH = 4862;
    
    //
    // Constants used for drawing the tabs
    //
    
    private static final int bd = 2;
    private static final double BFACTOR = 0.8;
    private static final double DFACTOR = 0.7;
    
    private static final int tabipadx = 14;
    private static final int tabipady = 14;
    private static final int comppadx = 20;
    private static final int comppady = 14;
    private static final Insets folderInsets = new Insets(6, 6, 6, 6);
    
    //
    // Cached tab information
    //
    
    private Image buffer;
    private int tabx[];
    private String tabtext[];
    private int tabW, tabH;
    private boolean cancelSwitch = false;
    
    
    public TabbedFolder() {
    }
    
    public TabbedFolder(String tabs[]) {
        for (int i = 0; i < tabs.length; i++) {
            super.addTab(tabs[i]);
        }
    }
    
    protected Label newCardLabel() {
        return new Label(Global.getMsg(
		"sunsoft.jws.visual.rt.awt.TabbedFolder.NewCardLabel"));
    }
    
    //
    // Methods that comprise the public interface for TabbedFolder
    //
    
    public void addTab(String tab) {
        super.addTab(tab);
        flushCache();
        repaint();
    }
    
    public void addTab(String tab, int index) {
        super.addTab(tab, index);
        flushCache();
        repaint();
    }
    
    public void renameTab(String oldName, String newName) {
        super.renameTab(oldName, newName);
        flushCache();
        repaint();
    }
    
    public void removeTab(String tab) {
        super.removeTab(tab);
        flushCache();
        repaint();
    }
    
    public void removeAllTabs() {
        super.removeAllTabs();
        flushCache();
        repaint();
    }
    
    public String getCurrentFolder() {
        return getCurrentCard();
    }
    
    public void show(String tab) {
        super.show(tab);
        repaint();
    }
    
    //
    // Overridden methods from Component
    //
    
    public void addNotify() {
        super.addNotify();
        flushCache();
    }
    
    public void removeNotify() {
        super.removeNotify();
        flushCache();
    }
    
    public void setFont(Font font) {
        super.setFont(font);
        flushCache();
    }
    
    public Dimension minimumSize() {
        cacheTabInfo();
        
        Dimension d = super.minimumSize();
        int w = tabW + folderInsets.left + folderInsets.right;
        if (w > d.width)
            d = new Dimension(w, d.height);
        
        return d;
    }
    
    public Dimension preferredSize() {
        cacheTabInfo();
        
        Dimension d = super.preferredSize();
        int w = tabW + folderInsets.left + folderInsets.right;
        if (w > d.width)
            d = new Dimension(w, d.height);
        
        return d;
    }
    
    public Insets insets() {
        cacheTabInfo();
        
        Insets insets = new Insets(0, 0, 0, 0);
        insets.left = folderInsets.left + bd + comppadx/2;
        insets.right = folderInsets.right + bd + comppadx/2;
        insets.top = folderInsets.top + tabH + comppady/2;
        insets.bottom = folderInsets.bottom + bd + comppady/2;
        
        return insets;
    }
    
    //
    // Event Handling
    //
    
    public boolean mouseDown(Event evt, int x, int y) {
        int index = calcTabIndex(x, y);
        if (index >= 0 && index < tabs.size()) {
            String name = (String)tabs.elementAt(index);
            
            cancelSwitch = false;
            postEvent(new Event(this, CONFIRM_SWITCH, name));
            
            if (!cancelSwitch) {
                show(name);
                postEvent(new Event(this, Event.ACTION_EVENT, name));
            } else {
                cancelSwitch = false;
            }
        }
        
        return false;
    }
    
    public void cancelSwitch() {
        cancelSwitch = true;
    }
    
    private synchronized int calcTabIndex(int x, int y) {
        cacheTabInfo();
        
        if (x < (folderInsets.left+tabx[0]) ||
	    x > (folderInsets.left+tabx[tabx.length-1])) {
            return -1;
        }
        if (y < (folderInsets.top+bd) || y > (folderInsets.top+tabH)) {
            return -1;
        }
        
        for (int i = 0; i < tabtext.length; i++) {
            if (x >= (folderInsets.left+tabx[i]) &&
		x <= (folderInsets.left + tabx[i+1])) {
                return i;
            }
        }
        
        return -1;
    }
    
    //
    // Cache all the information and the image needed for the tabs.
    //
    
    private synchronized void cacheTabInfo() {
        if (tabx == null) {
            if (getPeer() == null)
                return;
            
            FontMetrics fontMetrics = getFontMetrics(getFont());
            int len = tabs.size();
            
            if (len == 0) {
                tabx = new int[2];
                tabtext = new String[1];
                tabtext[0] = Global.getMsg(
			   "sunsoft.jws.visual.rt.awt.TabbedFolder.Empty");
                tabx[0] = bd;
                tabx[1] = tabx[0] +
		    fontMetrics.stringWidth(tabtext[0]) + tabipadx + 2*bd;
            } else {
                Enumeration e = tabs.elements();
                int i = 0;
                int x = bd;
                tabx = new int[tabs.size()+1];
                tabtext = new String[tabs.size()];
                
                while (e.hasMoreElements()) {
                    tabtext[i] = (String)e.nextElement();
                    tabx[i] = x;
                    x += fontMetrics.stringWidth(tabtext[i]) +
			tabipadx + 2*bd;
                    i++;
                }
                tabx[i] = x;
            }
            
            // Need 4 extra pixels: 2 on each end
            tabW = tabx[tabx.length-1] - tabx[0] + 2*bd;
            
            // Need 6 extra pixels: 4 on top, and 2 on the bottom
            tabH = fontMetrics.getMaxAscent() + tabipady + 3*bd;
            
            // Create the image buffer
            buffer = createImage(tabW, tabH);
        }
    }
    
    private synchronized void flushCache() {
        tabx = null;
        tabtext = null;
        tabW = 0;
        tabH = 0;
        buffer = null;
        if (isValid())
            invalidate();
    }
    
    //
    // Drawing methods
    //
    
    public void update(Graphics g) {
        if (Global.isWindows())
            g = getGraphics();
        
        cacheTabInfo();
        Dimension size = size();
        int x, y;
        
        x = folderInsets.left + tabW;
        y = folderInsets.top + tabH;
        
        // Clear the background
        g.setColor(getBackground());
        g.fillRect(0, 0, size.width, folderInsets.top);
        g.fillRect(0, y, size.width, size.height-y);
        g.fillRect(0, 0, folderInsets.left, size.height);
        g.fillRect(x, 0, size.width-x, size.height);
        
        draw(g);
    }
    
    public void paint(Graphics g) {
        if (Global.isWindows())
            g = getGraphics();
        draw(g);
    }
    
    private synchronized void draw(Graphics g) {
        cacheTabInfo();
        Dimension size = size();
        
        if (buffer != null) {
            drawTabs(size);
            g.drawImage(buffer, folderInsets.left,
			folderInsets.top, null);
        }
        
        drawBox(g, size);
    }
    
    private synchronized void drawTabs(Dimension size) {
        Graphics g = buffer.getGraphics();
        String card = getCurrentCard();
        int selIndex = -1;
        if (card != null)
            selIndex = tabs.indexOf(card);
        
        g.setColor(getBackground());
        g.fillRect(0, 0, tabW, tabH);
        
        for (int i = 0; i < tabtext.length; i++) {
            if (i != selIndex) {
                drawTab(g, i, false);
            }
        }
        
        for (int i = 0; i < tabtext.length; i++) {
            if (i == selIndex) {
                drawTab(g, i, true);
                break;
            }
        }
        
        // Draw the left extra bit
        g.setColor(brighter(getBackground()));
        g.fillRect(0, tabH-bd, bd, bd);
        
        // Draw the right extra bit
        int rightEdge = tabx[tabx.length-1];
        if ((size.width - tabW) > (folderInsets.left +
				   folderInsets.right)) {
            // The corner does not lie within the image.
            // This can happen
            // when the tabs do not completely fill
            // the top of the folder.
            g.setColor(brighter(getBackground()));
            g.fillRect(tabW-bd, tabH-bd, bd, bd);
        } else {
            drawUpperRightCorner(g, tabW-bd, tabH-bd);
        }
    }
    
    private void drawUpperRightCorner(Graphics g, int x, int y) {
        String card = getCurrentCard();
        int selIndex = -1;
        if (card != null)
            selIndex = tabs.indexOf(card);
        
        g.setColor(darker(getBackground()));
        fillRect(g, x, y, bd, bd);
        
        int size = tabs.size();
        if (size == 0 || selIndex != size-1) {
            g.setColor(brighter(getBackground()));
            fillRect(g, x, y, 1, 1);
        }
    }
    
    private void drawTab(Graphics g, int index, boolean selected) {
        int x = tabx[index];
        int y = bd;
        int w = tabx[index+1]-tabx[index]-1;
        int h = tabH-bd-1;
        
        if (selected) {
            x -= bd;
            y -= bd;
            w += 2*bd;
            h += 2*bd;
        }
        
        g.setColor(getBackground());
        draw3DOuterTab(g, x, y, w, h, selected);
        draw3DInnerTab(g, x+1, y+1, w-2, h-2, selected);
        
        x = tabx[index] + bd + (tabipadx/2);
        y = tabH - bd - tabipady/2;
        if (selected)
            y -= bd;
        
        g.setColor(getForeground());
        g.setFont(getFont());
        g.drawString(tabtext[index], x, y-1);
    }
    
    private void drawBox(Graphics g, Dimension size) {
        int x = folderInsets.left;
        int y = folderInsets.top + tabH;
        int w = size.width - (folderInsets.left +
			      folderInsets.right) - 1;
        int h = size.height - (tabH + folderInsets.top +
			       folderInsets.bottom) - 1;
        
        if (x >= size.width || y >= size.height || w <= 0 || h <= 0)
            return;
        
        g.setColor(getBackground());
        draw3DU(g, x, y, w, h, true);
        
        // Draw the extra line on the top-right side if the tab image
        // does not cover the area.  The tab image is only as wide as
        // the tabs, so we need to account for any possible extra space
        // here.
        if ((size.width - tabW) > (folderInsets.left +
				   folderInsets.right)) {
            g.setColor(brighter(getBackground()));
            fillRect(g, folderInsets.left + tabW,
		     folderInsets.top + tabH - bd,
		     size.width - (folderInsets.left + folderInsets.right +
				   tabW),
		     bd);
            drawUpperRightCorner(g,
				 size.width - folderInsets.right - bd,
				 folderInsets.top + tabH - bd);
        }
    }
    
    private void draw3DU(Graphics g, int x, int y, int width,
			 int height, boolean raised) {
        Color c = g.getColor();
        Color brighter = brighter(c);
        Color darker = darker(c);
        
        g.setColor(raised ? brighter : darker);
        g.drawLine(x, y, x, y + height);
        g.drawLine(x+1, y, x+1, y + height);
        
        g.setColor(raised ? darker : brighter);
        g.drawLine(x + 1, y + height, x + width, y + height);
        g.drawLine(x + 2, y + height - 1, x + width - 1,
		   y + height - 1);
        
        g.drawLine(x + width, y, x + width, y + height - 1);
        g.drawLine(x + width - 1, y, x + width - 1, y + height - 1);
        g.setColor(c);
    }
    
    private void draw3DInnerTab(Graphics g,
				int x, int y, int width, int height,
				boolean selected) {
        Color c = g.getColor();
        Color brighter = brighter(c);
        Color darker = darker(c);
        
        g.setColor(brighter);
        g.drawLine(x, y, x, y + height);
        g.drawLine(x + 1, y, x + width - 1, y);
        if (!selected)
            g.drawLine(x + 1, y + height, x + width + 1, y + height);
        g.setColor(darker);
        g.drawLine(x + width, y, x + width, y + height - 1);
        g.setColor(c);
    }
    
    private void draw3DOuterTab(Graphics g,
				int x, int y, int width, int height,
				boolean selected) {
        Color c = g.getColor();
        Color brighter = brighter(c);
        Color darker = darker(c);
        
        // Left, Top, Bottom, Right
        
        g.setColor(brighter);
        g.drawLine(x, y + 2, x, y + height);
        g.drawLine(x + 2, y, x + width - 2, y);
        if (!selected)
            g.drawLine(x + 1, y + height, x + width, y + height);
        g.setColor(darker);
        g.drawLine(x + width, y + 2, x + width, y + height - 2);
        g.setColor(c);
    }
    
    /**
     * Returns a brighter version of this color.
     */
    private Color brighter(Color c) {
        // fix for bug where the brighter color doesn't show up
        // against a white background The Util.brighter will return
        // new Color(<some light grey>) for whites.
        return Global.util.brighter(c);
    }
    
    /**
     * Returns a darker version of this color.
     */
    private Color darker(Color c) {
        return new Color(Math.max((int)(c.getRed()  *DFACTOR), 0),
			 Math.max((int)(c.getGreen()*DFACTOR), 0),
			 Math.max((int)(c.getBlue() *DFACTOR), 0));
    }
    
    // Workaround for Windows fillRect bug.
    // The Windows fillRect sometimes
    // fills the lower-right edges when it shouldn't.
    // The bug appears to
    // only happen is certain situations.  It does
    // not seem to happen when
    // drawing inside an off-screen buffer.
    private void fillRect(Graphics g, int x, int y, int w, int h) {
        if (Global.isWindows()) {
            w -= 1;
            h -= 1;
            g.drawRect(x, y, w, h);
        }
        g.fillRect(x, y, w, h);
    }
}
