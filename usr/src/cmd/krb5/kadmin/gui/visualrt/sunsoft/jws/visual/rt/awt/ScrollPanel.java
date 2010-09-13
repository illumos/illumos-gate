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
 * @(#) ScrollPanel.java 1.41 - last change made 07/25/97
 */

package sunsoft.jws.visual.rt.awt;

import sunsoft.jws.visual.rt.awt.*;
import sunsoft.jws.visual.rt.base.Global;
import sunsoft.jws.visual.rt.base.Util;
import java.awt.*;

public class ScrollPanel extends VJPanel {
    protected VJScrollbar vbar, hbar;
    
    private Component comp;
    private boolean vshow, hshow;
    private GBLayout gridbag;
    private boolean hasFocus;
    
    private int scrollAreaWidth = 0;
    private int scrollAreaHeight = 0;
    private Insets scrollAreaInsets;
    
    public ScrollPanel() {
        super(Util.WIN95_FIELD_BORDER);
        setBorderInsets(new Insets(0, 0, 0, 0));
        
        GBConstraints c = new GBConstraints();
        gridbag = new GBLayout();
        setLayout(gridbag);
        
        hbar = new VJScrollbar(VJScrollbar.HORIZONTAL);
        vbar = new VJScrollbar(VJScrollbar.VERTICAL);
        
        c.gridx = 1;
        c.gridy = 0;
        c.shrinkx = false;
        c.shrinky = true;
        c.fill = GBConstraints.VERTICAL;
        
        // #ifdef JDK1.1
        super.addImpl(vbar, null, -1);
        // #else
	// super.add(vbar, -1);
        // #endif
        
        gridbag.setConstraints(vbar, c);
        
        c.gridx = 0;
        c.gridy = 1;
        c.shrinkx = true;
        c.shrinky = false;
        c.fill = GBConstraints.HORIZONTAL;
        
        // #ifdef JDK1.1
        super.addImpl(hbar, null, -1);
        // #else
	// super.add(hbar, -1);
        // #endif
        
        gridbag.setConstraints(hbar, c);
        
        // Have the initial minimumSize include the vertical scrollbar,
        // but not the horizontal scrollbar.
        vshow = true;
        hbar.hide();
    }
    
    // #ifdef JDK1.1
    protected void addImpl(Component comp, Object constraints,
			   int index) {
        super.addImpl(comp, constraints, index);
        doAdd(comp);
    }
    // #else
    // public Component add(Component comp, int pos) {
    //   super.add(comp, pos);
    //   doAdd(comp);
    //   return comp;
    // }
    // #endif
    
    private void doAdd(Component comp) {
        if (!(comp instanceof Scrollable))
            throw new Error(Global.getMsg(
		  "sunsoft.jws.visual.rt.awt.ScrollPanel.OnlyOneInstance"));
        
        if (this.comp != null)
            remove(this.comp);
        
        this.comp = comp;
        
        GBConstraints c = new GBConstraints();
        c.gridx = 0;
        c.gridy = 0;
        c.weightx = 1;
        c.weighty = 1;
        c.shrinkx = true;
        c.shrinky = true;
        c.fill = GBConstraints.BOTH;
        c.insets = scrollAreaInsets;
        
        gridbag.setConstraints(comp, c);
    }
    
    public int getScrollAreaWidth() {
        return scrollAreaWidth;
    }
    
    public void setScrollAreaWidth(int scrollAreaWidth) {
        this.scrollAreaWidth = scrollAreaWidth;
    }
    
    public int getScrollAreaHeight() {
        return scrollAreaHeight;
    }
    
    public void setScrollAreaHeight(int scrollAreaHeight) {
        this.scrollAreaHeight = scrollAreaHeight;
    }
    
    public Insets getScrollAreaInsets() {
        return scrollAreaInsets;
    }
    
    public void setScrollAreaInsets(Insets insets) {
        scrollAreaInsets = insets;
        
        if (comp != null) {
            GBConstraints c = gridbag.getConstraints(comp);
            c.insets = insets;
            gridbag.setConstraints(comp, c);
        }
    }
    
    public int getVisibleIndex() {
        if (!vshow)
            return 0;
        
        int lineHeight = ((Scrollable)comp).lineHeight();
        int scrolly = vbar.getValue();
        
        return (scrolly+lineHeight-1)/lineHeight;
    }
    
    public void makeVisible(int index) {
        if (!vshow)
            return;
        
        if (index == -1)
            return;
        
        Scrollable scrollable = (Scrollable)comp;
        Dimension viewSize = scrollable.viewSize(comp.size());
        int lineHeight = scrollable.lineHeight();
        int y = lineHeight*index;
        int scrolly = vbar.getValue();
        
        if (y < scrolly) {
            vbar.setValue(y);
            scrollable.scrollY(y);
        } else if ((y + lineHeight) > scrolly + viewSize.height) {
            y -= (viewSize.height - lineHeight);
            if (y < 0)
                y = 0;
            vbar.setValue(y);
            scrollable.scrollY(y);
        }
    }
    
    public boolean handleEvent(Event e) {
        if (e.id == Event.GOT_FOCUS) {
            hasFocus = true;
            return super.handleEvent(e);
        } else if (e.id == Event.LOST_FOCUS) {
            hasFocus = false;
            return super.handleEvent(e);
        } else if (e.target == hbar)
            ((Scrollable)comp).scrollX(hbar.getValue());
        else if (e.target == vbar)
            ((Scrollable)comp).scrollY(vbar.getValue());
        else
            return super.handleEvent(e);
        
        return true;
    }
    
    private Dimension viewSize() {
        Dimension size = size();
        size = new Dimension(size.width, size.height);
        
        // take out our insets
        Insets insets = insets();
        Insets scrollAreaInsets = getScrollAreaInsets();
        if (scrollAreaInsets == null)
            scrollAreaInsets = new Insets(0, 0, 0, 0);
        
        size.width -= (insets.left + insets.right +
		       scrollAreaInsets.left + scrollAreaInsets.right);
        size.height -= (insets.top + insets.bottom +
			scrollAreaInsets.top + scrollAreaInsets.bottom);
        
        return ((Scrollable)comp).viewSize(size);
    }
    
    // Always leave space for the scrollbars
    public Dimension minimumSize() {
        Dimension compMin;
        Dimension hbarMin = hbar.minimumSize();
        Dimension vbarMin = vbar.minimumSize();
        
        if (comp != null) {
            compMin = comp.minimumSize();
            compMin = new Dimension(compMin.width, compMin.height);
        }
        else
            compMin = new Dimension(0, 0);
        
        return calcSize(compMin, hbarMin, vbarMin);
    }
    
    // Always leave space for the scrollbars
    public Dimension preferredSize() {
        Dimension compPref;
        Dimension hbarPref = hbar.preferredSize();
        Dimension vbarPref = vbar.preferredSize();
        
        if (comp != null) {
            compPref = comp.preferredSize();
            compPref = new Dimension(compPref.width, compPref.height);
        }
        else
            compPref = new Dimension(0, 0);
        
        return calcSize(compPref, hbarPref, vbarPref);
    }
    
    private Dimension calcSize(Dimension compMin,
			       Dimension hbarMin, Dimension vbarMin) {
        Insets insets = insets();
        Insets scrollAreaInsets = getScrollAreaInsets();
        if (scrollAreaInsets == null)
            scrollAreaInsets = new Insets(0, 0, 0, 0);
        
        if (scrollAreaWidth != 0)
            compMin.width = scrollAreaWidth;
        if (scrollAreaHeight != 0)
            compMin.height = scrollAreaHeight;
        
        int insetsWidth = insets.left + insets.right +
	    scrollAreaInsets.left + scrollAreaInsets.right;
        compMin.width += (vbarMin.width + insetsWidth);
        compMin.width = Math.max(compMin.width, (hbarMin.width +
						 insetsWidth));
        
        int insetsHeight = insets.top + insets.bottom +
	    scrollAreaInsets.top + scrollAreaInsets.bottom;
        compMin.height += (hbarMin.height + insetsHeight);
        compMin.height = Math.max(compMin.height, (vbarMin.height +
						   insetsHeight));
        
        return compMin;
    }
    
    public void layout() {
        boolean hadFocus = hasFocus;
        
        Dimension viewSize = viewSize();
        if (viewSize.width <= 0 || viewSize.height <= 0) {
            super.layout();
            return;
        }
        
        Dimension d;
        Dimension scrollSize = ((Scrollable)comp).scrollSize();
        boolean needHShow = false, needVShow = false;
        boolean revalidate = false;
        
        if (viewSize.width < scrollSize.width)
            needHShow = true;
        if (viewSize.height < scrollSize.height)
            needVShow = true;
        
        if ((needHShow || needVShow) && !(needHShow && needVShow)) {
            if (needVShow) {
                d = vbar.minimumSize();
                if (viewSize.width < (scrollSize.width + d.width))
                    needHShow = true;
            } else if (needHShow) {
                d = hbar.minimumSize();
                if (viewSize.height < (scrollSize.height + d.height))
                    needVShow = true;
            }
        }
        
        if (needHShow) {
            if (!hshow) {
                hbar.show();
                hshow = true;
                revalidate = true;
            }
        } else {
            if (hshow) {
                hbar.hide();
                hshow = false;
                revalidate = true;
                if (hbar.getValue() != 0)
                    hbar.setValue(0);
                ((Scrollable)comp).scrollX(0);
            }
        }
        
        if (needVShow) {
            if (!vshow) {
                vbar.show();
                vshow = true;
                revalidate = true;
            }
        } else {
            if (vshow) {
                vbar.hide();
                vshow = false;
                revalidate = true;
                if (vbar.getValue() != 0)
                    vbar.setValue(0);
                ((Scrollable)comp).scrollY(0);
            }
        }
        
        if (hshow)
            updateHScrollbar();
        if (vshow)
            updateVScrollbar();
        
        if (revalidate) {
            validate();
            if (hadFocus && Global.isMotif())
                comp.requestFocus();
        } else {
            super.layout();
        }
    }
    
    public void updateWindow() {
        invalidate();
        validate();
    }
    
    protected void updateHScrollbar() {
        Dimension viewSize = viewSize();
        Dimension scrollSize = ((Scrollable)comp).scrollSize();
        
        if (vshow) {
            Dimension d = vbar.minimumSize();
            viewSize.width -= d.width;
        }
        
        // (viewSize.width-d.width) can become negative
        // during initialization
        if (viewSize.width < 1)
            return;
        
        int maximum = scrollSize.width;
        // #ifndef MAXIMUM_HACK
        // maximum -= viewSize.width;
        // #endif
        
        hbar.setValues(hbar.getValue(), viewSize.width, 0, maximum);
        
        Scrollable scrollable = (Scrollable)comp;
        int lineWidth = Math.max(10, viewSize.width/6);
        int pageSize = Math.max(lineWidth, viewSize.width - lineWidth);
        pageSize = Math.min(scrollSize.width - viewSize.width,
			    pageSize);
        
        hbar.setLineIncrement(lineWidth);
        hbar.setPageIncrement(pageSize);
        
        scrollable.scrollX(hbar.getValue());
    }
    
    protected void updateVScrollbar() {
        Dimension viewSize = viewSize();
        Dimension scrollSize = ((Scrollable)comp).scrollSize();
        
        if (hshow) {
            Dimension d = hbar.minimumSize();
            viewSize.height -= d.height;
        }
        
        // (viewSize.height-d.height) can become
        // negative during initialization
        if (viewSize.height < 1)
            return;
        
        int maximum = scrollSize.height;
        // #ifndef MAXIMUM_HACK
        // maximum -= viewSize.height;
        // #endif
        vbar.setValues(vbar.getValue(), viewSize.height, 0, maximum);
        
        Scrollable scrollable = (Scrollable)comp;
        int lineHeight = scrollable.lineHeight();
        int pageSize =
	    Math.max(lineHeight,
		     (viewSize.height/lineHeight)*lineHeight - lineHeight);
        pageSize = Math.min(scrollSize.height-viewSize.height,
			    pageSize);
        
        vbar.setLineIncrement(lineHeight);
        vbar.setPageIncrement(pageSize);
        
        scrollable.scrollY(vbar.getValue());
    }
}
