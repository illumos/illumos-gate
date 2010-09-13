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
 * @(#) VJPanel.java 1.31 - last change made 08/25/97
 */

package sunsoft.jws.visual.rt.awt;

import sunsoft.jws.visual.rt.base.*;
import java.awt.*;
import java.util.Hashtable;

public class VJPanel extends Panel {
    // Relief constants
    public static final int RELIEF_FLAT   = Util.RELIEF_FLAT;
    public static final int RELIEF_RAISED = Util.RELIEF_RAISED;
    public static final int RELIEF_SUNKEN = Util.RELIEF_SUNKEN;
    public static final int RELIEF_RIDGE  = Util.RELIEF_RIDGE;
    public static final int RELIEF_GROOVE = Util.RELIEF_GROOVE;
    public static final int WIN95_RAISED = Util.WIN95_RAISED;
    public static final int WIN95_SUNKEN = Util.WIN95_SUNKEN;
    /* BEGIN JSTYLED */
    public static final int WIN95_FIELD_BORDER = Util.WIN95_FIELD_BORDER;
    public static final int WIN95_WINDOW_BORDER = Util.WIN95_WINDOW_BORDER;
    /* END JSTYLED */
    public static final int BLACK_BORDER = Util.BLACK_BORDER;
    
    // Alignment constants
    public static final int LEFT = Label.LEFT;
    public static final int CENTER = Label.CENTER;
    public static final int RIGHT = Label.RIGHT;
    
    // Drawing constants
    private static final int labelpadx = 10;
    private static final int labelipadx = 4;
    private static final int labelpadtop = 2;
    
    // Maker event
    private static final int MARKER_EVENT = 83250;
    
    // Multiply factor for darker color
    private static double FACTOR = 0.85;
    
    // request focus workaround for Windows
    static boolean isMouseDown;
    
    // click count adjustment
    private static final int CLICK_TIMEOUT = 400;
    private static final int CLICK_DISTANCE = 2;
    private static int clickCount = 1;
    private static long clickTime = 0;
    private static long clickWhen = -1;
    private static int clickX, clickY;
    
    // Relief
    private int relief;
    
    // Border width
    int borderWidth;
    
    // Label for the upper border of the panel
    private String borderLabel;
    
    // Alignment for the borderLabel
    private int labelAlignment;
    
    // Insets between the border decoration and the child components
    private Insets borderInsets;
    
    //
    // Event forwarding to groups.
    //
    // The MARKER_EVENT stuff is necessary because AWT is broken.  For
    // example, say a key is pressed in a textfield.  All of the parents
    // of the textfield get a chance at the event before the textfield's
    // peer.  If any of the parents returns true from handleEvent, then
    // the peer never sees the event.
    //
    // VJPanel overrides postEvent instead of handleEvent.  handleEvent
    // would have been overridden if it we possible to return true from
    // handleEvent and not screw up AWT.  Since this is not the case, it
    // becomes necessary to override postEvent instead of handleEvent,
    // to ensure that all AWT event handling has taken place everywhere
    // before the event is forwarded to the shadow (and from there to
    // the group).
    //
    // The panel cannot return true from postEvent or else no one
    // will ever see the event.  Therefore, postEvent returns false,
    // and the MARKER_EVENT stuff ensures that the event doesn't get
    // delivered twice.
    //
    //
    
    /**
     * markEvent - Marks events that should be forwarded to the shadow.
     *
     * Returns true if the event has been marked, false otherwise.
     */
    public static boolean markEvent(Event evt, Component comp) {
        //
        // Check for events that are already marked
        //
        Event e = evt.evt;
        while (e != null) {
            if (e.id == MARKER_EVENT)
                return false;
            e = e.evt;
        }
        
        //
        // Figure out the mgr to send the mesage to, and also figure
        // out the target for the message.
        //
        Object messageTarget = null;
        AttributeManager mgr = null;
        Hashtable shadowTable = DesignerAccess.getShadowTable();
        
        if (evt.target != null) {
            mgr = (AttributeManager)shadowTable.get(evt.target);
            messageTarget = mgr;
        }
        if (mgr == null) {
            mgr = (AttributeManager)shadowTable.get(comp);
            messageTarget = evt.target;
        }
        
        //
        // If we found a mgr, then mark the event and return true.
        // Otherwise, return false.
        //
        if (mgr != null) {
            Message msg = new Message(messageTarget, /* NOI18N */"AWT",
				      evt, true);
            
            e = evt;
            while (e.evt != null)
                e = e.evt;
            e.evt = new Event(mgr, MARKER_EVENT, msg);
            
            e.evt.x = e.x;
            e.evt.y = e.y;
            
            return true;
        } else {
            return false;
        }
    }
    
    /**
     * forwardEvent - Forwards marked events to the shadow
     */
    public static void forwardEvent(Event evt, Component comp) {
        // Find the marker event and remove it
        Event p = evt;
        Event e = evt;
        while (e.evt != null) {
            p = e;
            e = e.evt;
        }
        p.evt = null;
        
        // Make sure we have a marked event
        if (e.id != MARKER_EVENT) {
            throw new Error(
			    /* JSTYLED */
			    Global.fmtMsg("sunsoft.jws.visual.rt.awt.VJPanel.UnmarkedEvent", "forwardEvent"));
        }
        
        // Need to untranslate the (x,y) for the event.
        evt.x = e.x;
        evt.y = e.y;
        
        Component target = null;
        if (evt.target instanceof Component)
            target = (Component)evt.target;
        
        while (target != null && target != comp) {
            Container parent = target.getParent();
            if (parent == null) {
                // We didn't hit comp on the way up the tree,
                // so don't translate
                evt.x = e.x;
                evt.y = e.y;
                break;
            }
            
            translateEvent(evt, target, parent, true);
            target = parent;
        }
        
        // Fix the click count
        fixClickCount(evt);
        
        // Send the message
        AttributeManager mgr = (AttributeManager)e.target;
        mgr.postMessage((Message)e.arg);
    }
    
    // Windows workaround:  The location of most
    // components gets totally
    // screwed up on Windows.  The solution is to
    // use the location in the
    // GBConstraints instead.  This version of
    // postEvent translates events
    // according to the GBConstraints location variable.
    public boolean postEvent(Event e) {
        // Fix the click count
        fixClickCount(e);
        
        if (e.id == Event.MOUSE_DOWN)
            VJPanel.isMouseDown = true;
        else if (e.id == Event.MOUSE_UP)
            VJPanel.isMouseDown = false;
        
        boolean marked = markEvent(e, this);
        boolean handled = doPostEvent(e);
        if (marked)
            VJPanel.forwardEvent(e, this);
        
        return handled;
    }
    
    private boolean doPostEvent(Event e) {
        boolean handled = false;
        
        if (Global.isWindows()) {
            if (handleEvent(e)) {
                handled = true;
            } else {
                Container parent = getParent();
                if (parent != null) {
                    translateEvent(e, this, parent);
                    
                    if (parent.postEvent(e)) {
                        handled = true;
                    }
                }
            }
        } else {
            handled = super.postEvent(e);
        }
        
        return handled;
    }
    
    
    //
    // This is a workaround for two different problems.
    //
    // The first problem is that on Motif, the
    // click count sometimes does
    // not work.  Sometimes is does sort of work,
    // but you have to double-
    // click REALLY fast.  This workaround adjusts
    // the clickCount according
    // to a reasonable click timeout.
    //
    // The second problem is that on Windows you can get double-clicks
    // even if the second click is at a different x,y
    // location than the first
    // click.  This workaround makes sure that
    // if the clicks are far apart,
    // then it isn't a double click.
    //
    
    static void fixClickCount(Event evt) {
        if (evt.id != Event.MOUSE_DOWN || evt.when == clickWhen)
            return;
        
        if (Global.isMotif()) {
            long curtime = System.currentTimeMillis();
            if (evt.when == 0)
                evt.when = curtime;
            
            int d = Math.abs(clickX - evt.x) + Math.abs(clickY - evt.y);
            
            if ((curtime - clickTime) < CLICK_TIMEOUT
		&& (d <= CLICK_DISTANCE)) {
                clickCount++;
                evt.clickCount = clickCount;
            } else {
                clickCount = 1;
            }
            
            if (evt.clickCount == 1)
                evt.clickCount = clickCount;
            clickTime = curtime;
            clickWhen = evt.when;
            clickX = evt.x;
            clickY = evt.y;
        } else if (Global.isWindows()) {
            long curtime = System.currentTimeMillis();
            if (evt.when == 0)
                evt.when = curtime;
            
            int d = Math.abs(clickX - evt.x) + Math.abs(clickY - evt.y);
            
            if (d > CLICK_DISTANCE) {
                evt.clickCount = 1;
            }
            
            clickWhen = evt.when;
            clickX = evt.x;
            clickY = evt.y;
        }
    }
    
    public void translateEvent(Event e, Component child,
			       Container parent) {
        translateEvent(e, child, parent, false);
    }
    
    private static void translateEvent(Event e,
				       Component child, Container parent,
				       boolean negate) {
        
        LayoutManager parentMgr = parent.getLayout();
        
        // Translate the event using the location
        // from the GridBagLayout,
        // if available.  This solves the location problem if you use
        // GridBagLayout for all your containers.
        if (parentMgr instanceof GBLayout) {
            GBLayout gb = (GBLayout)parentMgr;
            GBConstraints c = gb.getConstraints(child);
            
            Point p = null;
            if (c != null)
                p = c.location;
            if (p == null)
                p = child.location();
            
            if (negate)
                e.translate(-p.x, -p.y);
            else
                e.translate(p.x, p.y);
        } else {
            Point p = child.location();
            if (negate)
                e.translate(-p.x, -p.y);
            else
                e.translate(p.x, p.y);
        }
    }
    
    //
    // Constructor
    //
    
    public VJPanel() {
        relief = Util.RELIEF_FLAT;
        borderLabel = null;
        borderWidth = 2;
        borderInsets = new Insets(5, 5, 5, 5);
        labelAlignment = LEFT;
    }
    
    public VJPanel(int relief) {
        this();
        setRelief(relief);
    }
    
    public VJPanel(int relief, String label) {
        this(relief);
        setBorderLabel(label);
    }
    
    public VJPanel(int relief, String label,
		   int borderWidth, Insets borderInsets) {
        this(relief, label);
        setBorderWidth(borderWidth);
        setBorderInsets(borderInsets);
    }
    
    //
    // Children that are not visible should
    // not be layed out.  The reason
    // for this is that layout managers ignore non-visible components,
    // therefore non-visible components do not get reshaped.
    //
    // In the case of a non-visible, non-container component, there is
    // no problem.  But if you have a non-visible container, then the
    // layout method should not be called on that container.   But AWT
    // ignores visibility and calls layout on
    // all containers regardless.
    //
    // The problem with this is that a non-visible container will not
    // have been reshaped when its parent was layed out.  Therefore,
    // calling layout on this container causes it to do a layout based
    // on its own bogus size.  This means that all the child components
    // get reshaped and validated with incorrect sizes!  If the
    // non-visible container is later made
    // visible, all of its components
    // are already valid so they don't get layed out again.  But these
    // components have incorrect sizes.
    //
    // This workaround ensures that layout is not called on non-visible
    // children of the container.
    //
    public void validate() {
        if (!isValid() && getPeer() != null) {
            layout();
            
            // Unfortunately, we don't have access to the valid flag.
            // Fortunately, it is okay to leave the component invalid.
            //
            // Components in an AWT application
            // are invalid most of the time
            // anyways, because if any child component invalidate, then
            // all the parents are invalidated.  And there are many
            // situations where a child calls
            // invalidate where you don't
            // want to call validate again.  So many components end up
            // invalid all the time.  This is okay, because
            // it just means
            // that if you do call validate, then everything will get
            // layed out again.
            
            // valid = true;
        }
        
        int ncomponents = countComponents();
        for (int i = 0; i < ncomponents; i++) {
            Component comp = getComponent(i);
            if (!comp.isValid() && comp.getPeer() !=
		null && comp.isVisible()) {
                comp.validate();
            }
        }
    }
    
    protected void validateTree() {
        if (!isValid() && getPeer() != null) {
            layout();
            
            int ncomponents = countComponents();
            for (int i = 0; i < ncomponents; ++i) {
                Component comp = getComponent(i);
                if ((comp instanceof Container) &&
		    !(comp instanceof Window) &&
		    (!comp.isValid() && comp.getPeer() != null) &&
		    comp.isVisible()) {
                    ((Container)comp).validate();
                }
            }
        }
    }
    
    // Workaround for idiotic JDK1.1 bug where if you add a
    // component to a container that it is already in, then
    // the component will be removed from the container!
    //
    // #ifdef JDK1.1
    protected void addImpl(Component comp, Object constraints,
			   int index) {
        if (comp.getParent() != this)
            super.addImpl(comp, constraints, index);
    }
    // #endif
    
    public void setRelief(int relief) {
        this.relief = relief;
        
        // Need to invalidate because changing
        // from a flat relief to something
        // else will cause the preferredSize to change.
	invalidate();
        repaint();
    }
    
    public int getRelief() {
        return relief;
    }
    
    public void setBorderWidth(int borderWidth) {
        if (borderWidth != this.borderWidth) {
            this.borderWidth = borderWidth;
            invalidate();
            repaint();
        }
    }
    
    public int getBorderWidth() {
        return borderWidth;
    }
    
    public void setBorderLabel(String label) {
        borderLabel = label;
        invalidate();
        repaint();
    }
    
    public String getBorderLabel() {
        return borderLabel;
    }
    
    public void setLabelAlignment(int alignment) {
        labelAlignment = alignment;
        repaint();
    }
    
    public int getLabelAlignment() {
        return labelAlignment;
    }
    
    public void setBorderInsets(Insets insets) {
        if (insets == null)
            this.borderInsets = new Insets(0, 0, 0, 0);
        else
            this.borderInsets = (Insets)insets.clone();
        invalidate();
    }
    
    public Insets getBorderInsets() {
        return (Insets)borderInsets.clone();
    }
    
    public Insets insets() {
        int bd = getBD();
        int h = getLabelAdjustedTop();
        Insets insets = getAdjustedInsets();
        
        return new Insets(h + insets.top,
			  bd + insets.left,
			  bd + insets.bottom,
			  bd + insets.right);
    }
    
    public Dimension minimumSize() {
        Dimension d = super.minimumSize();
        int w = getLabelAdjustedMinWidth();
        if (w > d.width)
            d = new Dimension(w, d.height);
        return d;
    }
    
    public Dimension preferredSize() {
        Dimension d = super.preferredSize();
        int w = getLabelAdjustedMinWidth();
        if (w > d.width)
            d = new Dimension(w, d.height);
        return d;
    }
    
    private int getBD() {
        int bd = 0;
        if (relief != Util.RELIEF_FLAT || borderLabel != null)
            bd = borderWidth;
        return bd;
    }
    
    private Insets getAdjustedInsets() {
        Insets insets;
        if (relief == Util.RELIEF_FLAT && borderLabel == null)
            insets = new Insets(0, 0, 0, 0);
        else
            insets = borderInsets;
        return insets;
    }
    
    private int getLabelAdjustedTop() {
        if (relief == Util.RELIEF_FLAT && borderLabel == null)
            return 0;
        
        int bd = borderWidth;
        int top = bd;
        Font font = getFont();
        
        if (borderLabel != null && font != null) {
            FontMetrics fm = getFontMetrics(font);
            top = fm.getAscent() + fm.getDescent() + labelpadtop;
            
            if (!isLabelInBorder())
                top += bd;
            else if (top < bd)
                top = bd;
        }
        
        return top;
    }
    
    private int getLabelAdjustedMinWidth() {
        if (relief == Util.RELIEF_FLAT && borderLabel == null)
            return 0;
        
        int bd = borderWidth;
        int w = 2*bd + borderInsets.left + borderInsets.right;
        
        Font font = getFont();
        if (borderLabel != null && font != null) {
            FontMetrics fm = getFontMetrics(font);
            w = Math.max(w, 2*bd + fm.stringWidth(borderLabel)
			 + labelpadx + labelipadx);
        }
        
        return w;
    }
    
    private boolean isLabelInBorder() {
        switch (relief) {
	case Util.RELIEF_RAISED:
	case Util.RELIEF_SUNKEN:
	case Util.WIN95_RAISED:
	case Util.WIN95_SUNKEN:
	case Util.WIN95_FIELD_BORDER:
	case Util.WIN95_WINDOW_BORDER:
            return false;
            
	case Util.RELIEF_GROOVE:
	case Util.RELIEF_RIDGE:
	case Util.BLACK_BORDER:
	case Util.RELIEF_FLAT:
	default:
            return true;
        }
    }
    
    public void update(Graphics g) {
        if (Global.isWindows())
            g = getGraphics();
        Dimension size = size();
        Insets insets = insets();
        
        g.setColor(getBackground());
        if (insets.left > 0)
            g.fillRect(0, 0, insets.left, size.height);
        if (insets.top > 0)
            g.fillRect(0, 0, size.width, insets.top);
        if (insets.bottom > 0)
            g.fillRect(0, size.height-insets.bottom,
		       size.width, insets.bottom);
        if (insets.right > 0)
            g.fillRect(size.width-insets.right, 0,
		       insets.right, size.height);
        
        paint(g);
    }
    
    public void paint(Graphics g) {
        // XXX This workaround is needed for both
        // Windows and Solaris to ensure
        //     all lightweight components contained
        // within VJPanel are repainted
        //     correctly;  For some reasons, VJPanel
        // is entirely filled with
        //     the background color whenever update()
        // is called.  If only the
        //     components within the clip region
        // of the "Graphics g" parameter
        //     is repainted, then the other lightweight
        // components become
        //     invisible because they get painted
        // over with the VJPanel background.
        //     The obvious suspect for filling
        // the VJPanel background is the
        //     fillRect calls in update(), but
        // the problem exists even when
        //     those fillRect calls are not executed.  See bug 4074362.
        g = getGraphics();
        // end of workaround
        
        super.paint(g);
        
        Dimension size = size();
        Insets insets = insets();
        int bd = borderWidth;
        
        FontMetrics fm = null;
        if (borderLabel != null) {
            fm = getFontMetrics(getFont());
        }
        
        // Draw the border
        if (relief != Util.RELIEF_FLAT && bd > 0) {
            switch (relief) {
	    case Util.RELIEF_FLAT:
	    case Util.RELIEF_RAISED:
	    case Util.RELIEF_SUNKEN:
	    case Util.RELIEF_RIDGE:
	    case Util.RELIEF_GROOVE:
	    case Util.WIN95_RAISED:
	    case Util.WIN95_SUNKEN:
	    case Util.BLACK_BORDER:
                g.setColor(getBackground());
                break;
                
	    case Util.WIN95_FIELD_BORDER:
	    case Util.WIN95_WINDOW_BORDER:
                g.setColor(getParent().getBackground());
                break;
            }
            int yoff = 0;
            if (borderLabel != null) {
                int ascent = fm.getAscent();
                int descent = fm.getDescent();
                
                if (isLabelInBorder())
                    yoff = (ascent + descent + labelpadtop - bd)/2;
                else
                    yoff = ascent + descent + labelpadtop;
                
                if (yoff < 0)
                    yoff = 0;
            }
            
            Global.util.draw3DRect(g, 0, yoff,
				   size.width-1, size.height-1-yoff,
				   relief, bd);
        }
        
        // Draw the label
        if (borderLabel != null) {
            int stringWidth = fm.stringWidth(borderLabel);
            int ascent = fm.getAscent();
            int descent = fm.getDescent();
            int x, y, h;
            
            switch (labelAlignment) {
	    case LEFT:
	    default:
                x = bd + (labelpadx + labelipadx)/2;
                break;
	    case CENTER:
                x = (size.width - stringWidth)/2;
                break;
	    case RIGHT:
                x = size.width - (stringWidth + (labelpadx
						 + labelipadx)/2 + bd);
                break;
            }
            
            y = labelpadtop + ascent;
            h = labelpadtop + ascent + descent;
            
            if (isLabelInBorder() && bd > h) {
                y = (bd - h)/2 + (labelpadtop + ascent);
                h = bd;
            }
            
            g.setColor(getBackground());
            g.fillRect(x - labelipadx/2, 0, stringWidth +
		       labelipadx, h);
            
            g.setColor(getForeground());
            g.setFont(getFont());
            g.drawString(borderLabel, x, y-1);
        }
    }
    
    //
    // Workaround for Windows95 AWT bug:  If you call
    // request focus while
    // the mouse is pressed, you get spurious
    // mouse down events.  Not only
    // that, but the spurious events have
    // clickCount set to 2, so you end
    // up with spurious double clicks.  On Windows95 the component
    // automatically gets the focus when you press the mouse inside it.
    // Therefore, it isn't necessary to call
    // requestFocus at all if running
    // on Windows and the mouse is down (and this avoids the bug).
    //
    public void requestFocus() {
        if (!Global.isWindows() || !VJPanel.isMouseDown)
            super.requestFocus();
    }
}
