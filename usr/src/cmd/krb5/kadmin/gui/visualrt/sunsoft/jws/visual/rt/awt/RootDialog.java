/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 *        Copyright (C) 1996  Active Software, Inc.
 *                  All rights reserved.
 *
 * @(#) RootDialog.java 1.44 - last change made 06/19/97
 */

package sunsoft.jws.visual.rt.awt;

import sunsoft.jws.visual.rt.base.DesignerAccess;
import sunsoft.jws.visual.rt.base.*;

import java.awt.*;

public class RootDialog extends Dialog implements RootWindow {
    private RWHelper helper;
    private Thread eventThread;
    
    public RootDialog(Frame parent, boolean modal) {
        super(parent, modal);
        initHelper();
    }
    
    public RootDialog(Frame parent, String title, boolean modal) {
        super(parent, title, modal);
        initHelper();
    }
    
    private void initHelper() {
        Class c = DesignerAccess.getRootWindowHelperClass();
        if (c != null) {
            try {
                helper = (RWHelper)c.newInstance();
                helper.setWindow(this);
            }
            catch (Exception ex) {
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
    
    /**
     * Make dialogs on Windows behave the same as
     * dialogs on Motif.
     */
    public void pack() {
        Component parent = getParent();
        Boolean dis = isDisplayable();
        
        if (parent != null && parent.isDisplayable() == false) {
            parent.addNotify();
        }
        if (dis.equals(false)) {
            addNotify();
        }

        Dimension d = getPreferredSize();
        Point p = getDialogLocation(d);
        
        // Adjust the location the first time the dialog is mapped after
        // the peer has been created.  There is an AWT bug that screws
        // up the location of the dialog, so we
        // have to make this adjustment.
        if (Global.isMotif() && dis.equals(false)) {
            p.x -= d.width/2;
            p.y -= d.height/2;
        }
        setLocation(p.x, p.y);
        
        setSize(getPreferredSize());
        validate();
    }
    
    private Point getDialogLocation(Dimension prefSize) {
        Frame frame = (Frame)getParent();
        Point p = frame.location();
        Dimension fsize = frame.size();
        Dimension dsize = prefSize;
        
        p.x += (fsize.width - dsize.width)/2;
        p.y += (fsize.height - dsize.height)/2;
        
        return p;
    }
    
    /**
     * Make sure the insets aren't screwed up on Windows.  The dialog
     * will come up too small the first time it is shown if we don't
     * fix the insets here.
     */
    public Insets insets() {
        Insets insets = (Insets)super.insets().clone();
        
        if (Global.isWindows()) {
            if (insets.top < 10)
                insets.top = 25;
            if (insets.bottom < 5)
                insets.bottom = 5;
            if (insets.left < 5)
                insets.left = 5;
            if (insets.right < 5)
                insets.right = 5;
        }
        
        return insets;
    }
    
    /**
     * Event forwarding to groups.
     *
     * (see comment in GBPanel.java)
     */
    public boolean postEvent(Event evt) {
	/* BEGIN JSTYLED */
	// AWT Bug: JDK-1.0 AWT gives a WINDOW_ICONIFY event to a Dialog
	// when it is shown (causing us to obediently iconify the windows in the
	// dialog's group, including the dialog iteself.)  AWT then gives a
	// WINDOW_DEICONFY event to the same Dialog, resulting in a show and an
	// infinite loop of hiding and showing.  Dialogs can't be iconfied
	// anyway, so just what is this event doing here!!?
	//
	// Work-around: throw away these two spurious events on Dialogs before
	// they can muck up the works.
	//
	/* END JSTYLED */
        if (evt.id == Event.WINDOW_ICONIFY ||
	    evt.id == Event.WINDOW_DEICONIFY)
	    return true;
        
        boolean marked = VJPanel.markEvent(evt, this);
        boolean handled = super.postEvent(evt);
        
        if (marked)
            VJPanel.forwardEvent(evt, this);
        return handled;
    }
    
    public void select() {
        if (helper != null)
            helper.select();
    }
    
    public void unselect() {
        if (helper != null)
            helper.unselect();
    }
    
    public void layoutMode() {
        if (helper != null)
            helper.layoutMode();
    }
    
    public void previewMode() {
        if (helper != null)
            helper.previewMode();
    }
    
    public Dimension previewSize() {
        if (helper != null)
            return helper.previewSize();
        else
            return null;
    }
    
    public void addNotify() {
        Component parent = getParent();
        if (parent != null && parent.getPeer() == null)
            parent.addNotify();
        
        if (helper != null)
            helper.addNotify();
        super.addNotify();
    }
    
    public void removeNotify() {
        if (Global.isWindows())
            reshapeZero(this);
        
        if (helper != null)
            helper.removeNotify();
        super.removeNotify();
    }
    
    /**
     * Recursively reshapes the component and all its children to zero.
     * You need to do this on Windows when removeNotify is called.
     * Otherwise when you call addNotify, the children are offset
     * about 25 extra pixels from the top on the window, and the bottom
     * 25 pixels will get clipped off.  I don't know why this happens,
     * but I do know that reshaping everything back to zero avoids
     * the problem.  I noticed the problem on WindowsNT, but not as
     * often on Windows95.
     */
    private void reshapeZero(Component comp) {
        comp.reshape(0, 0, 0, 0);
        
        if (comp instanceof Container) {
            Container cntr = (Container)comp;
            int count = cntr.countComponents();
            
            for (int i = 0; i < count; i++)
                reshapeZero(cntr.getComponent(i));
        }
    }
    
    public void layout() {
        if (helper != null)
            helper.layout();
        super.layout();
    }
    
    public void paint(Graphics g) {
        if (Global.isWindows())
            g = getGraphics();
        if (helper != null)
            helper.paint(g);
        super.paint(g);
    }
    
    public boolean mouseDown(Event evt, int x, int y) {
        if (helper != null)
            return helper.mouseDown(evt, x, y);
        return false;
    }
}
