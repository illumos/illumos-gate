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
 * @(#) RootFrame.java 1.50 - last change made 07/25/97
 */

package sunsoft.jws.visual.rt.awt;

import sunsoft.jws.visual.rt.base.DesignerAccess;
import sunsoft.jws.visual.rt.base.*;

import java.awt.*;

public class RootFrame extends Frame implements RootWindow {
    
    private Point location = new Point(0, 0);
    
    private boolean skipValidate = false;
    
    /* BEGIN JSTYLED */
    //
    // The ignoreShow and ignoreHide flags are used as part of a workaround
    // for an AWT problem with iconify and deiconify events.  An infinite
    // loop can happen under certain circumstances without this workaround.
    //
    // When hide is called on a window that is currently showing, AWT will
    // deliver a WINDOW_ICONIFY event.  Similarly, when show is called on a
    // window that is currently hidden, AWT will deliver a WINDOW_DEICONIFY
    // event.  (Note that in JDK1.0.2, iconify events are not delivered with
    // Windows95, but they are delivered with Motif).
    //
    // Now say that you have a callback for WINDOW_ICONIFY that hides
    // the window, and a callback for WINDOW_DEICONIFY that shows the
    // window.  Normally this is ok because calling hide on a hidden window
    // will not cause an iconify event to be delivered, and calling show
    // on a mapped window will not cause a deiconify event to be delivered.
    //
    // But if the user iconifies and deiconifies a window while the
    // application is busy, then a WINDOW_ICONIFY event and a
    // WINDOW_DEICONIFY event will both be in the event queue at the same
    // time.  When the WINDOW_ICONIFY event is then handled, calling hide
    // on the window will cause another WINDOW_ICONIFY event to be delivered
    // because the window is currently showing.  Then, when the
    // WINDOW_DEICONIFY is handled, show will be called causing another
    // WINDOW_DEICONIFY event to be delivered.  You then go into an infinite
    // loop with the window mapping and unmapping itself.
    //
    // The solution is to never allow hide to be called in the callback
    // from  a WINDOW_ICONIFY event, and never allow show to be called
    // in the callback from a WINDOW_DEICONIFY event.
    //
    /* END JSTYLED */
    private boolean ignoreShow = false;
    private boolean ignoreHide = false;
    
    // Give windows a nice looking border.
    static {
        if (Global.isWindows95())
            GBLayout.setWindowInsets(new Insets(1, 1, 1, 1));
        else if (Global.isWindowsNT())
            GBLayout.setWindowInsets(new Insets(2, 3, 2, 3));
        else
            GBLayout.setWindowInsets(new Insets(4, 4, 4, 4));
    }
    
    private RWHelper helper;
    private Group subGroup;
    
    public RootFrame() {
        super();
        initHelper();
    }
    
    public RootFrame(String title) {
        super(title);
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
    
    /**
     * The subgroup is set on the bogus frames that are put around
     * panel groups when the panel groups are running standalone.
     * This situation only occurs when the generated main for a
     * panel group is run from the command line.
     */
    public void setSubGroup(Group subGroup) {
        this.subGroup = subGroup;
    }
    
    /**
     * Returns the subgroup.  The subgroup is non-null for frames
     * that are used as wrappers for panel groups.
     */
    public Group getSubGroup() {
        return subGroup;
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
     * Workaround: Return the correct window location for Motif.
     */
    public Point location() {
        if (Global.isMotif())
            return new Point(location.x, location.y);
        else
            return super.location();
    }
    
    /**
     * Update the location.
     */
    public void reshape(int x, int y, int w, int h) {
        super.reshape(x, y, w, h);
        location = new Point(x, y);
    }
    
    /**
     * Event forwarding to groups.
     *
     * (see comment in GBPanel.java)
     */
    public boolean postEvent(Event evt) {
        // See the comment at the top of the file
        // for ignoreShow and ignoreHide
        if (evt.id == Event.WINDOW_ICONIFY)
            ignoreHide = true;
        else if (evt.id == Event.WINDOW_DEICONIFY)
            ignoreShow = true;
        
        boolean marked = VJPanel.markEvent(evt, this);
        boolean handled = super.postEvent(evt);
        
        if (marked)
            VJPanel.forwardEvent(evt, this);
        
        // See the comment at the top of the file
        // for ignoreShow and ignoreHide
        if (evt.id == Event.WINDOW_ICONIFY)
            ignoreHide = false;
        else if (evt.id == Event.WINDOW_DEICONIFY)
            ignoreShow = false;
        
        return handled;
    }
    
    public boolean handleEvent(Event evt) {
        if (evt.id == Event.WINDOW_DESTROY) {
            if (subGroup != null) {
                subGroup.postMessage(new Message(
			 DesignerAccess.getContainer(subGroup), /* NOI18N */
						 "AWT", evt, true));
                return true;
            }
        } else if (evt.target == this && evt.id == Event.WINDOW_MOVED) {
            // The CDE window manager screws
            // up the window location sometimes.
            // The bug can be avoided by ignoring
            // WINDOW_MOVED events that have
            // the coordinates (0,0).
            if (evt.x != 0 && evt.y != 0)
                location = new Point(evt.x, evt.y);
        }
        
        return super.handleEvent(evt);
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
        if (helper != null)
            helper.addNotify();
        super.addNotify();
    }
    
    public void removeNotify() {
        if (helper != null)
            helper.removeNotify();
        super.removeNotify();
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
    
    public void show() {
        // See the comment at the top of the file
        // for ignoreShow and ignoreHide
        if (ignoreShow)
            return;
        
        //
        // Call show only if it is necessary.
        // When the peer's show method
        // is called, the peer will call validate
        // back on the AWT component.
        //
        if (isShowing()) {
            if (!Global.isWindows())
                toFront();
            return;
        }
        
        skipValidate = true;
        super.show();
        skipValidate = false;
    }
    
    public void hide() {
        // See the comment at the top of the file
        // for ignoreShow and ignoreHide
        if (!ignoreHide)
            super.hide();
    }
    
    /**
     * Don't do a validate during a show.
     */
    public void validate() {
        if (!skipValidate)
            super.validate();
    }
    
    /**
     * Add some extra to the top inset if we are 
     * on Windows and the frame
     * has a menubar.  There is an AWT bug that
     * causes the top insets to
     * be too small when there is a menubar.
     */
    public Insets insets() {
        Insets insets = (Insets)super.insets().clone();
        if (Global.isWindows() && getMenuBar() != null &&
	    insets.top < 30)
	    insets.top += 30;
        return insets;
    }
}
