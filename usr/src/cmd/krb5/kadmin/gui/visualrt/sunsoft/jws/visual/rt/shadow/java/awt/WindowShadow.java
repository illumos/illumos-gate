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
 * @(#) WindowShadow.java 1.119 - last change made 07/28/97
 */

package sunsoft.jws.visual.rt.shadow.java.awt;

import sunsoft.jws.visual.rt.base.*;
import sunsoft.jws.visual.rt.awt.*;
import sunsoft.jws.visual.rt.type.AnchorEnum;
import sunsoft.jws.visual.rt.base.Global;

import java.util.*;
import java.awt.*;

/* BEGIN JSTYLED */
/**
 * Wraps an AWT widget.  The attributes available for this
 * class are listed below.  In the type column, type names beginning
 * with "sunsoft.jws.visual.rt" have been abbreviated to begin with "rt".
 *
 * <pre>
 name            type                      default value
 -----------------------------------------------------------------------
 location        java.awt.Point            null
 size            java.awt.Dimension        null
 *  < /pre>
*
* location: location for the window, if the location is set before
* the window is mapped, then when the window is mapped, it will come
* up at the specified location.  If the location is set while the
* window is mapped, then window will immediately be moved to the new
* location.
*  < p>
* size: desired size for the window, if set before mapping, the
* window will later be mapped with this size.  However, the size
* dimensions are first checked to ensure that the dimensions are at
* least as big as the preferredSize. If set after mapping and
* non-null, the window will be resized to the new size after maxing
* with preferredSize.  "get" returns the value for the desired size,
* NOT the actual size of the window. The "size" attribute does not
* take effect when in layout mode.
*  < p>
* Check the super class for additional attributes.
*
* @see Window
* @version 1.119, 07/28/97
*/
/* END JSTYLED */

public class WindowShadow extends ContainerShadow {
    private static final int PADX = 100;
    private static final int PADY = 100;
    
    private static Point defaultLocation = new Point(100, 100);
    private static Dimension defaultSize = new Dimension(100, 100);
    
    private boolean packed = false;
    
    public static void setDefaultLocation(Point p) {
        defaultLocation = p;
    }
    
    public static Point getDefaultLocation() {
        return defaultLocation;
    }
    
    public static void setDefaultSize(Dimension d) {
        defaultSize = d;
    }
    
    public static Dimension getDefaultSize() {
        return defaultSize;
    }
    
    private boolean layoutMode = false;
    
    public WindowShadow() {
        attributes.remove(/* NOI18N */"GBConstraints");
        attributes.remove(/* NOI18N */"borderName");
        attributes.remove(/* NOI18N */"flowRank");
        attributes.remove(/* NOI18N */"anchor");
        attributes.remove(/* NOI18N */"insets");
        
        attributes.add(/* NOI18N */"visible",
		       /* NOI18N */"java.lang.Boolean", Boolean.TRUE, NONBODY);
        
        attributes.add(/* NOI18N */"location",
		       /* NOI18N */"java.awt.Point", null, 0);
        attributes.add(/* NOI18N */"layoutLocation",
		       /* NOI18N */"java.awt.Point", null, HIDDEN);
        attributes.add(/* NOI18N */"currentLocation",
		       /* NOI18N */"java.awt.Point", null,
		       HIDDEN | TRANSIENT | READONLY);
        
        attributes.add(/* NOI18N */"size",
		       /* NOI18N */"java.awt.Dimension", null, 0);
        attributes.add(/* NOI18N */"layoutSize",
		       /* NOI18N */"java.awt.Dimension", null, HIDDEN);
        attributes.add(/* NOI18N */"currentSize",
		       /* NOI18N */"java.awt.Dimension", null,
		       HIDDEN | TRANSIENT | READONLY);
    }
    
    protected boolean useLayoutLocation() {
        if (!layoutMode)
            return false;
        
        if (inDesignerRoot())
	    return true;
        
        Group g = getGroup();
        if (g == null)
            return false;
        
        if (DesignerAccess.getWindow(g) != this)
	    return false;
        
        return (g.inDesignerRoot());
    }
    
    protected boolean useLayoutSize() {
        return (layoutMode && inDesignerRoot());
    }
    
    protected Object getOnBody(String key) {
        Window win = (Window)body;
        
        if (key.equals(/* NOI18N */"location")) {
            return getFromTable(key);
        } else if (key.equals(/* NOI18N */"layoutLocation")) {
            if (useLayoutLocation()) {
                // fix for Sun bug #4037679: layout window locations
                // are not being remembered. This is because
                // win.location() returns the location that the window
                // was created with, rather than the screen location.
                // So if the window moved, the location() method
                // doesn't report the new location. However,
                // locationOnScreen() only works if the window is
                // actually showing. Otherwise it throws an exception.
                //   -- Simran. 5/7/97
                Point loc;
                try {
                    loc = win.getLocationOnScreen();
                } catch (IllegalComponentStateException e) {
                    loc = win.getLocation();
                }
                
                return loc;
            } else
                return getFromTable(key);
        } else if (key.equals(/* NOI18N */"currentLocation")) {
            return win.location();
        } else if (key.equals(/* NOI18N */"size")) {
            return getFromTable(key);
        } else if (key.equals(/* NOI18N */"layoutSize")) {
            if (useLayoutSize())
		return win.size();
            else
                return getFromTable(key);
        } else if (key.equals(/* NOI18N */"currentSize")) {
            return win.size();
        } else {
            return super.getOnBody(key);
        }
    }
    
    protected void setOnBody(String key, Object value) {
        Window win = (Window)body;
        
        if (key.equals(/* NOI18N */"location")) {
            putInTable(key, value);
            if (value != null && !useLayoutLocation()) {
                Point p = getWindowLocation(false);
                win.move(p.x, p.y);
            }
        } else if (key.equals(/* NOI18N */"layoutLocation")) {
            putInTable(key, value);
            if (value != null && useLayoutLocation()) {
                Point p = getWindowLocation(true);
                win.move(p.x, p.y);
            }
        } else if (key.equals(/* NOI18N */"size")) {
            putInTable(key, value);
            if (value != null && !useLayoutSize())
		win.resize(getWindowSize(win, false));
        } else if (key.equals(/* NOI18N */"layoutSize")) {
            putInTable(key, value);
            if (value != null && useLayoutSize())
		win.resize(getWindowSize(win, true));
        } else {
            super.setOnBody(key, value);
        }
    }
    
    // REMIND: if Window had a frame attribute like a dialog it could be
    // instantiated here (but would probably only work on Windows 96 at
    // the moment)
    public void createBody() {};
    
    protected void registerBody() {
        Window win = (Window)body;
        if (!(win.getLayout() instanceof GBLayout)) {
            GBLayout gridbag = new GBLayout();
            double w[] = {1};
            gridbag.columnWeights = w;
            gridbag.rowWeights = w;
            
            win.setLayout(gridbag);
        }
        
        super.registerBody();
    }
    
    protected void postCreate() {
        super.postCreate();
        
        if (body instanceof RootWindow) {
            if (layoutMode)
                ((RootWindow)body).layoutMode();
            else
                ((RootWindow)body).previewMode();
        }
        
        if (!doingShow())
	    showComponent(isVisible());
    }
    
    protected void preDestroy() {
        packed = false;
    }
    
    /**
     * Returns true if the window's group is currently visible,
     * and the window's visible attribute is set to true.
     */
    public boolean isVisible() {
        if (!hasAttribute(/* NOI18N */"visible"))
	    return false;
        
        Boolean v = (Boolean) getFromTable(/* NOI18N */"visible");
        if (!v.booleanValue())
	    return false;
        
        Group g = getRoot().getGroup();
        if (g != null)
            return g.isShowing();
        
        return true;
    }
    
    public void updateContainerAttribute(AttributeManager child,
					 String key, Object value) {
        if (key.equals(/* NOI18N */"anchor")) {
            GBConstraints c =
		(GBConstraints)child.get(/* NOI18N */"GBConstraints");
            if (c == null)
                return;
            
            int anchor = ((AnchorEnum)value).intValue();
            if (anchor != c.anchor) {
                c.anchor = anchor;
                child.set(/* NOI18N */"GBConstraints", c);
            }
        } else if (key.equals(/* NOI18N */"insets")) {
            GBConstraints c =
		(GBConstraints)child.get(/* NOI18N */"GBConstraints");
            if (c == null)
                return;
            
            Insets insets = (Insets)value;
            if (c.insets != insets) {
                c.insets = insets;
                child.set(/* NOI18N */"GBConstraints", c);
            }
        } else if (key.equals(/* NOI18N */"GBConstraints")) {
            GBConstraints c = (GBConstraints)value;
            if (c == null)
                c = new GBConstraints();
            
            Shadow s = (Shadow)child;
            Component comp = (Component)s.getBody();
            if (comp == null)
                return;
            
            int anchor =
		((AnchorEnum)child.get(/* NOI18N */"anchor")).intValue();
            c.anchor = anchor;
            c.insets = (Insets)child.get(/* NOI18N */"insets");
            
            GBLayout gb = (GBLayout)((Window)body).getLayout();
            gb.setConstraints(comp, c);
        }
    }
    
    public void pack() {
        checkCreate();
        
        // Get the body AFTER the call to checkCreate
        Window win = (Window)body;
        
        boolean hasPeer = (win.getPeer() != null);
        
        if (!hasPeer) {
            //
            // Workaround for SGI: When a frame is shown with size
            // (0,0), it will fill the entire screen area momentarily
            // until reshape is called.  This causes annoying
            // flickering behavior.
            //
            if (Global.isIrix()) {
                Dimension size = win.size();
                if (size.width == 0 || size.height == 0)
                    win.reshape(0, 0, 40, 40);
            }
            
            win.addNotify();
            
            Group g = getGroup();
            if (g != null && DesignerAccess.getWindow(g) == this)
		DesignerAccess.preValidate(g);
            
            preValidate();
        }
        
        // Reshape the window
        resizePreferredSize(win, hasPeer);
        
        // Validate the window.
        win.validate();
        
        // Set the packed flag to true
        packed = true;
    }
    
    /**
     * Shows the component.  Calling showComponent does not affect the
     * value of the visible attrbute.  You should use "show" instead of
     * "showComponent".  The only reason this method exists is that
     * Visual Java needs to use it in certain situations.
     */
    public void showComponent() {
        checkCreate();
        
        // Pack the window if necessary
        Window win = (Window)body;
        
        if (packed && win.getPeer() == null)
	    packed = false;
        
        if (!packed)
            pack();
        
        // Show the window
        win.show();
        
        // Usually, calling show() on a visible Window will bring it
        // to the front.  Unfortunately, it doesn't behave like this.
        if (Global.isWindows()) {
            win.toFront();
        }
        
        // Make sure the window shows up right away.  This tends to make
        // the user happier.
        win.getToolkit().sync();
    }
    
    protected void checkCreate() {
        // Call create if it hasn't already been called.
        if (!isCreated()) {
            doingShow = true;
            create();
            doingShow = false;
        }
    }
    
    private void resizePreferredSize(Window win, boolean hasPeer) {
        Point location = getWindowLocation(useLayoutLocation());
        Dimension size = getWindowSize(win, useLayoutSize());
        
        constrainToScreen(win, location, size);
        
        if (win instanceof Dialog) {
            // Adjust the location the first time the dialog is mapped
            // after the peer has been created.  There is an AWT bug
            // that screws up the location of the dialog, so we have
            // to make this adjustment.
            if (Global.isMotif() && !hasPeer) {
                location.x -= size.width/2;
                location.y -= size.height/2;
            }
            
            win.reshape(location.x, location.y, size.width, size.height);
        } else {
            if (hasPeer)
                win.resize(size.width, size.height);
            else
                win.reshape(location.x, location.y, size.width, size.height);
        }
    }
    
    private Point getDialogLocation(Dialog dialog) {
        Frame frame = (Frame)dialog.getParent();
        Point p = frame.location();
        Dimension fsize = frame.size();
        Dimension dsize = dialog.preferredSize();
        
        p.x += (fsize.width - dsize.width)/2;
        p.y += (fsize.height - dsize.height)/2;
        
        return p;
    }
    
    private Point getWindowLocation(boolean layoutLocation) {
        if (body instanceof Dialog)
            return getDialogLocation((Dialog)body);
        
        ContainerShadow panel = getPanel();
        Point location = null;
        
        if (layoutLocation) {
            if (panel != null)
                location = (Point) panel.get(/* NOI18N */"layoutLocation");
            else
                location = (Point) getFromTable(/* NOI18N */"layoutLocation");
            
            if (location == null)
                location = getDefaultLocation();
        } else {
            location = (Point) getFromTable(/* NOI18N */"location");
            
            if (location == null)
                location = getDefaultLocation();
        }
        
        return location;
    }
    
    private Dimension getWindowSize(Window win, boolean layoutSize) {
        ContainerShadow panel = getPanel();
        Dimension size;
        
        if (layoutSize) {
            if (panel != null)
                size = (Dimension) panel.get(/* NOI18N */"layoutSize");
            else
                size = (Dimension) getFromTable(/* NOI18N */"layoutSize");
            
            if (size == null)
                size = getDefaultSize();
        } else {
            Dimension prefSize = win.preferredSize();
            size = (Dimension) getFromTable(/* NOI18N */"size");
            
            if (size == null) {
                size = prefSize;
            } else {
                size.width = Math.max(size.width, prefSize.width);
                size.height = Math.max(size.height, prefSize.height);
            }
        }
        
        return size;
    }
    
    private void constrainToScreen(Window win, Point location, Dimension size) {
        // Constrain the window to fit on the screen
        Dimension screenSize = getScreenSize(win);
        
        int x = screenSize.width - size.width;
        if (location.x > x)
            location.x = x;
        if (location.x < 0)
            location.x = 0;
        
        int y = screenSize.height - size.height;
        if (location.y > y)
            location.y = y;
        if (location.y < 0)
            location.y = 0;
        
        int width = screenSize.width - location.x;
        if (size.width > width)
            size.width = width;
        
        int height = screenSize.height - location.y;
        if (size.height > height)
            size.height = height;
    }
    
    private Dimension getScreenSize(Window win) {
        Dimension d = win.getToolkit().getScreenSize();
        d.width -= 6;
        d.height -= 6;
        
        if (Global.isWindows95()) {
            // Subtract some extra space for the icon bar
            d.height -= 30;
        }
        
        return d;
    }
    
    private void recurseInvalidate(Component comp) {
        comp.invalidate();
        if (comp instanceof Container) {
            Container cntr = (Container)comp;
            int count = cntr.countComponents();
            for (int i = 0; i < count; i++)
                recurseInvalidate(cntr.getComponent(i));
        }
    }
    
    /**
     * Disposes of the AWT top-level window so that window system
     * resources are reclaimed.
     */
    protected void destroyBody() {
        //
        // Cache the location when the window is destroyed.
        //
        // "put" is called directly because "set" won't work if
        // "isPanel" is true.
        //
        if (useLayoutLocation()) {
            Point location = ((Window)body).location();
            putInTable(/* NOI18N */"layoutLocation", location);
        }
        
        ((Window)body).dispose();
        body = null;
    }
    
    /**
     * "isPanel" flag.  If this flag is set, then this frame exists only
     * to allow the panel to be edited in the builder.  When a saving or
     * generation is performed, this window should be omitted.
     */
    
    private boolean isPanel = false;
    private String prevTitle = /* NOI18N */"Unnamed Window";
    
    public boolean isPanel() {
        return isPanel;
    }
    
    public void isPanel(boolean isPanel) {
        if (this.isPanel != isPanel) {
            if (isPanel) {
                prevTitle = (String)get(/* NOI18N */"title");
                set(/* NOI18N */"title", /* NOI18N */"PANEL");
                this.isPanel = isPanel;		// this must be last
            } else {
                // Ordering is important here.  As soon as isPanel is
                // changed, the nature of this window changes (and
                // affects the isUniqueName call, for example.)  While
                // isPanel is still true, get("name") returns the name
                // of the surrounded panel.
                //
                this.isPanel = isPanel;		// this must be first
                
                // It is possible that a new frame has been imported
                // or created that has the same name as this one (that
                // was surrounding a panel and was invisible in the
                // hierarchy.)  Until a frame has isPanel set to
                // false, it is never included in a unique name check,
                // so make sure that the window's name is unique in
                // the Root tree.  If the frame isn't in a Root tree
                // then don't worry about it.
                //
                if (getRoot() != null) {
                    String name = (String) get(/* NOI18N */"name");
                    if ((name == null)
                        || !DesignerAccess.isUniqueName(getRoot(), name, this))
			set(/* NOI18N */"name",
			    DesignerAccess.getUniqueName(getRoot(), this));
                }
                
                set(/* NOI18N */"title", prevTitle);
            }
        }
    }
    
    /**
     * If the "isPanel" flag is set, all the attributes should come from
     * the child panel, not the frame.
     */
    
    public ContainerShadow getPanel() {
        if (!isPanel)
            return null;
        
        if (getChildCount() == 0)
	    return null;
        
        return (ContainerShadow)getChildList().nextElement();
    }
    
    // Bug 4054883 Mark Davison July 9, 1997
    // The next series of methods are implemented as a work around in which
    // attributes are set on the VJLayout frame instead of the GBPanel
    // if isPanel == false. This is just a quick and safe fix. The real solution
    // is to get rid of the isPanel flag and associated behaviour altogether.
    
    private static Class enclosingFrame = null;
    
    /**
     * Caching method which returns the enclosing frame (most likely VJLayout)
     */
    private Class getEnclosingFrameClass() {
        if (enclosingFrame == null)
            enclosingFrame = DesignerAccess.getFrameClass();
        
        return enclosingFrame;
    }
    
    /**
     * Tests to see if the object is an enclosing frame.
     */
    private boolean isEnclosingFrame(Object obj) {
        Class frame = getEnclosingFrameClass();
        if (frame != null && frame.isInstance(body))
	    return true;
        else
            return false;
    }
    
    /**
     * Puts the attribute on the enclosed PanelShadow rather than on the 
     * WindowShadow.
     * This bypasses the getPanel method because if VJLayout represents
     * a Frame
     * or Dialog, the attributes will be set on the VJLayout (which
     * is incorrect).
     */
    protected void setOnPanel(String key, Object value) {
        ContainerShadow panel = (ContainerShadow)getChildList().nextElement();
        if (panel != null && panel instanceof PanelShadow)
            panel.set(key, value);
    }
    
    /**
     * Retrieves the attributes from the panel thereby bypassing the
     * isPanel flag.
     */
    protected Object getOnPanel(String key) {
        ContainerShadow panel = (ContainerShadow)getChildList().nextElement();
        if (panel != null && panel instanceof PanelShadow)
            return panel.get(key);
        return null;
    }
    
    public void set(String key, Object value) {
        ContainerShadow panel = getPanel();
        
        if (panel != null &&
	    !key.equals(/* NOI18N */"location") &&
	    !key.equals(/* NOI18N */"layoutLocation") &&
	    !key.equals(/* NOI18N */"size") &&
	    !key.equals(/* NOI18N */"layoutSize")) {
            panel.set(key, value);
        } else if (key.equals(/* NOI18N */"visible")) {
            if (!hasAttribute(/* NOI18N */"visible"))
		return;
            
            Boolean oldValue, newValue;
            
            oldValue = (Boolean)get(/* NOI18N */"visible");
            newValue = (Boolean)value;
            
            // Don't let visible be set to false if we are the main
            // container and we are running inside vjava.
            if (inDesignerRoot() && isMainContainer()
		&& !newValue.booleanValue()) {
		    /* JSTYLED */
                throw new VJException(Global.getMsg("sunsoft.jws.visual.rt.awt.java.awt.WindowShadow.IllegalSetVisible"));
            }
            
            super.set(key, value);
            
            if (!doingShow()) {
                if (oldValue.booleanValue() != newValue.booleanValue()) {
                    showComponent(isVisible());
                }
            }
        } else {
            // If the body is an enclosing frame, the atributes should not be
            // set on the body.
            if (isEnclosingFrame(body)) {
                if (key.equals(/* NOI18N */"background") ||
		    key.equals(/* NOI18N */"foreground")) {
                    setOnPanel(key, value);
                    return;
                }
            }
            
            super.set(key, value);
        }
    }
    
    public Object get(String key) {
        ContainerShadow panel = getPanel();
        if (panel != null &&
	    !key.equals(/* NOI18N */"location") &&
	    !key.equals(/* NOI18N */"layoutLocation") &&
	    !key.equals(/* NOI18N */"size") &&
	    !key.equals(/* NOI18N */"layoutSize"))
	    return panel.get(key);
        else {
            // If the body is an enclosing frame, the atributes should
            // be retrieved from the panel.
            if (isEnclosingFrame(body)) {
                if (key.equals(/* NOI18N */"background") ||
		    key.equals(/* NOI18N */"foreground"))
		    return getOnPanel(key);
            }
            
            return super.get(key);
        }
    }
    
    public String getType(String key) {
        ContainerShadow panel = getPanel();
        if (panel != null)
            return panel.getType(key);
        else
            return super.getType(key);
    }
    
    public int getFlags(String key) {
        ContainerShadow panel = getPanel();
        if (panel != null)
            return panel.getFlags(key);
        else
            return super.getFlags(key);
    }
    
    public boolean hasAttribute(String key) {
        ContainerShadow panel = getPanel();
        if (panel != null)
            return panel.hasAttribute(key);
        else
            return super.hasAttribute(key);
    }
    
    public boolean hasAttribute(String key, String type) {
        ContainerShadow panel = getPanel();
        if (panel != null)
            return panel.hasAttribute(key, type);
        else
            return super.hasAttribute(key, type);
    }
    
    public AttributeList getAttributeList() {
        ContainerShadow panel = getPanel();
        if (panel != null)
            return panel.getAttributeList();
        else
            return super.getAttributeList();
    }
    
    public void refetchAttributeList() {
        ContainerShadow panel = getPanel();
        if (panel != null)
            panel.refetchAttributeList();
        else
            super.refetchAttributeList();
    }
    
    public void layoutMode() {
        super.layoutMode();
        setLayout(true);
    }
    
    public void previewMode() {
        super.previewMode();
        setPreview(true);
    }
    
    public void setLayout(boolean shouldResize) {
        if (layoutMode)
            return;
        
        layoutMode = true;
        
        if (body != null) {
            Window win = (Window)body;
            
            if (body instanceof RootWindow)
                ((RootWindow)body).layoutMode();
            
            if (shouldResize) {
                if (win.getPeer() != null) {
                    if (useLayoutLocation() || useLayoutSize()) {
                        Point p = getWindowLocation(useLayoutLocation());
                        Dimension d = getWindowSize(win, useLayoutSize());
                        win.reshape(p.x, p.y, d.width, d.height);
                    }
                }
                
                win.validate();
            }
        }
    }
    
    public void setPreview(boolean shouldResize) {
        if (!layoutMode)
            return;
        
        if (body != null) {
            Window win = (Window)body;
            
            if (win instanceof RootWindow)
                ((RootWindow)win).previewMode();
            
            if (shouldResize) {
                if (win.getPeer() != null) {
                    if (useLayoutLocation()) {
                        putInTable(/* NOI18N */"layoutLocation",
				   win.location());
                    }
                    if (useLayoutSize()) {
                        putInTable(/* NOI18N */"layoutSize", win.size());
                    }
                    
                    if (useLayoutLocation() || useLayoutSize()) {
                        // fix for bug id 1263220 -kp commented out
                        // was in their originally
                        //	    Point p = getWindowLocation(false);
                        Point p = getWindowLocation(useLayoutLocation());
                        Dimension d = getWindowSize(win, false);
                        constrainToScreen(win, p, d);
                        win.reshape(p.x, p.y, d.width, d.height);
                    }
                }
                
                win.validate();
            }
        }
        
        layoutMode = false;
    }
    
    public Dimension previewSize() {
        boolean isLayout = layoutMode;
        
        if (isLayout) {
            setPreview(false);
            super.previewMode();
        }
        
        Dimension size = ((Window)body).preferredSize();
        size = new Dimension(size.width, size.height);
        
        if (isLayout) {
            setLayout(false);
            super.layoutMode();
        }
        
        return size;
    }
    
    public boolean handleEvent(Message msg, Event evt) {
        if (msg.target == this && evt.id == Event.WINDOW_MOVED) {
            ContainerShadow panel = getPanel();
            if (panel != null) {
                boolean dirty = DesignerAccess.getChangesMade();
                panel.set(/* NOI18N */"layoutLocation",
			  get(/* NOI18N */"layoutLocation"));
                panel.set(/* NOI18N */"layoutSize",
			  get(/* NOI18N */"layoutSize"));
                DesignerAccess.setChangesMade(dirty);
            }
        }
        
        return super.handleEvent(msg, evt);
    }
}
