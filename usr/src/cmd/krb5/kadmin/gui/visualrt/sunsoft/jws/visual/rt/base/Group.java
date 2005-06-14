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
 * @(#) Group.java 1.143 - last change made 07/25/97
 */

package sunsoft.jws.visual.rt.base;

import sunsoft.jws.visual.rt.awt.RootFrame;
import sunsoft.jws.visual.rt.shadow.*;
import sunsoft.jws.visual.rt.shadow.java.awt.*;
import sunsoft.jws.visual.rt.type.Converter;
import sunsoft.jws.visual.rt.type.AMConverter;
import sunsoft.jws.visual.rt.type.AMRef;
import sunsoft.jws.visual.rt.base.Global;


import java.awt.*;
import java.util.*;
import java.net.URL;
import java.applet.Applet;

/**
 * The base class for every kind of group.
 * <p>
 * The attributes available for this
 * class are listed below.  In the type column, type names beginning
 * with "sunsoft.jws.visual.rt" have been abbreviated to begin
 * with "rt".
 *
 * <pre>
 * name            type                      default value
 * ---------------------------------------------------------------
 * visible         java.lang.Boolean         true
*  < /pre>
*
* Check the super class for additional attributes.
*
* @version 	1.143, 07/25/97
*/
public abstract class Group extends AttributeManager {
    
    // Print the warning message only once.
    private boolean warned = false;
    
    /**
     * This flag is used to detect when showGroup is called
     * recursively during create.
     * We don't want to execute the showGroup code twice
     * because modal dialogs block during "show".
     * This means that if
     * show is called twice, the modal dialog will pop up
     * again after it is hidden.
     */
    private boolean doingShow = false;
    
    /**
     * This flag indicates whether or not the group is
     * currently shown.
     */
    private boolean isShowing = false;
    
    /**
     * This flag is set for forwarded attributes in a group.
     */
    public static final int FORWARD = 0x100;
    
    /**
     * This flag is set for forwarded attributes that will
     * be removed during initialization if the group's
     * container does not define the attribute.
     */
    public static final int FORWARD_REMOVE = 0x200;
    
    /**
     * This constant can be passed to the setCursor call.
     * It indicates
     * that the cursor should be restored to its previous value.
     */
    public static final int RESTORE_CURSOR = 50000;
    
    public static final int BACKSPACE_KEY = 8;
    public static final int TAB_KEY = 9;
    public static final int RETURN_KEY = 10;
    public static final int ESCAPE_KEY = 27;
    public static final int DELETE_KEY = 127;
    
    // The root of the shadow tree.
    private Root root;
    
    /**
     * Set to true when this group is initialized.
     */
    private boolean isInitialized;
    
    /**
     * Set to true when this group has been started, but
     * has not yet been stopped.
     */
    private boolean isStarted = false;
    
    /**
     * Parent group for this group.
     */
    private Group parentGroup = null;
    
    private Vector children = new Vector();
    
    // Operations
    private Vector operations = null;
    
    /**
     * Time Bomb
     */
    private void checkDate() {
        // August 1, 1996   : 838882801
        // August 15, 1996  : 840092401
        // October 15, 1996 : 845362801
        
        Date date = new Date(840092401000L);
        if (System.currentTimeMillis() >= 840092401000L) {
            throw new Error(Global.getMsg(
		    "sunsoft.jws.visual.rt.base.Group.ExpiredVersion"));
        } else if (!warned) {
            warned = true;
            System.out.println(Global.fmtMsg(
		    "sunsoft.jws.visual.rt.base.Group.ExpiredVersionDate",
		    date.toString()));
        }
    }
    
    // NOTE: Any changes made to this comment should also
    // be made in the lib/visual/gen/group.java file.
    /**
     * All the attributes used by this group must be defined in the
     * constructor.  setOnGroup is called at initialization for all
     * the attributes.  If the attribute has not been set prior to
     * initialization, setOnGroup is called with the default value.
     */
    public Group() {
        // The "visible" attribute MUST have the DEFAULT
        // flag set!  We don't want "visible"
        // being set during initialization.
        attributes.add(/* NOI18N */"visible",
		    /* NOI18N */"java.lang.Boolean", Boolean.TRUE, DEFAULT);
    }
    
    /**
     * Initialize the group.  The shadow tree for the group
     * is created during initialization.
     */
	public void initialize() {
		boolean wasInitialized = isInitialized;
        
		if (!isInitialized) {
			if (!hasEnvironment()) {
				throw new Error(Global.getMsg(
"sunsoft.jws.visual.rt.base.Group.GroupInitializationWarning"));
			}
            
			isInitialized = true;
            
			/**
			 * AMREF: We could have started a recording of all
			 * new AMRef's
			 * here, but it's a performance hit that doesn't buy us
			 * anything, the user shouldn't be making AMRef's
			 * that point to
			 * an object by a certain name, changing the name
			 * of that object, and expecting it to work.
			 *  The stopRecording call
			 * further down goes with this call.
			 */
			// AMRef.startRecording();
            
			root = initRoot();
            
			if (root == null && !(this instanceof NVGroup))
				throw new Error(Global.fmtMsg(
"sunsoft.jws.visual.rt.base.Group.RootIsNull", this.getClass().getName()));
            
			/** AMREF: resolves all AMRef's loaded */
			// AMRef.stopRecording(root);

			removeForwardedAttributes();
	     
			initGroup();
	     
			if (operations != null) {
				Enumeration e = operations.elements();
				while (e.hasMoreElements()) {
					Operations ops =
						(Operations)e.nextElement();
					ops.setRoot(root);
				}
			}
		}
	 
		// Initialize the visible sub-groups
		Enumeration e = getChildList();
		while (e.hasMoreElements()) {
			Group child = (Group)e.nextElement();
			if (wouldBeVisible(child))
				child.initialize();
		}
	 
		if (!wasInitialized) {
			// Set attributes on the newly initialized group
			e = attributes.elements();
			while (e.hasMoreElements()) {
				Attribute a = (Attribute) e.nextElement();
				String name = a.getName();
      
				if (a.isModified() ||
				    !a.flagged(DEFAULT | READONLY)) {
					set(name, a.getValue());
				}
			}
  
			if (isLayoutMode()) {
				WindowShadow s = getWindow();
				if (s != null)
					s.setLayout(true);
			}
		}
	}
     
	/**
	 * Returns true if the group is currently initialized.
	 */
    public boolean isInitialized() {
        return isInitialized;
    }
    
    // NOTE: Any changes made to this comment should
    // also be made in the
    // lib/visual/gen/group.java file.
    /**
     * initRoot must be overridden in group subclasses to
     * initialize the shadow tree.  The return value must be the
     * root of the newly initialized shadow tree.
     */
    protected abstract Root initRoot();
    
    // NOTE: Any changes made to this comment should
    // also be made in the
    // lib/visual/gen/group.java file.
    /**
     * Called during initialization.  It is called just after
     * initRoot is called, but before the sub-groups
     * are initialized and
     * before the attributes are sent to the setOnGroup method.
     *
     * initGroup is only called once in the lifetime of the Group.
     * This is because groups cannot be uninitialized.
     * Anything that
     * needs to be cleaned up should be created in
     * createGroup instead
     * of initGroup, and then can be cleaned up in destroyGroup.
     * createGroup and destroyGroup may be called multiple
     * times during
     * the lifetime of a group.
     */
    protected void initGroup() {};
    
    /**
     * Returns a type name for this group to be used by visual java.
     * May be overridden in sub-classes to give more useful names.
     */
    protected String getUserTypeName() {
        return (Converter.shortClassName(getClass().getName()).toLowerCase());
    }
    
    /**
     * Returns the main container for this group.  This can
     * be either a WindowShadow or a PanelShadow.
     */
    public ContainerShadow getContainer() {
        if (root == null)
            return null;
        
        AttributeManager mgr = root.getMainChild();
        if (mgr == null)
            return null;
        else if (mgr instanceof ContainerShadow)
            return (ContainerShadow)mgr;
        else if (mgr instanceof Group)
            return ((Group)mgr).getContainer();
        else
            throw new Error(Global.fmtMsg(
		    "sunsoft.jws.visual.rt.base.Group.UnexpectedMainChildType",
		    mgr));
    }
    
    /**
     * Returns the main panel for this group.  Returns
     * null if the main container is not a panel.
     */
    public PanelShadow getPanel() {
        ContainerShadow c = getContainer();
        if (c instanceof PanelShadow)
            return (PanelShadow)c;
        else
            return null;
    }
    
    /**
     * Returns the main window for this group.  Returns
     * null if the main container is not a window.
     */
    public WindowShadow getWindow() {
        ContainerShadow c = getContainer();
        if (c instanceof WindowShadow)
            return (WindowShadow)c;
        else
            return null;
    }
    
    /**
     * Calls show or hide, depending on the value of cond.
     */
    public void show(boolean cond) {
        if (cond)
            show();
        else
            hide();
    }
    
    /**
     * Shows the group by setting the visible attribute to true.
     */
    public void show() {
        set(/* NOI18N */"visible", Boolean.TRUE);
    }
    
    /**
     * Hides the group by setting the visible attribute to false.
     */
    public void hide() {
        set(/* NOI18N */"visible", Boolean.FALSE);
    }
    
    /**
     * Returns true if the group is currently visible.
     *
     * If the application has not yet been fully initialized
     * and created,
     * then isVisible may return true for a group that is  not yet
     * visible on the screen.  This means that by the time the
     * initialization is complete, the group will be visible
     * on the screen.
     */
    public boolean isVisible() {
        Group base = getBase();
        if (base == null)
            return false;
        else
            return base.wouldBeVisible(this);
    }
    
    /**
     * Returns true if the child group passed as a parameter
     * will be visible
     * when this group is made visible.  If the group parameter
     * is not a
     * child of this group, then the return value will be false.
     */
    public boolean wouldBeVisible(Group group) {
        while (group != null && group != this) {
            Boolean v = (Boolean)group.get(/* NOI18N */"visible");
            if (!v.booleanValue())
                return false;
            
            AttributeManager mgr = (AttributeManager)group.getParent();
            while (!(mgr instanceof Root)) {
                v = (Boolean)mgr.get(/* NOI18N */"visible");
                if (!v.booleanValue())
                    return false;
                mgr = (AttributeManager)mgr.getParent();
            }
            
            if (mgr == null)
                return false;
            
            group = ((Root)mgr).getGroup();
        }
        
        if (group == null)
            return false;
        
        return true;
    }
    
    /**
     * Returns true if the group is currently showing.
     */
    public boolean isShowing() {
        return isShowing;
    }
    
    /**
     * The only reason that this method exists if because
     *  the FrameEditor
     * bypasses the visible attribute, and calls internalShowGroup
     * directly.  This means that the group becomes visible 
     * even though
     * the visible attribute is set to false.  In this situation, we
     * still want the isVisible call for child groups to
     * return true,
     * hence the need for the isContainerVisible method.
     */
    private boolean isContainerVisible() {
        if (inDesignerRoot()) {
            ComponentShadow s = getContainer();
            if (s == null)
                return false;
            
            Component comp = (Component)s.getBody();
            if (comp == null)
                return false;
            
            return comp.isVisible();
        } else {
            return false;
        }
    }
    
    // NOTE: Any changes made to this comment should also
    // be made in the
    // lib/visual/gen/group.java file.
    /**
     * May be overridden by group subclasses that want
     * to know when the group becomes visible.
     *  It is called just before
     * the group becomes visible.
     *  The group will already be initialized
     * and created at this point.
     */
    protected void showGroup() {
    }
    
    /**
     * Shows the group.  Calling internalShowGroup does
     * not affect the
     * value of the visible attribute.
     */
    void internalShowGroup() {
        Group base = null;
        
        // Initialize ourselves if we haven't been initialized yet
        if (!isInitialized) {
            base = getBase();
            if (base != null)
                base.setCursor(Frame.WAIT_CURSOR);
            
            initialize();
        }
        
        // Create ourselves if we haven't been created yet
        if (!isCreated) {
            doingShow = true;
            create();
            doingShow = false;
        }
        
        if (!isShowing) {
            isShowing = true;
            
            if (root != null)
                showGroup();
            
            // showGroup might call hide (trust me, it can happen)
            if (!isShowing)
                return;
        }
        
        //
        // Invoke "show" on all the child groups that
        // are not directly
        // descended from the root.  This solves two problems:
        //
        // 1) Panel groups are not immediate children of the root,
        //    therefore showRoot does not show the panel groups.
        //
        // 2) Some of the groups may not yet be created due
        // to delayed
        // instantiation.  Calling internalShowGroup
        // on these groups
        // will cause them to be initialized and created, as well as
        // shown. For example, say that this group was created while
        // its visible attribute was set to false.  This means that
        //   none of its child groups would be created because
        // isVisible
        //    would return false for them.
        //  Now say that visibile is set
        //   to true for this group, causing internalShowGroup to be
        //    called.  At this point, the child groups need to be
        //    initialized, created and shown, because now
        // isVisible will
        //    return true for them.
        //
        // Note that this needs to be done before the call
        // to showRoot.
        // This is because panel groups must be created
        // before the frames
        // that contain them are shown in showRoot,or else the frame
	// will come up the wrong size.
        //
        Enumeration e = children.elements();
        while (e.hasMoreElements()) {
            Group child = (Group)e.nextElement();
            if (wouldBeVisible(child) && child.getParent() != root)
                child.internalShowGroup();
        }
        
        // Invoke "show" on all the children of the root
        if (root != null)
            root.showRoot();
        
        // Start the group if it isn't already started
        if (hasStarted() && !isStarted)
            start();
        
        // Revert the cursor
        if (base != null)
            base.setCursor(RESTORE_CURSOR);
    }
    
    // NOTE: Any changes made to this comment should
    // also be made in the
    // lib/visual/gen/group.java file.
    /**
     * May be overridden by group subclasses that want
     * to know when the group becomes non-visible.
     *  It is called just
     * before the group becomes non-visible.
     */
    protected void hideGroup() {
    }
    
    /**
     * Hides the group.  Calling hideGroup does not affect the
     * value of the visible attribute.
     *  You should normally use "hide"
     * instead of "hideGroup" so that the visible attribute is
     * properly
     * updated.
     */
    void internalHideGroup() {
        if (!isInitialized)
            return;
        
        if (isShowing) {
            isShowing = false;
            if (root != null)
                hideGroup();
        }
        
        // Invoke "hide" on all the child groups
        Enumeration e = children.elements();
        while (e.hasMoreElements()) {
            Group group = (Group)e.nextElement();
            if (group.getParent() != root)
                group.internalHideGroup();
        }
        
        // Invoke "hide" on all the children of the root
        if (root != null)
            root.hideRoot();
    }
    
    //
    // Create and Destroy - Life span of the shadow bodies
    //
    
    /**
     * Create the group.  Creating the group causes
     * all the AWT components
     * to be created.  Also, the createGroup method is called during
     * group creation.
     */
    public void create() {
        // Initialize ourselves if we haven't been initialized yet
        if (!isInitialized)
            initialize();
        
        if (!hasBase()) {
            throw new Error(Global.getMsg(
		    "sunsoft.jws.visual.rt.base.Group.GroupCreationWarning"));
        }
        
        boolean wasCreated = isCreated;
        boolean tmpShow = doingShow;
        boolean shouldShow = false;
        
        if (!wasCreated && !doingShow() && isVisible()) {
            // Set the doingShow flag to true so that the windows
            // under the
            // root will not show while they are being created.
            //  We want to
            // have them wait to be shown until internalShowGroup
            // is called.
            doingShow = true;
            shouldShow = true;
        }
        
        super.create();
        
        if (root == null && !(this instanceof NVGroup))
            throw new Error(Global.getMsg(
		    "sunsoft.jws.visual.rt.base.Group.RootIsNull2"));
        
        if (root != null)
            root.create();
        
        if (!wasCreated) {
            createGroup();
            
            // Show the group if it is visible
            if (shouldShow)
                internalShowGroup();
        }
        
        doingShow = tmpShow;
    }
    
    // NOTE: Any changes made to this comment should
    // also be made in the
    // lib/visual/gen/group.java file.
    /**
     * Called during group creation.  Groups can be
     * created and destroyed multiple times during their lifetime.
     * Anything that is created in createGroup should be cleaned up
     * in destroyGroup.  createGroup is called just after the group
     * has been created.  Anything that needs to be done before the
     * group is created should be done in initGroup.
     */
    protected void createGroup() {}
    
    /**
     * Destroy the group.  This will destroy all AWT components, but
     * does not destroy the shadow tree or the group tree. The group
     * can be created again after a destroy by calling the "create"
     * method.
     */
    public void destroy() {
        if (!isInitialized)
            return;
        
        stop();
        
        if (isCreated)
            destroyGroup();
        
        super.destroy();
        
        if (root != null)
            root.destroy();
    }
    
    // NOTE: Any changes made to this comment should also
    // be made in the
    // lib/visual/gen/group.java file.
    /**
     * Called during the destroy operation.  Groups can
     * be created and destroyed multiple times during their
     * lifetime.
     * Anything that has been created in createGroup should be
     * cleaned up
     * in destroyGroup.  destroyGroup is called just before the
     * group
     * is destroyed.
     */
    protected void destroyGroup() {}
    
    //
    // start/stop
    //
    
    /**
     * This method should not be overridden by group subclasses.
     * The "startGroup" method should be overridden instead.
     */
    public void start() {
        if (!isInitialized)
            return;
        
        if (!isCreated)
            create();
        
        if (!isStarted) {
            isStarted = true;
            startGroup();
        }
        
        Enumeration e = children.elements();
        while (e.hasMoreElements()) {
            Group child = (Group)e.nextElement();
            if (wouldBeVisible(child))
                child.start();
        }
    }
    
    // NOTE: Any changes made to this comment should also
    // be made in the
    // lib/visual/gen/group.java file.
    /**
     * May be overridden by group subclasses that want
     * to be informed when the application is starting.
     *  This method is
     * only called after the entire application has been
     * initialized and created.
     *
     * For applets, startGroup is called whenever start
     * is called on the  applet.
     */
    protected void startGroup() {}
    
    /**
     * Returns true if the group is currently started.
     */
    public boolean isStarted() {
        return isStarted;
    }
    
    /**
     * This method should not be overridden by group subclasses.
     * The "stopGroup" method should be overridden instead.
     */
    public void stop() {
        if (!isInitialized)
            return;
        
        if (isStarted) {
            isStarted = false;
            stopGroup();
        }
        
        Enumeration e = children.elements();
        while (e.hasMoreElements())
            ((Group)e.nextElement()).stop();
    }
    
    // NOTE: Any changes made to this comment should also
    // be made in the
    // lib/visual/gen/group.java file.
    /**
     * May be overridden by group subclasses that want
     * to be informed when the application is stopping.  This method
     * will be called before a destroy is done.
     *
     * For applets, stopGroup is called whenever stop is called
     * on the applet.
     */
    protected void stopGroup() {}
    
    /**
     * Returns true if the base group has been started.
     */
    protected boolean hasStarted() {
        if (isBase()) {
            return isStarted;
        } else if (parentGroup != null) {
            return parentGroup.hasStarted();
        } else {
            return false;
        }
    }
    
    //
    // Group tree - An group can be either a node or a leaf.
    //
    
    void add(Group child) {
        if (!children.contains(child)) {
            child.setParentGroup(this);
            children.addElement(child);
        }
    }
    
    void remove(Group child) {
        if (children.contains(child)) {
            child.setParentGroup(null);
            children.removeElement(child);
        }
    }
    
    void addRootChildren(Root root) {
        addChildren((AMContainer)root);
    }
    
    private void addChildren(AMContainer cntr) {
        Enumeration e = cntr.getChildList();
        while (e.hasMoreElements()) {
            AttributeManager child = (AttributeManager)e.nextElement();
            if (child instanceof Group)
                add((Group)child);
            if (child instanceof AMContainer)
                addChildren((AMContainer)child);
        }
    }
    
    void removeRootChildren(Root root) {
        Enumeration e = children.elements();
        while (e.hasMoreElements()) {
            Group child = (Group)e.nextElement();
            if (child.getRoot() == root)
                remove(child);
        }
    }
    
    /**
     * Looks up a named child group of this group.  Not recursive.
     */
    public Group getChild(String name) {
        for (Enumeration e = children.elements(); e.hasMoreElements(); )
	    {
		Group child = (Group)e.nextElement();
		if (name.equals(child.get(/* NOI18N */"name")))
		    return (child);
	    }
        return (null);
    }
    
    /**
     * Returns an enumerated list of this group's children. The list
     * is cloned because the caller might use it for removing child
     * groups from this group.
     */
    public Enumeration getChildList() {
        return ((Vector)children.clone()).elements();
    }
    
    private void setParentGroup(Group parent) {
        parentGroup = parent;
    }
    
    /**
     * Returns this group's parent.
     */
    public Group getParentGroup() {
        return parentGroup;
    }
    
    /**
     * Returns this group (overrides the behavior of getGroup
     * as defined in AttributeManager).
     */
    public Group getGroup() {
        return this;
    }
    
    /**
     * Returns a hierarchy name based on the group tree.
     */
    public String getFullName() {
        String name = getName();
        if (name == null)
            return null;
        
        if (parentGroup != null) {
            String parentName = parentGroup.getFullName();
            if (parentName != null)
                name = parentName + /* NOI18N */"." + name;
        }
        
        return name;
    }
    
    /**
     * Find a component from its full path name.
     */
    public AttributeManager resolveFullName(String name) {
        AttributeManager mgr = null;
        Group group = this;
        Group newGroup;
        
        while (group != null && !group.isBase())
            group = group.parentGroup;
        if (group == null)
            return null;
        
        StringTokenizer st = new StringTokenizer(name, /* NOI18N */".");
        
        if (group.getName() != null) {
            if (!st.hasMoreTokens())
                return null;
            
            name = st.nextToken();
            if (!name.equals(group.getName()))
                return null;
        }
        
        while (st.hasMoreTokens()) {
            name = st.nextToken();
            newGroup = group.resolveGroup(name);
            
            if (newGroup == null) {
                if (group.root == null)
                    return null;
                
                mgr = group.root.resolve(name);
                break;
            } else {
                group = newGroup;
            }
        }
        
        if (st.hasMoreTokens())
            return null;
        
        return mgr;
    }
    
    /**
     * Recursively looks for a named sub-group of this group.
     */
    public Group resolveGroup(String name) {
        Group group;
        String groupName;
        
        Enumeration e = children.elements();
        while (e.hasMoreElements()) {
            group = (Group)e.nextElement();
            groupName = group.getName();
            if (groupName != null &&
		groupName.equals(name)) {
                return group;
            }
        }
        
        return null;
    }
    
    //
    // AWT parenting
    //
    
    void setParentBody() {
        if (root != null)
            root.addChildBody(getContainer());
    }
    
    void unsetParentBody() {
        if (root != null)
            root.removeChildBody(getContainer());
    }
    
    /**
     * Add an operations class.
     */
    public synchronized void addOperations(Operations ops) {
        if (operations == null)
            operations = new Vector();
        
        if (!operations.contains(ops)) {
            ops.setGroup(this);
            if (root != null)
                ops.setRoot(root);
            operations.addElement(ops);
        }
    }
    
    /**
     * Remove an operations class.
     */
    public synchronized void removeOperations(Operations ops) {
        if (operations != null)
            operations.removeElement(ops);
    }
    
    //
    // Events
    //
    
    /**
     * Posts a message to this group's parent.  This method should
     * be used when sending a message from within this group.
     */
    public void postMessageToParent(Message msg) {
        if (parentGroup != null)
            parentGroup.postMessage(msg);
    }
    
    /**
     * Posts a message to this group.  This method should
     * be used when sending a message to this group.
     */
    public void postMessage(Message msg) {
        // Distribute the message to the operations classes
        if (operations != null) {
            Enumeration e = operations.elements();
            while (e.hasMoreElements()) {
                Operations ops = (Operations)e.nextElement();
                if (ops.handleMessage(msg))
                    return;
            }
        }
        
        // Handle the message
        if (handleMessage(msg))
            return;
        
        // Don't pass AWT events up to the parent.  If you want
        // an AWT event
        // to go to the parent group, call
        // "parent.postEvent()" directly.
        if (!msg.isAWT && parentGroup != null)
            parentGroup.postMessage(msg);
    }
    
    // NOTE: Any changes made to this comment should also be
    // made in the
    // lib/visual/gen/group.java file.
    /**
     * May be overridden by subclasses that want to act
     * on messages that are sent to the group.
     * Typically, messages are
     * either AWT events that have been translated to
     * messages, or they
     * are messages that have been sent by other groups.
     * super.handleMessage should be called for any messages
     * that aren't handled.  If super.handleMessage is not
     * called, then handleEvent
     * will not be called.
     * <p>
     * AWT events are not propagated regardless of the return
     * value from
     * handleEvent.  If you want an AWT event to go to the parent
     * group, you need to call postMessageToParent()
     * with the event message.
     * <p>
     */
    public boolean handleMessage(Message msg) {
        if (msg.isAWT) {
            Event evt = (Event)msg.arg;
            
            handleEvent(msg, evt);
            
            // Post AcceleratorKey messages for certain keys
            if (evt.id == Event.KEY_PRESS && evt.key != 0 &&
		(evt.key < 32 || evt.key >= 127)) {
                postMessage(new Message(this,
					/* NOI18N */"AcceleratorKey", evt));
            }
            
            return true;
        }
        
        return false;
    }
    
    // NOTE: Any changes made to this comment should also be
    // made in the
    // lib/visual/gen/group.java file.
    /**
     * May be overridden by subclasses that want to get
     * notified when AWT events that are sent by the gui components.
     * The return value should be true for handled events, and
     * super.handleEvent should be called for unhandled events.
     * If super.handleEvent is not called, then the specific event
     * handling methods will not be called.
     * <p>
     * The message's target is set to the shadow that sent
     * the event.
     * The event's target is set to the AWT component that
     * sent the event.
     * <p>
     * The following more specific methods may also be overridden:
     * <pre>
     * public boolean mouseDown(Message msg,
     * Event evt, int x, int y);
     * public boolean mouseDrag(Message msg, Event evt,
     * int x, int y);
     * public boolean mouseUp(Message msg, Event evt, int x, int y);
     * public boolean mouseMove(Message msg, Event evt,
     * int x, int y);
     * public boolean mouseEnter(Message msg, Event evt,
     * int x, int y);
     * public boolean mouseExit(Message msg, Event evt,
     * int x, int y);
     * public boolean keyDown(Message msg, Event evt, int key);
     * public boolean keyUp(Message msg, Event evt, int key);
     * public boolean action(Message msg, Event evt, Object what);
     * public boolean gotFocus(Message msg, Event evt, Object what);
     * public boolean lostFocus(Message msg,
     * Event evt, Object what);
     * </pre>
     */
    public boolean handleEvent(Message msg, Event evt) {
        if (super.handleEvent(msg, evt))
            return true;
        
        // Intercept some of the WINDOW events.
        //  Sub-groups that want to do
        // something different with these WINDOW events
        // should return true
        // after handling the event.
        
        switch (evt.id) {
	case Event.WINDOW_DESTROY:
            windowDestroy(msg);
            return true;
            
	case Event.WINDOW_ICONIFY:
            if (evt.target instanceof Window) {
                if (isBaseWindow((Window)evt.target)) {
                    hide();
                    return true;
                }
            }
            return false;
            
	case Event.WINDOW_DEICONIFY:
            if (evt.target instanceof Window) {
                if (isBaseWindow((Window)evt.target)) {
                    show();
                    return true;
                }
            }
            return false;
        }
        
        return false;
    }
    
    /**
     * Exit the application with no error code.
     */
    public void exit() {
        exit(0);
    }
    
    /**
     * Exit the application.  Calls exit on the parent
     * if there is a parent.
     * Only calls System.exit() if there is no applet.
     */
    public void exit(int errCode) {
        if (isBase()) {
            destroy();
            if (applet == null)
                System.exit(errCode);
        } else if (parentGroup != null) {
            parentGroup.exit(errCode);
        } else {
            destroy();
        }
    }
    
    /**
     * Called when a WINDOW_DESTROY event is received by this group.
     * The default behavior for WINDOW_DESTROY events is to
     * set the visible
     * attribute to false for the target of the event.
     * If the target of
     * the event is the main window, then set this group's
     * visible attribute
     * to false.  If this group is the base group, then exit the
     * application.
     */
    protected void windowDestroy(Message msg) {
        if (msg.target == getContainer()) {
            if (inDesignerRoot())
                internalHideGroup();
            else if (isBase())
                exit();
            else
                hide();
        } else {
            if (msg.target instanceof AttributeManager)
                ((AttributeManager)msg.target).set(/* NOI18N */"visible",
						Boolean.FALSE);
            else if (msg.target instanceof Component)
                ((Component)msg.target).hide();
        }
    }
    
    /**
     * Attribute forwarding
     */
    
    private Vector forwardVector = new Vector();
    
    /**
     * Adds the attribute manager to the list of forwards.  When
     * an attribute is set and is flagged FORWARD, the value for the
     * attribute will be forwarded to every matching attribute
     * manager
     * in the list of forwards.
     */
    protected void addAttributeForward(AttributeManager mgr) {
        if (forwardVector.contains(mgr))
            return;
        
        // Add this guy to the list of attribute forwards
        forwardVector.addElement(mgr);
        
        // Override values in mgr with values from forwards
        Enumeration e = attributes.attributesWithFlags(FORWARD);
        
        while (e.hasMoreElements()) {
            Attribute attr = (Attribute)e.nextElement();
            String name = attr.getName();
            String type = attr.getType();
            
            if (mgr.hasAttribute(name, type)) {
                Object value = mgr.get(name);
                
                if (!attr.flagged(READONLY)) {
                    if (!attr.isModified())
                        putInTable(name, value);
                    else
                        if (!mgr.getAttribute(name).flagged(READONLY))
			    mgr.set(name, attr.getValue());
                }
                
                attr.setDefaultValue(value);
            }
        }
    }
    
    /**
     * Adds a set of attributes to this group that
     * are suitable for forwarding to a frame, dialog or panel.
     */
    protected void addForwardedAttributes() {
        if (genericAttrList == null) {
            genericAttrList = new AttributeList();
            mergeForward(genericAttrList, new VJPanelShadow());
            mergeForward(genericAttrList, new FrameShadow());
            mergeForward(genericAttrList, new DialogShadow());
        }
        
        Enumeration e = genericAttrList.elements();
        while (e.hasMoreElements()) {
            Attribute attr = (Attribute)e.nextElement();
            if (!hasAttribute(attr.getName()))
                attributes.add((Attribute)attr.clone());
        }
        
        if (!hasAttribute(/* NOI18N */"text"))
            attributes.alias(/* NOI18N */"text", /* NOI18N */"title");
    }
    
    private void mergeForward(AttributeList list, Shadow shadow) {
        AttributeList shadowList =
	    (AttributeList)shadow.getAttributeList().clone();
        Enumeration e = shadowList.elements();
        
        while (e.hasMoreElements()) {
            Attribute attr = (Attribute)e.nextElement();
            if (!list.contains(attr.getName())) {
                // System.out.println(/* NOI18N */"add " +
                // attr.getName() + /* NOI18N */" " + attr.getType());
                attr.addFlags(FORWARD | FORWARD_REMOVE);
                list.add(attr);
            }
        }
    }
    
    private void removeForwardedAttributes() {
        ContainerShadow cntr = getContainer();
        if (cntr == null)
            return;
        
        Enumeration e = attributes.attributesWithFlags(FORWARD_REMOVE);
        while (e.hasMoreElements()) {
            Attribute attr = (Attribute)e.nextElement();
            if (!cntr.hasAttribute(attr.getName())) {
                attributes.remove(attr.getName());
            }
        }
    }
    
    /**
     * Return true if we are forwarding the attribute "attrName"
     * to "mgr",
     * otherwise return false.
     */
    boolean hasAttributeForward(AttributeManager mgr, String attrName) {
        return (forwardVector.contains(mgr) &&
		attributes.get(attrName).flagged(FORWARD));
    }
    
    /**
     * These are helper routines for the group.
     * If you are fowarding
     * attributes to a component, dialog or frame, you should call
     * one of these methods in the constructor.
     */
    
    private static AttributeList genericAttrList = null;
    
    /**
     * Compatibility method - do not use!
     */
    protected void addComponentAttributes() {
        addForwardedAttributes();
    }
    
    /**
     * Compatibility method - do not use!
     */
    protected void addPanelAttributes() {
        addForwardedAttributes();
    }
    
    /**
     * Compatibility method - do not use!
     */
    protected void addFrameAttributes() {
        addForwardedAttributes();
    }
    
    /**
     * Compatibility method - do not use!
     */
    protected void addDialogAttributes() {
        addForwardedAttributes();
    }
    
    //
    // Attributes - get and set
    //
    
    /**
     * Get the value of a named attribute.
     */
    public Object get(String key) {
        Attribute attr = attributes.get(key);
        
        if (key.equals(/* NOI18N */"name")) {
            return super.get(key);
        } else if (key.equals(/* NOI18N */"visible")) {
            return super.get(key);
        } else if (!isInitialized) {
            return super.get(key);
        } else if (attr != null && attr.flagged(FORWARD)) {
            Enumeration e = forwardVector.elements();
            AttributeManager mgr;
            
            while (e.hasMoreElements()) {
                mgr = (AttributeManager)e.nextElement();
                if (mgr.hasAttribute(key, attr.getType())) {
                    return mgr.get(key);
                }
            }
            
            return null;
        } else {
            return getOnGroup(key);
        }
    }
    
    // NOTE: Any changes made to this comment should also
    // be made in the
    // lib/visual/gen/group.java file.
    /**
     * May be overridden by sub-groups that
     * store attribute values themselves, and do not depend on the
     * group superclass to store them. 
     * This method should be overridden
     * instead of "get".  Any attributes handled in setOnGroup where
     * super.setOnGroup is not called must also be handled
     * in getOnGroup.
     * <p>
     * The default implementation of getOnGroup retrieves the value
     * from the attribute table.
     * <p>
     * The reason that "getOnGroup" should be overridden instead
     * of "get" is that "getOnGroup" is guaranteed not to be called
     * until the group class is initialized.
     * This means that initRoot
     * will always be called before any calls to getOnGroup
     * are made.
     * <p>
     * Also, this method is only for attributes that are defined
     * in the
     * sub-groups.  It is not called for forwarded attributes.
     * <p>
     */
    protected Object getOnGroup(String key) {
        return super.get(key);
    }
    
    /**
     * Set the value of a named attribute.
     */
    public void set(String key, Object value) {
        Attribute attr = attributes.get(key);
        
        if (key.equals(/* NOI18N */"name")) {
            super.set(key, value);
        } else if (key.equals(/* NOI18N */"visible")) {
            super.set(key, value);
            if (((Boolean)value).booleanValue()) {
                if (isVisible())
                    internalShowGroup();
            } else
                internalHideGroup();
        } else if (!isInitialized) {
            super.set(key, value);
        } else if (attr != null && attr.flagged(FORWARD)) {
            super.set(key, value);
            
            Enumeration e = forwardVector.elements();
            AttributeManager mgr;
            boolean set = false;
            
            while (e.hasMoreElements()) {
                mgr = (AttributeManager)e.nextElement();
                if (mgr.hasAttribute(key, attr.getType())) {
                    mgr.set(key, value);
                    set = true;
                }
            }
            
            if (set) {
                // update the the global register for unsaved changes
                if (inDesignerRoot())
                    DesignerAccess.setChangesMade(true);
            }
        } else {
            setOnGroup(key, value);
        }
    }
    
    // NOTE: Any changes made to this comment should also
    // be made in the
    // lib/visual/gen/group.java file.
    /**
     * May be overridden by sub-groups that
     * want notification when attributes are changed.  This method
     * should be overridden instead of "set".  
     * Any attributes handled
     * in setOnGroup where super.setOnGroup is not called
     * must also be
     * handled in getOnGroup.
     * <p>
     * The default implementation of setOnGroup puts the value
     * in the attribute table.
     * <p>
     * The reason that "setOnGroup" should be overridden instead
     * of "set" is that "setOnGroup" is guaranteed not to be called
     * until the group class is initialized.
     * This means that initRoot
     * will always be called before any calls to setOnGroup
     * are made.
     * <p>
     * During initialization, "setOnGroup" will be called for all
     * the group's attributes even if they have not be changed from
     * the default value.  But for attributes that have the DEFAULT
     * flag set, "setOnGroup" will only be called if the value
     * of the attribute has changed from the default.
     * <p>
     * Also, this method is only called when attributes defined
     * in the
     * sub-groups are updated.  It is not called for forwarded
     * attributes.
     * <p>
     */
    protected void setOnGroup(String key, Object value) {
        super.set(key, value);
    }
    
    /**
     * Base group information.
     */
    
    private Applet applet = null;
    private String cmdLineArgs[];
    private Frame topLevel = null;
    private Registry registry = null;
    
    private boolean hasEnvironment = false;
    
    private boolean hasEnvironment() {
        if (hasEnvironment)
            return true;
        else if (parentGroup != null)
            return parentGroup.hasEnvironment();
        else
            return false;
    }
    
    /**
     * Returns true if this group is the base group.
     */
    public boolean isBase() {
        return hasEnvironment;
    }
    
    /**
     * Returns true if the given window this group's base window.
     */
    protected boolean isBaseWindow(Window win) {
        WindowShadow shadow =
	    (WindowShadow)DesignerAccess.getShadowTable().get(win);
        return (isBase() && (getWindow() == shadow));
    }
    
    /**
     * Returns true if this group is either the base group
     * or is a descendant
     * of the base group.
     */
    public boolean hasBase() {
        if (hasEnvironment)
            return true;
        else if (parentGroup != null)
            return parentGroup.hasBase();
        else
            return false;
    }
    
    /**
     * Returns the base group.
     */
    public Group getBase() {
        if (hasEnvironment)
            return this;
        else if (parentGroup != null)
            return parentGroup.getBase();
        else
            return null;
    }
    
    /**
     * Returns true if we are doing a create operation in the
     * middle of a show operation.  Create likes to call show if the
     * visible attribute is set to true, but create shouldn't call
     * show if show caused create to be called if the first place.
     */
    boolean doingShow() {
        if (doingShow)
            return true;
        else if (parentGroup != null)
            return parentGroup.doingShow();
        else
            return false;
    }
    
    /**
     * Sets the environment information for the group. 
     * This method should
     * be invoked only on the top-most group in the application.
     * Invoking
     * setEnvironmentInfo and setTopLevel on a group makes 
     * it the base group.
     */
    public void setEnvironmentInfo(Applet applet, String args[]) {
        // checkDate();
        this.applet = applet;
        this.cmdLineArgs = args;
        hasEnvironment = true;
    }
    
    /**
     * Sets the top level frame for the group.  This method should
     * be invoked only on the top most group in the application.
     * Invoking setEnvironmentInfo and setTopLevel on a group
     * makes it
     * the base group.
     */
    public void setTopLevel(Frame topLevel) {
        this.topLevel = topLevel;
    }
    
    /**
     * Sets the cursor for all of the group's frames to the given
     * cursor value.  Calls setCursor on all the child groups.
     */
    public void setCursor(int cursor) {
        if (root != null)
            root.setCursor(cursor);
        
        Enumeration e = children.elements();
        while (e.hasMoreElements()) {
            Group child = (Group)e.nextElement();
            child.setCursor(cursor);
        }
    }
    
    /**
     * Accessor method for the applet. Null is returned
     * when you're not
     * running as an applet.
     */
    public Applet getApplet() {
        if (applet != null)
            return applet;
        else if (parentGroup != null)
            return parentGroup.getApplet();
        else
            return null;
    }
    
    /**
     * Accessor method for the command line arguments.
     * Null is returned
     * when you're not running from the command line.
     */
    public String[] getCmdLineArgs() {
        if (cmdLineArgs != null)
            return cmdLineArgs;
        else if (parentGroup != null)
            return parentGroup.getCmdLineArgs();
        else
            return null;
    }
    
    /**
     * Returns the first frame found while traversing up the
     * group tree.  If no frame is found, then the top level
     * frame is returned.
     */
    public Frame getFrame() {
        WindowShadow win = getWindow();
        if (win != null && win.getBody() != null)
	    {
		if (win instanceof DialogShadow)
		    return (Frame)((Window) win.getBody()).getParent();
		else
		    return (Frame)win.getBody();
	    } else if (parentGroup != null)
		return parentGroup.getFrame();
        else
            return getTopLevel();
    }
    
    /**
     * Accessor method for the top level frame.  This will not
     * return null providing that the base group has been 
     * initialized  properly.
     */
    public Frame getTopLevel() {
        if (topLevel != null)
            return topLevel;
        else if (parentGroup != null)
            return parentGroup.getTopLevel();
        else
            return null;
    }
    
    /**
     * Accessor method for the registry.  The registry is
     * created when
     * the application starts.
     */
    public Registry getRegistry() {
        if (isBase()) {
            initRegistry();
            return registry;
        } else if (parentGroup != null)
            return parentGroup.getRegistry();
        else
            return null;
    }
    
    private synchronized void initRegistry() {
        if (registry == null)
            registry = new Registry();
    }
    
    public void layoutMode() {
        super.layoutMode();
        
        WindowShadow s = getWindow();
        if (s != null)
            s.setLayout(true);
    }
    
    public void previewMode() {
        super.previewMode();
        
        WindowShadow s = getWindow();
        if (s != null)
            s.setPreview(true);
    }
    
    protected void preValidate() {
        PanelShadow panel = getPanel();
        if (panel != null)
            panel.preValidate();
    }
}
