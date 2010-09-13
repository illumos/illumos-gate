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
 * @(#) Shadow.java 1.89 - last change made 07/25/97
 */

package sunsoft.jws.visual.rt.base;

import java.util.Enumeration;
import java.util.StringTokenizer;

/**
 * This class implements the basic interfaces
 * that Visual Java requires
 * for its visual components.  Objects that wish to be added to
 * the Visual Java palette must be sub-classed from Shadow.
 * <p>
 * The attributes this class adds to an AttributeManager
 * class are listed below.  In the type column, type names beginning
 * with "sunsoft.jws.visual.rt" have been abbreviated to begin
 * with "rt".
 *
 * <pre>
 * name            type                      default value
 * --------------------------------------------------------------------
 * none
*  < /pre>
*
* Check the super class for additional attributes.
*
* @version 1.89, 07/25/97
*/
public class Shadow extends AttributeManager {
    /**
     * Flags
     */
    
    /**
     * When this flag is set, a provision must be made in order
     * to set
     * the attribute in the body's constructor.  It is up to the
     * caller to call
     * recreate on the shadow and validate on the shadow's
     * parent after
     * a constructor attribute has been set.
     */
    public static final int CONSTRUCTOR = 0x40;
    
    /**
     * This flag signifies that the attribute has nothing to
     * do with a shadow 'body' and therefore
     * <a href="sunsoft.jws.visual.rt.base.Shadow.html
     * #getOnBody(java.lang.String)">getOnBody</a> and
     * <a href="sunsoft.jws.visual.rt.base.Shadow.html
     * #setOnBody(java.lang.String, java.lang.Object)">setOnBody</a>
     * will not be called for this attribute.
     */
    public static final int NONBODY = 0x80;
    
    /**
     * Constructor
     */
    public Shadow() {
        super();
    }
    
    /**
     * The AWT component for this shadow.
     */
    protected Object body;
    
    /**
     * Returns the AWT component for this shadow.
     * The return value is of
     * type Object, therefore the caller must do a cast to the
     * appropriate AWT component type.
     */
    public Object getBody() {
        return (body);
    }
    
    /**
     * Returns a type name suitable for use in naming instances of
     * shadow sub-classes (i.e. names that make sense to a user.)
     *  This
     * can be overridden in sub-classes to give more useful
     * names when
     * this (default) algorithm comes up with something ugly.
     */
    protected String getUserTypeName() {
        // get the final word after the last '.'
        String last = /* NOI18N */"unknown";
        StringTokenizer st = new StringTokenizer(
			 getClass().getName(), /* NOI18N */".", false);
        while (st.hasMoreTokens()) {
            last = st.nextToken();
        }
        
        // remove "Shadow" from the end of the string
        int index = last.lastIndexOf(/* NOI18N */"Shadow");
        if (index != -1) {
            last = last.substring(0, index);
        }
        
        // always return a lower case word
        if (last.length() > 0)
            return (last.toLowerCase());
        else
            return (/* NOI18N */"shadow");
    }
    
    /**
     * Gets attributes from this shadow's body.
     * Should be overridden in each sub-class which has its own
     * attributes.  There should be an entry for every
     * attribute that
     * doesn't have the NONBODY flag, even if it's just to return
     * the value from the attribute list when a certain attribute
     * can't
     * be looked up from the body.
     */
    protected Object getOnBody(String key) {
        throw new Error(Global.fmtMsg(
		"sunsoft.jws.visual.rt.base.Shadow.NoSuchKey", key));
    }
    
    /**
     * Gets an attribute either from the body (if available)
     * or from the
     * shadow's attribute list.
     */
    public Object get(String key) {
        key = attributes.resolveAlias(key);
        if (attributes.contains(key)) {
            Attribute a = attributes.get(key);
            if (body != null && !a.flagged(NONBODY))
                return (getOnBody(key));
            else
                return (a.getValue());
        } else {
            throw new Error(Global.fmtMsg(
		    "sunsoft.jws.visual.rt.base.Shadow.UnknownAttribute",
					  key, getClass().getName()));
        }
    }
    
    /**
     * Sets attributes on this shadow's body.
     * Should be overridden in each sub-class which has its own
     * attributes. There should be an entry for every attribute that
     * doesn't have the NONBODY flag, even if it's just to set the
     * value in the attribute list when a certain attribute
     * can't be set on the body.
     */
    protected void setOnBody(String key, Object value) {
        throw new Error(Global.fmtMsg(
		"sunsoft.jws.visual.rt.base.Shadow.NoSuchKey2", key));
    }
    
    /**
     * Sets an attribute either in the body (if available) or in the
     * shadow's attribute list.  Destroys the body when
     * a CONSTRUCTOR attribute is set.
     * It is up to the caller to call
     * recreate on the shadow and validate on the shadow's
     * parent after a constructor attribute has been set.
     */
    public void set(String key, Object value) {
        key = attributes.resolveAlias(key);
        Attribute a = attributes.get(key);
        if (a == null)
            throw new Error(Global.fmtMsg(
		    "sunsoft.jws.visual.rt.base.Shadow.InvalidAttributeSet",
		    key));
        if (a.flagged(READONLY))
            throw new Error(Global.fmtMsg(
		    "sunsoft.jws.visual.rt.base.Shadow.ReadOnlyAttributeSet",
		    key));
        
        if (a.flagged(CONSTRUCTOR)) {
            if (isCreated) {
                isCreated = false;
                refetchAttributeList();
                unregisterBody();
                destroyBody();
                if (body != null)
                    throw new Error(Global.getMsg(
		    "sunsoft.jws.visual.rt.base.Shadow.BodyNotDestroyed"));
            }
        }
        
        // Save the previous value
        Object prev = a.getValue();
        a.setValue(value);
        
        if (body != null && !a.flagged(NONBODY)) {
            // If setOnBody throws a VJException, then restore
            // the old value.  I couldn't just move the setValue
            // to be after
            // setOnBody, because many shadows depend on the value
            // being set first.
            try {
                setOnBody(key, value);
            }
            catch (VJException ex) {
                a.setValue(prev);
                throw ex;
            }
        }
        
        // update the the global register for unsaved changes
        if (inDesignerRoot())
            DesignerAccess.setChangesMade(true);
        
        if (parent != null && a.flagged(CONTAINER))
            ((AMContainer)parent).updateContainerAttribute(this,
							   key, value);
    }
    
    /**
     * Creates this shadow.
     * It is safe to call create multiple times on a shadow object.
     */
    public void create() {
        if (!isCreated) {
            isCreated = true;
            
            if (getGroup() == null || !getGroup().hasBase()) {
                throw new Error(Global.getMsg(
		"sunsoft.jws.visual.rt.base.Group.ShadowCreationWarning"));
            }
            
            if (body == null)
                createBody();
            if (body == null)
                throw new Error(Global.getMsg(
			"sunsoft.jws.visual.rt.base.Group.BodyNotCreated"));
            
            registerBody();
            
            super.create();
            if (parent != null && body != null)
                parent.addChildBody(this);
            
            postCreate();
        } else {
            super.create();
            if (parent != null && body != null)
                parent.addChildBody(this);
        }
    }
    
    /**
     * Called just after this shadow has been created.
     */
    protected void postCreate() {};
    
    /**
     * Creates the AWT component for this shadow.
     * Sub-classes must override this method.
     */
    public void createBody() {};
    
    /**
     * Registers newly created shadows. 
     * Sub-classes should not override
     * this method.
     */
    protected void registerBody() {
        // Add this shadow's body to the global shadow table.
        DesignerAccess.getShadowTable().put(body, this);
        
        // Set attributes on the new body
        for (Enumeration e = attributes.attributesWithoutFlags(
					       NONBODY|READONLY);
	     /* JSTYLED */
	     e.hasMoreElements(); ) {
	    Attribute a = (Attribute) e.nextElement();
	    if (a.isModified() || !a.flagged(DEFAULT)) {
		setOnBody(a.getName(), a.getValue());
	    }
	}
    
	// System.out.println("Shadow created: " + toString());
    }

    /**
     * Creates this shadow again after a constructor
     * attribute has been set.
     */
    public void recreate() {
	if (!isCreated) {
	    isCreated = true;
        
	    createBody();
        
	    // Reparent the children
	    if (this instanceof AMContainer)
		((AMContainer)this).reparentChildren();
        
	    registerBody();
        
	    postCreate();
	}
    
	if (parent != null && body != null)
	    parent.addChildBody(this);
    }

    /**
     * Destroys this shadow and all its children.
     */
    public void destroy() {
	if (isCreated) {
	    isCreated = false;
        
	    preDestroy();
        
	    super.destroy();
        
	    unregisterBody();
        
	    destroyBody();
	    if (body != null)
		throw new Error(Global.getMsg(
			"sunsoft.jws.visual.rt.base.Shadow.BodyNotDestroyed"));
	} else {
	    super.destroy();
	}
    }

    /**
     * Called during destroy, but before the children are 
     * destroyed.  By the time destroyBody is called, all
     * the children have already been destroyed.
     */
    protected void preDestroy() {
    }

    /**
     * Destroys the body for this shadow.
     * Sub-classes are not required  to override this method.
     */
    protected void destroyBody() {
	body = null;
    }

    /**
     * Unregisters destroyed shadows.  Sub-classes should not
     * override this method.
     */
    protected void unregisterBody() {
	// remove this shadow's body from its container and from the
	// global shadow table
	if (body != null) {
	    if (parent != null && body != null)
		parent.removeChildBody(this);
	    DesignerAccess.getShadowTable().remove(body);
	}
    }

    public String toString() {
	return (super.toString() + /* NOI18N */"["
		+ /* NOI18N */"," + /* NOI18N */"body=" +
		((body == null) ? /* NOI18N */"null" : body.toString())
		+ /* NOI18N */"]");
    }
}
