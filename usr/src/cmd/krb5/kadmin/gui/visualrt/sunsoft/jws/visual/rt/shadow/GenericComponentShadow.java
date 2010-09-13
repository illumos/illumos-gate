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
 * @(#) GenericComponentShadow.java 1.14 - last change made 07/25/97
 */
        
package sunsoft.jws.visual.rt.shadow;
        
import sunsoft.jws.visual.rt.shadow.java.awt.CanvasShadow;
import sunsoft.jws.visual.rt.awt.GBPanel;
import sunsoft.jws.visual.rt.base.VJException;
import sunsoft.jws.visual.rt.base.Global;
        
import java.awt.Button;
import java.awt.Component;
        
/**
         * Wraps an AWT widget.  The attributes available for this
         * class are listed below.  In the type column, type names beginning
         * with "sunsoft.jws.visual.rt" have been abbreviated to begin with
	 * "rt".
         *
         * < pre>
        name            type                      default value
        -----------------------------------------------------------------------
        class           java.lang.String          java.awt.Button
        *  < /pre>
        *
        * class: the java class(that must be a sub-class of
        * java.awt.Component and have a null constructor) of a user-written
        * AWT class that there is no wrapper shadow class for yet.
        * GenericComponentShadow is useful for quickly incorporating a user's
        * existing custom AWT components in a Visual Java GUI.
        *  < p>
        * Check the super class for additional attributes.
        *
        * @see Component
        * @see GenericWindowShadow
        * @version 1.14, 07/25/97
        */
public class GenericComponentShadow extends CanvasShadow {
    private String className;
    private Class genericClass;
            
    public GenericComponentShadow() {
	attributes.add(/* NOI18N */"class",
		       /* NOI18N */"java.lang.String",
		       /* NOI18N */"java.awt.Button", NOEDITOR);
    }
            
    protected Object getOnBody(String key) {
	if (key.equals(/* NOI18N */"class"))
	    return getFromTable(/* NOI18N */"class");
	else
	    return super.getOnBody(key);
    }
            
    protected void setOnBody(String key, Object value) {
	if (key.equals(/* NOI18N */"class")) {
	    // Don't create a new instance unless the
	    // class name has changed
	    if (className.equals((String)value))
		return;
                    
	    Object obj = loadClass((String)value);
	    destroy();
	    body = obj;
	    create();
	}
	else
	    super.setOnBody(key, value);
    }
            
    public void createBody() {
	body = loadClass((String)get(/* NOI18N */"class"));
    }
            
    private Object loadClass(String name) {
	Class c;
	Object obj;
                
	// Load the class if the name doesn't match the previous name
	if (!name.equals(className)) {
	    try {
		c = Class.forName(name);
	    }
	    catch (ClassNotFoundException ex) {
		throw new VJException(Global.fmtMsg(
/* JSTYLED */
		    "sunsoft.jws.visual.rt.shadow.GenericComponentShadow.FMT.1",
		    Global.getMsg(
/* JSTYLED */
			"sunsoft.jws.visual.rt.shadow.GenericComponentShadow.Class__not__found"),
		    name));
	    }
	} else {
	    c = genericClass;
	}
                
	// Create a new instance from the class
	try {
	    obj = c.newInstance();
	    if (!(obj instanceof Component)) {
		throw new VJException(
/* JSTYLED */
		    Global.fmtMsg("sunsoft.jws.visual.rt.shadow.GenericComponentShadow.NotAComponentSubclass", name));
	    }
	}
	catch (IllegalAccessException ex) {
	    throw new VJException(
/* JSTYLED */
		Global.fmtMsg("sunsoft.jws.visual.rt.shadow.GenericComponentShadow.IllegalAccess", name));
	}
	catch (InstantiationException ex) {
	    throw new VJException(
/* JSTYLED */
		Global.fmtMsg("sunsoft.jws.visual.rt.shadow.GenericComponentShadow.InstantiationException", name));
	}
	catch (NoSuchMethodError ex) {
	    throw new VJException(
/* JSTYLED */
		Global.fmtMsg("sunsoft.jws.visual.rt.shadow.GenericComponentShadow.Noconstructor", name));
	}
                
	// No errors occurred, so update the name and class variables.
	genericClass = c;
	className = name;
                
	// Set the runtime flag for GBPanel instances
	if ((obj instanceof GBPanel) && inDesignerRoot())
	    ((GBPanel)obj).setRuntime(false);
                
	return obj;
    }
}
