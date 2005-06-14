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
 * @(#) AMConverter.java 1.63 - last change made 06/25/97
 */

package sunsoft.jws.visual.rt.type;

import sunsoft.jws.visual.rt.base.Global;

import sunsoft.jws.visual.rt.base.*;
import sunsoft.jws.visual.rt.shadow.java.awt.*;
import sunsoft.jws.visual.rt.awt.CardPanel;
import sunsoft.jws.visual.rt.shadow.CardPanelShadow;
import java.util.*;

/**
 * This class can convert attribute managment trees to strings and
 * such strings back again to attribute management trees.  The string
 * produced is a complete description of an application, and so it can
 * be used to save a tree to a file.
 *
 * @see AttributeManager
 * @version 1.63, 06/25/97
 */
public class AMConverter extends Converter {
    
    private static AttributeListConverter attrlistconv =
	new AttributeListConverter();
    
    public AMConverter() {
    }
    
    /**
     * List of paths (package prefixes) to groups of Shadow classes
     * also a few individual Shadow classes.  The Hashtables are for
     * caching the matches after they are discovered.
     */
    private static Vector shadows = new Vector();
    private static Hashtable shortShadowKeyed = new Hashtable();
    private static Hashtable longShadowKeyed = new Hashtable();
    
    /**
     * Caches the matches after they are discovered.
     */
    private static void cacheShadowPair(String shortName,
					String longName) {
        shortShadowKeyed.put(shortName, longName);
        longShadowKeyed.put(longName, shortName);
    }
    
    /**
     * Adds the name of a package where custom shadow 
     * classes can be found.
     * Package names in this list always end with a "."
     */
    private static void addShadowPath(String pkgName) {
        if (pkgName.endsWith(/* NOI18N */"."))
            shadows.addElement(pkgName);
        else
            shadows.addElement(/* NOI18N */(pkgName + "."));
    }
    
    /**
     * Adds a specific shadow class to the list.  
     * Specific shadow classes
     * in the list never end with a "."
     */
    private static void addShadowItem(String className) {
        cacheShadowPair(Converter.shortClassName(className),
			className);
    }
    
    static {
        // add packages where shadow classes might be found
        //
        // Don't add any more of these or the quick
        // code generation will
        // be screwed!
        addShadowPath(/* NOI18N */"sunsoft.jws.visual.rt.shadow");
        
        // add individual exceptions
        addShadowItem
	    (/* NOI18N */"sunsoft.jws.visual.rt.base.Root");
    }
    
    /**
     * Figures out the short name for a shadow class.  Removes the
     * initial component of a class name if it's one of the currently
     * listed paths for finding shadow classes.  The result is the
     * abbreviated name for the shadow class that can be placed in the
     * save file.
     *
     * Warning: you should not nest shadow packages in the path within
     * each other, as this routine might return the wrong shortened 
     * form
     * of the class name.
     */
    private static String shortenShadowPath(String longClassName) {
        // return the cached value if available
        if (longShadowKeyed.containsKey(longClassName))
            return ((String) longShadowKeyed.get(longClassName));
        /* JSTYLED */
	for (Enumeration e = shadows.elements(); e.hasMoreElements(); ) {
	    String s = (String) e.nextElement();
	    if (longClassName.startsWith(s))
		return (longClassName.substring(s.length()));
	}
    
	// the long class name was not found in any of the paths
	return (longClassName);
    }

    /**
     * Searches the currently listed shadow paths for the shadow class
     * given.  Returns a runtime class reference to the shadow class
     * once it finds that class under one of the paths (or, in the end,
     * under the actual name given.)
     *
     * This is basically the reverse of shortenShadowPath.
     */
    private static Class searchShadowPath(String shortClassName) {
	// return the cached value if available
	if (shortShadowKeyed.containsKey(shortClassName)) {
	    try {
		return (Global.util.getClassLoader().loadClass
			((String) shortShadowKeyed.get
			 (shortClassName)));
	    }
	    catch (ClassNotFoundException ex) {
		// that didn't work, silently try something else...
            }
	}
    
	Class retval = null;
	/* JSTYLED */
	for (Enumeration e = shadows.elements(); e.hasMoreElements(); ) {
	    String path = (String) e.nextElement();
	    try {
		retval = Global.util.getClassLoader().loadClass
		    (path + shortClassName);
		break;
	    }
	    catch (ClassNotFoundException ex) {
		// that didn't work, silently try again...
	    }
	}

	if (retval == null) {
	    try {
		retval = Global.util.getClassLoader().loadClass
		    (shortClassName);
	    }
	    catch (ClassNotFoundException ex) {
		// that didn't work either, how sad
		throw new ParseException(Global.fmtMsg
			 ("sunsoft.jws.visual.rt.type.AMConverter.FMT.0",
					  Global.newline(), /* NOI18N */"\t",
					  ex.toString()));
	    }
	}

	// cache this pairing so it won't have to be looked up again
	if (retval != null && !shortShadowKeyed.containsKey
	    (shortClassName))
	    cacheShadowPair(retval.getName(), shortClassName);

	return (retval);
    }

    /**
     * Creates a string from the reference to the root or branch of the
     * attribute management tree given.  Appends the string to the given
     * string buffer.
     *
     * @param obj attribute management tree reference
     * @param buf string buffer to append to
     * @return string that describes the tree
     */
    public void convertToString(Object obj, StringBuffer buf) {
	if (obj == null)
	    return;
    
	// Make sure the first card is showing before saving the card panel.
	if (obj instanceof CardPanelShadow) {
	    CardPanel cardPanel = (CardPanel)
		((CardPanelShadow)obj).getCardPanel();
	    if (cardPanel != null)
		cardPanel.first();
	}
    
	AttributeManager tree = (AttributeManager) obj;
    
	//
	// Skip over any windows that are marked as panels.
	//
	/* JSTYLED */
	if ((tree instanceof WindowShadow) && ((WindowShadow)tree).isPanel()) {
	    AttributeManager child = ((WindowShadow)tree).getPanel();
	    if (child != null)
		convertToString(child, buf);
	    return;
	}

	// this object's own attributes
	indent(buf);
	buf.append(shortenShadowPath(tree.getClass().getName()));
	buf.append(/* NOI18N */" ");

	ListParser.quote(tree.getName(), buf, false);

	buf.append(/* NOI18N */" {");
	newline(buf);
	incrIndent();
	attrlistconv.convertToString(tree.getAttributeList(), buf);
	decrIndent();

	// children
	if (tree instanceof AMContainer) {
	    Enumeration e = ((AMContainer) tree).getChildList();
	    AttributeManager child;
    
	    if (e.hasMoreElements()) {
		incrIndent();
		indent(buf);
		buf.append(/* NOI18N */"child list {");
		newline(buf);
        
		incrIndent();
		while (e.hasMoreElements()) {
		    child = (AttributeManager) e.nextElement();
		    convertToString(child, buf);
		}
		decrIndent();
        
		indent(buf);
		buf.append(/* NOI18N */"}");
		newline(buf);
		decrIndent();
	    }
	}

	indent(buf);
	buf.append(/* NOI18N */"}");
	newline(buf);
    }

    /**
     * Call the convertFromString function that takes a version number
     * instead.  Tree conversion cannot take place without a version
     * number (for the string description.)
     *
     * @exception Error when an attempt is made to call this method
     */
    public Object convertFromString(String s) {
	throw new Error(Global.getMsg(
		/* JSTYLED */
				      "sunsoft.jws.visual.rt.type.AMConverter.AMConverter__convertF.0"));
    }

    /**
     * Creates a new tree based upon the description string given.
     * There should only be one object (as the root of the tree) in the
     * string.  That root object may contain other objects, or children,
     * as it were.
     *
     * @param version the version number for the gui description string
     * @param s the string to convert to a tree @return new shadow tree
     * @exception ParseException when there is an error in the string
     */
    public Object convertFromString(double version, String s) {
	if (s == null)
	    return null;
    
	// Parse the string
	Enumeration e = ListParser.getListElements(s, 3);
	String type = null, name = null, attr = null;
    
	try {
	    type = (String)e.nextElement();
	    name = (String)e.nextElement();
	    attr = (String)e.nextElement();
	}
	catch (NoSuchElementException ex) {
	    throw new ParseException(Global.newline() +
				     /* BEGIN JSTYLED */
				     Global.getMsg("sunsoft.jws.visual.rt.type.AMConverter.________Incomplete__attri.1") +
				     /* END JSTYLED */
		     Global.newline() + /* NOI18N */"      type = " + type +
		     Global.newline() + /* NOI18N */"      name = " + name +
		     Global.newline() + /* NOI18N */"      attr = " + attr);
	}
    
	// Start recording AMRef's made during construction of tree
	AMRef.startRecording();
    
	// Create the attribute manager
	AttributeManager mgr = convertParent(type, name);
	if (mgr == null)
	    return null;
    
	// Parse the attributes and children
	convertChildren(version, mgr, attr);
    
	// Stop recording and resolve all AMRef's that were made
	AMRef.stopRecording(mgr);
    
	return mgr;
    }

    private AttributeManager convertParent(String type, String name) {
	AttributeManager mgr = null;
    
	// Instantiate a new attribute manager
	Class onLineType = searchShadowPath(type);
	if (onLineType == null)
	    return null;
    
	try {
	    mgr = (AttributeManager) onLineType.newInstance();
	}
	catch (IllegalAccessException e) {
	    /* BEGIN JSTYLED */
	    throw new ParseException(Global.fmtMsg("sunsoft.jws.visual.rt.type.AMConverter.FMT.1", Global.getMsg("sunsoft.jws.visual.rt.type.AMConverter.Could__not__access__"), onLineType.getName()));
	    /* END JSTYLED */
	}
	catch (InstantiationException e) {
	    /* BEGIN JSTYLED */
	    throw new ParseException(Global.fmtMsg("sunsoft.jws.visual.rt.type.AMConverter.FMT.2", Global.getMsg("sunsoft.jws.visual.rt.type.AMConverter.Could__not__instantiat.2"), onLineType.getName()));
	    /* END JSTYLED */
	}
    
	if (mgr != null) {
	    // Assign name of shadow object
	    mgr.set(/* NOI18N */"name", name);
	}
    
	return mgr;
    }

    private void convertChildren(double version,
				 AttributeManager parent, String attr) {
	String type, name;
	String children = attrlistconv.convertFromString
	    (version, parent, attr);
	if (children == null)
	    return;
    
	Enumeration e = ListParser.getListElements(children, 3);
    
	while (e.hasMoreElements()) {
	    type = null;
	    name = null;
	    attr = null;
        
	    try {
		type = (String)e.nextElement();
		name = (String)e.nextElement();
		attr = (String)e.nextElement();
	    }
	    catch (NoSuchElementException ex) {
		throw new ParseException(Global.newline() +
					 /* BEGIN JSTYLED */
					 Global.getMsg("sunsoft.jws.visual.rt.type.AMConverter.________Incomplete__attri.3") +
					 /* END JSTYLED */
		 Global.newline() + /* NOI18N */"      type = " + type +
		 Global.newline() + /* NOI18N */"      name = " + name +
		 Global.newline() + /* NOI18N */"      attr = " + attr);
	    }
        
	    AttributeManager child = convertParent(type, name);
	    if (child == null)
		continue;
        
	    //
	    // Insert a frame around any panels that are
	    // immediate children
	    // of the root, and mark the frame as a panel.
	    //
	    if ((parent instanceof Root) &&
		(child instanceof PanelShadow)) {
		FrameShadow f = new FrameShadow();
		f.isPanel(true);
            
		((AMContainer)parent).add(f);
		f.add(child);
	    } else {
		// REMIND: add error check for non-AMContainer type
		((AMContainer)parent).add(child);
	    }
        
	    convertChildren(version, child, attr);
	}
    }

    /**
     * The conversion of shadow trees into code is performed within the
     * designer and not implemented here.  This method should never be
     * called.
     *
     * @exception Error when an attempt is made to call this method
     */
    public String convertToCode(Object obj) {
	/* BEGIN JSTYLED */
	throw new Error(Global.fmtMsg("sunsoft.jws.visual.rt.type.AMConverter.FMT.3", Global.getMsg("sunsoft.jws.visual.rt.type.AMConverter.will__not__generate__co.4"),
				      Global.getMsg("sunsoft.jws.visual.rt.type.AMConverter.implementation__of__th.5")));
	/* END JSTYLED */
    }
}
