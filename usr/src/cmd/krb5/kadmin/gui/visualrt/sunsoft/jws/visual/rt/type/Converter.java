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
 * @(#) Converter.java 1.65 - last change made 08/20/97
 */

package sunsoft.jws.visual.rt.type;

import sunsoft.jws.visual.rt.base.Global;

import sunsoft.jws.visual.rt.base.*;

import java.util.*;

/**
* Base class for all converters.  Converts a type of 
* object to a string
* and back again.
*
* @version 1.65, 08/20/97
*/

public abstract class Converter {
    /**
     * Table of names for each registered converter.
     */
    private static Hashtable converterNameTable = new Hashtable();
    
    /**
     * Table of instances for each converter that has 
     * been instantiated.
    */
    private static Hashtable converterInstanceTable = new Hashtable();
    
    /**
     * Adds a new type converter to the global table of converters.  A
     * converter must be listed for this table in order for the search
     * for a converter for that particular type to be successful.
     *
     * @param typeName the name of the type (what is returned by a 
     * call to getClass().getType() for an instance of that type)
     * @param converterClassName the full name of the converter class
     */
    public static void addConverter(String typeName,
				    String converterClassName) {
        converterNameTable.put(typeName, converterClassName);
    }
    
    /**
     * Initialize the type converters for the types we know about.
     */
    static {
        addConverter(/* NOI18N */"[I", /* NOI18N */
		     "sunsoft.jws.visual.rt.type.IntArrayConverter");
        addConverter(/* NOI18N */"[D", /* NOI18N */
		     "sunsoft.jws.visual.rt.type.DoubleArrayConverter");
        addConverter(/* NOI18N */"java.lang.String",
		     /* NOI18N */"sunsoft.jws.visual.rt.type.StringConverter");
        addConverter(/* NOI18N */"[Ljava.lang.String;",
	     /* NOI18N */"sunsoft.jws.visual.rt.type.StringArrayConverter");
        addConverter(/* NOI18N */"java.lang.Boolean",
	     /* NOI18N */"sunsoft.jws.visual.rt.type.BooleanConverter");
        addConverter(/* NOI18N */"java.lang.Character",
	     /* NOI18N */"sunsoft.jws.visual.rt.type.CharacterConverter");
        addConverter(/* NOI18N */"java.lang.Integer",
	     /* NOI18N */"sunsoft.jws.visual.rt.type.IntegerConverter");
        addConverter(/* NOI18N */"java.awt.Color",
		     /* NOI18N */"sunsoft.jws.visual.rt.type.ColorConverter");
        addConverter(/* NOI18N */"java.awt.SystemColor",
		     /* NOI18N */"sunsoft.jws.visual.rt.type.ColorConverter");
        addConverter(/* NOI18N */"java.awt.Font",
		     /* NOI18N */"sunsoft.jws.visual.rt.type.FontConverter");
        addConverter(/* NOI18N */"java.awt.Point",
		     /* NOI18N */"sunsoft.jws.visual.rt.type.PointConverter");
        addConverter(/* NOI18N */"java.awt.Dimension",
	     /* NOI18N */"sunsoft.jws.visual.rt.type.DimensionConverter");
        addConverter(/* NOI18N */"java.awt.Insets",
		     /* NOI18N */"sunsoft.jws.visual.rt.type.InsetsConverter");
        addConverter(/* NOI18N */
		     "sunsoft.jws.visual.rt.awt.GBConstraints",
	     /* NOI18N */"sunsoft.jws.visual.rt.type.GBConstraintsConverter");
        addConverter(/* NOI18N */
		     "sunsoft.jws.visual.rt.base.AttributeManager",
		     /* NOI18N */"sunsoft.jws.visual.rt.type.AMConverter");
        addConverter(/* NOI18N */"sunsoft.jws.visual.rt.type.AMRef",
		     /* NOI18N */"sunsoft.jws.visual.rt.type.AMRefConverter");
        addConverter(/* NOI18N */
		     "sunsoft.jws.visual.rt.base.Attribute",
	     /* NOI18N */"sunsoft.jws.visual.rt.type.AttributeConverter");
        addConverter(/* NOI18N */
		     "sunsoft.jws.visual.rt.base.AttributeList",
	     /* NOI18N */"sunsoft.jws.visual.rt.type.AttributeListConverter");
        addConverter(/* NOI18N */"sunsoft.jws.visual.rt.type.ImageRef",
	     /* NOI18N */"sunsoft.jws.visual.rt.type.ImageRefConverter");
        addConverter(/* NOI18N */
		     "sunsoft.jws.visual.rt.type.AlignmentEnum",
	     /* NOI18N */"sunsoft.jws.visual.rt.type.BaseEnumConverter");
        addConverter(/* NOI18N */
		     "sunsoft.jws.visual.rt.type.AnchorEnum",
	     /* NOI18N */"sunsoft.jws.visual.rt.type.BaseEnumConverter");
        addConverter(/* NOI18N */
		     "sunsoft.jws.visual.rt.type.OrientationEnum",
	     /* NOI18N */"sunsoft.jws.visual.rt.type.BaseEnumConverter");
        addConverter(/* NOI18N */
		     "sunsoft.jws.visual.rt.type.ReliefEnum",
	     /* NOI18N */"sunsoft.jws.visual.rt.type.BaseEnumConverter");
        addConverter(/* NOI18N */"sunsoft.jws.visual.rt.type.ModeEnum",
	     /* NOI18N */"sunsoft.jws.visual.rt.type.BaseEnumConverter");
        addConverter(/* NOI18N */"unknown", /* NOI18N */
		     "sunsoft.jws.visual.rt.type.UnknownTypeConverter");
    }
    
    /**
     * Returns an existing converter for the given type.  Creates a new
     * converter only if necessary (typically the first 
     * time one is asked for.)
    */
    public static Converter getConverter(String typeName) {
        Converter converter;
        
        converter = (Converter)converterInstanceTable.get(typeName);
        if (converter != null)
            return converter;
        
        String converterType = (String) converterNameTable.get
	    (typeName);
        if (converterType == null) {
            /* JSTYLED */
	    // Load the class for the type and try again. Some types have
            // static initializers that register their converters.
            loadType(typeName);
            converterType = (String) converterNameTable.get(typeName);
        }
        
        if (converterType == null) {
            converterType = (String) converterNameTable.get
		(/* NOI18N */"unknown");
            if (converterType == null)
                /* JSTYLED */
		throw new Error(Global.getMsg("sunsoft.jws.visual.rt.type.Converter.No__converter__defined.20"));
        }
        try {
            Class c = Class.forName(converterType);
            converter = (Converter) c.newInstance();
            converter.setConverterType(typeName);
            converterInstanceTable.put(typeName, converter);
            return converter;
        }
        catch (Exception e) {
            throw new Error(e.getMessage());
        }
    }
    
    private static void loadType(String typeName) {
        // For arrays, use the array type
        if (typeName.charAt(0) == /* NOI18N */ '[') {
            int i;
            int len = typeName.length();
            for (i = 0; i < len; i++) {
                if (typeName.charAt(i) != /* NOI18N */ '[')
                    break;
            }
            i++;
            if (i < len)
                typeName = typeName.substring(i, len-1);
        }
        
        try {
            Class.forName(typeName);
        }
        catch (ClassNotFoundException ex) {
            /* JSTYLED */
	    System.out.println(Global.getMsg("sunsoft.jws.visual.rt.type.Converter.Class__not__found__for__.21") + typeName + /* NOI18N */"\".");
        }
    }
    
    /**
     * Returns true if there is a converter for the given type.
     */
    public static boolean hasConverter(String typeName) {
        return (converterNameTable.containsKey(typeName));
    }
    
    /**
     * The type editors (for more complex types.)
     */
    private static Hashtable typeEditorNameTable = new Hashtable();
    
    /**
     * Registers a type editor for a type.  At run-time (in generated
     * applications) there will typically be no editors, but they are
     * needed for the attribute editor in the designer.  The designer
     * will set up all the standard ones.
     *
     * @see TypeEditor
     */
    public static void addTypeEditor(String typeName,
				     String editorClassName) {
        typeEditorNameTable.put(typeName, editorClassName);
    }
    
    /**
     * Returns true if there is an editor for the given type.
     *
     * @see TypeEditor
     */
    public static boolean hasTypeEditor(String typeName) {
        return (typeEditorNameTable.containsKey(typeName));
    }
    
    /* BEGIN JSTYLED */
    /**
     * Returns a new instance of a type editor.  
     * The caller (typically the
     * Designer) gets a new one of these every time, one for each
     * attribute being edited, even if they are the same type.  Caching
     * instances of these type editors is up to the caller.
     */
    /* END JSTYLED */
    
    public static TypeEditor newTypeEditor(String typeName) {
        String editorType = (String) typeEditorNameTable.get(typeName);
        
        if (editorType != null) {
            try {
                // instances of type editors are NOT cached
                Class c = Class.forName(editorType);
                return ((TypeEditor) c.newInstance());
            }
            catch (Exception ex) {
                /* JSTYLED */
		throw new VJException(Global.newline() + /* NOI18N */"    " + ex.toString());
            }
        }
        
        return null;
    }
    
    /**
     * Returns whether a converter instance has an 
     * associated type editor.
     *
     * @see TypeEditor
     */
    public boolean hasTypeEditor() {
        return (hasTypeEditor(getConverterType()));
    }
    
    /**
     * Returns a new instance of the type editor associated with this
     * converter.
     */
    public TypeEditor newTypeEditor() {
        return (newTypeEditor(getConverterType()));
    }
    /* JSTYLED */
    // ------ Interfaces for Sub-Classers -----------------------------------
    
    /**
     * The name of the type being edited.
     */
    protected String converterType;
    
    /**
     * An interface that can be overridden in sub-classes 
     * to whom the type
     * converted is important.
     *
     * @see BaseEnumConverter
     */
    protected void setConverterType(String type) {
        converterType = type;
    }
    
    /**
     * Returns the type of object converted by this converter.
     */
    public String getConverterType() {
        return (converterType);
    }
    
    /* BEGIN JSTYLED */
    /**
     * Returns the string representation for an instance of 
     * the type this
     * converter converts.  Must be declared in subclasses 
     * to convert an
     * object of the type specific to that subclass of Converter.
     * <p>
     * One of the two "convertToString" methods must be overridden in
     * the converter sub-class.  The overridden "convertToString" 
     * method
     * should NOT call "super.convertToString".  It is preferrable to
     * override the StringBuffer version (the other one) because this
     * will result in better performance.
     */
    /* END JSTYLED */
    public String convertToString(Object obj) {
        enterConvert(TOSTRING, false);
        StringBuffer buf = new StringBuffer();
        convertToString(obj, buf);
        exitConvert(TOSTRING, false);
        
        return buf.toString();
    }
    
    /**
     * Places a string representation of an instance of the type this
     * converter converts into a string buffer.
     */
    public void convertToString(Object obj, StringBuffer buf) {
        enterConvert(TOSTRING, true);
        buf.append(convertToString(obj));
        exitConvert(TOSTRING, true);
    }
    
    /**
     * Returns a new instance of the type this converter converts, as
     * specified by the string given.  Must be declared 
     * in subclasses of
     * Converter to convert a string representation into an object of
     * the type converted by the subclass.
     */
    public abstract Object convertFromString(String s);
    
    /**
     * Converts an instance of the type into a block of code.
     */
    public void convertToCodeBlock(String amName,
				   Attribute a, int indent, StringBuffer buf) {
        
        Converter c = getConverter(a.getType());
        String attr_name;
        
        indent(buf, indent);
        buf.append(amName);
        buf.append(/* NOI18N */".set(\"");
        attr_name = a.getName();
        buf.append(attr_name);
        buf.append(/* NOI18N */"\", ");
        buf.append(c.convertToCode(a.getValue()));
        buf.append(/* NOI18N */");");
        newline(buf);
    }
    
    /**
     * Converts an instance of the type converted into a line of code.
     * This method provides a default way for any type to get a
     * convertToCode method into it.  It generates code that will feed
     * the string representation of the object into the 
     * appropriate type
     * converter.  The performance isn't as good as customized
     * convertToCode functions in subclasses since more classes have to
     * be loaded at runtime.
     */
    public String convertToCode(Object obj) {
        if (obj != null)
            return (/* NOI18N */"convert(\"" +
		    obj.getClass().getName() + /* NOI18N */"\", \""
		    + convertToString(obj) + /* NOI18N */"\")");
        else
            return (/* NOI18N */"null");
    }
    
    /**
     * Returns the string that should be displayed in the attribute
     * editor.  Subclassers that want something displayed other than
     * what is returned from convertToString should override this
     * method to return that.
     */
    public String displayString(Object obj) {
        return (convertToString(obj));
    }
    
    /**
     * Returns true if this type should be displayed in an editor.
     *
     * For the attribute editor, a return value of false means that the
     * the textfield will be hidden.
     *
     * @return true
     */
    public boolean viewableAsString() {
        return true;
    }
    
    /**
     * Returns true if this type is simple enough to be 
     * edited as a string
     * in an editor.
     *
     * Sub-classers that represent type too complex for
     * this should override
     * this function to return false.  For the attribute editor,
     * this means
     * that the textfield will be read-only.
     *
     * @see #viewableAsString
     * @return same as viewableAsString
     */
    public boolean editableAsString() {
        return viewableAsString();
    }
    
    /**
     * These weird looking enter/exit methods ensure that the converter
     * sub-class is overriding at least one of the "convertToString"
     * methods, and at least one of the "convertToCode" methods.
     * An error will be thrown at runtime if this in not the case.
     * If this check wasn't done here , then the failure to 
     * override one
     * of the methods would result in an infinite loop.
     */
    private static final int TOSTRING = 0;
    private static final int TOCODE = 1;
    
    private boolean converting[] = {false, false};
    private boolean isBuffered[] = {false, false};
    private int convertRecurse[] = {0, 0};
    
    private void enterConvert(int c, boolean isBuffered) {
        if (converting[c] && this.isBuffered[c] != isBuffered)
            throw new Error(Global.getMsg(
	  "sunsoft.jws.visual.rt.type.Converter.Sub-classes__of__Conve.22"));
        
        this.isBuffered[c] = isBuffered;
        converting[c] = true;
        convertRecurse[c]++;
    }
    
    private void exitConvert(int c, boolean isBuffered) {
        if (!converting[c])
	    /* BEGIN JSTYLED */
	    throw new Error(Global.getMsg("sunsoft.jws.visual.rt.type.Converter.Convert__exit__without.25"));
                
	if (this.isBuffered[c] != isBuffered)
	    throw new Error(Global.getMsg("sunsoft.jws.visual.rt.type.Converter.isBuffered__mismatch__.26"));
                
	/* END JSTYLED */
	convertRecurse[c]--;
        if (convertRecurse[c] == 0)
            converting[c] = false;
    }
    /* BEGIN JSTYLED */
    // ------ Utility Functions ----------------------------------------------
            
    /**
     * Returns a string that can be used as a newline.  
     * This string includes
     * a carriage return if we are running on Windows.
     */
    /* END JSTYLED */
    public static String newline() {
        return Global.newline();
    }
    
    /**
     * Appends a newline to buf.  This also appends a carriage return
     * if we are running on Windows.
     */
    public static void newline(StringBuffer buf) {
        Global.newline(buf);
    }
    
    private static final String indentString = /* NOI18N */"  ";
    private static int indentLevel = 0;
    
    /**
     * Appends spaces to "buf" based on the current indent level.
     */
    protected static void indent(StringBuffer buf) {
        for (int i = 0; i < indentLevel; i++)
            buf.append(indentString);
    }
    
    /**
     * Appends spaces to "buf" based on the given indent level.
     */
    protected static void indent(StringBuffer buf, int indentLevel) {
        for (int i = 0; i < indentLevel; i++)
            buf.append(/* NOI18N */ ' ');
    }
    
    /**
     * Increments the indent level.
     */
    protected static void incrIndent() {
        indentLevel++;
    }
    
    /**
     * Decrements the indent level.
     */
    protected static void decrIndent() {
        indentLevel--;
    }
    
    /**
     * Returns the current indent level.
     */
    protected static int indentLevel() {
        return indentLevel;
    }
    
    /**
     * Returns the last token in a class name.  i.e. the name that you
     * can use for a class when you've imported the class already.
     */
    public static String shortClassName(String className) {
        int index = className.lastIndexOf(/* NOI18N */ '.');
        if (index == -1)
            return (className);
        else
            return (className.substring(index + 1));
    }
    
}
