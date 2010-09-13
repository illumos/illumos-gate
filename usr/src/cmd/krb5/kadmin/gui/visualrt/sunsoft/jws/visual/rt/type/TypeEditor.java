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
 * @(#) TypeEditor.java 1.11 - last change made 07/25/97
 */

package sunsoft.jws.visual.rt.type;

import sunsoft.jws.visual.rt.base.*;
import sunsoft.jws.visual.rt.awt.VJErrorDialog;

import java.util.*;

/**
 * Base class for type editors.  This should be subclassed for each
 * new type editor that needs to be added to the designer.
 * TypeEditors are used by the Designer's attribute editor in order to
 * edit the values of complex types, like Colors, Fonts, and arrays.
 *
 * @see Converter
 * @version 1.11, 07/25/97
 */
public abstract class TypeEditor extends Group {
    
    /**
     * Set the hasChanges flag to true as soon as the user 
     * edits anything.
    */
    protected boolean hasChanges = false;
    
    // Most recent value from setValue, or from the most recent apply
    private Object resetValue;
    
    // Disabled title
    private String disabledTitle = /* NOI18N */"<no value>";
    
    // Indicates if the resetValue has been changed while the group was
    // not showing.
    private boolean resetValueChanged;
    
    // List of child type editors
    private Vector children = new Vector();
    
    // State flag for apply
    private boolean applying = false;
    
    // Error messages
    private VJErrorDialog errorDialog;
    
    // Are we enabled?
    private boolean isEnabled = true;
    
    // Editor parent
    private TypeEditor parentEditor;
    
    /**
     * Creates a new instance of TypeEditor with an attribute called
     * "enabled" that is a Boolean and is set to true when the type
     * editor should be graphically enabled (i.e. not greyed out.)
     */
    public TypeEditor() {
        attributes.add(/* NOI18N */"enabled", /* NOI18N */
		       "java.lang.Boolean", Boolean.TRUE, DEFAULT);
    }
    
    public Object get(String key) {
        if (key.equals(/* NOI18N */"enabled")) {
            return new Boolean(isEnabled);
        } else {
            return super.get(key);
        }
    }
    
    public void set(String key, Object value) {
        if (key.equals(/* NOI18N */"enabled")) {
            enable(((Boolean)value).booleanValue());
        } else {
            super.set(key, value);
        }
    }
    
    //
    // Methods that subclasses should override
    //
    
    /**
     * Subclassers should override this method.
     *
     * This method should return a new value based on the edits that
     * the user has made.
     *
     * The values from the child type editors need not be queried
     * during this method.  Any children who have unapplied changes
     * will have already been dealt with by calls to 
     * the updateFromChild
     * method.
     */
    protected abstract Object getApplyValue() throws ApplyException;
    
    /**
     * Subclassers should override this method.
     *
     * This method is called when the child's value has been applied.
     *
     * Do NOT call apply from this method.  All you have to do is
     * record the new value for the child in your state.  Then,
     * when getApplyValue is called, the new value from the child
     * should be reflected in the return value from getApplyValue.
     */
    protected void childApply(TypeEditor child, Object value) { }
    
    /**
     * Subclassers should override this method.
     *
     * This method should load the user interface from a given value.
     *
     * The loading of the child editors is dealt with using the
     * getValueForChild method.
     */
    protected abstract void resetFromValue(Object value);
    
    /**
     * Subclassers should override this method.
     *
     * Return true if the given child should be enabled for the
     * given value.  Otherwise return false.  If this method returns
     * true, then getValueForChild will be called next.
     */
    protected boolean shouldEnableChild(TypeEditor child,
					Object value) {
        return true;
    }
    
    /**
     * Subclassers may wish to override this method.
     *
     * This method is called during a reset operation.  If this method
     * is not overridden, then the child values will be set to null.
     *
     * The return value should be some subset of the value parameter.
     * The value parameter is the same value that is passed to the
     * resetFromValue method.
     */
    protected void resetChildFromValue(TypeEditor child, Object value)
    {
        child.setValue(null);
    }
    
    /**
     * Subclassers should override this method.
     *
     * When enableEditor is called with a true value, then all the
     * editor components should be enabled.
     *
     * When invoked with a false value, all the components should
     * be disabled except for the Cancel and Help buttons.
     */
    protected abstract void enableEditor(Boolean enable);
    
    /**
     * Returns a title string based on the given component and
     * attribute names.
     */
    protected String getTitle(String compName, String attrName) {
        if (compName == null && attrName == null)
            return disabledTitle;
        else
            return compName + /* NOI18N */" " + attrName;
    }
    
    /**
     * Sets the title of the window based on the given component name
     * and attribute name.
     */
    public void setTitle(String compName, String attrName) {
        if (hasAttribute(/* NOI18N */"title"))
            set(/* NOI18N */"title", getTitle(compName, attrName));
        
        Enumeration e = children.elements();
        while (e.hasMoreElements()) {
            TypeEditor child = (TypeEditor)e.nextElement();
            child.setTitle(compName, attrName);
        }
    }
    
    /**
     * Subclassers may wish to override this method.
     *
     * Returns a string to be placed within a button in the attribute
     * editor.  If non-null is returned, then in place of a text field
     * or choice menu in the attribute editor, a button will be placed
     * in the slot that can only be used for calling up a type editor.
     * The button will contain the text returned.
     *
     * The default value, null, means that the type's regular converter
     * should be consulted for how to display the type in the attribute
     * editor slot.
     */
    public String editorButtonName() {
        return (null);
    }
    
    //
    // Do not override these methods in subclasses!
    //
    
    protected void showGroup() {
        enable(isEnabled);
        
        if (resetValueChanged)
            reset();
    }
    
    protected void hideGroup() {
        resetValueChanged = false;
    }
    
    /**
     * Part of TypeEditor implementation, subclassers should NOT
     * override this method.
     */
    public void setParentEditor(TypeEditor parentEditor) {
        this.parentEditor = parentEditor;
    }
    
    /**
     * Part of TypeEditor implementation, subclassers should NOT
     * override this method.
     */
    public TypeEditor getParentEditor() {
        return parentEditor;
    }
    
    /**
     * Part of TypeEditor implementation, subclassers should NOT
     * override this method.
     */
    protected void addChildEditor(TypeEditor child) {
        // check to see that child isn't one of this container's parents
        TypeEditor editor = child.getParentEditor();
        while (editor != null) {
            if (editor == child) {
                throw new VJException(Global.getMsg(
		    "sunsoft.jws.visual.rt.type.TypeEditor.AddChildError"));
            }
            editor = editor.getParentEditor();
        }
        
        if (child.getParentEditor() != null)
            child.getParentEditor().removeChildEditor(child);
        
        children.addElement(child);
        child.setParentEditor(this);
    }
    
    /**
     * Part of TypeEditor implementation, subclassers should NOT
     * override this method.
     */
    protected void removeChildEditor(TypeEditor child) {
        if (child.getParentEditor() != this)
            return;
        
        children.removeElement(child);
        child.setParentEditor(null);
    }
    
    /**
     * Part of TypeEditor implementation, subclassers should NOT
     * override this method.
     */
    protected Enumeration getChildEditorList() {
        return children.elements();
    }
    
    /**
     * Returns true when changes have been made to the value in this
     * type editor (or any of its children) and they have not yet been
     * applied.
     */
    public boolean hasChanges() {
        Enumeration e = children.elements();
        while (e.hasMoreElements()) {
            TypeEditor child = (TypeEditor)e.nextElement();
            if (child.hasChanges())
                return true;
        }
        
        return hasChanges;
    }
    
    /**
     * Clears the change flag in this type editor and all 
     * of its children.
    */
    private void clearChanges() {
        hasChanges = false;
        
        Enumeration e = children.elements();
        while (e.hasMoreElements()) {
            TypeEditor child = (TypeEditor)e.nextElement();
            child.clearChanges();
        }
    }
    
    /**
     * Sets a new value for this type editor to edit and causes the
     * editor to reset its interface based on the new value.
     */
    public void setValue(Object value) {
        resetValue = value;
        resetValueChanged = true;
        reset();
    }
    
    /**
     * Sets a new reset value for this type editor to 
     * reset to, but does not
     * change the current value or cause the editor to reset.
     */
    public void setResetValue(Object value) {
        resetValue = value;
        resetValueChanged = true;
    }
    
    /**
     * Returns the value to which this type editor would 
     * reset to if the user
     * chooses to "Reset".
     */
    public Object getResetValue() {
        return resetValue;
    }
    
    /**
     * Returns true if this type editor is enabled.
     */
    public boolean isEnabled() {
        return isEnabled;
    }
    
    /**
     * Applies all changes made to the value being edited 
     * in this type editor.
     * If the type editor has children, they are made to
     * apply themselves
     * first.  An "Apply" message is posted to the parent
     * with the message
     * argument being the new value of the object edited.
     */
    public boolean apply() {
        if (!isShowing())
            return true;
        
        if (applying || !hasChanges())
            return true;
        
        // Set this flag before calling apply on the children
        applying = true;
        
        Enumeration e = children.elements();
        while (e.hasMoreElements()) {
            TypeEditor child = (TypeEditor)e.nextElement();
            if (!child.apply()) {
                applying = false;
                return false;
            }
        }
        
        Object applyValue;
        try {
            applyValue = getApplyValue();
        }
        catch (ApplyException ex) {
            applying = false;
            showError(ex.getMessage());
            return false;
        }
        
        resetValue = applyValue;
        resetValueChanged = true;
        hasChanges = false;
        
        // Order is important!  Set the hasChanges flag to false BEFORE
        // posting the apply message.
        
        postMessageToParent(new Message(this, /* NOI18N */
					"Apply", applyValue));
        
        // Want to call reset here to catch bugs, but this
        // would be inefficient.
        // So let the AttributeDialog do the reset at the top level.
        
        applying = false;
        return true;
    }
    
    /**
     * Causes the type editor to throw away the current 
     * value being edited
     * and reset to the value last applied.
     */
    public void reset() {
        if (!isShowing())
            return;
        
        hasChanges = false;
        resetFromValue(resetValue);
        
        Enumeration e = children.elements();
        while (e.hasMoreElements()) {
            TypeEditor child = (TypeEditor)e.nextElement();
            
            if (isEnabled && shouldEnableChild(child, resetValue)) {
                child.enable(true);
                resetChildFromValue(child, resetValue);
            } else {
                child.enable(false);
                child.setValue(null);
            }
        }
    }
    
    /**
     * Applies changes and hides the type editor.
     */
    public void ok() {
        if (!isShowing())
            return;
        
        if (apply())
            cancel();
    }
    
    /**
     * Hides the type editor and clears any changes that 
     * have been made to
     * the value being edited.
     */
    public void cancel() {
        if (!isShowing())
            return;
        
        hide();
        clearChanges();
    }
    
    /**
     * Enables or disables the type editor and its children.
     */
    public void enable(boolean enable) {
        isEnabled = enable;
        
        if (!isShowing())
            return;
        
        enableEditor(new Boolean(enable));
        
        // Don't need to enable the children.  The children
        // will be enabled or
        // disabled anyways as the result of a reset operation.
    }
    
    /**
     * Handles "Apply" messages.  These are typically sent by children
     * of the type editor.
     */
    public boolean handleMessage(Message msg) {
        if (!msg.isAWT && msg.name.equals(/* NOI18N */"Apply")) {
            childApply((TypeEditor)msg.target, msg.arg);
            apply();
            return true;
        }
        
        return super.handleMessage(msg);
    }
    
    /**
     * Useful utility method for enabling.  Enables this type editor
     * and all of its children.
     */
    protected void recurseEnable(AttributeManager mgr, Boolean value) {
        if (mgr.hasAttribute(/* NOI18N */"enabled"))
            mgr.set(/* NOI18N */"enabled", value);
        
        if (mgr instanceof AMContainer) {
            AMContainer cntr = (AMContainer)mgr;
            Enumeration e = cntr.getChildList();
            while (e.hasMoreElements()) {
                recurseEnable((AttributeManager)e.nextElement(), value);
            }
        }
    }
    
    //
    // Error messages
    //
    
    /**
     * Brings up a modal error dialog window with the 
     * given message in it
     * and an "Ok" button.
     *
     * @see VJErrorDialog
     */
    protected void showError(String message) {
        if (errorDialog == null)
            errorDialog = new VJErrorDialog(getFrame(), Global.getMsg(
		      "sunsoft.jws.visual.rt.type.TypeEditor.Error"), true);
        
        errorDialog.setLabel(message);
        errorDialog.pack();
        errorDialog.show();
    }
}
