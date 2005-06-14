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
 * @(#) OpAction.java 1.17 - last change made 07/25/97
 */

package sunsoft.jws.visual.rt.type;

import sunsoft.jws.visual.rt.base.*;
import java.util.Hashtable;

/**
* Stores the action that should be triggered in an operation whose
* filter has matched an event or message.  This class 
* also simultaneously
* acts as its own converter.
*
* @see Op
* @version 	1.17, 07/25/97
*/
public class OpAction extends Converter implements Cloneable {
    // Register the converter
    static {
        Converter.addConverter(/* NOI18N */
        "sunsoft.jws.visual.rt.type.OpAction",
        /* NOI18N */"sunsoft.jws.visual.rt.type.OpAction");
    }
    
    /**
     * Action is to set an attribute.
     */
    public static final int ATTRIBUTE = 0;
    
    /**
     * Action is to send a message.
     */
    public static final int MESSAGE = 1;
    
    /**
     * Action is to execute some code.
     */
    public static final int CODE = 2;
    
    // Action Details
    public static final int SHOW = 1;
    public static final int HIDE = 2;
    public static final int EXIT = 3;

	/* BEGIN JSTYLED */
    /**
    * Used when setting the action target, specifies 
    * that the target is
    * permanently set (i.e. always use what is stored in this objects
    * target memeber.
    *
    * @see #target
    */
	/* END JSTYLED */
    public static final int CONSTANT = 10;
    
    /**
    * Used when setting the action target, specifies that 
    * the target should
    * be the same as the target of the event
    * or message that triggered this
    * operation.
    */
    public static final int TARGET = 11;
    
    /**
    * Used when setting the action target, specifies 
    * that the target should
    * be whatever is in the arg variable of the message or event.
    */
    public static final int ARG = 12;
    
    /**
     * Action type, ATTRIBUTE, MESSAGE, or CODE.
     */
    public int actionType;
    
    /**
    * Action detail, used by the action editor to 
    * keep track of simple actions.
    */
    public int actionDetail;
    
    /**
    * Action target, used when targetSource == CONSTANT.
    */
    public AMRef target;
    
    /**
    * Specifies how the target or the action is determined, is either
    * CONSTANT, TARGET, or ARG.
    */
    public int targetSource;
    
    /**
    * Message or Attribute name.
    */
    public String name;
    
	/* BEGIN JSTYLED */
    /** 
    * Message arg or Attribute value, used when valueSource == CONSTANT.
    */
	/* END JSTYLED */
    public Object value;
    
    /**
     * Where is the arg/value from for setting an attribute,
     * is either CONSTANT, TARGET, or ARG.
     */
    public int valueSource;
    
    /**
     * Message type, used when the action is to send a message.
     */
    public String type;
    
    /**
     * Message target name, used when the action is to send a message.
     */
    public String targetName;
    
    /**
     * The code associate with the action, in string form.
     */
    public String code;
    
    /**
     * Constructs an instance where targetSource and 
     * valueSource are CONSTANT.
    */
    public OpAction() {
        this.targetSource = CONSTANT;
        this.valueSource = CONSTANT;
    }
    
    /**
     * Constructs an instance where targetSource and 
     * valueSource are CONSTANT.
    */
    public OpAction(int actionType, AMRef target, String name,
    Object value) {
        this.actionType = actionType;
        this.target = target;
        this.name = name;
        this.targetSource = CONSTANT;
        this.value = value;
        this.valueSource = CONSTANT;
    }
    
    /**
     * Performs the action.
     *
     * @param target the target of the action if targetSource == TARGET
     * @param arg the argument of the message or event 
     * and the target of the action if targetSource == ARG
     * @param scope the root tree in which to search for the target
     */
    void invoke(Object target, Object arg, Root scope) {
        if (name == null)
            return;
        
        // Lookup the target
        AttributeManager mgr = lookupTarget(target, arg, scope);
        if (mgr == null)
            return;
        
        // Lookup the value
        Object value = lookupValue(target, arg, scope);
        
        // Perform the action
        performAction(mgr, value);
    }
    
    private AttributeManager lookupTarget(Object target, Object arg,
    Root scope) {
        AttributeManager mgr = null;
        
        switch (targetSource) {
            case CONSTANT:
            if (this.target != null)
                mgr = this.target.getRef(scope);
            break;
            
            case TARGET:
            mgr = (AttributeManager)target;
            break;
            
            case ARG:
            mgr = (AttributeManager)arg;
            break;
        }
        
        return mgr;
    }
    
    private Object lookupValue(Object target, Object arg, Root scope) {
        Object value = null;
        
        switch (valueSource) {
            case CONSTANT:
            value = this.value;
            break;
            
            case TARGET:
            value = target;
            break;
            
            case ARG:
            value = arg;
            break;
        }
        
        return value;
    }
    
    private void performAction(AttributeManager target, Object value) {
        switch (actionType) {
            case ATTRIBUTE:
            if (name != null)
                target.set(name, value);
            break;
            
            case MESSAGE:
            if (name != null)
                target.postMessage(new Message(target, targetName,
            type, name, value));
            break;
            
            case CODE:
            System.out.println(/* NOI18N */"CODE: " + code);
            break;
        }
    }
    
    /**
     * Returns a new copy of this action.
     */
    public Object clone() {
        try {
            return super.clone();
        } catch (CloneNotSupportedException e) {
            // this shouldn't happen, since we are Cloneable
            throw new InternalError();
        }
    }
    
    //
    // Code generation
    //
    
    /**
     * Appends the initialization code for this operation filter into
     * the buffer given.
     *
     * @param varname variable name of the operation filter
     * @param buf buffer onto which the code should be appended
     */
    public void genInitCode(StringBuffer buf, String varname) {
        // Action type
        buf.append(/* NOI18N */"    ");
        buf.append(varname);
        buf.append(/* NOI18N */".actionType = ");
        buf.append(/* NOI18N */"OpAction.");
        buf.append(constantToString(actionType));
        buf.append(/* NOI18N */";");
        Global.newline(buf);
        
        // Target
        if (target != null) {
            buf.append(/* NOI18N */"    ");
            buf.append(varname);
            buf.append(/* NOI18N */".target = new AMRef(");
            ListParser.quote(target.getName(), buf, true);
            buf.append(/* NOI18N */");");
            Global.newline(buf);
        }
        
        // Target source
        if (targetSource != CONSTANT) {
            buf.append(/* NOI18N */"    ");
            buf.append(varname);
            buf.append(/* NOI18N */".targetSource = ");
            buf.append(/* NOI18N */"OpAction.");
            buf.append(constantToString(targetSource));
            buf.append(/* NOI18N */";");
            Global.newline(buf);
        }
        
        // Name
        if (name != null) {
            buf.append(/* NOI18N */"    ");
            buf.append(varname);
            buf.append(/* NOI18N */".name = ");
            ListParser.quote(name, buf, true);
            buf.append(/* NOI18N */";");
            Global.newline(buf);
        }
        
        // Value source
        if (valueSource != CONSTANT) {
            buf.append(/* NOI18N */"    ");
            buf.append(varname);
            buf.append(/* NOI18N */".valueSource = ");
            buf.append(/* NOI18N */"OpAction.");
            buf.append(constantToString(valueSource));
            buf.append(/* NOI18N */";");
            Global.newline(buf);
        }
        
        // Value
        if (value != null) {
            // Lookup converter for value
            String valueType = value.getClass().getName();
            if (Converter.hasConverter(valueType)) {
                Converter c = Converter.getConverter(valueType);
                buf.append(/* NOI18N */"    ");
                buf.append(varname);
                buf.append(/* NOI18N */".value = ");
                buf.append(c.convertToCode(value));
                buf.append(/* NOI18N */";");
                Global.newline(buf);
            }
        }
        
        // Message type
        if (type != null) {
            buf.append(/* NOI18N */"    ");
            buf.append(varname);
            buf.append(/* NOI18N */".type = ");
            ListParser.quote(type, buf, true);
            buf.append(/* NOI18N */";");
            Global.newline(buf);
        }
        
        // Message target name
        if (targetName != null) {
            buf.append(/* NOI18N */"    ");
            buf.append(varname);
            buf.append(/* NOI18N */".targetName = ");
            ListParser.quote(targetName, buf, true);
            buf.append(/* NOI18N */";");
            Global.newline(buf);
        }
    }
    
    //
    // String converters
    //
    
    private String constantToString(int c) {
        switch (c) {
            // Action consts
            case ATTRIBUTE:
            return /* NOI18N */"ATTRIBUTE";
            case MESSAGE:
            return /* NOI18N */"MESSAGE";
            case CODE:
            return /* NOI18N */"CODE";
            
            // Source consts
            case CONSTANT:
            return /* NOI18N */"CONSTANT";
            case TARGET:
            return /* NOI18N */"TARGET";
            case ARG:
            return /* NOI18N */"ARG";
            
            default:
            return null;
        }
    }
    
    private int stringToConstant(String s) {
        // Action consts
        if (s.equals(/* NOI18N */"ATTRIBUTE"))
            return ATTRIBUTE;
        else if (s.equals(/* NOI18N */"MESSAGE"))
            return MESSAGE;
        else if (s.equals(/* NOI18N */"CODE"))
            return CODE;
        
        // Source consts
        else if (s.equals(/* NOI18N */"CONSTANT"))
            return CONSTANT;
        else if (s.equals(/* NOI18N */"TARGET"))
            return TARGET;
        else if (s.equals(/* NOI18N */"ARG"))
            return ARG;
        
        else
            return -1;
    }
    
    public void convertToString(Object obj, StringBuffer buf) {
        OpAction a = (OpAction)obj;
        
        // Open brace
        buf.append(/* NOI18N */"{");
        newline(buf);
        incrIndent();
        
        // Action type
        indent(buf);
        buf.append(/* NOI18N */"actionType ");
        buf.append(constantToString(a.actionType));
        newline(buf);
        
        // Action detail
        if (a.actionDetail != 0) {
            indent(buf);
            buf.append(/* NOI18N */"actionDetail ");
            buf.append(Integer.toString(a.actionDetail));
            newline(buf);
        }
        
        // Action target
        if (a.target != null) {
            indent(buf);
            buf.append(/* NOI18N */"target ");
            buf.append(a.target.getName());
            newline(buf);
        }
        
        // Target source
        if (a.targetSource != CONSTANT) {
            indent(buf);
            buf.append(/* NOI18N */"targetSource ");
            buf.append(constantToString(a.targetSource));
            newline(buf);
        }
        
        // Name
        if (a.name != null) {
            indent(buf);
            buf.append(/* NOI18N */"name ");
            ListParser.quote(a.name, buf, false);
            newline(buf);
        }
        
        // Value
        if (a.value != null) {
            indent(buf);
            buf.append(/* NOI18N */"value ");
            
            // Lookup converter for value
            String valueType = value.getClass().getName();
            if (Converter.hasConverter(valueType)) {
                Converter c = Converter.getConverter(valueType);
                ListParser.quote(c.convertToString(value), buf, false);
            } else {
                buf.append(/* NOI18N */"null");
            }
            
            newline(buf);
            
            indent(buf);
            buf.append(/* NOI18N */"valueType ");
            buf.append(valueType);
            newline(buf);
        }
        
        // Value source
        if (a.valueSource != CONSTANT) {
            indent(buf);
            buf.append(/* NOI18N */"valueSource ");
            buf.append(constantToString(a.valueSource));
            newline(buf);
        }
        
        // Message type
        if (a.type != null) {
            indent(buf);
            buf.append(/* NOI18N */"type ");
            ListParser.quote(a.type, buf, false);
            newline(buf);
        }
        
        // Message target name
        if (a.targetName != null) {
            indent(buf);
            buf.append(/* NOI18N */"targetName ");
            ListParser.quote(a.targetName, buf, false);
            newline(buf);
        }
        
        // Code
        if (a.code != null) {
            indent(buf);
            buf.append(/* NOI18N */"code ");
            ListParser.list(a.code, buf);
            newline(buf);
        }
        
        // Close brace
        decrIndent();
        indent(buf);
        buf.append(/* NOI18N */"}");
    }
    
    public Object convertFromString(String s) {
        OpAction action = new OpAction();
        convertFromString(s, action);
        return action;
    }
    
    public void convertFromString(String s, OpAction a) {
        Hashtable table = ListParser.makeListTable(s);
        String val;
        
        // Action type
        val = (String)table.get(/* NOI18N */"actionType");
        a.actionType = stringToConstant(val);
        
        // Action detail
        val = (String)table.get(/* NOI18N */"actionDetail");
        if (val != null) {
            try {
                a.actionDetail = Integer.parseInt(val);
            }
            catch (NumberFormatException ex) {
                /* JSTYLED */
                        throw new ParseException(Global.fmtMsg("sunsoft.jws.visual.rt.type.OpAction.NumberFormatException", val));
            }
        }
        
        // Action target
        val = (String)table.get(/* NOI18N */"target");
        if (val != null)
            a.target = new AMRef(val);
        
        // Target source
        val = (String)table.get(/* NOI18N */"targetSource");
        if (val != null)
            a.targetSource = stringToConstant(val);
        
        // Name
        a.name = (String)table.get(/* NOI18N */"name");
        
        // Value
        val = (String)table.get(/* NOI18N */"value");
        if (val != null) {
            if (val.equals(/* NOI18N */"null")) {
                a.value = null;
            } else {
                String valueType = (String)table.get(/* NOI18N */
                "valueType");
                if (valueType == null) { /* JSTYLED */
                            throw new ParseException(Global.fmtMsg("sunsoft.jws.visual.rt.type.OpAction.ValWithoutType", s));
            }
            
            if (!Converter.hasConverter(valueType)) {
                throw new ParseException(Global.fmtMsg(
                "sunsoft.jws.visual.rt.type.OpAction.NoConverter",
                valueType));
            }
            /* JSTYLED */
                        a.value = Converter.getConverter(valueType).convertFromString(val);
        }
    }
    
    // Value source
    val = (String)table.get(/* NOI18N */"valueSource");
    if (val != null)
        a.valueSource = stringToConstant(val);
    
    // Message type
    a.type = (String)table.get(/* NOI18N */"type");
    
    // Message target name
    a.targetName = (String)table.get(/* NOI18N */"targetName");
    
    // Code
    a.code = (String)table.get(/* NOI18N */"code");
}

/**
 * Returns true if this type should be displayed in an editor.
 *
 * For the attribute editor, a return value of false means that the
 * the textfield will be hidden.
 *
 * @return false
 */
public boolean viewableAsString() {
    return (false);
}
}
