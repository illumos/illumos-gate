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
 * @(#) Op.java 1.15 - last change made 07/25/97
 */

package sunsoft.jws.visual.rt.type;

import sunsoft.jws.visual.rt.base.*;
import java.awt.Event;
import java.util.Hashtable;

/**
 * Stores a single operation.  An operation is an action that will
 * take place when a particular kind of event comes in on the
 * component that owns the operation.  The operation has two main
 * subparts, the filter and the action.  The filter is used to
 * determine which events or messages trigger the performance of the
 * operation's action.  This class also simultaneously acts as its own
 * converter.
 *
 * @see OpFilter
 * @see OpAction
 * @version 1.15, 07/25/97
 */
public class Op extends Converter implements Cloneable {
    
    // Register the converters
    static {
        Converter.addConverter(/* NOI18N */
			       "sunsoft.jws.visual.rt.type.Op",
			       /* NOI18N */"sunsoft.jws.visual.rt.type.Op");
        Converter.addConverter(/* NOI18N */
			       "[Lsunsoft.jws.visual.rt.type.Op;",
	       /* NOI18N */"sunsoft.jws.visual.rt.type.OpArrayConverter");
    }
    
    /**
     * The Root object under which this operation is held.
     */
    public Root scope;
    
    /**
     * The name of the operation.
     */
    public String name;
    
    /**
     * The filter of the operation.  Used to determine 
     * whether a particular
     * event should trigger the operation.
     */
    public OpFilter filter;
    
    /**
     * The action to be taken by the operation.
     */
    public OpAction action;
    
    /**
     * Constructs a new instance.
     */
    public Op() {
    }
    
    /**
     * Constructs a new instance given a scope (attribute 
     * manager tree root)
     * in which to operate.
     */
    public Op(Root scope) {
        this.scope = scope;
    }
    
    /**
     * Returns true if the message given matches the 
     * filter for this operation.
    */
    public boolean matchMessage(Message msg) {
        if (msg.isAWT)
            return filter.match(msg, (Event)msg.arg);
        else
            return filter.match(msg);
    }
    
    /**
     * Returns true if this operation has code associated with it.
     * The code will have been compiled in a separate section 
     * of the generated
     * Ops class and must be specially called upon.
     */
    public boolean hasCode() {
        return (action != null &&
		action.actionType == OpAction.CODE);
    }
    
    /**
     * Evokes the action of this operation if the message 
     * given matches with
     * the operation's filter.
     */
    public boolean handleMessage(Message msg) {
        if (msg.isAWT)
            return handleEvent(msg, (Event)msg.arg);
        
        if (filter.match(msg)) {
            action.invoke(msg.target, msg.arg, scope);
            return true;
        } else {
            return false;
        }
    }
    
    /**
     * Evokes the action of this operation if the event 
     * given matches with
     * the operation's filter.
     */
    public boolean handleEvent(Message msg, Event evt) {
        if (filter.match(msg, evt)) {
            action.invoke(msg.target, evt.arg, scope);
            return true;
        } else {
            return false;
        }
    }
    
    /**
     * Returns a new copy of this operation.  Makes new copies of the
     * internal action and filter members as well.
     */
    public Object clone() {
        Op op;
        
        try {
            op = (Op)super.clone();
        } catch (CloneNotSupportedException e) {
            // this shouldn't happen, since we are Cloneable
            throw new InternalError();
        }
        
        if (op.filter != null)
            op.filter = (OpFilter)op.filter.clone();
        if (op.action != null)
            op.action = (OpAction)op.action.clone();
        
        return op;
    }
    
    //
    // Code generation
    //
    
    /**
     * Appends the initialization code for this operation 
     * into the buffer
     * given.
     *
     * @param name name of the operation
     * @param buf buffer onto which the code should be appended
     */
    public void genInitCode(StringBuffer buf, String name) {
        Global.newline(buf);
        buf.append(/* NOI18N */"    ");
        buf.append(name);
        buf.append(/* NOI18N */" = new Op(gui);");
        Global.newline(buf);
        
        if (this.name != null) {
            buf.append(/* NOI18N */"    ");
            buf.append(name);
            buf.append(/* NOI18N */".name = ");
            ListParser.quote(this.name, buf, true);
            buf.append(/* NOI18N */";");
            Global.newline(buf);
        }
        
        if (filter != null) {
            buf.append(/* NOI18N */"    ");
            buf.append(name);
            buf.append(/* NOI18N */".filter = new OpFilter();");
            Global.newline(buf);
            filter.genInitCode(buf, name + /* NOI18N */".filter");
        }
        
        if (action != null) {
            buf.append(/* NOI18N */"    ");
            buf.append(name);
            buf.append(/* NOI18N */".action = new OpAction();");
            Global.newline(buf);
            action.genInitCode(buf, name + /* NOI18N */".action");
        }
    }
    
    public void convertToString(Object obj, StringBuffer buf) {
        Op op = (Op)obj;
        
        if (op == null)
            return;
        
        buf.append(/* NOI18N */"{");
        newline(buf);
        incrIndent();
        
        if (op.name != null) {
            indent(buf);
            buf.append(/* NOI18N */"name ");
            ListParser.quote(op.name, buf, false);
            newline(buf);
        }
        
        if (op.filter != null) {
            indent(buf);
            buf.append(/* NOI18N */"filter ");
            op.filter.convertToString(op.filter, buf);
            newline(buf);
        }
        
        if (op.action != null) {
            indent(buf);
            buf.append(/* NOI18N */"action ");
            op.action.convertToString(op.action, buf);
            newline(buf);
        }
        
        decrIndent();
        indent(buf);
        buf.append(/* NOI18N */"}");
    }
    
    public Object convertFromString(String s) {
        Op op = new Op();
        convertFromString(s, op);
        return op;
    }
    
    public void convertFromString(String s, Op op) {
        Hashtable table = ListParser.makeListTable(s);
        
        op.name = (String)table.get(/* NOI18N */"name");
        
        s = (String)table.get(/* NOI18N */"filter");
        if (s != null) {
            op.filter = new OpFilter();
            op.filter.convertFromString(s, op.filter);
        }
        
        s = (String)table.get(/* NOI18N */"action");
        if (s != null) {
            op.action = new OpAction();
            op.action.convertFromString(s, op.action);
        }
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
