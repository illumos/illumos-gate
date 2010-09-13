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
 * @(#) OpFilter.java 1.16 - last change made 07/25/97
 */

package sunsoft.jws.visual.rt.type;

import sunsoft.jws.visual.rt.base.*;
import java.awt.Event;
import java.util.Hashtable;

/**
 * Stores the conditions under which an operation 
 * should be activated.  The
* parameters stored here are compared with the fields
* in events and messages
* to determine a match.  This class also simultaneously
* acts as its own
* converter.
*
* @see Op
* @see Message
* @see Event
* @version 	1.16, 07/25/97
*/
public class OpFilter extends Converter implements Cloneable {
    /**
     * The operation should match against an event.
     */
    public static final int EVENT = 0;
    
    /**
     * The operation should match against a message.
     */
    public static final int MESSAGE = 1;
    
    public static final int LEFT_MOUSE = 0;
    public static final int MIDDLE_MOUSE = 8;
    public static final int RIGHT_MOUSE = 4;
    
    // Converter
    static {
        Converter.addConverter(/* NOI18N */
			       "sunsoft.jws.visual.rt.type.OpFilter",
		       /* NOI18N */"sunsoft.jws.visual.rt.type.OpFilter");
    }
    
    /**
     * Filter type, either EVENT or MESSAGE.
     */
    public int filterType;
    
    /**
     * AttributeManager object that should be the target of a matching
     * event or message.
     */
    public AttributeManager target;
    
    /**
     * Target reference (left in for compatibility reasons.)
     */
    public AMRef targetRef;
    
    /**
     * Message filter on name.
     *
     * @see Message#name
     */
    public String name;
    
    /**
     * Message filter on type.
     *
     * @see Message#type
     */
    public String type;
    
    /**
     * Message filter on target name.
     *
     * @see Message#targetName
     */
    public String targetName;
    
    /**
     * Event filter on id.
     *
     * @see Event#id
     */
    public int id;
    
    /**
     * Event filter on key.
     *
     * @see Event#key
     */
    public int key = -1;
    
    /**
     * Event filter on modifiers.
     *
     * @see Event#modifiers
     */
    public int modifiers = -1;
    
    /**
     * Event filter on clickCount.
     *
     * @see Event#clickCount
     */
    public int clickCount = 0;
    
    /**
     * Constructs a new instance.
     */
    public OpFilter() {
    }
    
    /**
     * Constructs a new instance that filters on a message.
     */
    public OpFilter(AttributeManager target, String name) {
        filterType = MESSAGE;
        this.target = target;
        this.name = name;
    }
    
    /**
     * Constructs a new instance that filters on a message.
     */
    public OpFilter(AttributeManager target, String name,
		    String type, String targetName) {
        this(target, name);
        this.type = type;
        this.targetName = targetName;
    }
    
    /**
     * Constructs a new instance that filters on an event.
     */
    public OpFilter(AttributeManager target, int id) {
        filterType = EVENT;
        this.target = target;
        this.id = id;
    }
    
    /**
     * Constructs a new instance that filters on an event.
     */
    public OpFilter(AttributeManager target, int id,
		    int key, int modifiers, int clickCount) {
        this(target, id);
        this.key = key;
        this.modifiers = modifiers;
        this.clickCount = clickCount;
    }
    
    /**
     * Returns true if this filter matches with the message given.
     */
    boolean match(Message msg) {
        if (filterType != MESSAGE)
            return false;
        
        return ((target == null || target == msg.target) &&
		(name == null || name.equals(msg.name)) &&
		(type == null || type.equals(msg.type)) &&
		(targetName == null || targetName.equals(msg.targetName)));
    }
    
    /**
     * Returns true if this filter matches with the event given.
     */
    boolean match(Message msg, Event evt) {
        if (filterType != EVENT)
            return false;
        
        return (evt.id == id &&
		(target == null || target == msg.target) &&
		(key == -1 || evt.key == key) &&
		(modifiers == -1 ||
		 (((evt.modifiers & modifiers) == modifiers) &&
		  ((evt.modifiers & ~modifiers) == 0))) &&
		(clickCount == 0 || evt.clickCount == clickCount));
    }
    
    /**
     * Returns a new copy of this filter.
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
        buf.append(/* NOI18N */"    ");
        buf.append(varname);
        buf.append(/* NOI18N */".filterType = ");
        buf.append(/* NOI18N */"OpFilter.");
        buf.append(constantToString(filterType));
        buf.append(/* NOI18N */";");
        Global.newline(buf);
        
        // The targetRef is used for code generation so that QuickGen can work.
        if (targetRef != null) {
            buf.append(/* NOI18N */"    ");
            buf.append(varname);
            buf.append(/* NOI18N */".target = gui.");
            buf.append(targetRef.getName());
            buf.append(/* NOI18N */";");
            Global.newline(buf);
        }
        
        if (name != null) {
            buf.append(/* NOI18N */"    ");
            buf.append(varname);
            buf.append(/* NOI18N */".name = ");
            ListParser.quote(name, buf, true);
            buf.append(/* NOI18N */";");
            Global.newline(buf);
        }
        
        if (type != null) {
            buf.append(/* NOI18N */"    ");
            buf.append(varname);
            buf.append(/* NOI18N */".type = ");
            ListParser.quote(type, buf, true);
            buf.append(/* NOI18N */";");
            Global.newline(buf);
        }
        
        if (targetName != null) {
            buf.append(/* NOI18N */"    ");
            buf.append(varname);
            buf.append(/* NOI18N */".targetName = ");
            ListParser.quote(targetName, buf, true);
            buf.append(/* NOI18N */";");
            Global.newline(buf);
        }
        
        buf.append(/* NOI18N */"    ");
        buf.append(varname);
        buf.append(/* NOI18N */".id = ");
        buf.append(id);
        buf.append(/* NOI18N */";");
        Global.newline(buf);
        
        if (key != -1) {
            buf.append(/* NOI18N */"    ");
            buf.append(varname);
            buf.append(/* NOI18N */".key = ");
            buf.append(key);
            buf.append(/* NOI18N */";");
            Global.newline(buf);
        }
        
        if (modifiers != -1) {
            buf.append(/* NOI18N */"    ");
            buf.append(varname);
            buf.append(/* NOI18N */".modifiers = ");
            buf.append(modifiers);
            buf.append(/* NOI18N */";");
            Global.newline(buf);
        }
        
        if (clickCount != 0) {
            buf.append(/* NOI18N */"    ");
            buf.append(varname);
            buf.append(/* NOI18N */".clickCount = ");
            buf.append(clickCount);
            buf.append(/* NOI18N */";");
            Global.newline(buf);
        }
    }
    
    //
    // String converters
    //
    
    private String constantToString(int c) {
        switch (c) {
	case EVENT:
            return /* NOI18N */"EVENT";
	case MESSAGE:
            return /* NOI18N */"MESSAGE";
	default:
            return null;
        }
    }
    
    private int stringToConstant(String s) {
        if (s.equals(/* NOI18N */"EVENT"))
            return EVENT;
        else if (s.equals(/* NOI18N */"MESSAGE"))
            return MESSAGE;
        else
            return -1;
    }
    
    public void convertToString(Object obj, StringBuffer buf) {
        OpFilter f = (OpFilter)obj;
        
        // Open brace
        buf.append(/* NOI18N */"{");
        newline(buf);
        incrIndent();
        
        // Filter type
        indent(buf);
        buf.append(/* NOI18N */"filterType ");
        buf.append(constantToString(f.filterType));
        newline(buf);
        
        // Don't save the target.  The target is determined during code
        // generation by figuring out which shadow has the operation
        // as its attribute.
        //
        // if (f.targetRef != null) {
        //   indent(buf);
        //   buf.append("target ");
        //   buf.append(f.targetRef.getName());
        //   newline(buf);
        // }
        
        // Message filters
        if (f.name != null) {
            indent(buf);
            buf.append(/* NOI18N */"name ");
            ListParser.quote(f.name, buf, false);
            newline(buf);
        }
        if (f.type != null) {
            indent(buf);
            buf.append(/* NOI18N */"type ");
            ListParser.quote(f.type, buf, false);
            newline(buf);
        }
        if (f.targetName != null) {
            indent(buf);
            buf.append(/* NOI18N */"targetName ");
            ListParser.quote(f.targetName, buf, false);
            newline(buf);
        }
        
        // Event filters
        indent(buf);
        buf.append(/* NOI18N */"id ");
        buf.append(f.id);
        newline(buf);
        
        if (f.key != -1) {
            indent(buf);
            buf.append(/* NOI18N */"key ");
            buf.append(f.key);
            newline(buf);
        }
        
        if (f.modifiers != -1) {
            indent(buf);
            buf.append(/* NOI18N */"modifiers ");
            buf.append(f.modifiers);
            newline(buf);
        }
        
        if (f.clickCount != 0) {
            indent(buf);
            buf.append(/* NOI18N */"clickCount ");
            buf.append(f.clickCount);
            newline(buf);
        }
        
        // Close brace
        decrIndent();
        indent(buf);
        buf.append(/* NOI18N */"}");
    }
    
    public Object convertFromString(String s) {
        OpFilter filter = new OpFilter();
        convertFromString(s, filter);
        return filter;
    }
    
    public void convertFromString(String s, OpFilter f) {
        Hashtable table = ListParser.makeListTable(s);
        String val;
        
        //
        // Filter type
        //
        val = (String)table.get(/* NOI18N */"filterType");
        if (val == null) {
            throw new ParseException(/* NOI18N */
				     "filterType not found: " + s);
        }
        f.filterType = stringToConstant(val);
        
        //
        // Message or event target to match against.
        // Left in for compatibility reasons.
        //
        val = (String)table.get(/* NOI18N */"target");
        if (val != null)
            f.targetRef = new AMRef(val);
        
        //
        // Message filters
        //
        f.name = (String)table.get(/* NOI18N */"name");
        f.type = (String)table.get(/* NOI18N */"type");
        f.targetName = (String)table.get(/* NOI18N */"targetName");
        
        //
        // Event filters
        //
        val = (String)table.get(/* NOI18N */"id");
        if (val != null)
            f.id = ListParser.parseInt(val);
        
        val = (String)table.get(/* NOI18N */"key");
        if (val != null)
            f.key = ListParser.parseInt(val);
        
        val = (String)table.get(/* NOI18N */"modifiers");
        if (val != null)
            f.modifiers = ListParser.parseInt(val);
        
        val = (String)table.get(/* NOI18N */"clickCount");
        if (val != null)
            f.clickCount = ListParser.parseInt(val);
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
