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
 * @(#) Operations.java 1.2 - last change made 07/18/96
 */

package sunsoft.jws.visual.rt.base;

import java.awt.Event;

public abstract class Operations {
    
    /**
     * Set the group class.
     */
    public abstract void setGroup(Group group);
    
    /**
     * Set the root from the group class.
     * This is called as soon as the root
     * becomes available.
     */
    public abstract void setRoot(Root root);
    
    //
    // Events
    //
    
    public boolean handleMessage(Message msg) {
        if (msg.isAWT)
            return handleEvent(msg, (Event)msg.arg);
        else
            return false;
    }
    
    public boolean handleEvent(Message msg, Event evt) {
        switch (evt.id) {
	case Event.MOUSE_ENTER:
            return mouseEnter(msg, evt, evt.x, evt.y);
	case Event.MOUSE_EXIT:
            return mouseExit(msg, evt, evt.x, evt.y);
	case Event.MOUSE_MOVE:
            return mouseMove(msg, evt, evt.x, evt.y);
	case Event.MOUSE_DOWN:
            return mouseDown(msg, evt, evt.x, evt.y);
	case Event.MOUSE_DRAG:
            return mouseDrag(msg, evt, evt.x, evt.y);
	case Event.MOUSE_UP:
            return mouseUp(msg, evt, evt.x, evt.y);
            
	case Event.KEY_PRESS:
	case Event.KEY_ACTION:
            return keyDown(msg, evt, evt.key);
	case Event.KEY_RELEASE:
	case Event.KEY_ACTION_RELEASE:
            return keyUp(msg, evt, evt.key);
            
	case Event.ACTION_EVENT:
            return action(msg, evt, evt.arg);
	case Event.GOT_FOCUS:
            return gotFocus(msg, evt, evt.arg);
	case Event.LOST_FOCUS:
            return lostFocus(msg, evt, evt.arg);
            
	default:
            return false;
        }
    }
    
    public boolean mouseDown(Message msg, Event evt, int x, int y) {
        return false;
    }
    
    public boolean mouseDrag(Message msg, Event evt, int x, int y) {
        return false;
    }
    
    public boolean mouseUp(Message msg, Event evt, int x, int y) {
        return false;
    }
    
    public boolean mouseMove(Message msg, Event evt, int x, int y) {
        return false;
    }
    
    public boolean mouseEnter(Message msg,
			      Event evt, int x, int y) {
        return false;
    }
    
    public boolean mouseExit(Message msg, Event evt, int x, int y) {
        return false;
    }
    
    public boolean keyDown(Message msg, Event evt, int key) {
        return false;
    }
    
    public boolean keyUp(Message msg, Event evt, int key) {
        return false;
    }
    
    public boolean action(Message msg, Event evt, Object what) {
        return false;
    }
    
    public boolean gotFocus(Message msg, Event evt, Object what) {
        return false;
    }
    
    public boolean lostFocus(Message msg, Event evt, Object what) {
        return false;
    }
}
