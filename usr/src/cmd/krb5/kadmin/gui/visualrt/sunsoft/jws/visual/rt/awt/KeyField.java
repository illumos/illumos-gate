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
 * @(#) KeyField.java 1.6 - last change made 05/02/97
 */

package sunsoft.jws.visual.rt.awt;

import sunsoft.jws.visual.rt.base.Global;
import java.awt.*;

public class KeyField extends Canvas {
    // commented out -kp use Event constants...
    //  public static final int ESC = 27;
    //  public static final int DELETE = 127;
    
    
    
    
    private static int ipadx = 20;
    private static int ipady = 14;
    
    private int key;
    private FontMetrics fontMetrics;
    private boolean hasFocus;
    
    public void addNotify() {
        super.addNotify();
        fontMetrics = getFontMetrics(getFont());
    }
    
    public void removeNotify() {
        super.removeNotify();
        fontMetrics = null;
    }
    
    public Dimension minimumSize() {
        Dimension d = new Dimension(0, 0);
        
        if (fontMetrics != null) {
            d.width = fontMetrics.stringWidth(/* NOI18N */
					      "Carriage Return") + ipadx;
            d.height = fontMetrics.getMaxAscent() + ipady;
        }
        
        return d;
    }
    
    public Dimension preferredSize() {
        return minimumSize();
    }
    
    public void setKey(int key) {
        this.key = key;
        repaint();
    }
    
    public int getKey() {
        return key;
    }
    
    private String getKeyString() {
        String str;
        
        switch (key) {
	case 0:
            str = /* NOI18N */"null";
            break;
	case /* NOI18N */ '\n':
            str = /* NOI18N */"Line Feed";
            break;
	case /* NOI18N */ '\t':
            str = /* NOI18N */"Tab";
            break;
	case /* NOI18N */ '\f':
            str = /* NOI18N */"Form Feed";
            break;
	case /* NOI18N */ '\r':
            str = /* NOI18N */"Carriage Return";
            break;
            //    case /* NOI18N */ '\b':
	case Event.BACK_SPACE:
            str = /* NOI18N */"Back Space";
            break;
	case /* NOI18N */ ' ':
            str = /* NOI18N */"Space";
            break;
            
            //    case ESC:
	case Event.ESCAPE:
            str = /* NOI18N */"Esc";
            break;
            //    case DELETE:
	case Event.DELETE:
            str = /* NOI18N */"Delete";
            break;
            /* added -kp */
	case Event.INSERT:
            str = /* NOI18N */"Insert";
            break;
	case Event.CAPS_LOCK:
            str = /* NOI18N */"Caps Lock";
            break;
	case Event.NUM_LOCK:
            str = /* NOI18N */"Num Lock";
            break;
	case Event.PAUSE:
            str = /* NOI18N */"Pause";
            break;
	case Event.PRINT_SCREEN:
            str = /* NOI18N */"Print Screen";
            break;
	case Event.SCROLL_LOCK:
            str = /* NOI18N */"Scroll Lock";
            break;
            /* end added -kp */
	case Event.HOME:
            str = /* NOI18N */"Home";
            break;
	case Event.END:
            str = /* NOI18N */"End";
            break;
	case Event.PGUP:
            str = /* NOI18N */"Page Up";
            break;
	case Event.PGDN:
            str = /* NOI18N */"Page Down";
            break;
	case Event.UP:
            str = /* NOI18N */"Up";
            break;
	case Event.DOWN:
            str = /* NOI18N */"Down";
            break;
	case Event.LEFT:
            str = /* NOI18N */"Left";
            break;
	case Event.RIGHT:
            str = /* NOI18N */"Right";
            break;
	case Event.F1:
            str = /* NOI18N */"F1";
            break;
	case Event.F2:
            str = /* NOI18N */"F2";
            break;
	case Event.F3:
            str = /* NOI18N */"F3";
            break;
	case Event.F4:
            str = /* NOI18N */"F4";
            break;
	case Event.F5:
            str = /* NOI18N */"F5";
            break;
	case Event.F6:
            str = /* NOI18N */"F6";
            break;
	case Event.F7:
            str = /* NOI18N */"F7";
            break;
	case Event.F8:
            str = /* NOI18N */"F8";
            break;
	case Event.F9:
            str = /* NOI18N */"F9";
            break;
	case Event.F10:
            str = /* NOI18N */"F10";
            break;
	case Event.F11:
            str = /* NOI18N */"F11";
            break;
	case Event.F12:
            str = /* NOI18N */"F12";
            break;
            
	default:
            if (key >= 32)
                str = String.valueOf((char)key);
            else
                str = /* NOI18N */"^" + String.valueOf((char)
					       (key+ /* NOI18N */ 'A'-1));
            
            break;
        }
        
        return str;
    }
    
    public void paint(Graphics g) {
        if (Global.isWindows())
            g = getGraphics();
        Dimension size = size();
        
        String str = getKeyString();
        int x = (size.width - fontMetrics.stringWidth(str)) / 2;
        int y = (size.height + fontMetrics.getMaxAscent()) / 2 - 1;
        if (isEnabled())
            g.setColor(getForeground());
        else
            g.setColor(getBackground().darker());
        g.setFont(getFont());
        g.drawString(str, x, y);
        
        g.setColor(getBackground());
        g.draw3DRect(1, 1, size.width-3, size.height-3, false);
        g.draw3DRect(2, 2, size.width-5, size.height-5, false);
        
        if (hasFocus) {
            g.setColor(getForeground());
            g.drawRect(0, 0, size.width-1, size.height-1);
        }
    }
    
    public boolean handleEvent(Event e) {
        
        if (e.id == Event.GOT_FOCUS) {
            if (!hasFocus) {
                hasFocus = true;
                repaint();
            }
        } else if (e.id == Event.LOST_FOCUS) {
            if (hasFocus) {
                hasFocus = false;
                repaint();
            }
        } else {
            return super.handleEvent(e);
        }
        
        return false;
    }
    
    public boolean mouseDown(Event e, int x, int y) {
        if (!hasFocus)
            requestFocus();
        return false;
    }
    
    public boolean keyDown(Event e, int key) {
        setKey(key);
        return false;
    }
}
