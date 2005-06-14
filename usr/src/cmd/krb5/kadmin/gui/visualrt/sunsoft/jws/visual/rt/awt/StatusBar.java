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
 * @(#) StatusBar.java 1.15 - last change made 07/25/97
 */

package sunsoft.jws.visual.rt.awt;

import sunsoft.jws.visual.rt.base.Global;
import sunsoft.jws.visual.rt.base.Util;
import java.awt.*;

/**
 * A label that shows a single line of text for while.  After a set
 * time period the text is blanked.  It's useful for a status bar at
 * the bottom of a frame.
 *
 * @version 1.15, 07/25/97
 */
public class StatusBar extends Canvas implements Runnable {
    private String text;
    private long wakeupTime;
    private long timeout;
    
    public StatusBar(String text) {
        wakeupTime = 0;
        timeout = 7000;
        setFont(new Font(/* NOI18N */"Sansserif", Font.BOLD, 14));
        
        Thread thread = new Thread(this);
        thread.setDaemon(true);
        thread.start();
    }
    
    public StatusBar() {
        this(/* NOI18N */"");
    }
    
    public synchronized void setTimeout(long millis) {
        timeout = millis;
        resetTimer(true);
    }
    
    public void setText(String text) {
        setText(text, true);
    }
    
    public void setText(String text, boolean shouldTimeout) {
        if (text != this.text && (this.text == null ||
				  !this.text.equals(text))) {
            this.text = text;
            repaint();
        }
        
        resetTimer(shouldTimeout);
    }
    
    public String getText() {
        return text;
    }
    
    public void paint(Graphics g) {
        if (Global.isWindows())
            g = getGraphics();
        Dimension d = size();
        
        g.setColor(getBackground());
        if (Global.isWindows())
            g.fillRect(0, 0, d.width, d.height);
        Global.util.draw3DRect(g, 0, 0, d.width-1, d.height-1,
			       Util.WIN95_SUNKEN, 1);
        
        if (text != null) {
            g.setColor(getForeground());
            g.setFont(getFont());
            FontMetrics fm = g.getFontMetrics();
            g.drawString(text, 5, fm.getAscent() + 3);
        }
    }
    
    public Dimension minimumSize() {
        Graphics g = getGraphics();
        int w = 10;
        int h = 6;
        
        if (g != null) {
            FontMetrics fm = g.getFontMetrics();
            if (text != null)
                w += fm.stringWidth(text);
            h += fm.getHeight();
        }
        
        return new Dimension(w, h);
    }
    
    public Dimension preferredSize() {
        return minimumSize();
    }
    
    public synchronized void run() {
        long currentTime = System.currentTimeMillis();
        
        while (true) {
            try {
                if (wakeupTime == 0)
                    wait();
                else
                    wait(wakeupTime - currentTime);
            }
            catch (java.lang.InterruptedException ex) {
            }
            
            currentTime = System.currentTimeMillis();
            if (wakeupTime != 0 && wakeupTime < currentTime) {
                text = null;
                repaint();
                wakeupTime = 0;
            }
        }
    }
    
    private synchronized void resetTimer(boolean shouldTimeout) {
        if (timeout > 0 && shouldTimeout && text != null &&
	    !text.equals(/* NOI18N */"")) {
            wakeupTime = System.currentTimeMillis() + timeout;
            notify();
        } else {
            wakeupTime = 0;
        }
    }
}
