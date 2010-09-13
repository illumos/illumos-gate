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
 * @(#) GBPanel.java 1.35 - last change made 06/17/97
 */

package sunsoft.jws.visual.rt.awt;

import sunsoft.jws.visual.rt.base.Global;

import sunsoft.jws.visual.rt.base.*;
import java.awt.*;

public class GBPanel extends VJPanel {
    
    private static Class gbclass;
    
    private boolean runtime = true;
    private GBContainer cntr;
    private GBLayout mgr;
    
    public GBPanel() {
        setLayout(new GBLayout());
    }
    
    public boolean handleEvent(Event evt) {
        if (cntr != null)
            return cntr.handleEvent(evt);
        else
            return super.handleEvent(evt);
    }
    
    public void setRuntime(boolean rt) {
        if (runtime == rt)
            return;
        
        runtime = rt;
        
        if (runtime) {
            cntr.setGBPanel(null);
            cntr = null;
        } else {
            if (gbclass == null)
                gbclass = DesignerAccess.getGBPanelClass();
            
            try {
                cntr = (GBContainer)gbclass.newInstance();
            }
            catch (IllegalAccessException ex) {
                throw new Error(ex.toString());
            }
            catch (InstantiationException ex) {
                throw new Error(ex.toString());
            }
            
            cntr.setGBPanel(this);
        }
    }
    
    public GBContainer getGBContainer() {
        return cntr;
    }
    
    //
    // Special hack for flow layout so that it
    // can re-adjust its vertical
    // size based on the horizontal space available.
    // This method is needed
    // to make the flow layout take up more space
    // vertically when it runs
    // short on horizontal space.
    //
    public void layout() {
        boolean hasFlow = false;
        int count = countComponents();
        GBLayout gridbag = (GBLayout)getLayout();
        Component comp;
        LayoutManager mgr;
        
        for (int i = 0; i < count; i++) {
            comp = getComponent(i);
            if (comp instanceof Container) {
                mgr = ((Container)comp).getLayout();
                if (mgr instanceof VJFlowLayout) {
                    hasFlow = true;
                    ((VJFlowLayout)mgr).setMinimumWidth(0);
                }
            }
        }
        
        if (hasFlow) {
            gridbag.layoutContainerNoReshape(this);
            
            for (int i = 0; i < count; i++) {
                comp = getComponent(i);
                if (comp instanceof Container) {
                    mgr = ((Container)comp).getLayout();
                    if (mgr instanceof VJFlowLayout) {
                        GBConstraints c = gridbag.getConstraints(comp);
                        if (c.size != null)
                            ((VJFlowLayout)mgr).setMinimumWidth(
								c.size.width);
                    }
                }
            }
        }
        
        super.layout();
        
        if (hasFlow) {
            for (int i = 0; i < count; i++) {
                comp = getComponent(i);
                if (comp instanceof Container) {
                    mgr = ((Container)comp).getLayout();
                    if (mgr instanceof VJFlowLayout) {
                        ((VJFlowLayout)mgr).setMinimumWidth(0);
                    }
                }
            }
        }
        
        if (cntr != null)
            cntr.layout();
    }
    
    //
    // Forwarding of container methods
    //
    
    public void setLayout(LayoutManager mgr) {
        if (cntr != null)
            cntr.setLayout(mgr);
        else
            super.setLayout(mgr);
        updateLayout();
    }
    
    public void setLayoutSuper(LayoutManager mgr) {
        super.setLayout(mgr);
        updateLayout();
    }
    
    private void updateLayout() {
        LayoutManager m = getLayout();
        if (m instanceof GBLayout)
            mgr = (GBLayout)m;
        else
            mgr = null;
    }
    
    // #ifdef JDK1.1
    protected void addImpl(Component comp, Object constraints,
			   int index) {
        super.addImpl(comp, constraints, index);
        doAdd(comp);
    }
    // #else
    // public Component add(Component comp, int pos) {
    //   super.add(comp, pos);
    //   doAdd(comp);
    //   return comp;
    // }
    // #endif
    
    
    private void doAdd(Component comp) {
        if (cntr != null)
            cntr.add(comp);
    }
    
    public void remove(Component comp) {
        super.remove(comp);
        if (cntr != null)
            cntr.remove(comp);
    }
    
    public void removeAll() {
        super.removeAll();
        if (cntr != null)
            cntr.removeAll();
    }
    
    public void update(Graphics g) {
        if (Global.isWindows())
            g = getGraphics();
        
        if (cntr != null)
            cntr.update(g);
        
        super.update(g);
    }
    
    public void paint(Graphics g) {
        if (Global.isWindows())
            g = getGraphics();
        
        if (cntr != null)
            cntr.paint(g);
        
        super.paint(g);
    }
    
    public void reshape(int x, int y, int w, int h) {
        super.reshape(x, y, w, h);
        if (cntr != null)
            cntr.reshape(x, y, w, h);
    }
    
    //
    // Layout and Preview modes
    //
    
    public void layoutMode() {
        if (cntr != null)
            cntr.layoutMode();
    }
    
    public void previewMode() {
        if (cntr != null)
            cntr.previewMode();
    }
    
    //
    // Constraints
    //
    
    public void setConstraints(Component comp, GBConstraints c) {
        if (c == null)
            /* JSTYLED */
	    throw new Error(Global.getMsg("sunsoft.jws.visual.rt.awt.GBPanel.null__constraints"));
        
        if (cntr != null)
            cntr.setConstraints(comp, c);
        else if (mgr != null)
            mgr.setConstraints(comp, c);
    }
    
    public GBConstraints getConstraints(Component comp) {
        if (cntr != null)
            return cntr.getConstraints(comp);
        else if (mgr != null)
            return mgr.getConstraints(comp);
        else
            return null;
    }
    
    //
    // GBLayout attributes
    //
    
    public void setColumnWeights(double w[]) {
        if (cntr != null)
            cntr.setColumnWeights(w);
        else if (mgr != null)
            mgr.columnWeights = w;
    }
    
    public void setRowWeights(double w[]) {
        if (cntr != null)
            cntr.setRowWeights(w);
        else if (mgr != null)
            mgr.rowWeights = w;
    }
    
    public double [] getColumnWeights() {
        if (cntr != null)
            return cntr.getColumnWeights();
        else if (mgr != null)
            return mgr.columnWeights;
        else
            return null;
    }
    
    public double [] getRowWeights() {
        if (cntr != null)
            return cntr.getRowWeights();
        else if (mgr != null)
            return mgr.rowWeights;
        else
            return null;
    }
    
    public void setColumnWidths(int w[]) {
        if (cntr != null)
            cntr.setColumnWidths(w);
        else if (mgr != null)
            mgr.columnWidths = w;
    }
    
    public void setRowHeights(int h[]) {
        if (cntr != null)
            cntr.setRowHeights(h);
        else if (mgr != null)
            mgr.rowHeights = h;
    }
    
    public int[] getColumnWidths() {
        if (cntr != null)
            return cntr.getColumnWidths();
        else if (mgr != null)
            return mgr.columnWidths;
        else
            return null;
    }
    
    public int[] getRowHeights() {
        if (cntr != null)
            return cntr.getRowHeights();
        else if (mgr != null)
            return mgr.rowHeights;
        else
            return null;
    }
}
