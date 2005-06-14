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
 * @(#) MainHelper.java 1.29 - last change made 07/25/97
 */

package sunsoft.jws.visual.rt.base;

import sunsoft.jws.visual.rt.awt.RootFrame;
import sunsoft.jws.visual.rt.awt.GBLayout;
import sunsoft.jws.visual.rt.awt.GBConstraints;
import sunsoft.jws.visual.rt.shadow.java.awt.PanelShadow;
import sunsoft.jws.visual.rt.shadow.java.awt.DialogShadow;
import sunsoft.jws.visual.rt.shadow.java.awt.FrameShadow;
import sunsoft.jws.visual.rt.shadow.java.awt.WindowShadow;

import java.awt.*;
import java.util.Date;
import java.applet.Applet;

/**
 * Helper class for the generated main class.
 *
 * @version 1.29, 07/25/97
 */
public class MainHelper {
    /**
     * The base group
     */
    private Group baseGroup;
    
    /**
     * Name of an external call-out class if there is one.
     */
    private String ecoClassName;
    
    /**
     * Pointer to an external call-out class if there is one.
     */
    private ExternalCallOut eco;
    
    
    /**
     * Checks the version of the runtime.
     */
    public void checkVersion(double version) {
        if (Global.getVersion() < version) {
            Double d1 = new Double(version);
            Double d2 = new Double(Global.getVersion());
            System.out.println(Global.fmtMsg(
		    "sunsoft.jws.visual.rt.base.MainHelper.NeedRuntimeVersion",
		    d1, d2));
        }
    }
    
    /**
     * Accepts the command line arguments.
     * Sets an external class callout
     * name if there is one.  Registers the remaining
     * command line arguments
     * with the Global class.
     */
    private String[] parseCmdLineArgs(String args[]) {
        String registerArgs[] = args;
        // args that will be registered
        
        if (args.length >= 2) {
            for (int i = 0; i < args.length - 1; i++) {
                if (args[i].equals(/* NOI18N */"-external")) {
                    // set the class name for use in external callout later
                    ecoClassName = args[i + 1];
                    
                    // create a new argument list from the remaining
                    // cmd line args
                    registerArgs = new String[args.length - 2];
                    int count = 0;
                    for (int j = 0; j < args.length; j++) {
                        if (j < i || j > i + 1) {
                            registerArgs[count] = args[j];
                            count++;
                        }
                    }
                    break;
                }
            }
        }
        
        return registerArgs;
    }
    
    /**
     * Called when application is run from the command line.
     */
    public void main(Group group, String args[]) {
        // Set the base group
        baseGroup = group;
        
        RootFrame frame = null;
        
        // Set the environment information. This must be done before
        // initialization.
        args = parseCmdLineArgs(args);
        baseGroup.setEnvironmentInfo(null, args);
        
        // Initialize the group
        baseGroup.initialize();
        
        WindowShadow win = baseGroup.getWindow();
        
        // The top level frame must be set before the group
        // is created.
        if (win instanceof FrameShadow) {
            win.createBody();
            baseGroup.setTopLevel((Frame)win.getBody());
        } else if (win instanceof DialogShadow) {
            // Create a frame for the dialog
            // if there are no other frames
            String title = win.getName();
            if (title == null || title.equals(/* NOI18N */""))
                title = /* NOI18N */"Unnamed";
            
            RootFrame f = new RootFrame(title);
            f.setSubGroup(baseGroup);
            
            // SGI and Windows have bad defaults for
            // font and background
            if (Global.isIrix()) {
                f.setFont(new Font(/* NOI18N */"Sansserif",
				   Font.PLAIN, 12));
            }
            if (Global.isWindows()) {
                f.setBackground(Color.lightGray);
                f.setFont(new Font(/* NOI18N */"Dialog",
				   Font.PLAIN, 12));
            }
            
            baseGroup.setTopLevel(f);
            
            f.resize(25, 25);
            f.show();
            f.reshape(20, 20, 120, 80);
            f.validate();
        } else if (baseGroup.getPanel() != null) {
            // Put a frame around the group's panel
            // if it is a panel group
            String title = group.getPanel().getName();
            if (title == null || title.equals(/* NOI18N */""))
                title = /* NOI18N */"Unnamed";
            
            frame = new RootFrame(title);
            frame.setSubGroup(baseGroup);
            
            // SGI and Windows have bad defaults for
            // font and background
            if (Global.isIrix()) {
                frame.setFont(new Font(/* NOI18N */"Sansserif",
				       Font.PLAIN, 12));
            }
            if (Global.isWindows()) {
                frame.setBackground(Color.lightGray);
                frame.setFont(new Font(/* NOI18N */"Dialog",
				       Font.PLAIN, 12));
            }
            
            baseGroup.setTopLevel(frame);
        } else {
            throw new Error(Global.fmtMsg(
	        "sunsoft.jws.visual.rt.base.MainHelper.BaseGroupMustBeNonVis",
	        group));
        }
        
        // Create the group
        baseGroup.create();
        
        // This part needs to happen after the group is created
        if (frame != null) {
            frame.add(/* NOI18N */"Center",
		      (Panel)baseGroup.getPanel().getBody());
            // Window managers get confused when a window is shown with
            // zero width and height
            frame.resize(25, 25);
            frame.show();
            Dimension d = frame.preferredSize();
            frame.reshape(20, 20, d.width, d.height);
            frame.validate();
        }
        
        // Start the group
        baseGroup.start();
        
        if (ecoClassName != null) {
            initExternalCallOut(ecoClassName, baseGroup);
            startExternalCallOut();
            stopExternalCallOut();
        }
    }
    
    /**
     * Called when the applet is loaded.
     */
    public void init(Applet applet, Group group) {
        // Set the base group
        baseGroup = group;
        
        // Set the environment information. This must be done before
        // initialization.
        baseGroup.setEnvironmentInfo(applet, null);
        
        // Initialize the group
        baseGroup.initialize();
        
        WindowShadow win = baseGroup.getWindow();
        
        // The top level frame must be set before the
        // group is created.
        if (win instanceof FrameShadow) {
            win.createBody();
            baseGroup.setTopLevel((Frame)win.getBody());
        } else {
            // Figure out the applet's frame
            Component comp = applet;
            while (comp != null && !(comp instanceof Frame))
                comp = comp.getParent();
            
            baseGroup.setTopLevel((Frame)comp);
        }
        
        // Create the group
        baseGroup.create();
        
        // Adjust the font of the panel
        if (Global.isIrix())
            applet.setFont(new Font(/* NOI18N */"Sansserif",
				    Font.PLAIN, 12));
        else if (Global.isWindows())
            applet.setFont(new Font(/* NOI18N */"Dialog",
				    Font.PLAIN, 12));
        
        // Set up the layout for the Applet panel
        GBLayout gridbag = new GBLayout();
        applet.setLayout(gridbag);
        GBConstraints c = new GBConstraints();
        c.fill = GBConstraints.BOTH;
        c.weightx = 1;
        c.weighty = 1;
        
        // Add the group panel to the applet
        PanelShadow panelshadow = baseGroup.getPanel();
        if (panelshadow != null) {
            Panel panel = (Panel)panelshadow.getBody();
            gridbag.setConstraints(applet.add(panel), c);
        }
        
        // Check for and initialize an external call-out class
        ecoClassName = applet.getParameter(/* NOI18N */"external");
        if (ecoClassName != null)
            initExternalCallOut(ecoClassName, baseGroup);
    }
    
    /**
     * Called whenever the applet's page is visited.
     */
    public void start() {
        if (baseGroup != null)
            baseGroup.start();
        startExternalCallOut();
    }
    
    /**
     * Called by the browser when the user leaves the page.
     */
    public void stop() {
        if (baseGroup != null)
            baseGroup.stop();
        stopExternalCallOut();
    }
    
    /**
     * Called by the browser when the applet should be destroyed.
     */
    public void destroy() {
        if (baseGroup != null)
            baseGroup.destroy();
    }
    
    /**
     * Initializes a call-out to an external class. 
     * Gives the external
     * class a reference to this main's Group object.
     */
    private void initExternalCallOut(String name, Group group) {
        try {
            Class c = Global.util.getClassLoader().loadClass(name);
            eco = (ExternalCallOut) c.newInstance();
        }
        catch (ClassNotFoundException e) {
            throw new Error(Global.fmtMsg(
		    "sunsoft.jws.visual.rt.base.MainHelper.ClassNotFound",
		    name));
        }
        catch (InstantiationException e) {
            throw new Error(Global.fmtMsg(
	    "sunsoft.jws.visual.rt.base.MainHelper.InstantiationException",
	    name));
        }
        catch (IllegalAccessException e) {
            throw new Error(Global.fmtMsg(
		    "sunsoft.jws.visual.rt.base.MainHelper.illegalAccess",
		    name));
        }
        if (eco != null)
            eco.initExternal(group);
    }
    
    /**
     * Starts the external call-out class, if there is one.
     */
    private void startExternalCallOut() {
        if (eco != null)
            eco.startExternal();
    }
    
    /**
     * Stops the external call-out class, if there is one.
     */
    private void stopExternalCallOut() {
        if (eco != null)
            eco.stopExternal();
    }
}
