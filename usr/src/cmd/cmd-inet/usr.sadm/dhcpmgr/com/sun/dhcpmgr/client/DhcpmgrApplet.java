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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
package com.sun.dhcpmgr.client;

import java.awt.*;
import java.awt.event.*;
import java.util.*;
import java.net.*;
import java.rmi.RemoteException;
import java.rmi.NotBoundException;
import javax.swing.*;
import java.text.MessageFormat;
import java.applet.AppletContext;

import com.sun.dhcpmgr.ui.*;
import com.sun.dhcpmgr.data.*;
import com.sun.dhcpmgr.server.DhcpMgr;
import com.sun.dhcpmgr.server.DhcpServiceMgr;
import com.sun.dhcpmgr.bridge.BridgeException;
import com.sun.dhcpmgr.bridge.NotRunningException;

/**
 * Main class for DHCP Manager.  It is theoretically possible to run this
 * application as a command managing the local system, a command managing a
 * remote system using RMI, or as an applet managing the system from which it
 * was downloaded.  We presently only support the first option, but there is
 * vestigial code here from when the other options were supported as they may
 * be again.  That's why we extend JApplet.
 */
public class DhcpmgrApplet extends JApplet {
    private static MainFrame frame = null;
    private JButton button;
    public static boolean modeIsRelay;
    private static HelpIds helpIds = null;
    private static URL docBase = null;
    private static AppletContext appletContext = null;
    private AddressView addressView;
    private RestartAction restartAction;
    private StopAction stopAction;
    private StartAction startAction;
    private DisableAction disableAction;
    private EnableAction enableAction;
    
    // Handler for Help->Overview menu item
    class OverviewAction extends MnemonicAction {
	public OverviewAction() {
	    super(ResourceStrings.getString("overview_item"));
	}
	
	public void actionPerformed(ActionEvent e) {
	    showHelp("overview");
	}
    }
    
    // Handler for Help->How To menu item
    class HowToAction extends MnemonicAction {
	public HowToAction() {
	    super(ResourceStrings.getString("howto_item"));
	}
	
	public void actionPerformed(ActionEvent e) {
	    showHelp("howto");
	}
    }
    
    // Handler for Help->Index menu item
    class IndexAction extends MnemonicAction {
	public IndexAction() {
	    super(ResourceStrings.getString("index_item"));
	}
	
	public void actionPerformed(ActionEvent e) {
	    showHelp("index");
	}
    }
    
    // Handler for Help->On Service menu item
    class ServiceAction extends MnemonicAction {
	public ServiceAction() {
	    super(ResourceStrings.getString("on_service_item"));
	}
	
	public void actionPerformed(ActionEvent e) {
	    showHelp("service_reference");
	}
    }
    
    // Handler for the Service->Restart menu item
    class RestartAction extends MnemonicAction {
	public RestartAction() {
	    super(ResourceStrings.getString("restart_item"));
	}
	
	public void actionPerformed(ActionEvent e) {
	    try {
		DataManager.get().getDhcpServiceMgr().reload();
		frame.setStatusText(
		    ResourceStrings.getString("service_restarted"));
	    } catch (NotRunningException ex) {
		// Server not running, ignore the error and just start it
		startAction.actionPerformed(e);
	    } catch (Throwable t) {
		Object [] args = new Object[1];
		MessageFormat form = new MessageFormat(
		    ResourceStrings.getString("restart_server_error"));
		args[0] = t.getMessage();
		JOptionPane.showMessageDialog(frame, form.format(args),
		    ResourceStrings.getString("server_error_title"),
		    JOptionPane.ERROR_MESSAGE);
	    }
	}
    }
    
    // Handler for the Service->Stop menu item
    class StopAction extends MnemonicAction {
	public StopAction() {
	    super(ResourceStrings.getString("stop_item"));
	}
	
	public void actionPerformed(ActionEvent e) {
	    try {
		DataManager.get().getDhcpServiceMgr().shutdown();
		frame.setStatusText(
		    ResourceStrings.getString("service_stopped"));
		startAction.setEnabled(true);
		restartAction.setEnabled(false);
		setEnabled(false);
	    } catch (Throwable t) {
		Object [] args = new Object[1];
		MessageFormat form = new MessageFormat(
		    ResourceStrings.getString("shutdown_server_error"));
		args[0] = t.getMessage();
		JOptionPane.showMessageDialog(frame, form.format(args),
		    ResourceStrings.getString("server_error_title"),
		    JOptionPane.ERROR_MESSAGE);
	    }
	}
    }
    
    // Handler for the Service->Restart menu item
    class StartAction extends MnemonicAction {
	public StartAction() {
	    super(ResourceStrings.getString("start_item"));
	}
	
	public void actionPerformed(ActionEvent e) {
	    try {
		DataManager.get().getDhcpServiceMgr().startup();
		frame.setStatusText(
		    ResourceStrings.getString("service_started"));
		stopAction.setEnabled(true);
		restartAction.setEnabled(true);
		setEnabled(false);
	    } catch (Throwable t) {
		Object [] args = new Object[1];
		MessageFormat form = new MessageFormat(
		    ResourceStrings.getString("startup_server_error"));
		args[0] = t.getMessage();
		JOptionPane.showMessageDialog(frame, form.format(args),
		    ResourceStrings.getString("server_error_title"),
		    JOptionPane.ERROR_MESSAGE);
	    }
	}
    }
    
    // handler for the Service->Disable service menu item
    class DisableAction extends MnemonicAction {
	public DisableAction() {
	    super(ResourceStrings.getString("disable_item"));
	}
	
	public void actionPerformed(ActionEvent e) {
	    DisableServiceDialog d = new DisableServiceDialog(frame, true);
	    d.addActionListener(new ActionListener() {
		public void actionPerformed(ActionEvent e) {
		    // Update menu item state once we've disabled it
		    enableAction.setEnabled(true);
		    disableAction.setEnabled(false);
		    stopAction.setEnabled(false);
		    startAction.setEnabled(false);
		    restartAction.setEnabled(false);
		}
	    });
	    d.pack();
	    d.setVisible(true);
	}
    }
    
    // handler for the Service->Enable service menu item
    class EnableAction extends MnemonicAction {
	public EnableAction() {
	    super(ResourceStrings.getString("enable_item"));
	}
	
	public void actionPerformed(ActionEvent e) {
	    DisableServiceDialog d = new DisableServiceDialog(frame, false);
	    d.addActionListener(new ActionListener() {
		public void actionPerformed(ActionEvent e) {
		    // Update menu item state once we've enabled it
		    disableAction.setEnabled(true);
		    enableAction.setEnabled(false);
		    stopAction.setEnabled(true);
		    startAction.setEnabled(false);
		    restartAction.setEnabled(true);
		}
	    });
	    d.pack();
	    d.setVisible(true);
	}
    }
    
    // handler for the Service->Modify service menu item
    class ModifyServiceAction extends MnemonicAction {
	public ModifyServiceAction() {
	    super(ResourceStrings.getString("modify_service_item"));
	}
	
	public void actionPerformed(ActionEvent e) {
	    try {
		DhcpdOptions opts =
		    DataManager.get().getDhcpServiceMgr().readDefaults();
		ServerOptionsDialog d = new ServerOptionsDialog(frame, opts);
		d.pack();
		d.setVisible(true);
	    } catch (BridgeException ex) {
		// Error reading options
		MessageFormat form = new MessageFormat(
		    ResourceStrings.getString("err_reading_options"));
		Object [] args = new Object[] { ex.getMessage() };
		JOptionPane.showMessageDialog(frame, form.format(args),
		    ResourceStrings.getString("server_error_title"),
		    JOptionPane.ERROR_MESSAGE);
	    }
	}
    }
    
    // handler for the Service->Convert service menu item
    class ConvertAction extends MnemonicAction {
	public ConvertAction() {
	    super(ResourceStrings.getString("cvt_service_item"));

	}
	
	public void actionPerformed(ActionEvent e) {
	    ConvertWizard wiz = new ConvertWizard(frame,
		ResourceStrings.getString("cvt_wiz_title"));
	    wiz.addActionListener(new ActionListener() {
		public void actionPerformed(ActionEvent e) {
		    if (e.getActionCommand().equals("finished")) {
			frame.refreshAllViews();
			showFrame();
		    }
		}
	    });
	    wiz.pack();
	    wiz.setModal(true);
	    wiz.setVisible(true);
	}

	public void setEnabled(boolean b) {
	    if (!modeIsRelay) {
		super.setEnabled(b);
	    } else {
		super.setEnabled(false);
	    }
	}
    }

    // handler for the Service->Unconfigure service menu item
    class UnconfigureServiceAction extends MnemonicAction {
	public UnconfigureServiceAction() {
	    super(ResourceStrings.getString("unconfigure_service_item"));
	}
	
	public void actionPerformed(ActionEvent e) {
	    UnconfigureDialog d = new UnconfigureDialog(frame);
	    d.addActionListener(new ActionListener() {
		public void actionPerformed(ActionEvent e) {
		    if (e.getActionCommand().equals(DialogActions.OK)) {
			/*
			 * User unconfigured the service; there's nothing
			 * else to do so just get rid of the frame which
			 * will as a side effect shut us down.
			 */
			frame.setVisible(false);
			frame.dispose();
			frame = null;
		    }
		}
	    });	    
	    d.pack();
	    d.setVisible(true);
	}
    }

    // Action for Service->Export data
    class ExportAction extends MnemonicAction {
	public ExportAction() {
	    super(ResourceStrings.getString("export_item"));
	}
	public void actionPerformed(ActionEvent e) {
	    ExportWizard wiz = new ExportWizard(frame);
	    wiz.addActionListener(new ActionListener() {
		public void actionPerformed(ActionEvent e) {
		    if (e.getActionCommand().equals("finished")) {
			frame.refreshAllViews();
			showFrame();
		    }
		}
	    });
	    wiz.pack();
	    wiz.setVisible(true);
	}
    }

    // Action for Service->Import data
    class ImportAction extends MnemonicAction {
	public ImportAction() {
	    super(ResourceStrings.getString("import_item"));
	}

	public void actionPerformed(ActionEvent e) {
	    ImportWizard wiz = new ImportWizard(frame);
	    wiz.addActionListener(new ActionListener() {
		public void actionPerformed(ActionEvent e) {
		    if (e.getActionCommand().equals("finished")) {
			frame.refreshAllViews();
			showFrame();
		    }
		}
	    });
	    wiz.pack();
	    wiz.setVisible(true);
	}
    }

    /*
     * This class provides a transition dialog which allows the user
     * to initiate the address wizard immediately upon startup.  It's
     * done this way so that the startMeUp() method can use invokeLater()
     * to cause it to be displayed after the config wizard exit event
     * has been processed rather than during that event's processing;
     * otherwise the wizard doesn't disappear until after the user presses
     * Yes or No in this dialog.
     */
    class WizardTransition implements Runnable {
	public void run() {
	    // Now transition to configuring addresses
	    int status = JOptionPane.showConfirmDialog(frame,
		ResourceStrings.getString("start_address_wizard"),
		ResourceStrings.getString("start_address_wizard_title"),
		JOptionPane.YES_NO_OPTION);
	    if (status == JOptionPane.YES_OPTION) {
		addressView.startAddressWizard();
	    }
	}
    }

    /*
     * This class provides a transition dialog which allows the user
     * to initiate the conversion wizard immediately upon startup if a
     * version mismatch exists (a data store upgrade is necessary).
     */
    class ConversionTransition implements Runnable {
	public void run() {
	    try {
		DhcpServiceMgr svcMgr = DataManager.get().getDhcpServiceMgr();
		while (!svcMgr.isVersionCurrent()) {
		    int status = JOptionPane.showConfirmDialog(frame,
			ResourceStrings.getString("start_cvt_wizard"),
			ResourceStrings.getString("start_cvt_wizard_title"),
			JOptionPane.YES_NO_OPTION);
		    if (status == JOptionPane.YES_OPTION) {
			ConvertAction converter = new ConvertAction();
			ActionEvent e = new ActionEvent(this,
			    ActionEvent.ACTION_PERFORMED, "");
			converter.actionPerformed(e);
		    } else {
			frame = null;
			DataManager.get().reset();
			requestExit();
		    }
		}
	    } catch (Throwable e) {
		System.err.println(
		    ResourceStrings.getString("err_initializing_program"));
		System.err.println(e.getMessage());
		requestExit();
	    }
	}
    }

    // Create the frame within which the UI will live
    private void createFrame() {
	if (frame == null) {
	
	    frame = new MainFrame(ResourceStrings.getString("dhcp_manager"));
	    
	    // Create the views for this tool
	    if (modeIsRelay) {
		frame.addView(new RelayView(), true);
	    } else {
		addressView = new AddressView();
		frame.addView(addressView, true);
		frame.addView(new MacroView(), false);
		frame.addView(new OptionView(), false);
	    }
	    
	    // Set up the services menu
	    frame.addMenuAction(MainFrame.ACTIONS_MENU,
		(restartAction = new RestartAction()));
	    frame.addMenuAction(MainFrame.ACTIONS_MENU,
		(stopAction = new StopAction()));
	    frame.addMenuAction(MainFrame.ACTIONS_MENU,
		(startAction = new StartAction()));
	    frame.addMenuAction(MainFrame.ACTIONS_MENU,
		(disableAction = new DisableAction()));
	    frame.addMenuAction(MainFrame.ACTIONS_MENU,
		(enableAction = new EnableAction()));
	    frame.addMenuAction(MainFrame.ACTIONS_MENU,
		new ModifyServiceAction());
	    if (!modeIsRelay) {
		frame.addMenuAction(MainFrame.ACTIONS_MENU,
		    new ExportAction());
		frame.addMenuAction(MainFrame.ACTIONS_MENU,
		    new ImportAction());
		frame.addMenuAction(MainFrame.ACTIONS_MENU,
    		    new ConvertAction());
	    }
	    frame.addMenuAction(MainFrame.ACTIONS_MENU,
		new UnconfigureServiceAction());
	    
	    // Set up the Help menu
	    frame.addMenuAction(MainFrame.HELP_MENU, new OverviewAction());
	    frame.addMenuAction(MainFrame.HELP_MENU, new HowToAction());
	    frame.addMenuAction(MainFrame.HELP_MENU, new IndexAction());
	    frame.addMenuAction(MainFrame.HELP_MENU, new ServiceAction());
	    
	    // In relay mode, let it size itself (quite small)
	    if (modeIsRelay) {
		frame.pack();
	    } else {
		/*
		 * Normal mode set it to a reasonable size.  This ought to be
		 * a user preference, but until we run as something other than
		 * root it's not really a useful idea.
		 */
		frame.setSize(800, 600);
	    }
	    
	    // Listen for closing events
	    frame.addWindowListener(new WindowAdapter() {
		public void windowClosing(WindowEvent e) {
		    /*
		     * This is here to work around the Close selection frame
		     * menu on Solaris not causing the closed function to be
		     * called
		     */
		    windowClosed(e);
		}
		public void windowClosed(WindowEvent e) {
		    // Dispose of all data and exit when window goes away.
		    frame = null;
		    DataManager.get().reset();
		    requestExit();
		}
	    });
	}
    }
    
    // Show the frame
    private void showFrame() {
	if (frame == null) {
	    createFrame();
	}
	frame.initialize();
	if (modeIsRelay) {
	    // Disable edit & view menus in the relay case
	    frame.setMenuEnabled(MainFrame.EDIT_MENU, false);
	    frame.setMenuEnabled(MainFrame.VIEW_MENU, false);
	}
	try {
	    // Set status of service menu options based on server state
	    DhcpdOptions opts =
		DataManager.get().getDhcpServiceMgr().readDefaults();
	    boolean enabled = opts.isDaemonEnabled();
	    enableAction.setEnabled(!enabled);
	    disableAction.setEnabled(enabled);
	    boolean running =
		DataManager.get().getDhcpServiceMgr().isServerRunning();
	    restartAction.setEnabled(running && enabled);
	    stopAction.setEnabled(running);
	    startAction.setEnabled(!running && enabled);
	} catch (Throwable e) {
	    // Enable all the menu items, as something went wrong
	    restartAction.setEnabled(true);
	    stopAction.setEnabled(true);
	    startAction.setEnabled(true);
	    enableAction.setEnabled(true);
	    disableAction.setEnabled(true);
	}    
	frame.setVisible(true);
    }
    
    /*
     * main startup code; checks whether server is already configured, and if
     * not runs through the config wizard sequence in order to get the server
     * configured.
     */
    private void startMeUp() {
	try {
	    if (DataManager.get().getServer() == null) {
		DataManager.get().setServer(getCodeBase().getHost());
	    }

	    // See if server is already configured, and start up
	    DhcpServiceMgr svcMgr = DataManager.get().getDhcpServiceMgr();
	    DhcpdOptions opts = svcMgr.readDefaults();
	    modeIsRelay = opts.isRelay();
	    // If server mode, ensure RESOURCE and PATH were set
	    if (!modeIsRelay) {
	    	if ((opts.getResource() == null) || (opts.getPath() == null)) {
		    System.err.println(
		        ResourceStrings.getString("err_initializing_options"));
	    	    requestExit();
		}
	    }
	    
	    showFrame();

	    // Check to make sure that the data store version is up to date.
	    // If not, inform the user and present them with the conversion
	    // wizard so that they can upgrade.
	    if (!modeIsRelay && !svcMgr.isVersionCurrent()) {
		SwingUtilities.invokeLater(new ConversionTransition());
	    }

	} catch (BridgeException e) {
	    // Let user select which type of service to configure
	    int choice = ConfigureChoiceDialog.showDialog(frame);
	    if (choice == ConfigureChoiceDialog.DHCP) {
		// DHCP; run the wizard
		ConfigWizard wiz = new ConfigWizard(frame,
		    ResourceStrings.getString("cfg_wiz_title"), true);
		wiz.addActionListener(new ActionListener() {
		    public void actionPerformed(ActionEvent e) {
			if (e.getActionCommand().equals("finished")) {
			    // Service config completed, start up
			    modeIsRelay = false;
			    showFrame();
			    // Now transition to configuring addresses
			    SwingUtilities.invokeLater(new WizardTransition());
			} else {
			    // User cancelled the wizard, exit
			    requestExit();
			}
		    }
		});
		wiz.pack();
		wiz.setVisible(true);
	    } else if (choice == ConfigureChoiceDialog.BOOTP) {
		// Wants to configure a relay, show the dialog for that
		ConfigureRelayDialog d = new ConfigureRelayDialog(frame);
		d.addActionListener(new ActionListener() {
		    public void actionPerformed(ActionEvent e) {
			if (e.getActionCommand().equals(DialogActions.OK)) {
			    // Relay configuration completed, start up
			    modeIsRelay = true;
			    showFrame();
			} else {
			    // User cancelled, exit
			    requestExit();
			}
		    }
		});
		d.pack();
		d.setVisible(true);
	    } else {
		// User cancelled; exit
		requestExit();
	    }
	} catch (Throwable e) {
	    // Couldn't really get started, dump the stack and exit
	    System.err.println(
	        ResourceStrings.getString("err_initializing_program"));
	    System.err.println(e.getMessage());
	    e.printStackTrace();
	    requestExit();
	}
    }

    // Show a help file referenced by tag
    public static void showHelp(String helpId) {
	// If help tag mapping table not loaded yet, then load it
	if (helpIds == null) {
	    try {
		helpIds = new HelpIds("com.sun.dhcpmgr.client.HelpBundle");
	    } catch (Throwable e) {
		// Error initializing help system
		JOptionPane.showMessageDialog(frame,
		    ResourceStrings.getString("err_initializing_help"),
		    ResourceStrings.getString("server_error_title"),
		    JOptionPane.ERROR_MESSAGE);
		return;
	    }
	}
	// Ask browser to display
	try {
	    Runtime.getRuntime().exec(
		    "/usr/sfw/bin/mozilla file:"
		    + helpIds.getFilePath(helpId));
	} catch (java.io.IOException e) {
	    JOptionPane.showMessageDialog(frame,
	    	ResourceStrings.getString("err_starting_help"),
		ResourceStrings.getString("server_error_title"),
		JOptionPane.ERROR_MESSAGE);
	}
    }
    
    // Exit the application
    private void requestExit() {
	System.exit(0);
    }
    
    // Main function when we're run as an application
    public static void main(String [] args) {

	// Ensure that we're running as root; exit if not
	if (!System.getProperty("user.name").equals("root")) {
	    System.err.println(ResourceStrings.getString("err_must_be_root"));
	    System.exit(0);
	}

	DhcpmgrApplet applet = new DhcpmgrApplet();
	applet.startMeUp();
    }
}
