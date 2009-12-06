/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 *
 *
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * pmTop.java
 * Top level
 */

package com.sun.admin.pm.client;

import java.awt.*;
import java.awt.event.*;
import java.util.*;
import java.util.Vector;
import java.lang.*;
import javax.swing.JPanel;
import javax.swing.JTable;
import javax.swing.ListSelectionModel;
import javax.swing.event.ListSelectionListener;
import javax.swing.event.ListSelectionEvent;
import javax.swing.table.AbstractTableModel;
import javax.swing.text.*;
import javax.swing.border.*;
import javax.swing.*;

import com.sun.admin.pm.server.*;


/*
 * Top window for printer manager
 */

public class pmTop extends JPanel {

    static private pmTop myTop = null;
    static private pmHelpFrame helpFrame = null;
    static private pmAboutBox aboutBox = null;
    static private pmLogDisplay commandLog = null;
    static private pmFindFrame findFrame = null;

    JLabel nameserviceLabel = new JLabel();
    JLabel domainhostLabel;
    JLabel defaultpLabel;
    String defaultPrinter;
    JScrollPane scrollPane;
    JTable listTable;
    Host host = new Host();
    private JPanel north = new JPanel();
    JPanel center;
    listTableModel listModel;
    ListSelectionModel listSM;

    JMenuBar menuBar;
    JFrame parentFrame;
    JCheckBoxMenuItem logCheck;
    JCheckBoxMenuItem confirmCheck;
    JCheckBoxMenuItem usePPD;
    JCheckBoxMenuItem useLocalhost;
    JMenuItem modifyMenuItem = null;
    JMenuItem deleteMenuItem = null;

    JMenuItem access;
    JMenuItem local;
    JMenuItem network;

    int actionindex = 0;
    private String newNS;
    NameService ns = null;
    NameService nisns = null;
    NameService systemns = null;
    NameService ldapns = null;

    pmAccess accessView = null;
    pmInstallPrinter localinstallView = null;
    pmInstallPrinter networkinstallView = null;
    pmDelete deleteView = null;
    pmInstallPrinter modifyView = null;
    pmLoad loadView = null;

    String clickedPrinter;
    String selectedPrinter = null;
    String selprinterServer = null;
    int selectedRow = -1;

    String cmdLog = null;
    String errorLog = null;
    String warningLog = null;

    boolean runningAuth = false;
    boolean isRoot = false;

    pmFrame frame;


    public pmTop(JFrame parent) {
	parentFrame = parent;
	setLayout(new BorderLayout());
	pmTopInit();

    }

    public void pmTopInit() {

	try {
		systemns = new NameService("system");
	} catch (Exception e) {
		Debug.message("CLNT:  system:Nameservice exception " + e);
	}
	try {
		nisns = new NameService("nis");
	} catch (Exception e) {
		Debug.message("CLNT:  nis:Nameservice exception " + e);
	}
	try {
		ldapns = new NameService("ldap");
	} catch (Exception e) {
		Debug.message("CLNT:  ldap:Nameservice exception " + e);
	}

	ns = systemns;
	newNS = "files";

        // determine root privileges
        try {
            ns.checkAuth();
        } catch (Exception ax) {
            Debug.message("CLNT:  checkAuth threw " + ax);
        }

        if (ns.isAuth()) {
	    runningAuth = true;
	    isRoot = true;
            Debug.message("CLNT:  Running as root");
        } else
            Debug.message("CLNT:  Not running as root");

	northPanel();
	centerPanel();
	southPanel();

    }

    // Set values so that printer selection null
    public void clearSelected() {
	selectedPrinter = null;
	selprinterServer = null;
	selectedRow = -1;
    	enableEditMenuItems(false);
    }


    // Create north panel with GridBagLayout
    public void northPanel() {

	menuBar = new JMenuBar();
	menuBar.setBorder(new EmptyBorder(5, 5, 5, 5));
	menuBar.add(appMenu());
	menuBar.add(objectMenu());
	menuBar.add(toolsMenu());
	menuBar.add(Box.createHorizontalGlue());
	menuBar.add(helpMenu());

	parentFrame.setJMenuBar(menuBar);
    }

    public class listTableModel extends AbstractTableModel {
	int numColumns;

        String[] columnNames = {
            pmUtility.getResource("Printer.Name"),
            pmUtility.getResource("Printer.Server"),
            pmUtility.getResource("Description")

        };

	// Initialize for JTable calls from SWING classes
	Vector data = new Vector(0, 0);

        public listTableModel() {
            numColumns = getColumnCount();
        }

	public void insertlistTable(String rowDataList[], int numcols) {
		Vector rowData = new Vector(3, 1);
		data = new Vector(100, 5);
		int j = 0;

		if ((rowDataList.length) <= 1) {
			return;
		}

		for (int i = 0; i < rowDataList.length; i = i + 3) {
			rowData = new Vector(3, 1);
			for (j = 0; j < 3; j++) {
			    rowData.addElement(
				rowDataList[i + j]);
			}
			data.addElement(rowData);
		}
	}

	public void removeRow(int row) {
		data.removeElementAt(row);
	}

	public int getRowCount() {
		return data.size();
	}

	public int getColumnCount() {
		return columnNames.length;
	}

	public String getColumnName(int col) {
		return columnNames[col];
	}

	public Object getValueAt(int row, int col) {
		Vector rowVector = (Vector)data.elementAt(row);
		return rowVector.elementAt(col);
	}

	public void setValueAt(String value, int row, int col) {
		Vector rowVector = (Vector)data.elementAt(row);
		rowVector.setElementAt(value, col);
	}

	public void addRow(Vector row) {
		data.addElement(row);
	}

	public int findValue(String value) {
		for (int i = 0; i < data.size(); i++) {
			if (getValueAt(i, 0).equals(value))
				return i;
		}
		return -1;
	}

    };


    // called on enter or double-click
    void modifySelectedPrinter() {

        ListSelectionModel m = listTable.getSelectionModel();

        if (m.isSelectionEmpty()) {
            Debug.message("CLNT:  list selection is empty");
            return;
        }

        int selectedRow = m.getMinSelectionIndex();

        Debug.message("CLNT:  list row selected is " + selectedRow);

        selectedPrinter =
            (String) listTable.getModel().getValueAt(selectedRow, 0);
        selprinterServer =
                    (String)listTable.getModel().getValueAt(selectedRow, 1);

        Debug.message("CLNT:  selectedPrinter is " + selectedPrinter);

        doModify();
    }


    // Create printer list in center panel
    public void centerPanel() {

	center = new JPanel();

	listModel = new listTableModel();
	listTable = new JTable(listModel);
        listTable.setColumnSelectionAllowed(false);
        listTable.setRowSelectionAllowed(true);
	listTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        listTable.setShowGrid(false);
        listTable.registerKeyboardAction(new ActionListener() {

	public void actionPerformed(ActionEvent e) {
            Debug.message("CLNT:  enter action");
            if (runningAuth)
                modifySelectedPrinter();
            else
               Toolkit.getDefaultToolkit().beep();
            }},
            KeyStroke.getKeyStroke(KeyEvent.VK_ENTER, 0, false),
            JComponent.WHEN_IN_FOCUSED_WINDOW);


	listTable.addMouseListener(new MouseAdapter() {
	    public void mouseClicked(MouseEvent e) {
                Point pt = e.getPoint();
                int rowIndex = listTable.rowAtPoint(pt);
                int colIndex = listTable.columnAtPoint(pt);
                int clickCount = e.getClickCount();

                Debug.message("CLNT:  getClickCount() is " + clickCount);

                if (clickCount == 2) {
                    if (rowIndex == -1) {
                        Debug.message("CLNT:  clicked outside table");
                    } else {
                        if (runningAuth)
                            modifySelectedPrinter();
                        else
                            Toolkit.getDefaultToolkit().beep();
                    }
                }
            }
	});

	// Add selection listener
	ListSelectionModel rowSelectModel = listTable.getSelectionModel();

	rowSelectModel.addListSelectionListener(new ListSelectionListener() {

	    public void valueChanged(ListSelectionEvent e) {

		listSM = (ListSelectionModel)e.getSource();
		Debug.message("CLNT:  listSM is " + listSM);

		if (listSM.isSelectionEmpty()) {
                           Debug.message("CLNT:  list selection is empty");
                           enableEditMenuItems(false);
		} else {
		    selectedRow = listSM.getMinSelectionIndex();
		    Debug.message(
			"CLNT:  list element selected" + selectedRow);
		    selectedPrinter =
		    (String)listTable.getModel().getValueAt(selectedRow, 0);
		    selprinterServer =
			(String)listTable.getModel().getValueAt(selectedRow, 1);
		    Debug.message(
			"CLNT:  selectedPrinter is " + selectedPrinter);
		    enableEditMenuItems(true);
		}
	    }
	});

	GridBagConstraints c = new GridBagConstraints();
	center.setLayout(new BorderLayout());

	c.insets = new Insets(35, 50, 35, 50);

	try {
            listModel.insertlistTable(PrinterUtil.getPrinterList(ns),
			listModel.getColumnCount());
	} catch (Exception e) {
		Debug.fatal("CLNT:  pmTop:getPrinterList() caught " + e);
		pmMessageDialog m = new pmMessageDialog(
		frame,
		    pmUtility.getResource("Error"),
		    pmUtility.getResource(
			"Cannot.get.list.of.printers.Exiting."),
		    myTop,
		    "getPrinterListFailed");
		m.setVisible(true);
		System.exit(-1);
	}

	scrollPane = new JScrollPane();
	scrollPane.setViewportView(listTable);

	listTable.setPreferredScrollableViewportSize(
					new Dimension(500, 500));
	scrollPane.getViewport().setView(listTable);
	center.add(scrollPane);
	add("Center", center);
    }

	// Create south panel with grid layout

    public void southPanel() {
	JPanel south = new JPanel();
	GridBagConstraints c = new GridBagConstraints();
	south.setLayout(new GridBagLayout());

	// Constraints applied across all entries
	c.fill = GridBagConstraints.BOTH;
	c.insets = new Insets(6, 6, 6, 6);
	c.gridheight = 1;
	c.gridwidth = 1;
	c.gridy = 1;

	// Create the labels
	c.gridx = 0;
	c.weightx = c.weighty = 1.0;

	try {
	defaultpLabel =
		new JLabel(pmUtility.getResource("Default.Printer:") +
                       " " + PrinterUtil.getDefaultPrinter(ns));

	} catch (Exception e) {
		Debug.warning("CLNT:  pmTop:getDefaultPrinter() caught " + e);
		defaultpLabel =	new JLabel(
			pmUtility.getResource("Default.Printer:"));
	}

	south.add(defaultpLabel, c);


	if (newNS.startsWith("files")) {
		try {
			domainhostLabel = new JLabel(pmUtility.getResource(
				"Host:") + " " + host.getLocalHostName());

			nameserviceLabel.setText("    ");

		} catch (Exception e) {
		    Debug.warning("CLNT: pmTop:getLocalHostName caught " + e);
		}

	} else {
		try {
		    nameserviceLabel.setText(
		    pmUtility.getResource("Naming.Service:") + " " + newNS);
		   domainhostLabel = new JLabel(
			pmUtility.getResource("Domain:") + " " +
                   host.getDomainName());
		} catch (Exception e) {
		    Debug.warning("CLNT: pmTop:getDomainName caught " + e);
		}
	}

	c.weightx = c.weighty = 1.0;
	c.gridx = 2;
	south.add(nameserviceLabel, c);
	c.gridx = 3;
	south.add(domainhostLabel, c);
	add("South", south);
    }


	public JMenu appMenu() {
        // name service
        // ---
        // cmd line console
        // confirm all actions
	// use ppd file
        // ---
        // exit

        JMenu appMenu = new JMenu(pmUtility.getResource("Print.Manager"));
        appMenu.setMnemonic(
            pmUtility.getIntResource("Print.Manager.mnemonic"));

	appMenu.addMouseListener(new MouseAdapter() {
		public void mouseClicked(MouseEvent e) {
			Debug.message("CLNT: appMenu MouseListener");
		};
	});

        JMenuItem load = new JMenuItem(
            pmUtility.getResource("Select.Naming.Service"),
            pmUtility.getIntResource("Select.Naming.Service.mnemonic"));

        load.addActionListener(
            new ActionListener() {
            public void actionPerformed(ActionEvent e) {
			    Debug.message("CLNT:  call from load action");
                if (loadView != null)
                    loadView.setVisible(true);
                else
                    loadView = new pmLoad(myTop);
                loadView.Show();

            };
        });
        load.setEnabled(true);
        appMenu.add(load);

        appMenu.addSeparator();

		logCheck = new JCheckBoxMenuItem(
            pmUtility.getResource("Show.Command-Line.Console"));
		logCheck.setMnemonic(
            pmUtility.getIntResource("Show.Command-Line.Console.mnemonic"));

        logCheck.addActionListener(new AbstractAction() {
            public void actionPerformed(ActionEvent e) {
			    Debug.message("CLNT:  call from checkbox action");
                JCheckBoxMenuItem c = (JCheckBoxMenuItem) e.getSource();
                if (c.isSelected() == true) {
                    commandLog.setVisible(true);
                } else {
                    commandLog.setVisible(false);
                }
            }
        });

        if (!runningAuth)
            logCheck.setEnabled(false);

	appMenu.add(logCheck);

        confirmCheck = new JCheckBoxMenuItem(
            pmUtility.getResource("Confirm.All.Actions"), false);
		confirmCheck.setMnemonic(
		    pmUtility.getIntResource("Confirm.All.Actions.mnemonic"));
        if (!runningAuth)
            confirmCheck.setEnabled(false);

	appMenu.add(confirmCheck);

	usePPD = new JCheckBoxMenuItem(
		pmUtility.getResource("Use.PPD.files"), true);
	usePPD.setMnemonic(pmUtility.getIntResource("Use.PPD.files.mnemonic"));

	useLocalhost = new JCheckBoxMenuItem(
		pmUtility.getResource("Use.localhost"), false);
	useLocalhost.setMnemonic(
		pmUtility.getIntResource("Use.localhost.mnemonic"));


	if (!runningAuth) {
		usePPD.setEnabled(false);
		useLocalhost.setEnabled(false);
	}
	appMenu.add(usePPD);
	appMenu.add(useLocalhost);

        appMenu.addSeparator();

        JMenuItem exit = new JMenuItem(
            pmUtility.getResource("Exit"),
            pmUtility.getIntResource("Exit.mnemonic"));

        exit.addActionListener(
            new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                Debug.message("CLNT:  call from exit action");
                System.exit(0);
            };
        });

        exit.setEnabled(true);
        appMenu.add(exit);

        return appMenu;
    }

    // disable everything is not running as root
	public JMenu objectMenu() {
        // add access to printer...
        // ---
        // new local printer...
        // new network printer...
        // ---
        // delete printer
        // modify properties...

        JMenu objectMenu = new JMenu(
            pmUtility.getResource("Printer"));

        objectMenu.setMnemonic(
            pmUtility.getIntResource("Printer.mnemonic"));

            access = new JMenuItem(
            pmUtility.getResource("Add.Access.to.Printer..."),
            pmUtility.getIntResource("Add.Access.to.Printer.mnemonic"));

        access.addActionListener(
	    new ActionListener() {
		public void actionPerformed(ActionEvent e) {
                	Debug.message("CLNT:  call from access action");
			if (accessView != null)
                		accessView.setVisible(true);
			else
                   		accessView = new pmAccess(myTop);
		    accessView.Show();
		};
	    });

        if (!runningAuth)
            access.setEnabled(false);

        objectMenu.add(access);
        objectMenu.addSeparator();

        local = new JMenuItem(
            pmUtility.getResource("New.Attached.Printer..."),
            pmUtility.getIntResource("New.Attached.Printer.mnemonic"));

        local.addActionListener(
            new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                Debug.message("CLNT:  call from localinstall action");
                if (localinstallView != null)
                    localinstallView.setVisible(true);
		else {
		    try {
                	localinstallView = new pmInstallPrinter(
					myTop, Constants.ADDLOCAL);
		    } catch (Exception ex) {
			Debug.message("CLNT:pmTop:caught exception"  + ex);
		    }
		}
                localinstallView.Show();
            };
        });

        if (!runningAuth)
            local.setEnabled(false);

        objectMenu.add(local);

        network = new JMenuItem(
            pmUtility.getResource("New.Network.Printer..."),
            pmUtility.getIntResource("New.Network.Printer.mnemonic"));

        network.addActionListener(
            new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                Debug.message("CLNT:  call from networkinstall action");
                if (networkinstallView != null)
                    networkinstallView.setVisible(true);
		else {
		    try {
                    networkinstallView = new
                        pmInstallPrinter(myTop, Constants.ADDNETWORK);
		    } catch (Exception ex) {
			Debug.message("CLNT:pmTop:caught exception" + ex);
		    }
		}

                networkinstallView.Show();
            };
        });

        if (!runningAuth)
            network.setEnabled(false);

        objectMenu.add(network);
        objectMenu.addSeparator();

        modifyMenuItem = new JMenuItem(
            pmUtility.getResource("Modify.Printer.Properties..."),
            pmUtility.getIntResource("Modify.Printer.Properties.mnemonic"));

	    modifyMenuItem.addActionListener(
            new ActionListener() {
            public void actionPerformed(ActionEvent e) {

		Debug.message("CLNT:  Modify " + selectedPrinter);
		Debug.message("CLNT:  Modify " + selprinterServer);

		doModify();
            };
        });

        modifyMenuItem.setEnabled(false);
        objectMenu.add(modifyMenuItem);

        deleteMenuItem = new JMenuItem(
            pmUtility.getResource("Delete.Printer..."),
            pmUtility.getIntResource("Delete.Printer.mnemonic"));

        deleteMenuItem.addActionListener(
            new ActionListener() {
		public void actionPerformed(ActionEvent e) {
		    Debug.message("CLNT:  call from delete action");
			if (selectedPrinter == null) {
			    Debug.warning("CLNT:  selectedPrinter is null");
			    Debug.message("CLNT:  cannot call pmDelete");
			    // show error window
			} else {
			    deleteView = new pmDelete(myTop);
			}
            };
        });
        deleteMenuItem.setEnabled(false);
        objectMenu.add(deleteMenuItem);
        return objectMenu;
    }

    // returns true iff name was found in the printer list
    public boolean findPrinterInList(String name) {

        int row = -1;

        try {
            String p = name.trim();
            row = listModel.findValue(p);
        } catch (Exception ee) {
            Debug.warning("CLNT:  pmTop:find ActionList: caught " + ee);
        }

        if (row != -1) {
            selectedRow = row;
            listTable.clearSelection();
            listTable.setRowSelectionInterval(row, row);
            listTable.scrollRectToVisible(listTable.getCellRect(row, 0, true));
            listTable.revalidate();
            scrollPane.revalidate();
            scrollPane.repaint();
        }
        return row != -1;
    }

    public JMenu toolsMenu() {

        // find printer...
        JMenu toolsMenu = new JMenu(
            pmUtility.getResource("Tools"));
        toolsMenu.setMnemonic(
            pmUtility.getIntResource("Tools.mnemonic"));

        JMenuItem find = new JMenuItem(
            pmUtility.getResource("Find.Printer"),
            pmUtility.getIntResource("Find.Printer.mnemonic"));
        find.addActionListener(
            new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                Debug.message("CLNT:  call from find action");
                findFrame.setVisible(true);
            }
        });

        toolsMenu.add(find);
        return toolsMenu;
    }

	// Create help Menu

    public JMenu helpMenu() {
        JMenu helpMenu = new JMenu(pmUtility.getResource("Help"));
		helpMenu.setMnemonic(pmUtility.getIntResource("Help.mnemonic"));

        JMenuItem ov = new JMenuItem(
            pmUtility.getResource("Overview"),
            pmUtility.getIntResource("Overview.mnemonic"));
        ov.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
              myTop.showHelpItem("Overview");
            };
        });

        helpMenu.add(ov);

        JMenuItem on = new JMenuItem(
            pmUtility.getResource("On.Help"),
            pmUtility.getIntResource("On.Help.mnemonic"));
        on.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
              myTop.showHelpItem("HelpOnHelp");
            };
        });

        helpMenu.add(on);
        helpMenu.addSeparator();

        JMenuItem about = new JMenuItem(
            pmUtility.getResource("About.Print.Manager"),
            pmUtility.getIntResource("About.Print.Manager.mnemonic"));
        about.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
		Debug.message("CLNT:  call from about help action");
		aboutBox.setVisible(true);
            };
        });

        helpMenu.add(about);
        helpMenu.addSeparator();

        JMenuItem settings = new JMenuItem(
            pmUtility.getResource("Print.Manager.Settings"),
            pmUtility.getIntResource("Print.Manager.Settings.mnemonic"));
	    settings.addActionListener(new ActionListener() {
		public void actionPerformed(ActionEvent e) {
		    Debug.message("CLNT:  print manager settings help action");
		    myTop.showHelpItem("PrintManagerSettings");
		};
        });

        helpMenu.add(settings);
        return helpMenu;
    }

    public void actionPerformed(java.awt.event.ActionEvent e) {
    }

    public void doModify() {

        if (modifyView != null)
            modifyView.pmScreendispose();

	    try {

		if (selectedPrinter == null || selprinterServer == null) {

		} else {

		    if ((host.getLocalHostName()).equals(selprinterServer) ||
			selprinterServer.equals("localhost")) {

			if (isNetwork()) {

			    modifyView = new
				pmInstallPrinter(
					myTop, Constants.MODIFYNETWORK);

			} else {
			    modifyView = new
				pmInstallPrinter(
					myTop, Constants.MODIFYATTACHED);
			}

			modifyView.Show();

		    } else {

			try {
				modifyView = new pmInstallPrinter(
					myTop, Constants.MODIFYREMOTE);
			} catch (Exception e) {
				Debug.message(
				"CLNT:pmTop:caught exception" + e);
			}
			modifyView.Show();
		    }
		}
	    } catch (Exception e) {
		Debug.warning("CLNT:  pmTop:getLocalHostName() caught " + e);
        }
    } // doModify()


    public boolean isNetwork() {

	Printer newpr = new Printer(myTop.ns);
	newpr.setPrinterName(selectedPrinter);

	try {
		newpr.getPrinterDetails();
	} catch (Exception e) {
		Debug.warning("CLNT:  pmTop:getPrinterDetails() caught " + e);
	}

	pmCalls.debugShowPrinter(newpr);

	if (newpr.getDestination() != null)  {
		Debug.message("CLNT:  isNetwork:getDestination " +
                          newpr.getDestination());
		return true;
	} else {
		Debug.message("CLNT:  isNetwork:getDestination is null");
		return false;
	}
    }

    // Set the new namespace
    public void pmsetNS() {

	String serverNS;

	// translate from gui to server
	if (newNS.startsWith("files")) {
		serverNS = new String("system");
		useLocalhost.setState(true);
	} else if (newNS.equals("NIS")) {
		serverNS = new String("nis");
		useLocalhost.setState(false);
	} else if (newNS.equals("LDAP")) {
		serverNS = new String("ldap");
		useLocalhost.setState(false);
	} else {
		serverNS = new String("system");
		useLocalhost.setState(true);
	}

        Debug.message("CLNT:  newNS: " + newNS +
                       "\n serverNS: " + serverNS +
                       "\n ns.getNameService(): " + ns.getNameService());

	if (!serverNS.equals(ns.getNameService())) {

		if (newNS.startsWith("files")) {
			useLocalhost.setState(true);
			ns = systemns;
		} else if (newNS.equals("NIS")) {
			useLocalhost.setState(false);
			ns = nisns;
		} else if (newNS.equals("LDAP")) {
			useLocalhost.setState(false);
			ns = ldapns;
		} else {
			useLocalhost.setState(true);
			ns = systemns;
		}
	}


	// This tool is read-only unless the user is root on the
	// print server. Thus, don't check for namespace authorization
	// if user is not root.

	if (isRoot) {
		// Check if user is authorized with this nameservice
		if (ns.isAuth()) {
			runningAuth = true;
		} else {
		    // nis/ldap is a special case
		    // need to login to nis/ldap server
		    if (ns.getNameService().equals("nis") == true ||
			ns.getNameService().equals("ldap") == true) {

                	try {
                            if (!ns.isAuth()) {
                        	pmUtility.doLogin(myTop, loadView.frame);
				runningAuth = true;
                            }
                	} catch (pmUserCancelledException e) {
                        	Debug.message(
				    "CLNT:pmTop:user cancelled login");
				runningAuth = false;
                	} catch (pmGuiException e) {
                        	Debug.message(
                                    "CLNT:pmTop:login nis/ldap failed: " + e);
				runningAuth = false;
				pmMessageDialog m = new pmMessageDialog(
				    loadView.frame,
				    pmUtility.getResource("Error"),
				    pmUtility.getResource(
					"Required.login.failed."),
				    myTop,
				    "LoginFailed");
				m.setVisible(true);
                	} catch (Exception e) {
                            Debug.message(
                                "CLNT:pmTop:login nis/ldap failed: " + e);
			    runningAuth = false;
			    pmMessageDialog m = new pmMessageDialog(
				    loadView.frame,
				    pmUtility.getResource("Error"),
				    pmUtility.getResource(
					"Required.login.failed."),
				    myTop,
				    "LoginFailed");
			    m.setVisible(true);
                	}
		    } else {
			try {
				ns.checkAuth();
				runningAuth = true;
			} catch (Exception ca) {
			runningAuth = false;
			    pmMessageDialog m = new pmMessageDialog(
			    loadView.frame,
			    pmUtility.getResource("Error"),
			    pmUtility.getResource(
			    "User.not.authorized.to.modify.this.namespace."),
			    myTop,
			    "AuthorizationFailed");
			m.setVisible(true);
			}
		    }
		}

		if (!serverNS.equals(ns.getNameService())) {
			deleteAllScreens();
		}

		// Change front panel as unauthorized to modify
		if (!runningAuth) {
			logCheck.setEnabled(false);
			confirmCheck.setEnabled(false);
			usePPD.setEnabled(false);
			useLocalhost.setEnabled(false);
			access.setEnabled(false);
			local.setEnabled(false);
			network.setEnabled(false);
			modifyMenuItem.setEnabled(false);
			deleteMenuItem.setEnabled(false);
		} else {
			logCheck.setEnabled(true);
			confirmCheck.setEnabled(true);
			access.setEnabled(true);
			local.setEnabled(true);
			network.setEnabled(true);
			if (pmMisc.isppdCachefile())
				usePPD.setEnabled(true);
			else
				usePPD.setEnabled(false);
        		if (ns.getNameService().equals("system") == true) {
				useLocalhost.setEnabled(true);
				useLocalhost.setVisible(true);
			} else {
				useLocalhost.setVisible(false);
			}
		}

	} else {
		runningAuth = false;
	}


        Debug.message("CLNT:  NEW ns.getNameService(): " +
                       ns.getNameService());

    }

    class topnsListener implements ItemListener {
        public topnsListener() {}

        public void itemStateChanged(ItemEvent e) {
            Debug.message("CLNT:  hello from topnsListener" + e.getItem());
			if (e.getStateChange() == ItemEvent.SELECTED) {
				newNS = (String)e.getItem();
			}
        }
    }

    public void pmsetdefaultpLabel() {
	try {
            defaultpLabel.setText(
                pmUtility.getResource("Default.Printer:") +
                " " + PrinterUtil.getDefaultPrinter(ns));

		Debug.message(
			"CLNT: pmTop:pmsetdefaultpLabel(): default printer: " +
                          PrinterUtil.getDefaultPrinter(ns));

	} catch (Exception e) {
		Debug.warning("CLNT: pmTop:getDefaultPrinter() caught " + e);
	}
    }

    public boolean getLogOption() {
	return logCheck.getState();
    }

    public void setLogOption(boolean val) {
	 logCheck.setState(val);
    }

    public boolean getConfirmOption() {
	return confirmCheck.getState();
    }

    public boolean getUsePPD() {
	return usePPD.getState();
    }

    public boolean getUseLocalhost() {
	return useLocalhost.getState();
    }

    public void doFind(String printer) {
    }

    public void deleteAllScreens() {

        if (accessView != null)
            accessView.pmScreendispose();
	accessView = null;

        if (localinstallView != null)
            localinstallView.pmScreendispose();
	localinstallView = null;

        if (networkinstallView != null)
            networkinstallView.pmScreendispose();
	networkinstallView = null;

        if (modifyView != null)
            modifyView.pmScreendispose();
	modifyView = null;

        if (loadView != null)
            loadView.pmScreendispose();
        loadView = null;
    }


    /*
     * enable/disable modify and delete items
     * this must be called when:
     *    . an existing printer is selected
     *    . the selection is disabled
     */
    void enableEditMenuItems(boolean state) {
        if (!runningAuth)
            return;
        modifyMenuItem.setEnabled(state);
        deleteMenuItem.setEnabled(state);
    }

    /*
     * set the log/error state for the current operation
     */
    void setLogData(String cmd, String err, String warn) {
        cmdLog = cmd;
        errorLog = err;
        warningLog = warn;
    }

    /*
     * display current log state for the specified action
     * if the cmdLog is empty nothing at all will be displayed!
     */
    void showLogData(String actionName) {

	// Debug.info("CLNT: showLogData():actionName: " + actionName);
	// Debug.info("CLNT: showLogData():cmdLog: " + cmdLog);

        if (cmdLog == null)
		return;

        addToCommandLog(actionName + "\n");

	// iterate over multiline cmds
	StringTokenizer st = new StringTokenizer(
			cmdLog, "\n\r", false);
	while (st.hasMoreTokens()) {
		addToCommandLog("% " + st.nextToken());
		addToCommandLog("\n");
	}

        if (errorLog != null) {
		st = new StringTokenizer(errorLog, "\n\r", false);
		while (st.hasMoreTokens()) {
			addToCommandLog(st.nextToken());
			addToCommandLog("\n");
		}
	}

        if (warningLog != null) {
		st = new StringTokenizer(warningLog, "\n\r", false);
		while (st.hasMoreTokens()) {
			addToCommandLog(st.nextToken());
			addToCommandLog("\n");
		}
	}

        addToCommandLog("***\n");
    }

    private void addToCommandLog(String s) {
        commandLog.addText(s);
    }

    public void showHelpItem(String tag) {
        if (helpFrame != null)
	    helpFrame.showHelp(tag);
	else
	    Toolkit.getDefaultToolkit().beep();
    }

    public void pmsetNSLabel() {

	if (newNS.startsWith("files")) {

	    nameserviceLabel.setText("    ");
	    Debug.message("CLNT: pmsetNSLabel:nameserviceLabel is : " +
		nameserviceLabel.getText());

	    try {
		domainhostLabel.setText(
		pmUtility.getResource("Host:") + " " +
		host.getLocalHostName());
	    } catch (Exception e) {
		    Debug.warning(
			"CLNT: pmTop:getLocalHostName caught " + e);
	    }

	} else {
		nameserviceLabel.setText(
		    pmUtility.getResource("Naming.Service:") + newNS);
		Debug.message(
		    "CLNT: pmsetNSLabel:nameserviceLabel is : " +
		    nameserviceLabel.getText());

		try {
		    domainhostLabel.setText(
		    pmUtility.getResource("Domain:") + " " +
		    host.getDomainName());
		} catch (Exception e) {
		    Debug.warning(
			"CLNT: pmTop:getDomainName caught " + e);
		}
	}
    }

	// Update the list of printers
	// Printer list will change if nameservice changes and when user
	// adds/deletes/changes printers

    public void pmsetPrinterList() {

        Debug.message("CLNT: pmsetPrinterList() ns is :" +
                       ns.getNameService());

        try {
            listModel.insertlistTable(PrinterUtil.getPrinterList(ns),
                                      listModel.getColumnCount());
        } catch (Exception e) {
            Debug.warning("CLNT: pmTop:getPrinterList() caught " + e);
        }

	listTable.clearSelection();
	scrollPane.getViewport().setView(listTable);
	scrollPane.revalidate();
	scrollPane.repaint();
    }


    // returns -1 if error, 0 otherwise
    protected static int parseArgs(String[] args) {
        int rv = 0;

        for (int i = 0; i < args.length; ++i) {
            if (args[i].compareTo("-debugall") == 0)
                Debug.setDebugLevel(Debug.ALL);
            else if (args[i].compareTo("-debugnone") == 0)
                Debug.setDebugLevel(Debug.NONE);
            else if (args[i].compareTo("-debugwarn") == 0)
                Debug.setDebugLevel(Debug.WARNING);
            else if (args[i].compareTo("-debugerr") == 0)
                Debug.setDebugLevel(Debug.ERROR);
            else if (args[i].compareTo("-debugfatal") == 0)
                Debug.setDebugLevel(Debug.FATAL);
            else if (args[i].compareTo("-debugmsg") == 0)
                Debug.setDebugLevel(Debug.MESSAGE);
            else if (args[i].compareTo("-debuginfo") == 0)
                Debug.setDebugLevel(Debug.INFO);
        }

        return rv;
    }

    public static void main(String[] args) {

        if (parseArgs(args) < 0)
            System.exit(-1);

        // use pmFrame to get app icon
        pmFrame frame = new pmFrame(pmUtility.getResource("info_name"));

	myTop = new pmTop(frame);

	frame.addWindowListener(new WindowAdapter() {
		public void windowClosing(WindowEvent e) {
               		System.exit(0);
            	}
	});

	frame.getContentPane().add("Center", myTop);
	frame.pack();
	frame.setVisible(true);
	frame.repaint();

	pmLoad firstload = new pmLoad(myTop);
	myTop.loadView = firstload;
	firstload.Show();

        aboutBox = new pmAboutBox();
        commandLog = new pmLogDisplay(myTop, "ShowCommandConsole");
        findFrame = new pmFindFrame(myTop);

	/*
	 * Make sure to open the help frame after the about box,
	 * command log, and find frame windows have been opened.
	 * Otherwise it might cause null pointer exceptions as it
	 * takes a long time for the help frame to load.
	 */
        helpFrame = new pmHelpFrame();

    }

    // disable Enter action **for all JTextFields**
    static {
        JTextField f = new JTextField();
        KeyStroke enter = KeyStroke.getKeyStroke(KeyEvent.VK_ENTER, 0);
        Keymap map = f.getKeymap();
        map.removeKeyStrokeBinding(enter);
    }

}
