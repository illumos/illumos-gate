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
 * ident	"%Z%%M%	%I%	%E% SMI"
 *
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/**
 * GUI interface for Kerberos KDC
 */

// Java Workshop stuff
import sunsoft.jws.visual.rt.base.*;
import sunsoft.jws.visual.rt.base.Global;
import sunsoft.jws.visual.rt.awt.TabbedFolder;
import sunsoft.jws.visual.rt.awt.TextList;
import sunsoft.jws.visual.rt.awt.StringVector;
import sunsoft.jws.visual.rt.shadow.java.awt.*;

// Regular JDK stuff
import java.awt.*;
import java.awt.event.*;
import java.util.EventListener;
import java.util.Properties;
import java.util.Vector;
import java.util.Random;
import java.util.StringTokenizer;
import java.io.IOException;
import java.io.File;
import java.io.InputStream;
import java.net.URL;

// Stuff to support I18N
import java.util.Date;
import java.util.Calendar;
import java.util.GregorianCalendar;
import java.util.Locale;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.DateFormatSymbols;
import java.text.NumberFormat;
import java.util.ResourceBundle;
import java.util.ListResourceBundle;
import java.util.MissingResourceException;
import java.util.Enumeration;

public class KdcGui extends Group {
    
    // Basics
    private KdcGuiRoot gui;
    private Krb5Conf kc;
    private Principal prin = null;
    private Policy pol = null;
    private Defaults defaults = null;
    private Defaults olddefaults = null;
    public Frame defaultsEditingFrame = null; // public since used
    // by ContextHelp class
    public Frame realMainFrame = null;
    public Frame realLoginFrame = null;
    
    public Kadmin Kadmin = null;
    
    // Privileges stuff: corresponds to ADMCIL set in kdc.conf
    public int privs = 0;
    public static final int PRIV_ADD	= 0x02;		// KADM5_PRIV_ADD
    public static final int PRIV_DELETE	= 0x08;		// KADM5_PRIV_DELETE
    public static final int PRIV_MODIFY	= 0x04;		// KADM5_PRIV_MODIFY
    public static final int PRIV_CHANGEPW	= 0x20;	// KADM5_PRIV_CPW
    public static final int PRIV_INQUIRE	= 0x01;	// KADM5_PRIV_GET
    public static final int PRIV_LIST	= 0x10;		// KADM5_PRIV_LIST
    public boolean noLists = false;
    
    // For modal warning dialog and context-sensitive help dialog
    private Dialog dialog;
    public ContextHelp cHelp = null; // tweaked from ContextHelp when
    // it is dismissed
    
    private static Toolkit toolkit;
    
    // For showDataFormatError() to determine what kind of error to show
    
    public static final int DURATION_DATA = 1;
    public static final int DATE_DATA = 2;
    public static final int NUMBER_DATA = 3;
    
    private static String[] durationErrorText = null;
    private static String[] dateErrorText = null;
    private static String[] numberErrorText = null;
    
    // For date & time helper dialogs
    private DateTimeDialog dateTimeDialog = null;
    private DurationHelper durationHelper = null;

    // For the encryption list helper dialog
    private EncListDialog encListDialog = null;
    
    // Important defaults and current settings
    private String DefName = null;
    private String DefRealm = null;
    private String DefServer = null;
    private String DefPort = "0";
    private String CurName, CurPass, CurRealm, CurServer;
    private int CurPort;
    private String CurPrincipal;
    private String CurPolicy;
    private String curPrPattern = "";
    private String curPoPattern = "";
    private int curPrListPos = 0;
    private int curPoListPos = 0;
    private String[] principalList = null;
    private Date principalListDate = new Date(0);
    private String[] policyList = null;
    private Date policyListDate = new Date(0);
    private static final long A_LONG_TIME = 1000 * 60 * 60 * 24 * 365;
    
    // General state variables
    private boolean prSelValid = false;
    private String[] prMulti = null;
    private boolean prNeedSave = false;
    private boolean poSelValid = false;
    private String[] poMulti = null;
    private boolean poNeedSave = false;
    private boolean glNeedSave = false;
    private boolean firsttime = true;
    private boolean prnameEditable = false;
    private boolean ponameEditable = false;
    
    // Support for context-sensitive help
    private static final int BUTTON_ACTION = 1;
    private static final int BUTTON_MOUSE = 2;
    private static final int TEXTFIELD_ACTION = 3;
    private static final int TEXTFIELD_MOUSE = 4;
    private static final int TEXTFIELD_KEY = 5;
    private static final int CHOICE_ITEM = 6;
    private static final int CHOICE_MOUSE = 7;
    private static final int CHECKBOX_ITEM = 8;
    private static final int CHECKBOX_MOUSE = 9;
    private static final int LABEL_MOUSE = 10;
    private static final int WINDOW_LISTENER = 11;
    
    private boolean loginListeners = false;
    private Vector LoginNormal = null;
    private Vector LoginHelp = null;
    private Vector LoginFixers = null;
    private Vector MainNormal = null;
    private Vector MainHelp = null;
    private Vector MainFixers = null;
    private Vector defaultsNormal = null;
    private Vector defaultsHelp = null;
    private Vector defaultsFixers = null;
    public boolean loginHelpMode = false;
    public boolean mainHelpMode = false;
    public boolean defaultsHelpMode = false;
    
    // For Principal and Policy Keystroke listeners
    private static final int PRINCIPAL_EDITING = 1;
    private static final int POLICY_EDITING = 2;
    private static final int DEFAULTS_EDITING = 3;
    private static final int PRINCIPAL_LIST = 4;
    private static final int POLICY_LIST = 5;
    
    // For status line
    private String OpString = "";
    private String ModeString = "";
    private String SaveString = "";
    
    // For I18N
    private static ResourceBundle rb;
    private static ResourceBundle hrb;
    private static DateFormat df;
    private static NumberFormat nf;
    
    private static String neverString;
    
    // For general pupose help
    Process browserProcess;
    String helpIndexFile = "file:/usr/lib/krb5/HelpIndex.html";
    
    // For performance monitoring
    boolean perfmon = false;
    Date pdateFirst;
    Date pdateAfterKrb5Conf;
    Date pdateEndGuiRoot;
    Date pdateBeginStartGroup;
    Date pdateStringsDone;
    Date pdateLoginReady;
    Date pdateLoginDone;
    Date pdateSessionUp;
    Date pdatePreMainShow;
    Date pdatePostMainShow;
    Date pdateMainActive;
    Date pdateStartPlist;
    Date pdateHavePlist;
    Date pdateEmptyPlist;
    Date pdateDonePlist;
    
    public void reportTime(String s0, Date curr, Date prev) {
        if (!perfmon)
            return;
        String s1 = curr.toString();
        long curdiff = curr.getTime() - prev.getTime();
        String s2 = (new Long(curdiff)).toString();
        long cumdiff = curr.getTime() - pdateFirst.getTime();
        String s3 = (new Long(cumdiff)).toString();
        System.out.println(s0+s1+" delta "+s2+" cume "+s3);
    }
    
    public void reportStartTimes() {
        if (!perfmon)
            return;
        System.out.println("");
        reportTime("First timestamp: ", pdateFirst, pdateFirst);
        reportTime("After krb5.conf: ", pdateAfterKrb5Conf, pdateFirst);
        reportTime("KdcGuiRoot done: ", pdateEndGuiRoot, pdateAfterKrb5Conf);
        reportTime("At startGroup  : ", pdateBeginStartGroup, pdateEndGuiRoot);
        reportTime("Strings set up : ", pdateStringsDone, pdateBeginStartGroup);
        reportTime("Login ready    : ", pdateLoginReady, pdateStringsDone);
        reportTime("Login complete : ", pdateLoginDone, pdateLoginReady);
        reportTime("Session set up : ", pdateSessionUp, pdateLoginDone);
        reportTime("Start main win : ", pdatePreMainShow, pdateSessionUp);
        reportTime("Done main win  : ", pdatePostMainShow, pdatePreMainShow);
        reportTime("Main win active: ", pdateMainActive, pdatePostMainShow);
    }
    
    /**
     * Sample method call ordering during a group's lifetime:
     *
     * Constructor
     * initRoot
     * initGroup
     * (setOnGroup and getOnGroup may be called at any time in any
     *  order after initGroup has been called)
     * createGroup
     * showGroup/hideGroup + startGroup/stopGroup
     * destroyGroup
     */
    
    /**
     * The constructor sets up defaults for login screen
     *
     */
    public KdcGui() {
        
        /*
         * Set up defaults from /etc/krb5/krb5.conf
         */
        
        pdateFirst = new Date();
        DefName = System.getProperty("user.name" /* NOI18N */)+
	    "/admin" /* NOI18N */;
        kc = new Krb5Conf();
        DefRealm = kc.getDefaultRealm();
        DefServer = kc.getRealmServer(DefRealm);
        DefPort = kc.getRealmPort(DefRealm);
        pdateAfterKrb5Conf = new Date();
        
        /*
         * Take care of Java Workshop attribute plumbing
         */
        addForwardedAttributes();
    }
    
    /**
     * Inherited from the Java Workshop skeleton
     *
     */
    protected Root initRoot() {
        /*
         * Initialize the gui components
         */
        gui = new KdcGuiRoot(this);
        pdateEndGuiRoot = new Date();
        
        /*
         * Take care of Java Workshop attribute plumbing.
         */
        addAttributeForward(gui.getMainChild());
        
        initLoginStrings();
        initMainStrings();
        pdateStringsDone = new Date();
        return gui;
    }
    
    /**
     * Set up the login screen properly.
     *
     */
    protected void startGroup() {
        pdateBeginStartGroup = new Date();
        realLoginFrame = (Frame)gui.loginframe.getBody();
        realLoginFrame.setTitle(getString("SEAM Administration Login"));
        setLoginDefaults();
        pdateLoginReady = new Date();
    }
    
    /**
     * All cleanup done here.
     */
    protected void stopGroup() {
        killHelpBrowser();
    }
    
    
    /**
     * Callbacks from Java workshop to decide whether to take the action
     * or show appropriate help for it.
     * 
     * 1. Actions that are triggered from all three - mainframe,
     *    loginframe, and defaultsEditingFrame - are: context sensitive help.
     * 2. Actions that are triggered only from mainframe are: printing,
     *    logging out, edit preferences.
     * 3. Actions that are triggered from mainframe and loginframe are:
     *    exit, general help, context sensitive help, about.
     */
    
    
    // All three frames
    
    public void checkContextSensitiveHelp(Frame frame) {
        if ((loginHelpMode && frame == realLoginFrame)
            || (mainHelpMode && frame == realMainFrame)
	    || (defaultsHelpMode && frame == defaultsEditingFrame))
	    showHelp("ContextSensitiveHelp");
        else
            contextHelp(frame);
    }
    
    // Mainframe only
    
    public void checkPrintCurPr() {
        if (mainHelpMode)
            showHelp("PrintCurrentPrincipal");
        else
            printCurPr();
    }
    
    public void checkPrintCurPol() {
        if (mainHelpMode)
            showHelp("PrintCurrentPolicy");
        else
            printCurPol();
    }
    
    public void checkPrintPrList() {
        if (mainHelpMode)
            showHelp("PrintPrincipalList");
        else
            printPrList();
    }
    
    public void checkPrintPoList() {
        if (mainHelpMode)
            showHelp("PrintPolicyList");
        else
            printPoList();
    }
    
    public void checkLogout() {
        if (mainHelpMode)
            showHelp("Logout");
        else if (okayToLeave(realMainFrame))
            logout();
    }
    
    public void checkEditPreferences() {
        if (mainHelpMode)
            showHelp("EditPreferences");
        else
            editPreferences();
    }
    
    public void checkRefreshPrincipals() {
        if (mainHelpMode)
            showHelp("RefreshPrincipals");
        else {
            principalList = null;
            fillPrincipalList(curPrPattern);
        }
    }
    
    public void checkRefreshPolicies() {
        if (mainHelpMode)
            showHelp("RefreshPolicies");
        else {
            policyList = null;
            fillPolicyList(curPoPattern);
        }
    }
    
    // Mainframe and loginframe
    
    public void checkExit(Frame frame) {
        if ((loginHelpMode && frame == realLoginFrame)
            || (mainHelpMode && frame == realMainFrame))
	    showHelp("Exit");
        else if (okayToLeave(frame))
            exit();
    }
    
    public void checkHelp(Frame frame) {
        if ((loginHelpMode && frame == realLoginFrame)
            || (mainHelpMode && frame == realMainFrame))
	    showHelp("HelpBrowser");
        else
            showHelpBrowser(frame);
    }
    
    public void checkAbout(Frame frame) {
        if ((loginHelpMode && frame == realLoginFrame)
            || (mainHelpMode && frame == realMainFrame))
	    showHelp("About");
        else
            doAbout(frame);
    }
    
    public boolean okayToLeave(Frame frame) {
        if (prNeedSave || poNeedSave || glNeedSave) {
            String text[] = {getString("You are about to lose changes."),
			     getString("Click Save to commit changes, "
				       +"Discard to discard changes, "
				       +"or Cancel to continue editing.")};
            String resp = confirmSave(frame, text);
            if (resp.equals(getString("Cancel")))
                return false;
            else if (resp.equals(getString("Save"))) {
                if (prNeedSave)
                    if (!prDoSave())
			return false; // found an error so cannot leave
                if (poNeedSave)
                    if (!poDoSave())
			return false; // found an error so cannot leave
                if (glNeedSave)
                    glDoSave(true);
            } else
                prNeedSave = poNeedSave = glNeedSave = false;
        }
        return true;
    }
    
    /**
     * We use the JDK 1.1 event model for most of our events, but
     * we do still need to handle old-style events because the
     * tabbed folder and the card panel(supplied by Java Workshop)
     * are not compatible with the new event model.  We use the
     * callouts from Java Workshop to deal with the card panel,
     * but we need to have some code here to do the right thing
     * when the user selects a new tab in the tabbed folder.
     *
     * It is important that not too many conditions are tested here,
     * because all events flow through this code path.
     *
     */
    public boolean handleEvent(Message msg, Event evt) {
        
        /*
         * Look for events from the principal and policy list.
         */
        
        if (evt.target == gui.Prlist.getBody()) {
            if (mainHelpMode) {
                if (evt.id == Event.ACTION_EVENT
		    || evt.id == Event.LIST_SELECT) {
                    restorePrListSelection();
                    showHelp(((Component)gui.Prlist.getBody()).getName());
                }
            } // end of help mode
            else if (evt.id == Event.ACTION_EVENT)
                prModify();
            else if (evt.id == Event.LIST_SELECT)
                lookAtPrList();
            return true;
        } // end of Prlist
        
        if (evt.target == gui.Pollist.getBody()) {
            if (mainHelpMode) {
                if (evt.id == Event.ACTION_EVENT
		    || evt.id == Event.LIST_SELECT) {
                    restorePoListSelection();
                    showHelp(((Component)gui.Pollist.getBody()).getName());
                }
            } // end of help mode
            else if (evt.id == Event.ACTION_EVENT)
                poSelected();
            else if (evt.id == Event.LIST_SELECT)
                lookAtPoList();
            return true;
        } // end of Pollist
        
        /*
         * Look for a unique event from the tabbed folder component;
         * if I see it, I know I have a chance to disallow a switch.
         * This makes sure data is saved before leaving a tab.
         */
        if (evt.id == TabbedFolder.CONFIRM_SWITCH) {
            // System.out.println("Got confirm for "+evt.arg);
            String e = (String)evt.arg;
            if (!mainHelpMode && okayToLeave(realMainFrame) == false) {
                // System.out.println("Denying switch");
                ((TabbedFolder)gui.tabbedfolder1.getBody()).cancelSwitch();
            }
            /*
             * Okay with switch; make sure the data is up to date
             */
            else if (e.compareTo(getString("Principals")) == 0) {
                if (mainHelpMode) {
                    showHelp("PrincipalTab");
                    ((TabbedFolder)gui.tabbedfolder1.getBody()).cancelSwitch();
                } else {
                    showPrincipalList(curPrPattern);
                    disablePolicyPrinting();
                }
            } else if (e.compareTo(getString("Policies")) == 0) {
                if (mainHelpMode) {
                    showHelp("PolicyTab");
                    ((TabbedFolder)gui.tabbedfolder1.getBody()).cancelSwitch();
                } else {
                    showPolicyList(curPoPattern);
                    disablePrincipalPrinting();
                }
            }
        }
        return super.handleEvent(msg, evt);
    }
    
    /*
     * New methods for the admin gui login screen.
     */
    
    /**
     * Set strings on login screen to their I18N'd values
     *
     */
    public void initLoginStrings() {
        gui.File2.set("text" /* NOI18N */, getString("File"));
        gui.Exit2.set("text" /* NOI18N */, getString("Exit"));
        gui.menu1.set("text" /* NOI18N */, getString("Help"));
        gui.browserHelp1.set("text" /* NOI18N */, getString("Help Contents"));
        gui.Context2.set("text" /* NOI18N */,
			 getString("Context-Sensitive Help"));
        gui.About2.set("text" /* NOI18N */, getString("About"));
        gui.LoginNameLabel.set("text" /* NOI18N */,
			       getString("Principal Name:"));
        gui.LoginPassLabel.set("text" /* NOI18N */, getString("Password:"));
        gui.LoginRealmLabel.set("text" /* NOI18N */, getString("Realm:"));
        gui.LoginServerLabel.set("text" /* NOI18N */, getString("Master KDC:"));
        gui.LoginOK.set("text" /* NOI18N */, getString("OK"));
        gui.LoginStartOver.set("text" /* NOI18N */, getString("Start Over"));
    }
    
    /**
     * Set strings on main screen to their I18N'd values
     *
     */
    public void initMainStrings() {
        gui.mainframe.set("title" /* NOI18N */,
			  getString("SEAM Administration Tool"));
        gui.File.set("text" /* NOI18N */, getString("File"));
        gui.Print.set("text" /* NOI18N */, getString("Print"));
        gui.PrintCurPr.set("text" /* NOI18N */, getString("Current Principal"));
        gui.PrintCurPol.set("text" /* NOI18N */, getString("Current Policy"));
        gui.PrintPrlist.set("text" /* NOI18N */, getString("Principal List"));
        gui.PrintPollist.set("text" /* NOI18N */, getString("Policy List"));
        gui.logout.set("text" /* NOI18N */, getString("Log Out"));
        gui.Exit.set("text" /* NOI18N */, getString("Exit"));
        gui.editMenu.set("text" /* NOI18N */, getString("Edit"));
        gui.editPreferences.set("text" /* NOI18N */,
				getString("Properties..."));
        gui.menu2.set("text" /* NOI18N */, getString("Refresh"));
        gui.refreshPrincipals.set("text" /* NOI18N */,
				  getString("Principal List"));
        gui.refreshPolicies.set("text" /* NOI18N */, getString("Policy List"));
        gui.Help.set("text" /* NOI18N */, getString("Help"));
        gui.browserHelp2.set("text" /* NOI18N */, getString("Help Contents"));
        gui.Context.set("text" /* NOI18N */,
			getString("Context-Sensitive Help"));
        gui.About.set("text" /* NOI18N */, getString("About"));
        
        gui.Prlisttab.set("layoutName", getString("Principals"));
        gui.Pollisttab.set("layoutName", getString("Policies"));
        
        gui.PrListLabel.set("text" /* NOI18N */, getString("Principal List"));
        gui.PrSearchLab.set("text" /* NOI18N */, getString("Filter Pattern:"));
        gui.PrListClear.set("text" /* NOI18N */, getString("Clear Filter"));
        gui.PrListModify.set("text" /* NOI18N */, getString("Modify"));
        gui.PrListAdd.set("text" /* NOI18N */, getString("Create New"));
        gui.PrListDelete.set("text" /* NOI18N */, getString("Delete"));
        gui.PrListDuplicate.set("text" /* NOI18N */, getString("Duplicate"));
        
        gui.PrBasicLabel.set("text" /* NOI18N */,
			     getString("Principal Basics"));
        gui.PrNameLabel1.set("text" /* NOI18N */, getString("Principal Name:"));
        gui.LabelBarGeneral.set("text" /* NOI18N */, getString("General"));
        gui.PrCommentsLabel.set("text" /* NOI18N */, getString("Comments:"));
        gui.PrPolicyLabel.set("text" /* NOI18N */, getString("Policy:"));
        gui.PrPasswordLabel.set("text" /* NOI18N */, getString("Password:"));
        gui.PrBasicRandomPw.set("text" /* NOI18N */,
				getString("Generate Random Password"));
        gui.EncListLabel.set("text" /* NOI18N */,
			getString("Encryption Key Types:"));
        gui.LabelBarPrincipal.set("text" /* NOI18N */,
				  getString("Admin History"));
        gui.PrLastChangedTimeLabel.set("text" /* NOI18N */,
				       getString("Last Principal Change:"));
        gui.PrLastChangedByLabel.set("text" /* NOI18N */,
				     getString("Last Changed By:"));
        gui.PrExpiryLabel.set("text" /* NOI18N */,
			      getString("Account Expires:"));
        gui.PrBasicSave.set("text" /* NOI18N */, getString("Save"));
        gui.PrBasicPrevious.set("text" /* NOI18N */, getString("Previous"));
        gui.PrBasicNext.set("text" /* NOI18N */, getString("Next"));
        gui.PrBasicCancel.set("text" /* NOI18N */, getString("Cancel"));
        
        gui.PrDetailLabel.set("text" /* NOI18N */,
			      getString("Principal Details"));
        gui.LabelBarPassword.set("text" /* NOI18N */, getString("Password"));
        gui.PrLastSuccessLabel.set("text" /* NOI18N */,
				   getString("Last Success:"));
        gui.PrLastFailureLabel.set("text" /* NOI18N */,
				   getString("Last Failure:"));
        gui.PrFailureCountLabel.set("text" /* NOI18N */,
				    getString("Failure Count:"));
        gui.PrPwLastChangedLabel.set("text" /* NOI18N */,
				     getString("Last Password Change:"));
        gui.PrPwExpiryLabel.set("text" /* NOI18N */,
				getString("Password Expires:"));
        gui.PrKvnoLabel.set("text" /* NOI18N */, getString("Key Version:"));
        gui.LabelBarTicket.set("text" /* NOI18N */,
			       getString("Ticket Lifetimes"));
        gui.PrMaxTicketLifetimeLabel.set("text" /* NOI18N */,
				 getString("Maximum Lifetime (seconds):"));
        gui.PrMaxTicketRenewalLabel.set("text" /* NOI18N */,
				getString("Maximum Renewal (seconds):"));
        gui.PrDetailSave.set("text" /* NOI18N */, getString("Save"));
        gui.PrDetailPrevious.set("text" /* NOI18N */, getString("Previous"));
        gui.PrDetailNext.set("text" /* NOI18N */, getString("Next"));
        gui.PrDetailCancel.set("text" /* NOI18N */, getString("Cancel"));
        
        gui.PrFlagLabel.set("text" /* NOI18N */, getString("Principal Flags"));
        gui.LabelBarSecurity.set("text" /* NOI18N */, getString("Security"));
        
        gui.PrLockAcct.set("text" /* NOI18N */,
			   Flags.getLabel(Flags.DISALLOW_ALL_TIX));
        gui.PrForcePwChange.set("text" /* NOI18N */,
				Flags.getLabel(Flags.REQUIRES_PWCHANGE));
        gui.LabelBarTickets.set("text" /* NOI18N */, getString("Ticket"));
        gui.PrAllowPostdated.set("text" /* NOI18N */,
				 Flags.getLabel(Flags.DISALLOW_POSTDATED));
        gui.PrAllowForwardable.set("text" /* NOI18N */,
				   Flags.getLabel(Flags.DISALLOW_FORWARDABLE));
        gui.PrAllowRenewable.set("text" /* NOI18N */,
				 Flags.getLabel(Flags.DISALLOW_RENEWABLE));
        gui.PrAllowProxiable.set("text" /* NOI18N */,
				 Flags.getLabel(Flags.DISALLOW_PROXIABLE));
        gui.PrAllowSvr.set("text" /* NOI18N */,
			   Flags.getLabel(Flags.DISALLOW_SVR));
        gui.LabelBarMiscellany.set("text" /* NOI18N */,
				   getString("Miscellaneous"));
        gui.PrAllowTGT.set("text" /* NOI18N */,
			   Flags.getLabel(Flags.DISALLOW_TGT_BASED));
        gui.PrAllowDupAuth.set("text" /* NOI18N */,
			       Flags.getLabel(Flags.DISALLOW_DUP_SKEY));
        gui.PrRequirePreAuth.set("text" /* NOI18N */,
				 Flags.getLabel(Flags.REQUIRE_PRE_AUTH));
        gui.PrRequireHwPreAuth.set("text" /* NOI18N */,
				   Flags.getLabel(Flags.REQUIRE_HW_AUTH));
        gui.PrFlagsSave.set("text" /* NOI18N */, getString("Save"));
        gui.PrFlagsPrevious.set("text" /* NOI18N */, getString("Previous"));
        gui.PrFlagsNext.set("text" /* NOI18N */, getString("Done"));
        gui.PrFlagsCancel.set("text" /* NOI18N */, getString("Cancel"));
        
        gui.PoListLabel.set("text" /* NOI18N */, getString("Policy List"));
        gui.PoListPatternLabel.set("text" /* NOI18N */,
				   getString("Filter Pattern:"));
        gui.PoListClear.set("text" /* NOI18N */, getString("Clear Filter"));
        gui.PoListModify.set("text" /* NOI18N */, getString("Modify"));
        gui.PoListAdd.set("text" /* NOI18N */, getString("Create New"));
        gui.PoListDelete.set("text" /* NOI18N */, getString("Delete"));
        gui.PoListDuplicate.set("text" /* NOI18N */, getString("Duplicate"));
        
        gui.PoDetailLabel.set("text" /* NOI18N */, getString("Policy Details"));
        gui.PoNameLabel.set("text" /* NOI18N */, getString("Policy Name:"));
        gui.PoMinPwLengthLabel.set("text" /* NOI18N */,
				   getString("Minimum Password Length:"));
        gui.PoMinPwClassLabel.set("text" /* NOI18N */,
				  getString("Minimum Password Classes:"));
        gui.PoSavedPasswordsLabel.set("text" /* NOI18N */,
				      getString("Saved Password History:"));
        gui.PoMinTicketLifetimeLabel.set("text" /* NOI18N */,
			 getString("Minimum Password Lifetime (seconds):"));
        gui.PoMaxTicketLifetimeLabel.set("text" /* NOI18N */,
			 getString("Maximum Password Lifetime (seconds):"));
        gui.PoReferencesLabel.set("text" /* NOI18N */,
				  getString("Principals Using This Policy:"));
        gui.PoDetailSave.set("text" /* NOI18N */, getString("Save"));
        gui.PoDetailPrevious.set("text" /* NOI18N */, getString("Previous"));
        gui.PoDetailDone.set("text" /* NOI18N */, getString("Done"));
        gui.PoDetailCancel.set("text" /* NOI18N */, getString("Cancel"));
    }
    
    /**
     * Allow user to see a fatal error before exiting
     */
    public void fatalError(Frame frame, String[] text) {
        String title = getString("Error");
        String[] buttons = new String[1];
        buttons[0] = getString("OK");
        ChoiceDialog cd = new ChoiceDialog(frame, title, text, buttons);
        cd.getSelection();
        exit();
    }
    
    /**
     * Set the defaults for the login screen.  Called on startup,
     * when "Start Over" is pressed, or when "Log Out" is chosen
     * from the main screen's menu.
     *
     */
    public void setLoginDefaults() {
        CurName = DefName;
        CurPass = "";
        if (DefRealm != null)
            CurRealm = DefRealm;
        else {
            CurRealm = "";
            if (firsttime) {
                showLoginWarning(getString("Cannot find default realm; "
					   +"check /etc/krb5/krb5.conf"));
                firsttime = false;
            }
        }
        if (DefServer != null)
            CurServer = DefServer;
        else
            CurServer = "";
        CurPort = 0;
        try {
            Integer i = new Integer(DefPort);
            CurPort = i.intValue();
        } catch (NumberFormatException e) {}
        gui.LoginName.set("text" /* NOI18N */, CurName);
        gui.LoginPass.set("text" /* NOI18N */, CurPass);
        gui.LoginRealm.set("text" /* NOI18N */, CurRealm);
        gui.LoginServer.set("text" /* NOI18N */, CurServer);
        if (CurRealm.equals("___default_realm___")) {
            String[] error = new String[1];
            error[0] = getString(
				 "Kerberos /etc/krb5/krb5.conf configuration"
				 +" file not configured; exiting");
            fatalError(realLoginFrame, error);
        }
        if (!loginListeners)
            setupLoginNormalListeners();
        loginListeners = true;
        TextField name = (TextField)gui.LoginName.getBody();
        name.selectAll();
        name.requestFocus();
    }
    
    /**
     * React after new realm entered
     *
     */
    public void newRealm() {
        CurRealm = (String)gui.LoginRealm.get("text" /* NOI18N */);
        String s = kc.getRealmServer(CurRealm);
        if (s != null) {
            CurServer = s;
            gui.LoginServer.set("text" /* NOI18N */, CurServer);
            
        } else {
            showLoginWarning(getString("Cannot find default server for realm"));
            CurServer = "";
            gui.LoginServer.set("text" /* NOI18N */, CurServer);
            ((TextField)gui.LoginServer.getBody()).requestFocus();
        }
    }
    
    /**
     * React after new server entered
     *
     */
    public void newServer() {
        CurServer = (String)gui.LoginServer.get("text" /* NOI18N */);
        if (CurPass.compareTo("") != 0)
            loginComplete();
    }
    
    /**
     * React after username is complete
     *
     */
    public void nameComplete() {
        ((TextField)gui.LoginName.getBody()).select(0, 0);
        ((TextField)gui.LoginPass.getBody()).requestFocus();
    }
    
    /**
     * React after password is complete or "OK" button is pressed.
     * We insist that the realm and server are set here separately
     * so that we can permit field-to-field motion if /etc/krb5/krb5.conf
     * does not exist.
     *
     */
    public void passwordComplete() {
        CurPass = (String)gui.LoginPass.get("text" /* NOI18N */);
        if (CurRealm.compareTo("") == 0) {
            ((TextField)gui.LoginRealm.getBody()).requestFocus();
            return;
        }
        if (CurServer.compareTo("") == 0) {
            ((TextField)gui.LoginServer.getBody()).requestFocus();
            return;
        }
        loginComplete();
    }
    
    /**
     * Check to see if we're happy with the login information.
     * We may want to go to the main screen, principal list tab.
     *
     */
    public void loginComplete() {
        pdateLoginDone = new Date();
        CurName   = (String)gui.LoginName.get("text" /* NOI18N */);
        CurPass   = (String)gui.LoginPass.get("text" /* NOI18N */);
        CurRealm  = (String)gui.LoginRealm.get("text" /* NOI18N */);
        CurServer = (String)gui.LoginServer.get("text" /* NOI18N */);
        if (CurPass.compareTo("") == 0) {
            showLoginWarning(getString("A password must be specified"));
            ((TextField)gui.LoginPass.getBody()).requestFocus();
            return;
        }
        if (CurRealm.compareTo("") == 0) {
            showLoginWarning(getString("A realm entry must be specified"));
            ((TextField)gui.LoginRealm.getBody()).requestFocus();
            return;
        }
        if (CurServer.compareTo("") == 0) {
            showLoginWarning(getString("A master KDC entry must be specified"));
            ((TextField)gui.LoginServer.getBody()).requestFocus();
            return;
        }
        
        realLoginFrame.setCursor(new Cursor(Cursor.WAIT_CURSOR));
        Kadmin = new Kadmin();
        boolean b;
        try {
            b = Kadmin.sessionInit(CurName, CurPass, CurRealm, CurServer,
				   CurPort);
        } catch (Exception e) {
            b = false;
            realLoginFrame.setCursor(new Cursor(Cursor.DEFAULT_CURSOR));
            showLoginError(e.getMessage());
            return;
        }
        realLoginFrame.setCursor(new Cursor(Cursor.DEFAULT_CURSOR));
        if (b == false) {
            showLoginError(getString("Invalid login, please try again"));
            return;
        }
        pdateSessionUp = new Date();
        
        // Instantiate defaults for this user
        if (defaults == null)
            defaults = new Defaults(System.getProperty("user.home" /* NOI18N */)
				    + "/.gkadmin" /* NOI18N */,
			    (java.awt.Color)gui.mainframe.get("background"));
        else
            defaults.refreshDefaults();
        
        // Figure out what privileges we have
        try {
            privs = Kadmin.getPrivs();
        } catch (Exception e) {
            showLoginError(e.getMessage());
        }
        
        // Check privileges; if bad enough, we'll just give up.
        if (checkPrivs() == false) {
            try {
                Kadmin.sessionExit();
            } catch (Exception e) {}
            return;
        }
        reactToPrivs();
        
        prSetEditable(false);
        prSetCanSave(false);
        poSetEditable(false);
        poSetCanSave(false);
        prSelValid(false);
        poSelValid(false);
        gui.PrListPattern.set("text" /* NOI18N */, "");
        gui.PoListPattern.set("text" /* NOI18N */, "");
        
        // Disable login frame
        setListeners(LoginNormal, false);
        loginListeners = false;
        
        pdatePreMainShow = new Date();
        realLoginFrame.setCursor(new Cursor(Cursor.WAIT_CURSOR));
        gui.mainframe.show(true);	/* XXX - done waaay too early, fix */
        realLoginFrame.setCursor(new Cursor(Cursor.DEFAULT_CURSOR));
        pdatePostMainShow = new Date();
        realMainFrame  = (Frame)gui.mainframe.getBody();
        realMainFrame.setCursor(new Cursor(Cursor.WAIT_CURSOR));
        gui.tabbedfolder1.show(getString("Principals"));
        gui.cardpanel2.show("List" /* NOI18N */);
        setupMainNormalListeners();
        setupDefaultsEditingFrame();
        realMainFrame.setCursor(new Cursor(Cursor.DEFAULT_CURSOR));
        pdateMainActive = new Date();
        reportStartTimes();
        
        showPolicyList("");
        showPrincipalList("");
        setPolicyChoice();
        /* XXX - disabled multiple selection until double-click works */
        gui.Prlist.set("allowMultipleSelections" /* NOI18N */,
		       new Boolean(false));
        gui.Pollist.set("allowMultipleSelections" /* NOI18N */,
			new Boolean(false));
        if ((privs & PRIV_LIST) == 0) {
            showWarning(
	getString("Unable to access lists; please use the Name field."));
            ((TextField)gui.PrListPattern.getBody()).requestFocus();
        }
    }
    
    /**
     * React to main screen's "Log Out" choice by going back to login screen.
     *
     */
    public void logout() {
        realMainFrame.setCursor(new Cursor(Cursor.WAIT_CURSOR));
        setListeners(MainNormal, false);
        setListeners(defaultsNormal, false);
        try {
            Kadmin.sessionExit();
            Kadmin = null;
        } catch (Exception e) {
            realMainFrame.setCursor(new Cursor(Cursor.DEFAULT_CURSOR));
            showError(e.getMessage());
            return;
        }
        setLoginDefaults();
        principalList = null;
        gui.Prlist.set("items" /* NOI18N */, null);
        policyList = null;
        gui.Pollist.set("items" /* NOI18N */, null);
        gui.mainframe.show(false);
        curPrListPos = 0;
        curPrPattern = "";
        curPoListPos = 0;
        curPoPattern = "";
        
        // Forget this user's print preferences
        PrintUtil.reinitialize();
        
        realMainFrame.setCursor(new Cursor(Cursor.DEFAULT_CURSOR));
    }
    
    public void exit() {
        try {
            if (Kadmin != null)
                Kadmin.sessionExit();
        } catch (Exception e) {}
        super.exit();
    }
    
    /*
     * Methods for the principal list panel
     */
    
    /**
     * Update all principal text fields from gui.
     * Check to see if anyone of them had a parse error.
     * @param nullPasswdOK true if the password can be null. This is
     * allowed only when the operation is a modify on an existing
     * principal or if it is an attempt to print a new principal still
     * in creation.
     * @returns true if all is ok,  false if an error occurs
     */
    // Quits as soon as the first error is detected. The method that
    // detects the error also shows a dialog box with a message.
    public boolean prUpdateFromGui(boolean nullPasswdOK) {
        return (setPrName1() && setPrPassword(nullPasswdOK) && setPrExpiry() &&
		setPrComments() && setPrPwExpiry() && setPrKvno() &&
		setPrMaxlife() && setPrMaxrenew() && setEncType());
    }
    
    /**
     * Is the principal name field editable?
     *
     */
    public void prSetEditable(boolean editable) {
        prnameEditable = editable;
        Boolean b = new Boolean(editable);
        gui.PrName1.set("editable" /* NOI18N */, b);
    }
    
    /**
     * React to a change in the principal search pattern
     *
     */
    public void prPatternComplete() {
        curPrListPos = 0;
        String pattern = (String)gui.PrListPattern.get("text" /* NOI18N */);
        if (!noLists)
            showPrincipalList(pattern);
        else
            setCurPrincipal(pattern);
    }
    
    /**
     * Clear principal search pattern
     *
     */
    public void prPatternClear() {
        if (noLists) {
            gui.PrListPattern.set("text" /* NOI18N */, "");
            ((TextField)gui.PrListPattern.getBody()).requestFocus();
        } else {
            String tempName = CurPrincipal;
            fillPrincipalList("");
            selectPrincipal(tempName);
        }
    }
    
    /**
     * Show the principal list after applying the filter passed in.
     */
    public void showPrincipalList(String pattern) {
        prin = null; // we are not editing a principal
        fillPrincipalList(pattern);
        ModeString = "";
        OpString = "";
        updateStatus();
        gui.cardpanel1.show("List" /* NOI18N */);
        if (noLists)
            ((TextField)gui.PrListPattern.getBody()).requestFocus();
    }
    
    /**
     * Generate the principal list for the first time or after a pattern
     * has been chosen.
     *
     */
    public void fillPrincipalList(String pattern) {
        if (noLists) {
            setCurPrincipal((String)gui.PrListPattern.get("text" /* NOI18N */));
            ((TextField)gui.PrListPattern.getBody()).requestFocus();
            disablePrincipalPrinting();
            return;
        }
        realMainFrame.setCursor(new Cursor(Cursor.WAIT_CURSOR));
        pdateStartPlist = new Date();
        // Do we still want to cache the principal list?
        long cachetime = A_LONG_TIME;
        if (!defaults.getStaticLists())
            cachetime = defaults.getCacheTime() * 1000;
        if (principalList != null
	    && ((new Date()).getTime() - principalListDate.getTime())
	    <= cachetime) {
            
            // Has the pattern changed?
            if (pattern.compareTo(curPrPattern) != 0)
                newPrPattern(pattern);
            realMainFrame.setCursor(new Cursor(Cursor.DEFAULT_CURSOR));
            selectPrincipal(curPrListPos);
            return;
            
        }
        PrincipalList p = new PrincipalList(Kadmin);
        gui.StatusLine.set("text" /* NOI18N */,
			   getString("Loading principal list"));
        try {
            principalList = p.getPrincipalList(CurRealm);
            principalListDate = new Date();
        } catch (Exception e) {
            realMainFrame.setCursor(new Cursor(Cursor.DEFAULT_CURSOR));
            showError(e.getMessage());
            updateStatus();
            return;
        }
        updateStatus();
        pdateHavePlist = new Date();
        reportTime("Fetched Plist  : ", pdateHavePlist, pdateStartPlist);
        newPrPattern(pattern);
        selectPrincipal(curPrListPos);
        realMainFrame.setCursor(new Cursor(Cursor.DEFAULT_CURSOR));
        pdateDonePlist = new Date();
        reportTime("Completed Plist: ", pdateDonePlist, pdateHavePlist);
        if (perfmon)
            System.out.println("Principal list has "
	       +(new Integer(principalList.length)).toString()+" items");
    }
    
    private void newPrPattern(String pattern) {
        curPrPattern = pattern;
        gui.PrListPattern.set("text" /* NOI18N */, pattern);
        refreshPrincipalList();
    }
    
    private void refreshPrincipalList() {
        if (noLists)
            return;
        Filter f = new Filter(principalList, curPrPattern);
        gui.Prlist.set("items" /* NOI18N */, f.out);
    }
    
    private void selectPrincipal(int pos) {
        TextList list = (TextList)gui.Prlist.getBody();
        if (list.countItems() == 0) {
            setCurPrincipal("");
            return;
        }
        
        if (pos < 0)
            pos = 0;
        else if (pos >= list.countItems())
            pos = list.countItems() - 1;
        
        list.select(pos);
        enablePrincipalPrinting();
        list.makeVisible(pos);
        setCurPrincipal(list.getItem(pos));
    }
    
    private void selectPrincipal(String name) {
        String[] list = getItemsFromTextList(((TextList)gui.Prlist.getBody()));
        selectPrincipal(search(list, name));
    }
    
    private String[] getItemsFromTextList(TextList list) {
        StringVector v = list.items();
        String [] ret = new String[v.size()];
        v.copyInto(ret);
        return ret;
    }
    
    /**
     * Find index where "name" might go in a sorted string array;
     * returns either the element which matches "name" exactly
     * or the element just lexographically greater than "name".
     */
    private int search(String[] array, String name) {
        int lo = 0;
        int hi = array.length;
        int mid = hi;
        while (lo < hi) {
            mid = (lo + hi) / 2;
            int cmp = name.concat("@").compareTo(array[mid].concat("@"));
            if (hi - lo == 1) {
                if (cmp > 0)
                    mid = hi;
                break;
            }
            if (cmp == 0)
                break;
            if (cmp < 0)
                hi = mid;
            else if (cmp > 0)
                lo = mid;
        }
        return mid;
    }
    
    private String[] addToList(String[] list, String name) {
        if (list == null)
            return null;
        int index = search(list, name);
        int rem = list.length - index;
        String[] newlist = new String[list.length+1];
        if (index > 0)
            System.arraycopy(list, 0, newlist, 0, index);
        newlist[index] = name;
        if (rem > 0)
            System.arraycopy(list, index, newlist, index+1, rem);
        return newlist;
    }
    
    private String[] delFromList(String[] list, String name) {
        if (list == null)
            return null;
        int index = search(list, name);
        int rem = list.length - index;
        String[] newlist = new String[list.length-1];
        if (index > 0)
            System.arraycopy(list, 0, newlist, 0, index);
        if (rem > 1)
            System.arraycopy(list, index+1, newlist, index, rem-1);
        return newlist;
    }
    
    /**
     * Collect the policy choice entries
     *
     */
    public void setPolicyChoice() {
        String[] pols = null;
        if (!noLists) {
            PolicyList p = new PolicyList(Kadmin);
            try {
                pols = p.getPolicyList();
            } catch (Exception e) {
                showError(e.getMessage());
                return;
            }
        }
        Choice c = (Choice)gui.PrPolicy.getBody();
        c.removeAll();
        c.add(getString("(no policy)"));
        for (int i = 0; pols != null && i < pols.length; i++)
            c.add(pols[i]);
    }
    
    /**
     * Look at the principal list to see what's selected
     *
     */
    public void lookAtPrList() {
        if (noLists)
            return;
        TextList list = (TextList) gui.Prlist.getBody();
        prMulti = null;
        String[] sel = list.getSelectedItems();
        if (sel.length == 1) {
            setCurPrincipal(sel[0]);
            curPrListPos = list.getSelectedIndex();
        } else {
            if (sel.length > 0)
                prMulti = sel;
            setCurPrincipal("");
        }
    }
    
    private void restorePrListSelection() {
        if (noLists)
            return;
        TextList list = (TextList) gui.Prlist.getBody();
        list.select(curPrListPos);
    }
    
    /**
     * When the principal name choice changes, we want to reflect
     * the name in the other principal tabs.  We can also use this
     * opportunity to enable/disable buttons.
     *
     */
    public void setCurPrincipal(String name) {
        CurPrincipal = name;
        gui.PrName1.set("text" /* NOI18N */, name);
        gui.PrName2.set("text" /* NOI18N */, name);
        gui.PrName3.set("text" /* NOI18N */, name);
        if (name.compareTo("") == 0) {
            prSelValid(false);
            return;
        }
        prSelValid(true);
    }
    
    /**
     * Make Modify, Delete and Duplicate buttons react to what is selected.
     * Privileges:
     * If we have neither modify or inquire, we keep Modify disabled;
     * if we have no modify privileges, we permit Modify to see info,
     * but the principal panel components are disabled in reactToPrivs().
     * If we have add and inquire privileges, we can permit Duplicate;
     * no add also means Create New is permanently disabled in reactToPrivs().
     * If we have no delete privileges, we keep Delete disabled.
     */
    public void prSelValid(boolean selected) {
        prSelValid = selected;
        Boolean b = new Boolean(selected && (privs & PRIV_INQUIRE) != 0);
        gui.PrListModify.set("enabled" /* NOI18N */, b);
        int want = (PRIV_ADD | PRIV_INQUIRE);
        b = new Boolean(selected && (privs & want) == want);
        gui.PrListDuplicate.set("enabled" /* NOI18N */, b);
        b = new Boolean((selected || prMulti != null)
			&&(privs & PRIV_DELETE) != 0);
        gui.PrListDelete.set("enabled" /* NOI18N */, b);
    }
    
    /**
     * Make the Save button do the right thing.
     *
     */
    public void prSetCanSave(boolean ok) {
        Boolean b = new Boolean(ok);
        gui.PrBasicSave.set("enabled" /* NOI18N */, b);
        gui.PrDetailSave.set("enabled" /* NOI18N */, b);
        gui.PrFlagsSave.set("enabled" /* NOI18N */, b);
    }
    
    /**
     * Update status line with current information.
     *
     */
    public void updateStatus() {
        gui.StatusLine.set("text" /* NOI18N */, ModeString+OpString+SaveString);
    }
    
    /**
     * This is a way for the data modification actions to note that
     * the principal has edits outstanding.
     *
     */
    public void prSetNeedSave() {
        prNeedSave = true;
        prSetCanSave(true);
        SaveString = getString("- *CHANGES*");
        updateStatus();
    }
    
    public boolean prDoSave() {
        
        // before attempting to save make sure all text fields are in order
        if (prUpdateFromGui(!prin.isNew) == false)
            return false;
        
        boolean b = true;
        realMainFrame.setCursor(new Cursor(Cursor.WAIT_CURSOR));
        try {
            b = prin.savePrincipal();
        } catch (Exception e) {
            b = false;
            showError(e.getMessage());
        }
        realMainFrame.setCursor(new Cursor(Cursor.DEFAULT_CURSOR));
        if (!b)
            return false;
        if (prin.isNew) {
            principalList = addToList(principalList, prin.PrName);
            refreshPrincipalList();
            selectPrincipal(prin.PrName);
        }
        prin.isNew = false;
        gui.PrPassword.set("text" /* NOI18N */, "");
        prin.setPassword("");
        prSetEditable(false);
        prSetCanSave(false);
        prNeedSave = false;
        SaveString = "";
        updateStatus();
        return true;
    }
    
    /**
     * React to a choice from the principal list via double-click or
     * single-click+Modify; we want to go to the next tab in each case.
     * If we don't have modify privileges, we need to simply show values.
     */
    public void prModify() {
        enablePrincipalPrinting();
        if (!prNeedSave) {
            prSetEditable(false);
            prSetCanSave(false);
        }
        if (noLists)
            CurPrincipal = (String)gui.PrListPattern.get("text" /* NOI18N */);
        realMainFrame.setCursor(new Cursor(Cursor.WAIT_CURSOR));
        enablePrAttributes(new Boolean((privs & (PRIV_ADD|PRIV_MODIFY)) != 0));
        Boolean b = new Boolean((privs & PRIV_CHANGEPW) != 0);
        gui.PrPassword.set("enabled" /* NOI18N */, b);
        gui.PrBasicRandomPw.set("enabled" /* NOI18N */, b);
        gui.EncList.set("enabled" /* NOI18N */, b);
        try {
            prin = new Principal(Kadmin, CurPrincipal);
        } catch (Exception e) {
            showError(e.getMessage());
            realMainFrame.setCursor(new Cursor(Cursor.DEFAULT_CURSOR));
            return;
        }
        realMainFrame.setCursor(new Cursor(Cursor.DEFAULT_CURSOR));
        showPrincipal(prin);
        String policy = (String)gui.PrPolicy.get("selectedItem" /* NOI18N */);
        if (policy.compareTo(getString("(no policy)")) == 0)
            policy = "";
        else
            setDefaultPolicy(policy);
        ModeString = getString("Modify")+" ";
        OpString = getString("Principal");
        updateStatus();
        gui.cardpanel1.show("Basics" /* NOI18N */);
    }
    
    /**
     * React to add principal button
     * If we got here, we need to enable attributes since we have privs.
     */
    public void prAdd() {
        enablePrincipalPrinting();
        setCurPrincipal("");
        prSelValid = true;
        prSetEditable(true);
        prSetNeedSave();
        realMainFrame.setCursor(new Cursor(Cursor.WAIT_CURSOR));
        Boolean b = new Boolean(true);
        enablePrAttributes(b);
        gui.PrPassword.set("enabled" /* NOI18N */, b);
        gui.PrBasicRandomPw.set("enabled" /* NOI18N */, b);
        gui.EncList.set("enabled" /* NOI18N */, b);
        try {
            prin = new Principal(Kadmin, defaults);
        } catch (Exception e) {
            showError(e.getMessage());
            realMainFrame.setCursor(new Cursor(Cursor.DEFAULT_CURSOR));
            return;
        }
        realMainFrame.setCursor(new Cursor(Cursor.DEFAULT_CURSOR));
        showPrincipal(prin);
        ModeString = getString("Create New")+" ";
        OpString = getString("Principal");
        updateStatus();
        gui.cardpanel1.show("Basics" /* NOI18N */);
        ((TextField)gui.PrName1.getBody()).requestFocus();
    }
    
    /**
     * React to duplicate principal button
     *
     */
    public void prDuplicate() {
        enablePrincipalPrinting();
        if (noLists)
            CurPrincipal = (String)gui.PrListPattern.get("text" /* NOI18N */);
        realMainFrame.setCursor(new Cursor(Cursor.WAIT_CURSOR));
        try {
            prin = new Principal(Kadmin, CurPrincipal);
        } catch (Exception e) {
            showError(e.getMessage());
            realMainFrame.setCursor(new Cursor(Cursor.DEFAULT_CURSOR));
            return;
        }
        realMainFrame.setCursor(new Cursor(Cursor.DEFAULT_CURSOR));
        setCurPrincipal("");
        prSelValid = true;
        prSetEditable(true);
        prSetNeedSave();
        realMainFrame.setCursor(new Cursor(Cursor.WAIT_CURSOR));
        Boolean b = new Boolean(true);
        enablePrAttributes(b);
        gui.PrPassword.set("enabled" /* NOI18N */, b);
        gui.PrBasicRandomPw.set("enabled" /* NOI18N */, b);
        gui.PrBasicRandomPw.set("enabled" /* NOI18N */, b);
        try {
            prin = new Principal(Kadmin, prin);
        } catch (Exception e) {
            showError(e.getMessage());
            realMainFrame.setCursor(new Cursor(Cursor.DEFAULT_CURSOR));
            return;
        }
        realMainFrame.setCursor(new Cursor(Cursor.DEFAULT_CURSOR));
        prin.PrName = "";
        showPrincipal(prin);
        ModeString = getString("Duplicate")+" ";
        OpString = getString("Principal");
        updateStatus();
        gui.cardpanel1.show("Basics" /* NOI18N */);
        ((TextField)gui.PrName1.getBody()).requestFocus();
    }
    
    /**
     * React to delete principal button
     */
    public void prDelete() {
        String text[] = {getString("You are about to destroy data."),
			 getString("Click OK to proceed or"
				   +" Cancel to continue editing.")};
        String resp = confirmAction(realMainFrame, text);
        if (resp.equals(getString("Cancel")))
            return;
        if (noLists)
            CurPrincipal = (String)gui.PrListPattern.get("text" /* NOI18N */);
        boolean b = false;
        try {
            b = Kadmin.deletePrincipal(CurPrincipal);
        } catch (Exception e) {
            showError(e.getMessage());
            return;
        }
        if (!b)
            return;
        principalList = delFromList(principalList, CurPrincipal);
        refreshPrincipalList();
        setCurPrincipal("");
        prSelValid = true;
        prSetEditable(true);
        if (curPrListPos == ((TextList)gui.Prlist.getBody()).countItems())
            curPrListPos--;
        showPrincipalList(curPrPattern);
    }
    
    /**
     * React to Previous button on basic screen
     *
     */
    public void prBasicPrevious() {
        prCancel();
    }
    
    /**
     * React to Next button on basic screen. If some changes were made
     * then check to see if they contain a parse error. If so, do
     * nothing. The method that checks for error messages also displays
     * the error message.
     *
     */
    public void prBasicNext() {
        if (prNeedSave)
            if (!prUpdateFromGui(!prin.isNew))
		return;
        
        updateStatus();
        gui.cardpanel1.show("Details" /* NOI18N */);
    }
    
    /**
     * React to Previous button on detail screen. If some changes were made
     * then check to see if they contain a parse error. If so, do
     * nothing. The method that checks for error messages also displays
     * the error message.
     */
    public void prDetailPrevious() {
        if (prNeedSave)
            if (!prUpdateFromGui(!prin.isNew))
		return;
        
        updateStatus();
        gui.cardpanel1.show("Basics" /* NOI18N */);
    }
    
    /**
     * React to Next button on detail screen. If some changes were made
     * then check to see if they contain a parse error. If so, do
     * nothing. The method that checks for error messages also displays
     * the error message.
     *
     */
    public void prDetailNext() {
        if (prNeedSave)
            if (!prUpdateFromGui(!prin.isNew))
		return;
        
        updateStatus();
        gui.cardpanel1.show("Flags" /* NOI18N */);
    }
    
    /**
     * React to Previous button on flags screen
     *
     */
    public void prFlagsPrevious() {
        updateStatus();
        gui.cardpanel1.show("Details" /* NOI18N */);
    }
    
    /**
     * React to Done button on flags screen. If any changes were made to
     * the principal, then try to save them. If the save fails for any
     * reason, do not return to the principal list.
     *
     */
    public void prFlagsDone() {
        if (prNeedSave && prDoSave() == false)
            return;
        showPrincipalList(curPrPattern);
    }
    
    /**
     * React to save principal button
     *
     */
    public void prSave() {
        prDoSave();
    }
    
    /**
     * React to cancel principal button
     *
     */
    public void prCancel() {
        if (prNeedSave) {
            String text[] = {getString("You are about to lose changes."),
			     getString("Click Save to commit changes, "
				       +"Discard to discard changes, "
				       +"or Cancel to continue editing.")};
            String resp = confirmSave(realMainFrame, text);
            if (resp.equals(getString("Cancel")))
                return;
            if (resp.equals(getString("Save")))
                if (!prDoSave())
		    return;
        }
        prSetEditable(false);
        prSetCanSave(false);
        prNeedSave = false;
        lookAtPrList();
        SaveString = "";
        showPrincipalList(curPrPattern);
    }
    
    /*
     * Methods for the principal attribute panels
     */
    
    public boolean setPrName1() {
        if (!prnameEditable)
            return true;
        
        String p = ((String)gui.PrName1.get("text" /* NOI18N */)).trim();
        if (p.compareTo("") == 0) {
            showError(getString("Please enter a principal name or cancel"));
            ((TextField)gui.PrName1.getBody()).requestFocus();
            return false;
        }
        // visually delete any white space that was at the start or end
        // by resetting the field to the trimmmed String.
        gui.PrName1.set("text" /* NOI18N */, p);
        setCurPrincipal(p);
        prin.setName(p);
        return true;
    }
    
    public boolean setPrComments() {
        prin.setComments((String)gui.PrComments.get("text" /* NOI18N */));
        return true;
    }
    
    public boolean setEncType() {
        if (prin.setEncType((String)gui.EncList.get("text" /* NOI18N */))) {
            // visually delete any extraneous data that was ignored in the
            // parsing by resetting the gui data
            gui.EncList.set("text" /* NOI18N */,  prin.getEncType());
            return true;
        } else
            return false;
    }

    public boolean setPrExpiry() {
        if (prin.setExpiry((String)gui.PrExpiry.get("text" /* NOI18N */))) {
            // visually delete any extraneous data that was ignored in the
            // parsing by resetting the gui data
            gui.PrExpiry.set("text" /* NOI18N */,  prin.getExpiry());
            return true;
        } else {
            showDataFormatError(((TextField)gui.PrExpiry.getBody()),
				DATE_DATA);
            return false;
        }
    }
    
    public boolean setPrPassword(boolean nullOK) {
        String p = (String)gui.PrPassword.get("text" /* NOI18N */);
        if (p.compareTo("") == 0) {
            if (!nullOK) {
                showError(getString("Please enter a password or cancel"));
                ((TextField)gui.PrPassword.getBody()).requestFocus();
                return false;
            } else return true;
	}
        
        prin.setPassword(p);
        return true;
    }
    
    public void genRandomPassword() {
        int n, count = 0;
        byte[] buf = new byte[20];
        byte b;
        Random r = new Random();
        String passlist = "abcdefghijklmnopqrstuvwxyz1234567890!#$%&*+@"
	    /* NOI18N */;
        
        gui.PrPassword.set("text" /* NOI18N */, "");
        while (count < 10) {
            n = r.nextInt() & 0x7F;
            b = (byte)n;
            if (passlist.indexOf(b) == -1)
                continue;
            buf[count++] = b;
        }
        buf[count] = 0;
        CurPass = new String(buf);
        gui.PrPassword.set("text" /* NOI18N */, CurPass);
        prin.setPassword((String)gui.PrPassword.get("text" /* NOI18N */));
    }
    
    public void setPrPolicy() {
        if (prin == null)
                return;
        String policy = (String)gui.PrPolicy.get("selectedItem" /* NOI18N */);
        if (policy.compareTo(getString("(no policy)")) == 0)
            policy = "";
        try {
                prin.setPolicy(policy);
        } catch (Exception e) {};
        setDefaultPolicy(policy);
    }
    
    public boolean setPrMaxlife() {
        if (prin.setMaxlife((String)gui.PrMaxLifetime.get("text"
							  /* NOI18N */))) {
            // visually delete any extraneous data that was ignored in the
            // parsing by resetting the gui data
            gui.PrMaxLifetime.set("text" /* NOI18N */, prin.getMaxLife());
            return true;
        } else {
            showDataFormatError(((TextField)gui.PrMaxLifetime.getBody()),
				DURATION_DATA);
            return false;
        }
    }
    
    public boolean setPrMaxrenew() {
        if (prin.setMaxrenew((String)gui.PrMaxRenewal.get(
						  "text" /* NOI18N */))) {
            // visually delete any extraneous data that was ignored in the
            // parsing  by resetting the gui data
            gui.PrMaxRenewal.set("text" /* NOI18N */, prin.getMaxRenew());
            return true;
        } else {
            showDataFormatError(((TextField)gui.PrMaxRenewal.getBody()),
				DURATION_DATA);
            return false;
        }
    }
    
    public boolean setPrKvno() {
        if (prin.setKvno((String)gui.PrKvno.get("text" /* NOI18N */))) {
            // visually delete any extraneous data that was ignored in the
            // parsing by resetting the gui data
            gui.PrKvno.set("text" /* NOI18N */, nf.format(prin.Kvno));
            return true;
        } else {
            showDataFormatError(((TextField)gui.PrKvno.getBody()), NUMBER_DATA);
            return false;
        }
    }
    
    public boolean setPrPwExpiry() {
        if (prin.setPwExpiry((String)gui.PrPwExpiry.get("text" /* NOI18N */))) {
            // visually delete any extraneous data that was ignored in the
            // parsing by resetting the gui data
            gui.PrPwExpiry.set("text" /* NOI18N */, prin.getPwExpireTime());
            return true;
        } else {
            showDataFormatError(((TextField)gui.PrPwExpiry.getBody()),
				DATE_DATA);
            return false;
        }
    }
    
    public void setPrFlag(int bitmask) {
        prin.flags.toggleFlags(bitmask);
    }
    
    /**
     * Update components to reflect data in this principal
     *
     */
    public void showPrincipal(Principal p) {
        
        gui.PrName1.set("text" /* NOI18N */, p.PrName);
        gui.PrName2.set("text" /* NOI18N */, p.PrName);
        gui.PrName3.set("text" /* NOI18N */, p.PrName);
        gui.PrComments.set("text" /* NOI18N */, p.Comments);
        String policy = p.Policy;
        if (policy.compareTo("") == 0)
            policy = getString("(no policy)");
        gui.PrPolicy.set("selectedItem" /* NOI18N */, policy);
        gui.PrPassword.set("text" /* NOI18N */, "");
        
        gui.PrLastChangedTime.set("text" /* NOI18N */, p.getModTime());
        gui.PrLastChangedBy.set("text" /* NOI18N */,   p.ModName);
        gui.PrExpiry.set("text" /* NOI18N */,          p.getExpiry());
        gui.EncList.set("text" /* NOI18N */,           p.getEncType());
        gui.PrLastSuccess.set("text" /* NOI18N */,     p.getLastSuccess());
        gui.PrLastFailure.set("text" /* NOI18N */,     p.getLastFailure());
        gui.PrFailCount.set("text" /* NOI18N */, nf.format(p.NumFailures));
        gui.PrLastPwChange.set("text" /* NOI18N */,    p.getLastPwChange());
        gui.PrPwExpiry.set("text" /* NOI18N */,        p.getPwExpireTime());
        gui.PrKvno.set("text" /* NOI18N */, nf.format(p.Kvno));
        gui.PrMaxLifetime.set("text" /* NOI18N */, p.getMaxLife());
        gui.PrMaxRenewal.set("text" /* NOI18N */, p.getMaxRenew());
        
        gui.PrLockAcct.set("state" /* NOI18N */,
		   new Boolean(p.flags.getFlag(Flags.DISALLOW_ALL_TIX)));
        gui.PrForcePwChange.set("state" /* NOI18N */,
			new Boolean(p.flags.getFlag(Flags.REQUIRES_PWCHANGE)));
        gui.PrAllowPostdated.set("state" /* NOI18N */,
		 new Boolean(!p.flags.getFlag(Flags.DISALLOW_POSTDATED)));
        gui.PrAllowForwardable.set("state" /* NOI18N */,
		   new Boolean(!p.flags.getFlag(Flags.DISALLOW_FORWARDABLE)));
        gui.PrAllowRenewable.set("state" /* NOI18N */,
		 new Boolean(!p.flags.getFlag(Flags.DISALLOW_RENEWABLE)));
        gui.PrAllowProxiable.set("state" /* NOI18N */,
		 new Boolean(!p.flags.getFlag(Flags.DISALLOW_PROXIABLE)));
        gui.PrAllowSvr.set("state" /* NOI18N */,
			   new Boolean(!p.flags.getFlag(Flags.DISALLOW_SVR)));
        gui.PrAllowTGT.set("state" /* NOI18N */,
		   new Boolean(!p.flags.getFlag(Flags.DISALLOW_TGT_BASED)));
        gui.PrAllowDupAuth.set("state" /* NOI18N */,
		       new Boolean(!p.flags.getFlag(Flags.DISALLOW_DUP_SKEY)));
        gui.PrRequirePreAuth.set("state" /* NOI18N */,
			 new Boolean(p.flags.getFlag(Flags.REQUIRE_PRE_AUTH)));
        gui.PrRequireHwPreAuth.set("state" /* NOI18N */,
			   new Boolean(p.flags.getFlag(Flags.REQUIRE_HW_AUTH)));
    }
    
    /**
     * Format a time duration for printing, using I18N formats
     *
     */
    public String showDuration(Integer seconds) {
        return nf.format(seconds.longValue());
    }
    
    /*
     * Methods for the policy list panel
     */
    
    /**
     * Update all policy text fields from gui.
     * Check to see if anyone of them had a parse error.
     * @returns true if all is ok,  false if an error occurs
     */
    // Quits as soon as the first error is detected. The method that
    // detects the error also shows a dialog box with a message.
    public boolean poUpdateFromGui() {
        return (setPolName() && setPolMinlife() && setPolMaxlife());
    }
    
    /**
     * If we have edited a principal, select their policy by default
     *
     */
    public void setDefaultPolicy(String name) {
        setCurPolicy(name);
        fillPolicyList("");
        TextList l = (TextList)gui.Pollist.getBody();
        int itemcount = l.countItems();
        for (int i = 0; i < itemcount; i++)
            if (l.getItem(i).compareTo(name) == 0) {
		curPoListPos = i;
		break;
	    }
    }
    
    /**
     * Is the policy name field editable?
     *
     */
    public void poSetEditable(boolean editable) {
        ponameEditable = editable;
        Boolean b = new Boolean(editable);
        gui.PoName.set("editable" /* NOI18N */, b);
    }
    
    /**
     * React to a change in the policy list pattern
     *
     */
    public void poPatternComplete() {
        curPoListPos = 0;
        String pattern = (String)gui.PoListPattern.get("text" /* NOI18N */);
        if (!noLists)
            showPolicyList(pattern);
        else
            setCurPolicy(pattern);
    }
    
    /**
     * Clear policy list pattern
     *
     */
    public void poPatternClear() {
        if (noLists) {
            gui.PoListPattern.set("text" /* NOI18N */, "");
            ((TextField)gui.PoListPattern.getBody()).requestFocus();
        } else {
            String tempName = CurPolicy;
            fillPolicyList("");
            selectPolicy(tempName);
        }
    }
    
    /**
     * Show the policy list after applying the filter passed in.
     */
    public void showPolicyList(String pattern) {
        pol = null; // we are not editing a policy
        fillPolicyList(pattern);
        ModeString = "";
        OpString = "";
        updateStatus();
        gui.cardpanel2.show("List" /* NOI18N */);
        if (noLists)
            ((TextField)gui.PoListPattern.getBody()).requestFocus();
    }
    
    /**
     * Generate the policy list for the first time or after a pattern
     * has been chosen.
     *
     */
    public void fillPolicyList(String pattern) {
        if (noLists) {
            setCurPolicy((String)gui.PoListPattern.get("text" /* NOI18N */));
            ((TextField)gui.PoListPattern.getBody()).requestFocus();
            disablePolicyPrinting();
            return;
        }
        realMainFrame.setCursor(new Cursor(Cursor.WAIT_CURSOR));
        long cachetime = A_LONG_TIME;
        if (!defaults.getStaticLists())
            cachetime = defaults.getCacheTime() * 1000;
        if (policyList != null
	    && ((new Date()).getTime() - policyListDate.getTime())
	    <= cachetime) {
            if (pattern.compareTo(curPoPattern) != 0)
                newPoPattern(pattern);
            realMainFrame.setCursor(new Cursor(Cursor.DEFAULT_CURSOR));
            selectPolicy(curPoListPos);
            return;
        }
        PolicyList p = new PolicyList(Kadmin);
        gui.StatusLine.set("text" /* NOI18N */,
			   getString("Loading policy list"));
        try {
            policyList = p.getPolicyList();
            policyListDate = new Date();
        } catch (Exception e) {
            realMainFrame.setCursor(new Cursor(Cursor.DEFAULT_CURSOR));
            showError(e.getMessage());
            updateStatus();
            return;
        }
        updateStatus();
        newPoPattern(pattern);
        selectPolicy(curPoListPos);
        realMainFrame.setCursor(new Cursor(Cursor.DEFAULT_CURSOR));
    }
    
    private void newPoPattern(String pattern) {
        curPoPattern = pattern;
        gui.PoListPattern.set("text" /* NOI18N */, pattern);
        refreshPolicyList();
    }
    
    private void refreshPolicyList() {
        if (noLists)
            return;
        Filter f = new Filter(policyList, curPoPattern);
        gui.Pollist.set("items" /* NOI18N */, f.out);
    }
    
    private void selectPolicy(int pos) {
        TextList list = (TextList)gui.Pollist.getBody();
        if (list.countItems() == 0) {
            setCurPolicy("");
            return;
        }
        
        if (pos < 0)
            pos = 0;
        else if (pos >= list.countItems())
            pos = list.countItems() - 1;
        
        list.select(pos);
        enablePolicyPrinting();
        list.makeVisible(pos);
        setCurPolicy(list.getItem(pos));
    }
    
    private void selectPolicy(String name) {
        String[] list = getItemsFromTextList((TextList)gui.Pollist.getBody());
        selectPolicy(search(list, name));
    }
    
    /**
     * When the policy name choice changes, we want to reflect
     * the name in the policy detail tab.
     *
     */
    public void setCurPolicy(String name) {
        CurPolicy = name;
        gui.PoName.set("text" /* NOI18N */, CurPolicy);
        if (name.compareTo("") == 0) {
            poSelValid(false);
            return;
        }
        poSelValid(true);
    }
    
    /**
     * Look at the policy list to see what's selected
     *
     */
    public void lookAtPoList() {
        if (noLists)
            return;
        TextList list = (TextList) gui.Pollist.getBody();
        poMulti = null;
        String[] sel = list.getSelectedItems();
        if (sel.length == 1) {
            setCurPolicy(sel[0]);
            curPoListPos = list.getSelectedIndex();
        } else {
            if (sel.length > 0)
                poMulti = sel;
            setCurPolicy("");
        }
    }
    
    private void restorePoListSelection() {
        if (noLists)
            return;
        TextList list = (TextList) gui.Pollist.getBody();
        list.select(curPoListPos);
    }
    
    /**
     * Make Modify, Delete and Duplicate buttons react to what is selected.
     *
     */
    public void poSelValid(boolean selected) {
        poSelValid = selected;
        Boolean b = new Boolean(selected && (privs & PRIV_INQUIRE) != 0);
        gui.PoListModify.set("enabled" /* NOI18N */, b);
        int want = (PRIV_ADD | PRIV_INQUIRE);
        b = new Boolean(selected && (privs & want) == want);
        gui.PoListDuplicate.set("enabled" /* NOI18N */, b);
        b = new Boolean((selected || poMulti != null)
			&&(privs & PRIV_DELETE) != 0);
        gui.PoListDelete.set("enabled" /* NOI18N */, b);
    }
    
    /**
     * Make the Save button do the right thing.
     *
     */
    public void poSetCanSave(boolean ok) {
        Boolean b = new Boolean(ok);
        gui.PoDetailSave.set("enabled"  /* NOI18N */, b);
    }
    
    /**
     * This is a way for the data modification actions to note that
     * the principal has edits outstanding.
     *
     */
    public void poSetNeedSave() {
        poNeedSave = true;
        poSetCanSave(true);
        SaveString = getString("- *CHANGES*");
        updateStatus();
    }
    
    public boolean poDoSave() {
        
        // before attempting to save make sure all text fields are in order
        if (poUpdateFromGui() == false)
            return false;
        
        boolean b = true;
        realMainFrame.setCursor(new Cursor(Cursor.WAIT_CURSOR));
        try {
            b = pol.savePolicy();
        } catch (Exception e) {
            b = false;
            showError(e.getMessage());
        }
        realMainFrame.setCursor(new Cursor(Cursor.DEFAULT_CURSOR));
        if (!b)
            return false;
        if (pol.isNew) {
            policyList = addToList(policyList, pol.PolicyName);
            refreshPolicyList();
            selectPolicy(pol.PolicyName);
            setPolicyChoice();
        }
        pol.isNew = false;
        poSetEditable(false);
        poSetCanSave(false);
        poNeedSave = false;
        SaveString = "";
        updateStatus();
        return true;
    }
    
    /**
     * React to a choice from the policy list via double-click or
     * single-click+Modify; we want to go to the next tab in each case.
     * If we don't have modify privileges, we need to simply show values.
     */
    public void poSelected() {
        enablePolicyPrinting();
        lookAtPoList();
        if (!poNeedSave) {
            poSetEditable(false);
            poSetCanSave(false);
        }
        if (noLists)
            CurPolicy = (String)gui.PoListPattern.get("text" /* NOI18N */);
        realMainFrame.setCursor(new Cursor(Cursor.WAIT_CURSOR));
        enablePoAttributes(new Boolean((privs & (PRIV_ADD|PRIV_MODIFY)) != 0));
        try {
            pol = new Policy(Kadmin, CurPolicy);
        } catch (Exception e) {
            showError(e.getMessage());
            realMainFrame.setCursor(new Cursor(Cursor.DEFAULT_CURSOR));
            return;
        }
        realMainFrame.setCursor(new Cursor(Cursor.DEFAULT_CURSOR));
        showPolicy(pol);
        ModeString = getString("Modify")+" ";
        OpString = getString("Policy");
        updateStatus();
        gui.cardpanel2.show("Details" /* NOI18N */);
    }
    
    /**
     * React to add policy button
     * If we got here, we need to enable attributes since we have privs.
     */
    public void poAdd() {
        enablePolicyPrinting();
        setCurPolicy("");
        poSelValid = true;
        poSetEditable(true);
        poSetNeedSave();
        enablePoAttributes(new Boolean(true));
        realMainFrame.setCursor(new Cursor(Cursor.WAIT_CURSOR));
        try {
            pol = new Policy(Kadmin);
        } catch (Exception e) {
            showError(e.getMessage());
            realMainFrame.setCursor(new Cursor(Cursor.DEFAULT_CURSOR));
            return;
        }
        realMainFrame.setCursor(new Cursor(Cursor.DEFAULT_CURSOR));
        showPolicy(pol);
        ModeString = getString("Create New")+" ";
        OpString = getString("Policy");
        updateStatus();
        gui.cardpanel2.show("Details" /* NOI18N */);
        ((TextField)gui.PoName.getBody()).requestFocus();
    }
    
    /**
     * React to duplicate policy button
     *
     */
    public void poDuplicate() {
        enablePolicyPrinting();
        if (noLists)
            CurPolicy = (String)gui.PoListPattern.get("text" /* NOI18N */);
        realMainFrame.setCursor(new Cursor(Cursor.WAIT_CURSOR));
        try {
            pol = new Policy(Kadmin, CurPolicy);
        } catch (Exception e) {
            showError(e.getMessage());
            realMainFrame.setCursor(new Cursor(Cursor.DEFAULT_CURSOR));
            return;
        }
        realMainFrame.setCursor(new Cursor(Cursor.DEFAULT_CURSOR));
        setCurPolicy("");
        poSelValid = true;
        poSetEditable(true);
        poSetNeedSave();
        try {
            pol = new Policy(Kadmin, pol);
        } catch (Exception e) {
            showError(e.getMessage());
            return;
        }
        pol.PolicyName = "";
        showPolicy(pol);
        ModeString = getString("Duplicate")+" ";
        OpString = getString("Policy");
        updateStatus();
        gui.cardpanel2.show("Details" /* NOI18N */);
        ((TextField)gui.PoName.getBody()).requestFocus();
    }
    
    /**
     * React to delete policy button
     */
    public void poDelete() {
        String text[] = {getString("You are about to destroy data."),
			 getString("Click OK to proceed or"
				   +" Cancel to continue editing.")};
        String resp = confirmAction(realMainFrame, text);
        if (resp.equals(getString("Cancel")))
            return;
        boolean b;
        if (noLists)
            CurPolicy = (String)gui.PoListPattern.get("text" /* NOI18N */);
        realMainFrame.setCursor(new Cursor(Cursor.WAIT_CURSOR));
        try {
            b = Kadmin.deletePolicy(CurPolicy);
        } catch (Exception e) {
            showError(e.getMessage());
            realMainFrame.setCursor(new Cursor(Cursor.DEFAULT_CURSOR));
            return;
        }
        realMainFrame.setCursor(new Cursor(Cursor.DEFAULT_CURSOR));
        if (!b)
            return;
        policyList = delFromList(policyList, CurPolicy);
        refreshPolicyList();
        setPolicyChoice();
        setCurPolicy("");
        poSelValid = true;
        poSetEditable(true);
        if (curPoListPos == ((TextList)gui.Pollist.getBody()).countItems())
            curPoListPos--;
        showPolicyList(curPoPattern);
    }
    
    /**
     * React to save policy button
     *
     */
    public void poSave() {
        poDoSave();
    }
    
    /**
     * React to cancel policy button
     *
     */
    public void poCancel() {
        if (poNeedSave) {
            String text[] = {getString("You are about to lose changes."),
			     getString("Click Save to commit changes, "
				       +"Discard to discard changes, "
				       +"or Cancel to continue editing.")};
            String resp = confirmSave(realMainFrame, text);
            if (resp.equals(getString("Cancel")))
                return;
            if (resp.equals(getString("Save")))
                if (!poDoSave())
		    return;
        }
        poSetEditable(false);
        poSetCanSave(false);
        poNeedSave = false;
        lookAtPoList();
        SaveString = "";
        showPolicyList(curPoPattern);
    }
    
    /**
     * React to previous button on policy detail screen
     *
     */
    public void polPrevious() {
        poCancel();
    }
    
    /**
     * React to done button on policy detail screen
     *
     */
    public void polDone() {
        if (poNeedSave && poDoSave() == false)
            return;
        showPolicyList(curPoPattern);
    }
    
    /*
     * Methods for the policy details panel
     */
    
    public boolean setPolName() {
        if (!ponameEditable)
            return true;
        
        String p = (String)gui.PoName.get("text" /* NOI18N */);
        if (p.compareTo(getString("(no policy)")) == 0) {
            showError(getString("Policy name already exists. Please choose "
				+"a different policy name or cancel"));
            gui.PoName.set("text" /* NOI18N */, "");
            ((TextField)gui.PoName.getBody()).requestFocus();
            return false;
        }
        if (p.compareTo("") == 0) {
            showError(getString("Please enter a policy name or cancel"));
            ((TextField)gui.PoName.getBody()).requestFocus();
            return false;
        }
        
        setCurPolicy(p);
        pol.setName(p);
        return true;
    }
    
    public void setPolPwLength() {
        if (pol == null)
                return;
        try {
            pol.setPolPwLength((String)gui.PoMinPwLength.get("selectedItem"
							 /* NOI18N */));
        } catch (Exception e) {};
    }
    
    public void setPolPwClasses() {
        if (pol == null)
                return;
        try {
            pol.setPolPwClasses((String)gui.PoMinPwClass.get("selectedItem"
							 /* NOI18N */));
        } catch (Exception e) {};
    }
    
    public void setPolPwHistory() {
        if (pol == null)
                return;
        try {
            pol.setPolPwHistory((String)gui.PoSavedPasswords.get("selectedItem"
							     /* NOI18N */));
        } catch (Exception e) {};
    }
    
    public boolean setPolMinlife() {
        if (pol.setPolMinlife((String)gui.PoMinTicketLifetime.get("text"
							  /* NOI18N */))) {
            // visually delete any extraneous data that was ignored in the
            // parsing by resetting the gui data
            gui.PoMinTicketLifetime.set("text" /* NOI18N */,
					showDuration(pol.PwMinLife));
            return true;
        } else {
            showDataFormatError(((TextField)gui.PoMinTicketLifetime.getBody()),
				DURATION_DATA);
            return false;
        }
    }
    
    public boolean setPolMaxlife() {
        if (pol.setPolMaxlife((String)gui.PoMaxTicketLifetime.get(
						  "text" /* NOI18N */))) {
            // visually delete any extraneous data that was ignored in the
            // parsing by resetting the gui data
            gui.PoMaxTicketLifetime.set("text" /* NOI18N */,
					showDuration(pol.PwMaxLife));
            return true;
        } else {
            showDataFormatError(((TextField)gui.PoMaxTicketLifetime.getBody()),
				DURATION_DATA);
            return false;
        }
    }
    
    /**
     * Update components to reflect data in this policy
     *
     */
    public void showPolicy(Policy p) {
        gui.PoName.set("text" /* NOI18N */, p.PolicyName);
        gui.PoMinPwLength.set("selectedItem" /* NOI18N */,
			      nf.format(p.PwMinLength));
        gui.PoMinPwClass.set("selectedItem" /* NOI18N */,
			     nf.format(p.PwMinClasses));
        gui.PoSavedPasswords.set("selectedItem" /* NOI18N */,
				 nf.format(p.PwSaveCount));
        gui.PoMinTicketLifetime.set("text" /* NOI18N */,
				    showDuration(p.PwMinLife));
        gui.PoMaxTicketLifetime.set("text" /* NOI18N */,
				    showDuration(p.PwMaxLife));
        gui.PoReferences.set("text" /* NOI18N */, nf.format(p.RefCount));
    }
    
    /*
     * Methods for defaults tab
     */
    
    /**
     * React to save button
     *
     */
    public void glSave() {
        if (defaults.updateFromGui()) {
            glDoSave(true);
            glUpdate();
        }
    }
    
    /**
     * React to apply button
     *
     */
    public void glApply() {
        if (defaults.updateFromGui()) {
            glDoSave(false);
            glUpdate();
        }
    }
    
    /**
     * React to cancel button
     *
     */
    public void glCancel() {
        if (glNeedSave) {
            String text[] = {getString("You are about to lose changes."),
			     getString("Click Save to commit changes, "
				       +"Discard to discard changes, "
				       +"or Cancel to continue editing.")};
            String resp = confirmSave(defaultsEditingFrame, text);
            if (resp.equals(getString("Cancel")))
                return;
            if (resp.equals(getString("Discard")))
                defaults.restoreValues(olddefaults);
            if (resp.equals(getString("Save"))) {
                glDoSave(true);
                glUpdate();
                return;
            }
        }
        glDoSave(false);
    }
    
    public void glDoSave(boolean save) {
        defaults.close(save);
        glSetCanSave(false);
        glNeedSave = false;
        SaveString = "";
        updateStatus();
    }
    
    public void glUpdate() {
        noLists = ((privs & PRIV_LIST) == 0 || !defaults.getShowLists());
        fixHelpTags();
        fixListPanels();
        // Load principal list if we are in the principal tab and are not
        // editing a principal
        if (gui.tabbedfolder1.get("currentCard" /* NO18N */) ==
	    getString("Principals") && prin == null)
	    fillPrincipalList(curPrPattern);
        // Load policy list if we are in the policy tab and are not
        // editing a policy
        if (gui.tabbedfolder1.get("currentCard" /* NO18N */) ==
	    getString("Policies") && pol == null)
	    fillPolicyList(curPoPattern);
    }
    
    /**
     * This is a way for the data modification actions to note that
     * the principal has edits outstanding.
     *
     */
    public void glSetNeedSave() {
        glNeedSave = true;
        glSetCanSave(true);
    }
    
    /**
     * Make the Save button do the right thing.
     *
     */
    public void glSetCanSave(boolean ok) {
        defaults.saveButton.setEnabled(ok);
        defaults.applyButton.setEnabled(ok);
    }
    
    public boolean setGlobalMaxrenew() {
        boolean done = defaults.setMaxTicketRenewableLife();
        glSetNeedSave();
        return done;
    }
    
    public boolean setGlobalMaxlife() {
        boolean done = defaults.setMaxTicketLife();
        glSetNeedSave();
        return done;
    }
    
    public boolean setGlobalExpiry() {
        boolean done = defaults.setAccountExpiryDate();
        glSetNeedSave();
        return done;
    }
    
    public boolean setServerSide() {
        boolean done = defaults.setServerSide();
        glSetNeedSave();
        return done;
    }
    
    public boolean setShowLists() {
        boolean done = defaults.setShowLists();
        glSetNeedSave();
        return done;
    }
    
    public boolean setStaticLists() {
        boolean done = defaults.setStaticLists();
        glSetNeedSave();
        return done;
    }
    
    public boolean setCacheTime() {
        boolean done = defaults.setCacheTime();
        glSetNeedSave();
        return done;
    }
    
    public void setGlobalFlag(int bitfield) {
        defaults.toggleFlag(bitfield);
        glSetNeedSave();
    }
    
    /*
     * Miscellany
     */
    public void printPrList() {
        String title = getString("Principal List");
        if (curPrPattern.length() > 0)
            title = title.concat(" (" + getString("Filter Pattern:") + " "
				 + curPrPattern + ")");
        if (principalList == null)
            fillPrincipalList(curPrPattern);
        printList((TextList)gui.Prlist.getBody(), title);
    }
    
    public void printCurPr() {
        Principal toPrint;
        
        if (prin == null) {
            // We are viewing the principal list. Instantiate a new
            // principal using the current name.
            toPrint =  new Principal(Kadmin, CurPrincipal);
        } else {
            // We are in the middle of editing a principal. Update the
            // current principal object with the current contents of the
            // gui. It's ok for the password to be null, we are not printing
            // it anyway.
            if (!prUpdateFromGui(true))
                return;
            toPrint = prin;
        }
        
        PrintUtil.dump(realMainFrame, toPrint);
    }
    
    public void printPoList() {
        String title = getString("Policy List");
        if (curPoPattern.length() > 0)
            title = title.concat(" (" + getString("Filter Pattern:") + " "
				 + curPoPattern + ")");
        if (policyList == null)
            fillPolicyList(curPoPattern);
        printList((TextList)gui.Pollist.getBody(), title);
    }
    
    public void printCurPol() {
        Policy toPrint;
        
        if (pol == null) {
            // We are viewing the policy list. Instantiate a new
            // policy using the current name.
            toPrint = new Policy(Kadmin, CurPolicy);
        } else {
            // We are in the middle of editing a policy. Update the current
            // policy object with the current contents of the gui.
            if (!poUpdateFromGui())
                return;
            toPrint = pol;
        }
        
        PrintUtil.dump(realMainFrame, toPrint);
        
    }
    
    private void printList(TextList guiList, String title) {
        String[] list = getItemsFromTextList(guiList);
        StringBuffer sb = new StringBuffer(title).append('\n');
        
        for (int i = 0; i < list.length; i++) {
            sb.append(list[i]).append('\n');
        }
        
        PrintUtil.dump(realMainFrame, sb);
    }
    
    public void showHelpBrowser(Frame frame) {
        try {
            
            File file = new File("/usr/dt/bin/sdtwebclient");
            if (!file.exists()) {
                showDialog(frame, getString("Error"),
			   getString("Can't run /usr/dt/bin/sdtwebclient."));
                return;
            }
            String url = kc.getHelpURL();
            if (url == null)
                url = helpIndexFile;
            URL help = new URL(url);
            InputStream is = null;
            try {
                is = help.openStream();
            } catch (IOException e) {}
            if (is == null) {
                showDialog(frame, getString("Error"),
			   getString("Invalid URL: ")+url);
                return;
            }
            
            if (browserProcess != null) {
                // Will throw IllegalThreadStateException if thread not exited
                // yet
                int i = browserProcess.exitValue();
            }
            
            // Thread has exited or never existed
            browserProcess =
		Runtime.getRuntime().exec("/usr/dt/bin/sdtwebclient" +url);
            
        } catch (IOException e) {
            showDialog(frame, getString("Error"), e.getMessage());
        } catch (IllegalThreadStateException e) {
            // Ok. All this mean is that a previous instance of the browser
            // exists
        }
    }
    
    private void killHelpBrowser() {
        if (browserProcess != null) {
            browserProcess.destroy();
        }
    }
    
    private void setupDefaultsEditingFrame() {
        defaultsEditingFrame = defaults.getEditingFrame();
        glSetCanSave(false);
        setupDefaultsNormalListeners();
        defaults.csHelp.addActionListener
	    (new DefaultsContextSensitiveHelpListener());
    }
    
    public void editPreferences() {
        olddefaults = new Defaults(defaults);
        defaults.updateGuiComponents();
        defaultsEditingFrame.setVisible(true);
    }
    
    static Frame getFrame(Component c) {
        Frame frame = null;
        
        while ((c = c.getParent()) != null)
            if (c instanceof Frame)
		frame = (Frame)c;
        return frame;
    }
    
    /**
     * General purpose dialog with title and a label settable
     */
    public void showDialog(Frame frame, String title, String text) {
        String[] lines = new String[1];
        lines[0] = text;
        String[] buttons = new String[1];
        buttons[0] = getString("OK");
        ChoiceDialog cd = new ChoiceDialog(frame, title, lines, buttons);
    }
    
    public void showLoginWarning(String err) {
        showDialog(realLoginFrame, getString("Warning"), err);
    }
    
    public void showLoginError(String err) {
        showDialog(realLoginFrame, getString("Error"), err);
    }
    
    public void showWarning(String err) {
        showDialog(realMainFrame, getString("Warning"), err);
    }
    
    public void showError(String err) {
        showDialog(realMainFrame, getString("Error"), err);
    }
    
    public static void showDataFormatError(TextField tf, int dataType) {
        
        Frame parent = getFrame(tf);
        
        tf.selectAll();
        toolkit.beep();
        
        String title = getString("Error");
        
        String[] lines = null;
        String[] buttons = {getString("OK")};
        
        switch (dataType) {
	case DURATION_DATA:
            lines = durationErrorText;
            break;
	case DATE_DATA:
            lines = dateErrorText;
            break;
	case NUMBER_DATA:
            lines = numberErrorText;
            break;
        }
        
        Point p = tf.getLocationOnScreen();
        ChoiceDialog cd = new ChoiceDialog(parent, title, lines,
					   buttons, p.x, p.y);
        
        tf.requestFocus();
        
    }
    
    /**
     * Confirm a destructive user action
     */
    public String confirmAction(Frame frame, String[] text) {
        String title = getString("Confirm Action");
        String[] buttons = new String[2];
        buttons[0] = getString("OK");
        buttons[1] = getString("Cancel");
        ChoiceDialog cd = new ChoiceDialog(frame, title, text, buttons);
        return (cd.getSelection() == null? getString("Cancel")
		:cd.getSelection());
    }
    
    /**
     * Confirm a destructive user action, offering choice of saving
     */
    public String confirmSave(Frame frame, String[] text) {
        String title = getString("Confirm Action");
        String[] buttons = new String[3];
        buttons[0] = getString("Save");
        buttons[1] = getString("Discard");
        buttons[2] = getString("Cancel");
        ChoiceDialog cd = new ChoiceDialog(frame, title, text, buttons);
        return (cd.getSelection() == null? getString("Cancel")
		: cd.getSelection());
    }
    
    /**
     * Show version info
     */
    public void doAbout(Frame frame) {
        String title = getString("About SEAM Adminstration Tool");
        String[] text = new String[7];
        text[0] = getString("Sun Enterprise Authentication"
			    +" Mechanism Administration Tool");
        text[1] = System.getProperty("SEAM_VERS" /* NOI18N */);
        text[2] = getString("Copyright 2005 Sun Microsystems, Inc.  "
				+"All rights reserved.");
        text[3] = getString("Use is subject to license terms.");
        text[4] = System.getProperty("os.name" /* NOI18N */);
        text[5] = System.getProperty("os.arch" /* NOI18N */);
        text[6] = System.getProperty("os.version" /* NOI18N */);
        String[] button = new String[1];
        button[0] = getString("Dismiss");
        ChoiceDialog cd = new ChoiceDialog(frame, title, text, button);
    }
    
    private void getDateTimeFromDialogBox(TextField tf, Frame frame) {
        tf.select(0, 0);
        dateTimeDialog = new DateTimeDialog(frame, tf.getBackground(),
					    tf.getForeground());
        
        if (!tf.getText().equalsIgnoreCase(neverString)) {
            try {
                Date currVal = df.parse(tf.getText());
                dateTimeDialog.setDate(currVal);
                /*
                 * In case an exception occurs, let the dialog box be
                 * initialized to its default date (viz current time).
                 */
            } catch (ParseException e) {
            } catch (NullPointerException e) {
                // gets thrown when parse string begins with text
                // probable JDK bug
            }
            catch (StringIndexOutOfBoundsException e) {
                // gets thrown when parse string contains only one number
                // probable JDK bug
            }
        }
        dateTimeDialog.setVisible(true);
        
        // Modal dialog box so this is after dialog box disappers
        if (dateTimeDialog.isSaved()) {
            tf.setText(dateTimeDialog.toString());
            tf.dispatchEvent(new ActionEvent(tf, ActionEvent.ACTION_PERFORMED,
				     "setFromDateTimeDialog" /* NOI18N */));
        }
    }

    private void getDurationFromDialogBox(TextField tf, Frame frame) {
        tf.select(0, 0);
        durationHelper = new DurationHelper(frame, tf.getBackground(),
					    tf.getForeground());
        durationHelper.setVisible(true);
        
        // Modal dialog box so this is after dialog box disappers
        if (durationHelper.isSaved()) {
            tf.setText(durationHelper.toString());
            tf.dispatchEvent(new ActionEvent(tf, ActionEvent.ACTION_PERFORMED,
				     "setFromDurationHelper" /* NOI18N */));
        }
    }

    private void getEncListFromDialogBox(TextField tf, Frame frame) {
	tf.select(0, 0);
	encListDialog = new EncListDialog(frame, tf.getBackground(),
	    tf.getForeground(), Kadmin);

	encListDialog.setEncTypes(tf.getText());
	encListDialog.setVisible(true);

	// Modal dialog box so this is after dialog box disappers
	if (encListDialog.isSaved()) {
		String e = encListDialog.toString();

		if (e.compareTo("") != 0) {
	    	    String p = (String)gui.PrPassword.get("text" /* NOI18N */);

		    // In order to change the key encryption type(s) the admin
		    // will have to supply a password.
	    	    if (p.compareTo("") == 0) {
			showWarning(getString(
			"If changing the key encryption types then specify a" +
			" new password for the principal whose keys are" +
			" being changed"));
			((TextField)gui.PrPassword.getBody()).requestFocus();
	    	    }
		}  
		tf.setText(e);
		tf.dispatchEvent(new ActionEvent(tf,
		    ActionEvent.ACTION_PERFORMED,
		    "setFromEncListDialog" /* NOI18N */));
	}
    }
    
    /**
     * By going into context-sensitive help mode, normal listeners will
     * be removed and replaced with help listeners, so that help will
     * be shown for the object.
     *
     */
    public void contextHelp(Frame frame) {
        
        if (cHelp == null) {
            cHelp = new ContextHelp(frame, this);
            cHelp.setVisible(true);
        }
        
        if (frame == realLoginFrame)
            setupLoginHelpListeners();
        else if (frame == realMainFrame)
            setupMainHelpListeners();
        else if (frame == defaultsEditingFrame)
            setupDefaultsHelpListeners();
        
        frame.setCursor(new Cursor(Cursor.CROSSHAIR_CURSOR));
    }
    
    
    /**
     * Enables the print menu for printing principal related info.
     */
    private void enablePrincipalPrinting() {
        ((MenuItem)gui.PrintCurPr.getBody()).setEnabled(true);
    }
    
    /**
     * Enables the print menu for printing policy related info.
     */
    private void enablePolicyPrinting() {
        ((MenuItem)gui.PrintCurPol.getBody()).setEnabled(true);
    }
    
    /**
     * Disables the print menu for printing principal related info.
     */
    private void disablePrincipalPrinting() {
        ((MenuItem)gui.PrintCurPr.getBody()).setEnabled(false);
    }
    
    /**
     * Disables the print menu for printing policy related info.
     */
    private void disablePolicyPrinting() {
        ((MenuItem)gui.PrintCurPol.getBody()).setEnabled(false);
    }
    
    /**
     * Set up the listeners for the objects on the login screen in normal mode
     *
     */
    public void setupLoginNormalListeners() {
        if (LoginNormal == null) {
            LoginNormal = new Vector(10, 10);
            ActionListener al;
            Association a;
            Object o;
            
            al = new LoginNameAction();
            o = gui.LoginName.getBody();
            a = new Association(o, al, TEXTFIELD_ACTION);
            LoginNormal.addElement(a);
            
            al = new LoginPassAction();
            o = gui.LoginPass.getBody();
            a = new Association(o, al, TEXTFIELD_ACTION);
            LoginNormal.addElement(a);
            
            al = new LoginRealmAction();
            o = gui.LoginRealm.getBody();
            a = new Association(o, al, TEXTFIELD_ACTION);
            LoginNormal.addElement(a);
            
            al = new LoginServerAction();
            o = gui.LoginServer.getBody();
            a = new Association(o, al, TEXTFIELD_ACTION);
            LoginNormal.addElement(a);
            
            al = new LoginOKAction();
            o = gui.LoginOK.getBody();
            a = new Association(o, al, BUTTON_ACTION);
            LoginNormal.addElement(a);
            
            al = new LoginStartOverAction();
            o = gui.LoginStartOver.getBody();
            a = new Association(o, al, BUTTON_ACTION);
            LoginNormal.addElement(a);
        }
        setListeners(LoginHelp, false);
        setListeners(LoginFixers, false);
        setListeners(LoginNormal, true);
        loginHelpMode = false;
    }
    
    /**
     * Set up the listeners for the objects on the login screen in help mode
     *
     */
    public void setupLoginHelpListeners() {
        if (LoginHelp == null) {
            LoginHelp = new Vector(10, 10);
            MouseListener ml = new HelpListener();
            Association a;
            Object o;
            
            o = gui.LoginName.getBody();
            a = new Association(o, ml, TEXTFIELD_MOUSE);
            LoginHelp.addElement(a);
            ((TextField)o).setName("LoginName" /* NOI18N */);
            
            o = gui.LoginNameLabel.getBody();
            a = new Association(o, ml, LABEL_MOUSE);
            LoginHelp.addElement(a);
            ((Label)o).setName("LoginName" /* NOI18N */);
            
            o = gui.LoginPass.getBody();
            a = new Association(o, ml, TEXTFIELD_MOUSE);
            LoginHelp.addElement(a);
            ((TextField)o).setName("LoginPass" /* NOI18N */);
            
            o = gui.LoginPassLabel.getBody();
            a = new Association(o, ml, LABEL_MOUSE);
            LoginHelp.addElement(a);
            ((Label)o).setName("LoginPass" /* NOI18N */);
            
            o = gui.LoginRealm.getBody();
            a = new Association(o, ml, TEXTFIELD_MOUSE);
            LoginHelp.addElement(a);
            ((TextField)o).setName("LoginRealm" /* NOI18N */);
            
            o = gui.LoginRealmLabel.getBody();
            a = new Association(o, ml, LABEL_MOUSE);
            LoginHelp.addElement(a);
            ((Label)o).setName("LoginRealm" /* NOI18N */);
            
            o = gui.LoginServer.getBody();
            a = new Association(o, ml, TEXTFIELD_MOUSE);
            LoginHelp.addElement(a);
            ((TextField)o).setName("LoginServer" /* NOI18N */);
            
            o = gui.LoginServerLabel.getBody();
            a = new Association(o, ml, LABEL_MOUSE);
            LoginHelp.addElement(a);
            ((Label)o).setName("LoginServer" /* NOI18N */);
            
            o = gui.LoginOK.getBody();
            a = new Association(o, ml, BUTTON_MOUSE);
            LoginHelp.addElement(a);
            ((Button)o).setName("LoginOK" /* NOI18N */);
            
            o = gui.LoginStartOver.getBody();
            a = new Association(o, ml, BUTTON_MOUSE);
            LoginHelp.addElement(a);
            ((Button)o).setName("LoginStartOver" /* NOI18N */);
        }
        setListeners(LoginNormal, false);
        setListeners(LoginHelp, true);
        setupLoginHelpFixers();
        loginHelpMode = true;
    }
    
    public void setupLoginHelpFixers() {
        LoginFixers = new Vector(10, 10);
        Object o;
        Association a;
        TextFixer tf;
        
        o = gui.LoginName.getBody();
        tf = new TextFixer((TextField)o);
        a = new Association(o, tf, TEXTFIELD_KEY);
        LoginFixers.addElement(a);
        
        o = gui.LoginPass.getBody();
        tf = new TextFixer((TextField)o);
        a = new Association(o, tf, TEXTFIELD_KEY);
        LoginFixers.addElement(a);
        
        o = gui.LoginRealm.getBody();
        tf = new TextFixer((TextField)o);
        a = new Association(o, tf, TEXTFIELD_KEY);
        LoginFixers.addElement(a);
        
        o = gui.LoginServer.getBody();
        tf = new TextFixer((TextField)o);
        a = new Association(o, tf, TEXTFIELD_KEY);
        LoginFixers.addElement(a);
        
        setListeners(LoginFixers, true);
    }
    
    /**
     * Set up the listeners for the objects on the main screen in normal mode
     *
     */
    public void setupMainNormalListeners() {
        if (MainNormal == null) {
            Frame fr = realMainFrame;
            MainNormal = new Vector(10, 10);
            ActionListener al;
            ItemListener il;
            DateTimeListener dtl;
            DurationListener dl;
            EncListListener ell;
            KeyListener kl1 = new KeystrokeDetector(PRINCIPAL_EDITING);
            KeyListener kl2 = new KeystrokeDetector(POLICY_EDITING);
            KeyListener kl3 = new KeystrokeDetector(PRINCIPAL_LIST);
            KeyListener kl4 = new KeystrokeDetector(POLICY_LIST);
            Association a;
            Object o;
            
            WindowListener wl = new MainWindowCloseAction();
            o = realMainFrame;
            a = new Association(o, wl, WINDOW_LISTENER);
            MainNormal.addElement(a);
            
            al = new PrListPatternAction();
            o = gui.PrListPattern.getBody();
            a = new Association(o, al, TEXTFIELD_ACTION);
            MainNormal.addElement(a);
            a = new Association(o, kl3, TEXTFIELD_KEY);
            MainNormal.addElement(a);
            
            al = new PrListClearAction();
            o = gui.PrListClear.getBody();
            a = new Association(o, al, BUTTON_ACTION);
            MainNormal.addElement(a);
            
            al = new PrListModifyAction();
            o = gui.PrListModify.getBody();
            a = new Association(o, al, BUTTON_ACTION);
            MainNormal.addElement(a);
            
            al = new PrListAddAction();
            o = gui.PrListAdd.getBody();
            a = new Association(o, al, BUTTON_ACTION);
            MainNormal.addElement(a);
            
            al = new PrListDeleteAction();
            o = gui.PrListDelete.getBody();
            a = new Association(o, al, BUTTON_ACTION);
            MainNormal.addElement(a);
            
            al = new PrListDuplicateAction();
            o = gui.PrListDuplicate.getBody();
            a = new Association(o, al, BUTTON_ACTION);
            MainNormal.addElement(a);
            
            al = new PrSaveAction();
            o = gui.PrBasicSave.getBody();
            a = new Association(o, al, BUTTON_ACTION);
            MainNormal.addElement(a);
            o = gui.PrDetailSave.getBody();
            a = new Association(o, al, BUTTON_ACTION);
            MainNormal.addElement(a);
            o = gui.PrFlagsSave.getBody();
            a = new Association(o, al, BUTTON_ACTION);
            MainNormal.addElement(a);
            
            al = new PrCancelAction();
            o = gui.PrBasicCancel.getBody();
            a = new Association(o, al, BUTTON_ACTION);
            MainNormal.addElement(a);
            o = gui.PrDetailCancel.getBody();
            a = new Association(o, al, BUTTON_ACTION);
            MainNormal.addElement(a);
            o = gui.PrFlagsCancel.getBody();
            a = new Association(o, al, BUTTON_ACTION);
            MainNormal.addElement(a);
            
            al = new PrCommentsAction();
            o = gui.PrComments.getBody();
            a = new Association(o, al, TEXTFIELD_ACTION);
            MainNormal.addElement(a);
            a = new Association(o, kl1, TEXTFIELD_KEY);
            MainNormal.addElement(a);
            
            il = new PrPolicyAction();
            o = gui.PrPolicy.getBody();
            a = new Association(o, il, CHOICE_ITEM);
            MainNormal.addElement(a);
            
            al = new PrPasswordAction();
            o = gui.PrPassword.getBody();
            a = new Association(o, al, TEXTFIELD_ACTION);
            MainNormal.addElement(a);
            a = new Association(o, kl1, TEXTFIELD_KEY);
            MainNormal.addElement(a);
            
            al = new PrRandomPwAction();
            o = gui.PrBasicRandomPw.getBody();
            a = new Association(o, al, BUTTON_ACTION);
            MainNormal.addElement(a);

            al = new EncListAction();
            o = gui.EncList.getBody();
            a = new Association(o, al, TEXTFIELD_ACTION);
            MainNormal.addElement(a);
            a = new Association(o, kl1, TEXTFIELD_KEY);
            MainNormal.addElement(a);
            
            ell = new EncListListener((TextField)gui.EncList.getBody(), fr);
            o = gui.EncListMoreButton.getBody();
            a = new Association(o, ell, BUTTON_ACTION);
            MainNormal.addElement(a);

            al = new PrExpiryAction();
            o = gui.PrExpiry.getBody();
            a = new Association(o, al, TEXTFIELD_ACTION);
            MainNormal.addElement(a);
            a = new Association(o, kl1, TEXTFIELD_KEY);
            MainNormal.addElement(a);
            
            dtl = new DateTimeListener((TextField)gui.PrExpiry.getBody(), fr);
            o = gui.PrExpiryMoreButton.getBody();
            a = new Association(o, dtl, BUTTON_ACTION);
            MainNormal.addElement(a);
            
            al = new PrBasicPreviousAction();
            o = gui.PrBasicPrevious.getBody();
            a = new Association(o, al, BUTTON_ACTION);
            MainNormal.addElement(a);
            
            al = new PrBasicNextAction();
            o = gui.PrBasicNext.getBody();
            a = new Association(o, al, BUTTON_ACTION);
            MainNormal.addElement(a);
            
            al = new PrPwExpiryAction();
            o = gui.PrPwExpiry.getBody();
            a = new Association(o, al, TEXTFIELD_ACTION);
            MainNormal.addElement(a);
            a = new Association(o, kl1, TEXTFIELD_KEY);
            MainNormal.addElement(a);
            
            dtl = new DateTimeListener((TextField)gui.PrPwExpiry.getBody(), fr);
            o = gui.PrPwExpiryMoreButton.getBody();
            a = new Association(o, dtl, BUTTON_ACTION);
            MainNormal.addElement(a);
            
            al = new PrKvnoAction();
            o = gui.PrKvno.getBody();
            a = new Association(o, al, TEXTFIELD_ACTION);
            MainNormal.addElement(a);
            a = new Association(o, kl1, TEXTFIELD_KEY);
            MainNormal.addElement(a);
            
            al = new PrMaxLifetimeAction();
            o = gui.PrMaxLifetime.getBody();
            a = new Association(o, al, TEXTFIELD_ACTION);
            MainNormal.addElement(a);
            a = new Association(o, kl1, TEXTFIELD_KEY);
            MainNormal.addElement(a);
            
            dl = new DurationListener((TextField)gui.PrMaxLifetime.getBody(),
				      fr);
            o = gui.PrMaxLifetimeMoreButton.getBody();
            a = new Association(o, dl, BUTTON_ACTION);
            MainNormal.addElement(a);
            
            al = new PrMaxRenewalAction();
            o = gui.PrMaxRenewal.getBody();
            a = new Association(o, al, TEXTFIELD_ACTION);
            MainNormal.addElement(a);
            a = new Association(o, kl1, TEXTFIELD_KEY);
            MainNormal.addElement(a);
            
            dl = new DurationListener((TextField)gui.PrMaxRenewal.getBody(),
				      fr);
            o = gui.PrMaxRenewalMoreButton.getBody();
            a = new Association(o, dl, BUTTON_ACTION);
            MainNormal.addElement(a);
            
            al = new PrDetailPreviousAction();
            o = gui.PrDetailPrevious.getBody();
            a = new Association(o, al, BUTTON_ACTION);
            MainNormal.addElement(a);
            
            al = new PrDetailNextAction();
            o = gui.PrDetailNext.getBody();
            a = new Association(o, al, BUTTON_ACTION);
            MainNormal.addElement(a);
            
            al = new PrFlagsPreviousAction();
            o = gui.PrFlagsPrevious.getBody();
            a = new Association(o, al, BUTTON_ACTION);
            MainNormal.addElement(a);
            
            al = new PrFlagsNextAction();
            o = gui.PrFlagsNext.getBody();
            a = new Association(o, al, BUTTON_ACTION);
            MainNormal.addElement(a);
            
            il = new PrLockAcctAction();
            o = gui.PrLockAcct.getBody();
            a = new Association(o, il, CHECKBOX_ITEM);
            MainNormal.addElement(a);
            
            il = new PrForcePwChangeAction();
            o = gui.PrForcePwChange.getBody();
            a = new Association(o, il, CHECKBOX_ITEM);
            MainNormal.addElement(a);
            
            il = new PrAllowPostdatedAction();
            o = gui.PrAllowPostdated.getBody();
            a = new Association(o, il, CHECKBOX_ITEM);
            MainNormal.addElement(a);
            
            il = new PrAllowForwardableAction();
            o = gui.PrAllowForwardable.getBody();
            a = new Association(o, il, CHECKBOX_ITEM);
            MainNormal.addElement(a);
            
            il = new PrAllowRenewableAction();
            o = gui.PrAllowRenewable.getBody();
            a = new Association(o, il, CHECKBOX_ITEM);
            MainNormal.addElement(a);
            
            il = new PrAllowProxiableAction();
            o = gui.PrAllowProxiable.getBody();
            a = new Association(o, il, CHECKBOX_ITEM);
            MainNormal.addElement(a);
            
            il = new PrAllowSvrAction();
            o = gui.PrAllowSvr.getBody();
            a = new Association(o, il, CHECKBOX_ITEM);
            MainNormal.addElement(a);
            
            il = new PrAllowTGTAction();
            o = gui.PrAllowTGT.getBody();
            a = new Association(o, il, CHECKBOX_ITEM);
            MainNormal.addElement(a);
            
            il = new PrAllowDupAuthAction();
            o = gui.PrAllowDupAuth.getBody();
            a = new Association(o, il, CHECKBOX_ITEM);
            MainNormal.addElement(a);
            
            il = new PrRequirePreAuthAction();
            o = gui.PrRequirePreAuth.getBody();
            a = new Association(o, il, CHECKBOX_ITEM);
            MainNormal.addElement(a);
            
            il = new PrRequireHwPreAuthAction();
            o = gui.PrRequireHwPreAuth.getBody();
            a = new Association(o, il, CHECKBOX_ITEM);
            MainNormal.addElement(a);
            
            al = new PoListPatternAction();
            o = gui.PoListPattern.getBody();
            a = new Association(o, al, TEXTFIELD_ACTION);
            MainNormal.addElement(a);
            a = new Association(o, kl4, TEXTFIELD_KEY);
            MainNormal.addElement(a);
            
            al = new PoListClearAction();
            o = gui.PoListClear.getBody();
            a = new Association(o, al, BUTTON_ACTION);
            MainNormal.addElement(a);
            
            al = new PoListModifyAction();
            o = gui.PoListModify.getBody();
            a = new Association(o, al, BUTTON_ACTION);
            MainNormal.addElement(a);
            
            al = new PoListAddAction();
            o = gui.PoListAdd.getBody();
            a = new Association(o, al, BUTTON_ACTION);
            MainNormal.addElement(a);
            
            al = new PoListDeleteAction();
            o = gui.PoListDelete.getBody();
            a = new Association(o, al, BUTTON_ACTION);
            MainNormal.addElement(a);
            
            al = new PoListDuplicateAction();
            o = gui.PoListDuplicate.getBody();
            a = new Association(o, al, BUTTON_ACTION);
            MainNormal.addElement(a);
            
            il = new PoMinPwLengthAction();
            o = gui.PoMinPwLength.getBody();
            a = new Association(o, il, CHOICE_ITEM);
            MainNormal.addElement(a);
            
            il = new PoMinPwClassAction();
            o = gui.PoMinPwClass.getBody();
            a = new Association(o, il, CHOICE_ITEM);
            MainNormal.addElement(a);
            
            il = new PoSavedPasswordsAction();
            o = gui.PoSavedPasswords.getBody();
            a = new Association(o, il, CHOICE_ITEM);
            MainNormal.addElement(a);
            
            al = new PoMinTicketLifetimeAction();
            o = gui.PoMinTicketLifetime.getBody();
            a = new Association(o, al, TEXTFIELD_ACTION);
            MainNormal.addElement(a);
            a = new Association(o, kl2, TEXTFIELD_KEY);
            MainNormal.addElement(a);
            
            dl = new DurationListener(
			      (TextField)gui.PoMinTicketLifetime.getBody(), fr);
            o = gui.PoMinTicketLifetimeMoreButton.getBody();
            a = new Association(o, dl, BUTTON_ACTION);
            MainNormal.addElement(a);
            
            al = new PoMaxTicketLifetimeAction();
            o = gui.PoMaxTicketLifetime.getBody();
            a = new Association(o, al, TEXTFIELD_ACTION);
            MainNormal.addElement(a);
            a = new Association(o, kl2, TEXTFIELD_KEY);
            MainNormal.addElement(a);
            
            dl = new DurationListener(
			      (TextField)gui.PoMaxTicketLifetime.getBody(), fr);
            o = gui.PoMaxTicketLifetimeMoreButton.getBody();
            a = new Association(o, dl, BUTTON_ACTION);
            MainNormal.addElement(a);
            
            al = new PoSaveAction();
            o = gui.PoDetailSave.getBody();
            a = new Association(o, al, BUTTON_ACTION);
            MainNormal.addElement(a);
            
            al = new PoCancelAction();
            o = gui.PoDetailCancel.getBody();
            a = new Association(o, al, BUTTON_ACTION);
            MainNormal.addElement(a);
            
            al = new PoPreviousAction();
            o = gui.PoDetailPrevious.getBody();
            a = new Association(o, al, BUTTON_ACTION);
            MainNormal.addElement(a);
            
            al = new PoDoneAction();
            o = gui.PoDetailDone.getBody();
            a = new Association(o, al, BUTTON_ACTION);
            MainNormal.addElement(a);
            
        }
        setListeners(MainHelp, false);
        setListeners(MainFixers, false);
        setListeners(MainNormal, true);
        mainHelpMode = false;
    }
    
    /**
     * Set up the listeners for the objects on the main screen in help mode
     *
     */
    public void setupMainHelpListeners() {
        if (MainHelp == null) {
            MainHelp = new Vector(10, 10);
            MouseListener ml = new HelpListener();
            Association a;
            Object o;
            
            o = gui.PrListPattern.getBody();
            a = new Association(o, ml, TEXTFIELD_MOUSE);
            MainHelp.addElement(a);
            ((TextField)o).setName("PrListPattern" /* NOI18N */);
            
            o = gui.PrSearchLab.getBody();
            a = new Association(o, ml, LABEL_MOUSE);
            MainHelp.addElement(a);
            ((Label)o).setName("PrListPattern" /* NOI18N */);
            
            o = gui.PrListClear.getBody();
            a = new Association(o, ml, BUTTON_MOUSE);
            MainHelp.addElement(a);
            ((Button)o).setName("PrListClear" /* NOI18N */);
            
            o = gui.PrListModify.getBody();
            a = new Association(o, ml, BUTTON_MOUSE);
            MainHelp.addElement(a);
            ((Button)o).setName("PrListModify" /* NOI18N */);
            
            o = gui.PrListAdd.getBody();
            a = new Association(o, ml, BUTTON_MOUSE);
            MainHelp.addElement(a);
            ((Button)o).setName("PrListAdd" /* NOI18N */);
            
            o = gui.PrListDelete.getBody();
            a = new Association(o, ml, BUTTON_MOUSE);
            MainHelp.addElement(a);
            ((Button)o).setName("PrListDelete" /* NOI18N */);
            
            o = gui.PrListDuplicate.getBody();
            a = new Association(o, ml, BUTTON_MOUSE);
            MainHelp.addElement(a);
            ((Button)o).setName("PrListDuplicate" /* NOI18N */);
            
            o = gui.PrBasicSave.getBody();
            a = new Association(o, ml, BUTTON_MOUSE);
            MainHelp.addElement(a);
            ((Button)o).setName("PrSave" /* NOI18N */);
            
            o = gui.PrDetailSave.getBody();
            a = new Association(o, ml, BUTTON_MOUSE);
            MainHelp.addElement(a);
            ((Button)o).setName("PrSave" /* NOI18N */);
            
            o = gui.PrFlagsSave.getBody();
            a = new Association(o, ml, BUTTON_MOUSE);
            MainHelp.addElement(a);
            ((Button)o).setName("PrSave" /* NOI18N */);
            
            o = gui.PrBasicCancel.getBody();
            a = new Association(o, ml, BUTTON_MOUSE);
            MainHelp.addElement(a);
            ((Button)o).setName("PrCancel" /* NOI18N */);
            
            o = gui.PrDetailCancel.getBody();
            a = new Association(o, ml, BUTTON_MOUSE);
            MainHelp.addElement(a);
            ((Button)o).setName("PrCancel" /* NOI18N */);
            
            o = gui.PrFlagsCancel.getBody();
            a = new Association(o, ml, BUTTON_MOUSE);
            MainHelp.addElement(a);
            ((Button)o).setName("PrCancel" /* NOI18N */);
            
            o = gui.PrName1.getBody();
            a = new Association(o, ml, TEXTFIELD_MOUSE);
            MainHelp.addElement(a);
            ((TextField)o).setName("PrName" /* NOI18N */);
            
            o = gui.PrNameLabel1.getBody();
            a = new Association(o, ml, LABEL_MOUSE);
            MainHelp.addElement(a);
            ((Label)o).setName("PrName" /* NOI18N */);
            
            o = gui.PrComments.getBody();
            a = new Association(o, ml, TEXTFIELD_MOUSE);
            MainHelp.addElement(a);
            ((TextField)o).setName("PrComments" /* NOI18N */);
            
            o = gui.PrCommentsLabel.getBody();
            a = new Association(o, ml, LABEL_MOUSE);
            MainHelp.addElement(a);
            ((Label)o).setName("PrComments" /* NOI18N */);
            
            o = gui.PrPolicy.getBody();
            a = new Association(o, ml, CHOICE_MOUSE);
            MainHelp.addElement(a);
            ((Choice)o).setName("PrPolicy" /* NOI18N */);
            
            o = gui.PrPolicyLabel.getBody();
            a = new Association(o, ml, LABEL_MOUSE);
            MainHelp.addElement(a);
            ((Label)o).setName("PrPolicy" /* NOI18N */);
            
            o = gui.PrPassword.getBody();
            a = new Association(o, ml, TEXTFIELD_MOUSE);
            MainHelp.addElement(a);
            ((TextField)o).setName("PrPassword" /* NOI18N */);
            
            o = gui.PrPasswordLabel.getBody();
            a = new Association(o, ml, LABEL_MOUSE);
            MainHelp.addElement(a);
            ((Label)o).setName("PrPassword" /* NOI18N */);
            
            o = gui.PrBasicRandomPw.getBody();
            a = new Association(o, ml, BUTTON_MOUSE);
            MainHelp.addElement(a);
            ((Button)o).setName("PrBasicRandomPw" /* NOI18N */);

            o = gui.EncList.getBody();
            a = new Association(o, ml, TEXTFIELD_MOUSE);
            MainHelp.addElement(a);
            ((TextField)o).setName("EncList" /* NOI18N */);
            
            o = gui.EncListLabel.getBody();
            a = new Association(o, ml, LABEL_MOUSE);
            MainHelp.addElement(a);
            ((Label)o).setName("EncList" /* NOI18N */);
            
            o = gui.EncListMoreButton.getBody();
            a = new Association(o, ml, BUTTON_MOUSE);
            MainHelp.addElement(a);
            ((Button)o).setName("EncListHelperButton" /* NOI18N */);

            o = gui.PrExpiry.getBody();
            a = new Association(o, ml, TEXTFIELD_MOUSE);
            MainHelp.addElement(a);
            ((TextField)o).setName("PrExpiry" /* NOI18N */);
            
            o = gui.PrExpiryLabel.getBody();
            a = new Association(o, ml, LABEL_MOUSE);
            MainHelp.addElement(a);
            ((Label)o).setName("PrExpiry" /* NOI18N */);
            
            o = gui.PrExpiryMoreButton.getBody();
            a = new Association(o, ml, BUTTON_MOUSE);
            MainHelp.addElement(a);
            ((Button)o).setName("DateHelperButton" /* NOI18N */);
            
            o = gui.PrLastChangedTime.getBody();
            a = new Association(o, ml, LABEL_MOUSE);
            MainHelp.addElement(a);
            ((Label)o).setName("PrinBasLastPrincipalChange" /* NOI18N */);
            
            o = gui.PrLastChangedTimeLabel.getBody();
            a = new Association(o, ml, LABEL_MOUSE);
            MainHelp.addElement(a);
            ((Label)o).setName("PrinBasLastPrincipalChange" /* NOI18N */);
            
            o = gui.PrLastChangedBy.getBody();
            a = new Association(o, ml, LABEL_MOUSE);
            MainHelp.addElement(a);
            ((Label)o).setName("PrinBasLastChangedBy" /* NOI18N */);
            
            o = gui.PrLastChangedByLabel.getBody();
            a = new Association(o, ml, LABEL_MOUSE);
            MainHelp.addElement(a);
            ((Label)o).setName("PrinBasLastChangedBy" /* NOI18N */);
            
            o = gui.PrBasicPrevious.getBody();
            a = new Association(o, ml, BUTTON_MOUSE);
            MainHelp.addElement(a);
            ((Button)o).setName("PrBasicPrevious" /* NOI18N */);
            
            o = gui.PrBasicNext.getBody();
            a = new Association(o, ml, BUTTON_MOUSE);
            MainHelp.addElement(a);
            ((Button)o).setName("PrBasicNext" /* NOI18N */);
            
            o = gui.PrLastSuccess.getBody();
            a = new Association(o, ml, LABEL_MOUSE);
            MainHelp.addElement(a);
            ((Label)o).setName("PrinDetLastSuccess" /* NOI18N */);
            
            o = gui.PrLastSuccessLabel.getBody();
            a = new Association(o, ml, LABEL_MOUSE);
            MainHelp.addElement(a);
            ((Label)o).setName("PrinDetLastSuccess" /* NOI18N */);
            
            o = gui.PrLastFailure.getBody();
            a = new Association(o, ml, LABEL_MOUSE);
            MainHelp.addElement(a);
            ((Label)o).setName("PrinDetLastFailure" /* NOI18N */);
            
            o = gui.PrLastFailureLabel.getBody();
            a = new Association(o, ml, LABEL_MOUSE);
            MainHelp.addElement(a);
            ((Label)o).setName("PrinDetLastFailure" /* NOI18N */);
            
            o = gui.PrFailCount.getBody();
            a = new Association(o, ml, LABEL_MOUSE);
            MainHelp.addElement(a);
            ((Label)o).setName("PrinDetFailureCount" /* NOI18N */);
            
            o = gui.PrFailureCountLabel.getBody();
            a = new Association(o, ml, LABEL_MOUSE);
            MainHelp.addElement(a);
            ((Label)o).setName("PrinDetFailureCount" /* NOI18N */);
            
            o = gui.PrLastPwChange.getBody();
            a = new Association(o, ml, LABEL_MOUSE);
            MainHelp.addElement(a);
            ((Label)o).setName("PrinDetLastPasswordChange" /* NOI18N */);
            
            o = gui.PrPwLastChangedLabel.getBody();
            a = new Association(o, ml, LABEL_MOUSE);
            MainHelp.addElement(a);
            ((Label)o).setName("PrinDetLastPasswordChange" /* NOI18N */);
            
            o = gui.PrPwExpiry.getBody();
            a = new Association(o, ml, TEXTFIELD_MOUSE);
            MainHelp.addElement(a);
            ((TextField)o).setName("PrPwExpiry" /* NOI18N */);
            
            o = gui.PrPwExpiryLabel.getBody();
            a = new Association(o, ml, LABEL_MOUSE);
            MainHelp.addElement(a);
            ((Label)o).setName("PrPwExpiry" /* NOI18N */);
            
            o = gui.PrPwExpiryMoreButton.getBody();
            a = new Association(o, ml, BUTTON_MOUSE);
            MainHelp.addElement(a);
            ((Button)o).setName("DateHelperButton" /* NOI18N */);
            
            o = gui.PrKvno.getBody();
            a = new Association(o, ml, TEXTFIELD_MOUSE);
            MainHelp.addElement(a);
            ((TextField)o).setName("PrKvno" /* NOI18N */);
            
            o = gui.PrKvnoLabel.getBody();
            a = new Association(o, ml, LABEL_MOUSE);
            MainHelp.addElement(a);
            ((Label)o).setName("PrKvno" /* NOI18N */);
            
            o = gui.PrMaxLifetime.getBody();
            a = new Association(o, ml, TEXTFIELD_MOUSE);
            MainHelp.addElement(a);
            ((TextField)o).setName("PrMaxLifetime" /* NOI18N */);
            
            o = gui.PrMaxTicketLifetimeLabel.getBody();
            a = new Association(o, ml, LABEL_MOUSE);
            MainHelp.addElement(a);
            ((Label)o).setName("PrMaxLifetime" /* NOI18N */);
            
            o = gui.PrMaxLifetimeMoreButton.getBody();
            a = new Association(o, ml, BUTTON_MOUSE);
            MainHelp.addElement(a);
            ((Button)o).setName("DurationHelperButton" /* NOI18N */);
            
            o = gui.PrMaxRenewal.getBody();
            a = new Association(o, ml, TEXTFIELD_MOUSE);
            MainHelp.addElement(a);
            ((TextField)o).setName("PrMaxRenewal" /* NOI18N */);
            
            o = gui.PrMaxTicketRenewalLabel.getBody();
            a = new Association(o, ml, LABEL_MOUSE);
            MainHelp.addElement(a);
            ((Label)o).setName("PrMaxRenewal" /* NOI18N */);
            
            o = gui.PrMaxRenewalMoreButton.getBody();
            a = new Association(o, ml, BUTTON_MOUSE);
            MainHelp.addElement(a);
            ((Button)o).setName("DurationHelperButton" /* NOI18N */);
            
            o = gui.PrDetailPrevious.getBody();
            a = new Association(o, ml, BUTTON_MOUSE);
            MainHelp.addElement(a);
            ((Button)o).setName("PrDetailPrevious" /* NOI18N */);
            
            o = gui.PrDetailNext.getBody();
            a = new Association(o, ml, BUTTON_MOUSE);
            MainHelp.addElement(a);
            ((Button)o).setName("PrDetailNext" /* NOI18N */);
            
            o = gui.PrFlagsPrevious.getBody();
            a = new Association(o, ml, BUTTON_MOUSE);
            MainHelp.addElement(a);
            ((Button)o).setName("PrFlagsPrevious" /* NOI18N */);
            
            o = gui.PrFlagsNext.getBody();
            a = new Association(o, ml, BUTTON_MOUSE);
            MainHelp.addElement(a);
            ((Button)o).setName("PrFlagsNext" /* NOI18N */);
            
            o = gui.PrLockAcct.getBody();
            a = new Association(o, ml, CHECKBOX_MOUSE);
            MainHelp.addElement(a);
            ((Checkbox)o).setName("PrLockAcct" /* NOI18N */);
            
            o = gui.PrForcePwChange.getBody();
            a = new Association(o, ml, CHECKBOX_MOUSE);
            MainHelp.addElement(a);
            ((Checkbox)o).setName("PrForcePwChange" /* NOI18N */);
            
            o = gui.PrAllowPostdated.getBody();
            a = new Association(o, ml, CHECKBOX_MOUSE);
            MainHelp.addElement(a);
            ((Checkbox)o).setName("PrAllowPostdated" /* NOI18N */);
            
            o = gui.PrAllowForwardable.getBody();
            a = new Association(o, ml, CHECKBOX_MOUSE);
            MainHelp.addElement(a);
            ((Checkbox)o).setName("PrAllowForwardable" /* NOI18N */);
            
            o = gui.PrAllowRenewable.getBody();
            a = new Association(o, ml, CHECKBOX_MOUSE);
            MainHelp.addElement(a);
            ((Checkbox)o).setName("PrAllowRenewable" /* NOI18N */);
            
            o = gui.PrAllowProxiable.getBody();
            a = new Association(o, ml, CHECKBOX_MOUSE);
            MainHelp.addElement(a);
            ((Checkbox)o).setName("PrAllowProxiable" /* NOI18N */);
            
            o = gui.PrAllowSvr.getBody();
            a = new Association(o, ml, CHECKBOX_MOUSE);
            MainHelp.addElement(a);
            ((Checkbox)o).setName("PrAllowSvr" /* NOI18N */);
            
            o = gui.PrAllowTGT.getBody();
            a = new Association(o, ml, CHECKBOX_MOUSE);
            MainHelp.addElement(a);
            ((Checkbox)o).setName("PrAllowTGT" /* NOI18N */);
            
            o = gui.PrAllowDupAuth.getBody();
            a = new Association(o, ml, CHECKBOX_MOUSE);
            MainHelp.addElement(a);
            ((Checkbox)o).setName("PrAllowDupAuth" /* NOI18N */);
            
            o = gui.PrRequirePreAuth.getBody();
            a = new Association(o, ml, CHECKBOX_MOUSE);
            MainHelp.addElement(a);
            ((Checkbox)o).setName("PrRequirePreAuth" /* NOI18N */);
            
            o = gui.PrRequireHwPreAuth.getBody();
            a = new Association(o, ml, CHECKBOX_MOUSE);
            MainHelp.addElement(a);
            ((Checkbox)o).setName("PrRequireHwPreAuth" /* NOI18N */);
            
            o = gui.PoListPattern.getBody();
            a = new Association(o, ml, TEXTFIELD_MOUSE);
            MainHelp.addElement(a);
            ((TextField)o).setName("PoListPattern" /* NOI18N */);
            
            o = gui.PoListPatternLabel.getBody();
            a = new Association(o, ml, LABEL_MOUSE);
            MainHelp.addElement(a);
            ((Label)o).setName("PoListPattern" /* NOI18N */);
            
            o = gui.PoListClear.getBody();
            a = new Association(o, ml, BUTTON_MOUSE);
            MainHelp.addElement(a);
            ((Button)o).setName("PoListClear" /* NOI18N */);
            
            o = gui.PoListModify.getBody();
            a = new Association(o, ml, BUTTON_MOUSE);
            MainHelp.addElement(a);
            ((Button)o).setName("PoListModify" /* NOI18N */);
            
            o = gui.PoListAdd.getBody();
            a = new Association(o, ml, BUTTON_MOUSE);
            MainHelp.addElement(a);
            ((Button)o).setName("PoListAdd" /* NOI18N */);
            
            o = gui.PoListDelete.getBody();
            a = new Association(o, ml, BUTTON_MOUSE);
            MainHelp.addElement(a);
            ((Button)o).setName("PoListDelete" /* NOI18N */);
            
            o = gui.PoListDuplicate.getBody();
            a = new Association(o, ml, BUTTON_MOUSE);
            MainHelp.addElement(a);
            ((Button)o).setName("PoListDuplicate" /* NOI18N */);
            
            o = gui.PoName.getBody();
            a = new Association(o, ml, TEXTFIELD_MOUSE);
            MainHelp.addElement(a);
            ((TextField)o).setName("PoName" /* NOI18N */);
            
            o = gui.PoNameLabel.getBody();
            a = new Association(o, ml, LABEL_MOUSE);
            MainHelp.addElement(a);
            ((Label)o).setName("PoName" /* NOI18N */);
            
            o = gui.PoMinPwLength.getBody();
            a = new Association(o, ml, CHOICE_MOUSE);
            MainHelp.addElement(a);
            ((Choice)o).setName("PoMinPwLength" /* NOI18N */);
            
            o = gui.PoMinPwLengthLabel.getBody();
            a = new Association(o, ml, LABEL_MOUSE);
            MainHelp.addElement(a);
            ((Label)o).setName("PoMinPwLength" /* NOI18N */);
            
            o = gui.PoMinPwClass.getBody();
            a = new Association(o, ml, CHOICE_MOUSE);
            MainHelp.addElement(a);
            ((Choice)o).setName("PoMinPwClass" /* NOI18N */);
            
            o = gui.PoMinPwClassLabel.getBody();
            a = new Association(o, ml, LABEL_MOUSE);
            MainHelp.addElement(a);
            ((Label)o).setName("PoMinPwClass" /* NOI18N */);
            
            o = gui.PoSavedPasswords.getBody();
            a = new Association(o, ml, CHOICE_MOUSE);
            MainHelp.addElement(a);
            ((Choice)o).setName("PoSavedPasswords" /* NOI18N */);
            
            o = gui.PoSavedPasswordsLabel.getBody();
            a = new Association(o, ml, LABEL_MOUSE);
            MainHelp.addElement(a);
            ((Label)o).setName("PoSavedPasswords" /* NOI18N */);
            
            o = gui.PoMinTicketLifetime.getBody();
            a = new Association(o, ml, TEXTFIELD_MOUSE);
            MainHelp.addElement(a);
            ((TextField)o).setName("PoMinTicketLifetime" /* NOI18N */);
            
            o = gui.PoMinTicketLifetimeLabel.getBody();
            a = new Association(o, ml, LABEL_MOUSE);
            MainHelp.addElement(a);
            ((Label)o).setName("PoMinTicketLifetime" /* NOI18N */);
            
            o = gui.PoMinTicketLifetimeMoreButton.getBody();
            a = new Association(o, ml, BUTTON_MOUSE);
            MainHelp.addElement(a);
            ((Button)o).setName("DurationHelperButton" /* NOI18N */);
            
            o = gui.PoMaxTicketLifetime.getBody();
            a = new Association(o, ml, TEXTFIELD_MOUSE);
            MainHelp.addElement(a);
            ((TextField)o).setName("PoMaxTicketLifetime" /* NOI18N */);
            
            o = gui.PoMaxTicketLifetimeLabel.getBody();
            a = new Association(o, ml, LABEL_MOUSE);
            MainHelp.addElement(a);
            ((Label)o).setName("PoMaxTicketLifetime" /* NOI18N */);
            
            o = gui.PoMaxTicketLifetimeMoreButton.getBody();
            a = new Association(o, ml, BUTTON_MOUSE);
            MainHelp.addElement(a);
            ((Button)o).setName("DurationHelperButton" /* NOI18N */);
            
            o = gui.PoReferences.getBody();
            a = new Association(o, ml, LABEL_MOUSE);
            MainHelp.addElement(a);
            ((Label)o).setName("PolDetPrincipalsUsingThisPolicy" /* NOI18N */);
            
            o = gui.PoReferencesLabel.getBody();
            a = new Association(o, ml, LABEL_MOUSE);
            MainHelp.addElement(a);
            ((Label)o).setName("PolDetPrincipalsUsingThisPolicy" /* NOI18N */);
            
            o = gui.PoDetailSave.getBody();
            a = new Association(o, ml, BUTTON_MOUSE);
            MainHelp.addElement(a);
            ((Button)o).setName("PoSave" /* NOI18N */);
            
            o = gui.PoDetailCancel.getBody();
            a = new Association(o, ml, BUTTON_MOUSE);
            MainHelp.addElement(a);
            ((Button)o).setName("PoCancel" /* NOI18N */);
            
            o = gui.PoDetailPrevious.getBody();
            a = new Association(o, ml, BUTTON_MOUSE);
            MainHelp.addElement(a);
            ((Button)o).setName("PoDetailPrevious" /* NOI18N */);
            
            o = gui.PoDetailDone.getBody();
            a = new Association(o, ml, BUTTON_MOUSE);
            MainHelp.addElement(a);
            ((Button)o).setName("PoDetailDone" /* NOI18N */);
            
            setupMainHelpFlagTogglers();
        }
        
        fixHelpTags();
        setListeners(MainNormal, false);
        setListeners(MainHelp, true);
        setupMainHelpFixers();
        mainHelpMode = true;
    }
    
    public void fixHelpTags() {
        if (noLists) {
            ((TextList)gui.Prlist.getBody()).setName("PrNoList" /* NOI18N */);
            ((TextField)gui.PrListPattern.getBody()).setName("PrNameNoList"
							     /* NOI18N */);
            ((Button)gui.PrListClear.getBody()).setName("PrNoListClear"
							/* NOI18N */);
            ((TextList)gui.Pollist.getBody()).setName("PolNoList" /* NOI18N */);
            ((TextField)gui.PoListPattern.getBody()).setName("PoNameNoList"
							     /* NOI18N */);
            ((Button)gui.PoListClear.getBody()).setName("PoNoListClear"
							/* NOI18N */);
        } else {
            ((TextList)gui.Prlist.getBody()).setName("PrList" /* NOI18N */);
            ((TextField)gui.PrListPattern.getBody()).setName("PrListPattern"
							     /* NOI18N */);
            ((Button)gui.PrListClear.getBody()).setName("PrListClear"
							/* NOI18N */);
            ((TextList)gui.Pollist.getBody()).setName("Pollist" /* NOI18N */);
            ((TextField)gui.PoListPattern.getBody()).setName("PoListPattern"
							     /* NOI18N */);
            ((Button)gui.PoListClear.getBody()).setName("PoListClear"
							/* NOI18N */);
        }
    }
    
    /**
     * Helper method to setupMainHelpListeners. Should be called from
     * only from there.
     */
    private void 	setupMainHelpFlagTogglers() {
        
        if (MainHelp == null)
            return;
        
        CheckboxToggler ml = new CheckboxToggler();
        Object o;
        Association a;
        
        o = gui.PrLockAcct.getBody();
        a = new Association(o, ml, CHECKBOX_MOUSE);
        MainHelp.addElement(a);
        
        o = gui.PrForcePwChange.getBody();
        a = new Association(o, ml, CHECKBOX_MOUSE);
        MainHelp.addElement(a);
        
        o = gui.PrAllowPostdated.getBody();
        a = new Association(o, ml, CHECKBOX_MOUSE);
        MainHelp.addElement(a);
        
        o = gui.PrAllowForwardable.getBody();
        a = new Association(o, ml, CHECKBOX_MOUSE);
        MainHelp.addElement(a);
        
        o = gui.PrAllowRenewable.getBody();
        a = new Association(o, ml, CHECKBOX_MOUSE);
        MainHelp.addElement(a);
        
        o = gui.PrAllowProxiable.getBody();
        a = new Association(o, ml, CHECKBOX_MOUSE);
        MainHelp.addElement(a);
        
        o = gui.PrAllowSvr.getBody();
        a = new Association(o, ml, CHECKBOX_MOUSE);
        MainHelp.addElement(a);
        
        o = gui.PrAllowTGT.getBody();
        a = new Association(o, ml, CHECKBOX_MOUSE);
        MainHelp.addElement(a);
        
        o = gui.PrAllowDupAuth.getBody();
        a = new Association(o, ml, CHECKBOX_MOUSE);
        MainHelp.addElement(a);
        
        o = gui.PrRequirePreAuth.getBody();
        a = new Association(o, ml, CHECKBOX_MOUSE);
        MainHelp.addElement(a);
        
        o = gui.PrRequireHwPreAuth.getBody();
        a = new Association(o, ml, CHECKBOX_MOUSE);
        MainHelp.addElement(a);
    }
    
    public void setupMainHelpFixers() {
        MainFixers = new Vector(10, 10);
        Object o;
        Association a;
        TextFixer tf;
        ChoiceFixer cf;
        
        o = gui.PrListPattern.getBody();
        tf = new TextFixer((TextField)o);
        a = new Association(o, tf, TEXTFIELD_KEY);
        MainFixers.addElement(a);
        
        o = gui.PrName1.getBody();
        tf = new TextFixer((TextField)o);
        a = new Association(o, tf, TEXTFIELD_KEY);
        MainFixers.addElement(a);
        
        o = gui.PrComments.getBody();
        tf = new TextFixer((TextField)o);
        a = new Association(o, tf, TEXTFIELD_KEY);
        MainFixers.addElement(a);
        
        o = gui.PrPolicy.getBody();
        cf = new ChoiceFixer((Choice)o);
        a = new Association(o, cf, CHOICE_ITEM);
        MainFixers.addElement(a);
        
        o = gui.PrPassword.getBody();
        tf = new TextFixer((TextField)o);
        a = new Association(o, tf, TEXTFIELD_KEY);
        MainFixers.addElement(a);
        
        o = gui.PrExpiry.getBody();
        tf = new TextFixer((TextField)o);
        a = new Association(o, tf, TEXTFIELD_KEY);
        MainFixers.addElement(a);

        o = gui.EncList.getBody();
        tf = new TextFixer((TextField)o);
        a = new Association(o, tf, TEXTFIELD_KEY);
        MainFixers.addElement(a);
        
        o = gui.PrPwExpiry.getBody();
        tf = new TextFixer((TextField)o);
        a = new Association(o, tf, TEXTFIELD_KEY);
        MainFixers.addElement(a);
        
        o = gui.PrKvno.getBody();
        tf = new TextFixer((TextField)o);
        a = new Association(o, tf, TEXTFIELD_KEY);
        MainFixers.addElement(a);
        
        o = gui.PrMaxLifetime.getBody();
        tf = new TextFixer((TextField)o);
        a = new Association(o, tf, TEXTFIELD_KEY);
        MainFixers.addElement(a);
        
        o = gui.PrMaxRenewal.getBody();
        tf = new TextFixer((TextField)o);
        a = new Association(o, tf, TEXTFIELD_KEY);
        MainFixers.addElement(a);
        
        o = gui.PoListPattern.getBody();
        tf = new TextFixer((TextField)o);
        a = new Association(o, tf, TEXTFIELD_KEY);
        MainFixers.addElement(a);
        
        o = gui.PoName.getBody();
        tf = new TextFixer((TextField)o);
        a = new Association(o, tf, TEXTFIELD_KEY);
        MainFixers.addElement(a);
        
        o = gui.PoMinPwLength.getBody();
        cf = new ChoiceFixer((Choice)o);
        a = new Association(o, cf, CHOICE_ITEM);
        MainFixers.addElement(a);
        
        o = gui.PoMinPwClass.getBody();
        cf = new ChoiceFixer((Choice)o);
        a = new Association(o, cf, CHOICE_ITEM);
        MainFixers.addElement(a);
        
        o = gui.PoSavedPasswords.getBody();
        cf = new ChoiceFixer((Choice)o);
        a = new Association(o, cf, CHOICE_ITEM);
        MainFixers.addElement(a);
        
        o = gui.PoMinTicketLifetime.getBody();
        tf = new TextFixer((TextField)o);
        a = new Association(o, tf, TEXTFIELD_KEY);
        MainFixers.addElement(a);
        
        o = gui.PoMaxTicketLifetime.getBody();
        tf = new TextFixer((TextField)o);
        a = new Association(o, tf, TEXTFIELD_KEY);
        MainFixers.addElement(a);
        
        setListeners(MainFixers, true);
    }
    
    public void setupDefaultsNormalListeners() {
        
        if (defaultsNormal == null) {
            defaultsNormal = new Vector(10, 10);
            ActionListener al;
            ItemListener il;
            KeyListener kl = new KeystrokeDetector(DEFAULTS_EDITING);
            Association a;
            Object o;
            
            // Action listeners for Defaults
            
            il = new GlobalLockAcctAction();
            o = defaults.disableAccount;
            a = new Association(o, il, CHECKBOX_ITEM);
            defaultsNormal.addElement(a);
            
            il = new GlobalForcePwChangeAction();
            o = defaults.forcePasswordChange;
            a = new Association(o, il, CHECKBOX_ITEM);
            defaultsNormal.addElement(a);
            
            il = new GlobalAllowPostdatedAction();
            o = defaults.allowPostdatedTix;
            a = new Association(o, il, CHECKBOX_ITEM);
            defaultsNormal.addElement(a);
            
            il = new GlobalAllowForwardableAction();
            o = defaults.allowForwardableTix;
            a = new Association(o, il, CHECKBOX_ITEM);
            defaultsNormal.addElement(a);
            
            il = new GlobalAllowRenewableAction();
            o = defaults.allowRenewableTix;
            a = new Association(o, il, CHECKBOX_ITEM);
            defaultsNormal.addElement(a);
            
            il = new GlobalAllowProxiableAction();
            o = defaults.allowProxiableTix;
            a = new Association(o, il, CHECKBOX_ITEM);
            defaultsNormal.addElement(a);
            
            il = new GlobalAllowSvrAction();
            o = defaults.allowServiceTix;
            a = new Association(o, il, CHECKBOX_ITEM);
            defaultsNormal.addElement(a);
            
            il = new GlobalAllowTGTAction();
            o = defaults.allowTGTAuth;
            a = new Association(o, il, CHECKBOX_ITEM);
            defaultsNormal.addElement(a);
            
            il = new GlobalAllowDupAuthAction();
            o = defaults.allowDupAuth;
            a = new Association(o, il, CHECKBOX_ITEM);
            defaultsNormal.addElement(a);
            
            il = new GlobalRequirePreAuthAction();
            o = defaults.requirePreauth;
            a = new Association(o, il, CHECKBOX_ITEM);
            defaultsNormal.addElement(a);
            
            il = new GlobalRequireHwPreAuthAction();
            o = defaults.requireHWAuth;
            a = new Association(o, il, CHECKBOX_ITEM);
            defaultsNormal.addElement(a);
            
            il = new GlobalDefaultServerSideAction();
            o = defaults.serverSide;
            a = new Association(o, il, CHECKBOX_ITEM);
            defaultsNormal.addElement(a);
            
            al = new GlobalDefaultRenewableLifeAction();
            o = defaults.maxTicketRenewableLife;
            a = new Association(o, al, TEXTFIELD_ACTION);
            defaultsNormal.addElement(a);
            a = new Association(o, kl, TEXTFIELD_KEY);
            defaultsNormal.addElement(a);
            
            al = new GlobalDefaultLifeAction();
            o = defaults.maxTicketLife;
            a = new Association(o, al, TEXTFIELD_ACTION);
            defaultsNormal.addElement(a);
            a = new Association(o, kl, TEXTFIELD_KEY);
            defaultsNormal.addElement(a);
            
            al = new GlobalDefaultExpiryAction();
            o = defaults.accountExpiryDate;
            a = new Association(o, al, TEXTFIELD_ACTION);
            defaultsNormal.addElement(a);
            a = new Association(o, kl, TEXTFIELD_KEY);
            defaultsNormal.addElement(a);
            
            il = new GlobalDefaultShowListsAction();
            o = defaults.showLists;
            a = new Association(o, il, CHECKBOX_ITEM);
            defaultsNormal.addElement(a);
            
            il = new GlobalDefaultStaticListsAction();
            o = defaults.staticLists;
            a = new Association(o, il, CHECKBOX_ITEM);
            defaultsNormal.addElement(a);
            
            al = new GlobalDefaultCacheTimeAction();
            o = defaults.cacheTime;
            a = new Association(o, al, TEXTFIELD_ACTION);
            defaultsNormal.addElement(a);
            a = new Association(o, kl, TEXTFIELD_KEY);
            defaultsNormal.addElement(a);
            
            al = new GlobalSaveAction();
            o = defaults.saveButton;
            a = new Association(o, al, BUTTON_ACTION);
            defaultsNormal.addElement(a);
            
            al = new GlobalApplyAction();
            o = defaults.applyButton;
            a = new Association(o, al, BUTTON_ACTION);
            defaultsNormal.addElement(a);
            
            al = new GlobalCancelAction();
            o = defaults.cancelButton;
            a = new Association(o, al, BUTTON_ACTION);
            defaultsNormal.addElement(a);
            
            DateTimeListener dtl = new DateTimeListener(
			defaults.accountExpiryDate, defaultsEditingFrame);
            o = defaults.dateMoreButton;
            a = new Association(o, dtl, BUTTON_ACTION);
            defaultsNormal.addElement(a);
            
            DurationListener dl = new DurationListener(
		       defaults.maxTicketRenewableLife, defaultsEditingFrame);
            o = defaults.renewalMoreButton;
            a = new Association(o, dl, BUTTON_ACTION);
            defaultsNormal.addElement(a);
            
            dl = new DurationListener(defaults.maxTicketLife,
				      defaultsEditingFrame);
            o = defaults.lifeMoreButton;
            a = new Association(o, dl, BUTTON_ACTION);
            defaultsNormal.addElement(a);
            
            dl = new DurationListener(defaults.cacheTime, defaultsEditingFrame);
            o = defaults.cacheMoreButton;
            a = new Association(o, dl, BUTTON_ACTION);
            defaultsNormal.addElement(a);
            
        }
        setListeners(defaultsHelp, false);
        setListeners(defaultsFixers, false);
        setListeners(defaultsNormal, true);
        defaultsHelpMode = false;
    }
    
    public void setupDefaultsHelpListeners() {
        if (defaultsHelp == null) {
            defaultsHelp = new Vector(10, 10);
            MouseListener ml = new HelpListener();
            Association a;
            Object o;
            
            o = defaults.disableAccount;
            a = new Association(o, ml, CHECKBOX_MOUSE);
            defaultsHelp.addElement(a);
            defaults.disableAccount.setName("GlobalLockAcct" /* NOI18N */);
            
            o = defaults.forcePasswordChange;
            a = new Association(o, ml, CHECKBOX_MOUSE);
            defaultsHelp.addElement(a);
            defaults.forcePasswordChange.setName("GlobalForcePwChange"
						 /* NOI18N */);
            
            o = defaults.allowPostdatedTix;
            a = new Association(o, ml, CHECKBOX_MOUSE);
            defaultsHelp.addElement(a);
            defaults.allowPostdatedTix.setName("GlobalAllowPostdated"
					       /* NOI18N */);
            
            o = defaults.allowForwardableTix;
            a = new Association(o, ml, CHECKBOX_MOUSE);
            defaultsHelp.addElement(a);
            defaults.allowForwardableTix.setName("GlobalAllowForwardable"
						 /* NOI18N */);
            
            o = defaults.allowRenewableTix;
            a = new Association(o, ml, CHECKBOX_MOUSE);
            defaultsHelp.addElement(a);
            defaults.allowRenewableTix.setName("GlobalAllowRenewable"
					       /* NOI18N */);
            
            o = defaults.allowProxiableTix;
            a = new Association(o, ml, CHECKBOX_MOUSE);
            defaultsHelp.addElement(a);
            defaults.allowProxiableTix.setName("GlobalAllowProxiable"
					       /* NOI18N */);
            
            o = defaults.allowServiceTix;
            a = new Association(o, ml, CHECKBOX_MOUSE);
            defaultsHelp.addElement(a);
            defaults.allowServiceTix.setName("GlobalAllowSvr" /* NOI18N */);
            
            o = defaults.allowTGTAuth;
            a = new Association(o, ml, CHECKBOX_MOUSE);
            defaultsHelp.addElement(a);
            defaults.allowTGTAuth.setName("GlobalAllowTGT" /* NOI18N */);
            
            o = defaults.allowDupAuth;
            a = new Association(o, ml, CHECKBOX_MOUSE);
            defaultsHelp.addElement(a);
            defaults.allowDupAuth.setName("GlobalAllowDupAuth" /* NOI18N */);
            
            o = defaults.requirePreauth;
            a = new Association(o, ml, CHECKBOX_MOUSE);
            defaultsHelp.addElement(a);
            defaults.requirePreauth.setName("GlobalRequirePreAuth"
					    /* NOI18N */);
            
            o = defaults.requireHWAuth;
            a = new Association(o, ml, CHECKBOX_MOUSE);
            defaultsHelp.addElement(a);
            defaults.requireHWAuth.setName("GlobalRequireHwPreAuth"
					   /* NOI18N */);
            
            o = defaults.serverSide;
            a = new Association(o, ml, CHECKBOX_MOUSE);
            defaultsHelp.addElement(a);
            defaults.serverSide.setName("GlDefServerSide" /* NOI18N */);
            
            o = defaults.maxTicketRenewableLife;
            a = new Association(o, ml, TEXTFIELD_MOUSE);
            defaultsHelp.addElement(a);
            defaults.maxTicketRenewableLife.setName("GlDefRenewableLife"
						    /* NOI18N */);
            
            o = defaults.maxTicketRenewableLifeLabel;
            a = new Association(o, ml, LABEL_MOUSE);
            defaultsHelp.addElement(a);
            defaults.maxTicketRenewableLifeLabel.setName("GlDefRenewableLife"
							 /* NOI18N */);
            
            o = defaults.maxTicketLife;
            a = new Association(o, ml, TEXTFIELD_MOUSE);
            defaultsHelp.addElement(a);
            defaults.maxTicketLife.setName("GlDefLife" /* NOI18N */);
            
            o = defaults.maxTicketLifeLabel;
            a = new Association(o, ml, LABEL_MOUSE);
            defaultsHelp.addElement(a);
            defaults.maxTicketLifeLabel.setName("GlDefLife" /* NOI18N */);
            
            o = defaults.accountExpiryDate;
            a = new Association(o, ml, TEXTFIELD_MOUSE);
            defaultsHelp.addElement(a);
            defaults.accountExpiryDate.setName("GlDefExpiry" /* NOI18N */);
            
            o = defaults.accountExpiryDateLabel;
            a = new Association(o, ml, LABEL_MOUSE);
            defaultsHelp.addElement(a);
            defaults.accountExpiryDateLabel.setName("GlDefExpiry" /* NOI18N */);
            
            o = defaults.showLists;
            a = new Association(o, ml, CHECKBOX_MOUSE);
            defaultsHelp.addElement(a);
            defaults.showLists.setName("GlDefShowLists" /* NOI18N */);
            
            o = defaults.staticLists;
            a = new Association(o, ml, CHECKBOX_MOUSE);
            defaultsHelp.addElement(a);
            defaults.staticLists.setName("GlDefStaticLists" /* NOI18N */);
            
            o = defaults.cacheTime;
            a = new Association(o, ml, TEXTFIELD_MOUSE);
            defaultsHelp.addElement(a);
            defaults.cacheTime.setName("GlDefCacheTime" /* NOI18N */);
            
            o = defaults.cacheTimeLabel;
            a = new Association(o, ml, LABEL_MOUSE);
            defaultsHelp.addElement(a);
            defaults.cacheTimeLabel.setName("GlDefCacheTime" /* NOI18N */);
            
            o = defaults.saveButton;
            a = new Association(o, ml, BUTTON_MOUSE);
            defaultsHelp.addElement(a);
            defaults.saveButton.setName("GlobalSave" /* NOI18N */);
            
            o = defaults.applyButton;
            a = new Association(o, ml, BUTTON_MOUSE);
            defaultsHelp.addElement(a);
            defaults.applyButton.setName("GlobalApply" /* NOI18N */);
            
            o = defaults.cancelButton;
            a = new Association(o, ml, BUTTON_MOUSE);
            defaultsHelp.addElement(a);
            defaults.cancelButton.setName("GlobalCancel" /* NOI18N */);
            
            o = defaults.dateMoreButton;
            a = new Association(o, ml, BUTTON_MOUSE);
            defaultsHelp.addElement(a);
            defaults.dateMoreButton.setName("DateHelperButton" /* NOI18N */);
            
            o = defaults.lifeMoreButton;
            a = new Association(o, ml, BUTTON_MOUSE);
            defaultsHelp.addElement(a);
            defaults.lifeMoreButton.setName("DurationHelperButton"
					    /* NOI18N */);
            
            o = defaults.renewalMoreButton;
            a = new Association(o, ml, BUTTON_MOUSE);
            defaultsHelp.addElement(a);
            defaults.renewalMoreButton.setName("DurationHelperButton"
					       /* NOI18N */);
            
            o = defaults.cacheMoreButton;
            a = new Association(o, ml, BUTTON_MOUSE);
            defaultsHelp.addElement(a);
            defaults.cacheMoreButton.setName("DurationHelperButton"
					     /* NOI18N */);
            
            setupDefaultsHelpFlagTogglers();
        }
        
        setListeners(defaultsNormal, false);
        setListeners(defaultsHelp, true);
        setupDefaultsHelpFixers();
        defaultsHelpMode = true;
    }
    
    /**
     * Helper method to setupDefaultsHelpListeners. Should be called from
     * only from there.
     */
    private void 	setupDefaultsHelpFlagTogglers() {
        
        if (defaultsHelp == null)
            return;
        
        CheckboxToggler ml = new CheckboxToggler();
        Object o;
        Association a;
        
        o = defaults.disableAccount;
        a = new Association(o, ml, CHECKBOX_MOUSE);
        defaultsHelp.addElement(a);
        
        o = defaults.forcePasswordChange;
        a = new Association(o, ml, CHECKBOX_MOUSE);
        defaultsHelp.addElement(a);
        
        o = defaults.allowPostdatedTix;
        a = new Association(o, ml, CHECKBOX_MOUSE);
        defaultsHelp.addElement(a);
        
        o = defaults.allowForwardableTix;
        a = new Association(o, ml, CHECKBOX_MOUSE);
        defaultsHelp.addElement(a);
        
        o = defaults.allowRenewableTix;
        a = new Association(o, ml, CHECKBOX_MOUSE);
        defaultsHelp.addElement(a);
        
        o = defaults.allowProxiableTix;
        a = new Association(o, ml, CHECKBOX_MOUSE);
        defaultsHelp.addElement(a);
        
        o = defaults.allowServiceTix;
        a = new Association(o, ml, CHECKBOX_MOUSE);
        defaultsHelp.addElement(a);
        
        o = defaults.allowTGTAuth;
        a = new Association(o, ml, CHECKBOX_MOUSE);
        defaultsHelp.addElement(a);
        
        o = defaults.allowDupAuth;
        a = new Association(o, ml, CHECKBOX_MOUSE);
        defaultsHelp.addElement(a);
        
        o = defaults.requirePreauth;
        a = new Association(o, ml, CHECKBOX_MOUSE);
        defaultsHelp.addElement(a);
        
        o = defaults.requireHWAuth;
        a = new Association(o, ml, CHECKBOX_MOUSE);
        defaultsHelp.addElement(a);
        
        o = defaults.showLists;
        a = new Association(o, ml, CHECKBOX_MOUSE);
        defaultsHelp.addElement(a);
        
        o = defaults.serverSide;
        a = new Association(o, ml, CHECKBOX_MOUSE);
        defaultsHelp.addElement(a);
        
        o = defaults.staticLists;
        a = new Association(o, ml, CHECKBOX_MOUSE);
        defaultsHelp.addElement(a);
    }
    
    public void setupDefaultsHelpFixers() {
        defaultsFixers = new Vector(10, 10);
        Association a;
        Object o;
        TextFixer tf;
        
        o = defaults.maxTicketRenewableLife;
        tf = new TextFixer((TextField)o);
        a = new Association(o, tf, TEXTFIELD_KEY);
        defaultsFixers.addElement(a);
        
        o = defaults.maxTicketLife;
        tf = new TextFixer((TextField)o);
        a = new Association(o, tf, TEXTFIELD_KEY);
        defaultsFixers.addElement(a);
        
        o = defaults.accountExpiryDate;
        tf = new TextFixer((TextField)o);
        a = new Association(o, tf, TEXTFIELD_KEY);
        defaultsFixers.addElement(a);
        
        o = defaults.cacheTime;
        tf = new TextFixer((TextField)o);
        a = new Association(o, tf, TEXTFIELD_KEY);
        defaultsFixers.addElement(a);
        
        setListeners(defaultsFixers, true);
    }
    
    /**
     * Set up listeners from a vector of Associations objects
     *
     */
    public void setListeners(Vector associations, boolean install) {
        setListeners(associations, install, false);
    }
    
    public void setListeners(Vector associations, boolean install, boolean loud)
    {
        Association a;
        Button b;
        TextField t;
        Choice c;
        Checkbox x;
        Label z;
        Window w;
        
        if (associations != null) {
            for (int i = 0; i < associations.size(); i++) {
                a = (Association)associations.elementAt(i);
                int type = a.Type;
                EventListener el = a.Listener;
                if (loud) {
                    Object o = a.Object;
                    String flag = install ? "install" : "deinstall";
                    System.out.println(flag+
				       "ing listener "+el+" on component "+o);
                }
                
                switch (type) {
		case BUTTON_ACTION:
                    b = (Button)a.Object;
                    if (install)
                        b.addActionListener((ActionListener)el);
                    else
                        b.removeActionListener((ActionListener)el);
                    break;
                    
		case BUTTON_MOUSE:
                    b = (Button)a.Object;
                    if (install)
                        b.addMouseListener((MouseListener)el);
                    else
                        b.removeMouseListener((MouseListener)el);
                    break;
                    
		case TEXTFIELD_ACTION:
                    t = (TextField)a.Object;
                    if (install)
                        t.addActionListener((ActionListener)el);
                    else
                        t.removeActionListener((ActionListener)el);
                    break;
                    
		case TEXTFIELD_MOUSE:
                    t = (TextField)a.Object;
                    if (install)
                        t.addMouseListener((MouseListener)el);
                    else
                        t.removeMouseListener((MouseListener)el);
                    break;
                    
		case TEXTFIELD_KEY:
                    t = (TextField)a.Object;
                    if (install)
                        t.addKeyListener((KeyListener)el);
                    else
                        t.removeKeyListener((KeyListener)el);
                    break;
                    
		case CHOICE_ITEM:
                    c = (Choice)a.Object;
                    if (install)
                        c.addItemListener((ItemListener)el);
                    else
                        c.removeItemListener((ItemListener)el);
                    break;
                    
		case CHOICE_MOUSE:
                    c = (Choice)a.Object;
                    if (install)
                        c.addMouseListener((MouseListener)el);
                    else
                        c.removeMouseListener((MouseListener)el);
                    break;
                    
		case CHECKBOX_ITEM:
                    x = (Checkbox)a.Object;
                    if (install)
                        x.addItemListener((ItemListener)el);
                    else
                        x.removeItemListener((ItemListener)el);
                    break;
                    
		case CHECKBOX_MOUSE:
                    x = (Checkbox)a.Object;
                    if (install)
                        x.addMouseListener((MouseListener)el);
                    else
                        x.removeMouseListener((MouseListener)el);
                    break;
                    
		case LABEL_MOUSE:
                    z = (Label)a.Object;
                    if (install)
                        z.addMouseListener((MouseListener)el);
                    else
                        z.removeMouseListener((MouseListener)el);
                    break;
                    
		case WINDOW_LISTENER:
                    w = (Window)a.Object;
                    if (install)
                        w.addWindowListener((WindowListener)el);
                    else
                        w.removeWindowListener((WindowListener)el);
                    break;
                }
            }
        }
    }
    
    /*
     * About a million actions here ...
     */
    private class LoginOKAction implements ActionListener {
        public void actionPerformed(ActionEvent e) {
            loginComplete();
        }
    }
    
    private class LoginStartOverAction implements ActionListener {
        public void actionPerformed(ActionEvent e) {
            setLoginDefaults();
        }
    }
    
    private class LoginNameAction implements ActionListener {
        public void actionPerformed(ActionEvent e) {
            nameComplete();
        }
    }
    
    private class LoginPassAction implements ActionListener {
        public void actionPerformed(ActionEvent e) {
            loginComplete();
        }
    }
    
    private class LoginRealmAction implements ActionListener {
        public void actionPerformed(ActionEvent e) {
            newRealm();
        }
    }
    
    private class LoginServerAction implements ActionListener {
        public void actionPerformed(ActionEvent e) {
            newServer();
        }
    }
    
    private class MainWindowCloseAction extends WindowAdapter {
        public void windowClosing(WindowEvent e) {
            checkLogout();
        }
    };
    
    private class PrListPatternAction implements ActionListener {
        public void actionPerformed(ActionEvent e) {
            prPatternComplete();
        }
    }
    
    private class PrListClearAction implements ActionListener {
        public void actionPerformed(ActionEvent e) {
            prPatternClear();
        }
    }
    
    private class PrListModifyAction implements ActionListener {
        public void actionPerformed(ActionEvent e) {
            prModify();
        }
    }
    
    private class PrListAddAction implements ActionListener {
        public void actionPerformed(ActionEvent e) {
            prAdd();
        }
    }
    
    private class PrListDeleteAction implements ActionListener {
        public void actionPerformed(ActionEvent e) {
            prDelete();
        }
    }
    
    private class PrListDuplicateAction implements ActionListener {
        public void actionPerformed(ActionEvent e) {
            prDuplicate();
        }
    }
    
    private class PrCommentsAction implements ActionListener {
        public void actionPerformed(ActionEvent e) {
            setPrComments();
            prSetNeedSave();
        }
    }
    
    private class PrPolicyAction implements ItemListener {
        public void itemStateChanged(ItemEvent e) {
            setPrPolicy();
            prSetNeedSave();
        }
    }
    
    private class PrPasswordAction implements ActionListener {
        public void actionPerformed(ActionEvent e) {
            setPrPassword(!prin.isNew);
            prSetNeedSave();
        }
    }
    
    private class PrRandomPwAction implements ActionListener {
        public void actionPerformed(ActionEvent e) {
            genRandomPassword();
            prSetNeedSave();
        }
    }

    private class EncListAction implements ActionListener {
        public void actionPerformed(ActionEvent e) {
            setEncType();
            prSetNeedSave();
        }
    }
    
    private class PrExpiryAction implements ActionListener {
        public void actionPerformed(ActionEvent e) {
            setPrExpiry();
            prSetNeedSave();
        }
    }
    
    private class PrSaveAction implements ActionListener {
        public void actionPerformed(ActionEvent e) {
            prSave();
        }
    }
    
    private class PrCancelAction implements ActionListener {
        public void actionPerformed(ActionEvent e) {
            prCancel();
        }
    }
    
    private class PrBasicPreviousAction implements ActionListener {
        public void actionPerformed(ActionEvent e) {
            prBasicPrevious();
        }
    }
    
    private class PrBasicNextAction implements ActionListener {
        public void actionPerformed(ActionEvent e) {
            prBasicNext();
        }
    }
    
    private class PrPwExpiryAction implements ActionListener {
        public void actionPerformed(ActionEvent e) {
            setPrPwExpiry();
            prSetNeedSave();
        }
    }
    
    private class PrKvnoAction implements ActionListener {
        public void actionPerformed(ActionEvent e) {
            setPrKvno();
            prSetNeedSave();
        }
    }
    
    private class PrMaxLifetimeAction implements ActionListener {
        public void actionPerformed(ActionEvent e) {
            setPrMaxlife();
            prSetNeedSave();
        }
    }
    
    private class PrMaxRenewalAction implements ActionListener {
        public void actionPerformed(ActionEvent e) {
            setPrMaxrenew();
            prSetNeedSave();
        }
    }
    
    private class PrDetailPreviousAction implements ActionListener {
        public void actionPerformed(ActionEvent e) {
            prDetailPrevious();
        }
    }
    
    private class PrDetailNextAction implements ActionListener {
        public void actionPerformed(ActionEvent e) {
            prDetailNext();
        }
    }
    
    private class PrFlagsPreviousAction implements ActionListener {
        public void actionPerformed(ActionEvent e) {
            prFlagsPrevious();
        }
    }
    
    private class PrLockAcctAction implements ItemListener {
        public void itemStateChanged(ItemEvent e) {
            setPrFlag(Flags.DISALLOW_ALL_TIX);
            prSetNeedSave();
        }
    }
    
    private class PrForcePwChangeAction implements ItemListener {
        public void itemStateChanged(ItemEvent e) {
            setPrFlag(Flags.REQUIRES_PWCHANGE);
            prSetNeedSave();
        }
    }
    
    private class PrAllowPostdatedAction implements ItemListener {
        public void itemStateChanged(ItemEvent e) {
            setPrFlag(Flags.DISALLOW_POSTDATED);
            prSetNeedSave();
        }
    }
    
    private class PrAllowForwardableAction implements ItemListener {
        public void itemStateChanged(ItemEvent e) {
            setPrFlag(Flags.DISALLOW_FORWARDABLE);
            prSetNeedSave();
        }
    }
    
    private class PrAllowRenewableAction implements ItemListener {
        public void itemStateChanged(ItemEvent e) {
            setPrFlag(Flags.DISALLOW_RENEWABLE);
            prSetNeedSave();
        }
    }
    
    private class PrAllowProxiableAction implements ItemListener {
        public void itemStateChanged(ItemEvent e) {
            setPrFlag(Flags.DISALLOW_PROXIABLE);
            prSetNeedSave();
        }
    }
    
    private class PrAllowSvrAction implements ItemListener {
        public void itemStateChanged(ItemEvent e) {
            setPrFlag(Flags.DISALLOW_SVR);
            prSetNeedSave();
        }
    }
    
    private class PrAllowTGTAction implements ItemListener {
        public void itemStateChanged(ItemEvent e) {
            setPrFlag(Flags.DISALLOW_TGT_BASED);
            prSetNeedSave();
        }
    }
    
    private class PrAllowDupAuthAction implements ItemListener {
        public void itemStateChanged(ItemEvent e) {
            setPrFlag(Flags.DISALLOW_DUP_SKEY);
            prSetNeedSave();
        }
    }
    
    private class PrRequirePreAuthAction implements ItemListener {
        public void itemStateChanged(ItemEvent e) {
            setPrFlag(Flags.REQUIRE_PRE_AUTH);
            prSetNeedSave();
        }
    }
    
    private class PrRequireHwPreAuthAction implements ItemListener {
        public void itemStateChanged(ItemEvent e) {
            setPrFlag(Flags.REQUIRE_HW_AUTH);
            prSetNeedSave();
        }
    }
    
    private class PrFlagsNextAction implements ActionListener {
        public void actionPerformed(ActionEvent e) {
            prFlagsDone();
        }
    }
    
    private class PoListPatternAction implements ActionListener {
        public void actionPerformed(ActionEvent e) {
            poPatternComplete();
        }
    }
    
    private class PoListClearAction implements ActionListener {
        public void actionPerformed(ActionEvent e) {
            poPatternClear();
        }
    }
    
    private class PoListModifyAction implements ActionListener {
        public void actionPerformed(ActionEvent e) {
            poSelected();
        }
    }
    
    private class PoListAddAction implements ActionListener {
        public void actionPerformed(ActionEvent e) {
            poAdd();
        }
    }
    
    private class PoListDeleteAction implements ActionListener {
        public void actionPerformed(ActionEvent e) {
            poDelete();
        }
    }
    
    private class PoListDuplicateAction implements ActionListener {
        public void actionPerformed(ActionEvent e) {
            poDuplicate();
        }
    }
    
    private class PoMinPwLengthAction implements ItemListener {
        public void itemStateChanged(ItemEvent e) {
            setPolPwLength();
            poSetNeedSave();
        }
    }
    
    private class PoMinPwClassAction implements ItemListener {
        public void itemStateChanged(ItemEvent e) {
            setPolPwClasses();
            poSetNeedSave();
        }
    }
    
    private class PoSavedPasswordsAction implements ItemListener {
        public void itemStateChanged(ItemEvent e) {
            setPolPwHistory();
            poSetNeedSave();
        }
    }
    
    private class PoMinTicketLifetimeAction implements ActionListener {
        public void actionPerformed(ActionEvent e) {
            setPolMinlife();
            poSetNeedSave();
        }
    }
    
    private class PoMaxTicketLifetimeAction implements ActionListener {
        public void actionPerformed(ActionEvent e) {
            setPolMaxlife();
            poSetNeedSave();
        }
    }
    
    private class PoSaveAction implements ActionListener {
        public void actionPerformed(ActionEvent e) {
            poSave();
        }
    }
    
    private class PoCancelAction implements ActionListener {
        public void actionPerformed(ActionEvent e) {
            poCancel();
        }
    }
    
    private class PoPreviousAction implements ActionListener {
        public void actionPerformed(ActionEvent e) {
            polPrevious();
        }
    }
    
    private class PoDoneAction implements ActionListener {
        public void actionPerformed(ActionEvent e) {
            polDone();
        }
    }
    
    private class GlobalLockAcctAction implements ItemListener {
        public void itemStateChanged(ItemEvent e) {
            setGlobalFlag(Flags.DISALLOW_ALL_TIX);
        }
    }
    
    private class GlobalForcePwChangeAction implements ItemListener {
        public void itemStateChanged(ItemEvent e) {
            setGlobalFlag(Flags.REQUIRES_PWCHANGE);
        }
    }
    
    private class GlobalAllowPostdatedAction implements ItemListener {
        public void itemStateChanged(ItemEvent e) {
            setGlobalFlag(Flags.DISALLOW_POSTDATED);
        }
    }
    
    private class GlobalAllowForwardableAction implements ItemListener {
        public void itemStateChanged(ItemEvent e) {
            setGlobalFlag(Flags.DISALLOW_FORWARDABLE);
        }
    }
    
    private class GlobalAllowRenewableAction implements ItemListener {
        public void itemStateChanged(ItemEvent e) {
            setGlobalFlag(Flags.DISALLOW_RENEWABLE);
        }
    }
    
    private class GlobalAllowProxiableAction implements ItemListener {
        public void itemStateChanged(ItemEvent e) {
            setGlobalFlag(Flags.DISALLOW_PROXIABLE);
        }
    }
    
    private class GlobalAllowSvrAction implements ItemListener {
        public void itemStateChanged(ItemEvent e) {
            setGlobalFlag(Flags.DISALLOW_SVR);
        }
    }
    
    private class GlobalAllowTGTAction implements ItemListener {
        public void itemStateChanged(ItemEvent e) {
            setGlobalFlag(Flags.DISALLOW_TGT_BASED);
        }
    }
    
    private class GlobalAllowDupAuthAction implements ItemListener {
        public void itemStateChanged(ItemEvent e) {
            setGlobalFlag(Flags.DISALLOW_DUP_SKEY);
        }
    }
    
    private class GlobalRequirePreAuthAction implements ItemListener {
        public void itemStateChanged(ItemEvent e) {
            setGlobalFlag(Flags.REQUIRE_PRE_AUTH);
        }
    }
    
    private class GlobalRequireHwPreAuthAction implements ItemListener {
        public void itemStateChanged(ItemEvent e) {
            setGlobalFlag(Flags.REQUIRE_HW_AUTH);
        }
    }
    
    private class GlobalDefaultServerSideAction implements ItemListener {
        public void itemStateChanged(ItemEvent e) {
            setServerSide();
        }
    }
    
    private class GlobalDefaultRenewableLifeAction implements ActionListener {
        public void actionPerformed(ActionEvent e) {
            if (!setGlobalMaxrenew()) {
                ((TextField)e.getSource()).requestFocus();
            }
        }
    }
    
    private class GlobalDefaultLifeAction implements ActionListener {
        public void actionPerformed(ActionEvent e) {
            if (!setGlobalMaxlife()) {
                ((TextField)e.getSource()).requestFocus();
            }
        }
    }
    
    private class GlobalDefaultExpiryAction implements ActionListener {
        public void actionPerformed(ActionEvent e) {
            if (!setGlobalExpiry())
                ((TextField)e.getSource()).requestFocus();
        }
    }
    
    private class GlobalDefaultShowListsAction implements ItemListener {
        public void itemStateChanged(ItemEvent e) {
            setShowLists();
        }
    }
    
    private class GlobalDefaultStaticListsAction implements ItemListener {
        public void itemStateChanged(ItemEvent e) {
            setStaticLists();
        }
    }
    
    private class GlobalDefaultCacheTimeAction implements ActionListener {
        public void actionPerformed(ActionEvent e) {
            setCacheTime();
        }
    }
    
    private class GlobalSaveAction implements ActionListener {
        public void actionPerformed(ActionEvent e) {
            glSave();
        }
    }
    
    private class GlobalApplyAction implements ActionListener {
        public void actionPerformed(ActionEvent e) {
            glApply();
        }
    }
    
    private class GlobalCancelAction implements ActionListener {
        public void actionPerformed(ActionEvent e) {
            glCancel();
        }
    }
    
    private class HelpListener extends MouseAdapter {
        public void mouseClicked(MouseEvent e) {
            showHelp(e.getComponent().getName());
        }
    }
    
    private class CheckboxToggler extends MouseAdapter {
        public void mouseClicked(MouseEvent e) {
            if (e.getComponent() instanceof Checkbox) {
                Checkbox cb = (Checkbox)e.getComponent();
                cb.setState(!cb.getState());
            }
        }
    }
    
    private class ChoiceFixer implements ItemListener {
        private Choice c;
        private String s;
        
        ChoiceFixer(Choice c) {
            this.c = c;
            s = c.getSelectedItem();
            // System.out.println("CF: Saving string "+s);
        }
        
        public void itemStateChanged(ItemEvent e) {
            if (e.getSource() == c && !c.getSelectedItem().equals(s))
                c.select(s);
            // System.out.println("CF: Restoring string "+s);
        }
    }
    
    private class TextFixer extends KeyAdapter {
        private TextField t;
        private String s;
        
        TextFixer(TextField t) {
            this.t = t;
            s = t.getText();
            // System.out.println("TF: Saving string "+s);
        }
        
        public void keyTyped(KeyEvent e) {
            if (e.getSource() == t)
                t.setText(s);
            // System.out.println("TF: Restoring string "+s);
        }
    }
    
    /*
     * End of the million listeners
     */
    
    /**
     * Call rb.getString(), but catch exception and returns English
     * key so that small spelling errors don't cripple the GUI
     *
     */
    private static final String getString(String key) {
        try {
            String res = rb.getString(key);
            return res;
        } catch (MissingResourceException e) {
            System.out.println("Missing resource "+key+", using English.");
            return key;
        }
    }
    
    private static final String getHelpString(String key) {
        String res;
        try {
            res = hrb.getString(key);
        } catch (MissingResourceException e) {
            res = "Missing help on key "+key;
        }
        return res;
    }
    
    
    /**
     * Check the privileges this principal has to see what we should not try.
     */
    private boolean checkPrivs() {
        boolean okay = true;
        String lpriv = (((privs & PRIV_ADD) == 0) ? "A" : "a")
	    + (((privs & PRIV_DELETE) == 0) ? "D" : "d")
	    + (((privs & PRIV_MODIFY) == 0) ? "M" : "m")
	    + (((privs & PRIV_CHANGEPW) == 0) ? "C" : "c")
	    + (((privs & PRIV_INQUIRE) == 0) ? "I" : "i")
	    + (((privs & PRIV_LIST) == 0) ? "L" : "l");
        // System.out.println("Privileges are "+lpriv+" "
        // 			+(new Integer(privs).toString()));
        /**
         * Having modify is not useful if we can't either add or see
         * old values
         */
        if ((privs & (PRIV_MODIFY | PRIV_INQUIRE | PRIV_ADD)) == PRIV_MODIFY)
            okay = false;
        /* Having changepw without inquire is not useful */
        if (privs == PRIV_CHANGEPW)
            okay = false;
        if (!okay) {
            showLoginError(
		   getString("Insufficient privileges to use gkadmin: ")+lpriv
			   +getString(" Please try using another principal."));
            return false;
        }
        return true;
    }
    
    /*
     * Try to cope with the privileges we have.
     */
    private void reactToPrivs() {
        Boolean off = new Boolean(false);
        
        /*
         * If we don't have the Add privilege, we turn off "Create New"
         * and "Duplicate".  "Duplicate" is also handled in prSelValid/
         * poSelValid because it's sensitive to selection from the lists.
         */
        if ((privs & PRIV_ADD) == 0) {
            // System.out.println("Disabling Create New buttons");
            gui.PrListAdd.set("enabled" /* NOI18N */, off);
            gui.PoListAdd.set("enabled" /* NOI18N */, off);
            gui.PrListDuplicate.set("enabled" /* NOI18N */, off);
            gui.PoListDuplicate.set("enabled" /* NOI18N */, off);
        }
        
        /*
         * If we don't have the Delete privilege, we turn off "Delete".
         * This is also done in prSelValid/poSelValid because it is
         * thought about when a list item is selected.
         */
        if ((privs & PRIV_DELETE) == 0) {
            // System.out.println("Disabling Delete buttons");
            gui.PrListDelete.set("enabled" /* NOI18N */, off);
            gui.PoListDelete.set("enabled" /* NOI18N */, off);
        }
        
        /*
         * If we don't have changepw, disable textfield and random button.
         * Add needs to turn this on again for an add operation only.
         */
        if ((privs & PRIV_CHANGEPW) == 0) {
            // System.out.println("Disabling password components");
            gui.PrPassword.set("enabled" /* NOI18N */, off);
            gui.PrBasicRandomPw.set("enabled" /* NOI18N */, off);
            gui.EncList.set("enabled" /* NOI18N */, off);
        }
        
        /*
         * If we don't have inquire, we can't get an existing principal
         * to duplicate, and permitting modification seems a bad idea.
         * We can still use the panels if we can add.  These will also
         * get dealt with in prSelValid/poSelValid.
         */
        if ((privs & PRIV_INQUIRE) == 0) {
            // System.out.println("Disabling Modify buttons");
            gui.PrListModify.set("enabled" /* NOI18N */, off);
            gui.PoListModify.set("enabled" /* NOI18N */, off);
            gui.PrListDuplicate.set("enabled" /* NOI18N */, off);
            gui.PoListDuplicate.set("enabled" /* NOI18N */, off);
        }
        
        /*
         * If we don't have Modify or Add but do have Inquire, we want to
         * turn off save and cancel buttons, as well as all principal and
         * policy components to prevent any changes.
         */
        if ((privs & (PRIV_MODIFY | PRIV_ADD)) == 0) {
            // System.out.println("Disabling attribute components");
            enablePrAttributes(off);
            enablePoAttributes(off);
        }
        
        /*
         * We may have no list privs, or we may have turned off lists.
         * Set things up accordingly.
         */
        noLists = ((privs & PRIV_LIST) == 0 || !defaults.getShowLists());
        fixListPanels();
    }
    
    private void fixListPanels() {
        /*
         * If we can't use lists, we won't fetch lists, which means the
         * only way to get a principal is to type something into the
         * list pattern field.  Relabel those so they work better.
         */
        String s;
        Boolean yes = new Boolean(true);
        Boolean no = new Boolean(false);
        if (noLists) {
            // System.out.println("Hijacking list pattern stuff");
            gui.PrListLabel.set("enabled" /* NOI18N */, no);
            gui.PoListLabel.set("enabled" /* NOI18N */, no);
            s = getString("Principal Name:");
            gui.PrSearchLab.set("text" /* NOI18N */, s);
            s = getString("Policy Name:");
            gui.PoListPatternLabel.set("text" /* NOI18N */, s);
            s = getString("Clear Name");
            gui.PrListClear.set("text" /* NOI18N */, s);
            gui.PoListClear.set("text" /* NOI18N */, s);
            gui.Prlist.set("enabled", no);
            gui.Pollist.set("enabled", no);
            gui.refreshPrincipals.set("enabled", no);
            gui.refreshPolicies.set("enabled", no);
            gui.Prlist.set("selectedItem" /* NOI18N */, null);
            gui.Pollist.set("selectedItem" /* NOI18N */, null);
            gui.PrintPrlist.set("enabled" /* NOI18N */, no);
            gui.PrintPollist.set("enabled" /* NOI18N */, no);
        } else {
            gui.PrListLabel.set("enabled" /* NOI18N */, yes);
            gui.PoListLabel.set("enabled" /* NOI18N */, yes);
            s = getString("Filter Pattern:");
            gui.PrSearchLab.set("text" /* NOI18N */, s);
            gui.PoListPatternLabel.set("text" /* NOI18N */, s);
            s = getString("Clear Filter");
            gui.PrListClear.set("text" /* NOI18N */, s);
            gui.PoListClear.set("text" /* NOI18N */, s);
            gui.Prlist.set("enabled", yes);
            gui.Pollist.set("enabled", yes);
            gui.refreshPrincipals.set("enabled", yes);
            gui.refreshPolicies.set("enabled", yes);
            gui.PrintPrlist.set("enabled", yes);
            gui.PrintPollist.set("enabled", yes);
        }
    }
    
    private void enablePrAttributes(Boolean sense) {
        // Basics
        gui.PrPolicy.set("enabled" /* NOI18N */, sense);
        gui.PrExpiry.set("enabled" /* NOI18N */, sense);
        gui.EncList.set("enabled" /* NOI18N */, sense);
        gui.PrComments.set("enabled" /* NOI18N */, sense);
        // Details
        gui.PrPwExpiry.set("enabled" /* NOI18N */, sense);
        gui.PrKvno.set("enabled" /* NOI18N */, sense);
        gui.PrMaxLifetime.set("enabled" /* NOI18N */, sense);
        gui.PrMaxRenewal.set("enabled" /* NOI18N */, sense);
        // Flags
        gui.PrLockAcct.set("enabled" /* NOI18N */, sense);
        gui.PrForcePwChange.set("enabled" /* NOI18N */, sense);
        gui.PrAllowPostdated.set("enabled" /* NOI18N */, sense);
        gui.PrAllowForwardable.set("enabled" /* NOI18N */, sense);
        gui.PrAllowRenewable.set("enabled" /* NOI18N */, sense);
        gui.PrAllowProxiable.set("enabled" /* NOI18N */, sense);
        gui.PrAllowSvr.set("enabled" /* NOI18N */, sense);
        gui.PrAllowTGT.set("enabled" /* NOI18N */, sense);
        gui.PrAllowDupAuth.set("enabled" /* NOI18N */, sense);
        gui.PrRequirePreAuth.set("enabled" /* NOI18N */, sense);
        gui.PrRequireHwPreAuth.set("enabled" /* NOI18N */, sense);
    }
    
    private void enablePoAttributes(Boolean sense) {
        // Policy
        gui.PoMinPwLength.set("enabled" /* NOI18N */, sense);
        gui.PoMinPwClass.set("enabled" /* NOI18N */, sense);
        gui.PoSavedPasswords.set("enabled" /* NOI18N */, sense);
        gui.PoMinTicketLifetime.set("enabled" /* NOI18N */, sense);
        gui.PoMaxTicketLifetime.set("enabled" /* NOI18N */, sense);
    }
    
    /**
     * Show context-sensitive help from HelpData class
     *
     */
    public void showHelp(String what) {
        String res;
        
        // System.out.println("Help on "+what);
        if (cHelp == null) {
            // System.out.println("showHelp called without context.");
            return;
        }
        res = getHelpString(what);
        cHelp.setText(res);
        cHelp.setVisible(true);
    }
    
    /**
     * Holds an association between an object and a listener, keeping
     * track of the types so that they can be assigned en masse later
     *
     */
    private class Association extends Object {
        Object Object;
        EventListener Listener;
        int Type;
        
        public Association(Object obj, EventListener list, int type) {
            Object = obj;
            Listener = list;
            Type = type;
        }
    }
    
    /**
     * Action listeners for the defaults editing frame.
     */
    
    private class DefaultsContextSensitiveHelpListener
	implements ActionListener {
        public void actionPerformed(ActionEvent e) {
            if (defaultsHelpMode)
                showHelp("ContextSensitiveHelp");
            else
                contextHelp(defaultsEditingFrame);
        }
    }
    
    /**
     * This class launches the dateTimeDialog box when the user presses
     * the "..." button. An instance of this is shared by all the
     * buttons that are meant to do this.
     */
    private class DateTimeListener  implements ActionListener {
        
        private TextField tf;
        private Frame frame;
        
        DateTimeListener(TextField tf, Frame frame) {
            this.tf = tf;
            this.frame = frame;
        }
        
        public void actionPerformed(ActionEvent e) {
            if (mainHelpMode && frame == realMainFrame)
                showHelp("DateTime...");
            else
                if (defaultsHelpMode && frame == defaultsEditingFrame)
		    showHelp("DateTime...");
		else
		    getDateTimeFromDialogBox(tf, frame);
        } // actionPerformed
    } // class DateTimeListener

    /**
     * This class launches the EncListDialog box when the user presses
     * the "..." button. An instance of this is shared by all the
     * buttons that are meant to do this.
     */
    private class EncListListener implements ActionListener {
        
        private TextField tf;
        private Frame frame;
        
        EncListListener(TextField tf, Frame frame) {
            this.tf = tf;
            this.frame = frame;
        }
        
        public void actionPerformed(ActionEvent e) {
            if (mainHelpMode && frame == realMainFrame)
                showHelp("EncList...");
            else
                if (defaultsHelpMode && frame == defaultsEditingFrame)
		    showHelp("EncList...");
		else
		    getEncListFromDialogBox(tf, frame);
        } // actionPerformed
    } // class EncListListener
    
    /**
     * This class launches the durrationHelper dialog box when the user presses
     * the "..." button. An instance of this is shared by all the
     * buttons that are meant to do this.
     */
    private class DurationListener implements ActionListener {
        
        private TextField tf;
        private Frame frame;
        
        DurationListener(TextField tf, Frame frame) {
            this.tf = tf;
            this.frame = frame;
        }
        
        public void actionPerformed(ActionEvent e) {
            if (mainHelpMode && frame == realMainFrame)
                showHelp("Duration...");
            else
                if (defaultsHelpMode && frame == defaultsEditingFrame)
		    showHelp("Duration...");
		else
		    getDurationFromDialogBox(tf, frame);
        }
    }
    
    
    private class KeystrokeDetector extends KeyAdapter {
        
        private int changeType; // principal or policy change
        
        public KeystrokeDetector(int type) {
            changeType = type;
        }
        
        public void keyTyped(KeyEvent e) {
            reactToKey(changeType);
            ((TextField)e.getComponent()).requestFocus();
        }
    }
    
    private void reactToKey(int changeType) {
        switch (changeType) {
	case PRINCIPAL_EDITING:
            prSetNeedSave();
            break;
            
	case POLICY_EDITING:
            poSetNeedSave();
            break;
            
	case DEFAULTS_EDITING:
            glSetNeedSave();
            break;
            
	case PRINCIPAL_LIST:
            if (noLists)
                prSelValid(true);
            break;
            
	case POLICY_LIST:
            if (noLists)
                poSelValid(true);
            break;
        }
    }
    
    private static String enclose(String value) {
        return new StringBuffer("\"").append(value).append("\"").toString();
    }
    
    private static String constructDurationExample() {
        StringBuffer result = new StringBuffer(getString("Example: "));
        result.append(enclose(nf.format(28800)));
        return result.toString();
    }
    
    private static String constructDateExample() {
        StringBuffer result = new StringBuffer(getString("Example: "));
        result.append(enclose(df.format(new Date())));
        result.append(' ').append(getString("or")).append(' ');
        result.append(enclose(neverString));
        return result.toString();
    }
    
    private static String constructNumberExample() {
        StringBuffer result =  new StringBuffer(getString("Example: "));
        result.append(enclose(nf.format(4)));
        return result.toString();
    }
    
    static {
        rb = ResourceBundle.getBundle("GuiResource" /* NOI18N */);
        hrb = ResourceBundle.getBundle("HelpData" /* NOI18N */);
        df = DateFormat.getDateTimeInstance(DateFormat.MEDIUM,
					    DateFormat.MEDIUM);
        nf = NumberFormat.getInstance();
        
        neverString = getString("Never");
        
        toolkit = Toolkit.getDefaultToolkit();
        
        durationErrorText = new String[] {getHelpString("Bad Duration"),
					  constructDurationExample()};
        dateErrorText = new String[] {getHelpString("Bad Date"),
				      constructDateExample()};
        numberErrorText = new String[] {getHelpString("Bad Number"),
					constructNumberExample()};
    }
    
}
