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
 * Copyright (c) 1999, 2010, Oracle and/or its affiliates. All rights reserved.
 *
 * pmResources.java
 * Localizable resource strings
 */

package com.sun.admin.pm.client;

import java.util.*;

/*
 * In accordance with the ResourceBundle pattern,
 * each line in this file defines a tuple containing
 * two strings:
 *	string 1 is the key used by the app -- DO NOT LOCALIZE
 *	string 2 is the string to be localized
 *
 * For example, in the tuple
 *	{"info_name", "Oracle Solaris Print Manager"}
 *
 *	"info_name" is the resource key that must
 *			not be modified in any way
 *
 *       "Oracle Solaris Print Manager" is the corresponding
 *                        text to be localized
 */

public class pmResources extends ListResourceBundle {
    static final Object[][] pmBundlecontents = {

	/*
	 * Descriptive strings used in the 'About' dialog
	 */
        {"info_name", "Oracle Solaris Print Manager"},
        {"info_version", "Version 1.0"},
	{"info_authors", "Authors: Wendy Phillips"},

	// Note: the copyright notice is displayed on two lines.
	{"info_copyright1", "Copyright \251 "},
	/* JSTYLED */
	{"info_copyright2", " (c) Oracle and/or its affiliates. All rights reserved."},

	/*
	 * Main window title, the application name
	 */
	{"Solaris.Print.Manager", "Oracle Solaris Print Manager"},


        /*
         * Main window column labels for printer list
         */
        {"Printer.Name", "Printer Name"},
        {"Printer.Server", "Printer Server"},
        {"Description", "Description"},


	/*
	 * Main window menu titles and mnemonics
	 */
        {"Print.Manager", "Print Manager"},
        {"Print.Manager.mnemonic", "M"},

        {"Printer", "Printer" },
        {"Printer.mnemonic", "P"},

        {"Tools", "Tools" },
        {"Tools.mnemonic", "T"},

	{"Help", "Help"},
	{"Help.mnemonic", "H"},


	/*
	 * Main window data labels
	 */
        {"Default.Printer:", "Default Printer:"},
        {"Domain:", "Domain:"},
	{"Host:", "Host:"},


	/*
	 * 'Printer Manager' menu item labels and mnemonics
	 */
        {"Select.Naming.Service", "Select Naming Service..."},
        {"Select.Naming.Service.mnemonic", "N"},

        {"Show.Command-Line.Console", "Show Command-Line Console"},
        {"Show.Command-Line.Console.mnemonic", "L"},

        {"Confirm.All.Actions", "Confirm All Actions"},
        {"Confirm.All.Actions.mnemonic", "C"},

	{"Use.PPD.files", "Use PPD files"},
	{"Use.PPD.files.mnemonic", "F"},

	{"Use.localhost", "Use localhost for Printer Server"},
	{"Use.localhost.mnemonic", "U"},

	{"Exit", "Exit"},
	{"Exit.mnemonic", "X"},

	/*
	 * 'Printer' menu item labels and mnemonics
	 */
	{"Add.Access.to.Printer...", "Add Access to Printer..."},
	{"Add.Access.to.Printer.mnemonic", "A"},

        {"New.Attached.Printer...", "New Attached Printer..."},
        {"New.Attached.Printer.mnemonic", "T"},

        {"New.Network.Printer...", "New Network Printer..."},
        {"New.Network.Printer.mnemonic", "N"},

        {"Modify.Printer.Properties...", "Modify Printer Properties..."},
        {"Modify.Printer.Properties.mnemonic", "M"},

        {"Delete.Printer...", "Delete Printer..."},
        {"Delete.Printer.mnemonic", "D"},


	/*
	 * 'Tools' menu item labels
	 */
	{"Find.Printer", "Find Printer..."},
	{"Find.Printer.mnemonic", "F"},


	/*
	 * 'Help' menu item labels
	 */
        {"Overview", "Overview"},
        {"Overview.mnemonic", "O"},

        {"On.Help", "On Help"},
        {"On.Help.mnemonic", "H"},

	{"About.Print.Manager", "About Print Manager..."},
	{"About.Print.Manager.mnemonic", "A"},

	{"Print.Manager.Settings", "Print Manager Settings"},
	{"Print.Manager.Settings.mnemonic", "P"},


	/*
	 * 'Select Naming Service' dialog title
	 */
        {"SPM:Select.Naming.Service",
                "Oracle Solaris Print Manager: Select Naming Service"},


	/*
	 * 'Command-Line Console' dialog title
	 */
        {"SPM:Command-Line.Console",
                "Oracle Solaris Print Manager: Command-Line Console"},


	/*
	 * 'Delete Printer' confirmation dialog title
	 */
        {"SPM:Delete.Printer", "Oracle Solaris Print Manager: Delete Printer"},


	/*
	 * 'Add Access to Printer' dialog title
	 */
        {"SPM:Add.Access.To.Printer",
                "Oracle Solaris Print Manager: Add Access to Printer"},


	/*
	 * 'Add Attached Printer' dialog title
	 */
        {"SPM:New.Attached.Printer",
                "Oracle Solaris Print Manager: New Attached Printer"},


	/*
	 * 'Add Network Printer' dialog title
	 */
        {"SPM:New.Network.Printer",
                "Oracle Solaris Print Manager: New Network Printer"},


	/*
	 * 'Modify Printer Properties' dialog title
	 */
        {"SPM:Modify.Printer.Properties",
                "Oracle Solaris Print Manager: Modify Printer Properties"},


	/*
	 * 'Find Printer' dialog title
	 */
        {"SPM:Find.Printer", "Oracle Solaris Print Manager: Find Printer"},


	/*
	 * 'Help' dialog title
	 */
        {"SPM:Help", "Oracle Solaris Print Manager: Help"},


        /*
         * 'About Print Manager' dialog title
         */
        {"About.Solaris.Print.Manager", "About Oracle Solaris Print Manager"},


	/*
	 * 'User Input of Printer Port' dialog title
	 */
        {"SPM:Specify.Printer.Port",
		"Oracle Solaris Print Manager: Specify Printer Port"},


	/*
	 * 'User Input of Printer Type' dialog title
	 */
        {"SPM:Specify.Printer.Type",
		"Oracle Solaris Print Manager: Specify Printer Type"},


	/*
	 * 'NIS Authentication' dialog title
	 */
	{"NIS.Authentication", "NIS Authentication"},

	/*
	 * 'LDAP Authentication' dialog title
	 */
	{"LDAP.Authentication", "LDAP Authentication"},


	/*
	 * 'Action Confirmation' dialog title
	 */
	{"Action.Confirmation", "Action Confirmation"},


	/*
	 * Button labels and mnemonics
	 */
        {"Apply", "Apply"},
        {"Apply.mnemonic", "P"},

        {"Cancel", "Cancel"},
        {"Cancel.mnemonic", "C"},

        {"Clear", "Clear"},
        {"Clear.mnemonic", "L"},

        {"Dismiss", "Dismiss"},
        {"Dismiss.mnemonic", "D"},

        // {"Button Help", "Help"},
        // {"Button.Help.mnemonic", "H"},

        {"OK", "OK"},
        {"OK.mnemonic", "O"},

        {"Reset", "Reset"},
        {"Reset.mnemonic", "R"},

        {"Find", "Find"},
        {"Find.mnemonic", "F"},

        {"Show", "Show"},
        {"Show.mnemonic", "S"},

        {"Forward", "Forward"},
        {"Forward.mnemonic", "W"},

        {"Back", "Back"},
        {"Back.mnemonic", "B"},

        {"Add", "Add"},
        {"Add.mnemonic", "A"},

        {"Delete", "Delete"},
        {"Delete.mnemonic", "D"},


	/*
	 * Actions performed by the application
	 * as displayed in the Command-Line Console
	 */
	{"New.Attached.Printer", "New Attached Printer"},
	{"New.Network.Printer", "New Network Printer"},
	{"Modify.Printer.Properties", "Modify Printer Properties"},
	{"Delete.Printer", "Delete Printer"},
	{"Add.Access.To.Printer", "Add Access To Printer"},


	/*
	 * Prompts: messages to user describing required input.
	 */
	{"Enter.name.of.printer.to.find",
		"Enter the name of a printer to find:"},
	{"Please.confirm.deletion.of.printer",
		"Please confirm deletion of printer "},
	{"Enter.printer.type:", "Enter printer type:"},
	{"Enter.printer.port.or.file", "Enter printer port or file:"},


	/*
	 * 'Help' dialog tabbed-pane tab selection labels
	 */
        {"View", "View"},
        {"Index", "Index"},
        {"Search", "Search"},


	/*
	 * 'Help' dialog prompts, labels, and mnemonics
	 */
        {"Help.on:", "Help on:"},
        {"See.also:", "See also:"},

	{"Matching.entries:", "Matching entries:"},
	{"Matching.entries:.mnemonic", "M"},

	{"Search.help.index.for:", "Search help index for: "},
	{"Search.help.index.for:.mnemonic", "S"},

        {"Search.Results:", "Search Results:"},
        {"Search.Results:.mnemonic", "R"},

        {"Keywords:", "Keywords: "},
        {"Keywords:.mnemonic", "K"},


	/*
	 * 'Help' dialog descriptive messages to provide
	 * assistance in using the features.
	 */

	/*
	 * The following two labels create one message, displayed on
	 * two adjacent lines.
	 */
        {"To.search.the.index...",
		 "To search the index of help articles alphabetically,"},
        {"type.your.query.below...",
		 "type your query below then select the desired article."},

	/*
	 * The following two labels create one message, displayed on
	 * two adjacent lines.
	 */
        {"To.find.help.articles...",
		"To find help articles about a particular topic,"},
        {"enter.keywords.below...",
		 "enter keywords below then press the Find button."},


	/*
	 * Prompts/labels on 'Install Printer' and 'Modify Printer' dialogs
	 */
	{"Printer.Name:", "Printer Name:"},
	{"Printer.Server:", "Printer Server:"},
	{"Description:", "Description:"},
	{"Printer.Port:", "Printer Port:"},
	{"Not.Selected", "Not Selected"},
	{"Printer.Type:", "Printer Type:"},
	{"Printer.Driver:", "Printer Driver:"},
	{"No.PPD.Files.Found", "No PPD files found"},
	{"Printer.Make:", "Printer Make:"},
	{"Printer.Model:", "Printer Model:"},
	{"No.Models.Found", "No Models Found"},
	{"File.Contents:", "File Contents:"},
	{"Fault.Notification:", "Fault Notification:"},
	{"Destination:", "Destination:"},
	{"Protocol:", "Protocol:"},
	{"Options:", "Options:"},
	{"Banner:", "Banner:"},
	{"Options.mnemonic", "O"},
	{"Option:", "Option:"},
	{"User.Access.List:", "User Access List:"},


	/*
	 * Combo item allowing custom 'Printer Port' selection
	 * See "Printer.Port:" above.
	 */
	{"Other...", "Other..."},


	/*
	 * Combo items specifying printer 'File Contents'
	 * See "File.Contents" above.
	 */
	{"PostScript", "PostScript"},
	{"ASCII", "ASCII"},
	{"None", "None"},
	{"Any", "Any"},
	{"Both.PostScript.and.ASCII", "Both PostScript and ASCII"},


	/*
	 * Combo items specifying 'Fault Notification' options.
	 * See "Fault.Notification" above.
	 */
	{"Write.to.Superuser", "Write to Superuser"},
	{"Mail.to.Superuser", "Mail to Superuser"},


	/*
	 * Labels for checkboxes used in 'Install Printer' and
	 * 'Modify Printer' dialogs
	 */
	{"Default.Printer", "Default Printer"},
	{"Always.Print.Banner", "Always Print Banner"},
	{"User.Selectable.Default.On", "User Selectable - Default=on"},
	{"Never.Print.Banner", "Never Print Banner"},


	/*
	 * Prompt for 'Select Naming Service' combo
	 */
	{"Naming.Service:", "Naming Service:"},


	/*
	 * Descriptive label for 'NIS Authentication' dialog
	 */
	{"Enter.NIS.authentication.data.", "Enter NIS authentication data."},

	/*
	 * Descriptive label for 'LDAP Authentication' dialog
	 */
	{"Enter.LDAP.authentication.data.", "Enter LDAP authentication data."},


	/*
	 * Prompts and mnemonics for 'NIS Authentication' dialog
	 */
	{"Hostname:", "Hostname:"},
	{"Hostname.mnemonic", "H"},

	{"Username:", "Username:"},
	{"Username.mnemonic", "U"},

	{"Password:", "Password:"},
	{"Password.mnemonic", "P"},

	/*
	 * Prompts for 'LDAP Authentication' dialog
	 */
	{"LDAP.Server:", "LDAP Server:"},
	{"Distinguished.Name:", "Distinguished Name:"},
	{"Password:", "Password:"},


	/*
	 * Error dialog titles
	 */
	{"Application.Error", "Application Error"},
	{"Unknown.Application.Error", "Unknown Application Error"},
	{"Command.Failed.Error", "Command Failed Error"},
	{"Error", "Error"},
	{"Warning", "Warning"},


        /*
         * Error messages displayed to user
         */
        {"Item.not.found:", "Item not found: "},
        {"No.information.available.", "No information available."},
	{"Unable.to.find.printer", "Unable to find printer "},
	{"Printer.delete.operation.failed.",
		"Printer delete operation failed."},
	{"Invalid.printer.type.", "Invalid printer type."},
	{"Device.missing.or.not.writeable.",
		"Device missing or not writeable."},
        {"Printer.name.required.", "Printer name required."},
	{"Printer.Port.Selection.required", "Printer Port Selection required."},
	{"Printer.Make.Selection.required", "Printer Make Selection required."},
        {"Printer.name.invalid.", "Printer name invalid."},
        {"Server.name.required.", "Server name required."},
        {"Server.name.invalid.", "Server name invalid."},
        {"User.Cancelled.Login", "User Cancelled Login"},
        {"Destination.required.", "Destination required."},
        {"User.Cancelled.Login", "User Cancelled Login"},
	{"Destination.invalid.", "Destination invalid."},
	{"Operation.Cancelled", "Operation Cancelled"},
	{"Login.Failure", "Login Failure"},
	{"Required.login.failed.", "Required login failed."},
	{"Login.Authorization.Failed", "Login Authorization Failed"},
	{"Cannot.modify.this.queue;ppdcache.file.missing.",
		"Cannot modify this queue; ppdcache file missing."},
	{"Cannot.modify.this.queue;PPD.file.not.in.ppdcache.",
		"Cannot modify this queue; PPD file not in ppdcache."},
	{"Request.cannot.be.completed.", "Request cannot be completed."},
	{"Could.not.get.local.hostname", "Could not get local hostname"},
	{"The.specified.printer.already.exists.",
		"The specified printer already exists."},
	{"The.server.must.be.a.remote.server.",
		"The server must be a remote server."},
	{"Required.login.failed.", "Required login failed."},
	{"Invalid.printer.type.", "Invalid printer type."},
	{"Invalid.username", "Invalid username"},
	{"Device.missing.or.not.writeable.",
		"Device missing or not writeable."},
	{"User.cancelled.login.", "User cancelled login."},
        {"Nothing.matched.", "Nothing matched."},
        {"The.specified.printer.already.exists.",
                "The specified printer already exists."},
        {"The.selected.printer.does.not.exist.",
                "The selected printer does not exist."},
        {"User.not.authorized.to.modify.this.namespace.",
                "User not authorized to modify this namespace."},
        {"Cannot.get.list.of.printers.Exiting.",
                "Cannot get list of printers. Exiting."},
        {"LDAP.server.name.required.",
                "LDAP Server Name required."},
        {"LDAP.Distinguished.name.required.",
                "LDAP Distinguished Name required."},
        {"LDAP.Password.required.",
                "LDAP Password required."},


	/*
	 * Prompts for 'Confirm Action' dialogs
	 */
	{"Continue.action.for.this.printer?",
		"Continue action for this printer?"},
	{"Continue.creating.access.for.this.printer?",
		"Continue creating access for this printer?"},


	/*
	 * The help subsystem builds a database of searchable
	 * keywords based in part on the title of each help
	 * article.  In order to avoid excessive false hits, the
	 * following words are ignored when adding title words
	 * to the searchable keyword list.
	 *
	 * If this list is left empty, all the words in the title of
	 * each help article will be added to the keywords database.
	 */
        {"help.ignore.words", "to an a of if the and or"},



	/*
	 * Title for the authorization dialog which is invoked by
	 * the printmgr executable.
	 */
	{"Authentication.required", "Authentication Required"},

	/*
	 * Prompt for the printmgr authorization dialog.
	 * This is displayed with line breaks.
	 */
	/* JSTYLED */
	{"Root.access.is.required", "Root access is required for full functionality.\nYou may authenticate as root or continue\nwith limited functionality."},

	/*
	 * Buttons for the authorization dialog.
	 */
	{"Authenticate", "Authenticate"},
	{"Authenticate.mnemonic", "A"},

	{"Continue", "Continue"},
	{"Continue.mnemonic", "N"},

	/*
	 * Title for the root password request dialog invoked by printmgr.
	 */
	{"Root.authentication", "Root Authentication"},

	/*
	 * Prompt for the root password request dialog.
	 */
	{"Enter.root.password", "Enter root password"},

	/*
	 * Prompt for the root password request dialog.
	 */
	{"Invalid.password", "Invalid password entered.  Retry?"},

	/*
	 * Just a placeholder, never used.
	 */
	{"dummy", ""}
    };

    public Object[][] getContents() {
	    return pmBundlecontents;
    }
}
