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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

import java.util.ListResourceBundle;

// On-line spot help.  Defined as strings of a "contents" object.

public class HelpData extends ListResourceBundle {
    public Object [][] getContents() {
        return contents;
    }
    
    static final Object [][] contents = {
        
        //
        //  Main Login Panel
        //
        
        {"MainLoginPanel",
	 // Not currently available in GUI
	 "This window enables you to log in and use the SEAM Administration"
	 +"Tool. The default information that initially fills in the fields"
	 +" is read from the system's /etc/krb5/krb5.conf file (except"
	 +" for the principal name)."},
        
        
        {"LoginName",
	 "The principal name to log in with (without realm included)."
	 +"In order to use the SEAM Administration Tool, your principal"
	 +" must have the appropriate privileges specified in the master"
	 +" KDC's kadm5.acl"
	 +" file.\n"
	 +" \n"
	 +"The default principal name consists of your user name with the"
	 +" 'admin' instance appended. For example, 'jdb/admin'."},
        
        
        {"LoginPass",
	 "The password for the principal."},
        
        
        {"LoginRealm",
	 "The Kerberos realm, which is similar to a DNS domain."
	 +"In most cases, the realm name is your domain name, and it should"
	 +" be upper-case. For example, 'MTN.ACME.COM'.\n"
	 +" \n"
	 +"Each realm has one master KDC and may include slave"
	 +" KDCs that contain read-only copies of the master."
	 +"The default realm is read from the system's"
	 +" /etc/krb5/krb5.conf file."},
        
        
        {"LoginServer",
	 "The master KDC where the Kerberos administration server, kadmind,"
	 +" is running and where the KDC (Key Distribution Center) is located."
	 +"You must provide a fully-qualified host name for the master KDC.\n"
	 +" \n"
	 +"The default admin server is read from the"
	 +" system's /etc/krb5/krb5.conf file."},
        
        
        {"LoginOK",
	 "Checks the information"
	 +" in this window, and if valid, logs you into the tool."},
        
        
        {"LoginStartOver",
	 "Resets all fields in this window to their initial"
	 +" settings (when the tool was started)."},
        
        
        //
        // Panel Tabs
        //
        
        
        {"PrincipalTab",
	 "Sends you to the list of principals. If you are currently"
	 +" working on a principal or policy and you've made"
	 +" changes, you'll be prompted to cancel or save"
	 +" the changes before being sent to Principal List panel."},
        
        
        {"PolicyTab",
	 "Sends you to the list of policies. If you are currently working on a"
	 +" principal or policy and you've made changes, you'll be prompted to"
	 +" cancel or save the changes before being sent to Policy"
	 +" List panel."},
        
        
        
        //
        // Principal List Panel
        //
        
        
        {"PrinListPanel",
	 // Not currently available in GUI
	 "This panel enables you to select a principal from the list to modify,"
	 +" delete, and duplicate. You can also create a new principal.\n"
	 +" \n"
	 +"  principal is an entity to which tickets may be assigned, generally"
	 +" of the form <primary>/<instance>@<REALM>. For example,"
	 +" jdb/admin@MTN.ACME.COM.\n"
	 +" \n"
	 +" display a specific principal or"
	 +" sublist of principals, enter a filter string in the Filter Pattern"
	 +" field and press"
	 +" return.\n"
	 +" \n"
	 +"To perform an operation on a principal, select it from the list and"
	 +" click the appropriate button. To create a new principal, click"
	 +" Create New."},
        
        
        {"PrList",
	 "Displays all the available principals in the specified realm.\n"
	 +" \n"
	 +"To select a principal, click on its name in the list;"
	 +" double-clicking on a principal is equivalent to selecting"
	 +" the principal and clicking Modify."},
        
        
        {"PrNoList",
	 "This list panel is blank when you don't have list privileges"
	 +" or you've chosen not to show lists."},
        
        
        {"PrListPattern",
	 "Enables you to apply a filter on the available principals to"
	 +" display a particular principal or sublist of principals."
	 +"The filter string you enter may consist of one or more"
	 +" characters. And, because the filter mechanism is case"
	 +" sensitive, you need to use the appropriate upper-case and"
	 +" lower-case letters for the filter.\n"
	 +" \n"
	 +"For example, entering 'user' for the filter would match"
	 +" and display principals such as 'enguser', 'user1',"
	 +" and 'useradmin'.\n"
	 +" '\n"
	 +"To display a particular principal or sublist of"
	 +" principals, enter a filter string and press return.\n"
	 +" \n"
	 +"To display the entire list of principals, click Clear"
	 +" Filter(or clear the Filter Pattern field and press return)."},
        
        
        {"PrNameNoList",
	 "When the principal list is not displayed,"
	 +" you must enter principal names in this field to perform"
	 +" operations on them. Entering a name is equivalent to selecting"
	 +" an item from the principal list in normal operation.\n"
	 +" \n"
	 +"To clear the principal entry, click Clear Name (or clear the"
	 +" Name field and press return)."},
        
        
        {"PrListClear",
	 "Clears the filter and displays the full list of available",
	 " principals."},
        
        
        {"PrNoListClear",
	 "Clears the Name field."},
        
        
        {"PrListModify",
	 "Opens a series of panels that enable you to modify the selected"
	 +" principal, such as the principal's password, expiry date,"
	 +" and policy."},
        
        
        {"PrListAdd",
	 "Opens a series of panels that enable you to create a new principal."
	 +" The panels will have some of the fields already filled in with"
	 +" default values, which you can set up by choosing Properties from"
	 +" the Edit menu.\n"
	 +" \n"
	 +"The Duplicate button performs the same function; however,"
	 +" instead of the fields filled in with default values, the fields"
	 +" are filled in with the same values as the selected principal."},
        
        
        {"PrListDelete",
	 "Deletes the selected principal from the Kerberos realm.  The deleted"
	 +" principal can no longer be assigned Kerberos tickets."},
        
        
        {"PrListDuplicate",
	 "Opens a series of panels that enable you to duplicate the selected"
	 +" principal. The panels will have the fields already filled in"
	 +" with the same values as the selected principal,"
	 +" except for the principal's name and password."
	 +"You can use this button to quickly create a new principal using "
	 +" another principal as a template.\n"
	 +" \n"
	 +"The Create New button performs the same function; however,"
	 +" instead of"
	 +" the fields filled in with the same values as the selected"
	 +" principal, the fields are filled in with default values."},
        
        
        
        //
        //  Principal Basics Panel
        //
        
        
        {"PrincipalBasicsPanel",
	 // Not currently available in GUI
	 "This panel enables you to specify the basic attributes for a"
	 +" principal."},
        
        
        {"PrName",
	 "The name of the principal (the <primary>/<instance> part of a"
	 +" fully-qualified principal name).  A principal is a unique identity"
	 +" to which the KDC can assign tickets.\n"
	 +" \n"
	 +"If you are modifying a principal,"
	 +" you cannot edit a principal's name.\n"
	 +" \n"
	 +"For service (or host) principal names, the <primary> part must be"
	 +" the name of a service, such as 'host' for telnet and rsh"
	 +" services,'ftp', or 'nfs'."
	 +"The < instance > part must be the name of the system"
	 +" that requires Kerberos authentication for that service."
	 +"For example, 'host/denver.mtn.acme.com'.\n"
	 +" \n"
	 +"For user principal names, the < primary > part must be"
	 +" the name of the"
	 +" user."
	 +"The < instance > part is optional, but it can be a term used to"
	 +" describe the intended use for the principals, such as 'admin', or"
	 +" it can be the name of a system, which enables you to create"
	 +" different"
	 +" principals for the same user on a per-system basis."
	 +" For example, 'jdb/admin', 'jdb/denver@acme.com', or 'jdb'."},
        
        
        {"PrComments",
	 "Comments related to the principal (for example,"
	 +" 'Temporary Account')."},
        
        
        {"PrPolicy",
	 "A menu of available policies for the principal."},
        
        
        {"PrPassword",
	 "The password for the principal."},
        
        
        {"PrBasicRandomPw",
	 "Creates a random password for the principal and copies it into"
	 +" the Password field."},
        
        
        {"PrinBasLastPrincipalChange",
	 "The date on which information for the principal was"
	 +" last modified."},
        
        
        {"PrinBasLastChangedBy",
	 "The name of the principal who last modified the account for this"
	 +" principal."},
        
        {"EncList",
	 "The encryption types that the principal's keys will be created with."
	 +" Use a white space to separate encryption types."
	 +" Leave blank if the default set of encryption types is desired."
	 +" Refer to krb5.conf for the available encryption types supported."
	 +" The default set of dialog choices can be over-ridden by defining"
	 +" supported_enctypes with the desired list of encryption types in"
	 +" the realm's section of krb5.conf."
	 +" \n"
	 +"Changing encryption types is only applicable when creating a"
	 +" principal or when changing a password.  So a password must be"
	 +" accompanied with any encryption type changes."},
        
        {"PrExpiry",
	 "The date and time on which the principal's account expires. When the"
	 +" account expires, the principal can no longer"
	 +" get a ticket-granting ticket (TGT) and may not be able to log in.\n"
	 +" \n"
	 +"To set up the account with no expiration date,"
	 +" enter the word 'never' in the field.\n"
	 +" \n"
	 +"To help create a formatted date and time entry, click the adjacent"
	 +" '...' button to bring up a helper."},
        
        
        {"PrSave",
	 "Saves any changes you've made to the current principal."},
        
        
        {"PrCancel",
	 "Discards all the changes you've made to the current principal"
	 +" and sends you back to the list of principals."},
        
        
        {"PrBasicPrevious",
	 "Sends you back to the list of principals.\n"
	 +" \n"
	 +"Note that you must save or cancel any changes you've made to"
	 +" the current principal before you can go back to the list."},
        
        
        {"PrBasicNext",
	 "Sends you to the next Principal Details panel that contains"
	 +" the password and ticket lifetime attributes for the principal."},
        
        
        
        //
        // Principal Detail Panel
        //
        
        
        {"PrincipalDetailPanel",
	 // Not currently available in GUI
	 "This panel enables you to specify the password and"
	 +" ticket lifetime attributes for the principal principal."},
        
        
        {"PrinDetLastSuccess",
	 "The date and time when the principal last logged in successfully."},
        
        
        {"PrinDetLastFailure",
	 "The date and time when the last login failure for the"
	 +" principal occurred."},
        
        
        {"PrinDetFailureCount",
	 "The number of times that there has been a login failure"
	 +" for the principal."},
        
        
        {"PrinDetLastPasswordChange",
	 "The date and time when the principal's password was "
	 +" last changed."},
        
        
        {"PrPwExpiry",
	 "The date and time when the principal's current password"
	 +" will expire.\n"
	 +" \n"
	 +"To set up the password with no expiration date, enter the"
	 +" word 'never'in the field.\n"
	 +" \n"
	 +"To help create a formatted date and time entry, click the adjacent"
	 +" '...' button to bring up a helper."},
        
        
        {"PrKvno",
	 "The key version number for the principal; this is normally"
	 +" changed only when a password has been compromised."},
        
        
        {"PrMaxLifetime",
	 "The maximum length of time for which a ticket can be"
	 +" granted for the principal (without renewal).\n"
	 +" \n"
	 +"To help create a time duration in seconds, click the adjacent"
	 +" '...' button to bring up a helper."},
        
        
        {"PrMaxRenewal",
	 "The maximum length of time for which an existing"
	 +" ticket may be renewed for the principal.\n"
	 +" \n"
	 +"To help create a time duration in seconds, click the adjacent"
	 +" '...' button to bring up a helper."},
        
        
        {"PrDetailPrevious",
	 "Sends you back to the previous Principal Basics panel."},
        
        
        {"PrDetailNext",
	 "Sends you to the next Principal Flags panel that contains"
	 +" security, ticket control, and miscellaneous attributes for"
	 +" the principal."},
        
        
        
        //
        // Principal Flags Panel
        //
        
        
        
        {"PrincipalFlagsPanel",
	 // Not currently available in GUI
	 "This panel enables you to specify the security, ticket control, and"
	 +" miscellaneous attributes for the principal."},
        
        
        {"PrLockAcct",
	 "When checked, prevents the principal from logging in."
	 +" This is a easy way to temporarily freeze"
	 +" a principal account for any reason."},
        
        
        {"PrForcePwChange",
	 "When checked, expires the principal's current password, forcing the"
	 +" user to use the kpasswd command to create a new password."
	 +" This is useful if"
	 +" there is a security breach and you need to make sure that old"
	 +" passwords are replaced."},
        
        
        {"PrAllowPostdated",
	 "When checked, allows the principal to obtain postdated tickets.\n"
	 +" \n"
	 +"For example, you may need to use postdated tickets for cron jobs"
	 +" that need to run after hours and can't obtain tickets in"
	 +" advance because of short ticket lifetimes."},
        
        
        {"PrAllowRenewable",
	 "When checked, allows the principal to obtain renewable tickets.\n"
	 +" \n"
	 +"A principal can automatically extend the expiration date or time of"
	 +" a ticket that is renewable (rather than having to get a new"
	 +" ticket after the first one expires). Currently, the NFS service"
	 +" is the only service that can renew tickets."},
        
        
        {"PrAllowSvr",
	 "When checked, allows service tickets to be issued for"
	 +" the principal.\n"
	 +" \n"
	 +"You should not allow service tickets to be issued for the"
	 +" 'kadmin/admin' and 'changepw/admin' principals."
	 +"  This will ensure that these"
	 +" principals can only update the KDC database." },
        
        
        {"PrAllowForwardable",
	 "When checked, allows the principal to obtain forwardable"
	 +" tickets.\n"
	 +" \n"
	 +"Forwardable tickets are tickets that are forwarded to the"
	 +" remote host to provide a single-sign-on session."
	 +"For example, if you are using forwardable tickets and you"
	 +" authenticate yourself through ftp or rsh, other services,"
	 +" such as NFS, are available without you being prompted"
	 +" for another password."},
        
        
        {"PrAllowProxiable",
	 "When checked, allows the principal to obtain proxiable tickets.\n"
	 +" \n"
	 +"A proxiable ticket is a ticket that can be used by a service"
	 +" on behalf  of a client to perform an operation for the client."
	 +" With a proxiable ticket, a service can take on the identity"
	 +" of a client and obtain a ticket for another service, but it"
	 +" cannot obtain a ticket-granting ticket."},
        
        
        {"PrEnforcePolicy",
	 "When checked, the policy selected for this principal"
	 +" will be enforced."},
        
        
        {"PrAllowTGT",
	 "When checked, allows the service principal to provide services"
	 +" to another principal. More specifically, it allows the KDC to"
	 +" issue a service ticket for the service principal.\n"
	 +" \n"
	 +"This attribute is valid only for service principals."
	 +"When not checked, service tickets cannot be issued for"
	 +" the service principal."},
        
        
        {"PrRequirePreAuth",
	 "When checked, the KDC will not send a requested ticket-granting"
	 +" ticket(TGT) to the principal until it can"
	 +" authenticate (through software) that it is really the principal"
	 +" requesting the TGT. This preauthentication is usually done"
	 +" through an  extra password, for example, from a DES card.\n"
	 +" \n"
	 +"When not checked, the KDC will not need to preauthenticate"
	 +" the principal before it sends a requested TGT to it."},
        
        
        {"PrAllowDupAuth",
	 "When checked, allows the user principal to obtain service tickets for"
	 +" other user principals.\n"
	 +" \n"
	 +"This attribute is valid only for user principals. When not checked,"
	 +" the user principal can still obtain service tickets for"
	 +" service principals, but not for other user principals."},
        
        
        {"PrRequireHwPreAuth",
	 "When checked, the KDC will not send a requested ticket-granting"
	 +" ticket(TGT) to the principal until"
	 +" it can authenticate (through hardware) that it is really the"
	 +" principal requesting the TGT. Hardware preauthentication could"
	 +" be something like a Java ring reader.\n"
	 +" \n"
	 +"When not checked, the KDC will not need to preauthenticate"
	 +" the principal before it sends a requested TGT to it."},
        
        
        {"PrFlagsPrevious",
	 "Sends you back to the previous Principal Details panel."},
        
        //
        // Done Button
        //
        
        {"PrFlagsNext",
	 "Saves any changes you've made to the current principal and"
	 +" sends you back to list of principals."},
        
        
        
        //
        // Policies Panel
        //
        
        
        
        {"PoliciesPanel",
	 // Not currently available in GUI
	 "This panel enables you to select a policy from the list to"
	 +" modify, delete, or duplicate. You can also create a new policy.\n"
	 +" \n"
	 +"A policy is a set of behaviors regarding"
	 +" passwords and tickets that can be applied to a principal."
	 +" For example, the principals for system administrators might"
	 +" all have the same policy."
	 +" \n"
	 +"To display a specific policy or sublist of policy,"
	 +" enter a filter string in the Filter Pattern field and press"
	 +" return.\n"
	 +" \n"
	 +"To perform an operation on a policy, select it from the list and"
	 +" click the appropriate button. To add a new policy, click New."},
        
        
        {"Pollist",
	 "Displays the all the available policies in the specified realm.\n"
	 +" \n"
	 +"To select a policy, click on its name in the list; double-clicking"
	 +" on a policy is equivalent to selecting the policy and clicking"
	 +" Modify"},
        
        {"PolNoList",
	 "This list panel is blank when you don't have list privileges"
	 +" or you've chosen not to show lists."},
        
        {"PoListPattern",
	 "Enables you to apply a filter on the available policies to display a"
	 +" particular policy or sublist of policies. The filter string you"
	 +" enter may consist of one or more characters, And, because"
	 +" the filter mechanism is case-sensitive, you need to use the"
	 +" appropriate upper-case and lower-case letters for the filter.\n"
	 +" \n"
	 +"For example, entering 'adm' for the filter would match and display,"
	 +" policies such as 'admpol', 'adm1', and 'poladmin'.\n"
	 +" \n"
	 +"To display a particular policy or sublist of"
	 +" policies, enter a filter string and press"
	 +" return.\n"
	 +" \n"
	 +"To display the entire list of policies, click Clear"
	 +" Filter (or clear the Filter Pattern field and press return)."},
        
        
        {"PoNameNoList",
	 "When the policy list is not displayed,"
	 +" you must enter policy names in this field to perform"
	 +" operations on them. Entering a name is equivalent to selecting"
	 +" an item from the list in normal operation.\n"
	 +" \n"
	 +"To clear the policy entry, click Clear Name (or clear the"
	 +" Name field and press return)."},
        
        
        {"PoListClear",
	 "Clears the filter and displays the full list of available policies."},
        
        
        {"PoNoListClear",
	 "Clears the Name field."},
        
        
        {"PoListModify",
	 "Opens the Policy Details panel that enables you to modify the"
	 +" selected policy attributes, such as the policy's minimum password"
	 +" length and the minimum ticket lifetime."},
        
        
        
        {"PoListAdd",
	 "Opens the Policy Details panel that enables you to create a new"
	 +" policy.  The panel will have some of the fields already filled"
	 +" in with default values.\n"
	 +" \n"
	 +"The Duplicate button performs the same function; however,"
	 +" instead of the fields filled in with default values, the"
	 +" fields are filled in with the same values as the selected policy."},
        
        
        {"PoListDelete",
	 "Deletes the selected policy from the Kerberos realm."},
        
        
        
        {"PoListDuplicate",
	 "Opens the Policy Details panel that enables you to duplicate"
	 +" the selected policy. The panels will have the fields already"
	 +" filled in with the same values as the selected policy,"
	 +" except for the policy's name."
	 +"You can use this button to quickly create a new policy using"
	 +" another policy as a template.\n"
	 +" \n"
	 +"The Create New button performs the same function; however,"
	 +" the fields are filled in with default values."},
        
        
        
        //
        // Policy.Detail
        //
        
        
        {"PoName",
	 "The name of the policy. A policy is set of rules governing a"
	 +" principal's password and tickets.\n"
	 +" \n"
	 +"If you are modifying a policy, you cannot edit a policy's name."},
        
        
        
        {"PoMinPwLength",
	 "The minimum length for the principal's password."},
        
        
        {"PoMinPwClass",
	 "The minimum number of different character types required in the"
	 +"  principal's    password."
	 +"For example, a minimum classes value of 2 means that the"
	 +" password must have at least two different character types,"
	 +" such as letters and numbers(hi2mom). A value of 3 means that"
	 +" the password must have at least three different character"
	 +" types, such as letters, numbers, and punctuation (hi2mom!)."
	 +"And so on. \n"
	 +" \n"
	 +"A value of 1 basically sets no restriction on the number of password"
	 +" character types."},
        
        
        {"PoSavedPasswords",
	 "The number of previous passwords that have been used by the principal"
	 +" and cannot be reused."},
        
        
        {"PoMinTicketLifetime",
	 "The minimum time that the password must be used before it can be"
	 +" changed.\n"
	 +" \n"
	 +"To help create a time duration in seconds, click the adjacent"
	 +" '...' button to bring up a helper."},
        
        
        {"PoMaxTicketLifetime",
	 "The maximum time that the password can be used before it must be"
	 +" changed.\n"
	 +" \n"
	 +"To help create a time duration in seconds, click the adjacent"
	 +" '...' button to bring up a helper."},
        
        
        {"PolDetPrincipalsUsingThisPolicy",
	 "The number of principals to which this policy currently applies."},
        
        
        {"PoSave",
	 "Saves any changes you've made to the current policy."},
        
        
        {"PoCancel",
	 "Discards all the changes you've made to the current policy and sends"
	 +" you back to the list of policies."},
        
        
        {"PoDetailPrevious",
	 "Sends you back to the list of policies.\n"
	 +" \n"
	 +"Note that you must save or cancel any changes you've made to the"
	 +" current policy before you can go back to the list."},
        
        
        {"PoDetailDone",
	 "Saves any changes you've made to the current policy and sends"
	 +" you back to list of policies."},
        
        
        
        //
        // Defaults Panel
        //
        
        
        {"DefaultsPanel",
	 // Not currently available in GUI
	 "This window enables you to change the default settings for adding new"
	 +" principals."},
        
        
        {"GlobalLockAcct",
	 "When checked, prevents the new principal from logging in."
	 +"This is a easy way to temporarily freeze"
	 +" new principal accounts for any reason. For example, you may want"
	 +" to add a number of new principals in the beginning of the week,"
	 +" but you might not want to activate them until the end of the"
	 +" week."},
        
        
        {"GlobalAllowPostdated",
	 "When checked, allows the new principal to obtain postdated tickets.\n"
	 +" \n"
	 +"For example, you may need to use postdated tickets for cron jobs"
	 +" that need to run after hours and can't obtain tickets in advance"
	 +" because of short ticket lifetimes."},
        
        
        {"GlobalAllowRenewable",
	 "When checked, allows the new principal to obtain renewable tickets.\n"
	 +" \n"
	 +"A principal can automatically extend the expiration date or time of"
	 +" a ticket that is renewable (rather than having to get a new ticket"
	 +" after the first one expires). Currently, the NFS service is the"
	 +" only service that can obtain renewable tickets."},
        
        
        {"GlobalEnforcePolicy",
	 "When checked, the policy selected for the new principal"
	 +" will be enforced."},
        
        {"GlobalAllowTGT",
	 "When checked, allows the new service principal to provide services to"
	 +" another principal. More specifically, it allows the KDC to issue a"
	 +" service ticket for the new service principal.\n"
	 +" \n"
	 +"This attribute is valid only for service principals."
	 +"When not checked,"
	 +" service tickets cannot be issued for the new service principal."},
        
        
        {"GlobalForcePwChange",
	 "When checked, expires the principal's current password, forcing the"
	 +" user to use the kpasswd command to create a new password. This is"
	 +" is useful if you want to force users with new principals to set"
	 +" up their own passwords."},
        
        
        {"GlobalAllowForwardable",
	 "When checked, allows the new principal to obtain forwardable"
	 +" tickets.\n"
	 +" \n"
	 +"Forwardable tickets are tickets that are forwarded to the remote"
	 +" host to provide a single-sign-on session. For example, if you"
	 +" are using forwardable tickets and you authenticate yourself"
	 +" through ftp or rsh, other services, such as NFS, are available"
	 +" without you being prompted for another password."},
        
        
        {"GlobalAllowSvr",
	 "When checked, allows service tickets to be issued for"
	 +" the new principal.\n"
	 +" \n"
	 +"You should not allow service tickets to be issued for the"
	 +" 'kadmin/admin' and the 'changepw/admin' principals."
	 +" This will ensure that these"
	 +" principals can only update the KDC database." },
        
        
        {"GlobalAllowProxiable",
	 "When checked, allows the new principal to obtain proxiable tickets.\n"
	 +" \n"
	 +"A proxiable ticket is a ticket that can be used by a service on"
	 +" behalf of a client to perform an operation for the client."
	 +"With a proxiable ticket, a service can take on the identity of"
	 +" a client and obtain a ticket for another service, but it cannot"
	 +" obtain a ticket-granting ticket."},
        
        
        
        {"GlobalAllowDupAuth",
	 "When checked, allows the new user principal to obtain service"
	 +" tickets for other user principals.\n"
	 +" \n"
	 +"This attribute is valid only for user principals. When not checked,"
	 +" the new user principal can still obtain service tickets for"
	 +" service principals, but not for other user principals."},
        
        
        {"GlobalRequirePreAuth",
	 "When checked, the KDC will not send a requested ticket-granting"
	 +" ticket(TGT)"
	 +" for the new principal until"
	 +" it can authenticate (through software) that it is really the"
	 +" principal requesting the TGT. This preauthentication is usually"
	 +" done through an extra password, for example, from a DES card.\n"
	 +" \n"
	 +"When not checked, the KDC will not need preauthenticate the new"
	 +" principal before it sends a requested TGT for it."},
        
        
        {"GlobalRequireHwPreAuth",
	 "When checked, the KDC will not send a requested ticket-granting"
	 +" ticket(TGT) for the new principal until it can authenticate"
	 +" (through hardware) that it is really the principal"
	 +" requesting the TGT. Hardware preauthentication could be something"
	 +" like a Java ring reader.\n"
	 +" \n"
	 +"When not checked, the KDC will not need to preauthenticate the new"
	 +" principal with hardware before it sends a requested TGT for it."},
        
        {"GlDefServerSide",
	 "When checked, the ticket lifetime values in the new principal are set"
	 +" such that "
	 +"the maximum value is used. When issuing a ticket the KDC uses the"
	 +" minimum of the value defined in the principal entry, in "
	 +" /etc/krb5/kdc.conf, or whatever the client requests with kinit."},
        
        {"GlDefLife",
	 "The maximum length of time for which a ticket can be"
	 +" granted for the new principal (without renewal).\n"
	 +" \n"
	 +"To help create a time duration in seconds, click the adjacent"
	 +" '...' button to bring up a helper."},
        
        {"GlDefRenewableLife",
	 "The maximum length of time for which an existing"
	 +" ticket may be renewed for the new principal.\n"
	 +" \n"
	 +"To help create a time duration in seconds, click the adjacent"
	 +" '...' button to bring up a helper."},
        
        
        {"GlDefExpiry",
	 "The date and time on which the new principal's account expires."
	 +"When the account expires, the principal can no longer"
	 +" get a ticket-granting ticket (TGT) and may not be able to log in.\n"
	 +" \n"
	 +"To set up the new account with no expiration date, enter the word"
	 +"  'never' in the field.\n"
	 +" \n"
	 +"To help create a formatted date and time entry, click the adjacent"
	 +" '...' button to bring up a helper."},
        
        
        
        {"GlDefShowLists",
	 "When checked, the principal and policy lists will be loaded and"
	 +" displayed in the list panels. Large lists may produce significant"
	 +" loading times, so it may be more convenient to work without lists"
	 +" when they are very large, or you should cache them."
	 +"The default is on."},
        
        
        {"GlDefStaticLists",
	 "When checked, the principal and policy lists will be cached"
	 +" when they are initially loaded, and the lists will not be refreshed"
	 +" from the server unless you use the Refresh menu. Because large"
	 +" lists may produce significant loading times, you should cache"
	 +" large lists and refresh them when necessary. The default"
	 +" is off."},
        
        
        {"GlDefCacheTime",
	 "The period of time that the principal and policy lists will be"
	 +" cached before being considered stale and refreshed from the"
	 +" server.  The default is 300 seconds (6 minutes)."},
        
        
        {"GlobalSave",
	 "Makes a permanent change to the default values by writing them"
	 +" to ~/.gkadmin, updates the tool, and closes the window."},
        
        
        {"GlobalApply",
	 "Makes a temporary change to the default values in the tool and"
	 +" closes the window. This does not update ~/.gkadmin."},
        
        
        {"GlobalCancel",
	 "Discards all the changes you've made to the current defaults and"
	 +" closes the window."},
        
        //
        // Generic Helper Button Descriptions
        //
        
        {"DateHelperButton",
	 "Opens the Date and Time Helper window to help you create"
	 +" a formatted date and time entry for the associated field."},
        
        {"DurationHelperButton",
	 "Opens the Time Duration Helper window to help you create a time"
	 +" duration in seconds for the associated field."},

        {"EncListHelperButton",
	 "Opens the Encryption Types Helper window to help you create"
	 +" the principal's keys from the default set."},

	//
	// EncryptionTypeDialogHelp
	//

	{"EncryptionTypeDialogHelp",
	 "You can select/deselect encryption types for this principal as"
	 +" needed.  Certain encryption types are similar therefore when"
	 +" one of these encryption types is selected the other type(s)"
	 +" will be deselected.  If no encryption types are selected the"
	 +" default set of types will be used, see krb5.conf(4) for these.\n"
	 +" \n"
	 +"Click OK to copy the encryption list that you've selected to the"
	 +" corresponding field.\n"
	 +" \n"
	 +"Click Clear to unselect all encryption types listed."},
        
        //
        // DateTimeDialog
        //
        
        {"DateTimeDialogHelp",
	 "To change the month, choose from the Month menu.\n "
	 +" \n"
	 +"To change the other date and time fields, click in the field and"
	 +" enter a value, or use the +/- buttons to increment/decrement their"
	 +" value. (Hint: Keeping the buttons pressed makes the value change"
	 +" at a faster rate.)\n"
	 +" \n"
	 +"Click Midnight to change the time to midnight, and click Now to"
	 +" change the time to the current time based on the system's clock.\n"
	 +" \n"
	 +"Click OK to copy the date and time settings you've changed to"
	 +" the corresponding field."},
        
        
        //
        // DurationHelper
        //
        
        {"DurationHelperHelp",
	 "To help create a time duration in seconds, choose a unit of time"
	 +" from the Unit menu, enter a number of units under the"
	 +" Value field, and press return (or click '='). The number of"
	 +" seconds based on your input will be displayed.\n"
	 +" \n"
	 +"Click OK to copy the number of seconds you've specified into the"
	 +" corresponding field."},
        
        //
        // PrintUtil
        //
        
        {"PrintUtilHelp",
	 "You can either print to a printer or a file.\n"
	 +" \n"
	 +"To print directly to a printer, click the Print Command"
	 +" radio button, enter a print command (if you don't want the default"
	 +" print command), and click Print.\n"
	 +" \n"
	 +"To print to a file, click the File Name radio button, enter a file"
	 +" name, and click Print. The file name can be an absolute path."
	 +" If no path is given, the file will be saved in the directory"
	 +" where gkadmin was started. Click '...' next to the File Name field"
	 +" to open the File Helper window to help you specify a"
	 +" a location and name for the file."},
        
        //
        // Menubar context sensitive help
        //
        
        {"ContextSensitiveHelp",
	 "Opens the Context-Sensitive Help window and switches the tool into"
	 +" help mode.  In help mode, you can get help on any part of the"
	 +" current window just by clicking on it. To dismiss the Help window"
	 +" and switch back to the normal mode, click Dismiss on the Help"
	 +" window."},
        
        {"PrintCurrentPrincipal",
	 "Prints the attributes of the currently selected principal in the"
	 +" list or the currently loaded principal."},
        
        {"PrintCurrentPolicy",
	 "Prints the attributes of the currently selected policy in the"
	 +" list or the currently loaded policy."},
        
        {"PrintPrincipalList",
	 "Prints the list of all the available principals on the master KDC."},
        
        {"PrintPolicyList",
	 "Prints the list of all the available policies on the master KDC."},
        
        {"Logout",
	 "Quits the current session and sends you back to the Login window, so"
	 +" you can change the login fields and log in again."},
        
        {"EditPreferences",
	 "Opens the Properties window, which enables you to"
	 +" specify the default settings for creating new principals"
	 +" and how the tool should manage the principal"
	 +" and policy lists."},
        
        {"RefreshPrincipals",
	 "Forces the principal list to be updated from the server."},
        
        {"RefreshPolicies",
	 "Forces the policy list to be updated from the server."},
        
        {"Exit",
	 "Quits the SEAM Administration Tool."},
        
        {"HelpBrowser",
	 "Opens an HTML browser that provides pointers to overview and task"
	 +" information"
	 +" for the SEAM Administration Tool. This provides the same"
	 +" information as the 'Sun Enterprise Authentication Management"
	 +" Guide'."},
        
        {"About",
	 "Displays the current version of the SEAM Administration Tool."},
        
        {"DateTime...",
	 "Opens the SEAM Date and Time Helper window, which enables you to"
	 +" set the date and time. After you set the date and time and click"
	 +" OK, the settings are automatically formatted and copied into the"
	 +" corresponding field."},
        
        {"Duration...",
	 "Opens the SEAM Duration Helper window, which enables you to specify a"
	 +" time duration and have it converted into seconds."
	 +" After you specify the time"
	 +" and click OK, the time duration is copied into the corresponding"
	 +" field."},

	{"EncList...",
	 "Opens the SEAM Encryption Type List Helper window, which enables you"
	 +" to specify custom encryption types for the principal. "
	 +" After you select the encryption types and click OK, the encryption"
	 +" type list is copied into the corresponding field."},

        {"Print...",
	 "Opens the SEAM Print Dialog window, which enables you to specify a"
	 +" printer"
	 +" to print the information or a file name in which to save the"
	 +" information."},
        
        {"Bad Duration",
	 "Please enter the duration (in seconds) correctly."},
        
        {"Bad Date",
	 "Please enter the date correctly."},
        
        {"Bad Number",
	 "Please enter the number correctly."}
        
    }; // end contents object
    
}
