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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <syslog.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <synch.h>
#include <netdb.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <smbsrv/libsmb.h>
#include <smbsrv/libsmbns.h>

#include <smbsrv/cifs.h>
#include <smbsrv/mailslot.h>

#include <smbns_browser.h>
#include <smbns_netbios.h>

/*
 * ntdomain_info
 * Temporary. It should be removed once NBTD is integrated.
 */
smb_ntdomain_t ntdomain_info;
mutex_t ntdomain_mtx;
cond_t ntdomain_cv;

#define	SMB_SERVER_SIGNATURE		0xaa550415

typedef struct smb_hostinfo {
	list_node_t	hi_lnd;
	smb_nic_t	hi_nic;
	char		hi_nbname[NETBIOS_NAME_SZ];
	name_entry_t	hi_netname;
	uint32_t	hi_nextannouce;
	int		hi_reps;
	int		hi_interval;
	uint8_t		hi_updatecnt;
	uint32_t	hi_type;
} smb_hostinfo_t;

typedef struct smb_browserinfo {
	list_t		bi_hlist;
	int		bi_hcnt;
	rwlock_t	bi_hlist_rwl;
	boolean_t	bi_changed;
	mutex_t		bi_mtx;
} smb_browserinfo_t;

static smb_browserinfo_t smb_binfo;

static int smb_browser_init(void);
static void smb_browser_infoinit(void);
static void smb_browser_infoterm(void);
static void smb_browser_infofree(void);




void
smb_browser_reconfig(void)
{
	(void) mutex_lock(&smb_binfo.bi_mtx);
	smb_binfo.bi_changed = B_TRUE;
	(void) mutex_unlock(&smb_binfo.bi_mtx);
}

/*
 * 3. Browser Overview
 *
 * Hosts involved in the browsing process can be separated into two
 * distinct groups, browser clients and browser servers (often referred to
 * simply as "browsers").
 *
 * A browser is a server which maintains information about servers -
 * primarily the domain they are in and the services that they are running
 * -- and about domains. Browsers may assume several different roles in
 * their lifetimes, and dynamically switch between them.
 *
 *  Browser clients are of two types: workstations and (non-browser)
 * servers. In the context of browsing, workstations query browsers for the
 * information they contain; servers supply browsers the information by
 * registering with them. Note that, at times, browsers may themselves
 * behave as browser clients and query other browsers.
 *
 * For the purposes of this specification, a domain is simply a name with
 * which to associate a group of resources such as computers, servers and
 * users. Domains allow a convenient means for browser clients to restrict
 * the scope of a search when they query browser servers. Every domain has
 * a "master" server called the Primary Domain Controller (PDC) that
 * manages various  activities within the domain.
 *
 * One browser for each domain on a subnet is designated the Local Master
 * Browser for that domain. Servers in its domain on the subnet register
 * with it, as do the Local Master Browsers for other domains on the
 * subnet. It uses these registrations to maintain authoritative
 * information about its domain on its subnet. If there are other subnets
 * in the network, it also knows the name of the server running the
 * domain's Domain Master Browser; it registers with it, and uses it to
 * obtain information about the rest of the network (see below).
 *
 * Clients on a subnet query browsers designated as the Backup Browsers for
 * the subnet (not the Master Browser). Backup Browsers maintain a copy of
 * the information on the Local Master Browser; they get it by periodically
 * querying the Local Master Browser for all of its information. Clients
 * find the Backup Browsers by asking the Local Master Browser. Clients are
 * expected to spread their queries evenly across Backup Browsers to
 * balance the load.
 *
 * The Local Master Browser is dynamically elected automatically. Multiple
 * Backup Browser Servers may exist per subnet; they are selected from
 * among the potential browser servers by the Local Master Browser, which
 * is configured to select enough to handle the expected query load.
 *
 * When there are multiple subnets, a Domain Master Browser is assigned
 * the task of keeping the multiple subnets in synchronization. The Primary
 * Domain Controller (PDC) always acts as the Domain Master Browser. The
 * Domain Master Browser periodically acts as a client and queries all the
 * Local Master Browsers for its domain, asking them for a list containing
 * all the domains and all the servers in their domain known within their
 * subnets; it merges all the replies into a single master list. This
 * allows a Domain Master Browser server to act as a collection point for
 * inter-subnet browsing information. Local Master Browsers periodically
 * query the Domain Master Browser to retrieve the network-wide information
 * it maintains.
 *
 * When a domain spans only a single subnet, there will not be any distinct
 * Local Master Browser; this role will be handled by the Domain Master
 * Browser. Similarly, the Domain Master Browser is always the Local Master
 * Browser for the subnet it is on.
 *
 * When a browser client suspects that the Local Master Browser has failed,
 * the client will instigate an election in which the browser servers
 * participate, and some browser servers may change roles.
 *
 * Some characteristics of a good browsing mechanism include:
 * . minimal network traffic
 * . minimum server discovery time
 * . minimum change discovery latency
 * . immunity to machine failures
 *
 * Historically, Browser implementations had been very closely tied to
 * NETBIOS and datagrams. The early implementations caused a lot of
 * broadcast traffic. See Appendix D for an overview that presents how the
 * Browser specification evolved.
 *
 * 4. Browsing Protocol Architecture
 *
 * This section first describes the how the browsing protocol is layered,
 * then describes the roles of clients, servers, and browsers in the
 * browsing subsystem.
 *
 * 4.1 Layering of Browsing Protocol Requests
 *
 * Most of the browser functionality is implemented using mailslots.
 * Mailslots provide a mechanism for fast, unreliable unidirectional data
 * transfer; they are named via ASCII "mailslot (path) name". Mailslots are
 * implemented using the CIFS Transact SMB which is encapsulated in a
 * NETBIOS datagram. Browser protocol requests are sent to browser specific
 * mailslots using some browser-specific NETBIOS names. These datagrams can
 * either be unicast or broadcast, depending on whether the NETBIOS name is
 * a "unique name" or a "group name". Various data structures, which are
 * detailed subsequently within this document, flow as the data portion of
 * the Transact SMB.
 *
 * Here is an example of a generic browser SMB, showing how a browser
 * request is encapsulated in a TRANSACT SMB request. Note that the PID,
 * TID, MID, UID, and Flags are all 0 in mailslot requests.
 *
 * SMB: C transact, File = \MAILSLOT\BROWSE
 *   SMB: SMB Status = Error Success
 *     SMB: Error class = No Error
 *     SMB: Error code = No Error
 *   SMB: Header: PID = 0x0000 TID = 0x0000 MID = 0x0000 UID = 0x0000
 *     SMB: Tree ID   (TID) = 0 (0x0)
 *     SMB: Process ID  (PID) = 0 (0x0)
 *     SMB: User ID   (UID) = 0 (0x0)
 *     SMB: Multiplex ID (MID) = 0 (0x0)
 *     SMB: Flags Summary = 0 (0x0)
 *   SMB: Command = C transact
 *     SMB: Word count = 17
 *     SMB: Word parameters
 *     SMB: Total parm bytes = 0
 *     SMB: Total data bytes = 33
 *     SMB: Max parm bytes = 0
 *     SMB: Max data bytes = 0
 *     SMB: Max setup words = 0
 *     SMB: Transact Flags Summary = 0 (0x0)
 *       SMB: ...............0 = Leave session intact
 *       SMB: ..............0. = Response required
 *     SMB: Transact timeout = 0 (0x0)
 *     SMB: Parameter bytes = 0 (0x0)
 *     SMB: Parameter offset = 0 (0x0)
 *     SMB: Data bytes = 33 (0x21)
 *     SMB: Data offset = 86 (0x56)
 *     SMB: Setup word count = 3
 *     SMB: Setup words
 *     SMB: Mailslot opcode = Write mailslot
 *     SMB: Transaction priority = 1
 *     SMB: Mailslot class = Unreliable (broadcast)
 *     SMB: Byte count = 50
 *     SMB: Byte parameters
 *     SMB: Path name = \MAILSLOT\BROWSE
 *     SMB: Transaction data
 *   SMB: Data: Number of data bytes remaining = 33 (0x0021)
 *
 * Note the SMB command is Transact, the opcode within the Transact SMB is
 * Mailslot Write, and the browser data structure is carried as the
 * Transact data.
 * The Transaction data begins with an opcode, that signifies the operation
 * and determines the size and structure of data that follows. This opcode
 * is named as per one of the below:
 *
 * HostAnnouncement         1
 * AnnouncementRequest      2
 * RequestElection          8
 * GetBackupListReq         9
 * GetBackupListResp        10
 * BecomeBackup             11
 * DomainAnnouncment        12
 * MasterAnnouncement       13
 * LocalMasterAnnouncement  15
 *
 * Browser datagrams are often referred to as simply browser frames. The
 * frames are in particular, referred to by the name of the opcode within
 * the Transaction data e.g. a GetBackupListReq browser frame, a
 * RequestElection browser frame, etc.
 *
 * The structures that are sent as the data portion of the Transact SMB are
 * described in section(s) 6.2 through 6.12 in this document. These
 * structures are tightly packed, i.e. there are no intervening pad bytes
 * in the structure, unless they are explicitly described as being there.
 * All quantities are sent in native Intel format and multi-byte values are
 * transmitted least significant byte first.
 *
 * Besides mailslots and Transaction SMBs, the other important piece of the
 * browser architecture is the NetServerEnum2 request. This request that
 * allows an application to interrogate a Browser Server and obtain a
 * complete list of resources (servers, domains, etc) known to that Browser
 * server. Details of the NetServerEnum2 request are presented in section
 * 6.4. Some examples of the NetServerEnum2 request being used are when a
 * Local Master Browser sends a NetServerEnum2 request to the Domain Master
 * Browser and vice versa. Another example is when a browser client sends a
 * NetServerEnum2 request to a Backup Browser server.
 *
 * 4.3 Non-Browser Server
 *
 * A non-browser server is a server that has some resource(s) or service(s)
 * it wishes to advertise as being available using the browsing protocol.
 * Examples of non-browser servers would be an SQL server, print server,
 * etc.
 *
 * A non-browser server MUST periodically send a HostAnnouncement browser
 * frame, specifying the type of resources or services it is advertising.
 * Details are in section 6.5.
 *
 * A non-browser server SHOULD announce itself relatively frequently when
 * it first starts up in order to make its presence quickly known to the
 * browsers and thence to potential clients. The frequency of the
 * announcements SHOULD then be gradually stretched, so as to minimize
 * network traffic. Typically,  non-browser servers announce themselves
 * once every minute upon start up and then gradually adjust the frequency
 * of the announcements to once every 12 minutes.
 *
 * A non-browser server SHOULD send a HostAnnouncement browser frame
 * specifying a type of  0 just prior to shutting down, to allow it to
 * quickly be removed from the list of available servers.
 *
 * A non-browser server MUST receive and process AnnouncementRequest frames
 * from the Local Master Browser, and MUST respond with a HostAnnouncement
 * frame, after a delay chosen randomly from the interval [0,30] seconds.
 * AnnouncementRequests typically happen when a Local Master Browser starts
 * up with an empty list of servers for the domain, and wants to fill it
 * quickly. The 30 second range for responses prevents the Master Browser
 * from becoming overloaded and losing replies, as well as preventing the
 * network from being flooded with responses.
 *
 * 4.4  Browser Servers
 *
 * The following sections describe the roles of the various types of
 * browser servers.
 *
 * 4.4.1  Potential Browser Server
 *
 * A Potential Browser server is a browser server that is capable of being
 * a Backup Browser server or Master Browser server, but is not currently
 * fulfilling either of those roles.
 *
 * A Potential Browser MUST set type SV_TYPE_POTENTIAL_BROWSER (see section
 * 6.4.1) in its HostAnnouncement until it is ready to shut down. In its
 * last HostAnnouncement frame before it shuts down, it SHOULD specify a
 * type of  0.
 *
 * A Potential Browser server MUST receive and process BecomeBackup frames
 * (see section 6.9) and become a backup browser upon their receipt.
 *
 * A Potential Browser MUST participate in browser elections (see section
 * 6.8).
 *
 * 4.4.2  Backup Browser
 *
 * Backup Browser servers are a subset of the Potential Browsers that have
 * been chosen by the Master Browser on their subnet to be the Backup
 * Browsers for the subnet.
 *
 * A Backup Browser MUST set type SV_TYPE_BACKUP_BROWSER (see section
 * 6.4.1) in its HostAnnouncement until it is ready to shut down. In its
 * last HostAnnouncement frame before it shuts down, it SHOULD specify a
 * type of  0.
 *
 * A Backup Browser MUST listen for a LocalMasterAnnouncement frame (see
 * section 6.10) from the Local Master Browser, and use it to set the name
 * of the Master Browser it queries for the server and domain lists.
 *
 * A  Backup Browsers MUST periodically make a NetServerEnum2 request of
 * the Master Browser on its subnet for its domain to get a list of servers
 * in that domain, as well as a list of domains. The period is a
 * configuration option balancing currency of the information with network
 * traffic costs - a typical value is 15 minutes.
 *
 * A Backup Browser SHOULD force an election by sending a RequestElection
 * frame (see section 6.7) if it does not get a response to its periodic
 * NetServeEnum2 request to the Master Browser.
 *
 * A Backup Browser MUST receive and process NetServerEnum2 requests from
 * browser clients, for its own domain and others. If the request is for a
 * list of servers in its domain, or for a list of domains, it can answer
 * from its internal lists. If the request is for a list of servers in a
 * domain different than the one it serves, it sends a NetServerEnum2
 * request to the Domain Master Browser for that domain (which it can in
 * find in its list of domains and their Domain Master Browsers).
 *
 * A Backup Browser MUST participate in browser elections (see section
 * 6.8).
 *
 * 4.4.3 Master Browser
 *
 * Master Browsers are responsible for:
 * . indicating it is a Master Browser
 * . receiving server announcements and building a list of such servers
 *   and keeping it reasonably up-to-date.
 * . returning lists of Backup Browsers to browser clients.
 * . ensuring an appropriate number of Backup Browsers are available.
 * . announcing their existence to other Master Browsers on their subnet,
 *   to the Domain Master Browser for their domain, and to all browsers in
 *   their domain on their subnet
 * . forwarding requests for lists of servers on other domains to the
 *   Master Browser for that domain
 * . keeping a list of domains in its subnet
 * . synchronizing with the Domain Master Browser (if any) for its domain
 * . participating in browser elections
 * . ensuring that there is only one Master Browser on its subnet
 *
 * A Master Browser MUST set type SV_TYPE_MASTER_BROWSER (see section
 * 6.4.1) in its HostAnnouncement until it is ready to shut down. In its
 * last HostAnnouncement frame before it shuts down, it SHOULD specify a
 * type of  0.
 *
 * A Master Browser MUST receive and process HostAnnouncement frames from
 * servers, adding the server name and other information to its servers
 * list; it must mark them as "local" entries. Periodically, it MUST check
 * all local server entries to see if a server's HostAnnouncement has timed
 * out (no HostAnnouncement received for three times the periodicity the
 * server gave in the last received HostAnnouncement) and remove timed-out
 * servers from its list.
 *
 * A Master Browser MUST receive and process DomainAnnouncement frames (see
 * section 6.12) and maintain the domain names and their associated (Local)
 * Master Browsers in its internal domain list until they time out; it must
 * mark these as "local" entries. Periodically, it MUST check all local
 * domain entries to see if a server's DomainAnnouncement has timed out (no
 * DomainAnnouncement received for three times the periodicity the server
 * gave in the last received DomainAnnouncement) and remove timed-out
 * servers from its list.
 *
 * A Master Browser MUST receive and process GetBackupListRequest frames
 * from clients, returning GetBackupListResponse frames containing a list
 * of the Backup Servers for its domain.
 *
 * A Master Browser MUST eventually send BecomeBackup frames (see section
 * 6.9) to one or more Potential Browser servers to increase the number of
 * Backup Browsers if there are not enough Backup Browsers to handle the
 * anticipated query load. Note: possible good times for checking for
 * sufficient backup browsers are after being elected, when timing out
 * server HostAnnouncements, and when receiving a server's HostAnnouncement
 * for the first time.
 *
 * A Master Browser MUST periodically announce itself and the domain it
 * serves to other (Local) Master Browsers on its subnet, by sending a
 * DomainAnnouncement frame (see section 6.12) to its subnet.
 *
 * A Master Browser MUST send a MasterAnnouncement frame (see section 6.11)
 * to the Domain Master Browser after it is first elected, and periodically
 * thereafter. This informs the Domain Master Browser of the presence of
 * all the Master Browsers.
 *
 * A Master Browser MUST periodically announce itself to all browsers for
 * its domain on its subnet by sending a LocalMasterAnnouncement frame (see
 * section 6.10).
 *
 * A Master Browser MUST receive and process NetServerEnum2 requests from
 * browser clients, for its own domain and others. If the request is for a
 * list of servers in its domain, or for a list of domains, it can answer
 * from its internal lists. Entries in its list marked "local" MUST have
 * the SV_TYPE_LOCAL_LIST_ONLY bit set in the returned results; it must be
 * clear for all other entries. If the request is for a list of servers in
 * a domain different than the one it serves, it sends a NetServerEnum2
 * request to the Domain Master Browser for that domain (which it can in
 * find in its list of domains and their Domain Master Browsers).
 *
 *     Note: The list of servers that the Master Browser maintains and
 *     returns to the Backup Browsers, is limited in size to 64K of
 *     data. This will limit the number of systems that can be in a
 *     browse list in a single workgroup or domain to approximately two
 *     thousand systems.
 *
 * A Master Browser SHOULD request all servers to register with it by
 * sending an AnnouncementRequest frame, if, on becoming the Master Browser
 * by winning an election, its server list is empty. Otherwise, clients
 * might get an incomplete list of servers until the servers' periodic
 * registrations fill the server list.
 *
 * If the Master Browser on a subnet is not the Primary Domain Controller
 * (PDC), then it is a Local Master Browser.
 *
 * A Local Master Browser MUST periodically synchronize with the Domain
 * Master Browser (which is the PDC). This synchronization is performed by
 * making a NetServerEnum2 request to the Domain Master Browser and merging
 * the results with its list of servers and domains. An entry from the
 * Domain Master Browser should be marked "non-local", and must not
 * overwrite an entry with the same name marked "local". The Domain Master
 * Browser is located as specified in Appendix B.
 *
 * A Master Browser MUST participate in browser elections (see section
 * 6.8).
 *
 * A Master Browser MUST, if it receives a HostAnnouncement,
 * DomainAnnouncement, or LocalMasterAnnouncement frame another system that
 * claims to be the Master Browser for its domain, demote itself from
 * Master Browser and force an election. This ensures that there is only
 * ever one Master Browser in each workgroup or domain.
 *
 * A Master Browser SHOULD, if it loses an election, become a Backup
 * Browser (without being told to do so by the new Master Browser). Since
 * it has more up-to-date information in its lists than a Potential
 * Browser, it is more efficient to have it be a Backup Browser than to
 * promote a Potential Browser.
 *
 * 4.4.3.1 Preferred Master Browser
 *
 * A Preferred Master Browser supports exactly the same protocol elements
 * as a Potential Browser, except as follows.
 *
 * A Preferred Master Browser MUST always force an election when it starts
 * up.
 *
 * A Preferred Master Browser MUST participate in browser elections (see
 * section 6.8).
 *
 * A Preferred Master Browser MUST set the Preferred Master bit in the
 * RequestElection frame (see section 6.7) to bias the election in its
 * favor.
 *
 * A Preferred Master Browser SHOULD, if it loses an election,
 * automatically become a Backup Browser, without being told to do so by
 * the Master Browser.
 *
 * 4.4.4 Domain Master Browser
 *
 * Since the Domain Master Browser always runs on the PDC, it must
 * implement all the protocols required of a PDC in addition to the
 * browsing protocol, and that is way beyond the scope of this
 * specification.
 *
 * 5. Mailslot Protocol Specification
 *
 * The only transaction allowed to a mailslot is a mailslot write. Mailslot
 * writes requests are encapsulated in TRANSACT SMBs. The following table
 * shows the interpretation of the TRANSACT SMB parameters for a mailslot
 * transaction:
 *
 *  Name            Value               Description
 *  Command         SMB_COM_TRANSACTION
 *  Name            <name>              STRING name of mail slot to write;
 *                                      must start with "\\MAILSLOT\\"
 *  SetupCount      3                   Always 3 for mailslot writes
 *  Setup[0]        1                   Command code == write mailslot
 *  Setup[1]        Ignored
 *  Setup[2]        Ignored
 *  TotalDataCount  n                   Size of data in bytes to write to
 *                                      the mailslot
 *  Data[ n ]                           The data to write to the mailslot
 *
 */

/*
 * SMB: C transact, File = \MAILSLOT\BROWSE
 *   SMB: SMB Status = Error Success
 *     SMB: Error class = No Error
 *     SMB: Error code = No Error
 *   SMB: Header: PID = 0x0000 TID = 0x0000 MID = 0x0000 UID = 0x0000
 *     SMB: Tree ID   (TID) = 0 (0x0)
 *     SMB: Process ID  (PID) = 0 (0x0)
 *     SMB: User ID   (UID) = 0 (0x0)
 *     SMB: Multiplex ID (MID) = 0 (0x0)
 *     SMB: Flags Summary = 0 (0x0)
 *   SMB: Command = C transact
 *     SMB: Word count = 17
 *     SMB: Word parameters
 *     SMB: Total parm bytes = 0
 *     SMB: Total data bytes = 33
 *     SMB: Max parm bytes = 0
 *     SMB: Max data bytes = 0
 *     SMB: Max setup words = 0
 *     SMB: Transact Flags Summary = 0 (0x0)
 *       SMB: ...............0 = Leave session intact
 *       SMB: ..............0. = Response required
 *     SMB: Transact timeout = 0 (0x0)
 *     SMB: Parameter bytes = 0 (0x0)
 *     SMB: Parameter offset = 0 (0x0)
 *     SMB: Data bytes = 33 (0x21)
 *     SMB: Data offset = 86 (0x56)
 *     SMB: Setup word count = 3
 *     SMB: Setup words
 *     SMB: Mailslot opcode = Write mailslot
 *     SMB: Transaction priority = 1
 *     SMB: Mailslot class = Unreliable (broadcast)
 *     SMB: Byte count = 50
 *     SMB: Byte parameters
 *     SMB: Path name = \MAILSLOT\BROWSE
 *     SMB: Transaction data
 *   SMB: Data: Number of data bytes remaining = 33 (0x0021)
 *
 * 5. Mailslot Protocol Specification
 *
 * The only transaction allowed to a mailslot is a mailslot write. Mailslot
 * writes requests are encapsulated in TRANSACT SMBs. The following table
 * shows the interpretation of the TRANSACT SMB parameters for a mailslot
 * transaction:
 *
 *  Name            Value               Description
 *  Command         SMB_COM_TRANSACTION
 *  Name            <name>              STRING name of mail slot to write;
 *                                      must start with "\MAILSLOT\"
 *  SetupCount      3                   Always 3 for mailslot writes
 *  Setup[0]        1                   Command code == write mailslot
 *  Setup[1]        Ignored
 *  Setup[2]        Ignored
 *  TotalDataCount  n                   Size of data in bytes to write to
 *                                      the mailslot
 *  Data[ n ]                           The data to write to the mailslot
 *
 *	Magic		0xFF 'S' 'M' 'B'
 *	smb_com 	a byte, the "first" command
 *	Error		a 4-byte union, ignored in a request
 *	smb_flg		a one byte set of eight flags
 *	smb_flg2	a two byte set of 16 flags
 *	.		twelve reserved bytes, have a role
 *			in connectionless transports (IPX, UDP?)
 *	smb_tid		a 16-bit tree ID, a mount point sorta,
 *			0xFFFF is this command does not have
 *			or require a tree context
 *	smb_pid		a 16-bit process ID
 *	smb_uid		a 16-bit user ID, specific to this "session"
 *			and mapped to a system (bona-fide) UID
 *	smb_mid		a 16-bit multiplex ID, used to differentiate
 *			multiple simultaneous requests from the same
 *			process (pid) (ref RPC "xid")
 */

int
smb_browser_load_transact_header(unsigned char *buffer, int maxcnt,
    int data_count, int reply, char *mailbox)
{
	smb_msgbuf_t mb;
	int	mailboxlen;
	char *fmt;
	int result;
	short	class = (reply == ONE_WAY_TRANSACTION) ? 2 : 0;

	/*
	 * If the mailboxlen is an even number we need to pad the
	 * header so that the data starts on a word boundary.
	 */
	fmt = "Mb4.bw20.bwwwwb.wl2.wwwwb.wwwws";
	mailboxlen = strlen(mailbox) + 1;

	if ((mailboxlen & 0x01) == 0) {
		++mailboxlen;
		fmt = "Mb4.bw20.bwwwwb.wl2.wwwwb.wwwws.";
	}

	bzero(buffer, maxcnt);
	smb_msgbuf_init(&mb, buffer, maxcnt, 0);

	result = smb_msgbuf_encode(&mb, fmt,
	    SMB_COM_TRANSACTION,	/* Command */
	    0x18,
	    0x3,
	    17,				/* Count of parameter words */
	    0,				/* Total Parameter words sent */
	    data_count,			/* Total Data bytes sent */
	    2,				/* Max Parameters to return */
	    0,				/* Max data bytes to return */
	    0,				/* Max setup bytes to return */
	    reply,			/* No reply */
	    0xffffffff,			/* Timeout */
	    0,				/* Parameter bytes sent */
	    0,				/* Parameter offset */
	    data_count,			/* Data bytes sent */
	    69 + mailboxlen,		/* Data offset */
	    3,				/* Setup word count */
	    1,				/* Setup word[0] */
	    0,				/* Setup word[1] */
	    class,			/* Setup word[2] */
	    mailboxlen + data_count,	/* Total request bytes */
	    mailbox);			/* Mailbox address */

	smb_msgbuf_term(&mb);
	return (result);
}

static int
smb_browser_addr_of_subnet(struct name_entry *name, smb_hostinfo_t *hinfo,
    struct name_entry *result)
{
	uint32_t ipaddr, mask, saddr;
	struct addr_entry *addr;

	if (name == NULL)
		return (-1);

	if (hinfo->hi_nic.nic_smbflags & SMB_NICF_ALIAS)
		return (-1);

	ipaddr = hinfo->hi_nic.nic_ip.a_ipv4;
	mask = hinfo->hi_nic.nic_mask;

	*result = *name;
	addr = &name->addr_list;
	do {
		saddr = addr->sin.sin_addr.s_addr;
		if ((saddr & mask) == (ipaddr & mask)) {
			*result = *name;
			result->addr_list = *addr;
			result->addr_list.forw = result->addr_list.back =
			    &result->addr_list;
			return (0);
		}
		addr = addr->forw;
	} while (addr != &name->addr_list);

	return (-1);
}


static int
smb_browser_bcast_addr_of_subnet(struct name_entry *name, uint32_t bcast,
    struct name_entry *result)
{
	if (name != NULL && name != result)
		*result = *name;

	result->addr_list.sin.sin_family = AF_INET;
	result->addr_list.sinlen = sizeof (result->addr_list.sin);
	result->addr_list.sin.sin_addr.s_addr = bcast;
	result->addr_list.sin.sin_port = htons(DGM_SRVC_UDP_PORT);
	result->addr_list.forw = result->addr_list.back = &result->addr_list;
	return (0);
}

/*
 * 6.5 HostAnnouncement Browser Frame
 *
 * To advertise its presence, i.e. to publish itself as being available, a
 * non-browser server sends a HostAnnouncement browser frame. If the server
 * is a member of domain "D", this frame is sent to the NETBIOS unique name
 * D(1d) and mailslot "\\MAILSLOT\\BROWSE". The definition of  the
 * HostAnnouncement frame is:
 *
 *     struct {
 *         unsigned short  Opcode;
 *         unsigned char   UpdateCount;
 *         uint32_t   Periodicity;
 *         unsigned char   ServerName[];
 *         unsigned char   VersionMajor;
 *         unsigned char   VersionMinor;
 *         uint32_t   Type;
 *         uint32_t   Signature;
 *         unsigned char   Comment[];
 *     }
 *
 * where:
 *      Opcode - Identifies this structure as a browser server
 *          announcement and is defined as HostAnnouncement with a
 *          value of decimal 1.
 *
 *      UpdateCount - must be sent as zero and ignored on receipt.
 *
 *      Periodicity - The announcement frequency of the server (in
 *          seconds). The server will be removed from the browse list
 *          if it has not been heard from in 3X its announcement
 *          frequency. In no case will the server be removed from the
 *          browse list before the period 3X has elapsed. Actual
 *          implementations may take more than 3X to actually remove
 *          the server from the browse list.
 *
 *      ServerName - Null terminated ASCII server name (up to 16 bytes
 *          in length).
 *
 *      VersionMajor - The major version number of the OS the server
 *          is running. it will be returned by NetServerEnum2.
 *
 *      VersionMinor - The minor version number of the OS the server
 *          is running. This is entirely informational and does not
 *          have any significance for the browsing protocol.
 *
 *      Type - Specifies the type of the server. The server type bits
 *          are specified in the NetServerEnum2 section.
 *
 *      Signature -  The browser protocol minor version number in the
 *          low 8 bits, the browser protocol major version number in
 *          the next higher 8 bits and the signature 0xaa55 in the
 *          high 16 bits of this field. Thus, for this version of the
 *          browser protocol (1.15) this field has the value
 *          0xaa55010f. This may used to isolate browser servers that
 *          are running out of revision browser software; otherwise,
 *          it is ignored.
 *
 *      Comment - Null terminated ASCII comment for the server.
 *          Limited to 43 bytes.
 *
 * When a non-browser server starts up, it announces itself in the manner
 * described once every minute. The frequency of these statements is
 * gradually stretched to once every 12 minutes.
 *
 * Note: older non-browser servers in a domain "D" sent HostAnnouncement
 * frames to the NETBIOS group name D(00). Non-Browser servers supporting
 * version 1.15 of the browsing protocol SHOULD NOT use this NETBIOS name,
 * but for backwards compatibility Master Browsers MAY receive and process
 * HostAnnouncement frames on this name as described above for D(1d).
 */

static void
smb_browser_send_HostAnnouncement(smb_hostinfo_t *hinfo,
    uint32_t next_announcement, boolean_t remove,
    struct addr_entry *addr, char suffix)
{
	smb_msgbuf_t mb;
	int offset, announce_len, data_length;
	struct name_entry dest_name;
	unsigned char *buffer;
	uint32_t type;
	char resource_domain[SMB_PI_MAX_DOMAIN];

	if (smb_getdomainname(resource_domain, SMB_PI_MAX_DOMAIN) != 0)
		return;
	(void) utf8_strupr(resource_domain);

	if (addr == NULL) {
		/* Local master Browser */
		smb_init_name_struct((unsigned char *)resource_domain, suffix,
		    0, 0, 0, 0, 0, &dest_name);
		if (smb_browser_bcast_addr_of_subnet(0, hinfo->hi_nic.nic_bcast,
		    &dest_name) < 0)
			return;
	} else {
		smb_init_name_struct((unsigned char *)resource_domain, suffix,
		    0, 0, 0, 0, 0, &dest_name);
		dest_name.addr_list = *addr;
		dest_name.addr_list.forw = dest_name.addr_list.back =
		    &dest_name.addr_list;
	}

	/* give some extra room */
	buffer = (unsigned char *)malloc(MAX_DATAGRAM_LENGTH * 2);
	if (buffer == 0) {
		syslog(LOG_ERR, "HostAnnouncement: resource shortage");
		return;
	}

	data_length = 1 + 1 + 4 + 16 + 1 + 1 + 4 + 4 +
	    strlen(hinfo->hi_nic.nic_cmnt) + 1;

	offset = smb_browser_load_transact_header(buffer,
	    MAX_DATAGRAM_LENGTH, data_length, ONE_WAY_TRANSACTION,
	    MAILSLOT_BROWSE);

	if (offset < 0) {
		free(buffer);
		return;
	}

	/*
	 * A non-browser server SHOULD send a HostAnnouncement browser frame
	 * specifying a type of 0 just prior to shutting down, to allow it to
	 * quickly be removed from the list of available servers.
	 */
	if (remove || (nb_status.state & NETBIOS_SHUTTING_DOWN))
		type = 0;
	else
		type = hinfo->hi_type;

	smb_msgbuf_init(&mb, buffer + offset, MAX_DATAGRAM_LENGTH - offset, 0);

	announce_len = smb_msgbuf_encode(&mb, "bbl16cbblls",
	    HOST_ANNOUNCEMENT,
	    ++hinfo->hi_updatecnt,
	    next_announcement * 60000,	/* Periodicity in MilliSeconds */
	    hinfo->hi_nbname,
	    SMB_VERSION_MAJOR,
	    SMB_VERSION_MINOR,
	    type,
	    SMB_SERVER_SIGNATURE,
	    hinfo->hi_nic.nic_cmnt);

	if (announce_len > 0)
		(void) smb_netbios_datagram_send(&hinfo->hi_netname, &dest_name,
		    buffer, offset + announce_len);

	free(buffer);
	smb_msgbuf_term(&mb);
}

static void
smb_browser_process_AnnouncementRequest(struct datagram *datagram,
    char *mailbox)
{
	smb_hostinfo_t *hinfo;
	uint32_t next_announcement;
	uint32_t delay = random() % 29; /* in seconds */
	boolean_t h_found = B_FALSE;

	if (strcmp(mailbox, MAILSLOT_LANMAN) != 0) {
		syslog(LOG_DEBUG, "smb_browse: Wrong Mailbox (%s)", mailbox);
		return;
	}

	(void) sleep(delay);

	(void) rw_rdlock(&smb_binfo.bi_hlist_rwl);
	hinfo = list_head(&smb_binfo.bi_hlist);
	while (hinfo) {
		if ((hinfo->hi_nic.nic_ip.a_ipv4 &
		    hinfo->hi_nic.nic_mask) ==
		    (datagram->src.addr_list.sin.sin_addr.s_addr &
		    hinfo->hi_nic.nic_mask)) {
			h_found = B_TRUE;
			break;
		}
		hinfo = list_next(&smb_binfo.bi_hlist, hinfo);
	}

	if (h_found) {
		next_announcement = hinfo->hi_nextannouce * 60 * 1000;
		smb_browser_send_HostAnnouncement(hinfo, next_announcement,
		    B_FALSE, &datagram->src.addr_list, 0x1D);
	}
	(void) rw_unlock(&smb_binfo.bi_hlist_rwl);
}

void *
smb_browser_dispatch(void *arg)
{
	struct datagram *datagram = (struct datagram *)arg;
	smb_msgbuf_t 	mb;
	int		rc;
	unsigned char	command;
	unsigned char	parameter_words;
	unsigned short	total_parameter_words;
	unsigned short	total_data_count;
	unsigned short	max_parameters_to_return;
	unsigned short	max_data_to_return;
	unsigned char	max_setup_bytes_to_return;
	unsigned short	reply;
	unsigned short	parameter_bytes_sent;
	unsigned short	parameter_offset;
	unsigned short	data_bytes_sent;
	unsigned short	data_offset;
	unsigned char	setup_word_count;
	unsigned short	setup_word_0;
	unsigned short	setup_word_1;
	unsigned short	setup_word_2;
	unsigned short	total_request_bytes;
	char 		*mailbox;
	unsigned char	message_type;
	unsigned char 	*data;
	int		datalen;

	syslog(LOG_DEBUG, "smb_browse: packet_received");

	smb_msgbuf_init(&mb, datagram->data, datagram->data_length, 0);
	rc = smb_msgbuf_decode(&mb, "Mb27.bwwwwb.w6.wwwwb.wwwws",
	    &command,			/* Command */
	    &parameter_words,		/* Count of parameter words */
	    &total_parameter_words,	/* Total Parameter words sent */
	    &total_data_count,		/* Total Data bytes sent */
	    &max_parameters_to_return,	/* Max Parameters to return */
	    &max_data_to_return,	/* Max data bytes to return */
	    &max_setup_bytes_to_return,	/* Max setup bytes to return */
	    &reply,			/* No reply */
	    &parameter_bytes_sent,	/* Parameter bytes sent */
	    &parameter_offset,		/* Parameter offset */
	    &data_bytes_sent,		/* Data bytes sent */
	    &data_offset,		/* Data offset */
	    &setup_word_count,		/* Setup word count */
	    &setup_word_0,		/* Setup word[0] */
	    &setup_word_1,		/* Setup word[1] */
	    &setup_word_2,		/* Setup word[2] */
	    &total_request_bytes,	/* Total request bytes */
	    &mailbox);			/* Mailbox address */

	if (rc < 0) {
		syslog(LOG_ERR, "smb_browser_dispatch: decode error");
		smb_msgbuf_term(&mb);
		free(datagram);
		return (0);
	}

	data = &datagram->data[data_offset];
	datalen = datagram->data_length - data_offset;

	/*
	 * The PDC location protocol, i.e. anything on the \\NET
	 * mailslot, is handled by the smb_netlogon module.
	 */
	if (strncasecmp("\\MAILSLOT\\NET\\", mailbox, 14) == 0) {
		smb_netlogon_receive(datagram, mailbox, data, datalen);
		smb_msgbuf_term(&mb);
		free(datagram);
		return (0);
	}

	/*
	 * If it's not a netlogon message, assume it's a browser request.
	 * This is not the most elegant way to extract the command byte
	 * but at least we no longer use it to get the netlogon opcode.
	 */
	message_type = datagram->data[data_offset];

	switch (message_type) {
	case ANNOUNCEMENT_REQUEST :
		smb_browser_process_AnnouncementRequest(datagram, mailbox);
		break;

	default:
		syslog(LOG_DEBUG, "smb_browse: invalid message_type(%d, %x)",
		    message_type, message_type);
		break;
	}

	smb_msgbuf_term(&mb);
	free(datagram);
	return (0);
}


/*
 * 11.1 Registered unique names
 *
 *  <COMPUTER>(00)
 *     This name is used by all servers and clients to receive second
 *     class mailslot messages. A system must add this name in order to
 *     receive mailslot messages. The only browser requests that should
 *     appear on this name are BecomeBackup, GetBackupListResp,
 *     MasterAnnouncement, and LocalMasterAnnouncement frames. All other
 *     datagrams (other than the expected non-browser datagrams) may be
 *     ignored and an error logged.
 *
 *   <DOMAIN>(1d)
 *     This name is used to identify a master browser server for domain
 *     "DOMAIN" on a subnet.  A master browser server adds this name as a
 *     unique NETBIOS name when it becomes master browser. If the attempt
 *     to add the name fails, the master browser server assumes that there
 *     is another master in the domain and will fail to come up. It may
 *     log an error if the failure occurs more than 3 times in a row (this
 *     either indicates some form of network misconfiguration or a
 *     software error). The only requests that should appear on this name
 *     are GetBackupListRequest and HostAnnouncement requests. All other
 *     datagrams on this name may be ignored (and an error logged). If
 *     running a NETBIOS name service (NBNS, such as WINS), this name
 *     should not be registered with the NBNS.
 *
 *   <DOMAIN>(1b)
 *     This name is used to identify the Domain Master Browser for domain
 *     "DOMAIN" (which is also the primary domain controller). It is a
 *     unique name added only by the primary domain controller. The
 *     primary domain controller will respond to GetBackupListRequest on
 *     this name just as it responds to these requests on the <DOMAIN>(1d)
 *     name.
 *
 * 11.2 Registered group names
 *
 *   (01)(02)__MSBROWSE__(02)(01)
 *     This name is used by Master Browsers to announce themselves to the
 *     other Master Browsers on a subnet. It is added as a group name by
 *     all Master Browser servers. The only broadcasts that should appear
 *     on this name is DomainAnnouncement requests. All other datagrams
 *     can be ignored.
 *
 *   <DOMAIN>(00)
 *     This name is used by clients and servers in domain "DOMAIN" to
 *     process server announcements. The only requests that should appear
 *     on this name that the browser is interested in are
 *     AnnouncementRequest and NETLOGON_QUERY (to locate the PDC) packets.
 *     All other unidentifiable requests may be ignored (and an error
 *     logged).
 *
 *   <DOMAIN>(1E)
 *     This name is used for announcements to browsers for domain "DOMAIN"
 *     on a subnet. This name is registered by all the browser servers in
 *     the domain. The only requests that should appear on this name are
 *     RequestElection and AnnouncementRequest packets. All other
 *     datagrams may be ignored (and an error logged).
 *
 *   <DOMAIN>(1C)
 *     This name is registered by Primary Domain Controllers.
 */

static void
smb_browser_config(void)
{
	smb_hostinfo_t *hinfo;
	struct name_entry	name;
	struct name_entry	master;
	struct name_entry	dest;
	struct name_entry	*entry;
	char resource_domain[SMB_PI_MAX_DOMAIN];
	int rc;

	if (smb_browser_init() != 0)
		return;

	if (smb_getdomainname(resource_domain, SMB_PI_MAX_DOMAIN) != 0)
		return;
	(void) utf8_strupr(resource_domain);

	/* domain<00> */
	smb_init_name_struct((unsigned char *)resource_domain, 0x00,
	    0, 0, 0, 0, 0, &name);
	entry = smb_name_find_name(&name);
	smb_name_unlock_name(entry);

	(void) rw_rdlock(&smb_binfo.bi_hlist_rwl);
	hinfo = list_head(&smb_binfo.bi_hlist);
	while (hinfo) {
		smb_init_name_struct((unsigned char *)resource_domain, 0x00, 0,
		    hinfo->hi_nic.nic_ip.a_ipv4,
		    htons(DGM_SRVC_UDP_PORT), NAME_ATTR_GROUP,
		    NAME_ATTR_LOCAL, &name);
		(void) smb_name_add_name(&name);

		hinfo = list_next(&smb_binfo.bi_hlist, hinfo);
	}
	(void) rw_unlock(&smb_binfo.bi_hlist_rwl);

	/* All our local master browsers */
	smb_init_name_struct((unsigned char *)resource_domain, 0x1D,
	    0, 0, 0, 0, 0, &dest);
	entry = smb_name_find_name(&dest);

	if (entry) {
		(void) rw_rdlock(&smb_binfo.bi_hlist_rwl);
		hinfo = list_head(&smb_binfo.bi_hlist);
		while (hinfo) {
			rc = smb_browser_addr_of_subnet(entry, hinfo, &master);
			if (rc == 0) {
				syslog(LOG_DEBUG,
				    "smbd: Master browser found at %s",
				    inet_ntoa(master.addr_list.sin.sin_addr));
			}
			hinfo = list_next(&smb_binfo.bi_hlist, hinfo);
		}
		(void) rw_unlock(&smb_binfo.bi_hlist_rwl);

		smb_name_unlock_name(entry);
	}

	/* Domain master browser */
	smb_init_name_struct((unsigned char *)resource_domain,
	    0x1B, 0, 0, 0, 0, 0, &dest);

	if ((entry = smb_name_find_name(&dest)) != 0) {
		syslog(LOG_DEBUG, "smbd: Domain Master browser for %s is %s",
		    resource_domain,
		    inet_ntoa(entry->addr_list.sin.sin_addr));
		smb_name_unlock_name(entry);
	}
}

static int
smb_browser_init(void)
{
	smb_hostinfo_t *hinfo;
	smb_niciter_t ni;
	uint32_t type;

	(void) rw_wrlock(&smb_binfo.bi_hlist_rwl);
	smb_browser_infofree();

	if (smb_nic_getfirst(&ni) != 0) {
		(void) rw_unlock(&smb_binfo.bi_hlist_rwl);
		return (-1);
	}

	type = MY_SERVER_TYPE;
	if (smb_config_get_secmode() == SMB_SECMODE_DOMAIN)
		type |= SV_DOMAIN_MEMBER;

	do {
		if ((ni.ni_nic.nic_smbflags & SMB_NICF_NBEXCL) ||
		    (ni.ni_nic.nic_smbflags & SMB_NICF_ALIAS))
			continue;

		hinfo = malloc(sizeof (smb_hostinfo_t));
		if (hinfo == NULL) {
			smb_browser_infofree();
			(void) rw_unlock(&smb_binfo.bi_hlist_rwl);
			return (-1);
		}

		hinfo->hi_nic = ni.ni_nic;
		/* One Minute announcements for first five */
		hinfo->hi_nextannouce = 1;
		hinfo->hi_interval = 1;
		hinfo->hi_reps = 5;
		hinfo->hi_updatecnt = 0;
		hinfo->hi_type = type;

		/* This is the name used for HostAnnouncement */
		(void) strlcpy(hinfo->hi_nbname, hinfo->hi_nic.nic_host,
		    NETBIOS_NAME_SZ);
		(void) utf8_strupr(hinfo->hi_nbname);
		/* 0x20: file server service  */
		smb_init_name_struct((unsigned char *)hinfo->hi_nbname,
		    0x20, 0, hinfo->hi_nic.nic_ip.a_ipv4,
		    htons(DGM_SRVC_UDP_PORT), NAME_ATTR_UNIQUE, NAME_ATTR_LOCAL,
		    &hinfo->hi_netname);

		list_insert_tail(&smb_binfo.bi_hlist, hinfo);
		smb_binfo.bi_hcnt++;
	} while (smb_nic_getnext(&ni) == 0);

	(void) rw_unlock(&smb_binfo.bi_hlist_rwl);
	return (0);
}

/*
 * smb_browser_non_master_duties
 *
 * To advertise its presence, i.e. to publish itself as being available, a
 * non-browser server sends a HostAnnouncement browser frame. If the server
 * is a member of domain "D", this frame is sent to the NETBIOS unique name
 * D(1d) and mailslot "\\MAILSLOT\\BROWSE".
 */
static void
smb_browser_non_master_duties(smb_hostinfo_t *hinfo, boolean_t remove)
{
	struct name_entry name;
	struct name_entry *dest;
	struct addr_entry addr;
	char resource_domain[SMB_PI_MAX_DOMAIN];

	smb_browser_send_HostAnnouncement(hinfo, hinfo->hi_interval,
	    remove, 0, 0x1D);
	if (smb_getdomainname(resource_domain, SMB_PI_MAX_DOMAIN) != 0)
		return;

	(void) utf8_strupr(resource_domain);

	smb_init_name_struct((unsigned char *)resource_domain, 0x1D,
	    0, 0, 0, 0, 0, &name);

	if ((dest = smb_name_find_name(&name))) {
		addr = dest->addr_list;
		addr.forw = addr.back = &addr;
		smb_name_unlock_name(dest);
		smb_browser_send_HostAnnouncement(hinfo, hinfo->hi_interval,
		    remove, &addr, 0x1D);
	} else {
		smb_init_name_struct((unsigned char *)resource_domain, 0x1B,
		    0, 0, 0, 0, 0, &name);
		if ((dest = smb_name_find_name(&name))) {
			addr = dest->addr_list;
			addr.forw = addr.back = &addr;
			smb_name_unlock_name(dest);
			smb_browser_send_HostAnnouncement(hinfo,
			    remove, hinfo->hi_interval, &addr, 0x1B);
		}
	}

	/*
	 * One Minute announcements for first five
	 * minutes, one minute longer each round
	 * until 12 minutes and every 12 minutes
	 * thereafter.
	 */
	if (--hinfo->hi_reps == 0) {
		if (hinfo->hi_interval < 12)
			hinfo->hi_interval++;

		hinfo->hi_reps = 1;
	}

	hinfo->hi_nextannouce = hinfo->hi_interval;
}


/*
 * smb_browser_sleep
 *
 * Put browser in 1 minute sleep if netbios services are not
 * shutting down and both name and datagram services are still
 * running. It'll wake up after 1 minute or if one of the above
 * conditions go false. It checks the conditions again and return
 * 1 if everything is ok or 0 if browser shouldn't continue
 * running.
 */
static boolean_t
smb_browser_sleep(void)
{
	boolean_t slept = B_FALSE;
	timestruc_t to;

	(void) mutex_lock(&nb_status.mtx);
	while (((nb_status.state & NETBIOS_SHUTTING_DOWN) == 0) &&
	    (nb_status.state & NETBIOS_NAME_SVC_RUNNING) &&
	    (nb_status.state & NETBIOS_DATAGRAM_SVC_RUNNING)) {

		if (slept) {
			(void) mutex_unlock(&nb_status.mtx);
			return (B_TRUE);
		}

		to.tv_sec = 60;  /* 1 minute */
		to.tv_nsec = 0;
		(void) cond_reltimedwait(&nb_status.cv, &nb_status.mtx, &to);
		slept = B_TRUE;
	}
	(void) mutex_unlock(&nb_status.mtx);

	return (B_FALSE);
}

/*
 * smb_browser_daemon
 *
 * Smb Netbios browser daemon.
 */
/*ARGSUSED*/
void *
smb_browser_daemon(void *arg)
{
	smb_hostinfo_t *hinfo;

	smb_browser_infoinit();
	smb_browser_config();

	smb_netbios_chg_status(NETBIOS_BROWSER_RUNNING, 1);

restart:
	do {
		(void) rw_rdlock(&smb_binfo.bi_hlist_rwl);
		hinfo = list_head(&smb_binfo.bi_hlist);
		while (hinfo) {
			if (--hinfo->hi_nextannouce > 0 ||
			    hinfo->hi_nic.nic_bcast == 0) {
				hinfo = list_next(&smb_binfo.bi_hlist, hinfo);
				continue;
			}

			smb_browser_non_master_duties(hinfo, B_FALSE);

			/* Check to see whether reconfig is needed */
			(void) mutex_lock(&smb_binfo.bi_mtx);
			if (smb_binfo.bi_changed) {
				smb_binfo.bi_changed = B_FALSE;
				(void) mutex_unlock(&smb_binfo.bi_mtx);
				(void) rw_unlock(&smb_binfo.bi_hlist_rwl);
				smb_browser_config();
				goto restart;
			}
			(void) mutex_unlock(&smb_binfo.bi_mtx);

			hinfo = list_next(&smb_binfo.bi_hlist, hinfo);
		}
		(void) rw_unlock(&smb_binfo.bi_hlist_rwl);
	} while (smb_browser_sleep());

	smb_browser_infoterm();
	smb_netbios_chg_status(NETBIOS_BROWSER_RUNNING, 0);
	return (0);
}

/*
 * smb_browser_netlogon
 *
 * Sends SAMLOGON/NETLOGON request for all host/ips, except
 * aliases, to find a domain controller.
 *
 * The dc argument will be set if a DC is found.
 */
boolean_t
smb_browser_netlogon(char *domain, char *dc, uint32_t dc_len)
{
	smb_hostinfo_t *hinfo;
	int protocol;
	boolean_t found = B_FALSE;
	timestruc_t to;
	int err;

	if (smb_config_getbool(SMB_CI_DOMAIN_MEMB))
		protocol = NETLOGON_PROTO_SAMLOGON;
	else
		protocol = NETLOGON_PROTO_NETLOGON;

	(void) rw_rdlock(&smb_binfo.bi_hlist_rwl);
	hinfo = list_head(&smb_binfo.bi_hlist);
	while (hinfo) {
		if ((hinfo->hi_nic.nic_smbflags & SMB_NICF_ALIAS) == 0)
			smb_netlogon_request(&hinfo->hi_netname, protocol,
			    domain);
		hinfo = list_next(&smb_binfo.bi_hlist, hinfo);
	}
	(void) rw_unlock(&smb_binfo.bi_hlist_rwl);

	bzero(dc, dc_len);
	to.tv_sec = 30;
	to.tv_nsec = 0;
	(void) mutex_lock(&ntdomain_mtx);
	while (ntdomain_info.n_ipaddr == 0) {
		err = cond_reltimedwait(&ntdomain_cv, &ntdomain_mtx, &to);
		if (err == ETIME)
			break;
	}

	if (ntdomain_info.n_ipaddr != 0) {
		(void) strlcpy(dc, ntdomain_info.n_name, dc_len);
		found = B_TRUE;
	}
	(void) mutex_unlock(&ntdomain_mtx);

	return (found);
}

/*
 * smb_browser_infoinit
 *
 * This function is called only once when browser daemon starts
 * to initialize global smb_binfo structure
 */
static void
smb_browser_infoinit(void)
{
	(void) mutex_lock(&ntdomain_mtx);
	bzero(&ntdomain_info, sizeof (ntdomain_info));
	(void) mutex_unlock(&ntdomain_mtx);

	(void) rw_wrlock(&smb_binfo.bi_hlist_rwl);
	list_create(&smb_binfo.bi_hlist, sizeof (smb_hostinfo_t),
	    offsetof(smb_hostinfo_t, hi_lnd));
	smb_binfo.bi_hcnt = 0;
	(void) rw_unlock(&smb_binfo.bi_hlist_rwl);

	(void) mutex_lock(&smb_binfo.bi_mtx);
	smb_binfo.bi_changed = B_FALSE;
	(void) mutex_unlock(&smb_binfo.bi_mtx);
}

/*
 * smb_browser_infoterm
 *
 * This function is called only once when browser daemon stops
 * to destruct smb_binfo structure
 */
static void
smb_browser_infoterm(void)
{
	(void) rw_wrlock(&smb_binfo.bi_hlist_rwl);
	smb_browser_infofree();
	list_destroy(&smb_binfo.bi_hlist);
	(void) rw_unlock(&smb_binfo.bi_hlist_rwl);
}

/*
 * smb_browser_infofree
 *
 * Removes all the hostinfo structures from the browser list
 * and frees the allocated memory
 */
static void
smb_browser_infofree(void)
{
	smb_hostinfo_t *hinfo;

	while ((hinfo = list_head(&smb_binfo.bi_hlist)) != NULL) {
		list_remove(&smb_binfo.bi_hlist, hinfo);
		free(hinfo);
	}

	smb_binfo.bi_hcnt = 0;
}
