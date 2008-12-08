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
 * Copyright 2008 Emulex.  All rights reserved.
 * Use is subject to License terms.
 */


#ifndef _EMLXS_MESSAGES_H
#define	_EMLXS_MESSAGES_H

#ifdef	__cplusplus
extern "C" {
#endif


#ifdef DEF_MSG_REPORT

#define	DEFINE_MSG(_id, _name, _msg, _level, _mask, _desc, _action) \
		{_msg, _id, _level, _mask, _desc, _action, 0},

#else	/* DEF_MSG_REPORT */

#ifdef DEF_MSG_STRUCT

#define	DEFINE_MSG(_id, _name, _msg, _level, _mask, _desc, _action) \
			emlxs_msg_t _name = {_msg, _id, _level, _mask};

#else

#define	DEFINE_MSG(_id, _name, _msg, _level, _mask, _desc, _action) \
			extern emlxs_msg_t _name;

#endif	/* DEF_MSG_STRUCT */

#endif	/* DEF_MSG_REPORT */


/*
 *
 * LOG Message Types Numbering Sequence
 *
 * Message Group            From
 *
 * MISC                     000
 * DRIVER                   100    -Driver Attach and Detach events
 * INIT                     200    -HBA initialization events
 * MEM                      300
 * SLI                      400
 * MBOX                     500
 * NODE                     600
 * LINK                     700
 * ELS                      800
 * PKT                      900
 * FCP                      1000
 * FCT (FCP Target)         1100
 * IP                       1200
 * SFS               		1300
 * IOCTL                    1400
 * FIRMWARE                 1500
 * CT                       1600
 * FCSP                     1700
 * EVENTS                   2000
 *
 */

#ifdef DEF_MSG_REPORT
typedef struct emlxs_msg_group {
	uint32_t min;
	uint32_t max;
	char desc[80];

} emlxs_msg_group_t;

emlxs_msg_group_t msg_group[] =
{
	{0, 99, "Miscellaneous Events"},
	{100, 199, "Driver Events"},
	{200, 299, "HBA Initialization Events"},
	{300, 399, "Memory Management Events"},
	{400, 499, "Service level Interface (SLI) Events"},
	{500, 599, "Mailbox Events"},
	{600, 699, "Node Events"},
	{700, 799, "Link Events"},
	{800, 899, "ELS Events"},
	{900, 999, "General I/O Packet Events"},
	{1000, 1099, "FCP Traffic Events"},
	{1100, 1199, "FCT Traffic Events"},
	{1200, 1299, "IP Traffic Events"},
	{1300, 1399, "Solaris SFS Events"},
	{1400, 1499, "IOCTL Events"},
	{1500, 1599, "Firmware Download Events"},
	{1600, 1699, "Common Transport Events"},
	{1700, 1799, "Fibre Channel Security Protocol (FCSP) Events"},
};
#define	MAX_MSG_GROUPS   (sizeof (msg_group)/sizeof (emlxs_msg_group_t))
#endif	/* DEF_MSG_REPORT */


/* Verbose flags */
#define	MSG_DISABLED	0x00000000	/* Always off */
#define	MSG_MISC	0x00000001	/* Misc events */
#define	MSG_DRIVER	0x00000002	/* Driver attach and detach events */
#define	MSG_INIT	0x00000004	/* Initialization events */
#define	MSG_MEM		0x00000008	/* Memory management events */
#define	MSG_SLI		0x00000010	/* SLI events */
#define	MSG_MBOX	0x00000020	/* Mailbox events */
#define	MSG_NODE	0x00000040	/* Node table events */
#define	MSG_LINK	0x00000080	/* Link events */
#define	MSG_ELS		0x00000100	/* ELS events */
#define	MSG_PKT		0x00000200	/* General I/O packet events */
#define	MSG_FCP		0x00000400	/* FCP traffic events */
#define	MSG_FCT		0x00000800	/* FCP Target Mode events */
#define	MSG_IP		0x00001000	/* IP traffic events */
#define	MSG_SFS		0x00002000	/* ULP interface events */
#define	MSG_IOCTL	0x00004000	/* IOCtl events */
#define	MSG_FIRMWARE	0x00008000	/* Firmware download events */
#define	MSG_CT		0x00010000	/* CT events */
#define	MSG_FCSP	0x00020000	/* FCSP events */
#define	MSG_RESV18	0x00040000
#define	MSG_RESV19	0x00080000
#define	MSG_RESV20	0x00100000
#define	MSG_RESV21	0x00200000
#define	MSG_FCT_API	0x00400000	/* FCP Target Mode API trace */
#define	MSG_FCT_DETAIL	0x00800000	/* Detailed Target Mode events */
#define	MSG_FCSP_DETAIL	0x01000000	/* Detailed FCSP events */
#define	MSG_NODE_DETAIL	0x02000000	/* Detailed node events */
#define	MSG_IOCTL_DETAIL 0x04000000	/* Detailed IOCTL events */
#define	MSG_IP_DETAIL	0x08000000	/* Detailed ip events (very verbose) */
#define	MSG_FIRMWARE_DETAIL 0x10000000	/* Detailed firmware */
					/*   download events (very verbose) */
#define	MSG_SFS_DETAIL	0x20000000	/* Detailed SFS interface events */
					/*   (very verbose) */
#define	MSG_MBOX_DETAIL	0x40000000	/* Detailed Mailbox events */
					/*   (very verbose) */
#define	MSG_SLI_DETAIL	0x80000000	/* Detailed SLI events */
					/*   (very verbose) */
#define	MSG_ALWAYS	0xffffffff	/* Always on   */

/* DFC Events */
#define	EVT_LINK	0x00000001	/* FC_REG_LINK_EVENT */
#define	EVT_RSCN	0x00000002	/* FC_REG_RSCN_EVENT */
#define	EVT_CT		0x00000004	/* FC_REG_CT_EVENT   */
#define	EVT_MPULSE	0x00000008	/* FC_REG_MULTIPULSE_EVENT */
#define	EVT_DUMP	0x00000010	/* FC_REG_DUMP_EVENT */
#define	EVT_TEMP	0x00000020	/* FC_REG_TEMP_EVENT */
#define	EVT_FCOE	0x80000000	/* FC_REG_FCOE_EVENT */

/* Msg Levels */
#define	EMLXS_DEBUG	1
#define	EMLXS_NOTICE	2
#define	EMLXS_WARNING	3
#define	EMLXS_ERROR	4
#define	EMLXS_PANIC	5
#define	EMLXS_EVENT	6


typedef struct emlxs_msg {
	char buffer[64];	/* Msg buffer */
	uint32_t id;	/* Msg number */
	uint32_t level;	/* Msg level  */
	uint32_t mask;	/* Msg mask (bit field) Message will be logged only */

#ifdef DEF_MSG_REPORT
	char desc[512];
	char action[512];
	uint32_t flags;
#endif	/* DEF_MSG_REPORT */

} emlxs_msg_t;


/* ACTION defines (common) */
#define	ACTION_NONE		"No action needed, informational."
#define	ACTION_NONE_REP		"No action needed, informational." \
				" However, if the problem persists," \
				" report these errors to your customer" \
				" service representative."
#define	ACTION_NONE_ADM		"No action needed, informational." \
				" However, if the problem persists, report" \
				" these errors to your system administrator."
#define	ACTION_CHK_HSCFG	"Check your hardware and software" \
				" configuration.  If the problem persists," \
				" report these errors to your customer" \
				" service representative."
#define	ACTION_CHK_HCFG		"Check your hardware configuration." \
				"  If the problem persists, report these" \
				" errors to your customer service" \
				" representative."
#define	ACTION_CHK_CONN		"Check your network connections." \
				"  If the problem persists, report these" \
				" errors to your system administrator."
#define	ACTION_REP		"Contact your customer service" \
				" representative."
#define	ACTION_IMG_REP		"Obtain the proper image file." \
				" If the problem persists, report these" \
				" errors to your customer service" \
				" representative."


/* MESSAGE defines */
#ifdef DEF_MSG_REPORT
emlxs_msg_t emlxs_message[] =
{
#endif	/* DEF_MSG_REPORT */

	/*
	 * GROUP:	MISC	000 - 099
	 */

	DEFINE_MSG(1, \
		    emlxs_debug_msg, \
		    "", \
		    EMLXS_DEBUG, \
		    MSG_MISC, \
		    "This is a general purpose informational message.", \
		    ACTION_NONE)

	DEFINE_MSG(2, \
		    emlxs_notice_msg, \
		    "", \
		    EMLXS_NOTICE, \
		    MSG_MISC, \
		    "This is a general purpose informational message.", \
		    ACTION_NONE)

	DEFINE_MSG(3, \
		    emlxs_warning_msg, \
		    "", \
		    EMLXS_WARNING, \
		    MSG_MISC, \
		    "This is a general purpose warning message.", \
		    ACTION_NONE)

	DEFINE_MSG(4, \
		    emlxs_error_msg, \
		    "", \
		    EMLXS_ERROR, \
		    MSG_MISC, \
		    "This is a general purpose error message.", \
		    ACTION_NONE)

	DEFINE_MSG(5, \
		    emlxs_panic_msg, \
		    "", \
		    EMLXS_PANIC, \
		    MSG_MISC, \
		    "This is a general purpose panic message.", \
		    ACTION_REP)

	DEFINE_MSG(6, \
		    emlxs_event_msg, \
		    "", \
		    EMLXS_EVENT, \
		    MSG_MISC, \
		    "This is a general purpose event message.", \
		    ACTION_REP)

	/*
	 * GROUP:	DRIVER	100 - 199
	 */

	DEFINE_MSG(100, \
		    emlxs_attach_msg, \
		    "Driver attach.", \
		    EMLXS_NOTICE, \
		    MSG_DRIVER, \
		    "This indicates that the driver is performing an attach"
			" operation.", \
		    ACTION_NONE)

	DEFINE_MSG(101, \
		    emlxs_attach_failed_msg, \
		    "Driver attach failed.", \
		    EMLXS_ERROR, \
		    MSG_DRIVER, \
		    "This indicates that the driver was unable to attach due"
			" to some issue.", \
		    ACTION_CHK_HSCFG)

	DEFINE_MSG(102, \
		    emlxs_attach_debug_msg, \
		    "Driver attach.", \
		    EMLXS_DEBUG, \
		    MSG_DRIVER, \
		    "This indicates that the driver is performing a attach"
			" operation.", \
		    ACTION_NONE)

	DEFINE_MSG(110, \
		    emlxs_detach_msg, \
		    "Driver detach.", \
		    EMLXS_NOTICE, \
		    MSG_DRIVER, \
		    "This indicates that the driver is performing a detach"
			" operation.", \
		    ACTION_NONE)

	DEFINE_MSG(111, \
		    emlxs_detach_failed_msg, \
		    "Driver detach failed.", \
		    EMLXS_ERROR, \
		    MSG_DRIVER, \
		    "This indicates that the driver was unable to detach due"
			" to some issue.", \
		    ACTION_CHK_HSCFG)

	DEFINE_MSG(112, \
		    emlxs_detach_debug_msg, \
		    "Driver detach.", \
		    EMLXS_DEBUG, \
		    MSG_DRIVER, \
		    "This indicates that the driver is performing a detach"
			" operation.", \
		    ACTION_NONE)

	DEFINE_MSG(120, \
		    emlxs_suspend_msg, \
		    "Driver suspend.", \
		    EMLXS_DEBUG, \
		    MSG_DRIVER, \
		    "This indicates that the driver is performing a suspend"
			" operation.", \
		    ACTION_NONE)

	DEFINE_MSG(121, \
		    emlxs_suspend_failed_msg, \
		    "Driver suspend failed.", \
		    EMLXS_ERROR, \
		    MSG_DRIVER, \
		    "This indicates that the driver was unable to suspend due"
			" to some issue.", \
		    ACTION_CHK_HSCFG)

	DEFINE_MSG(130, \
		    emlxs_resume_msg, \
		    "Driver resume.", \
		    EMLXS_DEBUG, \
		    MSG_DRIVER, \
		    "This indicates that the driver is performing a resume"
			" operation.", \
		    ACTION_NONE)

	DEFINE_MSG(131, \
		    emlxs_resume_failed_msg, \
		    "Driver resume failed.", \
		    EMLXS_ERROR, \
		    MSG_DRIVER, \
		    "This indicates that the driver was unable to resume due"
			" to some issue.", \
		    ACTION_CHK_HSCFG)

	/*
	 * GROUP:	INIT	200 - 299
	 */


	DEFINE_MSG(200, \
		    emlxs_init_msg, \
		    "Adapter initialization.", \
		    EMLXS_NOTICE, \
		    MSG_INIT, \
		    "This indicates that the adapter is initializing.", \
		    ACTION_NONE)

	DEFINE_MSG(201, \
		    emlxs_init_failed_msg, \
		    "Adapter initialization failed.", \
		    EMLXS_ERROR, \
		    MSG_INIT, \
		    "This indicates that an attempt to initialize the adapter"
			" has failed.", \
		    ACTION_CHK_HCFG)

	DEFINE_MSG(202, \
		    emlxs_init_debug_msg, \
		    "Adapter initialization.", \
		    EMLXS_DEBUG, \
		    MSG_INIT, \
		    "This indicates that the adapter is initializing.", \
		    ACTION_NONE)

	DEFINE_MSG(210, \
		    emlxs_adapter_trans_msg, \
		    "Adapter transition.", \
		    EMLXS_DEBUG, \
		    MSG_INIT, \
		    "This indicates that the adapter is changing states.", \
		    ACTION_NONE)

	DEFINE_MSG(220, \
		    emlxs_online_msg, \
		    "Adapter online.", \
		    EMLXS_DEBUG, \
		    MSG_INIT, \
		    "This indicates that the adapter is online and ready to"
			" communicate.", \
		    ACTION_NONE)

	DEFINE_MSG(230, \
		    emlxs_offline_msg, \
		    "Adapter offline.", \
		    EMLXS_DEBUG, \
		    MSG_INIT, \
		    "This indicates that the adapter is offline and unable to"
			" communicate.", \
		    ACTION_NONE)

	DEFINE_MSG(231, \
		    emlxs_shutdown_msg, \
		    "Adapter shutdown.", \
		    EMLXS_WARNING, \
		    MSG_INIT, \
		    "This indicates that the adapter has been shutdown and"
			" will require a reboot to reinitialize.", \
		    ACTION_REP)

	DEFINE_MSG(240, \
		    emlxs_reset_failed_msg, \
		    "Adapter reset failed.", \
		    EMLXS_ERROR, \
		    MSG_INIT, \
		    "This indicates that an attempt to reset the adapter has"
			" failed.", \
		    ACTION_CHK_HCFG)

	/*
	 * GROUP:	MEM	300 - 399
	 */


	DEFINE_MSG(300, \
		    emlxs_mem_alloc_msg, \
		    "Memory alloc.", \
		    EMLXS_DEBUG, \
		    MSG_MEM, \
		    "This indicates that the driver allocated system"
			" memory.", \
		    ACTION_NONE)

	DEFINE_MSG(301, \
		    emlxs_mem_alloc_failed_msg, \
		    "Memory alloc failed.", \
		    EMLXS_ERROR, \
		    MSG_MEM, \
		    "This indicates that the driver was unable to allocate"
			" system memory. The system is low on memory"
			" resources.", \
		    ACTION_NONE_ADM)

	DEFINE_MSG(310, \
		    emlxs_pool_error_msg, \
		    "Memory pool error.", \
		    EMLXS_ERROR, \
		    MSG_MEM, \
		    "This indicates that a problem has occurred with the"
			" memory buffer pool management.", \
		    ACTION_NONE_REP)

	DEFINE_MSG(311, \
		    emlxs_pool_alloc_failed_msg, \
		    "Memory pool alloc failed.", \
		    EMLXS_DEBUG, \
		    MSG_MEM, \
		    "This indicates that the driver was unable to allocate"
			" memory from one of its own memory pools.", \
		    "If the problem occurs frequently you may be able to"
			" configure more resources for that pool. If this"
			" does not solve the problem, report these errors to"
			" customer service.")

	DEFINE_MSG(320, \
		    emlxs_no_unsol_buf_msg, \
		    "No unsolicited buffer available.", \
		    EMLXS_NOTICE, \
		    MSG_MEM, \
		    "This indicates that the driver's unsolicited buffer pool"
			" is exhausted. The I/O will be dropped and most"
			" likely retried by the remote device.", \
		    "If the problem occurs frequently you may be able to"
			" configure more resources for that pool. If this"
			" does not solve the problem, report these errors to"
			" customer service.")

	/*
	 * GROUP:	SLI	400 - 499
	 */


	DEFINE_MSG(400, \
		    emlxs_vpd_msg, \
		    "Vital Product Data.", \
		    EMLXS_DEBUG, \
		    MSG_SLI, \
		    "This provides vendor specific information about the"
			" adapter.", \
		    ACTION_NONE)

	DEFINE_MSG(410, \
		    emlxs_link_atten_msg, \
		    "Link atten.", \
		    EMLXS_DEBUG, \
		    MSG_SLI, \
		    "This indicates that the adapter has triggered a link"
			" attention interrupt.", \
		    ACTION_NONE)

	DEFINE_MSG(411, \
		    emlxs_state_msg, \
		    "State change.", \
		    EMLXS_DEBUG, \
		    MSG_SLI, \
		    "This indicates that the adapter has changed state.", \
		    ACTION_NONE)

	DEFINE_MSG(420, \
		    emlxs_hardware_error_msg, \
		    "Adapter hardware error.", \
		    EMLXS_ERROR, \
		    MSG_SLI, \
		    "This indicates that an interrupt has occurred and the"
			" status register indicates a nonrecoverable hardware"
			" error.", \
		    "This error usually indicates a hardware problem with the"
			" adapter. Try running adapter diagnostics. Report"
			" these errors to customer service.")

	DEFINE_MSG(421, \
		    emlxs_temp_msg, \
		    "Adapter temperature.", \
		    EMLXS_NOTICE, \
		    MSG_SLI, \
		    "This indicates that the adapter has provided general"
			" information about the adapter's temperature.", \
		    ACTION_NONE)

	DEFINE_MSG(422, \
		    emlxs_temp_warning_msg, \
		    "Adapter temperature.", \
		    EMLXS_WARNING, \
		    MSG_SLI, \
		    "This indicates that adapter's temperature is too hot.", \
		    "Check hardware ventilation. Reduce adapter usage."
			" Shutdown host system.")

	DEFINE_MSG(423, \
		    emlxs_adapter_notice_msg, \
		    "Adapter notice.", \
		    EMLXS_NOTICE, \
		    MSG_SLI, \
		    "This indicates that the adapter has provided general"
			" information about the adapter's condition.", \
		    ACTION_NONE)

	DEFINE_MSG(424, \
		    emlxs_adapter_warning_msg, \
		    "Adapter warning.", \
		    EMLXS_WARNING, \
		    MSG_SLI, \
		    "This indicates that an interrupt has occurred indicating"
			" a recoverable adapter error.", \
		    "This error usually indicates a hardware or firmware"
			" problem with the adapter. Check and/or update"
			" firmware levels. Report these errors to customer"
			" service.")

	DEFINE_MSG(425, \
		    emlxs_adapter_error_msg, \
		    "Adapter error.", \
		    EMLXS_ERROR, \
		    MSG_SLI, \
		    "This indicates that a recoverable adapter error has"
			" occurred.", \
		    "This error usually indicates a hardware or firmware"
			" problem with the adapter. Check and/or update"
			" firmware levels. Report these errors to customer"
			" service.")

	DEFINE_MSG(430, \
		    emlxs_ring_event_msg, \
		    "Ring event.", \
		    EMLXS_DEBUG, \
		    MSG_SLI, \
		    "This indicates that an SLI ring event has occurred.", \
		    ACTION_NONE)

	DEFINE_MSG(431, \
		    emlxs_ring_error_msg, \
		    "Ring error.", \
		    EMLXS_DEBUG, \
		    MSG_SLI, \
		    "This indicates an SLI ring error is being reported by"
			" the adapter", \
		    ACTION_NONE)

	DEFINE_MSG(432, \
		    emlxs_ring_reset_msg, \
		    "Ring reset.", \
		    EMLXS_DEBUG, \
		    MSG_SLI, \
		    "This indicates an SLI ring is being reset.", \
		    ACTION_NONE)

	DEFINE_MSG(440, \
		    emlxs_adapter_msg, \
		    "Adapter msg.", \
		    EMLXS_DEBUG, \
		    MSG_SLI, \
		    "This indicates that a message was sent to the driver"
			" from the adapter.", \
		    ACTION_NONE)

	DEFINE_MSG(450, \
		    emlxs_iocb_invalid_msg, \
		    "IOCB invalid.", \
		    EMLXS_ERROR, \
		    MSG_SLI, \
		    "This indicates that an IOCB was received from the adapter"
			" with an illegal value. This error could indicate a"
			" driver or firmware problem.", \
		    ACTION_NONE_REP)

	DEFINE_MSG(451, \
		    emlxs_iocb_qfull_msg, \
		    "IOCB queue full.", \
		    EMLXS_DEBUG, \
		    MSG_SLI, \
		    "This indicates that the IOCB queue is full. This will"
			" occur during normal operation.", \
		    ACTION_NONE)

	DEFINE_MSG(452, \
		    emlxs_iocb_event_msg, \
		    "IOCB event.", \
		    EMLXS_DEBUG, \
		    MSG_SLI, \
		    "This indicates an IOCB local error event is being"
			" reported by the adapter", \
		    ACTION_NONE)

	DEFINE_MSG(453, \
		    emlxs_iocb_stale_msg, \
		    "IOCB stale.", \
		    EMLXS_DEBUG, \
		    MSG_SLI, \
		    "This indicates an IOCB completed after its associated"
			" packet completed.", \
		    ACTION_NONE)

	DEFINE_MSG(460, \
		    emlxs_sli_detail_msg, \
		    "SLI detail.", \
		    EMLXS_DEBUG, \
		    MSG_SLI_DETAIL, \
		    "This provides detailed information about an SLI event.", \
		    ACTION_NONE)

	/*
	 * GROUP:	MBOX	500 - 599
	 */


	DEFINE_MSG(500, \
		    emlxs_mbox_event_msg, \
		    "Mailbox event.", \
		    EMLXS_DEBUG, \
		    MSG_MBOX, \
		    "This indicates that a mailbox event has occurred.", \
		    ACTION_NONE)

	DEFINE_MSG(501, \
		    emlxs_mbox_detail_msg, \
		    "Mailbox detail.", \
		    EMLXS_DEBUG, \
		    MSG_MBOX_DETAIL, \
		    "This provides detailed information about a mailbox"
			" event.", \
		    ACTION_NONE)

	DEFINE_MSG(510, \
		    emlxs_stray_mbox_intr_msg, \
		    "Stray mailbox interrupt.", \
		    EMLXS_DEBUG, \
		    MSG_MBOX, \
		    "This indicates that a mailbox command completion"
			" interrupt was received and the mailbox is not valid."
			"  This error could indicate a driver or firmware"
				" problem.", \
		    ACTION_NONE_REP)

	DEFINE_MSG(520, \
		    emlxs_mbox_completion_error_msg, \
		    "Mailbox error.", \
		    EMLXS_DEBUG, \
		    MSG_MBOX, \
		    "This indicates that an unsupported or illegal mailbox"
			" command was completed.  This error could indicate a"
			" driver or firmware problem.", \
		    ACTION_NONE_REP)

	/*
	 * GROUP:	NODE	600 - 699
	 */

	DEFINE_MSG(600, \
		    emlxs_node_create_msg, \
		    "Node create.", \
		    EMLXS_DEBUG, \
		    MSG_NODE, \
		    "This indicates that a node has been created for a remote"
			" device.", \
		    ACTION_NONE)

	DEFINE_MSG(601, \
		    emlxs_node_opened_msg, \
		    "Node opened.", \
		    EMLXS_DEBUG, \
		    MSG_NODE_DETAIL, \
		    "This indicates that a node has been opened for IO"
			" transport.", \
		    ACTION_NONE)

	DEFINE_MSG(602, \
		    emlxs_node_create_failed_msg, \
		    "Node create failed.", \
		    EMLXS_NOTICE, \
		    MSG_NODE, \
		    "This indicates that a node create request for a remote"
			" device has failed.", \
		    ACTION_NONE)

	DEFINE_MSG(603, \
		    emlxs_node_update_msg, \
		    "Node updated.", \
		    EMLXS_DEBUG, \
		    MSG_NODE, \
		    "This indicates that a node has been updated for a remote"
			" device.", \
		    ACTION_NONE)

	DEFINE_MSG(610, \
		    emlxs_node_destroy_msg, \
		    "Node destroy.", \
		    EMLXS_DEBUG, \
		    MSG_NODE, \
		    "This indicates that a node has been destroyed for a remote"
			" device.", \
		    ACTION_NONE)

	DEFINE_MSG(611, \
		    emlxs_node_closed_msg, \
		    "Node closed.", \
		    EMLXS_DEBUG, \
		    MSG_NODE_DETAIL, \
		    "This indicates that a node has been temporarily closed"
			" for IO transport.", \
		    ACTION_NONE)

	DEFINE_MSG(612, \
		    emlxs_node_missing_msg, \
		    "Node missing.", \
		    EMLXS_NOTICE, \
		    MSG_NODE, \
		    "This indicates that a FCP2 device node has been found"
			" missing.", \
		    ACTION_NONE)

	DEFINE_MSG(620, \
		    emlxs_node_not_found_msg, \
		    "Node not found.", \
		    EMLXS_DEBUG, \
		    MSG_NODE, \
		    "This indicates that there was an attempt to send an I/O"
			" pkt to an unknown device node. The driver maintains"
			" a node table entry for every device it needs to"
			" communicate with on the FC network.", \
		    ACTION_NONE_REP)

	/*
	 * GROUP:	LINK	700 - 799
	 */

	DEFINE_MSG(700, \
		    emlxs_link_event_msg, \
		    "Link event.", \
		    EMLXS_DEBUG, \
		    MSG_LINK | MSG_SLI, \
		    "This indicates that a link event has occurred.", \
		    ACTION_NONE)

	DEFINE_MSG(710, \
		    emlxs_link_down_msg, \
		    "Link down.", \
		    EMLXS_NOTICE, \
		    MSG_LINK, \
		    "This indicates that the fibre channel link is down to"
			" the adapter.", \
		    ACTION_CHK_CONN)

	DEFINE_MSG(720, \
		    emlxs_link_up_msg, \
		    "Link up.", \
		    EMLXS_NOTICE, \
		    MSG_LINK, \
		    "This indicates that the fibre channel link is up.", \
		    ACTION_NONE)

	DEFINE_MSG(721, \
		    emlxs_npiv_link_up_msg, \
		    "NPIV Link up.", \
		    EMLXS_NOTICE, \
		    MSG_LINK, \
		    "This indicates that the fibre channel link is up for all"
			" virtual ports.", \
		    ACTION_NONE)

	DEFINE_MSG(730, \
		    emlxs_link_reset_msg, \
		    "Link reset.", \
		    EMLXS_NOTICE, \
		    MSG_LINK | MSG_SFS, \
		    "This indicates that an issue has forced the fibre channel"
			" link to be reset.", \
		    ACTION_NONE)

	DEFINE_MSG(731, \
		    emlxs_link_reset_failed_msg, \
		    "Link reset failed.", \
		    EMLXS_ERROR, \
		    MSG_LINK | MSG_SFS, \
		    "This indicates that an attempt to reset the fibre channel"
			" link has failed.", \
		    ACTION_NONE_REP)

	/*
	 * GROUP:	ELS	800 - 899
	 */

	DEFINE_MSG(800, \
		    emlxs_els_send_msg, \
		    "ELS sent. ", \
		    EMLXS_DEBUG, \
		    MSG_ELS, \
		    "This indicates that an ELS command is being sent.", \
		    ACTION_NONE)

	DEFINE_MSG(801, \
		    emlxs_els_completion_msg, \
		    "ELS comp. ", \
		    EMLXS_DEBUG, \
		    MSG_ELS, \
		    "This indicates that an ELS command completed normally.", \
		    ACTION_NONE)

	DEFINE_MSG(810, \
		    emlxs_stray_els_completion_msg, \
		    "Stray ELS completion.", \
		    EMLXS_ERROR, \
		    MSG_ELS, \
		    "This indicates that the an ELS command completion was"
			" received without issuing a corresponding ELS"
			" command. This error could indicate a driver or"
			" firmware problem. ", \
		    ACTION_NONE_REP)

	DEFINE_MSG(811, \
		    emlxs_bad_els_completion_msg, \
		    "Abnormal ELS completion.", \
		    EMLXS_DEBUG, \
		    MSG_ELS, \
		    "This indicates that an ELS command completed with a"
			" status error in the IOCB.  It could mean the Fibre"
			" Channel device on the network is not responding or"
			" the Fibre Channel device is not an FCP target. The"
			" driver will automatically retry this ELS command if"
			" needed.", \
		    "If the command is a PLOGI or PRLI, and the destination"
			" PortID is not an FCP Target, no action is needed."
			" Otherwise, check physical connections to Fibre"
			" Channel network and the state the remote PortID"
				" is in.")

	DEFINE_MSG(820, \
		    emlxs_unsol_els_msg, \
		    "ELS rcvd. ", \
		    EMLXS_DEBUG, \
		    MSG_ELS, \
		    "This indicates that an unsolicited ELS command was"
			" received.", \
		    ACTION_NONE)

	DEFINE_MSG(821, \
		    emlxs_unsol_els_dropped_msg, \
		    "Unsolicited ELS dropped.", \
		    EMLXS_DEBUG, \
		    MSG_ELS, \
		    "This indicates that an unsolicited ELS command was"
			" received and then dropped for some reason.", \
		    ACTION_NONE)

	DEFINE_MSG(822, \
		    emlxs_els_reply_msg, \
		    "ELS reply.", \
		    EMLXS_DEBUG, \
		    MSG_ELS, \
		    "This indicates that a reply is being sent for an"
			" unsolicited ELS command.", \
		    ACTION_NONE)

	DEFINE_MSG(830, \
		    emlxs_invalid_els_msg, \
		    "Invalid ELS command found.", \
		    EMLXS_ERROR, \
		    MSG_ELS, \
		    "This indicates that an ELS command was found with an"
			" invalid command code.", \
		    ACTION_NONE_REP)

	/*
	 * GROUP:	PKT	900 - 999
	 */


	DEFINE_MSG(900, \
		    emlxs_pkt_abort_msg, \
		    "Packet abort.", \
		    EMLXS_NOTICE, \
		    MSG_PKT, \
		    "This indicates that an I/O packet is being aborted.", \
		    ACTION_NONE)

	DEFINE_MSG(901, \
		    emlxs_pkt_abort_failed_msg, \
		    "Packet abort failed.", \
		    EMLXS_WARNING, \
		    MSG_PKT, \
		    "This indicates that an attempt to abort an I/O packet"
			" has failed.", \
		    ACTION_NONE_REP)

	DEFINE_MSG(910, \
		    emlxs_pkt_timeout_msg, \
		    "Packet timeout.", \
		    EMLXS_DEBUG, \
		    MSG_PKT, \
		    "This indicates that an I/O packet has timed out and is"
			" being aborted.", \
		    ACTION_NONE)

	DEFINE_MSG(911, \
		    emlxs_ring_watchdog_msg, \
		    "Ring watchdog.", \
		    EMLXS_DEBUG, \
		    MSG_PKT, \
		    "This indicates that IO(s) are getting stale waiting on a"
			" ring tx queue.", \
		    ACTION_NONE)

	DEFINE_MSG(912, \
		    emlxs_txq_watchdog_msg, \
		    "TXQ watchdog.", \
		    EMLXS_DEBUG, \
		    MSG_PKT, \
		    "This indicates that an IO was found missing from the"
			" transmit queue.", \
		    ACTION_NONE)

	DEFINE_MSG(920, \
		    emlxs_pkt_flush_msg, \
		    "Packet flush.", \
		    EMLXS_DEBUG, \
		    MSG_PKT, \
		    "This indicates that an I/O packet is being flushed.", \
		    ACTION_NONE)

	DEFINE_MSG(921, \
		    emlxs_pkt_flushed_msg, \
		    "Packet flushed.", \
		    EMLXS_DEBUG, \
		    MSG_PKT, \
		    "This indicates that an I/O packet has been flushed.", \
		    ACTION_NONE)

	DEFINE_MSG(922, \
		    emlxs_flush_timeout_msg, \
		    "Packet flush timeout.", \
		    EMLXS_NOTICE, \
		    MSG_PKT, \
		    "This indicates that an I/O packet flush request has"
			" timed out with some I/O packets's still not"
			" completed. The driver will attempt to recover by"
			" itself.", \
		    ACTION_NONE_REP)

	DEFINE_MSG(930, \
		    emlxs_pkt_trans_failed_msg, \
		    "Packet transport failed.", \
		    EMLXS_NOTICE, \
		    MSG_PKT, \
		    "This indicates that an attempt to send an I/O packet"
			" failed. The I/O packet will be retried by the upper"
			" layer.", \
		    ACTION_NONE)

	DEFINE_MSG(931, \
		    emlxs_pkt_trans_error_msg, \
		    "Packet transport error.", \
		    EMLXS_ERROR, \
		    MSG_PKT, \
		    "This indicates that an error occurred while attempting"
			" to send an I/O packet. The I/O packet will likely"
			" be failed back to the user application.", \
		    ACTION_NONE_REP)

	DEFINE_MSG(932, \
		    emlxs_pkt_trans_msg, \
		    "Packet transport.", \
		    EMLXS_DEBUG, \
		    MSG_PKT, \
		    "This provides additional information about a packet"
			" being sent.", \
		    ACTION_NONE)

	DEFINE_MSG(940, \
		    emlxs_pkt_completion_error_msg, \
		    "Packet completion error.", \
		    EMLXS_DEBUG, \
		    MSG_PKT, \
		    "This indicates that an I/O packet was completed with an"
			" error status. This can occur during normal"
			" operation.", \
		    ACTION_NONE_REP)

	/*
	 * GROUP:	FCP	1000 - 1099
	 */

	DEFINE_MSG(1000, \
		    emlxs_stray_fcp_completion_msg, \
		    "Stray FCP completion.", \
		    EMLXS_DEBUG, \
		    MSG_FCP, \
		    "This indicates that an FCP command completion was"
			" received without issuing a corresponding FCP"
			" Command. This error could indicate a driver or"
			" firmware problem.", \
		    ACTION_NONE_REP)

	DEFINE_MSG(1001, \
		    emlxs_fcp_completion_error_msg, \
		    "FCP completion error.", \
		    EMLXS_DEBUG, \
		    MSG_FCP, \
		    "This indicates that an FCP command completed with an"
			" error status. These errors can occur during normal"
			" operation.", \
		    ACTION_NONE)

	/*
	 * GROUP:   FCT    1100 - 1199
	 */

#ifdef SFCT_SUPPORT
	DEFINE_MSG(1100, \
		    emlxs_fct_detail_msg, \
		    "FCT detail.", \
		    EMLXS_DEBUG, \
		    MSG_FCT_DETAIL, \
		    "This provides detailed information about the driver's"
				" FCT interface.", \
		    ACTION_NONE)

	DEFINE_MSG(1110, \
		    emlxs_fct_debug_msg, \
		    "FCT debug.", \
		    EMLXS_DEBUG, \
		    MSG_FCT, \
		    "This provides general information about the driver's"
			" FCT interface.", \
		    ACTION_NONE)

	DEFINE_MSG(1120, \
		    emlxs_fct_error_msg, \
		    "FCT error.", \
		    EMLXS_DEBUG, \
		    MSG_FCT, \
		    "This indicates a general error has occurred in the"
			" driver's FCT interface.", \
		    ACTION_NONE_REP)

	DEFINE_MSG(1130, \
		    emlxs_fct_api_msg, \
		    "FCT API.", \
		    EMLXS_DEBUG, \
		    MSG_FCT_API, \
		    "This provides an API trace with the driver's FCT"
			" interface.", \
		    ACTION_NONE)

#endif	/* SFCT_SUPPORT */

	/*
	 * GROUP:	IP	1200 - 1299
	 */


	DEFINE_MSG(1200, \
		    emlxs_ip_detail_msg, \
		    "IP detail. ", \
		    EMLXS_DEBUG, \
		    MSG_IP_DETAIL, \
		    "This provides detailed information about the driver's"
			" IP interface.", \
		    ACTION_NONE)

	DEFINE_MSG(1210, \
		    emlxs_stray_ip_completion_msg, \
		    "Stray IP completion.", \
		    EMLXS_ERROR, \
		    MSG_IP, \
		    "This indicates that the an IP sequence completion was"
			" received without issuing a corresponding IP"
			" sequence. This error could indicate a driver or"
			" firmware problem. ", \
		    ACTION_NONE_REP)

	DEFINE_MSG(1211, \
		    emlxs_bad_ip_completion_msg, \
		    "Abnormal IP completion.", \
		    EMLXS_DEBUG, \
		    MSG_IP, \
		    "This indicates that an IP sequence completed with a"
			" status error in the IOCB.  It could mean the Fibre"
			" Channel device on the network is not responding.", \
		    ACTION_NONE_ADM)

	DEFINE_MSG(1220, \
		    emlxs_unsol_ip_dropped_msg, \
		    "Unsolicited IP dropped.", \
		    EMLXS_DEBUG, \
		    MSG_IP, \
		    "This indicates that an unsolicited IP sequence was"
			" received, but was dropped for some reason.", \
		    ACTION_NONE)

	DEFINE_MSG(1221, \
		    emlxs_unsol_ip_debug_msg, \
		    "IP recvd.", \
		    EMLXS_DEBUG, \
		    MSG_IP, \
		    "This indicates that an unsolicited IP sequence was"
			" received.", \
		    ACTION_NONE)

	DEFINE_MSG(1230, \
		    emlxs_invalid_ip_msg, \
		    "Invalid IP sequence found.", \
		    EMLXS_ERROR, \
		    MSG_IP, \
		    "This indicates that an IP sequence was found with an"
			" invalid code.", \
		    ACTION_NONE_REP)

	/*
	 * GROUP:	SFS	1300 - 1399
	 */

	DEFINE_MSG(1300, \
		    emlxs_sfs_debug_msg, \
		    "SFS.", \
		    EMLXS_DEBUG, \
		    MSG_SFS, \
		    "This provides general information about the driver's SFS"
			" interface.", \
		    ACTION_NONE)

	DEFINE_MSG(1301, \
		    emlxs_sfs_detail_msg, \
		    "SFS detail.", \
		    EMLXS_DEBUG, \
		    MSG_SFS_DETAIL, \
		    "This provides detailed information about the driver's SFS"
			" interface.", \
		    ACTION_NONE)

	DEFINE_MSG(1310, \
		    emlxs_diag_error_msg, \
		    "Diagnostic error.", \
		    EMLXS_WARNING, \
		    MSG_SFS, \
		    "This indicates that a diagnostic request did not complete"
			" because of some issue.", \
		    ACTION_NONE_REP)

	DEFINE_MSG(1311, \
		    emlxs_echo_complete_msg, \
		    "ECHO diagnostic completed.", \
		    EMLXS_DEBUG, \
		    MSG_SFS, \
		    "This indicates that an ECHO diagnostic has completed.", \
		    ACTION_NONE)

	DEFINE_MSG(1312, \
		    emlxs_echo_failed_msg, \
		    "ECHO diagnostic failed.", \
		    EMLXS_WARNING, \
		    MSG_SFS, \
		    "This indicates that an ECHO diagnostic has failed to"
			" return a positive result. This could indicate a"
			" connectivity problem with your FC network.", \
		    ACTION_CHK_CONN)

	DEFINE_MSG(1313, \
		    emlxs_biu_complete_msg, \
		    "BIU diagnostic completed.", \
		    EMLXS_DEBUG, \
		    MSG_SFS, \
		    "This indicates that an BIU diagnostic has completed.", \
		    ACTION_NONE)

	DEFINE_MSG(1314, \
		    emlxs_biu_failed_msg, \
		    "BIU diagnostic failed.", \
		    EMLXS_ERROR, \
		    MSG_SFS, \
		    "This indicates that an BIU diagnostic has failed to"
			" return a positive result. This usually caused by an"
			" adapter hardware problem.", \
		    ACTION_REP)

	DEFINE_MSG(1315, \
		    emlxs_post_complete_msg, \
		    "POST diagnostic completed.", \
		    EMLXS_DEBUG, \
		    MSG_SFS, \
		    "This indicates that an POST diagnostic has completed.", \
		    ACTION_NONE)

	DEFINE_MSG(1316, \
		    emlxs_post_failed_msg, \
		    "POST diagnostic failed.", \
		    EMLXS_ERROR, \
		    MSG_SFS, \
		    "This indicates that an POST diagnostic has failed to"
			" return a positive result. This is usually caused by"
			" an adapter hardware problem.", \
		    ACTION_REP)

	/*
	 * GROUP:	IOCTL	1400 - 1499
	 */


	DEFINE_MSG(1400, \
		    emlxs_ioctl_debug_msg, \
		    "IOCTL.", \
		    EMLXS_DEBUG, \
		    MSG_IOCTL, \
		    "This provides general information about the driver's"
			" IOCTL interface.", \
		    ACTION_NONE)

	DEFINE_MSG(1401, \
		    emlxs_ioctl_detail_msg, \
		    "IOCTL detail.", \
		    EMLXS_DEBUG, \
		    MSG_IOCTL_DETAIL, \
		    "This provides detailed information about the driver's"
			" IOCTL interface.", \
		    ACTION_NONE)

	DEFINE_MSG(1410, \
		    emlxs_dfc_debug_msg, \
		    "DFC", \
		    EMLXS_DEBUG, \
		    MSG_IOCTL, \
		    "This provides general information about the driver's"
			" DFC interface.", \
		    ACTION_NONE)

	DEFINE_MSG(1411, \
		    emlxs_dfc_detail_msg, \
		    "DFC detail.", \
		    EMLXS_DEBUG, \
		    MSG_IOCTL_DETAIL, \
		    "This provides detailed information about the driver's"
			" DFC interface.", \
		    ACTION_NONE)

	DEFINE_MSG(1420, \
		    emlxs_dfc_error_msg, \
		    "DFC Error.", \
		    EMLXS_DEBUG, \
		    MSG_IOCTL, \
		    "This indicates that an error was found while processing a"
			" DFC request.", \
		    ACTION_NONE)

	/*
	 * GROUP:   FIRMWARE   1500 - 1599
	 */

	DEFINE_MSG(1500, \
		    emlxs_image_msg, \
		    "Firmware image.", \
		    EMLXS_DEBUG, \
		    MSG_FIRMWARE, \
		    "This provides information about the firmware image.", \
		    ACTION_NONE)

	DEFINE_MSG(1501, \
		    emlxs_image_detail_msg, \
		    "Firmware detail.", \
		    EMLXS_DEBUG, \
		    MSG_FIRMWARE_DETAIL, \
		    "This provides detailed information about the firmware"
			" image.", \
		    ACTION_NONE)

	DEFINE_MSG(1502, \
		    emlxs_image_library_msg, \
		    "Firmware Library", \
		    EMLXS_NOTICE, \
		    MSG_DRIVER, \
		    "This shows the versions of firmware contained in the"
			" driver's library.", \
		    ACTION_NONE)

	DEFINE_MSG(1510, \
		    emlxs_image_bad_msg, \
		    "Bad firmware image.", \
		    EMLXS_ERROR, \
		    MSG_FIRMWARE, \
		    "This indicates that a bad firmware image was provided"
			" to the download function.", \
		    ACTION_IMG_REP)

	DEFINE_MSG(1511, \
		    emlxs_image_incompat_msg, \
		    "Firmware image not compatible.", \
		    EMLXS_ERROR, \
		    MSG_FIRMWARE, \
		    "This indicates that the firmware image provided was not"
			" compatible with the existing hardware.", \
		    ACTION_IMG_REP)

	DEFINE_MSG(1520, \
		    emlxs_download_msg, \
		    "Firmware download.", \
		    EMLXS_NOTICE, \
		    MSG_FIRMWARE, \
		    "This indicates that an attempt to download a firmware"
			" image has occurred.", \
		    ACTION_NONE)

	DEFINE_MSG(1521, \
		    emlxs_download_complete_msg, \
		    "Firmware download complete.", \
		    EMLXS_NOTICE, \
		    MSG_FIRMWARE, \
		    "This indicates that an attempt to download a firmware"
			" image was successful.", \
		    ACTION_NONE)

	DEFINE_MSG(1522, \
		    emlxs_download_failed_msg, \
		    "Firmware download failed.", \
		    EMLXS_ERROR, \
		    MSG_FIRMWARE, \
		    "This indicates that an attempt to download a firmware"
			" image was failed.", \
		    ACTION_CHK_HCFG)

	/*
	 * GROUP:	CT	1600 - 1699
	 */

	DEFINE_MSG(1600, \
		    emlxs_ct_send_msg, \
		    "CT sent. ", \
		    EMLXS_DEBUG, \
		    MSG_CT, \
		    "This indicates that an CT command is being sent.", \
		    ACTION_NONE)

	DEFINE_MSG(1601, \
		    emlxs_ct_completion_msg, \
		    "CT comp. ", \
		    EMLXS_DEBUG, \
		    MSG_CT, \
		    "This indicates that an CT command completed normally.", \
		    ACTION_NONE)

	DEFINE_MSG(1610, \
		    emlxs_stray_ct_completion_msg, \
		    "Stray CT completion.", \
		    EMLXS_ERROR, \
		    MSG_CT, \
		    "This indicates that the an CT command completion was"
			" received without issuing a corresponding CT command."
			" This error could indicate a driver or"
			" firmware problem. ", \
		    ACTION_NONE_REP)

	DEFINE_MSG(1611, \
		    emlxs_bad_ct_completion_msg, \
		    "Abnormal CT completion.", \
		    EMLXS_DEBUG, \
		    MSG_CT, \
		    "This indicates that an CT command completed with a status"
			" error in the IOCB.  It could mean the Fibre Channel"
			" device on the network is not responding. The"
			" driver will automatically retry this CT command"
			" if needed.", \
		    "Check physical connections to Fibre Channel network "
			" and the state the remote PortID is in.")

	DEFINE_MSG(1620, \
		    emlxs_unsol_ct_msg, \
		    "CT rcvd. ", \
		    EMLXS_DEBUG, \
		    MSG_CT, \
		    "This indicates that an unsolicited CT command was"
			" received.", \
		    ACTION_NONE)

	DEFINE_MSG(1621, \
		    emlxs_unsol_ct_dropped_msg, \
		    "Unsolicited CT dropped.", \
		    EMLXS_DEBUG, \
		    MSG_CT, \
		    "This indicates that an unsolicited CT command was"
			" received and then dropped for some reason.", \
		    ACTION_NONE)

	DEFINE_MSG(1622, \
		    emlxs_ct_reply_msg, \
		    "CT reply.", \
		    EMLXS_DEBUG, \
		    MSG_CT, \
		    "This indicates that a reply is being sent for an"
			" unsolicited CT command.", \
		    ACTION_NONE)

	DEFINE_MSG(1630, \
		    emlxs_invalid_ct_msg, \
		    "Invalid CT command found.", \
		    EMLXS_ERROR, \
		    MSG_CT, \
		    "This indicates that an CT command was found with an"
			" invalid command code.", \
		    ACTION_NONE_REP)

	/*
	 * GROUP:  FC-SP (DHCHAP)   1700 - 1799
	 */

#ifdef DHCHAP_SUPPORT

	DEFINE_MSG(1700, \
		    emlxs_fcsp_debug_msg, \
		    "FCSP", \
		    EMLXS_DEBUG, \
		    MSG_FCSP, \
		    "This provides general information about the driver's FCSP"
			" interface.", \
		    ACTION_NONE)

	DEFINE_MSG(1701, \
		    emlxs_fcsp_detail_msg, \
		    "FCSP detail.", \
		    EMLXS_DEBUG, \
		    MSG_FCSP_DETAIL, \
		    "This provides detailed information about the driver's"
			" FCSP interface.", \
		    ACTION_NONE)

	DEFINE_MSG(1702, \
		    emlxs_fcsp_error_msg, \
		    "FCSP error.", \
		    EMLXS_DEBUG, \
		    MSG_FCSP, \
		    "This indicates that an error was found while processing"
			" a DFC request.", \
		    ACTION_NONE)

	DEFINE_MSG(1705, \
		    emlxs_fcsp_state_msg, \
		    "FCSP state.", \
		    EMLXS_DEBUG, \
		    MSG_FCSP, \
		    "This indicates that an authentication state is"
			" changing.", \
		    ACTION_NONE)

	DEFINE_MSG(1706, \
		    emlxs_fcsp_event_msg, \
		    "FCSP event", \
		    EMLXS_DEBUG, \
		    MSG_FCSP, \
		    "This indicates that an authentication event has"
			" occurred.", \
		    ACTION_NONE)

	DEFINE_MSG(1707, \
		    emlxs_fcsp_status_msg, \
		    "FCSP status.", \
		    EMLXS_DEBUG, \
		    MSG_FCSP, \
		    "This indicates that an authentication status is being"
			" updated.", \
		    ACTION_NONE)

	DEFINE_MSG(1710, \
		    emlxs_fcsp_start_msg, \
		    "FCSP start.", \
		    EMLXS_DEBUG, \
		    MSG_FCSP, \
		    "This indicates that authentication is being started to a"
			" specific node.", \
		    ACTION_NONE)

	DEFINE_MSG(1720, \
		    emlxs_fcsp_complete_msg, \
		    "FCSP comp. ", \
		    EMLXS_DEBUG, \
		    MSG_FCSP, \
		    "This indicates that authentication is being stopped or"
			" completed to a specific node.", \
		    ACTION_NONE)

#endif	/* DHCHAP_SUPPORT */


	/*
	 * GROUP:   EVENT   2000 - 2099
	 */

	DEFINE_MSG(2000, \
		    emlxs_link_event, \
		    "Link.", \
		    EMLXS_EVENT, \
		    EVT_LINK, \
		    "This indicates that a link event has occurred.", \
		    ACTION_NONE)

	DEFINE_MSG(2010, \
		    emlxs_rscn_event, \
		    "RSCN.", \
		    EMLXS_EVENT, \
		    EVT_RSCN, \
		    "This indicates that an unsolicited RSCN command was"
			" received.", \
		    ACTION_NONE)

	DEFINE_MSG(2020, \
		    emlxs_ct_event, \
		    "CT.", \
		    EMLXS_EVENT, \
		    EVT_CT, \
		    "This indicates that an unsolicited CT command was"
			" received.", \
		    ACTION_NONE)

	DEFINE_MSG(2030, \
		    emlxs_dump_event, \
		    "DUMP", \
		    EMLXS_EVENT, \
		    EVT_DUMP, \
		    "This indicates that an HBA core dump has occurred.", \
		    ACTION_NONE)

	DEFINE_MSG(2040, \
		    emlxs_temp_event, \
		    "TEMP", \
		    EMLXS_EVENT, \
		    EVT_TEMP, \
		    "This indicates that an adapter temperature event has"
			" occurred.", \
		    ACTION_NONE)

	DEFINE_MSG(2050, \
		    emlxs_fcoe_event, \
		    "FCOE", \
		    EMLXS_EVENT, \
		    EVT_FCOE, \
		    "This indicates that an adapter FCOE event has"
			" occurred.", \
		    ACTION_NONE)

#ifdef DEF_MSG_REPORT
};	/* emlxs_message[] */
#endif	/* DEF_MSG_REPORT */

#ifdef	__cplusplus
}
#endif

#endif	/* _EMLXS_MESSAGES_H */
