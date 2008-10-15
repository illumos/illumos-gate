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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * ldom_xmpp_client.h	Extensible Messaging and Presence Protocol
 */

#ifndef	_LDOM_XMPP_CLIENT_H
#define	_LDOM_XMPP_CLIENT_H

#include <sys/fm/ldom.h>

#include <pthread.h>
#include <libxml/xmlstring.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	XMPP_DEFAULT_PORT	6482
#define	XMPP_BUF_SIZE		1024
#define	RAND_BUF_SIZE		1024
#define	XMPP_SLEEP		3

#define	STREAM_NODE		(xmlChar *)"stream:stream"
#define	FEATURE_NODE		(xmlChar *)"stream:features"
#define	STARTTLS_NODE		(xmlChar *)"starttls"
#define	PROCEED_NODE		(xmlChar *)"proceed"
#define	XML_LDM_INTERFACE	((xmlChar *)"LDM_interface")
#define	XML_LDM_EVENT		((xmlChar *)"LDM_event")

#define	XML_SUCCESS		((xmlChar *)"success")
#define	XML_FAILURE		((xmlChar *)"failure")

#define	XML_CMD			((xmlChar *)"cmd")
#define	XML_ACTION		((xmlChar *)"action")
#define	XML_RESPONSE		((xmlChar *)"response")
#define	XML_STATUS		((xmlChar *)"status")
#define	XML_DATA		((xmlChar *)"data")
#define	XML_ENVELOPE		((xmlChar *)"Envelope")
#define	XML_CONTENT		((xmlChar *)"Content")

#define	XML_ATTR_ID		((xmlChar *)"id")

#define	XML_REGISTER_ACTION	"reg-domain-events"

#define	STREAM_START		"<?xml version='1.0'?><stream:stream " \
				"xml:lang=\"en\" version=\"1.0\" id=\"xmpp\"" \
				">"
#define	START_TLS	"<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>"

#define	LDM_REG_DOMAIN_EVENTS	\
			"<LDM_interface version=\"1.1\">" \
			"   <cmd>" \
			"      <action>reg-domain-events</action>" \
			"      <data version=\"3.0\"> </data>" \
			"   </cmd>" \
			"</LDM_interface>"


typedef struct ldom_event_info {
	ldom_event_t id;
	char *name;
} ldom_event_info_t;


typedef struct client_info {
	ldom_hdl_t *lhp;
	ldom_reg_cb_t cb;
	ldom_cb_arg_t data;
	struct client_info *next;
	struct client_info *prev;
} client_info_t;

typedef struct client_list {
	client_info_t *head;
	client_info_t *tail;
	pthread_mutex_t lock;
} client_list_t;


extern int xmpp_add_client(ldom_hdl_t *lhp, ldom_reg_cb_t cb,
				ldom_cb_arg_t data);
extern int xmpp_remove_client(ldom_hdl_t *lhp);
extern void xmpp_start(void);
extern void xmpp_stop(void);

#ifdef	__cplusplus
}
#endif

#endif	/* _LDOM_XMPP_CLIENT_H */
