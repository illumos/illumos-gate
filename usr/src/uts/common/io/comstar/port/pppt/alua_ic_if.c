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
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * XXX TODO
 * #includes cribbed from stmf.c -- undoubtedly only a small subset of these
 * are actually needed.
 */
#include <sys/conf.h>
#include <sys/file.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/scsi/scsi.h>
#include <sys/scsi/generic/persist.h>
#include <sys/byteorder.h>
#include <sys/nvpair.h>
#include <sys/door.h>

#include <sys/stmf.h>
#include <sys/lpif.h>
#include <sys/stmf_ioctl.h>
#include <sys/portif.h>
#include <sys/pppt_ic_if.h>

#include "pppt.h"

/*
 * Macros
 */

/* Free a struct if it was allocated */
#define	FREE_IF_ALLOC(m)					\
	do {							\
		if ((m)) kmem_free((m), sizeof (*(m)));		\
		_NOTE(CONSTCOND)				\
	} while (0)

/*
 * Macros to simplify the addition of struct fields to an nvlist.
 * The name of the fields in the nvlist is the same as the name
 * of the struct field.
 *
 * These macros require an int rc and a "done:" return retval label;
 * they assume that the nvlist is named "nvl".
 */
#define	NVLIST_ADD_FIELD(type, structure, field)			\
	do {								\
		rc = nvlist_add_##type(nvl, #field, structure->field);  \
		if (rc) goto done;					\
		_NOTE(CONSTCOND)					\
	} while (0)

/* use this macro when the array is defined as part of the struct */
#define	NVLIST_ADD_ARRAY(type, structure, field)			\
	do {								\
		rc = nvlist_add_##type##_array(nvl, #field,		\
		    structure->field, sizeof (structure->field));	\
		if (rc) goto done;					\
		_NOTE(CONSTCOND)					\
	} while (0)

/*
 * use this macro when the array field is a ptr or you need to explictly
 * call out the size.
 */
#define	NVLIST_ADD_ARRAY_LEN(type, structure, field, len)		\
	do {								\
		rc = nvlist_add_##type##_array(nvl, #field,		\
		    structure->field, len);				\
		if (rc) goto done;					\
		_NOTE(CONSTCOND)					\
	} while (0)

#define	NVLIST_ADD_DEVID(structure, field)				\
	do {								\
		rc = stmf_ic_scsi_devid_desc_marshal(nvl, #field,	\
		    structure->field);					\
		if (rc) goto done;					\
		_NOTE(CONSTCOND)					\
	} while (0)

#define	NVLIST_ADD_RPORT(structure, field)				\
	do {								\
		rc = stmf_ic_remote_port_marshal(nvl, #field,		\
		    structure->field);					\
		if (rc) goto done;					\
		_NOTE(CONSTCOND)					\
	} while (0)

#define	NVLIST_ADD_FIELD_UINT8(structure, field)			\
	NVLIST_ADD_FIELD(structure, field, uint8)

/*
 * Macros to simplify the extraction of struct fields from an nvlist.
 * The name of the fields in the nvlist is the same as the name
 * of the struct field.
 *
 * Requires an int rc and a "done:" return retval label.
 * Assumes that the nvlist is named "nvl".
 *
 * Sample usage: NVLIST_LOOKUP_FIELD(uint8, structname, fieldname);
 */
#define	NVLIST_LOOKUP_FIELD(type, structure, field)			\
	do {								\
		rc = nvlist_lookup_##type(nvl, #field,			\
		    &(structure->field));				\
		if (rc) { 						\
			stmf_ic_nvlookup_warn(__func__, #field);	\
			goto done;					\
		}							\
		_NOTE(CONSTCOND)					\
	} while (0)

/*
 * Look up a field which gets stored into a structure bit field.
 * The type passed is a uint type which can hold the largest value
 * in the bit field.
 *
 * Requires an int rc and a "done:" return retval label.
 * Assumes that the nvlist is named "nvl".
 *
 * Sample usage: NVLIST_LOOKUP_BIT_FIELD(uint8, structname, fieldname);
 */
#define	NVLIST_LOOKUP_BIT_FIELD(type, structure, field)			\
	do {								\
		type##_t tmp;						\
		rc = nvlist_lookup_##type(nvl, #field, &tmp);		\
		if (rc) { 						\
			stmf_ic_nvlookup_warn(__func__, #field);	\
			goto done;					\
		}							\
		structure->field = tmp;					\
		_NOTE(CONSTCOND)					\
	} while (0)

/*
 * Look up a boolean field which gets stored into a structure bit field.
 *
 * Requires an int rc and a "done:" return retval label.
 * Assumes that the nvlist is named "nvl".
 */
#define	NVLIST_LOOKUP_BIT_FIELD_BOOLEAN(structure, field)		\
	do {								\
		boolean_t tmp;						\
		rc = nvlist_lookup_boolean_value(nvl, #field, &tmp);	\
		if (rc) { 						\
			stmf_ic_nvlookup_warn(__func__, #field);	\
			goto done;					\
		}							\
		structure->field = (tmp ?  1 : 0);			\
		_NOTE(CONSTCOND)					\
	} while (0)

/* shorthand  for nvlist_lookup_pairs() args */
#define	NV_PAIR(type, strct, field) #field, DATA_TYPE_##type, &(strct->field)

/* number of times to retry the upcall to transmit */
#define	STMF_MSG_TRANSMIT_RETRY	    3

/*
 * How was the message constructed?
 *
 * We need to know this when we free the message in order to
 * determine what to do with pointers in the message:
 *
 * - messages which were unmarshaled from an nvlist may point to
 *   memory within that nvlist; this memory should not be freed since
 *   it will be deallocated when we free the nvlist.
 *
 * - messages which built using a constructor (alloc) function may
 *   point to memory which was explicitly allocated by the constructor;
 *   it should be freed when the message is freed.
 *
 */
typedef enum {
	STMF_CONSTRUCTOR = 0,
	STMF_UNMARSHAL
} stmf_ic_msg_construction_method_t;


/*
 * Function prototypes.
 */

/*
 * Helpers for msg_alloc routines, used when the msg payload is
 * the same for multiple types of messages.
 */
static stmf_ic_msg_t *stmf_ic_reg_dereg_lun_msg_alloc(
    stmf_ic_msg_type_t msg_type, uint8_t *lun_id,
    char *lu_provider_name, uint16_t cb_arg_len,
    uint8_t *cb_arg, stmf_ic_msgid_t msgid);

static stmf_ic_msg_t *stmf_ic_session_create_destroy_msg_alloc(
    stmf_ic_msg_type_t msg_type,
    stmf_scsi_session_t *session,
    stmf_ic_msgid_t msgid);

static stmf_ic_msg_t *stmf_ic_echo_request_reply_msg_alloc(
    stmf_ic_msg_type_t msg_type,
    uint32_t data_len,
    uint8_t *data,
    stmf_ic_msgid_t msgid);

/*
 * Msg free routines.
 */
static void stmf_ic_reg_port_msg_free(stmf_ic_reg_port_msg_t *m,
    stmf_ic_msg_construction_method_t cmethod);
static void stmf_ic_dereg_port_msg_free(stmf_ic_dereg_port_msg_t *m,
    stmf_ic_msg_construction_method_t cmethod);
static void stmf_ic_reg_dereg_lun_msg_free(stmf_ic_reg_dereg_lun_msg_t *m,
    stmf_ic_msg_construction_method_t cmethod);
static void stmf_ic_scsi_cmd_msg_free(stmf_ic_scsi_cmd_msg_t *m,
    stmf_ic_msg_construction_method_t cmethod);
static void stmf_ic_scsi_data_msg_free(stmf_ic_scsi_data_msg_t *m,
    stmf_ic_msg_construction_method_t cmethod);
static void stmf_ic_scsi_data_xfer_done_msg_free(
    stmf_ic_scsi_data_xfer_done_msg_t *m,
    stmf_ic_msg_construction_method_t cmethod);
static void stmf_ic_scsi_status_msg_free(stmf_ic_scsi_status_msg_t *m,
    stmf_ic_msg_construction_method_t cmethod);
static void stmf_ic_r2t_msg_free(stmf_ic_r2t_msg_t *m,
    stmf_ic_msg_construction_method_t cmethod);
static void stmf_ic_status_msg_free(stmf_ic_status_msg_t *m,
    stmf_ic_msg_construction_method_t cmethod);
static void stmf_ic_session_create_destroy_msg_free(
    stmf_ic_session_create_destroy_msg_t *m,
    stmf_ic_msg_construction_method_t cmethod);
static void stmf_ic_echo_request_reply_msg_free(
    stmf_ic_echo_request_reply_msg_t *m,
    stmf_ic_msg_construction_method_t cmethod);

/*
 * Marshaling routines.
 */
static nvlist_t *stmf_ic_msg_marshal(stmf_ic_msg_t *msg);
static int stmf_ic_reg_port_msg_marshal(nvlist_t *nvl, void *msg);
static int stmf_ic_dereg_port_msg_marshal(nvlist_t *nvl, void *msg);
static int stmf_ic_reg_dereg_lun_msg_marshal(nvlist_t *nvl, void *msg);
static int stmf_ic_scsi_cmd_msg_marshal(nvlist_t *nvl, void *msg);
static int stmf_ic_scsi_data_msg_marshal(nvlist_t *nvl, void *msg);
static int stmf_ic_scsi_data_xfer_done_msg_marshal(nvlist_t *nvl, void *msg);
static int stmf_ic_scsi_status_msg_marshal(nvlist_t *nvl, void *msg);
static int stmf_ic_r2t_msg_marshal(nvlist_t *nvl, void *msg);
static int stmf_ic_status_msg_marshal(nvlist_t *nvl, void *msg);
static int stmf_ic_session_create_destroy_msg_marshal(nvlist_t *nvl, void *msg);
static int stmf_ic_echo_request_reply_msg_marshal(nvlist_t *nvl, void *msg);
static int stmf_ic_scsi_devid_desc_marshal(nvlist_t *parent_nvl,
	char *sdid_name, scsi_devid_desc_t *sdid);
static int stmf_ic_remote_port_marshal(nvlist_t *parent_nvl,
	char *rport_name, stmf_remote_port_t *rport);

/*
 * Unmarshaling routines.
 */
static stmf_ic_msg_t *stmf_ic_msg_unmarshal(nvlist_t *nvl);
static void *stmf_ic_reg_port_msg_unmarshal(nvlist_t *nvl);
static void *stmf_ic_dereg_port_msg_unmarshal(nvlist_t *nvl);
static void *stmf_ic_reg_dereg_lun_msg_unmarshal(nvlist_t *nvl);
static void *stmf_ic_scsi_cmd_msg_unmarshal(nvlist_t *nvl);
static void *stmf_ic_scsi_data_msg_unmarshal(nvlist_t *nvl);
static void *stmf_ic_scsi_data_xfer_done_msg_unmarshal(nvlist_t *nvl);
static void *stmf_ic_scsi_status_msg_unmarshal(nvlist_t *nvl);
static void *stmf_ic_r2t_msg_unmarshal(nvlist_t *nvl);
static void *stmf_ic_status_msg_unmarshal(nvlist_t *nvl);
static void *stmf_ic_session_create_destroy_msg_unmarshal(nvlist_t *nvl);
static void *stmf_ic_echo_request_reply_msg_unmarshal(nvlist_t *nvl);
static scsi_devid_desc_t *stmf_ic_lookup_scsi_devid_desc_and_unmarshal(
    nvlist_t *nvl, char *field_name);
static scsi_devid_desc_t *stmf_ic_scsi_devid_desc_unmarshal(
    nvlist_t *nvl_devid);
static uint8_t *stmf_ic_uint8_array_unmarshal(nvlist_t *nvl, char *field_name,
	uint64_t len, uint8_t *buf);
static char *stmf_ic_string_unmarshal(nvlist_t *nvl, char *field_name);
static stmf_remote_port_t *stmf_ic_lookup_remote_port_and_unmarshal(
	nvlist_t *nvl, char *field_name);
static stmf_remote_port_t *stmf_ic_remote_port_unmarshal(nvlist_t *nvl);

/*
 * Transmit and recieve routines.
 */
stmf_ic_msg_status_t stmf_ic_transmit(char *buf, size_t size);

/*
 * Utilities.
 */
static stmf_ic_msg_t *stmf_ic_alloc_msg_header(stmf_ic_msg_type_t msg_type,
	stmf_ic_msgid_t msgid);
static size_t sizeof_scsi_devid_desc(int ident_length);
static char *stmf_ic_strdup(char *str);
static scsi_devid_desc_t *scsi_devid_desc_dup(scsi_devid_desc_t *did);
static stmf_remote_port_t *remote_port_dup(stmf_remote_port_t *rport);
static void scsi_devid_desc_free(scsi_devid_desc_t *did);
static inline void stmf_ic_nvlookup_warn(const char *func, char *field);

/*
 * Send a message out over the interconnect, in the process marshalling
 * the arguments.
 *
 * After being sent, the message is freed.
 */
stmf_ic_msg_status_t
stmf_ic_tx_msg(stmf_ic_msg_t *msg)
{
	size_t size = 0;
	nvlist_t *nvl = NULL;
	char *buf = NULL;
	int err = 0;
	stmf_ic_msg_status_t status = STMF_IC_MSG_SUCCESS;

	nvl = stmf_ic_msg_marshal(msg);
	if (!nvl) {
		cmn_err(CE_WARN, "stmf_ic_tx_msg: marshal failed");
		status = STMF_IC_MSG_INTERNAL_ERROR;
		goto done;
	}

	err = nvlist_size(nvl, &size, NV_ENCODE_XDR);
	if (err) {
		status = STMF_IC_MSG_INTERNAL_ERROR;
		goto done;
	}

	buf = kmem_alloc(size, KM_SLEEP);
	err = nvlist_pack(nvl, &buf, &size, NV_ENCODE_XDR, 0);
	if (err) {
		status = STMF_IC_MSG_INTERNAL_ERROR;
		goto done;
	}

	/* push the bits out on the wire */

	status = stmf_ic_transmit(buf, size);

done:
	nvlist_free(nvl);

	if (buf)
		kmem_free(buf, size);

	stmf_ic_msg_free(msg);


	return (status);
}

/*
 * Pass the command to the daemon for transmission to the other node.
 */
stmf_ic_msg_status_t
stmf_ic_transmit(char *buf, size_t size)
{
	int i;
	int rc;
	door_arg_t arg;
	door_handle_t door;
	uint32_t result;

	mutex_enter(&pppt_global.global_door_lock);
	if (pppt_global.global_door == NULL) {
		/* daemon not listening */
		mutex_exit(&pppt_global.global_door_lock);
		return (STMF_IC_MSG_INTERNAL_ERROR);
	}
	door = pppt_global.global_door;
	door_ki_hold(door);
	mutex_exit(&pppt_global.global_door_lock);

	arg.data_ptr = buf;
	arg.data_size = size;
	arg.desc_ptr = NULL;
	arg.desc_num = 0;
	arg.rbuf = (char *)&result;
	arg.rsize = sizeof (result);
	/*
	 * Retry a few times if there is a shortage of threads to
	 * service the upcall. This shouldn't happen unless a large
	 * number of initiators issue commands at once.
	 */
	for (i = 0; i < STMF_MSG_TRANSMIT_RETRY; i++) {
		rc = door_ki_upcall(door, &arg);
		if (rc != EAGAIN)
			break;
		delay(hz);
	}
	door_ki_rele(door);
	if (rc != 0) {
		cmn_err(CE_WARN,
		    "stmf_ic_transmit door_ki_upcall failed %d", rc);
		return (STMF_IC_MSG_INTERNAL_ERROR);
	}
	if (result != 0) {
		/* XXX Just warn for now */
		cmn_err(CE_WARN,
		    "stmf_ic_transmit bad result from daemon %d", result);
	}

	return (STMF_IC_MSG_SUCCESS);
}

/*
 * This is a low-level upcall which is called when a message has
 * been received on the interconnect.
 *
 * The caller is responsible for freeing the buffer which is passed in.
 */
/*ARGSUSED*/
void
stmf_ic_rx_msg(char *buf, size_t len)
{
	nvlist_t *nvl = NULL;
	stmf_ic_msg_t *m = NULL;
	stmf_ic_echo_request_reply_msg_t *icerr;
	stmf_ic_msg_t *echo_msg;
	int rc = 0;

	rc = nvlist_unpack(buf, len, &nvl, 0);
	if (rc) {
		cmn_err(CE_WARN, "stmf_ic_rx_msg: unpack failed");
		return;
	}

	m = stmf_ic_msg_unmarshal(nvl);
	if (m == NULL) {
		cmn_err(CE_WARN, "stmf_ic_rx_msg: unmarshal failed");
		nvlist_free(nvl);
		return;
	}

	switch (m->icm_msg_type) {

	case STMF_ICM_REGISTER_PROXY_PORT:
	case STMF_ICM_DEREGISTER_PROXY_PORT:
	case STMF_ICM_SCSI_CMD:
	case STMF_ICM_SCSI_DATA_XFER_DONE:
	case STMF_ICM_SESSION_CREATE:
	case STMF_ICM_SESSION_DESTROY:
		/*
		 * These messages are all received by pppt.
		 * Currently, pppt will parse the message for type
		 */
		(void) pppt_msg_rx(m);
		break;

	case STMF_ICM_LUN_ACTIVE:
	case STMF_ICM_REGISTER_LUN:
	case STMF_ICM_DEREGISTER_LUN:
	case STMF_ICM_SCSI_DATA:
	case STMF_ICM_SCSI_STATUS:
		/*
		 * These messages are all received by stmf.
		 * Currently, stmf will parse the message for type
		 */
		(void) stmf_msg_rx(m);
		break;

	case STMF_ICM_ECHO_REQUEST:
		icerr = m->icm_msg;
		echo_msg = stmf_ic_echo_reply_msg_alloc(icerr->icerr_datalen,
		    icerr->icerr_data, 0);
		if (echo_msg != NULL) {
			(void) stmf_ic_tx_msg(echo_msg);
		}
		stmf_ic_msg_free(m);
		break;

	case STMF_ICM_ECHO_REPLY:
		stmf_ic_msg_free(m);
		break;

	case STMF_ICM_R2T:
		/*
		 * XXX currently not supported
		 */
		stmf_ic_msg_free(m);
		break;

	case STMF_ICM_STATUS:
		(void) stmf_msg_rx(m);
		break;

	default:
		ASSERT(0);
	}
}

/*
 * IC message allocation routines.
 */

stmf_ic_msg_t *
stmf_ic_reg_port_msg_alloc(
    scsi_devid_desc_t *port_id,
    uint16_t relative_port_id,
    uint16_t cb_arg_len,
    uint8_t *cb_arg,
    stmf_ic_msgid_t msgid)
{
	stmf_ic_msg_t *icm = NULL;
	stmf_ic_reg_port_msg_t *icrp = NULL;

	icm = stmf_ic_alloc_msg_header(STMF_ICM_REGISTER_PROXY_PORT, msgid);
	icrp = (stmf_ic_reg_port_msg_t *)kmem_zalloc(sizeof (*icrp), KM_SLEEP);
	icm->icm_msg = (void *)icrp;

	icrp->icrp_port_id = scsi_devid_desc_dup(port_id);
	icrp->icrp_relative_port_id = relative_port_id;

	if (cb_arg_len) {
		icrp->icrp_cb_arg_len = cb_arg_len;
		icrp->icrp_cb_arg = cb_arg;
	}

	return (icm);
}

stmf_ic_msg_t *
stmf_ic_dereg_port_msg_alloc(
    scsi_devid_desc_t *port_id,
    uint16_t cb_arg_len,
    uint8_t *cb_arg,
    stmf_ic_msgid_t msgid)
{
	stmf_ic_msg_t *icm = NULL;
	stmf_ic_dereg_port_msg_t *icdp = NULL;

	icm = stmf_ic_alloc_msg_header(STMF_ICM_DEREGISTER_PROXY_PORT, msgid);
	icdp = (stmf_ic_dereg_port_msg_t *)kmem_zalloc(sizeof (*icdp),
	    KM_SLEEP);
	icm->icm_msg = (void *)icdp;

	icdp->icdp_port_id = scsi_devid_desc_dup(port_id);

	if (cb_arg_len) {
		icdp->icdp_cb_arg_len = cb_arg_len;
		icdp->icdp_cb_arg = cb_arg;
	}

	return (icm);
}


stmf_ic_msg_t *
stmf_ic_reg_lun_msg_alloc(
    uint8_t *lun_id,
    char *lu_provider_name,
    uint16_t cb_arg_len,
    uint8_t *cb_arg,
    stmf_ic_msgid_t msgid)
{
	return (stmf_ic_reg_dereg_lun_msg_alloc(STMF_ICM_REGISTER_LUN, lun_id,
	    lu_provider_name, cb_arg_len, cb_arg, msgid));
}

stmf_ic_msg_t *
stmf_ic_lun_active_msg_alloc(
    uint8_t *lun_id,
    char *lu_provider_name,
    uint16_t cb_arg_len,
    uint8_t *cb_arg,
    stmf_ic_msgid_t msgid)
{
	return (stmf_ic_reg_dereg_lun_msg_alloc(STMF_ICM_LUN_ACTIVE, lun_id,
	    lu_provider_name, cb_arg_len, cb_arg, msgid));
}

stmf_ic_msg_t *
stmf_ic_dereg_lun_msg_alloc(
    uint8_t *lun_id,
    char *lu_provider_name,
    uint16_t cb_arg_len,
    uint8_t *cb_arg,
    stmf_ic_msgid_t msgid)
{
	return (stmf_ic_reg_dereg_lun_msg_alloc(STMF_ICM_DEREGISTER_LUN, lun_id,
	    lu_provider_name, cb_arg_len, cb_arg, msgid));
}

/*
 * Guts of lun register/deregister/active alloc routines.
 */
static stmf_ic_msg_t *
stmf_ic_reg_dereg_lun_msg_alloc(
    stmf_ic_msg_type_t msg_type,
    uint8_t *lun_id,
    char *lu_provider_name,
    uint16_t cb_arg_len,
    uint8_t *cb_arg,
    stmf_ic_msgid_t msgid)
{
	stmf_ic_msg_t *icm = NULL;
	stmf_ic_reg_dereg_lun_msg_t *icrl = NULL;

	icm = stmf_ic_alloc_msg_header(msg_type, msgid);
	icrl = (stmf_ic_reg_dereg_lun_msg_t *)
	    kmem_zalloc(sizeof (*icrl), KM_SLEEP);
	icm->icm_msg = (void *)icrl;

	icrl->icrl_lu_provider_name = stmf_ic_strdup(lu_provider_name);

	bcopy(lun_id, icrl->icrl_lun_id, sizeof (icrl->icrl_lun_id));

	if (cb_arg_len) {
		icrl->icrl_cb_arg_len = cb_arg_len;
		icrl->icrl_cb_arg = cb_arg;
	}

	return (icm);
}

stmf_ic_msg_t *
stmf_ic_scsi_cmd_msg_alloc(
    stmf_ic_msgid_t task_msgid,
    scsi_task_t *task,
    uint32_t immed_data_len,
    uint8_t *immed_data,
    stmf_ic_msgid_t msgid)
{
	stmf_ic_msg_t *icm = NULL;
	stmf_ic_scsi_cmd_msg_t *icsc = NULL;
	scsi_devid_desc_t *ini_devid = task->task_session->ss_rport_id;
	scsi_devid_desc_t *tgt_devid = task->task_lport->lport_id;
	stmf_remote_port_t *rport = task->task_session->ss_rport;

	icm = stmf_ic_alloc_msg_header(STMF_ICM_SCSI_CMD, msgid);
	icsc = (stmf_ic_scsi_cmd_msg_t *)kmem_zalloc(sizeof (*icsc), KM_SLEEP);
	icm->icm_msg = (void *)icsc;

	icsc->icsc_task_msgid = task_msgid;
	icsc->icsc_ini_devid = scsi_devid_desc_dup(ini_devid);
	icsc->icsc_tgt_devid = scsi_devid_desc_dup(tgt_devid);
	icsc->icsc_rport = remote_port_dup(rport);
	icsc->icsc_session_id = task->task_session->ss_session_id;

	if (!task->task_mgmt_function && task->task_lu->lu_id) {
		bcopy(task->task_lu->lu_id->ident,
		    icsc->icsc_lun_id, sizeof (icsc->icsc_lun_id));
	}

	bcopy(task->task_lun_no, icsc->icsc_task_lun_no,
	    sizeof (icsc->icsc_task_lun_no));

	icsc->icsc_task_expected_xfer_length = task->task_expected_xfer_length;
	if (task->task_cdb_length) {
		ASSERT(task->task_mgmt_function == TM_NONE);
		icsc->icsc_task_cdb_length = task->task_cdb_length;
		icsc->icsc_task_cdb =
		    (uint8_t *)kmem_zalloc(task->task_cdb_length, KM_SLEEP);
		bcopy(task->task_cdb, icsc->icsc_task_cdb,
		    task->task_cdb_length);
	}

	icsc->icsc_task_flags = task->task_flags;
	icsc->icsc_task_priority = task->task_priority;
	icsc->icsc_task_mgmt_function = task->task_mgmt_function;

	icsc->icsc_immed_data_len = immed_data_len;
	icsc->icsc_immed_data = immed_data;

	return (icm);
}

stmf_ic_msg_t *
stmf_ic_scsi_data_msg_alloc(
    stmf_ic_msgid_t task_msgid,
    uint64_t session_id,
    uint8_t *lun_id,
    uint64_t data_len,
    uint8_t *data,
    stmf_ic_msgid_t msgid)
{
	stmf_ic_msg_t *icm = NULL;
	stmf_ic_scsi_data_msg_t *icsd = NULL;

	icm = stmf_ic_alloc_msg_header(STMF_ICM_SCSI_DATA, msgid);
	icsd = (stmf_ic_scsi_data_msg_t *)kmem_zalloc(sizeof (*icsd), KM_SLEEP);
	icm->icm_msg = (void *)icsd;

	icsd->icsd_task_msgid = task_msgid;
	icsd->icsd_session_id = session_id;
	bcopy(lun_id, icsd->icsd_lun_id, sizeof (icsd->icsd_lun_id));
	icsd->icsd_data_len = data_len;
	icsd->icsd_data = data;

	return (icm);
}

stmf_ic_msg_t *
stmf_ic_scsi_data_xfer_done_msg_alloc(
    stmf_ic_msgid_t task_msgid,
    uint64_t session_id,
    stmf_status_t status,
    stmf_ic_msgid_t msgid)
{
	stmf_ic_msg_t *icm = NULL;
	stmf_ic_scsi_data_xfer_done_msg_t *icsx = NULL;

	icm = stmf_ic_alloc_msg_header(STMF_ICM_SCSI_DATA_XFER_DONE, msgid);
	icsx = (stmf_ic_scsi_data_xfer_done_msg_t *)kmem_zalloc(
	    sizeof (*icsx), KM_SLEEP);
	icm->icm_msg = (void *)icsx;

	icsx->icsx_task_msgid = task_msgid;
	icsx->icsx_session_id = session_id;
	icsx->icsx_status = status;

	return (icm);
}

stmf_ic_msg_t *
stmf_ic_scsi_status_msg_alloc(
    stmf_ic_msgid_t task_msgid,
    uint64_t session_id,
    uint8_t *lun_id,
    uint8_t response,
    uint8_t status,
    uint8_t flags,
    uint32_t resid,
    uint8_t sense_len,
    uint8_t *sense,
    stmf_ic_msgid_t msgid)
{
	stmf_ic_msg_t *icm = NULL;
	stmf_ic_scsi_status_msg_t *icss = NULL;

	icm = stmf_ic_alloc_msg_header(STMF_ICM_SCSI_STATUS, msgid);
	icss = (stmf_ic_scsi_status_msg_t *)kmem_zalloc(sizeof (*icss),
	    KM_SLEEP);
	icm->icm_msg = (void *)icss;

	icss->icss_task_msgid = task_msgid;
	icss->icss_session_id = session_id;
	bcopy(lun_id, icss->icss_lun_id, sizeof (icss->icss_lun_id));
	icss->icss_response = response;
	icss->icss_status = status;
	icss->icss_flags = flags;
	icss->icss_resid = resid;
	icss->icss_sense_len = sense_len;
	icss->icss_sense = sense;

	return (icm);
}

stmf_ic_msg_t *
stmf_ic_r2t_msg_alloc(
    stmf_ic_msgid_t task_msgid,
    uint64_t session_id,
    uint32_t offset,
    uint32_t length,
    stmf_ic_msgid_t msgid)
{
	stmf_ic_msg_t *icm = NULL;
	stmf_ic_r2t_msg_t *icrt = NULL;

	icm = stmf_ic_alloc_msg_header(STMF_ICM_R2T, msgid);
	icrt = (stmf_ic_r2t_msg_t *)kmem_zalloc(sizeof (*icrt), KM_SLEEP);
	icm->icm_msg = (void *)icrt;

	icrt->icrt_task_msgid = task_msgid;
	icrt->icrt_session_id = session_id;
	icrt->icrt_offset = offset;
	icrt->icrt_length = length;

	return (icm);
}

stmf_ic_msg_t *
stmf_ic_status_msg_alloc(
    stmf_status_t status,
    stmf_ic_msg_type_t msg_type,
    stmf_ic_msgid_t msgid)
{
	stmf_ic_msg_t *icm = NULL;
	stmf_ic_status_msg_t *ics = NULL;

	icm = stmf_ic_alloc_msg_header(STMF_ICM_STATUS, msgid);
	ics = (stmf_ic_status_msg_t *)kmem_zalloc(sizeof (*ics), KM_SLEEP);
	icm->icm_msg = (void *)ics;

	ics->ics_status = status;
	ics->ics_msg_type = msg_type;
	ics->ics_msgid = msgid;		/* XXX same as msgid in header */

	return (icm);
}

stmf_ic_msg_t *
stmf_ic_session_create_msg_alloc(
    stmf_scsi_session_t *session,
    stmf_ic_msgid_t msgid)
{
	return (stmf_ic_session_create_destroy_msg_alloc(
	    STMF_ICM_SESSION_CREATE, session, msgid));
}

stmf_ic_msg_t *
stmf_ic_session_destroy_msg_alloc(
    stmf_scsi_session_t *session,
    stmf_ic_msgid_t msgid)
{
	return (stmf_ic_session_create_destroy_msg_alloc(
	    STMF_ICM_SESSION_DESTROY, session, msgid));
}

/*
 * Guts of session create/destroy routines.
 */
static stmf_ic_msg_t *
stmf_ic_session_create_destroy_msg_alloc(
    stmf_ic_msg_type_t msg_type,
    stmf_scsi_session_t *session,
    stmf_ic_msgid_t msgid)
{
	stmf_ic_msg_t *icm = NULL;
	stmf_ic_session_create_destroy_msg_t *icscd = NULL;
	scsi_devid_desc_t *ini_devid = session->ss_rport_id;
	scsi_devid_desc_t *tgt_devid = session->ss_lport->lport_id;

	icm = stmf_ic_alloc_msg_header(msg_type, msgid);
	icscd = (stmf_ic_session_create_destroy_msg_t *)
	    kmem_zalloc(sizeof (*icscd), KM_SLEEP);
	icm->icm_msg = (void *)icscd;

	icscd->icscd_session_id = session->ss_session_id;
	icscd->icscd_ini_devid = scsi_devid_desc_dup(ini_devid);
	icscd->icscd_tgt_devid = scsi_devid_desc_dup(tgt_devid);
	icscd->icscd_rport = remote_port_dup(session->ss_rport);

	return (icm);
}

stmf_ic_msg_t *
stmf_ic_echo_request_msg_alloc(
    uint32_t data_len,
    uint8_t *data,
    stmf_ic_msgid_t msgid)
{
	return (stmf_ic_echo_request_reply_msg_alloc(
	    STMF_ICM_ECHO_REQUEST, data_len, data, msgid));
}

stmf_ic_msg_t *
stmf_ic_echo_reply_msg_alloc(
    uint32_t data_len,
    uint8_t *data,
    stmf_ic_msgid_t msgid)
{
	return (stmf_ic_echo_request_reply_msg_alloc(
	    STMF_ICM_ECHO_REPLY, data_len, data, msgid));
}


static stmf_ic_msg_t *
stmf_ic_echo_request_reply_msg_alloc(
    stmf_ic_msg_type_t msg_type,
    uint32_t data_len,
    uint8_t *data,
    stmf_ic_msgid_t msgid)
{
	stmf_ic_msg_t *icm = NULL;
	stmf_ic_echo_request_reply_msg_t *icerr = NULL;

	icm = stmf_ic_alloc_msg_header(msg_type, msgid);
	icerr = kmem_zalloc(sizeof (*icerr), KM_SLEEP);
	icm->icm_msg = (void *)icerr;

	icerr->icerr_data = data;
	icerr->icerr_datalen = data_len;

	return (icm);
}

/*
 * msg free routines.
 */
void
stmf_ic_msg_free(stmf_ic_msg_t *msg)
{
	stmf_ic_msg_construction_method_t cmethod =
	    (msg->icm_nvlist ? STMF_UNMARSHAL : STMF_CONSTRUCTOR);

	switch (msg->icm_msg_type) {
	case STMF_ICM_REGISTER_PROXY_PORT:
		stmf_ic_reg_port_msg_free(
		    (stmf_ic_reg_port_msg_t *)msg->icm_msg, cmethod);
		break;

	case STMF_ICM_DEREGISTER_PROXY_PORT:
		stmf_ic_dereg_port_msg_free(
		    (stmf_ic_dereg_port_msg_t *)msg->icm_msg, cmethod);
		break;

	case STMF_ICM_LUN_ACTIVE:
	case STMF_ICM_REGISTER_LUN:
	case STMF_ICM_DEREGISTER_LUN:
		stmf_ic_reg_dereg_lun_msg_free(
		    (stmf_ic_reg_dereg_lun_msg_t *)msg->icm_msg, cmethod);
		break;

	case STMF_ICM_SCSI_CMD:
		stmf_ic_scsi_cmd_msg_free(
		    (stmf_ic_scsi_cmd_msg_t *)msg->icm_msg, cmethod);
		break;

	case STMF_ICM_SCSI_DATA:
		stmf_ic_scsi_data_msg_free(
		    (stmf_ic_scsi_data_msg_t *)msg->icm_msg, cmethod);
		break;

	case STMF_ICM_SCSI_DATA_XFER_DONE:
		stmf_ic_scsi_data_xfer_done_msg_free(
		    (stmf_ic_scsi_data_xfer_done_msg_t *)msg->icm_msg, cmethod);
		break;

	case STMF_ICM_SCSI_STATUS:
		stmf_ic_scsi_status_msg_free(
		    (stmf_ic_scsi_status_msg_t *)msg->icm_msg, cmethod);
		break;

	case STMF_ICM_R2T:
		stmf_ic_r2t_msg_free(
		    (stmf_ic_r2t_msg_t *)msg->icm_msg, cmethod);
		break;

	case STMF_ICM_STATUS:
		stmf_ic_status_msg_free(
		    (stmf_ic_status_msg_t *)msg->icm_msg, cmethod);
		break;

	case STMF_ICM_SESSION_CREATE:
	case STMF_ICM_SESSION_DESTROY:
		stmf_ic_session_create_destroy_msg_free(
		    (stmf_ic_session_create_destroy_msg_t *)msg->icm_msg,
		    cmethod);
		break;

	case STMF_ICM_ECHO_REQUEST:
	case STMF_ICM_ECHO_REPLY:
		stmf_ic_echo_request_reply_msg_free(
		    (stmf_ic_echo_request_reply_msg_t *)msg->icm_msg, cmethod);
		break;

	case STMF_ICM_MAX_MSG_TYPE:
		ASSERT(0);
		break;

	default:
		ASSERT(0);
	}

	nvlist_free(msg->icm_nvlist);

	kmem_free(msg, sizeof (*msg));
}

/*ARGSUSED*/
static void
stmf_ic_reg_port_msg_free(stmf_ic_reg_port_msg_t *m,
    stmf_ic_msg_construction_method_t cmethod)
{
	scsi_devid_desc_free(m->icrp_port_id);

	kmem_free(m, sizeof (*m));
}


/*ARGSUSED*/
static void
stmf_ic_dereg_port_msg_free(stmf_ic_dereg_port_msg_t *m,
    stmf_ic_msg_construction_method_t cmethod)
{
	scsi_devid_desc_free(m->icdp_port_id);

	kmem_free(m, sizeof (*m));
}


/*
 * Works for both reg_lun_msg and dereg_lun_msg, since the message
 * payload is the same.
 */
static void
stmf_ic_reg_dereg_lun_msg_free(stmf_ic_reg_dereg_lun_msg_t *m,
    stmf_ic_msg_construction_method_t cmethod)
{
	if (cmethod == STMF_CONSTRUCTOR) {
		kmem_free(m->icrl_lu_provider_name,
		    strlen(m->icrl_lu_provider_name) + 1);
	}

	kmem_free(m, sizeof (*m));
}

static void
stmf_ic_scsi_cmd_msg_free(stmf_ic_scsi_cmd_msg_t *m,
    stmf_ic_msg_construction_method_t cmethod)
{
	scsi_devid_desc_free(m->icsc_ini_devid);
	scsi_devid_desc_free(m->icsc_tgt_devid);
	stmf_remote_port_free(m->icsc_rport);
	if ((cmethod == STMF_CONSTRUCTOR) && m->icsc_task_cdb) {
		kmem_free(m->icsc_task_cdb, m->icsc_task_cdb_length);
	}

	kmem_free(m, sizeof (*m));

}

/*ARGSUSED*/
static void
stmf_ic_scsi_data_msg_free(stmf_ic_scsi_data_msg_t *m,
    stmf_ic_msg_construction_method_t cmethod)
{
	kmem_free(m, sizeof (*m));
}

/*ARGSUSED*/
static void
stmf_ic_scsi_data_xfer_done_msg_free(stmf_ic_scsi_data_xfer_done_msg_t *m,
    stmf_ic_msg_construction_method_t cmethod)
{
	kmem_free(m, sizeof (*m));
}

/*ARGSUSED*/
static void
stmf_ic_scsi_status_msg_free(stmf_ic_scsi_status_msg_t *m,
    stmf_ic_msg_construction_method_t cmethod)
{
	kmem_free(m, sizeof (*m));
}

/*ARGSUSED*/
static void
stmf_ic_r2t_msg_free(stmf_ic_r2t_msg_t *m,
    stmf_ic_msg_construction_method_t cmethod)
{
	kmem_free(m, sizeof (*m));
}

/*ARGSUSED*/
static void
stmf_ic_status_msg_free(stmf_ic_status_msg_t *m,
    stmf_ic_msg_construction_method_t cmethod)
{
	kmem_free(m, sizeof (*m));
}

/*
 * Works for both session_create and session_destroy msgs, since the message
 * payload is the same.
 */
/*ARGSUSED*/
static void
stmf_ic_session_create_destroy_msg_free(stmf_ic_session_create_destroy_msg_t *m,
    stmf_ic_msg_construction_method_t cmethod)
{
	scsi_devid_desc_free(m->icscd_ini_devid);
	scsi_devid_desc_free(m->icscd_tgt_devid);
	stmf_remote_port_free(m->icscd_rport);

	kmem_free(m, sizeof (*m));
}

/*ARGSUSED*/
static void
stmf_ic_echo_request_reply_msg_free(stmf_ic_echo_request_reply_msg_t *m,
    stmf_ic_msg_construction_method_t cmethod)
{
	kmem_free(m, sizeof (*m));
}


/*
 * Marshaling routines.
 */

static nvlist_t *
stmf_ic_msg_marshal(stmf_ic_msg_t *msg)
{
	nvlist_t *nvl = NULL;
	int rc = 0;

	rc = nvlist_alloc(&nvl, NV_UNIQUE_NAME, KM_SLEEP);
	if (rc)
		goto done;

	NVLIST_ADD_FIELD(uint8, msg, icm_msg_type);
	NVLIST_ADD_FIELD(uint64, msg, icm_msgid);

	switch (msg->icm_msg_type) {
	case STMF_ICM_REGISTER_PROXY_PORT:
		rc = stmf_ic_reg_port_msg_marshal(nvl, msg->icm_msg);
		break;


	case STMF_ICM_DEREGISTER_PROXY_PORT:
		rc = stmf_ic_dereg_port_msg_marshal(nvl, msg->icm_msg);
		break;

	case STMF_ICM_LUN_ACTIVE:
	case STMF_ICM_REGISTER_LUN:
	case STMF_ICM_DEREGISTER_LUN:
		rc = stmf_ic_reg_dereg_lun_msg_marshal(nvl, msg->icm_msg);
		break;

	case STMF_ICM_SCSI_CMD:
		rc = stmf_ic_scsi_cmd_msg_marshal(nvl, msg->icm_msg);
		break;

	case STMF_ICM_SCSI_DATA:
		rc = stmf_ic_scsi_data_msg_marshal(nvl, msg->icm_msg);
		break;

	case STMF_ICM_SCSI_DATA_XFER_DONE:
		rc = stmf_ic_scsi_data_xfer_done_msg_marshal(nvl, msg->icm_msg);
		break;

	case STMF_ICM_SCSI_STATUS:
		rc = stmf_ic_scsi_status_msg_marshal(nvl, msg->icm_msg);
		break;

	case STMF_ICM_R2T:
		rc = stmf_ic_r2t_msg_marshal(nvl, msg->icm_msg);
		break;

	case STMF_ICM_STATUS:
		rc = stmf_ic_status_msg_marshal(nvl, msg->icm_msg);
		break;

	case STMF_ICM_SESSION_CREATE:
	case STMF_ICM_SESSION_DESTROY:
		rc = stmf_ic_session_create_destroy_msg_marshal(nvl,
		    msg->icm_msg);
		break;

	case STMF_ICM_ECHO_REQUEST:
	case STMF_ICM_ECHO_REPLY:
		rc = stmf_ic_echo_request_reply_msg_marshal(nvl,
		    msg->icm_msg);
		break;

	case STMF_ICM_MAX_MSG_TYPE:
		ASSERT(0);
		break;

	default:
		ASSERT(0);
	}

done:
	if (!rc)
		return (nvl);

	nvlist_free(nvl);

	return (NULL);
}


static int
stmf_ic_reg_port_msg_marshal(nvlist_t *nvl, void *msg)
{
	stmf_ic_reg_port_msg_t *m = (stmf_ic_reg_port_msg_t *)msg;
	int rc = 0;

	NVLIST_ADD_DEVID(m, icrp_port_id);
	NVLIST_ADD_FIELD(uint16, m, icrp_relative_port_id);

	NVLIST_ADD_FIELD(uint16, m, icrp_cb_arg_len);
	/* only add the callback arg if necessary */
	if (m->icrp_cb_arg_len) {
		NVLIST_ADD_ARRAY_LEN(uint8, m, icrp_cb_arg, m->icrp_cb_arg_len);
	}

done:
	return (rc);
}

static int
stmf_ic_dereg_port_msg_marshal(nvlist_t *nvl, void *msg)
{
	stmf_ic_dereg_port_msg_t *m = (stmf_ic_dereg_port_msg_t *)msg;
	int rc = 0;

	NVLIST_ADD_DEVID(m, icdp_port_id);
	NVLIST_ADD_FIELD(uint16, m, icdp_cb_arg_len);

	/* only add the callback arg if necessary */
	if (m->icdp_cb_arg_len) {
		NVLIST_ADD_ARRAY_LEN(uint8, m, icdp_cb_arg, m->icdp_cb_arg_len);
	}

done:
	return (rc);
}

/*
 * Handles STMF_ICM_LUN_ACTIVE, STMF_ICM_REGISTER_LUN and
 * STMF_ICM_DEREGISTER_LUN;
 * msg payload is the same for all.
 */
static int
stmf_ic_reg_dereg_lun_msg_marshal(nvlist_t *nvl, void *msg)
{
	stmf_ic_reg_dereg_lun_msg_t *m = (stmf_ic_reg_dereg_lun_msg_t *)msg;
	int rc = 0;

	NVLIST_ADD_ARRAY(uint8, m, icrl_lun_id);
	NVLIST_ADD_FIELD(string, m, icrl_lu_provider_name);
	NVLIST_ADD_FIELD(uint16, m, icrl_cb_arg_len);

	/* only add the callback arg if necessary */
	if (m->icrl_cb_arg_len) {
		NVLIST_ADD_ARRAY_LEN(uint8, m, icrl_cb_arg, m->icrl_cb_arg_len);
	}

done:
	return (rc);
}

static int
stmf_ic_scsi_cmd_msg_marshal(nvlist_t *nvl, void *msg)
{
	stmf_ic_scsi_cmd_msg_t *m = (stmf_ic_scsi_cmd_msg_t *)msg;
	int rc = 0;

	NVLIST_ADD_FIELD(uint64, m, icsc_task_msgid);
	NVLIST_ADD_DEVID(m, icsc_ini_devid);
	NVLIST_ADD_DEVID(m, icsc_tgt_devid);
	NVLIST_ADD_RPORT(m, icsc_rport);
	NVLIST_ADD_ARRAY(uint8, m, icsc_lun_id);
	NVLIST_ADD_FIELD(uint64, m, icsc_session_id);
	NVLIST_ADD_ARRAY_LEN(uint8, m, icsc_task_lun_no, 8);
	NVLIST_ADD_FIELD(uint32, m, icsc_task_expected_xfer_length);
	NVLIST_ADD_FIELD(uint16, m, icsc_task_cdb_length);
	/*
	 * icsc_task_cdb_length may be zero in the case of a task
	 * management function.
	 */
	NVLIST_ADD_ARRAY_LEN(uint8, m, icsc_task_cdb, m->icsc_task_cdb_length);
	NVLIST_ADD_FIELD(uint8, m, icsc_task_flags);
	NVLIST_ADD_FIELD(uint8, m, icsc_task_priority);
	NVLIST_ADD_FIELD(uint8, m, icsc_task_mgmt_function);

	NVLIST_ADD_FIELD(uint32, m, icsc_immed_data_len);
	/* only add immediate data if necessary */
	if (m->icsc_immed_data_len) {
		NVLIST_ADD_ARRAY_LEN(uint8, m, icsc_immed_data,
		    m->icsc_immed_data_len);
	}

done:
	return (rc);
}

static int
stmf_ic_scsi_data_msg_marshal(nvlist_t *nvl, void *msg)
{
	stmf_ic_scsi_data_msg_t *m = (stmf_ic_scsi_data_msg_t *)msg;
	int rc = 0;

	NVLIST_ADD_FIELD(uint64, m, icsd_task_msgid);
	NVLIST_ADD_FIELD(uint64, m, icsd_session_id);
	NVLIST_ADD_ARRAY(uint8, m, icsd_lun_id);
	NVLIST_ADD_FIELD(uint64, m, icsd_data_len);
	NVLIST_ADD_ARRAY_LEN(uint8, m, icsd_data, m->icsd_data_len);

done:
	return (rc);
}

static int
stmf_ic_scsi_data_xfer_done_msg_marshal(nvlist_t *nvl, void *msg)
{
	stmf_ic_scsi_data_xfer_done_msg_t *m =
	    (stmf_ic_scsi_data_xfer_done_msg_t *)msg;
	int rc = 0;

	NVLIST_ADD_FIELD(uint64, m, icsx_task_msgid);
	NVLIST_ADD_FIELD(uint64, m, icsx_session_id);
	NVLIST_ADD_FIELD(uint64, m, icsx_status);

done:
	return (rc);
}

static int
stmf_ic_scsi_status_msg_marshal(nvlist_t *nvl, void *msg)
{
	stmf_ic_scsi_status_msg_t *m = (stmf_ic_scsi_status_msg_t *)msg;
	int rc = 0;

	NVLIST_ADD_FIELD(uint64, m, icss_task_msgid);
	NVLIST_ADD_FIELD(uint64, m, icss_session_id);
	NVLIST_ADD_ARRAY(uint8, m, icss_lun_id);
	NVLIST_ADD_FIELD(uint8, m, icss_response);
	NVLIST_ADD_FIELD(uint8, m, icss_status);
	NVLIST_ADD_FIELD(uint8, m, icss_flags);
	NVLIST_ADD_FIELD(uint32, m, icss_resid);

	NVLIST_ADD_FIELD(uint8, m, icss_sense_len);

	if (m->icss_sense_len)
		NVLIST_ADD_ARRAY_LEN(uint8, m, icss_sense, m->icss_sense_len);

done:
	return (rc);
}

static int
stmf_ic_r2t_msg_marshal(nvlist_t *nvl, void *msg)
{
	stmf_ic_r2t_msg_t *m = (stmf_ic_r2t_msg_t *)msg;
	int rc = 0;

	NVLIST_ADD_FIELD(uint64, m, icrt_task_msgid);
	NVLIST_ADD_FIELD(uint64, m, icrt_session_id);
	NVLIST_ADD_FIELD(uint32, m, icrt_offset);
	NVLIST_ADD_FIELD(uint32, m, icrt_length);

done:
	return (rc);
}

static int
stmf_ic_status_msg_marshal(nvlist_t *nvl, void *msg)
{
	stmf_ic_status_msg_t *m = (stmf_ic_status_msg_t *)msg;
	int rc = 0;

	NVLIST_ADD_FIELD(uint8, m, ics_msg_type);
	NVLIST_ADD_FIELD(uint64, m, ics_msgid);
	NVLIST_ADD_FIELD(uint8, m, ics_status);

done:
	return (rc);
}

static int
stmf_ic_session_create_destroy_msg_marshal(nvlist_t *nvl, void *msg)
{
	stmf_ic_session_create_destroy_msg_t *m =
	    (stmf_ic_session_create_destroy_msg_t *)msg;
	int rc = 0;

	NVLIST_ADD_DEVID(m, icscd_ini_devid);
	NVLIST_ADD_DEVID(m, icscd_tgt_devid);
	NVLIST_ADD_RPORT(m, icscd_rport);
	NVLIST_ADD_FIELD(uint64, m, icscd_session_id);

done:
	return (rc);
}

static int
stmf_ic_echo_request_reply_msg_marshal(nvlist_t *nvl, void *msg)
{
	stmf_ic_echo_request_reply_msg_t *m = msg;
	int rc = 0;

	NVLIST_ADD_FIELD(uint32, m, icerr_datalen);
	if (m->icerr_datalen)
		NVLIST_ADD_ARRAY_LEN(uint8, m, icerr_data, m->icerr_datalen);

done:
	return (rc);
}

/*
 * Allocate a new nvlist representing the scsi_devid_desc and add it
 * to the nvlist.
 */
static int
stmf_ic_scsi_devid_desc_marshal(nvlist_t *parent_nvl,
	char *sdid_name,
	scsi_devid_desc_t *sdid)
{
	int rc = 0;
	nvlist_t *nvl = NULL;

	rc = nvlist_alloc(&nvl, NV_UNIQUE_NAME, KM_SLEEP);
	if (rc)
		goto done;

	NVLIST_ADD_FIELD(uint8, sdid, protocol_id);
	NVLIST_ADD_FIELD(uint8, sdid, code_set);
	NVLIST_ADD_FIELD(uint8, sdid, piv);
	NVLIST_ADD_FIELD(uint8, sdid, association);
	NVLIST_ADD_FIELD(uint8, sdid, ident_type);
	NVLIST_ADD_FIELD(uint8, sdid, ident_length);

	rc = nvlist_add_uint8_array(nvl, "ident", sdid->ident,
	    sdid->ident_length);
	if (rc)
		goto done;

	rc = nvlist_add_nvlist(parent_nvl, sdid_name, nvl);
done:
	if (nvl) {
		nvlist_free(nvl);
	}
	return (rc);
}

/*
 * Allocate a new nvlist representing the stmf_remote_port and add it
 * to the nvlist.
 */
static int
stmf_ic_remote_port_marshal(nvlist_t *parent_nvl, char *rport_name,
	stmf_remote_port_t *rport) {

	int rc = 0;
	nvlist_t *nvl = NULL;

	rc = nvlist_alloc(&nvl, NV_UNIQUE_NAME, KM_SLEEP);
	if (rc)
		goto done;

	NVLIST_ADD_FIELD(uint16, rport, rport_tptid_sz);
	rc = nvlist_add_uint8_array(nvl, "rport_tptid",
	    (uint8_t *)rport->rport_tptid, rport->rport_tptid_sz);
	if (rc)
		goto done;

	rc = nvlist_add_nvlist(parent_nvl, rport_name, nvl);
done:
	if (nvl) {
		nvlist_free(nvl);
	}
	return (rc);
}

/*
 * Unmarshaling routines.
 */

static stmf_ic_msg_t *
stmf_ic_msg_unmarshal(nvlist_t *nvl)
{
	stmf_ic_msg_t *m = kmem_zalloc(sizeof (*m), KM_SLEEP);
	uint8_t msg_type;
	int rc = 0;

	/*
	 * We'd like to do this:
	 *
	 *   NVLIST_LOOKUP_FIELD(uint8, m, icm_msg_type);
	 *
	 * but the fact that msg type is an enum causes type problems.
	 */
	rc = nvlist_lookup_uint8(nvl, "icm_msg_type", &msg_type);
	if (rc) {
		stmf_ic_nvlookup_warn(__func__, "icm_msg_type");
		goto done;
	}

	m->icm_msg_type = msg_type;
	m->icm_nvlist = nvl;

	NVLIST_LOOKUP_FIELD(uint64, m, icm_msgid);

	switch (m->icm_msg_type) {

	case STMF_ICM_REGISTER_PROXY_PORT:
		m->icm_msg = stmf_ic_reg_port_msg_unmarshal(nvl);
		break;


	case STMF_ICM_DEREGISTER_PROXY_PORT:
		m->icm_msg = stmf_ic_dereg_port_msg_unmarshal(nvl);
		break;

	case STMF_ICM_LUN_ACTIVE:
	case STMF_ICM_REGISTER_LUN:
	case STMF_ICM_DEREGISTER_LUN:
		m->icm_msg = stmf_ic_reg_dereg_lun_msg_unmarshal(nvl);
		break;

	case STMF_ICM_SCSI_CMD:
		m->icm_msg = stmf_ic_scsi_cmd_msg_unmarshal(nvl);
		break;

	case STMF_ICM_SCSI_DATA:
		m->icm_msg = stmf_ic_scsi_data_msg_unmarshal(nvl);
		break;

	case STMF_ICM_SCSI_DATA_XFER_DONE:
		m->icm_msg = stmf_ic_scsi_data_xfer_done_msg_unmarshal(nvl);
		break;

	case STMF_ICM_SCSI_STATUS:
		m->icm_msg = stmf_ic_scsi_status_msg_unmarshal(nvl);
		break;

	case STMF_ICM_R2T:
		m->icm_msg = stmf_ic_r2t_msg_unmarshal(nvl);
		break;

	case STMF_ICM_STATUS:
		m->icm_msg = stmf_ic_status_msg_unmarshal(nvl);
		break;

	case STMF_ICM_SESSION_CREATE:
	case STMF_ICM_SESSION_DESTROY:
		m->icm_msg = stmf_ic_session_create_destroy_msg_unmarshal(nvl);
		break;

	case STMF_ICM_ECHO_REQUEST:
	case STMF_ICM_ECHO_REPLY:
		m->icm_msg = stmf_ic_echo_request_reply_msg_unmarshal(nvl);
		break;

	case STMF_ICM_MAX_MSG_TYPE:
		ASSERT(0);
		break;

	default:
		ASSERT(0);
	}

done:

	if (!m->icm_msg) {
		kmem_free(m, sizeof (*m));
		return (NULL);
	}

	return (m);
}

static void *
stmf_ic_reg_port_msg_unmarshal(nvlist_t *nvl)
{
	nvlist_t *nvl_port_id = NULL;
	int rc = 0;
	stmf_ic_reg_port_msg_t *m = kmem_zalloc(sizeof (*m), KM_SLEEP);

	rc = nvlist_lookup_nvlist(nvl, "icrp_port_id", &nvl_port_id);
	if (rc) {
		stmf_ic_nvlookup_warn(__func__, "icrp_port_id nvl");
		rc = ENOMEM; /* XXX */
		goto done;
	}

	m->icrp_port_id = stmf_ic_scsi_devid_desc_unmarshal(nvl_port_id);
	if (m->icrp_port_id == NULL) {
		stmf_ic_nvlookup_warn(__func__, "icrp_port_id");
		rc = ENOMEM; /* XXX */
		goto done;
	}

	NVLIST_LOOKUP_FIELD(uint16, m, icrp_relative_port_id);
	NVLIST_LOOKUP_FIELD(uint16, m, icrp_cb_arg_len);

	if (m->icrp_cb_arg_len) {
		m->icrp_cb_arg = stmf_ic_uint8_array_unmarshal(nvl,
		    "icrp_cb_arg", m->icrp_cb_arg_len, NULL);
		if (m->icrp_cb_arg == NULL) {
			stmf_ic_nvlookup_warn(__func__, "icrp_cb_arg");
			rc = ENOMEM; /* XXX */
			goto done;
		}
	}

done:
	if (!rc)
		return (m);

	stmf_ic_reg_port_msg_free(m, STMF_UNMARSHAL);

	return (NULL);
}

/*
 * XXX largely the same as stmf_ic_reg_port_msg_unmarshal()
 * Common stuff should be factored out.  Type issues may make this
 * painful.
 */
static void *
stmf_ic_dereg_port_msg_unmarshal(nvlist_t *nvl)
{
	nvlist_t *nvl_port_id = NULL;
	int rc = 0;
	stmf_ic_dereg_port_msg_t *m = kmem_zalloc(sizeof (*m), KM_SLEEP);

	rc = nvlist_lookup_nvlist(nvl, "icdp_port_id", &nvl_port_id);
	if (rc) {
		stmf_ic_nvlookup_warn(__func__, "icdp_port_id nvl");
		goto done;
	}

	m->icdp_port_id = stmf_ic_scsi_devid_desc_unmarshal(nvl_port_id);
	if (m->icdp_port_id == NULL) {
		stmf_ic_nvlookup_warn(__func__, "icdp_port_id");
		rc = ENOMEM; /* XXX */
		goto done;
	}

	NVLIST_LOOKUP_FIELD(uint16, m, icdp_cb_arg_len);

	if (m->icdp_cb_arg_len) {
		m->icdp_cb_arg = stmf_ic_uint8_array_unmarshal(nvl,
		    "icdp_cb_arg", m->icdp_cb_arg_len, NULL);
		if (m->icdp_cb_arg == NULL) {
			stmf_ic_nvlookup_warn(__func__, "icdp_cb_arg");
			rc = ENOMEM; /* XXX */
			goto done;
		}
	}

done:
	if (!rc)
		return (m);

	stmf_ic_dereg_port_msg_free(m, STMF_UNMARSHAL);

	return (NULL);
}

static void *
stmf_ic_reg_dereg_lun_msg_unmarshal(nvlist_t *nvl)
{
	int rc = 0;
	stmf_ic_reg_dereg_lun_msg_t *m = kmem_zalloc(sizeof (*m), KM_SLEEP);

	if (! stmf_ic_uint8_array_unmarshal(nvl, "icrl_lun_id",
	    sizeof (m->icrl_lun_id), m->icrl_lun_id)) {
		stmf_ic_nvlookup_warn(__func__, "icrl_lun_id");
		rc = ENOMEM; /* XXX */
		goto done;
	}

	m->icrl_lu_provider_name = stmf_ic_string_unmarshal(nvl,
	    "icrl_lu_provider_name");

	if (!m->icrl_lu_provider_name) {
		stmf_ic_nvlookup_warn(__func__, "icrl_lu_provider_name");
		rc = ENOMEM; /* XXX */
		goto done;
	}

	NVLIST_LOOKUP_FIELD(uint16, m, icrl_cb_arg_len);

	if (m->icrl_cb_arg_len) {
		m->icrl_cb_arg = stmf_ic_uint8_array_unmarshal(nvl,
		    "icrl_cb_arg", m->icrl_cb_arg_len, NULL);
		if (m->icrl_cb_arg == NULL) {
			stmf_ic_nvlookup_warn(__func__, "icrl_cb_arg");
			rc = ENOMEM; /* XXX */
			goto done;
		}
	}

done:
	if (!rc)
		return (m);

	stmf_ic_reg_dereg_lun_msg_free(m, STMF_UNMARSHAL);

	return (NULL);
}

static void *
stmf_ic_scsi_cmd_msg_unmarshal(nvlist_t *nvl)
{
	int rc = 0;
	stmf_ic_scsi_cmd_msg_t *m = kmem_zalloc(sizeof (*m), KM_SLEEP);

	if (nvlist_lookup_pairs(nvl, 0,
	    NV_PAIR(UINT64, m, icsc_task_msgid),
	    NV_PAIR(UINT64, m, icsc_session_id),
	    NV_PAIR(UINT32, m, icsc_task_expected_xfer_length),
	    NV_PAIR(UINT16, m, icsc_task_cdb_length),
	    NV_PAIR(UINT8, m, icsc_task_flags),
	    NV_PAIR(UINT8, m, icsc_task_mgmt_function),
	    NV_PAIR(UINT32, m, icsc_immed_data_len),
	    NULL) != 0) {
		stmf_ic_nvlookup_warn(__func__, "icsc_task_msgid and friends");
		rc = ENOMEM; /* XXX need something better */
		goto done;
	}

	m->icsc_ini_devid = stmf_ic_lookup_scsi_devid_desc_and_unmarshal(
	    nvl, "icsc_ini_devid");
	if (m->icsc_ini_devid == NULL) {
		stmf_ic_nvlookup_warn(__func__, "icsc_ini_devid");
		rc = ENOMEM;
		goto done;
	}

	m->icsc_tgt_devid = stmf_ic_lookup_scsi_devid_desc_and_unmarshal(
	    nvl, "icsc_tgt_devid");
	if (m->icsc_tgt_devid == NULL) {
		stmf_ic_nvlookup_warn(__func__, "icsc_tgt_devid");
		rc = ENOMEM;
		goto done;
	}

	m->icsc_rport = stmf_ic_lookup_remote_port_and_unmarshal(
	    nvl, "icsc_rport");
	if (m->icsc_rport == NULL) {
		stmf_ic_nvlookup_warn(__func__, "icsc_rport");
		rc = ENOMEM;
		goto done;
	}

	/* icsc_lun_id */
	if (!stmf_ic_uint8_array_unmarshal(nvl, "icsc_lun_id",
	    sizeof (m->icsc_lun_id), m->icsc_lun_id)) {
		stmf_ic_nvlookup_warn(__func__, "icsc_lun_id");
		rc = ENOMEM;
		goto done;
	}

	/* icsc_task_lun_no */
	if (!stmf_ic_uint8_array_unmarshal(nvl, "icsc_task_lun_no",
	    sizeof (m->icsc_task_lun_no), m->icsc_task_lun_no)) {
		stmf_ic_nvlookup_warn(__func__, "icsc_task_lun_no");
		rc = ENOMEM;
		goto done;
	}

	/* icsc_task_cdb */
	if (m->icsc_task_cdb_length) {
		m->icsc_task_cdb = stmf_ic_uint8_array_unmarshal(nvl,
		    "icsc_task_cdb", m->icsc_task_cdb_length, NULL);
		if (!m->icsc_task_cdb) {
			stmf_ic_nvlookup_warn(__func__, "icsc_task_cdb");
			rc = ENOMEM;
			goto done;
		}
	}

	/* immediate data, if there is any */
	if (m->icsc_immed_data_len) {
		m->icsc_immed_data = stmf_ic_uint8_array_unmarshal(nvl,
		    "icsc_immed_data", m->icsc_immed_data_len, NULL);
		if (!m->icsc_immed_data) {
			stmf_ic_nvlookup_warn(__func__, "icsc_immed_data");
			rc = ENOMEM;
			goto done;
		}
	}

done:
	if (!rc)
		return (m);

	stmf_ic_scsi_cmd_msg_free(m, STMF_UNMARSHAL);

	return (NULL);
}

static void *
stmf_ic_scsi_data_msg_unmarshal(nvlist_t *nvl)
{
	int rc = 0;
	stmf_ic_scsi_data_msg_t *m = kmem_zalloc(sizeof (*m), KM_SLEEP);

	if (nvlist_lookup_pairs(nvl, 0,
	    NV_PAIR(UINT64, m, icsd_task_msgid),
	    NV_PAIR(UINT64, m, icsd_session_id),
	    NV_PAIR(UINT64, m, icsd_data_len),
	    NULL) != 0) {
		stmf_ic_nvlookup_warn(__func__, "icsd_task_msgid and friends");
		rc = ENOMEM; /* XXX need something better */
		goto done;
	}

	if (!stmf_ic_uint8_array_unmarshal(nvl, "icsd_lun_id",
	    sizeof (m->icsd_lun_id), m->icsd_lun_id)) {
		stmf_ic_nvlookup_warn(__func__, "icsd_lun_id");
		rc = ENOMEM;
		goto done;
	}

	m->icsd_data = stmf_ic_uint8_array_unmarshal(nvl, "icsd_data",
	    m->icsd_data_len, NULL);
	if (!m->icsd_data) {
		stmf_ic_nvlookup_warn(__func__, "icsd_data");
		rc = ENOMEM;
		goto done;
	}

done:
	if (!rc)
		return (m);

	stmf_ic_scsi_data_msg_free(m, STMF_UNMARSHAL);

	return (NULL);
}

static void *
stmf_ic_scsi_data_xfer_done_msg_unmarshal(nvlist_t *nvl)
{
	int rc = 0;
	stmf_ic_scsi_data_xfer_done_msg_t *m =
	    kmem_zalloc(sizeof (*m), KM_SLEEP);

	if (nvlist_lookup_pairs(nvl, 0,
	    NV_PAIR(UINT64, m, icsx_task_msgid),
	    NV_PAIR(UINT64, m, icsx_session_id),
	    NV_PAIR(UINT64, m, icsx_status),
	    NULL) != 0) {
		stmf_ic_nvlookup_warn(__func__, "icsx_task_msgid and friends");
		rc = ENOMEM; /* XXX need something better */
		goto done;
	}

done:
	if (!rc)
		return (m);

	stmf_ic_scsi_data_xfer_done_msg_free(m, STMF_UNMARSHAL);

	return (NULL);
}

static void *
stmf_ic_scsi_status_msg_unmarshal(nvlist_t *nvl)
{
	int rc = 0;
	stmf_ic_scsi_status_msg_t *m = kmem_zalloc(sizeof (*m), KM_SLEEP);

	if (nvlist_lookup_pairs(nvl, 0,
	    NV_PAIR(UINT64, m, icss_task_msgid),
	    NV_PAIR(UINT64, m, icss_session_id),
	    NV_PAIR(UINT8, m, icss_response),
	    NV_PAIR(UINT8, m, icss_status),
	    NV_PAIR(UINT8, m, icss_flags),
	    NV_PAIR(UINT32, m, icss_resid),
	    NV_PAIR(UINT8, m, icss_sense_len),
	    NULL) != 0) {
		stmf_ic_nvlookup_warn(__func__, "icss_task_msgid and friends");
		rc = ENOMEM; /* XXX need something better */
		goto done;
	}

	if (!stmf_ic_uint8_array_unmarshal(nvl, "icss_lun_id",
	    sizeof (m->icss_lun_id), m->icss_lun_id)) {
		stmf_ic_nvlookup_warn(__func__, "icss_lun_id");
		rc = ENOMEM;
		goto done;
	}

	if (m->icss_sense_len) {
		m->icss_sense = stmf_ic_uint8_array_unmarshal(nvl, "icss_sense",
		    m->icss_sense_len, NULL);
		if (!m->icss_sense) {
			stmf_ic_nvlookup_warn(__func__, "icss_sense");
			rc = ENOMEM;
			goto done;
		}
	}
done:
	if (!rc)
		return (m);

	stmf_ic_scsi_status_msg_free(m, STMF_UNMARSHAL);

	return (NULL);
}

static void *
stmf_ic_r2t_msg_unmarshal(nvlist_t *nvl)
{
	int rc = 0;
	stmf_ic_r2t_msg_t *m = kmem_zalloc(sizeof (*m), KM_SLEEP);

	if (nvlist_lookup_pairs(nvl, 0,
	    NV_PAIR(UINT64, m, icrt_task_msgid),
	    NV_PAIR(UINT64, m, icrt_session_id),
	    NV_PAIR(UINT32, m, icrt_offset),
	    NV_PAIR(UINT32, m, icrt_length),
	    NULL) != 0) {
		stmf_ic_nvlookup_warn(__func__, "icrt_task_msgid and friends");
		rc = ENOMEM; /* XXX need something better */
		goto done;
	}

done:
	if (!rc)
		return (m);

	stmf_ic_r2t_msg_free(m, STMF_UNMARSHAL);

	return (NULL);
}

static void *
stmf_ic_session_create_destroy_msg_unmarshal(nvlist_t *nvl)
{
	int rc = 0;
	stmf_ic_session_create_destroy_msg_t *m = kmem_zalloc(sizeof (*m),
	    KM_SLEEP);

	if (nvlist_lookup_pairs(nvl, 0,
	    NV_PAIR(UINT64, m, icscd_session_id),
	    NULL) != 0) {
		stmf_ic_nvlookup_warn(__func__, "icsd_session_id");
		rc = ENOMEM; /* XXX need something better */
		goto done;
	}

	m->icscd_ini_devid = stmf_ic_lookup_scsi_devid_desc_and_unmarshal(
	    nvl, "icscd_ini_devid");
	if (m->icscd_ini_devid == NULL) {
		stmf_ic_nvlookup_warn(__func__, "icsd_ini_devid");
		rc = ENOMEM;
		goto done;
	}

	m->icscd_tgt_devid = stmf_ic_lookup_scsi_devid_desc_and_unmarshal(
	    nvl, "icscd_tgt_devid");
	if (m->icscd_tgt_devid == NULL) {
		stmf_ic_nvlookup_warn(__func__, "icsd_tgt_devid");
		rc = ENOMEM;
		goto done;
	}

	m->icscd_rport = stmf_ic_lookup_remote_port_and_unmarshal(
	    nvl, "icscd_rport");
	if (m->icscd_rport == NULL) {
		stmf_ic_nvlookup_warn(__func__, "icscd_rport");
		rc = ENOMEM;
		goto done;
	}

done:
	if (!rc)
		return (m);

	stmf_ic_session_create_destroy_msg_free(m, STMF_UNMARSHAL);

	return (NULL);
}

static void *
stmf_ic_echo_request_reply_msg_unmarshal(nvlist_t *nvl)
{
	int rc = 0;
	stmf_ic_echo_request_reply_msg_t *m = kmem_zalloc(sizeof (*m),
	    KM_SLEEP);

	if (nvlist_lookup_pairs(nvl, 0,
	    NV_PAIR(UINT32, m, icerr_datalen),
	    NULL) != 0) {
		stmf_ic_nvlookup_warn(__func__, "icerr_datalen");
		rc = ENOMEM; /* XXX need something better */
		goto done;
	}

	/* immediate data, if there is any */
	if (m->icerr_datalen) {
		m->icerr_data = stmf_ic_uint8_array_unmarshal(nvl,
		    "icerr_data", m->icerr_datalen, NULL);
		if (!m->icerr_data) {
			stmf_ic_nvlookup_warn(__func__, "icerr_data");
			rc = ENOMEM;
			goto done;
		}
	}

done:
	if (!rc)
		return (m);

	stmf_ic_echo_request_reply_msg_free(m, STMF_UNMARSHAL);

	return (NULL);
}

static void *
stmf_ic_status_msg_unmarshal(nvlist_t *nvl)
{
	int rc = 0;
	stmf_ic_status_msg_t *m = kmem_zalloc(sizeof (*m), KM_SLEEP);

	if (nvlist_lookup_pairs(nvl, 0,
	    NV_PAIR(UINT8, m, ics_msg_type),
	    NV_PAIR(UINT64, m, ics_msgid),
	    NV_PAIR(UINT8, m, ics_status),
	    NULL) != 0) {
		stmf_ic_nvlookup_warn(__func__, "ics_msg_type and friends");
		rc = ENOMEM; /* XXX need something better */
		goto done;
	}

done:
	if (!rc)
		return (m);

	kmem_free(m, sizeof (*m));
	return (NULL);
}


static scsi_devid_desc_t *
stmf_ic_lookup_scsi_devid_desc_and_unmarshal(nvlist_t *nvl, char *field_name)
{
	nvlist_t *nvl_devid = NULL;
	scsi_devid_desc_t *did = NULL;
	int rc;

	rc = nvlist_lookup_nvlist(nvl, field_name, &nvl_devid);
	if (rc) {
		goto done;
	}

	did = stmf_ic_scsi_devid_desc_unmarshal(nvl_devid);

done:
	return (did);
}


static scsi_devid_desc_t *
stmf_ic_scsi_devid_desc_unmarshal(nvlist_t *nvl)
{
	scsi_devid_desc_t *sdid = NULL;
	uint8_t ident_length = 0;
	size_t sdid_size;
	int rc = 0;

	/*
	 * we get the ident_length first, since that's the only
	 * variable-sized field in the struct.
	 */
	rc = nvlist_lookup_uint8(nvl, "ident_length", &ident_length);
	if (rc)
		goto done;

	sdid_size = sizeof_scsi_devid_desc(ident_length);
	sdid = kmem_zalloc(sdid_size, KM_SLEEP);

	NVLIST_LOOKUP_BIT_FIELD(uint8, sdid, protocol_id);
	NVLIST_LOOKUP_BIT_FIELD(uint8, sdid, code_set);
	NVLIST_LOOKUP_BIT_FIELD(uint8, sdid, piv);
	NVLIST_LOOKUP_BIT_FIELD(uint8, sdid, association);
	NVLIST_LOOKUP_BIT_FIELD(uint8, sdid, ident_type);

	sdid->ident_length = ident_length;

	if (!stmf_ic_uint8_array_unmarshal(nvl, "ident",
	    sdid->ident_length, sdid->ident)) {
		rc = ENOMEM; /* XXX */
		goto done;
	}

done:
	if (!rc)
		return (sdid);

	kmem_free(sdid, sdid_size);

	return (NULL);
}

static stmf_remote_port_t *
stmf_ic_lookup_remote_port_and_unmarshal(nvlist_t *nvl, char *field_name)
{
	nvlist_t *nvl_rport = NULL;

	if (nvlist_lookup_nvlist(nvl, field_name, &nvl_rport) != 0)
		return (NULL);

	return (stmf_ic_remote_port_unmarshal(nvl_rport));
}

static stmf_remote_port_t *
stmf_ic_remote_port_unmarshal(nvlist_t *nvl)
{
	stmf_remote_port_t *rport = NULL;
	uint16_t rport_tptid_sz = 0;
	int rc = 0;

	rc = nvlist_lookup_uint16(nvl, "rport_tptid_sz", &rport_tptid_sz);
	if (rc || rport_tptid_sz < sizeof (scsi_transport_id_t))
		return (NULL);

	rport = stmf_remote_port_alloc(rport_tptid_sz);
	if (!stmf_ic_uint8_array_unmarshal(nvl, "rport_tptid", rport_tptid_sz,
	    (uint8_t *)rport->rport_tptid)) {
		stmf_remote_port_free(rport);
		rport = NULL;
	}
	return (rport);
}

/*
 * Unmarshal a uint8_t array.
 *
 * Takes a buf argument:
 *
 * - if non-null, the array contents are copied into the buf,
 *   and we return a pointer to the buffer.
 *
 * - if null, we return a pointer to the unmarshaled data, which
 *   resides in the nvlist.
 *
 * Returns NULL on failure.
 */
static uint8_t *
stmf_ic_uint8_array_unmarshal(
    nvlist_t *nvl,
    char *field_name,
    uint64_t len,
    uint8_t *buf)	/* non-NULL: copy array into buf */
{
	uint8_t *array = NULL;
	uint_t actual_len;
	int rc = 0;

	rc = nvlist_lookup_uint8_array(nvl, field_name, &array, &actual_len);
	if (rc) {
		return (NULL);
	}

	if (len != actual_len) {
		cmn_err(CE_WARN,
		    "stmf_ic_uint8_array_unmarshal: wrong len (%d != %d)",
		    (int)len, actual_len);
		return (NULL);
	}

	if (buf) {
		/* preallocated buf, copy in */
		bcopy(array, buf, len);
	} else {
		/* return a pointer to the underlying array in the nvlist */
		buf = array;
	}

	return (buf);
}

/*
 * Unmarshal a string.
 *
 * Returns NULL on failure.
 */
static char *
stmf_ic_string_unmarshal(
    nvlist_t *nvl,
    char *field_name)
{
	char *s = NULL;
	int rc = 0;

	rc = nvlist_lookup_string(nvl, field_name, &s);
	if (rc) {
		return (NULL);
	}

	return (s);
}

/*
 * Utility routines.
 */

static stmf_ic_msg_t *
stmf_ic_alloc_msg_header(
    stmf_ic_msg_type_t msg_type,
    stmf_ic_msgid_t msgid)
{
	stmf_ic_msg_t *icm;

	icm = (stmf_ic_msg_t *)kmem_zalloc(sizeof (*icm), KM_SLEEP);
	icm->icm_msg_type = msg_type;
	icm->icm_msgid = msgid;

	return (icm);
}

static size_t
sizeof_scsi_devid_desc(int ident_length)
{
	int num_ident_elems;
	size_t size;

	ASSERT(ident_length > 0);

	/*
	 * Need to account for the fact that there's
	 * already a single element in scsi_devid_desc_t.
	 *
	 * XXX would really like to have a way to determine the
	 * sizeof (struct scsi_devid_desc.ident[0]), but
	 * it's not clear that can be done.
	 * Thus, this code relies on the knowledge of the type of
	 * that field.
	 */
	num_ident_elems = ident_length - 1;
	size = sizeof (scsi_devid_desc_t) +
	    (num_ident_elems * sizeof (uint8_t));

	return (size);
}


/*
 * Duplicate the scsi_devid_desc_t.
 */
static scsi_devid_desc_t *
scsi_devid_desc_dup(scsi_devid_desc_t *did)
{
	scsi_devid_desc_t *dup;
	size_t dup_size;

	ASSERT(did->ident_length > 0);

	dup_size = sizeof_scsi_devid_desc(did->ident_length);
	dup = (scsi_devid_desc_t *)kmem_zalloc(dup_size, KM_SLEEP);
	bcopy(did, dup, dup_size);
	return (dup);
}

/*
 * May be called with a null pointer.
 */
static void
scsi_devid_desc_free(scsi_devid_desc_t *did)
{
	if (!did)
		return;

	kmem_free(did, sizeof_scsi_devid_desc(did->ident_length));
}

/*
 * Duplicate the stmf_remote_port_t.
 */
static stmf_remote_port_t *
remote_port_dup(stmf_remote_port_t *rport)
{
	stmf_remote_port_t *dup = NULL;
	if (rport) {
		dup = stmf_remote_port_alloc(rport->rport_tptid_sz);
		bcopy(rport->rport_tptid, dup->rport_tptid,
		    rport->rport_tptid_sz);
	}
	return (dup);
}

/*
 * Helper functions, returns NULL if no memory.
 */
static char *
stmf_ic_strdup(char *str)
{
	char *copy;

	ASSERT(str);

	copy = kmem_zalloc(strlen(str) + 1, KM_SLEEP);
	(void) strcpy(copy, str);
	return (copy);
}

static inline void
stmf_ic_nvlookup_warn(const char *func, char *field)
{
	cmn_err(CE_WARN, "%s: nvlist lookup of %s failed", func, field);
}
