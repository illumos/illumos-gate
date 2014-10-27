/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at
 * http://www.opensource.org/licenses/cddl1.txt.
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
 * Copyright (c) 2004-2012 Emulex. All rights reserved.
 * Use is subject to license terms.
 */

#include <emlxs.h>

#ifdef DUMP_SUPPORT

/* Required for EMLXS_CONTEXT in EMLXS_MSGF calls */
EMLXS_MSG_DEF(EMLXS_DUMP_C);

/* ************************************************************************* */
/* Utility functions */
/* ************************************************************************* */

static uint32_t
emlxs_menlo_set_mode(
	emlxs_hba_t *hba,
	uint32_t mode)
{
	emlxs_port_t *port = &PPORT;
	uint32_t cmd_size;
	uint32_t rsp_size;
	menlo_cmd_t *cmd_buf = NULL;
	menlo_rsp_t *rsp_buf = NULL;
	uint32_t rval = 0;

	if (hba->model_info.device_id != PCI_DEVICE_ID_HORNET) {
		return (DFC_INVALID_ADAPTER);
	}

	cmd_size = sizeof (menlo_set_cmd_t);
	cmd_buf = (menlo_cmd_t *)kmem_zalloc(cmd_size, KM_SLEEP);

	rsp_size = 4;
	rsp_buf = (menlo_rsp_t *)kmem_zalloc(rsp_size, KM_SLEEP);

	cmd_buf->code = MENLO_CMD_SET_MODE;
	cmd_buf->set.value1 = mode;
	cmd_buf->set.value2 = 0;

#ifdef EMLXS_BIG_ENDIAN
	emlxs_swap32_buffer((uint8_t *)cmd_buf, cmd_size);
#endif /* EMLXS_BIG_ENDIAN */

	if (rval = emlxs_send_menlo_cmd(hba, (uint8_t *)cmd_buf, cmd_size,
	    (uint8_t *)rsp_buf, &rsp_size)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
		    "menlo_set_mode: Unable to send command.");
		goto done;
	}
#ifdef EMLXS_BIG_ENDIAN
	emlxs_swap32_buffer((uint8_t *)rsp_buf, rsp_size);
#endif /* EMLXS_BIG_ENDIAN */

	if (rsp_buf->code != 0) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
		    "menlo_set_mode: Menlo command error. code=%d.\n",
		    rsp_buf->code);
	}

	rval = rsp_buf->code;

done:

	if (cmd_buf) {
		kmem_free(cmd_buf, sizeof (menlo_set_cmd_t));
	}

	if (rsp_buf) {
		kmem_free(rsp_buf, 4);
	}

	return (rval);

} /* emlxs_menlo_set_mode() */


static uint32_t
emlxs_menlo_reset(
	emlxs_hba_t *hba,
	uint32_t firmware)
{
	emlxs_port_t *port = &PPORT;
	uint32_t cmd_size;
	uint32_t rsp_size;
	menlo_cmd_t *cmd_buf = NULL;
	menlo_rsp_t *rsp_buf = NULL;
	uint32_t rval = 0;

	if (hba->model_info.device_id != PCI_DEVICE_ID_HORNET) {
		return (DFC_INVALID_ADAPTER);
	}

	cmd_size = sizeof (menlo_reset_cmd_t);
	cmd_buf = (menlo_cmd_t *)kmem_zalloc(cmd_size, KM_SLEEP);

	rsp_size = 4;
	rsp_buf = (menlo_rsp_t *)kmem_zalloc(rsp_size, KM_SLEEP);

	cmd_buf->code = MENLO_CMD_RESET;
	cmd_buf->reset.firmware = firmware;

#ifdef EMLXS_BIG_ENDIAN
	emlxs_swap32_buffer((uint8_t *)cmd_buf, cmd_size);
#endif /* EMLXS_BIG_ENDIAN */

	if (rval = emlxs_send_menlo_cmd(hba, (uint8_t *)cmd_buf, cmd_size,
	    (uint8_t *)rsp_buf, &rsp_size)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
		    "menlo_reset: Unable to send command.");
		goto done;
	}
#ifdef EMLXS_BIG_ENDIAN
	emlxs_swap32_buffer((uint8_t *)rsp_buf, rsp_size);
#endif /* EMLXS_BIG_ENDIAN */

	if (rsp_buf->code != 0) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
		    "menlo_reset: Menlo command error. code=%d.\n",
		    rsp_buf->code);
	}

	rval = rsp_buf->code;

done:

	if (cmd_buf) {
		kmem_free(cmd_buf, sizeof (menlo_reset_cmd_t));
	}

	if (rsp_buf) {
		kmem_free(rsp_buf, 4);
	}

	return (rval);

} /* emlxs_menlo_reset() */


static uint32_t
emlxs_menlo_get_cfg(
	emlxs_hba_t *hba,
	menlo_get_config_rsp_t *rsp_buf,
	uint32_t rsp_size)
{
	emlxs_port_t *port = &PPORT;
	uint32_t cmd_size;
	menlo_cmd_t *cmd_buf = NULL;
	uint32_t rval = 0;

	if (hba->model_info.device_id != PCI_DEVICE_ID_HORNET) {
		return (DFC_INVALID_ADAPTER);
	}

	cmd_size = sizeof (menlo_get_cmd_t);
	cmd_buf = (menlo_cmd_t *)kmem_zalloc(cmd_size, KM_SLEEP);

	rsp_size = sizeof (menlo_get_config_rsp_t);

	cmd_buf->code = MENLO_CMD_GET_CONFIG;
	cmd_buf->get.context = 0;
	cmd_buf->get.length = rsp_size;

#ifdef EMLXS_BIG_ENDIAN
	emlxs_swap32_buffer((uint8_t *)cmd_buf, cmd_size);
#endif /* EMLXS_BIG_ENDIAN */

	if (rval = emlxs_send_menlo_cmd(hba, (uint8_t *)cmd_buf, cmd_size,
	    (uint8_t *)rsp_buf, &rsp_size)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
		    "menlo_get_cfg: Unable to send command.");
		goto done;
	}
#ifdef EMLXS_BIG_ENDIAN
	emlxs_swap32_buffer((uint8_t *)rsp_buf, rsp_size);
#endif /* EMLXS_BIG_ENDIAN */

	if (rsp_buf->code != 0) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
		    "menlo_get_cfg: Menlo command error. code=%d.\n",
		    rsp_buf->code);
	}

	rval = rsp_buf->code;

done:

	if (cmd_buf) {
		kmem_free(cmd_buf, sizeof (menlo_get_cmd_t));
	}

	return (rval);

} /* emlxs_menlo_get_cfg() */



static uint32_t
emlxs_menlo_get_logcfg(
	emlxs_hba_t *hba,
	menlo_rsp_t *rsp_buf,
	uint32_t rsp_size)
{
	emlxs_port_t *port = &PPORT;
	uint32_t cmd_size;
	menlo_cmd_t *cmd_buf = NULL;
	uint32_t rval = 0;

	if (hba->model_info.device_id != PCI_DEVICE_ID_HORNET) {
		return (DFC_INVALID_ADAPTER);
	}

	cmd_size = sizeof (menlo_get_cmd_t);
	cmd_buf = (menlo_cmd_t *)kmem_zalloc(cmd_size, KM_SLEEP);

	cmd_buf->code = MENLO_CMD_GET_LOG_CONFIG;
	cmd_buf->get.context = 0;
	cmd_buf->get.length = rsp_size;

#ifdef EMLXS_BIG_ENDIAN
	emlxs_swap32_buffer((uint8_t *)cmd_buf, cmd_size);
#endif /* EMLXS_BIG_ENDIAN */

	if (rval = emlxs_send_menlo_cmd(hba, (uint8_t *)cmd_buf, cmd_size,
	    (uint8_t *)rsp_buf, &rsp_size)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
		    "menlo_get_logcfg: Unable to send command.");
		goto done;
	}
#ifdef EMLXS_BIG_ENDIAN
	emlxs_swap32_buffer((uint8_t *)rsp_buf, rsp_size);
#endif /* EMLXS_BIG_ENDIAN */

	if (rsp_buf->code != 0) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
		    "menlo_get_logcfg: Menlo command error. code=%d.\n",
		    rsp_buf->code);
	}

	rval = rsp_buf->code;

done:

	if (cmd_buf) {
		kmem_free(cmd_buf, sizeof (menlo_get_cmd_t));
	}

	return (rval);

} /* emlxs_menlo_get_logcfg() */


static uint32_t
emlxs_menlo_get_log(
	emlxs_hba_t *hba,
	uint32_t id,
	menlo_rsp_t *rsp_buf,
	uint32_t rsp_size)
{
	emlxs_port_t *port = &PPORT;
	uint32_t cmd_size;
	menlo_cmd_t *cmd_buf = NULL;
	uint32_t rval = 0;

	if (hba->model_info.device_id != PCI_DEVICE_ID_HORNET) {
		return (DFC_INVALID_ADAPTER);
	}

	cmd_size = sizeof (menlo_get_cmd_t);
	cmd_buf = (menlo_cmd_t *)kmem_zalloc(cmd_size, KM_SLEEP);

	cmd_buf->code = MENLO_CMD_GET_LOG_DATA;
	cmd_buf->get.context = id;
	cmd_buf->get.length = rsp_size;

#ifdef EMLXS_BIG_ENDIAN
	emlxs_swap32_buffer((uint8_t *)cmd_buf, cmd_size);
#endif /* EMLXS_BIG_ENDIAN */

	if (rval = emlxs_send_menlo_cmd(hba, (uint8_t *)cmd_buf, cmd_size,
	    (uint8_t *)rsp_buf, &rsp_size)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
		    "menlo_get_log: Unable to send command.");
		goto done;
	}
#ifdef EMLXS_BIG_ENDIAN
	emlxs_swap32_buffer((uint8_t *)rsp_buf, rsp_size);
#endif /* EMLXS_BIG_ENDIAN */

	if (rsp_buf->code != 0) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
		    "menlo_get_log: Menlo command error. code=%d.\n",
		    rsp_buf->code);
	}

	rval = rsp_buf->code;

done:

	if (cmd_buf) {
		kmem_free(cmd_buf, sizeof (menlo_get_cmd_t));
	}

	return (rval);

} /* emlxs_menlo_get_log() */


static uint32_t
emlxs_menlo_get_paniclog(
	emlxs_hba_t *hba,
	menlo_rsp_t *rsp_buf,
	uint32_t rsp_size)
{
	emlxs_port_t *port = &PPORT;
	uint32_t cmd_size;
	menlo_cmd_t *cmd_buf = NULL;
	uint32_t rval = 0;

	if (hba->model_info.device_id != PCI_DEVICE_ID_HORNET) {
		return (DFC_INVALID_ADAPTER);
	}

	cmd_size = sizeof (menlo_get_cmd_t);
	cmd_buf = (menlo_cmd_t *)kmem_zalloc(cmd_size, KM_SLEEP);

	cmd_buf->code = MENLO_CMD_GET_PANIC_LOG;
	cmd_buf->get.context = 0;
	cmd_buf->get.length = rsp_size;

#ifdef EMLXS_BIG_ENDIAN
	emlxs_swap32_buffer((uint8_t *)cmd_buf, cmd_size);
#endif /* EMLXS_BIG_ENDIAN */

	if (rval = emlxs_send_menlo_cmd(hba, (uint8_t *)cmd_buf, cmd_size,
	    (uint8_t *)rsp_buf, &rsp_size)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
		    "menlo_get_paniclog: Unable to send command.");
		goto done;
	}
#ifdef EMLXS_BIG_ENDIAN
	emlxs_swap32_buffer((uint8_t *)rsp_buf, rsp_size);
#endif /* EMLXS_BIG_ENDIAN */

	if (rsp_buf->code != 0) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
		    "menlo_get_paniclog: Menlo command error. code=%d.\n",
		    rsp_buf->code);
	}

	rval = rsp_buf->code;

done:

	if (cmd_buf) {
		kmem_free(cmd_buf, sizeof (menlo_get_cmd_t));
	}

	return (rval);

} /* emlxs_menlo_get_paniclog() */




extern void
emlxs_fflush(
	emlxs_file_t *fp)
{
	uint32_t offset;

	offset = (uint32_t)((uintptr_t)fp->ptr - (uintptr_t)fp->buffer);

	if (offset > fp->size) {
		fp->ptr = fp->buffer + fp->size;
	}

	return;

} /* emlxs_fflush() */


extern uint32_t
emlxs_ftell(
	emlxs_file_t *fp)
{
	uint32_t offset;

	offset = (uint32_t)((uintptr_t)fp->ptr - (uintptr_t)fp->buffer);

	return (offset);

} /* emlxs_ftell() */


static void
emlxs_fputc(
	uint8_t value,
	emlxs_file_t *fp)
{
	uint32_t offset;

	offset = (uint32_t)((uintptr_t)fp->ptr - (uintptr_t)fp->buffer);

	if ((offset + 1) <= fp->size) {
		*fp->ptr++ = value;
	}

	return;

} /* emlxs_fputc() */


static uint32_t
emlxs_fwrite(
	uint8_t *buffer,
	uint32_t size,
	uint32_t nitems,
	emlxs_file_t *fp)
{
	uint32_t offset;
	uint32_t length;

	length = size * nitems;

	if (length) {
		offset =
		    (uint32_t)((uintptr_t)fp->ptr - (uintptr_t)fp->buffer);

		if ((offset + length) > fp->size) {
			length = fp->size - offset;
		}

		if (length) {
			bcopy(buffer, fp->ptr, length);
			fp->ptr += length;
		}
	}

	return (length);

} /* emlxs_fwrite() */


static uint32_t
emlxs_fprintf(
	emlxs_file_t *fp,
	const char *fmt, ...)
{
	va_list valist;
	char va_str[1024];
	uint32_t length;

	va_start(valist, fmt);
	(void) vsnprintf(va_str, sizeof (va_str), fmt, valist);
	va_end(valist);

	length = emlxs_fwrite((uint8_t *)va_str, strlen(va_str), 1, fp);

	return (length);

} /* emlxs_fprintf() */


extern emlxs_file_t *
emlxs_fopen(
	emlxs_hba_t *hba,
	uint32_t file_type)
{
	emlxs_file_t *fp;

	switch (file_type) {
	case EMLXS_TXT_FILE:
		fp = &hba->dump_txtfile;
		fp->size = EMLXS_TXT_FILE_SIZE;
		break;

	case EMLXS_DMP_FILE:
		fp = &hba->dump_dmpfile;
		fp->size = EMLXS_DMP_FILE_SIZE;
		break;

	case EMLXS_CEE_FILE:
		fp = &hba->dump_ceefile;
		fp->size = EMLXS_CEE_FILE_SIZE;
		break;

	default:
		return (NULL);
	}

	/* Make sure it is word aligned */
	fp->size &= 0xFFFFFFFC;

	if (!fp->buffer) {
		fp->buffer =
		    (uint8_t *)kmem_zalloc(fp->size, KM_SLEEP);

	} else {
		bzero(fp->buffer, fp->size);
	}

	fp->ptr = fp->buffer;

	return (fp);

} /* emlxs_fopen() */


extern uint32_t
emlxs_fclose(
	emlxs_file_t *fp)
{
	uint32_t offset;

	if (fp == NULL) {
		return (0);
	}

	offset = (uint32_t)((uintptr_t)fp->ptr - (uintptr_t)fp->buffer);
	offset = offset % 4;

	switch (offset) {
	case 0:
		break;

	case 1:
		*fp->ptr++ = 0;
		*fp->ptr++ = 0;
		*fp->ptr++ = 0;
		break;

	case 2:
		*fp->ptr++ = 0;
		*fp->ptr++ = 0;
		break;

	case 3:
		*fp->ptr++ = 0;
		break;
	}

	return (0);

} /* emlxs_fclose() */


static void
emlxs_fdelete(
	emlxs_file_t *fp)
{
	if (fp == NULL) {
		return;
	}

	if (fp->buffer && fp->size) {
		kmem_free(fp->buffer, fp->size);
	}

	fp->buffer = NULL;
	fp->ptr = NULL;
	fp->size = 0;

	return;

} /* emlxs_fdelete() */


/* This builds a single core buffer for the IOCTL interface */
extern uint32_t
emlxs_get_dump(
	emlxs_hba_t *hba,
	uint8_t *buffer,
	uint32_t *buflen)
{
	emlxs_port_t *port = &PPORT;
	int32_t i;
	int32_t size;
	int32_t count;
	uint32_t size_dmp;
	uint32_t size_txt;
	uint32_t size_cee;
	emlxs_file_t *fp_txt;
	emlxs_file_t *fp_dmp;
	emlxs_file_t *fp_cee;
	uint32_t *wptr;
	uint8_t *bptr;

	if (!buflen) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fw_dump_msg,
		    "get_dump: Buffer length = 0");
		return (1);
	}

	fp_txt = &hba->dump_txtfile;
	fp_dmp = &hba->dump_dmpfile;
	fp_cee = &hba->dump_ceefile;

	size_txt = emlxs_ftell(fp_txt);
	size_dmp = emlxs_ftell(fp_dmp);
	size_cee = emlxs_ftell(fp_cee);

	size = 0;
	count = 0;
	if (size_txt) {
		count++;
		size += size_txt + 8;
	}
	if (size_dmp) {
		count++;
		size += size_dmp + 8;
	}
	if (size_cee) {
		count++;
		size += size_cee + 8;
	}

	if (size) {
		size += 4;
	}

	if (!buffer) {
		goto done;
	}

	bzero(buffer, *buflen);

	if (*buflen < size) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fw_dump_msg,
		    "get_dump: Buffer length too small. %d < %d",
		    *buflen, size);

		*buflen = 0;
		return (1);
	}

	wptr = (uint32_t *)buffer;
	wptr[0] = count;
	i = 1;

	if (size_txt) {
		wptr[i++] = EMLXS_TXT_FILE_ID;
		wptr[i++] = size_txt;
	}

	if (size_dmp) {
		wptr[i++] = EMLXS_DMP_FILE_ID;
		wptr[i++] = size_dmp;
	}

	if (size_cee) {
		if ((hba->model_info.chip == EMLXS_BE2_CHIP) ||
		    (hba->model_info.chip == EMLXS_BE3_CHIP)) {
			wptr[i++] = EMLXS_FAT_FILE_ID;
		} else {
			wptr[i++] = EMLXS_CEE_FILE_ID;
		}

		wptr[i++] = size_cee;
	}

	bptr = (uint8_t *)&wptr[i];

	if (size_txt) {
		bcopy(fp_txt->buffer, bptr, size_txt);
		bptr += size_txt;
	}

	if (size_dmp) {
		bcopy(fp_dmp->buffer, bptr, size_dmp);
		bptr += size_dmp;
	}

	if (size_cee) {
		bcopy(fp_cee->buffer, bptr, size_cee);
		bptr += size_cee;
	}

done:

	*buflen = size;

	/* printf("Done. buflen=%d \n", *buflen); */

	return (0);

} /* emlxs_get_dump() */


static uint32_t
emlxs_read_cfg_region(
	emlxs_hba_t *hba,
	uint32_t Identifier,
	uint32_t ByteCount,
	uint32_t *pRetByteCount,
	uint8_t *pBuffer)
{
	emlxs_port_t *port = &PPORT;
	MAILBOXQ *mbq;
	uint32_t ByteCountRem;	/* remaining portion of original byte count */
	uint32_t ByteCountReq;	/* requested byte count for a particular dump */
	uint32_t CopyCount;	/* bytes to copy after each successful dump */
	uint32_t Offset;	/* Offset into Config Region, for each dump */
	uint8_t *pLocalBuf;	/* ptr to buffer to receive each dump */

	if (! ByteCount) {
		return (0);
	}

	mbq =
	    (MAILBOXQ *)kmem_zalloc(sizeof (MAILBOXQ), KM_SLEEP);

	pLocalBuf = pBuffer;	/* init local pointer to caller's buffer */
	Offset = 0;	/* start at offset 0 */
	*pRetByteCount = 0;	/* init returned byte count */
	CopyCount = 0;

	for (ByteCountRem = ByteCount; ByteCountRem > 0;
	    ByteCountRem -= CopyCount) {

		if (hba->sli_mode == EMLXS_HBA_SLI4_MODE) {
			MAILBOX4 *mb = (MAILBOX4 *)mbq;

			ByteCountReq =
			    (ByteCountRem < hba->sli.sli4.dump_region.size) ?
			    ByteCountRem : hba->sli.sli4.dump_region.size;

			/* Clear the local dump_region */
			bzero(hba->sli.sli4.dump_region.virt,
			    hba->sli.sli4.dump_region.size);

			bzero((void *) mb, MAILBOX_CMD_SLI4_BSIZE);

			mb->mbxCommand = MBX_DUMP_MEMORY;
			mb->un.varDmp4.type = DMP_NV_PARAMS;
			mb->un.varDmp4.entry_index = Offset;
			mb->un.varDmp4.region_id = Identifier;

			mb->un.varDmp4.available_cnt = ByteCountReq;
			mb->un.varDmp4.addrHigh =
			    PADDR_HI(hba->sli.sli4.dump_region.phys);
			mb->un.varDmp4.addrLow =
			    PADDR_LO(hba->sli.sli4.dump_region.phys);
			mb->un.varDmp4.rsp_cnt = 0;

			mb->mbxOwner = OWN_HOST;
			mbq->mbox_cmpl = NULL;

			if (EMLXS_SLI_ISSUE_MBOX_CMD(hba, mbq, MBX_WAIT, 0) !=
			    MBX_SUCCESS) {
				EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
				    "Unable to read config region. id=%x "\
				    "offset=%x status=%x",
				    Identifier, Offset, mb->mbxStatus);

				kmem_free(mbq, sizeof (MAILBOXQ));
				return (1);
			}

			CopyCount = mb->un.varDmp4.rsp_cnt;

			/* if no more data returned */
			if (CopyCount == 0) {
				break;
			}

			if (CopyCount > ByteCountReq) {
				EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
				    "read_cfg_region: " \
				    "Byte count too big. %d > %d\n",
				    CopyCount, ByteCountReq);

				CopyCount = ByteCountReq;
			}

			bcopy((uint8_t *)hba->sli.sli4.dump_region.virt,
			    pLocalBuf, CopyCount);

		} else {
			MAILBOX *mb = (MAILBOX *)mbq;

			ByteCountReq =
			    (ByteCountRem < DUMP_BC_MAX) ? ByteCountRem :
			    DUMP_BC_MAX;

			bzero((void *)mb, MAILBOX_CMD_BSIZE);

			mb->mbxCommand = MBX_DUMP_MEMORY;
			mb->un.varDmp.type = DMP_NV_PARAMS;
			mb->un.varDmp.cv = 1;
			mb->un.varDmp.region_id = Identifier;
			mb->un.varDmp.entry_index = Offset;
			mb->un.varDmp.word_cnt = ByteCountReq / 4;
			mb->mbxOwner = OWN_HOST;
			mbq->mbox_cmpl = NULL;

			if (EMLXS_SLI_ISSUE_MBOX_CMD(hba, mbq, MBX_WAIT, 0) !=
			    MBX_SUCCESS) {
				EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
				    "Unable to read config region. id=%x "\
				    "offset=%x status=%x",
				    Identifier, Offset, mb->mbxStatus);

				kmem_free(mbq, sizeof (MAILBOXQ));
				return (1);
			}

			/* Note: for Type 2/3 Dumps, varDmp.word_cnt is */
			/* actually a byte count. */
			CopyCount = mb->un.varDmp.word_cnt;

			/* if no more data returned */
			if (CopyCount == 0) {
				break;
			}

			if (CopyCount > ByteCountReq) {
				EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
				    "read_cfg_region: " \
				    "Byte count too big. %d > %d\n",
				    CopyCount, ByteCountReq);

				CopyCount = ByteCountReq;
			}

			bcopy((uint8_t *)&mb->un.varDmp.resp_offset, pLocalBuf,
			    CopyCount);
		}

		pLocalBuf += CopyCount;
		Offset += CopyCount;
		*pRetByteCount += CopyCount;
	}

	return (0);

} /* emlxs_read_cfg_region() */



/* ************************************************************************* */
/* ************************************************************************* */
/* Dump Generators, Low-Level */
/* ************************************************************************* */
/* ************************************************************************* */

static uint32_t
emlxs_dump_string_txtfile(
	emlxs_file_t *fpTxtFile,
	char *pString,
	char *pSidLegend,
	char *pLidLegend,
	uint32_t pure)
{

	if (!fpTxtFile) {
		return (1);
	}

	if (pSidLegend && pLidLegend) {
		(void) emlxs_fprintf(fpTxtFile, "%s: %s\n", pSidLegend,
		    pLidLegend);

		if (pure == 0) {
			emlxs_fputc(' ', fpTxtFile);
		}

		(void) emlxs_fwrite((uint8_t *)pString, strlen(pString), 1,
		    fpTxtFile);

		if (pure == 0) {
			emlxs_fputc('\n', fpTxtFile);
			emlxs_fputc('\n', fpTxtFile);
		}
	} else {
		if (pure == 0) {
			emlxs_fputc(' ', fpTxtFile);
		}
		(void) emlxs_fwrite((uint8_t *)pString, strlen(pString), 1,
		    fpTxtFile);
	}

	emlxs_fflush(fpTxtFile);

	return (0);

} /* emlxs_dump_string_txtfile() */


static uint32_t
emlxs_dump_word_txtfile(
	emlxs_file_t *fpTxtFile,
	uint32_t *pBuffer,
	uint32_t WordCount,
	char *pSidLegend,
	char *pLidLegend)
{
	char buf1[256];
	char buf2[256];
	uint32_t *ptr;
	uint32_t j;

	if (!fpTxtFile) {
		return (1);
	}

	/* Write Legend String to the TXT File */
	(void) emlxs_fprintf(fpTxtFile, "%s: %s\n", pSidLegend, pLidLegend);

	/* Write the buffer to the TXT File */
	ptr = pBuffer;

	for (j = 0; j < WordCount; j++) {
		buf1[0] = 0;
		buf2[0] = 0;

		if ((j & 0x03) == 0) {
			(void) snprintf(buf1, sizeof (buf1), "\n%04x:", j * 4);
			(void) strlcat(buf2, buf1, sizeof (buf2));
		}
		/* print 1 word */
		(void) snprintf(buf1, sizeof (buf1), " %08x", ptr[j]);
		(void) strlcat(buf2, buf1, sizeof (buf2));
		(void) emlxs_fwrite((uint8_t *)buf2, strlen(buf2), 1,
		    fpTxtFile);
	}

	emlxs_fputc('\n', fpTxtFile);
	emlxs_fputc('\n', fpTxtFile);
	emlxs_fflush(fpTxtFile);
	return (0);

} /* emlxs_dump_word_txtfile() */




static uint32_t
emlxs_dump_string_dmpfile(
	emlxs_file_t *fpDmpFile,
	char *pString,
	uint8_t sid,
	char *pSidLegend,
	char *pLidLegend)
{
	uint32_t length;
	uint8_t byte;
	uint32_t pos;

	if (!fpDmpFile) {
		return (1);
	}

	/* Write Legend SID to the DMP File */
	emlxs_fputc(SID_LEGEND, fpDmpFile);

	/* Write Argument SID to the DMP File */
	emlxs_fputc(sid, fpDmpFile);

	/* Write Legend String to the DMP File, including a Null Byte */
	(void) emlxs_fprintf(fpDmpFile, "%s: %s", pSidLegend, pLidLegend);
	emlxs_fputc(0, fpDmpFile);

	/* Write Argument SID to the DMP File */
	emlxs_fputc(sid, fpDmpFile);

	/* Write Buffer Length to the DMP File */
	length = (uint32_t)(strlen(pString) + 1);
#ifdef EMLXS_LITTLE_ENDIAN
	byte = (uint8_t)(length & 0x0000FF);
	emlxs_fputc(byte, fpDmpFile);
	byte = (uint8_t)((length & 0x00FF00) >> 8);
	emlxs_fputc(byte, fpDmpFile);
	byte = (uint8_t)((length & 0xFF0000) >> 16);
	emlxs_fputc(byte, fpDmpFile);
#endif /* EMLXS_LITTLE_ENDIAN */

#ifdef EMLXS_BIG_ENDIAN
	byte = (uint8_t)((length & 0xFF0000) >> 16);
	emlxs_fputc(byte, fpDmpFile);
	byte = (uint8_t)((length & 0x00FF00) >> 8);
	emlxs_fputc(byte, fpDmpFile);
	byte = (uint8_t)(length & 0x0000FF);
	emlxs_fputc(byte, fpDmpFile);
#endif /* EMLXS_BIG_ENDIAN */

	/* Write Argument String to the DMP File, including a Null Byte */
	(void) emlxs_fwrite((uint8_t *)pString, strlen(pString), 1, fpDmpFile);
	emlxs_fputc(0, fpDmpFile);

	emlxs_fflush(fpDmpFile);

#if CC_DUMP_ENABLE_PAD
	/* check file size.. pad as necessary */
	pos = emlxs_ftell(fpDmpFile);
	switch (pos & 0x03) {
	case 0:
		break;
	case 1:
		emlxs_fputc(0, fpDmpFile);
		emlxs_fputc(0, fpDmpFile);
		emlxs_fputc(0, fpDmpFile);
		break;
	case 2:
		emlxs_fputc(0, fpDmpFile);
		emlxs_fputc(0, fpDmpFile);
		break;
	case 3:
		emlxs_fputc(0, fpDmpFile);
		break;
	}
	emlxs_fflush(fpDmpFile);
#endif

	return (0);

} /* emlxs_dump_string_dmpfile() */


/* ************************************************************************** */
/* emlxs_dump_word_dmpfile */
/* If little endian, just write the buffer normally. */
/* However, if Big Endian... Consider the following: */
/* Automatic Dump, initiated by driver, Port Offline (FW WarmStart Mode), */
/* Mailbox in SLIM. */
/* On-Demand Dump, initiated by utility, Port Online (FW Normal Mode), */
/* Mailbox in Host Memory. */
/* We use the same IOCTL to get the DUMP Data, for both cases. */
/* However, it normalizes the data before delivering it to us. */
/* In the Dump File, we must always write the data in native mode. */
/* So, if Big Endian, On-demand Dump, we must swap the words. */
/* ************************************************************************* */
/*ARGSUSED*/
extern uint32_t
emlxs_dump_word_dmpfile(
	emlxs_file_t *fpDmpFile,
	uint8_t *pBuffer,
	uint32_t bufferLen,
	int fSwap)
{
	uint32_t i;
	uint32_t *wptr;

	if (!fpDmpFile) {
		return (1);
	}

	wptr = (uint32_t *)pBuffer;
	for (i = 0; i < bufferLen / 4; i++, wptr++) {
		if (fSwap) {
			uint32_t w1;
			w1 = *wptr;
			*wptr = BE_SWAP32(w1);
		}

		(void) emlxs_fwrite((uint8_t *)wptr, 4, 1, fpDmpFile);
	}

	emlxs_fflush(fpDmpFile);

	return (0);

} /* emlxs_dump_word_dmpfile() */


static uint32_t
emlxs_dump_port_block(
	emlxs_file_t *fpDmpFile,
	uint8_t *pBuffer,
	uint32_t bufferLen,
	DUMP_TABLE_ENTRY entry,
	int fSwap)
{
	uint32_t status;
	uint32_t w;
	uint8_t b;

	if (!fpDmpFile) {
		return (1);
	}

	/* Write Argument SID to the DMP File */
	b = (uint8_t)entry.un.PortBlock.un.s.sid;
	emlxs_fputc(b, fpDmpFile);

#ifdef EMLXS_LITTLE_ENDIAN
	/* Write Buffer Length to the DMP File */
	w = entry.un.PortBlock.un.s.bc;
	b = (uint8_t)(w & 0x000000FF);
	emlxs_fputc(b, fpDmpFile);
	b = (uint8_t)((w & 0x0000FF00) >> 8);
	emlxs_fputc(b, fpDmpFile);
	b = (uint8_t)((w & 0x00FF0000) >> 16);
	emlxs_fputc(b, fpDmpFile);

	/* Write address to the DMP File */
	w = entry.un.PortBlock.un.s.addr;
	b = (uint8_t)(w & 0x000000FF);
	emlxs_fputc(b, fpDmpFile);
	b = (uint8_t)((w & 0x0000FF00) >> 8);
	emlxs_fputc(b, fpDmpFile);
	b = (uint8_t)((w & 0x00FF0000) >> 16);
	emlxs_fputc(b, fpDmpFile);
	b = (uint8_t)((w & 0xFF000000) >> 24);
	emlxs_fputc(b, fpDmpFile);
#endif /* EMLXS_LITTLE_ENDIAN */

#ifdef EMLXS_BIG_ENDIAN
	/* Write Buffer Length to the DMP File */
	w = entry.un.PortBlock.un.s.bc;
	b = (uint8_t)((w & 0x00FF0000) >> 16);
	emlxs_fputc(b, fpDmpFile);
	b = (uint8_t)((w & 0x0000FF00) >> 8);
	emlxs_fputc(b, fpDmpFile);
	b = (uint8_t)(w & 0x000000FF);
	emlxs_fputc(b, fpDmpFile);

	/* Write address to the DMP File */
	w = entry.un.PortBlock.un.s.addr;
	b = (uint8_t)((w & 0xFF000000) >> 24);
	emlxs_fputc(b, fpDmpFile);
	b = (uint8_t)((w & 0x00FF0000) >> 16);
	emlxs_fputc(b, fpDmpFile);
	b = (uint8_t)((w & 0x0000FF00) >> 8);
	emlxs_fputc(b, fpDmpFile);
	b = (uint8_t)(w & 0x000000FF);
	emlxs_fputc(b, fpDmpFile);
#endif /* EMLXS_BIG_ENDIAN */

	status =
	    emlxs_dump_word_dmpfile(fpDmpFile, pBuffer, bufferLen, fSwap);

	emlxs_fflush(fpDmpFile);

	return (status);

} /* emlxs_dump_port_block() */


static uint32_t
emlxs_dump_port_struct(
	emlxs_file_t *fpDmpFile,
	uint8_t *pBuffer,
	uint32_t bufferLen,
	DUMP_TABLE_ENTRY entry,
	int fSwap)
{
	uint32_t status;
	uint32_t w;
	uint8_t b;

	if (!fpDmpFile) {
		return (1);
	}

	/* Write Argument SID to the DMP File */
	b = (uint8_t)entry.un.PortStruct.un.s.sid;
	emlxs_fputc(b, fpDmpFile);

	/* Write Element Length to the DMP File */
	b = (uint8_t)entry.un.PortStruct.un.s.length;
	emlxs_fputc(b, fpDmpFile);

#ifdef EMLXS_LITTLE_ENDIAN
	/* Write Element Count to the DMP File */
	w = entry.un.PortStruct.un.s.count;
	b = (uint8_t)(w & 0x000000FF);
	emlxs_fputc(b, fpDmpFile);
	b = (uint8_t)((w & 0x0000FF00) >> 8);
	emlxs_fputc(b, fpDmpFile);

	/* Write Address to the DMP File */
	w = entry.un.PortStruct.un.s.addr;
	b = (uint8_t)(w & 0x000000FF);
	emlxs_fputc(b, fpDmpFile);
	b = (uint8_t)((w & 0x0000FF00) >> 8);
	emlxs_fputc(b, fpDmpFile);
	b = (uint8_t)((w & 0x00FF0000) >> 16);
	emlxs_fputc(b, fpDmpFile);
	b = (uint8_t)((w & 0xFF000000) >> 24);
	emlxs_fputc(b, fpDmpFile);
#endif /* EMLXS_LITTLE_ENDIAN */

#ifdef EMLXS_BIG_ENDIAN
	/* Write Element Count to the DMP File */
	w = entry.un.PortStruct.un.s.count;
	b = (uint8_t)((w & 0x0000FF00) >> 8);
	emlxs_fputc(b, fpDmpFile);
	b = (uint8_t)(w & 0x000000FF);
	emlxs_fputc(b, fpDmpFile);

	/* Write Address to the DMP File */
	w = entry.un.PortStruct.un.s.addr;
	b = (uint8_t)((w & 0xFF000000) >> 24);
	emlxs_fputc(b, fpDmpFile);
	b = (uint8_t)((w & 0x00FF0000) >> 16);
	emlxs_fputc(b, fpDmpFile);
	b = (uint8_t)((w & 0x0000FF00) >> 8);
	emlxs_fputc(b, fpDmpFile);
	b = (uint8_t)(w & 0x000000FF);
	emlxs_fputc(b, fpDmpFile);
#endif /* EMLXS_BIG_ENDIAN */

	status =
	    emlxs_dump_word_dmpfile(fpDmpFile, pBuffer, bufferLen, fSwap);

	emlxs_fflush(fpDmpFile);

	return (status);

} /* emlxs_dump_port_struct() */


static uint32_t
emlxs_dump_host_block(
	emlxs_file_t *fpDmpFile,
	uint8_t *pBuffer,
	uint32_t bufferLen,
	uint8_t sid,
	char *pSidLegend,
	char *pLidLegend,
	int fSwap)
{
	uint32_t status;
	uint32_t length;
	uint8_t byte;

	if (!fpDmpFile) {
		return (1);
	}

	/* Write Legend SID to the DMP File */
	emlxs_fputc(SID_LEGEND, fpDmpFile);

	/* Write Argument SID to the DMP File */
	emlxs_fputc(sid, fpDmpFile);

	/* Write Legend String to the DMP File, including a Null Byte */
	(void) emlxs_fprintf(fpDmpFile, "%s: %s", pSidLegend, pLidLegend);
	emlxs_fputc(0, fpDmpFile);

	/* Write Argument SID to the DMP File */
	emlxs_fputc(sid, fpDmpFile);

	/* Write Buffer Length to the DMP File */
	length = bufferLen;
#ifdef EMLXS_LITTLE_ENDIAN
	byte = (uint8_t)(length & 0x0000FF);
	emlxs_fputc(byte, fpDmpFile);
	byte = (uint8_t)((length & 0x00FF00) >> 8);
	emlxs_fputc(byte, fpDmpFile);
	byte = (uint8_t)((length & 0xFF0000) >> 16);
	emlxs_fputc(byte, fpDmpFile);
#endif /* EMLXS_LITTLE_ENDIAN */

#ifdef EMLXS_BIG_ENDIAN
	byte = (uint8_t)((length & 0xFF0000) >> 16);
	emlxs_fputc(byte, fpDmpFile);
	byte = (uint8_t)((length & 0x00FF00) >> 8);
	emlxs_fputc(byte, fpDmpFile);
	byte = (uint8_t)(length & 0x0000FF);
	emlxs_fputc(byte, fpDmpFile);
#endif /* EMLXS_BIG_ENDIAN */

	status =
	    emlxs_dump_word_dmpfile(fpDmpFile, pBuffer, bufferLen, fSwap);

	emlxs_fflush(fpDmpFile);

	return (status);

} /* emlxs_dump_host_block() */


static uint32_t
emlxs_dump_host_struct(
	emlxs_file_t *fpDmpFile,
	uint8_t *pBuffer,
	uint32_t bufferLen,
	uint32_t elementLength,
	uint32_t elementCount,
	uint8_t sid,
	char *pSidLegend,
	char *pLidLegend,
	int fSwap)
{
	uint32_t status;
	uint32_t w;
	uint8_t b;

	if (!fpDmpFile) {
		return (1);
	}

	/* Write Legend SID to the DMP File */
	emlxs_fputc(SID_LEGEND, fpDmpFile);

	/* Write Argument SID to the DMP File */
	emlxs_fputc(sid, fpDmpFile);

	/* Write Legend String to the DMP File, including a Null Byte */
	(void) emlxs_fprintf(fpDmpFile, "%s: %s", pSidLegend, pLidLegend);
	emlxs_fputc(0, fpDmpFile);

	/* Write Argument SID to the DMP File */
	emlxs_fputc(sid, fpDmpFile);

	/* Write Element Length to the DMP File */
	b = (uint8_t)elementLength;
	emlxs_fputc(b, fpDmpFile);

	/* Write Element Count to the DMP File */
	w = elementCount;
#ifdef EMLXS_LITTLE_ENDIAN
	b = (uint8_t)(w & 0x000000FF);
	emlxs_fputc(b, fpDmpFile);
	b = (uint8_t)((w & 0x0000FF00) >> 8);
	emlxs_fputc(b, fpDmpFile);
#endif /* EMLXS_LITTLE_ENDIAN */

#ifdef EMLXS_BIG_ENDIAN
	b = (uint8_t)((w & 0x0000FF00) >> 8);
	emlxs_fputc(b, fpDmpFile);
	b = (uint8_t)(w & 0x000000FF);
	emlxs_fputc(b, fpDmpFile);
#endif /* EMLXS_BIG_ENDIAN */

	status =
	    emlxs_dump_word_dmpfile(fpDmpFile, pBuffer, bufferLen, fSwap);

	emlxs_fflush(fpDmpFile);

	return (status);

} /* emlxs_dump_host_struct() */


/* ************************************************************************* */
/* ************************************************************************* */
/* Dump Generators, Mid-Level */
/* ************************************************************************* */
/* ************************************************************************* */

static uint32_t
emlxs_dump_parm_table(
	emlxs_hba_t *hba,
	emlxs_file_t *fpTxtFile,
	emlxs_file_t *fpDmpFile)
{
	emlxs_config_t *cfg = &CFG;
	uint32_t status;
	uint32_t i;

	/* vars used to build the Dump String */
	char *buf1;
	char *buf2;

	buf1 = (char *)kmem_zalloc(8192, KM_SLEEP);
	buf2 = (char *)kmem_zalloc(8192, KM_SLEEP);

	/* Driver Parameters Heading */
	(void) snprintf(buf1, 8192,
	    "IDX                     string      Low     "\
	    "High      Def      Cur  Exp  Dyn");

	/* Build the buffer containing all the Driver Params */
	for (i = 0; i < NUM_CFG_PARAM; i++) {
		(void) snprintf(buf2, 8192,
		    "\n  %02x: %25s %8x %8x %8x %8x %4x %4x", i,
		    cfg[i].string, cfg[i].low, cfg[i].hi, cfg[i].def,
		    cfg[i].current, (cfg[i].flags & PARM_HIDDEN) ? 0 : 1,
		    (cfg[i].flags & PARM_DYNAMIC) ? 1 : 0);

		(void) strlcat(buf1, buf2, 8192);
	}

	status =
	    emlxs_dump_string_txtfile(fpTxtFile, buf1, LEGEND_DP_TABLE,
	    LEGEND_NULL, 0);

	status =
	    emlxs_dump_string_dmpfile(fpDmpFile, buf1, SID_DP_TABLE,
	    LEGEND_DP_TABLE, LEGEND_NULL);

	kmem_free(buf1, 8192);
	kmem_free(buf2, 8192);

	return (status);

} /* emlxs_dump_parm_table() */


static uint32_t
emlxs_dump_model(
	emlxs_hba_t *hba,
	emlxs_file_t *fpTxtFile,
	emlxs_file_t *fpDmpFile)
{
	emlxs_vpd_t *vpd = &VPD;
	uint32_t status;

	/* vars used to build the Dump String */
	char buf1[512];
	char buf2[512];

	/* Write the Model into the buffer */
	(void) snprintf(buf2, sizeof (buf2), "%s", vpd->model);
	(void) strlcpy(buf1, "Model: ", sizeof (buf1));
	(void) strlcat(buf1, buf2, sizeof (buf1));

	/* Write the Model Description into the buffer */
	(void) snprintf(buf2, sizeof (buf2), "%s", vpd->model_desc);
	(void) strlcat(buf1, "\n Description: ", sizeof (buf1));
	(void) strlcat(buf1, buf2, sizeof (buf1));

	status =
	    emlxs_dump_string_txtfile(fpTxtFile, buf1, LEGEND_HBA_INFO,
	    LEGEND_HBA_MODEL, 0);

	status =
	    emlxs_dump_string_dmpfile(fpDmpFile, buf1, SID_HBA_INFO,
	    LEGEND_HBA_INFO, LEGEND_HBA_MODEL);

	return (status);

} /* emlxs_dump_model() */


static uint32_t
emlxs_dump_wwn(
	emlxs_hba_t *hba,
	emlxs_file_t *fpTxtFile,
	emlxs_file_t *fpDmpFile)
{
	uint32_t status;

	/* vars used to build the Dump String */
	char buf1[512];
	char buf2[512];
	int i;
	uint8_t *p;

	/* Write the WWPN into the buffer */
	(void) strlcpy(buf1, "Port WWN: ", sizeof (buf1));
	p = (uint8_t *)&hba->wwpn;
	for (i = 0; i < 7; i++) {
		(void) snprintf(buf2, sizeof (buf2), "%02x:", *p++);
		(void) strlcat(buf1, buf2, sizeof (buf1));
	}
	(void) snprintf(buf2, sizeof (buf2), "%02x", *p++);
	(void) strlcat(buf1, buf2, sizeof (buf1));

	/* Write the WWNN into the buffer */
	(void) strlcat(buf1, "\n Node WWN: ", sizeof (buf1));
	p = (uint8_t *)&hba->wwnn;
	for (i = 0; i < 7; i++) {
		(void) snprintf(buf2, sizeof (buf2), "%02x:", *p++);
		(void) strlcat(buf1, buf2, sizeof (buf1));
	}
	(void) snprintf(buf2, sizeof (buf2), "%02x", *p++);
	(void) strlcat(buf1, buf2, sizeof (buf1));

	status =
	    emlxs_dump_string_txtfile(fpTxtFile, buf1, LEGEND_HBA_INFO,
	    LEGEND_HBA_WWN, 0);

	status =
	    emlxs_dump_string_dmpfile(fpDmpFile, buf1, SID_HBA_INFO,
	    LEGEND_HBA_INFO, LEGEND_HBA_WWN);

	return (status);

} /* emlxs_dump_wwn() */


static uint32_t
emlxs_dump_serial_number(
	emlxs_hba_t *hba,
	emlxs_file_t *fpTxtFile,
	emlxs_file_t *fpDmpFile)
{
	emlxs_vpd_t *vpd = &VPD;
	uint32_t status;

	/* vars used to build the Dump String */
	char buf1[512];
	char buf2[512];

	/* Write the Serial Number into the buffer */
	(void) snprintf(buf2, sizeof (buf2), "%s", vpd->serial_num);
	(void) strlcpy(buf1, LEGEND_HBA_SN, sizeof (buf1));
	(void) strlcat(buf1, ": ", sizeof (buf1));
	(void) strlcat(buf1, buf2, sizeof (buf1));

	status =
	    emlxs_dump_string_txtfile(fpTxtFile, buf1, LEGEND_HBA_INFO,
	    LEGEND_HBA_SN, 0);

	status =
	    emlxs_dump_string_dmpfile(fpDmpFile, buf1, SID_HBA_INFO,
	    LEGEND_HBA_INFO, LEGEND_HBA_SN);

	return (status);

} /* emlxs_dump_serial_number() */


static uint32_t
emlxs_dump_fw_version(
	emlxs_hba_t *hba,
	emlxs_file_t *fpTxtFile,
	emlxs_file_t *fpDmpFile)
{
	emlxs_vpd_t *vpd = &VPD;
	uint32_t status;

	char *buf1;
	char *buf2;
	uint32_t buf1_size;
	uint32_t buf2_size;

	buf1_size = 1024;
	buf2_size = 1024;

	buf1 = (char *)kmem_zalloc(buf1_size, KM_SLEEP);
	buf2 = (char *)kmem_zalloc(buf2_size, KM_SLEEP);

	/* Write the Firmware Version into the buffer */
	(void) snprintf(buf2, buf2_size, "%s", vpd->fw_version);
	(void) strlcpy(buf1, LEGEND_HBA_FW_VERSION, buf1_size);
	(void) strlcat(buf1, ": ", buf1_size);
	(void) strlcat(buf1, buf2, buf1_size);

	/* Write the Operational FW Version into the buffer */
	(void) snprintf(buf2, buf2_size, "%s", vpd->opFwName);
	(void) strlcat(buf1, "\n ", buf1_size);
	(void) strlcat(buf1, LEGEND_HBA_FW_OPVERSION, buf1_size);
	(void) strlcat(buf1, ": ", buf1_size);
	(void) strlcat(buf1, buf2, buf1_size);

	/* Write the SLI-1 FW Version into the buffer */
	(void) snprintf(buf2, buf2_size, "%s", vpd->sli1FwName);
	(void) strlcat(buf1, "\n ", buf1_size);
	(void) strlcat(buf1, LEGEND_HBA_FW_SLI1VERSION, buf1_size);
	(void) strlcat(buf1, ": ", buf1_size);
	(void) strlcat(buf1, buf2, buf1_size);

	/* Write the SLI-2 FW Version into the buffer */
	(void) snprintf(buf2, buf2_size, "%s", vpd->sli2FwName);
	(void) strlcat(buf1, "\n ", buf1_size);
	(void) strlcat(buf1, LEGEND_HBA_FW_SLI2VERSION, buf1_size);
	(void) strlcat(buf1, ": ", buf1_size);
	(void) strlcat(buf1, buf2, buf1_size);

	/* Write the SLI-3 FW Version into the buffer */
	(void) snprintf(buf2, buf2_size, "%s", vpd->sli3FwName);
	(void) strlcat(buf1, "\n ", buf1_size);
	(void) strlcat(buf1, LEGEND_HBA_FW_SLI3VERSION, buf1_size);
	(void) strlcat(buf1, ": ", buf1_size);
	(void) strlcat(buf1, buf2, buf1_size);

	/* Write the Kernel FW Version into the buffer */
	(void) snprintf(buf2, buf2_size, "%s", vpd->postKernName);
	(void) strlcat(buf1, "\n ", buf1_size);
	(void) strlcat(buf1, LEGEND_HBA_FW_KERNELVERSION, buf1_size);
	(void) strlcat(buf1, ": ", buf1_size);
	(void) strlcat(buf1, buf2, buf1_size);

	status =
	    emlxs_dump_string_txtfile(fpTxtFile, buf1, LEGEND_HBA_INFO,
	    LEGEND_HBA_FW_VERSION, 0);

	status =
	    emlxs_dump_string_dmpfile(fpDmpFile, buf1, SID_HBA_INFO,
	    LEGEND_HBA_INFO, LEGEND_HBA_FW_VERSION);

	kmem_free(buf1, buf1_size);
	kmem_free(buf2, buf2_size);

	return (status);

} /* emlxs_dump_fw_version() */


static uint32_t
emlxs_dump_boot_version(
	emlxs_hba_t *hba,
	emlxs_file_t *fpTxtFile,
	emlxs_file_t *fpDmpFile)
{
	emlxs_vpd_t *vpd = &VPD;
	uint32_t status;
	uint32_t state;

	char *buf1;
	char *buf2;
	uint32_t buf1_size;
	uint32_t buf2_size;

	buf1_size = 1024;
	buf2_size = 1024;

	buf1 = (char *)kmem_zalloc(buf1_size, KM_SLEEP);
	buf2 = (char *)kmem_zalloc(buf2_size, KM_SLEEP);

#ifdef EMLXS_SPARC
	if (strcmp(vpd->fcode_version, "none") == 0)
#else
	if (strcmp(vpd->boot_version, "none") == 0)
#endif /* EMLXS_SPARC */
	{
		state = 2;	/* BOOT_BIOS_NOT_PRESENT */
	} else {
		state = emlxs_boot_code_state(hba);
	}

	/* Write the Boot Bios State into the buffer */
	(void) snprintf(buf2, buf2_size, " %d", state);
	(void) strlcpy(buf1, LEGEND_HBA_BB_STATE, buf1_size);
	(void) strlcat(buf1, ": ", buf1_size);
	(void) strlcat(buf1, buf2, buf1_size);

	/* Write the Boot Bios Version into the buffer */
	if (state == 2) {
		(void) snprintf(buf2, buf2_size, "%s", "unknown");
	} else {
#ifdef EMLXS_SPARC
		(void) snprintf(buf2, buf2_size, "%s (FCode)",
		    vpd->fcode_version);
#else
		(void) snprintf(buf2, buf2_size, "%s", vpd->boot_version);
#endif /* EMLXS_SPARC */
	}

	(void) strlcat(buf1, "\n ", buf1_size);
	(void) strlcat(buf1, LEGEND_HBA_BB_VERSION, buf1_size);
	(void) strlcat(buf1, ": ", buf1_size);
	(void) strlcat(buf1, buf2, buf1_size);

	status =
	    emlxs_dump_string_txtfile(fpTxtFile, buf1, LEGEND_HBA_INFO,
	    LEGEND_HBA_BB_VERSION, 0);

	status =
	    emlxs_dump_string_dmpfile(fpDmpFile, buf1, SID_HBA_INFO,
	    LEGEND_HBA_INFO, LEGEND_HBA_BB_VERSION);

	kmem_free(buf1, buf1_size);
	kmem_free(buf2, buf2_size);

	return (status);

} /* emlxs_dump_boot_version() */


/* ARGSUSED */
static uint32_t
emlxs_dump_cfg_region4_decoded(
	emlxs_hba_t *hba,
	emlxs_file_t *fpTxtFile,
	char *pLidLegend,
	DUMP_WAKE_UP_PARAMS *pBuffer,
	uint32_t ByteCount)
{
	uint32_t status;
	char *buf1;	/* text buffer */
	char *buf2;	/* text buffer */
	uint32_t buf1_size;
	uint32_t buf2_size;

	buf1_size = 1024;
	buf2_size = 1024;

	buf1 = (char *)kmem_zalloc(buf1_size, KM_SLEEP);
	buf2 = (char *)kmem_zalloc(buf2_size, KM_SLEEP);

	/* Write the Initial ID into the buffer */
	(void) snprintf(buf2, buf2_size, "%s: %08x %08x",
	    LEGEND_CR4_INITIAL_LOAD,
	    pBuffer->InitialId[0], pBuffer->InitialId[1]);
	(void) strlcat(buf1, buf2, buf1_size);

	/* Write the Flags Word into the buffer */
	(void) snprintf(buf2, buf2_size, "\n %s: %08x", LEGEND_CR4_FLAGS,
	    pBuffer->Flags);
	(void) strlcat(buf1, buf2, buf1_size);

	/* Write the Boot Bios ID into the buffer */
	(void) snprintf(buf2, buf2_size, "\n %s: %08x %08x",
	    LEGEND_CR4_BOOT_BIOS_ID,
	    pBuffer->BootBiosId[0], pBuffer->BootBiosId[1]);
	(void) strlcat(buf1, buf2, buf1_size);

	/* Write the SLI1 ID into the buffer */
	(void) snprintf(buf2, buf2_size, "\n %s: %08x %08x",
	    LEGEND_CR4_SLI1_ID,
	    pBuffer->Sli1Id[0], pBuffer->Sli1Id[1]);
	(void) strlcat(buf1, buf2, buf1_size);

	/* Write the SLI2 ID into the buffer */
	(void) snprintf(buf2, buf2_size, "\n %s: %08x %08x",
	    LEGEND_CR4_SLI2_ID,
	    pBuffer->Sli2Id[0], pBuffer->Sli2Id[1]);
	(void) strlcat(buf1, buf2, buf1_size);

	/* Write the SLI3 ID into the buffer */
	(void) snprintf(buf2, buf2_size, "\n %s: %08x %08x",
	    LEGEND_CR4_SLI3_ID,
	    pBuffer->Sli3Id[0], pBuffer->Sli3Id[1]);
	(void) strlcat(buf1, buf2, buf1_size);

	/* Write the SLI4 ID into the buffer */
	(void) snprintf(buf2, buf2_size, "\n %s: %08x %08x",
	    LEGEND_CR4_SLI4_ID,
	    pBuffer->Sli4Id[0], pBuffer->Sli4Id[1]);
	(void) strlcat(buf1, buf2, buf1_size);

	/* Write the Erom ID into the buffer */
	(void) snprintf(buf2, buf2_size, "\n %s: %08x %08x",
	    LEGEND_CR4_EROM_ID,
	    pBuffer->EromId[0], pBuffer->EromId[1]);
	(void) strlcat(buf1, buf2, buf1_size);

	status =
	    emlxs_dump_string_txtfile(fpTxtFile, buf1, LEGEND_CONFIG_REGION,
	    LEGEND_CONFIG_REGION_4, 0);

	kmem_free(buf1, buf1_size);
	kmem_free(buf2, buf2_size);

	return (status);

} /* emlxs_dump_cfg_region4_decoded() */


/* ARGSUSED */
uint32_t
emlxs_dump_cfg_region14_decoded(
	emlxs_hba_t *hba,
	emlxs_file_t *fpTxtFile,
	char *pLidLegend,
	char *pBuffer,
	uint32_t ByteCount)
{
	uint32_t status;
	char *buf1;	/* text buffer */
	char *buf2;	/* text buffer */
	uint32_t buf1_size;
	uint32_t buf2_size;
	int i;
	uint8_t tag;
	uint16_t length;
	uint16_t length2;
	char mnemonic[4];
	int fDone = FALSE;	/* flag to exit VPD loop */

#ifdef EMLXS_BIG_ENDIAN
	uint32_t *wptr;
	uint32_t w1;
#endif

	buf1_size = 1024;
	buf2_size = 1024;

	buf1 = (char *)kmem_zalloc(buf1_size, KM_SLEEP);
	buf2 = (char *)kmem_zalloc(buf2_size, KM_SLEEP);

/* If Big Endian, swap the data in place, */
/* because it's PCI Data (Little Endian) */
#ifdef EMLXS_BIG_ENDIAN
	wptr = (uint32_t *)pBuffer;
	for (i = 0; i < (int)ByteCount / 4; i++, wptr++) {
		w1 = *wptr;
		*wptr = BE_SWAP32(w1);
	}
#endif /* EMLXS_BIG_ENDIAN */

	/* Decode the VPD Data and write it into the buffer */

	/* CR 26941 */
	/* NOTE: The following code is correct, */
	/* should work, and used to work. */
	/* pBuffer points to char, and the symbol VPD_TAG_82 is 0x82. */
	/* The test is an equality test, not a relational test. */
	/* The compiler should generate an 8 bit test, and */
	/* sign extension does not apply. */
	/* I don't know when or why it stopped working, */
	/* and don't have time to dig. */
	/* The cast fixes it. */

	if (((unsigned char)pBuffer[0]) != VPD_TAG_82) {
		(void) snprintf(buf1, buf1_size,
		    "Bad VPD Data: (w0=0x%08x)", *(uint32_t *)pBuffer);
	} else {	/* begin good data */
		i = 0;
		while (!fDone) {
			tag = pBuffer[i++];
			length = pBuffer[i++];
			length |= (pBuffer[i++] << 8);

			switch (tag) {
			case VPD_TAG_82:
				(void) strncpy(buf2, &pBuffer[i],
				    length > buf2_size ? buf2_size : length);
				buf2[length >
				    (buf2_size - 1) ? (buf2_size -
				    1) : length] = 0;
				(void) strlcat(buf1, "Name: ", buf1_size);
				(void) strlcat(buf1, buf2, buf1_size);
				i += length;
				break;

			case VPD_TAG_90:
				for (;;) {
					mnemonic[0] = pBuffer[i++];
					mnemonic[1] = pBuffer[i++];
					mnemonic[2] = 0;

					if (strcmp(mnemonic, "RV") == 0) {
						fDone = TRUE;
						break;
					}

					if (mnemonic[0] == 0) {
						fDone = TRUE;
						break;
					}

					length2 = pBuffer[i++];
					(void) snprintf(buf2, buf2_size,
					    "\n %s: ", mnemonic);
					(void) strlcat(buf1, buf2,
					    buf1_size);
					(void) strncpy(buf2, &pBuffer[i],
					    length2 >
					    buf2_size ? buf2_size : length2);
					buf2[length2 >
					    (buf2_size - 1) ? (buf2_size -
					    1) : length2] = 0;
					(void) strlcat(buf1, buf2,
					    buf1_size);
					i += length2;
				}
				break;

			default:
				break;

			}	/* end switch */

		}	/* end while */

	}	/* good data */

	status =
	    emlxs_dump_string_txtfile(fpTxtFile, buf1, LEGEND_CONFIG_REGION,
	    LEGEND_CONFIG_REGION_14, 0);

	kmem_free(buf1, buf1_size);
	kmem_free(buf2, buf2_size);

	return (status);

} /* emlxs_dump_cfg_region14_decoded() */


static uint32_t
emlxs_dump_cfg_region(
	emlxs_hba_t *hba,
	emlxs_file_t *fpTxtFile,
	emlxs_file_t *fpDmpFile,
	uint8_t Region,
	char *pLidLegend,
	int fSwap)
{
	uint32_t status;
	uint32_t RetByteCount = 0;	/* returned byte count */
	char *buf1;	/* string ops buffer */
	char *buf2;	/* string ops buffer */
	uint32_t buf1_size;
	uint32_t buf2_size;
	uint32_t *buffer;
	int i;

#ifdef EMLXS_LITTLE_ENDIAN
	fSwap = FALSE;
#endif /* EMLXS_LITTLE_ENDIAN */

	buf1_size = 4096;
	buf2_size = 1024;

	buf1 = (char *)kmem_zalloc(buf1_size, KM_SLEEP);
	buf2 = (char *)kmem_zalloc(buf2_size, KM_SLEEP);

	buffer =
	    (uint32_t *)kmem_zalloc(DUMP_MAX_CONFIG_REGION_LENGTH, KM_SLEEP);

	status =
	    emlxs_read_cfg_region(hba, Region, DUMP_MAX_CONFIG_REGION_LENGTH,
	    &RetByteCount, (uint8_t *)buffer);

	if (status != 0) {
		kmem_free(buffer, DUMP_MAX_CONFIG_REGION_LENGTH);
		kmem_free(buf1, buf1_size);
		kmem_free(buf2, buf2_size);
		return (status);
	}

	/* Write the Data into the buffer */
	for (i = 0; i < (int)RetByteCount / 4; i++) {
		if ((i % 8 == 0) && (i != 0)) {
			(void) strlcat((char *)buf1, "\n ", buf1_size);
		}

		(void) snprintf(buf2, buf2_size, "%08x, ", buffer[i]);
		(void) strlcat((char *)buf1, buf2, buf1_size);
	}

	status =
	    emlxs_dump_string_txtfile(fpTxtFile, buf1, LEGEND_CONFIG_REGION,
	    pLidLegend, 0);

	status = emlxs_dump_host_block(fpDmpFile,
	    (uint8_t *)buffer,
	    RetByteCount,
	    SID_CONFIG_REGION, LEGEND_CONFIG_REGION, pLidLegend, fSwap);

	if (Region == 4) {
		status =
		    emlxs_dump_cfg_region4_decoded(hba, fpTxtFile, pLidLegend,
		    (DUMP_WAKE_UP_PARAMS *)buffer, RetByteCount);
	}

	if (Region == 14) {
		status =
		    emlxs_dump_cfg_region14_decoded(hba, fpTxtFile,
		    pLidLegend, (char *)buffer, RetByteCount);
	}

	kmem_free(buffer, DUMP_MAX_CONFIG_REGION_LENGTH);
	kmem_free(buf1, buf1_size);
	kmem_free(buf2, buf2_size);

	return (status);

} /* emlxs_dump_cfg_region() */


static uint32_t
emlxs_dump_cfg_regions(
	emlxs_hba_t *hba,
	emlxs_file_t *fpTxtFile,
	emlxs_file_t *fpDmpFile)
{
	uint32_t status;

	status =
	    emlxs_dump_cfg_region(hba, fpTxtFile, fpDmpFile, 0,
	    LEGEND_CONFIG_REGION_0, FALSE);

	status =
	    emlxs_dump_cfg_region(hba, fpTxtFile, fpDmpFile, 1,
	    LEGEND_CONFIG_REGION_1, FALSE);

	status =
	    emlxs_dump_cfg_region(hba, fpTxtFile, fpDmpFile, 2,
	    LEGEND_CONFIG_REGION_2, FALSE);

	status =
	    emlxs_dump_cfg_region(hba, fpTxtFile, fpDmpFile, 3,
	    LEGEND_CONFIG_REGION_3, FALSE);

	status =
	    emlxs_dump_cfg_region(hba, fpTxtFile, fpDmpFile, 4,
	    LEGEND_CONFIG_REGION_4, FALSE);

	status =
	    emlxs_dump_cfg_region(hba, fpTxtFile, fpDmpFile, 5,
	    LEGEND_CONFIG_REGION_5, FALSE);

	status =
	    emlxs_dump_cfg_region(hba, fpTxtFile, fpDmpFile, 6,
	    LEGEND_CONFIG_REGION_6, FALSE);

	status =
	    emlxs_dump_cfg_region(hba, fpTxtFile, fpDmpFile, 7,
	    LEGEND_CONFIG_REGION_7, FALSE);

	status =
	    emlxs_dump_cfg_region(hba, fpTxtFile, fpDmpFile, 8,
	    LEGEND_CONFIG_REGION_8, TRUE);

	status =
	    emlxs_dump_cfg_region(hba, fpTxtFile, fpDmpFile, 9,
	    LEGEND_CONFIG_REGION_9, TRUE);

	status =
	    emlxs_dump_cfg_region(hba, fpTxtFile, fpDmpFile, 10,
	    LEGEND_CONFIG_REGION_10, TRUE);

	status =
	    emlxs_dump_cfg_region(hba, fpTxtFile, fpDmpFile, 11,
	    LEGEND_CONFIG_REGION_11, FALSE);

	status =
	    emlxs_dump_cfg_region(hba, fpTxtFile, fpDmpFile, 12,
	    LEGEND_CONFIG_REGION_12, FALSE);

	status =
	    emlxs_dump_cfg_region(hba, fpTxtFile, fpDmpFile, 13,
	    LEGEND_CONFIG_REGION_13, FALSE);

	status =
	    emlxs_dump_cfg_region(hba, fpTxtFile, fpDmpFile, 14,
	    LEGEND_CONFIG_REGION_14, FALSE);

	status =
	    emlxs_dump_cfg_region(hba, fpTxtFile, fpDmpFile, 15,
	    LEGEND_CONFIG_REGION_15, FALSE);

	status =
	    emlxs_dump_cfg_region(hba, fpTxtFile, fpDmpFile, 16,
	    LEGEND_CONFIG_REGION_16, FALSE);

	status =
	    emlxs_dump_cfg_region(hba, fpTxtFile, fpDmpFile, 17,
	    LEGEND_CONFIG_REGION_17, FALSE);

	status =
	    emlxs_dump_cfg_region(hba, fpTxtFile, fpDmpFile, 18,
	    LEGEND_CONFIG_REGION_18, FALSE);

	status =
	    emlxs_dump_cfg_region(hba, fpTxtFile, fpDmpFile, 19,
	    LEGEND_CONFIG_REGION_19, FALSE);

	status =
	    emlxs_dump_cfg_region(hba, fpTxtFile, fpDmpFile, 20,
	    LEGEND_CONFIG_REGION_20, FALSE);

	status =
	    emlxs_dump_cfg_region(hba, fpTxtFile, fpDmpFile, 21,
	    LEGEND_CONFIG_REGION_21, FALSE);

	status =
	    emlxs_dump_cfg_region(hba, fpTxtFile, fpDmpFile, 22,
	    LEGEND_CONFIG_REGION_22, FALSE);

	status =
	    emlxs_dump_cfg_region(hba, fpTxtFile, fpDmpFile, 23,
	    LEGEND_CONFIG_REGION_23, FALSE);

	status =
	    emlxs_dump_cfg_region(hba, fpTxtFile, fpDmpFile, 24,
	    LEGEND_CONFIG_REGION_24, FALSE);

	status =
	    emlxs_dump_cfg_region(hba, fpTxtFile, fpDmpFile, 25,
	    LEGEND_CONFIG_REGION_25, FALSE);

	status =
	    emlxs_dump_cfg_region(hba, fpTxtFile, fpDmpFile, 26,
	    LEGEND_CONFIG_REGION_26, FALSE);

	status =
	    emlxs_dump_cfg_region(hba, fpTxtFile, fpDmpFile, 27,
	    LEGEND_CONFIG_REGION_27, FALSE);

	status =
	    emlxs_dump_cfg_region(hba, fpTxtFile, fpDmpFile, 28,
	    LEGEND_CONFIG_REGION_28, FALSE);

	status =
	    emlxs_dump_cfg_region(hba, fpTxtFile, fpDmpFile, 29,
	    LEGEND_CONFIG_REGION_29, FALSE);

	status =
	    emlxs_dump_cfg_region(hba, fpTxtFile, fpDmpFile, 30,
	    LEGEND_CONFIG_REGION_30, FALSE);

	status =
	    emlxs_dump_cfg_region(hba, fpTxtFile, fpDmpFile, 31,
	    LEGEND_CONFIG_REGION_31, FALSE);

	status =
	    emlxs_dump_cfg_region(hba, fpTxtFile, fpDmpFile, 32,
	    LEGEND_CONFIG_REGION_32, FALSE);

	return (status);

} /* emlxs_dump_cfg_regions() */


/*ARGSUSED*/
static uint32_t
emlxs_dump_os_version(
	emlxs_hba_t *hba,
	emlxs_file_t *fpTxtFile,
	emlxs_file_t *fpDmpFile)
{
	uint32_t status;
	char *buf1;
	char *buf2;
	uint32_t buf1_size;
	uint32_t buf2_size;

	buf1_size = 1024;
	buf2_size = 1024;

	buf1 = (char *)kmem_zalloc(buf1_size, KM_SLEEP);
	buf2 = (char *)kmem_zalloc(buf2_size, KM_SLEEP);

	/* First, write the OS Name string into the buffer */
	(void) strlcpy(buf1, utsname.sysname, buf1_size);

	/* Second, write the Version Info into the buffer */
	(void) snprintf(buf2, buf2_size, ", %s", utsname.release);
	(void) strlcat(buf1, buf2, buf1_size);

	status =
	    emlxs_dump_string_txtfile(fpTxtFile, buf1, LEGEND_REV_INFO,
	    LEGEND_REV_OS_VERSION, 0);

	status =
	    emlxs_dump_string_dmpfile(fpDmpFile, buf1, SID_REV_INFO,
	    LEGEND_REV_INFO, LEGEND_REV_OS_VERSION);

	kmem_free(buf1, buf1_size);
	kmem_free(buf2, buf2_size);

	return (status);

} /* emlxs_dump_os_version() */


/*ARGSUSED*/
static uint32_t
emlxs_dump_drv_version(
	emlxs_hba_t *hba,
	emlxs_file_t *fpTxtFile,
	emlxs_file_t *fpDmpFile)
{
	uint32_t status;
	char *buf1;
	char *buf2;
	uint32_t buf1_size;
	uint32_t buf2_size;

	buf1_size = 1024;
	buf2_size = 1024;

	buf1 = (char *)kmem_zalloc(buf1_size, KM_SLEEP);
	buf2 = (char *)kmem_zalloc(buf2_size, KM_SLEEP);

	/* Write the Driver Type into the buffer */
	(void) strlcpy(buf1, "Driver Type: ", buf1_size);
	(void) strlcat(buf1, DUMP_DRV_LEADVILLE, buf1_size);

	/* Write the Driver Name into the buffer */
	(void) snprintf(buf2, buf2_size, "%s", DRIVER_NAME);
	(void) strlcat(buf1, "\n Driver Name: ", buf1_size);
	(void) strlcat(buf1, buf2, buf1_size);

	/* Write the Driver Version into the buffer */
	(void) snprintf(buf2, buf2_size, "%s", emlxs_version);
	(void) strlcat(buf1, "\n Driver Version: ", buf1_size);
	(void) strlcat(buf1, buf2, buf1_size);

	status =
	    emlxs_dump_string_txtfile(fpTxtFile, buf1, LEGEND_REV_INFO,
	    LEGEND_REV_DRV_VERSION, 0);

	status =
	    emlxs_dump_string_dmpfile(fpDmpFile, buf1, SID_REV_INFO,
	    LEGEND_REV_INFO, LEGEND_REV_DRV_VERSION);

	kmem_free(buf1, buf1_size);
	kmem_free(buf2, buf2_size);

	return (status);

} /* emlxs_dump_drv_version() */


static uint32_t
emlxs_dump_file_create(
	emlxs_hba_t *hba,
	emlxs_file_t ** fpTxtFile,
	emlxs_file_t ** fpDmpFile,
	emlxs_file_t ** fpCeeFile)
{
	if (fpTxtFile) {
		/* Create the Dump Files */
		if ((*fpTxtFile = emlxs_fopen(hba, EMLXS_TXT_FILE)) == NULL) {
			return (1);
		}
	}

	if (fpCeeFile) {
		*fpCeeFile = NULL;

		if ((hba->model_info.device_id == PCI_DEVICE_ID_HORNET) ||
		    (hba->model_info.chip == EMLXS_BE2_CHIP) ||
		    (hba->model_info.chip == EMLXS_BE3_CHIP)) {
			if ((*fpCeeFile =
			    emlxs_fopen(hba, EMLXS_CEE_FILE)) == NULL) {
				emlxs_fdelete(*fpTxtFile);
				return (1);
			}
		}
	}

	if (fpDmpFile) {
		if ((*fpDmpFile = emlxs_fopen(hba, EMLXS_DMP_FILE)) == NULL) {
			emlxs_fdelete(*fpTxtFile);
			emlxs_fdelete(*fpCeeFile);
			return (1);
		}

		/* Initialize the DMP File */
		/* Write the single-byte Dump Identification */
		/* SID to the DMP File */
#ifdef EMLXS_LITTLE_ENDIAN
		emlxs_fputc(SID_DUMP_ID_LE, *fpDmpFile);
#endif /* EMLXS_LITTLE_ENDIAN */

#ifdef EMLXS_BIG_ENDIAN
		emlxs_fputc(SID_DUMP_ID_BE, *fpDmpFile);
#endif /* EMLXS_BIG_ENDIAN */

		emlxs_fputc(SID_NULL, *fpDmpFile);
		emlxs_fputc(SID_NULL, *fpDmpFile);
		emlxs_fputc(SID_NULL, *fpDmpFile);
		emlxs_fflush(*fpDmpFile);
	}

	return (0);

} /* emlxs_dump_file_create() */


static uint32_t
emlxs_dump_file_terminate(
	emlxs_hba_t *hba,
	emlxs_file_t *fpTxtFile,
	emlxs_file_t *fpDmpFile,
	emlxs_file_t *fpCeeFile)
{

	if (fpTxtFile) {
		/* Write a suitable string to the Dump TXT File */
		(void) emlxs_fprintf(fpTxtFile, "Dump File End\n");
		emlxs_fflush(fpTxtFile);
	}

	if (fpCeeFile) {
		if (hba->model_info.device_id == PCI_DEVICE_ID_HORNET) {
			(void) emlxs_fprintf(fpCeeFile, "Dump File End\n");
		}

		emlxs_fflush(fpCeeFile);
	}

	/* Write the single-byte Dump Termination SID to the DMP File */
	if (fpDmpFile) {
		emlxs_fputc(SID_DUMP_TERM, fpDmpFile);
		emlxs_fflush(fpDmpFile);
	}


	return (0);

} /* emlxs_dump_file_terminate() */


static uint32_t
emlxs_dump_file_close(
	emlxs_file_t *fpTxtFile,
	emlxs_file_t *fpDmpFile,
	emlxs_file_t *fpCeeFile)
{

	if (fpTxtFile) {
		(void) emlxs_fclose(fpTxtFile);
	}

	if (fpCeeFile) {
		(void) emlxs_fclose(fpCeeFile);
	}

	if (fpDmpFile) {
		(void) emlxs_fclose(fpDmpFile);
	}

	return (0);

} /* emlxs_dump_file_close() */


/* ************************************************************************* */
/* ************************************************************************* */
/* Dump Generators, High Level */
/* ************************************************************************* */
/* ************************************************************************* */


static uint32_t
emlxs_dump_rev_info(
	emlxs_hba_t *hba,
	emlxs_file_t *fpTxtFile,
	emlxs_file_t *fpDmpFile)
{
	(void) emlxs_dump_os_version(hba, fpTxtFile, fpDmpFile);
	(void) emlxs_dump_drv_version(hba, fpTxtFile, fpDmpFile);
	return (0);

} /* emlxs_dump_rev_info() */


/* ARGSUSED */
static uint32_t
emlxs_dump_hba_info(
	emlxs_hba_t *hba,
	emlxs_file_t *fpTxtFile,
	emlxs_file_t *fpDmpFile,
	uint32_t dump_type)
{
	(void) emlxs_dump_model(hba, fpTxtFile, fpDmpFile);
	(void) emlxs_dump_wwn(hba, fpTxtFile, fpDmpFile);
	(void) emlxs_dump_serial_number(hba, fpTxtFile, fpDmpFile);
	(void) emlxs_dump_fw_version(hba, fpTxtFile, fpDmpFile);
	(void) emlxs_dump_boot_version(hba, fpTxtFile, fpDmpFile);


	return (0);

} /* emlxs_dump_hba_info() */


/* ************************************************************************* */
/* emlxs_dump_table_check */
/* Examine Dump Table, and determine its size. */
/* Count and include ID SIDs, and the TERM SID, */
/* but not the Pointer at Addr 654. */
/* See comments for CC_DUMP_USE_ALL_TABLES for additional description. */
/* ************************************************************************* */
static uint32_t
emlxs_dump_table_check(
	emlxs_hba_t *hba,
	uint32_t *pSize)
{
	emlxs_port_t *port = &PPORT;
	int fDone = FALSE;	/* loop control flag */
	uint32_t tableSize = 0;	/* dump table size (word count) */
	MAILBOX *mb;
	MAILBOXQ *mbq;
	uint32_t DumpTableAddr;
	DUMP_TABLE_ENTRY entry;

	*pSize = 0;

	/* Read 1 word from low memory at address 654; */
	/* save the returned Dump Table Base Address */

	mbq =
	    (MAILBOXQ *)kmem_zalloc(sizeof (MAILBOXQ), KM_SLEEP);
	mb = (MAILBOX *) mbq;

	/* Read the dump table address */
	emlxs_mb_dump(hba, mbq, 0x654, 1);
	if (EMLXS_SLI_ISSUE_MBOX_CMD(hba, mbq, MBX_WAIT, 0) != MBX_SUCCESS) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
		    "Unable to read dump table address. "\
		    "offset=0x654 status=%x",
		    mb->mbxStatus);

		kmem_free(mbq, sizeof (MAILBOXQ));
		return (1);
	}

	DumpTableAddr = mb->un.varDmp.resp_offset;

	if (DumpTableAddr == 0) {
		kmem_free(mbq, sizeof (MAILBOXQ));
		return (1);
	}

	/* Now loop reading Dump Table Entries.. */
	/* break out when we see a Terminator SID */
	while (!fDone) {
		emlxs_mb_dump(hba, mbq, DumpTableAddr, 2);
		if (EMLXS_SLI_ISSUE_MBOX_CMD(hba, mbq, MBX_WAIT, 0) !=
		    MBX_SUCCESS) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
			    "Unable to read dump table entry. "\
			    "offset=%x status=%x",
			    DumpTableAddr, mb->mbxStatus);

			kmem_free(mbq, sizeof (MAILBOXQ));
			return (1);
		}

		entry.un.PortBlock.un.w[0] = mb->un.varWords[4];

		switch (entry.un.PortBlock.un.s.sid) {
		/* New Dump Table */
		case SID_ID01:
			tableSize++;
			DumpTableAddr += 4;
			break;

#ifdef CC_DUMP_USE_ALL_TABLES
		/* New Dump Table */
		case SID_ID02:
		case SID_ID03:
			tableSize++;
			DumpTableAddr += 4;
			break;
#else
		/* New Dump Table */
		case SID_ID02:
		case SID_ID03:
			tableSize++;
			fDone = TRUE;
			break;
#endif /* CC_DUMP_USE_ALL_TABLES */

		/* Dump Table(s) Termination - all done */
		case SID_TERM:
			tableSize++;
			fDone = TRUE;
			break;

			/* Dump Table Entry */
		default:
			tableSize += 2;
			DumpTableAddr += 8;
			break;
		}

	}	/* end while */

	*pSize = (tableSize * 4); /* return the total Dump Table size */

	kmem_free(mbq, sizeof (MAILBOXQ));
	return (0);

} /* emlxs_dump_table_check() */


/* ************************************************************************ */
/* emlxs_dump_table_read */
/* Read the Dump Table and store it, for use */
/* subsequently in emlxs_dump_hba_memory. */
/* See comments for CC_DUMP_USE_ALL_TABLES for additional description. */
/* ************************************************************************ */
static uint32_t
emlxs_dump_table_read(
	emlxs_hba_t *hba,
	emlxs_file_t *fpTxtFile,
	uint32_t **ppDumpTable,
	uint32_t *pDumpTableSize)
{
	emlxs_port_t *port = &PPORT;
	uint32_t status = 0;
	int fDone = FALSE;
	MAILBOXQ *mbq;
	MAILBOX *mb;
	uint32_t *pDumpTableEntry;
	uint32_t DumpTableAddr;
	DUMP_TABLE_ENTRY entry;

	char buf2[256];
	char *buf1;
	uint32_t size = (32 * 1024);

	/* First, check the dump table and if valid, get its size */
	status = emlxs_dump_table_check(hba, pDumpTableSize);
	if (status != 0) {
		return (status);
	}

	buf1 = (char *)kmem_zalloc(size, KM_SLEEP);

	/* Allocate a buffer to hold the Dump Table */
	*ppDumpTable = (uint32_t *)kmem_zalloc(*pDumpTableSize, KM_SLEEP);

	pDumpTableEntry = *ppDumpTable;

	/* Read 1 word from low memory at address 654; */
	/* save the returned Dump Table Base Address */
	mbq =
	    (MAILBOXQ *)kmem_zalloc(sizeof (MAILBOXQ), KM_SLEEP);

	mb = (MAILBOX *) mbq;

	/* Read the dump table address */
	emlxs_mb_dump(hba, mbq, 0x654, 1);
	if (EMLXS_SLI_ISSUE_MBOX_CMD(hba, mbq, MBX_WAIT, 0) != MBX_SUCCESS) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
		    "Unable to read dump table address. "\
		    "offset=0x654 status=%x",
		    mb->mbxStatus);

		kmem_free(buf1, size);
		kmem_free(mbq, sizeof (MAILBOXQ));

		kmem_free(*ppDumpTable, *pDumpTableSize);
		*pDumpTableSize = 0;
		*ppDumpTable = NULL;

		return (1);
	}

	DumpTableAddr = mb->un.varDmp.resp_offset;

	if (DumpTableAddr == 0) {
		kmem_free(buf1, size);
		kmem_free(mbq, sizeof (MAILBOXQ));

		kmem_free(*ppDumpTable, *pDumpTableSize);
		*pDumpTableSize = 0;
		*ppDumpTable = NULL;

		return (1);
	}


	/* Now loop reading Dump Table Entries.. */
	/* break out when we see a Terminator SID */
	while (!fDone) {
		emlxs_mb_dump(hba, mbq, DumpTableAddr, 2);
		if (EMLXS_SLI_ISSUE_MBOX_CMD(hba, mbq, MBX_WAIT, 0) !=
		    MBX_SUCCESS) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
			    "Unable to read dump table entry. "\
			    "offset=%x status=%x",
			    DumpTableAddr, mb->mbxStatus);

			kmem_free(buf1, size);
			kmem_free(mbq, sizeof (MAILBOXQ));

			kmem_free(*ppDumpTable, *pDumpTableSize);
			*pDumpTableSize = 0;
			*ppDumpTable = NULL;

			return (1);
		}

		(void) snprintf(buf2, sizeof (buf2), "\n Addr=%08x: ",
		    mb->un.varDmp.base_adr);
		(void) strlcat(buf1, buf2, size);

		entry.un.PortBlock.un.w[0] = mb->un.varWords[4];
		*pDumpTableEntry++ = mb->un.varWords[4];

		switch (entry.un.PortBlock.un.s.sid) {
			/* New Dump Table */
		case SID_ID01:
			(void) snprintf(buf2, sizeof (buf2), "w0=%08x",
			    entry.un.PortBlock.un.w[0]);
			(void) strlcat(buf1, buf2, size);
			DumpTableAddr += 4;
			break;

#ifdef CC_DUMP_USE_ALL_TABLES
		/* New Dump Table */
		case SID_ID02:
		case SID_ID03:
			(void) snprintf(buf2, sizeof (buf2), "w0=%08x",
			    entry.un.PortBlock.un.w[0]);
			(void) strlcat(buf1, buf2, size);
			DumpTableAddr += 4;
			break;
#else
			/* New Dump Table */
		case SID_ID02:
		case SID_ID03:
			(void) snprintf(buf2, sizeof (buf2), "w0=%08x",
			    entry.un.PortBlock.un.w[0]);
			(void) strlcat(buf1, buf2, size);
			fDone = TRUE;
			break;
#endif /* CC_DUMP_USE_ALL_TABLES */

			/* Dump Table(s) Termination - all done */
		case SID_TERM:
			(void) snprintf(buf2, sizeof (buf2), "w0=%08x",
			    entry.un.PortBlock.un.w[0]);
			(void) strlcat(buf1, buf2, size);
			fDone = TRUE;
			break;

			/* Dump Table Entry */
		default:
			entry.un.PortBlock.un.w[1] = mb->un.varWords[5];
			*pDumpTableEntry++ = mb->un.varWords[5];

			(void) snprintf(buf2, sizeof (buf2), "w0=%08x, w1=%08x",
			    entry.un.PortBlock.un.w[0],
			    entry.un.PortBlock.un.w[1]);
			(void) strlcat(buf1, buf2, size);
			DumpTableAddr += 8;
			break;
		}

	}	/* end while */

	status =
	    emlxs_dump_string_txtfile(fpTxtFile, buf1, LEGEND_HBA_MEM_DUMP,
	    LEGEND_HBA_MEM_DUMP_TABLE, 0);

	kmem_free(buf1, size);
	kmem_free(mbq, sizeof (MAILBOXQ));

	if (status != 0) {
		kmem_free(*ppDumpTable, *pDumpTableSize);
		*pDumpTableSize = 0;
		*ppDumpTable = NULL;

		return (status);
	}

	return (0);

} /* emlxs_dump_table_read() */


/* ************************************************************************* */
/* emlxs_dump_hba_memory */
/* Guided by the Dump Table previously read in, */
/* generate the Port Memory Dump. */
/* See comments for CC_DUMP_USE_ALL_TABLES for additional description. */
/* ************************************************************************* */
static uint32_t
emlxs_dump_hba_memory(
	emlxs_hba_t *hba,
	emlxs_file_t *fpDmpFile,
	uint32_t *pDumpTable)
{
	emlxs_port_t *port = &PPORT;
	uint32_t status = 0;
	int fDone = FALSE;
	DUMP_TABLE_ENTRY entry;
	MAILBOXQ *mbq;
	MAILBOX *mb;
	uint32_t byteCount;
	uint32_t byteCountRem;
	uint8_t *pBuf;
	uint8_t *p1;
	uint32_t portAddr;
	int fSwap = FALSE;
	uint32_t offset = 0;
	uint32_t wcount;
	uint32_t total = 0;

#ifdef EMLXS_BIG_ENDIAN
	fSwap = TRUE;
#endif /* EMLXS_BIG_ENDIAN */

	if (!fpDmpFile) {
		return (1);
	}

	mbq =
	    (MAILBOXQ *)kmem_zalloc(sizeof (MAILBOXQ), KM_SLEEP);

	mb = (MAILBOX *) mbq;

	/* loop reading Dump Table Entries.. break out when */
	/* we see a Terminator SID */
	while (!fDone) {
		entry.un.PortBlock.un.w[0] = *pDumpTable++;

		switch (entry.un.PortBlock.un.s.sid) {

			/* New Dump Table */
		case SID_ID01:
			break;

#ifdef CC_DUMP_USE_ALL_TABLES
			/* New Dump Table */
		case SID_ID02:
		case SID_ID03:
			break;
#else
			/* New Dump Table */
		case SID_ID02:
		case SID_ID03:
			fDone = TRUE;
			break;
#endif /* CC_DUMP_USE_ALL_TABLES */

			/* Dump Table(s) Termination - all done */
		case SID_TERM:
			fDone = TRUE;
			break;

		default:
			/* Dump Table Entry */
			entry.un.PortBlock.un.w[1] = *pDumpTable++;

#ifdef CC_DUMP_FW_BUG_1
			if (entry.un.PortBlock.un.w[1] == 0x3E0000) {
				break;
			}
#endif /* CC_DUMP_FW_BUG_1 */

			/* Check if indirect address, and */
			/* obtain the new address if so */
			if ((entry.un.PortBlock.un.s.addr & 0x80000000) != 0) {
				offset =
				    (entry.un.PortBlock.un.s.
				    addr & 0x01FFFFFF);
				emlxs_mb_dump(hba, mbq, offset, 1);
				if (EMLXS_SLI_ISSUE_MBOX_CMD(hba, mbq, MBX_WAIT,
				    0) != MBX_SUCCESS) {
					EMLXS_MSGF(EMLXS_CONTEXT,
					    &emlxs_init_debug_msg,
					    "Unable to read dump table entry. "\
					    "offset=%x status=%x",
					    offset, mb->mbxStatus);

					kmem_free(mbq, sizeof (MAILBOXQ));
					return (1);
				}

				/* replace the indirect address in the */
				/* Dump Table */
				entry.un.PortBlock.un.s.addr =
				    mb->un.varWords[4];
			}

			/* determine byte count to dump */
			byteCount = entry.un.PortBlock.un.s.bc;
			if (entry.un.PortBlock.un.s.sid & SID_MULT_ELEM) {
				if (entry.un.PortStruct.un.s.count == 0) {
					byteCount =
					    256 *
					    entry.un.PortStruct.un.s.length;
				} else {
					byteCount =
					    entry.un.PortStruct.un.s.count *
					    entry.un.PortStruct.un.s.length;
				}
			}

			total += byteCount;
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
			    "Dump: addr=%x count=%d total=%d", offset,
			    byteCount, total);

			/* allocate a buffer to receive the dump data */
			pBuf = (uint8_t *)kmem_zalloc(byteCount, KM_SLEEP);

			/* loop issuing MBX commands, 18x measly words at */
			/* a time */

			/* init vars */
			byteCountRem = byteCount;
			p1 = pBuf;
			portAddr = entry.un.PortBlock.un.s.addr;

			for (;;) {
				if (byteCountRem == 0) {
					break;
				}

				wcount =
				    (byteCountRem / 4 >=
				    0x18) ? 0x18 : (byteCountRem / 4);
				emlxs_mb_dump(hba, mbq, portAddr, wcount);
				if (EMLXS_SLI_ISSUE_MBOX_CMD(hba, mbq, MBX_WAIT,
				    0) != MBX_SUCCESS) {
					EMLXS_MSGF(EMLXS_CONTEXT,
					    &emlxs_init_debug_msg,
					    "Unable to read dump table entry."\
					    " offset=%x wc=%d status=%x",
					    portAddr, wcount, mb->mbxStatus);
					break;
				}

				bcopy((uint8_t *)&mb->un.varWords[4], p1,
				    (mb->un.varDmp.word_cnt * 4));

				byteCountRem -= (mb->un.varDmp.word_cnt * 4);
				p1 += (mb->un.varDmp.word_cnt * 4);
				portAddr += (mb->un.varDmp.word_cnt * 4);

			}	/* end for */

			if (status == 0) {
				if (entry.un.PortBlock.un.s.
				    sid & SID_MULT_ELEM) {
					status =
					    emlxs_dump_port_struct(fpDmpFile,
					    pBuf, byteCount, entry, fSwap);
				} else {
					status =
					    emlxs_dump_port_block(fpDmpFile,
					    pBuf, byteCount, entry, fSwap);
				}
			}

			if (pBuf) {
				kmem_free(pBuf, byteCount);
			}

			break;

		}	/* end switch */

	}	/* end while */

	kmem_free(mbq, sizeof (MAILBOXQ));

	return (status);

} /* emlxs_dump_hba_memory() */


static uint32_t
emlxs_dump_hba(
	emlxs_hba_t *hba,
	emlxs_file_t *fpTxtFile,
	emlxs_file_t *fpDmpFile)
{
	uint32_t status = 0;
	uint32_t *pDumpTable = 0;
	uint32_t DumpTableSize = 0;

	if (hba->sli_mode >= EMLXS_HBA_SLI4_MODE) {
		return (1);
	}

	/* HBA should be in WARM state here */
	status =
	    emlxs_dump_table_read(hba, fpTxtFile, &pDumpTable,
	    &DumpTableSize);
	if (status) {
		return (status);
	}

	status = emlxs_dump_hba_memory(hba, fpDmpFile, pDumpTable);

	if (pDumpTable != 0) {
		kmem_free(pDumpTable, DumpTableSize);
	}

	return (status);

} /* emlxs_dump_hba() */


/* ************************************************************************* */
/* emlxs_dump_drv_region */
/* Common subroutine for all the Dump_Sli"Structures" Routines */
/* NOTE: This routine does not free pBuf. This is by design. */
/* The caller does it. */
/* ************************************************************************* */
static uint32_t
emlxs_dump_drv_region(
	emlxs_hba_t *hba,
	uint32_t regionId,
	uint8_t **pBuf,
	uint32_t *pBufLen)
{  /* ptr to length of buffer */
	uint32_t status;
	uint32_t size;

	*pBuf = NULL;
	*pBufLen = 0;

	size = 0;
	status = emlxs_get_dump_region(hba, regionId, NULL, &size);

	if (status != 0) {
		return (1);
	}

	/* Now that we know the required length, request the actual data */
	*pBuf = (uint8_t *)kmem_zalloc(size, KM_SLEEP);

	status = emlxs_get_dump_region(hba, regionId, *pBuf, &size);

	if (status != 0) {
		kmem_free(*pBuf, size);
		*pBuf = NULL;

		return (1);
	}

	*pBufLen = size;

	return (status);

} /* emlxs_dump_drv_region() */


static uint32_t
emlxs_dump_sli_regs(
	emlxs_hba_t *hba,
	emlxs_file_t *fpDmpFile)
{
	uint32_t status;
	uint8_t *pBuf;	/* ptr to data buffer to receive Dump Region Data */
	uint32_t bufLen = 0;	/* length of buffer */
	int fSwap = FALSE;	/* flag to pass to emlxs_dump_word_dmpfile */

#ifdef EMLXS_BIG_ENDIAN
	fSwap = TRUE;
#endif /* EMLXS_BIG_ENDIAN */

	if (!fpDmpFile) {
		return (1);
	}

	status = emlxs_dump_drv_region(hba, DR_SLI_REGS, &pBuf, &bufLen);

	if (status != 0) {
		return (status);
	}

	status =
	    emlxs_dump_host_block(fpDmpFile, pBuf, bufLen, SID_SLI_REGS,
	    LEGEND_SLI_STRUCTURES, LEGEND_SLI_REGS, fSwap);

	kmem_free(pBuf, bufLen);

	return (status);

} /* emlxs_dump_sli_regs() */


static uint32_t
emlxs_dump_slim(
	emlxs_hba_t *hba,
	emlxs_file_t *fpTxtFile,
	emlxs_file_t *fpDmpFile,
	uint32_t dump_type)
{
	uint32_t status;
	uint8_t *pBuf;	/* ptr to data buffer to receive Dump Region Data */
	uint32_t bufLen = 0;	/* length of buffer */
	int fSwap = FALSE;	/* flag to pass to emlxs_dump_word_dmpfile */

#ifdef EMLXS_BIG_ENDIAN
	fSwap = TRUE;
#endif /* EMLXS_BIG_ENDIAN */

	status = emlxs_dump_drv_region(hba, DR_SLIM, &pBuf, &bufLen);

	if (status != 0) {
		return (status);
	}

	/* The SLIM Dump is only useful if it's a */
	/* Driver-Initiated dump, say, after a HW Error */
	if (dump_type == DUMP_TYPE_DRIVER) {
		status =
		    emlxs_dump_word_txtfile(fpTxtFile, (uint32_t *)pBuf,
		    0x40, LEGEND_SLI_STRUCTURES, LEGEND_SLIM);
	}

	status =
	    emlxs_dump_host_block(fpDmpFile, pBuf, bufLen, SID_SLIM,
	    LEGEND_SLI_STRUCTURES, LEGEND_SLIM, fSwap);

	kmem_free(pBuf, bufLen);

	return (status);

} /* emlxs_dump_slim() */


static uint32_t
emlxs_dump_pcb(
	emlxs_hba_t *hba,
	emlxs_file_t *fpDmpFile)
{
	uint32_t status;
	uint8_t *pBuf;	/* ptr to data buffer to receive Dump Region Data */
	uint32_t bufLen = 0;	/* length of buffer */
	int fSwap = FALSE;	/* flag to pass to emlxs_dump_word_dmpfile */

#ifdef EMLXS_BIG_ENDIAN
	fSwap = TRUE;
#endif /* EMLXS_BIG_ENDIAN */

	if (!fpDmpFile) {
		return (1);
	}

	status = emlxs_dump_drv_region(hba, DR_PCB, &pBuf, &bufLen);
	if (status != 0) {
		return (status);
	}

	status =
	    emlxs_dump_host_block(fpDmpFile, pBuf, bufLen, SID_PCB,
	    LEGEND_SLI_STRUCTURES, LEGEND_PCB, fSwap);

	kmem_free(pBuf, bufLen);

	return (status);

} /* emlxs_dump_pcb() */


static uint32_t
emlxs_dump_mbox(
	emlxs_hba_t *hba,
	emlxs_file_t *fpDmpFile)
{
	uint32_t status;
	uint8_t *pBuf;	/* ptr to data buffer to receive Dump Region Data */
	uint32_t bufLen = 0;	/* length of buffer */
	int fSwap = FALSE;	/* flag to pass to emlxs_dump_word_dmpfile */

#ifdef EMLXS_BIG_ENDIAN
	fSwap = TRUE;
#endif /* EMLXS_BIG_ENDIAN */

	if (!fpDmpFile) {
		return (1);
	}

	status = emlxs_dump_drv_region(hba, DR_MBX, &pBuf, &bufLen);
	if (status != 0) {
		return (status);
	}

	status =
	    emlxs_dump_host_block(fpDmpFile, pBuf, bufLen, SID_MBX,
	    LEGEND_SLI_STRUCTURES, LEGEND_MBX, fSwap);

	kmem_free(pBuf, bufLen);

	return (status);

} /* emlxs_dump_mbox() */


static uint32_t
emlxs_dump_host_pointers(
	emlxs_hba_t *hba,
	emlxs_file_t *fpDmpFile)
{
	uint32_t status;
	uint8_t *pBuf;	/* ptr to data buffer to receive Dump Region Data */
	uint32_t bufLen = 0;	/* length of buffer */
	int fSwap = FALSE;	/* flag to pass to emlxs_dump_word_dmpfile */

#ifdef EMLXS_BIG_ENDIAN
	fSwap = TRUE;
#endif /* EMLXS_BIG_ENDIAN */

	if (!fpDmpFile) {
		return (1);
	}

	status = emlxs_dump_drv_region(hba, DR_HOST_PTRS, &pBuf, &bufLen);
	if (status != 0) {
		return (status);
	}

	status =
	    emlxs_dump_host_block(fpDmpFile, pBuf, bufLen, SID_HOST_PTRS,
	    LEGEND_SLI_STRUCTURES, LEGEND_HOST_PTRS, fSwap);

	kmem_free(pBuf, bufLen);

	return (status);

} /* emlxs_dump_host_pointers() */


static uint32_t
emlxs_dump_port_pointers(
	emlxs_hba_t *hba,
	emlxs_file_t *fpDmpFile)
{
	uint32_t status;
	uint8_t *pBuf;	/* ptr to data buffer to receive Dump Region Data */
	uint32_t bufLen = 0;	/* length of buffer */
	int fSwap = FALSE;	/* flag to pass to emlxs_dump_word_dmpfile */

#ifdef EMLXS_BIG_ENDIAN
	fSwap = TRUE;
#endif /* EMLXS_BIG_ENDIAN */

	if (!fpDmpFile) {
		return (1);
	}

	status = emlxs_dump_drv_region(hba, DR_PORT_PTRS, &pBuf, &bufLen);
	if (status != 0) {
		return (status);
	}

	status =
	    emlxs_dump_host_block(fpDmpFile, pBuf, bufLen, SID_PORT_PTRS,
	    LEGEND_SLI_STRUCTURES, LEGEND_PORT_PTRS, fSwap);

	kmem_free(pBuf, bufLen);

	return (status);

} /* emlxs_dump_port_pointers() */


static uint32_t
emlxs_dump_rings(
	emlxs_hba_t *hba,
	emlxs_file_t *fpDmpFile)
{
	uint32_t status;
	uint8_t *pBuf;	/* ptr to data buffer to receive Dump Region Data */
	uint32_t bufLen = 0;	/* length of buffer */
	int fSwap = FALSE;	/* flag to pass to emlxs_dump_word_dmpfile */

#ifdef EMLXS_BIG_ENDIAN
	fSwap = TRUE;
#endif /* EMLXS_BIG_ENDIAN */

	if (!fpDmpFile) {
		return (1);
	}

	status = emlxs_dump_drv_region(hba, DR_RINGS, &pBuf, &bufLen);
	if (status != 0) {
		return (status);
	}

	status =
	    emlxs_dump_host_struct(fpDmpFile, pBuf, bufLen, sizeof (IOCB),
	    bufLen / sizeof (IOCB), SID_RINGS, LEGEND_SLI_STRUCTURES,
	    LEGEND_RINGS, fSwap);

	kmem_free(pBuf, bufLen);

	return (status);

} /* emlxs_dump_rings() */


static uint32_t
emlxs_dump_drv_internals(
	emlxs_hba_t *hba,
	emlxs_file_t *fpDmpFile)
{
	uint32_t status;
	uint8_t *pBuf;	/* ptr to data buffer to receive Dump Region Data */
	uint32_t bufLen = 0;	/* length of buffer */
	int fSwap = FALSE;	/* flag to pass to emlxs_dump_word_dmpfile */

#ifdef EMLXS_BIG_ENDIAN
	fSwap = TRUE;
#endif /* EMLXS_BIG_ENDIAN */

	if (!fpDmpFile) {
		return (1);
	}

	status = emlxs_dump_drv_region(hba, DR_INTERNAL, &pBuf, &bufLen);
	if (status != 0) {
		return (status);
	}

	status =
	    emlxs_dump_host_block(fpDmpFile, pBuf, bufLen, SID_INTERNAL_SOL,
	    LEGEND_SLI_STRUCTURES, LEGEND_DRIVER_SPEC, fSwap);

	kmem_free(pBuf, bufLen);

	return (status);

} /* emlxs_dump_drv_internals() */


static uint32_t
emlxs_dump_sli_interface(
	emlxs_hba_t *hba,
	emlxs_file_t *fpTxtFile,
	emlxs_file_t *fpDmpFile,
	uint32_t dump_type)
{

	if (hba->sli_mode <= EMLXS_HBA_SLI3_MODE) {
		/* HBA should be in OFFLINE state here */

		(void) emlxs_dump_sli_regs(hba, fpDmpFile);
		(void) emlxs_dump_slim(hba, fpTxtFile, fpDmpFile, dump_type);
		(void) emlxs_dump_pcb(hba, fpDmpFile);
		(void) emlxs_dump_mbox(hba, fpDmpFile);
		(void) emlxs_dump_host_pointers(hba, fpDmpFile);
		(void) emlxs_dump_port_pointers(hba, fpDmpFile);
		(void) emlxs_dump_rings(hba, fpDmpFile);
	}

	(void) emlxs_dump_drv_internals(hba, fpDmpFile);

	return (0);

} /* emlxs_dump_sli_interface() */


static uint32_t
emlxs_dump_menlo_log(
	emlxs_hba_t *hba,
	emlxs_file_t *fpCeeFile)
{
	uint32_t RmStatus;
	int i, j;
	int isWrapped = FALSE;
	char buf1[2048] = { 0 };
	char buf2[2048] = { 0 };

	/* Get Config Command vars */
	menlo_get_config_rsp_t GcBuf;
	menlo_get_config_rsp_t *pGcBuf = &GcBuf;

	/* Get Log Config Command vars */
	uint32_t LcBufSize;
	menlo_rsp_t *pLcBuf = NULL;
	uint32_t NumLogs;
	menlo_log_t *pLcEntry;

	/* Get Log Data Command vars */
	uint32_t LdBufSize;
	menlo_rsp_t *pLdBuf = NULL;
	uint16_t Head;
	uint8_t *pLogEntry;
	char *pLogString;

	/* Get Panic Log Command vars */
	uint32_t PlBufSize;
	menlo_rsp_t *pPlBuf = NULL;
	uint32_t PanicLogEntryCount;
	uint32_t PanicLogEntrySize;

	if (hba->model_info.device_id != PCI_DEVICE_ID_HORNET) {
		return (DFC_INVALID_ADAPTER);
	}

	/* First, issue a GetConfig command, which gives us */
	/* the Log Config and Panic Log sizes */

	RmStatus =
	    emlxs_menlo_get_cfg(hba, pGcBuf, sizeof (menlo_get_config_rsp_t));

	if (RmStatus != 0) {
		goto done;
	}

	LcBufSize = GcBuf.log_cfg_size + 8;
	PlBufSize = GcBuf.panic_log_size;

	pLcBuf = (menlo_rsp_t *)kmem_zalloc(LcBufSize, KM_SLEEP);

	RmStatus = emlxs_menlo_get_logcfg(hba, pLcBuf, LcBufSize);

	if (RmStatus != 0) {
		goto done;
	}

	buf1[0] = 0;
	RmStatus =
	    emlxs_dump_string_txtfile(fpCeeFile, buf1,
	    LEGEND_MENLO_LOG_CONFIG, LEGEND_NULL, 0);

	NumLogs = pLcBuf->log_cfg.num_logs;
	pLcEntry = (menlo_log_t *)&pLcBuf->log_cfg.data;

	buf1[0] = 0;
	(void) snprintf(buf2, sizeof (buf2), "LogId   Entries   Size   Name");
	(void) strlcat(buf1, buf2, sizeof (buf1));
	(void) snprintf(buf2, sizeof (buf2), "\n-----   -------   ----   ----");
	(void) strlcat(buf1, buf2, sizeof (buf1));

	RmStatus = emlxs_dump_string_txtfile(fpCeeFile, buf1, 0, 0, 1);

	for (i = 0; i < (int)NumLogs; i++) {
		buf1[0] = 0;
		(void) snprintf(buf2, sizeof (buf2),
		    "\n %2d      %4d    %4d    %s",
		    pLcEntry[i].id,
		    pLcEntry[i].num_entries,
		    pLcEntry[i].entry_size, pLcEntry[i].name);
		(void) strlcat(buf1, buf2, sizeof (buf1));
		RmStatus =
		    emlxs_dump_string_txtfile(fpCeeFile, buf1, 0, 0, 1);
	}

	/* Now issue a series of GetLogData commands, */
	/* which gives us the actual Logs */

	for (i = 0; i < (int)NumLogs; i++) {
		LdBufSize =
		    (pLcEntry[i].num_entries *pLcEntry[i].entry_size) + 8;

		pLdBuf = (menlo_rsp_t *)kmem_zalloc(LdBufSize, KM_SLEEP);

		RmStatus = emlxs_menlo_get_log(hba, i, pLdBuf, LdBufSize);

		if (RmStatus != 0) {
			goto done;
		}

		/* print a caption for the current log */
		buf1[0] = 0;
		(void) snprintf(buf2, sizeof (buf2), "\n\nLog %d:", i);
		(void) strlcat(buf1, buf2, sizeof (buf1));
		(void) snprintf(buf2, sizeof (buf2), " %s", pLcEntry[i].name);
		(void) strlcat(buf1, buf2, sizeof (buf1));
		(void) snprintf(buf2, sizeof (buf2), "\n");

		for (j = 0; j < 75; j++) {
			(void) strlcat(buf2, "-", sizeof (buf2));
		}

		(void) strlcat(buf1, buf2, sizeof (buf1));
		RmStatus =
		    emlxs_dump_string_txtfile(fpCeeFile, buf1, 0, 0, 1);

		/* check the head entry to determine whether */
		/* the log has wrapped or not */
		Head = pLdBuf->log.head;
		pLogEntry = (uint8_t *)&pLdBuf->log.data;
		pLogString =
		    (char *)&(pLogEntry[Head *pLcEntry[i].entry_size]);

		isWrapped = FALSE;
		if (strlen(pLogString) != 0) {
			isWrapped = TRUE;
		}

		/* if log is wrapped, get entries from the */
		/* Head through the End */
		if (isWrapped) {
			for (j = Head; j < (int)pLcEntry[i].num_entries; j++) {
				pLogString =
				    (char *)&(pLogEntry[j *
				    pLcEntry[i].entry_size]);
				buf1[0] = 0;
				(void) snprintf(buf2, sizeof (buf2),
				    "\n%3d: %s", j, pLogString);
				(void) strlcat(buf1, buf2, sizeof (buf1));
				RmStatus =
				    emlxs_dump_string_txtfile(fpCeeFile, buf1,
				    0, 0, 1);
			}
		}

		/* if wrapped or not, get entries from the Top */
		/* through the Head */
		for (j = 0; j < Head; j++) {
			pLogString =
			    (char *)&(pLogEntry[j * pLcEntry[i].entry_size]);
			buf1[0] = 0;
			(void) snprintf(buf2, sizeof (buf2), "\n%3d: %s", j,
			    pLogString);
			(void) strlcat(buf1, buf2, sizeof (buf1));
			RmStatus =
			    emlxs_dump_string_txtfile(fpCeeFile, buf1, 0, 0,
			    1);
		}
	}	/* end for i */

	/* Now issue a GetPanicLog command, which gives us the Panic Log */

	/* print a caption for the current log */
	(void) strlcpy(buf1, LEGEND_MENLO_LOG_PANIC_REGS, sizeof (buf1));
	buf2[0] = 0;
	for (j = 0; j < 75; j++) {
		(void) strlcat(buf2, "-", sizeof (buf2));
	}
	(void) strlcat(buf1, buf2, sizeof (buf1));
	RmStatus = emlxs_dump_string_txtfile(fpCeeFile, buf1, 0, 0, 1);

	pPlBuf = (menlo_rsp_t *)kmem_zalloc(PlBufSize, KM_SLEEP);

	RmStatus = emlxs_menlo_get_paniclog(hba, pPlBuf, PlBufSize);

	if (RmStatus == 0) {
		buf1[0] = 0;
		(void) snprintf(buf2, sizeof (buf2), "\nType         = %x",
		    pPlBuf->panic_log.type);
		(void) strlcat(buf1, buf2, sizeof (buf1));
		(void) snprintf(buf2, sizeof (buf2), "\nRegsEpc      = %08x",
		    pPlBuf->panic_log.regs_epc);
		(void) strlcat(buf1, buf2, sizeof (buf1));
		(void) snprintf(buf2, sizeof (buf2), "\nRegsCp0Cause = %08x",
		    pPlBuf->panic_log.regs_cp0_cause);
		(void) strlcat(buf1, buf2, sizeof (buf1));
		(void) snprintf(buf2, sizeof (buf2), "\nRegsCp0Stat  = %08x",
		    pPlBuf->panic_log.regs_cp0_status);
		(void) strlcat(buf1, buf2, sizeof (buf1));
		RmStatus =
		    emlxs_dump_string_txtfile(fpCeeFile, buf1, 0, 0, 1);

		buf1[0] = 0;
		for (i = 0; i < MENLO_NUM_GP_REGS; i++) {
			(void) snprintf(buf2, sizeof (buf2),
			    "\nRegsGp[%02x]   = %08x", i,
			    pPlBuf->panic_log.regs_gp[i]);
			(void) strlcat(buf1, buf2, sizeof (buf1));
		}
		RmStatus =
		    emlxs_dump_string_txtfile(fpCeeFile, buf1, 0, 0, 1);

		buf1[0] = 0;
		(void) snprintf(buf2, sizeof (buf2), "\nLogPresent   = %08x",
		    pPlBuf->panic_log.log_present);
		(void) strlcat(buf1, buf2, sizeof (buf1));
		PanicLogEntryCount = pPlBuf->panic_log.num_entries;
		(void) snprintf(buf2, sizeof (buf2), "\nNumEntries   = %08x",
		    PanicLogEntryCount);
		(void) strlcat(buf1, buf2, sizeof (buf1));
		PanicLogEntrySize = pPlBuf->panic_log.entry_size;
		(void) snprintf(buf2, sizeof (buf2), "\nEntrySize    = %d.",
		    PanicLogEntrySize);
		(void) strlcat(buf1, buf2, sizeof (buf1));
		(void) snprintf(buf2, sizeof (buf2), "\nHead Entry   = %d.",
		    pPlBuf->panic_log.head);
		(void) strlcat(buf1, buf2, sizeof (buf1));
		RmStatus =
		    emlxs_dump_string_txtfile(fpCeeFile, buf1, 0, 0, 1);

		/* print a caption for the current log */
		(void) strlcpy(buf1, LEGEND_MENLO_LOG_PANIC_LOGS,
		    sizeof (buf1));
		buf2[0] = 0;
		for (j = 0; j < 75; j++) {
			(void) strlcat(buf2, "-", sizeof (buf2));
		}
		(void) strlcat(buf1, buf2, sizeof (buf2));
		RmStatus =
		    emlxs_dump_string_txtfile(fpCeeFile, buf1, 0, 0, 1);

		/* check the head entry to determine whether the */
		/* log has wrapped or not */
		Head = pPlBuf->panic_log.head;
		pLogEntry = (uint8_t *)&pPlBuf->panic_log.data;
		pLogString = (char *)&(pLogEntry[Head * PanicLogEntrySize]);
		isWrapped = FALSE;
		if (strlen(pLogString) != 0) {
			isWrapped = TRUE;
		}

		/* if log is wrapped, get entries from the */
		/* Head through the End */
		if (isWrapped) {
			for (j = Head; j < (int)PanicLogEntryCount; j++) {
				pLogString =
				    (char *)&(pLogEntry[j *
				    PanicLogEntrySize]);
				buf1[0] = 0;
				(void) snprintf(buf2, sizeof (buf2),
				    "\n%3d: %s", j, pLogString);
				(void) strlcat(buf1, buf2, sizeof (buf2));
				RmStatus =
				    emlxs_dump_string_txtfile(fpCeeFile, buf1,
				    0, 0, 1);
			}
		}
		/* if wrapped or not, get entries from the Top */
		/* through the Head */
		for (j = 0; j < Head; j++) {
			pLogString =
			    (char *)&(pLogEntry[j * PanicLogEntrySize]);
			buf1[0] = 0;
			(void) snprintf(buf2, sizeof (buf2), "\n%3d: %s", j,
			    pLogString);
			(void) strlcat(buf1, buf2, sizeof (buf2));
			RmStatus =
			    emlxs_dump_string_txtfile(fpCeeFile, buf1, 0, 0,
			    1);
		}
	}

	RmStatus = emlxs_dump_string_txtfile(fpCeeFile, "\n\n", 0, 0, 1);

done:

	if (pLdBuf != 0) {
		kmem_free(pLdBuf, LdBufSize);
	}

	if (pLcBuf != 0) {
		kmem_free(pLcBuf, LcBufSize);
	}

	if (pPlBuf != 0) {
		kmem_free(pPlBuf, PlBufSize);
	}

	return (RmStatus);

} /* emlxs_dump_menlo_log() */


static uint32_t
emlxs_dump_saturn_log(
	emlxs_hba_t *hba,
	emlxs_file_t *fpTxtFile,
	emlxs_file_t *fpDmpFile)
{
	emlxs_port_t *port = &PPORT;
	MAILBOXQ *mbq;
	MAILBOX *mb;
	MATCHMAP *mp = NULL;
	uint32_t status;
	uint32_t logSize = 0;
	uintptr_t tempAddress;
	int fSwap = FALSE;
	uint32_t i;
	uint32_t block_size;
	uint32_t offset;

#ifdef EMLXS_BIG_ENDIAN
	fSwap = TRUE;
#endif /* EMLXS_BIG_ENDIAN */

	if (hba->model_info.chip != EMLXS_SATURN_CHIP) {
		return (1);
	}

	mbq =
	    (MAILBOXQ *)kmem_zalloc(sizeof (MAILBOXQ), KM_SLEEP);

	mb = (MAILBOX *) mbq;

	/* Step 1: Call MBX_READ_EVENT_LOG_STATUS to get the log size. */
	for (i = 0; i < 10; i++) {
		bzero((void *)mb, MAILBOX_CMD_BSIZE);
		mb->mbxCommand = MBX_READ_EVENT_LOG_STATUS;
		mbq->mbox_cmpl = NULL;

		if (EMLXS_SLI_ISSUE_MBOX_CMD(hba, mbq, MBX_WAIT, 0) ==
		    MBX_SUCCESS) {
			break;
		}

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
		    "Unable to read event log status. status=%x",
		    mb->mbxStatus);

		if ((mb->mbxStatus & 0xFFFF) == MBXERR_NOT_SUPPORTED ||
		    (mb->mbxStatus & 0xFFFF) == MBX_DRVR_ERROR) {
			(void) emlxs_dump_string_txtfile(fpTxtFile,
			    NV_LOG_NOT_INCLUDED_IN_DMP,
			    LEGEND_NON_VOLATILE_LOG,
			    LEGEND_NV_LOG_DRIVER_NOT_SUPPORTED, 0);

			kmem_free(mbq, sizeof (MAILBOXQ));
			return (1);
		}

		/* The call to get the log size simply fails. */
		/* Retry up to 10 times. */
		if ((mb->mbxStatus & 0xFFFF) != MBX_BUSY) {
			/* Mailbox fails for some unknown reason. */
			/* Put something in the txt to indicate this case. */
			(void) emlxs_dump_string_txtfile(fpTxtFile,
			    NV_LOG_NOT_INCLUDED_IN_DMP,
			    LEGEND_NON_VOLATILE_LOG,
			    LEGEND_NV_LOG_STATUS_ERROR, 0);

			kmem_free(mbq, sizeof (MAILBOXQ));
			return (1);
		}
	}

	if (i >= 10) {
		(void) emlxs_dump_string_txtfile(fpTxtFile,
		    NV_LOG_NOT_INCLUDED_IN_DMP, LEGEND_NON_VOLATILE_LOG,
		    LEGEND_NV_LOG_STATUS_ERROR, 0);

		kmem_free(mbq, sizeof (MAILBOXQ));
		return (1);
	}

	/* Step 2: Use the log size from step 1 to call MBX_READ_EVENT_LOG */
	logSize = mb->un.varLogStat.size;

	if ((mp = emlxs_mem_buf_alloc(hba, logSize)) == 0) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
		    "Unable to allocate receive buffer. "
		    "size=%d",
		    logSize);

		kmem_free(mbq, sizeof (MAILBOXQ));
		return (1);
	}

	for (offset = 0; offset < logSize; offset = offset + 1024) {
		if (logSize - offset < 1024) {
			block_size = logSize - offset;
		} else {
			block_size = 1024;
		}

		tempAddress = (uintptr_t)(mp->phys + offset);

		bzero((void *)mb, MAILBOX_CMD_BSIZE);
		mb->mbxCommand = MBX_READ_EVENT_LOG;	/* 0x38 */
		mb->un.varRdEvtLog.read_log = 1;	/* read log */
		mb->un.varRdEvtLog.mbox_rsp = 0;	/* not using Mailbox */
		mb->un.varRdEvtLog.offset = offset;
		mb->un.varRdEvtLog.un.sp64.tus.f.bdeFlags = 0x0;
		mb->un.varRdEvtLog.un.sp64.tus.f.bdeSize = block_size;
		mb->un.varRdEvtLog.un.sp64.addrLow = PADDR_LO(tempAddress);
		mb->un.varRdEvtLog.un.sp64.addrHigh = PADDR_HI(tempAddress);
		mbq->mbox_cmpl = NULL;

		if (EMLXS_SLI_ISSUE_MBOX_CMD(hba, mbq, MBX_WAIT, 0) !=
		    MBX_SUCCESS) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
			    "Unable to read event log. status=%x",
			    mb->mbxStatus);

			emlxs_mem_buf_free(hba, mp);
			kmem_free(mbq, sizeof (MAILBOXQ));
			return (1);
		}
	}

	/* Step 3: Dump the log to the DMP file as raw data. */

	/* Write a string to text file to direct the user to the DMP */
	/* file for the actual log. */
	status =
	    emlxs_dump_string_txtfile(fpTxtFile, NV_LOG_INCLUDED_IN_DMP,
	    LEGEND_NON_VOLATILE_LOG, LEGEND_NULL, 0);

	/* Write the real log to the DMP file. */
	EMLXS_MPDATA_SYNC(mp->dma_handle, 0, logSize, DDI_DMA_SYNC_FORKERNEL);

	status =
	    emlxs_dump_host_block(fpDmpFile, mp->virt, logSize,
	    SID_NON_VOLATILE_LOG, LEGEND_NON_VOLATILE_LOG, LEGEND_NULL,
	    fSwap);

#ifdef FMA_SUPPORT
	if (emlxs_fm_check_dma_handle(hba, mp->dma_handle)
	    != DDI_FM_OK) {
		EMLXS_MSGF(EMLXS_CONTEXT,
		    &emlxs_invalid_dma_handle_msg,
		    "dump_saturn_log: hdl=%p",
		    mp->dma_handle);
		status = 1;
	}
#endif  /* FMA_SUPPORT */

	emlxs_mem_buf_free(hba, mp);
	kmem_free(mbq, sizeof (MAILBOXQ));
	return (status);

} /* emlxs_dump_saturn_log() */


static uint32_t
emlxs_dump_tigershark_log(
	emlxs_hba_t *hba,
	emlxs_file_t *fpTxtFile,
	emlxs_file_t *fpCeeFile)
{
	emlxs_port_t *port = &PPORT;
	uint32_t rval = 0;
	uint32_t offset;
	uint32_t log_size;
	uint32_t xfer_size;
	uint32_t buffer_size;
	uint8_t *buffer = NULL;
	uint8_t *bptr;
	uint8_t *payload;
	MAILBOXQ *mbq = NULL;
	MAILBOX4 *mb = NULL;
	MATCHMAP *mp = NULL;
	IOCTL_COMMON_MANAGE_FAT *fat;
	mbox_req_hdr_t *hdr_req;

	if ((hba->model_info.chip != EMLXS_BE2_CHIP) &&
	    (hba->model_info.chip != EMLXS_BE3_CHIP)) {
		return (1);
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fw_dump_msg,
	    "Querying FAT...");

	mbq = (MAILBOXQ *)kmem_zalloc(sizeof (MAILBOXQ),
	    KM_SLEEP);

	mb = (MAILBOX4*)mbq;

	if ((mp = emlxs_mem_buf_alloc(hba, (sizeof (mbox_req_hdr_t) +
	    sizeof (IOCTL_COMMON_MANAGE_FAT) + BE_MAX_XFER_SIZE))) == NULL) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fw_dump_msg,
		    "Unable to allocate FAT buffer.");

		rval = 1;
		goto done;
	}

	/* Query FAT */
	mb->un.varSLIConfig.be.embedded = 0;
	mbq->nonembed = (void *)mp;
	mbq->mbox_cmpl = NULL;

	mb->mbxCommand = MBX_SLI_CONFIG;
	mb->mbxOwner = OWN_HOST;

	hdr_req = (mbox_req_hdr_t *)mp->virt;
	hdr_req->subsystem = IOCTL_SUBSYSTEM_COMMON;
	hdr_req->opcode = COMMON_OPCODE_MANAGE_FAT;
	hdr_req->timeout = 0;
	hdr_req->req_length = sizeof (IOCTL_COMMON_MANAGE_FAT);

	fat = (IOCTL_COMMON_MANAGE_FAT *)(hdr_req + 1);
	fat->params.request.fat_operation = QUERY_FAT;
	fat->params.request.read_log_offset = 0;
	fat->params.request.read_log_length = 0;
	fat->params.request.data_buffer_size = BE_MAX_XFER_SIZE;

	if (EMLXS_SLI_ISSUE_MBOX_CMD(hba, mbq, MBX_WAIT, 0) !=
	    MBX_SUCCESS) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fw_dump_msg,
		    "FAT Query failed. status=%x",
		    mb->mbxStatus);

		rval = 1;
		goto done;
	}

	log_size = fat->params.response.log_size;
	buffer_size = fat->params.response.log_size;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fw_dump_msg,
	    "FAT: log_size=%d", log_size);

	if (buffer_size == 0) {
		goto done;
	}

	if ((buffer = (uint8_t *)kmem_alloc(
	    buffer_size, KM_NOSLEEP)) == NULL) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fw_dump_msg,
		    "Unable to allocate log buffer.");

		rval = 1;
		goto done;
	}
	bzero(buffer, buffer_size);

	/* Upload Log */
	bptr = buffer;
	offset = 0;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fw_dump_msg,
	    "Uploading log... (%d bytes)", log_size);

	while (log_size) {
		bzero((void *) mb, MAILBOX_CMD_SLI4_BSIZE);
		bzero((void *) mp->virt, mp->size);

		xfer_size = min(BE_MAX_XFER_SIZE, log_size);

		mb->un.varSLIConfig.be.embedded = 0;
		mbq->nonembed = (void *)mp;
		mbq->mbox_cmpl = NULL;

		mb->mbxCommand = MBX_SLI_CONFIG;
		mb->mbxOwner = OWN_HOST;

		hdr_req = (mbox_req_hdr_t *)mp->virt;
		hdr_req->subsystem = IOCTL_SUBSYSTEM_COMMON;
		hdr_req->opcode = COMMON_OPCODE_MANAGE_FAT;
		hdr_req->timeout = 0;
		hdr_req->req_length =
		    sizeof (IOCTL_COMMON_MANAGE_FAT) + xfer_size;

		fat = (IOCTL_COMMON_MANAGE_FAT *)(hdr_req + 1);
		fat->params.request.fat_operation = RETRIEVE_FAT;
		fat->params.request.read_log_offset = offset;
		fat->params.request.read_log_length = xfer_size;
		fat->params.request.data_buffer_size = BE_MAX_XFER_SIZE;

		if (EMLXS_SLI_ISSUE_MBOX_CMD(hba, mbq, MBX_WAIT, 0) !=
		    MBX_SUCCESS) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fw_dump_msg,
			    "Failed to upload log. status=%x",
			    mb->mbxStatus);

			(void) emlxs_dump_string_txtfile(fpTxtFile,
			    NV_LOG_NOT_INCLUDED_IN_FAT,
			    LEGEND_NON_VOLATILE_LOG,
			    LEGEND_NV_LOG_STATUS_ERROR, 0);

			rval = 1;
			goto done;
		}

		payload = (uint8_t *)(&fat->params.response.data_buffer);

		BE_SWAP32_BCOPY(payload, bptr, xfer_size);

		log_size -= xfer_size;
		offset += xfer_size;
		bptr += xfer_size;
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fw_dump_msg,
	    "Log upload complete.");

	/* Write a string to text file to direct the user to the CEE */
	/* file for the actual log. */
	rval =
	    emlxs_dump_string_txtfile(fpTxtFile, NV_LOG_INCLUDED_IN_FAT,
	    LEGEND_NON_VOLATILE_LOG, LEGEND_NULL, 0);


	/* Write the log to the CEE file. */
	/* First word is the log size */
	bptr = buffer + sizeof (uint32_t);
	log_size = buffer_size - sizeof (uint32_t);
	rval = emlxs_dump_word_dmpfile(fpCeeFile, (uint8_t *)bptr,
	    log_size, 0);

done:

	if (mbq) {
		emlxs_mem_put(hba, MEM_MBOX, (void *)mbq);
	}

	if (mp) {
		emlxs_mem_buf_free(hba, mp);
	}

	if (buffer) {
		kmem_free(buffer, buffer_size);
	}

	if (rval == 0) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fw_dump_msg,
		    "Dump complete.");
	}

	return (rval);

} /* emlxs_dump_tigershark_log() */


extern uint32_t
emlxs_dump_user_event(
	emlxs_hba_t *hba)
{
	emlxs_port_t *port = &PPORT;
	uint32_t status;
	emlxs_file_t *fpTxtFile;
	emlxs_file_t *fpDmpFile;
	emlxs_file_t *fpCeeFile;

	mutex_enter(&EMLXS_DUMP_LOCK);

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fw_dump_msg,
	    "User Event: Firmware core dump initiated...");

	status =
	    emlxs_dump_file_create(hba, &fpTxtFile, &fpDmpFile, &fpCeeFile);
	if (status != 0) {
		mutex_exit(&EMLXS_DUMP_LOCK);
		return (1);
	}

	(void) emlxs_dump_rev_info(hba, fpTxtFile, fpDmpFile);
	(void) emlxs_dump_hba_info(hba, fpTxtFile, fpDmpFile, DUMP_TYPE_USER);
	(void) emlxs_dump_parm_table(hba, fpTxtFile, fpDmpFile);
	(void) emlxs_dump_cfg_regions(hba, fpTxtFile, fpDmpFile);

	if (hba->model_info.chip == EMLXS_SATURN_CHIP) {
		(void) emlxs_set_hba_mode(hba, DDI_ONDI);
		(void) emlxs_dump_saturn_log(hba, fpTxtFile, fpDmpFile);
	}

	if ((hba->model_info.chip == EMLXS_BE2_CHIP) ||
	    (hba->model_info.chip == EMLXS_BE3_CHIP)) {
		(void) emlxs_dump_tigershark_log(hba, fpTxtFile, fpCeeFile);
	}

	if (hba->sli_mode <= EMLXS_HBA_SLI3_MODE) {
		(void) emlxs_set_hba_mode(hba, DDI_DIAGDI);
	}

	(void) emlxs_dump_sli_interface(hba, fpTxtFile, fpDmpFile,
	    DUMP_TYPE_USER);

	if (hba->sli_mode <= EMLXS_HBA_SLI3_MODE) {
		(void) emlxs_set_hba_mode(hba, DDI_WARMDI);
	}

	(void) emlxs_dump_hba(hba, fpTxtFile, fpDmpFile);

	(void) emlxs_set_hba_mode(hba, DDI_ONDI);

	status = emlxs_menlo_set_mode(hba, MENLO_MAINTENANCE_MODE_ENABLE);
	if (status == 0) {
		(void) emlxs_dump_menlo_log(hba, fpCeeFile);
		(void) emlxs_menlo_set_mode(hba,
		    MENLO_MAINTENANCE_MODE_DISABLE);
	}

	(void) emlxs_dump_file_terminate(hba, fpTxtFile, fpDmpFile, fpCeeFile);
	(void) emlxs_dump_file_close(fpTxtFile, fpDmpFile, fpCeeFile);

	mutex_exit(&EMLXS_DUMP_LOCK);
	return (0);

} /* emlxs_dump_user_event() */


extern uint32_t
emlxs_dump_temp_event(
	emlxs_hba_t *hba,
	uint32_t tempType,
	uint32_t temp)
{
	emlxs_port_t *port = &PPORT;
	uint32_t status;
	emlxs_file_t *fpTxtFile;

	/* misc vars */
	char sBuf1[512];	/* general purpose string buffer */
	char sBuf2[256];	/* general purpose string buffer */
	char sBuf3[256];	/* general purpose string buffer */

	if (hba->sli_mode == EMLXS_HBA_SLI4_MODE) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fw_dump_msg,
		    "Temperature Event: type=%d temp=%d.  "\
		    "Invalid SLI4 event.",
		    tempType, temp);

		return (1);
	}

	mutex_enter(&EMLXS_DUMP_LOCK);

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fw_dump_msg,
	    "Temperature Event: type=%d temp=%d.  "\
	    "Firmware core dump initiated...",
	    tempType, temp);

	status = emlxs_dump_file_create(hba, &fpTxtFile, 0, 0);
	if (status != 0) {
		mutex_exit(&EMLXS_DUMP_LOCK);
		return (1);
	}

	/* Now generate the Dump */
	/* Note: ignore return (status); if one part fails, */
	/* keep trying to dump more stuff. */

	/* Write a warning at the top of the file */
	(void) strlcpy(sBuf1, "WARNING: HBA Temperature Event:\n",
	    sizeof (sBuf1));
	switch (tempType) {
	case TEMP_TYPE_CRITICAL:
		(void) snprintf(sBuf2, sizeof (sBuf2),
		    " Event Type  = %d (Critical)\n", tempType);
		break;
	case TEMP_TYPE_THRESHOLD:
		(void) snprintf(sBuf2, sizeof (sBuf2),
		    " Event Type  = %d (Threshold)\n", tempType);
		break;
	case TEMP_TYPE_NORMAL:
		(void) snprintf(sBuf2, sizeof (sBuf2),
		    " Event Type  = %d (Normal)\n", tempType);
		break;
	default:
		(void) snprintf(sBuf2, sizeof (sBuf2),
		    " Unknown Event Type  = %d\n", tempType);
		break;
	}
	(void) snprintf(sBuf3, sizeof (sBuf3), " Temperature = %d\n\n", temp);
	(void) strlcat(sBuf1, sBuf2, sizeof (sBuf1));
	(void) strlcat(sBuf1, sBuf3, sizeof (sBuf1));

	(void) emlxs_dump_string_txtfile(fpTxtFile, sBuf1, 0, 0, 0);

	(void) emlxs_dump_rev_info(hba, fpTxtFile, NULL);
	(void) emlxs_dump_hba_info(hba, fpTxtFile, NULL, DUMP_TYPE_TEMP);

	(void) emlxs_dump_file_terminate(hba, fpTxtFile, NULL, NULL);
	(void) emlxs_dump_file_close(fpTxtFile, NULL, NULL);

	mutex_exit(&EMLXS_DUMP_LOCK);
	return (0);

} /* emlxs_dump_temp_event() */


extern uint32_t
emlxs_dump_drv_event(
	emlxs_hba_t *hba)
{
	emlxs_port_t *port = &PPORT;
	uint32_t status;
	emlxs_file_t *fpTxtFile;
	emlxs_file_t *fpDmpFile;
	emlxs_file_t *fpCeeFile;

	mutex_enter(&EMLXS_DUMP_LOCK);

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fw_dump_msg,
	    "Dump Event: Firmware core dump initiated...");

	status =
	    emlxs_dump_file_create(hba, &fpTxtFile, &fpDmpFile, &fpCeeFile);
	if (status != 0) {
		mutex_exit(&EMLXS_DUMP_LOCK);
		return (1);
	}

	if (hba->model_info.chip == EMLXS_SATURN_CHIP) {
		(void) emlxs_set_hba_mode(hba, DDI_ONDI);
		(void) emlxs_dump_saturn_log(hba, fpTxtFile, fpDmpFile);
	}

	if ((hba->model_info.chip == EMLXS_BE2_CHIP) ||
	    (hba->model_info.chip == EMLXS_BE3_CHIP)) {
		(void) emlxs_dump_tigershark_log(hba, fpTxtFile, fpCeeFile);
	}

	if (hba->sli_mode <= EMLXS_HBA_SLI3_MODE) {
		(void) emlxs_set_hba_mode(hba, DDI_DIAGDI);
	}

	(void) emlxs_dump_sli_interface(hba, fpTxtFile, fpDmpFile,
	    DUMP_TYPE_DRIVER);

	if (hba->sli_mode <= EMLXS_HBA_SLI3_MODE) {
		(void) emlxs_set_hba_mode(hba, DDI_WARMDI);
	}

	(void) emlxs_dump_hba(hba, fpTxtFile, fpDmpFile);

	if (hba->sli_mode <= EMLXS_HBA_SLI3_MODE) {
		(void) emlxs_set_hba_mode(hba, DDI_ONDI);
	}

	status = emlxs_menlo_set_mode(hba, MENLO_MAINTENANCE_MODE_ENABLE);
	if (status == 0) {
		(void) emlxs_dump_menlo_log(hba, fpCeeFile);
	}

	/* Now generate the rest of the Dump */
	(void) emlxs_dump_rev_info(hba, fpTxtFile, fpDmpFile);
	(void) emlxs_dump_hba_info(hba, fpTxtFile, fpDmpFile, DUMP_TYPE_DRIVER);
	(void) emlxs_dump_parm_table(hba, fpTxtFile, fpDmpFile);
	(void) emlxs_dump_cfg_regions(hba, fpTxtFile, fpDmpFile);

	(void) emlxs_dump_file_terminate(hba, fpTxtFile, fpDmpFile, fpCeeFile);
	(void) emlxs_dump_file_close(fpTxtFile, fpDmpFile, fpCeeFile);

	/* The last step of the Menlo Dump. */
	(void) emlxs_menlo_reset(hba, MENLO_FW_OPERATIONAL);

	(void) emlxs_set_hba_mode(hba, DDI_WARMDI);

	mutex_exit(&EMLXS_DUMP_LOCK);


	return (0);

} /* emlxs_dump_drv_event() */


/* ARGSUSED */
extern void
emlxs_dump_drv_thread(emlxs_hba_t *hba,
	void *arg1, void *arg2)
{
	(void) emlxs_dump_drv_event(hba);

	/* Clear the Dump flag */
	mutex_enter(&EMLXS_PORT_LOCK);
	hba->flag &= ~FC_DUMP_ACTIVE;
	mutex_exit(&EMLXS_PORT_LOCK);

	return;

} /* emlxs_dump_drv_thread() */


/* ARGSUSED */
extern void
emlxs_dump_user_thread(emlxs_hba_t *hba,
	void *arg1, void *arg2)
{
	(void) emlxs_dump_user_event(hba);

	/* Clear the Dump flag */
	mutex_enter(&EMLXS_PORT_LOCK);
	hba->flag &= ~FC_DUMP_ACTIVE;
	mutex_exit(&EMLXS_PORT_LOCK);

	return;

} /* emlxs_dump_user_thread() */


/* ARGSUSED */
extern void
emlxs_dump_temp_thread(emlxs_hba_t *hba,
	void *arg1, void *arg2)
{
	dump_temp_event_t *temp_event = (dump_temp_event_t *)arg1;

	(void) emlxs_dump_temp_event(temp_event->hba, temp_event->type,
	    temp_event->temp);

	/* Free the temp event object */
	kmem_free(temp_event, sizeof (dump_temp_event_t));

	/* Clear the Dump flag */
	mutex_enter(&EMLXS_PORT_LOCK);
	hba->flag &= ~FC_DUMP_ACTIVE;
	mutex_exit(&EMLXS_PORT_LOCK);

	return;

} /* emlxs_dump_temp_thread() */


/* Schedules a dump thread */
/* temp_type and temp are only valid for type=EMLXS_TEMP_DUMP */
extern void
emlxs_dump(emlxs_hba_t *hba, uint32_t type, uint32_t temp_type, uint32_t temp)
{
	emlxs_port_t *port = &PPORT;
	dump_temp_event_t *temp_event = NULL;

	mutex_enter(&EMLXS_PORT_LOCK);

	/* Check if it is safe to dump */
	if (!(hba->flag & FC_DUMP_SAFE)) {
		mutex_exit(&EMLXS_PORT_LOCK);

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fw_dump_msg,
		    "dump: Dump disabled.");

		return;
	}

	/* Check if a dump is already in progess */
	if (hba->flag & FC_DUMP_ACTIVE) {
		mutex_exit(&EMLXS_PORT_LOCK);

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fw_dump_msg,
		    "dump: Dump already in progress.");

		return;
	}

	/* Prepare to schedule dump */
	switch (type) {
	case EMLXS_DRV_DUMP:
	case EMLXS_USER_DUMP:
		break;

	case EMLXS_TEMP_DUMP:
		temp_event = (dump_temp_event_t *)kmem_alloc(
		    sizeof (dump_temp_event_t), KM_NOSLEEP);

		if (temp_event == NULL) {
			mutex_exit(&EMLXS_PORT_LOCK);

			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fw_dump_msg,
			    "dump: Unable to allocate temp object.");

			return;
		}

		temp_event->hba  = hba;
		temp_event->type = temp_type;
		temp_event->temp = temp;
		break;

	default:
		mutex_exit(&EMLXS_PORT_LOCK);

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fw_dump_msg,
		    "dump: Error: Unknown dump type. (%x)",
		    type);

		return;
	}

	/* Set the Dump-in-progess flag */
	hba->flag |= FC_DUMP_ACTIVE;
	mutex_exit(&EMLXS_PORT_LOCK);

	/* Create a separate thread to run the dump event */
	switch (type) {
	case EMLXS_DRV_DUMP:
		emlxs_thread_spawn(hba, emlxs_dump_drv_thread, NULL, NULL);
		break;

	case EMLXS_TEMP_DUMP:
		emlxs_thread_spawn(hba, emlxs_dump_temp_thread,
		    (void *)temp_event, NULL);
		break;

	case EMLXS_USER_DUMP:
		emlxs_thread_spawn(hba, emlxs_dump_user_thread, NULL, NULL);
		break;
	}

	return;

} /* emlxs_dump() */

extern void
emlxs_dump_wait(emlxs_hba_t *hba)
{
	/* Wait for the Dump flag to clear */
	while ((hba->flag & FC_DUMP_ACTIVE)) {
		BUSYWAIT_MS(1000);
	}

} /* emlxs_dump_wait() */


#endif /* DUMP_SUPPORT */
