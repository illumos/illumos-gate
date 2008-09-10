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
 *
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


#include "lm_acs.h"
#include <lm.h>

static	char	*_SrcFile = __FILE__;

#define	Ptrdiff(a, b) ((((char *)(a) - (char *)(b)) > 0) ? \
	((char *)(a) - (char *)(b)) : 0)

int
lm_drive_geometry(ACS_DISPLAY_RESPONSE *from_server, char **geometry)
{

	char	xml_buf[MAX_MESSAGE_SIZE];
	char	*p, *pp, *qq, *ppp, *qqq;

	char	tmp_str[128];

	int	j;
	int	acs, lsm, panel, drive;
	int	p_diff;

	mms_trace(MMS_DEVP, "In lm_drive_geometry");

	mms_trace(MMS_DEBUG, "lm_drive_geometry: Type is %s",
	    acs_type(from_server->display_type));
	mms_trace(MMS_DEBUG, "lm_drive_geometry: XML length is %d",
	    from_server->display_xml_data.length);
	mms_trace(MMS_DEBUG, "lm_drive_geometry: Data is \n%s",
	    from_server->display_xml_data.xml_data);

	(void) memset(xml_buf, 0, sizeof (xml_buf));
	(void) strncpy(xml_buf, from_server->display_xml_data.xml_data,
	    from_server->display_xml_data.length);

	qq = &xml_buf[0];
	while ((pp = strstr(qq, "</r>")) != NULL) {
		p_diff = Ptrdiff(pp, qq);
		*(qq + p_diff) = '\0';
		qqq = qq;
		j = 0;
		while ((ppp = strstr(qqq, "</f>")) != NULL) {
			p_diff = Ptrdiff(ppp, qqq);
			*(qqq + p_diff) = '\0';
			p = strrchr(qqq, '>') + 1;
			if (j == 0) {
				acs = atoi(p);
				mms_trace(MMS_DEBUG, "acs - %d", acs);
			}
			if (j == 1) {
				lsm = atoi(p);
				mms_trace(MMS_DEBUG, "lsm - %d", lsm);
			}
			if (j == 2) {
				panel = atoi(p);
				mms_trace(MMS_DEBUG, "panel - %d", panel);
			}
			if (j == 3) {
				drive = atoi(p);
				mms_trace(MMS_DEBUG, "drive - %d", drive);
			}
			j++;
			qqq = ppp + 4;
		}
		qq = pp + 4;

	}

	(void) snprintf(tmp_str, sizeof (tmp_str), "%d,%d,%d,%d", acs, lsm,
	    panel, drive);
	*geometry = strdup(tmp_str);
	return (LM_OK);
}

int
lm_obtain_geometry(char *serial, char **geometry, char *cmd, char *tid,
    char *ret_msg)
{
	ACS_DISPLAY_RESPONSE 	*from_server;
	DISPLAY_XML_DATA	display_xml_data;
	acs_rsp_ele_t		*acs_rsp;

	char	dExample[MAX_XML_DATA_SIZE];
	char 	dBegin[] 	=
	    "<request type=\"DISPLAY\"><display><token>display</token>";
	char	dEnd[] 		= "</display></request>";
	char	dTokBegin[]	= "<token>";
	char	dTokEnd[]	= "</token>";
	char	token[100];

	(void) memset(dExample, 0, MAX_XML_DATA_SIZE);
	(void) strcat(dExample, dBegin);
	(void) snprintf(token, sizeof (token), "%s%s%s", dTokBegin, "drive",
	    dTokEnd);
	(void) strcat(dExample, token);
	(void) snprintf(token, sizeof (token), "%s%s%s", dTokBegin, "*",
	    dTokEnd);
	(void) strcat(dExample, token);
	(void) snprintf(token, sizeof (token), "%s%s%s", dTokBegin, "-serial",
	    dTokEnd);
	(void) strcat(dExample, token);
	(void) snprintf(token, sizeof (token), "%s%s%s", dTokBegin, serial,
	    dTokEnd);
	(void) strcat(dExample, token);

	(void) strcat(dExample, dEnd);

	display_xml_data.length = strlen(dExample);
	(void) strcpy(display_xml_data.xml_data, dExample);

	if ((lm_acs_display(&acs_rsp, display_xml_data, cmd, tid,
	    ret_msg)) == LM_ERROR)
		return (LM_ERROR);

	mms_trace(MMS_DEBUG, "lm_obtain_geometry: obtained final response from "
	    "display of drive serial number");

	from_server = (ACS_DISPLAY_RESPONSE *)acs_rsp->acs_rbuf;
	if (from_server->display_status != STATUS_SUCCESS) {
		mms_trace(MMS_ERR,
		    "lm_obtain_geometry: response display status "
		    "failed - %s", acs_status(from_server->display_status));
		lm_handle_acsls_error(from_server->display_status,
		    "acs_display", cmd, tid, ret_msg);
		free(acs_rsp);
		return (LM_ERROR);
	}

	if (lm_drive_geometry(from_server, geometry) != LM_OK) {
		mms_trace(MMS_ERR, "lm_obtain_geometry: obtaining "
		    "drive geometry from acs_display failed");
		free(acs_rsp);
		return (LM_ERROR);
	}

	free(acs_rsp);
	mms_trace(MMS_DEBUG, "lm_obtain_geometry: ACSLS says drive with "
	    "serial number %s has a geometry of %s", serial, *geometry);

	return (LM_OK);
}

int
lm_drive_serial(ACS_DISPLAY_RESPONSE *from_server, char **serial)
{

	char	xml_buf[MAX_MESSAGE_SIZE];
	char	*p, *pp, *qq, *ppp, *qqq;
	int	j;
	int	acs, lsm, panel, drive;
	int	p_diff;

	mms_trace(MMS_DEVP, "In lm_drive_serial");

	mms_trace(MMS_DEBUG, "lm_drive_serial: Type is %s",
	    acs_type(from_server->display_type));
	mms_trace(MMS_DEBUG, "lm_drive_serial: XML length is %d",
	    from_server->display_xml_data.length);
	mms_trace(MMS_DEBUG, "lm_drive_serial: Data is \n%s",
	    from_server->display_xml_data.xml_data);

	(void) memset(xml_buf, 0, sizeof (xml_buf));
	(void) strncpy(xml_buf, from_server->display_xml_data.xml_data,
	    from_server->display_xml_data.length);

	qq = &xml_buf[0];
	while ((pp = strstr(qq, "</r>")) != NULL) {
		p_diff = Ptrdiff(pp, qq);
		*(qq + p_diff) = '\0';
		qqq = qq;
		j = 0;
		while ((ppp = strstr(qqq, "</f>")) != NULL) {
			p_diff = Ptrdiff(ppp, qqq);
			*(qqq + p_diff) = '\0';
			p = strrchr(qqq, '>') + 1;
			if (j == 0) {
				acs = atoi(p);
				mms_trace(MMS_DEBUG, "acs - %d", acs);
			}
			if (j == 1) {
				lsm = atoi(p);
				mms_trace(MMS_DEBUG, "lsm - %d", lsm);
			}
			if (j == 2) {
				panel = atoi(p);
				mms_trace(MMS_DEBUG, "panel - %d", panel);
			}
			if (j == 3) {
				drive = atoi(p);
				mms_trace(MMS_DEBUG, "drive - %d", drive);
			}
			if (j == 4) {
				*serial = strdup(p);
				mms_trace(MMS_DEBUG,
				    "serial num - %s", *serial);
			}
			j++;
			qqq = ppp + 4;
		}
		qq = pp + 4;

	}
	return (LM_OK);
}

int
lm_obtain_serial_num(char *geometry, char **serial, char *cmd, char *tid,
    char *ret_msg)
{
	ACS_DISPLAY_RESPONSE 	*from_server;
	DISPLAY_XML_DATA	display_xml_data;
	acs_rsp_ele_t		*acs_rsp;

	char	dExample[MAX_XML_DATA_SIZE];
	char 	dBegin[] 	=
	    "<request type=\"DISPLAY\"><display><token>display</token>";
	char	dEnd[] 		= "</display></request>";
	char	dTokBegin[]	= "<token>";
	char	dTokEnd[]	= "</token>";
	char	token[100];

	(void) memset(dExample, 0, MAX_XML_DATA_SIZE);
	(void) strcat(dExample, dBegin);
	(void) snprintf(token, sizeof (token), "%s%s%s", dTokBegin, "drive",
	    dTokEnd);
	(void) strcat(dExample, token);
	(void) snprintf(token, sizeof (token), "%s%s%s", dTokBegin, geometry,
	    dTokEnd);
	(void) strcat(dExample, token);
	(void) snprintf(token, sizeof (token), "%s%s%s", dTokBegin, "-f",
	    dTokEnd);
	(void) strcat(dExample, token);
	(void) snprintf(token, sizeof (token), "%s%s%s", dTokBegin,
	    "serial_num", dTokEnd);
	(void) strcat(dExample, token);

	(void) strcat(dExample, dEnd);

	display_xml_data.length = strlen(dExample);
	(void) strcpy(display_xml_data.xml_data, dExample);

	if ((lm_acs_display(&acs_rsp, display_xml_data, cmd, tid,
	    ret_msg)) == LM_ERROR)
		return (LM_ERROR);

	mms_trace(MMS_DEBUG,
	    "lm_obtain_serial_num: obtained final response from "
	    "display of drive serial number");

	from_server = (ACS_DISPLAY_RESPONSE *)acs_rsp->acs_rbuf;
	if (from_server->display_status != STATUS_SUCCESS) {
		mms_trace(MMS_ERR,
		    "lm_obtain_serial_num: response display status "
		    "failed - %s", acs_status(from_server->display_status));
		lm_handle_acsls_error(from_server->display_status,
		    "acs_display", cmd, tid, ret_msg);
		free(acs_rsp);
		return (LM_ERROR);
	}

	if (lm_drive_serial(from_server, serial) != LM_OK) {
		mms_trace(MMS_ERR, "lm_obtain_serial_num: obtaining "
		    "drive serial numbers from acs_display failed");
		free(acs_rsp);
		return (LM_ERROR);
	}

	free(acs_rsp);
	mms_trace(MMS_DEBUG,
	    "lm_obtain_serial_num: ACSLS %s drive's serial number "
	    "is %s", geometry, *serial);

	return (LM_OK);
}

int
lm_set_drive_serial(ACS_DISPLAY_RESPONSE *from_server, char *tid, char *ret_msg)
{

	char	xml_buf[4096];
	char	str1[4096];
	char	*p, *pp, *qq;
	char	*serial;

	char	strs[20][4096];
	char	strss[20][4096];
	char	cmd_str[1024];

	int	rc;
	int	lmpl_tid;
	int	i, ii, j;
	int	acs, lsm, panel, drive;
	int	p_diff;

	lmpl_rsp_ele_t	*ele;

	mms_trace(MMS_DEVP, "in display_drive_info");

	mms_trace(MMS_DEBUG, "Type is %s", acs_type(from_server->display_type));
	mms_trace(MMS_DEBUG, "XML length is %d",
	    from_server->display_xml_data.length);
	mms_trace(MMS_DEBUG, "Data is \n%s",
	    from_server->display_xml_data.xml_data);

	(void) memset(xml_buf, 0, sizeof (xml_buf));
	(void) strncpy(xml_buf, from_server->display_xml_data.xml_data,
	    from_server->display_xml_data.length);

	(void) strcpy(str1, xml_buf);
	i = 0;
	qq = &xml_buf[0];
	while ((pp = strstr(qq, "</r>")) != NULL) {
		(void) strcpy(strs[i], qq);
		p_diff = Ptrdiff(pp, qq);
		strs[i][p_diff] = '\0';
		qq = pp + 4;
		i++;
	}

	for (ii = 0; ii < i; ii++) {
		qq = &strs[ii][0];
		j = 0;
		while ((pp = strstr(qq, "</f>")) != NULL) {
			(void) strcpy(strss[j], qq);
			p_diff = Ptrdiff(pp, qq);
			strss[j][p_diff] = '\0';
			qq = pp + 4;
			p = strrchr(strss[j], '>') + 1;
			if (j == 0) {
				acs = atoi(p);
				mms_trace(MMS_DEBUG, "acs - %d", atoi(p));
			}
			if (j == 1) {
				lsm = atoi(p);
				mms_trace(MMS_DEBUG, "lsm - %d", atoi(p));
			}
			if (j == 2) {
				panel = atoi(p);
				mms_trace(MMS_DEBUG, "panel - %d", atoi(p));
			}
			if (j == 3) {
				drive = atoi(p);
				mms_trace(MMS_DEBUG, "drive - %d", atoi(p));
			}
			if (j == 4) {
				serial = p;
				mms_trace(MMS_DEBUG, "serial num - %s", p);
			}
			j++;
		}

		if (lm_obtain_task_id(&lmpl_tid, &ele) != LM_OK) {
			mms_trace(MMS_CRIT,
			    "lm_set_drive_serial: lm_obtain_task_id "
			    "failed trying to generate attribute command");
			return (LM_ERROR);
		}
		(void) snprintf(cmd_str, sizeof (cmd_str), LM_DRIVE_SERIAL,
		    lmpl_tid, lm.lm_net_cfg.cli_name, acs, lsm, panel, drive,
		    serial);
		mms_trace(MMS_DEBUG, "lm_set_drive_serial: Attribute cmd: %s",
		    cmd_str);

		if ((rc = lm_gen_lmpl_cmd(cmd_str, ele, 0)) == LM_ERROR) {
			mms_trace(MMS_ERR, "lm_set_drive_serial: Internal "
			    "processing error encountered while processing "
			    "lmpl attribute command");
			lm_remove_lmpl_cmd(lmpl_tid, ele);
			return (LM_ERROR);
		} else if (rc != LMPL_FINAL_OK) {
			mms_trace(MMS_DEBUG,
			    "lm_set_drive_serial: Attribute cmd "
			    "did not get a success final response");
			handle_lmpl_cmd_error(rc, "activate", "attribute",
			    tid, ret_msg);
			lm_remove_lmpl_cmd(lmpl_tid, ele);
			return (LM_ERROR);
		}
		mms_trace(MMS_DEBUG, "lm_set_drive_serial: Attribute cmd "
		    "got sucess final response");
		lm_remove_lmpl_cmd(lmpl_tid, ele);
	}
	return (LM_OK);
}

int
lm_drive_serial_num(char *drive, char *tid, char *ret_msg)
{
	ACS_DISPLAY_RESPONSE 	*from_server;
	DISPLAY_XML_DATA	display_xml_data;

	acs_rsp_ele_t		*acs_rsp;

	char	dExample[MAX_XML_DATA_SIZE];
	char 	dBegin[] 	=
	    "<request type=\"DISPLAY\"><display><token>display</token>";
	char	dEnd[] 		= "</display></request>";
	char	dTokBegin[]	= "<token>";
	char	dTokEnd[]	= "</token>";
	char	token[100];

	(void) memset(dExample, 0, MAX_XML_DATA_SIZE);
	(void) strcat(dExample, dBegin);
	(void) snprintf(token, sizeof (token), "%s%s%s", dTokBegin, "drive",
	    dTokEnd);
	(void) strcat(dExample, token);

	if (drive == NULL)
		(void) snprintf(token, sizeof (token), "%s%d%s%s", dTokBegin,
		    lm.lm_acs, ",*,*,*", dTokEnd);
	else
		(void) snprintf(token, sizeof (token), "%s%s%s", dTokBegin,
		    drive, dTokEnd);

	(void) strcat(dExample, token);
	(void) snprintf(token, sizeof (token), "%s%s%s", dTokBegin, "-f",
	    dTokEnd);
	(void) strcat(dExample, token);
	(void) snprintf(token, sizeof (token), "%s%s%s", dTokBegin,
	    "serial_num", dTokEnd);
	(void) strcat(dExample, token);

	(void) strcat(dExample, dEnd);

	display_xml_data.length = strlen(dExample);
	(void) strcpy(display_xml_data.xml_data, dExample);
	if ((lm_acs_display(&acs_rsp, display_xml_data, "activate", tid,
	    ret_msg)) == LM_ERROR)
		return (LM_ERROR);

	mms_trace(MMS_DEBUG, "lm_drive_serial_num: "
	    "obtained final response from "
	    "display of drive serial numbers");

	from_server = (ACS_DISPLAY_RESPONSE *)acs_rsp->acs_rbuf;
	if (from_server->display_status != STATUS_SUCCESS) {
		mms_trace(MMS_ERR,
		    "lm_drive_serial_num: response display status "
		    "failed - %s", acs_status(from_server->display_status));
		lm_handle_acsls_error(from_server->display_status,
		    "acs_display", "activate", tid, ret_msg);
		free(acs_rsp);
		return (LM_ERROR);
	}

	(void) lm_set_drive_serial(from_server, tid, ret_msg);
	mms_trace(MMS_DEVP, "lm_drive_serial_num: Done with set_drive_serial");
	return (LM_OK);
}

int
lm_get_type_info(ACS_DISPLAY_RESPONSE *from_server, char *tid, char *ret_msg)
{

	char	xml_buf[4096];
	char	str1[4096];
	char	*p, *pp, *qq;
	char	msg_str[1024];
	int	p_diff;

	mms_trace(MMS_DEVP, "in display_lsm_info");

	mms_trace(MMS_DEBUG, "Type is %s", acs_type(from_server->display_type));
	mms_trace(MMS_DEBUG, "XML length is %d",
	    from_server->display_xml_data.length);
	(void) memset(xml_buf, 0, sizeof (xml_buf));
	(void) strncpy(xml_buf, from_server->display_xml_data.xml_data,
	    from_server->display_xml_data.length);
	xml_buf[from_server->display_xml_data.length] = '\0';
	mms_trace(MMS_DEBUG, "Data is \n%s", xml_buf);

	(void) strcpy(str1, xml_buf);
	qq = &xml_buf[0];
	pp = strstr(qq, "</r>");
	p_diff = Ptrdiff(pp, qq);
	xml_buf[p_diff] = '\0';

	qq = &xml_buf[0];
	pp = strrchr(qq, '<');
	p_diff = Ptrdiff(pp, qq);
	xml_buf[p_diff] = '\0';
	p = strrchr(xml_buf, '>') + 1;

	mms_trace(MMS_DEBUG, "Library Type is %s", p);

	if (strcmp(lm.lm_type, p) != 0) {
		mms_trace(MMS_ERR, "Library %s is suppose to be of type %s, "
		    "but ACSLS says library with ACSLS cordinates of %d,%d "
		    "is of type %s", lm.lm_name, lm.lm_type, lm.lm_acs, 0, p);
		(void) mms_buf_msgcl(msg_str, sizeof (msg_str), LM_7033_MSG,
		    "type", lm.lm_type, "a_type", p, NULL);
		(void) snprintf(ret_msg, RMBUFSIZE, LM_ERR_FINAL, tid,
		    mms_sym_code_to_str(MMS_INVALID),
		    mms_sym_code_to_str(MMS_LM_E_UNKNOWN), msg_str);
		return (LM_ERROR);
	}

	return (LM_OK);
}

int
lm_lib_type(int lsm, char *tid, char *ret_msg)
{
	int	rc;

	ACS_DISPLAY_RESPONSE 	*from_server;
	DISPLAY_XML_DATA	display_xml_data;

	acs_rsp_ele_t		*acs_rsp;

	char	dExample[MAX_XML_DATA_SIZE];
	char 	dBegin[] 	=
	    "<request type=\"DISPLAY\"><display><token>display</token>";
	char	dEnd[] 		= "</display></request>";
	char	dTokBegin[]	= "<token>";
	char	dTokEnd[]	= "</token>";
	char	token[100];

	(void) memset(dExample, 0, MAX_XML_DATA_SIZE);
	(void) strcat(dExample, dBegin);
	(void) snprintf(token, sizeof (token), "%s%s%s", dTokBegin, "lsm",
	    dTokEnd);
	(void) strcat(dExample, token);
	(void) snprintf(token, sizeof (token), "%s%d,%d%s", dTokBegin,
	    lm.lm_acs, lsm, dTokEnd);
	(void) strcat(dExample, token);
	(void) snprintf(token, sizeof (token), "%s%s%s", dTokBegin, "-f",
	    dTokEnd);
	(void) strcat(dExample, token);
	(void) snprintf(token, sizeof (token), "%s%s%s", dTokBegin, "type",
	    dTokEnd);
	(void) strcat(dExample, token);

	(void) strcat(dExample, dEnd);

	display_xml_data.length = strlen(dExample);
	(void) strcpy(display_xml_data.xml_data, dExample);
	if ((lm_acs_display(&acs_rsp, display_xml_data, "activate", tid,
	    ret_msg)) == LM_ERROR)
		return (LM_ERROR);

	mms_trace(MMS_DEBUG, "lm_lib_type: obtained final response from "
	    "display of lsm type");

	from_server = (ACS_DISPLAY_RESPONSE *)acs_rsp->acs_rbuf;
	if (from_server->display_status != STATUS_SUCCESS) {
		mms_trace(MMS_ERR, "lm_lib_type: response display status "
		    "failed - %s", acs_status(from_server->display_status));
		lm_handle_acsls_error(from_server->display_status,
		    "acs_display", "activate", tid, ret_msg);
		free(acs_rsp);
		return (LM_ERROR);
	}

	rc = lm_get_type_info(from_server, tid, ret_msg);

	mms_trace(MMS_DEVP, "lm_lib_type: Done with get_lsm_info");

	if (rc != LM_OK)
		return (LM_ERROR);
	return (LM_OK);
}

int
lm_get_display_cnt(ACS_DISPLAY_RESPONSE *from_server)
{

	char	xml_buf[4096];
	char	str1[4096];
	char	*p, *pp, *qq;

	int	rc;
	int	p_diff;

	mms_trace(MMS_DEVP, "in lm_get_display_cnt");

	mms_trace(MMS_DEBUG, "Type is %s", acs_type(from_server->display_type));
	mms_trace(MMS_DEBUG, "lm_get_display_cnt: XML length is %d",
	    from_server->display_xml_data.length);
	mms_trace(MMS_DEBUG, "lm_get_display_cnt: Data is \n%s",
	    from_server->display_xml_data.xml_data);

	(void) memset(xml_buf, 0, sizeof (xml_buf));
	(void) strncpy(xml_buf, from_server->display_xml_data.xml_data,
	    from_server->display_xml_data.length);

	(void) strcpy(str1, xml_buf);
	qq = &xml_buf[0];
	pp = strstr(qq, "</r>");
	p_diff = Ptrdiff(pp, qq);
	xml_buf[p_diff] = '\0';

	qq = &xml_buf[0];
	pp = strrchr(qq, '<');
	p_diff = Ptrdiff(pp, qq);
	xml_buf[p_diff] = '\0';
	p = strrchr(xml_buf, '>') + 1;

	rc = atoi(p);
	mms_trace(MMS_DEBUG, "lm_get_display_cnt: count is %s, %d", p, rc);
	return (rc);
}

int
lm_num_panels(int lsm, char *tid, char *ret_msg)
{
	ACS_DISPLAY_RESPONSE 	*from_server;
	DISPLAY_XML_DATA	display_xml_data;

	acs_rsp_ele_t		*acs_rsp;

	char	dExample[MAX_XML_DATA_SIZE];
	char 	dBegin[] 	=
	    "<request type=\"DISPLAY\"><display><token>display</token>";
	char	dEnd[] 		= "</display></request>";
	char	dTokBegin[]	= "<token>";
	char	dTokEnd[]	= "</token>";
	char	token[100];

	(void) memset(dExample, 0, MAX_XML_DATA_SIZE);
	(void) strcat(dExample, dBegin);
	(void) snprintf(token, sizeof (token), "%s%s%s", dTokBegin, "panel",
	    dTokEnd);
	(void) strcat(dExample, token);
	(void) snprintf(token, sizeof (token), "%s%d,%d,%s%s", dTokBegin,
	    lm.lm_acs, lsm, "*", dTokEnd);
	(void) strcat(dExample, token);
	(void) snprintf(token, sizeof (token), "%s%s%s", dTokBegin, "-c",
	    dTokEnd);
	(void) strcat(dExample, token);

	(void) strcat(dExample, dEnd);

	display_xml_data.length = strlen(dExample);
	(void) strcpy(display_xml_data.xml_data, dExample);
	if ((lm_acs_display(&acs_rsp, display_xml_data, "activate", tid,
	    ret_msg)) == LM_ERROR)
		return (LM_ERROR);

	mms_trace(MMS_DEBUG, "lm_num_panels: obtained final response from "
	    "display of count of panels");

	from_server = (ACS_DISPLAY_RESPONSE *)acs_rsp->acs_rbuf;
	if (from_server->display_status != STATUS_SUCCESS) {
		mms_trace(MMS_ERR, "lm_num_panels: response display status "
		    "failed - %s", acs_status(from_server->display_status));
		lm_handle_acsls_error(from_server->display_status,
		    "acs_display", "activate", tid, ret_msg);
		free(acs_rsp);
		return (LM_ERROR);
	}

	lm.lm_panels = lm_get_display_cnt(from_server);
	mms_trace(MMS_DEVP, "lm_num_panels: Number of panels is %d",
	    lm.lm_panels);
	return (LM_OK);
}

int
lm_num_vols(int *num_vols, int lsm, char *tid, char *ret_msg)
{
	ACS_DISPLAY_RESPONSE 	*from_server;
	DISPLAY_XML_DATA	display_xml_data;

	acs_rsp_ele_t		*acs_rsp;

	char	dExample[MAX_XML_DATA_SIZE];
	char 	dBegin[] 	=
	    "<request type=\"DISPLAY\"><display><token>display</token>";
	char	dEnd[] 		= "</display></request>";
	char	dTokBegin[]	= "<token>";
	char	dTokEnd[]	= "</token>";
	char	token[100];

	(void) memset(dExample, 0, MAX_XML_DATA_SIZE);
	(void) strcat(dExample, dBegin);
	(void) snprintf(token, sizeof (token), "%s%s%s", dTokBegin, "volume",
	    dTokEnd);
	(void) strcat(dExample, token);
	(void) snprintf(token, sizeof (token), "%s%s%s", dTokBegin, "*",
	    dTokEnd);
	(void) strcat(dExample, token);
	(void) snprintf(token, sizeof (token), "%s%s%s", dTokBegin, "-home",
	    dTokEnd);
	(void) strcat(dExample, token);
	(void) snprintf(token, sizeof (token), "%s%d,%d,*,*,*%s", dTokBegin,
	    lm.lm_acs, lsm, dTokEnd);
	(void) strcat(dExample, token);
	(void) snprintf(token, sizeof (token), "%s%s%s", dTokBegin, "-c",
	    dTokEnd);
	(void) strcat(dExample, token);
	(void) snprintf(token, sizeof (token), "%s%s%s", dTokBegin, "-status",
	    dTokEnd);
	(void) strcat(dExample, token);
	(void) snprintf(token, sizeof (token), "%s%s%s", dTokBegin, "home",
	    dTokEnd);
	(void) strcat(dExample, token);
	(void) strcat(dExample, dEnd);

	display_xml_data.length = strlen(dExample);
	(void) strcpy(display_xml_data.xml_data, dExample);
	if ((lm_acs_display(&acs_rsp, display_xml_data, "activate", tid,
	    ret_msg)) == LM_ERROR) {
		mms_trace(MMS_DEBUG, "lm_num_vols: lm_acs_display failed");
		return (LM_ERROR);
	}

	mms_trace(MMS_DEBUG, "lm_lib_type: obtained final response from "
	    "acs_display for number of volumes with status of home");

	from_server = (ACS_DISPLAY_RESPONSE *)acs_rsp->acs_rbuf;
	if (from_server->display_status != STATUS_SUCCESS) {
		mms_trace(MMS_ERR, "lm_num_vols: response display status "
		    "failed - %s", acs_status(from_server->display_status));
		lm_handle_acsls_error(from_server->display_status,
		    "acs_display", "activate", tid, ret_msg);
		free(acs_rsp);
		return (LM_ERROR);
	}

	*num_vols = lm_get_display_cnt(from_server);
	mms_trace(MMS_DEVP, "lm_num_vols: Number of volumes in slots - %d",
	    *num_vols);
	return (LM_OK);
}
