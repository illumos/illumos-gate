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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <string.h>
#include <sys/param.h>
#include <assert.h>
#include <pcidr.h>
#include <pcidr_cfga.h>


/*
 * misc config_admin(3cfgadm) related routines
 */

static struct {
	cfga_stat_t stat;
	char *name;
} pcidr_cfga_stat_nametab[] = {
	{CFGA_STAT_NONE, "CFGA_STAT_NONE"},
	{CFGA_STAT_EMPTY, "CFGA_STAT_EMPTY"},
	{CFGA_STAT_DISCONNECTED, "CFGA_STAT_DISCONNECTED"},
	{CFGA_STAT_CONNECTED, "CFGA_STAT_CONNECTED"},
	{CFGA_STAT_UNCONFIGURED, "CFGA_STAT_UNCONFIGURED"},
	{CFGA_STAT_CONFIGURED, "CFGA_STAT_CONFIGURED"},
};
static int pcidr_cfga_stat_nametab_len =
    sizeof (pcidr_cfga_stat_nametab) / sizeof (pcidr_cfga_stat_nametab[0]);

char *
pcidr_cfga_stat_name(cfga_stat_t val)
{
	int i;

	for (i = 0; i < pcidr_cfga_stat_nametab_len; i++) {
		if (pcidr_cfga_stat_nametab[i].stat == val)
			return (pcidr_cfga_stat_nametab[i].name);
	}
	return (NULL);
}


static struct {
	cfga_cmd_t cmd;
	char *name;
} pcidr_cfga_cmd_nametab[] = {
	{CFGA_CMD_NONE, "CFGA_CMD_NONE"},
	{CFGA_CMD_LOAD, "CFGA_CMD_LOAD"},
	{CFGA_CMD_UNLOAD, "CFGA_CMD_UNLOAD"},
	{CFGA_CMD_CONNECT, "CFGA_CMD_CONNECT"},
	{CFGA_CMD_DISCONNECT, "CFGA_CMD_DISCONNECT"},
	{CFGA_CMD_CONFIGURE, "CFGA_CMD_CONFIGURE"},
	{CFGA_CMD_UNCONFIGURE, "CFGA_CMD_UNCONFIGURE"},
};
static int pcidr_cfga_cmd_nametab_len =
    sizeof (pcidr_cfga_cmd_nametab) / sizeof (pcidr_cfga_cmd_nametab[0]);

char *
pcidr_cfga_cmd_name(cfga_cmd_t val)
{
	int i;

	for (i = 0; i < pcidr_cfga_cmd_nametab_len; i++) {
		if (pcidr_cfga_cmd_nametab[i].cmd == val)
			return (pcidr_cfga_cmd_nametab[i].name);
	}
	return (NULL);
}


static struct {
	cfga_cond_t cond;
	char *name;
} pcidr_cfga_cond_nametab[] = {
	{CFGA_COND_UNKNOWN, "CFGA_COND_UNKNOWN"},
	{CFGA_COND_OK, "CFGA_COND_OK"},
	{CFGA_COND_FAILING, "CFGA_COND_FAILING"},
	{CFGA_COND_FAILED, "CFGA_COND_FAILED"},
	{CFGA_COND_UNUSABLE, "CFGA_COND_UNUSABLE"},
};
static int pcidr_cfga_cond_nametab_len =
    sizeof (pcidr_cfga_cond_nametab) / sizeof (pcidr_cfga_cond_nametab[0]);

char *
pcidr_cfga_cond_name(cfga_cond_t val)
{
	int i;

	for (i = 0; i < pcidr_cfga_cond_nametab_len; i++) {
		if (pcidr_cfga_cond_nametab[i].cond == val)
			return (pcidr_cfga_cond_nametab[i].name);
	}
	return (NULL);
}


static struct {
	cfga_err_t err;
	char *name;
} pcidr_cfga_err_nametab[] = {
	{CFGA_OK, "CFGA_OK"},
	{CFGA_NACK, "CFGA_NACK"},
	{CFGA_NOTSUPP, "CFGA_NOTSUPP"},
	{CFGA_OPNOTSUPP, "CFGA_OPNOTSUPP"},
	{CFGA_PRIV, "CFGA_PRIV"},
	{CFGA_BUSY, "CFGA_BUSY"},
	{CFGA_SYSTEM_BUSY, "CFGA_SYSTEM_BUSY"},
	{CFGA_DATA_ERROR, "CFGA_DATA_ERROR"},
	{CFGA_LIB_ERROR, "CFGA_LIB_ERROR"},
	{CFGA_NO_LIB, "CFGA_NO_LIB"},
	{CFGA_INSUFFICENT_CONDITION, "CFGA_INSUFFICENT_CONDITION"},
	{CFGA_INVAL, "CFGA_INVAL"},
	{CFGA_ERROR, "CFGA_ERROR"},
	{CFGA_APID_NOEXIST, "CFGA_APID_NOEXIST"},
	{CFGA_ATTR_INVAL, "CFGA_ATTR_INVAL"},
};
static int pcidr_cfga_err_nametab_len =
    sizeof (pcidr_cfga_err_nametab) / sizeof (pcidr_cfga_err_nametab[0]);

char *
pcidr_cfga_err_name(cfga_err_t val)
{
	int i;

	for (i = 0; i < pcidr_cfga_err_nametab_len; i++) {
		if (pcidr_cfga_err_nametab[i].err == val)
			return (pcidr_cfga_err_nametab[i].name);
	}
	return (NULL);
}


void
pcidr_print_cfga(dlvl_t lvl, cfga_list_data_t *datap, char *prestr)
{
	char *str;

	if (prestr == NULL)
		prestr = "";

	dprint(lvl, "%slogical APID = %s\n", prestr, datap->ap_log_id);
	dprint(lvl, "%sphyiscal APID = %s\n", prestr, datap->ap_phys_id);
	dprint(lvl, "%sAP class = %s\n", prestr, datap->ap_class);

	str = pcidr_cfga_stat_name(datap->ap_r_state);
	if (str == NULL)
		str = "(unrecognized cfga_stat_t value!)";
	dprint(lvl, "%sAP receptacle state = %s\n", prestr, str);

	str = pcidr_cfga_stat_name(datap->ap_o_state);
	if (str == NULL)
		str = "(unrecognized cfga_stat_t value!)";
	dprint(lvl, "%sAP occupant state = %s\n", prestr, str);

	str = pcidr_cfga_cond_name(datap->ap_cond);
	if (str == NULL)
		str = "(unrecognized cfga_cond_t value!)";
	dprint(lvl, "%sAP condition = %s\n", prestr, str);

	dprint(lvl, "%sAP busy indicator = %d\n", prestr, datap->ap_busy);

	str = ctime(&datap->ap_status_time);
	str[strlen(str) - 1] = '\0';	/* get rid of newline */
	dprint(lvl, "%sAP last change time = %ld (%s)\n", prestr,
	    datap->ap_status_time, str);

	dprint(lvl, "%sAP info = %s\n", prestr, datap->ap_info);
	dprint(lvl, "%sAP type = %s\n", prestr, datap->ap_type);
}


/*
 * for use with config_admin(3cfgadm) functions in their
 * <struct cfga_msg *msgp> parameter
 */
int
pcidr_cfga_msg_func(void *datap, const char *msg)
{
	pcidr_cfga_msg_data_t *dp = (pcidr_cfga_msg_data_t *)datap;
	char *prestr = dp->prestr;

	if (prestr == NULL)
		prestr = "";

	dprint(dp->dlvl, "%s%s", prestr, msg);
	return (0);
}


/*
 * for use with config_admin(3cfgadm) functions in their
 * <struct cfga_confirm *confp> parameter
 */
/*ARGSUSED*/
int
pcidr_cfga_confirm_func(void *datap, const char *msg)
{
	return (1);
}


/*
 * returns 0 if successful, -1 if unusuccesful, 1 if the AP already had
 * <cmd> performed on it
 */
int
pcidr_cfga_do_cmd(cfga_cmd_t cmd, cfga_list_data_t *cfga_listp)
{
	char *fn = "pcidr_cfga_do_cmd";
	int rv, i, j;
	char *cmdnm, *cfga_errstr, *apid, *str;
	int cmdarr[2];
	int cmdarr_len = sizeof (cmdarr) / sizeof (cmdarr[0]);

	struct cfga_msg cfga_msg;
	pcidr_cfga_msg_data_t cfga_msg_data;
	struct cfga_confirm cfga_confirm;
	cfga_flags_t cfga_flags;

	cmdnm = pcidr_cfga_cmd_name(cmd);
	assert(cmdnm != NULL);

	apid = cfga_listp->ap_phys_id;
	cfga_msg_data.dlvl = DDEBUG;
	cfga_msg_data.prestr = "pcidr_cfga_do_cmd(msg): ";
	cfga_msg.message_routine = pcidr_cfga_msg_func;
	cfga_msg.appdata_ptr = (void *)&cfga_msg_data;
	cfga_confirm.confirm = pcidr_cfga_confirm_func;
	cfga_confirm.appdata_ptr = NULL;
	cfga_flags = CFGA_FLAG_VERBOSE;

	if (cfga_listp->ap_busy != 0) {
		dprint(DDEBUG, "%s: apid = %s is busy\n",
		    fn, cfga_listp->ap_phys_id);
		return (-1);
	}

	/*
	 * explicitly perform each step that would otherwise be done
	 * implicitly by cfgadm to isolate errors
	 */
	j = 0;
	switch (cmd) {
	case CFGA_CMD_CONFIGURE:
		if (cfga_listp->ap_o_state < CFGA_STAT_CONNECTED) {
			cmdarr[j] = CFGA_CMD_CONNECT;
			j++;
		}
		if (cfga_listp->ap_o_state < CFGA_STAT_CONFIGURED) {
			cmdarr[j] = CFGA_CMD_CONFIGURE;
			j++;
		}
		if (cfga_listp->ap_o_state >= CFGA_STAT_CONFIGURED)
			goto ALREADY;
		break;
	case CFGA_CMD_DISCONNECT:
		if (cfga_listp->ap_o_state >= CFGA_STAT_CONFIGURED) {
			cmdarr[j] = CFGA_CMD_UNCONFIGURE;
			j++;
		}
		if (cfga_listp->ap_o_state >= CFGA_STAT_CONNECTED) {
			cmdarr[j] = CFGA_CMD_DISCONNECT;
			j++;
		}
		if (cfga_listp->ap_r_state <= CFGA_STAT_DISCONNECTED)
			goto ALREADY;
		break;
	default:
		dprint(DDEBUG, "%s: unsupported cmd %d\n", cmd);
		return (-1);
	}
	assert(j <= cmdarr_len);

	for (i = 0; i < j; i++) {
		cmd = cmdarr[i];
		cmdnm = pcidr_cfga_cmd_name(cmd);
		assert(cmdnm != NULL);

		rv = config_change_state(cmd, 1, &apid, NULL, &cfga_confirm,
		    &cfga_msg, &cfga_errstr, cfga_flags);
		if (rv != CFGA_OK) {
			dprint(DDEBUG, "%s: command %s failed on apid %s",
			    fn, cmdnm, apid);

			str = pcidr_cfga_err_name(rv);
			if (str == NULL)
				str = "unrecognized rv!";
			dprint(DDEBUG, ": rv = %d (%s)", rv, str);

			if (cfga_errstr != NULL) {
				dprint(DDEBUG, ", error string = "
				    "\"%s\"", cfga_errstr);
				free(cfga_errstr);
			}
			dprint(DDEBUG, "\n");
			return (-1);
		}
	}

	return (0);
	/*NOTREACHED*/
ALREADY:
	dprint(DDEBUG, "%s: command %s already done on apid %s\n",
	    fn, cmdnm, apid);
	return (1);
}
