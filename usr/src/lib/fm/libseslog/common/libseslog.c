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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * SES Log reader library
 *
 * This library is responsible for accessing the SES log at the target address,
 * formatting and returning any log entries found.
 *
 * The data will be returned in an nvlist_t structure allocated here.
 */

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/param.h>
#include <libseslog.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/scsi/generic/commands.h>
#include <sys/scsi/generic/status.h>
#include <sys/scsi/impl/commands.h>

/*
 * open the device with given device name
 */
static int
open_device(const char *device_name)
{
	int oflags = O_NONBLOCK | O_RDWR;
	int fd;

	fd = open(device_name, oflags);
	if (fd < 0)
		fd = -errno;
	return (fd);
}

/*
 * Initialize scsi struct
 */
static void
construct_scsi_pt_obj(struct uscsi_cmd *uscsi)
{
	(void) memset(uscsi, 0, sizeof (struct uscsi_cmd));
	uscsi->uscsi_timeout = DEF_PT_TIMEOUT;
	uscsi->uscsi_flags = USCSI_READ | USCSI_ISOLATE | USCSI_RQENABLE;
}

/*
 * set control cdb of scsi structure
 */
static void
set_scsi_pt_cdb(struct uscsi_cmd *uscsi, const unsigned char *cdb,
    int cdb_len)
{
	uscsi->uscsi_cdb = (char *)cdb;
	uscsi->uscsi_cdblen = cdb_len;
}

/*
 * initialize sense data
 */
static void
set_scsi_pt_sense(struct uscsi_cmd *uscsi, unsigned char *sense,
    int max_sense_len)
{
	(void) memset(sense, 0, max_sense_len);
	uscsi->uscsi_rqbuf = (char *)sense;
	uscsi->uscsi_rqlen = max_sense_len;
}

/*
 * Initialize data going to device
 */
static void
set_scsi_pt_data_in(struct uscsi_cmd *uscsi, unsigned char *dxferp,
    int dxfer_len)
{
	if (dxfer_len > 0) {
		uscsi->uscsi_bufaddr = (char *)dxferp;
		uscsi->uscsi_buflen = dxfer_len;
		uscsi->uscsi_flags = USCSI_READ | USCSI_ISOLATE |
		    USCSI_RQENABLE;
	}
}

/*
 * Executes SCSI command(or at least forwards it to lower layers).
 */
static int
do_scsi_pt(struct uscsi_cmd *uscsi, int fd, int time_secs)
{
	if (time_secs > 0)
		uscsi->uscsi_timeout = time_secs;

	if (ioctl(fd, USCSICMD, uscsi)) {
		/* Took an error */
		return (errno);
	}
	return (0);
}


/*
 * Read log from device
 * Invokes a SCSI LOG SENSE command.
 * Return:
 * 0 -> success
 * SG_LIB_CAT_INVALID_OP -> Log Sense not supported,
 * SG_LIB_CAT_ILLEGAL_REQ -> bad field in cdb,
 * SG_LIB_CAT_NOT_READY -> device not ready,
 * -1 -> other failure
 */

static int
read_log(int sg_fd, unsigned char *resp, int mx_resp_len)
{
	int res, ret;
	unsigned char logsCmdBlk[CDB_GROUP1] =
	    {SCMD_LOG_SENSE_G1, 0, 0, 0, 0, 0, 0, 0, 0, 0};
	unsigned char sense_b[SENSE_BUFF_LEN];
	struct uscsi_cmd uscsi;

	if (mx_resp_len > 0xffff) {
		return (-1);
	}
	logsCmdBlk[1] = 0;
	/* pc = 1, pg_code = 0x7 (logs page) */
	/* (((pc << 6) & 0xc0) | (pg_code & 0x3f)) = 0x47; */
	logsCmdBlk[2] = 0x47;
	/* pc = 1 current values */
	logsCmdBlk[3] = 0; /* No subpage code */
	logsCmdBlk[5] = 0; /* Want all logs starting from 0 */
	logsCmdBlk[6] = 0;
	logsCmdBlk[7] = (unsigned char) ((mx_resp_len >> 8) & 0xff);
	logsCmdBlk[8] = (unsigned char) (mx_resp_len & 0xff);

	construct_scsi_pt_obj(&uscsi);

	set_scsi_pt_cdb(&uscsi, logsCmdBlk, sizeof (logsCmdBlk));
	set_scsi_pt_sense(&uscsi, sense_b, sizeof (sense_b));
	set_scsi_pt_data_in(&uscsi, resp, mx_resp_len);
	res = do_scsi_pt(&uscsi, sg_fd, DEF_PT_TIMEOUT);
	if (res) {
		ret = res;
	} else {
		ret = uscsi.uscsi_status;
	}
	return (ret);
}

/*
 * Save the logs by walking through the entries in the response buffer.
 *
 * resp buffer looks like:
 *
 * +=====-========-========-========-========-========-========-========-=====+
 * |  Bit|   7    |   6    |   5    |   4    |   3    |   2    |   1    |   0 |
 * |Byte |        |        |        |        |        |        |        |     |
 * |=====+====================================================================|
 * | 0   |  reserved       |     page code                                    |
 * |-----+--------------------------------------------------------------------|
 * | 1   |                   Reserved                                         |
 * |-----+--------------------------------------------------------------------|
 * | 2   |(MSB)                           Page Length(n-3)                    |
 * | --  |                                                                    |
 * | 3   |                                                            (LSB)   |
 * |-----+--------------------------------------------------------------------|
 * | 4   |                           Log Parameter (First)(Length X)          |
 * | --  |                                                                    |
 * | x+3 |                                                                    |
 * |-----+--------------------------------------------------------------------|
 * |n-y+1|                           Log Parameter (Last)(Length y)           |
 * | --  |                                                                    |
 * | n   |                                                                    |
 * +==========================================================================+
 *
 * Log parameter field looks like:
 *
 * +=====-========-========-========-========-========-========-========-=====+
 * |  Bit|   7    |   6    |   5    |   4    |   3    |   2    |   1    |   0 |
 * |Byte |        |        |        |        |        |        |        |     |
 * |=====+====================================================================|
 * | 0   |(MSB)                           Parameter Code                      |
 * | --  |                                                                    |
 * | 1   |                                                            (LSB)   |
 * |-----+--------------------------------------------------------------------|
 * | 2   | DU     |  DS    |  TSD    | ETC   |         TMC     |  LBIN  | LP  |
 * |-----+--------------------------------------------------------------------|
 * | 3   |                          Parameter Length(n-3)                     |
 * |-----+--------------------------------------------------------------------|
 * | 4   |                           Parameter Values                         |
 * | --  |                                                                    |
 * | n	 |                                                                    |
 * |-----+--------------------------------------------------------------------|
 */

static int
save_logs(unsigned char *resp, ses_log_call_t *data)
{
	int k;
	int param_code;		/* Parameter code */
	int param_len = 0;	/* Paramter length */
	unsigned char *log_param_ptr;	/* Log parameter pointer */
	unsigned char *log_str_ptr; /* ptr to ascii str returend by expander */

	char log_code[ENTRY_MAX_SIZE];
	char log_level[ENTRY_MAX_SIZE];
	nvlist_t *entry;
	char entry_num[15];
	int match_found = 0;
	char save_buffer[MAX_LOG_ENTRY_SZ];
	char entry_added = 0;
	int all_log_data_len;

	/*
	 * Bytes 2 and 3 of response buffer contain the page length of
	 * the log entries returned.
	 */
	all_log_data_len = SCSI_READ16(&resp[2]);

	/*
	 * Initialize log parameter pointer to point to first log entry.
	 * The resp includes 4 bytes of header info and then log entries
	 */
	log_param_ptr = &resp[0] + 4;

	/*
	 * If multiple heads are reading the logs, it is possible that we
	 * could be re-reading some of the same log entries plus some
	 * new additional entries. Check to see if any entries in this read
	 * contain the same log entry as the last entry we read last time.
	 */
	if (strlen(data->last_log_entry) == SES_LOG_VALID_LOG_SIZE) {
		/*
		 * We have a valid log entry from a previous read log
		 * operation.
		 */


		/*
		 * Start walking each log entry in response buffer looking for
		 * a duplicate entry.
		 */
		for (k = 0; k < all_log_data_len; k += param_len) {
			/*
			 * Calculate log entry length
			 * Log param ptr [3] contains the log length minus the
			 * header info which is 4 bytes so add that in.
			 */
			param_len = log_param_ptr[3] + 4;

			if (param_len <= 4) {
				/*
				 * Only header information in this entry
				 * process next log entry
				 */
				log_param_ptr += param_len;
				continue;
			}


			/*
			 * initialize log_str_ptr to point to string info
			 * returned by expander
			 * first 4 bytes of log parameter contains
			 * 2 bytes of parameter code, 1 byte of Control data
			 * and 1 byte for parameter length. Log string begins
			 * after that so add 4 to log param ptr.
			 */
			log_str_ptr = log_param_ptr + 4;

			/*
			 * Check to see if this is the
			 * same line
			 */
			if (strncmp((char *)log_str_ptr, data->last_log_entry,
			    SES_LOG_VALID_LOG_SIZE) == 0) {
				/* Found an exact match */
				log_param_ptr += param_len;
				k += param_len;
				match_found = 1;
				break;
			}
			log_param_ptr += param_len;
		}
	}
	if (!match_found) {
		log_param_ptr = &resp[0] + 4;
		k = 0;
	}
	if (k == all_log_data_len) {
		/*
		 * Either there was no log data or we have
		 * already read these log entries.
		 * Just return.
		 */
		return (0);
	}

	/* Grab memory to return logs with */
	if (nvlist_alloc(&data->log_data, NV_UNIQUE_NAME, 0) != 0) {
		/* Couldn't alloc memory for nvlist */
		return (SES_LOG_FAILED_NVLIST_CREATE);
	}

	(void) memset(log_code,		0, sizeof (log_code));
	(void) memset(save_buffer,	0, sizeof (save_buffer));
	(void) memset(log_level,	0, sizeof (log_level));

	/*
	 * Start saving new log entries
	 * Walk the log data adding any new entries
	 */

	for (; k < all_log_data_len; k += param_len) {
		/*
		 * Calculate log entry length
		 * Log ptr [3] contains the log length minus the header info
		 * which is 4 bytes so add that in
		 */
		param_len = log_param_ptr[3] + 4;

		if (param_len <= 4) {
			/* Only header information in this entry */
			/* process next log entry */
			log_param_ptr += param_len;
			continue;
		}

		/*
		 * initialize log_str_ptr to point to string info of the log
		 * entry. First 4 bytes of log entry contains param code,
		 * control byte, and length. Log string starts after that.
		 */
		log_str_ptr = log_param_ptr + 4;

		/*
		 * Format of log str is as follows
		 * "%8x %8x %8x %8x %8x %8x %8x %8x",
		 * log_entry.log_word0, log_entry.ts_u, log_entry.ts_l,
		 * log_entry.seq_num, log_entry.log_code, log_entry.log_word2,
		 * log_entry.log_word3, log_entry.log_word4
		 * following example has extra spaces removed to fit in 80 char
		 * 40004 0 42d5f5fe 185b 630002 fd0800 50800207 e482813
		 */

		(void) strncpy(save_buffer,
		    (const char *)log_str_ptr,
		    SES_LOG_VALID_LOG_SIZE);

		(void) strncpy(log_code,
		    (const char *)log_str_ptr+SES_LOG_CODE_START,
		    SES_LOG_SPECIFIC_ENTRY_SIZE);

		(void) strncpy(log_level,
		    (const char *) log_str_ptr +
		    SES_LOG_LEVEL_START, 1);


		/* Add this entry to the nvlist log data */
		if (nvlist_alloc(&entry, NV_UNIQUE_NAME, 0) != 0) {
			/* Couldn't alloc space, return error */
			return (SES_LOG_FAILED_NV_UNIQUE);
		}


		if (nvlist_add_string(entry, ENTRY_LOG, save_buffer) != 0) {
			/* Error adding string, return error */
			nvlist_free(entry);
			return (SES_LOG_FAILED_NV_LOG);
		}

		if (nvlist_add_string(entry, ENTRY_CODE, log_code) != 0) {
			/* Error adding string, return error */
			nvlist_free(entry);
			return (SES_LOG_FAILED_NV_CODE);
		}
		if (nvlist_add_string(entry, ENTRY_SEVERITY, log_level) != 0) {
			/* Error adding srtring, return error */
			nvlist_free(entry);
			return (SES_LOG_FAILED_NV_SEV);
		}

		param_code = SCSI_READ16(&log_param_ptr[0]);

		(void) snprintf(entry_num, sizeof (entry_num),
		    "%s%d", ENTRY_PREFIX, param_code);

		if (nvlist_add_nvlist(data->log_data, entry_num, entry) != 0) {
			/* Error adding nvlist, return error */
			nvlist_free(entry);
			return (SES_LOG_FAILED_NV_ENTRY);
		}
		nvlist_free(entry);

		entry_added = 1;
		(data->number_log_entries)++;

		log_param_ptr += param_len;

	}
	if (entry_added) {
		/* Update the last log entry string with last one read */
		(void) strncpy(data->last_log_entry, save_buffer, MAXNAMELEN);
	}
	return (0);
}



/* Setup struct to send command to device */
static void
set_scsi_pt_data_out(struct uscsi_cmd *uscsi, const unsigned char *dxferp,
    int dxfer_len)
{
	if (dxfer_len > 0) {
		uscsi->uscsi_bufaddr = (char *)dxferp;
		uscsi->uscsi_buflen = dxfer_len;
		uscsi->uscsi_flags = USCSI_WRITE | USCSI_ISOLATE |
		    USCSI_RQENABLE;
	}
}

/*
 * Invokes a SCSI MODE SENSE(10) command.
 * Return:
 * 0 for success
 * SG_LIB_CAT_INVALID_OP -> invalid opcode
 * SG_LIB_CAT_ILLEGAL_REQ -> bad field in cdb
 * SG_LIB_CAT_NOT_READY -> device not ready
 * -1 -> other failure
 */

static int
sg_ll_mode_sense10(int sg_fd, void * resp, int mx_resp_len)
{
	int res, ret;
	unsigned char modesCmdBlk[MODE_SENSE10_CMDLEN] =
	    {SCMD_MODE_SENSE_G1, 0, 0, 0, 0, 0, 0, 0, 0, 0};
	unsigned char sense_b[SENSE_BUFF_LEN];
	struct uscsi_cmd uscsi;

	modesCmdBlk[1] = 0;
	modesCmdBlk[2] = 0; /* page code 0 vendor specific */
	modesCmdBlk[3] = 0;
	modesCmdBlk[7] = (unsigned char) ((mx_resp_len >> 8) & 0xff);
	modesCmdBlk[8] = (unsigned char) (mx_resp_len & 0xff);

	construct_scsi_pt_obj(&uscsi);
	set_scsi_pt_cdb(&uscsi, modesCmdBlk, sizeof (modesCmdBlk));
	set_scsi_pt_sense(&uscsi, sense_b, sizeof (sense_b));
	set_scsi_pt_data_in(&uscsi, (unsigned char *) resp, mx_resp_len);
	res = do_scsi_pt(&uscsi, sg_fd, DEF_PT_TIMEOUT);
	if (res) {
		ret = res;
	} else {
		ret = uscsi.uscsi_status;
	}
	return (ret);
}

/*
 * Invokes a SCSI MODE SELECT(10) command.
 * Return:
 * 0 for success.
 * SG_LIB_CAT_INVALID_OP for invalid opcode
 * SG_LIB_CAT_ILLEGAL_REQ -> bad field in cdb,
 * SG_LIB_CAT_NOT_READY -> device not ready,
 * -1 -> other failure
 */
static int
sg_ll_mode_select10(int sg_fd, void * paramp, int param_len)
{
	int res, ret;
	unsigned char modesCmdBlk[MODE_SELECT10_CMDLEN] =
	    {SCMD_MODE_SELECT_G1, 0, 0, 0, 0, 0, 0, 0, 0, 0};
	unsigned char sense_b[SENSE_BUFF_LEN];
	struct uscsi_cmd uscsi;


	modesCmdBlk[1] = 0;
	/*
	 * modesCmdBlk 2 equal 0 PC 0 return current page code 0 return
	 * vendor specific
	 */

	modesCmdBlk[7] = (unsigned char)((param_len >> 8) & 0xff);
	modesCmdBlk[8] = (unsigned char)(param_len & 0xff);

	construct_scsi_pt_obj(&uscsi);

	set_scsi_pt_cdb(&uscsi, modesCmdBlk, sizeof (modesCmdBlk));
	set_scsi_pt_sense(&uscsi, sense_b, sizeof (sense_b));
	set_scsi_pt_data_out(&uscsi, (unsigned char *) paramp, param_len);
	res = do_scsi_pt(&uscsi, sg_fd, DEF_PT_TIMEOUT);
	if (res) {
		ret = res;
	} else {
		ret = uscsi.uscsi_status;
	}
	return (ret);
}



/*
 * MODE SENSE 10 commands yield a response that has block descriptors followed
 * by mode pages. In most cases users are interested in the first mode page.
 * This function returns the(byte) offset of the start of the first mode page.
 * Returns >= 0 is successful or -1 if failure. If there is a failure
 * a message is written to err_buff.
 */

/*
 * return data looks like:
 * Table 92 - Mode parameter header(10)
 * Bit
 * Byte
 *	7	6	5	4	3	2	1	0
 *	----------------------------------------------------------
 * 0	MSB Data length
 * 1	LSB Data length
 *	----------------------------------------------------------
 * 2	Medium type
 *	----------------------------------------------------------
 * 3	Device-specific parameter
 *	----------------------------------------------------------
 * 4	Reserved
 *	----------------------------------------------------------
 * 5	Reserved
 *	----------------------------------------------------------
 * 6	MSB block descriptor length
 * 7	LSB block descriptor length
 *	----------------------------------------------------------
 *	block desciptors....
 *	-----------------------
 *	mode sense page:
 *	0 : ps Reserved : page Code
 *	1 : Page Length(n-1)
 *	2-N  Mode parameters
 */
static int
sg_mode_page_offset(const unsigned char *resp, int resp_len)
{
	int bd_len;
	int calc_len;
	int offset;

	if ((NULL == resp) || (resp_len < 8)) {
		/* Too short of a response buffer */
		return (-1);
	}

	calc_len = (resp[0] << 8) + resp[1] + 2;
	bd_len = (resp[6] << 8) + resp[7];

	/* LongLBA doesn't change this calculation */
	offset = bd_len + MODE10_RESP_HDR_LEN;

	if ((offset + 2) > resp_len) {
		/* Given response length to small */
		offset = -1;
	} else if ((offset + 2) > calc_len) {
		/* Calculated response length too small */
		offset = -1;
	}
	return (offset);
}

/*
 * Clear logs
 */
static int
clear_log(int sg_fd, ses_log_call_t *data)
{

	int res, alloc_len, off;
	int md_len;
	int read_in_len = 0;
	unsigned char ref_md[MAX_ALLOC_LEN];
	struct log_clear_control_struct clear_data;
	long myhostid;
	int error = 0;
	long poll_time;
	char seq_num_str[10];
	unsigned long seq_num = 0;

	(void) memset(&clear_data, 0, sizeof (clear_data));

	clear_data.pageControls = 0x40;
	clear_data.subpage_code = 0;
	clear_data.page_lengthLower = 0x16;

	myhostid = gethostid();
	/* 0 -> 11 are memset to 0 */
	clear_data.host_id[12] = (myhostid & 0xff000000) >> 24;
	clear_data.host_id[13] = (myhostid & 0xff0000) >> 16;
	clear_data.host_id[14] = (myhostid & 0xff00) >> 8;
	clear_data.host_id[15] = myhostid & 0xff;

	/*
	 * convert nanosecond time to seconds
	 */
	poll_time = data->poll_time / 1000000000;
	/* Add 5 minutes to poll time to allow for data retrieval time */
	poll_time = poll_time + 300;
	clear_data.timeout[0] = (poll_time & 0xff00) >> 8;
	clear_data.timeout[1] = poll_time & 0xff;

	/*
	 * retrieve the last read sequence number from the last
	 * log entry read.
	 */
	if (strlen(data->last_log_entry) == SES_LOG_VALID_LOG_SIZE) {
		/*
		 * We have a valid log entry from a previous read log
		 * operation.
		 */
		(void) strncpy(seq_num_str,
		    (const char *) data->last_log_entry +
		    SES_LOG_SEQ_NUM_START, 8);
		seq_num = strtoul(seq_num_str, 0, 16);
	}
	clear_data.seq_clear[0] = (seq_num & 0xff000000) >> 24;
	clear_data.seq_clear[1] = (seq_num & 0xff0000) >> 16;
	clear_data.seq_clear[2] = (seq_num & 0xff00) >> 8;
	clear_data.seq_clear[3] = (seq_num & 0xff);

	read_in_len = sizeof (clear_data);


	/* do MODE SENSE to fetch current values */
	(void) memset(ref_md, 0, MAX_ALLOC_LEN);
	alloc_len = MAX_ALLOC_LEN;


	res = sg_ll_mode_sense10(sg_fd, ref_md, alloc_len);
	if (0 != res) {
		/* Error during mode sense */
		error = SES_LOG_FAILED_MODE_SENSE;
		return (error);
	}

	/* Setup mode Select to clear logs */
	off = sg_mode_page_offset(ref_md, alloc_len);
	if (off < 0) {
		/* Mode page offset error */
		error =  SES_LOG_FAILED_MODE_SENSE_OFFSET;
		return (error);
	}
	md_len = (ref_md[0] << 8) + ref_md[1] + 2;

	ref_md[0] = 0;
	ref_md[1] = 0;

	if (md_len > alloc_len) {
		/* Data length to large */
		error = SES_LOG_FAILED_BAD_DATA_LEN;
		return (error);
	}

	if ((md_len - off) != read_in_len) {
		/* Content length not correct */
		error = SES_LOG_FAILED_BAD_CONTENT_LEN;
		return (error);
	}

	if ((clear_data.pageControls & 0x40) != (ref_md[off] & 0x40)) {
		/* reference model doesn't have use subpage format bit set */
		/* Even though it should have */
		/* don't send the command */
		error = SES_LOG_FAILED_FORMAT_PAGE_ERR;
		return (error);
	}

	(void) memcpy(ref_md + off, (const void *) &clear_data,
	    sizeof (clear_data));

	res = sg_ll_mode_select10(sg_fd, ref_md, md_len);
	if (res != 0) {
		error = SES_LOG_FAILED_MODE_SELECT;
		return (error);
	}

	return (error);
}
/*
 * Gather data from given device.
 */
static int
gather_data(char *device_name, ses_log_call_t *data)
{
	int sg_fd;
	int resp_len, res;
	unsigned char rsp_buff[MAX_ALLOC_LEN];
	int error;

	/* Open device */
	if ((sg_fd = open_device(device_name)) < 0) {
		/* Failed to open device */
		return (SES_LOG_FAILED_TO_OPEN_DEVICE);
	}

	/* Read the logs */
	(void) memset(rsp_buff, 0, sizeof (rsp_buff));
	resp_len = 0x8000; /* Maximum size available to read */
	res = read_log(sg_fd, rsp_buff, resp_len);

	if (res != 0) {
		/* Some sort of Error during read of logs */
		(void) close(sg_fd);
		return (SES_LOG_FAILED_TO_READ_DEVICE);
	}

	/* Save the logs */
	error = save_logs(rsp_buff, data);
	if (error != 0) {
		(void) close(sg_fd);
		return (error);
	}
	/* Clear the logs */
	error = clear_log(sg_fd, data);

	(void) close(sg_fd);

	return (error);
}

/*
 * Access the SES target identified by the indicated path.  Read the logs
 * and return them in a nvlist.
 */
int
access_ses_log(ses_log_call_t *data)
{
	char real_path[MAXPATHLEN];
	struct stat buffer;
	int error;

	/* Initialize return data */
	data->log_data = NULL;
	data->number_log_entries = 0;

	if (*data->target_path == '\0') {
		/* empty target path, return error */
		return (SES_LOG_FAILED_NULL_TARGET_PATH);
	}

	/* Try to find a valid path */
	(void) snprintf(real_path, sizeof (real_path), "/devices%s:ses",
	    data->target_path);

	if (stat(real_path, &buffer) != 0) {

		(void) snprintf(real_path, sizeof (real_path), "/devices%s:0",
		    data->target_path);
		if (stat(real_path, &buffer) != 0) {
			/* Couldn't find a path that exists */
			return (SES_LOG_FAILED_BAD_TARGET_PATH);
		}
	}

	error = gather_data(real_path, data);

	/* Update the size of log entries being returned */
	data->size_of_log_entries =
	    data->number_log_entries * SES_LOG_VALID_LOG_SIZE;

	return (error);
}
