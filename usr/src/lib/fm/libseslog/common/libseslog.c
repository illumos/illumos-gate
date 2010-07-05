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
 * |3    |                          Paramter Length(n-3)                      |
 * |-----+--------------------------------------------------------------------|
 * | 4   |                           Parameter Values                         |
 * | --  |                                                                    |
 * | n	 |                                                                    |
 * |-----+--------------------------------------------------------------------|
 */

static int
save_logs(unsigned char *resp, int len, nvlist_t *log_data,
    char *last_log_entry, unsigned long *seq_num_ret, int *number_log_entries)
{
	int k, i;
	int paramCode; /* Parameter code */
	int paramLen = 0; /* Paramter length */
	int pcb; /* Paramter control Byte */
	unsigned char *lpp; /* Log parameter pointer */
	unsigned char *log_str_ptr; /* ptr to ascii str returend by expander */

	unsigned long seq_num_ul = 0;
	char seq_num[10];
	char log_event_type[10];
	char log_code[10];
	char log_level[10];
	nvlist_t *entry;
	char entry_num[15];
	int type;
	int match_found = 0;
	long current_seq_num;
	long last_num;
	char save_buffer[256];
	char entry_added = 0;
	char *s;


	(void) memset(seq_num, 0, sizeof (seq_num));

	*number_log_entries = 0;
	/* Initial log paramter pointer to point to first log entry */
	/* The resp includes 4 bytes of header info and then log entries */
	lpp = &resp[0] + 4;
	k = len;
	/* Find last sequence number from last log read */
	if (last_log_entry != NULL &&
	    (strlen(last_log_entry) == SES_LOG_VALID_LOG_SIZE)) {
		(void) strncpy(seq_num, (const char *) last_log_entry +
		    SES_LOG_SEQ_NUM_START, 8);
		last_num = strtoul(seq_num, 0, 16);
		/* save this in case there are no new entries */
		seq_num_ul = last_num;

		/* First find if there are duplicate entries */
		lpp = &resp[0] + 4;

		/*
		 * Start walking each log entry in return buffer looking for
		 * a duplicate entry.
		 */
		for (; k > 0; k -= paramLen) {
			if (k < 3) {
				/*
				 * Should always have at least 3 Bytes for
				 * each entry
				 * If not, it must be a bad record so stop
				 * processing
				 */
				nvlist_free(log_data);
				log_data = NULL;
				return (SES_LOG_FAILED_SHORT_LOG_PARAM_INIT);
			}
			pcb = lpp[2];
			paramLen = lpp[3] + 4;
			/*
			 * initial log_str_ptr to point to string info returned
			 * by expander
			 * first 4 bytes of log
			 * parameter are 2 param:
			 * codes Control byte, Parameter length
			 */
			log_str_ptr = lpp + 4;

			if (paramLen > 4) {
				if ((pcb & 0x1) && !(pcb & 2)) {

					(void) strncpy(seq_num,
					    (const char *)log_str_ptr +
					    SES_LOG_SEQ_NUM_START, 8);
					current_seq_num = strtoul(seq_num, 0,
					    16);

					if (current_seq_num == last_num) {
						/*
						 * Check to see if this is the
						 * same line
						 */
						if (strncmp(
						    (char *)log_str_ptr,
						    last_log_entry,
						    SES_LOG_VALID_LOG_SIZE) ==
						    0) {
							/*
							 * Found an exact
							 * match
							 */
							lpp += paramLen;
							k -= paramLen;
							match_found = 1;
							break;
						}
					}
				}
			}
			lpp += paramLen;
		}
	}
	if (!match_found) {
		lpp = &resp[0] + 4;
		k = len;
	}

	(void) memset(log_event_type, 0, sizeof (log_event_type));
	(void) memset(seq_num, 0, sizeof (seq_num));
	(void) memset(log_code, 0, sizeof (log_code));
	(void) memset(save_buffer, 0, sizeof (save_buffer));
	(void) memset(log_level, 0, sizeof (log_level));

	/* K will be initialized from above */
	for (; k > 0; k -= paramLen) {
		if (k < 3) {
			/* Should always have at least 3 Bytes for each entry */
			/* If not, it must be a bad record so stop processing */
			nvlist_free(log_data);
			log_data = NULL;
			return (SES_LOG_FAILED_SHORT_LOG_PARAM);
		}
		paramCode = (lpp[0] << 8) + lpp[1];
		pcb = lpp[2];
		paramLen = lpp[3] + 4;
		/*
		 * initial log_str_ptr to point to string info of the log entry
		 * First 4 bytes of log entry contains param code, control
		 * byte, length
		 */
		log_str_ptr = lpp + 4;

		/*
		 * Format of log str is as follows
		 * "%8x %8x %8x %8x %8x %8x %8x %8x",
		 * log_entry.log_word0, log_entry.ts_u, log_entry.ts_l,
		 * log_entry.seq_num, log_entry.log_code, log_entry.log_word2,
		 * log_entry.log_word3, log_entry.log_word4
		 * following example has extra spaces removed to fit in 80 char
		 * 40004 0 42d5f5fe 185b 630002 fd0800 50800207 e482813
		 */
		if (paramLen > 4) {
			if ((pcb & 0x1) && !(pcb & 2)) {

				(void) strncpy(save_buffer,
				    (const char *)log_str_ptr,
				    SES_LOG_VALID_LOG_SIZE);
				for (i = 0; (i < 8) && (s = strtok(i ? 0 :
				    (char *)log_str_ptr, " ")); i++) {
					char *ulp;
					switch (i) {
					case 0:
						/* event type */
						ulp = (char *)
						    &log_event_type;
					break;
					case 3:
						/* sequence number */
						ulp = (char *)
						    &seq_num;
					break;
					case 4:
						/* log code */
						ulp = (char *)
						    &log_code;
					break;
					default:
						ulp = 0;
					}

					if (ulp) {
						(void) strncpy(ulp, s, 8);
					}
				}


				seq_num_ul = strtoul(seq_num, 0, 16);

				(void) strncpy(log_level,
				    (const char *) log_str_ptr +
				    SES_LOG_LEVEL_START, 1);

				/* event type is in log_event_type */
				/* 4x004 = looking for x */
				type = (strtoul(log_event_type, 0, 16) >> 12) &
				    0xf;

				/*
				 * Check type. If type is 1, level needs to be
				 * changed to FATAL. If type is something other
				 * than 0 or 1, they are info only.
				 */
				if (type == 1) {
					(void) strcpy(log_level, "4");
				} else if (type > 1) {
					/* These are not application log */
					/* entries */
					/* make them info only */
					(void) strcpy(log_level, "0");
				}

				/* Add this entry to the nvlist log data */
				if (nvlist_alloc(&entry,
				    NV_UNIQUE_NAME, 0) != 0) {
					nvlist_free(log_data);
					log_data = NULL;
					return (SES_LOG_FAILED_NV_UNIQUE);
				}


				if (nvlist_add_string(entry, ENTRY_LOG,
				    save_buffer) != 0) {
					nvlist_free(entry);
					nvlist_free(log_data);
					log_data = NULL;
					return (SES_LOG_FAILED_NV_LOG);
				}

				if (nvlist_add_string(entry, ENTRY_CODE,
				    log_code) != 0) {
					nvlist_free(entry);
					nvlist_free(log_data);
					log_data = NULL;
					return (SES_LOG_FAILED_NV_CODE);
				}
				if (nvlist_add_string(entry, ENTRY_SEVERITY,
				    log_level) != 0) {
					nvlist_free(entry);
					nvlist_free(log_data);
					log_data = NULL;
					return (SES_LOG_FAILED_NV_SEV);
				}

				(void) snprintf(entry_num, sizeof (entry_num),
				    "%s%d", ENTRY_PREFIX, paramCode);

				if (nvlist_add_nvlist(log_data, entry_num,
				    entry) != 0) {
					nvlist_free(entry);
					nvlist_free(log_data);
					log_data = NULL;
					return (SES_LOG_FAILED_NV_ENTRY);
				}
				nvlist_free(entry);

				entry_added = 1;
				(*number_log_entries)++;

			}
		}
		lpp += paramLen;

	}
	if (entry_added) {
		/* Update the last log entry string with last one read */
		(void) strncpy(last_log_entry, save_buffer, MAXNAMELEN);
	}
	*seq_num_ret = seq_num_ul;

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
	 * modesCmdBlk 2   equal  0   PC 0 return current page code 0 return
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
 *	7 	6 	5 	4 	3 	2 	1 	0
 *	----------------------------------------------------------
 * 0	MSB Data length
 * 1	LSB Data length
 *	----------------------------------------------------------
 * 2	Medium type
 *	----------------------------------------------------------
 * 3 	Device-specific parameter
 *	----------------------------------------------------------
 * 4 	Reserved
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
sg_mode_page_offset(const unsigned char *resp, int resp_len,
    char *err_buff, int err_buff_len)
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
		(void) snprintf(err_buff, err_buff_len,
		    "given response length "
		    "too small, offset=%d given_len=%d bd_len=%d\n",
		    offset, resp_len, bd_len);
		offset = -1;
	} else if ((offset + 2) > calc_len) {
		(void) snprintf(err_buff, err_buff_len, "calculated response "
		    "length too small, offset=%d calc_len=%d bd_len=%d\n",
		    offset, calc_len, bd_len);
		offset = -1;
	}
	return (offset);
}

/*
 * Clear logs
 */
static int
clear_log(int sg_fd, unsigned long seq_num, long poll_time)
{

	int res, alloc_len, off;
	int md_len;
	int read_in_len = 0;
	unsigned char ref_md[MX_ALLOC_LEN];
	char ebuff[EBUFF_SZ];
	struct log_clear_control_struct clear_data;
	long myhostid;
	int error = 0;

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

	/* Timeout set to 32 seconds for now */
	/* Add 5 minutes to poll time to allow for data retrievel time */
	poll_time = poll_time + 300;
	clear_data.timeout[0] = (poll_time & 0xff00) >> 8;
	clear_data.timeout[1] = poll_time & 0xff;

	clear_data.seq_clear[0] = (seq_num & 0xff000000) >> 24;
	clear_data.seq_clear[1] = (seq_num & 0xff0000) >> 16;
	clear_data.seq_clear[2] = (seq_num & 0xff00) >> 8;
	clear_data.seq_clear[3] = (seq_num & 0xff);

	read_in_len = sizeof (clear_data);


	/* do MODE SENSE to fetch current values */
	(void) memset(ref_md, 0, MX_ALLOC_LEN);
	alloc_len = MX_ALLOC_LEN;


	res = sg_ll_mode_sense10(sg_fd, ref_md, alloc_len);
	if (0 != res) {
		/* Error during mode sense */
		error = SES_LOG_FAILED_MODE_SENSE;
		return (error);
	}

	/* Setup mode Select to clear logs */
	off = sg_mode_page_offset(ref_md, alloc_len, ebuff, EBUFF_SZ);
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
		error = SES_LOG_FAILED_FORMAT_PAGE_ERROR;
		return (error);
	}

	(void) memcpy(ref_md + off, (const void *) & clear_data,
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
gatherData(char *device_name, nvlist_t *log_data, char *last_log_entry,
    long poll_time, int *number_log_entries)
{
	int sg_fd;
	unsigned long seq_num;
	int pg_len, resp_len, res;
	unsigned char rsp_buff[MX_ALLOC_LEN];
	int error;



	/* Open device */
	if ((sg_fd = open_device(device_name)) < 0) {
		/* Failed to open device */
		nvlist_free(log_data);
		log_data = NULL;
		return (SES_LOG_FAILED_TO_OPEN_DEVICE);
	}

	/* Read the logs */
	(void) memset(rsp_buff, 0, sizeof (rsp_buff));
	resp_len = 0x8000; /* Maximum size available to read */
	res = read_log(sg_fd, rsp_buff, resp_len);

	if (res == 0) {
		pg_len = (rsp_buff[2] << 8) + rsp_buff[3];
		if ((pg_len + 4) > resp_len) {
			/* Didn't get entire response */
			/* Process what we did get */
			pg_len = resp_len - 4;
		}
	} else {
		/* Some sort of Error during read of logs */
		nvlist_free(log_data);
		log_data = NULL;
		return (SES_LOG_FAILED_TO_READ_DEVICE);
	}

	/* Save the logs */
	error = save_logs(rsp_buff, pg_len, log_data, last_log_entry,
	    &seq_num, number_log_entries);
	if (error != 0) {
		return (error);
	}
	/* Clear logs */
	error = clear_log(sg_fd, seq_num, poll_time);

	(void) close(sg_fd);

	return (error);

}

/*
 * Access the SES target identified by the indicated path.  Read the logs
 * and return them in a nvlist.
 */
int
access_ses_log(struct ses_log_call_struct *data)
{
	char real_path[MAXPATHLEN];
	long poll_time;
	struct stat buffer;
	int error;

	if (data->target_path == NULL) {
		/* NULL Target path, return error */
		return (SES_LOG_FAILED_NULL_TARGET_PATH);
	}
	if (strncmp("SUN-GENESIS", data->product_id, 11) != 0) {
		/* Not a supported node, return error */
		return (SES_LOG_UNSUPPORTED_HW_ERROR);
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


	/*
	 * convert nanosecond time to seconds
	 */
	poll_time = data->poll_time / 1000000000;

	error = nvlist_alloc(&data->log_data, NV_UNIQUE_NAME, 0);
	if (error != 0) {
		/* Couldn't alloc memory for nvlist */
		return (SES_LOG_FAILED_NVLIST_CREATE);
	}


	/* Record the protocol used for later when an ereport is generated. */
	error = nvlist_add_string(data->log_data, PROTOCOL, PROTOCOL_TYPE);
	if (error != 0) {
		nvlist_free(data->log_data);
		data->log_data = NULL;
		/* Error adding entry */
		return (SES_LOG_FAILED_NVLIST_PROTOCOL);
	}

	error = gatherData(real_path, data->log_data, data->last_log_entry,
	    poll_time, &data->number_log_entries);

	/* Update the size of log entries being returned */
	data->size_of_log_entries =
	    data->number_log_entries * SES_LOG_VALID_LOG_SIZE;

	return (error);
}
