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
 * Platform Channel Protocol Library functions on Nigara platforms
 * (Ontario, Erie, etc..) Solaris applications use these interfaces
 * to communicate with entities that reside on service processor.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <setjmp.h>
#include <inttypes.h>
#include <umem.h>
#include <strings.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/glvc.h>
#include <sys/vldc.h>
#include <sys/ldc.h>
#include <netinet/in.h>

#include "libpcp.h"
#include "pcp_common.h"
#include "pcp_utils.h"


/*
 * Following libpcp interfaces are exposed to user applications.
 *
 * int pcp_init(char *channel_name);
 * int pcp_send_recv(int channel_fd, pcp_msg_t *req_msg, pcp_msg_t *resp_msg,
 * 			uint32_t timeout);
 * int pcp_close(int channel_fd);
 *
 */

/*
 * Forward declarations.
 */
static int pcp_send_req_msg_hdr(pcp_req_msg_hdr_t *req_hdr);
static int pcp_recv_resp_msg_hdr(pcp_resp_msg_hdr_t *resp_hdr);
static int pcp_io_op(void *buf, int byte_cnt, int io_op);
static uint32_t pcp_get_xid(void);
static int pcp_get_prop(int channel_fd, int prop, unsigned int *val);
static int pcp_read(uint8_t *buf, int buf_len);
static int pcp_write(uint8_t *buf, int buf_len);
static int pcp_peek(uint8_t *buf, int buf_len);
static int pcp_peek_read(uint8_t *buf, int buf_len);
static int pcp_frame_error_handle(void);
static int check_magic_byte_presence(int byte_cnt, uint8_t *byte_val,
					int *ispresent);
static uint16_t checksum(uint16_t *addr, int32_t count);
static int pcp_cleanup(int channel_fd);

static int vldc_read(int fd, uint8_t *bufp, int size);
static int vldc_write(int fd, uint8_t *bufp, int size);
static int pcp_update_read_area(int byte_cnt);
static int pcp_vldc_frame_error_handle(void);

/*
 * local channel (glvc) file descriptor set by pcp_send_recv()
 */
static int chnl_fd = -1;

/*
 * Message Transaction ID
 */
static uint32_t msg_xid = 0;

/*
 * Channel MTU size.
 */
static unsigned int mtu_size = PCPL_DEF_MTU_SZ;

/*
 * timeout field is supplied by user. timeout field is used to decide
 * how long to block on glvc driver calls before we return timeout error
 * to user applications.
 *
 * Note: In the current implementation of glvc driver, all glvc calls are
 *       blocking.
 */
static uint32_t glvc_timeout = 0;

/*
 * variables used by setsetjmp/siglongjmp.
 */
static volatile sig_atomic_t jumpok = 0;
static sigjmp_buf jmpbuf;

/*
 * To unblock SIGALRM signal incase if it's blocked in libpcp user apps.
 * Restore it to old state during pcp_close.
 */
static sigset_t blkset;

/*
 * Buffers used for stream reading channel data. When data is read in
 * stream fashion, first data is copied from channel (glvc) buffers to
 * these local buffers from which the read requests are serviced.
 */
#define	READ_AREA_SIZE	(2*mtu_size)
static uint8_t *read_head = NULL;
static uint8_t *read_tail = NULL;
static uint8_t *read_area = NULL;

/*
 * Buffer used for peeking new data available in channel (glvc) buffers.
 */
#define	PEEK_AREA_SIZE	(mtu_size)
static uint8_t *peek_area = NULL;

/*
 * Buffers used for peeking data available either in local buffers or
 * new data available in channel (glvc) buffers.
 */
#define	PEEK_READ_AREA_SIZE	(2*mtu_size)
static uint8_t *peek_read_head = NULL;
static uint8_t *peek_read_tail = NULL;
static uint8_t *peek_read_area = NULL;

static pcp_req_msg_hdr_t *req_msg_hdr = NULL;
static pcp_resp_msg_hdr_t *resp_msg_hdr = NULL;
static int req_msg_hdr_sz = 0;
static int resp_msg_hdr_sz = 0;

/*
 * signal handling variables to handle glvc blocking calls.
 */
static struct sigaction glvc_act;

/* To restore old SIGALRM signal handler */
static struct sigaction old_act;

/*
 * Variables to support vldc based streaming transport
 */
static pcp_xport_t xport_type = GLVC_NON_STREAM;
#define	VLDC_MTU_SIZE	(2048)

static void
glvc_timeout_handler(void)
{
	if (jumpok == 0)
		return;
	siglongjmp(jmpbuf, 1);
}

/*
 * Initialize the virtual channel. It basically opens the virtual channel
 * provided by the host application.
 *
 */

int
pcp_init(char *channel_name)
{
	sigset_t oldset;
	int channel_fd;
	char *dev_path;
	vldc_opt_op_t op;

	if (channel_name == NULL)
		return (PCPL_INVALID_ARGS);

	/*
	 * Given the argument, try to locate a device in the device tree
	 */
	dev_path = platsvc_name_to_path(channel_name, &xport_type);

	/*
	 * Path exists ?
	 */
	if (NULL == dev_path)
		return (PCPL_INVALID_ARGS);

	/*
	 * Open virtual channel name.
	 */
	if ((channel_fd = open(dev_path, O_RDWR|O_EXCL)) < 0) {
		free(dev_path);
		return (PCPL_GLVC_ERROR);
	}

	free(dev_path);

	/*
	 * Handle transport-specific processing
	 */
	switch (xport_type) {
	case VLDC_STREAMING:
		mtu_size = VLDC_MTU_SIZE;

		op.op_sel = VLDC_OP_SET;
		op.opt_sel = VLDC_OPT_MODE;
		op.opt_val = LDC_MODE_RELIABLE;
		if (ioctl(channel_fd, VLDC_IOCTL_OPT_OP, &op) != 0) {
			(void) close(channel_fd);
			return (PCPL_GLVC_ERROR);
		}
		break;
	case GLVC_NON_STREAM:
	default:
		/*
		 * Get the Channel MTU size
		 */

		if (pcp_get_prop(channel_fd, GLVC_XPORT_OPT_MTU_SZ,
		    &mtu_size) != 0) {
			(void) close(channel_fd);
			return (PCPL_GLVC_ERROR);
		}
		break;
	}

	/*
	 * Get current signal mask. If SIGALRM is blocked
	 * unblock it.
	 */
	(void) sigprocmask(0, NULL, &oldset);

	(void) sigemptyset(&blkset);

	if (sigismember(&oldset, SIGALRM)) {
		(void) sigaddset(&blkset, SIGALRM);
		(void) sigprocmask(SIG_UNBLOCK, &blkset, NULL);
	}
	/*
	 * signal handler initialization to handle glvc call timeouts.
	 */
	glvc_act.sa_handler = glvc_timeout_handler;
	(void) sigemptyset(&glvc_act.sa_mask);
	glvc_act.sa_flags = SA_NODEFER;

	if (sigaction(SIGALRM, &glvc_act, &old_act) < 0) {
		(void) close(channel_fd);
		return (PCPL_ERROR);
	}

	return (channel_fd);
}

/*
 * Function: Close platform channel.
 * Arguments:
 *	int channel_fd - channel file descriptor.
 * Returns:
 *	always returns PCPL_OK for now.
 */
int
pcp_close(int channel_fd)
{

	if (channel_fd >= 0) {
		if (xport_type  == GLVC_NON_STREAM)
			(void) pcp_cleanup(channel_fd);
		(void) close(channel_fd);
	} else {
		return (-1);
	}

	/*
	 * free global buffers
	 */
	if (read_area != NULL) {
		umem_free(read_area, READ_AREA_SIZE);
		read_area = NULL;
	}
	if (peek_area != NULL) {
		umem_free(peek_area, PEEK_AREA_SIZE);
		peek_area = NULL;
	}
	if (peek_read_area != NULL) {
		umem_free(peek_read_area, PEEK_READ_AREA_SIZE);
		peek_read_area = NULL;
	}
	if (req_msg_hdr != NULL) {
		umem_free(req_msg_hdr, req_msg_hdr_sz);
		req_msg_hdr = NULL;
	}
	if (resp_msg_hdr != NULL) {
		umem_free(resp_msg_hdr, resp_msg_hdr_sz);
		resp_msg_hdr = NULL;
	}

	/*
	 * Restore SIGALRM signal mask incase if we unblocked
	 * it during pcp_init.
	 */
	if (sigismember(&blkset, SIGALRM)) {
		(void) sigprocmask(SIG_BLOCK, &blkset, NULL);
	}

	/* Restore SIGALRM signal handler */
	(void) sigaction(SIGALRM, &old_act, NULL);

	return (PCPL_OK);
}

/*
 * Function: Send and Receive messages on platform channel.
 * Arguments:
 *	int channel_fd      - channel file descriptor.
 *	pcp_msg_t *req_msg  - Request Message to send to other end of channel.
 *	pcp_msg_t *resp_msg - Response Message to be received.
 *	uint32_t timeout    - timeout field when waiting for data from channel.
 * Returns:
 *	0  - success (PCPL_OK).
 *	(-ve) - failure:
 *			PCPL_INVALID_ARGS - invalid args.
 *			PCPL_GLVC_TIMEOUT - glvc call timeout.
 *			PCPL_XPORT_ERROR - transport error in request message
 *						noticed by receiver.
 *			PCPL_MALLOC_FAIL - malloc failure.
 *			PCPL_CKSUM_ERROR - checksum error.
 */
int
pcp_send_recv(int channel_fd, pcp_msg_t *req_msg, pcp_msg_t *resp_msg,
    uint32_t timeout)
{
	void *datap;
	void *resp_msg_data = NULL;
	uint32_t status;
	uint16_t cksum = 0;
	int ret;
	int resp_hdr_ok;
#ifdef PCP_CKSUM_ENABLE
	uint16_t bkup_resp_hdr_cksum;
#endif
	if (channel_fd < 0) {
		return (PCPL_ERROR);
	}

	/* copy channel_fd to local fd (chnl_fd) for other functions use */
	chnl_fd = channel_fd;

	if (req_msg == NULL) {
		return (PCPL_INVALID_ARGS);
	}

	if (timeout > 0)
		glvc_timeout = timeout;
	else
		glvc_timeout = 0;

	if ((req_msg->msg_len != 0) && ((datap = req_msg->msg_data) == NULL))
		return (PCPL_INVALID_ARGS);

	if (req_msg_hdr == NULL) {
		req_msg_hdr_sz = sizeof (pcp_req_msg_hdr_t);
		req_msg_hdr = (pcp_req_msg_hdr_t *)umem_zalloc(req_msg_hdr_sz,
		    UMEM_DEFAULT);
		if (req_msg_hdr == NULL)
			return (PCPL_MALLOC_FAIL);
	}

	if (req_msg->msg_len != 0) {
		/* calculate request msg_cksum */
		cksum = checksum((uint16_t *)datap, req_msg->msg_len);
	}

	/*
	 * Fill in the message header for the request packet
	 */
	req_msg_hdr->magic_num = PCP_MAGIC_NUM;
	req_msg_hdr->proto_ver = PCP_PROT_VER_1;
	req_msg_hdr->msg_type = req_msg->msg_type;
	req_msg_hdr->sub_type = req_msg->sub_type;
	req_msg_hdr->rsvd_pad = 0;
	req_msg_hdr->xid = pcp_get_xid();
	req_msg_hdr->msg_len  = req_msg->msg_len;
	req_msg_hdr->timeout = timeout;
	req_msg_hdr->msg_cksum = cksum;
	req_msg_hdr->hdr_cksum = 0;

	/* fill request header checksum */
	req_msg_hdr->hdr_cksum = checksum((uint16_t *)req_msg_hdr,
	    req_msg_hdr_sz);
	/*
	 * set sig jmp location
	 */
	if (sigsetjmp(jmpbuf, 1)) {
		return (PCPL_GLVC_TIMEOUT);
	}
	jumpok = 1; /* monitor sigalrm from now on */

	/*
	 * send request message header
	 */
	if ((ret = pcp_send_req_msg_hdr(req_msg_hdr))) {

		return (ret);
	}

	/*
	 * send request message
	 */
	if (req_msg->msg_len != 0) {
		if ((ret = pcp_io_op(datap, req_msg->msg_len,
		    PCPL_IO_OP_WRITE))) {
			return (ret);
		}
	}

	if (timeout == (uint32_t)PCP_TO_NO_RESPONSE)
		return (PCPL_OK);

	if (resp_msg_hdr == NULL) {
		resp_msg_hdr_sz = sizeof (pcp_resp_msg_hdr_t);
		resp_msg_hdr = (pcp_resp_msg_hdr_t *)umem_alloc(resp_msg_hdr_sz,
		    UMEM_DEFAULT);
		if (resp_msg_hdr == NULL)
			return (PCPL_MALLOC_FAIL);
	}

	resp_hdr_ok = 0;
	while (!resp_hdr_ok) {

		/*
		 * Receive response message header
		 * Note: frame error handling is done in
		 * 'pcp_recv_resp_msg_hdr()'.
		 */
		if ((ret = pcp_recv_resp_msg_hdr(resp_msg_hdr))) {
			return (ret);
		}

		/*
		 * Check header checksum if it matches with the received hdr
		 * checksum.
		 */
#ifdef PCP_CKSUM_ENABLE
		bkup_resp_hdr_cksum = resp_msg_hdr->hdr_cksum;
		resp_msg_hdr->hdr_cksum = 0;
		cksum = checksum((uint16_t *)resp_msg_hdr, resp_msg_hdr_sz);

		if (cksum != bkup_resp_hdr_cksum) {
			return (PCPL_CKSUM_ERROR);
		}
#endif
		/*
		 * Check for matching request and response messages
		 */
		if (resp_msg_hdr->xid != req_msg_hdr->xid) {

			continue; /* continue reading response header */
		}
		resp_hdr_ok = 1;
	}

	/*
	 * check status field for any channel protocol errors
	 * This field signifies something happend during request
	 * message trasmission. This field is set by the receiver.
	 */
	status = resp_msg_hdr->status;
	if (status != PCP_OK) {
		return (PCPL_XPORT_ERROR);
	}

	if (resp_msg_hdr->msg_len != 0) {

		/* libpcp users should free this memory */
		if ((resp_msg_data = (uint8_t *)malloc(resp_msg_hdr->msg_len))
		    == NULL)
			return (PCPL_MALLOC_FAIL);
		bzero(resp_msg_data, resp_msg_hdr->msg_len);
		/*
		 * Receive response message.
		 */
		if ((ret = pcp_io_op(resp_msg_data, resp_msg_hdr->msg_len,
		    PCPL_IO_OP_READ))) {
			free(resp_msg_data);
			return (ret);
		}

#ifdef PCP_CKSUM_ENABLE
		/* verify response message data checksum */
		cksum = checksum((uint16_t *)resp_msg_data,
		    resp_msg_hdr->msg_len);
		if (cksum != resp_msg_hdr->msg_cksum) {
			free(resp_msg_data);
			return (PCPL_CKSUM_ERROR);
		}
#endif
	}
	/* Everything is okay put the received data into user */
	/* application's resp_msg struct */
	resp_msg->msg_len = resp_msg_hdr->msg_len;
	resp_msg->msg_type = resp_msg_hdr->msg_type;
	resp_msg->sub_type = resp_msg_hdr->sub_type;
	resp_msg->msg_data = (uint8_t *)resp_msg_data;

	return (PCPL_OK);

}

/*
 * Function: Get channel property values.
 * Arguments:
 *	int channel_fd - channel file descriptor.
 *	int prop - property id.
 *	unsigned int *val - property value tobe copied.
 * Returns:
 *	0 - success
 *	(-ve) - failure:
 *		PCPL_ERR_GLVC - glvc ioctl failure.
 */

static int
pcp_get_prop(int channel_fd, int prop, unsigned int *val)
{
	glvc_xport_opt_op_t	channel_op;
	int			ret;

	channel_op.op_sel = GLVC_XPORT_OPT_GET;
	channel_op.opt_sel = prop;
	channel_op.opt_val = 0;

	(void) alarm(glvc_timeout);

	if ((ret = ioctl(channel_fd, GLVC_XPORT_IOCTL_OPT_OP,
	    &channel_op)) < 0) {

		(void) alarm(0);
		return (ret);
	}
	(void) alarm(0);

	*val = channel_op.opt_val;

	return (0);
}

/*
 * Function: wrapper for handling glvc calls (read/write/peek).
 */
static int
pcp_io_op(void *buf, int byte_cnt, int io_op)
{
	int	rv;
	int	n;
	uint8_t	*datap;
	int	(*func_ptr)(uint8_t *, int);
	int	io_sz;
	int	try_cnt;


	if ((buf == NULL) || (byte_cnt < 0)) {
		return (PCPL_INVALID_ARGS);
	}

	switch (io_op) {
		case PCPL_IO_OP_READ:
			func_ptr = pcp_read;
			break;
		case PCPL_IO_OP_WRITE:
			func_ptr = pcp_write;
			break;
		case PCPL_IO_OP_PEEK:
			func_ptr = pcp_peek;
			break;
		default:
			return (PCPL_INVALID_ARGS);
	}

	/*
	 * loop until all I/O done, try limit exceded, or real failure
	 */

	rv = 0;
	datap = buf;
	while (rv < byte_cnt) {
		io_sz = MIN((byte_cnt - rv), mtu_size);
		try_cnt = 0;
		while ((n = (*func_ptr)(datap, io_sz)) < 0) {
			try_cnt++;
			if (try_cnt > PCPL_MAX_TRY_CNT) {
				rv = n;
				goto done;
			}
			(void) sleep(PCPL_GLVC_SLEEP);
		} /* while trying the io operation */

		if (n < 0) {
			rv = n;
			goto done;
		}
		rv += n;
		datap += n;
	} /* while still have more data */

done:
	if (rv == byte_cnt)
		return (0);
	else
		return (PCPL_GLVC_ERROR);
}

/*
 * For peeking 'bytes_cnt' bytes in channel (glvc) buffers.
 * If data is available, the data is copied into 'buf'.
 */
static int
pcp_peek(uint8_t *buf, int bytes_cnt)
{
	int			ret;
	glvc_xport_msg_peek_t	peek_ctrl;
	int			n, m;

	if (bytes_cnt < 0 || bytes_cnt > mtu_size) {
		return (PCPL_INVALID_ARGS);
	}

	/*
	 * initialization of buffers used for peeking data in channel buffers.
	 */
	if (peek_area == NULL) {
		peek_area = (uint8_t *)umem_zalloc(PEEK_AREA_SIZE,
		    UMEM_DEFAULT);
		if (peek_area == NULL) {
			return (PCPL_MALLOC_FAIL);
		}
	}

	/*
	 * peek max MTU size bytes
	 */
	peek_ctrl.buf = (caddr_t)peek_area;
	peek_ctrl.buflen = mtu_size;
	peek_ctrl.flags = 0;

	(void) alarm(glvc_timeout);

	if ((ret = ioctl(chnl_fd, GLVC_XPORT_IOCTL_DATA_PEEK, &peek_ctrl))
	    < 0) {
		(void) alarm(0);
		return (ret);
	}
	(void) alarm(0);

	n = peek_ctrl.buflen;

	if (n < 0)
		return (PCPL_GLVC_ERROR);

	/*
	 * satisfy request as best as we can
	 */
	m = MIN(bytes_cnt, n);
	(void) memcpy(buf, peek_area, m);

	return (m);
}

/*
 * Function: write 'byte_cnt' bytes from 'buf' to channel.
 */
static int
pcp_write(uint8_t *buf, int byte_cnt)
{

	int	ret;

	/* check for valid arguments */
	if (buf == NULL || byte_cnt < 0 || byte_cnt > mtu_size) {
		return (PCPL_INVALID_ARGS);
	}

	if (xport_type == GLVC_NON_STREAM) {
		(void) alarm(glvc_timeout);

		if ((ret = write(chnl_fd, buf, byte_cnt)) < 0) {
			(void) alarm(0);
			return (ret);
		}
		(void) alarm(0);
	} else {
		if ((ret = vldc_write(chnl_fd, buf, byte_cnt)) <= 0) {
			return (ret);
		}
	}

	return (ret);
}

/*
 * In current implementaion of glvc driver, streams reads are not supported.
 * pcp_read mimics stream reads by first reading all the bytes present in the
 * channel buffer into a local buffer and from then on read requests
 * are serviced from local buffer. When read requests are not serviceble
 * from local buffer, it repeates by first reading data from channel buffers.
 *
 * This call may need to be enhanced when glvc supports buffered (stream)
 * reads - TBD
 */

static int
pcp_read(uint8_t *buf, int byte_cnt)
{
	int			ret;
	int			n, m, i;

	if (byte_cnt < 0 || byte_cnt > mtu_size) {
		return (PCPL_INVALID_ARGS);
	}

	/*
	 * initialization of local read buffer
	 * from which the stream read requests are serviced.
	 */
	if (read_area == NULL) {
		read_area = (uint8_t *)umem_zalloc(READ_AREA_SIZE,
		    UMEM_DEFAULT);
		if (read_area == NULL) {
			return (PCPL_MALLOC_FAIL);
		}
		read_head = read_area;
		read_tail = read_area;
	}

	/*
	 * if we already read this data then copy from local buffer it self
	 * without calling new read.
	 */
	if (byte_cnt <= (read_tail - read_head)) {
		(void) memcpy(buf, read_head, byte_cnt);
		read_head += byte_cnt;
		return (byte_cnt);
	}

	/*
	 * if the request is not satisfied from the buffered data, then move the
	 * remaining data to front of the buffer and read new data.
	 */
	for (i = 0; i < (read_tail - read_head); ++i) {
		read_area[i] = read_head[i];
	}
	read_head = read_area;
	read_tail = read_head + i;

	/*
	 * do a peek to see how much data is available and read complete data.
	 */

	if (xport_type == GLVC_NON_STREAM) {
		if ((m = pcp_peek(read_tail, mtu_size)) < 0) {
			return (m);
		}

		(void) alarm(glvc_timeout);
		if ((ret = read(chnl_fd, read_tail, m)) < 0) {
			(void) alarm(0);
			return (ret);
		}

		(void) alarm(0);
	} else {
		/*
		 * Read the extra number of bytes
		 */
		m = byte_cnt - (read_tail - read_head);
		if ((ret = vldc_read(chnl_fd,
		    read_tail, m)) <= 0) {
			return (ret);
		}
	}
	read_tail += ret;

	/*
	 * copy the requested bytes.
	 */
	n = MIN(byte_cnt, (read_tail - read_head));
	(void) memcpy(buf, read_head, n);

	read_head += n;

	return (n);
}

/*
 * Issue read from the driver until byet_cnt number
 * of bytes are present in read buffer. Do not
 * move the read head.
 */
static int
pcp_update_read_area(int byte_cnt)
{
	int			ret;
	int			n, i;

	if (byte_cnt < 0 || byte_cnt > mtu_size) {
		return (PCPL_INVALID_ARGS);
	}

	/*
	 * initialization of local read buffer
	 * from which the stream read requests are serviced.
	 */
	if (read_area == NULL) {
		read_area = (uint8_t *)umem_zalloc(READ_AREA_SIZE,
		    UMEM_DEFAULT);
		if (read_area == NULL) {
			return (PCPL_MALLOC_FAIL);
		}
		read_head = read_area;
		read_tail = read_area;
	}

	/*
	 * if we already have sufficient data in the buffer,
	 * just return
	 */
	if (byte_cnt <= (read_tail - read_head)) {
		return (byte_cnt);
	}

	/*
	 * if the request is not satisfied from the buffered data, then move the
	 * remaining data to front of the buffer and read new data.
	 */
	for (i = 0; i < (read_tail - read_head); ++i) {
		read_area[i] = read_head[i];
	}
	read_head = read_area;
	read_tail = read_head + i;

	n = byte_cnt - (read_tail - read_head);

	if ((ret = vldc_read(chnl_fd,
	    read_tail, n)) <= 0) {
		return (ret);
	}
	read_tail += ret;

	/*
	 * Return the number of bytes we could read
	 */
	n = MIN(byte_cnt, (read_tail - read_head));

	return (n);
}

/*
 * This function is slight different from pcp_peek. The peek requests are first
 * serviced from local read buffer, if data is available. If the peek request
 * is not serviceble from local read buffer, then the data is peeked from
 * channel buffer. This function is mainly used for proper protocol framing
 * error handling.
 */
static int
pcp_peek_read(uint8_t *buf, int byte_cnt)
{
	int	n, m, i;

	if (byte_cnt < 0 || byte_cnt > mtu_size) {
		return (PCPL_INVALID_ARGS);
	}

	/*
	 * initialization of peek_read buffer.
	 */
	if (peek_read_area == NULL) {
		peek_read_area = (uint8_t *)umem_zalloc(PEEK_READ_AREA_SIZE,
		    UMEM_DEFAULT);
		if (peek_read_area == NULL) {
			return (PCPL_MALLOC_FAIL);
		}
		peek_read_head = peek_read_area;
		peek_read_tail = peek_read_area;
	}

	/*
	 * if we already have the data in local read buffer then copy
	 * from local buffer it self w/out calling new peek
	 */
	if (byte_cnt <= (read_tail - read_head)) {
		(void) memcpy(buf, read_head, byte_cnt);
		return (byte_cnt);
	}

	/*
	 * if the request is not satisfied from local read buffer, then first
	 * copy the remaining data in local read buffer to peek_read_area and
	 * then issue new peek.
	 */
	for (i = 0; i < (read_tail - read_head); ++i) {
		peek_read_area[i] = read_head[i];
	}
	peek_read_head = peek_read_area;
	peek_read_tail = peek_read_head + i;

	/*
	 * do a peek to see how much data is available and read complete data.
	 */

	if ((m = pcp_peek(peek_read_tail, mtu_size)) < 0) {
		return (m);
	}
	peek_read_tail += m;

	/*
	 * copy the requested bytes
	 */
	n = MIN(byte_cnt, (peek_read_tail - peek_read_head));
	(void) memcpy(buf, peek_read_head, n);

	return (n);
}

/*
 * Send Request Message Header.
 */
static int
pcp_send_req_msg_hdr(pcp_req_msg_hdr_t *req_hdr)
{
	pcp_req_msg_hdr_t	*hdrp;
	int			hdr_sz;
	int			ret;

	hdr_sz = sizeof (pcp_req_msg_hdr_t);
	if ((hdrp = (pcp_req_msg_hdr_t *)umem_zalloc(hdr_sz,
	    UMEM_DEFAULT)) == NULL) {
		return (PCPL_MALLOC_FAIL);
	}

	hdrp->magic_num = htonl(req_hdr->magic_num);
	hdrp->proto_ver = req_hdr->proto_ver;
	hdrp->msg_type = req_hdr->msg_type;
	hdrp->sub_type = req_hdr->sub_type;
	hdrp->rsvd_pad = htons(req_hdr->rsvd_pad);
	hdrp->xid = htonl(req_hdr->xid);
	hdrp->timeout = htonl(req_hdr->timeout);
	hdrp->msg_len = htonl(req_hdr->msg_len);
	hdrp->msg_cksum = htons(req_hdr->msg_cksum);
	hdrp->hdr_cksum = htons(req_hdr->hdr_cksum);

	if ((ret = pcp_io_op((char *)hdrp, hdr_sz, PCPL_IO_OP_WRITE)) != 0) {
		umem_free(hdrp, hdr_sz);
		return (ret);
	}
	umem_free(hdrp, hdr_sz);
	return (PCP_OK);
}

/*
 * Receive Response message header.
 */
static int
pcp_recv_resp_msg_hdr(pcp_resp_msg_hdr_t *resp_hdr)
{
	uint32_t	magic_num;
	uint8_t		proto_ver;
	uint8_t		msg_type;
	uint8_t		sub_type;
	uint8_t		rsvd_pad;
	uint32_t	xid;
	uint32_t	timeout;
	uint32_t	msg_len;
	uint32_t	status;
	uint16_t	msg_cksum;
	uint16_t	hdr_cksum;
	int		ret;

	if (resp_hdr == NULL) {
		return (PCPL_INVALID_ARGS);
	}

	/*
	 * handle protocol framing errors.
	 * pcp_frame_error_handle() returns when proper frame arrived
	 * (magic seq) or if an error happens while reading data from
	 * channel.
	 */
	if (xport_type  == GLVC_NON_STREAM)
		ret = pcp_frame_error_handle();
	else
		ret = pcp_vldc_frame_error_handle();

	if (ret != 0)
		return (PCPL_FRAME_ERROR);

	/* read magic number first */
	if ((ret = pcp_io_op(&magic_num, sizeof (magic_num),
	    PCPL_IO_OP_READ)) != 0) {
		return (ret);
	}

	magic_num = ntohl(magic_num);

	if (magic_num != PCP_MAGIC_NUM) {
		return (PCPL_FRAME_ERROR);
	}

	/* read version field */
	if ((ret = pcp_io_op(&proto_ver, sizeof (proto_ver),
	    PCPL_IO_OP_READ)) != 0) {
		return (ret);
	}

	/* check protocol version */
	if (proto_ver != PCP_PROT_VER_1) {
		return (PCPL_PROT_ERROR);
	}

	/* Read message type */
	if ((ret = pcp_io_op(&msg_type, sizeof (msg_type),
	    PCPL_IO_OP_READ)) != 0) {
		return (ret);
	}

	/* Read message sub type */
	if ((ret = pcp_io_op(&sub_type, sizeof (sub_type),
	    PCPL_IO_OP_READ)) != 0) {
		return (ret);
	}

	/* Read rcvd_pad bits */
	if ((ret = pcp_io_op(&rsvd_pad, sizeof (rsvd_pad),
	    PCPL_IO_OP_READ)) != 0) {
		return (ret);
	}

	/* receive transaction id */
	if ((ret = pcp_io_op(&xid, sizeof (xid),
	    PCPL_IO_OP_READ)) != 0) {
		return (ret);
	}

	xid = ntohl(xid);

	/* receive timeout value */
	if ((ret = pcp_io_op(&timeout, sizeof (timeout),
	    PCPL_IO_OP_READ)) != 0) {
		return (ret);
	}

	timeout = ntohl(timeout);

	/* receive message length */
	if ((ret = pcp_io_op(&msg_len, sizeof (msg_len),
	    PCPL_IO_OP_READ)) != 0) {
		return (ret);
	}

	msg_len = ntohl(msg_len);

	/* receive status field */
	if ((ret = pcp_io_op(&status, sizeof (status),
	    PCPL_IO_OP_READ)) != 0) {
		return (ret);
	}

	status = ntohl(status);

	/* receive message checksum */
	if ((ret = pcp_io_op(&msg_cksum, sizeof (msg_cksum),
	    PCPL_IO_OP_READ)) != 0) {
		return (ret);
	}

	msg_cksum = ntohs(msg_cksum);

	/* receive header checksum */
	if ((ret = pcp_io_op(&hdr_cksum, sizeof (hdr_cksum),
	    PCPL_IO_OP_READ)) != 0) {
		return (ret);
	}

	hdr_cksum = ntohs(hdr_cksum);

	/* copy to resp_hdr */

	resp_hdr->magic_num = magic_num;
	resp_hdr->proto_ver = proto_ver;
	resp_hdr->msg_type = msg_type;
	resp_hdr->sub_type = sub_type;
	resp_hdr->rsvd_pad = rsvd_pad;
	resp_hdr->xid = xid;
	resp_hdr->timeout = timeout;
	resp_hdr->msg_len = msg_len;
	resp_hdr->status = status;
	resp_hdr->msg_cksum = msg_cksum;
	resp_hdr->hdr_cksum = hdr_cksum;

	return (PCP_OK);
}

/*
 * Get next xid for including in request message.
 * Every request and response message are matched
 * for same xid.
 */

static uint32_t
pcp_get_xid(void)
{
	uint32_t ret;
	struct timeval tv;
	static boolean_t xid_initialized = B_FALSE;

	if (xid_initialized == B_FALSE) {
		xid_initialized = B_TRUE;
		/*
		 * starting xid is initialized to a different value everytime
		 * user application is restarted so that user apps will not
		 * receive previous session's packets.
		 *
		 * Note: The algorithm for generating initial xid is partially
		 *	 taken from Solaris rpc code.
		 */
		(void) gettimeofday(&tv, NULL);
		msg_xid = (uint32_t)((tv.tv_sec << 20) |
		    (tv.tv_usec >> 10));
	}

	ret = msg_xid++;

	/* zero xid is not allowed */
	if (ret == 0)
		ret = msg_xid++;

	return (ret);
}

/*
 * This function handles channel framing errors. It waits until proper
 * frame with starting sequence as magic numder (0xAFBCAFA0)
 * is arrived. It removes unexpected data (before the magic number sequence)
 * on the channel. It returns when proper magic number sequence is seen
 * or when any failure happens while reading/peeking the channel.
 */
static int
pcp_frame_error_handle(void)
{
	uint8_t		magic_num_buf[4];
	int		ispresent = 0;
	uint32_t	net_magic_num; /* magic byte in network byte order */
	uint32_t	host_magic_num = PCP_MAGIC_NUM;
	uint8_t		buf[2];

	net_magic_num =  htonl(host_magic_num);
	(void) memcpy(magic_num_buf, (uint8_t *)&net_magic_num, 4);

	while (!ispresent) {
		/*
		 * Check if next four bytes matches pcp magic number.
		 * if mathing not found, discard 1 byte and continue checking.
		 */
		if (!check_magic_byte_presence(4, &magic_num_buf[0],
		    &ispresent)) {
			if (!ispresent) {
				/* remove 1 byte */
				(void) pcp_io_op(buf, 1, PCPL_IO_OP_READ);
			}
		} else {
			return (-1);
		}
	}

	return (0);
}

/*
 * This function handles channel framing errors. It waits until proper
 * frame with starting sequence as magic numder (0xAFBCAFA0)
 * is arrived. It removes unexpected data (before the magic number sequence)
 * on the channel. It returns when proper magic number sequence is seen
 * or when any failure happens while reading/peeking the channel.
 */
static int
pcp_vldc_frame_error_handle(void)
{
	uint8_t		magic_num_buf[4];
	uint32_t	net_magic_num; /* magic byte in network byte order */
	uint32_t	host_magic_num = PCP_MAGIC_NUM;
	int		found_magic = 0;

	net_magic_num =  htonl(host_magic_num);
	(void) memcpy(magic_num_buf, (uint8_t *)&net_magic_num, 4);

	/*
	 * For vldc, we need to read whatever data is available and
	 * advance the read pointer one byte at a time until we get
	 * the magic word. When this function is invoked, we do not
	 * have any byte in the read buffer.
	 */

	/*
	 * Keep reading until we find the matching magic number
	 */
	while (!found_magic) {
		while ((read_tail - read_head) < sizeof (host_magic_num)) {
			if (pcp_update_read_area(sizeof (host_magic_num)) < 0)
				return (-1);
		}

		/*
		 * We should have at least 4 bytes in read buffer. Check
		 * if the magic number can be matched
		 */
		if (memcmp(read_head, magic_num_buf,
		    sizeof (host_magic_num))) {
			read_head += 1;
		} else {
			found_magic = 1;
		}
	}

	return (0);
}

/*
 * checks whether certain byte sequence is present in the data stream.
 */
static int
check_magic_byte_presence(int byte_cnt, uint8_t *byte_seq, int *ispresent)
{
	int		ret, i;
	uint8_t		buf[4];

	if ((ret = pcp_peek_read(buf, byte_cnt)) < 0) {
		return (ret);
	}

	/* 'byte_cnt' bytes not present */
	if (ret != byte_cnt) {
		*ispresent = 0;
		return (0);
	}

	for (i = 0; i < byte_cnt; ++i) {
		if (buf[i] != byte_seq[i]) {
			*ispresent = 0;
			return (0);
		}
	}
	*ispresent = 1;

	return (0);
}

/*
 * 16-bit simple internet checksum
 */
static uint16_t
checksum(uint16_t *addr, int32_t count)
{
	/*
	 * Compute Internet Checksum for "count" bytes
	 * beginning at location "addr".
	 */

	register uint32_t	sum = 0;

	while (count > 1)  {
		/*  This is the inner loop */
		sum += *(unsigned short *)addr++;
		count -= 2;
	}

	/*  Add left-over byte, if any */
	if (count > 0)
		sum += * (unsigned char *)addr;

	/* Fold 32-bit sum to 16 bits */
	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);

	sum = (~sum) & 0xffff;
	if (sum == 0)
		sum = 0xffff;

	return (sum);
}

/*
 * cleanup the channel if any data is hanging in
 * channel buffers.
 */
static int
pcp_cleanup(int channel_fd)
{
	int			ret;
	glvc_xport_msg_peek_t	peek_ctrl;
	int			n, done;
	uint8_t			*buf = NULL;
	int			retry = 0;


	buf = (uint8_t *)umem_zalloc((mtu_size), UMEM_DEFAULT);
	if (buf == NULL) {
		return (PCPL_MALLOC_FAIL);
	}

	peek_ctrl.buf = (caddr_t)buf;
	peek_ctrl.buflen = mtu_size;
	peek_ctrl.flags = 0;

	/*
	 * set sig jmp location
	 */
	if (sigsetjmp(jmpbuf, 1)) {
		umem_free(buf, mtu_size);
		return (PCPL_GLVC_TIMEOUT);
	}

	done = 0;
	while (!done) {

		(void) alarm(PCP_CLEANUP_TIMEOUT);
		if ((ret = ioctl(channel_fd, GLVC_XPORT_IOCTL_DATA_PEEK,
		    &peek_ctrl)) < 0) {
			(void) alarm(0);
			done = 1;
			continue;
		}
		(void) alarm(0);

		n = peek_ctrl.buflen;

		if (n <= 0 && retry > 2) {
			done = 1;
			continue;
		} else if (n <= 0) {
			++retry;
			continue;
		}

		/* remove data from channel */
		(void) alarm(PCP_CLEANUP_TIMEOUT);
		if ((ret = read(channel_fd, buf, n)) < 0) {
			(void) alarm(0);
			done = 1;
			continue;
		}
		(void) alarm(0);
	}

	umem_free(buf, mtu_size);
	return (ret);
}

static int
vldc_write(int fd, uint8_t *bufp, int size)
{
	int res;
	int left = size;
	pollfd_t pollfd;

	pollfd.events = POLLOUT;
	pollfd.revents = 0;
	pollfd.fd = fd;

	/*
	 * Poll for the vldc channel to be ready
	 */
	if (poll(&pollfd, 1, glvc_timeout * MILLISEC) <= 0) {
		return (-1);
	}

	do {
		if ((res = write(fd, bufp, left)) <= 0) {
			if (errno != EWOULDBLOCK) {
				return (res);
			}
		} else {
			bufp += res;
			left -= res;
		}
	} while (left > 0);

	/*
	 * Return number of bytes actually written
	 */
	return (size - left);
}

/*
 * Keep reading until we get the specified number of bytes
 */
static int
vldc_read(int fd, uint8_t *bufp, int size)
{
	int res;
	int left = size;

	struct pollfd fds[1];

	fds[0].events = POLLIN | POLLPRI;
	fds[0].revents = 0;
	fds[0].fd = fd;

	if (poll(fds, 1, glvc_timeout * MILLISEC) <= 0) {
		return (-1);
	}

	while (left > 0) {
		res = read(fd, bufp, left);
			/* return on error or short read */
		if ((res == 0) || ((res < 0) &&
		    (errno == EAGAIN))) {
				/* poll until the read is unblocked */
				if ((poll(fds, 1, glvc_timeout * MILLISEC)) < 0)
					return (-1);

				continue;
		} else
		if (res < 0) {
			/* unrecoverable error */

			return (-1);
		} else {
			bufp += res;
			left -= res;
		}
	}

	return (size - left);
}
