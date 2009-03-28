/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Part of Intel(R) Manageability Engine Interface Linux driver
 *
 * Copyright (c) 2003 - 2008 Intel Corp.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions, and the following disclaimer,
 *    without modification.
 * 2. Redistributions in binary form must reproduce at minimum a disclaimer
 *    substantially similar to the "NO WARRANTY" disclaimer below
 *    ("Disclaimer") and any redistribution must be conditioned upon
 *    including a substantially similar Disclaimer requirement for further
 *    binary redistribution.
 * 3. Neither the names of the above-listed copyright holders nor the names
 *    of any contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * Alternatively, this software may be distributed under the terms of the
 * GNU General Public License ("GPL") version 2 as published by the Free
 * Software Foundation.
 *
 * NO WARRANTY
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDERS OR CONTRIBUTORS BE LIABLE FOR SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGES.
 *
 */

#ifndef	_HECI_H_
#define	_HECI_H_


extern const struct guid heci_pthi_guid;
extern const struct guid heci_wd_guid;
extern const uint8_t start_wd_params[];
extern const uint8_t stop_wd_params[];
extern const uint8_t heci_wd_state_independence_msg[3][4];

/*
 * heci device ID
 */
#define	HECI_DEV_ID_82946GZ    0x2974  /* 82946GZ/GL */
#define	HECI_DEV_ID_82G35	0x2984  /* 82G35 Express */
#define	HECI_DEV_ID_82Q965	0x2994  /* 82Q963/Q965 */
#define	HECI_DEV_ID_82G965	0x29A4  /* 82P965/G965 */

#define	HECI_DEV_ID_82GM965	0x2A04  /* Mobile PM965/GM965 */
#define	HECI_DEV_ID_82GME965	0x2A14  /* Mobile GME965/GLE960 */

#define	HECI_DEV_ID_ICH9_82Q35	0x29B4  /* 82Q35 Express */
#define	HECI_DEV_ID_ICH9_82G33 0x29C4  /* 82G33/G31/P35/P31 Express */
#define	HECI_DEV_ID_ICH9_82Q33 0x29D4  /* 82Q33 Express */
#define	HECI_DEV_ID_ICH9_82X38 0x29E4  /* 82X38/X48 Express */
#define	HECI_DEV_ID_ICH9_3200  0x29F4  /* 3200/3210 Server */

#define	HECI_DEV_ID_ICH9_6	0x28B4  /* Bearlake */
#define	HECI_DEV_ID_ICH9_7	0x28C4  /* Bearlake */
#define	HECI_DEV_ID_ICH9_8	0x28D4  /* Bearlake */
#define	HECI_DEV_ID_ICH9_9	0x28E4  /* Bearlake */
#define	HECI_DEV_ID_ICH9_10	0x28F4  /* Bearlake */

#define	HECI_DEV_ID_ICH9M_1	0x2A44  /* Cantiga */
#define	HECI_DEV_ID_ICH9M_2	0x2A54  /* Cantiga */
#define	HECI_DEV_ID_ICH9M_3	0x2A64  /* Cantiga */
#define	HECI_DEV_ID_ICH9M_4	0x2A74  /* Cantiga */

#define	HECI_DEV_ID_ICH10_1	0x2E04  /* Eaglelake */
#define	HECI_DEV_ID_ICH10_2	0x2E14  /* Eaglelake */
#define	HECI_DEV_ID_ICH10_3	0x2E24  /* Eaglelake */
#define	HECI_DEV_ID_ICH10_4	0x2E34  /* Eaglelake */

/*
 * heci init function prototypes
 */
void init_heci_device(dev_info_t *dip,
	struct iamt_heci_device *device);
void fini_heci_device(struct iamt_heci_device *device);
void heci_reset(struct iamt_heci_device *dev, int interrupts);
int heci_hw_init(struct iamt_heci_device *dev);
void heci_task_initialize_clients(void *data);
int heci_initialize_clients(struct iamt_heci_device *dev);
struct heci_file_private *heci_alloc_file_private(struct heci_file *file);
int heci_disconnect_host_client(struct iamt_heci_device *dev,
				struct heci_file_private *file_ext);
void heci_initialize_list(struct io_heci_list *list,
	struct iamt_heci_device *dev);
void heci_flush_list(struct io_heci_list *list,
	struct heci_file_private *file_ext);
void heci_flush_queues(struct iamt_heci_device *dev,
	struct heci_file_private *file_ext);

void heci_remove_client_from_file_list(struct iamt_heci_device *dev,
	uint8_t host_client_id);

/*
 *  interrupt function prototype
 */
uint_t heci_isr_interrupt(caddr_t);

void heci_wd_timer(void *data);

/*
 *  input output function prototype
 */
int heci_ioctl_get_version(struct iamt_heci_device *device, int if_num,
	struct heci_message_data *u_msg, struct heci_message_data k_msg,
	struct heci_file_private *file_ext,
	int mode);

int heci_ioctl_connect_client(struct iamt_heci_device *dev, int if_num,
	struct heci_message_data *u_msg, struct heci_message_data k_msg,
	struct heci_file *file, int mode);

int heci_ioctl_wd(struct iamt_heci_device *device, int if_num,
	struct heci_message_data k_msg,
	struct heci_file_private *file_ext, int mode);

int heci_ioctl_bypass_wd(struct iamt_heci_device *device, int if_num,
	struct heci_message_data k_msg,
	struct heci_file_private *file_ext, int mode);

int heci_start_read(struct iamt_heci_device *device, int if_num,
	struct heci_file_private *file_ext);

int pthi_write(struct iamt_heci_device *device,
	struct heci_cb_private *priv_cb);

int pthi_read(struct iamt_heci_device *device, int if_num,
	struct heci_file *file, struct uio *uio_p);

struct heci_cb_private *find_pthi_read_list_entry(
	struct iamt_heci_device *device, struct heci_file *file);

void run_next_iamthif_cmd(struct iamt_heci_device *device);

void heci_free_cb_private(struct heci_cb_private *priv_cb);

void heci_free_file_private(struct heci_file_private *priv);

#endif /* _HECI_H_ */
