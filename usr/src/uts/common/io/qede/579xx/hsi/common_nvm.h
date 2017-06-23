/*
* CDDL HEADER START
*
* The contents of this file are subject to the terms of the
* Common Development and Distribution License, v.1,  (the "License").
* You may not use this file except in compliance with the License.
*
* You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
* or http://opensource.org/licenses/CDDL-1.0.
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
* Copyright 2014-2017 Cavium, Inc. 
* The contents of this file are subject to the terms of the Common Development 
* and Distribution License, v.1,  (the "License").

* You may not use this file except in compliance with the License.

* You can obtain a copy of the License at available 
* at http://opensource.org/licenses/CDDL-1.0

* See the License for the specific language governing permissions and 
* limitations under the License.
*/


#ifndef _COMMON_NVM_H_ 
#define _COMMON_NVM_H_ 

#include "nvm_map.h"
#include "append.h"
// Callbacks:

#ifndef MFW
#ifndef UEFI
	#define TRACE(module, ...) 	EDIAG_ERR(__VA_ARGS__)
#else // UEFI	
	#define TRACE	
#endif
#else // MFW
extern void memset32(u32 *ptr, u32 val, u32 byte_cnt);
extern void memcpy32(u32 *ptr, u32 *src, u32 byte_cnt);
#endif

extern int nvm_read(u32 nvm_addr, u32 n_bytes, u32 *read_buf);
extern void compute_crc_from_buf(u32 *buf_p, u32 len, u32 *crc_p);
extern int nvm_write(u32 nvm_addr, u32 byte_cnt, u32 *buf);
extern int validate_dir(u32 bundle_id, u32 num_images);
extern void nvm_write_progress_cb(u32 byte_cnt, u32 orig_byte_cnt);

#ifndef ERROR
#define ERROR (-1)
#endif

#ifndef OK
#define OK (0)
#endif

#define ROMIMG_NUM_MAX 		8

#define PCIR_OFFSET(f)  ((u32)((int_ptr_t) &(((pci30_rom_hdr *)0)->f)))

typedef enum {
	MBA_MBA_LEGACY_IDX = 0,
	MBA_MBA_PCI3CLP_IDX,
	MBA_MBA_PCI3_IDX,
	MBA_FCODE_IDX,
	EFI_X86_IDX,
	EFI_IPF_IDX,
	EFI_EBC_IDX,
	EFI_X64_IDX
} mba_image_t;

typedef struct _exp_rom_hdr_t
{
#define ROM_HEADER_SIG		0x0AA55
	u16 Signature;
	u8  Size;
	u8  Entry[4];
	u8  Cksum;
	u16 VendorOffset;             /* Offset to vendor_data_t structure */
	u8  reserved1[12];
	u16 ROMIDoffset;
	u16 PCIdsOffset;
	u16 PnPehOffset;              /* Offset to pci_rom_hdr_t structure */
	u8  reserved2[4];
} exp_rom_hdr;

typedef struct _pci30_rom_hdr_t
{
	u8  Signature[4]; /* PCIR */
	u16 VendorID;
	u16 DeviceID;
	u16 VP;
	u16 StructLength;
	u8  StructRev; /* PCI30 or not */
	u8  BaseClass;
	u8  SubClass;
	u8  Interface;
	u16 ImageLength;
	u16 ImageRev;
	u8  CodeType;
	u8  Indicator;
	u16 RunTimeImgLen;
	u16 CfgCodeHdr;
	u16 DmtfEntry;
} pci30_rom_hdr;

/*****************************************************************************
 *
 * FUNCTION:       validate_image_header
 *
 * DESCRIPTION:    Returns the flash size in bytes.
 *
 * INPUT:          p_img_hdr
 *         
 * OUTPUT:         None
 * 
 * RETURNS:        Flash size in bytes
 *****************************************************************************/
int validate_image_header(struct image_header *p_img_hdr);

/*****************************************************************************
 *
 * FUNCTION:       get_flash_size
 *
 * DESCRIPTION:    Returns the flash size in bytes.
 *
 * INPUT:          None
 *         
 * OUTPUT:         None
 * 
 * RETURNS:        Flash size in bytes
 *****************************************************************************/
u32 get_flash_size(void);

/*****************************************************************************
 *
 * FUNCTION:       allocate_nvram_for_image
 *
 * DESCRIPTION:    Responsible allocating nvram room for an image.
 *                 1. Remove the image from the directory (if exists)
 *                 2. In case it is MIM or LIM, select the fixed nvram offset,
 *                    otherwise, use the "find_room_for_image" to find room.
 *                 3. Add the new image_header to the directory.
 *                
 * INPUT:          p_dir - Pointer to directory
 *                 p_image_header - Pointer to the requested image header.
 * 
 * OUTPUT:         o_nvm_offset - nvm offset of the allocated room.
 * 
 * RETURNS:        OK / ERROR
 *****************************************************************************/
int allocate_nvram_for_image(struct nvm_dir *p_dir, struct image_header *p_image_header, u32 *o_nvm_offset);

/*****************************************************************************
 *
 * FUNCTION:       find_room_for_image
 *
 * DESCRIPTION:    Finds room for new nvm image
 *
 * INPUT           image_type
 *      	   byte_cnt
 *      	   p_dir
 * OUTPUT:         out_nvm_offset
 *
 * RETURNS:        OK/ERROR
 *
 *****************************************************************************/
int find_room_for_image(u32 image_type,
						u32 byte_cnt,
						struct nvm_dir *p_dir,
						u32 *out_nvm_offset);

/*****************************************************************************
 *
 * FUNCTION:       get_active_dir
 *
 * DESCRIPTION:    Responsible allocating nvram room for an image.
 *                 1. Read headers of both directories
 *                 2. Validate their CRC with accordance to their sequence number.
 *                 3. In case a directory is valid, return its id along with its next MFW.
 * OUTPUT:         o_dir_id - Active Dir ID
 *                 o_next_mfw - Next MFW scheduled to run from the dir.
 * 
 * RETURNS:        OK / ERROR
 *****************************************************************************/
int get_active_dir(u32 *o_dir_id, u32 *o_next_mfw);

/*****************************************************************************
 *
 * FUNCTION:       prepare_bootstrap
 *
 * DESCRIPTION:    This function updates the active NVM bootstrap. The active bootstrap is
 *                 read by the device ROM upon reset, and according to the bootstrap
 *                 information it loads LIM, which starts running the MFW.
 *
 * INPUT:          i_lim_header - Image header of LIM
 * 
 * OUTPUT:         o_bootstrap - Bootstrap struct to be stored in nvram.
 * 
 * RETURNS:        none
 *****************************************************************************/
void prepare_bootstrap(struct image_header *i_lim_header,
                       struct legacy_bootstrap_region *o_bootstrap);

/*****************************************************************************
 *
 * FUNCTION:       nvm_update_dir
 *
 * DESCRIPTION:    Update directory to nvram.
 *
 * INPUT:          p_dir - Pointer to the directory
 *                 is_mfw - true/false
 * INPUT/OUTPUT:   dir_id - Input - the current dir id. Output - The updated dir id
 * 
 * RETURNS:        none
 *****************************************************************************/
int nvm_update_dir(struct nvm_dir *p_dir, u32 *dir_id, u32 is_mfw);

/*****************************************************************************
 *
 * FUNCTION:       add_nvm_entry_to_dir
 *
 * DESCRIPTION:    Adds new image entry to a given directory.
 *                 1. Verify number of images doesn't exceed some crazy number - 200
 *                 2. Since the dir is sorted according to nvram offset, move up
 *                    all image entries higher than the requested offset for the
 *                    new image entry
 *                 3. Insert the new image entry
 *                 4. Increase the number of entries in the directory.
 *
 * INPUT/OUTPUT    p_dir - Pointer to the directory buffer
 *                 nvm_offset - The nvram address for the new image
 *                 p_image_header - Pointer to the image header.
 *
 * RETURNS:        ERROR/OK
 *****************************************************************************/
int add_nvm_entry_to_dir(struct nvm_dir *p_dir,
                         u32 nvm_offset,
                         struct image_header *p_image_header);

/*****************************************************************************
 * FUNCTION:       get_alt_image_type
 *
 * DESCRIPTION:    If image type is part of the MFW bundle (which has two
 *                 bundles/slots in the nvram), then set the image type as the
 *                 non-running one, otherwise, change nothing.
 * 
 * INPUT:          running_mfw - 0/1
 *                 image_type
 *
 * RETURNS:        Alternate image type
 *****************************************************************************/
u32 get_alt_image_type(u32 running_mfw, u32 image_type);

/*****************************************************************************
 * FUNCTION:       load_active_nvm_dir
 *
 * DESCRIPTION:    Loads the active nvm dir to the o_dir_p
 * 
 * INPUT:          None
 * 
 * OUTPUT:         o_dir_p - Pointer to directory structure to be populated.
 *                 o_cur_dir_id - Active Dir ID
 *
 * RETURNS:        OK/ERROR
 *****************************************************************************/
int load_active_nvm_dir(struct nvm_dir *o_dir_p, u32 *o_cur_dir_id);

/*****************************************************************************
 *
 * FUNCTION:       remove_image_from_dir
 *
 * DESCRIPTION:    Removes requested images from a giveN dir pointer, and
 *                 squeeze images back. In case the requested image is not found,
 *                 it does nothing.
 *                 NOTE: This function doesn't recalc the CRC, or write the dir
 *                 back to nvram !
 *
 * INPUT:          p_dir - pointer to the directory
 *                 image_type - Requested image type to remove
 *
 * RETURNS:        OK - Image removed
 *                 ERROR - Image not found
 *****************************************************************************/
int remove_image_from_dir(struct nvm_dir *p_dir,
                          u32 image_type);

/*****************************************************************************
 *
 * FUNCTION:       inner_nvm_block_write
 *
 * DESCRIPTION:    Internal function for writting block of data to nvram.
 *                 NOTE: 1. This function doesn't take nvram lock to allow multiple
 *                          transactions within the same page.
 *                       2. When calling this function, please use the nvm_flags
 *                          correctly:
 *                          MCP_REG_NVM_COMMAND_FIRST - Sets the FIRST flag on the first
 *                                              transaction.
 *                          MCP_REG_NVM_COMMAND_LAST  - Sets the LAST flag on the last byte write.
 *                                               Avoid setting this flag for multiple
 *                                               transaction on the same page, and set it
 *                                               only for the last one.
 *                                               In any case, the LAST flag will be set at
 *                                               the end of NVM page (4KB).
 *
 * INPUT:          nvm_flags - MCP_REG_NVM_COMMAND_FIRST/MCP_REG_NVM_COMMAND_LAST/0 - See above
 *                 nvm_addr  - Destination nvm address
 *                 byte_cnt  - Number of bytes
 *                 p_buf     - Pointer to the input buffer.
 *
 * RETURNS:        OK - Image removed
 *                 ERROR - Image not found
 *****************************************************************************/
#define MCP_REG_NVM_COMMAND_DISPLAY  (0x1<<31)
int inner_nvm_write(u32 nvm_flags, u32 nvm_addr, u32 byte_cnt, u32 *p_buf);

/**********************************************************************
 * FUNCTION:       find_image_by_type_in_dir
 *
 * DESCRIPTION:    Checks if the requested image type exist in the directory.
 *                 If so, it provide it in the output parameter index, and returns OK
 *                 Otherwise it returns ERROR;
 *
 * INPUT:          dir_p          - Pointer to directory
 *                 requested_type - Image type to look for
 *
 * RETURNS:        OK - If requested image found
 *                 ERROR - Otherwise.
 ***********************************************************************/
int find_image_by_type_in_dir(struct nvm_dir *dir_p,
                              u32 requested_type,
                              u32 *index);

#endif /* _COMMON_NVM_H_ */
