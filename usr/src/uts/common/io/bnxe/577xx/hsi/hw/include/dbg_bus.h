#ifndef _DBUS_ST_H
#define _DBUS_ST_H

#include "bcmtype.h"


typedef struct _dbg_reg_write
{
	u32_t addr;
	u32_t value;
} dbg_reg_write;


typedef struct _dbg_register_set_write
{
	dbg_reg_write *p_reg;
	u32_t count;
}	dbg_register_set_write;


typedef struct _dbg_reg_group
{
	dbg_register_set_write dbgCfg;
	dbg_register_set_write dbgOn;
	dbg_register_set_write dbgOff;
	dbg_register_set_write dbgFlush;
} dbg_reg_group;


typedef struct _dbg_driver_end_read_regs
{
	u32_t dbg_block_on;
	u32_t intr_buffer_read_ptr;
	u32_t intr_buffer_wr_ptr;
	u32_t ext_buffer_wr_ptr_lsb;
	u32_t ext_buffer_wr_ptr_msb;
	u32_t dbg_ovl_on_ext_buffer;
	u32_t dbg_wrap_ext;
} dbg_driver_end_read_regs;


typedef struct _dbg_driver_fill_regs
{
	u32_t ext_buffer_start_addr_lsb;
	u32_t ext_buffer_start_addr_msb;
	u32_t ext_buffer_size; // in 256 byte blocks
	u32_t pci_func_num; // not for E1 
} dbg_driver_fill_regs;


typedef struct _dbg_general_info
{
	u32_t timestamp;
	u32_t chip_num;
	u32_t chosen_config;
	u32_t path_num;
} dbg_general_info;


typedef struct _dbg_dump_hdr
{
	u32_t header_length; // will hold sizeof(dbg_dump_hdr)
	dbg_general_info info;
	dbg_driver_fill_regs driver_filled_info;
	dbg_driver_end_read_regs driver_read_regs;
} dbg_dump_hdr;


#define DBG_E1	0
#define DBG_E1H	1
#define DBG_E2	2
#define DBG_E3	4
extern dbg_general_info dbg_bus_general_info_E1;
extern dbg_driver_fill_regs dbg_bus_driver_fill_regs_E1;
extern dbg_driver_end_read_regs dbg_bus_driver_end_read_regs_E1;
extern dbg_reg_write dbg_bus_all_regs_E1[];
extern dbg_reg_group dbg_bus_configs_E1[6];

extern dbg_general_info dbg_bus_general_info_E1H;
extern dbg_driver_fill_regs dbg_bus_driver_fill_regs_E1H;
extern dbg_driver_end_read_regs dbg_bus_driver_end_read_regs_E1H;
extern dbg_reg_write dbg_bus_all_regs_E1H[];
extern dbg_reg_group dbg_bus_configs_E1H[25];

extern dbg_general_info dbg_bus_general_info_E2;
extern dbg_driver_fill_regs dbg_bus_driver_fill_regs_E2;
extern dbg_driver_end_read_regs dbg_bus_driver_end_read_regs_E2;
extern dbg_reg_write dbg_bus_all_regs_E2[];
extern dbg_reg_group dbg_bus_configs_E2[25];

extern dbg_general_info dbg_bus_general_info_E3;
extern dbg_driver_fill_regs dbg_bus_driver_fill_regs_E3;
extern dbg_driver_end_read_regs dbg_bus_driver_end_read_regs_E3;
extern dbg_reg_write dbg_bus_all_regs_E3[];
extern dbg_reg_group dbg_bus_configs_E3[34];



#endif //_DBUS_ST_H
