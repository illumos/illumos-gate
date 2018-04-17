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

#ifndef _USER_DBG_FW_FUNCS_H
#define _USER_DBG_FW_FUNCS_H
/******************************** Constants **********************************/

#define MAX_NAME_LEN	16


/***************************** Public Functions *******************************/

/**
 * @brief ecore_dbg_user_set_bin_ptr - Sets a pointer to the binary data with
 * debug arrays.
 *
 * @param bin_ptr - a pointer to the binary data with debug arrays.
 */
enum dbg_status ecore_dbg_user_set_bin_ptr(const u8 * const bin_ptr);

/**
 * @brief ecore_dbg_get_storm_id - Returns an ID for the specified storm name.
 *
 * @param storm_name - Storm name.
 *
 * @return an ID for the specified storm name, or NUM_OF_STORMS if not found.
 */
enum dbg_storms ecore_dbg_get_storm_id(const char *storm_name);

/**
 * @brief ecore_dbg_get_block_id - Returns an ID for the specified block name.
 *
 * @param block_name - Block name.
 *
 * @return an ID for the specified block name, or NUM_OF_BLOCKS if not found.
 */
enum block_id ecore_dbg_get_block_id(const char *block_name);

/**
 * @brief ecore_dbg_get_storm_mode_id - Returns an ID for the specified Storm
 * mode name.
 *
 * @param storm_mode_name - Storm mode name.
 *
 * @return an ID for the specified Storm mode name, or MAX_DBG_BUS_STORM_MODES
 * if not found.
 */
enum dbg_bus_storm_modes ecore_dbg_get_storm_mode_id(const char *storm_mode_name);

/**
 * @brief ecore_dbg_get_constraint_op_id - Returns an ID for the specified
 * constraint operation name.
 *
 * @param op_name - operation name.
 *
 * @return an ID for the specified constraint operation name, or
 * MAX_DBG_BUS_CONSTRAINT_OPS if not found.
 */
enum dbg_bus_constraint_ops ecore_dbg_get_constraint_op_id(const char *op_name);

/**
 * @brief ecore_dbg_get_status_str - Returns a string for the specified status.
 *
 * @param status - a debug status code.
 *
 * @return a string for the specified status
 */
const char* ecore_dbg_get_status_str(enum dbg_status status);

/**
 * @brief ecore_dbg_get_grc_param_id - Returns an ID for the specified GRC
 * param name.
 *
 * @param param_name - GRC param name.
 *
 * @return an ID for the specified GRC param name, or NUM_OF_GRC_PARAMS if not
 * found.
 */
enum dbg_grc_params ecore_dbg_get_grc_param_id(const char *param_name);

/**
 * @brief ecore_dbg_get_dbg_bus_line - Returns an ID for the specified Debug Bus
 * line.
 *
 * @param block_id - block ID
 * @param chip_id -  chip ID
 * @param line -     a string containing a debug line name that belongs to the
 *		     specified block/chip, or an 8-bit debug line number.
 *
 * @return an ID for the specified Debug Bus line name, or -1 if not found.
 */
int ecore_dbg_get_dbg_bus_line(enum block_id block_id, enum chip_ids chip_id, const char *line);

/**
 * @brief ecore_get_idle_chk_results_buf_size - Returns the required buffer
 * size for idle check results (in bytes).
 *
 * @param p_hwfn -		      HW device data
 * @param dump_buf -	      idle check dump buffer.
 * @param num_dumped_dwords - number of dwords that were dumped.
 * @param results_buf_size -  OUT: required buffer size (in bytes) for the
 *			      parsed results.
 *
 * @return error if the parsing fails, ok otherwise.
 */
enum dbg_status ecore_get_idle_chk_results_buf_size(struct ecore_hwfn *p_hwfn,
													u32 *dump_buf,
													u32 num_dumped_dwords,
													u32 *results_buf_size);

/**
 * @brief ecore_print_idle_chk_results - Prints idle check results
 *
 * @param p_hwfn -			HW device data
 * @param dump_buf -		idle check dump buffer.
 * @param num_dumped_dwords -	number of dwords that were dumped.
 * @param results_buf -		buffer for printing the idle check results.
 * @param num_errors -		OUT: number of errors found in idle check.
 * @param num_warnings -	OUT: number of warnings found in idle check.
 *
 * @return error if the parsing fails, ok otherwise.
 */
enum dbg_status ecore_print_idle_chk_results(struct ecore_hwfn *p_hwfn,
											 u32 *dump_buf,
											 u32 num_dumped_dwords,
											 char *results_buf,
											 u32 *num_errors,
											 u32 *num_warnings);

/**
 * @brief ecore_dbg_mcp_trace_set_meta_data - Sets a pointer to the MCP Trace
 * meta data.
 *
 * Needed in case the MCP Trace dump doesn't contain the meta data (e.g. due to
 * no NVRAM access).
 *
 * @param data - pointer to MCP Trace meta data
 * @param size - size of MCP Trace meta data in dwords
 */
void ecore_dbg_mcp_trace_set_meta_data(u32 *data,
									   u32 size);

/**
 * @brief ecore_get_mcp_trace_results_buf_size - Returns the required buffer
 * size for MCP Trace results (in bytes).
 *
 * @param p_hwfn -		      HW device data
 * @param dump_buf -	      MCP Trace dump buffer.
 * @param num_dumped_dwords - number of dwords that were dumped.
 * @param results_buf_size -  OUT: required buffer size (in bytes) for the
 *			      parsed results.
 *
 * @return error if the parsing fails, ok otherwise.
 */
enum dbg_status ecore_get_mcp_trace_results_buf_size(struct ecore_hwfn *p_hwfn,
													 u32 *dump_buf,
													 u32 num_dumped_dwords,
													 u32 *results_buf_size);


/**
 * @brief ecore_print_mcp_trace_results - Prints MCP Trace results
 *
 * @param p_hwfn -		      HW device data
 * @param dump_buf -	      mcp trace dump buffer, starting from the header.
 * @param num_dumped_dwords - number of dwords that were dumped.
 * @param results_buf -	      buffer for printing the mcp trace results.
 *
 * @return error if the parsing fails, ok otherwise.
 */
enum dbg_status ecore_print_mcp_trace_results(struct ecore_hwfn *p_hwfn,
											  u32 *dump_buf,
											  u32 num_dumped_dwords,
											  char *results_buf);

/**
 * @brief ecore_get_reg_fifo_results_buf_size - Returns the required buffer
 * size for reg_fifo results (in bytes).
 *
 * @param p_hwfn -		      HW device data
 * @param dump_buf -	      reg fifo dump buffer.
 * @param num_dumped_dwords - number of dwords that were dumped.
 * @param results_buf_size -  OUT: required buffer size (in bytes) for the
 *			      parsed results.
 *
 * @return error if the parsing fails, ok otherwise.
 */
enum dbg_status ecore_get_reg_fifo_results_buf_size(struct ecore_hwfn *p_hwfn,
													u32 *dump_buf,
													u32 num_dumped_dwords,
													u32 *results_buf_size);

/**
 * @brief ecore_print_reg_fifo_results - Prints reg fifo results
 *
 * @param p_hwfn -			HW device data
 * @param dump_buf -		reg fifo dump buffer, starting from the header.
 * @param num_dumped_dwords -	number of dwords that were dumped.
 * @param results_buf -		buffer for printing the reg fifo results.
 *
 * @return error if the parsing fails, ok otherwise.
 */
enum dbg_status ecore_print_reg_fifo_results(struct ecore_hwfn *p_hwfn,
											 u32 *dump_buf,
											 u32 num_dumped_dwords,
											 char *results_buf);

/**
 * @brief ecore_get_igu_fifo_results_buf_size - Returns the required buffer size
 * for igu_fifo results (in bytes).
 *
 * @param p_hwfn -		      HW device data
 * @param dump_buf -	      IGU fifo dump buffer.
 * @param num_dumped_dwords - number of dwords that were dumped.
 * @param results_buf_size -  OUT: required buffer size (in bytes) for the
 *			      parsed results.
 *
 * @return error if the parsing fails, ok otherwise.
 */
enum dbg_status ecore_get_igu_fifo_results_buf_size(struct ecore_hwfn *p_hwfn,
													u32 *dump_buf,
													u32 num_dumped_dwords,
													u32 *results_buf_size);

/**
* @brief ecore_print_igu_fifo_results - Prints IGU fifo results
*
* @param p_hwfn -		     HW device data
* @param dump_buf -	     IGU fifo dump buffer, starting from the header.
* @param num_dumped_dwords - number of dwords that were dumped.
* @param results_buf -	     buffer for printing the IGU fifo results.
*
* @return error if the parsing fails, ok otherwise.
*/
enum dbg_status ecore_print_igu_fifo_results(struct ecore_hwfn *p_hwfn,
											 u32 *dump_buf,
											 u32 num_dumped_dwords,
											 char *results_buf);

/**
 * @brief ecore_get_protection_override_results_buf_size - Returns the required
 * buffer size for protection override results (in bytes).
 *
 * @param p_hwfn -		      HW device data
 * @param dump_buf -	      protection override dump buffer.
 * @param num_dumped_dwords - number of dwords that were dumped.
 * @param results_buf_size -  OUT: required buffer size (in bytes) for the parsed results.
 *
 * @return error if the parsing fails, ok otherwise.
 */
enum dbg_status ecore_get_protection_override_results_buf_size(struct ecore_hwfn *p_hwfn,
															   u32 *dump_buf,
															   u32 num_dumped_dwords,
															   u32 *results_buf_size);

/*
 * @brief ecore_print_protection_override_results - Prints protection override
 * results.
 *
 * @param p_hwfn -               HW device data
 * @param dump_buf -          protection override dump buffer, starting from
 *			      the header.
 * @param num_dumped_dwords - number of dwords that were dumped.
 * @param results_buf -       buffer for printing the reg fifo results.
 *
 * @return error if the parsing fails, ok otherwise.
 */
enum dbg_status ecore_print_protection_override_results(struct ecore_hwfn *p_hwfn,
														u32 *dump_buf,
														u32 num_dumped_dwords,
														char *results_buf);

/**
 * @brief ecore_get_fw_asserts_results_buf_size - Returns the required buffer
 * size for FW Asserts results (in bytes).
 *
 * @param p_hwfn -		      HW device data
 * @param dump_buf -	      FW Asserts dump buffer.
 * @param num_dumped_dwords - number of dwords that were dumped.
 * @param results_buf_size -  OUT: required buffer size (in bytes) for the
 *			      parsed results.
 *
 * @return error if the parsing fails, ok otherwise.
*/
enum dbg_status ecore_get_fw_asserts_results_buf_size(struct ecore_hwfn *p_hwfn,
													  u32 *dump_buf,
													  u32 num_dumped_dwords,
													  u32 *results_buf_size);

/**
* @brief ecore_print_fw_asserts_results - Prints FW Asserts results
*
* @param p_hwfn -		     HW device data
* @param dump_buf -	     FW Asserts dump buffer, starting from the header.
* @param num_dumped_dwords - number of dwords that were dumped.
* @param results_buf -	     buffer for printing the FW Asserts results.
*
* @return error if the parsing fails, ok otherwise.
*/
enum dbg_status ecore_print_fw_asserts_results(struct ecore_hwfn *p_hwfn,
											   u32 *dump_buf,
											   u32 num_dumped_dwords,
											   char *results_buf);

/**
 * @brief ecore_dbg_parse_attn - Parses and prints attention registers values in
 * the specified results struct.
 *
 * @param p_hwfn -	    HW device data
 * @param results - Pointer to the attention read results
 *
 * @return error if one of the following holds:
 *	- the version wasn't set
 * Otherwise, returns ok.
 */
enum dbg_status ecore_dbg_parse_attn(struct ecore_hwfn *p_hwfn,
									 struct dbg_attn_block_result *results);


#endif
