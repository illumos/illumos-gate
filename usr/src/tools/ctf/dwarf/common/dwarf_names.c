/* Generated routines, do not edit. */
/* Generated on May 22 2011  03:05:33 */

/* BEGIN FILE */

#include "dwarf.h"

#include "libdwarf.h"

/* ARGSUSED */
int
dwarf_get_TAG_name (unsigned int val,const char ** s_out)
{
    switch (val) {
    case DW_TAG_array_type:
        *s_out = "DW_TAG_array_type";
        return DW_DLV_OK;
    case DW_TAG_class_type:
        *s_out = "DW_TAG_class_type";
        return DW_DLV_OK;
    case DW_TAG_entry_point:
        *s_out = "DW_TAG_entry_point";
        return DW_DLV_OK;
    case DW_TAG_enumeration_type:
        *s_out = "DW_TAG_enumeration_type";
        return DW_DLV_OK;
    case DW_TAG_formal_parameter:
        *s_out = "DW_TAG_formal_parameter";
        return DW_DLV_OK;
    case DW_TAG_imported_declaration:
        *s_out = "DW_TAG_imported_declaration";
        return DW_DLV_OK;
    case DW_TAG_label:
        *s_out = "DW_TAG_label";
        return DW_DLV_OK;
    case DW_TAG_lexical_block:
        *s_out = "DW_TAG_lexical_block";
        return DW_DLV_OK;
    case DW_TAG_member:
        *s_out = "DW_TAG_member";
        return DW_DLV_OK;
    case DW_TAG_pointer_type:
        *s_out = "DW_TAG_pointer_type";
        return DW_DLV_OK;
    case DW_TAG_reference_type:
        *s_out = "DW_TAG_reference_type";
        return DW_DLV_OK;
    case DW_TAG_compile_unit:
        *s_out = "DW_TAG_compile_unit";
        return DW_DLV_OK;
    case DW_TAG_string_type:
        *s_out = "DW_TAG_string_type";
        return DW_DLV_OK;
    case DW_TAG_structure_type:
        *s_out = "DW_TAG_structure_type";
        return DW_DLV_OK;
    case DW_TAG_subroutine_type:
        *s_out = "DW_TAG_subroutine_type";
        return DW_DLV_OK;
    case DW_TAG_typedef:
        *s_out = "DW_TAG_typedef";
        return DW_DLV_OK;
    case DW_TAG_union_type:
        *s_out = "DW_TAG_union_type";
        return DW_DLV_OK;
    case DW_TAG_unspecified_parameters:
        *s_out = "DW_TAG_unspecified_parameters";
        return DW_DLV_OK;
    case DW_TAG_variant:
        *s_out = "DW_TAG_variant";
        return DW_DLV_OK;
    case DW_TAG_common_block:
        *s_out = "DW_TAG_common_block";
        return DW_DLV_OK;
    case DW_TAG_common_inclusion:
        *s_out = "DW_TAG_common_inclusion";
        return DW_DLV_OK;
    case DW_TAG_inheritance:
        *s_out = "DW_TAG_inheritance";
        return DW_DLV_OK;
    case DW_TAG_inlined_subroutine:
        *s_out = "DW_TAG_inlined_subroutine";
        return DW_DLV_OK;
    case DW_TAG_module:
        *s_out = "DW_TAG_module";
        return DW_DLV_OK;
    case DW_TAG_ptr_to_member_type:
        *s_out = "DW_TAG_ptr_to_member_type";
        return DW_DLV_OK;
    case DW_TAG_set_type:
        *s_out = "DW_TAG_set_type";
        return DW_DLV_OK;
    case DW_TAG_subrange_type:
        *s_out = "DW_TAG_subrange_type";
        return DW_DLV_OK;
    case DW_TAG_with_stmt:
        *s_out = "DW_TAG_with_stmt";
        return DW_DLV_OK;
    case DW_TAG_access_declaration:
        *s_out = "DW_TAG_access_declaration";
        return DW_DLV_OK;
    case DW_TAG_base_type:
        *s_out = "DW_TAG_base_type";
        return DW_DLV_OK;
    case DW_TAG_catch_block:
        *s_out = "DW_TAG_catch_block";
        return DW_DLV_OK;
    case DW_TAG_const_type:
        *s_out = "DW_TAG_const_type";
        return DW_DLV_OK;
    case DW_TAG_constant:
        *s_out = "DW_TAG_constant";
        return DW_DLV_OK;
    case DW_TAG_enumerator:
        *s_out = "DW_TAG_enumerator";
        return DW_DLV_OK;
    case DW_TAG_file_type:
        *s_out = "DW_TAG_file_type";
        return DW_DLV_OK;
    case DW_TAG_friend:
        *s_out = "DW_TAG_friend";
        return DW_DLV_OK;
    case DW_TAG_namelist:
        *s_out = "DW_TAG_namelist";
        return DW_DLV_OK;
    case DW_TAG_namelist_item:
        *s_out = "DW_TAG_namelist_item";
        return DW_DLV_OK;
    case DW_TAG_packed_type:
        *s_out = "DW_TAG_packed_type";
        return DW_DLV_OK;
    case DW_TAG_subprogram:
        *s_out = "DW_TAG_subprogram";
        return DW_DLV_OK;
    case DW_TAG_template_type_parameter:
        *s_out = "DW_TAG_template_type_parameter";
        return DW_DLV_OK;
    case DW_TAG_template_value_parameter:
        *s_out = "DW_TAG_template_value_parameter";
        return DW_DLV_OK;
    case DW_TAG_thrown_type:
        *s_out = "DW_TAG_thrown_type";
        return DW_DLV_OK;
    case DW_TAG_try_block:
        *s_out = "DW_TAG_try_block";
        return DW_DLV_OK;
    case DW_TAG_variant_part:
        *s_out = "DW_TAG_variant_part";
        return DW_DLV_OK;
    case DW_TAG_variable:
        *s_out = "DW_TAG_variable";
        return DW_DLV_OK;
    case DW_TAG_volatile_type:
        *s_out = "DW_TAG_volatile_type";
        return DW_DLV_OK;
    case DW_TAG_dwarf_procedure:
        *s_out = "DW_TAG_dwarf_procedure";
        return DW_DLV_OK;
    case DW_TAG_restrict_type:
        *s_out = "DW_TAG_restrict_type";
        return DW_DLV_OK;
    case DW_TAG_interface_type:
        *s_out = "DW_TAG_interface_type";
        return DW_DLV_OK;
    case DW_TAG_namespace:
        *s_out = "DW_TAG_namespace";
        return DW_DLV_OK;
    case DW_TAG_imported_module:
        *s_out = "DW_TAG_imported_module";
        return DW_DLV_OK;
    case DW_TAG_unspecified_type:
        *s_out = "DW_TAG_unspecified_type";
        return DW_DLV_OK;
    case DW_TAG_partial_unit:
        *s_out = "DW_TAG_partial_unit";
        return DW_DLV_OK;
    case DW_TAG_imported_unit:
        *s_out = "DW_TAG_imported_unit";
        return DW_DLV_OK;
    case DW_TAG_mutable_type:
        *s_out = "DW_TAG_mutable_type";
        return DW_DLV_OK;
    case DW_TAG_condition:
        *s_out = "DW_TAG_condition";
        return DW_DLV_OK;
    case DW_TAG_shared_type:
        *s_out = "DW_TAG_shared_type";
        return DW_DLV_OK;
    case DW_TAG_type_unit:
        *s_out = "DW_TAG_type_unit";
        return DW_DLV_OK;
    case DW_TAG_rvalue_reference_type:
        *s_out = "DW_TAG_rvalue_reference_type";
        return DW_DLV_OK;
    case DW_TAG_template_alias:
        *s_out = "DW_TAG_template_alias";
        return DW_DLV_OK;
    case DW_TAG_lo_user:
        *s_out = "DW_TAG_lo_user";
        return DW_DLV_OK;
    case DW_TAG_MIPS_loop:
        *s_out = "DW_TAG_MIPS_loop";
        return DW_DLV_OK;
    case DW_TAG_HP_array_descriptor:
        *s_out = "DW_TAG_HP_array_descriptor";
        return DW_DLV_OK;
    case DW_TAG_format_label:
        *s_out = "DW_TAG_format_label";
        return DW_DLV_OK;
    case DW_TAG_function_template:
        *s_out = "DW_TAG_function_template";
        return DW_DLV_OK;
    case DW_TAG_class_template:
        *s_out = "DW_TAG_class_template";
        return DW_DLV_OK;
    case DW_TAG_GNU_BINCL:
        *s_out = "DW_TAG_GNU_BINCL";
        return DW_DLV_OK;
    case DW_TAG_GNU_EINCL:
        *s_out = "DW_TAG_GNU_EINCL";
        return DW_DLV_OK;
    case DW_TAG_GNU_template_template_parameter:
        *s_out = "DW_TAG_GNU_template_template_parameter";
        return DW_DLV_OK;
    case DW_TAG_GNU_template_parameter_pack:
        *s_out = "DW_TAG_GNU_template_parameter_pack";
        return DW_DLV_OK;
    case DW_TAG_GNU_formal_parameter_pack:
        *s_out = "DW_TAG_GNU_formal_parameter_pack";
        return DW_DLV_OK;
    case DW_TAG_SUN_function_template:
        *s_out = "DW_TAG_SUN_function_template";
        return DW_DLV_OK;
    case DW_TAG_SUN_class_template:
        *s_out = "DW_TAG_SUN_class_template";
        return DW_DLV_OK;
    case DW_TAG_SUN_struct_template:
        *s_out = "DW_TAG_SUN_struct_template";
        return DW_DLV_OK;
    case DW_TAG_SUN_union_template:
        *s_out = "DW_TAG_SUN_union_template";
        return DW_DLV_OK;
    case DW_TAG_SUN_indirect_inheritance:
        *s_out = "DW_TAG_SUN_indirect_inheritance";
        return DW_DLV_OK;
    case DW_TAG_SUN_codeflags:
        *s_out = "DW_TAG_SUN_codeflags";
        return DW_DLV_OK;
    case DW_TAG_SUN_memop_info:
        *s_out = "DW_TAG_SUN_memop_info";
        return DW_DLV_OK;
    case DW_TAG_SUN_omp_child_func:
        *s_out = "DW_TAG_SUN_omp_child_func";
        return DW_DLV_OK;
    case DW_TAG_SUN_rtti_descriptor:
        *s_out = "DW_TAG_SUN_rtti_descriptor";
        return DW_DLV_OK;
    case DW_TAG_SUN_dtor_info:
        *s_out = "DW_TAG_SUN_dtor_info";
        return DW_DLV_OK;
    case DW_TAG_SUN_dtor:
        *s_out = "DW_TAG_SUN_dtor";
        return DW_DLV_OK;
    case DW_TAG_SUN_f90_interface:
        *s_out = "DW_TAG_SUN_f90_interface";
        return DW_DLV_OK;
    case DW_TAG_SUN_fortran_vax_structure:
        *s_out = "DW_TAG_SUN_fortran_vax_structure";
        return DW_DLV_OK;
    case DW_TAG_SUN_hi:
        *s_out = "DW_TAG_SUN_hi";
        return DW_DLV_OK;
    case DW_TAG_ALTIUM_circ_type:
        *s_out = "DW_TAG_ALTIUM_circ_type";
        return DW_DLV_OK;
    case DW_TAG_ALTIUM_mwa_circ_type:
        *s_out = "DW_TAG_ALTIUM_mwa_circ_type";
        return DW_DLV_OK;
    case DW_TAG_ALTIUM_rev_carry_type:
        *s_out = "DW_TAG_ALTIUM_rev_carry_type";
        return DW_DLV_OK;
    case DW_TAG_ALTIUM_rom:
        *s_out = "DW_TAG_ALTIUM_rom";
        return DW_DLV_OK;
    case DW_TAG_upc_shared_type:
        *s_out = "DW_TAG_upc_shared_type";
        return DW_DLV_OK;
    case DW_TAG_upc_strict_type:
        *s_out = "DW_TAG_upc_strict_type";
        return DW_DLV_OK;
    case DW_TAG_upc_relaxed_type:
        *s_out = "DW_TAG_upc_relaxed_type";
        return DW_DLV_OK;
    case DW_TAG_PGI_kanji_type:
        *s_out = "DW_TAG_PGI_kanji_type";
        return DW_DLV_OK;
    case DW_TAG_PGI_interface_block:
        *s_out = "DW_TAG_PGI_interface_block";
        return DW_DLV_OK;
    case DW_TAG_hi_user:
        *s_out = "DW_TAG_hi_user";
        return DW_DLV_OK;
    }
    return DW_DLV_NO_ENTRY; 
}
/* ARGSUSED */
int
dwarf_get_children_name (unsigned int val,const char ** s_out)
{
    switch (val) {
    case DW_children_no:
        *s_out = "DW_children_no";
        return DW_DLV_OK;
    case DW_children_yes:
        *s_out = "DW_children_yes";
        return DW_DLV_OK;
    }
    return DW_DLV_NO_ENTRY; 
}
/* ARGSUSED */
int
dwarf_get_FORM_name (unsigned int val,const char ** s_out)
{
    switch (val) {
    case DW_FORM_addr:
        *s_out = "DW_FORM_addr";
        return DW_DLV_OK;
    case DW_FORM_block2:
        *s_out = "DW_FORM_block2";
        return DW_DLV_OK;
    case DW_FORM_block4:
        *s_out = "DW_FORM_block4";
        return DW_DLV_OK;
    case DW_FORM_data2:
        *s_out = "DW_FORM_data2";
        return DW_DLV_OK;
    case DW_FORM_data4:
        *s_out = "DW_FORM_data4";
        return DW_DLV_OK;
    case DW_FORM_data8:
        *s_out = "DW_FORM_data8";
        return DW_DLV_OK;
    case DW_FORM_string:
        *s_out = "DW_FORM_string";
        return DW_DLV_OK;
    case DW_FORM_block:
        *s_out = "DW_FORM_block";
        return DW_DLV_OK;
    case DW_FORM_block1:
        *s_out = "DW_FORM_block1";
        return DW_DLV_OK;
    case DW_FORM_data1:
        *s_out = "DW_FORM_data1";
        return DW_DLV_OK;
    case DW_FORM_flag:
        *s_out = "DW_FORM_flag";
        return DW_DLV_OK;
    case DW_FORM_sdata:
        *s_out = "DW_FORM_sdata";
        return DW_DLV_OK;
    case DW_FORM_strp:
        *s_out = "DW_FORM_strp";
        return DW_DLV_OK;
    case DW_FORM_udata:
        *s_out = "DW_FORM_udata";
        return DW_DLV_OK;
    case DW_FORM_ref_addr:
        *s_out = "DW_FORM_ref_addr";
        return DW_DLV_OK;
    case DW_FORM_ref1:
        *s_out = "DW_FORM_ref1";
        return DW_DLV_OK;
    case DW_FORM_ref2:
        *s_out = "DW_FORM_ref2";
        return DW_DLV_OK;
    case DW_FORM_ref4:
        *s_out = "DW_FORM_ref4";
        return DW_DLV_OK;
    case DW_FORM_ref8:
        *s_out = "DW_FORM_ref8";
        return DW_DLV_OK;
    case DW_FORM_ref_udata:
        *s_out = "DW_FORM_ref_udata";
        return DW_DLV_OK;
    case DW_FORM_indirect:
        *s_out = "DW_FORM_indirect";
        return DW_DLV_OK;
    case DW_FORM_sec_offset:
        *s_out = "DW_FORM_sec_offset";
        return DW_DLV_OK;
    case DW_FORM_exprloc:
        *s_out = "DW_FORM_exprloc";
        return DW_DLV_OK;
    case DW_FORM_flag_present:
        *s_out = "DW_FORM_flag_present";
        return DW_DLV_OK;
    case DW_FORM_ref_sig8:
        *s_out = "DW_FORM_ref_sig8";
        return DW_DLV_OK;
    }
    return DW_DLV_NO_ENTRY; 
}
/* ARGSUSED */
int
dwarf_get_AT_name (unsigned int val,const char ** s_out)
{
    switch (val) {
    case DW_AT_sibling:
        *s_out = "DW_AT_sibling";
        return DW_DLV_OK;
    case DW_AT_location:
        *s_out = "DW_AT_location";
        return DW_DLV_OK;
    case DW_AT_name:
        *s_out = "DW_AT_name";
        return DW_DLV_OK;
    case DW_AT_ordering:
        *s_out = "DW_AT_ordering";
        return DW_DLV_OK;
    case DW_AT_subscr_data:
        *s_out = "DW_AT_subscr_data";
        return DW_DLV_OK;
    case DW_AT_byte_size:
        *s_out = "DW_AT_byte_size";
        return DW_DLV_OK;
    case DW_AT_bit_offset:
        *s_out = "DW_AT_bit_offset";
        return DW_DLV_OK;
    case DW_AT_bit_size:
        *s_out = "DW_AT_bit_size";
        return DW_DLV_OK;
    case DW_AT_element_list:
        *s_out = "DW_AT_element_list";
        return DW_DLV_OK;
    case DW_AT_stmt_list:
        *s_out = "DW_AT_stmt_list";
        return DW_DLV_OK;
    case DW_AT_low_pc:
        *s_out = "DW_AT_low_pc";
        return DW_DLV_OK;
    case DW_AT_high_pc:
        *s_out = "DW_AT_high_pc";
        return DW_DLV_OK;
    case DW_AT_language:
        *s_out = "DW_AT_language";
        return DW_DLV_OK;
    case DW_AT_member:
        *s_out = "DW_AT_member";
        return DW_DLV_OK;
    case DW_AT_discr:
        *s_out = "DW_AT_discr";
        return DW_DLV_OK;
    case DW_AT_discr_value:
        *s_out = "DW_AT_discr_value";
        return DW_DLV_OK;
    case DW_AT_visibility:
        *s_out = "DW_AT_visibility";
        return DW_DLV_OK;
    case DW_AT_import:
        *s_out = "DW_AT_import";
        return DW_DLV_OK;
    case DW_AT_string_length:
        *s_out = "DW_AT_string_length";
        return DW_DLV_OK;
    case DW_AT_common_reference:
        *s_out = "DW_AT_common_reference";
        return DW_DLV_OK;
    case DW_AT_comp_dir:
        *s_out = "DW_AT_comp_dir";
        return DW_DLV_OK;
    case DW_AT_const_value:
        *s_out = "DW_AT_const_value";
        return DW_DLV_OK;
    case DW_AT_containing_type:
        *s_out = "DW_AT_containing_type";
        return DW_DLV_OK;
    case DW_AT_default_value:
        *s_out = "DW_AT_default_value";
        return DW_DLV_OK;
    case DW_AT_inline:
        *s_out = "DW_AT_inline";
        return DW_DLV_OK;
    case DW_AT_is_optional:
        *s_out = "DW_AT_is_optional";
        return DW_DLV_OK;
    case DW_AT_lower_bound:
        *s_out = "DW_AT_lower_bound";
        return DW_DLV_OK;
    case DW_AT_producer:
        *s_out = "DW_AT_producer";
        return DW_DLV_OK;
    case DW_AT_prototyped:
        *s_out = "DW_AT_prototyped";
        return DW_DLV_OK;
    case DW_AT_return_addr:
        *s_out = "DW_AT_return_addr";
        return DW_DLV_OK;
    case DW_AT_start_scope:
        *s_out = "DW_AT_start_scope";
        return DW_DLV_OK;
    case DW_AT_bit_stride:
        *s_out = "DW_AT_bit_stride";
        return DW_DLV_OK;
    case DW_AT_upper_bound:
        *s_out = "DW_AT_upper_bound";
        return DW_DLV_OK;
    case DW_AT_abstract_origin:
        *s_out = "DW_AT_abstract_origin";
        return DW_DLV_OK;
    case DW_AT_accessibility:
        *s_out = "DW_AT_accessibility";
        return DW_DLV_OK;
    case DW_AT_address_class:
        *s_out = "DW_AT_address_class";
        return DW_DLV_OK;
    case DW_AT_artificial:
        *s_out = "DW_AT_artificial";
        return DW_DLV_OK;
    case DW_AT_base_types:
        *s_out = "DW_AT_base_types";
        return DW_DLV_OK;
    case DW_AT_calling_convention:
        *s_out = "DW_AT_calling_convention";
        return DW_DLV_OK;
    case DW_AT_count:
        *s_out = "DW_AT_count";
        return DW_DLV_OK;
    case DW_AT_data_member_location:
        *s_out = "DW_AT_data_member_location";
        return DW_DLV_OK;
    case DW_AT_decl_column:
        *s_out = "DW_AT_decl_column";
        return DW_DLV_OK;
    case DW_AT_decl_file:
        *s_out = "DW_AT_decl_file";
        return DW_DLV_OK;
    case DW_AT_decl_line:
        *s_out = "DW_AT_decl_line";
        return DW_DLV_OK;
    case DW_AT_declaration:
        *s_out = "DW_AT_declaration";
        return DW_DLV_OK;
    case DW_AT_discr_list:
        *s_out = "DW_AT_discr_list";
        return DW_DLV_OK;
    case DW_AT_encoding:
        *s_out = "DW_AT_encoding";
        return DW_DLV_OK;
    case DW_AT_external:
        *s_out = "DW_AT_external";
        return DW_DLV_OK;
    case DW_AT_frame_base:
        *s_out = "DW_AT_frame_base";
        return DW_DLV_OK;
    case DW_AT_friend:
        *s_out = "DW_AT_friend";
        return DW_DLV_OK;
    case DW_AT_identifier_case:
        *s_out = "DW_AT_identifier_case";
        return DW_DLV_OK;
    case DW_AT_macro_info:
        *s_out = "DW_AT_macro_info";
        return DW_DLV_OK;
    case DW_AT_namelist_item:
        *s_out = "DW_AT_namelist_item";
        return DW_DLV_OK;
    case DW_AT_priority:
        *s_out = "DW_AT_priority";
        return DW_DLV_OK;
    case DW_AT_segment:
        *s_out = "DW_AT_segment";
        return DW_DLV_OK;
    case DW_AT_specification:
        *s_out = "DW_AT_specification";
        return DW_DLV_OK;
    case DW_AT_static_link:
        *s_out = "DW_AT_static_link";
        return DW_DLV_OK;
    case DW_AT_type:
        *s_out = "DW_AT_type";
        return DW_DLV_OK;
    case DW_AT_use_location:
        *s_out = "DW_AT_use_location";
        return DW_DLV_OK;
    case DW_AT_variable_parameter:
        *s_out = "DW_AT_variable_parameter";
        return DW_DLV_OK;
    case DW_AT_virtuality:
        *s_out = "DW_AT_virtuality";
        return DW_DLV_OK;
    case DW_AT_vtable_elem_location:
        *s_out = "DW_AT_vtable_elem_location";
        return DW_DLV_OK;
    case DW_AT_allocated:
        *s_out = "DW_AT_allocated";
        return DW_DLV_OK;
    case DW_AT_associated:
        *s_out = "DW_AT_associated";
        return DW_DLV_OK;
    case DW_AT_data_location:
        *s_out = "DW_AT_data_location";
        return DW_DLV_OK;
    case DW_AT_stride:
        *s_out = "DW_AT_stride";
        return DW_DLV_OK;
    case DW_AT_entry_pc:
        *s_out = "DW_AT_entry_pc";
        return DW_DLV_OK;
    case DW_AT_use_UTF8:
        *s_out = "DW_AT_use_UTF8";
        return DW_DLV_OK;
    case DW_AT_extension:
        *s_out = "DW_AT_extension";
        return DW_DLV_OK;
    case DW_AT_ranges:
        *s_out = "DW_AT_ranges";
        return DW_DLV_OK;
    case DW_AT_trampoline:
        *s_out = "DW_AT_trampoline";
        return DW_DLV_OK;
    case DW_AT_call_column:
        *s_out = "DW_AT_call_column";
        return DW_DLV_OK;
    case DW_AT_call_file:
        *s_out = "DW_AT_call_file";
        return DW_DLV_OK;
    case DW_AT_call_line:
        *s_out = "DW_AT_call_line";
        return DW_DLV_OK;
    case DW_AT_description:
        *s_out = "DW_AT_description";
        return DW_DLV_OK;
    case DW_AT_binary_scale:
        *s_out = "DW_AT_binary_scale";
        return DW_DLV_OK;
    case DW_AT_decimal_scale:
        *s_out = "DW_AT_decimal_scale";
        return DW_DLV_OK;
    case DW_AT_small:
        *s_out = "DW_AT_small";
        return DW_DLV_OK;
    case DW_AT_decimal_sign:
        *s_out = "DW_AT_decimal_sign";
        return DW_DLV_OK;
    case DW_AT_digit_count:
        *s_out = "DW_AT_digit_count";
        return DW_DLV_OK;
    case DW_AT_picture_string:
        *s_out = "DW_AT_picture_string";
        return DW_DLV_OK;
    case DW_AT_mutable:
        *s_out = "DW_AT_mutable";
        return DW_DLV_OK;
    case DW_AT_threads_scaled:
        *s_out = "DW_AT_threads_scaled";
        return DW_DLV_OK;
    case DW_AT_explicit:
        *s_out = "DW_AT_explicit";
        return DW_DLV_OK;
    case DW_AT_object_pointer:
        *s_out = "DW_AT_object_pointer";
        return DW_DLV_OK;
    case DW_AT_endianity:
        *s_out = "DW_AT_endianity";
        return DW_DLV_OK;
    case DW_AT_elemental:
        *s_out = "DW_AT_elemental";
        return DW_DLV_OK;
    case DW_AT_pure:
        *s_out = "DW_AT_pure";
        return DW_DLV_OK;
    case DW_AT_recursive:
        *s_out = "DW_AT_recursive";
        return DW_DLV_OK;
    case DW_AT_signature:
        *s_out = "DW_AT_signature";
        return DW_DLV_OK;
    case DW_AT_main_subprogram:
        *s_out = "DW_AT_main_subprogram";
        return DW_DLV_OK;
    case DW_AT_data_bit_offset:
        *s_out = "DW_AT_data_bit_offset";
        return DW_DLV_OK;
    case DW_AT_const_expr:
        *s_out = "DW_AT_const_expr";
        return DW_DLV_OK;
    case DW_AT_enum_class:
        *s_out = "DW_AT_enum_class";
        return DW_DLV_OK;
    case DW_AT_linkage_name:
        *s_out = "DW_AT_linkage_name";
        return DW_DLV_OK;
    case DW_AT_lo_user:
        *s_out = "DW_AT_lo_user";
        return DW_DLV_OK;
    case DW_AT_HP_unmodifiable:
        *s_out = "DW_AT_HP_unmodifiable";
        return DW_DLV_OK;
    case DW_AT_MIPS_loop_begin:
        *s_out = "DW_AT_MIPS_loop_begin";
        return DW_DLV_OK;
    case DW_AT_CPQ_split_lifetimes_var:
        *s_out = "DW_AT_CPQ_split_lifetimes_var";
        return DW_DLV_OK;
    case DW_AT_MIPS_epilog_begin:
        *s_out = "DW_AT_MIPS_epilog_begin";
        return DW_DLV_OK;
    case DW_AT_CPQ_prologue_length:
        *s_out = "DW_AT_CPQ_prologue_length";
        return DW_DLV_OK;
    case DW_AT_MIPS_software_pipeline_depth:
        *s_out = "DW_AT_MIPS_software_pipeline_depth";
        return DW_DLV_OK;
    case DW_AT_MIPS_linkage_name:
        *s_out = "DW_AT_MIPS_linkage_name";
        return DW_DLV_OK;
    case DW_AT_MIPS_stride:
        *s_out = "DW_AT_MIPS_stride";
        return DW_DLV_OK;
    case DW_AT_MIPS_abstract_name:
        *s_out = "DW_AT_MIPS_abstract_name";
        return DW_DLV_OK;
    case DW_AT_MIPS_clone_origin:
        *s_out = "DW_AT_MIPS_clone_origin";
        return DW_DLV_OK;
    case DW_AT_MIPS_has_inlines:
        *s_out = "DW_AT_MIPS_has_inlines";
        return DW_DLV_OK;
    case DW_AT_MIPS_stride_byte:
        *s_out = "DW_AT_MIPS_stride_byte";
        return DW_DLV_OK;
    case DW_AT_MIPS_stride_elem:
        *s_out = "DW_AT_MIPS_stride_elem";
        return DW_DLV_OK;
    case DW_AT_MIPS_ptr_dopetype:
        *s_out = "DW_AT_MIPS_ptr_dopetype";
        return DW_DLV_OK;
    case DW_AT_MIPS_allocatable_dopetype:
        *s_out = "DW_AT_MIPS_allocatable_dopetype";
        return DW_DLV_OK;
    case DW_AT_MIPS_assumed_shape_dopetype:
        *s_out = "DW_AT_MIPS_assumed_shape_dopetype";
        return DW_DLV_OK;
    case DW_AT_HP_proc_per_section:
        *s_out = "DW_AT_HP_proc_per_section";
        return DW_DLV_OK;
    case DW_AT_HP_raw_data_ptr:
        *s_out = "DW_AT_HP_raw_data_ptr";
        return DW_DLV_OK;
    case DW_AT_HP_pass_by_reference:
        *s_out = "DW_AT_HP_pass_by_reference";
        return DW_DLV_OK;
    case DW_AT_HP_opt_level:
        *s_out = "DW_AT_HP_opt_level";
        return DW_DLV_OK;
    case DW_AT_HP_prof_version_id:
        *s_out = "DW_AT_HP_prof_version_id";
        return DW_DLV_OK;
    case DW_AT_HP_opt_flags:
        *s_out = "DW_AT_HP_opt_flags";
        return DW_DLV_OK;
    case DW_AT_HP_cold_region_low_pc:
        *s_out = "DW_AT_HP_cold_region_low_pc";
        return DW_DLV_OK;
    case DW_AT_HP_cold_region_high_pc:
        *s_out = "DW_AT_HP_cold_region_high_pc";
        return DW_DLV_OK;
    case DW_AT_HP_all_variables_modifiable:
        *s_out = "DW_AT_HP_all_variables_modifiable";
        return DW_DLV_OK;
    case DW_AT_HP_linkage_name:
        *s_out = "DW_AT_HP_linkage_name";
        return DW_DLV_OK;
    case DW_AT_HP_prof_flags:
        *s_out = "DW_AT_HP_prof_flags";
        return DW_DLV_OK;
    case DW_AT_INTEL_other_endian:
        *s_out = "DW_AT_INTEL_other_endian";
        return DW_DLV_OK;
    case DW_AT_sf_names:
        *s_out = "DW_AT_sf_names";
        return DW_DLV_OK;
    case DW_AT_src_info:
        *s_out = "DW_AT_src_info";
        return DW_DLV_OK;
    case DW_AT_mac_info:
        *s_out = "DW_AT_mac_info";
        return DW_DLV_OK;
    case DW_AT_src_coords:
        *s_out = "DW_AT_src_coords";
        return DW_DLV_OK;
    case DW_AT_body_begin:
        *s_out = "DW_AT_body_begin";
        return DW_DLV_OK;
    case DW_AT_body_end:
        *s_out = "DW_AT_body_end";
        return DW_DLV_OK;
    case DW_AT_GNU_vector:
        *s_out = "DW_AT_GNU_vector";
        return DW_DLV_OK;
    case DW_AT_GNU_template_name:
        *s_out = "DW_AT_GNU_template_name";
        return DW_DLV_OK;
    case DW_AT_VMS_rtnbeg_pd_address:
        *s_out = "DW_AT_VMS_rtnbeg_pd_address";
        return DW_DLV_OK;
    case DW_AT_SUN_alignment:
        *s_out = "DW_AT_SUN_alignment";
        return DW_DLV_OK;
    case DW_AT_SUN_vtable:
        *s_out = "DW_AT_SUN_vtable";
        return DW_DLV_OK;
    case DW_AT_SUN_count_guarantee:
        *s_out = "DW_AT_SUN_count_guarantee";
        return DW_DLV_OK;
    case DW_AT_SUN_command_line:
        *s_out = "DW_AT_SUN_command_line";
        return DW_DLV_OK;
    case DW_AT_SUN_vbase:
        *s_out = "DW_AT_SUN_vbase";
        return DW_DLV_OK;
    case DW_AT_SUN_compile_options:
        *s_out = "DW_AT_SUN_compile_options";
        return DW_DLV_OK;
    case DW_AT_SUN_language:
        *s_out = "DW_AT_SUN_language";
        return DW_DLV_OK;
    case DW_AT_SUN_browser_file:
        *s_out = "DW_AT_SUN_browser_file";
        return DW_DLV_OK;
    case DW_AT_SUN_vtable_abi:
        *s_out = "DW_AT_SUN_vtable_abi";
        return DW_DLV_OK;
    case DW_AT_SUN_func_offsets:
        *s_out = "DW_AT_SUN_func_offsets";
        return DW_DLV_OK;
    case DW_AT_SUN_cf_kind:
        *s_out = "DW_AT_SUN_cf_kind";
        return DW_DLV_OK;
    case DW_AT_SUN_vtable_index:
        *s_out = "DW_AT_SUN_vtable_index";
        return DW_DLV_OK;
    case DW_AT_SUN_omp_tpriv_addr:
        *s_out = "DW_AT_SUN_omp_tpriv_addr";
        return DW_DLV_OK;
    case DW_AT_SUN_omp_child_func:
        *s_out = "DW_AT_SUN_omp_child_func";
        return DW_DLV_OK;
    case DW_AT_SUN_func_offset:
        *s_out = "DW_AT_SUN_func_offset";
        return DW_DLV_OK;
    case DW_AT_SUN_memop_type_ref:
        *s_out = "DW_AT_SUN_memop_type_ref";
        return DW_DLV_OK;
    case DW_AT_SUN_profile_id:
        *s_out = "DW_AT_SUN_profile_id";
        return DW_DLV_OK;
    case DW_AT_SUN_memop_signature:
        *s_out = "DW_AT_SUN_memop_signature";
        return DW_DLV_OK;
    case DW_AT_SUN_obj_dir:
        *s_out = "DW_AT_SUN_obj_dir";
        return DW_DLV_OK;
    case DW_AT_SUN_obj_file:
        *s_out = "DW_AT_SUN_obj_file";
        return DW_DLV_OK;
    case DW_AT_SUN_original_name:
        *s_out = "DW_AT_SUN_original_name";
        return DW_DLV_OK;
    case DW_AT_SUN_hwcprof_signature:
        *s_out = "DW_AT_SUN_hwcprof_signature";
        return DW_DLV_OK;
    case DW_AT_SUN_amd64_parmdump:
        *s_out = "DW_AT_SUN_amd64_parmdump";
        return DW_DLV_OK;
    case DW_AT_SUN_part_link_name:
        *s_out = "DW_AT_SUN_part_link_name";
        return DW_DLV_OK;
    case DW_AT_SUN_link_name:
        *s_out = "DW_AT_SUN_link_name";
        return DW_DLV_OK;
    case DW_AT_SUN_pass_with_const:
        *s_out = "DW_AT_SUN_pass_with_const";
        return DW_DLV_OK;
    case DW_AT_SUN_return_with_const:
        *s_out = "DW_AT_SUN_return_with_const";
        return DW_DLV_OK;
    case DW_AT_SUN_import_by_name:
        *s_out = "DW_AT_SUN_import_by_name";
        return DW_DLV_OK;
    case DW_AT_SUN_f90_pointer:
        *s_out = "DW_AT_SUN_f90_pointer";
        return DW_DLV_OK;
    case DW_AT_SUN_pass_by_ref:
        *s_out = "DW_AT_SUN_pass_by_ref";
        return DW_DLV_OK;
    case DW_AT_SUN_f90_allocatable:
        *s_out = "DW_AT_SUN_f90_allocatable";
        return DW_DLV_OK;
    case DW_AT_SUN_f90_assumed_shape_array:
        *s_out = "DW_AT_SUN_f90_assumed_shape_array";
        return DW_DLV_OK;
    case DW_AT_SUN_c_vla:
        *s_out = "DW_AT_SUN_c_vla";
        return DW_DLV_OK;
    case DW_AT_SUN_return_value_ptr:
        *s_out = "DW_AT_SUN_return_value_ptr";
        return DW_DLV_OK;
    case DW_AT_SUN_dtor_start:
        *s_out = "DW_AT_SUN_dtor_start";
        return DW_DLV_OK;
    case DW_AT_SUN_dtor_length:
        *s_out = "DW_AT_SUN_dtor_length";
        return DW_DLV_OK;
    case DW_AT_SUN_dtor_state_initial:
        *s_out = "DW_AT_SUN_dtor_state_initial";
        return DW_DLV_OK;
    case DW_AT_SUN_dtor_state_final:
        *s_out = "DW_AT_SUN_dtor_state_final";
        return DW_DLV_OK;
    case DW_AT_SUN_dtor_state_deltas:
        *s_out = "DW_AT_SUN_dtor_state_deltas";
        return DW_DLV_OK;
    case DW_AT_SUN_import_by_lname:
        *s_out = "DW_AT_SUN_import_by_lname";
        return DW_DLV_OK;
    case DW_AT_SUN_f90_use_only:
        *s_out = "DW_AT_SUN_f90_use_only";
        return DW_DLV_OK;
    case DW_AT_SUN_namelist_spec:
        *s_out = "DW_AT_SUN_namelist_spec";
        return DW_DLV_OK;
    case DW_AT_SUN_is_omp_child_func:
        *s_out = "DW_AT_SUN_is_omp_child_func";
        return DW_DLV_OK;
    case DW_AT_SUN_fortran_main_alias:
        *s_out = "DW_AT_SUN_fortran_main_alias";
        return DW_DLV_OK;
    case DW_AT_SUN_fortran_based:
        *s_out = "DW_AT_SUN_fortran_based";
        return DW_DLV_OK;
    case DW_AT_ALTIUM_loclist:
        *s_out = "DW_AT_ALTIUM_loclist";
        return DW_DLV_OK;
    case DW_AT_upc_threads_scaled:
        *s_out = "DW_AT_upc_threads_scaled";
        return DW_DLV_OK;
    case DW_AT_PGI_lbase:
        *s_out = "DW_AT_PGI_lbase";
        return DW_DLV_OK;
    case DW_AT_PGI_soffset:
        *s_out = "DW_AT_PGI_soffset";
        return DW_DLV_OK;
    case DW_AT_PGI_lstride:
        *s_out = "DW_AT_PGI_lstride";
        return DW_DLV_OK;
    case DW_AT_APPLE_closure:
        *s_out = "DW_AT_APPLE_closure";
        return DW_DLV_OK;
    case DW_AT_APPLE_major_runtime_vers:
        *s_out = "DW_AT_APPLE_major_runtime_vers";
        return DW_DLV_OK;
    case DW_AT_APPLE_runtime_class:
        *s_out = "DW_AT_APPLE_runtime_class";
        return DW_DLV_OK;
    case DW_AT_hi_user:
        *s_out = "DW_AT_hi_user";
        return DW_DLV_OK;
    }
    return DW_DLV_NO_ENTRY; 
}
/* ARGSUSED */
int
dwarf_get_OP_name (unsigned int val,const char ** s_out)
{
    switch (val) {
    case DW_OP_addr:
        *s_out = "DW_OP_addr";
        return DW_DLV_OK;
    case DW_OP_deref:
        *s_out = "DW_OP_deref";
        return DW_DLV_OK;
    case DW_OP_const1u:
        *s_out = "DW_OP_const1u";
        return DW_DLV_OK;
    case DW_OP_const1s:
        *s_out = "DW_OP_const1s";
        return DW_DLV_OK;
    case DW_OP_const2u:
        *s_out = "DW_OP_const2u";
        return DW_DLV_OK;
    case DW_OP_const2s:
        *s_out = "DW_OP_const2s";
        return DW_DLV_OK;
    case DW_OP_const4u:
        *s_out = "DW_OP_const4u";
        return DW_DLV_OK;
    case DW_OP_const4s:
        *s_out = "DW_OP_const4s";
        return DW_DLV_OK;
    case DW_OP_const8u:
        *s_out = "DW_OP_const8u";
        return DW_DLV_OK;
    case DW_OP_const8s:
        *s_out = "DW_OP_const8s";
        return DW_DLV_OK;
    case DW_OP_constu:
        *s_out = "DW_OP_constu";
        return DW_DLV_OK;
    case DW_OP_consts:
        *s_out = "DW_OP_consts";
        return DW_DLV_OK;
    case DW_OP_dup:
        *s_out = "DW_OP_dup";
        return DW_DLV_OK;
    case DW_OP_drop:
        *s_out = "DW_OP_drop";
        return DW_DLV_OK;
    case DW_OP_over:
        *s_out = "DW_OP_over";
        return DW_DLV_OK;
    case DW_OP_pick:
        *s_out = "DW_OP_pick";
        return DW_DLV_OK;
    case DW_OP_swap:
        *s_out = "DW_OP_swap";
        return DW_DLV_OK;
    case DW_OP_rot:
        *s_out = "DW_OP_rot";
        return DW_DLV_OK;
    case DW_OP_xderef:
        *s_out = "DW_OP_xderef";
        return DW_DLV_OK;
    case DW_OP_abs:
        *s_out = "DW_OP_abs";
        return DW_DLV_OK;
    case DW_OP_and:
        *s_out = "DW_OP_and";
        return DW_DLV_OK;
    case DW_OP_div:
        *s_out = "DW_OP_div";
        return DW_DLV_OK;
    case DW_OP_minus:
        *s_out = "DW_OP_minus";
        return DW_DLV_OK;
    case DW_OP_mod:
        *s_out = "DW_OP_mod";
        return DW_DLV_OK;
    case DW_OP_mul:
        *s_out = "DW_OP_mul";
        return DW_DLV_OK;
    case DW_OP_neg:
        *s_out = "DW_OP_neg";
        return DW_DLV_OK;
    case DW_OP_not:
        *s_out = "DW_OP_not";
        return DW_DLV_OK;
    case DW_OP_or:
        *s_out = "DW_OP_or";
        return DW_DLV_OK;
    case DW_OP_plus:
        *s_out = "DW_OP_plus";
        return DW_DLV_OK;
    case DW_OP_plus_uconst:
        *s_out = "DW_OP_plus_uconst";
        return DW_DLV_OK;
    case DW_OP_shl:
        *s_out = "DW_OP_shl";
        return DW_DLV_OK;
    case DW_OP_shr:
        *s_out = "DW_OP_shr";
        return DW_DLV_OK;
    case DW_OP_shra:
        *s_out = "DW_OP_shra";
        return DW_DLV_OK;
    case DW_OP_xor:
        *s_out = "DW_OP_xor";
        return DW_DLV_OK;
    case DW_OP_bra:
        *s_out = "DW_OP_bra";
        return DW_DLV_OK;
    case DW_OP_eq:
        *s_out = "DW_OP_eq";
        return DW_DLV_OK;
    case DW_OP_ge:
        *s_out = "DW_OP_ge";
        return DW_DLV_OK;
    case DW_OP_gt:
        *s_out = "DW_OP_gt";
        return DW_DLV_OK;
    case DW_OP_le:
        *s_out = "DW_OP_le";
        return DW_DLV_OK;
    case DW_OP_lt:
        *s_out = "DW_OP_lt";
        return DW_DLV_OK;
    case DW_OP_ne:
        *s_out = "DW_OP_ne";
        return DW_DLV_OK;
    case DW_OP_skip:
        *s_out = "DW_OP_skip";
        return DW_DLV_OK;
    case DW_OP_lit0:
        *s_out = "DW_OP_lit0";
        return DW_DLV_OK;
    case DW_OP_lit1:
        *s_out = "DW_OP_lit1";
        return DW_DLV_OK;
    case DW_OP_lit2:
        *s_out = "DW_OP_lit2";
        return DW_DLV_OK;
    case DW_OP_lit3:
        *s_out = "DW_OP_lit3";
        return DW_DLV_OK;
    case DW_OP_lit4:
        *s_out = "DW_OP_lit4";
        return DW_DLV_OK;
    case DW_OP_lit5:
        *s_out = "DW_OP_lit5";
        return DW_DLV_OK;
    case DW_OP_lit6:
        *s_out = "DW_OP_lit6";
        return DW_DLV_OK;
    case DW_OP_lit7:
        *s_out = "DW_OP_lit7";
        return DW_DLV_OK;
    case DW_OP_lit8:
        *s_out = "DW_OP_lit8";
        return DW_DLV_OK;
    case DW_OP_lit9:
        *s_out = "DW_OP_lit9";
        return DW_DLV_OK;
    case DW_OP_lit10:
        *s_out = "DW_OP_lit10";
        return DW_DLV_OK;
    case DW_OP_lit11:
        *s_out = "DW_OP_lit11";
        return DW_DLV_OK;
    case DW_OP_lit12:
        *s_out = "DW_OP_lit12";
        return DW_DLV_OK;
    case DW_OP_lit13:
        *s_out = "DW_OP_lit13";
        return DW_DLV_OK;
    case DW_OP_lit14:
        *s_out = "DW_OP_lit14";
        return DW_DLV_OK;
    case DW_OP_lit15:
        *s_out = "DW_OP_lit15";
        return DW_DLV_OK;
    case DW_OP_lit16:
        *s_out = "DW_OP_lit16";
        return DW_DLV_OK;
    case DW_OP_lit17:
        *s_out = "DW_OP_lit17";
        return DW_DLV_OK;
    case DW_OP_lit18:
        *s_out = "DW_OP_lit18";
        return DW_DLV_OK;
    case DW_OP_lit19:
        *s_out = "DW_OP_lit19";
        return DW_DLV_OK;
    case DW_OP_lit20:
        *s_out = "DW_OP_lit20";
        return DW_DLV_OK;
    case DW_OP_lit21:
        *s_out = "DW_OP_lit21";
        return DW_DLV_OK;
    case DW_OP_lit22:
        *s_out = "DW_OP_lit22";
        return DW_DLV_OK;
    case DW_OP_lit23:
        *s_out = "DW_OP_lit23";
        return DW_DLV_OK;
    case DW_OP_lit24:
        *s_out = "DW_OP_lit24";
        return DW_DLV_OK;
    case DW_OP_lit25:
        *s_out = "DW_OP_lit25";
        return DW_DLV_OK;
    case DW_OP_lit26:
        *s_out = "DW_OP_lit26";
        return DW_DLV_OK;
    case DW_OP_lit27:
        *s_out = "DW_OP_lit27";
        return DW_DLV_OK;
    case DW_OP_lit28:
        *s_out = "DW_OP_lit28";
        return DW_DLV_OK;
    case DW_OP_lit29:
        *s_out = "DW_OP_lit29";
        return DW_DLV_OK;
    case DW_OP_lit30:
        *s_out = "DW_OP_lit30";
        return DW_DLV_OK;
    case DW_OP_lit31:
        *s_out = "DW_OP_lit31";
        return DW_DLV_OK;
    case DW_OP_reg0:
        *s_out = "DW_OP_reg0";
        return DW_DLV_OK;
    case DW_OP_reg1:
        *s_out = "DW_OP_reg1";
        return DW_DLV_OK;
    case DW_OP_reg2:
        *s_out = "DW_OP_reg2";
        return DW_DLV_OK;
    case DW_OP_reg3:
        *s_out = "DW_OP_reg3";
        return DW_DLV_OK;
    case DW_OP_reg4:
        *s_out = "DW_OP_reg4";
        return DW_DLV_OK;
    case DW_OP_reg5:
        *s_out = "DW_OP_reg5";
        return DW_DLV_OK;
    case DW_OP_reg6:
        *s_out = "DW_OP_reg6";
        return DW_DLV_OK;
    case DW_OP_reg7:
        *s_out = "DW_OP_reg7";
        return DW_DLV_OK;
    case DW_OP_reg8:
        *s_out = "DW_OP_reg8";
        return DW_DLV_OK;
    case DW_OP_reg9:
        *s_out = "DW_OP_reg9";
        return DW_DLV_OK;
    case DW_OP_reg10:
        *s_out = "DW_OP_reg10";
        return DW_DLV_OK;
    case DW_OP_reg11:
        *s_out = "DW_OP_reg11";
        return DW_DLV_OK;
    case DW_OP_reg12:
        *s_out = "DW_OP_reg12";
        return DW_DLV_OK;
    case DW_OP_reg13:
        *s_out = "DW_OP_reg13";
        return DW_DLV_OK;
    case DW_OP_reg14:
        *s_out = "DW_OP_reg14";
        return DW_DLV_OK;
    case DW_OP_reg15:
        *s_out = "DW_OP_reg15";
        return DW_DLV_OK;
    case DW_OP_reg16:
        *s_out = "DW_OP_reg16";
        return DW_DLV_OK;
    case DW_OP_reg17:
        *s_out = "DW_OP_reg17";
        return DW_DLV_OK;
    case DW_OP_reg18:
        *s_out = "DW_OP_reg18";
        return DW_DLV_OK;
    case DW_OP_reg19:
        *s_out = "DW_OP_reg19";
        return DW_DLV_OK;
    case DW_OP_reg20:
        *s_out = "DW_OP_reg20";
        return DW_DLV_OK;
    case DW_OP_reg21:
        *s_out = "DW_OP_reg21";
        return DW_DLV_OK;
    case DW_OP_reg22:
        *s_out = "DW_OP_reg22";
        return DW_DLV_OK;
    case DW_OP_reg23:
        *s_out = "DW_OP_reg23";
        return DW_DLV_OK;
    case DW_OP_reg24:
        *s_out = "DW_OP_reg24";
        return DW_DLV_OK;
    case DW_OP_reg25:
        *s_out = "DW_OP_reg25";
        return DW_DLV_OK;
    case DW_OP_reg26:
        *s_out = "DW_OP_reg26";
        return DW_DLV_OK;
    case DW_OP_reg27:
        *s_out = "DW_OP_reg27";
        return DW_DLV_OK;
    case DW_OP_reg28:
        *s_out = "DW_OP_reg28";
        return DW_DLV_OK;
    case DW_OP_reg29:
        *s_out = "DW_OP_reg29";
        return DW_DLV_OK;
    case DW_OP_reg30:
        *s_out = "DW_OP_reg30";
        return DW_DLV_OK;
    case DW_OP_reg31:
        *s_out = "DW_OP_reg31";
        return DW_DLV_OK;
    case DW_OP_breg0:
        *s_out = "DW_OP_breg0";
        return DW_DLV_OK;
    case DW_OP_breg1:
        *s_out = "DW_OP_breg1";
        return DW_DLV_OK;
    case DW_OP_breg2:
        *s_out = "DW_OP_breg2";
        return DW_DLV_OK;
    case DW_OP_breg3:
        *s_out = "DW_OP_breg3";
        return DW_DLV_OK;
    case DW_OP_breg4:
        *s_out = "DW_OP_breg4";
        return DW_DLV_OK;
    case DW_OP_breg5:
        *s_out = "DW_OP_breg5";
        return DW_DLV_OK;
    case DW_OP_breg6:
        *s_out = "DW_OP_breg6";
        return DW_DLV_OK;
    case DW_OP_breg7:
        *s_out = "DW_OP_breg7";
        return DW_DLV_OK;
    case DW_OP_breg8:
        *s_out = "DW_OP_breg8";
        return DW_DLV_OK;
    case DW_OP_breg9:
        *s_out = "DW_OP_breg9";
        return DW_DLV_OK;
    case DW_OP_breg10:
        *s_out = "DW_OP_breg10";
        return DW_DLV_OK;
    case DW_OP_breg11:
        *s_out = "DW_OP_breg11";
        return DW_DLV_OK;
    case DW_OP_breg12:
        *s_out = "DW_OP_breg12";
        return DW_DLV_OK;
    case DW_OP_breg13:
        *s_out = "DW_OP_breg13";
        return DW_DLV_OK;
    case DW_OP_breg14:
        *s_out = "DW_OP_breg14";
        return DW_DLV_OK;
    case DW_OP_breg15:
        *s_out = "DW_OP_breg15";
        return DW_DLV_OK;
    case DW_OP_breg16:
        *s_out = "DW_OP_breg16";
        return DW_DLV_OK;
    case DW_OP_breg17:
        *s_out = "DW_OP_breg17";
        return DW_DLV_OK;
    case DW_OP_breg18:
        *s_out = "DW_OP_breg18";
        return DW_DLV_OK;
    case DW_OP_breg19:
        *s_out = "DW_OP_breg19";
        return DW_DLV_OK;
    case DW_OP_breg20:
        *s_out = "DW_OP_breg20";
        return DW_DLV_OK;
    case DW_OP_breg21:
        *s_out = "DW_OP_breg21";
        return DW_DLV_OK;
    case DW_OP_breg22:
        *s_out = "DW_OP_breg22";
        return DW_DLV_OK;
    case DW_OP_breg23:
        *s_out = "DW_OP_breg23";
        return DW_DLV_OK;
    case DW_OP_breg24:
        *s_out = "DW_OP_breg24";
        return DW_DLV_OK;
    case DW_OP_breg25:
        *s_out = "DW_OP_breg25";
        return DW_DLV_OK;
    case DW_OP_breg26:
        *s_out = "DW_OP_breg26";
        return DW_DLV_OK;
    case DW_OP_breg27:
        *s_out = "DW_OP_breg27";
        return DW_DLV_OK;
    case DW_OP_breg28:
        *s_out = "DW_OP_breg28";
        return DW_DLV_OK;
    case DW_OP_breg29:
        *s_out = "DW_OP_breg29";
        return DW_DLV_OK;
    case DW_OP_breg30:
        *s_out = "DW_OP_breg30";
        return DW_DLV_OK;
    case DW_OP_breg31:
        *s_out = "DW_OP_breg31";
        return DW_DLV_OK;
    case DW_OP_regx:
        *s_out = "DW_OP_regx";
        return DW_DLV_OK;
    case DW_OP_fbreg:
        *s_out = "DW_OP_fbreg";
        return DW_DLV_OK;
    case DW_OP_bregx:
        *s_out = "DW_OP_bregx";
        return DW_DLV_OK;
    case DW_OP_piece:
        *s_out = "DW_OP_piece";
        return DW_DLV_OK;
    case DW_OP_deref_size:
        *s_out = "DW_OP_deref_size";
        return DW_DLV_OK;
    case DW_OP_xderef_size:
        *s_out = "DW_OP_xderef_size";
        return DW_DLV_OK;
    case DW_OP_nop:
        *s_out = "DW_OP_nop";
        return DW_DLV_OK;
    case DW_OP_push_object_address:
        *s_out = "DW_OP_push_object_address";
        return DW_DLV_OK;
    case DW_OP_call2:
        *s_out = "DW_OP_call2";
        return DW_DLV_OK;
    case DW_OP_call4:
        *s_out = "DW_OP_call4";
        return DW_DLV_OK;
    case DW_OP_call_ref:
        *s_out = "DW_OP_call_ref";
        return DW_DLV_OK;
    case DW_OP_form_tls_address:
        *s_out = "DW_OP_form_tls_address";
        return DW_DLV_OK;
    case DW_OP_call_frame_cfa:
        *s_out = "DW_OP_call_frame_cfa";
        return DW_DLV_OK;
    case DW_OP_bit_piece:
        *s_out = "DW_OP_bit_piece";
        return DW_DLV_OK;
    case DW_OP_implicit_value:
        *s_out = "DW_OP_implicit_value";
        return DW_DLV_OK;
    case DW_OP_stack_value:
        *s_out = "DW_OP_stack_value";
        return DW_DLV_OK;
    case DW_OP_lo_user:
        *s_out = "DW_OP_lo_user";
        return DW_DLV_OK;
    case DW_OP_HP_is_value:
        *s_out = "DW_OP_HP_is_value";
        return DW_DLV_OK;
    case DW_OP_HP_fltconst4:
        *s_out = "DW_OP_HP_fltconst4";
        return DW_DLV_OK;
    case DW_OP_HP_fltconst8:
        *s_out = "DW_OP_HP_fltconst8";
        return DW_DLV_OK;
    case DW_OP_HP_mod_range:
        *s_out = "DW_OP_HP_mod_range";
        return DW_DLV_OK;
    case DW_OP_HP_unmod_range:
        *s_out = "DW_OP_HP_unmod_range";
        return DW_DLV_OK;
    case DW_OP_HP_tls:
        *s_out = "DW_OP_HP_tls";
        return DW_DLV_OK;
    case DW_OP_INTEL_bit_piece:
        *s_out = "DW_OP_INTEL_bit_piece";
        return DW_DLV_OK;
    case DW_OP_APPLE_uninit:
        *s_out = "DW_OP_APPLE_uninit";
        return DW_DLV_OK;
    case DW_OP_hi_user:
        *s_out = "DW_OP_hi_user";
        return DW_DLV_OK;
    }
    return DW_DLV_NO_ENTRY; 
}
/* ARGSUSED */
int
dwarf_get_ATE_name (unsigned int val,const char ** s_out)
{
    switch (val) {
    case DW_ATE_address:
        *s_out = "DW_ATE_address";
        return DW_DLV_OK;
    case DW_ATE_boolean:
        *s_out = "DW_ATE_boolean";
        return DW_DLV_OK;
    case DW_ATE_complex_float:
        *s_out = "DW_ATE_complex_float";
        return DW_DLV_OK;
    case DW_ATE_float:
        *s_out = "DW_ATE_float";
        return DW_DLV_OK;
    case DW_ATE_signed:
        *s_out = "DW_ATE_signed";
        return DW_DLV_OK;
    case DW_ATE_signed_char:
        *s_out = "DW_ATE_signed_char";
        return DW_DLV_OK;
    case DW_ATE_unsigned:
        *s_out = "DW_ATE_unsigned";
        return DW_DLV_OK;
    case DW_ATE_unsigned_char:
        *s_out = "DW_ATE_unsigned_char";
        return DW_DLV_OK;
    case DW_ATE_imaginary_float:
        *s_out = "DW_ATE_imaginary_float";
        return DW_DLV_OK;
    case DW_ATE_packed_decimal:
        *s_out = "DW_ATE_packed_decimal";
        return DW_DLV_OK;
    case DW_ATE_numeric_string:
        *s_out = "DW_ATE_numeric_string";
        return DW_DLV_OK;
    case DW_ATE_edited:
        *s_out = "DW_ATE_edited";
        return DW_DLV_OK;
    case DW_ATE_signed_fixed:
        *s_out = "DW_ATE_signed_fixed";
        return DW_DLV_OK;
    case DW_ATE_unsigned_fixed:
        *s_out = "DW_ATE_unsigned_fixed";
        return DW_DLV_OK;
    case DW_ATE_decimal_float:
        *s_out = "DW_ATE_decimal_float";
        return DW_DLV_OK;
    case DW_ATE_HP_float80:
        *s_out = "DW_ATE_HP_float80";
        return DW_DLV_OK;
    case DW_ATE_HP_complex_float80:
        *s_out = "DW_ATE_HP_complex_float80";
        return DW_DLV_OK;
    case DW_ATE_HP_float128:
        *s_out = "DW_ATE_HP_float128";
        return DW_DLV_OK;
    case DW_ATE_HP_complex_float128:
        *s_out = "DW_ATE_HP_complex_float128";
        return DW_DLV_OK;
    case DW_ATE_HP_floathpintel:
        *s_out = "DW_ATE_HP_floathpintel";
        return DW_DLV_OK;
    case DW_ATE_HP_imaginary_float80:
        *s_out = "DW_ATE_HP_imaginary_float80";
        return DW_DLV_OK;
    case DW_ATE_HP_imaginary_float128:
        *s_out = "DW_ATE_HP_imaginary_float128";
        return DW_DLV_OK;
    case DW_ATE_SUN_interval_float:
        *s_out = "DW_ATE_SUN_interval_float";
        return DW_DLV_OK;
    case DW_ATE_SUN_imaginary_float:
        *s_out = "DW_ATE_SUN_imaginary_float";
        return DW_DLV_OK;
    case DW_ATE_hi_user:
        *s_out = "DW_ATE_hi_user";
        return DW_DLV_OK;
    }
    return DW_DLV_NO_ENTRY; 
}
/* ARGSUSED */
int
dwarf_get_DS_name (unsigned int val,const char ** s_out)
{
    switch (val) {
    case DW_DS_unsigned:
        *s_out = "DW_DS_unsigned";
        return DW_DLV_OK;
    case DW_DS_leading_overpunch:
        *s_out = "DW_DS_leading_overpunch";
        return DW_DLV_OK;
    case DW_DS_trailing_overpunch:
        *s_out = "DW_DS_trailing_overpunch";
        return DW_DLV_OK;
    case DW_DS_leading_separate:
        *s_out = "DW_DS_leading_separate";
        return DW_DLV_OK;
    case DW_DS_trailing_separate:
        *s_out = "DW_DS_trailing_separate";
        return DW_DLV_OK;
    }
    return DW_DLV_NO_ENTRY; 
}
/* ARGSUSED */
int
dwarf_get_END_name (unsigned int val,const char ** s_out)
{
    switch (val) {
    case DW_END_default:
        *s_out = "DW_END_default";
        return DW_DLV_OK;
    case DW_END_big:
        *s_out = "DW_END_big";
        return DW_DLV_OK;
    case DW_END_little:
        *s_out = "DW_END_little";
        return DW_DLV_OK;
    case DW_END_lo_user:
        *s_out = "DW_END_lo_user";
        return DW_DLV_OK;
    case DW_END_hi_user:
        *s_out = "DW_END_hi_user";
        return DW_DLV_OK;
    }
    return DW_DLV_NO_ENTRY; 
}
/* ARGSUSED */
int
dwarf_get_ATCF_name (unsigned int val,const char ** s_out)
{
    switch (val) {
    case DW_ATCF_lo_user:
        *s_out = "DW_ATCF_lo_user";
        return DW_DLV_OK;
    case DW_ATCF_SUN_mop_bitfield:
        *s_out = "DW_ATCF_SUN_mop_bitfield";
        return DW_DLV_OK;
    case DW_ATCF_SUN_mop_spill:
        *s_out = "DW_ATCF_SUN_mop_spill";
        return DW_DLV_OK;
    case DW_ATCF_SUN_mop_scopy:
        *s_out = "DW_ATCF_SUN_mop_scopy";
        return DW_DLV_OK;
    case DW_ATCF_SUN_func_start:
        *s_out = "DW_ATCF_SUN_func_start";
        return DW_DLV_OK;
    case DW_ATCF_SUN_end_ctors:
        *s_out = "DW_ATCF_SUN_end_ctors";
        return DW_DLV_OK;
    case DW_ATCF_SUN_branch_target:
        *s_out = "DW_ATCF_SUN_branch_target";
        return DW_DLV_OK;
    case DW_ATCF_SUN_mop_stack_probe:
        *s_out = "DW_ATCF_SUN_mop_stack_probe";
        return DW_DLV_OK;
    case DW_ATCF_SUN_func_epilog:
        *s_out = "DW_ATCF_SUN_func_epilog";
        return DW_DLV_OK;
    case DW_ATCF_hi_user:
        *s_out = "DW_ATCF_hi_user";
        return DW_DLV_OK;
    }
    return DW_DLV_NO_ENTRY; 
}
/* ARGSUSED */
int
dwarf_get_ACCESS_name (unsigned int val,const char ** s_out)
{
    switch (val) {
    case DW_ACCESS_public:
        *s_out = "DW_ACCESS_public";
        return DW_DLV_OK;
    case DW_ACCESS_protected:
        *s_out = "DW_ACCESS_protected";
        return DW_DLV_OK;
    case DW_ACCESS_private:
        *s_out = "DW_ACCESS_private";
        return DW_DLV_OK;
    }
    return DW_DLV_NO_ENTRY; 
}
/* ARGSUSED */
int
dwarf_get_VIS_name (unsigned int val,const char ** s_out)
{
    switch (val) {
    case DW_VIS_local:
        *s_out = "DW_VIS_local";
        return DW_DLV_OK;
    case DW_VIS_exported:
        *s_out = "DW_VIS_exported";
        return DW_DLV_OK;
    case DW_VIS_qualified:
        *s_out = "DW_VIS_qualified";
        return DW_DLV_OK;
    }
    return DW_DLV_NO_ENTRY; 
}
/* ARGSUSED */
int
dwarf_get_VIRTUALITY_name (unsigned int val,const char ** s_out)
{
    switch (val) {
    case DW_VIRTUALITY_none:
        *s_out = "DW_VIRTUALITY_none";
        return DW_DLV_OK;
    case DW_VIRTUALITY_virtual:
        *s_out = "DW_VIRTUALITY_virtual";
        return DW_DLV_OK;
    case DW_VIRTUALITY_pure_virtual:
        *s_out = "DW_VIRTUALITY_pure_virtual";
        return DW_DLV_OK;
    }
    return DW_DLV_NO_ENTRY; 
}
/* ARGSUSED */
int
dwarf_get_LANG_name (unsigned int val,const char ** s_out)
{
    switch (val) {
    case DW_LANG_C89:
        *s_out = "DW_LANG_C89";
        return DW_DLV_OK;
    case DW_LANG_C:
        *s_out = "DW_LANG_C";
        return DW_DLV_OK;
    case DW_LANG_Ada83:
        *s_out = "DW_LANG_Ada83";
        return DW_DLV_OK;
    case DW_LANG_C_plus_plus:
        *s_out = "DW_LANG_C_plus_plus";
        return DW_DLV_OK;
    case DW_LANG_Cobol74:
        *s_out = "DW_LANG_Cobol74";
        return DW_DLV_OK;
    case DW_LANG_Cobol85:
        *s_out = "DW_LANG_Cobol85";
        return DW_DLV_OK;
    case DW_LANG_Fortran77:
        *s_out = "DW_LANG_Fortran77";
        return DW_DLV_OK;
    case DW_LANG_Fortran90:
        *s_out = "DW_LANG_Fortran90";
        return DW_DLV_OK;
    case DW_LANG_Pascal83:
        *s_out = "DW_LANG_Pascal83";
        return DW_DLV_OK;
    case DW_LANG_Modula2:
        *s_out = "DW_LANG_Modula2";
        return DW_DLV_OK;
    case DW_LANG_Java:
        *s_out = "DW_LANG_Java";
        return DW_DLV_OK;
    case DW_LANG_C99:
        *s_out = "DW_LANG_C99";
        return DW_DLV_OK;
    case DW_LANG_Ada95:
        *s_out = "DW_LANG_Ada95";
        return DW_DLV_OK;
    case DW_LANG_Fortran95:
        *s_out = "DW_LANG_Fortran95";
        return DW_DLV_OK;
    case DW_LANG_PLI:
        *s_out = "DW_LANG_PLI";
        return DW_DLV_OK;
    case DW_LANG_ObjC:
        *s_out = "DW_LANG_ObjC";
        return DW_DLV_OK;
    case DW_LANG_ObjC_plus_plus:
        *s_out = "DW_LANG_ObjC_plus_plus";
        return DW_DLV_OK;
    case DW_LANG_UPC:
        *s_out = "DW_LANG_UPC";
        return DW_DLV_OK;
    case DW_LANG_D:
        *s_out = "DW_LANG_D";
        return DW_DLV_OK;
    case DW_LANG_Python:
        *s_out = "DW_LANG_Python";
        return DW_DLV_OK;
    case DW_LANG_OpenCL:
        *s_out = "DW_LANG_OpenCL";
        return DW_DLV_OK;
    case DW_LANG_Go:
        *s_out = "DW_LANG_Go";
        return DW_DLV_OK;
    case DW_LANG_lo_user:
        *s_out = "DW_LANG_lo_user";
        return DW_DLV_OK;
    case DW_LANG_Mips_Assembler:
        *s_out = "DW_LANG_Mips_Assembler";
        return DW_DLV_OK;
    case DW_LANG_Upc:
        *s_out = "DW_LANG_Upc";
        return DW_DLV_OK;
    case DW_LANG_SUN_Assembler:
        *s_out = "DW_LANG_SUN_Assembler";
        return DW_DLV_OK;
    case DW_LANG_ALTIUM_Assembler:
        *s_out = "DW_LANG_ALTIUM_Assembler";
        return DW_DLV_OK;
    case DW_LANG_hi_user:
        *s_out = "DW_LANG_hi_user";
        return DW_DLV_OK;
    }
    return DW_DLV_NO_ENTRY; 
}
/* ARGSUSED */
int
dwarf_get_ID_name (unsigned int val,const char ** s_out)
{
    switch (val) {
    case DW_ID_case_sensitive:
        *s_out = "DW_ID_case_sensitive";
        return DW_DLV_OK;
    case DW_ID_up_case:
        *s_out = "DW_ID_up_case";
        return DW_DLV_OK;
    case DW_ID_down_case:
        *s_out = "DW_ID_down_case";
        return DW_DLV_OK;
    case DW_ID_case_insensitive:
        *s_out = "DW_ID_case_insensitive";
        return DW_DLV_OK;
    }
    return DW_DLV_NO_ENTRY; 
}
/* ARGSUSED */
int
dwarf_get_CC_name (unsigned int val,const char ** s_out)
{
    switch (val) {
    case DW_CC_normal:
        *s_out = "DW_CC_normal";
        return DW_DLV_OK;
    case DW_CC_program:
        *s_out = "DW_CC_program";
        return DW_DLV_OK;
    case DW_CC_nocall:
        *s_out = "DW_CC_nocall";
        return DW_DLV_OK;
    case DW_CC_lo_user:
        *s_out = "DW_CC_lo_user";
        return DW_DLV_OK;
    case DW_CC_ALTIUM_interrupt:
        *s_out = "DW_CC_ALTIUM_interrupt";
        return DW_DLV_OK;
    case DW_CC_ALTIUM_near_system_stack:
        *s_out = "DW_CC_ALTIUM_near_system_stack";
        return DW_DLV_OK;
    case DW_CC_ALTIUM_near_user_stack:
        *s_out = "DW_CC_ALTIUM_near_user_stack";
        return DW_DLV_OK;
    case DW_CC_ALTIUM_huge_user_stack:
        *s_out = "DW_CC_ALTIUM_huge_user_stack";
        return DW_DLV_OK;
    case DW_CC_hi_user:
        *s_out = "DW_CC_hi_user";
        return DW_DLV_OK;
    }
    return DW_DLV_NO_ENTRY; 
}
/* ARGSUSED */
int
dwarf_get_INL_name (unsigned int val,const char ** s_out)
{
    switch (val) {
    case DW_INL_not_inlined:
        *s_out = "DW_INL_not_inlined";
        return DW_DLV_OK;
    case DW_INL_inlined:
        *s_out = "DW_INL_inlined";
        return DW_DLV_OK;
    case DW_INL_declared_not_inlined:
        *s_out = "DW_INL_declared_not_inlined";
        return DW_DLV_OK;
    case DW_INL_declared_inlined:
        *s_out = "DW_INL_declared_inlined";
        return DW_DLV_OK;
    }
    return DW_DLV_NO_ENTRY; 
}
/* ARGSUSED */
int
dwarf_get_ORD_name (unsigned int val,const char ** s_out)
{
    switch (val) {
    case DW_ORD_row_major:
        *s_out = "DW_ORD_row_major";
        return DW_DLV_OK;
    case DW_ORD_col_major:
        *s_out = "DW_ORD_col_major";
        return DW_DLV_OK;
    }
    return DW_DLV_NO_ENTRY; 
}
/* ARGSUSED */
int
dwarf_get_DSC_name (unsigned int val,const char ** s_out)
{
    switch (val) {
    case DW_DSC_label:
        *s_out = "DW_DSC_label";
        return DW_DLV_OK;
    case DW_DSC_range:
        *s_out = "DW_DSC_range";
        return DW_DLV_OK;
    }
    return DW_DLV_NO_ENTRY; 
}
/* ARGSUSED */
int
dwarf_get_LNS_name (unsigned int val,const char ** s_out)
{
    switch (val) {
    case DW_LNS_copy:
        *s_out = "DW_LNS_copy";
        return DW_DLV_OK;
    case DW_LNS_advance_pc:
        *s_out = "DW_LNS_advance_pc";
        return DW_DLV_OK;
    case DW_LNS_advance_line:
        *s_out = "DW_LNS_advance_line";
        return DW_DLV_OK;
    case DW_LNS_set_file:
        *s_out = "DW_LNS_set_file";
        return DW_DLV_OK;
    case DW_LNS_set_column:
        *s_out = "DW_LNS_set_column";
        return DW_DLV_OK;
    case DW_LNS_negate_stmt:
        *s_out = "DW_LNS_negate_stmt";
        return DW_DLV_OK;
    case DW_LNS_set_basic_block:
        *s_out = "DW_LNS_set_basic_block";
        return DW_DLV_OK;
    case DW_LNS_const_add_pc:
        *s_out = "DW_LNS_const_add_pc";
        return DW_DLV_OK;
    case DW_LNS_fixed_advance_pc:
        *s_out = "DW_LNS_fixed_advance_pc";
        return DW_DLV_OK;
    case DW_LNS_set_prologue_end:
        *s_out = "DW_LNS_set_prologue_end";
        return DW_DLV_OK;
    case DW_LNS_set_epilogue_begin:
        *s_out = "DW_LNS_set_epilogue_begin";
        return DW_DLV_OK;
    case DW_LNS_set_isa:
        *s_out = "DW_LNS_set_isa";
        return DW_DLV_OK;
    }
    return DW_DLV_NO_ENTRY; 
}
/* ARGSUSED */
int
dwarf_get_LNE_name (unsigned int val,const char ** s_out)
{
    switch (val) {
    case DW_LNE_end_sequence:
        *s_out = "DW_LNE_end_sequence";
        return DW_DLV_OK;
    case DW_LNE_set_address:
        *s_out = "DW_LNE_set_address";
        return DW_DLV_OK;
    case DW_LNE_define_file:
        *s_out = "DW_LNE_define_file";
        return DW_DLV_OK;
    case DW_LNE_set_discriminator:
        *s_out = "DW_LNE_set_discriminator";
        return DW_DLV_OK;
    case DW_LNE_HP_negate_is_UV_update:
        *s_out = "DW_LNE_HP_negate_is_UV_update";
        return DW_DLV_OK;
    case DW_LNE_HP_push_context:
        *s_out = "DW_LNE_HP_push_context";
        return DW_DLV_OK;
    case DW_LNE_HP_pop_context:
        *s_out = "DW_LNE_HP_pop_context";
        return DW_DLV_OK;
    case DW_LNE_HP_set_file_line_column:
        *s_out = "DW_LNE_HP_set_file_line_column";
        return DW_DLV_OK;
    case DW_LNE_HP_set_routine_name:
        *s_out = "DW_LNE_HP_set_routine_name";
        return DW_DLV_OK;
    case DW_LNE_HP_set_sequence:
        *s_out = "DW_LNE_HP_set_sequence";
        return DW_DLV_OK;
    case DW_LNE_HP_negate_post_semantics:
        *s_out = "DW_LNE_HP_negate_post_semantics";
        return DW_DLV_OK;
    case DW_LNE_HP_negate_function_exit:
        *s_out = "DW_LNE_HP_negate_function_exit";
        return DW_DLV_OK;
    case DW_LNE_HP_negate_front_end_logical:
        *s_out = "DW_LNE_HP_negate_front_end_logical";
        return DW_DLV_OK;
    case DW_LNE_HP_define_proc:
        *s_out = "DW_LNE_HP_define_proc";
        return DW_DLV_OK;
    case DW_LNE_lo_user:
        *s_out = "DW_LNE_lo_user";
        return DW_DLV_OK;
    case DW_LNE_hi_user:
        *s_out = "DW_LNE_hi_user";
        return DW_DLV_OK;
    }
    return DW_DLV_NO_ENTRY; 
}
/* ARGSUSED */
int
dwarf_get_ISA_name (unsigned int val,const char ** s_out)
{
    switch (val) {
    case DW_ISA_UNKNOWN:
        *s_out = "DW_ISA_UNKNOWN";
        return DW_DLV_OK;
    case DW_ISA_ARM_thumb:
        *s_out = "DW_ISA_ARM_thumb";
        return DW_DLV_OK;
    case DW_ISA_ARM_arm:
        *s_out = "DW_ISA_ARM_arm";
        return DW_DLV_OK;
    }
    return DW_DLV_NO_ENTRY; 
}
/* ARGSUSED */
int
dwarf_get_MACINFO_name (unsigned int val,const char ** s_out)
{
    switch (val) {
    case DW_MACINFO_define:
        *s_out = "DW_MACINFO_define";
        return DW_DLV_OK;
    case DW_MACINFO_undef:
        *s_out = "DW_MACINFO_undef";
        return DW_DLV_OK;
    case DW_MACINFO_start_file:
        *s_out = "DW_MACINFO_start_file";
        return DW_DLV_OK;
    case DW_MACINFO_end_file:
        *s_out = "DW_MACINFO_end_file";
        return DW_DLV_OK;
    case DW_MACINFO_vendor_ext:
        *s_out = "DW_MACINFO_vendor_ext";
        return DW_DLV_OK;
    }
    return DW_DLV_NO_ENTRY; 
}
/* ARGSUSED */
int
dwarf_get_CFA_name (unsigned int val,const char ** s_out)
{
    switch (val) {
    case DW_CFA_extended:
        *s_out = "DW_CFA_extended";
        return DW_DLV_OK;
    case DW_CFA_set_loc:
        *s_out = "DW_CFA_set_loc";
        return DW_DLV_OK;
    case DW_CFA_advance_loc1:
        *s_out = "DW_CFA_advance_loc1";
        return DW_DLV_OK;
    case DW_CFA_advance_loc2:
        *s_out = "DW_CFA_advance_loc2";
        return DW_DLV_OK;
    case DW_CFA_advance_loc4:
        *s_out = "DW_CFA_advance_loc4";
        return DW_DLV_OK;
    case DW_CFA_offset_extended:
        *s_out = "DW_CFA_offset_extended";
        return DW_DLV_OK;
    case DW_CFA_restore_extended:
        *s_out = "DW_CFA_restore_extended";
        return DW_DLV_OK;
    case DW_CFA_undefined:
        *s_out = "DW_CFA_undefined";
        return DW_DLV_OK;
    case DW_CFA_same_value:
        *s_out = "DW_CFA_same_value";
        return DW_DLV_OK;
    case DW_CFA_register:
        *s_out = "DW_CFA_register";
        return DW_DLV_OK;
    case DW_CFA_remember_state:
        *s_out = "DW_CFA_remember_state";
        return DW_DLV_OK;
    case DW_CFA_restore_state:
        *s_out = "DW_CFA_restore_state";
        return DW_DLV_OK;
    case DW_CFA_def_cfa:
        *s_out = "DW_CFA_def_cfa";
        return DW_DLV_OK;
    case DW_CFA_def_cfa_register:
        *s_out = "DW_CFA_def_cfa_register";
        return DW_DLV_OK;
    case DW_CFA_def_cfa_offset:
        *s_out = "DW_CFA_def_cfa_offset";
        return DW_DLV_OK;
    case DW_CFA_def_cfa_expression:
        *s_out = "DW_CFA_def_cfa_expression";
        return DW_DLV_OK;
    case DW_CFA_expression:
        *s_out = "DW_CFA_expression";
        return DW_DLV_OK;
    case DW_CFA_offset_extended_sf:
        *s_out = "DW_CFA_offset_extended_sf";
        return DW_DLV_OK;
    case DW_CFA_def_cfa_sf:
        *s_out = "DW_CFA_def_cfa_sf";
        return DW_DLV_OK;
    case DW_CFA_def_cfa_offset_sf:
        *s_out = "DW_CFA_def_cfa_offset_sf";
        return DW_DLV_OK;
    case DW_CFA_val_offset:
        *s_out = "DW_CFA_val_offset";
        return DW_DLV_OK;
    case DW_CFA_val_offset_sf:
        *s_out = "DW_CFA_val_offset_sf";
        return DW_DLV_OK;
    case DW_CFA_val_expression:
        *s_out = "DW_CFA_val_expression";
        return DW_DLV_OK;
    case DW_CFA_lo_user:
        *s_out = "DW_CFA_lo_user";
        return DW_DLV_OK;
    case DW_CFA_MIPS_advance_loc8:
        *s_out = "DW_CFA_MIPS_advance_loc8";
        return DW_DLV_OK;
    case DW_CFA_GNU_window_save:
        *s_out = "DW_CFA_GNU_window_save";
        return DW_DLV_OK;
    case DW_CFA_GNU_args_size:
        *s_out = "DW_CFA_GNU_args_size";
        return DW_DLV_OK;
    case DW_CFA_GNU_negative_offset_extended:
        *s_out = "DW_CFA_GNU_negative_offset_extended";
        return DW_DLV_OK;
    case DW_CFA_high_user:
        *s_out = "DW_CFA_high_user";
        return DW_DLV_OK;
    case DW_CFA_advance_loc:
        *s_out = "DW_CFA_advance_loc";
        return DW_DLV_OK;
    case DW_CFA_offset:
        *s_out = "DW_CFA_offset";
        return DW_DLV_OK;
    case DW_CFA_restore:
        *s_out = "DW_CFA_restore";
        return DW_DLV_OK;
    }
    return DW_DLV_NO_ENTRY; 
}
/* ARGSUSED */
int
dwarf_get_EH_name (unsigned int val,const char ** s_out)
{
    switch (val) {
    case DW_EH_PE_absptr:
        *s_out = "DW_EH_PE_absptr";
        return DW_DLV_OK;
    case DW_EH_PE_uleb128:
        *s_out = "DW_EH_PE_uleb128";
        return DW_DLV_OK;
    case DW_EH_PE_udata2:
        *s_out = "DW_EH_PE_udata2";
        return DW_DLV_OK;
    case DW_EH_PE_udata4:
        *s_out = "DW_EH_PE_udata4";
        return DW_DLV_OK;
    case DW_EH_PE_udata8:
        *s_out = "DW_EH_PE_udata8";
        return DW_DLV_OK;
    case DW_EH_PE_sleb128:
        *s_out = "DW_EH_PE_sleb128";
        return DW_DLV_OK;
    case DW_EH_PE_sdata2:
        *s_out = "DW_EH_PE_sdata2";
        return DW_DLV_OK;
    case DW_EH_PE_sdata4:
        *s_out = "DW_EH_PE_sdata4";
        return DW_DLV_OK;
    case DW_EH_PE_sdata8:
        *s_out = "DW_EH_PE_sdata8";
        return DW_DLV_OK;
    case DW_EH_PE_pcrel:
        *s_out = "DW_EH_PE_pcrel";
        return DW_DLV_OK;
    case DW_EH_PE_textrel:
        *s_out = "DW_EH_PE_textrel";
        return DW_DLV_OK;
    case DW_EH_PE_datarel:
        *s_out = "DW_EH_PE_datarel";
        return DW_DLV_OK;
    case DW_EH_PE_funcrel:
        *s_out = "DW_EH_PE_funcrel";
        return DW_DLV_OK;
    case DW_EH_PE_aligned:
        *s_out = "DW_EH_PE_aligned";
        return DW_DLV_OK;
    case DW_EH_PE_omit:
        *s_out = "DW_EH_PE_omit";
        return DW_DLV_OK;
    }
    return DW_DLV_NO_ENTRY; 
}
/* ARGSUSED */
int
dwarf_get_FRAME_name (unsigned int val,const char ** s_out)
{
    switch (val) {
    case DW_FRAME_CFA_COL:
        *s_out = "DW_FRAME_CFA_COL";
        return DW_DLV_OK;
    case DW_FRAME_REG1:
        *s_out = "DW_FRAME_REG1";
        return DW_DLV_OK;
    case DW_FRAME_REG2:
        *s_out = "DW_FRAME_REG2";
        return DW_DLV_OK;
    case DW_FRAME_REG3:
        *s_out = "DW_FRAME_REG3";
        return DW_DLV_OK;
    case DW_FRAME_REG4:
        *s_out = "DW_FRAME_REG4";
        return DW_DLV_OK;
    case DW_FRAME_REG5:
        *s_out = "DW_FRAME_REG5";
        return DW_DLV_OK;
    case DW_FRAME_REG6:
        *s_out = "DW_FRAME_REG6";
        return DW_DLV_OK;
    case DW_FRAME_REG7:
        *s_out = "DW_FRAME_REG7";
        return DW_DLV_OK;
    case DW_FRAME_REG8:
        *s_out = "DW_FRAME_REG8";
        return DW_DLV_OK;
    case DW_FRAME_REG9:
        *s_out = "DW_FRAME_REG9";
        return DW_DLV_OK;
    case DW_FRAME_REG10:
        *s_out = "DW_FRAME_REG10";
        return DW_DLV_OK;
    case DW_FRAME_REG11:
        *s_out = "DW_FRAME_REG11";
        return DW_DLV_OK;
    case DW_FRAME_REG12:
        *s_out = "DW_FRAME_REG12";
        return DW_DLV_OK;
    case DW_FRAME_REG13:
        *s_out = "DW_FRAME_REG13";
        return DW_DLV_OK;
    case DW_FRAME_REG14:
        *s_out = "DW_FRAME_REG14";
        return DW_DLV_OK;
    case DW_FRAME_REG15:
        *s_out = "DW_FRAME_REG15";
        return DW_DLV_OK;
    case DW_FRAME_REG16:
        *s_out = "DW_FRAME_REG16";
        return DW_DLV_OK;
    case DW_FRAME_REG17:
        *s_out = "DW_FRAME_REG17";
        return DW_DLV_OK;
    case DW_FRAME_REG18:
        *s_out = "DW_FRAME_REG18";
        return DW_DLV_OK;
    case DW_FRAME_REG19:
        *s_out = "DW_FRAME_REG19";
        return DW_DLV_OK;
    case DW_FRAME_REG20:
        *s_out = "DW_FRAME_REG20";
        return DW_DLV_OK;
    case DW_FRAME_REG21:
        *s_out = "DW_FRAME_REG21";
        return DW_DLV_OK;
    case DW_FRAME_REG22:
        *s_out = "DW_FRAME_REG22";
        return DW_DLV_OK;
    case DW_FRAME_REG23:
        *s_out = "DW_FRAME_REG23";
        return DW_DLV_OK;
    case DW_FRAME_REG24:
        *s_out = "DW_FRAME_REG24";
        return DW_DLV_OK;
    case DW_FRAME_REG25:
        *s_out = "DW_FRAME_REG25";
        return DW_DLV_OK;
    case DW_FRAME_REG26:
        *s_out = "DW_FRAME_REG26";
        return DW_DLV_OK;
    case DW_FRAME_REG27:
        *s_out = "DW_FRAME_REG27";
        return DW_DLV_OK;
    case DW_FRAME_REG28:
        *s_out = "DW_FRAME_REG28";
        return DW_DLV_OK;
    case DW_FRAME_REG29:
        *s_out = "DW_FRAME_REG29";
        return DW_DLV_OK;
    case DW_FRAME_REG30:
        *s_out = "DW_FRAME_REG30";
        return DW_DLV_OK;
    case DW_FRAME_REG31:
        *s_out = "DW_FRAME_REG31";
        return DW_DLV_OK;
    case DW_FRAME_FREG0:
        *s_out = "DW_FRAME_FREG0";
        return DW_DLV_OK;
    case DW_FRAME_FREG1:
        *s_out = "DW_FRAME_FREG1";
        return DW_DLV_OK;
    case DW_FRAME_FREG2:
        *s_out = "DW_FRAME_FREG2";
        return DW_DLV_OK;
    case DW_FRAME_FREG3:
        *s_out = "DW_FRAME_FREG3";
        return DW_DLV_OK;
    case DW_FRAME_FREG4:
        *s_out = "DW_FRAME_FREG4";
        return DW_DLV_OK;
    case DW_FRAME_FREG5:
        *s_out = "DW_FRAME_FREG5";
        return DW_DLV_OK;
    case DW_FRAME_FREG6:
        *s_out = "DW_FRAME_FREG6";
        return DW_DLV_OK;
    case DW_FRAME_FREG7:
        *s_out = "DW_FRAME_FREG7";
        return DW_DLV_OK;
    case DW_FRAME_FREG8:
        *s_out = "DW_FRAME_FREG8";
        return DW_DLV_OK;
    case DW_FRAME_FREG9:
        *s_out = "DW_FRAME_FREG9";
        return DW_DLV_OK;
    case DW_FRAME_FREG10:
        *s_out = "DW_FRAME_FREG10";
        return DW_DLV_OK;
    case DW_FRAME_FREG11:
        *s_out = "DW_FRAME_FREG11";
        return DW_DLV_OK;
    case DW_FRAME_FREG12:
        *s_out = "DW_FRAME_FREG12";
        return DW_DLV_OK;
    case DW_FRAME_FREG13:
        *s_out = "DW_FRAME_FREG13";
        return DW_DLV_OK;
    case DW_FRAME_FREG14:
        *s_out = "DW_FRAME_FREG14";
        return DW_DLV_OK;
    case DW_FRAME_FREG15:
        *s_out = "DW_FRAME_FREG15";
        return DW_DLV_OK;
    case DW_FRAME_FREG16:
        *s_out = "DW_FRAME_FREG16";
        return DW_DLV_OK;
    case DW_FRAME_FREG17:
        *s_out = "DW_FRAME_FREG17";
        return DW_DLV_OK;
    case DW_FRAME_FREG18:
        *s_out = "DW_FRAME_FREG18";
        return DW_DLV_OK;
    case DW_FRAME_FREG19:
        *s_out = "DW_FRAME_FREG19";
        return DW_DLV_OK;
    case DW_FRAME_FREG20:
        *s_out = "DW_FRAME_FREG20";
        return DW_DLV_OK;
    case DW_FRAME_FREG21:
        *s_out = "DW_FRAME_FREG21";
        return DW_DLV_OK;
    case DW_FRAME_FREG22:
        *s_out = "DW_FRAME_FREG22";
        return DW_DLV_OK;
    case DW_FRAME_FREG23:
        *s_out = "DW_FRAME_FREG23";
        return DW_DLV_OK;
    case DW_FRAME_FREG24:
        *s_out = "DW_FRAME_FREG24";
        return DW_DLV_OK;
    case DW_FRAME_FREG25:
        *s_out = "DW_FRAME_FREG25";
        return DW_DLV_OK;
    case DW_FRAME_FREG26:
        *s_out = "DW_FRAME_FREG26";
        return DW_DLV_OK;
    case DW_FRAME_FREG27:
        *s_out = "DW_FRAME_FREG27";
        return DW_DLV_OK;
    case DW_FRAME_FREG28:
        *s_out = "DW_FRAME_FREG28";
        return DW_DLV_OK;
    case DW_FRAME_FREG29:
        *s_out = "DW_FRAME_FREG29";
        return DW_DLV_OK;
    case DW_FRAME_FREG30:
        *s_out = "DW_FRAME_FREG30";
        return DW_DLV_OK;
    case DW_FRAME_HIGHEST_NORMAL_REGISTER:
        *s_out = "DW_FRAME_HIGHEST_NORMAL_REGISTER";
        return DW_DLV_OK;
    }
    return DW_DLV_NO_ENTRY; 
}
/* ARGSUSED */
int
dwarf_get_CHILDREN_name (unsigned int val,const char ** s_out)
{
    switch (val) {
    case DW_CHILDREN_no:
        *s_out = "DW_CHILDREN_no";
        return DW_DLV_OK;
    case DW_CHILDREN_yes:
        *s_out = "DW_CHILDREN_yes";
        return DW_DLV_OK;
    }
    return DW_DLV_NO_ENTRY; 
}
/* ARGSUSED */
int
dwarf_get_ADDR_name (unsigned int val,const char ** s_out)
{
    switch (val) {
    case DW_ADDR_none:
        *s_out = "DW_ADDR_none";
        return DW_DLV_OK;
    }
    return DW_DLV_NO_ENTRY; 
}

/* END FILE */
