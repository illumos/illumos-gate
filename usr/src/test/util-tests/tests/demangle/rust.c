/*
 * Copyright (c) 2014 Alex Crichton
 *
 * Permission is hereby granted, free of charge, to any
 * person obtaining a copy of this software and associated
 * documentation files (the "Software"), to deal in the
 * Software without restriction, including without
 * limitation the rights to use, copy, modify, merge,
 * publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software
 * is furnished to do so, subject to the following
 * conditions:
 *
 * The above copyright notice and this permission notice
 * shall be included in all copies or substantial portions
 * of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF
 * ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED
 * TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
 * PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT
 * SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR
 * IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */
/*
 * Copyright 2019 Joyent, Inc.
 * Copyright 2021 Jason King
 */

/*
 * Test cases taken from rustc-demangle 0.1.9
 */
#include <errno.h>
#include <err.h>
#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sysmacros.h>
#include <demangle-sys.h>

#define	TEST_LOCALE "C.UTF-8"

typedef struct rust_test_case {
	const char *mangled;
	const char *demangled;
} rust_test_case_t;
#define	T(_m, _d) { .mangled = _m, .demangled = _d }
#define	T_ERR(_m) { .mangled = _m }

typedef struct rust_test_grp {
	const char		*name;
	rust_test_case_t	tests[];
} rust_test_grp_t;

#define	GROUP(_n, ...)			\
	static rust_test_grp_t _n = {	\
		.name = #_n,		\
		.tests = {		\
			__VA_ARGS__,	\
			{ NULL, NULL }	\
		}			\
	}

/* BEGIN CSTYLED */

GROUP(demangle,
    T_ERR("test"),
    T("_ZN4testE", "test"),
    T_ERR("_ZN4test"),
    T("_ZN4test1a2bcE", "test::a::bc"));

GROUP(demangle_dollars,
    T("_ZN4$RP$E", ")"),
    T("_ZN8$RF$testE", "&test"),
    T("_ZN8$BP$test4foobE", "*test::foob"),
    T("_ZN9$u20$test4foobE", " test::foob"),
    T("_ZN35Bar$LT$$u5b$u32$u3b$$u20$4$u5d$$GT$E", "Bar<[u32; 4]>"));

GROUP(demangle_many_dollars,
    T("_ZN13test$u20$test4foobE", "test test::foob"),
    T("_ZN12test$BP$test4foobE", "test*test::foob"));

GROUP(demangle_osx,
    T("__ZN5alloc9allocator6Layout9for_value17h02a996811f781011E",
    "alloc::allocator::Layout::for_value::h02a996811f781011"),
    T("__ZN38_$LT$core..option..Option$LT$T$GT$$GT$6unwrap18_MSG_FILE_LINE_COL17haf7cb8d5824ee659E",
    "<core::option::Option<T>>::unwrap::_MSG_FILE_LINE_COL::haf7cb8d5824ee659"),
    T("__ZN4core5slice89_$LT$impl$u20$core..iter..traits..IntoIterator$u20$for$u20$$RF$$u27$a$u20$$u5b$T$u5d$$GT$9into_iter17h450e234d27262170E",
    "core::slice::<impl core::iter::traits::IntoIterator for &'a [T]>::into_iter::h450e234d27262170"));

GROUP(demangle_elements_beginning_with_underscore,
    T("_ZN13_$LT$test$GT$E", "<test>"),
    T("_ZN28_$u7b$$u7b$closure$u7d$$u7d$E", "{{closure}}"),
    T("_ZN15__STATIC_FMTSTRE", "__STATIC_FMTSTR"));

GROUP(demangle_trait_impls,
    T("_ZN71_$LT$Test$u20$$u2b$$u20$$u27$static$u20$as$u20$foo..Bar$LT$Test$GT$$GT$3barE",
    "<Test + 'static as foo::Bar<Test>>::bar"));

GROUP(invalid_no_chop, T_ERR("_ZNfooE"));

GROUP(handle_assoc_types,
    T("_ZN151_$LT$alloc..boxed..Box$LT$alloc..boxed..FnBox$LT$A$C$$u20$Output$u3d$R$GT$$u20$$u2b$$u20$$u27$a$GT$$u20$as$u20$core..ops..function..FnOnce$LT$A$GT$$GT$9call_once17h69e8f44b3723e1caE",
    "<alloc::boxed::Box<alloc::boxed::FnBox<A, Output=R> + 'a> as core::ops::function::FnOnce<A>>::call_once::h69e8f44b3723e1ca"));

/* C++ mangled names that aren't valid rust names */
GROUP(cplusplus_as_rust, T_ERR("_ZN7mozilla3dom13BrowserParent22RecvUpdateContentCacheERKNS_12ContentCacheE"));

GROUP(v0_crate_with_leading_digit,
    T("_RNvC6_123foo3bar", "123foo::bar"));

GROUP(v0_utf8_idents,
    T("_RNqCs4fqI2P2rA04_11utf8_identsu30____7hkackfecea1cbdathfdh9hlq6y",
    "utf8_idents::საჭმელად_გემრიელი_სადილი"));

GROUP(v0_closure,
    T("_RNCNCNgCs6DXkGYLi8lr_2cc5spawn00B5_",
    "cc::spawn::{closure#0}::{closure#0}"),
    T("_RNCINkXs25_NgCsbmNqQUJIY6D_4core5sliceINyB9_4IterhENuNgNoBb_4iter8iterator8Iterator9rpositionNCNgNpB9_6memchr7memrchrs_0E0Bb_",
    "<core::slice::Iter<u8> as core::iter::iterator::Iterator>::rposition::<core::slice::memchr::memrchr::{closure#1}>::{closure#0}"));

GROUP(v0_dyn_trait,
    T("_RINbNbCskIICzLVDPPb_5alloc5alloc8box_freeDINbNiB4_5boxed5FnBoxuEp6OutputuEL_ECs1iopQbuBiw2_3std",
    "alloc::alloc::box_free::<dyn alloc::boxed::FnBox<(), Output = ()>>"));

GROUP(v0_const_generics,
    T("_RMC0INtC8arrayvec8ArrayVechKj7b_E", "<arrayvec::ArrayVec<u8, 123>>"),
    T("_RMCs4fqI2P2rA04_13const_genericINtB0_8UnsignedKhb_E", "<const_generic::Unsigned<11>>"),
    T("_RMCs4fqI2P2rA04_13const_genericINtB0_6SignedKs98_E", "<const_generic::Signed<152>>"),
    T("_RMCs4fqI2P2rA04_13const_genericINtB0_6SignedKanb_E", "<const_generic::Signed<-11>>"),
    T("_RMCs4fqI2P2rA04_13const_genericINtB0_4BoolKb0_E", "<const_generic::Bool<false>>"),
    T("_RMCs4fqI2P2rA04_13const_genericINtB0_4BoolKb1_E", "<const_generic::Bool<true>>"),
    T("_RMCs4fqI2P2rA04_13const_genericINtB0_4CharKc76_E", "<const_generic::Char<'v'>>"),
    T("_RMCs4fqI2P2rA04_13const_genericINtB0_4CharKca_E", "<const_generic::Char<'\\n'>>"),
    T("_RMCs4fqI2P2rA04_13const_genericINtB0_4CharKc2202_E", "<const_generic::Char<'∂'>>"));

GROUP(v0_exponential_explosion,
    T("_RMC0TTTTTTpB8_EB7_EB6_EB5_EB4_EB3_E",
    "<((((((_, _), (_, _)), ((_, _), (_, _))), (((_, _), (_, _)), ((_, _), (_, _)))), "
    "((((_, _), (_, _)), ((_, _), (_, _))), (((_, _), (_, _)), ((_, _), (_, _))))), "
    "(((((_, _), (_, _)), ((_, _), (_, _))), (((_, _), (_, _)), ((_, _), (_, _)))), "
    "((((_, _), (_, _)), ((_, _), (_, _))), (((_, _), (_, _)), ((_, _), (_, _))))))>"));

GROUP(v0_thinlto,
    T("_RC3foo.llvm.9D1C9369", "foo"),
    T("_RC3foo.llvm.9D1C9369@@16", "foo"),
    T("_RNvC9backtrace3foo.llvm.A5310EB9", "backtrace::foo"));

GROUP(v0_demangle_extra_suffix,
    T("_RNvNtNtNtNtCs92dm3009vxr_4rand4rngs7adapter9reseeding4fork23FORK_HANDLER_REGISTERED.0.0",
    "rand::rngs::adapter::reseeding::fork::FORK_HANDLER_REGISTERED.0.0"));

/*
 * From Rust RFC2603
 */
GROUP(v0_generic_func,
    T("_RINvNtC3std3mem8align_ofdE", "std::mem::align_of::<f64>"),
    T("_RINvNtC3std3mem8align_ofNtNtC3std3mem12DiscriminantE",
    "std::mem::align_of::<std::mem::Discriminant>"),
    T("_RINvNtC3std3mem8align_ofQTReuEE",
    "std::mem::align_of::<&mut (&str, ())>"));

GROUP(v0_eddyb,
    T("_RNvXsa_NtNtCs7hxHya3g3Sg_4core3ptr6uniqueINtB5_6UniqueNtNtNtCshRVCqTKO4VO_5cargo4util4toml10TomlTargetEINtNtB9_7convert4FromINtNtB7_8non_null7NonNullBQ_EE4fromBW_",
      "<core::ptr::unique::Unique<cargo::util::toml::TomlTarget> as core::convert::From<core::ptr::non_null::NonNull<cargo::util::toml::TomlTarget>>>::from"),
    T("_RNvXsG_NtNtCs2ZCqZGLqlfc_3std3ffi6os_strNtB5_5OsStrINtNtCs7hxHya3g3Sg_4core7convert5AsRefBC_E6as_ref",
      "<std::ffi::os_str::OsStr as core::convert::AsRef<std::ffi::os_str::OsStr>>::as_ref"),
    T("_RNvMs_NtCs7hxHya3g3Sg_4core6resultINtB4_6ResultNtNtB6_5alloc6LayoutNtBL_9LayoutErrE6unwrapCsdJWFNQ9j01_12aho_corasick",
      "<core::result::Result<core::alloc::Layout, core::alloc::LayoutErr>>::unwrap"),
    T("_RINvNtCs7hxHya3g3Sg_4core3mem7size_ofFUKCEPaECs2ZCqZGLqlfc_3std",
      "core::mem::size_of::<unsafe extern \"C\" fn() -> *const i8>"),
    T("_RINvCsc1o8JKpgQAm_4test28___rust_begin_short_backtraceFEuEB2_",
      "test::__rust_begin_short_backtrace::<fn()>"),
    T("_ZN4core5array104_$LT$impl$u20$core..iter..traits..collect..IntoIterator$u20$for$u20$$RF$$u5b$$RF$str$u3b$$u20$_$u5d$$GT$9into_iter17hc066f1a15f41761dE",
      "core::array::<impl core::iter::traits::collect::IntoIterator for &[&str; _]>::into_iter::hc066f1a15f41761d"));

GROUP(v0_afl_fast,
    T_ERR("_RMC0TTTTTTPB8_yB7_EB6_EB5_EB4_EB3_E"),
    T_ERR("_RMC0TTTTTTpB8_yB7_eB6_EB5_EB4_EB3_E"),
    T_ERR("_RMC0TTTTTTpB4_yB7_EB6_EB5_EB4_EB3_E"),
    T_ERR("_RMC0TTTTTTpB4_yB7_EB6_EB5_EB4_EB3_E"),
    T_ERR("_RMC0TTTTTTTB8_yB7_EB6_EB5_EB4_EB3_E"),
    T_ERR("_RMC0TTTTTTSB8_yB7_EB6_EB5_EB4_EB3_E"),
    T_ERR("_RMC0TTTTTTRB8_yB7_EB6_EB5_EB4_EB3_E"),
    T_ERR("_RMC0TTTTTTQB8_yB7_EB6_EB5_EB4_EB3_E"),
    T_ERR("_RMC0TTTTTTOB8_yB7_EB6_EB5_EB4_EB3_E"),
    T_ERR("_RMC0TTTTTTpB8_yB7_hB6_EB5_EB4_EB3_E"),
    T_ERR("_RMC0TTTTTTpB8_yB7_llvmEB5_EB4_EB3_E"),
    T_ERR("_RMC0TTTTTTpB1_yB7_eB6_EB5_EB4_EB3_E"),
    T_ERR("_RMC0TTTTTTpB1_tB7_fB6_EB5_EB4_EB3_E"),
    T_ERR("_RMC0TTTC0TTTTTPpB0_SB7_llvmTPpB8_SB7_EB6_EB5_EB4_EB3_E"),
    T_ERR("_RMC3TTTTTtpB_yB7_EB6_EB5_EB4_EB3_E"),
    T_ERR("_RMC0TTTTRLpB8_llvB_vmEB_EB5FEB4EB5FEB4_EB3_E"),
    T_ERR("_RMC0TTTTQLp.B_llvmEB6_EB5_EB4_EB3_E"),
    T_ERR("_RMC0TRMC0TTTTQLp.B_YBTTTQLp.B_YB7_EBd_EB5_EB4_EB3_E"),
    T_ERR("_RMC0TTTTQLp.B_llvmEB6_EB5_EB4_E!3_E"),
    T_ERR("_RMC0TRMC0TTTTQLp.B_bB7_EB6_EB5_EB4_E"),
    T_ERR("_RMC0TTTTRLp.B_llvmEB6_EB5_EB4_EB3_E"),
    T_ERR("_RMC0TTTTQLpC0TTTfQLp.B_B_EB84_EB3_E"),
    T_ERR("_RMC0TTTTQLp.TfQLp.B_jC0TTTfQLp.B_llvT_EB3_E"),
    T_ERR("_RMC0TTTTQLpB8_TTTTTQLp_B_llvmEB6_E3_E"),
    T_ERR("_RIC0TRLpB8B8_B8_llvmEB6_EB5_llvmEB6_EB5_EB4_EL3_E"),
    T_ERR("_RNCINkXs25NNNNNNNNNNNNNNNNNNNNNNNN_INyB9_4IterhENuNgNoBb_4iter8iteraionNCN1_6hr7m0E0Bb_"),
    T_ERR("_RNCXNkXs25_NgCsbmNqQUJIY6D_4core5sliceINyB4_4IterhENuNgNoBb_4iter8iterator8Iterator9rpositionNCNgNpB2_6hr7m0E0Bb_"),
    T_ERR("_RNCXNkXs25_NgCsbmNqQUJIY6D_4core5sliceINyB9_4IterhENuNgNoBZ_4iter8iterator8Iterator9rpositionNCNgNpB2_6hr7m0E0Bb_"),
    T_ERR("_RYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYyYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYyYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYNfYB_YYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYNfYB_"),
    T_ERR("_RNCXNkXs25_NSCsbmNqQUJIY6D_4core5sliceINyB2_4IterhENuNgNoBb_4iter8iterator8Iterator9rpositionNCNgNpB2_6D_4core5sliReINyB1_4IterhENu6D_4core5sliceINyB1_4IterhENuNgNoBb_4iter8iterator8Iterator9rpositionNCNgNpBNgNoBb_4iter8iterr9rpo25_NgCsbmNqQUJIY6D_4core5sliceIN4IterhENuNgNoBb_4iter8iterator8Iterator9rpositionNCNgNpB2_6NqQUJIY6D_4core5sliReINyB1_4IterhENu6D_4core5sliceINyB1_4IterhENuNgNoBb_4iter8iterator8Iterator9rpositionNCNgNpBNgNoBb_4iter8iterr9rpositionNCNgNpB2_6NqQUJIY6B2_6hr7m0E7m0EsitionNCNgNpB2_6NqQUJIY6B2_6hr7m0E7m0E0Bb_"),
    T_ERR("_RNCXNkXs25_NCCsbmNqQUJIY6D_4core5sliceINyB2_4IterhENuNgNoBb_4iter8iterator8Iterator9rpositionNCNgNpB2_6D_4core5sliReINyB1_4IterhENu6D_4core5sliceINyB1_4IterhENuNgNoBb_4iter8iterator8Iterator9rpositionNCNgNpBNgNoBb_4iter8iterr9rpo25_NgCsbmNqQUJIY6D_4core5sliceIN4IterhENuNgNoBb_4iter8iterator8Iterator9rpositionNCNgNpB2_6NqQUJIY6D_4core5sliReINyB1_4IterhENu6D_4core5sliceINyB1_4IterhENuNgNoBb_4iter8iterator8Iterator9rpositionNCNgNpBNgNoBb_4iter8iterr9rpositionNCNgNpB2_6NqQUJIY6B2_6hr7m0E7m0EsitionNCNgNpB2_6NqQUJIY6B2_6hr7m0E7m0E0Bb_"),
    T_ERR("_RMC0TTTTRL_B4_llvmEB6_EB5_EB4_EB3_E"),
    T_ERR("_RMC0TTTTRRMC0TB7_llvmEB6_EB5_EB4_EB3_EL_B7_llvmEB6_EB5_EB4_EB3_E"),
    T_ERR("_RIC0TTTTQIC0L_B7_llvmEB6_E75_EB4_EB3_E"),
    T_ERR("_RNCINkXs25_NSCsbmNqQUJIY6D_4core53liceINyBK_4IterhDNCINkXs25_NSCsbmD_4core5sRNCINkXs25_NSCsbmNqQUJIY6D_4core5sliceINyB9_4IterhDNCINkXs25_NSCsbmJIY6D_4core5sliceINyB9_4IterhENuNgNoBN_4iter8iterator8Iterato29rposillvmtionNCXs25_NSCsbUJIY6D_4core5sliceINyB9_4IterhDNuNgNCINkXs25_NSCsbmJIY6D_4core5sliceINyB9_4IterhDNuNgNoBN_4iter8iterator8IliceINyB1_4IterhENuNgNoBN_4iter8iterator8Iterator9rposillvmtionNCXs25_NSCsbUJIY6D_4core5sliceINyB9_4IterhDNuNgNCINkXs25_NSCsbmJIY6D_4core5sliceINyB9_4IterhDNuNgNoBN_4iter8iterator8Iter9rposillvmtionNCNgNpB1_Bb_"),
    T_ERR("_RNCINkXs25_NSCsbmNqQUJIY6D_4core93liceINyBK_4IterhDNCINkXs25_NSCsbmD_4core5sRNCINkXs25_NSCsbmNqQUJIY6D_4core5sliceINyB9_4IterhDNCINkXs25_NSCsbmJIY6D_4core5sliceINyB9_4IterhENuNgNoBN_4iter8iterator8Iterato29rposillvmtionNCXs25_NSCsbUJIY6D_4core5sliceINyB9_4IterhDNuNgNCINkXs25_NSCsbmJIY6D_4core5sliceINyB9_4IterhDNuNgNoBN_4iter8iterator8IliceINyB1_4IterhENuNgNoBN_4iter8iterator8Iterator9rposillvmtionNCXs25_NSCsbUJIY6D_4core5sliceINyB9_4IterhDNuNgNCINkXs25_NSCsbmJIY6D_4core5sliceINyB9_4IterhDNuNgNoBN_4iter8iterator8Iter9rposillvmtionNCNgNpB1_Bb_"),
    T_ERR("_RNCINkXs25_NSCsbmNqQUJIY6D_4core5sliceINyB9_4IterhDNCINkXs25_NSCsbmD_4core5sRNCINkXs25_NSCsbmNqQUJIY6D_4core5sliceINyB9_4IterhDNCINkXs25_NSCsbmJIY6D_4core5sliceINyB9_4IterhENuNgNoBN_4iter8iterator8Iterato29rposillvmtiB_NCXs25_NSCsbUJIY6D_4core5sliceINyB9_4IterhDNuNgNCINkXs25_NSCsbmJIY6D_4core5sliceINyB9_4IterhDNuNgNoBN_4iter8iterator8IliceINyB1_4IterhENuNgNoBN_4iter8iterator8Iterator9rposillvmtionNCXs25_NSCsbUJIY6D_4core5sliceINyB9_4IterhDNuNgNCINkXs25_NSCsbmJIY6D_4core5sliceINyB9_4IterhDNuNgNoBN_4iter8iterator8Iter9rposillvmtionNCNgNpB1_Bb_"),
    T_ERR("_RNCINkXs25_NSCsbmNqQUJIY6D_4coreu425_NSNgNoBN_4iter8iteratotliceINyB9_4IterhDNCINkXs25_NSCsbmD_4core5sRNCINkXs25_NSCsbeNqQUJIY6D_4core5sliceINyB9_4IterhLNCINkXs25_NSCsbmJIY6D_4core5sliceINyB9_48888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888eeeeeeeeeeeeeee88888888888888888888888888888888888888G88888888888888888888888888888888888888888888888888888888888888888888888888888888888888888NSCsbmJIY6D_4core5sliceINyB9_4IterhDNuNgNoBN_4iter8iteravmtionNCNgNpB1_Bb_"),
    T_ERR("_ZN9EB0_EB3_E"),
    T_ERR("_ZN9INTTB7_$B6_SB5_E"),
    T_ERR("_ZN9INTTB7 E.6_SBEEEEEEEEEEEEEEEEB7_EB6_EB5_EB0EB6_EB5_EB0_EB3_EEB0_EB3_E"),
    T_ERR("_ZN9I3TTB7_$B8_C0TTT9I3TTB7_$B8_$$5$B_E"),
    T_ERR("_ZN9$C$TB7_$B8_C0TTT9I3TB7_$B8_$$5$B_E"),
    T_ERR("_ZN9......=E"),
    T_ERR("_RMC0TTTTQLpfQNp.B_aaaaaTOTfQL_aaaaaB_"),
    T_ERR("_RMC0TTTTRLpB8_lRMC0B_aaB5_EB4_B5_EEB3_E"),
    T_ERR("_RMC0TTTTRLp_aalRMC0B_aaB5_EB4_B5_EEB3_E"),
    T_ERR("_RMC0TTTTRLp_C0TaalRMC0B6_EB_aaB4_B5_EEB3_E"),
    T_ERR("_RMC0TTTTRL0_aalRMC0B_aaB5_EB4_B5_EEB3_E"),
    T_ERR("_RMC6aEB8_XB4_YYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYAly_IYB_lYYYYYYYAly_HYB_"),
    T_ERR("_RMC6aEB8_XB4_YYYYYYYYYYYYYYYYYYYYYYYMC6aEB8ZXB4_YYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYAlypHYYYYYYYYYYYYYYYYYYAlyNHYB_"),
    T_ERR("_RMC6aEB8_NB4_YYNYYYNYYYYYYYYYYYxYYYYYYYRAC6aEB8_NBV_YYNYYYNYYYYYYYYYYYxYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYlYNHYB_YYY"),
    T_ERR("_ZN9A7$TB7_$B8_$B$TT9I3TB7m$__ZN98C$T_aa$B8_$C$TT9I3_ZN9$C$TB7_$B8_$B$TT9I3TB7m$__ZN9$C$TB_$BZN9A7$TB7_$B8_$B$TT6$C$$B$$B$$__ZN98C$T_aa$B8_$K$TT9I7_ZN9$C$TB7_$B8T_aa$B8_$C$TT9I3_ZN9$C$TB7_$BP$B$TT9I3TB7m$__ZN9$ $TB_$B8_$A$TT9I3TB7m$8_$A$TT9I3TB7m$__ZN2UE"),
    T_ERR("_ZN9A7$TB7_$B8_$B$TT9I3TB7m$__ZN98C$T_aa$B8_$C$TT9I3_ZN9$C$TB7_$B8_$B$TT9I3TB7m$__ZN9$C$TB_$BZN9A7$TB7_$B8_$B$TT6$C$$B$$B$$__ZN98C$T_aa$B8_$K$TT9I7_ZN9$C$TB7_$B8T_aa$B8_$C$TT9I3_ZN9$C$TB7_$SP$B$TT9I3TB7m$__ZN9$ $TB_$B8_$A$TT9I3TB7m$8_$A$TT9I3TB7m$__ZN2UE"),
    T_ERR("__ZN9?@EEEEEJE"),
    T_ERR("_RMC0TTTATjpB8_EB7_TB_aaB5_EB4_EB3_E"),
    T_ERR("_ZN949$TE7_llv4C$TE$C$7_llvm$C$TT9'3TB_$__................................................................................................................................................................................................................................................................................................................................................................................................$B$.E..........................................:.........................................................................................................................................P...............................................@..................................................................................................................................................................................................................................................................TTB7_E.6_SB_E.6_S65__ZQCI<_EB=E"),
    T_ERR("_RMC6aEB8_XB4_YYYYYYYYYYYYYYYYYYYYYYYYNSCsbmJIY6D_4core0MC6aEB8_XB4_YYYYYYYYYYYYYYYYYYsliceINyB9_rhDNuNgNoBN_4iter8iteravmt}ore5sliceINyB9_4IterhDNuNgNCINOXs25_NSCsbmJIY6D_4core5sliceI_yB9_4IterhDNuNgNoB__4llvmwionNB9_4INkXs25_NSCrhDYYYYYYYYYYYYYYYYYYYYYYYYYYYaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa)))))_aa)))))))))))))))))))))"),
    T_ERR("_ZN9A7$TB7_$B8_$B$TT9I3TB7m$__ZN98C$T_aa$B8_$C$TT9I3_ZN9$C$TB7_$B8_$B$TT9I3TB7m$__ZN9$C$TB_$BZN9A7$TB7_$B8_$B$TT6$C$$B$$B$$__ZN98C$T_aa$B8_$K$TT9I7_ZN9$C$TB7_$B8T_aa$B8_$C$TT9I3_ZN9$C$TB7_$LP$B$TT9I3TB7m$__ZN9$ $TB_$B8_$A$TT9I3TB7m$8_$A$TT9I3TB7m$__ZN2UE"),
    T_ERR("_ZN9A7$TB7_$B8_$B$TT9I3TB7m$__ZN98C$T_aa$B8_$C$TT9I3_ZN9$C$TB7_$B8_$B$TT9I3TB7m$__ZN9$C$TB_$BZN9A7$TB7_$B8_$B$TT6$C$$B$$B$$__ZN98C$T_aa$B8_$K$TT9I7_ZN9$C$TB7_$B8T_aa$B8_$C$TT9I3_ZN9$C$TB7_$LT$B$TT9I3TB7m$__ZN9$ $TB_$B8_$A$TT9I3TB7m$8_$A$TT9I3TB7m$__ZN2UE"),
    T_ERR("_ZN9A7$TB7_$B8_$B$TT9I3TB7m$__ZN98C$T_aa$B8_$C$TT9I3_ZN9$C$TB7_$B8_$B$TT9I3TB7m$__ZN9$C$TB_$BZN9A7$TB7_$B8_$B$TT6$C$$B$$B$$__ZN98C$T_aa$B8_$K$TT9I7_ZN9$C$TB7_$B8T_aa$B8_$C$TT9I3_ZN9$C$TB7_$GT$B$TT9I3TB7m$__ZN9$ $TB_$B8_$A$TT9I3TB7m$8_$A$TT9I3TB7m$__ZN2UE"),
    T_ERR("_ZN9A7$TB7_$B8_$B$TT9I3TB7m$__ZN98C$T_aa$B8_$C$TT9I3_ZN9$C$TB7_$B8_$B$TT9I3TB7m$__ZN9$C$TB_$BZN9A7$TB7_$B8_$B$TT6$C$$B$$B$$__ZN98C$T_aa$B8_$K$TT9I7_ZN9$C$TB7_$B8T_aa$B8_$C$TT9I3_ZN9$C$TB7_$RP$B$TT9I3TB7m$__ZN9$ $TB_$B8_$A$TT9I3TB7m$8_$A$TT9I3TB7m$__ZN2UE"),
    T_ERR("_ZN9A7$TB7_$B8_$B$TT9I3TB7m$__ZN98C$T_aa$B8_$C$TT9I3_ZN9$C$TB7_$B8_$B$TT9I3TB7m$__ZN9$C$TB_$BZN9A7$TB7_$B8_$B$TT6$C$$B$$B$$__ZN98C$T_aa$B8_$K$TT9I7_ZN9$C$TB7_$B8T_aa$B8_$C$TT9I3_ZN9$C$TB7_$RF$B$TT9I3TB7m$__ZN9$ $TB_$B8_$A$TT9I3TB7m$8_$A$TT9I3TB7m$__ZN2UE"),
    T_ERR("_RNCXNkXs25_NgCsbmNqQUJIY6D_4core5sliceINyBK_4IterhENuNGNoBb_4iter8iterator8Iterator9rpositionNCNgNpB2_6D_4core5sliReINyB1_4IterhENu6D_4core5sliceINyB1_4IterhENuNgNoBb_4iter8iterator8Iterator9rpositionNCNgNpBNgNoBb_4iter8iterr9rpo25_NgCsbmNqQUJIY6D_4core5sliceIN4IterhENuNgNoBb_4iter8iterator8Iterator9rpositionNCNgNpB2_6NqQUJIY6D_4core5sliReINyB1_4IterhENu6D_4core5sliceINyB1_4IterhENuNgNoBb_4iter8iterator8Iterator9rpositionNCNgNpBNgNoBb_4iter8iterr9rpositionNCNgNpB2_6NqQUJIY6B2_6hr7m0E7m0EsitionNCNgNpB2_6NqQUJIY6B2_6hr7m0E7m0E0Bb_"),
    T_ERR("_RIC6kIIIIIB4_lB5_EB4NEB3_A"),
    T_ERR("_ZN9I3TTB7_$B8_$B$TT9I398C$T$B8_$B$TT9I398C$T_aa$B8_$C$TT9I3_ZN9$C$TB7_$B8_$B$TB$$B$$__ZN98C$T_aa$B8_$K$TT9I7_ZN9$C$TB7_$B8T_aa$B8_$C$TT9ITB7$LT$B$TT9I3TB7m$__ZB8T_aa$B8K$C$TT9I3_ZN9$C$TB7_$LT$B$TT9I3TB7m$__ZN9$ $TB7m$__ZN98C$T_aa$B8_$C$TT9I3_ZN:$C$TB7_$B8_$B$TT9I3TB7m$__ZN$RF$9$C$TB_$BZN9A7$TB7_8B8_$B$TT6$C$$B$%B$$__ZN98C$T_aa$B8_$K$TT9I7_ZN9$C$TB7_$B8T_aa$B8_$C$TT9I3_ZN9$C$TB7_$LT$B$TT9I3TB7m$__ZN9$ UE"),
    T_ERR("_RIC6aOB_aaB4_RIC6aOB_aaB8_gB._NaEB5_gB8_gB4_NaEB5_))))))))))))))))))))))da)))))))C6aEB8_XB4_DC6aXB4_DC6aEJ8_gB_NaEB5_gB8_gB4_NaEB5_))))))))))))))))))))))_a))))))))sitUonNCNgNpB1_6hr7m0E0Bb_)))sitionNCNgNpB1_6hr7m0E0Bb_"));

/* END CSTYLED */

static rust_test_grp_t *rust_tests[] = {
	&demangle,
	&demangle_dollars,
	&demangle_many_dollars,
	&demangle_osx,
	&demangle_elements_beginning_with_underscore,
	&demangle_trait_impls,
	&invalid_no_chop,
	&handle_assoc_types,
	&cplusplus_as_rust,
	&v0_crate_with_leading_digit,
	&v0_utf8_idents,
	&v0_closure,
	&v0_dyn_trait,
	&v0_const_generics,
	&v0_exponential_explosion,
	&v0_thinlto,
	&v0_demangle_extra_suffix,
	&v0_generic_func,
	&v0_eddyb,
	&v0_afl_fast,
};
static const size_t n_rust_tests = ARRAY_SIZE(rust_tests);

static boolean_t
check_failure(size_t i, rust_test_case_t *tc, const char *dem, boolean_t res)
{
	int savederr = errno;

	if (dem == NULL && savederr == EINVAL)
		return (B_TRUE);

	if (res)
		(void) printf("FAILURE\n");

	if (dem != NULL) {
		(void) printf("  [%zu] Successfully demanged an invalid "
		    "name\n", i);
		(void) printf("         Name: '%s'\n", tc->mangled);
		(void) printf("    Demangled: '%s'\n", dem);
		return (B_FALSE);
	}

	(void) printf("  [%zu] demangle() returned an unexpected error\n", i);
	(void) printf("    Errno: %d\n", savederr);
	return (B_FALSE);
}

static boolean_t
check_success(size_t i, rust_test_case_t *tc, const char *dem, boolean_t res)
{
	if (dem != NULL && strcmp(tc->demangled, dem) == 0)
		return (B_TRUE);

	if (res)
		(void) printf("FAILURE\n");

	if (dem == NULL) {
		(void) printf("  [%zu] Failed to demangle '%s'\n", i,
		    tc->mangled);
		return (B_FALSE);
	}

	(void) printf("  [%zu] Demangled results do not match.\n", i);
	(void) printf("       Mangled: %s\n", tc->mangled);
	(void) printf("      Expected: %s\n", tc->demangled);
	(void) printf("        Actual: %s\n", dem);
	return (B_FALSE);
}

static boolean_t
run_test(rust_test_grp_t *test)
{
	boolean_t res = B_TRUE;

	(void) printf("Test %s: ", test->name);

	for (size_t i = 0; test->tests[i].mangled != NULL; i++) {
		char *dem;

		dem = sysdemangle(test->tests[i].mangled, SYSDEM_LANG_RUST,
		    NULL);
		if (test->tests[i].demangled == NULL)
			res &= check_failure(i, &test->tests[i], dem, res);
		else
			res &= check_success(i, &test->tests[i], dem, res);

		free(dem);
	}

	if (res)
		(void) printf("SUCCESS\n");

	return (res);
}

int
main(int argc, char **argv)
{
	const char *l;
	boolean_t ok = B_TRUE;

	l = setlocale(LC_CTYPE, TEST_LOCALE);
	if (l == NULL || strcmp(l, TEST_LOCALE) != 0)
		errx(EXIT_FAILURE, "failed to set locale to %s", TEST_LOCALE);

	for (size_t i = 0; i < n_rust_tests; i++)
		ok &= run_test(rust_tests[i]);

	return (ok ? 0 : 1);
}

const char *
_umem_debug_init(void)
{
	return ("default,verbose");
}

const char *
_umem_logging_init(void)
{
	return ("fail,contents");
}
