	.type	bss_symbol, @object
	.section	.bss.bss_symbol,"awG",@nobits,bss_symbol,comdat
	.hidden	bss_symbol
	.weak	bss_symbol
	.size	bss_symbol, 8
bss_symbol:
	.zero	8

	.type	data_symbol, @object
	.section	.data.data_symbol,"awG",@progbits,data_symbol,comdat
	.hidden	data_symbol
	.weak	data_symbol
	.size	data_symbol, 8
	/*
	 * Intentionally break the COMDAT rules and give this a different
	 * value, so we can assert that the value got from one place and the
	 * visibility resolved from the other
	 */
data_symbol:
	.zero	8
