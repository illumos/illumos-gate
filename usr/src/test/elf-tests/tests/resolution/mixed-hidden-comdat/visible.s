	.type	bss_symbol, @object
	.section	.bss.bss_symbol,"awG",@nobits,bss_symbol,comdat
	.weak	bss_symbol
	.size	bss_symbol, 8
bss_symbol:
	.zero	8

	.type	data_symbol, @object
	.section	.data.data_symbol,"awG",@progbits,data_symbol,comdat
	.weak	data_symbol
	.size	data_symbol, 8
data_symbol:
	.quad	8675309
