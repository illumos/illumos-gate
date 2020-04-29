#!/usr/bin/gawk

# Copyright 2020 Oxide Computer Company

# Converts the MD5 test vectors into the same format as the SHA ones
# usage: gawk -f convert.awk byte-hashes.md5

BEGIN {
	filenum = 0;
}

$2 == "^" {
	filename = sprintf("byte%04d.dat", filenum);
	# od -An -t x1 -w200000 < <file>  | sed -e 's/ //g'
	cmd = sprintf("sh -c \"od -An -t x1 -w200000 < %s | sed -e 's/ //g'\"", filename);
	cmd |& getline bindata
	binlen = length(bindata) / 2;
	if (binlen == 0) {
		bindata = "00"
	}
	printf("Len = %d\n", binlen * 8);
	printf("Msg = %s\n", bindata);
	printf("MD = %s\n\n", tolower($1));
	filenum++;
}
