function biz(baz, bar)
{
	print baz, bar
}

function buz(baz, bar)
{
	print length(baz), bar
}

function buz2(baz, baz1, bar, baz2)
{
	print length(baz), length(baz1), bar, length(baz2)
	baz2[0] = "baz2"
#	baz[0] = "baz"	# fatal
}

function buz3(baz)
{
	buz2(baz, baz, split("abc", baz, ""), baz)
} 


BEGIN {
	biz(foo, foo != "")

	biz(fy, fy = "fy")

	biz(fi = 10, fi = 20)
	print fi

	buz(a, split("abc", a, ""))

	buz2(c, c, split("abc", c, ""), c)
	print c[0], length(c)

	buz3(d)
	print d[0], length(d)

	biz(b, split("abc", b, ""))
}
