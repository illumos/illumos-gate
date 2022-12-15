This is a test that when stripping (via `ld -s`) members of a group, we do not
corrupt the group.

strip-one: We create a group where some, but not all members are strippable
	and verify that ld does not crash when processing such an object, that the
	right member was stripped, and that ld -r outputs a group which is valid.

strip-two: Create a group where the middle two sections are strippable, verify
    that the first and last survive.

strip-all: We create a group where all members are stripped and verify this
    works, and the group doesn't survive ld -r.
