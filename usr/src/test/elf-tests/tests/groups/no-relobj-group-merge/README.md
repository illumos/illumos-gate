This is a test that sections which are members of groups are not merged when
creating relocatable objects.

If we place an input section which is in a group in the same output section as
another input section this leaves us with problems:

1. If the other input section was not previously member of a group, its data
   becomes part of a group and we may now discard it along with that group.
2. If the other input section _was_ a member of a group we now have two groups
   containing the same section, where discarding one will corrupt the other.
3. ... and if that section had associated relocations, which must have been
   part of the group, we will now associate those relocations with the merged
   output section further corrupting the group, as there is now no mapping
   between input and output relocation sections.

We test this by defining 3 sections in two groups in two input objects:
- `.test_data_conflict` in `group1`
- `.test_data_conflict` in `group2`
- `.test_data_conflict` in no group at all

We then link these objects together using `ld -r` and expect:
- `.test_data_conflict` from `group1` remains in `group1`, is merged with no
  other input section, and has the duplicate section discarded by the COMDAT
  group logic.
- `.test_data_conflict` from `group2` remains in `group2`, is merged with no
  other input section, and has the duplicate section discarded by the COMDAT
  group logic.
- the ungrouped `.test_data_conflict` remains in no groups, and the two input
  sections are merged into a single output section.
