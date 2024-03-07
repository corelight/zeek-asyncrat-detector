# @TEST-DOC: Example of a test that runs Zeek on a pcap and verifies log content
# @TEST-EXEC: zeek -r $TRACES/30a385ed-171e-4f15-ac3f-08c96be7bfd1.pcap $PACKAGE %INPUT >output
#
# @TEST-EXEC: btest-diff notice.log