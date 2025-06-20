# @TEST-DOC: Example of a test that runs Zeek on a pcap and verifies log content
# @TEST-EXEC: zeek -r $TRACES/220209-vlt42sbab5-behavioral2.pcap $PACKAGE %INPUT >output
#
# @TEST-EXEC: btest-diff notice.log