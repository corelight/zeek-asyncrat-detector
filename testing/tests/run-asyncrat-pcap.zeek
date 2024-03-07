# @TEST-DOC: Example of a test that runs Zeek on a pcap and verifies log content
# @TEST-EXEC: zeek -r $TRACES/cd010953-5faf-4054-86be-58c020c3a532.pcap $PACKAGE %INPUT >output
#
# @TEST-EXEC: btest-diff notice.log
