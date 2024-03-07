# @TEST-DOC: Example of a test that runs Zeek on a pcap and verifies log content
# @TEST-EXEC: zeek -r $TRACES/9596cf60-0da6-47a7-a375-1f25ae32d843.pcap $PACKAGE %INPUT >output
#
# @TEST-EXEC: btest-diff notice.log
