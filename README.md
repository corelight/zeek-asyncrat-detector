# A Zeek Based AsyncRAT Malware Detector

Malware often hides communications with its command and control (C2) server over HTTPS. 
The encryption in HTTPS usually conceals the compromise long enough for the malware to 
accomplish its goal. This makes detecting malware that uses HTTPS challenging, but once 
in a while, you will catch a break, as in the case here with AsyncRAT, a Windows remote 
access tool that has been deployed over the past year to target organizations that manage 
critical infrastructure in the United States.

### Example Notice.log Output

```
#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	notice
#open	2024-03-12-13-19-10
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	fuid	file_mime_type	file_desc	proto	note	msg	sub	src	dst	p	n	peer_descr	actions	email_dest	suppress_for	remote_location.country_code	remote_location.region	remote_location.city	remote_location.latitude	remote_location.longitude
#types	time	string	addr	port	addr	port	string	string	string	enum	enum	string	string	addr	addr	port	count	string	set[enum]	set[string]	interval	string	string	string	double	double
1709051041.876652	CLNN1k2QMum1aexUK7	192.168.100.124	49207	181.131.218.39	4041	-	-	-	tcp	AsyncRAT::C2_Traffic_Observed	Potential AsyncRAT C2 discovered via a default SSL certificate.	Cert Fingerprints: [ce772ec37d88351f43e6350c6c2b9777c9a7855f2a55184fba784e5e7df9e3eb] Issuer: CN=AsyncRAT Server	192.168.100.124	181.131.218.39	4041	-	-	Notice::ACTION_LOG	(empty)	3600.000000	-	-	-	-	-
#close	2024-03-12-13-19-10
```

### PCAP Sources

- AsyncRAT
  - https://app.any.run/tasks/cd010953-5faf-4054-86be-58c020c3a532/ 
- DcRat By qwqdanchun
  - https://app.any.run/tasks/30a385ed-171e-4f15-ac3f-08c96be7bfd1/ 
  - https://github.com/qwqdanchun/DcRat/blob/30ca53b068b4ab7a2542835f7456abd26e1a0ed4/Server/Helper/CreateCertificate.cs#L32
- SXN Server 
  - https://app.any.run/tasks/9596cf60-0da6-47a7-a375-1f25ae32d843/ 