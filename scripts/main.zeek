module RatC2SslDetector;

export {
	## The notice when AsyncRAT or BitRAT C2 is observed.
	redef enum Notice::Type += { C2_Traffic_Observed, };
}

# Where the magic happens. Expanded regex to include BitRAT
global rat_re = /(((async|dc|bit)rat|SXN) Server)|(DcRat By)|(BitRAT)/i;

event ssl_established(c: connection)
	{
	if ( ! c?$ssl )
		return;

	local msg = "Potential RAT (AsyncRAT/BitRAT) C2 discovered via a default SSL certificate.";
	local data = "";
	local found_it = F;

	if ( c$ssl?$issuer && rat_re in c$ssl$issuer )
		{
		data = fmt("Cert Fingerprints: %s Issuer: %s", c$ssl$cert_chain_fps,
		    c$ssl$issuer);
		found_it = T;
		}
	else if ( c$ssl?$subject && rat_re in c$ssl$subject )
		{
		data = fmt("Cert Fingerprints: %s Subject: %s", c$ssl$cert_chain_fps,
		    c$ssl$subject);
		found_it = T;
		}

	if ( found_it )
		NOTICE([ $note=RatC2SslDetector::C2_Traffic_Observed, $msg=msg, $sub=data, $conn=c,
		    $identifier=cat(c$id$orig_h, c$id$resp_h) ]);
	}
