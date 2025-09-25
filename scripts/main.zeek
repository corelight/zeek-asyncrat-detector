module AsyncRAT;

export {
	redef enum Notice::Type += {
		## This notice is generated when a connection is potentially AsyncRAT
		## malware C2.
		C2_Traffic_Observed,
	};
}

# Where the magic happens.
global asyncrat_re = /(((async|dc)rat|SXN) Server)|(DcRat By)/i;

event ssl_established(c: connection)
	{
	if ( ! c?$ssl )
		return;

	local msg = "Potential AsyncRAT C2 discovered via a default SSL certificate.";
	local data = "";
	local found_it = F;

	if ( c$ssl?$issuer && asyncrat_re in c$ssl$issuer )
		{
		data = fmt("Cert Fingerprints: %s Issuer: %s", c$ssl$cert_chain_fps,
		    c$ssl$issuer);
		found_it = T;
		}
	else if ( c$ssl?$subject && asyncrat_re in c$ssl$subject )
		{
		data = fmt("Cert Fingerprints: %s Subject: %s", c$ssl$cert_chain_fps,
		    c$ssl$subject);
		found_it = T;
		}

	if ( found_it )
		NOTICE([ $note=AsyncRAT::C2_Traffic_Observed, $msg=msg, $sub=data, $conn=c,
		    $identifier=cat(c$id$orig_h, c$id$resp_h) ]);
	}
