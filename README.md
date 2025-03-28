This is a powershell script that converts STIX2 information into csv. It was created primarily to upload IOCs to MS Defender if you are provided with STIX2 format information. The columns have been mapped to what Defender uses. For example, STIX2 uses ipv4-addr while Defender uses ipAddress.

Usage:
.\stix2csv -InputFolder "C:\Path\to\Stix\JSON\files" -OutputFile "Output.csv"

Import your CSV in Defender
