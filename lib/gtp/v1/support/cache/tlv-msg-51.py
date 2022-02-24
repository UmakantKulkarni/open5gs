ies = []
ies.append({ "ie_value" : "Cause", "presence" : "Mandatory", "reference" : "7.7.1"})
ies.append({ "ie_value" : "IMSI", "presence" : "Conditional", "reference" : "7.7.2"})
ies.append({ "ie_value" : "Tunnel Endpoint Identifier Control Plane", "presence" : "Conditional", "reference" : "7.7.14"})
ies.append({ "ie_value" : "RAB Context", "presence" : "Conditional", "reference" : "7.7.19"})
ies.append({ "ie_value" : "Radio Priority SMS", "presence" : "Optional", "reference" : "7.7.20"})
ies.append({ "ie_value" : "Radio Priority", "presence" : "Optional", "reference" : "7.7.21"})
ies.append({ "ie_value" : "Packet Flow Id", "presence" : "Optional", "reference" : "7.7.22"})
ies.append({ "ie_value" : "Charging Characteristics", "presence" : "Optional", "reference" : "7.7.23"})
ies.append({ "ie_value" : "Radio Priority LCS", "presence" : "Optional", "reference" : "7.7.25B"})
ies.append({ "ie_value" : "MM Context", "presence" : "Conditional", "reference" : "7.7.28"})
ies.append({ "ie_value" : "PDP Context", "presence" : "Conditional", "reference" : "7.7.29"})
ies.append({ "ie_value" : "SGSN Address for Control Plane", "presence" : "Conditional", "reference" : "7.7.32"})
ies.append({ "ie_value" : "PDP Context Prioritization ", "presence" : "Optional", "reference" : "7.7.45"})
ies.append({ "ie_value" : "MBMS UE Context", "presence" : "Optional", "reference" : "7.7.55"})
ies.append({ "ie_value" : "Subscribed RFSP Index", "presence" : "Optional", "reference" : "7.7.88"})
ies.append({ "ie_value" : "RFSP Index in use", "presence" : "Optional", "reference" : "7.7.88"})
ies.append({ "ie_value" : "Co-located GGSN-PGW FQDN", "presence" : "Optional", "reference" : "7.7.90"})
ies.append({ "ie_value" : "Evolved Allocation/Retention Priority II", "presence" : "Optional", "reference" : "7.7.92"})
ies.append({ "ie_value" : "Extended Common Flags", "presence" : "Optional", "reference" : "7.7.93"})
ies.append({ "ie_value" : "UE Network Capability", "presence" : "Optional", "reference" : "7.7.99"})
ies.append({ "ie_value" : "UE-AMBR", "presence" : "Optional", "reference" : "7.7.100"})
ies.append({ "ie_value" : "APN-AMBR with NSAPI", "presence" : "Optional", "reference" : "7.7.101"})
ies.append({ "ie_value" : "Signalling Priority Indication with NSAPI", "presence" : "Optional", "reference" : "7.7.104"})
ies.append({ "ie_value" : "Higher bitrates than 16 Mbps flag", "presence" : "Optional", "reference" : "7.7.105"})
ies.append({ "ie_value" : "Selection Mode with NSAPI", "presence" : "Optional", "reference" : "7.7.113"})
ies.append({ "ie_value" : "Local Home Network ID with NSAPI", "presence" : "Optional", "reference" : "7.7.115"})
ies.append({ "ie_value" : "UE Usage Type", "presence" : "Optional", "reference" : "7.7.117"})
ies.append({ "ie_value" : "Extended Common Flags II", "presence" : "Optional", "reference" : "7.7.118"})
ies.append({ "ie_value" : "UE SCEF PDN Connection", "presence" : "Optional", "reference" : "7.7.121"})
ies.append({ "ie_value" : "IOV_updates counter", "presence" : "Optional", "reference" : "7.7.122"})
ies.append({ "ie_value" : "Alternative GGSN Address for control Plane", "presence" : "Optional", "reference" : "7.7.32"})
ies.append({ "ie_value" : "Alternative GGSN Address for user traffic", "presence" : "Optional", "reference" : "7.7.32"})
msg_list[key]["ies"] = ies
