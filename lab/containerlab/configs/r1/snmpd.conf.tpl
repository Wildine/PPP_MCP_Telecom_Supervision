createUser __SNMPV3_USER__ SHA "__SNMPV3_AUTH_KEY__" AES "__SNMPV3_PRIV_KEY__"

view limited included .1.3.6.1.2.1.1
view limited included .1.3.6.1.2.1.2
view limited included .1.3.6.1.2.1.4
view limited included .1.3.6.1.2.1.14
view limited included .1.3.6.1.2.1.15

rouser __SNMPV3_USER__ priv -V limited

agentaddress udp:161
