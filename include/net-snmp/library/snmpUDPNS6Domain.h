#ifndef _SNMPUDPNS6DOMAIN_H
#define _SNMPUDPNS6DOMAIN_H

#include <net-snmp/types.h>

#ifdef __cplusplus
extern          "C" {
#endif

#include <net-snmp/library/snmp_transport.h>

config_require(IPv6Base)
config_require(UDPBase)
config_require(SocketNS)

#include <net-snmp/library/snmpIPv6BaseDomain.h>
#include <net-snmp/library/snmpSocketNSDomain.h>

netsnmp_transport *netsnmp_udpns6_transport(struct sockaddr_in6 *addr,
      const char *ns, int local);

NETSNMP_IMPORT
void            netsnmp_udpns6_agent_config_tokens_register(void);
NETSNMP_IMPORT
void            netsnmp_udpns6_parse_security(const char *token, char *param);

/*
 * "Constructor" for transport domain object.
 */

NETSNMP_IMPORT void netsnmp_udpns6_ctor(void);

#ifdef __cplusplus
}
#endif
#endif/*_SNMPUDPNS6DOMAIN_H*/
