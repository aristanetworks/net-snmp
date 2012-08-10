#ifndef _SNMPTCPNS6DOMAIN_H
#define _SNMPTCPNS6DOMAIN_H

#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

config_require(IPv6Base)
config_require(SocketBase)
config_require(TCPBase)

#include <net-snmp/library/snmpIPv6BaseDomain.h>
#include <net-snmp/library/snmpSocketNSDomain.h>

#ifdef __cplusplus
extern          "C" {
#endif

netsnmp_transport *netsnmp_tcpns6_transport(struct sockaddr_in6 *addr,
                                            const char *ns, int local);

/*
 * "Constructor" for transport domain object.
 */

NETSNMP_IMPORT void     netsnmp_tcpipv6_ctor(void);

#ifdef __cplusplus
}
#endif
#endif/*_SNMPTCPNS6DOMAIN_H*/
