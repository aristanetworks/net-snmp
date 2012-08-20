// Copyright (c) 2011 Arista Networks, Inc.  All rights reserved.
// Arista Networks, Inc. Confidential and Proprietary.

#ifndef _SNMPUDPNSDOMAIN_H
#define _SNMPUDPNSDOMAIN_H

#ifdef __cplusplus
extern          "C" {
#endif

#include <net-snmp/library/snmp_transport.h>
#include <net-snmp/library/asn1.h>

#if HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

config_require(UDPIPv4Base)
config_require(SocketNS)
#include <net-snmp/library/snmpUDPIPv4BaseDomain.h>

netsnmp_transport *netsnmp_udpns_transport(struct sockaddr_in *addr,
                                           char *ns, int local);


/*
 * Register any configuration tokens specific to the agent.
 */

NETSNMP_IMPORT
void            netsnmp_udpns_agent_config_tokens_register(void);

NETSNMP_IMPORT
void            netsnmp_udpns_parse_security(const char *token, char *param);

NETSNMP_IMPORT
int             netsnmp_udpns_getSecName(void *opaque, int olength,
                                         const char *community,
                                         size_t community_len,
                                         const char **secname,
                                         const char **contextName);

/*
 * "Constructor" for transport domain object.
 */

void            netsnmp_udpns_ctor(void);

/*
 * protected-ish functions used by other core-code
 */
char *netsnmp_udpns_fmtaddr(netsnmp_transport *t, void *data, int len);
#if defined(linux) && defined(IP_PKTINFO) || \
    defined(IP_RECVDSTADDR) && !defined(_MSC_VER)
int netsnmp_udpns_recvfrom(int s, void *buf, int len, struct sockaddr *from,
                           socklen_t *fromlen, struct sockaddr *dstip,
                           socklen_t *dstlen, int *if_index);
int netsnmp_udpns_sendto(int fd, struct in_addr *srcip, int if_index,
                         struct sockaddr *remote, void *data, int len);
int netsnmp_udpns_send(netsnmp_transport *t, void *buf, int size,
                       void **opaque, int *olength);
int netsnmp_udpns_recv(netsnmp_transport *t, void *buf, int size,
                       void **opaque, int *olength);
#endif

#ifdef __cplusplus
}
#endif
#endif/*_SNMPUDPNSDOMAIN_H*/
