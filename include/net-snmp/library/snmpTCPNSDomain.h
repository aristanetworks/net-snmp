// Copyright (c) 2011 Arista Networks, Inc.  All rights reserved.
// Arista Networks, Inc. Confidential and Proprietary.

#ifndef _SNMPTCPNSDOMAIN_H
#define _SNMPTCPNSDOMAIN_H

#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

config_require(IPv4Base)
config_require(SocketBase)
config_require(SocketNS)
config_require(TCPBase)

#include <net-snmp/library/snmpIPv4BaseDomain.h>

#ifdef __cplusplus
extern          "C" {
#endif

/*
 * Prototypes
 */
int netsnmp_tcpns_recv(netsnmp_transport *t, void *buf, int size,
                         void **opaque, int *olength);
int netsnmp_tcpns_send(netsnmp_transport *t, void *buf, int size,
                         void **opaque, int *olength);

netsnmp_transport *netsnmp_tcpns_transport(struct sockaddr_in *addr,
                                           char * ns, int local);

/*
 * "Constructor" for transport domain object.
 */

void            netsnmp_tcpns_ctor(void);

#ifdef __cplusplus
}
#endif

#endif/*_SNMPTCPNSDOMAIN_H*/
