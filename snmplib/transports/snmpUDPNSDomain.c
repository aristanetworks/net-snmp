// Copyright (c) 2011 Arista Networks, Inc.  All rights reserved.
// Arista Networks, Inc. Confidential and Proprietary.

/* Portions of this file are subject to the following copyright(s).  See
 * the Net-SNMP's COPYING file for more details and other copyrights
 * that may apply:
 */
/*
 * Portions of this file are copyrighted by:
 * Copyright Copyright 2003 Sun Microsystems, Inc. All rights reserved.
 * Use is subject to license terms specified in the COPYING file
 * distributed with the Net-SNMP package.
 */

#include <stddef.h>
#include <stdio.h>
#include <sys/types.h>
#include <ctype.h>
#include <errno.h>

#if HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif
#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#if HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#if HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#if HAVE_NETDB_H
#include <netdb.h>
#endif
#if HAVE_SYS_UIO_H
#include <sys/uio.h>
#endif

#if HAVE_DMALLOC_H
#include <dmalloc.h>
#endif

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/types.h>
#include <net-snmp/output_api.h>
#include <net-snmp/config_api.h>
#include <net-snmp/library/system.h>
#include <net-snmp/library/tools.h>
#include <net-snmp/library/snmp_assert.h>

#include <net-snmp/library/snmp_transport.h>
#include <net-snmp/library/snmpSocketBaseDomain.h>
#include <net-snmp/library/snmpSocketNSDomain.h>
#include <net-snmp/library/snmpUDPNSDomain.h>
#include <net-snmp/library/snmpUDPIPv4BaseDomain.h>

#include "inet_ntop.h"
#include "inet_pton.h"

#ifndef INADDR_NONE
#define INADDR_NONE	-1
#endif

#ifndef INET_ADDRSTRLEN
#define INET_ADDRSTRLEN 16
#endif

static netsnmp_tdomain udpnsDomain;

/*
 * needs to be in sync with the definitions in snmplib/snmpTCPDomain.c
 * and perl/agent/agent.xs
 */
typedef netsnmp_indexed_addr_pair netsnmp_udpns_addr_pair;

/*
 * Return a string representing the address in data, or else the "far end"
 * address if data is NULL.
 */

char *
netsnmp_udpns_fmtaddr(netsnmp_transport *t, void *data, int len)
{
    return netsnmp_ipv4_fmtaddr("UDPNS", t, data, len);
}

#if (defined(linux) && defined(IP_PKTINFO)) \
    || defined(IP_RECVDSTADDR) && HAVE_STRUCT_MSGHDR_MSG_CONTROL \
                               && HAVE_STRUCT_MSGHDR_MSG_FLAGS

int netsnmp_udpns_recvfrom(int s, void *buf, int len, struct sockaddr *from, socklen_t *fromlen, struct sockaddr *dstip, socklen_t *dstlen, int *if_index)
{
    /** udpiv4 just calls udpbase. should we skip directly to there? */
    return netsnmp_udpipv4_recvfrom(s, buf, len, from, fromlen, dstip, dstlen,
                                    if_index);
}

int netsnmp_udpns_sendto(int fd, struct in_addr *srcip, int if_index, struct sockaddr *remote,
                void *data, int len)
{
    /** udpiv4 just calls udpbase. should we skip directly to there? */
    return netsnmp_udpipv4_sendto(fd, srcip, if_index, remote, data, len);
}
#endif /* (linux && IP_PKTINFO) || IP_RECVDSTADDR */

int
netsnmp_udpns_send(netsnmp_transport *t, void *buf, int size,
                     void **opaque, int *olength)
{
    int rc = -1;
    netsnmp_indexed_addr_pair *addr_pair = NULL;
    struct sockaddr *to = NULL;

    if (opaque != NULL && *opaque != NULL &&
        ((*olength == sizeof(netsnmp_indexed_addr_pair) ||
          (*olength == sizeof(struct sockaddr_in))))) {
        addr_pair = (netsnmp_indexed_addr_pair *) (*opaque);
    } else if (t != NULL && t->data != NULL &&
                t->data_length == sizeof(netsnmp_indexed_addr_pair)) {
        addr_pair = (netsnmp_indexed_addr_pair *) (t->data);
    }

    to = &addr_pair->remote_addr.sa;

    if (to != NULL && t != NULL && t->sock >= 0) {
        char *str = netsnmp_udpns_fmtaddr(NULL, (void *) addr_pair,
                                        sizeof(netsnmp_indexed_addr_pair));
        DEBUGMSGTL(("netsnmp_udpns", "send %d bytes from %p to %s on fd %d\n",
                    size, buf, str, t->sock));
        free(str);
	while (rc < 0) {
#if defined(linux) && defined(IP_PKTINFO)
            rc = netsnmp_udpns_sendto(t->sock,
                    addr_pair ? &(addr_pair->local_addr.sin.sin_addr) : NULL,
                    addr_pair ? addr_pair->if_index : 0, to, buf, size);
#else
            rc = sendto(t->sock, buf, size, 0, to, sizeof(struct sockaddr));
#endif /* linux && IP_PKTINFO */
	    if (rc < 0 && errno != EINTR) {
                DEBUGMSGTL(("netsnmp_udpns", "sendto error, rc %d (errno %d)\n",
                            rc, errno));
		break;
	    }
	}
    }
    return rc;
}

int
netsnmp_udpns_recv(netsnmp_transport *t, void *buf, int size,
                     void **opaque, int *olength)
{
    int             rc = -1;
    socklen_t       fromlen = sizeof(struct sockaddr);
    netsnmp_indexed_addr_pair *addr_pair = NULL;
    struct sockaddr *from;

    if (t != NULL && t->sock >= 0) {
        addr_pair = (netsnmp_indexed_addr_pair *) malloc(sizeof(netsnmp_indexed_addr_pair));
        if (addr_pair == NULL) {
            *opaque = NULL;
            *olength = 0;
            return -1;
        } else {
            memset(addr_pair, 0, sizeof(netsnmp_indexed_addr_pair));
            from = &addr_pair->remote_addr.sa;
        }

	while (rc < 0) {
#if defined(linux) && defined(IP_PKTINFO)
            socklen_t local_addr_len = sizeof(addr_pair->local_addr);
            rc = netsnmp_udpns_recvfrom(t->sock, buf, size, from, &fromlen,
                                      (struct sockaddr*)&(addr_pair->local_addr),
                                      &local_addr_len, &(addr_pair->if_index));
#else
            rc = recvfrom(t->sock, buf, size, NETSNMP_DONTWAIT, from, &fromlen);
#endif /* linux && IP_PKTINFO */
	    if (rc < 0 && errno != EINTR) {
		break;
	    }
	}

        if (rc >= 0) {
            char *str = netsnmp_udpns_fmtaddr(NULL, addr_pair, sizeof(netsnmp_indexed_addr_pair));
            DEBUGMSGTL(("netsnmp_udpns",
			"recvfrom fd %d got %d bytes (from %s)\n",
			t->sock, rc, str));
            free(str);
        } else {
            DEBUGMSGTL(("netsnmp_udpns", "recvfrom fd %d err %d (\"%s\")\n",
                        t->sock, errno, strerror(errno)));
        }
        *opaque = (void *)addr_pair;
        *olength = sizeof(netsnmp_indexed_addr_pair);
    }
    return rc;
}

/*
 * Open a UDP-based transport for SNMP.  Local is TRUE if addr is the local
 * address to bind to (i.e. this is a server-type session); otherwise addr is
 * the remote address to send things to.
 */

netsnmp_transport *
netsnmp_udpns_transport(struct sockaddr_in *addr, char *ns, int local)
{
    netsnmp_transport *t = netsnmp_udpipv4base_transport(addr, ns, local);

    if (NULL == t) {
        return NULL;
    }

    /*
     * Set Domain
     */

    t->domain = netsnmpUDPNSDomain;
    t->domain_length = netsnmpUDPNSDomain_len;

    /*
     * 16-bit length field, 8 byte UDP header, 20 byte IPv4 header
     */

    t->msgMaxSize = 0xffff - 8 - 20;
    t->f_recv     = netsnmp_udpns_recv;
    t->f_send     = netsnmp_udpns_send;
    t->f_close    = netsnmp_socketbase_close;
    t->f_accept   = NULL;
    t->f_fmtaddr  = netsnmp_udpns_fmtaddr;

    return t;
}

#if !defined(NETSNMP_DISABLE_SNMPV1) || !defined(NETSNMP_DISABLE_SNMPV2C)
/*
 * The following functions provide the "com2sec" configuration token
 * functionality for compatibility.
 */

#define EXAMPLE_NETWORK		"NETWORK"
#define EXAMPLE_COMMUNITY	"COMMUNITY"

typedef struct com2SecEntry_s {
    const char *secName;
    const char *contextName;
    struct com2SecEntry_s *next;
    in_addr_t   network;
    in_addr_t   mask;
    const char  community[1];
} com2SecEntry;

static com2SecEntry   *com2SecList = NULL, *com2SecListLast = NULL;

void
netsnmp_udpns_parse_security(const char *token, char *param)
{
    char            secName[VACMSTRINGLEN + 1];
    size_t          secNameLen;
    char            contextName[VACMSTRINGLEN + 1];
    size_t          contextNameLen;
    char            community[COMMUNITY_MAX_LEN + 1];
    size_t          communityLen;
    char            source[270]; /* dns-name(253)+/(1)+mask(15)+\0(1) */
    struct in_addr  network, mask;

    /*
     * Get security, source address/netmask and community strings.
     */

    param = copy_nword( param, secName, sizeof(secName));
    if (strcmp(secName, "-Cn") == 0) {
        if (!param) {
            config_perror("missing CONTEXT_NAME parameter");
            return;
        }
        param = copy_nword( param, contextName, sizeof(contextName));
        contextNameLen = strlen(contextName) + 1;
        if (contextNameLen > VACMSTRINGLEN) {
            config_perror("context name too long");
            return;
        }
        if (!param) {
            config_perror("missing NAME parameter");
            return;
        }
        param = copy_nword( param, secName, sizeof(secName));
    } else {
        contextNameLen = 0;
    }

    secNameLen = strlen(secName) + 1;
    if (secNameLen == 1) {
        config_perror("empty NAME parameter");
        return;
    } else if (secNameLen > VACMSTRINGLEN) {
        config_perror("security name too long");
        return;
    }

    if (!param) {
        config_perror("missing SOURCE parameter");
        return;
    }
    param = copy_nword( param, source, sizeof(source));
    if (source[0] == '\0') {
        config_perror("empty SOURCE parameter");
        return;
    }
    if (strncmp(source, EXAMPLE_NETWORK, strlen(EXAMPLE_NETWORK)) == 0) {
        config_perror("example config NETWORK not properly configured");
        return;
    }

    if (!param) {
        config_perror("missing COMMUNITY parameter");
        return;
    }
    param = copy_nword( param, community, sizeof(community));
    if (community[0] == '\0') {
        config_perror("empty COMMUNITY parameter");
        return;
    }
    communityLen = strlen(community) + 1;
    if (communityLen >= COMMUNITY_MAX_LEN) {
        config_perror("community name too long");
        return;
    }
    if (communityLen == sizeof(EXAMPLE_COMMUNITY) &&
        memcmp(community, EXAMPLE_COMMUNITY, sizeof(EXAMPLE_COMMUNITY)) == 0) {
        config_perror("example config COMMUNITY not properly configured");
        return;
    }

    /* Deal with the "default" case first. */
    if (strcmp(source, "default") == 0) {
        network.s_addr = 0;
        mask.s_addr = 0;
    } else {
        /* Split the source/netmask parts */
        char *strmask = strchr(source, '/');
        if (strmask != NULL)
            /* Mask given. */
            *strmask++ = '\0';

        /* Try interpreting as a dotted quad. */
        if (inet_pton(AF_INET, source, &network) == 0) {
            /* Nope, wasn't a dotted quad.  Must be a hostname. */
            int ret = netsnmp_gethostbyname_v4(source, &network.s_addr);
            if (ret < 0) {
                config_perror("cannot resolve source hostname");
                return;
            }
        }

        /* Now work out the mask. */
        if (strmask == NULL || *strmask == '\0') {
            /* No mask was given. Assume /32 */
            mask.s_addr = (in_addr_t)(~0UL);
        } else {
            /* Try to interpret mask as a "number of 1 bits". */
            char* cp;
            long maskLen = strtol(strmask, &cp, 10);
            if (*cp == '\0') {
                if (0 < maskLen && maskLen <= 32)
                    mask.s_addr = htonl((in_addr_t)(~0UL << (32 - maskLen)));
                else {
                    config_perror("bad mask length");
                    return;
                }
            }
            /* Try to interpret mask as a dotted quad. */
            else if (inet_pton(AF_INET, strmask, &mask) == 0) {
                config_perror("bad mask");
                return;
            }

            /* Check that the network and mask are consistent. */
            if (network.s_addr & ~mask.s_addr) {
                config_perror("source/mask mismatch");
                return;
            }
        }
    }

    {
        void* v = malloc(offsetof(com2SecEntry, community) + communityLen +
                         secNameLen + contextNameLen);

        com2SecEntry* e = (com2SecEntry*)v;
        char* last = ((char*)v) + offsetof(com2SecEntry, community);

        if (v == NULL) {
            config_perror("memory error");
            return;
        }

        /*
         * Everything is okay.  Copy the parameters to the structure allocated
         * above and add it to END of the list.
         */

        {
          char buf1[INET_ADDRSTRLEN];
          char buf2[INET_ADDRSTRLEN];
          DEBUGMSGTL(("netsnmp_udpns_parse_security",
                      "<\"%s\", %s/%s> => \"%s\"\n", community,
                      inet_ntop(AF_INET, &network, buf1, sizeof(buf1)),
                      inet_ntop(AF_INET, &mask, buf2, sizeof(buf2)),
                      secName));
        }

        memcpy(last, community, communityLen);
        last += communityLen;
        memcpy(last, secName, secNameLen);
        e->secName = last;
        last += secNameLen;
        if (contextNameLen) {
            memcpy(last, contextName, contextNameLen);
            e->contextName = last;
        } else
            e->contextName = last - 1;
        e->network = network.s_addr;
        e->mask = mask.s_addr;
        e->next = NULL;

        if (com2SecListLast != NULL) {
            com2SecListLast->next = e;
            com2SecListLast = e;
        } else {
            com2SecListLast = com2SecList = e;
        }
    }
}

void
netsnmp_udpns_com2SecList_free(void)
{
    com2SecEntry   *e = com2SecList;
    while (e != NULL) {
        com2SecEntry   *tmp = e;
        e = e->next;
        free(tmp);
    }
    com2SecList = com2SecListLast = NULL;
}
#endif /* support for community based SNMP */

void
netsnmp_udpns_agent_config_tokens_register(void)
{
#if !defined(NETSNMP_DISABLE_SNMPV1) || !defined(NETSNMP_DISABLE_SNMPV2C)
    register_app_config_handler("com2sec", netsnmp_udpns_parse_security,
                                netsnmp_udpns_com2SecList_free,
                                "[-Cn CONTEXT] secName IPv4-network-address[/netmask] community");
#endif /* support for community based SNMP */
}

netsnmp_transport *
netsnmp_udpns_create_tstring(const char *str, int local,
			   const char *default_target)
{
    struct sockaddr_in addr;
    char ns[NS_MAX_LENGTH];

    if (netsnmp_sockaddr_and_ns_in2(&addr, ns, str, default_target)) {
       return netsnmp_udpns_transport(&addr, ns, local);
    } else {
        return NULL;
    }
}

netsnmp_transport *
netsnmp_udpns_create_ostring(const u_char * o, size_t o_len, int local)
{
   DEBUGMSGTL(("netsnmp_udpns", "netsnmp_tcpns_create_ostring not implemented\n"));
   return NULL;
}

void
netsnmp_udpns_ctor(void)
{
    udpnsDomain.name = netsnmpUDPNSDomain;
    udpnsDomain.name_length = netsnmpUDPNSDomain_len;
    udpnsDomain.prefix = (const char**)calloc(2, sizeof(char *));
    udpnsDomain.prefix[0] = "udpns";

    udpnsDomain.f_create_from_tstring     = NULL;
    udpnsDomain.f_create_from_tstring_new = netsnmp_udpns_create_tstring;
    udpnsDomain.f_create_from_ostring     = netsnmp_udpns_create_ostring;

    netsnmp_tdomain_register(&udpnsDomain);
}
