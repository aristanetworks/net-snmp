// Copyright (c) 2012 Arista Networks, Inc.  All rights reserved.
// Arista Networks, Inc. Confidential and Proprietary.

#ifndef SNMPSOCKETNSDOMAIN_H
#define SNMPSOCKETNSDOMAIN_H

#ifdef __cplusplus
extern          "C" {
#endif

#define NS_MAX_LENGTH 150

/*
 * Prototypes
 */
    int netsnmp_open_namespace_socket(int domain, int type, int protocol,
                                      const char *destNs);

#ifdef __cplusplus
}
#endif

#endif // SNMPSOCKETNSDOMAIN_H
