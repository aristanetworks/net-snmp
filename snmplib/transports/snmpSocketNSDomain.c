// Copyright (c) 2012 Arista Networks, Inc.  All rights reserved.
// Arista Networks, Inc. Confidential and Proprietary.

/* UDPNS/TCPNS transport support functions
 */

#include <sys/socket.h>
#include <signal.h>
#include <limits.h>
#include <errno.h>
#include <fcntl.h>

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/types.h>
#include <net-snmp/output_api.h>

#include <net-snmp/library/snmpSocketNSDomain.h>

#ifdef __i386__
#define __NR_setns 346
#else
#define __NR_setns 308
#endif
#ifndef CLONE_NEWNET
#define CLONE_NEWNET 0x40000000    /* New network namespace (lo, device,
                                      names sockets, etc) */
#endif

const char *PROC_SELF_NS_NET_FILE = "/proc/self/ns/net";
const char *NETNS_RUN_DIR = "/var/run/netns";

/**
 * Moves execution to another namespace.
 *
 * @param[in] name       Kernel name of the namespace.
 *
 * @return zero upon success and -1 upon error.
 */
int
netsnmp_set_namespace( const char *name )
{
   DEBUGMSGTL(("netsnmp_set_namespace", "Namespace: %s", name ));
   char net_path[PATH_MAX];
   int netns;

   snprintf(net_path, sizeof(net_path), "%s/%s", NETNS_RUN_DIR, name);
   netns = open(net_path, O_RDONLY);
   if ( netns < 0 ) {
      DEBUGMSGTL(("netsnmp_set_namespace", "Cannot open: %s. Error: %s",
                  net_path, strerror(errno)));
      return -1;
   }
   if (syscall(__NR_setns, netns, CLONE_NEWNET) < 0) {
      DEBUGMSGTL(("netsnmp_set_namespace", "Cannot set namespace: %s. Error: %s",
                  net_path, strerror(errno)));
      close(netns);
      return -1;
   }
   close(netns);
   return 0;
}

/**
 * Opens a socket in non-default namespace.
 *
 * @param[in] domain      Communication domain.
 * @param[in] type        Type of socket.
 * @param[in] protocol    Protocol to be used with the socket.
 * @param[in] destNs      The namespace in which to open the socket.
 *
 * @return zero upon success and -1 upon error.
 */
int
netsnmp_open_namespace_socket(int domain, int type, int protocol,
                              const char *destNs)
{
   int rc = 0, fd = -1;
   sigset_t set, oset;
   struct stat stat_buf;
   int inode1 = 0, inode2 = -1;
   int curr_netns_fd = -1;

   // Get the NSid for current NS
   if (stat(PROC_SELF_NS_NET_FILE, &stat_buf) == -1) {
      DEBUGMSGTL(("netsnmp_open_namespace_socket", "stat %s failed: %s",
                  PROC_SELF_NS_NET_FILE, strerror(errno)));
   } else {
      inode1 = stat_buf.st_ino;
   }

   // Get a fd to the current NS
   curr_netns_fd = open(PROC_SELF_NS_NET_FILE, O_RDONLY);
   if (curr_netns_fd < 0) {
      DEBUGMSGTL(("netsnmp_open_namespace_socket: Cannot open: %s. Error: %s",
                  PROC_SELF_NS_NET_FILE, strerror(errno)));
      return -1;
   }

   //Block all signals
   sigfillset(&set);
   sigprocmask(SIG_BLOCK, &set, &oset);

   rc = netsnmp_set_namespace(destNs);
   if (rc != 0) {
      goto netsnmp_open_namespace_socket_error;
   }

   // Get the NSid for new NS
   if (stat( PROC_SELF_NS_NET_FILE, &stat_buf) == -1) {
      DEBUGMSGTL(("netsnmp_open_namespace_socket", "stat %s failed: %s",
                  PROC_SELF_NS_NET_FILE, strerror(errno)));
   } else {
      inode2 = stat_buf.st_ino;
      //assert(inode1 != inode2);
   }

   fd = socket(domain, type, protocol);
   if (fd == -1) {
      DEBUGMSGTL(("netsnmp_open_namespace_socket", "socket failed %s",
                  strerror(errno)));
      rc = -1;
      goto netsnmp_open_namespace_socket_error;
   }

   if (syscall(__NR_setns, curr_netns_fd, CLONE_NEWNET) < 0) {
      DEBUGMSGTL(("netsnmp_open_namespace_socket",
                  "Cannot set namespace: %s. Error: %s",
                  PROC_SELF_NS_NET_FILE, strerror(errno)));
      goto netsnmp_open_namespace_socket_error;
   }
   close(curr_netns_fd);

   // Get the NSid again
   if (stat(PROC_SELF_NS_NET_FILE, &stat_buf) == -1) {
      DEBUGMSGTL(("netsnmp_open_namespace_socket", "stat %s failed: %s",
                  PROC_SELF_NS_NET_FILE, strerror(errno)));
   } else {
      inode2 = stat_buf.st_ino;
   }
   sigprocmask(SIG_SETMASK, &oset, NULL);
   return fd;

  netsnmp_open_namespace_socket_error:
   if (curr_netns_fd != -1) {
      close(curr_netns_fd);
   }
   if (fd != -1) {
      close(fd);
   }
   //Restore the signal handling
   sigprocmask(SIG_SETMASK, &oset, NULL);
   return rc;
}
