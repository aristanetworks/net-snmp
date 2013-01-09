/*
 *   AgentX utility routines
 */

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-features.h>

#include <stdio.h>
#include <errno.h>
#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <sys/types.h>
#if TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# if HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif

#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>
#include <net-snmp/agent/agent_index.h>

#include "agentx/protocol.h"
#include "agentx/client.h"
#include "agentx/subagent.h"

struct reg_list {
    netsnmp_pdu *pdu;
    int reqid;
    struct reg_list *next;
};
typedef struct reg_list reg_list;

typedef struct {
    reg_list *pendingRegistrations;
    reg_list *pendingRegistrationsLast;
} agentx_data;

static agentx_data *
sess_agentx_data(netsnmp_session *ss)
{
    return (agentx_data *)ss->agentxData;
}

static void
sess_set_agentx_data(netsnmp_session *ss, agentx_data *data);

static void
sess_free_agentx_data(netsnmp_session *ss)
{
    DEBUGMSGTL(("agentx/subagent", "sess_free_agentx_data\n"));
    agentx_data *agentxData = sess_agentx_data(ss);
    if (agentxData) {
        reg_list *rp = agentxData->pendingRegistrations;
        while (rp) {
            reg_list *nrp = rp->next;
            /* The PDUs themselves are freed by snmp_sess_close. */
            free(rp);
            rp = nrp;
        }
        DEBUGMSGTL(("agentx/subagent", "free sess_free_agentx_data element\n"));
        free(agentxData);
        sess_set_agentx_data(ss, NULL);
    }
}

static void
sess_set_agentx_data(netsnmp_session *ss, agentx_data *data)
{
    DEBUGMSGTL(("agentx/subagent", "set_agentx_data\n"));
    if (data) {
        netsnmp_assert(!ss->agentxData);
    }
    ss->agentxData = data;
    ss->free_session_callback = &sess_free_agentx_data;
}

netsnmp_feature_require(set_agent_uptime)

        /*
         * AgentX handling utility routines
         *
         * Mostly wrappers round, or re-writes of
         *   the SNMP equivalents
         */

int
agentx_synch_input(int op,
                   netsnmp_session * session,
                   int reqid, netsnmp_pdu *pdu, void *magic)
{
    struct synch_state *state = (struct synch_state *) magic;

    if (!state || reqid != state->reqid) {
        if (!session->openReqPending) {
            return handle_agentx_packet(op, session, reqid, pdu, magic);
        } else {
           /* While awaiting a synchronous response for opening a session,
              we drop all packets. */
           DEBUGMSGTL(("agentx/subagent",
                       "Packet dropped while attempting to open session."));
           return 0;
        }
    }

    DEBUGMSGTL(("agentx/subagent", "synching input, op 0x%02x\n", op));
    state->waiting = 0;
    if (op == NETSNMP_CALLBACK_OP_RECEIVED_MESSAGE) {
        if (pdu->command == AGENTX_MSG_RESPONSE) {
            state->pdu = snmp_clone_pdu(pdu);
            state->status = STAT_SUCCESS;
            session->s_snmp_errno = SNMPERR_SUCCESS;

            /*
             * Synchronise sysUpTime with the master agent
             */
            netsnmp_set_agent_uptime(pdu->time);
        }
    } else if (op == NETSNMP_CALLBACK_OP_TIMED_OUT) {
        state->pdu = NULL;
        state->status = STAT_TIMEOUT;
        session->s_snmp_errno = SNMPERR_TIMEOUT;
    } else if (op == NETSNMP_CALLBACK_OP_DISCONNECT) {
        return handle_agentx_packet(op, session, reqid, pdu, magic);
    }

    return 1;
}



int
agentx_synch_response(netsnmp_session * ss, netsnmp_pdu *pdu,
                      netsnmp_pdu **response)
{
    return snmp_synch_response_cb(ss, pdu, response, agentx_synch_input);
}


        /*
         * AgentX PofE convenience functions
         */

int
agentx_open_session(netsnmp_session * ss)
{
    netsnmp_pdu    *pdu, *response;
    extern oid      version_sysoid[];
    extern int      version_sysoid_len;
    u_long 	    timeout;

    DEBUGMSGTL(("agentx/subagent", "opening session \n"));
    if (ss == NULL || !IS_AGENTX_VERSION(ss->version)) {
        return 0;
    }

    pdu = snmp_pdu_create(AGENTX_MSG_OPEN);
    if (pdu == NULL)
        return 0;
    timeout = netsnmp_ds_get_int(NETSNMP_DS_APPLICATION_ID,
                                   NETSNMP_DS_AGENT_AGENTX_TIMEOUT);
    if (timeout < 0) 
    pdu->time = 0;
    else
	/* for master TIMEOUT is usec, but Agentx Open specifies sec */
    	pdu->time = timeout/ONE_SEC;

    snmp_add_var(pdu, version_sysoid, version_sysoid_len,
		 's', "Net-SNMP AgentX sub-agent");

    ss->openReqPending = 1;
    int rc = agentx_synch_response(ss, pdu, &response);

    if (rc != STAT_SUCCESS)
        return 0;

    if (!response)
        return 0;

    if (response->errstat != SNMP_ERR_NOERROR) {
        snmp_free_pdu(response);
        return 0;
    }

    ss->sessid = response->sessid;
    snmp_free_pdu(response);

    /* Allocate list of pending registration requests. */
    agentx_data *agentxData = (agentx_data *) malloc(sizeof(agentx_data));
    if (agentxData) {
        agentxData->pendingRegistrations = NULL;
        agentxData->pendingRegistrationsLast = NULL;
        DEBUGMSGTL(("agentx/subagent", "allocating agentx_data\n"));
        sess_set_agentx_data(ss, agentxData);
    } else {
        DEBUGMSGTL(("agentx/subagent", "unable to allocate agentx_data\n"));
        return 0;
    }

    DEBUGMSGTL(("agentx/subagent", "open \n"));
    return 1;
}

int
agentx_close_session(netsnmp_session * ss, int why)
{
    netsnmp_pdu    *pdu;
    DEBUGMSGTL(("agentx/subagent", "closing session\n"));

    if (ss == NULL || !IS_AGENTX_VERSION(ss->version)) {
        return 0;
    }

    pdu = snmp_pdu_create(AGENTX_MSG_CLOSE);
    if (pdu == NULL)
        return 0;
    pdu->time = 0;
    pdu->errstat = why;
    pdu->sessid = ss->sessid;

    pdu->once = 1;
    snmp_send(ss, pdu);

    DEBUGMSGTL(("agentx/subagent", "closed\n"));

    return 1;
}

static void
agentx_data_remove_request(netsnmp_session * ss, int reqid)
{
    DEBUGMSGTL(("agentx/subagent", "agentx_data_remove_request\n"));
    agentx_data *agentxData = sess_agentx_data(ss);
    reg_list **rlp = &agentxData->pendingRegistrations;

    reg_list *prev = NULL;
    while (*rlp) {
        if ((*rlp)->reqid == reqid) {
            DEBUGMSGTL(("agentx/subagent",
                        "clearing pending register request %ld (pdu %p)\n",
                        reqid, (*rlp)->pdu));
            reg_list *tmp = *rlp;
            *rlp = (*rlp)->next;

            free(tmp);
            break;
        } else {
            prev = *rlp;
            rlp = &((*rlp)->next);
        }
    }

    agentxData->pendingRegistrationsLast = prev;
    if( agentxData->pendingRegistrations == NULL ) {
        netsnmp_assert( agentxData->pendingRegistrationsLast == NULL );
        DEBUGMSGTL(("agentx/subagent",
                    "all pending registrations cleared\n"));
    }
}

static int
agentx_register_request_callback(int op, netsnmp_session * ss, int reqid,
                                 netsnmp_pdu *pdu, void *magic)
{
    agentx_data *agentxData = sess_agentx_data(ss);
    reg_list *rp;

    if (!agentxData->pendingRegistrations) {
        DEBUGMSGTL(("agentx/subagent",
                    "All pending registrations have already been completed.\n"));
        return 1;
    }

    if (op == NETSNMP_CALLBACK_OP_RECEIVED_MESSAGE &&
        pdu->errstat == SNMP_ERR_NOERROR) {
        DEBUGMSGTL(("agentx/subagent", "register request %ld (pdu %p) succeeded\n",
                    reqid, magic));
        agentx_data_remove_request(ss, reqid);

        /*
         * Synchronise sysUpTime with the master agent
         */
        // See BUG46916
        // netsnmp_set_agent_uptime(pdu->time);

        ss->s_snmp_errno = SNMPERR_SUCCESS;
        return 1;
    } else if (op == NETSNMP_CALLBACK_OP_DISCONNECT) {
        ss->s_snmp_errno = SNMPERR_ABORT;
        agentx_data_remove_request(ss, reqid);
        return 1;
    } else if (op == NETSNMP_CALLBACK_OP_RECEIVED_MESSAGE) {
        DEBUGMSGTL(("agentx/subagent",
                    "register request %ld (pdu %p) got an error response: %d\n",
                    reqid, pdu, pdu->errstat));

        ss->s_snmp_errno = SNMPERR_GENERR;
        /* Original request succeded on the master agent side, but response timed out. */
        if (pdu->errstat == AGENTX_ERR_DUPLICATE_REGISTRATION) {
            DEBUGMSGTL(("agentx/subagent",
                        "AGENTX_ERR_DUPLICATE_REGISTRATION response\n",
                        reqid, pdu, pdu->errstat));
            agentx_data_remove_request(ss, reqid);
            return 1;
       }
    } else if (op == NETSNMP_CALLBACK_OP_TIMED_OUT) {
        ss->s_snmp_errno = SNMPERR_TIMEOUT;
        DEBUGMSGTL(("agentx/subagent",
                    "register request %d (pdu %p) timed out\n", reqid, pdu));
    } else {
        netsnmp_assert(!"unexpected callback operation");
        return 0;
    }

    /* Received timeout or error response. */
    for (rp = agentxData->pendingRegistrations; rp; rp = rp->next) {
        if (reqid == rp->reqid) {
            netsnmp_pdu *newpdu;
            DEBUGMSGTL(("agentx/subagent",
                        "failed registration was pending as %p\n", rp));

            /* _sess_process_packet will free the current PDU. */
            newpdu = snmp_clone_pdu(rp->pdu);
            if (newpdu) {
                newpdu->flags = rp->pdu->flags;
                newpdu->time = rp->pdu->time;
                newpdu->once = rp->pdu->once;
            } else {
                DEBUGMSGTL(("agentx/subagent", "unable to clone pdu\n"));
            }
            rp->pdu = newpdu;

            /* If the clone fails, the registration will be cleaned up by
               agentx_register_request_callback at the next successful registration (or
               when the session is closed). */

            /* reqid = 0 flags that the registration should be retried at the end of
               a ping request */
            rp->reqid = 0;
            break;
        }
    }

    return 1;
}

int
agentx_register(netsnmp_session * ss, oid start[], size_t startlen,
                int priority, int range_subid, oid range_ubound,
                int timeout, u_char flags, const char *contextName)
{
   netsnmp_pdu    *pdu;

    DEBUGMSGTL(("agentx/subagent", "registering: "));
    DEBUGMSGOIDRANGE(("agentx/subagent", start, startlen, range_subid,
                      range_ubound));
    DEBUGMSG(("agentx/subagent", "\n"));

    if (ss == NULL || !IS_AGENTX_VERSION(ss->version)) {
        return 0;
    }

    pdu = snmp_pdu_create(AGENTX_MSG_REGISTER);
    if (pdu == NULL) {
        return 0;
    }

    pdu->time = 0;
    pdu->flags &= ~(UCD_MSG_FLAG_PDU_TIMEOUT);
    pdu->once = 1;

    pdu->priority = priority;
    pdu->sessid = ss->sessid;
    pdu->range_subid = range_subid;
    if (contextName) {
        pdu->flags |= AGENTX_MSG_FLAG_NON_DEFAULT_CONTEXT;
        pdu->community = (u_char *) strdup(contextName);
        pdu->community_len = strlen(contextName);
    }

    if (flags & FULLY_QUALIFIED_INSTANCE) {
        pdu->flags |= AGENTX_MSG_FLAG_INSTANCE_REGISTER;
    }

    if (range_subid) {
        snmp_pdu_add_variable(pdu, start, startlen, ASN_OBJECT_ID,
                              (u_char *) start, startlen * sizeof(oid));
        pdu->variables->val.objid[range_subid - 1] = range_ubound;
    } else {
        snmp_add_null_var(pdu, start, startlen);
    }

    int reqid = snmp_async_send(ss, pdu, agentx_register_request_callback, pdu);
    if (reqid) {
        DEBUGMSGTL(("agentx/subagent", "register request %ld (pdu %p) successfully sent\n",
                    reqid, pdu));

        agentx_data *agentxData = sess_agentx_data(ss);
        reg_list *rp = (reg_list *) malloc(sizeof(reg_list));

        if (!rp) {
            /* Continue in case the registration still succeeds. */
           DEBUGMSGTL(("agentx/subagent",
                       "failed to record pending registration\n"));
            return 1;
        }

        rp->pdu = pdu;
        rp->reqid = reqid;
        rp->next = NULL;

       if (!agentxData->pendingRegistrations) {
           agentxData->pendingRegistrations = rp;
        } else {
           netsnmp_assert(agentxData->pendingRegistrationsLast);
           agentxData->pendingRegistrationsLast->next = rp;
        }
        agentxData->pendingRegistrationsLast = rp;

        return 1;
    } else {
        DEBUGMSGTL(("agentx/subagent", "failed to send register pdu %p\n",
                    pdu));
        snmp_free_pdu(pdu);
        return 0;
    }
}

int
agentx_unregister(netsnmp_session * ss, oid start[], size_t startlen,
                  int priority, int range_subid, oid range_ubound,
                  const char *contextName)
{
    netsnmp_pdu    *pdu, *response;

    if (ss == NULL || !IS_AGENTX_VERSION(ss->version)) {
        return 0;
    }

    DEBUGMSGTL(("agentx/subagent", "unregistering: "));
    DEBUGMSGOIDRANGE(("agentx/subagent", start, startlen, range_subid,
                      range_ubound));
    DEBUGMSG(("agentx/subagent", "\n"));
    pdu = snmp_pdu_create(AGENTX_MSG_UNREGISTER);
    if (pdu == NULL) {
        return 0;
    }
    pdu->time = 0;
    pdu->priority = priority;
    pdu->sessid = ss->sessid;
    pdu->range_subid = range_subid;
    if (contextName) {
        pdu->flags |= AGENTX_MSG_FLAG_NON_DEFAULT_CONTEXT;
        pdu->community = (u_char *) strdup(contextName);
        pdu->community_len = strlen(contextName);
    }

    if (range_subid) {
        snmp_pdu_add_variable(pdu, start, startlen, ASN_OBJECT_ID,
                              (u_char *) start, startlen * sizeof(oid));
        pdu->variables->val.objid[range_subid - 1] = range_ubound;
    } else {
        snmp_add_null_var(pdu, start, startlen);
    }

    if (agentx_synch_response(ss, pdu, &response) != STAT_SUCCESS)
        return 0;

    if (response->errstat != SNMP_ERR_NOERROR) {
        snmp_free_pdu(response);
        return 0;
    }

    snmp_free_pdu(response);
    DEBUGMSGTL(("agentx/subagent", "unregistered\n"));
    return 1;
}

netsnmp_variable_list *
agentx_register_index(netsnmp_session * ss,
                      netsnmp_variable_list * varbind, int flags)
{
    netsnmp_pdu    *pdu, *response;
    netsnmp_variable_list *varbind2;

    if (ss == NULL || !IS_AGENTX_VERSION(ss->version)) {
        return NULL;
    }

    /*
     * Make a copy of the index request varbind
     *    for the AgentX request PDU
     *    (since the pdu structure will be freed)
     */
    varbind2 =
        (netsnmp_variable_list *) malloc(sizeof(netsnmp_variable_list));
    if (varbind2 == NULL)
        return NULL;
    if (snmp_clone_var(varbind, varbind2)) {
        snmp_free_varbind(varbind2);
        return NULL;
    }
    if (varbind2->val.string == NULL)
        varbind2->val.string = varbind2->buf;   /* ensure it points somewhere */

    pdu = snmp_pdu_create(AGENTX_MSG_INDEX_ALLOCATE);
    if (pdu == NULL) {
        snmp_free_varbind(varbind2);
        return NULL;
    }
    pdu->time = 0;
    pdu->sessid = ss->sessid;
    if (flags == ALLOCATE_ANY_INDEX)
        pdu->flags |= AGENTX_MSG_FLAG_ANY_INSTANCE;
    if (flags == ALLOCATE_NEW_INDEX)
        pdu->flags |= AGENTX_MSG_FLAG_NEW_INSTANCE;

    /*
     *  Just send a single index request varbind.
     *  Although the AgentX protocol supports
     *    multiple index allocations in a single
     *    request, the model used in the net-snmp agent
     *    doesn't currently take advantage of this.
     *  I believe this is our prerogative - just as
     *    long as the master side Index request handler
     *    can cope with multiple index requests.
     */
    pdu->variables = varbind2;

    if (agentx_synch_response(ss, pdu, &response) != STAT_SUCCESS)
        return NULL;

    if (response->errstat != SNMP_ERR_NOERROR) {
        snmp_free_pdu(response);
        return NULL;
    }

    /*
     * Unlink the (single) response varbind to return
     *  to the main driving index request routine.
     *
     * This is a memory leak, as nothing will ever
     *  release this varbind.  If this becomes a problem,
     *  we'll need to keep a list of these here, and
     *  free the memory in the "index release" routine.
     * But the master side never frees these either (by
     *  design, since it still needs them), so expecting
     *  the subagent to is discrimination, pure & simple :-)
     */
    varbind2 = response->variables;
    response->variables = NULL;
    snmp_free_pdu(response);
    return varbind2;
}

int
agentx_unregister_index(netsnmp_session * ss,
                        netsnmp_variable_list * varbind)
{
    netsnmp_pdu    *pdu, *response;
    netsnmp_variable_list *varbind2;

    if (ss == NULL || !IS_AGENTX_VERSION(ss->version)) {
        return -1;
    }

    /*
     * Make a copy of the index request varbind
     *    for the AgentX request PDU
     *    (since the pdu structure will be freed)
     */
    varbind2 =
        (netsnmp_variable_list *) malloc(sizeof(netsnmp_variable_list));
    if (varbind2 == NULL)
        return -1;
    if (snmp_clone_var(varbind, varbind2)) {
        snmp_free_varbind(varbind2);
        return -1;
    }

    pdu = snmp_pdu_create(AGENTX_MSG_INDEX_DEALLOCATE);
    if (pdu == NULL) {
        snmp_free_varbind(varbind2);
        return -1;
    }
    pdu->time = 0;
    pdu->sessid = ss->sessid;

    /*
     *  Just send a single index release varbind.
     *      (as above)
     */
    pdu->variables = varbind2;

    if (agentx_synch_response(ss, pdu, &response) != STAT_SUCCESS)
        return -1;

    if (response->errstat != SNMP_ERR_NOERROR) {
        snmp_free_pdu(response);
        return -1;              /* XXX - say why */
    }

    snmp_free_pdu(response);
    return SNMP_ERR_NOERROR;
}

int
agentx_add_agentcaps(netsnmp_session * ss,
                     const oid * agent_cap, size_t agent_caplen,
                     const char *descr)
{
    netsnmp_pdu    *pdu, *response;

    if (ss == NULL || !IS_AGENTX_VERSION(ss->version)) {
        return 0;
    }

    pdu = snmp_pdu_create(AGENTX_MSG_ADD_AGENT_CAPS);
    if (pdu == NULL)
        return 0;
    pdu->time = 0;
    pdu->sessid = ss->sessid;
    snmp_add_var(pdu, agent_cap, agent_caplen, 's', descr);

    if (agentx_synch_response(ss, pdu, &response) != STAT_SUCCESS)
        return 0;

    if (response->errstat != SNMP_ERR_NOERROR) {
        snmp_free_pdu(response);
        return 0;
    }

    snmp_free_pdu(response);
    return 1;
}

int
agentx_remove_agentcaps(netsnmp_session * ss,
                        const oid * agent_cap, size_t agent_caplen)
{
    netsnmp_pdu    *pdu, *response;

    if (ss == NULL || !IS_AGENTX_VERSION(ss->version)) {
        return 0;
    }

    pdu = snmp_pdu_create(AGENTX_MSG_REMOVE_AGENT_CAPS);
    if (pdu == NULL)
        return 0;
    pdu->time = 0;
    pdu->sessid = ss->sessid;
    snmp_add_null_var(pdu, agent_cap, agent_caplen);

    if (agentx_synch_response(ss, pdu, &response) != STAT_SUCCESS)
        return 0;

    if (response->errstat != SNMP_ERR_NOERROR) {
        snmp_free_pdu(response);
        return 0;
    }

    snmp_free_pdu(response);
    return 1;
}

int
agentx_send_ping(netsnmp_session * ss, snmp_callback callback, void *cb_data)
{
   netsnmp_pdu    *pdu;

    if (ss == NULL) {
       snmp_log(LOG_WARNING,
                "netsnmp_session is NULL\n");
       return 0;
    }

    if (!IS_AGENTX_VERSION(ss->version)) {
        snmp_log(LOG_WARNING,
                 "erroneous session version: %ld\n",
                 ss->version);
        return 0;
    }

    pdu = snmp_pdu_create(AGENTX_MSG_PING);
    if (pdu == NULL) {
       snmp_log(LOG_WARNING,
                "snmp_pdu_create(AGENTX_MSG_PING) returned NULL\n");
       return 0;
    }
    pdu->time = 0;
    pdu->flags &= ~(UCD_MSG_FLAG_PDU_TIMEOUT);
    pdu->sessid = ss->sessid;
    pdu->once = 1;

    int reqid = snmp_async_send(ss, pdu, callback, cb_data);
    return reqid != 0;
}

void
agentx_ping_succeeded(netsnmp_session * ss)
{
    agentx_data *agentxData = sess_agentx_data(ss);

    reg_list **rlp = &agentxData->pendingRegistrations;
    reg_list *prev = NULL;

    while (*rlp) {
        if ((*rlp)->reqid == 0) {
            if (!(*rlp)->pdu) {
                DEBUGMSGTL(("agentx/subagent",
                            "clearing pending register request %ld because pdu is NULL\n",
                            (*rlp)->reqid));
                reg_list *tmp = *rlp;
                *rlp = (*rlp)->next;
                free(tmp);
            } else {
                netsnmp_pdu *pdu = (*rlp)->pdu;

                int reqid = snmp_async_send(ss, pdu, agentx_register_request_callback, pdu);
                if (reqid) {
                    DEBUGMSGTL(("agentx/subagent", "resent register request %d, pdu %p\n",
                                reqid, pdu));
                } else {
                    DEBUGMSGTL(("agentx/subagent", "failed to resend register pdu\n"));
                }

                (*rlp)->reqid = reqid;

                prev = *rlp;
                rlp = &((*rlp)->next);
            }
        }
    }

    agentxData->pendingRegistrationsLast = prev;
    if( agentxData->pendingRegistrations == NULL ) {
        netsnmp_assert( agentxData->pendingRegistrationsLast == NULL );
        DEBUGMSGTL(("agentx/subagent",
                    "all pending registrations cleared\n"));
    }
}
