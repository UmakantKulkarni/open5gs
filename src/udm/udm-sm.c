/*
 * Copyright (C) 2019-2024 by Sukchan Lee <acetcom@gmail.com>
 *
 * This file is part of Open5GS.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include "sbi-path.h"
#include "nnrf-handler.h"

void udm_state_initial(ogs_fsm_t *s, udm_event_t *e)
{
    udm_sm_debug(e);

    ogs_assert(s);

    OGS_FSM_TRAN(s, &udm_state_operational);
}

void udm_state_final(ogs_fsm_t *s, udm_event_t *e)
{
    udm_sm_debug(e);
}

void udm_state_operational(ogs_fsm_t *s, udm_event_t *e)
{
    ogs_info("PCS UDM ogs_queue_size is %d",ogs_queue_size(ogs_app()->queue));
    int rv;
    const char *api_version = NULL;

    ogs_sbi_stream_t *stream = NULL;
    ogs_pool_id_t stream_id = OGS_INVALID_POOL_ID;
    ogs_sbi_request_t *request = NULL;

    ogs_sbi_nf_instance_t *nf_instance = NULL;
    ogs_sbi_subscription_data_t *subscription_data = NULL;
    ogs_sbi_response_t *response = NULL;
    ogs_sbi_message_t message;
    ogs_sbi_xact_t *sbi_xact = NULL;
    ogs_pool_id_t sbi_xact_id = OGS_INVALID_POOL_ID;

    udm_ue_t *udm_ue = NULL;
    ogs_pool_id_t udm_ue_id = OGS_INVALID_POOL_ID;
    udm_sess_t *sess = NULL;
    ogs_pool_id_t sess_id = OGS_INVALID_POOL_ID;

    udm_sm_debug(e);

    ogs_assert(s);

    switch (e->h.id) {
    case OGS_FSM_ENTRY_SIG:
        break;

    case OGS_FSM_EXIT_SIG:
        break;

    case OGS_EVENT_SBI_SERVER:
        request = e->h.sbi.request;
        ogs_assert(request);

        stream_id = OGS_POINTER_TO_UINT(e->h.sbi.data);
        ogs_assert(stream_id >= OGS_MIN_POOL_ID &&
                stream_id <= OGS_MAX_POOL_ID);

        stream = ogs_sbi_stream_find_by_id(stream_id);
        if (!stream) {
            ogs_error("STREAM has already been removed [%d]", stream_id);
            break;
        }

        rv = ogs_sbi_parse_request(&message, request);
        if (rv != OGS_OK) {
            /* 'message' buffer is released in ogs_sbi_parse_request() */
            ogs_error("cannot parse HTTP message");
            ogs_assert(true ==
                ogs_sbi_server_send_error(
                    stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                    NULL, "cannot parse HTTP message", NULL, NULL));
            break;
        }

        SWITCH(message.h.service.name)
        CASE(OGS_SBI_SERVICE_NAME_NUDM_SDM)
            api_version = OGS_SBI_API_V2;
            break;
        DEFAULT
            api_version = OGS_SBI_API_V1;
        END

        if (strcmp(message.h.api.version, api_version) != 0) {
            ogs_error("Not supported version [%s]", message.h.api.version);
            ogs_assert(true ==
                ogs_sbi_server_send_error(
                    stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                    &message, "Not supported version", NULL, NULL));
            ogs_sbi_message_free(&message);
            break;
        }

        SWITCH(message.h.service.name)
        CASE(OGS_SBI_SERVICE_NAME_NNRF_NFM)

            SWITCH(message.h.resource.component[0])
            CASE(OGS_SBI_RESOURCE_NAME_NF_STATUS_NOTIFY)
                SWITCH(message.h.method)
                CASE(OGS_SBI_HTTP_METHOD_POST)
                    ogs_nnrf_nfm_handle_nf_status_notify(stream, &message);
                    break;

                DEFAULT
                    ogs_error("Invalid HTTP method [%s]",
                            message.h.method);
                    ogs_assert(true ==
                        ogs_sbi_server_send_error(stream,
                            OGS_SBI_HTTP_STATUS_FORBIDDEN, &message,
                            "Invalid HTTP method", message.h.method,
                            NULL));
                END
                break;

            DEFAULT
                ogs_error("Invalid resource name [%s]",
                        message.h.resource.component[0]);
                ogs_assert(true ==
                    ogs_sbi_server_send_error(stream,
                        OGS_SBI_HTTP_STATUS_BAD_REQUEST, &message,
                        "Unknown resource name",
                        message.h.resource.component[0], NULL));
            END
            break;

        CASE(OGS_SBI_SERVICE_NAME_NUDM_UEAU)
        CASE(OGS_SBI_SERVICE_NAME_NUDM_UECM)
        CASE(OGS_SBI_SERVICE_NAME_NUDM_SDM)
            if (!message.h.resource.component[0]) {
                ogs_error("Not found [%s]", message.h.method);
                ogs_assert(true ==
                    ogs_sbi_server_send_error(stream,
                        OGS_SBI_HTTP_STATUS_NOT_FOUND,
                        &message, "Not found", message.h.method, NULL));
                break;
            }

            if (!message.h.resource.component[1]) {
                ogs_error("Invalid resource name [%s]", message.h.method);
                ogs_assert(true ==
                    ogs_sbi_server_send_error(stream,
                        OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                        &message, "Invalid resource name", message.h.method,
                        NULL));
                break;
            }

            SWITCH(message.h.resource.component[1])
            CASE(OGS_SBI_RESOURCE_NAME_AUTH_EVENTS)
                if (message.h.resource.component[2]) {
                    udm_ue = udm_ue_find_by_ctx_id(
                            message.h.resource.component[2]);
                }
            DEFAULT
            END

            if (!udm_ue) {
                udm_ue = udm_ue_find_by_suci_or_supi(
                        message.h.resource.component[0]);
                if (!udm_ue) {
                    if (!strcmp(message.h.method,
                                OGS_SBI_HTTP_METHOD_POST)) {
                        udm_ue = udm_ue_add(message.h.resource.component[0]);
                        if (!udm_ue) {
                            ogs_error("Invalid Request [%s]",
                                    message.h.resource.component[0]);
                        }
                    } else {
                        ogs_error("Invalid HTTP method [%s]", message.h.method);
                    }
                }
            }

            if (!udm_ue) {
                ogs_error("Not found [%s]", message.h.method);
                ogs_assert(true ==
                    ogs_sbi_server_send_error(stream,
                        OGS_SBI_HTTP_STATUS_NOT_FOUND,
                        &message, "Not found", message.h.method, NULL));
                break;
            }

            SWITCH(message.h.resource.component[2])
            CASE(OGS_SBI_RESOURCE_NAME_SMF_REGISTRATIONS)
                if (message.h.resource.component[3]) {
                    uint8_t psi = atoi(message.h.resource.component[3]);

                    sess = udm_sess_find_by_psi(udm_ue, psi);
                    if (!sess) {
                        sess = udm_sess_add(udm_ue, psi);
                        ogs_assert(sess);
                        ogs_debug("[%s:%d] UDM session added",
                                udm_ue->supi, sess->psi);
                    }
                }

                ogs_assert(sess);
                ogs_assert(OGS_FSM_STATE(&sess->sm));

                e->sess_id = sess->id;
                e->h.sbi.message = &message;
                ogs_fsm_dispatch(&sess->sm, e);
                if (OGS_FSM_CHECK(&sess->sm, udm_sess_state_exception)) {
                    ogs_error("[%s:%d] State machine exception",
                            udm_ue->suci, sess->psi);
                    udm_sess_remove(sess);
                }
                break;

            DEFAULT
                ogs_assert(OGS_FSM_STATE(&udm_ue->sm));

                e->udm_ue_id = udm_ue->id;
                e->h.sbi.message = &message;
                ogs_fsm_dispatch(&udm_ue->sm, e);
                if (OGS_FSM_CHECK(&udm_ue->sm, udm_ue_state_exception)) {
                    ogs_error("[%s] State machine exception", udm_ue->suci);
                    udm_ue_remove(udm_ue);
                }
            END
            break;

        DEFAULT
            ogs_error("Invalid API name [%s]", message.h.service.name);
            ogs_assert(true ==
                ogs_sbi_server_send_error(stream,
                    OGS_SBI_HTTP_STATUS_BAD_REQUEST, &message,
                    "Invalid API name", message.h.service.name, NULL));
        END

        /* In lib/sbi/server.c, notify_completed() releases 'request' buffer. */
        ogs_sbi_message_free(&message);
        break;

    case OGS_EVENT_SBI_CLIENT:
        ogs_assert(e);

        response = e->h.sbi.response;
        ogs_assert(response);
        rv = ogs_sbi_parse_response(&message, response);
        if (rv != OGS_OK) {
            ogs_error("cannot parse HTTP response");
            ogs_sbi_message_free(&message);
            ogs_sbi_response_free(response);
            break;
        }

        SWITCH(message.h.service.name)
        CASE(OGS_SBI_SERVICE_NAME_NUDM_SDM)
            api_version = OGS_SBI_API_V2;
            break;
        DEFAULT
            api_version = OGS_SBI_API_V1;
        END

        if (strcmp(message.h.api.version, api_version) != 0) {
            ogs_error("Not supported version [%s]", message.h.api.version);
            ogs_sbi_message_free(&message);
            ogs_sbi_response_free(response);
            break;
        }

        SWITCH(message.h.service.name)
        CASE(OGS_SBI_SERVICE_NAME_NNRF_NFM)

            SWITCH(message.h.resource.component[0])
            CASE(OGS_SBI_RESOURCE_NAME_NF_INSTANCES)
                nf_instance = e->h.sbi.data;
                ogs_assert(nf_instance);
                ogs_assert(OGS_FSM_STATE(&nf_instance->sm));

                e->h.sbi.message = &message;
                ogs_fsm_dispatch(&nf_instance->sm, e);
                break;

            CASE(OGS_SBI_RESOURCE_NAME_SUBSCRIPTIONS)
                subscription_data = e->h.sbi.data;
                ogs_assert(subscription_data);

                SWITCH(message.h.method)
                CASE(OGS_SBI_HTTP_METHOD_POST)
                    if (message.res_status == OGS_SBI_HTTP_STATUS_CREATED ||
                        message.res_status == OGS_SBI_HTTP_STATUS_OK) {
                        ogs_nnrf_nfm_handle_nf_status_subscribe(
                                subscription_data, &message);
                    } else {
                        ogs_error("HTTP response error : %d",
                                message.res_status);
                    }
                    break;

                CASE(OGS_SBI_HTTP_METHOD_PATCH)
                    if (message.res_status == OGS_SBI_HTTP_STATUS_OK ||
                        message.res_status == OGS_SBI_HTTP_STATUS_NO_CONTENT) {
                        ogs_nnrf_nfm_handle_nf_status_update(
                                subscription_data, &message);
                    } else {
                        ogs_error("[%s] HTTP response error [%d]",
                                subscription_data->id ?
                                    subscription_data->id : "Unknown",
                                message.res_status);
                    }
                    break;

                CASE(OGS_SBI_HTTP_METHOD_DELETE)
                    if (message.res_status ==
                            OGS_SBI_HTTP_STATUS_NO_CONTENT) {
                        ogs_sbi_subscription_data_remove(subscription_data);
                    } else {
                        ogs_error("[%s] HTTP response error [%d]",
                                subscription_data->id ?
                                    subscription_data->id : "Unknown",
                                message.res_status);
                    }
                    break;

                DEFAULT
                    ogs_error("[%s] Invalid HTTP method [%s]",
                            subscription_data->id, message.h.method);
                    ogs_assert_if_reached();
                END
                break;
            
            DEFAULT
                ogs_error("Invalid resource name [%s]",
                        message.h.resource.component[0]);
                ogs_assert_if_reached();
            END
            break;

        CASE(OGS_SBI_SERVICE_NAME_NNRF_DISC)
            SWITCH(message.h.resource.component[0])
            CASE(OGS_SBI_RESOURCE_NAME_NF_INSTANCES)
                sbi_xact_id = OGS_POINTER_TO_UINT(e->h.sbi.data);
                ogs_assert(sbi_xact_id >= OGS_MIN_POOL_ID &&
                        sbi_xact_id <= OGS_MAX_POOL_ID);

                sbi_xact = ogs_sbi_xact_find_by_id(sbi_xact_id);
                if (!sbi_xact) {
                    /* CLIENT_WAIT timer could remove SBI transaction
                     * before receiving SBI message */
                    ogs_error("SBI transaction has already been removed [%d]",
                            sbi_xact_id);
                    break;
                }

                SWITCH(message.h.method)
                CASE(OGS_SBI_HTTP_METHOD_GET)
                    if (message.res_status == OGS_SBI_HTTP_STATUS_OK)
                        udm_nnrf_handle_nf_discover(sbi_xact, &message);
                    else
                        ogs_error("HTTP response error [%d]",
                                message.res_status);
                    break;

                DEFAULT
                    ogs_error("Invalid HTTP method [%s]", message.h.method);
                    ogs_assert_if_reached();
                END
                break;

            DEFAULT
                ogs_error("Invalid resource name [%s]",
                        message.h.resource.component[0]);
                ogs_assert_if_reached();
            END
            break;

        CASE(OGS_SBI_SERVICE_NAME_NUDR_DR)
            SWITCH(message.h.resource.component[0])
            CASE(OGS_SBI_RESOURCE_NAME_SUBSCRIPTION_DATA)
                SWITCH(message.h.resource.component[3])
                CASE(OGS_SBI_RESOURCE_NAME_SMF_REGISTRATIONS)
                    sbi_xact_id = OGS_POINTER_TO_UINT(e->h.sbi.data);
                    ogs_assert(sbi_xact_id >= OGS_MIN_POOL_ID &&
                            sbi_xact_id <= OGS_MAX_POOL_ID);

                    sbi_xact = ogs_sbi_xact_find_by_id(sbi_xact_id);
                    if (!sbi_xact) {
                        /* CLIENT_WAIT timer could remove SBI transaction
                         * before receiving SBI message */
                        ogs_error(
                                "SBI transaction has already been removed [%d]",
                                sbi_xact_id);
                        break;
                    }

                    sess_id = sbi_xact->sbi_object_id;
                    ogs_assert(sess_id >= OGS_MIN_POOL_ID &&
                            sess_id <= OGS_MAX_POOL_ID);

                    if (sbi_xact->assoc_stream_id >= OGS_MIN_POOL_ID &&
                        sbi_xact->assoc_stream_id <= OGS_MAX_POOL_ID)
                        e->h.sbi.data =
                            OGS_UINT_TO_POINTER(sbi_xact->assoc_stream_id);

                    ogs_sbi_xact_remove(sbi_xact);

                    sess = udm_sess_find_by_id(sess_id);
                    if (!sess) {
                        ogs_error("SESS Context has already been removed");
                        break;
                    }

                    udm_ue = udm_ue_find_by_id(sess->udm_ue_id);
                    if (!udm_ue) {
                        ogs_error("UE Context has already been removed");
                        break;
                    }

                    e->sess_id = sess->id;
                    e->h.sbi.message = &message;

                    ogs_fsm_dispatch(&sess->sm, e);
                    if (OGS_FSM_CHECK(&sess->sm, udm_sess_state_exception)) {
                        ogs_error("[%s:%d] State machine exception",
                                udm_ue->suci, sess->psi);
                        udm_sess_remove(sess);
                    }
                    break;

                DEFAULT
                    sbi_xact_id = OGS_POINTER_TO_UINT(e->h.sbi.data);
                    ogs_assert(sbi_xact_id >= OGS_MIN_POOL_ID &&
                            sbi_xact_id <= OGS_MAX_POOL_ID);

                    sbi_xact = ogs_sbi_xact_find_by_id(sbi_xact_id);
                    if (!sbi_xact) {
                        /* CLIENT_WAIT timer could remove SBI transaction
                         * before receiving SBI message */
                        ogs_error(
                                "SBI transaction has already been removed [%d]",
                                sbi_xact_id);
                        break;
                    }

                    udm_ue_id = sbi_xact->sbi_object_id;
                    ogs_assert(udm_ue_id >= OGS_MIN_POOL_ID &&
                            udm_ue_id <= OGS_MAX_POOL_ID);

                    if (sbi_xact->assoc_stream_id >= OGS_MIN_POOL_ID &&
                        sbi_xact->assoc_stream_id <= OGS_MAX_POOL_ID)
                        e->h.sbi.data =
                            OGS_UINT_TO_POINTER(sbi_xact->assoc_stream_id);

                    ogs_sbi_xact_remove(sbi_xact);

                    udm_ue = udm_ue_find_by_id(udm_ue_id);
                    if (!udm_ue) {
                        ogs_error("UE Context has already been removed");
                        break;
                    }

                    e->udm_ue_id = udm_ue->id;
                    e->h.sbi.message = &message;

                    ogs_fsm_dispatch(&udm_ue->sm, e);
                    if (OGS_FSM_CHECK(&udm_ue->sm, udm_ue_state_exception)) {
                        ogs_error("[%s] State machine exception", udm_ue->suci);
                        udm_ue_remove(udm_ue);
                    }
                END
                break;

            DEFAULT
                ogs_error("Invalid resource name [%s]",
                        message.h.resource.component[0]);
                ogs_assert_if_reached();
            END
            break;

        DEFAULT
            ogs_error("Invalid API name [%s]", message.h.service.name);
            ogs_assert_if_reached();
        END

        ogs_sbi_message_free(&message);
        ogs_sbi_response_free(response);
        break;

    case OGS_EVENT_SBI_TIMER:
        ogs_assert(e);

        switch(e->h.timer_id) {
        case OGS_TIMER_NF_INSTANCE_REGISTRATION_INTERVAL:
        case OGS_TIMER_NF_INSTANCE_HEARTBEAT_INTERVAL:
        case OGS_TIMER_NF_INSTANCE_NO_HEARTBEAT:
        case OGS_TIMER_NF_INSTANCE_VALIDITY:
            nf_instance = e->h.sbi.data;
            ogs_assert(nf_instance);
            ogs_assert(OGS_FSM_STATE(&nf_instance->sm));

            ogs_sbi_self()->nf_instance->load = get_ue_load();

            ogs_fsm_dispatch(&nf_instance->sm, e);
            if (OGS_FSM_CHECK(&nf_instance->sm, ogs_sbi_nf_state_exception))
                ogs_error("[%s:%s] State machine exception [%d]",
                        OpenAPI_nf_type_ToString(nf_instance->nf_type),
                        nf_instance->id, e->h.timer_id);
            break;

        case OGS_TIMER_SUBSCRIPTION_VALIDITY:
            subscription_data = e->h.sbi.data;
            ogs_assert(subscription_data);

            ogs_assert(true ==
                ogs_nnrf_nfm_send_nf_status_subscribe(
                    ogs_sbi_self()->nf_instance->nf_type,
                    subscription_data->req_nf_instance_id,
                    subscription_data->subscr_cond.nf_type,
                    subscription_data->subscr_cond.service_name));
            
            ogs_error("[%s] Subscription validity expired",
                subscription_data->id);
            ogs_sbi_subscription_data_remove(subscription_data);
            break;

        case OGS_TIMER_SUBSCRIPTION_PATCH:
            subscription_data = e->h.sbi.data;
            ogs_assert(subscription_data);

            ogs_assert(true ==
                ogs_nnrf_nfm_send_nf_status_update(subscription_data));

            ogs_info("[%s] Need to update Subscription",
                    subscription_data->id);
            break;

        case OGS_TIMER_SBI_CLIENT_WAIT:
            /*
             * ogs_pollset_poll() receives the time of the expiration
             * of next timer as an argument. If this timeout is
             * in very near future (1 millisecond), and if there are
             * multiple events that need to be processed by ogs_pollset_poll(),
             * these could take more than 1 millisecond for processing,
             * resulting in the timer already passed the expiration.
             *
             * In case that another NF is under heavy load and responds
             * to an SBI request with some delay of a few seconds,
             * it can happen that ogs_pollset_poll() adds SBI responses
             * to the event list for further processing,
             * then ogs_timer_mgr_expire() is called which will add
             * an additional event for timer expiration. When all events are
             * processed one-by-one, the SBI xact would get deleted twice
             * in a row, resulting in a crash.
             *
             * 1. ogs_pollset_poll()
             *    message was received and put into an event list,
             * 2. ogs_timer_mgr_expire()
             *    add an additional event for timer expiration
             * 3. message event is processed. (free SBI xact)
             * 4. timer expiration event is processed. (double-free SBI xact)
             *
             * To avoid double-free SBI xact,
             * we need to check ogs_sbi_xact_find_by_id()
             */
            sbi_xact_id = OGS_POINTER_TO_UINT(e->h.sbi.data);
            ogs_assert(sbi_xact_id >= OGS_MIN_POOL_ID &&
                    sbi_xact_id <= OGS_MAX_POOL_ID);

            sbi_xact = ogs_sbi_xact_find_by_id(sbi_xact_id);
            if (!sbi_xact) {
                ogs_error("SBI transaction has already been removed [%d]",
                        sbi_xact_id);
                break;
            }

            ogs_assert(sbi_xact->assoc_stream_id >= OGS_MIN_POOL_ID &&
                    sbi_xact->assoc_stream_id <= OGS_MAX_POOL_ID);
            stream = ogs_sbi_stream_find_by_id(sbi_xact->assoc_stream_id);

            ogs_sbi_xact_remove(sbi_xact);

            ogs_error("Cannot receive SBI message");

            if (!stream) {
                ogs_error("STREAM has alreadt been removed [%d]",
                        sbi_xact->assoc_stream_id);
                break;
            }
            ogs_assert(true ==
                ogs_sbi_server_send_error(stream,
                    OGS_SBI_HTTP_STATUS_GATEWAY_TIMEOUT, NULL,
                    "Cannot receive SBI message", NULL, NULL));
            break;

        default:
            ogs_error("Unknown timer[%s:%d]",
                    ogs_timer_get_name(e->h.timer_id), e->h.timer_id);
        }
        break;

    default:
        ogs_error("No handler for event %s", udm_event_get_name(e));
        break;
    }
}
