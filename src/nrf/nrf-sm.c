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

void nrf_state_initial(ogs_fsm_t *s, nrf_event_t *e)
{
    nrf_sm_debug(e);

    ogs_assert(s);

    OGS_FSM_TRAN(s, &nrf_state_operational);
}

void nrf_state_final(ogs_fsm_t *s, nrf_event_t *e)
{
    nrf_sm_debug(e);

    ogs_assert(s);
}

void nrf_state_operational(ogs_fsm_t *s, nrf_event_t *e)
{
    ogs_info("PCS NRF ogs_queue_size is %d",ogs_queue_size(ogs_app()->queue));
    int rv;
    ogs_sbi_stream_t *stream = NULL;
    ogs_pool_id_t stream_id = OGS_INVALID_POOL_ID;
    ogs_sbi_request_t *request = NULL;

    ogs_sbi_nf_instance_t *nf_instance = NULL;
    ogs_sbi_subscription_data_t *subscription_data = NULL;

    ogs_sbi_message_t message;

    ogs_assert(e);

    nrf_sm_debug(e);

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

        if (strcmp(message.h.api.version, OGS_SBI_API_V1) != 0) {
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
            CASE(OGS_SBI_RESOURCE_NAME_NF_INSTANCES)
                SWITCH(message.h.method)
                CASE(OGS_SBI_HTTP_METHOD_GET)
                    if (message.h.resource.component[1]) {
                        nrf_nnrf_handle_nf_profile_retrieval(stream, &message);
                    } else {
                        nrf_nnrf_handle_nf_list_retrieval(stream, &message);
                    }
                    break;

                CASE(OGS_SBI_HTTP_METHOD_OPTIONS)
                    ogs_assert(
                        true ==
                        ogs_sbi_server_send_error(
                            stream,
                            OGS_SBI_HTTP_STATUS_NOT_IMPLEMENTED,
                            &message, "OPTIONS method is not implemented yet",
                            NULL, NULL));
                    break;

                DEFAULT
                    if (message.h.resource.component[1]) {
                        nf_instance = ogs_sbi_nf_instance_find(
                                message.h.resource.component[1]);
                    }

                    if (!nf_instance) {
                        SWITCH(message.h.method)
                        CASE(OGS_SBI_HTTP_METHOD_PUT)
                            if (ogs_sbi_nf_instance_maximum_number_is_reached())
                            {
                                ogs_warn("Can't add instance [%s] "
                                         "due to insufficient space",
                                         message.h.resource.component[1]);
                                ogs_assert(
                                    true ==
                                    ogs_sbi_server_send_error(
                                        stream,
                                        OGS_SBI_HTTP_STATUS_PAYLOAD_TOO_LARGE,
                                        &message, "Insufficient space",
                                        message.h.resource.component[1], NULL));
                                break;
                            }
                            nf_instance = ogs_sbi_nf_instance_add();
                            ogs_assert(nf_instance);
                            ogs_sbi_nf_instance_set_id(nf_instance,
                                    message.h.resource.component[1]);

                            /*
                             * If nrf_nf_fsm_init() is executed,
                             * nrf_nf_fsm_final() is executed later
                             * in nrf_context_final().
                             */
                            nrf_nf_fsm_init(nf_instance);
                            break;
                        DEFAULT
                            ogs_warn("Not found [%s]",
                                    message.h.resource.component[1]);
                            ogs_assert(true ==
                                ogs_sbi_server_send_error(stream,
                                    OGS_SBI_HTTP_STATUS_NOT_FOUND,
                                    &message, "Not found",
                                    message.h.resource.component[1], NULL));
                        END
                    }

                    if (nf_instance) {
                        e->nf_instance = nf_instance;
                        ogs_assert(OGS_FSM_STATE(&nf_instance->sm));

                        e->h.sbi.message = &message;
                        ogs_fsm_dispatch(&nf_instance->sm, e);
                        if (OGS_FSM_CHECK(&nf_instance->sm,
                                    nrf_nf_state_de_registered)) {
                            ogs_info("[%s] NF de-registered", nf_instance->id);
                            nrf_nf_fsm_fini(nf_instance);
                            ogs_sbi_nf_instance_remove(nf_instance);
                        } else if (OGS_FSM_CHECK(&nf_instance->sm,
                                    nrf_nf_state_exception)) {
                            ogs_error("[%s] State machine exception",
                                    nf_instance->id);

                            nrf_nf_fsm_fini(nf_instance);
                            ogs_sbi_nf_instance_remove(nf_instance);
                        }
                    }
                END
                break;

            CASE(OGS_SBI_RESOURCE_NAME_SUBSCRIPTIONS)
                SWITCH(message.h.method)
                CASE(OGS_SBI_HTTP_METHOD_POST)
                    nrf_nnrf_handle_nf_status_subscribe(stream, &message);
                    break;

                CASE(OGS_SBI_HTTP_METHOD_PATCH)
                    nrf_nnrf_handle_nf_status_update(stream, &message);
                    break;

                CASE(OGS_SBI_HTTP_METHOD_DELETE)
                    nrf_nnrf_handle_nf_status_unsubscribe(stream, &message);
                    break;

                DEFAULT
                    ogs_error("Invalid HTTP method [%s]",
                            message.h.method);
                    ogs_assert(true ==
                        ogs_sbi_server_send_error(stream,
                            OGS_SBI_HTTP_STATUS_FORBIDDEN, &message,
                            "Invalid HTTP method", message.h.method, NULL));
                END
                break;

            DEFAULT
                ogs_error("Invalid resource name [%s]",
                        message.h.resource.component[0]);
                ogs_assert(true ==
                    ogs_sbi_server_send_error(stream,
                        OGS_SBI_HTTP_STATUS_BAD_REQUEST, &message,
                        "Invalid resource name",
                        message.h.resource.component[0], NULL));
            END
            break;

        CASE(OGS_SBI_SERVICE_NAME_NNRF_DISC)

            SWITCH(message.h.resource.component[0])
            CASE(OGS_SBI_RESOURCE_NAME_NF_INSTANCES)

                SWITCH(message.h.method)
                CASE(OGS_SBI_HTTP_METHOD_GET)
                    nrf_nnrf_handle_nf_discover(stream, &message);
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
                        "Invalid resource name",
                        message.h.resource.component[0], NULL));
            END
            break;

        DEFAULT
            ogs_error("Invalid API name [%s]", message.h.service.name);
            ogs_assert(true ==
                ogs_sbi_server_send_error(stream,
                    OGS_SBI_HTTP_STATUS_BAD_REQUEST, &message,
                    "Invalid API name", message.h.resource.component[0],
                    NULL));
        END

        /* In lib/sbi/server.c, notify_completed() releases 'request' buffer. */
        ogs_sbi_message_free(&message);
        break;

    case OGS_EVENT_SBI_TIMER:
        switch(e->h.timer_id) {
        case NRF_TIMER_NF_INSTANCE_NO_HEARTBEAT:
            nf_instance = e->nf_instance;
            ogs_assert(nf_instance);

            ogs_warn("[%s] No heartbeat", nf_instance->id);
            nf_instance->nf_status = OpenAPI_nf_status_SUSPENDED;

            nrf_nf_fsm_fini(nf_instance);
            ogs_sbi_nf_instance_remove(nf_instance);

            /* FIXME : Remove unnecessary Client */
            break;

        case NRF_TIMER_SUBSCRIPTION_VALIDITY:
            subscription_data = e->subscription_data;
            ogs_assert(subscription_data);

            ogs_error("[%s] Subscription validity expired",
                    subscription_data->id);
            ogs_sbi_subscription_data_remove(subscription_data);
            break;

        default:
            ogs_error("Unknown timer[%s:%d]",
                    nrf_timer_get_name(e->h.timer_id), e->h.timer_id);
        }
        break;

    default:
        ogs_error("No handler for event %s", nrf_event_get_name(e));
        break;
    }
}
