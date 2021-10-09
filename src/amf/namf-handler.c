/*
 * Copyright (C) 2019 by Sukchan Lee <acetcom@gmail.com>
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

#include "namf-handler.h"
#include "nsmf-handler.h"

#include "nas-path.h"
#include "ngap-path.h"
#include "sbi-path.h"
#include "pcs-helper.h"
#include "mongoc.h"
#include "parson.h"
#include <pthread.h>
#include "pcs-thread-pool.h"

int amf_namf_comm_handle_n1_n2_message_transfer(
        ogs_sbi_stream_t *stream, ogs_sbi_message_t *recvmsg, pcs_fsm_struct_t *pcs_fsmdata)
{
    int status;

    amf_ue_t *amf_ue = NULL;
    amf_sess_t *sess = NULL;

    ogs_pkbuf_t *n1buf = NULL;
    ogs_pkbuf_t *n2buf = NULL;

    ogs_pkbuf_t *gmmbuf = NULL;
    ogs_pkbuf_t *ngapbuf = NULL;

    char *supi = NULL;
    uint8_t pdu_session_id = OGS_NAS_PDU_SESSION_IDENTITY_UNASSIGNED;

    ogs_sbi_message_t sendmsg;
    ogs_sbi_response_t *response = NULL;

    OpenAPI_n1_n2_message_transfer_req_data_t *N1N2MessageTransferReqData;
    OpenAPI_n1_n2_message_transfer_rsp_data_t N1N2MessageTransferRspData;
    OpenAPI_n1_message_container_t *n1MessageContainer = NULL;
    OpenAPI_ref_to_binary_data_t *n1MessageContent = NULL;
    OpenAPI_n2_info_container_t *n2InfoContainer = NULL;
    OpenAPI_n2_sm_information_t *smInfo = NULL;
    OpenAPI_n2_info_content_t *n2InfoContent = NULL;
    OpenAPI_ref_to_binary_data_t *ngapData = NULL;

    ogs_assert(stream);
    ogs_assert(recvmsg);

    N1N2MessageTransferReqData = recvmsg->N1N2MessageTransferReqData;
    if (!N1N2MessageTransferReqData) {
        ogs_error("No N1N2MessageTransferReqData");
        return OGS_ERROR;
    }

    if (N1N2MessageTransferReqData->is_pdu_session_id == false) {
        ogs_error("No PDU Session Identity");
        return OGS_ERROR;
    }
    pdu_session_id = N1N2MessageTransferReqData->pdu_session_id;

    supi = recvmsg->h.resource.component[1];
    if (!supi) {
        ogs_error("No SUPI");
        return OGS_ERROR;
    }

    amf_ue = amf_ue_find_by_supi(supi);
    if (!amf_ue) {
        ogs_error("No UE context [%s]", supi);
        return OGS_ERROR;
    }

    sess = amf_sess_find_by_psi(amf_ue, pdu_session_id);
    if (!sess) {
        ogs_error("[%s] No PDU Session Context [%d]",
                amf_ue->supi, pdu_session_id);
        return OGS_ERROR;
    }

    if (pcs_fsmdata->pcs_dbcommenabled && !pcs_fsmdata->pcs_isproceduralstateless && !pcs_fsmdata->pcs_blockingapienabledcreate)
    {
        int pcs_loop = 0;
        while(sess->pcs.pcs_udsfcreatedone == 0 && pcs_loop < 10000) {
            usleep(5);
            pcs_loop = pcs_loop + 1;
            if (sess->pcs.pcs_udsfcreatedone)
            {
                ogs_info("PCS Finally create is done %d", pcs_loop);
            }
        }
    }

    n1MessageContainer = N1N2MessageTransferReqData->n1_message_container;
    if (n1MessageContainer) {
        n1MessageContent = n1MessageContainer->n1_message_content;
        if (!n1MessageContent || !n1MessageContent->content_id) {
            ogs_error("No n1MessageContent");
            return OGS_ERROR;
        }

        n1buf = ogs_sbi_find_part_by_content_id(
                recvmsg, n1MessageContent->content_id);
        if (!n1buf) {
            ogs_error("[%s] No N1 SM Content", amf_ue->supi);
            return OGS_ERROR;
        }

        /*
         * NOTE : The pkbuf created in the SBI message will be removed
         *        from ogs_sbi_message_free(), so it must be copied.
         */
        n1buf = ogs_pkbuf_copy(n1buf);
        ogs_assert(n1buf);
    }

    n2InfoContainer = N1N2MessageTransferReqData->n2_info_container;
    if (n2InfoContainer) {
        smInfo = n2InfoContainer->sm_info;
        if (!smInfo) {
            ogs_error("No smInfo");
            return OGS_ERROR;
        }
        n2InfoContent = smInfo->n2_info_content;
        if (!n2InfoContent) {
            ogs_error("No n2InfoContent");
            return OGS_ERROR;
        }

        ngapData = n2InfoContent->ngap_data;
        if (!ngapData || !ngapData->content_id) {
            ogs_error("No ngapData");
            return OGS_ERROR;
        }
        n2buf = ogs_sbi_find_part_by_content_id(
                recvmsg, ngapData->content_id);
        if (!n2buf) {
            ogs_error("[%s] No N2 SM Content", amf_ue->supi);
            return OGS_ERROR;
        }

        /*
         * NOTE : The pkbuf created in the SBI message will be removed
         *        from ogs_sbi_message_free(), so it must be copied.
         */
        n2buf = ogs_pkbuf_copy(n2buf);
        ogs_assert(n2buf);
    }

    switch (n2InfoContent->ngap_ie_type) {
    case OpenAPI_ngap_ie_type_PDU_RES_SETUP_REQ:
    case OpenAPI_ngap_ie_type_PDU_RES_MOD_REQ:
    case OpenAPI_ngap_ie_type_PDU_RES_REL_CMD:
        /* N1 SM Message */
        if (n1buf) {
            gmmbuf = gmm_build_dl_nas_transport(sess,
                    OGS_NAS_PAYLOAD_CONTAINER_N1_SM_INFORMATION, n1buf, 0, 0);
            ogs_assert(gmmbuf);
        }
        break;
    default:
        ogs_error("Not implemented ngap_ie_type[%d]",
                n2InfoContent->ngap_ie_type);
        return OGS_ERROR;
    }

    memset(&sendmsg, 0, sizeof(sendmsg));

    status = OGS_SBI_HTTP_STATUS_OK;

    memset(&N1N2MessageTransferRspData, 0, sizeof(N1N2MessageTransferRspData));
    N1N2MessageTransferRspData.cause =
        OpenAPI_n1_n2_message_transfer_cause_N1_N2_TRANSFER_INITIATED;

    sendmsg.N1N2MessageTransferRspData = &N1N2MessageTransferRspData;

    switch (n2InfoContent->ngap_ie_type) {
    case OpenAPI_ngap_ie_type_PDU_RES_SETUP_REQ:
        if (!n2buf) {
            ogs_error("[%s] No N2 SM Content", amf_ue->supi);
            return OGS_ERROR;
        }

        if (gmmbuf) {
            ran_ue_t *ran_ue = NULL;

            /***********************************
             * 4.3.2 PDU Session Establishment *
             ***********************************/

            ran_ue = ran_ue_cycle(amf_ue->ran_ue);
            ogs_assert(ran_ue);

            if (sess->pdu_session_establishment_accept) {
                ogs_pkbuf_free(sess->pdu_session_establishment_accept);
                sess->pdu_session_establishment_accept = NULL;
            }

            if (ran_ue->initial_context_setup_request_sent == true) {
                ngapbuf = ngap_sess_build_pdu_session_resource_setup_request(
                        sess, gmmbuf, n2buf);
                ogs_assert(ngapbuf);
            } else {
                ngapbuf = ngap_sess_build_initial_context_setup_request(
                        sess, gmmbuf, n2buf);
                ogs_assert(ngapbuf);

                ran_ue->initial_context_setup_request_sent = true;
            }

            if (SESSION_CONTEXT_IN_SMF(sess)) {
                /*
                 * [1-CLIENT] /nsmf-pdusession/v1/sm-contexts
                 * [2-SERVER] /namf-comm/v1/ue-contexts/{supi}/n1-n2-messages
                 *
                 * If [2-SERVER] arrives after [1-CLIENT],
                 * sm-context-ref is created in [1-CLIENT].
                 * So, the PDU session establishment accpet can be transmitted.
                 */
                if (nas_5gs_send_to_gnb(amf_ue, ngapbuf) != OGS_OK)
                    ogs_error("nas_5gs_send_to_gnb() failed");
            } else {
                sess->pdu_session_establishment_accept = ngapbuf;
            }

        } else {
            /*********************************************
             * 4.2.3.3 Network Triggered Service Request *
             *********************************************/

            if (CM_IDLE(amf_ue)) {
                ogs_sbi_server_t *server = NULL;
                ogs_sbi_header_t header;
                ogs_sbi_client_t *client = NULL;
                ogs_sockaddr_t *addr = NULL;

                if (!N1N2MessageTransferReqData->n1n2_failure_txf_notif_uri) {
                    ogs_error("[%s:%d] No n1-n2-failure-notification-uri",
                            amf_ue->supi, sess->psi);
                    return OGS_ERROR;
                }

                addr = ogs_sbi_getaddr_from_uri(
                        N1N2MessageTransferReqData->n1n2_failure_txf_notif_uri);
                if (!addr) {
                    ogs_error("[%s:%d] Invalid URI [%s]",
                            amf_ue->supi, sess->psi,
                            N1N2MessageTransferReqData->
                                n1n2_failure_txf_notif_uri);
                    return OGS_ERROR;;
                }

                client = ogs_sbi_client_find(addr);
                if (!client) {
                    client = ogs_sbi_client_add(addr);
                    ogs_assert(client);
                }
                OGS_SETUP_SBI_CLIENT(&sess->paging, client);

                ogs_freeaddrinfo(addr);

                status = OGS_SBI_HTTP_STATUS_ACCEPTED;
                N1N2MessageTransferRspData.cause =
                    OpenAPI_n1_n2_message_transfer_cause_ATTEMPTING_TO_REACH_UE;

                /* Location */
                server = ogs_sbi_server_from_stream(stream);
                ogs_assert(server);

                memset(&header, 0, sizeof(header));
                header.service.name = (char *)OGS_SBI_SERVICE_NAME_NAMF_COMM;
                header.api.version = (char *)OGS_SBI_API_V1;
                header.resource.component[0] =
                    (char *)OGS_SBI_RESOURCE_NAME_UE_CONTEXTS;
                header.resource.component[1] = amf_ue->supi;
                header.resource.component[2] =
                    (char *)OGS_SBI_RESOURCE_NAME_N1_N2_MESSAGES;
                header.resource.component[3] = sess->sm_context_ref;

                sendmsg.http.location = ogs_sbi_server_uri(server, &header);

                /* Store Paging Info */
                AMF_SESS_STORE_PAGING_INFO(
                        sess, sendmsg.http.location,
                        N1N2MessageTransferReqData->n1n2_failure_txf_notif_uri);

                /* Store N2 Transfer message */
                AMF_SESS_STORE_N2_TRANSFER(
                        sess, pdu_session_resource_setup_request, n2buf);

                ogs_assert(OGS_OK == ngap_send_paging(amf_ue));

            } else if (CM_CONNECTED(amf_ue)) {
                ogs_assert(OGS_OK ==
                    ngap_send_pdu_resource_setup_request(sess, n2buf));

            } else {

                ogs_fatal("[%s] Invalid AMF-UE state", amf_ue->supi);
                ogs_assert_if_reached();

            }

        }
        break;

    case OpenAPI_ngap_ie_type_PDU_RES_MOD_REQ:
        if (!gmmbuf) {
            ogs_error("[%s] No N1 SM Content", amf_ue->supi);
            return OGS_ERROR;
        }
        if (!n2buf) {
            ogs_error("[%s] No N2 SM Content", amf_ue->supi);
            return OGS_ERROR;
        }

        if (CM_IDLE(amf_ue)) {
            ogs_fatal("[%s] IDLE state is not implemented", amf_ue->supi);
            ogs_assert_if_reached();

        } else if (CM_CONNECTED(amf_ue)) {
            ngapbuf = ngap_build_pdu_session_resource_modify_request(
                    sess, gmmbuf, n2buf);
            ogs_assert(ngapbuf);

            if (nas_5gs_send_to_gnb(amf_ue, ngapbuf) != OGS_OK)
                ogs_error("nas_5gs_send_to_gnb() failed");

        } else {
            ogs_fatal("[%s] Invalid AMF-UE state", amf_ue->supi);
            ogs_assert_if_reached();
        }

        break;

    case OpenAPI_ngap_ie_type_PDU_RES_REL_CMD:
        if (!n2buf) {
            ogs_error("[%s] No N2 SM Content", amf_ue->supi);
            return OGS_ERROR;
        }

        if (CM_IDLE(amf_ue)) {
            if (gmmbuf)
                ogs_pkbuf_free(gmmbuf);
            if (n2buf)
                ogs_pkbuf_free(n2buf);

            if (N1N2MessageTransferReqData->is_skip_ind == true &&
                N1N2MessageTransferReqData->skip_ind == true) {
                N1N2MessageTransferRspData.cause =
                    OpenAPI_n1_n2_message_transfer_cause_N1_MSG_NOT_TRANSFERRED;
            } else {
                ogs_fatal("[%s] No skipInd", amf_ue->supi);
                ogs_assert_if_reached();
            }

        } else if (CM_CONNECTED(amf_ue)) {
            ngapbuf = ngap_build_pdu_session_resource_release_command(
                    sess, NULL, n2buf);
            ogs_assert(ngapbuf);

            if (nas_5gs_send_to_gnb(amf_ue, ngapbuf) != OGS_OK)
                ogs_error("nas_5gs_send_to_gnb() failed");

        } else {
            ogs_fatal("[%s] Invalid AMF-UE state", amf_ue->supi);
            ogs_assert_if_reached();
        }
        break;

    default:
        ogs_error("Not implemented ngap_ie_type[%d]",
                n2InfoContent->ngap_ie_type);
        ogs_assert_if_reached();
    }

    if (pcs_fsmdata->pcs_dbcommenabled && !pcs_fsmdata->pcs_isproceduralstateless && !pcs_fsmdata->pcs_blockingapienabledn1n2)
    {
        if (sess->pcs.pcs_udsfcreatedone)
        {
            pcs_threadpool = pcs_fsmdata->pcs_threadpool;
            char *pcs_imsistr = sess->amf_ue->supi;
            pcs_imsistr += 5;
            pthread_t pcs_thread1;
            struct pcs_amf_n1n2_udsf_s *pcs_amfn1n2udsf = malloc(sizeof(struct pcs_amf_n1n2_udsf_s));
            pcs_amfn1n2udsf->pcs_dbcollection = pcs_fsmdata->pcs_dbcollection;
            (*pcs_amfn1n2udsf).pcs_amfuengapid = (uint64_t *)sess->amf_ue->ran_ue->amf_ue_ngap_id;
            (*pcs_amfn1n2udsf).pcs_pdusessionid = (long *) (long)sess->psi;
            pcs_amfn1n2udsf->n1buf = ogs_pkbuf_copy(n1buf);
            pcs_amfn1n2udsf->n2buf = ogs_pkbuf_copy(n2buf);
            pcs_amfn1n2udsf->pcs_dbrdata = ogs_strdup(read_data_from_db(pcs_fsmdata->pcs_dbcollection, pcs_imsistr));
            //pcs_amf_n1n2_udsf(pcs_amfn1n2udsf);
            //pthread_create(&pcs_thread1, NULL, pcs_amf_n1n2_udsf, (void*) pcs_amfn1n2udsf);
            mt_add_job(pcs_threadpool, &pcs_amf_n1n2_udsf, pcs_amfn1n2udsf);
            ogs_info("PCS Started N1-N2 UDSF thread");    
        }
        else
        {
            ogs_error("pcs_udsfcreatedone thread is not complete");
            sess->pcs.pcs_udsfn1n2done = 0;
        }
    }

    response = ogs_sbi_build_response(&sendmsg, status);
    ogs_assert(response);
    ogs_assert(true == ogs_sbi_server_send_response(stream, response));

    if (sendmsg.http.location)
        ogs_free(sendmsg.http.location);

    if (pcs_fsmdata->pcs_dbcommenabled && pcs_fsmdata->pcs_isproceduralstateless && sess->pcs.pcs_createdone && strcmp(pcs_fsmdata->pcs_dbcollectioname, "amf") == 0)
    {
        struct pcs_amf_n1n2 pcs_n1n2data = pcs_get_amf_n1n2_data(sess, n1buf, n2buf);
        sess->pcs.pcs_n1n2done = 1;
        sess->pcs.pcs_n1n2data = pcs_n1n2data;
        ogs_info("PCS Successfully completed Procedural Stateless n1-n2 transaction for supi [%s]", sess->amf_ue->supi);
    }
    else if (pcs_fsmdata->pcs_dbcommenabled && pcs_fsmdata->pcs_isproceduralstateless && sess->pcs.pcs_createdone && strcmp(pcs_fsmdata->pcs_dbcollectioname, "amf") != 0)
    {
        ogs_info("PCS Successfully completed n1-n2 transaction with shared UDSF for supi [%s]", sess->amf_ue->supi);
    }
    else if (pcs_fsmdata->pcs_dbcommenabled && !pcs_fsmdata->pcs_isproceduralstateless && pcs_fsmdata->pcs_blockingapienabledn1n2)
    {
        mongoc_collection_t *pcs_dbcollection = pcs_fsmdata->pcs_dbcollection;
        double pcs_createdone = 0;
        int pcs_rv;
        char *pcs_imsistr = sess->amf_ue->supi;
        pcs_imsistr += 5;
        char *pcs_dbrdata = read_data_from_db(pcs_dbcollection, pcs_imsistr);
        JSON_Value *pcs_dbrdatajsonval = json_parse_string(pcs_dbrdata);
        if (json_value_get_type(pcs_dbrdatajsonval) == JSONObject)
        {
            JSON_Object *pcs_dbrdatajsonobj = json_object(pcs_dbrdatajsonval);
            pcs_createdone = json_object_get_number(pcs_dbrdatajsonobj, "pcs-create-done");
        }
        if (strcmp(pcs_fsmdata->pcs_dbcollectioname, "amf") == 0)
        {
            if ((int)pcs_createdone)
            {
                struct pcs_amf_n1n2 pcs_n1n2data = pcs_get_amf_n1n2_data(sess, n1buf, n2buf);
                if (pcs_fsmdata->pcs_updateapienabledn1n2)
                {
                    bson_error_t error;
                    bson_t *bson_doc_nas_qos_rule = bson_new_from_json((const uint8_t *)pcs_n1n2data.pcs_nasqosrulestr, -1, &error);
                    bson_t *bson_doc_nas_qos_flow = bson_new_from_json((const uint8_t *)pcs_n1n2data.pcs_nasqosflowstr, -1, &error);
                    bson_t *bson_doc_nas_epco = bson_new_from_json((const uint8_t *)pcs_n1n2data.pcs_nasepcostr, -1, &error);
                    bson_t *bson_doc = BCON_NEW("$set", "{", "pcs-n1n2-done", BCON_INT32(1), "pdu-session-id", BCON_INT32(pdu_session_id), "pdu-address", BCON_UTF8(pcs_n1n2data.pcs_pduaddress), "dnn", BCON_UTF8(pcs_n1n2data.pcs_dnn), "sesion-ambr", "{", "uplink", BCON_INT32(pcs_n1n2data.pcs_sambrulv), "ul-unit", BCON_INT32(pcs_n1n2data.pcs_sambrulu), "downlink", BCON_INT32(pcs_n1n2data.pcs_sambrdlv), "dl-unit", BCON_INT32(pcs_n1n2data.pcs_sambrdlu), "}", "pdu-session-type", BCON_INT32(pcs_n1n2data.pcs_pdusesstype), "PDUSessionAggregateMaximumBitRate", "{", "pDUSessionAggregateMaximumBitRateUL", BCON_INT64(pcs_n1n2data.pcs_pdusessionaggregatemaximumbitrateul), "pDUSessionAggregateMaximumBitRateDL", BCON_INT64(pcs_n1n2data.pcs_pdusessionaggregatemaximumbitratedl), "}", "QosFlowSetupRequestList", "[", "{", "qosFlowIdentifier", BCON_INT64(pcs_n1n2data.pcs_qosflowidentifier), "fiveQI", BCON_INT64(pcs_n1n2data.pcs_fiveqi), "priorityLevelARP", BCON_INT64(pcs_n1n2data.pcs_plarp), "pre_emptionCapability", BCON_INT64(pcs_n1n2data.pcs_preemptioncapability), "pre_emptionVulnerability", BCON_INT64(pcs_n1n2data.pcs_preemptionvulnerability), "}", "]", "UL_NGU_UP_TNLInformation", "{", "transportLayerAddress", BCON_UTF8(pcs_n1n2data.pcs_upfn3ip), "gTP_TEID", BCON_INT32(pcs_n1n2data.pcs_upfn3teid), "}", "nas-authorized-qos-rules", BCON_ARRAY(bson_doc_nas_qos_rule), "nas-authorized-qos-flow_descriptions", BCON_ARRAY(bson_doc_nas_qos_flow), "nas-extended-protocol-configuration-option", BCON_DOCUMENT(bson_doc_nas_epco), "}");

                    pcs_rv = insert_data_to_db(pcs_dbcollection, "update", pcs_imsistr, bson_doc);
                    bson_destroy(bson_doc_nas_qos_rule);
                    bson_destroy(bson_doc_nas_qos_flow);
                    bson_destroy(bson_doc_nas_epco);                
                }
                else
                {
                    char *pcs_updatedoc;
                    asprintf(&pcs_updatedoc, ", \"pcs-n1n2-done\": 1, \"pdu-session-id\": %d, \"pdu-address\": \"%s\", \"dnn\": \"%s\", \"sesion-ambr\": {\"uplink\": %d, \"ul-unit\": %d, \"downlink\": %d, \"dl-unit\": %d}, \"pdu-session-type\": %d, \"PDUSessionAggregateMaximumBitRate\": {\"pDUSessionAggregateMaximumBitRateUL\": %ld, \"pDUSessionAggregateMaximumBitRateDL\": %ld}, \"QosFlowSetupRequestList\": [{ \"qosFlowIdentifier\": %ld, \"fiveQI\": %ld, \"priorityLevelARP\": %ld, \"pre_emptionCapability\": %ld, \"pre_emptionVulnerability\": %ld}], \"UL_NGU_UP_TNLInformation\": {\"transportLayerAddress\": \"%s\", \"gTP_TEID\": %d}, \"nas-authorized-qos-rules\": %s, \"nas-authorized-qos-flow_descriptions\": %s, \"nas-extended-protocol-configuration-option\": %s}", pdu_session_id, pcs_n1n2data.pcs_pduaddress, pcs_n1n2data.pcs_dnn, pcs_n1n2data.pcs_sambrulv, pcs_n1n2data.pcs_sambrulu, pcs_n1n2data.pcs_sambrdlv, pcs_n1n2data.pcs_sambrdlu, pcs_n1n2data.pcs_pdusesstype, pcs_n1n2data.pcs_pdusessionaggregatemaximumbitrateul, pcs_n1n2data.pcs_pdusessionaggregatemaximumbitratedl, pcs_n1n2data.pcs_qosflowidentifier, pcs_n1n2data.pcs_fiveqi, pcs_n1n2data.pcs_plarp, pcs_n1n2data.pcs_preemptioncapability, pcs_n1n2data.pcs_preemptionvulnerability, pcs_n1n2data.pcs_upfn3ip, pcs_n1n2data.pcs_upfn3teid, pcs_n1n2data.pcs_nasqosrulestr, pcs_n1n2data.pcs_nasqosflowstr, pcs_n1n2data.pcs_nasepcostr);
                    pcs_rv = delete_create_data_to_db(pcs_dbcollection, pcs_imsistr, pcs_dbrdata, pcs_updatedoc);
                }

                if (pcs_rv != OGS_OK)
                {
                    ogs_error("PCS Error while updateing n1-n2 data to MongoDB for supi [%s]", sess->amf_ue->supi);
                }
                else
                {
                    sess->pcs.pcs_udsfn1n2done = 1;
                    ogs_info("PCS Successfully updated n1-n2 data to MongoDB for supi [%s]", sess->amf_ue->supi);
                }

                free(pcs_n1n2data.pcs_nasqosrulestr);
                free(pcs_n1n2data.pcs_nasqosflowstr);
                free(pcs_n1n2data.pcs_nasepcostr);

                /* ogs_free(pcs_n1n2data.pcs_upfn3ip);
                ogs_free(pcs_n1n2data.pcs_pduaddress);
                ogs_free(pcs_n1n2data.pcs_ie);
                ogs_free(pcs_n1n2data.pcs_gtptunnel);
                ogs_free(pcs_n1n2data.pcs_qosflowsetuprequestitem);*/
            }
            else
            {
                ogs_error("PCS n1-n2 request got triggered without processing Create-SM-Context request");
            }
        }
        else
        {
            ogs_info("PCS Successfully completed n1-n2 transaction with shared UDSF for supi [%s]", sess->amf_ue->supi);
        }
        json_value_free(pcs_dbrdatajsonval);
        bson_free(pcs_dbrdata);
    }
    else if (!pcs_fsmdata->pcs_dbcommenabled)
    {
        ogs_info("PCS Successfully completed n1-n2 transaction for supi [%s]", sess->amf_ue->supi);
    }

    return OGS_OK;
}

int amf_namf_callback_handle_sm_context_status(
        ogs_sbi_stream_t *stream, ogs_sbi_message_t *recvmsg)
{
    int status = OGS_SBI_HTTP_STATUS_NO_CONTENT;

    amf_ue_t *amf_ue = NULL;
    amf_sess_t *sess = NULL;

    uint8_t pdu_session_identity;

    ogs_sbi_message_t sendmsg;
    ogs_sbi_response_t *response = NULL;

    OpenAPI_sm_context_status_notification_t *SmContextStatusNotification;
    OpenAPI_status_info_t *StatusInfo;

    ogs_assert(stream);
    ogs_assert(recvmsg);

    if (!recvmsg->h.resource.component[0]) {
        status = OGS_SBI_HTTP_STATUS_BAD_REQUEST;
        ogs_error("No SUPI");
        goto cleanup;
    }

    amf_ue = amf_ue_find_by_supi(recvmsg->h.resource.component[0]);
    if (!amf_ue) {
        status = OGS_SBI_HTTP_STATUS_NOT_FOUND;
        ogs_error("Cannot find SUPI [%s]", recvmsg->h.resource.component[0]);
        goto cleanup;
    }

    if (!recvmsg->h.resource.component[2]) {
        status = OGS_SBI_HTTP_STATUS_BAD_REQUEST;
        ogs_error("[%s] No PDU Session Identity", amf_ue->supi);
        goto cleanup;
    }

    pdu_session_identity = atoi(recvmsg->h.resource.component[2]);
    if (pdu_session_identity == OGS_NAS_PDU_SESSION_IDENTITY_UNASSIGNED) {
        status = OGS_SBI_HTTP_STATUS_BAD_REQUEST;
        ogs_error("[%s] PDU Session Identity is unassigned", amf_ue->supi);
        goto cleanup;
    }

    sess = amf_sess_find_by_psi(amf_ue, pdu_session_identity);
    if (!sess) {
        status = OGS_SBI_HTTP_STATUS_NOT_FOUND;
        ogs_warn("[%s] Cannot find session", amf_ue->supi);
        goto cleanup;
    }

    SmContextStatusNotification = recvmsg->SmContextStatusNotification;
    if (!SmContextStatusNotification) {
        status = OGS_SBI_HTTP_STATUS_BAD_REQUEST;
        ogs_error("[%s:%d] No SmContextStatusNotification",
                amf_ue->supi, sess->psi);
        goto cleanup;
    }

    StatusInfo = SmContextStatusNotification->status_info;
    if (!StatusInfo) {
        status = OGS_SBI_HTTP_STATUS_BAD_REQUEST;
        ogs_error("[%s:%d] No StatusInfo", amf_ue->supi, sess->psi);
        goto cleanup;
    }

    sess->resource_status = StatusInfo->resource_status;

    /*
     * Race condition for PDU session release complete
     *  - CLIENT : /nsmf-pdusession/v1/sm-contexts/{smContextRef}/modify
     *  - SERVER : /namf-callback/v1/{supi}/sm-context-status/{psi})
     *
     * If NOTIFICATION is received before the CLIENT response is received,
     * CLIENT sync is not finished. In this case, the session context
     * should not be removed.
     *
     * If NOTIFICATION comes after the CLIENT response is received,
     * sync is done. So, the session context can be removed.
     */
    if (sess->n1_released == true &&
        sess->n2_released == true &&
        sess->resource_status == OpenAPI_resource_status_RELEASED) {

        ogs_debug("[%s:%d] SM context remove", amf_ue->supi, sess->psi);
        amf_nsmf_pdusession_handle_release_sm_context(
                sess, AMF_RELEASE_SM_CONTEXT_NO_STATE);
    }

cleanup:
    memset(&sendmsg, 0, sizeof(sendmsg));

    response = ogs_sbi_build_response(&sendmsg, status);
    ogs_assert(response);
    ogs_assert(true == ogs_sbi_server_send_response(stream, response));

    return OGS_OK;
}
