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

#include "sbi-path.h"
#include "ngap-path.h"
#include "binding.h"
#include "namf-handler.h"
#include "mongoc.h"
#include "pcs-helper.h"

bool smf_namf_comm_handle_n1_n2_message_transfer(
        smf_sess_t *sess, int state, ogs_sbi_message_t *recvmsg, pcs_fsm_struct_t *pcs_fsmdata)
{
    smf_ue_t *smf_ue = NULL;
    OpenAPI_n1_n2_message_transfer_rsp_data_t *N1N2MessageTransferRspData;

    ogs_assert(sess);
    smf_ue = sess->smf_ue;
    ogs_assert(smf_ue);
    ogs_assert(state);
    ogs_assert(recvmsg);

    switch (state) {
    case SMF_UE_REQUESTED_PDU_SESSION_ESTABLISHMENT:
        if (recvmsg->res_status == OGS_SBI_HTTP_STATUS_OK) {
            smf_qos_flow_binding(sess);
        } else {
            ogs_error("[%s:%d] HTTP response error [%d]",
                smf_ue->supi, sess->psi, recvmsg->res_status);
        }
        break;

    case SMF_NETWORK_TRIGGERED_SERVICE_REQUEST:
    case SMF_NETWORK_REQUESTED_QOS_FLOW_MODIFICATION:
        N1N2MessageTransferRspData = recvmsg->N1N2MessageTransferRspData;
        if (!N1N2MessageTransferRspData) {
            ogs_error("No N1N2MessageTransferRspData [status:%d]",
                    recvmsg->res_status);
            break;
        }

        if (recvmsg->res_status == OGS_SBI_HTTP_STATUS_OK) {
            if (N1N2MessageTransferRspData->cause ==
                OpenAPI_n1_n2_message_transfer_cause_N1_N2_TRANSFER_INITIATED) {
                /* Nothing */
            } else {
                ogs_error("Not implemented [cause:%d]",
                        N1N2MessageTransferRspData->cause);
                ogs_assert_if_reached();
            }
        } else if (recvmsg->res_status == OGS_SBI_HTTP_STATUS_ACCEPTED) {
            if (N1N2MessageTransferRspData->cause ==
                OpenAPI_n1_n2_message_transfer_cause_ATTEMPTING_TO_REACH_UE) {
                if (recvmsg->http.location)
                    smf_sess_set_paging_n1n2message_location(
                            sess, recvmsg->http.location);
                else
                    ogs_error("No HTTP Location");
            } else {
                ogs_error("Not implemented [cause:%d]",
                        N1N2MessageTransferRspData->cause);
                ogs_assert_if_reached();
            }
        } else {

    /*
     * TODO:
     *
     * TS23.502 4.2.3.3 Network Triggered Service Request
     *
     * 3c. [Conditional] SMF responds to the UPF
     *
     * If the SMF receives an indication from the AMF that the UE is
     * unreachable or reachable only for regulatory prioritized service
     * and the SMF determines that Extended Buffering does not apply,
     * the SMF may, based on network policies, either:
     *
     * - indicate to the UPF to stop sending Data Notifications;
     * - indicate to the UPF to stop buffering DL data and
     *   discard the buffered data;
     * - indicate to the UPF to stop sending Data Notifications and
     *   stop buffering DL data and discard the buffered data; or
     * - refrains from sending further Namf_Communication_N1N2MessageTransfer
     *   message for DL data to the AMF while the UE is unreachable.
     */

            ogs_error("[%s:%d] HTTP response error [status:%d cause:%d]",
                smf_ue->supi, sess->psi, recvmsg->res_status,
                N1N2MessageTransferRspData->cause);
        }
        break;

    case SMF_NETWORK_REQUESTED_PDU_SESSION_RELEASE:
    case SMF_ERROR_INDICATON_RECEIVED_FROM_5G_AN:
        N1N2MessageTransferRspData = recvmsg->N1N2MessageTransferRspData;
        if (!N1N2MessageTransferRspData) {
            ogs_error("No N1N2MessageTransferRspData [status:%d]",
                    recvmsg->res_status);
            break;
        }

        if (recvmsg->res_status == OGS_SBI_HTTP_STATUS_OK) {
            if (N1N2MessageTransferRspData->cause ==
                OpenAPI_n1_n2_message_transfer_cause_N1_MSG_NOT_TRANSFERRED) {
                smf_n1_n2_message_transfer_param_t param;

                memset(&param, 0, sizeof(param));
                param.state = SMF_NETWORK_TRIGGERED_SERVICE_REQUEST;
                param.n2smbuf =
                    ngap_build_pdu_session_resource_setup_request_transfer(
                            sess);
                ogs_assert(param.n2smbuf);

                param.n1n2_failure_txf_notif_uri = true;

                smf_namf_comm_send_n1_n2_message_transfer(sess, &param);
            } else if (N1N2MessageTransferRspData->cause ==
                OpenAPI_n1_n2_message_transfer_cause_N1_N2_TRANSFER_INITIATED) {
                /* Nothing */
            } else {
                ogs_error("Not implemented [cause:%d]",
                        N1N2MessageTransferRspData->cause);
                ogs_assert_if_reached();
            }
        } else {
            ogs_error("[%s:%d] HTTP response error [status:%d cause:%d]",
                smf_ue->supi, sess->psi, recvmsg->res_status,
                N1N2MessageTransferRspData->cause);
        }
        break;

    default:
        ogs_fatal("Unexpected state [%d]", state);
        ogs_assert_if_reached();
    }

    if (PCS_DBCOMMENABLED)
    {
        if (PCS_ISPROCEDURALSTATELESS)
        {
            sess->pcs.pcs_n1n2done = 1;
            ogs_info("PCS Successfully completed Procedural Stateless n1-n2 transfer transaction for supi [%s]", sess->smf_ue->supi);
        }
        else
        {
            clock_t pcs_clk_sd = clock();
            struct pcs_db_write_op_s pcs_db_write_op;
            struct pcs_mongo_info_s pcs_mongo_info = pcs_get_mongo_info(pcs_fsmdata);
            mongoc_collection_t *pcs_dbcollection = pcs_mongo_info.pcs_dbcollection;
            int pcs_uedbid = imsi_to_dbid(sess->smf_ue->supi);
            struct pcs_smf_n1n2 pcs_n1n2data = sess->pcs.pcs_n1n2data;

            if (PCS_UPDATEAPIENABLEDN1N2)
            {
                bson_error_t error;
                bson_t *bson_doc_nas_qos_rule = bson_new_from_json((const uint8_t *)pcs_n1n2data.pcs_nasqosrulestr, -1, &error);
                bson_t *bson_doc_nas_qos_flow = bson_new_from_json((const uint8_t *)pcs_n1n2data.pcs_nasqosflowstr, -1, &error);
                bson_t *bson_doc_nas_epco = bson_new_from_json((const uint8_t *)pcs_n1n2data.pcs_nasepcostr, -1, &error);

                bson_t *bson_doc = BCON_NEW("$set", "{", "pcs-n1n2-done", BCON_INT32(1), "pdu-address", BCON_UTF8(pcs_n1n2data.pcs_pduaddress), "sesion-ambr", "{", "uplink", BCON_INT32(pcs_n1n2data.pcs_sambrulv), "ul-unit", BCON_INT32(pcs_n1n2data.pcs_sambrulu), "downlink", BCON_INT32(pcs_n1n2data.pcs_sambrdlv), "dl-unit", BCON_INT32(pcs_n1n2data.pcs_sambrdlu), "}", "pdu-session-type", BCON_INT32(pcs_n1n2data.pcs_pdusesstype), "PDUSessionAggregateMaximumBitRate", "{", "pDUSessionAggregateMaximumBitRateUL", BCON_INT64(pcs_n1n2data.pcs_pdusessionaggregatemaximumbitrateul), "pDUSessionAggregateMaximumBitRateDL", BCON_INT64(pcs_n1n2data.pcs_pdusessionaggregatemaximumbitratedl), "}", "QosFlowSetupRequestList", "[", "{", "qosFlowIdentifier", BCON_INT64(pcs_n1n2data.pcs_qosflowidentifier), "fiveQI", BCON_INT64(pcs_n1n2data.pcs_fiveqi), "priorityLevelARP", BCON_INT64(pcs_n1n2data.pcs_plarp), "pre_emptionCapability", BCON_INT64(pcs_n1n2data.pcs_preemptioncapability), "pre_emptionVulnerability", BCON_INT64(pcs_n1n2data.pcs_preemptionvulnerability), "}", "]", "UL_NGU_UP_TNLInformation", "{", "transportLayerAddress", BCON_UTF8(pcs_n1n2data.pcs_upfn3ip), "gTP_TEID", BCON_INT32(pcs_n1n2data.pcs_upfn3teid), "}", "nas-authorized-qos-rules", BCON_ARRAY(bson_doc_nas_qos_rule), "nas-authorized-qos-flow_descriptions", BCON_ARRAY(bson_doc_nas_qos_flow), "nas-extended-protocol-configuration-option", BCON_DOCUMENT(bson_doc_nas_epco), "}");

                pcs_db_write_op = insert_data_to_db(pcs_dbcollection, "update", pcs_uedbid, bson_doc);
                bson_destroy(bson_doc_nas_qos_rule);
                bson_destroy(bson_doc_nas_qos_flow);
                bson_destroy(bson_doc_nas_epco);
            }
            else
            {
                char *pcs_updatedoc;
                char *pcs_dbrdata = sess->pcs.pcs_dbrdata;
                asprintf(&pcs_updatedoc, ", \"pcs-n1n2-done\": 1, \"pdu-address\": \"%s\", \"sesion-ambr\": {\"uplink\": %d, \"ul-unit\": %d, \"downlink\": %d, \"dl-unit\": %d}, \"pdu-session-type\": %d, \"PDUSessionAggregateMaximumBitRate\": {\"pDUSessionAggregateMaximumBitRateUL\": %ld, \"pDUSessionAggregateMaximumBitRateDL\": %ld}, \"QosFlowSetupRequestList\": [{ \"qosFlowIdentifier\": %ld, \"fiveQI\": %ld, \"priorityLevelARP\": %ld, \"pre_emptionCapability\": %ld, \"pre_emptionVulnerability\": %ld}], \"UL_NGU_UP_TNLInformation\": {\"transportLayerAddress\": \"%s\", \"gTP_TEID\": %d}, \"nas-authorized-qos-rules\": %s, \"nas-authorized-qos-flow_descriptions\": %s, \"nas-extended-protocol-configuration-option\": %s }", pcs_n1n2data.pcs_pduaddress, pcs_n1n2data.pcs_sambrulv, pcs_n1n2data.pcs_sambrulu, pcs_n1n2data.pcs_sambrdlv, pcs_n1n2data.pcs_sambrdlu, pcs_n1n2data.pcs_pdusesstype, pcs_n1n2data.pcs_pdusessionaggregatemaximumbitrateul, pcs_n1n2data.pcs_pdusessionaggregatemaximumbitratedl, pcs_n1n2data.pcs_qosflowidentifier, pcs_n1n2data.pcs_fiveqi, pcs_n1n2data.pcs_plarp, pcs_n1n2data.pcs_preemptioncapability, pcs_n1n2data.pcs_preemptionvulnerability, pcs_n1n2data.pcs_upfn3ip, pcs_n1n2data.pcs_upfn3teid, pcs_n1n2data.pcs_nasqosrulestr, pcs_n1n2data.pcs_nasqosflowstr, pcs_n1n2data.pcs_nasepcostr);
                if (PCS_REPLACEAPIENABLEDN1N2)
                {
                    pcs_db_write_op = replace_data_to_db(pcs_dbcollection, pcs_uedbid, pcs_dbrdata, pcs_updatedoc);
                }
                else
                {
                    pcs_db_write_op = delete_create_data_to_db(pcs_dbcollection, pcs_uedbid, pcs_dbrdata, pcs_updatedoc);
                }
                //bson_free(pcs_dbrdata);
            }
            mongoc_client_pool_push(PCS_MONGO_POOL, pcs_mongo_info.pcs_mongoclient);
            if (pcs_db_write_op.rc != OGS_OK)
            {
                ogs_error("PCS Error while uploading n1-n2 transfer data to MongoDB for supi [%s]", sess->smf_ue->supi);
            }
            else
            {
                ogs_info("PCS Successfully uploading n1-n2 transfer data to MongoDB for supi [%s]", sess->smf_ue->supi);
            }

            free(pcs_n1n2data.pcs_nasqosrulestr);
            free(pcs_n1n2data.pcs_nasqosflowstr);
            free(pcs_n1n2data.pcs_nasepcostr);

            /* ogs_pkbuf_free(param.n1smbuf);
            ogs_pkbuf_free(param.n2smbuf);
            ogs_free(pcs_n1n2data.pcs_upfn3ip);
            ogs_free(pcs_n1n2data.pcs_pduaddress);
            ogs_free(pcs_n1n2data.pcs_ie);
            ogs_free(pcs_n1n2data.pcs_gtptunnel);
            ogs_free(pcs_n1n2data.pcs_qosflowsetuprequestitem);*/

            ogs_info("PCS time taken by UE with imsi %s and smf-n4-seid %ld for transaction %s is: %g sec.\n", sess->smf_ue->supi, sess->smf_n4_seid, "N1N2SmfWriteIOTime", pcs_db_write_op.pcs_clk_io);
            ogs_info("PCS time taken by UE with imsi %s and smf-n4-seid %ld for transaction %s is: %g sec.\n", sess->smf_ue->supi, sess->smf_n4_seid, "N1N2SmfWriteSDTime", (((double)(clock() - (pcs_clk_sd))) / CLOCKS_PER_SEC) - (pcs_db_write_op.pcs_clk_io));
            
        }
    }
    else
    {
        ogs_info("PCS Successfully completed n1-n2 transfer transaction for supi [%s]", sess->smf_ue->supi);
    }

    return true;
}

bool smf_namf_comm_handle_n1_n2_message_transfer_failure_notify(
        ogs_sbi_stream_t *stream, ogs_sbi_message_t *recvmsg)
{
    OpenAPI_n1_n2_msg_txfr_failure_notification_t
        *N1N2MsgTxfrFailureNotification = NULL;

    smf_sess_t *sess = NULL;

    ogs_assert(stream);
    ogs_assert(recvmsg);

    N1N2MsgTxfrFailureNotification = recvmsg->N1N2MsgTxfrFailureNotification;
    if (!N1N2MsgTxfrFailureNotification) {
        ogs_error("No N1N2MsgTxfrFailureNotification");
        ogs_assert(true ==
            ogs_sbi_server_send_error(stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                recvmsg, "No N1N2MsgTxfrFailureNotification", NULL));
        return false;
    }

    if (!N1N2MsgTxfrFailureNotification->cause) {
        ogs_error("No Cause");
        ogs_assert(true ==
            ogs_sbi_server_send_error(stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                recvmsg, "No Cause", NULL));
        return false;
    }

    if (!N1N2MsgTxfrFailureNotification->n1n2_msg_data_uri) {
        ogs_error("No n1n2MsgDataUri");
        ogs_assert(true ==
            ogs_sbi_server_send_error(stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                recvmsg, "No n1n2MsgDataUri", NULL));
        return false;
    }

    sess = smf_sess_find_by_paging_n1n2message_location(
        N1N2MsgTxfrFailureNotification->n1n2_msg_data_uri);
    if (!sess) {
        ogs_error("Not found");
        ogs_assert(true ==
            ogs_sbi_server_send_error(stream, OGS_SBI_HTTP_STATUS_NOT_FOUND,
                recvmsg, N1N2MsgTxfrFailureNotification->n1n2_msg_data_uri,
                NULL));
        return false;
    }

    /*
     * TODO:
     *
     * TS23.502 4.2.3.3 Network Triggered Service Request
     *
     * 5. [Conditional] AMF to SMF:
     * Namf_Communication_N1N2Transfer Failure Notification.
     *
     * When a Namf_Communication_N1N2Transfer Failure Notification
     * is received, SMF informs the UPF (if applicable).
     *
     * Procedure for pause of charging at SMF is specified in clause 4.4.4.
     */

    ogs_assert(true == ogs_sbi_send_http_status_no_content(stream));
    return true;
}
