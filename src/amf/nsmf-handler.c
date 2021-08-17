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

#include "nsmf-handler.h"
#include "nas-path.h"
#include "ngap-path.h"
#include "sbi-path.h"

#include "gmm-build.h"
#include "pcs-helper.h"
#include "mongoc.h"
#include <pthread.h>

int amf_nsmf_pdusession_handle_create_sm_context(
        amf_sess_t *sess, ogs_sbi_message_t *recvmsg, pcs_fsm_struct_t *pcs_fsmdata)
{
    int rv;

    ogs_assert(sess);
    ogs_assert(recvmsg);

    if (recvmsg->res_status == OGS_SBI_HTTP_STATUS_CREATED) {
        ogs_sbi_message_t message;
        ogs_sbi_header_t header;

        if (!recvmsg->http.location) {
            ogs_error("[%d:%d] No http.location", sess->psi, sess->pti);
            ogs_assert(OGS_OK ==
                nas_5gs_send_back_gsm_message(sess,
                    OGS_5GMM_CAUSE_PAYLOAD_WAS_NOT_FORWARDED,
                    AMF_NAS_BACKOFF_TIME));
            return OGS_ERROR;
        }

        memset(&header, 0, sizeof(header));
        header.uri = recvmsg->http.location;

        rv = ogs_sbi_parse_header(&message, &header);
        if (rv != OGS_OK) {
            ogs_error("[%d:%d] Cannot parse http.location [%s]",
                    sess->psi, sess->pti, recvmsg->http.location);
            ogs_assert(OGS_OK ==
                nas_5gs_send_back_gsm_message(sess,
                    OGS_5GMM_CAUSE_PAYLOAD_WAS_NOT_FORWARDED,
                    AMF_NAS_BACKOFF_TIME));
            return OGS_ERROR;
        }

        if (!message.h.resource.component[1]) {
            ogs_error("[%d:%d] No SmContextRef [%s]",
                    sess->psi, sess->pti, recvmsg->http.location);

            ogs_sbi_header_free(&header);
            ogs_assert(OGS_OK ==
                nas_5gs_send_back_gsm_message(sess,
                    OGS_5GMM_CAUSE_PAYLOAD_WAS_NOT_FORWARDED,
                    AMF_NAS_BACKOFF_TIME));
            return OGS_ERROR;
        }

        if (sess->pdu_session_establishment_accept) {
            /*
             * [1-SERVER] /namf-comm/v1/ue-contexts/{supi}/n1-n2-messages
             * [2-CLIENT] /nsmf-pdusession/v1/sm-contexts
             *
             * If [1-SERVER] arrives before [2-CLIENT],
             * there is no sm-context-ref. The PDU session establishment accept
             * stored in [1-SERVER] is now trasnmitted to gNB.
             */
            amf_ue_t *amf_ue = sess->amf_ue;
            ogs_assert(amf_ue);

            rv = nas_5gs_send_to_gnb(amf_ue,
                    sess->pdu_session_establishment_accept);

            sess->pdu_session_establishment_accept = NULL;

            if (rv != OGS_OK) {
                ogs_error("[%d:%d] nas_5gs_send_to_gnb() failed",
                        sess->psi, sess->pti);

                ogs_sbi_header_free(&header);
                ogs_assert(OGS_OK ==
                    nas_5gs_send_back_gsm_message(sess,
                        OGS_5GMM_CAUSE_PAYLOAD_WAS_NOT_FORWARDED,
                        AMF_NAS_BACKOFF_TIME));
                return OGS_ERROR;
            }
        }

        if (sess->sm_context_ref)
            ogs_free(sess->sm_context_ref);
        sess->sm_context_ref = ogs_strdup(message.h.resource.component[1]);
        ogs_assert(sess->sm_context_ref);

        ogs_sbi_header_free(&header);

    } else {
        OpenAPI_sm_context_create_error_t *SmContextCreateError = NULL;
        OpenAPI_ref_to_binary_data_t *n1SmMsg = NULL;
        ogs_pkbuf_t *n1smbuf = NULL;

        SmContextCreateError = recvmsg->SmContextCreateError;
        if (!SmContextCreateError) {
            ogs_error("[%d:%d] No SmContextCreateError", sess->psi, sess->pti);
            ogs_assert(OGS_OK ==
                nas_5gs_send_back_gsm_message(sess,
                    OGS_5GMM_CAUSE_PAYLOAD_WAS_NOT_FORWARDED,
                    AMF_NAS_BACKOFF_TIME));
            return OGS_ERROR;
        }
        if (!SmContextCreateError->error) {
            ogs_error("[%d:%d] No Error", sess->psi, sess->pti);
            ogs_assert(OGS_OK ==
                nas_5gs_send_back_gsm_message(sess,
                    OGS_5GMM_CAUSE_PAYLOAD_WAS_NOT_FORWARDED,
                    AMF_NAS_BACKOFF_TIME));
            return OGS_ERROR;
        }

        n1SmMsg = SmContextCreateError->n1_sm_msg;
        if (n1SmMsg && n1SmMsg->content_id) {
            n1smbuf = ogs_sbi_find_part_by_content_id(
                    recvmsg, n1SmMsg->content_id);
            if (n1smbuf) {
                /*
                 * NOTE : The pkbuf created in the SBI message will be removed
                 *        from ogs_sbi_message_free(), so it must be copied.
                 */
                n1smbuf = ogs_pkbuf_copy(n1smbuf);
                ogs_assert(n1smbuf);
                ogs_assert(OGS_OK ==
                    nas_5gs_send_gsm_reject(sess,
                        OGS_NAS_PAYLOAD_CONTAINER_N1_SM_INFORMATION, n1smbuf));
                return OGS_ERROR;
            }
        }

        ogs_assert(OGS_OK ==
            nas_5gs_send_back_gsm_message(sess,
                OGS_5GMM_CAUSE_PAYLOAD_WAS_NOT_FORWARDED,
                AMF_NAS_BACKOFF_TIME));
        return OGS_ERROR;
    }

    if (pcs_fsmdata->pcs_dbcommenabled && pcs_fsmdata->pcs_blockingapienabled)
    {
        mongoc_collection_t *pcs_dbcollection = pcs_fsmdata->pcs_dbcollection;
        char *pcs_imsistr = sess->amf_ue->supi;
        pcs_imsistr += 5;
        char *pcs_dbrdata = read_data_from_db(pcs_dbcollection, pcs_imsistr);
        if (strlen(pcs_dbrdata) <= 29 && !pcs_fsmdata->pcs_isproceduralstateless && strcmp(pcs_fsmdata->pcs_dbcollectioname, "amf") == 0)
        {
            struct pcs_amf_create pcs_createdata = pcs_get_amf_create_data(sess);
            int pcs_rv;
            char *pcs_docjson;
            asprintf(&pcs_docjson, "{\"_id\": \"%s\", \"pcs-create-done\": 1, \"supi\": \"%s\", \"sm-context-ref\": \"%s\", \"pdu-session-id\": %d, \"ue-access-type\": %d, \"allowed_pdu_session_status\": %d, \"pei\": \"%s\", \"dnn\": \"%s\", \"s-nssai\": {\"sst\": %d, \"sd\": \"%s\"}, \"plmnid\": \"%s\", \"amf-id\": \"%s\", \"tac\": \"%s\", \"ue-location-timestamp\": %ld, \"ran-ue-ngap-id\": %d, \"amf-ue-ngap-id\": %d, \"gnb-id\": %d, \"rat_type\": \"%s\"}", pcs_imsistr, pcs_createdata.pcs_supi, pcs_createdata.pcs_smcontextref, pcs_createdata.pcs_pdusessionid, pcs_createdata.pcs_amfueaccesstype, pcs_createdata.pcs_amfueallowedpdusessionstatus, pcs_createdata.pcs_amfuepei, pcs_createdata.pcs_amfsessdnn, pcs_createdata.pcs_snssaisst, pcs_createdata.pcs_snssaisd, pcs_createdata.pcs_amfueplmnid, pcs_createdata.pcs_amfueamfid, pcs_createdata.pcs_amfuetac, (long)pcs_createdata.pcs_amfuelocts, pcs_createdata.pcs_ranuengapid, pcs_createdata.pcs_amfuengapid, pcs_createdata.pcs_ranuegnbid, pcs_createdata.pcs_ranuerattype);

            bson_error_t error;
            bson_t *bson_doc = bson_new_from_json((const uint8_t *)pcs_docjson, -1, &error);
            pcs_rv = insert_data_to_db(pcs_dbcollection, "create", pcs_imsistr, bson_doc);
            ogs_free(pcs_createdata.pcs_snssaisd);
            ogs_free(pcs_createdata.pcs_amfueamfid);
            ogs_free(pcs_createdata.pcs_amfuetac);
            free(pcs_createdata.pcs_amfueplmnid);
            free(pcs_docjson);
            if (pcs_rv != OGS_OK)
            {
                ogs_error("PCS Error while inserting Create-SM-Context data to MongoDB for supi [%s]", sess->amf_ue->supi);
            }
            else
            {
                ogs_info("PCS Successfully inserted Create-SM-Context data to MongoDB for supi [%s]", sess->amf_ue->supi);
            }
        }
        else if (!pcs_fsmdata->pcs_isproceduralstateless && strcmp(pcs_fsmdata->pcs_dbcollectioname, "amf") != 0)
        {
            ogs_info("PCS Successfully completed Create transaction with shared UDSF for supi [%s]", sess->amf_ue->supi);
        }
        else if (strlen(pcs_dbrdata) <= 29 && pcs_fsmdata->pcs_isproceduralstateless && strcmp(pcs_fsmdata->pcs_dbcollectioname, "amf") == 0)
        {
            struct pcs_amf_create pcs_createdata = pcs_get_amf_create_data(sess);
            sess->pcs.pcs_createdone = 1;
            sess->pcs.pcs_createdata = pcs_createdata;
            ogs_info("PCS Successfully completed Procedural Stateless Create-SM-Context transaction for supi [%s]", sess->amf_ue->supi);
        }
        else if (pcs_fsmdata->pcs_isproceduralstateless && strcmp(pcs_fsmdata->pcs_dbcollectioname, "amf") != 0)
        {
            ogs_info("PCS Successfully completed Procedural Create transaction with shared UDSF for supi [%s]", sess->amf_ue->supi);
        }
        else
        {
            ogs_error("PCS UE Context for UE [%s] is already present in DB", sess->amf_ue->supi);
        }
    }
    else if (pcs_fsmdata->pcs_dbcommenabled && !pcs_fsmdata->pcs_blockingapienabled)
    {
        pthread_t pcs_thread1;
        struct pcs_amf_create_udsf pcs_amfcreateudsf;
        pcs_amfcreateudsf.pcs_fsmdata = pcs_fsmdata;
        pcs_amfcreateudsf.sess = sess;
        //pcs_amf_create_udsf(pcs_amfcreateudsf);
        pthread_create(&pcs_thread1, NULL, pcs_amf_create_udsf, &pcs_amfcreateudsf);
    }
    else
    {
        ogs_info("PCS Successfully completed Create-SM-Context transaction for supi [%s]", sess->amf_ue->supi);
    }

    return OGS_OK;
}

int amf_nsmf_pdusession_handle_update_sm_context(
        amf_sess_t *sess, int state, ogs_sbi_message_t *recvmsg, pcs_fsm_struct_t *pcs_fsmdata)
{
    amf_ue_t *amf_ue = NULL;
    ogs_assert(sess);
    amf_ue = sess->amf_ue;
    ogs_assert(amf_ue);
    ogs_assert(recvmsg);

    if (recvmsg->res_status == OGS_SBI_HTTP_STATUS_NO_CONTENT ||
        recvmsg->res_status == OGS_SBI_HTTP_STATUS_OK) {

        OpenAPI_sm_context_updated_data_t *SmContextUpdatedData = NULL;
        OpenAPI_ref_to_binary_data_t *n1SmMsg = NULL;
        OpenAPI_ref_to_binary_data_t *n2SmInfo = NULL;
        ogs_pkbuf_t *n1smbuf = NULL;
        ogs_pkbuf_t *n2smbuf = NULL;

        if (recvmsg->SmContextUpdatedData &&
            recvmsg->SmContextUpdatedData->n2_sm_info) {

            SmContextUpdatedData = recvmsg->SmContextUpdatedData;
            ogs_assert(SmContextUpdatedData);
            n2SmInfo = SmContextUpdatedData->n2_sm_info;
            ogs_assert(n2SmInfo);

            if (n2SmInfo->content_id) {
                n2smbuf = ogs_sbi_find_part_by_content_id(
                        recvmsg, n2SmInfo->content_id);
            }

            n1SmMsg = SmContextUpdatedData->n1_sm_msg;
            if (n1SmMsg && n1SmMsg->content_id) {
                n1smbuf = ogs_sbi_find_part_by_content_id(
                        recvmsg, n1SmMsg->content_id);
            }

            switch (SmContextUpdatedData->n2_sm_info_type) {
            case OpenAPI_n2_sm_info_type_PDU_RES_SETUP_REQ:
                if (!n2smbuf) {
                    ogs_error("[%s:%d] No N2 SM Content",
                            amf_ue->supi, sess->psi);
                    nas_5gs_send_gmm_reject(amf_ue,
                            OGS_5GMM_CAUSE_5GS_SERVICES_NOT_ALLOWED);
                    return OGS_ERROR;
                }

                if (state == AMF_UPDATE_SM_CONTEXT_REGISTRATION_REQUEST) {
                    AMF_SESS_STORE_N2_TRANSFER(
                            sess, pdu_session_resource_setup_request,
                            ogs_pkbuf_copy(n2smbuf));

                    if (SESSION_SYNC_DONE(amf_ue,
                            AMF_RELEASE_SM_CONTEXT_REGISTRATION_ACCEPT) &&
                        SESSION_SYNC_DONE(amf_ue,
                            AMF_UPDATE_SM_CONTEXT_REGISTRATION_REQUEST)) {

                        CLEAR_AMF_UE_TIMER(amf_ue->t3550);
                        ogs_assert(OGS_OK ==
                            nas_5gs_send_registration_accept(amf_ue));

                        AMF_UE_CLEAR_N2_TRANSFER(
                                amf_ue, pdu_session_resource_setup_request);
                    }
                } else if (state == AMF_UPDATE_SM_CONTEXT_SERVICE_REQUEST) {
                    AMF_SESS_STORE_N2_TRANSFER(
                            sess, pdu_session_resource_setup_request,
                            ogs_pkbuf_copy(n2smbuf));

                    if (SESSION_SYNC_DONE(amf_ue,
                                AMF_RELEASE_SM_CONTEXT_SERVICE_ACCEPT) &&
                        SESSION_SYNC_DONE(amf_ue,
                                AMF_UPDATE_SM_CONTEXT_SERVICE_REQUEST)) {
                        ogs_assert(OGS_OK ==
                            nas_5gs_send_service_accept(amf_ue));

                        AMF_UE_CLEAR_N2_TRANSFER(
                                amf_ue, pdu_session_resource_setup_request);
                    }
                } else if (state == AMF_UPDATE_SM_CONTEXT_HANDOVER_REQUIRED) {
                    AMF_SESS_STORE_N2_TRANSFER(
                            sess, handover_request, ogs_pkbuf_copy(n2smbuf));

                    if (SESSION_SYNC_DONE(amf_ue,
                                AMF_UPDATE_SM_CONTEXT_HANDOVER_REQUIRED)) {
                        ogs_assert(OGS_OK ==
                            ngap_send_handover_request(amf_ue));

                        AMF_UE_CLEAR_N2_TRANSFER(amf_ue, handover_request);
                    }
                } else {
                    ogs_error("Invalid STATE[%d]", state);
                    ogs_assert_if_reached();
                }
                break;

            case OpenAPI_n2_sm_info_type_PDU_RES_REL_CMD:
                if (!n1smbuf) {
                    ogs_error("[%s:%d] No N1 SM Content [%s]",
                            amf_ue->supi, sess->psi, n1SmMsg->content_id);
                    ogs_assert(OGS_OK ==
                        nas_5gs_send_back_gsm_message(sess,
                            OGS_5GMM_CAUSE_PAYLOAD_WAS_NOT_FORWARDED,
                            AMF_NAS_BACKOFF_TIME));
                    return OGS_ERROR;
                }

                if (!n2smbuf) {
                    ogs_error("[%s:%d] No N2 SM Content",
                            amf_ue->supi, sess->psi);
                    ogs_assert(OGS_OK ==
                        nas_5gs_send_back_gsm_message(sess,
                            OGS_5GMM_CAUSE_PAYLOAD_WAS_NOT_FORWARDED,
                            AMF_NAS_BACKOFF_TIME));
                    return OGS_ERROR;
                }

                /*
                 * NOTE : The pkbuf created in the SBI message will be removed
                 *        from ogs_sbi_message_free(), so it must be copied.
                 */
                n1smbuf = ogs_pkbuf_copy(n1smbuf);
                ogs_assert(n1smbuf);

                n2smbuf = ogs_pkbuf_copy(n2smbuf);
                ogs_assert(n2smbuf);

                ogs_assert(OGS_OK ==
                    nas_send_pdu_session_release_command(
                        sess, n1smbuf, n2smbuf));
                break;

            case OpenAPI_n2_sm_info_type_PATH_SWITCH_REQ_ACK:
                if (!n2smbuf) {
                    ogs_error("[%s:%d] No N2 SM Content",
                            amf_ue->supi, sess->psi);
                    ogs_assert(OGS_OK ==
                        ngap_send_error_indication2(amf_ue,
                            NGAP_Cause_PR_protocol,
                            NGAP_CauseProtocol_semantic_error));
                    return OGS_ERROR;
                }

                AMF_SESS_STORE_N2_TRANSFER(
                        sess, path_switch_request_ack,
                        ogs_pkbuf_copy(n2smbuf));

                if (SESSION_SYNC_DONE(amf_ue, state)) {
                    ogs_assert(OGS_OK ==
                        ngap_send_path_switch_ack(sess));

                    AMF_UE_CLEAR_N2_TRANSFER(amf_ue, path_switch_request_ack);
                }
                break;

            case OpenAPI_n2_sm_info_type_HANDOVER_CMD:
                if (!n2smbuf) {
                    ogs_error("[%s:%d] No N2 SM Content",
                            amf_ue->supi, sess->psi);
                    ogs_assert(OGS_OK ==
                        ngap_send_error_indication2(amf_ue,
                            NGAP_Cause_PR_protocol,
                            NGAP_CauseProtocol_semantic_error));
                    return OGS_ERROR;
                }

                AMF_SESS_STORE_N2_TRANSFER(
                        sess, handover_command, ogs_pkbuf_copy(n2smbuf));

                if (SESSION_SYNC_DONE(amf_ue, state)) {
                    ogs_assert(OGS_OK ==
                        ngap_send_handover_command(amf_ue));

                    AMF_UE_CLEAR_N2_TRANSFER(amf_ue, handover_command);
                }
                break;

            default:
                ogs_error("Not implemented [%d]",
                        SmContextUpdatedData->n2_sm_info_type);
                ogs_assert(OGS_OK ==
                    ngap_send_error_indication2(amf_ue,
                        NGAP_Cause_PR_protocol,
                        NGAP_CauseProtocol_semantic_error));
            }

        } else {

            if (state == AMF_UPDATE_SM_CONTEXT_ACTIVATED) {
                /*
                 * 1. PDUSessionResourceSetupResponse
                 * 2. /nsmf-pdusession/v1/sm-contexts/{smContextRef}/modify
                 * 3. PFCP Session Modifcation Request (OuterHeaderCreation)
                 * 4. PFCP Session Modifcation Response
                 */

                /*
                 * 1. InitialContextSetupResponse
                 * 2. /nsmf-pdusession/v1/sm-contexts/{smContextRef}/modify
                 * 3. PFCP Session Modifcation Request (Apply: FORWARD)
                 * 4. PFCP Session Modifcation Response
                 */

            } else if (state == AMF_UPDATE_SM_CONTEXT_MODIFIED) {
                /*
                 * 1. PDUSessionResourceModifyResponse
                 * 2. /nsmf-pdusession/v1/sm-contexts/{smContextRef}/modify
                 * 3. PFCP Session Modifcation Request
                 * 4. PFCP Session Modifcation Response
                 */

            } else if (state == AMF_UPDATE_SM_CONTEXT_DEACTIVATED) {
                /*
                 * 1. UEContextReleaseRequest
                 * 2. /nsmf-pdusession/v1/sm-contexts/{smContextRef}/modify
                 * 3. PFCP Session Modifcation Request (Apply:Buff & NOCP)
                 * 4. PFCP Session Modifcation Response
                 * 5. UEContextReleaseCommand
                 * 6. UEContextReleaseComplete
                 */

                if (SESSION_SYNC_DONE(amf_ue, state)) {
                    ogs_assert(amf_ue->deactivation.group);

                    ogs_assert(OGS_OK ==
                        ngap_send_amf_ue_context_release_command(amf_ue,
                            amf_ue->deactivation.group,
                            amf_ue->deactivation.cause,
                            NGAP_UE_CTX_REL_NG_REMOVE_AND_UNLINK, 0));
                }

            } else if (state == AMF_UPDATE_SM_CONTEXT_REGISTRATION_REQUEST) {

                /* Not reached here */
                ogs_assert_if_reached();

            } else if (state == AMF_UPDATE_SM_CONTEXT_SERVICE_REQUEST) {

                /* Not reached here */
                ogs_assert_if_reached();

            } else if (state == AMF_UPDATE_SM_CONTEXT_N2_RELEASED) {

                /*
                 * 1. PDUSessionResourceReleaseResponse
                 * 2. /nsmf-pdusession/v1/sm-contexts/{smContextRef}/modify
                 */
                ogs_debug("[%s:%d] Receive Update SM context(N2-RELEASED)",
                        amf_ue->supi, sess->psi);

                sess->n2_released = true;

            } else if (state == AMF_UPDATE_SM_CONTEXT_N1_RELEASED) {
                /*
                 * 1. PDU session release complete
                 *    CLEAR_SM_CONTEXT_REF(sess) in gmm-handler.c
                 * 2. /nsmf-pdusession/v1/sm-contexts/{smContextRef}/modify
                 */

                ogs_debug("[%s:%d] Receive Update SM context(N1-RELEASED)",
                        amf_ue->supi, sess->psi);

                sess->n1_released = true;

            } else if (state ==
                    AMF_UPDATE_SM_CONTEXT_DUPLICATED_PDU_SESSION_ID) {
                /*
                 * 1. PDU session establishment request
                 *    (Duplicated PDU Session ID)
                 * 2. /nsmf-pdusession/v1/sm-contexts/{smContextRef}/modify
                 * 3. POST /nsmf-pdusession/v1/sm-contexts
                 */

                ogs_warn("[%s:%d] Receive Update SM context"
                        "(DUPLICATED_PDU_SESSION_ID)", amf_ue->supi, sess->psi);

                amf_sess_sbi_discover_and_send(OpenAPI_nf_type_SMF,
                        sess, AMF_CREATE_SM_CONTEXT_NO_STATE, NULL,
                        amf_nsmf_pdusession_build_create_sm_context);

            } else if (state == AMF_UPDATE_SM_CONTEXT_PATH_SWITCH_REQUEST) {

                /* Not reached here */
                ogs_assert_if_reached();

            } else if (state == AMF_UPDATE_SM_CONTEXT_HANDOVER_REQUIRED) {

                /* Not reached here */
                ogs_assert_if_reached();

            } else if (state == AMF_UPDATE_SM_CONTEXT_HANDOVER_REQ_ACK) {

                /* Not reached here */
                ogs_assert_if_reached();

            } else if (state == AMF_UPDATE_SM_CONTEXT_HANDOVER_CANCEL) {

                if (SESSION_SYNC_DONE(amf_ue, state)) {
                    ran_ue_t *source_ue = NULL, *target_ue = NULL;

                    source_ue = amf_ue->ran_ue;
                    ogs_assert(source_ue);
                    target_ue = source_ue->target_ue;
                    ogs_assert(target_ue);

                    ogs_assert(OGS_OK ==
                        ngap_send_ran_ue_context_release_command(target_ue,
                            NGAP_Cause_PR_radioNetwork,
                            NGAP_CauseRadioNetwork_handover_cancelled,
                            NGAP_UE_CTX_REL_NG_HANDOVER_CANCEL, 0));
                }

            } else if (state == AMF_UPDATE_SM_CONTEXT_HANDOVER_NOTIFY) {

                /* Nothing to do */

            } else if (state == AMF_REMOVE_S1_CONTEXT_BY_LO_CONNREFUSED) {
                if (SESSION_SYNC_DONE(amf_ue, state)) {
                    ran_ue_t *ran_ue = ran_ue_cycle(amf_ue->ran_ue);

                    amf_ue_deassociate(amf_ue);

                    if (ran_ue) {
                        ogs_debug("    SUPI[%s]", amf_ue->supi);
                        ran_ue_remove(ran_ue);
                    } else {
                        ogs_warn("[%s] RAN-NG Context has already been removed",
                                amf_ue->supi);
                    }
                }

            } else if (state == AMF_REMOVE_S1_CONTEXT_BY_RESET_ALL) {
                if (SESSION_SYNC_DONE(amf_ue, state)) {
                    ran_ue_t *ran_ue = ran_ue_cycle(amf_ue->ran_ue);

                    amf_ue_deassociate(amf_ue);

                    if (ran_ue) {
                        amf_gnb_t *gnb = ran_ue->gnb;
                        ogs_assert(gnb);

                        ogs_debug("    SUPI[%s]", amf_ue->supi);
                        ran_ue_remove(ran_ue);

                        if (ogs_list_count(&gnb->ran_ue_list) == 0)
                            ogs_assert(OGS_OK ==
                                ngap_send_ng_reset_ack(gnb, NULL));

                    } else {
                        ogs_warn("[%s] RAN-NG Context has already been removed",
                                amf_ue->supi);
                    }
                }

            } else if (state == AMF_REMOVE_S1_CONTEXT_BY_RESET_PARTIAL) {
                if (SESSION_SYNC_DONE(amf_ue, state)) {
                    ran_ue_t *iter = NULL;
                    ran_ue_t *ran_ue = ran_ue_cycle(amf_ue->ran_ue);

                    amf_ue_deassociate(amf_ue);

                    if (ran_ue) {
                        amf_gnb_t *gnb = ran_ue->gnb;
                        ogs_assert(gnb);

                        ogs_debug("    SUPI[%s]", amf_ue->supi);
                        ran_ue_remove(ran_ue);

                        ogs_list_for_each(&gnb->ran_ue_list, iter) {
                            if (iter->part_of_ng_reset_requested == true) {
                                /* The GNB_UE context
                                 * where PartOfNG_interface was requested
                                 * still remains */
                                return OGS_OK;
                            }
                        }

                        /* All GNB_UE context
                         * where PartOfNG_interface was requested
                         * REMOVED */
                        ngap_send_to_gnb(
                                gnb, gnb->ng_reset_ack, NGAP_NON_UE_SIGNALLING);

                        /* Clear NG-Reset Ack Buffer */
                        gnb->ng_reset_ack = NULL;

                    } else {
                        ogs_warn("[%s] RAN-NG Context has already been removed",
                                amf_ue->supi);
                    }
                }
            } else {
                ogs_error("Invalid STATE[%d]", state);
                ogs_assert_if_reached();
            }

            /*
             * If resource-status has already been updated by
             *   notify(/namf-callback/v1/{supi}/sm-context-status/{psi})
             * Remove 'amf_sess_t' context to call
             *   amf_nsmf_pdusession_handle_release_sm_context().
             */
            if (sess->n1_released == true &&
                sess->n2_released == true &&
                sess->resource_status == OpenAPI_resource_status_RELEASED) {

                ogs_debug("[%s:%d] SM context remove", amf_ue->supi, sess->psi);
                amf_nsmf_pdusession_handle_release_sm_context(
                        sess, AMF_RELEASE_SM_CONTEXT_NO_STATE);
            }
        }
    } else {
        amf_ue_t *amf_ue = NULL;

        OpenAPI_sm_context_update_error_t *SmContextUpdateError = NULL;
        OpenAPI_ref_to_binary_data_t *n1SmMsg = NULL;
        ogs_pkbuf_t *n1smbuf = NULL;

#if 0 /* Is it needed? */
        OpenAPI_ref_to_binary_data_t *n2SmInfo = NULL;
        ogs_pkbuf_t *n2smbuf = NULL;
#endif

        amf_ue = sess->amf_ue;
        ogs_assert(amf_ue);

        SmContextUpdateError = recvmsg->SmContextUpdateError;
        if (!SmContextUpdateError) {
            ogs_error("[%d:%d] No SmContextUpdateError [%d]",
                    sess->psi, sess->pti, recvmsg->res_status);
            ogs_assert(OGS_OK ==
                ngap_send_error_indication2(amf_ue,
                    NGAP_Cause_PR_protocol, NGAP_CauseProtocol_semantic_error));
            return OGS_ERROR;
        }
        if (!SmContextUpdateError->error) {
            ogs_error("[%d:%d] No Error [%d]",
                    sess->psi, sess->pti, recvmsg->res_status);
            ogs_assert(OGS_OK ==
                ngap_send_error_indication2(amf_ue,
                    NGAP_Cause_PR_protocol, NGAP_CauseProtocol_semantic_error));
            return OGS_ERROR;
        }

        n1SmMsg = SmContextUpdateError->n1_sm_msg;
        if (n1SmMsg && n1SmMsg->content_id) {
            n1smbuf = ogs_sbi_find_part_by_content_id(
                    recvmsg, n1SmMsg->content_id);
            if (n1smbuf) {
                /*
                 * NOTE : The pkbuf created in the SBI message will be removed
                 *        from ogs_sbi_message_free(), so it must be copied.
                 */
                n1smbuf = ogs_pkbuf_copy(n1smbuf);
                ogs_assert(n1smbuf);
                ogs_assert(OGS_OK ==
                    nas_5gs_send_gsm_reject(sess,
                        OGS_NAS_PAYLOAD_CONTAINER_N1_SM_INFORMATION, n1smbuf));
                return OGS_ERROR;
            }
        }

#if 0 /* Is it needed? */
        n2SmInfo = SmContextUpdateError->n2_sm_info;
        if (!n2SmInfo || !n2SmInfo->content_id) {
            ogs_error("[%d:%d] No N2 SM Message", sess->psi, sess->pti);
            ogs_assert(OGS_OK ==
                ngap_send_error_indication2(amf_ue,
                    NGAP_Cause_PR_protocol, NGAP_CauseProtocol_semantic_error));
            return OGS_ERROR;
        }

        n2smbuf = ogs_sbi_find_part_by_content_id(
                recvmsg, n2SmInfo->content_id);
        if (!n2smbuf) {
            ogs_error("[%d:%d] No N2 SM Content [%s]",
                    sess->psi, sess->pti, n2SmInfo->content_id);
            ogs_assert(OGS_OK ==
                ngap_send_error_indication2(amf_ue,
                    NGAP_Cause_PR_protocol, NGAP_CauseProtocol_semantic_error));
            return OGS_ERROR;
        }
#endif

        ogs_error("[%d:%d] HTTP response error [%d]",
                sess->psi, sess->pti, recvmsg->res_status);
        ogs_assert(OGS_OK ==
            ngap_send_error_indication2(amf_ue,
                NGAP_Cause_PR_protocol, NGAP_CauseProtocol_semantic_error));

        return OGS_ERROR;
    }

    if (pcs_fsmdata->pcs_dbcommenabled && recvmsg->res_status == OGS_SBI_HTTP_STATUS_NO_CONTENT && strcmp(pcs_fsmdata->pcs_dbcollectioname, "amf") == 0)
    {
        mongoc_collection_t *pcs_dbcollection = pcs_fsmdata->pcs_dbcollection;
        char *pcs_imsistr = sess->amf_ue->supi;
        pcs_imsistr += 5;
        int pcs_rv;
        struct pcs_amf_update pcs_updatedata = sess->pcs.pcs_updatedata;
        if (pcs_fsmdata->pcs_isproceduralstateless)
        {
            struct pcs_amf_create pcs_createdata = sess->pcs.pcs_createdata;
            struct pcs_amf_n1n2 pcs_n1n2data = sess->pcs.pcs_n1n2data;
            char *pcs_docjson;
            asprintf(&pcs_docjson, "{\"_id\": \"%s\", \"pcs-create-done\": 1, \"supi\": \"%s\", \"sm-context-ref\": \"%s\", \"pdu-session-id\": %d, \"ue-access-type\": %d, \"allowed_pdu_session_status\": %d, \"pei\": \"%s\", \"dnn\": \"%s\", \"s-nssai\": {\"sst\": %d, \"sd\": \"%s\"}, \"plmnid\": \"%s\", \"amf-id\": \"%s\", \"tac\": \"%s\", \"ue-location-timestamp\": %ld, \"ran-ue-ngap-id\": %d, \"amf-ue-ngap-id\": %d, \"gnb-id\": %d, \"rat_type\": \"%s\", \"pcs-n1n2-done\": 1, \"pdu-address\": \"%s\", \"dnn\": \"%s\", \"sesion-ambr\": {\"uplink\": %d, \"ul-unit\": %d, \"downlink\": %d, \"dl-unit\": %d}, \"pdu-session-type\": %d, \"PDUSessionAggregateMaximumBitRate\": {\"pDUSessionAggregateMaximumBitRateUL\": %ld, \"pDUSessionAggregateMaximumBitRateDL\": %ld}, \"QosFlowSetupRequestList\": [{ \"qosFlowIdentifier\": %ld, \"fiveQI\": %ld, \"priorityLevelARP\": %ld, \"pre_emptionCapability\": %ld, \"pre_emptionVulnerability\": %ld}], \"UL_NGU_UP_TNLInformation\": {\"transportLayerAddress\": \"%s\", \"gTP_TEID\": %d}, \"nas-authorized-qos-rules\": %s, \"nas-authorized-qos-flow_descriptions\": %s, \"nas-extended-protocol-configuration-option\": %s, \"pcs-update-done\": 1, \"dLQosFlowPerTNLInformation\": {\"transportLayerAddress\": \"%s\", \"gTP_TEID\": %d, \"associatedQosFlowId\": %ld } }", pcs_imsistr, pcs_createdata.pcs_supi, pcs_createdata.pcs_smcontextref, pcs_createdata.pcs_pdusessionid, pcs_createdata.pcs_amfueaccesstype, pcs_createdata.pcs_amfueallowedpdusessionstatus, pcs_createdata.pcs_amfuepei, pcs_createdata.pcs_amfsessdnn, pcs_createdata.pcs_snssaisst, pcs_createdata.pcs_snssaisd, pcs_createdata.pcs_amfueplmnid, pcs_createdata.pcs_amfueamfid, pcs_createdata.pcs_amfuetac, (long)pcs_createdata.pcs_amfuelocts, pcs_createdata.pcs_ranuengapid, pcs_createdata.pcs_amfuengapid, pcs_createdata.pcs_ranuegnbid, pcs_createdata.pcs_ranuerattype, pcs_n1n2data.pcs_pduaddress, pcs_n1n2data.pcs_dnn, pcs_n1n2data.pcs_sambrulv, pcs_n1n2data.pcs_sambrulu, pcs_n1n2data.pcs_sambrdlv, pcs_n1n2data.pcs_sambrdlu, pcs_n1n2data.pcs_pdusesstype, pcs_n1n2data.pcs_pdusessionaggregatemaximumbitrateul, pcs_n1n2data.pcs_pdusessionaggregatemaximumbitratedl, pcs_n1n2data.pcs_qosflowidentifier, pcs_n1n2data.pcs_fiveqi, pcs_n1n2data.pcs_plarp, pcs_n1n2data.pcs_preemptioncapability, pcs_n1n2data.pcs_preemptionvulnerability, pcs_n1n2data.pcs_upfn3ip, pcs_n1n2data.pcs_upfn3teid, pcs_n1n2data.pcs_nasqosrulestr, pcs_n1n2data.pcs_nasqosflowstr, pcs_n1n2data.pcs_nasepcostr, pcs_updatedata.pcs_upfn3ip, pcs_updatedata.pcs_upfn3teid, pcs_updatedata.pcs_qosflowid);
            bson_error_t error;
            bson_t *bson_doc = bson_new_from_json((const uint8_t *)pcs_docjson, -1, &error);
            pcs_rv = insert_data_to_db(pcs_dbcollection, "create", pcs_imsistr, bson_doc);
            sess->pcs.pcs_updatedone = 1;
            ogs_free(pcs_createdata.pcs_snssaisd);
            ogs_free(pcs_createdata.pcs_amfueamfid);
            ogs_free(pcs_createdata.pcs_amfuetac);
            free(pcs_createdata.pcs_amfueplmnid);
            free(pcs_n1n2data.pcs_nasqosrulestr);
            free(pcs_n1n2data.pcs_nasqosflowstr);
            free(pcs_n1n2data.pcs_nasepcostr);
            /* ogs_free(pcs_n1n2data.pcs_upfn3ip);
            ogs_free(pcs_n1n2data.pcs_pduaddress);
            ogs_free(pcs_n1n2data.pcs_ie);
            ogs_free(pcs_n1n2data.pcs_gtptunnel);
            ogs_free(pcs_n1n2data.pcs_qosflowsetuprequestitem);*/
            free(pcs_docjson);
        }
        else
        {
            if (pcs_fsmdata->pcs_updateapienabledmodify)
            {  
                bson_t *bson_doc = BCON_NEW("$set", "{", "pcs-update-done", BCON_INT32(1), "dLQosFlowPerTNLInformation", "{", "transportLayerAddress", BCON_UTF8(pcs_updatedata.pcs_upfn3ip), "gTP_TEID", BCON_INT32(pcs_updatedata.pcs_upfn3teid), "associatedQosFlowId", BCON_INT64(pcs_updatedata.pcs_qosflowid), "}", "}");
                
                pcs_rv = insert_data_to_db(pcs_dbcollection, "update", pcs_imsistr, bson_doc);
            }
            else
            {
                char *pcs_dbrdata = sess->pcs.pcs_dbrdata;
                char *pcs_updatedoc;
                asprintf(&pcs_updatedoc, ", \"pcs-update-done\": 1, \"dLQosFlowPerTNLInformation\": {\"transportLayerAddress\": \"%s\", \"gTP_TEID\": %d, \"associatedQosFlowId\": %ld } }", pcs_updatedata.pcs_upfn3ip, pcs_updatedata.pcs_upfn3teid, pcs_updatedata.pcs_qosflowid);
                
                pcs_rv = delete_create_data_to_db(pcs_dbcollection, pcs_imsistr, pcs_dbrdata, pcs_updatedoc);
                bson_free(pcs_dbrdata);
            }
        }

        if (pcs_rv != OGS_OK)
        {
            ogs_error("PCS Error while uploading Update-SM-Context data to MongoDB for supi [%s]", sess->amf_ue->supi);
        }
        else
        {
            ogs_info("PCS Successfully uploaded Update-SM-Context data to MongoDB for supi [%s]", sess->amf_ue->supi);
        }
    }
    if (pcs_fsmdata->pcs_dbcommenabled && recvmsg->res_status == OGS_SBI_HTTP_STATUS_NO_CONTENT && strcmp(pcs_fsmdata->pcs_dbcollectioname, "amf") != 0)
    {
        ogs_info("PCS Successfully completed Update-SM-Context transaction with shared UDSF for supi [%s]", sess->amf_ue->supi);
    }
    else if (recvmsg->res_status == OGS_SBI_HTTP_STATUS_NO_CONTENT)
    {
        ogs_info("PCS Successfully completed Update-SM-Context transaction for supi [%s]", sess->amf_ue->supi);
    }

    return OGS_OK;
}

int amf_nsmf_pdusession_handle_release_sm_context(amf_sess_t *sess, int state)
{
    amf_ue_t *amf_ue = NULL;

    ogs_assert(sess);
    amf_ue = sess->amf_ue;
    ogs_assert(amf_ue);

    amf_sess_remove(sess);

    if (state == AMF_RELEASE_SM_CONTEXT_REGISTRATION_ACCEPT) {
        /*
         * 1. Registration request
         * 2. Release All SM contexts
         * 3. Registration accept
         */
        if (SESSION_SYNC_DONE(
                amf_ue, AMF_RELEASE_SM_CONTEXT_REGISTRATION_ACCEPT) &&
            SESSION_SYNC_DONE(
                amf_ue, AMF_UPDATE_SM_CONTEXT_REGISTRATION_REQUEST))

            CLEAR_AMF_UE_TIMER(amf_ue->t3550);
            ogs_assert(OGS_OK ==
                nas_5gs_send_registration_accept(amf_ue));

    } else if (state == AMF_RELEASE_SM_CONTEXT_SERVICE_ACCEPT) {
        /*
         * 1. Service request
         * 2. Release All SM contexts
         * 3. Service accept
         */
        if (SESSION_SYNC_DONE(amf_ue, AMF_RELEASE_SM_CONTEXT_SERVICE_ACCEPT) &&
            SESSION_SYNC_DONE(amf_ue, AMF_UPDATE_SM_CONTEXT_SERVICE_REQUEST))
            ogs_assert(OGS_OK ==
                nas_5gs_send_service_accept(amf_ue));

    } else {

        if (SESSION_SYNC_DONE(amf_ue, state)) {

            if (state == AMF_RELEASE_SM_CONTEXT_NG_CONTEXT_REMOVE) {
                /*
                 * 1. Initial context setup failure
                 * 2. Release All SM contexts
                 * 3. UE Context release command
                 * 4. UE Context release complete
                 */
                ogs_assert(OGS_OK ==
                    ngap_send_amf_ue_context_release_command(amf_ue,
                        NGAP_Cause_PR_nas, NGAP_CauseNas_normal_release,
                        NGAP_UE_CTX_REL_NG_CONTEXT_REMOVE, 0));

            } else if (state == AMF_RELEASE_SM_CONTEXT_REGISTRATION_ACCEPT) {

                /* Not reached here */
                ogs_assert_if_reached();

            } else if (state == AMF_RELEASE_SM_CONTEXT_SERVICE_ACCEPT) {

                /* Not reached here */
                ogs_assert_if_reached();

            } else if (state == AMF_RELEASE_SM_CONTEXT_NO_STATE) {
                /* NO_STATE */

                if (OGS_FSM_CHECK(&amf_ue->sm, gmm_state_authentication)) {

                    ogs_assert(true ==
                        amf_ue_sbi_discover_and_send(
                            OpenAPI_nf_type_AUSF, amf_ue, NULL,
                            amf_nausf_auth_build_authenticate));

                } else if (OGS_FSM_CHECK(&amf_ue->sm,
                            gmm_state_de_registered)) {
                    /*
                     * 1. PDU session release request
                     * 2. PDUSessionResourceReleaseCommand +
                     *    PDU session release command
                     * 3. PDUSessionResourceReleaseREsponse
                     * 4. PDU session release complete
                     * 5. Deregistration request
                     * 6. UEContextReleaseCommand
                     * 7. UEContextReleaseComplete
                     */

                    ogs_assert(OGS_OK ==
                        nas_5gs_send_de_registration_accept(amf_ue));

                } else if (OGS_FSM_CHECK(&amf_ue->sm, gmm_state_registered)) {
                    /*
                     * 1. PDU session release request
                     * 2. PDUSessionResourceReleaseCommand +
                     *    PDU session release command
                     * 3. PDUSessionResourceReleaseREsponse
                     * 4. PDU session release complete
                     *
                     * No Deregistration request in the above step
                     *
                     * So, Nothing to do!
                     */
                } else if (OGS_FSM_CHECK(&amf_ue->sm, gmm_state_exception)) {
                    /*
                     * 1. GMM Exception
                     * 2. Release All SM contexts
                     * 3. UE Context release command
                     * 4. UE Context release complete
                     */
                    ogs_assert(OGS_OK ==
                        ngap_send_amf_ue_context_release_command(amf_ue,
                            NGAP_Cause_PR_nas, NGAP_CauseNas_normal_release,
                            NGAP_UE_CTX_REL_UE_CONTEXT_REMOVE, 0));

                } else if (OGS_FSM_CHECK(&amf_ue->sm,
                                gmm_state_initial_context_setup)) {
                    ogs_fatal("Release SM Context in initial-context-setup");
                    ogs_assert_if_reached();
                } else if (OGS_FSM_CHECK(
                            &amf_ue->sm, gmm_state_security_mode)) {
                    ogs_fatal("Release SM Context in security-mode");
                    ogs_assert_if_reached();
                } else {
                    ogs_fatal("Release SM Context : INVALID STATE");
                    ogs_assert_if_reached();
                }
            } else {
                ogs_fatal("Release SM STATE undefined");
                ogs_assert_if_reached();
            }
        }
    }

    return OGS_OK;
}
