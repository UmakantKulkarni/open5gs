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

#define _GNU_SOURCE
#include <stdio.h>
#include "context.h"
#include "pfcp-path.h"
#include "gtp-path.h"
#include "n4-handler.h"
#include "mongoc.h"
#include "pcs-helper.h"
#include "parson.h"
#include "pcs-thread-pool.h"

void upf_n4_handle_session_establishment_request(
        upf_sess_t *sess, ogs_pfcp_xact_t *xact, 
        ogs_pfcp_session_establishment_request_t *req, pcs_fsm_struct_t *pcs_fsmdata)
{
    ogs_pfcp_pdr_t *pdr = NULL;
    ogs_pfcp_far_t *far = NULL;
    ogs_pfcp_pdr_t *created_pdr[OGS_MAX_NUM_OF_PDR];
    int num_of_created_pdr = 0;
    uint8_t cause_value = 0;
    uint8_t offending_ie_value = 0;
    int i;
    
    ogs_assert(xact);
    ogs_assert(req);

    ogs_debug("Session Establishment Request");

    cause_value = OGS_PFCP_CAUSE_REQUEST_ACCEPTED;

    if (!sess) {
        ogs_error("No Context");
        ogs_pfcp_send_error_message(xact, 0,
                OGS_PFCP_SESSION_ESTABLISHMENT_RESPONSE_TYPE,
                OGS_PFCP_CAUSE_MANDATORY_IE_MISSING, 0);
        return;
    }

    if (PCS_DBCOMMENABLED)
    {
        clock_t pcs_clk_sd = clock();
        char *pcs_dbrdata;
        struct pcs_db_read_op_s pcs_db_read_op;
        pcs_db_read_op.pcs_clk_io = 0;
        if (strcmp(PCS_DBCOLLECTIONAME, "upf") == 0)
        {
            struct pcs_mongo_info_s pcs_mongo_info = pcs_get_mongo_info(pcs_fsmdata);
            pcs_db_read_op = read_data_from_db(pcs_mongo_info.pcs_dbcollection, "_id", sess->smf_n4_seid, -1);
            mongoc_client_pool_push(PCS_MONGO_POOL, pcs_mongo_info.pcs_mongoclient);
            pcs_dbrdata = pcs_db_read_op.pcs_dbrdata;
        }
        else
        {
            if (PCS_ENABLESINGLEREAD)
            {
                pcs_dbrdata = ogs_strdup(req->create_pdr->pdi.framed_route.data);
            }
            else
            {
                struct pcs_mongo_info_s pcs_mongo_info = pcs_get_mongo_info(pcs_fsmdata);
                pcs_db_read_op = read_data_from_db(pcs_mongo_info.pcs_dbcollection, "SMF-N4-SEID", sess->smf_n4_seid, sess->smf_n4_seid);
                mongoc_client_pool_push(PCS_MONGO_POOL, pcs_mongo_info.pcs_mongoclient);
                pcs_dbrdata = pcs_db_read_op.pcs_dbrdata;
            }
        }
        sess->pcs.pcs_dbrdata = ogs_strdup(pcs_dbrdata);
        ogs_info("PCS time taken by UE %ld for transaction %s is: %g sec.\n",  sess->smf_n4_seid, "CreateUpfReadIOTime", pcs_db_read_op.pcs_clk_io);
        ogs_info("PCS time taken by UE %ld for transaction %s is: %g sec.\n",  sess->smf_n4_seid, "CreateUpfReadSDTime", (((double)(clock() - (pcs_clk_sd))) / CLOCKS_PER_SEC) - (pcs_db_read_op.pcs_clk_io));
    }

    for (i = 0; i < OGS_MAX_NUM_OF_PDR; i++) {
        created_pdr[i] = ogs_pfcp_handle_create_pdr(&sess->pfcp,
                &req->create_pdr[i], &cause_value, &offending_ie_value);
        if (created_pdr[i] == NULL)
            break;
    }
    num_of_created_pdr = i;
    if (cause_value != OGS_PFCP_CAUSE_REQUEST_ACCEPTED)
        goto cleanup;

    for (i = 0; i < OGS_MAX_NUM_OF_FAR; i++) {
        if (ogs_pfcp_handle_create_far(&sess->pfcp, &req->create_far[i],
                    &cause_value, &offending_ie_value) == NULL)
            break;
    }
    if (cause_value != OGS_PFCP_CAUSE_REQUEST_ACCEPTED)
        goto cleanup;

    for (i = 0; i < OGS_MAX_NUM_OF_URR; i++) {
        if (ogs_pfcp_handle_create_urr(&sess->pfcp, &req->create_urr[i],
                    &cause_value, &offending_ie_value) == NULL)
            break;
    }
    if (cause_value != OGS_PFCP_CAUSE_REQUEST_ACCEPTED)
        goto cleanup;

    for (i = 0; i < OGS_MAX_NUM_OF_QER; i++) {
        if (ogs_pfcp_handle_create_qer(&sess->pfcp, &req->create_qer[i],
                    &cause_value, &offending_ie_value) == NULL)
            break;
    }
    if (cause_value != OGS_PFCP_CAUSE_REQUEST_ACCEPTED)
        goto cleanup;

    ogs_pfcp_handle_create_bar(&sess->pfcp, &req->create_bar,
                &cause_value, &offending_ie_value);
    if (cause_value != OGS_PFCP_CAUSE_REQUEST_ACCEPTED)
        goto cleanup;

    /* Setup GTP Node */
    ogs_list_for_each(&sess->pfcp.far_list, far) {
        ogs_assert(OGS_ERROR != ogs_pfcp_setup_far_gtpu_node(far));
        if (far->gnode)
            ogs_pfcp_far_f_teid_hash_set(far);
    }
   
    for (i = 0; i < num_of_created_pdr; i++) {
        pdr = created_pdr[i];
        ogs_assert(pdr);

        /* Setup UE IP address */
        if (req->pdn_type.presence && pdr->ue_ip_addr_len) {
            ogs_assert(OGS_PFCP_CAUSE_REQUEST_ACCEPTED ==
                    upf_sess_set_ue_ip(sess, req->pdn_type.u8, pdr));
        }

        /* Setup UPF-N3-TEID & QFI Hash */
        if (pdr->f_teid_len) {
            ogs_pfcp_object_type_e type = OGS_PFCP_OBJ_PDR_TYPE;

            if (ogs_pfcp_self()->up_function_features.ftup &&
                pdr->f_teid.ch) {

                ogs_pfcp_pdr_t *choosed_pdr = NULL;

                if (pdr->f_teid.chid) {
                    type = OGS_PFCP_OBJ_SESS_TYPE;

                    choosed_pdr = ogs_pfcp_pdr_find_by_choose_id(
                            &sess->pfcp, pdr->f_teid.choose_id);
                    if (!choosed_pdr) {
                        pdr->chid = true;
                        pdr->choose_id = pdr->f_teid.choose_id;
                    }
                }

                if (choosed_pdr) {
                    pdr->f_teid_len = choosed_pdr->f_teid_len;
                    memcpy(&pdr->f_teid, &choosed_pdr->f_teid, pdr->f_teid_len);
                } else {
                    ogs_gtpu_resource_t *resource = NULL;
                    resource = ogs_pfcp_find_gtpu_resource(
                            &ogs_gtp_self()->gtpu_resource_list,
                            pdr->dnn, OGS_PFCP_INTERFACE_ACCESS);
                    if (resource) {
                        ogs_assert(OGS_OK ==
                            ogs_pfcp_user_plane_ip_resource_info_to_f_teid(
                            &resource->info, &pdr->f_teid, &pdr->f_teid_len));
                        if (resource->info.teidri)
                            pdr->f_teid.teid = OGS_PFCP_GTPU_INDEX_TO_TEID(
                                    pdr->index, resource->info.teidri,
                                    resource->info.teid_range);
                        else
                            pdr->f_teid.teid = pdr->index;
                    } else {
                        ogs_assert(OGS_OK ==
                            ogs_pfcp_sockaddr_to_f_teid(
                                ogs_gtp_self()->gtpu_addr,
                                ogs_gtp_self()->gtpu_addr6,
                                &pdr->f_teid, &pdr->f_teid_len));
                        pdr->f_teid.teid = pdr->index;
                    }
                }
            }

            ogs_pfcp_object_teid_hash_set(type, pdr);
        }
    }

    /* Send Buffered Packet to gNB/SGW */
    ogs_list_for_each(&sess->pfcp.pdr_list, pdr) {
        if (pdr->src_if == OGS_PFCP_INTERFACE_CORE) { /* Downlink */
            ogs_pfcp_send_buffered_packet(pdr);
        }
    }

    if (PCS_DBCOMMENABLED && !PCS_BLOCKINGAPIENABLEDCREATE && !PCS_ISPROCEDURALSTATELESS && cause_value && strcmp(PCS_DBCOLLECTIONAME, "upf") == 0)
    {
        clock_t pcs_clk_sd = clock();
        sess->pcs.pcs_udsfcreatedone = 0;
        sess->pcs.pcs_udsfupdatedone = 0;
        struct pcs_upf_create_udsf_s *pcs_upfcreateudsf = malloc(sizeof(struct pcs_upf_create_udsf_s));
        pcs_upfcreateudsf->pcs_dbcollection = pcs_fsmdata->pcs_dbcollection;
        (*pcs_upfcreateudsf).pcs_upfn4seid = (uint64_t *)sess->upf_n4_seid;
        pcs_upfcreateudsf->sess = sess;
        //pthread_t pcs_thread1;
        //pthread_create(&pcs_thread1, NULL, pcs_upf_create_udsf, (void*) pcs_upfcreateudsf);
        mt_add_job(PCS_THREADPOOL, &pcs_upf_create_udsf, (void*) pcs_upfcreateudsf);
        ogs_info("PCS Started Create UDSF thread");
        ogs_info("PCS time taken by UE %ld for transaction %s is: %g sec.\n", sess->smf_n4_seid, "CreateUpfWriteSDTime", (((double)(clock() - (pcs_clk_sd))) / CLOCKS_PER_SEC));
    }

    ogs_assert(OGS_OK ==
        upf_pfcp_send_session_establishment_response(
            xact, sess, created_pdr, num_of_created_pdr));

    if (PCS_DBCOMMENABLED && PCS_BLOCKINGAPIENABLEDCREATE && !PCS_ISPROCEDURALSTATELESS && strcmp(PCS_DBCOLLECTIONAME, "upf") == 0)
    {
        clock_t pcs_clk_sd = clock();
        sess->pcs.pcs_udsfcreatedone = 0;
        sess->pcs.pcs_udsfupdatedone = 0;
        struct pcs_upf_create_udsf_s *pcs_upfcreateudsf = malloc(sizeof(struct pcs_upf_create_udsf_s));
        pcs_upfcreateudsf->pcs_dbcollection = pcs_fsmdata->pcs_dbcollection;
        (*pcs_upfcreateudsf).pcs_upfn4seid = (uint64_t *)sess->upf_n4_seid;
        pcs_upfcreateudsf->sess = sess;
        ogs_info("PCS time taken by UE %ld for transaction %s is: %g sec.\n", sess->smf_n4_seid, "CreateUpfWriteSDTime", (((double)(clock() - (pcs_clk_sd))) / CLOCKS_PER_SEC));
        pcs_upf_create_udsf((void*) pcs_upfcreateudsf);
    }
    else if (PCS_DBCOMMENABLED && PCS_BLOCKINGAPIENABLEDCREATE && strcmp(PCS_DBCOLLECTIONAME, "upf") != 0)
    {
        ogs_info("PCS Successfully completed N4 Session Establishment transaction with shared UDSF for Session with N4 SEID [%ld]", sess->smf_n4_seid);
    }
    else if (PCS_DBCOMMENABLED && PCS_BLOCKINGAPIENABLEDCREATE && PCS_ISPROCEDURALSTATELESS && strcmp(PCS_DBCOLLECTIONAME, "upf") == 0)
    {
        clock_t pcs_clk_sd = clock();
        char *pcs_dbrdata = ogs_strdup(sess->pcs.pcs_dbrdata);
        if (pcs_dbrdata == NULL || strlen(pcs_dbrdata) <= 19)
        {
            struct pcs_upf_n4_create pcs_n4createdata = pcs_get_upf_n4_create_data(sess);
            pcs_n4createdata.pcs_smfnodeip = ogs_strdup(ogs_ipv4_to_string(sess->pfcp_node->addr.sin.sin_addr.s_addr));
            pcs_n4createdata.cause_value = cause_value;
            sess->pcs.pcs_n4createdone = 1;
            sess->pcs.pcs_n4createdata = pcs_n4createdata;
            ogs_info("PCS Successfully completed Procedural Stateless N4 Session Establishment transaction for Session with N4 SEID [%ld]", sess->smf_n4_seid);
        }
        else
        {
            ogs_error("PCS UE Context for UE [%ld] is already present in DB", sess->smf_n4_seid);
        }
        ogs_info("PCS time taken by UE %ld for transaction %s is: %g sec.\n", sess->smf_n4_seid, "CreateUpfWriteSDTime", (((double)(clock() - (pcs_clk_sd))) / CLOCKS_PER_SEC));
    }
    else if (!PCS_DBCOMMENABLED)
    {
        ogs_info("PCS Successfully completed N4 Session Establishment transaction for Session with N4 SEID [%ld]", sess->smf_n4_seid);
    }

    return;

cleanup:
    ogs_pfcp_sess_clear(&sess->pfcp);
    ogs_pfcp_send_error_message(xact, sess ? sess->smf_n4_seid : 0,
            OGS_PFCP_SESSION_ESTABLISHMENT_RESPONSE_TYPE,
            cause_value, offending_ie_value);
}

void upf_n4_handle_session_modification_request(
        upf_sess_t *sess, ogs_pfcp_xact_t *xact, 
        ogs_pfcp_session_modification_request_t *req, pcs_fsm_struct_t *pcs_fsmdata)
{
    ogs_pfcp_pdr_t *pdr = NULL;
    ogs_pfcp_far_t *far = NULL;
    ogs_pfcp_pdr_t *created_pdr[OGS_MAX_NUM_OF_PDR];
    int num_of_created_pdr = 0;
    uint8_t cause_value = 0;
    uint8_t offending_ie_value = 0;
    int i;

    ogs_assert(xact);
    ogs_assert(req);

    ogs_debug("Session Modification Request");

    cause_value = OGS_PFCP_CAUSE_REQUEST_ACCEPTED;

    if (!sess) {
        ogs_error("No Context");
        ogs_pfcp_send_error_message(xact, 0,
                OGS_PFCP_SESSION_MODIFICATION_RESPONSE_TYPE,
                OGS_PFCP_CAUSE_SESSION_CONTEXT_NOT_FOUND, 0);
        return;
    }

    /* if (PCS_DBCOMMENABLED && !req->update_far->bar_id.presence && !PCS_BLOCKINGAPIENABLEDCREATE)
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
    } */

    if (PCS_DBCOMMENABLED && !PCS_ISPROCEDURALSTATELESS)
    {
        clock_t pcs_clk_sd = clock();
        char *pcs_dbrdata;
        struct pcs_db_read_op_s pcs_db_read_op;
        pcs_db_read_op.pcs_clk_io = 0;
        if (strcmp(PCS_DBCOLLECTIONAME, "upf") == 0)
        {
            struct pcs_mongo_info_s pcs_mongo_info = pcs_get_mongo_info(pcs_fsmdata);
            pcs_db_read_op = read_data_from_db(pcs_mongo_info.pcs_dbcollection, "_id", sess->smf_n4_seid, -1);
            mongoc_client_pool_push(PCS_MONGO_POOL, pcs_mongo_info.pcs_mongoclient);
            pcs_dbrdata = pcs_db_read_op.pcs_dbrdata;
        }
        else
        {
            if (PCS_ENABLESINGLEREAD)
            {
                pcs_dbrdata = ogs_strdup(req->update_far->update_forwarding_parameters.framed_route.data);
            }
            else
            {
                struct pcs_mongo_info_s pcs_mongo_info = pcs_get_mongo_info(pcs_fsmdata);
                pcs_db_read_op = read_data_from_db(pcs_mongo_info.pcs_dbcollection, "SMF-N4-SEID", sess->smf_n4_seid, sess->smf_n4_seid);
                mongoc_client_pool_push(PCS_MONGO_POOL, pcs_mongo_info.pcs_mongoclient);
                pcs_dbrdata = pcs_db_read_op.pcs_dbrdata;
            }
        }
        sess->pcs.pcs_dbrdata = ogs_strdup(pcs_dbrdata);
        ogs_info("PCS time taken by UE %ld for transaction %s is: %g sec.\n",  sess->smf_n4_seid, "UpdateUpfReadIOTime", pcs_db_read_op.pcs_clk_io);
        ogs_info("PCS time taken by UE %ld for transaction %s is: %g sec.\n",  sess->smf_n4_seid, "UpdateUpfReadSDTime", (((double)(clock() - (pcs_clk_sd))) / CLOCKS_PER_SEC) - (pcs_db_read_op.pcs_clk_io));
    }

    for (i = 0; i < OGS_MAX_NUM_OF_PDR; i++) {
        created_pdr[i] = ogs_pfcp_handle_create_pdr(&sess->pfcp,
                &req->create_pdr[i], &cause_value, &offending_ie_value);
        if (created_pdr[i] == NULL)
            break;
    }
    num_of_created_pdr = i;
    if (cause_value != OGS_PFCP_CAUSE_REQUEST_ACCEPTED)
        goto cleanup;

    for (i = 0; i < OGS_MAX_NUM_OF_PDR; i++) {
        if (ogs_pfcp_handle_update_pdr(&sess->pfcp, &req->update_pdr[i],
                    &cause_value, &offending_ie_value) == NULL)
            break;
    }
    if (cause_value != OGS_PFCP_CAUSE_REQUEST_ACCEPTED)
        goto cleanup;

    for (i = 0; i < OGS_MAX_NUM_OF_PDR; i++) {
        if (ogs_pfcp_handle_remove_pdr(&sess->pfcp, &req->remove_pdr[i],
                &cause_value, &offending_ie_value) == false)
            break;
    }
    if (cause_value != OGS_PFCP_CAUSE_REQUEST_ACCEPTED)
        goto cleanup;

    for (i = 0; i < OGS_MAX_NUM_OF_FAR; i++) {
        if (ogs_pfcp_handle_create_far(&sess->pfcp, &req->create_far[i],
                    &cause_value, &offending_ie_value) == NULL)
            break;
    }
    if (cause_value != OGS_PFCP_CAUSE_REQUEST_ACCEPTED)
        goto cleanup;

    for (i = 0; i < OGS_MAX_NUM_OF_FAR; i++) {
        if (ogs_pfcp_handle_update_far_flags(&sess->pfcp, &req->update_far[i],
                    &cause_value, &offending_ie_value) == NULL)
            break;
    }
    if (cause_value != OGS_PFCP_CAUSE_REQUEST_ACCEPTED)
        goto cleanup;

    /* Send End Marker to gNB */
    ogs_list_for_each(&sess->pfcp.pdr_list, pdr) {
        far = pdr->far;
        if (far && far->smreq_flags.send_end_marker_packets)
            ogs_assert(OGS_ERROR != ogs_pfcp_send_end_marker(pdr));
    }
    /* Clear PFCPSMReq-Flags */
    ogs_list_for_each(&sess->pfcp.far_list, far)
        far->smreq_flags.value = 0;

    for (i = 0; i < OGS_MAX_NUM_OF_FAR; i++) {
        if (ogs_pfcp_handle_update_far(&sess->pfcp, &req->update_far[i],
                    &cause_value, &offending_ie_value) == NULL)
            break;
    }
    if (cause_value != OGS_PFCP_CAUSE_REQUEST_ACCEPTED)
        goto cleanup;

    for (i = 0; i < OGS_MAX_NUM_OF_FAR; i++) {
        if (ogs_pfcp_handle_remove_far(&sess->pfcp, &req->remove_far[i],
                &cause_value, &offending_ie_value) == false)
            break;
    }
    if (cause_value != OGS_PFCP_CAUSE_REQUEST_ACCEPTED)
        goto cleanup;

    for (i = 0; i < OGS_MAX_NUM_OF_URR; i++) {
        if (ogs_pfcp_handle_create_urr(&sess->pfcp, &req->create_urr[i],
                    &cause_value, &offending_ie_value) == NULL)
            break;
    }
    if (cause_value != OGS_PFCP_CAUSE_REQUEST_ACCEPTED)
        goto cleanup;

    for (i = 0; i < OGS_MAX_NUM_OF_URR; i++) {
        if (ogs_pfcp_handle_update_urr(&sess->pfcp, &req->update_urr[i],
                    &cause_value, &offending_ie_value) == NULL)
            break;
    }
    if (cause_value != OGS_PFCP_CAUSE_REQUEST_ACCEPTED)
        goto cleanup;

    for (i = 0; i < OGS_MAX_NUM_OF_URR; i++) {
        if (ogs_pfcp_handle_remove_urr(&sess->pfcp, &req->remove_urr[i],
                &cause_value, &offending_ie_value) == false)
            break;
    }
    if (cause_value != OGS_PFCP_CAUSE_REQUEST_ACCEPTED)
        goto cleanup;

    for (i = 0; i < OGS_MAX_NUM_OF_QER; i++) {
        if (ogs_pfcp_handle_create_qer(&sess->pfcp, &req->create_qer[i],
                    &cause_value, &offending_ie_value) == NULL)
            break;
    }
    if (cause_value != OGS_PFCP_CAUSE_REQUEST_ACCEPTED)
        goto cleanup;

    for (i = 0; i < OGS_MAX_NUM_OF_QER; i++) {
        if (ogs_pfcp_handle_update_qer(&sess->pfcp, &req->update_qer[i],
                    &cause_value, &offending_ie_value) == NULL)
            break;
    }
    if (cause_value != OGS_PFCP_CAUSE_REQUEST_ACCEPTED)
        goto cleanup;

    for (i = 0; i < OGS_MAX_NUM_OF_QER; i++) {
        if (ogs_pfcp_handle_remove_qer(&sess->pfcp, &req->remove_qer[i],
                &cause_value, &offending_ie_value) == false)
            break;
    }
    if (cause_value != OGS_PFCP_CAUSE_REQUEST_ACCEPTED)
        goto cleanup;

    ogs_pfcp_handle_create_bar(&sess->pfcp, &req->create_bar,
                &cause_value, &offending_ie_value);
    if (cause_value != OGS_PFCP_CAUSE_REQUEST_ACCEPTED)
        goto cleanup;

    ogs_pfcp_handle_remove_bar(&sess->pfcp, &req->remove_bar,
            &cause_value, &offending_ie_value);
    if (cause_value != OGS_PFCP_CAUSE_REQUEST_ACCEPTED)
        goto cleanup;

    /* Setup GTP Node */
    ogs_list_for_each(&sess->pfcp.far_list, far) {
        ogs_assert(OGS_ERROR != ogs_pfcp_setup_far_gtpu_node(far));
        if (far->gnode)
            ogs_pfcp_far_f_teid_hash_set(far);
    }

    /* Setup UPF-N3-TEID & QFI Hash */
    for (i = 0; i < num_of_created_pdr; i++) {
        pdr = created_pdr[i];
        ogs_assert(pdr);

        if (pdr->f_teid_len) {
            ogs_pfcp_object_type_e type = OGS_PFCP_OBJ_PDR_TYPE;

            if (ogs_pfcp_self()->up_function_features.ftup &&
                pdr->f_teid.ch) {

                ogs_pfcp_pdr_t *choosed_pdr = NULL;

                if (pdr->f_teid.chid) {
                    type = OGS_PFCP_OBJ_SESS_TYPE;

                    choosed_pdr = ogs_pfcp_pdr_find_by_choose_id(
                            &sess->pfcp, pdr->f_teid.choose_id);
                    if (!choosed_pdr) {
                        pdr->chid = true;
                        pdr->choose_id = pdr->f_teid.choose_id;
                    }
                }

                if (choosed_pdr) {
                    pdr->f_teid_len = choosed_pdr->f_teid_len;
                    memcpy(&pdr->f_teid, &choosed_pdr->f_teid, pdr->f_teid_len);

                } else {
                    ogs_gtpu_resource_t *resource = NULL;
                    resource = ogs_pfcp_find_gtpu_resource(
                            &ogs_gtp_self()->gtpu_resource_list,
                            pdr->dnn, OGS_PFCP_INTERFACE_ACCESS);
                    if (resource) {
                        ogs_assert(OGS_OK ==
                            ogs_pfcp_user_plane_ip_resource_info_to_f_teid(
                            &resource->info, &pdr->f_teid, &pdr->f_teid_len));
                        if (resource->info.teidri)
                            pdr->f_teid.teid = OGS_PFCP_GTPU_INDEX_TO_TEID(
                                    pdr->index, resource->info.teidri,
                                    resource->info.teid_range);
                        else
                            pdr->f_teid.teid = pdr->index;
                    } else {
                        ogs_assert(OGS_OK ==
                            ogs_pfcp_sockaddr_to_f_teid(
                                ogs_gtp_self()->gtpu_addr,
                                ogs_gtp_self()->gtpu_addr6,
                                &pdr->f_teid, &pdr->f_teid_len));
                        pdr->f_teid.teid = pdr->index;
                    }
                }
            }

            ogs_pfcp_object_teid_hash_set(type, pdr);
        }
    }

    /* Send Buffered Packet to gNB/SGW */
    ogs_list_for_each(&sess->pfcp.pdr_list, pdr) {
        if (pdr->src_if == OGS_PFCP_INTERFACE_CORE) { /* Downlink */
            ogs_pfcp_send_buffered_packet(pdr);
        }
    }

    ogs_assert(OGS_OK ==
        upf_pfcp_send_session_modification_response(
            xact, sess, created_pdr, num_of_created_pdr));

    if (PCS_DBCOMMENABLED && !req->update_far->bar_id.presence && PCS_BLOCKINGAPIENABLEDMODIFYRSP && strcmp(PCS_DBCOLLECTIONAME, "upf") == 0)
    {
        clock_t pcs_clk_x = clock();
        struct pcs_db_write_op_s pcs_db_write_op;
        uint64_t pcs_smfn4seid = sess->smf_n4_seid;
        char *pcs_dbrdata;
        double pcs_pfcpestdone = 0;
        struct pcs_upf_n4_create pcs_n4createdata;
        if (!PCS_ISPROCEDURALSTATELESS)
        {
            pcs_dbrdata = ogs_strdup(sess->pcs.pcs_dbrdata);
            JSON_Value *pcs_dbrdatajsonval = json_parse_string(pcs_dbrdata);
            if (json_value_get_type(pcs_dbrdatajsonval) == JSONObject)
            {
                JSON_Object *pcs_dbrdatajsonobj = json_object(pcs_dbrdatajsonval);
                pcs_pfcpestdone = json_object_get_number(pcs_dbrdatajsonobj, "pcs-pfcp-est-done");
            }
            json_value_free(pcs_dbrdatajsonval);
        }
        else
        {
            pcs_pfcpestdone = sess->pcs.pcs_n4createdone;
            if ((int)pcs_pfcpestdone)
            {
                pcs_n4createdata = sess->pcs.pcs_n4createdata;
            }
            else
            {
                ogs_error("PCS PFCP update got triggered without processing PFCP Est request");
            }
        }
        if ((int)pcs_pfcpestdone)
        {
            char *pcs_pfcpie, *pcs_fars, *pcs_var, *pcs_temp, *pcs_docjson;
            char pcs_comma[] = ",";
            char pcs_curlybrace[] = "}";
            char pcs_squarebrace[] = "]";
            int pcs_numfar = 0;

            asprintf(&pcs_fars, "[");
            ogs_list_for_each(&sess->pfcp.far_list, far)
            {
                pcs_numfar = pcs_numfar + 1;
                if (pcs_numfar > 1)
                {
                    pcs_fars = pcs_combine_strings(pcs_fars, pcs_comma);
                }

                asprintf(&pcs_pfcpie, "{\"id\": %d", far->id);
                asprintf(&pcs_var, ", \"apply-action\": %d", far->apply_action);
                pcs_pfcpie = pcs_combine_strings(pcs_pfcpie, pcs_var);
                if (far->dst_if)
                {
                    asprintf(&pcs_var, ", \"dst-if\": %d", far->dst_if);
                    pcs_pfcpie = pcs_combine_strings(pcs_pfcpie, pcs_var);
                }
                if (far->outer_header_creation.addr)
                {
                    asprintf(&pcs_var, ", \"outer-header-creation\": {\"teid\": %d", far->outer_header_creation.teid);
                    pcs_pfcpie = pcs_combine_strings(pcs_pfcpie, pcs_var);
                    pcs_temp = ogs_ipv4_to_string(far->outer_header_creation.addr);
                    asprintf(&pcs_var, ", \"ip-addr\": \"%s\"}", pcs_temp);
                    pcs_pfcpie = pcs_combine_strings(pcs_pfcpie, pcs_var);
                    ogs_free(pcs_temp);
                }
                pcs_pfcpie = pcs_combine_strings(pcs_pfcpie, pcs_curlybrace);
                pcs_fars = pcs_combine_strings(pcs_fars, pcs_pfcpie);
            }
            pcs_fars = pcs_combine_strings(pcs_fars, pcs_squarebrace);
            pcs_n4createdata.pcs_smfnodeip = ogs_strdup(ogs_ipv4_to_string(sess->pfcp_node->addr.sin.sin_addr.s_addr));
            struct pcs_mongo_info_s pcs_mongo_info = pcs_get_mongo_info(pcs_fsmdata);
            mongoc_collection_t *pcs_dbcollection = pcs_mongo_info.pcs_dbcollection;

            if (PCS_ISPROCEDURALSTATELESS)
            {
                asprintf(&pcs_docjson, "{\"_id\": %ld, \"pcs-pfcp-est-done\": 1, \"UPF-Node-IP\": \"%s\", \"SMF-Node-IP\": \"%s\", \"UPF-N4-SEID\": %ld, \"SMF-N4-SEID\": %ld, \"Cause\": %d, \"PDRs\": %s, \"FARs\": %s, \"QERs\": %s, \"BAR\": %s, \"pcs-pfcp-update-done\": 1}", pcs_n4createdata.pcs_smfn4seid, pcs_n4createdata.pcs_upfnodeip, pcs_n4createdata.pcs_smfnodeip, pcs_n4createdata.pcs_upfn4seid, pcs_n4createdata.pcs_smfn4seid, pcs_n4createdata.cause_value, pcs_n4createdata.pcs_pdrs, pcs_fars, pcs_n4createdata.pcs_qers, pcs_n4createdata.pcs_bars);
            
                bson_error_t error;
                bson_t *bson_doc = bson_new_from_json((const uint8_t *)pcs_docjson, -1, &error);
                pcs_db_write_op = insert_data_to_db(pcs_dbcollection, "create", pcs_smfn4seid, bson_doc);
                free(pcs_docjson);
            }
            else
            {
                if (PCS_UPDATEAPIENABLEDMODIFY)
                {
                    bson_error_t error;
                    bson_t *bson_doc_ary = bson_new_from_json((const uint8_t *)pcs_fars, -1, &error);

                    bson_t *bson_doc = BCON_NEW("$set", "{", "pcs-pfcp-update-done", BCON_INT32(1), "FARs", BCON_ARRAY(bson_doc_ary), "}");
                    pcs_db_write_op = insert_data_to_db(pcs_dbcollection, "update", pcs_smfn4seid, bson_doc);
                    bson_destroy(bson_doc_ary);
                }
                else
                {
                    char *pcs_updatedoc;
                    asprintf(&pcs_updatedoc, ", \"pcs-pfcp-update-done\": 1, \"FARs\": %s}", pcs_fars);
                    if (PCS_REPLACEAPIENABLEDMODIFY)
                    {
                        pcs_db_write_op = replace_data_to_db(pcs_dbcollection, pcs_smfn4seid, pcs_dbrdata, pcs_updatedoc);   
                    }
                    else
                    {
                        pcs_db_write_op = delete_create_data_to_db(pcs_dbcollection, pcs_smfn4seid, pcs_dbrdata, pcs_updatedoc);
                    }
                }
            }
            mongoc_client_pool_push(PCS_MONGO_POOL, pcs_mongo_info.pcs_mongoclient);
            
            if (pcs_db_write_op.rc != OGS_OK)
            {
                ogs_error("PCS Error while inserting N4 Session Modification data to MongoDB for Session with N4 SEID [%ld]", sess->smf_n4_seid);
            }
            else
            {
                ogs_info("PCS Successfully inserted N4 Session Modification data to MongoDB for Session with N4 SEID [%ld]", sess->smf_n4_seid);
            }

            free(pcs_var);
            free(pcs_pfcpie);
            free(pcs_fars);

            if (PCS_ISPROCEDURALSTATELESS)
            {
                sess->pcs.pcs_n4updatedone = 1;
                ogs_free(pcs_n4createdata.pcs_upfnodeip);
                ogs_free(pcs_n4createdata.pcs_smfnodeip);
                free(pcs_n4createdata.pcs_pdrs);
                free(pcs_n4createdata.pcs_fars);
            }
            ogs_info("PCS time taken by UE %ld for transaction %s is: %g sec.\n", sess->smf_n4_seid, "UpdateUpfWriteIOTime", pcs_db_write_op.pcs_clk_io);
            ogs_info("PCS time taken by UE %ld for transaction %s is: %g sec.\n", sess->smf_n4_seid, "UpdateUpfWriteSDTime", (((double)(clock() - (pcs_clk_x))) / CLOCKS_PER_SEC) - (pcs_db_write_op.pcs_clk_io));
        }
        else
        {
            ogs_error("PCS PFCP Modify request got triggered without processing PFCP Create request");
        }   
    }
    else if (PCS_DBCOMMENABLED && !req->update_far->bar_id.presence && PCS_BLOCKINGAPIENABLEDMODIFYRSP && strcmp(PCS_DBCOLLECTIONAME, "upf") != 0)
    {
        ogs_info("PCS Successfully completed N4 Session Modification transaction with shared UDSF for Session with N4 SEID [%ld]", sess->smf_n4_seid);
    }
    else if (PCS_DBCOMMENABLED && !req->update_far->bar_id.presence && !PCS_BLOCKINGAPIENABLEDMODIFYRSP)
    {
        if (sess->pcs.pcs_udsfcreatedone)
        {
            clock_t pcs_clk_sd = clock();
            struct pcs_upf_update_udsf_s *pcs_upfupdateudsf = malloc(sizeof(struct pcs_upf_update_udsf_s));
            pcs_upfupdateudsf->pcs_dbcollection = pcs_fsmdata->pcs_dbcollection;
            (*pcs_upfupdateudsf).pcs_upfn4seid = (uint64_t *)sess->upf_n4_seid;
            pcs_upfupdateudsf->pcs_dbrdata = ogs_strdup(sess->pcs.pcs_dbrdata);
            //pthread_t pcs_thread1;
            //pthread_create(&pcs_thread1, NULL, pcs_upf_update_udsf, (void*) pcs_upfupdateudsf);
            mt_add_job(PCS_THREADPOOL, &pcs_upf_update_udsf, (void*) pcs_upfupdateudsf);
            ogs_info("PCS Started Update UDSF thread");
            ogs_info("PCS time taken by UE %ld for transaction %s is: %g sec.\n", sess->smf_n4_seid, "UpdateUpfWriteSDTime", (((double)(clock() - (pcs_clk_sd))) / CLOCKS_PER_SEC));
        }
        else
        {
            ogs_error("pcs_udsfcreatedone thread is not complete");
            sess->pcs.pcs_udsfupdatedone = 0;
        }
    }
    else if (!PCS_DBCOMMENABLED && !req->update_far->bar_id.presence)
    {
        ogs_info("PCS Successfully completed N4 Session Modification transaction for Session with N4 SEID [%ld]", sess->smf_n4_seid);
    }

    return;

cleanup:
    ogs_pfcp_sess_clear(&sess->pfcp);
    ogs_pfcp_send_error_message(xact, sess ? sess->smf_n4_seid : 0,
            OGS_PFCP_SESSION_MODIFICATION_RESPONSE_TYPE,
            cause_value, offending_ie_value);
}

void upf_n4_handle_session_deletion_request(
        upf_sess_t *sess, ogs_pfcp_xact_t *xact,
        ogs_pfcp_session_deletion_request_t *req)
{
    ogs_assert(xact);
    ogs_assert(req);

    ogs_debug("Session Deletion Request");

    if (!sess) {
        ogs_error("No Context");
        ogs_pfcp_send_error_message(xact, 0,
                OGS_PFCP_SESSION_DELETION_RESPONSE_TYPE,
                OGS_PFCP_CAUSE_SESSION_CONTEXT_NOT_FOUND, 0);
        return;
    }

    ogs_assert(sess);

    upf_pfcp_send_session_deletion_response(xact, sess);

    upf_sess_remove(sess);
}

void upf_n4_handle_session_report_response(
        upf_sess_t *sess, ogs_pfcp_xact_t *xact,
        ogs_pfcp_session_report_response_t *rsp)
{
    uint8_t cause_value = 0;

    ogs_assert(xact);
    ogs_assert(rsp);

    ogs_pfcp_xact_commit(xact);

    ogs_debug("Session report resopnse");

    cause_value = OGS_PFCP_CAUSE_REQUEST_ACCEPTED;

    if (!sess) {
        ogs_warn("No Context");
        cause_value = OGS_PFCP_CAUSE_SESSION_CONTEXT_NOT_FOUND;
    }

    if (rsp->cause.presence) {
        if (rsp->cause.u8 != OGS_PFCP_CAUSE_REQUEST_ACCEPTED) {
            ogs_error("PFCP Cause[%d] : Not Accepted", rsp->cause.u8);
            cause_value = rsp->cause.u8;
        }
    } else {
        ogs_error("No Cause");
        cause_value = OGS_PFCP_CAUSE_MANDATORY_IE_MISSING;
    }

    if (cause_value != OGS_PFCP_CAUSE_REQUEST_ACCEPTED) {
        ogs_error("Cause request not accepted[%d]", cause_value);
        return;
    }
}
