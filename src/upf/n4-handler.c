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
#include "../../lib/sbi/openapi/external/cJSON.h"

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
            upf_sess_set_ue_ip(sess, req->pdn_type.u8, pdr);
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

    ogs_assert(OGS_OK ==
        upf_pfcp_send_session_establishment_response(
            xact, sess, created_pdr, num_of_created_pdr));

    if (pcs_fsmdata->pcs_dbcommenabled)
    {
        mongoc_collection_t *pcs_dbcollection = pcs_fsmdata->pcs_dbcollection;
        uint64_t pcs_smfn4seid = sess->smf_n4_seid;
        char *pcs_upfdbid, *pcs_dbrdata;
        asprintf(&pcs_upfdbid, "%ld", pcs_smfn4seid);
        pcs_dbrdata = read_data_from_db(pcs_dbcollection, pcs_upfdbid);
        if (strlen(pcs_dbrdata) <= 19)
        {
            char *pcs_upfnodeip, *pcs_smfnodeip, *pcs_docjson, *pcs_pfcpie, *pcs_pdrs, *pcs_fars, *pcs_qers, *pcs_var, *pcs_temp;
            char pcs_comma[] = ",";
            char pcs_curlybrace[] = "}";
            char pcs_squarebrace[] = "]";
            int pcs_rv, pcs_numfar = 0, pcs_numqer = 0;
            ogs_pfcp_qer_t *qer = NULL;
            pcs_upfnodeip = ogs_ipv4_to_string(sess->pfcp_node->sock->local_addr.sin.sin_addr.s_addr);
            pcs_smfnodeip = ogs_ipv4_to_string(xact->node->addr.sin.sin_addr.s_addr);
            uint64_t pcs_upfn4seid = sess->upf_n4_seid;
            
            asprintf(&pcs_pdrs, "[");
            for (i = 0; i < num_of_created_pdr; i++)
            {
                pdr = created_pdr[i];
                ogs_assert(pdr);

                if (i > 0)
                {
                    pcs_pdrs = pcs_combine_strings(pcs_pdrs, pcs_comma);
                }

                asprintf(&pcs_pfcpie, "{\"id\": %d", pdr->id);
                asprintf(&pcs_var, ", \"precedence\": %d", pdr->precedence);
                pcs_pfcpie = pcs_combine_strings(pcs_pfcpie, pcs_var);
                asprintf(&pcs_var, ", \"src-if\": %d", pdr->src_if);
                pcs_pfcpie = pcs_combine_strings(pcs_pfcpie, pcs_var);
                if (pdr->f_teid_len)
                {
                    asprintf(&pcs_var, ", \"F-TEID\": {\"fteid\": %d", pdr->f_teid.teid);
                    pcs_pfcpie = pcs_combine_strings(pcs_pfcpie, pcs_var);
                    pcs_temp = ogs_ipv4_to_string(ogs_gtp_self()->gtpu_addr->sin.sin_addr.s_addr);
                    asprintf(&pcs_var, ", \"fteid-ip\": \"%s\"", pcs_temp);
                    pcs_pfcpie = pcs_combine_strings(pcs_pfcpie, pcs_var);
                    ogs_free(pcs_temp);
                    asprintf(&pcs_var, ", \"ip-type\": %d}", pdr->f_teid.ipv4);
                    pcs_pfcpie = pcs_combine_strings(pcs_pfcpie, pcs_var);
                }
                if (pdr->ue_ip_addr.addr)
                {
                    pcs_temp = ogs_ipv4_to_string(pdr->ue_ip_addr.addr);
                    asprintf(&pcs_var, ", \"ue-ip\": \"%s\"", pcs_temp);
                    pcs_pfcpie = pcs_combine_strings(pcs_pfcpie, pcs_var);
                    ogs_free(pcs_temp);
                    asprintf(&pcs_var, ", \"pdn-type\": %d", pdr->ue_ip_addr.ipv4);
                    pcs_pfcpie = pcs_combine_strings(pcs_pfcpie, pcs_var);
                }
                if (pdr->dnn)
                {
                    asprintf(&pcs_var, ", \"dnn\": \"%s\"", pdr->dnn);
                    pcs_pfcpie = pcs_combine_strings(pcs_pfcpie, pcs_var);
                }
                if (sizeof(*pdr->flow_description))
                {
                    asprintf(&pcs_var, ", \"flow-description\": \"%s\"", *pdr->flow_description);
                    if(strstr(pcs_var, "null") == NULL)
                    {
                        pcs_pfcpie = pcs_combine_strings(pcs_pfcpie, pcs_var);
                    }
                }
                if (pdr->qfi)
                {
                    asprintf(&pcs_var, ", \"qfi\": %d", pdr->qfi);
                    pcs_pfcpie = pcs_combine_strings(pcs_pfcpie, pcs_var);
                }
                if (pdr->outer_header_removal_len)
                {
                    asprintf(&pcs_var, ", \"outer-header-removal\": %d", pdr->outer_header_removal.description);
                    pcs_pfcpie = pcs_combine_strings(pcs_pfcpie, pcs_var);
                }
                if (pdr->far)
                {
                    if (pdr->far->id)
                    {
                        asprintf(&pcs_var, ", \"far-id\": %d", pdr->far->id);
                        pcs_pfcpie = pcs_combine_strings(pcs_pfcpie, pcs_var);
                    }
                }
                if (pdr->qer)
                {
                    if (pdr->qer->id)
                    {
                        asprintf(&pcs_var, ", \"qer-id\": %d", pdr->qer->id);
                        pcs_pfcpie = pcs_combine_strings(pcs_pfcpie, pcs_var);
                    }
                }
                pcs_pfcpie = pcs_combine_strings(pcs_pfcpie, pcs_curlybrace);
                pcs_pdrs = pcs_combine_strings(pcs_pdrs, pcs_pfcpie);
            }
            pcs_pdrs = pcs_combine_strings(pcs_pdrs, pcs_squarebrace);

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

            asprintf(&pcs_qers, "[");
            ogs_list_for_each(&sess->pfcp.qer_list, qer)
            {
                pcs_numqer = pcs_numqer + 1;
                if (pcs_numqer > 1)
                {
                    pcs_qers = pcs_combine_strings(pcs_qers, pcs_comma);
                }

                asprintf(&pcs_pfcpie, "{\"id\": %d", qer->id);
                asprintf(&pcs_var, ", \"gate-status\": {\"uplink\": %d, \"downlink\": %d}", qer->gate_status.uplink, qer->gate_status.downlink);
                pcs_pfcpie = pcs_combine_strings(pcs_pfcpie, pcs_var);
                asprintf(&pcs_var, ", \"mbr\": {\"uplink\": %ld, \"downlink\": %ld}", qer->mbr.uplink, qer->mbr.downlink);
                pcs_pfcpie = pcs_combine_strings(pcs_pfcpie, pcs_var);
                asprintf(&pcs_var, ", \"qfi\": %d", qer->qfi);
                pcs_pfcpie = pcs_combine_strings(pcs_pfcpie, pcs_var);
                pcs_pfcpie = pcs_combine_strings(pcs_pfcpie, pcs_curlybrace);
                pcs_qers = pcs_combine_strings(pcs_qers, pcs_pfcpie);
            }
            pcs_qers = pcs_combine_strings(pcs_qers, pcs_squarebrace);

            asprintf(&pcs_pfcpie, "{\"bar-id\": %d}", sess->pfcp.bar->id);

            asprintf(&pcs_docjson, "{\"_id\": \"%ld\", \"pcs-pfcp-est-done\": 1, \"UPF-Node-IP\": \"%s\", \"SMF-Node-IP\": \"%s\", \"UPF-N4-SEID\": %ld, \"SMF-N4-SEID\": %ld, \"Cause\": %d, \"PDRs\": %s, \"FARs\": %s, \"QERs\": %s, \"BAR\": %s}", pcs_smfn4seid, pcs_upfnodeip, pcs_smfnodeip, pcs_upfn4seid, pcs_smfn4seid, cause_value, pcs_pdrs, pcs_fars, pcs_qers, pcs_pfcpie);
            bson_error_t error;
            bson_t *bson_doc = bson_new_from_json((const uint8_t *)pcs_docjson, -1, &error);
            pcs_rv = insert_data_to_db(pcs_dbcollection, "create", pcs_upfdbid, bson_doc);
            ogs_free(pcs_upfnodeip);
            ogs_free(pcs_smfnodeip);
            free(pcs_upfdbid);
            free(pcs_var);
            free(pcs_pfcpie);
            free(pcs_pdrs);
            free(pcs_fars);
            free(pcs_docjson);
            if (pcs_rv != OGS_OK)
            {
                ogs_error("PCS Error while inserting N4 data to MongoDB for Session with N4 SEID [%ld]", sess->smf_n4_seid);
            }
            else
            {
                ogs_info("PCS Successfully inserted N4 data to MongoDB for Session with N4 SEID [%ld]", sess->smf_n4_seid);
            }
        }
        else
        {
            ogs_error("PCS UE Context for UE [%ld] is already present in DB", sess->smf_n4_seid);
        }
        bson_free(pcs_dbrdata);
    }
    else
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

    if (pcs_fsmdata->pcs_dbcommenabled && !req->update_far->bar_id.presence)
    {
        mongoc_collection_t *pcs_dbcollection = pcs_fsmdata->pcs_dbcollection;
        uint64_t pcs_smfn4seid = sess->smf_n4_seid;
        char *pcs_upfdbid, *pcs_dbrdata;
        int pcs_pfcpestdone = 0;
        asprintf(&pcs_upfdbid, "%ld", pcs_smfn4seid);
        pcs_dbrdata = read_data_from_db(pcs_dbcollection, pcs_upfdbid);
        cJSON *pcs_dbreadjson = cJSON_Parse(pcs_dbrdata);
        cJSON *pcs_jsondbval = cJSON_GetObjectItemCaseSensitive(pcs_dbreadjson, "pcs-pfcp-est-done");
        if (cJSON_IsNumber(pcs_jsondbval))
        {
            pcs_pfcpestdone = pcs_jsondbval->valueint;
        }
        if (pcs_pfcpestdone)
        {
            char *pcs_pfcpie, *pcs_fars, *pcs_var, *pcs_temp;
            char pcs_comma[] = ",";
            char pcs_curlybrace[] = "}";
            char pcs_squarebrace[] = "]";
            int pcs_rv, pcs_numfar = 0;

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

            if (pcs_fsmdata->pcs_updateapienabledmodify)
            {
                bson_error_t error;
                bson_t *bson_doc_ary = bson_new_from_json((const uint8_t *)pcs_fars, -1, &error);

                bson_t *bson_doc = BCON_NEW("$set", "{", "pcs-pfcp-update-done", BCON_INT32(1), "FARs", BCON_ARRAY(bson_doc_ary), "}");
                pcs_rv = insert_data_to_db(pcs_dbcollection, "update", pcs_upfdbid, bson_doc);
                bson_destroy(bson_doc_ary);
            }
            else
            {
                char *pcs_updatedoc;
                asprintf(&pcs_updatedoc, ", \"pcs-pfcp-update-done\": 1, \"FARs\": %s}", pcs_fars);
                pcs_rv = delete_create_data_to_db(pcs_dbcollection, pcs_upfdbid, pcs_dbrdata, pcs_updatedoc);
            }
            free(pcs_var);
            free(pcs_upfdbid);
            free(pcs_pfcpie);
            free(pcs_fars);
            if (pcs_rv != OGS_OK)
            {
                ogs_error("PCS Error while inserting N4 update data to MongoDB for Session with N4 SEID [%ld]", sess->smf_n4_seid);
            }
            else
            {
                ogs_info("PCS Successfully inserted N4 update data to MongoDB for Session with N4 SEID [%ld]", sess->smf_n4_seid);
            }
        }
        else
        {
            ogs_error("PCS PFCP Modify request got triggered without processing PFCP Create request");
        }
        bson_free(pcs_dbrdata);
        ogs_free(pcs_dbreadjson);
        ogs_free(pcs_jsondbval);
    }
    else if (!pcs_fsmdata->pcs_dbcommenabled && !req->update_far->bar_id.presence)
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
