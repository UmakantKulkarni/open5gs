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

#include "context.h"
#include "timer.h"
#include "pfcp-path.h"
#include "gtp-path.h"
#include "n4-handler.h"
#include "binding.h"
#include "sbi-path.h"
#include "ngap-path.h"
#include "pcs-helper.h"
#include "mongoc.h"

static uint8_t gtp_cause_from_pfcp(uint8_t pfcp_cause)
{
    switch (pfcp_cause) {
    case OGS_PFCP_CAUSE_REQUEST_ACCEPTED:
        return OGS_GTP_CAUSE_REQUEST_ACCEPTED;
    case OGS_PFCP_CAUSE_REQUEST_REJECTED:
        return OGS_GTP_CAUSE_REQUEST_REJECTED_REASON_NOT_SPECIFIED;
    case OGS_PFCP_CAUSE_SESSION_CONTEXT_NOT_FOUND:
        return OGS_GTP_CAUSE_CONTEXT_NOT_FOUND;
    case OGS_PFCP_CAUSE_MANDATORY_IE_MISSING:
        return OGS_GTP_CAUSE_MANDATORY_IE_MISSING;
    case OGS_PFCP_CAUSE_CONDITIONAL_IE_MISSING:
        return OGS_GTP_CAUSE_CONDITIONAL_IE_MISSING;
    case OGS_PFCP_CAUSE_INVALID_LENGTH:
        return OGS_GTP_CAUSE_INVALID_LENGTH;
    case OGS_PFCP_CAUSE_MANDATORY_IE_INCORRECT:
        return OGS_GTP_CAUSE_MANDATORY_IE_INCORRECT;
    case OGS_PFCP_CAUSE_INVALID_FORWARDING_POLICY:
    case OGS_PFCP_CAUSE_INVALID_F_TEID_ALLOCATION_OPTION:
        return OGS_GTP_CAUSE_INVALID_MESSAGE_FORMAT;
    case OGS_PFCP_CAUSE_NO_ESTABLISHED_PFCP_ASSOCIATION:
        return OGS_GTP_CAUSE_REMOTE_PEER_NOT_RESPONDING;
    case OGS_PFCP_CAUSE_RULE_CREATION_MODIFICATION_FAILURE:
        return OGS_GTP_CAUSE_SEMANTIC_ERROR_IN_THE_TFT_OPERATION;
    case OGS_PFCP_CAUSE_PFCP_ENTITY_IN_CONGESTION:
        return OGS_GTP_CAUSE_GTP_C_ENTITY_CONGESTION;
    case OGS_PFCP_CAUSE_NO_RESOURCES_AVAILABLE:
        return OGS_GTP_CAUSE_NO_RESOURCES_AVAILABLE;
    case OGS_PFCP_CAUSE_SERVICE_NOT_SUPPORTED:
        return OGS_GTP_CAUSE_SERVICE_NOT_SUPPORTED;
    case OGS_PFCP_CAUSE_SYSTEM_FAILURE:
        return OGS_GTP_CAUSE_SYSTEM_FAILURE;
    default:
        return OGS_GTP_CAUSE_SYSTEM_FAILURE;
    }

    return OGS_GTP_CAUSE_SYSTEM_FAILURE;
}

static int sbi_status_from_pfcp(uint8_t pfcp_cause)
{
    switch (pfcp_cause) {
    case OGS_PFCP_CAUSE_REQUEST_ACCEPTED:
        return OGS_SBI_HTTP_STATUS_OK;
    case OGS_PFCP_CAUSE_REQUEST_REJECTED:
        return OGS_SBI_HTTP_STATUS_FORBIDDEN;
    case OGS_PFCP_CAUSE_SESSION_CONTEXT_NOT_FOUND:
        return OGS_SBI_HTTP_STATUS_NOT_FOUND;
    case OGS_PFCP_CAUSE_MANDATORY_IE_MISSING:
    case OGS_PFCP_CAUSE_CONDITIONAL_IE_MISSING:
    case OGS_PFCP_CAUSE_INVALID_LENGTH:
    case OGS_PFCP_CAUSE_MANDATORY_IE_INCORRECT:
    case OGS_PFCP_CAUSE_INVALID_FORWARDING_POLICY:
    case OGS_PFCP_CAUSE_INVALID_F_TEID_ALLOCATION_OPTION:
    case OGS_PFCP_CAUSE_RULE_CREATION_MODIFICATION_FAILURE:
    case OGS_PFCP_CAUSE_PFCP_ENTITY_IN_CONGESTION:
    case OGS_PFCP_CAUSE_NO_RESOURCES_AVAILABLE:
        return OGS_SBI_HTTP_STATUS_BAD_REQUEST;
    case OGS_PFCP_CAUSE_NO_ESTABLISHED_PFCP_ASSOCIATION:
        return OGS_SBI_HTTP_STATUS_GATEWAY_TIMEOUT;
    case OGS_PFCP_CAUSE_SERVICE_NOT_SUPPORTED:
        return OGS_SBI_HTTP_STATUS_SERVICE_UNAVAILABLE;
    case OGS_PFCP_CAUSE_SYSTEM_FAILURE:
        return OGS_SBI_HTTP_STATUS_INTERNAL_SERVER_ERROR;
    default:
        return OGS_SBI_HTTP_STATUS_INTERNAL_SERVER_ERROR;
    }

    return OGS_SBI_HTTP_STATUS_INTERNAL_SERVER_ERROR;
}

void smf_5gc_n4_handle_session_establishment_response(
        smf_sess_t *sess, ogs_pfcp_xact_t *xact,
        ogs_pfcp_session_establishment_response_t *rsp, pcs_fsm_struct_t *pcs_fsmdata)
{
    int i;

    smf_n1_n2_message_transfer_param_t param;
    ogs_sbi_stream_t *stream = NULL;

    uint8_t pfcp_cause_value = OGS_PFCP_CAUSE_REQUEST_ACCEPTED;
    uint8_t offending_ie_value = 0;

    ogs_pfcp_f_seid_t *up_f_seid = NULL;

    ogs_assert(xact);
    ogs_assert(rsp);

    stream = xact->assoc_stream;
    ogs_assert(stream);

    ogs_pfcp_xact_commit(xact);

    if (!sess) {
        ogs_warn("No Context");
        return;
    }

    if (rsp->up_f_seid.presence == 0) {
        ogs_error("No UP F-SEID");
        return;
    }

    if (rsp->created_pdr[0].presence == 0) {
        ogs_error("No Created PDR");
        return;
    }

    if (rsp->cause.presence) {
        if (rsp->cause.u8 != OGS_PFCP_CAUSE_REQUEST_ACCEPTED) {
            ogs_error("PFCP Cause [%d] : Not Accepted", rsp->cause.u8);
            return;
        }
    } else {
        ogs_error("No Cause");
        return;
    }

    ogs_assert(sess);

    pfcp_cause_value = OGS_PFCP_CAUSE_REQUEST_ACCEPTED;
    for (i = 0; i < OGS_MAX_NUM_OF_PDR; i++) {
        ogs_pfcp_pdr_t *pdr = NULL;
        ogs_pfcp_far_t *far = NULL;

        pdr = ogs_pfcp_handle_created_pdr(
                &sess->pfcp, &rsp->created_pdr[i],
                &pfcp_cause_value, &offending_ie_value);

        if (!pdr)
            break;

        far = pdr->far;
        ogs_assert(far);

        if (pdr->src_if == OGS_PFCP_INTERFACE_ACCESS) {
            if (far->dst_if == OGS_PFCP_INTERFACE_CP_FUNCTION)
                ogs_pfcp_far_teid_hash_set(far);

            ogs_assert(sess->pfcp_node);
            if (sess->pfcp_node->up_function_features.ftup &&
                pdr->f_teid_len) {
                if (sess->upf_n3_addr)
                    ogs_freeaddrinfo(sess->upf_n3_addr);
                if (sess->upf_n3_addr6)
                    ogs_freeaddrinfo(sess->upf_n3_addr6);

                ogs_assert(OGS_OK ==
                    ogs_pfcp_f_teid_to_sockaddr(
                        &pdr->f_teid, pdr->f_teid_len,
                        &sess->upf_n3_addr, &sess->upf_n3_addr6));
                sess->upf_n3_teid = pdr->f_teid.teid;
            }
        } else if (pdr->src_if == OGS_PFCP_INTERFACE_CP_FUNCTION) {
            ogs_assert(OGS_ERROR != ogs_pfcp_setup_pdr_gtpu_node(pdr));
        }
    }

    if (pfcp_cause_value != OGS_PFCP_CAUSE_REQUEST_ACCEPTED) {
        ogs_error("PFCP Cause [%d] : Not Accepted", pfcp_cause_value);
        return;
    }

    if (sess->upf_n3_addr == NULL && sess->upf_n3_addr6 == NULL) {
        ogs_error("No UP F-TEID");
        return;
    }

    /* UP F-SEID */
    up_f_seid = rsp->up_f_seid.data;
    ogs_assert(up_f_seid);
    sess->upf_n4_seid = be64toh(up_f_seid->seid);

    memset(&param, 0, sizeof(param));
    param.state = SMF_UE_REQUESTED_PDU_SESSION_ESTABLISHMENT;
    param.n1smbuf = gsm_build_pdu_session_establishment_accept(sess);
    ogs_assert(param.n1smbuf);
    param.n2smbuf = ngap_build_pdu_session_resource_setup_request_transfer(
                        sess);
    ogs_assert(param.n2smbuf);

    smf_namf_comm_send_n1_n2_message_transfer(sess, &param);

    if (pcs_fsmdata->pcs_dbcommenabled)
    {
        mongoc_collection_t *pcs_dbcollection = pcs_fsmdata->pcs_dbcollection;
        char *pcs_dbrdata;
        int pcs_createdone = 0;
        char *pcs_imsistr = sess->amf_ue->supi;
        pcs_imsistr += 5;
        pcs_dbrdata = read_data_from_db(pcs_dbcollection, pcs_imsistr);
        cJSON *pcs_dbreadjson = cJSON_Parse(pcs_dbrdata);
        cJSON *pcs_jsondbval = cJSON_GetObjectItemCaseSensitive(pcs_dbreadjson, "pcs-create-done");
        if (cJSON_IsNumber(pcs_jsondbval))
        {
            pcs_createdone = pcs_jsondbval->valueint;
        }
        if (pcs_createdone)
        {
            int pcs_nas_decode_status = 1, pcs_ngap_decode_status = 1;
            ogs_nas_5gs_message_t pcs_nasmessage;
            pcs_nas_decode_status = ogs_nas_5gsm_decode(&pcs_nasmessage, param.n1smbuf);
            if (pcs_nas_decode_status == 0 && pcs_nasmessage.gsm.h.message_type == 194)
            {
                ogs_nas_5gs_pdu_session_establishment_accept_t *pcs_pdusessionestablishmentaccept = &pcs_nasmessage.gsm.pdu_session_establishment_accept;

                char *pcs_pduaddress = ogs_ipv4_to_string(pcs_pdusessionestablishmentaccept->pdu_address.addr);
                int pcs_sambrulv = pcs_pdusessionestablishmentaccept->session_ambr.uplink.value;
                int pcs_sambrulu = pcs_pdusessionestablishmentaccept->session_ambr.uplink.unit;
                int pcs_sambrdlv = pcs_pdusessionestablishmentaccept->session_ambr.downlink.value;
                int pcs_sambrdlu = pcs_pdusessionestablishmentaccept->session_ambr.downlink.unit;
                int pcs_pdusesstype = pcs_pdusessionestablishmentaccept->selected_pdu_session_type.value;
                int pcs_rv;

                char pcs_hexauthqosrule[OGS_HUGE_LEN];
                decode_buffer_to_hex(pcs_hexauthqosrule, (void *)pcs_pdusessionestablishmentaccept->authorized_qos_rules.buffer, pcs_pdusessionestablishmentaccept->authorized_qos_rules.length);
                char *pcs_nasqosrulestr = decode_nas_qos_rule_hex_to_str(pcs_hexauthqosrule);

                char pcs_hexqosflowdesc[OGS_HUGE_LEN];
                decode_buffer_to_hex(pcs_hexqosflowdesc, (void *)pcs_pdusessionestablishmentaccept->authorized_qos_flow_descriptions.buffer, pcs_pdusessionestablishmentaccept->authorized_qos_flow_descriptions.length);
                char *pcs_nasqosflowstr = decode_nas_qos_flow_hex_to_str(pcs_hexqosflowdesc);

                char pcs_hexepco[OGS_HUGE_LEN];
                decode_buffer_to_hex(pcs_hexepco, (void *)pcs_pdusessionestablishmentaccept->extended_protocol_configuration_options.buffer, pcs_pdusessionestablishmentaccept->extended_protocol_configuration_options.length);
                char *pcs_nasepcostr = decode_nas_epco_hex_to_str(pcs_hexepco);

                int pcs_k, pcs_l;
                char *pcs_upfn3ip;
                uint64_t pcs_pdusessionaggregatemaximumbitrateul, pcs_pdusessionaggregatemaximumbitratedl;
                uint32_t pcs_upfn3teid;
                ogs_ip_t pcs_upfn3ipbitstr;
                long pcs_qosflowidentifier, pcs_fiveqi, pcs_plarp, pcs_preemptioncapability, pcs_preemptionvulnerability;
                NGAP_PDUSessionResourceSetupRequestTransfer_t pcs_n2smmessage;
                NGAP_PDUSessionResourceSetupRequestTransferIEs_t *pcs_ie = NULL;
                NGAP_UPTransportLayerInformation_t *pcs_uptransportlayerinformation = NULL;
                NGAP_GTPTunnel_t *pcs_gtptunnel = NULL;
                NGAP_QosFlowSetupRequestList_t *pcs_qosflowsetuprequestlist = NULL;
                NGAP_QosFlowSetupRequestItem_t *pcs_qosflowsetuprequestitem = NULL;
                NGAP_QosFlowLevelQosParameters_t *pcs_qosflowlevelqosparameters = NULL;
                NGAP_QosCharacteristics_t *pcs_qoscharacteristics = NULL;
                NGAP_AllocationAndRetentionPriority_t *pcs_allocationandretentionpriority;
                pcs_ngap_decode_status = ogs_asn_decode(&asn_DEF_NGAP_PDUSessionResourceSetupRequestTransfer, &pcs_n2smmessage, sizeof(pcs_n2smmessage), param.n2smbuf);
                if (pcs_ngap_decode_status == 0)
                {
                    for (pcs_k = 0; pcs_k < pcs_n2smmessage.protocolIEs.list.count; pcs_k++)
                    {
                        pcs_ie = pcs_n2smmessage.protocolIEs.list.array[pcs_k];
                        switch (pcs_ie->id)
                        {
                        case NGAP_ProtocolIE_ID_id_PDUSessionAggregateMaximumBitRate:
                            pcs_pdusessionaggregatemaximumbitrateul = sess->session.ambr.uplink;
                            pcs_pdusessionaggregatemaximumbitratedl = sess->session.ambr.downlink;
                            break;
                        case NGAP_ProtocolIE_ID_id_QosFlowSetupRequestList:
                            pcs_qosflowsetuprequestlist = &pcs_ie->value.choice.QosFlowSetupRequestList;
                            ogs_assert(pcs_qosflowsetuprequestlist);
                            for (pcs_l = 0; pcs_l < pcs_qosflowsetuprequestlist->list.count; pcs_l++)
                            {
                                pcs_qosflowsetuprequestitem = (struct NGAP_QosFlowSetupRequestItem *)pcs_qosflowsetuprequestlist->list.array[pcs_l];
                                ogs_assert(pcs_qosflowsetuprequestitem);
                                pcs_qosflowlevelqosparameters = &pcs_qosflowsetuprequestitem->qosFlowLevelQosParameters;
                                pcs_qoscharacteristics = &pcs_qosflowlevelqosparameters->qosCharacteristics;
                                pcs_allocationandretentionpriority = &pcs_qosflowlevelqosparameters->allocationAndRetentionPriority;
                                pcs_preemptioncapability = pcs_allocationandretentionpriority->pre_emptionCapability;
                                pcs_preemptionvulnerability = pcs_allocationandretentionpriority->pre_emptionVulnerability;
                                pcs_plarp = pcs_allocationandretentionpriority->priorityLevelARP;
                                pcs_qosflowidentifier = pcs_qosflowsetuprequestitem->qosFlowIdentifier;
                                pcs_fiveqi = pcs_qoscharacteristics->choice.nonDynamic5QI->fiveQI;
                            }
                            break;
                        case NGAP_ProtocolIE_ID_id_UL_NGU_UP_TNLInformation:
                            pcs_uptransportlayerinformation = &pcs_ie->value.choice.UPTransportLayerInformation;
                            pcs_gtptunnel = pcs_uptransportlayerinformation->choice.gTPTunnel;
                            ogs_assert(pcs_gtptunnel);
                            ogs_asn_BIT_STRING_to_ip(&pcs_gtptunnel->transportLayerAddress, &pcs_upfn3ipbitstr);
                            ogs_asn_OCTET_STRING_to_uint32(&pcs_gtptunnel->gTP_TEID, &pcs_upfn3teid);
                            pcs_upfn3ip = ogs_ipv4_to_string(pcs_upfn3ipbitstr.addr);
                            break;
                        }
                    }

                    char *pcs_upfnodeip, *pcs_smfnodeip, *pcs_pfcpie, *pcs_pdrs, *pcs_fars, *pcs_qers, *pcs_var, *pcs_temp;
                    char pcs_comma[] = ",";
                    char pcs_curlybrace[] = "}";
                    char pcs_squarebrace[] = "]";
                    int pcs_numpdr = 0, pcs_numfar = 0, pcs_numqer = 0;
                    ogs_pfcp_pdr_t *pdr = NULL;
                    ogs_pfcp_far_t *far = NULL;
                    ogs_pfcp_qer_t *qer = NULL;
                    pcs_smfnodeip = ogs_ipv4_to_string(sess->pfcp_node->sock->local_addr.sin.sin_addr.s_addr);
                    pcs_upfnodeip = ogs_ipv4_to_string(xact->node->addr.sin.sin_addr.s_addr);
                    uint64_t pcs_upfn4seid = sess->upf_n4_seid;
                    uint64_t pcs_smfn4seid = sess->smf_n4_seid;

                    asprintf(&pcs_pdrs, "[");
                    ogs_list_for_each(&sess->pfcp.pdr_list, pdr)
                    {
                        pcs_numpdr =pcs_numpdr + 1;
                        if (pcs_numpdr > 1)
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

                    if (pcs_fsmdata->pcs_updateapienabledn1n2)
                    {
                        bson_error_t error;
                        bson_t *bson_pdr_ary = bson_new_from_json((const uint8_t *)pcs_pdrs, -1, &error);
                        bson_t *bson_far_ary = bson_new_from_json((const uint8_t *)pcs_fars, -1, &error);
                        bson_t *bson_qer_ary = bson_new_from_json((const uint8_t *)pcs_qers, -1, &error);
                        bson_t *bson_bar_doc = bson_new_from_json((const uint8_t *)pcs_pfcpie, -1, &error);
                        
                        bson_t *bson_doc = BCON_NEW("$set", "{", "pcs-n1n2-done", BCON_INT32(1), "pdu-address", BCON_UTF8(pcs_pduaddress), "sesion-ambr", "{", "uplink", BCON_INT32(pcs_sambrulv), "ul-unit", BCON_INT32(pcs_sambrulu), "downlink", BCON_INT32(pcs_sambrdlv), "dl-unit", BCON_INT32(pcs_sambrdlu), "}", "pdu-session-type", BCON_INT32(pcs_pdusesstype), "PDUSessionAggregateMaximumBitRate", "{", "pDUSessionAggregateMaximumBitRateUL", BCON_INT64(pcs_pdusessionaggregatemaximumbitrateul), "pDUSessionAggregateMaximumBitRateDL", BCON_INT64(pcs_pdusessionaggregatemaximumbitratedl), "}", "QosFlowSetupRequestList", "[", "{", "qosFlowIdentifier", BCON_INT64(pcs_qosflowidentifier), "fiveQI", BCON_INT64(pcs_fiveqi), "priorityLevelARP", BCON_INT64(pcs_plarp), "pre_emptionCapability", BCON_INT64(pcs_preemptioncapability), "pre_emptionVulnerability", BCON_INT64(pcs_preemptionvulnerability), "}", "]", "UL_NGU_UP_TNLInformation", "{", "transportLayerAddress", BCON_UTF8(pcs_upfn3ip), "gTP_TEID", BCON_INT32(pcs_upfn3teid), "}", "nas-authorized-qos-rules", BCON_ARRAY(bson_doc_nas_qos_rule), "nas-authorized-qos-flow_descriptions", BCON_ARRAY(bson_doc_nas_qos_flow), "nas-extended-protocol-configuration-option", BCON_DOCUMENT(bson_doc_nas_epco), "UPF-Node-IP", BCON_UTF8(pcs_upfnodeip), "SMF-Node-IP", BCON_UTF8(pcs_smfnodeip), "UPF-N4-SEID", BCON_INT64(pcs_upfn4seid), "SMF-N4-SEID", BCON_INT64(pcs_smfn4seid), "Cause", BCON_INT32(pfcp_cause_value), "PDRs", BCON_ARRAY(bson_pdr_ary), "FARs", BCON_ARRAY(bson_far_ary), "QERs", BCON_ARRAY(bson_qer_ary), "BAR", BCON_DOCUMENT(bson_bar_doc), "}");

                        pcs_rv = insert_data_to_db(pcs_dbcollection, "update", pcs_imsistr, bson_doc);
                        bson_destroy(bson_doc_nas_qos_rule);
                        bson_destroy(bson_doc_nas_qos_flow);
                        bson_destroy(bson_doc_nas_epco);
                        bson_destroy(bson_pdr_ary);
                        bson_destroy(bson_far_ary);
                        bson_destroy(bson_qer_ary);
                        bson_destroy(bson_bar_doc);
                    }
                    else
                    {
                        char *pcs_updatedoc;
                        asprintf(&pcs_updatedoc, ", \"pcs-n1n2-done\": 1, \"pdu-address\": \"%s\", \"sesion-ambr\": {\"uplink\": %d, \"ul-unit\": %d, \"downlink\": %d, \"dl-unit\": %d}, \"pdu-session-type\": %d, \"PDUSessionAggregateMaximumBitRate\": {\"pDUSessionAggregateMaximumBitRateUL\": %ld, \"pDUSessionAggregateMaximumBitRateDL\": %ld}, \"QosFlowSetupRequestList\": [{ \"qosFlowIdentifier\": %ld, \"fiveQI\": %ld, \"priorityLevelARP\": %ld, \"pre_emptionCapability\": %ld, \"pre_emptionVulnerability\": %ld}], \"UL_NGU_UP_TNLInformation\": {\"transportLayerAddress\": \"%s\", \"gTP_TEID\": %d}, \"nas-authorized-qos-rules\": %s, \"nas-authorized-qos-flow_descriptions\": %s, \"nas-extended-protocol-configuration-option\": %s, \"UPF-Node-IP\": \"%s\", \"SMF-Node-IP\": \"%s\", \"UPF-N4-SEID\": %ld, \"SMF-N4-SEID\": %ld, \"Cause\": %d, \"PDRs\": %s, \"FARs\": %s, \"QERs\": %s, \"BAR\": %s }", pcs_pduaddress, pcs_sambrulv, pcs_sambrulu, pcs_sambrdlv, pcs_sambrdlu, pcs_pdusesstype, pcs_pdusessionaggregatemaximumbitrateul, pcs_pdusessionaggregatemaximumbitratedl, pcs_qosflowidentifier, pcs_fiveqi, pcs_plarp, pcs_preemptioncapability, pcs_preemptionvulnerability, pcs_upfn3ip, pcs_upfn3teid, pcs_nasqosrulestr, pcs_nasqosflowstr, pcs_nasepcostr, pcs_upfnodeip, pcs_smfnodeip, pcs_upfn4seid, pcs_smfn4seid, pfcp_cause_value, pcs_pdrs, pcs_fars, pcs_qers, pcs_pfcpie);
                        pcs_rv = delete_create_data_to_db(pcs_dbcollection, pcs_imsistr, pcs_dbrdata, pcs_updatedoc);
                    }
                    ogs_free(pcs_upfn3ip);
                    ogs_free(pcs_pduaddress);
                    ogs_free(pcs_ie);
                    //ogs_pkbuf_free(param.n1smbuf);
                    //ogs_pkbuf_free(param.n2smbuf);
                    ogs_free(pcs_gtptunnel);
                    ogs_free(pcs_qosflowsetuprequestitem);
                    ogs_free(pcs_upfnodeip);
                    ogs_free(pcs_smfnodeip);
                    free(pcs_var);
                    free(pcs_pfcpie);
                    free(pcs_pdrs);
                    free(pcs_fars);
                    if (pcs_rv != OGS_OK)
                    {
                        ogs_error("PCS Error while updating n1-n2 transfer data to MongoDB for supi [%s]", sess->smf_ue->supi);
                    }
                    else
                    {
                        ogs_info("PCS Successfully updated n1-n2 transfer data to MongoDB for supi [%s]", sess->smf_ue->supi);
                    }
                }
                else
                {
                    ogs_error("PCS ogs_asn_decode failed");
                }
            }
            else
            {
                ogs_error("PCS ogs_nas_5gsm_decode failed");
            }
        }
        else
        {
            ogs_error("PCS n1-n2 request got triggered without processing Create-SM-Context request");
        }
    }
    else
    {
        ogs_info("PCS Successfully completed n1-n2 transfer transaction for supi [%s]", sess->smf_ue->supi);
    }

}

void smf_5gc_n4_handle_session_modification_response(
        smf_sess_t *sess, ogs_pfcp_xact_t *xact,
        ogs_pfcp_session_modification_response_t *rsp, pcs_fsm_struct_t *pcs_fsmdata)
{
    int status = 0;
    uint64_t flags = 0;
    ogs_sbi_stream_t *stream = NULL;
    smf_bearer_t *qos_flow = NULL;

    ogs_assert(xact);
    ogs_assert(rsp);

    flags = xact->modify_flags;
    ogs_assert(flags);

    /* 'stream' could be NULL in smf_qos_flow_binding() */
    stream = xact->assoc_stream;

    /* If smf_5gc_pfcp_send_qos_flow_modification_request() is called */
    qos_flow = xact->data;

    ogs_pfcp_xact_commit(xact);

    status = OGS_SBI_HTTP_STATUS_OK;

    if (!sess) {
        ogs_warn("No Context");
        status = OGS_SBI_HTTP_STATUS_NOT_FOUND;
    }

    if (rsp->cause.presence) {
        if (rsp->cause.u8 != OGS_PFCP_CAUSE_REQUEST_ACCEPTED) {
            ogs_warn("PFCP Cause [%d] : Not Accepted", rsp->cause.u8);
            status = sbi_status_from_pfcp(rsp->cause.u8);
        }
    } else {
        ogs_error("No Cause");
        status = OGS_SBI_HTTP_STATUS_BAD_REQUEST;
    }

    if (status == OGS_SBI_HTTP_STATUS_OK) {
        int i;

        uint8_t pfcp_cause_value = OGS_PFCP_CAUSE_REQUEST_ACCEPTED;
        uint8_t offending_ie_value = 0;

        ogs_assert(sess);
        for (i = 0; i < OGS_MAX_NUM_OF_PDR; i++) {
            ogs_pfcp_pdr_t *pdr = NULL;
            ogs_pfcp_far_t *far = NULL;

            pdr = ogs_pfcp_handle_created_pdr(
                    &sess->pfcp, &rsp->created_pdr[i],
                    &pfcp_cause_value, &offending_ie_value);

            if (!pdr)
                break;

            far = pdr->far;
            ogs_assert(far);

            if (pdr->src_if == OGS_PFCP_INTERFACE_ACCESS) {
                if (far->dst_if == OGS_PFCP_INTERFACE_CP_FUNCTION)
                    ogs_pfcp_far_teid_hash_set(far);

                ogs_assert(sess->pfcp_node);
                if (sess->pfcp_node->up_function_features.ftup &&
                    pdr->f_teid_len) {

                    if (far->dst_if == OGS_PFCP_INTERFACE_CORE) {
                        if (sess->upf_n3_addr)
                            ogs_freeaddrinfo(sess->upf_n3_addr);
                        if (sess->upf_n3_addr6)
                            ogs_freeaddrinfo(sess->upf_n3_addr6);

                        ogs_assert(OGS_OK ==
                            ogs_pfcp_f_teid_to_sockaddr(
                                &pdr->f_teid, pdr->f_teid_len,
                                &sess->upf_n3_addr, &sess->upf_n3_addr6));
                        sess->upf_n3_teid = pdr->f_teid.teid;
                    } else if (far->dst_if == OGS_PFCP_INTERFACE_ACCESS) {
                        if (sess->handover.upf_dl_addr)
                            ogs_freeaddrinfo(sess->handover.upf_dl_addr);
                        if (sess->handover.upf_dl_addr6)
                            ogs_freeaddrinfo(sess->handover.upf_dl_addr6);

                        ogs_assert(OGS_OK ==
                            ogs_pfcp_f_teid_to_sockaddr(
                                &pdr->f_teid, pdr->f_teid_len,
                                &sess->handover.upf_dl_addr,
                                &sess->handover.upf_dl_addr6));
                        sess->handover.upf_dl_teid = pdr->f_teid.teid;
                    }
                }
            } else if (pdr->src_if == OGS_PFCP_INTERFACE_CP_FUNCTION) {
                ogs_assert(OGS_ERROR != ogs_pfcp_setup_pdr_gtpu_node(pdr));
            }
        }

        if (pcs_fsmdata->pcs_dbcommenabled && !sess->paging.ue_requested_pdu_session_establishment_done)
        {
            mongoc_collection_t *pcs_dbcollection = pcs_fsmdata->pcs_dbcollection;
            char *pcs_pfcpie, *pcs_fars, *pcs_var, *pcs_temp, *pcs_dbrdata;
            char pcs_comma[] = ",";
            char pcs_curlybrace[] = "}";
            char pcs_squarebrace[] = "]";
            int pcs_rv, pcs_numfar = 0, pcs_n1n2done = 0;
            ogs_pfcp_far_t *far = NULL;
            uint64_t pcs_smfn4seid = sess->smf_n4_seid;
            char *pcs_imsistr = sess->smf_ue->supi;
            pcs_imsistr += 5;

            pcs_dbrdata = read_data_from_db(pcs_dbcollection, pcs_imsistr);
            cJSON *pcs_dbreadjson = cJSON_Parse(pcs_dbrdata);
            cJSON *pcs_jsondbval = cJSON_GetObjectItemCaseSensitive(pcs_dbreadjson, "pcs-n1n2-done");
            if (cJSON_IsNumber(pcs_jsondbval))
            {
                pcs_n1n2done = pcs_jsondbval->valueint;
            }
            if (pcs_n1n2done)
            {
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
                    bson_t *bson_doc = BCON_NEW("$set", "{", "FARs", BCON_ARRAY(bson_doc_ary), "}");
                    pcs_rv = insert_data_to_db(pcs_dbcollection, "update", pcs_imsistr, bson_doc);
                    bson_destroy(bson_doc_ary);
                }
                else
                {
                    char *pcs_updatedoc;
                    asprintf(&pcs_updatedoc, ", \"pcs-pfcp-update-done\": 1, \"FARs\": %s}", pcs_fars);
                    pcs_rv = delete_create_data_to_db(pcs_dbcollection, pcs_imsistr, pcs_dbrdata, pcs_updatedoc);
                }
                free(pcs_var);
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
                ogs_error("PCS PFCP Session Modify Request got triggered without processing n1-n2/PFCP Session Est request");
            }
        }
        else if (!pcs_fsmdata->pcs_dbcommenabled && !sess->paging.ue_requested_pdu_session_establishment_done)
        {
            ogs_info("PCS Successfully completed N4 Session Modification transaction for Session with N4 SEID [%ld]", sess->smf_n4_seid);
        }

        status = sbi_status_from_pfcp(pfcp_cause_value);
    }

    if (status != OGS_SBI_HTTP_STATUS_OK) {
        char *strerror = ogs_msprintf(
                "PFCP Cause [%d] : Not Accepted", rsp->cause.u8);
        if (stream)
            smf_sbi_send_sm_context_update_error(
                    stream, status, strerror, NULL, NULL, NULL);
        ogs_free(strerror);
        return;
    }

    ogs_assert(sess);

    if (sess->upf_n3_addr == NULL && sess->upf_n3_addr6 == NULL) {
        if (stream)
            smf_sbi_send_sm_context_update_error(
                    stream, status, "No UP F_TEID", NULL, NULL, NULL);
        return;
    }

    if (flags & OGS_PFCP_MODIFY_ACTIVATE) {
        if (flags & OGS_PFCP_MODIFY_XN_HANDOVER) {
            ogs_pkbuf_t *n2smbuf =
                ngap_build_path_switch_request_ack_transfer(sess);
            ogs_assert(n2smbuf);

            smf_sbi_send_sm_context_updated_data_n2smbuf(sess, stream,
                OpenAPI_n2_sm_info_type_PATH_SWITCH_REQ_ACK, n2smbuf);
        } else if (flags & OGS_PFCP_MODIFY_N2_HANDOVER) {

            if (smf_sess_have_indirect_data_forwarding(sess) == true) {
                ogs_assert(OGS_OK ==
                    smf_5gc_pfcp_send_session_modification_request(
                        sess, stream,
                        OGS_PFCP_MODIFY_INDIRECT|OGS_PFCP_MODIFY_REMOVE,
                        ogs_app()->time.handover.duration));
            }

            smf_sbi_send_sm_context_updated_data_ho_state(
                    sess, stream, OpenAPI_ho_state_COMPLETED);

        } else {
            sess->paging.ue_requested_pdu_session_establishment_done = true;
            ogs_assert(true == ogs_sbi_send_http_status_no_content(stream));
        }

    } else if (flags & OGS_PFCP_MODIFY_DEACTIVATE) {
        if (flags & OGS_PFCP_MODIFY_ERROR_INDICATION) {
            smf_n1_n2_message_transfer_param_t param;

            memset(&param, 0, sizeof(param));
            param.state = SMF_ERROR_INDICATON_RECEIVED_FROM_5G_AN;
            param.n2smbuf =
                ngap_build_pdu_session_resource_release_command_transfer(
                    sess, SMF_NGAP_STATE_ERROR_INDICATION_RECEIVED_FROM_5G_AN,
                    NGAP_Cause_PR_nas, NGAP_CauseNas_normal_release);
            ogs_assert(param.n2smbuf);

            param.skip_ind = true;

            smf_namf_comm_send_n1_n2_message_transfer(sess, &param);
        } else {
            smf_sbi_send_sm_context_updated_data_up_cnx_state(
                    sess, stream, OpenAPI_up_cnx_state_DEACTIVATED);
        }
    /*
     * You should not change the following order to support
     * OGS_PFCP_MODIFY_REMOVE|OGS_PFCP_MODIFY_CREATE.
     *
     * 1. if (flags & OGS_PFCP_MODIFY_REMOVE) {
     * 2. } else if (flags & OGS_PFCP_MODIFY_CREATE) {
     *    }
     */
    } else if (flags & OGS_PFCP_MODIFY_REMOVE) {
        if (flags & OGS_PFCP_MODIFY_INDIRECT) {

            smf_sess_delete_indirect_data_forwarding(sess);

            /*
             * OGS_PFCP_MODIFY_CREATE remains.
             * So now we do some extra work to create an indirect tunnel.
             */
            if (flags & OGS_PFCP_MODIFY_CREATE) {
                smf_sess_create_indirect_data_forwarding(sess);

                ogs_assert(OGS_OK ==
                    smf_5gc_pfcp_send_session_modification_request(
                        sess, stream,
                        OGS_PFCP_MODIFY_INDIRECT|OGS_PFCP_MODIFY_CREATE,
                        0));
            } else if (flags & OGS_PFCP_MODIFY_HANDOVER_CANCEL) {
                smf_sbi_send_sm_context_updated_data_ho_state(
                        sess, stream, OpenAPI_ho_state_CANCELLED);
            }
        }
    } else if (flags & OGS_PFCP_MODIFY_CREATE) {
        if (flags & OGS_PFCP_MODIFY_INDIRECT) {
            ogs_pkbuf_t *n2smbuf = ngap_build_handover_command_transfer(sess);
            ogs_assert(n2smbuf);

            smf_sbi_send_sm_context_updated_data(
                sess, stream, 0, OpenAPI_ho_state_PREPARED,
                NULL, OpenAPI_n2_sm_info_type_HANDOVER_CMD, n2smbuf);

        } else {
            smf_n1_n2_message_transfer_param_t param;

            memset(&param, 0, sizeof(param));
            param.state = SMF_NETWORK_REQUESTED_QOS_FLOW_MODIFICATION;
            param.n1smbuf = gsm_build_qos_flow_modification_command(qos_flow,
                    OGS_NAS_PROCEDURE_TRANSACTION_IDENTITY_UNASSIGNED);
            ogs_assert(param.n1smbuf);
            param.n2smbuf =
                ngap_build_qos_flow_resource_modify_request_transfer(qos_flow);
            ogs_assert(param.n2smbuf);

            smf_namf_comm_send_n1_n2_message_transfer(sess, &param);
        }
    }
}

void smf_5gc_n4_handle_session_deletion_response(
        smf_sess_t *sess, ogs_pfcp_xact_t *xact,
        ogs_pfcp_session_deletion_response_t *rsp)
{
    int status = 0;
    int trigger;

    ogs_sbi_stream_t *stream = NULL;

    ogs_sbi_message_t sendmsg;
    ogs_sbi_response_t *response = NULL;

    ogs_assert(xact);
    ogs_assert(rsp);

    stream = xact->assoc_stream;
    ogs_assert(stream);
    trigger = xact->delete_trigger;
    ogs_assert(trigger);

    ogs_pfcp_xact_commit(xact);

    status = OGS_SBI_HTTP_STATUS_OK;

    if (!sess) {
        ogs_warn("No Context");
        status = OGS_SBI_HTTP_STATUS_NOT_FOUND;
    }

    if (rsp->cause.presence) {
        if (rsp->cause.u8 != OGS_PFCP_CAUSE_REQUEST_ACCEPTED) {
            ogs_warn("PFCP Cause [%d] : Not Accepted", rsp->cause.u8);
            status = sbi_status_from_pfcp(rsp->cause.u8);
        }
    } else {
        ogs_error("No Cause");
        status = OGS_SBI_HTTP_STATUS_BAD_REQUEST;
    }

    if (status != OGS_SBI_HTTP_STATUS_OK) {
        char *strerror = ogs_msprintf(
                "PFCP Cause [%d] : Not Accepted", rsp->cause.u8);
        ogs_assert(true ==
            ogs_sbi_server_send_error(stream, status, NULL, NULL, NULL));
        ogs_free(strerror);
        return;
    }

    ogs_assert(sess);

    if (trigger == OGS_PFCP_DELETE_TRIGGER_UE_REQUESTED) {
        ogs_pkbuf_t *n1smbuf = NULL, *n2smbuf = NULL;

        n1smbuf = gsm_build_pdu_session_release_command(
                sess, OGS_5GSM_CAUSE_REGULAR_DEACTIVATION);
        ogs_assert(n1smbuf);

        n2smbuf = ngap_build_pdu_session_resource_release_command_transfer(
                sess, SMF_NGAP_STATE_DELETE_TRIGGER_UE_REQUESTED,
                NGAP_Cause_PR_nas, NGAP_CauseNas_normal_release);
        ogs_assert(n2smbuf);

        smf_sbi_send_sm_context_updated_data_n1_n2_message(sess, stream,
                n1smbuf, OpenAPI_n2_sm_info_type_PDU_RES_REL_CMD, n2smbuf);
    } else {

        memset(&sendmsg, 0, sizeof(sendmsg));

        response = ogs_sbi_build_response(
                &sendmsg, OGS_SBI_HTTP_STATUS_NO_CONTENT);
        ogs_assert(response);
        ogs_assert(true == ogs_sbi_server_send_response(stream, response));

        SMF_SESS_CLEAR(sess);
    }
}

void smf_epc_n4_handle_session_establishment_response(
        smf_sess_t *sess, ogs_pfcp_xact_t *xact,
        ogs_pfcp_session_establishment_response_t *rsp)
{
    uint8_t cause_value = 0;

    smf_bearer_t *bearer = NULL;
    ogs_gtp_xact_t *gtp_xact = NULL;

    ogs_pfcp_f_seid_t *up_f_seid = NULL;

    ogs_assert(xact);
    ogs_assert(rsp);

    gtp_xact = xact->assoc_xact;
    ogs_assert(gtp_xact);

    ogs_pfcp_xact_commit(xact);

    cause_value = OGS_GTP_CAUSE_REQUEST_ACCEPTED;

    if (!sess) {
        ogs_warn("No Context");
        cause_value = OGS_GTP_CAUSE_CONTEXT_NOT_FOUND;
    }

    if (rsp->up_f_seid.presence == 0) {
        ogs_error("No UP F-SEID");
        cause_value = OGS_GTP_CAUSE_MANDATORY_IE_MISSING;
    }

    if (rsp->created_pdr[0].presence == 0) {
        ogs_error("No Created PDR");
        cause_value = OGS_GTP_CAUSE_MANDATORY_IE_MISSING;
    }

    if (rsp->cause.presence) {
        if (rsp->cause.u8 != OGS_PFCP_CAUSE_REQUEST_ACCEPTED) {
            ogs_warn("PFCP Cause [%d] : Not Accepted", rsp->cause.u8);
            cause_value = gtp_cause_from_pfcp(rsp->cause.u8);
        }
    } else {
        ogs_error("No Cause");
        cause_value = OGS_GTP_CAUSE_MANDATORY_IE_MISSING;
    }

    if (cause_value == OGS_GTP_CAUSE_REQUEST_ACCEPTED) {
        int i;

        uint8_t pfcp_cause_value = OGS_PFCP_CAUSE_REQUEST_ACCEPTED;
        uint8_t offending_ie_value = 0;

        ogs_assert(sess);
        for (i = 0; i < OGS_MAX_NUM_OF_PDR; i++) {
            ogs_pfcp_pdr_t *pdr = NULL;
            ogs_pfcp_far_t *far = NULL;

            pdr = ogs_pfcp_handle_created_pdr(
                    &sess->pfcp, &rsp->created_pdr[i],
                    &pfcp_cause_value, &offending_ie_value);

            if (!pdr)
                break;

            far = pdr->far;
            ogs_assert(far);

            if (pdr->src_if == OGS_PFCP_INTERFACE_ACCESS) {
                if (far->dst_if == OGS_PFCP_INTERFACE_CP_FUNCTION)
                    ogs_pfcp_far_teid_hash_set(far);

                bearer = smf_bearer_find_by_pdr_id(sess, pdr->id);
                if (bearer) {
                    ogs_assert(sess->pfcp_node);
                    if (sess->pfcp_node->up_function_features.ftup &&
                        pdr->f_teid_len) {
                        if (bearer->pgw_s5u_addr)
                            ogs_freeaddrinfo(bearer->pgw_s5u_addr);
                        if (bearer->pgw_s5u_addr)
                            ogs_freeaddrinfo(bearer->pgw_s5u_addr6);

                        ogs_assert(OGS_OK ==
                            ogs_pfcp_f_teid_to_sockaddr(
                                &pdr->f_teid, pdr->f_teid_len,
                                &bearer->pgw_s5u_addr, &bearer->pgw_s5u_addr6));
                        bearer->pgw_s5u_teid = pdr->f_teid.teid;
                    }
                }
            } else if (pdr->src_if == OGS_PFCP_INTERFACE_CP_FUNCTION) {
                ogs_assert(OGS_ERROR != ogs_pfcp_setup_pdr_gtpu_node(pdr));
            }
        }

        cause_value = gtp_cause_from_pfcp(pfcp_cause_value);
    }

    if (cause_value != OGS_GTP_CAUSE_REQUEST_ACCEPTED) {
        ogs_gtp_send_error_message(gtp_xact, sess ? sess->sgw_s5c_teid : 0,
                OGS_GTP_CREATE_SESSION_RESPONSE_TYPE, cause_value);
        return;
    }

    ogs_assert(sess);
    bearer = smf_default_bearer_in_sess(sess);
    ogs_assert(bearer);

    if (bearer->pgw_s5u_addr == NULL && bearer->pgw_s5u_addr6 == NULL) {
        ogs_error("No UP F-TEID");
        ogs_gtp_send_error_message(gtp_xact, sess ? sess->sgw_s5c_teid : 0,
                OGS_GTP_CREATE_SESSION_RESPONSE_TYPE,
                OGS_GTP_CAUSE_GRE_KEY_NOT_FOUND);
        return;
    }

    /* UP F-SEID */
    up_f_seid = rsp->up_f_seid.data;
    ogs_assert(up_f_seid);
    sess->upf_n4_seid = be64toh(up_f_seid->seid);

    ogs_assert(OGS_OK == smf_gtp_send_create_session_response(sess, gtp_xact));

    if (sess->gtp_rat_type == OGS_GTP_RAT_TYPE_WLAN) {
        smf_ue_t *smf_ue = NULL;
        smf_sess_t *eutran_sess = NULL;

        smf_ue = sess->smf_ue;
        ogs_assert(smf_ue);

        ogs_assert(sess->session.name);
        eutran_sess = smf_sess_find_by_apn(
                smf_ue, sess->session.name, OGS_GTP_RAT_TYPE_EUTRAN);
        if (eutran_sess) {
            smf_bearer_t *eutran_linked_bearer =
                ogs_list_first(&eutran_sess->bearer_list);
            ogs_assert(eutran_linked_bearer);

            ogs_assert(OGS_OK ==
                smf_gtp_send_delete_bearer_request(
                    eutran_linked_bearer,
                    OGS_NAS_PROCEDURE_TRANSACTION_IDENTITY_UNASSIGNED,
                    OGS_GTP_CAUSE_RAT_CHANGED_FROM_3GPP_TO_NON_3GPP));
        }
    }

    smf_bearer_binding(sess);
}

void smf_epc_n4_handle_session_modification_response(
        smf_sess_t *sess, ogs_pfcp_xact_t *xact,
        ogs_pfcp_session_modification_response_t *rsp)
{
    int i;

    smf_bearer_t *bearer = NULL;
    uint64_t flags = 0;

    uint8_t pfcp_cause_value = OGS_PFCP_CAUSE_REQUEST_ACCEPTED;
    uint8_t offending_ie_value = 0;

    ogs_assert(xact);
    ogs_assert(rsp);

    bearer = xact->data;
    ogs_assert(bearer);
    flags = xact->modify_flags;
    ogs_assert(flags);

    ogs_pfcp_xact_commit(xact);

    if (!sess) {
        ogs_error("No Context");
        return;
    }

    if (rsp->cause.presence) {
        if (rsp->cause.u8 != OGS_PFCP_CAUSE_REQUEST_ACCEPTED) {
            ogs_error("PFCP Cause [%d] : Not Accepted", rsp->cause.u8);
            return;
        }
    } else {
        ogs_error("No Cause");
        return;
    }

    ogs_assert(sess);

    pfcp_cause_value = OGS_PFCP_CAUSE_REQUEST_ACCEPTED;
    for (i = 0; i < OGS_MAX_NUM_OF_PDR; i++) {
        ogs_pfcp_pdr_t *pdr = NULL;
        ogs_pfcp_far_t *far = NULL;

        pdr = ogs_pfcp_handle_created_pdr(
                &sess->pfcp, &rsp->created_pdr[i],
                &pfcp_cause_value, &offending_ie_value);

        if (!pdr)
            break;

        far = pdr->far;
        ogs_assert(far);

        if (pdr->src_if == OGS_PFCP_INTERFACE_ACCESS) {
            if (far->dst_if == OGS_PFCP_INTERFACE_CP_FUNCTION)
                ogs_pfcp_far_teid_hash_set(far);

            ogs_assert(sess->pfcp_node);
            if (sess->pfcp_node->up_function_features.ftup &&
                pdr->f_teid_len) {
                if (bearer->pgw_s5u_addr)
                    ogs_freeaddrinfo(bearer->pgw_s5u_addr);
                if (bearer->pgw_s5u_addr)
                    ogs_freeaddrinfo(bearer->pgw_s5u_addr6);

                ogs_assert(OGS_OK ==
                    ogs_pfcp_f_teid_to_sockaddr(
                        &pdr->f_teid, pdr->f_teid_len,
                        &bearer->pgw_s5u_addr, &bearer->pgw_s5u_addr6));
                bearer->pgw_s5u_teid = pdr->f_teid.teid;
            }
        } else if (pdr->src_if == OGS_PFCP_INTERFACE_CP_FUNCTION) {
            ogs_assert(OGS_ERROR != ogs_pfcp_setup_pdr_gtpu_node(pdr));
        }
    }

    if (pfcp_cause_value != OGS_PFCP_CAUSE_REQUEST_ACCEPTED) {
        ogs_error("PFCP Cause [%d] : Not Accepted", pfcp_cause_value);
        return;
    }

    if (flags & OGS_PFCP_MODIFY_REMOVE) {
        smf_bearer_remove(bearer);

    } else if (flags & OGS_PFCP_MODIFY_CREATE) {
        ogs_assert(OGS_OK == smf_gtp_send_create_bearer_request(bearer));

    } else if (flags & OGS_PFCP_MODIFY_ACTIVATE) {
        /* Nothing */
    }
}

void smf_epc_n4_handle_session_deletion_response(
        smf_sess_t *sess, ogs_pfcp_xact_t *xact,
        ogs_pfcp_session_deletion_response_t *rsp)
{
    uint8_t cause_value = 0;
    ogs_gtp_xact_t *gtp_xact = NULL;

    ogs_assert(xact);
    ogs_assert(rsp);

    gtp_xact = xact->assoc_xact;

    ogs_pfcp_xact_commit(xact);

    cause_value = OGS_GTP_CAUSE_REQUEST_ACCEPTED;

    if (!sess) {
        ogs_warn("No Context");
        cause_value = OGS_GTP_CAUSE_CONTEXT_NOT_FOUND;
    }

    if (rsp->cause.presence) {
        if (rsp->cause.u8 != OGS_PFCP_CAUSE_REQUEST_ACCEPTED) {
            ogs_warn("PFCP Cause[%d] : Not Accepted", rsp->cause.u8);
            cause_value = gtp_cause_from_pfcp(rsp->cause.u8);
        }
    } else {
        ogs_error("No Cause");
        cause_value = OGS_GTP_CAUSE_MANDATORY_IE_MISSING;
    }

    if (cause_value != OGS_GTP_CAUSE_REQUEST_ACCEPTED) {
        if (gtp_xact)
            ogs_gtp_send_error_message(gtp_xact, sess ? sess->sgw_s5c_teid : 0,
                    OGS_GTP_DELETE_SESSION_RESPONSE_TYPE, cause_value);
        return;
    }

    ogs_assert(sess);

    if (gtp_xact) {
        /*
         * 1. MME sends Delete Session Request to SGW/SMF.
         * 2. SMF sends Delete Session Response to SGW/MME.
         */
        ogs_assert(OGS_OK ==
                smf_gtp_send_delete_session_response(sess, gtp_xact));
    } else {
        /*
         * 1. SMF sends Delete Bearer Request(DEFAULT BEARER) to SGW/MME.
         * 2. MME sends Delete Bearer Response to SGW/SMF.
         *
         * OR
         *
         * 1. SMF sends Delete Bearer Request(DEFAULT BEARER) to ePDG.
         * 2. ePDG sends Delete Bearer Response(DEFAULT BEARER) to SMF.
         *
         * Note that the following messages are not processed here.
         * - Bearer Resource Command
         * - Delete Bearer Request/Response with DEDICATED BEARER.
         */
    }

    SMF_SESS_CLEAR(sess);
}

void smf_n4_handle_session_report_request(
        smf_sess_t *sess, ogs_pfcp_xact_t *pfcp_xact,
        ogs_pfcp_session_report_request_t *pfcp_req)
{
    smf_bearer_t *qos_flow = NULL;
    ogs_pfcp_pdr_t *pdr = NULL;

    ogs_pfcp_report_type_t report_type;
    uint8_t cause_value = 0;
    uint16_t pdr_id = 0;

    ogs_assert(pfcp_xact);
    ogs_assert(pfcp_req);

    cause_value = OGS_GTP_CAUSE_REQUEST_ACCEPTED;

    if (!sess) {
        ogs_warn("No Context");
        cause_value = OGS_PFCP_CAUSE_SESSION_CONTEXT_NOT_FOUND;
    }

    if (pfcp_req->report_type.presence == 0) {
        ogs_error("No Report Type");
        cause_value = OGS_GTP_CAUSE_MANDATORY_IE_MISSING;
    }

    if (cause_value != OGS_GTP_CAUSE_REQUEST_ACCEPTED) {
        ogs_pfcp_send_error_message(pfcp_xact, 0,
                OGS_PFCP_SESSION_REPORT_RESPONSE_TYPE,
                cause_value, 0);
        return;
    }

    ogs_assert(sess);
    report_type.value = pfcp_req->report_type.u8;

    if (report_type.downlink_data_report) {
        ogs_pfcp_downlink_data_service_information_t *info = NULL;
        uint8_t paging_policy_indication_value = 0;
        uint8_t qfi = 0;

        if (pfcp_req->downlink_data_report.presence) {
            if (pfcp_req->downlink_data_report.
                    downlink_data_service_information.presence) {
                info = pfcp_req->downlink_data_report.
                    downlink_data_service_information.data;
                if (info) {
                    if (info->qfii && info->ppi) {
                        paging_policy_indication_value =
                            info->paging_policy_indication_value;
                        qfi = info->qfi;
                    } else if (info->qfii) {
                        qfi = info->qfi;
                    } else if (info->ppi) {
                        paging_policy_indication_value =
                            info->paging_policy_indication_value;
                    } else {
                        ogs_error("Invalid Downlink Data Service Information");
                    }

                    if (paging_policy_indication_value) {
                        ogs_warn("Not implement - "
                                "Paging Policy Indication Value");
                        ogs_pfcp_send_error_message(pfcp_xact, 0,
                                OGS_PFCP_SESSION_REPORT_RESPONSE_TYPE,
                                OGS_GTP_CAUSE_SERVICE_NOT_SUPPORTED, 0);
                        return;
                    }

                    if (qfi) {
                        qos_flow = smf_qos_flow_find_by_qfi(sess, qfi);
                        if (!qos_flow)
                            ogs_error("Cannot find the QoS Flow[%d]", qfi);
                    }
                } else {
                    ogs_error("No Info");
                }
            }

            if (pfcp_req->downlink_data_report.pdr_id.presence) {
                pdr = ogs_pfcp_pdr_find(&sess->pfcp,
                    pfcp_req->downlink_data_report.pdr_id.u16);
                if (!pdr)
                    ogs_error("Cannot find the PDR-ID[%d]", pdr_id);

            } else {
                ogs_error("No PDR-ID");
            }
        } else {
            ogs_error("No Downlink Data Report");
        }

        if (!pdr || !qos_flow) {
            ogs_error("No Context [%p:%p]", pdr, qos_flow);
            ogs_pfcp_send_error_message(pfcp_xact, 0,
                    OGS_PFCP_SESSION_REPORT_RESPONSE_TYPE,
                    cause_value, 0);
            return;
        }

        ogs_assert(OGS_OK ==
            smf_pfcp_send_session_report_response(
                pfcp_xact, sess, OGS_PFCP_CAUSE_REQUEST_ACCEPTED));

        if (sess->paging.ue_requested_pdu_session_establishment_done == true) {
            smf_n1_n2_message_transfer_param_t param;

            memset(&param, 0, sizeof(param));
            param.state = SMF_NETWORK_TRIGGERED_SERVICE_REQUEST;
            param.n2smbuf =
                ngap_build_pdu_session_resource_setup_request_transfer(sess);
            ogs_assert(param.n2smbuf);

            param.n1n2_failure_txf_notif_uri = true;

            smf_namf_comm_send_n1_n2_message_transfer(sess, &param);
        }

    } else if (report_type.error_indication_report) {
        smf_ue_t *smf_ue = sess->smf_ue;
        smf_sess_t *error_indication_session = NULL;
        ogs_assert(smf_ue);

        ogs_assert(OGS_OK ==
            smf_pfcp_send_session_report_response(
                pfcp_xact, sess, OGS_PFCP_CAUSE_REQUEST_ACCEPTED));

        error_indication_session = smf_sess_find_by_error_indication_report(
                smf_ue, &pfcp_req->error_indication_report);

        if (!error_indication_session) return;

        ogs_assert(OGS_OK ==
            smf_5gc_pfcp_send_session_modification_request(
                error_indication_session, NULL,
                OGS_PFCP_MODIFY_DL_ONLY|OGS_PFCP_MODIFY_DEACTIVATE|
                OGS_PFCP_MODIFY_ERROR_INDICATION,
                0));

    } else {
        ogs_error("Not supported Report Type[%d]", report_type.value);
        ogs_assert(OGS_OK ==
            smf_pfcp_send_session_report_response(
                pfcp_xact, sess, OGS_PFCP_CAUSE_SYSTEM_FAILURE));
    }
}
