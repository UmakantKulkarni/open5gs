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

#include "test-common.h"

ogs_pkbuf_t *test_s2b_build_create_session_request(
        uint8_t type, test_sess_t *sess)
{
    int rv;
    ogs_session_t *session = NULL;
    test_ue_t *test_ue = NULL;
    test_bearer_t *bearer = NULL;
    ogs_gtp_message_t gtp_message;
    ogs_gtp_create_session_request_t *req = &gtp_message.create_session_request;

    uint8_t msisdn_buf[OGS_MAX_MSISDN_LEN];
    int msisdn_len;

    ogs_gtp_uli_t uli;
    char uli_buf[OGS_GTP_MAX_ULI_LEN];
    ogs_gtp_f_teid_t test_s2b_c_teid, test_s2b_u_teid;
    int len;
    ogs_paa_t paa;

    ogs_gtp_ambr_t ambr;
    ogs_gtp_bearer_qos_t bearer_qos;
    char bearer_qos_buf[GTP_BEARER_QOS_LEN];
    char apn[OGS_MAX_APN_LEN];

    ogs_assert(sess);
    bearer = ogs_list_first(&sess->bearer_list);
    ogs_assert(bearer);
    test_ue = sess->test_ue;
    ogs_assert(test_ue);

    ogs_debug("Create Session Request");
    memset(&gtp_message, 0, sizeof(ogs_gtp_message_t));

    ogs_assert(test_ue->imsi_len);
    req->imsi.presence = 1;
    req->imsi.data = test_ue->imsi_buf;
    req->imsi.len = test_ue->imsi_len;

    ogs_bcd_to_buffer(TEST_MSISDN, msisdn_buf, &msisdn_len);

    req->msisdn.presence = 1;
    req->msisdn.data = msisdn_buf;
    req->msisdn.len = msisdn_len;

    memset(&uli, 0, sizeof(ogs_gtp_uli_t));
    uli.flags.e_cgi = 1;
    uli.flags.tai = 1;
    ogs_nas_from_plmn_id(&uli.tai.nas_plmn_id, &test_ue->e_tai.plmn_id);
    uli.tai.tac = test_ue->e_tai.tac;
    ogs_nas_from_plmn_id(&uli.e_cgi.nas_plmn_id, &test_ue->e_cgi.plmn_id);
    uli.e_cgi.cell_id = test_ue->e_cgi.cell_id;
    req->user_location_information.presence = 1;
    ogs_gtp_build_uli(&req->user_location_information, &uli, 
            uli_buf, OGS_GTP_MAX_ULI_LEN);

    req->serving_network.presence = 1;
    req->serving_network.data = &uli.tai.nas_plmn_id;
    req->serving_network.len = sizeof(uli.tai.nas_plmn_id);

    req->rat_type.presence = 1;
    req->rat_type.u8 = OGS_GTP_RAT_TYPE_WLAN;

    memset(&test_s2b_c_teid, 0, sizeof(ogs_gtp_f_teid_t));
    test_s2b_c_teid.interface_type = OGS_GTP_F_TEID_S2B_EPDG_GTP_C;
    test_s2b_c_teid.teid = htobe32(sess->epdg_s2b_c_teid);
    ogs_assert(sess->gnode->sock);
    rv = ogs_gtp_sockaddr_to_f_teid(
            &sess->gnode->sock->local_addr, NULL, &test_s2b_c_teid, &len);
    ogs_assert(rv == OGS_OK);
    req->sender_f_teid_for_control_plane.presence = 1;
    req->sender_f_teid_for_control_plane.data = &test_s2b_c_teid;
    req->sender_f_teid_for_control_plane.len = len;

    req->access_point_name.presence = 1;
    req->access_point_name.len = ogs_fqdn_build(
            apn, sess->apn, strlen(sess->apn));
    req->access_point_name.data = apn;

    req->selection_mode.presence = 1;
    req->selection_mode.u8 = 
        OGS_GTP_SELECTION_MODE_MS_OR_NETWORK_PROVIDED_APN;

    memset(&paa, 0, sizeof(paa));
    paa.session_type = OGS_PDU_SESSION_TYPE_IPV4V6;

    req->pdn_address_allocation.presence = 1;
    req->pdn_address_allocation.data = &paa;
    req->pdn_address_allocation.len = OGS_PAA_IPV4V6_LEN;

    memset(&ambr, 0, sizeof(ogs_gtp_ambr_t));
    ambr.uplink = htobe32(50000);
    ambr.downlink = htobe32(150000);
    req->aggregate_maximum_bit_rate.presence = 1;
    req->aggregate_maximum_bit_rate.data = &ambr;
    req->aggregate_maximum_bit_rate.len = sizeof(ambr);

    req->bearer_contexts_to_be_created.presence = 1;
    req->bearer_contexts_to_be_created.eps_bearer_id.presence = 1;
    req->bearer_contexts_to_be_created.eps_bearer_id.u8 = bearer->ebi;

    memset(&test_s2b_u_teid, 0, sizeof(ogs_gtp_f_teid_t));
    test_s2b_u_teid.interface_type = OGS_GTP_F_TEID_S2B_U_EPDG_GTP_U;
    test_s2b_u_teid.teid = htobe32(sess->epdg_s2b_u_teid);
    ogs_assert(sess->gnode->sock);
    rv = ogs_gtp_sockaddr_to_f_teid(
            &sess->gnode->sock->local_addr, NULL, &test_s2b_u_teid, &len);

    req->bearer_contexts_to_be_created.s2b_u_epdg_f_teid_5.presence = 1;
    req->bearer_contexts_to_be_created.s2b_u_epdg_f_teid_5.data =
        &test_s2b_u_teid;
    req->bearer_contexts_to_be_created.s2b_u_epdg_f_teid_5.len = len;

    memset(&bearer_qos, 0, sizeof(bearer_qos));
    bearer_qos.qci = 8;
    bearer_qos.priority_level = 1;
    bearer_qos.pre_emption_capability = 0;
    bearer_qos.pre_emption_vulnerability = 0;
    req->bearer_contexts_to_be_created.bearer_level_qos.presence = 1;
    ogs_gtp_build_bearer_qos(
            &req->bearer_contexts_to_be_created.bearer_level_qos,
            &bearer_qos, bearer_qos_buf, GTP_BEARER_QOS_LEN);

    req->recovery.presence = 1;
    req->recovery.u8 = 66;

    req->additional_protocol_configuration_options.presence = 1;
    req->additional_protocol_configuration_options.data =
        (uint8_t *)"\x80\x00\x0d\x00";
    req->additional_protocol_configuration_options.len = 4;

    gtp_message.h.type = type;
    return ogs_gtp_build_msg(&gtp_message);
}
