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

    ogs_gtp_uli_t uli;
    char uli_buf[OGS_GTP_MAX_ULI_LEN];
    ogs_gtp_f_teid_t test_s11_teid, pgw_s5c_teid;
    int len;
    ogs_gtp_ambr_t ambr;
    ogs_gtp_bearer_qos_t bearer_qos;
    char bearer_qos_buf[GTP_BEARER_QOS_LEN];
    ogs_gtp_ue_timezone_t ue_timezone;
    struct timeval now;
    struct tm time_exp;
    char apn[OGS_MAX_APN_LEN];

#if 0
    ogs_assert(sess);
    session = sess->session;
    ogs_assert(session);
    ogs_assert(session->name);
    bearer = test_default_bearer_in_sess(sess);
    ogs_assert(bearer);
    test_ue = sess->test_ue;
    ogs_assert(test_ue);
#endif

    ogs_debug("Create Session Request");
#if 0
    ogs_debug("    MME_S11_TEID[%d] SGW_S11_TEID[%d]",
            test_ue->test_s11_teid, test_ue->sgw_s11_teid);
#endif
    memset(&gtp_message, 0, sizeof(ogs_gtp_message_t));

    req->rat_type.presence = 1;
    req->rat_type.u8 = OGS_GTP_RAT_TYPE_EUTRAN;

#if 0
    ogs_assert(test_ue->imsi_len);
    req->imsi.presence = 1;
    req->imsi.data = test_ue->imsi;
    req->imsi.len = test_ue->imsi_len;

    if (test_ue->imeisv_len) {
        req->me_identity.presence = 1;
        req->me_identity.data = test_ue->imeisv;
        req->me_identity.len = test_ue->imeisv_len;
    }

    if (test_ue->msisdn_len) {
        req->msisdn.presence = 1;
        req->msisdn.data = test_ue->msisdn;
        req->msisdn.len = test_ue->msisdn_len;
    }

    memset(&uli, 0, sizeof(ogs_gtp_uli_t));
    uli.flags.e_cgi = 1;
    uli.flags.tai = 1;
    ogs_nas_from_plmn_id(&uli.tai.nas_plmn_id, &test_ue->tai.plmn_id);
    uli.tai.tac = test_ue->tai.tac;
    ogs_nas_from_plmn_id(&uli.e_cgi.nas_plmn_id, &test_ue->e_cgi.plmn_id);
    uli.e_cgi.cell_id = test_ue->e_cgi.cell_id;
    req->user_location_information.presence = 1;
    ogs_gtp_build_uli(&req->user_location_information, &uli, 
            uli_buf, OGS_GTP_MAX_ULI_LEN);

    req->serving_network.presence = 1;
    req->serving_network.data = &uli.tai.nas_plmn_id;
    req->serving_network.len = sizeof(uli.tai.nas_plmn_id);

    req->rat_type.presence = 1;
    req->rat_type.u8 = OGS_GTP_RAT_TYPE_EUTRAN;

    memset(&test_s11_teid, 0, sizeof(ogs_gtp_f_teid_t));
    test_s11_teid.interface_type = OGS_GTP_F_TEID_S11_MME_GTP_C;
    test_s11_teid.teid = htobe32(test_ue->test_s11_teid);
    rv = ogs_gtp_sockaddr_to_f_teid(
            ogs_gtp_self()->gtpc_addr, ogs_gtp_self()->gtpc_addr6,
            &test_s11_teid, &len);
    ogs_assert(rv == OGS_OK);
    req->sender_f_teid_for_control_plane.presence = 1;
    req->sender_f_teid_for_control_plane.data = &test_s11_teid;
    req->sender_f_teid_for_control_plane.len = len;

    memset(&pgw_s5c_teid, 0, sizeof(ogs_gtp_f_teid_t));
    pgw_s5c_teid.interface_type = OGS_GTP_F_TEID_S5_S8_PGW_GTP_C;
    if (session->smf_ip.ipv4 || session->smf_ip.ipv6) {
        pgw_s5c_teid.ipv4 = session->smf_ip.ipv4;
        pgw_s5c_teid.ipv6 = session->smf_ip.ipv6;
        if (pgw_s5c_teid.ipv4 && pgw_s5c_teid.ipv6) {
            pgw_s5c_teid.both.addr = session->smf_ip.addr;
            memcpy(pgw_s5c_teid.both.addr6, session->smf_ip.addr6,
                    sizeof session->smf_ip.addr6);
            req->pgw_s5_s8_address_for_control_plane_or_pmip.len =
                OGS_GTP_F_TEID_IPV4V6_LEN;
        } else if (pgw_s5c_teid.ipv4) {
            pgw_s5c_teid.addr = session->smf_ip.addr;
            req->pgw_s5_s8_address_for_control_plane_or_pmip.len =
                OGS_GTP_F_TEID_IPV4_LEN;
        } else if (pgw_s5c_teid.ipv6) {
            memcpy(pgw_s5c_teid.addr6, session->smf_ip.addr6,
                    sizeof session->smf_ip.addr6);
            req->pgw_s5_s8_address_for_control_plane_or_pmip.len =
                OGS_GTP_F_TEID_IPV6_LEN;
        }
        req->pgw_s5_s8_address_for_control_plane_or_pmip.presence = 1;
        req->pgw_s5_s8_address_for_control_plane_or_pmip.data =
            &pgw_s5c_teid;
    } else {
        ogs_sockaddr_t *pgw_addr = NULL;
        ogs_sockaddr_t *pgw_addr6 = NULL;

        pgw_addr = test_pgw_addr_find_by_apn(
                &test_self()->pgw_list, AF_INET, session->name);
        pgw_addr6 = test_pgw_addr_find_by_apn(
                &test_self()->pgw_list, AF_INET6, session->name);
        if (!pgw_addr && !pgw_addr6) {
            pgw_addr = test_self()->pgw_addr;
            pgw_addr6 = test_self()->pgw_addr6;
        }

        rv = ogs_gtp_sockaddr_to_f_teid(
                pgw_addr, pgw_addr6, &pgw_s5c_teid, &len);
        ogs_assert(rv == OGS_OK);
        req->pgw_s5_s8_address_for_control_plane_or_pmip.presence = 1;
        req->pgw_s5_s8_address_for_control_plane_or_pmip.data = &pgw_s5c_teid;
        req->pgw_s5_s8_address_for_control_plane_or_pmip.len = len;
    }

    req->access_point_name.presence = 1;
    req->access_point_name.len = ogs_fqdn_build(
            apn, session->name, strlen(session->name));
    req->access_point_name.data = apn;

    req->selection_mode.presence = 1;
    req->selection_mode.u8 = 
        OGS_GTP_SELECTION_MODE_MS_OR_NETWORK_PROVIDED_APN | 0xfc;

    ogs_assert(sess->request_type.type == OGS_NAS_EPS_PDN_TYPE_IPV4 ||
            sess->request_type.type == OGS_NAS_EPS_PDN_TYPE_IPV6 ||
            sess->request_type.type == OGS_NAS_EPS_PDN_TYPE_IPV4V6);

    req->pdn_type.u8 = ((session->session_type + 1) &
            sess->request_type.type);
    if (session->session_type == OGS_PDU_SESSION_TYPE_IPV4 ||
        session->session_type == OGS_PDU_SESSION_TYPE_IPV6 ||
        session->session_type == OGS_PDU_SESSION_TYPE_IPV4V6) {
        req->pdn_type.u8 =
            (session->session_type & sess->request_type.type);
        if (req->pdn_type.u8 == 0) {
            ogs_fatal("Cannot derive PDN Type [UE:%d,HSS:%d]",
                sess->request_type.type, session->session_type);
            ogs_assert_if_reached();
        }
    } else {
        ogs_fatal("Invalid PDN_TYPE[%d]", session->session_type);
        ogs_assert_if_reached();
    }
    req->pdn_type.presence = 1;

    /* If we started with both addrs (IPV4V6) but the above code 
     * (pdn_type & sess->request_type) truncates us down to just one,
     * we need to change position of addresses in struct. */
    if (req->pdn_type.u8 == OGS_PDU_SESSION_TYPE_IPV4 &&
        session->session_type == OGS_PDU_SESSION_TYPE_IPV4V6) {
	    uint32_t addr = session->paa.both.addr;
	    session->paa.addr = addr;
    }
    if (req->pdn_type.u8 == OGS_PDU_SESSION_TYPE_IPV6 &&
        session->session_type == OGS_PDU_SESSION_TYPE_IPV4V6) {
	    uint8_t addr[16];
	    memcpy(&addr, session->paa.both.addr6, OGS_IPV6_LEN);
	    memcpy(session->paa.addr6, &addr, OGS_IPV6_LEN);
    }

    session->paa.session_type = req->pdn_type.u8;
    req->pdn_address_allocation.data = &session->paa;
    if (req->pdn_type.u8 == OGS_PDU_SESSION_TYPE_IPV4)
        req->pdn_address_allocation.len = OGS_PAA_IPV4_LEN;
    else if (req->pdn_type.u8 == OGS_PDU_SESSION_TYPE_IPV6)
        req->pdn_address_allocation.len = OGS_PAA_IPV6_LEN;
    else if (req->pdn_type.u8 == OGS_PDU_SESSION_TYPE_IPV4V6)
        req->pdn_address_allocation.len = OGS_PAA_IPV4V6_LEN;
    else
        ogs_assert_if_reached();
    req->pdn_address_allocation.presence = 1;

    req->maximum_apn_restriction.presence = 1;
    req->maximum_apn_restriction.u8 = OGS_GTP_APN_NO_RESTRICTION;

    if (session->ambr.uplink || session->ambr.downlink) {
        /*
         * Ch 8.7. Aggregate Maximum Bit Rate(AMBR) in TS 29.274 V15.9.0
         *
         * AMBR is defined in clause 9.9.4.2 of 3GPP TS 24.301 [23],
         * but it shall be encoded as shown in Figure 8.7-1 as
         * Unsigned32 binary integer values in kbps (1000 bits per second).
         */
        memset(&ambr, 0, sizeof(ogs_gtp_ambr_t));
        ambr.uplink = htobe32(session->ambr.uplink / 1000);
        ambr.downlink = htobe32(session->ambr.downlink / 1000);
        req->aggregate_maximum_bit_rate.presence = 1;
        req->aggregate_maximum_bit_rate.data = &ambr;
        req->aggregate_maximum_bit_rate.len = sizeof(ambr);
    }

    if (sess->ue_pco.length && sess->ue_pco.buffer) {
        req->protocol_configuration_options.presence = 1;
        req->protocol_configuration_options.data = sess->ue_pco.buffer;
        req->protocol_configuration_options.len = sess->ue_pco.length;
    }

    req->bearer_contexts_to_be_created.presence = 1;
    req->bearer_contexts_to_be_created.eps_bearer_id.presence = 1;
    req->bearer_contexts_to_be_created.eps_bearer_id.u8 = bearer->ebi;

    memset(&bearer_qos, 0, sizeof(bearer_qos));
    bearer_qos.qci = session->qos.index;
    bearer_qos.priority_level = session->qos.arp.priority_level;
    bearer_qos.pre_emption_capability = session->qos.arp.pre_emption_capability;
    bearer_qos.pre_emption_vulnerability =
        session->qos.arp.pre_emption_vulnerability;
    req->bearer_contexts_to_be_created.bearer_level_qos.presence = 1;
    ogs_gtp_build_bearer_qos(
            &req->bearer_contexts_to_be_created.bearer_level_qos,
            &bearer_qos, bearer_qos_buf, GTP_BEARER_QOS_LEN);

    /* UE Time Zone */
    memset(&ue_timezone, 0, sizeof(ue_timezone));
    ogs_gettimeofday(&now);
    ogs_localtime(now.tv_sec, &time_exp);
    if (time_exp.tm_gmtoff >= 0) {
        ue_timezone.timezone = OGS_GTP_TIME_TO_BCD(time_exp.tm_gmtoff / 900);
    } else {
        ue_timezone.timezone = OGS_GTP_TIME_TO_BCD((-time_exp.tm_gmtoff) / 900);
        ue_timezone.timezone |= 0x08;
    }
    /* quarters of an hour */
    ue_timezone.daylight_saving_time = 
        OGS_GTP_UE_TIME_ZONE_NO_ADJUSTMENT_FOR_DAYLIGHT_SAVING_TIME;
    req->ue_time_zone.presence = 1;
    req->ue_time_zone.data = &ue_timezone;
    req->ue_time_zone.len = sizeof(ue_timezone);

    req->charging_characteristics.presence = 1;
    req->charging_characteristics.data = (uint8_t *)"\x54\x00";
    req->charging_characteristics.len = 2;
#endif

    gtp_message.h.type = type;
    return ogs_gtp_build_msg(&gtp_message);
}
