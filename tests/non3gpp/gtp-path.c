/*
 * Copyright (C) 2019,2020 by Sukchan Lee <acetcom@gmail.com>
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

ogs_socknode_t *test_gtpv2c_server(void)
{
    int rv;
    ogs_sockaddr_t *addr = NULL;
    ogs_socknode_t *node = NULL;
    ogs_sock_t *sock = NULL;
    ogs_gtp_node_t *gnode = NULL;

#define TEST_EPDG_IPV4          "127.0.0.5"

    rv = ogs_getaddrinfo(&addr, AF_UNSPEC,
            TEST_EPDG_IPV4, OGS_GTPV2_C_UDP_PORT, 0);
    ogs_assert(rv == OGS_OK);

    node = ogs_socknode_new(addr);
    ogs_assert(node);

    sock = ogs_udp_server(node);
    ogs_assert(sock);

    ogs_list_for_each(&test_self()->gtpc_list, gnode) {
        rv = ogs_gtp_connect(sock, NULL, gnode);
        ogs_assert(rv == OGS_OK);
    }

    return node;
}

void test_gtpv2c_close(ogs_socknode_t *node)
{
    ogs_socknode_free(node);
}

ogs_pkbuf_t *test_gtpv2c_read(ogs_socknode_t *node)
{
    int rc = 0;
    ogs_sockaddr_t from;
    ogs_pkbuf_t *recvbuf = ogs_pkbuf_alloc(NULL, OGS_MAX_SDU_LEN);
    ogs_assert(recvbuf);
    ogs_pkbuf_put(recvbuf, OGS_MAX_SDU_LEN);

    ogs_assert(node);
    ogs_assert(node->sock);

    while (1) {
        rc = ogs_recvfrom(
                node->sock->fd, recvbuf->data, recvbuf->len, 0, &from);
        if (rc <= 0) {
            ogs_log_message(OGS_LOG_ERROR, ogs_socket_errno,
                    "ogs_recvfrom() failed");
        }
        break;
    }
    recvbuf->len = rc;

    return recvbuf;
}

int test_gtpv2c_send(ogs_socknode_t *node, ogs_pkbuf_t *pkbuf)
{
    ogs_assert(node);
    ogs_assert(node->sock);
    ogs_assert(pkbuf);
    ogs_assert(pkbuf->data);
    ogs_assert(pkbuf->len);

    return ogs_sendto(node->sock->fd, pkbuf->data, pkbuf->len, 0, NULL);
}

int test_gtpv2c_send_create_session_request(
        ogs_socknode_t *node, test_sess_t *sess)
{
    int rv;
    ogs_gtp_header_t h;
    ogs_pkbuf_t *pkbuf = NULL;
    test_ue_t *test_ue = NULL;

    test_ue = sess->test_ue;
    ogs_assert(test_ue);

    memset(&h, 0, sizeof(ogs_gtp_header_t));
    h.type = OGS_GTP_CREATE_SESSION_REQUEST_TYPE;
    h.teid = test_ue->epdg_s2b_teid;

    pkbuf = test_s2b_build_create_session_request(h.type, sess);
    ogs_expect_or_return_val(pkbuf, OGS_ERROR);

    return test_gtpv2c_send(node, pkbuf);;
}
