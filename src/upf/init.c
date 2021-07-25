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
#include "gtp-path.h"
#include "pfcp-path.h"
#include "mongoc.h"
#include "pcs-helper.h"

static ogs_thread_t *thread;
static void upf_main(void *data);

static int initialized = 0;

int upf_initialize()
{
    int rv;

    ogs_gtp_context_init(OGS_MAX_NUM_OF_GTPU_RESOURCE);
    ogs_pfcp_context_init();

    upf_context_init();
    upf_event_init();
    upf_gtp_init();

    rv = ogs_pfcp_xact_init();
    if (rv != OGS_OK) return rv;

    rv = ogs_gtp_context_parse_config("upf", "smf");
    if (rv != OGS_OK) return rv;

    rv = ogs_pfcp_context_parse_config("upf", "smf");
    if (rv != OGS_OK) return rv;

    rv = upf_context_parse_config();
    if (rv != OGS_OK) return rv;

    rv = ogs_log_config_domain(
            ogs_app()->logger.domain, ogs_app()->logger.level);
    if (rv != OGS_OK) return rv;

    rv = ogs_pfcp_ue_pool_generate();
    if (rv != OGS_OK) return rv;

    rv = upf_pfcp_open();
    if (rv != OGS_OK) return rv;

    rv = upf_gtp_open();
    if (rv != OGS_OK) return rv;

    thread = ogs_thread_create(upf_main, NULL);
    if (!thread) return OGS_ERROR;

    initialized = 1;

    return OGS_OK;
}

void upf_terminate(void)
{
    if (!initialized) return;

    upf_event_term();

    ogs_thread_destroy(thread);

    upf_pfcp_close();
    upf_gtp_close();

    upf_context_final();

    ogs_pfcp_context_final();
    ogs_gtp_context_final();

    ogs_pfcp_xact_final();

    upf_gtp_final();
    upf_event_final();
}

static void upf_main(void *data)
{
    ogs_fsm_t upf_sm;
    int rv;

    upf_sm.pcs_fsmdata.pcs_dbcommenabled = pcs_set_int_from_env("PCS_DB_COMM_ENABLED");
    upf_sm.pcs_fsmdata.pcs_updateapienabledcreate = pcs_set_int_from_env("PCS_UPDATE_API_ENABLED_CREATE");
    upf_sm.pcs_fsmdata.pcs_updateapienabledn1n2 = pcs_set_int_from_env("PCS_UPDATE_API_ENABLED_N1N2");
    upf_sm.pcs_fsmdata.pcs_updateapienabledmodify = pcs_set_int_from_env("PCS_UPDATE_API_ENABLED_MODIFY");
    upf_sm.pcs_fsmdata.pcs_blockingapienabled = pcs_set_int_from_env("PCS_BLOCKING_API_ENABLED");
    upf_sm.pcs_fsmdata.pcs_isfullystateless = pcs_set_int_from_env("PCS_IS_TRANSACTIONAL_STATELESS");

    mongoc_uri_t *uri;
    mongoc_client_t *client;
    mongoc_database_t *database;
    mongoc_collection_t *collection;
    if (upf_sm.pcs_fsmdata.pcs_dbcommenabled)
    {
        const char *uri_string = "mongodb://mongodb-svc:27017";
        bson_error_t error;
        bson_t *command, reply;
        char *str;
        bool retval;

        /*
        * Required to initialize libmongoc's internals
        */
        mongoc_init();

        /*
        * Safely create a MongoDB URI object from the given string
        */
        uri = mongoc_uri_new_with_error(uri_string, &error);
        if (!uri)
        {
            ogs_error("PCS failed to parse URI: %s. Error message is: %s ", uri_string, error.message);
        }

        /*
        * Create a new client instance
        */
        client = mongoc_client_new_from_uri(uri);
        if (!client)
        {
            ogs_info("PCS client create failure");
        }

        /*
        * Register the application name so we can track it in the profile logs
        * on the server. This can also be done from the URI (see other examples).
        */
        mongoc_client_set_appname(client, "pcs-db");

        /*
        * Get a handle on the database "db_name" and collection "coll_name"
        */
        database = mongoc_client_get_database(client, "pcs_db");
        collection = mongoc_client_get_collection(client, "pcs_db", "upf");

        /*
        * Do work. This example pings the database, prints the result as JSON and
        * performs an insert
        */
        command = BCON_NEW("ping", BCON_INT32(1));

        retval = mongoc_client_command_simple(
            client, "admin", command, NULL, &reply, &error);

        if (!retval)
        {
            ogs_error("PCS mongoc_client_command_simple error %s", error.message);
        }

        str = bson_as_json(&reply, NULL);
        ogs_info("PCS MongoDB Ping reply is %s", str);

        upf_sm.pcs_fsmdata.pcs_dbcollection = collection;
        ogs_info("PCS Created handle on the database in the initialization phase");
    }
    else
    {
        ogs_info("PCS DB Communication is not enabled");
    }

    ogs_fsm_create(&upf_sm, upf_state_initial, upf_state_final);
    ogs_fsm_init(&upf_sm, 0);

    for ( ;; ) {
        ogs_pollset_poll(ogs_app()->pollset,
                ogs_timer_mgr_next(ogs_app()->timer_mgr));

        /*
         * After ogs_pollset_poll(), ogs_timer_mgr_expire() must be called.
         *
         * The reason is why ogs_timer_mgr_next() can get the corrent value
         * when ogs_timer_stop() is called internally in ogs_timer_mgr_expire().
         *
         * You should not use event-queue before ogs_timer_mgr_expire().
         * In this case, ogs_timer_mgr_expire() does not work
         * because 'if rv == OGS_DONE' statement is exiting and
         * not calling ogs_timer_mgr_expire().
         */
        ogs_timer_mgr_expire(ogs_app()->timer_mgr);

        for ( ;; ) {
            upf_event_t *e = NULL;

            rv = ogs_queue_trypop(ogs_app()->queue, (void**)&e);
            ogs_assert(rv != OGS_ERROR);

            if (rv == OGS_DONE)
                goto done;

            if (rv == OGS_RETRY)
                break;

            ogs_assert(e);
            ogs_fsm_dispatch(&upf_sm, e);
            upf_event_free(e);
        }
    }
done:

    if (upf_sm.pcs_fsmdata.pcs_dbcommenabled)
    {
        mongoc_collection_destroy(collection);
        mongoc_database_destroy(database);
        mongoc_uri_destroy(uri);
        mongoc_client_destroy(client);
        mongoc_cleanup();
    }

    ogs_fsm_fini(&upf_sm, 0);
    ogs_fsm_delete(&upf_sm);
}
