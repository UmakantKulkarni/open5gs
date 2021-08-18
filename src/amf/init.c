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

#include "sbi-path.h"
#include "ngap-path.h"
#include "mongoc.h"
#include "pcs-helper.h"

static ogs_thread_t *thread;
static void amf_main(void *data);
static int initialized = 0;

int amf_initialize()
{
    int rv;

    amf_context_init();
    amf_event_init();
    ogs_sbi_context_init();

    rv = ogs_sbi_context_parse_config("amf", "nrf");
    if (rv != OGS_OK) return rv;

    rv = amf_context_parse_config();
    if (rv != OGS_OK) return rv;

    rv = amf_m_tmsi_pool_generate();
    if (rv != OGS_OK) return rv;

    rv = ogs_log_config_domain(
            ogs_app()->logger.domain, ogs_app()->logger.level);
    if (rv != OGS_OK) return rv;

    rv = amf_sbi_open();
    if (rv != OGS_OK) return rv;

    rv = ngap_open();
    if (rv != OGS_OK) return rv;

    thread = ogs_thread_create(amf_main, NULL);
    if (!thread) return OGS_ERROR;

    initialized = 1;

    return OGS_OK;
}

static ogs_timer_t *t_termination_holding = NULL;

static void event_termination(void)
{
    ogs_sbi_nf_instance_t *nf_instance = NULL;

    /* Sending NF Instance De-registeration to NRF */
    ogs_list_for_each(&ogs_sbi_self()->nf_instance_list, nf_instance)
        amf_nf_fsm_fini(nf_instance);

    /* Starting holding timer */
    t_termination_holding = ogs_timer_add(ogs_app()->timer_mgr, NULL, NULL);
    ogs_assert(t_termination_holding);
#define TERMINATION_HOLDING_TIME ogs_time_from_msec(300)
    ogs_timer_start(t_termination_holding, TERMINATION_HOLDING_TIME);

    /* Sending termination event to the queue */
    ogs_queue_term(ogs_app()->queue);
    ogs_pollset_notify(ogs_app()->pollset);
}

void amf_terminate(void)
{
    if (!initialized) return;

    /* Daemon terminating */
    event_termination();
    ogs_thread_destroy(thread);
    ogs_timer_delete(t_termination_holding);

    ngap_close();
    amf_sbi_close();

    amf_context_final();
    ogs_sbi_context_final();

    amf_event_final(); /* Destroy event */
}

static void amf_main(void *data)
{
    ogs_fsm_t amf_sm;
    int rv;

    amf_sm.pcs_fsmdata.pcs_dbcommenabled = pcs_set_int_from_env("PCS_DB_COMM_ENABLED");
    amf_sm.pcs_fsmdata.pcs_updateapienabledcreate = pcs_set_int_from_env("PCS_UPDATE_API_ENABLED_CREATE");
    amf_sm.pcs_fsmdata.pcs_updateapienabledn1n2 = pcs_set_int_from_env("PCS_UPDATE_API_ENABLED_N1N2");
    amf_sm.pcs_fsmdata.pcs_updateapienabledmodify = pcs_set_int_from_env("PCS_UPDATE_API_ENABLED_MODIFY");
    amf_sm.pcs_fsmdata.pcs_blockingapienabled = pcs_set_int_from_env("PCS_BLOCKING_API_ENABLED");
    amf_sm.pcs_fsmdata.pcs_isfullystateless = pcs_set_int_from_env("PCS_IS_TRANSACTIONAL_STATELESS");
    amf_sm.pcs_fsmdata.pcs_isproceduralstateless = pcs_set_int_from_env("PCS_IS_PROCEDURAL_STATELESS");
    amf_sm.pcs_fsmdata.pcs_dbcollectioname = getenv("PCS_DB_COLLECTION_NAME");

    mongoc_uri_t *uri;
    mongoc_client_t *client;
    mongoc_database_t *database;
    mongoc_collection_t *collection;
    if (amf_sm.pcs_fsmdata.pcs_dbcommenabled)
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

        if (amf_sm.pcs_fsmdata.pcs_blockingapienabled)
        {
            mongoc_client_pool_t *pcs_mongopool = mongoc_client_pool_new (uri);
            amf_sm.pcs_fsmdata.pcs_mongopool = pcs_mongopool;
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
        collection = mongoc_client_get_collection(client, "pcs_db", amf_sm.pcs_fsmdata.pcs_dbcollectioname);

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

        amf_sm.pcs_fsmdata.pcs_dbcollection = collection;
        ogs_info("PCS Created handle on the database in the initialization phase");
    }
    else
    {
        ogs_info("PCS DB Communication is not enabled");
    }
    

    ogs_fsm_create(&amf_sm, amf_state_initial, amf_state_final);
    ogs_fsm_init(&amf_sm, 0);

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
            amf_event_t *e = NULL;

            rv = ogs_queue_trypop(ogs_app()->queue, (void**)&e);
            ogs_assert(rv != OGS_ERROR);

            if (rv == OGS_DONE)
                goto done;

            if (rv == OGS_RETRY)
                break;

            ogs_assert(e);
            ogs_fsm_dispatch(&amf_sm, e);
            amf_event_free(e);
        }
    }
done:

    if (amf_sm.pcs_fsmdata.pcs_dbcommenabled)
    {
        mongoc_collection_destroy(collection);
        mongoc_database_destroy(database);
        mongoc_uri_destroy(uri);
        mongoc_client_destroy(client);
        mongoc_cleanup();
    }

    ogs_fsm_fini(&amf_sm, 0);
    ogs_fsm_delete(&amf_sm);
}
