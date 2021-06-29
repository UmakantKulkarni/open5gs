#include "mongoc.h"
#include "ogs-app.h"
#include "bson.h"

int insert_data_to_db(const char *db_coll, const char *db_op, char *doc_id, char *doc_json);

int insert_data_to_db (const char *db_coll, const char *db_op, char *doc_id, char *doc_json)
{
   const char *uri_string = "mongodb://mongodb-svc:27017";
   mongoc_uri_t *uri;
   mongoc_client_t *client;
   mongoc_database_t *database;
   mongoc_collection_t *collection;
   bson_t *bson_doc;
   bson_error_t error;
   bson_t *query = NULL;

   /*
    * Required to initialize libmongoc's internals
    */
   mongoc_init ();

   /*
    * Safely create a MongoDB URI object from the given string
    */
   uri = mongoc_uri_new_with_error (uri_string, &error);
   if (!uri) {
      fprintf (stderr,
               "failed to parse URI: %s\n"
               "error message:       %s\n",
               uri_string,
               error.message);
      return EXIT_FAILURE;
   }

   /*
    * Create a new client instance
    */
   client = mongoc_client_new_from_uri (uri);
   if (!client) {
      return EXIT_FAILURE;
   }

   /*
    * Register the application name so we can track it in the profile logs
    * on the server. This can also be done from the URI (see other examples).
    */
   mongoc_client_set_appname (client, "connect-example");

   /*
    * Get a handle on the database "db_name" and collection "coll_name"
    */
   database = mongoc_client_get_database (client, "db_name");
   collection = mongoc_client_get_collection (client, "db_name", db_coll);

   if (strcmp(db_op, "create") == 0) {
      bson_doc = bson_new_from_json ((const uint8_t *)doc_json, -1, &error);

      if (!mongoc_collection_insert_one (collection, bson_doc, NULL, NULL, &error)) {
         fprintf (stderr, "%s\n", error.message);
      }
      ogs_info("PCS Added new data to mongo by AMF");

   } else if (strcmp(db_op, "update") == 0) {
      query = BCON_NEW ("_id", doc_id);

      if (!mongoc_collection_delete_one (collection, query, NULL, NULL, &error)) {
              fprintf (stderr, "Delete failed: %s\n", error.message);
      }
      bson_doc = bson_new_from_json ((const uint8_t *)doc_json, -1, &error);

      if (!mongoc_collection_insert_one (collection, bson_doc, NULL, NULL, &error)) {
         fprintf (stderr, "%s\n", error.message);
      }
      ogs_info("PCS Updated data to mongo by AMF");
   }

   bson_destroy (query);
   bson_destroy (bson_doc);

   /*
    * Release our handles and clean up libmongoc
    */
   mongoc_collection_destroy (collection);
   mongoc_database_destroy (database);
   mongoc_uri_destroy (uri);
   mongoc_client_destroy (client);
   mongoc_cleanup ();

   return EXIT_SUCCESS;
}