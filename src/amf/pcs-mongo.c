#include "mongoc.h"
#include "ogs-app.h"

int insert_data_to_db(char *key);

int insert_data_to_db (char *key)
{
   const char *uri_string = "mongodb://10.102.110.93:27017";
   mongoc_uri_t *uri;
   mongoc_client_t *client;
   mongoc_database_t *database;
   mongoc_collection_t *collection;
   bson_t *insert, *update;
   bson_error_t error;

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
   collection = mongoc_client_get_collection (client, "db_name", "coll_name");
   insert = BCON_NEW (key, BCON_UTF8 ("world_7"));
   //update = BCON_NEW("$set", "{", "hello_3", BCON_UTF8("world_5"), "}");

   //if (!mongoc_collection_update_one (collection, insert, update, NULL, NULL, &error)) {
   //   fprintf (stderr, "%s\n", error.message);
   //}

   if (!mongoc_collection_insert_one (collection, insert, NULL, NULL, &error)) {
      fprintf (stderr, "%s\n", error.message);
   }
   ogs_info("UKK Added data to mongo by AMF");

   bson_destroy (insert);
   //bson_destroy (update);
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