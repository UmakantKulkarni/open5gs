#include "mongoc.h"
#include "ogs-app.h"
#include "bson.h"

int insert_data_to_db(const char *pcs_dbcoll, const char *pcs_dbop, char *pcs_docid, bson_t *bson_doc);
void decode_buffer_to_hex(char *pcs_hexstr, const unsigned char *pcs_data, size_t pcs_len);

int insert_data_to_db(const char *pcs_dbcoll, const char *pcs_dbop, char *pcs_docid, bson_t *bson_doc)
{
   const char *uri_string = "mongodb://mongodb-svc:27017";
   mongoc_uri_t *uri;
   mongoc_client_t *client;
   mongoc_database_t *database;
   mongoc_collection_t *collection;
   bson_error_t error;
   bson_t *query = NULL;

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
      fprintf(stderr,
              "failed to parse URI: %s\n"
              "error message:       %s\n",
              uri_string,
              error.message);
      return EXIT_FAILURE;
   }

   /*
    * Create a new client instance
    */
   client = mongoc_client_new_from_uri(uri);
   if (!client)
   {
      return EXIT_FAILURE;
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
   collection = mongoc_client_get_collection(client, "pcs_db", pcs_dbcoll);

   if (strcmp(pcs_dbop, "create") == 0)
   {
      if (!mongoc_collection_insert_one(collection, bson_doc, NULL, NULL, &error))
      {
         ogs_error("PCS mongoc_collection_insert_one failed %s\n", error.message);
      }
      ogs_info("PCS Added new data to mongo by AMF");
   }
   else if (strcmp(pcs_dbop, "update") == 0)
   {
      query = BCON_NEW("_id", pcs_docid);

      if (!mongoc_collection_update_one(collection, query, bson_doc, NULL, NULL, &error))
      {
         ogs_error("PCS mongoc_collection_update_one failed %s\n", error.message);
      }
      ogs_info("PCS Updated data to mongo by AMF");
   }

   bson_destroy(query);
   bson_destroy(bson_doc);

   /*
    * Release our handles and clean up libmongoc
    */
   mongoc_collection_destroy(collection);
   mongoc_database_destroy(database);
   mongoc_uri_destroy(uri);
   mongoc_client_destroy(client);
   mongoc_cleanup();

   return EXIT_SUCCESS;
}

void decode_buffer_to_hex(char *pcs_hexstr, const unsigned char *pcs_data, size_t pcs_len)
{
   size_t n, m;
   char *p, *last;

   last = pcs_hexstr + OGS_HUGE_LEN;
   p = pcs_hexstr;

   for (n = 0; n < pcs_len; n += 16)
   {
      for (m = n; m < n + 16; m++)
      {
         if (m < pcs_len)
            p = ogs_slprintf(p, last, "%02x", pcs_data[m]);
      }
      p = ogs_slprintf(p, last, "\n");
      pcs_hexstr[pcs_len * 2] = '\0';
   }
}