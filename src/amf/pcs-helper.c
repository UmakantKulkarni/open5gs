#include "mongoc.h"
#include "ogs-app.h"
#include "bson.h"
#include "pcs-helper.h"

void pcs_get_substring(char *pcs_str, char *pcs_sub_str, int pcs_start_index, int pcs_end_index)
{
   char *pcs_start = &pcs_str[pcs_start_index];
   char *pcs_end = &pcs_str[pcs_end_index];
   strncpy(pcs_sub_str, pcs_start, pcs_end - pcs_start);
   pcs_sub_str[pcs_end_index - pcs_start_index] = '\0';
   ogs_info("PCS Substring of %s from index %d to index %d is %s", pcs_str, pcs_start_index, pcs_end_index, pcs_sub_str);
}

int pcs_hex_to_int(char *pcs_hex_str, int pcs_start_index, int pcs_end_index)
{
   char pcs_substr[pcs_end_index - pcs_start_index];
   pcs_get_substring(pcs_hex_str, pcs_substr, pcs_start_index, pcs_end_index);
   int pcs_h2i = strtol(pcs_substr, NULL, 16);
   ogs_info("PCS Conversion of Hex string %s to int is %d", pcs_substr, pcs_h2i);
   return pcs_h2i;
}

int pcs_binary_to_decimal(char *pcs_bin_str)
{
   int pcs_result = 0;
   char pcs_bin_str_dup[strlen(pcs_bin_str)];
   pcs_get_substring(pcs_bin_str, pcs_bin_str_dup, 0, strlen(pcs_bin_str));
   for (; *pcs_bin_str; pcs_bin_str++)
   {
      if ((*pcs_bin_str != '0') && (*pcs_bin_str != '1'))
         return -1;
      pcs_result = pcs_result * 2 + (*pcs_bin_str - '0');
      if (pcs_result < 0)
         return -1;
   }
   pcs_get_substring(pcs_bin_str_dup, pcs_bin_str, 0, strlen(pcs_bin_str_dup));
   ogs_info("PCS Conversion of binary string %s to int is %d", pcs_bin_str, pcs_result);
   return pcs_result;
}

void pcs_hex_to_binary_str(char *pcs_hex_str, char *pcs_bin_str, int pcs_start_index, int pcs_end_index)
{
   char pcs_substr[pcs_end_index - pcs_start_index];
   pcs_get_substring(pcs_hex_str, pcs_substr, pcs_start_index, pcs_end_index);
   pcs_bin_str[0] = '\0';
   int p = 0;
   int value = 0;
   char binary_str_ar[16][5] = {"0000", "0001", "0010", "0011", "0100", "0101", "0110", "0111", "1000", "1001", "1010", "1011", "1100", "1101", "1110", "1111"};
   char digits[] = "0123456789abcdef";
   while (pcs_substr[p])
   {
      const char *v = strchr(digits, tolower(pcs_substr[p]));
      if (v[0] > 96)
      {
         value = v[0] - 87;
      }
      else
      {
         value = v[0] - 48;
      }
      if (v)
      {
         strcat(pcs_bin_str, binary_str_ar[value]);
      }
      p++;
   }
   ogs_info("PCS Conversion of Hex string %s to binary string is %s", pcs_substr, pcs_bin_str);
}

int insert_data_to_db(mongoc_collection_t *collection, const char *pcs_dbop, char *pcs_docid, bson_t *bson_doc)
{
   bson_error_t error;
   bson_t *query = NULL;

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