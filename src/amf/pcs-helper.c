#define _GNU_SOURCE
#include <stdio.h>
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
   ogs_debug("PCS Substring of %s from index %d to index %d is %s", pcs_str, pcs_start_index, pcs_end_index, pcs_sub_str);
}

int pcs_hex_to_int(char *pcs_hex_str, int pcs_start_index, int pcs_end_index)
{
   char pcs_substr[pcs_end_index - pcs_start_index];
   pcs_get_substring(pcs_hex_str, pcs_substr, pcs_start_index, pcs_end_index);
   int pcs_h2i = strtol(pcs_substr, NULL, 16);
   ogs_debug("PCS Conversion of Hex string %s to int is %d", pcs_substr, pcs_h2i);
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
   ogs_debug("PCS Conversion of binary string %s to int is %d", pcs_bin_str, pcs_result);
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
   ogs_debug("PCS Conversion of Hex string %s to binary string is %s", pcs_substr, pcs_bin_str);
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
      ogs_debug("PCS Added new data to mongo by AMF");
   }
   else if (strcmp(pcs_dbop, "update") == 0)
   {
      query = BCON_NEW("_id", pcs_docid);

      if (!mongoc_collection_update_one(collection, query, bson_doc, NULL, NULL, &error))
      {
         ogs_error("PCS mongoc_collection_update_one failed %s\n", error.message);
      }
      ogs_debug("PCS Updated data to mongo by AMF");
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

bson_t *decode_nas_qos_rule_hex_to_bson(char *pcs_hexauthqosrule)
{
   char pcs_temp[8];
   int pcs_num_qos_rules = 0;
   char *pcs_docjson, *pcs_docjson2;
   char pcs_hexauthqosruledup[strlen(pcs_hexauthqosrule)];
   pcs_get_substring(pcs_hexauthqosrule, pcs_hexauthqosruledup, 0, strlen(pcs_hexauthqosrule));
   while (pcs_hexauthqosruledup[0] != '\0')
   {
      if (pcs_num_qos_rules > 0)
      {
         strcat(pcs_docjson2, ",");
      }
      int pcs_qosruleid = pcs_hex_to_int(pcs_hexauthqosrule, 0, 2);
      char pcs_qosruleopcodedesc[20], pcs_qosrulepfdirdesc[34], pcs_qosrulepfcompdesc[34];
      int pcs_qosrulelen = pcs_hex_to_int(pcs_hexauthqosrule, 2, 6);
      char pcs_qosrulef1[9], pcs_qosrulef2[9], pcs_qosrulef3[9];
      pcs_hex_to_binary_str(pcs_hexauthqosrule, pcs_qosrulef1, 6, 8);
      pcs_get_substring(pcs_qosrulef1, pcs_temp, 0, 3);
      int pcs_qosruleopcode = pcs_binary_to_decimal(pcs_temp);
      if (pcs_qosruleopcode == 1)
      {
         strcpy(pcs_qosruleopcodedesc, "CREATE_NEW_QOS_RULE");
      }
      else
      {
         strcpy(pcs_qosruleopcodedesc, "INCORRECT_QOS_RULE");
      }
      pcs_get_substring(pcs_qosrulef1, pcs_temp, 3, 4);
      int pcs_qosruledqr = pcs_binary_to_decimal(pcs_temp);
      pcs_get_substring(pcs_qosrulef1, pcs_temp, 4, 8);
      int pcs_qosrulenumpf = pcs_binary_to_decimal(pcs_temp);
      pcs_hex_to_binary_str(pcs_hexauthqosrule, pcs_qosrulef2, 8, 10);
      pcs_get_substring(pcs_qosrulef2, pcs_temp, 2, 4);
      int pcs_qosrulepfdir = pcs_binary_to_decimal(pcs_temp);
      if (pcs_qosrulepfdir == 3)
      {
         strcpy(pcs_qosrulepfdirdesc, "BIDIRECTIONAL_PACKET_FILTER");
      }
      else
      {
         strcpy(pcs_qosrulepfdirdesc, "INCORRECT_PACKET_FILTER_DIRECTION");
      }
      pcs_get_substring(pcs_qosrulef2, pcs_temp, 4, 8);
      int pcs_qosrulepfid = pcs_binary_to_decimal(pcs_temp);
      int pcs_qosrulepflen = pcs_hex_to_int(pcs_hexauthqosrule, 10, 12);
      int pcs_qosrulepfcomp = pcs_hex_to_int(pcs_hexauthqosrule, 12, 14);
      if (pcs_qosrulepfcomp == 1)
      {
         strcpy(pcs_qosrulepfcompdesc, "MATCH_ALL_PACKET_FILTER");
      }
      else
      {
         strcpy(pcs_qosrulepfcompdesc, "INCORRECT_PACKET_FILTER_COMPONENT");
      }
      int pcs_qosrulepreced = pcs_hex_to_int(pcs_hexauthqosrule, 14, 16);
      pcs_hex_to_binary_str(pcs_hexauthqosrule, pcs_qosrulef3, 16, 18);
      pcs_get_substring(pcs_qosrulef3, pcs_temp, 2, 8);
      int pcs_qosruleqfid = pcs_binary_to_decimal(pcs_temp);

      asprintf(&pcs_docjson, "{\"%d\": {\"QOS-Rule-Identifier\": %d, \"QOS-Rule-Length\": %d, \"QOS-Rule-Operation-Code-Value\": %d, \"QOS-Rule-Operation-Code-Description\": \"%s\", \"QOS-Rule-DQR\": %d, \"QOS-Rule-Num-Packet-Filters\": %d, \"Packet-Filter-1\": { \"QOS-Rule-Packet-Filters-Direction-Value\": %d, \"QOS-Rule-Packet-Filters-Direction-Description\": \"%s\", \"QOS-Rule-Packet-Filters-Direction-ID\": %d, \"QOS-Rule-Packet-Filters-Length\": %d, \"QOS-Rule-Packet-Filters-Component-Value\": %d, \"QOS-Rule-Packet-Filters-Component-Description\": \"%s\" }, \"QOS-Rule-Precedence\": %d, \"QOS-Rule-Flow-Identifier\": %d } }", pcs_num_qos_rules, pcs_qosruleid, pcs_qosrulelen, pcs_qosruleopcode, pcs_qosruleopcodedesc, pcs_qosruledqr, pcs_qosrulenumpf, pcs_qosrulepfdir, pcs_qosrulepfdirdesc, pcs_qosrulepfid, pcs_qosrulepflen, pcs_qosrulepfcomp, pcs_qosrulepfcompdesc, pcs_qosrulepreced, pcs_qosruleqfid);
      if (pcs_num_qos_rules > 0)
      {
         strcat(pcs_docjson2, pcs_docjson);
      }
      else
      {
         pcs_docjson2 = pcs_docjson;
      }
      pcs_num_qos_rules = pcs_num_qos_rules + 1;
      pcs_get_substring(pcs_hexauthqosrule, pcs_hexauthqosruledup, 2 * (3 + pcs_qosrulelen), strlen(pcs_hexauthqosrule));
   }
   bson_error_t error;
   bson_t *bson_doc_nas_qos_rule = bson_new_from_json((const uint8_t *)pcs_docjson2, -1, &error);
   free(pcs_docjson);
   return bson_doc_nas_qos_rule;
}