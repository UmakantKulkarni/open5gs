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

bson_t *decode_nas_qos_rule_hex_to_bson(char *pcs_hexipdata)
{
   char pcs_temp[8];
   int pcs_num_qos_rules = 0;
   char *pcs_docjson, *pcs_docjson2;
   char pcs_hexipdatadup[strlen(pcs_hexipdata)];
   pcs_get_substring(pcs_hexipdata, pcs_hexipdatadup, 0, strlen(pcs_hexipdata));
   while (pcs_hexipdatadup[0] != '\0')
   {
      if (pcs_num_qos_rules > 0)
      {
         strcat(pcs_docjson2, ",");
      }
      int pcs_qosruleid = pcs_hex_to_int(pcs_hexipdata, 0, 2);
      char pcs_qosruleopcodedesc[20], pcs_qosrulepfdirdesc[34], pcs_qosrulepfcompdesc[34];
      int pcs_qosrulelen = pcs_hex_to_int(pcs_hexipdata, 2, 6);
      char pcs_qosrulef1[9];
      pcs_hex_to_binary_str(pcs_hexipdata, pcs_qosrulef1, 6, 8);
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
      pcs_hex_to_binary_str(pcs_hexipdata, pcs_qosrulef1, 8, 10);
      pcs_get_substring(pcs_qosrulef1, pcs_temp, 2, 4);
      int pcs_qosrulepfdir = pcs_binary_to_decimal(pcs_temp);
      if (pcs_qosrulepfdir == 3)
      {
         strcpy(pcs_qosrulepfdirdesc, "BIDIRECTIONAL_PACKET_FILTER");
      }
      else
      {
         strcpy(pcs_qosrulepfdirdesc, "INCORRECT_PACKET_FILTER_DIRECTION");
      }
      pcs_get_substring(pcs_qosrulef1, pcs_temp, 4, 8);
      int pcs_qosrulepfid = pcs_binary_to_decimal(pcs_temp);
      int pcs_qosrulepflen = pcs_hex_to_int(pcs_hexipdata, 10, 12);
      int pcs_qosrulepfcomp = pcs_hex_to_int(pcs_hexipdata, 12, 14);
      if (pcs_qosrulepfcomp == 1)
      {
         strcpy(pcs_qosrulepfcompdesc, "MATCH_ALL_PACKET_FILTER");
      }
      else
      {
         strcpy(pcs_qosrulepfcompdesc, "INCORRECT_PACKET_FILTER_COMPONENT");
      }
      int pcs_qosrulepreced = pcs_hex_to_int(pcs_hexipdata, 14, 16);
      pcs_hex_to_binary_str(pcs_hexipdata, pcs_qosrulef1, 16, 18);
      pcs_get_substring(pcs_qosrulef1, pcs_temp, 2, 8);
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
      pcs_get_substring(pcs_hexipdata, pcs_hexipdatadup, 2 * (3 + pcs_qosrulelen), strlen(pcs_hexipdata));
   }
   bson_error_t error;
   bson_t *bson_doc_nas_qos_rule = bson_new_from_json((const uint8_t *)pcs_docjson2, -1, &error);
   free(pcs_docjson);
   return bson_doc_nas_qos_rule;
}

bson_t *decode_nas_qos_flow_hex_to_bson(char *pcs_hexipdata)
{
   char pcs_temp[8];
   char *pcs_docjson;
   char pcs_qosflowf1[9], pcs_qosflowopcodedesc[20];
   pcs_hex_to_binary_str(pcs_hexipdata, pcs_qosflowf1, 0, 2);
   pcs_get_substring(pcs_qosflowf1, pcs_temp, 2, 8);
   int pcs_qosflowid = pcs_binary_to_decimal(pcs_temp);

   pcs_hex_to_binary_str(pcs_hexipdata, pcs_qosflowf1, 2, 4);
   pcs_get_substring(pcs_qosflowf1, pcs_temp, 0, 3);
   int pcs_qosflowopcode = pcs_binary_to_decimal(pcs_temp);
   if (pcs_qosflowopcode == 1)
   {
      strcpy(pcs_qosflowopcodedesc, "CREATE_NEW_QOS_FLOW");
   }
   else
   {
      strcpy(pcs_qosflowopcodedesc, "INCORRECT_QOS_FLOW");
   }

   pcs_hex_to_binary_str(pcs_hexipdata, pcs_qosflowf1, 4, 6);
   pcs_get_substring(pcs_qosflowf1, pcs_temp, 0, 2);
   int pcs_qosflowebit = pcs_binary_to_decimal(pcs_temp);
   pcs_get_substring(pcs_qosflowf1, pcs_temp, 2, 8);
   int pcs_qosflownumparam = pcs_binary_to_decimal(pcs_temp);
   int c = 1;
   int pcs_qosflowparamid, pcs_qosflowparamlen, pcs_qosflowparam5qi;
   for (; c <= pcs_qosflownumparam; c++)
   {
      pcs_qosflowparamid = pcs_hex_to_int(pcs_hexipdata, 6, 8);
      pcs_qosflowparamlen = pcs_hex_to_int(pcs_hexipdata, 8, 10);
      pcs_qosflowparam5qi = pcs_hex_to_int(pcs_hexipdata, 10, 12);
   }

   asprintf(&pcs_docjson, "{\"%d\": {\"QOS-Flow-Identifier\": %d, \"QOS-Flow-Operation-Code-Value\": %d, \"QOS-Flow-Operation-Code-Description\": \"%s\", \"QOS-Flow-Ebit\": %d, \"QOS-Rule-Num-Parameters\": %d, \"Parameter-1\": { \"QOS-Flow-Param-Identifier\": %d, \"QOS-Flow-Param-Length\": %d, \"QOS-Flow-Param-5QI\": %d } } }", 0, pcs_qosflowid, pcs_qosflowopcode, pcs_qosflowopcodedesc, pcs_qosflowebit, pcs_qosflownumparam, pcs_qosflowparamid, pcs_qosflowparamlen, pcs_qosflowparam5qi);

   bson_error_t error;
   bson_t *bson_doc_nas_qos_flow = bson_new_from_json((const uint8_t *)pcs_docjson, -1, &error);
   return bson_doc_nas_qos_flow;
}

bson_t *decode_nas_epco_hex_to_bson(char *pcs_hexipdata)
{
   char pcs_temp[8];
   char *pcs_docjson;
   char pcs_qosflowf1[9], pcs_epcocpdesc[33], pcs_protcnt1id[5], pcs_protcnt1iddesc[24], pcs_protcnt2id[5], pcs_protcnt2iddesc[24];
   pcs_hex_to_binary_str(pcs_hexipdata, pcs_qosflowf1, 0, 2);
   pcs_get_substring(pcs_qosflowf1, pcs_temp, 0, 4);
   int pcs_epcoextension = pcs_binary_to_decimal(pcs_temp);
   pcs_get_substring(pcs_qosflowf1, pcs_temp, 5, 8);
   int pcs_epcocp = pcs_binary_to_decimal(pcs_temp);
   if (pcs_epcocp == 0)
   {
      strcpy(pcs_epcocpdesc, "Configuration_Protocol_PPP");
   }
   else
   {
      strcpy(pcs_epcocpdesc, "INCORRECT_Configuration_Protocol");
   }
   
   pcs_get_substring(pcs_hexipdata, pcs_protcnt1id, 2, 6);
   if (strcmp(pcs_protcnt1id, "000d") == 0)
   {
      strcpy(pcs_protcnt1iddesc, "DNS_SERVER_IPV4_ADDRESS");
      int pcs_procont1len = pcs_hex_to_int(pcs_hexipdata, 6, 8);
      int pcs_procont1ip = pcs_hex_to_int(pcs_hexipdata, 8, 16);
   }

   pcs_get_substring(pcs_hexipdata, pcs_protcnt2id, 16, 20);
   if (strcmp(pcs_protcnt2id, "000d") == 0)
   {
      strcpy(pcs_protcnt2iddesc, "DNS_SERVER_IPV4_ADDRESS");
      int pcs_procont2len = pcs_hex_to_int(pcs_hexipdata, 20, 22);
      int pcs_procont2ip = pcs_hex_to_int(pcs_hexipdata, 22, 30);
   }

   asprintf(&pcs_docjson, "{\"IS-Extension\": %d, \"Configuration-Protocol-Value\": %d, \"Configuration-Protocol-Description\": \"%s\", \"Protocol-Containers\": [{\"Container-ID\": \"%s\", \"Container-Description\": \"%s\", \"Container-Length\": \"%d\", \"IPv4-Address\": \"%d\"}, {\"Container-ID\": \"%s\", \"Container-Description\": \"%s\", \"Container-Length\": \"%d\", \"IPv4-Address\": \"%d\"}] }", pcs_epcoextension, pcs_epcocp, pcs_epcocpdesc, pcs_protcnt1id, pcs_protcnt1iddesc, pcs_procont1len, pcs_procont1ip, pcs_protcnt2id, pcs_protcnt2iddesc, pcs_procont2len, pcs_procont2ip);

   bson_error_t error;
   bson_t *bson_doc_nas_epco = bson_new_from_json((const uint8_t *)pcs_docjson, -1, &error);
   return bson_doc_nas_epco;
}