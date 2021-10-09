#define _GNU_SOURCE
#include <stdio.h>
#include "mongoc.h"
#include "ogs-app.h"
#include "bson.h"
#include "pcs-helper.h"
#include <arpa/inet.h>
#include "parson.h"

extern mongoc_client_pool_t *PCS_MONGO_POOL;

const int PCS_REPEAT_COUNTER = 100000;

int pcs_set_int_from_env(const char *pcs_env_var)
{
   int pcs_enval = 0;

   if (strcmp(getenv(pcs_env_var), "true") == 0)
   {
      pcs_enval = 1;
   }
   else
   {
      pcs_enval = 0;
   }

   return pcs_enval;
}

char *pcs_combine_strings(char *pcs_input_a, char *pcs_input_b)
{
   size_t pcs_len_a = 0, pcs_len_b = 0;
   while (pcs_input_a[pcs_len_a] != '\0')
      pcs_len_a++;
   while (pcs_input_b[pcs_len_b] != '\0')
      pcs_len_b++;
   char *pcs_output_str = malloc(pcs_len_a + pcs_len_b);
   asprintf(&pcs_output_str, "%s%s", pcs_input_a, pcs_input_b);
   return pcs_output_str;
}

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
      ogs_debug("PCS Added new data to mongo by UPF");
   }
   else if (strcmp(pcs_dbop, "update") == 0)
   {
      query = BCON_NEW("_id", pcs_docid);

      if (!mongoc_collection_update_one(collection, query, bson_doc, NULL, NULL, &error))
      {
         ogs_error("PCS mongoc_collection_update_one failed %s\n", error.message);
      }
      ogs_debug("PCS Updated data to mongo by UPF");
   }

   bson_destroy(query);
   bson_destroy(bson_doc);

   return EXIT_SUCCESS;
}

int delete_create_data_to_db(mongoc_collection_t *collection, char *pcs_docid, char *pcs_dbrdata, char *pcs_dbnewdata)
{
   bson_error_t error;
   bson_t *query = BCON_NEW("_id", pcs_docid);

   pcs_dbrdata[strlen(pcs_dbrdata) - 1] = '\0';
   pcs_dbnewdata = pcs_combine_strings(pcs_dbrdata, pcs_dbnewdata);
   ogs_debug("Final Data after delete-create operation is %s", pcs_dbnewdata);
   bson_t *bson_doc = bson_new_from_json((const uint8_t *)pcs_dbnewdata, -1, &error);

   if (!mongoc_collection_delete_one(collection, query, NULL, NULL, &error))
   {
      ogs_error("PCS mongoc_collection_delete_one failed during delete-create process %s\n", error.message);
   }
   if (!mongoc_collection_insert_one(collection, bson_doc, NULL, NULL, &error))
   {
      ogs_error("PCS mongoc_collection_insert_one failed during delete-create process %s\n", error.message);
   }

   bson_destroy(query);
   bson_destroy(bson_doc);
   free(pcs_dbnewdata);

   return EXIT_SUCCESS;
}

char *read_data_from_db(mongoc_collection_t *collection, const char *pcs_dockey, char *pcs_docval, long pcs_docseid)
{
   mongoc_cursor_t *cursor;
   const bson_t *doc;
   bson_t *query = NULL;
   char *pcs_dbrdata;

   if (pcs_docseid == -1)
   {
      query = BCON_NEW(pcs_dockey, pcs_docval);
   }
   else
   {
      query = bson_new();
      BSON_APPEND_DOUBLE(query, pcs_dockey, pcs_docseid);
   }

   cursor = mongoc_collection_find_with_opts(collection, query, NULL, NULL);
   int i = 0;

   while (mongoc_cursor_next(cursor, &doc))
   {
      i = i + 1;
      pcs_dbrdata = bson_as_relaxed_extended_json(doc, NULL);
      ogs_debug("PCS Read Data from MongoDB is %s", pcs_dbrdata);
   }

   if (i == 0)
   {
      if (pcs_docseid == -1)
      {
         asprintf(&pcs_dbrdata, "{ \"%s\" : \"%s\" }", pcs_dockey, pcs_docval);
      }
      else
      {
         asprintf(&pcs_dbrdata, "{ \"%s\" : %ld }", pcs_dockey, pcs_docseid);
      }
   }
   bson_destroy(query);
   mongoc_cursor_destroy(cursor);

   return pcs_dbrdata;
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

char *decode_nas_qos_rule_hex_to_str(char *pcs_hexipdata)
{
   char pcs_temp[8];
   char pcs_comma[] = ",";
   char pcs_curlybrace[] = "}";
   char pcs_squarebrace[] = "]";
   int pcs_num_qos_rules = 0;
   char *pcs_docjson, *pcs_keyval, *pcs_var;
   char pcs_hexipdatadup[strlen(pcs_hexipdata)];
   pcs_get_substring(pcs_hexipdata, pcs_hexipdatadup, 0, strlen(pcs_hexipdata));
   asprintf(&pcs_docjson, "[");
   while (pcs_hexipdatadup[0] != '\0')
   {
      if (pcs_num_qos_rules > 0)
      {
         pcs_docjson = pcs_combine_strings(pcs_docjson, pcs_comma);
      }
      int pcs_qosruleid = pcs_hex_to_int(pcs_hexipdata, 0, 2);
      asprintf(&pcs_keyval, "{\"QOS-Rule-Identifier\": %d", pcs_qosruleid);
      int pcs_qosrulelen = pcs_hex_to_int(pcs_hexipdata, 2, 6);
      asprintf(&pcs_var, ", \"QOS-Rule-Length\": %d", pcs_qosrulelen);
      pcs_keyval = pcs_combine_strings(pcs_keyval, pcs_var);

      char pcs_qosrulef1[9];
      pcs_hex_to_binary_str(pcs_hexipdata, pcs_qosrulef1, 6, 8);
      pcs_get_substring(pcs_qosrulef1, pcs_temp, 0, 3);
      int pcs_qosruleopcode = pcs_binary_to_decimal(pcs_temp);
      asprintf(&pcs_var, ", \"QOS-Rule-Operation-Code-Value\": %d", pcs_qosruleopcode);
      pcs_keyval = pcs_combine_strings(pcs_keyval, pcs_var);

      if (pcs_qosruleopcode == 1)
      {
         asprintf(&pcs_var, ", \"QOS-Rule-Operation-Code-Description\": \"CREATE_NEW_QOS_RULE\"");
         pcs_keyval = pcs_combine_strings(pcs_keyval, pcs_var);
      }
      else
      {
         asprintf(&pcs_var, ", \"QOS-Rule-Operation-Code-Description\": \"INCORRECT_QOS_RULE\"");
         pcs_keyval = pcs_combine_strings(pcs_keyval, pcs_var);
      }

      pcs_get_substring(pcs_qosrulef1, pcs_temp, 3, 4);
      int pcs_qosruledqr = pcs_binary_to_decimal(pcs_temp);
      asprintf(&pcs_var, ", \"QOS-Rule-DQR\": %d", pcs_qosruledqr);
      pcs_keyval = pcs_combine_strings(pcs_keyval, pcs_var);

      pcs_get_substring(pcs_qosrulef1, pcs_temp, 4, 8);
      int pcs_qosrulenumpf = pcs_binary_to_decimal(pcs_temp);
      asprintf(&pcs_var, ", \"QOS-Rule-Num-Packet-Filters\": %d", pcs_qosrulenumpf);
      pcs_keyval = pcs_combine_strings(pcs_keyval, pcs_var);

      pcs_hex_to_binary_str(pcs_hexipdata, pcs_qosrulef1, 8, 10);
      pcs_get_substring(pcs_qosrulef1, pcs_temp, 2, 4);
      int pcs_qosrulepfdir = pcs_binary_to_decimal(pcs_temp);
      if (pcs_qosrulepfdir == 3)
      {
         asprintf(&pcs_var, ", \"Packet-Filter-1\": {\"QOS-Rule-Packet-Filters-Direction-Value\": %d, \"QOS-Rule-Packet-Filters-Direction-Description\": \"BIDIRECTIONAL_PACKET_FILTER\"", pcs_qosrulepfdir);
         pcs_keyval = pcs_combine_strings(pcs_keyval, pcs_var);
      }
      else
      {
         asprintf(&pcs_var, ", \"Packet-Filter-1\": {\"QOS-Rule-Packet-Filters-Direction-Value\": %d, \"QOS-Rule-Packet-Filters-Direction-Description\": \"INCORRECT_PACKET_FILTER_DIRECTION\"", pcs_qosrulepfdir);
         pcs_keyval = pcs_combine_strings(pcs_keyval, pcs_var);
      }

      pcs_get_substring(pcs_qosrulef1, pcs_temp, 4, 8);

      int pcs_qosrulepfid = pcs_binary_to_decimal(pcs_temp);
      asprintf(&pcs_var, ", \"QOS-Rule-Packet-Filters-Direction-ID\": %d", pcs_qosrulepfid);
      pcs_keyval = pcs_combine_strings(pcs_keyval, pcs_var);

      int pcs_qosrulepflen = pcs_hex_to_int(pcs_hexipdata, 10, 12);
      asprintf(&pcs_var, ", \"QOS-Rule-Packet-Filters-Length\": %d", pcs_qosrulepflen);
      pcs_keyval = pcs_combine_strings(pcs_keyval, pcs_var);

      int pcs_qosrulepfcomp = pcs_hex_to_int(pcs_hexipdata, 12, 14);
      if (pcs_qosrulepfcomp == 1)
      {
         asprintf(&pcs_var, ", \"QOS-Rule-Packet-Filters-Component-Value\": %d, \"QOS-Rule-Packet-Filters-Component-Description\": \"MATCH_ALL_PACKET_FILTER\"}", pcs_qosrulepfcomp);
         pcs_keyval = pcs_combine_strings(pcs_keyval, pcs_var);
      }
      else
      {
         asprintf(&pcs_var, ", \"QOS-Rule-Packet-Filters-Component-Value\": %d, \"QOS-Rule-Packet-Filters-Component-Description\": \"INCORRECT_PACKET_FILTER_COMPONENT\"}", pcs_qosrulepfcomp);
         pcs_keyval = pcs_combine_strings(pcs_keyval, pcs_var);
      }

      int pcs_qosrulepreced = pcs_hex_to_int(pcs_hexipdata, 14, 16);
      asprintf(&pcs_var, ", \"QOS-Rule-Precedence\": %d", pcs_qosrulepreced);
      pcs_keyval = pcs_combine_strings(pcs_keyval, pcs_var);

      pcs_hex_to_binary_str(pcs_hexipdata, pcs_qosrulef1, 16, 18);
      pcs_get_substring(pcs_qosrulef1, pcs_temp, 2, 8);
      int pcs_qosruleqfid = pcs_binary_to_decimal(pcs_temp);
      asprintf(&pcs_var, ", \"QOS-Rule-Flow-Identifier\": %d", pcs_qosruleqfid);
      pcs_keyval = pcs_combine_strings(pcs_keyval, pcs_var);

      pcs_keyval = pcs_combine_strings(pcs_keyval, pcs_curlybrace);
      pcs_docjson = pcs_combine_strings(pcs_docjson, pcs_keyval);

      pcs_num_qos_rules = pcs_num_qos_rules + 1;
      pcs_get_substring(pcs_hexipdata, pcs_hexipdatadup, 2 * (3 + pcs_qosrulelen), strlen(pcs_hexipdata));
   }
   pcs_docjson = pcs_combine_strings(pcs_docjson, pcs_squarebrace);

   return pcs_docjson;
}

char *decode_nas_qos_flow_hex_to_str(char *pcs_hexipdata)
{
   char pcs_temp[8], pcs_qosflowf1[9];
   char pcs_curlybrace[] = "}";
   char pcs_squarebrace[] = "]";
   char *pcs_docjson, *pcs_keyval, *pcs_var;
   asprintf(&pcs_docjson, "[");

   pcs_hex_to_binary_str(pcs_hexipdata, pcs_qosflowf1, 0, 2);
   pcs_get_substring(pcs_qosflowf1, pcs_temp, 2, 8);
   int pcs_qosflowid = pcs_binary_to_decimal(pcs_temp);
   asprintf(&pcs_keyval, "{\"QOS-Flow-Identifier\": %d", pcs_qosflowid);

   pcs_hex_to_binary_str(pcs_hexipdata, pcs_qosflowf1, 2, 4);
   pcs_get_substring(pcs_qosflowf1, pcs_temp, 0, 3);
   int pcs_qosflowopcode = pcs_binary_to_decimal(pcs_temp);
   if (pcs_qosflowopcode == 1)
   {
      asprintf(&pcs_var, ", \"QOS-Flow-Operation-Code-Value\": %d, \"QOS-Flow-Operation-Code-Description\": \"CREATE_NEW_QOS_FLOW\"", pcs_qosflowopcode);
      pcs_keyval = pcs_combine_strings(pcs_keyval, pcs_var);
   }
   else
   {
      asprintf(&pcs_var, ", \"QOS-Flow-Operation-Code-Value\": %d, \"QOS-Flow-Operation-Code-Description\": \"INCORRECT_QOS_FLOW\"", pcs_qosflowopcode);
      pcs_keyval = pcs_combine_strings(pcs_keyval, pcs_var);
   }

   pcs_hex_to_binary_str(pcs_hexipdata, pcs_qosflowf1, 4, 6);
   pcs_get_substring(pcs_qosflowf1, pcs_temp, 0, 2);
   int pcs_qosflowebit = pcs_binary_to_decimal(pcs_temp);
   asprintf(&pcs_var, ", \"QOS-Flow-Ebit\": %d", pcs_qosflowebit);
   pcs_keyval = pcs_combine_strings(pcs_keyval, pcs_var);

   pcs_get_substring(pcs_qosflowf1, pcs_temp, 2, 8);
   int pcs_qosflownumparam = pcs_binary_to_decimal(pcs_temp);
   asprintf(&pcs_var, ", \"QOS-Rule-Num-Parameters\": %d", pcs_qosflownumparam);
   pcs_keyval = pcs_combine_strings(pcs_keyval, pcs_var);

   int c = 1;
   int pcs_qosflowparamid, pcs_qosflowparamlen, pcs_qosflowparam5qi;
   for (; c <= pcs_qosflownumparam; c++)
   {
      pcs_qosflowparamid = pcs_hex_to_int(pcs_hexipdata, 6, 8);
      pcs_qosflowparamlen = pcs_hex_to_int(pcs_hexipdata, 8, 10);
      pcs_qosflowparam5qi = pcs_hex_to_int(pcs_hexipdata, 10, 12);
      asprintf(&pcs_var, ", \"Parameter-1\": { \"QOS-Flow-Param-Identifier\": %d, \"QOS-Flow-Param-Length\": %d, \"QOS-Flow-Param-5QI\": %d }", pcs_qosflowparamid, pcs_qosflowparamlen, pcs_qosflowparam5qi);
      pcs_keyval = pcs_combine_strings(pcs_keyval, pcs_var);
   }
   pcs_keyval = pcs_combine_strings(pcs_keyval, pcs_curlybrace);
   pcs_docjson = pcs_combine_strings(pcs_docjson, pcs_keyval);
   pcs_docjson = pcs_combine_strings(pcs_docjson, pcs_squarebrace);

   return pcs_docjson;
}

char *decode_nas_epco_hex_to_str(char *pcs_hexipdata)
{
   char pcs_temp[8];
   char pcs_curlybrace[] = "}";
   char *pcs_docjson, *pcs_keyval, *pcs_var, *pcs_protcnt2ipv4;
   char pcs_qosflowf1[9], pcs_protcnt1id[5], pcs_protcnt2id[5];
   int pcs_procont1len, pcs_procont1ip, pcs_procont2len, pcs_procont2ip;
   struct in_addr pcs_addr;
   asprintf(&pcs_docjson, "{");

   pcs_hex_to_binary_str(pcs_hexipdata, pcs_qosflowf1, 0, 2);
   pcs_get_substring(pcs_qosflowf1, pcs_temp, 0, 1);
   int pcs_epcoextension = pcs_binary_to_decimal(pcs_temp);
   asprintf(&pcs_keyval, "\"IS-Extension\": %d", pcs_epcoextension);
   pcs_get_substring(pcs_qosflowf1, pcs_temp, 5, 8);
   int pcs_epcocp = pcs_binary_to_decimal(pcs_temp);
   if (pcs_epcocp == 0)
   {
      asprintf(&pcs_var, ", \"Configuration-Protocol-Value\": %d, \"Configuration-Protocol-Description\": \"CONFIGURATION_PROTOCOL_PPP\"", pcs_epcocp);
      pcs_keyval = pcs_combine_strings(pcs_keyval, pcs_var);
   }
   else
   {
      asprintf(&pcs_var, ", \"Configuration-Protocol-Value\": %d, \"Configuration-Protocol-Description\": \"INCORRECT_CONFIGURATION_PROTOCOL\"", pcs_epcocp);
      pcs_keyval = pcs_combine_strings(pcs_keyval, pcs_var);
   }

   pcs_get_substring(pcs_hexipdata, pcs_protcnt1id, 2, 6);
   if (strcmp(pcs_protcnt1id, "000d") == 0)
   {
      pcs_procont1len = pcs_hex_to_int(pcs_hexipdata, 6, 8);
      pcs_procont1ip = pcs_hex_to_int(pcs_hexipdata, 8, 16);
      unsigned char bytes[4];
      bytes[0] = pcs_procont1ip & 0xFF;
      bytes[1] = (pcs_procont1ip >> 8) & 0xFF;
      bytes[2] = (pcs_procont1ip >> 16) & 0xFF;
      bytes[3] = (pcs_procont1ip >> 24) & 0xFF;
      asprintf(&pcs_var, ", \"Protocol-Containers\": [{\"Container-ID\": \"%s\", \"Container-Description\": \"DNS_SERVER_IPV4_ADDRESS\", \"Container-Length\": \"%d\", \"IPv4-Address\": \"%d.%d.%d.%d\"}", pcs_protcnt1id, pcs_procont1len, bytes[3], bytes[2], bytes[1], bytes[0]);
      pcs_keyval = pcs_combine_strings(pcs_keyval, pcs_var);
   }

   pcs_get_substring(pcs_hexipdata, pcs_protcnt2id, 16, 20);
   if (strcmp(pcs_protcnt2id, "000d") == 0)
   {
      pcs_procont2len = pcs_hex_to_int(pcs_hexipdata, 20, 22);
      pcs_procont2ip = pcs_hex_to_int(pcs_hexipdata, 22, 30);
      pcs_addr.s_addr = htonl(pcs_procont2ip);
      pcs_protcnt2ipv4 = inet_ntoa(pcs_addr);
      asprintf(&pcs_var, ", {\"Container-ID\": \"%s\", \"Container-Description\": \"DNS_SERVER_IPV4_ADDRESS\", \"Container-Length\": \"%d\", \"IPv4-Address\": \"%s\"}]", pcs_protcnt2id, pcs_procont2len, pcs_protcnt2ipv4);
      pcs_keyval = pcs_combine_strings(pcs_keyval, pcs_var);
   }

   pcs_keyval = pcs_combine_strings(pcs_keyval, pcs_curlybrace);
   pcs_docjson = pcs_combine_strings(pcs_docjson, pcs_keyval);

   return pcs_docjson;
}

struct pcs_upf_n4_create pcs_get_upf_n4_create_data(upf_sess_t *sess)
{
   struct pcs_upf_n4_create pcs_n4createdata;

   char *pcs_pfcpie, *pcs_pdrs, *pcs_fars, *pcs_qers, *pcs_var, *pcs_temp;
   char pcs_comma[] = ",";
   char pcs_curlybrace[] = "}";
   char pcs_squarebrace[] = "]";
   int pcs_numpdr = 0, pcs_numfar = 0, pcs_numqer = 0;
   ogs_pfcp_pdr_t *pdr = NULL;
   ogs_pfcp_far_t *far = NULL;
   ogs_pfcp_qer_t *qer = NULL;
   pcs_n4createdata.pcs_upfnodeip = ogs_strdup(ogs_ipv4_to_string(sess->pfcp_node->sock->local_addr.sin.sin_addr.s_addr));
   pcs_n4createdata.pcs_upfn4seid = sess->upf_n4_seid;
   pcs_n4createdata.pcs_smfn4seid = sess->smf_n4_seid;

   asprintf(&pcs_pdrs, "[");
   ogs_list_for_each(&sess->pfcp.pdr_list, pdr)
   {
      ogs_assert(pdr);

      pcs_numpdr = pcs_numpdr + 1;
      if (pcs_numpdr > 1)
      {
         pcs_pdrs = pcs_combine_strings(pcs_pdrs, pcs_comma);
      }

      asprintf(&pcs_pfcpie, "{\"id\": %d", pdr->id);
      asprintf(&pcs_var, ", \"precedence\": %d", pdr->precedence);
      pcs_pfcpie = pcs_combine_strings(pcs_pfcpie, pcs_var);
      asprintf(&pcs_var, ", \"src-if\": %d", pdr->src_if);
      pcs_pfcpie = pcs_combine_strings(pcs_pfcpie, pcs_var);
      if (pdr->f_teid_len)
      {
         asprintf(&pcs_var, ", \"F-TEID\": {\"fteid\": %d", pdr->f_teid.teid);
         pcs_pfcpie = pcs_combine_strings(pcs_pfcpie, pcs_var);
         pcs_temp = ogs_ipv4_to_string(ogs_gtp_self()->gtpu_addr->sin.sin_addr.s_addr);
         asprintf(&pcs_var, ", \"fteid-ip\": \"%s\"", pcs_temp);
         pcs_pfcpie = pcs_combine_strings(pcs_pfcpie, pcs_var);
         ogs_free(pcs_temp);
         asprintf(&pcs_var, ", \"ip-type\": %d}", pdr->f_teid.ipv4);
         pcs_pfcpie = pcs_combine_strings(pcs_pfcpie, pcs_var);
      }
      if (pdr->ue_ip_addr.addr)
      {
         pcs_temp = ogs_ipv4_to_string(pdr->ue_ip_addr.addr);
         asprintf(&pcs_var, ", \"ue-ip\": \"%s\"", pcs_temp);
         pcs_pfcpie = pcs_combine_strings(pcs_pfcpie, pcs_var);
         ogs_free(pcs_temp);
         asprintf(&pcs_var, ", \"pdn-type\": %d", pdr->ue_ip_addr.ipv4);
         pcs_pfcpie = pcs_combine_strings(pcs_pfcpie, pcs_var);
      }
      if (pdr->dnn)
      {
         asprintf(&pcs_var, ", \"dnn\": \"%s\"", pdr->dnn);
         pcs_pfcpie = pcs_combine_strings(pcs_pfcpie, pcs_var);
      }
      if (sizeof(*pdr->flow_description))
      {
         asprintf(&pcs_var, ", \"flow-description\": \"%s\"", *pdr->flow_description);
         if (strstr(pcs_var, "null") == NULL)
         {
            pcs_pfcpie = pcs_combine_strings(pcs_pfcpie, pcs_var);
         }
      }
      if (pdr->qfi)
      {
         asprintf(&pcs_var, ", \"qfi\": %d", pdr->qfi);
         pcs_pfcpie = pcs_combine_strings(pcs_pfcpie, pcs_var);
      }
      if (pdr->outer_header_removal_len)
      {
         asprintf(&pcs_var, ", \"outer-header-removal\": %d", pdr->outer_header_removal.description);
         pcs_pfcpie = pcs_combine_strings(pcs_pfcpie, pcs_var);
      }
      if (pdr->far)
      {
         if (pdr->far->id)
         {
            asprintf(&pcs_var, ", \"far-id\": %d", pdr->far->id);
            pcs_pfcpie = pcs_combine_strings(pcs_pfcpie, pcs_var);
         }
      }
      if (pdr->qer)
      {
         if (pdr->qer->id)
         {
            asprintf(&pcs_var, ", \"qer-id\": %d", pdr->qer->id);
            pcs_pfcpie = pcs_combine_strings(pcs_pfcpie, pcs_var);
         }
      }
      pcs_pfcpie = pcs_combine_strings(pcs_pfcpie, pcs_curlybrace);
      pcs_pdrs = pcs_combine_strings(pcs_pdrs, pcs_pfcpie);
   }
   pcs_n4createdata.pcs_pdrs = pcs_combine_strings(pcs_pdrs, pcs_squarebrace);

   asprintf(&pcs_fars, "[");
   ogs_list_for_each(&sess->pfcp.far_list, far)
   {
      pcs_numfar = pcs_numfar + 1;

      if (pcs_numfar > 1)
      {
         pcs_fars = pcs_combine_strings(pcs_fars, pcs_comma);
      }

      asprintf(&pcs_pfcpie, "{\"id\": %d", far->id);
      asprintf(&pcs_var, ", \"apply-action\": %d", far->apply_action);
      pcs_pfcpie = pcs_combine_strings(pcs_pfcpie, pcs_var);
      if (far->dst_if)
      {
         asprintf(&pcs_var, ", \"dst-if\": %d", far->dst_if);
         pcs_pfcpie = pcs_combine_strings(pcs_pfcpie, pcs_var);
      }
      if (far->outer_header_creation.addr)
      {
         asprintf(&pcs_var, ", \"outer-header-creation\": {\"teid\": %d", far->outer_header_creation.teid);
         pcs_pfcpie = pcs_combine_strings(pcs_pfcpie, pcs_var);
         pcs_temp = ogs_ipv4_to_string(far->outer_header_creation.addr);
         asprintf(&pcs_var, ", \"ip-addr\": \"%s\"}", pcs_temp);
         pcs_pfcpie = pcs_combine_strings(pcs_pfcpie, pcs_var);
         ogs_free(pcs_temp);
      }
      pcs_pfcpie = pcs_combine_strings(pcs_pfcpie, pcs_curlybrace);
      pcs_fars = pcs_combine_strings(pcs_fars, pcs_pfcpie);
   }
   pcs_n4createdata.pcs_fars = pcs_combine_strings(pcs_fars, pcs_squarebrace);

   asprintf(&pcs_qers, "[");
   ogs_list_for_each(&sess->pfcp.qer_list, qer)
   {
      pcs_numqer = pcs_numqer + 1;
      if (pcs_numqer > 1)
      {
         pcs_qers = pcs_combine_strings(pcs_qers, pcs_comma);
      }

      asprintf(&pcs_pfcpie, "{\"id\": %d", qer->id);
      asprintf(&pcs_var, ", \"gate-status\": {\"uplink\": %d, \"downlink\": %d}", qer->gate_status.uplink, qer->gate_status.downlink);
      pcs_pfcpie = pcs_combine_strings(pcs_pfcpie, pcs_var);
      asprintf(&pcs_var, ", \"mbr\": {\"uplink\": %ld, \"downlink\": %ld}", qer->mbr.uplink, qer->mbr.downlink);
      pcs_pfcpie = pcs_combine_strings(pcs_pfcpie, pcs_var);
      asprintf(&pcs_var, ", \"qfi\": %d", qer->qfi);
      pcs_pfcpie = pcs_combine_strings(pcs_pfcpie, pcs_var);
      pcs_pfcpie = pcs_combine_strings(pcs_pfcpie, pcs_curlybrace);
      pcs_qers = pcs_combine_strings(pcs_qers, pcs_pfcpie);
   }
   pcs_n4createdata.pcs_qers = pcs_combine_strings(pcs_qers, pcs_squarebrace);

   asprintf(&pcs_pfcpie, "{\"bar-id\": %d}", sess->pfcp.bar->id);
   pcs_n4createdata.pcs_bars = pcs_pfcpie;

   //free(pcs_var);
   //free(pcs_pfcpie);

   return (pcs_n4createdata);
}

void pcs_upf_create_udsf(void *pcs_upfcreateudsf)
{
   struct pcs_upf_create_udsf_s *pcs_upfcreateudsfstruct = pcs_upfcreateudsf;
   char *pcs_dbrdata = pcs_upfcreateudsfstruct->pcs_dbrdata;
   upf_sess_t *sess = upf_sess_find_by_up_seid((uint64_t)pcs_upfcreateudsfstruct->pcs_upfn4seid);

   char *pcs_dbcollectioname = getenv("PCS_DB_COLLECTION_NAME");
   uint8_t pcs_isproceduralstateless = pcs_set_int_from_env("PCS_IS_PROCEDURAL_STATELESS");
   mongoc_collection_t *pcs_dbcollection;
   mongoc_client_t *pcs_mongoclient = mongoc_client_pool_try_pop(PCS_MONGO_POOL);
   if (pcs_mongoclient == NULL)
   {
      pcs_dbcollection = pcs_upfcreateudsfstruct->pcs_dbcollection;
   }
   else
   {
      pcs_dbcollection = mongoc_client_get_collection(pcs_mongoclient, "pcs_db", pcs_dbcollectioname);
   }

   struct pcs_upf_n4_create pcs_n4createdata;
   pcs_n4createdata.pcs_smfn4seid = sess->smf_n4_seid;
   char *pcs_upfdbid;
   asprintf(&pcs_upfdbid, "%ld", pcs_n4createdata.pcs_smfn4seid);

   if (strlen(pcs_dbrdata) <= 19 && !pcs_isproceduralstateless && strcmp(pcs_dbcollectioname, "upf") == 0)
   {
      char *pcs_docjson;
      int pcs_rv;
      pcs_n4createdata = pcs_get_upf_n4_create_data(sess);
      pcs_n4createdata.pcs_smfnodeip = ogs_ipv4_to_string(sess->pfcp_node->addr.sin.sin_addr.s_addr);

      asprintf(&pcs_docjson, "{\"_id\": \"%ld\", \"pcs-pfcp-est-done\": 1, \"UPF-Node-IP\": \"%s\", \"SMF-Node-IP\": \"%s\", \"UPF-N4-SEID\": %ld, \"SMF-N4-SEID\": %ld, \"Cause\": %d, \"PDRs\": %s, \"FARs\": %s, \"QERs\": %s, \"BAR\": %s}", pcs_n4createdata.pcs_smfn4seid, pcs_n4createdata.pcs_upfnodeip, pcs_n4createdata.pcs_smfnodeip, pcs_n4createdata.pcs_upfn4seid, pcs_n4createdata.pcs_smfn4seid, 1, pcs_n4createdata.pcs_pdrs, pcs_n4createdata.pcs_fars, pcs_n4createdata.pcs_qers, pcs_n4createdata.pcs_bars);

      bson_error_t error;
      bson_t *bson_doc = bson_new_from_json((const uint8_t *)pcs_docjson, -1, &error);
      pcs_rv = insert_data_to_db(pcs_dbcollection, "create", pcs_upfdbid, bson_doc);

      if (pcs_rv != OGS_OK)
      {
         ogs_error("PCS Error while inserting N4 Session Establishment data to MongoDB for Session with N4 SEID [%ld]", sess->smf_n4_seid);
      }
      else
      {
         ogs_info("PCS Successfully inserted N4 Session Establishment data to MongoDB for Session with N4 SEID [%ld]", sess->smf_n4_seid);
      }

      ogs_free(pcs_n4createdata.pcs_upfnodeip);
      ogs_free(pcs_n4createdata.pcs_smfnodeip);
      free(pcs_upfdbid);
      free(pcs_n4createdata.pcs_pdrs);
      free(pcs_n4createdata.pcs_fars);
      free(pcs_docjson);
   }
   else if (!pcs_isproceduralstateless && strcmp(pcs_dbcollectioname, "upf") != 0)
   {
      ogs_info("PCS Successfully completed N4 Session Establishment transaction with shared UDSF for Session with N4 SEID [%ld]", sess->smf_n4_seid);
   }

   mongoc_client_pool_push(PCS_MONGO_POOL, pcs_mongoclient);
   sess->pcs.pcs_udsfcreatedone = 1;
   return;
   //pthread_exit(NULL);
}

void pcs_upf_update_udsf(void *pcs_upfupdateudsf)
{
   struct pcs_upf_create_udsf_s *pcs_upfupdateudsfstruct = pcs_upfupdateudsf;
   char *pcs_dbrdata = pcs_upfupdateudsfstruct->pcs_dbrdata;
   upf_sess_t *sess = upf_sess_find_by_up_seid((uint64_t)pcs_upfupdateudsfstruct->pcs_upfn4seid);

   char *pcs_dbcollectioname = getenv("PCS_DB_COLLECTION_NAME");
   uint8_t pcs_isproceduralstateless = pcs_set_int_from_env("PCS_IS_PROCEDURAL_STATELESS");
   uint8_t pcs_updateapienabledmodify = pcs_set_int_from_env("PCS_UPDATE_API_ENABLED_MODIFY");
   mongoc_collection_t *pcs_dbcollection;
   mongoc_client_t *pcs_mongoclient = mongoc_client_pool_try_pop(PCS_MONGO_POOL);
   if (pcs_mongoclient == NULL)
   {
      pcs_dbcollection = pcs_upfupdateudsfstruct->pcs_dbcollection;
   }
   else
   {
      pcs_dbcollection = mongoc_client_get_collection(pcs_mongoclient, "pcs_db", pcs_dbcollectioname);
   }

   uint64_t pcs_smfn4seid = sess->smf_n4_seid;
   char *pcs_upfdbid;
   double pcs_pfcpestdone = 0;
   asprintf(&pcs_upfdbid, "%ld", pcs_smfn4seid);
   if (!pcs_isproceduralstateless)
   {
      JSON_Value *pcs_dbrdatajsonval = json_parse_string(pcs_dbrdata);
      if (json_value_get_type(pcs_dbrdatajsonval) == JSONObject)
      {
         JSON_Object *pcs_dbrdatajsonobj = json_object(pcs_dbrdatajsonval);
         pcs_pfcpestdone = json_object_get_number(pcs_dbrdatajsonobj, "pcs-pfcp-est-done");
      }
      json_value_free(pcs_dbrdatajsonval);
   }

   if (strcmp(pcs_dbcollectioname, "upf") == 0)
   {
      if ((int)pcs_pfcpestdone)
      {
         char *pcs_pfcpie, *pcs_fars, *pcs_var, *pcs_temp;
         char pcs_comma[] = ",";
         char pcs_curlybrace[] = "}";
         char pcs_squarebrace[] = "]";
         int pcs_rv, pcs_numfar = 0;
         ogs_pfcp_far_t *far = NULL;

         asprintf(&pcs_fars, "[");
         ogs_list_for_each(&sess->pfcp.far_list, far)
         {
            pcs_numfar = pcs_numfar + 1;
            if (pcs_numfar > 1)
            {
               pcs_fars = pcs_combine_strings(pcs_fars, pcs_comma);
            }

            asprintf(&pcs_pfcpie, "{\"id\": %d", far->id);
            asprintf(&pcs_var, ", \"apply-action\": %d", far->apply_action);
            pcs_pfcpie = pcs_combine_strings(pcs_pfcpie, pcs_var);
            if (far->dst_if)
            {
               asprintf(&pcs_var, ", \"dst-if\": %d", far->dst_if);
               pcs_pfcpie = pcs_combine_strings(pcs_pfcpie, pcs_var);
            }
            if (far->outer_header_creation.addr)
            {
               asprintf(&pcs_var, ", \"outer-header-creation\": {\"teid\": %d", far->outer_header_creation.teid);
               pcs_pfcpie = pcs_combine_strings(pcs_pfcpie, pcs_var);
               pcs_temp = ogs_ipv4_to_string(far->outer_header_creation.addr);
               asprintf(&pcs_var, ", \"ip-addr\": \"%s\"}", pcs_temp);
               pcs_pfcpie = pcs_combine_strings(pcs_pfcpie, pcs_var);
               ogs_free(pcs_temp);
            }
            pcs_pfcpie = pcs_combine_strings(pcs_pfcpie, pcs_curlybrace);
            pcs_fars = pcs_combine_strings(pcs_fars, pcs_pfcpie);
         }
         pcs_fars = pcs_combine_strings(pcs_fars, pcs_squarebrace);

         if (!pcs_isproceduralstateless)
         {
            if (pcs_updateapienabledmodify)
            {
               bson_error_t error;
               bson_t *bson_doc_ary = bson_new_from_json((const uint8_t *)pcs_fars, -1, &error);

               bson_t *bson_doc = BCON_NEW("$set", "{", "pcs-pfcp-update-done", BCON_INT32(1), "FARs", BCON_ARRAY(bson_doc_ary), "}");
               pcs_rv = insert_data_to_db(pcs_dbcollection, "update", pcs_upfdbid, bson_doc);
               bson_destroy(bson_doc_ary);
            }
            else
            {
               char *pcs_updatedoc;
               asprintf(&pcs_updatedoc, ", \"pcs-pfcp-update-done\": 1, \"FARs\": %s}", pcs_fars);
               pcs_rv = delete_create_data_to_db(pcs_dbcollection, pcs_upfdbid, pcs_dbrdata, pcs_updatedoc);
            }
         }

         if (pcs_rv != OGS_OK)
         {
            ogs_error("PCS Error while inserting N4 Session Modification data to MongoDB for Session with N4 SEID [%ld]", sess->smf_n4_seid);
         }
         else
         {
            ogs_info("PCS Successfully inserted N4 Session Modification data to MongoDB for Session with N4 SEID [%ld]", sess->smf_n4_seid);
         }

         free(pcs_var);
         free(pcs_upfdbid);
         free(pcs_pfcpie);
         free(pcs_fars);

      }
      else
      {
         ogs_error("PCS PFCP Modify request got triggered without processing PFCP Create request");
      }
   }
   else
   {
      ogs_info("PCS Successfully completed N4 Session Modification transaction with shared UDSF for Session with N4 SEID [%ld]", sess->smf_n4_seid);
   }

   mongoc_client_pool_push(PCS_MONGO_POOL, pcs_mongoclient);
   sess->pcs.pcs_udsfupdatedone = 1;

   return;
   //pthread_exit(NULL);
}