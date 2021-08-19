#define _GNU_SOURCE
#include <stdio.h>
#include "mongoc.h"
#include "ogs-app.h"
#include "bson.h"
#include "pcs-helper.h"
#include <arpa/inet.h>
#include "parson.h"

extern mongoc_client_pool_t *PCS_MONGO_POOL;

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

char *read_data_from_db(mongoc_collection_t *collection, char *pcs_docid)
{
   mongoc_cursor_t *cursor;
   const bson_t *doc;
   bson_t *query = NULL;
   char *pcs_dbrdata;

   query = BCON_NEW("_id", pcs_docid);
   cursor = mongoc_collection_find_with_opts(collection, query, NULL, NULL);
   int i = 0;

   while (mongoc_cursor_next(cursor, &doc))
   {
      i = i + 1;
      pcs_dbrdata = bson_as_relaxed_extended_json(doc, NULL);
      ogs_debug("PCS Read Data from MongoDB for id %s is %s", pcs_docid, pcs_dbrdata);
   }

   if (i == 0)
   {
      asprintf(&pcs_dbrdata, "{ \"_id\" : \"%s\" }", pcs_docid);
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

struct pcs_amf_create pcs_get_amf_create_data(amf_sess_t *sess)
{
   struct pcs_amf_create pcs_createdata;
   pcs_createdata.pcs_supi = sess->amf_ue->supi;
   pcs_createdata.pcs_smcontextref = sess->sm_context_ref;
   pcs_createdata.pcs_pdusessionid = sess->psi;
   pcs_createdata.pcs_amfueaccesstype = sess->amf_ue->nas.access_type;
   pcs_createdata.pcs_amfueallowedpdusessionstatus = sess->amf_ue->nas.present.allowed_pdu_session_status;
   pcs_createdata.pcs_amfuepei = sess->amf_ue->pei;
   pcs_createdata.pcs_amfsessdnn = sess->dnn;
   pcs_createdata.pcs_snssaisst = sess->s_nssai.sst;
   pcs_createdata.pcs_snssaisd = ogs_s_nssai_sd_to_string(sess->s_nssai.sd);
   char pcs_plmnid[OGS_PLMNIDSTRLEN];
   ogs_plmn_id_to_string(&sess->amf_ue->guami->plmn_id, pcs_plmnid);
   char *pcs_amfueplmnid;
   asprintf(&pcs_amfueplmnid, "%s", pcs_plmnid);
   pcs_createdata.pcs_amfueplmnid = pcs_amfueplmnid;
   pcs_createdata.pcs_amfueamfid = ogs_amf_id_to_string(&sess->amf_ue->guami->amf_id);
   pcs_createdata.pcs_amfuetac = ogs_s_nssai_sd_to_string(sess->amf_ue->nr_tai.tac);
   pcs_createdata.pcs_amfuelocts = sess->amf_ue->ue_location_timestamp;
   pcs_createdata.pcs_ranuengapid = sess->amf_ue->ran_ue->ran_ue_ngap_id;
   pcs_createdata.pcs_amfuengapid = sess->amf_ue->ran_ue->amf_ue_ngap_id;
   pcs_createdata.pcs_ranuegnbid = sess->amf_ue->ran_ue->gnb->gnb_id;
   pcs_createdata.pcs_ranuerattype = OpenAPI_rat_type_ToString(sess->amf_ue->ran_ue->gnb->rat_type);

   return (pcs_createdata);
}

struct pcs_amf_n1n2 pcs_get_amf_n1n2_data(amf_sess_t *sess, ogs_pkbuf_t *n1buf, ogs_pkbuf_t *n2buf)
{
   struct pcs_amf_n1n2 pcs_n1n2data;
   int pcs_nas_decode_status = 1, pcs_ngap_decode_status = 1;
   ogs_nas_5gs_message_t pcs_nasmessage;
   if (n1buf)
      pcs_nas_decode_status = ogs_nas_5gsm_decode(&pcs_nasmessage, n1buf);
   if (pcs_nas_decode_status == 0 && pcs_nasmessage.gsm.h.message_type == 194)
   {
      ogs_nas_5gs_pdu_session_establishment_accept_t *pcs_pdusessionestablishmentaccept = &pcs_nasmessage.gsm.pdu_session_establishment_accept;
      pcs_n1n2data.pcs_pduaddress = ogs_ipv4_to_string(pcs_pdusessionestablishmentaccept->pdu_address.addr);
      pcs_n1n2data.pcs_dnn = pcs_pdusessionestablishmentaccept->dnn.value;
      pcs_n1n2data.pcs_sambrulv = pcs_pdusessionestablishmentaccept->session_ambr.uplink.value;
      pcs_n1n2data.pcs_sambrulu = pcs_pdusessionestablishmentaccept->session_ambr.uplink.unit;
      pcs_n1n2data.pcs_sambrdlv = pcs_pdusessionestablishmentaccept->session_ambr.downlink.value;
      pcs_n1n2data.pcs_sambrdlu = pcs_pdusessionestablishmentaccept->session_ambr.downlink.unit;
      pcs_n1n2data.pcs_pdusesstype = pcs_pdusessionestablishmentaccept->selected_pdu_session_type.value;

      char pcs_hexauthqosrule[OGS_HUGE_LEN];
      decode_buffer_to_hex(pcs_hexauthqosrule, (void *)pcs_pdusessionestablishmentaccept->authorized_qos_rules.buffer, pcs_pdusessionestablishmentaccept->authorized_qos_rules.length);
      pcs_n1n2data.pcs_nasqosrulestr = decode_nas_qos_rule_hex_to_str(pcs_hexauthqosrule);

      char pcs_hexqosflowdesc[OGS_HUGE_LEN];
      decode_buffer_to_hex(pcs_hexqosflowdesc, (void *)pcs_pdusessionestablishmentaccept->authorized_qos_flow_descriptions.buffer, pcs_pdusessionestablishmentaccept->authorized_qos_flow_descriptions.length);
      pcs_n1n2data.pcs_nasqosflowstr = decode_nas_qos_flow_hex_to_str(pcs_hexqosflowdesc);

      char pcs_hexepco[OGS_HUGE_LEN];
      decode_buffer_to_hex(pcs_hexepco, (void *)pcs_pdusessionestablishmentaccept->extended_protocol_configuration_options.buffer, pcs_pdusessionestablishmentaccept->extended_protocol_configuration_options.length);
      pcs_n1n2data.pcs_nasepcostr = decode_nas_epco_hex_to_str(pcs_hexepco);

      int pcs_k, pcs_l;
      uint32_t pcs_upfn3teid;
      ogs_ip_t pcs_upfn3ipbitstr;
      NGAP_PDUSessionResourceSetupRequestTransfer_t pcs_n2smmessage;
      NGAP_PDUSessionResourceSetupRequestTransferIEs_t *pcs_ie = NULL;
      NGAP_UPTransportLayerInformation_t *pcs_uptransportlayerinformation = NULL;
      NGAP_GTPTunnel_t *pcs_gtptunnel = NULL;
      NGAP_QosFlowSetupRequestList_t *pcs_qosflowsetuprequestlist = NULL;
      NGAP_QosFlowSetupRequestItem_t *pcs_qosflowsetuprequestitem = NULL;
      NGAP_QosFlowLevelQosParameters_t *pcs_qosflowlevelqosparameters = NULL;
      NGAP_QosCharacteristics_t *pcs_qoscharacteristics = NULL;
      NGAP_AllocationAndRetentionPriority_t *pcs_allocationandretentionpriority;
      pcs_ngap_decode_status = ogs_asn_decode(&asn_DEF_NGAP_PDUSessionResourceSetupRequestTransfer, &pcs_n2smmessage, sizeof(pcs_n2smmessage), n2buf);
      if (pcs_ngap_decode_status == 0)
      {
         for (pcs_k = 0; pcs_k < pcs_n2smmessage.protocolIEs.list.count; pcs_k++)
         {
            pcs_ie = pcs_n2smmessage.protocolIEs.list.array[pcs_k];
            switch (pcs_ie->id)
            {
            case NGAP_ProtocolIE_ID_id_PDUSessionAggregateMaximumBitRate:
               pcs_n1n2data.pcs_pdusessionaggregatemaximumbitrateul = sess->amf_ue->ue_ambr.uplink;
               pcs_n1n2data.pcs_pdusessionaggregatemaximumbitratedl = sess->amf_ue->ue_ambr.downlink;
               break;
            case NGAP_ProtocolIE_ID_id_QosFlowSetupRequestList:
               pcs_qosflowsetuprequestlist = &pcs_ie->value.choice.QosFlowSetupRequestList;
               ogs_assert(pcs_qosflowsetuprequestlist);
               for (pcs_l = 0; pcs_l < pcs_qosflowsetuprequestlist->list.count; pcs_l++)
               {
                  pcs_qosflowsetuprequestitem = (struct NGAP_QosFlowSetupRequestItem *)pcs_qosflowsetuprequestlist->list.array[pcs_l];
                  ogs_assert(pcs_qosflowsetuprequestitem);
                  pcs_qosflowlevelqosparameters = &pcs_qosflowsetuprequestitem->qosFlowLevelQosParameters;
                  pcs_qoscharacteristics = &pcs_qosflowlevelqosparameters->qosCharacteristics;
                  pcs_allocationandretentionpriority = &pcs_qosflowlevelqosparameters->allocationAndRetentionPriority;
                  pcs_n1n2data.pcs_preemptioncapability = pcs_allocationandretentionpriority->pre_emptionCapability;
                  pcs_n1n2data.pcs_preemptionvulnerability = pcs_allocationandretentionpriority->pre_emptionVulnerability;
                  pcs_n1n2data.pcs_plarp = pcs_allocationandretentionpriority->priorityLevelARP;
                  pcs_n1n2data.pcs_qosflowidentifier = pcs_qosflowsetuprequestitem->qosFlowIdentifier;
                  pcs_n1n2data.pcs_fiveqi = pcs_qoscharacteristics->choice.nonDynamic5QI->fiveQI;
               }
               break;
            case NGAP_ProtocolIE_ID_id_UL_NGU_UP_TNLInformation:
               pcs_uptransportlayerinformation = &pcs_ie->value.choice.UPTransportLayerInformation;
               pcs_gtptunnel = pcs_uptransportlayerinformation->choice.gTPTunnel;
               ogs_assert(pcs_gtptunnel);
               ogs_asn_BIT_STRING_to_ip(&pcs_gtptunnel->transportLayerAddress, &pcs_upfn3ipbitstr);
               ogs_asn_OCTET_STRING_to_uint32(&pcs_gtptunnel->gTP_TEID, &pcs_upfn3teid);
               pcs_n1n2data.pcs_upfn3teid = pcs_upfn3teid;
               pcs_n1n2data.pcs_upfn3ip = ogs_ipv4_to_string(pcs_upfn3ipbitstr.addr);
               break;
            }
         }
      }
      else
      {
         ogs_error("PCS ogs_asn_decode failed");
      }
   }
   else
   {
      ogs_error("PCS ogs_nas_5gsm_decode failed");
   }

   return (pcs_n1n2data);
}

struct pcs_amf_update pcs_get_amf_update_data(ogs_pkbuf_t *n2buf)
{
   struct pcs_amf_update pcs_updatedata;
   uint32_t pcs_upfn3teid;
   ogs_ip_t pcs_upfn3ipbitstr;
   NGAP_PDUSessionResourceSetupResponseTransfer_t pcs_n2smmessage;
   NGAP_QosFlowPerTNLInformation_t *pcs_dlqosflowpertnlinformation = NULL;
   NGAP_UPTransportLayerInformation_t *pcs_uptransportlayerinformation = NULL;
   NGAP_GTPTunnel_t *pcs_gtptunnel = NULL;
   NGAP_AssociatedQosFlowList_t *pcs_associatedqosflowlist = NULL;
   NGAP_AssociatedQosFlowItem_t *pcs_associatedqosflowitem = NULL;
   int i, pcs_decode_status = 1;

   pcs_decode_status = ogs_asn_decode(&asn_DEF_NGAP_PDUSessionResourceSetupResponseTransfer, &pcs_n2smmessage, sizeof(pcs_n2smmessage), n2buf);
   if (pcs_decode_status == 0)
   {
      pcs_dlqosflowpertnlinformation = &pcs_n2smmessage.dLQosFlowPerTNLInformation;
      pcs_uptransportlayerinformation = &pcs_dlqosflowpertnlinformation->uPTransportLayerInformation;
      pcs_gtptunnel = pcs_uptransportlayerinformation->choice.gTPTunnel;
      ogs_assert(pcs_gtptunnel);
      ogs_asn_BIT_STRING_to_ip(&pcs_gtptunnel->transportLayerAddress, &pcs_upfn3ipbitstr);
      pcs_updatedata.pcs_upfn3ip = ogs_ipv4_to_string(pcs_upfn3ipbitstr.addr);
      ogs_asn_OCTET_STRING_to_uint32(&pcs_gtptunnel->gTP_TEID, &pcs_upfn3teid);
      pcs_updatedata.pcs_upfn3teid = pcs_upfn3teid;

      pcs_associatedqosflowlist = &pcs_dlqosflowpertnlinformation->associatedQosFlowList;
      for (i = 0; i < pcs_associatedqosflowlist->list.count; i++)
      {
         pcs_associatedqosflowitem = (NGAP_AssociatedQosFlowItem_t *)pcs_associatedqosflowlist->list.array[i];
         if (pcs_associatedqosflowitem)
         {
            pcs_updatedata.pcs_qosflowid = pcs_associatedqosflowitem->qosFlowIdentifier;
         }
      }
   }
   else
   {
      ogs_error("PCS ogs_asn_decode failed");
   }

   //ogs_free(pcs_upfn3ip);
   //ogs_free(pcs_gtptunnel);
   //ogs_free(ie);

   return (pcs_updatedata);
}

void *pcs_amf_create_udsf(void *pcs_amfcreateudsf)
{
   struct pcs_amf_create_udsf_s *pcs_amfcreateudsfstruct = pcs_amfcreateudsf;

   ran_ue_t *ran_ue = ran_ue_find_by_amf_ue_ngap_id(pcs_amfcreateudsfstruct->pcs_amfuengapid);
   amf_ue_t *amf_ue;
   if (ran_ue)
   {
      amf_ue = ran_ue->amf_ue;
   }
   else
   {
      return NULL;
   }

   amf_sess_t *sess = amf_sess_find_by_psi(amf_ue, pcs_amfcreateudsfstruct->pcs_pdusessionid);
   char *pcs_dbcollectioname = getenv("PCS_DB_COLLECTION_NAME");
   uint8_t pcs_isproceduralstateless = pcs_set_int_from_env("PCS_IS_PROCEDURAL_STATELESS");
   
   mongoc_collection_t *pcs_dbcollection;
   mongoc_client_t *pcs_mongoclient = mongoc_client_pool_try_pop(PCS_MONGO_POOL);
   if (pcs_mongoclient == NULL)
   {
      pcs_dbcollection = pcs_amfcreateudsfstruct->pcs_dbcollection;
   }
   else
   {
      pcs_dbcollection = mongoc_client_get_collection(pcs_mongoclient, "pcs_db", pcs_dbcollectioname);
   }
   char *pcs_imsistr;
   if (sess)
   {
      pcs_imsistr = sess->amf_ue->supi;
   }
   else
   {
      return NULL;
   }
   pcs_imsistr += 5;
   char *pcs_dbrdata = read_data_from_db(pcs_dbcollection, pcs_imsistr);
   if (strlen(pcs_dbrdata) <= 29 && !pcs_isproceduralstateless && strcmp(pcs_dbcollectioname, "amf") == 0)
   {
      struct pcs_amf_create pcs_createdata = pcs_get_amf_create_data(sess);
      int pcs_rv;
      char *pcs_docjson;
      asprintf(&pcs_docjson, "{\"_id\": \"%s\", \"pcs-create-done\": 1, \"supi\": \"%s\", \"sm-context-ref\": \"%s\", \"pdu-session-id\": %d, \"ue-access-type\": %d, \"allowed_pdu_session_status\": %d, \"pei\": \"%s\", \"dnn\": \"%s\", \"s-nssai\": {\"sst\": %d, \"sd\": \"%s\"}, \"plmnid\": \"%s\", \"amf-id\": \"%s\", \"tac\": \"%s\", \"ue-location-timestamp\": %ld, \"ran-ue-ngap-id\": %d, \"amf-ue-ngap-id\": %d, \"gnb-id\": %d, \"rat_type\": \"%s\"}", pcs_imsistr, pcs_createdata.pcs_supi, pcs_createdata.pcs_smcontextref, pcs_createdata.pcs_pdusessionid, pcs_createdata.pcs_amfueaccesstype, pcs_createdata.pcs_amfueallowedpdusessionstatus, pcs_createdata.pcs_amfuepei, pcs_createdata.pcs_amfsessdnn, pcs_createdata.pcs_snssaisst, pcs_createdata.pcs_snssaisd, pcs_createdata.pcs_amfueplmnid, pcs_createdata.pcs_amfueamfid, pcs_createdata.pcs_amfuetac, (long)pcs_createdata.pcs_amfuelocts, pcs_createdata.pcs_ranuengapid, pcs_createdata.pcs_amfuengapid, pcs_createdata.pcs_ranuegnbid, pcs_createdata.pcs_ranuerattype);

      bson_error_t error;
      bson_t *bson_doc = bson_new_from_json((const uint8_t *)pcs_docjson, -1, &error);
      pcs_rv = insert_data_to_db(pcs_dbcollection, "create", pcs_imsistr, bson_doc);
      ogs_free(pcs_createdata.pcs_snssaisd);
      ogs_free(pcs_createdata.pcs_amfueamfid);
      ogs_free(pcs_createdata.pcs_amfuetac);
      free(pcs_createdata.pcs_amfueplmnid);
      free(pcs_docjson);
      if (pcs_rv != OGS_OK)
      {
         ogs_error("PCS Error while inserting Create-SM-Context data to MongoDB for supi [%s]", sess->amf_ue->supi);
      }
      else
      {
         ogs_info("PCS Successfully inserted Create-SM-Context data to MongoDB for supi [%s]", sess->amf_ue->supi);
      }
   }
   else if (!pcs_isproceduralstateless && strcmp(pcs_dbcollectioname, "amf") != 0)
   {
      ogs_info("PCS Successfully completed Create transaction with shared UDSF for supi [%s]", sess->amf_ue->supi);
   }
   mongoc_collection_destroy(pcs_dbcollection);
   mongoc_client_pool_push(PCS_MONGO_POOL, pcs_mongoclient);
   sess->pcs.pcs_udsfcreatedone = 1;
   return NULL;
   //pthread_exit(NULL);
}

void *pcs_amf_n1n2_udsf(void *pcs_amfn1n2udsf)
{
   struct pcs_amf_n1n2_udsf_s *pcs_amfn1n2udsfstruct = pcs_amfn1n2udsf;
   ogs_pkbuf_t *n1buf = pcs_amfn1n2udsfstruct->n1buf;
   ogs_pkbuf_t *n2buf = pcs_amfn1n2udsfstruct->n2buf;
   uint8_t pdu_session_id = pcs_amfn1n2udsfstruct->pdu_session_id;

   ran_ue_t *ran_ue = ran_ue_find_by_amf_ue_ngap_id(pcs_amfn1n2udsfstruct->pcs_amfuengapid);
   amf_ue_t *amf_ue;
   if (ran_ue)
   {
      amf_ue = ran_ue->amf_ue;
   }
   else
   {
      return NULL;
   }

   amf_sess_t *sess = amf_sess_find_by_psi(amf_ue, pcs_amfn1n2udsfstruct->pcs_pdusessionid);
   char *pcs_dbcollectioname = getenv("PCS_DB_COLLECTION_NAME");
   uint8_t pcs_updateapienabledn1n2 = pcs_set_int_from_env("PCS_UPDATE_API_ENABLED_N1N2");

   mongoc_collection_t *pcs_dbcollection;
   mongoc_client_t *pcs_mongoclient = mongoc_client_pool_try_pop(PCS_MONGO_POOL);
   if (pcs_mongoclient == NULL)
   {
      pcs_dbcollection = pcs_amfn1n2udsfstruct->pcs_dbcollection;
   }
   else
   {
      pcs_dbcollection = mongoc_client_get_collection(pcs_mongoclient, "pcs_db", pcs_dbcollectioname);
   }
   double pcs_createdone = 0;
   int pcs_rv;
   char *pcs_imsistr;
   if (sess)
   {
      pcs_imsistr = sess->amf_ue->supi;
   }
   else
   {
      return NULL;
   }
   pcs_imsistr += 5;
   char *pcs_dbrdata = read_data_from_db(pcs_dbcollection, pcs_imsistr);
   JSON_Value *pcs_dbrdatajsonval = json_parse_string(pcs_dbrdata);
   if (json_value_get_type(pcs_dbrdatajsonval) == JSONObject)
   {
      JSON_Object *pcs_dbrdatajsonobj = json_object(pcs_dbrdatajsonval);
      pcs_createdone = json_object_get_number(pcs_dbrdatajsonobj, "pcs-create-done");
   }
   if (strcmp(pcs_dbcollectioname, "amf") == 0)
   {
      if ((int)pcs_createdone)
      {
         struct pcs_amf_n1n2 pcs_n1n2data = pcs_get_amf_n1n2_data(sess, n1buf, n2buf);
         if (pcs_updateapienabledn1n2)
         {
            bson_error_t error;
            bson_t *bson_doc_nas_qos_rule = bson_new_from_json((const uint8_t *)pcs_n1n2data.pcs_nasqosrulestr, -1, &error);
            bson_t *bson_doc_nas_qos_flow = bson_new_from_json((const uint8_t *)pcs_n1n2data.pcs_nasqosflowstr, -1, &error);
            bson_t *bson_doc_nas_epco = bson_new_from_json((const uint8_t *)pcs_n1n2data.pcs_nasepcostr, -1, &error);
            bson_t *bson_doc = BCON_NEW("$set", "{", "pcs-n1n2-done", BCON_INT32(1), "pdu-session-id", BCON_INT32(pdu_session_id), "pdu-address", BCON_UTF8(pcs_n1n2data.pcs_pduaddress), "dnn", BCON_UTF8(pcs_n1n2data.pcs_dnn), "sesion-ambr", "{", "uplink", BCON_INT32(pcs_n1n2data.pcs_sambrulv), "ul-unit", BCON_INT32(pcs_n1n2data.pcs_sambrulu), "downlink", BCON_INT32(pcs_n1n2data.pcs_sambrdlv), "dl-unit", BCON_INT32(pcs_n1n2data.pcs_sambrdlu), "}", "pdu-session-type", BCON_INT32(pcs_n1n2data.pcs_pdusesstype), "PDUSessionAggregateMaximumBitRate", "{", "pDUSessionAggregateMaximumBitRateUL", BCON_INT64(pcs_n1n2data.pcs_pdusessionaggregatemaximumbitrateul), "pDUSessionAggregateMaximumBitRateDL", BCON_INT64(pcs_n1n2data.pcs_pdusessionaggregatemaximumbitratedl), "}", "QosFlowSetupRequestList", "[", "{", "qosFlowIdentifier", BCON_INT64(pcs_n1n2data.pcs_qosflowidentifier), "fiveQI", BCON_INT64(pcs_n1n2data.pcs_fiveqi), "priorityLevelARP", BCON_INT64(pcs_n1n2data.pcs_plarp), "pre_emptionCapability", BCON_INT64(pcs_n1n2data.pcs_preemptioncapability), "pre_emptionVulnerability", BCON_INT64(pcs_n1n2data.pcs_preemptionvulnerability), "}", "]", "UL_NGU_UP_TNLInformation", "{", "transportLayerAddress", BCON_UTF8(pcs_n1n2data.pcs_upfn3ip), "gTP_TEID", BCON_INT32(pcs_n1n2data.pcs_upfn3teid), "}", "nas-authorized-qos-rules", BCON_ARRAY(bson_doc_nas_qos_rule), "nas-authorized-qos-flow_descriptions", BCON_ARRAY(bson_doc_nas_qos_flow), "nas-extended-protocol-configuration-option", BCON_DOCUMENT(bson_doc_nas_epco), "}");

            pcs_rv = insert_data_to_db(pcs_dbcollection, "update", pcs_imsistr, bson_doc);
            bson_destroy(bson_doc_nas_qos_rule);
            bson_destroy(bson_doc_nas_qos_flow);
            bson_destroy(bson_doc_nas_epco);
         }
         else
         {
            char *pcs_updatedoc;
            asprintf(&pcs_updatedoc, ", \"pcs-n1n2-done\": 1, \"pdu-session-id\": %d, \"pdu-address\": \"%s\", \"dnn\": \"%s\", \"sesion-ambr\": {\"uplink\": %d, \"ul-unit\": %d, \"downlink\": %d, \"dl-unit\": %d}, \"pdu-session-type\": %d, \"PDUSessionAggregateMaximumBitRate\": {\"pDUSessionAggregateMaximumBitRateUL\": %ld, \"pDUSessionAggregateMaximumBitRateDL\": %ld}, \"QosFlowSetupRequestList\": [{ \"qosFlowIdentifier\": %ld, \"fiveQI\": %ld, \"priorityLevelARP\": %ld, \"pre_emptionCapability\": %ld, \"pre_emptionVulnerability\": %ld}], \"UL_NGU_UP_TNLInformation\": {\"transportLayerAddress\": \"%s\", \"gTP_TEID\": %d}, \"nas-authorized-qos-rules\": %s, \"nas-authorized-qos-flow_descriptions\": %s, \"nas-extended-protocol-configuration-option\": %s}", pdu_session_id, pcs_n1n2data.pcs_pduaddress, pcs_n1n2data.pcs_dnn, pcs_n1n2data.pcs_sambrulv, pcs_n1n2data.pcs_sambrulu, pcs_n1n2data.pcs_sambrdlv, pcs_n1n2data.pcs_sambrdlu, pcs_n1n2data.pcs_pdusesstype, pcs_n1n2data.pcs_pdusessionaggregatemaximumbitrateul, pcs_n1n2data.pcs_pdusessionaggregatemaximumbitratedl, pcs_n1n2data.pcs_qosflowidentifier, pcs_n1n2data.pcs_fiveqi, pcs_n1n2data.pcs_plarp, pcs_n1n2data.pcs_preemptioncapability, pcs_n1n2data.pcs_preemptionvulnerability, pcs_n1n2data.pcs_upfn3ip, pcs_n1n2data.pcs_upfn3teid, pcs_n1n2data.pcs_nasqosrulestr, pcs_n1n2data.pcs_nasqosflowstr, pcs_n1n2data.pcs_nasepcostr);
            pcs_rv = delete_create_data_to_db(pcs_dbcollection, pcs_imsistr, pcs_dbrdata, pcs_updatedoc);
         }

         if (pcs_rv != OGS_OK)
         {
            ogs_error("PCS Error while updateing n1-n2 data to MongoDB for supi [%s]", sess->amf_ue->supi);
         }
         else
         {
            ogs_info("PCS Successfully updated n1-n2 data to MongoDB for supi [%s]", sess->amf_ue->supi);
         }

         free(pcs_n1n2data.pcs_nasqosrulestr);
         free(pcs_n1n2data.pcs_nasqosflowstr);
         free(pcs_n1n2data.pcs_nasepcostr);

         /* ogs_free(pcs_n1n2data.pcs_upfn3ip);
            ogs_free(pcs_n1n2data.pcs_pduaddress);
            ogs_free(pcs_n1n2data.pcs_ie);
            ogs_free(pcs_n1n2data.pcs_gtptunnel);
            ogs_free(pcs_n1n2data.pcs_qosflowsetuprequestitem);*/
      }
      else
      {
         ogs_error("PCS n1-n2 request got triggered without processing Create-SM-Context request");
      }
   }
   else
   {
      ogs_info("PCS Successfully completed n1-n2 transaction with shared UDSF for supi [%s]", sess->amf_ue->supi);
   }
   mongoc_collection_destroy(pcs_dbcollection);
   mongoc_client_pool_push(PCS_MONGO_POOL, pcs_mongoclient);
   json_value_free(pcs_dbrdatajsonval);
   bson_free(pcs_dbrdata);
   sess->pcs.pcs_udsfn1n2done = 1;
   return NULL;
   //pthread_exit(NULL);
}

void *pcs_amf_update_req_udsf(void *pcs_amfupdaterequdsf)
{
   struct pcs_amf_update_req_udsf_s *pcs_amfupdaterequdsfstruct = pcs_amfupdaterequdsf;
   ogs_pkbuf_t *n2smbuf = pcs_amfupdaterequdsfstruct->n2smbuf;

   ran_ue_t *ran_ue = ran_ue_find_by_amf_ue_ngap_id(pcs_amfupdaterequdsfstruct->pcs_amfuengapid);
   amf_ue_t *amf_ue;
   if (ran_ue)
   {
      amf_ue = ran_ue->amf_ue;
   }
   else
   {
      return NULL;
   }
    
   amf_sess_t *sess = amf_sess_find_by_psi(amf_ue, pcs_amfupdaterequdsfstruct->pcs_pdusessionid);
   char *pcs_dbcollectioname = getenv("PCS_DB_COLLECTION_NAME");
   uint8_t pcs_isproceduralstateless = pcs_set_int_from_env("PCS_IS_PROCEDURAL_STATELESS");

   mongoc_collection_t *pcs_dbcollection;
   double pcs_n1n2done = 0;
   if (pcs_isproceduralstateless && sess->pcs.pcs_createdone && strcmp(pcs_dbcollectioname, "amf") == 0)
   {
      pcs_n1n2done = sess->pcs.pcs_n1n2done;
   }
   else if (!pcs_isproceduralstateless)
   {
      mongoc_client_t *pcs_mongoclient = mongoc_client_pool_try_pop(PCS_MONGO_POOL);
      if (pcs_mongoclient == NULL)
      {
         pcs_dbcollection = pcs_amfupdaterequdsfstruct->pcs_dbcollection;
      }
      else
      {
         pcs_dbcollection = mongoc_client_get_collection(pcs_mongoclient, "pcs_db", pcs_dbcollectioname);
      }
      char *pcs_imsistr;
      if (sess)
      {
         pcs_imsistr = sess->amf_ue->supi;
      }
      else
      {
         return NULL;
      }
      pcs_imsistr += 5;
      if (!pcs_isproceduralstateless)
      {
         char *pcs_dbrdata = read_data_from_db(pcs_dbcollection, pcs_imsistr);
         sess->pcs.pcs_dbrdata = pcs_dbrdata;
         JSON_Value *pcs_dbrdatajsonval = json_parse_string(pcs_dbrdata);
         if (json_value_get_type(pcs_dbrdatajsonval) == JSONObject)
         {
            JSON_Object *pcs_dbrdatajsonobj = json_object(pcs_dbrdatajsonval);
            pcs_n1n2done = json_object_get_number(pcs_dbrdatajsonobj, "pcs-n1n2-done");
         }
         json_value_free(pcs_dbrdatajsonval);
      }
      mongoc_collection_destroy(pcs_dbcollection);
      mongoc_client_pool_push(PCS_MONGO_POOL, pcs_mongoclient);
   }

   if (strcmp(pcs_dbcollectioname, "amf") == 0)
   {
      if ((int)pcs_n1n2done)
      {
         struct pcs_amf_update pcs_updatedata = pcs_get_amf_update_data(n2smbuf);
         sess->pcs.pcs_updatedata = pcs_updatedata;
      }
      else
      {
         ogs_error("PCS Update-SM-Context got triggered without processing n1-n2 request");
      }
   }
   else
   {
      ogs_debug("PCS Update-SM-Transaction Stated with shared UDSF");
   }
   sess->pcs.pcs_udsfupdatereqdone = 1;
   return NULL;
   //pthread_exit(NULL);
}

void *pcs_amf_update_rsp_udsf(void *pcs_amfupdaterspudsf)
{
   struct pcs_amf_update_rsp_udsf_s *pcs_amfupdaterspudsfstruct = pcs_amfupdaterspudsf;
   
   ran_ue_t *ran_ue = ran_ue_find_by_amf_ue_ngap_id(pcs_amfupdaterspudsfstruct->pcs_amfuengapid);
   amf_ue_t *amf_ue;
   if (ran_ue)
   {
      amf_ue = ran_ue->amf_ue;
   }
   else
   {
      return NULL;
   }

   amf_sess_t *sess = amf_sess_find_by_psi(amf_ue, pcs_amfupdaterspudsfstruct->pcs_pdusessionid);
   char *pcs_dbcollectioname = getenv("PCS_DB_COLLECTION_NAME");
   uint8_t pcs_isproceduralstateless = pcs_set_int_from_env("PCS_IS_PROCEDURAL_STATELESS");
   uint8_t pcs_updateapienabledmodify = pcs_set_int_from_env("PCS_UPDATE_API_ENABLED_MODIFY");

   mongoc_collection_t *pcs_dbcollection;
   mongoc_client_t *pcs_mongoclient = mongoc_client_pool_try_pop(PCS_MONGO_POOL);
   if (pcs_mongoclient == NULL)
   {
      pcs_dbcollection = pcs_amfupdaterspudsfstruct->pcs_dbcollection;
   }
   else
   {
      pcs_dbcollection = mongoc_client_get_collection(pcs_mongoclient, "pcs_db", pcs_dbcollectioname);
   }
   char *pcs_imsistr;
   if (sess)
   {
      pcs_imsistr = sess->amf_ue->supi;
   }
   else
   {
      return NULL;
   }
   pcs_imsistr += 5;
   int pcs_rv;
   struct pcs_amf_update pcs_updatedata = sess->pcs.pcs_updatedata;
   if (pcs_isproceduralstateless)
   {
      struct pcs_amf_create pcs_createdata = sess->pcs.pcs_createdata;
      struct pcs_amf_n1n2 pcs_n1n2data = sess->pcs.pcs_n1n2data;
      char *pcs_docjson;
      asprintf(&pcs_docjson, "{\"_id\": \"%s\", \"pcs-create-done\": 1, \"supi\": \"%s\", \"sm-context-ref\": \"%s\", \"pdu-session-id\": %d, \"ue-access-type\": %d, \"allowed_pdu_session_status\": %d, \"pei\": \"%s\", \"dnn\": \"%s\", \"s-nssai\": {\"sst\": %d, \"sd\": \"%s\"}, \"plmnid\": \"%s\", \"amf-id\": \"%s\", \"tac\": \"%s\", \"ue-location-timestamp\": %ld, \"ran-ue-ngap-id\": %d, \"amf-ue-ngap-id\": %d, \"gnb-id\": %d, \"rat_type\": \"%s\", \"pcs-n1n2-done\": 1, \"pdu-address\": \"%s\", \"dnn\": \"%s\", \"sesion-ambr\": {\"uplink\": %d, \"ul-unit\": %d, \"downlink\": %d, \"dl-unit\": %d}, \"pdu-session-type\": %d, \"PDUSessionAggregateMaximumBitRate\": {\"pDUSessionAggregateMaximumBitRateUL\": %ld, \"pDUSessionAggregateMaximumBitRateDL\": %ld}, \"QosFlowSetupRequestList\": [{ \"qosFlowIdentifier\": %ld, \"fiveQI\": %ld, \"priorityLevelARP\": %ld, \"pre_emptionCapability\": %ld, \"pre_emptionVulnerability\": %ld}], \"UL_NGU_UP_TNLInformation\": {\"transportLayerAddress\": \"%s\", \"gTP_TEID\": %d}, \"nas-authorized-qos-rules\": %s, \"nas-authorized-qos-flow_descriptions\": %s, \"nas-extended-protocol-configuration-option\": %s, \"pcs-update-done\": 1, \"dLQosFlowPerTNLInformation\": {\"transportLayerAddress\": \"%s\", \"gTP_TEID\": %d, \"associatedQosFlowId\": %ld } }", pcs_imsistr, pcs_createdata.pcs_supi, pcs_createdata.pcs_smcontextref, pcs_createdata.pcs_pdusessionid, pcs_createdata.pcs_amfueaccesstype, pcs_createdata.pcs_amfueallowedpdusessionstatus, pcs_createdata.pcs_amfuepei, pcs_createdata.pcs_amfsessdnn, pcs_createdata.pcs_snssaisst, pcs_createdata.pcs_snssaisd, pcs_createdata.pcs_amfueplmnid, pcs_createdata.pcs_amfueamfid, pcs_createdata.pcs_amfuetac, (long)pcs_createdata.pcs_amfuelocts, pcs_createdata.pcs_ranuengapid, pcs_createdata.pcs_amfuengapid, pcs_createdata.pcs_ranuegnbid, pcs_createdata.pcs_ranuerattype, pcs_n1n2data.pcs_pduaddress, pcs_n1n2data.pcs_dnn, pcs_n1n2data.pcs_sambrulv, pcs_n1n2data.pcs_sambrulu, pcs_n1n2data.pcs_sambrdlv, pcs_n1n2data.pcs_sambrdlu, pcs_n1n2data.pcs_pdusesstype, pcs_n1n2data.pcs_pdusessionaggregatemaximumbitrateul, pcs_n1n2data.pcs_pdusessionaggregatemaximumbitratedl, pcs_n1n2data.pcs_qosflowidentifier, pcs_n1n2data.pcs_fiveqi, pcs_n1n2data.pcs_plarp, pcs_n1n2data.pcs_preemptioncapability, pcs_n1n2data.pcs_preemptionvulnerability, pcs_n1n2data.pcs_upfn3ip, pcs_n1n2data.pcs_upfn3teid, pcs_n1n2data.pcs_nasqosrulestr, pcs_n1n2data.pcs_nasqosflowstr, pcs_n1n2data.pcs_nasepcostr, pcs_updatedata.pcs_upfn3ip, pcs_updatedata.pcs_upfn3teid, pcs_updatedata.pcs_qosflowid);
      bson_error_t error;
      bson_t *bson_doc = bson_new_from_json((const uint8_t *)pcs_docjson, -1, &error);
      pcs_rv = insert_data_to_db(pcs_dbcollection, "create", pcs_imsistr, bson_doc);
      sess->pcs.pcs_updatedone = 1;
      ogs_free(pcs_createdata.pcs_snssaisd);
      ogs_free(pcs_createdata.pcs_amfueamfid);
      ogs_free(pcs_createdata.pcs_amfuetac);
      free(pcs_createdata.pcs_amfueplmnid);
      free(pcs_n1n2data.pcs_nasqosrulestr);
      free(pcs_n1n2data.pcs_nasqosflowstr);
      free(pcs_n1n2data.pcs_nasepcostr);
      /* ogs_free(pcs_n1n2data.pcs_upfn3ip);
      ogs_free(pcs_n1n2data.pcs_pduaddress);
      ogs_free(pcs_n1n2data.pcs_ie);
      ogs_free(pcs_n1n2data.pcs_gtptunnel);
      ogs_free(pcs_n1n2data.pcs_qosflowsetuprequestitem);*/
      free(pcs_docjson);
   }
   else
   {
      if (pcs_updateapienabledmodify)
      {
         bson_t *bson_doc = BCON_NEW("$set", "{", "pcs-update-done", BCON_INT32(1), "dLQosFlowPerTNLInformation", "{", "transportLayerAddress", BCON_UTF8(pcs_updatedata.pcs_upfn3ip), "gTP_TEID", BCON_INT32(pcs_updatedata.pcs_upfn3teid), "associatedQosFlowId", BCON_INT64(pcs_updatedata.pcs_qosflowid), "}", "}");

         pcs_rv = insert_data_to_db(pcs_dbcollection, "update", pcs_imsistr, bson_doc);
      }
      else
      {
         char *pcs_dbrdata = sess->pcs.pcs_dbrdata;
         char *pcs_updatedoc;
         asprintf(&pcs_updatedoc, ", \"pcs-update-done\": 1, \"dLQosFlowPerTNLInformation\": {\"transportLayerAddress\": \"%s\", \"gTP_TEID\": %d, \"associatedQosFlowId\": %ld } }", pcs_updatedata.pcs_upfn3ip, pcs_updatedata.pcs_upfn3teid, pcs_updatedata.pcs_qosflowid);

         pcs_rv = delete_create_data_to_db(pcs_dbcollection, pcs_imsistr, pcs_dbrdata, pcs_updatedoc);
         bson_free(pcs_dbrdata);
      }
   }
   mongoc_collection_destroy(pcs_dbcollection);
   mongoc_client_pool_push(PCS_MONGO_POOL, pcs_mongoclient);

   if (pcs_rv != OGS_OK)
   {
      ogs_error("PCS Error while uploading Update-SM-Context data to MongoDB for supi [%s]", sess->amf_ue->supi);
   }
   else
   {
      ogs_info("PCS Successfully uploaded Update-SM-Context data to MongoDB for supi [%s]", sess->amf_ue->supi);
   }
   sess->pcs.pcs_udsfupdaterspdone = 1;
   return NULL;
   //pthread_exit(NULL);
}