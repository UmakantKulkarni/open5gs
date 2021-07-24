#ifndef PCS_HELPER_H
#define PCS_HELPER_H

#ifdef __cplusplus
extern "C"
{
#endif

#include "bson.h"
    char *pcs_combine_strings(char *pcs_input_a, char *pcs_input_b);
    int insert_data_to_db(mongoc_collection_t *collection, const char *pcs_dbop, char *pcs_docid, bson_t *bson_doc);
    char *read_data_from_db(mongoc_collection_t *collection, char *pcs_docid);
    void decode_buffer_to_hex(char *pcs_hexstr, const unsigned char *pcs_data, size_t pcs_len);
    void pcs_get_substring(char *pcs_str, char *pcs_sub_str, int pcs_start_index, int pcs_end_index);
    int pcs_hex_to_int(char *pcs_hex_str, int pcs_start_index, int pcs_end_index);
    int pcs_binary_to_decimal(char *pcs_bin_str);
    void pcs_hex_to_binary_str(char *pcs_hex_str, char *pcs_bin_str, int pcs_start_index, int pcs_end_index);
    bson_t *decode_nas_qos_rule_hex_to_bson(char *pcs_hexipdata);
    bson_t *decode_nas_qos_flow_hex_to_bson(char *pcs_hexipdata);
    bson_t *decode_nas_epco_hex_to_bson(char *pcs_hexipdata);

#ifdef __cplusplus
}
#endif

#endif /* PCS_HELPER_H */