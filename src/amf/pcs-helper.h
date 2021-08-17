#ifndef PCS_HELPER_H
#define PCS_HELPER_H

#ifdef __cplusplus
extern "C"
{
#endif

#include "context.h"
#include "bson.h"


struct pcs_amf_create_udsf 
{
    pcs_fsm_struct_t pcs_fsmdata;
    amf_sess_t *sess;
};

    int pcs_set_int_from_env(const char *pcs_env_var);
    char *pcs_combine_strings(char *pcs_input_a, char *pcs_input_b);
    int insert_data_to_db(mongoc_collection_t *collection, const char *pcs_dbop, char *pcs_docid, bson_t *bson_doc);
    int delete_create_data_to_db(mongoc_collection_t *collection, char *pcs_docid, char *pcs_dbrdata, char *pcs_dbnewdata);
    char *read_data_from_db(mongoc_collection_t *collection, char *pcs_docid);
    void decode_buffer_to_hex(char *pcs_hexstr, const unsigned char *pcs_data, size_t pcs_len);
    void pcs_get_substring(char *pcs_str, char *pcs_sub_str, int pcs_start_index, int pcs_end_index);
    int pcs_hex_to_int(char *pcs_hex_str, int pcs_start_index, int pcs_end_index);
    int pcs_binary_to_decimal(char *pcs_bin_str);
    void pcs_hex_to_binary_str(char *pcs_hex_str, char *pcs_bin_str, int pcs_start_index, int pcs_end_index);
    char *decode_nas_qos_rule_hex_to_str(char *pcs_hexipdata);
    char *decode_nas_qos_flow_hex_to_str(char *pcs_hexipdata);
    char *decode_nas_epco_hex_to_str(char *pcs_hexipdata);
    struct pcs_amf_create pcs_get_amf_create_data(amf_sess_t *sess);
    struct pcs_amf_n1n2 pcs_get_amf_n1n2_data(amf_sess_t *sess, ogs_pkbuf_t *n1buf, ogs_pkbuf_t *n2buf);
    struct pcs_amf_update pcs_get_amf_update_data(ogs_pkbuf_t *n2buf);
    void pcs_amf_create_udsf(pcs_amf_create_udsf pcs_amfcreateudsf);

#ifdef __cplusplus
}
#endif

#endif /* PCS_HELPER_H */