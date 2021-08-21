#ifndef PCS_HELPER_H
#define PCS_HELPER_H

#ifdef __cplusplus
extern "C"
{
#endif

#include "context.h"
#include "bson.h"

    struct pcs_amf_create_udsf_s
    {
        uint64_t *pcs_amfuengapid;
        long *pcs_pdusessionid;
        mongoc_collection_t *pcs_dbcollection;
        char *pcs_dbrdata;
    };

    struct pcs_amf_n1n2_udsf_s
    {
        mongoc_collection_t *pcs_dbcollection;
        uint64_t *pcs_amfuengapid;
        long *pcs_pdusessionid;
        ogs_pkbuf_t *n1buf;
        ogs_pkbuf_t *n2buf;
        char *pcs_dbrdata;
    };

    struct pcs_amf_update_req_udsf_s
    {
        uint64_t *pcs_amfuengapid;
        long *pcs_pdusessionid;
        mongoc_collection_t *pcs_dbcollection;
        ogs_pkbuf_t *n2smbuf;
        char *pcs_dbrdata;
    };

    struct pcs_amf_update_rsp_udsf_s
    {
        uint64_t *pcs_amfuengapid;
        long *pcs_pdusessionid;
        mongoc_collection_t *pcs_dbcollection;
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
    void *pcs_amf_create_udsf(void *pcs_amfcreateudsf);
    void *pcs_amf_n1n2_udsf(void *pcs_amfn1n2udsf);
    void *pcs_amf_update_req_udsf(void *pcs_amfupdaterequdsf);
    void *pcs_amf_update_rsp_udsf(void *pcs_amfupdaterspudsf);

#ifdef __cplusplus
}
#endif

#endif /* PCS_HELPER_H */