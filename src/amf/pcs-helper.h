#ifndef PCS_HELPER_H
#define PCS_HELPER_H

#ifdef __cplusplus
extern "C"
{
#endif

    extern mongoc_client_pool_t *PCS_MONGO_POOL;

    extern ThreadPool *PCS_THREADPOOL;

#include "context.h"
#include "bson.h"

    struct pcs_db_read_op_s
    {
        char *pcs_dbrdata;
        double pcs_clk_io;
    };

    struct pcs_db_write_op_s
    {
        int rc;
        double pcs_clk_io;
    };

    struct pcs_mongo_info_s
    {
        mongoc_client_t *pcs_mongoclient;
        mongoc_collection_t *pcs_dbcollection;
    };

    struct pcs_amf_create_udsf_s
    {
        uint64_t *pcs_amfuengapid;
        long *pcs_pdusessionid;
        mongoc_collection_t *pcs_dbcollection;
        char *pcs_dbrdata;
        amf_sess_t *sess;
    };

    struct pcs_amf_n1n2_udsf_s
    {
        mongoc_collection_t *pcs_dbcollection;
        uint64_t *pcs_amfuengapid;
        long *pcs_pdusessionid;
        ogs_pkbuf_t *n1buf;
        ogs_pkbuf_t *n2buf;
        char *pcs_dbrdata;
        amf_sess_t *sess;
    };

    struct pcs_amf_update_req_udsf_s
    {
        uint64_t *pcs_amfuengapid;
        long *pcs_pdusessionid;
        mongoc_collection_t *pcs_dbcollection;
        ogs_pkbuf_t *n2smbuf;
        char *pcs_dbrdata;
        amf_sess_t *sess;
    };

    struct pcs_amf_update_rsp_udsf_s
    {
        uint64_t *pcs_amfuengapid;
        long *pcs_pdusessionid;
        mongoc_collection_t *pcs_dbcollection;
        amf_sess_t *sess;
    };

    int imsi_to_dbid(char *ue_imsi);
    struct pcs_mongo_info_s pcs_get_mongo_info(pcs_fsm_struct_t *pcs_fsmdata);
    int pcs_set_int_from_env(const char *pcs_env_var);
    char *pcs_combine_strings(char *pcs_input_a, char *pcs_input_b);
    struct pcs_db_write_op_s insert_data_to_db(mongoc_collection_t *collection, const char *pcs_dbop, int pcs_docid, bson_t *bson_doc);
    struct pcs_db_write_op_s delete_create_data_to_db(mongoc_collection_t *collection, int pcs_docid, char *pcs_dbrdata, char *pcs_dbnewdata);
    struct pcs_db_write_op_s replace_data_to_db(mongoc_collection_t *collection, int pcs_docid, char *pcs_dbrdata, char *pcs_dbnewdata);
    struct pcs_db_read_op_s read_data_from_db(mongoc_collection_t *collection, int pcs_docid);
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
    void pcs_amf_create_udsf(void *pcs_amfcreateudsf);
    void pcs_amf_n1n2_udsf(void *pcs_amfn1n2udsf);
    void pcs_amf_update_req_udsf(void *pcs_amfupdaterequdsf);
    void pcs_amf_update_rsp_udsf(void *pcs_amfupdaterspudsf);

#ifdef __cplusplus
}
#endif

#endif /* PCS_HELPER_H */