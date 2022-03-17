#ifndef PCS_HELPER_H
#define PCS_HELPER_H

#ifdef __cplusplus
extern "C"
{
#endif

    extern uint8_t PCS_DBCOMMENABLED;
    extern uint8_t PCS_UPSERTAPIENABLEDCREATE;
    extern uint8_t PCS_UPDATEAPIENABLEDMODIFY;
    extern uint8_t PCS_BLOCKINGAPIENABLEDCREATE;
    extern uint8_t PCS_BLOCKINGAPIENABLEDMODIFYRSP;
    extern uint8_t PCS_ISPROCEDURALSTATELESS;
    extern uint8_t PCS_REPLACEAPIENABLEDMODIFY;
    extern uint8_t PCS_ENABLESINGLEREAD;
    extern char *PCS_DBCOLLECTIONAME;
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

    struct pcs_upf_create_udsf_s
    {
        mongoc_collection_t *pcs_dbcollection;
        uint64_t *pcs_upfn4seid;
        char *pcs_dbrdata;
        upf_sess_t *sess;
    };

    struct pcs_upf_update_udsf_s
    {
        mongoc_collection_t *pcs_dbcollection;
        uint64_t *pcs_upfn4seid;
        char *pcs_dbrdata;
    };

    struct pcs_mongo_info_s pcs_get_mongo_info(pcs_fsm_struct_t *pcs_fsmdata);
    int pcs_set_int_from_env(const char *pcs_env_var);
    char *pcs_combine_strings(char *pcs_input_a, char *pcs_input_b);
    struct pcs_db_write_op_s insert_data_to_db(mongoc_collection_t *collection, const char *pcs_dbop, uint64_t pcs_docid, bson_t *bson_doc);
    struct pcs_db_write_op_s delete_create_data_to_db(mongoc_collection_t *collection, uint64_t pcs_docid, char *pcs_dbrdata, char *pcs_dbnewdata);
    struct pcs_db_write_op_s replace_data_to_db(mongoc_collection_t *collection, uint64_t pcs_docid, char *pcs_dbrdata, char *pcs_dbnewdata);
    struct pcs_db_read_op_s read_data_from_db(mongoc_collection_t *collection, const char *pcs_dockey, uint64_t pcs_docval, long pcs_docseid);
    void decode_buffer_to_hex(char *pcs_hexstr, const unsigned char *pcs_data, size_t pcs_len);
    void pcs_get_substring(char *pcs_str, char *pcs_sub_str, int pcs_start_index, int pcs_end_index);
    int pcs_hex_to_int(char *pcs_hex_str, int pcs_start_index, int pcs_end_index);
    int pcs_binary_to_decimal(char *pcs_bin_str);
    void pcs_hex_to_binary_str(char *pcs_hex_str, char *pcs_bin_str, int pcs_start_index, int pcs_end_index);
    char *decode_nas_qos_rule_hex_to_str(char *pcs_hexipdata);
    char *decode_nas_qos_flow_hex_to_str(char *pcs_hexipdata);
    char *decode_nas_epco_hex_to_str(char *pcs_hexipdata);
    struct pcs_upf_n4_create pcs_get_upf_n4_create_data(upf_sess_t *sess);
    void pcs_upf_create_udsf(void *pcs_upfcreateudsf);
    void pcs_upf_update_udsf(void *pcs_upfupdateudsf);

#ifdef __cplusplus
}
#endif

#endif /* PCS_HELPER_H */