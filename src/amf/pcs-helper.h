#ifndef PCS_HELPER_H
#define PCS_HELPER_H

#ifdef __cplusplus
extern "C"
{
#endif

#include "bson.h"
    int insert_data_to_db(const char *pcs_dbcoll, const char *pcs_dbop, char *pcs_docid, bson_t *bson_doc);
    void decode_buffer_to_hex(char *pcs_hexstr, const unsigned char *pcs_data, size_t pcs_len);

#ifdef __cplusplus
}
#endif

#endif /* PCS_HELPER_H */