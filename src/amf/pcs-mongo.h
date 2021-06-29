#ifndef PCS_MONGO_H
#define PCS_MONGO_H

#ifdef __cplusplus
extern "C" {
#endif

int insert_data_to_db(const char *db_coll, const char *db_op, char *doc_id, char *doc_json);

#ifdef __cplusplus
}
#endif

#endif /* PCS_MONGO_H */