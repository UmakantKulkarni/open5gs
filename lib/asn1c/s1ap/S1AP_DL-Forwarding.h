/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "S1AP-IEs"
 * 	found in "../support/s1ap-r16.7.0/36413-g70.asn"
 * 	`asn1c -pdu=all -fcompound-names -findirect-choice -fno-include-deps -no-gen-BER -no-gen-XER -no-gen-OER -no-gen-UPER`
 */

#ifndef	_S1AP_DL_Forwarding_H_
#define	_S1AP_DL_Forwarding_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeEnumerated.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum S1AP_DL_Forwarding {
	S1AP_DL_Forwarding_dL_Forwarding_proposed	= 0
	/*
	 * Enumeration is extensible
	 */
} e_S1AP_DL_Forwarding;

/* S1AP_DL-Forwarding */
typedef long	 S1AP_DL_Forwarding_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_S1AP_DL_Forwarding_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_S1AP_DL_Forwarding;
extern const asn_INTEGER_specifics_t asn_SPC_DL_Forwarding_specs_1;
asn_struct_free_f DL_Forwarding_free;
asn_struct_print_f DL_Forwarding_print;
asn_constr_check_f DL_Forwarding_constraint;
per_type_decoder_f DL_Forwarding_decode_aper;
per_type_encoder_f DL_Forwarding_encode_aper;

#ifdef __cplusplus
}
#endif

#endif	/* _S1AP_DL_Forwarding_H_ */
#include <asn_internal.h>
