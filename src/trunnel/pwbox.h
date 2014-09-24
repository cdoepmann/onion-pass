
/* pwbox.h -- generated by trunnel. */
#ifndef TRUNNEL_PWBOX_H
#define TRUNNEL_PWBOX_H

#include <stdint.h>
#include "trunnel.h"

#define PWBOX0_CONST0 1414484546
#define PWBOX0_CONST1 1331179568
#if !defined(TRUNNEL_OPAQUE) && !defined(TRUNNEL_OPAQUE_PWBOX_ENCODED)
struct pwbox_encoded_st {
  uint32_t fixedbytes0;
  uint32_t fixedbytes1;
  uint8_t header_len;
  TRUNNEL_DYNARRAY_HEAD(, uint8_t) skey_header;
  uint8_t iv[16];
  TRUNNEL_DYNARRAY_HEAD(, uint8_t) data;
  uint8_t hmac[32];
  uint8_t trunnel_error_code_;
};
#endif
typedef struct pwbox_encoded_st pwbox_encoded_t;
/** Return a newly allocated pwbox_encoded with all elements set to
 * zero.
 */
pwbox_encoded_t *pwbox_encoded_new(void);
/** Release all storage held by the pwbox_encoded in 'victim'. (Do
 * nothing if 'victim' is NULL.)
 */
void pwbox_encoded_free(pwbox_encoded_t *victim);
/** Try to parse a pwbox_encoded from the buffer in 'input', using up
 * to 'len_in' bytes from the input buffer. On success, return the
 * number of bytes consumed and set *output to the newly allocated
 * pwbox_encoded_t. On failure, return -2 if the input appears
 * truncated, and -1 if the input is otherwise invalid.
 */
ssize_t pwbox_encoded_parse(pwbox_encoded_t **output, const uint8_t *input, const size_t len_in);
/** Return the number of bytes we expect to need to encode the
 * pwbox_encoded in 'obj'. On failure, return a negative value. Note
 * that this value may be an overestimate, and can even be an
 * underestimate for certain unencodeable objects.
 */
ssize_t pwbox_encoded_encoded_len(const pwbox_encoded_t *obj);
/** Try to encode the pwbox_encoded from 'input' into the buffer at
 * 'output', using up to 'avail' bytes of the output buffer. On
 * success, return the number of bytes used. On failure, return -2 if
 * the buffer was not long enough, and -1 if the input was invalid.
 */
ssize_t pwbox_encoded_encode(uint8_t *output, const size_t avail, const pwbox_encoded_t *input);
/** Check whether the internal state of the pwbox_encoded in 'obj' is
 * consistent. Return NULL if it is, and a short message if it is not.
 */
const char *pwbox_encoded_check(const pwbox_encoded_t *obj);
/** Clear any errors that were set on the object 'obj' by its setter
 * functions. Return true iff errors were cleared.
 */
int pwbox_encoded_clear_errors(pwbox_encoded_t *obj);
/** Return the value of the fixedbytes0 field of the pwbox_encoded_t
 * in 'inp'
 */
uint32_t pwbox_encoded_get_fixedbytes0(pwbox_encoded_t *inp);
/** Set the value of the fixedbytes0 field of the pwbox_encoded_t in
 * 'inp' to 'val'. Return 0 on success; return -1 and set the error
 * code on 'inp' on failure.
 */
int pwbox_encoded_set_fixedbytes0(pwbox_encoded_t *inp, uint32_t val);
/** Return the value of the fixedbytes1 field of the pwbox_encoded_t
 * in 'inp'
 */
uint32_t pwbox_encoded_get_fixedbytes1(pwbox_encoded_t *inp);
/** Set the value of the fixedbytes1 field of the pwbox_encoded_t in
 * 'inp' to 'val'. Return 0 on success; return -1 and set the error
 * code on 'inp' on failure.
 */
int pwbox_encoded_set_fixedbytes1(pwbox_encoded_t *inp, uint32_t val);
/** Return the value of the header_len field of the pwbox_encoded_t in
 * 'inp'
 */
uint8_t pwbox_encoded_get_header_len(pwbox_encoded_t *inp);
/** Set the value of the header_len field of the pwbox_encoded_t in
 * 'inp' to 'val'. Return 0 on success; return -1 and set the error
 * code on 'inp' on failure.
 */
int pwbox_encoded_set_header_len(pwbox_encoded_t *inp, uint8_t val);
/** Return the length of the dynamic array holding the skey_header
 * field of the pwbox_encoded_t in 'inp'.
 */
size_t pwbox_encoded_getlen_skey_header(const pwbox_encoded_t *inp);
/** Return the element at position 'idx' of the dynamic array field
 * skey_header of the pwbox_encoded_t in 'inp'.
 */
uint8_t pwbox_encoded_get_skey_header(pwbox_encoded_t *inp, size_t idx);
/** Change the element at position 'idx' of the dynamic array field
 * skey_header of the pwbox_encoded_t in 'inp', so that it will hold
 * the value 'elt'.
 */
int pwbox_encoded_set_skey_header(pwbox_encoded_t *inp, size_t idx, uint8_t elt);
/** Append a new element 'elt' to the dynamic array field skey_header
 * of the pwbox_encoded_t in 'inp'.
 */
int pwbox_encoded_add_skey_header(pwbox_encoded_t *inp, uint8_t elt);
/** Return a pointer to the variable-length array field skey_header of
 * 'inp'.
 */
uint8_t * pwbox_encoded_getarray_skey_header(pwbox_encoded_t *inp);
/** Change the length of the variable-length array field skey_header
 * of 'inp' to 'newlen'.Fill extra elements with 0. Return 0 on
 * success; return -1 and set the error code on 'inp' on failure.
 */
int pwbox_encoded_setlen_skey_header(pwbox_encoded_t *inp, size_t newlen);
/** Return the (constant) length of the array holding the iv field of
 * the pwbox_encoded_t in 'inp'.
 */
size_t pwbox_encoded_getlen_iv(const pwbox_encoded_t *inp);
/** Return the element at position 'idx' of the fixed array field iv
 * of the pwbox_encoded_t in 'inp'.
 */
uint8_t pwbox_encoded_get_iv(const pwbox_encoded_t *inp, size_t idx);
/** Change the element at position 'idx' of the fixed array field iv
 * of the pwbox_encoded_t in 'inp', so that it will hold the value
 * 'elt'.
 */
int pwbox_encoded_set_iv(pwbox_encoded_t *inp, size_t idx, uint8_t elt);
/** Return a pointer to the 16-element array field iv of 'inp'.
 */
uint8_t * pwbox_encoded_getarray_iv(pwbox_encoded_t *inp);
/** Return the length of the dynamic array holding the data field of
 * the pwbox_encoded_t in 'inp'.
 */
size_t pwbox_encoded_getlen_data(const pwbox_encoded_t *inp);
/** Return the element at position 'idx' of the dynamic array field
 * data of the pwbox_encoded_t in 'inp'.
 */
uint8_t pwbox_encoded_get_data(pwbox_encoded_t *inp, size_t idx);
/** Change the element at position 'idx' of the dynamic array field
 * data of the pwbox_encoded_t in 'inp', so that it will hold the
 * value 'elt'.
 */
int pwbox_encoded_set_data(pwbox_encoded_t *inp, size_t idx, uint8_t elt);
/** Append a new element 'elt' to the dynamic array field data of the
 * pwbox_encoded_t in 'inp'.
 */
int pwbox_encoded_add_data(pwbox_encoded_t *inp, uint8_t elt);
/** Return a pointer to the variable-length array field data of 'inp'.
 */
uint8_t * pwbox_encoded_getarray_data(pwbox_encoded_t *inp);
/** Change the length of the variable-length array field data of 'inp'
 * to 'newlen'.Fill extra elements with 0. Return 0 on success; return
 * -1 and set the error code on 'inp' on failure.
 */
int pwbox_encoded_setlen_data(pwbox_encoded_t *inp, size_t newlen);
/** Return the (constant) length of the array holding the hmac field
 * of the pwbox_encoded_t in 'inp'.
 */
size_t pwbox_encoded_getlen_hmac(const pwbox_encoded_t *inp);
/** Return the element at position 'idx' of the fixed array field hmac
 * of the pwbox_encoded_t in 'inp'.
 */
uint8_t pwbox_encoded_get_hmac(const pwbox_encoded_t *inp, size_t idx);
/** Change the element at position 'idx' of the fixed array field hmac
 * of the pwbox_encoded_t in 'inp', so that it will hold the value
 * 'elt'.
 */
int pwbox_encoded_set_hmac(pwbox_encoded_t *inp, size_t idx, uint8_t elt);
/** Return a pointer to the 32-element array field hmac of 'inp'.
 */
uint8_t * pwbox_encoded_getarray_hmac(pwbox_encoded_t *inp);


#endif
