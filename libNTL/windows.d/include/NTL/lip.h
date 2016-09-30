
#ifndef NTL_g_lip__H
#define NTL_g_lip__H

#include <NTL/config.h>
#include <NTL/mach_desc.h>


#ifdef NTL_GMP_LIP

#include <NTL/gmp_aux.h>
#include <NTL/g_lip.h>


#else

#include <NTL/c_lip.h>


#endif


// These are common to both implementations

class _ntl_tmp_vec {
public:
   virtual ~_ntl_tmp_vec() { }
};

class _ntl_crt_struct {
public:
   virtual ~_ntl_crt_struct() { }
   virtual bool special() = 0;
   virtual void insert(long i, NTL_verylong m) = 0;
   virtual _ntl_tmp_vec *extract() = 0;
   virtual _ntl_tmp_vec *fetch() = 0;
   virtual void eval(NTL_verylong *x, const long *b, 
                     _ntl_tmp_vec *tmp_vec) = 0;
};

_ntl_crt_struct * 
_ntl_crt_struct_build(long n, NTL_verylong p, long (*primes)(long));

class _ntl_rem_struct {
public:
   virtual ~_ntl_rem_struct() { }
   virtual void eval(long *x, NTL_verylong a, _ntl_tmp_vec *tmp_vec) = 0;
   virtual _ntl_tmp_vec *fetch() = 0;
};

_ntl_rem_struct *
_ntl_rem_struct_build(long n, NTL_verylong modulus, long (*p)(long));





#endif
