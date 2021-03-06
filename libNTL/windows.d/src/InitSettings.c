
#include <NTL/ZZ.h>

NTL_CLIENT

#define make_string_aux(x) #x
#define make_string(x) make_string_aux(x)


int main()
{

#ifdef NTL_LEGACY_NO_NAMESPACE
   cout << "NTL_LEGACY_NO_NAMESPACE=1\n";
#else
   cout << "NTL_LEGACY_NO_NAMESPACE=0\n";
#endif

#ifdef NTL_LEGACY_INPUT_ERROR
   cout << "NTL_LEGACY_INPUT_ERROR=1\n";
#else
   cout << "NTL_LEGACY_INPUT_ERROR=0\n";
#endif

#ifdef NTL_THREADS
   cout << "NTL_THREADS=1\n";
#else
   cout << "NTL_THREADS=0\n";
#endif

#ifdef NTL_DISABLE_TLS_HACK
   cout << "NTL_DISABLE_TLS_HACK=1\n";
#else
   cout << "NTL_DISABLE_TLS_HACK=0\n";
#endif

#ifdef NTL_ENABLE_TLS_HACK
   cout << "NTL_ENABLE_TLS_HACK=1\n";
#else
   cout << "NTL_ENABLE_TLS_HACK=0\n";
#endif

#ifdef NTL_EXCEPTIONS
   cout << "NTL_EXCEPTIONS=1\n";
#else
   cout << "NTL_EXCEPTIONS=0\n";
#endif

#ifdef NTL_THREAD_BOOST
   cout << "NTL_THREAD_BOOST=1\n";
#else
   cout << "NTL_THREAD_BOOST=0\n";
#endif


#ifdef NTL_LEGACY_SP_MULMOD
   cout << "NTL_LEGACY_SP_MULMOD=1\n";
#else
   cout << "NTL_LEGACY_SP_MULMOD=0\n";
#endif


#ifdef NTL_DISABLE_LONGDOUBLE
   cout << "NTL_DISABLE_LONGDOUBLE=1\n";
#else
   cout << "NTL_DISABLE_LONGDOUBLE=0\n";
#endif


#ifdef NTL_DISABLE_LONGLONG
   cout << "NTL_DISABLE_LONGLONG=1\n";
#else
   cout << "NTL_DISABLE_LONGLONG=0\n";
#endif


#ifdef NTL_DISABLE_LL_ASM
   cout << "NTL_DISABLE_LL_ASM=1\n";
#else
   cout << "NTL_DISABLE_LL_ASM=0\n";
#endif

#ifdef NTL_MAXIMIZE_SP_NBITS
   cout << "NTL_MAXIMIZE_SP_NBITS=1\n";
#else
   cout << "NTL_MAXIMIZE_SP_NBITS=0\n";
#endif



#ifdef NTL_GMP_LIP
   cout << "NTL_GMP_LIP=1\n";
#else
   cout << "NTL_GMP_LIP=0\n";
#endif


#ifdef NTL_GF2X_LIB
   cout << "NTL_GF2X_LIB=1\n";
#else
   cout << "NTL_GF2X_LIB=0\n";
#endif

#ifdef NTL_LONG_LONG_TYPE
   cout << "FLAG_LONG_LONG_TYPE=1\n";
   cout << "NTL_LONG_LONG_TYPE=" make_string(NTL_LONG_LONG_TYPE) "\n";
#else
   cout << "FLAG_LONG_LONG_TYPE=0\n";
   cout << "NTL_LONG_LONG_TYPE=long long\n";
#endif


#ifdef NTL_UNSIGNED_LONG_LONG_TYPE
   cout << "FLAG_UNSIGNED_LONG_LONG_TYPE=1\n";
   cout << "NTL_UNSIGNED_LONG_LONG_TYPE=" make_string(NTL_UNSIGNED_LONG_LONG_TYPE) "\n";
#else
   cout << "FLAG_UNSIGNED_LONG_LONG_TYPE=0\n";
   cout << "NTL_UNSIGNED_LONG_LONG_TYPE=unsigned long long\n";
#endif


#ifdef NTL_X86_FIX
   cout << "NTL_X86_FIX=1\n";
#else
   cout << "NTL_X86_FIX=0\n";
#endif

#ifdef NTL_NO_X86_FIX
   cout << "NTL_NO_X86_FIX=1\n";
#else
   cout << "NTL_NO_X86_FIX=0\n";
#endif


#ifdef NTL_NO_INIT_TRANS
   cout << "NTL_NO_INIT_TRANS=1\n";
#else
   cout << "NTL_NO_INIT_TRANS=0\n";
#endif

#ifdef NTL_CLEAN_INT
   cout << "NTL_CLEAN_INT=1\n";
#else
   cout << "NTL_CLEAN_INT=0\n";
#endif

#ifdef NTL_CLEAN_PTR
   cout << "NTL_CLEAN_PTR=1\n";
#else
   cout << "NTL_CLEAN_PTR=0\n";
#endif

#ifdef NTL_RANGE_CHECK
   cout << "NTL_RANGE_CHECK=1\n";
#else
   cout << "NTL_RANGE_CHECK=0\n";
#endif


// the following is synthetically defined
#ifdef NTL_LONGLONG_SP_MULMOD
   cout << "NTL_LONGLONG_SP_MULMOD=1\n";
#else
   cout << "NTL_LONGLONG_SP_MULMOD=0\n";
#endif


   return 0;
}
