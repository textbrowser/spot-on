#include <NTL/config.h>
#include <NTL/new.h>
#include <atomic>
#include <thread>
#include <cstdlib>

#include <iostream>

void TerminalError(const char *s)
{
   std::cerr << s << "\n";
   std::abort();
}

void MemoryError() { TerminalError("out of memory"); }
void ResourceError(const char *msg) { TerminalError(msg); }


#if (defined(NTL_THREADS) && defined(NTL_TLS_HACK)) 
#include <pthread.h>
#endif

#define NTL_THREAD_LOCAL thread_local

#ifdef __GNUC__
#define NTL_CHEAP_THREAD_LOCAL __thread
#else
#define NTL_CHEAP_THREAD_LOCAL thread_local
#endif



#if (defined(NTL_THREADS) && defined(NTL_TLS_HACK)) 


namespace details_pthread {


template<class T> void do_delete_aux(T* t) noexcept { delete t;  }
// an exception here would likely lead to a complete mess...
// the noexcept specification should force an immediate termination

template<class T> void do_delete(void* t) { do_delete_aux((T*)t);  }

using namespace std;
// I'm not sure if pthread stuff might be placed in namespace std

struct key_wrapper {
   pthread_key_t key;

   key_wrapper(void (*destructor)(void*))
   {
      if (pthread_key_create(&key, destructor))
         ResourceError("pthread_key_create failed");
   }

   template<class T>
   T* set(T *p)
   {
      if (!p) MemoryError();
      if (pthread_setspecific(key, p)) {
         do_delete_aux(p);
         ResourceError("pthread_setspecific failed");
      }
      return p;
   }

};

}


#define NTL_TLS_LOCAL_INIT(type, var, init)  \
   static NTL_CHEAP_THREAD_LOCAL type *_ntl_hidden_variable_tls_local_ptr_ ## var = 0;  \
   type *_ntl_hidden_variable_tls_local_ptr1_ ## var = _ntl_hidden_variable_tls_local_ptr_ ## var;  \
   if (!_ntl_hidden_variable_tls_local_ptr1_ ## var) {  \
      static details_pthread::key_wrapper hidden_variable_key(details_pthread::do_delete<type>);  \
      type *_ntl_hidden_variable_tls_local_ptr2_ ## var = hidden_variable_key.set(NTL_NEW_OP type init);  \
      _ntl_hidden_variable_tls_local_ptr1_ ## var = _ntl_hidden_variable_tls_local_ptr2_ ## var;  \
      _ntl_hidden_variable_tls_local_ptr_ ## var = _ntl_hidden_variable_tls_local_ptr1_ ## var;  \
   }  \
   type &var = *_ntl_hidden_variable_tls_local_ptr1_ ## var  \



#else


// NOTE: this definition of NTL_TLS_LOCAL_INIT ensures that var names
// a local reference, regardless of the implementation
#define NTL_TLS_LOCAL_INIT(type,var,init) \
    static NTL_THREAD_LOCAL type _ntl_hidden_variable_tls_local ## var init; \
    type &var = _ntl_hidden_variable_tls_local ## var




#endif

#define NTL_EMPTY_ARG
#define NTL_TLS_LOCAL(type,var) NTL_TLS_LOCAL_INIT(type,var,NTL_EMPTY_ARG)

#define NTL_TLS_GLOBAL_DECL_INIT(type,var,init)  \
   typedef type _ntl_hidden_typedef_tls_access_ ## var;  \
   static inline  \
   type& _ntl_hidden_function_tls_access_ ## var() {  \
      NTL_TLS_LOCAL_INIT(type,var,init);  \
      return var;  \
   }  \


#define NTL_TLS_GLOBAL_DECL(type,var) NTL_TLS_GLOBAL_DECL_INIT(type,var,NTL_EMPTY_ARG)

#define NTL_TLS_GLOBAL_ACCESS(var) \
_ntl_hidden_typedef_tls_access_ ## var & var = _ntl_hidden_function_tls_access_ ## var()


std::atomic_long count(0);
std::atomic_long count1(0);

struct X {
   long d;

   X() { d = count1++; count++; }
   ~X() { count--; }
};

NTL_TLS_GLOBAL_DECL(X,x)

void task(long *v)
{
   NTL_TLS_GLOBAL_ACCESS(x);
   *v = x.d;
}


#define MIN(a,b) ((a)<(b)?(a):(b))
#define MAX(a,b) ((a)>(b)?(a):(b))

int main()
{
   long v1, v2, v3;
   std::thread t1(task, &v1);
   std::thread t2(task, &v2);
   std::thread t3(task, &v3);

   t1.join();
   t2.join();
   t3.join();

   //std::cout << count << "\n";
   //std::cout << v1 << " " << v2 << " " << v3 << "\n";

   long s1, s2, s3;
   s1 = MIN(MIN(v1,v2),v3);
   s3 = MAX(MAX(v1,v2),v3);
   s2 = v1+v2+v3-s1-s3;

   if (count != 0 || s1 != 0 || s2 != 1 || s3 != 2) {
      return -1;
   }
   return 0;
}
