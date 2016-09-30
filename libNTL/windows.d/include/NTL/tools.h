
#ifndef NTL_tools__H
#define NTL_tools__H

//#define NTL_TEST_EXCEPTIONS

#include <NTL/ctools.h>
#include <NTL/new.h>

#include <iostream>
#include <new>
#include <stdexcept>

#include <cstdlib>
#include <cmath>




#define NTL_SNS std ::
#define NTL_USE_SNS using namespace std;

#ifndef NTL_LEGACY_NO_NAMESPACE

// This wraps NTL in the NTL namespace.
// This is the current default.

#define NTL_NAMESPACE NTL
#define NTL_OPEN_NNS namespace NTL_NAMESPACE {
#define NTL_CLOSE_NNS  }
#define NTL_USE_NNS using namespace NTL_NAMESPACE;
#define NTL_NNS NTL_NAMESPACE ::

// To make things work, we have to apply using declarations of all std
// functions that are both overloaded by NTL and are used in
// the implementation of NTL.

#define NTL_START_IMPL NTL_USE_SNS NTL_OPEN_NNS \
   using NTL_SNS abs; \
   using NTL_SNS ceil; \
   using NTL_SNS exp; \
   using NTL_SNS fabs; \
   using NTL_SNS floor; \
   using NTL_SNS ldexp; \
   using NTL_SNS log; \
   using NTL_SNS sqrt; 

#define NTL_END_IMPL NTL_CLOSE_NNS

#else

// This puts NTL in the global namespace.
// Provided only for backward compatibility.

#define NTL_NAMESPACE 
#define NTL_OPEN_NNS 
#define NTL_CLOSE_NNS 
#define NTL_USE_NNS 
#define NTL_NNS 

#define NTL_START_IMPL
#define NTL_END_IMPL

#endif

#define NTL_CLIENT NTL_USE_SNS NTL_USE_NNS



double _ntl_GetTime();
unsigned long _ntl_GetPID();

typedef unsigned long _ntl_ulong;
typedef _ntl_ulong *_ntl_ulong_ptr;
// I made these have "obscure" names to avoid conflict with
// (non-standard but common) definitions in standard headers.
// Putting u_long inside namespace NTL only tends to creates ambiguities,
// for no good reason.




NTL_OPEN_NNS

#ifndef NTL_LEGACY_INPUT_ERROR

// this newer version is more in line with wider C++
// practice, setting the "fail bit" of an input stream
// when an error is encounted.  This is now the default in NTL

#define NTL_INPUT_ERROR(s, msg) \
   do {\
      s.setstate(NTL_SNS ios::failbit);\
      return s;\
   } while (0)\


#else

// this version provides full backward compatibility,
// raising an error on ill-formed or missing input

#define NTL_INPUT_ERROR(s, msg) \
   do {\
      InputError(msg);\
   } while (0)\


#endif


#define NTL_INPUT_CHECK_ERR(stmt) \
   do {\
      if (!(stmt)) InputError("bad input\n");\
   } while (0)\



#define NTL_INPUT_CHECK_RET(s, stmt) \
   do {\
      if (!(stmt)) { s.setstate(NTL_SNS ios::failbit); return s; }\
   } while (0)\





#define NTL_FILE_THRESH (64000.0)
// threshold in KB for switching to external storage of certain
// tables (currently in the DDF polynomial factoring routines)




struct INIT_SIZE_STRUCT { };
const INIT_SIZE_STRUCT INIT_SIZE = INIT_SIZE_STRUCT();
typedef const INIT_SIZE_STRUCT& INIT_SIZE_TYPE;

struct INIT_VAL_STRUCT { };
const INIT_VAL_STRUCT INIT_VAL = INIT_VAL_STRUCT();
typedef const INIT_VAL_STRUCT& INIT_VAL_TYPE;

struct INIT_TRANS_STRUCT { };
const INIT_TRANS_STRUCT INIT_TRANS = INIT_TRANS_STRUCT();
typedef const INIT_TRANS_STRUCT& INIT_TRANS_TYPE;


struct INIT_LOOP_HOLE_STRUCT { };
const INIT_LOOP_HOLE_STRUCT INIT_LOOP_HOLE = INIT_LOOP_HOLE_STRUCT();
typedef const INIT_LOOP_HOLE_STRUCT& INIT_LOOP_HOLE_TYPE;

struct INIT_FFT_STRUCT { };
const INIT_FFT_STRUCT INIT_FFT = INIT_FFT_STRUCT();
typedef const INIT_FFT_STRUCT& INIT_FFT_TYPE;

struct INIT_USER_FFT_STRUCT { };
const INIT_USER_FFT_STRUCT INIT_USER_FFT = INIT_USER_FFT_STRUCT();
typedef const INIT_USER_FFT_STRUCT& INIT_USER_FFT_TYPE;

struct INIT_NO_ALLOC_STRUCT { };
const INIT_NO_ALLOC_STRUCT INIT_NO_ALLOC = INIT_NO_ALLOC_STRUCT();
typedef const INIT_NO_ALLOC_STRUCT& INIT_NO_ALLOC_TYPE;

struct INIT_ALLOC_STRUCT { };
const INIT_ALLOC_STRUCT INIT_ALLOC = INIT_ALLOC_STRUCT();
typedef const INIT_ALLOC_STRUCT& INIT_ALLOC_TYPE;

struct INIT_MONO_STRUCT { };
const INIT_MONO_STRUCT INIT_MONO = INIT_MONO_STRUCT();
typedef const INIT_MONO_STRUCT& INIT_MONO_TYPE;



#ifdef NTL_NO_INIT_TRANS
#define NTL_OPT_RETURN(t, x) return x
#else
#define NTL_OPT_RETURN(t, x) return t(x, INIT_TRANS)
#endif


#ifndef NTL_NO_MIN_MAX

inline int min(int a, int b) { return (a < b) ?  a : b; } 
inline int max(int a, int b) { return (a < b) ? b : a; }

inline long min(long a, long b) { return (a < b) ?  a : b; } 
inline long max(long a, long b) { return (a < b) ? b : a; }

inline long min(int a, long b) { return (a < b) ?  long(a) : b; } 
inline long max(int a, long b) { return (a < b) ? b : long(a); }

inline long min(long a, int b) { return (a < b) ?  a : long(b); } 
inline long max(long a, int b) { return (a < b) ? long(b) : a; }

#endif


inline void swap(long& a, long& b)  {  long t;  t = a; a = b; b = t; }
inline void swap(int& a, int& b)  {  int t;  t = a; a = b; b = t; }



inline void conv(int& x, int a) { x = a; }
inline void conv(int& x, long a) 
   { unsigned y = (unsigned) a;  x = NTL_UINT_TO_INT(y); }
inline void conv(int& x, float a) { x = int(NTL_SNS floor(double(a))); }
inline void conv(int& x, double a) { x = int(NTL_SNS floor(a)); }

inline void conv(int& x, unsigned a) 
   { x = NTL_UINT_TO_INT(a); }

inline void conv(int& x, unsigned long a)
   { unsigned y = (unsigned) a;  x = NTL_UINT_TO_INT(y); }

inline int to_int(int a) { return a; }
inline int to_int(long a) 
   { unsigned y = (unsigned) a;  return NTL_UINT_TO_INT(y); }
inline int to_int(float a) { return int(NTL_SNS floor(double(a))); }
inline int to_int(double a) { return int(NTL_SNS floor(a)); }

inline int to_int(unsigned a) 
   { return NTL_UINT_TO_INT(a); }

inline int to_int(unsigned long a) 
   { unsigned y = (unsigned) a;  return NTL_UINT_TO_INT(y); }


inline void conv(long& x, int a) { x = a; }
inline void conv(long& x, long a) { x = a; }
inline void conv(long& x, float a) { x = long(NTL_SNS floor(double(a))); }
inline void conv(long& x, double a) { x = long(NTL_SNS floor(a)); }

inline void conv(long& x, unsigned a)
   { unsigned long y = a;  x = NTL_ULONG_TO_LONG(y); }

inline void conv(long& x, unsigned long a)
   { x = NTL_ULONG_TO_LONG(a); }

inline long to_long(int a) { return a; }
inline long to_long(long a) { return a; }
inline long to_long(float a) { return long(NTL_SNS floor(double(a))); }
inline long to_long(double a) { return long(NTL_SNS floor(a)); }

inline long to_long(unsigned a)
   { unsigned long y = a;  return NTL_ULONG_TO_LONG(y); }

inline long to_long(unsigned long a)
   { return NTL_ULONG_TO_LONG(a); }

inline void conv(float& x, int a) { x = float(a); }
inline void conv(float& x, long a) { x = float(a); }
inline void conv(float& x, unsigned a) { x = float(a); }
inline void conv(float& x, unsigned long a) { x = float(a); }
inline void conv(float& x, float a) { x = a; }
inline void conv(float& x, double a) { x = float(a); }

inline float to_float(int a) { return float(a); }
inline float to_float(long a) { return float(a); }
inline float to_float(unsigned a) { return float(a); }
inline float to_float(unsigned long a) { return float(a); }
inline float to_float(float a) { return a; }
inline float to_float(double a) { return float(a); }

inline void conv(double& x, int a) { x = double(a); }
inline void conv(double& x, long a) { x = double(a); }
inline void conv(double& x, unsigned a) { x = double(a); }
inline void conv(double& x, unsigned long a) { x = double(a); }
inline void conv(double& x, float a) { x = double(a); }
inline void conv(double& x, double a) { x = a; }

inline double to_double(int a) { return double(a); }
inline double to_double(long a) { return double(a); }
inline double to_double(unsigned a) { return double(a); }
inline double to_double(unsigned long a) { return double(a); }
inline double to_double(float a) { return double(a); }
inline double to_double(double a) { return a; }



/* additional legacy conversions for v6 conversion regime */


inline void conv(unsigned int& x, int a) { x = ((unsigned int)(a)); }
inline void conv(unsigned int& x, long a) { x = ((unsigned int)(a)); }
inline void conv(unsigned int& x, unsigned a) { x = a; }
inline void conv(unsigned int& x, unsigned long a) { x = ((unsigned int)(a)); }
inline void conv(unsigned int& x, float a) { x = ((unsigned int) to_long(a)); }
inline void conv(unsigned int& x, double a) { x = ((unsigned int) to_long(a)); }

inline void conv(unsigned long& x, int a) { x = ((unsigned long)(a)); }
inline void conv(unsigned long& x, long a) { x = ((unsigned long)(a)); }
inline void conv(unsigned long& x, unsigned a) { x = ((unsigned long)(a)); }
inline void conv(unsigned long& x, unsigned long a) { x = a; }
inline void conv(unsigned long& x, float a) { x = ((unsigned int) to_long(a)); }
inline void conv(unsigned long& x, double a) { x = ((unsigned int) to_long(a)); }


/* ------------------------------------- */


// new style converson function
//   example: ZZ x = conv<ZZ>(1);
//   note: modern C++ compilers should implemented 
//     "named return value optimization", so the
//     result statement should not create a temporary

template<class T, class S>
T conv(const S& a)
{
   T x;
   conv(x, a);
   return x;
}


long SkipWhiteSpace(NTL_SNS istream& s);
long IsWhiteSpace(long c);
long IsEOFChar(long c);

long CharToIntVal(long c);
char IntValToChar(long a);





inline double GetTime() { return _ntl_GetTime(); }
inline unsigned long GetPID() { return _ntl_GetPID(); }

inline long IsFinite(double *p) { return _ntl_IsFinite(p); }


#if (NTL_EXT_DOUBLE)

inline void ForceToMem(double *p) { _ntl_ForceToMem(p); }

#else

inline void ForceToMem(double *p) { }

#endif



void PrintTime(NTL_SNS ostream& s, double t);



#if (defined(__GNUC__) && (__GNUC__ >= 4))

// on relative modern versions of gcc, we can 
// decalare "restricted" pointers in C++

#define NTL_RESTRICT __restrict

#else

#define NTL_RESTRICT

#endif

// A very lightly wrapped pointer than does nothing more than provide
// auto cleanup in a destructor.  Use the UniquePtr class (in SmartPtr.h) 
// for a class with more safety and convenience features.
// This class is easiest to use to retrofit older code with RAII
// semantics.

// A call to Deleter::apply should free the pointed-to storage
// and set the pointer itself to zero, so apply should
// take an argument that is a reference to a T*.

template<class T, class Deleter>
class WrappedPtr {
private:
   WrappedPtr(const WrappedPtr&); // disable
   void operator=(const WrappedPtr&); // disable
public:
   typedef T * raw_ptr;

   raw_ptr rep;

   WrappedPtr() : rep(0) { }
   void operator=(const raw_ptr& _rep)  { rep = _rep; }

   ~WrappedPtr() { Deleter::apply(rep); } 

   operator const raw_ptr& () const { return rep; }
   operator raw_ptr& () { return rep; }

   const raw_ptr* operator&() const { return &rep; }
   raw_ptr* operator&() { return &rep; }

   void kill() { Deleter::apply(rep); }

   void swap(WrappedPtr& other) { _ntl_swap(rep, other.rep); }

};

template<class T, class Deleter>
void swap(WrappedPtr<T,Deleter>& x, WrappedPtr<T,Deleter>& y)
{
   x.swap(y);
}



// Error Handling



class ErrorObject : public NTL_SNS runtime_error {
public:
   ErrorObject(const char *msg) : runtime_error(msg) { }
};

class LogicErrorObject : public ErrorObject {
public: 
   LogicErrorObject(const char *msg) : ErrorObject(msg) { }
};

class ArithmeticErrorObject : public ErrorObject {
public: 
   ArithmeticErrorObject(const char *msg) : ErrorObject(msg) { }
};

class ResourceErrorObject : public ErrorObject {
public: 
   ResourceErrorObject(const char *msg) : ErrorObject(msg) { }
};

class FileErrorObject : public ErrorObject {
public: 
   FileErrorObject(const char *msg) : ErrorObject(msg) { }
};

class InputErrorObject : public ErrorObject {
public: 
   InputErrorObject(const char *msg) : ErrorObject(msg) { }
};



NTL_THREAD_LOCAL extern void (*ErrorCallback)();

void TerminalError(const char *s);

#ifdef NTL_EXCEPTIONS

inline void MemoryError() { throw NTL_SNS bad_alloc(); }
inline void Error(const char *msg) { throw ErrorObject(msg); }
inline void LogicError(const char *msg) { throw LogicErrorObject(msg); }
inline void ArithmeticError(const char *msg) { throw ArithmeticErrorObject(msg); }
inline void InvModError(const char *msg) { throw ArithmeticErrorObject(msg); }
inline void ResourceError(const char *msg) { throw ResourceErrorObject(msg); }
inline void FileError(const char *msg) { throw FileErrorObject(msg); }
inline void InputError(const char *msg) { throw InputErrorObject(msg); }

#else

inline void MemoryError() { TerminalError("out of memory"); }
inline void Error(const char *msg) { TerminalError(msg); }
inline void LogicError(const char *msg) { TerminalError(msg); }
inline void ArithmeticError(const char *msg) { TerminalError(msg); }
inline void InvModError(const char *msg) { TerminalError(msg); }
inline void ResourceError(const char *msg) { TerminalError(msg); }
inline void FileError(const char *msg) { TerminalError(msg); }
inline void InputError(const char *msg) { TerminalError(msg); }

#endif






#ifdef NTL_EXCEPTIONS


template < typename F  >
class scope_guard 
{
    typename std::remove_reference<F>::type f;
    bool active;
    const char *info;
    
public:
    scope_guard(F&& _f, const char *_info) : 
       f(std::forward<F>(_f)), active(true), info(_info) { }

    ~scope_guard() {
        if (active) {
#ifdef NTL_TEST_EXCEPTIONS
            NTL_SNS cerr << "*** ACTIVE SCOPE GUARD TRIGGERED: "
                         <<  info << "\n";
#endif
            f();
        }
    }

    void relax() { active = false; }
};


struct scope_guard_builder {  
   const char *info;
   scope_guard_builder(const char *_info) : info(_info) { }
};

template < typename F >
scope_guard<F> 
operator+(scope_guard_builder b, F&& f)
{
    return scope_guard<F>(std::forward<F>(f), b.info);
}


#define NTL_SCOPE(var) auto var =  \
   scope_guard_builder(__FILE__ ":" NTL_STRINGIFY(__LINE__)) + [&]


#else


class DummyScopeGuard {
public:
   void relax() { }
};

#define NTL_SCOPE(var) DummyScopeGuard var; if (false)




#endif




NTL_CLOSE_NNS


#endif

