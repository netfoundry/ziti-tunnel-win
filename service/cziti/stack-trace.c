
/* compile with:
on linux:   gcc -g stack_traces.c
on OS X:    gcc -g -fno-pie stack_traces.c
on windows: gcc -g stack_traces.c -limagehlp
*/

#include <ziti/ziti_log.h>
#include <signal.h>
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>

#include <windows.h>
#include <imagehlp.h>

static char const *icky_global_program_name;

/* Resolve symbol name and source location given the path to the executable
   and an address */
int addr2line(char const *const program_name, void const *const addr)
{
  char addr2line_cmd[512] = {0};
  sprintf(addr2line_cmd, "addr2line -f -p -e %.256s %p", program_name, addr);

  FILE *fp;
  char buf[1035];

  /* Open the command for reading. */
  fp = popen(addr2line_cmd, "r");
  if (fp == NULL)
  {
    ZITI_LOG(ERROR, "Failed to run command");
    return 1;
  }

  /* Read the output a line at a time - output it. */
  while (fgets(buf, sizeof(buf), fp) != NULL)
  {
    ZITI_LOG(ERROR, "%s result %s", addr2line_cmd, buf);
  }

  /* close */
  pclose(fp);
  return 0;
}

void windows_print_stacktrace(CONTEXT *context)
{
  SymInitialize(GetCurrentProcess(), 0, true);

  STACKFRAME frame = {0};

  /* setup initial stack frame */
  frame.AddrPC.Offset = context->Rip;
  frame.AddrPC.Mode = AddrModeFlat;
  frame.AddrStack.Offset = context->Rsp;
  frame.AddrStack.Mode = AddrModeFlat;
  frame.AddrFrame.Offset = context->Rbp;
  frame.AddrFrame.Mode = AddrModeFlat;

  while (StackWalk(IMAGE_FILE_MACHINE_I386,
                   GetCurrentProcess(),
                   GetCurrentThread(),
                   &frame,
                   context,
                   0,
                   SymFunctionTableAccess,
                   SymGetModuleBase,
                   0))
  {
    int result = addr2line(icky_global_program_name, (void *)frame.AddrPC.Offset);
    ZITI_LOG(ERROR, "stackwalking result %d", result);
  }

  SymCleanup(GetCurrentProcess());
}

LONG WINAPI windows_exception_handler(EXCEPTION_POINTERS *ExceptionInfo)
{
  switch (ExceptionInfo->ExceptionRecord->ExceptionCode)
  {
  case EXCEPTION_ACCESS_VIOLATION:
    ZITI_LOG(ERROR, "Error: EXCEPTION_ACCESS_VIOLATION");
    break;
  case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:
    ZITI_LOG(ERROR, "Error: EXCEPTION_ARRAY_BOUNDS_EXCEEDED");
    break;
  case EXCEPTION_BREAKPOINT:
    ZITI_LOG(ERROR, "Error: EXCEPTION_BREAKPOINT");
    break;
  case EXCEPTION_DATATYPE_MISALIGNMENT:
    ZITI_LOG(ERROR, "Error: EXCEPTION_DATATYPE_MISALIGNMENT");
    break;
  case EXCEPTION_FLT_DENORMAL_OPERAND:
    ZITI_LOG(ERROR, "Error: EXCEPTION_FLT_DENORMAL_OPERAND");
    break;
  case EXCEPTION_FLT_DIVIDE_BY_ZERO:
    ZITI_LOG(ERROR, "Error: EXCEPTION_FLT_DIVIDE_BY_ZERO");
    break;
  case EXCEPTION_FLT_INEXACT_RESULT:
    ZITI_LOG(ERROR, "Error: EXCEPTION_FLT_INEXACT_RESULT");
    break;
  case EXCEPTION_FLT_INVALID_OPERATION:
    ZITI_LOG(ERROR, "Error: EXCEPTION_FLT_INVALID_OPERATION");
    break;
  case EXCEPTION_FLT_OVERFLOW:
    ZITI_LOG(ERROR, "Error: EXCEPTION_FLT_OVERFLOW");
    break;
  case EXCEPTION_FLT_STACK_CHECK:
    ZITI_LOG(ERROR, "Error: EXCEPTION_FLT_STACK_CHECK");
    break;
  case EXCEPTION_FLT_UNDERFLOW:
    ZITI_LOG(ERROR, "Error: EXCEPTION_FLT_UNDERFLOW");
    break;
  case EXCEPTION_ILLEGAL_INSTRUCTION:
    ZITI_LOG(ERROR, "Error: EXCEPTION_ILLEGAL_INSTRUCTION");
    break;
  case EXCEPTION_IN_PAGE_ERROR:
    ZITI_LOG(ERROR, "Error: EXCEPTION_IN_PAGE_ERROR");
    break;
  case EXCEPTION_INT_DIVIDE_BY_ZERO:
    ZITI_LOG(ERROR, "Error: EXCEPTION_INT_DIVIDE_BY_ZERO");
    break;
  case EXCEPTION_INT_OVERFLOW:
    ZITI_LOG(ERROR, "Error: EXCEPTION_INT_OVERFLOW");
    break;
  case EXCEPTION_INVALID_DISPOSITION:
    ZITI_LOG(ERROR, "Error: EXCEPTION_INVALID_DISPOSITION");
    break;
  case EXCEPTION_NONCONTINUABLE_EXCEPTION:
    ZITI_LOG(ERROR, "Error: EXCEPTION_NONCONTINUABLE_EXCEPTION");
    break;
  case EXCEPTION_PRIV_INSTRUCTION:
    ZITI_LOG(ERROR, "Error: EXCEPTION_PRIV_INSTRUCTION");
    break;
  case EXCEPTION_SINGLE_STEP:
    ZITI_LOG(ERROR, "Error: EXCEPTION_SINGLE_STEP");
    break;
  case EXCEPTION_STACK_OVERFLOW:
    ZITI_LOG(ERROR, "Error: EXCEPTION_STACK_OVERFLOW");
    break;
  default:
    ZITI_LOG(ERROR, "Error: Unrecognized Exception");
    break;
  }
  /* If this is a stack overflow then we can't walk the stack, so just show
      where the error happened */
  if (EXCEPTION_STACK_OVERFLOW != ExceptionInfo->ExceptionRecord->ExceptionCode)
  {
    windows_print_stacktrace(ExceptionInfo->ContextRecord);
  }
  else
  {
    ZITI_LOG(ERROR, "EXCEPTION_STACK_OVERFLOW");
    addr2line(icky_global_program_name, (void *)ExceptionInfo->ContextRecord->Rip);
  }

  return EXCEPTION_EXECUTE_HANDLER;
}
LONG WINAPI VectoredHandler(PEXCEPTION_POINTERS ExceptionInfo)
{
  return windows_exception_handler(ExceptionInfo);
}

void set_signal_handler(char *programName)
{
  icky_global_program_name = programName;
  SetUnhandledExceptionFilter(windows_exception_handler);
  AddVectoredExceptionHandler(1, VectoredHandler);
}
