#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <tlhelp32.h>
#include <cstdio>
#include <cwchar>
#include <memory>
#include "contract.hpp"
using supervisor::require;
namespace {
struct Handle { HANDLE h=nullptr; explicit Handle(HANDLE v=nullptr):h(v){} ~Handle(){if(h&&h!=INVALID_HANDLE_VALUE)CloseHandle(h);} Handle(const Handle&)=delete; Handle& operator=(const Handle&)=delete; };
void checked(BOOL ok,const char* name){if(!ok)throw std::runtime_error(std::string(name)+" Win32="+std::to_string(GetLastError()));}
HANDLE stopEvent=nullptr;
BOOL WINAPI control(DWORD kind){if(kind==CTRL_C_EVENT||kind==CTRL_BREAK_EVENT||kind==CTRL_CLOSE_EVENT||kind==CTRL_LOGOFF_EVENT||kind==CTRL_SHUTDOWN_EVENT){SetEvent(stopEvent);return TRUE;}return FALSE;}
struct ConsoleHandler { explicit ConsoleHandler(HANDLE event){stopEvent=event;checked(SetConsoleCtrlHandler(control,TRUE),"console handler");} ~ConsoleHandler(){SetConsoleCtrlHandler(control,FALSE);stopEvent=nullptr;} };
void nonAdmin(){Handle token;checked(OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&token.h),"OpenProcessToken");TOKEN_ELEVATION elevation{};DWORD n=0;checked(GetTokenInformation(token.h,TokenElevation,&elevation,sizeof(elevation),&n),"GetTokenInformation");require(!elevation.TokenIsElevated,"must run non-elevated");}
void verifyParent(DWORD pid,HANDLE parent){Handle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0));require(snapshot.h!=INVALID_HANDLE_VALUE,"process snapshot failed");PROCESSENTRY32W entry{};entry.dwSize=sizeof(entry);bool match=false;for(BOOL more=Process32FirstW(snapshot.h,&entry);more;more=Process32NextW(snapshot.h,&entry))if(entry.th32ProcessID==GetCurrentProcessId()){match=entry.th32ParentProcessID==pid;break;}require(match,"parent PID does not identify launcher");FILETIME pc,pe,pk,pu,sc,se,sk,su;checked(GetProcessTimes(parent,&pc,&pe,&pk,&pu),"parent times");checked(GetProcessTimes(GetCurrentProcess(),&sc,&se,&sk,&su),"self times");require(CompareFileTime(&pc,&sc)<=0,"parent PID reused");require(WaitForSingleObject(parent,0)==WAIT_TIMEOUT,"parent already exited");}
void allowed(const supervisor::Request& r){const auto& a=r.argv;require(a.size()>=11&&a[0]==L"-c"&&a[1]==L"windows.sandbox=\"elevated\""&&a[2]==L"-c"&&a[3]==L"prefer_mxc=false"&&a[4]==L"-c"&&a[5]==L"shell_environment_policy.inherit=\"all\""&&a[6]==L"sandbox"&&a[7]==L"--sandbox-state-json"&&a[9]==L"--"&&supervisor::absolute(a[10]),"only pinned Codex sandbox invocation allowed");auto pos=r.executable.find_last_of(L'\\');auto base=r.executable.substr(pos+1);require(_wcsicmp(base.c_str(),L"codex.exe")==0,"Codex executable required");}
struct Attributes { std::vector<unsigned char> bytes; LPPROC_THREAD_ATTRIBUTE_LIST p=nullptr; Attributes(){SIZE_T n=0;InitializeProcThreadAttributeList(nullptr,2,0,&n);require(n>0,"attribute size unavailable");bytes.resize(n);p=reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(bytes.data());checked(InitializeProcThreadAttributeList(p,2,0,&n),"attribute init");}~Attributes(){if(p)DeleteProcThreadAttributeList(p);} };
DWORD run(const supervisor::Request& r){nonAdmin();allowed(r);auto line=supervisor::commandLine(r);
  Handle parent(OpenProcess(SYNCHRONIZE|PROCESS_QUERY_LIMITED_INFORMATION,FALSE,r.parentPid));require(parent.h!=nullptr,"cannot watch parent");verifyParent(r.parentPid,parent.h);
  Handle job(CreateJobObjectW(nullptr,nullptr));require(job.h!=nullptr,"CreateJobObject failed");JOBOBJECT_EXTENDED_LIMIT_INFORMATION limit{};limit.BasicLimitInformation.LimitFlags=JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;checked(SetInformationJobObject(job.h,JobObjectExtendedLimitInformation,&limit,sizeof(limit)),"job limits");
  Handle stop(CreateEventW(nullptr,TRUE,FALSE,nullptr));require(stop.h!=nullptr,"stop event failed");ConsoleHandler handler(stop.h);
  Handle input,output,error;Handle* copies[]={&input,&output,&error};DWORD ids[]={STD_INPUT_HANDLE,STD_OUTPUT_HANDLE,STD_ERROR_HANDLE};HANDLE inherited[3];
  for(int i=0;i<3;++i){auto source=GetStdHandle(ids[i]);require(source&&source!=INVALID_HANDLE_VALUE,"three valid standard handles required");checked(DuplicateHandle(GetCurrentProcess(),source,GetCurrentProcess(),&copies[i]->h,0,TRUE,DUPLICATE_SAME_ACCESS),"duplicate standard handle");inherited[i]=copies[i]->h;}
  Attributes attrs;checked(UpdateProcThreadAttribute(attrs.p,0,PROC_THREAD_ATTRIBUTE_HANDLE_LIST,inherited,sizeof(inherited),nullptr,nullptr),"handle allowlist");
  // Windows 10+ atomically assigns the job during process creation. This closes
  // the orphan-suspended-child window of CreateProcess + AssignProcess alone.
  HANDLE jobs[]={job.h};checked(UpdateProcThreadAttribute(attrs.p,0,PROC_THREAD_ATTRIBUTE_JOB_LIST,jobs,sizeof(jobs),nullptr,nullptr),"atomic job assignment");
  STARTUPINFOEXW si{};si.StartupInfo.cb=sizeof(si);si.StartupInfo.dwFlags=STARTF_USESTDHANDLES;si.StartupInfo.hStdInput=input.h;si.StartupInfo.hStdOutput=output.h;si.StartupInfo.hStdError=error.h;si.lpAttributeList=attrs.p;PROCESS_INFORMATION pi{};
  checked(CreateProcessW(r.executable.c_str(),line.data(),nullptr,nullptr,TRUE,CREATE_SUSPENDED|EXTENDED_STARTUPINFO_PRESENT|CREATE_UNICODE_ENVIRONMENT,nullptr,r.cwd.c_str(),&si.StartupInfo,&pi),"CreateProcessW");Handle process(pi.hProcess),thread(pi.hThread);
  // Every exit/exception after creation closes the non-inherited job handle.
  BOOL member=FALSE;checked(IsProcessInJob(process.h,job.h,&member),"IsProcessInJob");require(member,"atomic job membership missing");
  require(WaitForSingleObject(parent.h,0)==WAIT_TIMEOUT,"parent exited before resume");require(ResumeThread(thread.h)!=static_cast<DWORD>(-1),"ResumeThread failed");
  HANDLE waits[]={parent.h,stop.h,process.h};DWORD event=WaitForMultipleObjects(3,waits,FALSE,INFINITE);require(event>=WAIT_OBJECT_0&&event<WAIT_OBJECT_0+3,"wait failed");DWORD exitCode=125;
  if(event==WAIT_OBJECT_0+2)checked(GetExitCodeProcess(process.h,&exitCode),"root exit code");
  checked(TerminateJobObject(job.h,event==WAIT_OBJECT_0+2?0:125),"terminate process tree");
  // Do not report success until the whole assigned job, including nested jobs,
  // is empty. A failed query or timeout is an explicit supervisor failure.
  ULONGLONG deadline=GetTickCount64()+30000;for(;;){JOBOBJECT_BASIC_ACCOUNTING_INFORMATION info{};checked(QueryInformationJobObject(job.h,JobObjectBasicAccountingInformation,&info,sizeof(info),nullptr),"job accounting");if(info.ActiveProcesses==0)break;require(GetTickCount64()<deadline,"job drain timeout");Sleep(10);}
  return exitCode;
}
}
int wmain(int argc,wchar_t** argv){try{
  if(argc==2&&(wcscmp(argv[1],L"-v")==0||wcscmp(argv[1],L"--version")==0)){puts("pi-job-supervisor 0.1.0");return 0;}
  if(argc==2&&wcscmp(argv[1],L"--capabilities")==0){puts("{\"protocol\":1,\"version\":\"0.1.0\",\"atomicJobAssignment\":true,\"killOnJobClose\":true,\"parentDeathWatch\":true,\"nativeIntegrationValidated\":false}");return 0;}
  require(argc==3&&wcscmp(argv[1],L"--request-json")==0,"usage: pi-job-supervisor --request-json JSON");auto request=supervisor::Parser(argv[2]).parse();DWORD result=run(request);ExitProcess(result);
}catch(const std::exception& e){fprintf(stderr,"PI_SUPERVISOR_FAILURE: %s\n",e.what());return 125;}}
