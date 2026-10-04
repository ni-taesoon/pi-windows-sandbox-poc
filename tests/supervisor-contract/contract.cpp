#include "../../native/supervisor/contract.hpp"
#include <cassert>
#include <iostream>
using namespace supervisor;
// Independent Windows CRT-style decoder for generated command line contracts.
std::vector<std::wstring> decode(const std::wstring& s){std::vector<std::wstring> out;size_t i=0;while(i<s.size()){while(i<s.size()&&s[i]==L' ')++i;if(i==s.size())break;std::wstring a;bool quoted=false;while(i<s.size()&&(quoted||s[i]!=L' ')){size_t n=0;while(i<s.size()&&s[i]==L'\\'){++n;++i;}if(i<s.size()&&s[i]==L'"'){a.append(n/2,L'\\');if(n%2)a+=L'"';else quoted=!quoted;++i;}else{a.append(n,L'\\');if(i<s.size()&&(quoted||s[i]!=L' '))a+=s[i++];}}out.push_back(a);}return out;}
bool rejects(const std::wstring& s){try{Parser(s).parse();return false;}catch(const std::exception&){return true;}}
int main(){
  std::vector<std::wstring> cases={L"",L"plain",L"space here",L"\"",L"a\\\"b",L"C:\\path with spaces\\",L"&& | > < %PATH%",L"한글"};
  for(const auto& a:cases){auto got=decode(quote(a));assert(got.size()==1&&got[0]==a);}
  // Exhaustive short combinations exercise quote/backslash parity.
  std::vector<std::wstring> generated={L""};for(int length=0;length<6;++length){auto prior=generated;for(const auto& a:prior)for(auto c:std::wstring(L"a \\\"")){auto next=a+c;auto got=decode(quote(next));assert(got.size()==1&&got[0]==next);generated.push_back(next);}}
  auto good=LR"({"schemaVersion":1,"executable":"C:\\bin\\codex.exe","cwd":"C:\\work","argv":["x","a\\","\uD83D\uDE00"],"parentPid":123})";
  auto r=Parser(good).parse();assert(r.parentPid==123&&r.argv.size()==3);auto decoded=decode(commandLine(r));assert(decoded[0]==r.executable&&decoded[2]==r.argv[1]);
  assert(rejects(LR"({"schemaVersion":1})"));
  for(const auto& field:std::vector<std::wstring>{L"\"parentPid\":1",L"\"extra\":1"}){std::wstring s=good;s.insert(s.size()-1,L","+field);assert(rejects(s));}
  for(const auto& bad:std::vector<std::wstring>{L"0",L"01",L"-1",L"4294967296",L"1.5"}){std::wstring s=good;auto p=s.find(L"123");s.replace(p,3,bad);assert(rejects(s));}
  for(const auto& bad:std::vector<std::wstring>{L"\\u0000",L"\\uD800",L"\\uDC00"}){std::wstring s=good;auto p=s.find(L"\"x\"");s.replace(p,3,L"\""+bad+L"\"");assert(rejects(s));}
  assert(!absolute(L"C:relative")&&!absolute(L"\\\\server\\share")&&!absolute(L"C:/dir"));
  r.argv={std::wstring(32767,L'x')};bool longRejected=false;try{commandLine(r);}catch(...){longRejected=true;}assert(longRejected);
  std::cout<<"Portable parser/quoting contracts PASS; Win32 compilation and integration NOT RUN\n";
}
