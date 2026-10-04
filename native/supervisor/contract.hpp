#pragma once
#include <string>
#include <vector>
#include <set>
#include <stdexcept>
#include <cstdint>
namespace supervisor {
struct Request { std::wstring executable, cwd; std::vector<std::wstring> argv; uint32_t parentPid=0; };
inline void require(bool b, const char* reason) { if (!b) throw std::runtime_error(reason); }
// Implements the Windows CRT argv quoting rules, without a shell.
inline std::wstring quote(const std::wstring& s) {
  require(s.find(L'\0')==s.npos,"NUL argument");
  std::wstring r=L"\""; size_t slashes=0;
  for(wchar_t c:s) { if(c==L'\\') { ++slashes; continue; }
    r.append(slashes*(c==L'"'?2:1),L'\\'); slashes=0;
    if(c==L'"') { r+=L'\\'; }
    r+=c;
  } r.append(slashes*2,L'\\'); return r+L'"';
}
inline bool absolute(const std::wstring& s) {
  // Deliberately narrow: no UNC/device paths or drive-relative paths.
  return s.size()>=3 && ((s[0]>=L'A'&&s[0]<=L'Z')||(s[0]>=L'a'&&s[0]<=L'z')) && s[1]==L':' && s[2]==L'\\' && s.find(L'/')==s.npos;
}
class Parser {
  const std::wstring& s; size_t i=0;
  void ws(){while(i<s.size()&&(s[i]==L' '||s[i]==L'\n'||s[i]==L'\r'||s[i]==L'\t'))++i;}
  bool take(wchar_t c){ws();if(i<s.size()&&s[i]==c){++i;return true;}return false;}
  void expect(wchar_t c){require(take(c),"invalid JSON punctuation");}
  unsigned hex(){require(i+4<=s.size(),"short unicode escape");unsigned n=0;for(int k=0;k<4;++k){auto c=s[i++];n*=16;if(c>=L'0'&&c<=L'9')n+=c-L'0';else if(c>=L'a'&&c<=L'f')n+=c-L'a'+10;else if(c>=L'A'&&c<=L'F')n+=c-L'A'+10;else throw std::runtime_error("invalid unicode escape");}return n;}
  std::wstring str(){expect(L'"');std::wstring out;bool end=false;
    while(i<s.size()){auto c=s[i++];if(c==L'"'){end=true;break;}require(c>=32,"control character");if(c==L'\\'){require(i<s.size(),"short escape");c=s[i++];switch(c){case L'"':case L'\\':case L'/':break;case L'b':c=8;break;case L'f':c=12;break;case L'n':c=10;break;case L'r':c=13;break;case L't':c=9;break;case L'u':c=static_cast<wchar_t>(hex());break;default:throw std::runtime_error("invalid escape");}} require(c!=0,"NUL string");out+=c;}
    require(end,"unterminated string");for(size_t j=0;j<out.size();++j){auto c=static_cast<uint32_t>(out[j]);if(c>=0xd800&&c<=0xdbff){require(++j<out.size()&&out[j]>=0xdc00&&out[j]<=0xdfff,"unpaired surrogate");}else require(!(c>=0xdc00&&c<=0xdfff),"unpaired surrogate");}return out;}
  uint32_t num(){ws();require(i<s.size()&&s[i]>=L'0'&&s[i]<=L'9',"expected unsigned integer");uint64_t n=0;size_t start=i;while(i<s.size()&&s[i]>=L'0'&&s[i]<=L'9'){n=n*10+(s[i++]-L'0');require(n<=UINT32_MAX,"integer overflow");}require(i-start==1||s[start]!=L'0',"leading zero");return static_cast<uint32_t>(n);}
public:
  explicit Parser(const std::wstring& input):s(input){}
  Request parse(){require(s.size()<=30000,"request too large");Request r;std::set<std::wstring> keys;expect(L'{');do{auto key=str();require(keys.insert(key).second,"duplicate field");expect(L':');if(key==L"schemaVersion")require(num()==1,"schema version");else if(key==L"executable")r.executable=str();else if(key==L"cwd")r.cwd=str();else if(key==L"parentPid")r.parentPid=num();else if(key==L"argv"){expect(L'[');if(!take(L']')){do{require(r.argv.size()<1024,"too many arguments");r.argv.push_back(str());}while(take(L','));expect(L']');}}else throw std::runtime_error("unknown field");}while(take(L','));expect(L'}');ws();require(i==s.size()&&keys.size()==5,"missing fields or trailing JSON");require(absolute(r.executable)&&absolute(r.cwd),"absolute drive paths required");require(r.parentPid>0,"parent PID required");return r;}
};
inline std::wstring commandLine(const Request& r){auto line=quote(r.executable);for(const auto& a:r.argv){line+=L' ';line+=quote(a);require(line.size()<32767,"Windows command line too long");}require(line.size()<32767,"Windows command line too long");return line;}
}
