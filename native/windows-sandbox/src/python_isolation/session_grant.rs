//! Owner-side fixed synthetic grant. No caller-selected path/SID or automatic
//! rollback when process-tree cleanup is uncertain. This is not product policy.
use super::{VerifiedSessionIdentity,OUTSIDE_LOGON};
use crate::{setup::no_reparse_dir as nr,token,winutil,process::Handle};
use serde::Serialize;
use std::{ffi::c_void,os::windows::io::{AsHandle,AsRawHandle,OwnedHandle},path::Path,ptr::null_mut};
use windows_sys::Win32::{Foundation::*,Security::*,Security::Authorization::*,Storage::FileSystem::*};
const MODIFY:u32=FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_GENERIC_EXECUTE | DELETE;
const INHERIT:u8=3;
#[derive(Debug,Clone,Serialize)]
#[serde(rename_all="camelCase")]
pub struct GrantError {pub stage:&'static str,pub winerror:Option<u32>}
impl std::fmt::Display for GrantError {fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result{write!(f,"session grant stage={}; win32={:?}",self.stage,self.winerror)}}
impl std::error::Error for GrantError {}
type Result<T>=std::result::Result<T,GrantError>;
fn bad(stage:&'static str)->GrantError{GrantError{stage,winerror:None}}
fn mapped(stage:&'static str,error:anyhow::Error)->GrantError{GrantError{stage,winerror:error.chain().find_map(|e|e.downcast_ref::<std::io::Error>().and_then(|e|e.raw_os_error()).and_then(|e|u32::try_from(e).ok()))}}
unsafe fn api(ok:i32,stage:&'static str)->Result<()>{if ok==0{let code=GetLastError();Err(GrantError{stage,winerror:Some(code)})}else{Ok(())}}
#[derive(Clone,PartialEq,Eq)]
struct Ace {kind:u8,flags:u8,mask:u32,sid:Vec<u8>}
struct Snapshot {sd:*mut c_void,dacl:*mut ACL,owner:Vec<u8>,protected:bool,aces:Vec<Ace>}
impl Drop for Snapshot {fn drop(&mut self){unsafe{LocalFree(self.sd as HLOCAL);}}}
unsafe fn sid_bytes(sid:*mut c_void)->Result<Vec<u8>>{
    if IsValidSid(sid)==0{return Err(bad("invalid-trustee"));}
    let length=GetLengthSid(sid) as usize;if !(8..=68).contains(&length){return Err(bad("trustee-size"));}
    Ok(std::slice::from_raw_parts(sid.cast(),length).to_vec())
}
unsafe fn read_aces(dacl:*mut ACL)->Result<Vec<Ace>>{
    if dacl.is_null() || IsValidAcl(dacl)==0 || (*dacl).AceCount>64{return Err(bad("dacl-shape-bound"));}
    let start=dacl as usize;let end=start+(*dacl).AclSize as usize;let mut result=Vec::new();
    for index in 0..(*dacl).AceCount{
        let mut raw=null_mut();api(GetAce(dacl,index as u32,&mut raw),"get-ace")?;
        let addr=raw as usize;if addr<start || !addr.checked_add(16).is_some_and(|n|n<=end){return Err(bad("ace-bounds"));}
        let h=&*raw.cast::<ACE_HEADER>();
        if h.AceType!=0 || h.AceSize<16 || !addr.checked_add(h.AceSize as usize).is_some_and(|n|n<=end){return Err(bad("simple-allow-ace-required"));}
        let a=&*raw.cast::<ACCESS_ALLOWED_ACE>();let sid=std::ptr::addr_of!(a.SidStart).cast_mut().cast::<c_void>();
        let length=8+4*usize::from(*sid.cast::<u8>().add(1));if 8+length>h.AceSize as usize{return Err(bad("ace-sid-bounds"));}
        result.push(Ace{kind:h.AceType,flags:h.AceFlags,mask:a.Mask,sid:sid_bytes(sid)?});
    }Ok(result)
}
unsafe fn snapshot(handle:isize)->Result<Snapshot>{
    let mut sd=null_mut();let mut dacl=null_mut();let mut owner=null_mut();
    let code=GetSecurityInfo(handle,SE_FILE_OBJECT,OWNER_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION,
        &mut owner,null_mut(),&mut dacl,null_mut(),&mut sd);
    if code!=0{return Err(GrantError{stage:"read-leaf-security",winerror:Some(code)});}
    let read=(||->Result<(Vec<u8>,bool,Vec<Ace>)>{let mut control=0;let mut revision=0;
        api(GetSecurityDescriptorControl(sd,&mut control,&mut revision),"read-dacl-protection")?;
        Ok((sid_bytes(owner)?,control & SE_DACL_PROTECTED!=0,read_aces(dacl)?))})();
    match read{Ok((owner,protected,aces))=>Ok(Snapshot{sd,dacl,owner,protected,aces}),Err(error)=>{LocalFree(sd as HLOCAL);Err(error)}}
}
unsafe fn identity(handle:isize)->Result<(u32,u32,u32)>{
    let mut info:BY_HANDLE_FILE_INFORMATION=std::mem::zeroed();api(GetFileInformationByHandle(handle,&mut info),"leaf-file-identity")?;
    if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT!=0 || info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY==0{return Err(bad("non-reparse-leaf-required"));}
    Ok((info.dwVolumeSerialNumber,info.nFileIndexHigh,info.nFileIndexLow))
}
pub struct SessionGrant {
    leaf:OwnedHandle,_ancestors:Vec<OwnedHandle>,_guard:OwnedHandle,original:Snapshot,
    owner_sid:Vec<u8>,admin_sid:Vec<u8>,system_sid:Vec<u8>,users_sid:Vec<u8>,logon:token::LocalSid,logon_bytes:Vec<u8>,
    initial_identity:(u32,u32,u32),attempted:bool,applied:bool,restored:bool,
}
impl SessionGrant {
    /// Only the broker can supply this identity, queried from its authenticated
    /// suspended helper. The fixed path is outside every writable root.
    pub fn prepare(identity_proof:&VerifiedSessionIdentity)->Result<Self>{unsafe{
        let owner_token=Handle::from_raw(token::get_current_token_for_restriction().map_err(|e|mapped("owner-token",e))?).map_err(|e|mapped("owner-token-handle",e))?;
        let owner_sid=token::get_user_sid_bytes(owner_token.raw()).map_err(|e|mapped("owner-sid",e))?;
        let owner_string=winutil::string_from_sid_bytes(&owner_sid).map_err(|_|bad("owner-sid-format"))?;
        if owner_string==identity_proof.account_sid || !identity_proof.logon_sid.starts_with("S-1-5-5-")
            || identity_proof.logon_sid==identity_proof.capability_sid{return Err(bad("verified-session-identity"));}
        let logon=token::LocalSid::from_string(&identity_proof.logon_sid).map_err(|e|mapped("logon-sid",e))?;
        let logon_bytes=sid_bytes(logon.as_ptr())?;
        let known=|s:&str|->Result<Vec<u8>>{let v=token::LocalSid::from_string(s).map_err(|e|mapped("known-role",e))?;sid_bytes(v.as_ptr())};
        let admin_sid=known("S-1-5-32-544")?;let system_sid=known("S-1-5-18")?;let users_sid=known("S-1-5-32-545")?;
        let mut ancestors=Vec::new();for p in [r"C:\",r"C:\PiSandboxLab",r"C:\PiSandboxLab\fixtures"]{
            ancestors.push(nr::open_directory_no_reparse(Path::new(p),FILE_TRAVERSE,FILE_SHARE_READ|FILE_SHARE_WRITE,nr::DirectoryOpenDisposition::OpenExisting).map_err(|e|mapped("pin-ancestor",e))?);
        }
        let leaf=nr::open_directory_no_reparse(Path::new(OUTSIDE_LOGON),READ_CONTROL|WRITE_DAC|FILE_READ_ATTRIBUTES|FILE_TRAVERSE,
            FILE_SHARE_READ|FILE_SHARE_WRITE,nr::DirectoryOpenDisposition::OpenExisting).map_err(|e|mapped("pin-fixed-leaf",e))?;
        let initial_identity=identity(leaf.as_raw_handle() as isize)?;
        let original=snapshot(leaf.as_raw_handle() as isize)?;
        if original.owner!=admin_sid && original.owner!=owner_sid{return Err(bad("trusted-leaf-owner"));}
        for a in &original.aces{
            if a.sid==owner_sid || a.sid==admin_sid || a.sid==system_sid{continue;}
            if a.sid==users_sid && a.mask & !(FILE_GENERIC_READ|FILE_GENERIC_EXECUTE)==0{continue;}
            return Err(bad("initial-leaf-trustees"));
        }
        if std::fs::read_dir(OUTSIDE_LOGON).map_err(|e|GrantError{stage:"fresh-leaf-enumeration",winerror:e.raw_os_error().and_then(|n|u32::try_from(n).ok())})?.next().is_some(){return Err(bad("fresh-empty-logon-leaf-required"));}
        let guard=nr::create_directory_guard(leaf.as_handle()).map_err(|e|mapped("leaf-reparse-guard",e))?;
        let post=nr::open_directory_no_reparse(Path::new(OUTSIDE_LOGON),FILE_TRAVERSE|FILE_READ_ATTRIBUTES,FILE_SHARE_READ|FILE_SHARE_WRITE,
            nr::DirectoryOpenDisposition::OpenExisting).map_err(|e|mapped("post-guard-pin",e))?;
        if identity(post.as_raw_handle() as isize)?!=initial_identity{return Err(bad("leaf-identity-changed"));}ancestors.push(post);
        Ok(Self{leaf,_ancestors:ancestors,_guard:guard,original,owner_sid,admin_sid,system_sid,users_sid,logon,logon_bytes,
            initial_identity,attempted:false,applied:false,restored:false})
    }}
    pub fn apply(&mut self)->Result<()>{unsafe{
        if self.attempted{return Err(bad("single-grant-attempt"));}
        let current=snapshot(self.leaf.as_raw_handle() as isize)?;
        if current.owner!=self.original.owner || current.protected!=self.original.protected || current.aces!=self.original.aces{return Err(bad("leaf-preimage-changed"));}
        let entry=EXPLICIT_ACCESS_W{grfAccessPermissions:MODIFY,grfAccessMode:GRANT_ACCESS,grfInheritance:INHERIT as u32,
            Trustee:TRUSTEE_W{pMultipleTrustee:null_mut(),MultipleTrusteeOperation:0,TrusteeForm:TRUSTEE_IS_SID,
                TrusteeType:TRUSTEE_IS_UNKNOWN,ptstrName:self.logon.as_ptr().cast()}};
        let mut updated=null_mut();let code=SetEntriesInAclW(1,&entry,current.dacl,&mut updated);
        if code!=0{return Err(GrantError{stage:"build-exact-logon-grant",winerror:Some(code)});}
        self.attempted=true;
        let code=SetSecurityInfo(self.leaf.as_raw_handle() as isize,SE_FILE_OBJECT,DACL_SECURITY_INFORMATION,
            null_mut(),null_mut(),updated,null_mut());LocalFree(updated as HLOCAL);
        if code!=0{return Err(GrantError{stage:"apply-exact-logon-grant",winerror:Some(code)});}
        let after=snapshot(self.leaf.as_raw_handle() as isize)?;
        let grants=after.aces.iter().filter(|a|a.sid==self.logon_bytes).collect::<Vec<_>>();
        let others=after.aces.iter().filter(|a|a.sid!=self.logon_bytes).cloned().collect::<Vec<_>>();
        if after.owner!=self.original.owner || after.protected!=self.original.protected || grants.len()!=1
            || grants[0].mask!=MODIFY || grants[0].flags!=INHERIT || others!=self.original.aces{return Err(bad("exact-logon-grant-readback"));}
        self.applied=true;Ok(())
    }}
    pub fn is_applied(&self)->bool{self.applied && !self.restored}
    /// Call only after the trusted broker proves inner/outer process-tree death.
    /// Restores this leaf DACL only. There is deliberately no mutating Drop path.
    pub unsafe fn restore_after_verified_cleanup(&mut self)->Result<()>{
        if !self.applied || self.restored{return Err(bad("verified-grant-required-for-restore"));}
        if identity(self.leaf.as_raw_handle() as isize)?!=self.initial_identity{return Err(bad("restore-leaf-identity"));}
        let protection=if self.original.protected{PROTECTED_DACL_SECURITY_INFORMATION}else{UNPROTECTED_DACL_SECURITY_INFORMATION};
        let code=SetSecurityInfo(self.leaf.as_raw_handle() as isize,SE_FILE_OBJECT,DACL_SECURITY_INFORMATION|protection,
            null_mut(),null_mut(),self.original.dacl,null_mut());
        if code!=0{return Err(GrantError{stage:"restore-original-leaf-dacl",winerror:Some(code)});}
        let after=snapshot(self.leaf.as_raw_handle() as isize)?;
        if after.owner!=self.original.owner || after.protected!=self.original.protected || after.aces!=self.original.aces{return Err(bad("restore-original-leaf-readback"));}
        self.restored=true;Ok(())
    }
    pub fn receipt(&self,status:&str,error:Option<&GrantError>)->serde_json::Value{
        let role=|sid:&Vec<u8>| if *sid==self.owner_sid{"OWNER"}else if *sid==self.admin_sid{"ADMINISTRATORS"}
            else if *sid==self.system_sid{"SYSTEM"}else if *sid==self.users_sid{"BUILTIN_USERS"}else if *sid==self.logon_bytes{"LOGON"}else{"OTHER"};
        let current=unsafe{snapshot(self.leaf.as_raw_handle() as isize)};
        let aces=current.as_ref().ok().map(|s|s.aces.iter().enumerate().map(|(index,a)|serde_json::json!({"index":index,"type":a.kind,
            "flags":a.flags,"mask":a.mask,"maskHex":format!("0x{:08x}",a.mask),"trusteeRole":role(&a.sid),"fileDeleteChild":a.mask&FILE_DELETE_CHILD!=0})).collect::<Vec<_>>());
        serde_json::json!({"schemaVersion":1,"target":"OUTSIDE_LOGON_DIR","status":status,
            "outsideWritableRoots":true,"authorizedException":true,"grantRole":"LOGON","grantMask":MODIFY,
            "attempted":self.attempted,"appliedVerified":self.applied,"originalLeafDaclRestored":self.restored,
            "originalLeafOwnerRole":role(&self.original.owner),"currentAces":aces,
            "error":error,"snapshotError":current.err(),"strictWorkspaceOnlyAcceptance":false,
            "cleanupScope":"leaf DACL only; child artifact ACL/ownership is not a production revocation guarantee; dispose the VM"})
    }
}
