//! Two explicit default-off lab profiles: capability-only with upstream default
//! object DACL, then capability plus the actual helper Logon SID with that DACL.
//! No product selector, account/Everyone restricting SID, privilege or launch change.
use super::*;
use crate::python_isolation::{CandidateTokenConfiguration, DefaultDaclAce, DefaultDaclRole};
use windows_sys::Win32::Security::{GetAce,IsValidAcl,EqualSid,ACE_HEADER,ACCESS_ALLOWED_ACE};

/// # Safety
/// Caller is the authenticated fixed lab helper, with a fresh dedicated-account
/// base token and its sole admitted capability. Execute only the fixed candidate
/// cases, after every unchanged control has been durably recorded and acknowledged.
pub(crate) unsafe fn create_lab_policy_repair_token_from(
    base: HANDLE, capability: *mut c_void,
) -> Result<(HANDLE,CandidateTokenConfiguration)> {
    let derived=create_strict_write_token_from(base,&[capability])?;
    let verification=(|| -> Result<CandidateTokenConfiguration> {
        let mut logon=get_logon_sid_bytes(base)?;
        // Changes ONLY TokenDefaultDacl on this new derivative. The strict
        // constructor already fixed flags, privileges and capability-only SIDs.
        set_default_dacl(derived,logon.as_mut_ptr().cast(),&[])?;
        let restricting_sids=crate::python_isolation::observer::restricting_sids(derived)?;
        ensure!(IsValidSid(capability) != 0,"candidate capability SID invalid");
        let capability_string=crate::winutil::string_from_sid_bytes(std::slice::from_raw_parts(
            capability.cast::<u8>(),windows_sys::Win32::Security::GetLengthSid(capability) as usize)).map_err(anyhow::Error::msg)?;
        let default_dacl_aces=read_default_dacl(derived,logon.as_mut_ptr().cast())?;
        let result=CandidateTokenConfiguration {profile:"CAP_ONLY_UPSTREAM_DEFAULT_DACL_V1".into(),
            restricting_sids,default_dacl_aces};
        ensure!(result.matches_capability(&capability_string),"candidate token configuration readback mismatch");
        Ok(result)
    })();
    match verification { Ok(configuration)=>Ok((derived,configuration)),Err(error)=>{CloseHandle(derived);Err(error)} }
}
unsafe fn read_default_dacl(token: HANDLE,logon: *mut c_void) -> Result<Vec<DefaultDaclAce>> {
    let owner_rights=LocalSid::from_string("S-1-3-4")?;
    let mut needed=0;
    GetTokenInformation(token,TokenDefaultDacl,std::ptr::null_mut(),0,&mut needed);
    let size_error=GetLastError();
    ensure!(needed as usize >= std::mem::size_of::<TokenDefaultDaclInfo>() && needed <= 65536,
        "candidate default-DACL query bounds: win32={size_error}");
    let mut buffer=vec![0usize;(needed as usize+std::mem::size_of::<usize>()-1)/std::mem::size_of::<usize>()];
    if GetTokenInformation(token,TokenDefaultDacl,buffer.as_mut_ptr().cast(),needed,&mut needed) == 0 {
        let code=GetLastError();anyhow::bail!("candidate GetTokenInformation(TokenDefaultDacl): win32={code}");
    }
    ensure!(needed as usize <= buffer.len()*std::mem::size_of::<usize>(),"candidate default-DACL returned bounds");
    let descriptor=std::ptr::read_unaligned(buffer.as_ptr().cast::<TokenDefaultDaclInfo>());
    let lower=buffer.as_ptr() as usize;let upper=lower+needed as usize;
    let start=descriptor.default_dacl as usize;
    ensure!(start >= lower && start.checked_add(std::mem::size_of::<ACL>()).is_some_and(|n|n<=upper),
        "candidate default-DACL pointer bounds");
    let size=(*descriptor.default_dacl).AclSize as usize;
    ensure!(size >= std::mem::size_of::<ACL>() && start.checked_add(size).is_some_and(|n|n<=upper),
        "candidate default-DACL length bounds");
    ensure!(IsValidAcl(descriptor.default_dacl) != 0 && (*descriptor.default_dacl).AceCount == 2,
        "candidate default-DACL must contain exactly two valid ACEs");
    let mut result=Vec::new();
    for index in 0..2 {
        let mut raw=std::ptr::null_mut();
        if GetAce(descriptor.default_dacl,index,&mut raw) == 0 {
            let code=GetLastError();anyhow::bail!("candidate GetAce: win32={code}");
        }
        let address=raw as usize;
        ensure!(address>=start && address.checked_add(16).is_some_and(|n|n<=start+size),"candidate ACE pointer bounds");
        let header=&*(raw.cast::<ACE_HEADER>());
        ensure!(header.AceType == 0 && header.AceFlags == 0 && header.AceSize >= 16
            && address.checked_add(header.AceSize as usize).is_some_and(|n|n<=start+size),"candidate ACE shape mismatch");
        let ace=&*(raw.cast::<ACCESS_ALLOWED_ACE>());
        let sid=std::ptr::addr_of!(ace.SidStart).cast_mut().cast::<c_void>();
        let length=8+4*usize::from(*sid.cast::<u8>().add(1));
        ensure!(8+length <= header.AceSize as usize && IsValidSid(sid) != 0,"candidate ACE SID bounds");
        let role=if EqualSid(sid,logon) != 0 {DefaultDaclRole::Logon}
            else if EqualSid(sid,owner_rights.as_ptr()) != 0 {DefaultDaclRole::OwnerRights}
            else {anyhow::bail!("candidate default-DACL contains unexpected principal")};
        result.push(DefaultDaclAce {role,mask:ace.Mask,flags:header.AceFlags});
    }
    Ok(result)
}

#[cfg(feature="lab-python-logon-sid-comparison")]
pub(crate) unsafe fn create_lab_logon_session_token_from(base:HANDLE,capability:*mut c_void)
    -> Result<(HANDLE,crate::python_isolation::SessionTokenConfiguration)> {
    // Never derive this from the already restricted strict/candidate/pinned token.
    let base_sids=crate::python_isolation::observer::restricting_sids(base)?;
    ensure!(base_sids.is_empty(),"session comparison requires original unrestricted helper base");
    let mut logon=get_logon_sid_bytes(base)?;
    let logon_ptr=logon.as_mut_ptr().cast();
    let derived=create_token_with_caps_impl(base,&[capability],&[logon_ptr],false)?;
    let verified=(|| -> Result<crate::python_isolation::SessionTokenConfiguration> {
        set_default_dacl(derived,logon_ptr,&[])?;
        let result=crate::python_isolation::SessionTokenConfiguration {
            profile:"CAP_PLUS_ACTUAL_LOGON_UPSTREAM_DEFAULT_DACL_V1".into(),base_restricting_sid_count:0,
            actual_logon_sid:crate::winutil::string_from_sid_bytes(&logon).map_err(anyhow::Error::msg)?,
            restricting_sids:crate::python_isolation::observer::restricting_sids(derived)?,
            default_dacl_aces:read_default_dacl(derived,logon_ptr)?,
        };
        ensure!(IsValidSid(capability) != 0,"session capability SID invalid");
        let cap=crate::winutil::string_from_sid_bytes(std::slice::from_raw_parts(capability.cast(),
            windows_sys::Win32::Security::GetLengthSid(capability) as usize)).map_err(anyhow::Error::msg)?;
        ensure!(result.matches_capability(&cap),"session token exact readback mismatch");Ok(result)
    })();
    match verified {Ok(config)=>Ok((derived,config)),Err(error)=>{CloseHandle(derived);Err(error)}}
}
