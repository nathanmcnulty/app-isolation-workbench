function Get-AiwPackageProcessInventory {
 $all=@(Get-Process)
 if($all.Count -gt 512){throw 'Research process inventory bound exceeded'}
 $matches=@();$errors=@();$exited=@();$nonPackageImageUnavailable=@()
 foreach($process in $all){
  # PID 0 and 4 are reserved kernel processes, not package applications.
  if($process.Id -eq 0 -or $process.Id -eq 4){continue}
  try{
   $observed=[AiwMsixNative]::Inspect([uint32]$process.Id)
   if($null -ne $observed.ImageQueryError){
    # Native NO_PACKAGE is positive package-identity evidence, not image absence.
    # Preserve the narrower query scope; a named application candidate still fails.
    $nonPackageImageUnavailable+= [pscustomobject]@{Pid=$observed.Pid;Name=$process.ProcessName;SessionId=$observed.SessionId;PackageIdentityStatus=$observed.PackageIdentityStatus;PackageFullName=$observed.PackageFullName;ImagePath=$observed.ImagePath;ImageQueryError=$observed.ImageQueryError}
    if($process.ProcessName -ceq 'notepad++'){$errors+= [pscustomobject]@{pid=$process.Id;name=$process.ProcessName;error='Named application image query failed';nativeError=$observed.ImageQueryError}}
   }
   if($observed.PackageFullName -ceq 'AIWResearch.NotepadPP_8.9.8.0_x64__q1fhfzcjv9wt6' -or $process.ProcessName -ceq 'notepad++' -or $observed.ImagePath -match '\\AIWResearch\.NotepadPP_8\.9\.8\.0_x64__q1fhfzcjv9wt6\\'){$matches+= $observed}
  }catch{
   $queryError=$_.Exception.Message
   if(@(Get-Process -Id $process.Id -ErrorAction SilentlyContinue).Count -eq 0){$exited+= $process.Id}else{$errors+= [pscustomobject]@{pid=$process.Id;name=$process.ProcessName;error=$queryError}}
  }finally{$process.Dispose()}
 }
 return [pscustomobject]@{matches=$matches;queryErrors=$errors;nonPackageImageUnavailable=$nonPackageImageUnavailable;exitedDuringQuery=$exited;processesScanned=$all.Count;excludedReservedPids=@(0,4)}
}
