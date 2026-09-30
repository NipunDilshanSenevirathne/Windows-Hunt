// symlink / junction primitive skeleton — arbitrary file write or delete AS SYSTEM
//
// Class: a privileged process writes/deletes a path under a directory the user controls
// (typically C:\ProgramData\<app>\... or %TEMP%). Redirect that path with an NTFS junction
// plus an object-manager symlink and the privileged write lands wherever you choose.
//
// This is a SKELETON, not a weapon: it sets up the redirection and records where the
// privileged write actually landed. It does not place a payload.
//
// The mature primitives live in James Forshaw's symboliclink-testing-tools
// (CreateMountPoint / CreateSymlink / SetOpLock / BaitAndSwitch). Use those in the VM; this
// file documents the exact sequence for the report so a triager can follow it.
//
//   1. Confirm the privileged write:      Procmon → Operation is CreateFile/WriteFile,
//                                          Result SUCCESS, Integrity System,
//                                          Path under the user-writable directory.
//   2. Empty the directory and replace it with a junction:
//        CreateMountPoint.exe C:\ProgramData\Target\work \RPC Control
//   3. Add the object-manager symlink from the file name the service uses to your target:
//        CreateSymlink.exe \RPC Control\config.dat \??\C:\Windows\System32\wh_proof.txt
//   4. Trigger the privileged operation (service restart, update check, scheduled task).
//   5. Prove it: the target file now contains your content, written by SYSTEM.
//
// RACE variant: if the service writes then ACLs, or checks then opens (TOCTOU), hold an
// oplock on the first access (SetOpLock.exe) and swap the directory inside the window.
//
// Report what you measured: the exact Procmon line, the token of the writing process, and
// the resulting file with its new owner.
