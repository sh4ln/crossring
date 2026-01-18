; CROSSRING Installer Script for Inno Setup
; Download Inno Setup from https://jrsoftware.org/isdl.php

#define MyAppName "CROSSRING"
#define MyAppVersion "1.0.0"
#define MyAppPublisher "CROSSRING Security"
#define MyAppURL "https://github.com/Shxlnh/crossring"
#define MyAppExeName "CrossringUI.exe"
#define MyServiceName "CrossringService.exe"

[Setup]
AppId={{A1B2C3D4-E5F6-7890-ABCD-CROSSRING0001}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
AllowNoIcons=yes
LicenseFile=LICENSE.txt
OutputDir=installer_output
OutputBaseFilename=CrossringSetup
SetupIconFile=CrossringUI\Resources\icon.ico
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64
UninstallDisplayIcon={app}\{#MyAppExeName}

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked
Name: "startupicon"; Description: "Start with Windows"; GroupDescription: "{cm:AdditionalIcons}"

[Files]
; Main application files
Source: "bin\Release\{#MyAppExeName}"; DestDir: "{app}"; Flags: ignoreversion
Source: "bin\Release\{#MyServiceName}"; DestDir: "{app}"; Flags: ignoreversion
Source: "bin\Release\*.dll"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs

; Data directory (created at runtime)
; ProgramData will be used for database and logs

[Dirs]
Name: "{commonappdata}\CROSSRING"; Permissions: everyone-full
Name: "{commonappdata}\CROSSRING\logs"; Permissions: everyone-full

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{group}\{cm:UninstallProgram,{#MyAppName}}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon
Name: "{userstartup}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: startupicon

[Run]
; Install and start the service
Filename: "{app}\{#MyServiceName}"; Parameters: "/install"; Flags: runhidden waituntilterminated; StatusMsg: "Installing CROSSRING Service..."
Filename: "sc"; Parameters: "start CrossringService"; Flags: runhidden; StatusMsg: "Starting CROSSRING Service..."
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent

[UninstallRun]
; Stop and uninstall the service
Filename: "sc"; Parameters: "stop CrossringService"; Flags: runhidden
Filename: "{app}\{#MyServiceName}"; Parameters: "/uninstall"; Flags: runhidden waituntilterminated

[Code]
function InitializeSetup(): Boolean;
begin
  Result := True;
  // Could add .NET check here if needed
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
  begin
    // Create restore point
    // Could add additional post-install tasks here
  end;
end;
