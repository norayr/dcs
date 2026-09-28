unit Identities;

{$mode delphi}{$H+}

interface

{ Reads the identities dcs keeps on disk, so that logging in can be a name
  rather than a path.

  The layout is a directory of pairs named after the SHA256 fingerprint of the
  certificate, with a .crt and a .key file each.  pishmish keeps its identities
  this way, so a directory copied from one is picked up as it stands, but
  nothing here depends on that and any layout of pairs will do. }

type
  TIdentity = record
    { Lowercase hex, no separators, taken from the file name. }
    Fingerprint: string;
    CertFile: string;
    KeyFile: string;
    { Filled in where they could be read; empty otherwise. }
    CN: string;
    Mail: string;
    NotAfter: string;
  end;

  TIdentities = array of TIdentity;

  { Positions in a TIdentities, as given back by FindIdentity. }
  TIdentityIndexes = array of Integer;

{ Where identities are looked for.  Honours XDG_CONFIG_HOME. }
function DefaultIdentitiesDir: string;

{ Every identity pair in ADir.  A .crt without a matching .key is skipped,
  since a certificate alone cannot authenticate anything. }
function LoadIdentities(const ADir: string): TIdentities;

{ Index of the identity AQuery names, or -1 when it names none or names several.

  AQuery is matched against the fingerprint, then the common name, then the mail
  address, preferring the most exact kind of match.  ACandidates receives the
  indices the deciding kind of match found, so that an ambiguous query can be
  answered with the choices rather than just a refusal. }
function FindIdentity(const AIdentities: TIdentities; const AQuery: string;
  out ACandidates: TIdentityIndexes): Integer;

{ Fills in CN, Mail and NotAfter of AIdentity by reading its certificate.
  Returns False, leaving them empty, when they cannot be read. }
function ReadIdentityDetails(var AIdentity: TIdentity): Boolean;

implementation

uses
  SysUtils, Classes, StrUtils,
  {$IFDEF USE_TAURUS}
  TaurusTLS, TaurusTLS_X509, TaurusTLSHeaders_types, TaurusTLSHeaders_bio,
  TaurusTLSHeaders_pem, TaurusTLSHeaders_x509
  {$ELSE}
  IdSSLOpenSSL, IdSSLOpenSSLHeaders
  {$ENDIF};

function DefaultIdentitiesDir: string;
var
  Config: string;
begin
  Config := GetEnvironmentVariable('XDG_CONFIG_HOME');
  { Fall back to ~/.config when unset, or set to something not a path. }
  if (Config = '') or (Config[1] <> '/') then
    Config := IncludeTrailingPathDelimiter(GetEnvironmentVariable('HOME')) +
      '.config';
  Result := IncludeTrailingPathDelimiter(Config) + 'dcs' + PathDelim + 'idents';
end;

function LoadIdentities(const ADir: string): TIdentities;
var
  SR: TSearchRec;
  Count: Integer;
  Key: string;
begin
  Result := nil;
  Count := 0;
  { DirectoryExists, not FileExists: the latter is false for a directory on
    Linux, which would make the whole listing come up empty. }
  if (ADir = '') or (not DirectoryExists(ADir)) then
    Exit;
  if FindFirst(IncludeTrailingPathDelimiter(ADir) + '*.crt', faAnyFile, SR) = 0 then
  begin
    { For each .crt, the .key beside it. }
    repeat
      Key := IncludeTrailingPathDelimiter(ADir) + ChangeFileExt(SR.Name, '.key');
      if FileExists(Key) then
      begin
        SetLength(Result, Count + 1);
        Result[Count].Fingerprint := LowerCase(ChangeFileExt(SR.Name, ''));
        Result[Count].CertFile :=
          IncludeTrailingPathDelimiter(ADir) + SR.Name;
        Result[Count].KeyFile := Key;
        Inc(Count);
      end;
    until FindNext(SR) <> 0;
    FindClose(SR);
  end;

  { Read the subjects here rather than leaving it to callers, so that a caller
    matching on a mail address or a name has something to match against. }
  for Count := 0 to High(Result) do
    ReadIdentityDetails(Result[Count]);
end;

{ Case insensitive substring containment, so a mail or a name can be abbreviated
  as far as it stays unambiguous. }
function Contains(const AHaystack, ANeedle: string): Boolean;
begin
  Result := Pos(LowerCase(ANeedle), LowerCase(AHaystack)) > 0;
end;

function Same(const A, B: string): Boolean;
begin
  Result := SameText(A, B);
end;

{ Index of the identity AQuery names, or -1 when it names none.

  Several certificates can share a mail address, and guessing between them
  would mean logging in as somebody unexpected, so the most specific kind of
  match wins and a still ambiguous query is refused rather than resolved.

  A fingerprint prefix is checked first, since only one certificate can start
  that way.  Then an exact common name, which comes before an exact mail
  address because on a board the common name is the account: matching a user
  name should find the certificate whose common name is that, not one of several
  that merely share an address.  Failing those, any containing match will do, as
  long as exactly one identity matches.

  ACount receives the number of candidates considered, so a caller can tell
  "none" from "several": a result of -1 with a count above one means the query
  was ambiguous. }
type
  TMatchKind = (mkFingerprint, mkCommonName, mkMail, mkContains);

function Matches(const A: TIdentity; AQuery: string; AKind: TMatchKind): Boolean;
begin
  case AKind of
    mkFingerprint: Result := StartsText(AQuery, A.Fingerprint);
    mkCommonName: Result := Same(A.CN, AQuery);
    mkMail: Result := Same(A.Mail, AQuery);
    mkContains: Result := Contains(A.CN, AQuery) or Contains(A.Mail, AQuery);
  else
    Result := False;
  end;
end;

{ Index of the identity AQuery names, or -1 when it names none or names several.

  ACandidates receives the indices the deciding kind of match found, so that an
  ambiguous query can be answered with the choices rather than just a refusal. }
function FindIdentity(const AIdentities: TIdentities; const AQuery: string;
  out ACandidates: TIdentityIndexes): Integer;
var
  Kind: TMatchKind;
  I: Integer;
begin
  ACandidates := nil;
  Result := -1;
  if AQuery = '' then
    Exit;

  { Each kind is tried in turn, from most specific to least, and the first
    kind that matches anything is the one that decides.  A fingerprint, or the
    start of one, can only mean a single certificate; an exact common name
    comes before an exact mail address because on a board the common name is
    the account; and a merely containing match has to leave no choice. }
  for Kind := Low(TMatchKind) to High(TMatchKind) do
  begin
    ACandidates := nil;
    for I := 0 to High(AIdentities) do
      if Matches(AIdentities[I], AQuery, Kind) then
        ACandidates := ACandidates + [I];
    if Length(ACandidates) = 0 then
      Continue;
    { One match is the identity.  Several are left for the caller to show,
      since picking one would mean logging in as whichever was read first. }
    if Length(ACandidates) = 1 then
      Result := ACandidates[0];
    Exit;
  end;
end;

{$IFDEF USE_TAURUS}

{ Reads the subject and expiry out of a PEM certificate.  The certificate is
  only ever inspected, never presented, so the returned X509 is freed again
  straight away. }
function ReadIdentityDetails(var AIdentity: TIdentity): Boolean;
var
  Bio: PBIO;
  Raw: PX509;
  Cert: TTaurusTLSX509;
  Data: TMemoryStream;
  LYear, LMonth, LDay: Word;
begin
  Result := False;
  AIdentity.CN := '';
  AIdentity.Mail := '';
  AIdentity.NotAfter := '';
  if not FileExists(AIdentity.CertFile) then
    Exit;

  { The OpenSSL library is loaded lazily, when a connection first needs it.
    Reading a certificate here happens before any connection, so ask for the
    library first or the calls below jump through nothing. }
  if not LoadOpenSSLLibrary then
    Exit;

  Data := nil;
  Bio := nil;
  Raw := nil;
  Cert := nil;
  try
    try
      Data := TMemoryStream.Create;
      Data.LoadFromFile(AIdentity.CertFile);
    except
      Data.Free;
      Data := nil;
      Exit;
    end;

    Bio := BIO_new_mem_buf(Data.Memory^, Data.Size);
    if Bio = nil then
      Exit;
    Raw := PEM_read_bio_X509(Bio, nil, nil, nil);
    if Raw = nil then
      Exit;

    Cert := TTaurusTLSX509.Create(Raw, False);
    try
      AIdentity.CN := Cert.Subject.CommonName;
      AIdentity.Mail := Cert.Subject.EMail;
      { DecodeDate rather than FormatDateTime: this FPC's date formatting
        rejects the value outright when the library decodes an odd time, and the
        expiry is only there to be read by a person. }
      try
        DecodeDate(Cert.notAfter, LYear, LMonth, LDay);
        AIdentity.NotAfter := Format('%.4d-%.2d-%.2d', [LYear, LMonth, LDay]);
      except
        AIdentity.NotAfter := '';
      end;
      Result := True;
    finally
      Cert.Free;
    end;
  finally
    if Raw <> nil then
      X509_free(Raw);
    if Bio <> nil then
      BIO_free(Bio);
    Data.Free;
  end;
end;

{$ELSE}

{ The Indy build has no X509 wrapper, so the details are simply left empty and
  identities can still be selected by fingerprint. }
function ReadIdentityDetails(var AIdentity: TIdentity): Boolean;
begin
  AIdentity.CN := '';
  AIdentity.Mail := '';
  AIdentity.NotAfter := '';
  Result := False;
end;

{$ENDIF}

end.
