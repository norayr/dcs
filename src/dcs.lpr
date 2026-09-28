program dcs;

{ dcs - a command line Gemini client.

    dcs <url> [input]                 fetch and print
    dcs --fingerprint <url>           print the server's SHA256 fingerprint
    dcs --pin <sha256> <url> [input]  fetch, trusting only that certificate
    dcs --ident <who> <url> [input]   fetch, presenting an identity
    dcs --cert <file> --key <file>    same, with explicit paths
    dcs --idents                      list the identities found on this machine

  An identity is a client certificate.  Servers that care who you are answer
  60 certificate required, and you identify yourself by presenting a
  certificate; no password is involved.  --ident looks the certificate up among
  the ones a graphical Gemini client keeps, matching on mail address, then on
  common name, then on the start of the fingerprint.

  The TLS backend is fixed at compile time: build with USE_TAURUS=1 for TLS 1.3
  via TaurusTLS, or USE_TAURUS=0 for Indy's own OpenSSL handler.

  Certificates are not verified by default, since servers under test use
  self-signed ones.  Use --pin to require a specific fingerprint instead. }

{$mode delphi}{$H+}

uses
  {$IFDEF UNIX}
  cthreads,
  {$ENDIF}
  SysUtils, Classes, GemClient, Identities;

{ One label column for the whole output, so that the values line up and a
  transcript reads as a table.  The longest label is identity, at eight. }
const
  LABEL_IDENTITY = 'identity: ';
  LABEL_URL = 'url:      ';
  LABEL_STATUS = 'status:   ';
  LABEL_META = 'meta:     ';
  LABEL_ERROR = 'error:    ';
  LABEL_WROTE = 'wrote:    ';

{ Whether a byte can be shown as itself.  Newline and tab qualify: they are
  ordinary text, and a line break in gemtext is the point of it. }
function Showable(C: Byte): Boolean;
begin
  Result := ((C >= 32) and (C <> 127)) or (C = 10) or (C = 9);
end;

{ The body, ready to print.

  Everything is passed through as it arrived: line breaks stay line breaks, so
  that gemtext reads as gemtext, and the bytes of a UTF-8 character are left
  alone, so that a terminal shows an emoji as an emoji.  Turning a character
  into four \x escapes loses nothing that a reader could use and costs them the
  one thing they wanted, which is to read the text.

  What is escaped is only what a terminal cannot show without being confused by
  it: carriage return, which would overwrite the line it is on, and the
  remaining C0 controls and delete, which have no glyphs at all. }
function ForDisplay(const S: string): string;
const
  Digits = '0123456789abcdef';
var
  I: Integer;
  RunStart: Integer;
  C: Byte;
begin
  Result := '';
  I := 1;
  while I <= Length(S) do
  begin
    C := Byte(S[I]);
    if Showable(C) then
    begin
      { Take the whole run of showable bytes at once, so that a long body is
        copied in chunks rather than a character at a time. }
      RunStart := I;
      Inc(I);
      while I <= Length(S) do
      begin
        C := Byte(S[I]);
        if not Showable(C) then
          Break;
        Inc(I);
      end;
      AppendStr(Result, Copy(S, RunStart, I - RunStart));
    end
    else
    begin
      if C = 13 then
        AppendStr(Result, '\r')
      else
      begin
        AppendStr(Result, '\x');
        { Indexed from one: in this dialect a string's [0] is the byte before
          the data, which is the length, not the first character. }
        AppendStr(Result, Digits[C shr 4 + 1]);
        AppendStr(Result, Digits[C and $0F + 1]);
      end;
      Inc(I);
    end;
  end;
end;

{ Writes the body to a file exactly as it arrived: no escaping, no newline
  translation, so that the file is a real gemtext or a real image rather than a
  description of one. }
function TryWriteWholeFile(const AFileName: string; const AContent: string): Boolean;
var
  F: TFileStream;
begin
  Result := False;
  try
    F := TFileStream.Create(AFileName, fmCreate);
  except
    Exit;
  end;
  try
    if Length(AContent) > 0 then
      F.WriteBuffer(AContent[1], Length(AContent));
    Result := True;
  finally
    F.Free;
  end;
end;

{ Whether input is expected at all, since an empty argument is still an
  argument. }
function HasArg(Index: Integer): Boolean;
begin
  Result := Index <= ParamCount;
end;

procedure Usage;
begin
  WriteLn('usage: dcs [options] <url> [input]');
  WriteLn;
  WriteLn('  --ident <cn|mail|fingerprint>  log in with an identity');
  WriteLn('  --cert <file> --key <file>     log in with a certificate pair');
  WriteLn('  --input <file>                 input from a file, or from');
  WriteLn('                                 standard input when named "-"');
  WriteLn('  --output <file>                save the body to a file, as it');
  WriteLn('                                 arrived, instead of printing it');
  WriteLn('  --pin <sha256>                 require this server certificate');
  WriteLn('  --fingerprint                  print the server certificate');
  WriteLn('                                 fingerprint and stop');
  WriteLn('  --idents                       list the identities available');
  WriteLn;
  WriteLn('Identities are the certificate and key pairs under');
  WriteLn('  ', DefaultIdentitiesDir);
end;

{ The request line, the status and the metadata: everything a transcript
  needs before the body starts. }
procedure ReportHead(const AURL: string; AStatus: Integer; const AMeta: string);
begin
  WriteLn(LABEL_URL, AURL);
  WriteLn(LABEL_STATUS, AStatus, '  ', GemStatusName(AStatus));
  WriteLn(LABEL_META, '"', AMeta, '"');
end;

procedure Report(const AURL, AError: string; AStatus: Integer; const AMeta,
  ABody: string);
begin
  if AError <> '' then
  begin
    WriteLn(LABEL_URL, AURL);
    WriteLn(LABEL_ERROR, AError);
    Exit;
  end;
  ReportHead(AURL, AStatus, AMeta);
  { No label for the body: with real line breaks in it, anything written here
    would be a line of gemtext that is not really gemtext. }
  if ABody <> '' then
  begin
    WriteLn;
    Write(ForDisplay(ABody));
    if ABody[Length(ABody)] <> #10 then
      WriteLn;
  end;
end;

{ Reports the identities available, so that --ident can be used with something
  that is actually there. }
procedure DescribeIdentity(I: Integer; const AIdentities: TIdentities);
var
  Person: string;
begin
  Person := AIdentities[I].CN;
  if AIdentities[I].Mail <> '' then
    if Person <> '' then
      Person := Person + ' <' + AIdentities[I].Mail + '>'
    else
      Person := AIdentities[I].Mail;
  if Person = '' then
    Person := '(no subject)';
  Write('  ', Copy(AIdentities[I].Fingerprint, 1, 16), '  ', Person);
  { A far off expiry does not survive the conversion to a date, and saying
    "until" with nothing after it helps nobody. }
  if AIdentities[I].NotAfter <> '' then
    Write('  until ', AIdentities[I].NotAfter);
  WriteLn;
end;

procedure ListIdentities;
var
  Idents: TIdentities;
  I: Integer;
begin
  Idents := LoadIdentities(DefaultIdentitiesDir);
  if Length(Idents) = 0 then
  begin
    WriteLn('no identities in ', DefaultIdentitiesDir);
    Exit;
  end;
  WriteLn('identities in ', DefaultIdentitiesDir, ':');
  for I := 0 to High(Idents) do
    DescribeIdentity(I, Idents);
end;

{ Everything a stream holds, as one string with newlines and all, so that a post
  is not reshaped on the way out. }
function ReadAll(AStream: TStream): string;
var
  Chunk: array[0..4095] of Byte;
  Got: Integer;
  Total: Integer;
begin
  Total := 0;
  repeat
    Got := AStream.Read(Chunk[0], SizeOf(Chunk));
    if Got > 0 then
    begin
      SetLength(Result, Total + Got);
      Move(Chunk[0], Result[Total + 1], Got);
      Inc(Total, Got);
    end;
  until Got < SizeOf(Chunk);
  SetLength(Result, Total);
end;

{ A whole file as one string.  A file that is there but cannot be opened is an
  error rather than an empty post, which would otherwise post silently. }
function TryReadWholeFile(const AFileName: string; out AContent: string): Boolean;
var
  F: TFileStream;
begin
  AContent := '';
  Result := False;
  if not FileExists(AFileName) then
    Exit;
  try
    F := TFileStream.Create(AFileName, fmOpenRead or fmShareDenyNone);
  except
    Exit;
  end;
  try
    AContent := ReadAll(F);
    Result := True;
  finally
    F.Free;
  end;
end;

{ Everything on standard input, which is how a post is piped in.  Handle 0 is
  the stream the shell hands over, on every platform FPC builds for. }
function ReadFromStandardInput: string;
var
  F: THandleStream;
begin
  F := THandleStream.Create(THandle(0));
  try
    Result := ReadAll(F);
  finally
    F.Free;
  end;
end;

{ Fills AOptions from --ident, or from an explicit --cert and --key. }
procedure ApplyIdentity(const AWho, ACertFile, AKeyFile: string;
  AOptions: TGemOptions);
var
  Idents: TIdentities;
  Index: Integer;
  I: Integer;
  Candidates: TIdentityIndexes;
begin
  if AWho <> '' then
  begin
    Idents := LoadIdentities(DefaultIdentitiesDir);
    if Length(Idents) = 0 then
    begin
      WriteLn('error:  no identities in ', DefaultIdentitiesDir);
      Halt(1);
    end;
    Index := FindIdentity(Idents, AWho, Candidates);
    if Index < 0 then
    begin
      if Length(Candidates) > 1 then
        WriteLn('error:  "', AWho, '" matches ', Length(Candidates),
          ' identities, so it is not clear which one to log in as:')
      else
        WriteLn('error:  no identity matches "', AWho, '"');
      for I := 0 to High(Candidates) do
        DescribeIdentity(Candidates[I], Idents);
      WriteLn('        name one of the above by its fingerprint');
      Halt(1);
    end;
    AOptions.CertFile := Idents[Index].CertFile;
    AOptions.KeyFile := Idents[Index].KeyFile;
    WriteLn(LABEL_IDENTITY, Idents[Index].CN, ' <', Idents[Index].Mail, '>');
  end;

  if ACertFile <> '' then
    AOptions.CertFile := ACertFile;
  if AKeyFile <> '' then
    AOptions.KeyFile := AKeyFile;

  if (AOptions.CertFile = '') <> (AOptions.KeyFile = '') then
  begin
    WriteLn('error:  an identity needs both a certificate and a key');
    Halt(1);
  end;
  if AOptions.CertFile <> '' then
  begin
    if not FileExists(AOptions.CertFile) then
    begin
      WriteLn('error:  no such certificate: ', AOptions.CertFile);
      Halt(1);
    end;
    if not FileExists(AOptions.KeyFile) then
    begin
      WriteLn('error:  no such key: ', AOptions.KeyFile);
      Halt(1);
    end;
  end;
end;

var
  URL: string;
  InputText: string;
  Status: Integer;
  Meta: string;
  Body: string;
  ErrMsg: string;
  Fingerprint: string;
  Who: string;
  CertFile: string;
  KeyFile: string;
  InputFile: string;
  OutputFile: string;
  Options_: TGemOptions;
  Pins: TTrustedCerts;
  Pos_: Integer;
  First: Integer;
  Ok: Boolean;
  WantFingerprint: Boolean;
  WantIdents: Boolean;
begin
  if ParamCount < 1 then
  begin
    Usage;
    Halt(1);
  end;

  Options_ := TGemOptions.Create;
  First := 1;
  WantFingerprint := False;
  WantIdents := False;

  { Options may appear in any order before the URL, and each one consumes only
    itself and its value: the URL and any input stay positional.  Input, being
    positional too, is whatever is left over and so is taken last. }
  Pos_ := 1;
  while Pos_ <= ParamCount do
  begin
    if SameText(ParamStr(Pos_), '--fingerprint') then
    begin
      WantFingerprint := True;
      Inc(Pos_);
    end
    else if SameText(ParamStr(Pos_), '--pin') and HasArg(Pos_ + 1) then
    begin
      { Trusted is a property, so the array has to be built before assigning. }
      SetLength(Pins, 1);
      Pins[0] := ParamStr(Pos_ + 1);
      Options_.Trusted := Pins;
      Inc(Pos_, 2);
    end
    else if SameText(ParamStr(Pos_), '--ident') and HasArg(Pos_ + 1) then
    begin
      Who := ParamStr(Pos_ + 1);
      Inc(Pos_, 2);
    end
    else if SameText(ParamStr(Pos_), '--cert') and HasArg(Pos_ + 1) then
    begin
      CertFile := ParamStr(Pos_ + 1);
      Inc(Pos_, 2);
    end
    else if SameText(ParamStr(Pos_), '--key') and HasArg(Pos_ + 1) then
    begin
      KeyFile := ParamStr(Pos_ + 1);
      Inc(Pos_, 2);
    end
    else if SameText(ParamStr(Pos_), '--input') and HasArg(Pos_ + 1) then
    begin
      InputFile := ParamStr(Pos_ + 1);
      Inc(Pos_, 2);
    end
    else if SameText(ParamStr(Pos_), '--output') and HasArg(Pos_ + 1) then
    begin
      OutputFile := ParamStr(Pos_ + 1);
      Inc(Pos_, 2);
    end
    else if SameText(ParamStr(Pos_), '--idents') then
    begin
      WantIdents := True;
      Inc(Pos_);
    end
    else if SameText(ParamStr(Pos_), '--help') or SameText(ParamStr(Pos_), '-h') then
    begin
      Usage;
      Halt(0);
    end
    else
      break;
  end;
  First := Pos_;

  if WantIdents then
  begin
    ListIdentities;
    Halt(0);
  end;

  if First > ParamCount then
  begin
    Usage;
    Halt(1);
  end;

  URL := ParamStr(First);
  if InputFile <> '' then
  begin
    { Input from a file, or from standard input when named "-".  Either way it
      replaces the positional input, since a file is a deliberate choice and
      the leftover argument is only there for a quick one liner. }
    if InputFile = '-' then
      InputText := ReadFromStandardInput
    else if not TryReadWholeFile(InputFile, InputText) then
    begin
      WriteLn('error:  cannot read ', InputFile);
      Halt(1);
    end;
  end
  else if First + 1 <= ParamCount then
  begin
    InputText := ParamStr(First + 1);
  end
  else
    InputText := '';

  ApplyIdentity(Who, CertFile, KeyFile, Options_);

  if WantFingerprint then
  begin
    Fingerprint := GemServerFingerprint(URL, Options_, ErrMsg);
    if ErrMsg <> '' then
    begin
      WriteLn('error:  ', ErrMsg);
      Halt(1);
    end;
    WriteLn(Fingerprint);
    Halt(0);
  end;

  Ok := GemRequest(URL, InputText, Options_, Status, Meta, Body, ErrMsg);
  if not Ok then
  begin
    Report(URL, ErrMsg, -1, '', '');
    Halt(1);
  end;

  { A download gets the headers here and the body in the file, so that what is
    saved is the response and not a report about it. }
  if (OutputFile <> '') and (OutputFile <> '-') then
  begin
    ReportHead(URL, Status, Meta);
    if not TryWriteWholeFile(OutputFile, Body) then
    begin
      WriteLn(LABEL_ERROR, 'cannot write ', OutputFile);
      Halt(1);
    end;
    WriteLn(LABEL_WROTE, OutputFile, '  ', Length(Body), ' bytes');
  end
  else
    Report(URL, '', Status, Meta, Body);
end.
