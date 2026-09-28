program gem;

{ A command line Gemini client.

    gem <url>                    fetch and print
    gem <url> <input>            fetch, sending gemtext input
    gem --fingerprint <url>      print the server's SHA256 certificate fingerprint
    gem --pin <sha256> <url>     fetch, trusting only that SHA256

  The TLS backend is fixed at compile time: build with USE_TAURUS=1 for TLS 1.3
  via TaurusTLS, or USE_TAURUS=0 for Indy's own OpenSSL handler.

  Certificates are not validated by default, since the servers under test use
  self-signed ones.  Use --pin to require a specific fingerprint instead. }

{$mode delphi}{$H+}

uses
  {$IFDEF UNIX}
  cthreads,
  {$ENDIF}
  SysUtils, Classes, GemClient;

{ Renders control characters so binary responses stay visible. }
function Visible(const S: string): string;
var
  I: Integer;
begin
  Result := '';
  for I := 1 to Length(S) do
    case S[I] of
      #13: Result := Result + '\r';
      #10: Result := Result + '\n';
      #9: Result := Result + '\t';
      #32..#126: Result := Result + S[I];
    else
      Result := Result + '\x' + IntToHex(Ord(S[I]), 2);
    end;
end;

procedure Usage;
begin
  WriteLn('usage: gem <url> [input]');
  WriteLn('       gem --fingerprint <url>');
  WriteLn('       gem --pin <sha256> <url> [input]');
end;

procedure Report(const AURL, AError: string; AStatus: Integer; const AMeta,
  ABody: string);
begin
  WriteLn('url:    ', AURL);
  if AError <> '' then
  begin
    WriteLn('error:  ', AError);
    Exit;
  end;
  WriteLn('status: ', AStatus, '  ', GemStatusName(AStatus));
  WriteLn('meta:   "', AMeta, '"');
  WriteLn('body:   ', Visible(ABody));
end;

var
  URL: string;
  InputText: string;
  Status: Integer;
  Meta: string;
  Body: string;
  ErrMsg: string;
  Fingerprint: string;
  Pins: TTrustedCerts;
  First: Integer;
  Ok: Boolean;
  WantFingerprint: Boolean;
begin
  if ParamCount < 1 then
  begin
    Usage;
    Halt(1);
  end;

  SetLength(Pins, 0);
  First := 1;
  WantFingerprint := False;
  if (ParamCount >= 2) and (ParamStr(1) = '--fingerprint') then
  begin
    WantFingerprint := True;
    First := 2;
  end
  else if (ParamCount >= 3) and (ParamStr(1) = '--pin') then
  begin
    SetLength(Pins, 1);
    Pins[0] := ParamStr(2);
    First := 3;
  end;

  URL := ParamStr(First);
  if First + 1 <= ParamCount then
    InputText := ParamStr(First + 1)
  else
    InputText := '';

  if WantFingerprint then
  begin
    Fingerprint := GemServerFingerprint(URL, ErrMsg);
    if ErrMsg <> '' then
    begin
      WriteLn('error:  ', ErrMsg);
      Halt(1);
    end;
    WriteLn(Fingerprint);
    Halt(0);
  end;

  Ok := GemRequest(URL, InputText, Status, Meta, Body, ErrMsg, Pins);
  if Ok then
    Report(URL, '', Status, Meta, Body)
  else
  begin
    Report(URL, ErrMsg, -1, '', '');
    Halt(1);
  end;
end.
