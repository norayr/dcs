unit GemClient;

{$mode delphi}{$H+}

interface

{ A Gemini client built on Indy's TIdGemini, with the TLS backend chosen at
  compile time.  With USE_TAURUS it speaks TLS 1.3 through TaurusTLS; without
  it, it falls back to Indy's own OpenSSL handler, which stops at TLS 1.2.

  Certificates are not validated by default, because the servers under test use
  self-signed ones.  Supply SHA256 fingerprints to pin instead, and pinning
  takes precedence over the chain result, which is what lets a self-signed
  certificate be trusted deliberately.

  The two backends expose verification differently: Indy has OnVerifyPeer, a
  boolean-returning callback, while TaurusTLS has OnVerifyCallback, which sets a
  Continue flag.  Both are handled here so pinning behaves the same either way. }

type
  TTrustedCerts = array of string;

{ Performs one request.  Returns True when the exchange completed, whatever
  status the server chose.  Returns False on a transport or protocol error, in
  which case AError explains it and AStatus is -1.  AInput, when not empty, is
  sent as gemtext input. }
function GemRequest(const AURL: string; const AInput: string;
  out AStatus: Integer; out AMeta: string; out ABody: string;
  out AError: string; ATrusted: TTrustedCerts = nil): Boolean;

{ Human readable name for a Gemini status code. }
function GemStatusName(AStatus: Integer): string;

{ SHA256 fingerprint of the certificate the server presents, for pinning.
  AError is empty on success. }
function GemServerFingerprint(const AURL: string; out AError: string): string;

implementation

uses
  SysUtils, Classes, IdGlobal, IdSocketHandle, IdContext, IdURI, IdSSL,
  IdSSLOpenSSL, IdSSLOpenSSLHeaders, IdGemini
  {$IFDEF USE_TAURUS}
  // TaurusTLS declares its verification callback in terms of TTaurusTLSX509,
  // which lives in its own unit rather than the main one.
  , TaurusTLS, TaurusTLS_X509
  {$ENDIF};

type
  { Owns the pin list and captures the certificate the server presents.

    The verification callbacks arrive as method pointers, so they have to hang
    off an instance; this is that instance. }
  TCertificateWatch = class
  private
    FPins: TTrustedCerts;
    FCaptured: string;
    FCaptureOnly: Boolean;
    function Normalise(const AFingerprint: string): string;
    function IsTrusted(const AFingerprint: string): Boolean;
  public
    constructor Create(const APins: TTrustedCerts; ACaptureOnly: Boolean = False);
    function Captured: string;
    function Match(const AFingerprint: string): Boolean;
{$IFDEF USE_TAURUS}
    procedure Allow(Sender: TObject; const Preverify_ok: LongInt;
      Certificate: TTaurusTLSX509; const Depth: Integer; const Err: Int64;
      const Msg, Descr: string; var Continue: Boolean);
{$ELSE}
    function Allow(Certificate: TIdX509; AOk: Boolean; Depth,
      Err: Integer): Boolean;
{$ENDIF}
  end;

function TCertificateWatch.Normalise(const AFingerprint: string): string;
var
  I: Integer;
  C: Char;
begin
  { Drop separators and case, so a fingerprint pasted with or without colons
    compares equal. }
  Result := '';
  for I := 1 to Length(AFingerprint) do
  begin
    C := AFingerprint[I];
    if (C <> ':') and (C <> ' ') and (C <> #9) then
      Result := Result + UpperCase(C);
  end;
end;

constructor TCertificateWatch.Create(const APins: TTrustedCerts;
  ACaptureOnly: Boolean);
begin
  inherited Create;
  SetLength(FPins, Length(APins));
  if Length(APins) > 0 then
    Move(APins[0], FPins[0], Length(APins) * SizeOf(string));
  FCaptured := '';
  FCaptureOnly := ACaptureOnly;
end;

function TCertificateWatch.Captured: string;
begin
  Result := FCaptured;
end;

function TCertificateWatch.IsTrusted(const AFingerprint: string): Boolean;
var
  I: Integer;
  Norm: string;
begin
  Norm := Normalise(AFingerprint);
  if Norm = '' then
    Exit(False);
  for I := 0 to High(FPins) do
    if Normalise(FPins[I]) = Norm then
      Exit(True);
  Result := False;
end;

function TCertificateWatch.Match(const AFingerprint: string): Boolean;
begin
  Result := IsTrusted(AFingerprint);
end;

function FingerprintOf(Certificate: TIdX509): string;
begin
  Result := '';
  if (Certificate = nil) or (Certificate.Fingerprints = nil) then
    Exit;
  Result := Certificate.Fingerprints.SHA256AsString;
end;

{$IFDEF USE_TAURUS}

function TaurusFingerprint(Certificate: TTaurusTLSX509): string;
begin
  Result := '';
  if Certificate = nil then
    Exit;
  Result := Certificate.Fingerprints.SHA256AsString;
end;

procedure TCertificateWatch.Allow(Sender: TObject; const Preverify_ok: LongInt;
  Certificate: TTaurusTLSX509; const Depth: Integer; const Err: Int64;
  const Msg, Descr: string; var Continue: Boolean);
begin
  { Record the leaf certificate, which is the one a pin refers to. }
  if (FCaptured = '') and (Certificate <> nil) then
    FCaptured := TaurusFingerprint(Certificate);
  { In capture-only mode there is nothing to check against, so the point is
    just to reach the certificate of a self-signed server. }
  Continue := FCaptureOnly or (Preverify_ok <> 0) or Match(FCaptured);
end;

{$ELSE}

function TCertificateWatch.Allow(Certificate: TIdX509; AOk: Boolean;
  Depth, Err: Integer): Boolean;
begin
  if FCaptured = '' then
    FCaptured := FingerprintOf(Certificate);
  Result := FCaptureOnly or AOk or Match(FCaptured);
end;

{$ENDIF}

function GemStatusName(AStatus: Integer): string;
begin
  case AStatus of
    10: Result := '10 input';
    11: Result := '11 sensitive input';
    20: Result := '20 success';
    21: Result := '21 not found';
    30: Result := '30 temporary redirect';
    31: Result := '31 permanent redirect';
    40: Result := '40 temporary failure';
    41: Result := '41 server unavailable';
    42: Result := '42 CGI error';
    43: Result := '43 proxy request refused';
    44: Result := '44 slow down';
    50: Result := '50 permanent failure';
    51: Result := '51 not found';
    52: Result := '52 gone';
    53: Result := '53 proxy request forbidden';
    59: Result := '59 bad request';
    60: Result := '60 certificate required';
    61: Result := '61 certificate not authorised';
    62: Result := '62 certificate not valid';
  else
    Result := IntToStr(AStatus) + ' (unknown)';
  end;
end;

function StreamToText(AStream: TStream): string;
begin
  Result := '';
  if (AStream = nil) or (AStream.Size <= 0) then
    Exit;
  AStream.Position := 0;
  SetLength(Result, AStream.Size);
  AStream.ReadBuffer(Result[1], AStream.Size);
end;

{ Attaches the TLS handler appropriate to the build.  When AWatch is not nil,
  verification is switched on and routed through it. }
procedure ConfigureTLS(AClient: TIdGemini; AWatch: TCertificateWatch);
{$IFDEF USE_TAURUS}
var
  Handler: TTaurusTLSIOHandlerSocket;
begin
  Handler := TTaurusTLSIOHandlerSocket.Create(AClient);
  try
    if AWatch <> nil then
    begin
      Handler.SSLOptions.VerifyMode := [sslvrfPeer];
      Handler.OnVerifyCallback := AWatch.Allow;
    end;
    Handler.MaxLineLength := 1024;
    AClient.IOHandler := Handler;
  except
    Handler.Free;
    raise;
  end;
end;
{$ELSE}
begin
  if AWatch <> nil then
  begin
    AClient.SSLIOHandler.SSLOptions.VerifyMode := [sslvrfPeer];
    AClient.SSLIOHandler.OnVerifyPeer := AWatch.Allow;
  end;
  AClient.SSLIOHandler.MaxLineLength := 1024;
end;
{$ENDIF}

function GemRequest(const AURL: string; const AInput: string;
  out AStatus: Integer; out AMeta: string; out ABody: string;
  out AError: string; ATrusted: TTrustedCerts = nil): Boolean;
var
  Client: TIdGemini;
  Response: TGeminiResponse;
  Watch: TCertificateWatch;
begin
  Result := False;
  AStatus := -1;
  AMeta := '';
  ABody := '';
  AError := '';

  { No pins means no verification, which is what these test servers need. }
  if Length(ATrusted) > 0 then
    Watch := TCertificateWatch.Create(ATrusted)
  else
    Watch := nil;

  try
    Client := TIdGemini.Create(nil);
    Response := nil;
    try
      try
        ConfigureTLS(Client, Watch);

        if AInput = '' then
          Response := Client.Request(AURL)
        else
          Response := Client.Request(AURL, AInput);
      except
        on E: Exception do
        begin
          AError := E.ClassName + ': ' + E.Message;
          Response := nil;
          Exit;
        end;
      end;

      AStatus := Response.StatusCode;
      AMeta := Response.Meta;
      ABody := StreamToText(Response.Content);
      Result := True;
    finally
      Response.Free;
      Client.Free;
    end;
  finally
    Watch.Free;
  end;
end;

{ Connects once purely to read the certificate.  Verification is enabled and
  then overridden, which is the only way to reach the certificate a self-signed
  server presents. }
function GemServerFingerprint(const AURL: string; out AError: string): string;
var
  Client: TIdGemini;
  Response: TGeminiResponse;
  Watch: TCertificateWatch;
begin
  Result := '';
  AError := '';

  { Capture-only: the pin list is empty, so the callback has nothing to
    check and simply records the certificate. }
  Watch := TCertificateWatch.Create(nil, True);
  Client := TIdGemini.Create(nil);
  Response := nil;
  try
    try
      ConfigureTLS(Client, Watch);
      Response := Client.Request(AURL);
    except
      on E: Exception do
      begin
        AError := E.ClassName + ': ' + E.Message;
        Exit;
      end;
    end;
    Result := Watch.Captured;
  finally
    Response.Free;
    Client.Free;
    Watch.Free;
  end;
end;

end.
