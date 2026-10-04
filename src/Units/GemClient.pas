unit GemClient;

{$mode delphi}{$H+}

interface

{ A Gemini client built on Indy's TIdGemini, with the TLS backend chosen at
  compile time.  With USE_TAURUS it speaks TLS 1.3 through TaurusTLS; without
  it, it falls back to Indy's own OpenSSL handler, which stops at TLS 1.2.

  Certificates are not validated by default, because many servers use
  self-signed ones.  Supply SHA256 fingerprints to pin instead, and pinning
  takes precedence over the chain result, which is what lets a self-signed
  certificate be trusted deliberately.

  A client certificate can be supplied, which is how a Gemini identity works:
  the server asks for one, usually with a 60 certificate required, and decides
  who you are from the subject of the certificate you present.

  The two backends expose verification differently: Indy has OnVerifyPeer, a
  boolean-returning callback, while TaurusTLS has OnVerifyCallback, which sets a
  Continue flag.  Both are handled here so pinning behaves the same either way. }

type
  TTrustedCerts = array of string;

{ Everything a request needs beyond the URL and the input.  All of it is
  optional: with nothing set, certificates are not verified and no identity is
  presented. }
type
  TGemOptions = class
  private
    FTrusted: TTrustedCerts;
    FCertFile: string;
    FKeyFile: string;
  public
    { SHA256 fingerprints to accept.  A matching certificate is allowed through
      even if the chain result says otherwise. }
    property Trusted: TTrustedCerts read FTrusted write FTrusted;
    { Client certificate, the identity presented to servers that ask for one. }
    property CertFile: string read FCertFile write FCertFile;
    { Private key for CertFile. }
    property KeyFile: string read FKeyFile write FKeyFile;
    { True when an identity was supplied. }
    function HasIdentity: Boolean;
  end;

{ Performs one request.  Returns True when the exchange completed, whatever
  status the server chose.  Returns False on a transport or protocol error, in
  which case AError explains it and AStatus is -1.  AInput, when not empty, is
  sent as gemtext input, which is how a query or a post is submitted: the server
  answers 10 or 11, asks for the input, and then replies again. }
function GemRequest(const AURL: string; const AInput: string; AOptions: TGemOptions;
  out AStatus: Integer; out AMeta: string; out ABody: string;
  out AError: string): Boolean;

{ Human readable name for a Gemini status code. }
function GemStatusName(AStatus: Integer): string;

{ SHA256 fingerprint of the certificate the server presents, for pinning.
  AError is empty on success. }
function GemServerFingerprint(const AURL: string; AOptions: TGemOptions;
  out AError: string): string;

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

function TGemOptions.HasIdentity: Boolean;
begin
  Result := (FCertFile <> '') and (FKeyFile <> '');
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

{ Attaches the TLS handler appropriate to the build.  AWatch, when given,
  switches verification on and routes it through the watch, which is how
  pinning and fingerprint capture work.  AOptions, when it carries an identity,
  presents a client certificate so that servers demanding one can identify the
  caller. }
procedure ConfigureTLS(AClient: TIdGemini; AWatch: TCertificateWatch;
  AOptions: TGemOptions);
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
    if AOptions.HasIdentity then
    begin
      { ClientCert holds the certificate and key paths for a client, and is
        applied to the context when the handler initialises. }
      Handler.ClientCert.PublicKey := AOptions.CertFile;
      Handler.ClientCert.PrivateKey := AOptions.KeyFile;
    end;
    Handler.MaxLineLength := 1024;
    AClient.IOHandler := Handler;
  except
    Handler.Free;
    raise;
  end;
end;
{$ELSE}
var
  { TIdGemini deliberately leaves IOHandler empty, so that Indy's OpenSSL
    handler is not linked into every build that speaks TLS some other way.
    Create the handler here rather than assuming one is already there. }
  Handler: TIdSSLIOHandlerSocketOpenSSL;
begin
  Handler := TIdSSLIOHandlerSocketOpenSSL.Create(AClient);
  try
    if AWatch <> nil then
    begin
      Handler.SSLOptions.VerifyMode := [sslvrfPeer];
      Handler.OnVerifyPeer := AWatch.Allow;
    end;
    if AOptions.HasIdentity then
    begin
      Handler.SSLOptions.CertFile := AOptions.CertFile;
      Handler.SSLOptions.KeyFile := AOptions.KeyFile;
    end;
    Handler.MaxLineLength := 1024;
    AClient.IOHandler := Handler;
  except
    Handler.Free;
    raise;
  end;
end;
{$ENDIF}

function GemRequest(const AURL: string; const AInput: string;
  AOptions: TGemOptions; out AStatus: Integer; out AMeta: string;
  out ABody: string; out AError: string): Boolean;
var
  Client: TIdGemini;
  LOk: Boolean;
  Watch: TCertificateWatch;
  Pins: TTrustedCerts;
begin
  Result := False;
  AStatus := -1;
  AMeta := '';
  ABody := '';
  AError := '';

  Pins := nil;
  if AOptions <> nil then
    Pins := AOptions.Trusted;

  { No pins means no verification, which is what self-signed servers need. }
  if Length(Pins) > 0 then
    Watch := TCertificateWatch.Create(Pins)
  else
    Watch := nil;

  try
    Client := TIdGemini.Create(nil);
    try
      try
        ConfigureTLS(Client, Watch, AOptions);

        { The response belongs to Client, so it is read back through
          Client.Response instead of being held, and freed, here. }
        if AInput = '' then
          LOk := Client.Request(AURL)
        else
          LOk := Client.Request(AURL, AInput);
        if not LOk then
        begin
          AError := 'no response';
          Exit;
        end;
      except
        on E: Exception do
        begin
          AError := E.ClassName + ': ' + E.Message;
          Exit;
        end;
      end;

      AStatus := Client.Response.StatusCode;
      AMeta := Client.Response.Meta;
      ABody := StreamToText(Client.Response.Content);
      Result := True;
    finally
      Client.Free;
    end;
  finally
    Watch.Free;
  end;
end;

{ Connects once purely to read the certificate.  Verification is enabled and
  then overridden, which is the only way to reach the certificate a self-signed
  server presents. }
function GemServerFingerprint(const AURL: string; AOptions: TGemOptions;
  out AError: string): string;
var
  Client: TIdGemini;
  Watch: TCertificateWatch;
begin
  Result := '';
  AError := '';

  { Capture-only: the pin list is empty, so the callback has nothing to
    check and simply records the certificate. }
  Watch := TCertificateWatch.Create(nil, True);
  Client := TIdGemini.Create(nil);
  try
    try
      ConfigureTLS(Client, Watch, AOptions);
      Client.Request(AURL);
    except
      on E: Exception do
      begin
        AError := E.ClassName + ': ' + E.Message;
        Exit;
      end;
    end;
    Result := Watch.Captured;
  finally
    Client.Free;
    Watch.Free;
  end;
end;

end.
