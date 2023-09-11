{==============================================================================|
| Project : Object Pascal WebSocket Client/Server Library                      |
|==============================================================================|
| Content: Core WebSocket client and server classes                            |
|==============================================================================|
| Copyright (c) 2023, Vahid Nasehi Oskouei                                     |
| All rights reserved.                                                         |
|                                                                              |
| Remastered and rewritten version which is based on                           |
|   https://github.com/MFernstrom/Bauglir-WebSocket-2                          |
| and                                                                          |
|   https://github.com/Robert-112/Bauglir-WebSocket-2                          |
| which originally are based on Bronislav Klucka source code as                |
|   http://code.google.com/p/bauglir-websocket                                 |
|                                                                              |
|                                                                              |
| Project download homepage:                                                   |
|   https://github.com/biot2/libWebSocket.pas                                  |
| WebSocket RFC:                                                               |
|   http://tools.ietf.org/html/rfc6455                                         |
|                                                                              |
|                                                                              |
|==============================================================================|
| Requirements: Ararat Synapse (http://www.ararat.cz/synapse/)                 |
|==============================================================================}



unit WebSocket.Core;

{$IFDEF FPC}
  {$MODE DELPHI}
{$ENDIF}
{$H+}

interface

uses
  {$IFDEF UNIX}
  cthreads,
  {$ENDIF}
  Classes, SysUtils, blcksock, syncobjs, WebSocket.Helper, strutils;

const
  {:Constants section defining what kind of data are sent from one pont to another}
  {:Continuation frame }
  wsCodeContinuation = $0;
  {:Text frame }
  wsCodeText         = $1;
  {:Binary frame }
  wsCodeBinary       = $2;
  {:Close frame }
  wsCodeClose        = $8;
  {:Ping frame }
  wsCodePing         = $9;
  {:Frame frame }
  wsCodePong         = $A;


  {:Constants section defining close codes}
  {:Normal valid closure, connection purpose was fulfilled}
  wsCloseNormal              = 1000;
  {:Endpoint is going away (like server shutdown) }
  wsCloseShutdown            = 1001;
  {:Protocol error }
  wsCloseErrorProtocol       = 1002;
  {:Unknown frame data type or data type application cannot handle }
  wsCloseErrorData           = 1003;
  {:Reserved }
  wsCloseReserved1           = 1004;
  {:Close received by peer but without any close code. This close code MUST NOT be sent by application. }
  wsCloseNoStatus            = 1005;
  {:Abnotmal connection shutdown close code. This close code MUST NOT be sent by application. }
  wsCloseErrorClose          = 1006;
  {:Received text data are not valid UTF-8. }
  wsCloseErrorUTF8           = 1007;
  {:Endpoint is terminating the connection because it has received a message that violates its policy. Generic error. }
  wsCloseErrorPolicy         = 1008;
  {:Too large message received }
  wsCloseTooLargeMessage     = 1009;
  {:Client is terminating the connection because it has expected the server to negotiate one or more extension, but the server didn't return them in the response message of the WebSocket handshake }
  wsCloseClientExtensionError= 1010;
  {:Server is terminating the connection because it encountered an unexpected condition that prevented it from fulfilling the request }
  wsCloseErrorServerRequest  = 1011;
  {:Connection was closed due to a failure to perform a TLS handshake. This close code MUST NOT be sent by application. }
  wsCloseErrorTLS            = 1015;

type
  TReadOnlyMemoryStream = class(TCustomMemoryStream)
  public
    constructor Create(Memory: Pointer; Size: PtrInt);
    procedure ResetPointer(Memory: Pointer; Size: PtrInt);
	end;

  TWSFlag = (FIN, RSV1, RSV2, RSV3);
  TWSFlags = set of TWSFlag;

  TWebSocketCustomConnection = class;

  {:Event procedural type to hook OnOpen events on connection
  }
  TWebSocketConnectionEvent = procedure(Sender: TWebSocketCustomConnection) of object;

  {:Event procedural type to hook OnPing, OnPong events on connection
  }
  TWebSocketConnectionPingPongEvent = procedure(Sender: TWebSocketCustomConnection; Data: AnsiString) of object;

  {:Event procedural type to hook OnClose event on connection
  }
  TWebSocketConnectionClose = procedure(Sender: TWebSocketCustomConnection; CloseCode: Integer; CloseReason: AnsiString; ClosedByPeer: Boolean) of object;

  {:Event procedural type to hook OnRead on OnWrite event on connection
  }
  TWebSocketConnectionData = procedure(Sender: TWebSocketCustomConnection; Flags: TWSFlags; OpCode: Byte; Data: TMemoryStream) of object;
  TWebSocketConnectionDataWrite = procedure(Sender: TWebSocketCustomConnection; Flags: TWSFlags; OpCode: Byte; Data: TStream) of object;

  {:Event procedural type to hook OnReadFull
  }
  TWebSocketConnectionDataFull = procedure(Sender: TWebSocketCustomConnection; OpCode: Byte; Data: TMemoryStream) of object;

  {:abstract(WebSocket connection)
    class is parent class for server and client connection 
  }
  TWebSocketCustomConnection = class(TCustomConnection)
  private
  protected
    FOnOpen: TWebSocketConnectionEvent;
    FOnClose: TWebSocketConnectionClose;
    FOnRead: TWebSocketConnectionData;
    FOnReadFull: TWebSocketConnectionDataFull;
    FOnWrite: TWebSocketConnectionDataWrite;
    FOnPing: TWebSocketConnectionPingPongEvent;
    FOnPong: TWebSocketConnectionPingPongEvent;

    FCookie: AnsiString;
    FVersion: Integer;
    FProtocol: AnsiString;
    FResourceName: AnsiString;
    FOrigin: AnsiString;
    FExtension: AnsiString;
    FPort: AnsiString;
    FHost: AnsiString;
    FHeaders: TStringList;


    FClosedByMe: Boolean;
    FClosedByPeer: Boolean;
    FMasking: Boolean;
    FRequireMasking: Boolean;
    FHandshake: Boolean;


    FCloseCode: Integer;
    FCloseReason: AnsiString;
    FClosingByPeer: Boolean;


    FSendCriticalSection: TCriticalSection;

    FFullDataProcess: Boolean;
    FFullDataStream: TMemoryStream;

    function GetClosed: Boolean;
    function GetClosing: Boolean;

    procedure ExecuteConnection; override;
    function ReadData(out Flags: TWSFlags; out OpCode: Byte; Data: TMemoryStream): Integer; virtual;
    function ValidConnection: Boolean;

    procedure DoOpen;
    procedure DoClose(CloseCode: Integer; CloseReason: AnsiString; ClosedByPeer: Boolean);
    procedure DoPing(Data: AnsiString);
    procedure DoPong(Data: AnsiString);
    procedure DoRead(Flags: TWSFlags; OpCode: Byte; Data: TMemoryStream);
    procedure DoReadFull(OpCode: Byte; Data: TMemoryStream);
    procedure DoWrite(Flags: TWSFlags; OpCode: Byte; Data: TStream);

    {:Overload this function to process connection close (not at socket level, but as an actual WebSocket frame)
      CloseCode represents close code (see wsClose constants)
      CloseReason represents textual information transfered with frame (there is no specified format or meaning)
      ClosedByPeer whether connection has been closed by this connection object or by peer endpoint
    }
    procedure ProcessOpen; virtual;
    procedure ProcessClose(CloseCode: Integer; CloseReason: AnsiString; ClosedByPeer: Boolean); virtual;


    {:Overload this function to process ping frame)
      Data represents textual information transfered with frame (there is no specified format or meaning)
    }
    procedure ProcessPing(Data: AnsiString); virtual;

    {:Overload this function to process pong frame)
      Data represents textual information transfered with frame (there is no specified format or meaning)
    }
    procedure ProcessPong(Data: AnsiString); virtual;

    {:Overload this function to process data as soon as they are read before other Process<data> function is called
      this function should be used by extensions to modify incomming data before the are process based on code
      Flags frame flags including FIN and 3 extension bits
      Opcode is frame opcode
      Data data stream
    }
    procedure ProcessReadData(var Flags: TWSFlags; var OpCode: Byte; Data: TMemoryStream); virtual;
    procedure ProcessReadDataFull(var {%H-}Flags: TWSFlags; var OpCode: Byte; Data: TMemoryStream); virtual;
    procedure ProcessWriteData(var Flags: TWSFlags; var OpCode: Byte; Data: TStream); virtual;

  public
    constructor Create(Socket: TTCPCustomConnectionSocket); override;
    destructor Destroy; override;

    {:
      Whether connection is in active state (not closed, closing, socket, exists, i/o  threads not Terminated..)
    }
    function CanReceiveOrSend: Boolean;

    {:Procedure to close connection
      CloseCode represents close code (see wsClose constants)
      CloseReason represents textual information transfered with frame (there is no specified format or meaning) the AnsiString can only be 123 bytes length
    }
    procedure Close(CloseCode: Integer; CloseReason: AnsiString); virtual; abstract;


    {:Send generic frame
      Flags frame flags including FIN and 3 extension bits
      OpCode frame opcode
      Data data stream or string
    }
    function SendData(Flags: TWSFlags; OpCode: Byte; Data: TStream): Integer; overload; virtual;
    function SendData(Flags: TWSFlags; OpCode: Byte; Data: Pointer; DataSize: Integer): Integer; overload; virtual;
    function SendData(Flags: TWSFlags; OpCode: Byte; Data: AnsiString): Integer; overload; virtual;
    function SendDataSplitted(OpCode: Byte; Data: Pointer; DataSize: Int64; SplitSize: Integer): Integer; overload;
    function SendDataSplitted(OpCode: Byte; Data: TStream; SplitSize: Integer): Integer; overload;


    {:Send textual frame
      Data data AnsiString (MUST be UTF-8)
      Flags frame flags including FIN and 3 extension bits
    }
    procedure SendText(Data: AnsiString; Flags: TWSFlags = [FIN]);
    procedure SendTextSplitted(Data: AnsiString; SplitSize: Integer = 1048576);

    {:Send textual continuation frame
      Data data AnsiString (MUST be UTF-8)
      Flags frame flags including FIN and 3 extension bits
    }
    procedure SendTextContinuation(Data: AnsiString; Flags: TWSFlags = [FIN]);

    {:Send binary frame
      Data data stream
      Flags frame flags including FIN and 3 extension bits
    }
    procedure SendBinary(Data: TStream; Flags: TWSFlags = [FIN]);
    procedure SendBinarySplitted(Data: TStream; SplitSize: Integer = 1048576);

    {:Send binary continuation frame
      Data data stream
      Flags frame flags including FIN and 3 extension bits
    }
    procedure SendBinaryContinuation(Data: TStream; Flags: TWSFlags = [FIN]);
    {:Send Ping
      Data ping informations
    }
    procedure Ping(Data: AnsiString);

    {:Send Pong
      Data pong informations
    }
    procedure Pong(Data: AnsiString);

    {:Temination procedure
      This method should be called instead of Terminate to terminate thread,
      it internally calls Terminate, but can be overloaded,
      and can be used for data clean up
    }
    procedure TerminateThread; override;



    {: Whether connection has been closed
      (either socket has been closed or thread has been Terminated or WebSocket has been closed by this and peer connection)
     }
    property Closed: Boolean read GetClosed;

    {: Whether WebSocket has been closed by this and peer connection }
    property Closing: Boolean read GetClosing;

    {: WebSocket connection cookies
      Property is regular unparsed Cookie header AnsiString
      e.g. cookie1=value1;cookie2=value2

      empty AnsiString represents that no cookies are present
    }
    property Cookie: AnsiString read FCookie;

    {: WebSocket connection extensions
      Property is regular unparsed Sec-WebSocket-Extensions header AnsiString
      e.g. foo, bar; baz=2

      On both client and server connection this value represents the extension(s) selected by server to be used
      as a Result of extension negotioation

      value - represents that no extension was negotiated and no header will be sent to client
      it is the default value
    }
    property Extension: AnsiString read FExtension;

    {:Whether to register for full data processing
    (callink @link(ProcessFullText), @link(ProcessFullStream) @link(OnFullRead)
    those methods/events are called if FullDataProcess is @True and whole message is read (after FIN frame)
    }
    property FullDataProcess: Boolean read FFullDataProcess write FFullDataProcess;


    {:
      Whether WebSocket handshake was succecfull (and connection is afer WS handshake) 
    }
    property Handshake: Boolean read FHandshake;

    {: WebSocket connection host
      Property is regular unparsed Host header AnsiString
      e.g. server.example.com
    }
    property Host: AnsiString read FHost;

    {: WebSocket connection origin
      Property is regular unparsed Sec-WebSocket-Origin header AnsiString
      e.g. http://example.com
    }
    property Origin: AnsiString read FOrigin;

    {: WebSocket connection protocol
      Property is regular unparsed Sec-WebSocket-Protocol header AnsiString
      e.g. chat, superchat

      On both client and server connection this value represents the protocol(s) selected by server to be used
      as a Result of protocol negotioation

      value - represents that no protocol was negotiated and no header will be sent to client
      it is the default value
    }
    property Protocol: AnsiString read FProtocol;

    {: Connection port }
    property Port: AnsiString read FPort;
    
    {: Connection resource
      e.g. /path1/path2/path3/file.ext
    }
    property ResourceName: AnsiString read FResourceName;

    {: WebSocket version (either 7 or 8 or 13)}
    property Version: Integer read FVersion;

    {: WebSocket connection successfully }
    property OnOpen: TWebSocketConnectionEvent read FOnOpen write FOnOpen;

    {: WebSocket Close frame event }
    property OnClose: TWebSocketConnectionClose read FOnClose write FOnClose;

    { : WebSocket ping }
    property OnPing: TWebSocketConnectionPingPongEvent read FOnPing write FOnPing;

    { : WebSocket pong }
    property OnPong: TWebSocketConnectionPingPongEvent read FOnPong write FOnPong;

    {: WebSocket frame read }
    property OnRead: TWebSocketConnectionData read FOnRead write FOnRead;

    {: WebSocket read full data}
    property OnReadFull: TWebSocketConnectionDataFull read FOnReadFull write FOnReadFull;

    {: WebSocket frame written }
    property OnWrite: TWebSocketConnectionDataWrite read FOnWrite write FOnWrite;
  end;

  {: Class of WebSocket connections }
  TWebSocketCustomConnections = class of TWebSocketCustomConnection;

  {: WebSocket server connection automatically created by server on incoming connection }
  TWebSocketServerConnection = class(TWebSocketCustomConnection)
  public
    constructor Create(Socket: TTCPCustomConnectionSocket); override;
    procedure Close(CloseCode: Integer; CloseReason: AnsiString); override;
    procedure TerminateThread; override;

    {: List of all headers
      keys are lowercased header name
      e.g host, connection, sec-websocket-key
    }
    property Header: TStringList read FHeaders;

  end;

  {: Class of WebSocket server connections }
  TWebSocketServerConnections = class of TWebSocketServerConnection;

  {: WebSocket client connection, this object shoud be created to establish client to server connection  }
  TWebSocketClient = class(TWebSocketCustomConnection)
  private
    FEvent: TSimpleEvent;
  protected
    function BeforeExecuteConnection: Boolean; override;
    procedure Execute; override;
    procedure DoConnect;
  public
    {: construstor to create connection,
      parameters has the same meaning as corresponging connection properties (see 2 differences below) and
      should be formated according to headers values

      Protocol and Extension in constructor represents protocol(s) and extension(s)
      client is trying to negotiate, obejst properties then represents
      protocol(s) and extension(s) the server is supporting (the negotiation Result)

      Version must be >= 8
    }
    constructor Create(Host, Port, ResourceName: AnsiString; Origin: AnsiString = '-'; Protocol: AnsiString = '-'; Extension: AnsiString = '-'; Cookie: AnsiString = '-'; Version: Integer = 13); reintroduce; virtual;
    constructor CreateFromURL(URL: AnsiString; Origin: AnsiString = '-'; Protocol: AnsiString = '-'; Extension: AnsiString = '-'; Cookie: AnsiString = '-'; Version: Integer = 13); virtual;
    destructor Destroy; override;

    procedure Close(CloseCode: Integer; CloseReason: AnsiString); override;

    function WaitForConnect(Timeout: Cardinal): Boolean;
  end;


  TWebSocketServer = class;

  {:Event procedural type to hook OnReceiveConnection events on server
    every time new server connection is about to be created (client is connecting to server)
    this event is called

    properties are representing connection properties as defined in @link(TWebSocketServerConnection)

    Protocol and Extension represents corresponding headers sent by client, as their out value
    server must define what kind of protocol(s) and extension(s) server is supporting, if event
    is not implemented, both values are considered as - (no value at all)

    HttpResult represents the HTTP Result to be send in response, if connection is about to be
    accepted, the value MUST BE 101, any other value meand that the client will be informed about the
    Result (using the HTTP code meaning) and connection will be closed, if event is not implemented
    101 is used as a default value 
  }
  TWebSocketServerReceiveConnection = procedure(Server: TWebSocketServer;
                                                Socket: TTCPCustomConnectionSocket;
                                                Header: TStringList;
                                                ResourceName, Host, Port, Origin, Cookie: AnsiString;
                                                HttpResult: Integer;
                                                Protocol, Extensions: AnsiString) of object;



  TWebSocketServer = class(TCustomServer)
  protected
    {CreateServerConnection sync variables}
    FNCSocket: TTCPCustomConnectionSocket;
    FNCResourceName: AnsiString;
    FNCHost: AnsiString;
    FNCPort: AnsiString;
    FNCOrigin: AnsiString;
    FNCProtocol: AnsiString;
    FNCExtensions: AnsiString;
    FNCCookie: AnsiString;
    FNCHeaders: AnsiString;
    FNCResultHttp: Integer;

    FOnReceiveConnection: TWebSocketServerReceiveConnection;  protected
    function CreateServerConnection(Socket: TTCPCustomConnectionSocket): TCustomConnection; override;
    procedure DoSyncReceiveConnection;
    procedure SyncReceiveConnection;
    property Terminated;

    {:This function defines what kind of TWebSocketServerConnection implementation should be used as
      a connection object.
      The servers default return value is TWebSocketServerConnection.

      If new connection class based on TWebSocketServerConnection is implemented,
      new server should be implemented as well with this method overloaded

      properties are representing connection properties as defined in @link(TWebSocketServerConnection)

      Protocol and Extension represents corresponding headers sent by client, as their out value
      server must define what kind of protocol(s) and extension(s) server is supporting, if event
      is not implemented, both values are cosidered as - (no value at all)

      HttpResult represents the HTTP Result to be send in response, if connection is about to be
      accepted, the value MUST BE 101, any other value meand that the client will be informed about the
      Result (using the HTTP code meaning) and connection will be closed, if event is not implemented
      101 is used as a default value

    }
    function GetWebSocketConnectionClass({%H-}Socket: TTCPCustomConnectionSocket;
                                         {%H-}Header: TStringList;
                                         {%H-}ResourceName, {%H-}Host, {%H-}Port, {%H-}Origin, {%H-}Cookie: AnsiString;
                                         out {%H-}HttpResult: Integer;
                                         var {%H-}Protocol, {%H-}Extensions: AnsiString): TWebSocketServerConnections; virtual;

  public
    {: WebSocket connection received }
    property OnReceiveConnection: TWebSocketServerReceiveConnection read FOnReceiveConnection write FOnReceiveConnection;

    {: close all connections
    for parameters see connection Close method
    }
    procedure CloseAllConnections(CloseCode: Integer; Reason: AnsiString);


    {:Temination procedure
      This method should be called instead of Terminate to terminate thread,
      it internally calls Terminate, but can be overloaded,
      and can be used for data clean up
    }
    procedure TerminateThread; override;

    {: Method to send binary data to all connected clients
      see @link(TWebSocketServerConnection.SendBinary) for parameters description
    }
    procedure BroadcastBinary(Data: TStream; Flags: TWSFlags = [FIN]);

    {: Method to send text data to all connected clients
      see @link(TWebSocketServerConnection.SendText) for parameters description
    }
    procedure BroadcastText(Data: AnsiString; Flags: TWSFlags = [FIN]);

  end;

implementation

uses
  Math, synautil, synacode, synsock {$IFDEF Win32}, Windows{$ENDIF Win32},
  synachar;

{$IFDEF Win32} {$O-} {$ENDIF Win32}


function HTTPCodeToText(HTTPCode: Integer): AnsiString;
begin
  case HTTPCode of
     100: Result := 'Continue'; 
     101: Result := 'Switching Protocols'; 
     200: Result := 'OK'; 
     201: Result := 'Created'; 
     202: Result := 'Accepted'; 
     203: Result := 'Non-Authoritative Information'; 
     204: Result := 'No Content'; 
     205: Result := 'Reset Content';
     206: Result := 'Partial Content'; 
     300: Result := 'Multiple Choices'; 
     301: Result := 'Moved Permanently'; 
     302: Result := 'Found'; 
     303: Result := 'See Other'; 
     304: Result := 'Not Modified'; 
     305: Result := 'Use Proxy'; 
     307: Result := 'Temporary Redirect'; 
     400: Result := 'Bad Request'; 
     401: Result := 'Unauthorized'; 
     402: Result := 'Payment Required'; 
     403: Result := 'Forbidden'; 
     404: Result := 'Not Found'; 
     405: Result := 'Method Not Allowed'; 
     406: Result := 'Not Acceptable'; 
     407: Result := 'Proxy Authentication Required'; 
     408: Result := 'Request Time-out'; 
     409: Result := 'Conflict'; 
     410: Result := 'Gone'; 
     411: Result := 'Length Required'; 
     412: Result := 'Precondition Failed'; 
     413: Result := 'Request Entity Too Large';
     414: Result := 'Request-URI Too Large'; 
     415: Result := 'Unsupported Media Type'; 
     416: Result := 'Requested range not satisfiable'; 
     417: Result := 'Expectation Failed'; 
     500: Result := 'Internal Server Error'; 
     501: Result := 'Not Implemented'; 
     502: Result := 'Bad Gateway'; 
     503: Result := 'Service Unavailable';
     504: Result := 'Gateway Time-out';
     else
       Result := 'unknown code: $code';
  end;
end;


function ReadHttpHeaders(Socket: TTCPCustomConnectionSocket; out Data: AnsiString; Headers: TStrings): Boolean;
var
  s, name: AnsiString;
begin
  Data := '';
  Headers.Clear;
  Result := True;
  repeat
    Socket.MaxLineLength := 1024 * 1024; // not to attack memory on server
    s := Socket.RecvString(30 * 1000); // not to hang up connection
    if (Socket.LastError <> 0) then
    begin
      Result := False;
      break;
    end;
    if (s = '') then
      break;
    if (Data = '') then
      Data := s
    else
    begin
      name := LowerCase(trim(SeparateLeft(s, ':')));
      if (Headers.Values[name] = '') then
        Headers.Values[name] := trim(SeparateRight(s, ':'))
      else
        Headers.Values[name] := Headers.Values[name] + ',' + trim(SeparateRight(s, ':'));
    end;
  until {IsTerminated} False;
  Socket.MaxLineLength := 0;
end;

procedure ODS({%H-}Str: AnsiString); overload;
begin
  {$IFDEF Win32}
  OutputDebugString(pChar(FormatDateTime('yyyy-mm-dd hh:nn:ss', now) + ': ' + Str));
  {$ENDIF Win32}
end;

procedure ODS({%H-}Str: AnsiString; {%H-}Data: array of const); overload;
begin
  {$IFDEF Win32}
  ODS(Format(Str, Data));
  {$ENDIF Win32}
end;

{ TReadOnlyMemoryStream }

constructor TReadOnlyMemoryStream.Create(Memory: Pointer; Size: PtrInt);
begin
  inherited Create;
  SetPointer(Memory, Size);
end;

procedure TReadOnlyMemoryStream.ResetPointer(Memory: Pointer; Size: PtrInt);
begin
  SetPointer(Memory, Size);
  Position := 0;
end;

{ TWebSocketServer }

procedure TWebSocketServer.BroadcastBinary(Data: TStream; Flags: TWSFlags);
var
  i: Integer;
begin
  LockTermination;
  for i := 0 to FConnections.Count - 1 do
  begin
    if (not TWebSocketServerConnection(FConnections[i]).IsTerminated) then
      TWebSocketServerConnection(FConnections[i]).SendBinary(Data, Flags);
  end;
  UnLockTermination;
end;

procedure TWebSocketServer.BroadcastText(Data: AnsiString; Flags: TWSFlags);
var
  i: Integer;
begin
  LockTermination;
  for i := 0 to FConnections.Count - 1 do
  begin
    if (not TWebSocketServerConnection(FConnections[i]).IsTerminated) then
      TWebSocketServerConnection(FConnections[i]).SendText(Data, Flags);
  end;
  UnLockTermination;
end;

procedure TWebSocketServer.CloseAllConnections(CloseCode: Integer; Reason: AnsiString);
var
  i: Integer;
begin
  LockTermination;
  //for i := 0 to FConnections.Count - 1 do
  for i := FConnections.Count - 1 downto 0 do
  begin
    if (not TWebSocketServerConnection(FConnections[i]).IsTerminated) then
      TWebSocketServerConnection(FConnections[i]).Close(CloseCode, Reason);// SendBinary(Data, IsFinal, aRes1, aRes2,  aRes3);
  end;
  UnLockTermination;
end;

function TWebSocketServer.CreateServerConnection(Socket: TTCPCustomConnectionSocket): TCustomConnection;
var
  headers, hrs: TStringList;
  data: AnsiString;
  s{, resName, host, port}, key, version{, origin, protocol, extensions, cookie}, tmpExtension, tmpWord, extensionKey, extensionValue: AnsiString;
  iversion, vv, extCounter: Integer;
  res: Boolean;
  r: TWebSocketServerConnections;
begin
  FNCSocket := Socket;
  Result := inherited CreateServerConnection(Socket);
  headers := TStringList.Create;
  try
    res := ReadHttpHeaders(Socket, data, headers);
    if (res) then
    begin
      res := False;
      try
        //CHECK HTTP data
        if ((Pos('GET ', Uppercase(data)) <> 0) and (Pos(' HTTP/1.1', Uppercase(data)) <> 0)) then
        begin
          FNCResourceName := SeparateRight(data, ' ');
          FNCResourceName := SeparateLeft(FNCResourceName, ' ');
        end
        else Exit;
        FNCResourceName := trim(FNCResourceName);

  {
      : AnsiString;
      : AnsiString;
      : AnsiString;
      : AnsiString;
      : AnsiString;
      : AnsiString;
      : AnsiString;
      FNCHeaders: AnsiString;
  }

        //CHECK HOST AND PORT
        s := headers.Values['host'];
        if (s <> '') then
        begin
          FNCHost := trim(s);
          FNCPort := SeparateRight(FNCHost, ':');
          FNCHost := SeparateLeft(FNCHost, ':');
        end;
        FNCHost := trim(FNCHost);
        FNCPort := trim(FNCPort);

        if (FNCHost = '') then Exit;
        //if (FNCPort <> '') and (FNCPort <> Self.port) then Exit;

        {
        if  (Self.host <> '0.0.0.0') and (Self.Host <> '127.0.0.1') and
            (Self.host <> 'localhost') and (FNCHost <> Self.host) then Exit;
        }    

        //WEBSOCKET KEY
        s := headers.Values['sec-websocket-key'];
        if (s <> '') then
        begin
          if (Length(DecodeBase64(s)) = 16) then
          begin
            key := s;
          end;

        end;
        if (key = '') then Exit;
        key := trim(key);

        //WEBSOCKET VERSION
        s := headers.Values['sec-websocket-version'];
        if (s <> '') then
        begin
          vv := StrToIntDef(s, -1);

          if ((vv >= 7) and (vv <= 13)) then
          begin
            version := s;
          end;
        end;
        if (version = '') then Exit;
        version := trim(version);
        iversion := StrToIntDef(version, 13);

        if (LowerCase(headers.Values['upgrade']) <> LowerCase('websocket')) or (pos('upgrade', LowerCase(headers.Values['connection'])) = 0) then
          Exit;

        //COOKIES


        FNCProtocol := '-';
        tmpExtension := '-';
        FNCCookie := '-';
        FNCOrigin := '-';

        if (iversion < 13) then
        begin
          if (headers.IndexOfName('sec-websocket-origin') > -1) then
            FNCOrigin := trim(headers.Values['sec-websocket-origin']);
        end
        else begin
          if (headers.IndexOfName('origin') > -1) then
            FNCOrigin := trim(headers.Values['origin']);
        end;

        if (headers.IndexOfName('sec-websocket-protocol') > -1) then
          FNCProtocol := trim(headers.Values['sec-websocket-protocol']);
        if (headers.IndexOfName('sec-websocket-extensions') > -1) then
          tmpExtension := trim(headers.Values['sec-websocket-extensions']);
        if (headers.IndexOfName('cookie') > -1) then
          FNCCookie := trim(headers.Values['cookie']);

        FNCHeaders := trim(headers.text);

        {
        ODS(data);
        ODS(FNCHeaders);
        ODS('ResourceName: %s', [FNCResourceName]);
        ODS('Host: %s', [FNCHost]);
        ODS('Post: %s', [FNCPort]);
        ODS('Key: %s', [key]);
        ODS('Version: %s', [version]);
        ODS('Origin: %s', [FNCOrigin]);
        ODS('Protocol: %s', [FNCProtocol]);
        ODS('Extensions: %s', [FNCExtensions]);
        ODS('Cookie: %s', [FNCCookie]);
        {}

        // Account for client_max_window_bits, probably add more later on
        for extCounter := 1 to WordCount(tmpExtension, [';']) do begin
            tmpWord := ExtractWord(extCounter, tmpExtension, [' ', ';']);

            extensionKey := ExtractWord(1, tmpWord, ['=']);
            extensionValue := ExtractWord(2, tmpWord, ['=']);

            if Not IsWordPresent(extensionKey, FNCExtensions, [' ', ';', '=']) then begin
              FNCExtensions := FNCExtensions + extensionKey;

              if (extensionKey = 'client_max_window_bits') and (length(extensionValue) = 0) then
                FNCExtensions := FNCExtensions + '=15;'
              else begin
                if length(extensionValue) > 0 then
                  FNCExtensions := FNCExtensions + '=' + extensionValue + ';'
                else
                  FNCExtensions := FNCExtensions + ';'
              end;
            end;
        end;

        if FNCExtensions[length(FNCExtensions)] = ';' then
          Delete(FNCExtensions, Length(FNCExtensions), 1);

        res := True;
      finally
        if (res) then
        begin
          FNCResultHttp := 101;
          hrs := TStringList.Create;
          hrs.Assign(headers);
          r := GetWebSocketConnectionClass(
            FNCSocket,
            hrs,
            FNCResourceName, FNCHost, FNCPort, FNCOrigin, FNCCookie,
            FNCResultHttp, FNCProtocol,  FNCExtensions
          );
          if (Assigned(r)) then
          begin
            DoSyncReceiveConnection;
            if (FNCResultHttp <> 101) then //HTTP ERROR FALLBACK
            begin
              Socket.SendString(Format('HTTP/1.1 %d %s'+#13#10, [FNCResultHttp, HTTPCodeToText(FNCResultHttp)]));
              Socket.SendString(Format('%d %s'+#13#10#13#10, [FNCResultHttp, HTTPCodeToText(FNCResultHttp)]));
            end
            else
            begin

              key := EncodeBase64(SHA1(key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'));

              s :=        'HTTP/1.1 101 Switching Protocols' + #13#10;
              s := s +    'Upgrade: websocket' + #13#10;
              s := s +    'Connection: Upgrade' + #13#10;
              s := s +    'Sec-WebSocket-Accept: ' + key + #13#10;
              if (FNCProtocol <> '-') then
              begin
                s := s +  'Sec-WebSocket-Protocol: ' + FNCProtocol + #13#10;
              end;
              if (FNCExtensions <> '-') then
              begin
                s := s +  'Sec-WebSocket-Extensions: ' + FNCExtensions + #13#10;
              end;
              s := s + #13#10;

              Socket.SendString(s);
              if (Socket.LastError = 0) then
              begin
                Result := r.Create(Socket);
                TWebSocketCustomConnection(Result).fCookie := FNCCookie;
                TWebSocketCustomConnection(Result).fVersion := StrToInt(version);
                TWebSocketCustomConnection(Result).fProtocol := FNCProtocol;
                TWebSocketCustomConnection(Result).fResourceName := FNCResourceName;
                TWebSocketCustomConnection(Result).fOrigin := FNCOrigin;
                TWebSocketCustomConnection(Result).fExtension := FNCExtensions;
                TWebSocketCustomConnection(Result).fPort := FNCPort;
                TWebSocketCustomConnection(Result).fHost := FNCHost;
                TWebSocketCustomConnection(Result).fHeaders.Assign(headers);
                TWebSocketCustomConnection(Result).fHandshake := True;
              end;
            end;
          end;
          hrs.Free;
        end;
      end;
    end;
  finally
    headers.Free;
  end;
end;

procedure TWebSocketServer.DoSyncReceiveConnection;
begin
  if (Assigned(FOnReceiveConnection)) then
    Synchronize(SyncReceiveConnection)
end;

function TWebSocketServer.GetWebSocketConnectionClass(Socket: TTCPCustomConnectionSocket;
                                                      Header: TStringList;
                                                      ResourceName, Host, Port, Origin, Cookie: AnsiString;
                                                      out HttpResult: Integer;
                                                      var Protocol, Extensions: AnsiString): TWebSocketServerConnections;
begin
  Result := TWebSocketServerConnection;
end;

procedure TWebSocketServer.SyncReceiveConnection;
var
  h: TStringList;
begin
  if (Assigned(FOnReceiveConnection)) then
  begin
    h := TStringList.Create;
    try
      h.Text := FNCHeaders;
      FOnReceiveConnection(Self, FNCSocket, h, FNCResourceName,
                           FNCHost, FNCPort, FNCOrigin, FNCCookie, FNCResultHttp, FNCProtocol, FNCExtensions);
    finally
      h.Free;
    end;
  end;
end;

procedure TWebSocketServer.TerminateThread;
begin
  if Terminated then Exit;
  FOnReceiveConnection := nil;
  inherited;
end;

{ TWebSocketCustomConnection }

function TWebSocketCustomConnection.CanReceiveOrSend: Boolean;
begin
  Result := ValidConnection and not (FClosedByMe or FClosedByPeer) and FHandshake;
end;

function TWebSocketCustomConnection.SendData(Flags: TWSFlags; OpCode: Byte; Data: Pointer; DataSize: Integer): Integer;
var
  ms : TReadOnlyMemoryStream;
begin
  ms := TReadOnlyMemoryStream.Create(Data, DataSize);
  try
    Result := SendData(Flags, OpCode, ms);
  finally
    ms.Free;
  end;
end;

constructor TWebSocketCustomConnection.Create(Socket: TTCPCustomConnectionSocket);
begin
  FHeaders := TStringList.Create;
  FCookie := '';
  FVersion := 0;
  FProtocol := '-';
  FResourceName := '';
  FOrigin := '';
  FExtension := '-';
  FPort := '';
  FHost := '';
  FClosedByMe := False;
  FClosedByPeer := False;
  FMasking := False;
  FClosingByPeer := False;
  FRequireMasking := False;

  FFullDataProcess := False;
  FFullDataStream := TMemoryStream.Create;

  FSendCriticalSection := TCriticalSection.Create;
  FHandshake := False;

  inherited;

end;

destructor TWebSocketCustomConnection.Destroy;
begin
  inherited;
  FSendCriticalSection.Free;
  FFullDataStream.Free;
  FHeaders.Free;
end;

procedure TWebSocketCustomConnection.DoOpen;
begin
  if Assigned(FOnOpen) then
    FOnOpen(Self);
end;

procedure TWebSocketCustomConnection.DoClose(CloseCode: Integer; CloseReason: AnsiString; ClosedByPeer: Boolean);
begin
  if Assigned(FOnClose) then
    FOnClose(Self, CloseCode, CloseReason, ClosedByPeer);
end;

procedure TWebSocketCustomConnection.DoPing(Data: AnsiString);
begin
  if Assigned(FOnPing) then
    FOnPing(Self, Data);
end;

procedure TWebSocketCustomConnection.DoPong(Data: AnsiString);
begin
  if Assigned(FOnPong) then
    FOnPong(Self, Data);
end;

procedure TWebSocketCustomConnection.DoRead(Flags: TWSFlags; OpCode: Byte; Data: TMemoryStream);
begin
  if Assigned(FOnRead) then
    FOnRead(Self, Flags, OpCode, Data);
end;

procedure TWebSocketCustomConnection.DoReadFull(OpCode: Byte; Data: TMemoryStream);
begin
  if Assigned(FOnReadFull) then
    FOnReadFull(Self, OpCode, Data);
end;

procedure TWebSocketCustomConnection.DoWrite(Flags: TWSFlags; OpCode: Byte; Data: TStream);
begin
  if Assigned(FOnWrite) then
    FOnWrite(Self, Flags, OpCode, Data);
end;

procedure TWebSocketCustomConnection.ProcessOpen;
begin
  DoOpen;
end;

procedure TWebSocketCustomConnection.ExecuteConnection;
var
  Res: Integer;
  //Data: AnsiString;
  CloseCode: Integer;
  CloseResult: AnsiString;
  LastDataOpCode, LastDataOpCode2: Integer;
  Flags: TWSFlags;
  OpCode: Byte;
  Stream: TMemoryStream;
  //Data: TStringStream;
begin
  Flags := [];
  OpCode := 0;
  Stream := TMemoryStream.Create;
  ProcessOpen;
  try
    //while(not IsTerminated) or fClosed do
    LastDataOpCode := -1;
    LastDataOpCode2 := -1;
    while CanReceiveOrSend do
    begin
      //OutputDebugString(pChar(Format('execute %d', [fIndex])));
      Res := ReadData(Flags, OpCode, Stream);
      if CanReceiveOrSend then
      begin
        if Res = 0 then // no socket error occured
        begin
          Stream.Position := 0;
//          ProcessReadData(Flags, OpCode, Stream);

          if (OpCode in [wsCodeText, wsCodeBinary]) and FFullDataProcess then
          begin
            FFullDataStream.Size := 0;
            FFullDataStream.Position := 0;
          end;
          if (OpCode in [wsCodeContinuation, wsCodeText, wsCodeBinary]) and FFullDataProcess then
          begin
            Stream.Position := 0;
            FFullDataStream.CopyFrom(Stream, Stream.Size);
          end;
          //if (FReadFinal) then //FIN frame
          begin
            case OpCode of
              wsCodeContinuation: begin
                                    if LastDataOpCode in [wsCodeText, wsCodeBinary] then
                                    begin
                                      Stream.Position := 0;
                                      ProcessReadData(Flags, OpCode, Stream);
                                    end
                                    else Close(wsCloseErrorProtocol, 'Unknown continuaton');
                                    if FIN in Flags then
                                      LastDataOpCode := -1;
                                  end;
              wsCodeText        : begin // text, binary frame
                                    Stream.Position := 0;
                                    ProcessReadData(Flags, OpCode, Stream);
                                    if not (FIN in Flags) then
                                      LastDataOpCode := wsCodeText
                                    else
                                      LastDataOpCode := -1;
                                    LastDataOpCode2 := wsCodeText;
                                  end;
              wsCodeBinary      : begin // text, binary frame
                                    Stream.Position := 0;
                                    ProcessReadData(Flags, OpCode, Stream);
                                    if not (FIN in Flags) then
                                      LastDataOpCode := wsCodeBinary
                                    else
                                      LastDataOpCode := -1;
                                    LastDataOpCode2 := wsCodeBinary;
                                  end;
              wsCodeClose       : begin //connection close
                                    CloseCode := wsCloseNoStatus;
                                    Stream.Position := 0;
                                    CloseResult := ReadStrFromStream(Stream, Stream.Size);
                                    if Length(CloseResult) > 1 then
                                    begin
                                      CloseCode := Ord(CloseResult[1]) shl 8 or Ord(CloseResult[2]);
                                      Delete(CloseResult, 1, 2);
                                    end;
                                    FClosedByPeer := True;
                                    //OutputDebugString(pChar(Format('closing1 %d', [fIndex])));
                                    ProcessClose(closeCode, closeResult, True);
                                    //OutputDebugString(pChar(Format('closing2 %d', [fIndex])));
                                    TerminateThread;
                                    //OutputDebugString(pChar(Format('closing3 %d', [fIndex])));
//                                    FSendCriticalSection.Enter;
                                  end;
              wsCodePing        : begin // ping
                                    Stream.Position := 0;
                                    ProcessPing(ReadStrFromStream(Stream, Stream.Size));
                                  end;
              wsCodePong        : begin // pong
                                    Stream.Position := 0;
                                    ProcessPong(ReadStrFromStream(Stream, Stream.Size));
                                  end
              else begin //ERROR
                Close(wsCloseErrorData, Format('Unknown data type: %d', [OpCode]));
              end;
            end;
          end;

          if (OpCode in [wsCodeContinuation, wsCodeText, wsCodeBinary]) and FFullDataProcess and (FIN in Flags) then
          begin
            if LastDataOpCode2 in [wsCodeText, wsCodeBinary] then begin
              FFullDataStream.Position := 0;
              ProcessReadDataFull(Flags, OpCode, FFullDataStream);
            end;
          end;
        end
        else
          TerminateThread;
      end;
    end;
  finally
    FreeAndNil(Stream);
//    {$IFDEF UNIX} Sleep(2000); {$ENDIF UNIX}
  end;
{  while not Terminated do
    Sleep(500);}
  //OutputDebugString(pChar(Format('terminating %d', [fIndex])));
//  FSendCriticalSection.Enter;
end;

function TWebSocketCustomConnection.GetClosed: Boolean;
begin
  Result := not CanReceiveOrSend;
end;

function TWebSocketCustomConnection.GetClosing: Boolean;
begin
  Result := FClosedByMe or FClosedByPeer;
end;

procedure TWebSocketCustomConnection.Ping(Data: AnsiString);
begin
  if CanReceiveOrSend then
  begin
    SendData([FIN], wsCodePing, Data);
  end;
end;

procedure TWebSocketCustomConnection.Pong(Data: AnsiString);
begin
  if (CanReceiveOrSend) then
  begin
    SendData([FIN], wsCodePong, Data);
  end;
end;

procedure TWebSocketCustomConnection.ProcessClose(CloseCode: Integer; CloseReason: AnsiString; ClosedByPeer: Boolean);
begin
  FCloseCode := CloseCode;
  FCloseReason := CloseReason;
  FClosingByPeer := ClosedByPeer;
  DoClose(CloseCode, CloseReason, ClosedByPeer);
end;


procedure TWebSocketCustomConnection.ProcessPing(Data: AnsiString);
begin
  DoPing(Data);
  Pong(Data);
end;

procedure TWebSocketCustomConnection.ProcessPong(Data: AnsiString);
begin
  DoPong(Data);
end;

procedure TWebSocketCustomConnection.ProcessReadData(var Flags: TWSFlags; var OpCode: Byte; Data: TMemoryStream);
begin
  DoRead(Flags, OpCode, Data);
end;

procedure TWebSocketCustomConnection.ProcessReadDataFull(var Flags: TWSFlags; var OpCode: Byte; Data: TMemoryStream);
begin
  DoReadFull(OpCode, Data);
end;

procedure TWebSocketCustomConnection.ProcessWriteData(var Flags: TWSFlags; var OpCode: Byte; Data: TStream);
begin
  DoWrite(Flags, OpCode, Data);
end;

function GetByte(Socket: TTCPCustomConnectionSocket; out Val: Byte; Timeout: Integer): Integer;
begin
  Val := Socket.RecvByte(Timeout);
  Result := Socket.LastError;
end;

function HexToStr(Dec: Integer; Len: Integer): AnsiString;
var
  tmp: AnsiString;
  i: Integer;
begin
  tmp := IntToHex(Dec, Len);
  Result := '';
  for i := 1 to (Length(tmp) + 1) div 2 do
  begin
    Result := Result + AnsiChar(StrToInt('$'+Copy(tmp, i * 2 - 1, 2)));
  end;
end;

function StrToHexStr2(str: AnsiString): AnsiString;
var
  i: Integer;
begin
  Result := '';
  for i := 1 to Length(str) do
    Result := Result + IntToHex(Ord(str[i]), 2) + ' ';
end;


function TWebSocketCustomConnection.ReadData(out Flags: TWSFlags; out OpCode: Byte; Data: TMemoryStream): Integer;
var
  timeout: Integer;
  b: byte;
  mask: Boolean;
  len, i: Int64;
  DataPtr: PByte;
  mBytes: array[0..3] of byte;
begin
  Result := 0;
  len := 0;
  //Code := 0;
  repeat
    timeout := 10 * 1000;
    if CanReceiveOrSend then
    begin
      //OutputDebugString(pChar(Format('%d', [Index])));
      if FSocket.CanReadEx(1000) then
      begin
        if CanReceiveOrSend then
        begin
          b := FSocket.RecvByte(1000);
          if FSocket.LastError = 0 then
          begin
            try
              // BASIC INFORMATIONS
              Flags := [];
              if b and $80 <> 0 then
                Include(Flags, FIN);
              if b and $40 <> 0 then
                Include(Flags, RSV1);
              if b and $20 <> 0 then
                Include(Flags, RSV2);
              if b and $10 <> 0 then
                Include(Flags, RSV3);
              OpCode := b and $F;


              // MASK AND LENGTH
              mask := False;
              Result := GetByte(FSocket, b, timeout);
              if Result = 0 then
              begin
                mask := (b and $80) = $80;
                len := (b and $7F);
                if len = 126 then
                begin
                  Result := GetByte(FSocket, b, timeout);
                  if Result = 0 then
                  begin
                    len := b * $100; // 00 00
                    Result := GetByte(FSocket, b, timeout);
                    if Result = 0 then
                    begin
                      len := len + b;
                    end;
                  end;
                end
                else if len = 127 then    //00 00 00 00 00 00 00 00
                begin
                  //TODO nesting og get byte should be different
                  Result := GetByte(FSocket, b, timeout);
                  if Result = 0 then
                  begin
                    len := b * $100000000000000;
                    if Result = 0 then
                    begin
                      Result := GetByte(FSocket, b, timeout);
                      len := len + b * $1000000000000;
                    end;
                    if Result = 0 then
                    begin
                      Result := GetByte(FSocket, b, timeout);
                      len := len + b * $10000000000;
                    end;
                    if Result = 0 then
                    begin
                      Result := GetByte(FSocket, b, timeout);
                      len := len + b * $100000000;
                    end;
                    if Result = 0 then
                    begin
                      Result := GetByte(FSocket, b, timeout);
                      len := len + b * $1000000;
                    end;
                    if Result = 0 then
                    begin
                      Result := GetByte(FSocket, b, timeout);
                      len := len + b * $10000;
                    end;
                    if Result = 0 then
                    begin
                      Result := GetByte(FSocket, b, timeout);
                      len := len + b * $100;
                    end;
                    if Result = 0 then
                    begin
                      Result := GetByte(FSocket, b, timeout);
                      len := len + b;
                    end;
                  end;
                end;
              end;

              if (Result = 0) and FRequireMasking and not mask then
              begin
                // TODO some protocol error
                raise Exception.Create('mask');
              end;

              // MASKING KEY
              if mask and (Result = 0) then
              begin
                Result := GetByte(FSocket, mBytes[0], timeout);
                if Result = 0 then
                  Result := GetByte(FSocket, mBytes[1], timeout);
                if Result = 0 then
                  Result := GetByte(FSocket, mBytes[2], timeout);
                if Result = 0 then
                  Result := GetByte(FSocket, mBytes[3], timeout);
              end;
              // READ DATA
              if Result = 0 then
              begin
                Data.Clear;
                timeout := 1000 * 60 * 60 * 2; //(len div (1024 * 1024)) * 1000 * 60;
                FSocket.RecvStreamSize(Data, timeout, len);
                Result := FSocket.LastError;
                if Result = 0 then
                begin
                  if mask then
                  begin
                    DataPtr := Data.Memory;
                    for i := 0 to len - 1 do
                    begin
                      DataPtr^ := DataPtr^ xor mBytes[i mod 4];
                      inc(DataPtr);
                    end;
                  end;
                end
                else
                  Data.Clear;
                Data.Position := 0;
                Break;
              end;
            except
              Result := -1;
            end;
          end
          else
            Result := -1;
        end
        else
          Result := -1;
      end
      else
      begin
//        if (FSocket.CanRead(0)) then
//          ODS(StrToHexstr2(FSocket.RecvBufferStr(10, 1000)));
        if (FSocket.LastError <> WSAETIMEDOUT) and (FSocket.LastError <> 0) then
        begin
          //if (FSocket.LastError = WS then
          Result := -1;
        end;
      end;
    end
    else
      Result := -1;
    if (Result <> 0) then
    begin
      if not Terminated then
      begin
        if FSocket.LastError = WSAECONNRESET then
        begin
          Result := 0;
          OpCode := wsCodeClose;
          Flags := [FIN];
          Data.Size := 0;
          WriteStrToStream(Data, AnsiChar(wsCloseErrorClose div 256) + AnsiChar(wsCloseErrorClose mod 256));
          Data.Position := 0;
        end
        else
        begin
          if not FClosedByMe then
          begin
            Close(wsCloseErrorProtocol, '');
            TerminateThread;
          end;
        end;
      end;
      Break;
    end
  until False;
end;

function TWebSocketCustomConnection.SendData(Flags: TWSFlags; OpCode: Byte; Data: TStream): Integer;
var
  b: byte;
  s: ansistring;
  mBytes: array[0..3] of byte;
  DataPtr: PByte;
  i: Int64;
begin
  Result := 0;
  if CanReceiveOrSend or ((OpCode = wsCodeClose) and (not FClosedByPeer)) then
  begin
    FSendCriticalSection.Enter;
    try
      s := '';
      // BASIC INFORMATIONS
      b := 0;
      if FIN in Flags then
        b := b or $80;
      if RSV1 in Flags then
        b := b or $40;
      if RSV2 in Flags then
        b := b or $20;
      if RSV3 in Flags then
        b := b or $10;
      b := b + OpCode;
      s := s + AnsiChar(b);

      // MASK AND LENGTH
      b := IfThen(FMasking, 1, 0) * $80;
      if Data.Size < 126 then
        b := b + Data.Size
      else if Data.Size < 65536 then
        b := b + 126
      else
        b := b + 127;
      s := s + AnsiChar(b);
      if Data.Size >= 126 then
      begin
        if Data.Size < 65536 then
        begin
          s := s + HexToStr(Data.Size, 4);
        end
        else
        begin
          s := s + HexToStr(Data.Size, 16);
        end;
      end;

      // MASKING KEY
      if FMasking then
      begin
        mBytes[0] := Random(256);
        mBytes[1] := Random(256);
        mBytes[2] := Random(256);
        mBytes[3] := Random(256);


        s := s + AnsiChar(mBytes[0]);
        s := s + AnsiChar(mBytes[1]);
        s := s + AnsiChar(mBytes[2]);
        s := s + AnsiChar(mBytes[3]);
      end;

      FSocket.SendString(s);
      Result := FSocket.LastError;
      if Result = 0 then
      begin
        Data.Position := 0;
        if not FMasking then
        begin
          FSocket.SendStreamRaw(Data);
        end
        else
        begin
          SetLength(s, Data.Size);
          DataPtr := PByte(PAnsiChar(s));
          Data.ReadBuffer(DataPtr^, Length(s));
          for i := 0 to Length(s) - 1 do
          begin
            DataPtr^ := DataPtr^ xor mBytes[i mod 4];
            Inc(DataPtr);
          end;
          FSocket.SendString(s);
        end;

        Result := FSocket.LastError;
        if (Result = 0) then
        begin
          Data.Position := 0;
          ProcessWriteData(Flags, OpCode, Data);
        end;
      end;
    finally
      if OpCode <> wsCodeClose then
        while not FSocket.CanWrite(10) do
          Sleep(10);
      FSendCriticalSection.Leave;
    end;
  end;
end;

function TWebSocketCustomConnection.SendData(Flags: TWSFlags; OpCode: Byte; Data: AnsiString): Integer;
var
  ms : TReadOnlyMemoryStream;
begin
  ms := TReadOnlyMemoryStream.Create(PAnsiChar(Data), Length(Data));
  try
    Result := SendData(Flags, OpCode, ms);
  finally
    ms.Free;
  end;
end;

function TWebSocketCustomConnection.SendDataSplitted(OpCode: Byte; Data: Pointer; DataSize: Int64; SplitSize: Integer): Integer;
var
  ms: TReadOnlyMemoryStream;
  BatchSize: Integer;
  Flags: TWSFlags;
begin
  if DataSize <= 0 then
    Exit(0);
  ms := TReadOnlyMemoryStream.Create(Data, DataSize);
  try
    if DataSize <= SplitSize then
      Result := SendData([FIN], OpCode, ms)
    else begin
      BatchSize := SplitSize;
      Flags := [];
      repeat
        if BatchSize >= DataSize then begin
          BatchSize := DataSize;
          Flags := [FIN]
				end;
				ms.ResetPointer(Data, BatchSize);
        Result := SendData(Flags, wsCodeContinuation, ms);
        if Result <> 0 then
          Break;
        Inc(PByte(Data), BatchSize);
        Dec(DataSize, BatchSize);
			until DataSize = 0;
		end;
	finally
    ms.Free;
  end;
end;

function TWebSocketCustomConnection.SendDataSplitted(OpCode: Byte; Data: TStream; SplitSize: Integer): Integer;
var
  ms: TMemoryStream;
  DataSize, BatchSize: Integer;
  Flags: TWSFlags;
begin
  DataSize := Data.Size;
  if DataSize <= SplitSize then
    Result := SendData([FIN], OpCode, Data)
  else begin
    ms := TMemoryStream.Create;
    try
      BatchSize := SplitSize;
      Flags := [];
      repeat
        if BatchSize >= DataSize then begin
          BatchSize := DataSize;
          Flags := [FIN]
				end;
				ms.Position := 0;
        ms.CopyFrom(Data, BatchSize);
        ms.Size := BatchSize;
        Result := SendData(Flags, wsCodeContinuation, ms);
        if Result <> 0 then
          Break;
        Dec(DataSize, BatchSize);
			until DataSize = 0;
    finally
      ms.Free;
    end;
  end;
end;

procedure TWebSocketCustomConnection.SendBinary(Data: TStream; Flags: TWSFlags);
begin
  SendData(Flags, wsCodeBinary, Data);
end;

procedure TWebSocketCustomConnection.SendBinarySplitted(Data: TStream; SplitSize: Integer);
begin
  SendDataSplitted(wsCodeBinary, Data, SplitSize)
end;

procedure TWebSocketCustomConnection.SendBinaryContinuation(Data: TStream; Flags: TWSFlags);
begin
  SendData(Flags, wsCodeContinuation, Data);
end;

procedure TWebSocketCustomConnection.SendText(Data: AnsiString; Flags: TWSFlags);
begin
  SendData(Flags, wsCodeText, Data);
end;

procedure TWebSocketCustomConnection.SendTextSplitted(Data: AnsiString; SplitSize: Integer);
begin
  SendDataSplitted(wsCodeText, PAnsiChar(Data), Length(Data), SplitSize)
end;

procedure TWebSocketCustomConnection.SendTextContinuation(Data: AnsiString; Flags: TWSFlags);
begin
  SendData(Flags, wsCodeContinuation, Data);
end;

{
procedure TWebSocketCustomConnection.SendStream(IsFinal: Boolean; ExtFlags: Byte; Data: TStream);
begin
  if (CanReceiveOrSend) then
  begin
    SendData(IsFinal, aRes1, aRes2, aRes3, wsCodeBinary, Data);
  end;
end;
}
{
procedure TWebSocketCustomConnection.SendStream(Data: TStream);
begin
  //SendStream(IsFinal, False, False, False, Data);
end;
}
{
procedure TWebSocketCustomConnection.SendText(IsFinal: Boolean; ExtFlags: Byte; Data: AnsiString);
//var tmp: AnsiString;
begin
  if (CanReceiveOrSend) then
  begin
    SendData(IsFinal, False, False, False, wsCodeText, Data);
  end;
end;
}
{
procedure TWebSocketCustomConnection.SendText(Data: AnsiString);
begin
  //SendText(True, False, False, False, Data);
  //SendData(True, False, False
end;
}

procedure TWebSocketCustomConnection.TerminateThread;
begin
  if Terminated then
    Exit;

  if not Closed then
    DoClose(FCloseCode, FCloseReason, FClosedByPeer);
  Socket.OnSyncStatus := nil;
  Socket.OnStatus := nil;
  FOnRead := nil;
  FOnReadFull := nil;
  FOnWrite := nil;
  FOnClose := nil;
  FOnOpen := nil;
  {
  if not Closing then
  begin
    SendData(True, False, False, False, wsCodeClose, '1001');
  end;
  }
  inherited;
end;

function TWebSocketCustomConnection.ValidConnection: Boolean;
begin
  Result := not IsTerminated and (Socket.Socket <> INVALID_SOCKET);
end;

{ TWebSocketServerConnection }

procedure TWebSocketServerConnection.Close(CloseCode: Integer; CloseReason: AnsiString);
begin
  if (Socket.Socket <> INVALID_SOCKET) and not FClosedByMe then
  begin
    FClosedByMe := True;
    if not FClosedByPeer then
    begin
      SendData([FIN], wsCodeClose, HexToStr(CloseCode, 4) + Copy(CloseReason, 1, 123));
      //Sleep(2000);
      ProcessClose(CloseCode, CloseReason, False);
    end;

    TerminateThread;
  end;
end;

constructor TWebSocketServerConnection.Create(Socket: TTCPCustomConnectionSocket);
begin
  inherited;
  FRequireMasking := True;
end;

procedure TWebSocketServerConnection.TerminateThread;
begin
  if Terminated then
    Exit;
  //if (not TWebSocketServer(fParent).Terminated) and (not FClosedByMe) then DoSyncClose;
  FOnClose := nil;
  inherited;
end;

{ TWebSocketClient }

function TWebSocketClient.BeforeExecuteConnection: Boolean;
var
  key, s, Data: AnsiString;
  i: Integer;
  headers: TStringList;
begin
  Result := not IsTerminated;
  if Result then
  begin
    s := Format('GET %s HTTP/1.1' + #13#10, [FResourceName]);
    s := s + Format('Upgrade: websocket' + #13#10, []);
    s := s + Format('Connection: Upgrade' + #13#10, []);
    s := s + Format('Host: %s:%s' + #13#10, [FHost, FPort]);

    key := '';
    for I := 1 to 16 do
      key := key + ansichar(Random(85) + 32);
    key := EncodeBase64(key);
    s := s + Format('Sec-WebSocket-Key: %s' + #13#10, [(key)]);
    s := s + Format('Sec-WebSocket-Version: %d' + #13#10, [FVersion]);

    //TODO extensions
    if (FProtocol <> '-') then
      s := s + Format('Sec-WebSocket-Protocol: %s' + #13#10, [FProtocol]);
    if (FOrigin <> '-') then
    begin
      if (FVersion < 13) then
        s := s + Format('Sec-WebSocket-Origin: %s' + #13#10, [FOrigin])
      else
        s := s + Format('Origin: %s' + #13#10, [FOrigin]);
    end;
    if (FCookie <> '-') then
      s := s + Format('Cookie: %s' + #13#10, [(FCookie)]);
    if (FExtension <> '-') then
      s := s + Format('Sec-WebSocket-Extensions: %s' + #13#10, [FExtension]);
    s := s + #13#10;
    FSocket.SendString(s);
    Result := (not IsTerminated) and (FSocket.LastError = 0);
    if Result then
    begin
      headers := TStringList.Create;
      try
        Result := ReadHttpHeaders(FSocket, Data, headers);
        if Result then Result := pos(LowerCase('HTTP/1.1 101'), LowerCase(Data)) = 1;
        if Result then Result := (LowerCase(headers.Values['upgrade']) = LowerCase('websocket')) and (LowerCase(headers.Values['connection']) = 'upgrade');
        FProtocol := '-';
        FExtension := '-';
        if (headers.IndexOfName('sec-websocket-protocol') > -1) then
          FProtocol := trim(headers.Values['sec-websocket-protocol']);
        if (headers.IndexOfName('sec-websocket-extensions') > -1) then
          FExtension := trim(headers.Values['sec-websocket-extensions']);
        if Result then Result := (headers.Values['sec-websocket-accept'] = EncodeBase64(SHA1(key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11')));

      finally
        headers.Free;
      end;
    end;

  end;
  if Result then begin
    FHandshake := True;
    FEvent.SetEvent;
  end;
end;

procedure TWebSocketClient.Close(CloseCode: Integer; CloseReason: AnsiString);
begin
  if ValidConnection and not FClosedByMe then
  begin
    FClosedByMe := True;
    if not FClosedByPeer then
    begin
      SendData([FIN], wsCodeClose, HexToStr(CloseCode, 4) + Copy(CloseReason, 1, 123));
      //Sleep(2000);
      ProcessClose(CloseCode, CloseReason, False);
    end;

    TerminateThread;
  end;
end;

constructor TWebSocketClient.Create(Host, Port, ResourceName: AnsiString; Origin: AnsiString; Protocol: AnsiString; Extension: AnsiString; Cookie: AnsiString; Version: Integer);
begin
  FEvent := TSimpleEvent.Create;
  FSocket := TTCPCustomConnectionSocket.Create;
  inherited Create(FSocket);
  FOrigin := Origin;
  FHost := Host;
  FPort := Port;
  FResourceName := ResourceName;
  FProtocol := Protocol;
  FVersion := Version;
  FMasking := True;
  FCookie := Cookie;
  FExtension := Extension;
end;

constructor TWebSocketClient.CreateFromURL(URL: AnsiString; Origin: AnsiString; Protocol: AnsiString; Extension: AnsiString; Cookie: AnsiString; Version: Integer);
var
  Proto, Username, Password, Host, Port, Path, Parameters, URI: AnsiString;
begin
  URI := ParseURL(URL, Proto, Username, Password, Host, Port, Path, Parameters);
  Create(Host, Port, URI, Origin, Protocol, Extension, Cookie, Version);
  Proto := LowerCase(Proto);
  UseSSL := (Proto = 'wss') or (Proto = 'https');
end;

destructor TWebSocketClient.Destroy;
begin
  inherited Destroy;
  FreeAndNil(FEvent);
end;

function TWebSocketClient.WaitForConnect(Timeout: Cardinal): Boolean;
begin
  Start;
  Result := CanReceiveOrSend or (FEvent.WaitFor(Timeout) = TWaitResult.wrSignaled);
end;

procedure TWebSocketClient.Execute;
begin
  if not IsTerminated and (FVersion >= 8) then
  begin
    DoConnect;
    if FSocket.LastError = 0 then
    begin
      //DoConnect;
      inherited Execute;
      //DoDisconnect;
    end
    else TerminateThread;
  end;
end;

procedure TWebSocketClient.DoConnect;
begin
  if ValidConnection and ((FSocket.LastError <> 0) or (FSocket.SSL.SSLEnabled and UseSSL)) then
    FSocket.CloseSocket;
  if not ValidConnection then begin
    FSocket.Connect(FHost, FPort);
    if UseSSL and (FSocket.LastError = 0) then
      FSocket.SSLDoConnect;
  end;
end;

initialization
  Randomize;

{
GET / HTTP/1.1
Upgrade: websocket
Connection: Upgrade
Host: 81.0.231.149:81
Sec-WebSocket-Origin: http://html5.bauglir.dev
Sec-WebSocket-Key: Q9ceXTuzjdF2o23CRYvnuA==
Sec-WebSocket-Version: 8


GET / HTTP/1.1
Host: 81.0.231.149:81
User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:6.0) Gecko/20100101 Firefox/6.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: sk,cs;q=0.8,en-us;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
Accept-Charset: ISO-8859-2,utf-8;q=0.7,*;q=0.7
Connection: keep-alive, Upgrade
Sec-WebSocket-Version: 7
Sec-WebSocket-Origin: http://html5.bauglir.dev
Sec-WebSocket-Key: HgBKcPfdBSzjCYxGnWCO3g==
Pragma: no-cache
Cache-Control: no-cache
Upgrade: websocket
Cookie: __utma=72544661.1949147240.1313811966.1313811966.1313811966.1; __utmb=72544661.3.10.1313811966; __utmc=72544661; __utmz=72544661.1313811966.1.1.utmcsr=localhost|utmccn=(referral)|utmcmd=referral|utmcct=/websocket/index.php
1300}

end.
