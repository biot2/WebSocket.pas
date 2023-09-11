{==============================================================================|
| Project : Object Pascal WebSocket Client/Server Library                      |
|==============================================================================|
| Content: Generic connection and server classes                               |
|==============================================================================|
| Copyright (c)2023, Vahid Nasehi Oskouei                                      |
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
|   https://github.com/biot2/libWebSocket.pas                                      |
| WebSocket RFC:                                                               |
|   http://tools.ietf.org/html/rfc6455                                         |
|                                                                              |
|                                                                              |
|==============================================================================|
| Requirements: Ararat Synapse (http://www.ararat.cz/synapse/)                 |
|==============================================================================}

unit WebSocket.Helper;

{$IFDEF FPC}
  {$MODE DELPHI}
{$ENDIF}
{$H+}

interface

uses
  {$IFDEF UNIX}
  cthreads,
  {$ENDIF}
  Classes, SysUtils, blcksock, syncobjs, Sockets, ssl_openssl;

type
  TCustomServer = class;
  TCustomConnection = class;

  {:abstract(Socket used for @link(TCustomConnection)) }
  TTCPCustomConnectionSocket = class(TTCPBlockSocket)
  protected
    FConnection: TCustomConnection;
    FCurrentStatusReason: THookSocketReason;
    FCurrentStatusValue: string;
    FOnSyncStatus: THookSocketStatus;

    procedure DoOnStatus(Sender: TObject; Reason: THookSocketReason; const Value: String);
    procedure SyncOnStatus;
  public
    constructor Create;

    destructor Destroy; override;

    {:Owner (@link(TCustomConnection))}
    property Connection: TCustomConnection read FConnection;
    {:Socket status event (synchronized to main thread)}
    property OnSyncStatus: THookSocketStatus read FOnSyncStatus write FOnSyncStatus;
  end;


  {:abstract(Basic connection thread)
    This object is used from server and client as working thread.


    When object is server connection: object is created automatically by @link(Parent) server.
    Thread can be Terminated from outside. If server is Terminated, all remaining
    connections are closed. This object is used to communicate with client.
    Object should not be created directly.
  }
  TCustomConnection = class(TThread)
  private
  protected
    FIndex: Integer;
    FParent: TCustomServer;
    FSocket: TTCPCustomConnectionSocket;
    FUseSSL: Boolean;
    procedure AfterConnectionExecute; virtual;
    function BeforeExecuteConnection: Boolean; virtual;
    procedure ExecuteConnection; virtual;
    function GetIsTerminated: Boolean;
    {:Thread execute method}
    procedure Execute; override;
  public
    constructor Create(Socket: TTCPCustomConnectionSocket); virtual;
    destructor Destroy; override;

    {:Thread resume method}
    procedure Start;
    {:Thread suspend method}
    procedure Stop;

    {:Temination procedure
      One should call this procedure to terminate thread,
      it internally calls Terminate, but can be overloaded,
      and can be used for clean um
    }
    procedure TerminateThread; virtual;

    {:@Connection index.
      Automatically generated.
    }
    property Index: Integer read FIndex;
    {:@True if thread is not Terminated and @link(Socket) exists}
    property IsTerminated: Boolean read GetIsTerminated;
    {:@Connection parent
      If client connection, this property is always nil, if server
      connection, this property is @link(TCustomServer) that created this connection
    }
    property Parent: TCustomServer read FParent;

    {:@Connection socket}
    property Socket: TTCPCustomConnectionSocket read FSocket;
    {:Whether SSL is used}
    property UseSSL: Boolean read FUseSSL write FUseSSL;
  end;



  { TCustomServerConnection

  TCustomServerConnection = class(TCustomConnection)
  protected
    fBroadcastData: TStringList;
    fBroadcastLock: TCriticalSection;
    fParent: TCustomServer;

    //procedure ExecuteConnection; override;
    procedure SyncConnectionRemove;
  public
    constructor Create(aSocket: TTCPCustomServerConnectionSocket; aParent: TCustomServer); reintroduce; virtual;
    destructor Destroy; override;
    procedure Execute; override;

    :Data setup by server's Broadcast method.
      Connection is responsible to send data the data itself.
      Connection must delete the data after sending.

    procedure Broadcast(aData: string); virtual;

  end;
  }

  {:abstract(Class of connections)}
//  TCustomServerConnections = class of TCustomConnection;

  {:Event procedural type to hook OnAfterAddConnection in server
    Use this hook to get informations about connection accepted server that was added
  }
  TServerAfterAddConnection = procedure(Server: TCustomServer; Connection: TCustomConnection) of object;
  {:Event procedural type to hook OnBeforeAddConnection in server
    Use this hook to be informed that connection is about to be accepred by server.
    Use CanAdd parameter (@false) to refuse connection
  }
  TServerBeforeAddConnection = procedure(Server: TCustomServer; Connection: TCustomConnection; var CanAdd: Boolean) of object;
  {:Event procedural type to hook OnAfterRemoveConnection in server
    Use this hook to get informations about connection removed from server (connection is closed)
  }
  TServerAfterRemoveConnection = procedure(Server: TCustomServer; Connection: TCustomConnection) of object;
  {:Event procedural type to hook OnAfterRemoveConnection in server
    Use this hook to get informations about connection removed from server (connection is closed)
  }
  TServerBeforeRemoveConnection = procedure(Server: TCustomServer; Connection: TCustomConnection) of object;
  {:Event procedural type to hook OnSockedError in server
    Use this hook to get informations about error on server binding
  }
  TServerSocketError = procedure(Server: TCustomServer; Socket: TTCPBlockSocket) of object;


  {:abstract(Server listening on address and port and spawning @link(TCustomConnection))
    Use this object to create server. Object is accepting connections and creating new
    server connection objects (@link(TCustomConnection))
  }
  TCustomServer = class(TThread)
  private

  protected
    FBind: string;
    FPort: string;
    FCanAddConnection: Boolean;
    FConnections: TList;
    FConnectionTermLock: TCriticalSection;
    FCurrentAddConnection: TCustomConnection;
    FCurrentRemoveConnection: TCustomConnection;
    FCurrentSocket: TTCPBlockSocket;
    FIndex: Integer;
    FMaxConnectionsCount: Integer;
    FOnAfterAddConnection: TServerAfterAddConnection;
    FOnAfterRemoveConnection: TServerAfterRemoveConnection;
    FOnBeforeAddConnection: TServerBeforeAddConnection;
    FOnBeforeRemoveConnection: TServerBeforeRemoveConnection;
    FOnSocketErrot: TServerSocketError;
    FSSL: Boolean;
    FSSLCertificateFile: string;
    FSSLKeyPassword: string;
    FSSLPrivateKeyFile: string;

    function AddConnection(var aSocket: TTCPCustomConnectionSocket): TCustomConnection; virtual;
    {:Main function to determine what kind of connection will be used
      @link(AddConnection) uses this functino to actually create connection thread
    }
    function CreateServerConnection(aSocket: TTCPCustomConnectionSocket): TCustomConnection; virtual;
    procedure DoAfterAddConnection; virtual;
    procedure DoBeforeAddConnection;
    procedure DoAfterRemoveConnection;
    procedure DoBeforeRemoveConnection;
    procedure DoSocketError;
    function GetConnection(Index: Integer): TCustomConnection;
    function GetConnectionByIndex(Index: Integer): TCustomConnection;
    function GetCount: Integer;
    procedure OnConnectionTerminate(Sender: TObject);
    procedure RemoveConnection(Connection: TCustomConnection);
    procedure SyncAfterAddConnection;
    procedure SyncBeforeAddConnection;
    procedure SyncAfterRemoveConnection;
    procedure SyncBeforeRemoveConnection;
    procedure SyncSocketError;
  public
    {:Create new server
      aBind represents local IP address server will be listening on.
      IP address may be numeric or symbolic ('192.168.74.50', 'cosi.nekde.cz', 'ff08::1').
      You can use for listening 0.0.0.0 for localhost

      The same for aPort it may be number or mnemonic port ('23', 'telnet').

      If port value is '0', system chooses itself and conects unused port in the
      range 1024 to 4096 (this depending by operating system!).

      Warning: when you call : Bind('0.0.0.0','0'); then is nothing done! In this
      case is used implicit system bind instead.
    }
    constructor Create(Bind: string; Port: string); virtual;
    destructor Destroy; override;
    procedure Execute; override;

    {:Temination procedure
      This method should be called instead of Terminate to terminate thread,
      it internally calls Terminate, but can be overloaded,
      and can be used for data clean up
    }   
    procedure TerminateThread; virtual;


    { :Method used co send the same data to all server connections.
      Method only stores data in connection (append to existing data).
      Connection must send and delete the data itself.
    }
    //procedure Broadcast(aData: string); virtual;

    {: Procedure to stop removing connections from connections list in case there
      is need to walk through it
    }
    procedure LockTermination;
    {:Thread resume method}
    procedure Start;
    {:Thread suspend method}
    procedure Stop;
    {: Procedure to resume removing connections. see LockTermination
    }
    procedure UnLockTermination;



    {:Get connection from connection list
      Index represent index within connection list (not Connection.Index property)
    }
    property Connection[Index: Integer]: TCustomConnection read GetConnection; default;
    {:Get connection by its Index}
    property ConnectionByIndex[Index: Integer]: TCustomConnection read GetConnectionByIndex;
    {:Valid connections count}
    property Count: Integer read GetCount;
    {:IP address where server is listening (see aBind in constructor)}
    property Host: string read FBind;
    {:Server index. Automatically generated. }
    property Index: Integer read FIndex;
    {:Maximum number of accepted connections. -1 (default value) represents unlimited number.
      If limit is reached and new client is trying to connection, it's refused
    }
    property MaxConnectionsCount: Integer read FMaxConnectionsCount write FMaxConnectionsCount;
    {:Port where server is listening (see aPort in constructor)}
    property Port: string read FPort;
    {:Whether SSL is used}
    property SSL: Boolean read FSSL write FSSL;
    {:SSL certification file}
    property SSLCertificateFile: string read FSSLCertificateFile write FSSLCertificateFile;
    {:SSL key file}
    property SSLKeyPassword: string read FSSLKeyPassword write FSSLKeyPassword;
    {:SSL key file}
    property SSLPrivateKeyFile: string read FSSLPrivateKeyFile write FSSLPrivateKeyFile;


    {:See @link(TServerAfterAddConnection)}
    property OnAfterAddConnection: TServerAfterAddConnection read FOnAfterAddConnection write FOnAfterAddConnection;
    {:See @link(TServerBeforeAddConnection)}
    property OnBeforeAddConnection: TServerBeforeAddConnection read FOnBeforeAddConnection write FOnBeforeAddConnection;
    {:See @link(TServerAfterRemoveConnection)}
    property OnAfterRemoveConnection: TServerAfterRemoveConnection read FOnAfterRemoveConnection write FOnAfterRemoveConnection;
    {:See @link(TServerBeforeRemoveConnection)}
    property OnBeforeRemoveConnection: TServerBeforeRemoveConnection read FOnBeforeRemoveConnection write FOnBeforeRemoveConnection;
    {:See @link(TServerSocketError)}
    property OnSocketError: TServerSocketError read FOnSocketErrot write FOnSocketErrot;
  end;


implementation

uses
  SynSock {$IFDEF WIN32}, Windows {$ENDIF WIN32};

var
  FConnectionsIndex: Integer = 0;


function getConnectionIndex: Integer;
begin
  Result := FConnectionsIndex;
  Inc(FConnectionsIndex);
end;

{ TCustomServer }

procedure TCustomServer.OnConnectionTerminate(Sender: TObject);
begin
  try
    //OutputDebugString(pChar(Format('srv terminating 1 %d', [TCustomConnection(Sender).Index])));
//    FConnectionTermLock.Enter;
    //OutputDebugString(pChar(Format('srv terminating 2 %d', [TCustomConnection(Sender).Index])));
    RemoveConnection(TCustomConnection(Sender));
    //OutputDebugString(pChar(Format('srv terminating 3 %d', [TCustomConnection(Sender).Index])));
//    FConnectionTermLock.Leave;
  finally
  end;
  //OutputDebugString(pChar(Format('srv terminating e %d', [TCustomConnection(Sender).Index])));
end;

procedure TCustomServer.RemoveConnection(Connection: TCustomConnection);
var
  Index: Integer;
begin
  Index := FConnections.IndexOf(Connection);
  if Index <> -1 then
  begin
    FCurrentRemoveConnection := Connection;
    DoBeforeRemoveConnection;
    FConnectionTermLock.Enter;
    //OutputDebugString(pChar(Format('removing %d %d %d', [Connection.fIndex, Index, FConnections.Count])));
    FConnections.Extract(Connection);
    //FConnections.Delete(Index);
    //OutputDebugString(pChar(Format('removed %d %d %d', [Connection.fIndex, Index, FConnections.Count])));
    FConnectionTermLock.Leave;
    DoAfterRemoveConnection;
  end;
end;

procedure TCustomServer.DoAfterAddConnection;
begin
  if (Assigned(FOnAfterAddConnection)) then
    Synchronize(SyncAfterAddConnection);
end;

procedure TCustomServer.DoBeforeAddConnection;
begin
  if (Assigned(FOnBeforeAddConnection)) then
    Synchronize(SyncBeforeAddConnection);
end;

procedure TCustomServer.DoAfterRemoveConnection;
begin
  if (Assigned(FOnAfterRemoveConnection)) then
    Synchronize(SyncAfterRemoveConnection);
end;

procedure TCustomServer.DoBeforeRemoveConnection;
begin
  if (Assigned(FOnBeforeRemoveConnection)) then
    Synchronize(SyncBeforeRemoveConnection);
end;

procedure TCustomServer.DoSocketError;
begin
  if (Assigned(FOnSocketErrot)) then
    Synchronize(SyncSocketError);
end;

procedure TCustomServer.SyncAfterAddConnection;
begin
  if (Assigned(FOnAfterAddConnection)) then
    FOnAfterAddConnection(Self, FCurrentAddConnection);
end;

procedure TCustomServer.SyncBeforeAddConnection;
begin
  if (Assigned(FOnBeforeAddConnection)) then
    FOnBeforeAddConnection(Self, FCurrentAddConnection, FCanAddConnection);
end;

procedure TCustomServer.SyncAfterRemoveConnection;
begin
  if (Assigned(FOnAfterRemoveConnection)) then
    FOnAfterRemoveConnection(Self, FCurrentRemoveConnection);
end;

procedure TCustomServer.SyncBeforeRemoveConnection;
begin
  if (Assigned(FOnBeforeRemoveConnection)) then
    FOnBeforeRemoveConnection(Self, FCurrentRemoveConnection);
end;

procedure TCustomServer.SyncSocketError;
begin
  if (Assigned(FOnSocketErrot)) then
    FOnSocketErrot(Self, FCurrentSocket);
end;

procedure TCustomServer.TerminateThread;
begin
  if (Terminated) then exit;
  Terminate;
end;

constructor TCustomServer.Create(Bind: string; Port: string);
begin
  FBind := Bind;
  FPort := Port;

//  FreeOnTerminate := True;
  FConnections := TList.Create;
  FConnectionTermLock := TCriticalSection.Create;
  FMaxConnectionsCount := -1;
  FCanAddConnection := True;
  FCurrentAddConnection := nil;
  FCurrentRemoveConnection := nil;
  FCurrentSocket := nil;
  FIndex := getConnectionIndex;
  inherited Create(True);
end;

destructor TCustomServer.Destroy;
begin
  FConnectionTermLock.Free;
  FConnections.Free;
  inherited Destroy;
end;


function TCustomServer.GetCount: Integer;
begin
  Result := FConnections.Count;
end;

function TCustomServer.GetConnection(Index: Integer): TCustomConnection;
begin
  FConnectionTermLock.Enter;
  Result := TCustomConnection(FConnections[Index]);
  FConnectionTermLock.Leave;
end;

function TCustomServer.GetConnectionByIndex(Index: Integer): TCustomConnection;
var i: Integer;
begin
  Result := nil;
  FConnectionTermLock.Enter;
  for i := 0 to FConnections.Count - 1 do
  begin
    if (TCustomConnection(FConnections[i]).Index = Index) then
    begin
      Result := TCustomConnection(FConnections[i]);
      break;
    end;
  end;
  FConnectionTermLock.Leave;
end;

function TCustomServer.CreateServerConnection(aSocket: TTCPCustomConnectionSocket): TCustomConnection;
begin
  Result := nil;
end;

function TCustomServer.AddConnection(var aSocket: TTCPCustomConnectionSocket): TCustomConnection;
begin
  if ((FMaxConnectionsCount = -1) or (FConnections.count < FMaxConnectionsCount)) then
  begin
    Result := CreateServerConnection(aSocket);
    if (Result <> nil)  then
    begin
      Result.fParent := Self;
      FCurrentAddConnection := Result;
      FCanAddConnection := True;
      DoBeforeAddConnection;
      if (FCanAddConnection) then
      begin
        FConnections.add(Result);
        DoAfterAddConnection;
        Result.Resume;
      end
      else
      begin
        FreeAndNil(Result);
        //aSocket := nil;
      end;
    end
    //else aSocket := nil;
  end;
end;

procedure TCustomServer.Execute;
var
  c: TCustomConnection;
  s: TTCPCustomConnectionSocket;
  sock: TSocket;
  i: Integer;
begin
  FCurrentSocket := TTCPBlockSocket.Create;
  with FCurrentSocket do
  begin
    CreateSocket;
    if lastError <> 0 then DoSocketError;
    SetLinger(True, 10000);
    if lastError <> 0 then DoSocketError;
    bind(fBind, fPort);
    if lastError <> 0 then DoSocketError;
    listen;
    if lastError <> 0 then DoSocketError;
    repeat
      if Terminated then
        break;
      if canread(1000) then
      begin
        if LastError = 0 then
        begin
          sock := Accept;
          if lastError = 0 then
          begin
            s := TTCPCustomConnectionSocket.Create;
            s.Socket := sock;

            if (fSSL) then
            begin
              s.SSL.CertificateFile := fSSLCertificateFile;
              s.SSL.PrivateKeyFile := fSSLPrivateKeyFile;
              //s.SSL.SSLType := LT_SSLv3;
              if (SSLKeyPassword <> '') then
                s.SSL.KeyPassword := fSSLKeyPassword;
              s.SSLAcceptConnection;
              i := s.SSL.LastError;
              if (i <> 0) then
              begin
                FreeAndNil(s);
              end;
            end;
            if (s <> nil) then
            begin
              s.GetSins;
              c := AddConnection(s);
              if (c = nil) and (s <> nil) then
                s.Free;
            end;
          end
          else
          begin
            DoSocketError;
          end;
        end
        else
        begin
          if lastError <> WSAETIMEDOUT then
            DoSocketError;
        end;
      end;
    until false;
  end;
  FOnAfterAddConnection := nil;
  FOnBeforeAddConnection := nil;
  FOnAfterRemoveConnection := nil;
  FOnBeforeRemoveConnection := nil;
  FOnSocketErrot := nil;

  //while FConnections.Count > 0 do

  for i := FConnections.Count - 1 downto 0 do
  begin
    c := TCustomConnection(FConnections[i]);
    try
      OnConnectionTerminate(c);
      c.TerminateThread;
      {$IFDEF WIN32} WaitForSingleObject(c.Handle, 100) {$ELSE WIN32} sleep(100); {$ENDIF WIN32}
    finally end;
  end;




  FreeAndNil(FCurrentSocket);
  //while FConnections.Count > 0 do sleep(500);
end;

procedure TCustomServer.LockTermination;
begin
  FConnectionTermLock.Enter;
end;



procedure TCustomServer.Start;
begin
  Resume;
end;

procedure TCustomServer.Stop;
begin
  Suspend;
end;

procedure TCustomServer.UnLockTermination;
begin
  FConnectionTermLock.Leave;
end;

{ TTCPCustomConnectionSocket }

destructor TTCPCustomConnectionSocket.Destroy;
begin
  OnStatus := nil;
  OnSyncStatus := nil;
  inherited;
end;

procedure TTCPCustomConnectionSocket.DoOnStatus(Sender: TObject; Reason: THookSocketReason; const Value: String);
begin
  if (FConnection <> nil) and (not FConnection.Terminated) and (Assigned(FOnSyncStatus)) then
  begin
    FCurrentStatusReason := Reason;
    FCurrentStatusValue := Value;
    FConnection.Synchronize(SyncOnStatus);
    
    {
    if (FCurrentStatusReason = HR_Error) and (LastError = WSAECONNRESET) then
      FConnection.Terminate;
    }
  end;
end;

procedure TTCPCustomConnectionSocket.SyncOnStatus;
begin
  if (Assigned(FOnSyncStatus)) then
    FOnSyncStatus(Self, FCurrentStatusReason, FCurrentStatusValue);
end;

constructor TTCPCustomConnectionSocket.Create;
begin
  inherited Create;
  FConnection := nil;
  OnStatus := DoOnStatus;
end;

{ TCustomConnection }

constructor TCustomConnection.Create(Socket: TTCPCustomConnectionSocket);
begin
  FSocket := Socket;
  FSocket.FConnection := Self;
//  FreeOnTerminate := True;
  FIndex := getConnectionIndex;
  inherited Create(True);
end;

destructor TCustomConnection.Destroy;
begin
  if FSocket <> nil then
  begin
    FSocket.OnSyncStatus := nil;
    FSocket.OnStatus := nil;
    FSocket.Free;
  end;
    
  inherited Destroy;
end;

procedure TCustomConnection.Execute;
begin
  if BeforeExecuteConnection then
  begin
    ExecuteConnection;
    AfterConnectionExecute;
  end;
  if FParent <> nil then
    if not FParent.Terminated then
      FParent.OnConnectionTerminate(Self);
end;


procedure TCustomConnection.Start;
begin
  Resume;
end;

procedure TCustomConnection.Stop;
begin
  Suspend;
end;

procedure TCustomConnection.TerminateThread;
begin
  if (Terminated) then exit;
  
  Socket.OnSyncStatus := nil;
  Socket.OnStatus := nil;
  Terminate;
end;

function TCustomConnection.GetIsTerminated: Boolean;
begin
  Result := Terminated or (FSocket = nil)// or (FSocket.Socket = INVALID_SOCKET);
end;

procedure TCustomConnection.AfterConnectionExecute;
begin

end;

function TCustomConnection.BeforeExecuteConnection: Boolean;
begin
  Result := True;
end;

procedure TCustomConnection.ExecuteConnection;
begin

end;


end.

