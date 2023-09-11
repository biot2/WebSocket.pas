program WebSocketTest;

{$Mode Delphi}

uses
  cthreads,
  Classes,
  SysUtils,
  WebSocket.Helper,
  WebSocket.Core;

type
  TMyClass = class
  public
    procedure OnRead(Sender: TWebSocketCustomConnection; {%H-}Flags: TWSFlags; OpCode: Byte; Data: TMemoryStream);
    procedure OnReadFull(Sender: TWebSocketCustomConnection; OpCode: Byte; Data: TMemoryStream);
    procedure OnPing(Sender: TWebSocketCustomConnection; Data: AnsiString);
    procedure OnPong(Sender: TWebSocketCustomConnection; Data: AnsiString);
  end;

{ TMyClass }

procedure TMyClass.OnRead(Sender: TWebSocketCustomConnection; Flags: TWSFlags; OpCode: Byte; Data: TMemoryStream);
var
  s: AnsiString;
begin
  SetLength(s{%H-}, Data.Size);
  Move(Data.Memory^, s[1], Data.Size);
  WriteLn(OpCode, ':', Data.Size, '-', s);
end;

procedure TMyClass.OnReadFull(Sender: TWebSocketCustomConnection; OpCode: Byte; Data: TMemoryStream);
begin
  WriteLn(OpCode, ':', Data.Size, '-', PAnsiChar(Data.Memory));
end;

procedure TMyClass.OnPing(Sender: TWebSocketCustomConnection; Data: AnsiString);
begin
  WriteLn('PING:', Length(Data), '-', Data);
end;

procedure TMyClass.OnPong(Sender: TWebSocketCustomConnection; Data: AnsiString);
begin
  WriteLn('PONG:', Length(Data), '-', Data);
end;

var
  Client: TWebSocketClient;
  MyClass: TMyClass;
  i: Integer;

begin
  MyClass := TMyClass.Create;
  Client := TWebSocketClient.CreateFromURL('wss://127.0.0.1/websocket/test');
  Client.OnRead := MyClass.OnRead;
  Client.OnReadFull := MyClass.OnReadFull;
  Client.OnPing := MyClass.OnPing;
  Client.OnPong := MyClass.OnPong;
  Client.Start;
  Client.WaitForConnect(10000);
  Client.SendText('HeloHeloHeloHelo');
  Client.SendText('Hello', []);
  Client.SendTextContinuation('Hello', []);
  Client.SendTextContinuation('Hello', []);
  Client.SendTextContinuation('Hello', [FIN]);
  Client.Ping('PingPingPing');
  for i := 1 to 10 do begin
    Client.SendText('Hello ' + IntToStr(i));
    Client.Ping('Ping ' + IntToStr(i));
    Sleep(1000);
	end;
	Readln;
  Client.Ping('PingPingPing');
  Client.Free;
  MyClass.Free;
  Writeln('FINISHED!');
end.

