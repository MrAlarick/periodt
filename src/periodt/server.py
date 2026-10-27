"""
fveet - a python SMTP server
Copyright (C) 2026  Alarick Dyachenko

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published
by the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""


import re
import socket
import threading
import logging
import time
from auth import Authenticator
from send import Sender, ChunkingSender

VERSION = "0.0.1"

class SMTPServer: # base smtp server
    def __init__(self, authenticator: Authenticator, sender: Sender, port: int = 25, host: str = "", max_connections: int = 5, timeout: int | float = 300):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind((host, port))
        self.socket.listen(max_connections)
        self.timeout = timeout
        self.db = db
        self.sender = sender

    def start(self):
        try:
            print("Server started. Press CTRL+C")
            while True:
                conn, address = self.socket.accept()
                #conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                conn.settimeout(self.timeout)
                threading.Thread(target=self._process_connection, args=(conn, address)).start()
        finally:
            self.stop()

    def stop(self):
        self.socket.close()

    def _process_connection(self, conn: socket.socket, address: tuple[str, int]):
        context: dict = {
            "forward_path": [],
            "buffer": b"",
            "data": False,
            "reverse_path": None,
            "esmtp": True,
            "ehlo": None
        }
        self._send(conn, address, f"220 Periodt v{VERSION} Service ready\r\n".encode(encoding="us-ascii"))
        try:
            while True:
                chunk = conn.recv(BUFFER_SIZE)
                if chunk == b"":
                    logging.info(f"connection dropped {address[0]}:{address[1]}")
                    return
                context["buffer"] += chunk
                if context["data"]:
                    self.process_data(conn, address, context)
                elif context["buffer"].endswith(b"\r\n"):
                    self.process_command(conn, address, context)
        except socket.timeout:
            conn.sendall(b"421 Connection timeout\r\n")
            conn.close()
        except OSError:
            pass
        except Exception as e:
            logging.info(f"error {address[0]}:{address[1]} {type(e)}: {e}")

    def process_command(self, conn: socket.socket, address: tuple[str, int], context: dict):
        if b" " in context["buffer"]:
            func_name = context["buffer"].upper().split(b" ")[0]
        else:
            func_name = context["buffer"].upper()[:-2]
        try:
            func_name = func_name.decode(encoding="us-ascii")
        except UnicodeError:
            self._send(conn, address, b"500 syntax error - invalid character\r\n")
        else:
            if hasattr(self, func_name):
                getattr(self, func_name)(conn, address, context)
            else:
                self._send(conn, address, b"500 command unrecognized\r\n")
        context["buffer"] = b""

    def process_data(self, conn: socket.socket, address: tuple[str, int], context: dict):
        if context["buffer"].endswith(b"\r\n.\r\n") or context["buffer"] == b".\r\n":
            if any((i > 127 for i in context["buffer"])):
                self._send(conn, address, b"500 syntax error - invalid character\r\n")
            else:
                self._send(conn, address, self.sender.put(context["buffer"], context["reverse_path"], context["forward_path"]))
                context["forward_path"].clear()
                context["reverse_path"] = None
            context["data"] = False
            context["buffer"] = b""

    def _send(self, conn: socket.socket, address: tuple[str, int], data: bytes):
        result = conn.sendall(data)
        if result:
            logging.info(f"error {address[0]}:{address[1]} {result}")
            conn.close()

    def _do_EHLO(self, conn: socket.socket, address: tuple[str, int], context: dict):
        self._send(conn, address, f"250-{DOMAIN} is my domain name\r\n250-VRFY\r\n250-EXPN\r\n250-HELP\r\n".encode(encoding="us-ascii"))
        context["reverse_path"] = None
        context["forward_path"].clear()
        context["ehlo"] = context["buffer"][5:-2].strip()
        context["esmtp"] = True

    def _do_HELO(self, conn: socket.socket, address: tuple[str, int], context: dict):
        self._send(conn, address, f"250-{DOMAIN} is my domain name\r\n".encode(encoding="us-ascii"))
        context["reverse_path"] = None
        context["forward_path"].clear()
        context["esmtp"] = False
        context["ehlo"] = context["buffer"][5:-2].strip()

    def _do_NOOP(self, conn: socket.socket, address: tuple[str, int]):
        self._send(conn, address, b"250 OK\r\n")

    def _do_QUIT(self, conn: socket.socket, address: tuple[str, int], context: dict):
        if context["buffer"].upper() != b"QUIT \r\n" and context["buffer"].upper() != b"QUIT\r\n":
            self._send(conn, address, b"501 Syntax error\r\n")
        else:
            self._send(conn, address, b"221 OK\r\n")
            conn.close()

    def _do_RSET(self, conn: socket.socket, address: tuple[str, int], context: dict):
        if context["buffer"].upper() != b"RSET \r\n" and context["buffer"].upper() != b"RSET\r\n":
            self._send(conn, address, b"501 Syntax error\r\n")
        else:
            self._send(conn, address, b"250 OK\r\n")
            context["reverse_path"] = None
            context["forward_path"].clear()

    def _do_VRFY(self, conn: socket.socket, address: tuple[str, int], context: dict):
        if re.fullmatch(rb"""VRFY ("((\\[\x20-\x7E])|[\x20-\x21\x23-\x5B\x5D-\x7E])*"|[A-Z0-9!#$%&'*+/=?^_{|}~-]+)( )*\r\n""", context["buffer"].upper()):
            self._send(conn, address, self.db.verify(context["buffer"][5:-2].rstrip()))
        else:
            self._send(conn, address, b"501 Syntax error\r\n")

    def _do_MAIL(self, conn: socket.socket, address: tuple[str, int], context: dict):
        if context["ehlo"] is not None and context["reverse_path"] is None:
            if re.fullmatch(rb"""MAIL FROM:<((((@([A-Z\d]([A-Z\d-]*[A-Z\d])?)(\.([A-Z\d]([A-Z\d-]*[A-Z\d])?))?)(,@(([A-Z\d]([A-Z\d-]*[A-Z\d])?)(\.([A-Z\d]([A-Z\d-]*[A-Z\d])?))?))*):)?(("((\\[\x20-\x7E])|[\x20-\x21\x23-\x5B\x5D-\x7E])*")|([A-Z0-9!#$%&'*+\-/=?^_{|}~]+(\.[A-Z0-9!#$%&'*+\-/=?^_{|}~]+)*))@[A-Z\d.-]+)?>( )*\r\n""",
                            context["buffer"].upper()):
                context["reverse_path"] = context["buffer"][11:-2].rstrip()[:-1].rsplit(":", 1)[:-1]
                self._send(conn, address, b"250 OK\r\n")
                context["forward_path"].clear()
            elif re.fullmatch(rb"""MAIL FROM:<((((@([A-Z\d]([A-Z\d-]*[A-Z\d])?)(\.([A-Z\d]([A-Z\d-]*[A-Z\d])?))?)(,@(([A-Z\d]([A-Z\d-]*[A-Z\d])?)(\.([A-Z\d]([A-Z\d-]*[A-Z\d])?))?))*):)?(("((\\[\x20-\x7E])|[\x20-\x21\x23-\x5B\x5D-\x7E])*")|([A-Z0-9!#$%&'*+\-/=?^_{|}~]+(\.[A-Z0-9!#$%&'*+\-/=?^_{|}~]+)*))@[A-Z\d.-]+)?>( ([A-Z\d]([A-Z\d-]*))(((^[!-<>-~]+$)+)?))+( )*\r\n""",
                              context["buffer"].upper()):
                self._send(conn, address, b"555 MAIL FROM/RCPT TO parameters not recognized or not implemented")
            else:
                self._send(conn, address, b"501 Syntax error\r\n")
        else:
            self._send(conn, address, b"503 bad sequence of commands\r\n")

    def _do_RCPT(self, conn: socket.socket, address: tuple[str, int], context: dict):
        if context["ehlo"] and context["reverse_path"] is not None:
            if re.fullmatch(rb"""RCPT TO:<(POSTMASTER|((((@([A-Z\d]([A-Z\d-]*[A-Z\d])?)(\.([A-Z\d]([A-Z\d-]*[A-Z\d])?))?)(,@(([A-Z\d]([A-Z\d-]*[A-Z\d])?)(\.([A-Z\d]([A-Z\d-]*[A-Z\d])?))?))*):)?(("((\\[\x20-\x7E])|[\x20-\x21\x23-\x5B\x5D-\x7E])*")|([A-Z0-9!#$%&'*+\-/=?^_{|}~]+(\.[A-Z0-9!#$%&'*+\-/=?^_{|}~]+)*))@[A-Z\d.-]+))>( )*\r\n""",
                    context["buffer"].upper()):
                context["forward_path"].append(context["buffer"][9:-2].rstrip()[:-1].rsplit(":", 1)[:-1])
                self._send(conn, address, b"250 OK\r\n")
            elif re.fullmatch(rb"""RCPT TO:<(POSTMASTER|((((@([A-Z\d]([A-Z\d-]*[A-Z\d])?)(\.([A-Z\d]([A-Z\d-]*[A-Z\d])?))?)(,@(([A-Z\d]([A-Z\d-]*[A-Z\d])?)(\.([A-Z\d]([A-Z\d-]*[A-Z\d])?))?))*):)?(("((\\[\x20-\x7E])|[\x20-\x21\x23-\x5B\x5D-\x7E])*")|([A-Z0-9!#$%&'*+\-/=?^_{|}~]+(\.[A-Z0-9!#$%&'*+\-/=?^_{|}~]+)*))@[A-Z\d.-]+))>( ([A-Z\d]([A-Z\d-]*))(((^[!-<>-~]+$)+)?))+( )*\r\n""",
                              context["buffer"].upper()):
                self._send(conn, address, b"555 RCPT TO parameters not recognized or not implemented")
            else:
                self._send(conn, address, b"501 syntax error\r\n")
        else:
            self._send(conn, address, b"503 Bad sequence of commands\r\n")

    def _do_DATA(self, conn: socket.socket, address: tuple[str, int], context: dict):
        if context["ehlo"] is not None and context["reverse_path"] is not None and context["forward_path"]:
            context["data"] = True
            self._send(conn, address, b"354 Intermediate reply\r\n")
        else:
            self._send(conn, address, b"503 Command out of sequence\r\n")


class ExtSMTPServer(SMTPServer): # smtp server with 8bitmime, chunking, binarymime, size, smtputf8, pipelining
    def __init__(self, authenticator: Authenticator, sender: ChunkingSender, port: int = 25, host: str = "", max_connections: int = 5, timeout: int | float = 300, size_limit: int = 52428800):
        super().__init__(authenticator, sender, port, host, max_connections, timeout)
        self.size = size_limit

    def _process_connection(self, conn: socket.socket, address: tuple[str, int]):
        context: dict = {
            "forward_path": [],
            "buffer": b"",
            "data": False,
            "reverse_path": None,
            "esmtp": True,
            "ehlo": None,
            "bdat": False,
            "bdat_buffer": b"",
            "bdat_err": False,
            "mode": None,
            "size": None
        }
        self._send(conn, address, f"220 Periodt v{VERSION} Service ready\r\n".encode(encoding="us-ascii"))
        try:
            while True:
                chunk = conn.recv(BUFFER_SIZE)
                if chunk == b"":
                    logging.info(f"connection dropped {address[0]}:{address[1]}")
                    return
                context["buffer"] += chunk
                if context["data"]:
                    self.process_data(conn, address, context)
                elif context["buffer"].startswith(b"BDAT"):
                    self.process_bdat(conn, address, context)
                elif context["buffer"].endswith(b"\r\n"):
                    if context["bdat_err"]:
                        if context["buffer"] == b"RSET\r\n":
                            self._do_RSET(conn, address, context)
                        else:
                            self._send(conn, address, b"503 bad sequence of commands\r\n")
                    self.process_command(conn, address, context)
        except socket.timeout:
            conn.sendall(b"421 Connection timeout\r\n")
            conn.close()
        except OSError:
            pass
        except Exception as e:
            logging.info(f"error {address[0]}:{address[1]} {type(e)}: {e}")

    def process_data(self, conn: socket.socket, address: tuple[str, int], context: dict):
        if context["buffer"].endswith(b"\r\n.\r\n") or context["buffer"] == b".\r\n":
            if context["mode"] != b"8BITMIME" and any((i > 127 for i in context["buffer"])):
                self._send(conn, address, b"500 syntax error - invalid character\r\n")
            else:
                self._send(conn, address, self.sender.put(context["buffer"], context["reverse_path"], context["forward_path"]))
                context["forward_path"].clear()
                context["reverse_path"] = None
            context["data"] = False
            context["buffer"] = b""

    def _do_DATA(self, conn: socket.socket, address: tuple[str, int], context: dict):
        if context["ehlo"] is not None and context["reverse_path"] is not None and context["forward_path"] and context["mode"] in (None, b"7BIT", b"8BITMIME"):
            context["data"] = True
            self._send(conn, address, b"354 Intermediate reply\r\n")
        else:
            self._send(conn, address, b"503 Command out of sequence\r\n")

    def process_bdat(self, conn: socket.socket, address: tuple[str, int], context: dict):
        if re.fullmatch(rb"BDAT (\d+)( LAST)?\r\n([\x00-\xFF]*)", context["buffer"]):
            data = context["buffer"].split(b"\r\n", 1)[1]
            if int(context["buffer"].split(b"\r\n", 1)[0].split()[1]) == len(data):
                context["buffer"] = b""
                if context["ehlo"] is not None and context["reverse_path"] is not None and context["forward_path"]:
                    context["bdat_buffer"] += data
                    if b"LAST" in context["buffer"].split(b"\r\n", 1)[0]:
                        err, msg = self.sender.chunking_put(context["bdat_buffer"], context["reverse_path"], context["forward_path"])
                        if err:
                            context["bdat_err"] = True
                        else:
                            context["forward_path"].clear()
                            context["reverse_path"] = None
                            context["bdat_buffer"] = b""
                    else:
                        msg = b"250 OK"
                        context["bdat"] = True
                    self._send(conn, address, msg)
                else:
                    self._send(conn, address, b"503 Command out of sequence\r\n")

    def _do_RSET(self, conn: socket.socket, address: tuple[str, int], context: dict):
        if context["buffer"].upper() != b"RSET \r\n" and context["buffer"].upper() != b"RSET\r\n":
            self._send(conn, address, b"501 Syntax error\r\n")
        else:
            self._send(conn, address, b"250 OK\r\n")
            context["reverse_path"] = None
            context["forward_path"].clear()
            context["bdat_buffer"] = b""

    def _do_MAIL(self, conn: socket.socket, address: tuple[str, int], context: dict):
        if context["ehlo"] is not None and context["reverse_path"] is None:
            if re.fullmatch(rb"""MAIL FROM:<((((@([A-Z\d]([A-Z\d-]*[A-Z\d])?)(\.([A-Z\d]([A-Z\d-]*[A-Z\d])?))?)"""
                            rb"""(,@(([A-Z\d]([A-Z\d-]*[A-Z\d])?)(\.([A-Z\d]([A-Z\d-]*[A-Z\d])?))?))*):)?"""
                            rb"""(("((\\[\x20-\x7E])|[\x20-\x21\x23-\x5B\x5D-\x7E])*")|([A-Z0-9!#$%&'*+\-/=?^_{|}~]+"""
                            rb"""(\.[A-Z0-9!#$%&'*+\-/=?^_{|}~]+)*))@[A-Z\d.-]+)?>( )*((BODY=(7BIT|8BITMIME))(SIZE=(\d*)?)|(SIZE=(\d*))(BODY=(7BIT|8BITMIME))?)?\r\n""",
                            context["buffer"].upper()):
                context["reverse_path"] = context["buffer"][11:-2].split()[0][:-1].rsplit(b":", 1)[:-1]
                if b"BODY=" in context["buffer"].upper().rsplit(b">", 1)[1]:
                    context["mode"] = context["buffer"][:-2].split(b"BODY=", 1)[1].split(" ", 1)[0]
                if b"SIZE=" in context["buffer"].upper().rsplit(b">", 1)[1]:
                    size = int(context["buffer"][:-2].split(b"SIZE=", 1)[1].split(" ", 1)[0])
                    context["size"] = size
                    if not self.sender.size(size):
                        self._send(conn, address, b"452 insufficient system storage\r\n")
                        return
                    if size > self.size:
                        self._send(conn, address, b"552 message size exceeds fixed maximum message size\r\n")
                        return
                self._send(conn, address, b"250 OK\r\n")
                context["forward_path"].clear()
            elif re.fullmatch(rb"""MAIL FROM:<((((@([A-Z\d]([A-Z\d-]*[A-Z\d])?)(\.([A-Z\d]([A-Z\d-]*[A-Z\d])?))?)"""
                              rb"""(,@(([A-Z\d]([A-Z\d-]*[A-Z\d])?)(\.([A-Z\d]([A-Z\d-]*[A-Z\d])?))?))*):)?"""
                              rb"""(("((\\[\x20-\x7E])|[\x20-\x21\x23-\x5B\x5D-\x7E])*")|([A-Z0-9!#$%&'*+\-/=?^_{|}~]+"""
                              rb"""(\.[A-Z0-9!#$%&'*+\-/=?^_{|}~]+)*))@[A-Z\d.-]+)?>( ([A-Z\d]([A-Z\d-]*))(((^[!-<>-~]+$)+)?))+( )*\r\n""",
                              context["buffer"].upper()):
                self._send(conn, address, b"555 MAIL FROM/RCPT TO parameters not recognized or not implemented")
            else:
                self._send(conn, address, b"501 Syntax error\r\n")

        else:
            self._send(conn, address, b"503 bad sequence of commands\r\n")

    def _do_EHLO(self, conn: socket.socket, address: tuple[str, int], context: dict):
        self._send(conn, address, f"250-{DOMAIN} is my domain name\r\n250-VRFY\r\n250-EXPN\r\n250-HELP\r\n250-8BITMIME\r\n250-CHUNKING\r\n250-BINARYMIME\r\n250-SIZE {self.size}\r\n".encode(encoding="us-ascii"))
        context["reverse_path"] = None
        context["forward_path"].clear()
        context["ehlo"] = context["buffer"][5:-2].strip()
        context["esmtp"] = True

    def _do_RCPT(self, conn: socket.socket, address: tuple[str, int], context: dict):
        if context["ehlo"] and context["reverse_path"] is not None:
            if re.fullmatch(rb"""RCPT TO:<(POSTMASTER|((((@([A-Z\d]([A-Z\d-]*[A-Z\d])?)(\.([A-Z\d]([A-Z\d-]*[A-Z\d])?))?)(,@(([A-Z\d]([A-Z\d-]*[A-Z\d])?)(\.([A-Z\d]([A-Z\d-]*[A-Z\d])?))?))*):)?(("((\\[\x20-\x7E])|[\x20-\x21\x23-\x5B\x5D-\x7E])*")|([A-Z0-9!#$%&'*+\-/=?^_{|}~]+(\.[A-Z0-9!#$%&'*+\-/=?^_{|}~]+)*))@[A-Z\d.-]+))>( )*\r\n""",
                    context["buffer"].upper()):
                rcpt = context["buffer"][9:-2].rstrip()[:-1].rsplit(":", 1)[:-1]
                if context["size"] is not None:
                    if not self.sender.check_rcpt_size(rcpt, context["size"]):
                        self._send(conn, address, b"552 message size exceeds fixed maximum message size\r\n")
                        return
                    if not self.sender.check_rcpt_curr_size(rcpt, context["size"]):
                        self._send(conn, address, b"452 insufficient system storage\r\n")
                        return
                context["forward_path"].append(rcpt)
                self._send(conn, address, b"250 OK\r\n")
            elif re.fullmatch(rb"""RCPT TO:<(POSTMASTER|((((@([A-Z\d]([A-Z\d-]*[A-Z\d])?)(\.([A-Z\d]([A-Z\d-]*[A-Z\d])?))?)(,@(([A-Z\d]([A-Z\d-]*[A-Z\d])?)(\.([A-Z\d]([A-Z\d-]*[A-Z\d])?))?))*):)?(("((\\[\x20-\x7E])|[\x20-\x21\x23-\x5B\x5D-\x7E])*")|([A-Z0-9!#$%&'*+\-/=?^_{|}~]+(\.[A-Z0-9!#$%&'*+\-/=?^_{|}~]+)*))@[A-Z\d.-]+))>( ([A-Z\d]([A-Z\d-]*))(((^[!-<>-~]+$)+)?))+( )*\r\n""",
                              context["buffer"].upper()):
                self._send(conn, address, b"555 RCPT TO parameters not recognized or not implemented")
            else:
                self._send(conn, address, b"501 syntax error\r\n")
        else:
            self._send(conn, address, b"503 Bad sequence of commands\r\n")
