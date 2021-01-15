/*
 * simplesocks
 * Copyright 2015 Kenny Root
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.connectbot.simplesocks;

import java.io.*;
import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.nio.charset.CharsetDecoder;

/**
 * A simple SOCKS5 server which does no authentication and only accepts {@code CONNECT} requests (i.e., no
 * {@code BIND}).
 * <p>
 * Example usage:
 * <pre><code>
 *     Socks5Server server = new Socks5Server(sockIn, sockOut);
 *     if (server.acceptAuthentication() &amp;&amp; server.readRequest()) {
 *         server.sendReply(ResponseCode.SUCCESS);
 *     } else {
 *         {@literal /}* handle failure *{@literal /}
 *     }
 * </code></pre>
 */
public class Socks5Server {
    /**
     * Address type that indicates the request is IPv4.
     */
    private static final int ATYPE_IPV4 = 0x01;

    /**
     * Address type that indicates the request is IPv6.
     */
    private static final int ATYPE_DNS = 0x03;

    /**
     * Address type that indicates the request is IPv6.
     */
    private static final int ATYPE_IPV6 = 0x04;

    private final DataInputStream in;
    private final DataOutputStream out;

    /**
     * Command that a client can request. Currently only the {@link #CONNECT} command is supported in ConnectBot, so
     * {@link #BIND} may fail.
     */
    public enum Command {
        /**
         * Represents a request from the client for the server to connect the input and output streams to a remote host.
         */
        CONNECT(0x01),
        /**
         * Represents a request from the client for the server to start listening on a port.
         */
        BIND(0x02);

        public static Command fromCommandNumber(int commandNumber) {
            if (commandNumber == Command.CONNECT.commandNumber()) {
                return Command.CONNECT;
            } else if (commandNumber == Command.BIND.commandNumber()) {
                return Command.BIND;
            } else {
                return null;
            }
        }

        private final int commandNumber;

        Command(int commandNumber) {
            this.commandNumber = commandNumber;
        }

        public int commandNumber() {
            return commandNumber;
        }
    }

    public enum ResponseCode {
        /**
         * Sent when the server accepted the command and is going to connect the client.
         */
        SUCCESS((byte) 0x00),
        /**
         * An unspecified failure caused the server not to be able to comply.
         */
        GENERAL_FAILURE((byte) 0x01),
        /**
         * The server denied the connection due to a ruleset that prevented it.
         */
        RULESET_DENIED((byte) 0x02),
        /**
         * The requested network was unreachable.
         */
        NETWORK_UNREACHABLE((byte) 0x03),
        /**
         * The requested host was unreachable.
         */
        HOST_UNREACHABLE((byte) 0x04),
        /**
         * The host refused a connection on the requested port.
         */
        CONNECTION_REFUSED((byte) 0x05),
        /**
         * The Time-To-Live expired when trying to reach the server.
         */
        TTL_EXPIRED((byte) 0x06),
        /**
         * The command sent was not supported.
         */
        COMMAND_NOT_SUPPORTED((byte) 0x07),
        /**
         * The address type requested was not supported.
         */
        ADDRESS_TYPE_NOT_SUPPORTED((byte) 0x08);

        private final byte code;

        ResponseCode(byte code) {
            this.code = code;
        }

        public byte getCode() {
            return code;
        }
    }

    /**
     * The command the request is referring to.
     */
    private Command command;

    /**
     * IP address requested when the {@link Command} was given.
     */
    private InetAddress address;

    /**
     * Hostname requested when the {@link Command} was given.
     */
    private String hostName;

    /**
     * The port requested when the {@link Command} was given.
     */
    private int port = -1;

    public Socks5Server(InputStream in, OutputStream out) {
        this.in = new DataInputStream(in);
        this.out = new DataOutputStream(out);
    }

    /**
     * Begin the authentication with the client. If the authentication succeeds, this will return {@code true}.
     * Otherwise, the server must hang up on the client.
     *
     * @throws IOException when the underlying stream has a problem
     * @return {@code true} when authentication succeeds
     */
    public boolean acceptAuthentication() throws IOException {
        checkProtocolVersion();

        int numMethods = in.read();
        byte[] methods = new byte[numMethods];
        in.readFully(methods);

        boolean success = false;
        for (byte method : methods) {
            if (method == 0x00) {
                success = true;
                break;
            }
        }

        byte[] reply = new byte[2];
        reply[0] = 0x05;
        if (success) {
            reply[1] = 0x00;
        } else {
            reply[1] = (byte) 0xFF;
        }
        out.write(reply);
        return success;
    }

    private void checkProtocolVersion() throws IOException {
        if (in.read() != 0x05) {
            throw new IOException("Unsupported protocol");
        }
    }

    /**
     * Reads the type of request the client has made.
     *
     * @throws IOException when the underlying stream has a problem
     * @see #getCommand()
     * @see #getAddress()
     * @see #getPort()
     * @return {@code true} if the client request was valid
     */
    public boolean readRequest() throws IOException {
        checkProtocolVersion();

        boolean correct = true;

        command = Command.fromCommandNumber(in.read());
        if (command == null) {
            correct = false;
        }

        if (in.read() != 0x00) {
            correct = false;
        }

        int atype = in.read();
        if (atype == ATYPE_IPV4) {
            byte[] addressBytes = new byte[4];
            in.readFully(addressBytes);
            address = InetAddress.getByAddress(addressBytes);
        } else if (atype == ATYPE_DNS) {
            int hostNameLength = in.read();
            byte[] hostName = new byte[hostNameLength];
            in.readFully(hostName);

            // We use this so we have an IOException thrown instead of an unchecked exception.
            CharsetDecoder asciiDecoder = Charset.forName("US-ASCII").newDecoder();
            CharBuffer hostBuffer = asciiDecoder.decode(ByteBuffer.wrap(hostName));

            this.hostName = hostBuffer.toString();
        } else if (atype == ATYPE_IPV6) {
            byte[] addressBytes = new byte[16];
            in.readFully(addressBytes);
            address = InetAddress.getByAddress(addressBytes);
        } else {
            correct = false;
        }

        port = in.read() << 8 | in.read();

        return correct;
    }

    /**
     * Send back to the client the given {@code response}. If the {@link ResponseCode#SUCCESS SUCCESS} code is returned,
     * the server must immediately connect the input and output streams to the requested socket. If any other code is
     * returned, then the server must hang up on the client.
     *
     * @param response code to send back to the client
     * @throws IOException when the underlying stream has a problem
     */
    public void sendReply(ResponseCode response) throws IOException {
        byte[] responseBytes = new byte[]{
                (byte) 0x05, /* version */
                response.getCode(),
                (byte) 0x00, /* reserved */
                (byte) 0x01, /* Address type: IPv4 */
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, /* INADDR_ANY */
                (byte) 0x00, (byte) 0x00, /* port */
        };
        out.write(responseBytes);
    }

    public Command getCommand() {
        return command;
    }

    public InetAddress getAddress() {
        return address;
    }

    public String getHostName() {
        return hostName;
    }

    public int getPort() {
        return port;
    }
}
