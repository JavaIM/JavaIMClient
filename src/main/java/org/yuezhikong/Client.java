package org.yuezhikong;

import com.google.gson.Gson;
import io.netty.bootstrap.Bootstrap;
import io.netty.channel.*;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.handler.codec.LineBasedFrameDecoder;
import io.netty.handler.codec.MessageToMessageEncoder;
import io.netty.handler.codec.string.StringDecoder;
import io.netty.handler.codec.string.StringEncoder;
import io.netty.handler.logging.LogLevel;
import io.netty.handler.logging.LoggingHandler;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.util.ReferenceCountUtil;
import org.yuezhikong.Protocol.*;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.util.UUID;
import java.util.List;
import java.util.concurrent.ThreadFactory;

public abstract class Client {
    protected static final int protocolVersion = 12;//协议版本

    private String UserName = "";//用户名
    private String Passwd = "";//密码

    /**
     * 启动客户端
     * @param ServerAddress 远程服务器地址
     * @param ServerPort 远程服务器端口
     * @param ServerCACert 远程服务器X.509 CA证书
     * @param UserName 用户名
     * @param Passwd 密码
     */
    public void start(String ServerAddress,
                      int ServerPort,
                      X509Certificate ServerCACert,
                      String UserName,
                      String Passwd)
    {
        this.UserName = UserName;
        this.Passwd = Passwd;
        start(ServerAddress, ServerPort, ServerCACert);
    }

    /**
     * 关闭客户端
     */
    public void disconnect()
    {
        channel.close();
    }

    protected Channel channel;
    /**
     * 启动客户端
     * @param ServerAddress 远程服务器地址
     * @param ServerPort 远程服务器端口
     * @param ServerCACert 远程服务器X.509 CA证书
     */
    public void start(String ServerAddress,
                      int ServerPort,
                      X509Certificate ServerCACert)
    {
        EventLoopGroup workGroup = new NioEventLoopGroup(getWorkerThreadFactory());

        try
        {
            Bootstrap bootstrap = new Bootstrap()
                    .group(workGroup)
                    .channel(NioSocketChannel.class)
                    .handler(new ChannelInitializer<>() {
                        @Override
                        protected void initChannel(Channel ch) throws Exception {
                            ch.pipeline().addLast(SslContextBuilder.forClient()
                                    .trustManager(ServerCACert)
                                    .build().newHandler(ch.alloc()));
                            ch.pipeline().addLast(new LoggingHandler(LogLevel.DEBUG));// 对于每条Channel消息打印debug级别日志
                            ch.pipeline().addLast(new LineBasedFrameDecoder(Integer.MAX_VALUE));// 根据回车分割消息
                            ch.pipeline().addLast(new StringEncoder(StandardCharsets.UTF_8), new StringDecoder(StandardCharsets.UTF_8));// 处理文本为String
                            ch.pipeline().addLast(new MessageToMessageEncoder<CharSequence>() {
                                @Override
                                protected void encode(ChannelHandlerContext ctx, CharSequence msg, List<Object> out) {
                                    out.add(CharBuffer.wrap(msg+"\n"));
                                }
                            });// 每行消息添加换行符
                            ch.pipeline().addLast(new ClientHandler());
                        }
                    });
            ChannelFuture future = bootstrap.connect(ServerAddress,ServerPort).sync();
            channel = future.channel();
            future.channel().closeFuture().sync();
        } catch (InterruptedException e) {
            normalPrint("主线程受到中断，程序已结束");
        } finally {
            workGroup.shutdownGracefully();
        }
    }

    /**
     * 获取Netty工作线程的线程工厂
     * @return 线程工厂
     */
    protected abstract ThreadFactory getWorkerThreadFactory();

    private class ClientHandler extends ChannelInboundHandlerAdapter
    {
        private final Gson gson = new Gson();

        @Override
        public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception {
            StringWriter sw = new StringWriter();
            PrintWriter pw = new PrintWriter(sw);
            cause.printStackTrace(pw);

            errorPrint("出现未捕获的错误");
            errorPrint(sw.toString());
            disconnect();
        }

        @Override
        public void channelActive(ChannelHandlerContext ctx) throws Exception {
            LoginProtocol loginPacket;
            if (!getToken().isEmpty())
            {
                LoginProtocol.LoginPacketHeadBean headBean = new LoginProtocol.LoginPacketHeadBean();
                headBean.setType("token");

                LoginProtocol.LoginPacketBodyBean bodyBean = new LoginProtocol.LoginPacketBodyBean();
                LoginProtocol.LoginPacketBodyBean.ReLoginBean reLoginBean = new LoginProtocol.LoginPacketBodyBean.ReLoginBean();
                reLoginBean.setToken(getToken());
                bodyBean.setReLogin(reLoginBean);

                loginPacket = new LoginProtocol();
                loginPacket.setLoginPacketHead(headBean);
                loginPacket.setLoginPacketBody(bodyBean);
            }
            else {
                LoginProtocol.LoginPacketHeadBean headBean = new LoginProtocol.LoginPacketHeadBean();
                headBean.setType("passwd");

                LoginProtocol.LoginPacketBodyBean bodyBean = new LoginProtocol.LoginPacketBodyBean();
                LoginProtocol.LoginPacketBodyBean.NormalLoginBean normalLoginBean = new LoginProtocol.LoginPacketBodyBean.NormalLoginBean();
                normalLoginBean.setUserName(UserName);
                normalLoginBean.setPasswd(Passwd);
                bodyBean.setNormalLogin(normalLoginBean);

                loginPacket = new LoginProtocol();
                loginPacket.setLoginPacketHead(headBean);
                loginPacket.setLoginPacketBody(bodyBean);
            }

            GeneralProtocol generalProtocol = new GeneralProtocol();
            generalProtocol.setProtocolName("LoginProtocol");
            generalProtocol.setProtocolVersion(protocolVersion);
            generalProtocol.setProtocolData(gson.toJson(loginPacket));
            ctx.writeAndFlush(gson.toJson(generalProtocol));
        }

        private void HandleSystemProtocol(ChannelHandlerContext ctx, SystemProtocol protocol) throws IOException {
            switch (protocol.getType())
            {
                case "Error": {
                    onError(protocol);
                    break;
                }
                case "GetFileIdByFileNameResult" : {
                    caughtFileSystemReport("FileId",protocol.getMessage());
                    break;
                }
                case "GetFileNameByFileIdResult" : {
                    caughtFileSystemReport("FileName",protocol.getMessage());
                    break;
                }
                case "DisplayMessage" : {
                    displayMessage(protocol.getMessage());
                    break;
                }
                case "Login" : {
                    if ("Authentication Failed".equals(protocol.getMessage()))
                    {
                        normalPrint("登录失败，token已过期或用户名、密码错误");
                        ctx.channel().close();
                    } else if ("Already Logged".equals(protocol.getMessage()))
                        normalPrint("操作失败，已经登录过了");
                    else {
                        if ("Success".equals(protocol.getMessage())) {
                            normalPrint("登录成功!");
                        } else {
                            normalPrintf("登录成功! 新的 Token 为 %s%n", protocol.getMessage());
                            setToken(protocol.getMessage());
                        }
                       onClientLogin();
                    }
                    break;
                }
                case "TOTP" : {
                    recvRequireTOTP();
                }
            }
        }
        @Override
        public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
            try
            {
                if (!(msg instanceof String))
                    return;
                // 兼容 Java 16- 写法，目的是为了代码可以在Android平台通用，仅需重新编译
                String Msg = (String) msg;
                GeneralProtocol protocol = gson.fromJson(Msg, GeneralProtocol.class);
                if (protocol.getProtocolVersion() != protocolVersion)
                {
                    errorPrint("服务器协议版本与当前客户端不一致");
                    errorPrintf("服务器版本:%s，当前客户端版本:%s%n",protocol.getProtocolVersion(),protocolVersion);
                    errorPrint("客户端已经断开与服务器的连接...");
                    ctx.channel().close();
                }
                switch (protocol.getProtocolName())
                {
                    case "SystemProtocol":
                    {
                        HandleSystemProtocol(ctx,gson.fromJson(protocol.getProtocolData(), SystemProtocol.class));
                        break;
                    }
                    case "ChatProtocol" : {
                        ChatProtocol chatProtocol = gson.fromJson(protocol.getProtocolData(), ChatProtocol.class);
                        displayChatMessage(chatProtocol.getSourceUserName(), chatProtocol.getMessage());
                        break;
                    }
                    case "TransferProtocol": {
                        TransferProtocol transferProtocol = gson.fromJson(protocol.getProtocolData(), TransferProtocol.class);

                        switch (transferProtocol.getTransferProtocolHead().getType()) {
                            case "fileList" : {
                                caughtFileSystemReport("fileList",transferProtocol);
                                break;
                            }

                            case "download" : {
                                List<TransferProtocol.TransferProtocolBodyBean> bodyBeans = transferProtocol.getTransferProtocolBody();
                                String fileName = bodyBeans.get(0).getData();
                                if (fileName.contains("..") || fileName.contains("/") || fileName.contains("\\")) {
                                    String randomName = UUID.randomUUID().toString();
                                    errorPrintf("服务端发送的文件: %s 中存在非法字符，自动重命名为%s", fileName, randomName);
                                    fileName = randomName;
                                }
                                byte[] content = decodeBase64(bodyBeans.get(1).getData());

                                writeDownloadFile(fileName, content);
                                break;
                            }

                            case "QRCode" : {
                                for (TransferProtocol.TransferProtocolBodyBean bodyBean : transferProtocol.getTransferProtocolBody()) {
                                    recvQRCodeData(decodeBase64(bodyBean.getData()));
                                }
                                break;
                            }

                            default : {
                                errorPrintf("服务端发送的 TransferProtocol 模式%s 当前客户端不兼容服务端发送的 %s 模式",
                                        transferProtocol.getTransferProtocolHead().getType(),
                                        transferProtocol.getTransferProtocolHead().getType());
                                return;
                            }
                        }
                        break;
                    }
                    default: {
                        errorPrintf("服务器发送的协议为 %s 但是当前客户端不支持此协议%n", protocol.getProtocolName());
                        break;
                    }
                }
            } catch (Throwable throwable)
            {
                StringWriter sw = new StringWriter();
                PrintWriter pw = new PrintWriter(sw);
                throwable.printStackTrace(pw);
                errorPrint(sw.toString());
            }
            finally {
                ReferenceCountUtil.release(msg);
            }
        }
    }

    /**
     * 当接收到文件系统报告时(所有一般性)
     * @param mode 模式(fileList/FileId/fileName)
     * @param data 数据
     */
    protected abstract void caughtFileSystemReport(String mode, Object data);

    /**
     * 接收到服务端要求TOTP验证码时
     */
    protected abstract void recvRequireTOTP();

    /**
     * 当接收到二维码时
     * @param data 图片
     */
    protected abstract void recvQRCodeData(byte[] data);

    /**
     * 当请求出现错误时
     * @param systemProtocol 服务端发送的错误信息
     */
    protected abstract void onError(SystemProtocol systemProtocol);

    /**
     * 解码 Base64
     * @param src   Base64编码的字符串
     * @return      Base64解码后的字符串
     */
    protected abstract byte[] decodeBase64(String src);

    /**
     * 写入下载的文件
     * @param fileName  文件名
     * @param content   内容
     */
    protected abstract void writeDownloadFile(String fileName, byte[] content);

    /**
     * 显示聊天消息
     * @param sourceUserName 消息来源用户
     * @param message 消息
     */
    protected abstract void displayChatMessage(String sourceUserName, String message);

    /**
     * 显示消息
     * @param message 消息
     */
    protected abstract void displayMessage(String message);


    /**
     * 发送数据
     * @param Data 数据
     */
    public void sendData(String Data)
    {
        channel.writeAndFlush(Data);
    }

    /**
     * 当客户端登录时
     */
    protected abstract void onClientLogin();

    /**
     * 获取 Token
     * @return Token
     */
    protected abstract String getToken();

    /**
     * 写入 Token
     * @param newToken 写入的token
     */
    protected abstract void setToken(String newToken);

    /**
     * 打印正常消息
     * @param data 信息
     */
    protected abstract void normalPrint(String data);

    /**
     * printf打印正常消息
     * @param data 信息
     * @param args 参数
     */
    protected abstract void normalPrintf(String data, Object ... args);

    /**
     * 打印错误消息
     * @param data 信息
     */
    protected abstract void errorPrint(String data);

    /**
     * printf打印错误消息
     * @param data 信息
     * @param args 参数
     */
    protected abstract void errorPrintf(String data, Object ... args);
}
