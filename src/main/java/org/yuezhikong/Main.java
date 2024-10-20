package org.yuezhikong;

import com.google.gson.Gson;
import org.apache.commons.io.FileUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.jetbrains.annotations.NotNull;
import org.yuezhikong.Protocol.ChatProtocol;
import org.yuezhikong.Protocol.GeneralProtocol;
import org.yuezhikong.Protocol.SystemProtocol;
import org.yuezhikong.Protocol.TransferProtocol;

import java.awt.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Scanner;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicInteger;

public class Main {
    public static void main(String[] args) {
        Security.addProvider(new BouncyCastleProvider());
        Scanner scanner = new Scanner(System.in);
        System.out.print("请输入服务器IP地址：");
        String ServerIP = scanner.nextLine();
        System.out.print("请输入服务器端口：");
        int ServerPort = Integer.parseInt(scanner.nextLine());
        System.out.print("请输入服务器CA证书路径：");
        X509Certificate ServerCARootCert;
        try (FileInputStream stream = new FileInputStream(scanner.nextLine())){
            CertificateFactory factory = CertificateFactory.getInstance("X.509","BC");
            ServerCARootCert = (X509Certificate) factory.generateCertificate(stream);
        } catch (CertificateException | NoSuchProviderException | IOException e) {
            throw new RuntimeException("Failed to open X.509 CA Cert & X.509 RSA Private key, Permission denied?",e);
        }

        class ConsoleClient extends Client
        {
            private final Gson gson = new Gson();
            private boolean requireTOTP = false;

            public ConsoleClient clientCommandSystem() {
                Thread UserCommandRequestThread = new Thread(() -> {
                    // 用户消息处理
                    while (true)
                    {
                        try {
                            Scanner scanner = new Scanner(System.in);
                            String Data = scanner.nextLine();
                            if (Data.startsWith("./")) {
                                // 客户端指令
                                String[] args = Data.split("\\s+");
                                switch (args[0]) {
                                    case "./help" -> {
                                        normalPrint("./help 显示此帮助");
                                        normalPrint("./upload <文件路径> 上传文件");
                                        normalPrint("./getUploadFiles 获取上传的文件列表(只可获取自己上传的)");
                                        normalPrint("./getFileIdByFileName <文件名> 根据文件名获取文件Id(只可获取自己上传的)");
                                        normalPrint("./getFileNameByFileId <文件Id> 根据文件Id获取文件名(没有权限限制)");
                                        normalPrint("./downloadFileByFileName <文件名> 根据文件名下载上传的文件(只可下载自己上传的)");
                                        normalPrint("./downloadFileByFileId <文件Id> 根据文件Id下载上传的文件(可下载任何人上传的)");
                                        normalPrint("./deleteFileByFileId <文件Id> 根据文件Id删除上传的文件(可下载自己上传的)(如果你是管理员，可以删除他人的文件)");
                                        normalPrint("./submitTOTP <TOTP验证码> 上传TOTP验证码到服务端");
                                    }

                                    case "./submitTOTP" -> {
                                        if (args.length != 2) {
                                            errorPrint("语法错误，正确的语法为 ./submitTOTP <文件Id>");
                                            break;
                                        }
                                        if (!requireTOTP) {
                                            errorPrint("服务端没有要求提供TOTP验证码!");
                                            break;
                                        }
                                        SystemProtocol systemProtocol = new SystemProtocol();
                                        systemProtocol.setType("TOTP");
                                        systemProtocol.setMessage(args[1]);

                                        GeneralProtocol generalProtocol = new GeneralProtocol();
                                        generalProtocol.setProtocolData(gson.toJson(systemProtocol));
                                        generalProtocol.setProtocolVersion(protocolVersion);
                                        generalProtocol.setProtocolName("SystemProtocol");

                                        sendData(gson.toJson(generalProtocol));
                                        normalPrint("已发送请求。");
                                    }

                                    case "./upload" -> {
                                        if (args.length != 2) {
                                            errorPrint("语法错误，正确的语法为 ./upload <文件路径>");
                                            break;
                                        }
                                        File file = new File(args[1]);
                                        if (!file.exists()) {
                                            errorPrint("此文件不存在");
                                            break;
                                        }

                                        String data = Base64.getEncoder().encodeToString(FileUtils.readFileToByteArray(file));
                                        TransferProtocol transferProtocol = new TransferProtocol();
                                        transferProtocol.setTransferProtocolHead(new TransferProtocol.TransferProtocolHeadBean());
                                        transferProtocol.getTransferProtocolHead().setTargetUserName("");
                                        transferProtocol.getTransferProtocolHead().setType("upload");
                                        transferProtocol.setTransferProtocolBody(new ArrayList<>());

                                        TransferProtocol.TransferProtocolBodyBean fileNameBean = new TransferProtocol.TransferProtocolBodyBean();
                                        fileNameBean.setData(file.getName());
                                        transferProtocol.getTransferProtocolBody().add(fileNameBean);

                                        TransferProtocol.TransferProtocolBodyBean fileDataBean = new TransferProtocol.TransferProtocolBodyBean();
                                        fileDataBean.setData(data);
                                        transferProtocol.getTransferProtocolBody().add(fileDataBean);

                                        GeneralProtocol generalProtocol = new GeneralProtocol();
                                        generalProtocol.setProtocolData(gson.toJson(transferProtocol));
                                        generalProtocol.setProtocolVersion(protocolVersion);
                                        generalProtocol.setProtocolName("TransferProtocol");

                                        sendData(gson.toJson(generalProtocol));
                                        normalPrint("已发送请求。");
                                    }

                                    case "./getUploadFiles" -> {
                                        SystemProtocol systemProtocol = new SystemProtocol();
                                        systemProtocol.setType("GetUploadFileList");
                                        systemProtocol.setMessage("");

                                        GeneralProtocol generalProtocol = new GeneralProtocol();
                                        generalProtocol.setProtocolData(gson.toJson(systemProtocol));
                                        generalProtocol.setProtocolVersion(protocolVersion);
                                        generalProtocol.setProtocolName("SystemProtocol");

                                        sendData(gson.toJson(generalProtocol));
                                        normalPrint("已发送请求。");
                                    }

                                    case "./getFileIdByFileName" -> {
                                        if (args.length != 2) {
                                            errorPrint("语法错误，正确的语法为 ./getFileIdByFileName <文件名>");
                                            break;
                                        }
                                        SystemProtocol systemProtocol = new SystemProtocol();
                                        systemProtocol.setType("GetFileIdByFileName");
                                        systemProtocol.setMessage(args[1]);

                                        GeneralProtocol generalProtocol = new GeneralProtocol();
                                        generalProtocol.setProtocolData(gson.toJson(systemProtocol));
                                        generalProtocol.setProtocolVersion(protocolVersion);
                                        generalProtocol.setProtocolName("SystemProtocol");

                                        sendData(gson.toJson(generalProtocol));
                                        normalPrint("已发送请求。");
                                    }

                                    case "./getFileNameByFileId" -> {
                                        if (args.length != 2) {
                                            errorPrint("语法错误，正确的语法为 ./getFileNameByFileId <文件Id>");
                                            return;
                                        }
                                        SystemProtocol systemProtocol = new SystemProtocol();
                                        systemProtocol.setType("GetFileNameByFileId");
                                        systemProtocol.setMessage(args[1]);

                                        GeneralProtocol generalProtocol = new GeneralProtocol();
                                        generalProtocol.setProtocolData(gson.toJson(systemProtocol));
                                        generalProtocol.setProtocolVersion(protocolVersion);
                                        generalProtocol.setProtocolName("SystemProtocol");

                                        sendData(gson.toJson(generalProtocol));
                                        normalPrint("已发送请求。");
                                    }

                                    case "./downloadFileByFileName" -> {
                                        if (args.length != 2) {
                                            errorPrint("语法错误，正确的语法为 ./downloadFileByFileName <文件名>");
                                            break;
                                        }
                                        SystemProtocol systemProtocol = new SystemProtocol();
                                        systemProtocol.setType("DownloadOwnFileByFileName");
                                        systemProtocol.setMessage(args[1]);

                                        GeneralProtocol generalProtocol = new GeneralProtocol();
                                        generalProtocol.setProtocolData(gson.toJson(systemProtocol));
                                        generalProtocol.setProtocolVersion(protocolVersion);
                                        generalProtocol.setProtocolName("SystemProtocol");

                                        sendData(gson.toJson(generalProtocol));
                                        normalPrint("已发送请求。");
                                    }

                                    case "./downloadFileByFileId" -> {
                                        if (args.length != 2) {
                                            errorPrint("语法错误，正确的语法为 ./downloadFileByFileId <文件Id>");
                                            break;
                                        }
                                        SystemProtocol systemProtocol = new SystemProtocol();
                                        systemProtocol.setType("DownloadFileByFileId");
                                        systemProtocol.setMessage(args[1]);

                                        GeneralProtocol generalProtocol = new GeneralProtocol();
                                        generalProtocol.setProtocolData(gson.toJson(systemProtocol));
                                        generalProtocol.setProtocolVersion(protocolVersion);
                                        generalProtocol.setProtocolName("SystemProtocol");

                                        sendData(gson.toJson(generalProtocol));
                                        normalPrint("已发送请求。");
                                    }

                                    case "./deleteFileByFileId" -> {
                                        if (args.length != 2) {
                                            errorPrint("语法错误，正确的语法为 ./deleteFileByFileId <文件Id>");
                                            break;
                                        }
                                        SystemProtocol systemProtocol = new SystemProtocol();
                                        systemProtocol.setType("DeleteUploadFileByFileId");
                                        systemProtocol.setMessage(args[1]);

                                        GeneralProtocol generalProtocol = new GeneralProtocol();
                                        generalProtocol.setProtocolData(gson.toJson(systemProtocol));
                                        generalProtocol.setProtocolVersion(protocolVersion);
                                        generalProtocol.setProtocolName("SystemProtocol");

                                        sendData(gson.toJson(generalProtocol));
                                        normalPrint("已发送请求。");
                                    }

                                    default -> normalPrint("未知的客户端指令! 请输入 ./help 查看帮助");
                                }
                                continue;
                            }
                            ChatProtocol userInput = new ChatProtocol();
                            userInput.setMessage(Data);

                            GeneralProtocol generalProtocol = new GeneralProtocol();
                            generalProtocol.setProtocolData(gson.toJson(userInput));
                            generalProtocol.setProtocolVersion(protocolVersion);
                            generalProtocol.setProtocolName("ChatProtocol");

                            sendData(gson.toJson(generalProtocol));
                        } catch (Throwable throwable) {
                            StringWriter sw = new StringWriter();
                            PrintWriter pw = new PrintWriter(sw);
                            throwable.printStackTrace(pw);
                            errorPrint(sw.toString());
                        }
                    }
                }, "User Command Request Thread");
                UserCommandRequestThread.setDaemon(true);
                UserCommandRequestThread.start();
                return this;
            }

            @Override
            protected void writeDownloadFile(String fileName, byte[] content) {
                try {
                    FileUtils.writeByteArrayToFile(new File("./downloadFiles/"+fileName), content);
                } catch (IOException e) {
                    StringWriter sw = new StringWriter();
                    PrintWriter pw = new PrintWriter(sw);
                    e.printStackTrace(pw);
                    errorPrintf("文件写入失败%s%n", sw.toString());
                }
            }

            @Override
            protected void onError(SystemProtocol systemProtocol) {
                errorPrintf("连接出现错误，服务端发送的错误代码为 %s%n", systemProtocol.getMessage());
            }

            @Override
            protected byte[] decodeBase64(String src) {
                return Base64.getDecoder().decode(src);
            }

            @Override
            protected void onClientLogin() {

            }

            @Override
            protected String getToken() {
                File token = new File("./token.txt");
                if (!token.exists())
                    return "";
                else if (!token.canRead())
                {
                    errorPrint("Token 文件无权访问!");
                    errorPrint("请检查您的权限配置");
                    return "";
                }
                try {
                    return FileUtils.readFileToString(token, StandardCharsets.UTF_8);
                } catch (IOException e) {
                    errorPrint("Token 文件读取失败!");
                    errorPrint("请检查您的权限配置");
                    return "";
                }
            }

            @Override
            protected void setToken(String newToken) {
                File token = new File("./token.txt");
                if (token.exists() && !token.canWrite())
                {
                    errorPrint("Token 文件无权写入!");
                    errorPrint("请检查您的权限配置");
                    return;
                }
                try {
                    FileUtils.writeStringToFile(token, newToken , StandardCharsets.UTF_8);
                } catch (IOException e) {
                    errorPrint("Token 文件读取失败!");
                    errorPrint("请检查您的权限配置");
                }
            }

            @Override
            protected void normalPrint(String data) {
                System.out.println(data);
            }

            @Override
            protected void normalPrintf(String data, Object... args) {
                System.out.printf(data,args);
            }

            @Override
            protected void errorPrint(String data) {
                System.err.println(data);
            }

            @Override
            protected void errorPrintf(String data, Object... args) {
                System.err.printf(data,args);
            }

            @Override
            protected ThreadFactory getWorkerThreadFactory() {
                return new ThreadFactory() {
                    private final AtomicInteger threadNumber = new AtomicInteger(1);
                    private final ThreadGroup IOThreadGroup = new ThreadGroup(Thread.currentThread().getThreadGroup(), "IO Thread Group");

                    @Override
                    public Thread newThread(@NotNull Runnable r) {
                        return new Thread(IOThreadGroup,
                                r,"Netty Worker Thread #"+threadNumber.getAndIncrement());
                    }
                };
            }

            @Override
            protected void recvRequireTOTP() {
                normalPrint("服务端要求基于TOTP的增强安全性");
                normalPrint("请使用submitTOTP客户端指令提交TOTP验证码");
                requireTOTP = true;
            }

            @Override
            protected void displayChatMessage(String sourceUserName, String message) {
                normalPrintf("[%s]:%s%n",sourceUserName,message);
            }

            @Override
            protected void displayMessage(String message) {
                normalPrintf("%s%n",message);
            }

            @Override
            protected void recvQRCodeData(byte[] data) {
                try {
                    File qrCode = File.createTempFile("JavaIM","QRCode.png");
                    qrCode.deleteOnExit();
                    FileUtils.writeByteArrayToFile(qrCode,data);
                    normalPrintf("接收到的二维码已临时保存至：%s%n",qrCode.getAbsolutePath());
                    if (!Desktop.isDesktopSupported()) {
                        normalPrint("您的系统没有桌面，无法自动打开二维码");
                        normalPrint("请您手动打开二维码");
                        return;
                    }
                    if (!Desktop.getDesktop().isSupported(Desktop.Action.OPEN)) {
                        normalPrint("您的系统不支持以关联的应用程序打开文件");
                        normalPrint("请您手动打开二维码");
                        return;
                    }
                    Desktop.getDesktop().open(qrCode);
                } catch (IOException e) {
                    errorPrint("创建临时文件失败!");
                }
            }

            @Override
            protected void caughtFileSystemReport(String mode, Object data) {
                switch (mode) {
                    case "fileList" -> {
                        TransferProtocol transferProtocol = (TransferProtocol) data;
                        StringBuilder builder = new StringBuilder();
                        transferProtocol.getTransferProtocolBody().forEach(body -> builder.append(body.getData()));
                        System.out.println("接收到文件列表报告，文件列表有:" + builder);
                    }
                    case "FileId" -> System.out.println("接收到文件ID报告，文件ID为:" + data);
                    case "FileName" -> System.out.println("接收到文件名报告，文件名为:" + data);
                }
            }
        }
        if (!new File("./token.txt").exists() || new File("./token.txt").length() == 0) {
            System.out.print("请输入用户名：");
            String userName = scanner.nextLine();
            System.out.print("请输入密码：");
            String passwd = scanner.nextLine();
            new ConsoleClient().clientCommandSystem().start(ServerIP,ServerPort,ServerCARootCert,userName,passwd);
        }
        else {
            new ConsoleClient().clientCommandSystem().start(ServerIP,ServerPort,ServerCARootCert);
        }
    }
}