package org.yuezhikong;

import com.google.gson.Gson;
import org.apache.commons.io.FileUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.jetbrains.annotations.NotNull;
import org.yuezhikong.Protocol.GeneralProtocol;
import org.yuezhikong.Protocol.NormalProtocol;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
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
            @Override
            protected void onClientLogin() {
                new Thread(() -> {
                    // 用户消息处理
                    while (true)
                    {
                        try {
                            Scanner scanner = new Scanner(System.in);
                            String Data = scanner.nextLine();
                            NormalProtocol userInput = new NormalProtocol();
                            userInput.setType("Chat");
                            userInput.setMessage(Data);

                            GeneralProtocol generalProtocol = new GeneralProtocol();
                            generalProtocol.setProtocolData(gson.toJson(userInput));
                            generalProtocol.setProtocolVersion(protocolVersion);
                            generalProtocol.setProtocolName("NormalProtocol");

                            SendData(gson.toJson(generalProtocol));
                        } catch (Throwable throwable)
                        {
                            StringWriter sw = new StringWriter();
                            PrintWriter pw = new PrintWriter(sw);
                            throwable.printStackTrace(pw);
                            System.err.println(sw);
                        }
                    }
                }, "User Command Request Thread").start();
            }

            @Override
            protected String getToken() {
                File token = new File("./token.txt");
                if (!token.exists())
                    return "";
                else if (!token.canRead())
                {
                    ErrorPrint("Token 文件无权访问!");
                    ErrorPrint("请检查您的权限配置");
                    return "";
                }
                try {
                    return FileUtils.readFileToString(token, StandardCharsets.UTF_8);
                } catch (IOException e) {
                    ErrorPrint("Token 文件读取失败!");
                    ErrorPrint("请检查您的权限配置");
                    return "";
                }
            }

            @Override
            protected void setToken(String newToken) {
                File token = new File("./token.txt");
                if (token.exists() && !token.canWrite())
                {
                    ErrorPrint("Token 文件无权写入!");
                    ErrorPrint("请检查您的权限配置");
                    return;
                }
                try {
                    FileUtils.writeStringToFile(token, newToken , StandardCharsets.UTF_8);
                } catch (IOException e) {
                    ErrorPrint("Token 文件读取失败!");
                    ErrorPrint("请检查您的权限配置");
                }
            }

            @Override
            protected void NormalPrint(String data) {
                System.out.println(data);
            }

            @Override
            protected void NormalPrintf(String data, Object... args) {
                System.out.printf(data,args);
            }

            @Override
            protected void ErrorPrint(String data) {
                System.err.println(data);
            }

            @Override
            protected void ErrorPrintf(String data, Object... args) {
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
        }
        if (!new File("./token.txt").exists() || new File("./token.txt").length() == 0) {
            System.out.print("请输入用户名：");
            String userName = scanner.nextLine();
            System.out.print("请输入密码：");
            String passwd = scanner.nextLine();
            new ConsoleClient().start(ServerIP,ServerPort,ServerCARootCert,userName,passwd);
        }
        else {
            new ConsoleClient().start(ServerIP,ServerPort,ServerCARootCert);
        }
    }
}