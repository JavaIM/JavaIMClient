package org.yuezhikong;

import com.google.gson.Gson;
import org.apache.commons.io.FileUtils;
import org.jetbrains.annotations.NotNull;
import org.yuezhikong.Protocol.GeneralProtocol;
import org.yuezhikong.Protocol.NormalProtocol;

import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.util.Scanner;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicInteger;

public class Main {
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.print("请输入服务器IP地址：");
        String ServerIP = scanner.nextLine();
        System.out.print("请输入服务器端口：");
        int ServerPort = Integer.parseInt(scanner.nextLine());
        System.out.print("请输入服务器CA证书路径：");
        File ServerCARootCert = new File(scanner.nextLine());
        class ConsoleClient extends Client
        {
            private final Gson gson = new Gson();
            @Override
            protected void onClientLogin() {
                new Thread(() -> {
                    // 用户指令处理
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