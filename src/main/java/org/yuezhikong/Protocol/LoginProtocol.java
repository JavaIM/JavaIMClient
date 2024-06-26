/*
 * Simplified Chinese (简体中文)
 *
 * 版权所有 (C) 2023 QiLechan <qilechan@outlook.com> 和本程序的贡献者
 *
 * 本程序是自由软件：你可以再分发之和/或依照由自由软件基金会发布的 GNU 通用公共许可证修改之，无论是版本 3 许可证，还是 3 任何以后版都可以。
 * 发布该程序是希望它能有用，但是并无保障;甚至连可销售和符合某个特定的目的都不保证。请参看 GNU 通用公共许可证，了解详情。
 * 你应该随程序获得一份 GNU 通用公共许可证的副本。如果没有，请看 <https://www.gnu.org/licenses/>。
 * English (英语)
 *
 * Copyright (C) 2023 QiLechan <qilechan@outlook.com> and contributors to this program
 *
 * This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or 3 any later version.
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
 * You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.
 */
package org.yuezhikong.Protocol;
/**
 * 接受/发送的json的序列化/反序列化流程
 * <p>如果修改了protocol，请使用GsonFormat插件直接替换</p>
 */
public class LoginProtocol {

    /**
     * LoginPacketHead : {"type":""}
     * LoginPacketBody : {"ReLogin":{"Token":""},"NormalLogin":{"UserName":"","Passwd":""}}
     */

    private LoginPacketHeadBean LoginPacketHead;
    private LoginPacketBodyBean LoginPacketBody;

    public LoginPacketHeadBean getLoginPacketHead() {
        return LoginPacketHead;
    }

    public void setLoginPacketHead(LoginPacketHeadBean LoginPacketHead) {
        this.LoginPacketHead = LoginPacketHead;
    }

    public LoginPacketBodyBean getLoginPacketBody() {
        return LoginPacketBody;
    }

    public void setLoginPacketBody(LoginPacketBodyBean LoginPacketBody) {
        this.LoginPacketBody = LoginPacketBody;
    }

    public static class LoginPacketHeadBean {
        /**
         * type :
         */

        private String type;

        public String getType() {
            return type;
        }

        public void setType(String type) {
            this.type = type;
        }
    }

    public static class LoginPacketBodyBean {
        /**
         * ReLogin : {"Token":""}
         * NormalLogin : {"UserName":"","Passwd":""}
         */

        private ReLoginBean ReLogin;
        private NormalLoginBean NormalLogin;

        public ReLoginBean getReLogin() {
            return ReLogin;
        }

        public void setReLogin(ReLoginBean ReLogin) {
            this.ReLogin = ReLogin;
        }

        public NormalLoginBean getNormalLogin() {
            return NormalLogin;
        }

        public void setNormalLogin(NormalLoginBean NormalLogin) {
            this.NormalLogin = NormalLogin;
        }

        public static class ReLoginBean {
            /**
             * Token :
             */

            private String Token;

            public String getToken() {
                return Token;
            }

            public void setToken(String Token) {
                this.Token = Token;
            }
        }

        public static class NormalLoginBean {
            /**
             * UserName :
             * Passwd :
             */

            private String UserName;
            private String Passwd;

            public String getUserName() {
                return UserName;
            }

            public void setUserName(String UserName) {
                this.UserName = UserName;
            }

            public String getPasswd() {
                return Passwd;
            }

            public void setPasswd(String Passwd) {
                this.Passwd = Passwd;
            }
        }
    }
}
