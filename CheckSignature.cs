using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Tencent;

namespace Sample_1
{
    //public class CheckSignature
    //{
    //    /// <summary>
    //    /// 在网站没有提供Token（或传入为null）的情况下的默认Token。
    //    /// </summary>
    //    public const string Token = "weixin";
    //    /// <summary>
    //    /// 在网站没有提供EncodingAESKey（或传入为null）的情况下的默认Token，建议在网站中进行配置。
    //    /// </summary>
    //    public const string EncodingAESKey = "5VAJ4SaTmWyPyMkEwgfC4UtYPK6ntm7iRn6UHBQ5A16";
    //    ///// <summary>
    //    ///// 在网站没有提供CorpId（或传入为null）的情况下的默认Token，建议在网站中进行配置。
    //    ///// </summary>
    //    //public const string CorpId = "Senparc";

    //    /// <summary>
    //    /// 检查签名是否正确
    //    /// </summary>
    //    /// <param name="signature"></param>
    //    /// <param name="timestamp"></param>
    //    /// <param name="nonce"></param>
    //    /// <param name="token"></param>
    //    /// <returns></returns>
    //    public static bool Check(string signature, string timestamp, string nonce, string token)
    //    {
    //        return signature == GetSignature(timestamp, nonce, token);
    //    }

    //    /// <summary>
    //    /// 返回正确的签名
    //    /// </summary>
    //    /// <param name="timestamp"></param>
    //    /// <param name="nonce"></param>
    //    /// <param name="token"></param>
    //    /// <returns></returns>
    //    public static string GetSignature(string timestamp, string nonce, string token = Token)
    //    {
    //        token = token ?? Token;
    //        string[] arr = new[] { token, timestamp, nonce }.OrderBy(z => z).ToArray();
    //        string arrString = string.Join("", arr);
    //        System.Security.Cryptography.SHA1 sha1 = System.Security.Cryptography.SHA1.Create();
    //        byte[] sha1Arr = sha1.ComputeHash(Encoding.UTF8.GetBytes(arrString));
    //        StringBuilder enText = new StringBuilder();
    //        foreach (var b in sha1Arr)
    //        {
    //            enText.AppendFormat("{0:x2}", b);
    //        }
    //        return enText.ToString();
    //    }
    //}





{
    public static class Signature
    {
        /// <summary>
        /// 在网站没有提供Token（或传入为null）的情况下的默认Token，建议在网站中进行配置。
        /// </summary>
        public const string Token = "weixin";
        /// <summary>
        /// 在网站没有提供EncodingAESKey（或传入为null）的情况下的默认Token，建议在网站中进行配置。
        /// </summary>
        public const string EncodingAESKey = "8eKaVU1Ei6M3c3kGY21LKNObvepQuIyQLCLKIt5Zc8u";
        /// <summary>
        /// 在网站没有提供CorpId（或传入为null）的情况下的默认Token，建议在网站中进行配置。
        /// </summary>
        public const string CorpId = "Senparc";

        /// <summary>
        /// 获取签名
        /// </summary>
        /// <param name="token"></param>
        /// <param name="timeStamp"></param>
        /// <param name="nonce"></param>
        /// <param name="msgEncrypt"></param>
        /// <returns></returns>
        public static string GenarateSinature(string token, string timeStamp, string nonce, string msgEncrypt)
        {
            string msgSignature = null;
            var result = Tencent.WXBizMsgCrypt.GenarateSinature(token, timeStamp, nonce, msgEncrypt, ref msgSignature);
            return result == 0 ? msgSignature : result.ToString();
        }

        /// <summary>
        /// 检查签名
        /// </summary>
        /// <param name="token"></param>
        /// <param name="encodingAESKey"></param>
        /// <param name="corpId"></param>
        /// <param name="msgSignature">签名串，对应URL参数的msg_signature</param>
        /// <param name="timeStamp">时间戳，对应URL参数的timestamp</param>
        /// <param name="nonce">随机串，对应URL参数的nonce</param>
        /// <param name="echoStr">随机串，对应URL参数的echostr</param>
        /// <returns></returns>
        public static string VerifyURL(string token, string encodingAESKey, string corpId, string msgSignature, string timeStamp, string nonce, string echoStr)
        {
            WXBizMsgCrypt crypt = new WXBizMsgCrypt(token, encodingAESKey, corpId);
            string replyEchoStr = null;
            var result = crypt.VerifyURL(msgSignature, timeStamp, nonce, echoStr, ref replyEchoStr);
            if (result == 0)
            {
                //验证成功，比较随机字符串
                return replyEchoStr;
            }
            else
            {
                //验证错误，这里可以分析具体的错误信息
                return null;
            }
        }

        /// <summary>
        /// 加密消息
        /// </summary>
        /// <param name="token"></param>
        /// <param name="encodingAESKey"></param>
        /// <param name="corpId"></param>
        /// <param name="replyMsg"></param>
        /// <param name="timeStamp"></param>
        /// <param name="nonce"></param>
        /// <returns></returns>
        public static string EncryptMsg(string token, string encodingAESKey, string corpId, string replyMsg, string timeStamp, string nonce)
        {
            WXBizMsgCrypt crypt = new WXBizMsgCrypt(token, encodingAESKey, corpId);
            string encryptMsg = null;
            var result = crypt.EncryptMsg(replyMsg, timeStamp, nonce, ref encryptMsg);
            return encryptMsg;
        }
    }
}
