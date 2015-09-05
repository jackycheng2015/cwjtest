using Rabbit.WeiXin.Utility;
using System;
using System.Collections;

namespace Rabbit.WeiXin.MP.Api.Material
{
    /// <summary>
    /// �زķ�����ࡣ
    /// </summary>
    public abstract class MaterialServiceBase
    {
        #region Protected Method

        /// <summary>
        /// �ϴ���
        /// </summary>
        /// <typeparam name="TResult">������͡�</typeparam>
        /// <param name="url">�����ַ��</param>
        /// <param name="bytes">���ݡ�</param>
        /// <param name="fieldName">�ļ����ơ�</param>
        /// <param name="func">�����ֶ����ݡ�</param>
        /// <returns>�����</returns>
        protected static TResult Upload<TResult>(string url, byte[] bytes, string fieldName, Func<CreateBytes, byte[][]> func = null) where TResult : class
        {
            var createBytes = new CreateBytes();
            var list = new ArrayList
            {
                createBytes.CreateFieldData(fieldName, FileHelper.GetRandomFileName(bytes), FileHelper.GetContentType(bytes), bytes),
            };
            if (func != null)
                foreach (var b in func(createBytes))
                {
                    list.Add(b);
                }
            var data = createBytes.JoinBytes(list);

            return WeiXinHttpHelper.PostResultByJson<TResult>(url, data, createBytes.ContentType);
        }

        #endregion Protected Method
    }
}