using Rabbit.WeiXin.DependencyInjection;
using Rabbit.WeiXin.MP.Messages.Request;
using Rabbit.WeiXin.MP.Messages.Response;
using Rabbit.WeiXin.Utility.Extensions;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Web;

namespace Rabbit.WeiXin.Handlers
{
    /// <summary>
    /// һ������Ĵ��������ġ�
    /// </summary>
    public interface IHandlerContext
    {
        /// <summary>
        /// һ������
        /// </summary>
        HttpRequestBase Request { get; }

        /// <summary>
        /// ������Ӧ��΢�ŵ�Xml���ݡ�
        /// </summary>
        string ResponseXml { get; set; }

        /// <summary>
        /// ��������
        /// </summary>
        IDictionary<string, object> Environment { get; }

        /// <summary>
        /// �ӻ����еõ�һ��ֵ��
        /// </summary>
        /// <typeparam name="T">ֵ���͡�</typeparam>
        /// <param name="key">ֵ��key��</param>
        /// <returns>ֵ��</returns>
        T Get<T>(string key);

        /// <summary>
        /// ����һ������ֵ��
        /// </summary>
        /// <typeparam name="T">ֵ���͡�</typeparam>
        /// <param name="key">ֵ��key��</param>
        /// <param name="value">����ֵ��</param>
        /// <returns>���������ġ�</returns>
        IHandlerContext Set<T>(string key, T value);
    }

    /// <summary>
    /// һ��Ĭ�ϵĴ��������ġ�
    /// </summary>
    public sealed class HandlerContext : IHandlerContext
    {
        /// <summary>
        /// ��ʼ��һ���µĴ��������ġ�
        /// </summary>
        /// <param name="request">һ������</param>
        /// <exception cref="ArgumentNullException"><paramref name="request"/> Ϊnull��</exception>
        public HandlerContext(HttpRequest request)
            : this(new HttpRequestWrapper(request.NotNull("request")))
        {
        }

        /// <summary>
        /// ��ʼ��һ���µĴ��������ġ�
        /// </summary>
        /// <param name="request">һ������</param>
        /// <exception cref="ArgumentNullException"><paramref name="request"/> Ϊnull��</exception>
        public HandlerContext(HttpRequestBase request)
        {
            Request = request.NotNull("request");
            Environment = new ConcurrentDictionary<string, object>(StringComparer.OrdinalIgnoreCase);

            //����Ĭ�ϵ�������������
            this.SetDependencyResolver(DefaultDependencyResolver.Instance);
        }

        #region Implementation of IHandlerContext

        /// <summary>
        /// һ������
        /// </summary>
        public HttpRequestBase Request { get; private set; }

        /// <summary>
        /// ������Ӧ��΢�ŵ�Xml���ݡ�
        /// </summary>
        public string ResponseXml { get; set; }

        /// <summary>
        /// ��������
        /// </summary>
        public IDictionary<string, object> Environment { get; private set; }

        /// <summary>
        /// �ӻ����еõ�һ��ֵ��
        /// </summary>
        /// <typeparam name="T">ֵ���͡�</typeparam>
        /// <param name="key">ֵ��key�������ִ�Сд����</param>
        /// <returns>ֵ��</returns>
        public T Get<T>(string key)
        {
            object value;
            if (Environment.TryGetValue(key, out value))
                return (T)value;

            return default(T);
        }

        /// <summary>
        /// ����һ������ֵ��
        /// </summary>
        /// <typeparam name="T">ֵ���͡�</typeparam>
        /// <param name="key">ֵ��key�������ִ�Сд����</param>
        /// <param name="value">����ֵ��</param>
        /// <returns>���������ġ�</returns>
        public IHandlerContext Set<T>(string key, T value)
        {
            Environment[key] = value;

            return this;
        }

        #endregion Implementation of IHandlerContext
    }

    /// <summary>
    /// ������������չ������
    /// </summary>
    public static partial class HandlerContextExtensions
    {
        /// <summary>
        /// ����������������
        /// </summary>
        /// <param name="context">���������ġ�</param>
        /// <param name="dependencyResolver">����������ʵ����</param>
        /// <exception cref="ArgumentNullException"><paramref name="context"/> Ϊ null��</exception>
        /// <exception cref="ArgumentNullException"><paramref name="dependencyResolver"/> Ϊ null��</exception>
        /// <returns>���������ġ�</returns>
        public static IHandlerContext SetDependencyResolver(this IHandlerContext context, IDependencyResolver dependencyResolver)
        {
            context.NotNull("context").Environment["Rabbit.WeiXin.DependencyResolver"] = dependencyResolver.NotNull("dependencyResolver");

            return context;
        }

        /// <summary>
        /// ��ȡ������������
        /// </summary>
        /// <param name="context">���������ġ�</param>
        /// <exception cref="ArgumentNullException"><paramref name="context"/> Ϊ null��</exception>
        /// <exception cref="Exception">�ڵ�ǰ���������Ҳ���������������</exception>
        /// <returns>������������</returns>
        public static IDependencyResolver GetDependencyResolver(this IHandlerContext context)
        {
            var dependencyResolver = context.NotNull("context").Get<IDependencyResolver>("Rabbit.WeiXin.DependencyResolver");

            if (dependencyResolver == null)
                throw new Exception("�ڵ�ǰ���������Ҳ���������������������ͨ�� SetDependencyResolver ��������һ��������������");

            return dependencyResolver;
        }

        /// <summary>
        /// ��ȡ������Ϣ��
        /// </summary>
        /// <param name="context">���������ġ�</param>
        /// <exception cref="ArgumentNullException"><paramref name="context"/> Ϊ null��</exception>
        /// <exception cref="Exception">�ڵ�ǰ���������Ҳ���������Ϣ��</exception>
        /// <returns>������Ϣʵ����</returns>
        public static IRequestMessageBase GetRequestMessage(this IHandlerContext context)
        {
            var requestMessage = context.NotNull("content").Get<IRequestMessageBase>("Rabbit.WeiXin.RequestMessage");

            if (requestMessage == null)
                throw new Exception("�ڵ�ǰ���������Ҳ���������Ϣ����ȷ��ע��Ĵ����м�����а�����������Ϣ�����Ĵ�������");
            return requestMessage;
        }

        /// <summary>
        /// ����������Ϣ��
        /// </summary>
        /// <param name="context">���������ġ�</param>
        /// <param name="requestMessage">������Ϣ��</param>
        /// <exception cref="ArgumentNullException"><paramref name="context"/> Ϊ null��</exception>
        /// <exception cref="ArgumentNullException"><paramref name="requestMessage"/> Ϊ null��</exception>
        /// <returns>���������ġ�</returns>
        internal static IHandlerContext SetRequestMessage(this IHandlerContext context, IRequestMessageBase requestMessage)
        {
            context.NotNull("context").Environment["Rabbit.WeiXin.RequestMessage"] = requestMessage.NotNull("requestMessage");

            return context;
        }

        /// <summary>
        /// ��ȡ��Ӧ��Ϣ��
        /// </summary>
        /// <param name="context">���������ġ�</param>
        /// <exception cref="ArgumentNullException"><paramref name="context"/> Ϊ null��</exception>
        /// <exception cref="Exception">�ڵ�ǰ���������Ҳ�����Ӧ��Ϣ��</exception>
        /// <returns>��Ӧ��Ϣʵ����</returns>
        public static IResponseMessage GetResponseMessage(this IHandlerContext context)
        {
            var responseMessage = context.NotNull("context").Get<IResponseMessage>("Rabbit.WeiXin.ResponseMessage");
            return responseMessage;
        }

        /// <summary>
        /// ������Ӧ��Ϣ��
        /// </summary>
        /// <param name="context">���������ġ�</param>
        /// <param name="responseMessage">��Ӧ��Ϣ��</param>
        /// <exception cref="ArgumentNullException"><paramref name="context"/> Ϊ null��</exception>
        /// <returns>���������ġ�</returns>
        public static IHandlerContext SetResponseMessage(this IHandlerContext context, IResponseMessage responseMessage)
        {
            context.NotNull("context").Environment["Rabbit.WeiXin.ResponseMessage"] = responseMessage;

            return context;
        }

        /// <summary>
        /// ��ȡ��Ϣ���������Ϣ��
        /// </summary>
        /// <param name="context">���������ġ�</param>
        /// <exception cref="ArgumentNullException"><paramref name="context"/> Ϊ null��</exception>
        /// <exception cref="Exception">�ڵ�ǰ���������Ҳ�����Ϣ���������Ϣ��</exception>
        /// <returns>��Ϣ���������Ϣ��</returns>
        public static MessageHandlerBaseInfo GetMessageHandlerBaseInfo(this IHandlerContext context)
        {
            var info = context.NotNull("context").Get<MessageHandlerBaseInfo>("Rabbit.WeiXin.MessageHandlerBaseInfo");
            if (info == null)
                throw new Exception("�ڵ�ǰ���������Ҳ�����Ϣ���������Ϣ����ȷ������������ע������Ϣ���������Ϣ��");
            return info;
        }

        /// <summary>
        /// ������Ϣ���������Ϣ��
        /// </summary>
        /// <param name="context">���������ġ�</param>
        /// <param name="baseInfo">��Ϣ���������Ϣ��</param>
        /// <exception cref="ArgumentNullException"><paramref name="context"/> Ϊ null��</exception>
        /// <exception cref="ArgumentNullException"><paramref name="baseInfo"/> Ϊ null��</exception>
        /// <returns>���������ġ�</returns>
        public static IHandlerContext SetMessageHandlerBaseInfo(this IHandlerContext context, MessageHandlerBaseInfo baseInfo)
        {
            context.NotNull("context").Environment["Rabbit.WeiXin.MessageHandlerBaseInfo"] = baseInfo.NotNull("baseInfo");

            return context;
        }
    }
}