using Rabbit.WeiXin.DependencyInjection;
using Rabbit.WeiXin.MP.Messages;
using Rabbit.WeiXin.Utility.Extensions;
using System.Text;
using System.Threading.Tasks;
using Tencent;

namespace Rabbit.WeiXin.Handlers.Impl
{
    /// <summary>
    /// ����������Ϣģ���м���������Ϣ���������Ƚ��н��ܲ�������
    /// </summary>
    public sealed class CreateRequestMessageHandlerMiddleware : HandlerMiddleware
    {
        /// <summary>
        /// ��ʼ��һ���µĴ����м����
        /// </summary>
        /// <param name="next">��һ�������м����</param>
        public CreateRequestMessageHandlerMiddleware(HandlerMiddleware next)
            : base(next)
        {
        }

        #region Overrides of HandlerMiddleware

        /// <summary>
        /// ���á�
        /// </summary>
        /// <param name="context">���������ġ�</param>
        /// <returns>����</returns>
        public override Task Invoke(IHandlerContext context)
        {
            var request = context.Request;
            var dependencyResolver = context.GetDependencyResolver();
            var requestMessageFactory = dependencyResolver.GetService<IRequestMessageFactory>();

            var content = Encoding.UTF8.GetString(request.InputStream.ReadBytes());

            #region Decrypt

            var encryptType = request.QueryString["encrypt_type"];

            if (encryptType != null)
            {
                var nonce = request.QueryString["nonce"];
                var signature = request.QueryString["msg_signature"];
                var timestamp = request.QueryString["timestamp"];

                var baseInfo = context.GetMessageHandlerBaseInfo();
                var appId = baseInfo.AppId;
                var encodingAesKey = baseInfo.EncodingAesKey;
                var token = baseInfo.Token;

                var wxBizMsgCrypt = new WXBizMsgCrypt(token, encodingAesKey, appId);
                wxBizMsgCrypt.DecryptMsg(signature, timestamp, nonce, content, ref content);
            }

            #endregion Decrypt

            context.SetRequestMessage(requestMessageFactory.CreateRequestMessage(content));

            return Next.Invoke(context);
        }

        #endregion Overrides of HandlerMiddleware
    }
}