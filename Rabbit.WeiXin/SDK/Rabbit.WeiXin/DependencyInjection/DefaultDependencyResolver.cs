﻿using Rabbit.WeiXin.Handlers.Impl;
using Rabbit.WeiXin.MP.Messages;
using Rabbit.WeiXin.MP.Serialization;
using System;
using System.Collections.Generic;

namespace Rabbit.WeiXin.DependencyInjection
{
    /// <summary>
    /// 默认的依赖解析器实现。
    /// </summary>
    public class DefaultDependencyResolver : IDependencyResolver
    {
        #region Field

        private static readonly IDependencyResolver DependencyResolver;

        private static readonly ISignatureService SignatureService = new SignatureService();

        private static readonly IMessageFormatterFactory MessageFormatterFactory = new MessageFormatterFactory();

        private static readonly IRequestMessageFactory RequestMessageFactory = new RequestMessageFactory(MessageFormatterFactory);
        private static readonly IResponseMessageFactory ResponseMessageFactory = new ResponseMessageFactory(MessageFormatterFactory);

        //局部单例。
        private readonly IUserSessionCollection _userSessionCollection = new UserSessionCollection(TimeSpan.FromMinutes(20));

        private static readonly IDictionary<Type, Func<object>> ServiceDictionary = new Dictionary<Type, Func<object>>
        {
            {typeof (ISignatureService), () => SignatureService},
            {typeof (IRequestMessageFactory), () => RequestMessageFactory},
            {typeof (IResponseMessageFactory), () => ResponseMessageFactory}
        };

        #endregion Field

        #region Constructor

        static DefaultDependencyResolver()
        {
            DependencyResolver = new DefaultDependencyResolver();
        }

        /// <summary>
        /// 初始化一个新的默认的依赖解析器。
        /// </summary>
        public DefaultDependencyResolver()
        {
            ServiceDictionary[typeof(IUserSessionCollection)] = () => _userSessionCollection;
        }

        #endregion Constructor

        #region Property

        /// <summary>
        /// 一个全局的依赖解析器实例。
        /// </summary>
        public static IDependencyResolver Instance { get { return DependencyResolver; } }

        #endregion Property

        #region Implementation of IDependencyResolver

        /// <summary>
        /// 得到一个服务实例。
        /// </summary>
        /// <param name="serviceType">服务类型。</param>
        /// <returns>服务实例。</returns>
        public virtual object GetService(Type serviceType)
        {
            return !ServiceDictionary.ContainsKey(serviceType) ? null : ServiceDictionary[serviceType]();
        }

        /// <summary>
        /// 获取多个服务实例。
        /// </summary>
        /// <param name="serviceType">服务类型。</param>
        /// <returns>服务实例数组。</returns>
        public virtual IEnumerable<object> GetServices(Type serviceType)
        {
            throw new NotImplementedException();
        }

        #endregion Implementation of IDependencyResolver

        #region Public Method

        /// <summary>
        /// 创建一个新的 <see cref="DefaultDependencyResolver"/> 依赖解析器。
        /// </summary>
        /// <returns>依赖解析器。</returns>
        public static IDependencyResolver New()
        {
            return new DefaultDependencyResolver();
        }

        #endregion Public Method
    }
}