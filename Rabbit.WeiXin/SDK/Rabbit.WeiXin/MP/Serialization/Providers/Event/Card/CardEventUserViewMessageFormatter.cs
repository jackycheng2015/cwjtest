﻿using Rabbit.WeiXin.MP.Messages.Events.Card;
using System;
using System.Xml.Linq;

namespace Rabbit.WeiXin.MP.Serialization.Providers.Event.Card
{
    internal sealed class CardEventUserViewMessageFormatter : XmlMessageFormatterBase<CardEventUserViewMessage>
    {
        #region Overrides of XmlMessageFormatterBase<CardEventUserViewMessage>

        /// <summary>
        /// 反序列化。
        /// </summary>
        /// <param name="container">Xml容器。</param>
        /// <returns>消息实例。</returns>
        public override CardEventUserViewMessage Deserialize(XContainer container)
        {
            return SetBaseInfo(container, new CardEventUserViewMessage
            {
                CardId = GetValue(container, "CardId"),
                UserCardCode = GetValue(container, "UserCardCode")
            });
        }

        /// <summary>
        /// 序列化。
        /// </summary>
        /// <param name="graph">消息实例。</param>
        /// <returns>xml内容。</returns>
        public override string Serialize(CardEventUserViewMessage graph)
        {
            throw new NotImplementedException();
        }

        #endregion Overrides of XmlMessageFormatterBase<CardEventUserViewMessage>
    }
}