namespace Rabbit.WeiXin.MP.Messages.Events
{
    /// <summary>
    /// �¼����͡�
    /// </summary>
    public enum EventType
    {
        /// <summary>
        /// ���ġ�
        /// </summary>
        Subscribe,

        /// <summary>
        /// ȡ�����ġ�
        /// </summary>
        UnSubscribe,

        /// <summary>
        /// �û��ѹ�ע��
        /// </summary>
        Scan,

        /// <summary>
        /// �ϱ�����λ�á�
        /// </summary>
        Location,

        /// <summary>
        /// ����˵���ȡ��Ϣ�¼���
        /// </summary>
        Click,

        /// <summary>
        /// ����˵���ת�¼���
        /// </summary>
        View,

        /// <summary>
        /// ģ����Ϣ���͡�
        /// </summary>
        TemplateSendJobFinish,

        /// <summary>
        /// Ⱥ����Ϣ���͡�
        /// </summary>
        MassSendJobFinish,

        /// <summary>
        /// ɨ�����¼����¼����͡�
        /// </summary>
        ScanCode_Push,

        /// <summary>
        /// ɨ�����¼��ҵ�������Ϣ�����С���ʾ����¼�����
        /// </summary>
        ScanCode_WaitMsg,

        /// <summary>
        /// ����ϵͳ���շ�ͼ���¼����͡�
        /// </summary>
        Pic_SysPhoto,

        /// <summary>
        /// �������ջ�����ᷢͼ���¼����͡�
        /// </summary>
        Pic_Photo_Or_Album,

        /// <summary>
        /// ����΢����ᷢͼ�����¼����͡�
        /// </summary>
        Pic_WeiXin,

        /// <summary>
        /// ��������λ��ѡ�������¼����͡�
        /// </summary>
        Location_Select,

        /// <summary>
        /// �����Ự��
        /// </summary>
        KF_Create_Session,

        /// <summary>
        /// �رջỰ��
        /// </summary>
        KF_Close_Session,

        /// <summary>
        /// ת�ӻỰ��
        /// </summary>
        KF_Switch_Session,

        /// <summary>
        /// ��ȯͨ����ˡ�
        /// </summary>
        Card_Pass_Check,

        /// <summary>
        /// ��ȯ��ͨ����ˡ�
        /// </summary>
        Card_Not_Pass_Check,

        /// <summary>
        /// �û�����ȡ��ȯʱ��
        /// </summary>
        Card_User_Get,

        /// <summary>
        /// �û���ɾ����ȯʱ��
        /// </summary>
        Card_User_Delete,

        /// <summary>
        /// ��ȯ������ʱ��
        /// </summary>
        Card_User_Consume,

        /// <summary>
        /// �û��ڽ����Ա��ʱ��
        /// </summary>
        Card_User_View,

        /// <summary>
        /// �û��ڿ�ȯ�����鿴���ںŽ���Ựʱ����Ҫ�û��Ѿ���ע���ںţ���
        /// </summary>
        Card_UserEnterSession
    }
}