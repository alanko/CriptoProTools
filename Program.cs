using System;
using System.IO;
using System.Net;
using System.Net.Mail;
using System.Net.Mime;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace SignMail
{
    class Program
    {
        static void Main(string[] args)
        {
            //Проверка корректности переданных параметров
            if (args.Length == 0)
            {
                Console.WriteLine(
                   "Mail.SignMessage <server> <smtpport> <login> <password> <from> <to> <subject> <mailbody> <file_attach>");
                return;
            }
        
        //РАЗБЕРЕМ ПЕРЕДАННЫЕ ПАРАМЕТРЫ
        // Адрес SMTP сервера
        string smtpserver = args[0];
        // порт подключения
        int smtpport = int.Parse(args[1]);
        // логин для авторизации
        string login = args[2];
        // пароль для авторизация
        string pass = args[3];
        // адрес отправителя
        string from = args[4];
        // адрес получателя
        string to = args[5];
        // текст темы
        string mailsubject = args[6];
        // текст сообщения
        string mailbody = args[7];
        string attachFile = args[8];

        // подстрока поиска собственного сертификата - 
        // считаем, что строка отправителя содержится в
        // Subject сертификата.
        string signercertdn = args[4];

        // Проверям существует ли файл
        if (!File.Exists(attachFile))
        {
            Console.WriteLine("File not found.");
            return;
        }

        // Распарсим информацию о файле вложения
        FileInfo fname = new FileInfo(attachFile);
        string attachname = fname.Name;

        // декодируем файл в base64
        string encoded = base64encode(attachFile);

        // Ищем сертификат для подписи.
        X509Store store = new X509Store(StoreLocation.LocalMachine);
        store.Open(OpenFlags.OpenExistingOnly | OpenFlags.ReadOnly);
        X509Certificate2Collection certColl = store.
            Certificates.Find(X509FindType.FindBySubjectName,
            signercertdn, false);
        if (certColl.Count == 0)
        {
            Console.WriteLine("Certificate not found.");
            return;
        }
        if (certColl.Count > 1)
        {
            Console.WriteLine("Found more than one signing certificate.");
            return;
        }
        X509Certificate2 signercert = certColl[0];

        // Создаем тело сообщения для подписи.
        string strbody =
            "Content-Type: multipart/mixed;boundary=\"--line888\"\r\n" +
            "\r\n" +
            "----line888\r\n" +
            "Content-Type: text/plain;charset=\"utf-8\"\r\n" +
            "Content-Transfer-Encoding: quoted-printable\r\n" +
            "\r\n" +
            mailbody +
            "\r\n" +
            "----line888\r\n" +
            "Content-Type: application/octet-stream;name=\"" + attachname + "\"\r\n" +
            "Content-Transfer-Encoding: base64\r\n" +
            "Content-Disposition: attachment; filename=\"" + attachname + "\"\r\n" +
            "\r\n" +
            encoded +
            "\r\n" +
            "----line888--\r\n";

        // Подписываем.
        byte[] data = Encoding.UTF8.GetBytes(strbody);
        ContentInfo content = new ContentInfo(data);
        SignedCms signedCms = new SignedCms(content, true);
        CmsSigner signer = new CmsSigner(
            SubjectIdentifierType.IssuerAndSerialNumber,
            signercert);
        signedCms.ComputeSignature(signer);
        byte[] signedbytes = signedCms.Encode();

        string signData = Convert.ToBase64String(signedbytes, Base64FormattingOptions.InsertLineBreaks);

        //Создаем тело письма для отправки
        string msgbody =
           "----line222\r\n" +
           "Content-Type: multipart/mixed;boundary=\"--line888\"\r\n" +
           "\r\n" +
           "----line888\r\n" +
           "Content-Type: text/plain;charset=\"utf-8\"\r\n" +
           "Content-Transfer-Encoding: quoted-printable\r\n" +
           "\r\n" +
           mailbody +
           "\r\n" +
           "----line888\r\n" +
           "Content-Type: application/octet-stream;name=\"" + attachname + "\"\r\n" +
           "Content-Transfer-Encoding: base64\r\n" +
           "Content-Disposition: attachment; filename=\"" + attachname + "\"\r\n" +
           "\r\n" +
           encoded +
           "\r\n" +
           "----line888--\r\n" +
           "----line222\r\n" +
           "Content-Type: application/pkcs7-signature; name=\"smime.p7s\"\r\n" +
           "Content-Transfer-Encoding: base64\r\n" +
           "Content-Disposition: attachment; filename=\"smime.p7s\"\r\n" +
           "Content-Description: S/MIME Cryptographic Signature\r\n" +
           "\r\n" +
           signData +
           "\r\n" +
           "----line222--\r\n";


        // Создаем email сообщение
        MailMessage msg = new MailMessage();
        msg.From = new MailAddress(from);
        msg.To.Add(new MailAddress(to));
        msg.Subject = mailsubject;
        msg.Headers.Remove("Content-Transfer-Encoding");
        
        // Выставляем параметры для просмотра сообщения.
        ContentType mimeType = new System.Net.Mime.ContentType("multipart/signed; protocol=\"application/pkcs7-signature\"; boundary=\"--line222\"");

        AlternateView av = AlternateView.CreateAlternateViewFromString(msgbody, mimeType);
        av.TransferEncoding = TransferEncoding.EightBit;
        msg.AlternateViews.Add(av);

        // Отправляем сообщение.
        SmtpClient client = new SmtpClient(smtpserver);
        client.Credentials = new NetworkCredential(login, pass);
        client.Port = smtpport;
        client.EnableSsl = true;
        try
        {
            Console.WriteLine("Sending mail...");
            client.Send(msg);
            client.Dispose();
            Console.WriteLine("Mail was sent successfully!");
            string[] keys = msg.Headers.AllKeys;
            Console.WriteLine("Headers");
            foreach (string s in keys)
            {
                Console.WriteLine("{0}:", s);
                Console.WriteLine("    {0}", msg.Headers[s]);
            }
        }
        catch (Exception ep)
        {
            Console.WriteLine("failed to send mail:");
            Console.WriteLine(ep.Message);
        }

        }
        
        // Функция преобразования файла в строку в base64
        public static string base64encode(string filename)
        {
            FileStream fs = new FileStream(filename, FileMode.Open, FileAccess.Read);
            byte[] filebytes = new byte[fs.Length];
            fs.Read(filebytes, 0, Convert.ToInt32(fs.Length));
            string encodedData = Convert.ToBase64String(filebytes, Base64FormattingOptions.InsertLineBreaks);
            return encodedData;
        }
    }
}
