using System;
using System.Text;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Net.Security;
using System.Xml;
using System.IO;
using Saft_client;

namespace SimpleTest
{

    public class Simple2
    {
        public const string userName = "xxxxxxxxxxx";
        public const string password = "xxxxxxxxxxx";

        public const string STORE_PATH = "";
        public const string STORE_PASSWORD = "";

        public void Call()
        {

            X509Certificate2 certificate = new X509Certificate2(STORE_PATH, STORE_PASSWORD);

            HttpWebRequest webRequest = CreateSOAPWebRequest();
            webRequest.ClientCertificates.Add(certificate);
            webRequest.ServerCertificateValidationCallback = RemoteCertificateValidationCallback;

            XmlDocument soapEnvelop = CreateEnvelop(certificate, userName, password);

            InsertSoapEnvelopeIntoWebRequest(soapEnvelop, webRequest);


            // begin async call to web request.
            IAsyncResult asyncResult = webRequest.BeginGetResponse(null, null);

            // suspend this thread until call is complete. You might want to
            // do something usefull here like update your UI.
            asyncResult.AsyncWaitHandle.WaitOne();

            // get the response from the completed web request.
            string soapResult;
            using (WebResponse webResponse = webRequest.EndGetResponse(asyncResult))
            {
                using (StreamReader rd = new StreamReader(webResponse.GetResponseStream()))
                {
                    soapResult = rd.ReadToEnd();
                }
                Console.Write(soapResult);
            }
        }

        /// <summary>
        /// create web request for "guia transporte"
        /// </summary>
        /// <returns></returns>
        public HttpWebRequest CreateSOAPWebRequest()
        {

            UriBuilder guiat = new UriBuilder();
            guiat.Host = "servicos.portaldasfinancas.gov.pt";
            guiat.Scheme = "https";
            guiat.Port = 701;
            guiat.Path = "sgdtws/documentosTransporte";

            //Making Web Request    
            HttpWebRequest Req = (HttpWebRequest)WebRequest.Create(guiat.Uri);
            //SOAPAction    
            Req.Headers.Add(@"SOAPAction:https://servicos.portaldasfinancas.gov.pt:701/sgdtws/documentosTransporte");
            //Content_type    
            Req.ContentType = "text/xml;charset=\"utf-8\"";
            Req.Accept = "text/xml";
            //HTTP method    
            Req.Method = "POST";
            //return HttpWebRequest    
            return Req;
        }

        private static bool RemoteCertificateValidationCallback(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            return true;
        }


        public XmlDocument CreateEnvelop( X509Certificate2 cert, string userName, string password)
        {
            XmlDocument SOAPReqBody = new XmlDocument();
            // SOAP header request
            string  doc = Helpers.CreateHeader(cert, userName, password);
            //SOAP body request  
            doc += System.IO.File.ReadAllText(@"exemplo_body.txt");

            SOAPReqBody.LoadXml(doc);

            return SOAPReqBody;
        }

        private void InsertSoapEnvelopeIntoWebRequest(XmlDocument soapEnvelopeXml, HttpWebRequest webRequest)
        {
            using (Stream stream = webRequest.GetRequestStream())
            {
                soapEnvelopeXml.Save(stream);
            }
        }

    }
}