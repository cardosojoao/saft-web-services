using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Net.Security;
using System.ServiceModel.Channels;
using System.ServiceModel.Security;
using System.ServiceModel;

namespace SimpleTest
{
    public class Simple1
    {
        public const string userName = "xxxxxxxxxxx";
        public const string password = "xxxxxxxxxxx";

        public const string STORE_PATH = "store.pfx";
        public const string STORE_PASSWORD = "";

        public void Call()
        {
            string remoteAddress = "https://servicos.portaldasfinancas.gov.pt:701/sgdtws/documentosTransporte";
            string endpointConfigurationName = "documentosTransporteSOAP";

            AtIRCService.documentosTransporteClient proxy = new AtIRCService.documentosTransporteClient(endpointConfigurationName, remoteAddress);

            X509Certificate2 certificate = new X509Certificate2("store.pfx", STORE_PASSWORD);

            proxy.ClientCredentials.ClientCertificate.Certificate = certificate;

            AtIRCService.StockMovement req = new AtIRCService.StockMovement();

            //req.declaracao , todo:  popular a declaracao
            //req.versaoDeclaracao = "2217";

            //colocar os bytes do ficheiro modelo 22 como mandam as regras, else da um erro interno
            //req.declaracao= Encoding.UTF8.GetBytes("blah blah bçagdfklg dfgdf");

            proxy.envioDocumentoTransporte(req);
        }

    }
}
