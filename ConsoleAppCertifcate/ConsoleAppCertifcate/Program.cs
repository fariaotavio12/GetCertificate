
using System.Drawing;
using System.Security.Cryptography.X509Certificates;
using Assinatura;
using iText.Kernel.Pdf;
using iText.Signatures;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using static iText.Signatures.PdfSigner;

class Program
{
    static void Main(string[] args)
    {


        string documentPath = @"C:\Users\55349\OneDrive\Área de Trabalho\test.pdf";

        // Permita que o usuário selecione o certificado
        X509Certificate2 certificate = SelectCertificate();

        if (certificate == null)
        {
            Console.WriteLine("Nenhum certificado selecionado. O programa será encerrado.");
            return;
        }

        AssinarPdf(documentPath, certificate);
        // Configurar o nome do assinante


        Console.WriteLine("Documento assinado com sucesso.");
    }

    private static X509Certificate2 SelectCertificate()
    {
        X509Certificate2 certificate = null;

        // Exiba a caixa de diálogo para selecionar o certificado
        X509Certificate2Collection certificates = X509Certificate2UI.SelectFromCollection(
            GetCertificates(),
            "Selecione o certificado",
            "Selecione o certificado que deseja usar para assinar o documento.",
            X509SelectionFlag.SingleSelection
        );

        // Verifique se o usuário selecionou um certificado
        if (certificates.Count > 0)
        {
            certificate = certificates[0];
        }

        return certificate;
    }

    private static X509Certificate2Collection GetCertificates()
    {
        X509Store store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadOnly);

        X509Certificate2Collection certificates = store.Certificates;

        store.Close();

        return certificates;
    }

    public static void AssinarPdf(string caminhoPdfOriginal, X509Certificate2 certificate)
    {
        string signerName = certificate.SubjectName.Name;

        // Carregue o arquivo PDF a ser assinado
        using (FileStream documentStream = new FileStream(caminhoPdfOriginal, FileMode.Open))
        {
            // Crie o assinante PDF usando o certificado
            PdfSigner pdfSigner = new PdfSigner(new PdfReader(documentStream), new FileStream(caminhoPdfOriginal + "_signed.pdf", FileMode.Create), new StampingProperties());

            // Crie um dicionário com metadados da assinatura
            PdfSignatureAppearance appearance = pdfSigner.GetSignatureAppearance();
            appearance.SetReason("Motivo da assinatura");
            appearance.SetLocation("Local da assinatura");
            appearance.SetContact("Contato do assinante");
            appearance.SetLayer2Text("Assinado por: " + signerName); // Exibir o nome do assinante na camada 2



            Org.BouncyCastle.X509.X509Certificate bcCertificate = Org.BouncyCastle.Security.DotNetUtilities.FromX509Certificate(certificate);
            Org.BouncyCastle.X509.X509Certificate[] chain = new Org.BouncyCastle.X509.X509Certificate[] { bcCertificate };


            IExternalSignature pks = new X509Certificate2Signature(certificate);

            pdfSigner.SignDetached(null, (iText.Commons.Bouncycastle.Cert.IX509Certificate[])chain, null, null, null, 0, CryptoStandard.CMS);
        }
    }

    
}
