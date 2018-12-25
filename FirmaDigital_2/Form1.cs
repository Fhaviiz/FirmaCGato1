using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Security.Cryptography.X509Certificates;
using System.IO;
using iTextSharp.text.pdf;
using System.Security.Cryptography;

namespace FirmaDigital_2
{
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();
        }

        private void Form1_Load(object sender, EventArgs e)
        {

        }

        private void button1_Click(object sender, EventArgs e)
        {
            buscaCertificado();



            //Firma con PFX
            /*
            var certificado = new Certificado(@"c:\demos\certificado.pfx");
            var firmante = new Firmante(certificado);
            firmante.Firmar(@"c:\demos\documento.pdf", @"c:\demos\documento-firmado.pdf");
            */
        }

        private void buscaCertificado()
        {
            X509Store objStore = new X509Store(StoreName.My, StoreLocation.LocalMachine);
            objStore.Open(OpenFlags.ReadOnly);
            X509Certificate2 objCert = null;
            lb_nombre_certificado.Items.Clear();

            if (objStore.Certificates != null)
                foreach (X509Certificate2 objCertTemp in objStore.Certificates)
                {
                    lb_nombre_certificado.Items.Add(objCertTemp.Subject.ToString().Replace("CN=", ""));
                }


            //if (objCert == null)
            //    MessageBox.Show("No posee certificados personal con clave privada");
            //else
            //{

            MessageBox.Show("Proceso finalizado");
            //}
        }

        private void lb_nombre_certificado_DoubleClick(object sender, EventArgs e)
        {
            //MessageBox.Show(lb_nombre_certificado.SelectedItem.ToString());
            if (lb_nombre_certificado.Items.Count == 0)
                return;

            Firma(lb_nombre_certificado.SelectedItem.ToString(), openFileDialog1.FileName, saveFileDialog1.FileName);
        }


        public void Firma(string Firmante, string PDFaFirmar, string PDFaGuardar)
        {
            X509Store objStore = new X509Store(StoreName.My, StoreLocation.LocalMachine);
            objStore.Open(OpenFlags.ReadOnly);

            var certificado = objStore.Certificates.Find(X509FindType.FindBySubjectName, Firmante, true);

            if (certificado.Count == 0)
            {
                MessageBox.Show("Error");
                return;
            }

            byte[] pdfData = File.ReadAllBytes(PDFaFirmar);
            byte[] signedData = firmaDocumento(pdfData, certificado[0]);

            File.WriteAllBytes(PDFaGuardar, signedData);
        }

        private static byte[] firmaDocumento(byte[] pdfData, X509Certificate2 cert)
        {
            using (MemoryStream stream = new MemoryStream())
            {
                var reader = new PdfReader(pdfData);
                var stp = PdfStamper.CreateSignature(reader, stream, '\0');
                var sap = stp.SignatureAppearance;

                //Protect certain features of the document 
                stp.SetEncryption(null,
                    Guid.NewGuid().ToByteArray(), //random password 
                    PdfWriter.ALLOW_PRINTING | PdfWriter.ALLOW_COPY | PdfWriter.ALLOW_SCREENREADERS,
                    PdfWriter.ENCRYPTION_AES_256);

                //Get certificate chain
                var cp = new Org.BouncyCastle.X509.X509CertificateParser();
                var certChain = new Org.BouncyCastle.X509.X509Certificate[] { cp.ReadCertificate(cert.RawData) };

                sap.SetCrypto(null, certChain, null, PdfSignatureAppearance.WINCER_SIGNED);

                //Set signature appearance
                //BaseFont helvetica = BaseFont.CreateFont(BaseFont.HELVETICA, BaseFont.CP1250, BaseFont.EMBEDDED);
                //Font font = new Font(helvetica, 12, iTextSharp.text.Font.NORMAL);
                //sap.Layer2Font = font;
                sap.SetVisibleSignature(new iTextSharp.text.Rectangle(415, 100, 585, 40), 1, null);

                var dic = new PdfSignature(PdfName.ADOBE_PPKMS, PdfName.ADBE_PKCS7_SHA1);
                //Set some stuff in the signature dictionary.
                dic.Date = new PdfDate(sap.SignDate);
                dic.Name = cert.Subject;    //Certificate name 
                if (sap.Reason != null)
                {
                    dic.Reason = sap.Reason;
                }
                if (sap.Location != null)
                {
                    dic.Location = sap.Location;
                }

                //Set the crypto dictionary 
                sap.CryptoDictionary = dic;

                //Set the size of the certificates and signature. 
                int csize = 4096; //Size of the signature - 4K

                //Reserve some space for certs and signatures
                var reservedSpace = new Dictionary<PdfName, int>();
                reservedSpace[PdfName.CONTENTS] = csize * 2 + 2; //*2 because binary data is stored as hex strings. +2 for end of field
                sap.PreClose(reservedSpace);    //Actually reserve it 

                //Build the signature 
                HashAlgorithm sha = new SHA1CryptoServiceProvider();

                var sapStream = sap.GetRangeStream();
                int read = 0;
                byte[] buff = new byte[8192];
                while ((read = sapStream.Read(buff, 0, 8192)) > 0)
                {
                    sha.TransformBlock(buff, 0, read, buff, 0);
                }
                sha.TransformFinalBlock(buff, 0, 0);

                byte[] pk = SignMsg(sha.Hash, cert, false);

                //Put the certs and signature into the reserved buffer 
                byte[] outc = new byte[csize];
                Array.Copy(pk, 0, outc, 0, pk.Length);

                //Put the reserved buffer into the reserved space 
                PdfDictionary certificateDictionary = new PdfDictionary();
                certificateDictionary.Put(PdfName.CONTENTS, new PdfString(outc).SetHexWriting(true));

                //Write the signature 
                sap.Close(certificateDictionary);
                //Close the stamper and save it 
                stp.Close();

                reader.Close();

                //Return the saved pdf 
                return stream.GetBuffer();
            }



        }

        private static byte[] SignMsg(Byte[] msg, X509Certificate2 cert, bool detached)
        {
            //Place message in a ContentInfo object. This is required to build a SignedCms object. 
            ContentInfo contentInfo = new ContentInfo(msg);

            //Instantiate SignedCms object with the ContentInfo above. 
            //Has default SubjectIdentifierType IssuerAndSerialNumber. 
            SignedCms signedCms = new SignedCms(contentInfo, detached);

            //Formulate a CmsSigner object for the signer. 
            CmsSigner cmsSigner = new CmsSigner(cert);  //First cert in the chain is the signer cert

            //Do the whole certificate chain. This way intermediate certificates get sent across as well.
            cmsSigner.IncludeOption = X509IncludeOption.ExcludeRoot;

            //Sign the CMS/PKCS #7 message. The second argument is needed to ask for the pin. 
            signedCms.ComputeSignature(cmsSigner, false);

            //Encode the CMS/PKCS #7 message. 
            return signedCms.Encode();
        }
    }
}
