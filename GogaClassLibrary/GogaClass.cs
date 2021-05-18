using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.IO;
using System.Linq;
using System.Management;
using System.Net;
using System.Net.NetworkInformation;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace GogaClassLibrary
{
    class GogaClass
    {
    }
    

    public class FilterTextBox : TextBox
    {
        private string _ForbidenChars;
        private bool _InternalEditing;
        private bool _CaptleLetterOnly;
        private AcceptableCharacters _AcceptableChar;

        public enum AcceptableCharacters
        {
            LetterOnly = 0,
            DigitOnly,
            LetterOrDigit,
            All
        }

        public FilterTextBox()
        {
            _ForbidenChars = string.Empty;
            _InternalEditing = false;
            _CaptleLetterOnly = false;
            _AcceptableChar = AcceptableCharacters.All;
        }

        #region " Appearance "

        /// <summary>
        /// Indicate wich characters can't be in string
        /// </summary>
        [Category("Behavior"), DefaultValue(""),
            Description("Indicate wich characters can't be in string")]
        public string ForbidenChars
        {
            get
            {
                return _ForbidenChars;
            }
            set
            {
                _ForbidenChars = value;
                Text = Text;
            }
        }

        /// <summary>
        /// Indicate only Captle characters can write
        /// </summary>
        [Category("Behavior"), DefaultValue(false),
            Description("Indicate only Captle characters can write"), Browsable(true)]
        public bool CaptleLettersOnly
        {
            get
            {
                return _CaptleLetterOnly;
            }
            set
            {
                _CaptleLetterOnly = value;
                Text = Text;
            }
        }

        /// <summary>
        /// Indicate wich type of characters are acceptable
        /// </summary>
        [Category("Behavior"), DefaultValue(FilterTextBox.AcceptableCharacters.All),
            Description("Indicate wich type of characters are acceptable"), Browsable(true)]
        public AcceptableCharacters AcceptableChars
        {
            get
            {
                return _AcceptableChar;
            }
            set
            {
                _AcceptableChar = value;
                Text = Text;
            }
        }
        #endregion

        #region " Overrides "

        public override string Text
        {
            get
            {
                return base.Text;
            }
            set
            {
                if (_InternalEditing == true)
                    base.Text = value;
                else
                    base.Text = RemoveForbidens(value);
            }
        }

        protected override void OnTextChanged(EventArgs e)
        {
            base.OnTextChanged(e);
            int SelS = this.SelectionStart;
            _InternalEditing = true;
            Text = RemoveForbidens(Text, ref SelS);
            _InternalEditing = false;
            this.SelectionStart = SelS;
        }
        #endregion

        private string RemoveForbidens(string IncomingString, ref int SelStart)
        {
            if (_CaptleLetterOnly == true)
                IncomingString = IncomingString.ToUpper();

            for (int i = IncomingString.Length - 1; i >= 0; i--)
            {
                if (_ForbidenChars.IndexOf(IncomingString[i]) != -1)
                {
                    IncomingString = IncomingString.Remove(i, 1);
                    if (i < SelStart)
                        SelStart--;
                }
                else if (_AcceptableChar == AcceptableCharacters.DigitOnly && char.IsDigit(IncomingString[i]) != true)
                {
                    IncomingString = IncomingString.Remove(i, 1);
                    if (i < SelStart)
                        SelStart--;
                }
                else if (_AcceptableChar == AcceptableCharacters.LetterOnly && char.IsLetter(IncomingString[i]) != true)
                {
                    IncomingString = IncomingString.Remove(i, 1);
                    if (i < SelStart)
                        SelStart--;
                }
                else if (_AcceptableChar == AcceptableCharacters.LetterOrDigit && char.IsLetterOrDigit(IncomingString[i]) != true)
                {
                    IncomingString = IncomingString.Remove(i, 1);
                    if (i < SelStart)
                        SelStart--;
                }
            }
            return IncomingString;
        }

        private string RemoveForbidens(string IncomingString)
        {
            int Length = IncomingString.Length;
            return RemoveForbidens(IncomingString, ref Length);
        }
    }
    
    public static class ForNetwork
    {
        public static string GetExternalIP()
        {
            string externalIP = "";
            externalIP = new WebClient().DownloadString("http://checkip.dyndns.org/");
            externalIP = (new Regex(@"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"))
                                           .Matches(externalIP)[0].ToString();
            return externalIP;
        }
    }
    public static class Encryption
    {
        private static TripleDESCryptoServiceProvider Crypto()
        {
            TripleDESCryptoServiceProvider tdes = new TripleDESCryptoServiceProvider();
            tdes.Key = new byte[] {
                  8, 58, 198, 98, 217, 44, 142, 111,
                 170,195,22,79,212,205,72,167,
                 247,217,14,85,140,224,155,130
              };
            tdes.IV = new byte[] { 217, 114, 106, 249, 14, 55, 157, 205 };
            return tdes;
        }

        public static void Save(DataSet DataFile, string FileName)
        {
            FileStream OutStream = new FileStream(FileName, FileMode.Create);
            TripleDESCryptoServiceProvider CryptoServiceProvider = Crypto();
            CryptoStream CryptoStrm = new CryptoStream(OutStream, CryptoServiceProvider.CreateEncryptor(),
                CryptoStreamMode.Write);
            StreamWriter CryptoOutStream = new StreamWriter(CryptoStrm);

            DataFile.WriteXml(CryptoOutStream);
            CryptoOutStream.Flush(); CryptoOutStream.Close(); OutStream.Close();

        }

        public static void Read(DataSet DataFile, string FileName)
        {

            FileStream IncomingStream = null;
            IncomingStream = new FileStream(FileName, FileMode.Open);
            TripleDESCryptoServiceProvider CryptoServiceProvider = Crypto();
            CryptoStream CryptoStrm = new CryptoStream(IncomingStream, CryptoServiceProvider.CreateDecryptor(),
                CryptoStreamMode.Read);
            StreamReader cryptoInStream = new StreamReader(CryptoStrm);
            DataFile.ReadXml(cryptoInStream);
            cryptoInStream.Close(); IncomingStream.Close();


        }
    }

    public static class SerialEncryption
    {
        public static string InverseByBase(string IncomingString, int MoveBase)
        {
            if (MoveBase == 0) MoveBase = 10;
            StringBuilder InversedString = new StringBuilder();
            //st = ConvertToLetterDigit(st);
            int Index;
            for (int i = 0; i < IncomingString.Length; i += MoveBase)
            {
                if (i + MoveBase > IncomingString.Length - 1)
                    Index = IncomingString.Length - i;
                else
                    Index = MoveBase;
                InversedString.Append(InverseString(IncomingString.Substring(i, Index)));
            }
            return InversedString.ToString();
        }

        public static string InverseString(string IncomingString)
        {
            StringBuilder InversedString = new StringBuilder();
            for (int Index = IncomingString.Length - 1; Index >= 0; Index--)
            {
                InversedString.Append(IncomingString[Index]);
            }
            return InversedString.ToString();
        }

        public static string ConvertToLetterDigit(string IncomingString)
        {
            StringBuilder InversedString = new StringBuilder();
            foreach (char value in IncomingString)
            {
                if (char.IsLetterOrDigit(value) == false)
                    InversedString.Append(Convert.ToInt16(value).ToString());
                else
                    InversedString.Append(value);
            }
            return InversedString.ToString();
        }

        /// <summary>
        /// moving all characters in string insert then into new index
        /// </summary>
        /// <param name="IncomingString">string to moving characters</param>
        /// <returns>moved characters string</returns>
        public static string Boring(string IncomingString)
        {
            int NewPlace;
            char ch;
            for (int index = 0; index < IncomingString.Length; index++)
            {
                NewPlace = index * Convert.ToUInt16(IncomingString[index]);
                NewPlace = NewPlace % IncomingString.Length;
                ch = IncomingString[index];
                IncomingString = IncomingString.Remove(index, 1);
                IncomingString = IncomingString.Insert(NewPlace, ch.ToString());
            }
            return IncomingString;
        }


        public static string MakeLicenceCode(string AccessCode, string EmailAddress)
        {
            string Identifier = "";
            Identifier += (EmailAddress.Length % 10).ToString();
            Identifier += "458";// 4 characters
            return MakePassword(AccessCode, Identifier);

        }
        private static string MakePassword(string IncomingString, string Identifier)
        {
            if (Identifier.Length != 4)
                throw new ArgumentException("Identifier must be 4 character length");

            int[] IdentifierArray = new int[4];
            IdentifierArray[0] = Convert.ToInt32(Identifier[0].ToString(), 10);
            IdentifierArray[1] = Convert.ToInt32(Identifier[1].ToString(), 10);
            IdentifierArray[2] = Convert.ToInt32(Identifier[2].ToString(), 10);
            IdentifierArray[3] = Convert.ToInt32(Identifier[3].ToString(), 10);
            IncomingString = Boring(IncomingString);
            IncomingString = InverseByBase(IncomingString, IdentifierArray[0]);
            IncomingString = InverseByBase(IncomingString, IdentifierArray[1]);
            IncomingString = InverseByBase(IncomingString, IdentifierArray[2]);
            IncomingString = InverseByBase(IncomingString, IdentifierArray[3]);

            StringBuilder PasswordString = new StringBuilder();
            foreach (char value in IncomingString)
            {
                PasswordString.Append(ChangeChar(value, IdentifierArray));
            }
            return PasswordString.ToString();
        }

        private static char ChangeChar(char IncomingChar, int[] EnCode)
        {
            IncomingChar = char.ToUpper(IncomingChar);
            if (IncomingChar >= 'A' && IncomingChar <= 'H')
                return Convert.ToChar(Convert.ToInt16(IncomingChar) + 2 * EnCode[0]);
            else if (IncomingChar >= 'I' && IncomingChar <= 'P')
                return Convert.ToChar(Convert.ToInt16(IncomingChar) - EnCode[2]);
            else if (IncomingChar >= 'Q' && IncomingChar <= 'Z')
                return Convert.ToChar(Convert.ToInt16(IncomingChar) - EnCode[1]);
            else if (IncomingChar >= '0' && IncomingChar <= '4')
                return Convert.ToChar(Convert.ToInt16(IncomingChar) + 5);
            else if (IncomingChar >= '5' && IncomingChar <= '9')
                return Convert.ToChar(Convert.ToInt16(IncomingChar) - 5);
            else
                return '0';
        }




        private static string RunQuery(string TableName, string MethodName)
        {

            ManagementObjectSearcher ObjectSearcher = new ManagementObjectSearcher(
                "Select * from Win32_" + TableName);
            foreach (ManagementObject MObject in ObjectSearcher.Get())
            {
                try
                {
                    return MObject[MethodName].ToString();
                }
                catch
                {

                }
            }
            return "";
        }

        private static string RemoveUseLess(string IncomingString)
        {
            char value;
            for (int i = IncomingString.Length - 1; i >= 0; i--)
            {
                value = char.ToUpper(IncomingString[i]);

                if ((value < 'A' || value > 'Z') &&
                    (value < '0' || value > '9'))
                {
                    IncomingString = IncomingString.Remove(i, 1);
                }
            }
            return IncomingString;
        }

        public static string MakeAccessCode(string IncomingString)
        {

            IncomingString += GetMacAddresss();
            IncomingString += RunQuery("BaseBoard", "SerialNumber");
            IncomingString += RunQuery("BaseBoard", "product");
            IncomingString = RemoveUseLess(IncomingString);
            if (IncomingString.Length < 25)
                return MakeAccessCode(IncomingString);

            IncomingString = IncomingString.Substring(0, 25).ToUpper();

            IncomingString = SerialEncryption.Boring(SerialEncryption.InverseByBase(IncomingString, 10));
            return IncomingString;
        }

        public static string GetMacAddresss()
        {
            try
            {
                IPGlobalProperties computerProperties = IPGlobalProperties.GetIPGlobalProperties();

                //ClientId, Computer_Name,MAC,  IP, Date/Time, ? Username 
                NetworkInterface Adapter = null; 
                NetworkInterface[] NetworkInterfaces = NetworkInterface.GetAllNetworkInterfaces();
                if (NetworkInterfaces == null || NetworkInterfaces.Length < 1) return null;
                for (int i = 0; i < NetworkInterfaces.Length; i++)
                {
                    if (NetworkInterfaces[i].NetworkInterfaceType.Equals(NetworkInterfaceType.Ethernet))
                    {
                        Adapter = NetworkInterfaces[i]; break;
                    }
                }

                PhysicalAddress address = Adapter.GetPhysicalAddress();
                byte[] bytes = address.GetAddressBytes();
                string bytesString = "";
                for (int i = 0; i < bytes.Length; i++)
                    bytesString += string.Format("{0:X2}", bytes[i]);
                String hostName = Dns.GetHostName();

                IPAddress[] addresses = Dns.GetHostAddresses(hostName);

                return bytesString;
            }
            catch
            {
                return null;
            }

        }



    }

    public class SoftwareLocker
    {
        public enum SoftwareRegime
        {
            SendRequestRegisterServer = 0,
            SendRequestRegisterLocal = 1,
            MakeSerial = 2,
            ShowServerLicense = 3
        }
        public enum RunTypes
        {
            Trial = 0,
            Full,
            Expired,
            UnKnown
        }

        public RunTypes ShowDialog(Form RegDialog, SoftwareRegime Regime)
        {
              /*   
            DialogResult Dialog;
            switch (Regime)
            {

                case SoftwareRegime.SendRequestRegisterServer:
                    if (!LocalCL.Connected) return RunTypes.UnKnown;
                    if (SerialCL.CheckServerLicense() == true)
                        return RunTypes.Full;
                    RegDialog = new registration(
                        SerialFormsCL.SFRegime.SendRequestRegisterServer);
                    Dialog = RegDialog.ShowDialog();
                    if (Dialog == System.Windows.Forms.DialogResult.OK)
                    {
                        return RunTypes.Full;
                    }
                    else if (Dialog == DialogResult.Retry)
                        return RunTypes.Trial;
                    else
                        return RunTypes.Expired;


                case SoftwareRegime.ShowServerLicense:
                    if (!LocalCL.Connected) return RunTypes.UnKnown;

                    RegDialog = new registration(
                        SerialFormsCL.SFRegime.SendRequestRegisterServer);
                    Dialog = RegDialog.ShowDialog();
                    if (Dialog == System.Windows.Forms.DialogResult.OK)
                    {
                        return RunTypes.Full;
                    }
                    else if (Dialog == DialogResult.Retry)
                        return RunTypes.Trial;
                    else
                        return RunTypes.Expired;


                default:
                    return RunTypes.UnKnown;
            }
        */

            return RunTypes.UnKnown;

        }

        public static string LicenseChecker(SoftwareRegime Regime)
        {
            /*
            RunTypes rTypes;

                        SerialFormsCL.SoftLocker sLo = new SerialFormsCL.SoftLocker(LocalCL.CurDir);
                        rTypes = sLo.ShowDialog(SFRegime.SendRequestRegisterServer);

                        if (rTypes == RunTypes.Full)
                            return "Service is Activated";
                        else
                            return "Service runs in demo mode";
       */
           
            return "";
        }
    }

    public static class NewLicense
    {
        static string AppName = "YourAppName";
        static string MacID;
        static string IP;
        static string CompName;
        static string Notes;

        static string OrgName = "";
        static string email = "";
        static DateTime createdate = DateTime.Now;
        static DateTime enddate = DateTime.Now.AddMonths(1);
        static DateTime lastlogin = DateTime.Now;
        static DateTime supportstart = DateTime.Now;
        static DateTime supportend = DateTime.Now.AddMonths(1);
        public static void SetLicData(string Org, string em, string Notes0)
        {
            OrgName = Org;
            email = em;
            Notes = Notes0;
        }
        public static int check()
        {

            GetComputerParametters(out NewLicense.CompName, out NewLicense.MacID, out NewLicense.IP);
            string hostUrl = string.Format(
                "http://stn.cxtgroup.com/get.php/?APPName={0}&MACID={1}"
                , AppName, MacID);
            Uri hostUri = new Uri(hostUrl);

            WebClient webClient = new WebClient();

            Stream webClientStream = webClient.OpenRead(hostUri);
            StreamReader webClientStreamReader = new StreamReader(webClientStream);

            string webClientString = webClientStreamReader.ReadToEnd();

            if (webClientString == "-1")
            {
                Form WorkForm = new Form();
                WorkForm.ShowDialog();
                if (WorkForm.DialogResult == DialogResult.OK)
                {
                    string newHostUrl = string.Format(
            "http://stn.cxtgroup.com/addNewRec.php/?APPName={0}&MACID={1}&IP={2}&&CompName={3}&OrgName={4}&Email={5}&CreateDate={6}"
            + "&EndDate={7}&LastLogin={8}&SupportStart={9}&SupportEnd={10}&Notes={11}"
            , AppName, MacID, IP, CompName, OrgName, email, createdate.ToString("yyyy-MM-dd HH:mm")
            , "", lastlogin.ToString("yyyy-MM-dd HH:mm")
            , supportstart.ToString("yyyy-MM-dd HH:mm"), "", Notes
            );

                    Uri newHostUri = new Uri(newHostUrl);
                    webClientStream = webClient.OpenRead(newHostUri);
                    return 1;
                }
                else
                    return -1;
            }
            else
                return int.Parse(webClientString);

        }

        public static void GetComputerParametters(out string ComputerName, out string MacAddress, out string outgoingIPAddress)
        {
            ComputerName = Dns.GetHostName();

            IPAddress[] ipAddreses = Dns.GetHostAddresses(ComputerName);

            outgoingIPAddress = ipAddreses[0].ToString();

            try
            {
                IPGlobalProperties computerProperties = IPGlobalProperties.GetIPGlobalProperties();

                //ClientId, Computer_Name,MAC,  IP, Date/Time, ? Username 
                NetworkInterface networkInterface = null; int i;
                NetworkInterface[] networkInterfaces = NetworkInterface.GetAllNetworkInterfaces();
                if (networkInterfaces == null || networkInterfaces.Length < 1)
                {
                    MacAddress = null; 
                    return;
                }
                for (i = 0; i < networkInterfaces.Length; i++)
                {
                    if (networkInterfaces[i].NetworkInterfaceType.Equals(NetworkInterfaceType.Ethernet))
                    {
                        networkInterface = networkInterfaces[i]; 
                        break;
                    }
                }

                PhysicalAddress address = networkInterface.GetPhysicalAddress();
                byte[] bytes = address.GetAddressBytes();
                string macAddressFromBytes = "";
                for (i = 0; i < bytes.Length; i++)
                    macAddressFromBytes += string.Format("{0:X2}", bytes[i]);
                MacAddress = macAddressFromBytes;
            }
            catch
            {
                MacAddress = null;
            }
        }
    }

}
