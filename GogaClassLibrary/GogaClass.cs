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
        static public string InverseByBase(string IncomingString, int MoveBase)
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

        static public string InverseString(string IncomingString)
        {
            StringBuilder InversedString = new StringBuilder();
            for (int Index = IncomingString.Length - 1; Index >= 0; Index--)
            {
                InversedString.Append(IncomingString[Index]);
            }
            return InversedString.ToString();
        }

        static public string ConvertToLetterDigit(string IncomingString)
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

        private static char ChangeChar(char ch, int[] EnCode)
        {
            ch = char.ToUpper(ch);
            if (ch >= 'A' && ch <= 'H')
                return Convert.ToChar(Convert.ToInt16(ch) + 2 * EnCode[0]);
            else if (ch >= 'I' && ch <= 'P')
                return Convert.ToChar(Convert.ToInt16(ch) - EnCode[2]);
            else if (ch >= 'Q' && ch <= 'Z')
                return Convert.ToChar(Convert.ToInt16(ch) - EnCode[1]);
            else if (ch >= '0' && ch <= '4')
                return Convert.ToChar(Convert.ToInt16(ch) + 5);
            else if (ch >= '5' && ch <= '9')
                return Convert.ToChar(Convert.ToInt16(ch) - 5);
            else
                return '0';
        }




        private static string RunQuery(string TableName, string MethodName)
        {

            ManagementObjectSearcher MOS = new ManagementObjectSearcher(
                "Select * from Win32_" + TableName);
            foreach (ManagementObject MO in MOS.Get())
            {

                try
                {

                    return MO[MethodName].ToString();
                }
                catch
                {
                }
            }
            return "";
        }

        private static string RemoveUseLess(string st)
        {
            char ch;
            for (int i = st.Length - 1; i >= 0; i--)
            {
                ch = char.ToUpper(st[i]);

                if ((ch < 'A' || ch > 'Z') &&
                    (ch < '0' || ch > '9'))
                {
                    st = st.Remove(i, 1);
                }
            }
            return st;
        }

        public static string MakeAccessCode(string zzz)
        {

            zzz += GetMacAddresss();
            zzz += RunQuery("BaseBoard", "SerialNumber");
            zzz += RunQuery("BaseBoard", "product");
            zzz = RemoveUseLess(zzz);
            if (zzz.Length < 25)
                return MakeAccessCode(zzz);

            zzz = zzz.Substring(0, 25).ToUpper();

            zzz = SerialEncryption.Boring(SerialEncryption.InverseByBase(zzz, 10));
            return zzz;
        }

        public static string GetMacAddresss()
        {
            try
            {
                IPGlobalProperties computerProperties = IPGlobalProperties.GetIPGlobalProperties();

                //ClientId, Computer_Name,MAC,  IP, Date/Time, ? Username 
                NetworkInterface adapter = null; int i;
                NetworkInterface[] nics = NetworkInterface.GetAllNetworkInterfaces();
                if (nics == null || nics.Length < 1) return null;
                for (i = 0; i < nics.Length; i++)
                {
                    if (nics[i].NetworkInterfaceType.Equals(NetworkInterfaceType.Ethernet))
                    {
                        adapter = nics[i]; break;
                    }
                }

                PhysicalAddress address = adapter.GetPhysicalAddress();
                byte[] bytes = address.GetAddressBytes();
                string s = "";
                for (i = 0; i < bytes.Length; i++) s += string.Format("{0:X2}", bytes[i]);
                String strHostName = Dns.GetHostName();

                IPAddress[] addr = Dns.GetHostAddresses(strHostName);

                return s;
            }
            catch
            {
                return null;
            }

        }



    }

}
