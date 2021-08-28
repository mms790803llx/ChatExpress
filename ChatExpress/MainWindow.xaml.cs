using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Numerics;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using CryptLibrary;


namespace ChatExpress
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            if (File.Exists(UserUtils.UserInfoPath))
            {
                new LoginWindow().Show();
                Close();
            }
            InitializeComponent();
        }

        private void OkButton_Click(object sender, RoutedEventArgs e)
        {
            if (UserNameInput.Text == "" || PasswordInput.Password == "")
            {
                MessageBox.Show("Must Non-Empty Password and Username");
                return;
            }
            if(!UserUtils.SetUpFirst(UserNameInput.Text, PasswordInput.Password))
            {
                MessageBox.Show("Set up failed!");
                return;
            }
            else
            {
                new LoginWindow().Show();
                Close();
            }

        }

        private void MakeRandButton_Click(object sender, RoutedEventArgs e)
        {
            byte[] key = new byte[10];
            new Random().NextBytes(key);
            PasswordInput.Password = new UnicodeEncoding().GetString(key);

        }
        private void InputButton_Click(object sender, RoutedEventArgs e)
        {
            if (MessageBox.Show("Are you sure to import password(The password before will be reseted.)", "Warning", MessageBoxButton.YesNo) == MessageBoxResult.Yes)
            {

                try
                {
                    var fileChooser = new Microsoft.Win32.OpenFileDialog()
                    {
                        Filter = "Password Files(*.dat)|*.dat"
                    };
                    var result = fileChooser.ShowDialog();
                    if (result == true)
                    {
                        if (File.Exists(UserUtils.UserInfoPath))
                        {
                            File.Delete(UserUtils.UserInfoPath);
                        }
                        File.Copy(fileChooser.FileName, UserUtils.UserInfoPath);
                    }
                }
                catch (Exception ex)
                {
                    MessageBox.Show("Failed to import password.");
                }
            }
        }



#if TEST
        private void startButton_Click(object sender, RoutedEventArgs e)
        {
            var stream = new CryptoUtils.CryptoStream(CryptoUtils.CryptoType.AES128, CryptoUtils.CryptWay.Encrypt, null);
            var srcArr = new UnicodeEncoding().GetBytes(textInput.Text);
            stream.Write(srcArr);
            var resultArr = new byte[stream.Length];
            stream.Seek(0, SeekOrigin.Begin);
            stream.Read(resultArr,0,(int)stream.Length);
            stream.Clear();
            stream.Crypto = CryptoUtils.CryptoType.AES128;
            stream.Way = CryptoUtils.CryptWay.Decrypt;
            stream.Write(resultArr);
            var againArr = new byte[stream.Length];
            stream.Seek(0, SeekOrigin.Begin);
            stream.Read(againArr, 0, (int)stream.Length);
            stream.Clear();
            var again = new UnicodeEncoding().GetString(againArr);
            outputText.Text += "\nAES128 TESTED.RESULT:\n";
            outputText.Text += "Encrypt Result:"+new BigInteger(resultArr).ToString()+"\n";
            outputText.Text += "Pubkey:" + new BigInteger(stream.Password.PublicKey).ToString() + "\n";
            outputText.Text += "Privkey:" + new BigInteger(stream.Password.PrivateKey).ToString() + "\n";
            outputText.Text += "Again:" + again;
            //CHECKS THE RSA.
            stream.Password = null;
            stream.Crypto = CryptoUtils.CryptoType.RSA2048;
            stream.Way = CryptoUtils.CryptWay.Encrypt;
            stream.Write(srcArr);
             resultArr = new byte[stream.Length];
            stream.Seek(0, SeekOrigin.Begin);
            stream.Read(resultArr, 0, (int)stream.Length);
            stream.Clear();
            stream.Crypto = CryptoUtils.CryptoType.RSA2048;
            stream.Way = CryptoUtils.CryptWay.Decrypt;
            stream.Write(resultArr);
           againArr = new byte[stream.Length];
            stream.Seek(0, SeekOrigin.Begin);
            stream.Read(againArr, 0, (int)stream.Length);
            stream.Clear();
            again = new UnicodeEncoding().GetString(againArr);
            outputText.Text += "\nRSA2048 TESTED.RESULT:\n";
            outputText.Text += "Encrypt Result:" + new BigInteger(resultArr).ToString() + "\n";
            outputText.Text += "Pubkey:" + new BigInteger(stream.Password.PublicKey).ToString() + "\n";
            outputText.Text += "Privkey:" + new BigInteger(stream.Password.PrivateKey).ToString() + "\n";
            outputText.Text += "Again:" + again;
            //CHECKS THE SM2.
            stream.Password = null;
            stream.Crypto = CryptoUtils.CryptoType.SM2;
            stream.Way = CryptoUtils.CryptWay.Encrypt;
            stream.Write(srcArr);
            resultArr = new byte[stream.Length];
            stream.Seek(0, SeekOrigin.Begin);
            stream.Read(resultArr, 0, (int)stream.Length);
            stream.Clear();
            stream.Crypto = CryptoUtils.CryptoType.SM2;
            stream.Way = CryptoUtils.CryptWay.Decrypt;
            stream.Write(resultArr);
            againArr = new byte[stream.Length];
            stream.Seek(0, SeekOrigin.Begin);
            stream.Read(againArr, 0, (int)stream.Length);
            stream.Clear();
            again = new UnicodeEncoding().GetString(againArr);
            outputText.Text += "\nSM2 TESTED.RESULT:\n";
            outputText.Text += "Encrypt Result:" + new BigInteger(resultArr).ToString() + "\n";
            outputText.Text += "Pubkey:" + new BigInteger(stream.Password.PublicKey).ToString() + "\n";
            outputText.Text += "Privkey:" + new BigInteger(stream.Password.PrivateKey).ToString() + "\n";
            outputText.Text += "Again:" + again;
        }
#endif
    }
}
