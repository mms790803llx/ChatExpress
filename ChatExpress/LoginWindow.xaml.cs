using System;
using System.Collections.Generic;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Shapes;
using System.IO;

namespace ChatExpress
{
    /// <summary>
    /// LoginWindow.xaml 的交互逻辑
    /// </summary>
    public partial class LoginWindow : Window
    {
        public LoginWindow()
        {
            InitializeComponent();
        }

        private void OkButton_Click(object sender, RoutedEventArgs e)
        {
            if (UserUtils.CheckUser(UserNameInput.Text, PasswordInput.Password))
            {
                new ChatWindow().Show();
                Close();
            }
            else
            {
                MessageBox.Show("Wrong Password or Username!");
            }
        }

        private void ResetButton_Click(object sender, RoutedEventArgs e)
        {
            if (MessageBox.Show("Are you sure to reset username and password(Can't decrypt cache files like chat logs!)","Warning",MessageBoxButton.YesNo) == MessageBoxResult.Yes)
            {
                File.Delete(UserUtils.UserInfoPath);
                MessageBox.Show("Reseted.");
                new MainWindow().Show();
                Close();
            }
        }

        private void InputButton_Click(object sender, RoutedEventArgs e)
        {
            if(MessageBox.Show("Are you sure to import password(The password before will be reseted.)", "Warning", MessageBoxButton.YesNo) == MessageBoxResult.Yes)
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
                catch(Exception ex)
                {
                    MessageBox.Show("Failed to import password.");
                }
            }
        }
    }
}
