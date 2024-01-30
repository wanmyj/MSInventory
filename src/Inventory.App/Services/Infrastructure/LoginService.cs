#region copyright
// ******************************************************************
// Copyright (c) Microsoft. All rights reserved.
// This code is licensed under the MIT License (MIT).
// THE CODE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
// INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
// IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
// TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH
// THE CODE OR THE USE OR OTHER DEALINGS IN THE CODE.
// ******************************************************************
#endregion

using System;
using System.Threading.Tasks;

using Windows.Storage.Streams;
using Windows.Security.Credentials;
using Windows.Security.Cryptography;
using Windows.Security.Cryptography.Core;
using System.Security.Cryptography;
using System.IO;
using System.Text;

namespace Inventory.Services
{
    public class LoginService : ILoginService
    {
        public LoginService(IMessageService messageService, IDialogService dialogService)
        {
            IsAuthenticated = false;
            MessageService = messageService;
            DialogService = dialogService;
        }

        public IMessageService MessageService { get; }
        public IDialogService DialogService { get; }

        public bool IsAuthenticated { get; set; }
        // generate a variable to store the filename for user account
        private static readonly string AccountFileName = "useraccount.txt";
        private static readonly string DefaultAdmin = "admin";
        private static readonly string DefaultAdminPassword = "password";

        public bool IsWindowsHelloEnabled(string userName)
        {
            if (!String.IsNullOrEmpty(userName))
            {
                if (userName.Equals(AppSettings.Current.UserName, StringComparison.OrdinalIgnoreCase))
                {
                    return AppSettings.Current.WindowsHelloPublicKeyHint != null;
                }
            }
            return false;
        }

        public Task<Result> SignInWithPasswordAsync(string userName, string password)
        {
            // Verify the password by comparing the stored hash with the computed hash
            Result verified = VerifyPassword(password, userName);
            if (!verified.IsOk)
            {
                UpdateAuthenticationStatus(false);
                return Task.FromResult(Result.Error(verified.Message, verified.Description));
            }
            UpdateAuthenticationStatus(true);
            return Task.FromResult(Result.Ok());
        }

        // Create a local user account
        public Task<bool> AddLocalAccountAsync(string userName, string password)
        {
            // make sure the user name is not empty or used
            if (string.IsNullOrWhiteSpace(password) || string.IsNullOrWhiteSpace(userName))
            {
                DialogService.ShowAsync("User name or password is empty", "Please enter a valid user name and password.", "Ok");
                return Task.FromResult(false);
            }
            if (File.Exists(AccountFileName))
            {
                string[] lines = File.ReadAllLines(AccountFileName);
                for (int i = 0; i < lines.Length; i++)
                {
                    if (lines[i].Equals(userName))
                    {
                        DialogService.ShowAsync("User name is already used", "Please enter a different user name.", "Ok");
                        return Task.FromResult(false);
                    }
                }
            }
            // Create a random salt value
            byte[] salt = new byte[16];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(salt);
            }

            // Hash the password with the salt using SHA256
            byte[] hash = HashPasswordWithSalt(password, salt);

            // Convert the hash to a base64 string for storage
            string hashString = Convert.ToBase64String(hash);

            // Save the hash and the salt to the local file
            using (var writer = new StreamWriter(AccountFileName))
            {
                writer.WriteLine(userName); // Write the user name
                writer.WriteLine(hashString); // Write the hash
                writer.WriteLine(Convert.ToBase64String(salt)); // Write the salt
            }

            UpdateAuthenticationStatus(true);
            return Task.FromResult(true);
        }

        // A method that hashes a password with a salt using SHA256
        private byte[] HashPasswordWithSalt(string password, byte[] salt)
        {
            // Convert the password to a byte array
            byte[] passwordBytes = Encoding.UTF8.GetBytes(password);

            // Create a SHA256 hash object
            using (var sha256 = SHA256.Create())
            {
                // Combine the password and the salt
                byte[] combinedBytes = new byte[passwordBytes.Length + salt.Length];
                System.Buffer.BlockCopy(passwordBytes, 0, combinedBytes, 0, passwordBytes.Length);
                System.Buffer.BlockCopy(salt, 0, combinedBytes, passwordBytes.Length, salt.Length);

                // Compute the hash of the combined bytes
                byte[] hash = sha256.ComputeHash(combinedBytes);

                // Return the hash
                return hash;
            }
        }

        private Result VerifyPassword(string password, string userName)
        {
            System.Diagnostics.Debug.WriteLine("Verify: " + password);
            if (userName == DefaultAdmin && password == DefaultAdminPassword)
            {
                return Result.Ok();
            }
            // If AccountFileName not exist, return false
            if (!File.Exists(AccountFileName))
            {
                return Result.Error("Login failed", "Please use the Admin account to initialize");
            }
            // Read the hash and the salt from the file
            string[] lines = File.ReadAllLines(AccountFileName);

            // find the user name in the file and its corresponding hash and salt
            for (int i = 0; i < lines.Length; i++)
            {
                if (lines[i].Equals(userName))
                {
                    string storedHash = lines[i + 1];
                    string storedSalt = lines[i + 2];

                    // Convert the hash and the salt to byte arrays
                    byte[] hashBytes = Convert.FromBase64String(storedHash);
                    byte[] saltBytes = Convert.FromBase64String(storedSalt);

                    // Hash the password with the salt using SHA256
                    byte[] computedHash = HashPasswordWithSalt(password, saltBytes);

                    // Compare the stored hash with the computed hash
                    if (!CompareHashes(hashBytes, computedHash))
                    {
                        return Result.Error("Password is incorrect.","Please enter a valid password.");
                    }
                    return Result.Ok();
                }
            }
            return Result.Error("User name not found", "Please enter a valid user name.");
        }

        static private bool CompareHashes(byte[] hash1, byte[] hash2)
        {
            // Check if the hashes have the same length
            if (hash1.Length != hash2.Length)
            {
                return false;
            }

            // Check if the hashes have the same content
            for (int i = 0; i < hash1.Length; i++)
            {
                if (hash1[i] != hash2[i])
                {
                    return false;
                }
            }

            // If no difference is found, the hashes are equal
            return true;
        }

#if ENABLE_WINDOWS_HELLO
        public async Task<Result> SignInWithWindowsHelloAsync()
        {
            string userName = AppSettings.Current.UserName;
            if (IsWindowsHelloEnabled(userName))
            {
                var retrieveResult = await KeyCredentialManager.OpenAsync(userName);
                if (retrieveResult.Status == KeyCredentialStatus.Success)
                {
                    var credential = retrieveResult.Credential;
                    var challengeBuffer = CryptographicBuffer.DecodeFromBase64String("challenge");
                    var result = await credential.RequestSignAsync(challengeBuffer);
                    if (result.Status == KeyCredentialStatus.Success)
                    {
                        UpdateAuthenticationStatus(true);
                        return Result.Ok();
                    }
                    return Result.Error("Windows Hello", $"Cannot sign in with Windows Hello: {result.Status}");
                }
                return Result.Error("Windows Hello", $"Cannot sign in with Windows Hello: {retrieveResult.Status}");
            }
            return Result.Error("Windows Hello", "Windows Hello is not enabled for current user.");
        }

        public async Task TrySetupWindowsHelloAsync(string userName)
        {
            if (await KeyCredentialManager.IsSupportedAsync())
            {
                if (await DialogService.ShowAsync("Windows Hello", "Your device supports Windows Hello and you can use it to authenticate with the app.\r\n\r\nDo you want to enable Windows Hello for your next sign in with this user?", "Ok", "Maybe later"))
                {
                    await SetupWindowsHelloAsync(userName);
                }
                else
                {
                    await TryDeleteCredentialAccountAsync(userName);
                }
            }
        }

        private async Task SetupWindowsHelloAsync(string userName)
        {
            var publicKey = await CreatePassportKeyCredentialAsync(userName);
            if (publicKey != null)
            {
                if (await RegisterPassportCredentialWithServerAsync(publicKey))
                {
                    // When communicating with the server in the future, we pass a hash of the
                    // public key in order to identify which key the server should use to verify the challenge.
                    var hashProvider = HashAlgorithmProvider.OpenAlgorithm(HashAlgorithmNames.Sha256);
                    var publicKeyHash = hashProvider.HashData(publicKey);
                    AppSettings.Current.WindowsHelloPublicKeyHint = CryptographicBuffer.EncodeToBase64String(publicKeyHash);
                }
            }
            else
            {
                await TryDeleteCredentialAccountAsync(userName);
            }
        }

        private async Task<IBuffer> CreatePassportKeyCredentialAsync(string userName)
        {
            // Create a new KeyCredential for the user on the device
            var keyCreationResult = await KeyCredentialManager.RequestCreateAsync(userName, KeyCredentialCreationOption.ReplaceExisting);

            if (keyCreationResult.Status == KeyCredentialStatus.Success)
            {
                // User has autheniticated with Windows Hello and the key credential is created
                var credential = keyCreationResult.Credential;
                return credential.RetrievePublicKey();
            }
            else if (keyCreationResult.Status == KeyCredentialStatus.NotFound)
            {
                await DialogService.ShowAsync("Windows Hello", "To proceed, Windows Hello needs to be configured in Windows Settings (Accounts -> Sign-in options)");
            }
            else if (keyCreationResult.Status == KeyCredentialStatus.UnknownError)
            {
                await DialogService.ShowAsync("Windows Hello Error", "The key credential could not be created. Please try again.");
            }

            return null;
        }

        const int NTE_NO_KEY = unchecked((int)0x8009000D);
        const int NTE_PERM = unchecked((int)0x80090010);

        static private async Task<bool> TryDeleteCredentialAccountAsync(string userName)
        {
            try
            {
                AppSettings.Current.WindowsHelloPublicKeyHint = null;
                await KeyCredentialManager.DeleteAsync(userName);
                return true;
            }
            catch (Exception ex)
            {
                switch (ex.HResult)
                {
                    case NTE_NO_KEY:
                        // Key is already deleted. Ignore this error.
                        break;
                    case NTE_PERM:
                        // Access is denied. Ignore this error. We tried our best.
                        break;
                    default:
                        System.Diagnostics.Debug.WriteLine(ex.Message);
                        break;
                }
            }
            return false;
        }

        static private Task<bool> RegisterPassportCredentialWithServerAsync(IBuffer publicKey)
        {
            // TODO:
            // Register the public key and attestation of the key credential with the server
            // In a real-world scenario, this would likely also include:
            //      - Certificate chain for attestation endorsement if available
            //      - Status code of the Key Attestation result : Included / retrieved later / retry type
            return Task.FromResult(true);
        }

#endif
        public void Logoff()
        {
            UpdateAuthenticationStatus(false);
        }

        private void UpdateAuthenticationStatus(bool isAuthenticated)
        {
            IsAuthenticated = isAuthenticated;
            MessageService.Send(this, "AuthenticationChanged", IsAuthenticated);
        }
    }
}
