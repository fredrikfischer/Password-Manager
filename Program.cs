using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using System.Security.Cryptography;
using System.Text;
using System.Reflection;



namespace passwordmanager
{
    public class Program
    {
        public static void Main(string[] args)
        {
            HandleInput(args);
        }

        public static void HandleInput(string[] argsInput)
        {
            try
            {
                switch (argsInput[0].ToLower())
                {
                    case "init":
                        InitClientAndServerFiles(argsInput[1].ToString(), argsInput[2].ToString());
                        break;
                    case "create": //Log in to existing vault
                        CreateLogInToVault(argsInput[1].ToString(), argsInput[2].ToString());
                        break;
                    case "get":
                        if (argsInput.Length == 3)
                        {
                            GetPropPassword(argsInput[1].ToString(), argsInput[2].ToString());
                        }
                        else if (argsInput.Length == 4)
                        {
                            GetPropPassword(argsInput[1].ToString(), argsInput[2].ToString(), argsInput[3].ToString());
                        }
                        else
                        {
                            System.Console.WriteLine("Pls ");
                        }
                        break;
                    case "set":
                        if (argsInput.Length == 4)
                        {
                            SetPropPassword(argsInput[1].ToString(), argsInput[2].ToString(), argsInput[3].ToString());
                        }
                        else if (argsInput.Length == 5)
                        {
                            SetPropPassword(argsInput[1].ToString(), argsInput[2].ToString(), argsInput[3].ToString(), argsInput[4].ToString());
                        }


                        break;
                    case "delete":
                        DeletePropPassword(argsInput[1].ToString(), argsInput[2].ToString(), argsInput[3].ToString());
                        break;
                    case "secret":
                        string secretKeyString = Convert.ToBase64String(GetSecretKey(argsInput[1]));
                        System.Console.WriteLine(secretKeyString);
                        break;
                    default:
                        System.Console.WriteLine("An argument must be provided.");
                        break;
                }
            }
            catch (Exception)
            {

            }

        }

        ///<summary>
        ///Initiates a client- and a server file. The Ccient file includes a secretkey and the server file includes an initialising vector and an empty vault.
        /// The master password is also choosen via this method.
        ///</summary>
        public static void InitClientAndServerFiles(string clientFile, string serverFile)
        {
            Kryptering krypt = new Kryptering();
            string masterpassword = ChooseMasterPassword(); //Väljer ett master password
            byte[] secretKey = krypt.kryptering.Key; //Genererar secret key
            var dictClient = new Dictionary<string, byte[]>(); //Gör en dictionary --> lägger in secretkeyn 
            dictClient.Add("secret", secretKey);
            CreateClientFile(clientFile, dictClient); //skapar clientfil
            byte[] vaultKey = CreateVaultKey(masterpassword, secretKey);
            CreateServerFile(serverFile, krypt.kryptering.IV, vaultKey); // Skapar serverfil
        }

        ///<summary>
        ///Method that returns a masterpassword from userinput.
        ///</summary>
        private static string ChooseMasterPassword()
        {
            System.Console.WriteLine("Choose a master password:");
            return System.Console.ReadLine();
        }
        private static string EnterMasterPassword()
        {
            System.Console.WriteLine("Enter master password:");
            return System.Console.ReadLine();
        }

        private static string EnterSecretKey()
        {
            byte[] secretKey;
            string secretKeyString;

            System.Console.WriteLine("Enter secret key:");
            try
            {
                secretKey = Convert.FromBase64String(System.Console.ReadLine());
                secretKeyString = Convert.ToBase64String(secretKey);
            }
            catch (Exception)
            {
                secretKeyString = "error";
            }

            return secretKeyString;
        }

        ///<summary>
        ///
        ///</summary>
        private static void CreateLogInToVault(string clientPath, string serverPath)
        {
            //skapar ny client i 'client' som login för 'server'

            //kräver MP & SK
            //Om    MP & SK + IV('server') = misslyckad dekryptering av 'vault' från 'server' = så felmeddelande + aborterat
            //När man använder 'Client' kan man GET, SET, DELETE till/från 'vault' genom att skriva in MP, men utan att behöva skriva in SK vid varje interaktion
            //OM 

            string masterPassword = EnterMasterPassword();

            string secretKeyString = EnterSecretKey();
            byte[] secretKey;
            if (secretKeyString == "error")
            {
                System.Console.WriteLine("Invalid secret key format");
            }
            else
            {
                secretKey = Convert.FromBase64String(secretKeyString);

                var dictClient = new Dictionary<string, byte[]>(); //Gör en dictionary --> lägger in secretkeyn 
                dictClient.Add("secret", secretKey);

                Dictionary<string, string> result = JsonSerializer.Deserialize<Dictionary<string, string>>(File.ReadAllText(serverPath));

                string vaultResult = result["vault"];

                Kryptering krypt = new Kryptering();
                if (krypt.Decrypt(vaultResult, CreateVaultKey(masterPassword, secretKey), GetIV(serverPath)) == "error")
                {
                    System.Console.WriteLine("Failed to unlock password vault.");
                    System.Console.WriteLine("Wrong secret key or password, try again.");
                }
                else
                {
                    System.Console.WriteLine("Vault successfully unlocked!");
                    CreateClientFile(clientPath, dictClient);
                }
            }





        }

        ///<summary>
        ///Creates and returns a vaultkey using the Rfc2898DeriveBytes class.
        ///</summary>
        private static byte[] CreateVaultKey(string masterPassword, byte[] secretKey)
        {
            Rfc2898DeriveBytes vaultKey = new Rfc2898DeriveBytes(masterPassword, secretKey);
            return vaultKey.GetBytes(32);
        }

        ///<summary>
        /// This method creates a clientfile. It checks that the clientfile is created and displays a validating text to the user.
        ///</summary>
        public static void CreateClientFile(string clientFile, Dictionary<string, byte[]> dictClient)
        {
            // Skapar clientfile och och lägger in jsonformaterad secretkey i clientfile.
            File.WriteAllText(clientFile, JsonSerializer.Serialize(dictClient));
            // verifierar att filerna skapats
            if (File.Exists(clientFile))
            {
                System.Console.WriteLine("A clientfile named " + clientFile + " exists");
            }
        }

        ///<summary>
        ///Creates a initial serverfile with IV and encrypted vault. 
        ///</summary>
        public static void CreateServerFile(string serverFile, byte[] IvValue, byte[] vaultKey)
        {
            var dictServer = new Dictionary<string, string>();
            dictServer.Add("IV", Convert.ToBase64String(IvValue));
            Kryptering krypt = new Kryptering();
            //Gör en tom dictionary
            Dictionary<string, string> initVault = new Dictionary<string, string>();
            string initVaultToJson = JsonSerializer.Serialize(initVault);
            dictServer.Add("vault", krypt.Encrypt(initVaultToJson, vaultKey, IvValue));
            File.WriteAllText(serverFile, JsonSerializer.Serialize(dictServer));

            if (File.Exists(serverFile))
            {
                System.Console.WriteLine("A serverfile named " + serverFile + " exists");
            }
        }

        ///<summary>
        ///Gets the password for a certain prop. 
        ///</summary>
        private static void GetPropPassword(string clientPath, string serverPath, string prop)
        {
            Kryptering krypt = new Kryptering();
            Dictionary<string, string> result = JsonSerializer.Deserialize<Dictionary<string, string>>(File.ReadAllText(serverPath));

            string vaultResult = result["vault"];
            byte[] IV = Convert.FromBase64String(result["IV"]);
            byte[] vaultKey = CreateVaultKey(EnterMasterPassword(), GetSecretKey(clientPath));
            string decryptedVaultResult = krypt.Decrypt(vaultResult, vaultKey, IV);

            Dictionary<string, string> deserializeVaultResult = JsonSerializer.Deserialize<Dictionary<string, string>>(decryptedVaultResult);

            if (deserializeVaultResult.ContainsKey(prop))
            {
                //System.Console.WriteLine("Your password for " + prop + " is: " + deserializeVaultResult[prop]);
                System.Console.WriteLine(deserializeVaultResult[prop]);
            }
            else
            {
                System.Console.WriteLine("Key/password does not exist in vault");
            }

            //om prop inte finns --> inget printas
            //om någon <prop> inte anges så listas alla domäner vi har nycklar sparade i, men inte nycklarna själva
            //Ska fråga efter master password
            //Om antingen MP eller SK är inkorrekt från 'server' --> misslyckad dekryptering --> aborterad command + felmeddelande
        }
        private static void GetPropPassword(string clientPath, string serverPath)
        {
            System.Console.WriteLine("Please enter your master password");
            string masterPassword = Console.ReadLine();

            Kryptering krypt = new Kryptering();
            Dictionary<string, string> result = JsonSerializer.Deserialize<Dictionary<string, string>>(File.ReadAllText(serverPath));

            string vaultResult = result["vault"];
            byte[] IV = Convert.FromBase64String(result["IV"]);
            byte[] secretKey = GetSecretKey(clientPath);
            byte[] vaultKey = CreateVaultKey(masterPassword, secretKey);
            string decryptedVaultResult = krypt.Decrypt(vaultResult, vaultKey, IV);

            Dictionary<string, string> deserializeVaultResult = JsonSerializer.Deserialize<Dictionary<string, string>>(decryptedVaultResult);


            foreach (var item in deserializeVaultResult)
            {
                System.Console.WriteLine(item.Key);
            }

            //om prop inte finns --> inget printas
            //om någon <prop> inte anges så listas alla domäner vi har nycklar sparade i, men inte nycklarna själva
            //Ska fråga efter master password
            //Om antingen MP eller SK är inkorrekt från 'server' --> misslyckad dekryptering --> aborterad command + felmeddelande
        }

        ///<summary>
        ///Sets the password for a certain prop.
        ///</summary>
        private static void SetPropPassword(string clientPath, string serverPath, string prop)
        {
            string masterPassword = EnterMasterPassword();

            System.Console.WriteLine("Choose a password for " + prop);
            string newPassword = Console.ReadLine();


            Kryptering krypt = new Kryptering();

            // Decrypts
            byte[] IV = GetIV(serverPath);
            byte[] secretKey = GetSecretKey(clientPath);
            byte[] vaultKey = CreateVaultKey(masterPassword, secretKey);
            string encryptedVault = GetEncryptedVault(serverPath);
            string decryptedSerializedVault = krypt.Decrypt(encryptedVault, vaultKey, IV);
            // Deserialize
            Dictionary<string, string> decryptedDeserializedVault = JsonSerializer.Deserialize<Dictionary<string, string>>(decryptedSerializedVault);
            //Creates new vault
            Dictionary<string, string> serverDict = new Dictionary<string, string>();
            serverDict.Add("IV", Convert.ToBase64String(IV));

            decryptedDeserializedVault.Add(prop, newPassword);
            string jsonVault = JsonSerializer.Serialize(decryptedDeserializedVault);
            string encryptedJsonVault = krypt.Encrypt(jsonVault, vaultKey, IV);
            serverDict.Add("vault", encryptedJsonVault);

            File.WriteAllText(serverPath, JsonSerializer.Serialize(serverDict));

            //Tilldelar lösenord lagrat under <prop> i 'vault' i 'server'
            //Om det redan har ett lösenord, så överskrivs det gamla lösenordet utan att fråga efter bekräftelse
            //Om <prop> inte är providerad --> operationen är aborterad + felmeddelande skrivs ut
            // Ska fråga efter båda MP + nytt PW. Om USER skriver "-g" eller "---generate", så ska ett randomiserat lösenord genereras utan bekräftelse
        }

        private static void SetPropPassword(string clientPath, string serverPath, string prop, string generate)
        {
            string masterPassword = EnterMasterPassword();
            string newPassword = null;
            
            if (generate == "-g" || generate == "--generate")
            {
                newPassword = GenerateRandomPassword();
            }
            else 
            {
                System.Console.WriteLine("One or several of the arguments is incorrect");
                Environment.Exit(0);
            }

            Kryptering krypt = new Kryptering();

            // Decrypts
            byte[] IV = GetIV(serverPath);
            byte[] secretKey = GetSecretKey(clientPath);
            byte[] vaultKey = CreateVaultKey(masterPassword, secretKey);
            string encryptedVault = GetEncryptedVault(serverPath);
            string decryptedSerializedVault = krypt.Decrypt(encryptedVault, vaultKey, IV);
            // Deserialize
            Dictionary<string, string> decryptedDeserializedVault = JsonSerializer.Deserialize<Dictionary<string, string>>(decryptedSerializedVault);
            //Creates new vault
            Dictionary<string, string> serverDict = new Dictionary<string, string>();
            serverDict.Add("IV", Convert.ToBase64String(IV));

            decryptedDeserializedVault.Add(prop, newPassword);
            string jsonVault = JsonSerializer.Serialize(decryptedDeserializedVault);
            string encryptedJsonVault = krypt.Encrypt(jsonVault, vaultKey, IV);
            serverDict.Add("vault", encryptedJsonVault);

            File.WriteAllText(serverPath, JsonSerializer.Serialize(serverDict));

            //Tilldelar lösenord lagrat under <prop> i 'vault' i 'server'
            //Om det redan har ett lösenord, så överskrivs det gamla lösenordet utan att fråga efter bekräftelse
            //Om <prop> inte är providerad --> operationen är aborterad + felmeddelande skrivs ut
            // Ska fråga efter båda MP + nytt PW. Om USER skriver "-g" eller "---generate", så ska ett randomiserat lösenord genereras utan bekräftelse
        }

        ///<summary>
        ///Generates a random password for the user and returns it.
        ///</summary>
        private static string GenerateRandomPassword()
        {

            string charachters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
            char[] stringChars = new char[20];
            Random random = new Random();

            for (int i = 0; i < stringChars.Length; i++)
            {
                stringChars[i] = charachters[random.Next(charachters.Length)];
            }
            string result = new string(stringChars);
            return result;
        }

        ///<summary>
        ///Deletes the password and prop for a certain prop. 
        ///</summary>
        private static void DeletePropPassword(string clientPath, string serverPath, string prop)
        {

            string masterPassword = EnterMasterPassword();

            Dictionary<string, string> getServerFile = JsonSerializer.Deserialize<Dictionary<string, string>>(File.ReadAllText(serverPath));
            string getVault = getServerFile["vault"];

            Kryptering krypt = new Kryptering();
            byte[] vaultKey = CreateVaultKey(masterPassword, GetSecretKey(clientPath));
            string decryptedVault = krypt.Decrypt(getVault, vaultKey, GetIV(serverPath));

            Dictionary<string, string> deserializedVault = JsonSerializer.Deserialize<Dictionary<string, string>>(decryptedVault);
            Dictionary<string, string> serverDict = new Dictionary<string, string>();

            deserializedVault.Remove(prop);
            string jsonVault = JsonSerializer.Serialize(deserializedVault);
            string encryptedJsonVault = krypt.Encrypt(jsonVault, vaultKey, GetIV(serverPath));
            serverDict.Add("IV", Convert.ToBase64String(GetIV(serverPath)));
            serverDict.Add("vault", encryptedJsonVault);
            File.WriteAllText(serverPath, JsonSerializer.Serialize(serverDict));

        }

        ///<summary>
        ///Gets the IV for a specified serverfile
        ///</summary>
        private static byte[] GetIV(string serverPath)
        {
            Dictionary<string, string> getServerFile = JsonSerializer.Deserialize<Dictionary<string, string>>(File.ReadAllText(serverPath));
            string getIVValue = getServerFile["IV"];
            return Convert.FromBase64String(getIVValue);
        }

        ///<summary>
        ///Gets the encrypted vault from a specified serverfile. 
        ///</summary>
        private static string GetEncryptedVault(string serverPath)
        {
            Dictionary<string, string> getServerFile = JsonSerializer.Deserialize<Dictionary<string, string>>(File.ReadAllText(serverPath));
            string getEncryptedVault = getServerFile["vault"];

            return getEncryptedVault;
        }

        ///<summary>
        ///Gets the secret key from a specified clientfile. 
        ///</summary>
        private static byte[] GetSecretKey(string clientPath)
        {

            string clientText = File.ReadAllText(clientPath);

            Dictionary<string, byte[]> foundSecretKey =
            JsonSerializer.Deserialize<Dictionary<string, byte[]>>(clientText);

            //try-catch


            return foundSecretKey["secret"];



        }
    }
}


