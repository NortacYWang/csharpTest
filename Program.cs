
using System.Text;
using System.IO.Compression;
using System.Security.Cryptography;

namespace csharpTest;

class Program
{
    static void Main(string[] args)
    {
        // st = "3D000100000F546163746963616C4F626A656374731F8B0800000000000003E3E6CFDBA5C820CBC0C09122ECA1C8C0F281CDC54B2138D2CF99C9D0C87866B788E9FC37860700B43D2BB325000000";

        // string objects = "1F8B0800000000000003E3E6CFDBA5C820CBC0C09122ECA1C8C0F281CDC54B2138D2CF99C9D0C87866B788E9FC37860700B43D2BB325000000";

        // string result = UnZip(objects);

        // Console.WriteLine(result);

        // byte[] posArr = new byte[] {
        //     0x99, 0x8B, 0x14, 0x35, 0x9F, 0xEC
        // };

        // byte[] arr = new byte[] {
        //     0x85, 0x9a, 0x30, 0x0d, 0x3c, 0x47, 0xb1, 0x73, 0x6e, 0x17, 0x3f, 0x81, 0xaf, 0x0f, 0xd6, 0x41
        // };
        // byte[] key = new byte[] {
        //     0xBC, 0x5B,0xA0,0x59,0x2F,0xE1,0x21,0x86,0xCD,0x41,0x4A,0x4A,0x7D,0x6A,0xCD,0x9C,0xCE,0x1C,0xB4,0x86,0x36,0x6D,0x20,0x48,0x8C,0x57,0x1F,0x80,0xD9,0x5F,0x42,0xFB
        // };
        // string result = DecryptMessage(arr, key);
        // Console.WriteLine(result);

        string pos = "998B14359FEC";
        string key = "BC5BA0592FE12186CD414A4A7D6ACD9CCE1CB486366D20488C571F80D95F42FB";
        string result = EncryptMessage(pos, key);
        Console.WriteLine(result);
    }

    public static string UnZip(string toUnzip)
    {
        try
        {
            byte[] payload = Utils.StringToByteArray(toUnzip);
            byte[] objectArr;
            using GZipStream stream = new(new MemoryStream(payload), CompressionMode.Decompress);
            const int size = 4096;
            byte[] buffer = new byte[size];
            using MemoryStream memory = new();
            int count = 0;
            do
            {
                count = stream.Read(buffer, 0, size);
                if (count > 0)
                {
                    memory.Write(buffer, 0, count);
                }
            }
            while (count > 0);
            objectArr = memory.ToArray();
            return Utils.ToString(objectArr);
        }
        catch (Exception)
        {
            return "";
        }
    }

    public static string DecryptMessage(string dataString, string keyString)
    {
        try
        {
            byte[] data = Utils.StringToByteArray(dataString);
            byte[] key = Utils.StringToByteArray(keyString);
            using var stream = new MemoryStream();
            using var decryptor = Aes.Create();
            decryptor.Mode = CipherMode.ECB;
            decryptor.Padding = PaddingMode.None;
            decryptor.Key = key;
            using CryptoStream lCryptStream = new(stream, decryptor.CreateDecryptor(), CryptoStreamMode.Write);
            lCryptStream.Write(data, 0, data.Length);
            lCryptStream.Close();
            Byte[] decryptedData = stream.ToArray();


            int lastIndex = Array.FindLastIndex(decryptedData, b => b != 0);
            Array.Resize(ref decryptedData, lastIndex + 1);
            return Utils.ToString(decryptedData);
        }
        catch (Exception)
        {
            return "";
        }

    }

    public static string EncryptMessage(string dataString, string keyString)
    {

        try
        {
            byte[] data = Utils.StringToByteArray(dataString);
            byte[] key = Utils.StringToByteArray(keyString);
            int finalPayloadSize = data.Length;
            int numPaddingBytes = 16 - (finalPayloadSize % 16);

            if (numPaddingBytes == 16)
                numPaddingBytes = 0;

            // If data length is less than the final size
            if (data.Length != finalPayloadSize + numPaddingBytes)
            {
                // add and zeroize padding
                Array.Resize<Byte>(ref data, finalPayloadSize + numPaddingBytes);
                for (int i = 0; i < numPaddingBytes; i++)
                    data[data.Length - 1 - i] = 0;
            }

            using MemoryStream stream = new MemoryStream();
            // Create a new Rijndael object.
            using Aes encryptor = Aes.Create();
            encryptor.Mode = CipherMode.ECB;
            encryptor.Padding = PaddingMode.None;
            encryptor.Key = key;
            // Create a CryptoStream using the FileStream and the passed key and
            // initialization vector (IV).
            using CryptoStream crypto = new(stream, encryptor.CreateEncryptor(), CryptoStreamMode.Write);
            crypto.Write(data, 0, data.Length);
            crypto.Close();
            stream.Close();

            return Utils.ToString(stream.ToArray());
        }
        catch (Exception)
        {
            return "";
        }


    }

}
