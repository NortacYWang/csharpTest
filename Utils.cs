
namespace csharpTest;

public class Utils
{

    public static byte[] StringToByteArray(string hex)
    {
        return Enumerable.Range(0, hex.Length)
                         .Where(x => x % 2 == 0)
                         .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                         .ToArray();
    }

    public static string ToString(byte[] bytes)
    {
        // convert the byte array back to a true string
        string strTemp = "";
        for (int x = 0; x <= bytes.GetUpperBound(0); x++)
        {
            int number = int.Parse(bytes[x].ToString());
            strTemp += number.ToString("X").PadLeft(2, '0');
        }
        // return the finished string of hex values
        return strTemp;
    }

}