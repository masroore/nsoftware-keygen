using System.Text;
using ipw240x;
using Microsoft.Win32;

namespace nsoftwareKeygen;

public struct ProductKey
{
    public string Serial { get; set; }
    public string Key { get; set; }
    public string RuntimeKey { get; set; }
    public string Node { get; set; }
}

public class KeyGenerator
{
    private static readonly Dictionary<char, string> EncodingMap = new()
    {
        { '0', "30" },
        { '1', "31" },
        { '2', "32" },
        { '3', "33" },
        { '4', "34" },
        { '5', "35" },
        { '6', "36" },
        { '7', "37" },
        { '8', "38" },
        { '9', "39" },
        { 'A', "41" },
        { 'B', "42" },
        { 'C', "43" },
        { 'D', "44" },
        { 'E', "45" },
        { 'F', "46" },
        { 'G', "47" },
        { 'H', "48" },
        { 'I', "49" },
        { 'J', "4A" },
        { 'K', "4B" },
        { 'L', "4C" },
        { 'M', "4D" },
        { 'N', "4E" },
        { 'O', "4F" },
        { 'P', "50" },
        { 'Q', "51" },
        { 'R', "52" },
        { 'S', "53" },
        { 'T', "54" },
        { 'U', "55" },
        { 'V', "56" },
        { 'W', "57" },
        { 'X', "58" },
        { 'Y', "59" },
        { 'Z', "5A" }
    };

    private static readonly Dictionary<ProductType, byte[]> ProductMap = new();

    private static readonly byte[] _QRD =
    [
        48, 49, 50, 51, 52, 53, 54, 55, 56, 57,
        65, 66, 67, 68, 69, 70, 71, 72, 74, 75,
        77, 78, 80, 82, 83, 84, 85, 86, 87, 88,
        89, 90
    ];

    private static readonly string PASSWORD_CHARS_LCASE = "abcdefghijklmnopqrstuvwxyz";

    private static readonly string PASSWORD_CHARS_UCASE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    private static readonly string PASSWORD_CHARS_NUMERIC = "1234567890";

    private static readonly string PASSWORD_CHARS_SPECIAL = "*$-+?_&=!%{}/";

    public static string GetStringForProduct(ProductType productType)
    {
        var productBytes = ProductMap[productType];
        return Encoding.ASCII.GetString(productBytes);
    }

    public static void WriteLicenseFile(ProductType productType, ProductKey key)
    {
        void writeParam(StreamWriter sw, string label, string value, bool noQuotes = false)
        {
            label = label.Trim(['"']);
            if (!noQuotes)
                label = @$"""{label}""";
            value = @$"""{value.Trim(['"'])}""";
            sw.WriteLine(@$"{label}={value}");
        }

        var productCode = M.PRODUCT_NAMES[productType];
        var filePath = productCode + ".lic";
        using var fs = File.OpenWrite(filePath);
        using var writer = new StreamWriter(fs);
        writer.WriteLine($@"[HKEY_LOCAL_MACHINE\SOFTWARE\nsoftware\RT\{productCode}]");
        writeParam(writer, "@", key.Serial, true);
        writeParam(writer, "*", key.Key);
        writeParam(writer, key.Node, key.Key);
        writeParam(writer, "RTK", key.RuntimeKey);
    }

    public static void InitProductSignatures(ProductType type) => ProductMap[type] = ProductSignatures.GetSignature(type);

    public static ProductKey Generate(ProductType productType)
    {
        var rtk = "";
        var serial = "";
        serial += RandomString(5, false, true, true, false);
        serial += h.ROYALTY_FREE_VERSION_INDEPENDENT;
        serial += RandomString(16, false, true, true, false);
        var nodeId = GetNodeId();
        var node = nodeId.Substring(0, 8);
        for (var i = 0; i < 22; i++)
            rtk += EncodingMap[serial[i]];

        /*var rtk2 = string.Empty;
        foreach (var c in serial) {
            rtk2 += $"{(byte)c:00}";
        }*/

        for (var j = 22; j < 40; j++) rtk += "00";

        for (var k = 40; k < 49; k++) rtk += node.Length > k - 40 ? EncodingMap[node[k - 40]] : "00";

        for (var l = 49; l < 50; l++) rtk += "00";

        var array = new byte[40];
        var array2 = new byte[9];
        for (var m = 0; m < 22; m++) array[m] = Encoding.UTF8.GetBytes(serial)[m];

        for (var n = 0; n < 8; n++) array2[n] = Encoding.UTF8.GetBytes(node)[n];

        var productBytes = ProductMap[productType];
        var bytes = Key(array, array2, productBytes);
        var key = Encoding.UTF8.GetString(bytes).Substring(0, 12);
        for (var num = 50; num < 62; num++) rtk += key.Length > num - 50 ? EncodingMap[key[num - 50]] : "00";

        for (var num2 = 62; num2 < 64; num2++) rtk += "00";

        return new ProductKey
        {
            Node = node,
            Serial = serial,
            Key = key,
            RuntimeKey = rtk
        };
    }

    private static string RandomString(int pwdLength, bool lowerCaseChars, bool upperCaseChars, bool numericChars, bool specialChars)
    {
        var text = "";
        if (lowerCaseChars) text += PASSWORD_CHARS_LCASE;

        if (upperCaseChars) text += PASSWORD_CHARS_UCASE;

        if (numericChars) text += PASSWORD_CHARS_NUMERIC;

        if (specialChars) text += PASSWORD_CHARS_SPECIAL;

        var stringBuilder = new StringBuilder();
        var random = new Random();
        while (0 < pwdLength--) stringBuilder.Append(text[random.Next(text.Length)]);

        return stringBuilder.ToString();
    }

    private static string GetNodeId()
    {
        var text = "";
        try {
            text = Environment.MachineName;
            try {
                var environmentVariable = Environment.GetEnvironmentVariable("_CLUSTER_NETWORK_NAME_");
                if (environmentVariable is { Length: > 0 })
                    text = (string)Registry.LocalMachine.OpenSubKey("SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters").GetValue("NV Hostname");
            }
            catch { }
        }
        catch (Exception) {
            return "00000000";
        }

        return _UNh(text);
    }

    private static string DefaultGetBytes(byte[] bytes, int index, int count) => Encoding.Default.GetString(bytes, index, count);

    private static byte[] UTF8GetBytes(string str) => Encoding.UTF8.GetBytes(str);

    private static void ArrayCopy(byte[] sourceArray, int sourceIndex, byte[] destinationArray, int destinationIndex, int length)
    {
        Array.Copy(sourceArray, sourceIndex, destinationArray, destinationIndex, length);
    }

    private static byte[] Key(byte[] serialBytes, byte[] nodeBytes, byte[] productBytes)
    {
        var array = _TNc(_sGA(serialBytes, nodeBytes, productBytes), 8);
        array[12] = 0;
        return array;
    }

    private static string _UNh(string P_0)
    {
        var array = new byte[100];
        var array2 = UTF8GetBytes(P_0);
        ArrayCopy(array2, 0, array, 1, array2.Length);
        array[0] = 65;
        var productBytes = Encoding.ASCII.GetBytes("EnikamEruhdyrthS");
        return DefaultGetBytes(Key(array, [], productBytes), 0, 8);
    }

    private static byte[] _sGA(byte[] serialBytes, byte[] nodeBytes, byte[] productBytes)
    {
        var array = new byte[301];
        var array2 = new byte[14];
        ArrayCopy(serialBytes, 0, array, 0, serialBytes.Length);
        var num = _jRD(array, 0);
        if (num == 0) return array2;

        if (nodeBytes.Length > 0) {
            array[num++] = 42;
            var num2 = 0;
            for (num2 = num; num2 < array.Length - 1 && num2 - num < nodeBytes.Length && nodeBytes[num2 - num] != 0; num2++)
                array[num2] = nodeBytes[num2 - num];

            array[num2] = 0;
            num += _jRD(array, num);
        }

        while (num % 8 != 0) array[num++] = 0;

        for (var i = 0; i < num / 8; i++) {
            for (var j = 0; j < 8; j++) array2[j] ^= array[8 * i + j];

            _qxd(array2, 0, productBytes);
        }

        return array2;
    }

    private static byte[] _TNc(byte[] P_0, int P_1)
    {
        while (P_1 % 5 != 0) P_0[P_1++] = 0;

        P_0[P_1] = 0;
        var num = P_1 / 5 * 8;
        var array = new byte[num + 1];
        for (var i = 0; i < P_1; i++) array[i] = P_0[i];

        _EFH(array, P_1 * 8);
        for (var j = 0; j < num; j++) array[j] = _6UA(array[j]);

        array[num] = 0;
        return array;
    }

    private static void _EFH(byte[] P_0, int P_1)
    {
        for (var num = P_1 - 1; num >= 0; num--) {
            if ((P_0[num / 8] & (1 << (num % 8))) != 0)
                P_0[num / 5] |= (byte)(1 << (num % 5));
            else
                P_0[num / 5] &= (byte)~(1 << (num % 5));

            if (num % 5 == 0) P_0[num / 5] &= 31;
        }
    }

    private static byte _6UA(byte P_0)
    {
        var b = P_0;
        return _QRD[b % 32];
    }

    private static int _jRD(byte[] P_0, int P_1)
    {
        int i;
        int num;
        for (i = num = P_1; P_0[i] != 0; i++) {
            var b = _lSF(P_0[i]);
            if (-1 != b)
                P_0[num++] = _6UA((byte)b);
            else
                P_0[i] = 0;
        }

        for (var j = num; j < i; j++) P_0[j] = 0;

        return num - P_1;
    }

    private static sbyte _lSF(byte P_0)
    {
        if (P_0 >= 97 && P_0 <= 122) P_0 -= 32;

        if (P_0 == 73) P_0 = 49;

        if (P_0 == 76) P_0 = 49;

        if (P_0 == 79) P_0 = 48;

        if (P_0 == 81) P_0 = 48;

        for (sbyte b = 0; b < 32; b++)
            if (P_0 == _QRD[b])
                return b;

        return -1;
    }

    private static void _qxd(byte[] P_0, int P_1, byte[] P_2)
    {
        var array = new uint[2];
        var array2 = new uint[4];
        for (var i = 0; i < 2; i++) array[i] = _ZOH(P_0, P_1 + i * 4);

        for (var j = 0; j < 4; j++) array2[j] = _ZOH(P_2, P_1 + j * 4);

        _rmB(array, array2);
        for (var k = 0; k < 2; k++) _rGh(array[k], P_0, k * 4);
    }

    private static uint _ZOH(byte[] P_0, int P_1) =>
        (uint)((((P_0[P_1 + 3] & 0xFF) * 256 + (P_0[P_1 + 2] & 0xFF)) * 256 + (P_0[P_1 + 1] & 0xFF)) * 256 + (P_0[P_1] & 0xFF));

    private static void _rGh(uint P_0, byte[] P_1, int P_2)
    {
        P_1[P_2++] = (byte)P_0;
        P_1[P_2++] = (byte)((P_0 >> 8) & 0xFFu);
        P_1[P_2++] = (byte)((P_0 >> 16) & 0xFFu);
        P_1[P_2++] = (byte)((P_0 >> 24) & 0xFFu);
    }

    private static void _rmB(uint[] P_0, uint[] P_1)
    {
        var num = P_0[0];
        var num2 = P_0[1];
        var num3 = 0u;
        var num4 = 2654435769u;
        var num5 = 32u;
        while (num5-- != 0) {
            num3 += num4;
            num += ((num2 << 4) + P_1[0]) ^ (num2 + num3) ^ ((num2 >> 5) + P_1[1]);
            num2 += ((num << 4) + P_1[2]) ^ (num + num3) ^ ((num >> 5) + P_1[3]);
        }

        P_0[0] = num;
        P_0[1] = num2;
    }
}