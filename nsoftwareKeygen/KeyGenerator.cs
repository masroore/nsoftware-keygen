using System.ComponentModel.Design;
using System.Text;
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

    private static readonly Dictionary<nsoftwareProductType, byte[]> ProductMap = new()
    {
        {
            nsoftwareProductType.IPWorks,
            [
                48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 65, 66, 67, 68, 69, 70, 71, 72, 74, 75, 77, 78, 80, 82, 83, 84, 85, 86, 87, 88, 89, 90
            ]
            /*
            [
                169, 159, 166, 130, 168, 155, 165, 152, 102, 159,
                155, 166, 159, 126, 148, 136, 0
            ]
            */
        },
        {
            nsoftwareProductType.IPWorksSSL,
            [
                119, 129, 114, 165, 157, 102, 147, 150, 167, 152,
                164, 145, 134, 167, 133, 127, 0
            ]
        },
        {
            nsoftwareProductType.IPWorksSSH,
            [
                122, 167, 123, 162, 169, 164, 115, 133, 164, 162,
                153, 117, 149, 162, 160, 95, 0
            ]
        },
        {
            nsoftwareProductType.IPWorksSMIME,
            [
                161, 161, 128, 135, 126, 126, 114, 113, 120, 150,
                144, 117, 112, 112, 126, 144, 0
            ]
        },
        {
            nsoftwareProductType.IPWorksEncrypt,
            [
                135, 167, 96, 120, 115, 122, 124, 161, 156, 154,
                151, 164, 136, 158, 163, 150, 0
            ]
        },
        {
            nsoftwareProductType.IPWorksOpenPGP,
            [
                123, 155, 144, 156, 158, 167, 168, 128, 102, 132,
                118, 130, 132, 132, 160, 133, 0
            ]
        },
        {
            nsoftwareProductType.IPWorksSNMP,
            [
                146, 123, 102, 121, 163, 150, 164, 123, 135, 122,
                130, 125, 169, 97, 104, 154, 0
            ]
        },
        {
            nsoftwareProductType.IPWorksZip,
            [
                131, 165, 118, 137, 162, 147, 132, 96, 112, 156,
                152, 156, 116, 127, 150, 166, 0
            ]
        },
        {
            nsoftwareProductType.IPWorksAuth,
            [
                160, 150, 157, 114, 95, 169, 127, 102, 96, 163,
                166, 98, 97, 122, 163, 112, 0
            ]
        },
        {
            nsoftwareProductType.IPWorksIPC,
            [
                151, 144, 149, 163, 122, 163, 156, 144, 145, 134,
                165, 134, 117, 114, 120, 133, 0
            ]
        },
        {
            nsoftwareProductType.IPWorksMQ,
            [
                124, 115, 127, 120, 128, 97, 112, 169, 119, 98,
                157, 135, 104, 118, 126, 128, 0
            ]
        },
        {
            nsoftwareProductType.IPWorksIOT,
            [
                160, 135, 166, 95, 164, 146, 134, 95, 154, 98,
                115, 159, 128, 113, 169, 132, 0
            ]
        },
        {
            nsoftwareProductType.IPWorksSFTP,
            [
                127, 163, 145, 115, 161, 121, 137, 161, 162, 155,
                120, 132, 127, 150, 148, 150, 0
            ]
        },
        {
            nsoftwareProductType.IPWorksEDI,
            [
                127, 150, 137, 116, 129, 113, 114, 124, 122, 119,
                162, 116, 98, 97, 131, 168, 0
            ]
        },
        {
            nsoftwareProductType.IPWorksEDITranslator,
            [
                95, 113, 124, 156, 116, 157, 151, 136, 129, 122,
                96, 112, 137, 146, 123, 147, 0
            ]
        },
        {
            nsoftwareProductType.IPWorksBLE,
            [
                152, 96, 133, 133, 133, 127, 136, 131, 155, 130,
                151, 156, 165, 123, 134, 169, 0
            ]
        },
        {
            nsoftwareProductType.IPWorks3DS,
            [
                126, 96, 153, 146, 126, 118, 129, 153, 155, 157,
                163, 137, 151, 97, 137, 137, 0
            ]
        },
        {
            nsoftwareProductType.CloudMail,
            [
                102, 115, 98, 153, 113, 124, 158, 158, 156, 121,
                124, 154, 129, 155, 158, 130, 0
            ]
        },
        {
            nsoftwareProductType.CloudKeys,
            [
                153, 169, 163, 162, 118, 165, 98, 147, 123, 125,
                121, 160, 120, 112, 158, 126, 0
            ]
        },
        {
            nsoftwareProductType.CloudStorage,
            [
                156, 157, 96, 157, 128, 149, 131, 118, 104, 164,
                144, 137, 127, 167, 115, 136, 0
            ]
        },
        {
            nsoftwareProductType.SecureBlackbox,
            [
                119, 149, 96, 136, 132, 155, 128, 124, 114, 126,
                146, 97, 154, 112, 151, 152, 0
            ]
        }
    };

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

    public static string GetStringForProduct(nsoftwareProductType productType)
    {
        var productBytes = ProductMap[productType];
        return Encoding.ASCII.GetString(productBytes);
    }

    public static ProductKey GenerateRuntimeKey(nsoftwareProductType productType)
    {
        var rtk = "";
        var serial = "";
        serial += RandomString(5, false, true, true, false);
        serial += "V";
        serial += RandomString(16, false, true, true, false);
        var node = GetNodeId().Substring(0, 8);
        for (var i = 0; i < 22; i++) rtk += EncodingMap[serial[i]];

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