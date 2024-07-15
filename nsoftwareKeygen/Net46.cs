using System.Collections;
using System.Reflection;
using System.Security;
using System.Text;
using Microsoft.Win32;

namespace ipw240x;

public class Net46 { }

public class h
{
    internal static byte[] O;

    /**
     * Get string from bytes (default encoding)
     */
    public static string y(byte[] buf, int index, int length) =>
        Encoding.Default.GetString(buf, index, length);

    /**
     * Get string from bytes (UTF8)
     */
    public static byte[] utf8StrToBytes(string str) => Encoding.UTF8.GetBytes(str);

    /**
     * Array copy from src to dest
     */
    public static void y(byte[] bufFirst40, int srcOffset, byte[] bufDest, int destOffset, int length) =>
        Array.Copy(bufFirst40, srcOffset, bufDest, destOffset, length);

    /**
     * Check license type (FULL version)
     * A-G,M,P,S,T,V,X,Z is okay
     */
    public static bool A(byte lic_typ)
    {
        return (char)lic_typ switch
        {
            'A' => true,
            'B' => true,
            'C' => true,
            'D' => true,
            'E' => true,
            'F' => true,
            'G' => true,
            'M' => true,
            'P' => true,
            'S' => true,
            'T' => true,
            'V' => true,
            'X' => true,
            'Z' => true,
            _   => false,
        };
    }

    /**
     * Get license type description
     */
    public static string v(byte lic_typ)
    {
        return (char)lic_typ switch
        {
            'A' => "Royalty-Free",
            'B' => "Royalty-Free",
            'C' => "Royalty-Free, Single Control",
            'D' => "Royalty-Free",
            'E' => "Single-Server, All Controls",
            'F' => "Royalty-Free, Single Control",
            'G' => "Single-Server, Single Control",
            'V' => "Royalty-Free, Version Independent",
            'X' => "Trial",
            'Z' => "Trial",
            'S' => "Single-Server, All Controls",
            'T' => "Single-Server, Single Control",
            'P' => "Single-Server, Processor Bound, All Controls",
            'M' => "Metered",
            _   => string.Concat((char)lic_typ),
        };
    }

    public static bool i(byte lic_typ) => lic_typ is 88 or 90;

    public static bool p(byte lic_typ) => lic_typ == 80;

    public static bool f(byte lic_typ)
    {
        var x = (char)68;
        x = (char)69;
        x = (char)70;
        x = (char)71;
        return lic_typ is 68 or 69 or 70 or 71;
    }

    /*
     * Check if limited license type
     */
    public static bool o(byte lic_typ)
    {
        return (char)lic_typ switch
        {
            'A' => true,
            'B' => true,
            'C' => true,
            'D' => true,
            'F' => true,
            'V' => true,
            'Z' => true,
            _   => false,
        };
    }

    public static bool y(byte lic_typ) => lic_typ is 67 or 70 or 71 or 84;

    public static bool K(byte lic_typ) => lic_typ is 66 or 90;

    internal static void l(uint[] P_0, uint[] P_1)
    {
        uint num = P_0[0];
        uint num2 = P_0[1];
        uint num3 = 0u;
        uint num4 = 2654435769u;
        uint num5 = 32u;
        while (num5-- != 0) {
            num3 += num4;
            num += ((num2 << 4) + P_1[0]) ^ (num2 + num3) ^ ((num2 >> 5) + P_1[1]);
            num2 += ((num << 4) + P_1[2]) ^ (num + num3) ^ ((num >> 5) + P_1[3]);
        }

        P_0[0] = num;
        P_0[1] = num2;
    }

    internal static uint b(byte[] P_0, int P_1)
    {
        uint num = P_0[P_1 + 3] & 0xFFu;
        num = num * 256 + (uint)(P_0[P_1 + 2] & 0xFF);
        num = num * 256 + (uint)(P_0[P_1 + 1] & 0xFF);
        return num * 256 + (uint)(P_0[P_1] & 0xFF);
    }

    internal static void a(uint P_0, byte[] P_1, int P_2)
    {
        P_1[P_2++] = (byte)P_0;
        P_1[P_2++] = (byte)((P_0 >> 8) & 0xFFu);
        P_1[P_2++] = (byte)((P_0 >> 16) & 0xFFu);
        P_1[P_2++] = (byte)((P_0 >> 24) & 0xFFu);
    }

    internal static void b(byte[] P_0, int P_1, byte[] P_2)
    {
        uint[] array = new uint[2];
        uint[] array2 = new uint[4];
        for (int i = 0; i < 2; i++) {
            array[i] = b(P_0, P_1 + i * 4);
        }

        for (int j = 0; j < 4; j++) {
            array2[j] = b(P_2, P_1 + j * 4);
        }

        l(array, array2);
        for (var k = 0; k < 2; k++) {
            a(array[k], P_0, k * 4);
        }
    }

    internal static void P(byte[] P_0, int endOffset)
    {
        for (var index = endOffset - 1; index >= 0; index--) {
            if ((P_0[index / 8] & (1 << index % 8)) != 0) {
                P_0[index / 5] |= (byte)(1 << index % 5);
            }
            else {
                P_0[index / 5] &= (byte)(~(1 << index % 5));
            }

            if (index % 5 == 0) {
                P_0[index / 5] &= 31;
            }
        }
    }

    public static void init()
    {
        O = new byte[32];
        O[0] = 48;
        O[1] = 49;
        O[2] = 50;
        O[3] = 51;
        O[4] = 52;
        O[5] = 53;
        O[6] = 54;
        O[7] = 55;
        O[8] = 56;
        O[9] = 57;
        O[10] = 65;
        O[11] = 66;
        O[12] = 67;
        O[13] = 68;
        O[14] = 69;
        O[15] = 70;
        O[16] = 71;
        O[17] = 72;
        O[18] = 74;
        O[19] = 75;
        O[20] = 77;
        O[21] = 78;
        O[22] = 80;
        O[23] = 82;
        O[24] = 83;
        O[25] = 84;
        O[26] = 85;
        O[27] = 86;
        O[28] = 87;
        O[29] = 88;
        O[30] = 89;
        O[31] = 90;
    }

    internal static byte d(byte leByte) => O[leByte % 32];

    internal static sbyte U(byte theByte)
    {
        if (theByte is >= 97 and <= 122) theByte -= 32;

        if (theByte == 73) theByte = 49;

        if (theByte == 76) theByte = 49;

        if (theByte == 79) theByte = 48;

        if (theByte == 81) theByte = 48;

        for (sbyte b = 0; b < 32; b++) {
            if (theByte == O[b]) {
                return b;
            }
        }

        return -1;
    }

    internal static byte B(byte leByte)
    {
        if (leByte is >= 97 and <= 122) {
            leByte -= 32;
        }

        return leByte;
    }

    internal static void d(byte[] buffer, int offset, int length)
    {
        ulong num = (ulong)DateTime.Now.Ticks;
        for (var i = 0; i < length; i++) {
            if (i > 0 && i % 4 == 0) {
                num = num * 25214903917L + 11;
            }

            buffer[offset + i] = (byte)(65 + ((byte)(num >> i % 4 * 8) & 0x7F) % 26);
        }
    }

    protected internal static int R(byte[] buffer, int offset)
    {
        int i;
        int num;
        for (i = num = offset; buffer[i] != 0; i++) {
            var b = U(buffer[i]);
            if (-1 == b)
                buffer[i] = 0;
            else
                buffer[num++] = d((byte)b);
        }

        for (var j = num; j < i; j++) buffer[j] = 0;

        return num - offset;
    }

    internal static byte[] u(byte[] buffer, int length)
    {
        while (length % 5 != 0) {
            buffer[length++] = 0;
        }

        buffer[length] = 0;
        var div5_8bit = length / 5 * 8;
        var array = new byte[div5_8bit + 1];
        for (var i = 0; i < length; i++) {
            array[i] = buffer[i];
        }

        P(array, length * 8);
        for (int j = 0; j < div5_8bit; j++) {
            array[j] = d(array[j]);
        }

        array[div5_8bit] = 0;
        return array;
    }

    protected internal static void G(byte[] P_0, byte P_1, byte P_2)
    {
        for (var i = 0; i < 16; i++) {
            P_0[i] = (byte)(P_0[i] + (P_1 - 48) + (P_2 - 48));
        }
    }

    internal static byte[] P(byte[] bufFirst40, byte[] bufMiddle9, byte[] signatureBuf)
    {
        byte[] workBuffer = new byte[301];
        byte[] resultBuffer = new byte[14];
        // copy bufFirst40 to wokr buffer
        y(bufFirst40, 0, workBuffer, 0, bufFirst40.Length);
        var num = R(workBuffer, 0);
        if (num == 0) {
            return resultBuffer;
        }

        if (bufMiddle9 is { Length: > 0 }) {
            workBuffer[num++] = 42;
            int num2;
            for (num2 = num; num2 < workBuffer.Length - 1 && num2 - num < bufMiddle9.Length && bufMiddle9[num2 - num] != 0; num2++) {
                workBuffer[num2] = bufMiddle9[num2 - num];
            }

            workBuffer[num2] = 0;
            num += R(workBuffer, num);
        }

        while (num % 8 != 0) {
            workBuffer[num++] = 0;
        }

        for (int num2 = 0; num2 < num / 8; num2++) {
            for (int i = 0; i < 8; i++) {
                resultBuffer[i] ^= workBuffer[8 * num2 + i];
            }

            b(resultBuffer, 0, signatureBuf);
        }

        return resultBuffer;
    }

    internal static byte[] w(byte[] bufFirst40, byte[] bufMiddle9, byte[] signatureBuf)
    {
        var array = P(bufFirst40, bufMiddle9, signatureBuf);
        array = u(array, 8);
        array[12] = 0;
        return array;
    }

    public static int L(byte[] buf40, byte[] buf9, byte[] buf16, byte[] signatureBytes)
    {
        var buf31 = new byte[31];
        int i;
        for (i = 0; i < buf31.Length - 1 && buf16[i] != 0; i++) {
            buf31[i] = buf16[i];
        }

        buf31[i] = 0;
        R(buf31, 0);
        byte[] array2 = w(buf40, buf9, signatureBytes);
        int num = 1;
        for (i = 0; i < (buf31[6] == 0 ? 6 : 12); i++) {
            if (buf31[i] != 0) {
                num = 0;
            }

            if (buf31[i] == 0) {
                return 1;
            }

            if (buf31[i] != array2[i]) {
                return 2;
            }
        }

        if (buf31[12] != 0)
            return 3;
        return num != 0 ? 4 : 0;
    }

    public static string M(string P_0, string P_1, string expiry_date, string productKey, string P_4, bool P_5)
    {
        var text =
            "         Product : [product]\r\n     Product Key : [productKey]\r\n  License Source : [licenseSource]\r\n    License Type : [licenseType]\r\nLast Valid Build : [lastValidBuild]\r\n";
        if (P_1 is { Length: < 128 }) {
            P_1 = null;
        }

        var buffer = ((P_1 != null) ? j(utf8StrToBytes(P_1 + "\0"), 128) : utf8StrToBytes(productKey + "\0"));
        if (P_1 != null) {
            buffer[64] = 0;
        }

        string text2 = P_4;
        if (P_0.Length > 0) {
            text2 = text2 + " (" + P_0 + ")";
        }

        string product_key = "n/a";
        if (P_1 is { Length: > 0 }) {
            string @string = Encoding.ASCII.GetString(buffer, 0, buffer.Length);
            product_key = @string.Substring(0, @string.IndexOf("\0", StringComparison.Ordinal));
        }
        else if (productKey is { Length: > 0 }) {
            product_key = productKey;
        }

        string license_src = "n/a";
        if (P_1 is { Length: > 0 }) {
            license_src = "RuntimeLicense";
        }
        else if (P_5) {
            license_src = "License File";
        }
        else if (productKey is { Length: > 0 }) {
            license_src = "Registry";
        }

        byte b = (byte)((buffer.Length > 5) ? buffer[5] : 0);
        string license_type;
        if (!expiry_date.Equals("")) {
            license_type = "Beta (Expires on " + expiry_date + ")";
        }
        else if (b != 0) {
            license_type = v(b);
            if (i(b)) {
                license_type = license_type + " (Expires on " + DateTime.Now.AddDays(w(buffer)).ToString("MM/dd/yyyy") + ")";
            }
        }
        else {
            license_type = "None (No license could be found for using " + P_4 + " on this system.)";
        }

        var build_num = "n/a";
        if (f(b)) {
            R(buffer, 0);
            build_num = string.Concat(c(buffer));
        }

        text = text.Replace("[product]", text2);
        text = text.Replace("[productKey]", product_key);
        text = text.Replace("[licenseSource]", license_src);
        text = text.Replace("[licenseType]", license_type);
        return text.Replace("[lastValidBuild]", build_num);
    }

    /**
     * Get the machine name
     */
    public static string L()
    {
        var machine_name = "";
        try {
            machine_name = Environment.MachineName;
            string environmentVariable = Environment.GetEnvironmentVariable("_CLUSTER_NETWORK_NAME_");
            try {
                if (environmentVariable is { Length: > 0 }) {
                    machine_name = (string)Registry.LocalMachine.OpenSubKey("SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters").GetValue("NV Hostname");
                }
            }
            catch { }
        }
        catch (Exception) {
            return "00000000";
        }

        return l(machine_name);
    }

    public static string l(string machine_name)
    {
        var array = new byte[100];
        var machine_name_utf_bytes = utf8StrToBytes(machine_name);
        y(machine_name_utf_bytes, 0, array, 1, machine_name_utf_bytes.Length);
        array[0] = 65;
        byte[] seed =
        [
            69, 110, 105, 107, 97, 109, 69, 114, 117, 104,
            100, 121, 114, 116, 104, 83
        ];
        var array4 = w(array, [], seed);
        return y(array4, 0, 8);
    }

    public static byte[] _h(byte[] P_0, int P_1)
    {
        byte[] array =
        [
            48, 49, 50, 51, 52, 53, 54, 55, 56, 57,
            65, 66, 67, 68, 69, 70
        ];
        byte[] array2 = new byte[P_1 * 2];
        for (int num = P_1 - 1; num >= 0; num--) {
            byte b = P_0[num];
            P_0[2 * num + 1] = array[b & 0xF];
            b >>= 4;
            P_0[2 * num] = array[b];
        }

        return P_0;
    }

    public static byte[] j(byte[] rtkBuf, int length)
    {
        //var array = Encoding.ASCII.GetBytes("0123456789ABCDEF");
        for (var i = 0; i < length / 2; i++) {
            var b = rtkBuf[2 * i];
            if (b is >= 48 and <= 57) {
                rtkBuf[i] = (byte)(b - 48 << 4);
            }
            else {
                if (b is < 65 or > 70) {
                    for (i = 0; i < length; i++) {
                        rtkBuf[i] = 0;
                    }

                    return rtkBuf;
                }

                rtkBuf[i] = (byte)(b - 65 + 10 << 4);
            }

            b = rtkBuf[2 * i + 1];
            if (b is >= 48 and <= 57) {
                rtkBuf[i] += (byte)(b - 48);
                continue;
            }

            if (b is >= 65 and <= 70) {
                rtkBuf[i] += (byte)(b - 65 + 10);
                continue;
            }

            for (i = 0; i < length; i++) {
                rtkBuf[i] = 0;
            }

            return rtkBuf;
        }

        return rtkBuf;
    }

    public static byte[] x(byte[] P_0, byte[] P_1, byte[] P_2, byte[] P_3)
    {
        if (P_0 != null) {
            P_0[0] = 0;
        }

        int num = R(P_1, 0);
        if (P_1[0] == 0) {
            return P_0;
        }

        d(P_1, num + 1, 40 - num - 2);
        P_1[39] = 0;
        byte[] array = w(P_1, P_2, P_3);
        int num2 = 0;
        for (num2 = 0; num2 < 40; num2++) {
            P_0[num2] = P_1[num2];
        }

        for (num2 = 40; num2 < 48; num2++) {
            P_0[num2] = P_2[num2 - 40];
        }

        for (num2 = 50; num2 < 62; num2++) {
            P_0[num2] = array[num2 - 50];
        }

        P_0 = _h(P_0, 64);
        P_0[128] = 0;
        return P_0;
    }

    public static byte[] S(byte[] P_0, byte[] P_1, byte[] P_2)
    {
        byte[] array = utf8StrToBytes(L());
        return x(P_0, P_1, array, P_2);
    }

    private const int INVALID_RTK = 17;
    private const int EMPTY_RTK = 18;

    public static int T(byte[] rtkBuf, byte[] sigBuf, int prodCode)
    {
        if (rtkBuf == null) {
            return INVALID_RTK;
        }

        int num = rtkBuf.Length - 1;
        if (num < 128) {
            return INVALID_RTK;
        }

        // ?? decode buffer
        rtkBuf = j(rtkBuf, 128);
        rtkBuf[64] = 0;
        if (rtkBuf[0] == 0) {
            return EMPTY_RTK;
        }

        // split the 64 bytes array into 3 segments
        byte[] buf40 = new byte[40];
        byte[] buf9 = new byte[9];
        byte[] buf16 = new byte[16];
        int index;
        for (index = 0; index < 40; index++) {
            buf40[index] = rtkBuf[index];
        }

        for (index = 40; index < 49; index++) {
            buf9[index - 40] = rtkBuf[index];
        }

        for (index = 50; index < 62; index++) {
            buf16[index - 50] = rtkBuf[index];
        }

        int num3 = L(buf40, buf9, buf16, sigBuf);
        if (num3 != 0) {
            return num3;
        }

        switch ((char)B(rtkBuf[5])) {
            case 'A':
            case 'B':
            case 'D':
            case 'V':
                return 0;
            case 'X':
            {
                byte[] array4 = utf8StrToBytes(L());
                for (index = 0; index < 8; index++) {
                    if (array4[index] != rtkBuf[40 + index]) {
                        return 20;
                    }
                }

                return _xh(rtkBuf);
            }
            case 'Z':
                return _xh(rtkBuf);
            case 'C':
            case 'F':
                if (prodCode == 0) {
                    return num3;
                }

                if (prodCode != 10 * (rtkBuf[6] - 48) + rtkBuf[7] - 48) {
                    return 11;
                }

                return 0;
            default:
                return 10;
        }
    }

    public static int k(byte[] P_0, char P_1)
    {
        byte b = B(P_0[5]);
        if (b == 86) {
            return 0;
        }

        if (B(P_0[3]) != P_1) {
            return 21;
        }

        return 0;
    }

    public static int M(byte[] P_0, char P_1)
    {
        byte b = B(P_0[5]);
        if (b == 86) {
            return 0;
        }

        if (B(P_0[3]) != P_1) {
            return 21;
        }

        return 0;
    }

    public static int i(byte[] rtkBytes, int buildNum)
    {
        var the5thByte = B(rtkBytes[5]);
        if (!f(the5thByte)) {
            return 0;
        }

        var num = c(rtkBytes);
        if (buildNum > num) {
            return 13;
        }

        return 0;
    }

    public static int a(byte[] P_0, int P_1)
    {
        byte b = B(P_0[5]);
        if (!f(b)) {
            return 0;
        }

        int num = c(P_0);
        if (P_1 > num) {
            return 14;
        }

        return 0;
    }

    public static int _xh(byte[] P_0)
    {
        P_0[P_0.Length - 1] = 0;
        R(P_0, 0);
        if (i(P_0[5])) {
            int num = 10 * (P_0[12] - 48) + (P_0[13] - 48);
            DateTime now = DateTime.Now;
            int num2 = 365 * (now.Year - 2000) + 30 * now.Month + now.Day;
            int num3 = 365 * (10 * (P_0[10] - 48) + (P_0[11] - 48)) + 30 * (10 * (P_0[6] - 48) + (P_0[7] - 48)) + (10 * (P_0[8] - 48) + (P_0[9] - 48));
            if (num2 > num3 + num) {
                return 9;
            }

            if (num2 < num3 - num) {
                return 12;
            }
        }

        if (p(P_0[5])) {
            int num4 = ((P_0[6] <= 56) ? (P_0[6] - 48) : 0);
        }

        return 0;
    }

    public static int w(byte[] P_0)
    {
        P_0[P_0.Length - 1] = 0;
        R(P_0, 0);
        if (i(P_0[5])) {
            int num = 10 * (P_0[12] - 48) + (P_0[13] - 48);
            DateTime now = DateTime.Now;
            int num2 = 365 * (now.Year - 2000) + 30 * now.Month + now.Day;
            int num3 = 365 * (10 * (P_0[10] - 48) + (P_0[11] - 48)) + 30 * (10 * (P_0[6] - 48) + (P_0[7] - 48)) + (10 * (P_0[8] - 48) + (P_0[9] - 48));
            if (num2 > num3 + num) {
                return 0;
            }

            if (num2 < num3) {
                return 0;
            }

            return num3 + num - num2;
        }

        return 0;
    }


    /**
     * Get the BUILD NUMBER from the buffer
     */
    public static int c(byte[] decodedFromLicenseFile)
    {
        if (decodedFromLicenseFile[0] == 0 || !f(B(decodedFromLicenseFile[5]))) {
            return -1;
        }

        int num = 10;
        int year = 1000 * (decodedFromLicenseFile[num] - 48) + 100 * (decodedFromLicenseFile[num + 1] - 48) + 10 * (decodedFromLicenseFile[num + 2] - 48) +
                   (decodedFromLicenseFile[num + 3] - 48);
        int month = 10 * (decodedFromLicenseFile[num + 4] - 48) + (decodedFromLicenseFile[num + 5] - 48);
        int day = 10 * (decodedFromLicenseFile[num + 6] - 48) + (decodedFromLicenseFile[num + 7] - 48);
        return (new DateTime(year, month, day, 0, 0, 0, DateTimeKind.Utc) - new DateTime(2000, 1, 1, 0, 0, 0, DateTimeKind.Utc)).Days;
    }
}

public sealed class M : h
{
    public static void n(int code, Type asmType, string runTimeKey)
    {
        l(code, asmType, (runTimeKey != null) ? utf8StrToBytes(runTimeKey + "\0") : null);
    }

    internal static void l(int code, Type asmType, byte[]? rtkBytes)
    {
        int num = 18;
        if (rtkBytes != null) {
            byte[] array = new byte[17];
            d(array);
            num = T(rtkBytes, array, code);
            if (num == 0) {
                num = k(rtkBytes, 'J');
            }

            if (num == 0) {
                num = i(rtkBytes, 8949);
                if (num != 0) {
                    int num2 = ipw240x.h.c(rtkBytes);
                    char c = (char)(65 + num);
                    string text = L();
                    string text2 = "IPWorks 2024";
                    if (asmType != null) {
                        object obj = text2;
                        text2 = string.Concat(obj, " (", asmType, " component)");
                    }

                    text2 +=
                        ". The specified runtime license is only valid for use with IPWorks 2024 builds {0} and earlier. To use the current build ({1}), please generate a new runtime license from a valid license key. For more information, please visit www.nsoftware.com or email support@nsoftware.com [code: {2} nodeid: {3}].";
                    throw new Exception(string.Format(text2, num2, 8949, c, text));
                }
            }
        }

        if (num != 0) {
            Q(code, asmType, ref num);
        }
    }

    internal static string Q(int prodCode, Type asmType, ref int transformResult)
    {
        string? text = null;
        return h(prodCode, asmType, ref transformResult, ref text, true);
    }

    internal static void W(string some_kind_of_product_type, string exception_tpl)
    {
        var flag = false;
        if (some_kind_of_product_type.Length >= 10 && ((flag && some_kind_of_product_type.IndexOf("1DEV", StringComparison.Ordinal) == 6) ||
                                                       some_kind_of_product_type.IndexOf("1DSK", StringComparison.Ordinal) == 6 ||
                                                       (flag && some_kind_of_product_type.IndexOf("1SUB", StringComparison.Ordinal) == 6)) && D()) {
            throw new Exception(string.Format(exception_tpl, 'Z', L()));
        }
    }

    internal static bool D()
    {
        return false;
        //return RtlLib.IsServerOS();
    }

    private static void x(byte[] P_0)
    {
        v(P_0, 1);
    }

    private static void v(byte[] P_0, int P_1)
    {
        int num = 0;
        P_0[num++] = 51;
        P_0[num++] = 79;
        P_0[num++] = 90;
        P_0[num++] = 109;
        P_0[num++] = 83;
        P_0[num++] = 82;
        P_0[num++] = 76;
        P_0[num++] = 49;
        P_0[num++] = 68;
        P_0[num++] = 103;
        P_0[num++] = 100;
        P_0[num++] = 51;
        P_0[num++] = 51;
        P_0[num++] = 121;
        P_0[num++] = 66;
        P_0[num++] = 101;
        if (P_1 != 0) {
            G(P_0, 78, 65);
        }
    }

    //t("SOFTWARE\\nsoftware\\RT\\IPNJA", signature_internal, prodCode, ref outMessage, ref array2, ref text2);
    private static int t(string regKey, byte[] sigBytes, int prodCode, ref string serial, ref byte[] outBuffer, ref string serialFromLicenseFile)
    {
        var num = c(regKey, sigBytes, ref serial, ref outBuffer, ref serialFromLicenseFile);
        if (num != 0) {
            return num;
        }

        if (outBuffer == null) {
            return num;
        }

        if (!y(outBuffer[5])) {
            return num;
        }

        if (prodCode == 10 * (outBuffer[6] - 48) + outBuffer[7] - 48) {
            return 0;
        }

        regKey = regKey + "\\" + prodCode;
        num = c(regKey, sigBytes, ref serial, ref outBuffer, ref serialFromLicenseFile);
        switch (num) {
            case 6:
                return 11;
            default:
                return num;
            case 0:
                if (!y(outBuffer[5])) {
                    return 10;
                }

                if (prodCode != 10 * (outBuffer[6] - 48) + outBuffer[7] - 48) {
                    return 11;
                }

                return 0;
        }
    }

    public static bool J = false;

    private static string? k()
    {
        var codeBase = Assembly.GetExecutingAssembly().CodeBase;
        var length = codeBase.LastIndexOf("/", StringComparison.Ordinal);
        codeBase = codeBase.Substring(0, length);
        codeBase = codeBase.Substring(8);
        if (File.Exists(codeBase + "/nsoftware.IPWorks.lic")) {
            return codeBase + "/nsoftware.IPWorks.lic";
        }

        if (File.Exists(codeBase + "/IPNJA.lic")) {
            return codeBase + "/IPNJA.lic";
        }

        var platform = Environment.OSVersion.Platform;
        codeBase = (!(platform != PlatformID.Unix && platform != PlatformID.MacOSX)
            ? Environment.GetEnvironmentVariable("HOME")
            : Environment.ExpandEnvironmentVariables("%HOMEDRIVE%%HOMEPATH%"))!;
        codeBase += "/.nsoftware";
        if (File.Exists(codeBase + "/nsoftware.IPWorks.lic")) {
            return codeBase + "/nsoftware.IPWorks.lic";
        }

        if (File.Exists(codeBase + "/IPNJA.lic")) {
            return codeBase + "/IPNJA.lic";
        }

        return null;
    }

    private static int c(string RunTimeLicenseCode, byte[] signatureBytes, ref string serial, ref byte[] serialDecodedBytes, ref string valIPNJA)
    {
        byte[] key_bytes;
        Hashtable? hashtable = null;
        byte[] array2 =
        [
            42, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0
        ];
        var num = 0;
        var licenseFilename = k();
        string? text2 = null;
        if (licenseFilename != null || text2 != null) {
            hashtable = new Hashtable();
            string? licenseFileContent = null;
            if (licenseFileContent == null && text2 != null) {
                licenseFileContent = text2;
            }

            licenseFileContent ??= File.ReadAllText(licenseFilename);

            var reader = new StringReader(licenseFileContent);
            try {
                var trimChars = new[] { '"' };
                while (reader.ReadLine() is { } line) {
                    if (!line.StartsWith("[HKEY_LOCAL_MACHINE\\", StringComparison.Ordinal)) {
                        continue;
                    }

                    var foundRuntimeContext = line.Equals("[HKEY_LOCAL_MACHINE\\" + RunTimeLicenseCode + "]");
                    while ((line = reader.ReadLine()) != null && line.Length != 0) {
                        var pos = line.IndexOf("=", StringComparison.Ordinal);
                        if (pos >= 0) {
                            var lbl = line.Substring(0, pos).Trim(trimChars);
                            var val = line.Substring(pos + 1).Trim(trimChars);
                            if (foundRuntimeContext) {
                                hashtable.Add(lbl, val);
                            }

                            if (lbl.Equals("IPNJA")) {
                                valIPNJA = val;
                            }
                        }
                    }
                }
            }
            finally {
                reader.Close();
            }

            if (!hashtable.ContainsKey("@")) {
                return 6;
            }

            serial = (string)hashtable["@"];
            serialDecodedBytes = sM.f(serial + "\0", null);
        }
        else {
            if (J || NN.H()) {
                return 6;
            }

            RegistryKey registryKey = null;
            try {
                registryKey = Registry.LocalMachine.OpenSubKey(RunTimeLicenseCode.Replace("IPNJA", ""));
                if (registryKey != null) {
                    object value = registryKey.GetValue("IPNJA");
                    if (value != null) {
                        valIPNJA = (string)value;
                    }
                }
            }
            catch { }

            try {
                registryKey = Registry.LocalMachine.OpenSubKey(RunTimeLicenseCode);
                if (registryKey == null) {
                    return 6;
                }

                object value = registryKey.GetValue("");
                if (value == null) {
                    return 6;
                }

                serial = (string)value;
                serialDecodedBytes = sM.f((string)value + "\0", null);
            }
            catch (SecurityException ex) {
                throw new Exception("Error reading registry: " + ex.Message);
            }
            catch (Exception) {
                return 6;
            }
        }

        R(serialDecodedBytes, 0);
        if (serialDecodedBytes[0] == 0) {
            return 7;
        }

        if (!A(serialDecodedBytes[5])) {
            return 10;
        }

        if (K(serialDecodedBytes[5])) {
            array2[0] = 42;
            array2[1] = 0;
        }
        else {
            array2 = sM.f(L(), null);
        }

        try {
            string label = y(array2, 0, 8);
            if (label[0] == '*') {
                label = "*";
            }

            object the_key = null;
            if (hashtable != null) {
                the_key = hashtable[label];
            }
            else {
                RegistryKey registryKey = Registry.LocalMachine.OpenSubKey(RunTimeLicenseCode);
                if (registryKey != null) {
                    the_key = registryKey.GetValue(label);
                }
            }

            if (the_key == null) {
                return KEY_NOT_FOUND;
            }

            key_bytes = sM.f((string)the_key + "\0", null);
        }
        catch (Exception) {
            return 8;
        }

        num = array2[0] != 42 ? L(serialDecodedBytes, array2, key_bytes, signatureBytes) : L(serialDecodedBytes, null, key_bytes, signatureBytes);
        if (num == 0) {
            num = M(serialDecodedBytes, 'J');
            if (num != 0) {
                return num;
            }
        }

        if (num == 0) {
            num = a(serialDecodedBytes, 8949);
            if (num != 0) {
                return num;
            }
        }

        if (num != 0) {
            return 8;
        }

        return _xh(serialDecodedBytes);
    }

    private const int KEY_NOT_FOUND = 8;


    private const int LICENSE_NOT_ACTIVATED = 8;
    private const int EXPIRED_TRIAL = 9;
    private const int INVALID_BUILD_NUMBER = 14;

    internal static string h(int prodCode, Type asmType, ref int resultCode, ref string serialCode, bool trialNag)
    {
        string text = "IPWorks 2024";
        if (asmType != null) {
            object obj = text;
            text = string.Concat(obj, " (", asmType, " component)");
        }

        text += ". ";
        byte[] signature_internal = new byte[16];
        x(signature_internal);
        byte[] outBuffer = null;
        var licenseFromFile = "";
        resultCode = t("SOFTWARE\\nsoftware\\RT\\IPNJA", signature_internal, prodCode, ref serialCode, ref outBuffer, ref licenseFromFile);
        if (resultCode != 0) {
            var c = (char)(65 + resultCode);
            var arg = L();
            switch (resultCode) {
                case LICENSE_NOT_ACTIVATED:
                    text +=
                        "This system contains a license for IPWorks 2024 that has been installed but not activated.  You must run setup in order to activate the license on this system [code: {0} nodeid: {1}].";
                    break;
                case EXPIRED_TRIAL:
                    text +=
                        "This system contains a trial license for IPWorks 2024 that has expired.  Please visit www.nsoftware.com or email support@nsoftware.com for information on purchasing a license or extending your trial [code: {0} nodeid: {1}].";
                    break;
                case INVALID_BUILD_NUMBER:
                {
                    var build_number = ipw240x.h.c(outBuffer);
                    object obj = text;
                    text = string.Concat(obj, "This system contains a license for IPWorks 2024 that is only valid for use with builds ", build_number,
                                         " and earlier, but the current build is ", 8949,
                                         ". Please visit www.nsoftware.com or email support@nsoftware.com for more information [code: {0} nodeid: {1}].");
                    break;
                }
                default:
                    text +=
                        "Could not find a valid license for using IPWorks 2024 on this system.  To obtain a trial license, please visit https://www.nsoftware.com/trial/IPNJA or email support@nsoftware.com [code: {0} nodeid: {1}].";
                    break;
            }

            throw new Exception(string.Format(text, c, arg));
        }

        W(serialCode,
          "This system contains a developer license for IPWorks 2024 which cannot be used on this operating system. See www.nsoftware.com for licensing options. [code: {0} nodeid: {1}]");
        if (!trialNag) {
            if (i(outBuffer[5])) {
                return "EXPIRING TRIAL [" + w(outBuffer) + " DAYS LEFT]";
            }

            return serialCode;
        }

        if (Environment.OSVersion.Platform == PlatformID.WinCE) {
            return null;
        }

        if (i(outBuffer[5])) {
            return null;
        }

        if (!o(outBuffer[5])) {
            return null;
        }

        byte[] array3 = new byte[16];
        d(array3);
        byte[] array4 = new byte[129];
        string text3 = serialCode + "                                           \0";
        S(array4, sM.f(text3, null), array3);
        return y(array4, 0, 128);
    }

    private static void n(byte[] P_0, int P_1)
    {
        int num = 0;
        P_0[num++] = 70;
        P_0[num++] = 105;
        P_0[num++] = 78;
        P_0[num++] = 65;
        P_0[num++] = 73;
        P_0[num++] = 68;
        P_0[num++] = 49;
        P_0[num++] = 116;
        P_0[num++] = 117;
        P_0[num++] = 84;
        P_0[num++] = 113;
        P_0[num++] = 116;
        P_0[num++] = 117;
        P_0[num++] = 100;
        P_0[num++] = 74;
        P_0[num++] = 70;
        if (P_1 != 0) {
            G(P_0, 78, 65);
        }
    }

    private static void d(byte[] P_0)
    {
        n(P_0, 1);
    }
}

internal sealed class sM
{
    public static byte[] f(string serial, string? encoding)
    {
        return saE.aI(serial, encoding);
    }

    public static string V(byte[] serial, string? encoding)
    {
        return saE.aM(serial, encoding);
    }
}

internal class saE
{
    internal static string aM(byte[] serial, string? encoding)
    {
        try {
            return w(serial, 0, serial.Length, encoding);
        }
        catch (Exception ex) {
            throw new Exception(ex.Message);
        }
    }

    internal static string su(byte[] serial, int offset, int len)
    {
        return x().GetString(serial, offset, len);
    }

    internal static char[] n =
    [
        '\0', '\u0001', '\u0002', '\u0003', '\u0004', '\u0005', '\u0006', '\a', '\b', '\t',
        '\n', '\v', '\f', '\r', '\u000e', '\u000f', '\u0010', '\u0011', '\u0012', '\u0013',
        '\u0014', '\u0015', '\u0016', '\u0017', '\u0018', '\u0019', '\u001a', '\u001b', '\u001c', '\u001d',
        '\u001e', '\u001f', ' ', '!', '"', '#', '$', '%', '&', '\'',
        '(', ')', '*', '+', ',', '-', '.', '/', '0', '1',
        '2', '3', '4', '5', '6', '7', '8', '9', ':', ';',
        '<', '=', '>', '?', '@', 'A', 'B', 'C', 'D', 'E',
        'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O',
        'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y',
        'Z', '[', '\\', ']', '^', '_', '`', 'a', 'b', 'c',
        'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
        'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w',
        'x', 'y', 'z', '{', '|', '}', '~', '\u007f', '\u0080', '\u0081',
        '\u0082', '\u0083', '\u0084', '\u0085', '\u0086', '\u0087', '\u0088', '\u0089', '\u008a', '\u008b',
        '\u008c', '\u008d', '\u008e', '\u008f', '\u0090', '\u0091', '\u0092', '\u0093', '\u0094', '\u0095',
        '\u0096', '\u0097', '\u0098', '\u0099', '\u009a', '\u009b', '\u009c', '\u009d', '\u009e', '\u009f',
        '\u00a0', 'Ḃ', 'ḃ', '£', 'Ċ', 'ċ', 'Ḋ', '§', 'Ẁ', '©',
        'Ẃ', 'ḋ', 'Ỳ', '\u00ad', '®', 'Ÿ', 'Ḟ', 'ḟ', 'Ġ', 'ġ',
        'Ṁ', 'ṁ', '¶', 'Ṗ', 'ẁ', 'ṗ', 'ẃ', 'Ṡ', 'ỳ', 'Ẅ',
        'ẅ', 'ṡ', 'À', 'Á', 'Â', 'Ã', 'Ä', 'Å', 'Æ', 'Ç',
        'È', 'É', 'Ê', 'Ë', 'Ì', 'Í', 'Î', 'Ï', 'Ŵ', 'Ñ',
        'Ò', 'Ó', 'Ô', 'Õ', 'Ö', 'Ṫ', 'Ø', 'Ù', 'Ú', 'Û',
        'Ü', 'Ý', 'Ŷ', 'ß', 'à', 'á', 'â', 'ã', 'ä', 'å',
        'æ', 'ç', 'è', 'é', 'ê', 'ë', 'ì', 'í', 'î', 'ï',
        'ŵ', 'ñ', 'ò', 'ó', 'ô', 'õ', 'ö', 'ṫ', 'ø', 'ù',
        'ú', 'û', 'ü', 'ý', 'ŷ', 'ÿ'
    ];

    internal static string ss(byte[] P_0, int P_1, int P_2)
    {
        var array = new char[P_2];
        for (var i = 0; i < array.Length; i++) {
            array[i] = n[P_0[i + P_1] & 0xFF];
        }

        return new string(array);
    }

    internal static Encoding x() => Encoding.Default;

    internal static string w(byte[] serial, int offset, int length, string? encodingName)
    {
        try {
            if (string.IsNullOrEmpty(encodingName)) {
                return su(serial, offset, length);
            }

            Encoding encoding = Encoding.GetEncoding(sd(encodingName));
            return encoding.GetString(serial, offset, length);
        }
        catch (Exception ex) {
            if (encodingName.ToLowerInvariant().Equals("iso-8859-14")) {
                return ss(serial, offset, length);
            }

            throw new Exception(ex.Message);
        }
    }

    internal static byte[] aI(string serial, string? encoding)
    {
        try {
            return string.IsNullOrEmpty(encoding) ? sC(serial) : Encoding.GetEncoding(sd(encoding)).GetBytes(serial);
        }
        catch (Exception ex) {
            if (encoding.ToLowerInvariant().Equals("iso-8859-14")) {
                return sN(serial);
            }

            throw new Exception(ex.Message);
        }
    }

    internal static byte[] sC(string src)
    {
        return x().GetBytes(src);
    }

    public static bool bT(string P_0)
    {
        return P_0 == null || P_0.Length <= 0;
    }

    protected static string sd(string P_0)
    {
        if (bT(P_0)) {
            return P_0;
        }

        string text = P_0.ToLower();
        if (text.Equals("utf8")) {
            return "UTF-8";
        }

        if (text.Equals("euc") || text.Equals("eucjp") || text.Equals("eucjpms") || text.Equals("eucjp-win") || text.Equals("eucjis") ||
            text.Equals("euc_jp") || text.Equals("eucjp-ms") || text.Equals("euc-jp-ms") || text.Equals("euc-jis-2004") || text.Equals("euc-jp-open") ||
            text.Equals("ujis")) {
            return "euc-jp";
        }

        if (text.Equals("cp932") || text.Equals("ms932") || text.Equals("windows-31j") || text.Equals("cswindows31j") || text.Equals("sjis-win") ||
            text.Equals("shift_jis-2004") || text.Equals("jis_c6220-1969-jp")) {
            return "shift_jis";
        }

        if (text.Equals("iso-2022-jp-1") || text.Equals("iso-2022-jp-2") || text.Equals("iso-2022-jp-ms") || text.Equals("jis") || text.Equals("jis-ms")) {
            return "iso-2022-jp";
        }

        if (text.Equals("ansi_x3.110-1983") || text.Equals("iso-ir-99") || text.Equals("csa_t500-1983") || text.Equals("naplps") ||
            text.Equals("csiso99naplps")) {
            return "us-ascii";
        }

        if (text.Equals("8bit")) {
            return "ISO-8859-1";
        }

        if (text.Equals("cp-850") || text.Equals("cp850")) {
            return "cp850";
        }

        if (text.Equals("cp1252") || text.Equals("cp-1252")) {
            return "windows-1252";
        }

        if (text.Equals("t.101-g2") || text.Equals("iso-ir-128")) {
            return "UTF-8";
        }

        return P_0;
    }

    internal static byte[]? C;

    internal static byte[] sN(string P_0)
    {
        if (C == null) {
            lock (n) {
                if (C == null) {
                    C = new byte[65535];
                    for (int i = 0; i < n.Length; i++) {
                        int num = n[i] & 0xFFFF;
                        C[num] = (byte)((uint)i & 0xFFu);
                    }
                }
            }
        }

        char[] array = P_0.ToCharArray();
        byte[] array2 = new byte[array.Length];
        for (int i = 0; i < array2.Length; i++) {
            array2[i] = C[array[i] & 0xFFFF];
        }

        return array2;
    }
}

internal class NN // : IDisposable
{
    protected static bool n = false;

    public static bool H()
    {
        return n;
    }
}