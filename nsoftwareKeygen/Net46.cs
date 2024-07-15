using System.Collections;
using System.Reflection;
using System.Security;
using System.Text;
using Microsoft.Win32;

namespace ipw240x;

public class h
{
    /**
     * alpha numeric table: 0-9, A-Z
     */
    internal static byte[] O__ALPHA_NUM_TBL = Encoding.ASCII.GetBytes("0123456789ABCDEFGHJKMNPRSTUVWXYZ");

    /**
     * Get string from bytes (default encoding)
     */
    public static string y__bytes_to_string(byte[] buf, int index, int length) =>
        Encoding.Default.GetString(buf, index, length);

    /**
     * Get string from bytes (UTF8)
     */
    public static byte[] utf8StrToBytes(string str) => Encoding.UTF8.GetBytes(str);

    /**
     * Array copy from src to dest
     */
    public static void y__array_copy(byte[] source, int srcOffset, byte[] dest, int destOffset, int length) =>
        Array.Copy(source, srcOffset, dest, destOffset, length);

    /**
     * Check license type (FULL version)
     * A-G,M,P,S,T,V,X,Z is okay
     */
    public static bool A__license_type_is_valid(byte lic_typ)
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
            ROYALTY_FREE_VERSION_INDEPENDENT => true,
            'X' => true,
            'Z' => true,
            _ => false,
        };
    }

    public const char ROYALTY_FREE_VERSION_INDEPENDENT = 'V';

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
            ROYALTY_FREE_VERSION_INDEPENDENT => "Royalty-Free, Version Independent",
            'X' => "Trial",
            'Z' => "Trial",
            'S' => "Single-Server, All Controls",
            'T' => "Single-Server, Single Control",
            'P' => "Single-Server, Processor Bound, All Controls",
            'M' => "Metered",
            _ => string.Concat((char)lic_typ),
        };
    }

    /**
     * License type is Z or X
     */
    public static bool i__license_type_is_trial(byte lic_typ)
        => lic_typ is 88 or 90;

    /**
     * License type is P
     */
    public static bool p_license_type_is_server_cpu_bound(byte lic_typ) => lic_typ == 80;

    /**
     * License type is C / D / E / F
     */
    public static bool f_license_type_is_royalty_free_server(byte lic_typ) => lic_typ is 68 or 69 or 70 or 71;

    /*
     * Check if limited license type
     */
    public static bool o_is_limited_license_type(byte lic_typ) =>
        (char)lic_typ switch
        {
            'A' => true,
            'B' => true,
            'C' => true,
            'D' => true,
            'F' => true,
            'V' => true,
            'Z' => true,
            _ => false,
        };

    /**
     * License is Royalty-Free, Single Control (C,F) or Single-Server, Single Control (G,T)
     */
    public static bool y_license_type_is_single_royalty_server(byte lic_typ) => lic_typ is 67 or 70 or 71 or 84;

    /**
     * License is Royalty-free (B) or Trial (Z)
     */
    public static bool K_license_is_royalty_or_trial(byte lic_typ) => lic_typ is 66 or 90;

    internal static void l(uint[] P_0, uint[] P_1)
    {
        uint num = P_0[0];
        uint num2 = P_0[1];
        uint num3 = 0u;
        uint num4 = 2654435769u;
        uint num5 = 32u;
        while (num5-- != 0)
        {
            num3 += num4;
            num += ((num2 << 4) + P_1[0]) ^ (num2 + num3) ^ ((num2 >> 5) + P_1[1]);
            num2 += ((num << 4) + P_1[2]) ^ (num + num3) ^ ((num >> 5) + P_1[3]);
        }

        P_0[0] = num;
        P_0[1] = num2;
    }

    internal static uint b(byte[] buf, int offset)
    {
        uint num = buf[offset + 3] & 0xFFu;
        num = num * 256 + (uint)(buf[offset + 2] & 0xFF);
        num = num * 256 + (uint)(buf[offset + 1] & 0xFF);
        return num * 256 + (uint)(buf[offset] & 0xFF);
    }

    internal static void a(uint le_byt, byte[] buffer, int offset)
    {
        buffer[offset++] = (byte)le_byt;
        buffer[offset++] = (byte)((le_byt >> 8) & 0xFFu);
        buffer[offset++] = (byte)((le_byt >> 16) & 0xFFu);
        buffer[offset++] = (byte)((le_byt >> 24) & 0xFFu);
    }

    internal static void b(byte[] buf, int offset, byte[] buf2)
    {
        uint[] array = new uint[2];
        uint[] array2 = new uint[4];
        for (int i = 0; i < 2; i++) array[i] = b(buf, offset + i * 4);

        for (int j = 0; j < 4; j++) array2[j] = b(buf2, offset + j * 4);

        l(array, array2);
        for (var k = 0; k < 2; k++) a(array[k], buf, k * 4);
    }

    internal static void P(byte[] buf, int endOffset)
    {
        for (var index = endOffset - 1; index >= 0; index--)
        {
            if ((buf[index / 8] & (1 << index % 8)) != 0)
            {
                buf[index / 5] |= (byte)(1 << index % 5);
            }
            else
            {
                buf[index / 5] &= (byte)(~(1 << index % 5));
            }

            if (index % 5 == 0)
            {
                buf[index / 5] &= 31;
            }
        }
    }

    public static void init()
    {
        O__ALPHA_NUM_TBL = new byte[32];
        O__ALPHA_NUM_TBL[0] = 48;
        O__ALPHA_NUM_TBL[1] = 49;
        O__ALPHA_NUM_TBL[2] = 50;
        O__ALPHA_NUM_TBL[3] = 51;
        O__ALPHA_NUM_TBL[4] = 52;
        O__ALPHA_NUM_TBL[5] = 53;
        O__ALPHA_NUM_TBL[6] = 54;
        O__ALPHA_NUM_TBL[7] = 55;
        O__ALPHA_NUM_TBL[8] = 56;
        O__ALPHA_NUM_TBL[9] = 57;
        O__ALPHA_NUM_TBL[10] = 65;
        O__ALPHA_NUM_TBL[11] = 66;
        O__ALPHA_NUM_TBL[12] = 67;
        O__ALPHA_NUM_TBL[13] = 68;
        O__ALPHA_NUM_TBL[14] = 69;
        O__ALPHA_NUM_TBL[15] = 70;
        O__ALPHA_NUM_TBL[16] = 71;
        O__ALPHA_NUM_TBL[17] = 72;
        O__ALPHA_NUM_TBL[18] = 74;
        O__ALPHA_NUM_TBL[19] = 75;
        O__ALPHA_NUM_TBL[20] = 77;
        O__ALPHA_NUM_TBL[21] = 78;
        O__ALPHA_NUM_TBL[22] = 80;
        O__ALPHA_NUM_TBL[23] = 82;
        O__ALPHA_NUM_TBL[24] = 83;
        O__ALPHA_NUM_TBL[25] = 84;
        O__ALPHA_NUM_TBL[26] = 85;
        O__ALPHA_NUM_TBL[27] = 86;
        O__ALPHA_NUM_TBL[28] = 87;
        O__ALPHA_NUM_TBL[29] = 88;
        O__ALPHA_NUM_TBL[30] = 89;
        O__ALPHA_NUM_TBL[31] = 90;
        var s = Encoding.ASCII.GetString(O__ALPHA_NUM_TBL);
    }

    internal static byte d__translate_from_LUT(byte leByte)
    {
        var b = leByte % 32;
        return O__ALPHA_NUM_TBL[leByte % 32];
    }

    internal static sbyte U__get_index_of_char_in_LUT(byte theByte)
    {
        // lower to UPPERCASE
        if (theByte is >= 97 and <= 122) theByte -= 32;

        // I => 1
        if (theByte == 73) theByte = 49;

        // L => 1
        if (theByte == 76) theByte = 49;

        // O => 0
        if (theByte == 79) theByte = 48;

        // Q => 0
        if (theByte == 81) theByte = 48;

        for (sbyte ix = 0; ix < 32; ix++)
            if (theByte == O__ALPHA_NUM_TBL[ix])
                return ix;

        return -1;
    }

    internal static byte B_char_to_uppercase(byte leByte)
    {
        if (leByte is >= 97 and <= 122) leByte -= 32;

        return leByte;
    }

    internal static void d(byte[] buffer, int offset, int length)
    {
        ulong num = (ulong)DateTime.Now.Ticks;
        for (var i = 0; i < length; i++)
        {
            if (i > 0 && i % 4 == 0)
            {
                num = num * 25214903917L + 11;
            }

            buffer[offset + i] = (byte)(65 + ((byte)(num >> i % 4 * 8) & 0x7F) % 26);
        }
    }

    /**
     * Decode/Encode buffer
     */
    protected internal static int R___decode_buffer(byte[] buffer, int offset)
    {
        var orig = Encoding.Default.GetString(buffer);
        int i;
        int index;
        for (i = index = offset; buffer[i] != 0; i++)
        {
            var lut_index = U__get_index_of_char_in_LUT(buffer[i]);
            if (lut_index == -1)
                buffer[i] = 0;
            else
                buffer[index++] = d__translate_from_LUT((byte)lut_index);
        }

        for (var j = index; j < i; j++) buffer[j] = 0;

        var after = y__bytes_to_string(buffer, 0, index);
        return index - offset;
    }

    internal static byte[] u__translate_bytes_to_alphanum(byte[] buffer, int length)
    {
        while (length % 5 != 0) buffer[length++] = 0;

        buffer[length] = 0;
        var div5_8bit = length / 5 * 8;
        var array = new byte[div5_8bit + 1];
        for (var i = 0; i < length; i++) array[i] = buffer[i];

        P(array, length * 8);
        for (var j = 0; j < div5_8bit; j++) array[j] = d__translate_from_LUT(array[j]);

        array[div5_8bit] = 0;
        return array;
    }

    /**
     * Encodes buffer
     */
    protected internal static void G(byte[] buf, byte b78, byte b65)
    {
        var before = buf;
        var s_before = Encoding.ASCII.GetString(buf);
        for (var i = 0; i < 16; i++)
        {
            buf[i] = (byte)(buf[i] + (b78 - 48) + (b65 - 48));
        }

        var s_after = Encoding.Default.GetString(buf);
    }

    internal static byte[] P__generate_key_for_serial_node(byte[] serial_40, byte[] node_id8, byte[] signatureBuf)
    {
        var workBuffer = new byte[301];
        var resultBuffer = new byte[14];
        y__array_copy(serial_40, 0, workBuffer, 0, serial_40.Length);
        var index = R___decode_buffer(workBuffer, 0);
        if (index == 0)
            return resultBuffer;

        if (node_id8 is { Length: > 0 })
        {
            workBuffer[index++] = 42; // '*'
            int index_node;
            for (index_node = index;
                 index_node < workBuffer.Length - 1 && index_node - index < node_id8.Length &&
                 node_id8[index_node - index] != 0;
                 index_node++) workBuffer[index_node] = node_id8[index_node - index];

            workBuffer[index_node] = 0;
            var wb_s = y__bytes_to_string(workBuffer, 0, index_node);
            index += R___decode_buffer(workBuffer, index);
            wb_s = y__bytes_to_string(workBuffer, 0, index);
        }

        while (index % 8 != 0) workBuffer[index++] = 0;

        var rb_s = "";
        for (var xor_offt = 0; xor_offt < index / 8; xor_offt++)
        {
            for (var i = 0; i < 8; i++)
                resultBuffer[i] ^= workBuffer[8 * xor_offt + i];

            rb_s = y__bytes_to_string(resultBuffer, 0, 14);
            b(resultBuffer, 0, signatureBuf);
            rb_s = y__bytes_to_string(resultBuffer, 0, 14);
        }

        return resultBuffer;
    }

    /**
     * Get 12 byte array - <b>possibly the key XXXX-XXXX-XXXX</b>
     */
    internal static byte[] w__generate_key(byte[] serial_code_40, byte[] node_id_8_chars, byte[] signature_bytes)
    {
        var key_buff = P__generate_key_for_serial_node(serial_code_40, node_id_8_chars, signature_bytes);
        key_buff = u__translate_bytes_to_alphanum(key_buff, 8);
        key_buff[12] = 0;
        var s2 = y__bytes_to_string(key_buff, 0, 12);
        return key_buff;
    }

    public const int KEY_VALID = 0;
    public const int KEY_EMPTY = 1;
    public const int KEY_INVALID = 2;
    public const int KEY_INVALID_LENGTH = 3;
    public const int KEY_ERROR = 4;

    public static int L(byte[] serial_from_license_file, byte[] node_id_buffer, byte[] key_from_license_file,
        byte[] signature_bytes)
    {
        var key_buffer = new byte[31];
        int i;
        for (i = 0; i < key_buffer.Length - 1 && key_from_license_file[i] != 0; i++)
            key_buffer[i] = key_from_license_file[i];

        key_buffer[i] = 0;
        var src_s = y__bytes_to_string(key_buffer, 0, i);
        R___decode_buffer(key_buffer, 0);
        var generated_key = w__generate_key(serial_from_license_file, node_id_buffer, signature_bytes);
        var num = 1;
        var key_length = key_buffer[6] == 0 ? 6 : 12; // 6 or 12 chars key
        var gen_s = y__bytes_to_string(generated_key, 0, key_length);
        for (i = 0; i < key_length; i++)
        {
            var src_byte = key_buffer[i];
            var generated_byte = generated_key[i];
            var c = (char)src_byte;

            if (src_byte != 0) num = 0;

            if (src_byte == 0)
                return KEY_EMPTY;

            if (src_byte != generated_byte)
                return KEY_INVALID;
        }

        if (key_buffer[12] != 0)
            return KEY_INVALID_LENGTH;

        return num != 0 ? KEY_ERROR : KEY_VALID;
    }

    public static string M(string P_0, string P_1, string expiry_date, string productKey, string P_4, bool P_5)
    {
        var text =
            "         Product : [product]\r\n     Product Key : [productKey]\r\n  License Source : [licenseSource]\r\n    License Type : [licenseType]\r\nLast Valid Build : [lastValidBuild]\r\n";
        if (P_1 is { Length: < 128 })
        {
            P_1 = null;
        }

        var buffer = ((P_1 != null)
            ? j__convert_runtimekey_to_serialcode(utf8StrToBytes(P_1 + "\0"), 128)
            : utf8StrToBytes(productKey + "\0"));
        if (P_1 != null)
        {
            buffer[64] = 0;
        }

        string text2 = P_4;
        if (P_0.Length > 0)
        {
            text2 = text2 + " (" + P_0 + ")";
        }

        string product_key = "n/a";
        if (P_1 is { Length: > 0 })
        {
            string @string = Encoding.ASCII.GetString(buffer, 0, buffer.Length);
            product_key = @string.Substring(0, @string.IndexOf("\0", StringComparison.Ordinal));
        }
        else if (productKey is { Length: > 0 })
        {
            product_key = productKey;
        }

        string license_src = "n/a";
        if (P_1 is { Length: > 0 })
        {
            license_src = "RuntimeLicense";
        }
        else if (P_5)
        {
            license_src = "License File";
        }
        else if (productKey is { Length: > 0 })
        {
            license_src = "Registry";
        }

        byte b = (byte)((buffer.Length > 5) ? buffer[5] : 0);
        string license_type;
        if (!expiry_date.Equals(""))
        {
            license_type = "Beta (Expires on " + expiry_date + ")";
        }
        else if (b != 0)
        {
            license_type = v(b);
            if (i__license_type_is_trial(b))
            {
                license_type = license_type + " (Expires on " + DateTime.Now.AddDays(w(buffer)).ToString("MM/dd/yyyy") +
                               ")";
            }
        }
        else
        {
            license_type = "None (No license could be found for using " + P_4 + " on this system.)";
        }

        var build_num = "n/a";
        if (f_license_type_is_royalty_free_server(b))
        {
            R___decode_buffer(buffer, 0);
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
    public static string L__get_machine_name()
    {
        var machine_name = "";
        try
        {
            machine_name = Environment.MachineName;
            string environmentVariable = Environment.GetEnvironmentVariable("_CLUSTER_NETWORK_NAME_");
            try
            {
                if (environmentVariable is { Length: > 0 })
                {
                    machine_name = (string)Registry.LocalMachine
                        .OpenSubKey("SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters").GetValue("NV Hostname");
                }
            }
            catch
            {
            }
        }
        catch (Exception)
        {
            return "00000000";
        }

        return l(machine_name);
    }

    /**
     * Get the serial key from machine name
     */
    public static string l(string node_id_8chars)
    {
        var serial_code_maybe = new byte[100];
        var node_id_bytes = utf8StrToBytes(node_id_8chars);
        y__array_copy(node_id_bytes, 0, serial_code_maybe, 1, node_id_bytes.Length);
        serial_code_maybe[0] = 65; // "A"
        byte[] seed_bytes =
        [
            69, 110, 105, 107, 97, 109, 69, 114, 117, 104,
            100, 121, 114, 116, 104, 83
        ];
        var key_buffer = w__generate_key(serial_code_maybe, [], seed_bytes);
        return y__bytes_to_string(key_buffer, 0, 8);
    }

    public static byte[] _h(byte[] buf, int last_offset)
    {
        var before = buf;
        var s_before = Encoding.Default.GetString(buf);
        byte[] array =
        [
            48, 49, 50, 51, 52, 53, 54, 55, 56, 57,
            65, 66, 67, 68, 69, 70
        ];
        for (var index = last_offset - 1; index >= 0; index--)
        {
            var b = buf[index];
            buf[2 * index + 1] = array[b & 15];
            b >>= 4;
            buf[2 * index] = array[b];
        }

        var s_after = Encoding.Default.GetString(buf);
        return buf;
    }

    public static byte[] j__convert_runtimekey_to_serialcode(byte[] rtkBuf, int length)
    {
        var orig = Encoding.ASCII.GetString(rtkBuf);
        var after = string.Empty;
        var chr = ' ';
        //var array = Encoding.ASCII.GetBytes("0123456789ABCDEF");
        for (var i = 0; i < length / 2; i++)
        {
            var curr_byte = rtkBuf[2 * i];
            chr = (char)curr_byte;
            switch (curr_byte)
            {
                // 0-9
                case >= 48 and <= 57:
                    var num_v = (byte)(curr_byte - 48 << 4);
                    chr = (char)num_v;
                    rtkBuf[i] = num_v;
                    break;
                default:
                {
                    // if not in A-F
                    if (curr_byte is < 65 or > 70)
                    {
                        for (i = 0; i < length; i++) rtkBuf[i] = 0;
                        return rtkBuf;
                    }

                    var alpha_v = (byte)(curr_byte - 65 + 10 << 4);
                    chr = (char)alpha_v;
                    rtkBuf[i] = alpha_v;
                    break;
                }
            }

            curr_byte = rtkBuf[2 * i + 1];
            chr = (char)curr_byte;

            switch (curr_byte)
            {
                // 0-9
                case >= 48 and <= 57:
                    var num_val = (byte)(curr_byte - 48);
                    chr = (char)num_val;
                    rtkBuf[i] += num_val;
                    continue;
                // A-F
                case >= 65 and <= 70:
                    var alpha_val = (byte)(curr_byte - 65 + 10);
                    chr = (char)alpha_val;
                    rtkBuf[i] += alpha_val;
                    continue;
            }

            for (i = 0; i < length; i++) rtkBuf[i] = 0;
            after = Encoding.ASCII.GetString(rtkBuf);
            return rtkBuf;
        }

        after = Encoding.ASCII.GetString(rtkBuf);
        return rtkBuf;
    }

    public static byte[] x(byte[] dest_buffer, byte[] serial_code_format, byte[] node_id_bytes,
        byte[] encoded_seed_buffer)
    {
        if (dest_buffer != null)
        {
            dest_buffer[0] = 0;
        }

        var num = R___decode_buffer(serial_code_format, 0);
        if (serial_code_format[0] == 0)
        {
            return dest_buffer;
        }

        d(serial_code_format, num + 1, 40 - num - 2);
        serial_code_format[39] = 0;
        byte[] array = w__generate_key(serial_code_format, node_id_bytes, encoded_seed_buffer);
        int num2 = 0;
        for (num2 = 0; num2 < 40; num2++)
        {
            dest_buffer[num2] = serial_code_format[num2];
        }

        for (num2 = 40; num2 < 48; num2++)
        {
            dest_buffer[num2] = node_id_bytes[num2 - 40];
        }

        for (num2 = 50; num2 < 62; num2++)
        {
            dest_buffer[num2] = array[num2 - 50];
        }

        dest_buffer = _h(dest_buffer, 64);
        dest_buffer[128] = 0;
        return dest_buffer;
    }

    public static byte[] S(byte[] dest_buffer, byte[] serial_code_format, byte[] encoded_seed_buffer)
    {
        var node_id_bytes = utf8StrToBytes(L__get_machine_name());
        return x(dest_buffer, serial_code_format, node_id_bytes, encoded_seed_buffer);
    }

    private const int INVALID_RTK = 17;
    private const int EMPTY_RTK = 18;

    public static int T(byte[]? rtkBuf, byte[] sigBuf, int prodCode)
    {
        if (rtkBuf == null)
            return INVALID_RTK;

        var rtk_len = rtkBuf.Length - 1;
        if (rtk_len < 128)
            return INVALID_RTK;

        // ?? decode buffer
        rtkBuf = j__convert_runtimekey_to_serialcode(rtkBuf, 128);
        rtkBuf[64] = 0;
        var s = y__bytes_to_string(rtkBuf, 0, 64);
        if (rtkBuf[0] == 0)
            return EMPTY_RTK;

        // split the 64 bytes array into 3 segments
        var serial_from_license_40 = new byte[40];
        var node_id_9 = new byte[9];
        var key_from_license_16 = new byte[16];
        int index;
        for (index = 0; index < 40; index++) serial_from_license_40[index] = rtkBuf[index];

        for (index = 40; index < 49; index++) node_id_9[index - 40] = rtkBuf[index];

        for (index = 50; index < 62; index++) key_from_license_16[index - 50] = rtkBuf[index];
        var serial__str = Encoding.Default.GetString(serial_from_license_40);
        var node_str = Encoding.Default.GetString(node_id_9);
        var key_str = Encoding.Default.GetString(key_from_license_16);

        var result = L(serial_from_license_40, node_id_9, key_from_license_16, sigBuf);
        if (result != 0)
            return result;

        switch ((char)B_char_to_uppercase(rtkBuf[5]))
        {
            case 'A':
            case 'B':
            case 'D':
            case 'V':
                return 0;
            case 'X':
            {
                var node_id = utf8StrToBytes(L__get_machine_name());
                for (index = 0; index < 8; index++)
                    if (node_id[index] != rtkBuf[40 + index])
                        return 20;

                return _xh(rtkBuf);
            }
            case 'Z':
                return _xh(rtkBuf);
            case 'C':
            case 'F':
                if (prodCode == 0)
                    return result;

                return prodCode != 10 * (rtkBuf[6] - 48) + rtkBuf[7] - 48 ? 11 : 0;

            default:
                return 10;
        }
    }

    public static int k(byte[] runtime_key, char char_check)
    {
        var the_5th = runtime_key[5];
        var b = B_char_to_uppercase(the_5th);
        if (b == 86)
            return 0;

        if (B_char_to_uppercase(runtime_key[3]) != char_check)
            return 21;

        return 0;
    }

    public static int M(byte[] P_0, char P_1)
    {
        byte b = B_char_to_uppercase(P_0[5]);
        if (b == 86)
        {
            return 0;
        }

        if (B_char_to_uppercase(P_0[3]) != P_1)
        {
            return 21;
        }

        return 0;
    }

    public static int i(byte[] rtkBytes, int buildNum)
    {
        var the5thByte = B_char_to_uppercase(rtkBytes[5]);
        if (!f_license_type_is_royalty_free_server(the5thByte))
        {
            return 0;
        }

        var num = c(rtkBytes);
        if (buildNum > num)
        {
            return 13;
        }

        return 0;
    }

    public static int a(byte[] P_0, int P_1)
    {
        byte b = B_char_to_uppercase(P_0[5]);
        if (!f_license_type_is_royalty_free_server(b))
        {
            return 0;
        }

        int num = c(P_0);
        if (P_1 > num)
        {
            return 14;
        }

        return 0;
    }

    public static int _xh(byte[] buf)
    {
        buf[buf.Length - 1] = 0;
        R___decode_buffer(buf, 0);
        if (i__license_type_is_trial(buf[5]))
        {
            var num = 10 * (buf[12] - 48) + (buf[13] - 48);
            DateTime now = DateTime.Now;
            int num2 = 365 * (now.Year - 2000) + 30 * now.Month + now.Day;
            int num3 = 365 * (10 * (buf[10] - 48) + (buf[11] - 48)) + 30 * (10 * (buf[6] - 48) + (buf[7] - 48)) +
                       (10 * (buf[8] - 48) + (buf[9] - 48));
            if (num2 > num3 + num)
            {
                return 9;
            }

            if (num2 < num3 - num)
            {
                return 12;
            }
        }

        if (p_license_type_is_server_cpu_bound(buf[5]))
        {
            int num4 = ((buf[6] <= 56) ? (buf[6] - 48) : 0);
        }

        return 0;
    }

    public static int w(byte[] P_0)
    {
        P_0[P_0.Length - 1] = 0;
        R___decode_buffer(P_0, 0);
        if (i__license_type_is_trial(P_0[5]))
        {
            int num = 10 * (P_0[12] - 48) + (P_0[13] - 48);
            DateTime now = DateTime.Now;
            int num2 = 365 * (now.Year - 2000) + 30 * now.Month + now.Day;
            int num3 = 365 * (10 * (P_0[10] - 48) + (P_0[11] - 48)) + 30 * (10 * (P_0[6] - 48) + (P_0[7] - 48)) +
                       (10 * (P_0[8] - 48) + (P_0[9] - 48));
            if (num2 > num3 + num)
            {
                return 0;
            }

            if (num2 < num3)
            {
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
        if (decodedFromLicenseFile[0] == 0 ||
            !f_license_type_is_royalty_free_server(B_char_to_uppercase(decodedFromLicenseFile[5])))
        {
            return -1;
        }

        int num = 10;
        int year = 1000 * (decodedFromLicenseFile[num] - 48) + 100 * (decodedFromLicenseFile[num + 1] - 48) +
                   10 * (decodedFromLicenseFile[num + 2] - 48) +
                   (decodedFromLicenseFile[num + 3] - 48);
        int month = 10 * (decodedFromLicenseFile[num + 4] - 48) + (decodedFromLicenseFile[num + 5] - 48);
        int day = 10 * (decodedFromLicenseFile[num + 6] - 48) + (decodedFromLicenseFile[num + 7] - 48);
        return (new DateTime(year, month, day, 0, 0, 0, DateTimeKind.Utc) -
                new DateTime(2000, 1, 1, 0, 0, 0, DateTimeKind.Utc)).Days;
    }
}

public sealed class M : h
{
    public static void n(int product_code, Type asmType, string? runTimeKey) =>
        l(product_code, asmType, runTimeKey != null ? utf8StrToBytes(runTimeKey + "\0") : null);

    internal static void l(int product_code, Type? asmType, byte[]? runtime_key)
    {
        var result = 18;
        if (runtime_key != null)
        {
            var signature_buf = new byte[17];
            d_populate_signature(signature_buf);
            result = T(runtime_key, signature_buf, product_code);
            if (result == 0) result = k(runtime_key, 'J');

            if (result == 0)
            {
                result = i(runtime_key, 8949);
                if (result != 0)
                {
                    var build_num = ipw240x.h.c(runtime_key);
                    var code_id = (char)(65 + result);
                    var node_id = L__get_machine_name();
                    var err_message = "IPWorks 2024";
                    if (asmType != null) err_message = string.Concat(err_message, " (", asmType, " component)");

                    err_message +=
                        ". The specified runtime license is only valid for use with IPWorks 2024 builds {0} and earlier. To use the current build ({1}), please generate a new runtime license from a valid license key. For more information, please visit www.nsoftware.com or email support@nsoftware.com [code: {2} nodeid: {3}].";
                    throw new Exception(string.Format(err_message, build_num, 8949, code_id, node_id));
                }
            }
        }

        if (result != 0) Q(product_code, asmType, ref result);
    }

    internal static string Q(int prodCode, Type? asmType, ref int transformResult)
    {
        string? text = null;
        return h(prodCode, asmType, ref transformResult, ref text, true);
    }

    internal static void W(string some_kind_of_product_type, string exception_tpl)
    {
        var flag = false;
        if (some_kind_of_product_type.Length >= 10 &&
            ((flag && some_kind_of_product_type.IndexOf("1DEV", StringComparison.Ordinal) == 6) ||
             some_kind_of_product_type.IndexOf("1DSK", StringComparison.Ordinal) == 6 ||
             (flag && some_kind_of_product_type.IndexOf("1SUB", StringComparison.Ordinal) == 6)) && D())
        {
            throw new Exception(string.Format(exception_tpl, 'Z', L__get_machine_name()));
        }
    }

    internal static bool D()
    {
        return false;
        //return RtlLib.IsServerOS();
    }

    /**
     * Populate signature buffer
     */
    private static void x(byte[] buf) => v(buf, 1);

    /**
     * Populate signature buffer and encoded if required
     */
    private static void v(byte[] buf, int decode)
    {
        var num = 0;
        buf[num++] = 51;
        buf[num++] = 79;
        buf[num++] = 90;
        buf[num++] = 109;
        buf[num++] = 83;
        buf[num++] = 82;
        buf[num++] = 76;
        buf[num++] = 49;
        buf[num++] = 68;
        buf[num++] = 103;
        buf[num++] = 100;
        buf[num++] = 51;
        buf[num++] = 51;
        buf[num++] = 121;
        buf[num++] = 66;
        buf[num] = 101;

        var xbuf = Encoding.ASCII.GetBytes("FiNAID1tuTqtudJF");
        var b = buf == xbuf;

        if (decode != 0) G(buf, 78, 65);
    }

    //t("SOFTWARE\\nsoftware\\RT\\IPNJA", signature_internal, prodCode, ref outMessage, ref array2, ref text2);
    private static int t(string regKey, byte[] sigBytes, int prodCode, ref string serial, ref byte[] outBuffer,
        ref string serialFromLicenseFile)
    {
        var result = c__read_license_from_file_or_registry(regKey, sigBytes, ref serial, ref outBuffer,
            ref serialFromLicenseFile);
        if (result != 0)
            return result;

        if (outBuffer == null)
            return result;

        if (!y_license_type_is_single_royalty_server(outBuffer[5]))
            return result;

        if (prodCode == 10 * (outBuffer[6] - 48) + outBuffer[7] - 48)
            return 0;

        regKey = regKey + "\\" + prodCode;
        result = c__read_license_from_file_or_registry(regKey, sigBytes, ref serial, ref outBuffer,
            ref serialFromLicenseFile);
        switch (result)
        {
            case 6:
                return 11;
            default:
                return result;
            case 0:
                if (!y_license_type_is_single_royalty_server(outBuffer[5]))
                    return 10;

                return prodCode != 10 * (outBuffer[6] - 48) + outBuffer[7] - 48 ? 11 : 0;
        }
    }

    public static bool J = false;

    private static string? k()
    {
        var codeBase = Assembly.GetExecutingAssembly().CodeBase;
        var length = codeBase.LastIndexOf("/", StringComparison.Ordinal);
        codeBase = codeBase.Substring(0, length);
        codeBase = codeBase.Substring(8);
        if (File.Exists(codeBase + "/nsoftware.IPWorks.lic"))
        {
            return codeBase + "/nsoftware.IPWorks.lic";
        }

        if (File.Exists(codeBase + "/IPNJA.lic"))
        {
            return codeBase + "/IPNJA.lic";
        }

        var platform = Environment.OSVersion.Platform;
        codeBase = (!(platform != PlatformID.Unix && platform != PlatformID.MacOSX)
            ? Environment.GetEnvironmentVariable("HOME")
            : Environment.ExpandEnvironmentVariables("%HOMEDRIVE%%HOMEPATH%"))!;
        codeBase += "/.nsoftware";
        if (File.Exists(codeBase + "/nsoftware.IPWorks.lic"))
        {
            return codeBase + "/nsoftware.IPWorks.lic";
        }

        if (File.Exists(codeBase + "/IPNJA.lic"))
        {
            return codeBase + "/IPNJA.lic";
        }

        return null;
    }

    public const int NO_SERIAL_FOUND = 6;
    public const int NULL_LICENSE_KEY = 7;
    public const int ERROR_LICENSE_PROCESSING = 8;
    public const int INVALIDE_LICENSE_TYPE = 10;

    private static int c__read_license_from_file_or_registry(
        string RunTimeLicenseCode,
        byte[] signatureBytes,
        ref string serial,
        ref byte[] serialDecodedBytes,
        ref string valIPNJA)
    {
        byte[] key_bytes;
        Hashtable? hashtable = null;
        byte[] node_id = [42, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        int return_code;
        var licenseFilename = k();
        string? text2 = null;
        if (licenseFilename != null || text2 != null)
        {
            hashtable = new Hashtable();
            string? licenseFileContent = null;
            if (licenseFileContent == null && text2 != null) licenseFileContent = text2;

            licenseFileContent ??= File.ReadAllText(licenseFilename);

            var reader = new StringReader(licenseFileContent);
            try
            {
                var trimChars = new[] { '"' };
                while (reader.ReadLine() is { } line)
                {
                    if (!line.StartsWith("[HKEY_LOCAL_MACHINE\\", StringComparison.Ordinal))
                        continue;

                    var foundRuntimeContext = line.Equals("[HKEY_LOCAL_MACHINE\\" + RunTimeLicenseCode + "]");
                    while ((line = reader.ReadLine()) != null && line.Length != 0)
                    {
                        var pos = line.IndexOf("=", StringComparison.Ordinal);
                        if (pos >= 0)
                        {
                            var lbl = line.Substring(0, pos).Trim(trimChars);
                            var val = line.Substring(pos + 1).Trim(trimChars);
                            if (foundRuntimeContext) hashtable.Add(lbl, val);

                            if (lbl.Equals("IPNJA")) valIPNJA = val;
                        }
                    }
                }
            }
            finally
            {
                reader.Close();
            }

            if (!hashtable.ContainsKey("@"))
                return NO_SERIAL_FOUND;

            serial = (string)hashtable["@"];
            serialDecodedBytes = sM.f___str_to_bytes(serial + "\0", null);
        }
        else
        {
            if (J || NN.H())
                return NO_SERIAL_FOUND;

            RegistryKey registryKey = null;
            try
            {
                registryKey = Registry.LocalMachine.OpenSubKey(RunTimeLicenseCode.Replace("IPNJA", ""));
                if (registryKey != null)
                {
                    object value = registryKey.GetValue("IPNJA");
                    if (value != null)
                    {
                        valIPNJA = (string)value;
                    }
                }
            }
            catch
            {
            }

            try
            {
                registryKey = Registry.LocalMachine.OpenSubKey(RunTimeLicenseCode);
                if (registryKey == null)
                    return NO_SERIAL_FOUND;

                object value = registryKey.GetValue("");
                if (value == null)
                    return NO_SERIAL_FOUND;

                serial = (string)value;
                serialDecodedBytes = sM.f___str_to_bytes((string)value + "\0", null);
            }
            catch (SecurityException ex)
            {
                throw new Exception("Error reading registry: " + ex.Message);
            }
            catch (Exception)
            {
                return ERROR_READING_REGISTRY;
            }
        }

        R___decode_buffer(serialDecodedBytes, 0);
        if (serialDecodedBytes[0] == 0)
            return NULL_LICENSE_KEY;

        var license_type_byte = serialDecodedBytes[5];

        if (!A__license_type_is_valid(license_type_byte))
            return INVALIDE_LICENSE_TYPE;

        if (K_license_is_royalty_or_trial(license_type_byte))
        {
            // all nodes
            node_id[0] = 42; // "*"
            node_id[1] = 0;
        }
        else
            node_id = sM.f___str_to_bytes(L__get_machine_name(), null);

        try
        {
            // (re)convert node_id to string
            var node_id_string = y__bytes_to_string(node_id, 0, 8);
            if (node_id_string[0] == '*') node_id_string = "*";

            object the_key = null;
            if (hashtable != null)
                the_key = hashtable[node_id_string];
            else
            {
                var registryKey = Registry.LocalMachine.OpenSubKey(RunTimeLicenseCode);
                if (registryKey != null) the_key = registryKey.GetValue(node_id_string);
            }

            if (the_key == null)
                return KEY_NOT_FOUND;

            key_bytes = sM.f___str_to_bytes((string)the_key + "\0", null);
        }
        catch (Exception)
        {
            return ERROR_LICENSE_PROCESSING;
        }

        return_code = node_id[0] != 42 /* is not '*" */
            ? L(serialDecodedBytes, node_id, key_bytes, signatureBytes)
            : L(serialDecodedBytes, null, key_bytes, signatureBytes);

        if (return_code == 0)
        {
            return_code = M(serialDecodedBytes, 'J');
            if (return_code != 0)
                return return_code;
        }

        if (return_code == 0)
        {
            return_code = a(serialDecodedBytes, 8949);
            if (return_code != 0)
                return return_code;
        }

        if (return_code != 0)
            return ERROR_LICENSE_PROCESSING;

        return _xh(serialDecodedBytes);
    }

    private const int ERROR_READING_REGISTRY = 6;
    private const int KEY_NOT_FOUND = 8;


    private const int LICENSE_NOT_ACTIVATED = 8;
    private const int EXPIRED_TRIAL = 9;
    private const int INVALID_BUILD_NUMBER = 14;

    internal static string h(int prodCode, Type? asmType, ref int error_code, ref string serialCode, bool trialNag)
    {
        var text = "IPWorks 2024";
        if (asmType != null)
        {
            object obj = text;
            text = string.Concat(obj, " (", asmType, " component)");
        }

        text += ". ";
        var signature_internal = new byte[16];
        x(signature_internal);
        byte[]? outBuffer = null;
        var licenseFromFile = "";
        error_code = t("SOFTWARE\\nsoftware\\RT\\IPNJA", signature_internal, prodCode, ref serialCode, ref outBuffer,
            ref licenseFromFile);
        if (error_code != 0)
        {
            var err_code_str = (char)(65 + error_code);
            var node_id = L__get_machine_name();
            switch (error_code)
            {
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
                    text = string.Concat(obj,
                        "This system contains a license for IPWorks 2024 that is only valid for use with builds ",
                        build_number,
                        " and earlier, but the current build is ", 8949,
                        ". Please visit www.nsoftware.com or email support@nsoftware.com for more information [code: {0} nodeid: {1}].");
                    break;
                }
                default:
                    text +=
                        "Could not find a valid license for using IPWorks 2024 on this system.  To obtain a trial license, please visit https://www.nsoftware.com/trial/IPNJA or email support@nsoftware.com [code: {0} nodeid: {1}].";
                    break;
            }

            throw new Exception(string.Format(text, err_code_str, node_id));
        }

        W(serialCode,
            "This system contains a developer license for IPWorks 2024 which cannot be used on this operating system. See www.nsoftware.com for licensing options. [code: {0} nodeid: {1}]");
        if (!trialNag)
        {
            if (i__license_type_is_trial(outBuffer[5]))
            {
                return "EXPIRING TRIAL [" + w(outBuffer) + " DAYS LEFT]";
            }

            return serialCode;
        }

        if (Environment.OSVersion.Platform == PlatformID.WinCE)
        {
            return string.Empty;
        }

        if (i__license_type_is_trial(outBuffer[5]))
        {
            return string.Empty;
        }

        if (!o_is_limited_license_type(outBuffer[5]))
        {
            return string.Empty;
        }

        byte[] seed_buffer = new byte[16];
        d_populate_signature(seed_buffer);
        var dest_buffer = new byte[129];
        var serial_code_format = serialCode + "                                           \0";
        S(dest_buffer, sM.f___str_to_bytes(serial_code_format, null), seed_buffer);
        return y__bytes_to_string(dest_buffer, 0, 128);
    }

    /**
     * Initialize seed buffer (encoded)
     */
    private static void n_create_signature(byte[] buf, int encode)
    {
        int num = 0;
        buf[num++] = 70;
        buf[num++] = 105;
        buf[num++] = 78;
        buf[num++] = 65;
        buf[num++] = 73;
        buf[num++] = 68;
        buf[num++] = 49;
        buf[num++] = 116;
        buf[num++] = 117;
        buf[num++] = 84;
        buf[num++] = 113;
        buf[num++] = 116;
        buf[num++] = 117;
        buf[num++] = 100;
        buf[num++] = 74;
        buf[num++] = 70;
        if (encode > 0) G(buf, 78, 65);
    }

    private static void d_populate_signature(byte[] signateure) => n_create_signature(signateure, 1);
}

internal sealed class sM
{
    public static byte[] f___str_to_bytes(string serial, string? encoding)
    {
        return saE.aI(serial, encoding);
    }

    public static string V__bytest_to_str(byte[] serial, string? encoding)
    {
        return saE.aM(serial, encoding);
    }
}

internal class saE
{
    internal static string aM(byte[] serial, string? encoding)
    {
        try
        {
            return w(serial, 0, serial.Length, encoding);
        }
        catch (Exception ex)
        {
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
        for (var i = 0; i < array.Length; i++)
        {
            array[i] = n[P_0[i + P_1] & 0xFF];
        }

        return new string(array);
    }

    internal static Encoding x() => Encoding.Default;

    internal static string w(byte[] serial, int offset, int length, string? encodingName)
    {
        try
        {
            if (string.IsNullOrEmpty(encodingName))
            {
                return su(serial, offset, length);
            }

            Encoding encoding = Encoding.GetEncoding(sd(encodingName));
            return encoding.GetString(serial, offset, length);
        }
        catch (Exception ex)
        {
            if (encodingName.ToLowerInvariant().Equals("iso-8859-14"))
            {
                return ss(serial, offset, length);
            }

            throw new Exception(ex.Message);
        }
    }

    internal static byte[] aI(string serial, string? encoding)
    {
        try
        {
            return string.IsNullOrEmpty(encoding) ? sC(serial) : Encoding.GetEncoding(sd(encoding)).GetBytes(serial);
        }
        catch (Exception ex)
        {
            if (encoding.ToLowerInvariant().Equals("iso-8859-14"))
            {
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
        if (bT(P_0))
        {
            return P_0;
        }

        string text = P_0.ToLower();
        if (text.Equals("utf8"))
        {
            return "UTF-8";
        }

        if (text.Equals("euc") || text.Equals("eucjp") || text.Equals("eucjpms") || text.Equals("eucjp-win") ||
            text.Equals("eucjis") ||
            text.Equals("euc_jp") || text.Equals("eucjp-ms") || text.Equals("euc-jp-ms") ||
            text.Equals("euc-jis-2004") || text.Equals("euc-jp-open") ||
            text.Equals("ujis"))
        {
            return "euc-jp";
        }

        if (text.Equals("cp932") || text.Equals("ms932") || text.Equals("windows-31j") || text.Equals("cswindows31j") ||
            text.Equals("sjis-win") ||
            text.Equals("shift_jis-2004") || text.Equals("jis_c6220-1969-jp"))
        {
            return "shift_jis";
        }

        if (text.Equals("iso-2022-jp-1") || text.Equals("iso-2022-jp-2") || text.Equals("iso-2022-jp-ms") ||
            text.Equals("jis") || text.Equals("jis-ms"))
        {
            return "iso-2022-jp";
        }

        if (text.Equals("ansi_x3.110-1983") || text.Equals("iso-ir-99") || text.Equals("csa_t500-1983") ||
            text.Equals("naplps") ||
            text.Equals("csiso99naplps"))
        {
            return "us-ascii";
        }

        if (text.Equals("8bit"))
        {
            return "ISO-8859-1";
        }

        if (text.Equals("cp-850") || text.Equals("cp850"))
        {
            return "cp850";
        }

        if (text.Equals("cp1252") || text.Equals("cp-1252"))
        {
            return "windows-1252";
        }

        if (text.Equals("t.101-g2") || text.Equals("iso-ir-128"))
        {
            return "UTF-8";
        }

        return P_0;
    }

    internal static byte[]? C;

    internal static byte[] sN(string P_0)
    {
        if (C == null)
        {
            lock (n)
            {
                if (C == null)
                {
                    C = new byte[65535];
                    for (int i = 0; i < n.Length; i++)
                    {
                        int num = n[i] & 0xFFFF;
                        C[num] = (byte)((uint)i & 0xFFu);
                    }
                }
            }
        }

        char[] array = P_0.ToCharArray();
        byte[] array2 = new byte[array.Length];
        for (int i = 0; i < array2.Length; i++)
        {
            array2[i] = C[array[i] & 0xFFFF];
        }

        return array2;
    }
}

internal class NN // : IDisposable
{
    protected static bool n = false;

    public static bool H() => n;
}